#!/usr/bin/env node

import assert from 'node:assert/strict';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

import {
  atomicWriteFile, openWorkspaceRoot, preflightWorkspaceMaterialization, probeFilesystemCapabilities,
} from '../core/paths-filesystem/js/src/index.mjs';

const [root, outside] = process.argv.slice(2);
if (!isAbsolute(root ?? '') || !isAbsolute(outside ?? '')) {
  throw new Error('usage: node tools/path-filesystem-trace-fixture.mjs <workspace-root> <outside-root>');
}

const workspace = await openWorkspaceRoot(root);
const capabilities = await probeFilesystemCapabilities(root);
async function plan(path) {
  const segments = path.split('/');
  const entries = segments.slice(0, -1).map((_, index) => ({
    id: `directory-${index}`, path: segments.slice(0, index + 1).join('/'), kind: 'directory', mode: 'directory',
  }));
  entries.push({ id: 'target', path, kind: 'regular', mode: 'regular-file' });
  return preflightWorkspaceMaterialization(workspace, {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: workspace.caseMode,
    profile: workspace.profile, platform: capabilities.platform,
    capabilities: { atomicReplace: capabilities.atomicReplace, executableBit: capabilities.executableBit, symlink: capabilities.symlink },
    entries,
  });
}
async function denied(path, content, options = {}) {
  let code;
  try { await atomicWriteFile(workspace, path, Buffer.from(content), { ...options, plan: await plan(path) }); }
  catch (error) { code = error?.code; }
  return code;
}

const symlinkAncestor = await denied('escape/pwned', 'must-not-escape');
assert.equal(symlinkAncestor, 'UNSAFE_TARGET');

await atomicWriteFile(workspace, 'Race/target', Buffer.from('base'), { createParents: true, plan: await plan('Race/target') });
const targetRace = await denied('Race/target', 'trusted', {
  hooks: { boundary: async (name) => { if (name === 'before-publish') await writeFile(join(root, 'Race/target'), 'racer'); } },
});
assert.equal(targetRace, 'TARGET_CHANGED');

await atomicWriteFile(workspace, 'Ancestor/target', Buffer.from('base'), { createParents: true, plan: await plan('Ancestor/target') });
const ancestorRace = await denied('Ancestor/target', 'trusted', {
  hooks: { boundary: async (name) => {
    if (name === 'before-publish') {
      await rename(join(root, 'Ancestor'), join(root, 'Ancestor-displaced'));
      await mkdir(join(root, 'Ancestor'));
    }
  } },
});
assert.equal(ancestorRace, 'TARGET_CHANGED');

process.stdout.write(`${JSON.stringify({
  schemaVersion: 'ogvcs.path/trace-fixture-result/v1', denied: true,
  symlinkAncestor, targetRace, ancestorRace,
})}\n`);
