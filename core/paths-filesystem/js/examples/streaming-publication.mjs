import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';

import {
  atomicWriteStream,
  openWorkspaceRoot,
  preflightWorkspaceMaterialization,
  probeFilesystemCapabilities,
  validateRepositoryPath,
} from '../src/index.mjs';

const [root, repositoryPath, sourcePath, expectedSha256] = process.argv.slice(2);
if ([root, repositoryPath, sourcePath, expectedSha256].some((value) => value === undefined)) {
  throw new Error('usage: node examples/streaming-publication.mjs <absolute-private-root> <repository-path> <source-file> <expected-sha256>');
}

const workspace = await openWorkspaceRoot(root);
const canonical = validateRepositoryPath(repositoryPath, { profile: workspace.profile }).canonical;
const capabilities = await probeFilesystemCapabilities(workspace.root);
const segments = canonical.split('/');
const entries = [];
for (let index = 1; index < segments.length; index += 1) {
  entries.push({
    id: `parent-${index}`, path: segments.slice(0, index).join('/'), kind: 'directory', mode: 'directory',
  });
}
entries.push({ id: 'reconstructed-content', path: canonical, kind: 'regular', mode: 'regular-file' });
const plan = await preflightWorkspaceMaterialization(workspace, {
  schemaVersion: 'ogvcs.path/preflight-request/v1',
  caseMode: workspace.caseMode,
  profile: workspace.profile,
  platform: capabilities.platform,
  capabilities: {
    atomicReplace: capabilities.atomicReplace,
    executableBit: capabilities.executableBit,
    symlink: capabilities.symlink,
  },
  entries,
});
const expectedBytes = (await stat(sourcePath)).size;

const result = await atomicWriteStream(workspace, canonical, createReadStream(sourcePath), {
  createParents: true,
  plan,
  expectedBytes,
  expectedSha256,
  maxBytes: expectedBytes,
  maxScratchBytes: expectedBytes,
  maxChunkBytes: 8 * 1024 * 1024,
  maxTimeMs: 30 * 60 * 1000,
});
process.stdout.write(`${JSON.stringify(result)}\n`);
