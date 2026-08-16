#!/usr/bin/env node

import assert from 'node:assert/strict';
import { isAbsolute } from 'node:path';

import { atomicWriteFile, openWorkspaceRoot } from '../core/paths-filesystem/js/src/index.mjs';

const [root, outside] = process.argv.slice(2);
if (!isAbsolute(root ?? '') || !isAbsolute(outside ?? '')) {
  throw new Error('usage: node tools/path-filesystem-trace-fixture.mjs <workspace-root> <outside-root>');
}

const workspace = await openWorkspaceRoot(root);
let code;
try {
  await atomicWriteFile(workspace, 'escape/pwned', Buffer.from('must-not-escape'));
} catch (error) {
  code = error?.code;
}
assert.equal(code, 'UNSAFE_TARGET');
process.stdout.write(`${JSON.stringify({ schemaVersion: 'ogvcs.path/trace-fixture-result/v1', denied: true, code })}\n`);
