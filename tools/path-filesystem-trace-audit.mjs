#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, open } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const MAX_TRACE_BYTES = 16 * 1024 * 1024;

async function boundedTrace(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size === 0 || info.size > MAX_TRACE_BYTES) throw new Error('trace is not a bounded nonempty regular file');
  const handle = await open(path, 'r');
  try {
    const before = await handle.stat();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || bytes.length !== before.size) throw new Error('trace changed while reading');
    return bytes;
  } finally { await handle.close(); }
}

export async function auditPathFilesystemTrace(tracePath, workspaceRoot, outsideRoot) {
  if (![tracePath, workspaceRoot, outsideRoot].every((value) => typeof value === 'string' && isAbsolute(value))) throw new Error('trace audit requires absolute paths');
  const workspace = resolve(workspaceRoot); const outside = resolve(outsideRoot);
  if (workspace === outside || workspace.startsWith(`${outside}/`) || outside.startsWith(`${workspace}/`)) throw new Error('trace roots must be disjoint');
  const bytes = await boundedTrace(tracePath);
  const text = bytes.toString('utf8');
  if (Buffer.from(text, 'utf8').length !== bytes.length || !text.includes(workspace)) throw new Error('trace does not cover the workspace fixture');
  if (text.includes(outside)) throw new Error('traced filesystem operation reached the outside fixture');
  return Object.freeze({
    schemaVersion: 'ogvcs.path/filesystem-trace-audit/v1',
    bytes: bytes.length,
    lines: text.split('\n').filter(Boolean).length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    outsideReferences: 0,
  });
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length !== 6 || args[0] !== '--trace' || args[2] !== '--workspace' || args[4] !== '--outside') {
    throw new Error('usage: node tools/path-filesystem-trace-audit.mjs --trace <file> --workspace <root> --outside <root>');
  }
  process.stdout.write(`${JSON.stringify(await auditPathFilesystemTrace(resolve(args[1]), resolve(args[3]), resolve(args[5])))}\n`);
}
