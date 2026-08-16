import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { resolve } from 'node:path';

import { probeFilesystemCapabilities } from './capabilities.mjs';
import { PathFilesystemError } from './errors.mjs';
import { evaluateCollisions, evaluatePath } from './path.mjs';
import { evaluatePreflight } from './preflight.mjs';
import { evaluateRenames } from './rename.mjs';
import { writeConformanceReport } from './report.mjs';
import { atomicWriteFile, openWorkspaceRoot } from './workspace.mjs';

const HELP = `ogvcs-path commands:
  validate <path> [--profile <ProfileRef>] [--case-mode <mode>]
  collisions <request.json>
  preflight <request.json>
  renames <request.json>
  capabilities <absolute-root>
  write <absolute-root> <repository-path> <source-file>
  conformance --output <report.json>
`;

function valueAfter(args, flag, fallback) {
  const index = args.indexOf(flag);
  if (index === -1) return fallback;
  if (index + 1 >= args.length) throw new Error(`${flag} requires a value`);
  return args[index + 1];
}
async function boundedFile(path, maximum) {
  const absolute = resolve(path);
  const pathInfo = await lstat(absolute);
  if (!pathInfo.isFile() || pathInfo.isSymbolicLink() || pathInfo.size > maximum) throw new Error('input is not a bounded regular file');
  const handle = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > maximum || String(before.dev) !== String(pathInfo.dev) || String(before.ino) !== String(pathInfo.ino)) throw new Error('input identity changed');
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (String(after.dev) !== String(before.dev) || String(after.ino) !== String(before.ino) || after.size !== before.size || Math.trunc(after.mtimeMs) !== Math.trunc(before.mtimeMs) || bytes.length !== before.size) throw new Error('input identity changed');
    return bytes;
  } finally { await handle.close(); }
}
async function jsonFile(path, maximum = 16 * 1024 * 1024) {
  const bytes = await boundedFile(path, maximum);
  return JSON.parse(bytes);
}
function output(value, stream = process.stdout) { stream.write(`${JSON.stringify(value)}\n`); }

export async function runCli(args = process.argv.slice(2)) {
  const [command, ...rest] = args;
  if (command === undefined || command === 'help' || command === '--help') { process.stdout.write(HELP); return 0; }
  if (command === 'validate') {
    if (!rest[0]) throw new Error('validate requires a path');
    output(evaluatePath(rest[0], { profile: valueAfter(rest, '--profile', 'path.opengamevcs/portable@1'), caseMode: valueAfter(rest, '--case-mode', 'case-sensitive') }));
    return 0;
  }
  if (command === 'collisions') {
    const request = await jsonFile(rest[0]);
    output(evaluateCollisions(request.items, { profile: request.profile, caseMode: request.caseMode })); return 0;
  }
  if (command === 'preflight') { output(evaluatePreflight(await jsonFile(rest[0]))); return 0; }
  if (command === 'renames') { output(evaluateRenames(await jsonFile(rest[0]))); return 0; }
  if (command === 'capabilities') { output(await probeFilesystemCapabilities(resolve(rest[0]))); return 0; }
  if (command === 'write') {
    if (rest.length !== 3) throw new Error('write requires root, repository path, and source file');
    const workspace = await openWorkspaceRoot(resolve(rest[0]));
    output(await atomicWriteFile(workspace, rest[1], await boundedFile(rest[2], 64 * 1024 * 1024), { createParents: true })); return 0;
  }
  if (command === 'conformance') {
    const destination = valueAfter(rest, '--output');
    if (!destination) throw new Error('conformance requires --output');
    const report = await writeConformanceReport(resolve(destination));
    output({ output: resolve(destination), total: report.total, passed: report.passed, failed: report.failed, resultsSha256: report.resultsSha256 });
    return report.failed === 0 ? 0 : 1;
  }
  throw new Error(`unknown command: ${command}`);
}

export async function main(args = process.argv.slice(2)) {
  try { return await runCli(args); }
  catch (error) {
    if (error instanceof PathFilesystemError) { output(error.toJSON(), process.stderr); return error.exitCode; }
    output({ error: 'IO_ERROR' }, process.stderr); return 6;
  }
}
