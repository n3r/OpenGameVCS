import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const packageDirectory = fileURLToPath(new URL('../', import.meta.url));
export const cliPath = path.join(packageDirectory, 'bin', 'ogvcs-fixture.mjs');

export async function temporaryDirectory(t, prefix = 'ogvcs-fixture-test-') {
  const directory = await mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => rm(directory, { force: true, recursive: true }));
  return directory;
}

export function runProcess(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const executable = process.platform === 'win32' && command === 'npm' ? 'npm.cmd' : command;
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({
      code,
      signal,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8'),
    }));
  });
}

export function runCli(cwd, args, options = {}) {
  return runProcess(process.execPath, [cliPath, ...args], { ...options, cwd });
}

export function jsonOutput(result) {
  return JSON.parse(result.stdout);
}

export function jsonError(result) {
  return JSON.parse(result.stderr.trim().split('\n').at(-1));
}

export function progressEvents(result) {
  return result.stderr
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

export function smallCliArguments(profile, destination, overrides = {}) {
  return [
    '--profile', profile,
    '--seed', overrides.seed ?? 'acceptance-seed-v1',
    '--destination', destination,
    '--path-count', String(overrides.pathCount ?? 12),
    '--history-operations', String(overrides.historyOperationCount ?? 10),
    '--large-file-bytes', String(overrides.largeFileBytes ?? 4096),
    '--max-depth', String(overrides.maxDepth ?? 6),
    '--checkpoint-every', String(overrides.checkpointEvery ?? 4),
    '--materialization', overrides.materialization ?? 'full',
    '--large-file-mode', overrides.largeFileMode ?? 'full',
  ];
}
