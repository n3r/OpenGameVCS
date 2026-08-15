#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import path from 'node:path';

const packageDirectory = path.resolve(import.meta.dirname, '..');
const testDirectory = path.join(packageDirectory, 'test');
const testFiles = (await readdir(testDirectory))
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => path.join('test', name));

const maximumDiagnosticBytes = 48 * 1024;
let diagnosticTail = '';

function forwardAndCapture(chunk, destination) {
  destination.write(chunk);
  diagnosticTail = `${diagnosticTail}${chunk.toString('utf8')}`.slice(-maximumDiagnosticBytes);
}

function workflowCommandValue(value) {
  return value
    .replaceAll('\0', '')
    .replaceAll('%', '%25')
    .replaceAll('\r', '%0D')
    .replaceAll('\n', '%0A');
}

const child = spawn(
  process.execPath,
  ['--test', '--test-concurrency=1', ...testFiles],
  {
    cwd: packageDirectory,
    env: process.env,
    stdio: ['inherit', 'pipe', 'pipe'],
  },
);

child.stdout.on('data', (chunk) => forwardAndCapture(chunk, process.stdout));
child.stderr.on('data', (chunk) => forwardAndCapture(chunk, process.stderr));

const result = await new Promise((resolve, reject) => {
  child.once('error', reject);
  // `close` fires only after stdout/stderr are drained, so the failure annotation
  // cannot omit the final assertion emitted after the process exit event.
  child.once('close', (code, signal) => resolve({ code, signal }));
});

if (result.code !== 0) {
  const status = result.signal ? `signal ${result.signal}` : `exit code ${result.code ?? 1}`;
  if (process.env.GITHUB_ACTIONS === 'true') {
    const details = workflowCommandValue(`Test process ended with ${status}.\n\n${diagnosticTail}`);
    process.stderr.write(`::error title=Fixture generator tests failed::${details}\n`);
  }
  process.exitCode = result.code ?? 1;
}
