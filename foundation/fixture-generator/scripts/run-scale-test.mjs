#!/usr/bin/env node

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDirectory = fileURLToPath(new URL('../', import.meta.url));
const child = spawn(process.execPath, [
  '--test',
  '--test-concurrency=1',
  path.join(packageDirectory, 'test', 'scale.test.mjs'),
], {
  cwd: packageDirectory,
  env: { ...process.env, OGVCS_RUN_SCALE: '1' },
  stdio: 'inherit',
  windowsHide: true,
});

child.on('error', (error) => {
  process.stderr.write(`Unable to start reference-scale test: ${error.message}\n`);
  process.exitCode = 1;
});
child.on('close', (code, signal) => {
  if (signal) {
    process.stderr.write(`Reference-scale test terminated by ${signal}\n`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
