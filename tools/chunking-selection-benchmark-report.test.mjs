import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { buildChunkingSelectionReport } from './chunking-selection-benchmark-report.mjs';

const ROOT = resolve(import.meta.dirname, '..');

function run(script, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'tools', script), ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({
      code,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8'),
    }));
  });
}

test('bounded chunking selection report covers all seven workload classes and passes its gates', { timeout: 120_000 }, async () => {
  const report = await buildChunkingSelectionReport();
  assert.equal(report.schemaVersion, 'ogvcs.chunking/selection-benchmark-report/v1');
  assert.equal(report.overallStatus, 'passed');
  assert.equal(report.exactScaleExecuted, false);
  assert.deepEqual(
    report.workloads.map(({ workloadId }) => workloadId),
    ['source-like', 'structured', 'already-compressed', 'encrypted-random', 'insertion', 'replacement', 'append'],
  );
  assert.equal(report.summary.workloadCount, 7);
  assert.equal(report.summary.successCount, 7);
  assert.equal(report.summary.accountingMismatchCount, 0);
  assert.equal(report.thresholdEvaluations.filter(({ severity, status }) => severity === 'gate' && status === 'failed').length, 0);
  assert.equal(report.workloads.find(({ workloadId }) => workloadId === 'encrypted-random').compare.reusedBytes, '0');
});

test('cli writes the report file', { timeout: 120_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-selection-report-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const output = join(directory, 'report.json');
  const result = await run('chunking-selection-benchmark-report.mjs', ['--output', output]);
  assert.equal(result.code, 0, result.stderr);
  const report = JSON.parse(await readFile(output, 'utf8'));
  assert.equal(report.schemaVersion, 'ogvcs.chunking/selection-benchmark-report/v1');
  assert.equal(report.summary.workloadCount, 7);
});
