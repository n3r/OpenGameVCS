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
  assert.equal(report.summary.thresholdFailureCount, 0);
  assert.equal(report.workloads.find(({ workloadId }) => workloadId === 'encrypted-random').compare.reusedBytes, '0');
  assert.equal(report.workloads.find(({ workloadId }) => workloadId === 'insertion').deltas.resynchronization.resynchronizationDistanceBytes, 218510);
  assert.equal(report.workloads.find(({ workloadId }) => workloadId === 'replacement').deltas.resynchronization.resynchronizationDistanceBytes, 895195);
  assert.deepEqual(report.sourceIdentity, {
    entryCount: report.sourceIdentity.entryCount,
    sourceSetSha256: report.sourceIdentity.sourceSetSha256,
    type: 'selection-benchmark-source-set/v1',
  });
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

test('every behavioral threshold can fail the report and forces overallStatus failed', { timeout: 120_000 }, async () => {
  const baseline = await buildChunkingSelectionReport();
  const scenarios = [
    { thresholdId: 'source-like-retains-material-reuse' },
    { thresholdId: 'structured-retains-material-reuse' },
    {
      thresholdId: 'compressed-observes-poor-reuse',
      mutateWorkloads(workloads) {
        return workloads.map((row) => row.workloadId === 'already-compressed'
          ? { ...row, compare: { ...row.compare, reusedBytes: '262145' } }
          : row);
      },
    },
    {
      thresholdId: 'random-observes-no-reuse',
      mutateWorkloads(workloads) {
        return workloads.map((row) => row.workloadId === 'encrypted-random'
          ? { ...row, compare: { ...row.compare, reusedBytes: '1' } }
          : row);
      },
    },
    { thresholdId: 'insertion-resynchronizes-boundedly' },
    { thresholdId: 'replacement-resynchronizes-boundedly' },
    { thresholdId: 'append-limits-new-tail-bytes' },
  ];
  for (const { thresholdId, mutateWorkloads } of scenarios) {
    const current = baseline.thresholdEvaluations.find((row) => row.thresholdId === thresholdId);
    assert.ok(current, thresholdId);
    const thresholdFile = structuredClone(baseline.thresholdFile);
    const entry = thresholdFile.entries.find((row) => row.id === thresholdId);
    assert.ok(entry, thresholdId);
    if (mutateWorkloads === undefined) {
      entry.value = entry.operator === 'minimum' ? current.actual + 1 : current.actual - 1;
    }
    const mutated = await buildChunkingSelectionReport({ mutateWorkloads, thresholdFile });
    assert.equal(mutated.overallStatus, 'failed', thresholdId);
    assert.equal(mutated.summary.thresholdFailureCount >= 1, true, thresholdId);
    assert.equal(mutated.thresholdEvaluations.find((row) => row.thresholdId === thresholdId)?.status, 'failed', thresholdId);
  }
});

test('a failed workload cannot emit a passed report', { timeout: 120_000 }, async () => {
  const report = await buildChunkingSelectionReport({
    mutateWorkloads(workloads) {
      return workloads.map((row) => row.workloadId === 'append' ? { ...row, success: false } : row);
    },
  });
  assert.equal(report.overallStatus, 'failed');
  assert.equal(report.thresholdEvaluations.find((row) => row.thresholdId === 'all-seven-workloads-succeed')?.status, 'failed');
});
