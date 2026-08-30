import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { buildResultBundle, verifyResultBundle, writeResultBundle } from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  BUNDLE_PROFILE,
  DEFAULT_OPERATOR,
  DEFAULT_SEED,
  buildChunkingSelectionBenchmarkBundle,
  buildChunkingSelectionPublicMetadata,
  runWorker,
} from './chunking-selection-benchmark-bundle.mjs';
import {
  RETAINED_ERROR_MESSAGE_LIMIT,
  normalizeRetainedFailureError,
  stableFailureMessage,
  truncateUtf8Scalars,
} from './chunking-selection-benchmark-common.mjs';
import { verifyChunkingSelectionBenchmarkBundle } from './verify-chunking-selection-benchmark-bundle.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const HOSTED_RECORD_PATH = join(ROOT, 'docs/evidence/OGVCS-007/github-actions-run-33328072458.json');
const CHECKED_IN_BUNDLE_PATH = join(ROOT, 'docs/evidence/OGVCS-007/bounded-selection-bundle-2026-08-30');
const CHECKED_IN_VALIDATION_PATH = join(ROOT, 'docs/evidence/OGVCS-007/bounded-selection-bundle-validation-2026-08-30.json');
const WORKER_FIXTURE_PATH = join(ROOT, 'tools/fixtures/chunking-selection-benchmark-worker-fixture.mjs');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function republishChunkingBundle(bundle, options = {}) {
  const matrix = {
    ...bundle.matrix,
    ...(options.matrix ?? {}),
  };
  const captures = options.captures ?? bundle.publication.result.publicMetadata.chunkingSelection.retainedCaptures;
  const selectionReport = options.selectionReport ?? bundle.selectionReport;
  const publicMetadata = options.publicMetadata ?? buildChunkingSelectionPublicMetadata({
    thresholdFile: matrix.thresholdFile,
    selectionReport,
    captures,
  });
  return buildResultBundle(bundle.contract, matrix, {
    seed: DEFAULT_SEED,
    operator: DEFAULT_OPERATOR,
    classification: 'synthetic',
    clock: () => new Date(bundle.publication.result.createdAt),
    retentionDays: bundle.publication.result.redaction.retentionDays,
    publicMetadata,
    evidenceReport: bundle.publication.evidenceReport,
    faultSchedules: bundle.publication.result.faultSchedules,
  });
}

async function writeBundleInChildDirectory(root, contract, publication, label) {
  const directory = join(root, label);
  await writeResultBundle(directory, contract, publication);
  return directory;
}

async function unpublishedBundleDirectory(t, prefix) {
  const parent = await mkdtemp(join(tmpdir(), prefix));
  t.after(() => rm(parent, { recursive: true, force: true }));
  return join(parent, 'bundle');
}

function differentOs(current) {
  return current === 'linux' ? 'darwin' : 'linux';
}

async function waitForProcessExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
      await new Promise((resolve) => setTimeout(resolve, 10));
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ESRCH') return true;
      throw error;
    }
  }
  return false;
}

async function waitForPidFile(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const pid = Number((await readFile(path, 'utf8')).trim());
      if (Number.isSafeInteger(pid) && pid > 0) return pid;
    } catch (error) {
      if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'ENOENT') throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return null;
}

test('chunking selection benchmark bundle emits an authenticated retained-evidence bundle that independent validation can replay', { timeout: 240_000 }, async (t) => {
  const directory = await unpublishedBundleDirectory(t, 'ogvcs-chunking-selection-bundle-');

  const { contract, publication, selectionReport } = await buildChunkingSelectionBenchmarkBundle();
  await writeResultBundle(directory, contract, publication);

  const verified = await verifyResultBundle(directory, contract);
  const retained = await verifyChunkingSelectionBenchmarkBundle(directory);

  assert.equal(publication.result.schemaVersion, 'ogvcs.benchmark/result-bundle/v1');
  assert.equal(publication.result.reproduction.harnessProfile, BUNDLE_PROFILE);
  assert.equal(publication.result.reproduction.command, 'node tools/chunking-selection-benchmark-bundle.mjs --output <bundle-dir> --seed <recorded-seed>');
  assert.equal(publication.result.overallStatus, 'passed');
  assert.equal(verified.result.overallStatus, 'passed');
  assert.equal(retained.verified, true);
  assert.equal(retained.sampleCount, 7);
  assert.equal(retained.summaryCount, 7);
  assert.equal(selectionReport.implementation.publishedFileCount, 13);
  assert.deepEqual(
    publication.result.publicMetadata.chunkingSelection.retainedCaptures.map(({ workloadId, success }) => ({ workloadId, success })),
    ['source-like', 'structured', 'already-compressed', 'encrypted-random', 'insertion', 'replacement', 'append'].map((workloadId) => ({ workloadId, success: true })),
  );
});

test('incomplete captures stay retained and independently verify as incomplete rows', { timeout: 240_000 }, async (t) => {
  const directory = await unpublishedBundleDirectory(t, 'ogvcs-chunking-selection-bundle-incomplete-');

  const { contract, publication } = await buildChunkingSelectionBenchmarkBundle({
    mutateCaptures(captures) {
      return captures.map((capture) => capture.workloadId === 'append'
        ? (() => {
          const { workload, ...rest } = capture;
          return {
            ...rest,
          success: false,
          error: { code: 'HARNESS_TASK_INCOMPLETE', name: 'Error', message: 'synthetic retained failure for bundle validation' },
          process: {
            ...capture.process,
            peakMemoryBytes: Math.max(capture.process.peakMemoryBytes, 1),
          },
          };
        })()
        : capture);
    },
  });
  await writeResultBundle(directory, contract, publication);
  const verified = await verifyResultBundle(directory, contract);
  const retained = await verifyChunkingSelectionBenchmarkBundle(directory);

  assert.equal(publication.result.overallStatus, 'failed');
  assert.equal(verified.result.overallStatus, 'failed');
  assert.equal(retained.verified, true);
  assert.equal(publication.result.sampleCount, 7);
  assert.equal(publication.result.environmentCount, 7);
  assert.equal(publication.result.publicMetadata.chunkingSelection.retainedCaptures.length, 7);
  assert.equal(verified.samples.find(({ corpusId }) => corpusId === 'append')?.status, 'incomplete');
  assert.equal(
    verified.result.thresholdEvaluations.find(({ thresholdId }) => thresholdId === 'chunking-workloads-have-no-failed-samples')?.status,
    'passed',
  );
  assert.equal(
    verified.result.thresholdEvaluations.find(({ thresholdId }) => thresholdId === 'chunking-workloads-have-no-incomplete-samples')?.status,
    'failed',
  );
});

test('failed captures stay retained, unknown worker codes normalize, and the bundle cannot self-certify overall success', { timeout: 240_000 }, async (t) => {
  const directory = await unpublishedBundleDirectory(t, 'ogvcs-chunking-selection-bundle-failed-');

  const { contract, publication } = await buildChunkingSelectionBenchmarkBundle({
    mutateCaptures(captures) {
      return captures.map((capture) => capture.workloadId === 'append'
        ? (() => {
          const { workload, ...rest } = capture;
          return {
            ...rest,
          success: false,
          error: { code: 'WORKER_CUSTOM_FAILURE', name: 'Error', message: 'synthetic retained failed row for bundle validation' },
          };
        })()
        : capture);
    },
  });
  await writeResultBundle(directory, contract, publication);
  const verified = await verifyResultBundle(directory, contract);
  const retained = await verifyChunkingSelectionBenchmarkBundle(directory);

  assert.equal(publication.result.overallStatus, 'failed');
  assert.equal(verified.result.overallStatus, 'failed');
  assert.equal(retained.verified, true);
  assert.equal(verified.samples.find(({ corpusId }) => corpusId === 'append')?.status, 'failed');
  assert.equal(verified.samples.find(({ corpusId }) => corpusId === 'append')?.failureCode, 'HARNESS_DRIVER_FAILED');
  assert.equal(
    verified.result.thresholdEvaluations.find(({ thresholdId }) => thresholdId === 'chunking-workloads-have-no-failed-samples')?.status,
    'failed',
  );
  assert.equal(
    verified.result.thresholdEvaluations.find(({ thresholdId }) => thresholdId === 'chunking-workloads-have-no-incomplete-samples')?.status,
    'passed',
  );
});

test('worker bridge retains parent-observed wall time for bounded spawn, timeout, output, parse, and exit failures', async () => {
  const scenarios = [
    { label: 'spawn', options: { command: join(ROOT, 'tools/fixtures/does-not-exist') }, expectedCode: 'HARNESS_DRIVER_FAILED' },
    { label: 'timeout', options: { args: [WORKER_FIXTURE_PATH, '--mode', 'timeout', '--workload-id', 'append'], timeoutMs: 20 }, expectedCode: 'HARNESS_TASK_INCOMPLETE' },
    { label: 'overflow', options: { args: [WORKER_FIXTURE_PATH, '--mode', 'overflow', '--workload-id', 'append'], outputLimitBytes: 256 }, expectedCode: 'HARNESS_LIMIT_EXCEEDED' },
    { label: 'parse', options: { args: [WORKER_FIXTURE_PATH, '--mode', 'invalid-json', '--workload-id', 'append'], parseLimitBytes: 256 }, expectedCode: 'HARNESS_DRIVER_FAILED' },
    { label: 'exit', options: { args: [WORKER_FIXTURE_PATH, '--mode', 'exit-mismatch', '--workload-id', 'append'], parseLimitBytes: 256 }, expectedCode: 'HARNESS_DRIVER_FAILED' },
  ];
  for (const scenario of scenarios) {
    const capture = await runWorker('append', scenario.options);
    assert.equal(capture.success, false, scenario.label);
    assert.equal(capture.error.code, scenario.expectedCode, scenario.label);
    assert.equal(capture.process.totalWallMicroseconds > 0, true, scenario.label);
    assert.equal(capture.process.sampleIntervalMs > 0, true, scenario.label);
  }
});

test('UTF-8 byte truncation stays scalar-safe and retained failure normalization is idempotent', () => {
  const boundary = `${'a'.repeat(RETAINED_ERROR_MESSAGE_LIMIT - 3)}😀`;
  const truncated = truncateUtf8Scalars(boundary, RETAINED_ERROR_MESSAGE_LIMIT, 'fallback');
  assert.equal(Buffer.byteLength(truncated, 'utf8'), RETAINED_ERROR_MESSAGE_LIMIT - 3);
  assert.equal(truncated, 'a'.repeat(RETAINED_ERROR_MESSAGE_LIMIT - 3));
  assert.doesNotMatch(truncated, /[\uD800-\uDFFF]/u);

  const normalized = normalizeRetainedFailureError({ code: 'HARNESS_DRIVER_FAILED', message: boundary });
  assert.deepEqual(normalizeRetainedFailureError(normalized), normalized);
});

test('retained failure normalization is path-neutral across POSIX, drive, and UNC-looking inputs', () => {
  for (const message of [
    '/workspace/build/output/error.log',
    '/builds/team/project/secret.txt',
    '/srv/app/releases/current/runtime.json',
    'D:/build/output/runtime.txt',
    'D:\\build\\output\\runtime.txt',
    '\\\\server\\share\\secrets\\runtime.txt',
  ]) {
    const normalized = normalizeRetainedFailureError({ code: 'UNREGISTERED_FAILURE', name: 'TypeError', message });
    assert.deepEqual(normalized, {
      code: 'HARNESS_DRIVER_FAILED',
      name: 'Error',
      message: stableFailureMessage('HARNESS_DRIVER_FAILED'),
    });
  }
});

test('worker timeout keeps escalation armed after direct child exit and kills lingering inherited-pipe grandchildren', {
  skip: process.platform === 'win32' ? 'POSIX-specific process-group kill assertion' : false,
  timeout: 10_000,
}, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-worker-timeout-'));
  const pidFile = join(directory, 'grandchild.pid');
  let pid = null;
  t.after(async () => {
    try {
      if (pid === null) pid = await waitForPidFile(pidFile, 50);
      if (pid === null || await waitForProcessExit(pid, 20)) return;
      try {
        process.kill(pid, 'SIGKILL');
      } catch (error) {
        if (!error || typeof error !== 'object' || !('code' in error) || error.code !== 'ESRCH') throw error;
        return;
      }
      await waitForProcessExit(pid, 1_000);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
  const started = Date.now();
  const capturePromise = runWorker('append', {
    args: [WORKER_FIXTURE_PATH, '--mode', 'exit-on-term-grandchild-inherits-pipes', '--workload-id', 'append', '--pid-file', pidFile],
    timeoutMs: 1_000,
    terminateGraceMs: 20,
    terminateKillWaitMs: 20,
  });
  pid = await waitForPidFile(pidFile, 750);
  const capture = await capturePromise;
  const elapsedMs = Date.now() - started;
  assert.notEqual(pid, null, 'worker fixture did not publish its grandchild PID before the timeout window');
  assert.equal(capture.success, false);
  assert.equal(capture.error.code, 'HARNESS_TASK_INCOMPLETE');
  assert.equal(capture.process.totalWallMicroseconds >= 1_000_000, true);
  assert.equal(elapsedMs < 3_000, true);
  assert.equal(await waitForProcessExit(pid, 1_000), true);
});

test('producer normalizes failed retained captures to the shared publication limit with stable path-neutral messages', { timeout: 240_000 }, async (t) => {
  const directory = await unpublishedBundleDirectory(t, 'ogvcs-chunking-selection-bundle-normalized-failure-');
  const overlongMessage = `${'a'.repeat(RETAINED_ERROR_MESSAGE_LIMIT - 3)}😀`;

  const { contract, publication } = await buildChunkingSelectionBenchmarkBundle({
    mutateCaptures(captures) {
      return captures.map((capture) => capture.workloadId === 'append'
        ? (() => {
          const { workload, ...rest } = capture;
          return {
            ...rest,
            success: false,
            error: { code: 'UNREGISTERED_FAILURE', name: 'TypeError', message: overlongMessage },
          };
        })()
        : capture);
    },
  });
  const retainedCapture = publication.result.publicMetadata.chunkingSelection.retainedCaptures.find(({ workloadId }) => workloadId === 'append');
  assert.ok(retainedCapture);
  assert.equal(retainedCapture.error.code, 'HARNESS_DRIVER_FAILED');
  assert.equal(retainedCapture.error.name, 'Error');
  assert.equal(Buffer.byteLength(retainedCapture.error.message, 'utf8') <= RETAINED_ERROR_MESSAGE_LIMIT, true);
  assert.equal(retainedCapture.error.message, stableFailureMessage('HARNESS_DRIVER_FAILED'));
  assert.doesNotMatch(retainedCapture.error.message, /\/workspace\/|\/builds\/|\/srv\/|[A-Za-z]:[\\/]|\\\\server\\/u);

  await writeResultBundle(directory, contract, publication);
  const verified = await verifyResultBundle(directory, contract);
  const retained = await verifyChunkingSelectionBenchmarkBundle(directory);
  assert.equal(verified.samples.find(({ corpusId }) => corpusId === 'append')?.failureCode, 'HARNESS_DRIVER_FAILED');
  assert.equal(retained.verified, true);
});

test('chunking publisher and verifier reject corpus-authority and metadata tampering', { timeout: 240_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-selection-bundle-mutations-'));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const bundle = await buildChunkingSelectionBenchmarkBundle();
  const firstEnvironment = bundle.matrix.environmentRecords[0];
  assert.throws(() => republishChunkingBundle(bundle, {
    matrix: {
      environmentRecords: bundle.matrix.environmentRecords.map((environment, index) => index === 0
        ? {
          ...environment,
          corpus: {
            ...environment.corpus,
            manifestDigest: '0'.repeat(64),
          },
        }
        : environment),
    },
  }), (error) => error.code === 'HARNESS_INPUT_INVALID');

  const thresholdMutation = republishChunkingBundle(bundle, {
    publicMetadata: {
      ...bundle.publication.result.publicMetadata,
      chunkingSelection: {
        ...bundle.publication.result.publicMetadata.chunkingSelection,
        bundleThresholdIds: ['forged-threshold'],
      },
    },
  });
  const thresholdDirectory = await writeBundleInChildDirectory(directory, bundle.contract, thresholdMutation, 'threshold');
  await assert.rejects(verifyChunkingSelectionBenchmarkBundle(thresholdDirectory), /threshold/i);

  const requestDigestMutation = republishChunkingBundle(bundle, {
    matrix: {
      environmentRecords: bundle.matrix.environmentRecords.map((environment, index) => index === 0
        ? {
          ...environment,
          corpus: {
            ...environment.corpus,
            requestDigest: '1'.repeat(64),
          },
        }
        : environment),
    },
  });
  const requestDigestDirectory = await writeBundleInChildDirectory(directory, bundle.contract, requestDigestMutation, 'request-digest');
  await assert.rejects(verifyChunkingSelectionBenchmarkBundle(requestDigestDirectory), /environment corpus authority drifted/u);

  const tamperedOs = differentOs(bundle.publication.result.publicMetadata.chunkingSelection.retainedCaptures[0].host.os);
  assert.notEqual(tamperedOs, bundle.publication.result.publicMetadata.chunkingSelection.retainedCaptures[0].host.os);
  const hostMutation = republishChunkingBundle(bundle, {
    captures: bundle.publication.result.publicMetadata.chunkingSelection.retainedCaptures.map((capture, index) => index === 0
      ? {
        ...capture,
        host: { ...capture.host, os: tamperedOs },
      }
      : capture),
  });
  assert.equal(hostMutation.result.publicMetadata.chunkingSelection.retainedCaptures[0].host.os, tamperedOs);
  const hostDirectory = await writeBundleInChildDirectory(directory, bundle.contract, hostMutation, 'host');
  await assert.rejects(verifyChunkingSelectionBenchmarkBundle(hostDirectory), /host/i);

  const extraFieldMutation = republishChunkingBundle(bundle, {
    publicMetadata: {
      ...bundle.publication.result.publicMetadata,
      chunkingSelection: {
        ...bundle.publication.result.publicMetadata.chunkingSelection,
        extraClaim: true,
      },
    },
  });
  const extraFieldDirectory = await writeBundleInChildDirectory(directory, bundle.contract, extraFieldMutation, 'extra-field');
  await assert.rejects(verifyChunkingSelectionBenchmarkBundle(extraFieldDirectory), /chunkingSelection/u);

  const swappedWorkloadMutation = republishChunkingBundle(bundle, {
    captures: bundle.publication.result.publicMetadata.chunkingSelection.retainedCaptures.map((capture, index, captures) => index === 0
      ? { ...capture, workload: captures[1].workload }
      : index === 1
        ? { ...capture, workload: captures[0].workload }
        : capture),
  });
  const swappedWorkloadDirectory = await writeBundleInChildDirectory(directory, bundle.contract, swappedWorkloadMutation, 'swapped-workload');
  await assert.rejects(verifyChunkingSelectionBenchmarkBundle(swappedWorkloadDirectory), /workload id/u);

  assert.equal(firstEnvironment.configuration.harnessProfile, BUNDLE_PROFILE);
});

test('retained six-leg hosted reports match their run record and comparator', async () => {
  const record = JSON.parse(await readFile(HOSTED_RECORD_PATH, 'utf8'));
  assert.equal(record.schemaVersion, 'ogvcs.chunking/hosted-evidence/v1');
  assert.equal(record.status, 'bounded-current-source-passed');
  assert.equal(record.exactScaleExecuted, false);
  assert.equal(record.workflow.runId, 33328072458);
  assert.equal(record.sourceRevision, 'b098c3e2b8377fdf4cc2ec152e8a6b7b6f37f383');
  assert.equal(record.jobs.length, 7);
  assert.equal(record.jobs.every(({ conclusion }) => conclusion === 'success'), true);
  assert.equal(record.artifacts.length, 6);
  assert.equal(record.remainingGates.some((gate) => gate.includes('production acceptor')), true);
  assert.equal(record.remainingGates.some((gate) => gate.includes('completion/release campaign')), true);

  const expectedArtifactNames = [
    'chunking-javascript-Linux', 'chunking-javascript-macOS', 'chunking-javascript-Windows',
    'chunking-rust-Linux', 'chunking-rust-macOS', 'chunking-rust-Windows',
  ];
  assert.deepEqual(record.artifacts.map(({ name }) => name), expectedArtifactNames);

  const reports = new Map();
  for (const retained of record.retainedReports) {
    const path = join(ROOT, 'docs/evidence/OGVCS-007', retained.path);
    const bytes = await readFile(path);
    assert.equal(bytes.length, retained.bytes);
    assert.equal(sha256(bytes), retained.sha256);
    const report = JSON.parse(bytes);
    assert.equal(report.schemaVersion, 'ogvcs.chunking/bounded-conformance-report/v1');
    assert.equal(report.profile, 'chunking.opengamevcs/gear-fastcdc-1m@1');
    assert.deepEqual(retained.identicalAcross, ['Linux', 'macOS', 'Windows']);
    reports.set(retained.language, path);
  }

  const reportPaths = [];
  for (const artifact of record.artifacts) {
    const path = join(ROOT, 'docs/evidence/OGVCS-007', artifact.retainedReportPath);
    const bytes = await readFile(path);
    assert.equal(bytes.length, artifact.reportBytes);
    assert.equal(sha256(bytes), artifact.reportSha256);
    const language = artifact.name.includes('javascript') ? 'javascript' : 'rust';
    assert.equal(path, reports.get(language));
    reportPaths.push(path);
  }
  const comparison = spawnSync(process.execPath, [
    join(ROOT, 'core/chunking-manifest/js/scripts/compare-bounded-reports.mjs'),
    ...reportPaths,
  ], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(comparison.status, 0, comparison.stderr);
  assert.equal(comparison.stdout.trim(), record.comparison.result);
});

test('checked-in bounded selection bundle and retained validation report stay reproducible', async () => {
  const retained = JSON.parse(await readFile(CHECKED_IN_VALIDATION_PATH, 'utf8'));
  const replay = await verifyChunkingSelectionBenchmarkBundle(CHECKED_IN_BUNDLE_PATH);
  assert.deepEqual(replay, retained);
});
