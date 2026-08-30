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
} from './chunking-selection-benchmark-bundle.mjs';
import { verifyChunkingSelectionBenchmarkBundle } from './verify-chunking-selection-benchmark-bundle.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const HOSTED_RECORD_PATH = join(ROOT, 'docs/evidence/OGVCS-007/github-actions-run-33328072458.json');
const CHECKED_IN_BUNDLE_PATH = join(ROOT, 'docs/evidence/OGVCS-007/bounded-selection-bundle-2026-08-30');
const CHECKED_IN_VALIDATION_PATH = join(ROOT, 'docs/evidence/OGVCS-007/bounded-selection-bundle-validation-2026-08-30.json');

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

test('chunking selection benchmark bundle emits an authenticated retained-evidence bundle that independent validation can replay', { timeout: 240_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-selection-bundle-'));
  t.after(() => rm(directory, { recursive: true, force: true }));

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
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-selection-bundle-incomplete-'));
  t.after(() => rm(directory, { recursive: true, force: true }));

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
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-selection-bundle-failed-'));
  t.after(() => rm(directory, { recursive: true, force: true }));

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

  const hostMutation = republishChunkingBundle(bundle, {
    captures: bundle.publication.result.publicMetadata.chunkingSelection.retainedCaptures.map((capture, index) => index === 0
      ? {
        ...capture,
        host: { ...capture.host, os: 'linux' },
      }
      : capture),
  });
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

test.skip('checked-in bounded selection bundle and retained validation report stay reproducible', async () => {
  const retained = JSON.parse(await readFile(CHECKED_IN_VALIDATION_PATH, 'utf8'));
  const replay = await verifyChunkingSelectionBenchmarkBundle(CHECKED_IN_BUNDLE_PATH);
  assert.deepEqual(replay, retained);
});
