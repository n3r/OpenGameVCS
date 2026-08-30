#!/usr/bin/env node

import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalDigest,
  canonicalJson as benchmarkCanonicalJson,
  evaluateThresholds,
  loadBenchmarkContract,
  summarizeSamples,
  verifyResultBundle,
} from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  RETAINED_ERROR_MESSAGE_LIMIT,
  ROOT,
  RETAINED_BUNDLE_SOURCE_PATHS,
  buildChunkingSelectionReport,
  buildSelectionReportFromWorkloads,
  canonicalJson,
  loadSelectionAuthority,
  normalizeRetainedFailureError,
  sha256,
  stableFailureCode,
} from './chunking-selection-benchmark-common.mjs';
import { BUNDLE_PROFILE, BUNDLE_TASK, CHILD_MAX_RSS_SOURCE, PROCESS_PEAK_SOURCE } from './chunking-selection-benchmark-bundle.mjs';

function parseArguments(argv) {
  const options = { output: null };
  for (let index = 0; index < argv.length; index += 2) {
    if (index + 1 >= argv.length) throw new Error('usage: node tools/verify-chunking-selection-benchmark-bundle.mjs --bundle <bundle-dir> [--output <report.json>]');
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--bundle') options.bundle = resolve(process.cwd(), value);
    else if (flag === '--output') options.output = resolve(process.cwd(), value);
    else throw new Error(`unknown argument ${flag}`);
  }
  if (!options.bundle) throw new Error('usage: node tools/verify-chunking-selection-benchmark-bundle.mjs --bundle <bundle-dir> [--output <report.json>]');
  return options;
}

function stripMeasuredFields(report) {
  return {
    contractManifestSha256: report.contractManifestSha256,
    exactScaleExecuted: report.exactScaleExecuted,
    implementation: report.implementation,
    overallStatus: report.overallStatus,
    profile: report.profile,
    scalarWorkingMemoryBytesMinimum: report.scalarWorkingMemoryBytesMinimum,
    schemaVersion: report.schemaVersion,
    sourceIdentity: report.sourceIdentity,
    summary: report.summary,
    thresholdEvaluations: report.thresholdEvaluations,
    thresholdFile: report.thresholdFile,
    thresholdFileDigest: report.thresholdFileDigest,
    workloadDefinitionsDigest: report.workloadDefinitionsDigest,
    workloads: report.workloads.map((row) => ({
      accounting: row.accounting,
      base: {
        ledger: row.base.ledger,
        logicalBytes: row.base.logicalBytes,
        manifestBytes: row.base.manifestBytes,
        partCount: row.base.partCount,
        wholeFileSha256: row.base.wholeFileSha256,
      },
      candidate: {
        ledger: row.candidate.ledger,
        logicalBytes: row.candidate.logicalBytes,
        manifestBytes: row.candidate.manifestBytes,
        partCount: row.candidate.partCount,
        wholeFileSha256: row.candidate.wholeFileSha256,
      },
      class: row.class,
      compare: {
        ledger: row.compare.ledger,
        logicalBytes: row.compare.logicalBytes,
        manifestObjectId: row.compare.manifestObjectId,
        newlyRequiredBytes: row.compare.newlyRequiredBytes,
        partCount: row.compare.partCount,
        repeatedBytes: row.compare.repeatedBytes,
        reusedBytes: row.compare.reusedBytes,
        uniqueBytes: row.compare.uniqueBytes,
        uniqueChunks: row.compare.uniqueChunks,
      },
      deltas: row.deltas,
      description: row.description,
      exactScaleExecuted: row.exactScaleExecuted,
      mutationKind: row.mutationKind,
      schemaVersion: row.schemaVersion,
      success: row.success,
      verify: {
        ledger: row.verify.ledger,
        logicalBytes: row.verify.logicalBytes,
        manifestObjectId: row.verify.manifestObjectId,
        partCount: row.verify.partCount,
        providerReads: row.verify.providerReads,
        repeatedBytes: row.verify.repeatedBytes,
        uniqueBytes: row.verify.uniqueBytes,
      },
      workloadId: row.workloadId,
    })),
  };
}

function correctedWallMicroseconds(totalWallMicroseconds, overhead) {
  return overhead?.correctionApplied ? Math.max(0, totalWallMicroseconds - overhead.correctionMicroseconds) : totalWallMicroseconds;
}

function throughputBytesPerSecond(bytes, elapsedMicroseconds) {
  assert.equal(Number.isSafeInteger(bytes) && bytes >= 0, true, 'throughput bytes must be a non-negative safe integer');
  assert.equal(Number.isSafeInteger(elapsedMicroseconds) && elapsedMicroseconds >= 0, true, 'elapsed microseconds must be a non-negative safe integer');
  return elapsedMicroseconds === 0 ? bytes * 1_000_000 : Math.floor((bytes * 1_000_000) / elapsedMicroseconds);
}

function stripStaticReportFields(report) {
  return {
    contractManifestSha256: report.contractManifestSha256,
    exactScaleExecuted: report.exactScaleExecuted,
    implementation: report.implementation,
    profile: report.profile,
    scalarWorkingMemoryBytesMinimum: report.scalarWorkingMemoryBytesMinimum,
    schemaVersion: report.schemaVersion,
    sourceIdentity: report.sourceIdentity,
    thresholdFile: report.thresholdFile,
    thresholdFileDigest: report.thresholdFileDigest,
    workloadDefinitionsDigest: report.workloadDefinitionsDigest,
  };
}

function stripWorkloadFields(row) {
  return {
    accounting: row.accounting,
    base: {
      ledger: row.base.ledger,
      logicalBytes: row.base.logicalBytes,
      manifestBytes: row.base.manifestBytes,
      partCount: row.base.partCount,
      wholeFileSha256: row.base.wholeFileSha256,
    },
    candidate: {
      ledger: row.candidate.ledger,
      logicalBytes: row.candidate.logicalBytes,
      manifestBytes: row.candidate.manifestBytes,
      partCount: row.candidate.partCount,
      wholeFileSha256: row.candidate.wholeFileSha256,
    },
    class: row.class,
    compare: {
      ledger: row.compare.ledger,
      logicalBytes: row.compare.logicalBytes,
      manifestObjectId: row.compare.manifestObjectId,
      newlyRequiredBytes: row.compare.newlyRequiredBytes,
      partCount: row.compare.partCount,
      repeatedBytes: row.compare.repeatedBytes,
      reusedBytes: row.compare.reusedBytes,
      uniqueBytes: row.compare.uniqueBytes,
      uniqueChunks: row.compare.uniqueChunks,
    },
    deltas: row.deltas,
    description: row.description,
    exactScaleExecuted: row.exactScaleExecuted,
    mutationKind: row.mutationKind,
    schemaVersion: row.schemaVersion,
    success: row.success,
    verify: {
      ledger: row.verify.ledger,
      logicalBytes: row.verify.logicalBytes,
      manifestObjectId: row.verify.manifestObjectId,
      partCount: row.verify.partCount,
      providerReads: row.verify.providerReads,
      repeatedBytes: row.verify.repeatedBytes,
      uniqueBytes: row.verify.uniqueBytes,
    },
    workloadId: row.workloadId,
  };
}

function expectedChunkingRequestDigest(definition) {
  return sha256({
    baseRecipe: definition.baseRecipe,
    candidateRecipe: definition.candidateRecipe,
    class: definition.class,
    mutationKind: definition.mutationKind,
    workloadId: definition.workloadId,
  });
}

function assertRetainedCapture(capture, environment) {
  assert.equal(capture?.schemaVersion, 'ogvcs.chunking/selection-workload-capture/v1');
  assert.deepEqual(Object.keys(capture).sort(), capture.success ? ['host', 'process', 'schemaVersion', 'success', 'workload', 'workloadId'] : ['error', 'host', 'process', 'schemaVersion', 'success', 'workloadId']);
  assert.equal(typeof capture?.workloadId, 'string');
  assert.equal(typeof capture?.success, 'boolean');
  assert.deepEqual(Object.keys(capture.host ?? {}).sort(), ['architecture', 'node', 'os']);
  assert.deepEqual(Object.keys(capture.process ?? {}).sort(), ['maxRssBytes', 'maxRssSource', 'peakMemoryBytes', 'sampleIntervalMs', 'sampledPeakRssBytes', 'systemCpuMicroseconds', 'totalWallMicroseconds', 'userCpuMicroseconds']);
  for (const key of ['peakMemoryBytes', 'sampledPeakRssBytes', 'maxRssBytes', 'sampleIntervalMs', 'userCpuMicroseconds', 'systemCpuMicroseconds', 'totalWallMicroseconds']) {
    assert.equal(Number.isSafeInteger(capture.process[key]), true, key);
    assert.equal(capture.process[key] >= 0, true, key);
  }
  assert.equal(capture.process.sampleIntervalMs > 0, true);
  assert.equal(capture.success ? capture.process.sampledPeakRssBytes > 0 : capture.process.sampledPeakRssBytes >= 0, true);
  assert.equal(capture.success ? capture.process.peakMemoryBytes > 0 : capture.process.peakMemoryBytes >= 0, true);
  assert.equal(capture.process.peakMemoryBytes, Math.max(capture.process.sampledPeakRssBytes, capture.process.maxRssBytes));
  assert.equal(capture.process.maxRssSource, capture.process.maxRssBytes > 0 ? CHILD_MAX_RSS_SOURCE : 'unavailable');
  if (capture.success) assert.equal(capture.workload?.workloadId, capture.workloadId, 'retained capture workload id must match its inner workload id');
  assert.equal(capture.host.architecture, environment.hardware.architecture);
  assert.equal(capture.host.os, environment.platform.os);
  assert.equal(`v${capture.host.node}`, environment.platform.nodeVersion);
  if (capture.success) {
    assert.equal(typeof capture.workload, 'object');
    assert.equal(capture.error, undefined);
  } else {
    assert.deepEqual(Object.keys(capture.error ?? {}).sort(), ['code', 'message', 'name']);
    assert.equal(
      benchmarkCanonicalJson(capture.error),
      benchmarkCanonicalJson(normalizeRetainedFailureError(capture.error)),
      'failed retained capture error must be normalized',
    );
    assert.equal(Buffer.byteLength(capture.error.message, 'utf8') <= RETAINED_ERROR_MESSAGE_LIMIT, true, 'failed retained capture error message exceeds the shared publication limit');
  }
}

function assertWorkloadTimingInvariants(workload, capture) {
  assert.deepEqual(Object.keys(workload.base).sort(), ['generationMicroseconds', 'ledger', 'logicalBytes', 'manifestBytes', 'partCount', 'throughputBytesPerSecond', 'wholeFileSha256']);
  assert.deepEqual(Object.keys(workload.candidate).sort(), ['generationMicroseconds', 'ledger', 'logicalBytes', 'manifestBytes', 'partCount', 'throughputBytesPerSecond', 'wholeFileSha256']);
  assert.deepEqual(Object.keys(workload.compare).sort(), ['compareMicroseconds', 'ledger', 'logicalBytes', 'manifestObjectId', 'newlyRequiredBytes', 'partCount', 'repeatedBytes', 'reusedBytes', 'throughputBytesPerSecond', 'uniqueBytes', 'uniqueChunks']);
  assert.deepEqual(Object.keys(workload.verify).sort(), ['ledger', 'logicalBytes', 'manifestObjectId', 'partCount', 'providerReads', 'repeatedBytes', 'throughputBytesPerSecond', 'uniqueBytes', 'verifyMicroseconds']);
  for (const value of [
    workload.base.generationMicroseconds,
    workload.candidate.generationMicroseconds,
    workload.compare.compareMicroseconds,
    workload.verify.verifyMicroseconds,
    workload.base.throughputBytesPerSecond,
    workload.candidate.throughputBytesPerSecond,
    workload.compare.throughputBytesPerSecond,
    workload.verify.throughputBytesPerSecond,
  ]) {
    assert.equal(Number.isSafeInteger(value) && value >= 0, true, 'timing/throughput fields must be non-negative safe integers');
  }
  assert.equal(workload.base.throughputBytesPerSecond, throughputBytesPerSecond(workload.base.logicalBytes, workload.base.generationMicroseconds));
  assert.equal(workload.candidate.throughputBytesPerSecond, throughputBytesPerSecond(workload.candidate.logicalBytes, workload.candidate.generationMicroseconds));
  assert.equal(workload.compare.throughputBytesPerSecond, throughputBytesPerSecond(Number(workload.compare.logicalBytes), workload.compare.compareMicroseconds));
  assert.equal(workload.verify.throughputBytesPerSecond, throughputBytesPerSecond(Number(workload.verify.logicalBytes), workload.verify.verifyMicroseconds));
  assert.equal(
    capture.process.totalWallMicroseconds >= (
      workload.base.generationMicroseconds
      + workload.candidate.generationMicroseconds
      + workload.compare.compareMicroseconds
      + workload.verify.verifyMicroseconds
    ),
    true,
    'child wall time must cover sequential stage timings',
  );
}

function captureClaimsValid(workload) {
  if (!workload) return false;
  const compare = workload.compare;
  const verify = workload.verify;
  return Number(compare.reusedBytes) + Number(compare.newlyRequiredBytes) === Number(compare.uniqueBytes)
    && Number(compare.logicalBytes) === Number(compare.uniqueBytes) + Number(compare.repeatedBytes)
    && Number(verify.uniqueBytes) === Number(compare.uniqueBytes)
    && Number(verify.repeatedBytes) === Number(compare.repeatedBytes)
    && verify.logicalBytes === compare.logicalBytes;
}

function thresholdRowsForWorkload(thresholdFile, workload) {
  return thresholdFile.entries.map((entry) => {
    if (!['*', workload.workloadId].includes(entry.workloadId)) return null;
    let actual;
    switch (entry.metric) {
      case 'reusedBytes':
        actual = Number(workload.compare.reusedBytes);
        break;
      case 'newlyRequiredBytes':
        actual = Number(workload.compare.newlyRequiredBytes);
        break;
      case 'resynchronizationDistanceBytes':
        actual = workload.deltas.resynchronization.resynchronizationDistanceBytes ?? Number.MAX_SAFE_INTEGER;
        break;
      default:
        return null;
    }
    return { thresholdId: entry.id, workloadId: workload.workloadId, status: entry.operator === 'maximum' ? (actual <= entry.value ? 'passed' : 'failed') : (actual >= entry.value ? 'passed' : 'failed') };
  }).filter(Boolean);
}

function sampleFromRetainedCapture(capture, thresholdFile, overhead) {
  const workload = capture.workload;
  const workloadThresholds = workload ? thresholdRowsForWorkload(thresholdFile, workload).filter(({ workloadId }) => workloadId === capture.workloadId) : [];
  const assertions = [
    { id: 'chunking-accounting-balanced', passed: workload?.accounting?.balanced === true },
    { id: 'chunking-derived-claims-recomputed', passed: capture.success === true && captureClaimsValid(workload) },
    { id: 'chunking-thresholds-held', passed: capture.success === true && workloadThresholds.every(({ status }) => status === 'passed') },
  ];
  const status = capture.success === false
    ? stableFailureCode(capture.error.code) === 'HARNESS_TASK_INCOMPLETE' ? 'incomplete' : 'failed'
    : assertions.every(({ passed }) => passed) ? 'success' : 'failed';
  return {
    schemaVersion: 'ogvcs.benchmark/sample/v1',
    id: `sample/${capture.workloadId}/cold/loopback-simulated/${BUNDLE_TASK}/0`,
    taskId: BUNDLE_TASK,
    corpusId: capture.workloadId,
    repetition: 0,
    cacheState: 'cold',
    networkProfile: 'loopback-simulated',
    status,
    failureCode: status === 'success' ? null : capture.success === false ? stableFailureCode(capture.error.code) : 'HARNESS_ASSERTION_FAILED',
    wallMicroseconds: correctedWallMicroseconds(capture.process.totalWallMicroseconds, overhead),
    cpuMicroseconds: capture.process.userCpuMicroseconds + capture.process.systemCpuMicroseconds,
    peakMemoryBytes: capture.process.peakMemoryBytes,
    diskReadBytes: 0,
    diskWriteBytes: 0,
    networkReadBytes: 0,
    networkWriteBytes: 0,
    logicalBytes: workload?.candidate?.logicalBytes ?? 0,
    uniqueBytes: workload ? Number(workload.compare.uniqueBytes) : 0,
    retries: 0,
    assertions,
    faultScheduleDigest: null,
  };
}

export async function verifyChunkingSelectionBenchmarkBundle(bundleDirectory) {
  const contract = await loadBenchmarkContract({ root: join(ROOT, 'spec/benchmark-fault/v1'), cache: false });
  const verified = await verifyResultBundle(bundleDirectory, contract);
  assert.deepEqual(Object.keys(verified.result.publicMetadata ?? {}).sort(), ['benchmarkProfile', 'chunkingSelection', 'exactScaleExecuted', 'schemaVersion']);
  assert.equal(verified.result.publicMetadata?.schemaVersion, 'ogvcs.chunking/selection-benchmark-retained-evidence/v1');
  assert.equal(verified.result.publicMetadata?.exactScaleExecuted, false);
  assert.equal(verified.result.publicMetadata?.benchmarkProfile, BUNDLE_PROFILE);
  assert.equal(verified.result.reproduction.harnessProfile, BUNDLE_PROFILE);
  const expectedThresholdFile = contract.thresholds['chunking-selection-bounded-v1'];
  const expectedThresholdDigest = canonicalDigest(expectedThresholdFile, 'ogvcs.benchmark/thresholds/v1');
  assert.equal(benchmarkCanonicalJson(verified.result.thresholdFile), benchmarkCanonicalJson(expectedThresholdFile), 'bundle threshold authority must equal chunking-selection-bounded-v1');
  assert.equal(verified.result.thresholdFileDigest, expectedThresholdDigest);
  const metadata = verified.result.publicMetadata?.chunkingSelection;
  assert.ok(metadata, 'bundle public metadata is missing chunking selection evidence');
  assert.deepEqual(
    Object.keys(metadata).sort(),
    ['bundleThresholdFileDigest', 'bundleThresholdFileOwner', 'bundleThresholdIds', 'processPeakSource', 'reportJson', 'retainedCaptures'],
    'chunkingSelection metadata envelope is invalid',
  );
  assert.equal(metadata.processPeakSource, PROCESS_PEAK_SOURCE);
  assert.equal(metadata.bundleThresholdFileDigest, expectedThresholdDigest);
  assert.equal(metadata.bundleThresholdFileOwner, expectedThresholdFile.owner);
  assert.deepEqual(metadata.bundleThresholdIds, expectedThresholdFile.entries.map(({ id }) => id));
  const retainedReport = JSON.parse(metadata.reportJson);
  assert.deepEqual(Object.keys(retainedReport).sort(), ['contractManifestSha256', 'exactScaleExecuted', 'generatedAt', 'host', 'implementation', 'overallStatus', 'profile', 'reportSha256', 'scalarWorkingMemoryBytesMinimum', 'schemaVersion', 'sourceIdentity', 'summary', 'thresholdEvaluations', 'thresholdFile', 'thresholdFileDigest', 'workloadDefinitionsDigest', 'workloads']);
  const captures = metadata.retainedCaptures;
  assert.ok(Array.isArray(captures) && captures.length === 7, 'bundle must retain seven workload captures');
  const captureIds = captures.map(({ workloadId }) => workloadId);
  assert.deepEqual(captureIds, ['source-like', 'structured', 'already-compressed', 'encrypted-random', 'insertion', 'replacement', 'append']);
  assert.equal(canonicalJson(retainedReport.host), canonicalJson(captures[0].host), 'retained report host must equal the child capture host');
  assert.equal(captures.every(({ host }) => canonicalJson(host) === canonicalJson(captures[0].host)), true, 'all retained captures must share one host identity');

  const { contract: chunkingContract, packageJson, workloadFile } = await loadSelectionAuthority();
  const chunkingManifestSha256 = sha256(await readFile(join(ROOT, 'spec/chunking-manifest/v1/manifest.json')));
  const expectedCorpora = new Map(workloadFile.workloads.map((definition) => [definition.workloadId, {
    profileId: definition.workloadId,
    profileVersion: '0.1.0-rc.1',
    requestDigest: expectedChunkingRequestDigest(definition),
    manifestDigest: chunkingManifestSha256,
    generatorVersion: '1.0.0',
  }]));
  assert.equal(verified.environmentRecords.length, captureIds.length);
  const expectedImplementationCommit = canonicalDigest(retainedReport.sourceIdentity.sourceSetSha256, 'ogvcs.benchmark/implementation-commit/v1');
  for (const environment of verified.environmentRecords) {
    const expectedCorpus = expectedCorpora.get(environment.corpus.profileId);
    assert.ok(expectedCorpus, environment.corpus.profileId);
    assert.equal(benchmarkCanonicalJson(environment.corpus), benchmarkCanonicalJson(expectedCorpus), 'environment corpus authority drifted');
    assert.equal(environment.configuration.harnessProfile, BUNDLE_PROFILE);
    assert.equal(environment.implementation.id, 'ogvcs.chunking-manifest/javascript@1');
    assert.equal(environment.implementation.version, retainedReport.implementation.version);
    assert.equal(environment.implementation.version, packageJson.version);
    assert.equal(environment.implementation.commit, expectedImplementationCommit);
    const capture = captures.find(({ workloadId }) => workloadId === environment.corpus.profileId);
    assert.ok(capture, environment.corpus.profileId);
    assertRetainedCapture(capture, environment);
    if (capture.success) assertWorkloadTimingInvariants(capture.workload, capture);
  }
  const recomputedReport = await buildSelectionReportFromWorkloads({
    workloads: captures.filter(({ success, workload }) => success === true && workload).map(({ workload }) => workload),
    contract: chunkingContract,
    thresholdFile: retainedReport.thresholdFile,
    workloadDefinitionsDigest: retainedReport.workloadDefinitionsDigest,
    packageJson,
    generatedAt: retainedReport.generatedAt,
    host: retainedReport.host,
    extraSourcePaths: RETAINED_BUNDLE_SOURCE_PATHS,
  });
  assert.equal(canonicalJson(recomputedReport), canonicalJson(retainedReport), 'chunking report must reproduce from retained captures');

  const sourceReplay = await buildChunkingSelectionReport({ extraSourcePaths: RETAINED_BUNDLE_SOURCE_PATHS });
  assert.equal(canonicalJson(stripStaticReportFields(sourceReplay)), canonicalJson(stripStaticReportFields(retainedReport)), 'retained report static authority drifted from current checked-in chunking semantics');
  const sourceReplayRows = new Map(sourceReplay.workloads.map((row) => [row.workloadId, row]));
  for (const row of retainedReport.workloads) {
    const current = sourceReplayRows.get(row.workloadId);
    assert.ok(current, row.workloadId);
    assert.equal(canonicalJson(stripWorkloadFields(current)), canonicalJson(stripWorkloadFields(row)), `retained workload semantics drifted: ${row.workloadId}`);
  }

  const recomputedSamples = captures.map((capture) => sampleFromRetainedCapture(capture, retainedReport.thresholdFile, verified.result.overhead));
  assert.equal(benchmarkCanonicalJson(recomputedSamples), benchmarkCanonicalJson(verified.samples), 'bundle sample set must reproduce from retained workload captures');
  const recomputedSummaries = summarizeSamples(recomputedSamples);
  assert.equal(benchmarkCanonicalJson(recomputedSummaries), benchmarkCanonicalJson(verified.summaries), 'bundle summaries must reproduce from retained samples');
  const thresholdEvaluations = evaluateThresholds(verified.result.thresholdFile, recomputedSummaries, {
    harnessProfile: verified.result.reproduction.harnessProfile,
    faultInvariantFailures: verified.result.evidence.faultInvariantFailures,
    securityNegativeMisses: verified.result.evidence.securityNegativeMisses,
    protocolFailures: verified.result.evidence.protocolFailures,
    overheadBasisPoints: verified.result.overhead.measuredBasisPoints,
  }).rows;
  assert.equal(benchmarkCanonicalJson(thresholdEvaluations), benchmarkCanonicalJson(verified.result.thresholdEvaluations), 'bundle threshold evaluations must reproduce from retained samples and evidence');
  const retainedReportBody = { ...retainedReport };
  delete retainedReportBody.reportSha256;
  assert.equal(sha256(retainedReportBody), retainedReport.reportSha256, 'chunking report self-hash must match its body');

  return {
    schemaVersion: 'ogvcs.chunking/selection-benchmark-retained-validation/v1',
    bundleDirectory: relative(ROOT, bundleDirectory).replaceAll('\\', '/') || '.',
    bundleDigest: verified.manifest.bundleDigest,
    verified: true,
    workloadIds: captureIds,
    sampleCount: verified.samples.length,
    summaryCount: verified.summaries.length,
    thresholdEvaluationCount: verified.result.thresholdEvaluations.length,
    selectionReportSha256: retainedReport.reportSha256,
    sampleSetDigest: verified.result.sampleSetDigest,
    summarySetDigest: verified.result.summarySetDigest,
    resultThresholdFileDigest: verified.result.thresholdFileDigest,
    retainedCaptureDigest: canonicalDigest(captures, 'ogvcs.chunking/selection-workload-capture-set/v1'),
    resultOverallStatus: verified.result.overallStatus,
    reportOverallStatus: retainedReport.overallStatus,
  };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const report = await verifyChunkingSelectionBenchmarkBundle(options.bundle);
  if (options.output) {
    await mkdir(dirname(options.output), { recursive: true });
    await writeFile(options.output, `${canonicalJson(report)}\n`, 'utf8');
  }
  process.stdout.write(`${canonicalJson(report)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
