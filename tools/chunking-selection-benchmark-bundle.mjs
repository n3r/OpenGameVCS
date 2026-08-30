#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyEvidenceToMatrix,
  buildResultBundle,
  canonicalDigest,
  canonicalJson,
  captureEnvironment,
  evaluateThresholds,
  loadBenchmarkContract,
  measureHarnessOverhead,
  proveFaultDeterminism,
  runBrokenServiceSelfTest,
  runFaultMatrix,
  runSecurityNegativeSuites,
  summarizeSamples,
  validateBenchmarkValue,
  verifyResultBundle,
  writeResultBundle,
} from '../foundation/benchmark-fault-harness/src/index.mjs';
import { canonicalSequenceDigest, parseJson } from '../foundation/benchmark-fault-harness/src/canonical.mjs';
import { harnessFail } from '../foundation/benchmark-fault-harness/src/errors.mjs';
import { expectedSecurityPathCases } from '../foundation/benchmark-fault-harness/src/security.mjs';
import {
  RETAINED_BUNDLE_SOURCE_PATHS,
  RETAINED_ERROR_MESSAGE_LIMIT,
  ROOT,
  SPEC_ROOT,
  buildSelectionReportFromWorkloads,
  canonicalJson as chunkingCanonicalJson,
  loadSelectionAuthority,
  normalizeRetainedFailureError,
  sha256,
  stableFailureCode,
} from './chunking-selection-benchmark-common.mjs';

export const BUNDLE_PROFILE = 'chunking-selection-bounded';
export const BUNDLE_TASK = 'chunking-verify';
export const DEFAULT_OPERATOR = 'local-operator';
export const DEFAULT_SEED = 'ogvcs-007-chunking-selection-v1';
export const PROCESS_PEAK_SOURCE = 'whole-process child peak via max(process.resourceUsage().maxRSS*1024, sampled process.memoryUsage().rss)';
export const CHILD_MAX_RSS_SOURCE = 'node:process.resourceUsage().maxRSS (reported KiB)';
const DEFAULT_SAMPLE_INTERVAL_MS = 5;
export const DEFAULT_WORKER_TIMEOUT_MS = 60_000;
export const DEFAULT_WORKER_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024;
export const DEFAULT_WORKER_TERMINATION_GRACE_MS = 250;
export const DEFAULT_WORKER_KILL_WAIT_MS = 250;
const WORKER_PARSE_LIMIT_BYTES = 1_048_576;
const WORKER = fileURLToPath(new URL('./chunking-selection-benchmark-worker.mjs', import.meta.url));

function parseArguments(argv) {
  const options = { output: null, seed: DEFAULT_SEED };
  for (let index = 0; index < argv.length; index += 2) {
    if (index + 1 >= argv.length) throw new Error('usage: node tools/chunking-selection-benchmark-bundle.mjs --output <bundle-dir> [--seed <seed>]');
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--output') options.output = resolve(process.cwd(), value);
    else if (flag === '--seed') options.seed = value;
    else throw new Error(`unknown argument ${flag}`);
  }
  if (!options.output) throw new Error('usage: node tools/chunking-selection-benchmark-bundle.mjs --output <bundle-dir> [--seed <seed>]');
  return options;
}

function cacheInspectionDigest() {
  const body = { state: 'cold', localBytes: 0, regionalBytes: 0, reads: 0, localHits: 0, regionalHits: 0, originBytes: 0 };
  return canonicalDigest(body, 'ogvcs.benchmark/cache-inspection/v1');
}

function correctedWallMicroseconds(totalWallMicroseconds, overhead) {
  return overhead?.correctionApplied ? Math.max(0, totalWallMicroseconds - overhead.correctionMicroseconds) : totalWallMicroseconds;
}

function validateNonNegativeSafeInteger(value, label, { allowZero = true } = {}) {
  if (!Number.isSafeInteger(value) || value < 0 || (!allowZero && value === 0)) harnessFail('HARNESS_INPUT_INVALID', `${label} must be a ${allowZero ? 'non-negative' : 'positive'} safe integer`);
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

function deterministicCorpus(definition, chunkingManifestSha256) {
  return {
    id: definition.workloadId,
    logicalBytes: 0,
    manifestDigest: chunkingManifestSha256,
    requestDigest: expectedChunkingRequestDigest(definition),
    profile: { id: definition.workloadId, version: '0.1.0-rc.1' },
    generatorVersion: '1.0.0',
    verified: true,
  };
}

function buildEvidenceReport(contract, faultMatrix, brokenServices, security, deterministicFaults) {
  return validateBenchmarkValue(contract, 'HarnessEvidence.schema.json', {
    schemaVersion: 'ogvcs.benchmark/evidence/v1',
    faultMatrix: {
      rows: faultMatrix.rows,
      failed: faultMatrix.failed,
      scheduleSetDigest: canonicalSequenceDigest(faultMatrix.schedules, 'ogvcs.benchmark/fault-schedule-set/v1'),
    },
    brokenServices: { cases: brokenServices.cases, missed: brokenServices.missed },
    security: {
      authorizationManifestSha256: security.authorization.manifestSha256,
      authorizationRegistrySetSha256: security.authorization.registrySetSha256,
      authorizationAdapter: security.authorization.adapter,
      authorizationResultsSha256: security.authorization.resultsSha256,
      authorizationVectors: security.authorization.vectors,
      authorizationPassed: security.authorization.passed,
      authorizationFailed: security.authorization.failed,
      authorizationRows: security.authorization.rows,
      pathManifestSha256: security.pathManifestSha256,
      enumerationDetected: security.enumerationDetected,
      workspaceEscapeDetected: security.workspaceEscapeDetected,
      pathCases: security.pathRows.map(({ path, decision }) => ({ caseDigest: canonicalDigest(path, 'ogvcs.benchmark/security-path-case/v1'), rejected: decision.accepted !== true, code: decision.error ?? 'PATH_ACCEPTED' })),
      misses: security.misses,
    },
    deterministicFaults: deterministicFaults.deterministic,
  });
}

export function captureClaimsValid(workload) {
  if (!workload) return false;
  const compare = workload.compare;
  const verify = workload.verify;
  return Number(compare.reusedBytes) + Number(compare.newlyRequiredBytes) === Number(compare.uniqueBytes)
    && Number(compare.logicalBytes) === Number(compare.uniqueBytes) + Number(compare.repeatedBytes)
    && Number(verify.uniqueBytes) === Number(compare.uniqueBytes)
    && Number(verify.repeatedBytes) === Number(compare.repeatedBytes)
    && verify.logicalBytes === compare.logicalBytes;
}

export function validateRetainedCapture(capture, environment = null) {
  if (!capture || typeof capture !== 'object') harnessFail('HARNESS_INPUT_INVALID', 'retained capture must be an object');
  const expectedKeys = capture.success === true
    ? ['host', 'process', 'schemaVersion', 'success', 'workload', 'workloadId']
    : ['error', 'host', 'process', 'schemaVersion', 'success', 'workloadId'];
  if (capture.success !== undefined && chunkingCanonicalJson(Object.keys(capture).sort()) !== chunkingCanonicalJson(expectedKeys)) harnessFail('HARNESS_INPUT_INVALID', 'retained capture envelope is invalid');
  if (capture.schemaVersion !== 'ogvcs.chunking/selection-workload-capture/v1') harnessFail('HARNESS_INPUT_INVALID', 'retained capture schema version is invalid');
  if (typeof capture.workloadId !== 'string' || capture.workloadId.length === 0) harnessFail('HARNESS_INPUT_INVALID', 'retained capture workload id is invalid');
  if (typeof capture.success !== 'boolean') harnessFail('HARNESS_INPUT_INVALID', 'retained capture success flag is invalid');
  if (!capture.host || typeof capture.host !== 'object') harnessFail('HARNESS_INPUT_INVALID', 'retained capture host is invalid');
  if (chunkingCanonicalJson(Object.keys(capture.host).sort()) !== chunkingCanonicalJson(['architecture', 'node', 'os'])) harnessFail('HARNESS_INPUT_INVALID', 'retained capture host envelope is invalid');
  for (const key of ['architecture', 'node', 'os']) {
    if (typeof capture.host[key] !== 'string' || capture.host[key].length === 0) harnessFail('HARNESS_INPUT_INVALID', `retained capture host ${key} is invalid`);
  }
  if (!capture.process || typeof capture.process !== 'object') harnessFail('HARNESS_INPUT_INVALID', 'retained capture process metrics are invalid');
  if (chunkingCanonicalJson(Object.keys(capture.process).sort()) !== chunkingCanonicalJson(['maxRssBytes', 'maxRssSource', 'peakMemoryBytes', 'sampleIntervalMs', 'sampledPeakRssBytes', 'systemCpuMicroseconds', 'totalWallMicroseconds', 'userCpuMicroseconds'])) harnessFail('HARNESS_INPUT_INVALID', 'retained capture process envelope is invalid');
  validateNonNegativeSafeInteger(capture.process.totalWallMicroseconds, 'retained capture totalWallMicroseconds');
  validateNonNegativeSafeInteger(capture.process.userCpuMicroseconds, 'retained capture userCpuMicroseconds');
  validateNonNegativeSafeInteger(capture.process.systemCpuMicroseconds, 'retained capture systemCpuMicroseconds');
  validateNonNegativeSafeInteger(capture.process.sampleIntervalMs, 'retained capture sampleIntervalMs', { allowZero: false });
  validateNonNegativeSafeInteger(capture.process.sampledPeakRssBytes, 'retained capture sampledPeakRssBytes', { allowZero: capture.success === false });
  validateNonNegativeSafeInteger(capture.process.maxRssBytes, 'retained capture maxRssBytes');
  validateNonNegativeSafeInteger(capture.process.peakMemoryBytes, 'retained capture peakMemoryBytes', { allowZero: capture.success === false });
  if (capture.process.peakMemoryBytes !== Math.max(capture.process.sampledPeakRssBytes, capture.process.maxRssBytes)) harnessFail('HARNESS_INPUT_INVALID', 'retained capture peak memory must equal the maximum of sampledPeakRssBytes and maxRssBytes');
  const expectedMaxRssSource = capture.process.maxRssBytes > 0 ? CHILD_MAX_RSS_SOURCE : 'unavailable';
  if (capture.process.maxRssSource !== expectedMaxRssSource) harnessFail('HARNESS_INPUT_INVALID', 'retained capture maxRss source is invalid');
  if (capture.success === true && (capture.process.sampledPeakRssBytes === 0 || capture.process.peakMemoryBytes === 0)) harnessFail('HARNESS_INPUT_INVALID', 'successful retained captures must include a positive peak measurement');
  if (capture.success === true) {
    if (capture.workload?.workloadId !== capture.workloadId) harnessFail('HARNESS_INPUT_INVALID', 'successful retained capture workload id does not match its outer capture id');
    if (!capture.workload || capture.error !== undefined) harnessFail('HARNESS_INPUT_INVALID', 'successful retained capture must include workload only');
  } else if (!capture.error || typeof capture.error !== 'object' || typeof capture.error.message !== 'string' || typeof capture.error.name !== 'string' || typeof capture.error.code !== 'string') {
    harnessFail('HARNESS_INPUT_INVALID', 'failed retained capture must include a typed error');
  } else if (chunkingCanonicalJson(Object.keys(capture.error).sort()) !== chunkingCanonicalJson(['code', 'message', 'name'])) {
    harnessFail('HARNESS_INPUT_INVALID', 'retained capture error envelope is invalid');
  } else if (chunkingCanonicalJson(capture.error) !== chunkingCanonicalJson(normalizeRetainedFailureError(capture.error))) {
    harnessFail('HARNESS_INPUT_INVALID', 'failed retained capture error must be normalized');
  } else if (Buffer.byteLength(capture.error.message, 'utf8') > RETAINED_ERROR_MESSAGE_LIMIT) {
    harnessFail('HARNESS_INPUT_INVALID', 'failed retained capture error message exceeds the shared publication limit');
  }
  if (environment) {
    if (environment.corpus.profileId !== capture.workloadId) harnessFail('HARNESS_INPUT_INVALID', 'retained capture workload id does not match its environment corpus id');
    if (environment.hardware.architecture !== capture.host.architecture) harnessFail('HARNESS_INPUT_INVALID', 'retained capture host architecture does not match its environment record');
    if (environment.platform.os !== capture.host.os) harnessFail('HARNESS_INPUT_INVALID', 'retained capture host OS does not match its environment record');
    if (environment.platform.nodeVersion !== `v${capture.host.node}`) harnessFail('HARNESS_INPUT_INVALID', 'retained capture host Node version does not match its environment record');
  }
  return capture;
}

function captureStatus(capture) {
  if (capture.success === false) return stableFailureCode(capture.error?.code) === 'HARNESS_TASK_INCOMPLETE' ? 'incomplete' : 'failed';
  return 'success';
}

export function buildChunkingSelectionPublicMetadata({ thresholdFile, selectionReport, captures }) {
  return {
    schemaVersion: 'ogvcs.chunking/selection-benchmark-retained-evidence/v1',
    exactScaleExecuted: false,
    benchmarkProfile: BUNDLE_PROFILE,
    chunkingSelection: {
      bundleThresholdFileDigest: canonicalDigest(thresholdFile, 'ogvcs.benchmark/thresholds/v1'),
      bundleThresholdFileOwner: thresholdFile.owner,
      bundleThresholdIds: thresholdFile.entries.map(({ id }) => id),
      processPeakSource: PROCESS_PEAK_SOURCE,
      reportJson: chunkingCanonicalJson(selectionReport),
      retainedCaptures: captures,
    },
  };
}

export function sampleFromCapture(capture, thresholdFile, { contract, overhead } = {}) {
  validateRetainedCapture(capture);
  const workload = capture.workload;
  const workloadThresholds = workload
    ? buildSelectionReportFromThresholds(thresholdFile, [workload]).filter(({ workloadId }) => workloadId === capture.workloadId)
    : [];
  const assertions = [
    { id: 'chunking-accounting-balanced', passed: workload?.accounting?.balanced === true },
    { id: 'chunking-derived-claims-recomputed', passed: capture.success === true && captureClaimsValid(workload) },
    { id: 'chunking-thresholds-held', passed: capture.success === true && workloadThresholds.every(({ status }) => status === 'passed') },
  ];
  const status = captureStatus(capture) === 'success'
    ? assertions.every(({ passed }) => passed) ? 'success' : 'failed'
    : captureStatus(capture);
  const failureCode = status === 'success'
    ? null
    : capture.success === false
      ? stableFailureCode(capture.error?.code)
      : 'HARNESS_ASSERTION_FAILED';
  return validateBenchmarkValue(contract, 'BenchmarkSample.schema.json', {
    schemaVersion: 'ogvcs.benchmark/sample/v1',
    id: `sample/${capture.workloadId}/cold/loopback-simulated/${BUNDLE_TASK}/0`,
    taskId: BUNDLE_TASK,
    corpusId: capture.workloadId,
    repetition: 0,
    cacheState: 'cold',
    networkProfile: 'loopback-simulated',
    status,
    failureCode,
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
  });
}

function buildSelectionReportFromThresholds(thresholdFile, workloads) {
  return thresholdFile.entries.map((entry) => {
    const row = workloads.find(({ workloadId }) => workloadId === entry.workloadId);
    if (!row) return null;
    let actual;
    switch (entry.metric) {
      case 'reusedBytes':
        actual = Number(row.compare.reusedBytes);
        break;
      case 'newlyRequiredBytes':
        actual = Number(row.compare.newlyRequiredBytes);
        break;
      case 'resynchronizationDistanceBytes':
        actual = row.deltas.resynchronization.resynchronizationDistanceBytes ?? Number.MAX_SAFE_INTEGER;
        break;
      default:
        return null;
    }
    const passed = entry.operator === 'maximum' ? actual <= entry.value : actual >= entry.value;
    return {
      thresholdId: entry.id,
      workloadId: entry.workloadId,
      status: passed ? 'passed' : 'failed',
    };
  }).filter(Boolean);
}

function elapsedMicroseconds(startedWall) {
  return Number((process.hrtime.bigint() - startedWall) / 1000n);
}

function syntheticFailureCapture(workloadId, code, message, startedWall, sampleIntervalMs) {
  return {
    schemaVersion: 'ogvcs.chunking/selection-workload-capture/v1',
    workloadId,
    success: false,
    host: { architecture: process.arch, node: process.versions.node, os: process.platform },
    process: {
      totalWallMicroseconds: elapsedMicroseconds(startedWall),
      userCpuMicroseconds: 0,
      systemCpuMicroseconds: 0,
      peakMemoryBytes: 0,
      sampledPeakRssBytes: 0,
      maxRssBytes: 0,
      maxRssSource: 'unavailable',
      sampleIntervalMs,
    },
    error: normalizeRetainedFailureError({ code, message }),
  };
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return !(error instanceof Error) || error.name !== 'Error' || !('code' in error) || error.code !== 'ESRCH';
  }
}

function signalProcessTree(child, signal) {
  if (!child?.pid) return false;
  if (process.platform !== 'win32') {
    try {
      process.kill(-child.pid, signal);
      return true;
    } catch {}
    try {
      child.kill(signal);
      return true;
    } catch {}
    return false;
  }
  try {
    if (signal === 'SIGKILL') {
      const killer = spawn('taskkill', ['/T', '/F', '/PID', String(child.pid)], {
        stdio: 'ignore',
        windowsHide: true,
      });
      killer.once('error', () => {});
      return true;
    }
    child.kill(signal);
    return true;
  } catch {}
  return false;
}

export async function runWorker(workloadId, options = {}) {
  return new Promise((resolvePromise) => {
    const startedWall = process.hrtime.bigint();
    const command = options.command ?? process.execPath;
    const args = options.args ?? [options.workerPath ?? WORKER, '--workload-id', workloadId];
    const timeoutMs = options.timeoutMs ?? DEFAULT_WORKER_TIMEOUT_MS;
    const outputLimitBytes = options.outputLimitBytes ?? DEFAULT_WORKER_OUTPUT_LIMIT_BYTES;
    const parseLimitBytes = options.parseLimitBytes ?? WORKER_PARSE_LIMIT_BYTES;
    const sampleIntervalMs = options.sampleIntervalMs ?? DEFAULT_SAMPLE_INTERVAL_MS;
    const terminateGraceMs = options.terminateGraceMs ?? DEFAULT_WORKER_TERMINATION_GRACE_MS;
    const terminateKillWaitMs = options.terminateKillWaitMs ?? DEFAULT_WORKER_KILL_WAIT_MS;
    let child;
    try {
      child = spawn(command, args, {
        cwd: options.cwd ?? ROOT,
        detached: process.platform !== 'win32',
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch (error) {
      resolvePromise(syntheticFailureCapture(workloadId, 'HARNESS_DRIVER_FAILED', `worker spawn failed: ${error instanceof Error ? error.message : String(error)}`, startedWall, sampleIntervalMs));
      return;
    }
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let settled = false;
    let timedOut = false;
    let overflowed = false;
    let termination = null;
    let escalationTimeout = null;
    let forceTimeout = null;
    const timeout = setTimeout(() => {
      timedOut = true;
      beginTermination('HARNESS_TASK_INCOMPLETE', `worker timed out after ${timeoutMs} ms`);
    }, timeoutMs);
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      clearTimeout(escalationTimeout);
      clearTimeout(forceTimeout);
      child.stdout?.destroy();
      child.stderr?.destroy();
      resolvePromise(value);
    };
    const stderrPreview = () => normalizeRetainedFailureError({ message: Buffer.concat(stderr).toString('utf8').trim() }).message;
    const retainFailure = (code, message) => finish(syntheticFailureCapture(workloadId, code, message, startedWall, sampleIntervalMs));
    const beginTermination = (code, message) => {
      if (settled || termination) return;
      termination = { code, message };
      signalProcessTree(child, 'SIGTERM');
      escalationTimeout = setTimeout(() => {
        if (settled) return;
        signalProcessTree(child, 'SIGKILL');
        forceTimeout = setTimeout(() => {
          if (settled) return;
          finish(syntheticFailureCapture(workloadId, code, message, startedWall, sampleIntervalMs));
        }, terminateKillWaitMs);
      }, terminateGraceMs);
    };
    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > outputLimitBytes) {
        overflowed = true;
        beginTermination('HARNESS_LIMIT_EXCEEDED', `worker output exceeded ${outputLimitBytes} bytes`);
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > outputLimitBytes) {
        overflowed = true;
        beginTermination('HARNESS_LIMIT_EXCEEDED', `worker output exceeded ${outputLimitBytes} bytes`);
        return;
      }
      stderr.push(chunk);
    });
    child.once('error', (error) => retainFailure('HARNESS_DRIVER_FAILED', `worker spawn failed: ${error instanceof Error ? error.message : String(error)}`));
    child.once('close', (code, signal) => {
      if (settled) return;
       if (termination) return retainFailure(termination.code, termination.message);
      const output = Buffer.concat(stdout).toString('utf8').trim();
      if (timedOut) return retainFailure('HARNESS_TASK_INCOMPLETE', `worker timed out after ${timeoutMs} ms`);
      if (overflowed) return retainFailure('HARNESS_LIMIT_EXCEEDED', `worker output exceeded ${outputLimitBytes} bytes`);
      if (output.length === 0) return retainFailure('HARNESS_DRIVER_FAILED', `worker emitted no stdout${stderr.length > 0 ? `: ${stderrPreview()}` : ''}`);
      let capture;
      try {
        capture = parseJson(output, { requireCanonical: true, maxBytes: parseLimitBytes });
      } catch (error) {
        beginTermination('HARNESS_DRIVER_FAILED', `worker emitted invalid canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
        return retainFailure('HARNESS_DRIVER_FAILED', `worker emitted invalid canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (capture?.success === false) capture = { ...capture, error: normalizeRetainedFailureError(capture.error) };
      try {
        validateRetainedCapture(capture);
      } catch (error) {
        beginTermination('HARNESS_DRIVER_FAILED', error instanceof Error ? error.message : String(error));
        return retainFailure('HARNESS_DRIVER_FAILED', error instanceof Error ? error.message : String(error));
      }
      if (capture.workloadId !== workloadId) return retainFailure('HARNESS_DRIVER_FAILED', 'worker capture workload id mismatch');
      if ((code === 0 && signal === null) !== (capture.success === true)) return retainFailure('HARNESS_DRIVER_FAILED', 'worker exit status does not match retained capture success');
      finish(capture);
    });
  });
}

export async function buildChunkingSelectionBenchmarkBundle(options = {}) {
  const contract = options.contract ?? await loadBenchmarkContract({ root: resolve(ROOT, 'spec/benchmark-fault/v1'), cache: false });
  const seed = options.seed ?? DEFAULT_SEED;
  const thresholdFile = options.thresholdFile ?? contract.thresholds['chunking-selection-bounded-v1'];
  const profile = contract.registries['harness-profiles'].entries.find(({ id }) => id === BUNDLE_PROFILE);
  const { contract: chunkingContract, packageJson, thresholdFile: selectionThresholdFile, workloadFile, workloadDefinitionsDigest } = await loadSelectionAuthority();
  const chunkingManifestSha256 = sha256(await readFile(join(SPEC_ROOT, 'manifest.json')));
  const captures = [];
  for (const definition of workloadFile.workloads) captures.push(await runWorker(definition.workloadId));
  const mutatedCaptures = typeof options.mutateCaptures === 'function' ? options.mutateCaptures(captures) : captures;
  const workloads = mutatedCaptures.filter(({ success, workload }) => success === true && workload).map(({ workload }) => workload);
  const selectionReport = await buildSelectionReportFromWorkloads({
    workloads,
    contract: chunkingContract,
    thresholdFile: selectionThresholdFile,
    workloadDefinitionsDigest,
    packageJson,
    extraSourcePaths: RETAINED_BUNDLE_SOURCE_PATHS,
  });
  const corpora = workloadFile.workloads.map((definition) => deterministicCorpus(definition, chunkingManifestSha256));
  const corpusById = new Map(corpora.map((corpus) => [corpus.id, corpus]));
  const implementationCommit = selectionReport.sourceIdentity.sourceSetSha256;
  const environmentRecords = workloadFile.workloads.map((definition) => validateBenchmarkValue(contract, 'EnvironmentRecord.schema.json', captureEnvironment({
    corpus: corpusById.get(definition.workloadId),
    cacheInspection: { state: 'cold', localBytes: 0, regionalBytes: 0, stateDigest: cacheInspectionDigest() },
    network: contract.registries.networks.entries.find(({ id }) => id === 'loopback-simulated'),
    thresholdDigest: canonicalDigest(thresholdFile, 'ogvcs.benchmark/thresholds/v1'),
    seed,
    harnessProfile: BUNDLE_PROFILE,
    iterations: 1,
    concurrency: 1,
    operator: options.operator ?? DEFAULT_OPERATOR,
    classification: 'synthetic',
    filesystem: 'local-workspace',
    implementationCommit,
    implementationId: 'ogvcs.chunking-manifest/javascript@1',
    implementationVersion: packageJson.version,
    clientRegion: 'local-client',
    serviceRegion: 'local-service',
    cacheRegion: 'local-cache',
    clock: options.clock,
  })));
  for (const [index, capture] of mutatedCaptures.entries()) {
    if (capture?.success === false) mutatedCaptures[index] = { ...capture, error: normalizeRetainedFailureError(capture.error) };
    validateRetainedCapture(mutatedCaptures[index], environmentRecords[index]);
  }
  const captureHost = mutatedCaptures[0]?.host;
  if (mutatedCaptures.some(({ host }) => chunkingCanonicalJson(host) !== chunkingCanonicalJson(captureHost))) harnessFail('HARNESS_INPUT_INVALID', 'retained captures must share one exact child host identity');
  if (chunkingCanonicalJson(selectionReport.host) !== chunkingCanonicalJson(captureHost)) harnessFail('HARNESS_INPUT_INVALID', 'selection report host must equal the retained child host identity');
  const overhead = options.overhead ?? await measureHarnessOverhead({ iterations: 10 });
  const samples = mutatedCaptures.map((capture) => sampleFromCapture(capture, selectionThresholdFile, { contract, overhead }));
  const summaries = summarizeSamples(samples);
  const initialMatrix = {
    profile,
    thresholdFile,
    thresholdDigest: canonicalDigest(thresholdFile, 'ogvcs.benchmark/thresholds/v1'),
    samples,
    summaries,
    environmentRecords,
    thresholdEvaluations: evaluateThresholds(thresholdFile, summaries, { harnessProfile: BUNDLE_PROFILE, faultInvariantFailures: 0, securityNegativeMisses: 0, protocolFailures: 0, overheadBasisPoints: overhead.measuredBasisPoints }).rows,
    overallStatus: 'incomplete',
    overhead,
  };
  const [faultMatrix, brokenServices, security] = await Promise.all([
    runFaultMatrix(contract, { seed }),
    runBrokenServiceSelfTest(contract),
    runSecurityNegativeSuites(),
  ]);
  const deterministicFaults = proveFaultDeterminism(contract, seed);
  const matrix = applyEvidenceToMatrix(initialMatrix, {
    faultInvariantFailures: faultMatrix.failed + brokenServices.missed,
    securityNegativeMisses: security.misses,
    protocolFailures: 0,
  });
  const evidenceReport = buildEvidenceReport(contract, faultMatrix, brokenServices, security, deterministicFaults);
  const publication = buildResultBundle(contract, matrix, {
    seed,
    operator: options.operator ?? DEFAULT_OPERATOR,
    classification: 'synthetic',
    clock: options.clock,
    retentionDays: 30,
    publicMetadata: {
      ...buildChunkingSelectionPublicMetadata({ thresholdFile, selectionReport, captures: mutatedCaptures }),
    },
    evidenceReport,
    faultSchedules: [...faultMatrix.schedules, deterministicFaults.schedule],
  });
  return { contract, chunkingContract, selectionReport, corpora, matrix, publication };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const { contract, publication } = await buildChunkingSelectionBenchmarkBundle(options);
  await mkdir(dirname(options.output), { recursive: true });
  await writeResultBundle(options.output, contract, publication);
  await verifyResultBundle(options.output, contract);
  process.stdout.write(`${chunkingCanonicalJson(publication.result)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
