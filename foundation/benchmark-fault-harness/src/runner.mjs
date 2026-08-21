import { DeterministicCacheController } from './cache.mjs';
import { canonicalDigest, codeUnitCompare, deepFreeze } from './canonical.mjs';
import { validateBenchmarkValue } from './contract.mjs';
import { captureEnvironment } from './environment.mjs';
import { harnessFail } from './errors.mjs';
import { FakeRepositoryService } from './fake-service.mjs';
import { HARNESS_LIMITS, HarnessDeadline, boundedInteger } from './limits.mjs';
import { measureHarnessOverhead, measureTask, validateHarnessOverhead } from './measurement.mjs';
import { NetworkController } from './network.mjs';
import { summarizeSamples } from './statistics.mjs';
import { evaluateThresholds } from './thresholds.mjs';

const SAMPLE_WORKING_BYTES = 3_500;
const ENVIRONMENT_WORKING_BYTES = 4_096;
const SUMMARY_WORKING_BYTES = 3_072;

function nonNegative(value, name) {
  const result = value ?? 0;
  if (!Number.isSafeInteger(result) || result < 0) harnessFail('HARNESS_INPUT_INVALID', `${name} is invalid`);
  return result;
}

export function applyEvidenceToMatrix(matrix, evidence = {}) {
  const completeEvidence = {
    faultInvariantFailures: nonNegative(evidence.faultInvariantFailures, 'faultInvariantFailures'),
    securityNegativeMisses: nonNegative(evidence.securityNegativeMisses, 'securityNegativeMisses'),
    protocolFailures: nonNegative(evidence.protocolFailures, 'protocolFailures'),
    overheadBasisPoints: nonNegative(matrix?.overhead?.measuredBasisPoints, 'overheadBasisPoints'),
  };
  const thresholds = evaluateThresholds(matrix.thresholdFile, matrix.summaries, { ...completeEvidence, harnessProfile: matrix.profile.id });
  const incomplete = matrix.samples.some(({ status }) => status === 'incomplete');
  const coreFailure = matrix.samples.some(({ status, assertions }) => status === 'failed' || assertions.some(({ passed }) => !passed)) || completeEvidence.faultInvariantFailures > 0 || completeEvidence.securityNegativeMisses > 0 || completeEvidence.protocolFailures > 0;
  return deepFreeze({ ...matrix, evidence: completeEvidence, thresholdEvaluations: thresholds.rows, overallStatus: coreFailure || thresholds.gateFailed ? 'failed' : incomplete ? 'incomplete' : 'passed', warnings: thresholds.warnings });
}

function taskInput(taskId, corpus, runtime, repetition, signal) {
  const key = `task-${corpus.id}-${runtime.cacheState}-${runtime.network.id}-${taskId}-${repetition}`;
  const boundedLogicalBytes = Math.min(Number(corpus.logicalBytes), 1024 * 1024);
  const logicalBytes = Number.isFinite(boundedLogicalBytes) && boundedLogicalBytes >= 0 ? Math.floor(boundedLogicalBytes) : 1024 * 1024;
  const input = {
    idempotencyKey: key.padEnd(16, '-'), logicalBytes, uniqueBytes: Math.max(1, Math.floor(logicalBytes * 3 / 4)),
    actor: 'operator-a', fileId: '00000000000000000000000000000001', authorized: true, cache: runtime.cache, network: runtime.networkController, signal,
  };
  if (['submit', 'merge'].includes(taskId)) input.expectedHead = runtime.service.snapshot().branches.find(([name]) => name === 'main')[1];
  if (taskId === 'restore' && runtime.backupId) input.backupId = runtime.backupId;
  return input;
}

function plannedCounts(profile, iterations) {
  const units = BigInt(profile.corpora.length) * BigInt(profile.cacheStates.length) * BigInt(profile.networkProfiles.length) * BigInt(iterations);
  const samples = units * BigInt(profile.tasks.length);
  const environments = BigInt(profile.corpora.length) * BigInt(profile.cacheStates.length) * BigInt(profile.networkProfiles.length);
  const summaries = BigInt(profile.corpora.length) * BigInt(profile.cacheStates.length) * BigInt(profile.networkProfiles.length) * BigInt(profile.tasks.length);
  for (const [name, value] of [['units', units], ['samples', samples], ['environments', environments], ['summaries', summaries]]) if (value > BigInt(Number.MAX_SAFE_INTEGER)) harnessFail('HARNESS_LIMIT_EXCEEDED', `benchmark ${name} count exceeds the safe integer range`);
  return { units: Number(units), samples: Number(samples), environments: Number(environments), summaries: Number(summaries) };
}

function matrixWorkingBytes(counts) {
  const value = BigInt(counts.samples) * BigInt(SAMPLE_WORKING_BYTES) + BigInt(counts.environments) * BigInt(ENVIRONMENT_WORKING_BYTES) + BigInt(counts.summaries) * BigInt(SUMMARY_WORKING_BYTES);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) harnessFail('HARNESS_LIMIT_EXCEEDED', 'benchmark matrix working set exceeds the safe integer range');
  return Number(value);
}

async function runPool(units, concurrency, operation) {
  const rows = new Array(units.length);
  const failures = [];
  let cursor = 0;
  let stopped = false;
  async function worker() {
    while (true) {
      if (stopped) return;
      const index = cursor;
      cursor += 1;
      if (index >= units.length) return;
      try { rows[index] = await operation(units[index], index); }
      catch (error) { failures.push({ error, index }); stopped = true; return; }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, units.length) }, () => worker()));
  if (failures.length > 0) {
    failures.sort((left, right) => left.index - right.index);
    throw failures[0].error;
  }
  return rows;
}

export async function runBenchmarkMatrix(options) {
  const { contract } = options ?? {};
  if (!contract || !Array.isArray(options.corpora) || options.corpora.length < 1 || options.corpora.length > HARNESS_LIMITS.maxCorpora) harnessFail('HARNESS_INPUT_INVALID', 'benchmark matrix requires a contract and bounded corpora');
  const profile = contract.registries['harness-profiles'].entries.find(({ id }) => id === (options.harnessProfile ?? 'local-smoke'));
  if (!profile) harnessFail('HARNESS_INPUT_INVALID', 'harness profile is not registered');
  const corporaById = new Map();
  for (const corpus of options.corpora) {
    if (!corpus || typeof corpus.id !== 'string' || corpus.verified !== true || corporaById.has(corpus.id)) harnessFail('HARNESS_INPUT_INVALID', 'benchmark corpus inventory is invalid');
    corporaById.set(corpus.id, corpus);
  }
  const corpora = profile.corpora.map((id) => corporaById.get(id));
  if (corpora.some((value) => !value) || corporaById.size !== profile.corpora.length) harnessFail('HARNESS_INPUT_INVALID', 'benchmark corpora do not exactly match the selected profile');
  const taskById = new Map(contract.registries.tasks.entries.map((entry) => [entry.id, entry]));
  const tasks = profile.tasks.map((id) => taskById.get(id));
  if (tasks.some((value) => !value)) harnessFail('HARNESS_BUNDLE_INVALID', 'harness profile names an unknown task');
  const errorAuthority = new Map(contract.registries.errors.entries.map((entry) => [entry.name, entry]));
  const networkById = new Map(contract.registries.networks.entries.map((entry) => [entry.id, entry]));
  const networks = profile.networkProfiles.map((id) => networkById.get(id));
  if (networks.some((value) => !value)) harnessFail('HARNESS_BUNDLE_INVALID', 'harness profile names an unknown network');
  if (networks.some(({ mode }) => mode === 'privileged') && options.allowPrivileged !== true) harnessFail('HARNESS_PRIVILEGE_REQUIRED', 'selected harness profile contains an isolated privileged network');
  const iterations = boundedInteger(options.iterations, profile.repetitions, HARNESS_LIMITS.maxIterations, 'iterations');
  const concurrency = boundedInteger(options.concurrency, 1, 1024, 'concurrency');
  if (concurrency !== 1 && networks.some(({ mode }) => mode === 'privileged')) harnessFail('HARNESS_PRIVILEGE_REQUIRED', 'privileged network profiles require a single isolated execution lane');
  const taskTimeoutMs = boundedInteger(options.taskTimeoutMs, HARNESS_LIMITS.maxTaskTimeMs, HARNESS_LIMITS.maxTaskTimeMs, 'taskTimeoutMs');
  const seed = options.seed ?? 'ogvcs-benchmark-smoke-v1';
  if (typeof seed !== 'string' || seed.length < 1 || seed.length > 1024 || seed.includes('\0') || seed.normalize('NFC') !== seed || /[\uD800-\uDFFF]/u.test(seed)) harnessFail('HARNESS_INPUT_INVALID', 'benchmark seed is invalid');
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARNESS_LIMITS.maxWorkingMemoryBytes, HARNESS_LIMITS.maxWorkingMemoryBytes, 'maxWorkingMemoryBytes');
  const counts = plannedCounts(profile, iterations);
  const retainedMatrixBytes = matrixWorkingBytes(counts);
  if (counts.samples > HARNESS_LIMITS.maxSamples || retainedMatrixBytes > maximumWorking) harnessFail('HARNESS_LIMIT_EXCEEDED', 'benchmark matrix exceeds its configured sample or aggregate working-memory bound');
  const cacheAuthority = new Map(contract.registries['cache-states'].entries.map((entry) => [entry.id, entry]));
  const maximumSeededCacheBytes = profile.cacheStates.reduce((maximum, id) => {
    const entry = cacheAuthority.get(id);
    if (!entry || !Number.isSafeInteger(entry.localBytes) || !Number.isSafeInteger(entry.regionalBytes)) harnessFail('HARNESS_BUNDLE_INVALID', 'harness profile names an invalid cache state');
    return Math.max(maximum, entry.localBytes + entry.regionalBytes);
  }, 0);
  const activeLanes = Math.min(concurrency, counts.units);
  const remainingWorkingBytes = maximumWorking - retainedMatrixBytes;
  if (remainingWorkingBytes < maximumSeededCacheBytes * activeLanes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'benchmark matrix and active cache lanes exceed their aggregate working-memory bound');
  const cacheBytesPerLane = Math.floor(remainingWorkingBytes / activeLanes);
  const thresholdFile = validateBenchmarkValue(contract, 'ThresholdFile.schema.json', options.thresholdFile ?? contract.thresholds['default-v1']);
  const thresholdDigest = canonicalDigest(thresholdFile, 'ogvcs.benchmark/thresholds/v1');
  const units = [];
  for (const corpus of corpora) for (const cacheState of profile.cacheStates) for (const network of networks) for (let repetition = 0; repetition < iterations; repetition += 1) units.push({ corpus, cacheState, network, repetition });
  const unitRows = await runPool(units, concurrency, async (unit, unitIndex) => {
    const { corpus, cacheState, network, repetition } = unit;
    const cache = new DeterministicCacheController({ maxBytes: cacheBytesPerLane });
    const cacheInspection = cache.prepare(cacheState);
    const adapter = options.networkAdapterFactory ? await options.networkAdapterFactory({ ...unit, unitIndex }) : options.networkAdapter;
    const networkController = new NetworkController(network, { allowPrivileged: options.allowPrivileged, adapter, signal: options.signal, simulateDelay: options.simulateNetworkDelay });
    const service = await (options.serviceFactory?.({ ...unit, unitIndex }) ?? new FakeRepositoryService());
    if (!service || typeof service.executeTask !== 'function' || typeof service.snapshot !== 'function') harnessFail('HARNESS_INPUT_INVALID', 'service factory did not return a benchmark task service');
    const runtime = { cache, cacheState, network, networkController, service, backupId: undefined };
    const environment = repetition === 0 ? validateBenchmarkValue(contract, 'EnvironmentRecord.schema.json', captureEnvironment({ corpus, cacheInspection, network, thresholdDigest, seed, harnessProfile: profile.id, iterations, concurrency, operator: options.operator, classification: options.classification, filesystem: options.filesystem, implementationCommit: options.implementationCommit, implementationId: options.implementationId, implementationVersion: options.implementationVersion, clientRegion: options.clientRegion, serviceRegion: options.serviceRegion, cacheRegion: options.cacheRegion, clock: options.environmentClock })) : undefined;
    const samples = [];
    try {
      for (const task of tasks) {
        const deadline = new HarnessDeadline({ timeoutMs: taskTimeoutMs, signal: options.signal });
        const measurement = options.measurementFactory ? options.measurementFactory({ ...unit, unitIndex, taskId: task.id }) : options.measurement;
        const measured = await deadline.race(measureTask(() => service.executeTask(task.id, taskInput(task.id, corpus, runtime, repetition, deadline.signal)), measurement), `task ${task.id}`);
        const result = measured.value;
        if (!result || !['success', 'failed', 'incomplete'].includes(result.status) || !result.metrics || !Array.isArray(result.assertions)) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'benchmark task returned an invalid result');
        const assertionIds = result.assertions.map(({ id }) => id);
        const codeAuthority = errorAuthority.get(result.code);
        const statusCodeValid = result.status === 'success'
          ? result.code === 'HARNESS_OK' && codeAuthority?.retryable === false
          : result.code !== 'HARNESS_OK' && codeAuthority?.retryable === (result.status === 'incomplete');
        if (!statusCodeValid || !Number.isSafeInteger(result.mutationCount) || result.mutationCount < 0 || !Number.isSafeInteger(result.retries) || result.retries < 0 || result.retries !== result.metrics.retries || assertionIds.length !== task.assertions.length || assertionIds.some((id, index) => id !== task.assertions[index]) || new Set(assertionIds).size !== assertionIds.length || result.status === 'success' && result.assertions.some(({ passed }) => passed !== true)) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'benchmark task status, code, retry, mutation, or assertion authority is inconsistent');
        if (task.id === 'backup' && result.status === 'success') {
          if (!result.output || typeof result.output.backupId !== 'string' || result.output.backupId.length < 1 || result.output.backupId.length > 256) harnessFail('HARNESS_PROTOCOL_MALFORMED', 'successful backup task omitted its bounded backup identity');
          runtime.backupId = result.output.backupId;
        }
        const metrics = result.metrics;
        const sample = {
          schemaVersion: 'ogvcs.benchmark/sample/v1', id: `sample/${corpus.id}/${cacheState}/${network.id}/${task.id}/${repetition}`,
          taskId: task.id, corpusId: corpus.id, repetition, cacheState, networkProfile: network.id, status: result.status,
          failureCode: result.status === 'success' ? null : result.code,
          wallMicroseconds: measured.wallMicroseconds, cpuMicroseconds: measured.cpuMicroseconds, peakMemoryBytes: measured.peakMemoryBytes,
          diskReadBytes: metrics.diskReadBytes, diskWriteBytes: metrics.diskWriteBytes, networkReadBytes: metrics.networkReadBytes, networkWriteBytes: metrics.networkWriteBytes, logicalBytes: metrics.logicalBytes, uniqueBytes: metrics.uniqueBytes, retries: result.retries,
          assertions: result.assertions, faultScheduleDigest: null,
        };
        try { samples.push(validateBenchmarkValue(contract, 'BenchmarkSample.schema.json', sample)); }
        catch (error) { harnessFail('HARNESS_PROTOCOL_MALFORMED', 'benchmark task metrics or assertions violate the sample contract', { cause: error }); }
      }
    } finally { networkController.reset(); }
    return { environment, samples };
  });
  let samples = unitRows.flatMap(({ samples: values }) => values).sort((left, right) => codeUnitCompare(left.id, right.id));
  const environmentRecords = unitRows.flatMap(({ environment }) => environment ? [environment] : []).sort((left, right) => codeUnitCompare(`${left.corpus.profileId}\0${left.configuration.cacheState}\0${left.configuration.networkProfile}`, `${right.corpus.profileId}\0${right.configuration.cacheState}\0${right.configuration.networkProfile}`));
  if (samples.length !== counts.samples || environmentRecords.length !== counts.environments || new Set(samples.map(({ id }) => id)).size !== samples.length) harnessFail('HARNESS_ASSERTION_FAILED', 'benchmark execution inventory differs from its bounded plan');
  const overhead = validateHarnessOverhead(options.overhead ?? await measureHarnessOverhead({ iterations: 10 }));
  if (overhead.correctionApplied) samples = samples.map((sample) => deepFreeze({ ...sample, wallMicroseconds: Math.max(0, sample.wallMicroseconds - overhead.correctionMicroseconds) }));
  const summaries = summarizeSamples(samples);
  return applyEvidenceToMatrix({ profile, thresholdFile, thresholdDigest, samples, summaries, environmentRecords, overhead, planned: counts }, { faultInvariantFailures: options.faultInvariantFailures, securityNegativeMisses: options.securityNegativeMisses, protocolFailures: options.protocolFailures });
}
