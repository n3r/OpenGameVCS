import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, mkdtemp, open, opendir, rename, rm } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';

import { canonicalDigest, canonicalJson, canonicalSequenceDigest, codeUnitCompare, deepFreeze, parseJson, parseLargeCanonical, sha256 } from './canonical.mjs';
import { validateBenchmarkValue } from './contract.mjs';
import { BenchmarkHarnessError, harnessFail } from './errors.mjs';
import { FaultScheduler } from './faults.mjs';
import { HARNESS_LIMITS, checkedAdd } from './limits.mjs';
import { validateHarnessOverhead } from './measurement.mjs';
import { redactPublicData } from './redaction.mjs';
import { expectedSecurityPathCases } from './security.mjs';
import { summarizeSamples } from './statistics.mjs';
import { evaluateThresholds } from './thresholds.mjs';

const SMALL_ARTIFACT_BYTES = 16 * 1024 * 1024;
const STREAM_TRANSIENT_BYTES = 2 * 1024 * 1024;

function retainedJsonBytes(bytes, label) {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > Math.floor((Number.MAX_SAFE_INTEGER - 256) / 8)) harnessFail('HARNESS_LIMIT_EXCEEDED', `${label} retained working set exceeds the safe integer range`);
  return bytes * 8 + 256;
}

function clockDate(clock) {
  if (clock !== undefined && typeof clock !== 'function') harnessFail('HARNESS_INPUT_INVALID', 'bundle clock must be callable');
  let raw;
  try { raw = clock?.() ?? new Date(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'bundle clock failed', { cause: error }); }
  const value = raw instanceof Date ? new Date(raw.valueOf()) : new Date(raw);
  try { value.toISOString(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'bundle clock is invalid', { cause: error }); }
  return value;
}

function validateIdentityInventory(rows, key, label) {
  const seen = new Set();
  for (const row of rows) {
    const identity = key(row);
    if (typeof identity !== 'string' || seen.has(identity)) harnessFail('HARNESS_BUNDLE_INVALID', `${label} contains a duplicate or invalid identity`);
    seen.add(identity);
  }
}

function summaryKey(row) { return `${row.taskId}\0${row.corpusId}\0${row.cacheState}\0${row.networkProfile}`; }
function environmentKey(row) { return `${row.corpus.profileId}\0${row.configuration.cacheState}\0${row.configuration.networkProfile}`; }

function reproduceMatrix(contract, matrix) {
  const thresholdFile = validateBenchmarkValue(contract, 'ThresholdFile.schema.json', matrix.thresholdFile);
  const thresholdDigest = canonicalDigest(thresholdFile, 'ogvcs.benchmark/thresholds/v1');
  if (matrix.thresholdDigest !== thresholdDigest || !matrix.profile || typeof matrix.profile.id !== 'string') harnessFail('HARNESS_INPUT_INVALID', 'result matrix threshold authority or profile is invalid');
  const summaries = summarizeSamples(matrix.samples);
  const overhead = validateHarnessOverhead(matrix.overhead);
  const evidence = matrix.evidence;
  if (!evidence || !Number.isSafeInteger(evidence.faultInvariantFailures) || !Number.isSafeInteger(evidence.securityNegativeMisses) || !Number.isSafeInteger(evidence.protocolFailures)) harnessFail('HARNESS_INPUT_INVALID', 'result matrix evidence is invalid');
  const thresholds = evaluateThresholds(thresholdFile, summaries, { ...evidence, overheadBasisPoints: overhead.measuredBasisPoints, harnessProfile: matrix.profile.id });
  const incomplete = matrix.samples.some(({ status }) => status === 'incomplete');
  const coreFailure = matrix.samples.some(({ status, assertions }) => status === 'failed' || assertions.some(({ passed }) => !passed)) || evidence.faultInvariantFailures > 0 || evidence.securityNegativeMisses > 0 || evidence.protocolFailures > 0;
  return { thresholdFile, thresholdDigest, summaries, thresholdEvaluations: thresholds.rows, overallStatus: coreFailure || thresholds.gateFailed ? 'failed' : incomplete ? 'incomplete' : 'passed' };
}

function claimFailure(code, message, cause) { harnessFail(code, message, cause ? { cause } : undefined); }

function reproducePublishedMatrix(contract, result, samples, errorCode) {
  try {
    return reproduceMatrix(contract, {
      samples,
      thresholdFile: result.thresholdFile,
      thresholdDigest: result.thresholdFileDigest,
      profile: { id: result.reproduction.harnessProfile },
      overhead: result.overhead,
      evidence: result.evidence,
    });
  } catch (error) {
    claimFailure(errorCode, 'published result claims cannot be reproduced from their authenticated inputs', error);
  }
}

function assertPublicationClaims(contract, result, evidenceReport, environmentRecords, samples, conformance, errorCode) {
  const fail = (message, cause) => claimFailure(errorCode, message, cause);
  const workloadDigest = canonicalDigest(contract.registries.tasks.entries, 'ogvcs.benchmark/workload-definitions/v1');
  if (result.contractManifestSha256 !== contract.manifestSha256 || result.workloadDefinitionsDigest !== workloadDigest) fail('published result contract or workload authority differs');
  if (canonicalDigest(result.thresholdFile, 'ogvcs.benchmark/thresholds/v1') !== result.thresholdFileDigest || result.reproduction.tolerancePartsPerMillion !== result.thresholdFile.comparisonTolerancePartsPerMillion) fail('published comparison tolerance differs from its threshold authority');
  const normalizedPublicMetadata = redactPublicData(result.publicMetadata);
  if (normalizedPublicMetadata.credentialsRemoved !== 0 || normalizedPublicMetadata.partnerIdentifiersHashed !== 0 || canonicalJson(normalizedPublicMetadata.value) !== canonicalJson(result.publicMetadata)) fail('published public metadata is not already safely redacted');

  const faultFailures = evidenceReport.faultMatrix.rows.filter(({ injected, taskStatus, invariantPassed }) => !injected || taskStatus !== 'incomplete' || !invariantPassed).length;
  const faultAuthority = new Map(contract.registries.faults.entries.map((entry) => [entry.id, entry]));
  const expectedFaultRows = contract.registries.faults.entries.flatMap(({ id }) => ['crash-before', 'crash-after', 'error'].map((action) => `${id}\0${action}`));
  const actualFaultRows = evidenceReport.faultMatrix.rows.map(({ faultPoint, action }) => `${faultPoint}\0${action}`);
  const faultInventoryInvalid = canonicalJson(actualFaultRows) !== canonicalJson(expectedFaultRows) || evidenceReport.faultMatrix.rows.some(({ faultPoint, taskId, invariantPassed, invariantFailures }) => !faultAuthority.get(faultPoint)?.tasks.includes(taskId) || invariantPassed !== (invariantFailures.length === 0));
  const brokenWitnessInvalid = evidenceReport.brokenServices.cases.some(({ detected, expectedInvariant, failures }) => detected !== failures.includes(expectedInvariant));
  const brokenMisses = evidenceReport.brokenServices.cases.filter(({ detected }) => !detected).length;
  const expectedBrokenServices = [
    ['missing-content-publication', 'content-complete'], ['invisible-committed-state', 'single-visible-commit'], ['dual-hard-lock-submit', 'single-hard-lock'],
    ['unauthorized-access', 'authorized'], ['unverifiable-backup', 'backup-verifiable'], ['unverifiable-export', 'export-verifiable'], ['workspace-escape', 'workspace-confined'],
  ];
  const actualBrokenServices = evidenceReport.brokenServices.cases.map(({ mode, expectedInvariant }) => [mode, expectedInvariant]);
  const security = evidenceReport.security;
  const authorizationIds = new Set(security.authorizationRows.map(({ id }) => id));
  const authorizationFailed = security.authorizationRows.filter(({ status }) => status === 'failed').length;
  const authorizationPassed = security.authorizationRows.length - authorizationFailed;
  const authorizationRowsInvalid = security.authorizationRows.some(({ status, expectedCode, actualCode }) => status !== (expectedCode === actualCode ? 'passed' : 'failed'));
  const authorizationResultsDigest = sha256(Buffer.from(canonicalJson(security.authorizationRows), 'utf8'));
  const workspaceEscapeDetected = security.pathCases.every(({ rejected }) => rejected);
  const pathCaseIds = new Set(security.pathCases.map(({ caseDigest }) => caseDigest));
  const securityMisses = authorizationFailed + (security.enumerationDetected ? 0 : 1) + (workspaceEscapeDetected ? 0 : 1);
  const authorizationAuthority = contract.manifest.predecessorPins.authorization;
  const pathAuthority = contract.manifest.predecessorPins.path;
  if (faultInventoryInvalid || faultFailures !== evidenceReport.faultMatrix.failed || brokenWitnessInvalid || canonicalJson(actualBrokenServices) !== canonicalJson(expectedBrokenServices) || brokenMisses !== evidenceReport.brokenServices.missed || security.authorizationManifestSha256 !== authorizationAuthority.manifestSha256 || security.authorizationRegistrySetSha256 !== authorizationAuthority.registrySetSha256 || security.authorizationAdapter !== authorizationAuthority.referenceAdapter || authorizationIds.size !== security.authorizationRows.length || authorizationRowsInvalid || authorizationResultsDigest !== security.authorizationResultsSha256 || security.authorizationResultsSha256 !== authorizationAuthority.referenceResultsSha256 || security.authorizationVectors !== security.authorizationRows.length || security.authorizationVectors !== authorizationAuthority.referenceVectors || security.authorizationPassed !== authorizationPassed || security.authorizationFailed !== authorizationFailed || security.pathManifestSha256 !== pathAuthority.manifestSha256 || pathCaseIds.size !== security.pathCases.length || canonicalJson(security.pathCases) !== canonicalJson(expectedSecurityPathCases()) || security.workspaceEscapeDetected !== workspaceEscapeDetected || security.misses !== securityMisses || evidenceReport.deterministicFaults !== true) fail('published fault, checker, or security evidence contains a derived-claim mismatch');

  const schedules = new Map();
  for (const schedule of result.faultSchedules) {
    try { new FaultScheduler(schedule); } catch (error) { fail('published fault schedule does not reproduce from its events', error); }
    if (schedules.has(schedule.scheduleDigest)) fail('published fault schedule identities are duplicated');
    schedules.set(schedule.scheduleDigest, schedule);
  }
  const matrixSchedules = [];
  const rowScheduleIds = new Set();
  for (const row of evidenceReport.faultMatrix.rows) {
    const schedule = schedules.get(row.scheduleDigest);
    if (!schedule || rowScheduleIds.has(row.scheduleDigest) || schedule.events.length !== 1 || schedule.events[0].faultPoint !== row.faultPoint || schedule.events[0].action !== row.action) fail('published fault evidence does not name one exact matching schedule per row');
    rowScheduleIds.add(row.scheduleDigest); matrixSchedules.push(schedule);
  }
  const proofSchedules = [...schedules.values()].filter(({ scheduleDigest }) => !rowScheduleIds.has(scheduleDigest));
  const expectedFaultPoints = contract.registries.faults.entries.map(({ id }) => id).sort(codeUnitCompare);
  const proofFaultPoints = proofSchedules.length === 1 ? proofSchedules[0].events.map(({ faultPoint }) => faultPoint).sort(codeUnitCompare) : [];
  if (canonicalSequenceDigest(matrixSchedules, 'ogvcs.benchmark/fault-schedule-set/v1') !== evidenceReport.faultMatrix.scheduleSetDigest || schedules.size !== evidenceReport.faultMatrix.rows.length + 1 || proofSchedules.length !== 1 || canonicalJson(proofFaultPoints) !== canonicalJson(expectedFaultPoints) || samples.some(({ faultScheduleDigest }) => faultScheduleDigest !== null && !schedules.has(faultScheduleDigest))) fail('published fault schedule inventory differs from its raw evidence');

  if (conformance === null) {
    if (result.conformanceReportDigest !== null || result.evidence.protocolFailures !== 0) fail('published result omits its declared conformance evidence');
  } else {
    const expectedCases = contract.vectors.conformance.cases;
    const conformanceIds = new Set(conformance.rows.map(({ id }) => id));
    const conformancePassed = conformance.rows.filter(({ status }) => status === 'passed').length;
    const conformanceFailed = conformance.rows.length - conformancePassed;
    const conformanceInventoryInvalid = conformance.rows.length !== expectedCases.length || conformance.rows.some((row, index) => { const expected = expectedCases[index]; const passed = row.code === expected?.expected.code && row.preMutation === expected?.expected.preMutation; return row.id !== expected?.id || canonicalJson(row.requirementIds) !== canonicalJson(expected?.requirementIds) || row.status !== (passed ? 'passed' : 'failed'); });
    if (conformance.contractManifestSha256 !== contract.manifestSha256 || conformanceInventoryInvalid || conformanceIds.size !== conformance.rows.length || conformance.cases !== conformance.rows.length || conformance.passed !== conformancePassed || conformance.failed !== conformanceFailed || conformance.resultsDigest !== canonicalDigest(conformance.rows, 'ogvcs.benchmark/conformance-results/v1') || result.conformanceReportDigest !== canonicalDigest(conformance, 'ogvcs.benchmark/conformance-report/v1') || result.evidence.protocolFailures !== conformanceFailed) fail('published conformance report contains a derived-claim or authority mismatch');
  }

  const profile = contract.registries['harness-profiles'].entries.find(({ id }) => id === result.reproduction.harnessProfile);
  if (!profile) fail('published result selects an unknown harness profile');
  const cacheAuthority = new Map(contract.registries['cache-states'].entries.map((entry) => [entry.id, entry]));
  const networkAuthority = new Map(contract.registries.networks.entries.map((entry) => [entry.id, entry]));
  const expectedEnvironmentKeys = new Set();
  for (const corpusId of profile.corpora) for (const cacheState of profile.cacheStates) for (const networkProfile of profile.networkProfiles) expectedEnvironmentKeys.add(`${corpusId}\0${cacheState}\0${networkProfile}`);
  const actualEnvironmentKeys = new Set();
  const seedDigest = canonicalDigest(result.reproduction.seed, 'ogvcs.benchmark/seed/v1');
  const cacheStates = new Set();
  const operators = new Set();
  const corpusAuthorities = new Map();
  let iterations; let concurrency; let executionAuthority;
  for (const environment of environmentRecords) {
    const key = environmentKey(environment); const cache = cacheAuthority.get(environment.configuration.cacheState); const network = networkAuthority.get(environment.configuration.networkProfile);
    const cacheBody = cache && { state: cache.id, localBytes: cache.localBytes, regionalBytes: cache.regionalBytes, reads: 0, localHits: 0, regionalHits: 0, originBytes: 0 };
    const networkBody = network && { rttMs: network.rttMs, bandwidthBytesPerSecond: network.bandwidthBytesPerSecond, lossPartsPerMillion: network.lossPartsPerMillion, interruptionEvery: network.interruptionEvery, duplicateEvery: network.duplicateEvery, reorderWindow: network.reorderWindow, mode: network.mode };
    iterations ??= environment.configuration.iterations; concurrency ??= environment.configuration.concurrency;
    const corpusAuthority = { profileVersion: environment.corpus.profileVersion, requestDigest: environment.corpus.requestDigest, manifestDigest: environment.corpus.manifestDigest, generatorVersion: environment.corpus.generatorVersion };
    const priorCorpusAuthority = corpusAuthorities.get(environment.corpus.profileId); if (priorCorpusAuthority === undefined) corpusAuthorities.set(environment.corpus.profileId, corpusAuthority);
    const laneExecutionAuthority = { implementation: environment.implementation, hardware: environment.hardware, platform: environment.platform, topology: environment.topology };
    executionAuthority ??= laneExecutionAuthority;
    if (!expectedEnvironmentKeys.has(key) || actualEnvironmentKeys.has(key) || environment.classification !== result.classification || environment.configuration.harnessProfile !== profile.id || environment.configuration.thresholdDigest !== result.thresholdFileDigest || environment.configuration.seedDigest !== seedDigest || environment.configuration.iterations !== iterations || environment.configuration.concurrency !== concurrency || environment.configuration.cacheState !== environment.cacheInspection.state || environment.corpus.profileVersion !== contract.manifest.predecessorPins.fixtures.profileVersion || environment.corpus.generatorVersion !== contract.manifest.predecessorPins.fixtures.packageVersion || priorCorpusAuthority && canonicalJson(priorCorpusAuthority) !== canonicalJson(corpusAuthority) || canonicalJson(executionAuthority) !== canonicalJson(laneExecutionAuthority) || !cacheBody || environment.cacheInspection.localBytes !== cache.localBytes || environment.cacheInspection.regionalBytes !== cache.regionalBytes || environment.cacheInspection.stateDigest !== canonicalDigest(cacheBody, 'ogvcs.benchmark/cache-inspection/v1') || !networkBody || canonicalJson(environment.network) !== canonicalJson(networkBody)) fail('published environment inventory differs from its selected profile or authority');
    actualEnvironmentKeys.add(key); cacheStates.add(environment.cacheInspection.state); operators.add(environment.operatorDigest);
  }
  if (actualEnvironmentKeys.size !== expectedEnvironmentKeys.size || [...expectedEnvironmentKeys].some((key) => !actualEnvironmentKeys.has(key)) || operators.size !== 1 || iterations === undefined) fail('published environment inventory is incomplete or ambiguous');
  const plannedSampleCount = BigInt(expectedEnvironmentKeys.size) * BigInt(profile.tasks.length) * BigInt(iterations);
  if (plannedSampleCount > BigInt(HARNESS_LIMITS.maxSamples) || plannedSampleCount !== BigInt(result.sampleCount)) fail('published sample plan exceeds its bound or differs from its result count');
  const expectedSampleKeys = new Set();
  for (const environmentKeyValue of expectedEnvironmentKeys) for (const taskId of profile.tasks) for (let repetition = 0; repetition < iterations; repetition += 1) expectedSampleKeys.add(`${environmentKeyValue}\0${taskId}\0${repetition}`);
  const actualSampleKeys = new Set();
  for (const sample of samples) {
    const environmentKeyValue = `${sample.corpusId}\0${sample.cacheState}\0${sample.networkProfile}`;
    const key = `${environmentKeyValue}\0${sample.taskId}\0${sample.repetition}`;
    const task = contract.registries.tasks.entries.find(({ id }) => id === sample.taskId);
    const assertionIds = sample.assertions.map(({ id }) => id);
    const expectedSampleId = `sample/${sample.corpusId}/${sample.cacheState}/${sample.networkProfile}/${sample.taskId}/${sample.repetition}`;
    if (!expectedSampleKeys.has(key) || actualSampleKeys.has(key) || sample.id !== expectedSampleId || !task || canonicalJson(assertionIds) !== canonicalJson(task.assertions)) fail('published sample inventory or task assertion authority differs from its selected profile matrix');
    actualSampleKeys.add(key);
  }
  const inspectedCacheStates = [...cacheStates].sort(codeUnitCompare);
  const runBasis = { contractManifestSha256: result.contractManifestSha256, createdAt: result.createdAt, classification: result.classification, seedDigest, profile: profile.id, operatorDigest: [...operators][0], environmentSetDigest: result.environmentSetDigest, sampleSetDigest: result.sampleSetDigest, metadata: result.publicMetadata };
  const expectedRunId = `run/${canonicalDigest(runBasis, 'ogvcs.benchmark/run/v1')}`;
  let expectedExpiry;
  try { expectedExpiry = new Date(new Date(result.createdAt).valueOf() + result.redaction.retentionDays * 86_400_000).toISOString(); }
  catch (error) { fail('published retention expiry is outside the supported date range', error); }
  const expectedCommand = `ogvcs-benchmark smoke --profile ${profile.id} --seed <recorded-seed>`;
  if (actualSampleKeys.size !== expectedSampleKeys.size || result.sampleCount !== expectedSampleKeys.size || canonicalJson(result.evidence.cacheStatesInspected) !== canonicalJson(inspectedCacheStates) || result.evidence.faultInvariantFailures !== faultFailures + brokenMisses || result.evidence.securityNegativeMisses !== securityMisses || result.runId !== expectedRunId || result.redaction.expiresAt !== expectedExpiry || result.reproduction.command !== expectedCommand) fail('published result counters, run identity, retention, or reproduction template do not reproduce');
}

function parseBundleJson(bytes, options = {}) {
  try { return options.large ? parseLargeCanonical(bytes, options) : parseJson(bytes, { requireCanonical: true, maxBytes: options.maxBytes }); }
  catch (error) { harnessFail('HARNESS_BUNDLE_INVALID', 'bundle artifact is not bounded canonical JSON', { cause: error }); }
}

function validateBundleValue(contract, selector, value) {
  try { return validateBenchmarkValue(contract, selector, value); }
  catch (error) { harnessFail('HARNESS_BUNDLE_INVALID', `bundle artifact violates ${selector}`, { cause: error }); }
}

export function buildResultBundle(contract, matrix, options = {}) {
  if (!contract || !matrix || !Array.isArray(matrix.samples) || matrix.samples.length < 1 || matrix.samples.length > HARNESS_LIMITS.maxSamples || !Array.isArray(matrix.environmentRecords) || !Array.isArray(matrix.summaries) || !Array.isArray(matrix.thresholdEvaluations)) harnessFail('HARNESS_INPUT_INVALID', 'result matrix is incomplete or outside its bound');
  for (const sample of matrix.samples) validateBenchmarkValue(contract, 'BenchmarkSample.schema.json', sample);
  for (const environment of matrix.environmentRecords) validateBenchmarkValue(contract, 'EnvironmentRecord.schema.json', environment);
  for (const summary of matrix.summaries) validateBenchmarkValue(contract, 'TaskSummary.schema.json', summary);
  for (const evaluation of matrix.thresholdEvaluations) validateBenchmarkValue(contract, 'ThresholdEvaluation.schema.json', evaluation);
  const reproduced = reproduceMatrix(contract, matrix);
  if (canonicalJson(reproduced.summaries) !== canonicalJson(matrix.summaries) || canonicalJson(reproduced.thresholdEvaluations) !== canonicalJson(matrix.thresholdEvaluations) || reproduced.overallStatus !== matrix.overallStatus) harnessFail('HARNESS_INPUT_INVALID', 'result matrix derived summaries, thresholds, or status do not reproduce');
  const comparisonTolerance = reproduced.thresholdFile.comparisonTolerancePartsPerMillion;
  if (options.tolerancePartsPerMillion !== undefined && options.tolerancePartsPerMillion !== comparisonTolerance) harnessFail('HARNESS_INPUT_INVALID', 'bundle comparison tolerance must equal the selected threshold authority');
  const evidenceReport = validateBenchmarkValue(contract, 'HarnessEvidence.schema.json', options.evidenceReport);
  if (evidenceReport.faultMatrix.failed + evidenceReport.brokenServices.missed !== matrix.evidence.faultInvariantFailures || evidenceReport.security.misses !== matrix.evidence.securityNegativeMisses || evidenceReport.deterministicFaults !== true) harnessFail('HARNESS_INPUT_INVALID', 'raw harness evidence differs from the matrix evidence counters');
  validateIdentityInventory(matrix.samples, ({ id }) => id, 'sample set');
  validateIdentityInventory(matrix.summaries, summaryKey, 'summary set');
  validateIdentityInventory(matrix.environmentRecords, environmentKey, 'environment set');
  const created = clockDate(options.clock);
  const retentionDays = options.retentionDays ?? 30;
  if (!Number.isSafeInteger(retentionDays) || retentionDays < 1 || retentionDays > 365) harnessFail('HARNESS_INPUT_INVALID', 'bundle retention is invalid');
  const expires = new Date(created.valueOf() + retentionDays * 86_400_000);
  try { expires.toISOString(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'bundle retention exceeds the supported date range', { cause: error }); }
  const classification = options.classification ?? 'synthetic';
  if (!['synthetic', 'partner-derived'].includes(classification)) harnessFail('HARNESS_INPUT_INVALID', 'bundle classification is invalid');
  const publicMetadata = redactPublicData(options.publicMetadata ?? {});
  const seed = options.seed ?? 'ogvcs-benchmark-smoke-v1';
  if (typeof seed !== 'string' || seed.length < 1 || seed.length > 1024 || seed.includes('\0') || seed.normalize('NFC') !== seed || /[\uD800-\uDFFF]/u.test(seed)) harnessFail('HARNESS_INPUT_INVALID', 'bundle seed is invalid');
  const operator = options.operator ?? 'local-operator';
  if (typeof operator !== 'string' || operator.length < 1 || operator.length > 256 || operator.includes('\0') || operator.normalize('NFC') !== operator || /[\uD800-\uDFFF]/u.test(operator)) harnessFail('HARNESS_INPUT_INVALID', 'bundle operator identity is invalid');
  const operatorDigest = canonicalDigest(operator, 'ogvcs.benchmark/operator/v1');
  const environmentSetDigest = canonicalSequenceDigest(matrix.environmentRecords, 'ogvcs.benchmark/environment-set/v1');
  const sampleSetDigest = canonicalSequenceDigest(matrix.samples, 'ogvcs.benchmark/sample-set/v1');
  const runBasis = { contractManifestSha256: contract.manifestSha256, createdAt: created.toISOString(), classification, seedDigest: canonicalDigest(seed, 'ogvcs.benchmark/seed/v1'), profile: matrix.profile.id, operatorDigest, environmentSetDigest, sampleSetDigest, metadata: publicMetadata.value };
  const faultSchedules = options.faultSchedules ?? [];
  if (!Array.isArray(faultSchedules) || faultSchedules.length > HARNESS_LIMITS.maxFaultEvents) harnessFail('HARNESS_INPUT_INVALID', 'bundle fault schedule inventory is invalid');
  for (const schedule of faultSchedules) validateBenchmarkValue(contract, 'FaultSchedule.schema.json', schedule);
  const bundle = {
    schemaVersion: 'ogvcs.benchmark/result-bundle/v1',
    contractManifestSha256: contract.manifestSha256,
    conformanceReportDigest: options.conformanceReport ? canonicalDigest(options.conformanceReport, 'ogvcs.benchmark/conformance-report/v1') : null,
    evidenceReportDigest: canonicalDigest(evidenceReport, 'ogvcs.benchmark/evidence/v1'),
    runId: `run/${canonicalDigest(runBasis, 'ogvcs.benchmark/run/v1')}`,
    createdAt: created.toISOString(), classification,
    environmentCount: matrix.environmentRecords.length,
    environmentSetDigest,
    workloadDefinitionsDigest: canonicalDigest(contract.registries.tasks.entries, 'ogvcs.benchmark/workload-definitions/v1'),
    faultSchedules,
    sampleCount: matrix.samples.length,
    sampleSetDigest,
    summaryCount: matrix.summaries.length,
    summarySetDigest: canonicalSequenceDigest(matrix.summaries, 'ogvcs.benchmark/summary-set/v1'),
    thresholdFile: reproduced.thresholdFile,
    thresholdFileDigest: reproduced.thresholdDigest,
    thresholdEvaluations: matrix.thresholdEvaluations,
    overallStatus: matrix.overallStatus,
    overhead: matrix.overhead,
    evidence: { faultInvariantFailures: matrix.evidence.faultInvariantFailures, securityNegativeMisses: matrix.evidence.securityNegativeMisses, protocolFailures: matrix.evidence.protocolFailures, cacheStatesInspected: [...new Set(matrix.environmentRecords.map(({ cacheInspection }) => cacheInspection.state))].sort() },
    reproduction: { command: `ogvcs-benchmark smoke --profile ${matrix.profile.id} --seed <recorded-seed>`, seed, harnessProfile: matrix.profile.id, tolerancePartsPerMillion: comparisonTolerance },
    publicMetadata: publicMetadata.value,
    redaction: { retentionDays, expiresAt: expires.toISOString() },
  };
  const result = validateBenchmarkValue(contract, 'BenchmarkResultBundle.schema.json', bundle);
  const conformanceReport = options.conformanceReport ? validateBenchmarkValue(contract, 'ConformanceReport.schema.json', options.conformanceReport) : null;
  assertPublicationClaims(contract, result, evidenceReport, matrix.environmentRecords, matrix.samples, conformanceReport, 'HARNESS_INPUT_INVALID');
  return deepFreeze({ result, evidenceReport, environmentRecords: matrix.environmentRecords, samples: matrix.samples, summaries: matrix.summaries, ...(conformanceReport ? { conformanceReport } : {}) });
}

async function writeSynced(path, bytes) {
  const handle = await open(path, 'wx', 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}

function artifact(path, bytes, mediaType, digest = sha256(bytes)) { return { path, bytes: typeof bytes === 'number' ? bytes : bytes.length, sha256: digest, mediaType }; }
function manifestDigest(artifacts) { return canonicalDigest(artifacts.map(({ path, bytes, sha256: digest }) => ({ path, bytes, sha256: digest })), 'ogvcs.benchmark/publication/v1'); }

async function writeJsonlStream(path, artifactPath, values, selector, contract, maximum, sequenceDomain) {
  const handle = await open(path, 'wx', 0o600);
  const hash = createHash('sha256');
  const sequenceHash = createHash('sha256'); sequenceHash.update(sequenceDomain, 'utf8'); sequenceHash.update(Buffer.from([0]));
  let total = 0; let count = 0;
  try {
    for (const value of values) {
      validateBenchmarkValue(contract, selector, value);
      const valueBytes = Buffer.from(canonicalJson(value, { maxBytes: 1_048_576, maxWorkingMemoryBytes: 8_388_608 }));
      const bytes = Buffer.concat([valueBytes, Buffer.from([0x0a])], valueBytes.length + 1);
      total = checkedAdd(total, bytes.length, `${artifactPath} bytes`);
      if (total > maximum) harnessFail('HARNESS_LIMIT_EXCEEDED', `${artifactPath} exceeds the remaining result-bundle bound`);
      await handle.writeFile(bytes);
      hash.update(bytes);
      const length = Buffer.allocUnsafe(8); length.writeBigUInt64BE(BigInt(valueBytes.length));
      sequenceHash.update(length); sequenceHash.update(valueBytes); count = checkedAdd(count, 1, `${artifactPath} rows`);
    }
    await handle.sync();
  } finally { await handle.close(); }
  return { ...artifact(artifactPath, total, 'application/jsonl', hash.digest('hex')), count, sequenceDigest: sequenceHash.digest('hex') };
}

async function syncDirectory(path) {
  let handle;
  try { handle = await open(path, fsConstants.O_RDONLY); await handle.sync(); return true; }
  catch (error) {
    if (['EINVAL', 'ENOTSUP', 'EPERM', 'EISDIR'].includes(error?.code)) return false;
    throw error;
  } finally { await handle?.close().catch(() => {}); }
}

export async function writeResultBundle(directory, contract, publication) {
  if (typeof directory !== 'string' || directory.length < 1 || directory.includes('\0')) harnessFail('HARNESS_INPUT_INVALID', 'bundle destination is invalid');
  const bundle = validateBundleValue(contract, 'BenchmarkResultBundle.schema.json', publication?.result);
  if (!Array.isArray(publication?.samples) || publication.samples.length !== bundle.sampleCount || canonicalSequenceDigest(publication.samples, 'ogvcs.benchmark/sample-set/v1') !== bundle.sampleSetDigest || !Array.isArray(publication.environmentRecords) || publication.environmentRecords.length !== bundle.environmentCount || canonicalSequenceDigest(publication.environmentRecords, 'ogvcs.benchmark/environment-set/v1') !== bundle.environmentSetDigest || !Array.isArray(publication.summaries) || publication.summaries.length !== bundle.summaryCount || canonicalSequenceDigest(publication.summaries, 'ogvcs.benchmark/summary-set/v1') !== bundle.summarySetDigest) harnessFail('HARNESS_BUNDLE_INVALID', 'publication raw sets differ from their result envelope');
  for (const sample of publication.samples) validateBundleValue(contract, 'BenchmarkSample.schema.json', sample);
  for (const environment of publication.environmentRecords) validateBundleValue(contract, 'EnvironmentRecord.schema.json', environment);
  for (const summary of publication.summaries) validateBundleValue(contract, 'TaskSummary.schema.json', summary);
  validateIdentityInventory(publication.samples, ({ id }) => id, 'sample set');
  validateIdentityInventory(publication.environmentRecords, environmentKey, 'environment set');
  validateIdentityInventory(publication.summaries, summaryKey, 'summary set');
  const resultBytes = Buffer.from(canonicalJson(bundle));
  const evidenceReport = validateBundleValue(contract, 'HarnessEvidence.schema.json', publication.evidenceReport);
  const evidenceBytes = Buffer.from(canonicalJson(evidenceReport));
  if (canonicalDigest(publication.evidenceReport, 'ogvcs.benchmark/evidence/v1') !== bundle.evidenceReportDigest) harnessFail('HARNESS_BUNDLE_INVALID', 'publication evidence report differs from its result envelope');
  const conformanceReport = publication.conformanceReport ? validateBundleValue(contract, 'ConformanceReport.schema.json', publication.conformanceReport) : null;
  const conformanceBytes = conformanceReport ? Buffer.from(canonicalJson(conformanceReport)) : undefined;
  if ((conformanceBytes === undefined) !== (bundle.conformanceReportDigest === null) || conformanceBytes && canonicalDigest(conformanceReport, 'ogvcs.benchmark/conformance-report/v1') !== bundle.conformanceReportDigest) harnessFail('HARNESS_BUNDLE_INVALID', 'publication conformance report differs from its result envelope');
  const reproduced = reproducePublishedMatrix(contract, bundle, publication.samples, 'HARNESS_BUNDLE_INVALID');
  if (canonicalJson(reproduced.summaries) !== canonicalJson(publication.summaries) || canonicalJson(reproduced.thresholdEvaluations) !== canonicalJson(bundle.thresholdEvaluations) || reproduced.overallStatus !== bundle.overallStatus) harnessFail('HARNESS_BUNDLE_INVALID', 'publication derived summaries, thresholds, or status do not reproduce');
  assertPublicationClaims(contract, bundle, evidenceReport, publication.environmentRecords, publication.samples, conformanceReport, 'HARNESS_BUNDLE_INVALID');
  let total = resultBytes.length + evidenceBytes.length + (conformanceBytes?.length ?? 0);
  if (!Number.isSafeInteger(total) || total >= HARNESS_LIMITS.maxResultBundleBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'result bundle exceeds its configured byte ceiling');
  const parent = dirname(directory); const prefix = `.${basename(directory)}.ogvcs-stage-`;
  let stage;
  try { stage = await mkdtemp(join(parent, prefix)); }
  catch (error) { harnessFail('HARNESS_IO', 'result bundle staging directory cannot be created', { cause: error }); }
  let committed = false;
  try {
    if (conformanceBytes) await writeSynced(join(stage, 'conformance.json'), conformanceBytes);
    await writeSynced(join(stage, 'evidence.json'), evidenceBytes);
    await writeSynced(join(stage, 'result.json'), resultBytes);
    const environmentArtifact = await writeJsonlStream(join(stage, 'environments.jsonl'), 'environments.jsonl', publication.environmentRecords, 'EnvironmentRecord.schema.json', contract, HARNESS_LIMITS.maxResultBundleBytes - total, 'ogvcs.benchmark/environment-set/v1');
    total = checkedAdd(total, environmentArtifact.bytes, 'result bundle bytes');
    const sampleArtifact = await writeJsonlStream(join(stage, 'samples.jsonl'), 'samples.jsonl', publication.samples, 'BenchmarkSample.schema.json', contract, HARNESS_LIMITS.maxResultBundleBytes - total, 'ogvcs.benchmark/sample-set/v1');
    total = checkedAdd(total, sampleArtifact.bytes, 'result bundle bytes');
    const summaryArtifact = await writeJsonlStream(join(stage, 'summaries.jsonl'), 'summaries.jsonl', publication.summaries, 'TaskSummary.schema.json', contract, HARNESS_LIMITS.maxResultBundleBytes - total, 'ogvcs.benchmark/summary-set/v1');
    total = checkedAdd(total, summaryArtifact.bytes, 'result bundle bytes');
    if (environmentArtifact.count !== bundle.environmentCount || environmentArtifact.sequenceDigest !== bundle.environmentSetDigest || sampleArtifact.count !== bundle.sampleCount || sampleArtifact.sequenceDigest !== bundle.sampleSetDigest || summaryArtifact.count !== bundle.summaryCount || summaryArtifact.sequenceDigest !== bundle.summarySetDigest) harnessFail('HARNESS_BUNDLE_INVALID', 'publication input changed while its authenticated streams were staged');
    delete environmentArtifact.count; delete environmentArtifact.sequenceDigest;
    delete sampleArtifact.count; delete sampleArtifact.sequenceDigest;
    delete summaryArtifact.count; delete summaryArtifact.sequenceDigest;
    const artifacts = [...(conformanceBytes ? [artifact('conformance.json', conformanceBytes, 'application/json')] : []), artifact('evidence.json', evidenceBytes, 'application/json'), environmentArtifact, artifact('result.json', resultBytes, 'application/json'), sampleArtifact, summaryArtifact].sort((a, b) => codeUnitCompare(a.path, b.path));
    const manifest = validateBenchmarkValue(contract, 'BundleManifest.schema.json', { schemaVersion: 'ogvcs.benchmark/publication-manifest/v1', contractManifestSha256: contract.manifestSha256, bundleDigest: manifestDigest(artifacts), artifacts });
    const manifestBytes = Buffer.from(canonicalJson(manifest)); total = checkedAdd(total, manifestBytes.length, 'bundle bytes');
    if (total > HARNESS_LIMITS.maxResultBundleBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'result bundle exceeds its configured byte ceiling');
    await writeSynced(join(stage, 'manifest.json'), manifestBytes);
    const stageSynced = await syncDirectory(stage);
    await rename(stage, directory);
    committed = true;
    let parentSynced = false;
    try { parentSynced = await syncDirectory(parent); } catch { /* committed success is reported with a stable warning */ }
    const postCommitWarnings = [...(stageSynced ? [] : [{ phase: 'staging-directory-sync', code: 'HARNESS_IO' }]), ...(parentSynced ? [] : [{ phase: 'parent-directory-sync', code: 'HARNESS_IO' }])];
    return deepFreeze({ directory, manifest, postCommitWarnings });
  } catch (error) {
    if (!committed) await rm(stage, { recursive: true, force: true });
    if (error instanceof BenchmarkHarnessError) throw error;
    harnessFail('HARNESS_IO', 'result bundle could not be published atomically', { cause: error });
  }
}

async function openRegular(path, maximum) {
  let handle;
  try {
    const link = await lstat(path);
    if (!link.isFile() || link.isSymbolicLink()) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle artifact is not a regular no-link file');
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum || !sameStat(link, stat)) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle artifact is not a stable bounded regular file');
    return { handle, stat };
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error instanceof BenchmarkHarnessError) throw error;
    harnessFail('HARNESS_IO', 'bundle artifact cannot be opened', { cause: error });
  }
}

async function readRegular(path, maximum) {
  const { handle, stat } = await openRegular(path, maximum);
  try { return { bytes: await handle.readFile(), stat }; }
  catch (error) { harnessFail('HARNESS_IO', 'bundle artifact cannot be read', { cause: error }); }
  finally { await handle.close().catch(() => {}); }
}

async function authenticateRegular(path, entry) {
  const { handle, stat } = await openRegular(path, HARNESS_LIMITS.maxResultBundleBytes);
  const hash = createHash('sha256'); const buffer = Buffer.allocUnsafe(64 * 1024); let offset = 0;
  try {
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, stat.size - offset), offset);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
    }
    const after = await handle.stat();
    if (offset !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || stat.size !== entry.bytes || hash.digest('hex') !== entry.sha256) harnessFail('HARNESS_BUNDLE_INVALID', `bundle artifact authentication failed: ${entry.path}`);
    return stat;
  } catch (error) {
    if (error instanceof BenchmarkHarnessError) throw error;
    harnessFail('HARNESS_IO', `bundle artifact cannot be authenticated: ${entry.path}`, { cause: error });
  } finally { await handle.close().catch(() => {}); }
}

function sameStat(left, right) { return left.size === right.size && left.mtimeMs === right.mtimeMs && (left.ino === 0 || right.ino === 0 || left.ino === right.ino); }

async function parseJsonlStream(path, authenticated, contract, selector, maximumItems, maximumWorkingBytes) {
  if (!Number.isSafeInteger(maximumWorkingBytes) || maximumWorkingBytes <= STREAM_TRANSIENT_BYTES) harnessFail('HARNESS_LIMIT_EXCEEDED', `${authenticated.entry.path} has no remaining parse workspace`);
  const { handle, stat } = await openRegular(path, HARNESS_LIMITS.maxResultBundleBytes);
  if (!sameStat(stat, authenticated.stat)) { await handle.close(); harnessFail('HARNESS_BUNDLE_INVALID', 'sample stream changed after authentication'); }
  const buffer = Buffer.allocUnsafe(64 * 1024); const hash = createHash('sha256'); const values = [];
  let pending = Buffer.alloc(0); let offset = 0; let retainedWorkingBytes = 0;
  try {
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, stat.size - offset), offset);
      if (bytesRead === 0) break;
      const chunk = Buffer.from(buffer.subarray(0, bytesRead)); hash.update(chunk); offset += bytesRead;
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk], pending.length + chunk.length);
      while (true) {
        const newline = pending.indexOf(0x0a); if (newline < 0) break;
        if (newline === 0 || newline > 1_048_576 || pending[newline - 1] === 0x0d) harnessFail('HARNESS_BUNDLE_INVALID', `${authenticated.entry.path} has invalid framing`);
        const nextWorking = checkedAdd(retainedWorkingBytes, retainedJsonBytes(newline, `${authenticated.entry.path} row`), `${authenticated.entry.path} retained working bytes`);
        if (checkedAdd(nextWorking, STREAM_TRANSIENT_BYTES, `${authenticated.entry.path} parse working bytes`) > maximumWorkingBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', `${authenticated.entry.path} exceeds its aggregate parse workspace`);
        const value = validateBundleValue(contract, selector, parseBundleJson(pending.subarray(0, newline), { maxBytes: 1_048_576 }));
        values.push(value);
        retainedWorkingBytes = nextWorking;
        if (values.length > maximumItems) harnessFail('HARNESS_LIMIT_EXCEEDED', `${authenticated.entry.path} exceeds its item bound`);
        pending = pending.subarray(newline + 1);
      }
      if (pending.length > 1_048_576) harnessFail('HARNESS_LIMIT_EXCEEDED', 'sample line exceeds its byte bound');
    }
    const after = await handle.stat();
    if (pending.length !== 0 || offset !== stat.size || !sameStat(after, stat) || hash.digest('hex') !== authenticated.entry.sha256) harnessFail('HARNESS_BUNDLE_INVALID', `${authenticated.entry.path} changed, failed authentication, or lacks terminal LF`);
    return { values, retainedWorkingBytes };
  } finally { await handle.close().catch(() => {}); }
}

export async function verifyResultBundle(directory, contract) {
  let root;
  try { root = await lstat(directory); }
  catch (error) { harnessFail('HARNESS_IO', 'bundle directory cannot be inspected', { cause: error }); }
  if (!root.isDirectory() || root.isSymbolicLink()) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle root must be a regular no-link directory');
  const { bytes: manifestBytes } = await readRegular(join(directory, 'manifest.json'), 1024 * 1024);
  const manifest = validateBundleValue(contract, 'BundleManifest.schema.json', parseBundleJson(manifestBytes, { maxBytes: 1024 * 1024 }));
  if (manifest.contractManifestSha256 !== contract.manifestSha256 || manifest.bundleDigest !== manifestDigest(manifest.artifacts)) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle manifest authority differs');
  if (manifest.artifacts.some((entry, index) => index > 0 && codeUnitCompare(manifest.artifacts[index - 1].path, entry.path) >= 0)) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle artifact inventory is not uniquely ordered');
  const expectedPaths = manifest.artifacts.some(({ path }) => path === 'conformance.json') ? ['conformance.json', 'environments.jsonl', 'evidence.json', 'result.json', 'samples.jsonl', 'summaries.jsonl'] : ['environments.jsonl', 'evidence.json', 'result.json', 'samples.jsonl', 'summaries.jsonl'];
  if (manifest.artifacts.length !== expectedPaths.length || manifest.artifacts.some(({ path, mediaType }, index) => path !== expectedPaths[index] || mediaType !== (path.endsWith('.jsonl') ? 'application/jsonl' : 'application/json'))) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle manifest artifact inventory is invalid');
  let aggregate = manifestBytes.length;
  for (const entry of manifest.artifacts) { aggregate = checkedAdd(aggregate, entry.bytes, 'bundle artifact bytes'); if (aggregate > HARNESS_LIMITS.maxResultBundleBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'bundle artifact inventory exceeds its aggregate byte bound'); }
  const allowed = new Set(['manifest.json', ...expectedPaths]);
  const handle = await opendir(directory); const actual = new Set();
  for await (const entry of handle) { if (!entry.isFile() || entry.isSymbolicLink()) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle contains a non-regular artifact'); actual.add(entry.name); }
  if (actual.size !== allowed.size || [...actual].some((name) => !allowed.has(name))) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle contains missing or unexpected artifacts');
  const authenticated = new Map();
  for (const entry of manifest.artifacts) authenticated.set(entry.path, { entry, stat: await authenticateRegular(join(directory, entry.path), entry) });
  const resultRead = await readRegular(join(directory, 'result.json'), SMALL_ARTIFACT_BYTES);
  if (!sameStat(resultRead.stat, authenticated.get('result.json').stat) || sha256(resultRead.bytes) !== authenticated.get('result.json').entry.sha256) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle JSON artifact changed after authentication');
  let retainedWorkingBytes = checkedAdd(1_048_576, retainedJsonBytes(manifestBytes.length, 'bundle manifest'), 'bundle retained working bytes');
  retainedWorkingBytes = checkedAdd(retainedWorkingBytes, retainedJsonBytes(resultRead.bytes.length, 'bundle result'), 'bundle retained working bytes');
  if (retainedWorkingBytes > HARNESS_LIMITS.maxWorkingMemoryBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'bundle JSON artifacts exceed the aggregate parse workspace');
  const result = validateBundleValue(contract, 'BenchmarkResultBundle.schema.json', parseBundleJson(resultRead.bytes, { large: true, maxBytes: SMALL_ARTIFACT_BYTES, maxWorkingMemoryBytes: HARNESS_LIMITS.maxWorkingMemoryBytes - retainedWorkingBytes + retainedJsonBytes(resultRead.bytes.length, 'bundle result') }));
  const evidenceRead = await readRegular(join(directory, 'evidence.json'), SMALL_ARTIFACT_BYTES); const evidenceAuthority = authenticated.get('evidence.json');
  if (!sameStat(evidenceRead.stat, evidenceAuthority.stat) || sha256(evidenceRead.bytes) !== evidenceAuthority.entry.sha256) harnessFail('HARNESS_BUNDLE_INVALID', 'evidence artifact changed after authentication');
  const evidenceWorking = retainedJsonBytes(evidenceRead.bytes.length, 'harness evidence');
  if (checkedAdd(retainedWorkingBytes, evidenceWorking, 'bundle retained working bytes') > HARNESS_LIMITS.maxWorkingMemoryBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'harness evidence exceeds the aggregate parse workspace');
  const evidenceReport = validateBundleValue(contract, 'HarnessEvidence.schema.json', parseBundleJson(evidenceRead.bytes, { large: true, maxBytes: SMALL_ARTIFACT_BYTES, maxWorkingMemoryBytes: HARNESS_LIMITS.maxWorkingMemoryBytes - retainedWorkingBytes }));
  retainedWorkingBytes += evidenceWorking;
  const environmentStream = await parseJsonlStream(join(directory, 'environments.jsonl'), authenticated.get('environments.jsonl'), contract, 'EnvironmentRecord.schema.json', HARNESS_LIMITS.maxCorpora * 4 * 5, HARNESS_LIMITS.maxWorkingMemoryBytes - retainedWorkingBytes);
  const environmentRecords = environmentStream.values; retainedWorkingBytes = checkedAdd(retainedWorkingBytes, environmentStream.retainedWorkingBytes, 'bundle retained working bytes');
  const sampleStream = await parseJsonlStream(join(directory, 'samples.jsonl'), authenticated.get('samples.jsonl'), contract, 'BenchmarkSample.schema.json', HARNESS_LIMITS.maxSamples, HARNESS_LIMITS.maxWorkingMemoryBytes - retainedWorkingBytes);
  const samples = sampleStream.values; retainedWorkingBytes = checkedAdd(retainedWorkingBytes, sampleStream.retainedWorkingBytes, 'bundle retained working bytes');
  const summaryStream = await parseJsonlStream(join(directory, 'summaries.jsonl'), authenticated.get('summaries.jsonl'), contract, 'TaskSummary.schema.json', HARNESS_LIMITS.maxSamples, HARNESS_LIMITS.maxWorkingMemoryBytes - retainedWorkingBytes);
  const summaries = summaryStream.values; retainedWorkingBytes = checkedAdd(retainedWorkingBytes, summaryStream.retainedWorkingBytes, 'bundle retained working bytes');
  let conformance = null;
  if (authenticated.has('conformance.json')) {
    const read = await readRegular(join(directory, 'conformance.json'), 1024 * 1024); const authority = authenticated.get('conformance.json');
    if (!sameStat(read.stat, authority.stat) || sha256(read.bytes) !== authority.entry.sha256) harnessFail('HARNESS_BUNDLE_INVALID', 'conformance artifact changed after authentication');
    const conformanceWorking = retainedJsonBytes(read.bytes.length, 'conformance report');
    if (checkedAdd(retainedWorkingBytes, conformanceWorking, 'bundle retained working bytes') > HARNESS_LIMITS.maxWorkingMemoryBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'conformance report exceeds the aggregate parse workspace');
    conformance = validateBundleValue(contract, 'ConformanceReport.schema.json', parseBundleJson(read.bytes, { maxBytes: 1024 * 1024 }));
    retainedWorkingBytes += conformanceWorking;
  }
  validateIdentityInventory(samples, ({ id }) => id, 'sample set');
  validateIdentityInventory(summaries, summaryKey, 'summary set');
  validateIdentityInventory(environmentRecords, environmentKey, 'environment set');
  const reproduced = reproduceMatrix(contract, { samples, summaries, thresholdFile: result.thresholdFile, thresholdDigest: result.thresholdFileDigest, thresholdEvaluations: result.thresholdEvaluations, overallStatus: result.overallStatus, profile: { id: result.reproduction.harnessProfile }, overhead: result.overhead, evidence: result.evidence });
  if (samples.length !== result.sampleCount || canonicalSequenceDigest(samples, 'ogvcs.benchmark/sample-set/v1') !== result.sampleSetDigest || summaries.length !== result.summaryCount || canonicalSequenceDigest(summaries, 'ogvcs.benchmark/summary-set/v1') !== result.summarySetDigest || canonicalJson(reproduced.summaries) !== canonicalJson(summaries) || canonicalJson(reproduced.thresholdEvaluations) !== canonicalJson(result.thresholdEvaluations) || reproduced.overallStatus !== result.overallStatus || result.reproduction.tolerancePartsPerMillion !== reproduced.thresholdFile.comparisonTolerancePartsPerMillion || environmentRecords.length !== result.environmentCount || canonicalSequenceDigest(environmentRecords, 'ogvcs.benchmark/environment-set/v1') !== result.environmentSetDigest || canonicalDigest(evidenceReport, 'ogvcs.benchmark/evidence/v1') !== result.evidenceReportDigest || evidenceReport.faultMatrix.failed + evidenceReport.brokenServices.missed !== result.evidence.faultInvariantFailures || evidenceReport.security.misses !== result.evidence.securityNegativeMisses || evidenceReport.deterministicFaults !== true || (conformance === null) !== (result.conformanceReportDigest === null) || conformance && canonicalDigest(conformance, 'ogvcs.benchmark/conformance-report/v1') !== result.conformanceReportDigest) harnessFail('HARNESS_BUNDLE_INVALID', 'bundle raw artifacts or derived claims differ from the result envelope');
  assertPublicationClaims(contract, result, evidenceReport, environmentRecords, samples, conformance, 'HARNESS_BUNDLE_INVALID');
  return deepFreeze({ verified: true, manifest, result, evidenceReport, environmentRecords, samples, summaries, conformance });
}
