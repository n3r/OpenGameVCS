import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { DeterministicCacheController } from './cache.mjs';
import { buildResultBundle, verifyResultBundle, writeResultBundle } from './bundle.mjs';
import { canonicalDigest, deepFreeze } from './canonical.mjs';
import { compareResultBundles } from './comparison.mjs';
import { validateBenchmarkValue } from './contract.mjs';
import { runExternalDriverConformance, startExternalDriver } from './driver.mjs';
import { BenchmarkHarnessError } from './errors.mjs';
import { FakeRepositoryService } from './fake-service.mjs';
import { proveFaultDeterminism, runBrokenServiceSelfTest, runFaultMatrix } from './fault-harness.mjs';
import { measureHarnessOverhead } from './measurement.mjs';
import { NetworkController } from './network.mjs';
import { redactPublicData } from './redaction.mjs';
import { runBenchmarkMatrix } from './runner.mjs';
import { runSecurityNegativeSuites } from './security.mjs';
import { summarizeSamples } from './statistics.mjs';
import { snapshotData } from './input.mjs';
import { evaluateThresholds } from './thresholds.mjs';

function fakeDriverDescriptor(contract, flags = []) {
  return [process.execPath, fileURLToPath(new URL('../bin/ogvcs-benchmark-fake-driver.mjs', import.meta.url)), '--contract', fileURLToPath(new URL(contract.root)), ...flags];
}

async function codeOf(operation) {
  try { const value = await operation(); return value ?? { code: 'HARNESS_OK', preMutation: true }; }
  catch (error) { if (error instanceof BenchmarkHarnessError) return { code: error.code, preMutation: true }; throw error; }
}

async function driverNegotiation(contract, flags = []) {
  const session = await startExternalDriver(fakeDriverDescriptor(contract, flags), contract, { timeoutMs: 30_000 });
  await session.close();
  return { code: 'HARNESS_OK', preMutation: true };
}

async function driverRetry(contract) {
  const session = await startExternalDriver(fakeDriverDescriptor(contract, ['--retry-once-operation', 'run-task']), contract, { timeoutMs: 30_000 });
  try {
    await session.command('configure', { cacheState: 'cold', networkProfile: 'loopback-simulated' });
    await session.command('start', {});
    const value = await session.command('run-task', { taskId: 'setup', input: { idempotencyKey: 'conformance-retry-task' } });
    await session.close();
    return { code: value.code, preMutation: value.preMutation };
  } catch (error) { await session.abort(); throw error; }
}

function sample(overrides = {}) {
  return {
    schemaVersion: 'ogvcs.benchmark/sample/v1', id: 'sample/conformance', taskId: 'status', corpusId: 'code-heavy', repetition: 0, cacheState: 'cold', networkProfile: 'loopback-simulated', status: 'success', failureCode: null,
    wallMicroseconds: 100, cpuMicroseconds: 80, peakMemoryBytes: 1024, diskReadBytes: 128, diskWriteBytes: 0, networkReadBytes: 0, networkWriteBytes: 0, logicalBytes: 1024, uniqueBytes: 512, retries: 0,
    assertions: [{ id: 'status-complete', passed: true }], faultScheduleDigest: null, ...overrides,
  };
}

function deterministicMeasurement() {
  let wall = 0n;
  let user = 0;
  return {
    clock() { wall += 1_000_000n; return wall; },
    cpu() { user += 500; return { user, system: 0 }; },
    memory() { return 1_048_576; },
    sampleIntervalMs: 1_000,
  };
}

async function proveSecondOperatorReproduction(contract, corpora, referencePublication) {
  const common = {
    contract,
    corpora,
    harnessProfile: 'local-smoke',
    iterations: 1,
    seed: 'ogvcs-second-operator-conformance-v1',
    classification: 'synthetic',
    filesystem: 'conformance-memory',
    implementationCommit: 'conformance-fixed-implementation',
    environmentClock: () => new Date('2026-01-01T00:00:00.000Z'),
    measurementFactory: () => deterministicMeasurement(),
    overhead: { measuredBasisPoints: 0, correctionApplied: false, correctionMicroseconds: 0, method: 'measured-below-threshold' },
    simulateNetworkDelay: false,
  };
  const [leftMatrix, rightMatrix] = await Promise.all([
    runBenchmarkMatrix({ ...common, operator: 'independent-operator-a' }),
    runBenchmarkMatrix({ ...common, operator: 'independent-operator-b' }),
  ]);
  const bundleOptions = { seed: common.seed, classification: 'synthetic', clock: common.environmentClock, evidenceReport: referencePublication.evidenceReport, faultSchedules: referencePublication.result.faultSchedules };
  const left = buildResultBundle(contract, leftMatrix, { ...bundleOptions, operator: 'independent-operator-a', command: 'independent-operator-a bounded reproduction' });
  const right = buildResultBundle(contract, rightMatrix, { ...bundleOptions, operator: 'independent-operator-b', command: 'independent-operator-b bounded reproduction' });
  if (left.environmentRecords.every((row, index) => row.operatorDigest === right.environmentRecords[index]?.operatorDigest)) return { code: 'HARNESS_ASSERTION_FAILED', preMutation: true };
  const report = compareResultBundles(contract, left, right, { tolerancePartsPerMillion: 0 });
  return { code: report.reproduced ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: true };
}

export async function runHarnessConformance(contract, options) {
  options = snapshotData(options, 'harness conformance options');
  const cases = contract.vectors.conformance.cases;
  const memo = {};
  const evaluate = async (entry) => {
    switch (entry.id) {
      case 'environment-record-complete': return { code: options.matrix.environmentRecords.every((value) => { validateBenchmarkValue(contract, 'EnvironmentRecord.schema.json', value); return true; }) ? 'HARNESS_OK' : 'HARNESS_INPUT_INVALID', preMutation: true };
      case 'task-start-end-and-assertions': {
        const service = new FakeRepositoryService(); const value = await service.executeTask('status', { idempotencyKey: 'conformance-incomplete-status' });
        return { code: value.code === 'HARNESS_TASK_INCOMPLETE' && value.assertions.some(({ id, passed }) => id === 'status-complete' && passed === false) ? value.code : 'HARNESS_ASSERTION_FAILED', preMutation: value.mutationCount === 0 };
      }
      case 'task-assertion-inventory-complete': {
        const serviceFactory = () => {
          const service = new FakeRepositoryService();
          return {
            snapshot: () => service.snapshot(),
            async executeTask(taskId, input) {
              const result = await service.executeTask(taskId, input);
              return taskId === 'status' ? { ...result, assertions: result.assertions.slice(1) } : result;
            },
          };
        };
        try {
          await runBenchmarkMatrix({ contract, corpora: options.corpora, harnessProfile: 'local-smoke', iterations: 1, concurrency: 1, serviceFactory, measurementFactory: () => deterministicMeasurement(), overhead: { measuredBasisPoints: 0, correctionApplied: false, correctionMicroseconds: 0, method: 'measured-below-threshold' }, simulateNetworkDelay: false });
          return { code: 'HARNESS_OK', preMutation: false };
        } catch (error) {
          if (error instanceof BenchmarkHarnessError) return { code: error.code, preMutation: false };
          throw error;
        }
      }
      case 'task-status-retryability-consistent': {
        const serviceFactory = () => {
          const service = new FakeRepositoryService();
          return {
            snapshot: () => service.snapshot(),
            async executeTask(taskId, input) {
              const result = await service.executeTask(taskId, input);
              return taskId === 'status' ? { ...result, status: 'incomplete', code: 'HARNESS_ASSERTION_FAILED' } : result;
            },
          };
        };
        try {
          await runBenchmarkMatrix({ contract, corpora: options.corpora, harnessProfile: 'local-smoke', iterations: 1, concurrency: 1, serviceFactory, measurementFactory: () => deterministicMeasurement(), overhead: { measuredBasisPoints: 0, correctionApplied: false, correctionMicroseconds: 0, method: 'measured-below-threshold' }, simulateNetworkDelay: false });
          return { code: 'HARNESS_OK', preMutation: false };
        } catch (error) {
          if (error instanceof BenchmarkHarnessError) return { code: error.code, preMutation: false };
          throw error;
        }
      }
      case 'network-range-and-fault-controls': return { code: contract.registries.networks.entries.some(({ rttMs }) => rttMs === 20) && contract.registries.networks.entries.some(({ rttMs, lossPartsPerMillion, interruptionEvery, duplicateEvery, reorderWindow }) => rttMs === 200 && lossPartsPerMillion > 0 && interruptionEvery > 0 && duplicateEvery > 0 && reorderWindow > 0) ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: true };
      case 'statistics-and-byte-accounting': {
        const rows = summarizeSamples([sample(), sample({ id: 'sample/conformance-2', repetition: 1, wallMicroseconds: 300 })]);
        return { code: rows[0].durationMicroseconds.p50 === 100 && rows[0].durationMicroseconds.p95 === 300 && rows[0].bytes.logical === 2048 ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: true };
      }
      case 'all-five-corpora-smoke': return { code: options.corpora.length === 5 && options.corpora.every(({ verified }) => verified) ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: false };
      case 'second-operator-tolerance': {
        memo.reproduction ??= await proveSecondOperatorReproduction(contract, options.corpora, options.publication);
        return memo.reproduction;
      }
      case 'comparison-tolerance-authority': return codeOf(() => compareResultBundles(contract, options.publication, options.publication, { tolerancePartsPerMillion: contract.thresholds['default-v1'].comparisonTolerancePartsPerMillion + 1 }));
      case 'tiered-matrix-without-code-edit': {
        const profiles = contract.registries['harness-profiles'].entries;
        const baseProfiles = profiles.filter(({ id }) => ['local-smoke', 'presubmit', 'nightly', 'release'].includes(id));
        const additiveProfiles = profiles.filter(({ id }) => !['local-smoke', 'presubmit', 'nightly', 'release'].includes(id));
        const exactBase = canonicalDigest(baseProfiles, 'ogvcs.benchmark/conformance-profile-set/v1') === canonicalDigest([
          { id: 'local-smoke', repetitions: 1, cacheStates: ['cold', 'warm-local-cache'], networkProfiles: ['loopback-simulated'], tasks: ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export'], corpora: ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'], faults: false, privileged: false },
          { id: 'presubmit', repetitions: 3, cacheStates: ['cold', 'warm-local-cache', 'warm-regional-cache', 'mixed-cache'], networkProfiles: ['loopback-simulated', 'studio-near-20ms'], tasks: ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export'], corpora: ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'], faults: true, privileged: false },
          { id: 'nightly', repetitions: 10, cacheStates: ['cold', 'warm-local-cache', 'warm-regional-cache', 'mixed-cache'], networkProfiles: ['loopback-simulated', 'studio-near-20ms', 'regional-80ms', 'intercontinental-200ms'], tasks: ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export'], corpora: ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'], faults: true, privileged: false },
          { id: 'release', repetitions: 30, cacheStates: ['cold', 'warm-local-cache', 'warm-regional-cache', 'mixed-cache'], networkProfiles: ['loopback-simulated', 'studio-near-20ms', 'regional-80ms', 'intercontinental-200ms', 'privileged-netem-80ms'], tasks: ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export'], corpora: ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'], faults: true, privileged: true },
        ], 'ogvcs.benchmark/conformance-profile-set/v1');
        const exactAdditive = canonicalDigest(additiveProfiles, 'ogvcs.benchmark/conformance-profile-set/v1') === canonicalDigest([
          {
            id: 'chunking-selection-bounded',
            repetitions: 1,
            cacheStates: ['cold'],
            networkProfiles: ['loopback-simulated'],
            tasks: ['chunking-verify'],
            corpora: ['source-like', 'structured', 'already-compressed', 'encrypted-random', 'insertion', 'replacement', 'append'],
            faults: false,
            privileged: false,
            corpusAuthority: { manifestPath: 'spec/chunking-manifest/v1/manifest.json', profileVersion: '0.1.0-rc.1', generatorVersion: '1.0.0' },
            reproductionCommand: 'node tools/chunking-selection-benchmark-bundle.mjs --output <bundle-dir> --seed <recorded-seed>',
          },
        ], 'ogvcs.benchmark/conformance-profile-set/v1');
        return { code: exactBase && exactAdditive ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: true };
      }
      case 'driver-compatible-negotiation': return driverNegotiation(contract);
      case 'driver-incompatible-before-mutation': return codeOf(() => driverNegotiation(contract, ['--incompatible']));
      case 'driver-malformed-line-bounded': return codeOf(() => driverNegotiation(contract, ['--malformed-hello']));
      case 'driver-message-limit-before-mutation': return codeOf(() => driverNegotiation(contract, ['--oversized-hello']));
      case 'driver-retry-idempotent': return driverRetry(contract);
      case 'driver-lifecycle-fault-hook-executed': {
        memo.driverFull ??= await runExternalDriverConformance(fakeDriverDescriptor(contract), contract, { timeoutMs: 30_000 });
        return { code: memo.driverFull.failed === 0 && memo.driverFull.faultObserved === true ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: false };
      }
      case 'fault-schedule-repeatable': return { code: proveFaultDeterminism(contract).deterministic ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: true };
      case 'fault-matrix-healthy': memo.faults ??= await runFaultMatrix(contract); return { code: memo.faults.failed === 0 ? 'HARNESS_OK' : 'HARNESS_FAULT_INVARIANT_FAILED', preMutation: false };
      case 'broken-submit-detected': memo.broken ??= await runBrokenServiceSelfTest(contract); return { code: memo.broken.missed === 0 ? 'HARNESS_FAULT_INVARIANT_FAILED' : 'HARNESS_ASSERTION_FAILED', preMutation: false };
      case 'authorization-enumeration-detected': memo.security ??= await runSecurityNegativeSuites(); return { code: memo.security.enumerationDetected ? 'HARNESS_ASSERTION_FAILED' : 'HARNESS_OK', preMutation: true };
      case 'workspace-escape-detected': memo.security ??= await runSecurityNegativeSuites(); return { code: memo.security.workspaceEscapeDetected ? 'HARNESS_ASSERTION_FAILED' : 'HARNESS_OK', preMutation: true };
      case 'cache-state-independent-inspection': {
        const cache = new DeterministicCacheController(); const rows = contract.registries['cache-states'].entries.map(({ id }) => cache.prepare(id));
        return { code: new Set(rows.map(({ stateDigest }) => stateDigest)).size === 4 && rows[0].localBytes === 0 && rows[1].localBytes > 0 && rows[2].regionalBytes > 0 && rows[3].localBytes > 0 && rows[3].regionalBytes > 0 ? 'HARNESS_OK' : 'HARNESS_CACHE_STATE_INVALID', preMutation: true };
      }
      case 'threshold-requirement-binding': {
        const summary = summarizeSamples([sample({ status: 'failed', failureCode: 'HARNESS_ASSERTION_FAILED', assertions: [{ id: 'status-complete', passed: false }] })]);
        const value = evaluateThresholds(contract.thresholds['default-v1'], summary, { harnessProfile: 'local-smoke', overheadBasisPoints: 0, faultInvariantFailures: 0, securityNegativeMisses: 0, protocolFailures: 0 });
        return { code: value.gateFailed ? 'HARNESS_THRESHOLD_FAILED' : 'HARNESS_OK', preMutation: true };
      }
      case 'public-bundle-tamper-detected': {
        const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-tamper-')); const directory = join(root, 'bundle');
        try { await writeResultBundle(directory, contract, options.publication); const target = join(directory, 'samples.jsonl'); const bytes = await readFile(target); bytes[0] ^= 1; await writeFile(target, bytes); return await codeOf(() => verifyResultBundle(directory, contract)); }
        finally { await rm(root, { recursive: true, force: true }); }
      }
      case 'public-bundle-derived-claims-recomputed': {
        const thresholdEvaluations = options.matrix.thresholdEvaluations.map((row, index) => index === 0 ? { ...row, actual: row.actual + 1 } : row);
        return codeOf(() => buildResultBundle(contract, { ...options.matrix, thresholdEvaluations }, { evidenceReport: options.publication.evidenceReport, faultSchedules: options.publication.result.faultSchedules }));
      }
      case 'public-bundle-evidence-claims-recomputed': {
        const rows = options.publication.evidenceReport.faultMatrix.rows.slice(1);
        const evidenceReport = { ...options.publication.evidenceReport, faultMatrix: { ...options.publication.evidenceReport.faultMatrix, rows } };
        return codeOf(() => buildResultBundle(contract, options.matrix, { evidenceReport, faultSchedules: options.publication.result.faultSchedules }));
      }
      case 'public-bundle-security-authority-binding': {
        const security = { ...options.publication.evidenceReport.security, pathCases: options.publication.evidenceReport.security.pathCases.slice(1) };
        const evidenceReport = { ...options.publication.evidenceReport, security };
        return codeOf(() => buildResultBundle(contract, options.matrix, { evidenceReport, faultSchedules: options.publication.result.faultSchedules }));
      }
      case 'public-bundle-authority-binding': {
        const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-authority-'));
        try {
          const publication = { ...options.publication, result: { ...options.publication.result, contractManifestSha256: '0'.repeat(64) } };
          return await codeOf(() => writeResultBundle(join(root, 'bundle'), contract, publication));
        } finally { await rm(root, { recursive: true, force: true }); }
      }
      case 'public-bundle-input-stability': {
        const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-stability-')); const directory = join(root, 'bundle');
        try {
          const publication = structuredClone(options.publication);
          const pending = writeResultBundle(directory, contract, publication);
          publication.samples[0].wallMicroseconds += 1;
          return await codeOf(() => pending);
        } finally { await rm(root, { recursive: true, force: true }); }
      }
      case 'public-bundle-conformance-inventory': {
        const rows = contract.vectors.conformance.cases.map((entry, index) => ({ id: index === 0 ? `forged-${entry.id}` : entry.id, requirementIds: entry.requirementIds, status: 'passed', code: entry.expected.code, preMutation: entry.expected.preMutation }));
        const conformanceReport = { schemaVersion: 'ogvcs.benchmark/conformance-report/v1', contractManifestSha256: contract.manifestSha256, implementation: 'ogvcs.benchmark/forged-conformance@1', cases: rows.length, passed: rows.length, failed: 0, resultsDigest: canonicalDigest(rows, 'ogvcs.benchmark/conformance-results/v1'), rows };
        const publication = { ...options.publication, result: { ...options.publication.result, conformanceReportDigest: canonicalDigest(conformanceReport, 'ogvcs.benchmark/conformance-report/v1') }, conformanceReport };
        const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-conformance-inventory-'));
        try { return await codeOf(() => writeResultBundle(join(root, 'bundle'), contract, publication)); }
        finally { await rm(root, { recursive: true, force: true }); }
      }
      case 'public-bundle-public-fields-owned': {
        const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-public-fields-'));
        try {
          const publication = { ...options.publication, result: { ...options.publication.result, reproduction: { ...options.publication.result.reproduction, command: 'caller-owned --access-token credential-canary' } } };
          return await codeOf(() => writeResultBundle(join(root, 'bundle'), contract, publication));
        } finally { await rm(root, { recursive: true, force: true }); }
      }
      case 'partner-identifier-redacted': {
        const marker = 'partner-canary-never-publish'; const value = redactPublicData({ partnerId: marker, accessToken: 'credential-canary', safe: 'ok' });
        return { code: JSON.stringify(value).includes(marker) || JSON.stringify(value).includes('credential-canary') || value.credentialsRemoved !== 1 || value.partnerIdentifiersHashed !== 1 ? 'HARNESS_ASSERTION_FAILED' : 'HARNESS_OK', preMutation: true };
      }
      case 'privileged-network-isolated': return codeOf(async () => new NetworkController(contract.registries.networks.entries.find(({ id }) => id === 'privileged-netem-80ms')));
      case 'privileged-network-apply-rollback': {
        let reset = 0;
        const actual = await codeOf(() => new NetworkController(contract.registries.networks.entries.find(({ id }) => id === 'privileged-netem-80ms'), { allowPrivileged: true, adapter: { isolated: true, apply() { throw new Error('partial apply'); }, reset() { reset += 1; } } }));
        return reset === 1 ? actual : { code: 'HARNESS_ASSERTION_FAILED', preMutation: true };
      }
      case 'measurement-overhead-reported-or-corrected': {
        const value = await measureHarnessOverhead({ baselineMicroseconds: [100, 100, 100, 100, 100], wrappedMicroseconds: [106, 106, 106, 106, 106] });
        return { code: value.measuredBasisPoints === 600 && value.correctionApplied && value.method === 'measured-and-corrected' ? 'HARNESS_OK' : 'HARNESS_ASSERTION_FAILED', preMutation: true };
      }
      default: return { code: 'HARNESS_INPUT_INVALID', preMutation: true };
    }
  };
  const rows = [];
  for (const entry of cases) {
    const actual = await evaluate(entry); const passed = actual.code === entry.expected.code && actual.preMutation === entry.expected.preMutation;
    rows.push({ id: entry.id, requirementIds: entry.requirementIds, status: passed ? 'passed' : 'failed', code: actual.code, preMutation: actual.preMutation });
  }
  const report = { schemaVersion: 'ogvcs.benchmark/conformance-report/v1', contractManifestSha256: contract.manifestSha256, implementation: options.implementation ?? 'ogvcs.benchmark/reference-js@1', cases: rows.length, passed: rows.filter(({ status }) => status === 'passed').length, failed: rows.filter(({ status }) => status === 'failed').length, resultsDigest: canonicalDigest(rows, 'ogvcs.benchmark/conformance-results/v1'), rows };
  return deepFreeze(validateBenchmarkValue(contract, 'ConformanceReport.schema.json', report));
}
