import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { buildResultBundle, verifyResultBundle, writeResultBundle } from './bundle.mjs';
import { canonicalDigest, canonicalSequenceDigest, deepFreeze } from './canonical.mjs';
import { runHarnessConformance } from './conformance.mjs';
import { loadBenchmarkContract, validateBenchmarkValue } from './contract.mjs';
import { materializeReferenceCorpora } from './corpora.mjs';
import { harnessFail } from './errors.mjs';
import { runBrokenServiceSelfTest, runFaultMatrix, proveFaultDeterminism } from './fault-harness.mjs';
import { runBenchmarkMatrix, applyEvidenceToMatrix } from './runner.mjs';
import { runSecurityNegativeSuites } from './security.mjs';

export function planHarnessMatrix(contract) {
  return deepFreeze(contract.registries['harness-profiles'].entries.map((profile) => ({
    profile: profile.id,
    corpora: profile.corpora.length,
    tasks: profile.tasks.length,
    cacheStates: profile.cacheStates.length,
    networkProfiles: profile.networkProfiles.length,
    repetitions: profile.repetitions,
    timedSamples: profile.corpora.length * profile.tasks.length * profile.cacheStates.length * profile.networkProfiles.length * profile.repetitions,
    faultPoints: profile.faults ? contract.registries.faults.entries.length : 0,
    privileged: profile.privileged,
  })));
}

function buildEvidenceReport(contract, faultMatrix, brokenServices, security, deterministicFaults) {
  const report = {
    schemaVersion: 'ogvcs.benchmark/evidence/v1',
    faultMatrix: { rows: faultMatrix.rows, failed: faultMatrix.failed, scheduleSetDigest: canonicalSequenceDigest(faultMatrix.schedules, 'ogvcs.benchmark/fault-schedule-set/v1') },
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
  };
  return validateBenchmarkValue(contract, 'HarnessEvidence.schema.json', report);
}

export async function runReferenceHarness(options) {
  if (!options || typeof options.workspace !== 'string' || options.workspace.length < 1 || options.workspace.includes('\0')) harnessFail('HARNESS_INPUT_INVALID', 'reference harness workspace is required');
  await mkdir(options.workspace, { recursive: true });
  const contract = options.contract ?? await loadBenchmarkContract({ ...(options.contractRoot ? { root: options.contractRoot } : {}), cache: false });
  const corpora = options.corpora ?? await materializeReferenceCorpora(options.workspace, { seed: options.seed });
  const [faultMatrix, brokenServices, security] = await Promise.all([runFaultMatrix(contract, { seed: options.seed }), runBrokenServiceSelfTest(contract), runSecurityNegativeSuites()]);
  const deterministicFaults = proveFaultDeterminism(contract, options.seed);
  const evidenceReport = buildEvidenceReport(contract, faultMatrix, brokenServices, security, deterministicFaults);
  const initialMatrix = await runBenchmarkMatrix({
    contract, corpora, harnessProfile: options.harnessProfile ?? 'local-smoke', seed: options.seed, iterations: options.iterations,
    operator: options.operator, classification: options.classification, filesystem: options.filesystem, implementationCommit: options.implementationCommit,
    implementationId: options.implementationId, implementationVersion: options.implementationVersion, clientRegion: options.clientRegion, serviceRegion: options.serviceRegion, cacheRegion: options.cacheRegion,
    environmentClock: options.clock, measurement: options.measurement, measurementFactory: options.measurementFactory, overhead: options.overhead,
    concurrency: options.concurrency, taskTimeoutMs: options.taskTimeoutMs, maxWorkingMemoryBytes: options.maxWorkingMemoryBytes, signal: options.signal,
    simulateNetworkDelay: options.simulateNetworkDelay, allowPrivileged: options.allowPrivileged, networkAdapter: options.networkAdapter, networkAdapterFactory: options.networkAdapterFactory, serviceFactory: options.serviceFactory,
    faultInvariantFailures: faultMatrix.failed + brokenServices.missed, securityNegativeMisses: security.misses, protocolFailures: 0,
  });
  const preliminary = buildResultBundle(contract, initialMatrix, { seed: options.seed, operator: options.operator, classification: options.classification, clock: options.clock, retentionDays: options.retentionDays, publicMetadata: options.publicMetadata, command: options.command, evidenceReport, faultSchedules: [...faultMatrix.schedules, deterministicFaults.schedule] });
  const conformance = await runHarnessConformance(contract, { matrix: initialMatrix, corpora, publication: preliminary });
  const matrix = applyEvidenceToMatrix(initialMatrix, { faultInvariantFailures: faultMatrix.failed + brokenServices.missed, securityNegativeMisses: security.misses, protocolFailures: conformance.failed });
  const publication = buildResultBundle(contract, matrix, { seed: options.seed, operator: options.operator, classification: options.classification, clock: options.clock, retentionDays: options.retentionDays, publicMetadata: options.publicMetadata, command: options.command, conformanceReport: conformance, evidenceReport, faultSchedules: [...faultMatrix.schedules, deterministicFaults.schedule] });
  let written;
  if (options.output) { await mkdir(dirname(options.output), { recursive: true }); written = await writeResultBundle(options.output, contract, publication); await verifyResultBundle(options.output, contract); }
  return deepFreeze({ contract, corpora, matrix, publication, conformance, faultMatrix, brokenServices, security, deterministicFaults, written });
}
