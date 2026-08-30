#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadBenchmarkContract, validateBenchmarkValue } from '../../../foundation/benchmark-fault-harness/src/contract.mjs';
import { HARNESS_ERROR_CODES } from '../../../foundation/benchmark-fault-harness/src/errors.mjs';
import { getProfile, listProfiles } from '../../../foundation/fixture-generator/src/index.mjs';
import { runThreatVectors } from '../../../core/authz-contract/js/src/index.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const workspace = resolve(root, '../../..');
const contract = await loadBenchmarkContract({ root, cache: false });

function assert(condition, message) { if (!condition) throw new Error(message); }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}
function canonical(value) { return JSON.stringify(ordered(value)); }

const referenceCorpora = ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'];
const chunkingCorpora = ['source-like', 'structured', 'already-compressed', 'encrypted-random', 'insertion', 'replacement', 'append'];
const expectedBaseTasks = ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export'];
const chunkingTaskId = 'chunking-verify';
const expectedTasks = [...expectedBaseTasks, chunkingTaskId];
const fixtureProfileVersion = '2.0.0';
const fixtureGeneratorVersion = '1.0.0';
const chunkingProfileVersion = '0.1.0-rc.1';
const chunkingGeneratorVersion = '1.0.0';
const expectedTaskEntries = [
  { assertions: ['workspace-isolated', 'repository-ready'], endCondition: 'configured repository is ready', faultPoints: ['durable.write', 'metadata.commit'], id: 'setup', mutating: false, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'empty isolated run workspace' },
  { assertions: ['status-complete', 'no-hidden-mutation'], endCondition: 'status is complete and generation-bound', faultPoints: [], id: 'status', mutating: false, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'repository and workspace are ready' },
  { assertions: ['content-complete', 'cache-state-observed'], endCondition: 'requested projection is materialized and verified', faultPoints: ['durable.write', 'object.finalize'], id: 'sync', mutating: false, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'requested immutable snapshot and cache state are declared' },
  { assertions: ['content-complete', 'authorized', 'single-visible-commit'], endCondition: 'one visible branch generation names only available content', faultPoints: ['durable.write', 'object.finalize', 'policy.decision', 'branch.cas', 'metadata.commit', 'event.publish', 'index.cursor'], id: 'submit', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'expected branch head, content closure, policy and lock facts are fixed' },
  { assertions: ['single-hard-lock', 'lock-generation-fenced'], endCondition: 'one fenced lock generation is visible', faultPoints: ['policy.decision', 'lock.mutation', 'metadata.commit', 'event.publish'], id: 'lock', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'FileID, branch domain, owner and expected generation are fixed' },
  { assertions: ['content-complete', 'merge-base-bound', 'single-visible-commit'], endCondition: 'merge result is verified and publication is atomic', faultPoints: ['durable.write', 'object.finalize', 'policy.decision', 'branch.cas', 'metadata.commit', 'event.publish', 'index.cursor'], id: 'merge', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'base, source and target snapshots are immutable and declared' },
  { assertions: ['content-complete', 'snapshot-bound'], endCondition: 'CI projection is content-complete and digest-verified', faultPoints: ['object.finalize', 'index.cursor'], id: 'ci', mutating: false, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'immutable snapshot and selection are declared' },
  { assertions: ['content-complete', 'references-verifiable'], endCondition: 'all reached objects and mutable invariants are checked and unreachable objects are swept', faultPoints: ['gc.mark', 'gc.sweep', 'index.cursor'], id: 'verify', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'repository generation is fixed' },
  { assertions: ['backup-verifiable', 'content-complete'], endCondition: 'independently verifiable backup generation is published', faultPoints: ['backup.generate', 'metadata.commit'], id: 'backup', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'metadata generation and content inventory are fixed' },
  { assertions: ['backup-verifiable', 'content-complete', 'activation-atomic'], endCondition: 'restored target verifies before activation', faultPoints: ['durable.write', 'object.finalize', 'metadata.commit'], id: 'restore', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'verified backup generation and empty target are fixed' },
  { assertions: ['export-verifiable', 'content-complete'], endCondition: 'independently verifiable export is finalized', faultPoints: ['durable.write', 'export.finalize'], id: 'export', mutating: true, requirementIds: ['OGVCS-005-FR-02'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'source snapshot and export mode are fixed' },
  { assertions: ['chunking-accounting-balanced', 'chunking-derived-claims-recomputed', 'chunking-thresholds-held'], endCondition: 'bounded chunking compare and verify evidence is retained and authenticated', faultPoints: [], id: 'chunking-verify', mutating: false, requirementIds: ['OGVCS-005-FR-02', 'OGVCS-007-FR-08', 'OGVCS-007-AC-04'], schemaVersion: 'ogvcs.benchmark/workload-definition/v1', startCondition: 'bounded base and candidate chunking workload definitions, threshold authority, and immutable chunking sources are fixed' },
];
const expectedProfiles = [
  { id: 'local-smoke', repetitions: 1, cacheStates: ['cold', 'warm-local-cache'], networkProfiles: ['loopback-simulated'], tasks: expectedBaseTasks, corpora: referenceCorpora, faults: false, privileged: false },
  { id: 'presubmit', repetitions: 3, cacheStates: ['cold', 'warm-local-cache', 'warm-regional-cache', 'mixed-cache'], networkProfiles: ['loopback-simulated', 'studio-near-20ms'], tasks: expectedBaseTasks, corpora: referenceCorpora, faults: true, privileged: false },
  { id: 'nightly', repetitions: 10, cacheStates: ['cold', 'warm-local-cache', 'warm-regional-cache', 'mixed-cache'], networkProfiles: ['loopback-simulated', 'studio-near-20ms', 'regional-80ms', 'intercontinental-200ms'], tasks: expectedBaseTasks, corpora: referenceCorpora, faults: true, privileged: false },
  { id: 'release', repetitions: 30, cacheStates: ['cold', 'warm-local-cache', 'warm-regional-cache', 'mixed-cache'], networkProfiles: ['loopback-simulated', 'studio-near-20ms', 'regional-80ms', 'intercontinental-200ms', 'privileged-netem-80ms'], tasks: expectedBaseTasks, corpora: referenceCorpora, faults: true, privileged: true },
  {
    id: 'chunking-selection-bounded',
    repetitions: 1,
    cacheStates: ['cold'],
    networkProfiles: ['loopback-simulated'],
    tasks: [chunkingTaskId],
    corpora: chunkingCorpora,
    faults: false,
    privileged: false,
    corpusAuthority: { manifestPath: 'spec/chunking-manifest/v1/manifest.json', profileVersion: chunkingProfileVersion, generatorVersion: chunkingGeneratorVersion },
    reproductionCommand: 'node tools/chunking-selection-benchmark-bundle.mjs --output <bundle-dir> --seed <recorded-seed>',
  },
];
const tasks = contract.registries.tasks.entries;
assert(JSON.stringify(tasks.map(({ id }) => id)) === JSON.stringify(expectedTasks), 'task registry differs from the normative operation set');
assert(new Set(tasks.map(({ id }) => id)).size === tasks.length, 'task registry contains duplicate identities');
assert(canonical(tasks) === canonical(expectedTaskEntries), 'task registry bodies drifted from the exact normative operation set');
for (const task of tasks) validateBenchmarkValue(contract, 'WorkloadDefinition.schema.json', task);
assert(JSON.stringify(tasks.find(({ id }) => id === chunkingTaskId)?.assertions) === JSON.stringify(['chunking-accounting-balanced', 'chunking-derived-claims-recomputed', 'chunking-thresholds-held']), 'chunking workload task assertions drifted');

const faults = contract.registries.faults.entries;
assert(faults.length === 12 && faults.every(({ testModeOnly, tasks: names }) => testModeOnly === true && names.length > 0 && names.every((name) => expectedBaseTasks.includes(name))), 'fault registry is incomplete or not test-only');
assert(new Set(faults.map(({ id }) => id)).size === faults.length, 'fault registry contains duplicate identities');
const taskById = new Map(tasks.map((entry) => [entry.id, entry]));
const faultById = new Map(faults.map((entry) => [entry.id, entry]));
for (const task of tasks) for (const faultId of task.faultPoints) assert(faultById.get(faultId)?.tasks.includes(task.id), `task/fault authority is not bidirectional: ${task.id}/${faultId}`);
for (const fault of faults) for (const taskId of fault.tasks) assert(taskById.get(taskId)?.faultPoints.includes(fault.id), `fault/task authority is not bidirectional: ${fault.id}/${taskId}`);

const networks = contract.registries.networks.entries;
assert(networks.some(({ rttMs }) => rttMs === 20) && networks.some(({ rttMs }) => rttMs === 200), 'network registry does not span 20 through 200 ms RTT');
assert(networks.some(({ lossPartsPerMillion, interruptionEvery, duplicateEvery, reorderWindow }) => lossPartsPerMillion > 0 && interruptionEvery > 0 && duplicateEvery > 0 && reorderWindow > 0), 'network registry omits required fault controls');

const harnessProfiles = contract.registries['harness-profiles'].entries;
assert(canonical(harnessProfiles) === canonical(expectedProfiles), 'harness profile registry drifted from the exact bounded matrices');
assert(harnessProfiles.slice(0, 4).every((profile) => canonical(profile.tasks) === canonical(expectedBaseTasks) && canonical(profile.corpora) === canonical(expectedProfiles[0].corpora)), 'base profiles no longer preserve the original task/corpus matrices');

const environmentRecordSchema = JSON.parse(await readFile(resolve(root, 'schemas/EnvironmentRecord.schema.json'), 'utf8'));
assert(
  canonical(environmentRecordSchema.properties.corpus.oneOf) === canonical([
    {
      properties: {
        generatorVersion: { const: fixtureGeneratorVersion },
        profileId: { enum: referenceCorpora },
        profileVersion: { const: fixtureProfileVersion },
      },
    },
    {
      properties: {
        generatorVersion: { const: chunkingGeneratorVersion },
        profileId: { enum: chunkingCorpora },
        profileVersion: { const: chunkingProfileVersion },
      },
    },
  ]),
  'EnvironmentRecord corpus authority branches drifted',
);

const driverProfile = contract.profiles['benchmark-fault-driver-v1'];
assert(driverProfile.baseProtocolProfile === 'ogvcs.control.https-json@1' && driverProfile.testModeOnly === true && driverProfile.productionFaultHooks === 'forbidden', 'driver profile does not preserve the OGVCS-041/test-mode boundary');
assert(driverProfile.requiredCapabilities.length === 6 && driverProfile.operations.length === 8, 'driver capability or operation inventory differs');

const errors = contract.registries.errors.entries.map(({ name }) => name);
assert(JSON.stringify(errors) === JSON.stringify(HARNESS_ERROR_CODES), 'runtime and contract error registries differ');

for (const threshold of Object.values(contract.thresholds)) validateBenchmarkValue(contract, 'ThresholdFile.schema.json', threshold);
assert(
  contract.thresholds['default-v1'].entries.every(({ profiles }) => canonical(profiles) === canonical(['local-smoke', 'presubmit', 'nightly', 'release'])),
  'default threshold authority must remain scoped to the original four profiles',
);
assert(
  contract.thresholds['chunking-selection-bounded-v1'].entries.every(({ profiles, taskId }) => canonical(profiles) === canonical(['chunking-selection-bounded']) && taskId === chunkingTaskId),
  'chunking threshold authority must remain scoped to the additive chunking profile only',
);
const cases = contract.vectors.conformance.cases;
assert(cases.length === contract.manifest.counts.scenarios, 'scenario inventory differs from manifest');
assert(new Set(cases.map(({ id }) => id)).size === cases.length, 'scenario inventory contains duplicate identities');
const covered = new Set(cases.flatMap(({ requirementIds }) => requirementIds));
for (const threshold of Object.values(contract.thresholds)) for (const entry of threshold.entries) covered.add(entry.requirementId);
for (const family of ['FR', 'NFR', 'AC']) {
  const count = family === 'FR' ? 10 : family === 'NFR' ? 3 : 7;
  for (let index = 1; index <= count; index += 1) {
    const id = `OGVCS-005-${family}-${String(index).padStart(2, '0')}`;
    assert(covered.has(id), `requirement lacks executable contract evidence: ${id}`);
  }
}

const fixturePin = contract.manifest.predecessorPins.fixtures;
const chunkingPin = contract.manifest.predecessorPins.chunking;
const fixturePackage = JSON.parse(await readFile(resolve(workspace, 'foundation/fixture-generator/package.json')));
const fixtureProfiles = listProfiles().map(({ id, version }) => getProfile(id, version));
const chunkingManifestBytes = await readFile(resolve(workspace, 'spec/chunking-manifest/v1/manifest.json'));
const chunkingManifest = JSON.parse(chunkingManifestBytes);
assert(fixturePackage.name === fixturePin.package, 'fixture package name pin drifted');
assert(fixturePackage.version === fixturePin.packageVersion, 'fixture package version pin drifted');
assert(fixtureProfiles.every(({ version }) => version === fixturePin.profileVersion), 'fixture profile version pin drifted');
assert(
  canonical(fixtureProfiles.map(({ id, digest: profileDigest }) => ({ id, digest: profileDigest })))
    === canonical(fixturePin.profiles),
  'fixture profile inventory pin drifted',
);
assert(digest(canonical(fixtureProfiles)) === fixturePin.profileSetSha256, 'fixture profile-set pin drifted');
assert(canonical(chunkingPin) === canonical({
  contractVersion: chunkingManifest.contractVersion,
  manifestPath: 'spec/chunking-manifest/v1/manifest.json',
  manifestSha256: digest(chunkingManifestBytes),
  profile: chunkingManifest.profile,
  tableSha256: chunkingManifest.tableSha256,
}), 'chunking predecessor pin drifted');

for (const [name, pin] of Object.entries(contract.manifest.predecessorPins)) {
  if (name === 'fixtures') continue;
  const bytes = await readFile(resolve(workspace, pin.manifestPath));
  assert(digest(bytes) === pin.manifestSha256, `predecessor manifest pin drifted: ${name}`);
}
const authorizationReport = await runThreatVectors();
const authorizationPin = contract.manifest.predecessorPins.authorization;
assert(authorizationReport.manifestSha256 === authorizationPin.manifestSha256 && authorizationReport.registrySetSha256 === authorizationPin.registrySetSha256, 'authorization reference report authority drifted');
assert(authorizationReport.adapter === authorizationPin.referenceAdapter && authorizationReport.vectors === authorizationPin.referenceVectors && authorizationReport.resultsSha256 === authorizationPin.referenceResultsSha256 && authorizationReport.failed === 0, 'authorization reference result inventory drifted');

process.stdout.write(`validated benchmark-fault contract ${contract.manifestSha256}: ${tasks.length} tasks, ${faults.length} fault points, ${cases.length} scenarios\n`);
