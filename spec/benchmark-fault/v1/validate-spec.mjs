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

const expectedTasks = ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export'];
const tasks = contract.registries.tasks.entries;
assert(JSON.stringify(tasks.map(({ id }) => id)) === JSON.stringify(expectedTasks), 'task registry differs from the normative operation set');
assert(new Set(tasks.map(({ id }) => id)).size === tasks.length, 'task registry contains duplicate identities');
for (const task of tasks) validateBenchmarkValue(contract, 'WorkloadDefinition.schema.json', task);

const faults = contract.registries.faults.entries;
assert(faults.length === 12 && faults.every(({ testModeOnly, tasks: names }) => testModeOnly === true && names.length > 0 && names.every((name) => expectedTasks.includes(name))), 'fault registry is incomplete or not test-only');
assert(new Set(faults.map(({ id }) => id)).size === faults.length, 'fault registry contains duplicate identities');
const taskById = new Map(tasks.map((entry) => [entry.id, entry]));
const faultById = new Map(faults.map((entry) => [entry.id, entry]));
for (const task of tasks) for (const faultId of task.faultPoints) assert(faultById.get(faultId)?.tasks.includes(task.id), `task/fault authority is not bidirectional: ${task.id}/${faultId}`);
for (const fault of faults) for (const taskId of fault.tasks) assert(taskById.get(taskId)?.faultPoints.includes(fault.id), `fault/task authority is not bidirectional: ${fault.id}/${taskId}`);

const networks = contract.registries.networks.entries;
assert(networks.some(({ rttMs }) => rttMs === 20) && networks.some(({ rttMs }) => rttMs === 200), 'network registry does not span 20 through 200 ms RTT');
assert(networks.some(({ lossPartsPerMillion, interruptionEvery, duplicateEvery, reorderWindow }) => lossPartsPerMillion > 0 && interruptionEvery > 0 && duplicateEvery > 0 && reorderWindow > 0), 'network registry omits required fault controls');

const harnessProfiles = contract.registries['harness-profiles'].entries;
for (const profile of harnessProfiles) {
  assert(JSON.stringify([...profile.corpora].sort()) === JSON.stringify(['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like']), `${profile.id} omits a reference corpus`);
  assert(profile.tasks.length === expectedTasks.length, `${profile.id} omits a workload task`);
}
assert(harnessProfiles.find(({ id }) => id === 'presubmit')?.privileged === false, 'presubmit profile must remain unprivileged');
assert(harnessProfiles.find(({ id }) => id === 'release')?.privileged === true, 'release profile must make the isolated privileged matrix explicit');

const driverProfile = contract.profiles['benchmark-fault-driver-v1'];
assert(driverProfile.baseProtocolProfile === 'ogvcs.control.https-json@1' && driverProfile.testModeOnly === true && driverProfile.productionFaultHooks === 'forbidden', 'driver profile does not preserve the OGVCS-041/test-mode boundary');
assert(driverProfile.requiredCapabilities.length === 6 && driverProfile.operations.length === 8, 'driver capability or operation inventory differs');

const errors = contract.registries.errors.entries.map(({ name }) => name);
assert(JSON.stringify(errors) === JSON.stringify(HARNESS_ERROR_CODES), 'runtime and contract error registries differ');

for (const threshold of Object.values(contract.thresholds)) validateBenchmarkValue(contract, 'ThresholdFile.schema.json', threshold);
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
const fixturePackage = JSON.parse(await readFile(resolve(workspace, 'foundation/fixture-generator/package.json')));
const fixtureProfiles = listProfiles().map(({ id, version }) => getProfile(id, version));
assert(fixturePackage.name === fixturePin.package, 'fixture package name pin drifted');
assert(fixturePackage.version === fixturePin.packageVersion, 'fixture package version pin drifted');
assert(fixtureProfiles.every(({ version }) => version === fixturePin.profileVersion), 'fixture profile version pin drifted');
assert(
  canonical(fixtureProfiles.map(({ id, digest: profileDigest }) => ({ id, digest: profileDigest })))
    === canonical(fixturePin.profiles),
  'fixture profile inventory pin drifted',
);
assert(digest(canonical(fixtureProfiles)) === fixturePin.profileSetSha256, 'fixture profile-set pin drifted');

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
