#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { getProfile, listProfiles } from '../../../../foundation/fixture-generator/src/index.mjs';
import { runThreatVectors } from '../../../../core/authz-contract/js/src/index.mjs';
import {
  CONTRACT_VERSION,
  PACKAGE_NAME,
  PROFILES,
  REGISTRIES,
  SCHEMAS,
  THRESHOLDS,
  VECTORS,
} from './model.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = resolve(root, '../../..');
const check = process.argv.includes('--check');

function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]));
  }
  return value;
}

function canonical(value) {
  return JSON.stringify(ordered(value));
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function compareText(left, right) { return left < right ? -1 : left > right ? 1 : 0; }

function artifact(path, text) {
  const bytes = Buffer.byteLength(text);
  return { path, bytes, sha256: digest(text), mediaType: 'application/json' };
}

function setDigest(entries) {
  return digest(canonical(entries.map(({ path, sha256 }) => ({ path, sha256 })).sort((a, b) => compareText(a.path, b.path))));
}

async function manifestPin(relative) {
  const bytes = await readFile(resolve(workspace, relative));
  const value = JSON.parse(bytes);
  return {
    contractVersion: value.contractVersion ?? value.formatVersion ?? value.version,
    manifestPath: relative,
    manifestSha256: digest(bytes),
    registrySetSha256: value.registrySetSha256,
  };
}

async function emit(relative, text) {
  const target = resolve(root, relative);
  if (check) {
    let existing;
    try { existing = await readFile(target, 'utf8'); } catch { throw new Error(`missing generated benchmark contract artifact: ${relative}`); }
    if (existing !== text) throw new Error(`generated benchmark contract artifact differs: ${relative}`);
    return;
  }
  await writeFile(target, text, 'utf8');
}

function assertModel() {
  const schemaVersions = new Set();
  for (const [name, schema] of Object.entries(SCHEMAS)) {
    if (!name.endsWith('.schema.json') || schema.$schema !== 'https://json-schema.org/draft/2020-12/schema' || schema['x-ogvcs-license'] !== 'MIT') throw new Error(`invalid schema model: ${name}`);
    const version = schema.properties?.schemaVersion?.const;
    if (version !== undefined && schemaVersions.has(version)) throw new Error(`duplicate schemaVersion: ${version}`);
    if (version !== undefined) schemaVersions.add(version);
  }
  for (const [name, registry] of Object.entries(REGISTRIES)) {
    if (registry.registry !== name || registry.license !== 'MIT' || !Array.isArray(registry.entries) || registry.entries.length === 0) throw new Error(`invalid registry model: ${name}`);
  }
  const tasks = new Map(REGISTRIES.tasks.entries.map((entry) => [entry.id, entry]));
  const faults = new Map(REGISTRIES.faults.entries.map((entry) => [entry.id, entry]));
  if (tasks.size !== REGISTRIES.tasks.entries.length) throw new Error('task registry contains duplicate identities');
  if (faults.size !== REGISTRIES.faults.entries.length) throw new Error('fault registry contains duplicate identities');
  for (const task of tasks.values()) for (const faultId of task.faultPoints) if (!faults.get(faultId)?.tasks.includes(task.id)) throw new Error(`task/fault authority is not bidirectional: ${task.id}/${faultId}`);
  for (const fault of faults.values()) for (const taskId of fault.tasks) if (!tasks.get(taskId)?.faultPoints.includes(fault.id)) throw new Error(`fault/task authority is not bidirectional: ${fault.id}/${taskId}`);
  for (const [name, vectorFile] of Object.entries(VECTORS)) {
    const identities = vectorFile.cases.map(({ id }) => id);
    if (new Set(identities).size !== identities.length) throw new Error(`vector corpus contains duplicate identities: ${name}`);
  }
  const requirementIds = new Set();
  for (const thresholdFile of Object.values(THRESHOLDS)) for (const entry of thresholdFile.entries) requirementIds.add(entry.requirementId);
  for (const vectorFile of Object.values(VECTORS)) for (const entry of vectorFile.cases) for (const id of entry.requirementIds) requirementIds.add(id);
  const required = [
    ...Array.from({ length: 10 }, (_, index) => `OGVCS-005-FR-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 3 }, (_, index) => `OGVCS-005-NFR-${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 7 }, (_, index) => `OGVCS-005-AC-${String(index + 1).padStart(2, '0')}`),
  ];
  for (const id of required) if (!requirementIds.has(id)) throw new Error(`benchmark contract lacks executable requirement binding: ${id}`);
}

async function generate() {
  assertModel();
  const documents = new Map();
  for (const [name, value] of Object.entries(SCHEMAS)) documents.set(`schemas/${name}`, canonical(value));
  const schemaArtifacts = [...documents].map(([path, text]) => artifact(path, text)).sort((a, b) => compareText(a.path, b.path));
  const schemaRegistry = {
    schemaVersion: 'ogvcs.benchmark/registry/v1', registry: 'schemas', version: 1, license: 'MIT',
    entries: schemaArtifacts.map(({ path, sha256, bytes }) => ({ id: SCHEMAS[path.slice('schemas/'.length)].$id, path, sha256, bytes, state: 'candidate' })),
  };
  const registries = { ...REGISTRIES, schemas: schemaRegistry };
  for (const [name, value] of Object.entries(registries)) documents.set(`registries/${name}.json`, canonical(value));
  for (const [name, value] of Object.entries(PROFILES)) documents.set(`profiles/${name}`, canonical(value));
  for (const [name, value] of Object.entries(THRESHOLDS)) documents.set(`thresholds/${name}`, canonical(value));
  for (const [name, value] of Object.entries(VECTORS)) documents.set(`vectors/${name}`, canonical(value));

  const artifacts = [...documents].map(([path, text]) => artifact(path, text)).sort((a, b) => compareText(a.path, b.path));
  const groups = (prefix) => artifacts.filter(({ path }) => path.startsWith(prefix));
  const modelBytes = await readFile(new URL('./model.mjs', import.meta.url));
  const generatorBytes = await readFile(fileURLToPath(import.meta.url));
  const profiles = listProfiles().map(({ id, version }) => getProfile(id, version));
  const authorizationReport = await runThreatVectors();
  const authorizationPin = await manifestPin('spec/authorization/v1/manifest.json');
  if (authorizationReport.manifestSha256 !== authorizationPin.manifestSha256 || authorizationReport.registrySetSha256 !== authorizationPin.registrySetSha256 || authorizationReport.adapter !== 'reference-fixture' || authorizationReport.failed !== 0) throw new Error('authorization reference evidence differs from its predecessor authority');
  const predecessorPins = {
    authorization: { ...authorizationPin, referenceAdapter: authorizationReport.adapter, referenceVectors: authorizationReport.vectors, referenceResultsSha256: authorizationReport.resultsSha256 },
    path: await manifestPin('spec/path-filesystem/v1/manifest.json'),
    protocol: await manifestPin('spec/protocols/v1/manifest.json'),
    repository: await manifestPin('spec/repository-format/v1/vectors/manifest.json'),
    fixtures: {
      package: '@opengamevcs/fixture-generator',
      packageVersion: '1.0.0',
      profileVersion: '2.0.0',
      profileSetSha256: digest(canonical(profiles)),
      profiles: profiles.map(({ id, digest: profileDigest }) => ({ id, digest: profileDigest })),
    },
  };
  const manifest = {
    schemaVersion: 'ogvcs.benchmark/contract-manifest/v1',
    contractVersion: CONTRACT_VERSION,
    packageName: PACKAGE_NAME,
    license: 'MIT',
    generatedBy: {
      modelSha256: digest(modelBytes),
      generatorSha256: digest(generatorBytes),
    },
    predecessorPins,
    artifacts,
    artifactSetSha256: setDigest(artifacts),
    registrySetSha256: setDigest(groups('registries/')),
    schemaSetSha256: setDigest(groups('schemas/')),
    vectorSetSha256: setDigest(groups('vectors/')),
    thresholdSetSha256: setDigest(groups('thresholds/')),
    counts: {
      artifacts: artifacts.length,
      schemas: groups('schemas/').length,
      registries: groups('registries/').length,
      profiles: groups('profiles/').length,
      thresholds: Object.values(THRESHOLDS).reduce((sum, value) => sum + value.entries.length, 0),
      scenarios: Object.values(VECTORS).reduce((sum, value) => sum + value.cases.length, 0),
      tasks: REGISTRIES.tasks.entries.length,
      faultPoints: REGISTRIES.faults.entries.length,
    },
  };
  for (const [path, text] of documents) await emit(path, text);
  await emit('manifest.json', canonical(manifest));
  process.stdout.write(`${check ? 'verified' : 'generated'} benchmark-fault contract: ${manifest.counts.artifacts} artifacts, ${manifest.counts.scenarios} scenarios\n`);
}

await generate();
