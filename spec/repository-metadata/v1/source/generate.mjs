#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CONTRACT_VERSION,
  DOMAIN_ERRORS,
  OGVCS_041_AUTHORITY,
  OPERATIONS,
  PACKAGE_NAME,
  REGISTRIES,
  SCHEMAS,
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

function canonical(value) { return `${JSON.stringify(ordered(value))}\n`; }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function compareText(left, right) { return left < right ? -1 : left > right ? 1 : 0; }

function artifact(path, text) {
  return { path, bytes: Buffer.byteLength(text), sha256: digest(text), mediaType: 'application/json' };
}

function setDigest(entries) {
  const projection = entries.map(({ path, sha256 }) => ({ path, sha256 })).sort((a, b) => compareText(a.path, b.path));
  return digest(canonical(projection));
}

async function predecessorPin(relative, authority) {
  const bytes = await readFile(resolve(workspace, relative));
  const value = JSON.parse(bytes);
  return {
    authority,
    manifestPath: relative,
    manifestSha256: digest(bytes),
    contractVersion: value.contractVersion ?? value.formatVersion ?? value.version,
    registrySetSha256: value.registrySetSha256 ?? null,
  };
}

async function emit(relative, text) {
  const target = resolve(root, relative);
  if (check) {
    let existing;
    try { existing = await readFile(target, 'utf8'); }
    catch { throw new Error(`missing generated repository-metadata artifact: ${relative}`); }
    if (existing !== text) throw new Error(`generated repository-metadata artifact differs: ${relative}`);
    return;
  }
  await writeFile(target, text, 'utf8');
}

function assertModel() {
  const operationNames = new Set();
  const operationCodes = new Set();
  for (const operation of OPERATIONS) {
    if (operationNames.has(operation.name) || operationCodes.has(operation.code)) throw new Error('duplicate operation assignment');
    operationNames.add(operation.name);
    operationCodes.add(operation.code);
  }
  const errorNames = new Set();
  const errorCodes = new Set();
  for (const error of DOMAIN_ERRORS) {
    if (errorNames.has(error.name) || errorCodes.has(error.code)
      || error.protocolBinding !== null
      || error.wireSurface !== 'internal-unassigned') throw new Error('invalid domain-error assignment');
    errorNames.add(error.name);
    errorCodes.add(error.code);
  }
  for (const [name, schema] of Object.entries(SCHEMAS)) {
    if (!name.endsWith('.schema.json') || schema.$schema !== 'https://json-schema.org/draft/2020-12/schema' || schema['x-ogvcs-license'] !== 'MIT') throw new Error(`invalid schema model: ${name}`);
  }
  for (const [name, registry] of Object.entries(REGISTRIES)) {
    if (registry.registry !== name || registry.license !== 'MIT' || registry.entries.length === 0) throw new Error(`invalid registry model: ${name}`);
  }
}

async function generate() {
  assertModel();
  const documents = new Map();
  for (const [name, value] of Object.entries(SCHEMAS)) documents.set(`schemas/${name}`, canonical(value));
  const initialSchemas = [...documents].map(([path, value]) => artifact(path, value)).sort((a, b) => compareText(a.path, b.path));
  const registries = {
    ...REGISTRIES,
    schemas: {
      schemaVersion: 'ogvcs.repository-metadata/registry/v1',
      registry: 'schemas',
      version: 1,
      license: 'MIT',
      entries: initialSchemas.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256, state: 'candidate' })),
    },
  };
  for (const [name, value] of Object.entries(registries)) documents.set(`registries/${name}.json`, canonical(value));
  for (const [name, value] of Object.entries(VECTORS)) documents.set(`vectors/${name}`, canonical(value));

  const artifacts = [...documents].map(([path, value]) => artifact(path, value)).sort((a, b) => compareText(a.path, b.path));
  const group = (prefix) => artifacts.filter(({ path }) => path.startsWith(prefix));
  const modelBytes = await readFile(new URL('./model.mjs', import.meta.url));
  const generatorBytes = await readFile(fileURLToPath(import.meta.url));
  const predecessorPins = {
    repository: await predecessorPin('spec/repository-format/v1/vectors/manifest.json', 'ogvcs.repository-format@1'),
    authorization: await predecessorPin('spec/authorization/v1/manifest.json', 'ogvcs.authorization@1'),
    path: await predecessorPin('spec/path-filesystem/v1/manifest.json', 'ogvcs.path-filesystem@1'),
    protocol: {
      ...await predecessorPin('spec/protocols/v1/manifest.json', 'ogvcs.protocol@1'),
      negotiationRegistrySetSha256: OGVCS_041_AUTHORITY.negotiationRegistrySetSha256,
    },
    benchmarkFault: await predecessorPin('spec/benchmark-fault/v1/manifest.json', 'ogvcs.benchmark-fault@1'),
  };
  const manifest = {
    schemaVersion: 'ogvcs.repository-metadata/contract-manifest/v1',
    contractVersion: CONTRACT_VERSION,
    packageName: PACKAGE_NAME,
    state: 'candidate',
    license: 'MIT',
    protocolBinding: 'ogvcs.control.https-json@1',
    generatedBy: { modelSha256: digest(modelBytes), generatorSha256: digest(generatorBytes) },
    predecessorPins,
    artifacts,
    artifactSetSha256: setDigest(artifacts),
    registrySetSha256: setDigest(group('registries/')),
    schemaSetSha256: setDigest(group('schemas/')),
    vectorSetSha256: setDigest(group('vectors/')),
    counts: {
      artifacts: artifacts.length,
      schemas: group('schemas/').length,
      registries: group('registries/').length,
      operations: OPERATIONS.length,
      domainErrors: DOMAIN_ERRORS.length,
      scenarios: Object.values(VECTORS).reduce((sum, value) => sum + value.cases.length, 0),
    },
  };

  for (const [path, value] of documents) await emit(path, value);
  await emit('manifest.json', canonical(manifest));
  process.stdout.write(`${check ? 'verified' : 'generated'} repository-metadata contract: ${artifacts.length} artifacts, ${manifest.counts.scenarios} scenarios\n`);
}

await generate();
