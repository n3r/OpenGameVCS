#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONTRACT_VERSION, LIMITS, PACKAGE_NAME, REGISTRIES, SCHEMAS, VECTORS } from './model.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = resolve(root, '../../..');
const check = process.argv.includes('--check');
const ordered = (value) => Array.isArray(value) ? value.map(ordered)
  : value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]))
    : value;
const canonical = (value) => `${JSON.stringify(ordered(value))}\n`;
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const artifact = (path, bytes) => ({ path, bytes: Buffer.byteLength(bytes), sha256: digest(bytes), mediaType: 'application/json' });
const setDigest = (entries) => digest(canonical(entries.map(({ path, sha256 }) => ({ path, sha256 })).sort((a, b) => compare(a.path, b.path))));

async function predecessorPin(relative, authority) {
  const bytes = await readFile(resolve(workspace, relative));
  const value = JSON.parse(bytes);
  return {
    authority,
    manifestPath: relative,
    manifestSha256: digest(bytes),
    contractVersion: value.contractVersion ?? value.version,
    registrySetSha256: value.registrySetSha256 ?? null,
  };
}

async function emit(relative, bytes) {
  const target = resolve(root, relative);
  if (check) {
    const existing = await readFile(target, 'utf8').catch(() => null);
    if (existing !== bytes) throw new Error(`generated identity-policy artifact differs: ${relative}`);
  } else {
    await writeFile(target, bytes, 'utf8');
  }
}

const documents = new Map();
for (const [name, value] of Object.entries(SCHEMAS)) documents.set(`schemas/${name}`, canonical(value));
const initialSchemas = [...documents].map(([path, bytes]) => artifact(path, bytes)).sort((a, b) => compare(a.path, b.path));
const registries = {
  ...REGISTRIES,
  schemas: {
    schemaVersion: 'ogvcs.identity-policy/registry/v1', registry: 'schemas', version: 1, license: 'MIT',
    entries: initialSchemas.map(({ path, bytes, sha256 }) => ({ path, bytes, sha256, state: 'candidate' })),
  },
};
for (const [name, value] of Object.entries(registries)) documents.set(`registries/${name}.json`, canonical(value));
for (const [name, value] of Object.entries(VECTORS)) documents.set(`vectors/${name}`, canonical(value));

const artifacts = [...documents].map(([path, bytes]) => artifact(path, bytes)).sort((a, b) => compare(a.path, b.path));
const group = (prefix) => artifacts.filter(({ path }) => path.startsWith(prefix));
const manifest = {
  schemaVersion: 'ogvcs.identity-policy/contract-manifest/v1', contractVersion: CONTRACT_VERSION,
  packageName: PACKAGE_NAME, state: 'candidate', license: 'MIT', protocolBinding: 'unassigned-future-release-required',
  generatedBy: {
    modelSha256: digest(await readFile(new URL('./model.mjs', import.meta.url))),
    generatorSha256: digest(await readFile(fileURLToPath(import.meta.url))),
  },
  predecessorPins: {
    authorization: await predecessorPin('spec/authorization/v1/manifest.json', 'ogvcs.authorization@1'),
    path: await predecessorPin('spec/path-filesystem/v1/manifest.json', 'ogvcs.path-filesystem@1'),
    protocol: await predecessorPin('spec/protocols/v1/manifest.json', 'ogvcs.protocol@1'),
    metadata: await predecessorPin('spec/repository-metadata/v1/manifest.json', 'ogvcs.repository-metadata@1'),
  },
  artifacts,
  artifactSetSha256: setDigest(artifacts), registrySetSha256: setDigest(group('registries/')),
  schemaSetSha256: setDigest(group('schemas/')), vectorSetSha256: setDigest(group('vectors/')),
  counts: {
    artifacts: artifacts.length, registries: group('registries/').length, schemas: group('schemas/').length,
    vectors: Object.values(VECTORS).reduce((sum, value) => sum + value.cases.length, 0), limits: Object.keys(LIMITS).length,
  },
};

for (const [path, bytes] of documents) await emit(path, bytes);
await emit('manifest.json', canonical(manifest));
process.stdout.write(`${check ? 'verified' : 'generated'} identity-policy contract: ${artifacts.length} artifacts, ${manifest.counts.vectors} vectors\n`);
