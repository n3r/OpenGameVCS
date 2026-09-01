#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONTRACT, ERROR_REGISTRY, GOLDEN_INPUTS, SPEC_SCHEMA } from '../source/model.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const PATH_ROOT = dirname(require.resolve('@opengamevcs/path-contract-v1/package.json'));
const CHECK = process.argv.length === 3 && process.argv[2] === '--check';
if (process.argv.length > (CHECK ? 3 : 2)) throw new Error('usage: node scripts/generate.mjs [--check]');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new TypeError('generator input is not canonical-JSON compatible');
};
const json = (value) => Buffer.from(`${canonical(value)}\n`, 'utf8');

const goldenSource = JSON.parse(await readFile(resolve(ROOT, 'source/golden.json'), 'utf8'));
if (goldenSource.schemaVersion !== 'ogvcs.selective-sync/golden-vectors/v1'
    || !Array.isArray(goldenSource.cases)
    || goldenSource.cases.length !== GOLDEN_INPUTS.length
    || goldenSource.cases.some((item, index) => item.caseId !== GOLDEN_INPUTS[index].caseId)) {
  throw new Error('source/golden.json must contain one frozen expected record for every model input');
}
const golden = { schemaVersion: goldenSource.schemaVersion, cases: GOLDEN_INPUTS.map((input, index) => ({ ...input, expected: goldenSource.cases[index].expected })) };
const generated = new Map([
  ['contract.json', json(CONTRACT)],
  ['registries/errors.json', json(ERROR_REGISTRY)],
  ['schemas/workspace-selection-spec.schema.json', json(SPEC_SCHEMA)],
  ['vectors/golden.json', json(golden)],
]);
for (const [path, bytes] of generated) {
  const destination = resolve(ROOT, path);
  if (CHECK) {
    const actual = await readFile(destination).catch(() => null);
    if (actual === null || !actual.equals(bytes)) throw new Error(`${path}: generated content differs`);
  } else {
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, bytes);
  }
}

const artifactPaths = [
  'LICENSE', 'README.md', 'contract.json', 'package.json',
  'registries/errors.json',
  'schemas/workspace-selection-spec.schema.json', 'scripts/generate.mjs', 'scripts/reference.mjs',
  'source/golden.json', 'source/model.mjs',
  'test/contract.test.mjs', 'validate-spec.mjs', 'vectors/golden.json',
];
const artifacts = [];
for (const path of artifactPaths) {
  const bytes = await readFile(resolve(ROOT, path));
  artifacts.push({ bytes: bytes.length, path, sha256: sha256(bytes) });
}
const pathManifest = await readFile(resolve(PATH_ROOT, 'manifest.json'));
if (sha256(pathManifest) !== CONTRACT.predecessorPins.path.manifestSha256) throw new Error('path predecessor manifest drifted');
const generatorBytes = await readFile(fileURLToPath(import.meta.url));
const modelBytes = await readFile(resolve(ROOT, 'source/model.mjs'));
const manifest = {
  schemaVersion: 'ogvcs.selective-sync/contract-manifest/v1',
  contractVersion: CONTRACT.contractVersion,
  state: CONTRACT.state,
  packageName: '@opengamevcs/selective-sync-kernel-contract-v1',
  license: 'MIT',
  predecessorPins: CONTRACT.predecessorPins,
  artifacts,
  artifactSetSha256: sha256(Buffer.concat(artifacts.map(({ path, sha256: digest, bytes }) => Buffer.from(`${path}\0${digest}\0${bytes}\n`)))),
  counts: { artifacts: artifacts.length, errors: ERROR_REGISTRY.entries.length, goldenCases: golden.cases.length, schemas: 1 },
  generatedBy: { generatorSha256: sha256(generatorBytes), modelSha256: sha256(modelBytes) },
  publicClaims: CONTRACT.publicClaims,
  networkRoutes: [],
};
const manifestBytes = json(manifest);
if (CHECK) {
  const actual = await readFile(resolve(ROOT, 'manifest.json')).catch(() => null);
  if (actual === null || !actual.equals(manifestBytes)) throw new Error('manifest.json: generated content differs');
} else {
  await writeFile(resolve(ROOT, 'manifest.json'), manifestBytes);
}
