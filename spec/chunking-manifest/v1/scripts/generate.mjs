#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ERRORS,
  GOLDEN_INPUTS,
  MALFORMED,
  PROFILE_TEXT,
  SELECTION_BENCHMARK_THRESHOLDS,
  SELECTION_BENCHMARK_WORKLOADS,
} from './model.mjs';
import { calculate, materialize, table, tableSha256 } from './reference.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const canonical = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};
const bytes = (value) => Buffer.from(`${canonical(value)}\n`);
const sha = (value) => createHash('sha256').update(value).digest('hex');
async function output(path, value) {
  const expected = bytes(value); const absolute = resolve(ROOT, path);
  if (check) { const actual = await readFile(absolute).catch(() => null); if (!actual?.equals(expected)) throw new Error(`${path} is stale`); }
  else await writeFile(absolute, expected);
}
async function files(directory) {
  const result = [];
  for (const entry of await readdir(resolve(ROOT, directory), { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) result.push(...await files(path)); else result.push(path);
  }
  return result;
}

const golden = {
  schemaVersion: 'ogvcs.chunking/golden-vectors/v1', profile: PROFILE_TEXT, tableSha256,
  cases: GOLDEN_INPUTS.map(({ caseId, recipe }) => ({ caseId, recipe, expected: calculate(materialize(recipe)) })),
  'x-ogvcs-license': 'MIT',
};
const fragmentation = {
  schemaVersion: 'ogvcs.chunking/fragmentation-vectors/v1',
  cases: ['counter-a-six-mib', 'counter-b-four-mib', 'insertion-plus-17'].map((caseId) => ({
    caseId, fragmentPatterns: [[1], [17, 257, 4093], [262143, 1, 524287, 1048576, 3]],
  })),
  'x-ogvcs-license': 'MIT',
};
const malformed = { schemaVersion: 'ogvcs.chunking/malformed-vectors/v1', cases: MALFORMED, 'x-ogvcs-license': 'MIT' };
const selectionWorkloads = {
  schemaVersion: 'ogvcs.chunking/selection-benchmark-workloads/v1',
  profile: PROFILE_TEXT,
  workloads: SELECTION_BENCHMARK_WORKLOADS,
  'x-ogvcs-license': 'MIT',
};
const errors = {
  schemaVersion: 'ogvcs.chunking/registry/v1',
  registry: 'ogvcs.chunking.errors',
  version: 1,
  entries: ERRORS.map((name) => ({ name })),
  'x-ogvcs-license': 'MIT',
};
const tableDocument = { schemaVersion: 'ogvcs.chunking/gear-table/v1', derivationDomainHex: Buffer.from('OpenGameVCS Gear table v1\0').toString('hex'), entries: table.map((value) => value.toString(16).padStart(16, '0')), tableSha256, 'x-ogvcs-license': 'MIT' };
await output('vectors/gear-table.json', tableDocument);
await output('vectors/golden.json', golden);
await output('vectors/fragmentation.json', fragmentation);
await output('vectors/malformed.json', malformed);
await output('vectors/selection-benchmark-workloads.json', selectionWorkloads);
await output('registries/errors.json', errors);
await output('thresholds/selection-bounded-v1.json', { ...SELECTION_BENCHMARK_THRESHOLDS, profile: PROFILE_TEXT, 'x-ogvcs-license': 'MIT' });

const shipped = ['LICENSE', 'README.md', 'package.json', 'validate-spec.mjs', ...await files('docs'), ...await files('profiles'), ...await files('registries'), ...await files('schemas'), ...await files('scripts'), ...await files('test'), ...await files('thresholds'), ...await files('vectors')].filter((path) => path !== 'manifest.json').sort();
const artifacts = [];
for (const path of shipped) { const body = await readFile(resolve(ROOT, path)); artifacts.push({ bytes: body.length, path, sha256: sha(body) }); }
const artifactSetSha256 = sha(Buffer.concat(artifacts.map((item) => Buffer.from(`${item.path}\0${item.sha256}\0${item.bytes}\n`))));
const manifest = {
  schemaVersion: 'ogvcs.chunking/contract-manifest/v1', contractVersion: '0.1.0-rc.1', profile: PROFILE_TEXT,
  tableSha256, artifactSetSha256, artifacts,
  counts: {
    artifacts: artifacts.length,
    benchmarkThresholds: 1,
    benchmarkWorkloads: selectionWorkloads.workloads.length,
    goldenCases: golden.cases.length,
    malformedCases: malformed.cases.length,
    fragmentationCases: fragmentation.cases.length,
    schemas: 7,
  },
  generatedBy: { generatorSha256: sha(await readFile(fileURLToPath(import.meta.url))), modelSha256: sha(await readFile(resolve(ROOT, 'scripts/model.mjs'))) },
  license: 'MIT',
};
await output('manifest.json', manifest);
if (!check) process.stdout.write(`${relative(process.cwd(), resolve(ROOT, 'manifest.json'))}\n`);
