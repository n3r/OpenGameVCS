#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CASE_FOLDING_SHA256,
  CONTRACT_VERSION,
  SCHEMA_VERSION,
  UNICODE_LICENSE_SHA256,
  UNICODE_VERSION,
  caseModes,
  collisionCases,
  errors,
  foldCases,
  operationOutcomes,
  pathCases,
  platformProfiles,
  preflightCases,
  renameCases,
  watcherCases,
} from '../source/contract.mjs';
import {
  canonicalBytes,
  caseFoldV1,
  collisionKeys,
  detectCollisions,
  initialWatcherState,
  planRenames,
  preflightMaterialization,
  sha256,
  watcherTransition,
} from '../source/reference.mjs';
import { allSchemas } from '../source/schemas.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.slice(2).includes('--check');
if (process.argv.length > 3 || (process.argv.length === 3 && !CHECK)) {
  throw new Error('usage: node scripts/generate.mjs [--check]');
}

const generated = new Map();
const registry = (name, entries) => ({ schemaVersion: 'ogvcs.path/registry/v1', registry: name, version: 1, entries });

const registries = Object.freeze({
  'case-modes.json': registry('case-modes', caseModes),
  'errors.json': registry('errors', errors),
  'operation-outcomes.json': registry('operation-outcomes', operationOutcomes),
  'platform-profiles.json': registry('platform-profiles', platformProfiles),
});

for (const [name, value] of Object.entries(registries)) generated.set(`registries/${name}`, canonicalBytes(value));
for (const [name, value] of Object.entries(allSchemas)) generated.set(`schemas/${name}`, canonicalBytes(value));

const pathVectors = pathCases.map((item) => ({ ...item, expected: collisionKeys(item.input, item.caseMode, item.profile, platformProfiles) }));
const foldVectors = foldCases.map((item) => ({ ...item, expected: caseFoldV1(item.input) }));
const collisionVectors = collisionCases.map((item) => ({
  ...item,
  expected: detectCollisions(item.paths.map((path, index) => ({ id: String(index), path })), item.caseMode, item.profile, platformProfiles),
}));
const preflightVectors = preflightCases.map((item) => {
  const { id, ...input } = item;
  const request = { schemaVersion: 'ogvcs.path/preflight-request/v1', ...input };
  return { id, ...request, expected: preflightMaterialization(request, platformProfiles) };
});
const renameVectors = renameCases.map((item) => ({ ...item, expected: planRenames(item, platformProfiles) }));
const watcherVectors = watcherCases.map((item) => {
  let state = initialWatcherState();
  const outcomes = [];
  for (const event of item.events) {
    const raw = watcherTransition(state, event);
    const result = raw.state === undefined ? { ...raw, state } : raw;
    outcomes.push(result);
    if (raw.state !== undefined) state = raw.state;
    if (!result.accepted) break;
  }
  return { ...item, expected: { outcomes, state } };
});

const vectorDocuments = Object.freeze({
  'collision-cases.json': { schemaVersion: 'ogvcs.path/collision-vectors/v1', cases: collisionVectors },
  'fold-cases.json': { schemaVersion: 'ogvcs.path/fold-vectors/v1', cases: foldVectors },
  'path-cases.json': { schemaVersion: 'ogvcs.path/path-vectors/v1', cases: pathVectors },
  'preflight-cases.json': { schemaVersion: 'ogvcs.path/preflight-vectors/v1', cases: preflightVectors },
  'rename-cases.json': { schemaVersion: 'ogvcs.path/rename-vectors/v1', cases: renameVectors },
  'watcher-cases.json': { schemaVersion: 'ogvcs.path/watcher-vectors/v1', cases: watcherVectors },
});
for (const [name, value] of Object.entries(vectorDocuments)) generated.set(`vectors/${name}`, canonicalBytes(value));

async function sourceDigest() {
  const hash = createHash('sha256');
  for (const relative of ['scripts/generate.mjs', 'source/contract.mjs', 'source/reference.mjs', 'source/schemas.mjs']) {
    const bytes = await readFile(resolve(ROOT, relative));
    hash.update(`${relative}\0`, 'utf8');
    hash.update(bytes);
  }
  return hash.digest('hex');
}

const staticArtifacts = [
  'LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md',
  'data/CaseFolding-16.0.0.txt', 'data/UNICODE-LICENSE.txt',
  'docs/path-contract.md', 'docs/versioning-and-operations.md',
  'docs/watcher-contract.md', 'docs/workspace-safety.md',
  'package.json',
];

async function artifactRecord(relative, bytes = undefined) {
  const body = bytes ?? await readFile(resolve(ROOT, relative));
  return { path: relative, bytes: body.length, sha256: sha256(body) };
}

const records = [];
for (const relative of [...staticArtifacts, ...generated.keys()].sort()) {
  records.push(await artifactRecord(relative, generated.get(relative)));
}
const registryRecords = records.filter(({ path }) => path.startsWith('registries/'));
const vectorRecords = records.filter(({ path }) => path.startsWith('vectors/'));
const manifest = {
  schemaVersion: SCHEMA_VERSION,
  contractVersion: CONTRACT_VERSION,
  unicode: {
    version: UNICODE_VERSION,
    caseFoldingSha256: CASE_FOLDING_SHA256,
    licenseSha256: UNICODE_LICENSE_SHA256,
    mapping: 'full-default-C-and-F-without-T-or-post-fold-normalization',
  },
  generatorSha256: await sourceDigest(),
  registrySetSha256: sha256(canonicalBytes(registryRecords)),
  vectorSetSha256: sha256(canonicalBytes(vectorRecords)),
  counts: {
    artifacts: records.length,
    registries: registryRecords.length,
    schemas: Object.keys(allSchemas).length,
    pathCases: pathVectors.length,
    foldCases: foldVectors.length,
    collisionCases: collisionVectors.length,
    preflightCases: preflightVectors.length,
    renameCases: renameVectors.length,
    watcherCases: watcherVectors.length,
    errors: errors.length,
    profiles: platformProfiles.length,
  },
  artifacts: records,
};
generated.set('manifest.json', canonicalBytes(manifest));

let changed = false;
for (const [relative, expected] of generated) {
  const destination = resolve(ROOT, relative);
  if (CHECK) {
    const actual = await readFile(destination).catch(() => null);
    if (actual === null || !actual.equals(expected)) {
      process.stderr.write(`${relative}: generated content differs\n`);
      changed = true;
    }
  } else {
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, expected);
  }
}
if (changed) process.exitCode = 1;
