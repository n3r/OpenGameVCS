#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = resolve(root, '../../..');
const migrations = resolve(root, '../../migrations/repository-metadata');

function assert(condition, message) { if (!condition) throw new Error(message); }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

const cargo = await readFile(resolve(root, 'Cargo.toml'), 'utf8');
assert(cargo.includes('name = "ogvcs-repository-metadata"'), 'Cargo package name differs');
assert(cargo.includes('ogvcs-object-model = { path = "../../../core/object-model/rust" }'), 'object-model dependency is not public path dependency');

const rustFiles = ['lib.rs', 'error.rs', 'migration.rs', 'ports.rs', 'types.rs'];
for (const file of rustFiles) {
  const source = await readFile(resolve(root, 'src', file), 'utf8');
  assert(!/\bunsafe\b/u.test(source.replace('#![forbid(unsafe_code)]', '')), `unsafe Rust appears in ${file}`);
}

const manifest = JSON.parse(await readFile(resolve(migrations, 'manifest.json')));
assert(manifest.schemaVersion === 'ogvcs.repository-metadata/migration-manifest/v1', 'migration manifest schema differs');
assert(JSON.stringify(manifest.entries.map(({ phase }) => phase)) === '["expand","migrate","contract"]', 'migration phases are not ordered');
for (const entry of manifest.entries) {
  const bytes = await readFile(resolve(migrations, entry.path));
  const sql = bytes.toString('utf8');
  assert(digest(bytes) === entry.sha256, `migration checksum differs: ${entry.path}`);
  assert(sql.startsWith('BEGIN;\n') && sql.endsWith('COMMIT;\n'), `migration is not transaction framed: ${entry.path}`);
}

const errors = JSON.parse(await readFile(resolve(workspace, 'spec/repository-metadata/v1/registries/domain-errors.json'))).entries;
const errorSource = await readFile(resolve(root, 'src/error.rs'), 'utf8');
for (const error of errors) {
  assert(errorSource.includes(`= ${error.code},`), `Rust domain error code missing: ${error.name}`);
  assert(errorSource.includes(`"${error.name}"`), `Rust domain error name missing: ${error.name}`);
}

const expand = await readFile(resolve(migrations, '000001_expand.sql'), 'utf8');
assert(expand.includes('object_kind IN (2, 3, 4, 5, 6, 7, 9, 10, 11)'), 'metadata kind allowlist omits manifests or includes an unexpected kind');
assert(!expand.includes('object_kind IN (1,'), 'chunk bytes entered metadata ownership');
assert(expand.includes('FOREIGN KEY (repository_id, tree_kind, tree_algorithm, tree_digest)'), 'tree entry owner is not tied to kind-3 metadata');
assert(expand.includes("resource_type IN ('repository', 'reference', 'snapshot', 'tree', 'path')"), 'outbox resource types differ from the domain registry');

process.stdout.write(`statically verified repository-metadata Rust/SQL scaffold: ${rustFiles.length} Rust modules, ${manifest.entries.length} migrations, ${errors.length} errors\n`);
