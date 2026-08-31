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
assert(cargo.includes('postgres = { version = "=0.19.10"'), 'PostgreSQL dependency is not exactly pinned');
assert(cargo.includes('rust-version = "1.82"'), 'Rust MSRV differs');

const rustFiles = [
  'lib.rs',
  'error.rs',
  'migration.rs',
  'migration_runner.rs',
  'ports.rs',
  'postgres.rs',
  'types.rs',
];
for (const file of rustFiles) {
  const source = await readFile(resolve(root, 'src', file), 'utf8');
  assert(!/\bunsafe\b/u.test(source.replace('#![forbid(unsafe_code)]', '')), `unsafe Rust appears in ${file}`);
}

const manifest = JSON.parse(await readFile(resolve(migrations, 'manifest.json')));
assert(manifest.schemaVersion === 'ogvcs.repository-metadata/migration-manifest/v1', 'migration manifest schema differs');
assert(JSON.stringify(manifest.entries.map(({ version, phase }) => [version, phase])) === '[[1,"expand"],[1,"migrate"],[1,"contract"],[2,"expand"],[2,"migrate"],[2,"contract"],[3,"expand"],[3,"migrate"],[3,"contract"],[4,"expand"],[4,"migrate"],[4,"contract"],[5,"expand"],[5,"migrate"],[5,"contract"],[6,"expand"],[6,"migrate"],[6,"contract"]]', 'migration phases are not ordered');
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

const expandV1Bytes = await readFile(resolve(migrations, '000001_expand.sql'));
const expand = expandV1Bytes.toString('utf8');
assert(digest(expandV1Bytes) === '58b53c7cd61b5f8b0e6fca4184a36379c049947a34751bedb1bd77ded674d53c', 'version 1 migration identity was rewritten');
assert(expand.includes('object_kind IN (2, 3, 4, 5, 6, 7, 9, 10, 11)'), 'metadata kind allowlist omits manifests or includes an unexpected kind');
assert(!expand.includes('object_kind IN (1,'), 'chunk bytes entered metadata ownership');
assert(expand.includes('FOREIGN KEY (repository_id, tree_kind, tree_algorithm, tree_digest)'), 'tree entry owner is not tied to kind-3 metadata');
assert(expand.includes("resource_type IN ('repository', 'reference', 'snapshot', 'tree', 'path')"), 'outbox resource types differ from the domain registry');
const expandV2 = await readFile(resolve(migrations, '000002_expand.sql'), 'utf8');
const migrateV2 = await readFile(resolve(migrations, '000002_migrate.sql'), 'utf8');
assert(expandV2.includes('CREATE TRIGGER repository_settings_immutable'), 'immutable repository settings trigger missing from version 2');
assert(expandV2.includes('file_path_history_by_file_id_v2'), 'version 2 history index missing operation ordinal');
assert(
  !expandV2.includes('published_commit_sequence')
    && !migrateV2.includes('published_commit_sequence'),
  'version 2 infers historical publication markers',
);
const expandV3 = await readFile(resolve(migrations, '000003_expand.sql'), 'utf8');
assert(expandV3.includes('outbox_events_lease_complete'), 'version 3 complete outbox lease invariant missing');
assert(expandV3.includes('acknowledged_at'), 'version 3 outbox acknowledgement state missing');
assert(expandV3.includes('WHERE acknowledged_at IS NULL'), 'version 3 deliverable index includes acknowledged events');
const expandV4 = await readFile(resolve(migrations, '000004_expand.sql'), 'utf8');
assert(expandV4.includes('bounded_snapshot_ancestry'), 'version 4 bounded ancestry primitive missing');
assert(expandV4.includes('requested_maximum_work > 100001'), 'version 4 history work cap missing');
assert(expandV4.includes('ORDER BY parent.ordinal'), 'version 4 parent order is not deterministic');
const expandV5 = await readFile(resolve(migrations, '000005_expand.sql'), 'utf8');
assert(expandV5.includes('repository_list_cursor_states'), 'version 5 project cursor ledger missing');
assert(expandV5.includes('position_repository_id uuid'), 'version 5 project cursor position missing');
const expandV6 = await readFile(resolve(migrations, '000006_expand.sql'), 'utf8');
assert(expandV6.includes('file_id_allocation_receipts'), 'version 6 allocation receipt ledger missing');
assert(expandV6.includes('authenticated_scope_digest'), 'allocation receipt is not bound to authenticated scope');
assert(expandV6.includes('consumed_at'), 'allocation receipt is not one-use');

const adapter = await readFile(resolve(root, 'src/postgres.rs'), 'utf8');
const ports = await readFile(resolve(root, 'src/ports.rs'), 'utf8');
assert(
  adapter.split('crate::verify_schema_compatibility(&mut self.client)?').length - 1 === 17,
  'every mutation/read entry point is not schema-compatibility gated',
);
assert(ports.includes('ValidationMode::Production'), 'default object validator is not production lifecycle');
assert(ports.includes('type AuthorizedView: AuthorizedView'), 'authorizer output is not an exact view contract');
assert(ports.includes('resource: &AuthorizationResource'), 'authorizer is not bound to a typed resource projection');
for (const evidence of [
  'pub fn begin_authorized(',
  'pub fn execute_serializable<T>(',
  'ON CONFLICT DO NOTHING RETURNING 1',
  'generation = generation + 1',
  'published_commit_sequence IS NULL',
  'KeyReuseRejected',
  'authorized_repository_id: RepositoryId',
  'authorization_context: AuthorizationContext',
  'authorized_view: View',
  'capability: TransactionCapability',
  'AuthorizationResource::RepositoryTransaction',
  'finish_committed_replay',
  'outbox_events: Vec<RequiredOutboxEvent>',
  'fact.resource_opaque_id(event.repository_id, event.event_id, &safe_payload)',
  'valid_public_uuid(&event.event_id)',
  'self.outbox_events.iter().any(|event| !event.emitted)',
  'MAX_REQUIRED_OUTBOX_EVENTS',
  'MAX_JSON_PREFLIGHT_DEPTH',
  'MAX_JSON_PREFLIGHT_NODES',
  'self.mutation_started && !self.idempotency_committed',
  'reservation.is_valid_at(server_now)',
  'idempotency_scope_digest',
  'capability.as_str().as_bytes()',
  'pub fn allocate_file_id(',
  'consume_allocation_receipt',
  'authenticated_scope_digest = $2',
  'pub fn idempotency_status(',
  'repository_object_matches_settings',
  'descriptor_matches_repository_settings',
  'validation_contract != VALIDATION_CONTRACT',
  'validate_publication_candidate',
  'validate_repository_candidate(candidate, &context)',
  'metadata_closure(&entries, candidate)',
  'candidate_tree_file_ids(&entries, candidate)',
  'first_change_set_digest = $3',
  'validate_snapshot_graph(candidate, &context)',
  'enforce_configured_tree_limits',
  'canonical_file_history_from_change',
  'expected_state.as_str()',
  'MAX_AUTHORIZATION_SCAN',
  'AuthorizationResource::TreeEntry',
  'AuthorizationResource::FileHistoryEntry',
  'authorized_view.permits(context',
  'require_repository_tenant',
  'require_published_snapshot_tree',
  'pub fn get_repository_settings(',
  'pub fn repository_page(',
  'AuthorizationResource::ProjectRepository',
  'repository_list_cursor_states',
  'pub fn get_object(',
  'AuthorizationResource::MetadataObject',
  'pub fn tree_page_consistent(',
  'pub fn reference_page_filtered(',
  'pub fn file_history_page_consistent(',
  'pub fn ancestry_page(',
  'pub fn history_file_id_page(',
  'pub fn history_path_page(',
  'AuthorizationResource::SnapshotHistoryEntry',
  'AuthorizationResource::SnapshotFileHistoryEntry',
  'MAX_HISTORY_WORK',
  'HistoryIncompleteReason::DepthLimit',
  'HistoryIncompleteReason::WorkLimit',
  'ReferenceFilter::Kind',
  'resolve_tree_prefix',
  'valid_tree_prefix',
  'traversed_edges > limits.max_edges',
  'snapshot.published_commit_sequence',
  'matches!(existing_state.as_str(), "reserved" | "active")',
  'snapshot.published_commit_sequence > 0',
  'is_database_concurrency()',
  '"40001" | "40P01"',
  'clock_timestamp() + interval \'5 minutes\'',
  'FOR UPDATE SKIP LOCKED',
  'MetadataPermission::ServiceInternal',
  'acknowledged_at IS NULL',
  'lease_expires_at > clock_timestamp()',
  'ORDER BY basename_utf8',
  'ORDER BY reference.reference_kind, reference.reference_name',
  'ORDER BY history.snapshot_digest, history.operation_ordinal',
]) assert(adapter.includes(evidence), `PostgreSQL adapter evidence missing: ${evidence}`);

const liveContract = await readFile(resolve(root, 'tests/postgres_integration.rs'), 'utf8');
assert(liveContract.includes('CollectionOnlyAllow'), 'item-level AuthorizedView denial regression missing');
assert(liveContract.includes('authorized-view-item-projections'), 'projection non-disclosure report missing');
assert(liveContract.includes('CapabilityMisbindingAllow'), 'transaction capability-misbinding regression missing');
assert(liveContract.includes('RevocableAllow'), 'authorized-view revocation regression missing');
assert(liveContract.includes('SingleUseAllow'), 'read-view revalidation regression missing');
assert(liveContract.includes('missing-publication-marker'), 'publication-marker fail-closed regression missing');
assert(liveContract.includes('restore-capability-alias'), 'restore capability alias regression missing');
assert(liveContract.includes('file-import-tampered-owner'), 'import replay binding regression missing');

const types = await readFile(resolve(root, 'src/types.rs'), 'utf8');
for (const permission of ['"discover"', '"metadata.read"', '"submit"', '"service-internal"']) {
  assert(types.includes(permission), `canonical permission missing: ${permission}`);
}
const outboxInputStart = types.indexOf('pub struct OutboxEvent {');
const outboxInputEnd = types.indexOf('\n}', outboxInputStart);
assert(outboxInputStart >= 0 && outboxInputEnd > outboxInputStart, 'outbox input type missing');
const outboxInput = types.slice(outboxInputStart, outboxInputEnd);
for (const forbiddenCallerField of [
  'pub event_type:',
  'pub event_version:',
  'pub resource_type:',
  'pub resource_opaque_id:',
  'pub safe_payload:',
]) {
  assert(!outboxInput.includes(forbiddenCallerField), `caller still controls outbox fact: ${forbiddenCallerField}`);
}

for (const method of [
  'create_repository',
  'put_object',
  'index_tree_entry',
  'index_snapshot',
  'append_file_history',
  'reserve_file_id',
  'reserve_imported_file_id',
  'activate_file_id',
  'tombstone_file_id',
  'reserve_idempotency',
  'commit_idempotency',
  'compare_and_swap_reference',
  'append_outbox',
  'issue_consistency_token',
]) {
  const start = adapter.indexOf(`    fn ${method}(`);
  const end = adapter.indexOf('\n    fn ', start + 8);
  assert(start >= 0, `transaction method missing: ${method}`);
  assert(
    adapter.slice(start, end < 0 ? adapter.length : end).includes('poison_transaction_on_error!'),
    `transaction method does not poison every Err: ${method}`,
  );
}
assert(
  adapter.indexOf('reservation.origin == FileIdOrigin::Restore')
    < adapter.indexOf('INSERT INTO ogvcs_metadata.file_id_registry'),
  'generic FileID restore is not rejected before SQL',
);
{
  const start = adapter.indexOf('    fn reserve_file_id(');
  const end = adapter.indexOf('\n    fn reserve_imported_file_id(', start);
  assert(
    start >= 0 && end > start
      && !adapter.slice(start, end).includes('TransactionCapability::RestoreFileId'),
    'restore capability can alias generic FileID reservation',
  );
}

const migrationRunner = await readFile(resolve(root, 'src/migration_runner.rs'), 'utf8');
assert(migrationRunner.includes('pub fn verify_schema_compatibility'), 'mutation schema compatibility gate missing');
assert(
  migrationRunner.indexOf('let existing =') < migrationRunner.indexOf('migration.requires_compatibility_fence'),
  'closed migration fence bypasses ledger checksum validation',
);

const reportDriver = await readFile(resolve(root, 'scripts/service-report.mjs'), 'utf8');
assert(reportDriver.includes('exactScaleExecuted: false'), 'service report does not exclude exact scale');
assert(reportDriver.includes('OGVCS_METADATA_DATABASE_URL is unset'), 'service report does not declare database skip');

process.stdout.write(`statically verified repository-metadata Rust/SQL scaffold: ${rustFiles.length} Rust modules, ${manifest.entries.length} migrations, ${errors.length} errors\n`);
