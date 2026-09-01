#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)));
const RUST = resolve(ROOT, '../../../src/production/workspace_index.rs');
const PRODUCTION_RUST = resolve(ROOT, '../../../src/production.rs');
const RETENTION_RUST = resolve(ROOT, '../../../src/production/workspace_index/retention.rs');
const contract = JSON.parse(await readFile(resolve(ROOT, 'contract.json'), 'utf8'));
const vector = JSON.parse(await readFile(resolve(ROOT, 'vectors/status-cursor-hmac.json'), 'utf8'));
const retentionVector = JSON.parse(await readFile(resolve(ROOT, 'vectors/retention-hmac.json'), 'utf8'));
const source = await readFile(RUST, 'utf8');
const productionSource = await readFile(PRODUCTION_RUST, 'utf8');
const retentionSource = await readFile(RETENTION_RUST, 'utf8');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function bodyAfter(marker) {
  const start = source.indexOf(marker);
  assert(start >= 0, `Rust marker missing: ${marker}`);
  const open = source.indexOf('{', start);
  assert(open >= 0, `Rust body missing: ${marker}`);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === '{') depth += 1;
    if (source[index] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(open + 1, index);
    }
  }
  throw new Error(`unterminated Rust body: ${marker}`);
}

const constantValues = new Map([
  ['WORKSPACE_INDEX_CONTRACT_VERSION', `"${contract.contractVersion}"`],
  ['MAX_BASELINE_ENTRIES', '10_000_000'],
  ['MAX_BASELINE_CHUNK_ITEMS', '1_000'],
  ['MAX_BASELINE_CHUNK_BYTES', '1024 * 1024'],
  ['MAX_WATCH_EVENTS', '100_000'],
  ['MAX_WATCH_CHUNK_ITEMS', '1_000'],
  ['MAX_WATCH_CHUNK_BYTES', '1024 * 1024'],
  ['MAX_STATUS_PAGE_ITEMS', '1_000'],
  ['MAX_IGNORE_RULES', '2_000'],
]);
for (const [name, rendered] of constantValues) {
  assert(source.includes(`pub const ${name}`) && source.includes(`= ${rendered};`), `${name} drift`);
}
assert(contract.limits.baselineEntries === 10_000_000, 'baselineEntries contract drift');
assert(contract.limits.baselineChunkItems === 1_000, 'baselineChunkItems contract drift');
assert(contract.limits.baselineChunkBytes === 1024 * 1024, 'baselineChunkBytes contract drift');
assert(contract.limits.watchEventsPerGeneration === 100_000, 'watchEventsPerGeneration contract drift');
assert(contract.limits.watchChunkItems === 1_000, 'watchChunkItems contract drift');
assert(contract.limits.watchChunkBytes === 1024 * 1024, 'watchChunkBytes contract drift');
assert(contract.limits.statusPageItems === 1_000, 'statusPageItems contract drift');
assert(contract.limits.ignoreRules === 2_000, 'ignoreRules contract drift');
assert(contract.limits.authenticatedGenerations === 128, 'authenticatedGenerations contract drift');
assert(contract.limits.readerLeases === 128, 'readerLeases contract drift');
assert(contract.limits.baseRetainedGenerations === 2, 'baseRetainedGenerations contract drift');
assert(contract.limits.compactionGenerationsPerRun === 8, 'compactionGenerationsPerRun contract drift');
assert(contract.limits.leaseExpiryEpochs === 2, 'leaseExpiryEpochs contract drift');
for (const [name, rendered] of new Map([
  ['MAX_AUTHENTICATED_GENERATIONS', '128'],
  ['MAX_READER_LEASES', '128'],
  ['BASE_RETAINED_GENERATIONS', '2'],
  ['MAX_COMPACTION_GENERATIONS_PER_RUN', '8'],
])) {
  assert(retentionSource.includes(`pub const ${name}: usize = ${rendered};`), `${name} drift`);
}
assert(retentionSource.includes('const LEASE_EXPIRY_EPOCHS: u64 = 2;'), 'LEASE_EXPIRY_EPOCHS drift');

assert(new Set(contract.statusCursor.requiredBindings).size === contract.statusCursor.requiredBindings.length, 'cursor bindings must be unique');
const cursorBody = bodyAfter('fn encode_status_cursor(');
const cursorNeedles = new Map([
  ['generation-id', 'generation_id: context.active.payload.generation_id.clone()'],
  ['active-payload-sha256', 'active_sha256: context.active.payload_sha256.clone()'],
  ['watcher-payload-sha256', 'watcher_payload_sha256: context.watcher.payload_sha256.clone()'],
  ['watcher-cursor', 'watcher_cursor: context.watcher.payload.cursor.clone()'],
  ['watcher-authority-sha256', 'watcher_authority_sha256: watcher_cursor_authority_digest(context.watcher)?'],
  ['watcher-event-count', 'watcher_event_count: context.watcher.payload.event_count'],
  ['watcher-event-bytes', 'watcher_event_bytes: context.watcher.payload.event_bytes'],
  ['watcher-event-tail-sha256', 'watcher_event_tail_sha256: context.watcher.payload.event_tail_sha256.clone()'],
  ['staging-generation', 'staging_generation: context.staging_generation'],
  ['staging-state-sha256', 'staging_state_sha256: context.staging_state_sha256.to_owned()'],
  ['repository-settings-digest', 'repository_settings_digest: context.binding.repository_settings_digest.clone()'],
  ['path-profile', 'path_profile: context.binding.path_profile.clone()'],
  ['case-mode', 'case_mode: context.binding.case_mode.clone()'],
  ['repository-ignore-rules-sha256', 'repository_ignore_rules_sha256: context.seal.repository_ignore_rules_sha256.clone()'],
  ['local-ignore-rules-sha256', 'local_ignore_rules_sha256: context.seal.local_ignore_rules_sha256.clone()'],
  ['filter-sha256', 'filter_sha256: context.filter_sha256.to_owned()'],
  ['after-repository-path', 'after_repository_path: after_path.to_owned()'],
  ['after-platform-key', 'after_platform_key'],
]);
assert(cursorNeedles.size === contract.statusCursor.requiredBindings.length, 'cursor registry/code mapping cardinality drift');
for (const binding of contract.statusCursor.requiredBindings) {
  assert(cursorNeedles.has(binding), `unmapped cursor binding: ${binding}`);
  assert(cursorBody.includes(cursorNeedles.get(binding)), `cursor encoder omits ${binding}`);
}
assert(cursorBody.includes('hmac_sha256(key, &payload_bytes)'), 'runtime cursor encoder is not authenticated');
assert(cursorBody.includes('schema: "ogvcs.workspace-index/status-cursor/v2"'), 'cursor schema must be v2');
const decodeCursorBody = bodyAfter('fn decode_status_cursor(');
assert(decodeCursorBody.includes('cursor.payload.schema != "ogvcs.workspace-index/status-cursor/v2"'), 'cursor decoder must reject non-v2 schema');
assert(decodeCursorBody.includes('watcher_cursor_authority_digest(context.watcher)?'), 'cursor decoder must recompute watcher authority');
assert(decodeCursorBody.includes('cursor.payload.watcher_authority_sha256 != watcher_authority_sha256'), 'cursor decoder must bind watcher authority');
assert(decodeCursorBody.includes('cursor.payload.watcher_event_count != context.watcher.payload.event_count'), 'cursor decoder must bind exact event transcript');
assert(!decodeCursorBody.includes('cursor.payload.watcher_payload_sha256 != context.watcher.payload_sha256'), 'idle cursor continuation must not exact-match a prior payload digest');
assert(!decodeCursorBody.includes('cursor.payload.watcher_cursor != context.watcher.payload.cursor'), 'idle cursor continuation must not exact-match a prior volume-global cursor');
assert(source.includes('fn v1_status_cursor_shape_and_schema_are_rejected_under_v2()'), 'v1 cursor rejection regression missing');
assert(source.includes('b"ogvcs.workspace-index/status-cursor-hmac/v2\\0"'), 'cursor HMAC domain must be v2');
assert(source.includes('const CURSOR_KEY_NAME: &str = "cursor-hmac-key-v1.bin";'), 'cursor key storage format drift');
assert(contract.statusCursor.keyStorage.startsWith('cursor-hmac-key-v1.bin-'), 'cursor key storage contract drift');

const publicStatusBody = bodyAfter('pub fn workspace_status_page(');
assert(publicStatusBody.includes('let mut watcher = UnavailableWorkspaceWatcher'), 'public status must install only the unavailable watcher');
assert(publicStatusBody.includes('workspace_status_page_fenced(request, &mut watcher)'), 'public status must delegate through the fail-degraded fence');
const statusBody = bodyAfter('fn workspace_status_page_fenced(');
assert(statusBody.includes('load_active(&root, false)?'), 'status must fail closed during a transition');
assert(statusBody.includes('retention::acquire_generation_read_lease(&index, &metadata, &active)?'), 'status must acquire a generation lease');
assert(statusBody.indexOf('fence_status_locked(') < statusBody.indexOf('retention::acquire_generation_read_lease'), 'status fence must publish before reader lease/release');
assert(statusBody.includes('read_validated_staging_snapshot(&root, &metadata.binding)?'), 'status must snapshot validated staging under the lock');
assert(statusBody.includes('&& staging.state.intents.is_empty()'), 'early clean must require empty staging');
assert(statusBody.includes('merge_staged_candidates(&metadata.binding, &mut candidates, &staging.state)?'), 'status must seed staged candidates');
assert((statusBody.match(/revalidate_status_snapshot\(/g) ?? []).length === 2, 'status must revalidate both early and classified returns');
const statusRevalidation = bodyAfter('fn revalidate_status_snapshot(');
for (const needle of [
  'let _lock = MutationLock::acquire(root)?',
  'load_active(root, false)?',
  'current_active.payload.generation != snapshot.active.payload.generation',
  'current_active.payload.generation_id != snapshot.active.payload.generation_id',
  'current_active.payload_sha256 != snapshot.active.payload_sha256',
  'current_watcher.payload_sha256 != watcher.payload_sha256',
  'current_watcher.payload.event_count != watcher.payload.event_count',
  'current_watcher.payload.event_bytes != watcher.payload.event_bytes',
  'current_watcher.payload.event_tail_sha256 != watcher.payload.event_tail_sha256',
  'validate_watcher_state(snapshot.index, &current_seal, &current_watcher)?',
  'current_staging.state.generation != snapshot.staging_generation',
  'current_staging.state_sha256 != snapshot.staging_state_sha256',
  'fence_status_locked(',
  'final_staging.state.generation != snapshot.staging_generation',
  '*watcher = current_watcher',
]) assert(statusRevalidation.includes(needle), `status after-check omits: ${needle}`);
assert(statusRevalidation.indexOf('fence_status_locked(') < statusRevalidation.lastIndexOf('current_watcher.payload.event_count != watcher.payload.event_count'), 'final native barrier must precede transcript comparison');
assert(statusBody.lastIndexOf('revalidate_status_snapshot(') < statusBody.indexOf('encode_status_cursor('), 'next cursor must bind the final native barrier payload');
const watcherAuthorityBody = bodyAfter('fn watcher_state_is_authoritative(');
for (const needle of [
  'payload.continuity_proven',
  'payload.resume_supported',
  'payload.session_open',
  '!payload.reconciliation_required',
]) assert(watcherAuthorityBody.includes(needle), `authoritative watcher shape omits: ${needle}`);
const watcherCoherenceBody = bodyAfter('fn watcher_liveness_shape_is_coherent(');
for (const needle of [
  'watcher_state_is_authoritative(payload)',
  '!payload.continuity_proven',
  '!payload.session_open',
  'payload.reconciliation_required',
]) assert(watcherCoherenceBody.includes(needle), `watcher coherence omits: ${needle}`);
assert(source.includes('|| !watcher_liveness_shape_is_coherent(payload)'), 'watcher validator must reject incoherent liveness shapes');
assert(source.includes('fn closed_but_continuous_watcher_state_cannot_bypass_public_fence()'), 'closed continuous watcher regression missing');
assert(source.includes('fn final_native_barrier_rejects_event_withheld_during_clean_scan()'), 'withheld final-barrier regression missing');
assert(source.includes('fn idle_final_cursor_advance_is_bound_to_returned_page()'), 'idle final-cursor regression missing');
assert(source.includes('assert_eq!(authority.fences, 4)'), 'idle cursor pagination progress regression missing');
assert(source.includes('fn page_cursor_rejects_watcher_authority_change_with_unchanged_transcript()'), 'watcher authority cursor regression missing');
assert(source.includes('fn page_cursor_rejects_earlier_staging_snapshot_between_pages()'), 'staging cursor regression missing');
assert(contract.watcher.samePathCoalescing === 'creation-and-rename-destination-history-survives-later-modify-delete-post-delete-create-resets-rename-lineage-conflict-is-sticky', 'same-path coalescing contract drift');
assert(contract.watcher.renameLineage === 'later-modify-preserves-destination-prior-path-and-source-baseline-file-id-later-delete-preserves-source-deletion-post-delete-create-clears-prior-path-and-source-file-id', 'rename lineage contract drift');
assert(contract.watcher.renameOntoBaselineDestination === 'conflicted-without-file-id-and-reconciliation-required-for-regular-equal-content-or-absent-destination', 'baseline-destination rename contract drift');
assert(contract.watcher.transientCollapse === 'only-finally-absent-unstaged-untracked-created-or-rename-destination-then-deleted', 'transient collapse contract drift');
const mergeEventBody = bodyAfter('fn merge_event_candidate(');
assert(mergeEventBody.includes('WorkspaceWatchEventKind::Created | WorkspaceWatchEventKind::Renamed'), 'rename destination must retain creation history');
assert(mergeEventBody.includes('candidate.event_kind != Some(WorkspaceWatchEventKind::Conflict)'), 'conflict must remain sticky during same-path coalescing');
assert(mergeEventBody.includes('event.kind == WorkspaceWatchEventKind::Created && candidate.saw_deleted'), 'post-delete create must establish a new identity');
assert(mergeEventBody.includes('candidate.prior_path = None'), 'post-delete create must clear stale rename lineage');
const classifyCandidateBody = bodyAfter('fn classify_status_candidate(');
assert(classifyCandidateBody.includes('candidate.prior_path.is_some()'), 'classification must retain rename lineage');
assert(classifyCandidateBody.includes('map(|prior| lookup.find(prior, binding))'), 'rename lineage must look up the immutable source FileID');
assert(classifyCandidateBody.includes('&& !has_staged_intent'), 'staged intent must not qualify for transient collapse');
assert(classifyCandidateBody.includes('if baseline.is_some()'), 'baseline-destination rename must fail closed');
assert(classifyCandidateBody.includes('candidate.prior_path.is_some() || candidate.rename_identity_reset'), 'watcher-only baseline-destination rename and identity-reset intersections must fail closed');
assert(classifyCandidateBody.includes('rename-destination-baseline-identity-ambiguous'), 'baseline-destination rename reason missing');
assert(source.includes('fn same_path_watcher_transition_matrix_preserves_net_state_and_identity()'), 'same-path transition matrix regression missing');
assert(source.includes('label: "rename-delete-create"'), 'post-delete create identity-reset regression missing');
assert(source.includes('fn rename_onto_baseline_destination_fails_closed_without_guessing_identity()'), 'baseline-destination rename regression missing');
assert(source.includes('fn staged_and_watcher_overlap_matrix_never_collapses_applied_intent()'), 'staged/watcher overlap matrix regression missing');
assert(source.includes('MovedThenDeletedCreated'), 'staged move identity-reset regression missing');
assert(source.includes('candidate.rename_identity_reset |= candidate.prior_path.is_some()'), 'watcher rename reset must remain distinguishable from an ordinary baseline replacement');
assert(source.includes('destination_candidate.rename_identity_reset = true'), 'staged move reset must remain distinguishable from an ordinary baseline replacement');
assert(source.includes('fn staged_move_reset_has_no_cross_journal_order_and_is_always_ambiguous()'), 'cross-journal causal-order regression missing');
assert(source.includes('fn staged_move_reset_is_ambiguous_before_or_after_stage_with_or_without_baseline_destination()'), 'staged move reset ordering/baseline matrix missing');
assert(source.includes('fn staged_add_move_and_delete_identity_reset_intersections_fail_closed()'), 'all staged identity-reset roles regression missing');
assert(source.includes('fn incompatible_staged_and_watcher_lineage_fails_closed_for_every_intent_kind()'), 'staged/watcher lineage matrix missing');
assert(source.includes('fn outgoing_watcher_rename_from_every_staged_role_fails_closed()'), 'outgoing staged/watcher lineage matrix missing');
assert(source.includes('fn applied_move_or_delete_with_reoccupied_source_never_lends_staged_identity()'), 'staged source reoccupation regression missing');
assert(source.includes('fn locally_provable_staged_file_id_and_baseline_identity_conflicts_reconcile()'), 'staged immutable-source identity regression missing');
for (const needle of [
  'staged-watcher-identity-reset-order-ambiguous',
  'staged-watcher-lineage-incompatible',
  'staged-source-file-id-mismatch',
  'staged-source-reoccupation-identity-ambiguous',
  'staged-add-baseline-identity-incompatible',
]) assert(classifyCandidateBody.includes(needle) || source.includes(needle), `staged fail-closed reason missing: ${needle}`);
assert(source.includes('fn overlapping_applied_intents_fail_before_staging_or_filesystem_mutation()'), 'staged collision matrix regression missing');
assert(source.includes('fn duplicate_candidate_intent_id_is_rejected_before_journal_or_filesystem_mutation()'), 'candidate intent-ID admission regression missing');
assert(source.includes('fn persisted_staging_path_identities_are_rederived_and_unique_before_mutation()'), 'persisted staging identity regression missing');
assert(contract.stagingStatus.admittedState === 'structurally-valid-applied-intents-with-rederived-path-identities-only', 'staged admitted-state contract drift');
assert(contract.stagingStatus.watcherOverlap === 'compatible-applied-add-move-delete-overlap-remains-visible-while-unordered-identity-reset-or-incompatible-lineage-fails-closed', 'staged watcher-overlap contract drift');
assert(contract.stagingStatus.watcherOrdering === 'staging-records-bind-no-watcher-cursor-or-sequence-so-delete-create-reset-intersections-are-conflicted-without-file-id-or-prior-path', 'staged/watcher ordering contract drift');
assert(contract.stagingStatus.lineageCompatibility === 'only-the-exact-same-staged-move-source-destination-watcher-edge-is-compatible-other-incoming-or-outgoing-staged-path-lineage-conflicts-the-complete-intent-and-watcher-destination', 'staged lineage-compatibility contract drift');
assert(contract.stagingStatus.sourceIdentity === 'immutable-source-baseline-file-id-must-match-staged-move-delete-file-id-and-applied-source-must-be-absent-before-staged-identity-is-lent', 'staged source-identity contract drift');
assert(contract.stagingStatus.addBaselineIdentity === 'applied-add-on-an-immutable-baseline-path-is-conflicted-without-file-id', 'staged Add baseline contract drift');
assert(contract.stagingStatus.futureOrderingNonclaim === 'definitive-post-stage-reset-semantics-require-durable-staging-to-watcher-order-binding', 'staged ordering nonclaim drift');
assert(contract.stagingStatus.persistedPathIdentity === 'rederive-and-match-repository-key-and-reject-duplicate-intent-id-or-repository-or-platform-path-identity-on-every-load', 'persisted staging identity contract drift');
assert(contract.stagingStatus.overlappingIntentPaths === 'reject-candidate-intent-id-or-repository-or-platform-path-identity-overlap-before-staging-publication-or-filesystem-mutation', 'staged admission-overlap contract drift');
for (const needle of [
  'fn read_validated_staging_state(',
  'validate_staging_state(&state, binding)?',
  'validated.repository_key != persisted_repository_key',
  'intent.intent_id == candidate.intent_id',
  'candidate_platform_keys.contains(&path.platform_key)',
]) assert(productionSource.includes(needle), `persisted staging validation omits: ${needle}`);
for (const needle of [
  'fn reconcile_staged_watcher_rename_edges(',
  'for record in records',
  'role == StagedPathRole::MoveSource',
  'intent.destination_path.as_deref() == Some(event.repository_path.as_str())',
  'conflict_paths.extend(intent.source_path.as_deref())',
  'conflict_paths.extend(intent.destination_path.as_deref())',
]) assert(source.includes(needle), `outgoing staged/watcher lineage reconciliation omits: ${needle}`);

const prepareBody = bodyAfter('fn prepare_reconciliation(');
assert(prepareBody.indexOf('append_untracked_findings(') < prepareBody.indexOf('self.reconciliation_prepared = true'), 'scan must complete before watcher drain admission');
const watcherSinkBody = bodyAfter('impl WorkspaceWatchEventSink for GenerationWriter');
assert(watcherSinkBody.includes('if !self.reconciliation_prepared'), 'writer must reject watcher drain before complete scan');
const rebuildBody = bodyAfter('pub fn rebuild_workspace_index(');
assert(rebuildBody.indexOf('writer.prepare_reconciliation(receipt)?') < rebuildBody.indexOf('watcher.finish_reconciliation('), 'rebuild must scan before final watcher barrier');
const fenceBody = bodyAfter('fn fence_status_locked(');
for (const needle of [
  'authority.fence_status(',
  'StatusFenceSink',
  'persist_status_checkpoint(index, watcher, checkpoint)',
  'persist_degraded_state(index, watcher, "status-fence-unavailable", true)',
  'persist_degraded_state(index, watcher, "status-fence-invalid", true)',
]) assert(fenceBody.includes(needle), `status fence omits: ${needle}`);
const batchBody = bodyAfter('fn append_watch_batch_locked(');
assert(batchBody.indexOf('events.sync_all()') < batchBody.indexOf('write_json_atomic('), 'status fence batch must fsync journal before state');
const repairBody = bodyAfter('pub fn repair_workspace_index(');
assert(!repairBody.includes('verify_workspace_index(root)?'), 'repair must not release verification lock');
assert(repairBody.indexOf('let _lock = MutationLock::acquire(&root)?') < repairBody.indexOf('verify_loaded_workspace_index('), 'repair verification must be under mutation lock');
assert(repairBody.indexOf('verify_loaded_workspace_index(') < repairBody.indexOf('open_private_file(&index.join(&old_seal.payload.entries.name))'), 'repair must verify the exact generation before consuming it');
const lookupBody = bodyAfter('fn find(');
for (const needle of [
  'entry.repository_path == repository_path',
  'entry.platform_key == keys.platform_key()',
  'entry.repository_key == keys.repository_key().as_str()',
  'entry.platform_key_sha256 == hex_bytes(&target)',
]) assert(lookupBody.includes(needle), `lookup omits full collision revalidation: ${needle}`);

const checkpointStruct = source.slice(source.indexOf('pub struct WorkspaceWatcherCheckpoint'), source.indexOf('impl WorkspaceWatcherCheckpoint'));
assert(!checkpointStruct.includes('pub continuity_proven'), 'external callers may not mint continuity proof fields');
const checkpointImpl = bodyAfter('impl WorkspaceWatcherCheckpoint');
assert(!checkpointImpl.includes('continuity_proven: true'), 'production constructor may not mint native continuity');

assert(contract.privateCandidateClaims.readerSafeGenerationGcImplemented === true, 'private reader-safe compaction claim drift');
for (const [claim, value] of Object.entries(contract.publicClaims)) {
  assert(value === false, `public completion claim must remain false: ${claim}`);
}
for (const status of contract.statusValues) {
  assert(source.includes(`"${status}"`), `status value missing from Rust: ${status}`);
}

const key = Buffer.from(vector.keyHex, 'hex');
assert(key.length === 32, 'vector key must be 32 bytes');
const payload = Buffer.from(JSON.stringify(vector.payload), 'utf8');
const domain = Buffer.from(`${contract.statusCursor.domainUtf8Nul}\0`, 'utf8');
const innerKey = Buffer.alloc(64, 0x36);
const outerKey = Buffer.alloc(64, 0x5c);
for (let index = 0; index < key.length; index += 1) {
  innerKey[index] ^= key[index];
  outerKey[index] ^= key[index];
}
const inner = sha256(Buffer.concat([innerKey, domain, payload]));
const actualMac = createHash('sha256').update(Buffer.concat([outerKey, inner])).digest('hex');
assert(actualMac === vector.expectedMacSha256, 'independent Node cursor HMAC vector mismatch');

const retentionKey = Buffer.from(retentionVector.keyHex, 'hex');
assert(retentionKey.length === 32, 'retention vector key must be 32 bytes');
const retentionDomain = Buffer.from(`${retentionVector.domainUtf8Nul}\0`, 'utf8');
const retentionMessage = Buffer.from(retentionVector.messageUtf8, 'utf8');
const retentionInnerKey = Buffer.alloc(64, 0x36);
const retentionOuterKey = Buffer.alloc(64, 0x5c);
for (let index = 0; index < retentionKey.length; index += 1) {
  retentionInnerKey[index] ^= retentionKey[index];
  retentionOuterKey[index] ^= retentionKey[index];
}
const retentionInner = sha256(Buffer.concat([retentionInnerKey, retentionDomain, retentionMessage]));
const retentionMac = createHash('sha256').update(Buffer.concat([retentionOuterKey, retentionInner])).digest('hex');
assert(retentionMac === retentionVector.expectedMacSha256, 'independent Node retention HMAC vector mismatch');

for (const needle of [
  'lock_shared(&validated.file)?',
  'sync_directory(&directory)?',
  'validate_authenticated_namespace(&index, &state)?',
  'validate_recovery_namespace(index, metadata, &state, &intent)?',
  'write_intent(&index, &intent)?',
  'pinned.insert(active_record.generation_id.clone())',
  'pinned.insert(record.generation_id.clone())',
  'remove_generation(index, record, missing_ok)?',
]) assert(retentionSource.includes(needle), `retention implementation omits: ${needle}`);

process.stdout.write(`workspace-index private contract ${contract.contractVersion}: valid\n`);
