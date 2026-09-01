#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)));
const RUST = resolve(ROOT, '../../../src/production/workspace_index.rs');
const RETENTION_RUST = resolve(ROOT, '../../../src/production/workspace_index/retention.rs');
const contract = JSON.parse(await readFile(resolve(ROOT, 'contract.json'), 'utf8'));
const vector = JSON.parse(await readFile(resolve(ROOT, 'vectors/status-cursor-hmac.json'), 'utf8'));
const retentionVector = JSON.parse(await readFile(resolve(ROOT, 'vectors/retention-hmac.json'), 'utf8'));
const source = await readFile(RUST, 'utf8');
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
  ['generation-id', 'generation_id: active.payload.generation_id.clone()'],
  ['active-payload-sha256', 'active_sha256: active.payload_sha256.clone()'],
  ['repository-settings-digest', 'repository_settings_digest: binding.repository_settings_digest.clone()'],
  ['path-profile', 'path_profile: binding.path_profile.clone()'],
  ['case-mode', 'case_mode: binding.case_mode.clone()'],
  ['repository-ignore-rules-sha256', 'repository_ignore_rules_sha256: seal.repository_ignore_rules_sha256.clone()'],
  ['local-ignore-rules-sha256', 'local_ignore_rules_sha256: seal.local_ignore_rules_sha256.clone()'],
  ['filter-sha256', 'filter_sha256: filter_sha256.to_owned()'],
  ['after-repository-path', 'after_repository_path: after_path.to_owned()'],
  ['after-platform-key', 'after_platform_key'],
]);
assert(cursorNeedles.size === contract.statusCursor.requiredBindings.length, 'cursor registry/code mapping cardinality drift');
for (const binding of contract.statusCursor.requiredBindings) {
  assert(cursorNeedles.has(binding), `unmapped cursor binding: ${binding}`);
  assert(cursorBody.includes(cursorNeedles.get(binding)), `cursor encoder omits ${binding}`);
}
assert(cursorBody.includes('hmac_sha256(key, &payload_bytes)'), 'runtime cursor encoder is not authenticated');

const statusBody = bodyAfter('pub fn workspace_status_page(');
assert(statusBody.includes('load_active(&root, false)?'), 'status must fail closed during a transition');
assert(statusBody.includes('retention::acquire_generation_read_lease(&index, &metadata, &active)?'), 'status must acquire a generation lease');
assert((statusBody.match(/revalidate_status_snapshot\(/g) ?? []).length === 2, 'status must revalidate both early and classified returns');
const statusRevalidation = bodyAfter('fn revalidate_status_snapshot(');
for (const needle of [
  'symlink_metadata(index.join("transition.json"))',
  'current_active.payload.generation != active.payload.generation',
  'current_active.payload.generation_id != active.payload.generation_id',
  'current_active.payload_sha256 != active.payload_sha256',
  'current_watcher.payload_sha256 != watcher.payload_sha256',
  'current_watcher.payload.event_count != watcher.payload.event_count',
  'current_watcher.payload.event_bytes != watcher.payload.event_bytes',
  'current_watcher.payload.event_tail_sha256 != watcher.payload.event_tail_sha256',
  'validate_watcher_state(index, seal, &current_watcher)?',
]) assert(statusRevalidation.includes(needle), `status after-check omits: ${needle}`);
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
