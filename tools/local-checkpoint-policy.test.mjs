import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private local checkpoint stays bounded, unwired, manifest-last, and Todo', async () => {
  const [cargo, source, readme, review, prd, packageValue, packed] = await Promise.all([
    read('client/local-checkpoint/rust/Cargo.toml'),
    read('client/local-checkpoint/rust/src/lib.rs'),
    read('client/local-checkpoint/rust/README.md'),
    read('docs/reviews/OGVCS-014-local-checkpoint-boundary-review.md'),
    read('prd/todo/OGVCS-014-local-checkpoints-offline-recovery.md'),
    read('package.json').then(JSON.parse),
    read('client/local-checkpoint/rust/scripts/test-packed.sh'),
  ]);

  assert.match(cargo, /name = "ogvcs-local-checkpoint"/u);
  assert.match(cargo, /rust-version = "1\.82"/u);
  assert.match(cargo, /publish = false/u);
  for (const direct of ['ogvcs-object-model', 'ogvcs-chunking-manifest', 'ogvcs-path-contract']) {
    assert.match(cargo, new RegExp(`^${direct} =`, 'mu'));
  }
  assert.match(cargo, /^winapi-util = "=0\.1\.11"$/mu);
  assert.doesNotMatch(cargo, /ogvcs-local-cli|server|reqwest|tokio/iu);

  for (const [constant, value] of [
    ['CHECKPOINTS_MAXIMUM', '10_000'],
    ['OPERATIONS_MAXIMUM', '10_000'],
    ['CHUNK_REFERENCES_MAXIMUM', '100_000'],
    ['LOCK_RECEIPTS_MAXIMUM', '10_000'],
    ['MESSAGE_BYTES_MAXIMUM', '16_384'],
    ['PATH_BYTES_TOTAL_MAXIMUM', '67_108_864'],
    ['RECORD_BYTES_MAXIMUM', '67_108_864'],
    ['STORE_RECORD_BYTES_MAXIMUM', '268_435_456'],
    ['GRAPH_DEPTH_MAXIMUM', '1_024'],
    ['PREVIEW_PATHS_MAXIMUM', '20_000'],
    ['PREVIEW_CONTENT_FACTS_MAXIMUM', '10_000'],
    ['PREVIEW_PATH_BYTES_MAXIMUM', '8_388_608'],
    ['PREVIEW_CHAIN_RECORD_BYTES_MAXIMUM', '268_435_456'],
    ['PREVIEW_CHAIN_OPERATIONS_MAXIMUM', '100_000'],
    ['PREVIEW_WORK_UNITS_MAXIMUM', '600_000'],
    ['PREVIEW_RETAINED_BYTES_MAXIMUM', '67_108_864'],
  ]) {
    assert.match(source, new RegExp(`pub const ${constant}: [^=]+ = ${value};`, 'u'));
  }
  assert.match(source, /OpenGameVCS local checkpoint record\\0/u);
  assert.match(source, /ogvcs_chunking_manifest::\{LOGICAL_MAXIMUM, MAXIMUM\}/u);
  assert.match(source, /part\.logical_length > MAXIMUM as u64/u);
  assert.match(source, /content-manifest-projection-conflict/u);
  assert.match(source, /content-chunk-length-conflict/u);
  assert.match(source, /#!\[forbid\(unsafe_code\)\]/u);
  assert.match(source, /historical-untrusted-exclusivity-unverified/u);
  assert.match(source, /\.ogvcs/u);
  assert.match(source, /local-checkpoints-v1/u);
  assert.match(source, /create_new\(true\)/u);
  assert.match(source, /FILE_FLAG_OPEN_REPARSE_POINT/u);
  assert.match(source, /libc::O_NOFOLLOW/u);
  assert.match(source, /builder\.mode\(0o700\)/u);
  assert.match(source, /metadata\.nlink\(\) != 1/u);
  assert.match(source, /information\.number_of_links\(\) != 1/u);
  assert.match(source, /sync_directory\(&self\.entries_root\)/u);
  assert.match(source, /PublicationBoundary::ManifestDirectorySynced/u);

  const directorySyncStart = source.indexOf('fn sync_directory(path: &Path)');
  const directorySyncEnd = source.indexOf('\nfn encode_hex(', directorySyncStart);
  assert.notEqual(directorySyncStart, -1);
  assert.ok(directorySyncEnd > directorySyncStart);
  const directorySync = source.slice(directorySyncStart, directorySyncEnd);
  const directorySyncOrder = [
    '.open(path)',
    '.metadata()',
    'metadata.file_type().is_dir()',
    'directory.sync_all()',
    'windows_directory_sync_unsupported(&failure)',
  ].map((needle) => directorySync.indexOf(needle));
  assert.equal(directorySyncOrder.every((offset) => offset >= 0), true);
  assert.deepEqual(
    directorySyncOrder,
    [...directorySyncOrder].sort((left, right) => left - right),
  );
  assert.match(source, /const WINDOWS_ERROR_ACCESS_DENIED: i32 = 5;/u);
  assert.match(
    source,
    /fn windows_directory_sync_unsupported\(failure: &std::io::Error\) -> bool \{\n    failure\.raw_os_error\(\) == Some\(WINDOWS_ERROR_ACCESS_DENIED\)\n\}/u,
  );
  assert.match(
    directorySync,
    /#\[cfg\(windows\)\]\n        Err\(failure\) if windows_directory_sync_unsupported\(&failure\) => Ok\(\(\)\)/u,
  );
  assert.doesNotMatch(directorySync, /options\.write\(true\)/u);
  assert.match(source, /windows_directory_sync_capability_classification_is_exact/u);

  const createStart = source.indexOf('    pub fn create(');
  const listStart = source.indexOf('    pub fn list(');
  assert.notEqual(createStart, -1);
  assert.ok(listStart > createStart);
  const createBody = source.slice(createStart, listStart);
  assert.ok(createBody.indexOf('INTENT_FILE') < createBody.indexOf('RECORD_FILE'));
  assert.ok(createBody.indexOf('RECORD_FILE') < createBody.lastIndexOf('COMPLETE_FILE'));
  assert.match(createBody, /let existing_entries = scan_entry_names\(&self\.entries_root\)\?/u);
  assert.match(createBody, /validate_creatable_entry_namespace\(&existing_entries\)\?/u);
  assert.match(createBody, /ensure_new_checkpoint_capacity\(existing_entries\.len\(\)\)\?/u);
  assert.match(createBody, /let loaded = self\.preflight_recoverable[\s\S]+require_artifacts[\s\S]+let loaded = self\.preflight_recoverable/u);
  assert.match(source, /require_artifacts\(&entry, &\[INTENT_FILE, RECORD_FILE\]\)/u);
  assert.match(source, /validate_pending_intent\(&intent, id\)/u);
  assert.match(source, /self\.load_verified_chain\(id\)\.map\(\|_\| \(\)\)/u);
  assert.match(source, /ensure_child_chain_depth\(parent_depth\)\?/u);
  assert.match(source, /sync_recoverable_artifacts\(&entry\)\?/u);
  assert.match(source, /sync_complete_artifacts\(&entry\)\?/u);
  assert.match(source, /os-name-hex:/u);
  assert.match(source, /0a65d00f0d7c832a39a4232d418d43520141e3e11f9213646f7f4023b3c4d18f/u);
  assert.match(source, /OpenGameVCS local checkpoint application preview\\0/u);
  assert.match(source, /d9cd72cba7f1d60e1d8e56b361d75f23b2c009e6b4c480333881fd0b78cff341/u);

  const production = source.slice(0, source.indexOf('#[cfg(test)]'));
  assert.doesNotMatch(production, /std::net|TcpListener|reqwest|AuthorizationContext|TransactionAuthorized/iu);
  assert.doesNotMatch(production, /remove_file|remove_dir|remove_dir_all|fs::rename|set_len/iu);
  assert.doesNotMatch(production, /pub fn (?:restore|delete|squash|publish|pin|evict)/iu);

  assert.match(readme, /does not\nread a manifest payload or chunk byte/u);
  assert.match(readme, /same-authority process can race/u);
  assert.match(readme, /integrity framing, not caller\nauthentication/u);
  assert.match(readme, /Operation records omit entry kind, mode, policy/u);
  assert.match(readme, /real power-loss durability is established only after/u);
  assert.match(readme, /no directory-entry power-loss durability on Windows/u);
  assert.match(readme, /intentionally narrower than checkpoint diff or restore/u);
  assert.match(readme, /AvailableUnverified[\s\S]+caller reported availability/u);
  assert.match(readme, /or removal \*intended\*; it is not authorization or permission/u);
  assert.match(readme, /no:[\s\S]+restore[\s\S]+cache pin[\s\S]+public CLI/iu);
  assert.match(review, /ship only as a private unwired candidate/u);
  assert.match(review, /no-ship for a\npublic command/u);
  assert.match(review, /does not\s+satisfy an\s+OGVCS-014 acceptance criterion/u);
  assert.match(review, /selected-record application-preview boundary/iu);
  assert.match(review, /not trusted filesystem\nor cache evidence/u);
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
  assert.match(prd, /OGVCS-014 remains \*\*Todo\*\*/u);
  assert.match(prd, /no acceptance criterion is claimed/u);
  assert.match(prd, /selected-record application preview cannot\n  account for untouched\/newer paths/u);

  assert.equal(packageValue.scripts['test:checkpoint'], 'node --test tools/local-checkpoint-policy.test.mjs');
  assert.match(packageValue.scripts.test, /npm run test:checkpoint/u);
  assert.match(packageValue.scripts['test:checkpoint:rust'], /cargo \+1\.82\.0 test/u);
  assert.match(packed, /cargo package/u);
  assert.match(packed, /cargo test --locked --offline/u);
  assert.match(packed, /ogvcs-local-checkpoint-0\.1\.0-rc\.1\.crate/u);
});

test('application preview binds supplied observations and remains read-only', async () => {
  const source = await read('client/local-checkpoint/rust/src/lib.rs');
  for (const type of [
    'CheckpointApplicationPreviewRequest',
    'PreviewReplacementIntent',
    'SuppliedWorkspacePathFact',
    'SuppliedWorkspacePathState',
    'SuppliedCheckpointContentFact',
    'SuppliedContentAvailability',
    'CheckpointApplicationPreview',
  ]) {
    assert.match(source, new RegExp(`pub (?:struct|enum) ${type}`, 'u'));
  }
  assert.match(source, /AvailableUnverified/u);
  assert.match(source, /Unavailable/u);
  assert.match(source, /PreserveCurrentWorkspace/u);
  assert.match(source, /ReplaceRecordedPaths/u);
  assert.match(source, /historical_lock_receipts_considered: false/u);

  const previewStart = source.indexOf('    pub fn preview_checkpoint_application(');
  const recoveryStart = source.indexOf('    /// Scans every bounded entry', previewStart);
  assert.notEqual(previewStart, -1);
  assert.ok(recoveryStart > previewStart);
  const preview = source.slice(previewStart, recoveryStart);
  const order = [
    'load_verified_chain_for_preview(',
    'loaded.checkpoint.bindings != request.bindings',
    'preflight_application_preview(',
    'preview-before-retained-projection',
    'fold_selected_record_effects(',
    'bind_supplied_workspace_facts(',
    'bind_supplied_content_facts(',
    'application_preview_digest(',
  ].map((needle) => preview.indexOf(needle));
  assert.equal(order.every((offset) => offset >= 0), true);
  assert.deepEqual(order, [...order].sort((left, right) => left - right));
  assert.doesNotMatch(
    preview,
    /fs::|remove_|write_|rename|set_len|create_new|Authorization|permission/iu,
  );
  assert.doesNotMatch(preview, /(?:checkpoint|loaded|request)\.lock_receipts/u);

  assert.match(source, /fn charge_preview_chain_record_bytes\(/u);
  assert.match(source, /fn charge_preview_chain_operations\(/u);
  assert.match(source, /fn charge_preview_work\(/u);
  assert.match(source, /fn charge_preview_path_bytes\(/u);
  assert.match(source, /fn charge_preview_retained_bytes\(/u);
  assert.match(source, /fn charge_preview_retained_path_projection\(/u);
  assert.match(source, /fn content_projection_identity\(/u);
  assert.match(source, /repository_path_key: sort_key\.0\.clone\(\)/u);
  assert.match(source, /platform_path_key: sort_key\.1\.clone\(\)/u);
  assert.match(source, /availability == Some\(SuppliedContentAvailability::Unavailable\)/u);
  assert.match(source, /PreviewWorkspaceImpact::Obstructed/u);
  assert.match(source, /preview-before-retained-projection/u);
  assert.match(source, /application_preview_is_deterministic_read_only_and_exactly_bound/u);
  assert.match(source, /replacement_intent_never_bypasses_obstruction_or_unavailable_content/u);
  assert.match(source, /preview_rejects_binding_path_file_id_content_and_case_substitution/u);
  assert.match(source, /preview_folds_copy_move_and_repeated_touch_to_final_record_effect/u);
  assert.match(source, /preview_count_byte_work_memory_and_cancellation_bounds_are_exact/u);
});

test('ordinary local-checkpoint gates contain no public, restore, or scale campaign', async () => {
  const packageValue = JSON.parse(await read('package.json'));
  for (const script of [
    packageValue.scripts['test:checkpoint'],
    packageValue.scripts['test:checkpoint:rust'],
  ]) {
    assert.doesNotMatch(script, /workflow_dispatch|100 ?GiB|million|restore|server|route/iu);
  }
});
