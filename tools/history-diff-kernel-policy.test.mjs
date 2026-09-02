import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private history/diff/text candidate stays unpublished, unwired, bounded, and Todo', async () => {
  const [cargo, source, cursor, textMerge, readme, review, textReview, golden, packageValue, prd] = await Promise.all([
    read('core/history-diff/rust/Cargo.toml'),
    read('core/history-diff/rust/src/lib.rs'),
    read('core/history-diff/rust/src/cursor.rs'),
    read('core/history-diff/rust/src/text_merge.rs'),
    read('core/history-diff/rust/README.md'),
    read('docs/reviews/OGVCS-015-history-diff-kernel-boundary-review.md'),
    read('docs/reviews/OGVCS-015-private-text-merge-kernel-review.md'),
    read('core/history-diff/rust/tests/text-merge-golden.json'),
    read('package.json').then(JSON.parse),
    read('prd/todo/OGVCS-015-branches-history-merge-revert.md'),
  ]);
  assert.match(cargo, /name = "ogvcs-history-diff-kernel"/u);
  assert.match(cargo, /rust-version = "1\.82"/u);
  assert.match(cargo, /publish = false/u);
  assert.doesNotMatch(cargo, /reqwest|tokio|sqlx|axum|tonic/iu);
  assert.match(source, /ValidationMode::Conformance/u);
  assert.match(source, /path_collision_keys_with_options/u);
  assert.match(source, /FailureKind::Ambiguous\(AmbiguousKind::SharedTree\)/u);
  assert.match(source, /ObjectReadOutcome::Found\(payload\)/u);
  assert.doesNotMatch(
    `${source}\n${cursor}\n${textMerge}`,
    /std::fs|std::process|Command::new|TcpListener|UdpSocket|reqwest|AuthorizationContext|TransactionAuthorized|compareAndSwap|workspace write/iu,
  );
  for (const evidence of [
    'ogvcs.text-merge/line-diff3@1',
    'TEXT_MERGE_INPUT_BYTES_MAXIMUM: u64 = 1_048_576',
    'TEXT_MERGE_LCS_CELLS_MAXIMUM: u64 = 263_169',
    'TEXT_MERGE_WORK_UNITS_MAXIMUM: u64 = 24_000_000',
    'TEXT_MERGE_CONFLICTS_MAXIMUM: u64 = 128',
    'TEXT_MERGE_CHARGED_MEMORY_BYTES_MAXIMUM: u64 = 12_582_912',
    'TextMergeInputErrorKind::CarriageReturnForbidden',
    'character.is_control()',
    'left.base_start.max(right.base_start) < left.base_end.min(right.base_end)',
    'conflicts: conflicts.into_boxed_slice()',
  ]) assert.match(textMerge, new RegExp(evidence.replaceAll(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  assert.doesNotMatch(textMerge, /<<<<<<<|>>>>>>>|external.driver|network|request-root/iu);
  assert.match(readme, /unpublished Rust 1\.82 crate/u);
  assert.match(readme, /conformance-scoped/u);
  assert.match(readme, /does not satisfy an OGVCS-015 acceptance criterion/u);
  assert.match(readme, /The seal is integrity detection, not a MAC/u);
  assert.match(readme, /never exposes a partial candidate file or manufactures conflict/u);
  assert.match(review, /OGVCS-015 remains Todo/u);
  assert.match(review, /AC-01 through AC-05 all remain open/u);
  assert.match(textReview, /OGVCS-015 remains Todo; AC-01 through AC-05 remain open/u);
  assert.match(textReview, /Request-root authorization is not read, changed, or inferred/u);
  assert.match(textReview, /No executable or process API is present here/u);
  assert.equal(JSON.parse(golden).schemaVersion, 'ogvcs.text-merge/private-golden/v1');
  assert.equal(packageValue.scripts['test:history-diff'], 'node --test tools/history-diff-kernel-policy.test.mjs');
  assert.match(packageValue.scripts.test, /npm run test:history-diff/u);
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
  assert.match(prd, /private, unpublished Rust 1\.82 history\/diff kernel/u);
  assert.match(prd, /No OGVCS-015 acceptance criterion is closed/u);
});

test('crate package boundary includes only declared offline sources', async () => {
  const cargo = await read('core/history-diff/rust/Cargo.toml');
  const files = await readdir(new URL('../core/history-diff/rust/src/', import.meta.url));
  assert.deepEqual(files.sort(), ['cursor.rs', 'lib.rs', 'model.rs', 'text_merge.rs']);
  assert.match(cargo, /"src\/\*\*"/u);
  assert.match(cargo, /"tests\/\*\*"/u);
  assert.match(cargo, /"scripts\/\*\*"/u);
  assert.doesNotMatch(cargo, /\.github|server\/|client\/|spec\//u);
});
