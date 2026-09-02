import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private history/diff candidate stays unpublished, unwired, bounded, and Todo', async () => {
  const [cargo, source, cursor, readme, review, packageValue, prd] = await Promise.all([
    read('core/history-diff/rust/Cargo.toml'),
    read('core/history-diff/rust/src/lib.rs'),
    read('core/history-diff/rust/src/cursor.rs'),
    read('core/history-diff/rust/README.md'),
    read('docs/reviews/OGVCS-015-history-diff-kernel-boundary-review.md'),
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
    `${source}\n${cursor}`,
    /std::fs|TcpListener|UdpSocket|reqwest|AuthorizationContext|TransactionAuthorized|compareAndSwap|workspace write/iu,
  );
  assert.match(readme, /unpublished Rust 1\.82 crate/u);
  assert.match(readme, /conformance-scoped/u);
  assert.match(readme, /does not satisfy an OGVCS-015 acceptance criterion/u);
  assert.match(readme, /The seal is integrity detection, not a MAC/u);
  assert.match(review, /OGVCS-015 remains Todo/u);
  assert.match(review, /AC-01 through AC-05 all remain open/u);
  assert.equal(packageValue.scripts['test:history-diff'], 'node --test tools/history-diff-kernel-policy.test.mjs');
  assert.match(packageValue.scripts.test, /npm run test:history-diff/u);
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
  assert.match(prd, /private, unpublished Rust 1\.82 history\/diff kernel/u);
  assert.match(prd, /No OGVCS-015 acceptance criterion is closed/u);
});

test('crate package boundary includes only declared offline sources', async () => {
  const cargo = await read('core/history-diff/rust/Cargo.toml');
  const files = await readdir(new URL('../core/history-diff/rust/src/', import.meta.url));
  assert.deepEqual(files.sort(), ['cursor.rs', 'lib.rs', 'model.rs']);
  assert.match(cargo, /"src\/\*\*"/u);
  assert.match(cargo, /"tests\/\*\*"/u);
  assert.match(cargo, /"scripts\/\*\*"/u);
  assert.doesNotMatch(cargo, /\.github|server\/|client\/|spec\//u);
});
