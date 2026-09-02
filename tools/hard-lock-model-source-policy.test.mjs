import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private hard-lock model composes frozen identity/path contracts and stays unwired', async () => {
  const [cargo, lib, target, submit] = await Promise.all([
    read('core/hard-lock/rust/Cargo.toml'),
    read('core/hard-lock/rust/src/lib.rs'),
    read('core/hard-lock/rust/src/target.rs'),
    read('core/hard-lock/rust/src/submit.rs'),
  ]);
  assert.match(cargo, /publish = false/u);
  assert.match(cargo, /rust-version = "1\.82"/u);
  assert.match(cargo, /ogvcs-object-model = \{ path = "\.\.\/\.\.\/object-model\/rust", version = "0\.1\.0" \}/u);
  assert.match(cargo, /ogvcs-path-contract = \{ path = "\.\.\/\.\.\/paths-filesystem\/rust", version = "1\.0\.0" \}/u);
  assert.doesNotMatch(cargo, /tokio|reqwest|axum|sqlx|postgres|rusqlite|tonic|aws-sdk|aws_sdk/iu);

  const source = `${lib}\n${target}\n${submit}`;
  assert.match(source, /pub const PERMISSION_LOCK_CREATE: u16 = 5;/u);
  assert.match(source, /pub const PERMISSION_SUBMIT: u16 = 6;/u);
  assert.match(source, /pub const PERMISSION_LOCK_FORCE_UNLOCK: u16 = 10;/u);
  assert.match(source, /FileId/u);
  assert.match(source, /repository_path_key/u);
  assert.match(source, /repository_prefix/u);
  assert.match(source, /ASSET_GROUP_MEMBERS_MAXIMUM: usize = 256/u);
  assert.match(source, /bounded_target_input_work/u);
  assert.match(source, /configuration_commitment/u);
  assert.match(source, /overlap_work/u);
  assert.match(source, /OVERSIZE-REQUEST-V1/u);
  assert.match(source, /pub fn validate_submit_facts\(\s*&self/u);
  assert.match(source, /pub server_time: u64/u);
  assert.doesNotMatch(source, /pub\s+(?:async\s+)?fn\s+(?:authorize|publish|commit_branch|serve|listen|persist|deliver_notification)/u);
  assert.doesNotMatch(source, /std::fs|std::net|TcpListener|TcpStream|UdpSocket|SystemTime|Instant|tokio|reqwest|axum|sqlx|postgres|rusqlite/iu);

  const event = lib.match(/pub struct EventCommitment \{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
  const receipt = lib.match(/pub struct OperationReceipt \{(?<body>[\s\S]*?)\n\}/u)?.groups?.body;
  assert.ok(event);
  assert.ok(receipt);
  for (const body of [event, receipt]) {
    assert.doesNotMatch(body, /String|SubjectId|WorkspaceId|FileId|TargetInput|path|owner|reason|members/iu);
  }
});

test('fault seam uses only the frozen lock-relevant OGVCS-005 assignments', async () => {
  const [lib, registryText] = await Promise.all([
    read('core/hard-lock/rust/src/lib.rs'),
    read('spec/benchmark-fault/v1/registries/faults.json'),
  ]);
  const registry = JSON.parse(registryText);
  const expected = ['policy.decision', 'lock.mutation', 'metadata.commit', 'event.publish'];
  const lockIds = registry.entries
    .filter((entry) => entry.tasks.includes('lock'))
    .map((entry) => entry.id)
    .sort();
  assert.deepEqual(lockIds, expected.toSorted());
  for (const id of expected) assert.ok(lib.includes(`"${id}"`));
  assert.match(lib, /AmbiguousAfterCommit/u);
  assert.match(lib, /InjectedBeforeCommit/u);
});

test('README and review retain the supplied-fact and nonclaim boundary', async () => {
  const [readme, review] = await Promise.all([
    read('core/hard-lock/rust/README.md'),
    read('docs/reviews/OGVCS-016-hard-lock-model-boundary-review.md'),
  ]);
  for (const text of [readme, review]) {
    assert.match(text, /unwired/iu);
    assert.match(text, /supplied/iu);
    assert.match(text, /not treat it as authorization|not\s+authorization|no\s+production authorization brand/iu);
    assert.match(text, /request-root/iu);
    assert.match(text, /real (?:wall )?clock/iu);
    assert.match(text, /public protocol\/CLI\/route|public\s+protocol\/CLI\/routes/iu);
    assert.match(text, /cross-branch/iu);
    assert.match(text, /hosted cross-OS|hosted three-OS/iu);
    assert.match(text, /scale|latency/iu);
    assert.match(text, /OGVCS-016 remains Todo/u);
  }
});

test('OGVCS-016 status and acceptance criteria remain unchanged while evidence is bounded', async () => {
  const [prd, packageValue] = await Promise.all([
    read('prd/todo/OGVCS-016-hard-locks-edit-intent.md'),
    read('package.json').then(JSON.parse),
  ]);
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
  const criteria = [
    '**OGVCS-016-AC-01:** Under concurrent and partitioned fault tests, no two clients receive successful submit acknowledgements for overlapping valid hard-lock targets.',
    '**OGVCS-016-AC-02:** Rename, case-only rename, sidecar expansion, delete/recreate, lease expiry, delayed renewal, and stale release match normative vectors.',
    '**OGVCS-016-AC-03:** A server crash at every lock/submit fault point recovers to exactly one explainable owner/generation and never publishes an unauthorized change.',
    '**OGVCS-016-AC-04:** An authorized user can identify a conflict owner and wait; an unauthorized user cannot infer the target or owner.',
    '**OGVCS-016-AC-05:** Every break/transfer is permission-checked, reasoned, notified where allowed, and correlated to an immutable audit record.',
    '**OGVCS-016-AC-06:** Promotion/failover tests prove old-epoch lock messages and submit proofs cannot mutate or authorize the new authority and clients display reacquire-required rather than retained exclusivity.',
  ];
  for (const criterion of criteria) assert.ok(prd.includes(criterion));
  assert.match(prd, /bounded candidate relevance only/iu);
  assert.match(prd, /No public protocol, CLI\/route, database adapter/iu);
  assert.equal(packageValue.scripts['test:hard-lock'], 'node --test tools/hard-lock-model-source-policy.test.mjs');
  assert.match(packageValue.scripts.test, /npm run test:hard-lock/u);
});
