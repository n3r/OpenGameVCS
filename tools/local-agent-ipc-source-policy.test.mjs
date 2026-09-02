import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

const workflowPaths = (workflow, event, nextEvent) => {
  const startToken = `  ${event}:\n`;
  const start = workflow.indexOf(startToken);
  assert.notEqual(start, -1, `${event} trigger exists`);
  const end = workflow.indexOf(`\n  ${nextEvent}:`, start + startToken.length);
  assert.notEqual(end, -1, `${event} trigger has a following event boundary`);
  const block = workflow.slice(start + startToken.length, end);
  const pathsToken = '    paths:\n';
  const pathsStart = block.indexOf(pathsToken);
  assert.notEqual(pathsStart, -1, `${event} trigger is path scoped`);
  const pathLines = block.slice(pathsStart + pathsToken.length).trimEnd().split('\n');
  for (const line of pathLines) {
    assert.match(line, /^      - '[^']+'$/u, `${event} contains only explicit path entries`);
  }
  return pathLines.map((line) => line.match(/^      - '([^']+)'$/u)[1]);
};

test('local-agent candidate is private, Rust 1.82, and composes owning types', async () => {
  const [cargo, lib, model, state] = await Promise.all([
    read('client/local-agent/rust/Cargo.toml'),
    read('client/local-agent/rust/src/lib.rs'),
    read('client/local-agent/rust/src/model.rs'),
    read('client/local-agent/rust/src/state.rs'),
  ]);

  assert.match(cargo, /^name = "ogvcs-local-agent-ipc"$/mu);
  assert.match(cargo, /^rust-version = "1\.82"$/mu);
  assert.match(cargo, /^publish = false$/mu);
  for (const direct of [
    'ogvcs-object-model',
    'ogvcs-path-contract',
    'opengamevcs-protocol-v1',
  ]) {
    assert.match(cargo, new RegExp(`^${direct} =`, 'mu'));
  }
  assert.doesNotMatch(cargo, /tokio|reqwest|keyring|ring|openssl|server|native-cli/iu);
  assert.match(lib, /#!\[forbid\(unsafe_code\)\]/u);
  assert.match(model, /pub use ogvcs_object_model::FileId/u);
  assert.match(model, /repository_path_key, repository_prefix/u);
  assert.match(model, /opengamevcs_protocol_v1::CONTRACT_MANIFEST_SHA256/u);
  assert.match(state, /agent_support_commitment/u);
  assert.match(state, /facts\.agent_offer != self\.agent_support/u);
});

test('all hard input, work, retained, queue, and time envelopes stay literal', async () => {
  const [model, state, tests] = await Promise.all([
    read('client/local-agent/rust/src/model.rs'),
    read('client/local-agent/rust/src/state.rs'),
    read('client/local-agent/rust/tests/contract.rs'),
  ]);
  for (const [name, value] of [
    ['RAW_INPUT_BYTES_MAXIMUM', '1_048_576'],
    ['COLLECTION_ITEMS_MAXIMUM', '256'],
    ['VERSION_ITEMS_MAXIMUM', '32'],
    ['CAPABILITY_ITEMS_MAXIMUM', '16'],
    ['PATH_SELECTORS_MAXIMUM', '256'],
    ['STATUS_ITEMS_MAXIMUM', '256'],
    ['EVENT_PAGE_ITEMS_MAXIMUM', '64'],
    ['EVENT_QUEUE_ITEMS_MAXIMUM', '256'],
    ['WORK_UNITS_MAXIMUM', '131_072'],
    ['RETAINED_LOGICAL_BYTES_MAXIMUM', '4_194_304'],
    ['RETAINED_RECORDS_MAXIMUM', '4_096'],
    ['SESSION_TTL_MAXIMUM_MS', '300_000'],
    ['HANDOFF_TTL_MAXIMUM_MS', '120_000'],
    ['FRESHNESS_AGE_MAXIMUM_MS', '30_000'],
    ['FRESHNESS_FUTURE_MAXIMUM_MS', '30_000'],
    ['DEADLINE_HORIZON_MAXIMUM_MS', '300_000'],
  ]) {
    assert.match(model, new RegExp(`pub const ${name}: [^=]+ = ${value};`, 'u'));
  }
  assert.match(state, /checked_add\(logical_bytes\)/u);
  assert.match(state, /checked_sub\(removed_bytes\)/u);
  assert.match(state, /facts\.logical_bytes\(\)\?/u);
  assert.match(state, /maximum_expiry/u);
  assert.match(state, /issued_cursor_expires_at_ms/u);
  assert.match(state, /expected_expiry != Some\(cursor\.expires_at_ms\)/u);
  assert.match(state, /consent_grant_commitment/u);
  assert.match(model, /pub struct SubscriptionCallerFacts/u);
  assert.match(model, /request_authentication: ExternalVerdict/u);
  assert.match(model, /subscription-caller-v1/u);
  assert.match(state, /caller_commitment/u);
  assert.match(state, /session\.transcript_commitment != caller\.session_transcript_commitment/u);
  assert.match(state, /facts\.replacement_endpoint\.id != self\.endpoint\.id/u);
  assert.match(state, /prior_state_commitment/u);
  assert.match(state, /consent-replacement-receipt-v1/u);
  assert.match(state, /builder\.digest\(raw_frame_commitment\)/u);
  assert.match(model, /semantically_equal/u);
  assert.match(model, /supplied_input_bytes/u);
  assert.match(model, /supplied_logical_bytes/u);
  assert.match(model, /contains_status_item/u);
  assert.match(model, /challenge_replay_commitment/u);
  assert.match(state, /EventEnqueueDisposition::ExactDuplicate/u);
  assert.match(state, /builder\.digest\(event\.event_commitment\)/u);
  assert.match(state, /ErrorCode::QueueFull/u);
  assert.match(state, /ErrorCode::CursorGap/u);
  assert.match(state, /ErrorCode::TimeReordered/u);
  assert.match(state, /check_cancel\(cancellation, CancellationPoint::BeforeCommit\)/u);
  assert.doesNotMatch(state, /get\(&cursor\.subscription_id\)[\s\S]{0,160}\.clone\(\)/u);
  assert.match(tests, /RAW_INPUT_BYTES_MAXIMUM \+ 1/u);
  assert.match(tests, /version maximum \+ 1/u);
  assert.match(tests, /PATH_SELECTORS_MAXIMUM \+ 1/u);
  assert.match(tests, /STATUS_ITEMS_MAXIMUM/u);
  assert.match(tests, /exact duplicate after original freshness/u);
  assert.match(tests, /idempotency-oracle/u);
  assert.match(tests, /an unkeyed cursor is not caller authentication/u);
  assert.match(tests, /an intermediate event without an issued cursor/u);
  assert.match(tests, /RETAINED_RECORDS_MAXIMUM/u);
  assert.match(tests, /assert_eq!\(fixture\.ledger\.snapshot\(\), before_/u);
});

test('source has no transport, filesystem, credential, clock, crypto, or mutation implementation', async () => {
  const [lib, commitment, model, state, readme, review] = await Promise.all([
    read('client/local-agent/rust/src/lib.rs'),
    read('client/local-agent/rust/src/commitment.rs'),
    read('client/local-agent/rust/src/model.rs'),
    read('client/local-agent/rust/src/state.rs'),
    read('client/local-agent/rust/README.md'),
    read('docs/reviews/OGVCS-042-local-agent-ipc-boundary-review.md'),
  ]);
  const source = [lib, commitment, model, state].join('\n');
  for (const forbidden of [
    /std::net/iu,
    /std::fs/iu,
    /std::process/iu,
    /SystemTime/iu,
    /Instant::now/iu,
    /TcpStream|UdpSocket|UnixStream/iu,
    /OpenOptions|File::open/iu,
    /Keyring|CredentialProvider/iu,
    /reqwest|hyper|tonic|tokio/iu,
    /\bring::|openssl|ed25519|\bhmac\b/iu,
    /\bunsafe\s*\{/u,
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
  for (const phrase of [
    'not an agent process',
    'does not parse the frame',
    'not\\s+authentication',
    'does not count allocator overhead',
    'same OS-user privileges',
    'no:',
  ]) {
    assert.match(readme, new RegExp(phrase, 'iu'));
  }
  assert.match(review, /SHIP only as a private, unpublished,/u);
  assert.match(review, /HOLD for any process, endpoint, authentication/u);
  assert.match(review, /No live P0\/P1\/P2 defect/u);
  assert.match(commitment, /Digest32\(<redacted>\)/u);
  assert.match(model, /impl std::fmt::Debug for HandshakeFacts/u);
  assert.match(model, /impl std::fmt::Debug for ValidatedScopePath/u);
});

test('package hook exists while OGVCS-042 and every acceptance criterion remain open', async () => {
  const [packageValue, prd, readme, review] = await Promise.all([
    read('package.json').then(JSON.parse),
    read('prd/todo/OGVCS-042-minimal-local-agent-first-party-ipc.md'),
    read('client/local-agent/rust/README.md'),
    read('docs/reviews/OGVCS-042-local-agent-ipc-boundary-review.md'),
  ]);
  assert.equal(
    packageValue.scripts['test:local-agent-ipc'],
    'node --test tools/local-agent-ipc-source-policy.test.mjs',
  );
  assert.match(packageValue.scripts.test, /npm run test:local-agent-ipc/u);
  assert.match(packageValue.engines.node, />=22/u);
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
  for (let criterion = 1; criterion <= 5; criterion += 1) {
    const id = String(criterion).padStart(2, '0');
    assert.match(prd, new RegExp(`OGVCS-042-AC-${id}`, 'u'));
  }
  assert.match(readme, /none of OGVCS-042-AC-01 through AC-05 is closed/u);
  assert.match(review, /AC-01 has no published schemas/u);
  assert.match(review, /All five remain open/u);
});

test('hosted portability workflow is pinned, path-complete, and preserves the private gate', async () => {
  const workflow = await read('.github/workflows/local-agent-ipc.yml');
  const expectedPaths = [
    '.github/workflows/local-agent-ipc.yml',
    'client/local-agent/rust/**',
    'core/object-model/rust/**',
    'core/paths-filesystem/rust/**',
    'foundation/protocol-baseline/bindings/rust/**',
    'docs/reviews/OGVCS-042-local-agent-ipc-boundary-review.md',
    'docs/evidence/OGVCS-042/**',
    'prd/todo/OGVCS-042-minimal-local-agent-first-party-ipc.md',
    'tools/local-agent-ipc-source-policy.test.mjs',
    'package.json',
    'package-lock.json',
  ];

  assert.match(workflow, /^name: R1 local-agent IPC candidate$/mu);
  assert.deepEqual(workflowPaths(workflow, 'pull_request', 'push'), expectedPaths);
  assert.deepEqual(workflowPaths(workflow, 'push', 'workflow_dispatch'), expectedPaths);
  assert.deepEqual(
    [...workflow.matchAll(/^    branches: (.+)$/gmu)].map((match) => match[1]),
    ['[main, r1-foundation-integration]'],
  );
  assert.match(workflow, /^  workflow_dispatch:\s*$/mu);
  assert.match(workflow, /^permissions:\n  contents: read\n\nconcurrency:$/mu);
  assert.match(
    workflow,
    /^  group: local-agent-ipc-\$\{\{ github\.workflow \}\}-\$\{\{ github\.ref \}\}$/mu,
  );
  assert.match(workflow, /cancel-in-progress: true/u);
  assert.deepEqual(
    [...workflow.slice(workflow.indexOf('jobs:\n')).matchAll(/^  ([a-z][a-z0-9-]+):$/gmu)]
      .map((match) => match[1]),
    ['portability'],
  );
  assert.match(workflow, /fail-fast: false/u);
  assert.match(workflow, /timeout-minutes: 30/u);
  assert.deepEqual(
    [...workflow.matchAll(/^          - \{ runner: ([^,]+), label: ([^ }]+) \}$/gmu)]
      .map((match) => ({ runner: match[1], label: match[2] })),
    [
      { runner: 'ubuntu-latest', label: 'Linux' },
      { runner: 'macos-latest', label: 'macOS' },
      { runner: 'windows-latest', label: 'Windows' },
    ],
  );

  assert.deepEqual(
    [...workflow.matchAll(/^      - uses: (\S+)(?:\s+#.*)?$/gmu)].map((match) => match[1]),
    [
      'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
      'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
      'dtolnay/rust-toolchain@7d11e79e1714f6b6da93cac39ad8435666f5c337',
    ],
  );
  assert.deepEqual(
    [...workflow.matchAll(/^          persist-credentials: (.+)$/gmu)].map((match) => match[1]),
    ['false'],
  );
  assert.match(
    workflow,
    /actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1\n        with:\n          persist-credentials: false\n      - uses: actions\/setup-node@/u,
  );
  assert.deepEqual(
    [...workflow.matchAll(/^          node-version: (.+)$/gmu)].map((match) => match[1]),
    ['24'],
  );
  assert.match(workflow, /# 1\.82\.0/u);
  assert.deepEqual(
    [...workflow.matchAll(/^          components: (.+)$/gmu)].map((match) => match[1]),
    ['clippy, rustfmt'],
  );
  assert.deepEqual(
    [...workflow.matchAll(/^\s+(?:- )?run: (.+)$/gmu)]
      .map((match) => match[1]),
    [
      'node --test tools/local-agent-ipc-source-policy.test.mjs',
      'cargo fetch --manifest-path client/local-agent/rust/Cargo.toml --locked',
      'cargo fmt --manifest-path client/local-agent/rust/Cargo.toml -- --check',
      'cargo test --manifest-path client/local-agent/rust/Cargo.toml --locked --offline',
      'cargo test --manifest-path client/local-agent/rust/Cargo.toml --locked --offline --release',
      'cargo clippy --manifest-path client/local-agent/rust/Cargo.toml --locked --offline --all-targets -- -D warnings',
      'sh ./scripts/test-packed.sh',
      'node prd/validate-roadmap.mjs && node --test prd/validate-roadmap.test.mjs',
    ],
  );
  assert.match(
    workflow,
    /- run: node --test tools\/local-agent-ipc-source-policy\.test\.mjs\n      - run: cargo fetch --manifest-path client\/local-agent\/rust\/Cargo\.toml --locked\n      - run: cargo fmt --manifest-path client\/local-agent\/rust\/Cargo\.toml -- --check/u,
  );
  assert.match(
    workflow,
    /- run: sh \.\/scripts\/test-packed\.sh\n        shell: bash\n        working-directory: client\/local-agent\/rust/u,
  );
  assert.match(
    workflow,
    /- name: Validate the open roadmap boundary\n        if: runner\.os == 'Linux'\n        run: node prd\/validate-roadmap\.mjs && node --test prd\/validate-roadmap\.test\.mjs/u,
  );
  assert.doesNotMatch(
    workflow,
    /continue-on-error|actions\/upload-artifact|\b(?:cargo|npm) publish\b|cosign|sigstore|pull_request_target/iu,
  );
});

test('retained hosted result is exact and bounded to private IPC source portability', async () => {
  const [evidence, evidenceReadme] = await Promise.all([
    read('docs/evidence/OGVCS-042/hosted-source-run-33636845159.json').then(JSON.parse),
    read('docs/evidence/OGVCS-042/README.md'),
  ]);

  assert.equal(evidence.schemaVersion, 'ogvcs.local-agent/hosted-source-run/v1');
  assert.deepEqual(evidence.run, {
    id: 33636845159,
    event: 'push',
    branch: 'r1-foundation-integration',
    headSha: '3563167763a54b97eb8166ded1db895aa3a5b7cd',
    status: 'completed',
    conclusion: 'success',
    createdAt: '2026-09-02T13:37:21Z',
    completedAt: '2026-09-02T13:40:23Z',
    url: 'https://github.com/n3r/OpenGameVCS/actions/runs/33636845159',
  });
  assert.deepEqual(
    evidence.jobs.map(({ id, name, conclusion }) => ({ id, name, conclusion })),
    [
      { id: 100269732676, name: 'Private IPC source portability (Windows)', conclusion: 'success' },
      { id: 100269732991, name: 'Private IPC source portability (macOS)', conclusion: 'success' },
      { id: 100269733202, name: 'Private IPC source portability (Linux)', conclusion: 'success' },
    ],
  );
  assert.deepEqual(evidence.claimBoundary, {
    privateSourcePortabilityOnly: true,
    agentProcess: false,
    osEndpoint: false,
    authenticatedJourney: false,
    acceptanceCriterion: false,
    releaseEvidence: false,
  });
  assert.match(evidenceReadme, /source-portability evidence only/iu);
  assert.match(evidenceReadme, /OGVCS-042 remains\s+\*\*Todo\*\*/u);
  assert.match(evidenceReadme, /AC-01 through AC-05 remain open/u);
});
