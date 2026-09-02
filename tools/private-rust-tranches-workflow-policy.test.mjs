import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

const manifests = {
  checkpoint: 'client/local-checkpoint/rust/Cargo.toml',
  history: 'core/history-diff/rust/Cargo.toml',
  integrity: 'core/integrity-verifier/rust/Cargo.toml',
};

test('private Rust tranche workflow is pinned, path-scoped, and three-OS bounded', async () => {
  const workflow = await read('.github/workflows/private-rust-tranches.yml');
  const watchedPaths = [
    '.github/workflows/private-rust-tranches.yml',
    'client/local-checkpoint/rust/**',
    'core/chunking-manifest/rust/**',
    'core/history-diff/rust/**',
    'core/integrity-verifier/rust/**',
    'core/object-model/rust/**',
    'core/paths-filesystem/rust/**',
    'docs/evidence/OGVCS-014/**',
    'docs/evidence/OGVCS-015/**',
    'docs/evidence/OGVCS-017/**',
    'docs/reviews/OGVCS-014-local-checkpoint-boundary-review.md',
    'docs/reviews/OGVCS-015-history-diff-kernel-boundary-review.md',
    'docs/reviews/OGVCS-015-private-text-merge-kernel-review.md',
    'docs/reviews/OGVCS-017-read-only-integrity-verifier-review.md',
    'package.json',
    'package-lock.json',
    'prd/ROADMAP.md',
    'prd/todo/OGVCS-014-local-checkpoints-offline-recovery.md',
    'prd/todo/OGVCS-015-branches-history-merge-revert.md',
    'prd/todo/OGVCS-017-integrity-verification-repair.md',
    'prd/validate-roadmap.mjs',
    'prd/validate-roadmap.test.mjs',
    'tools/history-diff-kernel-policy.test.mjs',
    'tools/integrity-verifier-source-policy.test.mjs',
    'tools/local-checkpoint-policy.test.mjs',
    'tools/private-rust-tranches-workflow-policy.test.mjs',
  ];
  const pullRequest = workflow.match(
    /on:\n  pull_request:\n    paths:\n(?<paths>(?:      - '[^']+'\n)+)  push:/u,
  );
  const push = workflow.match(
    /  push:\n    branches: \[main, r1-foundation-integration\]\n    paths:\n(?<paths>(?:      - '[^']+'\n)+)  workflow_dispatch:/u,
  );
  const decodePaths = (match) => match?.groups?.paths
    .trimEnd()
    .split('\n')
    .map((line) => line.slice(9, -1));
  assert.deepEqual(decodePaths(pullRequest), watchedPaths);
  assert.deepEqual(decodePaths(push), watchedPaths);
  assert.match(workflow, /  workflow_dispatch:\n\npermissions:/u);
  assert.match(workflow, /permissions:\n  contents: read\n\nconcurrency:/u);
  assert.match(workflow, /cancel-in-progress: true/u);
  assert.match(workflow, /timeout-minutes: 60/u);

  const runners = [...workflow.matchAll(/^          - \{ runner: ([^,]+), label: ([^ }]+) \}$/gmu)]
    .map((match) => ({ runner: match[1], label: match[2] }));
  assert.deepEqual(runners, [
    { runner: 'ubuntu-latest', label: 'Linux' },
    { runner: 'macos-latest', label: 'macOS' },
    { runner: 'windows-latest', label: 'Windows' },
  ]);
  assert.match(workflow, /runs-on: \$\{\{ matrix\.runner \}\}/u);

  const actionUses = [...workflow.matchAll(/^\s*- uses: ([^\s#]+)/gmu)]
    .map((match) => match[1]);
  assert.deepEqual(actionUses, [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
    'dtolnay/rust-toolchain@7d11e79e1714f6b6da93cac39ad8435666f5c337',
  ]);
  for (const action of actionUses) assert.match(action, /@[0-9a-f]{40}$/u);
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /# 1\.82\.0\n        with:\n          toolchain: 1\.82\.0/u);
  assert.match(workflow, /components: clippy, rustfmt/u);
});

test('workflow directly runs every declared private source and Rust gate', async () => {
  const workflow = await read('.github/workflows/private-rust-tranches.yml');
  for (const policy of [
    'tools/local-checkpoint-policy.test.mjs',
    'tools/history-diff-kernel-policy.test.mjs',
    'tools/integrity-verifier-source-policy.test.mjs',
    'tools/private-rust-tranches-workflow-policy.test.mjs',
  ]) assert.match(workflow, new RegExp(policy.replaceAll('.', '\\.')));

  for (const manifest of Object.values(manifests)) {
    const escaped = manifest.replaceAll('.', '\\.');
    assert.match(workflow, new RegExp(`cargo fetch --manifest-path ${escaped} --locked`, 'u'));
    assert.match(workflow, new RegExp(`cargo fmt --manifest-path ${escaped} -- --check`, 'u'));
    assert.match(
      workflow,
      new RegExp(`cargo test --manifest-path ${escaped} --locked --offline(?:\\n|$)`, 'mu'),
    );
    assert.match(
      workflow,
      new RegExp(`cargo clippy --manifest-path ${escaped} --locked --offline --all-targets -- -D warnings`, 'u'),
    );
  }

  const releaseTests = [...workflow.matchAll(/^\s*run: (cargo test [^\n]+ --release)$/gmu)]
    .map((match) => match[1]);
  assert.deepEqual(releaseTests, [
    `cargo test --manifest-path ${manifests.history} --locked --offline --release`,
  ]);
  assert.match(workflow, /shell: bash\n        run: sh client\/local-checkpoint\/rust\/scripts\/test-packed\.sh/u);
  assert.match(workflow, /shell: bash\n        run: sh core\/history-diff\/rust\/scripts\/test-packed\.sh/u);
  assert.match(
    workflow,
    /cargo package --manifest-path core\/integrity-verifier\/rust\/Cargo\.toml\n          --locked --offline --allow-dirty --no-verify/u,
  );
  assert.match(
    workflow,
    /if: runner\.os == 'Linux'\n        run: node prd\/validate-roadmap\.mjs && node --test prd\/validate-roadmap\.test\.mjs/u,
  );
});

test('ordinary hosted gate cannot acquire mutation authority or turn into scale execution', async () => {
  const workflow = await read('.github/workflows/private-rust-tranches.yml');
  assert.doesNotMatch(
    workflow,
    /pull_request_target|schedule:|repository_dispatch|workflow_call|self-hosted|continue-on-error|permissions: write-all|contents: write|id-token:|secrets\.|environment:|services:|container:|docker|podman|kubectl|helm|terraform|postgres|minio|aws|s3-compatible|curl|wget|request-root|authorization|authorize|public route|server|deploy|sandbox|100.?GiB|million-entry|1.?TiB|--ignored|rm -rf/iu,
  );
  assert.doesNotMatch(workflow, /workflow_dispatch:\n    inputs:/u);
  assert.doesNotMatch(workflow, /actions\/upload-artifact|actions\/download-artifact/u);
});

test('hosted portability leaves all three PRDs Todo with acceptance work open', async () => {
  const prds = await Promise.all([
    read('prd/todo/OGVCS-014-local-checkpoints-offline-recovery.md'),
    read('prd/todo/OGVCS-015-branches-history-merge-revert.md'),
    read('prd/todo/OGVCS-017-integrity-verification-repair.md'),
  ]);
  for (const prd of prds) {
    assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
    assert.match(prd, /acceptance criterion|acceptance criteria/iu);
  }
  assert.match(prds[0], /no acceptance criterion is claimed/iu);
  assert.match(prds[1], /No OGVCS-015 acceptance criterion is closed/u);
  assert.match(prds[2], /OGVCS-017 remains Todo/u);
});
