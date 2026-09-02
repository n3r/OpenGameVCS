import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { verifyRetainedSourceFiles } from './retained-source-evidence.mjs';

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
    'tools/retained-source-evidence.mjs',
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
  const retainedFetch = 'git fetch --no-tags --depth=1 origin fa61786b272a019b82f4e96eaaa47dbef60c5b6c';
  assert.equal([...workflow.matchAll(/git fetch\b/gu)].length, 1);
  assert.equal(workflow.split(retainedFetch).length - 1, 1);
  assert.ok(workflow.indexOf('persist-credentials: false') < workflow.indexOf(retainedFetch));
  assert.ok(workflow.indexOf(retainedFetch) < workflow.indexOf('Check private source and workflow policy'));
  assert.doesNotMatch(workflow, /fetch-depth:\s*0|persist-credentials:\s*true/u);
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /# 1\.82\.0\n        with:\n          components: clippy, rustfmt/u);
  assert.doesNotMatch(workflow, /^\s+toolchain:/mu);
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
  const [prds, evidence, evidenceReadme] = await Promise.all([
    Promise.all([
      read('prd/todo/OGVCS-014-local-checkpoints-offline-recovery.md'),
      read('prd/todo/OGVCS-015-branches-history-merge-revert.md'),
      read('prd/todo/OGVCS-017-integrity-verification-repair.md'),
    ]),
    read('docs/evidence/OGVCS-014/hosted-source-run-33664922225.json').then(JSON.parse),
    read('docs/evidence/OGVCS-014/README.md'),
  ]);
  for (const prd of prds) {
    assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
    assert.match(prd, /acceptance criterion|acceptance criteria/iu);
  }
  assert.match(prds[0], /no acceptance criterion is claimed/iu);
  assert.match(prds[1], /No OGVCS-015 acceptance criterion is closed/u);
  assert.match(prds[2], /OGVCS-017 remains Todo/u);

  assert.deepEqual(Object.keys(evidence), [
    'schemaVersion',
    'run',
    'evidenceCollection',
    'jobs',
    'successfulStepsOnEveryHost',
    'sourceFiles',
    'claimBoundary',
  ]);
  assert.equal(evidence.schemaVersion, 'ogvcs.local-checkpoint/hosted-source-run/v1');
  assert.deepEqual(evidence.run, {
    id: 33664922225,
    event: 'push',
    branch: 'r1-foundation-integration',
    headSha: 'fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
    status: 'completed',
    conclusion: 'success',
    createdAt: '2026-09-02T18:03:59Z',
    completedAt: '2026-09-02T18:11:00Z',
    url: 'https://github.com/n3r/OpenGameVCS/actions/runs/33664922225',
  });
  assert.deepEqual(evidence.evidenceCollection, {
    runAndDurationSource: 'public GitHub Actions HTML',
    jobSource: 'public GitHub Actions XHR matrix',
    completedAtDerivation: 'createdAt plus the displayed total duration',
    completedAtIsInferred: true,
    apiUnavailableReason: 'unauthenticated public API quota exhausted',
  });
  assert.deepEqual(evidence.jobs, [
    { id: 100364185739, name: 'Private Rust tranches (macOS)', conclusion: 'success' },
    { id: 100364185892, name: 'Private Rust tranches (Windows)', conclusion: 'success' },
    { id: 100364185952, name: 'Private Rust tranches (Linux)', conclusion: 'success' },
  ]);
  assert.deepEqual(evidence.successfulStepsOnEveryHost, [
    'private source and workflow policy',
    'exact locked Rust dependency closure',
    'Rust format check',
    'OGVCS-014 local-checkpoint tests',
    'OGVCS-014 warnings-denied Clippy',
    'freshly extracted OGVCS-014 package tests',
  ]);
  assert.deepEqual(evidence.claimBoundary, {
    privateSourcePortabilityOnly: true,
    checkpointCreation: false,
    checkpointRestore: false,
    crashCorruptionMatrix: false,
    acceptanceCriterion: false,
    releaseEvidence: false,
  });
  await verifyRetainedSourceFiles({
    root,
    evidence,
    revision: 'fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
    paths: [
      '.github/workflows/private-rust-tranches.yml',
      'client/local-checkpoint/rust/Cargo.lock',
      'client/local-checkpoint/rust/Cargo.toml',
      'client/local-checkpoint/rust/LICENSE',
      'client/local-checkpoint/rust/README.md',
      'client/local-checkpoint/rust/scripts/test-packed.sh',
      'client/local-checkpoint/rust/src/lib.rs',
    ],
  });
  assert.match(evidenceReadme, /source-portability evidence only/iu);
  assert.match(evidenceReadme, /OGVCS-014 remains \*\*Todo\*\*/u);
  assert.match(evidenceReadme, /AC-01\s+through AC-05 remain open/u);
});
