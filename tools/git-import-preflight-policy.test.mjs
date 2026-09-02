import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('hosted portability workflow is pinned, path-scoped, and cross-platform', async () => {
  const workflow = await read('.github/workflows/git-import-preflight.yml');
  const watchedPaths = [
    '.github/workflows/git-import-preflight.yml',
    'core/import-git-lfs/rust/**',
    'core/object-model/rust/**',
    'core/paths-filesystem/rust/**',
    'docs/reviews/OGVCS-020-git-import-preflight-boundary-review.md',
    'prd/todo/OGVCS-020-git-lfs-importer.md',
    'tools/git-import-preflight-policy.test.mjs',
    'package.json',
    'package-lock.json',
  ];

  const pullRequest = workflow.match(/on:\n  pull_request:\n    paths:\n(?<paths>(?:      - '[^']+'\n)+)  push:/u);
  const push = workflow.match(/  push:\n    branches: \[main, r1-foundation-integration\]\n    paths:\n(?<paths>(?:      - '[^']+'\n)+)  workflow_dispatch:/u);
  const decodePaths = (match) => match?.groups?.paths.trimEnd().split('\n').map((line) => line.slice(9, -1));
  assert.deepEqual(decodePaths(pullRequest), watchedPaths);
  assert.deepEqual(decodePaths(push), watchedPaths);
  assert.match(workflow, /  workflow_dispatch:\n/u);
  assert.match(workflow, /permissions:\n  contents: read/u);
  assert.match(workflow, /cancel-in-progress: true/u);
  assert.match(workflow, /timeout-minutes: 30/u);
  const runners = [...workflow.matchAll(/^          - \{ runner: ([^,]+), label: ([^ }]+) \}$/gmu)]
    .map((match) => ({ runner: match[1], label: match[2] }));
  assert.deepEqual(runners, [
    { runner: 'ubuntu-latest', label: 'Linux' },
    { runner: 'macos-latest', label: 'macOS' },
    { runner: 'windows-latest', label: 'Windows' },
  ]);
  assert.match(workflow, /runs-on: \$\{\{ matrix\.runner \}\}/u);

  const actionUses = [...workflow.matchAll(/^\s*- uses: ([^\s#]+)/gmu)].map((match) => match[1]);
  assert.deepEqual(actionUses, [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020',
    'dtolnay/rust-toolchain@7d11e79e1714f6b6da93cac39ad8435666f5c337',
  ]);
  for (const action of actionUses) assert.match(action, /@[0-9a-f]{40}$/u);
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /# 1\.82\.0/u);
  assert.match(workflow, /components: clippy, rustfmt/u);

  assert.match(workflow, /node --test tools\/git-import-preflight-policy\.test\.mjs/u);
  assert.match(workflow, /cargo fetch --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked/u);
  assert.match(workflow, /cargo fmt --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml -- --check/u);
  assert.match(workflow, /cargo test --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked --offline\n/u);
  assert.match(workflow, /cargo test --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked --offline --release/u);
  assert.match(workflow, /cargo clippy --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked --offline --all-targets -- -D warnings/u);
  assert.match(workflow, /run: \.\/scripts\/test-packed\.sh\n        shell: bash\n        working-directory: core\/import-git-lfs\/rust/u);
  assert.match(workflow, /if: runner\.os == 'Linux'\n        run: node prd\/validate-roadmap\.mjs && node --test prd\/validate-roadmap\.test\.mjs/u);
});

test('OGVCS-020 candidate remains private, bounded, unwired, and Todo', async () => {
  const [manifest, source, readme, review, packageValue, prd] = await Promise.all([
    read('core/import-git-lfs/rust/Cargo.toml'),
    Promise.all([
      read('core/import-git-lfs/rust/src/lib.rs'),
      read('core/import-git-lfs/rust/src/lfs.rs'),
      read('core/import-git-lfs/rust/src/oid.rs'),
      read('core/import-git-lfs/rust/src/preflight.rs'),
    ]).then((parts) => parts.join('\n')),
    read('core/import-git-lfs/rust/README.md'),
    read('docs/reviews/OGVCS-020-git-import-preflight-boundary-review.md'),
    read('package.json').then(JSON.parse),
    read('prd/todo/OGVCS-020-git-lfs-importer.md'),
  ]);

  assert.match(manifest, /rust-version = "1\.82"/u);
  assert.match(manifest, /publish = false/u);
  assert.match(manifest, /ogvcs-object-model/u);
  assert.match(manifest, /ogvcs-path-contract/u);
  assert.doesNotMatch(source, /std::fs|TcpListener|UdpSocket|reqwest|git2|Command::new|AuthorizationContext|TransactionAuthorized/iu);
  assert.match(source, /pub const ITEMS_HARD_MAXIMUM: u64 = 1_000_000;/u);
  assert.match(source, /pub const WORK_UNITS_HARD_MAXIMUM: u64 = 64_000_000;/u);
  assert.match(source, /pub const READ_CHUNK_BYTES_HARD_MAXIMUM: usize = 65_536;/u);
  assert.match(source, /GIT_LFS_POINTER_BYTES_MAXIMUM: usize = 1_023/u);
  assert.match(source, /bytes\.len\(\) > GIT_LFS_POINTER_BYTES_MAXIMUM[\s\S]*PointerClassification::NotPointer/u);
  assert.doesNotMatch(source, /looks_like_pointer[\s\S]{0,700}starts_with\(b"version "\)/u);
  assert.match(source, /first\.is_ascii_alphanumeric\(\) \|\| first == b'_'/u);
  assert.match(source, /pub struct GitObjectId\(GitObjectIdRepr\);/u);
  assert.doesNotMatch(source, /pub enum GitObjectId\s*\{/u);
  assert.match(source, /pub struct SourceOccurrence/u);
  assert.match(source, /pub enum LfsDisposition/u);
  assert.match(source, /LfsDisposition::Ordinary => \(metadata\.encoded_bytes, None, false\)/u);
  assert.doesNotMatch(source, /LfsExpectation|LfsDisposition::Auto/u);
  assert.match(source, /expected\.counts\.mappings != expected\.counts\.blob_occurrences/u);
  assert.match(source, /fn decide\(&self, request: &ImportRequest\)/u);
  assert.match(source, /work_units: u64,[\s\S]*peak_retained_bytes: u64,[\s\S]*limits: ImportLimits/u);
  assert.match(source, /#\[derive\(Clone, Eq, PartialEq\)\]\s+pub enum ImportRecord/u);
  assert.match(source, /#\[derive\(Clone, Eq, Ord, PartialEq, PartialOrd\)\]\s+pub enum ImportRecordKey/u);
  assert.match(source, /import_mapping_key/u);
  assert.match(source, /ImportMapping/u);
  assert.doesNotMatch(source, /permit_lfs_extensions/iu);
  assert.match(readme, /no Git pack parser/iu);
  assert.match(readme, /not allocator or\s+RSS measurement/iu);
  assert.match(readme, /opaque caller claim/iu);
  assert.match(readme, /at or above 1024 bytes is\s+unconditionally `NotPointer`/iu);
  assert.match(readme, /uppercase and underscore word bytes\s+are valid/iu);
  assert.match(readme, /Generic short text such as\s+`version 1\.0`/iu);
  assert.match(readme, /Symlink target blobs are always `Ordinary`/iu);
  assert.match(readme, /does not attest correct attribute discovery/iu);
  assert.match(readme, /No OGVCS-020\s+acceptance criterion is satisfied or closed/iu);
  assert.match(review, /OGVCS-020-AC-01 through OGVCS-020-AC-07 remain open/u);
  assert.match(review, /No Git pack\/loose-object\/archive parser/u);
  assert.match(review, /git-scm\.com\/docs\/gitdatamodel\.html/u);
  assert.match(review, /github\.com\/git\/git\/blob\/master\/entry\.c/u);
  assert.match(review, /There is intentionally no derivation or authentication relationship/u);
  assert.equal(packageValue.engines.node, '>=22');
  assert.equal(packageValue.scripts['test:git-import-preflight'], 'node --test tools/git-import-preflight-policy.test.mjs');
  assert.match(packageValue.scripts['test:git-import-preflight:rust'], /cargo \+1\.82\.0/u);
  assert.match(packageValue.scripts.test, /test:git-import-preflight/u);
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
  assert.doesNotMatch(prd, /^- \[x\].*OGVCS-020-AC-/mu);
  for (let number = 1; number <= 7; number += 1) {
    assert.match(prd, new RegExp(`OGVCS-020-AC-0${number}`));
  }
});

test('packed source includes tests, golden vector, docs, and no route declaration', async () => {
  const [manifest, packed, golden, readme] = await Promise.all([
    read('core/import-git-lfs/rust/Cargo.toml'),
    read('core/import-git-lfs/rust/scripts/test-packed.sh'),
    read('core/import-git-lfs/rust/tests/golden.json').then(JSON.parse),
    read('core/import-git-lfs/rust/README.md'),
  ]);
  assert.match(manifest, /"tests\/\*\*"/u);
  assert.match(manifest, /"scripts\/\*\*"/u);
  assert.match(packed, /cargo package/u);
  assert.match(packed, /cargo test --locked --offline/u);
  assert.equal(golden.lfsContentSha256, '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03');
  assert.doesNotMatch(readme, /production-ready|hosted importer|public API/iu);
});
