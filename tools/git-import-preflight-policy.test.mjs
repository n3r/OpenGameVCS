import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { verifyRetainedSourceFiles } from './retained-source-evidence.mjs';

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
    'docs/reviews/OGVCS-020-git-tree-frame-boundary-review.md',
    'docs/evidence/OGVCS-020/**',
    'prd/todo/OGVCS-020-git-lfs-importer.md',
    'tools/git-import-preflight-policy.test.mjs',
    'tools/retained-source-evidence.mjs',
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
  const retainedFetch = 'git fetch --no-tags --depth=1 origin fa61786b272a019b82f4e96eaaa47dbef60c5b6c';
  assert.equal([...workflow.matchAll(/git fetch\b/gu)].length, 1);
  assert.equal(workflow.split(retainedFetch).length - 1, 1);
  assert.ok(workflow.indexOf('persist-credentials: false') < workflow.indexOf(retainedFetch));
  assert.ok(workflow.indexOf(retainedFetch) < workflow.indexOf('node --test tools/git-import-preflight-policy.test.mjs'));
  assert.doesNotMatch(workflow, /fetch-depth:\s*0|persist-credentials:\s*true/u);
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /# 1\.82\.0/u);
  assert.match(workflow, /components: clippy, rustfmt/u);

  assert.match(workflow, /node --test tools\/git-import-preflight-policy\.test\.mjs/u);
  assert.match(workflow, /cargo fetch --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked/u);
  assert.match(workflow, /cargo fmt --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml -- --check/u);
  assert.match(workflow, /cargo test --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked --offline\n/u);
  assert.match(workflow, /cargo test --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked --offline --release/u);
  assert.match(workflow, /cargo clippy --manifest-path core\/import-git-lfs\/rust\/Cargo\.toml --locked --offline --all-targets -- -D warnings/u);
  assert.match(workflow, /run: sh \.\/scripts\/test-packed\.sh\n        shell: bash\n        working-directory: core\/import-git-lfs\/rust/u);
  assert.match(workflow, /if: runner\.os == 'Linux'\n        run: node prd\/validate-roadmap\.mjs && node --test prd\/validate-roadmap\.test\.mjs/u);
});

test('retained hosted result is exact and bounded to private preflight portability', async () => {
  const [historicalEvidence, evidence, evidenceReadme] = await Promise.all([
    read('docs/evidence/OGVCS-020/hosted-source-run-33638102757.json').then(JSON.parse),
    read('docs/evidence/OGVCS-020/hosted-source-run-33664922211.json').then(JSON.parse),
    read('docs/evidence/OGVCS-020/README.md'),
  ]);

  assert.equal(historicalEvidence.schemaVersion, 'ogvcs.import/hosted-source-run/v1');
  assert.deepEqual(historicalEvidence.run, {
    id: 33638102757,
    event: 'push',
    branch: 'r1-foundation-integration',
    headSha: '0e714329a903573c7aa0d16a58adda8bf67e1088',
    status: 'completed',
    conclusion: 'success',
    createdAt: '2026-09-02T13:49:28Z',
    completedAt: '2026-09-02T13:51:57Z',
    url: 'https://github.com/n3r/OpenGameVCS/actions/runs/33638102757',
  });
  assert.deepEqual(
    historicalEvidence.jobs.map(({ id, name, conclusion }) => ({ id, name, conclusion })),
    [
      { id: 100273965526, name: 'Private preflight portability (Linux)', conclusion: 'success' },
      { id: 100273965786, name: 'Private preflight portability (Windows)', conclusion: 'success' },
      { id: 100273965832, name: 'Private preflight portability (macOS)', conclusion: 'success' },
    ],
  );
  assert.deepEqual(historicalEvidence.claimBoundary, {
    privatePreflightOnly: true,
    gitParser: false,
    conversion: false,
    authenticatedImport: false,
    acceptanceCriterion: false,
    releaseEvidence: false,
  });

  assert.deepEqual(Object.keys(evidence), [
    'schemaVersion',
    'run',
    'evidenceCollection',
    'jobs',
    'successfulStepsOnEveryHost',
    'sourceFiles',
    'claimBoundary',
  ]);
  assert.equal(evidence.schemaVersion, 'ogvcs.import/hosted-source-run/v1');
  assert.deepEqual(evidence.run, {
    id: 33664922211,
    event: 'push',
    branch: 'r1-foundation-integration',
    headSha: 'fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
    status: 'completed',
    conclusion: 'success',
    createdAt: '2026-09-02T18:03:59Z',
    completedAt: '2026-09-02T18:06:47Z',
    url: 'https://github.com/n3r/OpenGameVCS/actions/runs/33664922211',
  });
  assert.deepEqual(evidence.evidenceCollection, {
    runAndDurationSource: 'public GitHub Actions HTML',
    jobSource: 'public GitHub Actions XHR matrix',
    completedAtDerivation: 'createdAt plus the displayed total duration',
    completedAtIsInferred: true,
    apiUnavailableReason: 'unauthenticated public API quota exhausted',
  });
  assert.deepEqual(evidence.jobs, [
    { id: 100364184134, name: 'Private preflight portability (macOS)', conclusion: 'success' },
    { id: 100364184431, name: 'Private preflight portability (Windows)', conclusion: 'success' },
    { id: 100364184514, name: 'Private preflight portability (Linux)', conclusion: 'success' },
  ]);
  assert.deepEqual(evidence.successfulStepsOnEveryHost, [
    'Node source/package/PRD/workflow policy',
    'Rust format check',
    'Rust debug tests',
    'Rust release tests',
    'Rust warnings-denied Clippy',
    'freshly extracted package tests',
  ]);
  assert.deepEqual(evidence.claimBoundary, {
    privatePreflightAndTreeFrameOnly: true,
    fullRepositoryParser: false,
    repositoryTraversal: false,
    conversion: false,
    authenticatedImport: false,
    acceptanceCriterion: false,
    releaseEvidence: false,
  });
  await verifyRetainedSourceFiles({
    root,
    evidence,
    revision: 'fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
    paths: [
      '.github/workflows/git-import-preflight.yml',
      'core/import-git-lfs/rust/Cargo.lock',
      'core/import-git-lfs/rust/Cargo.toml',
      'core/import-git-lfs/rust/LICENSE',
      'core/import-git-lfs/rust/README.md',
      'core/import-git-lfs/rust/scripts/test-packed.sh',
      'core/import-git-lfs/rust/src/git_tree.rs',
      'core/import-git-lfs/rust/src/lfs.rs',
      'core/import-git-lfs/rust/src/lib.rs',
      'core/import-git-lfs/rust/src/oid.rs',
      'core/import-git-lfs/rust/src/preflight.rs',
      'core/import-git-lfs/rust/tests/git-tree-golden.json',
      'core/import-git-lfs/rust/tests/git_tree.rs',
      'core/import-git-lfs/rust/tests/git_tree_golden.rs',
      'core/import-git-lfs/rust/tests/golden.json',
      'core/import-git-lfs/rust/tests/golden.rs',
      'core/import-git-lfs/rust/tests/lfs.rs',
      'core/import-git-lfs/rust/tests/oid.rs',
      'core/import-git-lfs/rust/tests/preflight.rs',
      'core/import-git-lfs/rust/tests/support/mod.rs',
    ],
  });
  assert.match(evidenceReadme, /source-portability evidence only/iu);
  assert.match(evidenceReadme, /fa61786b272a019b82f4e96eaaa47dbef60c5b6c/u);
  assert.match(evidenceReadme, /OGVCS-020 remains\s+\*\*Todo\*\*/u);
  assert.match(evidenceReadme, /AC-01 through AC-07\s+remain open/u);
});

test('OGVCS-020 candidate remains private, bounded, unwired, and Todo', async () => {
  const [manifest, source, treeSource, readme, review, treeReview, treeGolden, packageValue, prd] = await Promise.all([
    read('core/import-git-lfs/rust/Cargo.toml'),
    Promise.all([
      read('core/import-git-lfs/rust/src/lib.rs'),
      read('core/import-git-lfs/rust/src/lfs.rs'),
      read('core/import-git-lfs/rust/src/oid.rs'),
      read('core/import-git-lfs/rust/src/preflight.rs'),
    ]).then((parts) => parts.join('\n')),
    read('core/import-git-lfs/rust/src/git_tree.rs'),
    read('core/import-git-lfs/rust/README.md'),
    read('docs/reviews/OGVCS-020-git-import-preflight-boundary-review.md'),
    read('docs/reviews/OGVCS-020-git-tree-frame-boundary-review.md'),
    read('core/import-git-lfs/rust/tests/git-tree-golden.json').then(JSON.parse),
    read('package.json').then(JSON.parse),
    read('prd/todo/OGVCS-020-git-lfs-importer.md'),
  ]);

  assert.match(manifest, /rust-version = "1\.82"/u);
  assert.match(manifest, /publish = false/u);
  assert.match(manifest, /ogvcs-object-model/u);
  assert.match(manifest, /ogvcs-path-contract/u);
  assert.doesNotMatch(manifest, /^\s*(?:flate2|git2|sha1|zlib)\s*=/imu);
  assert.doesNotMatch(`${source}\n${treeSource}`, /std::fs|std::net|std::process|TcpListener|UdpSocket|reqwest|git2|Command::new|AuthorizationContext|TransactionAuthorized|request[_-]?root/iu);
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
  assert.match(treeSource, /GIT_TREE_ALGORITHM_VERSION: &str = "ogvcs\.git-tree-frame\/strict@1"/u);
  assert.match(treeSource, /GIT_TREE_FRAME_BYTES_HARD_MAXIMUM: u64 = 1_048_576/u);
  assert.match(treeSource, /GIT_TREE_ENTRIES_HARD_MAXIMUM: u64 = 4_096/u);
  assert.match(treeSource, /GIT_TREE_NAME_BYTES_HARD_MAXIMUM: u64 = 4_096/u);
  assert.match(treeSource, /GIT_TREE_WORK_UNITS_HARD_MAXIMUM: u64 = 16_777_216/u);
  assert.match(treeSource, /GIT_TREE_RETAINED_BYTES_HARD_MAXIMUM: u64 = 2_097_152/u);
  assert.match(treeSource, /DUPLICATE_CANDIDATE_RETAINED_BYTES: u64 = 8/u);
  assert.match(treeSource, /PROTECTED_NAME_WORK_MULTIPLIER: u64 = 3/u);
  assert.match(treeSource, /REQUEST_COMMITMENT_WORK: u64 = 192/u);
  assert.match(treeSource, /PROJECTION_FIXED_WORK: u64 = 192/u);
  assert.match(treeSource, /bytes\.get\(\.\.4\) != Some\(&b"tree"\[\.\.\]\)/u);
  assert.match(treeSource, /scan_payload_shape[\s\S]*validate_payload_order[\s\S]*materialize_entries/u);
  assert.match(treeSource, /comparison\.same_name/u);
  assert.match(treeSource, /if left\.mode\.is_tree\(\)[\s\S]*b'\/'/u);
  assert.match(treeSource, /struct DuplicateCandidate[\s\S]*name_start: u32,[\s\S]*name_len: u32/u);
  assert.match(treeSource, /size_of::<DuplicateCandidate>\(\)[\s\S]*DUPLICATE_CANDIDATE_RETAINED_BYTES/u);
  assert.match(treeSource, /Vec<DuplicateCandidate> = Vec::with_capacity\(capacity\)/u);
  assert.match(treeSource, /track_nonconsecutive_duplicate/u);
  assert.match(treeSource, /budget\.check_cancel\(GitTreePhase::Order\)/u);
  assert.match(treeSource, /is_hfs_dotgit\(entry\.name\) \|\| is_ntfs_dotgit\(entry\.name\)/u);
  assert.match(treeSource, /NameGitMetadataAlias => "GIT_TREE_NAME_GIT_METADATA_ALIAS"/u);
  assert.match(treeSource, /order_work_bound[\s\S]*budget\.ensure_work[\s\S]*actual_order_work/u);
  assert.doesNotMatch(treeSource, /networkRoutes|networkRegistered|registerRoute|routeDispatcher/iu);
  assert.doesNotMatch(
    treeSource,
    /sha1::|\bflate2\b|\blibz\b|\bzlib\b|\bpackfile\b|<<<<<<<|>>>>>>>/iu,
  );
  assert.match(readme, /no\s+Git pack, compressed loose-object, zlib, or archive parser/iu);
  assert.match(readme, /not allocator or\s+RSS measurement/iu);
  assert.match(readme, /opaque caller claim/iu);
  assert.match(readme, /at or above 1024 bytes is\s+unconditionally `NotPointer`/iu);
  assert.match(readme, /uppercase and underscore word bytes\s+are valid/iu);
  assert.match(readme, /Generic short text such as\s+`version 1\.0`/iu);
  assert.match(readme, /Symlink target blobs are always `Ordinary`/iu);
  assert.match(readme, /does not attest correct attribute discovery/iu);
  assert.match(readme, /No OGVCS-020\s+acceptance criterion is satisfied or closed/iu);
  assert.match(review, /OGVCS-020-AC-01 through OGVCS-020-AC-07 remain open/u);
  assert.match(review, /No Git pack\/compressed-loose-object\/archive parser/u);
  assert.match(review, /git-scm\.com\/docs\/gitdatamodel\.html/u);
  assert.match(review, /github\.com\/git\/git\/blob\/master\/entry\.c/u);
  assert.match(review, /There is intentionally no derivation or authentication relationship/u);
  assert.match(treeReview, /Exact integration base:\*\* `9b2e4ce18b0d246ee5a84b946686e670a68a01fa`/u);
  assert.match(treeReview, /does \*\*not\*\* recompute a Git SHA-1 object ID/iu);
  assert.match(treeReview, /non-consecutive\s+file\/directory duplicate rule/iu);
  assert.match(treeReview, /HFS and NTFS `\.git` recognizers/iu);
  assert.match(treeReview, /three-entry counterexample|`foo`, `foo\.bar`, then tree `foo`/iu);
  assert.match(treeReview, /OGVCS-020 remains Todo; AC-01 through AC-07 remain open/u);
  assert.match(treeReview, /request-root authorization/iu);
  assert.equal(treeGolden.schemaVersion, 'ogvcs.git-tree-frame/private-golden/v1');
  assert.deepEqual(treeGolden.cases.map(({ objectFormat }) => objectFormat), ['sha1', 'sha256']);
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

test('packed source includes tests, golden vectors, docs, and no route declaration', async () => {
  const [manifest, packed, golden, treeGolden, readme] = await Promise.all([
    read('core/import-git-lfs/rust/Cargo.toml'),
    read('core/import-git-lfs/rust/scripts/test-packed.sh'),
    read('core/import-git-lfs/rust/tests/golden.json').then(JSON.parse),
    read('core/import-git-lfs/rust/tests/git-tree-golden.json').then(JSON.parse),
    read('core/import-git-lfs/rust/README.md'),
  ]);
  assert.match(manifest, /"tests\/\*\*"/u);
  assert.match(manifest, /"scripts\/\*\*"/u);
  assert.match(packed, /cargo package/u);
  assert.match(packed, /cargo test --locked --offline/u);
  assert.equal(golden.lfsContentSha256, '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03');
  assert.equal(treeGolden.cases.length, 2);
  assert.doesNotMatch(readme, /production-ready|hosted importer|public API/iu);
});
