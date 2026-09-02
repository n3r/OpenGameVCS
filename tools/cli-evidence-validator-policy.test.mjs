import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import { verifyRetainedSourceFiles } from './retained-source-evidence.mjs';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private OGVCS-043 validator remains pure, bounded, unwired, and unpublished', async () => {
  const sourceNames = await readdir(new URL('../client/cli-evidence/rust/src/', import.meta.url));
  assert.deepEqual(sourceNames.sort(), [
    'lib.rs',
    'model.rs',
    'starter_preflight.rs',
    'transcript.rs',
    'validate.rs',
  ]);
  const [cargo, ...sources] = await Promise.all([
    read('client/cli-evidence/rust/Cargo.toml'),
    ...sourceNames.map((name) => read(`client/cli-evidence/rust/src/${name}`)),
  ]);
  const source = sources.join('\n');

  assert.match(cargo, /name = "ogvcs-cli-evidence-validator"/u);
  assert.match(cargo, /rust-version = "1\.82"/u);
  assert.match(cargo, /publish = false/u);
  assert.doesNotMatch(cargo, /docs\.rs/u);
  assert.match(cargo, /ogvcs-object-model/u);
  assert.match(cargo, /ogvcs-deployment-preflight/u);
  assert.doesNotMatch(cargo, /tokio|reqwest|serde|sqlx|axum|tonic|clap/iu);
  assert.match(source, /pub const COMPONENT_COUNT: usize = 8/u);
  assert.match(source, /pub const STEP_COUNT: usize = 16/u);
  assert.match(source, /pub const MAX_WORK_UNITS: u64 = 320/u);
  assert.match(source, /ObjectKind::Snapshot/u);
  assert.match(source, /PrivateFallbackForbidden/u);
  assert.match(source, /NotRunAfterSafeStop/u);
  assert.match(source, /OpenGameVCS R1 CLI evidence report\\0v1\\0/u);
  assert.match(source, /check_cancelled\(cancellation\)\?;/u);
  assert.doesNotMatch(
    source,
    /std::(?:fs|net|process)|tokio|reqwest|Command::|File::|OpenOptions|TcpStream|UdpSocket/iu,
  );
  assert.doesNotMatch(source, /\b(?:Vec|Box)\s*<|\bString\b/u);
  assert.doesNotMatch(source, /(?:HashMap|HashSet|BTreeMap|BTreeSet)/u);
  assert.match(source, /SkippedStepEvidenceInvalid/u);
  assert.match(source, /const fn recovery_allowed_for_phase/u);
  assert.match(source, /pub executed_steps: u64/u);
  assert.match(source, /Commitment\(\[REDACTED\]\)/u);
  assert.ok([...source.matchAll(/check_cancelled\(cancellation\)\?;/gu)].length >= 5);
});

test('starter deployment projection calls the bounded predecessor without creating evidence', async () => {
  const [cargo, source, packed] = await Promise.all([
    read('client/cli-evidence/rust/Cargo.toml'),
    read('client/cli-evidence/rust/src/starter_preflight.rs'),
    read('client/cli-evidence/rust/scripts/test-packed.sh'),
  ]);

  assert.match(cargo, /version = "0\.1\.0-rc\.2"/u);
  assert.match(cargo, /ogvcs-deployment-preflight = \{[^\n]+version = "0\.1\.0-rc\.3"/u);
  assert.match(source, /build_deployment_preflight\(/u);
  assert.match(source, /PreflightControl::with_cancellation\(cancellation\)/u);
  assert.match(source, /report\.has_valid_binding\(\)/u);
  assert.match(source, /!report\.live \|\| !report\.ready \|\| !report\.reasons\.is_empty\(\)/u);
  assert.match(source, /STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS: u64 = 12/u);
  assert.match(source, /STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES: u64 = 512/u);
  assert.match(source, /assert!\(PREFLIGHT_VERSION == 2\)/u);
  assert.match(source, /OpenGameVCS R1 CLI starter deployment preflight request\\0v1\\0/u);
  assert.match(source, /OpenGameVCS R1 CLI starter deployment composition\\0v1\\0/u);
  assert.match(source, /bindings", &"<redacted>"/u);
  assert.match(source, /CompositionCancellationStage::ProjectionFinalized/u);
  const projectionBody = source.match(
    /pub struct StarterDeploymentPreflightProjection \{(?<body>[\s\S]*?)\n\}/u,
  )?.groups?.body;
  assert.ok(projectionBody);
  const projectionFields = [
    ['version', 'u16'],
    ['deployment_commitment', 'Commitment'],
    ['artifact_set_commitment', 'Commitment'],
    ['compatibility_set_commitment', 'Commitment'],
    ['configuration_generation_commitment', 'Commitment'],
    ['configuration_digest', 'Commitment'],
    ['observation_digest', 'Commitment'],
    ['request_commitment', 'Commitment'],
    ['result_commitment', 'Commitment'],
    ['observation_captured_at_unix_seconds', 'u64'],
    ['evaluated_at_unix_seconds', 'u64'],
    ['maximum_observation_age_seconds', 'u64'],
    ['predecessor_work_units', 'u64'],
    ['predecessor_retained_bytes', 'u64'],
    ['total_work_units', 'u64'],
    ['peak_retained_bytes', 'u64'],
    ['projection_digest', 'Commitment'],
  ];
  const declaredFields = projectionBody.trim().split('\n').map((line) => {
    const match = /^(?<visibility>pub(?:\([^)]*\))?\s+)?(?<name>[a-z_]+): (?<type>[A-Za-z0-9_:<>]+),$/u
      .exec(line.trim());
    assert.ok(match, `unexpected projection field declaration: ${line}`);
    assert.equal(match.groups.visibility, undefined, `${match.groups.name} must remain private`);
    return [match.groups.name, match.groups.type];
  });
  assert.deepEqual(declaredFields, projectionFields);

  const projectionImpl = source.match(
    /impl StarterDeploymentPreflightProjection \{(?<body>[\s\S]*?)\n\}/u,
  )?.groups?.body;
  assert.ok(projectionImpl);
  const publicMethods = projectionImpl.split('\n')
    .filter((line) => /^\s*pub\b/u.test(line))
    .map((line) => {
      const match = /^\s*pub const fn (?<name>[a-z_]+)\(&self\) -> (?<type>u16|u64|Commitment) \{$/u
        .exec(line);
      assert.ok(match, `unexpected public projection API: ${line}`);
      return [match.groups.name, match.groups.type];
    });
  assert.deepEqual(publicMethods, projectionFields);
  const projectionImplHeaders = [...source.matchAll(/^impl (?<header>[^\n{]+) \{$/gmu)]
    .map((match) => match.groups.header)
    .filter((header) => header.includes('StarterDeploymentPreflightProjection'));
  assert.deepEqual(projectionImplHeaders, [
    'StarterDeploymentPreflightProjection',
    'fmt::Debug for StarterDeploymentPreflightProjection',
  ]);
  assert.equal(
    [...source.matchAll(/impl StarterDeploymentPreflightProjection \{/gu)].length,
    1,
  );
  assert.match(source, /#\[derive\(Clone, Copy, Eq, PartialEq\)\]\s+pub struct StarterDeploymentPreflightProjection/u);
  assert.match(
    source,
    /```compile_fail,E0451[\s\S]*StarterDeploymentPreflightProjection \{[\s\S]*projection_digest: Commitment\(\[0; 32\]\),[\s\S]*\.\.trusted[\s\S]*```/u,
  );
  assert.doesNotMatch(source, /impl (?:Default|DerefMut|AsMut(?:<[^>]+>)?) for StarterDeploymentPreflightProjection/u);
  assert.doesNotMatch(source, /DeploymentPreflightReport/u);
  assert.doesNotMatch(source, /CompatibilityEvidence|StepEvidence|ContractRoute|ArtifactVerification/u);
  assert.doesNotMatch(
    source,
    /std::(?:fs|net|process)|tokio|reqwest|Command::|File::|OpenOptions|TcpStream|UdpSocket/iu,
  );
  assert.match(packed, /ogvcs-deployment-preflight-0\.1\.0-rc\.3\.crate/u);
  assert.match(packed, /ogvcs-cli-evidence-validator-0\.1\.0-rc\.2\.crate/u);
  assert.match(packed, /patch\.crates-io\.ogvcs-deployment-preflight\.path/u);
});

test('documentation and package hooks preserve the exact open PRD boundary', async () => {
  const [readme, review, evidence, packageValue, prd] = await Promise.all([
    read('client/cli-evidence/rust/README.md'),
    read('docs/reviews/OGVCS-043-cli-evidence-validator-boundary-review.md'),
    read('docs/evidence/OGVCS-043/README.md'),
    read('package.json').then(JSON.parse),
    read('prd/todo/OGVCS-043-r1-cli-vertical-slice.md'),
  ]);

  assert.match(readme, /unpublished Rust 1\.82 library/u);
  assert.match(readme, /does not run the\s+native CLI/u);
  assert.match(readme, /does not prove their truth/u);
  assert.match(readme, /canonical zero request\/result/u);
  assert.match(readme, /Recovery phase matrix/u);
  assert.match(readme, /All other phase\/recovery pairs fail/u);
  assert.match(readme, /immediately before report release/u);
  assert.match(readme, /AC-01 through AC-05\s+remain open/u);
  assert.match(readme, /StarterDeploymentPreflightProjection/u);
  assert.match(readme, /private fields/u);
  assert.match(readme, /compile-fail/u);
  assert.match(readme, /does not create a compatibility record or\s+scenario step/u);
  assert.match(review, /based exactly on\s+`101d5673252290de362844f381b5176ad33c470d`/u);
  assert.match(
    review,
    /- \*\*Route-less projection base:\*\* exact integration\s+`8b6c55259bfad367e4d9c67598f561d957f19d35`/u,
  );
  assert.match(
    review,
    /route-less projection candidate based on exact integration parent\s+`8b6c55259bfad367e4d9c67598f561d957f19d35`/u,
  );
  assert.doesNotMatch(review, /9b2e4ce18b0d246ee5a84b946686e670a68a01fa/u);
  assert.match(review, /private fields/u);
  assert.match(review, /compile-fail/u);
  assert.match(review, /cannot satisfy any part of OGVCS-043-AC-01/u);
  assert.match(review, /route-less starter-deployment preflight projection/iu);
  assert.match(evidence, /not a clean-host installed-CLI run/iu);
  assert.match(
    evidence,
    /later private rc\.2 candidate, based on exact integration parent\s+`8b6c55259bfad367e4d9c67598f561d957f19d35`/u,
  );
  assert.doesNotMatch(evidence, /9b2e4ce18b0d246ee5a84b946686e670a68a01fa/u);
  assert.match(evidence, /private fields/u);
  assert.match(evidence, /compile-fail/u);
  assert.match(
    evidence,
    /Follow-on push run \[33664922248\]\(https:\/\/github\.com\/n3r\/OpenGameVCS\/actions\/runs\/33664922248\)/u,
  );
  assert.match(evidence, /exact revision `fa61786b272a019b82f4e96eaaa47dbef60c5b6c`/u);
  assert.match(
    evidence,
    /hosted-source-run-33664922248\.json[\s\S]{0,180}binds all three job identities and the exact workflow\/crate source, package,\s+and test bytes/u,
  );
  assert.match(
    evidence,
    /creation time and displayed duration[\s\S]{0,160}completion time is their sum rather than an API-returned timestamp/u,
  );
  assert.match(
    evidence,
    /public XHR\s+matrix fragments supplied the job identities, conclusions, and roadmap-step\s+dispositions/u,
  );
  assert.match(
    evidence,
    /This follow-on is exact-revision source portability only;[\s\S]{0,180}OGVCS-043 remains\s+\*\*Todo\*\*, and AC-01 through AC-05 remain open\./u,
  );
  assert.equal(
    packageValue.scripts['test:cli-evidence'],
    'node --test tools/cli-evidence-validator-policy.test.mjs',
  );
  assert.match(packageValue.scripts.test, /npm run test:cli-evidence/u);
  assert.match(packageValue.scripts['test:cli-evidence:rust'], /cargo \+1\.82\.0/u);

  const acceptanceStart = prd.indexOf('## Acceptance criteria');
  const verificationStart = prd.indexOf('## Verification plan');
  assert.ok(acceptanceStart >= 0 && verificationStart > acceptanceStart);
  const acceptance = prd.slice(acceptanceStart, verificationStart);
  const digest = createHash('sha256').update(acceptance).digest('hex');
  assert.equal(digest, '285256a0ad5afe001af90fd0c90324a348f2228ef7531e10d4e2a2652ddb4b5e');
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
  assert.match(prd, /^\*\*Last updated:\*\* 2026-09-02$/mu);
  assert.match(prd, /private, unpublished Rust 1\.82/u);
  assert.match(prd, /no\s+artifact was installed or published/iu);
  assert.match(prd, /OGVCS-043-AC-01 through OGVCS-043-AC-05 all remain open/u);
  const acceptanceIds = [...acceptance.matchAll(/\*\*(OGVCS-043-AC-\d{2}):\*\*/gu)]
    .map((match) => match[1]);
  assert.deepEqual(acceptanceIds, [
    'OGVCS-043-AC-01',
    'OGVCS-043-AC-02',
    'OGVCS-043-AC-03',
    'OGVCS-043-AC-04',
    'OGVCS-043-AC-05',
  ]);
});

test('crate package boundary contains only its offline validator sources', async () => {
  const cargo = await read('client/cli-evidence/rust/Cargo.toml');
  assert.match(cargo, /"src\/\*\*"/u);
  assert.match(cargo, /"scripts\/\*\*"/u);
  assert.match(cargo, /"tests\/\*\*"/u);
  assert.doesNotMatch(cargo, /server\/|native-cli|spec\/|\.github/u);
});

test('path-scoped hosted regression keeps the private source gate pinned', async () => {
  const workflow = await read('.github/workflows/cli-evidence-validator.yml');
  const watchedPaths = [
    '.github/workflows/cli-evidence-validator.yml',
    'client/cli-evidence/rust/**',
    'core/deployment-preflight/rust/**',
    'core/object-model/rust/**',
    'docs/evidence/OGVCS-043/**',
    'docs/reviews/OGVCS-043-cli-evidence-validator-boundary-review.md',
    'prd/todo/OGVCS-043-r1-cli-vertical-slice.md',
    'tools/cli-evidence-validator-policy.test.mjs',
    'tools/retained-source-evidence.mjs',
    'package.json',
    'package-lock.json',
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

  assert.match(workflow, /^name: R1 CLI evidence validator$/mu);
  assert.deepEqual(decodePaths(pullRequest), watchedPaths);
  assert.deepEqual(decodePaths(push), watchedPaths);
  assert.match(workflow, /  workflow_dispatch:\n\npermissions:/u);
  assert.doesNotMatch(workflow, /fetch-depth:\s*0/u);
  assert.equal([...workflow.matchAll(/persist-credentials:\s*false/gu)].length, 1);
  assert.doesNotMatch(workflow, /persist-credentials:\s*true/u);
  const retainedFetches = [
    'git fetch --no-tags --depth=1 origin c7049fd5063adaf40f6ad2f694104713966ed6c6',
    'git fetch --no-tags --depth=1 origin fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
  ];
  assert.equal([...workflow.matchAll(/git fetch\b/gu)].length, retainedFetches.length);
  for (const retainedFetch of retainedFetches) {
    assert.equal(workflow.split(retainedFetch).length - 1, 1);
  }
  assert.match(
    workflow,
    /- uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1\s+with:\s+persist-credentials: false/u,
  );
  const checkoutIndex = workflow.indexOf('actions/checkout@');
  const credentialIndex = workflow.indexOf('persist-credentials: false');
  const retainedFetchIndexes = retainedFetches.map((command) => workflow.indexOf(command));
  const policyIndex = workflow.indexOf('node --test tools/cli-evidence-validator-policy.test.mjs');
  assert.ok(checkoutIndex < credentialIndex);
  assert.ok(credentialIndex < retainedFetchIndexes[0]);
  assert.ok(retainedFetchIndexes[0] < retainedFetchIndexes[1]);
  assert.ok(retainedFetchIndexes[1] < policyIndex);
  assert.match(workflow, /tools\/cli-evidence-validator-policy\.test\.mjs/u);
  assert.match(workflow, /tools\/retained-source-evidence\.mjs/u);
  assert.match(workflow, /permissions:\s+contents: read/u);
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /# 1\.82\.0/u);
  assert.match(workflow, /ubuntu-latest/u);
  assert.match(workflow, /macos-latest/u);
  assert.match(workflow, /windows-latest/u);
  assert.match(workflow, /cargo fmt --manifest-path client\/cli-evidence\/rust\/Cargo\.toml/u);
  assert.match(workflow, /cargo test --manifest-path client\/cli-evidence\/rust\/Cargo\.toml --locked --release/u);
  assert.match(workflow, /cargo clippy --manifest-path client\/cli-evidence\/rust\/Cargo\.toml --locked --all-targets -- -D warnings/u);
  assert.match(workflow, /working-directory: client\/cli-evidence\/rust/u);
  assert.match(workflow, /node prd\/validate-roadmap\.mjs/u);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/u);
  assert.match(workflow, /actions\/setup-node@[0-9a-f]{40}/u);
  assert.match(workflow, /dtolnay\/rust-toolchain@[0-9a-f]{40}/u);
});

test('retained hosted result is exact and bounded to private source portability', async () => {
  const [historicalEvidence, evidence] = await Promise.all([
    read('docs/evidence/OGVCS-043/hosted-source-run-33629145724.json').then(JSON.parse),
    read('docs/evidence/OGVCS-043/hosted-source-run-33664922248.json').then(JSON.parse),
  ]);

  assert.equal(historicalEvidence.schemaVersion, 'ogvcs.cli-evidence/hosted-source-run/v1');
  assert.deepEqual(historicalEvidence.run, {
    id: 33629145724,
    event: 'push',
    branch: 'r1-foundation-integration',
    headSha: 'c7049fd5063adaf40f6ad2f694104713966ed6c6',
    status: 'completed',
    conclusion: 'success',
    createdAt: '2026-09-02T12:17:55Z',
    completedAt: '2026-09-02T12:20:45Z',
    url: 'https://github.com/n3r/OpenGameVCS/actions/runs/33629145724',
  });
  assert.deepEqual(
    historicalEvidence.jobs.map(({ id, name, conclusion }) => ({ id, name, conclusion })),
    [
      {
        id: 100243980763,
        name: 'Private source regression (Linux)',
        conclusion: 'success',
      },
      {
        id: 100243981138,
        name: 'Private source regression (Windows)',
        conclusion: 'success',
      },
      {
        id: 100243981173,
        name: 'Private source regression (macOS)',
        conclusion: 'success',
      },
    ],
  );
  assert.deepEqual(historicalEvidence.claimBoundary, {
    privateSourcePortabilityOnly: true,
    installedCli: false,
    cleanHost: false,
    authenticatedJourney: false,
    acceptanceCriterion: false,
    releaseEvidence: false,
  });
  await verifyRetainedSourceFiles({
    root,
    evidence: historicalEvidence,
    revision: 'c7049fd5063adaf40f6ad2f694104713966ed6c6',
    paths: [
      '.github/workflows/cli-evidence-validator.yml',
      'client/cli-evidence/rust/Cargo.lock',
      'client/cli-evidence/rust/Cargo.toml',
      'client/cli-evidence/rust/README.md',
      'client/cli-evidence/rust/scripts/test-packed.sh',
      'client/cli-evidence/rust/src/lib.rs',
      'client/cli-evidence/rust/src/model.rs',
      'client/cli-evidence/rust/src/transcript.rs',
      'client/cli-evidence/rust/src/validate.rs',
      'client/cli-evidence/rust/tests/validator.rs',
    ],
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
  assert.equal(evidence.schemaVersion, 'ogvcs.cli-evidence/hosted-source-run/v1');
  assert.deepEqual(evidence.run, {
    id: 33664922248,
    event: 'push',
    branch: 'r1-foundation-integration',
    headSha: 'fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
    status: 'completed',
    conclusion: 'success',
    createdAt: '2026-09-02T18:03:59Z',
    completedAt: '2026-09-02T18:06:30Z',
    url: 'https://github.com/n3r/OpenGameVCS/actions/runs/33664922248',
  });
  assert.deepEqual(evidence.evidenceCollection, {
    runAndDurationSource: 'public GitHub Actions HTML',
    jobSource: 'public GitHub Actions XHR matrix',
    completedAtDerivation: 'createdAt plus the displayed total duration',
    completedAtIsInferred: true,
    apiUnavailableReason: 'unauthenticated public API quota exhausted',
  });
  assert.deepEqual(evidence.jobs, [
    {
      id: 100364184772,
      name: 'Private source regression (Linux)',
      conclusion: 'success',
      roadmapStep: 'success',
    },
    {
      id: 100364184894,
      name: 'Private source regression (macOS)',
      conclusion: 'success',
      roadmapStep: 'skipped',
    },
    {
      id: 100364184914,
      name: 'Private source regression (Windows)',
      conclusion: 'success',
      roadmapStep: 'skipped',
    },
  ]);
  assert.deepEqual(evidence.successfulStepsOnEveryHost, [
    'Node source/package/PRD/workflow policy',
    'Rust format check',
    'Rust debug tests',
    'Rust release tests',
    'Rust warnings-denied Clippy',
    'freshly extracted package tests',
  ]);
  assert.deepEqual(evidence.claimBoundary, historicalEvidence.claimBoundary);
  await verifyRetainedSourceFiles({
    root,
    evidence,
    revision: 'fa61786b272a019b82f4e96eaaa47dbef60c5b6c',
    paths: [
      '.github/workflows/cli-evidence-validator.yml',
      'client/cli-evidence/rust/Cargo.lock',
      'client/cli-evidence/rust/Cargo.toml',
      'client/cli-evidence/rust/LICENSE',
      'client/cli-evidence/rust/README.md',
      'client/cli-evidence/rust/scripts/test-packed.sh',
      'client/cli-evidence/rust/src/lib.rs',
      'client/cli-evidence/rust/src/model.rs',
      'client/cli-evidence/rust/src/starter_preflight.rs',
      'client/cli-evidence/rust/src/transcript.rs',
      'client/cli-evidence/rust/src/validate.rs',
      'client/cli-evidence/rust/tests/starter_preflight.rs',
      'client/cli-evidence/rust/tests/validator.rs',
    ],
  });
});
