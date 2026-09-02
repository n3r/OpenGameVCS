import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private OGVCS-043 validator remains pure, bounded, unwired, and unpublished', async () => {
  const sourceNames = await readdir(new URL('../client/cli-evidence/rust/src/', import.meta.url));
  assert.deepEqual(sourceNames.sort(), ['lib.rs', 'model.rs', 'transcript.rs', 'validate.rs']);
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
  assert.match(review, /based exactly on\s+`101d5673252290de362844f381b5176ad33c470d`/u);
  assert.match(review, /cannot satisfy any part of OGVCS-043-AC-01/u);
  assert.match(evidence, /not a clean-host run/iu);
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
  assert.match(prd, /no artifact was installed or published/u);
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

  assert.match(workflow, /^name: R1 CLI evidence validator$/mu);
  assert.match(workflow, /branches: \[main, r1-foundation-integration\]/u);
  assert.match(workflow, /client\/cli-evidence\/rust\/\*\*/u);
  assert.match(workflow, /tools\/cli-evidence-validator-policy\.test\.mjs/u);
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
