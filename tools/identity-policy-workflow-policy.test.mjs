import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/identity-policy-audit.yml', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);
const modelUrl = new URL('../server/modules/identity-policy-audit/src/model.rs', import.meta.url);
const participantUrl = new URL('../server/modules/identity-policy-audit/src/participant.rs', import.meta.url);
const metadataUrl = new URL('../server/modules/repository-metadata/src/postgres.rs', import.meta.url);
const pageReviewUrl = new URL('../docs/reviews/OGVCS-009-transaction-authorized-page-boundary-review.md', import.meta.url);

test('identity-policy workflow is pinned, three-host, Node 24, and bounded', async () => {
  const [workflow, rootPackage] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(packageUrl, 'utf8').then(JSON.parse),
  ]);
  assert.match(workflow, /matrix:\s*\n\s*os: \[ubuntu-latest, macos-latest, windows-latest\]/u);
  assert.match(
    workflow,
    /push:\n    branches:\n      - main\n      - r1-foundation-integration\n      - "ogvcs-009\/\*\*"/u,
  );
  assert.match(workflow, /node-version: 24/u);
  assert.doesNotMatch(workflow, /node-version: (?:20|22)(?:\D|$)/u);
  assert.match(workflow, /actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1/u);
  assert.match(workflow, /actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7\.0\.0/u);
  assert.match(workflow, /npm run test:identity:spec/u);
  assert.match(workflow, /npm run test:identity/u);
  assert.match(workflow, /core\/paths-filesystem\/rust\/scripts\/sync-contract\.mjs --check/u);
  assert.match(workflow, /cargo test --manifest-path core\/paths-filesystem\/rust\/Cargo\.toml --locked --offline/u);
  assert.match(workflow, /cargo clippy --manifest-path core\/paths-filesystem\/rust\/Cargo\.toml --locked --offline --all-targets -- -D warnings/u);
  assert.match(workflow, /--test postgres_live -- --nocapture/u);
  assert.match(workflow, /--test aggregate_postgres_live -- --nocapture/u);
  assert.equal((workflow.match(/server\/modules\/identity-policy-audit\/scripts\/test-packed\.sh/gu) ?? []).length, 2);
  assert.match(workflow, /- "core\/paths-filesystem\/rust\/\*\*"/u);
  assert.doesNotMatch(workflow, /(?:test:scale|exact[-_: ]scale|100\s*(?:GiB|GB)|1\s*TiB|1,?000,?000)/iu);
  assert.doesNotMatch(workflow, /^\s*schedule:/mu);
  assert.match(rootPackage.scripts['test:identity'], /identity-policy-workflow-policy\.test\.mjs/u);
  assert.match(rootPackage.scripts['test:identity'], /core\/paths-filesystem\/rust\/scripts\/sync-contract\.mjs --check/u);
  assert.match(rootPackage.scripts['test:identity:rust'], /cargo \+1\.82\.0 test/u);
  assert.match(rootPackage.scripts['test:identity:rust'], /server\/modules\/identity-policy-audit\/scripts\/test-packed\.sh/u);
  assert.match(rootPackage.scripts['test:identity:postgres'], /--test postgres_live -- --nocapture/u);
  assert.match(rootPackage.scripts['test:identity:postgres'], /--test aggregate_postgres_live -- --nocapture/u);
});

test('transaction-authorized page source is bounded, opaque, fully scanned, and unwired', async () => {
  const [workflow, model, participant, metadata, review] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(modelUrl, 'utf8'),
    readFile(participantUrl, 'utf8'),
    readFile(metadataUrl, 'utf8'),
    readFile(pageReviewUrl, 'utf8'),
  ]);
  assert.match(model, /pub const MAXIMUM_AUTHORIZATION_PAGE_CANDIDATES: usize = 100_000;/u);
  assert.match(model, /pub const MAXIMUM_AUTHORIZED_PAGE_RESULTS: usize = 1_000;/u);
  assert.match(model, /#\[derive\(Clone, Eq, PartialEq\)\]\s*pub struct TransactionAuthorizedPage/u);
  assert.doesNotMatch(model, /impl (?:serde::)?Serialize for TransactionAuthorizedPage/u);
  assert.match(model, /pub\(crate\) fn transaction_id\(&self\) -> &str/u);
  assert.match(model, /pub\(crate\) fn authorized_ordinals\(&self\) -> &\[u32\]/u);
  assert.doesNotMatch(model, /\n\s*pub fn authorized_ordinals\(&self\)/u);
  assert.doesNotMatch(model, /\n\s*pub fn (?:query_context|candidate_set|authorized_ordinals)_digest\(&self\)/u);
  assert.match(model, /pub fn authorized_items\(/u);
  assert.match(participant, /for \(index, candidate\) in candidates\.iter\(\)\.enumerate\(\)/u);
  assert.match(participant, /Err\(error\) if error\.code\(\) == ParticipantErrorCode::AuthenticationDenied => \{\}/u);
  assert.match(participant, /fn hmac_sha256\(key: &\[u8; 32\], message: &\[u8\]\)/u);
  assert.match(participant, /view: NeutralAuthorizedView<'a>/u);
  assert.match(participant, /backend_pid: i32,\s*transaction_xid: i64,/u);
  assert.match(participant, /fn verify_authorized_page<'transaction, 'page>/u);
  assert.match(participant, /transaction: &'transaction mut Transaction<'_>/u);
  assert.match(participant, /self\.revalidate_view\(transaction, view\)\?;/u);
  assert.match(model, /transaction_borrow: PhantomData<&'transaction mut \(\)>/u);
  assert.match(model, /pub fn authorized_items\(\s*&self,\s*\) -> impl Iterator<Item = \(u32, &TransactionAuthorizationPageCandidate\)> \+ '_/u);
  assert.doesNotMatch(metadata, /\.authorize_page\(/u);
  assert.match(workflow, /docs\/reviews\/OGVCS-009-transaction-authorized-page-boundary-review\.md/u);
  for (const boundary of [
    'semantic query digest is metadata-owner supplied',
    'not yet bound to an OGVCS-041 negotiation session',
    '`sessionId` is still not linked to credential presentation',
    'No cursor or repository-metadata dispatcher calls the primitive',
    'all six acceptance criteria remain',
    'timing and non-disclosure acceptance',
    'witness retains the mutable transaction borrow',
    'item references reborrow',
  ]) assert.ok(review.includes(boundary), `authorized-page review missing boundary: ${boundary}`);
});
