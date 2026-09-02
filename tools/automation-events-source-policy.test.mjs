import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private automation event candidate is bounded, cryptographic, and unwired', async () => {
  const [cargo, source, packageValue] = await Promise.all([
    read('core/automation-events/rust/Cargo.toml'),
    read('core/automation-events/rust/src/lib.rs'),
    read('package.json').then(JSON.parse),
  ]);

  assert.match(cargo, /name = "ogvcs-automation-events"/u);
  assert.match(cargo, /rust-version = "1\.82"/u);
  assert.match(cargo, /publish = false/u);
  assert.match(cargo, /^hmac = "=0\.12\.1"$/mu);
  assert.match(cargo, /^sha2 = "=0\.10\.9"$/mu);
  assert.match(cargo, /^ogvcs-object-model = \{ path = "\.\.\/\.\.\/object-model\/rust", version = "0\.1\.0" \}$/mu);
  assert.doesNotMatch(cargo, /tokio|reqwest|axum|sqlx|postgres|aws-sdk|aws_sdk/iu);

  for (const [constant, value] of [
    ['EVENT_PAYLOAD_BYTES_HARD_MAXIMUM', '262_144'],
    ['REPLAY_PAGE_EVENTS_HARD_MAXIMUM', '1_024'],
    ['CURSOR_KEYS_HARD_MAXIMUM', '4'],
    ['CURSOR_TTL_MS_HARD_MAXIMUM', '604_800_000'],
    ['WEBHOOK_KEYS_HARD_MAXIMUM', '4'],
    ['WEBHOOK_BODY_BYTES_HARD_MAXIMUM', '1_048_576'],
    ['WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM', '300_000'],
    ['REPLAY_GUARD_ENTRIES_HARD_MAXIMUM', '8_192'],
    ['REPLAY_GUARD_RETENTION_MS_HARD_MAXIMUM', '86_400_000'],
    ['EVENT_SEQUENCE_HARD_MAXIMUM', 'u64::MAX - 1'],
  ]) {
    assert.match(source, new RegExp(`pub const ${constant}: [^=]+ = ${value};`, 'u'));
  }
  assert.match(source, /#!\[forbid\(unsafe_code\)\]/u);
  assert.match(source, /ObjectKind::Snapshot/u);
  assert.match(source, /HmacSha256/u);
  assert.match(source, /struct CursorSigningKey/u);
  assert.match(source, /struct WebhookSigningKey/u);
  assert.doesNotMatch(
    source,
    /#\[derive\([^\]]*(?:Clone|Copy|Debug)[^\]]*\)\]\s*pub struct (?:CursorSigningKey|WebhookSigningKey)/u,
  );
  assert.match(source, /cursor-signing-key-absent/u);
  assert.match(source, /pub authority_epoch: u64/u);
  assert.match(source, /pub high_watermark_at_issue: u64/u);
  assert.match(source, /cursor-authority-state/u);
  assert.match(source, /replay-page-cardinality/u);
  assert.match(source, /event\.draft\.commit\.acknowledged_at_unix_ms > request\.now_unix_ms/u);
  assert.match(source, /ReplayDisposition::Duplicate/u);
  assert.match(source, /AutomationErrorCode::ReplayConflict/u);
  assert.match(source, /replay-guard-retention-window/u);
  assert.match(source, /field\("draft", &"<redacted>"\)/u);
  assert.match(source, /field\("provenance_digest", &"<redacted>"\)/u);
  assert.match(source, /4de2f6|0x4d, 0xe2, 0xf6/u);
  assert.doesNotMatch(source, /std::fs|std::net|TcpStream|UdpSocket|tokio|reqwest|axum|sqlx/iu);
  assert.doesNotMatch(source, /pub fn (?:authorize|submit|restore|delete|materialize|publish|register_webhook|dead_letter)/iu);

  assert.equal(packageValue.scripts['test:automation'], 'node --test tools/automation-events-source-policy.test.mjs');
  assert.match(packageValue.scripts.test, /npm run test:automation/u);
});

test('automation documentation preserves supplied-fact and Todo boundaries', async () => {
  const [readme, review, prd] = await Promise.all([
    read('core/automation-events/rust/README.md'),
    read('docs/reviews/OGVCS-019-automation-events-boundary-review.md'),
    read('prd/todo/OGVCS-019-automation-events-ci-client.md'),
  ]);
  for (const text of [readme, review]) {
    assert.match(text, /private/iu);
    assert.match(text, /unwired/iu);
    assert.match(text, /supplied/iu);
    assert.match(text, /does not prove|cannot prove/iu);
    assert.match(text, /OGVCS-019 remains Todo/u);
    assert.match(text, /no acceptance criterion is closed/iu);
    assert.match(text, /hosted/iu);
  }
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
  assert.match(prd, /bounded private candidate relevance only/iu);
  assert.match(prd, /No acceptance\s+criterion is closed/iu);
});

test('ordinary automation gate contains no route, deployment, or scale campaign', async () => {
  const packageValue = JSON.parse(await read('package.json'));
  assert.doesNotMatch(
    packageValue.scripts['test:automation'],
    /workflow_dispatch|server|route|deploy|million|100 ?GiB/iu,
  );
});
