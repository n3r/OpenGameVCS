import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';

import {
  canonicalBytes,
  loadProtocolContract,
  MacReceiptCodec,
  NegotiationReceiptCodec,
  ProtocolBaselineError,
} from '../src/index.mjs';
import { RECEIPT_DOMAIN } from '../src/receipts.mjs';
import { protocolRoot } from './roots.mjs';

function claims(now = 100) {
  return {
    schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1',
    issuedAt: now,
    expiresAt: now + 50,
    subject: 'subject', tenant: 'tenant', repository: 'repository', authorityEpoch: 9,
    session: 'session', offerDigest: 'aa'.repeat(32), selectionDigest: 'bb'.repeat(32), registrySetSha256: 'cc'.repeat(32),
    clientNonce: 'client-nonce', serverNonce: 'server-nonce',
    selection: { protocol: 'ogvcs.control.https-json@1', schema: '1.0.0-rc.1' },
  };
}

const bindings = Object.freeze({
  subject: 'subject', tenant: 'tenant', repository: 'repository', authorityEpoch: 9,
  session: 'session', offerDigest: 'aa'.repeat(32), selectionDigest: 'bb'.repeat(32), registrySetSha256: 'cc'.repeat(32),
});

test('MAC receipt binds authenticated negotiation, identity, scope, epoch, session and expiry', () => {
  let now = 100;
  const codec = new MacReceiptCodec({ key: Buffer.alloc(32, 7), keyId: 'receipt-key', now: () => now, maxTtlMs: 100 });
  const token = codec.issue(claims(now));
  const verified = codec.verify(token, bindings);
  assert.equal(verified.selection.protocol, 'ogvcs.control.https-json@1');
  now = 151;
  assert.throws(() => codec.verify(token, bindings), (error) => error instanceof ProtocolBaselineError && error.code === 'PROTOCOL_STATE_CONFLICT');
});

test('tamper, downgrade, wrong subject, wrong repository and wrong key fail with one safe class', () => {
  const codec = new MacReceiptCodec({ key: Buffer.alloc(32, 1), keyId: 'receipt-key', now: () => 100 });
  const token = codec.issue(claims());
  const failures = [
    `${token.slice(0, -1)}A`,
    token.replace('nr1.receipt-key.', 'nr1.other-key.'),
  ];
  for (const supplied of failures) assert.throws(() => codec.verify(supplied, bindings), /invalid, stale, or foreign/u);
  for (const changed of [
    { ...bindings, subject: 'other' },
    { ...bindings, repository: 'other' },
    { ...bindings, selectionDigest: 'dd'.repeat(32) },
    { ...bindings, authorityEpoch: 10 },
  ]) assert.throws(() => codec.verify(token, changed), /invalid, stale, or foreign/u);

  const other = new MacReceiptCodec({ key: Buffer.alloc(32, 2), keyId: 'receipt-key', now: () => 100 });
  assert.throws(() => other.verify(token, bindings), /invalid, stale, or foreign/u);
});

test('receipt windows and keys are bounded before publication', () => {
  assert.throws(() => new MacReceiptCodec({ key: Buffer.alloc(16), keyId: 'key' }), /32 to 64/u);
  assert.throws(() => new MacReceiptCodec({ key: Buffer.alloc(32), keyId: 'key.with-dot' }), /key identifier/u);
  const codec = new MacReceiptCodec({ key: Buffer.alloc(32), keyId: 'key', now: () => 100, maxTtlMs: 10 });
  assert.throws(() => codec.issue({ ...claims(), expiresAt: 111 }), /validity window/u);
  const token = codec.issue({ ...claims(), expiresAt: 110 });
  assert.throws(() => codec.verify(token, {}), /expected bindings/u);
  assert.throws(() => codec.issue({ ...claims(), expiresAt: 110 }, { maxWorkingMemoryBytes: 1 }), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
  assert.throws(() => codec.verify(token, bindings, { maxWorkingMemoryBytes: 1 }), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
});

function selection(contract) {
  return contract.registries.compatibility.entries[0].selection;
}

test('structured receipt is schema-valid and binds selected registry tuple plus authenticated principal/session', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const now = 10_000;
  const codec = new NegotiationReceiptCodec({ contract, key: Buffer.alloc(32, 9), keyId: 'receipt-key@1', now: () => now });
  const structuredClaims = {
    schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1',
    selection: selection(contract),
    subjectDigest: '11'.repeat(32), tenantDigest: '22'.repeat(32), authorityEpoch: 3,
    sessionId: 'session-00000001', clientNonce: 'A'.repeat(22), serverNonce: Buffer.alloc(16, 1).toString('base64url'),
    issuedAtUnixMs: now, expiresAtUnixMs: now + 100,
  };
  const receipt = codec.issue(structuredClaims);
  assert.equal(receipt.algorithm, 'HMAC-SHA-256');
  assert.equal(receipt.mac.length, 43);
  const verified = codec.verify(receipt, {
    subjectDigest: structuredClaims.subjectDigest, tenantDigest: structuredClaims.tenantDigest,
    authorityEpoch: 3, sessionId: structuredClaims.sessionId, selection: structuredClaims.selection,
  });
  assert.equal(verified.selection.protocolVersion, 'ogvcs.control.https-json@1');
  assert.throws(() => codec.verify(receipt, { subjectDigest: '33'.repeat(32) }), /invalid, stale, or foreign/u);
  assert.throws(() => codec.verify({ ...receipt, mac: `${receipt.mac.slice(0, -1)}A` }, { subjectDigest: structuredClaims.subjectDigest }), /invalid, stale, or foreign/u);
});

test('structured receipts retain the registered dotted key identifier grammar', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const now = 10_000;
  const codec = new NegotiationReceiptCodec({ contract, key: Buffer.alloc(32, 9), keyId: 'receipt.key@1', now: () => now });
  const structuredClaims = {
    schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1',
    selection: selection(contract),
    subjectDigest: '11'.repeat(32), tenantDigest: '22'.repeat(32), authorityEpoch: 3,
    sessionId: 'session-00000001', clientNonce: 'A'.repeat(22), serverNonce: Buffer.alloc(16, 1).toString('base64url'),
    issuedAtUnixMs: now, expiresAtUnixMs: now + 100,
  };
  const receipt = codec.issue(structuredClaims);
  assert.equal(receipt.keyId, 'receipt.key@1');
  assert.equal(codec.verify(receipt, { subjectDigest: structuredClaims.subjectDigest }).subjectDigest, structuredClaims.subjectDigest);
});

test('structured receipt distinguishes expiry without disclosing foreign binding details', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const codec = new NegotiationReceiptCodec({ contract, key: Buffer.alloc(32, 4), keyId: 'receipt-key@1', now: () => 100 });
  const receipt = codec.issue({
    schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1', selection: selection(contract),
    subjectDigest: '11'.repeat(32), tenantDigest: '22'.repeat(32), authorityEpoch: 1,
    sessionId: 'session-00000001', clientNonce: 'A'.repeat(22), serverNonce: Buffer.alloc(16, 1).toString('base64url'), issuedAtUnixMs: 100, expiresAtUnixMs: 110,
  });
  assert.throws(
    () => codec.verify(receipt, { subjectDigest: '11'.repeat(32) }, { atUnixMs: 110 }),
    (error) => error.code === 'PROTOCOL_STATE_CONFLICT' && error.details.reason === 'expired',
  );
});

test('structured receipt codec enforces canonical 16 through 64 byte server nonces on issue and verify', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const now = 100;
  const key = Buffer.alloc(32, 5);
  const keyId = 'receipt-key@1';
  const codec = new NegotiationReceiptCodec({ contract, key, keyId, now: () => now });
  const base = {
    schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1', selection: selection(contract),
    subjectDigest: '11'.repeat(32), tenantDigest: '22'.repeat(32), authorityEpoch: 1,
    sessionId: 'session-00000001', clientNonce: 'A'.repeat(22),
    issuedAtUnixMs: now, expiresAtUnixMs: now + 10,
  };
  const nonce64 = Buffer.alloc(64, 7).toString('base64url');
  const receipt = codec.issue({ ...base, serverNonce: nonce64 });
  assert.equal(codec.verify(receipt, { subjectDigest: base.subjectDigest }).serverNonce, nonce64);
  assert.throws(
    () => codec.issue({ ...base, serverNonce: Buffer.alloc(65, 7).toString('base64url') }),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );

  const noncanonicalClaims = { ...base, serverNonce: 'B'.repeat(22) };
  const claimsBytes = canonicalBytes(noncanonicalClaims);
  const mac = createHmac('sha256', key)
    .update(RECEIPT_DOMAIN)
    .update(Buffer.from(keyId, 'ascii'))
    .update(Buffer.from([0]))
    .update(claimsBytes)
    .digest('base64url');
  assert.throws(
    () => codec.verify({ algorithm: 'HMAC-SHA-256', keyId, claims: noncanonicalClaims, mac }, { subjectDigest: base.subjectDigest }),
    /invalid, stale, or foreign/u,
  );
});
