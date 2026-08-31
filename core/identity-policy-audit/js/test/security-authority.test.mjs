import assert from 'node:assert/strict';
import test from 'node:test';

import { SecurityMutationAuthority } from '../src/index.mjs';
import { MemorySecurityMutationStore } from '../src/testing.mjs';
import { assertVectorOutcome } from './vector-outcome.mjs';

function fixture() {
  const store = new MemorySecurityMutationStore();
  store.initializeAuthority('studio', { authorityEpoch: 4, keyGeneration: 7, policyGeneration: 9 });
  store.putCredential('studio', { id: 'credential.artist', generation: 3, credentialClass: 'session', state: 'active' });
  const authority = new SecurityMutationAuthority({
    store,
    clock: () => 1_800_000_000,
    authorizer: {
      authorizeSecurityMutation({ request }) {
        return {
          allowed: true, actorClass: 'administrator', actorPseudonym: `pseudonym:${'cd'.repeat(16)}`,
          correlationId: request.revocationId ?? request.promotionId, decisionDigest: 'ab'.repeat(32),
          tenant: request.tenant, repository: request.repository, permission: 'policy.administer',
        };
      },
    },
  });
  return { store, authority };
}

test('credential revocation is bounded, audited, idempotent, and non-enumerating', () => {
  const { store, authority } = fixture();
  const input = { revocationId: 'revoke.artist.1', tenant: 'studio', repository: 'game', credentialId: 'credential.artist', reason: 'device reported stolen' };
  const receipt = authority.revokeCredential(input);
  assert.equal(receipt.credentialGeneration, 3); assert.equal(receipt.authorityEpoch, 4);
  assert.equal(receipt.maximumAuthorizingUntil - receipt.effectiveAt, 5);
  assert.deepEqual(authority.revokeCredential(input), receipt);
  const unknown = authority.revokeCredential({ ...input, revocationId: 'revoke.unknown.1', credentialId: 'credential.unknown' });
  assert.deepEqual(Object.keys(unknown).sort(), Object.keys(receipt).sort());
  assert.equal(store.auditLedger().verify('studio').records, 2);
  assertVectorOutcome('revocation-receipt-bounded', 'revoked', 'revoked');
});

test('authority promotion atomically advances epoch and key generation with one audit event', () => {
  const { store, authority } = fixture();
  const receipt = authority.promote({
    promotionId: 'promotion.region-b.5', tenant: 'studio', repository: 'game',
    authorityEpoch: 5, keyGeneration: 8, reason: 'verified disaster recovery promotion',
    recoveryBoundaryDigest: '12'.repeat(32),
  });
  assert.equal(receipt.previousAuthorityEpoch, 4); assert.equal(receipt.authorityEpoch, 5);
  assert.deepEqual(store.authority('studio'), { authorityEpoch: 5, keyGeneration: 8, policyGeneration: 9 });
  assert.equal(store.auditLedger().verify('studio').records, 1);
  assert.throws(() => authority.promote({
    promotionId: 'promotion.replay', tenant: 'studio', repository: 'game', authorityEpoch: 5, keyGeneration: 8,
    reason: 'stale replay', recoveryBoundaryDigest: '12'.repeat(32),
  }), ({ code }) => code === 'STATE_CONFLICT');
});

test('security mutation authorization cannot substitute tenant or permission', () => {
  const store = new MemorySecurityMutationStore();
  store.initializeAuthority('studio', { authorityEpoch: 1, keyGeneration: 1, policyGeneration: 1 });
  const authority = new SecurityMutationAuthority({
    store,
    authorizer: { authorizeSecurityMutation: () => ({
      allowed: true, actorClass: 'administrator', actorPseudonym: `pseudonym:${'cd'.repeat(16)}`,
      correlationId: 'hostile', decisionDigest: 'ab'.repeat(32), tenant: 'other', repository: 'game', permission: 'policy.administer',
    }) },
  });
  assert.throws(() => authority.revokeCredential({
    revocationId: 'revoke.hostile', tenant: 'studio', repository: 'game', credentialId: 'credential.missing', reason: 'test denial',
  }), ({ code }) => code === 'AUTHENTICATION_DENIED');
  assert.equal(store.auditLedger().verify('studio').records, 0);
});
