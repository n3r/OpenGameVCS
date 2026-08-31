import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { PolicyMutationAuthority } from '../src/index.mjs';
import { MemoryPolicyAuthorityStore } from '../src/testing.mjs';
import { assertVectorOutcome, assertVectorThrow } from './vector-outcome.mjs';

function policy(generation, effect = 'allow') {
  return {
    schemaVersion: 'ogvcs.identity-policy/policy/v1', id: 'studio.policy', version: `v${generation}`,
    generation, authorityEpoch: 3, pathProfile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive',
    default: 'deny', composition: 'deny-overrides-v1',
    rules: [{
      id: `admin.${generation}`, effect,
      subjects: { identities: ['admin.user'], groups: ['team-admin'], actorClasses: ['administrator'] },
      tenant: 'studio', repository: 'game', references: [], pathPrefixes: [],
      resourceTypes: ['policy'], permissions: ['policy.administer'],
    }],
  };
}

function previewRequest(generation = 1) {
  return {
    schemaVersion: 'ogvcs.authorization/request/v1', requestId: `preview.${generation}`,
    actor: {
      id: 'admin.user', class: 'administrator', groups: ['team-admin'], credentialClass: 'session',
      credentialGeneration: 1, credentialStatus: 'active', authorityEpoch: 3,
    },
    tenant: 'studio', repository: 'game', permission: 'policy.administer', reason: 'preview policy update',
    resource: { type: 'policy', path: null, fileId: null, objectId: null, name: 'studio.policy' },
    context: { reference: null, snapshot: null, policyGeneration: generation, authorityEpoch: 3 },
  };
}

function mutation(expectedGeneration = 1, nextEffect = 'deny') {
  return {
    schemaVersion: 'ogvcs.identity-policy/policy-mutation/v1', mutationId: `policy.change.${expectedGeneration}`,
    tenant: 'studio', repository: 'game', expectedGeneration,
    nextPolicy: policy(expectedGeneration + 1, nextEffect), previewRequests: [previewRequest(expectedGeneration)],
    reason: 'restrict policy during security review', diffRef: `policy.diff.${expectedGeneration}`,
  };
}

function authorityFixture() {
  const store = new MemoryPolicyAuthorityStore(); store.initialize('studio', policy(1));
  const authorizer = {
    authorizePolicyMutation({ mutation: input }) {
      return {
        allowed: true, actorClass: 'administrator', actorPseudonym: `pseudonym:${'ab'.repeat(16)}`,
        correlationId: input.mutationId,
        decisionDigest: createHash('sha256').update(input.mutationId).digest('hex'),
        tenant: input.tenant, repository: input.repository, permission: 'policy.administer',
      };
    },
  };
  return { store, authority: new PolicyMutationAuthority({ store, authorizer, clock: () => 1_800_000_000 }) };
}

test('policy mutation previews the exact generation and commits policy plus policy.changed atomically', () => {
  const { store, authority } = authorityFixture(); const input = mutation();
  const preview = authority.preview(input);
  assert.equal(preview.currentGeneration, 1); assert.equal(preview.nextGeneration, 2);
  assert.equal(preview.items[0].current.allowed, true); assert.equal(preview.items[0].next.allowed, false);
  const receipt = authority.commit(input);
  assert.equal(receipt.policyGeneration, 2); assert.match(receipt.previewDigest, /^[0-9a-f]{64}$/u);
  assert.match(receipt.auditRecordHash, /^[0-9a-f]{64}$/u);
  assert.equal(store.read('studio').generation, 2);
  assert.deepEqual(store.auditLedger().verify('studio'), { valid: true, records: 1, tailHash: receipt.auditRecordHash });
  assertVectorOutcome('policy-preview-cas-audit', 'committed', 'committed');
});

test('policy mutation loses a generation race without appending an audit record', () => {
  const { store, authority } = authorityFixture(); const input = mutation();
  authority.commit(input);
  assertVectorThrow('policy-change-lost-race', () => authority.commit(input), 'STATE_CONFLICT');
  assert.equal(store.auditLedger().verify('studio').records, 1);
});

test('policy mutation rejects widened or misbound authorization evidence before persistence', () => {
  const store = new MemoryPolicyAuthorityStore(); store.initialize('studio', policy(1));
  const authority = new PolicyMutationAuthority({
    store,
    authorizer: {
      authorizePolicyMutation() {
        return {
          allowed: true, actorClass: 'administrator', actorPseudonym: `pseudonym:${'ab'.repeat(16)}`,
          correlationId: 'policy.change.1', decisionDigest: '11'.repeat(32),
          tenant: 'other', repository: 'game', permission: 'policy.administer',
        };
      },
    },
  });
  assert.throws(() => authority.preview(mutation()), ({ code }) => code === 'AUTHENTICATION_DENIED');
  assert.throws(() => authority.commit(mutation()), ({ code }) => code === 'AUTHENTICATION_DENIED');
  assert.equal(store.read('studio').generation, 1);
  assert.equal(store.auditLedger().verify('studio').records, 0);
});
