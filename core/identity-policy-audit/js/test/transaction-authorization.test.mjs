import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AuthorityState,
  CredentialAuthority,
  TransactionAuthorizationAuthority,
} from '../src/index.mjs';
import {
  MemoryAuthorizationTransactionParticipant,
  MemoryCredentialStore,
  deterministicSecretSource,
} from '../src/testing.mjs';

const NOW = 1_800_000_000;

function policy(generation = 1, authorityEpoch = 2) {
  return {
    schemaVersion: 'ogvcs.identity-policy/policy/v1', id: 'studio.policy', version: `v${generation}`,
    generation, authorityEpoch, pathProfile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive',
    default: 'deny', composition: 'deny-overrides-v1',
    rules: [
      {
        id: 'deny.secret', effect: 'deny', subjects: { identities: [], groups: [], actorClasses: [] },
        tenant: 'studio', repository: 'game', references: ['main'], pathPrefixes: ['Game/Secret'],
        resourceTypes: ['path'], permissions: ['metadata.read'],
      },
      {
        id: 'allow.artist', effect: 'allow', subjects: { identities: [], groups: ['artists'], actorClasses: ['human'] },
        tenant: 'studio', repository: 'game', references: ['main'], pathPrefixes: ['Game'],
        resourceTypes: ['path'], permissions: ['metadata.read'],
      },
    ],
  };
}

function resource(path = 'Game/Public/asset.uasset') {
  return { type: 'path', path, fileId: 'ab'.repeat(16), objectId: null, name: null };
}

function request(path) {
  return {
    requestId: 'request.metadata.1', tenant: 'studio', repository: 'game', permission: 'metadata.read',
    reason: null, resource: resource(path), reference: 'main', snapshot: null,
  };
}

function fixture() {
  const state = new AuthorityState({ authorityEpoch: 2, keyGeneration: 4 });
  const store = new MemoryCredentialStore();
  const credentials = new CredentialAuthority({
    store, authorityState: state, secretSource: deterministicSecretSource('transaction-auth'), clock: () => NOW,
  });
  const issued = credentials.issue({
    credentialClass: 'session', subject: 'artist.user', actorClass: 'human', groups: ['artists'], ttlSeconds: 600,
    scope: {
      tenants: ['studio'], repositories: ['game'], references: ['main'], pathPrefixes: ['Game'], permissions: ['metadata.read'],
    },
  });
  const participant = new MemoryAuthorizationTransactionParticipant(); participant.initializePolicy('studio', policy());
  const authority = new TransactionAuthorizationAuthority({ credentialAuthority: credentials, participant });
  return { state, store, credentials, issued, participant, authority };
}

test('transaction view derives epoch, policy, scope, and actor from current credential authority', () => {
  const context = fixture(); const transaction = context.participant.open();
  const view = context.authority.begin({
    transaction, credentialToken: context.issued.token,
    request: request('Game/Public/asset.uasset'),
  });
  assert.equal(view.transactionId, 'memory.tx.1');
  assert.equal(view.authorityEpoch, 2); assert.equal(view.policyGeneration, 1);
  assert.match(view.subjectDigest, /^[0-9a-f]{64}$/u); assert.match(view.authenticatedScopeDigest, /^[0-9a-f]{64}$/u);
  assert.equal(context.authority.permits(view, { transaction, permission: 'metadata.read', resource: resource() }), true);
  assert.equal(context.authority.permits(structuredClone(view), { transaction, permission: 'metadata.read', resource: resource() }), false);
});

test('transaction view rejects resource, transaction, policy-generation, and revocation substitution', () => {
  const context = fixture(); const transaction = context.participant.open(); const other = context.participant.open();
  const view = context.authority.begin({ transaction, credentialToken: context.issued.token, request: request() });
  assert.equal(context.authority.permits(view, { transaction, permission: 'metadata.read', resource: resource('Game/Secret/known.uasset') }), false);
  assert.equal(context.authority.permits(view, { transaction: other, permission: 'metadata.read', resource: resource() }), false);
  context.participant.initializePolicy('studio', policy(2));
  assert.equal(context.authority.permits(view, { transaction, permission: 'metadata.read', resource: resource() }), false);
  context.participant.initializePolicy('studio', policy(1));
  context.credentials.revoke(context.issued.descriptor.id, { audit: () => {} });
  assert.equal(context.authority.permits(view, { transaction, permission: 'metadata.read', resource: resource() }), false);
});

test('decision commitment is exact, same-transaction, resource-bound, and single append', () => {
  const context = fixture(); const transaction = context.participant.open();
  const view = context.authority.begin({ transaction, credentialToken: context.issued.token, request: request() });
  const commitment = context.authority.appendDecisionCommitment(view, {
    transaction, correlationId: 'correlation.metadata.3', resources: [resource()],
    result: { commitSequence: 42, outcome: 'published' },
  });
  assert.equal(commitment.transactionId, 'memory.tx.1'); assert.equal(commitment.sequence, 1);
  assert.match(commitment.resourceSetDigest, /^[0-9a-f]{64}$/u); assert.match(commitment.recordHash, /^[0-9a-f]{64}$/u);
  assert.equal(context.participant.commitments('studio').length, 1);
  assert.throws(() => context.authority.appendDecisionCommitment(view, {
    transaction, correlationId: 'correlation.metadata.3', resources: [resource()], result: { commitSequence: 42 },
  }), ({ code }) => code === 'STATE_CONFLICT');
});

test('batch authorization rejects duplicate, hidden, and over-limit resources before commitment', () => {
  const context = fixture(); const transaction = context.participant.open();
  const view = context.authority.begin({ transaction, credentialToken: context.issued.token, request: request() });
  const batch = context.authority.authorizeBatch(view, { transaction, resources: [resource(), resource('Game/Public/other.uasset')] });
  assert.equal(batch.items.length, 2); assert.match(batch.resourceSetDigest, /^[0-9a-f]{64}$/u);
  assert.throws(() => context.authority.authorizeBatch(view, {
    transaction, resources: Array.from({ length: 1_001 }, (_, index) => resource(`Game/Public/${index}.uasset`)),
  }), ({ code }) => code === 'LIMIT_EXCEEDED');
  assert.throws(() => context.authority.authorizeBatch(view, {
    transaction, resources: [resource(), resource()],
  }), ({ code }) => code === 'INPUT_INVALID');
  assert.throws(() => context.authority.authorizeBatch(view, {
    transaction, resources: [resource(), resource('Game/Secret/known.uasset'), resource('Game/Public/final.uasset')],
  }), ({ code }) => code === 'AUTHENTICATION_DENIED');
  assert.throws(() => context.authority.appendDecisionCommitment(view, {
    transaction, correlationId: 'correlation.duplicate', resources: [resource(), resource()], result: {},
  }), ({ code }) => code === 'INPUT_INVALID');
});

test('ambiguous or malformed decision commits poison the exact transaction', () => {
  const context = fixture(); const transaction = context.participant.open();
  const view = context.authority.begin({ transaction, credentialToken: context.issued.token, request: request() });
  const original = context.participant.appendDecisionCommitment.bind(context.participant);
  context.participant.appendDecisionCommitment = (...arguments_) => ({ ...original(...arguments_), recordHash: 'invalid' });
  assert.throws(() => context.authority.appendDecisionCommitment(view, {
    transaction, correlationId: 'correlation.malformed', resources: [resource()], result: { outcome: 'published' },
  }), ({ code }) => code === 'POLICY_UNAVAILABLE');
  assert.throws(() => context.participant.readPolicy(transaction, 'studio'), ({ code }) => code === 'STATE_CONFLICT');
  assert.throws(() => context.authority.appendDecisionCommitment(view, {
    transaction, correlationId: 'correlation.retry', resources: [resource()], result: { outcome: 'published' },
  }), ({ code }) => code === 'STATE_CONFLICT');
});
