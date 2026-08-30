import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  LIFECYCLE_TRANSACTION_CONTRACT_VERSION,
  createLifecycleTransactionBoundary,
} from '../src/index.mjs';

const secret = Buffer.from('6d8d7686aa247b783d808ca7564d10e511640fa7634c6b734b63a63c41f4f386', 'hex');
const tenantId = '00000000-0000-4000-8000-000000000001';
const repositoryId = '00000000-0000-4000-8000-000000000002';
const transactionId = `ltx1.${'A'.repeat(43)}`;
const publicationRef = `ogvcs:v1:snapshot:sha256:${'4'.repeat(64)}`;
const objectIdA = `ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`;
const objectIdB = `ogvcs:v1:chunk:sha256:${'2'.repeat(64)}`;
const sha = (character) => character.repeat(64);
const uuid = (index) => `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`;
const transactionVectors = JSON.parse(await readFile(resolve(
  import.meta.dirname,
  '../../../../spec/object-transfer/v1/vectors/transaction-participant.json',
))).cases;
const vector = (id) => transactionVectors.find((entry) => entry.id === id);

function objectBinding(overrides = {}) {
  return {
    opaqueKey: sha('a'),
    objectId: objectIdA,
    expectedState: 'available',
    expectedGeneration: 2,
    expectedHealth: 'healthy',
    expectedHealthGeneration: 3,
    authorityBindingSha256: sha('b'),
    backendReceiptSha256: sha('c'),
    verificationReceiptSha256: null,
    deletionReceiptSha256: null,
    ...overrides,
  };
}

function claims(capability, objects = [objectBinding()]) {
  const configuration = {
    'submit.consume-publication': {
      permission: 'submit', operation: 'submit.finalize', publicationRef, rootProofSha256: null,
    },
    'gc.acquire-deleting': {
      permission: 'retention.delete', operation: 'gc.acquire-deleting', publicationRef: null, rootProofSha256: sha('d'),
    },
    'gc.complete-deletion': {
      permission: 'retention.delete', operation: 'gc.complete-deletion', publicationRef: null, rootProofSha256: sha('d'),
    },
    'transfer.reverify-deleted': {
      permission: 'content.upload', operation: 'transfer.reverify-deleted', publicationRef: null, rootProofSha256: null,
    },
    'transfer.record-available': {
      permission: 'content.upload', operation: 'transfer.record-available', publicationRef: null, rootProofSha256: null,
    },
  }[capability];
  return {
    schemaVersion: 'ogvcs.object-transfer/lifecycle-transaction-context/v1',
    transactionId,
    subjectDigestSha256: sha('e'),
    tenantId,
    repositoryId,
    authorizationEpoch: 11,
    permission: configuration.permission,
    operation: configuration.operation,
    capability,
    lifecycleContractVersion: LIFECYCLE_TRANSACTION_CONTRACT_VERSION,
    publicationRef: configuration.publicationRef,
    rootProofSha256: configuration.rootProofSha256,
    objects,
  };
}

function adapterResult(command) {
  return {
    schemaVersion: 'ogvcs.object-transfer/lifecycle-transaction-adapter-result/v1',
    contextDigestSha256: command.contextDigestSha256,
    transactionId: command.context.transactionId,
    capability: command.context.capability,
    objects: command.expectedObjects,
    persistedFacts: command.expectedFacts.map(({ factSha256 }, index) => ({
      factSha256,
      auditRecordId: uuid(index * 2 + 1),
      outboxEventId: uuid(index * 2 + 2),
    })),
  };
}

test('one branded submit participant call revives and links an exact closure in its owner transaction', async () => {
  const submit = vector('submit-consume-publication');
  const transaction = { audit: [], outbox: [] };
  let applications = 0;
  const boundary = createLifecycleTransactionBoundary({
    resourceSecret: secret,
    poison: async (value) => { value.poisoned = true; },
    apply: async (value, command) => {
      applications += 1;
      assert.equal(value, transaction);
      assert.deepEqual(command.expectedObjects.map(({ priorState, nextState, nextGeneration }) => ({
        priorState, nextState, nextGeneration,
      })), submit.expected.objects.map(({ priorState, nextState, nextGeneration }) => ({
        priorState, nextState, nextGeneration,
      })));
      assert.equal(command.expectedFacts.every((fact) => !Object.hasOwn(fact, 'opaqueKey')
        && /^or1\.[A-Za-z0-9_-]{43}$/u.test(fact.resourceOpaqueId)), true);
      value.audit.push(...command.expectedFacts);
      value.outbox.push(...command.expectedFacts);
      return adapterResult(command);
    },
  });
  const context = boundary.owner.bind(transaction, claims(submit.input.capability, submit.input.objects));
  const [first, replay] = await Promise.all([
    boundary.participant.consumePublication(context),
    boundary.participant.consumePublication(context),
  ]);
  assert.equal(first, replay);
  assert.equal(applications, 1);
  assert.equal(transaction.audit.length, 2);
  assert.equal(transaction.outbox.length, 2);
  assert.equal(transaction.poisoned, undefined);
});

test('every lifecycle transaction capability has one exact state/generation outcome', async () => {
  for (const entry of transactionVectors.filter(({ id }) => id !== 'submit-consume-publication')) {
    const transaction = {};
    const boundary = createLifecycleTransactionBoundary({
      resourceSecret: secret,
      poison: async () => {},
      apply: async (_value, command) => adapterResult(command),
    });
    const context = boundary.owner.bind(transaction, claims(entry.input.capability, entry.input.objects));
    const result = await boundary.participant[entry.input.method](context);
    assert.deepEqual(result.objects.map(({ priorState, nextState, nextGeneration, reachabilityRecorded }) => ({
      priorState, nextState, nextGeneration, reachabilityRecorded,
    })), entry.expected.objects);
  }
});

test('structural, cross-boundary, and wrong-capability contexts cannot invoke a transaction participant', async () => {
  let applications = 0;
  let poisonings = 0;
  const configuration = {
    resourceSecret: secret,
    poison: async () => { poisonings += 1; },
    apply: async (_value, command) => { applications += 1; return adapterResult(command); },
  };
  const first = createLifecycleTransactionBoundary(configuration);
  const second = createLifecycleTransactionBoundary(configuration);
  const context = first.owner.bind({}, claims('submit.consume-publication'));
  await assert.rejects(() => first.participant.consumePublication({ ...context }), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  await assert.rejects(() => second.participant.consumePublication(context), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  await assert.rejects(() => first.participant.acquireDeleting(context), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  await assert.rejects(() => first.participant.consumePublication(context), {
    code: 'TRANSFER_LIFECYCLE_STALE',
  });
  assert.equal(applications, 0);
  assert.equal(poisonings, 1);
});

test('adapter substitution or failure poisons the exact transaction and never becomes a replayable success', async () => {
  for (const mode of ['substitute', 'fail']) {
    const transaction = {};
    let poisonings = 0;
    const boundary = createLifecycleTransactionBoundary({
      resourceSecret: secret,
      poison: async (value) => { assert.equal(value, transaction); poisonings += 1; },
      apply: async (_value, command) => {
        if (mode === 'fail') {
          const error = new Error('private serialization failure');
          error.code = 'PRIVATE_DATABASE_SERIALIZATION';
          throw error;
        }
        const result = adapterResult(command);
        result.objects = [{ ...result.objects[0], nextGeneration: 99 }];
        return result;
      },
    });
    const context = boundary.owner.bind(transaction, claims('submit.consume-publication'));
    await assert.rejects(() => boundary.participant.consumePublication(context), mode === 'substitute'
      ? { code: 'TRANSFER_BACKEND_CORRUPT' }
      : { code: 'PRIVATE_DATABASE_SERIALIZATION' });
    await assert.rejects(() => boundary.participant.consumePublication(context), {
      code: 'TRANSFER_LIFECYCLE_STALE',
    });
    assert.equal(poisonings, 1);
  }
});
