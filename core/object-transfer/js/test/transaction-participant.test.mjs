import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  chunkBytes,
  consumeVerificationReceipt,
  PROFILE as CHUNKING_PROFILE,
  PRODUCTION_BOUNDARY_VERSION,
  VERIFICATION_RECEIPT_VERIFIER,
} from '@opengamevcs/chunking-manifest';
import { loadBundledRegistry, validateRegistrySet } from '@opengamevcs/object-model';
import { canonicalBytes } from '@opengamevcs/protocol-baseline';
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

async function productionRegistry() {
  const bundled = await loadBundledRegistry();
  const documents = structuredClone(Object.fromEntries(bundled.documents));
  documents['profiles.json'].entries.push({
    family: 'chunking',
    id: 'gear-fastcdc-1m',
    major: 1,
    namespace: 'chunking.opengamevcs',
    owner: 'OGVCS-007',
    productionWriteAllowed: true,
    state: 'ratified',
  });
  documents['profiles.json'].entries.sort((left, right) => {
    const a = `${left.namespace}\0${left.id}\0${String(left.major).padStart(10, '0')}`;
    const b = `${right.namespace}\0${right.id}\0${String(right.major).padStart(10, '0')}`;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  return validateRegistrySet(documents);
}

async function contentManifestFixture(text = 'OpenGameVCS object-transfer content-manifest fixture\n') {
  const bytes = Buffer.from(text, 'utf8');
  const generated = await chunkBytes(bytes);
  const statement = {
    boundary: PRODUCTION_BOUNDARY_VERSION,
    logicalBytes: String(bytes.length),
    manifestObjectId: generated.manifest.objectId,
    manifestSha256: createHash('sha256').update(generated.manifest.bytes).digest('hex'),
    profile: `${CHUNKING_PROFILE.namespace}/${CHUNKING_PROFILE.id}@${CHUNKING_PROFILE.major}`,
    verifier: VERIFICATION_RECEIPT_VERIFIER,
    wholeFileSha256: createHash('sha256').update(bytes).digest('hex'),
  };
  return Object.freeze({
    manifest: generated.manifest.bytes,
    objectId: generated.manifest.objectId,
    verificationReceipt: generated.verificationReceipt,
    verificationReceiptSha256: createHash('sha256')
      .update('OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-PRODUCTION-V1\0')
      .update(canonicalBytes(statement))
      .digest('hex'),
  });
}

function requiresContentManifestPublication(capability, object) {
  return object.objectId.includes(':content-manifest:')
    && (capability === 'transfer.record-available'
      || capability === 'submit.consume-publication' && object.expectedState === 'quarantined');
}

function privateContext(capability, objects, fixtures = new Map()) {
  return {
    contentManifestPublications: objects
      .filter((object) => requiresContentManifestPublication(capability, object))
      .map((object) => {
        const fixture = fixtures.get(object.objectId);
        assert.ok(fixture, `missing content-manifest fixture for ${object.objectId}`);
        return {
          manifest: fixture.manifest,
          objectId: object.objectId,
          opaqueKey: object.opaqueKey,
          verificationReceipt: fixture.verificationReceipt,
        };
      }),
  };
}

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
  const manifestFixture = await contentManifestFixture();
  const fixtures = new Map([[manifestFixture.objectId, manifestFixture]]);
  const transaction = { audit: [], outbox: [] };
  let applications = 0;
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await productionRegistry() },
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
  assert.equal(submit.input.objects[1].objectId, manifestFixture.objectId);
  const context = boundary.owner.bind(
    transaction,
    claims(submit.input.capability, submit.input.objects),
    privateContext(submit.input.capability, submit.input.objects, fixtures),
  );
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
  const manifestFixture = await contentManifestFixture();
  const fixtures = new Map([[manifestFixture.objectId, manifestFixture]]);
  for (const entry of transactionVectors.filter(({ id }) => id !== 'submit-consume-publication')) {
    const transaction = {};
    const boundary = createLifecycleTransactionBoundary({
      contentManifestProduction: { registry: await productionRegistry() },
      resourceSecret: secret,
      poison: async () => {},
      apply: async (_value, command) => adapterResult(command),
    });
    const context = boundary.owner.bind(
      transaction,
      claims(entry.input.capability, entry.input.objects),
      privateContext(entry.input.capability, entry.input.objects, fixtures),
    );
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
    const manifestFixture = await contentManifestFixture();
    const fixtures = new Map([[manifestFixture.objectId, manifestFixture]]);
    const transaction = {};
    let poisonings = 0;
    const boundary = createLifecycleTransactionBoundary({
      contentManifestProduction: { registry: await productionRegistry() },
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
    const submit = vector('submit-consume-publication');
    const context = boundary.owner.bind(
      transaction,
      claims(submit.input.capability, submit.input.objects),
      privateContext(submit.input.capability, submit.input.objects, fixtures),
    );
    await assert.rejects(() => boundary.participant.consumePublication(context), mode === 'substitute'
      ? { code: 'TRANSFER_BACKEND_CORRUPT' }
      : { code: 'PRIVATE_DATABASE_SERIALIZATION' });
    await assert.rejects(() => boundary.participant.consumePublication(context), {
      code: 'TRANSFER_LIFECYCLE_STALE',
    });
    assert.equal(poisonings, 1);
  }
});

test('content-manifest available CAS requires the exact one-use OGVCS-007 receipt', async () => {
  const fixture = await contentManifestFixture();
  const entry = vector('transfer-record-available');
  assert.equal(entry.input.objects[0].objectId, fixture.objectId);
  let applications = 0;
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await productionRegistry() },
    resourceSecret: secret,
    poison: async () => {},
    apply: async (_value, command) => { applications += 1; return adapterResult(command); },
  });
  const context = boundary.owner.bind(
    {},
    claims(entry.input.capability, entry.input.objects),
    {
      contentManifestPublications: [{
        manifest: fixture.manifest,
        objectId: fixture.objectId,
        opaqueKey: entry.input.objects[0].opaqueKey,
        verificationReceipt: { ...fixture.verificationReceipt },
      }],
    },
  );
  await assert.rejects(() => boundary.participant.recordAvailable(context), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  assert.equal(applications, 0);
});

test('content-manifest production receipt is one-use across independent lifecycle contexts', async () => {
  const fixture = await contentManifestFixture();
  const entry = vector('transfer-record-available');
  const registry = await productionRegistry();
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry },
    resourceSecret: secret,
    poison: async () => {},
    apply: async (_value, command) => adapterResult(command),
  });
  const claimsValue = claims(entry.input.capability, entry.input.objects);
  const first = boundary.owner.bind({}, claimsValue, {
    contentManifestPublications: [{
      manifest: fixture.manifest,
      objectId: fixture.objectId,
      opaqueKey: entry.input.objects[0].opaqueKey,
      verificationReceipt: fixture.verificationReceipt,
    }],
  });
  await boundary.participant.recordAvailable(first);
  const replay = boundary.owner.bind({}, claimsValue, {
    contentManifestPublications: [{
      manifest: fixture.manifest,
      objectId: fixture.objectId,
      opaqueKey: entry.input.objects[0].opaqueKey,
      verificationReceipt: fixture.verificationReceipt,
    }],
  });
  await assert.rejects(() => boundary.participant.recordAvailable(replay), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
});

test('content-manifest production registry must explicitly allow OGVCS-007 production writes', async () => {
  const fixture = await contentManifestFixture();
  const entry = vector('transfer-record-available');
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await loadBundledRegistry() },
    resourceSecret: secret,
    poison: async () => {},
    apply: async (_value, command) => adapterResult(command),
  });
  const context = boundary.owner.bind({}, claims(entry.input.capability, entry.input.objects), {
    contentManifestPublications: [{
      manifest: fixture.manifest,
      objectId: fixture.objectId,
      opaqueKey: entry.input.objects[0].opaqueKey,
      verificationReceipt: fixture.verificationReceipt,
    }],
  });
  await assert.rejects(() => boundary.participant.recordAvailable(context), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
});

test('stale content-manifest availability burns the one-use receipt and cannot be retried with a fresh generation', async () => {
  const fixture = await contentManifestFixture();
  const entry = vector('transfer-record-available');
  let attempts = 0;
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await productionRegistry() },
    resourceSecret: secret,
    poison: async () => {},
    apply: async () => {
      attempts += 1;
      if (attempts === 1) {
        const error = new Error('stale generation');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      return adapterResult({
        contextDigestSha256: sha('0'),
        context: claims(entry.input.capability, entry.input.objects),
        expectedObjects: [],
        expectedFacts: [],
      });
    },
  });
  const privateValue = {
    contentManifestPublications: [{
      manifest: fixture.manifest,
      objectId: fixture.objectId,
      opaqueKey: entry.input.objects[0].opaqueKey,
      verificationReceipt: fixture.verificationReceipt,
    }],
  };
  const stale = boundary.owner.bind({}, claims(entry.input.capability, entry.input.objects), privateValue);
  await assert.rejects(() => boundary.participant.recordAvailable(stale), {
    code: 'TRANSFER_LIFECYCLE_STALE',
  });
  const retry = boundary.owner.bind({}, claims(entry.input.capability, [{
    ...entry.input.objects[0],
    expectedGeneration: entry.input.objects[0].expectedGeneration + 1,
  }]), privateValue);
  await assert.rejects(() => boundary.participant.recordAvailable(retry), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  assert.equal(attempts, 1);
});

test('multiple content manifests reach one atomic apply only after every production commit', async () => {
  const fixtures = [
    await contentManifestFixture('first atomic content-manifest fixture\n'),
    await contentManifestFixture('second atomic content-manifest fixture\n'),
  ];
  const objects = fixtures.map((fixture, index) => objectBinding({
    opaqueKey: sha(index === 0 ? 'a' : 'b'),
    objectId: fixture.objectId,
    expectedState: 'staged',
    expectedHealth: 'not-applicable',
    expectedHealthGeneration: null,
    verificationReceiptSha256: fixture.verificationReceiptSha256,
  }));
  let applications = 0;
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await productionRegistry() },
    resourceSecret: secret,
    poison: async () => {},
    apply: async (_transaction, command) => {
      applications += 1;
      for (const fixture of fixtures) {
        assert.throws(() => consumeVerificationReceipt(fixture.verificationReceipt), {
          code: 'CHUNK_RESOURCE_INVALID',
        });
      }
      return adapterResult(command);
    },
  });
  const context = boundary.owner.bind({}, claims('transfer.record-available', objects), {
    contentManifestPublications: objects.map((object, index) => ({
      manifest: fixtures[index].manifest,
      objectId: object.objectId,
      opaqueKey: object.opaqueKey,
      verificationReceipt: fixtures[index].verificationReceipt,
    })),
  });
  const result = await boundary.participant.recordAvailable(context);
  assert.equal(applications, 1);
  assert.equal(result.objects.length, 2);
  assert.equal(result.objects.every(({ nextState }) => nextState === 'available'), true);
});

test('one wrong production statement releases all waiting commits without a partial apply', { timeout: 2_000 }, async () => {
  const fixtures = [
    await contentManifestFixture('first rejected atomic content-manifest fixture\n'),
    await contentManifestFixture('second rejected atomic content-manifest fixture\n'),
  ];
  const objects = fixtures.map((fixture, index) => objectBinding({
    opaqueKey: sha(index === 0 ? 'a' : 'b'),
    objectId: fixture.objectId,
    expectedState: 'staged',
    expectedHealth: 'not-applicable',
    expectedHealthGeneration: null,
    verificationReceiptSha256: index === 0 ? fixture.verificationReceiptSha256 : sha('f'),
  }));
  let applications = 0;
  let poisonings = 0;
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await productionRegistry() },
    resourceSecret: secret,
    poison: async () => { poisonings += 1; },
    apply: async (_transaction, command) => { applications += 1; return adapterResult(command); },
  });
  const context = boundary.owner.bind({}, claims('transfer.record-available', objects), {
    contentManifestPublications: objects.map((object, index) => ({
      manifest: fixtures[index].manifest,
      objectId: object.objectId,
      opaqueKey: object.opaqueKey,
      verificationReceipt: fixtures[index].verificationReceipt,
    })),
  });
  await assert.rejects(() => boundary.participant.recordAvailable(context), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  assert.equal(applications, 0);
  assert.equal(poisonings, 1);
});

test('private manifest bindings are snapshotted once and reject an over-budget aggregate before execution', async () => {
  const fixture = await contentManifestFixture();
  const object = objectBinding({
    objectId: fixture.objectId,
    expectedState: 'staged',
    expectedHealth: 'not-applicable',
    expectedHealthGeneration: null,
    verificationReceiptSha256: fixture.verificationReceiptSha256,
  });
  let manifestReads = 0;
  const exactBinding = {
    get manifest() { manifestReads += 1; return fixture.manifest; },
    objectId: object.objectId,
    opaqueKey: object.opaqueKey,
    verificationReceipt: fixture.verificationReceipt,
  };
  const boundary = createLifecycleTransactionBoundary({
    contentManifestProduction: { registry: await productionRegistry() },
    resourceSecret: secret,
    poison: async () => {},
    apply: async (_transaction, command) => adapterResult(command),
  });
  boundary.owner.bind({}, claims('transfer.record-available', [object]), {
    contentManifestPublications: [exactBinding],
  });
  assert.equal(manifestReads, 1);

  const oversized = new Proxy(new Uint8Array(0), {
    get(target, property) {
      if (property === 'byteLength') return 256 * 1024 * 1024 + 1;
      return Reflect.get(target, property, target);
    },
  });
  assert.throws(() => boundary.owner.bind({}, claims('transfer.record-available', [object]), {
    contentManifestPublications: [{
      manifest: oversized,
      objectId: object.objectId,
      opaqueKey: object.opaqueKey,
      verificationReceipt: fixture.verificationReceipt,
    }],
  }), { code: 'TRANSFER_LIMIT_EXCEEDED' });
});
