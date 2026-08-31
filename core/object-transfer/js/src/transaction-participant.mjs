import { createHash, createHmac } from 'node:crypto';
import {
  commitProductionManifest,
  PROFILE as CHUNKING_PROFILE,
  PRODUCTION_BOUNDARY_VERSION,
  VERIFICATION_RECEIPT_VERIFIER,
} from '@opengamevcs/chunking-manifest';
import { ObjectRef } from '@opengamevcs/object-model';
import { canonicalBytes, cloneJson } from '@opengamevcs/protocol-baseline';
import { transferError } from './errors.mjs';

export const LIFECYCLE_TRANSACTION_CONTRACT_VERSION = '0.1.0-rc.5';
export const LIFECYCLE_TRANSACTION_LIMITS = Object.freeze({ objectsMaximum: 1024 });
const PRIVATE_CONTENT_MANIFEST_BYTES_MAX = 256 * 1024 * 1024;

const SHA = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const TRANSACTION_ID = /^ltx1\.[A-Za-z0-9_-]{43}$/u;
const RESOURCE_ID = /^or1\.[A-Za-z0-9_-]{43}$/u;
const CONTEXT_KEYS = [
  'authorizationEpoch',
  'capability',
  'lifecycleContractVersion',
  'objects',
  'operation',
  'permission',
  'publicationRef',
  'repositoryId',
  'rootProofSha256',
  'schemaVersion',
  'subjectDigestSha256',
  'tenantId',
  'transactionId',
].sort().join('\0');
const OBJECT_KEYS = [
  'authorityBindingSha256',
  'backendReceiptSha256',
  'deletionReceiptSha256',
  'expectedGeneration',
  'expectedHealth',
  'expectedHealthGeneration',
  'expectedState',
  'objectId',
  'opaqueKey',
  'verificationReceiptSha256',
].sort().join('\0');
const ADAPTER_RESULT_KEYS = [
  'capability',
  'contextDigestSha256',
  'objects',
  'persistedFacts',
  'schemaVersion',
  'transactionId',
].sort().join('\0');
const RESULT_OBJECT_KEYS = [
  'backendReceiptSha256',
  'healthGeneration',
  'nextGeneration',
  'nextState',
  'opaqueKey',
  'priorGeneration',
  'priorState',
  'reachabilityRecorded',
].sort().join('\0');
const FACT_ACK_KEYS = ['auditRecordId', 'factSha256', 'outboxEventId'].sort().join('\0');
const PRIVATE_CONTEXT_KEYS = ['contentManifestPublications'].sort().join('\0');
const CONTENT_MANIFEST_PUBLICATION_KEYS = [
  'manifest',
  'objectId',
  'opaqueKey',
  'verificationReceipt',
].sort().join('\0');
const CONTENT_MANIFEST_PRODUCTION_STATEMENT_KEYS = [
  'boundary',
  'logicalBytes',
  'manifestObjectId',
  'manifestSha256',
  'profile',
  'verifier',
  'wholeFileSha256',
].sort().join('\0');
const CHUNKING_PROFILE_TEXT = `${CHUNKING_PROFILE.namespace}/${CHUNKING_PROFILE.id}@${CHUNKING_PROFILE.major}`;

const CAPABILITIES = Object.freeze({
  'submit.consume-publication': Object.freeze({
    permission: 'submit',
    operation: 'submit.finalize',
    states: new Set(['available', 'quarantined']),
    publication: true,
    rootProof: false,
  }),
  'gc.acquire-deleting': Object.freeze({
    permission: 'retention.delete',
    operation: 'gc.acquire-deleting',
    states: new Set(['quarantined']),
    publication: false,
    rootProof: true,
  }),
  'gc.complete-deletion': Object.freeze({
    permission: 'retention.delete',
    operation: 'gc.complete-deletion',
    states: new Set(['deleting']),
    publication: false,
    rootProof: true,
  }),
  'transfer.reverify-deleted': Object.freeze({
    permission: 'content.upload',
    operation: 'transfer.reverify-deleted',
    states: new Set(['deleted']),
    publication: false,
    rootProof: false,
  }),
  'transfer.record-available': Object.freeze({
    permission: 'content.upload',
    operation: 'transfer.record-available',
    states: new Set(['staged']),
    publication: false,
    rootProof: false,
  }),
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function exactKeys(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === keys);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function canonicalObjectId(value, label = 'lifecycle transaction ObjectID') {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value) throw new TypeError('ObjectID is not canonical');
    return value;
  } catch (error) {
    transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`, { cause: error });
  }
}

function nullableSha(value, label) {
  if (!(value === null || typeof value === 'string' && SHA.test(value))) {
    transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  }
  return value;
}

function objectRef(value) {
  return ObjectRef.parse(value);
}

function isContentManifestObjectId(value) {
  return objectRef(value).kindName === 'content-manifest';
}

function generation(value, nullable, label) {
  if (nullable && value === null) return value;
  if (!Number.isSafeInteger(value) || value < 1) {
    transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  }
  return value;
}

function validateObject(input, capability) {
  if (!exactKeys(input, OBJECT_KEYS) || !SHA.test(input.opaqueKey ?? '')
      || !SHA.test(input.authorityBindingSha256 ?? '')) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction object binding is invalid');
  }
  canonicalObjectId(input.objectId);
  const isContentManifest = isContentManifestObjectId(input.objectId);
  generation(input.expectedGeneration, false, 'lifecycle expected generation');
  generation(input.expectedHealthGeneration, true, 'lifecycle health generation');
  nullableSha(input.backendReceiptSha256, 'lifecycle backend receipt');
  nullableSha(input.verificationReceiptSha256, 'lifecycle verification receipt');
  nullableSha(input.deletionReceiptSha256, 'lifecycle deletion receipt');
  if (!capability.states.has(input.expectedState)
      || !['healthy', 'not-applicable'].includes(input.expectedHealth)) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle expected state or health is invalid');
  }
  if (capability.permission === 'submit') {
    if (input.expectedHealth !== 'healthy' || input.expectedHealthGeneration === null
        || input.backendReceiptSha256 === null
        || (input.expectedState === 'quarantined') !== (input.verificationReceiptSha256 !== null)
        || input.deletionReceiptSha256 !== null) {
      transferError('TRANSFER_INPUT_INVALID', 'submit lifecycle binding is incomplete');
    }
  } else if (capability.operation === 'gc.acquire-deleting') {
    if (input.expectedHealth !== 'healthy' || input.expectedHealthGeneration === null
        || input.backendReceiptSha256 === null || input.verificationReceiptSha256 !== null
        || input.deletionReceiptSha256 !== null) {
      transferError('TRANSFER_INPUT_INVALID', 'deleting acquisition binding is incomplete');
    }
  } else if (capability.operation === 'gc.complete-deletion') {
    if (input.expectedHealth !== 'not-applicable' || input.expectedHealthGeneration !== null
        || input.backendReceiptSha256 === null || input.verificationReceiptSha256 !== null
        || input.deletionReceiptSha256 === null) {
      transferError('TRANSFER_INPUT_INVALID', 'deletion completion binding is incomplete');
    }
  } else if (capability.operation === 'transfer.reverify-deleted') {
    if (input.expectedHealth !== 'not-applicable' || input.expectedHealthGeneration !== null
        || input.backendReceiptSha256 !== null || input.verificationReceiptSha256 === null
        || input.deletionReceiptSha256 === null) {
      transferError('TRANSFER_INPUT_INVALID', 'deleted reverification binding is incomplete');
    }
  } else if (input.expectedHealth !== 'not-applicable' || input.expectedHealthGeneration !== null
      || input.backendReceiptSha256 === null
      || (!isContentManifest && input.verificationReceiptSha256 !== null)
      || (isContentManifest && input.verificationReceiptSha256 === null)
      || input.deletionReceiptSha256 !== null) {
    transferError('TRANSFER_INPUT_INVALID', 'available recording binding is incomplete');
  }
  return deepFreeze(cloneJson(input, { maxBytes: 64 * 1024 }));
}

function validateClaims(input) {
  if (!exactKeys(input, CONTEXT_KEYS)
      || input.schemaVersion !== 'ogvcs.object-transfer/lifecycle-transaction-context/v1'
      || input.lifecycleContractVersion !== LIFECYCLE_TRANSACTION_CONTRACT_VERSION
      || !TRANSACTION_ID.test(input.transactionId ?? '')
      || !SHA.test(input.subjectDigestSha256 ?? '') || !UUID.test(input.tenantId ?? '')
      || !UUID.test(input.repositoryId ?? '')
      || !Number.isSafeInteger(input.authorizationEpoch) || input.authorizationEpoch < 1
      || !Array.isArray(input.objects) || input.objects.length < 1
      || input.objects.length > LIFECYCLE_TRANSACTION_LIMITS.objectsMaximum) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction context is invalid');
  }
  const capability = CAPABILITIES[input.capability];
  if (!capability || input.permission !== capability.permission || input.operation !== capability.operation
      || capability.publication !== (input.publicationRef !== null)
      || capability.rootProof !== (input.rootProofSha256 !== null)) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction authority binding is invalid');
  }
  if (input.publicationRef !== null) canonicalObjectId(input.publicationRef, 'publication ObjectID');
  nullableSha(input.rootProofSha256, 'lifecycle root proof');
  const objects = input.objects.map((value) => validateObject(value, capability));
  for (let index = 0; index < objects.length; index += 1) {
    if (index > 0 && objects[index - 1].opaqueKey >= objects[index].opaqueKey) {
      transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction object bindings are not unique and sorted');
    }
  }
  return deepFreeze({ ...cloneJson(input, { maxBytes: 1024 * 1024 }), objects });
}

function transitionFor(capability, object) {
  switch (capability) {
    case 'submit.consume-publication':
      return object.expectedState === 'available'
        ? { nextState: 'available', nextGeneration: object.expectedGeneration, reachabilityRecorded: true,
          receiptSha256: object.backendReceiptSha256, result: 'publication-linked' }
        : { nextState: 'available', nextGeneration: object.expectedGeneration + 1, reachabilityRecorded: true,
          receiptSha256: object.verificationReceiptSha256, result: 'quarantine-revived-and-linked' };
    case 'gc.acquire-deleting':
      return { nextState: 'deleting', nextGeneration: object.expectedGeneration + 1,
        reachabilityRecorded: false, receiptSha256: object.backendReceiptSha256, result: 'deleting-acquired' };
    case 'gc.complete-deletion':
      return { nextState: 'deleted', nextGeneration: object.expectedGeneration + 1,
        reachabilityRecorded: false, receiptSha256: object.deletionReceiptSha256, result: 'deletion-recorded' };
    case 'transfer.reverify-deleted':
      return { nextState: 'staged', nextGeneration: object.expectedGeneration + 1,
        reachabilityRecorded: false, receiptSha256: object.verificationReceiptSha256, result: 'deleted-generation-reopened' };
    case 'transfer.record-available':
      return { nextState: 'available', nextGeneration: object.expectedGeneration + 1,
        reachabilityRecorded: false,
        receiptSha256: object.verificationReceiptSha256 ?? object.backendReceiptSha256,
        result: 'availability-recorded' };
    default:
      transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction capability is unknown');
  }
}

function requiredContentManifestPublications(claims) {
  return claims.objects.filter((object) => {
    const transition = transitionFor(claims.capability, object);
    return isContentManifestObjectId(object.objectId)
      && transition.nextState === 'available'
      && transition.nextGeneration !== object.expectedGeneration;
  });
}

function validatePrivateContext(input, claims, production) {
  const required = requiredContentManifestPublications(claims);
  if (required.length === 0) {
    if (input === undefined || input === null) return Object.freeze([]);
    if (!exactKeys(input, PRIVATE_CONTEXT_KEYS)
        || !Array.isArray(input.contentManifestPublications)
        || input.contentManifestPublications.length !== 0) {
      transferError('TRANSFER_INPUT_INVALID', 'lifecycle private content-manifest bindings are invalid');
    }
    return Object.freeze([]);
  }
  if (!production?.registry) {
    transferError('TRANSFER_INPUT_INVALID', 'content-manifest production boundary is unavailable');
  }
  if (!exactKeys(input, PRIVATE_CONTEXT_KEYS)
      || !Array.isArray(input.contentManifestPublications)
      || input.contentManifestPublications.length !== required.length) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied');
  }
  let totalManifestBytes = 0;
  const bindings = input.contentManifestPublications.map((binding, index) => {
    const object = required[index];
    const manifest = binding?.manifest;
    const objectId = binding?.objectId;
    const opaqueKey = binding?.opaqueKey;
    const verificationReceipt = binding?.verificationReceipt;
    if (!exactKeys(binding, CONTENT_MANIFEST_PUBLICATION_KEYS)
        || !SHA.test(opaqueKey ?? '')
        || opaqueKey !== object.opaqueKey
        || typeof objectId !== 'string'
        || objectId !== object.objectId
        || !(manifest instanceof Uint8Array)
        || !verificationReceipt
        || typeof verificationReceipt !== 'object') {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied');
    }
    totalManifestBytes += manifest.byteLength;
    if (!Number.isSafeInteger(totalManifestBytes) || totalManifestBytes > PRIVATE_CONTENT_MANIFEST_BYTES_MAX) {
      transferError('TRANSFER_LIMIT_EXCEEDED', 'content-manifest production manifests exceed the bounded aggregate limit');
    }
    canonicalObjectId(objectId, 'content-manifest production ObjectID');
    return Object.freeze({
      manifest,
      objectId,
      opaqueKey,
      verificationReceipt,
    });
  });
  return Object.freeze(bindings);
}

function contentManifestProductionStatement(input) {
  const statement = {
    boundary: input.boundary,
    logicalBytes: input.logicalBytes,
    manifestObjectId: input.manifestObjectId,
    manifestSha256: input.manifestSha256,
    profile: input.profile,
    verifier: input.verifier,
    wholeFileSha256: input.wholeFileSha256,
  };
  if (!exactKeys(statement, CONTENT_MANIFEST_PRODUCTION_STATEMENT_KEYS)
      || statement.boundary !== PRODUCTION_BOUNDARY_VERSION
      || statement.verifier !== VERIFICATION_RECEIPT_VERIFIER
      || statement.profile !== CHUNKING_PROFILE_TEXT
      || statement.manifestObjectId !== input.manifestObjectId
      || !SHA.test(statement.manifestSha256 ?? '')
      || !SHA.test(statement.wholeFileSha256 ?? '')
      || typeof statement.logicalBytes !== 'string'
      || !/^(0|[1-9][0-9]*)$/u.test(statement.logicalBytes)) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied');
  }
  return Object.freeze(statement);
}

function contentManifestProductionStatementSha256(statement) {
  return sha256(Buffer.concat([
    Buffer.from('OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-PRODUCTION-V1\0'),
    canonicalBytes(statement),
  ]));
}

function productionApplyBarrier(bound, apply, requiredCount) {
  let arrivals = 0;
  let applyPromise = null;
  let failure = null;
  let released = false;
  let resolveRelease;
  const release = new Promise((resolve) => {
    resolveRelease = resolve;
  });
  return Object.freeze({
    reject(error) {
      if (released) return;
      failure = error;
      released = true;
      resolveRelease();
    },
    async commit() {
      arrivals += 1;
      if (arrivals === requiredCount) {
        applyPromise = (async () => validateAdapterResult(await apply(bound.transaction, bound.command), bound.command))();
        if (!released) {
          released = true;
          resolveRelease();
        }
      } else if (!applyPromise) {
        await release;
      }
      if (failure) throw failure;
      return applyPromise;
    },
    get result() {
      if (failure) throw failure;
      return applyPromise;
    },
  });
}

function productionPublicationFor(object, barrier) {
  let wrote = false;
  return Object.freeze({
    write(_bytes, context) {
      if (wrote || context.manifestObjectId !== object.objectId) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied');
      }
      wrote = true;
    },
    commit(context) {
      if (!wrote || context.manifestObjectId !== object.objectId) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied');
      }
      const statement = contentManifestProductionStatement(context);
      if (contentManifestProductionStatementSha256(statement) !== object.verificationReceiptSha256) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied');
      }
      return barrier.commit();
    },
    abort() {
      wrote = false;
      return true;
    },
  });
}

async function authorizeContentManifestPublications(bound, production, apply) {
  const required = requiredContentManifestPublications(bound.command.context);
  if (required.length === 0) {
    return validateAdapterResult(await apply(bound.transaction, bound.command), bound.command);
  }
  const barrier = productionApplyBarrier(bound, apply, required.length);
  const pending = required.map((object, index) => {
    const binding = bound.privateContentManifestPublications[index];
    return commitProductionManifest({
      registry: production.registry,
      manifest: binding.manifest,
      verificationReceipt: binding.verificationReceipt,
      publication: productionPublicationFor(object, barrier),
    }).catch((error) => {
      barrier.reject(error);
      throw error;
    });
  });
  const settled = await Promise.allSettled(pending);
  const failure = settled.find((entry) => entry.status === 'rejected');
  if (failure) {
    const cause = failure.reason;
    if (cause && typeof cause === 'object' && 'code' in cause && `${cause.code}`.startsWith('CHUNK_')) {
      if (cause.code === 'CHUNK_PUBLICATION_FAILED' && cause.cause) throw cause.cause;
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production receipt was denied', { cause });
    }
    throw cause;
  }
  return barrier.result;
}

function resourceId(secret, claims, object) {
  const digest = createHmac('sha256', secret)
    .update('OGVCS-LIFECYCLE-RESOURCE-ID-V1\0')
    .update(claims.tenantId)
    .update('\0')
    .update(claims.repositoryId)
    .update('\0')
    .update(object.opaqueKey)
    .digest('base64url');
  return `or1.${digest}`;
}

function expectedCommand(secret, claims) {
  const contextDigestSha256 = sha256(canonicalBytes(claims));
  const objects = [];
  const facts = [];
  for (const object of claims.objects) {
    const transition = transitionFor(claims.capability, object);
    const resourceOpaqueId = resourceId(secret, claims, object);
    const result = Object.freeze({
      opaqueKey: object.opaqueKey,
      priorState: object.expectedState,
      priorGeneration: object.expectedGeneration,
      nextState: transition.nextState,
      nextGeneration: transition.nextGeneration,
      backendReceiptSha256: object.backendReceiptSha256,
      healthGeneration: object.expectedHealthGeneration,
      reachabilityRecorded: transition.reachabilityRecorded,
    });
    const factBase = Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/lifecycle-transaction-fact/v1',
      transactionId: claims.transactionId,
      capability: claims.capability,
      tenantId: claims.tenantId,
      repositoryId: claims.repositoryId,
      authorizationEpoch: claims.authorizationEpoch,
      resourceOpaqueId,
      priorState: object.expectedState,
      priorGeneration: object.expectedGeneration,
      nextState: transition.nextState,
      nextGeneration: transition.nextGeneration,
      receiptSha256: transition.receiptSha256,
      result: transition.result,
    });
    if (!RESOURCE_ID.test(resourceOpaqueId)) transferError('TRANSFER_BACKEND_CORRUPT', 'opaque lifecycle resource ID is invalid');
    objects.push(result);
    facts.push(Object.freeze({ ...factBase, factSha256: sha256(canonicalBytes(factBase)) }));
  }
  return deepFreeze({
    schemaVersion: 'ogvcs.object-transfer/lifecycle-transaction-command/v1',
    contextDigestSha256,
    context: claims,
    expectedObjects: objects,
    expectedFacts: facts,
  });
}

function validateAdapterResult(input, command) {
  const value = cloneJson(input, { maxBytes: 1024 * 1024 });
  if (!exactKeys(value, ADAPTER_RESULT_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/lifecycle-transaction-adapter-result/v1'
      || value.contextDigestSha256 !== command.contextDigestSha256
      || value.transactionId !== command.context.transactionId
      || value.capability !== command.context.capability
      || !Array.isArray(value.objects) || !Array.isArray(value.persistedFacts)
      || value.objects.length !== command.expectedObjects.length
      || value.persistedFacts.length !== command.expectedFacts.length) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle transaction adapter result is invalid');
  }
  for (let index = 0; index < value.objects.length; index += 1) {
    if (!exactKeys(value.objects[index], RESULT_OBJECT_KEYS)
        || !canonicalBytes(value.objects[index]).equals(canonicalBytes(command.expectedObjects[index]))) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle transaction adapter substituted an object result');
    }
    const acknowledgement = value.persistedFacts[index];
    if (!exactKeys(acknowledgement, FACT_ACK_KEYS)
        || acknowledgement.factSha256 !== command.expectedFacts[index].factSha256
        || !UUID.test(acknowledgement.auditRecordId ?? '')
        || !UUID.test(acknowledgement.outboxEventId ?? '')) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle transaction fact acknowledgement is invalid');
    }
  }
  if (new Set(value.persistedFacts.map(({ auditRecordId }) => auditRecordId)).size !== value.persistedFacts.length
      || new Set(value.persistedFacts.map(({ outboxEventId }) => outboxEventId)).size !== value.persistedFacts.length) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle transaction fact identities are not unique');
  }
  return deepFreeze(value);
}

export function createLifecycleTransactionBoundary({ apply, contentManifestProduction, poison, resourceSecret } = {}) {
  if (typeof apply !== 'function' || typeof poison !== 'function'
      || !(resourceSecret instanceof Uint8Array) || resourceSecret.byteLength < 32) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction boundary configuration is invalid');
  }
  const secret = Buffer.from(resourceSecret);
  const contexts = new WeakMap();
  const owner = Object.freeze({
    bind(transaction, input, privateContext = undefined) {
      if (!transaction || !['object', 'function'].includes(typeof transaction)) {
        transferError('TRANSFER_INPUT_INVALID', 'lifecycle transaction owner handle is invalid');
      }
      const claims = validateClaims(input);
      const command = expectedCommand(secret, claims);
      const privateContentManifestPublications = validatePrivateContext(privateContext, claims, contentManifestProduction);
      const context = Object.freeze({
        schemaVersion: 'ogvcs.object-transfer/lifecycle-transaction-capability/v1',
        capability: claims.capability,
        contextDigestSha256: command.contextDigestSha256,
      });
      contexts.set(context, {
        transaction,
        command,
        privateContentManifestPublications,
        state: 'ready',
        outcome: null,
      });
      return context;
    },
  });
  async function execute(context, requiredCapability) {
    const bound = context && typeof context === 'object' ? contexts.get(context) : null;
    if (!bound) transferError('TRANSFER_AUTHORIZATION_DENIED', 'lifecycle transaction capability was denied');
    if (bound.command.context.capability !== requiredCapability) {
      bound.state = 'poisoned';
      await poison(bound.transaction).catch(() => {});
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'lifecycle transaction capability was denied');
    }
    if (bound.state === 'complete' || bound.state === 'running') return bound.outcome;
    if (bound.state === 'poisoned') transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle transaction is poisoned');
    bound.state = 'running';
    bound.outcome = (async () => {
      try {
        const result = await authorizeContentManifestPublications(bound, contentManifestProduction, apply);
        bound.state = 'complete';
        return result;
      } catch (error) {
        bound.state = 'poisoned';
        await poison(bound.transaction).catch(() => {});
        throw error;
      }
    })();
    return bound.outcome;
  }
  const participant = Object.freeze({
    consumePublication: (context) => execute(context, 'submit.consume-publication'),
    acquireDeleting: (context) => execute(context, 'gc.acquire-deleting'),
    completeDeletion: (context) => execute(context, 'gc.complete-deletion'),
    reverifyDeleted: (context) => execute(context, 'transfer.reverify-deleted'),
    recordAvailable: (context) => execute(context, 'transfer.record-available'),
  });
  return Object.freeze({ owner, participant });
}
