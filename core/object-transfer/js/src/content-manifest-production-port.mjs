import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import { ObjectRef, validateRegistrySet } from '@opengamevcs/object-model';
import { canonicalBytes, cloneJson } from '@opengamevcs/protocol-baseline';
import { transferError } from './errors.mjs';

const PORTS = new WeakMap();
const AUTHORITIES = new WeakMap();
const TRANSACTIONS = new WeakMap();

const SHA = /^[0-9a-f]{64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ADAPTER_METHODS = Object.freeze([
  'abortAvailability',
  'authorizeDependencyRead',
  'beginAvailability',
  'commitAvailability',
  'lookupCommittedCurrent',
  'mapGrantAuthority',
  'readCurrent',
]);
const CAPABILITY_KEYS = [
  'atomicWithRepositoryMetadata',
  'authenticatedCurrentLookup',
  'committedReplayProof',
  'dependencyAuthorizationProfile',
  'dependencyGenerationsAtomicThroughCommit',
  'generationFenced',
  'grantBoundDependencyReads',
  'lifecycleContractVersion',
  'requestRootDependencyClosure',
  'schemaVersion',
  'storageAuthority',
].sort().join('\0');
const AUTHORITY_REQUEST_KEYS = [
  'authorizationClosureSha256',
  'authorityBindingSha256',
  'grantBindingSha256',
  'grantObjectIds',
  'grantRepository',
  'grantRequestRoot',
  'grantTenant',
  'schemaVersion',
  'subjectDigestSha256',
  'tenantScopeSha256',
].sort().join('\0');
const AUTHORITY_MAPPING_KEYS = [
  'grantRepository',
  'grantTenant',
  'repositoryId',
  'schemaVersion',
  'tenantId',
].sort().join('\0');
const LOOKUP_KEYS = [
  'authorizationClosureSha256',
  'authorityBindingSha256',
  'backendReceiptSha256',
  'finalizeSemanticFingerprint',
  'length',
  'objectId',
  'opaqueKey',
  'schemaVersion',
  'subjectDigestSha256',
  'tenantScopeSha256',
].sort().join('\0');
const CURRENT_REQUEST_KEYS = [
  'authorityBindingSha256',
  'durableBackendReceiptSha256',
  'length',
  'objectId',
  'opaqueKey',
  'schemaVersion',
].sort().join('\0');
const CURRENT_KEYS = [
  'authorityBindingSha256',
  'backendReceiptSha256',
  'durableBackendReceiptSha256',
  'generation',
  'length',
  'objectId',
  'opaqueKey',
  'repositoryId',
  'schemaVersion',
  'state',
  'tenantId',
  'verificationReceiptSha256',
].sort().join('\0');
const DEPENDENCY_REQUEST_KEYS = [
  'dependencyLength',
  'dependencyObjectId',
  'dependencyOpaqueKey',
  'grantBindingSha256',
  'manifestObjectId',
  'manifestOpaqueKey',
  'schemaVersion',
].sort().join('\0');
const PRODUCTION_STATEMENT_KEYS = [
  'boundary',
  'logicalBytes',
  'manifestObjectId',
  'manifestSha256',
  'profile',
  'verifier',
  'wholeFileSha256',
].sort().join('\0');
const COMMITTED_KEYS = [
  'applicationId',
  'authorizationClosureSha256',
  'authorityBindingSha256',
  'backendReceiptSha256',
  'dependencyGenerationSetSha256',
  'dependencyCount',
  'finalizeSemanticFingerprint',
  'generation',
  'length',
  'objectId',
  'opaqueKey',
  'productionStatement',
  'productionStatementSha256',
  'proofSha256',
  'repositoryId',
  'schemaVersion',
  'state',
  'subjectDigestSha256',
  'tenantId',
  'tenantScopeSha256',
  'verificationReceiptSha256',
].sort().join('\0');
const COMMIT_COMMAND_KEYS = [
  'authorizationClosureSha256',
  'authorityBindingSha256',
  'backendReceiptSha256',
  'expectedGeneration',
  'expectedState',
  'finalizeSemanticFingerprint',
  'length',
  'objectId',
  'opaqueKey',
  'productionStatement',
  'productionStatementSha256',
  'repositoryId',
  'schemaVersion',
  'subjectDigestSha256',
  'targetGeneration',
  'targetState',
  'tenantId',
  'tenantScopeSha256',
  'verificationReceiptSha256',
].sort().join('\0');
const ADAPTER_COMMIT_COMMAND_KEYS = [
  ...COMMIT_COMMAND_KEYS.split('\0'),
  'dependencyCount',
  'dependencyGenerationSetSha256',
].sort().join('\0');

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function exactKeys(value, keys) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === keys);
}

function invalid(message) {
  transferError('TRANSFER_INPUT_INVALID', message);
}

function corrupt(message) {
  transferError('TRANSFER_BACKEND_CORRUPT', message);
}

function adapterFailure(error) {
  let code = null;
  if ((typeof error === 'object' && error !== null) || typeof error === 'function') {
    try {
      if (!utilTypes.isProxy(error)) {
        const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
        if (descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string'
            && descriptor.value.length <= 64) code = descriptor.value;
      }
    } catch {
      code = null;
    }
  }
  if (code === 'TRANSFER_AUTHORIZATION_DENIED') {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'repository-metadata content-manifest authorization was denied');
  }
  if (code === 'TRANSFER_LIFECYCLE_STALE') {
    transferError('TRANSFER_LIFECYCLE_STALE', 'repository-metadata content-manifest generation is stale');
  }
  if (code === 'TRANSFER_BACKEND_CORRUPT') {
    transferError('TRANSFER_BACKEND_CORRUPT', 'repository-metadata content-manifest response is invalid');
  }
  transferError('TRANSFER_BACKEND_IO', 'repository-metadata content-manifest operation failed');
}

async function invokeAdapter(operation) {
  try { return await operation(); }
  catch (error) { adapterFailure(error); }
}

function deepFreezePassive(value) {
  const pending = [value];
  const seen = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) pending.push(child);
    Object.freeze(current);
  }
  return value;
}

function canonicalObjectId(value, failure = corrupt) {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value) throw new TypeError('ObjectID is not canonical');
    return value;
  } catch (error) {
    failure('content-manifest production ObjectID is invalid', { cause: error });
  }
}

function exactCapabilities(input) {
  let value;
  try { value = deepFreezePassive(cloneJson(input, { maxBytes: 16 * 1024 })); }
  catch (error) { invalid('content-manifest production candidate capabilities are invalid', { cause: error }); }
  if (!exactKeys(value, CAPABILITY_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-production-candidate-capabilities/v1'
      || value.storageAuthority !== 'repository-metadata'
      || typeof value.lifecycleContractVersion !== 'string'
      || !/^[A-Za-z0-9._/@-]{1,128}$/u.test(value.lifecycleContractVersion)
      || value.atomicWithRepositoryMetadata !== true
      || value.authenticatedCurrentLookup !== true
      || value.committedReplayProof !== true
      || value.dependencyAuthorizationProfile !== 'explicit-grant-object-set/v1'
      || value.dependencyGenerationsAtomicThroughCommit !== true
      || value.generationFenced !== true
      || value.grantBoundDependencyReads !== true
      || value.requestRootDependencyClosure !== false) {
    invalid('content-manifest production candidate capabilities are invalid');
  }
  return value;
}

function captureAdapter(input) {
  if (!input || typeof input !== 'object' || utilTypes.isProxy(input)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) {
    invalid('content-manifest production candidate adapter is invalid');
  }
  let descriptors;
  try { descriptors = Object.getOwnPropertyDescriptors(input); }
  catch (error) { invalid('content-manifest production candidate adapter is invalid', { cause: error }); }
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')
      || Object.keys(descriptors).sort().join('\0') !== [...ADAPTER_METHODS].sort().join('\0')) {
    invalid('content-manifest production candidate adapter is invalid');
  }
  const captured = {};
  for (const method of ADAPTER_METHODS) {
    const descriptor = descriptors[method];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'function') {
      invalid('content-manifest production candidate adapter is invalid');
    }
    captured[method] = descriptor.value.bind(input);
  }
  return Object.freeze(captured);
}

function passive(
  value,
  maximum = 1024 * 1024,
  failure = invalid,
  message = 'content-manifest production candidate passive binding is invalid',
) {
  if (utilTypes.isProxy(value)) failure(message);
  try {
    return deepFreezePassive(cloneJson(value, {
      maxBytes: maximum,
      maxDepth: 64,
      maxNodes: 100_000,
      maxCollectionItems: 100_000,
    }));
  } catch (error) {
    failure(message, { cause: error });
  }
}

function sha(value) { return typeof value === 'string' && SHA.test(value); }

function authorizationClosureSha256(objectIds, requestRoot) {
  return sha256(Buffer.concat([
    Buffer.from('OGVCS-OBJECT-TRANSFER-AUTHORIZATION-CLOSURE-V1\0'),
    canonicalBytes({ objectIds: [...objectIds].sort(), requestRoot }),
  ]));
}

function validateAuthorityRequest(input) {
  const value = passive(input, 1024 * 1024);
  if (!exactKeys(value, AUTHORITY_REQUEST_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-grant-authority/v1'
      || typeof value.grantTenant !== 'string' || value.grantTenant.length < 1 || value.grantTenant.length > 256
      || typeof value.grantRepository !== 'string' || value.grantRepository.length < 1
      || value.grantRepository.length > 256
      || !Array.isArray(value.grantObjectIds) || value.grantObjectIds.length < 1
      || value.grantObjectIds.length > 4096 || value.grantRequestRoot !== null
      || new Set(value.grantObjectIds).size !== value.grantObjectIds.length
      || !sha(value.subjectDigestSha256) || !sha(value.authorityBindingSha256)
      || !sha(value.authorizationClosureSha256)
      || !sha(value.tenantScopeSha256) || !sha(value.grantBindingSha256)) {
    invalid('content-manifest grant authority binding is invalid');
  }
  for (const objectId of value.grantObjectIds) canonicalObjectId(objectId, invalid);
  if (value.authorizationClosureSha256
      !== authorizationClosureSha256(value.grantObjectIds, value.grantRequestRoot)) {
    invalid('content-manifest grant authority binding is invalid');
  }
  return value;
}

function validateAuthorityMapping(input, request) {
  const value = passive(
    input,
    64 * 1024,
    corrupt,
    'repository-metadata authority mapping is invalid',
  );
  if (!exactKeys(value, AUTHORITY_MAPPING_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/repository-metadata-authority/v1'
      || value.grantTenant !== request.grantTenant || value.grantRepository !== request.grantRepository
      || !UUID.test(value.tenantId ?? '') || !UUID.test(value.repositoryId ?? '')) {
    corrupt('repository-metadata authority mapping is invalid');
  }
  return value;
}

function validateLookup(input) {
  const value = passive(input, 64 * 1024);
  if (!exactKeys(value, LOOKUP_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-availability-lookup/v1'
      || !sha(value.opaqueKey) || !sha(value.authorityBindingSha256)
      || !sha(value.authorizationClosureSha256)
      || !sha(value.tenantScopeSha256) || !sha(value.subjectDigestSha256)
      || !sha(value.backendReceiptSha256) || !sha(value.finalizeSemanticFingerprint)
      || !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 67_108_864) {
    invalid('content-manifest availability lookup is invalid');
  }
  canonicalObjectId(value.objectId, invalid);
  return value;
}

function validateCurrentRequest(input) {
  const value = passive(input, 64 * 1024);
  if (!exactKeys(value, CURRENT_REQUEST_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-current-request/v1'
      || !sha(value.opaqueKey)
      || !(value.authorityBindingSha256 === null || sha(value.authorityBindingSha256))
      || !(value.durableBackendReceiptSha256 === null || sha(value.durableBackendReceiptSha256))
      || !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 67_108_864) {
    invalid('content-manifest current-object request is invalid');
  }
  canonicalObjectId(value.objectId, invalid);
  return value;
}

function validateDependencyRequest(input, bound) {
  const value = passive(input, 64 * 1024);
  if (!exactKeys(value, DEPENDENCY_REQUEST_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-dependency-read/v1'
      || value.manifestOpaqueKey !== bound.request.opaqueKey
      || value.manifestObjectId !== bound.request.objectId
      || value.grantBindingSha256 !== bound.authority.request.grantBindingSha256
      || !sha(value.dependencyOpaqueKey)
      || !Number.isSafeInteger(value.dependencyLength) || value.dependencyLength < 1
      || value.dependencyLength > 67_108_864) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest dependency read was denied');
  }
  const parsed = ObjectRef.parse(canonicalObjectId(value.dependencyObjectId, invalid));
  if (parsed.kindName !== 'chunk' || value.dependencyObjectId === value.manifestObjectId
      || !bound.authority.request.grantObjectIds.includes(value.dependencyObjectId)) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest dependency read was denied');
  }
  return value;
}

function validateCurrent(input, mapping, request) {
  const value = passive(
    input,
    64 * 1024,
    corrupt,
    'repository-metadata current object binding is invalid',
  );
  if (!exactKeys(value, CURRENT_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-current-object/v1'
      || value.tenantId !== mapping.tenantId || value.repositoryId !== mapping.repositoryId
      || value.opaqueKey !== request.opaqueKey || value.objectId !== request.objectId
      || value.length !== request.length
      || (request.authorityBindingSha256 !== null
        && value.authorityBindingSha256 !== request.authorityBindingSha256)
      || (request.durableBackendReceiptSha256 !== null
        && value.durableBackendReceiptSha256 !== request.durableBackendReceiptSha256)
      || !sha(value.authorityBindingSha256) || !sha(value.durableBackendReceiptSha256)
      || !['staged', 'available', 'quarantined', 'deleting', 'deleted'].includes(value.state)
      || !Number.isSafeInteger(value.generation) || value.generation < 1
      || !(value.backendReceiptSha256 === null || sha(value.backendReceiptSha256))
      || !(value.verificationReceiptSha256 === null || sha(value.verificationReceiptSha256))) {
    corrupt('repository-metadata current object binding is invalid');
  }
  const parsed = ObjectRef.parse(canonicalObjectId(value.objectId));
  const isManifest = parsed.kindName === 'content-manifest';
  if (value.state === 'staged') {
    if (value.backendReceiptSha256 !== null || value.verificationReceiptSha256 !== null) {
      corrupt('staged content-manifest current binding carries a published receipt');
    }
  } else if (['available', 'quarantined', 'deleting'].includes(value.state)) {
    if (value.backendReceiptSha256 !== value.durableBackendReceiptSha256
        || isManifest !== (value.verificationReceiptSha256 !== null)) {
      corrupt('published current-object receipt binding is invalid');
    }
  }
  return value;
}

function validateStatement(input, objectId) {
  const value = passive(input, 64 * 1024);
  if (!exactKeys(value, PRODUCTION_STATEMENT_KEYS)
      || value.boundary !== 'ogvcs.chunking-manifest/production-boundary@1'
      || value.verifier !== 'ogvcs.chunking-manifest/verifier@1'
      || value.profile !== 'chunking.opengamevcs/gear-fastcdc-1m@1'
      || value.manifestObjectId !== objectId
      || !sha(value.manifestSha256) || !sha(value.wholeFileSha256)
      || typeof value.logicalBytes !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(value.logicalBytes)) {
    corrupt('content-manifest production statement is invalid');
  }
  return value;
}

function committedProofDigest(value) {
  const { proofSha256: _proofSha256, ...body } = value;
  return sha256(Buffer.concat([
    Buffer.from('OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-COMMITTED-PROOF-V1\0'),
    canonicalBytes(body),
  ]));
}

function dependencyGenerationSetSha256(currents) {
  const digest = createHash('sha256');
  digest.update('OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-DEPENDENCY-GENERATIONS-V1\0');
  const count = Buffer.alloc(4);
  count.writeUInt32BE(currents.length);
  digest.update(count);
  for (const current of currents) {
    const encoded = canonicalBytes(current, { maxBytes: 64 * 1024 });
    const length = Buffer.alloc(4);
    length.writeUInt32BE(encoded.byteLength);
    digest.update(length);
    digest.update(encoded);
  }
  return digest.digest('hex');
}

export function contentManifestDependencyGenerationSetSha256(input) {
  if (!Array.isArray(input) || utilTypes.isProxy(input) || input.length > 4096) {
    invalid('content-manifest dependency generation set is invalid');
  }
  const currents = input.map((current) => passive(current, 64 * 1024));
  for (const current of currents) {
    if (!exactKeys(current, CURRENT_KEYS)
        || current.schemaVersion !== 'ogvcs.object-transfer/content-manifest-current-object/v1'
        || !UUID.test(current.tenantId ?? '') || !UUID.test(current.repositoryId ?? '')
        || !sha(current.opaqueKey) || !sha(current.authorityBindingSha256)
        || !sha(current.backendReceiptSha256) || !sha(current.durableBackendReceiptSha256)
        || current.backendReceiptSha256 !== current.durableBackendReceiptSha256
        || current.verificationReceiptSha256 !== null || current.state !== 'available'
        || !Number.isSafeInteger(current.generation) || current.generation < 1
        || !Number.isSafeInteger(current.length) || current.length < 1
        || current.length > 67_108_864
        || ObjectRef.parse(canonicalObjectId(current.objectId, invalid)).kindName !== 'chunk') {
      invalid('content-manifest dependency generation set is invalid');
    }
  }
  const ordered = [...currents].sort((left, right) => (
    left.opaqueKey < right.opaqueKey ? -1 : left.opaqueKey > right.opaqueKey ? 1 : 0
  ));
  if (new Set(ordered.map(({ opaqueKey }) => opaqueKey)).size !== ordered.length) {
    invalid('content-manifest dependency generation set is invalid');
  }
  return dependencyGenerationSetSha256(ordered);
}

export function contentManifestCommittedProofSha256(input) {
  return committedProofDigest(passive(input, 256 * 1024));
}

export function contentManifestProductionStatementSha256(input) {
  const snapshot = passive(input, 64 * 1024);
  const safe = validateStatement(snapshot, snapshot.manifestObjectId);
  return sha256(Buffer.concat([
    Buffer.from('OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-PRODUCTION-V1\0'),
    canonicalBytes(safe),
  ]));
}

function validateCommitted(input, mapping, lookup) {
  const value = passive(
    input,
    256 * 1024,
    corrupt,
    'repository-metadata committed content-manifest proof is invalid',
  );
  if (!exactKeys(value, COMMITTED_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-committed-current/v1'
      || value.state !== 'available' || !UUID.test(value.applicationId ?? '')
      || value.tenantId !== mapping.tenantId || value.repositoryId !== mapping.repositoryId
      || value.opaqueKey !== lookup.opaqueKey || value.objectId !== lookup.objectId
      || value.length !== lookup.length || value.authorityBindingSha256 !== lookup.authorityBindingSha256
      || value.authorizationClosureSha256 !== lookup.authorizationClosureSha256
      || value.tenantScopeSha256 !== lookup.tenantScopeSha256
      || value.subjectDigestSha256 !== lookup.subjectDigestSha256
      || value.backendReceiptSha256 !== lookup.backendReceiptSha256
      || value.finalizeSemanticFingerprint !== lookup.finalizeSemanticFingerprint
      || !Number.isSafeInteger(value.generation) || value.generation < 2
      || !Number.isSafeInteger(value.dependencyCount) || value.dependencyCount < 0
      || value.dependencyCount > 4096
      || !sha(value.dependencyGenerationSetSha256)
      || !sha(value.verificationReceiptSha256) || !sha(value.productionStatementSha256)
      || value.verificationReceiptSha256 !== value.productionStatementSha256
      || !sha(value.proofSha256)) {
    corrupt('repository-metadata committed content-manifest proof is invalid');
  }
  const statement = validateStatement(value.productionStatement, value.objectId);
  const statementSha256 = contentManifestProductionStatementSha256(statement);
  if (statementSha256 !== value.productionStatementSha256
      || committedProofDigest(value) !== value.proofSha256) {
    corrupt('repository-metadata committed content-manifest proof digest is invalid');
  }
  return value;
}

function validateCommitCommand(input, bound) {
  const value = passive(input, 256 * 1024);
  const current = bound.currents.get(bound.request.opaqueKey);
  if (!current || !exactKeys(value, COMMIT_COMMAND_KEYS)
      || value.schemaVersion !== 'ogvcs.object-transfer/content-manifest-availability-commit/v1'
      || value.tenantId !== bound.authority.mapping.tenantId
      || value.repositoryId !== bound.authority.mapping.repositoryId
      || value.opaqueKey !== bound.request.opaqueKey || value.objectId !== bound.request.objectId
      || value.length !== bound.request.length
      || value.authorityBindingSha256 !== bound.request.authorityBindingSha256
      || value.authorizationClosureSha256 !== bound.request.authorizationClosureSha256
      || value.tenantScopeSha256 !== bound.request.tenantScopeSha256
      || value.subjectDigestSha256 !== bound.request.subjectDigestSha256
      || value.backendReceiptSha256 !== bound.request.backendReceiptSha256
      || value.finalizeSemanticFingerprint !== bound.request.finalizeSemanticFingerprint
      || value.expectedState !== 'staged' || value.targetState !== 'available'
      || value.expectedGeneration !== current.generation
      || value.targetGeneration !== current.generation + 1
      || current.state !== 'staged' || current.backendReceiptSha256 !== null
      || current.verificationReceiptSha256 !== null
      || value.verificationReceiptSha256 !== value.productionStatementSha256
      || !sha(value.verificationReceiptSha256)) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest availability commit was denied');
  }
  const statement = validateStatement(value.productionStatement, value.objectId);
  if (contentManifestProductionStatementSha256(statement) !== value.productionStatementSha256) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest availability commit was denied');
  }
  return value;
}

function validateCommittedAgainstCommand(committed, command) {
  if (committed.state !== command.targetState
      || committed.generation !== command.targetGeneration
      || committed.tenantId !== command.tenantId
      || committed.repositoryId !== command.repositoryId
      || committed.opaqueKey !== command.opaqueKey
      || committed.objectId !== command.objectId
      || committed.length !== command.length
      || committed.authorityBindingSha256 !== command.authorityBindingSha256
      || committed.authorizationClosureSha256 !== command.authorizationClosureSha256
      || committed.tenantScopeSha256 !== command.tenantScopeSha256
      || committed.subjectDigestSha256 !== command.subjectDigestSha256
      || committed.backendReceiptSha256 !== command.backendReceiptSha256
      || committed.dependencyCount !== command.dependencyCount
      || committed.dependencyGenerationSetSha256 !== command.dependencyGenerationSetSha256
      || committed.verificationReceiptSha256 !== command.verificationReceiptSha256
      || committed.finalizeSemanticFingerprint !== command.finalizeSemanticFingerprint
      || committed.productionStatementSha256 !== command.productionStatementSha256
      || !canonicalBytes(committed.productionStatement, { maxBytes: 64 * 1024 })
        .equals(canonicalBytes(command.productionStatement, { maxBytes: 64 * 1024 }))) {
    corrupt('repository-metadata commit result differs from the accepted production command');
  }
  return committed;
}

function bindLookupToAuthority(request, authority) {
  if (request.authorityBindingSha256 !== authority.request.authorityBindingSha256
      || request.authorizationClosureSha256 !== authority.request.authorizationClosureSha256
      || request.tenantScopeSha256 !== authority.request.tenantScopeSha256
      || request.subjectDigestSha256 !== authority.request.subjectDigestSha256
      || !authority.request.grantObjectIds.includes(request.objectId)) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest lookup authority binding was denied');
  }
  return request;
}

function authorityRecord(portRecord, authority) {
  const value = AUTHORITIES.get(authority);
  if (!value || value.portRecord !== portRecord) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production authority was denied');
  }
  return value;
}

function transactionRecord(portRecord, transaction) {
  const value = TRANSACTIONS.get(transaction);
  if (!value || value.portRecord !== portRecord) {
    transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest production transaction was denied');
  }
  return value;
}

function trustedFacade(portRecord) {
  return Object.freeze({
    capabilities: portRecord.capabilities,
    registry: portRecord.registry,
    async mapGrantAuthority(input) {
      const request = validateAuthorityRequest(input);
      const mapping = validateAuthorityMapping(
        await invokeAdapter(() => portRecord.adapter.mapGrantAuthority(request)),
        request,
      );
      const handle = Object.freeze(Object.create(null));
      AUTHORITIES.set(handle, Object.freeze({ portRecord, request, mapping }));
      return Object.freeze({ handle, mapping });
    },
    async lookupCommittedCurrent(authority, input) {
      const bound = authorityRecord(portRecord, authority);
      const request = bindLookupToAuthority(validateLookup(input), bound);
      const result = await invokeAdapter(() => portRecord.adapter.lookupCommittedCurrent(
        bound.mapping, request, bound.request,
      ));
      return result === null ? null : validateCommitted(result, bound.mapping, request);
    },
    async beginAvailability(authority, input) {
      const bound = authorityRecord(portRecord, authority);
      const request = bindLookupToAuthority(validateLookup(input), bound);
      const raw = await invokeAdapter(() => portRecord.adapter.beginAvailability(
        bound.mapping, request, bound.request,
      ));
      if (!raw || !['object', 'function'].includes(typeof raw)) {
        corrupt('repository-metadata availability transaction handle is invalid');
      }
      const handle = Object.freeze(Object.create(null));
      TRANSACTIONS.set(handle, {
        portRecord,
        raw,
        authority: bound,
        request,
        state: 'ready',
        abortAttempted: false,
        currents: new Map(),
        dependencies: new Map(),
      });
      return handle;
    },
    async authorizeDependencyRead(transaction, input) {
      const bound = transactionRecord(portRecord, transaction);
      if (bound.state !== 'ready') {
        transferError('TRANSFER_LIFECYCLE_STALE', 'content-manifest production transaction is not authorizable');
      }
      const request = validateDependencyRequest(input, bound);
      const prior = bound.dependencies.get(request.dependencyOpaqueKey);
      if (prior && canonicalBytes(prior.request).equals(canonicalBytes(request))) return true;
      if (!prior && bound.dependencies.size >= 4096) {
        transferError('TRANSFER_LIMIT_EXCEEDED', 'content-manifest dependency count exceeds the grant bound');
      }
      const allowed = await invokeAdapter(() => portRecord.adapter.authorizeDependencyRead(
        bound.raw,
        bound.authority.mapping,
        request,
        bound.authority.request,
      ));
      if (allowed !== true) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest dependency read was denied');
      }
      bound.dependencies.set(request.dependencyOpaqueKey, { request, current: null });
      return true;
    },
    async readCurrent(transaction, input) {
      const bound = transactionRecord(portRecord, transaction);
      if (bound.state !== 'ready') {
        transferError('TRANSFER_LIFECYCLE_STALE', 'content-manifest production transaction is not readable');
      }
      const request = validateCurrentRequest(input);
      const isManifest = request.opaqueKey === bound.request.opaqueKey
        && request.objectId === bound.request.objectId
        && request.length === bound.request.length;
      const dependency = bound.dependencies.get(request.opaqueKey);
      if (!isManifest && (!dependency
          || dependency.request.dependencyObjectId !== request.objectId
          || dependency.request.dependencyLength !== request.length)) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest dependency read was denied');
      }
      const current = validateCurrent(
        await invokeAdapter(() => portRecord.adapter.readCurrent(
          bound.raw, bound.authority.mapping, request,
        )),
        bound.authority.mapping,
        request,
      );
      bound.currents.set(request.opaqueKey, current);
      if (dependency) dependency.current = current;
      return current;
    },
    async commitAvailability(transaction, input) {
      const bound = transactionRecord(portRecord, transaction);
      if (bound.state !== 'ready') {
        transferError('TRANSFER_LIFECYCLE_STALE', 'content-manifest production transaction is not committable');
      }
      const command = validateCommitCommand(input, bound);
      const dependencyCurrents = [...bound.dependencies.values()].map((dependency) => {
        const current = dependency.current;
        if (!current || current.state !== 'available'
            || current.objectId !== dependency.request.dependencyObjectId
            || current.opaqueKey !== dependency.request.dependencyOpaqueKey
            || current.length !== dependency.request.dependencyLength
            || current.backendReceiptSha256 !== current.durableBackendReceiptSha256
            || current.verificationReceiptSha256 !== null) {
          transferError('TRANSFER_LIFECYCLE_STALE', 'content-manifest dependency was not locked at an available generation');
        }
        return current;
      }).sort((left, right) => (left.opaqueKey < right.opaqueKey ? -1 : left.opaqueKey > right.opaqueKey ? 1 : 0));
      const adapterCommand = passive({
        ...command,
        dependencyCount: dependencyCurrents.length,
        dependencyGenerationSetSha256: contentManifestDependencyGenerationSetSha256(dependencyCurrents),
      }, 256 * 1024);
      if (!exactKeys(adapterCommand, ADAPTER_COMMIT_COMMAND_KEYS)) {
        corrupt('content-manifest dependency commit binding is invalid');
      }
      bound.state = 'committing';
      try {
        const result = await invokeAdapter(() => portRecord.adapter.commitAvailability(
          bound.raw,
          bound.authority.mapping,
          adapterCommand,
        ));
        const committed = validateCommittedAgainstCommand(
          validateCommitted(result, bound.authority.mapping, bound.request),
          adapterCommand,
        );
        bound.state = 'committed';
        return committed;
      } catch (error) {
        bound.state = 'uncertain';
        throw error;
      }
    },
    async abortAvailability(transaction) {
      const bound = transactionRecord(portRecord, transaction);
      if (bound.state === 'committed' || bound.state === 'aborted' || bound.abortAttempted) return false;
      bound.abortAttempted = true;
      try {
        await invokeAdapter(() => portRecord.adapter.abortAvailability(
          bound.raw, bound.authority.mapping,
        ));
      } finally {
        bound.state = 'aborted';
      }
      return true;
    },
  });
}

/**
 * Candidate-only OGVCS-008 bridge for an owning repository-metadata adapter.
 *
 * The returned object is an opaque brand. It deliberately exposes no adapter
 * functions or registry object; ObjectTransferService resolves both through a
 * package-private WeakMap and snapshots every passive value at the boundary.
 */
export function createRepositoryMetadataContentManifestCandidatePort({
  adapter,
  capabilities,
  registryDocuments,
} = {}) {
  const captured = captureAdapter(adapter);
  const exact = exactCapabilities(capabilities);
  let documents;
  let registry;
  try {
    documents = cloneJson(registryDocuments, {
      maxBytes: 1024 * 1024,
      maxDepth: 64,
      maxNodes: 100_000,
      maxCollectionItems: 100_000,
    });
    registry = validateRegistrySet(documents);
  } catch (error) {
    invalid('content-manifest production registry documents are invalid', { cause: error });
  }
  const port = Object.freeze(Object.create(null));
  const record = { adapter: captured, capabilities: exact, registry, facade: null };
  record.facade = trustedFacade(record);
  Object.freeze(record);
  PORTS.set(port, record);
  return port;
}

export function contentManifestProductionCandidateCapabilities(port) {
  const record = PORTS.get(port);
  if (!record) invalid('content-manifest production candidate port was not explicitly constructed');
  return record.capabilities;
}

export function trustedContentManifestProductionCandidatePort(port) {
  const record = PORTS.get(port);
  if (!record) invalid('content-manifest production candidate port was not explicitly constructed');
  return record.facade;
}
