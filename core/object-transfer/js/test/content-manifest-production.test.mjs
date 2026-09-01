import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { chunkBytes } from '@opengamevcs/chunking-manifest';
import { ObjectRef, loadBundledRegistry } from '@opengamevcs/object-model';
import { signConformanceGrant } from '@opengamevcs/authorization-contract';
import { canonicalBytes, semanticIdempotencyFingerprint } from '@opengamevcs/protocol-baseline';
import {
  ObjectTransferService,
  contentManifestCommittedProofSha256,
  contentManifestDependencyGenerationSetSha256,
  contentManifestProductionCandidateCapabilities,
  createLifecycleAdapterPort,
  createRepositoryMetadataContentManifestCandidatePort,
} from '../src/index.mjs';
import { trustedContentManifestProductionCandidatePort } from '../src/content-manifest-production-port.mjs';

const secret = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateJwk = privateKey.export({ format: 'jwk' });
const publicJwk = publicKey.export({ format: 'jwk' });
const nowMs = 1_800_000_030_000;
const tenantId = '00000000-0000-4000-8000-000000000001';
const repositoryId = '00000000-0000-4000-8000-000000000002';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const authorizationClosureSha256 = (objectIds) => sha256(Buffer.concat([
  Buffer.from('OGVCS-OBJECT-TRANSFER-AUTHORIZATION-CLOSURE-V1\0'),
  canonicalBytes({ objectIds: [...objectIds].sort(), requestRoot: null }),
]));

function deterministicBytes(length) {
  const bytes = Buffer.alloc(length);
  let value = 0x12345678;
  for (let index = 0; index < length; index += 1) {
    value ^= value << 13;
    value ^= value >>> 17;
    value ^= value << 5;
    bytes[index] = value & 0xff;
  }
  return bytes;
}

const logicalBytes = deterministicBytes(3_400_000);
const generated = await chunkBytes(logicalBytes);
assert.equal(generated.chunks.length, 3);
const allObjectIds = [
  ...generated.chunks.map(({ objectId }) => objectId),
  generated.manifest.objectId,
];
const substitutedObjectId = new ObjectRef(1, new Uint8Array(32).fill(0x7f)).toString();
assert.equal(allObjectIds.includes(substitutedObjectId), false);
const baseClaims = Object.freeze({
  schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1',
  issuer: 'auth.example',
  keyId: 'transfer-key',
  keyGeneration: 7,
  authorityEpoch: 11,
  subject: 'artist-one',
  tenant: 'tenant-alpha-not-a-uuid',
  repository: 'game-main-not-a-uuid',
  audience: 'objects.example',
  issuedAt: 1_800_000_000,
  expiresAt: 1_800_000_300,
  nonce: 'content-manifest-production',
  replay: 'idempotent',
  objectIds: allObjectIds,
  requestRoot: null,
});
const context = Object.freeze({
  issuer: 'auth.example',
  keyId: 'transfer-key',
  subject: 'artist-one',
  audience: 'objects.example',
  tenant: baseClaims.tenant,
  repository: baseClaims.repository,
  authorityEpoch: 11,
  keyGeneration: 7,
});

function grant(nonce = 'content-manifest-production', objectIds = allObjectIds, overrides = {}) {
  return signConformanceGrant({
    ...baseClaims,
    ...overrides,
    nonce,
    objectIds,
    operation: 'upload',
    permission: 'content.upload',
  }, privateJwk, { conformanceOnly: true });
}

function idempotencyKey(label) {
  const entropy = createHash('sha256').update(label).digest().subarray(0, 16).toString('base64url');
  return `ik1.${nowMs}.${nowMs + 60_000}.${entropy}`;
}

async function productionRegistryDocuments() {
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
  return documents;
}

function candidateCapabilities() {
  return {
    schemaVersion: 'ogvcs.object-transfer/content-manifest-production-candidate-capabilities/v1',
    storageAuthority: 'repository-metadata',
    lifecycleContractVersion: 'repository-metadata/v9',
    atomicWithRepositoryMetadata: true,
    authenticatedCurrentLookup: true,
    committedReplayProof: true,
    dependencyAuthorizationProfile: 'explicit-grant-object-set/v1',
    dependencyGenerationsAtomicThroughCommit: true,
    generationFenced: true,
    grantBoundDependencyReads: true,
    requestRootDependencyClosure: false,
  };
}

function minimalCandidateAdapter(overrides = {}) {
  return {
    abortAvailability: async () => {},
    authorizeDependencyRead: async () => true,
    beginAvailability: async () => ({}),
    commitAvailability: async () => { throw new Error('unused'); },
    lookupCommittedCurrent: async () => null,
    mapGrantAuthority: async (request) => ({
      schemaVersion: 'ogvcs.object-transfer/repository-metadata-authority/v1',
      grantTenant: request.grantTenant,
      grantRepository: request.grantRepository,
      tenantId,
      repositoryId,
    }),
    readCurrent: async () => { throw new Error('unused'); },
    ...overrides,
  };
}

function lifecycleReceipt(record, grantBindingSha256) {
  const body = {
    schemaVersion: 'ogvcs.object-transfer/available-receipt/v1',
    opaqueKey: record.opaqueKey,
    objectId: record.objectId,
    length: record.length,
    state: record.state,
    generation: record.generation,
    backendReceiptSha256: record.backendReceiptSha256,
    authorityBindingSha256: record.authorityBindingSha256,
    tenantScopeSha256: record.tenantScopeSha256,
    grantBindingSha256,
  };
  return Object.freeze({ ...body, receiptSha256: sha256(canonicalBytes(body)) });
}

function cloneRecord(record) {
  return record === null ? null : Object.freeze(structuredClone(record));
}

async function harness(options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-content-manifest-production-'));
  const records = new Map();
  const committed = new Map();
  const statistics = {
    aborts: 0,
    begins: 0,
    commits: 0,
    currentReads: [],
    dependencyAuthorizations: [],
    lookups: 0,
    mappings: 0,
    proofDisclosures: 0,
  };
  const controls = {
    commitMode: options.commitMode ?? 'normal',
    commitHook: null,
    currentHook: null,
    lookupOverride: null,
  };
  let serviceValue = null;
  const lifecycleAdapter = {
    initialize: async () => {},
    get: async (opaqueKey) => cloneRecord(records.get(opaqueKey) ?? null),
    createStaged: async (input) => {
      const prior = records.get(input.opaqueKey);
      if (prior) return cloneRecord(prior);
      const record = Object.freeze({
        schemaVersion: 'ogvcs.object-transfer/lifecycle-record/v1',
        opaqueKey: input.opaqueKey,
        objectId: input.objectId,
        length: input.length,
        state: 'staged',
        generation: 1,
        authorityBindingSha256: input.authorityBindingSha256,
        tenantScopeSha256: input.tenantScopeSha256,
        backendReceiptSha256: null,
        verificationReceiptSha256: null,
        deletionReceiptSha256: null,
        retentionUntilUnixMs: nowMs + 3_600_000,
        updatedAtUnixMs: nowMs,
      });
      records.set(input.opaqueKey, record);
      return cloneRecord(record);
    },
    compareAndSwap: async (input) => {
      const prior = records.get(input.opaqueKey);
      if (!prior || prior.generation !== input.expectedGeneration || prior.state !== input.expectedState) {
        const error = new Error('stale lifecycle');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      if (ObjectRef.parse(prior.objectId).kindName === 'content-manifest') {
        const error = new Error('generic kind-2 CAS denied');
        error.code = 'TRANSFER_AUTHORIZATION_DENIED';
        throw error;
      }
      if (input.nextState !== 'available' || input.backendReceipt?.receiptSha256 === undefined) {
        const error = new Error('unsupported fake transition');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      const next = Object.freeze({
        ...prior,
        state: 'available',
        generation: prior.generation + 1,
        backendReceiptSha256: input.backendReceipt.receiptSha256,
        updatedAtUnixMs: nowMs,
      });
      records.set(input.opaqueKey, next);
      return cloneRecord(next);
    },
    deleteAuthorized: async () => { throw new Error('unused'); },
    issueReuploadPermit: async () => { throw new Error('unused'); },
    listBounded: async (maximum) => [...records.values()].slice(0, maximum).map(cloneRecord),
    receipt: (record, grantBindingSha256) => lifecycleReceipt(record, grantBindingSha256),
    recordReverifiedDeleted: async () => { throw new Error('unused'); },
  };
  const lifecyclePort = createLifecycleAdapterPort({
    adapter: lifecycleAdapter,
    capabilities: {
      schemaVersion: 'ogvcs.object-transfer/lifecycle-adapter-capabilities/v1',
      storageAuthority: 'repository-metadata',
      lifecycleContractVersion: 'repository-metadata/v9',
      atomicWithRepositoryMetadata: true,
      generationFenced: true,
      receiptGatedContentManifest: true,
    },
  });

  const productionCurrent = (mapping, record, backend) => ({
    schemaVersion: 'ogvcs.object-transfer/content-manifest-current-object/v1',
    tenantId: mapping.tenantId,
    repositoryId: mapping.repositoryId,
    opaqueKey: record.opaqueKey,
    objectId: record.objectId,
    length: record.length,
    state: record.state,
    generation: record.generation,
    authorityBindingSha256: record.authorityBindingSha256,
    backendReceiptSha256: record.backendReceiptSha256,
    verificationReceiptSha256: record.verificationReceiptSha256,
    durableBackendReceiptSha256: backend.receiptSha256,
  });

  const productionAdapter = {
    abortAvailability: async (transaction) => {
      statistics.aborts += 1;
      transaction.aborted = true;
    },
    authorizeDependencyRead: async (transaction, _mapping, request, authority) => {
      statistics.dependencyAuthorizations.push(request.dependencyObjectId);
      if (!authority.grantObjectIds.includes(request.dependencyObjectId)
          || authority.grantBindingSha256 !== request.grantBindingSha256) {
        const error = new Error('dependency authorization denied');
        error.code = 'TRANSFER_AUTHORIZATION_DENIED';
        throw error;
      }
      transaction.dependencies.set(request.dependencyOpaqueKey, {
        request: structuredClone(request),
        current: null,
      });
      return true;
    },
    beginAvailability: async (_mapping, lookup, authority) => {
      statistics.begins += 1;
      assert.equal(authority.grantBindingSha256.length, 64);
      return {
        lookup: structuredClone(lookup),
        committed: false,
        aborted: false,
        dependencies: new Map(),
      };
    },
    commitAvailability: async (transaction, mapping, command) => {
      statistics.commits += 1;
      await controls.commitHook?.(transaction, command, records, serviceValue);
      if (controls.commitMode === 'precommit-failure') {
        controls.commitMode = 'normal';
        const error = new Error('precommit serialization failure');
        error.code = 'PRIVATE_SERIALIZATION_FAILURE';
        throw error;
      }
      const prior = records.get(command.opaqueKey);
      if (!prior || prior.state !== command.expectedState
          || prior.generation !== command.expectedGeneration
          || prior.backendReceiptSha256 !== null) {
        const error = new Error('stale content-manifest generation');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      if (command.dependencyCount !== transaction.dependencies.size
          || !Number.isSafeInteger(command.dependencyCount)
          || command.dependencyCount < 0
          || command.dependencyGenerationSetSha256.length !== 64) {
        const error = new Error('dependency generation set differs');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      const dependencyCurrents = [];
      for (const dependency of transaction.dependencies.values()) {
        const record = records.get(dependency.request.dependencyOpaqueKey);
        const backend = await serviceValue.backend.verify(dependency.request.dependencyOpaqueKey);
        const fresh = record ? productionCurrent(mapping, record, backend) : null;
        if (!record || record.state !== 'available'
            || record.objectId !== dependency.request.dependencyObjectId
            || record.length !== dependency.request.dependencyLength
            || record.backendReceiptSha256 !== backend.receiptSha256
            || dependency.current === null
            || !canonicalBytes(fresh).equals(canonicalBytes(dependency.current))) {
          const error = new Error('dependency generation changed before commit');
          error.code = 'TRANSFER_LIFECYCLE_STALE';
          throw error;
        }
        dependencyCurrents.push(dependency.current);
      }
      if (contentManifestDependencyGenerationSetSha256(dependencyCurrents)
          !== command.dependencyGenerationSetSha256) {
        const error = new Error('dependency generation digest changed before commit');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      const backend = await serviceValue.backend.verify(command.opaqueKey);
      if (backend.receiptSha256 !== command.backendReceiptSha256) {
        const error = new Error('backend receipt changed');
        error.code = 'TRANSFER_BACKEND_CORRUPT';
        throw error;
      }
      const next = Object.freeze({
        ...prior,
        state: command.targetState,
        generation: command.targetGeneration,
        backendReceiptSha256: command.backendReceiptSha256,
        verificationReceiptSha256: command.verificationReceiptSha256,
        updatedAtUnixMs: nowMs,
      });
      records.set(command.opaqueKey, next);
      const body = Object.freeze({
        schemaVersion: 'ogvcs.object-transfer/content-manifest-committed-current/v1',
        applicationId: `00000000-0000-4000-8000-${String(statistics.commits).padStart(12, '0')}`,
        tenantId: mapping.tenantId,
        repositoryId: mapping.repositoryId,
        opaqueKey: command.opaqueKey,
        objectId: command.objectId,
        length: command.length,
        state: command.targetState,
        generation: command.targetGeneration,
        authorizationClosureSha256: command.authorizationClosureSha256,
        authorityBindingSha256: command.authorityBindingSha256,
        tenantScopeSha256: command.tenantScopeSha256,
        subjectDigestSha256: command.subjectDigestSha256,
        backendReceiptSha256: command.backendReceiptSha256,
        dependencyCount: command.dependencyCount,
        dependencyGenerationSetSha256: command.dependencyGenerationSetSha256,
        verificationReceiptSha256: command.verificationReceiptSha256,
        finalizeSemanticFingerprint: command.finalizeSemanticFingerprint,
        productionStatement: structuredClone(command.productionStatement),
        productionStatementSha256: command.productionStatementSha256,
      });
      const proof = Object.freeze({
        ...body,
        proofSha256: contentManifestCommittedProofSha256(body),
      });
      committed.set(command.opaqueKey, proof);
      transaction.committed = true;
      if (controls.commitMode === 'response-loss') {
        controls.commitMode = 'normal';
        const error = new Error('commit response lost');
        error.code = 'PRIVATE_COMMIT_RESPONSE_LOST';
        throw error;
      }
      if (controls.commitMode === 'mismatched-response') {
        controls.commitMode = 'normal';
        const substituted = { ...proof, generation: proof.generation + 1 };
        substituted.proofSha256 = contentManifestCommittedProofSha256(substituted);
        return substituted;
      }
      return structuredClone(proof);
    },
    lookupCommittedCurrent: async (mapping, lookup, authority) => {
      statistics.lookups += 1;
      assert.equal(authority.authorityBindingSha256, lookup.authorityBindingSha256);
      assert.equal(authority.authorizationClosureSha256, lookup.authorizationClosureSha256);
      if (controls.lookupOverride !== null) return controls.lookupOverride(mapping, lookup);
      const proof = committed.get(lookup.opaqueKey);
      if (!proof || proof.finalizeSemanticFingerprint !== lookup.finalizeSemanticFingerprint
          || proof.authorizationClosureSha256 !== lookup.authorizationClosureSha256) return null;
      const current = records.get(lookup.opaqueKey);
      const backend = await serviceValue.backend.verify(lookup.opaqueKey);
      if (!current || current.state !== 'available' || current.generation !== proof.generation
          || current.backendReceiptSha256 !== proof.backendReceiptSha256
          || backend.receiptSha256 !== proof.backendReceiptSha256) return null;
      statistics.proofDisclosures += 1;
      return structuredClone(proof);
    },
    mapGrantAuthority: async (request) => {
      statistics.mappings += 1;
      assert.equal(request.grantTenant, baseClaims.tenant);
      assert.equal(request.grantRepository, baseClaims.repository);
      assert.equal(request.grantRequestRoot, null);
      assert.ok(request.grantObjectIds.includes(generated.manifest.objectId));
      assert.equal(
        request.authorizationClosureSha256,
        authorizationClosureSha256(request.grantObjectIds),
      );
      return {
        schemaVersion: 'ogvcs.object-transfer/repository-metadata-authority/v1',
        grantTenant: request.grantTenant,
        grantRepository: request.grantRepository,
        tenantId,
        repositoryId,
      };
    },
    readCurrent: async (transaction, mapping, request) => {
      const event = {
        count: statistics.currentReads.length + 1,
        mapping,
        moment: 'before',
        request,
        transaction,
      };
      statistics.currentReads.push({ objectId: request.objectId, opaqueKey: request.opaqueKey });
      await controls.currentHook?.(event, records, serviceValue);
      const record = records.get(request.opaqueKey);
      if (!record) {
        const error = new Error('current object absent');
        error.code = 'TRANSFER_LIFECYCLE_STALE';
        throw error;
      }
      const backend = await serviceValue.backend.verify(request.opaqueKey);
      const result = productionCurrent(mapping, record, backend);
      const dependency = transaction.dependencies.get(request.opaqueKey);
      if (dependency) dependency.current = structuredClone(result);
      await controls.currentHook?.({ ...event, moment: 'after' }, records, serviceValue);
      return result;
    },
  };
  const registryDocuments = await productionRegistryDocuments();
  const productionPort = createRepositoryMetadataContentManifestCandidatePort({
    adapter: productionAdapter,
    capabilities: candidateCapabilities(),
    registryDocuments,
  });
  // Both the registry and adapter tables are captured at construction.
  registryDocuments['profiles.json'].entries.length = 0;
  productionAdapter.mapGrantAuthority = async () => { throw new Error('mutable adapter dispatch'); };

  const construct = async () => {
    serviceValue = await new ObjectTransferService({
      root,
      backendSecret: secret,
      authorizationPublicJwk: publicJwk,
      audience: 'objects.example',
      authorityEpoch: 11,
      keyGeneration: 7,
      issuer: 'auth.example',
      keyId: 'transfer-key',
      now: () => nowMs,
      lifecycleAdapter: lifecyclePort,
      contentManifestProductionCandidatePort: productionPort,
    }).initialize();
    return serviceValue;
  };
  await construct();
  return {
    construct,
    controls,
    lifecyclePort,
    productionPort,
    records,
    root,
    get service() { return serviceValue; },
    statistics,
  };
}

async function upload(value, objectId, bytes, uploadGrant, label) {
  const startFingerprint = semanticIdempotencyFingerprint({
    declaredLength: bytes.length,
    objectId,
    operation: 'start-upload',
    partSize: bytes.length,
  });
  const started = await value.startUpload({
    objectId,
    declaredLength: bytes.length,
    partSize: bytes.length,
    idempotencyKey: idempotencyKey(`${label}-start`),
    idempotencyFingerprint: startFingerprint,
    grant: uploadGrant,
    context,
  });
  await value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes,
    sha256: sha256(bytes),
    grant: uploadGrant,
    context,
  });
  return started;
}

async function finalize(value, started, uploadGrant, label) {
  const fingerprint = semanticIdempotencyFingerprint({
    operation: 'finalize-upload',
    sessionId: started.sessionId,
  });
  return {
    fingerprint,
    result: await value.finalizeUpload({
      sessionId: started.sessionId,
      idempotencyKey: idempotencyKey(`${label}-finalize`),
      idempotencyFingerprint: fingerprint,
      grant: uploadGrant,
      context,
    }),
  };
}

async function prepare() {
  const value = await harness();
  const uploadGrant = grant();
  for (let index = 0; index < generated.chunks.length; index += 1) {
    const part = generated.chunks[index];
    const started = await upload(value.service, part.objectId, generated.chunkBytes[index], uploadGrant, `chunk-${index}`);
    await finalize(value.service, started, uploadGrant, `chunk-${index}`);
  }
  const manifest = await upload(
    value.service,
    generated.manifest.objectId,
    generated.manifest.bytes,
    uploadGrant,
    'manifest',
  );
  return { ...value, manifest, uploadGrant };
}

function backendPath(root, opaqueKey) {
  return join(root, 'backend', 'objects', opaqueKey.slice(0, 2), opaqueKey.slice(2, 4), `${opaqueKey}.obj`);
}

test('repository-metadata candidate verifies stored manifest and every exact chunk before atomic kind-2 availability', async () => {
  const value = await prepare();
  const accepted = await finalize(value.service, value.manifest, value.uploadGrant, 'manifest-success');
  assert.equal(accepted.result.state, 'available');
  assert.equal(accepted.result.generation, 2);
  const manifestRecord = [...value.records.values()].find(({ objectId }) => objectId === generated.manifest.objectId);
  assert.equal(manifestRecord.verificationReceiptSha256.length, 64);
  assert.equal(value.statistics.commits, 1);
  assert.equal(value.statistics.aborts, 0);
  assert.ok(value.statistics.currentReads.length >= 3 + generated.chunks.length * 3);

  const equivalentGrant = grant(
    'content-manifest-fresh-equivalent-grant',
    [...allObjectIds].reverse(),
    { issuedAt: baseClaims.issuedAt + 1, expiresAt: baseClaims.expiresAt - 1 },
  );
  const replayed = await finalize(
    value.service,
    value.manifest,
    equivalentGrant,
    'manifest-fresh-equivalent-replay',
  );
  assert.equal(replayed.result.state, 'available');
  assert.equal(replayed.result.generation, 2);
  assert.equal(value.statistics.commits, 1);
  const disclosuresBeforeMismatchedClosures = value.statistics.proofDisclosures;
  assert.ok(disclosuresBeforeMismatchedClosures > 0);

  const mismatchedClosures = [
    allObjectIds.filter((objectId) => objectId !== generated.chunks[0].objectId),
    allObjectIds.map((objectId) => (
      objectId === generated.chunks[0].objectId ? substitutedObjectId : objectId
    )),
  ];
  for (const [index, objectIds] of mismatchedClosures.entries()) {
    const mismatchedGrant = grant(`content-manifest-mismatched-closure-${index}`, objectIds, {
      issuedAt: baseClaims.issuedAt + index + 2,
      expiresAt: baseClaims.expiresAt - index - 2,
    });
    await assert.rejects(
      () => finalize(
        value.service,
        value.manifest,
        mismatchedGrant,
        `manifest-mismatched-closure-${index}`,
      ),
      { code: 'TRANSFER_LIFECYCLE_STALE' },
    );
    assert.equal(value.statistics.proofDisclosures, disclosuresBeforeMismatchedClosures);
    assert.equal(value.statistics.commits, 1);
  }
});

test('settled commit response loss recovers after restart only from the exact current committed proof', async () => {
  const value = await prepare();
  value.controls.commitMode = 'response-loss';
  await assert.rejects(
    () => finalize(value.service, value.manifest, value.uploadGrant, 'manifest-lost-response'),
    { code: 'TRANSFER_BACKEND_IO' },
  );
  assert.equal(value.statistics.commits, 1);
  assert.equal(value.statistics.aborts, 1);
  const restarted = await value.construct();
  const recovered = await finalize(restarted, value.manifest, value.uploadGrant, 'manifest-recovery');
  assert.equal(recovered.result.state, 'available');
  assert.equal(recovered.result.generation, 2);
  assert.equal(value.statistics.commits, 1);
});

test('available lifecycle state without the exact immutable proof never bypasses production verification', async () => {
  const value = await prepare();
  const record = [...value.records.values()].find(({ objectId }) => objectId === generated.manifest.objectId);
  await value.service.backend.createIfAbsent({
    opaqueKey: record.opaqueKey,
    objectId: record.objectId,
    length: record.length,
    source: generated.manifest.bytes,
  });
  const backend = await value.service.backend.verify(record.opaqueKey);
  value.records.set(record.opaqueKey, Object.freeze({
    ...record,
    state: 'available',
    generation: 2,
    backendReceiptSha256: backend.receiptSha256,
    verificationReceiptSha256: 'f'.repeat(64),
  }));
  await assert.rejects(
    () => finalize(value.service, value.manifest, value.uploadGrant, 'manifest-forged-available'),
    { code: 'TRANSFER_LIFECYCLE_STALE' },
  );
  assert.equal(value.statistics.commits, 0);
});

test('precommit failure aborts exactly once and leaves kind-2 staged', async () => {
  const value = await prepare();
  value.controls.commitMode = 'precommit-failure';
  await assert.rejects(
    () => finalize(value.service, value.manifest, value.uploadGrant, 'manifest-precommit-failure'),
  );
  const record = [...value.records.values()].find(({ objectId }) => objectId === generated.manifest.objectId);
  assert.equal(record.state, 'staged');
  assert.equal(record.generation, 1);
  assert.equal(value.statistics.aborts, 1);
});

test('a mismatched commit response is rejected and a later exact proof lookup repairs it', async () => {
  const value = await prepare();
  value.controls.commitMode = 'mismatched-response';
  await assert.rejects(
    () => finalize(value.service, value.manifest, value.uploadGrant, 'manifest-mismatched-response'),
    { code: 'TRANSFER_BACKEND_CORRUPT' },
  );
  const recovered = await finalize(value.service, value.manifest, value.uploadGrant, 'manifest-mismatched-recovery');
  assert.equal(recovered.result.generation, 2);
  assert.equal(value.statistics.commits, 1);
});

test('missing, wrong-length, wrong-ID, and wrong-receipt chunks fail at early, middle, and last positions', async () => {
  const value = await prepare();
  const manifestRecord = [...value.records.values()].find(({ objectId }) => objectId === generated.manifest.objectId);
  for (const defect of ['missing', 'wrong-length', 'wrong-id', 'wrong-receipt']) {
    for (const index of [0, 1, 2]) {
      const objectId = generated.chunks[index].objectId;
      const [opaqueKey, original] = [...value.records].find(([, record]) => record.objectId === objectId);
      if (defect === 'missing') value.records.delete(opaqueKey);
      else if (defect === 'wrong-length') value.records.set(opaqueKey, Object.freeze({ ...original, length: original.length + 1 }));
      else if (defect === 'wrong-id') {
        value.records.set(opaqueKey, Object.freeze({ ...original, objectId: generated.chunks[(index + 1) % 3].objectId }));
      } else value.records.set(opaqueKey, Object.freeze({ ...original, backendReceiptSha256: 'f'.repeat(64) }));
      await assert.rejects(
        () => finalize(value.service, value.manifest, value.uploadGrant, `${defect}-${index}`),
        (error) => error?.code === 'TRANSFER_LIFECYCLE_STALE' || error?.code === 'TRANSFER_BACKEND_CORRUPT',
      );
      value.records.set(opaqueKey, original);
      value.records.set(manifestRecord.opaqueKey, manifestRecord);
    }
  }
  assert.equal(value.statistics.commits, 0);
});

test('unauthorized manifest dependencies fail identically before early, middle, and last chunk reads', async () => {
  const value = await prepare();
  const denials = new Set();
  for (const [index, chunk] of generated.chunks.entries()) {
    value.statistics.dependencyAuthorizations.length = 0;
    const authorized = allObjectIds.filter((objectId) => objectId !== chunk.objectId);
    const restrictedGrant = grant(`content-manifest-missing-dependency-${index}`, authorized);
    await assert.rejects(
      () => finalize(value.service, value.manifest, restrictedGrant, `unauthorized-dependency-${index}`),
      (error) => {
        denials.add(`${error?.code}\0${error?.message}`);
        return error?.code === 'TRANSFER_AUTHORIZATION_DENIED';
      },
    );
    assert.equal(value.statistics.dependencyAuthorizations.length, index);
  }
  assert.equal(denials.size, 1);
  assert.equal(value.statistics.commits, 0);
});

test('stored chunk and manifest byte mutation are detected from durable storage, not upload-session bytes', async () => {
  const value = await prepare();
  const targets = [
    ...generated.chunks.map(({ objectId }) => objectId),
    generated.manifest.objectId,
  ];
  for (const [index, objectId] of targets.entries()) {
    const record = [...value.records.values()].find((entry) => entry.objectId === objectId);
    const path = backendPath(value.root, record.opaqueKey);
    const original = await readFile(path);
    const corrupt = Buffer.from(original);
    corrupt[corrupt.length - 1] ^= 0xff;
    await writeFile(path, corrupt);
    await assert.rejects(
      () => finalize(value.service, value.manifest, value.uploadGrant, `stored-mutation-${index}`),
      { code: 'TRANSFER_BACKEND_CORRUPT' },
    );
    await writeFile(path, original);
  }
  assert.equal(value.statistics.commits, 0);
});

test('generation/quarantine changes before and after bounded reads abort without availability', async () => {
  const value = await prepare();
  const targetId = generated.chunks[1].objectId;
  const [targetKey, target] = [...value.records].find(([, record]) => record.objectId === targetId);
  for (const trigger of [2, 3]) {
    let seen = 0;
    value.controls.currentHook = async ({ request, moment }, records) => {
      if (request.objectId !== targetId || moment !== 'before') return;
      seen += 1;
      if (seen === trigger) {
        records.set(targetKey, Object.freeze({ ...target, state: 'quarantined', generation: target.generation + 1 }));
      }
    };
    await assert.rejects(
      () => finalize(value.service, value.manifest, value.uploadGrant, `lifecycle-race-${trigger}`),
      { code: 'TRANSFER_LIFECYCLE_STALE' },
    );
    value.records.set(targetKey, target);
    value.controls.currentHook = null;
  }
  const manifestRecord = [...value.records.values()].find(({ objectId }) => objectId === generated.manifest.objectId);
  assert.equal(manifestRecord.state, 'staged');
  assert.equal(value.statistics.commits, 0);
});

test('the metadata transaction revalidates every dependency generation at commit', async () => {
  const value = await prepare();
  const targetId = generated.chunks[1].objectId;
  const [targetKey, target] = [...value.records].find(([, record]) => record.objectId === targetId);
  value.controls.commitHook = async (_transaction, _command, records) => {
    records.set(targetKey, Object.freeze({
      ...target,
      state: 'quarantined',
      generation: target.generation + 1,
    }));
  };
  await assert.rejects(
    () => finalize(value.service, value.manifest, value.uploadGrant, 'dependency-commit-race'),
    {
      code: 'TRANSFER_LIFECYCLE_STALE',
      message: 'repository-metadata content-manifest generation is stale',
    },
  );
  const manifest = [...value.records.values()].find(({ objectId }) => objectId === generated.manifest.objectId);
  assert.equal(manifest.state, 'staged');
  assert.equal(value.statistics.aborts, 1);
  assert.equal(value.statistics.commits, 1);
});

test('adapter error messages, causes, and details never cross the production port', async () => {
  const value = await prepare();
  const secretText = 'tenant-secret/path/token';
  const accessor = {};
  Object.defineProperty(accessor, 'code', { get() { throw new Error(`getter-${secretText}`); } });
  const hostileValues = [
    Object.assign(new Error(secretText, { cause: new Error(`cause-${secretText}`) }), {
      code: 'PRIVATE_DATABASE_FAILURE',
      details: { secretText },
    }),
    new Proxy({}, {
      get() { throw new Error(`proxy-get-${secretText}`); },
      getOwnPropertyDescriptor() { throw new Error(`proxy-descriptor-${secretText}`); },
    }),
    accessor,
    { [Symbol(secretText)]: secretText },
    secretText,
  ];
  for (const [index, hostile] of hostileValues.entries()) {
    value.controls.commitHook = async () => { throw hostile; };
    await assert.rejects(
      () => finalize(value.service, value.manifest, value.uploadGrant, `adapter-secret-error-${index}`),
      (error) => error?.code === 'TRANSFER_BACKEND_IO'
        && error.message === 'repository-metadata content-manifest operation failed'
        && !JSON.stringify(error).includes(secretText)
        && !String(error.stack).includes(secretText)
        && error.cause === undefined
        && error.details === undefined,
    );
  }
});

test('candidate port rejects raw, proxy, prototype, and cross-instance forgeries while retaining no mutable registry table', async () => {
  const first = await harness();
  const second = await harness();
  const config = {
    root: await mkdtemp(join(tmpdir(), 'ogvcs-content-manifest-forgery-')),
    backendSecret: secret,
    authorizationPublicJwk: publicJwk,
    audience: 'objects.example',
    authorityEpoch: 11,
    keyGeneration: 7,
    issuer: 'auth.example',
    keyId: 'transfer-key',
    lifecycleAdapter: first.lifecyclePort,
  };
  for (const forged of [
    {},
    new Proxy(first.productionPort, {}),
    Object.create(first.productionPort),
    second.lifecyclePort,
  ]) {
    assert.throws(
      () => new ObjectTransferService({ ...config, contentManifestProductionCandidatePort: forged }),
      { code: 'TRANSFER_INPUT_INVALID' },
    );
  }
  assert.equal(Object.keys(first.productionPort).length, 0);
  assert.equal(Object.isFrozen(first.productionPort), true);
});

test('candidate authority and transaction handles are instance-bound snapshots and the registry must be complete', async () => {
  const registryDocuments = await productionRegistryDocuments();
  const capabilities = candidateCapabilities();
  let mappingRecord = {
    schemaVersion: 'ogvcs.object-transfer/repository-metadata-authority/v1',
    grantTenant: baseClaims.tenant,
    grantRepository: baseClaims.repository,
    tenantId,
    repositoryId,
  };
  let requestWasFrozen = false;
  const firstPort = createRepositoryMetadataContentManifestCandidatePort({
    adapter: minimalCandidateAdapter({
      mapGrantAuthority: async (request) => {
        requestWasFrozen = Object.isFrozen(request) && Object.isFrozen(request.grantObjectIds);
        return mappingRecord;
      },
    }),
    capabilities,
    registryDocuments,
  });
  capabilities.atomicWithRepositoryMetadata = false;
  assert.equal(contentManifestProductionCandidateCapabilities(firstPort).atomicWithRepositoryMetadata, true);
  assert.equal(Object.isFrozen(contentManifestProductionCandidateCapabilities(firstPort)), true);

  const secondPort = createRepositoryMetadataContentManifestCandidatePort({
    adapter: minimalCandidateAdapter(),
    capabilities: candidateCapabilities(),
    registryDocuments: await productionRegistryDocuments(),
  });
  const first = trustedContentManifestProductionCandidatePort(firstPort);
  const second = trustedContentManifestProductionCandidatePort(secondPort);
  const authorityRequest = {
    schemaVersion: 'ogvcs.object-transfer/content-manifest-grant-authority/v1',
    grantTenant: baseClaims.tenant,
    grantRepository: baseClaims.repository,
    grantObjectIds: allObjectIds,
    grantRequestRoot: null,
    authorizationClosureSha256: authorizationClosureSha256(allObjectIds),
    subjectDigestSha256: 'c'.repeat(64),
    authorityBindingSha256: 'a'.repeat(64),
    tenantScopeSha256: 'b'.repeat(64),
    grantBindingSha256: 'd'.repeat(64),
  };
  await assert.rejects(() => first.mapGrantAuthority({
    ...authorityRequest,
    authorizationClosureSha256: '1'.repeat(64),
  }), { code: 'TRANSFER_INPUT_INVALID' });
  const authority = await first.mapGrantAuthority(authorityRequest);
  mappingRecord.tenantId = '00000000-0000-4000-8000-000000000099';
  assert.equal(requestWasFrozen, true);
  assert.equal(authority.mapping.tenantId, tenantId);
  assert.equal(Object.isFrozen(authority.mapping), true);
  const lookup = {
    schemaVersion: 'ogvcs.object-transfer/content-manifest-availability-lookup/v1',
    opaqueKey: 'e'.repeat(64),
    objectId: generated.manifest.objectId,
    length: generated.manifest.bytes.length,
    authorizationClosureSha256: authorizationClosureSha256(allObjectIds),
    authorityBindingSha256: 'a'.repeat(64),
    tenantScopeSha256: 'b'.repeat(64),
    subjectDigestSha256: 'c'.repeat(64),
    backendReceiptSha256: 'f'.repeat(64),
    finalizeSemanticFingerprint: '0'.repeat(64),
  };
  await assert.rejects(() => second.lookupCommittedCurrent(authority.handle, lookup), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  await assert.rejects(() => first.lookupCommittedCurrent(Object.create(authority.handle), lookup), {
    code: 'TRANSFER_AUTHORIZATION_DENIED',
  });
  await assert.rejects(() => first.lookupCommittedCurrent(authority.handle, {
    ...lookup,
    authorityBindingSha256: '1'.repeat(64),
  }), { code: 'TRANSFER_AUTHORIZATION_DENIED' });
  await assert.rejects(() => first.lookupCommittedCurrent(authority.handle, {
    ...lookup,
    authorizationClosureSha256: '1'.repeat(64),
  }), { code: 'TRANSFER_AUTHORIZATION_DENIED' });
  const transaction = await first.beginAvailability(authority.handle, lookup);
  await assert.rejects(() => second.readCurrent(transaction, {
    schemaVersion: 'ogvcs.object-transfer/content-manifest-current-request/v1',
    opaqueKey: lookup.opaqueKey,
    objectId: lookup.objectId,
    length: lookup.length,
    authorityBindingSha256: lookup.authorityBindingSha256,
    durableBackendReceiptSha256: lookup.backendReceiptSha256,
  }), { code: 'TRANSFER_AUTHORIZATION_DENIED' });

  const proxyMappingPort = createRepositoryMetadataContentManifestCandidatePort({
    adapter: minimalCandidateAdapter({
      mapGrantAuthority: async () => new Proxy({ ...mappingRecord, tenantId }, {}),
    }),
    capabilities: candidateCapabilities(),
    registryDocuments: await productionRegistryDocuments(),
  });
  await assert.rejects(
    () => trustedContentManifestProductionCandidatePort(proxyMappingPort).mapGrantAuthority(authorityRequest),
    { code: 'TRANSFER_BACKEND_CORRUPT' },
  );

  const partial = await productionRegistryDocuments();
  delete partial['profiles.json'];
  assert.throws(() => createRepositoryMetadataContentManifestCandidatePort({
    adapter: minimalCandidateAdapter(),
    capabilities: candidateCapabilities(),
    registryDocuments: partial,
  }), { code: 'TRANSFER_INPUT_INVALID' });
  const forged = await productionRegistryDocuments();
  forged['profiles.json'].entries.push(structuredClone(forged['profiles.json'].entries[0]));
  assert.throws(() => createRepositoryMetadataContentManifestCandidatePort({
    adapter: minimalCandidateAdapter(),
    capabilities: candidateCapabilities(),
    registryDocuments: forged,
  }), { code: 'TRANSFER_INPUT_INVALID' });
  const proxyAdapterRegistry = await productionRegistryDocuments();
  assert.throws(() => createRepositoryMetadataContentManifestCandidatePort({
    adapter: new Proxy(minimalCandidateAdapter(), {}),
    capabilities: candidateCapabilities(),
    registryDocuments: proxyAdapterRegistry,
  }), { code: 'TRANSFER_INPUT_INVALID' });
});
