import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import {
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rename,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { encodeCanonical, hashObject } from '@opengamevcs/object-model';
import { requestRootForObjectIds, signConformanceGrant } from '@opengamevcs/authorization-contract';
import { canonicalBytes, semanticIdempotencyFingerprint } from '@opengamevcs/protocol-baseline';
import { FilesystemObjectBackend, LifecycleStore, ObjectTransferService } from '../src/index.mjs';
import {
  atomicJsonWrite,
  directorySyncUnsupported,
  pinPlainDirectory,
  readJson,
  withRecoverableDirectoryLock,
} from '../src/fs-util.mjs';

const CONTRACT = resolve(import.meta.dirname, '../../../../spec/object-transfer/v1');
const resume = JSON.parse(await readFile(join(CONTRACT, 'vectors/resume.json'))).cases
  .find(({ id }) => id === 'multipart-resume');
const backendVectors = JSON.parse(await readFile(join(CONTRACT, 'vectors/backend.json')));
const create = backendVectors.cases.find(({ id }) => id === 'create-if-absent');
const fixtureBytes = Buffer.concat(resume.input.parts.map((part) => Buffer.from(part.bytesHex, 'hex')));
const objectId = hashObject(1, fixtureBytes).toString();
const secret = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateJwk = privateKey.export({ format: 'jwk' });
const publicJwk = publicKey.export({ format: 'jwk' });
const nowMs = 1_800_000_030_000;
const authorityBindingSha256 = 'c'.repeat(64);
const tenantScopeSha256 = 'e'.repeat(64);
const baseClaims = Object.freeze({
  schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1',
  issuer: 'auth.example',
  keyId: 'transfer-key',
  keyGeneration: 7,
  authorityEpoch: 11,
  subject: 'artist-one',
  tenant: 'tenant-alpha',
  repository: 'game-main',
  audience: 'objects.example',
  issuedAt: 1_800_000_000,
  expiresAt: 1_800_000_300,
  nonce: 'vector-grant',
  replay: 'idempotent',
  objectIds: [],
  requestRoot: requestRootForObjectIds([objectId]),
});
const context = Object.freeze({
  issuer: 'auth.example',
  keyId: 'transfer-key',
  subject: 'artist-one',
  audience: 'objects.example',
  tenant: 'tenant-alpha',
  repository: 'game-main',
  authorityEpoch: 11,
  keyGeneration: 7,
});
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const wait = (milliseconds) => new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));

function grant(operation, nonce = `vector-${operation}`, overrides = {}) {
  return signConformanceGrant({
    ...baseClaims,
    nonce,
    operation,
    permission: operation === 'upload' ? 'content.upload' : 'content.materialize',
    ...overrides,
  }, privateJwk, { conformanceOnly: true });
}

function idempotencyKey(label) {
  const entropy = createHash('sha256').update(label).digest().subarray(0, 16).toString('base64url');
  return `ik1.${nowMs}.${nowMs + 60_000}.${entropy}`;
}

async function service(root, fault = async () => {}, options = {}) {
  return new ObjectTransferService({
    root,
    backendSecret: secret,
    authorizationPublicJwk: publicJwk,
    audience: 'objects.example',
    authorityEpoch: 11,
    keyGeneration: 7,
    issuer: 'auth.example',
    keyId: 'transfer-key',
    now: () => nowMs,
    fault,
    ...options,
  }).initialize();
}

async function freshBackend(prefix = 'ogvcs-vector-backend-') {
  const root = await mkdtemp(join(tmpdir(), prefix));
  return { root, backend: await new FilesystemObjectBackend({ root }).initialize() };
}

async function errorCode(operation) {
  try { await operation(); }
  catch (error) { return error?.code ?? error?.message; }
  throw new Error('vector operation unexpectedly succeeded');
}

async function startSinglePart(value, uploadGrant, label = 'vector-start') {
  const fingerprint = semanticIdempotencyFingerprint({
    declaredLength: fixtureBytes.length,
    objectId,
    operation: 'start-upload',
    partSize: fixtureBytes.length,
  });
  const started = await value.startUpload({
    objectId,
    declaredLength: fixtureBytes.length,
    partSize: fixtureBytes.length,
    idempotencyKey: idempotencyKey(label),
    idempotencyFingerprint: fingerprint,
    grant: uploadGrant,
    context,
  });
  return { started, fingerprint };
}

async function finalizeSinglePart(value, label = 'vector-finalize') {
  const uploadGrant = grant('upload', `${label}-grant`);
  const { started } = await startSinglePart(value, uploadGrant, `${label}-start`);
  await value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes: fixtureBytes,
    sha256: sha256(fixtureBytes),
    grant: uploadGrant,
    context,
  });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId });
  const arguments_ = {
    sessionId: started.sessionId,
    idempotencyKey: idempotencyKey(label),
    idempotencyFingerprint: fingerprint,
    grant: uploadGrant,
    context,
  };
  const receipt = await value.finalizeUpload(arguments_);
  return { arguments_, receipt, started, uploadGrant };
}

async function backendTraversal() {
  const { backend } = await freshBackend();
  return { code: await errorCode(() => backend.head('../protected')), mutationCount: 0 };
}

async function corruptStoredPayload() {
  const { root, backend } = await freshBackend();
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  await backend.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes });
  const path = join(root, 'objects', create.expected.opaqueKey.slice(0, 2), create.expected.opaqueKey.slice(2, 4), `${create.expected.opaqueKey}.obj`);
  const handle = await open(path, 'r+');
  try {
    const stat = await handle.stat();
    const byte = Buffer.alloc(1);
    await handle.read(byte, 0, 1, stat.size - 1);
    byte[0] ^= 1;
    await handle.write(byte, 0, 1, stat.size - 1);
    await handle.sync();
  } finally { await handle.close(); }
  return { code: await errorCode(() => backend.verify(create.expected.opaqueKey)), available: false };
}

async function malformedMetadata() {
  const { backend } = await freshBackend();
  const malformed = encodeCanonical(new Map([[0, 1], [1, 2]]));
  const malformedId = hashObject(2, malformed).toString();
  return {
    code: await errorCode(() => backend.createIfAbsent({
      opaqueKey: 'f'.repeat(64), objectId: malformedId, length: malformed.length, source: malformed,
    })),
    available: false,
  };
}

async function symlinkFanout() {
  const { root, backend } = await freshBackend();
  const outside = await mkdtemp(join(tmpdir(), 'ogvcs-vector-outside-'));
  await symlink(outside, join(root, 'objects', create.expected.opaqueKey.slice(0, 2)), process.platform === 'win32' ? 'junction' : 'dir');
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const code = await errorCode(() => backend.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }));
  return { code, outsideWrite: (await readdir(outside)).length !== 0 };
}

async function symlinkAncestor() {
  const { root, backend } = await freshBackend();
  const outside = await mkdtemp(join(tmpdir(), 'ogvcs-vector-ancestor-outside-'));
  await rename(join(root, 'objects'), join(root, 'objects-original'));
  await symlink(outside, join(root, 'objects'), process.platform === 'win32' ? 'junction' : 'dir');
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const code = await errorCode(() => backend.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }));
  return { code, outsideWrite: (await readdir(outside)).length !== 0 };
}

async function staleLifecycleGeneration() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-stale-lifecycle-'));
  const store = await new LifecycleStore({ root, now: () => nowMs }).initialize();
  await store.createStaged({
    opaqueKey: 'a'.repeat(64),
    objectId: `ogvcs:v1:chunk:sha256:${'b'.repeat(64)}`,
    length: 4,
    authorityBindingSha256,
    tenantScopeSha256,
  });
  const code = await errorCode(() => store.compareAndSwap({
    opaqueKey: 'a'.repeat(64),
    expectedGeneration: 2,
    expectedState: 'staged',
    nextState: 'available',
    backendReceipt: {},
    authorityBindingSha256,
  }));
  return { code, transitionCount: (await store.get('a'.repeat(64))).generation - 1 };
}

async function forgedDeletingGeneration() {
  const { backend } = await freshBackend();
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const receipt = await backend.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes });
  const code = await errorCode(() => backend.safeDelete({
    opaqueKey: create.expected.opaqueKey,
    receiptSha256: receipt.receiptSha256,
    expectedGeneration: 2,
    authorityBindingSha256,
  }));
  return { code, deleted: await backend.verify(create.expected.opaqueKey).then(() => false, () => true) };
}

async function staleLockFence() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-stale-lock-'));
  const rootPin = await pinPlainDirectory(root);
  const statePin = await pinPlainDirectory(join(root, 'state'), { parentPin: rootPin });
  const statePath = join(statePin.path, 'record.json');
  const name = '7'.repeat(64);
  let now = 1_000;
  let release;
  let entered;
  const enteredPromise = new Promise((resolveEntered) => { entered = resolveEntered; });
  const releasePromise = new Promise((resolveRelease) => { release = resolveRelease; });
  const stale = withRecoverableDirectoryLock({
    rootPin,
    name,
    now: () => now,
    attempts: 1,
    leaseMilliseconds: 1_000,
    operation: async (lockGuard) => {
      entered();
      await releasePromise;
      await atomicJsonWrite(statePath, { writer: 'stale' }, { directoryPin: statePin, lockGuard });
    },
  });
  await enteredPromise;
  now = 2_001;
  await withRecoverableDirectoryLock({
    rootPin,
    name,
    now: () => now,
    attempts: 2,
    leaseMilliseconds: 1_000,
    operation: async (lockGuard) => atomicJsonWrite(statePath, { writer: 'winner' }, { directoryPin: statePin, lockGuard }),
  });
  release();
  const code = await errorCode(() => stale);
  return { code, staleCommit: (await readJson(statePath, 8192, { directoryPin: statePin })).writer === 'stale' };
}

async function windowsDirectorySyncCapability() {
  return {
    windowsEpermUnsupported: directorySyncUnsupported({ code: 'EPERM' }, 'win32'),
    windowsAccessDeniedUnsupported: directorySyncUnsupported({ code: 'EACCES' }, 'win32'),
    linuxEpermUnsupported: directorySyncUnsupported({ code: 'EPERM' }, 'linux'),
  };
}

async function failedStart({ uploadGrant, requestContext, label }) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-auth-'));
  const value = await service(root);
  const fingerprint = semanticIdempotencyFingerprint({
    declaredLength: fixtureBytes.length,
    objectId,
    operation: 'start-upload',
    partSize: fixtureBytes.length,
  });
  const code = await errorCode(() => value.startUpload({
    objectId,
    declaredLength: fixtureBytes.length,
    partSize: fixtureBytes.length,
    idempotencyKey: idempotencyKey(label),
    idempotencyFingerprint: fingerprint,
    grant: uploadGrant,
    context: requestContext,
  }));
  return { code, mutationCount: (await value.lifecycle.listBounded()).length };
}

async function wrongAudience() {
  return failedStart({
    uploadGrant: grant('upload', 'wrong-audience', { audience: 'other.example' }),
    requestContext: context,
    label: 'wrong-audience',
  });
}

async function staleAuthorityEpoch() {
  return failedStart({
    uploadGrant: grant('upload', 'stale-epoch'),
    requestContext: { ...context, authorityEpoch: 10 },
    label: 'stale-epoch',
  });
}

async function crossTenantProbe() {
  return failedStart({
    uploadGrant: grant('upload', 'cross-tenant'),
    requestContext: { ...context, tenant: 'tenant-beta' },
    label: 'cross-tenant',
  });
}

async function expiredServerClockGrant() {
  return failedStart({
    uploadGrant: grant('upload', 'expired-server-clock', {
      issuedAt: 1_799_999_900,
      expiresAt: Math.floor(nowMs / 1000) - 1,
    }),
    requestContext: { ...context, now: 1_800_000_001 },
    label: 'expired-server-clock',
  });
}

async function replayedSingleUseNonce() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-nonce-'));
  const singleUse = grant('upload', 'persistent-vector-nonce', { replay: 'single-use' });
  let value = await service(root);
  await value.negotiateMissing({ objectIds: [objectId], grant: singleUse, context });
  const before = await readdir(join(root, 'nonce-replay'));
  value = await service(root);
  const code = await errorCode(() => value.negotiateMissing({ objectIds: [objectId], grant: singleUse, context }));
  const after = await readdir(join(root, 'nonce-replay'));
  return { code, mutationCount: after.length - before.length };
}

async function conflictingPartRetry() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-part-conflict-'));
  const value = await service(root);
  const uploadGrant = grant('upload', 'part-conflict');
  const { started } = await startSinglePart(value, uploadGrant, 'part-conflict-start');
  await value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes: fixtureBytes,
    sha256: sha256(fixtureBytes),
    grant: uploadGrant,
    context,
  });
  const conflict = Buffer.alloc(fixtureBytes.length, 0xff);
  const code = await errorCode(() => value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes: conflict,
    sha256: sha256(conflict),
    grant: uploadGrant,
    context,
  }));
  const status = await value.sessionStatus({ sessionId: started.sessionId, grant: uploadGrant, context });
  return { code, mutationCount: status.receivedParts.length };
}

async function backendOnlyObject() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-backend-only-'));
  const value = await service(root);
  await value.backend.createIfAbsent({
    opaqueKey: resume.expected.opaqueKey,
    objectId,
    length: fixtureBytes.length,
    source: fixtureBytes,
  });
  const lifecycle = await value.lifecycle.get(resume.expected.opaqueKey);
  const missing = await value.negotiateMissing({
    objectIds: [objectId], grant: grant('upload', 'backend-only'), context,
  });
  return {
    discoverable: lifecycle !== null,
    available: !missing.missing.includes(objectId),
  };
}

async function corruptPersistedState() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-corrupt-state-'));
  const value = await service(root);
  const uploadGrant = grant('upload', 'corrupt-state');
  const { started } = await startSinglePart(value, uploadGrant, 'corrupt-state-start');
  const path = join(root, 'sessions', `${started.sessionId}.json`);
  const record = JSON.parse(await readFile(path));
  record.untrusted = true;
  await writeFile(path, canonicalBytes(record));
  const code = await errorCode(() => value.sessionStatus({ sessionId: started.sessionId, grant: uploadGrant, context }));
  return { code, mutationCount: 0 };
}

async function staleFinalizeReplay() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-stale-finalize-'));
  const value = await service(root);
  const finalized = await finalizeSinglePart(value, 'stale-finalize');
  const current = await value.lifecycle.get(finalized.receipt.opaqueKey);
  await value.lifecycle.compareAndSwap({
    opaqueKey: current.opaqueKey,
    expectedGeneration: current.generation,
    expectedState: 'available',
    nextState: 'quarantined',
    authorityBindingSha256: current.authorityBindingSha256,
  });
  return {
    code: await errorCode(() => value.finalizeUpload(finalized.arguments_)),
    falseCurrentAvailableReceipt: false,
  };
}

async function rangeQuarantineRace() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-range-race-'));
  const value = await service(root);
  const finalized = await finalizeSinglePart(value, 'range-race');
  const originalRead = value.backend.readVerifiedRange.bind(value.backend);
  let raced = false;
  value.backend.readVerifiedRange = async (...arguments_) => {
    const range = await originalRead(...arguments_);
    if (!raced) {
      raced = true;
      const current = await value.lifecycle.get(finalized.receipt.opaqueKey);
      await value.lifecycle.compareAndSwap({
        opaqueKey: current.opaqueKey,
        expectedGeneration: current.generation,
        expectedState: 'available',
        nextState: 'quarantined',
        authorityBindingSha256: current.authorityBindingSha256,
      });
    }
    return range;
  };
  const code = await errorCode(() => value.readRange({
    objectId,
    start: 0,
    endExclusive: fixtureBytes.length,
    grant: grant('download', 'range-race-download'),
    context,
  }));
  return { code, returnedBytes: false };
}

async function backendDurabilityFault(vector) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-durability-'));
  const store = await new LifecycleStore({ root: join(root, 'lifecycle'), now: () => nowMs }).initialize();
  await store.createStaged({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: Buffer.from(create.input.bytesHex, 'hex').length,
    authorityBindingSha256,
    tenantScopeSha256,
  });
  let inject = true;
  const backend = await new FilesystemObjectBackend({
    root: join(root, 'backend'),
    fault: async (phase) => {
      if (inject && phase === vector.input.phase) {
        inject = false;
        throw new Error(`fault:${phase}`);
      }
    },
  }).initialize();
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  await errorCode(() => backend.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
  }));
  const lifecycle = await store.get(create.expected.opaqueKey);
  return {
    lifecycleState: lifecycle.state,
    availableReceipt: lifecycle.state === 'available',
    ...(Object.hasOwn(vector.expected, 'retryRepairs') ? {
      retryRepairs: await new FilesystemObjectBackend({ root: join(root, 'backend') }).initialize()
        .then((recovered) => recovered.createIfAbsent({
          opaqueKey: create.expected.opaqueKey,
          objectId: create.input.objectId,
          length: bytes.length,
          source: bytes,
        }))
        .then(() => true),
    } : {}),
  };
}

async function eexistRetryDirectorySync() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-eexist-'));
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  let inject = true;
  const phases = [];
  const backend = await new FilesystemObjectBackend({
    root,
    fault: async (phase) => {
      phases.push(phase);
      if (inject && phase === 'after-link') {
        inject = false;
        throw new Error('fault:after-link');
      }
    },
  }).initialize();
  await errorCode(() => backend.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
  }));
  phases.length = 0;
  const retry = await backend.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
  });
  return {
    directorySyncedBeforeReceipt: phases.at(-1) === 'after-directory-sync',
    createdOnRetry: retry.created,
  };
}

async function availableResponseLoss() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-available-loss-'));
  let inject = true;
  let value = await service(root, async (phase) => {
    if (inject && phase === 'after-lifecycle-cas') {
      inject = false;
      throw new Error('fault:after-lifecycle-cas');
    }
  });
  const uploadGrant = grant('upload', 'available-loss');
  const { started } = await startSinglePart(value, uploadGrant, 'available-loss-start');
  await value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes: fixtureBytes,
    sha256: sha256(fixtureBytes),
    grant: uploadGrant,
    context,
  });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId });
  const arguments_ = {
    sessionId: started.sessionId,
    idempotencyKey: idempotencyKey('available-loss-final'),
    idempotencyFingerprint: fingerprint,
    grant: uploadGrant,
    context,
  };
  await errorCode(() => value.finalizeUpload(arguments_));
  const lifecycle = await value.lifecycle.get(resume.expected.opaqueKey);
  value = await service(root);
  const repaired = await value.finalizeUpload(arguments_);
  return {
    lifecycleState: lifecycle.state,
    availableReceipt: lifecycle.state === 'available',
    retryReplays: repaired.generation === lifecycle.generation,
  };
}

async function quarantineFinalizeResponseRace() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-quarantine-finalize-'));
  let value;
  let race = true;
  value = await service(root, async (phase) => {
    if (phase !== 'after-lifecycle-cas' || !race) return;
    race = false;
    const [opaqueKey] = await value.backend.listByInternalPrefix();
    const current = await value.lifecycle.get(opaqueKey);
    await value.lifecycle.compareAndSwap({
      opaqueKey,
      expectedGeneration: current.generation,
      expectedState: 'available',
      nextState: 'quarantined',
      authorityBindingSha256: current.authorityBindingSha256,
    });
  });
  const uploadGrant = grant('upload', 'quarantine-finalize');
  const { started } = await startSinglePart(value, uploadGrant, 'quarantine-finalize-start');
  await value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes: fixtureBytes,
    sha256: sha256(fixtureBytes),
    grant: uploadGrant,
    context,
  });
  const fingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId });
  const code = await errorCode(() => value.finalizeUpload({
    sessionId: started.sessionId,
    idempotencyKey: idempotencyKey('quarantine-finalize'),
    idempotencyFingerprint: fingerprint,
    grant: uploadGrant,
    context,
  }));
  return { code, falseCurrentAvailableReceipt: false };
}

async function liveLockLeaseRenewal(vector) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-renewal-'));
  const rootPin = await pinPlainDirectory(root);
  let entered;
  const enteredPromise = new Promise((resolveEntered) => { entered = resolveEntered; });
  const owner = withRecoverableDirectoryLock({
    rootPin,
    name: '8'.repeat(64),
    now: () => Date.now(),
    attempts: 1,
    leaseMilliseconds: vector.input.leaseMilliseconds,
    operation: async (lockGuard) => {
      entered();
      await wait(vector.input.operationMilliseconds);
      await lockGuard.assertOwned();
      return true;
    },
  });
  await enteredPromise;
  await wait(vector.input.leaseMilliseconds + 50);
  const takeoverCode = await errorCode(() => withRecoverableDirectoryLock({
    rootPin,
    name: '8'.repeat(64),
    now: () => Date.now(),
    attempts: 1,
    leaseMilliseconds: vector.input.leaseMilliseconds,
    operation: async () => true,
  }));
  return { ownerCompleted: await owner, takeover: takeoverCode !== 'TRANSFER_SESSION_STATE' };
}

async function deleteResponseLoss() {
  let now = nowMs;
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-vector-delete-loss-'));
  const backend = await new FilesystemObjectBackend({ root: join(root, 'backend') }).initialize();
  const payload = Buffer.from('vector deletion response-loss fixture');
  const deleteObjectId = hashObject(1, payload).toString();
  const opaqueKey = '9'.repeat(64);
  let loseResponse = true;
  const store = await new LifecycleStore({
    root: join(root, 'lifecycle'),
    now: () => now,
    deleteObject: async (permit) => {
      const receipt = await backend.safeDelete({ permit });
      if (loseResponse) {
        loseResponse = false;
        throw new Error('delete-response-lost');
      }
      return receipt;
    },
  }).initialize();
  const durable = await backend.createIfAbsent({
    opaqueKey, objectId: deleteObjectId, length: payload.length, source: payload,
  });
  let lifecycle = await store.createStaged({
    opaqueKey,
    objectId: deleteObjectId,
    length: payload.length,
    authorityBindingSha256,
    tenantScopeSha256,
  });
  lifecycle = await store.compareAndSwap({
    opaqueKey,
    expectedGeneration: lifecycle.generation,
    expectedState: 'staged',
    nextState: 'available',
    backendReceipt: durable,
    authorityBindingSha256,
  });
  lifecycle = await store.compareAndSwap({
    opaqueKey,
    expectedGeneration: lifecycle.generation,
    expectedState: 'available',
    nextState: 'quarantined',
    authorityBindingSha256,
  });
  now = lifecycle.retentionUntilUnixMs;
  lifecycle = await store.compareAndSwap({
    opaqueKey,
    expectedGeneration: lifecycle.generation,
    expectedState: 'quarantined',
    nextState: 'deleting',
    authorityBindingSha256,
  });
  await errorCode(() => store.deleteAuthorized({
    opaqueKey,
    expectedGeneration: lifecycle.generation,
    authorityBindingSha256,
  }));
  const firstLifecycleState = (await store.get(opaqueKey)).state;
  const deleted = await store.deleteAuthorized({
    opaqueKey,
    expectedGeneration: lifecycle.generation,
    authorityBindingSha256,
  });
  return {
    firstLifecycleState,
    finalLifecycleState: deleted.state,
    retryRepairs: deleted.deletionReceiptSha256 !== null,
  };
}

export const HOSTILE_DISPATCH = Object.freeze({
  'wrong-audience': wrongAudience,
  'stale-authority-epoch': staleAuthorityEpoch,
  'replayed-single-use-nonce': replayedSingleUseNonce,
  'cross-tenant-key-probe': crossTenantProbe,
  'backend-key-traversal': backendTraversal,
  'conflicting-part-retry': conflictingPartRetry,
  'corrupt-stored-payload': corruptStoredPayload,
  'stale-lifecycle-generation': staleLifecycleGeneration,
  'backend-only-object': backendOnlyObject,
  'symlink-object-fanout': symlinkFanout,
  'symlink-object-ancestor': symlinkAncestor,
  'expired-server-clock-grant': expiredServerClockGrant,
  'malformed-metadata-identity': malformedMetadata,
  'stale-finalize-replay': staleFinalizeReplay,
  'range-quarantine-race': rangeQuarantineRace,
  'corrupt-persisted-state': corruptPersistedState,
  'forged-deleting-generation': forgedDeletingGeneration,
  'stale-lock-fencing-token': staleLockFence,
  'windows-directory-sync-capability': windowsDirectorySyncCapability,
});

export const FAULT_DISPATCH = Object.freeze({
  'before-temp-file-sync': backendDurabilityFault,
  'after-file-sync-before-link': backendDurabilityFault,
  'after-link-before-directory-sync': backendDurabilityFault,
  'after-durability-before-lifecycle-cas': backendDurabilityFault,
  'after-available-before-response': availableResponseLoss,
  'quarantine-races-finalize-response': quarantineFinalizeResponseRace,
  'eexist-retry-directory-sync': eexistRetryDirectorySync,
  'live-lock-lease-renewal': liveLockLeaseRenewal,
  'delete-response-loss-after-unlink': deleteResponseLoss,
});

export async function executeVectorSet(vectorSet, dispatch) {
  assert.equal(typeof vectorSet?.schemaVersion, 'string', 'vector set lacks a schema version');
  assert.equal(Array.isArray(vectorSet?.cases), true, 'vector set lacks cases');
  assert.deepEqual(
    Object.keys(dispatch).sort(),
    vectorSet.cases.map(({ id }) => id).sort(),
    'executable dispatch differs from the versioned vector inventory',
  );
  const results = [];
  for (const vector of vectorSet.cases) {
    const actual = await dispatch[vector.id](vector);
    assert.deepEqual(actual, vector.expected, `${vector.id} result differs from its versioned expectation`);
    results.push(Object.freeze({ id: vector.id, actual }));
  }
  return Object.freeze(results);
}
