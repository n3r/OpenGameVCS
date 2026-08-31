import { createHash, createHmac, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, open, opendir, rmdir, unlink } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { ObjectRef } from '@opengamevcs/object-model';
import { verifyTransferGrant } from '@opengamevcs/authorization-contract';
import {
  IdempotencyReplayStore,
  canonicalBytes,
  cloneJson,
  semanticIdempotencyFingerprint,
} from '@opengamevcs/protocol-baseline';
import { FilesystemObjectBackend } from './backend.mjs';
import { ObjectTransferError, mapIo, transferError } from './errors.mjs';
import {
  assertPinnedDirectory,
  atomicJsonCreate,
  atomicJsonWrite,
  pinPlainDirectory,
  pinPlainDirectoryIfExists,
  readExact,
  readJson,
  syncDirectory,
  withRecoverableDirectoryLock,
  writeAll,
} from './fs-util.mjs';
import { LifecycleStore } from './lifecycle.mjs';

export const TRANSFER_LIMITS = Object.freeze({
  batchMaximum: 4096,
  objectMaximum: 67_108_864,
  partMaximum: 4_194_304,
  partsMaximum: 1024,
  sessionsMaximum: 1024,
  sessionsPerTenantMaximum: 256,
  sessionTtlMaximumMs: 86_400_000,
  nonceRecordsMaximum: 4096,
  tenantStagingBytesMaximum: 268_435_456,
  transferBytesPerMinuteMaximum: 268_435_456,
});

const SHA = /^[0-9a-f]{64}$/u;
const SESSION = SHA;
const QUOTA_LOCK = createHash('sha256').update('OGVCS-TRANSFER-SESSION-QUOTA-LOCK-V1').digest('hex');
const NONCE_LOCK = createHash('sha256').update('OGVCS-TRANSFER-NONCE-QUOTA-LOCK-V1').digest('hex');
const SESSION_KEYS = [
  'audience',
  'authorityBindingSha256',
  'authorityEpoch',
  'cleanupAfterUnixMs',
  'declaredLength',
  'expiresAtUnixMs',
  'finalized',
  'idempotencyFingerprint',
  'initialGrantBindingSha256',
  'keyGeneration',
  'lastGrantBindingSha256',
  'objectId',
  'opaqueKey',
  'partSize',
  'parts',
  'schemaVersion',
  'sessionId',
  'state',
  'tenantScopeSha256',
  'updatedAtUnixMs',
].sort().join('\0');
const AVAILABLE_RECEIPT_KEYS = [
  'authorityBindingSha256',
  'backendReceiptSha256',
  'generation',
  'grantBindingSha256',
  'length',
  'objectId',
  'opaqueKey',
  'receiptSha256',
  'schemaVersion',
  'state',
  'tenantScopeSha256',
].sort().join('\0');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function integer(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  }
  return value;
}

function objectIdValue(value) {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value) throw new TypeError('ObjectID is not canonical');
    return value;
  } catch (error) {
    transferError('TRANSFER_INPUT_INVALID', 'ObjectID is invalid', { cause: error });
  }
}

function sessionValue(value) {
  if (typeof value !== 'string' || !SESSION.test(value)) transferError('TRANSFER_INPUT_INVALID', 'session ID is invalid');
  return value;
}

function publicError(error) {
  if (error instanceof ObjectTransferError) throw error;
  if (error?.code === 'IDEMPOTENCY_KEY_REUSE') {
    transferError('TRANSFER_IDEMPOTENCY_CONFLICT', 'idempotency key conflicts with prior input');
  }
  if (error?.code?.startsWith?.('PROTOCOL_') || error?.code === 'IDEMPOTENCY_KEY_REQUIRED') {
    transferError('TRANSFER_INPUT_INVALID', 'public protocol idempotency input is invalid');
  }
  throw error;
}

function validateAvailableReceipt(value, session) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== AVAILABLE_RECEIPT_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/available-receipt/v1'
      || value.state !== 'available' || value.objectId !== session.objectId
      || value.opaqueKey !== session.opaqueKey || value.length !== session.declaredLength
      || value.authorityBindingSha256 !== session.authorityBindingSha256
      || value.tenantScopeSha256 !== session.tenantScopeSha256
      || value.grantBindingSha256 !== session.lastGrantBindingSha256
      || !Number.isSafeInteger(value.generation) || value.generation < 2
      || !SHA.test(value.backendReceiptSha256 ?? '') || !SHA.test(value.grantBindingSha256 ?? '')
      || !SHA.test(value.receiptSha256 ?? '')) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'finalized session receipt is invalid');
  }
  const { receiptSha256, ...body } = value;
  if (sha256(canonicalBytes(body)) !== receiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'finalized session receipt digest is invalid');
  }
  return Object.freeze(value);
}

function validateSessionRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== SESSION_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/upload-session/v1'
      || !SESSION.test(value.sessionId ?? '') || !SHA.test(value.opaqueKey ?? '')
      || !SHA.test(value.authorityBindingSha256 ?? '') || !SHA.test(value.tenantScopeSha256 ?? '')
      || !SHA.test(value.initialGrantBindingSha256 ?? '')
      || !(value.lastGrantBindingSha256 === null || SHA.test(value.lastGrantBindingSha256 ?? ''))
      || !SHA.test(value.idempotencyFingerprint ?? '')
      || !Number.isSafeInteger(value.declaredLength) || value.declaredLength < 0
      || value.declaredLength > TRANSFER_LIMITS.objectMaximum
      || !Number.isSafeInteger(value.partSize) || value.partSize < 1 || value.partSize > TRANSFER_LIMITS.partMaximum
      || !Number.isSafeInteger(value.authorityEpoch) || value.authorityEpoch < 1
      || !Number.isSafeInteger(value.keyGeneration) || value.keyGeneration < 1
      || typeof value.audience !== 'string' || value.audience.length < 1 || value.audience.length > 128
      || !Number.isSafeInteger(value.expiresAtUnixMs) || value.expiresAtUnixMs < 1
      || !Number.isSafeInteger(value.cleanupAfterUnixMs) || value.cleanupAfterUnixMs < value.expiresAtUnixMs
      || !Number.isSafeInteger(value.updatedAtUnixMs) || value.updatedAtUnixMs < 0
      || !['open', 'finalized', 'aborted'].includes(value.state)
      || !Array.isArray(value.parts) || value.parts.length > TRANSFER_LIMITS.partsMaximum) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'upload session record is invalid');
  }
  try {
    const parsed = ObjectRef.parse(value.objectId);
    if (parsed.toString() !== value.objectId) throw new TypeError('ObjectID is not canonical');
  } catch (error) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'persisted session ObjectID is invalid', { cause: error });
  }
  const expectedPartCount = Math.ceil(value.declaredLength / value.partSize);
  let prior = -1;
  for (const part of value.parts) {
    if (!part || typeof part !== 'object' || Array.isArray(part)
        || Object.keys(part).sort().join('\0') !== 'index\0length\0sha256'
        || !Number.isSafeInteger(part.index) || part.index < 0 || part.index >= expectedPartCount
        || part.index <= prior || !Number.isSafeInteger(part.length) || part.length < 1
        || part.length > value.partSize || !SHA.test(part.sha256 ?? '')) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'upload session part record is invalid');
    }
    const expectedLength = part.index === expectedPartCount - 1
      ? value.declaredLength - part.index * value.partSize
      : value.partSize;
    if (part.length !== expectedLength) transferError('TRANSFER_BACKEND_CORRUPT', 'upload session part length is invalid');
    prior = part.index;
  }
  if (value.state === 'finalized') {
    if (value.lastGrantBindingSha256 === null) transferError('TRANSFER_BACKEND_CORRUPT', 'finalized session lacks a grant binding');
    validateAvailableReceipt(value.finalized, value);
  } else if (value.finalized !== null || value.lastGrantBindingSha256 !== null) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'non-finalized session carries finalized state');
  }
  return Object.freeze(value);
}

export class ObjectTransferService {
  #fault;
  #idempotency;
  #publicJwk;
  #rate = new Map();
  #secret;
  #verifyGrant;
  #rootPin;
  #sessionsPin;
  #sessionLocksPin;
  #partsPin;
  #noncesPin;

  constructor({
    root,
    backendSecret,
    authorizationPublicJwk,
    audience,
    authorityEpoch,
    keyGeneration,
    issuer,
    keyId,
    now = () => Date.now(),
    verifyGrant = verifyTransferGrant,
    fault = async () => {},
    maxBatchRequestsPerMinute = 120,
    maxTransferBytesPerMinute = TRANSFER_LIMITS.transferBytesPerMinuteMaximum,
    maxTenantStagingBytes = TRANSFER_LIMITS.tenantStagingBytesMaximum,
    maxSessionsPerTenant = TRANSFER_LIMITS.sessionsPerTenantMaximum,
    safetyWindowMilliseconds = 3_600_000,
    lockLeaseMilliseconds = 300_000,
  } = {}) {
    if (typeof root !== 'string' || !isAbsolute(root) || !(backendSecret instanceof Uint8Array)
        || backendSecret.byteLength < 32 || typeof audience !== 'string' || typeof issuer !== 'string'
        || typeof keyId !== 'string' || typeof now !== 'function' || typeof verifyGrant !== 'function'
        || typeof fault !== 'function') {
      transferError('TRANSFER_INPUT_INVALID', 'transfer service configuration is invalid');
    }
    integer(authorityEpoch, 1, Number.MAX_SAFE_INTEGER, 'authority epoch');
    integer(keyGeneration, 1, Number.MAX_SAFE_INTEGER, 'key generation');
    integer(maxBatchRequestsPerMinute, 1, 100_000, 'rate limit');
    integer(maxTransferBytesPerMinute, 1, 1_099_511_627_776, 'transfer-byte rate limit');
    integer(maxTenantStagingBytes, 1, 1_099_511_627_776, 'tenant staging limit');
    integer(maxSessionsPerTenant, 1, TRANSFER_LIMITS.sessionsMaximum, 'tenant session limit');
    integer(safetyWindowMilliseconds, 3_600_000, 31_536_000_000, 'safety window');
    integer(lockLeaseMilliseconds, 1_000, 86_400_000, 'lock lease');
    this.root = resolve(root);
    this.sessionsRoot = join(this.root, 'sessions');
    this.sessionLocksRoot = join(this.root, 'session-locks');
    this.partsRoot = join(this.root, 'parts');
    this.noncesRoot = join(this.root, 'nonce-replay');
    this.backend = new FilesystemObjectBackend({ root: join(this.root, 'backend'), fault });
    this.lifecycle = new LifecycleStore({
      root: join(this.root, 'lifecycle'),
      now,
      safetyWindowMilliseconds,
      lockLeaseMilliseconds,
      deleteObject: (permit) => this.backend.safeDelete({ permit }),
    });
    this.#secret = Buffer.from(backendSecret);
    this.#publicJwk = cloneJson(authorizationPublicJwk, { maxBytes: 16 * 1024 });
    this.audience = audience;
    this.authorityEpoch = authorityEpoch;
    this.keyGeneration = keyGeneration;
    this.issuer = issuer;
    this.keyId = keyId;
    this.now = now;
    this.maxBatchRequestsPerMinute = maxBatchRequestsPerMinute;
    this.maxTransferBytesPerMinute = maxTransferBytesPerMinute;
    this.maxTenantStagingBytes = maxTenantStagingBytes;
    this.maxSessionsPerTenant = maxSessionsPerTenant;
    this.safetyWindowMilliseconds = safetyWindowMilliseconds;
    this.lockLeaseMilliseconds = lockLeaseMilliseconds;
    this.#verifyGrant = verifyGrant;
    this.#fault = fault;
    this.#idempotency = new IdempotencyReplayStore({
      now,
      maxEntries: 4096,
      maxBytes: 16 * 1024 * 1024,
      maxOutcomeBytes: 64 * 1024,
    });
  }

  async initialize() {
    this.#rootPin = await pinPlainDirectory(this.root);
    this.#sessionsPin = await pinPlainDirectory(this.sessionsRoot, { parentPin: this.#rootPin });
    this.#sessionLocksPin = await pinPlainDirectory(this.sessionLocksRoot, { parentPin: this.#rootPin });
    this.#partsPin = await pinPlainDirectory(this.partsRoot, { parentPin: this.#rootPin });
    this.#noncesPin = await pinPlainDirectory(this.noncesRoot, { parentPin: this.#rootPin });
    await this.backend.initialize({ parentPin: this.#rootPin });
    await this.lifecycle.initialize({ parentPin: this.#rootPin });
    await this.#withSessionLock(NONCE_LOCK, (lockGuard) => this.#cleanupNonces(lockGuard));
    await this.#withSessionLock(QUOTA_LOCK, (lockGuard) => this.#cleanupSessions(null, lockGuard));
    return this;
  }

  async #assertRoots() {
    if (!this.#rootPin) transferError('TRANSFER_BACKEND_IO', 'transfer service is not initialized');
    await assertPinnedDirectory(this.#rootPin);
    await assertPinnedDirectory(this.#sessionsPin);
    await assertPinnedDirectory(this.#sessionLocksPin);
    await assertPinnedDirectory(this.#partsPin);
    await assertPinnedDirectory(this.#noncesPin);
  }

  #hmac(domain, ...parts) {
    const hash = createHmac('sha256', this.#secret).update(domain);
    for (let index = 0; index < parts.length; index += 1) {
      if (index > 0) hash.update('\0');
      hash.update(parts[index]);
    }
    return hash.digest('hex');
  }

  #opaqueKey(tenant, objectId) { return this.#hmac('OGVCS-OBJECT-BACKEND-KEY-V1\0', tenant, objectId); }
  #tenantScope(tenant) { return this.#hmac('OGVCS-TRANSFER-TENANT-SCOPE-V1\0', tenant); }
  #grantBinding(claims) {
    return sha256(Buffer.concat([Buffer.from('OGVCS-TRANSFER-GRANT-BINDING-V1\0'), canonicalBytes(claims)]));
  }
  #authorityBinding(claims, objectId) {
    return sha256(Buffer.concat([
      Buffer.from('OGVCS-TRANSFER-AUTHORITY-BINDING-V1\0'),
      canonicalBytes({
        issuer: claims.issuer,
        keyId: claims.keyId,
        keyGeneration: claims.keyGeneration,
        authorityEpoch: claims.authorityEpoch,
        subject: claims.subject,
        tenant: claims.tenant,
        repository: claims.repository,
        permission: claims.permission,
        operation: claims.operation,
        audience: claims.audience,
        objectId,
        requestRoot: claims.requestRoot,
      }),
    ]));
  }

  #sessionPath(id) { return join(this.sessionsRoot, `${sessionValue(id)}.json`); }

  async #session(id) {
    await this.#assertRoots();
    const value = await readJson(this.#sessionPath(id), 1024 * 1024, { directoryPin: this.#sessionsPin });
    if (!value) transferError('TRANSFER_SESSION_STATE', 'upload session is absent');
    return validateSessionRecord(value);
  }

  async #withSessionLock(id, operation) {
    await this.#assertRoots();
    return withRecoverableDirectoryLock({
      rootPin: this.#sessionLocksPin,
      name: sessionValue(id),
      now: this.now,
      leaseMilliseconds: this.lockLeaseMilliseconds,
      busyCode: 'TRANSFER_SESSION_STATE',
      busyMessage: 'upload session is busy',
      operation,
    });
  }

  async #cleanupNonces(lockGuard) {
    await this.#assertRoots();
    const nowSeconds = Math.floor(this.now() / 1000);
    let seen = 0;
    let retained = 0;
    let changed = false;
    const directory = await opendir(this.noncesRoot);
    try {
      for await (const entry of directory) {
        seen += 1;
        if (seen > TRANSFER_LIMITS.nonceRecordsMaximum) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'nonce replay store exceeds its bound');
        }
        if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'nonce replay store contains an unexpected entry');
        }
        const path = join(this.noncesRoot, entry.name);
        const value = await readJson(path, 8192, { directoryPin: this.#noncesPin });
        if (!value || value.schemaVersion !== 'ogvcs.object-transfer/nonce-claim/v1'
            || Object.keys(value).sort().join('\0') !== 'claimId\0expiresAtUnixSeconds\0schemaVersion'
            || value.claimId !== entry.name.slice(0, 64) || !Number.isSafeInteger(value.expiresAtUnixSeconds)
            || value.expiresAtUnixSeconds < 0) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'nonce replay record is invalid');
        }
        if (value.expiresAtUnixSeconds <= nowSeconds) {
          await lockGuard.assertOwned();
          await unlink(path);
          changed = true;
        } else retained += 1;
      }
    } finally { await directory.close().catch(() => {}); }
    if (changed) {
      await syncDirectory(this.noncesRoot, this.#noncesPin);
      await lockGuard.assertOwned();
    }
    return retained;
  }

  async #claimSingleUse(claims) {
    if (claims.replay !== 'single-use') return;
    await this.#withSessionLock(NONCE_LOCK, async (lockGuard) => {
      const retained = await this.#cleanupNonces(lockGuard);
      if (retained >= TRANSFER_LIMITS.nonceRecordsMaximum) {
        transferError('TRANSFER_LIMIT_EXCEEDED', 'nonce replay store exceeds its bound');
      }
      const claimId = this.#hmac(
        'OGVCS-TRANSFER-NONCE-CLAIM-V1\0',
        canonicalBytes({
          issuer: claims.issuer,
          keyId: claims.keyId,
          keyGeneration: claims.keyGeneration,
          authorityEpoch: claims.authorityEpoch,
          tenant: claims.tenant,
          repository: claims.repository,
          subject: claims.subject,
          nonce: claims.nonce,
        }),
      );
      const created = await atomicJsonCreate(join(this.noncesRoot, `${claimId}.json`), {
        schemaVersion: 'ogvcs.object-transfer/nonce-claim/v1',
        claimId,
        expiresAtUnixSeconds: claims.expiresAt,
      }, { directoryPin: this.#noncesPin, lockGuard });
      if (!created) transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    });
  }

  async #authorize({ grant, context, objectId, requestObjectIds, operation }) {
    const permission = operation === 'upload' ? 'content.upload' : 'content.materialize';
    let safeContext;
    let envelope;
    try {
      safeContext = cloneJson(context, { maxBytes: 256 * 1024, maxDepth: 6, maxNodes: 8192, maxCollectionItems: 4096 });
      envelope = cloneJson(grant, { maxBytes: 256 * 1024, maxDepth: 12, maxNodes: 8192, maxCollectionItems: 4096 });
    } catch (error) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied', { cause: error });
    }
    if (!safeContext || typeof safeContext !== 'object' || Array.isArray(safeContext)
        || safeContext.audience !== this.audience || safeContext.authorityEpoch !== this.authorityEpoch
        || safeContext.keyGeneration !== this.keyGeneration || safeContext.issuer !== this.issuer
        || safeContext.keyId !== this.keyId) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
    const explicitObjectSet = envelope?.claims?.requestRoot === null;
    let verifierObjectIds = requestObjectIds;
    if (!explicitObjectSet && safeContext.requestObjectIds !== undefined) {
      if (!Array.isArray(safeContext.requestObjectIds) || safeContext.requestObjectIds.length < 1
          || safeContext.requestObjectIds.length > TRANSFER_LIMITS.batchMaximum) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
      }
      verifierObjectIds = safeContext.requestObjectIds.map(objectIdValue).sort();
      if (new Set(verifierObjectIds).size !== verifierObjectIds.length
          || requestObjectIds.some((id) => !verifierObjectIds.includes(id))) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
      }
    }
    const verifierContext = {
      schemaVersion: 'ogvcs.authorization/transfer-grant-context/v1',
      issuer: safeContext.issuer,
      keyId: safeContext.keyId,
      subject: safeContext.subject,
      permission,
      operation,
      audience: safeContext.audience,
      tenant: safeContext.tenant,
      repository: safeContext.repository,
      authorityEpoch: safeContext.authorityEpoch,
      keyGeneration: safeContext.keyGeneration,
      now: Math.floor(this.now() / 1000),
      objectId,
      requestObjectIds: explicitObjectSet ? [] : verifierObjectIds,
      consumedNonces: [],
    };
    let decision;
    try { decision = await this.#verifyGrant(envelope, verifierContext, this.#publicJwk); }
    catch (error) { transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied', { cause: error }); }
    if (decision?.result !== 'allow' || decision.code !== 'ALLOW_EXPLICIT') {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
    const claims = envelope?.claims;
    const explicitClaimsValid = claims?.requestRoot !== null
      || (Array.isArray(claims.objectIds)
        && claims.objectIds.length >= 1
        && claims.objectIds.length <= TRANSFER_LIMITS.batchMaximum
        && requestObjectIds.every((id) => claims.objectIds.includes(id)));
    if (!claims || typeof claims !== 'object' || Array.isArray(claims) || !explicitClaimsValid) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
    await this.#claimSingleUse(claims);
    return Object.freeze({
      claims,
      grantBindingSha256: this.#grantBinding(claims),
      authorityBindingSha256: this.#authorityBinding(claims, objectId),
      tenantScopeSha256: this.#tenantScope(claims.tenant),
      opaqueKey: this.#opaqueKey(claims.tenant, objectId),
    });
  }

  #checkRate(binding, { requests = 1, bytes = 0 } = {}) {
    integer(requests, 0, this.maxBatchRequestsPerMinute, 'rate request count');
    integer(bytes, 0, this.maxTransferBytesPerMinute, 'rate byte count');
    const scope = this.#hmac(
      'OGVCS-TRANSFER-RATE-SCOPE-V1\0',
      binding.claims.tenant,
      binding.claims.repository,
      binding.claims.subject,
    );
    const window = Math.floor(this.now() / 60_000);
    for (const [key, value] of this.#rate) if (value.window < window) this.#rate.delete(key);
    const existing = this.#rate.get(scope);
    const count = existing?.window === window ? existing.count + requests : requests;
    const transferred = existing?.window === window ? existing.bytes + bytes : bytes;
    if (this.#rate.size >= 1024 && !this.#rate.has(scope)) {
      transferError('TRANSFER_LIMIT_EXCEEDED', 'rate-state ceiling exceeded');
    }
    if (count > this.maxBatchRequestsPerMinute || transferred > this.maxTransferBytesPerMinute) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
    this.#rate.set(scope, { window, count, bytes: transferred });
  }

  #assertBindingFresh(binding) {
    const nowSeconds = Math.floor(this.now() / 1000);
    if (!Number.isSafeInteger(nowSeconds) || !Number.isSafeInteger(binding.claims.issuedAt)
        || !Number.isSafeInteger(binding.claims.expiresAt)
        || nowSeconds < binding.claims.issuedAt || nowSeconds >= binding.claims.expiresAt
        || binding.claims.authorityEpoch !== this.authorityEpoch
        || binding.claims.keyGeneration !== this.keyGeneration) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
  }

  async negotiateMissing({ objectIds, grant, context }) {
    if (!Array.isArray(objectIds) || objectIds.length < 1 || objectIds.length > TRANSFER_LIMITS.batchMaximum
        || new Set(objectIds).size !== objectIds.length) {
      transferError('TRANSFER_INPUT_INVALID', 'missing-object batch is invalid');
    }
    const ids = objectIds.map(objectIdValue).sort();
    const binding = await this.#authorize({ grant, context, objectId: ids[0], requestObjectIds: ids, operation: 'upload' });
    this.#checkRate(binding);
    const missing = [];
    for (const objectId of ids) {
      const key = this.#opaqueKey(binding.claims.tenant, objectId);
      const lifecycle = await this.lifecycle.get(key);
      if (lifecycle?.state !== 'available' || lifecycle.objectId !== objectId
          || lifecycle.tenantScopeSha256 !== binding.tenantScopeSha256) missing.push(objectId);
    }
    this.#assertBindingFresh(binding);
    return Object.freeze({ requestRoot: binding.claims.requestRoot, missing: Object.freeze(missing), count: missing.length });
  }

  async #executeIdempotent(input, mutate, authorizeReplay) {
    try {
      return await this.#idempotency.execute(input, mutate, {
        atUnixMs: this.now(),
        authorizeReplay,
        afterCommit: async () => this.#fault('after-idempotency-commit'),
      });
    } catch (error) { publicError(error); }
  }

  async #removeParts(sessionId, lockGuard) {
    const directoryPath = join(this.partsRoot, sessionValue(sessionId));
    const pin = await pinPlainDirectoryIfExists(directoryPath, { parentPin: this.#partsPin });
    if (!pin) return;
    let scanned = 0;
    const directory = await opendir(directoryPath);
    try {
      for await (const entry of directory) {
        scanned += 1;
        if (scanned > TRANSFER_LIMITS.partsMaximum * 2) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'session part directory exceeds its bound');
        }
        if (!entry.isFile() || (!/^\d+\.part$/u.test(entry.name)
            && !/^\.\d+\.[0-9a-f]{24}\.tmp$/u.test(entry.name))) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'session part directory contains an unexpected entry');
        }
        await assertPinnedDirectory(pin);
        await lockGuard.assertOwned();
        await unlink(join(directoryPath, entry.name));
      }
    } finally { await directory.close().catch(() => {}); }
    await lockGuard.assertOwned();
    await rmdir(directoryPath);
    await syncDirectory(this.partsRoot, this.#partsPin);
    await lockGuard.assertOwned();
  }

  async #cleanupPartTemps(session, lockGuard) {
    const directoryPath = join(this.partsRoot, sessionValue(session.sessionId));
    const pin = await pinPlainDirectoryIfExists(directoryPath, { parentPin: this.#partsPin });
    if (!pin) return;
    const partCount = Math.ceil(session.declaredLength / session.partSize);
    let scanned = 0;
    let changed = false;
    const directory = await opendir(directoryPath);
    try {
      for await (const entry of directory) {
        scanned += 1;
        if (scanned > TRANSFER_LIMITS.partsMaximum * 2) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'session part directory exceeds its bound');
        }
        if (!entry.isFile()) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'session part directory contains a non-file entry');
        }
        const persisted = /^(0|[1-9]\d{0,3})\.part$/u.exec(entry.name);
        if (persisted && Number(persisted[1]) < partCount) continue;
        const temporary = /^\.(0|[1-9]\d{0,3})\.[0-9a-f]{24}\.tmp$/u.exec(entry.name);
        if (!temporary || Number(temporary[1]) >= partCount) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'session part directory contains an unexpected entry');
        }
        await assertPinnedDirectory(pin);
        await lockGuard.assertOwned();
        await unlink(join(directoryPath, entry.name));
        changed = true;
      }
    } finally { await directory.close().catch(() => {}); }
    if (changed) {
      await syncDirectory(directoryPath, pin);
      await lockGuard.assertOwned();
    }
  }

  async #cleanupSessions(tenantScopeSha256 = null, quotaGuard) {
    await this.#assertRoots();
    if (tenantScopeSha256 !== null && !SHA.test(tenantScopeSha256)) {
      transferError('TRANSFER_INPUT_INVALID', 'tenant cleanup scope is invalid');
    }
    let retainedCount = 0;
    let tenantCount = 0;
    let tenantStagingBytes = 0;
    let scanned = 0;
    let changed = false;
    const directory = await opendir(this.sessionsRoot);
    try {
      for await (const entry of directory) {
        scanned += 1;
        if (scanned > TRANSFER_LIMITS.sessionsMaximum * 2) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'session directory exceeds its cleanup bound');
        }
        const temporary = /^\.([0-9a-f]{64})\.json\.[0-9a-f]{24}\.tmp$/u.exec(entry.name);
        if (temporary) {
          if (!entry.isFile()) transferError('TRANSFER_BACKEND_CORRUPT', 'session state temporary is not a file');
          const path = join(this.sessionsRoot, entry.name);
          let stat;
          try { stat = await lstat(path); } catch (error) {
            if (error?.code === 'ENOENT') continue;
            mapIo(error, 'session state temporary inspection failed');
          }
          if (!stat.isFile() || stat.isSymbolicLink()) {
            transferError('TRANSFER_BACKEND_CORRUPT', 'session state temporary is not plain');
          }
          if (stat.mtimeMs + 86_400_000 <= Date.now()) {
            await quotaGuard.assertOwned();
            await unlink(path);
            changed = true;
          }
          continue;
        }
        if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'session directory contains an unexpected entry');
        }
        const sessionId = entry.name.slice(0, 64);
        await this.#withSessionLock(sessionId, async (sessionGuard) => {
          const value = await readJson(this.#sessionPath(sessionId), 1024 * 1024, {
            directoryPin: this.#sessionsPin,
          });
          if (!value) return;
          const session = validateSessionRecord(value);
          if (this.now() >= session.cleanupAfterUnixMs) {
            await this.#removeParts(session.sessionId, sessionGuard);
            await quotaGuard.assertOwned();
            await sessionGuard.assertOwned();
            await unlink(this.#sessionPath(session.sessionId));
            changed = true;
          } else {
            await this.#cleanupPartTemps(session, sessionGuard);
            retainedCount += 1;
            if (session.tenantScopeSha256 === tenantScopeSha256) {
              tenantCount += 1;
              if (session.state === 'open') tenantStagingBytes += session.declaredLength;
            }
          }
        });
      }
    } finally { await directory.close().catch(() => {}); }
    if (changed) {
      await syncDirectory(this.sessionsRoot, this.#sessionsPin);
      await quotaGuard.assertOwned();
    }
    if (retainedCount > TRANSFER_LIMITS.sessionsMaximum) {
      transferError('TRANSFER_LIMIT_EXCEEDED', 'session-count ceiling exceeded');
    }
    return Object.freeze({ retainedCount, tenantCount, tenantStagingBytes });
  }

  #assertSessionBinding(session, binding) {
    this.#assertBindingFresh(binding);
    if (this.now() >= session.expiresAtUnixMs) transferError('TRANSFER_SESSION_EXPIRED', 'upload session expired');
    if (binding.authorityBindingSha256 !== session.authorityBindingSha256
        || binding.tenantScopeSha256 !== session.tenantScopeSha256
        || binding.opaqueKey !== session.opaqueKey) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
  }

  async startUpload({
    objectId: objectIdInput,
    declaredLength,
    partSize,
    idempotencyKey,
    idempotencyFingerprint,
    grant,
    context,
    sessionTtlMs = 3_600_000,
  }) {
    const objectId = objectIdValue(objectIdInput);
    integer(declaredLength, 0, TRANSFER_LIMITS.objectMaximum, 'declared length');
    integer(partSize, 1, TRANSFER_LIMITS.partMaximum, 'part size');
    integer(sessionTtlMs, 1, TRANSFER_LIMITS.sessionTtlMaximumMs, 'session TTL');
    const partCount = Math.ceil(declaredLength / partSize);
    if (partCount > TRANSFER_LIMITS.partsMaximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'part count exceeds its bound');
    const binding = await this.#authorize({ grant, context, objectId, requestObjectIds: [objectId], operation: 'upload' });
    this.#checkRate(binding);
    const expectedFingerprint = semanticIdempotencyFingerprint({ declaredLength, objectId, operation: 'start-upload', partSize });
    if (idempotencyFingerprint !== expectedFingerprint) {
      transferError('TRANSFER_IDEMPOTENCY_CONFLICT', 'start-upload fingerprint differs');
    }
    const scope = { authorityBindingSha256: binding.authorityBindingSha256, operation: 'start-upload' };
    const result = await this.#executeIdempotent({ scope, key: idempotencyKey, fingerprint: idempotencyFingerprint }, async () => {
      const sessionId = this.#hmac('OGVCS-UPLOAD-SESSION-ID-V1\0', binding.opaqueKey, idempotencyKey);
      return this.#withSessionLock(QUOTA_LOCK, (quotaGuard) => this.#withSessionLock(sessionId, async (sessionGuard) => {
        this.#assertBindingFresh(binding);
        const existingValue = await readJson(this.#sessionPath(sessionId), 1024 * 1024, { directoryPin: this.#sessionsPin });
        if (existingValue) {
          const existing = validateSessionRecord(existingValue);
          if (existing.idempotencyFingerprint !== idempotencyFingerprint
              || existing.authorityBindingSha256 !== binding.authorityBindingSha256) {
            transferError('TRANSFER_IDEMPOTENCY_CONFLICT', 'persisted session binding differs');
          }
          return this.#status(existing);
        }
        const usage = await this.#cleanupSessions(binding.tenantScopeSha256, quotaGuard);
        if (usage.retainedCount >= TRANSFER_LIMITS.sessionsMaximum
            || usage.tenantCount >= this.maxSessionsPerTenant
            || usage.tenantStagingBytes > this.maxTenantStagingBytes - declaredLength) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'tenant upload-session quota exceeded');
        }
        this.#assertBindingFresh(binding);
        await this.lifecycle.createStaged({
          opaqueKey: binding.opaqueKey,
          objectId,
          length: declaredLength,
          authorityBindingSha256: binding.authorityBindingSha256,
          tenantScopeSha256: binding.tenantScopeSha256,
        });
        const now = this.now();
        const expiresAtUnixMs = now + sessionTtlMs;
        const record = validateSessionRecord({
          schemaVersion: 'ogvcs.object-transfer/upload-session/v1',
          sessionId,
          objectId,
          opaqueKey: binding.opaqueKey,
          declaredLength,
          partSize,
          state: 'open',
          authorityEpoch: binding.claims.authorityEpoch,
          keyGeneration: binding.claims.keyGeneration,
          audience: binding.claims.audience,
          authorityBindingSha256: binding.authorityBindingSha256,
          tenantScopeSha256: binding.tenantScopeSha256,
          initialGrantBindingSha256: binding.grantBindingSha256,
          lastGrantBindingSha256: null,
          idempotencyFingerprint,
          expiresAtUnixMs,
          cleanupAfterUnixMs: expiresAtUnixMs + this.safetyWindowMilliseconds,
          updatedAtUnixMs: now,
          parts: [],
          finalized: null,
        });
        this.#assertBindingFresh(binding);
        await quotaGuard.assertOwned();
        await atomicJsonWrite(this.#sessionPath(sessionId), record, {
          directoryPin: this.#sessionsPin,
          lockGuard: sessionGuard,
        });
        return this.#status(record);
      }));
    }, async () => ({ result: 'allow', code: 'ALLOW_EXPLICIT' }));
    return result.outcome;
  }

  #status(session) {
    return Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/upload-session-status/v1',
      sessionId: session.sessionId,
      objectId: session.objectId,
      declaredLength: session.declaredLength,
      partSize: session.partSize,
      state: session.state,
      authorityEpoch: session.authorityEpoch,
      expiresAtUnixMs: session.expiresAtUnixMs,
      receivedParts: Object.freeze(session.parts.map(({ index, length, sha256: digest }) => Object.freeze({ index, length, sha256: digest }))),
      finalized: session.finalized,
    });
  }

  async #authorizeSession(session, grant, context) {
    if (this.now() >= session.expiresAtUnixMs) transferError('TRANSFER_SESSION_EXPIRED', 'upload session expired');
    const binding = await this.#authorize({ grant, context, objectId: session.objectId, requestObjectIds: [session.objectId], operation: 'upload' });
    this.#assertSessionBinding(session, binding);
    return binding;
  }

  async sessionStatus({ sessionId, grant, context }) {
    const session = await this.#session(sessionId);
    const binding = await this.#authorizeSession(session, grant, context);
    this.#checkRate(binding);
    return this.#status(session);
  }

  async uploadPart({ sessionId, index, bytes, sha256: expectedSha256, grant, context }) {
    const initial = await this.#session(sessionId);
    const binding = await this.#authorizeSession(initial, grant, context);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength > initial.partSize || !SHA.test(expectedSha256 ?? '')) {
      transferError('TRANSFER_INPUT_INVALID', 'upload part is invalid');
    }
    this.#checkRate(binding, { bytes: bytes.byteLength });
    return this.#withSessionLock(initial.sessionId, async (lockGuard) => {
      const session = await this.#session(initial.sessionId);
      this.#assertSessionBinding(session, binding);
      if (session.state !== 'open') transferError('TRANSFER_SESSION_STATE', 'upload session is not open');
      const partCount = Math.ceil(session.declaredLength / session.partSize);
      if (partCount < 1) transferError('TRANSFER_INPUT_INVALID', 'empty upload has no parts');
      integer(index, 0, partCount - 1, 'part index');
      const expectedLength = index === partCount - 1
        ? session.declaredLength - index * session.partSize
        : session.partSize;
      if (bytes.byteLength !== expectedLength || sha256(bytes) !== expectedSha256) {
        transferError('TRANSFER_INPUT_INVALID', 'upload part length or digest differs');
      }
      const directoryPath = join(this.partsRoot, session.sessionId);
      const directoryPin = await pinPlainDirectory(directoryPath, { parentPin: this.#partsPin });
      const path = join(directoryPath, `${index}.part`);
      const existing = session.parts.find((part) => part.index === index);
      if (existing) {
        if (existing.length !== bytes.byteLength || existing.sha256 !== expectedSha256) {
          transferError('TRANSFER_PART_CONFLICT', 'part retry differs');
        }
        const existingHandle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
          await assertPinnedDirectory(directoryPin);
          const stat = await existingHandle.stat();
          const stored = await readExact(existingHandle, existing.length, 0);
          if (!stat.isFile() || stat.size !== existing.length || sha256(stored) !== expectedSha256) {
            transferError('TRANSFER_BACKEND_CORRUPT', 'recorded part bytes are corrupt');
          }
        } finally { await existingHandle.close(); }
        return Object.freeze({ ...existing, replay: true });
      }
      const temporary = join(directoryPath, `.${index}.${randomBytes(12).toString('hex')}.tmp`);
      let handle;
      try {
        handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
        await assertPinnedDirectory(directoryPin);
        await writeAll(handle, Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength));
        await handle.sync();
        await handle.close();
        handle = undefined;
        await lockGuard.assertOwned();
        try { await link(temporary, path); } catch (error) { if (error?.code !== 'EEXIST') throw error; }
        await syncDirectory(directoryPath, directoryPin);
        await lockGuard.assertOwned();
        await unlink(temporary).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
        await syncDirectory(directoryPath, directoryPin);
        const persisted = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
        try {
          await assertPinnedDirectory(directoryPin);
          const stat = await persisted.stat();
          const stored = await readExact(persisted, expectedLength, 0);
          if (!stat.isFile() || stat.size !== expectedLength || sha256(stored) !== expectedSha256) {
            transferError('TRANSFER_PART_CONFLICT', 'persisted part differs');
          }
        } finally { await persisted.close(); }
        const parts = [...session.parts, { index, length: bytes.byteLength, sha256: expectedSha256 }]
          .sort((left, right) => left.index - right.index);
        const updated = validateSessionRecord({ ...session, parts, updatedAtUnixMs: this.now() });
        this.#assertBindingFresh(binding);
        await atomicJsonWrite(this.#sessionPath(session.sessionId), updated, {
          directoryPin: this.#sessionsPin,
          lockGuard,
        });
        return Object.freeze({ index, length: bytes.byteLength, sha256: expectedSha256, replay: false });
      } catch (error) {
        await handle?.close().catch(() => {});
        const removed = await unlink(temporary).then(() => true).catch(() => false);
        if (removed) await syncDirectory(directoryPath, directoryPin).catch(() => {});
        if (error?.code?.startsWith?.('TRANSFER_')) throw error;
        mapIo(error, 'part persistence failed');
      }
    });
  }

  async #assertFinalizedCurrent(sessionId, binding) {
    const session = await this.#session(sessionId);
    this.#assertSessionBinding(session, binding);
    if (session.state !== 'finalized' || !session.finalized) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'finalized session receipt is unavailable');
    }
    const current = await this.lifecycle.get(session.opaqueKey);
    if (current?.state !== 'available' || current.generation !== session.finalized.generation
        || current.backendReceiptSha256 !== session.finalized.backendReceiptSha256
        || current.authorityBindingSha256 !== session.authorityBindingSha256
        || current.tenantScopeSha256 !== session.tenantScopeSha256
        || current.objectId !== session.objectId || current.length !== session.declaredLength) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'finalized receipt is no longer current');
    }
    const backend = await this.backend.verify(session.opaqueKey);
    if (backend.receiptSha256 !== current.backendReceiptSha256 || backend.objectId !== session.objectId) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'finalized backend receipt is no longer exact');
    }
    const after = await this.lifecycle.get(session.opaqueKey);
    if (after?.state !== 'available' || after.generation !== current.generation
        || after.backendReceiptSha256 !== current.backendReceiptSha256
        || after.authorityBindingSha256 !== current.authorityBindingSha256
        || after.tenantScopeSha256 !== current.tenantScopeSha256
        || after.objectId !== current.objectId || after.length !== current.length) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'finalized receipt changed during replay');
    }
    return session.finalized;
  }

  async finalizeUpload({ sessionId, idempotencyKey, idempotencyFingerprint, grant, context }) {
    const original = await this.#session(sessionId);
    const initialBinding = await this.#authorizeSession(original, grant, context);
    this.#checkRate(initialBinding);
    const expectedFingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: original.sessionId });
    if (idempotencyFingerprint !== expectedFingerprint) {
      transferError('TRANSFER_IDEMPOTENCY_CONFLICT', 'finalize fingerprint differs');
    }
    if (original.finalized) await this.#assertFinalizedCurrent(original.sessionId, initialBinding);
    const scope = {
      authorityBindingSha256: initialBinding.authorityBindingSha256,
      operation: 'finalize-upload',
      sessionId: original.sessionId,
    };
    const result = await this.#executeIdempotent({ scope, key: idempotencyKey, fingerprint: idempotencyFingerprint }, async () => (
      this.#withSessionLock(original.sessionId, async (lockGuard) => {
        const session = await this.#session(sessionId);
        this.#assertSessionBinding(session, initialBinding);
        if (session.state === 'aborted') transferError('TRANSFER_SESSION_STATE', 'upload session is aborted');
        if (session.finalized) return this.#assertFinalizedCurrent(session.sessionId, initialBinding);
        const partCount = Math.ceil(session.declaredLength / session.partSize);
        if (session.parts.length !== partCount || session.parts.some((part, index) => part.index !== index)) {
          transferError('TRANSFER_SESSION_STATE', 'not all verified parts are present');
        }
        const directoryPath = join(this.partsRoot, session.sessionId);
        const directoryPin = partCount === 0 ? null : await pinPlainDirectory(directoryPath, {
          create: false,
          parentPin: this.#partsPin,
        });
        const source = async function* () {
          for (const part of session.parts) {
            await assertPinnedDirectory(directoryPin);
            const handle = await open(join(directoryPath, `${part.index}.part`), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
            try {
              const stat = await handle.stat();
              const partBytes = await readExact(handle, part.length, 0);
              if (!stat.isFile() || stat.size !== part.length || sha256(partBytes) !== part.sha256) {
                transferError('TRANSFER_BACKEND_CORRUPT', 'multipart source is corrupt');
              }
              yield partBytes;
            } finally { await handle.close(); }
          }
        };
        let deletedGeneration = null;
        let reuploadPermit = null;
        let lifecycle = await this.lifecycle.get(session.opaqueKey);
        if (lifecycle?.state === 'deleted') {
          if (lifecycle.objectId !== session.objectId || lifecycle.length !== session.declaredLength
              || lifecycle.tenantScopeSha256 !== session.tenantScopeSha256) {
            transferError('TRANSFER_LIFECYCLE_STALE', 'deleted lifecycle no longer matches the upload session');
          }
          deletedGeneration = lifecycle.generation;
          reuploadPermit = await this.lifecycle.issueReuploadPermit({
            opaqueKey: session.opaqueKey,
            expectedGeneration: lifecycle.generation,
            nextAuthorityBindingSha256: initialBinding.authorityBindingSha256,
          });
        }
        const backend = await this.backend.createIfAbsent({
          opaqueKey: session.opaqueKey,
          objectId: session.objectId,
          length: session.declaredLength,
          source: source(),
          reuploadPermit,
        });
        const verified = await this.backend.verify(session.opaqueKey);
        if (verified.receiptSha256 !== backend.receiptSha256) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'backend durability receipt changed during finalize');
        }
        this.#assertBindingFresh(initialBinding);
        lifecycle = deletedGeneration === null
          ? await this.lifecycle.get(session.opaqueKey)
          : await this.lifecycle.recordReverifiedDeleted({
            opaqueKey: session.opaqueKey,
            expectedGeneration: deletedGeneration,
            nextAuthorityBindingSha256: initialBinding.authorityBindingSha256,
            reopenReceipt: backend.reopenReceipt,
          });
        if (lifecycle?.state === 'staged') {
          if (ObjectRef.parse(session.objectId).kindName === 'content-manifest') {
            // Content manifests may be made durable here, but availability is
            // owned by the receipt-gated lifecycle transaction participant.
            // Leaving the record staged lets that same-transaction boundary
            // perform the only admissible kind-2 availability CAS.
            transferError(
              'TRANSFER_AUTHORIZATION_DENIED',
              'content-manifest availability requires the production receipt boundary',
            );
          }
          lifecycle = await this.lifecycle.compareAndSwap({
            opaqueKey: session.opaqueKey,
            expectedGeneration: lifecycle.generation,
            expectedState: 'staged',
            nextState: 'available',
            backendReceipt: verified,
            authorityBindingSha256: initialBinding.authorityBindingSha256,
          });
        } else if (lifecycle?.state !== 'available' || lifecycle.backendReceiptSha256 !== verified.receiptSha256
            || lifecycle.authorityBindingSha256 !== initialBinding.authorityBindingSha256
            || lifecycle.tenantScopeSha256 !== session.tenantScopeSha256
            || lifecycle.objectId !== session.objectId || lifecycle.length !== session.declaredLength) {
          transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle is not eligible for finalize');
        }
        await this.#fault('after-lifecycle-cas');
        const current = await this.lifecycle.get(session.opaqueKey);
        if (current?.state !== 'available' || current.generation !== lifecycle.generation
            || current.backendReceiptSha256 !== lifecycle.backendReceiptSha256
            || current.authorityBindingSha256 !== lifecycle.authorityBindingSha256
            || current.tenantScopeSha256 !== lifecycle.tenantScopeSha256
            || current.objectId !== lifecycle.objectId || current.length !== lifecycle.length) {
          transferError('TRANSFER_LIFECYCLE_STALE', 'available lifecycle changed before response');
        }
        const receipt = this.lifecycle.receipt(current, initialBinding.grantBindingSha256);
        const now = this.now();
        const updated = validateSessionRecord({
          ...session,
          state: 'finalized',
          lastGrantBindingSha256: initialBinding.grantBindingSha256,
          finalized: receipt,
          cleanupAfterUnixMs: Math.max(session.cleanupAfterUnixMs, now + this.safetyWindowMilliseconds),
          updatedAtUnixMs: now,
        });
        this.#assertBindingFresh(initialBinding);
        await atomicJsonWrite(this.#sessionPath(session.sessionId), updated, {
          directoryPin: this.#sessionsPin,
          lockGuard,
        });
        const finalCurrent = await this.lifecycle.get(session.opaqueKey);
        if (finalCurrent?.state !== 'available' || finalCurrent.generation !== receipt.generation
            || finalCurrent.backendReceiptSha256 !== receipt.backendReceiptSha256
            || finalCurrent.authorityBindingSha256 !== receipt.authorityBindingSha256
            || finalCurrent.tenantScopeSha256 !== receipt.tenantScopeSha256
            || finalCurrent.objectId !== receipt.objectId || finalCurrent.length !== receipt.length) {
          transferError('TRANSFER_LIFECYCLE_STALE', 'available lifecycle changed while finalization was recorded');
        }
        return receipt;
      })
    ), async () => {
      await this.#assertFinalizedCurrent(original.sessionId, initialBinding);
      return { result: 'allow', code: 'ALLOW_EXPLICIT' };
    });
    return result.outcome;
  }

  async abortUpload({ sessionId, grant, context }) {
    const initial = await this.#session(sessionId);
    const binding = await this.#authorizeSession(initial, grant, context);
    this.#checkRate(binding);
    return this.#withSessionLock(initial.sessionId, async (lockGuard) => {
      const session = await this.#session(initial.sessionId);
      this.#assertSessionBinding(session, binding);
      if (session.state === 'finalized') transferError('TRANSFER_SESSION_STATE', 'finalized session cannot be aborted');
      if (session.state === 'aborted') return this.#status(session);
      const now = this.now();
      const updated = validateSessionRecord({
        ...session,
        state: 'aborted',
        cleanupAfterUnixMs: Math.max(session.cleanupAfterUnixMs, now + this.safetyWindowMilliseconds),
        updatedAtUnixMs: now,
      });
      this.#assertBindingFresh(binding);
      await atomicJsonWrite(this.#sessionPath(session.sessionId), updated, {
        directoryPin: this.#sessionsPin,
        lockGuard,
      });
      return this.#status(updated);
    });
  }

  async readRange({ objectId: objectIdInput, start, endExclusive, grant, context }) {
    const objectId = objectIdValue(objectIdInput);
    integer(start, 0, TRANSFER_LIMITS.objectMaximum, 'range start');
    integer(endExclusive, start + 1, TRANSFER_LIMITS.objectMaximum, 'range end');
    const binding = await this.#authorize({ grant, context, objectId, requestObjectIds: [objectId], operation: 'download' });
    this.#checkRate(binding, { bytes: endExclusive - start });
    const lifecycle = await this.lifecycle.get(binding.opaqueKey);
    if (lifecycle?.state !== 'available' || lifecycle.tenantScopeSha256 !== binding.tenantScopeSha256
        || lifecycle.objectId !== objectId) {
      transferError('TRANSFER_AUTHORIZATION_DENIED', 'transfer authorization was denied');
    }
    const range = await this.backend.readVerifiedRange(binding.opaqueKey, start, endExclusive);
    if (range.receiptSha256 !== lifecycle.backendReceiptSha256 || range.objectId !== objectId
        || range.totalLength !== lifecycle.length) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'available lifecycle and backend receipt differ');
    }
    const current = await this.lifecycle.get(binding.opaqueKey);
    if (current?.state !== 'available' || current.generation !== lifecycle.generation
        || current.backendReceiptSha256 !== lifecycle.backendReceiptSha256
        || current.authorityBindingSha256 !== lifecycle.authorityBindingSha256
        || current.tenantScopeSha256 !== binding.tenantScopeSha256
        || current.objectId !== lifecycle.objectId || current.length !== lifecycle.length) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'available lifecycle changed during range verification');
    }
    this.#assertBindingFresh(binding);
    const receipt = this.lifecycle.receipt(current, binding.grantBindingSha256);
    const { receiptSha256: _backendReceiptSha256, objectId: _backendObjectId, opaqueKey: _backendKey,
      length: _backendLength, durable: _durable, schemaVersion: _backendSchema, ...publicRange } = range;
    return Object.freeze({ ...publicRange, lifecycleReceipt: receipt });
  }
}
