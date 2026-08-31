import { createHash } from 'node:crypto';
import { lstat, opendir, unlink } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { ObjectRef } from '@opengamevcs/object-model';
import { canonicalBytes } from '@opengamevcs/protocol-baseline';
import {
  assertDeletePermitConsumed,
  issueDeletePermit,
  issueReuploadPermit,
} from './delete-permit.mjs';
import {
  assertPinnedDirectory,
  atomicJsonWrite,
  pinPlainDirectory,
  readJson,
  syncDirectory,
  withRecoverableDirectoryLock,
} from './fs-util.mjs';
import { mapIo, transferError } from './errors.mjs';

const KEY = /^[0-9a-f]{64}$/u;
const RECORD_QUOTA_LOCK = createHash('sha256')
  .update('OGVCS-TRANSFER-LIFECYCLE-QUOTA-LOCK-V1')
  .digest('hex');
const TRANSITIONS = new Set([
  'staged->available',
  'available->quarantined',
  'quarantined->available',
  'quarantined->deleting',
  'deleting->deleted',
]);
const RECORD_KEYS = [
  'authorityBindingSha256',
  'backendReceiptSha256',
  'deletionReceiptSha256',
  'generation',
  'length',
  'objectId',
  'opaqueKey',
  'retentionUntilUnixMs',
  'schemaVersion',
  'state',
  'tenantScopeSha256',
  'updatedAtUnixMs',
].sort().join('\0');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function keyValue(value) {
  if (typeof value !== 'string' || !KEY.test(value)) transferError('TRANSFER_INPUT_INVALID', 'lifecycle key is invalid');
  return value;
}

function generationValue(value) {
  if (!Number.isSafeInteger(value) || value < 1) transferError('TRANSFER_INPUT_INVALID', 'lifecycle generation is invalid');
  return value;
}

function shaValue(value, label) {
  if (typeof value !== 'string' || !KEY.test(value)) transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  return value;
}

function canonicalObjectId(value) {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value) throw new TypeError('ObjectID is not canonical');
    return value;
  } catch (error) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle ObjectID is invalid', { cause: error });
  }
}

function validateLifecycleRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== RECORD_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/lifecycle-record/v1'
      || !KEY.test(value.opaqueKey ?? '') || !KEY.test(value.authorityBindingSha256 ?? '')
      || !KEY.test(value.tenantScopeSha256 ?? '')
      || !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 67_108_864
      || !Number.isSafeInteger(value.generation) || value.generation < 1
      || !['staged', 'available', 'quarantined', 'deleting', 'deleted'].includes(value.state)
      || !Number.isSafeInteger(value.retentionUntilUnixMs) || value.retentionUntilUnixMs < 0
      || !Number.isSafeInteger(value.updatedAtUnixMs) || value.updatedAtUnixMs < 0
      || (value.state === 'staged' ? value.backendReceiptSha256 !== null : !KEY.test(value.backendReceiptSha256 ?? ''))
      || (value.state === 'deleted'
        ? !KEY.test(value.deletionReceiptSha256 ?? '')
        : value.deletionReceiptSha256 !== null)) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle record is invalid');
  }
  canonicalObjectId(value.objectId);
  return Object.freeze(value);
}

function validateBackendReceipt(receipt, current) {
  if (!receipt || receipt.durable !== true || receipt.opaqueKey !== current.opaqueKey
      || receipt.objectId !== current.objectId || receipt.length !== current.length
      || !KEY.test(receipt.payloadSha256 ?? '') || !KEY.test(receipt.receiptSha256 ?? '')) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'available transition lacks an exact durable receipt');
  }
  const base = {
    schemaVersion: receipt.schemaVersion,
    opaqueKey: receipt.opaqueKey,
    objectId: receipt.objectId,
    length: receipt.length,
    payloadSha256: receipt.payloadSha256,
    durable: receipt.durable,
  };
  if (receipt.schemaVersion !== 'ogvcs.object-transfer/backend-receipt/v1'
      || sha256(canonicalBytes(base)) !== receipt.receiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend receipt digest is invalid');
  }
  return receipt.receiptSha256;
}

function validateDeletionReceipt(deletionReceipt, current) {
  const base = deletionReceipt && {
    schemaVersion: deletionReceipt.schemaVersion,
    opaqueKey: deletionReceipt.opaqueKey,
    priorReceiptSha256: deletionReceipt.priorReceiptSha256,
    expectedGeneration: deletionReceipt.expectedGeneration,
    authorityBindingSha256: deletionReceipt.authorityBindingSha256,
    deleted: deletionReceipt.deleted,
  };
  if (!deletionReceipt || deletionReceipt.schemaVersion !== 'ogvcs.object-transfer/backend-delete-receipt/v1'
      || deletionReceipt.deleted !== true || deletionReceipt.opaqueKey !== current.opaqueKey
      || deletionReceipt.priorReceiptSha256 !== current.backendReceiptSha256
      || deletionReceipt.expectedGeneration !== current.generation
      || deletionReceipt.authorityBindingSha256 !== current.authorityBindingSha256
      || !KEY.test(deletionReceipt.receiptSha256 ?? '')
      || sha256(canonicalBytes(base)) !== deletionReceipt.receiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'deleted transition lacks a generation-bound deletion receipt');
  }
  return deletionReceipt.receiptSha256;
}

function validateReopenReceipt(reopenReceipt, current, nextAuthorityBindingSha256) {
  const base = reopenReceipt && {
    schemaVersion: reopenReceipt.schemaVersion,
    opaqueKey: reopenReceipt.opaqueKey,
    objectId: reopenReceipt.objectId,
    length: reopenReceipt.length,
    expectedDeletedGeneration: reopenReceipt.expectedDeletedGeneration,
    stagedGeneration: reopenReceipt.stagedGeneration,
    deletionReceiptSha256: reopenReceipt.deletionReceiptSha256,
    authorityBindingSha256: reopenReceipt.authorityBindingSha256,
    reopened: reopenReceipt.reopened,
  };
  if (!reopenReceipt || reopenReceipt.schemaVersion !== 'ogvcs.object-transfer/backend-reopen-receipt/v1'
      || reopenReceipt.reopened !== true || reopenReceipt.opaqueKey !== current.opaqueKey
      || reopenReceipt.objectId !== current.objectId || reopenReceipt.length !== current.length
      || reopenReceipt.expectedDeletedGeneration !== current.generation
      || reopenReceipt.stagedGeneration !== current.generation + 1
      || reopenReceipt.deletionReceiptSha256 !== current.deletionReceiptSha256
      || reopenReceipt.authorityBindingSha256 !== nextAuthorityBindingSha256
      || !KEY.test(reopenReceipt.receiptSha256 ?? '')
      || sha256(canonicalBytes(base)) !== reopenReceipt.receiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'deleted-generation reopen receipt is invalid');
  }
  return reopenReceipt.receiptSha256;
}

export class LifecycleStore {
  #deleteObject;
  #rootPin;
  #recordsPin;
  #locksPin;

  constructor({
    root,
    safetyWindowMilliseconds = 3_600_000,
    now = () => Date.now(),
    lockAttempts = 200,
    lockLeaseMilliseconds = 300_000,
    recordsMaximum = 4096,
    deleteObject = null,
  } = {}) {
    if (typeof root !== 'string' || !isAbsolute(root) || root.includes('\0')) {
      transferError('TRANSFER_INPUT_INVALID', 'lifecycle root must be absolute');
    }
    if (!Number.isSafeInteger(safetyWindowMilliseconds) || safetyWindowMilliseconds < 3_600_000
        || typeof now !== 'function' || !Number.isSafeInteger(lockAttempts) || lockAttempts < 1
        || lockAttempts > 10_000 || !Number.isSafeInteger(lockLeaseMilliseconds)
        || lockLeaseMilliseconds < 1_000 || lockLeaseMilliseconds > 86_400_000
        || !Number.isSafeInteger(recordsMaximum)
        || recordsMaximum < 1 || recordsMaximum > 4096
        || !(deleteObject === null || typeof deleteObject === 'function')) {
      transferError('TRANSFER_INPUT_INVALID', 'lifecycle configuration is invalid');
    }
    this.root = resolve(root);
    this.recordsRoot = join(this.root, 'records');
    this.locksRoot = join(this.root, 'locks');
    this.safetyWindowMilliseconds = safetyWindowMilliseconds;
    this.now = now;
    this.lockAttempts = lockAttempts;
    this.lockLeaseMilliseconds = lockLeaseMilliseconds;
    this.recordsMaximum = recordsMaximum;
    this.#deleteObject = deleteObject;
  }

  async initialize({ parentPin = null } = {}) {
    this.#rootPin = await pinPlainDirectory(this.root, { parentPin });
    this.#recordsPin = await pinPlainDirectory(this.recordsRoot, { parentPin: this.#rootPin });
    this.#locksPin = await pinPlainDirectory(this.locksRoot, { parentPin: this.#rootPin });
    return this;
  }

  #path(key) { return join(this.recordsRoot, `${keyValue(key)}.json`); }

  async #assertRoots() {
    if (!this.#rootPin) transferError('TRANSFER_BACKEND_IO', 'lifecycle store is not initialized');
    await assertPinnedDirectory(this.#rootPin);
    await assertPinnedDirectory(this.#recordsPin);
    await assertPinnedDirectory(this.#locksPin);
  }

  async #withLock(key, operation) {
    await this.#assertRoots();
    return withRecoverableDirectoryLock({
      rootPin: this.#locksPin,
      name: keyValue(key),
      now: this.now,
      attempts: this.lockAttempts,
      leaseMilliseconds: this.lockLeaseMilliseconds,
      busyCode: 'TRANSFER_LIFECYCLE_STALE',
      busyMessage: 'lifecycle record is busy',
      operation,
    });
  }

  async get(opaqueKey) {
    await this.#assertRoots();
    const record = await readJson(this.#path(opaqueKey), 1024 * 1024, { directoryPin: this.#recordsPin });
    return record === null ? null : validateLifecycleRecord(record);
  }

  async createStaged({ opaqueKey, objectId, length, authorityBindingSha256, tenantScopeSha256 }) {
    const key = keyValue(opaqueKey);
    canonicalObjectId(objectId);
    if (!Number.isSafeInteger(length) || length < 0 || length > 67_108_864) {
      transferError('TRANSFER_INPUT_INVALID', 'staged lifecycle length is invalid');
    }
    shaValue(authorityBindingSha256, 'lifecycle authority binding');
    shaValue(tenantScopeSha256, 'lifecycle tenant scope');
    return this.#withLock(RECORD_QUOTA_LOCK, () => this.#withLock(key, async (lockGuard) => {
      const existing = await this.get(key);
      if (existing) {
        const authorityMatches = existing.state === 'deleted'
          ? true
          : existing.authorityBindingSha256 === authorityBindingSha256;
        if (existing.objectId !== objectId || existing.length !== length
            || !authorityMatches
            || existing.tenantScopeSha256 !== tenantScopeSha256
            || existing.state === 'deleting') {
          transferError('TRANSFER_BACKEND_CONFLICT', 'opaque key lifecycle binding differs');
        }
        return existing;
      }
      if ((await this.listBounded(this.recordsMaximum)).length >= this.recordsMaximum) {
        transferError('TRANSFER_LIMIT_EXCEEDED', 'lifecycle record ceiling exceeded');
      }
      const now = this.now();
      const record = validateLifecycleRecord({
        schemaVersion: 'ogvcs.object-transfer/lifecycle-record/v1',
        opaqueKey: key,
        objectId,
        length,
        state: 'staged',
        generation: 1,
        authorityBindingSha256,
        tenantScopeSha256,
        backendReceiptSha256: null,
        deletionReceiptSha256: null,
        retentionUntilUnixMs: now + this.safetyWindowMilliseconds,
        updatedAtUnixMs: now,
      });
      await atomicJsonWrite(this.#path(key), record, { directoryPin: this.#recordsPin, lockGuard });
      return record;
    }));
  }

  async compareAndSwap({
    opaqueKey,
    expectedGeneration,
    expectedState,
    nextState,
    backendReceipt,
    deletionReceipt,
    authorityBindingSha256,
  }) {
    const key = keyValue(opaqueKey);
    generationValue(expectedGeneration);
    shaValue(authorityBindingSha256, 'lifecycle authority binding');
    if (!TRANSITIONS.has(`${expectedState}->${nextState}`)) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle transition is not allowed');
    }
    if (nextState === 'deleted') {
      transferError('TRANSFER_LIFECYCLE_STALE', 'deleted transition requires an authoritative deleting-generation permit');
    }
    return this.#withLock(key, async (lockGuard) => {
      const current = await this.get(key);
      if (!current || current.generation !== expectedGeneration || current.state !== expectedState) {
        transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle generation or state is stale');
      }
      if (authorityBindingSha256 !== current.authorityBindingSha256) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'lifecycle authority binding differs');
      }
      // Kind-2 availability is intentionally not a generic lifecycle-store
      // operation.  It must go through the branded OGVCS-008 participant,
      // which consumes the OGVCS-007 production receipt in the same metadata
      // transaction before applying the CAS.
      if (nextState === 'available' && ObjectRef.parse(current.objectId).kindName === 'content-manifest') {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'content-manifest availability requires the production receipt boundary');
      }
      const now = this.now();
      if (nextState === 'deleting' && now < current.retentionUntilUnixMs) {
        transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle retention window is still active');
      }
      let backendReceiptSha256 = current.backendReceiptSha256;
      if (nextState === 'available') backendReceiptSha256 = validateBackendReceipt(backendReceipt, current);
      const retentionUntilUnixMs = ['available', 'quarantined'].includes(nextState)
        ? Math.max(current.retentionUntilUnixMs, now + this.safetyWindowMilliseconds)
        : current.retentionUntilUnixMs;
      const updated = validateLifecycleRecord({
        ...current,
        state: nextState,
        generation: current.generation + 1,
        backendReceiptSha256,
        retentionUntilUnixMs,
        updatedAtUnixMs: now,
      });
      await atomicJsonWrite(this.#path(key), updated, { directoryPin: this.#recordsPin, lockGuard });
      return updated;
    });
  }

  async deleteAuthorized({
    opaqueKey,
    expectedGeneration,
    authorityBindingSha256,
  }) {
    const key = keyValue(opaqueKey);
    generationValue(expectedGeneration);
    shaValue(authorityBindingSha256, 'lifecycle authority binding');
    if (this.#deleteObject === null) {
      transferError('TRANSFER_INPUT_INVALID', 'authoritative backend delete operation is required');
    }
    return this.#withLock(key, async (lockGuard) => {
      const current = await this.get(key);
      if (!current || current.state !== 'deleting' || current.generation !== expectedGeneration) {
        transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle deleting generation is stale');
      }
      if (current.authorityBindingSha256 !== authorityBindingSha256) {
        transferError('TRANSFER_AUTHORIZATION_DENIED', 'lifecycle authority binding differs');
      }
      const permit = issueDeletePermit({
        opaqueKey: key,
        objectId: current.objectId,
        length: current.length,
        priorReceiptSha256: current.backendReceiptSha256,
        expectedGeneration: current.generation,
        authorityBindingSha256: current.authorityBindingSha256,
      });
      const deletionReceipt = await this.#deleteObject(permit);
      assertDeletePermitConsumed(permit);
      const deletionReceiptSha256 = validateDeletionReceipt(deletionReceipt, current);
      await lockGuard.assertOwned();
      const updated = validateLifecycleRecord({
        ...current,
        state: 'deleted',
        generation: current.generation + 1,
        deletionReceiptSha256,
        updatedAtUnixMs: this.now(),
      });
      await atomicJsonWrite(this.#path(key), updated, { directoryPin: this.#recordsPin, lockGuard });
      return updated;
    });
  }

  async issueReuploadPermit({
    opaqueKey,
    expectedGeneration,
    nextAuthorityBindingSha256,
  }) {
    const key = keyValue(opaqueKey);
    generationValue(expectedGeneration);
    shaValue(nextAuthorityBindingSha256, 'next lifecycle authority binding');
    return this.#withLock(key, async () => {
      const current = await this.get(key);
      if (!current || current.state !== 'deleted' || current.generation !== expectedGeneration) {
        transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle deleted generation is stale');
      }
      return issueReuploadPermit({
        opaqueKey: key,
        objectId: current.objectId,
        length: current.length,
        expectedDeletedGeneration: current.generation,
        deletionReceiptSha256: current.deletionReceiptSha256,
        priorAuthorityBindingSha256: current.authorityBindingSha256,
        nextAuthorityBindingSha256,
      });
    });
  }

  async recordReverifiedDeleted({
    opaqueKey,
    expectedGeneration,
    nextAuthorityBindingSha256,
    reopenReceipt,
  }) {
    const key = keyValue(opaqueKey);
    generationValue(expectedGeneration);
    shaValue(nextAuthorityBindingSha256, 'next lifecycle authority binding');
    return this.#withLock(key, async (lockGuard) => {
      const current = await this.get(key);
      if (!current || current.state !== 'deleted' || current.generation !== expectedGeneration) {
        transferError('TRANSFER_LIFECYCLE_STALE', 'lifecycle deleted generation is stale');
      }
      validateReopenReceipt(reopenReceipt, current, nextAuthorityBindingSha256);
      const now = this.now();
      const updated = validateLifecycleRecord({
        ...current,
        state: 'staged',
        generation: current.generation + 1,
        authorityBindingSha256: nextAuthorityBindingSha256,
        backendReceiptSha256: null,
        deletionReceiptSha256: null,
        retentionUntilUnixMs: Math.max(current.retentionUntilUnixMs, now + this.safetyWindowMilliseconds),
        updatedAtUnixMs: now,
      });
      await atomicJsonWrite(this.#path(key), updated, { directoryPin: this.#recordsPin, lockGuard });
      return updated;
    });
  }

  receipt(recordInput, grantBindingSha256) {
    const record = validateLifecycleRecord(recordInput);
    if (record.state !== 'available' || !KEY.test(grantBindingSha256 ?? '')) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'object is not currently available or lacks a grant binding');
    }
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

  async listBounded(maximum = 4096) {
    if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > 4096) {
      transferError('TRANSFER_INPUT_INVALID', 'lifecycle list bound is invalid');
    }
    await this.#assertRoots();
    const records = [];
    let scanned = 0;
    let changed = false;
    const directory = await opendir(this.recordsRoot);
    try {
      for await (const entry of directory) {
        scanned += 1;
        if (scanned > 4096) transferError('TRANSFER_LIMIT_EXCEEDED', 'lifecycle directory exceeds its scan bound');
        if (/^\.[0-9a-f]{64}\.json\.[0-9a-f]{24}\.tmp$/u.test(entry.name)) {
          if (!entry.isFile()) transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle state temporary is not a file');
          const path = join(this.recordsRoot, entry.name);
          let stat;
          try { stat = await lstat(path); } catch (error) {
            if (error?.code === 'ENOENT') continue;
            mapIo(error, 'lifecycle state temporary inspection failed');
          }
          if (!stat.isFile() || stat.isSymbolicLink()) {
            transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle state temporary is not plain');
          }
          if (stat.mtimeMs + 86_400_000 <= Date.now()) {
            await unlink(path);
            changed = true;
          }
          continue;
        }
        if (!entry.isFile() || !/^([0-9a-f]{64})\.json$/u.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'lifecycle record directory contains an unexpected entry');
        }
        if (records.length >= maximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'lifecycle list exceeds its bound');
        records.push(await this.get(entry.name.slice(0, 64)));
      }
    } finally { await directory.close().catch(() => {}); }
    if (changed) await syncDirectory(this.recordsRoot, this.#recordsPin);
    return Object.freeze(records);
  }
}
