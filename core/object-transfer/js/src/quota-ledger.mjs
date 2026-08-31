import { isAbsolute, join, resolve } from 'node:path';
import { opendir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { transferError } from './errors.mjs';
import {
  atomicJsonCreate,
  atomicJsonWrite,
  pinPlainDirectory,
  readJson,
  withRecoverableDirectoryLock,
} from './fs-util.mjs';

const SHA = /^[0-9a-f]{64}$/u;
const RECORD_BYTES_MAXIMUM = 16 * 1024;
const RECORDS_MAXIMUM = 4096;
const GLOBAL_RECORD_LOCK = createHash('sha256')
  .update('OGVCS-TRANSFER-DURABLE-QUOTA-RECORD-LOCK-V1')
  .digest('hex');

function sha(value, label) {
  if (typeof value !== 'string' || !SHA.test(value)) transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  return value;
}

function length(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 67_108_864) {
    transferError('TRANSFER_INPUT_INVALID', 'durable quota length is invalid');
  }
  return value;
}

function validateRecord(value, persisted = false) {
  const fail = (message) => transferError(persisted ? 'TRANSFER_BACKEND_CORRUPT' : 'TRANSFER_INPUT_INVALID', message);
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== 'backendReceiptSha256\0length\0opaqueKey\0schemaVersion\0state\0tenantScopeSha256\0updatedAtUnixMs'
      || value.schemaVersion !== 'ogvcs.object-transfer/durable-quota-entry/v1'
      || !SHA.test(value.tenantScopeSha256 ?? '') || !SHA.test(value.opaqueKey ?? '')
      || !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 67_108_864
      || !['reserved', 'durable', 'released'].includes(value.state)
      || !Number.isSafeInteger(value.updatedAtUnixMs) || value.updatedAtUnixMs < 0
      || (value.state === 'reserved' && value.backendReceiptSha256 !== null)
      || (value.state === 'durable' && !SHA.test(value.backendReceiptSha256 ?? ''))
      || (value.state === 'released' && !(value.backendReceiptSha256 === null || SHA.test(value.backendReceiptSha256 ?? '')))) {
    fail('durable quota record is invalid');
  }
  return Object.freeze(value);
}

export class DurableQuotaLedger {
  #rootPin;
  #recordsPin;
  #locksPin;

  constructor({
    root,
    maximumBytes,
    maximumRecords = RECORDS_MAXIMUM,
    now = () => Date.now(),
    lockLeaseMilliseconds = 300_000,
    fault = async () => {},
  } = {}) {
    if (typeof root !== 'string' || !isAbsolute(root) || root.includes('\0') || typeof now !== 'function'
        || typeof fault !== 'function' || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1
        || maximumBytes > 1_099_511_627_776 || !Number.isSafeInteger(maximumRecords)
        || maximumRecords < 1 || maximumRecords > RECORDS_MAXIMUM) {
      transferError('TRANSFER_INPUT_INVALID', 'durable quota ledger configuration is invalid');
    }
    this.root = resolve(root);
    this.recordsRoot = join(this.root, 'records');
    this.locksRoot = join(this.root, 'locks');
    this.maximumBytes = maximumBytes;
    this.maximumRecords = maximumRecords;
    this.now = now;
    this.lockLeaseMilliseconds = lockLeaseMilliseconds;
    this.fault = fault;
  }

  async initialize() {
    this.#rootPin = await pinPlainDirectory(this.root);
    this.#recordsPin = await pinPlainDirectory(this.recordsRoot, { parentPin: this.#rootPin });
    this.#locksPin = await pinPlainDirectory(this.locksRoot, { parentPin: this.#rootPin });
    return this;
  }

  #path(key) { return join(this.recordsRoot, `${sha(key, 'opaque key')}.json`); }

  async #withTenant(scope, operation) {
    return withRecoverableDirectoryLock({
      rootPin: this.#locksPin,
      name: sha(scope, 'tenant scope'),
      now: this.now,
      leaseMilliseconds: this.lockLeaseMilliseconds,
      busyCode: 'TRANSFER_LIMIT_EXCEEDED',
      busyMessage: 'durable quota is busy',
      operation,
    });
  }

  async #withGlobal(operation) {
    return withRecoverableDirectoryLock({
      rootPin: this.#locksPin,
      name: GLOBAL_RECORD_LOCK,
      now: this.now,
      leaseMilliseconds: this.lockLeaseMilliseconds,
      busyCode: 'TRANSFER_LIMIT_EXCEEDED',
      busyMessage: 'durable quota record catalog is busy',
      operation,
    });
  }

  async #record(key) {
    const value = await readJson(this.#path(key), RECORD_BYTES_MAXIMUM, { directoryPin: this.#recordsPin });
    return value === null ? null : validateRecord(value, true);
  }

  async #usageUnlocked(scope) {
    let records = 0;
    let reservedBytes = 0;
    let durableBytes = 0;
    const directory = await opendir(this.recordsRoot);
    try {
      for await (const entry of directory) {
        records += 1;
        if (records > this.maximumRecords) transferError('TRANSFER_LIMIT_EXCEEDED', 'durable quota record bound exceeded');
        if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'durable quota directory contains an invalid entry');
        }
        const record = await this.#record(entry.name.slice(0, 64));
        if (record.tenantScopeSha256 !== scope) continue;
        if (record.state === 'reserved') reservedBytes += record.length;
        if (record.state === 'durable') durableBytes += record.length;
        if (!Number.isSafeInteger(reservedBytes) || !Number.isSafeInteger(durableBytes)) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'durable quota usage overflowed');
        }
      }
    } finally { await directory.close().catch(() => {}); }
    return Object.freeze({ reservedBytes, durableBytes, totalBytes: reservedBytes + durableBytes, records });
  }

  async usage(tenantScopeSha256) {
    const scope = sha(tenantScopeSha256, 'tenant scope');
    return this.#withTenant(scope, () => this.#usageUnlocked(scope));
  }

  async reserve({ tenantScopeSha256, opaqueKey, length: bytes } = {}) {
    const scope = sha(tenantScopeSha256, 'tenant scope');
    const key = sha(opaqueKey, 'opaque key');
    const exactLength = length(bytes);
    return this.#withGlobal(() => this.#withTenant(scope, async (lockGuard) => {
      const existing = await this.#record(key);
      if (existing) {
        if (existing.tenantScopeSha256 !== scope || existing.length !== exactLength) {
          transferError('TRANSFER_PART_CONFLICT', 'durable quota reservation differs');
        }
        if (existing.state === 'released') {
          const usage = await this.#usageUnlocked(scope);
          if (usage.totalBytes > this.maximumBytes - exactLength) {
            transferError('TRANSFER_LIMIT_EXCEEDED', 'durable unique-byte quota exceeded');
          }
          const reopened = validateRecord({
            ...existing,
            state: 'reserved',
            backendReceiptSha256: null,
            updatedAtUnixMs: this.now(),
          });
          await atomicJsonWrite(this.#path(key), reopened, { directoryPin: this.#recordsPin, lockGuard });
          await this.fault('after-durable-quota-reserve');
          return Object.freeze({ ...reopened, replay: false });
        }
        return Object.freeze({ ...existing, replay: true });
      }
      const usage = await this.#usageUnlocked(scope);
      if (usage.totalBytes > this.maximumBytes - exactLength) {
        transferError('TRANSFER_LIMIT_EXCEEDED', 'durable unique-byte quota exceeded');
      }
      if (usage.records >= this.maximumRecords) {
        transferError('TRANSFER_LIMIT_EXCEEDED', 'durable quota record bound exceeded');
      }
      const record = validateRecord({
        schemaVersion: 'ogvcs.object-transfer/durable-quota-entry/v1',
        tenantScopeSha256: scope,
        opaqueKey: key,
        length: exactLength,
        state: 'reserved',
        backendReceiptSha256: null,
        updatedAtUnixMs: this.now(),
      });
      const created = await atomicJsonCreate(this.#path(key), record, { directoryPin: this.#recordsPin, lockGuard });
      if (!created) transferError('TRANSFER_PART_CONFLICT', 'durable quota reservation raced');
      await this.fault('after-durable-quota-reserve');
      return Object.freeze({ ...record, replay: false });
    }));
  }

  async commit({ tenantScopeSha256, opaqueKey, length: bytes, backendReceiptSha256 } = {}) {
    const scope = sha(tenantScopeSha256, 'tenant scope');
    const key = sha(opaqueKey, 'opaque key');
    const exactLength = length(bytes);
    const receipt = sha(backendReceiptSha256, 'backend receipt');
    return this.#withTenant(scope, async (lockGuard) => {
      const existing = await this.#record(key);
      if (!existing || existing.tenantScopeSha256 !== scope || existing.length !== exactLength
          || existing.state === 'released') {
        transferError('TRANSFER_PART_CONFLICT', 'durable quota reservation is absent or differs');
      }
      if (existing.state === 'durable') {
        if (existing.backendReceiptSha256 !== receipt) transferError('TRANSFER_PART_CONFLICT', 'durable quota receipt replay differs');
        return Object.freeze({ ...existing, replay: true });
      }
      const record = validateRecord({ ...existing, state: 'durable', backendReceiptSha256: receipt, updatedAtUnixMs: this.now() });
      await atomicJsonWrite(this.#path(key), record, { directoryPin: this.#recordsPin, lockGuard });
      await this.fault('after-durable-quota-commit');
      return Object.freeze({ ...record, replay: false });
    });
  }

  // This seam is for the lifecycle/GC participant. Transfer finalization never
  // calls it and cannot infer release from backend absence.
  async release({ tenantScopeSha256, opaqueKey, backendReceiptSha256 } = {}) {
    const scope = sha(tenantScopeSha256, 'tenant scope');
    const key = sha(opaqueKey, 'opaque key');
    const receipt = sha(backendReceiptSha256, 'backend receipt');
    return this.#withTenant(scope, async (lockGuard) => {
      const existing = await this.#record(key);
      if (!existing || existing.tenantScopeSha256 !== scope || existing.state === 'reserved'
          || existing.backendReceiptSha256 !== receipt) {
        transferError('TRANSFER_PART_CONFLICT', 'durable quota release differs');
      }
      if (existing.state === 'released') return Object.freeze({ ...existing, replay: true });
      const record = validateRecord({ ...existing, state: 'released', updatedAtUnixMs: this.now() });
      await atomicJsonWrite(this.#path(key), record, { directoryPin: this.#recordsPin, lockGuard });
      return Object.freeze({ ...record, replay: false });
    });
  }
}
