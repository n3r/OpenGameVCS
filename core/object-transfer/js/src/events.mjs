import { createHash } from 'node:crypto';
import { isAbsolute, join, resolve } from 'node:path';
import { opendir } from 'node:fs/promises';
import { canonicalBytes } from '@opengamevcs/protocol-baseline';
import { transferError } from './errors.mjs';
import {
  atomicJsonCreate,
  pinPlainDirectory,
  readJson,
  withRecoverableDirectoryLock,
} from './fs-util.mjs';

const SHA = /^[0-9a-f]{64}$/u;
const EVENTS_MAXIMUM = 4096;
const EVENT_BYTES_MAXIMUM = 64 * 1024;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const EVENT_QUOTA_LOCK = sha256('OGVCS-TRANSFER-INTERNAL-EVENT-QUOTA-LOCK-V1');

function eventId(body) {
  return sha256(Buffer.concat([Buffer.from('OGVCS-TRANSFER-INTERNAL-EVENT-V1\0'), Buffer.from(canonicalBytes(body))]));
}

function exactSha(value, label) {
  if (typeof value !== 'string' || !SHA.test(value)) transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  return value;
}

function validateEvent(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || !Number.isSafeInteger(value.occurredAtUnixMs) || value.occurredAtUnixMs < 0
      || !SHA.test(value.eventId ?? '') || !SHA.test(value.tenantScopeSha256 ?? '')) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'internal transfer event is invalid');
  }
  let identity;
  if (value.type === 'content-available') {
    if (Object.keys(value).sort().join('\0') !== 'backendReceiptSha256\0eventId\0generation\0objectId\0occurredAtUnixMs\0schemaVersion\0tenantScopeSha256\0type'
        || value.schemaVersion !== 'ogvcs.object-transfer/content-available-event/v1'
        || !SHA.test(value.backendReceiptSha256 ?? '')
        || typeof value.objectId !== 'string' || value.objectId.length < 1 || value.objectId.length > 144
        || !Number.isSafeInteger(value.generation) || value.generation < 1) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'content-available event is invalid');
    }
    const { eventId: _eventId, occurredAtUnixMs: _occurredAtUnixMs, ...stable } = value;
    identity = stable;
  } else if (value.type === 'integrity-failure') {
    if (Object.keys(value).sort().join('\0') !== 'backendKind\0eventId\0occurredAtUnixMs\0operation\0schemaVersion\0tenantScopeSha256\0type'
        || value.schemaVersion !== 'ogvcs.object-transfer/integrity-failure-event/v1'
        || !['filesystem', 's3-compatible'].includes(value.backendKind)
        || typeof value.operation !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/u.test(value.operation)) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'integrity-failure event is invalid');
    }
    const { eventId: _eventId, ...stable } = value;
    identity = stable;
  } else {
    transferError('TRANSFER_BACKEND_CORRUPT', 'internal transfer event type is invalid');
  }
  if (eventId(identity) !== value.eventId) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'internal transfer event identity differs');
  }
  return Object.freeze(value);
}

export class TransferEventStore {
  #rootPin;
  #eventsPin;
  #locksPin;

  constructor({
    root,
    now = () => Date.now(),
    lockLeaseMilliseconds = 300_000,
    maximumRecords = EVENTS_MAXIMUM,
  } = {}) {
    if (typeof root !== 'string' || !isAbsolute(root) || root.includes('\0') || typeof now !== 'function') {
      transferError('TRANSFER_INPUT_INVALID', 'transfer event store configuration is invalid');
    }
    if (!Number.isSafeInteger(lockLeaseMilliseconds) || lockLeaseMilliseconds < 1_000
        || lockLeaseMilliseconds > 86_400_000) {
      transferError('TRANSFER_INPUT_INVALID', 'transfer event lock lease is invalid');
    }
    if (!Number.isSafeInteger(maximumRecords) || maximumRecords < 1 || maximumRecords > EVENTS_MAXIMUM) {
      transferError('TRANSFER_INPUT_INVALID', 'transfer event record bound is invalid');
    }
    this.root = resolve(root);
    this.eventsRoot = join(this.root, 'events');
    this.locksRoot = join(this.root, 'locks');
    this.now = now;
    this.lockLeaseMilliseconds = lockLeaseMilliseconds;
    this.maximumRecords = maximumRecords;
  }

  async initialize() {
    this.#rootPin = await pinPlainDirectory(this.root);
    this.#eventsPin = await pinPlainDirectory(this.eventsRoot, { parentPin: this.#rootPin });
    this.#locksPin = await pinPlainDirectory(this.locksRoot, { parentPin: this.#rootPin });
    return this;
  }

  async #existing(path, id, identity) {
    const persisted = await readJson(path, EVENT_BYTES_MAXIMUM, { directoryPin: this.#eventsPin });
    const existing = persisted === null ? null : validateEvent(persisted);
    if (existing === null) return null;
    if (existing?.eventId !== id || Object.entries(identity).some(([key, value]) => existing[key] !== value)) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'internal transfer event replay differs');
    }
    return Object.freeze({ ...existing, replay: true });
  }

  async #countUnlocked() {
    let count = 0;
    const directory = await opendir(this.eventsRoot);
    try {
      for await (const entry of directory) {
        count += 1;
        if (count > this.maximumRecords || !entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) {
          transferError(
            count > this.maximumRecords ? 'TRANSFER_LIMIT_EXCEEDED' : 'TRANSFER_BACKEND_CORRUPT',
            count > this.maximumRecords
              ? 'internal transfer event bound exceeded'
              : 'event directory contains an invalid entry',
          );
        }
      }
    } finally { await directory.close().catch(() => {}); }
    return count;
  }

  async #record(body, identity = body) {
    const id = eventId(identity);
    const event = Object.freeze({ ...body, eventId: id });
    const path = join(this.eventsRoot, `${id}.json`);
    const replay = await this.#existing(path, id, identity);
    if (replay) return replay;
    return withRecoverableDirectoryLock({
      rootPin: this.#locksPin,
      name: EVENT_QUOTA_LOCK,
      now: this.now,
      leaseMilliseconds: this.lockLeaseMilliseconds,
      busyCode: 'TRANSFER_LIMIT_EXCEEDED',
      busyMessage: 'internal transfer event store is busy',
      operation: async (lockGuard) => {
        const raced = await this.#existing(path, id, identity);
        if (raced) return raced;
        if (await this.#countUnlocked() >= this.maximumRecords) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'internal transfer event bound exceeded');
        }
        const created = await atomicJsonCreate(path, event, {
          directoryPin: this.#eventsPin,
          lockGuard,
        });
        if (!created) {
          const existing = await this.#existing(path, id, identity);
          if (existing) return existing;
          transferError('TRANSFER_BACKEND_IO', 'internal transfer event publication raced');
        }
        return Object.freeze({ ...event, replay: false });
      }
    });
  }

  async contentAvailable({ tenantScopeSha256, objectId, generation, backendReceiptSha256 } = {}) {
    exactSha(tenantScopeSha256, 'tenant scope');
    exactSha(backendReceiptSha256, 'backend receipt');
    if (typeof objectId !== 'string' || objectId.length < 1 || objectId.length > 144
        || !Number.isSafeInteger(generation) || generation < 1) {
      transferError('TRANSFER_INPUT_INVALID', 'content-available event is invalid');
    }
    const identity = Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/content-available-event/v1',
      type: 'content-available',
      tenantScopeSha256,
      objectId,
      generation,
      backendReceiptSha256,
    });
    return this.#record(Object.freeze({
      ...identity,
      occurredAtUnixMs: this.now(),
    }), identity);
  }

  async integrityFailure({ tenantScopeSha256, backendKind, operation } = {}) {
    exactSha(tenantScopeSha256, 'tenant scope');
    if (!['filesystem', 's3-compatible'].includes(backendKind)
        || typeof operation !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/u.test(operation)) {
      transferError('TRANSFER_INPUT_INVALID', 'integrity-failure event is invalid');
    }
    // Object IDs, paths, credentials, and backend keys are deliberately absent.
    return this.#record(Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/integrity-failure-event/v1',
      type: 'integrity-failure',
      tenantScopeSha256,
      backendKind,
      operation,
      occurredAtUnixMs: this.now(),
    }));
  }

  async listBounded(maximum = this.maximumRecords) {
    if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > this.maximumRecords) {
      transferError('TRANSFER_INPUT_INVALID', 'event list bound is invalid');
    }
    const events = [];
    const directory = await opendir(this.eventsRoot);
    try {
      for await (const entry of directory) {
        if (!entry.isFile() || !/^[0-9a-f]{64}\.json$/u.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'event directory contains an invalid entry');
        }
        const value = await readJson(join(this.eventsRoot, entry.name), EVENT_BYTES_MAXIMUM, { directoryPin: this.#eventsPin });
        events.push(validateEvent(value));
        if (events.length > maximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'event list exceeds its bound');
      }
    } finally { await directory.close().catch(() => {}); }
    return Object.freeze(events.sort((left, right) => left.eventId < right.eventId ? -1 : left.eventId > right.eventId ? 1 : 0));
  }
}
