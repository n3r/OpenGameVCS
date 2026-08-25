import { randomBytes } from 'node:crypto';

import { canonicalBytes, cloneJson, sha256 } from './canonical.mjs';
import {
  ProtocolBaselineError, RUNTIME_ERROR_CODES, protocolError, protocolSemanticError,
} from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

export const IDEMPOTENCY_DOMAIN = Buffer.from('ogvcs.protocol/idempotency/v1\0', 'ascii');

function nowValue(value) {
  if (!Number.isSafeInteger(value) || value < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency time is invalid');
  return value;
}

function expiryValue(now, ttlMs, label) {
  if (ttlMs > Number.MAX_SAFE_INTEGER - now) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} overflows the time domain`);
  return now + ttlMs;
}

const KEY_PATTERN = /^ik1\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.([A-Za-z0-9_-]{22,218})$/u;

function keyValue(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > HARD_LIMITS.idempotencyKeyBytes) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency key is invalid');
  }
  const match = KEY_PATTERN.exec(value);
  if (!match) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency key is invalid');
  const issuedAtUnixMs = Number(match[1]);
  const expiresAtUnixMs = Number(match[2]);
  if (!Number.isSafeInteger(issuedAtUnixMs) || !Number.isSafeInteger(expiresAtUnixMs)
      || expiresAtUnixMs <= issuedAtUnixMs
      || expiresAtUnixMs - issuedAtUnixMs > HARD_LIMITS.deadlineHorizonMs) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency key lifetime is invalid');
  }
  return Object.freeze({ value, issuedAtUnixMs, expiresAtUnixMs });
}

export function validateIdempotencyKeyBinding(value, issuedAtUnixMs, expiresAtUnixMs) {
  const parsed = keyValue(value);
  if (!Number.isSafeInteger(issuedAtUnixMs) || !Number.isSafeInteger(expiresAtUnixMs)
      || parsed.issuedAtUnixMs !== issuedAtUnixMs || parsed.expiresAtUnixMs !== expiresAtUnixMs) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency key timestamps do not match the declared binding');
  }
  return parsed;
}

function fingerprintValue(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency fingerprint is invalid');
  return value;
}

function scopeValue(input, options = {}) {
  const value = cloneJson(input, { ...options, maxBytes: 16 * 1024, maxDepth: 8, maxNodes: 256, maxStringBytes: 1024, maxCollectionItems: 128 });
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency scope is invalid');
  return value;
}

function operationInput(input, options = {}) {
  const value = cloneJson(input, { ...options, maxBytes: 20 * 1024, maxDepth: 9, maxNodes: 272, maxStringBytes: 1024, maxCollectionItems: 132 });
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== 'fingerprint\0key\0scope') {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency operation input is invalid');
  }
  return value;
}

export function semanticIdempotencyFingerprint(descriptor, options = {}) {
  const value = cloneJson(descriptor, options);
  return sha256(Buffer.concat([IDEMPOTENCY_DOMAIN, canonicalBytes(value, options)]));
}

export function requestIdempotencyProjection(requestInput, options = {}) {
  const request = options.contract === undefined
    ? cloneJson(requestInput, options)
    : validateProtocolValue(options.contract, options.requestSchema ?? 'RequestEnvelope.schema.json', requestInput, options);
  if (request === null || typeof request !== 'object' || Array.isArray(request) || typeof request.operation !== 'string' || !Object.hasOwn(request, 'body')) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency projection requires a validated request envelope');
  }
  if (typeof request.schemaVersion !== 'string') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency projection requires request schemaVersion');
  return cloneJson({
    schemaVersion: request.schemaVersion,
    operation: request.operation,
    body: request.body,
    extensions: request.extensions ?? {},
  }, options);
}

export function createIdempotencyDescriptor(contract, key, requestInput, options = {}) {
  const projection = requestIdempotencyProjection(requestInput, { ...options, contract });
  const parsedKey = keyValue(key);
  return validateProtocolValue(contract, 'IdempotencyDescriptor.schema.json', {
    key: parsedKey.value,
    algorithm: 'OGVCS-SEMANTIC-JCS-SHA-256',
    projectionVersion: 'ogvcs.protocol/fingerprint-projection@1',
    fingerprint: semanticIdempotencyFingerprint(projection, options),
    issuedAtUnixMs: parsedKey.issuedAtUnixMs,
    expiresAtUnixMs: parsedKey.expiresAtUnixMs,
  }, options);
}

export function validateIdempotencyDescriptor(contract, descriptorInput, requestInput, options = {}) {
  const descriptor = validateProtocolValue(contract, 'IdempotencyDescriptor.schema.json', descriptorInput, options);
  const parsedKey = keyValue(descriptor.key);
  const expected = semanticIdempotencyFingerprint(requestIdempotencyProjection(requestInput, { ...options, contract }), options);
  if (descriptor.algorithm !== 'OGVCS-SEMANTIC-JCS-SHA-256' || descriptor.projectionVersion !== 'ogvcs.protocol/fingerprint-projection@1' || descriptor.fingerprint !== expected) {
    protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency descriptor does not match the semantic request');
  }
  if (descriptor.issuedAtUnixMs !== parsedKey.issuedAtUnixMs || descriptor.expiresAtUnixMs !== parsedKey.expiresAtUnixMs) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency descriptor key timestamps do not match');
  }
  return descriptor;
}

export class IdempotencyReplayStore {
  #entries = new Map();
  #decisions = new WeakMap();
  #leases = new WeakMap();
  #maxBytes;
  #maxEntries;
  #maxOutcomeBytes;
  #memoryBytes = 0;
  #now;
  #tombstoneTtlMs;

  constructor(options = {}) {
    this.#maxEntries = boundedInteger(options.maxEntries, 10_000, HARD_LIMITS.stateEntries, 'idempotency maxEntries');
    this.#maxBytes = boundedInteger(options.maxBytes, 16 * 1024 * 1024, HARD_LIMITS.stateBytes, 'idempotency maxBytes');
    this.#maxOutcomeBytes = boundedInteger(options.maxOutcomeBytes, 64 * 1024, HARD_LIMITS.jsonBytes, 'idempotency maxOutcomeBytes');
    this.#tombstoneTtlMs = boundedInteger(
      options.tombstoneTtlMs,
      HARD_LIMITS.stateTtlMs,
      HARD_LIMITS.stateTtlMs,
      'idempotency tombstoneTtlMs',
      { minimum: 0 },
    );
    this.#now = options.now ?? (() => Date.now());
    if (typeof this.#now !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency clock must be callable');
  }

  #time() {
    return nowValue(this.#now());
  }

  #remove(identity, record) {
    if (this.#entries.get(identity) !== record) return;
    this.#entries.delete(identity);
    this.#memoryBytes -= record.reservedBytes;
  }

  #markIndeterminate(lease, error) {
    const binding = this.#leases.get(lease);
    if (!binding || binding.record.state !== 'pending' || this.#entries.get(binding.identity) !== binding.record) return false;
    this.#leases.delete(lease);
    binding.record.state = 'indeterminate';
    binding.record.outcome = undefined;
    binding.record.rejectCompletion(error);
    return true;
  }

  #markStarted(lease) {
    const binding = this.#leases.get(lease);
    if (!binding || binding.record.state !== 'pending' || this.#entries.get(binding.identity) !== binding.record) {
      protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency lease is stale or invalid');
    }
    binding.record.mutationStarted = true;
    return binding.record;
  }

  #prune(now, deadline) {
    let checked = 0;
    for (const [identity, record] of this.#entries) {
      checked += 1;
      if ((checked & 1023) === 0) deadline.checkpoint();
      if ((record.state === 'committed' || record.state === 'indeterminate') && record.expiresAt <= now) {
        record.state = 'tombstone';
        record.outcome = undefined;
      } else if (record.state === 'tombstone' && record.tombstoneExpiresAt <= now) {
        this.#remove(identity, record);
      }
    }
  }

  begin(input, options = {}) {
    const deadline = deadlineFrom(options);
    const value = operationInput(input, { ...options, deadline });
    const now = options.atUnixMs === undefined ? this.#time() : nowValue(options.atUnixMs);
    const scope = scopeValue(value.scope, { ...options, deadline });
    const parsedKey = keyValue(value.key);
    const key = parsedKey.value;
    const fingerprint = fingerprintValue(value.fingerprint);
    this.#prune(now, deadline);
    if (parsedKey.issuedAtUnixMs > now || parsedKey.expiresAtUnixMs <= now) {
      protocolSemanticError('IDEMPOTENCY_KEY_REQUIRED', 'idempotency key is not valid at the server clock');
    }
    const identity = sha256(Buffer.concat([Buffer.from('OGVCS-PROTOCOL-IDEMPOTENCY-KEY-V1\0', 'ascii'), canonicalBytes(scope, { ...options, deadline }), Buffer.from([0]), Buffer.from(key, 'utf8')]));
    const existing = this.#entries.get(identity);
    if (existing) {
      if (existing.fingerprint !== fingerprint) protocolSemanticError('IDEMPOTENCY_KEY_REUSE', 'idempotency key was reused with different semantic input');
      if (existing.state === 'committed') {
        const decision = Object.freeze({ kind: 'replay', fingerprint });
        this.#decisions.set(decision, existing);
        return decision;
      }
      if (existing.state === 'tombstone') protocolSemanticError('IDEMPOTENCY_KEY_REQUIRED', 'idempotency outcome expired; a new key is required');
      if (existing.state === 'indeterminate') protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency outcome is indeterminate; reconciliation or a new key is required');
      const decision = Object.freeze({ kind: 'pending', fingerprint });
      this.#decisions.set(decision, existing);
      return decision;
    }
    if (this.#entries.size >= this.#maxEntries) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'idempotency entry ceiling exceeded');
    const scopeBytes = canonicalBytes(scope, { ...options, deadline }).length;
    const reservedBytes = 512 + scopeBytes + Buffer.byteLength(key, 'utf8') + this.#maxOutcomeBytes;
    if (this.#memoryBytes + reservedBytes > this.#maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'idempotency memory ceiling exceeded');
    let resolveCompletion;
    let rejectCompletion;
    const completion = new Promise((resolve, reject) => { resolveCompletion = resolve; rejectCompletion = reject; });
    completion.catch(() => {});
    const expiresAt = parsedKey.expiresAtUnixMs;
    const record = {
      state: 'pending', fingerprint, scope, key, outcome: undefined,
      expiresAt, tombstoneExpiresAt: expiryValue(expiresAt, this.#tombstoneTtlMs, 'idempotency tombstone expiry'),
      reservedBytes, completion, resolveCompletion, rejectCompletion, mutationStarted: false,
    };
    const lease = Object.freeze({ id: randomBytes(16).toString('hex') });
    deadline.checkpoint();
    this.#entries.set(identity, record);
    this.#leases.set(lease, { identity, record });
    this.#memoryBytes += reservedBytes;
    return Object.freeze({ kind: 'new', lease, fingerprint });
  }

  commit(lease, outcome, options = {}) {
    const deadline = deadlineFrom(options);
    const binding = this.#leases.get(lease);
    if (!binding || binding.record.state !== 'pending' || this.#entries.get(binding.identity) !== binding.record) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency lease is stale or invalid');
    const cloned = cloneJson(outcome, { ...options, maxBytes: this.#maxOutcomeBytes });
    deadline.checkpoint();
    const record = binding.record;
    record.outcome = cloned;
    record.state = 'committed';
    this.#leases.delete(lease);
    // `cloneJson` returns a deeply frozen JSON graph. Sharing that immutable
    // outcome between the durable record, pending waiters, and the committing
    // caller avoids three simultaneous full-size clones without exposing
    // mutable store-owned state.
    record.resolveCompletion(cloned);
    return Object.freeze({ kind: 'committed', outcome: cloned, fingerprint: record.fingerprint });
  }

  abort(lease, error = new Error('idempotency operation aborted')) {
    const binding = this.#leases.get(lease);
    if (!binding || binding.record.state !== 'pending' || this.#entries.get(binding.identity) !== binding.record) return false;
    if (binding.record.mutationStarted) return false;
    this.#leases.delete(lease);
    this.#remove(binding.identity, binding.record);
    binding.record.state = 'aborted';
    binding.record.rejectCompletion(error);
    return true;
  }

  async execute(input, mutate, options = {}) {
    if (typeof mutate !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'idempotency mutation callback must be callable');
    const deadline = deadlineFrom(options);
    const decision = this.begin(input, { ...options, deadline });
    if (decision.kind === 'replay') {
      const record = this.#decisions.get(decision);
      if (!record || record.state !== 'committed') protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency replay state changed during authorization');
      await this.#authorizeReplay(options.authorizeReplay, record, { ...options, deadline }, 'committed');
      if (record.state !== 'committed') protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency replay state changed during authorization');
      return Object.freeze({ kind: 'replay', outcome: cloneJson(record.outcome, options), fingerprint: decision.fingerprint });
    }
    if (decision.kind === 'pending') {
      const record = this.#decisions.get(decision);
      if (!record || !['pending', 'committed'].includes(record.state)) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency pending state changed during authorization');
      await this.#authorizeReplay(options.authorizeReplay, record, { ...options, deadline }, 'pending');
      if (!['pending', 'committed'].includes(record.state)) protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'idempotency pending state changed during authorization');
      let outcome;
      try { outcome = await deadline.race(record.completion, 'idempotency replay wait'); } catch (error) {
        if (error?.code === RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED || error?.code === RUNTIME_ERROR_CODES.CANCELLED) {
          throw new ProtocolBaselineError(error.code, error.message, { cause: error, preMutation: false });
        }
        throw error;
      }
      return Object.freeze({ kind: 'replay', outcome: cloneJson(outcome, options), fingerprint: decision.fingerprint });
    }
    this.#markStarted(decision.lease);
    const settlement = Promise.resolve().then(() => mutate({ signal: deadline.signal })).then(
      (outcome) => {
        // Settlement continues after a caller-visible timeout so the durable
        // idempotency record can still become replayable. Carry the configured
        // memory reduction, but never reuse the already-expired caller deadline.
        const commitOptions = options.maxWorkingMemoryBytes === undefined
          ? {}
          : { maxWorkingMemoryBytes: options.maxWorkingMemoryBytes };
        try { return this.commit(decision.lease, outcome, commitOptions); } catch (error) {
          this.#markIndeterminate(decision.lease, error);
          throw error;
        }
      },
      (error) => {
        this.#markIndeterminate(decision.lease, error);
        throw error;
      },
    );
    settlement.catch(() => {});
    try {
      const committed = await deadline.race(settlement, 'idempotent mutation');
      if (typeof options.afterCommit === 'function') await deadline.race(options.afterCommit({ signal: deadline.signal }), 'post-commit response');
      return committed;
    } catch (error) {
      if (error?.code === RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED || error?.code === RUNTIME_ERROR_CODES.CANCELLED) {
        throw new ProtocolBaselineError(error.code, error.message, { cause: error, preMutation: false });
      }
      throw error;
    }
  }

  async #authorizeReplay(authorizeReplay, record, options, state) {
    const deadline = options.deadline;
    if (typeof authorizeReplay !== 'function') {
      protocolSemanticError('AUTHORIZATION_DENIED', 'idempotency replay authorization is required');
    }
    let decision;
    try {
      const supplied = await deadline.race(authorizeReplay(cloneJson({
        scope: record.scope,
        key: record.key,
        fingerprint: record.fingerprint,
        state,
      }, options), { signal: deadline.signal }), 'idempotency replay authorization');
      decision = cloneJson(supplied, { ...options, maxBytes: 1024, maxDepth: 2, maxNodes: 8, maxStringBytes: 128, maxCollectionItems: 4 });
    } catch (error) {
      if ([RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED, RUNTIME_ERROR_CODES.CANCELLED].includes(error?.code)) throw error;
      protocolSemanticError('AUTHORIZATION_DENIED', 'idempotency replay authorization was denied');
    }
    if (decision === null || typeof decision !== 'object' || Array.isArray(decision)
        || Object.keys(decision).sort().join('\0') !== 'code\0result'
        || decision.result !== 'allow'
        || !['ALLOW_EXPLICIT', 'ALLOW_PUBLIC'].includes(decision.code)) {
      protocolSemanticError('AUTHORIZATION_DENIED', 'idempotency replay authorization was denied');
    }
  }

  summary() {
    let pending = 0;
    for (const record of this.#entries.values()) if (record.state === 'pending') pending += 1;
    return Object.freeze({ entries: this.#entries.size, pending, memoryBytes: this.#memoryBytes });
  }
}
