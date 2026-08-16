import { randomBytes } from 'node:crypto';

import { base64urlDecode, base64urlEncode, canonicalBytes, cloneJson, inspectJson, sha256 } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError, protocolSemanticError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

const CURSOR_TOKEN_DOMAIN = Buffer.from('OGVCS-PROTOCOL-CURSOR-TOKEN-V1\0', 'ascii');

function timeValue(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is invalid`);
  return value;
}

function expiryValue(now, ttlMs, label) {
  if (ttlMs > Number.MAX_SAFE_INTEGER - now) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} overflows the time domain`);
  return now + ttlMs;
}

function boundedText(value, label, maximum = 256) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 1 || Buffer.byteLength(value, 'utf8') > maximum) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is invalid`);
  return value;
}

function scopeValue(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor scope is invalid');
  const expected = ['operation', 'queryDigest', 'repository', 'subject', 'tenant'];
  if (Object.keys(input).sort().join('\0') !== expected.join('\0')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor scope fields are invalid');
  const result = {
    subject: boundedText(input.subject, 'cursor subject'),
    tenant: boundedText(input.tenant, 'cursor tenant'),
    repository: boundedText(input.repository, 'cursor repository'),
    operation: boundedText(input.operation, 'cursor operation'),
    queryDigest: input.queryDigest,
  };
  if (!/^[0-9a-f]{64}$/u.test(result.queryDigest)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor query digest is invalid');
  return cloneJson(result, { maxBytes: 4096, maxDepth: 4, maxNodes: 32, maxStringBytes: 256, maxCollectionItems: 16 });
}

function tokenValue(value) {
  if (typeof value !== 'string' || !value.startsWith('c1.') || value.length > 64) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor token is malformed');
  const bytes = base64urlDecode(value.slice(3), { maxBytes: 32 });
  if (bytes.length !== 32) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor token has the wrong length');
  return value;
}

function identity(token) {
  return sha256(Buffer.concat([CURSOR_TOKEN_DOMAIN, Buffer.from(token, 'ascii')]));
}

function sameScope(left, right) {
  return left.subject === right.subject && left.tenant === right.tenant && left.repository === right.repository && left.operation === right.operation && left.queryDigest === right.queryDigest;
}

function cursorFailure(reason, message) {
  const code = {
    expired: 'CURSOR_EXPIRED',
    gap: 'CURSOR_GAP',
    generation: 'CURSOR_GAP',
    scope: 'CURSOR_SCOPE_MISMATCH',
    unknown: 'CURSOR_INVALID',
    position: 'CURSOR_INVALID',
  }[reason] ?? 'CURSOR_INVALID';
  protocolSemanticError(code, message, { details: { reason } });
}

export class CursorStore {
  #entries = new Map();
  #maxBytes;
  #maxEntries;
  #memoryBytes = 0;
  #now;
  #random;
  #ttlMs;
  #tombstoneRetentionMs;

  constructor(options = {}) {
    this.#maxEntries = boundedInteger(options.maxEntries, 10_000, HARD_LIMITS.stateEntries, 'cursor maxEntries');
    this.#maxBytes = boundedInteger(options.maxBytes, 16 * 1024 * 1024, HARD_LIMITS.stateBytes, 'cursor maxBytes');
    this.#ttlMs = boundedInteger(options.ttlMs, 15 * 60 * 1000, HARD_LIMITS.cursorLifetimeMs, 'cursor ttlMs');
    this.#tombstoneRetentionMs = boundedInteger(options.tombstoneRetentionMs, HARD_LIMITS.stateTtlMs, HARD_LIMITS.stateTtlMs, 'cursor tombstoneRetentionMs');
    this.#now = options.now ?? (() => Date.now());
    this.#random = options.randomBytes ?? randomBytes;
    if (typeof this.#now !== 'function' || typeof this.#random !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor clock and random source must be callable');
  }

  #time() {
    return timeValue(this.#now(), 'cursor time');
  }

  #remove(key, record) {
    if (this.#entries.get(key) !== record) return;
    this.#entries.delete(key);
    this.#memoryBytes -= record.memoryBytes;
  }

  #prune(now, deadline) {
    let checked = 0;
    for (const [key, record] of this.#entries) {
      checked += 1;
      if ((checked & 1023) === 0) deadline.checkpoint();
      if (record.state !== 'expired' && record.expiresAt <= now) record.state = 'expired';
      if (record.state === 'expired' && record.tombstoneExpiresAt <= now) this.#remove(key, record);
    }
  }

  #newToken() {
    let bytes;
    try { bytes = Buffer.from(this.#random(32)); } catch (error) {
      protocolError(RUNTIME_ERROR_CODES.IO, 'cursor random source failed', { cause: error });
    }
    if (bytes.length !== 32) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'cursor random source returned the wrong length');
    return `c1.${base64urlEncode(bytes)}`;
  }

  #record(input, now, ttlMs) {
    const scope = scopeValue(input?.scope);
    const generation = timeValue(input?.generation, 'cursor generation');
    const position = timeValue(input?.position, 'cursor position');
    const state = input?.state ?? 'active';
    if (!['active', 'gap'].includes(state)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor state is invalid');
    const gapCode = input?.gapCode ?? null;
    if (state === 'gap' && (typeof gapCode !== 'string' || gapCode.length === 0 || gapCode.length > 128)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'cursor gap code is invalid');
    if (state === 'active' && gapCode !== null) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'active cursor cannot carry a gap code');
    const expiresAt = expiryValue(now, ttlMs, 'cursor expiry');
    const record = {
      scope, generation, position, issuedAt: now, expiresAt, state, gapCode,
      tombstoneExpiresAt: expiryValue(expiresAt, this.#tombstoneRetentionMs, 'cursor tombstone expiry'),
    };
    inspectJson(record, { maxBytes: 8192, maxDepth: 4, maxNodes: 64, maxStringBytes: 256, maxCollectionItems: 32 });
    // Reserve the largest permitted gap code up front. `markGap` can then make
    // its bounded in-place state transition without silently growing beyond
    // the configured store ceiling.
    record.memoryBytes = 512 + canonicalBytes(record).length + 128;
    return record;
  }

  issue(input, options = {}) {
    const deadline = deadlineFrom(options);
    const now = options.atUnixMs === undefined ? this.#time() : timeValue(options.atUnixMs, 'cursor time');
    const ttlMs = boundedInteger(options.ttlMs, this.#ttlMs, this.#ttlMs, 'cursor issue ttlMs');
    const record = this.#record(input, now, ttlMs);
    this.#prune(now, deadline);
    if (this.#entries.size >= this.#maxEntries || this.#memoryBytes + record.memoryBytes > this.#maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'cursor store ceiling exceeded');
    let token;
    let key;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      token = this.#newToken();
      key = identity(token);
      if (!this.#entries.has(key)) break;
      token = undefined;
    }
    if (token === undefined) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'cursor random source repeatedly collided');
    deadline.checkpoint();
    this.#entries.set(key, record);
    this.#memoryBytes += record.memoryBytes;
    return Object.freeze({ token, issuedAt: record.issuedAt, expiresAt: record.expiresAt });
  }

  issuePublic(contract, input, options = {}) {
    const issued = this.issue(input, options);
    return validateProtocolValue(contract, 'Cursor.schema.json', { token: issued.token }, { ...options, maxBytes: HARD_LIMITS.cursorBytes });
  }

  read(tokenInput, scopeInput, options = {}) {
    const deadline = deadlineFrom(options);
    const scope = scopeValue(scopeInput);
    const token = tokenValue(tokenInput);
    const now = options.atUnixMs === undefined ? this.#time() : timeValue(options.atUnixMs, 'cursor time');
    const key = identity(token);
    const record = this.#entries.get(key);
    deadline.checkpoint();
    if (!record) cursorFailure('unknown', 'cursor is unknown or invalid');
    if (record.expiresAt <= now) {
      record.state = 'expired';
      cursorFailure('expired', 'cursor has expired');
    }
    if (!sameScope(record.scope, scope)) cursorFailure('scope', 'cursor scope does not match the request');
    if (options.generation !== undefined && timeValue(options.generation, 'cursor expected generation') !== record.generation) cursorFailure('generation', 'cursor generation is stale');
    if (record.state === 'gap') cursorFailure('gap', 'cursor retention gap requires reconciliation');
    return cloneJson({ generation: record.generation, position: record.position, issuedAt: record.issuedAt, expiresAt: record.expiresAt });
  }

  readPublic(contract, cursorInput, scopeInput, options = {}) {
    const cursor = validateProtocolValue(contract, 'Cursor.schema.json', cursorInput, { ...options, maxBytes: HARD_LIMITS.cursorBytes });
    return this.read(cursor.token, scopeInput, options);
  }

  advance(tokenInput, scopeInput, nextInput, options = {}) {
    const deadline = deadlineFrom(options);
    const scope = scopeValue(scopeInput);
    const token = tokenValue(tokenInput);
    const now = options.atUnixMs === undefined ? this.#time() : timeValue(options.atUnixMs, 'cursor time');
    const oldKey = identity(token);
    const old = this.#entries.get(oldKey);
    if (!old) cursorFailure('unknown', 'cursor is unknown or invalid');
    if (old.expiresAt <= now) { old.state = 'expired'; cursorFailure('expired', 'cursor has expired'); }
    if (!sameScope(old.scope, scope)) cursorFailure('scope', 'cursor scope does not match the request');
    if (old.state === 'gap') cursorFailure('gap', 'cursor retention gap requires reconciliation');
    const position = timeValue(nextInput?.position, 'cursor next position');
    const generation = nextInput?.generation === undefined ? old.generation : timeValue(nextInput.generation, 'cursor next generation');
    if (position < old.position) cursorFailure('position', 'cursor position cannot move backwards');
    const replacement = this.#record({ scope, generation, position, state: 'active', gapCode: null }, now, this.#ttlMs);
    if (this.#memoryBytes - old.memoryBytes + replacement.memoryBytes > this.#maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'cursor store memory ceiling exceeded');
    let nextToken;
    let nextKey;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      nextToken = this.#newToken();
      nextKey = identity(nextToken);
      if (!this.#entries.has(nextKey)) break;
      nextToken = undefined;
    }
    if (nextToken === undefined) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'cursor random source repeatedly collided');
    deadline.checkpoint();
    this.#entries.delete(oldKey);
    this.#entries.set(nextKey, replacement);
    this.#memoryBytes += replacement.memoryBytes - old.memoryBytes;
    return Object.freeze({ token: nextToken, issuedAt: replacement.issuedAt, expiresAt: replacement.expiresAt });
  }

  markGap(tokenInput, gapCode, options = {}) {
    const token = tokenValue(tokenInput);
    boundedText(gapCode, 'cursor gap code', 128);
    const key = identity(token);
    const record = this.#entries.get(key);
    deadlineFrom(options).checkpoint();
    if (!record) cursorFailure('unknown', 'cursor is unknown or invalid');
    record.state = 'gap';
    record.gapCode = gapCode;
  }

  summary() {
    return Object.freeze({ entries: this.#entries.size, memoryBytes: this.#memoryBytes });
  }
}
