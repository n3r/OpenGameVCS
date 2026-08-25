import { createHmac } from 'node:crypto';

import { base64urlDecode, base64urlEncode, canonicalBytes, cloneJson, equalBytes, parseJson } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

const RECEIPT_DOMAIN = Buffer.from('OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0', 'ascii');

function keyIdValue(value, options = {}) {
  const pattern = options.tokenSegment === true
    ? /^[a-z0-9][a-z0-9_/-]*(?:@[0-9]+)?$/u
    : /^[a-z0-9][a-z0-9._/-]*(?:@[0-9]+)?$/u;
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 256 || !pattern.test(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt key identifier is invalid');
  return value;
}

function keyValue(value) {
  if (!(Buffer.isBuffer(value) || value instanceof Uint8Array) || value.byteLength < 32 || value.byteLength > 64) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt MAC key must contain 32 to 64 bytes');
  return Buffer.from(value);
}

function timeValue(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is invalid`);
  return value;
}

export function validateNegotiationServerNonce(value) {
  const bytes = base64urlDecode(value, { maxBytes: 64 });
  if (bytes.length < 16) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'negotiation server nonce must decode to 16 through 64 bytes');
  return bytes;
}

function mac(key, keyId, claimsBytes) {
  return createHmac('sha256', key)
    .update(RECEIPT_DOMAIN)
    .update(Buffer.from(keyId, 'ascii'))
    .update(Buffer.from([0]))
    .update(claimsBytes)
    .digest();
}

function genericFailure(cause) {
  if ([RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED, RUNTIME_ERROR_CODES.CANCELLED].includes(cause?.code)) throw cause;
  protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'negotiation receipt is invalid, stale, or foreign', cause === undefined ? undefined : { cause });
}

export class MacReceiptCodec {
  #key;
  #keyId;
  #maxBytes;
  #maxTtlMs;
  #now;

  constructor(options = {}) {
    this.#key = keyValue(options.key);
    // The compact token uses `.` as its structural delimiter, so a key ID
    // accepted here must itself be one token segment. Structured negotiation
    // receipts keep the wider registered key-ID grammar below.
    this.#keyId = keyIdValue(options.keyId, { tokenSegment: true });
    this.#maxBytes = boundedInteger(options.maxBytes, 32 * 1024, HARD_LIMITS.jsonBytes, 'receipt maxBytes');
    this.#maxTtlMs = boundedInteger(options.maxTtlMs, 5 * 60 * 1000, HARD_LIMITS.stateTtlMs, 'receipt maxTtlMs');
    this.#now = options.now ?? (() => Date.now());
    if (typeof this.#now !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt clock must be callable');
  }

  #time(value) {
    return value === undefined ? timeValue(this.#now(), 'receipt time') : timeValue(value, 'receipt time');
  }

  issue(claimsInput, options = {}) {
    const deadline = deadlineFrom(options);
    const claims = cloneJson(claimsInput, { ...options, maxBytes: this.#maxBytes, maxDepth: 16, maxNodes: 10_000, maxStringBytes: 4096, maxCollectionItems: 4096, deadline });
    const now = this.#time(options.atUnixMs);
    if (!Number.isSafeInteger(claims.issuedAt) || claims.issuedAt !== now || !Number.isSafeInteger(claims.expiresAt) || claims.expiresAt <= now || claims.expiresAt - now > this.#maxTtlMs) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt validity window is invalid');
    }
    const claimsBytes = canonicalBytes(claims, { ...options, maxBytes: this.#maxBytes, deadline });
    const signature = mac(this.#key, this.#keyId, claimsBytes);
    const token = `nr1.${this.#keyId}.${base64urlEncode(claimsBytes)}.${base64urlEncode(signature)}`;
    if (Buffer.byteLength(token, 'ascii') > this.#maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'receipt byte ceiling exceeded');
    deadline.checkpoint();
    return token;
  }

  verify(token, expectedBindings, options = {}) {
    const deadline = deadlineFrom(options);
    if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') > this.#maxBytes || !token.startsWith('nr1.')) genericFailure();
    const parts = token.split('.');
    if (parts.length !== 4 || parts[1] !== this.#keyId) genericFailure();
    let claimsBytes;
    let suppliedMac;
    try {
      claimsBytes = base64urlDecode(parts[2], { maxBytes: this.#maxBytes });
      suppliedMac = base64urlDecode(parts[3], { maxBytes: 32 });
    } catch (error) { genericFailure(error); }
    const expectedMac = mac(this.#key, this.#keyId, claimsBytes);
    if (!equalBytes(suppliedMac, expectedMac)) genericFailure();
    let claims;
    try { claims = parseJson(claimsBytes, { ...options, requireCanonical: true, maxBytes: this.#maxBytes, deadline }); } catch (error) { genericFailure(error); }
    const now = this.#time(options.atUnixMs);
    if (!Number.isSafeInteger(claims.issuedAt) || !Number.isSafeInteger(claims.expiresAt) || claims.issuedAt > now || claims.expiresAt <= now || claims.expiresAt - claims.issuedAt > this.#maxTtlMs) genericFailure();
    const bindings = cloneJson(expectedBindings, { ...options, maxBytes: 16 * 1024, maxDepth: 8, maxNodes: 256, maxStringBytes: 1024, maxCollectionItems: 128, deadline });
    if (bindings === null || typeof bindings !== 'object' || Array.isArray(bindings) || Object.keys(bindings).length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt expected bindings are invalid');
    for (const [name, expected] of Object.entries(bindings)) {
      if (!Object.hasOwn(claims, name) || !equalBytes(canonicalBytes(claims[name], options), canonicalBytes(expected, options))) genericFailure();
    }
    deadline.checkpoint();
    return claims;
  }
}

export class NegotiationReceiptCodec {
  #contract;
  #key;
  #keyId;
  #maxBytes;
  #maxTtlMs;
  #now;

  constructor(options = {}) {
    this.#contract = options.contract;
    if (!this.#contract?.validator) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract is required for negotiation receipts');
    this.#key = keyValue(options.key);
    this.#keyId = keyIdValue(options.keyId);
    this.#maxBytes = boundedInteger(options.maxBytes, HARD_LIMITS.receiptBytes, HARD_LIMITS.receiptBytes, 'receipt maxBytes');
    this.#maxTtlMs = boundedInteger(options.maxTtlMs, HARD_LIMITS.receiptLifetimeMs, HARD_LIMITS.receiptLifetimeMs, 'receipt maxTtlMs');
    this.#now = options.now ?? (() => Date.now());
    if (typeof this.#now !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt clock must be callable');
  }

  #time(value) {
    return value === undefined ? timeValue(this.#now(), 'receipt time') : timeValue(value, 'receipt time');
  }

  issue(claimsInput, options = {}) {
    const deadline = deadlineFrom(options);
    const claims = validateProtocolValue(this.#contract, 'NegotiationReceiptClaims.schema.json', claimsInput, { ...options, maxBytes: this.#maxBytes, deadline });
    validateNegotiationServerNonce(claims.serverNonce);
    const now = this.#time(options.atUnixMs);
    if (claims.issuedAtUnixMs !== now || claims.expiresAtUnixMs <= now || claims.expiresAtUnixMs - now > this.#maxTtlMs) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt validity window is invalid');
    const claimsBytes = canonicalBytes(claims, { ...options, maxBytes: this.#maxBytes, deadline });
    const receipt = {
      algorithm: 'HMAC-SHA-256',
      keyId: this.#keyId,
      claims,
      mac: base64urlEncode(mac(this.#key, this.#keyId, claimsBytes)),
    };
    return validateProtocolValue(this.#contract, 'NegotiationReceipt.schema.json', receipt, { ...options, maxBytes: this.#maxBytes, deadline });
  }

  verify(receiptInput, expectedBindings, options = {}) {
    const deadline = deadlineFrom(options);
    let receipt;
    try { receipt = validateProtocolValue(this.#contract, 'NegotiationReceipt.schema.json', receiptInput, { ...options, maxBytes: this.#maxBytes, deadline }); } catch (error) { genericFailure(error); }
    if (receipt.algorithm !== 'HMAC-SHA-256' || receipt.keyId !== this.#keyId) genericFailure();
    const claimsBytes = canonicalBytes(receipt.claims, { ...options, maxBytes: this.#maxBytes, deadline });
    let suppliedMac;
    try { suppliedMac = base64urlDecode(receipt.mac, { maxBytes: 32 }); } catch (error) { genericFailure(error); }
    if (!equalBytes(suppliedMac, mac(this.#key, this.#keyId, claimsBytes))) genericFailure();
    try { validateNegotiationServerNonce(receipt.claims.serverNonce); } catch (error) { genericFailure(error); }
    const now = this.#time(options.atUnixMs);
    if (receipt.claims.issuedAtUnixMs > now || receipt.claims.expiresAtUnixMs <= now || receipt.claims.expiresAtUnixMs - receipt.claims.issuedAtUnixMs > this.#maxTtlMs) {
      protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'negotiation receipt has expired', { details: { reason: 'expired' } });
    }
    const bindings = cloneJson(expectedBindings, { ...options, maxBytes: 16 * 1024, maxDepth: 8, maxNodes: 256, maxStringBytes: 1024, maxCollectionItems: 128, deadline });
    if (bindings === null || typeof bindings !== 'object' || Array.isArray(bindings) || Object.keys(bindings).length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'receipt expected bindings are invalid');
    for (const [name, expected] of Object.entries(bindings)) {
      if (!Object.hasOwn(receipt.claims, name) || !equalBytes(canonicalBytes(receipt.claims[name], options), canonicalBytes(expected, options))) genericFailure();
    }
    return receipt.claims;
  }
}

export { RECEIPT_DOMAIN };
