import { createHash } from 'node:crypto';
import { encodeCanonical } from './cbor.js';
import { fail } from './errors.js';
import { configuredHardLimit, hardLimitMaximum } from './hard-limits.js';
import { ObjectRef, Digest, KIND_NAMES, equalBytes } from './types.js';
import {
  FROZEN_LOGICAL_TYPES, isKindNameAuthority, isLogicalTypeAuthority
} from './assignment-authority.js';

const OBJECT_DOMAIN = Buffer.from('OpenGameVCS object\0', 'ascii');
const LOGICAL_DOMAIN = Buffer.from('OpenGameVCS logical record\0', 'ascii');
const CONFLICT_DOMAIN = Buffer.from('OpenGameVCS conflict\0', 'ascii');
const BUNDLE_DOMAIN = Buffer.from('OpenGameVCS logical bundle\0', 'ascii');
const MAX_CHUNK_BYTES = hardLimitMaximum('chunk-payload-bytes');
const MAX_METADATA_BYTES = hardLimitMaximum('metadata-payload-bytes');
const MAX_BUNDLE_BYTES = hardLimitMaximum('bundle-sequence-bytes');

function u16(value, code = 'SCHEMA_FIELD_INVALID') {
  if (!Number.isInteger(value) || value < 1 || value > 65535) fail(code, { layer: 2 });
  return Uint8Array.of(value >>> 8, value & 0xff);
}

function bytes(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}

function assigned(registry, code) {
  return registry?.has?.(code) === true;
}

// Metadata and logical-record maps canonically begin with keys 0 and 1. This
// bounded prefix parser verifies the identity discriminator without decoding or
// retaining the payload. null means that another prefix chunk is required.
function uintAt(input, offset) {
  if (offset >= input.length) return null;
  const first = input[offset];
  const major = first >>> 5;
  const ai = first & 31;
  if (major !== 0 || ai === 31) fail('CBOR_NON_CANONICAL', { layer: 1, offset });
  if (ai < 24) return { value: ai, next: offset + 1 };
  const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : -1;
  if (size < 0) fail('CBOR_NON_CANONICAL', { layer: 1, offset });
  if (input.length < offset + 1 + size) return null;
  let value = 0n;
  for (let i = 0; i < size; i++) value = (value << 8n) | BigInt(input[offset + 1 + i]);
  if ((size === 1 && value < 24n) || (size === 2 && value <= 0xffn) ||
      (size === 4 && value <= 0xffffn) || (size === 8 && value <= 0xffff_ffffn) ||
      value > BigInt(Number.MAX_SAFE_INTEGER)) fail('CBOR_NON_CANONICAL', { layer: 1, offset });
  return { value: Number(value), next: offset + 1 + size };
}

function discriminatorAtFieldOne(input) {
  if (input.length === 0) return null;
  const first = input[0];
  if ((first >>> 5) !== 5 || (first & 31) === 31) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  let offset;
  if ((first & 31) < 24) {
    if ((first & 31) < 2) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    offset = 1;
  } else {
    // Re-read the map length as an unsigned header by replacing its major bits.
    const copy = input.slice();
    copy[0] = first & 31;
    const length = uintAt(copy, 0);
    if (!length) return null;
    if (length.value < 2) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    offset = length.next;
  }
  for (const expected of [0, 1, 1]) {
    const value = uintAt(input, offset);
    if (!value) return null;
    if (value.value !== expected) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    offset = value.next;
  }
  return uintAt(input, offset)?.value ?? null;
}

class DomainHashWriter {
  #hash;
  #finished = false;
  #bytes = 0;
  #maximum;
  #limitCode;
  #limitStage;
  #expectedFieldOne;
  #prefix = new Uint8Array();

  constructor(domain, discriminator, {
    maximum = Number.MAX_SAFE_INTEGER, limitCode = 'LIMIT_METADATA_BYTES', limitStage, expectedFieldOne
  } = {}) {
    this.#hash = createHash('sha256');
    this.#hash.update(domain);
    this.#hash.update(u16(1));
    if (discriminator !== undefined) this.#hash.update(u16(discriminator));
    this.#maximum = maximum;
    this.#limitCode = limitCode;
    this.#limitStage = limitStage;
    this.#expectedFieldOne = expectedFieldOne;
  }

  update(part) {
    if (this.#finished) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    const chunk = bytes(part);
    if (chunk.length > this.#maximum - this.#bytes) {
      const details = { layer: 1 };
      if (this.#limitStage !== undefined) details.stage = this.#limitStage;
      fail(this.#limitCode, details);
    }
    this.#bytes += chunk.length;
    if (this.#expectedFieldOne !== undefined && discriminatorAtFieldOne(this.#prefix) === null) {
      const take = Math.min(chunk.length, 128 - this.#prefix.length);
      const joined = new Uint8Array(this.#prefix.length + take);
      joined.set(this.#prefix);
      joined.set(chunk.subarray(0, take), this.#prefix.length);
      this.#prefix = joined;
    }
    this.#hash.update(chunk);
    return this;
  }

  finishBytes() {
    if (this.#finished) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    this.#finished = true;
    if (this.#expectedFieldOne !== undefined) {
      const actual = discriminatorAtFieldOne(this.#prefix);
      if (actual === null || actual !== this.#expectedFieldOne) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    }
    return new Uint8Array(this.#hash.digest());
  }
}

export class Sha256Writer {
  #hash = createHash('sha256');
  #finished = false;
  update(part) {
    if (this.#finished) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    this.#hash.update(bytes(part));
    return this;
  }
  finish() {
    if (this.#finished) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    this.#finished = true;
    return new Digest(1, new Uint8Array(this.#hash.digest()));
  }
}

export function createObjectHashWriter(kind, {
  maxChunkBytes = MAX_CHUNK_BYTES, maxMetadataBytes = MAX_METADATA_BYTES, registry = KIND_NAMES
} = {}) {
  if (!isKindNameAuthority(registry)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (!Number.isInteger(kind) || kind < 1 || kind > 65535 || !assigned(registry, kind)) {
    fail('OBJECT_KIND_UNSUPPORTED', { layer: 2 });
  }
  const maximum = kind === 1
    ? configuredHardLimit('chunk-payload-bytes', maxChunkBytes)
    : configuredHardLimit('metadata-payload-bytes', maxMetadataBytes);
  const state = new DomainHashWriter(OBJECT_DOMAIN, kind, {
    maximum,
    limitCode: kind === 1 ? 'LIMIT_CHUNK_BYTES' : 'LIMIT_METADATA_BYTES',
    expectedFieldOne: kind === 1 ? undefined : kind
  });
  return Object.freeze({
    update(part) { state.update(part); return this; },
    finish() { return new ObjectRef(kind, state.finishBytes(), registry); }
  });
}

/** Integrity-only hashing for an unassigned kind. It cannot mint ObjectRef. */
export function createOpaqueObjectHashWriter(kind, { maxBytes = MAX_METADATA_BYTES } = {}) {
  u16(kind, 'OBJECT_KIND_UNSUPPORTED');
  const state = new DomainHashWriter(OBJECT_DOMAIN, kind, {
    maximum: configuredHardLimit('metadata-payload-bytes', maxBytes)
  });
  return Object.freeze({
    update(part) { state.update(part); return this; },
    finish() { return new Digest(1, state.finishBytes()); }
  });
}

export function createLogicalRecordHashWriter(type, {
  registry = FROZEN_LOGICAL_TYPES, maxBytes = MAX_METADATA_BYTES
} = {}) {
  if (!isLogicalTypeAuthority(registry)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (!Number.isInteger(type) || type < 1 || type > 65535 || !assigned(registry, type)) {
    fail('LOGICAL_RECORD_TYPE_UNSUPPORTED', { layer: 2 });
  }
  const state = new DomainHashWriter(LOGICAL_DOMAIN, type, {
    maximum: configuredHardLimit('metadata-payload-bytes', maxBytes), expectedFieldOne: type
  });
  return Object.freeze({
    update(part) { state.update(part); return this; },
    finish() { return new Digest(1, state.finishBytes()); }
  });
}

export function createConflictHashWriter({ maxBytes = MAX_METADATA_BYTES } = {}) {
  const state = new DomainHashWriter(CONFLICT_DOMAIN, undefined, {
    maximum: configuredHardLimit('metadata-payload-bytes', maxBytes)
  });
  return Object.freeze({ update(part) { state.update(part); return this; }, finish() { return new Digest(1, state.finishBytes()); } });
}

export function createBundleTranscriptHashWriter({ maxBytes = MAX_BUNDLE_BYTES } = {}) {
  const state = new DomainHashWriter(BUNDLE_DOMAIN, undefined, {
    maximum: configuredHardLimit('bundle-sequence-bytes', maxBytes),
    limitCode: 'BUNDLE_BUDGET_EXCEEDED',
    limitStage: 'configured-resource-preflight'
  });
  return Object.freeze({ update(part) { state.update(part); return this; }, finish() { return new Digest(1, state.finishBytes()); } });
}

export async function hashByteIterable(iterable, writer = new Sha256Writer()) {
  for await (const chunk of iterable) writer.update(chunk);
  return writer.finish();
}

export function hashObject(kind, payload, options = {}) {
  const writer = createObjectHashWriter(kind, options);
  writer.update(payload);
  return writer.finish();
}

export function hashOpaqueObject(kind, payload, options = {}) {
  const writer = createOpaqueObjectHashWriter(kind, options);
  writer.update(payload);
  return writer.finish();
}

export function hashLogicalRecord(type, recordOrBytes, options = {}) {
  const payload = recordOrBytes instanceof Uint8Array ? recordOrBytes : encodeCanonical(recordOrBytes);
  const writer = createLogicalRecordHashWriter(type, options);
  writer.update(payload);
  return writer.finish();
}

export function hashConflictPreimage(preimageOrBytes) {
  const payload = preimageOrBytes instanceof Uint8Array ? preimageOrBytes : encodeCanonical(preimageOrBytes);
  const writer = createConflictHashWriter();
  writer.update(payload);
  return writer.finish();
}

export function hashBundleTranscript(itemBytes) {
  const writer = createBundleTranscriptHashWriter();
  for (const item of itemBytes) writer.update(item);
  return writer.finish();
}

export function verifyObjectId(reference, payload, options = {}) {
  const ref = reference instanceof ObjectRef ? reference : ObjectRef.fromMap(reference);
  const actual = hashObject(ref.kind, payload, options);
  if (!equalBytes(ref.digest, actual.digest)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
  return actual;
}

export function sha256Digest(value) {
  const writer = new Sha256Writer();
  writer.update(value);
  return writer.finish();
}
