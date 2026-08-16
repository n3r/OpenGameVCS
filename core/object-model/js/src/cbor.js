import { createHash } from 'node:crypto';

import { fail } from './errors.js';
import { configuredHardLimit, hardLimitMaximum } from './hard-limits.js';
import { ResourceGuard, writeFully } from './scale-util.js';

const U64_MAX = 0xffff_ffff_ffff_ffffn;
const I64_MIN = -0x8000_0000_0000_0000n;
const DEFAULTS = Object.freeze({
  maxBytes: hardLimitMaximum('metadata-payload-bytes'),
  maxDepth: hardLimitMaximum('cbor-nesting-depth'),
  maxValueBytes: hardLimitMaximum('generic-text-or-byte-value-bytes'),
  maxWorkingBytes: 67_108_864,
  // Content manifests may contain 1,048,576 chunk parts. A smaller generic
  // default would reject a value that is valid at the format's hard ceiling.
  maxContainerItems: hardLimitMaximum('manifest-chunks')
});
const HARD_LIMITS = Object.freeze({
  // The widest standalone item is a logical-bundle object wrapper. Metadata
  // scanners apply their smaller 512 MiB / 16 MiB contextual ceilings.
  maxBytes: hardLimitMaximum('bundle-largest-item-bytes'),
  maxDepth: hardLimitMaximum('cbor-nesting-depth'),
  maxValueBytes: hardLimitMaximum('metadata-payload-bytes'),
  maxContainerItems: hardLimitMaximum('manifest-chunks'),
  maxWorkingBytes: 67_108_864
});
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function bytes(value, stage = 'canonical-framing') {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail('SCHEMA_FIELD_INVALID', { layer: 1, stage });
}

function cmp(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function asJsInt(n) {
  return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
}

class Reader {
  constructor(input, options, { permitInputAfterItem = false } = {}) {
    this.input = bytes(input, 'configured-resource-preflight');
    this.pos = 0;
    this.retainedBytes = 0;
    this.options = { ...DEFAULTS, ...options };
    if (!Number.isInteger(this.options.maxDepth) || this.options.maxDepth < 1 ||
        !Number.isSafeInteger(this.options.maxBytes) || this.options.maxBytes < 0 ||
        !Number.isSafeInteger(this.options.maxValueBytes) || this.options.maxValueBytes < 0 ||
        !Number.isSafeInteger(this.options.maxWorkingBytes) || this.options.maxWorkingBytes < 0 ||
        !Number.isSafeInteger(this.options.maxContainerItems) || this.options.maxContainerItems < 0) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    this.options.maxDepth = configuredHardLimit('cbor-nesting-depth', this.options.maxDepth);
    this.options.maxBytes = Math.min(this.options.maxBytes, HARD_LIMITS.maxBytes);
    this.options.maxValueBytes = Math.min(this.options.maxValueBytes, HARD_LIMITS.maxValueBytes);
    this.options.maxWorkingBytes = Math.min(this.options.maxWorkingBytes, HARD_LIMITS.maxWorkingBytes);
    this.options.maxContainerItems = Math.min(this.options.maxContainerItems, HARD_LIMITS.maxContainerItems);
    if (!permitInputAfterItem && this.input.length > this.options.maxBytes) {
      fail('LIMIT_METADATA_BYTES', { layer: 1, offset: 0 });
    }
  }

  retain(count, offset) {
    const next = this.retainedBytes + count;
    if (!Number.isSafeInteger(next) || next > this.options.maxWorkingBytes) {
      fail('LIMIT_MEMORY', { layer: 1, offset });
    }
    this.retainedBytes = next;
  }

  take(count) {
    // Enforce the configured item boundary before slicing or copying. This is
    // essential for sequence readers, whose backing input may be much larger
    // than one item.
    // Physical EOF has precedence when the supplied input itself ends before
    // the requested bytes. A long-enough input that crosses the configured
    // item budget still selects LIMIT_METADATA_BYTES.
    if (this.pos + count > this.input.length) fail('CBOR_TRUNCATED', { layer: 1, offset: this.pos });
    if (count > this.options.maxBytes - this.pos) {
      fail('LIMIT_METADATA_BYTES', { layer: 1, offset: this.pos });
    }
    const out = this.input.subarray(this.pos, this.pos + count);
    this.pos += count;
    return out;
  }

  argument(ai, start) {
    if (ai < 24) return BigInt(ai);
    let size;
    if (ai === 24) size = 1;
    else if (ai === 25) size = 2;
    else if (ai === 26) size = 4;
    else if (ai === 27) size = 8;
    else fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
    const raw = this.take(size);
    let n = 0n;
    for (const b of raw) n = (n << 8n) | BigInt(b);
    if ((size === 1 && n < 24n) || (size === 2 && n <= 0xffn) ||
        (size === 4 && n <= 0xffffn) || (size === 8 && n <= 0xffff_ffffn)) {
      fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
    }
    return n;
  }

  length(n, start, code) {
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) fail(code, {
      layer: 1, stage: 'canonical-framing', offset: start
    });
    return Number(n);
  }

  count(n, start) {
    const count = this.length(n, start, 'LIMIT_COUNT');
    if (count > this.options.maxContainerItems) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight', offset: start
    });
    return count;
  }

  item(depth = 1) {
    const start = this.pos;
    const first = this.take(1)[0];
    const major = first >>> 5;
    const ai = first & 31;
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
    }
    if (major === 6 || ai === 31) fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
    const n = this.argument(ai, start);
    if (major === 0) return asJsInt(n);
    if (major === 1) {
      const signed = -1n - n;
      if (signed < I64_MIN) fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
      return signed >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(signed) : signed;
    }
    if (major === 2 || major === 3) {
      const length = this.length(n, start, 'LIMIT_VALUE_BYTES');
      if (length > this.options.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1, offset: start });
      const raw = this.take(length);
      if (major === 2) {
        this.retain(length + 32, start);
        return raw.slice();
      }
      this.retain(length * 2 + 32, start);
      let text;
      try { text = decoder.decode(raw); } catch (cause) { fail('CBOR_NON_CANONICAL', { layer: 1, offset: start, cause }); }
      if (encoder.encode(text).length !== raw.length || text.normalize('NFC') !== text) {
        fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
      }
      return text;
    }
    if (major === 4) {
      if (depth > this.options.maxDepth) fail('LIMIT_NESTING', { layer: 1, offset: start });
      const count = this.count(n, start);
      this.retain(count * 64, start);
      const out = new Array(count);
      for (let i = 0; i < count; i++) out[i] = this.item(depth + 1);
      return out;
    }
    if (major === 5) {
      if (depth > this.options.maxDepth) fail('LIMIT_NESTING', { layer: 1, offset: start });
      const count = this.count(n, start);
      this.retain(count * 128, start);
      const out = new Map();
      let previous;
      for (let i = 0; i < count; i++) {
        const keyStart = this.pos;
        const key = this.item(depth + 1);
        const encodedKey = this.input.slice(keyStart, this.pos);
        if (previous && cmp(previous, encodedKey) >= 0) fail('CBOR_NON_CANONICAL', { layer: 1, offset: keyStart });
        previous = encodedKey;
        out.set(key, this.item(depth + 1));
      }
      return out;
    }
    fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
  }
}

export function decodeCanonical(input, options = {}) {
  const reader = new Reader(input, options);
  const value = reader.item();
  if (reader.pos !== reader.input.length) fail('CBOR_TRAILING_BYTES', { layer: 1, offset: reader.pos });
  return value;
}

export function decodeFirst(input, options = {}) {
  const requestedMax = options.maxBytes ?? DEFAULTS.maxBytes;
  if (!Number.isSafeInteger(requestedMax) || requestedMax < 0) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  const reader = new Reader(input, { ...options, maxBytes: requestedMax }, { permitInputAfterItem: true });
  const value = reader.item();
  return { value, bytesRead: reader.pos, retainedBytes: reader.retainedBytes };
}

export function decodeSequence(input, options = {}) {
  const source = bytes(input, 'configured-resource-preflight');
  const values = [];
  const slices = [];
  const maxWorkingBytes = options.maxWorkingBytes ?? DEFAULTS.maxWorkingBytes;
  if (!Number.isSafeInteger(maxWorkingBytes) || maxWorkingBytes < 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  let retainedBytes = 0;
  let offset = 0;
  while (offset < source.length) {
    // Values and canonical item slices stay reachable until this function
    // returns. Charge them to one aggregate budget instead of resetting the
    // Reader's working counter for every sequence item.
    const sequenceRecordBytes = 64;
    if (retainedBytes + sequenceRecordBytes > maxWorkingBytes) {
      fail('LIMIT_MEMORY', { layer: 1, offset });
    }
    const remaining = maxWorkingBytes - retainedBytes - sequenceRecordBytes;
    const decoded = decodeFirst(source.subarray(offset), {
      ...options,
      maxBytes: Math.min(options.maxBytes ?? source.length, source.length - offset),
      maxWorkingBytes: remaining
    });
    const nextRetained = retainedBytes + sequenceRecordBytes + decoded.retainedBytes + decoded.bytesRead;
    if (!Number.isSafeInteger(nextRetained) || nextRetained > maxWorkingBytes) {
      fail('LIMIT_MEMORY', { layer: 1, offset });
    }
    const { value, bytesRead } = decoded;
    values.push(value);
    slices.push(source.slice(offset, offset + bytesRead));
    retainedBytes = nextRetained;
    offset += bytesRead;
  }
  return { values, slices, retainedBytes };
}

function header(major, n) {
  n = typeof n === 'bigint' ? n : BigInt(n);
  if (n < 0n || n > U64_MAX) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing'
  });
  if (n < 24n) return Uint8Array.of((major << 5) | Number(n));
  let size, ai;
  if (n <= 0xffn) [size, ai] = [1, 24];
  else if (n <= 0xffffn) [size, ai] = [2, 25];
  else if (n <= 0xffff_ffffn) [size, ai] = [4, 26];
  else [size, ai] = [8, 27];
  const out = new Uint8Array(1 + size);
  out[0] = (major << 5) | ai;
  for (let i = size; i > 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

function concat(parts) {
  const length = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

function effectiveLimits(options = {}) {
  const effective = { ...DEFAULTS, ...options };
  if (!Number.isSafeInteger(effective.maxBytes) || effective.maxBytes < 0 ||
      !Number.isInteger(effective.maxDepth) || effective.maxDepth < 1 ||
      !Number.isSafeInteger(effective.maxValueBytes) || effective.maxValueBytes < 0 ||
      !Number.isSafeInteger(effective.maxWorkingBytes) || effective.maxWorkingBytes < 0 ||
      !Number.isSafeInteger(effective.maxContainerItems) || effective.maxContainerItems < 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  effective.maxDepth = configuredHardLimit('cbor-nesting-depth', effective.maxDepth);
  effective.maxBytes = Math.min(effective.maxBytes, HARD_LIMITS.maxBytes);
  effective.maxValueBytes = Math.min(effective.maxValueBytes, HARD_LIMITS.maxValueBytes);
  effective.maxWorkingBytes = Math.min(effective.maxWorkingBytes, HARD_LIMITS.maxWorkingBytes);
  effective.maxContainerItems = Math.min(effective.maxContainerItems, HARD_LIMITS.maxContainerItems);
  return effective;
}

function* splitBody(body, chunkBytes) {
  for (let offset = 0; offset < body.length; offset += chunkBytes) {
    yield body.subarray(offset, Math.min(offset + chunkBytes, body.length));
  }
}

const MAP_KEY_RECORD_BYTES = 64;

function headerLength(n) { return header(0, n).length; }

function checkedLength(left, right, options) {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result > options.maxBytes) {
    fail('LIMIT_METADATA_BYTES', { layer: 1 });
  }
  return result;
}

function encodedLength(value, depth, options) {
  let size;
  if (value === false || value === true) size = 1;
  else if (typeof value === 'number' || typeof value === 'bigint') {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'canonical-framing'
    });
    const n = BigInt(value);
    if (n < I64_MIN || n > U64_MAX) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'canonical-framing'
    });
    size = headerLength(n >= 0n ? n : -1n - n);
  } else if (typeof value === 'string') {
    if (value.normalize('NFC') !== value) fail('CBOR_NON_CANONICAL', { layer: 1 });
    const body = encoder.encode(value);
    if (decoder.decode(body) !== value) fail('CBOR_NON_CANONICAL', { layer: 1 });
    if (body.length > options.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1 });
    size = checkedLength(headerLength(body.length), body.length, options);
  } else if (value instanceof Uint8Array || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    const body = bytes(value);
    if (body.length > options.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1 });
    size = checkedLength(headerLength(body.length), body.length, options);
  } else if (Array.isArray(value)) {
    if (depth > options.maxDepth) fail('LIMIT_NESTING', { layer: 1 });
    if (value.length > options.maxContainerItems) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    size = headerLength(value.length);
    for (const child of value) size = checkedLength(size, encodedLength(child, depth + 1, options), options);
  } else if (value instanceof Map) {
    if (depth > options.maxDepth) fail('LIMIT_NESTING', { layer: 1 });
    if (value.size > options.maxContainerItems) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    size = headerLength(value.size);
    for (const [key, child] of value) {
      size = checkedLength(size, encodedLength(key, depth + 1, options), options);
      size = checkedLength(size, encodedLength(child, depth + 1, options), options);
    }
  } else fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  if (size > options.maxBytes) fail('LIMIT_METADATA_BYTES', { layer: 1 });
  return size;
}

function reserveWorking(working, bytes) {
  const next = working.used + bytes;
  if (!Number.isSafeInteger(next) || next > working.maximum) fail('LIMIT_MEMORY', { layer: 1 });
  working.used = next;
}

function orderedMapPairs(value, depth, options, working) {
  const recordBytes = value.size * MAP_KEY_RECORD_BYTES;
  if (!Number.isSafeInteger(recordBytes)) fail('LIMIT_MEMORY', { layer: 1 });
  let workingBytes = recordBytes;
  const keyLengths = [];
  for (const key of value.keys()) {
    const keyLength = encodedLength(key, depth + 1, options);
    keyLengths.push(keyLength);
    workingBytes += keyLength;
    if (!Number.isSafeInteger(workingBytes)) fail('LIMIT_MEMORY', { layer: 1 });
  }
  reserveWorking(working, workingBytes);
  const pairs = [];
  try {
    let index = 0;
    for (const [key, child] of value) {
      const encoded = encodeItem(key, depth + 1, options, working);
      if (encoded.length !== keyLengths[index++]) fail('SCHEMA_FIELD_INVALID', {
        layer: 1, stage: 'canonical-framing'
      });
      pairs.push([encoded, child]);
    }
    pairs.sort((a, b) => cmp(a[0], b[0]));
    for (let i = 1; i < pairs.length; i++) {
      if (cmp(pairs[i - 1][0], pairs[i][0]) === 0) fail('CBOR_NON_CANONICAL', { layer: 1 });
    }
    return {
      pairs,
      release() { working.used -= workingBytes; }
    };
  } catch (error) {
    working.used -= workingBytes;
    throw error;
  }
}

function preflightEncoding(value, options) {
  encodedLength(value, 1, options);
  const working = { used: 0, maximum: options.maxWorkingBytes };
  function validateMaps(current, depth) {
    if (Array.isArray(current)) {
      for (const child of current) validateMaps(child, depth + 1);
    } else if (current instanceof Map) {
      const prepared = orderedMapPairs(current, depth, options, working);
      try {
        for (const [key, child] of current) {
          validateMaps(key, depth + 1);
          validateMaps(child, depth + 1);
        }
      } finally {
        prepared.release();
      }
    }
  }
  validateMaps(value, 1);
}

/**
 * Incrementally emits deterministic-CBOR. The only encoded sub-values retained
 * by the implementation are map keys, which are required for RFC 8949 key
 * ordering. Values and string bodies are forwarded in bounded chunks.
 */
function* emitCanonicalChunks(value, effective, chunkBytes) {
  const working = { used: 0, maximum: effective.maxWorkingBytes };
  let emitted = 0;
  function* emit(part) {
    if (part.length === 0) return;
    emitted += part.length;
    if (emitted > effective.maxBytes) fail('LIMIT_METADATA_BYTES', { layer: 1 });
    yield part;
  }
  function* item(current, depth) {
    if (current === false) { yield* emit(Uint8Array.of(0xf4)); return; }
    if (current === true) { yield* emit(Uint8Array.of(0xf5)); return; }
    if (typeof current === 'number' || typeof current === 'bigint') {
      if (typeof current === 'number' && !Number.isSafeInteger(current)) fail('SCHEMA_FIELD_INVALID', {
        layer: 1, stage: 'canonical-framing'
      });
      const n = BigInt(current);
      if (n >= 0n) yield* emit(header(0, n));
      else {
        if (n < I64_MIN) fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
        yield* emit(header(1, -1n - n));
      }
      return;
    }
    if (typeof current === 'string') {
      if (current.normalize('NFC') !== current) fail('CBOR_NON_CANONICAL', { layer: 1 });
      const body = encoder.encode(current);
      if (decoder.decode(body) !== current) fail('CBOR_NON_CANONICAL', { layer: 1 });
      if (body.length > effective.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1 });
      yield* emit(header(3, body.length));
      for (const part of splitBody(body, chunkBytes)) yield* emit(part);
      return;
    }
    if (current instanceof Uint8Array || ArrayBuffer.isView(current) || current instanceof ArrayBuffer) {
      const body = bytes(current);
      if (body.length > effective.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1 });
      yield* emit(header(2, body.length));
      for (const part of splitBody(body, chunkBytes)) yield* emit(part);
      return;
    }
    if (Array.isArray(current)) {
      if (depth > effective.maxDepth) fail('LIMIT_NESTING', { layer: 1 });
      if (current.length > effective.maxContainerItems) fail('LIMIT_COUNT', {
        layer: 1, stage: 'configured-resource-preflight'
      });
      yield* emit(header(4, current.length));
      for (const child of current) yield* item(child, depth + 1);
      return;
    }
    if (current instanceof Map) {
      if (depth > effective.maxDepth) fail('LIMIT_NESTING', { layer: 1 });
      if (current.size > effective.maxContainerItems) fail('LIMIT_COUNT', {
        layer: 1, stage: 'configured-resource-preflight'
      });
      // Values are deliberately not encoded here. Canonical maps need only
      // their encoded keys resident for sorting and duplicate detection.
      const prepared = orderedMapPairs(current, depth, effective, working);
      try {
        yield* emit(header(5, prepared.pairs.length));
        for (const [key, child] of prepared.pairs) {
          yield* emit(key);
          yield* item(child, depth + 1);
        }
      } finally {
        prepared.release();
      }
      return;
    }
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  yield* item(value, 1);
}

/**
 * Incrementally emit deterministic CBOR from a caller-owned value. A bounded
 * transcript pass precedes emission, and the emitted pass is checked against
 * it before successful iterator completion. This detects container or byte
 * mutation between yielded chunks without retaining the encoded value.
 */
export function* encodeCanonicalChunks(value, options = {}) {
  const effective = effectiveLimits(options);
  const chunkBytes = options.chunkBytes ?? 65_536;
  if (!Number.isSafeInteger(chunkBytes) || chunkBytes < 1) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  // Establish every deterministic format/size/key-order failure before the
  // first chunk reaches a caller-owned sink.
  preflightEncoding(value, effective);
  const expected = createHash('sha256');
  let expectedBytes = 0;
  for (const chunk of emitCanonicalChunks(value, effective, chunkBytes)) {
    expected.update(chunk);
    expectedBytes += chunk.length;
  }
  const expectedDigest = expected.digest();
  const actual = createHash('sha256');
  let actualBytes = 0;
  for (const liveChunk of emitCanonicalChunks(value, effective, chunkBytes)) {
    // Never expose a view into a caller-owned byte string across a yield/await.
    const chunk = liveChunk.slice();
    actual.update(chunk);
    actualBytes += chunk.length;
    yield chunk;
  }
  if (actualBytes !== expectedBytes || !actual.digest().equals(expectedDigest)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
}

/** Write deterministic-CBOR to a function, Node-style writer, or Web writer. */
export async function writeCanonical(value, sink, options = {}) {
  const guard = new ResourceGuard({
    maxTimeMs: options.maxTimeMs,
    maxMemoryBytes: options.maxWorkingBytes ?? DEFAULTS.maxWorkingBytes
  });
  guard.time();
  let webWriter;
  if (typeof sink !== 'function' && typeof sink?.write !== 'function' && typeof sink?.getWriter === 'function') {
    webWriter = sink.getWriter();
  }
  if (typeof sink !== 'function' && typeof sink?.write !== 'function' && !webWriter) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  let bytesWritten = 0;
  try {
    for (const chunk of encodeCanonicalChunks(value, options)) {
      guard.time();
      if (webWriter) {
        await guard.wait(() => webWriter.ready);
        await guard.wait(() => webWriter.write(chunk));
      } else {
        await writeFully(sink, chunk, { guard });
      }
      bytesWritten += chunk.length;
    }
  } catch (error) {
    if (webWriter && guard.signal.aborted && typeof webWriter.abort === 'function') {
      Promise.resolve().then(() => webWriter.abort(error)).catch(() => {});
    }
    throw error;
  } finally {
    webWriter?.releaseLock();
  }
  return bytesWritten;
}

function encodeItem(value, depth, options, working) {
  if (value === false) return Uint8Array.of(0xf4);
  if (value === true) return Uint8Array.of(0xf5);
  if (typeof value === 'number' || typeof value === 'bigint') {
    if (typeof value === 'number' && (!Number.isSafeInteger(value))) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'canonical-framing'
    });
    const n = BigInt(value);
    if (n >= 0n) return header(0, n);
    if (n < I64_MIN) fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    return header(1, -1n - n);
  }
  if (typeof value === 'string') {
    if (value.normalize('NFC') !== value) fail('CBOR_NON_CANONICAL', { layer: 1 });
    const body = encoder.encode(value);
    if (decoder.decode(body) !== value) fail('CBOR_NON_CANONICAL', { layer: 1 });
    if (body.length > options.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1 });
    return concat([header(3, body.length), body]);
  }
  if (value instanceof Uint8Array || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    const body = bytes(value);
    if (body.length > options.maxValueBytes) fail('LIMIT_VALUE_BYTES', { layer: 1 });
    return concat([header(2, body.length), body]);
  }
  if (Array.isArray(value)) {
    if (depth > options.maxDepth) fail('LIMIT_NESTING', { layer: 1 });
    if (value.length > options.maxContainerItems) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    const overhead = value.length * 16;
    if (!Number.isSafeInteger(overhead)) fail('LIMIT_MEMORY', { layer: 1 });
    reserveWorking(working, overhead);
    try {
      return concat([header(4, value.length), ...value.map(v => encodeItem(v, depth + 1, options, working))]);
    } finally {
      working.used -= overhead;
    }
  }
  if (value instanceof Map) {
    if (depth > options.maxDepth) fail('LIMIT_NESTING', { layer: 1 });
    if (value.size > options.maxContainerItems) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    const prepared = orderedMapPairs(value, depth, options, working);
    try {
      const pairs = prepared.pairs.map(([key, item]) => [key, encodeItem(item, depth + 1, options, working)]);
      return concat([header(5, pairs.length), ...pairs.flat()]);
    } finally {
      prepared.release();
    }
  }
  fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
}

export function encodeCanonical(value, options = {}) {
  return concat([...encodeCanonicalChunks(value, options)]);
}

export function compareCanonicalBytes(a, b) { return cmp(a, b); }
