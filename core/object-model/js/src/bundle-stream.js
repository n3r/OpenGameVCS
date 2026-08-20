import { fail } from './errors.js';
import { configuredHardLimit, hardLimitMaximum } from './hard-limits.js';
import { ResourceGuard } from './scale-util.js';
import { validationMode } from './validation-mode.js';
import { isUnicode15String } from './unicode-age.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const DEFAULTS = Object.freeze({
  maxSequenceBytes: hardLimitMaximum('bundle-sequence-bytes'),
  maxItemBytes: hardLimitMaximum('bundle-largest-item-bytes'),
  maxChunkBytes: hardLimitMaximum('chunk-payload-bytes'),
  maxMetadataBytes: hardLimitMaximum('metadata-payload-bytes'),
  maxValueBytes: hardLimitMaximum('generic-text-or-byte-value-bytes'),
  maxCaptureBytes: 67_108_864,
  maxContainerItems: hardLimitMaximum('manifest-chunks'),
  maxNesting: hardLimitMaximum('cbor-nesting-depth'),
  payloadChunkBytes: 65_536,
  maxItems: hardLimitMaximum('bundle-total-items')
});
const CONFIGURED_NAMES = Object.freeze({
  maxSequenceBytes: 'bundle-sequence-bytes',
  maxItemBytes: 'bundle-largest-item-bytes',
  maxChunkBytes: 'chunk-payload-bytes',
  maxMetadataBytes: 'metadata-payload-bytes',
  maxValueBytes: 'generic-text-or-byte-value-bytes',
  maxContainerItems: 'manifest-chunks',
  maxNesting: 'cbor-nesting-depth',
  maxItems: 'bundle-total-items'
});

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
}

function sourceOf(input) {
  if (input?.[Symbol.asyncIterator]) return input;
  if (input?.[Symbol.iterator] && !(input instanceof Uint8Array)) return input;
  return [asBytes(input)];
}

function compare(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function optionsOf(options) {
  validationMode(options.mode);
  const out = { ...DEFAULTS, ...options };
  for (const name of Object.keys(DEFAULTS)) {
    if (!Number.isSafeInteger(out[name]) || out[name] < (name === 'maxNesting' || name === 'payloadChunkBytes' ? 1 : 0)) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    const limitName = CONFIGURED_NAMES[name];
    const named = limitName ? configuredHardLimit(limitName, options.hardLimits?.[limitName]) : undefined;
    out[name] = limitName
      ? configuredHardLimit(limitName, options[name] ?? named)
      : Math.min(out[name], DEFAULTS[name]);
  }
  if (out.guard !== undefined && (typeof out.guard.wait !== 'function' ||
      typeof out.guard.cleanup !== 'function' || !(out.guard.signal instanceof AbortSignal))) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (out.guard === undefined && options.maxTimeMs !== undefined) {
    if (!Number.isSafeInteger(options.maxTimeMs) || options.maxTimeMs < 0) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    out.guard = new ResourceGuard({
      maxTimeMs: options.maxTimeMs,
      maxMemoryBytes: Number.MAX_SAFE_INTEGER
    });
  }
  return out;
}

class AsyncReader {
  #iterator;
  #current = new Uint8Array();
  #cursor = 0;
  #done = false;
  #captures = [];
  #captureBytes = 0;
  constructor(input, options, visitor) {
    this.#iterator = sourceOf(input)[Symbol.asyncIterator]?.() ?? (async function* (source) { yield* source; })(sourceOf(input))[Symbol.asyncIterator]();
    this.options = options;
    this.visitor = visitor;
    this.offset = 0;
    this.itemStart = 0;
  }
  async wait(callback) {
    if (this.options.guard) return this.options.guard.wait(callback);
    return callback(undefined);
  }
  async #fill() {
    while (this.#cursor === this.#current.length && !this.#done) {
      const next = this.options.guard
        ? await this.options.guard.wait(signal => this.#iterator.next({ signal }))
        : await this.#iterator.next();
      if (!next || typeof next !== 'object') fail('SCHEMA_FIELD_INVALID', {
        layer: 1, stage: 'configured-resource-preflight'
      });
      this.#done = next.done;
      if (!next.done) {
        this.#current = asBytes(next.value);
        this.#cursor = 0;
        if (this.visitor.onInputChunk) {
          await this.wait(signal => this.visitor.onInputChunk(this.#current, { signal }));
        }
      }
    }
    return !this.#done;
  }
  async take(count, callback) {
    if (!Number.isSafeInteger(count) || count < 0) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'canonical-framing'
    });
    if (count > this.options.maxSequenceBytes - this.offset) fail('BUNDLE_BUDGET_EXCEEDED', {
      layer: 1, stage: 'configured-resource-preflight', offset: this.offset
    });
    if (count > this.options.maxItemBytes - (this.offset - this.itemStart)) fail('BUNDLE_BUDGET_EXCEEDED', {
      layer: 1, stage: 'configured-resource-preflight', offset: this.offset
    });
    let remaining = count;
    while (remaining > 0) {
      if (!await this.#fill()) fail('CBOR_TRUNCATED', { layer: 1, offset: this.offset });
      const size = Math.min(remaining, this.#current.length - this.#cursor, this.options.payloadChunkBytes);
      const part = this.#current.subarray(this.#cursor, this.#cursor + size);
      this.#cursor += size;
      this.offset += size;
      remaining -= size;
      for (const capture of this.#captures) {
        if (part.length > capture.limit - capture.length) fail('LIMIT_SCRATCH', { layer: 1, offset: this.offset - size });
        const required = capture.length + part.length;
        if (required > capture.buffer.length) {
          const capacity = Math.min(capture.limit, Math.max(required, Math.max(1, capture.buffer.length * 2)));
          // The old and replacement buffers coexist while the replacement is
          // allocated and copied. Admit the replacement's complete capacity
          // before allocation, then release the old capacity after transfer.
          this.#reserveCapture(capacity);
          try {
            const old = capture.buffer;
            const grown = new Uint8Array(capacity);
            grown.set(old.subarray(0, capture.length));
            capture.buffer = grown;
            this.#releaseCapture(old.length);
          } catch (error) {
            this.#releaseCapture(capacity);
            throw error;
          }
        }
        capture.buffer.set(part, capture.length);
        capture.length += part.length;
      }
      if (this.visitor.onBytes) {
        await this.wait(signal => this.visitor.onBytes(part, { signal }));
      }
      if (callback) await this.wait(signal => callback(part, { signal }));
    }
  }
  #reserveCapture(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 ||
        bytes > this.options.maxCaptureBytes - this.#captureBytes) {
      fail('LIMIT_MEMORY', { layer: 1, offset: this.offset });
    }
    this.#captureBytes += bytes;
  }
  #releaseCapture(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.#captureBytes) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing', offset: this.offset });
    }
    this.#captureBytes -= bytes;
  }
  async byte() {
    let value;
    await this.take(1, part => { value = part[0]; });
    return value;
  }
  capture(limit = this.options.maxValueBytes + 16) {
    const capacity = Math.min(64, limit);
    this.#reserveCapture(capacity);
    let buffer;
    try { buffer = new Uint8Array(capacity); }
    catch (error) { this.#releaseCapture(capacity); throw error; }
    const state = { buffer, length: 0, limit };
    let active = true;
    this.#captures.push(state);
    const detach = () => {
      if (!active) return false;
      if (this.#captures.at(-1) !== state) fail('SCHEMA_FIELD_INVALID', {
        layer: 1, stage: 'canonical-framing'
      });
      this.#captures.pop();
      active = false;
      return true;
    };
    return Object.freeze({
      abort: () => {
        if (!detach()) return;
        this.#releaseCapture(state.buffer.length);
      },
      finish: () => {
        if (!detach()) fail('SCHEMA_FIELD_INVALID', {
          layer: 1, stage: 'canonical-framing'
        });
        // Transfer the already-admitted buffer into the retained key instead
        // of copying it. Its full capacity remains charged until release.
        const bytes = state.buffer.subarray(0, state.length);
        let retained = true;
        return Object.freeze({
          bytes,
          release: () => {
            if (!retained) return;
            retained = false;
            this.#releaseCapture(state.buffer.length);
          }
        });
      }
    });
  }
  async eof() { return !(await this.#fill()); }
  async close() {
    if (this.#done || typeof this.#iterator.return !== 'function') return;
    if (!this.options.guard) { await this.#iterator.return(); return; }
    if (this.options.guard.signal.aborted) {
      this.options.guard.cleanup(signal => this.#iterator.return({ signal }));
      return;
    }
    await this.options.guard.wait(signal => this.#iterator.return({ signal }));
  }
}

async function head(reader) {
  const start = reader.offset;
  const initial = await reader.byte();
  const major = initial >>> 5;
  const ai = initial & 31;
  if (ai === 31 || major === 6) fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
  if (major === 7) {
    if (ai === 20 || ai === 21) return { major, value: ai === 21, start };
    fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
  }
  let value;
  if (ai < 24) value = BigInt(ai);
  else {
    const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
    if (size === 0) fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
    const body = new Uint8Array(size);
    let cursor = 0;
    await reader.take(size, part => { body.set(part, cursor); cursor += part.length; });
    value = 0n;
    for (const byte of body) value = (value << 8n) | BigInt(byte);
    if ((size === 1 && value < 24n) || (size === 2 && value <= 0xffn) ||
        (size === 4 && value <= 0xffffn) || (size === 8 && value <= 0xffff_ffffn)) {
      fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
    }
  }
  if (major === 1 && value > 0x7fff_ffff_ffff_ffffn) fail('CBOR_NON_CANONICAL', { layer: 1, offset: start });
  return { major, value, start };
}

function count(value, maximum, start, code = 'LIMIT_COUNT') {
  if (value > BigInt(Math.min(maximum, Number.MAX_SAFE_INTEGER))) {
    const details = { layer: 1, offset: start };
    if (code === 'SCHEMA_FIELD_INVALID' || code === 'LIMIT_COUNT') details.stage = 'canonical-framing';
    fail(code, details);
  }
  return Number(value);
}

async function unsigned(reader, expected) {
  const item = await head(reader);
  if (item.major !== 0) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: item.start
  });
  const value = count(item.value, Number.MAX_SAFE_INTEGER, item.start, 'SCHEMA_FIELD_INVALID');
  if (expected !== undefined && value !== expected) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: item.start
  });
  return value;
}

async function scanValue(reader, depth = 1) {
  const item = await head(reader);
  if (item.major === 0 || item.major === 1 || item.major === 7) return;
  if (item.major === 2 || item.major === 3) {
    const length = count(item.value, reader.options.maxValueBytes, item.start, 'LIMIT_VALUE_BYTES');
    if (item.major === 2) { await reader.take(length); return; }
    const body = new Uint8Array(length);
    let offset = 0;
    await reader.take(length, part => { body.set(part, offset); offset += part.length; });
    let text;
    try { text = decoder.decode(body); } catch (cause) { fail('CBOR_NON_CANONICAL', { layer: 1, offset: item.start, cause }); }
    if (encoder.encode(text).length !== body.length || !isUnicode15String(text) ||
        text.normalize('NFC') !== text) fail('CBOR_NON_CANONICAL', { layer: 1, offset: item.start });
    return;
  }
  if (depth > reader.options.maxNesting) fail('LIMIT_NESTING', { layer: 1, offset: item.start });
  const length = count(item.value, reader.options.maxContainerItems, item.start);
  if (item.major === 4) {
    for (let index = 0; index < length; index++) await scanValue(reader, depth + 1);
    return;
  }
  if (item.major === 5) {
    let previous;
    try {
      for (let index = 0; index < length; index++) {
        const capture = reader.capture();
        let current;
        try {
          await scanValue(reader, depth + 1);
          current = capture.finish();
        } catch (error) {
          capture.abort();
          throw error;
        }
        if (previous && compare(previous.bytes, current.bytes) >= 0) {
          current.release();
          fail('CBOR_NON_CANONICAL', { layer: 1, offset: item.start });
        }
        previous?.release();
        previous = current;
        await scanValue(reader, depth + 1);
      }
    } finally {
      previous?.release();
    }
    return;
  }
  fail('CBOR_NON_CANONICAL', { layer: 1, offset: item.start });
}

async function objectRef(reader) {
  const map = await head(reader);
  if (map.major !== 5 || map.value !== 4n) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: map.start
  });
  // The assignment values participate in declared identity, which follows
  // sequence ordering.  The streaming framing pass therefore consumes them
  // opaquely and lets the verifier's identity pass reject unsupported values.
  await unsigned(reader, 0); await unsigned(reader);
  await unsigned(reader, 1); const kind = await unsigned(reader);
  if (kind < 1 || kind > 65_535) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing'
  });
  await unsigned(reader, 2); await unsigned(reader);
  await unsigned(reader, 3);
  const digest = await head(reader);
  if (digest.major !== 2 || digest.value !== 32n) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: digest.start
  });
  await reader.take(32);
  return kind;
}

async function bundleItem(reader, visitor, index) {
  reader.itemStart = reader.offset;
  const start = reader.offset;
  const map = await head(reader);
  if (map.major !== 5) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: start });
  const fields = count(map.value, 7, map.start);
  if (fields < 2) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: start });
  await unsigned(reader, 0); await unsigned(reader, 1);
  await unsigned(reader, 1); const type = await unsigned(reader);
  const expectedFields = type === 1 || type === 5 ? 7 : type === 2 || type === 3 ? 5 : type === 4 ? 6 : 0;
  if (!expectedFields || fields !== expectedFields) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: start });
  if (visitor.onItemStart) {
    await reader.wait(signal => visitor.onItemStart({ index, type, offset: start }, { signal }));
  }
  let objectKind;
  for (let key = 2; key < fields; key++) {
    await unsigned(reader, key);
    if (type === 2 && key === 3) objectKind = await objectRef(reader);
    else if (type === 2 && key === 4) {
      const payload = await head(reader);
      if (payload.major !== 2) fail('SCHEMA_FIELD_INVALID', {
        layer: 1, stage: 'canonical-framing', offset: payload.start
      });
      const maximum = objectKind === 1 ? reader.options.maxChunkBytes : reader.options.maxMetadataBytes;
      const length = count(payload.value, maximum, payload.start, objectKind === 1 ? 'LIMIT_CHUNK_BYTES' : 'LIMIT_METADATA_BYTES');
      if (visitor.onObjectPayloadStart) {
        await reader.wait(signal => visitor.onObjectPayloadStart(
          { index, kind: objectKind, length, offset: payload.start }, { signal }
        ));
      }
      await reader.take(length, (part, { signal }) => visitor.onObjectPayloadChunk?.(
        part, { index, kind: objectKind, signal }
      ));
      if (visitor.onObjectPayloadEnd) {
        await reader.wait(signal => visitor.onObjectPayloadEnd(
          { index, kind: objectKind, length }, { signal }
        ));
      }
    } else await scanValue(reader, 2);
  }
  const bytes = reader.offset - start;
  if (visitor.onItemEnd) {
    await reader.wait(signal => visitor.onItemEnd({ index, type, offset: start, bytes }, { signal }));
  }
  return { type, bytes };
}

/**
 * Visits a logical-bundle CBOR sequence without retaining decoded items or
 * payload slices. `input` may be bytes, an Iterable, or an AsyncIterable.
 * `onInputChunk` observes each caller-supplied chunk once for transport
 * spooling; `onBytes` observes exact parser-consumed slices. Pass `maxTimeMs`
 * to deadline-race source and visitor promises with one shared signal. Without
 * it a standalone visit has no elapsed-time ceiling; bounded verifiers inject
 * their own shared guard.
 */
export async function visitLogicalBundle(input, visitor = {}, options = {}) {
  const effective = optionsOf(options);
  const reader = new AsyncReader(input, effective, visitor);
  let items = 0;
  let result;
  let failure;
  try {
    while (!await reader.eof()) {
      if (items >= effective.maxItems) fail('BUNDLE_BUDGET_EXCEEDED', {
        layer: 1, stage: 'configured-resource-preflight', offset: reader.offset
      });
      await bundleItem(reader, visitor, items++);
    }
    if (visitor.onEnd) {
      await reader.wait(signal => visitor.onEnd({ items, bytes: reader.offset }, { signal }));
    }
    result = { items, bytes: reader.offset };
  } catch (error) {
    failure = error;
  }
  try { await reader.close(); } catch (error) { failure ??= error; }
  if (failure) throw failure;
  return result;
}
