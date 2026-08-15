import { createHash } from 'node:crypto';

const BLOCK_BYTES = 32;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT64_RANGE = 1n << 64n;
const MAX_DERIVATION_BYTES = 1024 * 1024 * 1024;

/**
 * Derive deterministic bytes using counter-mode SHA-256.
 *
 * Every preimage is length-delimited and domain-separated. `offset` permits
 * generation/resume at arbitrary byte boundaries without consuming earlier
 * output. The result is independent of wall clock, locale, OS randomness and
 * call ordering.
 */
export function deriveBytes(seed, stream, length, offset = 0) {
  const seedBytes = inputBytes(seed, 'seed');
  const streamBytes = inputBytes(stream, 'stream');
  assertSafeNonNegativeInteger(length, 'length');
  assertSafeNonNegativeInteger(offset, 'offset');
  if (length > MAX_DERIVATION_BYTES) {
    throw new RangeError(`length exceeds the ${MAX_DERIVATION_BYTES}-byte per-call bound`);
  }
  if (offset + length > Number.MAX_SAFE_INTEGER) {
    throw new RangeError('offset + length exceeds the safe integer range');
  }

  const output = Buffer.allocUnsafe(length);
  let written = 0;
  let position = offset;
  while (written < length) {
    const counter = BigInt(Math.floor(position / BLOCK_BYTES));
    const withinBlock = position % BLOCK_BYTES;
    const block = deriveBlock(seedBytes, streamBytes, counter);
    const available = Math.min(BLOCK_BYTES - withinBlock, length - written);
    block.copy(output, written, withinBlock, withinBlock + available);
    written += available;
    position += available;
  }
  return output;
}

/** Derive an unsigned 64-bit integer from the indexed block prefix. */
export function deriveUint64(seed, stream, index = 0) {
  assertSafeNonNegativeInteger(index, 'index');
  if (index > Math.floor((Number.MAX_SAFE_INTEGER - 7) / 8)) {
    throw new RangeError('index is too large to address an exact uint64 draw');
  }
  const bytes = deriveBytes(seed, stream, 8, index * 8);
  return bytes.readBigUInt64BE(0);
}

/**
 * Return an unbiased deterministic integer in [0, maxExclusive).
 * `index` identifies a logical draw, so callers need not share mutable state.
 */
export function deterministicInt(seed, stream, maxExclusive, index = 0) {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive <= 0) {
    throw new RangeError('maxExclusive must be a positive safe integer');
  }
  assertSafeNonNegativeInteger(index, 'index');

  const range = BigInt(maxExclusive);
  const acceptedLimit = UINT64_RANGE - (UINT64_RANGE % range);
  for (let attempt = 0; attempt < 1024; attempt += 1) {
    const candidate = deriveUint64(seed, `${stream}\u0000int-attempt:${attempt}`, index);
    if (candidate < acceptedLimit) return Number(candidate % range);
  }
  throw new Error('Deterministic integer rejection limit exceeded');
}

/** Stateless counter-addressable deterministic stream. */
export class DeterministicPrng {
  constructor(seed, stream = 'default') {
    inputBytes(seed, 'seed');
    inputBytes(stream, 'stream');
    this.seed = seed;
    this.stream = stream;
    Object.freeze(this);
  }

  bytesAt(offset, length) {
    return deriveBytes(this.seed, this.stream, length, offset);
  }

  uint64At(index) {
    return deriveUint64(this.seed, this.stream, index);
  }

  intAt(index, maxExclusive) {
    return deterministicInt(this.seed, this.stream, maxExclusive, index);
  }

  derive(label) {
    const labelBytes = inputBytes(label, 'label');
    const streamBytes = inputBytes(this.stream, 'stream');
    const child = Buffer.concat([
      Buffer.from('ogvcs.fixture/prng-child/v1\0', 'ascii'),
      lengthPrefix(streamBytes),
      lengthPrefix(labelBytes),
    ]).toString('base64url');
    return new DeterministicPrng(this.seed, child);
  }
}

function deriveBlock(seedBytes, streamBytes, counter) {
  if (counter < 0n || counter > UINT64_MAX) {
    throw new RangeError('counter is outside uint64 range');
  }
  const counterBytes = Buffer.allocUnsafe(8);
  counterBytes.writeBigUInt64BE(counter);
  return createHash('sha256')
    .update('ogvcs.fixture/prng/sha256-counter/v1\0', 'ascii')
    .update(lengthPrefix(seedBytes))
    .update(lengthPrefix(streamBytes))
    .update(counterBytes)
    .digest();
}

function inputBytes(value, name) {
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  throw new TypeError(`${name} must be a string or byte array`);
}

function lengthPrefix(bytes) {
  if (bytes.length > 0xffff_ffff) throw new RangeError('derivation input is too long');
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function assertSafeNonNegativeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}
