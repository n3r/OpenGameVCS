import { createCipheriv, createHash } from 'node:crypto';
import { deriveBytes } from './prng.mjs';

export const CONTENT_ALGORITHM = 'ogvcs.fixture/content-aes-256-ctr/v2';
const DEFAULT_CHUNK_BYTES = 1024 * 1024;
const MAX_CHUNK_BYTES = 64 * 1024 * 1024;
const MIXED_REGION_BYTES = 64 * 1024;

/**
 * Yield deterministic content chunks without retaining the entire file.
 *
 * `start` supports verified resume and range generation. Chunk boundaries are
 * transport-only: changing `chunkSize` never changes the byte stream.
 */
export function* deterministicChunks({
  seed,
  stream = 'content',
  size,
  start = 0,
  chunkSize = DEFAULT_CHUNK_BYTES,
  compressionClass = 'incompressible',
} = {}) {
  assertSafeNonNegativeInteger(size, 'size');
  assertSafeNonNegativeInteger(start, 'start');
  if (start > size) throw new RangeError('start cannot exceed size');
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > MAX_CHUNK_BYTES) {
    throw new RangeError(`chunkSize must be an integer from 1 through ${MAX_CHUNK_BYTES}`);
  }
  if (!['incompressible', 'mixed', 'compressible', 'zero'].includes(compressionClass)) {
    throw new RangeError(`Unknown compressionClass: ${compressionClass}`);
  }
  // Validate even an empty stream, which otherwise would never derive a block.
  deriveBytes(seed, `${CONTENT_ALGORITHM}:${stream}`, 0, start);

  let offset = start;
  while (offset < size) {
    const length = Math.min(chunkSize, size - offset);
    yield contentRange(seed, stream, offset, length, compressionClass);
    offset += length;
  }
}

/** Calculate SHA-256 and byte count for a deterministic content stream. */
export function digestDeterministicContent(options) {
  const hash = createHash('sha256');
  let bytes = 0;
  for (const chunk of deterministicChunks(options)) {
    hash.update(chunk);
    bytes += chunk.length;
  }
  return {
    algorithm: 'sha256',
    digest: hash.digest('hex'),
    bytes,
    contentAlgorithm: CONTENT_ALGORITHM,
  };
}

/**
 * Normalize a synthetic logical path to relative NFC POSIX form.
 * This is a fixture safety baseline, not OGVCS-004's final platform policy.
 */
export function normalizeLogicalPath(path) {
  if (typeof path !== 'string' || path.length === 0) throw new TypeError('path must be a non-empty string');
  if (path.includes('\\') || path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.includes('\u0000')) {
    throw new RangeError('logical path must be a relative POSIX path');
  }
  const normalized = path.normalize('NFC');
  const segments = normalized.split('/');
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    throw new RangeError('logical path contains an empty, dot, or parent segment');
  }
  return segments.join('/');
}

/** Derive a stable 128-bit synthetic identifier rendered as lowercase hex. */
export function deterministicId(seed, namespace, logicalKey) {
  if (typeof namespace !== 'string' || !/^[a-z][a-z0-9.-]{0,127}$/.test(namespace)) {
    throw new TypeError('namespace must be a lowercase fixture identifier');
  }
  const key = normalizeLogicalPath(logicalKey);
  return deriveBytes(seed, `id:${namespace}:${key}`, 16).toString('hex');
}

function contentRange(seed, stream, offset, length, compressionClass) {
  if (compressionClass === 'zero') return Buffer.alloc(length);
  if (compressionClass === 'incompressible') return aesCtrRange(seed, stream, offset, length);

  const output = Buffer.allocUnsafe(length);
  let written = 0;
  while (written < length) {
    const absoluteOffset = offset + written;
    const region = Math.floor(absoluteOffset / MIXED_REGION_BYTES);
    const withinRegion = absoluteOffset % MIXED_REGION_BYTES;
    const take = Math.min(length - written, MIXED_REGION_BYTES - withinRegion);
    const deterministicRegion = compressionClass === 'mixed' && region % 2 === 1;
    if (deterministicRegion) {
      aesCtrRange(seed, `${stream}:mixed-random`, absoluteOffset, take).copy(output, written);
    } else {
      const motif = deriveBytes(seed, `${CONTENT_ALGORITHM}:${stream}:motif:${region}`, 64);
      const phase = withinRegion % motif.length;
      const rotated = phase === 0 ? motif : Buffer.concat([motif.subarray(phase), motif.subarray(0, phase)]);
      output.fill(rotated, written, written + take);
    }
    written += take;
  }
  return output;
}

/**
 * Efficient random-access deterministic bytes. AES-CTR is used only as a
 * reproducible fixture stream, not for secrecy. The key and initial counter
 * are domain-separated SHA-256 derivations; the counter is advanced by the
 * requested 16-byte block offset, so arbitrary ranges reconstruct exactly.
 */
function aesCtrRange(seed, stream, offset, length) {
  const domain = `${CONTENT_ALGORITHM}\0${stream}`;
  const key = createHash('sha256').update('key\0').update(domain).update('\0').update(seed).digest();
  const initial = createHash('sha256').update('counter\0').update(domain).update('\0').update(seed).digest().subarray(0, 16);
  const withinBlock = offset % 16;
  const blockOffset = BigInt(Math.floor(offset / 16));
  const counterValue = (BigInt(`0x${initial.toString('hex')}`) + blockOffset) & ((1n << 128n) - 1n);
  const counter = Buffer.from(counterValue.toString(16).padStart(32, '0'), 'hex');
  const cipher = createCipheriv('aes-256-ctr', key, counter);
  const bytes = cipher.update(Buffer.alloc(length + withinBlock));
  return bytes.subarray(withinBlock);
}

function assertSafeNonNegativeInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative safe integer`);
  }
}
