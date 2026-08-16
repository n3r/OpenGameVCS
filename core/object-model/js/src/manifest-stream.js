import { createHash } from 'node:crypto';
import { encodeCanonical } from './cbor.js';
import { fail, isOgvcsError } from './errors.js';
import { createObjectHashWriter } from './hash.js';
import { configuredHardLimit, enforceHardLimit, hardLimitMaximum } from './hard-limits.js';
import { profileDecision, registryAssignmentDecision } from './registry.js';
import { validateKnownSchema } from './schema.js';
import { Digest, KIND_NAMES, ObjectRef, ProfileRef, equalBytes } from './types.js';
import {
  ResourceGuard, asBytes, asCount, asLimit, cborHeader, checkedBigUint,
  exactMap, guardedAsyncIterable, toAsyncIterable, writeFully
} from './scale-util.js';

const MAX_MANIFEST_PARTS = hardLimitMaximum('manifest-chunks');
const MAX_CHUNK_BYTES = BigInt(hardLimitMaximum('chunk-payload-bytes'));
const MAX_LOGICAL_BYTES = BigInt(hardLimitMaximum('logical-file-bytes'));
const MAX_METADATA_BYTES = hardLimitMaximum('metadata-payload-bytes');
const MAX_GENERIC_VALUE_BYTES = hardLimitMaximum('generic-text-or-byte-value-bytes');
const CHUNKING_FAMILY = 'chunking';
const RECORD_OVERHEAD = 96;

function namesFor(registry) { return registry?.kindNames ?? KIND_NAMES; }

function digestValue(value) {
  if (value instanceof Digest) return value;
  return Digest.fromMap(value);
}

function chunkProfile(value, registry, operation) {
  const ref = value instanceof ProfileRef ? value : ProfileRef.fromMap(value);
  if (registry) {
    const decision = profileDecision(registry, ref, operation);
    if (decision.family !== CHUNKING_FAMILY) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  return ref;
}

function encodeResident(value, options, remaining = options.maxMemoryBytes, overrides = {}) {
  const memoryBound = Math.min(remaining, options.maxBytes);
  try {
    return encodeCanonical(value, {
      ...overrides,
      maxBytes: memoryBound,
      maxWorkingBytes: Math.min(options.maxMemoryBytes, remaining)
    });
  } catch (error) {
    if (isOgvcsError(error, 'LIMIT_METADATA_BYTES') && memoryBound < options.maxBytes) {
      fail('LIMIT_MEMORY', { layer: 1, cause: error });
    }
    throw error;
  }
}

function optionsFor(input) {
  const maxItems = Math.min(
    configuredHardLimit('manifest-chunks', input.hardLimits?.['manifest-chunks']),
    configuredHardLimit('manifest-chunks', asLimit(input.maxItems, MAX_MANIFEST_PARTS))
  );
  enforceHardLimit(undefined, 'manifest-chunks', input.partCount, {
    maximum: maxItems, code: 'LIMIT_COUNT', layer: 2
  });
  const partCount = asCount(input.partCount, maxItems);
  const maxBytes = Math.min(
    configuredHardLimit('metadata-payload-bytes', input.hardLimits?.['metadata-payload-bytes']),
    configuredHardLimit('metadata-payload-bytes', asLimit(input.maxBytes, MAX_METADATA_BYTES))
  );
  const maxMemoryBytes = asLimit(input.maxMemoryBytes, 67_108_864);
  const guard = new ResourceGuard({ maxTimeMs: input.maxTimeMs, maxMemoryBytes });
  guard.time();
  if (!Array.isArray(input.requiredFeatures ?? [])) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  enforceHardLimit(undefined, 'logical-file-bytes', input.logicalLength, {
    maximum: input.hardLimits?.['logical-file-bytes'], code: 'LIMIT_LOGICAL_BYTES', layer: 2
  });
  const logicalLength = checkedBigUint(input.logicalLength, MAX_LOGICAL_BYTES, 'LIMIT_LOGICAL_BYTES');
  const profile = chunkProfile(input.chunkProfile, input.registry, input.operation ?? 'conformance');
  return {
    ...input, maxItems, partCount, maxBytes, maxMemoryBytes, guard, logicalLength, profile,
    requiredFeatures: input.requiredFeatures ?? [], operation: input.operation ?? 'conformance'
  };
}

function manifestPrefix(options, digest) {
  const digestMap = digest.toMap();
  const profileMap = options.profile.toMap();
  const pieces = [];
  let resident = 0;
  const push = part => {
    options.guard.memory(resident + part.length);
    resident += part.length;
    pieces.push(part);
  };
  const pushValue = (value, overrides) => push(encodeResident(
    value, options, options.maxMemoryBytes - resident, overrides
  ));
  push(cborHeader(5, options.extensions === undefined ? 7 : 8));
  pushValue(0); pushValue(1); pushValue(1); pushValue(2); pushValue(2); pushValue(options.requiredFeatures);
  if (options.extensions !== undefined) { pushValue(3); pushValue(options.extensions); }
  pushValue(16); pushValue(options.logicalLength); pushValue(17); pushValue(digestMap);
  pushValue(18); pushValue(profileMap); pushValue(19); push(cborHeader(4, options.partCount));

  const common = new Map([[0, 1], [1, 2], [2, options.requiredFeatures], [16, options.logicalLength],
    [17, digestMap], [18, profileMap], [19, []]]);
  if (options.extensions !== undefined) common.set(3, options.extensions);
  // Validate the common fields and profile family with an empty, internally
  // consistent manifest. The actual streamed count and sum are checked below.
  const empty = new Map(common);
  empty.set(16, 0);
  empty.set(17, new Digest(1, new Uint8Array(createHash('sha256').digest())).toMap());
  validateKnownSchema(empty, 2, {
    registry: options.registry, operation: options.operation, hardLimits: options.hardLimits
  });
  return pieces;
}

function validatePart(value, options) {
  exactMap(value, [0, 1]);
  const reference = ObjectRef.fromMap(value.get(0), namesFor(options.registry));
  if (reference.kind !== 1) {
    fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
  }
  if (options.registry) {
    registryAssignmentDecision(options.registry, 'object-kinds', 1, options.operation);
    registryAssignmentDecision(options.registry, 'hash-algorithms', 1, options.operation);
  }
  enforceHardLimit(undefined, 'chunk-payload-bytes', value.get(1), {
    maximum: options.hardLimits?.['chunk-payload-bytes'], code: 'MANIFEST_CHUNK_LENGTH_INVALID', layer: 2
  });
  const length = checkedBigUint(value.get(1), MAX_CHUNK_BYTES, 'MANIFEST_CHUNK_LENGTH_INVALID', 1n);
  const encoded = encodeResident(value, options, options.maxMemoryBytes, {
    maxValueBytes: MAX_GENERIC_VALUE_BYTES,
    maxContainerItems: 8
  });
  options.guard.memory(encoded.length + RECORD_OVERHEAD);
  return { reference, length, encoded };
}

async function iterableFromFactory(parts, pass, guard) {
  if (typeof parts === 'function') {
    return toAsyncIterable(await guard.wait(signal => parts(pass, { signal })));
  }
  if (pass !== 1) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return toAsyncIterable(parts);
}

async function providerBytes(provider, reference, context, guard) {
  if (typeof provider !== 'function') fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  const supplied = await guard.wait(signal => provider(reference, Object.freeze({ ...context, signal })));
  if (supplied instanceof Uint8Array || ArrayBuffer.isView(supplied) || supplied instanceof ArrayBuffer) {
    return [asBytes(supplied)];
  }
  return toAsyncIterable(supplied);
}

class ChunkVerifier {
  constructor(options, whole) {
    this.options = options;
    this.whole = whole;
    this.cache = new Map();
    this.cachedBytes = 0;
    this.contentBytes = 0n;
    this.providerReads = 0;
    this.maxCacheBytes = Math.min(asLimit(options.maxChunkCacheBytes, Math.floor(options.maxMemoryBytes / 2)),
      options.maxMemoryBytes);
  }

  async consume(part, index) {
    const key = part.reference.toString();
    const cached = this.cache.get(key);
    if (cached) {
      if (BigInt(cached.length) !== part.length) fail('MANIFEST_CHUNK_LENGTH_INVALID', { layer: 3 });
      this.whole.update(cached);
      this.contentBytes += BigInt(cached.length);
      return;
    }
    const projectedCache = this.cachedBytes + (this.cache.size + 1) * RECORD_OVERHEAD + Number(part.length);
    const shouldCache = projectedCache <= this.maxCacheBytes;
    if (shouldCache) this.options.guard.memory(projectedCache + part.encoded.length + RECORD_OVERHEAD);
    const retained = shouldCache ? new Uint8Array(Number(part.length)) : undefined;
    const chunkHash = createObjectHashWriter(1, {
      maxChunkBytes: Number(part.length),
      registry: namesFor(this.options.registry)
    });
    let length = 0n;
    this.providerReads += 1;
    const source = await providerBytes(this.options.chunkProvider, part.reference,
      { index, declaredLength: part.length }, this.options.guard);
    for await (const raw of guardedAsyncIterable(source, this.options.guard)) {
      this.options.guard.time();
      const bytes = asBytes(raw, 3);
      if (BigInt(bytes.length) > part.length - length) fail('MANIFEST_CHUNK_LENGTH_INVALID', { layer: 3 });
      if (retained) retained.set(bytes, Number(length));
      length += BigInt(bytes.length);
      this.contentBytes += BigInt(bytes.length);
      chunkHash.update(bytes);
      this.whole.update(bytes);
    }
    if (length !== part.length) fail('MANIFEST_CHUNK_LENGTH_INVALID', { layer: 3 });
    const actual = chunkHash.finish();
    if (!equalBytes(actual.digest, part.reference.digest)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
    if (retained) {
      this.cachedBytes += retained.length;
      this.options.guard.memory(this.cachedBytes + (this.cache.size + 1) * RECORD_OVERHEAD +
        part.encoded.length + RECORD_OVERHEAD);
      this.cache.set(key, retained);
    }
  }
}

async function scanParts(options, { pass, verifyContent, consume }) {
  let count = 0;
  let logical = 0n;
  const transcript = createHash('sha256');
  const whole = verifyContent ? createHash('sha256') : undefined;
  const verifier = verifyContent ? new ChunkVerifier(options, whole) : undefined;
  const source = await iterableFromFactory(options.parts, pass, options.guard);
  for await (const raw of guardedAsyncIterable(source, options.guard)) {
    options.guard.time();
    count += 1;
    if (count > options.maxItems) {
      fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
    }
    if (count > options.partCount) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    const part = validatePart(raw, options);
    logical += part.length;
    enforceHardLimit(undefined, 'logical-file-bytes', logical, {
      maximum: options.hardLimits?.['logical-file-bytes'], code: 'LIMIT_LOGICAL_BYTES', layer: 2
    });
    transcript.update(part.encoded);
    if (verifier) await verifier.consume(part, count - 1);
    if (consume) await consume(part.encoded);
  }
  if (count !== options.partCount) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  if (logical !== options.logicalLength || (options.logicalLength === 0n && count !== 0)) {
    fail('MANIFEST_LENGTH_MISMATCH', { layer: 2 });
  }
  return {
    count,
    logical,
    transcript: new Uint8Array(transcript.digest()),
    contentDigest: whole ? new Uint8Array(whole.digest()) : undefined,
    contentBytes: verifier?.contentBytes ?? 0n,
    providerReads: verifier?.providerReads ?? 0,
    cachedChunks: verifier?.cache.size ?? 0,
    cachedBytes: verifier?.cachedBytes ?? 0
  };
}

function createEmitter(options) {
  const hash = createObjectHashWriter(2, { maxMetadataBytes: options.maxBytes, registry: namesFor(options.registry) });
  let bytes = 0;
  return {
    async emit(part) {
      options.guard.time();
      if (part.length > options.maxBytes - bytes) fail('LIMIT_METADATA_BYTES', { layer: 1 });
      bytes += part.length;
      hash.update(part);
      await writeFully(options.sink, part, { guard: options.guard });
    },
    finish() { return { reference: hash.finish(), bytes }; }
  };
}

function stableSummary(reference, options, bytes) {
  return Object.freeze({
    format: 1,
    kind: 2,
    objectRef: reference.toString(),
    partCount: options.partCount,
    logicalBytes: options.logicalLength.toString(),
    metadataBytes: bytes
  });
}

/**
 * Validate and write ContentManifestV1 without retaining its part array.
 *
 * With a supplied wholeFileDigest, `parts` may be any iterable. Providing a
 * chunkProvider verifies every referenced byte and the whole-file digest.
 * Without a supplied digest, `parts` must be a repeatable factory: pass 1
 * validates content and derives the digest; pass 2 replays metadata, checks a
 * SHA-256 structural transcript, and writes the canonical object. This hashes
 * large logical content only once.
 */
export async function writeContentManifest(input) {
  const options = optionsFor(input ?? {});
  const derive = options.wholeFileDigest === undefined;
  const verifyContent = derive || options.verifyContent === true || options.chunkProvider !== undefined ||
    options.partCount === 0;
  if (derive && typeof options.parts !== 'function') fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  if (verifyContent && options.partCount > 0 && typeof options.chunkProvider !== 'function') {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }

  let digest;
  let verification;
  if (derive) {
    verification = await scanParts(options, { pass: 1, verifyContent: true });
    digest = new Digest(1, verification.contentDigest);
  } else {
    digest = digestValue(options.wholeFileDigest);
  }

  const prefix = manifestPrefix(options, digest);
  options.guard.memory(prefix.reduce((total, part) => total + part.length, 0));
  const emitter = createEmitter(options);
  for (const part of prefix) await emitter.emit(part);
  const outputPass = derive ? 2 : 1;
  const scanned = await scanParts(options, {
    pass: outputPass,
    verifyContent: !derive && verifyContent,
    consume: part => emitter.emit(part)
  });

  if (derive && !equalBytes(verification.transcript, scanned.transcript)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  if (!derive && verifyContent && !equalBytes(scanned.contentDigest, digest.bytes)) {
    fail('MANIFEST_FILE_DIGEST_MISMATCH', { layer: 3 });
  }
  const effectiveVerification = derive ? verification : scanned;
  const finished = emitter.finish();
  return Object.freeze({
    objectRef: finished.reference,
    wholeFileDigest: digest,
    summary: stableSummary(finished.reference, options, finished.bytes),
    verification: Object.freeze({
      contentVerified: verifyContent,
      contentBytesRead: effectiveVerification.contentBytes.toString(),
      providerReads: effectiveVerification.providerReads,
      cachedChunks: effectiveVerification.cachedChunks,
      cachedBytes: effectiveVerification.cachedBytes
    }),
    metrics: Object.freeze({ elapsedMilliseconds: options.guard.elapsedMilliseconds() })
  });
}

export const MANIFEST_STREAM_LIMITS = Object.freeze({
  maxParts: MAX_MANIFEST_PARTS,
  maxChunkBytes: MAX_CHUNK_BYTES,
  maxLogicalBytes: MAX_LOGICAL_BYTES,
  maxMetadataBytes: MAX_METADATA_BYTES
});
