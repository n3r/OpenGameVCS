import { createHash } from 'node:crypto';
import {
  Digest, ObjectRef, ProfileRef, createObjectHashWriter, decodeMetadata, equalBytes,
} from '@opengamevcs/object-model';
import { fail, wrap } from './errors.mjs';
import { createBoundaryScanner, LIMITS } from './gear.mjs';
import { createLedger } from './ledger.mjs';
import { PROFILE } from './identity.mjs';

const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;
const DEFAULT_INDEX_MEMORY_BYTES = 256 * 1024 * 1024;
const INDEX_ENTRY_BYTES = 256;

function configuredLimit(value, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 0) fail('CHUNK_RESOURCE_INVALID');
  return selected;
}

function asSafeInteger(value) {
  const integer = typeof value === 'bigint' ? value : BigInt(value);
  if (integer < 0n || integer > BigInt(Number.MAX_SAFE_INTEGER)) fail('CHUNK_MANIFEST_MISMATCH');
  return Number(integer);
}

function manifestBytes(input) {
  const selected = input?.bytes ?? input;
  if (!(selected instanceof Uint8Array)) fail('CHUNK_MANIFEST_MISMATCH');
  return Buffer.from(selected.buffer, selected.byteOffset, selected.byteLength);
}

function exactPart(raw) {
  if (!(raw instanceof Map) || raw.size !== 2 || !raw.has(0) || !raw.has(1)) {
    fail('CHUNK_MANIFEST_MISMATCH');
  }
  let reference;
  try { reference = ObjectRef.fromMap(raw.get(0)); } catch (cause) {
    throw wrap('CHUNK_MANIFEST_MISMATCH', cause);
  }
  if (reference.kind !== 1) fail('CHUNK_MANIFEST_MISMATCH');
  const length = asSafeInteger(raw.get(1));
  if (length < 1 || length > LIMITS.maximum) fail('CHUNK_MANIFEST_MISMATCH');
  return { reference, length };
}

function loadManifest(input, options = {}) {
  const bytes = manifestBytes(input);
  const maxManifestBytes = configuredLimit(options.maxManifestBytes, 64 * 1024 * 1024);
  if (bytes.byteLength > maxManifestBytes) fail('CHUNK_MANIFEST_MISMATCH');

  // This is intentionally the first format operation: OGVCS-002 canonical
  // framing and known-schema validation precede candidate profile semantics.
  let decoded;
  try {
    decoded = decodeMetadata(bytes, {
      semantic: false,
      maxBytes: maxManifestBytes,
      maxWorkingBytes: Math.min(configuredLimit(options.maxDecodeWorkingBytes, 64 * 1024 * 1024), 64 * 1024 * 1024),
      maxContainerItems: LIMITS.chunkCountMaximum,
    });
  } catch (cause) {
    throw wrap('CHUNK_MANIFEST_MISMATCH', cause);
  }
  if (decoded.kind !== 2) fail('CHUNK_MANIFEST_MISMATCH');
  if (options.expectedManifestObjectId !== undefined &&
      decoded.objectId?.toString() !== options.expectedManifestObjectId) {
    fail('CHUNK_MANIFEST_MISMATCH');
  }

  const value = decoded.value;
  let profile;
  let wholeFileDigest;
  try {
    profile = ProfileRef.fromMap(value.get(18));
    wholeFileDigest = Digest.fromMap(value.get(17));
  } catch (cause) {
    throw wrap('CHUNK_MANIFEST_MISMATCH', cause);
  }
  if (profile.toString() !== PROFILE_TEXT) fail('CHUNK_PROFILE_UNSUPPORTED');
  const logicalLength = asSafeInteger(value.get(16));
  if (logicalLength > LIMITS.logicalMaximum) fail('CHUNK_MANIFEST_MISMATCH');
  const rawParts = value.get(19);
  if (!Array.isArray(rawParts) || rawParts.length > LIMITS.chunkCountMaximum) {
    fail('CHUNK_MANIFEST_MISMATCH');
  }

  const ledger = createLedger({
    maxMemoryBytes: options.maxLedgerMemoryBytes,
    maxScratchBytes: options.maxScratchBytes,
    scratchDirectory: options.scratchDirectory,
  });
  const maxIndexMemoryBytes = configuredLimit(options.maxIndexMemoryBytes, DEFAULT_INDEX_MEMORY_BYTES);
  const metadata = new Map();
  let logical = 0;
  let uniqueBytes = 0;
  try {
    for (const raw of rawParts) {
      const { reference, length } = exactPart(raw);
      const objectId = reference.toString();
      const previous = metadata.get(objectId);
      if (previous !== undefined && previous !== length) {
        fail('CHUNK_METADATA_CONFLICT', { objectId, firstLength: previous, conflictingLength: length });
      }
      if (previous === undefined) {
        if ((metadata.size + 1) * INDEX_ENTRY_BYTES > maxIndexMemoryBytes) {
          fail('CHUNK_RESOURCE_EXHAUSTED', { maxIndexMemoryBytes });
        }
        metadata.set(objectId, length);
        uniqueBytes += length;
      }
      logical += length;
      if (!Number.isSafeInteger(logical) || logical > LIMITS.logicalMaximum) fail('CHUNK_MANIFEST_MISMATCH');
      ledger.append({ digest: reference.digest, length, boundary: logical });
    }
    if (logical !== logicalLength || (logicalLength === 0 && rawParts.length !== 0)) {
      fail('CHUNK_MANIFEST_MISMATCH');
    }
    return {
      bytes,
      dispose: () => ledger.dispose(),
      ledger,
      logicalLength,
      manifestObjectId: decoded.objectId.toString(),
      metadata,
      partCount: rawParts.length,
      uniqueBytes,
      wholeFileDigest: Buffer.from(wholeFileDigest.bytes),
    };
  } catch (error) {
    ledger.dispose();
    throw error;
  }
}

async function sourceValue(source, part, index) {
  try {
    if (typeof source === 'function') return await source(part, index);
    if (source instanceof Map) {
      if (!source.has(part.objectId)) fail('CHUNK_SOURCE_MISSING', { objectId: part.objectId });
      return source.get(part.objectId);
    }
    if (source && typeof source.getChunk === 'function') return await source.getChunk(part, index);
  } catch (cause) {
    if (cause?.code?.startsWith?.('CHUNK_')) throw cause;
    throw wrap('CHUNK_SOURCE_INVALID', cause, { objectId: part.objectId });
  }
  fail('CHUNK_SOURCE_MISSING', { objectId: part.objectId });
}

async function *fragments(value) {
  if (value instanceof Uint8Array) { yield value; return; }
  if (value?.[Symbol.asyncIterator]) {
    for await (const fragment of value) yield fragment;
    return;
  }
  if (value?.[Symbol.iterator] && typeof value !== 'string') {
    for (const fragment of value) yield fragment;
    return;
  }
  fail('CHUNK_SOURCE_INVALID');
}

async function consumeContent(parsed, source, publication) {
  if (source === undefined || source === null) fail('CHUNK_SOURCE_MISSING');
  const whole = createHash('sha256');
  const scanner = createBoundaryScanner(parsed.logicalLength);
  let boundaryMismatch = parsed.logicalLength <= LIMITS.smallMaximum
    ? parsed.partCount !== (parsed.logicalLength === 0 ? 0 : 1)
    : false;
  let contentBytes = 0;
  let providerReads = 0;
  let partIndex = 0;

  for (const part of parsed.ledger.records()) {
    const value = await sourceValue(source, part, partIndex);
    providerReads += 1;
    const chunkHash = createObjectHashWriter(1, { maxChunkBytes: LIMITS.maximum });
    let partBytes = 0;
    for await (const fragment of fragments(value)) {
      if (!(fragment instanceof Uint8Array) || fragment.byteLength > LIMITS.fragmentMaximum) {
        fail('CHUNK_SOURCE_INVALID', { objectId: part.objectId });
      }
      if (partBytes + fragment.byteLength > part.length) {
        fail('CHUNK_DIGEST_MISMATCH', { objectId: part.objectId });
      }
      const bytes = Buffer.from(fragment.buffer, fragment.byteOffset, fragment.byteLength);
      partBytes += bytes.length;
      contentBytes += bytes.length;
      chunkHash.update(bytes);
      whole.update(bytes);
      scanner.update(bytes, (boundary) => {
        if (boundary !== part.boundary) boundaryMismatch = true;
      });
      if (publication) {
        try { await publication.write(Buffer.from(bytes), Object.freeze({ partIndex, objectId: part.objectId })); }
        catch (cause) { throw wrap('CHUNK_PUBLICATION_FAILED', cause); }
      }
    }
    if (partBytes !== part.length || chunkHash.finish().toString() !== part.objectId) {
      fail('CHUNK_DIGEST_MISMATCH', { objectId: part.objectId });
    }
    if (parsed.logicalLength > LIMITS.smallMaximum && partIndex + 1 < parsed.partCount &&
        scanner.lastBoundary !== part.boundary) {
      boundaryMismatch = true;
    }
    partIndex += 1;
  }
  if (contentBytes !== parsed.logicalLength) fail('CHUNK_DIGEST_MISMATCH');
  if (!equalBytes(whole.digest(), parsed.wholeFileDigest)) fail('CHUNK_DIGEST_MISMATCH');
  if (boundaryMismatch) fail('CHUNK_BOUNDARY_MISMATCH');
  return Object.freeze({ contentBytes, providerReads });
}

function summary(parsed, content, ledger) {
  return Object.freeze({
    logicalBytes: String(parsed.logicalLength),
    manifestObjectId: parsed.manifestObjectId,
    partCount: parsed.partCount,
    providerReads: content.providerReads,
    uniqueBytes: String(parsed.uniqueBytes),
    repeatedBytes: String(parsed.logicalLength - parsed.uniqueBytes),
    ledger,
  });
}

export async function verifyManifest(input = {}) {
  const parsed = loadManifest(input.manifest, input);
  try {
    const content = await consumeContent(parsed, input.source);
    return summary(parsed, content, parsed.ledger.metrics());
  } finally {
    parsed.dispose();
  }
}

export async function reconstructManifest(input = {}) {
  const publication = input.publication;
  if (!publication || typeof publication.write !== 'function' ||
      typeof publication.commit !== 'function' || typeof publication.abort !== 'function') {
    fail('CHUNK_RESOURCE_INVALID');
  }
  const parsed = loadManifest(input.manifest, input);
  let started = false;
  try {
    const transactional = {
      async write(bytes, context) {
        started = true;
        return publication.write(bytes, context);
      },
    };
    const content = await consumeContent(parsed, input.source, transactional);
    let publicationResult;
    try { publicationResult = await publication.commit(); }
    catch (cause) { throw wrap('CHUNK_PUBLICATION_FAILED', cause); }
    return Object.freeze({ ...summary(parsed, content, parsed.ledger.metrics()), publicationResult });
  } catch (error) {
    if (started) {
      try { await publication.abort(error); } catch {}
    }
    throw error;
  } finally {
    parsed.dispose();
  }
}

async function knownLength(knownChunks, objectId, expectedLength) {
  let value;
  try {
    if (typeof knownChunks === 'function') value = await knownChunks(objectId, expectedLength);
    else if (knownChunks instanceof Map) value = knownChunks.get(objectId);
    else if (knownChunks && typeof knownChunks.knownLength === 'function') {
      value = await knownChunks.knownLength(objectId);
    } else if (knownChunks === undefined || knownChunks === null) return undefined;
    else fail('CHUNK_RESOURCE_INVALID');
  } catch (cause) {
    if (cause?.code?.startsWith?.('CHUNK_')) throw cause;
    throw wrap('CHUNK_SOURCE_INVALID', cause, { objectId });
  }
  if (value === undefined || value === null || value === false) return undefined;
  if (value === true) return expectedLength;
  if (!Number.isSafeInteger(value) || value < 0) fail('CHUNK_METADATA_CONFLICT', { objectId });
  return value;
}

export async function compareManifest(input = {}) {
  const parsed = loadManifest(input.manifest, input);
  try {
    let reusedBytes = 0;
    for (const [objectId, length] of parsed.metadata) {
      const known = await knownLength(input.knownChunks, objectId, length);
      if (known === undefined) continue;
      if (known !== length) {
        fail('CHUNK_METADATA_CONFLICT', { objectId, manifestLength: length, knownLength: known });
      }
      reusedBytes += length;
    }
    return Object.freeze({
      logicalBytes: String(parsed.logicalLength),
      manifestObjectId: parsed.manifestObjectId,
      newlyRequiredBytes: String(parsed.uniqueBytes - reusedBytes),
      partCount: parsed.partCount,
      repeatedBytes: String(parsed.logicalLength - parsed.uniqueBytes),
      reusedBytes: String(reusedBytes),
      uniqueBytes: String(parsed.uniqueBytes),
      uniqueChunks: parsed.metadata.size,
      ledger: parsed.ledger.metrics(),
    });
  } finally {
    parsed.dispose();
  }
}
