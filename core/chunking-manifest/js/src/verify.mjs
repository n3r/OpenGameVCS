import { createHash } from 'node:crypto';
import {
  Digest, ObjectRef, ProfileRef, createObjectHashWriter, decodeMetadata, equalBytes,
} from '@opengamevcs/object-model';
import { createOperationControl } from './control.mjs';
import { fail, normalizeError, wrap } from './errors.mjs';
import { createBoundaryScanner, LIMITS } from './gear.mjs';
import { createLedger } from './ledger.mjs';
import { PROFILE } from './identity.mjs';
import { createVerificationReceipt } from './receipt.mjs';

const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;
const DEFAULT_INDEX_MEMORY_BYTES = 256 * 1024 * 1024;
const INDEX_ENTRY_BYTES = 256;

function configuredLimit(value, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 0) fail('CHUNK_RESOURCE_INVALID');
  return selected;
}

function asSafeInteger(value) {
  try {
    const integer = typeof value === 'bigint' ? value : BigInt(value);
    if (integer < 0n || integer > BigInt(Number.MAX_SAFE_INTEGER)) fail('CHUNK_MANIFEST_MISMATCH');
    return Number(integer);
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_MANIFEST_MISMATCH');
  }
}

function manifestBytes(input) {
  try {
    const selected = input?.bytes ?? input;
    if (!(selected instanceof Uint8Array)) fail('CHUNK_MANIFEST_MISMATCH');
    return Buffer.from(selected.buffer, selected.byteOffset, selected.byteLength);
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_MANIFEST_MISMATCH');
  }
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

async function sourceValue(source, part, index, control) {
  return control.wait(async () => {
    if (typeof source === 'function') return source(part, index, control.context);
    if (source instanceof Map) {
      if (!source.has(part.objectId)) fail('CHUNK_SOURCE_MISSING', { objectId: part.objectId });
      return source.get(part.objectId);
    }
    if (source && typeof source.getChunk === 'function') {
      return source.getChunk(part, index, control.context);
    }
    fail('CHUNK_SOURCE_MISSING', { objectId: part.objectId });
  }, 'CHUNK_SOURCE_INVALID', { objectId: part.objectId });
}

async function consumeFragments(value, part, control, consume) {
  if (value instanceof Uint8Array) {
    await consume(value);
    return;
  }
  let iterator;
  try {
    const asyncFactory = value?.[Symbol.asyncIterator];
    const syncFactory = value?.[Symbol.iterator];
    if (typeof asyncFactory === 'function') iterator = asyncFactory.call(value);
    else if (typeof syncFactory === 'function' && typeof value !== 'string') iterator = syncFactory.call(value);
    else fail('CHUNK_SOURCE_INVALID', { objectId: part.objectId });
    if (!iterator || typeof iterator.next !== 'function') {
      fail('CHUNK_SOURCE_INVALID', { objectId: part.objectId });
    }
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_SOURCE_INVALID', { objectId: part.objectId });
  }

  let failure;
  try {
    while (true) {
      const step = await control.wait(
        () => iterator.next(),
        'CHUNK_SOURCE_INVALID',
        { objectId: part.objectId },
      );
      if (!step || typeof step !== 'object') fail('CHUNK_SOURCE_INVALID', { objectId: part.objectId });
      if (step.done) break;
      await consume(step.value);
    }
  } catch (cause) {
    failure = normalizeError(cause, 'CHUNK_SOURCE_INVALID', { objectId: part.objectId });
  }
  if (failure !== undefined) {
    try {
      const returnIterator = iterator.return;
      if (typeof returnIterator === 'function') {
        await Promise.resolve(returnIterator.call(iterator));
      }
    } catch {}
  }
  if (failure !== undefined) throw failure;
}

async function consumeContent(parsed, source, publication, control) {
  control.check();
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
    control.check();
    const value = await sourceValue(source, part, partIndex, control);
    providerReads += 1;
    const chunkHash = createObjectHashWriter(1, { maxChunkBytes: LIMITS.maximum });
    let partBytes = 0;
    await consumeFragments(value, part, control, async (fragment) => {
      if (!(fragment instanceof Uint8Array) || fragment.byteLength > LIMITS.fragmentMaximum) {
        fail('CHUNK_SOURCE_INVALID', { objectId: part.objectId });
      }
      if (partBytes + fragment.byteLength > part.length) {
        fail('CHUNK_DIGEST_MISMATCH', { objectId: part.objectId });
      }
      const bytes = Buffer.from(fragment.buffer, fragment.byteOffset, fragment.byteLength);
      partBytes += bytes.length;
      contentBytes += bytes.length;
      try {
        for (let offset = 0; offset < bytes.length; offset += 65_536) {
          control.check();
          const slice = bytes.subarray(offset, Math.min(offset + 65_536, bytes.length));
          chunkHash.update(slice);
          whole.update(slice);
          scanner.update(slice, (boundary) => {
            if (boundary !== part.boundary) boundaryMismatch = true;
          });
        }
      } catch (cause) {
        throw normalizeError(cause, 'CHUNK_DIGEST_MISMATCH', { objectId: part.objectId });
      }
      if (publication) {
        await control.wait(
          () => publication.write(Buffer.from(bytes), Object.freeze({
            ...control.context,
            partIndex,
            objectId: part.objectId,
          })),
          'CHUNK_PUBLICATION_FAILED',
          { objectId: part.objectId },
        );
      }
    });
    let actual;
    try { actual = chunkHash.finish().toString(); }
    catch (cause) { throw normalizeError(cause, 'CHUNK_DIGEST_MISMATCH', { objectId: part.objectId }); }
    if (partBytes !== part.length || actual !== part.objectId) {
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

function receiptRequirementsFromParsed(parsed) {
  return Object.freeze({
    profile: PROFILE_TEXT,
    manifestObjectId: parsed.manifestObjectId,
    manifestSha256: createHash('sha256').update(parsed.bytes).digest('hex'),
    logicalBytes: String(parsed.logicalLength),
    wholeFileSha256: Buffer.from(parsed.wholeFileDigest).toString('hex'),
  });
}

export function parseManifestReceiptRequirements(manifest, options = {}) {
  const parsed = loadManifest(manifest, options);
  try {
    return receiptRequirementsFromParsed(parsed);
  } finally {
    parsed.dispose();
  }
}

export async function verifyManifest(input = {}) {
  let parsed;
  let control;
  try {
    control = createOperationControl(input);
    control.check();
    parsed = loadManifest(input.manifest, input);
    const content = await consumeContent(parsed, input.source, undefined, control);
    const requirements = receiptRequirementsFromParsed(parsed);
    return Object.freeze({
      ...summary(parsed, content, parsed.ledger.metrics()),
      verificationReceipt: createVerificationReceipt(requirements),
    });
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_SESSION_FAILED');
  } finally {
    parsed?.dispose();
    control?.dispose();
  }
}

export async function reconstructManifest(input = {}) {
  let parsed;
  let control;
  let publication;
  let transactionOpen = false;
  try {
    publication = input.publication;
    if (!publication || typeof publication.write !== 'function' ||
        typeof publication.commit !== 'function' || typeof publication.abort !== 'function') {
      fail('CHUNK_RESOURCE_INVALID');
    }
    control = createOperationControl(input);
    control.check();
    parsed = loadManifest(input.manifest, input);
    transactionOpen = true;
    const content = await consumeContent(parsed, input.source, publication, control);
    const verificationReceipt = createVerificationReceipt(receiptRequirementsFromParsed(parsed));
    const publicationResult = await control.wait(
      () => publication.commit(Object.freeze({ ...control.context, verificationReceipt })),
      'CHUNK_PUBLICATION_FAILED',
    );
    transactionOpen = false;
    return Object.freeze({
      ...summary(parsed, content, parsed.ledger.metrics()),
      publicationResult,
      verificationReceipt: publicationResult?.verificationReceipt ?? verificationReceipt,
    });
  } catch (cause) {
    const error = normalizeError(cause, 'CHUNK_SESSION_FAILED');
    if (transactionOpen) {
      transactionOpen = false;
      try { await Promise.resolve(publication.abort(error)); } catch {}
    }
    throw error;
  } finally {
    parsed?.dispose();
    control?.dispose();
  }
}

async function knownLength(knownChunks, objectId, expectedLength, control) {
  const value = await control.wait(async () => {
    if (typeof knownChunks === 'function') {
      return knownChunks(objectId, expectedLength, control.context);
    }
    if (knownChunks instanceof Map) return knownChunks.get(objectId);
    if (knownChunks && typeof knownChunks.knownLength === 'function') {
      return knownChunks.knownLength(objectId, expectedLength, control.context);
    }
    if (knownChunks === undefined || knownChunks === null) return undefined;
    fail('CHUNK_RESOURCE_INVALID');
  }, 'CHUNK_SOURCE_INVALID', { objectId });
  if (value === undefined || value === null || value === false) return undefined;
  if (value === true) return expectedLength;
  if (!Number.isSafeInteger(value) || value < 0) fail('CHUNK_METADATA_CONFLICT', { objectId });
  return value;
}

export async function compareManifest(input = {}) {
  let parsed;
  let control;
  try {
    control = createOperationControl(input);
    control.check();
    parsed = loadManifest(input.manifest, input);
    let reusedBytes = 0;
    for (const [objectId, length] of parsed.metadata) {
      control.check();
      const known = await knownLength(input.knownChunks, objectId, length, control);
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
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_SESSION_FAILED');
  } finally {
    parsed?.dispose();
    control?.dispose();
  }
}
