import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

import { iterateLogicalRecordReferences, iterateObjectReferences } from './bundle.js';
import { visitLogicalBundle } from './bundle-stream.js';
import { BundleScratch, FixedRecordSorter, ScratchWriter } from './bundle-scratch.js';
import { decodeCanonical, decodeFirst, encodeCanonical } from './cbor.js';
import { compareErrorPrecedence, fail, OgvcsError } from './errors.js';
import {
  createBundleTranscriptHashWriter, createLogicalRecordHashWriter, createObjectHashWriter,
  createOpaqueObjectHashWriter
} from './hash.js';
import { configuredHardLimit, hardLimitMaximum } from './hard-limits.js';
import { registryAssignmentDecision } from './registry.js';
import { decodeMetadata, validateBundleItem, validateKnownSchema, validateLogicalRecord } from './schema.js';
import { ResourceGuard, asLimit, compareBytes } from './scale-util.js';
import { Digest, KIND_NAMES, ObjectRef, ProfileRef, equalBytes, toHex } from './types.js';
import { codecValidationContext } from './validation-mode.js';

const BUNDLE_LIMIT_NAMES = Object.freeze({
  sequenceBytes: 'bundle-sequence-bytes',
  itemBytes: 'bundle-largest-item-bytes',
  objects: 'bundle-objects',
  logicalRecords: 'bundle-logical-records',
  roots: 'bundle-roots',
  items: 'bundle-total-items',
  traversalEdges: 'bundle-traversal-edges',
  indexEntries: 'bundle-index-entries'
});
const HARD = Object.freeze(Object.fromEntries(Object.entries(BUNDLE_LIMIT_NAMES)
  .map(([key, name]) => [key, hardLimitMaximum(name)])));

const ITEM_INDEX_BYTES = 24;
const OBJECT_LOOKUP_BYTES = 42;
const LOGICAL_LOOKUP_BYTES = 40;
const OBJECT_ORDINAL_BYTES = 16;
const REFERENCE_BYTES = 34;
export const LOGICAL_BUNDLE_STREAM_LIMITS = HARD;

function uint(value, maximum = Number.MAX_SAFE_INTEGER, code = 'SCHEMA_FIELD_INVALID', layer = 1) {
  if ((typeof value !== 'number' || !Number.isSafeInteger(value)) && typeof value !== 'bigint') {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  const result = BigInt(value);
  if (result < 0n || result > BigInt(maximum)) fail(code, { layer,
    stage: code === 'BUNDLE_BUDGET_EXCEEDED'
      ? 'configured-resource-preflight' : 'canonical-framing' });
  return result;
}

function exactBundleMap(value, keys, offset) {
  if (!(value instanceof Map) || value.size !== keys.length || keys.some(key => !value.has(key))) {
    fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset });
  }
  return value;
}

function rawDigest(value, offset) {
  exactBundleMap(value, [0, 1], offset);
  if (value.get(0) !== 1 || !(value.get(1) instanceof Uint8Array) || value.get(1).length !== 32) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing', offset });
  }
  return value.get(1);
}

function rawLogicalType(value, offset) {
  if (!(value instanceof Map) || !value.has(1)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing', offset });
  }
  const raw = value.get(1);
  const numeric = uint(raw);
  const hashable = numeric >= 1n && numeric <= 65_535n;
  const type = hashable ? Number(numeric) : undefined;
  return {
    hashable,
    sortKey: hashable ? Uint8Array.of(type >>> 8, type & 255) : encodeCanonical(raw),
    type
  };
}

function configured(options) {
  const limits = {};
  for (const [key, name] of Object.entries(BUNDLE_LIMIT_NAMES)) {
    const named = configuredHardLimit(name, options.hardLimits?.[name]);
    limits[key] = configuredHardLimit(name, options[key] ?? named);
  }
  const maxMemoryBytes = asLimit(options.maxMemoryBytes, 67_108_864);
  const maxScratchBytes = asLimit(options.maxScratchBytes, 8_589_934_592);
  const maxRunBytes = asLimit(options.maxRunBytes,
    Math.min(8_388_608, Math.max(OBJECT_LOOKUP_BYTES, Math.floor(maxMemoryBytes / 8))));
  const maxOpenRuns = Math.min(asLimit(options.maxOpenRuns, 32), 256);
  const readChunkBytes = asLimit(options.readChunkBytes, Math.min(65_536, Math.max(1, Math.floor(maxMemoryBytes / 8))));
  const writeBufferBytes = Math.min(32_768, Math.max(1, Math.floor(maxMemoryBytes / 16)));
  const guard = new ResourceGuard({ maxTimeMs: options.maxTimeMs, maxMemoryBytes });
  const residentBaseBytes = maxRunBytes + readChunkBytes * 2 + writeBufferBytes * 3 +
    maxOpenRuns * OBJECT_LOOKUP_BYTES + 4_096;
  guard.memory(residentBaseBytes);
  const maxDecodedItemBytes = Math.min(
    asLimit(options.maxDecodedItemBytes, Math.max(1, Math.floor((maxMemoryBytes - residentBaseBytes) / 2))),
    HARD.itemBytes
  );
  const chunkBytes = configuredHardLimit('chunk-payload-bytes', options.hardLimits?.['chunk-payload-bytes']);
  const metadataBytes = configuredHardLimit('metadata-payload-bytes', options.hardLimits?.['metadata-payload-bytes']);
  const genericValueBytes = configuredHardLimit(
    'generic-text-or-byte-value-bytes', options.hardLimits?.['generic-text-or-byte-value-bytes']
  );
  const nestingDepth = configuredHardLimit('cbor-nesting-depth', options.hardLimits?.['cbor-nesting-depth']);
  const containerItems = configuredHardLimit('manifest-chunks', options.hardLimits?.['manifest-chunks']);
  const scannerValueBytes = Math.min(genericValueBytes,
    Math.max(1, Math.floor((maxMemoryBytes - residentBaseBytes) / 4)));
  // A scanner value may coexist with its decoded/text projections and every
  // active or retained canonical map-key capture. Give captures one explicit
  // share of the same aggregate remainder; the visitor accounts capacities
  // (including transient replacement buffers) within this share.
  const scannerCaptureBytes = scannerValueBytes;
  if (maxOpenRuns < 2 || readChunkBytes < 1 || maxDecodedItemBytes < 1) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return {
    ...limits, maxMemoryBytes, maxScratchBytes, maxDecodedItemBytes, maxRunBytes,
    maxOpenRuns, readChunkBytes, writeBufferBytes, residentBaseBytes, scannerValueBytes,
    scannerCaptureBytes,
    chunkBytes, metadataBytes, genericValueBytes, nestingDepth, containerItems, guard
  };
}

function putU64(target, offset, value) { target.writeBigUInt64BE(BigInt(value), offset); }
function getU64(source, offset) {
  const bytes = Buffer.from(source.buffer, source.byteOffset, source.byteLength);
  const value = bytes.readBigUInt64BE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  return Number(value);
}

function itemIndexRecord(offset, length, type) {
  const record = Buffer.alloc(ITEM_INDEX_BYTES);
  putU64(record, 0, offset);
  putU64(record, 8, length);
  record.writeUInt8(type, 16);
  return record;
}

function objectLookupRecord(ref, ordinal) {
  const record = Buffer.alloc(OBJECT_LOOKUP_BYTES);
  Buffer.from(ref.digest).copy(record, 0);
  record.writeUInt16BE(ref.kind, 32);
  putU64(record, 34, ordinal);
  return record;
}

function logicalLookupRecord(identity, ordinal) {
  const record = Buffer.alloc(LOGICAL_LOOKUP_BYTES);
  Buffer.from(identity.bytes).copy(record, 0);
  putU64(record, 32, ordinal);
  return record;
}

function objectOrdinalRecord(edgeStart, edgeCount) {
  const record = Buffer.alloc(OBJECT_ORDINAL_BYTES);
  putU64(record, 0, edgeStart);
  putU64(record, 8, edgeCount);
  return record;
}

function referenceRecord(ref) {
  const record = Buffer.alloc(REFERENCE_BYTES);
  Buffer.from(ref.digest).copy(record, 0);
  record.writeUInt16BE(ref.kind, 32);
  return record;
}

function referenceFromRecord(record, registry) {
  return new ObjectRef(record.readUInt16BE(32), record.subarray(0, 32), registry);
}

function tupleCompare(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    const order = compareBytes(left[index], right[index]);
    if (order !== 0) return order;
  }
  return 0;
}

function deferredStageCollector(layer, stage) {
  let selected;
  return Object.freeze({
    observe(callback) {
      try { return callback(); }
      catch (error) {
        if (!(error instanceof OgvcsError) || error.errorClass === 'resource' ||
            error.layer !== layer || error.stage !== stage) throw error;
        if (!selected || compareErrorPrecedence(error, selected) < 0) selected = error;
        return undefined;
      }
    },
    throwSelected() { if (selected) throw selected; }
  });
}

class PrefixReader {
  constructor(bytes, absoluteOffset) {
    this.bytes = bytes;
    this.cursor = 0;
    this.absoluteOffset = absoluteOffset;
  }

  take(count) {
    if (!Number.isSafeInteger(count) || count < 0 || this.cursor + count > this.bytes.length) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: this.absoluteOffset + this.cursor });
    }
    const out = this.bytes.subarray(this.cursor, this.cursor + count);
    this.cursor += count;
    return out;
  }

  head() {
    const start = this.cursor;
    const first = this.take(1)[0];
    const major = first >>> 5;
    const ai = first & 31;
    if (major === 6 || ai === 31 || major === 7) fail('CBOR_NON_CANONICAL', { layer: 1, offset: this.absoluteOffset + start });
    let value;
    if (ai < 24) value = BigInt(ai);
    else {
      const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
      if (size === 0) fail('CBOR_NON_CANONICAL', { layer: 1, offset: this.absoluteOffset + start });
      value = 0n;
      for (const byte of this.take(size)) value = (value << 8n) | BigInt(byte);
      if ((size === 1 && value < 24n) || (size === 2 && value <= 0xffn) ||
          (size === 4 && value <= 0xffffn) || (size === 8 && value <= 0xffff_ffffn)) {
        fail('CBOR_NON_CANONICAL', { layer: 1, offset: this.absoluteOffset + start });
      }
    }
    return { major, value, start };
  }

  unsigned(expected, code = 'BUNDLE_SEQUENCE_INVALID', layer = 1) {
    const item = this.head();
    if (item.major !== 0 || item.value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail(code, { layer, offset: this.absoluteOffset + item.start });
    }
    const value = Number(item.value);
    if (expected !== undefined && value !== expected) fail(code, { layer, offset: this.absoluteOffset + item.start });
    return value;
  }
}

async function readPrefix(scratch, file, offset, length) {
  const bytes = Buffer.alloc(Math.min(length, 512));
  await scratch.readExactly(file, bytes, 0, bytes.length, offset);
  return bytes;
}

async function objectEnvelope(scratch, file, item, { opaqueReference = false } = {}) {
  const reader = new PrefixReader(await readPrefix(scratch, file, item.offset, item.length), item.offset);
  const wrapper = reader.head();
  if (wrapper.major !== 5 || wrapper.value !== 5n) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
  reader.unsigned(0); reader.unsigned(1);
  reader.unsigned(1); reader.unsigned(2);
  reader.unsigned(2); const ordinal = reader.unsigned();
  reader.unsigned(3);
  const referenceStart = reader.cursor;
  if (opaqueReference) {
    const decoded = decodeFirst(reader.bytes.subarray(referenceStart), {
      maxBytes: reader.bytes.length - referenceStart,
      maxWorkingBytes: 65_536
    });
    const sortKey = reader.take(decoded.bytesRead).slice();
    reader.unsigned(4);
    const payload = reader.head();
    if (payload.major !== 2 || payload.value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('SCHEMA_FIELD_INVALID', {
        layer: 1, stage: 'canonical-framing', offset: item.offset + payload.start
      });
    }
    const payloadLength = Number(payload.value);
    const payloadOffset = item.offset + reader.cursor;
    if (payloadOffset + payloadLength !== item.offset + item.length) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: payloadOffset });
    }
    return { ordinal, payloadOffset, payloadLength, sortKey };
  }
  const refMap = reader.head();
  if (refMap.major !== 5 || refMap.value !== 4n) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: item.offset + reader.cursor
  });
  reader.unsigned(0, 'SCHEMA_FIELD_INVALID'); reader.unsigned(1, 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED');
  reader.unsigned(1, 'SCHEMA_FIELD_INVALID'); const kind = reader.unsigned(undefined, 'SCHEMA_FIELD_INVALID');
  if (kind < 1 || kind > 65_535) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: item.offset + reader.cursor
  });
  reader.unsigned(2, 'SCHEMA_FIELD_INVALID'); reader.unsigned(1, 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED');
  reader.unsigned(3);
  const digestHead = reader.head();
  if (digestHead.major !== 2 || digestHead.value !== 32n) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'canonical-framing', offset: item.offset + digestHead.start
  });
  const digest = reader.take(32).slice();
  reader.unsigned(4);
  const payload = reader.head();
  if (payload.major !== 2 || payload.value > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'canonical-framing', offset: item.offset + payload.start
    });
  }
  const payloadLength = Number(payload.value);
  const payloadOffset = item.offset + reader.cursor;
  if (payloadOffset + payloadLength !== item.offset + item.length) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: payloadOffset });
  const rawRef = { kind, digest };
  return {
    ordinal, rawRef, payloadOffset, payloadLength,
    sortKey: encodeCanonical(new Map([[0, 1], [1, kind], [2, 1], [3, digest]]))
  };
}

async function readItem(scratch, file, item, limits) {
  if (item.length > limits.maxDecodedItemBytes) fail('LIMIT_MEMORY', { layer: 1, offset: item.offset });
  // The raw item, a possible canonical re-encoding, and the decoded graph can
  // coexist. Reserve the two wire-sized buffers first and give the CBOR reader
  // only the exact remainder; compact arrays/maps are not safely approximated
  // by a multiple of their encoded length.
  const fixedBytes = limits.residentBaseBytes + item.length * 2;
  limits.guard.memory(fixedBytes);
  const maxWorkingBytes = limits.maxMemoryBytes - fixedBytes;
  const bytes = Buffer.alloc(item.length);
  await scratch.readExactly(file, bytes, 0, bytes.length, item.offset);
  return { bytes, value: decodeCanonical(bytes, {
    maxBytes: item.length,
    maxDepth: Math.max(1, limits.nestingDepth),
    maxValueBytes: Math.min(limits.genericValueBytes, limits.maxDecodedItemBytes),
    maxContainerItems: limits.containerItems,
    maxWorkingBytes
  }) };
}

async function readItemIndex(scratch, file, index) {
  const record = Buffer.alloc(ITEM_INDEX_BYTES);
  await scratch.readExactly(file, record, 0, record.length, index * ITEM_INDEX_BYTES);
  return { offset: getU64(record, 0), length: getU64(record, 8), type: record.readUInt8(16) };
}

async function spoolInput(input, scratch, limits) {
  const inputFile = await scratch.createFile('sequence');
  const itemFile = await scratch.createFile('items');
  const inputWriter = new ScratchWriter(scratch, inputFile, limits.writeBufferBytes);
  const itemWriter = new ScratchWriter(scratch, itemFile, limits.writeBufferBytes);
  let largestItem = 0;
  let sourceBytes = 0;
  const scan = await visitLogicalBundle(input, {
    async onInputChunk(part) {
      limits.guard.time();
      if (part.length > limits.sequenceBytes - sourceBytes) fail('BUNDLE_BUDGET_EXCEEDED', {
        layer: 1, stage: 'configured-resource-preflight'
      });
      sourceBytes += part.length;
      await inputWriter.write(part);
    },
    async onItemEnd(item) {
      largestItem = Math.max(largestItem, item.bytes);
      await itemWriter.write(itemIndexRecord(item.offset, item.bytes, item.type));
    }
  }, {
    maxSequenceBytes: limits.sequenceBytes,
    maxItemBytes: limits.itemBytes,
    maxChunkBytes: limits.chunkBytes,
    maxMetadataBytes: limits.metadataBytes,
    maxValueBytes: limits.scannerValueBytes,
    maxCaptureBytes: limits.scannerCaptureBytes,
    maxContainerItems: limits.containerItems,
    maxNesting: Math.max(1, limits.nestingDepth),
    payloadChunkBytes: limits.readChunkBytes,
    maxItems: limits.items,
    guard: limits.guard
  });
  await inputWriter.flush();
  await itemWriter.flush();
  if (scan.items < 2) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  if (sourceBytes !== scan.bytes || inputFile.size !== scan.bytes || itemFile.size !== scan.items * ITEM_INDEX_BYTES) {
    fail('LIMIT_SCRATCH', { layer: 1 });
  }
  return { inputFile, itemFile, items: scan.items, bytes: scan.bytes, largestItem };
}

function headerState(value, spooled, limits) {
  if (!(value instanceof Map) || value.get(0) !== 1 || value.get(1) !== 1) {
    fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  }
  if (value.get(2) !== 1) fail('BUNDLE_MODE_UNSUPPORTED', { layer: 1 });
  const objectCount = Number(uint(value.get(3), limits.objects, 'BUNDLE_BUDGET_EXCEEDED', 1));
  const logicalCount = Number(uint(value.get(4), limits.logicalRecords, 'BUNDLE_BUDGET_EXCEEDED', 1));
  const rootCount = Number(uint(value.get(5), limits.roots, 'BUNDLE_BUDGET_EXCEEDED', 1));
  const expectedItems = objectCount + logicalCount + rootCount + 2;
  if (expectedItems > limits.items || spooled.items !== expectedItems) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  const declarations = value.get(6);
  if (!(declarations instanceof Map)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  const declaredBytes = uint(declarations.get(0), limits.sequenceBytes, 'BUNDLE_BUDGET_EXCEEDED', 1);
  const declaredLargest = uint(declarations.get(1), limits.itemBytes, 'BUNDLE_BUDGET_EXCEEDED', 1);
  const declaredEdges = uint(declarations.get(2), limits.traversalEdges, 'BUNDLE_BUDGET_EXCEEDED', 1);
  const declaredIndex = uint(declarations.get(3), limits.indexEntries, 'BUNDLE_BUDGET_EXCEEDED', 1);
  const indexEntries = objectCount + logicalCount;
  if (spooled.largestItem > limits.itemBytes || indexEntries > limits.indexEntries) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return {
    objectCount, logicalCount, rootCount, expectedItems,
    declaredBytes: Number(declaredBytes), declaredLargest: Number(declaredLargest),
    declaredEdges: Number(declaredEdges), declaredIndex: Number(declaredIndex), indexEntries
  };
}

function expectedType(index, state) {
  if (index === 0) return 1;
  if (index <= state.objectCount) return 2;
  if (index <= state.objectCount + state.logicalCount) return 3;
  if (index <= state.objectCount + state.logicalCount + state.rootCount) return 4;
  return 5;
}

async function hashPayload(scratch, file, envelope, limits, registry, opaque = false) {
  const reference = envelope.ref ?? envelope.rawRef;
  const hash = opaque
    ? createOpaqueObjectHashWriter(reference.kind, {
      maxBytes: reference.kind === 1 ? limits.chunkBytes : limits.metadataBytes
    })
    : createObjectHashWriter(reference.kind, {
      maxChunkBytes: limits.chunkBytes,
      maxMetadataBytes: limits.metadataBytes,
      registry
    });
  let payload;
  if (reference.kind !== 1) {
    if (envelope.payloadLength > limits.maxDecodedItemBytes) fail('LIMIT_MEMORY', { layer: 1, offset: envelope.payloadOffset });
    limits.guard.memory(limits.residentBaseBytes + envelope.payloadLength);
    payload = Buffer.alloc(envelope.payloadLength);
  }
  const buffer = payload ?? Buffer.alloc(Math.min(limits.readChunkBytes, Math.max(1, envelope.payloadLength)));
  let cursor = 0;
  while (cursor < envelope.payloadLength) {
    limits.guard.time();
    const length = Math.min(limits.readChunkBytes, envelope.payloadLength - cursor);
    if (payload) {
      await scratch.readExactly(file, payload, cursor, length, envelope.payloadOffset + cursor);
      hash.update(payload.subarray(cursor, cursor + length));
    } else {
      await scratch.readExactly(file, buffer, 0, length, envelope.payloadOffset + cursor);
      hash.update(buffer.subarray(0, length));
    }
    cursor += length;
  }
  const actual = hash.finish();
  const actualDigest = actual.digest ?? actual.bytes;
  if (!equalBytes(actualDigest, reference.digest)) fail('OBJECT_ID_MISMATCH', { layer: 1, offset: envelope.payloadOffset });
  return payload;
}

async function transcriptOf(scratch, inputFile, trailerOffset, limits) {
  const writer = createBundleTranscriptHashWriter({ maxBytes: limits.sequenceBytes });
  const buffer = Buffer.alloc(Math.min(limits.readChunkBytes, Math.max(1, trailerOffset)));
  let cursor = 0;
  while (cursor < trailerOffset) {
    limits.guard.time();
    const length = Math.min(buffer.length, trailerOffset - cursor);
    await scratch.readExactly(inputFile, buffer, 0, length, cursor);
    writer.update(buffer.subarray(0, length));
    cursor += length;
  }
  return writer.finish();
}

async function preflightLayerOne(spooled, scratch, limits, state, names, registry) {
  let duplicateOffset;
  let previousObject;
  for (let ordinal = 0; ordinal < state.objectCount; ordinal += 1) {
    limits.guard.time();
    const item = await readItemIndex(scratch, spooled.itemFile, 1 + ordinal);
    if (item.type !== 2) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const envelope = await objectEnvelope(scratch, spooled.inputFile, item, { opaqueReference: true });
    if (envelope.ordinal !== ordinal) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const sortKey = envelope.sortKey;
    if (previousObject) {
      const order = compareBytes(previousObject, sortKey);
      if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
      if (order === 0 && duplicateOffset === undefined) duplicateOffset = item.offset;
    }
    previousObject = sortKey;
  }

  let previousLogical;
  for (let ordinal = 0; ordinal < state.logicalCount; ordinal += 1) {
    limits.guard.time();
    const itemIndex = 1 + state.objectCount + ordinal;
    const item = await readItemIndex(scratch, spooled.itemFile, itemIndex);
    if (item.type !== 3) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const { value } = await readItem(scratch, spooled.inputFile, item, limits);
    if (!(value instanceof Map) || value.get(0) !== 1 || value.get(1) !== 3 ||
        uint(value.get(2)) !== BigInt(ordinal)) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    }
    const identity = rawDigest(value.get(3), item.offset);
    const record = value.get(4);
    const recordType = rawLogicalType(record, item.offset);
    const sortKey = [recordType.sortKey, identity];
    if (recordType.hashable && previousLogical) {
      const order = tupleCompare(previousLogical, sortKey);
      if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
      if (order === 0 && duplicateOffset === undefined) duplicateOffset = item.offset;
    }
    previousLogical = recordType.hashable ? sortKey : undefined;
  }

  let previousRoot;
  let previousRootIdentity;
  for (let ordinal = 0; ordinal < state.rootCount; ordinal += 1) {
    limits.guard.time();
    const itemIndex = 1 + state.objectCount + state.logicalCount + ordinal;
    const item = await readItemIndex(scratch, spooled.itemFile, itemIndex);
    if (item.type !== 4) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const { value } = await readItem(scratch, spooled.inputFile, item, limits);
    if (!(value instanceof Map) || value.get(0) !== 1 || value.get(1) !== 4 ||
        uint(value.get(2)) !== BigInt(ordinal)) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    }
    const rootKindBytes = encodeCanonical(value.get(3));
    const identityBytes = encodeCanonical(value.get(4));
    const roleBytes = encodeCanonical(value.get(5));
    const sortKey = [rootKindBytes, identityBytes, roleBytes];
    const identityKey = [rootKindBytes, identityBytes];
    if (previousRoot) {
      const order = tupleCompare(previousRoot, sortKey);
      if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
      if (order === 0 && duplicateOffset === undefined) duplicateOffset = item.offset;
    }
    if (previousRootIdentity && tupleCompare(previousRootIdentity, identityKey) === 0) {
      if (duplicateOffset === undefined) duplicateOffset = item.offset;
    }
    previousRoot = sortKey;
    previousRootIdentity = identityKey;
  }
  if (duplicateOffset !== undefined) {
    fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1, offset: duplicateOffset });
  }

  for (let ordinal = 0; ordinal < state.objectCount; ordinal += 1) {
    limits.guard.time();
    const item = await readItemIndex(scratch, spooled.itemFile, 1 + ordinal);
    const envelope = await objectEnvelope(scratch, spooled.inputFile, item);
    await hashPayload(scratch, spooled.inputFile, envelope, limits, names, true);
  }
  for (let ordinal = 0; ordinal < state.logicalCount; ordinal += 1) {
    limits.guard.time();
    const itemIndex = 1 + state.objectCount + ordinal;
    const item = await readItemIndex(scratch, spooled.itemFile, itemIndex);
    const { value } = await readItem(scratch, spooled.inputFile, item, limits);
    const identity = rawDigest(value.get(3), item.offset);
    const record = value.get(4);
    const recordType = rawLogicalType(record, item.offset);
    if (!recordType.hashable) continue;
    const encoded = encodeCanonical(record, {
      maxBytes: limits.maxDecodedItemBytes,
      maxValueBytes: Math.min(limits.genericValueBytes, limits.maxDecodedItemBytes),
      maxContainerItems: limits.containerItems,
      maxDepth: Math.max(1, limits.nestingDepth)
    });
    const writer = createLogicalRecordHashWriter(recordType.type);
    writer.update(encoded);
    const actual = writer.finish();
    if (!equalBytes(identity, actual.bytes)) {
      fail('BUNDLE_RECORD_ID_MISMATCH', { layer: 1, offset: item.offset });
    }
  }

  const trailerItem = await readItemIndex(scratch, spooled.itemFile, state.expectedItems - 1);
  if (trailerItem.type !== 5) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: trailerItem.offset });
  const { value: trailer } = await readItem(scratch, spooled.inputFile, trailerItem, limits);
  if (!(trailer instanceof Map) || trailer.get(0) !== 1 || trailer.get(1) !== 5 ||
      uint(trailer.get(2)) !== BigInt(state.objectCount) ||
      uint(trailer.get(3)) !== BigInt(state.logicalCount) ||
      uint(trailer.get(4)) !== BigInt(state.rootCount) ||
      uint(trailer.get(5)) !== BigInt(state.expectedItems)) {
    fail('BUNDLE_TRAILER_MISMATCH', { layer: 1, offset: trailerItem.offset });
  }
  const expectedTranscript = rawDigest(trailer.get(6), trailerItem.offset);
  const transcript = await transcriptOf(scratch, spooled.inputFile, trailerItem.offset, limits);
  if (!equalBytes(expectedTranscript, transcript.bytes)) {
    fail('BUNDLE_TRAILER_MISMATCH', { layer: 1, offset: trailerItem.offset });
  }
  return { trailer, transcript };
}

function mark(bits, ordinal) {
  const byte = ordinal >>> 3;
  const mask = 1 << (ordinal & 7);
  if ((bits[byte] & mask) !== 0) return false;
  bits[byte] |= mask;
  return true;
}

async function findObject(index, ref) {
  const key = referenceRecord(ref);
  const exact = await index.find(key);
  if (exact) return getU64(exact, 34);
  const firstKind = Buffer.alloc(REFERENCE_BYTES);
  Buffer.from(ref.digest).copy(firstKind, 0);
  const candidatePosition = await index.lowerBound(firstKind);
  if (candidatePosition < index.count) {
    const candidate = await index.record(candidatePosition);
    if (compareBytes(candidate.subarray(0, 32), ref.digest) === 0) {
      fail('OBJECT_REFERENCE_KIND_MISMATCH', {
        layer: 2, stage: 'closure-and-reference-resolution'
      });
    }
  }
  fail('BUNDLE_CLOSURE_MISSING', { layer: 2 });
}

async function processSpooled(spooled, scratch, limits, options) {
  const names = options.registry?.kindNames ?? KIND_NAMES;
  const operation = options.operation;
  const first = await readItemIndex(scratch, spooled.itemFile, 0);
  if (first.type !== 1) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  const header = (await readItem(scratch, spooled.inputFile, first, limits)).value;
  const state = headerState(header, spooled, limits);
  const { trailer, transcript } = await preflightLayerOne(
    spooled, scratch, limits, state, names, options.registry
  );
  if (spooled.bytes > state.declaredBytes || spooled.largestItem > state.declaredLargest ||
      state.indexEntries > state.declaredIndex) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }
  const knownSchema = deferredStageCollector(2, 'known-schema');
  const registrySemantics = deferredStageCollector(3, 'registry-semantics');
  const headerValidation = knownSchema.observe(() => validateBundleItem(header, {
    hardLimits: options.hardLimits, semantic: false
  }));
  if (options.registry && headerValidation) registrySemantics.observe(() => validateBundleItem(header, {
    registry: options.registry, hardLimits: options.hardLimits, operation
  }));
  const trailerValidation = knownSchema.observe(() => validateBundleItem(trailer, {
    hardLimits: options.hardLimits, semantic: false
  }));
  if (options.registry && trailerValidation) registrySemantics.observe(() => validateBundleItem(trailer, {
    registry: options.registry, hardLimits: options.hardLimits, operation
  }));

  const objectSorter = new FixedRecordSorter({
    scratch, recordBytes: OBJECT_LOOKUP_BYTES, keyBytes: REFERENCE_BYTES,
    maxRunBytes: limits.maxRunBytes, maxOpenRuns: limits.maxOpenRuns,
    writeBufferBytes: limits.writeBufferBytes, check: () => limits.guard.time()
  });
  const logicalSorter = new FixedRecordSorter({
    scratch, recordBytes: LOGICAL_LOOKUP_BYTES, keyBytes: 32,
    maxRunBytes: limits.maxRunBytes, maxOpenRuns: limits.maxOpenRuns,
    writeBufferBytes: limits.writeBufferBytes, duplicateCode: 'BUNDLE_DUPLICATE_IDENTITY',
    check: () => limits.guard.time()
  });
  const ordinalFile = await scratch.createFile('object-ordinals');
  const edgeFile = await scratch.createFile('edges');
  const logicalReferenceFile = await scratch.createFile('logical-references');
  const objectRootFile = await scratch.createFile('object-roots');
  const logicalRootFile = await scratch.createFile('logical-roots');
  const ordinalWriter = new ScratchWriter(scratch, ordinalFile, limits.writeBufferBytes);
  const edgeWriter = new ScratchWriter(scratch, edgeFile, limits.writeBufferBytes);
  const logicalReferenceWriter = new ScratchWriter(scratch, logicalReferenceFile, limits.writeBufferBytes);
  const objectRootWriter = new ScratchWriter(scratch, objectRootFile, limits.writeBufferBytes);
  const logicalRootWriter = new ScratchWriter(scratch, logicalRootFile, limits.writeBufferBytes);

  let previousObject;
  let objectEdgeCount = 0;
  for (let ordinal = 0; ordinal < state.objectCount; ordinal += 1) {
    limits.guard.time();
    const item = await readItemIndex(scratch, spooled.itemFile, 1 + ordinal);
    if (item.type !== expectedType(1 + ordinal, state)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const envelope = await objectEnvelope(scratch, spooled.inputFile, item);
    envelope.ref = new ObjectRef(envelope.rawRef.kind, envelope.rawRef.digest, names);
    if (envelope.ordinal !== ordinal) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const sortKey = envelope.sortKey;
    if (previousObject && compareBytes(previousObject, sortKey) >= 0) {
      fail(compareBytes(previousObject, sortKey) === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID',
        { layer: 1, offset: item.offset });
    }
    previousObject = sortKey;
    const payload = await hashPayload(scratch, spooled.inputFile, envelope, limits, names);
    const edgeStart = objectEdgeCount;
    if (envelope.ref.kind !== 1) {
      const fixedDecodeBytes = limits.residentBaseBytes + payload.length * 2;
      limits.guard.memory(fixedDecodeBytes);
      const decoded = knownSchema.observe(() => decodeMetadata(payload, {
        hardLimits: options.hardLimits,
        semantic: false,
        maxWorkingBytes: limits.maxMemoryBytes - fixedDecodeBytes
      }));
      if (decoded) {
        const sameKind = decoded.kind === envelope.ref.kind;
        if (!sameKind) knownSchema.observe(() => fail('OBJECT_REFERENCE_KIND_MISMATCH', {
          layer: 2, stage: 'known-schema', offset: envelope.payloadOffset
        }));
        if (options.registry) registrySemantics.observe(() => validateKnownSchema(decoded.value, decoded.kind, {
          registry: options.registry, hardLimits: options.hardLimits, operation
        }));
        if (sameKind) for (const child of iterateObjectReferences(envelope.ref.kind, decoded.value)) {
          objectEdgeCount += 1;
          if (objectEdgeCount > limits.traversalEdges) {
            fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
          }
          await edgeWriter.write(referenceRecord(child));
        }
      }
    } else if (options.registry) {
      registrySemantics.observe(() => {
        registryAssignmentDecision(options.registry, 'object-kinds', 1, operation);
        registryAssignmentDecision(options.registry, 'hash-algorithms', 1, operation);
      });
    }
    await ordinalWriter.write(objectOrdinalRecord(edgeStart, objectEdgeCount - edgeStart));
    await objectSorter.add(objectLookupRecord(envelope.ref, ordinal));
  }
  await ordinalWriter.flush();
  await edgeWriter.flush();
  const objectIndex = await objectSorter.finish();

  let previousLogical;
  let logicalEdges = 0;
  for (let ordinal = 0; ordinal < state.logicalCount; ordinal += 1) {
    limits.guard.time();
    const itemIndex = 1 + state.objectCount + ordinal;
    const item = await readItemIndex(scratch, spooled.itemFile, itemIndex);
    if (item.type !== expectedType(itemIndex, state)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const { value } = await readItem(scratch, spooled.inputFile, item, limits);
    const itemValidation = knownSchema.observe(() => validateBundleItem(value, {
      hardLimits: options.hardLimits, semantic: false
    }));
    if (options.registry && itemValidation) registrySemantics.observe(() => validateBundleItem(value, {
      registry: options.registry, hardLimits: options.hardLimits, operation
    }));
    if (uint(value.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const identity = Digest.fromMap(value.get(3));
    const record = value.get(4);
    const validation = knownSchema.observe(() => validateLogicalRecord(record, {
      hardLimits: options.hardLimits, semantic: false
    }));
    if (options.registry && validation) registrySemantics.observe(() => validateLogicalRecord(record, {
      registry: options.registry, hardLimits: options.hardLimits, operation
    }));
    await logicalSorter.add(logicalLookupRecord(identity, ordinal));
    if (validation) for (const ref of iterateLogicalRecordReferences(validation.type, record)) {
      logicalEdges += 1;
      if (objectEdgeCount + logicalEdges > limits.traversalEdges) {
        fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
      }
      await logicalReferenceWriter.write(referenceRecord(ref));
    }
  }

  const logicalIndex = await logicalSorter.finish();
  const reachedBits = new Uint8Array(Math.ceil(state.objectCount / 8));
  limits.guard.memory(limits.residentBaseBytes + reachedBits.length);

  let previousRoot;
  let previousRootIdentity;
  let objectRoots = 0;
  let logicalRoots = 0;
  for (let ordinal = 0; ordinal < state.rootCount; ordinal += 1) {
    limits.guard.time();
    const itemIndex = 1 + state.objectCount + state.logicalCount + ordinal;
    const item = await readItemIndex(scratch, spooled.itemFile, itemIndex);
    if (item.type !== expectedType(itemIndex, state)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    const { value } = await readItem(scratch, spooled.inputFile, item, limits);
    const validation = knownSchema.observe(() => validateBundleItem(value, {
      hardLimits: options.hardLimits, semantic: false
    }));
    if (options.registry && validation) registrySemantics.observe(() => validateBundleItem(value, {
      registry: options.registry, hardLimits: options.hardLimits, operation
    }));
    if (uint(value.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    if (!validation) continue;
    const rootKind = Number(value.get(3));
    const identityBytes = encodeCanonical(value.get(4));
    const roleBytes = encodeCanonical(value.get(5));
    const sortKey = [Uint8Array.of(rootKind), identityBytes, roleBytes];
    if (previousRoot && tupleCompare(previousRoot, sortKey) >= 0) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset: item.offset });
    }
    previousRoot = sortKey;
    const identityKey = [Uint8Array.of(rootKind), identityBytes];
    if (previousRootIdentity && tupleCompare(previousRootIdentity, identityKey) === 0) {
      fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1, offset: item.offset });
    }
    previousRootIdentity = identityKey;
    // Reconstruct the typed values after schema validation so registry and
    // algorithm failures remain identical to the in-memory verifier.
    ProfileRef.fromMap(value.get(5));
    if (rootKind === 1) {
      const ref = ObjectRef.fromMap(value.get(4), names);
      await objectRootWriter.write(referenceRecord(ref));
      objectRoots += 1;
    } else {
      const identity = Digest.fromMap(value.get(4));
      await logicalRootWriter.write(identity.bytes);
      logicalRoots += 1;
    }
  }
  await logicalReferenceWriter.flush();
  await objectRootWriter.flush();
  await logicalRootWriter.flush();

  knownSchema.throwSelected();

  const traversalEdges = objectEdgeCount + logicalEdges;
  if (traversalEdges > state.declaredEdges) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }

  if (state.objectCount > 0 && objectRoots === 0) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  if (logicalRoots !== state.logicalCount) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  const logicalRootRecord = Buffer.alloc(32);
  for (let ordinal = 0; ordinal < state.logicalCount; ordinal += 1) {
    await scratch.readExactly(logicalRootFile, logicalRootRecord, 0, 32, ordinal * 32);
    const supplied = await logicalIndex.record(ordinal);
    if (compareBytes(logicalRootRecord, supplied.subarray(0, 32)) !== 0) {
      fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
    }
  }

  const queueFile = await scratch.createFile('queue');
  const queueWriter = new ScratchWriter(scratch, queueFile, limits.writeBufferBytes);
  for (const source of [objectRootFile, logicalReferenceFile]) {
    const bufferBytes = Math.max(REFERENCE_BYTES,
      Math.floor(limits.readChunkBytes / REFERENCE_BYTES) * REFERENCE_BYTES);
    const buffer = Buffer.alloc(bufferBytes);
    let offset = 0;
    while (offset < source.size) {
      limits.guard.time();
      const length = Math.min(buffer.length, source.size - offset);
      await scratch.readExactly(source, buffer, 0, length, offset);
      await queueWriter.write(buffer.subarray(0, length));
      offset += length;
    }
  }
  let queuedRecords = objectRoots + logicalEdges;
  await queueWriter.flush();
  await scratch.removeFile(objectRootFile);
  await scratch.removeFile(logicalReferenceFile);
  await scratch.removeFile(logicalRootFile);
  let queueCursor = 0;
  let reachedCount = 0;
  const queueRecord = Buffer.alloc(REFERENCE_BYTES);
  const ordinalRecord = Buffer.alloc(OBJECT_ORDINAL_BYTES);
  const edgeRecord = Buffer.alloc(REFERENCE_BYTES);
  while (queueCursor < queuedRecords) {
    limits.guard.time();
    if (queueCursor * REFERENCE_BYTES >= queueFile.size) await queueWriter.flush();
    await scratch.readExactly(queueFile, queueRecord, 0, queueRecord.length, queueCursor * REFERENCE_BYTES);
    queueCursor += 1;
    const ref = referenceFromRecord(queueRecord, names);
    const ordinal = await findObject(objectIndex, ref);
    if (!mark(reachedBits, ordinal)) continue;
    reachedCount += 1;
    await scratch.readExactly(ordinalFile, ordinalRecord, 0, ordinalRecord.length, ordinal * OBJECT_ORDINAL_BYTES);
    const edgeStart = getU64(ordinalRecord, 0);
    const edgeCount = getU64(ordinalRecord, 8);
    for (let index = 0; index < edgeCount; index += 1) {
      await scratch.readExactly(edgeFile, edgeRecord, 0, edgeRecord.length, (edgeStart + index) * REFERENCE_BYTES);
      await queueWriter.write(edgeRecord);
      queuedRecords += 1;
    }
  }
  if (reachedCount !== state.objectCount) fail('BUNDLE_CLOSURE_EXTRA', { layer: 2 });

  registrySemantics.throwSelected();
  return Object.freeze({
    highestLayer: options.registry ? 3 : 2,
    bytes: spooled.bytes,
    items: spooled.items,
    objectCount: state.objectCount,
    logicalRecordCount: state.logicalCount,
    rootCount: state.rootCount,
    traversalEdges,
    indexEntries: state.indexEntries,
    transcriptDigest: toHex(transcript.bytes),
    metrics: Object.freeze({
      elapsedMilliseconds: limits.guard.elapsedMilliseconds(),
      peakScratchBytes: scratch.peakBytes,
      scratchFiles: scratch.createdFiles,
      indexRuns: objectIndex.runCount + logicalIndex.runCount
    })
  });
}

/**
 * Verifies a logical-bundle-v1 byte stream with bounded retained buffers and
 * exact disk-backed identity/closure indexes. The scratch directory is always
 * caller supplied; all private files are removed on success or failure.
 */
export async function verifyLogicalBundleStream(input, options = {}) {
  const semantic = codecValidationContext(options);
  options = { ...options, ...semantic };
  if (options.semanticValidator !== undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const limits = configured(options);
  const scratch = await BundleScratch.create({
    scratchDirectory: options.scratchDirectory,
    maxScratchBytes: limits.maxScratchBytes,
    verifyBufferBytes: limits.readChunkBytes,
    check: () => limits.guard.time()
  });
  let result;
  let failure;
  try {
    limits.guard.time();
    const spooled = await spoolInput(input, scratch, limits);
    result = await processSpooled(spooled, scratch, limits, options);
  } catch (error) {
    failure = error;
  }
  try { await scratch.cleanup(); } catch (error) { failure ??= error; }
  if (failure) throw failure;
  return result;
}

async function* fileParts(handle, initial, limits) {
  const buffer = Buffer.alloc(Math.min(limits.readChunkBytes, Math.max(1, initial.size)));
  let offset = 0;
  while (offset < initial.size) {
    limits.guard.time();
    const length = Math.min(buffer.length, initial.size - offset);
    let result;
    try { result = await handle.read(buffer, 0, length, offset); } catch (cause) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset, cause });
    }
    if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead <= 0 || result.bytesRead > length) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, offset });
    }
    offset += result.bytesRead;
    yield buffer.subarray(0, result.bytesRead);
  }
}

/** Same-handle, no-follow regular-file wrapper for the spooled verifier. */
export async function verifyLogicalBundleFile(path, options = {}) {
  const semantic = codecValidationContext(options);
  options = { ...options, ...semantic };
  if (typeof path !== 'string' || path.length === 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const limits = configured(options);
  let handle;
  try {
    try {
      handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    } catch (cause) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight', cause });
    }
    let initial;
    try { initial = await handle.stat(); } catch (cause) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight', cause });
    }
    if (!initial.isFile()) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    if (initial.size > limits.sequenceBytes) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
    }
    const result = await verifyLogicalBundleStream(fileParts(handle, initial, limits), options);
    let final;
    try { final = await handle.stat(); } catch (cause) { fail('BUNDLE_SEQUENCE_INVALID', { layer: 1, cause }); }
    if (!final.isFile() || final.size !== initial.size || final.mtimeMs !== initial.mtimeMs) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    }
    return result;
  } finally {
    await handle?.close().catch(() => {});
  }
}
