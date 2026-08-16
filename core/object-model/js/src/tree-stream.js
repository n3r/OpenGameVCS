import { constants } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { resolve, join } from 'node:path';
import { encodeCanonical } from './cbor.js';
import { fail, isOgvcsError } from './errors.js';
import { createObjectHashWriter } from './hash.js';
import { configuredHardLimit, enforceHardLimit, hardLimitMaximum } from './hard-limits.js';
import { profileDecision, registryAssignmentDecision } from './registry.js';
import { validateKnownSchema } from './schema.js';
import { FileId, KIND_NAMES, ObjectRef, ProfileRef } from './types.js';
import {
  ResourceGuard, asCount, asLimit, cborHeader, checkedBigUint, compareBytes,
  exactMap, guardedAsyncIterable, toAsyncIterable, writeFully
} from './scale-util.js';

const MAX_TREE_ENTRIES = hardLimitMaximum('tree-entries');
const MAX_METADATA_BYTES = hardLimitMaximum('metadata-payload-bytes');
const MAX_LOGICAL_BYTES = BigInt(hardLimitMaximum('logical-file-bytes'));
const MAX_BASENAME_BYTES = hardLimitMaximum('path-segment-bytes');
const MAX_GENERIC_VALUE_BYTES = hardLimitMaximum('generic-text-or-byte-value-bytes');
const MAX_CONTAINER_ITEMS = hardLimitMaximum('manifest-chunks');
const MAX_NESTING = hardLimitMaximum('cbor-nesting-depth');
const CONTENT_FAMILIES = new Set(['content-policy', 'fixture-content-policy']);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const RUN_HEADER_BYTES = 38;
const RUN_RECORD_OVERHEAD = 96;
const FILE_ID_INDEX_OVERHEAD = 64;
const MAX_DEFAULT_MEMORY_INDEX_ITEMS = 100_000;

function namesFor(registry) { return registry?.kindNames ?? KIND_NAMES; }

function descriptorMap(value, registry) {
  const ref = value instanceof ObjectRef ? value : ObjectRef.fromMap(value, namesFor(registry));
  if (ref.kind !== 6) fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
  return ref.toMap();
}

function profileMap(value, registry, operation) {
  const ref = value instanceof ProfileRef ? value : ProfileRef.fromMap(value);
  if (registry) {
    const decision = profileDecision(registry, ref, operation);
    if (!CONTENT_FAMILIES.has(decision.family)) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  return { ref, map: ref.toMap() };
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

function basenameBytes(value, options) {
  if (typeof value !== 'string' || value.normalize('NFC') !== value || value === '.' || value === '..' ||
      value.includes('/') || value.includes('\0')) fail('PATH_CORE_INVALID', { layer: 2 });
  const bytes = textEncoder.encode(value);
  let roundTrip;
  try { roundTrip = textDecoder.decode(bytes); } catch { fail('PATH_CORE_INVALID', { layer: 2 }); }
  const maximum = configuredHardLimit('path-segment-bytes', options?.hardLimits?.['path-segment-bytes']);
  if (roundTrip !== value || bytes.length < 1 || bytes.length > maximum) {
    fail('PATH_CORE_INVALID', { layer: 2 });
  }
  return bytes;
}

function validateEntry(value, options) {
  exactMap(value, [0, 1, 2, 3, 4, 5, 6]);
  const name = basenameBytes(value.get(0), options);
  const kind = value.get(1);
  const mode = value.get(3);
  if (!Number.isInteger(kind) || kind < 1 || kind > 4 || mode !== kind) {
    fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  }
  if (options.registry) {
    registryAssignmentDecision(options.registry, 'entry-kinds', kind, options.operation);
    registryAssignmentDecision(options.registry, 'entry-modes', mode, options.operation);
    registryAssignmentDecision(options.registry, 'hash-algorithms', 1, options.operation);
  }
  const fileId = new FileId(value.get(2)).bytes;
  const target = ObjectRef.fromMap(value.get(4), namesFor(options.registry));
  const targetKind = kind === 1 ? 3 : 2;
  if (target.kind !== targetKind) {
    fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
  }
  if (options.registry) registryAssignmentDecision(options.registry, 'object-kinds', targetKind, options.operation);
  enforceHardLimit(undefined, 'logical-file-bytes', value.get(5), {
    maximum: options.hardLimits?.['logical-file-bytes'], code: 'LIMIT_LOGICAL_BYTES', layer: 2
  });
  const logicalSize = checkedBigUint(value.get(5), MAX_LOGICAL_BYTES, 'LIMIT_LOGICAL_BYTES');
  if (kind === 1 && logicalSize !== 0n) fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  profileMap(value.get(6), options.registry, options.operation);
  const encoded = encodeResident(value, options, options.maxMemoryBytes, {
    maxValueBytes: MAX_GENERIC_VALUE_BYTES,
    maxContainerItems: 16
  });
  return { encoded, name, fileId, kind, logicalSize };
}

function treePrefix(options) {
  const { descriptor, requiredFeatures, extensions, entryCount, registry, operation } = options;
  const descriptorValue = descriptorMap(descriptor, registry);
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
  push(cborHeader(5, extensions === undefined ? 5 : 6));
  pushValue(0); pushValue(1); pushValue(1); pushValue(3); pushValue(2); pushValue(requiredFeatures);
  if (extensions !== undefined) { pushValue(3); pushValue(extensions); }
  pushValue(16); pushValue(descriptorValue); pushValue(17); push(cborHeader(4, entryCount));
  const common = new Map([[0, 1], [1, 3], [2, requiredFeatures], [16, descriptorValue], [17, []]]);
  if (extensions !== undefined) common.set(3, extensions);
  validateKnownSchema(common, 3, { registry, operation, hardLimits: options.hardLimits });
  return pieces;
}

function optionsFor(input) {
  const maxItems = Math.min(
    configuredHardLimit('tree-entries', input.hardLimits?.['tree-entries']),
    configuredHardLimit('tree-entries', asLimit(input.maxItems, MAX_TREE_ENTRIES))
  );
  enforceHardLimit(undefined, 'tree-entries', input.entryCount, {
    maximum: maxItems, code: 'LIMIT_COUNT', layer: 2
  });
  const entryCount = asCount(input.entryCount, maxItems);
  const maxBytes = Math.min(
    configuredHardLimit('metadata-payload-bytes', input.hardLimits?.['metadata-payload-bytes']),
    configuredHardLimit('metadata-payload-bytes', asLimit(input.maxBytes, MAX_METADATA_BYTES))
  );
  const maxMemoryBytes = asLimit(input.maxMemoryBytes, 67_108_864);
  const guard = new ResourceGuard({ maxTimeMs: input.maxTimeMs, maxMemoryBytes });
  guard.time();
  if (!Array.isArray(input.requiredFeatures ?? [])) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return {
    ...input, entryCount, maxItems, maxBytes, maxMemoryBytes, guard,
    requiredFeatures: input.requiredFeatures ?? [], operation: input.operation ?? 'conformance'
  };
}

function emptyStats() { return { count: 0, logicalBytes: 0n, kinds: [0, 0, 0, 0, 0] }; }

function addStats(stats, entry) {
  stats.count += 1;
  stats.logicalBytes += entry.logicalSize;
  stats.kinds[entry.kind] += 1;
}

function stableSummary(reference, stats, metadataBytes) {
  return Object.freeze({
    format: 1,
    kind: 3,
    objectRef: reference.toString(),
    entryCount: stats.count,
    metadataBytes,
    logicalBytes: stats.logicalBytes.toString(),
    entriesByKind: Object.freeze({
      directory: stats.kinds[1], regular: stats.kinds[2], executable: stats.kinds[3], symlink: stats.kinds[4]
    })
  });
}

function createEmitter(options) {
  const hash = createObjectHashWriter(3, {
    maxMetadataBytes: options.maxBytes,
    registry: namesFor(options.registry)
  });
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

function memoryFileIdIndex(options) {
  if (options.entryCount > MAX_DEFAULT_MEMORY_INDEX_ITEMS) fail('LIMIT_MEMORY', { layer: 1 });
  const ids = new Set();
  return {
    async add(value) {
      const key = Buffer.from(value).toString('hex');
      if (ids.has(key)) fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
      options.guard.memory((ids.size + 1) * FILE_ID_INDEX_OVERHEAD);
      ids.add(key);
    },
    async finish() { const count = ids.size; ids.clear(); return { count, peakScratchBytes: 0, runCount: 0 }; },
    async abort() { ids.clear(); }
  };
}

function suppliedFileIdIndex(value) {
  if (!value || typeof value.add !== 'function' || typeof value.finish !== 'function' ||
      typeof value.abort !== 'function') fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return value;
}

async function abortFileIdIndex(fileIds, guard) {
  const abort = signal => fileIds.abort({ signal });
  if (guard.signal.aborted) {
    guard.cleanup(abort);
    return;
  }
  await guard.wait(abort).catch(() => {});
}

async function emitPrefix(emitter, prefix, guard) {
  const resident = prefix.reduce((total, part) => total + part.length, 0);
  guard.memory(resident);
  for (const part of prefix) await emitter.emit(part);
}

/**
 * Validate and write a canonical kind-3 one-directory tree from an already
 * UTF-8-byte-ordered iterable. The definite CBOR array count is declared up
 * front and is checked against the actual number yielded.
 */
export async function writeOrderedTree(input) {
  const options = optionsFor(input ?? {});
  const entries = toAsyncIterable(options.entries);
  const fileIds = options.fileIdIndex === undefined ? memoryFileIdIndex(options) : suppliedFileIdIndex(options.fileIdIndex);
  const prefix = treePrefix(options);
  const emitter = createEmitter(options);
  const stats = emptyStats();
  let previous;
  try {
    await emitPrefix(emitter, prefix, options.guard);
    for await (const raw of guardedAsyncIterable(entries, options.guard)) {
      options.guard.time();
      stats.count += 1;
      if (stats.count > options.maxItems) {
        fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
      }
      if (stats.count > options.entryCount) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
      const entry = validateEntry(raw, options);
      options.guard.memory(entry.encoded.length + entry.name.length + RUN_RECORD_OVERHEAD);
      if (previous && compareBytes(previous, entry.name) >= 0) fail('TREE_ENTRY_ORDER_INVALID', { layer: 2 });
      previous = entry.name.slice();
      const accepted = await options.guard.wait(signal => fileIds.add(entry.fileId, { signal }));
      if (accepted === false) fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
      stats.logicalBytes += entry.logicalSize;
      stats.kinds[entry.kind] += 1;
      await emitter.emit(entry.encoded);
    }
    if (stats.count !== options.entryCount) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    const uniqueness = await options.guard.wait(signal => fileIds.finish(stats.count, { signal }));
    if (uniqueness === false || (uniqueness?.count !== undefined && uniqueness.count !== stats.count)) {
      fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
    }
    const finished = emitter.finish();
    return Object.freeze({
      objectRef: finished.reference,
      summary: stableSummary(finished.reference, stats, finished.bytes),
      metrics: Object.freeze({
        elapsedMilliseconds: options.guard.elapsedMilliseconds(),
        peakScratchBytes: uniqueness?.peakScratchBytes ?? 0,
        runCount: uniqueness?.runCount ?? 0
      })
    });
  } catch (error) {
    await abortFileIdIndex(fileIds, options.guard);
    throw error;
  }
}

async function assertScratchDirectory(directory) {
  if (typeof directory !== 'string' || directory.length === 0) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  const requested = resolve(directory);
  let supplied;
  try { supplied = await lstat(requested); } catch (cause) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight', cause });
  }
  if (!supplied.isDirectory() || supplied.isSymbolicLink()) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  // Canonicalize any platform-owned ancestor aliases (for example macOS
  // /var -> /private/var) once, then create every run beneath that fixed path.
  const target = await realpath(requested);
  const final = await lstat(target);
  if (!final.isDirectory() || final.isSymbolicLink()) fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  return target;
}

class ScratchSpace {
  constructor(directory, maximum) {
    this.directory = directory;
    this.maximum = maximum;
    this.current = 0;
    this.peak = 0;
    this.files = new Map();
  }

  async create() {
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const path = join(this.directory, `.ogvcs-tree-${randomBytes(12).toString('hex')}.run`);
      try {
        const handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY |
          (constants.O_NOFOLLOW ?? 0), 0o600);
        this.files.set(path, 0);
        return {
          path, handle, hash: createHash('sha256'), identity: undefined, digest: undefined
        };
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
      }
    }
    fail('LIMIT_SCRATCH', { layer: 1 });
  }

  reserve(path, amount) {
    if (!Number.isSafeInteger(amount) || amount < 0 || amount > this.maximum - this.current) {
      fail('LIMIT_SCRATCH', { layer: 1 });
    }
    this.current += amount;
    this.peak = Math.max(this.peak, this.current);
    this.files.set(path, (this.files.get(path) ?? 0) + amount);
  }

  async remove(path) {
    const size = this.files.get(path);
    if (size === undefined) return;
    await unlink(path);
    this.files.delete(path);
    this.current -= size;
  }

  async cleanup() {
    const failures = [];
    for (const path of [...this.files.keys()]) {
      try { await this.remove(path); } catch (error) { failures.push(error); }
    }
    if (failures.length > 0) throw failures[0];
  }
}

function recordBytes(record) {
  const header = new Uint8Array(RUN_HEADER_BYTES);
  const view = new DataView(header.buffer);
  view.setUint16(0, record.name.length, false);
  view.setUint32(2, record.encoded.length, false);
  const checksum = createHash('sha256').update(record.name).update(record.encoded).digest();
  header.set(checksum, 6);
  return [header, record.name, record.encoded];
}

async function appendRecord(space, run, record) {
  for (const part of recordBytes(record)) {
    space.reserve(run.path, part.length);
    await writeFully(run.handle, part);
    run.hash.update(part);
  }
  run.size = space.files.get(run.path);
  run.count += 1;
}

async function closeRun(run) {
  if (run.handle) {
    try {
      const identity = await run.handle.stat();
      if (!identity.isFile() || identity.size !== run.size) fail('LIMIT_SCRATCH', { layer: 1 });
      await run.handle.close();
      run.handle = undefined;
      run.identity = identity;
      run.digest = run.hash.digest();
      run.hash = undefined;
    } catch (error) {
      await run.handle?.close().catch(() => {});
      run.handle = undefined;
      if (isOgvcsError(error)) throw error;
      fail('LIMIT_SCRATCH', { layer: 1, cause: error });
    }
  }
  return run;
}

function sameFile(left, right) {
  const identitiesAvailable = left.dev !== 0 && left.ino !== 0 && right.dev !== 0 && right.ino !== 0;
  const metadataSame = left.size === right.size && left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs && left.birthtimeMs === right.birthtimeMs;
  return metadataSame && (!identitiesAvailable || (left.dev === right.dev && left.ino === right.ino)) &&
    right.isFile() && !right.isSymbolicLink();
}

async function openVerifiedRun(run, guard, alignment = 1) {
  if (run.handle || !run.identity || !run.digest || !Number.isSafeInteger(run.size) || run.size < 0) {
    fail('LIMIT_SCRATCH', { layer: 1 });
  }
  let handle;
  try {
    handle = await open(run.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const info = await handle.stat();
    if (!sameFile(run.identity, info) || info.size !== run.size || info.size % alignment !== 0) {
      fail('LIMIT_SCRATCH', { layer: 1 });
    }
    if (run.size > 0 && guard.maxMemoryBytes < 1) fail('LIMIT_MEMORY', { layer: 1 });
    const verifyBytes = run.size === 0 ? 0 : Math.min(65_536, run.size, guard.maxMemoryBytes);
    guard.memory(verifyBytes);
    const buffer = Buffer.alloc(verifyBytes);
    const hash = createHash('sha256');
    let position = 0;
    while (position < run.size) {
      guard.time();
      const length = Math.min(buffer.length, run.size - position);
      const result = await handle.read(buffer, 0, length, position);
      if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead !== length) {
        fail('LIMIT_SCRATCH', { layer: 1 });
      }
      hash.update(buffer.subarray(0, length));
      position += length;
    }
    if (!hash.digest().equals(run.digest)) fail('LIMIT_SCRATCH', { layer: 1 });
    return { handle, size: info.size };
  } catch (error) {
    await handle?.close().catch(() => {});
    if (isOgvcsError(error)) throw error;
    fail('LIMIT_SCRATCH', { layer: 1, cause: error });
  }
}

async function readExactly(handle, length, position) {
  const result = new Uint8Array(length);
  let offset = 0;
  while (offset < length) {
    const read = await handle.read(result, offset, length - offset, position + offset);
    if (read.bytesRead <= 0) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    offset += read.bytesRead;
  }
  return result;
}

class RunReader {
  constructor(run, handle, size, guard) {
    this.run = run;
    this.handle = handle;
    this.size = size;
    this.guard = guard;
    this.offset = 0;
  }

  static async open(run, guard) {
    const { handle, size } = await openVerifiedRun(run, guard);
    return new RunReader(run, handle, size, guard);
  }

  async next() {
    this.guard.time();
    if (this.offset === this.size) return undefined;
    if (this.size - this.offset < RUN_HEADER_BYTES) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    const header = await readExactly(this.handle, RUN_HEADER_BYTES, this.offset);
    this.offset += RUN_HEADER_BYTES;
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    const nameLength = view.getUint16(0, false);
    const encodedLength = view.getUint32(2, false);
    if (nameLength < 1 || nameLength > MAX_BASENAME_BYTES || encodedLength < 1 ||
        encodedLength > this.guard.maxMemoryBytes || nameLength + encodedLength > this.size - this.offset) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    this.guard.memory(nameLength + encodedLength + RUN_RECORD_OVERHEAD);
    const name = await readExactly(this.handle, nameLength, this.offset);
    this.offset += nameLength;
    const encoded = await readExactly(this.handle, encodedLength, this.offset);
    this.offset += encodedLength;
    const actual = createHash('sha256').update(name).update(encoded).digest();
    if (!actual.equals(Buffer.from(header.subarray(6)))) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    return { name, encoded };
  }

  async close() { await this.handle.close(); }
}

class MinHeap {
  constructor() { this.values = []; }
  #compare(left, right) {
    const order = compareBytes(left.record.name, right.record.name);
    return order || left.readerIndex - right.readerIndex;
  }
  push(value) {
    const values = this.values;
    values.push(value);
    let index = values.length - 1;
    while (index > 0) {
      const parent = (index - 1) >>> 1;
      if (this.#compare(values[parent], value) <= 0) break;
      values[index] = values[parent];
      index = parent;
    }
    values[index] = value;
  }
  pop() {
    if (this.values.length === 0) return undefined;
    const first = this.values[0];
    const last = this.values.pop();
    if (this.values.length > 0) {
      let index = 0;
      while (true) {
        const left = index * 2 + 1;
        if (left >= this.values.length) break;
        const right = left + 1;
        const child = right < this.values.length && this.#compare(this.values[right], this.values[left]) < 0 ? right : left;
        if (this.#compare(this.values[child], last) >= 0) break;
        this.values[index] = this.values[child];
        index = child;
      }
      this.values[index] = last;
    }
    return first;
  }
}

async function mergeRuns(runs, guard, consume) {
  const readers = [];
  const heap = new MinHeap();
  let resident = 0;
  let previous;
  try {
    for (let index = 0; index < runs.length; index += 1) {
      const reader = await RunReader.open(runs[index], guard);
      readers.push(reader);
      const record = await reader.next();
      if (record) {
        resident += record.name.length + record.encoded.length + RUN_RECORD_OVERHEAD;
        guard.memory(resident);
        heap.push({ readerIndex: index, record });
      }
    }
    while (heap.values.length > 0) {
      guard.time();
      const item = heap.pop();
      resident -= item.record.name.length + item.record.encoded.length + RUN_RECORD_OVERHEAD;
      if (previous && compareBytes(previous, item.record.name) >= 0) fail('TREE_ENTRY_ORDER_INVALID', { layer: 2 });
      previous = item.record.name.slice();
      await consume(item.record);
      const record = await readers[item.readerIndex].next();
      if (record) {
        resident += record.name.length + record.encoded.length + RUN_RECORD_OVERHEAD;
        guard.memory(resident);
        heap.push({ readerIndex: item.readerIndex, record });
      }
    }
  } finally {
    await Promise.all(readers.map(reader => reader.close().catch(() => {})));
  }
}

async function writeMergedRun(space, runs, guard) {
  const output = await space.create();
  const result = { ...output, size: 0, count: 0 };
  try {
    await mergeRuns(runs, guard, record => appendRecord(space, result, record));
    await closeRun(result);
    for (const run of runs) await space.remove(run.path);
    return result;
  } catch (error) {
    await closeRun(result).catch(() => {});
    throw error;
  }
}

class IdRunReader {
  constructor(run, handle, guard) {
    this.run = run;
    this.handle = handle;
    this.guard = guard;
    this.offset = 0;
  }

  static async open(run, guard) {
    const { handle } = await openVerifiedRun(run, guard, 16);
    return new IdRunReader(run, handle, guard);
  }

  async next() {
    this.guard.time();
    if (this.offset === this.run.size) return undefined;
    const id = await readExactly(this.handle, 16, this.offset);
    this.offset += 16;
    return id;
  }

  async close() { await this.handle.close(); }
}

class IdHeap {
  constructor() { this.values = []; }
  #compare(left, right) { return compareBytes(left.id, right.id) || left.readerIndex - right.readerIndex; }
  push(value) {
    this.values.push(value);
    let index = this.values.length - 1;
    while (index > 0) {
      const parent = (index - 1) >>> 1;
      if (this.#compare(this.values[parent], value) <= 0) break;
      this.values[index] = this.values[parent];
      index = parent;
    }
    this.values[index] = value;
  }
  pop() {
    if (this.values.length === 0) return undefined;
    const first = this.values[0];
    const last = this.values.pop();
    if (this.values.length > 0) {
      let index = 0;
      while (true) {
        const left = index * 2 + 1;
        if (left >= this.values.length) break;
        const right = left + 1;
        const child = right < this.values.length && this.#compare(this.values[right], this.values[left]) < 0 ? right : left;
        if (this.#compare(this.values[child], last) >= 0) break;
        this.values[index] = this.values[child];
        index = child;
      }
      this.values[index] = last;
    }
    return first;
  }
}

async function appendId(space, run, id) {
  space.reserve(run.path, 16);
  await writeFully(run.handle, id);
  run.hash.update(id);
  run.size = space.files.get(run.path);
  run.count += 1;
}

async function mergeIdRuns(runs, guard, consume) {
  const readers = [];
  const heap = new IdHeap();
  let previous;
  try {
    for (let index = 0; index < runs.length; index += 1) {
      const reader = await IdRunReader.open(runs[index], guard);
      readers.push(reader);
      const id = await reader.next();
      if (id) heap.push({ id, readerIndex: index });
    }
    guard.memory(readers.length * FILE_ID_INDEX_OVERHEAD);
    while (heap.values.length > 0) {
      guard.time();
      const item = heap.pop();
      if (previous && compareBytes(previous, item.id) === 0) fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
      previous = item.id.slice();
      await consume(item.id);
      const id = await readers[item.readerIndex].next();
      if (id) heap.push({ id, readerIndex: item.readerIndex });
    }
  } finally {
    await Promise.all(readers.map(reader => reader.close().catch(() => {})));
  }
}

class DiskFileIdIndex {
  constructor(space, guard, { maxRunBytes, maxOpenRuns }) {
    this.space = space;
    this.guard = guard;
    this.maxRunBytes = maxRunBytes;
    this.maxOpenRuns = maxOpenRuns;
    this.buffer = [];
    this.runs = [];
    this.paths = new Set();
    this.count = 0;
    this.initialRuns = 0;
    this.finished = false;
  }

  async add(value) {
    if (this.finished) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    const id = new FileId(value).bytes;
    if (this.buffer.length > 0 && (this.buffer.length + 1) * FILE_ID_INDEX_OVERHEAD > this.maxRunBytes) {
      await this.flush();
    }
    if (FILE_ID_INDEX_OVERHEAD > this.maxRunBytes) fail('LIMIT_MEMORY', { layer: 1 });
    this.buffer.push(id);
    this.count += 1;
    this.guard.memory(this.buffer.length * FILE_ID_INDEX_OVERHEAD);
  }

  async flush() {
    if (this.buffer.length === 0) return;
    this.buffer.sort(compareBytes);
    for (let index = 1; index < this.buffer.length; index += 1) {
      if (compareBytes(this.buffer[index - 1], this.buffer[index]) === 0) fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
    }
    const created = await this.space.create();
    const run = { ...created, size: 0, count: 0 };
    this.paths.add(run.path);
    try {
      for (const id of this.buffer) await appendId(this.space, run, id);
      await closeRun(run);
      this.runs.push(run);
      this.initialRuns += 1;
      this.buffer = [];
    } catch (error) {
      await closeRun(run).catch(() => {});
      throw error;
    }
  }

  async mergeToRun(group) {
    const created = await this.space.create();
    const output = { ...created, size: 0, count: 0 };
    this.paths.add(output.path);
    try {
      await mergeIdRuns(group, this.guard, id => appendId(this.space, output, id));
      await closeRun(output);
      for (const run of group) {
        await this.space.remove(run.path);
        this.paths.delete(run.path);
      }
      return output;
    } catch (error) {
      await closeRun(output).catch(() => {});
      throw error;
    }
  }

  async finish(expectedCount) {
    if (this.finished) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    this.finished = true;
    try {
      await this.flush();
      while (this.runs.length > this.maxOpenRuns) {
        const next = [];
        for (let offset = 0; offset < this.runs.length; offset += this.maxOpenRuns) {
          const group = this.runs.slice(offset, offset + this.maxOpenRuns);
          next.push(group.length === 1 ? group[0] : await this.mergeToRun(group));
        }
        this.runs = next;
      }
      if (this.runs.length > 0) await mergeIdRuns(this.runs, this.guard, async () => {});
      for (const run of this.runs) {
        await this.space.remove(run.path);
        this.paths.delete(run.path);
      }
      if (expectedCount !== undefined && expectedCount !== this.count) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
      return { count: this.count, peakScratchBytes: this.space.peak, runCount: this.initialRuns };
    } catch (error) {
      await this.abort().catch(() => {});
      throw error;
    }
  }

  async abort() {
    this.buffer = [];
    for (const path of [...this.paths]) {
      await this.space.remove(path).catch(() => {});
      this.paths.delete(path);
    }
  }
}

/** Create a bounded external FileID uniqueness index for writeOrderedTree. */
export async function createDiskFileIdIndex(input = {}) {
  const directory = await assertScratchDirectory(input.scratchDirectory);
  const maxMemoryBytes = asLimit(input.maxMemoryBytes, 16_777_216);
  const maxRunBytes = asLimit(input.maxRunBytes, maxMemoryBytes);
  const maxOpenRuns = asLimit(input.maxOpenRuns, 64);
  if (maxMemoryBytes < FILE_ID_INDEX_OVERHEAD || maxRunBytes < FILE_ID_INDEX_OVERHEAD) {
    fail('LIMIT_MEMORY', { layer: 1 });
  }
  if (maxRunBytes > maxMemoryBytes || maxOpenRuns < 2) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const guard = new ResourceGuard({ maxTimeMs: input.maxTimeMs, maxMemoryBytes });
  const space = new ScratchSpace(directory, asLimit(input.maxScratchBytes, 268_435_456));
  return new DiskFileIdIndex(space, guard, { maxRunBytes, maxOpenRuns });
}

/**
 * Validate, external-sort, and write a canonical kind-3 tree. Scratch storage
 * is explicit, symlink-free, owner-only, exclusively created, bounded, and
 * removed on both success and failure.
 */
export async function writeSortedTree(input) {
  const options = optionsFor(input ?? {});
  const directory = await assertScratchDirectory(options.scratchDirectory);
  const maxScratchBytes = asLimit(options.maxScratchBytes, 1_073_741_824);
  const maxRunBytes = asLimit(options.maxRunBytes, Math.min(33_554_432, options.maxMemoryBytes));
  const maxOpenRuns = asLimit(options.maxOpenRuns, 64);
  const idRunBytes = Math.max(FILE_ID_INDEX_OVERHEAD, Math.floor(maxRunBytes / 5));
  const nameRunBytes = maxRunBytes - idRunBytes;
  if (nameRunBytes < 1 || maxRunBytes > options.maxMemoryBytes || maxOpenRuns < 2) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const space = new ScratchSpace(directory, maxScratchBytes);
  const fileIds = new DiskFileIdIndex(space, options.guard, { maxRunBytes: idRunBytes, maxOpenRuns });
  const stats = emptyStats();
  const runs = [];
  let buffer = [];
  let resident = 0;
  let initialRuns = 0;

  const flush = async () => {
    if (buffer.length === 0) return;
    buffer.sort((left, right) => compareBytes(left.name, right.name));
    for (let index = 1; index < buffer.length; index += 1) {
      if (compareBytes(buffer[index - 1].name, buffer[index].name) === 0) {
        fail('TREE_ENTRY_ORDER_INVALID', { layer: 2 });
      }
    }
    const created = await space.create();
    const run = { ...created, size: 0, count: 0 };
    try {
      for (const entry of buffer) await appendRecord(space, run, entry);
      await closeRun(run);
      runs.push(run);
      initialRuns += 1;
      buffer = [];
      resident = 0;
    } catch (error) {
      await closeRun(run).catch(() => {});
      throw error;
    }
  };

  try {
    for await (const raw of guardedAsyncIterable(options.entries, options.guard)) {
      options.guard.time();
      stats.count += 1;
      if (stats.count > options.maxItems) {
        fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
      }
      if (stats.count > options.entryCount) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
      const entry = validateEntry(raw, options);
      const memory = entry.name.length + entry.encoded.length + RUN_RECORD_OVERHEAD;
      options.guard.memory(memory);
      await options.guard.wait(signal => fileIds.add(entry.fileId, { signal }));
      if (buffer.length > 0 && resident + memory > nameRunBytes) await flush();
      if (memory > nameRunBytes) fail('LIMIT_MEMORY', { layer: 1 });
      buffer.push(entry);
      resident += memory;
      options.guard.memory(resident);
      stats.logicalBytes += entry.logicalSize;
      stats.kinds[entry.kind] += 1;
    }
    if (stats.count !== options.entryCount) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    await flush();
    while (runs.length > maxOpenRuns) {
      const next = [];
      for (let offset = 0; offset < runs.length; offset += maxOpenRuns) {
        const group = runs.slice(offset, offset + maxOpenRuns);
        next.push(group.length === 1 ? group[0] : await writeMergedRun(space, group, options.guard));
      }
      runs.splice(0, runs.length, ...next);
    }

    const uniqueness = await options.guard.wait(signal => fileIds.finish(stats.count, { signal }));

    const prefix = treePrefix(options);
    const emitter = createEmitter(options);
    await emitPrefix(emitter, prefix, options.guard);
    if (runs.length > 0) await mergeRuns(runs, options.guard, record => emitter.emit(record.encoded));
    const finished = emitter.finish();
    return Object.freeze({
      objectRef: finished.reference,
      summary: stableSummary(finished.reference, stats, finished.bytes),
      metrics: Object.freeze({
        elapsedMilliseconds: options.guard.elapsedMilliseconds(),
        peakScratchBytes: space.peak,
        runCount: initialRuns + uniqueness.runCount
      })
    });
  } finally {
    await space.cleanup();
  }
}

class CanonicalFileReader {
  constructor(handle, stat, options) {
    this.handle = handle;
    this.stat = stat;
    this.options = options;
    this.buffer = new Uint8Array();
    this.bufferOffset = 0;
    this.fileRead = 0;
    this.consumed = 0;
    this.hash = createObjectHashWriter(3, { maxMetadataBytes: options.maxBytes, registry: namesFor(options.registry) });
    this.decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    this.activeDecodeBytes = 0;
  }

  reserveDecoded(bytes) {
    const next = this.activeDecodeBytes + bytes;
    if (!Number.isSafeInteger(next)) fail('LIMIT_MEMORY', { layer: 1 });
    this.options.guard.memory(this.buffer.length + next);
    this.activeDecodeBytes = next;
  }

  async fill() {
    if (this.bufferOffset < this.buffer.length) return true;
    if (this.fileRead >= this.stat.size) return false;
    this.options.guard.time();
    const length = Math.min(this.options.readChunkBytes, this.stat.size - this.fileRead);
    this.options.guard.memory(length + this.activeDecodeBytes);
    const next = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      const result = await this.handle.read(next, offset, length - offset, this.fileRead + offset);
      if (result.bytesRead <= 0) fail('CBOR_TRUNCATED', { layer: 1, offset: this.consumed });
      offset += result.bytesRead;
    }
    this.hash.update(next);
    this.fileRead += next.length;
    this.buffer = next;
    this.bufferOffset = 0;
    return true;
  }

  async byte() {
    if (!await this.fill()) fail('CBOR_TRUNCATED', { layer: 1, offset: this.consumed });
    const value = this.buffer[this.bufferOffset++];
    this.consumed += 1;
    return value;
  }

  async take(length) {
    if (!Number.isSafeInteger(length) || length < 0) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'canonical-framing'
    });
    this.options.guard.memory(length);
    const result = new Uint8Array(length);
    let offset = 0;
    while (offset < length) {
      if (!await this.fill()) fail('CBOR_TRUNCATED', { layer: 1, offset: this.consumed });
      const count = Math.min(length - offset, this.buffer.length - this.bufferOffset);
      result.set(this.buffer.subarray(this.bufferOffset, this.bufferOffset + count), offset);
      this.bufferOffset += count;
      this.consumed += count;
      offset += count;
    }
    return result;
  }

  async header() {
    const offset = this.consumed;
    const first = await this.byte();
    const major = first >>> 5;
    const additional = first & 31;
    if (major === 6 || additional === 31) fail('CBOR_NON_CANONICAL', { layer: 1, offset });
    if (major === 7) return { major, additional, value: undefined, offset };
    if (additional < 24) return { major, additional, value: BigInt(additional), offset };
    const size = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0;
    if (size === 0) fail('CBOR_NON_CANONICAL', { layer: 1, offset });
    let value = 0n;
    for (let index = 0; index < size; index += 1) value = (value << 8n) | BigInt(await this.byte());
    if ((size === 1 && value < 24n) || (size === 2 && value <= 0xffn) ||
        (size === 4 && value <= 0xffffn) || (size === 8 && value <= 0xffff_ffffn)) {
      fail('CBOR_NON_CANONICAL', { layer: 1, offset });
    }
    return { major, additional, value, offset };
  }

  count(header) {
    if (header.value > BigInt(Number.MAX_SAFE_INTEGER)) fail('LIMIT_COUNT', {
      layer: 1, stage: 'canonical-framing', offset: header.offset
    });
    const count = Number(header.value);
    if (count > MAX_CONTAINER_ITEMS) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight', offset: header.offset
    });
    return count;
  }

  async item(depth = 1, sharedBudget = false) {
    const root = !sharedBudget;
    if (root) this.activeDecodeBytes = 0;
    try {
    const header = await this.header();
    if (header.major === 7) {
      if (header.additional === 20) return false;
      if (header.additional === 21) return true;
      fail('CBOR_NON_CANONICAL', { layer: 1, offset: header.offset });
    }
    if (header.major === 0) return header.value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(header.value) : header.value;
    if (header.major === 1) {
      if (header.value > 0x7fff_ffff_ffff_ffffn) fail('CBOR_NON_CANONICAL', { layer: 1, offset: header.offset });
      const value = -1n - header.value;
      return value >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(value) : value;
    }
    if (header.major === 2 || header.major === 3) {
      if (header.value > BigInt(MAX_GENERIC_VALUE_BYTES)) fail('LIMIT_VALUE_BYTES', { layer: 1, offset: header.offset });
      this.reserveDecoded(Number(header.value) + 32);
      const bytes = await this.take(Number(header.value));
      if (header.major === 2) return bytes;
      this.reserveDecoded(Number(header.value) * 2 + 32);
      let value;
      try { value = this.decoder.decode(bytes); } catch (cause) { fail('CBOR_NON_CANONICAL', { layer: 1, offset: header.offset, cause }); }
      if (textEncoder.encode(value).length !== bytes.length || value.normalize('NFC') !== value) {
        fail('CBOR_NON_CANONICAL', { layer: 1, offset: header.offset });
      }
      return value;
    }
    if (header.major !== 4 && header.major !== 5) fail('CBOR_NON_CANONICAL', { layer: 1, offset: header.offset });
    if (depth > MAX_NESTING) fail('LIMIT_NESTING', { layer: 1, offset: header.offset });
    const count = this.count(header);
    this.reserveDecoded(count * (header.major === 4 ? 16 : 48) + 32);
    if (header.major === 4) {
      const values = new Array(count);
      for (let index = 0; index < count; index += 1) values[index] = await this.item(depth + 1, true);
      return values;
    }
    const values = new Map();
    let previous;
    for (let index = 0; index < count; index += 1) {
      const key = await this.item(depth + 1, true);
      const encoded = encodeCanonical(key);
      if (previous && compareBytes(previous, encoded) >= 0) fail('CBOR_NON_CANONICAL', { layer: 1, offset: header.offset });
      previous = encoded;
      values.set(key, await this.item(depth + 1, true));
    }
    return values;
    } finally {
      if (root) this.activeDecodeBytes = 0;
    }
  }

  async arrayCount(maximum) {
    const header = await this.header();
    if (header.major !== 4) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    const count = this.count(header);
    if (count > maximum) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight', offset: header.offset
    });
    return count;
  }

  async finish() {
    if (this.consumed !== this.stat.size) fail('CBOR_TRAILING_BYTES', { layer: 1, offset: this.consumed });
    if (this.fileRead !== this.stat.size) fail('CBOR_TRUNCATED', { layer: 1, offset: this.consumed });
    const after = await this.handle.stat();
    if (after.size !== this.stat.size || after.mtimeMs !== this.stat.mtimeMs || after.ctimeMs !== this.stat.ctimeMs) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    return this.hash.finish();
  }
}

async function expectedIntegerKey(reader, expected) {
  const value = await reader.item();
  if (value !== expected) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}

/**
 * Verify a canonical tree file with bounded reads and one retained TreeEntry.
 * A disk FileID index is required above the bounded in-memory threshold.
 */
export async function verifyTreeFile(filePath, input = {}) {
  const maxItems = Math.min(
    configuredHardLimit('tree-entries', input.hardLimits?.['tree-entries']),
    configuredHardLimit('tree-entries', asLimit(input.maxItems, MAX_TREE_ENTRIES))
  );
  const maxBytes = Math.min(
    configuredHardLimit('metadata-payload-bytes', input.hardLimits?.['metadata-payload-bytes']),
    configuredHardLimit('metadata-payload-bytes', asLimit(input.maxBytes, MAX_METADATA_BYTES))
  );
  const maxMemoryBytes = asLimit(input.maxMemoryBytes, 67_108_864);
  const readChunkBytes = asLimit(input.readChunkBytes, 65_536);
  if (readChunkBytes < 1 || readChunkBytes > maxMemoryBytes) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  const guard = new ResourceGuard({ maxTimeMs: input.maxTimeMs, maxMemoryBytes });
  const noFollow = constants.O_NOFOLLOW ?? 0;
  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | noFollow);
    const stat = await handle.stat();
    if (!stat.isFile()) fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    if (stat.size > maxBytes) fail('LIMIT_METADATA_BYTES', { layer: 1 });
    const options = { ...input, maxItems, maxBytes, maxMemoryBytes, readChunkBytes, guard,
      operation: input.operation ?? 'conformance' };
    const reader = new CanonicalFileReader(handle, stat, options);
    const top = await reader.header();
    if (top.major !== 5 || (top.value !== 5n && top.value !== 6n)) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    await expectedIntegerKey(reader, 0);
    if (await reader.item() !== 1) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    await expectedIntegerKey(reader, 1);
    if (await reader.item() !== 3) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    await expectedIntegerKey(reader, 2);
    const requiredFeatures = await reader.item();
    let extensions;
    if (top.value === 6n) {
      await expectedIntegerKey(reader, 3);
      extensions = await reader.item();
    }
    await expectedIntegerKey(reader, 16);
    const descriptor = await reader.item();
    const embedded = ObjectRef.fromMap(descriptor, namesFor(options.registry));
    const expected = input.descriptor instanceof ObjectRef ? input.descriptor :
      ObjectRef.fromMap(input.descriptor, namesFor(options.registry));
    if (embedded.kind !== 6 || expected.kind !== 6 || embedded.toString() !== expected.toString()) {
      fail('REPOSITORY_DESCRIPTOR_MISMATCH', { layer: 3 });
    }
    await expectedIntegerKey(reader, 17);
    const entryCount = await reader.arrayCount(maxItems);
    const common = new Map([[0, 1], [1, 3], [2, requiredFeatures], [16, descriptor], [17, []]]);
    if (extensions !== undefined) common.set(3, extensions);
    validateKnownSchema(common, 3, {
      registry: options.registry, operation: options.operation, hardLimits: options.hardLimits
    });

    const fileIds = input.fileIdIndex === undefined ? memoryFileIdIndex({ ...options, entryCount }) :
      suppliedFileIdIndex(input.fileIdIndex);
    const stats = emptyStats();
    let previous;
    try {
      for (let index = 0; index < entryCount; index += 1) {
        guard.time();
        const entry = validateEntry(await reader.item(), options);
        if (previous && compareBytes(previous, entry.name) >= 0) fail('TREE_ENTRY_ORDER_INVALID', { layer: 2 });
        previous = entry.name.slice();
        const accepted = await guard.wait(signal => fileIds.add(entry.fileId, { signal }));
        if (accepted === false) fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
        addStats(stats, entry);
      }
      const uniqueness = await guard.wait(signal => fileIds.finish(entryCount, { signal }));
      if (uniqueness === false || (uniqueness?.count !== undefined && uniqueness.count !== entryCount)) {
        fail('FILEID_DUPLICATE_IN_TREE', { layer: 3 });
      }
      const reference = await reader.finish();
      return Object.freeze({
        objectRef: reference,
        summary: stableSummary(reference, stats, stat.size),
        highestLayer: options.registry ? 3 : 2,
        metrics: Object.freeze({
          elapsedMilliseconds: guard.elapsedMilliseconds(),
          peakScratchBytes: uniqueness?.peakScratchBytes ?? 0,
          runCount: uniqueness?.runCount ?? 0
        })
      });
    } catch (error) {
      await abortFileIdIndex(fileIds, guard);
      throw error;
    }
  } finally {
    await handle?.close().catch(() => {});
  }
}

export const TREE_STREAM_LIMITS = Object.freeze({
  maxEntries: MAX_TREE_ENTRIES,
  maxMetadataBytes: MAX_METADATA_BYTES,
  maxLogicalBytes: MAX_LOGICAL_BYTES,
  maxBasenameBytes: MAX_BASENAME_BYTES
});
