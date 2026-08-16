import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { fail as throwFailure, isOgvcsError } from './errors.js';
import { asLimit, compareBytes } from './scale-util.js';

const DEFAULT_WRITE_BUFFER_BYTES = 65_536;
const MAX_RETAINED_RUN_FILES = 16_384;

function fail(code, details) {
  if (code === 'SCHEMA_FIELD_INVALID' && details?.layer === 1 && details.stage === undefined) {
    details = { ...details, stage: 'configured-resource-preflight' };
  }
  throwFailure(code, details);
}

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail('SCHEMA_FIELD_INVALID', { layer: 1 });
}

async function scratchDirectory(directory) {
  if (typeof directory !== 'string' || directory.length === 0) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
  const requested = resolve(directory);
  let supplied;
  try { supplied = await lstat(requested); } catch (cause) { fail('SCHEMA_FIELD_INVALID', { layer: 1, cause }); }
  if (!supplied.isDirectory() || supplied.isSymbolicLink()) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
  let target;
  let canonical;
  try {
    target = await realpath(requested);
    canonical = await lstat(target);
  } catch (cause) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, cause });
  }
  if (!canonical.isDirectory() || canonical.isSymbolicLink()) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
  return target;
}

function sameFile(left, right) {
  // Windows may report zero for inode fields. Stable file timestamps and size
  // remain mandatory there; platforms with identities additionally require
  // the same device/inode pair.
  const identitiesAvailable = left.dev !== 0 && left.ino !== 0 && right.dev !== 0 && right.ino !== 0;
  const metadataSame = left.size === right.size && left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs && left.birthtimeMs === right.birthtimeMs;
  return metadataSame && (!identitiesAvailable || (left.dev === right.dev && left.ino === right.ino)) &&
    right.isFile() && !right.isSymbolicLink();
}

/** Private exact scratch allocator used by the high-level bundle verifier. */
export class BundleScratch {
  static async create(options = {}) {
    const directory = await scratchDirectory(options.scratchDirectory);
    return new BundleScratch(
      directory,
      asLimit(options.maxScratchBytes, 8_589_934_592),
      asLimit(options.verifyBufferBytes, 65_536),
      options.check ?? (() => {})
    );
  }

  constructor(directory, maximum, verifyBufferBytes, check) {
    if (verifyBufferBytes < 1 || typeof check !== 'function') fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    this.directory = directory;
    this.maximum = maximum;
    this.verifyBufferBytes = verifyBufferBytes;
    this.check = check;
    this.currentBytes = 0;
    this.peakBytes = 0;
    this.files = new Map();
    this.createdFiles = 0;
  }

  async createFile(label = 'data', flags = constants.O_RDWR) {
    const safe = String(label).replace(/[^a-z0-9-]/gi, '-').slice(0, 32) || 'data';
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const path = join(this.directory, `.ogvcs-bundle-${safe}-${randomBytes(12).toString('hex')}.tmp`);
      let handle;
      try {
        handle = await open(path, flags | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
        const file = {
          path, handle, size: 0, identity: undefined, digest: undefined,
          hash: createHash('sha256'), closed: false
        };
        this.files.set(path, file);
        this.createdFiles += 1;
        return file;
      } catch (error) {
        await handle?.close().catch(() => {});
        if (error?.code === 'EEXIST') continue;
        if (isOgvcsError(error)) throw error;
        fail('LIMIT_SCRATCH', { layer: 1, cause: error });
      }
    }
    fail('LIMIT_SCRATCH', { layer: 1 });
  }

  reserve(file, bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || !this.files.has(file.path)) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    }
    if (bytes > this.maximum - this.currentBytes) fail('LIMIT_SCRATCH', { layer: 1 });
    file.size += bytes;
    this.currentBytes += bytes;
    this.peakBytes = Math.max(this.peakBytes, this.currentBytes);
  }

  async append(file, value) {
    if (file.closed || !file.handle) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    const bytes = asBytes(value);
    this.reserve(file, bytes.length);
    let offset = 0;
    try {
      while (offset < bytes.length) {
        const result = await file.handle.write(bytes, offset, bytes.length - offset, null);
        if (!Number.isSafeInteger(result.bytesWritten) || result.bytesWritten <= 0 ||
            result.bytesWritten > bytes.length - offset) fail('LIMIT_SCRATCH', { layer: 1 });
        file.hash.update(bytes.subarray(offset, offset + result.bytesWritten));
        offset += result.bytesWritten;
      }
    } catch (error) {
      const unwritten = bytes.length - offset;
      file.size -= unwritten;
      this.currentBytes -= unwritten;
      if (isOgvcsError(error)) throw error;
      fail('LIMIT_SCRATCH', { layer: 1, cause: error });
    }
  }

  async readExactly(file, target, targetOffset, length, position) {
    if (!file.handle || file.closed || !Number.isSafeInteger(position) || position < 0 ||
        !Number.isSafeInteger(length) || length < 0 || position + length > file.size) {
      fail('LIMIT_SCRATCH', { layer: 1 });
    }
    let read = 0;
    while (read < length) {
      let result;
      try {
        result = await file.handle.read(target, targetOffset + read, length - read, position + read);
      } catch (cause) {
        fail('LIMIT_SCRATCH', { layer: 1, cause });
      }
      if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead <= 0 || result.bytesRead > length - read) {
        fail('LIMIT_SCRATCH', { layer: 1 });
      }
      read += result.bytesRead;
    }
  }

  async closeFile(file) {
    if (file.closed) return;
    let identity;
    try { identity = await file.handle.stat(); } catch (cause) { fail('LIMIT_SCRATCH', { layer: 1, cause }); }
    if (!identity.isFile() || identity.size !== file.size) fail('LIMIT_SCRATCH', { layer: 1 });
    try { await file.handle.close(); } catch (cause) { fail('LIMIT_SCRATCH', { layer: 1, cause }); }
    file.handle = undefined;
    file.closed = true;
    file.identity = identity;
    file.digest = file.hash.digest();
    file.hash = undefined;
  }

  async reopenFile(file, flags = constants.O_RDONLY) {
    if (!file.closed || file.handle || !file.identity) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    let handle;
    try {
      handle = await open(file.path, flags | (constants.O_NOFOLLOW ?? 0));
      const identity = await handle.stat();
      if (!sameFile(file.identity, identity)) fail('LIMIT_SCRATCH', { layer: 1 });
      const hash = createHash('sha256');
      const buffer = Buffer.alloc(Math.min(this.verifyBufferBytes, Math.max(1, file.size)));
      let position = 0;
      while (position < file.size) {
        this.check();
        const length = Math.min(buffer.length, file.size - position);
        const result = await handle.read(buffer, 0, length, position);
        if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead !== length) {
          fail('LIMIT_SCRATCH', { layer: 1 });
        }
        hash.update(buffer.subarray(0, length));
        position += length;
      }
      if (!file.digest || !hash.digest().equals(file.digest)) fail('LIMIT_SCRATCH', { layer: 1 });
      file.handle = handle;
      file.closed = false;
      return file;
    } catch (error) {
      await handle?.close().catch(() => {});
      if (isOgvcsError(error)) throw error;
      fail('LIMIT_SCRATCH', { layer: 1, cause: error });
    }
  }

  async removeFile(file) {
    if (!this.files.has(file.path)) return;
    if (!file.closed) await file.handle?.close().catch(() => {});
    file.handle = undefined;
    file.closed = true;
    try { await unlink(file.path); } catch (error) {
      if (error?.code !== 'ENOENT') fail('LIMIT_SCRATCH', { layer: 1, cause: error });
    }
    this.files.delete(file.path);
    this.currentBytes -= file.size;
  }

  async cleanup() {
    const files = [...this.files.values()];
    let failure;
    for (const file of files) {
      try { await this.removeFile(file); } catch (error) { failure ??= error; }
    }
    if (failure) throw failure;
  }
}

export class ScratchWriter {
  constructor(scratch, file, bufferBytes = DEFAULT_WRITE_BUFFER_BYTES) {
    if (!Number.isSafeInteger(bufferBytes) || bufferBytes < 1) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    this.scratch = scratch;
    this.file = file;
    this.bufferBytes = bufferBytes;
    this.parts = [];
    this.buffered = 0;
  }

  async write(value) {
    const bytes = asBytes(value);
    if (bytes.length === 0) return;
    if (bytes.length >= this.bufferBytes) {
      await this.flush();
      await this.scratch.append(this.file, bytes);
      return;
    }
    if (bytes.length > this.bufferBytes - this.buffered) await this.flush();
    this.parts.push(Uint8Array.from(bytes));
    this.buffered += bytes.length;
  }

  async flush() {
    if (this.buffered === 0) return;
    const joined = new Uint8Array(this.buffered);
    let offset = 0;
    for (const part of this.parts) { joined.set(part, offset); offset += part.length; }
    this.parts = [];
    this.buffered = 0;
    await this.scratch.append(this.file, joined);
  }
}

class RunReader {
  constructor(scratch, file, recordBytes) {
    this.scratch = scratch;
    this.file = file;
    this.recordBytes = recordBytes;
    this.cursor = 0;
    this.record = new Uint8Array(recordBytes);
    this.done = false;
  }

  async next() {
    if (this.cursor === this.file.size) { this.done = true; return false; }
    await this.scratch.readExactly(this.file, this.record, 0, this.recordBytes, this.cursor);
    this.cursor += this.recordBytes;
    return true;
  }
}

/**
 * Bounded external sorter for exact fixed-width records. Sort keys are bytes
 * inside each record; no lossy hash table participates in identity lookup.
 */
export class FixedRecordSorter {
  constructor({ scratch, recordBytes, keyOffset = 0, keyBytes = recordBytes,
    maxRunBytes = 8_388_608, maxOpenRuns = 32, writeBufferBytes = DEFAULT_WRITE_BUFFER_BYTES,
    duplicateCode, check = () => {} }) {
    if (!(scratch instanceof BundleScratch) || !Number.isSafeInteger(recordBytes) || recordBytes < 1 ||
        !Number.isSafeInteger(keyOffset) || keyOffset < 0 || !Number.isSafeInteger(keyBytes) || keyBytes < 1 ||
        keyOffset + keyBytes > recordBytes || !Number.isSafeInteger(maxOpenRuns) || maxOpenRuns < 2) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    }
    this.scratch = scratch;
    this.recordBytes = recordBytes;
    this.keyOffset = keyOffset;
    this.keyBytes = keyBytes;
    this.maxRunBytes = asLimit(maxRunBytes, 8_388_608);
    if (this.maxRunBytes < recordBytes) fail('LIMIT_MEMORY', { layer: 1 });
    this.maxOpenRuns = maxOpenRuns;
    this.writeBufferBytes = writeBufferBytes;
    this.duplicateCode = duplicateCode;
    this.check = check;
    this.records = [];
    this.bufferedBytes = 0;
    this.runs = [];
    this.count = 0;
    this.runCount = 0;
  }

  compare(left, right) {
    return compareBytes(
      left.subarray(this.keyOffset, this.keyOffset + this.keyBytes),
      right.subarray(this.keyOffset, this.keyOffset + this.keyBytes)
    );
  }

  async add(value) {
    this.check();
    const record = asBytes(value);
    if (record.length !== this.recordBytes) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    if (this.bufferedBytes > this.maxRunBytes - this.recordBytes) await this.flushRun();
    this.records.push(Uint8Array.from(record));
    this.bufferedBytes += this.recordBytes;
    this.count += 1;
  }

  async flushRun() {
    if (this.records.length === 0) return;
    this.check();
    if (this.runs.length >= MAX_RETAINED_RUN_FILES) fail('LIMIT_MEMORY', { layer: 1 });
    this.records.sort((left, right) => this.compare(left, right));
    if (this.duplicateCode) {
      for (let index = 1; index < this.records.length; index += 1) {
        if (this.compare(this.records[index - 1], this.records[index]) === 0) {
          fail(this.duplicateCode, { layer: 1 });
        }
      }
    }
    const file = await this.scratch.createFile('index-run');
    const writer = new ScratchWriter(this.scratch, file, this.writeBufferBytes);
    for (const record of this.records) { this.check(); await writer.write(record); }
    await writer.flush();
    await this.scratch.closeFile(file);
    this.runs.push(file);
    this.runCount += 1;
    this.records = [];
    this.bufferedBytes = 0;
  }

  async mergeGroup(group) {
    this.check();
    const readers = [];
    for (const file of group) {
      await this.scratch.reopenFile(file);
      const reader = new RunReader(this.scratch, file, this.recordBytes);
      if (await reader.next()) readers.push(reader);
    }
    const output = await this.scratch.createFile('index-merge');
    const writer = new ScratchWriter(this.scratch, output, this.writeBufferBytes);
    let previous;
    while (readers.length > 0) {
      this.check();
      let selected = 0;
      for (let index = 1; index < readers.length; index += 1) {
        if (this.compare(readers[index].record, readers[selected].record) < 0) selected = index;
      }
      const reader = readers[selected];
      if (this.duplicateCode && previous && this.compare(previous, reader.record) === 0) {
        fail(this.duplicateCode, { layer: 1 });
      }
      await writer.write(reader.record);
      previous = reader.record.slice();
      if (!await reader.next()) readers.splice(selected, 1);
    }
    await writer.flush();
    await this.scratch.closeFile(output);
    for (const file of group) await this.scratch.removeFile(file);
    return output;
  }

  async finish() {
    this.check();
    await this.flushRun();
    if (this.runs.length === 0) {
      const empty = await this.scratch.createFile('index-empty');
      await this.scratch.closeFile(empty);
      this.runs.push(empty);
    }
    while (this.runs.length > 1) {
      const merged = [];
      for (let offset = 0; offset < this.runs.length; offset += this.maxOpenRuns) {
        merged.push(await this.mergeGroup(this.runs.slice(offset, offset + this.maxOpenRuns)));
      }
      this.runs = merged;
    }
    const file = this.runs[0];
    await this.scratch.reopenFile(file);
    return new FixedRecordIndex({
      scratch: this.scratch,
      file,
      recordBytes: this.recordBytes,
      keyOffset: this.keyOffset,
      keyBytes: this.keyBytes,
      count: this.count,
      runCount: this.runCount
    });
  }
}

export class FixedRecordIndex {
  constructor(options) { Object.assign(this, options); }

  async record(index, target = new Uint8Array(this.recordBytes)) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.count || target.length < this.recordBytes) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    }
    await this.scratch.readExactly(this.file, target, 0, this.recordBytes, index * this.recordBytes);
    return target;
  }

  async lowerBound(key) {
    const wanted = asBytes(key);
    if (wanted.length !== this.keyBytes) fail('SCHEMA_FIELD_INVALID', { layer: 1 });
    let low = 0;
    let high = this.count;
    const record = new Uint8Array(this.recordBytes);
    while (low < high) {
      const middle = low + Math.floor((high - low) / 2);
      await this.record(middle, record);
      const order = compareBytes(record.subarray(this.keyOffset, this.keyOffset + this.keyBytes), wanted);
      if (order < 0) low = middle + 1;
      else high = middle;
    }
    return low;
  }

  async find(key) {
    const index = await this.lowerBound(key);
    if (index === this.count) return undefined;
    const record = await this.record(index);
    return compareBytes(record.subarray(this.keyOffset, this.keyOffset + this.keyBytes), asBytes(key)) === 0
      ? record : undefined;
  }
}
