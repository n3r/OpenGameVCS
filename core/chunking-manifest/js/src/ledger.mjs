import {
  closeSync, mkdtempSync, openSync, readSync, rmSync, writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ObjectRef } from '@opengamevcs/object-model';
import { fail, wrap } from './errors.mjs';

export const LEDGER_RECORD_BYTES = 48;
export const LEDGER_MAXIMUM_BYTES = 64 * 1024 * 1024;
export const LEDGER_DEFAULTS = Object.freeze({
  maxMemoryBytes: 1_048_576,
  maxScratchBytes: 64 * 1024 * 1024,
});

function limit(value, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 0 || selected > LEDGER_MAXIMUM_BYTES) {
    fail('CHUNK_RESOURCE_INVALID');
  }
  return selected;
}

function encode(record) {
  if (!(record.digest instanceof Uint8Array) || record.digest.byteLength !== 32 ||
      !Number.isSafeInteger(record.length) || record.length < 0 ||
      !Number.isSafeInteger(record.boundary) || record.boundary < 0) {
    fail('CHUNK_RESOURCE_INVALID');
  }
  const bytes = Buffer.allocUnsafe(LEDGER_RECORD_BYTES);
  Buffer.from(record.digest.buffer, record.digest.byteOffset, record.digest.byteLength).copy(bytes, 0);
  bytes.writeBigUInt64BE(BigInt(record.length), 32);
  bytes.writeBigUInt64BE(BigInt(record.boundary), 40);
  return bytes;
}

function decode(bytes) {
  const digest = Buffer.from(bytes.subarray(0, 32));
  const length = Number(bytes.readBigUInt64BE(32));
  const boundary = Number(bytes.readBigUInt64BE(40));
  const reference = new ObjectRef(1, digest);
  return Object.freeze({ digest, length, boundary, objectId: reference.toString(), reference });
}

/**
 * Append-only, repeatable fixed-record ledger. It uses at most maxMemoryBytes
 * for records, then atomically switches to an owner-private scratch file.
 * dispose() is idempotent and removes every scratch artifact.
 */
export function createLedger(options = {}) {
  const maxMemoryBytes = limit(options.maxMemoryBytes, LEDGER_DEFAULTS.maxMemoryBytes);
  const maxScratchBytes = limit(options.maxScratchBytes, LEDGER_DEFAULTS.maxScratchBytes);
  const memoryRecordMaximum = Math.floor(maxMemoryBytes / LEDGER_RECORD_BYTES);
  const scratchRoot = resolve(options.scratchDirectory ?? tmpdir());
  let resident = Buffer.alloc(0);
  let residentCount = 0;
  let directory;
  let path;
  let descriptor;
  let count = 0;
  let scratchBytes = 0;
  let peakMemoryBytes = 0;
  let peakScratchBytes = 0;
  let disposed = false;

  function assertOpen() {
    if (disposed) fail('CHUNK_SESSION_FINISHED');
  }

  function writeRecord(bytes) {
    if (scratchBytes > maxScratchBytes - LEDGER_RECORD_BYTES) {
      fail('CHUNK_SCRATCH_EXHAUSTED', { maxScratchBytes });
    }
    let offset = 0;
    while (offset < bytes.length) {
      const written = writeSync(descriptor, bytes, offset, bytes.length - offset, scratchBytes + offset);
      if (written <= 0) fail('CHUNK_SCRATCH_EXHAUSTED', { maxScratchBytes });
      offset += written;
    }
    scratchBytes += bytes.length;
    peakScratchBytes = Math.max(peakScratchBytes, scratchBytes);
  }

  function spill() {
    if (descriptor !== undefined) return;
    if (maxScratchBytes < (residentCount + 1) * LEDGER_RECORD_BYTES) {
      fail('CHUNK_SCRATCH_EXHAUSTED', { maxScratchBytes });
    }
    try {
      directory = mkdtempSync(join(scratchRoot, 'ogvcs-chunk-ledger-'));
      path = join(directory, 'records.bin');
      descriptor = openSync(path, 'wx+', 0o600);
      for (let index = 0; index < residentCount; index += 1) {
        writeRecord(resident.subarray(index * LEDGER_RECORD_BYTES, (index + 1) * LEDGER_RECORD_BYTES));
      }
      resident = Buffer.alloc(0);
      residentCount = 0;
    } catch (cause) {
      try { if (descriptor !== undefined) closeSync(descriptor); } catch {}
      descriptor = undefined;
      if (directory !== undefined) {
        try { rmSync(directory, { recursive: true, force: true }); } catch {}
      }
      directory = undefined;
      path = undefined;
      if (cause?.code === 'CHUNK_SCRATCH_EXHAUSTED') throw cause;
      throw wrap('CHUNK_SCRATCH_EXHAUSTED', cause, { maxScratchBytes });
    }
  }

  function append(record) {
    assertOpen();
    const bytes = encode(record);
    if (descriptor === undefined && residentCount < memoryRecordMaximum) {
      if (resident.byteLength === 0) {
        resident = Buffer.allocUnsafe(memoryRecordMaximum * LEDGER_RECORD_BYTES);
        peakMemoryBytes = resident.byteLength;
      }
      bytes.copy(resident, residentCount * LEDGER_RECORD_BYTES);
      residentCount += 1;
    }
    else {
      spill();
      writeRecord(bytes);
    }
    count += 1;
    return count;
  }

  function *records() {
    assertOpen();
    if (descriptor === undefined) {
      for (let index = 0; index < residentCount; index += 1) {
        yield decode(resident.subarray(index * LEDGER_RECORD_BYTES, (index + 1) * LEDGER_RECORD_BYTES));
      }
      return;
    }
    const bytes = Buffer.allocUnsafe(LEDGER_RECORD_BYTES);
    for (let index = 0; index < count; index += 1) {
      let offset = 0;
      while (offset < bytes.length) {
        const read = readSync(descriptor, bytes, offset, bytes.length - offset,
          index * LEDGER_RECORD_BYTES + offset);
        if (read <= 0) fail('CHUNK_SESSION_FAILED');
        offset += read;
      }
      yield decode(bytes);
    }
  }

  function metrics() {
    return Object.freeze({
      records: count,
      memoryBytes: descriptor === undefined ? residentCount * LEDGER_RECORD_BYTES : 0,
      peakMemoryBytes,
      scratchBytes,
      peakScratchBytes,
      spilled: descriptor !== undefined,
    });
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    resident = Buffer.alloc(0);
    residentCount = 0;
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
      descriptor = undefined;
    }
    if (directory !== undefined) {
      try { rmSync(directory, { recursive: true, force: true }); } catch {}
      directory = undefined;
      path = undefined;
    }
  }

  return Object.freeze({ append, dispose, get count() { return count; }, metrics, records });
}
