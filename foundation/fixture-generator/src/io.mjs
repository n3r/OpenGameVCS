import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { lstat, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import path from 'node:path';

import { canonicalStringify } from './canonical.mjs';
import { integrityFailure } from './errors.mjs';

let temporarySequence = 0;

/** Test-only deterministic persistence fault. Production environments leave it unset. */
export function injectPersistenceFault(boundary, filePath) {
  const configured = process.env.OGVCS_FIXTURE_TEST_FAIL_AT_PERSISTENCE;
  const qualified = filePath === undefined ? boundary : `${boundary}:${path.basename(filePath)}`;
  if (configured !== boundary && configured !== qualified) return;
  const error = new Error('Injected ENOSPC-like persistence failure');
  error.code = 'ENOSPC';
  error.persistenceBoundary = qualified;
  throw error;
}

/**
 * Flush a directory entry after an atomic rename. Some supported filesystems do
 * not permit directory handles; only those portability errors are ignored.
 */
export async function syncDirectory(directoryPath, boundary = 'directory-sync', faultPath = directoryPath) {
  injectPersistenceFault(boundary, faultPath);
  let handle;
  try {
    handle = await open(directoryPath, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EACCES', 'EBADF', 'EINVAL', 'EISDIR', 'ENOTSUP', 'EPERM'].includes(error.code)) throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function canonicalLine(value) {
  return `${canonicalStringify(value)}\n`;
}

export async function readJson(filePath, description = 'JSON document') {
  let bytes;
  try {
    bytes = await readFile(filePath, 'utf8');
  } catch (error) {
    throw integrityFailure(`Cannot read ${description}`, {
      code: error.code,
      path: filePath,
    });
  }

  try {
    return JSON.parse(bytes);
  } catch (error) {
    throw integrityFailure(`Malformed ${description}`, {
      path: filePath,
      reason: error.message,
    });
  }
}

export async function readBoundedJson(filePath, description, options = {}) {
  const maximumBytes = options.maximumBytes;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) {
    throw new TypeError('maximumBytes must be a positive safe integer');
  }
  let metadata;
  try {
    metadata = await lstat(filePath);
  } catch (error) {
    throw integrityFailure(`Cannot inspect ${description}`, {
      code: error.code,
      path: filePath,
    });
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw integrityFailure(`${description} is not a safe regular file`, { path: filePath });
  }
  if (metadata.size > maximumBytes) {
    throw integrityFailure(`${description} exceeds its safe byte bound`, {
      limit: maximumBytes,
      path: filePath,
      size: metadata.size,
    });
  }
  const phase = options.phase ?? 'json-document';
  options.budget?.checkRuntime(`${phase}-preparse`);
  options.budget?.assertMemoryHeadroom?.(metadata.size * 8, `${phase}-preparse`);
  const value = await readJson(filePath, description);
  options.budget?.checkRuntime(`${phase}-postparse`);
  return value;
}

export async function atomicWrite(filePath, data, options = {}) {
  temporarySequence += 1;
  const temporaryPath = `${filePath}.tmp-${process.pid}-${temporarySequence}`;
  const bytes = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data);
  const budgetArtifact = options.artifact ?? filePath;
  const budgetReservation = options.budget?.beginAtomicWrite?.(budgetArtifact, bytes);
  let handle;
  let renamed = false;
  try {
    injectPersistenceFault('atomic-open', filePath);
    handle = await open(temporaryPath, 'wx', options.mode ?? 0o600);
    injectPersistenceFault('atomic-write', filePath);
    await handle.writeFile(data);
    injectPersistenceFault('atomic-sync', filePath);
    await handle.sync();
    await handle.close();
    handle = undefined;
    injectPersistenceFault('atomic-rename', filePath);
    await rename(temporaryPath, filePath);
    renamed = true;
    budgetReservation?.commit();
    await syncDirectory(path.dirname(filePath), 'atomic-parent-sync', filePath);
  } catch (error) {
    if (!renamed) budgetReservation?.abort();
    await handle?.close().catch(() => {});
    if (!renamed) await unlink(temporaryPath).catch(() => {});
    throw error;
  }
}

export async function atomicWriteCanonical(filePath, value, options = {}) {
  await atomicWrite(filePath, canonicalLine(value), options);
}

export async function hashFile(filePath, budget, phase = 'hash-file') {
  const hash = createHash('sha256');
  const stream = fs.createReadStream(filePath);
  for await (const chunk of stream) {
    budget?.checkRuntime(phase);
    hash.update(chunk);
  }
  return hash.digest('hex');
}

export async function hashFilePrefix(filePath, byteLength) {
  const hash = createHash('sha256');
  const stream = fs.createReadStream(filePath, { start: 0, end: Math.max(0, byteLength - 1) });
  let consumed = 0;
  for await (const chunk of stream) {
    const remaining = byteLength - consumed;
    if (remaining <= 0) break;
    hash.update(chunk.subarray(0, remaining));
    consumed += Math.min(chunk.length, remaining);
  }
  return { bytes: consumed, digest: hash.digest('hex') };
}

export async function fileSize(filePath) {
  return Number((await stat(filePath)).size);
}

export function createDigest(domain) {
  const hash = createHash('sha256');
  hash.update(`${domain}\0`, 'utf8');
  return hash;
}

export function digestCanonicalSequence(domain, values) {
  const hash = createDigest(domain);
  for (const value of values) hash.update(canonicalLine(value), 'utf8');
  return hash.digest('hex');
}

export async function readNdjson(filePath, visitor, options = {}) {
  const stream = fs.createReadStream(filePath, { encoding: 'utf8' });
  const maximumLineBytes = options.maxLineBytes ?? 64 * 1024;
  if (!Number.isSafeInteger(maximumLineBytes) || maximumLineBytes < 1) {
    throw new TypeError('maxLineBytes must be a positive safe integer');
  }
  let pending = '';
  let count = 0;
  let offset = 0;
  for await (const chunk of stream) {
    pending += chunk;
    while (true) {
      const newline = pending.indexOf('\n');
      if (newline < 0) break;
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      const lineBytes = Buffer.byteLength(`${line}\n`);
      if (lineBytes - 1 > maximumLineBytes) {
        throw integrityFailure('NDJSON record exceeds the safe line bound', {
          limit: maximumLineBytes,
          line: count + 1,
          path: filePath,
        });
      }
      if (line.length === 0) {
        throw integrityFailure('NDJSON artifact contains an empty record', {
          line: count + 1,
          path: filePath,
        });
      }
      let value;
      try {
        value = JSON.parse(line);
      } catch (error) {
        throw integrityFailure('Malformed NDJSON record', {
          line: count + 1,
          path: filePath,
          reason: error.message,
        });
      }
      await visitor(value, { count, offset, line: `${line}\n` });
      count += 1;
      offset += lineBytes;
      if (options.maxRecords !== undefined && count >= options.maxRecords) {
        stream.destroy();
        return { bytes: offset, count, trailingBytes: pending.length };
      }
    }
    if (Buffer.byteLength(pending) > maximumLineBytes) {
      throw integrityFailure('NDJSON record exceeds the safe line bound', {
        limit: maximumLineBytes,
        line: count + 1,
        path: filePath,
      });
    }
  }
  if (pending.length > 0) {
    throw integrityFailure('NDJSON artifact has an unterminated record', {
      path: filePath,
      trailingBytes: Buffer.byteLength(pending),
    });
  }
  return { bytes: offset, count, trailingBytes: 0 };
}
