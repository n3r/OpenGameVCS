import { createHash } from 'node:crypto';
import { chmod, mkdir, open } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { validateRepositoryPath } from '@opengamevcs/path-filesystem';
import { canonicalJson, isDigest, sha256 } from './reference-contract.mjs';

const MAGIC = Buffer.from([0x4f, 0x47, 0x56, 0x43, 0x53, 0x42, 0x31, 0x00]);
const FILE_TAG = 0x01;
const END_TAG = 0xff;
const MAXIMUM_PATH_BYTES = 4096;

const exactRead = async (handle, length, position) => {
  const bytes = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const value = await handle.read(bytes, offset, length - offset, position + offset);
    if (value.bytesRead === 0) throw new Error('output frame ended early');
    offset += value.bytesRead;
  }
  return bytes;
};

const unsigned64 = (bytes) => {
  const value = bytes.readBigUInt64BE(0);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('output frame length exceeds safe integer');
  return Number(value);
};

const portablePath = (source) => {
  if (source.length < 1 || source.length > MAXIMUM_PATH_BYTES) return null;
  const value = source.toString('utf8');
  if (!Buffer.from(value, 'utf8').equals(source)) return null;
  try {
    const checked = validateRepositoryPath(value, { profile: 'path.opengamevcs/portable@1' });
    return checked.canonical === value ? value : null;
  } catch {
    return null;
  }
};

const safeOutputPath = (root, path) => {
  const target = resolve(root, ...path.split('/'));
  if (!target.startsWith(`${root}${sep}`)) throw new Error('validated output path escaped root');
  return target;
};

export const parseOutputFrame = async ({
  framePath,
  outputRoot,
  bindingDigest,
  maximumBytes,
  maximumFileBytes,
  maximumRecords,
  outputType,
}) => {
  if (!isDigest(bindingDigest) || !Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || !Number.isSafeInteger(maximumFileBytes) || maximumFileBytes < 1 || maximumFileBytes > maximumBytes || !Number.isSafeInteger(maximumRecords) || maximumRecords < 1 || maximumRecords > 10_000 || typeof outputType !== 'string') throw new TypeError('output frame policy is invalid');
  const handle = await open(framePath, 'r');
  const aggregate = createHash('sha256');
  let position = 0;
  let totalBytes = 0;
  let previousPathBytes = null;
  const outputs = [];
  const consume = async (length, hashed = true) => {
    const bytes = await exactRead(handle, length, position);
    position += length;
    if (hashed) aggregate.update(bytes);
    return bytes;
  };
  try {
    const magic = await consume(MAGIC.length);
    if (!magic.equals(MAGIC)) throw new Error('output frame magic differs');
    const binding = await consume(32);
    if (binding.toString('hex') !== bindingDigest) throw new Error('output frame binding differs');
    while (true) {
      const tag = await consume(1);
      if (tag[0] === END_TAG) {
        const terminalCounts = await consume(12);
        const declaredRecords = terminalCounts.readUInt32BE(0);
        const declaredBytes = unsigned64(terminalCounts.subarray(4));
        const declaredDigest = await consume(32, false);
        if (declaredRecords !== outputs.length || declaredBytes !== totalBytes || declaredDigest.toString('hex') !== aggregate.digest('hex')) throw new Error('output frame terminal commitment differs');
        const trailing = Buffer.alloc(1);
        if ((await handle.read(trailing, 0, 1, position)).bytesRead !== 0) throw new Error('output frame has trailing bytes');
        break;
      }
      if (tag[0] !== FILE_TAG || outputs.length >= maximumRecords) throw new Error('output frame record limit or tag differs');
      const header = await consume(12);
      const pathLength = header.readUInt32BE(0);
      const fileLength = unsigned64(header.subarray(4));
      if (pathLength < 1 || pathLength > MAXIMUM_PATH_BYTES || fileLength > maximumFileBytes || fileLength > maximumBytes - totalBytes) throw new Error('output frame file limit differs');
      const declaredFileDigest = await consume(32);
      const pathBytes = await consume(pathLength);
      const path = portablePath(pathBytes);
      if (!path || (previousPathBytes !== null && Buffer.compare(pathBytes, previousPathBytes) <= 0)) throw new Error('output frame paths are not canonical sorted unique paths');
      previousPathBytes = pathBytes;
      const target = safeOutputPath(outputRoot, path);
      await mkdir(dirname(target), { recursive: true, mode: 0o700 });
      const output = await open(target, 'wx', 0o600);
      const fileHash = createHash('sha256');
      let remaining = fileLength;
      try {
        while (remaining > 0) {
          const chunk = await consume(Math.min(64 * 1024, remaining));
          remaining -= chunk.length;
          fileHash.update(chunk);
          await output.write(chunk);
        }
        await output.sync();
      } finally {
        await output.close();
      }
      await chmod(target, 0o400);
      const digest = fileHash.digest('hex');
      if (digest !== declaredFileDigest.toString('hex')) throw new Error('output frame file digest differs');
      totalBytes += fileLength;
      outputs.push(Object.freeze({ digest, path, type: outputType }));
    }
  } finally {
    await handle.close();
  }
  const document = Object.freeze({ outputs: Object.freeze(outputs), schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' });
  const canonical = Buffer.from(canonicalJson(document), 'utf8');
  return Object.freeze({
    bytes: totalBytes,
    frameBytes: position,
    outputDigest: sha256(canonical),
    outputDocument: document,
    records: outputs.length,
  });
};

export const OUTPUT_FRAME_MAGIC_HEX = MAGIC.toString('hex');
