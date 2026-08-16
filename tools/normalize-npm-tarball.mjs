import { readFile, writeFile } from 'node:fs/promises';
import { gzipSync, gunzipSync } from 'node:zlib';

const BLOCK_BYTES = 512;
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;

function fail(message) {
  throw new Error(`portable npm tarball: ${message}`);
}

function fieldText(bytes, start, length) {
  const end = bytes.indexOf(0, start);
  return bytes.subarray(start, end === -1 || end > start + length ? start + length : end).toString('ascii');
}

function octalField(bytes, start, length, label) {
  const text = fieldText(bytes, start, length).trim();
  if (!/^[0-7]+$/.test(text)) fail(`invalid ${label}`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0) fail(`invalid ${label}`);
  return value;
}

function checksum(bytes, offset) {
  let result = 0;
  for (let index = 0; index < BLOCK_BYTES; index += 1) {
    result += index >= 148 && index < 156 ? 0x20 : bytes[offset + index];
  }
  return result;
}

function writeModeAndChecksum(bytes, offset, mode) {
  bytes.write(`${mode.toString(8).padStart(7, '0')}\0`, offset + 100, 8, 'ascii');
  bytes.fill(0x20, offset + 148, offset + 156);
  const value = checksum(bytes, offset);
  bytes.write(`${value.toString(8).padStart(6, '0')}\0 `, offset + 148, 8, 'ascii');
}

function isZeroBlock(bytes, offset) {
  for (let index = 0; index < BLOCK_BYTES; index += 1) if (bytes[offset + index] !== 0) return false;
  return true;
}

export function normalizeNpmTarballBytes(compressed, options = {}) {
  if (!Buffer.isBuffer(compressed) || compressed.length === 0 || compressed.length > MAX_ARCHIVE_BYTES) fail('compressed input exceeds its bound');
  const executables = new Set(options.executables ?? []);
  if ([...executables].some((path) => typeof path !== 'string' || !/^package\/[A-Za-z0-9._/-]+$/.test(path))) fail('invalid executable path');

  let bytes;
  try {
    bytes = gunzipSync(compressed, { maxOutputLength: MAX_ARCHIVE_BYTES });
  } catch (error) {
    fail(`invalid gzip stream: ${error.message}`);
  }
  if (bytes.length === 0 || bytes.length % BLOCK_BYTES !== 0) fail('invalid tar length');

  const found = new Set();
  let offset = 0;
  let terminated = false;
  while (offset + BLOCK_BYTES <= bytes.length) {
    if (isZeroBlock(bytes, offset)) {
      if (offset + 2 * BLOCK_BYTES > bytes.length || !isZeroBlock(bytes, offset + BLOCK_BYTES)) fail('tar lacks its second end block');
      terminated = true;
      break;
    }
    const expectedChecksum = octalField(bytes, offset + 148, 8, 'tar checksum');
    if (checksum(bytes, offset) !== expectedChecksum) fail('tar header checksum mismatch');
    const name = fieldText(bytes, offset, 100);
    const prefix = fieldText(bytes, offset + 345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const size = octalField(bytes, offset + 124, 12, 'tar member size');
    const type = bytes[offset + 156];
    if (executables.has(path)) {
      if (type !== 0 && type !== 0x30) fail(`executable is not a regular file: ${path}`);
      writeModeAndChecksum(bytes, offset, 0o755);
      found.add(path);
    }
    const paddedSize = Math.ceil(size / BLOCK_BYTES) * BLOCK_BYTES;
    offset += BLOCK_BYTES + paddedSize;
    if (!Number.isSafeInteger(offset) || offset > bytes.length) fail('tar member exceeds the archive');
  }
  if (!terminated) fail('unterminated tar archive');
  for (const path of executables) if (!found.has(path)) fail(`missing executable: ${path}`);

  const output = gzipSync(bytes, { level: 0 });
  output[9] = 0xff;
  return output;
}

export async function normalizeNpmTarball(path, options = {}) {
  const input = await readFile(path);
  const output = normalizeNpmTarballBytes(input, options);
  await writeFile(path, output);
  return output;
}
