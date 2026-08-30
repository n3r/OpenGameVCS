import { createHash } from 'node:crypto';
import { chunkIdentity, contentManifest, PROFILE } from './identity.mjs';

const TABLE_DOMAIN = Buffer.from('OpenGameVCS Gear table v1\0', 'ascii');
export const LIMITS = Object.freeze({
  smallMaximum: 262_144,
  minimum: 262_144,
  target: 1_048_576,
  maximum: 2_097_152,
  earlyMask: 0x1f_ffff,
  lateMask: 0x07_ffff,
  logicalMaximum: 1_099_511_627_776,
  chunkCountMaximum: 1_048_576,
  fragmentMaximum: 64 * 1024 * 1024,
  fixedWorkingBytes: 65_536,
  workerMaximum: 64,
  queuedChunksMaximum: 64,
  workingMaximum: 1_073_741_824,
  scalarWorkingMinimum: 4_259_840,
});

function fail(code) { const error = new Error(code); error.code = code; throw error; }
function tableEntryBytes(index) {
  const suffix = Buffer.alloc(2); suffix.writeUInt16BE(index);
  return createHash('sha256').update(TABLE_DOMAIN).update(suffix).digest().subarray(0, 8);
}
const GEAR_BYTES = Array.from({ length: 256 }, (_, index) => tableEntryBytes(index));
const GEAR_HIGH = new Uint32Array(GEAR_BYTES.map((value) => value.readUInt32BE(0)));
const GEAR_LOW = new Uint32Array(GEAR_BYTES.map((value) => value.readUInt32BE(4)));
export const GEAR_TABLE_SHA256 = createHash('sha256').update(Buffer.concat(GEAR_BYTES)).digest('hex');

export function gearStepU32(high, low, byte) {
  if (!Number.isInteger(high) || high < 0 || high > 0xffff_ffff || !Number.isInteger(low) || low < 0 || low > 0xffff_ffff || !Number.isInteger(byte) || byte < 0 || byte > 255) fail('CHUNK_FINGERPRINT_INPUT_INVALID');
  const shiftedLow = (low << 1) >>> 0;
  const shiftedHigh = ((high << 1) | (low >>> 31)) >>> 0;
  const nextLow = (shiftedLow + GEAR_LOW[byte]) >>> 0;
  const carry = nextLow < shiftedLow ? 1 : 0;
  return Object.freeze({ high: (shiftedHigh + GEAR_HIGH[byte] + carry) >>> 0, low: nextLow });
}

export function createChunker({ declaredLength, profile = PROFILE, onChunk = () => {}, workerCount = 1, queuedChunks = 0, maxWorkingMemoryBytes = LIMITS.scalarWorkingMinimum } = {}) {
  if (!Number.isSafeInteger(declaredLength) || declaredLength < 0 || declaredLength > LIMITS.logicalMaximum) fail('CHUNK_DECLARED_LENGTH_INVALID');
  if (!profile || profile.namespace !== PROFILE.namespace || profile.id !== PROFILE.id || profile.major !== PROFILE.major) fail('CHUNK_PROFILE_UNSUPPORTED');
  if (typeof onChunk !== 'function') fail('CHUNK_SINK_INVALID');
  if (workerCount !== 1 || queuedChunks !== 0) fail('CHUNK_RESOURCE_UNSUPPORTED');
  if (!Number.isSafeInteger(maxWorkingMemoryBytes) || maxWorkingMemoryBytes < LIMITS.scalarWorkingMinimum) fail('CHUNK_RESOURCE_EXHAUSTED');
  if (maxWorkingMemoryBytes > LIMITS.workingMaximum) fail('CHUNK_RESOURCE_INVALID');
  let consumed = 0; let fingerprintHigh = 0; let fingerprintLow = 0; let currentLength = 0; let finished = false; let failed = false;
  const current = Buffer.allocUnsafe(Math.min(declaredLength, LIMITS.maximum));
  const whole = createHash('sha256'); const parts = []; const boundaries = [];

  function emit() {
    if (parts.length >= LIMITS.chunkCountMaximum) fail('CHUNK_COUNT_EXCEEDED');
    const bytes = Buffer.from(current.subarray(0, currentLength));
    const identity = chunkIdentity(bytes);
    const part = Object.freeze({ digest: identity.digest, length: currentLength, objectId: identity.objectId, reference: identity.reference });
    try {
      onChunk(bytes, part, parts.length);
    } catch (cause) {
      const error = new Error('CHUNK_SINK_FAILED', { cause }); error.code = 'CHUNK_SINK_FAILED'; throw error;
    }
    parts.push(part); boundaries.push(consumed);
    fingerprintHigh = 0; fingerprintLow = 0; currentLength = 0;
  }

  return Object.freeze({
    update(fragment) {
      if (failed) fail('CHUNK_SESSION_FAILED');
      if (finished) fail('CHUNK_SESSION_FINISHED');
      try {
        if (!(fragment instanceof Uint8Array) || fragment.byteLength > LIMITS.fragmentMaximum) fail('CHUNK_FRAGMENT_INVALID');
        const bytes = Buffer.from(fragment.buffer, fragment.byteOffset, fragment.byteLength);
        if (consumed + bytes.length > declaredLength) fail('CHUNK_SOURCE_TOO_LONG');
        whole.update(bytes);
        for (let offset = 0; offset < bytes.length; offset += 1) {
          const byte = bytes[offset];
          current[currentLength] = byte;
          consumed += 1; currentLength += 1;
          if (declaredLength > LIMITS.smallMaximum) {
            const shiftedLow = (fingerprintLow << 1) >>> 0;
            const shiftedHigh = ((fingerprintHigh << 1) | (fingerprintLow >>> 31)) >>> 0;
            const nextLow = (shiftedLow + GEAR_LOW[byte]) >>> 0;
            fingerprintHigh = (shiftedHigh + GEAR_HIGH[byte] + (nextLow < shiftedLow ? 1 : 0)) >>> 0;
            fingerprintLow = nextLow;
            if (currentLength >= LIMITS.minimum) {
              const mask = currentLength < LIMITS.target ? LIMITS.earlyMask : LIMITS.lateMask;
              if ((fingerprintLow & mask) === 0 || currentLength === LIMITS.maximum) emit();
            }
          }
        }
        return consumed;
      } catch (error) {
        failed = true; finished = true;
        throw error;
      }
    },
    async finish() {
      if (failed) fail('CHUNK_SESSION_FAILED');
      if (finished) fail('CHUNK_SESSION_FINISHED');
      try {
        if (consumed !== declaredLength) fail('CHUNK_SOURCE_TOO_SHORT');
        if (currentLength > 0) emit();
        const wholeFileDigest = whole.digest();
        const manifest = await contentManifest(declaredLength, wholeFileDigest, parts);
        finished = true;
        return Object.freeze({
          boundaries: Object.freeze([...boundaries]),
          chunks: Object.freeze(parts.map(({ digest, reference: _reference, ...part }) => Object.freeze({ ...part, digest: Buffer.from(digest) }))),
          class: declaredLength === 0 ? 'empty' : declaredLength <= LIMITS.smallMaximum ? 'whole' : 'cdc-1m',
          logicalLength: declaredLength,
          manifest,
          wholeFileDigest,
        });
      } catch (error) {
        failed = true; finished = true;
        throw error;
      }
    },
  });
}

export async function chunkBytes(bytes, options = {}) {
  if (!(bytes instanceof Uint8Array)) fail('CHUNK_FRAGMENT_INVALID');
  const chunks = [];
  const session = createChunker({ declaredLength: options.declaredLength ?? bytes.byteLength, profile: options.profile, workerCount: options.workerCount, queuedChunks: options.queuedChunks, maxWorkingMemoryBytes: options.maxWorkingMemoryBytes, onChunk: (chunk) => chunks.push(Buffer.from(chunk)) });
  session.update(bytes);
  return Object.freeze({ ...await session.finish(), chunkBytes: Object.freeze(chunks) });
}
