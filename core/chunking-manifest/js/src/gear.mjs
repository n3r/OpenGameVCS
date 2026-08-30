import { createHash } from 'node:crypto';
import { chunkIdentity, contentManifest, PROFILE } from './identity.mjs';
import { createOperationControl } from './control.mjs';
import { fail, normalizeError, wrap } from './errors.mjs';
import { createLedger } from './ledger.mjs';
import { createVerificationReceipt } from './receipt.mjs';

const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;

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

// Internal profile scanner used by verification. It reports only algorithmic
// cuts; the final suffix boundary is supplied by the manifest verifier.
export function createBoundaryScanner(logicalLength) {
  if (!Number.isSafeInteger(logicalLength) || logicalLength < 0 || logicalLength > LIMITS.logicalMaximum) {
    fail('CHUNK_DECLARED_LENGTH_INVALID');
  }
  let fingerprintHigh = 0;
  let fingerprintLow = 0;
  let currentLength = 0;
  let consumed = 0;
  let lastBoundary = 0;
  return Object.freeze({
    update(fragment, onBoundary) {
      for (let offset = 0; offset < fragment.byteLength; offset += 1) {
        const byte = fragment[offset];
        consumed += 1;
        currentLength += 1;
        if (logicalLength <= LIMITS.smallMaximum) continue;
        const shiftedLow = (fingerprintLow << 1) >>> 0;
        const shiftedHigh = ((fingerprintHigh << 1) | (fingerprintLow >>> 31)) >>> 0;
        const nextLow = (shiftedLow + GEAR_LOW[byte]) >>> 0;
        fingerprintHigh = (shiftedHigh + GEAR_HIGH[byte] + (nextLow < shiftedLow ? 1 : 0)) >>> 0;
        fingerprintLow = nextLow;
        if (currentLength >= LIMITS.minimum) {
          const mask = currentLength < LIMITS.target ? LIMITS.earlyMask : LIMITS.lateMask;
          if ((fingerprintLow & mask) === 0 || currentLength === LIMITS.maximum) {
            lastBoundary = consumed;
            onBoundary(consumed);
            fingerprintHigh = 0;
            fingerprintLow = 0;
            currentLength = 0;
          }
        }
      }
    },
    get consumed() { return consumed; },
    get lastBoundary() { return lastBoundary; },
  });
}

export function createChunker(options = {}) {
  let control;
  try {
    const {
      declaredLength,
      profile = PROFILE,
      onChunk = () => {},
      workerCount = 1,
      queuedChunks = 0,
      maxWorkingMemoryBytes = LIMITS.scalarWorkingMinimum,
      maxLedgerMemoryBytes,
      maxScratchBytes,
      scratchDirectory,
      manifestSink,
      retainEntries = true,
      signal,
      maxElapsedMilliseconds,
    } = options;
    if (!Number.isSafeInteger(declaredLength) || declaredLength < 0 || declaredLength > LIMITS.logicalMaximum) fail('CHUNK_DECLARED_LENGTH_INVALID');
    if (!profile || profile.namespace !== PROFILE.namespace || profile.id !== PROFILE.id || profile.major !== PROFILE.major) fail('CHUNK_PROFILE_UNSUPPORTED');
    if (typeof onChunk !== 'function') fail('CHUNK_SINK_INVALID');
    if (workerCount !== 1 || queuedChunks !== 0) fail('CHUNK_RESOURCE_UNSUPPORTED');
    if (!Number.isSafeInteger(maxWorkingMemoryBytes) || maxWorkingMemoryBytes < LIMITS.scalarWorkingMinimum) fail('CHUNK_RESOURCE_EXHAUSTED');
    if (maxWorkingMemoryBytes > LIMITS.workingMaximum) fail('CHUNK_RESOURCE_INVALID');
    if (manifestSink !== undefined && typeof manifestSink !== 'function') fail('CHUNK_SINK_INVALID');
    if (typeof retainEntries !== 'boolean') fail('CHUNK_RESOURCE_INVALID');
    control = createOperationControl({ signal, maxElapsedMilliseconds });
    control.check();
    let consumed = 0; let fingerprintHigh = 0; let fingerprintLow = 0; let currentLength = 0; let finished = false; let failed = false;
    const current = Buffer.allocUnsafe(Math.min(declaredLength, LIMITS.maximum));
    const whole = createHash('sha256');
    const ledger = createLedger({
      maxMemoryBytes: maxLedgerMemoryBytes,
      maxScratchBytes,
      scratchDirectory,
    });

    function emit() {
      control.check();
      if (ledger.count >= LIMITS.chunkCountMaximum) fail('CHUNK_COUNT_EXCEEDED');
      const bytes = Buffer.from(current.subarray(0, currentLength));
      const identity = chunkIdentity(bytes);
      const part = Object.freeze({ digest: identity.digest, length: currentLength, objectId: identity.objectId, reference: identity.reference });
      ledger.append({ digest: identity.digest, length: currentLength, boundary: consumed });
      try {
        onChunk(bytes, part, ledger.count - 1, control.context);
        control.check();
      } catch (cause) {
        throw wrap('CHUNK_SINK_FAILED', cause);
      }
      fingerprintHigh = 0; fingerprintLow = 0; currentLength = 0;
    }

    return Object.freeze({
      update(fragment) {
        if (failed) fail('CHUNK_SESSION_FAILED');
        if (finished) fail('CHUNK_SESSION_FINISHED');
        try {
          control.check();
          if (!(fragment instanceof Uint8Array) || fragment.byteLength > LIMITS.fragmentMaximum) fail('CHUNK_FRAGMENT_INVALID');
          const bytes = Buffer.from(fragment.buffer, fragment.byteOffset, fragment.byteLength);
          if (consumed + bytes.length > declaredLength) fail('CHUNK_SOURCE_TOO_LONG');
          for (let offset = 0; offset < bytes.length; offset += 1) {
            if ((offset & 0xffff) === 0) {
              control.check();
              whole.update(bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)));
            }
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
          ledger.dispose();
          control.dispose();
          throw normalizeError(error, 'CHUNK_SESSION_FAILED');
        }
      },
      async finish() {
        if (failed) fail('CHUNK_SESSION_FAILED');
        if (finished) fail('CHUNK_SESSION_FINISHED');
        try {
          control.check();
          if (consumed !== declaredLength) fail('CHUNK_SOURCE_TOO_SHORT');
          if (currentLength > 0) emit();
          const wholeFileDigest = whole.digest();
          const controlledRecords = function *records() {
            for (const record of ledger.records()) {
              control.check();
              yield record;
            }
          };
          const manifestDigest = createHash('sha256');
          const manifest = await control.wait(
            () => contentManifest(
              declaredLength,
              wholeFileDigest,
              () => controlledRecords(),
              {
                partCount: ledger.count,
                sink: manifestSink === undefined
                  ? undefined
                  : (bytes) => {
                    manifestDigest.update(bytes);
                    return manifestSink(bytes, control.context);
                  },
              },
            ),
            'CHUNK_SESSION_FAILED',
          );
          const ledgerMetrics = ledger.metrics();
          const retained = retainEntries ? [...controlledRecords()] : undefined;
          if (manifest.bytes !== undefined) manifestDigest.update(manifest.bytes);
          const verificationReceipt = createVerificationReceipt({
            profile: PROFILE_TEXT,
            manifestObjectId: manifest.objectId,
            manifestSha256: manifestDigest.digest('hex'),
            logicalBytes: String(declaredLength),
            wholeFileSha256: Buffer.from(wholeFileDigest).toString('hex'),
          });
          finished = true;
          return Object.freeze({
            boundaries: retained === undefined ? undefined : Object.freeze(retained.map(({ boundary }) => boundary)),
            chunks: retained === undefined ? undefined : Object.freeze(retained.map(({ boundary: _boundary, reference: _reference, ...part }) => Object.freeze({ ...part, digest: Buffer.from(part.digest) }))),
            class: declaredLength === 0 ? 'empty' : declaredLength <= LIMITS.smallMaximum ? 'whole' : 'cdc-1m',
            ledger: ledgerMetrics,
            logicalLength: declaredLength,
            manifest,
            verificationReceipt,
            wholeFileDigest,
          });
        } catch (error) {
          failed = true; finished = true;
          throw normalizeError(error, 'CHUNK_SESSION_FAILED');
        } finally {
          ledger.dispose();
          control.dispose();
        }
      },
      abort() {
        if (finished) return false;
        failed = true;
        finished = true;
        ledger.dispose();
        control.dispose();
        return true;
      },
    });
  } catch (cause) {
    control?.dispose();
    throw normalizeError(cause, 'CHUNK_RESOURCE_INVALID');
  }
}

export async function chunkBytes(bytes, options = {}) {
  try {
    if (!(bytes instanceof Uint8Array)) fail('CHUNK_FRAGMENT_INVALID');
    const chunks = [];
    const session = createChunker({
      ...options,
      declaredLength: options.declaredLength ?? bytes.byteLength,
      retainEntries: true,
      onChunk: (chunk, part, index, context) => {
        chunks.push(Buffer.from(chunk));
        options.onChunk?.(chunk, part, index, context);
      },
    });
    session.update(bytes);
    return Object.freeze({ ...await session.finish(), chunkBytes: Object.freeze(chunks) });
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_SESSION_FAILED');
  }
}
