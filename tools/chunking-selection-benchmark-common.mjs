import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { chunkBytes, compareManifest, verifyManifest, LIMITS } from '../core/chunking-manifest/js/src/index.mjs';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const SPEC_ROOT = resolve(ROOT, 'spec/chunking-manifest/v1');
export const PACKAGE_JSON = resolve(ROOT, 'core/chunking-manifest/js/package.json');
export const RETAINED_ERROR_MESSAGE_LIMIT = 65_536;
export const RETAINED_BUNDLE_SOURCE_PATHS = [
  'tools/chunking-selection-benchmark-bundle.mjs',
  'tools/chunking-selection-benchmark-worker.mjs',
  'tools/verify-chunking-selection-benchmark-bundle.mjs',
];
const FAILURE_MESSAGES = Object.freeze({
  HARNESS_ASSERTION_FAILED: 'worker assertion failed before producing a valid retained capture',
  HARNESS_DRIVER_FAILED: 'worker failed before producing a valid retained capture',
  HARNESS_IO: 'worker I/O failed before producing a valid retained capture',
  HARNESS_LIMIT_EXCEEDED: 'worker output exceeded the bounded retained-capture limit',
  HARNESS_TASK_INCOMPLETE: 'worker did not complete before the bounded deadline',
});

export function canonicalJson(value, path = '$') {
  if (value === undefined) throw new Error(`canonical JSON cannot encode undefined at ${path}`);
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry, index) => canonicalJson(entry, `${path}[${index}]`)).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], `${path}.${key}`)}`).join(',')}}`;
}

export function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonicalJson(value)).digest('hex');
}

function compareCodeUnitStrings(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

export const PORTABLE_GZIP_ENCODER = 'ogvcs.portable-gzip-fixed-lz77/v1';

const LENGTH_BASES = Object.freeze([3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]);
const LENGTH_EXTRA_BITS = Object.freeze([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]);
const DISTANCE_BASES = Object.freeze([1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]);
const DISTANCE_EXTRA_BITS = Object.freeze([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]);

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) value = (value & 1) === 1 ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC32_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function reverseBits(value, count) {
  let reversed = 0;
  for (let index = 0; index < count; index += 1) {
    reversed = (reversed << 1) | (value & 1);
    value >>>= 1;
  }
  return reversed;
}

class DeflateBitWriter {
  #bytes = [];
  #pending = 0;
  #pendingBits = 0;

  writeBits(value, count) {
    this.#pending |= value << this.#pendingBits;
    this.#pendingBits += count;
    while (this.#pendingBits >= 8) {
      this.#bytes.push(this.#pending & 0xff);
      this.#pending >>>= 8;
      this.#pendingBits -= 8;
    }
  }

  finish() {
    if (this.#pendingBits > 0) this.#bytes.push(this.#pending & 0xff);
    return Buffer.from(this.#bytes);
  }
}

function writeFixedSymbol(writer, symbol) {
  if (symbol <= 143) writer.writeBits(reverseBits(0x30 + symbol, 8), 8);
  else if (symbol <= 255) writer.writeBits(reverseBits(0x190 + symbol - 144, 9), 9);
  else if (symbol <= 279) writer.writeBits(reverseBits(symbol - 256, 7), 7);
  else writer.writeBits(reverseBits(0xc0 + symbol - 280, 8), 8);
}

function tableIndex(value, bases) {
  for (let index = bases.length - 1; index >= 0; index -= 1) {
    if (value >= bases[index]) return index;
  }
  throw new Error('portable gzip table lookup failed');
}

function writeLengthDistance(writer, length, distance) {
  const lengthIndex = tableIndex(length, LENGTH_BASES);
  const lengthExtraBits = LENGTH_EXTRA_BITS[lengthIndex];
  writeFixedSymbol(writer, 257 + lengthIndex);
  if (lengthExtraBits > 0) writer.writeBits(length - LENGTH_BASES[lengthIndex], lengthExtraBits);

  const distanceIndex = tableIndex(distance, DISTANCE_BASES);
  const distanceExtraBits = DISTANCE_EXTRA_BITS[distanceIndex];
  writer.writeBits(reverseBits(distanceIndex, 5), 5);
  if (distanceExtraBits > 0) writer.writeBits(distance - DISTANCE_BASES[distanceIndex], distanceExtraBits);
}

function threeByteHash(bytes, offset) {
  return (((bytes[offset] * 251) + bytes[offset + 1]) * 251 + bytes[offset + 2]) & 0xffff;
}

function portableDeflateFixed(bytes) {
  const writer = new DeflateBitWriter();
  const latest = new Int32Array(65_536);
  latest.fill(-1);
  writer.writeBits(1, 1); // BFINAL
  writer.writeBits(1, 2); // BTYPE=01, fixed Huffman

  let offset = 0;
  while (offset < bytes.length) {
    let matchLength = 0;
    let matchDistance = 0;
    if (offset + 2 < bytes.length) {
      const hash = threeByteHash(bytes, offset);
      const previous = latest[hash];
      latest[hash] = offset;
      if (previous >= 0 && offset - previous <= 32_768) {
        const maximum = Math.min(258, bytes.length - offset);
        let length = 0;
        while (length < maximum && bytes[previous + length] === bytes[offset + length]) length += 1;
        if (length >= 3) {
          matchLength = length;
          matchDistance = offset - previous;
        }
      }
    }

    if (matchLength >= 3) {
      writeLengthDistance(writer, matchLength, matchDistance);
      const end = offset + matchLength;
      for (let skipped = offset + 1; skipped < end && skipped + 2 < bytes.length; skipped += 1) {
        latest[threeByteHash(bytes, skipped)] = skipped;
      }
      offset = end;
    } else {
      writeFixedSymbol(writer, bytes[offset]);
      offset += 1;
    }
  }
  writeFixedSymbol(writer, 256);
  return writer.finish();
}

export function deterministicGzip(bytes) {
  const source = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const header = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);
  const trailer = Buffer.alloc(8);
  trailer.writeUInt32LE(crc32(source), 0);
  trailer.writeUInt32LE(source.length >>> 0, 4);
  return Buffer.concat([header, portableDeflateFixed(source), trailer]);
}

export function stableFailureCode(code) {
  return ['HARNESS_ASSERTION_FAILED', 'HARNESS_DRIVER_FAILED', 'HARNESS_TASK_INCOMPLETE', 'HARNESS_IO', 'HARNESS_LIMIT_EXCEEDED'].includes(code)
    ? code
    : 'HARNESS_DRIVER_FAILED';
}

export function truncateUtf8Scalars(value, maximum, fallback) {
  const normalized = (typeof value === 'string' ? value : fallback)
    .normalize('NFC')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\uD800-\uDFFF]/gu, '');
  const source = normalized.length === 0 ? fallback : normalized;
  const units = [];
  let bytes = 0;
  for (const scalar of source) {
    const scalarBytes = Buffer.byteLength(scalar, 'utf8');
    if (bytes + scalarBytes > maximum) break;
    units.push(scalar);
    bytes += scalarBytes;
  }
  const bounded = units.join('');
  if (bounded.length > 0) return bounded;
  if (fallback === undefined) return '';
  if (source === fallback) return '';
  return truncateUtf8Scalars(fallback, maximum);
}

export function stableFailureMessage(code) {
  return FAILURE_MESSAGES[stableFailureCode(code)] ?? FAILURE_MESSAGES.HARNESS_DRIVER_FAILED;
}

export function normalizeRetainedFailureError(error) {
  const stableCode = stableFailureCode(error?.code);
  return {
    code: stableCode,
    name: 'Error',
    message: truncateUtf8Scalars(stableFailureMessage(stableCode), RETAINED_ERROR_MESSAGE_LIMIT, 'worker failure'),
  };
}

async function collectEntries(root, relativePath, results) {
  const absolutePath = join(root, relativePath);
  const directoryEntries = await readdir(absolutePath, { withFileTypes: true }).catch(() => null);
  if (directoryEntries === null) {
    const bytes = await readFile(absolutePath);
    results.push({ bytes: bytes.length, path: relativePath.replaceAll('\\', '/'), sha256: sha256(bytes) });
    return;
  }
  for (const entry of directoryEntries) {
    const entryPath = join(relativePath, entry.name);
    if (entry.isDirectory()) await collectEntries(root, entryPath, results);
    else if (entry.isFile()) {
      const bytes = await readFile(join(root, entryPath));
      results.push({ bytes: bytes.length, path: entryPath.replaceAll('\\', '/'), sha256: sha256(bytes) });
    }
  }
}

export async function fileEntries(root, paths) {
  const results = [];
  for (const relativePath of paths) await collectEntries(root, relativePath, results);
  return results.sort((left, right) => compareCodeUnitStrings(left.path, right.path));
}

export function digestEntries(entries, domain) {
  return sha256(entries.map(({ path, bytes, sha256: digest }) => ({ path, bytes, sha256: digest, domain })));
}

export async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

export function sha256Counter(seed, length) {
  const output = Buffer.alloc(length);
  let offset = 0;
  let counter = 0n;
  while (offset < output.length) {
    const suffix = Buffer.alloc(8);
    suffix.writeBigUInt64BE(counter);
    const block = createHash('sha256')
      .update('OpenGameVCS chunk vector block v1\0')
      .update(seed)
      .update('\0')
      .update(suffix)
      .digest();
    const take = Math.min(32, output.length - offset);
    block.copy(output, offset, 0, take);
    offset += take;
    counter += 1n;
  }
  return output;
}

function sourceLikeText({ lines, salt = 0, editStartLine = 0, editLineCount = 0 }) {
  const rows = [];
  for (let index = 0; index < lines; index += 1) {
    const edited = index >= editStartLine && index < editStartLine + editLineCount;
    const value = edited ? (index * (salt + 7)) % 997 : index % 997;
    const flags = edited ? (index + salt) % 19 : index % 19;
    rows.push(`asset_${index.toString(16).padStart(6, '0')} class=${index % 5} value=${value.toString().padStart(3, '0')} flags=${flags.toString().padStart(2, '0')}\n`);
  }
  return Buffer.from(rows.join(''), 'utf8');
}

function structuredRecords({ records, salt = 0, editStartRecord = 0, editRecordCount = 0 }) {
  const rows = [];
  for (let index = 0; index < records; index += 1) {
    const edited = index >= editStartRecord && index < editStartRecord + editRecordCount;
    const weight = edited ? ((index * 31) + salt) % 10000 : index % 10000;
    const enabled = edited ? (index + salt) % 2 : index % 2;
    rows.push(`{"id":"${index.toString().padStart(6, '0')}","zone":"${(index % 32).toString().padStart(2, '0')}","owner":"${(index % 7).toString().padStart(2, '0')}","enabled":"${enabled}","weight":"${weight.toString().padStart(4, '0')}"}\n`);
  }
  return Buffer.from(rows.join(''), 'utf8');
}

export function materialize(recipe) {
  switch (recipe.kind) {
    case 'literal':
      return Buffer.from(recipe.hex, 'hex');
    case 'repeat':
      return Buffer.alloc(recipe.length, recipe.byte);
    case 'sha256-counter':
      return sha256Counter(recipe.seed, recipe.length);
    case 'source-like-text':
      return sourceLikeText(recipe);
    case 'structured-records':
      return structuredRecords(recipe);
    case 'gzip':
      if (recipe.encoder !== PORTABLE_GZIP_ENCODER) throw new Error(`unsupported portable gzip encoder ${recipe.encoder}`);
      return deterministicGzip(materialize(recipe.source));
    case 'insert': {
      const base = materialize(recipe.base);
      return Buffer.concat([base.subarray(0, recipe.offset), Buffer.from(recipe.hex, 'hex'), base.subarray(recipe.offset)]);
    }
    case 'replace-window': {
      const base = materialize(recipe.base);
      const replacement = materialize(recipe.replacement);
      return Buffer.concat([base.subarray(0, recipe.offset), replacement, base.subarray(recipe.offset + replacement.length)]);
    }
    case 'append': {
      const base = materialize(recipe.base);
      return Buffer.concat([base, materialize(recipe.suffix)]);
    }
    default:
      throw new Error(`unknown recipe kind ${recipe.kind}`);
  }
}

async function measureMicroseconds(operation) {
  const start = process.hrtime.bigint();
  const value = operation();
  return Promise.resolve(value).then((resolved) => ({
    elapsedMicroseconds: Number((process.hrtime.bigint() - start) / 1000n),
    value: resolved,
  }));
}

export function throughputBytesPerSecond(bytes, elapsedMicroseconds) {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error('throughput bytes must be a non-negative safe integer');
  return elapsedMicroseconds === 0 ? bytes * 1_000_000 : Math.floor((bytes * 1_000_000) / elapsedMicroseconds);
}

export function firstDifference(left, right) {
  const maximum = Math.min(left.length, right.length);
  for (let index = 0; index < maximum; index += 1) {
    if (left[index] !== right[index]) return index;
  }
  return maximum;
}

function chunkOccurrences(result) {
  let start = 0;
  return result.chunks.map((part, index) => {
    const end = result.boundaries[index];
    const occurrence = { chunkIndex: index, end, length: part.length, objectId: part.objectId, start };
    start = end;
    return occurrence;
  });
}

export function resynchronizationAfterMutation(baseResult, candidateResult, mutationStartByte) {
  const baseOccurrences = chunkOccurrences(baseResult);
  const candidateOccurrences = chunkOccurrences(candidateResult);
  const baseByObjectId = new Map();
  for (const occurrence of baseOccurrences) {
    if (!baseByObjectId.has(occurrence.objectId)) baseByObjectId.set(occurrence.objectId, []);
    baseByObjectId.get(occurrence.objectId).push(occurrence);
  }
  const aligned = candidateOccurrences.find((candidate) => candidate.start >= mutationStartByte
    && (baseByObjectId.get(candidate.objectId) ?? []).some((base) => base.start >= mutationStartByte));
  if (!aligned) {
    return {
      firstAlignedCandidateChunkIndex: null,
      firstAlignedCandidateOffset: null,
      firstAlignedChunkObjectId: null,
      firstAlignedBaseChunkIndex: null,
      firstAlignedBaseOffset: null,
      metric: 'no-post-mutation-aligned-reused-chunk',
      resynchronizationDistanceBytes: null,
      schemaVersion: 'ogvcs.chunking/resynchronization-summary/v1',
    };
  }
  const base = baseByObjectId.get(aligned.objectId).find((occurrence) => occurrence.start >= mutationStartByte);
  return {
    firstAlignedBaseChunkIndex: base.chunkIndex,
    firstAlignedBaseOffset: base.start,
    firstAlignedCandidateChunkIndex: aligned.chunkIndex,
    firstAlignedCandidateOffset: aligned.start,
    firstAlignedChunkObjectId: aligned.objectId,
    metric: 'candidate-offset-to-first-post-mutation-aligned-reused-chunk',
    resynchronizationDistanceBytes: aligned.start - mutationStartByte,
    schemaVersion: 'ogvcs.chunking/resynchronization-summary/v1',
  };
}

export function evaluateSelectionThresholds(thresholdFile, workloads) {
  const rows = [];
  const workloadMap = new Map(workloads.map((row) => [row.workloadId, row]));
  const workloadCount = workloads.length;
  const successCount = workloads.filter(({ success }) => success).length;
  const accountingMismatchCount = workloads.filter(({ accounting }) => !accounting.balanced).length;
  for (const entry of thresholdFile.entries) {
    let actual;
    switch (entry.metric) {
      case 'workloadCount':
        actual = workloadCount;
        break;
      case 'successCount':
        actual = entry.workloadId === '*'
          ? successCount
          : workloadMap.get(entry.workloadId)?.success ? 1 : 0;
        break;
      case 'accountingMismatchCount':
        actual = accountingMismatchCount;
        break;
      case 'reusedBytes':
        actual = Number(workloadMap.get(entry.workloadId)?.compare.reusedBytes ?? 0);
        break;
      case 'newlyRequiredBytes':
        actual = Number(workloadMap.get(entry.workloadId)?.compare.newlyRequiredBytes ?? 0);
        break;
      case 'resynchronizationDistanceBytes': {
        const value = workloadMap.get(entry.workloadId)?.deltas.resynchronization.resynchronizationDistanceBytes;
        actual = value === null ? Number.MAX_SAFE_INTEGER : value;
        break;
      }
      default:
        throw new Error(`unknown threshold metric ${entry.metric}`);
    }
    const passed = entry.operator === 'maximum' ? actual <= entry.value : actual >= entry.value;
    rows.push({
      actual,
      expected: entry.value,
      metric: entry.metric,
      operator: entry.operator,
      requirementId: entry.requirementId,
      schemaVersion: 'ogvcs.chunking/selection-benchmark-threshold-evaluation/v1',
      severity: entry.severity,
      status: passed ? 'passed' : 'failed',
      thresholdId: entry.id,
      workloadId: entry.workloadId,
    });
  }
  return rows;
}

export async function implementationIdentity(packageJson) {
  const entries = await fileEntries(dirname(PACKAGE_JSON), ['package.json', ...packageJson.files]);
  return {
    id: '@opengamevcs/chunking-manifest/javascript',
    package: packageJson.name,
    packageJsonSha256: sha256(await readFile(PACKAGE_JSON)),
    publishedFileCount: entries.length,
    publishedFileSetSha256: digestEntries(entries, 'ogvcs.chunking/package-files/v1'),
    version: packageJson.version,
  };
}

export async function sourceIdentity(extraPaths = []) {
  const entries = await fileEntries(ROOT, [
    'core/chunking-manifest/js/LICENSE',
    'core/chunking-manifest/js/README.md',
    'core/chunking-manifest/js/package.json',
    'core/chunking-manifest/js/src',
    'spec/chunking-manifest/v1/docs',
    'spec/chunking-manifest/v1/manifest.json',
    'spec/chunking-manifest/v1/profiles',
    'spec/chunking-manifest/v1/registries',
    'spec/chunking-manifest/v1/schemas',
    'spec/chunking-manifest/v1/scripts',
    'spec/chunking-manifest/v1/thresholds',
    'spec/chunking-manifest/v1/vectors',
    'tools/chunking-selection-benchmark-common.mjs',
    'tools/chunking-selection-benchmark-report.mjs',
    ...extraPaths,
  ]);
  return {
    entryCount: entries.length,
    sourceSetSha256: digestEntries(entries, 'ogvcs.chunking/selection-benchmark-source-set/v1'),
    type: 'selection-benchmark-source-set/v1',
  };
}

export async function loadSelectionAuthority(options = {}) {
  const [contract, thresholdFile, workloadFile, packageJson] = await Promise.all([
    json(join(SPEC_ROOT, 'manifest.json')),
    options.thresholdFile ?? json(join(SPEC_ROOT, 'thresholds/selection-bounded-v1.json')),
    json(join(SPEC_ROOT, 'vectors/selection-benchmark-workloads.json')),
    json(PACKAGE_JSON),
  ]);
  return {
    contract,
    packageJson,
    thresholdFile,
    workloadFile,
    workloadDefinitionsDigest: sha256(workloadFile.workloads),
  };
}

export async function buildChunkingSelectionWorkload(definition) {
  const baseBytes = materialize(definition.baseRecipe);
  const candidateBytes = materialize(definition.candidateRecipe);
  const base = await measureMicroseconds(() => chunkBytes(baseBytes));
  const candidate = await measureMicroseconds(() => chunkBytes(candidateBytes));
  const knownChunks = new Map(base.value.chunks.map((part) => [part.objectId, part.length]));
  const comparison = await measureMicroseconds(() => compareManifest({ manifest: candidate.value.manifest.bytes, knownChunks }));
  const source = new Map(candidate.value.chunks.map((part, index) => [part.objectId, candidate.value.chunkBytes[index]]));
  const verification = await measureMicroseconds(() => verifyManifest({ manifest: candidate.value.manifest.bytes, source }));
  const { verificationReceipt, ...verificationSummary } = verification.value;
  const mutationStartByte = firstDifference(baseBytes, candidateBytes);
  const resynchronization = resynchronizationAfterMutation(base.value, candidate.value, mutationStartByte);
  const accounting = {
    balanced: Number(comparison.value.reusedBytes) + Number(comparison.value.newlyRequiredBytes) === Number(comparison.value.uniqueBytes)
      && Number(comparison.value.logicalBytes) === Number(comparison.value.uniqueBytes) + Number(comparison.value.repeatedBytes)
      && Number(verificationSummary.uniqueBytes) === Number(comparison.value.uniqueBytes)
      && Number(verificationSummary.repeatedBytes) === Number(comparison.value.repeatedBytes),
    schemaVersion: 'ogvcs.chunking/selection-benchmark-accounting/v1',
  };
  return {
    accounting,
    base: {
      generationMicroseconds: base.elapsedMicroseconds,
      ledger: base.value.ledger,
      logicalBytes: base.value.logicalLength,
      manifestBytes: base.value.manifest.bytes.length,
      partCount: base.value.chunks.length,
      throughputBytesPerSecond: throughputBytesPerSecond(base.value.logicalLength, base.elapsedMicroseconds),
      wholeFileSha256: base.value.wholeFileDigest.toString('hex'),
    },
    candidate: {
      generationMicroseconds: candidate.elapsedMicroseconds,
      ledger: candidate.value.ledger,
      logicalBytes: candidate.value.logicalLength,
      manifestBytes: candidate.value.manifest.bytes.length,
      partCount: candidate.value.chunks.length,
      throughputBytesPerSecond: throughputBytesPerSecond(candidate.value.logicalLength, candidate.elapsedMicroseconds),
      wholeFileSha256: candidate.value.wholeFileDigest.toString('hex'),
    },
    class: definition.class,
    compare: {
      ...comparison.value,
      compareMicroseconds: comparison.elapsedMicroseconds,
      throughputBytesPerSecond: throughputBytesPerSecond(candidate.value.logicalLength, comparison.elapsedMicroseconds),
    },
    deltas: {
      manifestBytesDelta: candidate.value.manifest.bytes.length - base.value.manifest.bytes.length,
      mutationStartByte,
      partCountDelta: candidate.value.chunks.length - base.value.chunks.length,
      resynchronization,
      reusedRatioPartsPerMillion: Math.floor((Number(comparison.value.reusedBytes) * 1_000_000) / Math.max(1, candidate.value.logicalLength)),
    },
    description: definition.description,
    exactScaleExecuted: false,
    mutationKind: definition.mutationKind,
    schemaVersion: 'ogvcs.chunking/selection-workload-report/v1',
    success: true,
    verify: {
      ...verificationSummary,
      verifyMicroseconds: verification.elapsedMicroseconds,
      throughputBytesPerSecond: throughputBytesPerSecond(candidate.value.logicalLength, verification.elapsedMicroseconds),
    },
    workloadId: definition.workloadId,
  };
}

export async function buildSelectionReportFromWorkloads({ workloads, contract, thresholdFile, workloadDefinitionsDigest, packageJson, generatedAt = new Date().toISOString(), host, extraSourcePaths = [] }) {
  const thresholdEvaluations = evaluateSelectionThresholds(thresholdFile, workloads);
  const thresholdFailed = thresholdEvaluations.some(({ status }) => status === 'failed');
  const warningCount = thresholdEvaluations.filter(({ severity, status }) => severity === 'warning' && status === 'failed').length;
  const summary = {
    accountingMismatchCount: workloads.filter(({ accounting }) => !accounting.balanced).length,
    baseLogicalBytes: workloads.reduce((sum, row) => sum + row.base.logicalBytes, 0),
    candidateLogicalBytes: workloads.reduce((sum, row) => sum + row.candidate.logicalBytes, 0),
    exactScaleExecuted: false,
    successCount: workloads.filter(({ success }) => success).length,
    thresholdFailureCount: thresholdEvaluations.filter(({ status }) => status === 'failed').length,
    totalNewlyRequiredBytes: workloads.reduce((sum, row) => sum + Number(row.compare.newlyRequiredBytes), 0),
    totalReusedBytes: workloads.reduce((sum, row) => sum + Number(row.compare.reusedBytes), 0),
    warningCount,
    workloadCount: workloads.length,
  };
  const reportBody = {
    contractManifestSha256: contract.artifacts ? sha256(await readFile(join(SPEC_ROOT, 'manifest.json'))) : contract.manifestSha256,
    exactScaleExecuted: false,
    generatedAt,
    host: host ?? { architecture: process.arch, node: process.versions.node, os: process.platform },
    implementation: await implementationIdentity(packageJson),
    overallStatus: thresholdFailed ? 'failed' : 'passed',
    profile: contract.profile,
    scalarWorkingMemoryBytesMinimum: LIMITS.scalarWorkingMinimum,
    schemaVersion: 'ogvcs.chunking/selection-benchmark-report/v1',
    sourceIdentity: await sourceIdentity(extraSourcePaths),
    summary,
    thresholdEvaluations,
    thresholdFile,
    thresholdFileDigest: sha256(thresholdFile),
    workloadDefinitionsDigest,
    workloads,
  };
  return { ...reportBody, reportSha256: sha256(reportBody) };
}

export async function buildChunkingSelectionReport(options = {}) {
  const { contract, thresholdFile, workloadFile, workloadDefinitionsDigest, packageJson } = await loadSelectionAuthority(options);
  const workloads = [];
  for (const definition of workloadFile.workloads) workloads.push(await buildChunkingSelectionWorkload(definition));
  const mutatedWorkloads = typeof options.mutateWorkloads === 'function' ? options.mutateWorkloads(workloads) : workloads;
  return buildSelectionReportFromWorkloads({
    workloads: mutatedWorkloads,
    contract,
    thresholdFile,
    workloadDefinitionsDigest,
    packageJson,
    extraSourcePaths: options.extraSourcePaths ?? [],
  });
}
