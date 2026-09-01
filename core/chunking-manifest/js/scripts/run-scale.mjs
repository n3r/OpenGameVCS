import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { performance } from 'node:perf_hooks';

import { createChunker, LIMITS, PROFILE } from '../src/index.mjs';

const LOGICAL_BYTES = 100 * 1024 * 1024 * 1024;
const PATTERN_BYTES = 8 * 1024 * 1024;
const REPETITIONS = LOGICAL_BYTES / PATTERN_BYTES;
const LCG_SEED = 0x4f475643;
const LCG_MULTIPLIER = 1_664_525;
const LCG_INCREMENT = 1_013_904_223;
const PATTERN_SHA256 = 'b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4';
const WALL_TIME_MILLISECONDS_MAXIMUM = 18_000_000;
const CPU_TIME_MICROSECONDS_MAXIMUM = 36_000_000_000;
const PROCESS_WRITE_BYTES_MAXIMUM = 512 * 1024 * 1024;
const PEAK_RSS_BYTES_MAXIMUM = 512 * 1024 * 1024;
const LEDGER_MEMORY_BYTES_MAXIMUM = 1024 * 1024;
const LEDGER_SCRATCH_BYTES_MAXIMUM = 64 * 1024 * 1024;
const MANIFEST_BYTES_MAXIMUM = 64 * 1024 * 1024 + 2 * 1024;
const TRANSCRIPT_DOMAIN = Buffer.from('OGVCS-CHUNK-SCALE-BOUNDARY-TRANSCRIPT-V1\0', 'ascii');
const SHA = /^[0-9a-f]{40}$/u;
const IO_SOURCE = 'linux:/proc/self/io:read_bytes+write_bytes';
const PROCESS_WRITE_SOURCE = 'linux:/proc/self/io:wchar';
const RESOURCE_SCOPE = 'source-pattern-generation-through-scratch-cleanup-before-report-publication';

function fail(message) {
  throw new Error(`chunking exact-scale failure: ${message}`);
}

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function pattern() {
  const bytes = Buffer.allocUnsafe(PATTERN_BYTES);
  let state = LCG_SEED;
  for (let index = 0; index < bytes.length; index += 1) {
    state = (Math.imul(state, LCG_MULTIPLIER) + LCG_INCREMENT) >>> 0;
    bytes[index] = state >>> 24;
  }
  return bytes;
}

function transcriptRecord(index, digest, length, boundary) {
  const record = Buffer.allocUnsafe(24);
  record.writeBigUInt64BE(BigInt(index), 0);
  record.writeBigUInt64BE(BigInt(length), 8);
  record.writeBigUInt64BE(BigInt(boundary), 16);
  return [record.subarray(0, 8), digest, record.subarray(8)];
}

async function processIo() {
  const text = await readFile('/proc/self/io', 'utf8').catch(() => fail('Linux process I/O counters are unavailable'));
  const values = new Map(text.trim().split('\n').map((line) => {
    const separator = line.indexOf(':');
    return [line.slice(0, separator), line.slice(separator + 1).trim()];
  }));
  const readBytes = Number(values.get('read_bytes'));
  const writeBytes = Number(values.get('write_bytes'));
  const processWriteBytes = Number(values.get('wchar'));
  if (!Number.isSafeInteger(readBytes) || readBytes < 0 || !Number.isSafeInteger(writeBytes) || writeBytes < 0
      || !Number.isSafeInteger(processWriteBytes) || processWriteBytes < 0) {
    fail('Linux process I/O counters are invalid');
  }
  return { processWriteBytes, readBytes, writeBytes };
}

function requireEnvironment() {
  const sourceRevision = process.env.OGVCS_SOURCE_REVISION;
  const output = process.env.OGVCS_SCALE_REPORT_PATH;
  if (process.platform !== 'linux') fail('the exact campaign is Linux-only');
  if (typeof sourceRevision !== 'string' || !SHA.test(sourceRevision)) {
    fail('OGVCS_SOURCE_REVISION must be one exact lowercase Git object ID');
  }
  if (typeof output !== 'string' || !isAbsolute(output)) {
    fail('OGVCS_SCALE_REPORT_PATH must be absolute');
  }
  return { output, sourceRevision };
}

const { output, sourceRevision } = requireEnvironment();
const scratchRoot = await mkdtemp(join(process.env.RUNNER_TEMP ?? tmpdir(), 'ogvcs-chunk-scale-js-'));
let scratchArtifactsAfter = -1;
let scratchRootRemoved = false;

try {
  const cpuStarted = process.cpuUsage();
  const ioStarted = await processIo();
  const started = performance.now();
  const sourcePattern = pattern();
  if (createHash('sha256').update(sourcePattern).digest('hex') !== PATTERN_SHA256) {
    fail('the deterministic source pattern does not match its frozen digest');
  }
  const transcript = createHash('sha256').update(TRANSCRIPT_DOMAIN);
  const manifestSha256 = createHash('sha256');
  let manifestBytes = 0;
  let chunkCount = 0;
  let totalChunkBytes = 0;
  let minimumChunkBytes = Number.MAX_SAFE_INTEGER;
  let maximumChunkBytes = 0;

  const chunker = createChunker({
    declaredLength: LOGICAL_BYTES,
    maxElapsedMilliseconds: WALL_TIME_MILLISECONDS_MAXIMUM,
    maxLedgerMemoryBytes: LEDGER_MEMORY_BYTES_MAXIMUM,
    maxScratchBytes: LEDGER_SCRATCH_BYTES_MAXIMUM,
    scratchDirectory: scratchRoot,
    retainEntries: false,
    onChunk(_bytes, part, index) {
      totalChunkBytes += part.length;
      minimumChunkBytes = Math.min(minimumChunkBytes, part.length);
      maximumChunkBytes = Math.max(maximumChunkBytes, part.length);
      for (const value of transcriptRecord(index, part.digest, part.length, totalChunkBytes)) {
        transcript.update(value);
      }
      chunkCount += 1;
    },
    manifestSink(bytes) {
      manifestSha256.update(bytes);
      manifestBytes += bytes.byteLength;
    },
  });

  for (let repetition = 0; repetition < REPETITIONS; repetition += 1) {
    chunker.update(sourcePattern);
    if ((repetition + 1) % 640 === 0) {
      process.stderr.write(`[javascript-scale] ${(repetition + 1) / 128} GiB / 100 GiB\n`);
    }
  }

  const result = await chunker.finish();
  scratchArtifactsAfter = (await readdir(scratchRoot)).length;
  await rm(scratchRoot, { recursive: true });
  scratchRootRemoved = true;
  const wallTimeMilliseconds = Math.ceil(performance.now() - started);
  const cpu = process.cpuUsage(cpuStarted);
  const cpuMicroseconds = cpu.user + cpu.system;
  const ioEnded = await processIo();
  const diskReadBytes = ioEnded.readBytes - ioStarted.readBytes;
  const diskWriteBytes = ioEnded.writeBytes - ioStarted.writeBytes;
  const processWriteBytes = ioEnded.processWriteBytes - ioStarted.processWriteBytes;
  const peakRssBytes = process.resourceUsage().maxRSS * 1024;
  const throughputBytesPerSecond = Math.floor(LOGICAL_BYTES * 1000 / Math.max(1, wallTimeMilliseconds));

  const violations = [];
  if (result.logicalLength !== LOGICAL_BYTES || totalChunkBytes !== LOGICAL_BYTES) violations.push('logical byte accounting');
  if (result.class !== 'cdc-1m' || chunkCount < 1 || result.ledger.records !== chunkCount) violations.push('chunk accounting');
  if (minimumChunkBytes < 1 || maximumChunkBytes > LIMITS.maximum) violations.push('chunk size bounds');
  if (!result.ledger.spilled || result.ledger.peakMemoryBytes > LEDGER_MEMORY_BYTES_MAXIMUM
      || result.ledger.peakScratchBytes > LEDGER_SCRATCH_BYTES_MAXIMUM) violations.push('ledger bounds');
  if (manifestBytes < 1 || manifestBytes > MANIFEST_BYTES_MAXIMUM) violations.push('manifest bytes');
  if (scratchArtifactsAfter !== 0) violations.push('scratch cleanup');
  if (peakRssBytes > PEAK_RSS_BYTES_MAXIMUM) violations.push('peak RSS');
  if (cpuMicroseconds < 1 || cpuMicroseconds > CPU_TIME_MICROSECONDS_MAXIMUM) violations.push('CPU time');
  if (diskReadBytes < 0 || diskWriteBytes < 0 || processWriteBytes < 0
      || processWriteBytes > PROCESS_WRITE_BYTES_MAXIMUM) violations.push('process I/O counters');
  if (wallTimeMilliseconds > WALL_TIME_MILLISECONDS_MAXIMUM) violations.push('wall time');
  if (violations.length > 0) fail(`declared bounds failed: ${violations.join(', ')}`);

  const report = {
    schemaVersion: 'ogvcs.chunking-manifest/scale-report/v1',
    implementation: 'javascript',
    profile: 'chunking.opengamevcs/gear-fastcdc-1m@1',
    sourceRevision,
    exactScaleExecuted: true,
    runtime: {
      os: process.platform,
      architecture: process.arch,
      version: process.version,
    },
    source: {
      schemaVersion: 'ogvcs.chunking-manifest/scale-source-repeated-lcg-v1',
      logicalBytes: String(LOGICAL_BYTES),
      patternBytes: PATTERN_BYTES,
      repetitions: REPETITIONS,
      patternSha256: PATTERN_SHA256,
      seed: LCG_SEED,
      multiplier: LCG_MULTIPLIER,
      increment: LCG_INCREMENT,
      outputByte: 'state-bits-31-through-24-after-step',
    },
    result: {
      class: result.class,
      logicalBytes: String(result.logicalLength),
      chunkCount,
      totalChunkBytes: String(totalChunkBytes),
      minimumChunkBytes,
      maximumChunkBytes,
      wholeFileSha256: hex(result.wholeFileDigest),
      manifestObjectId: result.manifest.objectId,
      manifestSha256: manifestSha256.digest('hex'),
      manifestBytes,
      boundaryTranscriptSha256: transcript.digest('hex'),
    },
    resources: {
      wallTimeMilliseconds,
      cpuMicroseconds,
      cpuSource: 'node:process.cpuUsage:user+system-microseconds',
      diskReadBytes,
      diskWriteBytes,
      ioSource: IO_SOURCE,
      processWriteBytes,
      processWriteSource: PROCESS_WRITE_SOURCE,
      measurementScope: RESOURCE_SCOPE,
      throughputBytesPerSecond,
      peakRssBytes,
      maxRssSource: 'node:process.resourceUsage().maxRSS-kib',
      patternBufferBytes: sourcePattern.byteLength,
      scalarWorkingMemoryBytes: LIMITS.scalarWorkingMinimum,
      ledgerRecords: result.ledger.records,
      ledgerPeakMemoryBytes: result.ledger.peakMemoryBytes,
      ledgerPeakScratchBytes: result.ledger.peakScratchBytes,
      ledgerSpilled: result.ledger.spilled,
      scratchArtifactsAfter,
    },
    bounds: {
      wallTimeMillisecondsMaximum: WALL_TIME_MILLISECONDS_MAXIMUM,
      cpuTimeMicrosecondsMaximum: CPU_TIME_MICROSECONDS_MAXIMUM,
      processWriteBytesMaximum: PROCESS_WRITE_BYTES_MAXIMUM,
      peakRssBytesMaximum: PEAK_RSS_BYTES_MAXIMUM,
      ledgerMemoryBytesMaximum: LEDGER_MEMORY_BYTES_MAXIMUM,
      ledgerScratchBytesMaximum: LEDGER_SCRATCH_BYTES_MAXIMUM,
      manifestBytesMaximum: MANIFEST_BYTES_MAXIMUM,
      temporaryWholeFileAllowed: false,
    },
    overallStatus: 'passed',
  };

  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
} finally {
  if (!scratchRootRemoved) await rm(scratchRoot, { recursive: true, force: true });
}
