#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import {
  createDiskFileIdIndex,
  hashObject,
  loadBundledRegistry,
  writeContentManifest,
  writeOrderedTree,
  writeSortedTree
} from '../src/index.js';

const EXACT_TREE_COUNT = 1_000_000;
const EXACT_MANIFEST_COUNT = 1_048_576;
const EXACT_CHUNK_BYTES = 1_048_576;
const TREE_SEED = Buffer.from('a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80', 'hex');
const MANIFEST_SEED = Buffer.from('860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65', 'hex');
const DESCRIPTOR = new Map([[0, 1], [1, 6], [2, 1],
  [3, Buffer.from('dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545', 'hex')]]);
const TREE_TARGET = new Map([[0, 1], [1, 2], [2, 1],
  [3, Buffer.from('82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12', 'hex')]]);
const CONTENT_PROFILE = new Map([[0, 'content-policy.test'], [1, 'opaque'], [2, 1]]);
const CHUNK_PROFILE = new Map([[0, 'chunking.test'], [1, 'external-boundaries'], [2, 1]]);
const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const NPM_CLI = process.env.npm_execpath ?? (process.platform === 'win32'
  ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
  : undefined);

function parsePositive(text, flag) {
  if (!/^[1-9][0-9]*$/.test(text ?? '')) throw new Error(`${flag} requires a positive decimal integer`);
  const value = Number(text);
  if (!Number.isSafeInteger(value)) throw new Error(`${flag} is outside the safe integer range`);
  return value;
}

function parseArguments(argv) {
  const result = {
    treeCount: EXACT_TREE_COUNT,
    manifestCount: EXACT_MANIFEST_COUNT,
    chunkBytes: EXACT_CHUNK_BYTES,
    structuralOnly: false,
    worker: false
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--worker') result.worker = true;
    else if (argument === '--structural-only') result.structuralOnly = true;
    else if (argument === '--smoke') {
      result.treeCount = 10_000;
      result.manifestCount = 4_096;
      result.chunkBytes = 4_096;
    } else if (argument === '--tree-count') result.treeCount = parsePositive(argv[++index], argument);
    else if (argument === '--manifest-count') result.manifestCount = parsePositive(argv[++index], argument);
    else if (argument === '--chunk-bytes') result.chunkBytes = parsePositive(argv[++index], argument);
    else throw new Error(`unknown argument: ${argument}`);
  }
  if (result.treeCount > EXACT_TREE_COUNT || result.manifestCount > EXACT_MANIFEST_COUNT ||
      result.chunkBytes > 67_108_864 || BigInt(result.manifestCount) * BigInt(result.chunkBytes) > 1_099_511_627_776n) {
    throw new Error('requested scale exceeds repository-format-v1 hard limits');
  }
  return result;
}

function uint64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; }
function uint32(value) { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }

function treeFileId(index) {
  for (let attempt = 0; attempt <= 0xffff_ffff; attempt += 1) {
    const candidate = createHash('sha256').update(TREE_SEED).update(Uint8Array.of(0x46))
      .update(uint64(index)).update(uint32(attempt)).digest().subarray(0, 16);
    if (candidate.some(byte => byte !== 0)) return new Uint8Array(candidate);
  }
  throw new Error('tree FileID recurrence exhausted uint32 attempts');
}

function treeEntry(index) {
  return new Map([[0, `e${String(index).padStart(6, '0')}`], [1, 2], [2, treeFileId(index)], [3, 2],
    [4, TREE_TARGET], [5, 24], [6, CONTENT_PROFILE]]);
}

function* orderedTree(count) { for (let index = 0; index < count; index += 1) yield treeEntry(index); }
function* reversedTree(count) { for (let index = count - 1; index >= 0; index -= 1) yield treeEntry(index); }

function repeatedChunk(length) {
  const block = createHash('sha256').update(MANIFEST_SEED).update(Uint8Array.of(0x43))
    .update(Buffer.from('repeated-chunk-v1', 'ascii')).digest();
  const chunk = new Uint8Array(length);
  for (let offset = 0; offset < chunk.length; offset += block.length) {
    chunk.set(block.subarray(0, Math.min(block.length, chunk.length - offset)), offset);
  }
  return { block: new Uint8Array(block), chunk };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function summaryDigest(summary) {
  return createHash('sha256').update(canonicalJson(summary), 'utf8').digest('hex');
}

async function filesEqual(leftPath, rightPath) {
  const left = await open(leftPath, 'r');
  const right = await open(rightPath, 'r');
  const leftBuffer = new Uint8Array(1_048_576);
  const rightBuffer = new Uint8Array(1_048_576);
  let position = 0;
  try {
    while (true) {
      const [a, b] = await Promise.all([
        left.read(leftBuffer, 0, leftBuffer.length, position),
        right.read(rightBuffer, 0, rightBuffer.length, position)
      ]);
      if (a.bytesRead !== b.bytesRead) return false;
      if (a.bytesRead === 0) return true;
      if (!Buffer.from(leftBuffer.subarray(0, a.bytesRead)).equals(Buffer.from(rightBuffer.subarray(0, b.bytesRead)))) return false;
      position += a.bytesRead;
    }
  } finally {
    await Promise.all([left.close(), right.close()]);
  }
}

async function fileSha256(path) {
  const handle = await open(path, 'r');
  const buffer = new Uint8Array(1_048_576);
  const hash = createHash('sha256');
  let position = 0;
  try {
    const initial = await handle.stat();
    if (!initial.isFile()) throw new Error('scale payload is not a regular file');
    while (position < initial.size) {
      const result = await handle.read(buffer, 0, Math.min(buffer.length, initial.size - position), position);
      if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead <= 0) {
        throw new Error('scale payload changed or truncated while hashing');
      }
      hash.update(buffer.subarray(0, result.bytesRead));
      position += result.bytesRead;
    }
    const final = await handle.stat();
    if (final.size !== initial.size || final.mtimeMs !== initial.mtimeMs || final.ctimeMs !== initial.ctimeMs) {
      throw new Error('scale payload changed while hashing');
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

async function timed(operation) {
  const started = process.hrtime.bigint();
  const value = await operation();
  return { value, wallTimeNanoseconds: (process.hrtime.bigint() - started).toString() };
}

async function invokePublicCli(arguments_) {
  const executable = process.env.OGVCS_SCALE_PACKAGED_CLI_PATH;
  if (!executable) throw new Error('scale worker requires an offline-installed packaged CLI path');
  const child = spawn(process.execPath, [executable, ...arguments_], { stdio: ['ignore', 'pipe', 'inherit'] });
  const chunks = [];
  child.stdout.on('data', chunk => chunks.push(chunk));
  const closed = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  if (closed.code !== 0) throw new Error(`public CLI failed: ${closed.signal ?? closed.code}`);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function runChild(command, arguments_, options = {}) {
  const child = spawn(command, arguments_, {
    cwd: options.cwd,
    env: options.env ?? process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  const stdout = []; const stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk));
  child.stderr.on('data', chunk => stderr.push(chunk));
  const closed = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  const result = { ...closed, stderr: Buffer.concat(stderr).toString('utf8'), stdout: Buffer.concat(stdout).toString('utf8') };
  if (closed.code !== 0) throw new Error(`${command} failed: ${result.stderr || result.stdout || closed.signal}`);
  return result;
}

function runNpm(arguments_, options = {}) {
  if (NPM_CLI) return runChild(process.execPath, [NPM_CLI, ...arguments_], options);
  return runChild('npm', arguments_, options);
}

async function preparePackagedCli() {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-js-scale-package-'));
  const packDirectory = join(directory, 'pack');
  const consumer = join(directory, 'consumer');
  const cache = join(directory, 'npm-cache');
  await Promise.all([mkdir(packDirectory), mkdir(consumer)]);
  const environment = {
    ...process.env,
    npm_config_audit: 'false',
    npm_config_cache: cache,
    npm_config_fund: 'false'
  };
  try {
    const packed = await runNpm(['pack', PACKAGE_ROOT, '--json', '--pack-destination', packDirectory], {
      cwd: PACKAGE_ROOT, env: environment
    });
    const result = JSON.parse(packed.stdout);
    if (!Array.isArray(result) || result.length !== 1) throw new Error('npm pack returned an invalid package result');
    const tarball = join(packDirectory, basename(result[0].filename));
    await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', 'utf8');
    await runNpm([
      'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', tarball
    ], { cwd: consumer, env: environment });
    const installedRoot = join(consumer, 'node_modules', '@opengamevcs', 'object-model');
    const metadata = JSON.parse(await readFile(join(installedRoot, 'package.json'), 'utf8'));
    if (metadata.name !== '@opengamevcs/object-model' || typeof metadata.version !== 'string') {
      throw new Error('offline-installed scale package identity is invalid');
    }
    return {
      directory,
      executable: join(installedRoot, 'bin', 'ogvcs-object.mjs'),
      name: metadata.name,
      tarballSha256Hex: await fileSha256(tarball),
      version: metadata.version
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
    throw error;
  }
}

async function runWorker(options) {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-js-scale-'));
  const scratch = join(directory, 'scratch');
  const orderedPath = join(directory, 'tree-ordered.cbor');
  const sortedPath = join(directory, 'tree-sorted.cbor');
  const manifestPath = join(directory, 'manifest.cbor');
  await mkdir(scratch, { mode: 0o700 });
  try {
    const registry = await loadBundledRegistry();
    const orderedFile = await open(orderedPath, 'wx', 0o600);
    let ordered;
    try {
      const fileIdIndex = await createDiskFileIdIndex({
        scratchDirectory: scratch,
        maxMemoryBytes: 16_777_216,
        maxRunBytes: 8_388_608,
        maxOpenRuns: 32,
        maxScratchBytes: 268_435_456
      });
      ordered = await timed(() => writeOrderedTree({
        descriptor: DESCRIPTOR,
        entryCount: options.treeCount,
        entries: orderedTree(options.treeCount),
        sink: orderedFile,
        maxMemoryBytes: 67_108_864,
        fileIdIndex,
        registry,
        operation: 'conformance'
      }));
    } finally { await orderedFile.close(); }

    const sortedFile = await open(sortedPath, 'wx', 0o600);
    let sorted;
    try {
      sorted = await timed(() => writeSortedTree({
        descriptor: DESCRIPTOR,
        entryCount: options.treeCount,
        entries: reversedTree(options.treeCount),
        sink: sortedFile,
        scratchDirectory: scratch,
        maxMemoryBytes: 67_108_864,
        maxRunBytes: 33_554_432,
        maxOpenRuns: 32,
        maxScratchBytes: 805_306_368,
        registry,
        operation: 'conformance'
      }));
    } finally { await sortedFile.close(); }
    assert.equal(ordered.value.objectRef.toString(), sorted.value.objectRef.toString());
    assert.equal(canonicalJson(ordered.value.summary), canonicalJson(sorted.value.summary));
    assert.equal(await filesEqual(orderedPath, sortedPath), true);
    const [treePayloadSha256Hex, sortedTreePayloadSha256Hex] = await Promise.all([
      fileSha256(orderedPath), fileSha256(sortedPath)
    ]);
    assert.match(treePayloadSha256Hex, /^[0-9a-f]{64}$/);
    assert.equal(treePayloadSha256Hex, sortedTreePayloadSha256Hex);
    const cli = await invokePublicCli(['tree', 'verify', orderedPath, '--descriptor',
      'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
      '--scratch', scratch, '--operation', 'conformance', '--max-memory-bytes', '67108864',
      '--max-scratch-bytes', '268435456']);
    assert.equal(cli.ok, true);
    assert.equal(cli.result.objectRef, ordered.value.objectRef.toString());
    assert.equal(cli.result.entryCount, options.treeCount);

    const { block, chunk } = repeatedChunk(options.chunkBytes);
    const chunkReference = hashObject(1, chunk);
    const part = new Map([[0, chunkReference.toMap()], [1, options.chunkBytes]]);
    const partFactory = () => ({
      *[Symbol.iterator]() { for (let index = 0; index < options.manifestCount; index += 1) yield part; }
    });
    const manifestFile = await open(manifestPath, 'wx', 0o600);
    let manifest;
    try {
      if (options.structuralOnly) {
        const marker = createHash('sha256').update(Buffer.from('OGVCS structural-only manifest\0', 'ascii'))
          .update(block).update(uint64(options.manifestCount)).update(uint64(options.chunkBytes)).digest();
        manifest = await timed(() => writeContentManifest({
          logicalLength: BigInt(options.manifestCount) * BigInt(options.chunkBytes),
          wholeFileDigest: new Map([[0, 1], [1, new Uint8Array(marker)]]),
          chunkProfile: CHUNK_PROFILE,
          partCount: options.manifestCount,
          parts: partFactory(),
          sink: manifestFile,
          maxMemoryBytes: 67_108_864,
          registry,
          operation: 'conformance'
        }));
      } else {
        manifest = await timed(() => writeContentManifest({
          logicalLength: BigInt(options.manifestCount) * BigInt(options.chunkBytes),
          chunkProfile: CHUNK_PROFILE,
          partCount: options.manifestCount,
          parts: partFactory,
          chunkProvider: () => chunk,
          sink: manifestFile,
          maxMemoryBytes: 67_108_864,
          registry,
          operation: 'conformance'
        }));
      }
    } finally { await manifestFile.close(); }
    const manifestPayloadSha256Hex = await fileSha256(manifestPath);
    assert.match(manifestPayloadSha256Hex, /^[0-9a-f]{64}$/);

    const usage = process.resourceUsage();
    return {
      schema: 'ogvcs.object-model.javascript-scale-report/v1',
      sourceRevision: process.env.GITHUB_SHA ?? null,
      implementation: '@opengamevcs/object-model/javascript',
      packagedCli: {
        name: process.env.OGVCS_SCALE_PACKAGE_NAME,
        tarballSha256Hex: process.env.OGVCS_SCALE_PACKAGE_SHA256,
        version: process.env.OGVCS_SCALE_PACKAGE_VERSION
      },
      runtime: process.version,
      platform: `${process.platform}-${process.arch}`,
      exactV1Scale: options.treeCount === EXACT_TREE_COUNT && options.manifestCount === EXACT_MANIFEST_COUNT &&
        options.chunkBytes === EXACT_CHUNK_BYTES && !options.structuralOnly,
      recurrence: {
        tree: {
          seedHex: TREE_SEED.toString('hex'),
          basename: "ASCII 'e' plus six-digit zero-padded i",
          fileId: 'first16(SHA-256(seed || 0x46 || uint64be(i) || uint32be(attempt))), retry only zero'
        },
        manifest: {
          seedHex: MANIFEST_SEED.toString('hex'),
          blockHex: Buffer.from(block).toString('hex'),
          chunk: "repeat SHA-256(seed || 0x43 || ASCII 'repeated-chunk-v1') to exact chunkBytes",
          sequence: 'repeat the same content-addressed chunk reference chunkCount times'
        }
      },
      tree: {
        entries: options.treeCount,
        objectRef: ordered.value.objectRef.toString(),
        payloadSha256Hex: treePayloadSha256Hex,
        outputBytes: ordered.value.summary.metadataBytes,
        summary: ordered.value.summary,
        summarySha256: summaryDigest(ordered.value.summary),
        orderedWallTimeNanoseconds: ordered.wallTimeNanoseconds,
        orderedFileIdPeakScratchBytes: ordered.value.metrics.peakScratchBytes,
        orderedFileIdRuns: ordered.value.metrics.runCount,
        sortedWallTimeNanoseconds: sorted.wallTimeNanoseconds,
        sortedPeakScratchBytes: sorted.value.metrics.peakScratchBytes,
        sortedInitialRuns: sorted.value.metrics.runCount,
        byteForByteParity: true,
        fileIdUniqueness: {
          orderedDiskIndex: 'verified',
          sortedSideIndex: 'verified',
          cliDiskIndex: 'verified'
        },
        cliVerification: {
          highestLayer: cli.result.highestLayer,
          objectRef: cli.result.objectRef,
          peakScratchBytes: cli.result.peakScratchBytes,
          processMaxRssBytes: cli.result.processMaxRssBytes,
          status: cli.result.status
        }
      },
      manifest: {
        chunks: options.manifestCount,
        chunkBytes: options.chunkBytes,
        chunkObjectRef: chunkReference.toString(),
        rawChunkSha256Hex: createHash('sha256').update(chunk).digest('hex'),
        logicalBytes: String(BigInt(options.manifestCount) * BigInt(options.chunkBytes)),
        wholeFileDigestHex: Buffer.from(manifest.value.wholeFileDigest.bytes).toString('hex'),
        objectRef: manifest.value.objectRef.toString(),
        payloadSha256Hex: manifestPayloadSha256Hex,
        outputBytes: manifest.value.summary.metadataBytes,
        summary: manifest.value.summary,
        summarySha256: summaryDigest(manifest.value.summary),
        wallTimeNanoseconds: manifest.wallTimeNanoseconds,
        verification: manifest.value.verification,
        structuralOnly: options.structuralOnly
      },
      process: {
        maxRssBytes: usage.maxRSS * 1024,
        maxRssSource: 'node:process.resourceUsage().maxRSS (reported KiB)',
        userCpuTimeMicroseconds: usage.userCPUTime,
        systemCpuTimeMicroseconds: usage.systemCPUTime
      }
    };
  } finally {
    await rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  }
}

async function runParent(argv) {
  const script = fileURLToPath(import.meta.url);
  const packaged = await preparePackagedCli();
  try {
    const worker = await runChild(process.execPath, [script, '--worker', ...argv], {
      env: {
        ...process.env,
        OGVCS_SCALE_PACKAGED_CLI_PATH: packaged.executable,
        OGVCS_SCALE_PACKAGE_NAME: packaged.name,
        OGVCS_SCALE_PACKAGE_SHA256: packaged.tarballSha256Hex,
        OGVCS_SCALE_PACKAGE_VERSION: packaged.version
      }
    });
    const report = JSON.parse(worker.stdout);
    assert.match(report.tree?.payloadSha256Hex, /^[0-9a-f]{64}$/);
    assert.match(report.manifest?.payloadSha256Hex, /^[0-9a-f]{64}$/);
    assert.deepEqual(report.packagedCli, {
      name: packaged.name,
      tarballSha256Hex: packaged.tarballSha256Hex,
      version: packaged.version
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } finally {
    await rm(packaged.directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  }
}

const options = parseArguments(process.argv.slice(2));
if (options.worker) {
  const report = await runWorker(options);
  process.stdout.write(`${JSON.stringify(report)}\n`);
} else {
  await runParent(process.argv.slice(2));
}
