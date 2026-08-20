import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  MANIFEST_STREAM_LIMITS, TREE_STREAM_LIMITS, createDiskFileIdIndex, decodeMetadata, encodeMetadata, hashObject,
  loadBundledRegistry, verifyTreeFile as verifyTreeFileRaw, writeContentManifest as writeContentManifestRaw,
  writeOrderedTree as writeOrderedTreeRaw, writeSortedTree as writeSortedTreeRaw
} from '../src/index.js';
import { OgvcsError } from '../src/errors.js';

const TREE_SEED = Buffer.from('a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80', 'hex');
const DESCRIPTOR = new Map([[0, 1], [1, 6], [2, 1], [3, Buffer.from('dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545', 'hex')]]);
const MANIFEST = new Map([[0, 1], [1, 2], [2, 1], [3, Buffer.from('82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12', 'hex')]]);
const CONTENT_PROFILE = new Map([[0, 'content-policy.test'], [1, 'opaque'], [2, 1]]);
const CHUNK_PROFILE = new Map([[0, 'chunking.test'], [1, 'external-boundaries'], [2, 1]]);
const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const registry = await loadBundledRegistry();
const writeContentManifest = input => writeContentManifestRaw({
  registry, operation: 'conformance', ...input
});
const writeOrderedTree = input => writeOrderedTreeRaw({ registry, operation: 'conformance', ...input });
const writeSortedTree = input => writeSortedTreeRaw({ registry, operation: 'conformance', ...input });
const verifyTreeFile = (path, options = {}) => verifyTreeFileRaw(path, {
  registry, operation: 'conformance', ...options
});

function fileId(index) {
  const i = Buffer.alloc(8);
  i.writeBigUInt64BE(BigInt(index));
  const attempt = Buffer.alloc(4);
  return new Uint8Array(createHash('sha256').update(TREE_SEED).update(Uint8Array.of(0x46)).update(i).update(attempt).digest().subarray(0, 16));
}

function treeEntry(index, overrides = {}) {
  const value = new Map([[0, `e${String(index).padStart(6, '0')}`], [1, 2], [2, fileId(index)],
    [3, 2], [4, MANIFEST], [5, 24], [6, CONTENT_PROFILE]]);
  for (const [key, item] of Object.entries(overrides)) value.set(Number(key), item);
  return value;
}

function* orderedEntries(count) { for (let index = 0; index < count; index += 1) yield treeEntry(index); }
function* reverseEntries(count) { for (let index = count - 1; index >= 0; index -= 1) yield treeEntry(index); }

function collector() {
  const chunks = [];
  return { sink(chunk) { chunks.push(chunk.slice()); }, bytes() { return Buffer.concat(chunks); } };
}

function code(expected, layer) {
  return error => error instanceof OgvcsError && error.code === expected &&
    (layer === undefined || error.layer === layer);
}

async function scratch(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-tree-test-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  return directory;
}

test('scale implementation constants reproduce the normative repeated-chunk plan', async () => {
  const tree = JSON.parse(await readFile(join(VECTORS, 'scenarios/definitions/tree-million-entries.json'), 'utf8'));
  const manifest = JSON.parse(await readFile(join(VECTORS, 'scenarios/definitions/manifest-one-tib.json'), 'utf8'));
  const treeCase = JSON.parse(await readFile(join(VECTORS, 'scenarios/cases/tree-million-entries.json'), 'utf8'));
  const manifestCase = JSON.parse(await readFile(join(VECTORS, 'scenarios/cases/manifest-one-tib.json'), 'utf8'));
  const treePlan = tree.exactConstructorValues.scalePlan;
  const manifestPlan = manifest.exactConstructorValues.scalePlan;
  assert.equal(treePlan.recurrence.seed, TREE_SEED.toString('hex'));
  assert.equal(treePlan.streamCardinality, '1000000');
  assert.deepEqual(treeCase.requirementIds, ['OGVCS-002-AC-02', 'OGVCS-002-FR-09', 'OGVCS-002-NFR-02']);
  assert.deepEqual(manifestCase.requirementIds, ['OGVCS-002-AC-09', 'OGVCS-002-FR-09', 'OGVCS-002-NFR-02']);
  assert.equal(manifestPlan.fixedFields.chunkCount, '1048576');
  assert.equal(manifestPlan.fixedFields.chunkBytes, '1048576');
  assert.equal(manifestPlan.fixedFields.logicalBytes, '1099511627776');

  const seed = Buffer.from(manifest.seedHex, 'hex');
  const block = createHash('sha256').update(seed).update(Uint8Array.of(0x43))
    .update(Buffer.from('repeated-chunk-v1', 'ascii')).digest();
  assert.equal(block.toString('hex'), manifestPlan.fixedFields.repeatedBlockSha256);
  const chunk = Buffer.alloc(1_048_576);
  for (let offset = 0; offset < chunk.length; offset += block.length) block.copy(chunk, offset);
  assert.equal(createHash('sha256').update(chunk).digest('hex'), manifestPlan.fixedFields.rawChunkSha256);
  assert.equal(hashObject(1, chunk).toString(), manifestPlan.fixedFields.chunkObjectRef);
});

test('ordered and bounded external-sort tree writers emit identical canonical bytes and summaries', async t => {
  const directory = await scratch(t);
  const ordered = collector();
  const sorted = collector();
  const left = await writeOrderedTree({
    descriptor: DESCRIPTOR, entryCount: 2_000, entries: orderedEntries(2_000), sink: ordered.sink
  });
  const right = await writeSortedTree({
    descriptor: DESCRIPTOR,
    entryCount: 2_000,
    entries: reverseEntries(2_000),
    sink: sorted.sink,
    scratchDirectory: directory,
    maxMemoryBytes: 16_384,
    maxRunBytes: 8_192,
    maxOpenRuns: 4,
    maxScratchBytes: 2_000_000
  });
  assert.ok(ordered.bytes().equals(sorted.bytes()));
  assert.equal(left.objectRef.toString(), right.objectRef.toString());
  assert.deepEqual(left.summary, right.summary);
  assert.equal(right.metrics.runCount > 4, true);
  assert.equal(right.metrics.peakScratchBytes > 0, true);
  assert.deepEqual(await readdir(directory), []);
  const decoded = decodeMetadata(new Uint8Array(ordered.bytes()), { semantic: false });
  assert.equal(decoded.kind, 3);
  assert.equal(decoded.value.get(17).length, 2_000);
  assert.equal(hashObject(3, new Uint8Array(ordered.bytes())).toString(), left.objectRef.toString());
});

test('ordered tree writer rejects counts, ordering, duplicates, resource ceilings, and incomplete writers', async () => {
  const discard = () => {};
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: TREE_STREAM_LIMITS.maxEntries + 1,
    entries: [], sink: discard }), code('LIMIT_COUNT', 1));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 2,
    entries: [treeEntry(1), treeEntry(0)], sink: discard }), code('TREE_ENTRY_ORDER_INVALID'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 2,
    entries: [treeEntry(0), treeEntry(0)], sink: discard }), code('TREE_ENTRY_ORDER_INVALID'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1,
    entries: [treeEntry(0), treeEntry(1)], sink: discard }), code('SCHEMA_FIELD_INVALID'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1, maxItems: 1,
    entries: [treeEntry(0), treeEntry(1)], sink: discard }), code('LIMIT_COUNT', 1));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 2,
    entries: [treeEntry(0), treeEntry(1, { 2: fileId(0) })], sink: discard }), code('FILEID_DUPLICATE_IN_TREE'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 100_001,
    entries: [], sink: discard }), code('LIMIT_MEMORY'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1,
    entries: [treeEntry(0)], sink: discard, maxMemoryBytes: 1 }), code('LIMIT_MEMORY'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1,
    entries: [treeEntry(0)], sink: discard, maxBytes: 1 }), code('LIMIT_METADATA_BYTES'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 0,
    entries: [], sink: discard, maxTimeMs: 0 }), code('LIMIT_TIME'));
  await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1,
    entries: [treeEntry(0)], sink: { write() { return { bytesWritten: 0 }; } } }), code('SCHEMA_FIELD_INVALID'));

  const output = [];
  const shortWriter = { write(chunk) {
    const length = Math.min(3, chunk.length);
    output.push(chunk.slice(0, length));
    return { bytesWritten: length };
  } };
  const result = await writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1,
    entries: [treeEntry(0)], sink: shortWriter });
  assert.equal(Buffer.concat(output).length, result.summary.metadataBytes);
});

test('tree and manifest prefix encoders honor configured CBOR working memory before sink output', async () => {
  const extensions = new Map([['extension.test/deep@1', new Map([[0, new Map([[0, true], [1, false]])]])]]);
  let treeWrites = 0;
  await assert.rejects(writeOrderedTree({
    descriptor: DESCRIPTOR,
    entryCount: 0,
    entries: [],
    extensions,
    sink: () => { treeWrites++; },
    maxMemoryBytes: 220
  }), code('LIMIT_MEMORY', 1));
  assert.equal(treeWrites, 0);

  const emptyDigest = new Map([[0, 1], [1, new Uint8Array(createHash('sha256').digest())]]);
  let manifestWrites = 0;
  await assert.rejects(writeContentManifest({
    logicalLength: 0,
    wholeFileDigest: emptyDigest,
    chunkProfile: CHUNK_PROFILE,
    partCount: 0,
    parts: [],
    extensions,
    sink: () => { manifestWrites++; },
    maxMemoryBytes: 220
  }), code('LIMIT_MEMORY', 1));
  assert.equal(manifestWrites, 0);
});

test('tree entry validation covers exact shape, path, identity, target, mode, profile, and size', async () => {
  const discard = () => {};
  const missing = treeEntry(0); missing.delete(6);
  const cases = [
    [missing, 'SCHEMA_FIELD_INVALID'],
    [treeEntry(0, { 0: 'e\u0301' }), 'PATH_CORE_INVALID'],
    [treeEntry(0, { 0: '.' }), 'PATH_CORE_INVALID'],
    [treeEntry(0, { 2: new Uint8Array(16) }), 'FILEID_ZERO'],
    [treeEntry(0, { 1: 2, 3: 3 }), 'TREE_ENTRY_TARGET_INVALID'],
    [treeEntry(0, { 4: DESCRIPTOR }), 'OBJECT_REFERENCE_KIND_MISMATCH'],
    [treeEntry(0, { 6: new Map([[0, 'bad'], [1, 'opaque'], [2, 1]]) }), 'SCHEMA_FIELD_INVALID'],
    [treeEntry(0, { 1: 1, 3: 1, 4: new Map([[0, 1], [1, 3], [2, 1], [3, new Uint8Array(32).fill(3)]]), 5: 1 }), 'TREE_ENTRY_TARGET_INVALID'],
    [treeEntry(0, { 5: TREE_STREAM_LIMITS.maxLogicalBytes + 1n }), 'LIMIT_LOGICAL_BYTES']
  ];
  for (const [entry, expected] of cases) {
    await assert.rejects(writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 1, entries: [entry], sink: discard }), code(expected));
  }
});

test('raw tree file verifier hashes and validates incrementally without decoding the entry array', async t => {
  const directory = await scratch(t);
  const output = collector();
  const written = await writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 500,
    entries: orderedEntries(500), sink: output.sink });
  const path = join(directory, 'tree.cbor');
  await writeFile(path, output.bytes(), { flag: 'wx', mode: 0o600 });
  const index = await createDiskFileIdIndex({ scratchDirectory: directory, maxMemoryBytes: 512,
    maxRunBytes: 256, maxOpenRuns: 4, maxScratchBytes: 100_000 });
  const verified = await verifyTreeFile(path, { descriptor: DESCRIPTOR, fileIdIndex: index,
    maxMemoryBytes: 65_536, readChunkBytes: 1_024 });
  assert.equal(verified.objectRef.toString(), written.objectRef.toString());
  assert.deepEqual(verified.summary, written.summary);
  assert.equal(verified.highestLayer, 3);
  await assert.rejects(verifyTreeFile(path, { descriptor: DESCRIPTOR, maxBytes: 1 }), code('LIMIT_METADATA_BYTES'));
  const other = new Map(DESCRIPTOR); other.set(3, new Uint8Array(32).fill(7));
  await assert.rejects(verifyTreeFile(path, { descriptor: other }), code('REPOSITORY_DESCRIPTOR_MISMATCH'));
});

test('raw tree verifier composes reader and FileID-index memory and reuses an aborted disk index', async t => {
  const directory = await scratch(t);
  const fullOutput = collector();
  await writeOrderedTree({
    descriptor: DESCRIPTOR, entryCount: 3, entries: orderedEntries(3), sink: fullOutput.sink
  });
  const recoveryOutput = collector();
  await writeOrderedTree({
    descriptor: DESCRIPTOR, entryCount: 1, entries: orderedEntries(1), sink: recoveryOutput.sink
  });
  const fullPath = join(directory, 'full-tree.cbor');
  const recoveryPath = join(directory, 'recovery-tree.cbor');
  await writeFile(fullPath, fullOutput.bytes(), { flag: 'wx', mode: 0o600 });
  await writeFile(recoveryPath, recoveryOutput.bytes(), { flag: 'wx', mode: 0o600 });
  const index = await createDiskFileIdIndex({
    scratchDirectory: directory, maxMemoryBytes: 512, maxRunBytes: 256,
    maxOpenRuns: 4, maxScratchBytes: 10_000
  });
  const options = {
    descriptor: DESCRIPTOR, fileIdIndex: index, maxMemoryBytes: 16_576, readChunkBytes: 128
  };
  await assert.rejects(verifyTreeFile(fullPath, options), code('LIMIT_MEMORY', 1));
  const recovered = await verifyTreeFile(recoveryPath, options);
  assert.equal(recovered.summary.entryCount, 1);
  assert.deepEqual((await readdir(directory)).filter(name => name.endsWith('.run')), []);
});

test('raw tree decoder charges cumulative nested value retention', async t => {
  const directory = await scratch(t);
  const seed = decodeMetadata(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/03-tree.cbor'
  ))), { semantic: false }).value;
  seed.set(3, new Map([[
    'extension-state.test/opaque@1',
    Array.from({ length: 32 }, () => new Uint8Array(128))
  ]]));
  const payload = encodeMetadata(seed, { registry, operation: 'conformance' });
  const path = join(directory, 'nested-memory.cbor');
  await writeFile(path, payload, { flag: 'wx', mode: 0o600 });
  await assert.rejects(verifyTreeFile(path, {
    descriptor: seed.get(16), maxMemoryBytes: 2_048, readChunkBytes: 128
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_MEMORY' &&
    error.stage === 'configured-resource-preflight');
});

test('external sorter enforces scratch bounds and removes all exclusive runs after failures', async t => {
  const directory = await scratch(t);
  await assert.rejects(writeSortedTree({
    descriptor: DESCRIPTOR,
    entryCount: 1,
    maxItems: 1,
    entries: [treeEntry(1), treeEntry(0)],
    sink: () => {},
    scratchDirectory: directory
  }), code('LIMIT_COUNT', 1));
  assert.deepEqual(await readdir(directory), []);
  await assert.rejects(writeSortedTree({
    descriptor: DESCRIPTOR,
    entryCount: 50,
    entries: reverseEntries(50),
    sink: () => {},
    scratchDirectory: directory,
    maxMemoryBytes: 2_048,
    maxRunBytes: 1_024,
    maxScratchBytes: 100
  }), code('LIMIT_SCRATCH'));
  assert.deepEqual(await readdir(directory), []);

  await assert.rejects(writeSortedTree({
    descriptor: DESCRIPTOR,
    entryCount: 2,
    entries: [treeEntry(1, { 2: fileId(0) }), treeEntry(0)],
    sink: () => {},
    scratchDirectory: directory,
    maxMemoryBytes: 2_048,
    maxRunBytes: 512,
    maxScratchBytes: 10_000
  }), code('FILEID_DUPLICATE_IN_TREE'));
  assert.deepEqual(await readdir(directory), []);

  const index = await createDiskFileIdIndex({ scratchDirectory: directory, maxMemoryBytes: 256,
    maxRunBytes: 128, maxOpenRuns: 2, maxScratchBytes: 10_000 });
  const output = collector();
  const indexed = await writeOrderedTree({ descriptor: DESCRIPTOR, entryCount: 20, entries: orderedEntries(20),
    sink: output.sink, fileIdIndex: index });
  assert.equal(indexed.summary.entryCount, 20);
  assert.equal(indexed.metrics.runCount > 1, true);
  assert.deepEqual(await readdir(directory), []);

  const real = join(directory, 'real');
  const link = join(directory, 'link');
  await mkdir(real);
  try {
    await symlink(real, link, process.platform === 'win32' ? 'junction' : 'dir');
    await assert.rejects(writeSortedTree({ descriptor: DESCRIPTOR, entryCount: 0, entries: [], sink: () => {},
      scratchDirectory: link }), code('SCHEMA_FIELD_INVALID'));
  } catch (error) {
    if (process.platform !== 'win32' || !['EPERM', 'EACCES'].includes(error?.code) ||
        process.env.OGVCS_REQUIRE_WINDOWS_JUNCTION === '1') throw error;
  }
});

test('external sorter rejects a closed scratch run replaced before reopening', async t => {
  const directory = await scratch(t);
  let replaced = false;
  async function* replacingEntries() {
    for (let index = 49; index >= 0; index -= 1) {
      yield treeEntry(index);
      if (replaced) continue;
      const runs = (await readdir(directory)).filter(name => name.endsWith('.run'));
      if (runs.length === 0) continue;
      const path = join(directory, runs[0]);
      const bytes = await readFile(path);
      if (bytes.length === 0) continue;
      bytes[bytes.length - 1] ^= 1;
      const replacement = `${path}.replacement`;
      await writeFile(replacement, bytes, { flag: 'wx', mode: 0o600 });
      await unlink(path);
      await rename(replacement, path);
      replaced = true;
    }
  }

  await assert.rejects(writeSortedTree({
    descriptor: DESCRIPTOR,
    entryCount: 50,
    entries: replacingEntries(),
    sink: () => {},
    scratchDirectory: directory,
    maxMemoryBytes: 2_048,
    maxRunBytes: 1_024,
    maxOpenRuns: 4,
    maxScratchBytes: 100_000
  }), code('LIMIT_SCRATCH', 1));
  assert.equal(replaced, true);
  assert.deepEqual(await readdir(directory), []);
});

function manifestFixture(repetitions = 2) {
  const chunk = new Uint8Array(Buffer.from('canonical repeated chunk'));
  const reference = hashObject(1, chunk);
  const part = new Map([[0, reference.toMap()], [1, chunk.length]]);
  const whole = createHash('sha256');
  for (let index = 0; index < repetitions; index += 1) whole.update(chunk);
  return {
    chunk, reference, part,
    logicalLength: BigInt(chunk.length * repetitions),
    digest: new Map([[0, 1], [1, new Uint8Array(whole.digest())]])
  };
}

test('streaming manifest writer verifies repeated chunks and matches the generic canonical codec', async () => {
  const fixture = manifestFixture(3);
  const output = collector();
  const result = await writeContentManifest({
    logicalLength: fixture.logicalLength,
    wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE,
    partCount: 3,
    parts: [fixture.part, fixture.part, fixture.part],
    chunkProvider: () => fixture.chunk,
    sink: output.sink
  });
  const expected = encodeMetadata(new Map([[0, 1], [1, 2], [2, []], [16, fixture.logicalLength],
    [17, fixture.digest], [18, CHUNK_PROFILE], [19, [fixture.part, fixture.part, fixture.part]]]), {
    registry,
    operation: 'conformance'
  });
  assert.ok(output.bytes().equals(expected));
  assert.equal(result.objectRef.toString(), hashObject(2, expected).toString());
  assert.deepEqual(result.verification, {
    contentVerified: true,
    contentBytesRead: String(fixture.chunk.length * 3),
    providerReads: 1,
    cachedChunks: 1,
    cachedBytes: fixture.chunk.length
  });
});

test('derived-digest manifest mode hashes content once and verifies repeatable metadata replay', async () => {
  const fixture = manifestFixture(4);
  let factories = 0;
  let providers = 0;
  const output = collector();
  const result = await writeContentManifest({
    logicalLength: fixture.logicalLength,
    chunkProfile: CHUNK_PROFILE,
    partCount: 4,
    parts(pass) { factories += 1; assert.ok(pass >= 1 && pass <= 4); return Array(4).fill(fixture.part); },
    chunkProvider() { providers += 1; return fixture.chunk; },
    sink: output.sink
  });
  assert.equal(factories, 4);
  assert.equal(providers, 1);
  assert.ok(result.wholeFileDigest.bytes.every((byte, index) => byte === fixture.digest.get(1)[index]));
  assert.equal(result.verification.contentBytesRead, String(fixture.logicalLength));

  let pass = 0;
  await assert.rejects(writeContentManifest({
    logicalLength: fixture.logicalLength,
    chunkProfile: CHUNK_PROFILE,
    partCount: 4,
    parts() { pass += 1; return pass === 1 ? Array(4).fill(fixture.part) : [fixture.part, fixture.part, fixture.part,
      new Map([[0, fixture.reference.toMap()], [1, fixture.chunk.length - 1]])]; },
    chunkProvider: () => fixture.chunk,
    sink: () => {}
  }), code('MANIFEST_LENGTH_MISMATCH'));

  const alternateChunk = fixture.chunk.slice();
  alternateChunk[0] ^= 1;
  const alternate = new Map([[0, hashObject(1, alternateChunk).toMap()], [1, alternateChunk.length]]);
  pass = 0;
  await assert.rejects(writeContentManifest({
    logicalLength: fixture.logicalLength,
    chunkProfile: CHUNK_PROFILE,
    partCount: 4,
    parts() { pass += 1; return pass === 1 ? Array(4).fill(fixture.part) :
      [fixture.part, fixture.part, fixture.part, alternate]; },
    chunkProvider: () => fixture.chunk,
    sink: () => {}
  }), code('SCHEMA_FIELD_INVALID'));
});

test('manifest writer fails closed on malformed parts, limits, provider bytes, and whole digest', async () => {
  const fixture = manifestFixture(2);
  const discard = () => {};
  const missing = new Map(fixture.part); missing.delete(1);
  const zero = new Map(fixture.part); zero.set(1, 0);
  const wrongKind = new Map(fixture.part); wrongKind.set(0, DESCRIPTOR);
  for (const [part, expected] of [[missing, 'SCHEMA_FIELD_INVALID'], [zero, 'MANIFEST_CHUNK_LENGTH_INVALID'],
    [wrongKind, 'OBJECT_REFERENCE_KIND_MISMATCH']]) {
    await assert.rejects(writeContentManifest({ logicalLength: fixture.chunk.length, wholeFileDigest: fixture.digest,
      chunkProfile: CHUNK_PROFILE, partCount: 1, parts: [part], sink: discard }), code(expected));
  }
  await assert.rejects(writeContentManifest({ logicalLength: 0, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: MANIFEST_STREAM_LIMITS.maxParts + 1, parts: [], sink: discard }), code('LIMIT_COUNT', 1));
  await assert.rejects(writeContentManifest({ logicalLength: fixture.logicalLength + 1n, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: 2, parts: [fixture.part, fixture.part], sink: discard }), code('MANIFEST_LENGTH_MISMATCH'));
  await assert.rejects(writeContentManifest({ logicalLength: fixture.chunk.length, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: 1, maxItems: 1,
    parts: [fixture.part, fixture.part], sink: discard }), code('LIMIT_COUNT', 1));
  await assert.rejects(writeContentManifest({ logicalLength: fixture.logicalLength, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: 2, parts: [fixture.part, fixture.part],
    chunkProvider: () => fixture.chunk.subarray(1), sink: discard }), code('MANIFEST_CHUNK_LENGTH_INVALID'));
  await assert.rejects(writeContentManifest({ logicalLength: fixture.logicalLength, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: 2, parts: [fixture.part, fixture.part],
    chunkProvider: () => new Uint8Array(fixture.chunk.length).fill(7), sink: discard }), code('OBJECT_ID_MISMATCH'));
  const wrongDigest = new Map([[0, 1], [1, new Uint8Array(32).fill(9)]]);
  await assert.rejects(writeContentManifest({ logicalLength: fixture.logicalLength, wholeFileDigest: wrongDigest,
    chunkProfile: CHUNK_PROFILE, partCount: 2, parts: [fixture.part, fixture.part],
    chunkProvider: () => fixture.chunk, sink: discard }), code('MANIFEST_FILE_DIGEST_MISMATCH'));
  await assert.rejects(writeContentManifest({ logicalLength: fixture.chunk.length, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: 1, parts: [fixture.part], sink: discard, maxMemoryBytes: 1 }), code('LIMIT_MEMORY'));
  await assert.rejects(writeContentManifest({ logicalLength: fixture.chunk.length, wholeFileDigest: fixture.digest,
    chunkProfile: CHUNK_PROFILE, partCount: 1, parts: [fixture.part], sink: discard, maxBytes: 1 }), code('LIMIT_METADATA_BYTES'));
  await assert.rejects(writeContentManifest({ logicalLength: 0, wholeFileDigest: new Map([[0, 1],
    [1, new Uint8Array(createHash('sha256').digest())]]), chunkProfile: CHUNK_PROFILE, partCount: 0,
    parts: [], sink: discard, maxTimeMs: 0 }), code('LIMIT_TIME'));
});

test('manifest content failures are selected across every independent provider occurrence', async () => {
  const expectedOne = new Uint8Array(Buffer.from('provider-one'));
  const expectedTwo = new Uint8Array(Buffer.from('provider-two'));
  const short = expectedOne.subarray(0, expectedOne.length - 1);
  const wrong = expectedTwo.slice(); wrong[0] ^= 1;
  const pair = [
    { part: new Map([[0, hashObject(1, expectedOne).toMap()], [1, 12]]), bytes: short },
    { part: new Map([[0, hashObject(1, expectedTwo).toMap()], [1, 12]]), bytes: wrong }
  ];
  const digest = new Map([[0, 1], [1, new Uint8Array(createHash('sha256')
    .update(expectedOne).update(expectedTwo).digest())]]);
  for (const ordered of [pair, [...pair].reverse()]) {
    await assert.rejects(writeContentManifest({
      logicalLength: 24n,
      wholeFileDigest: digest,
      chunkProfile: CHUNK_PROFILE,
      partCount: 2,
      parts: ordered.map(item => item.part),
      chunkProvider: (_reference, { index }) => ordered[index].bytes,
      sink: () => {}
    }), code('OBJECT_ID_MISMATCH', 1));
  }
});

test('empty manifest whole-file SHA-256 is checked without a provider', async () => {
  const emptyDigest = new Uint8Array(createHash('sha256').digest());
  const valid = await writeContentManifest({ logicalLength: 0, wholeFileDigest: new Map([[0, 1], [1, emptyDigest]]),
    chunkProfile: CHUNK_PROFILE, partCount: 0, parts: [], sink: () => {} });
  assert.equal(valid.verification.contentVerified, true);
  await assert.rejects(writeContentManifest({ logicalLength: 0, wholeFileDigest: new Map([[0, 1], [1, new Uint8Array(32)]]),
    chunkProfile: CHUNK_PROFILE, partCount: 0, parts: [], sink: () => {} }), code('MANIFEST_FILE_DIGEST_MISMATCH'));
});
