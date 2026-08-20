import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  OgvcsError, Sha256Writer, createBundleTranscriptHashWriter, createLogicalRecordHashWriter,
  createObjectHashWriter, createOpaqueObjectHashWriter, encodeCanonical, encodeCanonicalChunks,
  decodeCanonical, hashBundleTranscript, hashLogicalRecord, hashObject, sha256Digest, toHex, visitLogicalBundle,
  writeCanonical
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const expectCode = async (operation, code) => assert.rejects(operation, error => error instanceof OgvcsError && error.code === code);

async function* chunks(bytes, sizes = [1, 2, 7, 31, 64, 257]) {
  let offset = 0;
  let index = 0;
  while (offset < bytes.length) {
    const end = Math.min(bytes.length, offset + sizes[index++ % sizes.length]);
    yield bytes.subarray(offset, end);
    offset = end;
  }
}

test('streaming canonical encoder matches the collector and bounds writes', async () => {
  const value = new Map([
    [24, new Uint8Array(200_000).map((_, index) => index % 251)],
    [1, [true, 'streaming', new Map([[0, -12], [1, 1n << 54n]])]]
  ]);
  const expected = encodeCanonical(value);
  const emitted = [...encodeCanonicalChunks(value, { chunkBytes: 997 })];
  assert.ok(emitted.length > 100);
  assert.ok(emitted.every(part => part.length <= 997 || part.length < 16));
  assert.deepEqual(Buffer.concat(emitted), Buffer.from(expected));

  const sink = [];
  assert.equal(await writeCanonical(value, async part => sink.push(part.slice()), { chunkBytes: 4093 }), expected.length);
  assert.deepEqual(Buffer.concat(sink), Buffer.from(expected));
  class BackpressuredSink extends EventEmitter {
    parts = [];
    write(part) {
      this.parts.push(part.slice());
      setImmediate(() => this.emit('drain'));
      return false;
    }
  }
  const backpressured = new BackpressuredSink();
  await writeCanonical(value, backpressured, { chunkBytes: 32_767 });
  assert.deepEqual(Buffer.concat(backpressured.parts), Buffer.from(expected));
  assert.throws(() => [...encodeCanonicalChunks(value, { maxBytes: expected.length - 1 })],
    error => error instanceof OgvcsError && error.code === 'LIMIT_METADATA_BYTES');
  // Configurations can lower but never raise the format hard limit.
  assert.throws(() => [...encodeCanonicalChunks(new Uint8Array(17), { maxValueBytes: 16, maxBytes: 1_000_000_000 })],
    error => error instanceof OgvcsError && error.code === 'LIMIT_VALUE_BYTES');
});

test('streaming canonical encoder preflights duplicate keys, size, and key memory', async () => {
  const duplicate = [1, new Map([
    [new Uint8Array([1, 2]), true],
    [new Uint8Array([1, 2]), false]
  ])];
  const emitted = [];
  await expectCode(() => writeCanonical(duplicate, chunk => emitted.push(chunk)), 'CBOR_NON_CANONICAL');
  assert.deepEqual(emitted, []);

  const oversized = [new Uint8Array(32)];
  await expectCode(() => writeCanonical(oversized, chunk => emitted.push(chunk), { maxBytes: 8 }),
    'LIMIT_METADATA_BYTES');
  assert.deepEqual(emitted, []);

  const keyHeavy = new Map([
    [new Uint8Array(8).fill(1), true],
    [new Uint8Array(8).fill(2), false]
  ]);
  await expectCode(() => writeCanonical(keyHeavy, chunk => emitted.push(chunk), { maxWorkingBytes: 128 }),
    'LIMIT_MEMORY');
  assert.deepEqual(emitted, []);

  const nestedKeys = new Map([[0, new Map([[0, true], [1, false]])]]);
  await expectCode(() => writeCanonical(nestedKeys, chunk => emitted.push(chunk), { maxWorkingBytes: 150 }),
    'LIMIT_MEMORY');
  assert.deepEqual(emitted, []);

  const retained = encodeCanonical(new Array(20).fill(1));
  assert.throws(
    () => decodeCanonical(retained, { maxWorkingBytes: 1 }),
    error => error instanceof OgvcsError && error.code === 'LIMIT_MEMORY' && error.layer === 1
  );
});

test('streaming canonical encoder rejects caller mutation before reporting success', async () => {
  const value = [1];
  const emitted = [];
  let writes = 0;
  await expectCode(() => writeCanonical(value, async chunk => {
    emitted.push(chunk.slice());
    if (writes++ === 0) value.push(2);
  }, { chunkBytes: 1 }), 'SCHEMA_FIELD_INVALID');
  assert.throws(() => decodeCanonical(Buffer.concat(emitted)),
    error => error instanceof OgvcsError && error.code === 'CBOR_TRAILING_BYTES');

  const direct = [1];
  const iterator = encodeCanonicalChunks(direct, { chunkBytes: 1 });
  assert.deepEqual(iterator.next().value, Uint8Array.of(0x81));
  direct.push(2);
  assert.throws(() => [...iterator],
    error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID');
});

test('incremental digest and transcript writers are chunk-boundary invariant', async () => {
  const payload = new Uint8Array(262_177).map((_, index) => (index * 17) % 251);
  for (const size of [1, 3, 63, 64, 65, 4093]) {
    const sha = new Sha256Writer();
    for (let offset = 0; offset < payload.length; offset += size) sha.update(payload.subarray(offset, offset + size));
    assert.equal(toHex(sha.finish().bytes), toHex(sha256Digest(payload).bytes));
  }

  const items = [payload.subarray(0, 17), payload.subarray(17, 65_539), payload.subarray(65_539)];
  const bundle = createBundleTranscriptHashWriter();
  for await (const part of chunks(Buffer.concat(items))) bundle.update(part);
  assert.equal(toHex(bundle.finish().bytes), toHex(hashBundleTranscript(items).bytes));

  assert.throws(
    () => createBundleTranscriptHashWriter({ maxBytes: 1 }).update(Uint8Array.of(1, 2)),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_BUDGET_EXCEEDED' &&
      error.layer === 1 && error.stage === 'configured-resource-preflight'
  );
});

test('registered identity writers enforce assignments and payload discriminator', async () => {
  const tree = await readFile(resolve(VECTORS, 'objects/03-tree.cbor'));
  assert.deepEqual(Buffer.concat([...encodeCanonicalChunks(decodeCanonical(tree), { chunkBytes: 11 })]), tree);
  const expected = hashObject(3, tree);
  const writer = createObjectHashWriter(3);
  for await (const part of chunks(tree)) writer.update(part);
  assert.equal(toHex(writer.finish().digest), toHex(expected.digest));

  assert.throws(() => createObjectHashWriter(65_535), error => error instanceof OgvcsError && error.code === 'OBJECT_KIND_UNSUPPORTED');
  const opaque = createOpaqueObjectHashWriter(65_535);
  opaque.update(tree);
  assert.equal(opaque.finish().bytes.length, 32);

  const wrongObject = createObjectHashWriter(2);
  wrongObject.update(tree);
  assert.throws(() => wrongObject.finish(), error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID');

  const logical = await readFile(resolve(VECTORS, 'logical-records/02-mutable-ref.cbor'));
  const logicalWriter = createLogicalRecordHashWriter(2);
  for await (const part of chunks(logical)) logicalWriter.update(part);
  assert.equal(toHex(logicalWriter.finish().bytes), toHex(hashLogicalRecord(2, logical).bytes));
  assert.throws(() => createLogicalRecordHashWriter(42), error => error instanceof OgvcsError && error.code === 'LOGICAL_RECORD_TYPE_UNSUPPORTED');
  const wrongLogical = createLogicalRecordHashWriter(1);
  wrongLogical.update(logical);
  assert.throws(() => wrongLogical.finish(), error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID');
});

function objectItem(kind, payload) {
  return encodeCanonical(new Map([
    [0, 1], [1, 2], [2, 0],
    [3, new Map([[0, 1], [1, kind], [2, 1], [3, new Uint8Array(32)]])],
    [4, payload]
  ]), { maxValueBytes: 536_870_912 });
}

function declaredObjectItem(kind, length) {
  const ref = encodeCanonical(new Map([[0, 1], [1, kind], [2, 1], [3, new Uint8Array(32)]]));
  const prefix = Uint8Array.of(0xa5, 0x00, 0x01, 0x01, 0x02, 0x02, 0x00, 0x03);
  const header = Uint8Array.of(0x04, 0x5a, length >>> 24, length >>> 16 & 255, length >>> 8 & 255, length & 255);
  return Buffer.concat([prefix, ref, header]);
}

test('logical-bundle visitor is non-retaining and applies contextual payload ceilings', async () => {
  const payload = new Uint8Array(170_000).map((_, index) => index % 251);
  const encoded = objectItem(1, payload);
  let visited = 0;
  let largest = 0;
  const result = await visitLogicalBundle(chunks(encoded), {
    onObjectPayloadChunk(part) { visited += part.length; largest = Math.max(largest, part.length); }
  }, { payloadChunkBytes: 4096 });
  assert.deepEqual(result, { items: 1, bytes: encoded.length });
  assert.equal(visited, payload.length);
  assert.ok(largest <= 4096);

  const overChunk = declaredObjectItem(1, 67_108_865);
  await expectCode(() => visitLogicalBundle(chunks(overChunk)), 'LIMIT_CHUNK_BYTES');
  // The same declared size is within the metadata exception, so the scanner
  // advances to the body and reports truncation instead of the chunk ceiling.
  const metadata = declaredObjectItem(2, 67_108_865);
  await expectCode(() => visitLogicalBundle(chunks(metadata)), 'CBOR_TRUNCATED');
  await expectCode(() => visitLogicalBundle(chunks(metadata), {}, { maxMetadataBytes: 1024 }), 'LIMIT_METADATA_BYTES');

  const zeroSections = await readFile(resolve(VECTORS, 'logical-bundles/scenario-bundle-zero-sections.cborseq'));
  for (const limits of [{ maxItemBytes: 1 }, { maxItems: 1 }]) {
    await assert.rejects(
      () => visitLogicalBundle(chunks(zeroSections), {}, limits),
      error => error instanceof OgvcsError && error.code === 'BUNDLE_BUDGET_EXCEEDED' &&
        error.layer === 1 && error.stage === 'configured-resource-preflight'
    );
  }
});

test('logical-bundle visitor bounds cumulative nested map-key captures', async () => {
  const nested = await readFile(resolve(
    VECTORS, 'logical-bundles/nested-map-key-capture-memory.cborseq'
  ));
  const limits = { maxValueBytes: 64, maxNesting: 10 };
  await assert.rejects(
    () => visitLogicalBundle(chunks(nested), {}, { ...limits, maxCaptureBytes: 511 }),
    error => error instanceof OgvcsError && error.code === 'LIMIT_MEMORY' &&
      error.layer === 1 && error.stage === 'configured-resource-preflight'
  );
  assert.deepEqual(
    await visitLogicalBundle(chunks(nested), {}, { ...limits, maxCaptureBytes: 512 }),
    { items: 4, bytes: nested.length }
  );
});
