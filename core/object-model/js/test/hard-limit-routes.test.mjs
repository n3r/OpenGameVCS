import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  HARD_LIMIT_NAMES, OgvcsError, createObjectHashWriter, decodeCanonical, encodeCanonical,
  loadBundledRegistry, scanMetadata, validateKnownSchema, writeCanonical,
  writeOrderedLogicalBundle as writeOrderedLogicalBundleRaw
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const registry = await loadBundledRegistry();
const writeOrderedLogicalBundle = input => writeOrderedLogicalBundleRaw({
  registry, operation: 'conformance', ...input
});
const object = async name => decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects', name))));

function expected(code, layer) {
  return error => error instanceof OgvcsError && error.code === code && error.layer === layer;
}

function unreadArray(length = 1) {
  let touched = false;
  const value = [];
  value.length = length;
  Object.defineProperty(value, 0, {
    configurable: true,
    get() { touched = true; throw new Error('configured ceiling read an array element'); }
  });
  return { value, untouched: () => !touched };
}

test('every frozen hard limit is enforced by a reduced real caller route', async () => {
  const seen = new Set();
  const mark = name => { assert.equal(seen.has(name), false, name); seen.add(name); };

  const bundleCases = [
    ['bundle-objects', { objectCount: 1, logicalRecordCount: 0, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 1 } }, 0],
    ['bundle-logical-records', { objectCount: 0, logicalRecordCount: 1, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 1 } }, 0],
    ['bundle-roots', { objectCount: 0, logicalRecordCount: 0, rootCount: 1,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 0 } }, 0],
    ['bundle-total-items', { objectCount: 0, logicalRecordCount: 0, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 0 } }, 1],
    ['bundle-sequence-bytes', { objectCount: 0, logicalRecordCount: 0, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 0 } }, 99],
    ['bundle-largest-item-bytes', { objectCount: 0, logicalRecordCount: 0, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 0 } }, 99],
    ['bundle-traversal-edges', { objectCount: 0, logicalRecordCount: 0, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 1, indexEntries: 0 } }, 0],
    ['bundle-index-entries', { objectCount: 0, logicalRecordCount: 0, rootCount: 0,
      budget: { sequenceBytes: 100, largestItemBytes: 100, traversalEdges: 0, indexEntries: 1 } }, 0]
  ];
  for (const [name, plan, maximum] of bundleCases) {
    let iterated = false; let wrote = false;
    const poison = { [Symbol.asyncIterator]() { iterated = true; throw new Error('bundle iterable was opened'); } };
    await assert.rejects(writeOrderedLogicalBundle({
      plan, objects: poison, logicalRecords: poison, roots: poison,
      sink: () => { wrote = true; }, hardLimits: { [name]: maximum }
    }), expected('BUNDLE_BUDGET_EXCEEDED', 1), name);
    assert.equal(iterated, false, `${name} must reject before opening an iterable`);
    assert.equal(wrote, false, `${name} must reject before writing`);
    mark(name);
  }

  let wrote = false;
  await assert.rejects(writeCanonical([[0]], () => { wrote = true; }, { maxDepth: 1 }),
    expected('LIMIT_NESTING', 1));
  assert.equal(wrote, false);
  mark('cbor-nesting-depth');

  wrote = false;
  await assert.rejects(writeCanonical('ab', () => { wrote = true; }, { maxValueBytes: 1 }),
    expected('LIMIT_VALUE_BYTES', 1));
  assert.equal(wrote, false);
  mark('generic-text-or-byte-value-bytes');

  assert.throws(() => scanMetadata(Uint8Array.of(0, 0), {
    hardLimits: { 'metadata-payload-bytes': 1 }, computeId: false
  }), expected('LIMIT_METADATA_BYTES', 1));
  mark('metadata-payload-bytes');

  const chunkWriter = createObjectHashWriter(1, { maxChunkBytes: 1 });
  assert.throws(() => chunkWriter.update(Uint8Array.of(1, 2)), expected('LIMIT_CHUNK_BYTES', 1));
  mark('chunk-payload-bytes');

  const extensionBase = await object('02-content-manifest.cbor');
  extensionBase.set(3, new Map([['opaque.test/value@1', true]]));
  const extensionBytes = encodeCanonical(extensionBase);
  for (const [name, code] of [
    ['extensions-per-object', 'LIMIT_COUNT'],
    ['extension-aggregate-bytes-per-object', 'LIMIT_EXTENSION_BYTES']
  ]) {
    assert.throws(() => scanMetadata(extensionBytes, {
      hardLimits: { [name]: 0 }, computeId: false, semantic: false
    }), expected(code, 1), name);
    mark(name);
  }

  const manifest = await object('02-content-manifest.cbor');
  assert.throws(() => validateKnownSchema(manifest, 2, {
    semantic: false,
    hardLimits: { 'logical-file-bytes': Number(manifest.get(16)) - 1 }
  }), expected('LIMIT_LOGICAL_BYTES', 2));
  mark('logical-file-bytes');

  {
    const unread = unreadArray(); const value = new Map(manifest); value.set(19, unread.value);
    assert.throws(() => validateKnownSchema(value, 2, { semantic: false, hardLimits: { 'manifest-chunks': 0 } }),
      expected('LIMIT_COUNT', 2));
    assert.equal(unread.untouched(), true);
    mark('manifest-chunks');
  }

  const tree = await object('03-tree.cbor');
  {
    const unread = unreadArray(); const value = new Map(tree); value.set(17, unread.value);
    assert.throws(() => validateKnownSchema(value, 3, { semantic: false, hardLimits: { 'tree-entries': 0 } }),
      expected('LIMIT_COUNT', 2));
    assert.equal(unread.untouched(), true);
    mark('tree-entries');
  }
  assert.throws(() => validateKnownSchema(tree, 3, { semantic: false, hardLimits: { 'path-segment-bytes': 0 } }),
    expected('PATH_CORE_INVALID', 2));
  mark('path-segment-bytes');

  const changeSet = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'scenarios/objects/transition-create/candidate-change.cbor'
  ))));
  {
    const unread = unreadArray(); const value = new Map(changeSet); value.set(18, unread.value);
    assert.throws(() => validateKnownSchema(value, 4, { semantic: false, hardLimits: { 'change-set-operations': 0 } }),
      expected('LIMIT_COUNT', 2));
    assert.equal(unread.untouched(), true);
    mark('change-set-operations');
  }
  for (const name of ['path-segments', 'path-bytes']) {
    assert.throws(() => validateKnownSchema(changeSet, 4, { semantic: false, hardLimits: { [name]: 0 } }),
      expected('PATH_CORE_INVALID', 2), name);
    mark(name);
  }

  const groupSet = await object('05-asset-group-set.cbor');
  {
    const unread = unreadArray(); const value = new Map(groupSet); value.set(17, unread.value);
    assert.throws(() => validateKnownSchema(value, 5, { semantic: false, hardLimits: { 'asset-groups': 0 } }),
      expected('LIMIT_COUNT', 2));
    assert.equal(unread.untouched(), true);
    mark('asset-groups');
  }
  {
    const group = new Map(groupSet.get(17)[0]); const unread = unreadArray(); group.set(3, unread.value);
    const value = new Map(groupSet); value.set(17, [group]);
    assert.throws(() => validateKnownSchema(value, 5, { semantic: false, hardLimits: { 'asset-group-members': 0 } }),
      expected('LIMIT_COUNT', 2));
    assert.equal(unread.untouched(), true);
    mark('asset-group-members');
  }

  const snapshot = await object('07-snapshot.cbor');
  assert.throws(() => validateKnownSchema(snapshot, 7, { semantic: false, hardLimits: { 'snapshot-message-bytes': 0 } }),
    expected('LIMIT_VALUE_BYTES', 2));
  mark('snapshot-message-bytes');
  {
    const unread = unreadArray(); const value = new Map(snapshot); value.set(17, unread.value);
    assert.throws(() => validateKnownSchema(value, 7, { semantic: false, hardLimits: { 'snapshot-parents': 0 } }),
      expected('SNAPSHOT_PARENT_COUNT_INVALID', 2));
    assert.equal(unread.untouched(), true);
    mark('snapshot-parents');
  }

  assert.deepEqual([...seen].sort(), [...HARD_LIMIT_NAMES].sort());
  assert.equal(seen.size, 25);
});
