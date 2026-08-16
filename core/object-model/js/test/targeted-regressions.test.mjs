import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  ObjectRef, OgvcsError, ProfileRef, RepositoryObjectLookup, decodeCanonical, decodeSequence, encodeCanonical,
  encodeLogicalBundle,
  hashBundleTranscript, hashObject, sha256Digest,
  loadBundledRegistry, validateBundleItem, validateKnownSchema, validateLogicalRecord, verifyLogicalBundle,
  validateAssetGroups, verifyLogicalBundleStream, verifyManifest
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const error = (code, layer) => value => value instanceof OgvcsError && value.code === code && value.layer === layer;

test('convenience bundle encoder memory-preflights caller values before normalization', async () => {
  let refRead = false;
  const item = {
    payload: Uint8Array.of(0x41),
    get ref() { refRead = true; throw new Error('ref must remain unread'); }
  };
  assert.throws(() => encodeLogicalBundle({ objects: [item] }, { maxMemoryBytes: 1_000 }),
    error('LIMIT_MEMORY', 1));
  assert.equal(refRead, false);

  const annotation = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-records/08-annotation.cbor'
  ))));
  annotation.set(18, new Uint8Array(400_000));
  assert.throws(() => encodeLogicalBundle({ logicalRecords: [annotation] }, {
    maxMemoryBytes: 1_000_000
  }), error('LIMIT_MEMORY', 1));
});

test('supplied-closure root membership rejects at layer two in both verifiers', async t => {
  const payload = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/scenario-bundle-root-invalid.cborseq'
  )));
  const registry = await loadBundledRegistry();
  assert.throws(() => verifyLogicalBundle(payload, { registry, mode: 'conformance' }),
    error('BUNDLE_ROOT_INVALID', 2));

  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-root-layer-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([payload], {
    registry, mode: 'conformance', scratchDirectory
  }), error('BUNDLE_ROOT_INVALID', 2));
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('in-memory bundle verification accounts retained sequence state in one aggregate budget', async () => {
  const payload = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  )));
  assert.throws(() => verifyLogicalBundle(payload, { maxMemoryBytes: payload.length }),
    error('LIMIT_MEMORY', 1));
  // Decoding the sequence alone fits this ceiling; the second decoded object
  // representation plus lookup/root/closure indexes does not.
  assert.throws(() => verifyLogicalBundle(payload, { maxMemoryBytes: 19_000 }),
    error('LIMIT_MEMORY', 1));
});

test('actual traversal beyond the header declaration is a layer-one bundle budget failure', async t => {
  const original = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  )));
  const registry = await loadBundledRegistry();
  const actualTraversalEdges = verifyLogicalBundle(original, {
    registry, mode: 'conformance'
  }).traversalEdges;
  const { values } = decodeSequence(original, { maxValueBytes: 536_870_912 });
  const header = new Map(values[0]);
  const declarations = new Map(header.get(6));
  assert.ok(actualTraversalEdges > 0);
  declarations.set(2, actualTraversalEdges - 1);
  header.set(6, declarations);
  const prefixValues = [header, ...values.slice(1, -1)];
  const prefix = prefixValues.map(value => encodeCanonical(value, {
    maxBytes: 536_871_424,
    maxValueBytes: 536_870_912
  }));
  const trailer = new Map(values.at(-1));
  trailer.set(6, hashBundleTranscript(prefix).toMap());
  const changed = Buffer.concat([...prefix, encodeCanonical(trailer)]);
  assert.equal(changed.length, original.length);

  assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error('BUNDLE_BUDGET_EXCEEDED', 1));

  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-budget-layer-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([changed], {
    registry, mode: 'conformance', scratchDirectory
  }), error('BUNDLE_BUDGET_EXCEEDED', 1));
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('actual traversal accounting precedes later closure failure', async t => {
  const original = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  )));
  const treePayload = new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor')));
  const treeReference = hashObject(3, treePayload);
  const { values } = decodeSequence(original, { maxValueBytes: 536_870_912 });
  const originalObjectCount = Number(values[0].get(3));
  const originalLogicalCount = Number(values[0].get(4));
  const originalRootCount = Number(values[0].get(5));
  const objectItems = values.slice(1, 1 + originalObjectCount).map(value => new Map(value));
  objectItems.push(new Map([[0, 1], [1, 2], [2, 0], [3, treeReference.toMap()], [4, treePayload]]));
  objectItems.sort((left, right) => Buffer.compare(
    encodeCanonical(left.get(3)), encodeCanonical(right.get(3))
  ));
  objectItems.forEach((item, ordinal) => item.set(2, ordinal));
  const body = [
    ...objectItems,
    ...values.slice(1 + originalObjectCount, -1)
  ];
  let declaredBytes = 0;
  let declaredLargest = 0;
  let changed;
  for (let iteration = 0; iteration < 12; iteration += 1) {
    const header = new Map([
      [0, 1], [1, 1], [2, 1], [3, objectItems.length], [4, originalLogicalCount], [5, originalRootCount],
      [6, new Map([[0, declaredBytes], [1, declaredLargest], [2, 0],
        [3, objectItems.length + originalLogicalCount]])]
    ]);
    const prefixValues = [header, ...body];
    const prefix = prefixValues.map(value => encodeCanonical(value));
    const trailer = new Map([
      [0, 1], [1, 5], [2, objectItems.length], [3, originalLogicalCount], [4, originalRootCount],
      [5, prefixValues.length + 1], [6, hashBundleTranscript(prefix).toMap()]
    ]);
    const encoded = [...prefix, encodeCanonical(trailer)];
    const nextBytes = encoded.reduce((sum, item) => sum + item.length, 0);
    const nextLargest = Math.max(...encoded.map(item => item.length));
    changed = Buffer.concat(encoded);
    if (nextBytes === declaredBytes && nextLargest === declaredLargest) break;
    declaredBytes = nextBytes;
    declaredLargest = nextLargest;
  }

  const registry = await loadBundledRegistry();
  assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error('BUNDLE_BUDGET_EXCEEDED', 1));
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-unreachable-budget-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([changed], {
    registry, mode: 'conformance', scratchDirectory
  }), error('BUNDLE_BUDGET_EXCEEDED', 1));
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('same-stage invalid required fields outrank unknown metadata fields across object kinds', async () => {
  for (const [path, kind] of [
    ['objects/02-content-manifest.cbor', 2],
    ['objects/03-tree.cbor', 3],
    ['objects/05-asset-group-set.cbor', 5],
    ['objects/07-snapshot.cbor', 7]
  ]) {
    const value = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, path))));
    value.set(16, 'invalid-required-field');
    value.set(4095, true);
    assert.throws(() => validateKnownSchema(value, kind), error('SCHEMA_FIELD_INVALID', 2), path);
  }
});

test('bundle-wide known-schema selection ranks later invalid before earlier unknown', async t => {
  const registry = await loadBundledRegistry();
  const descriptor = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/06-repository-descriptor.cbor'
  ))));
  const invalid = new Map(descriptor);
  invalid.set(16, 'invalid-required-field');
  const invalidPayload = encodeCanonical(invalid);
  const invalidRef = hashObject(6, invalidPayload);

  let unknownPayload;
  let unknownRef;
  for (let nonce = 0; nonce < 10_000; nonce += 1) {
    const unknown = new Map(descriptor);
    unknown.set(4095, nonce);
    unknownPayload = encodeCanonical(unknown);
    unknownRef = hashObject(6, unknownPayload);
    if (Buffer.compare(encodeCanonical(unknownRef.toMap()), encodeCanonical(invalidRef.toMap())) < 0) break;
  }
  assert.ok(Buffer.compare(encodeCanonical(unknownRef.toMap()), encodeCanonical(invalidRef.toMap())) < 0);

  const seed = decodeSequence(new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  ))), { maxValueBytes: 536_870_912 }).values;
  const role = seed.find(item => item.get?.(1) === 4).get(5);
  const objects = [
    { ref: unknownRef, payload: unknownPayload },
    { ref: invalidRef, payload: invalidPayload }
  ];
  const objectItems = objects.map((item, ordinal) => new Map([
    [0, 1], [1, 2], [2, ordinal], [3, item.ref.toMap()], [4, item.payload]
  ]));
  const roots = objects.map((item, ordinal) => new Map([
    [0, 1], [1, 4], [2, ordinal], [3, 1], [4, item.ref.toMap()], [5, role]
  ]));
  const declarations = new Map([[0, 0], [1, 0], [2, 0], [3, 2]]);
  const header = new Map([
    [0, 1], [1, 1], [2, 1], [3, 2], [4, 0], [5, 2], [6, declarations]
  ]);
  let changed;
  for (let iteration = 0; iteration < 12; iteration += 1) {
    const prefix = [header, ...objectItems, ...roots].map(value => encodeCanonical(value));
    const trailer = new Map([
      [0, 1], [1, 5], [2, 2], [3, 0], [4, 2], [5, 6], [6, hashBundleTranscript(prefix).toMap()]
    ]);
    const encodedTrailer = encodeCanonical(trailer);
    changed = Buffer.concat([...prefix, encodedTrailer]);
    const largest = Math.max(encodedTrailer.length, ...prefix.map(item => item.length));
    if (declarations.get(0) === changed.length && declarations.get(1) === largest) break;
    declarations.set(0, changed.length);
    declarations.set(1, largest);
  }

  const selected = value => value instanceof OgvcsError && value.code === 'SCHEMA_FIELD_INVALID' &&
    value.layer === 2 && value.stage === 'known-schema';
  assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }), selected);
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-known-schema-rank-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([changed], {
    registry, mode: 'conformance', scratchDirectory
  }), selected);
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('configured resource preflight still outranks a deferred unknown field', async () => {
  const manifest = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/02-content-manifest.cbor'
  ))));
  manifest.set(4095, true);
  assert.throws(() => validateKnownSchema(manifest, 2, {
    hardLimits: { 'manifest-chunks': 0 }
  }), error('LIMIT_COUNT', 2));
});

test('configured count preflight never reads an over-limit tree element', async () => {
  const tree = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor'))));
  let reads = 0;
  const hostile = new Proxy({}, { get() { reads += 1; throw new Error('must not read'); } });
  tree.set(17, [hostile]);
  assert.throws(() => validateKnownSchema(tree, 3, {
    hardLimits: { 'tree-entries': 0 }
  }), error('LIMIT_COUNT', 2));
  assert.equal(reads, 0);
});

test('entry schema failure outranks global tree order failure in the known-schema stage', async () => {
  const tree = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor'))));
  tree.set(17, [...tree.get(17)].reverse());
  tree.get(17)[0].set(1, 99);
  assert.throws(() => validateKnownSchema(tree, 3), error('SCHEMA_FIELD_INVALID', 2));
});

test('operation schema failure outranks change-set sequence failure', async () => {
  const changeSet = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/04-change-set.cbor'
  ))));
  changeSet.get(18)[0].set(0, 99);
  changeSet.get(18)[0].set(1, 99);
  assert.throws(() => validateKnownSchema(changeSet, 4), error('SCHEMA_FIELD_INVALID', 2));
});

test('later tree-target failure outranks an earlier change-set sequence failure', async () => {
  const changeSet = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/04-change-set.cbor'
  ))));
  const operations = changeSet.get(18);
  assert.ok(operations.length >= 2);
  operations[0].set(0, 99);
  const laterState = operations.slice(1).find(operation => operation.get(3) instanceof Map).get(3);
  assert.ok(laterState instanceof Map);
  laterState.set(3, Number(laterState.get(1)) === 1 ? 2 : 1);
  assert.throws(() => validateKnownSchema(changeSet, 4), error('TREE_ENTRY_TARGET_INVALID', 2));
});

test('later manifest-part schema failure outranks an earlier chunk-length failure', async () => {
  const manifest = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/02-content-manifest.cbor'
  ))));
  manifest.get(19)[0].set(1, 0);
  manifest.get(19)[1].set(0, false);
  assert.throws(() => validateKnownSchema(manifest, 2), error('SCHEMA_FIELD_INVALID', 2));
});

test('snapshot field schema failure outranks the duplicate-parent constraint', async () => {
  const snapshot = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/07-snapshot.cbor'
  ))));
  const parent = snapshot.get(17)[0] ?? snapshot.get(16);
  snapshot.set(17, [structuredClone(parent), structuredClone(parent)]);
  snapshot.set(25, 123);
  assert.throws(() => validateKnownSchema(snapshot, 7), error('SCHEMA_FIELD_INVALID', 2));
});

test('mutable-ref names are nonempty', async () => {
  const record = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-records/02-mutable-ref.cbor'
  ))));
  record.set(18, '');
  assert.throws(() => validateLogicalRecord(record), error('SCHEMA_FIELD_INVALID', 2));
});

test('catalogue ranking covers every object, logical-record, and bundle-item shape', async () => {
  const objectFiles = [
    '02-content-manifest.cbor', '03-tree.cbor', '04-change-set.cbor',
    '05-asset-group-set.cbor', '06-repository-descriptor.cbor', '07-snapshot.cbor',
    '08-shelf-revision.cbor', '09-provenance.cbor', '10-attestation.cbor', '11-conflict-set.cbor'
  ];
  for (const file of objectFiles) {
    const value = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects', file))));
    const kind = value.get(1);
    value.set(0, 2);
    value.set(4095, true);
    assert.throws(() => validateKnownSchema(value, kind), error('SCHEMA_FIELD_INVALID', 2), file);
  }

  for (let type = 1; type <= 9; type += 1) {
    const file = `${String(type).padStart(2, '0')}-${[
      'repository-root', 'mutable-ref', 'shelf-pointer', 'file-id-lifetime', 'import-mapping',
      'pending-change-reference', 'lock-reference', 'annotation', 'fixture-event'
    ][type - 1]}.cbor`;
    const value = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'logical-records', file))));
    value.set(0, 2);
    value.set(4095, true);
    assert.throws(() => validateLogicalRecord(value), error('SCHEMA_FIELD_INVALID', 2), file);
  }

  const { values } = decodeSequence(new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-all-families.cborseq'
  ))), { maxValueBytes: 536_870_912 });
  for (let type = 1; type <= 5; type += 1) {
    const value = structuredClone(values.find(item => item.get(1) === type));
    value.set(4095, true);
    if (type === 1) value.get(6).set(0, 'invalid');
    else value.set(2, 'invalid');
    assert.throws(() => validateBundleItem(value), error('SCHEMA_FIELD_INVALID', 2), `bundle type ${type}`);
  }

  const nested = structuredClone(values.find(item => item.get(1) === 3));
  nested.get(4).set(0, 2);
  nested.get(4).set(4095, true);
  assert.throws(() => validateBundleItem(nested), error('SCHEMA_FIELD_INVALID', 2));
});

test('sequence ordering precedes too-small declared bytes in both bundle verifiers', async t => {
  const original = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  )));
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(original, { maxValueBytes: 536_870_912 });
  const header = new Map(values[0]);
  const declarations = new Map(header.get(6));
  declarations.set(0, 1);
  header.set(6, declarations);
  const first = new Map(values[2]);
  const second = new Map(values[1]);
  first.set(2, 0);
  second.set(2, 1);
  const prefixValues = [header, first, second, ...values.slice(3, -1)];
  const prefix = prefixValues.map(value => encodeCanonical(value));
  const trailer = new Map(values.at(-1));
  trailer.set(6, hashBundleTranscript(prefix).toMap());
  const changed = Buffer.concat([...prefix, encodeCanonical(trailer)]);

  assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error('BUNDLE_SEQUENCE_INVALID', 1));
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-accounting-order-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([changed], {
    registry, mode: 'conformance', scratchDirectory
  }), error('BUNDLE_SEQUENCE_INVALID', 1));
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('bundle object ordering precedes unsupported reference format', async t => {
  const original = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  )));
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(original, { maxValueBytes: 536_870_912 });
  const firstObject = new Map(values[1]);
  const unsupported = new Map(firstObject.get(3));
  unsupported.set(0, 2);
  firstObject.set(3, unsupported);
  const prefixValues = values.slice(0, -1);
  prefixValues[1] = firstObject;
  const prefix = prefixValues.map(value => encodeCanonical(value));
  const trailer = new Map(values.at(-1));
  trailer.set(6, hashBundleTranscript(prefix).toMap());
  const changed = Buffer.concat([...prefix, encodeCanonical(trailer)]);

  assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error('BUNDLE_SEQUENCE_INVALID', 1));
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-ref-order-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([changed], {
    registry, mode: 'conformance', scratchDirectory
  }), error('BUNDLE_SEQUENCE_INVALID', 1));
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('authenticated invalid bundle-root kind is a layer-two root failure in both verifiers', async t => {
  const original = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/scenario-bundle-multi-root-disambiguation.cborseq'
  )));
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(original, { maxValueBytes: 536_870_912 });
  const rootIndex = values.findLastIndex(item => item.get(1) === 4);
  assert.ok(rootIndex > 0);
  const root = new Map(values[rootIndex]);
  root.set(3, 3);
  const prefixValues = values.slice(0, -1);
  prefixValues[rootIndex] = root;
  const prefix = prefixValues.map(value => encodeCanonical(value));
  const trailer = new Map(values.at(-1));
  trailer.set(6, hashBundleTranscript(prefix).toMap());
  const changed = Buffer.concat([...prefix, encodeCanonical(trailer)]);

  assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error('BUNDLE_ROOT_INVALID', 2));
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-root-kind-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  await assert.rejects(verifyLogicalBundleStream([changed], {
    registry, mode: 'conformance', scratchDirectory
  }), error('BUNDLE_ROOT_INVALID', 2));
  assert.deepEqual(await readdir(scratchDirectory), []);
});

test('authenticated out-of-domain logical types defer to layer-two support checks', async t => {
  const original = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'
  )));
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(original, { maxValueBytes: 536_870_912 });
  const logicalIndex = values.findIndex(item => item.get(1) === 3);
  assert.ok(logicalIndex > 0);
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-logical-type-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));

  for (const type of [0, 65_536]) {
    const logical = new Map(values[logicalIndex]);
    const record = new Map(logical.get(4));
    record.set(1, type);
    logical.set(4, record);
    const prefixValues = values.slice(0, -1);
    prefixValues[logicalIndex] = logical;
    const header = new Map(prefixValues[0]);
    const declarations = new Map(header.get(6));
    header.set(6, declarations);
    prefixValues[0] = header;
    let changed;
    for (let iteration = 0; iteration < 12; iteration += 1) {
      const prefix = prefixValues.map(value => encodeCanonical(value));
      const trailer = new Map(values.at(-1));
      trailer.set(6, hashBundleTranscript(prefix).toMap());
      const encodedTrailer = encodeCanonical(trailer);
      changed = Buffer.concat([...prefix, encodedTrailer]);
      const largest = Math.max(encodedTrailer.length, ...prefix.map(item => item.length));
      if (declarations.get(0) === changed.length && declarations.get(1) === largest) break;
      declarations.set(0, changed.length);
      declarations.set(1, largest);
    }
    assert.throws(() => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
      error('LOGICAL_RECORD_TYPE_UNSUPPORTED', 2), String(type));
    await assert.rejects(verifyLogicalBundleStream([changed], {
      registry, mode: 'conformance', scratchDirectory
    }), error('LOGICAL_RECORD_TYPE_UNSUPPORTED', 2), String(type));
    assert.deepEqual(await readdir(scratchDirectory), []);
  }
});

test('asset-group repository-stage selection uses catalogue order across all groups', () => {
  const profile = (namespace, id) => new Map([[0, namespace], [1, id], [2, 1]]);
  const fileA = new Uint8Array(16).fill(0x11);
  const fileB = new Uint8Array(16).fill(0x22);
  const group = (serial, member) => new Map([
    [0, new Uint8Array(16).fill(serial)],
    [1, profile('group.test', 'opaque')],
    [2, member],
    [3, [new Map([[0, member], [1, profile('group-role.test', 'member')]])]]
  ]);
  const groups = [group(1, fileA), group(2, fileA), group(3, fileB)];
  const fileIds = new Map([[`fid:${Buffer.from(fileA).toString('hex')}`, true]]);
  assert.throws(() => validateAssetGroups(groups, fileIds), error('GROUP_MEMBER_INVALID', 3));
});

test('manifest reference resolution precedes chunk-length content semantics', async () => {
  const seed = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/02-content-manifest.cbor'
  ))));
  const presentChunk = new Uint8Array(12).fill(0x41);
  const presentReference = hashObject(1, presentChunk);
  const missingReference = new ObjectRef(1, new Uint8Array(32).fill(0x7f));
  const manifest = new Map([
    [0, 1], [1, 2], [2, []], [16, 24], [17, sha256Digest(new Uint8Array(24)).toMap()],
    [18, structuredClone(seed.get(18))],
    [19, [
      new Map([[0, presentReference.toMap()], [1, 11]]),
      new Map([[0, missingReference.toMap()], [1, 13]])
    ]]
  ]);
  const payload = encodeCanonical(manifest);
  const manifestReference = hashObject(2, payload);
  const lookup = new RepositoryObjectLookup([
    [manifestReference, payload], [presentReference, presentChunk]
  ]);
  assert.throws(() => verifyManifest(manifestReference, lookup), error('OBJECT_REFERENCE_MISSING', 2));
});

test('repository lookup selects known-schema failures across the complete object set', async () => {
  const manifest = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/02-content-manifest.cbor'
  ))));
  const tree = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor'))));
  manifest.set(4095, true);
  tree.set(16, 'invalid-required-field');
  const manifestPayload = encodeCanonical(manifest);
  const treePayload = encodeCanonical(tree);
  const manifestReference = hashObject(2, manifestPayload);
  const treeReference = hashObject(3, treePayload);
  const lookup = new RepositoryObjectLookup([
    [manifestReference, manifestPayload], [treeReference, treePayload]
  ]);
  assert.throws(() => lookup.validateAll(), error('SCHEMA_FIELD_INVALID', 2));
});

test('repository lookup completes whole-set framing and identity before schema', async () => {
  const manifest = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/02-content-manifest.cbor'
  ))));
  manifest.set(4095, true);
  const manifestPayload = encodeCanonical(manifest);
  const manifestReference = hashObject(2, manifestPayload);
  const treePayload = new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor')));
  const wrongTreeReference = new ObjectRef(3, new Uint8Array(32));
  const lookup = new RepositoryObjectLookup([
    [manifestReference, manifestPayload], [wrongTreeReference, treePayload]
  ]);
  assert.throws(() => lookup.validateAll(), error('OBJECT_ID_MISMATCH', 1));
});

test('repository lookup selects registry semantics across the complete object set', async () => {
  const manifest = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/02-content-manifest.cbor'
  ))));
  const descriptor = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/06-repository-descriptor.cbor'
  ))));
  manifest.set(18, new ProfileRef('chunking.missing', 'unknown', 1).toMap());
  descriptor.set(2, [1]);
  const manifestPayload = encodeCanonical(manifest);
  const descriptorPayload = encodeCanonical(descriptor);
  const registry = await loadBundledRegistry();
  const lookup = new RepositoryObjectLookup([
    [hashObject(2, manifestPayload), manifestPayload],
    [hashObject(6, descriptorPayload), descriptorPayload]
  ], { registry, mode: 'conformance', semanticProfiles: true });
  assert.throws(() => lookup.validateAll(), error('REQUIRED_FEATURE_UNSUPPORTED', 3));
});

test('repository lookup budgets compact decoded containers and returned clones', async () => {
  const descriptor = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/06-repository-descriptor.cbor'
  ))));
  descriptor.set(3, new Map([[
    'extension-state.test/opaque@1', new Array(1_000).fill(false)
  ]]));
  const payload = encodeCanonical(descriptor);
  const reference = hashObject(6, payload);
  // The 1.3 KiB wire value expands to more than 64 KiB of array slots. Both
  // whole-set validation and resolve must bind that graph (and resolve's deep
  // clone) to the exact remaining budget instead of payload-length heuristics.
  assert.throws(() => new RepositoryObjectLookup([[reference, payload]], {
    maxMemoryBytes: 50_000
  }).validateAll(), error('LIMIT_MEMORY', 1));
  assert.throws(() => new RepositoryObjectLookup([[reference, payload]], {
    maxMemoryBytes: 50_000
  }).resolve(reference), error('LIMIT_MEMORY', 1));
});
