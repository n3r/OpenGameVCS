import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import { ObjectRef, ProfileRef, decodeSequence, encodeLogicalBundle, OgvcsError,
  loadBundledRegistry, verifyLogicalBundle, writeOrderedLogicalBundle } from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const bytes = relative => readFile(resolve(VECTORS, relative));

test('logical bundle verifies identity, transcript, supplied closure, and exact accounting', async () => {
  const registry = await loadBundledRegistry();
  const result = verifyLogicalBundle(await bytes('logical-bundles/valid-supplied-closure.cborseq'), {
    registry,
    operation: 'conformance'
  });
  assert.deepEqual(result, {
    highestLayer: 3,
    bytes: 666,
    items: 7,
    objectCount: 2,
    logicalRecordCount: 1,
    rootCount: 2,
    traversalEdges: 3,
    indexEntries: 3,
    transcriptDigest: 'c302bd2f60d259e6859ce677e2d2f08133d53236abaa4de82c5fa868b020735c'
  });

  const empty = verifyLogicalBundle(await bytes('logical-bundles/scenario-bundle-zero-sections.cborseq'), {
    registry,
    operation: 'conformance'
  });
  assert.equal(empty.objectCount, 0);
  assert.equal(empty.logicalRecordCount, 0);
  assert.equal(empty.rootCount, 0);
  assert.equal(empty.traversalEdges, 0);

  const allFamilies = verifyLogicalBundle(await bytes('logical-bundles/valid-all-families.cborseq'), {
    registry,
    operation: 'conformance'
  });
  assert.deepEqual({
    items: allFamilies.items,
    objectCount: allFamilies.objectCount,
    logicalRecordCount: allFamilies.logicalRecordCount,
    rootCount: allFamilies.rootCount,
    traversalEdges: allFamilies.traversalEdges,
    indexEntries: allFamilies.indexEntries
  }, { items: 43, objectCount: 12, logicalRecordCount: 9, rootCount: 20, traversalEdges: 60, indexEntries: 21 });
});

test('logical bundle rejects every checked-in case with its normative code', async () => {
  const registry = await loadBundledRegistry();
  const cases = [
    ['logical-bundles/invalid-section-order.cborseq', 'BUNDLE_SEQUENCE_INVALID'],
    ['logical-bundles/invalid-duplicate-identity.cborseq', 'BUNDLE_DUPLICATE_IDENTITY'],
    ['logical-bundles/invalid-closure-missing.cborseq', 'BUNDLE_CLOSURE_MISSING'],
    ['logical-bundles/invalid-closure-extra.cborseq', 'BUNDLE_CLOSURE_EXTRA'],
    ['logical-bundles/invalid-reference-wrong-kind.cborseq', 'OBJECT_REFERENCE_KIND_MISMATCH'],
    ['logical-bundles/invalid-trailer-mismatch.cborseq', 'BUNDLE_TRAILER_MISMATCH'],
    ['logical-bundles/scenario-bundle-budget.cborseq', 'BUNDLE_BUDGET_EXCEEDED'],
    ['logical-bundles/scenario-bundle-count.cborseq', 'BUNDLE_SEQUENCE_INVALID'],
    ['logical-bundles/scenario-bundle-mode.cborseq', 'BUNDLE_MODE_UNSUPPORTED'],
    ['logical-bundles/scenario-bundle-ordinal.cborseq', 'BUNDLE_SEQUENCE_INVALID'],
    ['logical-bundles/scenario-bundle-object-id.cborseq', 'OBJECT_ID_MISMATCH'],
    ['logical-bundles/scenario-bundle-record-id.cborseq', 'BUNDLE_RECORD_ID_MISMATCH'],
    ['logical-bundles/scenario-bundle-root-invalid.cborseq', 'BUNDLE_ROOT_INVALID'],
    ['logical-bundles/scenario-bundle-eof.cborseq', 'BUNDLE_SEQUENCE_INVALID']
  ];
  for (const [artifact, expected] of cases) {
    const payload = await bytes(artifact);
    assert.throws(
      () => verifyLogicalBundle(payload, { registry, operation: 'conformance' }),
      error => error instanceof OgvcsError && error.code === expected,
      artifact
    );
  }
});

test('logical bundle writer reproduces the independent canonical sequence byte-for-byte', async () => {
  const registry = await loadBundledRegistry();
  const expected = await bytes('logical-bundles/valid-supplied-closure.cborseq');
  const { values } = decodeSequence(expected, { maxValueBytes: 536_871_424 });
  const objects = values.filter(item => item.get(1) === 2).map(item => ({
    ref: ObjectRef.fromMap(item.get(3)), payload: item.get(4)
  }));
  const logicalRecords = values.filter(item => item.get(1) === 3).map(item => item.get(4));
  const roots = values.filter(item => item.get(1) === 4).map(item => ({
    kind: item.get(3),
    identity: item.get(3) === 1 ? ObjectRef.fromMap(item.get(4)) : item.get(4),
    role: ProfileRef.fromMap(item.get(5))
  }));
  const declared = values[0].get(6);
  assert.deepEqual(Buffer.from(encodeLogicalBundle({ objects, logicalRecords, roots }, {
    registry, operation: 'conformance',
    declaredTraversalEdges: Number(declared.get(2)),
    declaredIndexEntries: Number(declared.get(3))
  })), Buffer.from(expected));
});

test('ordered sink writer reproduces every valid bundle with bounded current-item state', async () => {
  const registry = await loadBundledRegistry();
  for (const name of ['valid-supplied-closure', 'valid-all-families',
    'scenario-bundle-zero-sections', 'scenario-bundle-multi-root-disambiguation']) {
    const expected = await bytes(`logical-bundles/${name}.cborseq`);
    const { values } = decodeSequence(expected, { maxValueBytes: 536_871_424 });
    const header = values[0]; const declared = header.get(6);
    const objects = values.filter(item => item.get(1) === 2).map(item => ({ ref: item.get(3), payload: item.get(4) }));
    const logicalRecords = values.filter(item => item.get(1) === 3).map(item => item.get(4));
    const roots = values.filter(item => item.get(1) === 4).map(item => ({
      kind: item.get(3), identity: item.get(4), role: item.get(5)
    }));
    const chunks = [];
    const sink = {
      async write(part) {
        const written = Math.min(7, part.length);
        chunks.push(Buffer.from(part.subarray(0, written)));
        return { bytesWritten: written };
      }
    };
    const summary = await writeOrderedLogicalBundle({
      plan: {
        objectCount: Number(header.get(3)), logicalRecordCount: Number(header.get(4)), rootCount: Number(header.get(5)),
        budget: {
          sequenceBytes: Number(declared.get(0)), largestItemBytes: Number(declared.get(1)),
          traversalEdges: Number(declared.get(2)), indexEntries: Number(declared.get(3))
        }
      },
      objects, logicalRecords, roots, sink, registry, operation: 'conformance', maxMemoryBytes: 536_871_424
    });
    const actual = Buffer.concat(chunks);
    assert.deepEqual(actual, Buffer.from(expected), name);
    assert.equal(summary.bytes, expected.length, name);
    assert.equal(summary.items, values.length, name);
    assert.deepEqual(verifyLogicalBundle(actual, { registry, operation: 'conformance' }).transcriptDigest,
      summary.transcriptDigest, name);
  }
});

test('ordered sink writer rejects order, count, memory, budget, and invalid roots', async () => {
  const registry = await loadBundledRegistry();
  const expected = await bytes('logical-bundles/valid-supplied-closure.cborseq');
  const { values } = decodeSequence(expected, { maxValueBytes: 536_871_424 });
  const header = values[0]; const declared = header.get(6);
  const base = {
    plan: {
      objectCount: Number(header.get(3)), logicalRecordCount: Number(header.get(4)), rootCount: Number(header.get(5)),
      budget: {
        sequenceBytes: Number(declared.get(0)), largestItemBytes: Number(declared.get(1)),
        traversalEdges: Number(declared.get(2)), indexEntries: Number(declared.get(3))
      }
    },
    objects: values.filter(item => item.get(1) === 2).map(item => ({ ref: item.get(3), payload: item.get(4) })),
    logicalRecords: values.filter(item => item.get(1) === 3).map(item => item.get(4)),
    roots: values.filter(item => item.get(1) === 4).map(item => ({ kind: item.get(3), identity: item.get(4), role: item.get(5) })),
    sink: async () => undefined,
    registry,
    operation: 'conformance'
  };
  const rejects = async (override, expectedCode) => assert.rejects(
    writeOrderedLogicalBundle({ ...base, ...override }),
    error => error instanceof OgvcsError && error.code === expectedCode
  );
  await rejects({ objects: [...base.objects].reverse() }, 'BUNDLE_SEQUENCE_INVALID');
  await rejects({ objects: base.objects.slice(0, 1) }, 'BUNDLE_SEQUENCE_INVALID');
  await rejects({ maxMemoryBytes: 1 }, 'LIMIT_MEMORY');
  await rejects({ plan: { ...base.plan, budget: { ...base.plan.budget, sequenceBytes: 1 } } }, 'BUNDLE_BUDGET_EXCEEDED');
  await rejects({ roots: [] }, 'BUNDLE_SEQUENCE_INVALID');
});

test('ordered sink writer detects logical-record mutation between replay passes', async () => {
  const registry = await loadBundledRegistry();
  const expected = await bytes('logical-bundles/valid-supplied-closure.cborseq');
  const { values } = decodeSequence(expected, { maxValueBytes: 536_871_424 });
  const logicalItem = values.find(item => item.get(1) === 3);
  const logicalRoot = values.find(item => item.get(1) === 4 && item.get(3) === 2);
  const record = new Map(logicalItem.get(4));
  let writes = 0;
  const sink = async () => {
    writes += 1;
    if (writes === 2) {
      const changed = record.get(18).slice();
      changed[0] ^= 1;
      record.set(18, changed);
    }
  };
  await assert.rejects(
    writeOrderedLogicalBundle({
      plan: {
        objectCount: 0,
        logicalRecordCount: 1,
        rootCount: 1,
        budget: { sequenceBytes: 10_000, largestItemBytes: 5_000, traversalEdges: 1, indexEntries: 1 }
      },
      logicalRecords: [record],
      roots: [{ kind: 2, identity: logicalRoot.get(4), role: logicalRoot.get(5) }],
      sink,
      registry,
      operation: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_RECORD_ID_MISMATCH' && error.layer === 1
  );
});

test('ordered sink writer binds canonical-record working memory to its configured ceiling', async () => {
  const registry = await loadBundledRegistry();
  const expected = await bytes('logical-bundles/valid-supplied-closure.cborseq');
  const { values } = decodeSequence(expected, { maxValueBytes: 536_871_424 });
  const record = values.find(item => item.get(1) === 3).get(4);
  const root = values.find(item => item.get(1) === 4 && item.get(3) === 2);
  let writes = 0;
  await assert.rejects(writeOrderedLogicalBundle({
    plan: {
      objectCount: 0, logicalRecordCount: 1, rootCount: 1,
      budget: { sequenceBytes: 10_000, largestItemBytes: 5_000, traversalEdges: 1, indexEntries: 1 }
    },
    logicalRecords: [record],
    roots: [{ kind: 2, identity: root.get(4), role: root.get(5) }],
    sink: async () => { writes++; },
    registry,
    operation: 'conformance',
    maxMemoryBytes: 64
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_MEMORY' && error.layer === 1);
  assert.equal(writes, 1, 'only the staged header may be emitted before record preflight fails');
});

test('ordered sink writer detects object-payload mutation during emission', async () => {
  const registry = await loadBundledRegistry();
  const expected = await bytes('logical-bundles/valid-supplied-closure.cborseq');
  const { values } = decodeSequence(expected, { maxValueBytes: 536_871_424 });
  const header = values[0];
  const declared = header.get(6);
  const objects = values.filter(item => item.get(1) === 2).map(item => ({
    ref: item.get(3),
    payload: item.get(4).slice()
  }));
  let writes = 0;
  const sink = async () => {
    writes += 1;
    if (writes === 2) objects[0].payload[objects[0].payload.length - 1] ^= 1;
  };
  await assert.rejects(
    writeOrderedLogicalBundle({
      plan: {
        objectCount: Number(header.get(3)),
        logicalRecordCount: Number(header.get(4)),
        rootCount: Number(header.get(5)),
        budget: {
          sequenceBytes: Number(declared.get(0)),
          largestItemBytes: Number(declared.get(1)),
          traversalEdges: Number(declared.get(2)),
          indexEntries: Number(declared.get(3))
        }
      },
      objects,
      logicalRecords: values.filter(item => item.get(1) === 3).map(item => item.get(4)),
      roots: values.filter(item => item.get(1) === 4).map(item => ({
        kind: item.get(3), identity: item.get(4), role: item.get(5)
      })),
      sink,
      registry,
      operation: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'OBJECT_ID_MISMATCH' && error.layer === 1
  );
});
