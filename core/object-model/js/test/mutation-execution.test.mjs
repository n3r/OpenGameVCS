import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  OgvcsError,
  decodeCanonical,
  decodeMetadata,
  decodeSequence,
  hashLogicalRecord,
  hashObject,
  loadBundledRegistry,
  scanMetadata,
  toHex,
  validateLogicalRecord,
  verifyLogicalBundle
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const read = relative => readFile(resolve(VECTORS, relative));
const json = async relative => JSON.parse(await readFile(resolve(VECTORS, relative), 'utf8'));

const EXPECTED_ALGORITHM = Object.freeze({
  bitNumbering: 'bitIndex 0 is mask 0x01 and bitIndex 7 is mask 0x80',
  id: 'ogvcs.systematic-single-bit-xor',
  operation: 'for byteOffset in [0,byteLength), then bitIndex in [0,8), clone the selected byte range and XOR byte[byteOffset] with (1 << bitIndex)',
  order: ['source catalogue order', 'ascending byteOffset', 'ascending bitIndex'],
  version: 1
});

function mutate(original, byteOffset, bitIndex) {
  assert.ok(Number.isSafeInteger(byteOffset) && byteOffset >= 0 && byteOffset < original.length);
  assert.ok(Number.isSafeInteger(bitIndex) && bitIndex >= 0 && bitIndex < 8);
  const changed = original.slice();
  changed[byteOffset] ^= 1 << bitIndex;
  assert.equal(changed[byteOffset] ^ original[byteOffset], 1 << bitIndex);
  return changed;
}

function expectFormatRejection(operation, label) {
  try {
    operation();
    return false;
  } catch (error) {
    assert.ok(error instanceof OgvcsError, `${label}: unexpected ${error?.constructor?.name ?? typeof error}`);
    return true;
  }
}

test('cross-kind tree-to-conflict mutation returns a stable schema error', async () => {
  const registry = await loadBundledRegistry();
  const changed = new Uint8Array(await read('objects/03-tree.cbor'));
  changed[4] ^= 1 << 3;
  assert.equal(scanMetadata(changed).kind, 11);
  assert.throws(
    () => decodeMetadata(changed, { semantic: false }),
    error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID'
  );
});

test('all 58,520 frozen single-bit recipes execute through public validation APIs', async t => {
  const [recipe, objectIndex, logicalIndex, registry] = await Promise.all([
    json('mutations/single-bit.json'),
    json('objects/index.json'),
    json('logical-records/index.json'),
    loadBundledRegistry()
  ]);

  assert.equal(recipe.schema, 'ogvcs.repository-format.v1.single-bit-mutation-recipes.v1');
  assert.deepEqual(recipe.algorithm, EXPECTED_ALGORITHM);
  assert.deepEqual(recipe.invariants, {
    bundleItem: 'apply canonical framing first; if framing succeeds, item/record/object identity and then transcript verification use the original declarations',
    bundleSequence: 'apply canonical item framing, section/order/count/ordinal/mode/budget and embedded identity checks in normative layer order; if those pass, require BUNDLE_TRAILER_MISMATCH because the original trailer transcript digest cannot authenticate changed pre-trailer bytes',
    objectOrLogicalRecord: 'apply canonical framing before identity; a canonical changed payload must recompute a digest different from declaredIdentity and fail identityFailure'
  });

  const indexedSources = [
    ...objectIndex.objects.map(entry => ({
      source: entry.payloadPath,
      category: entry.kind === 1 ? 'raw-object' : 'metadata-object',
      declaredIdentity: entry.objectId,
      identityFailure: 'OBJECT_ID_MISMATCH',
      kind: entry.kind
    })),
    ...logicalIndex.records.map(entry => ({
      source: entry.payloadPath,
      category: 'logical-record',
      declaredIdentity: entry.identity,
      identityFailure: 'BUNDLE_RECORD_ID_MISMATCH',
      type: entry.type
    }))
  ];
  assert.equal(recipe.sources.length, indexedSources.length);

  let sourceCases = 0;
  let sourceFramingRejections = 0;
  let sourceIdentityRejections = 0;
  for (const [sourceIndex, source] of recipe.sources.entries()) {
    const indexed = indexedSources[sourceIndex];
    assert.deepEqual(
      {
        source: source.source,
        category: source.category,
        declaredIdentity: source.declaredIdentity,
        identityFailure: source.identityFailure
      },
      {
        source: indexed.source,
        category: indexed.category,
        declaredIdentity: indexed.declaredIdentity,
        identityFailure: indexed.identityFailure
      },
      `source catalogue entry ${sourceIndex}`
    );
    const original = new Uint8Array(await read(source.source));
    assert.equal(source.byteLength, original.length, source.source);

    if (source.category === 'logical-record') {
      const originalValue = decodeCanonical(original);
      assert.equal(validateLogicalRecord(originalValue, {
        registry, operation: 'conformance'
      }).type, indexed.type);
      assert.equal(toHex(hashLogicalRecord(indexed.type, original).bytes), source.declaredIdentity);
    } else {
      if (source.category === 'metadata-object') {
        assert.equal(decodeMetadata(original, { semantic: false }).kind, indexed.kind);
      }
      assert.equal(toHex(hashObject(indexed.kind, original).digest), source.declaredIdentity);
    }

    for (let byteOffset = 0; byteOffset < source.byteLength; byteOffset += 1) {
      for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
        const changed = mutate(original, byteOffset, bitIndex);
        let rejectedByFraming = false;
        let actualIdentity;
        if (source.category === 'raw-object') {
          actualIdentity = toHex(hashObject(indexed.kind, changed).digest);
        } else if (source.category === 'metadata-object') {
          rejectedByFraming = expectFormatRejection(() => {
            const decoded = decodeMetadata(changed, { semantic: false });
            if (decoded.kind !== indexed.kind) throw new OgvcsError('OBJECT_REFERENCE_KIND_MISMATCH');
            actualIdentity = toHex(hashObject(indexed.kind, changed).digest);
          }, `${source.source}:${byteOffset}:${bitIndex}`);
        } else {
          rejectedByFraming = expectFormatRejection(() => {
            const value = decodeCanonical(changed);
            const validated = validateLogicalRecord(value, {
              registry, operation: 'conformance'
            });
            actualIdentity = toHex(hashLogicalRecord(validated.type, changed).bytes);
          }, `${source.source}:${byteOffset}:${bitIndex}`);
        }
        if (rejectedByFraming) {
          sourceFramingRejections += 1;
        } else {
          assert.notEqual(actualIdentity, source.declaredIdentity,
            `${source.source}:${byteOffset}:${bitIndex} preserved its frozen identity`);
          sourceIdentityRejections += 1;
        }
        sourceCases += 1;
      }
    }
  }

  const bundle = new Uint8Array(await read(recipe.wholeSequence.source));
  assert.equal(recipe.wholeSequence.category, 'bundle-sequence');
  assert.equal(recipe.wholeSequence.byteLength, bundle.length);
  assert.equal(recipe.wholeSequence.source, 'logical-bundles/valid-supplied-closure.cborseq');
  assert.equal(verifyLogicalBundle(bundle, { registry, operation: 'conformance' }).items, 7);

  const { values, slices } = decodeSequence(bundle, { maxBytes: 536_871_424 });
  const offsets = [];
  let itemOffset = 0;
  for (const slice of slices) {
    offsets.push(itemOffset);
    itemOffset += slice.length;
  }
  const selectedItems = [0, 1, 3, 4, 6];
  const categories = ['bundle-header', 'bundle-object', 'bundle-logical-record', 'bundle-root', 'bundle-trailer'];
  assert.equal(recipe.bundleItemShapes.length, selectedItems.length);
  for (const [shapeIndex, shape] of recipe.bundleItemShapes.entries()) {
    const itemIndex = selectedItems[shapeIndex];
    assert.deepEqual(shape, {
      byteLength: slices[itemIndex].length,
      byteOffset: offsets[itemIndex],
      category: categories[shapeIndex],
      source: recipe.wholeSequence.source
    });
    assert.equal(values[itemIndex].get(1), [1, 2, 3, 4, 5][shapeIndex]);
  }

  const declaredSourceCases = recipe.sources.reduce((count, source) => count + source.byteLength * 8, 0);
  const declaredItemCases = recipe.bundleItemShapes.reduce((count, shape) => count + shape.byteLength * 8, 0);
  const declaredWholeCases = recipe.wholeSequence.byteLength * 8;
  assert.equal(declaredSourceCases, 50_360);
  assert.equal(declaredItemCases, 2_832);
  assert.equal(declaredWholeCases, 5_328);
  assert.equal(declaredSourceCases + declaredItemCases + declaredWholeCases, recipe.totalCases);

  let bundleItemCases = 0;
  for (const shape of recipe.bundleItemShapes) {
    assert.ok(shape.byteOffset >= 0 && shape.byteOffset + shape.byteLength <= bundle.length);
    for (let relativeOffset = 0; relativeOffset < shape.byteLength; relativeOffset += 1) {
      for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
        const absoluteOffset = shape.byteOffset + relativeOffset;
        const changed = mutate(bundle, absoluteOffset, bitIndex);
        assert.equal(expectFormatRejection(
          () => verifyLogicalBundle(changed, { registry, operation: 'conformance' }),
          `${shape.category}:${relativeOffset}:${bitIndex}`
        ), true, `${shape.category}:${relativeOffset}:${bitIndex} validated under the original declarations`);
        bundleItemCases += 1;
      }
    }
  }

  let wholeSequenceCases = 0;
  for (let byteOffset = 0; byteOffset < bundle.length; byteOffset += 1) {
    for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
      const changed = mutate(bundle, byteOffset, bitIndex);
      assert.equal(expectFormatRejection(
        () => verifyLogicalBundle(changed, { registry, operation: 'conformance' }),
        `bundle-sequence:${byteOffset}:${bitIndex}`
      ), true, `bundle-sequence:${byteOffset}:${bitIndex} validated under the original trailer`);
      wholeSequenceCases += 1;
    }
  }

  assert.equal(sourceCases, declaredSourceCases);
  assert.equal(sourceFramingRejections + sourceIdentityRejections, sourceCases);
  assert.equal(bundleItemCases, declaredItemCases);
  assert.equal(wholeSequenceCases, declaredWholeCases);
  const executed = sourceCases + bundleItemCases + wholeSequenceCases;
  assert.equal(executed, recipe.totalCases);
  assert.equal(executed, 58_520);
  t.diagnostic(JSON.stringify({
    language: 'javascript',
    executed,
    sourceCases,
    sourceFramingRejections,
    sourceIdentityRejections,
    bundleItemCases,
    wholeSequenceCases
  }));
});
