import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  OgvcsError, ProfileRef, decodeCanonical, decodeSequence, encodeCanonical, encodeLogicalBundle, hashBundleTranscript,
  hashObject, loadBundledRegistry, verifyLogicalBundle, verifyLogicalBundleFile, verifyLogicalBundleStream
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const bundle = name => readFile(join(VECTORS, 'logical-bundles', `${name}.cborseq`));

async function temporary(t, label = 'ogvcs-bundle-spool-') {
  const directory = await mkdtemp(join(tmpdir(), label));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  return directory;
}

async function empty(directory) { assert.deepEqual(await readdir(directory), []); }

function coreResult(value) {
  const { metrics: _metrics, ...result } = value;
  return result;
}

async function* fragmented(bytes, width = 1) {
  for (let offset = 0; offset < bytes.length; offset += width) yield bytes.subarray(offset, offset + width);
}

async function waitFor(directory, predicate, maximum = 2_000) {
  const started = Date.now();
  while (Date.now() - started < maximum) {
    const found = (await readdir(directory)).find(predicate);
    if (found) return found;
    await new Promise(resolvePromise => setTimeout(resolvePromise, 1));
  }
  assert.fail('timed out waiting for verifier scratch file');
}

test('spooled stream and same-handle file verification match every valid bundle vector', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  for (const name of ['valid-supplied-closure', 'valid-all-families', 'scenario-bundle-zero-sections']) {
    const payload = await bundle(name);
    const expected = verifyLogicalBundle(payload, { registry, mode: 'conformance' });
    const streamed = await verifyLogicalBundleStream(fragmented(payload, 7), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    });
    assert.deepEqual(coreResult(streamed), expected, name);
    assert.ok(streamed.metrics.peakScratchBytes > 0);
    assert.ok(streamed.metrics.scratchFiles > 0);
    assert.ok(streamed.metrics.indexRuns >= 0);
    await empty(directory);

    const path = join(directory, `${name}.cborseq`);
    await writeFile(path, payload);
    const fromFile = await verifyLogicalBundleFile(path, {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    });
    assert.deepEqual(coreResult(fromFile), expected, `${name} file`);
    await rm(path);
    await empty(directory);
  }
});

test('successful closure lookup spans many bounded external-sort merge runs', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const seed = decodeSequence(await bundle('valid-supplied-closure'), { maxValueBytes: 536_870_912 });
  const rootItem = seed.values.find(item => item.get(1) === 4 && item.get(3) === 1);
  const role = ProfileRef.fromMap(rootItem.get(5));
  const objects = [];
  const roots = [];
  for (let index = 0; index < 512; index += 1) {
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(index);
    const ref = hashObject(1, payload, { registry: registry.kindNames });
    objects.push({ ref, payload });
    roots.push({ kind: 1, identity: ref, role });
  }
  const encoded = encodeLogicalBundle({ objects, roots }, { registry, mode: 'conformance' });
  const result = await verifyLogicalBundleStream(fragmented(encoded, 29), {
    scratchDirectory: directory,
    maxScratchBytes: 16_777_216,
    maxRunBytes: 420,
    maxOpenRuns: 4,
    registry,
    mode: 'conformance'
  });
  assert.equal(result.objectCount, 512);
  assert.equal(result.rootCount, 512);
  assert.equal(result.traversalEdges, 0);
  assert.ok(result.metrics.indexRuns >= 52);
  await empty(directory);
});

test('canonical object ordering is checked independently of ordinals and transcript', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(await bundle('valid-supplied-closure'), { maxValueBytes: 536_870_912 });
  const first = new Map(values[2]);
  const second = new Map(values[1]);
  first.set(2, 0);
  second.set(2, 1);
  const prefixValues = [values[0], first, second, ...values.slice(3, -1)];
  const prefix = prefixValues.map(value => encodeCanonical(value, { maxBytes: 536_871_424, maxValueBytes: 536_870_912 }));
  const trailer = new Map(values.at(-1));
  trailer.set(6, hashBundleTranscript(prefix).toMap());
  const changed = Buffer.concat([...prefix, encodeCanonical(trailer)]);
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(changed, 13), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID'
  );
  await empty(directory);
});

test('complete sequence ordering precedes an earlier object identity mismatch', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(await bundle('valid-supplied-closure'), { maxValueBytes: 536_870_912 });
  const first = new Map(values[2]);
  first.set(2, 0);
  const changedPayload = first.get(4).slice();
  changedPayload[changedPayload.length - 1] ^= 1;
  first.set(4, changedPayload);
  const second = new Map(values[1]);
  second.set(2, 1);
  const prefixValues = [values[0], first, second, ...values.slice(3, -1)];
  const prefix = prefixValues.map(value => encodeCanonical(value, {
    maxBytes: 536_871_424,
    maxValueBytes: 536_870_912
  }));
  const trailer = new Map(values.at(-1));
  trailer.set(6, hashBundleTranscript(prefix).toMap());
  const changed = Buffer.concat([...prefix, encodeCanonical(trailer)]);
  assert.throws(
    () => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID' && error.layer === 1
  );
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(changed, 19), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID' && error.layer === 1
  );
  await empty(directory);
});

test('sequence-order failure outranks an earlier duplicate identity', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(await bundle('valid-all-families'), { maxValueBytes: 536_870_912 });
  const objectCount = Number(values[0].get(3));
  const objects = values.slice(1, 1 + objectCount).map(value => new Map(value));

  objects[1].set(3, objects[0].get(3));
  objects[1].set(4, objects[0].get(4));
  const thirdReference = objects[2].get(3);
  const thirdPayload = objects[2].get(4);
  objects[2].set(3, objects[3].get(3));
  objects[2].set(4, objects[3].get(4));
  objects[3].set(3, thirdReference);
  objects[3].set(4, thirdPayload);

  const changedValues = [values[0], ...objects, ...values.slice(1 + objectCount)];
  const changed = Buffer.concat(changedValues.map(value => Buffer.from(encodeCanonical(value, {
    maxBytes: 536_871_424,
    maxValueBytes: 536_870_912
  }))));
  assert.throws(
    () => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID' && error.layer === 1
  );
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(changed, 17), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID' && error.layer === 1
  );
  await empty(directory);
});

test('non-map section items fail with the stable sequence error', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(await bundle('valid-supplied-closure'), { maxValueBytes: 536_870_912 });
  const changed = Buffer.concat(values.map((value, index) => Buffer.from(encodeCanonical(index === 1 ? 0 : value, {
    maxBytes: 536_871_424,
    maxValueBytes: 536_870_912
  }))));
  assert.throws(
    () => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID' && error.layer === 1
  );
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(changed, 7), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_SEQUENCE_INVALID' && error.layer === 1
  );
  await empty(directory);
});

test('spooled verification preserves all checked-in malformed-vector codes', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const cases = [
    ['invalid-section-order', 'BUNDLE_SEQUENCE_INVALID'],
    ['invalid-duplicate-identity', 'BUNDLE_DUPLICATE_IDENTITY'],
    ['invalid-closure-missing', 'BUNDLE_CLOSURE_MISSING'],
    ['invalid-closure-extra', 'BUNDLE_CLOSURE_EXTRA'],
    ['invalid-reference-wrong-kind', 'OBJECT_REFERENCE_KIND_MISMATCH'],
    ['invalid-trailer-mismatch', 'BUNDLE_TRAILER_MISMATCH'],
    ['scenario-bundle-budget', 'BUNDLE_BUDGET_EXCEEDED'],
    ['scenario-bundle-count', 'BUNDLE_SEQUENCE_INVALID'],
    ['scenario-bundle-mode', 'BUNDLE_MODE_UNSUPPORTED'],
    ['scenario-bundle-ordinal', 'BUNDLE_SEQUENCE_INVALID'],
    ['scenario-bundle-object-id', 'OBJECT_ID_MISMATCH'],
    ['scenario-bundle-record-id', 'BUNDLE_RECORD_ID_MISMATCH'],
    ['scenario-bundle-root-invalid', 'BUNDLE_ROOT_INVALID'],
    ['scenario-bundle-eof', 'BUNDLE_SEQUENCE_INVALID']
  ];
  for (const [name, code] of cases) {
    await assert.rejects(
      verifyLogicalBundleStream(fragmented(await bundle(name), 11), {
        scratchDirectory: directory,
        maxScratchBytes: 16_777_216,
        registry,
        mode: 'conformance'
      }),
      error => error instanceof OgvcsError && error.code === code,
      name
    );
    await empty(directory);
  }
});

test('layer-one transcript authentication precedes later schema failures in both verifiers', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const seed = decodeSequence(await bundle('valid-supplied-closure'), { maxValueBytes: 536_870_912 }).values;
  const manifestIndex = seed.findIndex(item => item.get?.(1) === 2 && item.get(3).get(1) === 2);
  const manifestItem = new Map(seed[manifestIndex]);
  const manifest = new Map(decodeCanonical(manifestItem.get(4)));
  manifest.set(16, BigInt(manifest.get(16)) + 1n);
  const payload = encodeCanonical(manifest);
  manifestItem.set(3, hashObject(2, payload, { registry: registry.kindNames }).toMap());
  manifestItem.set(4, payload);
  const prefix = seed.slice(0, -1).map((value, index) => encodeCanonical(
    index === manifestIndex ? manifestItem : value,
    { maxBytes: 536_871_424, maxValueBytes: 536_870_912 }
  ));
  const changed = Buffer.concat([...prefix, encodeCanonical(seed.at(-1))]);
  assert.throws(
    () => verifyLogicalBundle(changed, { registry, mode: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_TRAILER_MISMATCH' && error.layer === 1
  );
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(changed, 13), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'BUNDLE_TRAILER_MISMATCH' && error.layer === 1
  );
  await empty(directory);
});

test('registry semantic failures are selected globally in catalogue order', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const descriptor = decodeCanonical(await readFile(join(VECTORS, 'objects', '06-repository-descriptor.cbor')));
  const unknownProfile = new Map(descriptor);
  unknownProfile.set(17, new ProfileRef('path.test', 'unregistered', 1).toMap());
  const unsupportedFeature = new Map(descriptor);
  unsupportedFeature.set(2, [4_294_967_295]);
  const payloads = [encodeCanonical(unknownProfile), encodeCanonical(unsupportedFeature)];
  const objects = payloads.map(payload => ({ ref: hashObject(6, payload), payload }));
  const seed = decodeSequence(await bundle('valid-supplied-closure'), { maxValueBytes: 536_870_912 }).values;
  const role = ProfileRef.fromMap(seed.find(item => item.get?.(1) === 4).get(5));
  const encoded = encodeLogicalBundle({
    objects,
    roots: objects.map(item => ({ kind: 1, identity: item.ref, role }))
  });
  assert.throws(
    () => verifyLogicalBundle(encoded, { registry, mode: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'REQUIRED_FEATURE_UNSUPPORTED' && error.layer === 3
  );
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(encoded, 17), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && error.code === 'REQUIRED_FEATURE_UNSUPPORTED' && error.layer === 3
  );
  await empty(directory);
});

test('selected header, identity, payload, and trailer bit mutations never validate', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const original = await bundle('valid-supplied-closure');
  const positions = [0, 24, 96, Math.floor(original.length / 2), original.length - 34, original.length - 1];
  for (const position of positions) {
    const changed = Buffer.from(original);
    changed[position] ^= 1;
    await assert.rejects(
      verifyLogicalBundleStream(fragmented(changed, 3), {
        scratchDirectory: directory,
        maxScratchBytes: 16_777_216,
        registry,
        mode: 'conformance'
      }),
      error => error instanceof OgvcsError,
      `mutation at ${position}`
    );
    await empty(directory);
  }
});

test('configured byte, count, traversal, memory, scratch, decode, and time limits fail cleanly', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const payload = await bundle('valid-supplied-closure');
  const cases = [
    [{ sequenceBytes: payload.length - 1 }, 'BUNDLE_BUDGET_EXCEEDED'],
    [{ objects: 1 }, 'BUNDLE_BUDGET_EXCEEDED'],
    [{ traversalEdges: 2 }, 'BUNDLE_BUDGET_EXCEEDED'],
    [{ indexEntries: 2 }, 'BUNDLE_BUDGET_EXCEEDED'],
    [{ maxDecodedItemBytes: 8 }, 'LIMIT_MEMORY'],
    [{ maxScratchBytes: 64 }, 'LIMIT_SCRATCH'],
    [{ maxMemoryBytes: 4_095 }, 'LIMIT_MEMORY'],
    [{ maxTimeMs: 0 }, 'LIMIT_TIME']
  ];
  for (const [limits, code] of cases) {
    await assert.rejects(
      verifyLogicalBundleStream([payload], {
        scratchDirectory: directory,
        maxScratchBytes: 16_777_216,
        registry,
        mode: 'conformance',
        ...limits
      }),
      error => error instanceof OgvcsError && error.code === code,
      JSON.stringify(limits)
    );
    await empty(directory);
  }
});

test('one-byte reads succeed while physical truncation is rejected and cleaned', async t => {
  const directory = await temporary(t);
  const registry = await loadBundledRegistry();
  const payload = await bundle('valid-supplied-closure');
  const result = await verifyLogicalBundleStream(fragmented(payload), {
    scratchDirectory: directory,
    maxScratchBytes: 16_777_216,
    registry,
    mode: 'conformance'
  });
  assert.equal(result.transcriptDigest, 'c302bd2f60d259e6859ce677e2d2f08133d53236abaa4de82c5fa868b020735c');
  await empty(directory);
  await assert.rejects(
    verifyLogicalBundleStream(fragmented(payload.subarray(0, -1)), {
      scratchDirectory: directory,
      maxScratchBytes: 16_777_216,
      registry,
      mode: 'conformance'
    }),
    error => error instanceof OgvcsError && ['CBOR_TRUNCATED', 'BUNDLE_SEQUENCE_INVALID'].includes(error.code)
  );
  await empty(directory);
});

test('input path replacement after open cannot redirect the same-handle verifier', {
  skip: process.platform === 'win32' ? 'open-file replacement semantics differ on Windows' : false,
  timeout: 30_000
}, async t => {
  const directory = await temporary(t, 'ogvcs-bundle-path-swap-');
  const scratch = join(directory, 'scratch');
  await mkdir(scratch);
  const registry = await loadBundledRegistry();
  const seed = await bundle('valid-supplied-closure');
  const rootItem = decodeSequence(seed, { maxValueBytes: 536_870_912 }).values.find(item => item.get(1) === 4 && item.get(3) === 1);
  const role = ProfileRef.fromMap(rootItem.get(5));
  const payload = Buffer.alloc(2_097_152, 0x5a);
  const ref = hashObject(1, payload, { registry: registry.kindNames });
  const encoded = encodeLogicalBundle({
    objects: [{ ref, payload }],
    roots: [{ kind: 1, identity: ref, role }]
  }, { registry, mode: 'conformance' });
  const path = join(directory, 'bundle.cborseq');
  const held = join(directory, 'opened-original.cborseq');
  await writeFile(path, encoded);
  const verification = verifyLogicalBundleFile(path, {
    scratchDirectory: scratch,
    maxScratchBytes: 16_777_216,
    readChunkBytes: 1_024,
    registry,
    mode: 'conformance'
  });
  await waitFor(scratch, name => name.includes('-sequence-'));
  await rename(path, held);
  await writeFile(path, new Uint8Array(encoded.length).fill(0xff));
  const result = await verification;
  assert.equal(result.objectCount, 1);
  assert.equal(result.bytes, encoded.length);
  await empty(scratch);
});

test('scratch run replacement is detected by exact same-file checks', { timeout: 30_000 }, async t => {
  const directory = await temporary(t, 'ogvcs-bundle-scratch-swap-');
  const scratch = join(directory, 'scratch');
  await mkdir(scratch);
  const registry = await loadBundledRegistry();
  const seed = await bundle('valid-supplied-closure');
  const rootItem = decodeSequence(seed, { maxValueBytes: 536_870_912 }).values.find(item => item.get(1) === 4 && item.get(3) === 1);
  const role = ProfileRef.fromMap(rootItem.get(5));
  const objects = [];
  const roots = [];
  for (let index = 0; index < 128; index += 1) {
    const payload = Uint8Array.of(index, index >>> 8);
    const ref = hashObject(1, payload, { registry: registry.kindNames });
    objects.push({ ref, payload });
    roots.push({ kind: 1, identity: ref, role });
  }
  const encoded = encodeLogicalBundle({ objects, roots }, { registry, mode: 'conformance' });
  const verification = verifyLogicalBundleStream(fragmented(encoded, 17), {
    scratchDirectory: scratch,
    maxScratchBytes: 16_777_216,
    maxRunBytes: 42,
    maxOpenRuns: 2,
    registry,
    mode: 'conformance'
  });
  const run = await waitFor(scratch, name => name.includes('-index-run-'));
  const held = join(directory, 'attacker-held-run');
  await rename(join(scratch, run), held);
  // Preserve the fixed run length so detection cannot rely on size alone.
  await writeFile(join(scratch, run), new Uint8Array(42));
  await assert.rejects(verification, error => error instanceof OgvcsError && error.code === 'LIMIT_SCRATCH');
  await rm(held, { force: true });
  await empty(scratch);
});

test('input-file and scratch-directory symlinks are refused', {
  skip: process.platform === 'win32' ? 'symlink creation may require elevated privileges on Windows' : false
}, async t => {
  const directory = await temporary(t);
  const target = join(directory, 'target');
  const link = join(directory, 'link');
  await mkdir(target);
  await symlink(target, link, 'dir');
  await assert.rejects(
    verifyLogicalBundleStream([await bundle('scenario-bundle-zero-sections')], { scratchDirectory: link }),
    error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID'
  );
  const input = join(directory, 'bundle.cborseq');
  const inputLink = join(directory, 'bundle-link.cborseq');
  await writeFile(input, await bundle('scenario-bundle-zero-sections'));
  await symlink(input, inputLink, 'file');
  await assert.rejects(
    verifyLogicalBundleFile(inputLink, { scratchDirectory: target }),
    error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID'
  );
  await empty(target);
});
