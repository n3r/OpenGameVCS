import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  ObjectRef, OgvcsError, ProfileRef, decodeCanonical, decodeSequence, hashObject, sha256Digest,
  loadBundledRegistry, verifyLogicalBundleStream, visitLogicalBundle, writeCanonical,
  writeContentManifest as writeContentManifestRaw,
  writeOrderedLogicalBundle as writeOrderedLogicalBundleRaw,
  writeOrderedTree as writeOrderedTreeRaw
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const registry = await loadBundledRegistry();
const writeContentManifest = input => writeContentManifestRaw({
  registry, operation: 'conformance', ...input
});
const writeOrderedLogicalBundle = input => writeOrderedLogicalBundleRaw({
  registry, operation: 'conformance', ...input
});
const writeOrderedTree = input => writeOrderedTreeRaw({ registry, operation: 'conformance', ...input });
const deadline = value => value instanceof OgvcsError && value.code === 'LIMIT_TIME' && value.layer === 1;
const never = () => new Promise(() => {});

async function bounded(promise) {
  const started = Date.now();
  await assert.rejects(promise, deadline);
  assert.ok(Date.now() - started < 2_000, 'deadline did not bound the external wait');
}

test('tree and manifest callback sinks receive one signal and cannot outwait the deadline', async () => {
  for (const [name, operation] of [
    ['tree', sink => writeOrderedTree({
      descriptor: new ObjectRef(6, new Uint8Array(32)), entryCount: 0, entries: [],
      sink, maxTimeMs: 25
    })],
    ['manifest', sink => writeContentManifest({
      chunkProfile: new ProfileRef('chunking.test', 'external-boundaries', 1),
      logicalLength: 0, partCount: 0, parts: [],
      wholeFileDigest: sha256Digest(new Uint8Array()), sink, maxTimeMs: 25
    })]
  ]) {
    let observed;
    await bounded(operation((_part, { signal }) => {
      observed = signal;
      return never();
    }));
    assert.ok(observed instanceof AbortSignal, name);
    assert.equal(observed.aborted, true, name);
    assert.equal(observed.reason?.code, 'LIMIT_TIME', name);
  }
});

test('non-draining stream sinks time out and release drain/error listeners', async () => {
  class BlockedSink extends EventEmitter {
    write() { return false; }
  }
  const sink = new BlockedSink();
  await bounded(writeOrderedTree({
    descriptor: new ObjectRef(6, new Uint8Array(32)), entryCount: 0, entries: [],
    sink, maxTimeMs: 25
  }));
  assert.equal(sink.listenerCount('drain'), 0);
  assert.equal(sink.listenerCount('error'), 0);
});

test('generic canonical writer bounds callback, Node drain, and Web-writer waits', async () => {
  let callbackSignal;
  await bounded(writeCanonical(new Map([[0, 1]]), (_part, { signal }) => {
    callbackSignal = signal;
    return never();
  }, { maxTimeMs: 25 }));
  assert.ok(callbackSignal instanceof AbortSignal);
  assert.equal(callbackSignal.aborted, true);

  class BlockedSink extends EventEmitter {
    write() { return false; }
  }
  const nodeSink = new BlockedSink();
  await bounded(writeCanonical(new Map([[0, 1]]), nodeSink, { maxTimeMs: 25 }));
  assert.equal(nodeSink.listenerCount('drain'), 0);
  assert.equal(nodeSink.listenerCount('error'), 0);

  let released = false;
  let aborted = false;
  const webSink = {
    getWriter() {
      return {
        ready: never(),
        write() { return never(); },
        abort() { aborted = true; },
        releaseLock() { released = true; }
      };
    }
  };
  await bounded(writeCanonical(new Map([[0, 1]]), webSink, { maxTimeMs: 25 }));
  await Promise.resolve();
  assert.equal(aborted, true);
  assert.equal(released, true);
});

test('bundle flush is deadline-bound, signalled, and late rejection is handled', async () => {
  const payload = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/scenario-bundle-zero-sections.cborseq'
  )));
  const { values } = decodeSequence(payload, { maxValueBytes: 536_870_912 });
  const header = values[0];
  const declarations = header.get(6);
  const plan = {
    objectCount: 0, logicalRecordCount: 0, rootCount: 0,
    budget: {
      sequenceBytes: Number(declarations.get(0)),
      largestItemBytes: Number(declarations.get(1)),
      traversalEdges: 0,
      indexEntries: 0
    }
  };
  const unhandled = [];
  const onUnhandled = reason => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  let observed;
  let published = false;
  try {
    await bounded(writeOrderedLogicalBundle({
      plan, maxTimeMs: 25,
      sink: {
        write() {},
        flush({ signal }) {
          observed = signal;
          return new Promise((resolvePromise, reject) => setTimeout(() => {
            if (signal.aborted) {
              reject(new Error('late flush rejection'));
              return;
            }
            published = true;
            resolvePromise();
          }, 75));
        }
      }
    }));
    assert.ok(observed instanceof AbortSignal);
    assert.equal(observed.aborted, true);
    assert.equal(observed.reason?.code, 'LIMIT_TIME');
    assert.equal(published, false, 'timed-out staged output was treated as published');
    await new Promise(resolvePromise => setTimeout(resolvePromise, 100));
    assert.equal(published, false, 'late-settling flush published after cancellation');
    assert.deepEqual(unhandled, []);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});

test('tree and bundle source iteration is deadline-bound and cancellation-aware', async () => {
  for (const [name, operation] of [
    ['tree', entries => writeOrderedTree({
      descriptor: new ObjectRef(6, new Uint8Array(32)), entryCount: 0, entries,
      sink() {}, maxTimeMs: 25
    })],
    ['bundle', objects => writeOrderedLogicalBundle({
      plan: {
        objectCount: 0, logicalRecordCount: 0, rootCount: 0,
        budget: { sequenceBytes: 512, largestItemBytes: 256, traversalEdges: 0, indexEntries: 0 }
      },
      objects, logicalRecords: [], roots: [], sink() {}, maxTimeMs: 25
    })]
  ]) {
    let nextSignal;
    let returnSignal;
    const source = {
      [Symbol.asyncIterator]() {
        return {
          next({ signal }) { nextSignal = signal; return never(); },
          return({ signal }) { returnSignal = signal; return Promise.resolve({ done: true }); }
        };
      }
    };
    await bounded(operation(source));
    await Promise.resolve();
    assert.ok(nextSignal instanceof AbortSignal, name);
    assert.equal(nextSignal.aborted, true, name);
    assert.strictEqual(returnSignal, nextSignal, name);
  }
});

test('spooled bundle verification bounds input next and return', async t => {
  const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-source-deadline-'));
  t.after(() => rm(scratchDirectory, { recursive: true, force: true }));
  let nextSignal;
  let returnSignal;
  const source = {
    [Symbol.asyncIterator]() {
      return {
        next({ signal }) { nextSignal = signal; return never(); },
        return({ signal }) { returnSignal = signal; return Promise.resolve({ done: true }); }
      };
    }
  };
  // The verifier's deadline includes no-follow scratch setup. Leave enough
  // room for a loaded Windows runner to reach the caller-owned iterator while
  // retaining the test's strict two-second external-wait ceiling.
  await bounded(verifyLogicalBundleStream(source, { semantic: false, scratchDirectory, maxTimeMs: 250 }));
  await Promise.resolve();
  assert.ok(nextSignal instanceof AbortSignal);
  assert.equal(nextSignal.aborted, true);
  assert.strictEqual(returnSignal, nextSignal);
});

test('public bundle visitor deadline-races nonsettling visitor hooks', async () => {
  const payload = new Uint8Array(await readFile(resolve(
    VECTORS, 'logical-bundles/scenario-bundle-zero-sections.cborseq'
  )));
  let observed;
  await bounded(visitLogicalBundle(payload, {
    onInputChunk(_part, { signal }) { observed = signal; return never(); }
  }, { maxTimeMs: 25 }));
  assert.ok(observed instanceof AbortSignal);
  assert.equal(observed.aborted, true);
  assert.equal(observed.reason?.code, 'LIMIT_TIME');
});

test('tree declared-count ranking completes a finite iterator without cancellation', async () => {
  const tree = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor'))));
  let returnSignal;
  const source = {
    [Symbol.asyncIterator]() {
      let first = true;
      return {
        next() {
          if (first) { first = false; return Promise.resolve({ value: tree.get(17)[0], done: false }); }
          return Promise.resolve({ done: true });
        },
        return({ signal }) { returnSignal = signal; return never(); }
      };
    }
  };
  const started = Date.now();
  await assert.rejects(writeOrderedTree({
    descriptor: ObjectRef.fromMap(tree.get(16)), entryCount: 0, entries: source,
    sink() {}, maxTimeMs: 25
  }), value => value instanceof OgvcsError && value.code === 'SCHEMA_FIELD_INVALID' && value.layer === 2);
  assert.ok(Date.now() - started < 2_000, 'finite iterator traversal exceeded the shared deadline');
  assert.equal(returnSignal, undefined);
});

test('manifest part and chunk-provider awaits share the writer deadline', async () => {
  let partSignal;
  const parts = {
    [Symbol.asyncIterator]() {
      return {
        next({ signal }) { partSignal = signal; return never(); },
        return() { return Promise.resolve({ done: true }); }
      };
    }
  };
  await bounded(writeContentManifest({
    chunkProfile: new ProfileRef('chunking.test', 'external-boundaries', 1),
    logicalLength: 0, partCount: 0, parts,
    wholeFileDigest: sha256Digest(new Uint8Array()), sink() {}, maxTimeMs: 25
  }));
  assert.ok(partSignal instanceof AbortSignal);
  assert.equal(partSignal.aborted, true);

  const chunk = Uint8Array.of(1, 2, 3);
  const reference = hashObject(1, chunk);
  let providerSignal;
  await bounded(writeContentManifest({
    chunkProfile: new ProfileRef('chunking.test', 'external-boundaries', 1),
    logicalLength: chunk.length, partCount: 1,
    parts: [new Map([[0, reference.toMap()], [1, chunk.length]])],
    wholeFileDigest: sha256Digest(chunk), verifyContent: true,
    chunkProvider(_reference, { signal }) { providerSignal = signal; return never(); },
    sink() {}, maxTimeMs: 25
  }));
  assert.ok(providerSignal instanceof AbortSignal);
  assert.equal(providerSignal.aborted, true);
});

test('caller-owned FileID index add and finish hooks are deadline-bound', async () => {
  const tree = decodeCanonical(new Uint8Array(await readFile(resolve(VECTORS, 'objects/03-tree.cbor'))));
  const descriptor = ObjectRef.fromMap(tree.get(16));
  let addSignal;
  await bounded(writeOrderedTree({
    descriptor, entryCount: 1, entries: [tree.get(17)[0]], sink() {}, maxTimeMs: 25,
    fileIdIndex: {
      begin() {},
      add(_fileId, { signal }) { addSignal = signal; return never(); },
      finish() { return { count: 1 }; },
      abort() {}
    }
  }));
  assert.ok(addSignal instanceof AbortSignal);
  assert.equal(addSignal.aborted, true);

  let finishSignal;
  await bounded(writeOrderedTree({
    descriptor, entryCount: 0, entries: [], sink() {}, maxTimeMs: 25,
    fileIdIndex: {
      begin() {},
      add() {},
      finish(_count, { signal }) { finishSignal = signal; return never(); },
      abort() {}
    }
  }));
  assert.ok(finishSignal instanceof AbortSignal);
  assert.equal(finishSignal.aborted, true);
});
