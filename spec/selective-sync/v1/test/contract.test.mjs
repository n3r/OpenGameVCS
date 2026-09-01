import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { calculateGolden, decodeProjection, evaluate, metadataProjectionDigest, referenceCollisionKeys, selectionSpecDigest, SelectionReferenceError } from '../scripts/reference.mjs';

const root = new URL('../', import.meta.url);
const load = async (path) => JSON.parse(await readFile(new URL(path, root), 'utf8'));
const contract = await load('contract.json');
const golden = await load('vectors/golden.json');
const require = createRequire(import.meta.url);
const pathRoot = dirname(require.resolve('@opengamevcs/path-contract-v1/package.json'));
const pathCases = JSON.parse(await readFile(resolve(pathRoot, 'vectors/path-cases.json'), 'utf8')).cases;

function prepared(vector, metadata = vector.metadata, contractValue = contract) {
  const metadataProjection = metadataProjectionDigest(metadata, metadata.length, contractValue);
  const specDigest = selectionSpecDigest(vector.spec, vector.bindings, contractValue);
  return {
    request: { spec: vector.spec, bindings: vector.bindings, metadata, expectedSpecDigest: specDigest.toString('hex'), expectedMetadataProjectionDigest: metadataProjection.digest.toString('hex'), declaredRecordCount: metadata.length },
    metadataProjection,
  };
}

function withUnopenedExtra(iteratorFactory, onExtraValue) {
  return {
    [Symbol.iterator]() {
      const iterator = iteratorFactory(); let emittedExtra = false;
      return {
        next() {
          const step = iterator.next();
          if (!step.done) return step;
          if (emittedExtra) return { done: true, value: undefined };
          emittedExtra = true;
          return Object.defineProperties({}, {
            done: { enumerable: true, value: false },
            value: { enumerable: true, get() { onExtraValue(); return { callerControlled: true }; } },
          });
        },
      };
    },
  };
}

test('independent reference reproduces exact golden projection bytes and decisions', () => {
  for (const vector of golden.cases) assert.deepEqual(calculateGolden(vector, contract), vector.expected, vector.caseId);
});

test('independent path projection matches all 25 frozen predecessor path vectors', () => {
  assert.equal(pathCases.length, 25);
  for (const vector of pathCases) {
    const actual = referenceCollisionKeys(vector.input, vector.caseMode, vector.profile);
    assert.equal(actual.accepted, vector.expected.accepted, vector.id);
    if (vector.expected.accepted) {
      assert.equal(actual.canonical, vector.expected.canonical, vector.id);
      assert.equal(actual.repositoryKey, vector.expected.repositoryKey, vector.id);
      assert.equal(actual.platformKey, vector.expected.platformKey, vector.id);
    }
  }
});

test('subtree includes its directory and exact-versus-subtree uses only later ordinal', () => {
  const vector = golden.cases.find(({ caseId }) => caseId === 'developer-exact-after-subtree-tie-by-ordinal');
  const decoded = decodeProjection(Buffer.from(vector.expected.projectionHex, 'hex'));
  assert.equal(decoded.records.find(({ path }) => path === 'Source').materialization, 'full');
  assert.equal(decoded.records.find(({ path }) => path === 'Source/Secrets.txt').materialization, 'absent-by-spec');
});

test('metadata-only and absent projection records contain no content identity', () => {
  for (const vector of golden.cases) {
    const decoded = decodeProjection(Buffer.from(vector.expected.projectionHex, 'hex'));
    for (const record of decoded.records) if (record.materialization !== 'full') assert.equal(record.content, null, `${vector.caseId}:${record.ordinal}`);
  }
});

test('changing excluded content cannot appear as an output record identity', () => {
  const vector = golden.cases[0];
  const changed = structuredClone(vector);
  const excluded = changed.metadata.find(({ path }) => path === 'Docs/Readme.txt');
  excluded.content.digest = 'fe'.repeat(32); excluded.content.logicalBytes += 1;
  const projection = metadataProjectionDigest(changed.metadata, changed.metadata.length, contract);
  const chunks = [];
  evaluate({ spec: changed.spec, bindings: changed.bindings, metadata: changed.metadata,
    expectedSpecDigest: changed.expected.specDigest, expectedMetadataProjectionDigest: projection.digest.toString('hex'),
    declaredRecordCount: changed.metadata.length }, { write(bytes) { chunks.push(Buffer.from(bytes)); }, flush() {} }, contract);
  const decoded = decodeProjection(Buffer.concat(chunks));
  const record = decoded.records.find(({ path }) => path === excluded.path);
  assert.deepEqual(record, { ordinal: 0, path: excluded.path, materialization: 'absent-by-spec', content: null });
});

test('bounded reference accepts exactly 100000 streamed records without collecting output', () => {
  const vector = golden.cases[1]; const count = contract.limits.metadataRecordsMaximum;
  const makeRecords = function* () {
    for (let ordinal = 0; ordinal < count; ordinal += 1) yield { ordinal, path: `Scale/${String(ordinal).padStart(6, '0')}`, entryDigest: 'ab'.repeat(32), content: { digest: 'cd'.repeat(32), logicalBytes: 1 } };
  };
  const metadata = metadataProjectionDigest(makeRecords(), count, contract);
  const specDigest = selectionSpecDigest(vector.spec, vector.bindings, contract);
  let bytes = 0; let maximum = 0;
  const summary = evaluate({ spec: vector.spec, bindings: vector.bindings, metadata: makeRecords(), expectedSpecDigest: specDigest.toString('hex'), expectedMetadataProjectionDigest: metadata.digest.toString('hex'), declaredRecordCount: count }, {
    write(fragment) { bytes += fragment.length; maximum = Math.max(maximum, fragment.length); }, flush() {},
  }, contract);
  assert.equal(summary.recordCount, count); assert.equal(summary.outputBytes, bytes);
  assert.ok(maximum <= contract.limits.sinkFragmentBytesMaximum);

  let evaluateExtraAccesses = 0; let rejectedBytes = 0; let rejectedFlushes = 0;
  const evaluateExtra = withUnopenedExtra(() => makeRecords(), () => { evaluateExtraAccesses += 1; });
  assert.throws(() => evaluate({ spec: vector.spec, bindings: vector.bindings, metadata: evaluateExtra,
    expectedSpecDigest: specDigest.toString('hex'), expectedMetadataProjectionDigest: metadata.digest.toString('hex'), declaredRecordCount: count }, {
    write(fragment) { rejectedBytes += fragment.length; }, flush() { rejectedFlushes += 1; },
  }, contract), (error) => error.code === 'SELECT_METADATA_COUNT_MISMATCH');
  assert.equal(evaluateExtraAccesses, 0); assert.equal(rejectedBytes, summary.outputBytes); assert.equal(rejectedFlushes, 0);

  let digestExtraAccesses = 0;
  const digestExtra = withUnopenedExtra(() => makeRecords(), () => { digestExtraAccesses += 1; });
  assert.throws(() => metadataProjectionDigest(digestExtra, count, contract), (error) => error.code === 'SELECT_METADATA_COUNT_MISMATCH');
  assert.equal(digestExtraAccesses, 0);
});

test('declared count plus one is rejected before the metadata source is entered', () => {
  const vector = golden.cases[0]; let entered = false;
  const metadata = { *[Symbol.iterator]() { entered = true; yield vector.metadata[0]; } };
  assert.throws(() => evaluate({ spec: vector.spec, bindings: vector.bindings, metadata, expectedSpecDigest: vector.expected.specDigest, expectedMetadataProjectionDigest: vector.expected.metadataProjectionDigest, declaredRecordCount: contract.limits.metadataRecordsMaximum + 1 }, { write() {}, flush() {} }, contract), (error) => error instanceof SelectionReferenceError && error.code === 'SELECT_METADATA_COUNT_LIMIT');
  assert.equal(entered, false);
});

test('small overlong sources fail before opening or emitting the extra record', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  let evaluateExtraAccesses = 0; let outputBytes = 0; let flushes = 0;
  const evaluateExtra = withUnopenedExtra(() => vector.metadata[Symbol.iterator](), () => { evaluateExtraAccesses += 1; });
  assert.throws(() => evaluate({ ...request, metadata: evaluateExtra }, {
    write(fragment) { outputBytes += fragment.length; }, flush() { flushes += 1; },
  }, contract), (error) => error.code === 'SELECT_METADATA_COUNT_MISMATCH');
  assert.equal(evaluateExtraAccesses, 0);
  assert.equal(outputBytes, Buffer.from(vector.expected.projectionHex, 'hex').length);
  assert.equal(flushes, 0);

  let digestExtraAccesses = 0;
  const digestExtra = withUnopenedExtra(() => vector.metadata[Symbol.iterator](), () => { digestExtraAccesses += 1; });
  assert.throws(() => metadataProjectionDigest(digestExtra, vector.metadata.length, contract), (error) => error.code === 'SELECT_METADATA_COUNT_MISMATCH');
  assert.equal(digestExtraAccesses, 0);
});

test('repository order, duplicate, and supported-platform collisions fail closed', () => {
  const vector = golden.cases[1];
  for (const paths of [['B', 'A'], ['A', 'A']]) {
    const records = paths.map((path, ordinal) => ({ ordinal, path, entryDigest: '11'.repeat(32), content: null }));
    const metadata = metadataProjectionDigest(records, records.length, contract);
    assert.throws(() => evaluate({ spec: vector.spec, bindings: vector.bindings, metadata: records, expectedSpecDigest: vector.expected.specDigest, expectedMetadataProjectionDigest: metadata.digest.toString('hex'), declaredRecordCount: records.length }, { write() {}, flush() {} }, contract), SelectionReferenceError);
  }
  const windowsBindings = { ...vector.bindings, pathProfile: 'path.opengamevcs/windows@1', platform: 'windows' };
  const records = ['Game/Hero', 'game/hero'].map((path, ordinal) => ({ ordinal, path, entryDigest: '22'.repeat(32), content: null }));
  const metadata = metadataProjectionDigest(records, records.length, contract);
  const specDigest = selectionSpecDigest(vector.spec, windowsBindings, contract);
  assert.throws(() => evaluate({ spec: vector.spec, bindings: windowsBindings, metadata: records, expectedSpecDigest: specDigest.toString('hex'), expectedMetadataProjectionDigest: metadata.digest.toString('hex'), declaredRecordCount: records.length }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_PATH_COLLISION');
});

test('cancellation is checked before header, around each source poll, and before flush', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  let bytes = 0; let flushes = 0;
  assert.throws(() => evaluate(request, { write(fragment) { bytes += fragment.length; }, flush() { flushes += 1; } }, contract, { isCancelled: () => true }), (error) => error.code === 'SELECT_CANCELLED');
  assert.equal(bytes, 0); assert.equal(flushes, 0);

  let checks = 0; bytes = 0;
  assert.throws(() => evaluate(request, { write(fragment) { bytes += fragment.length; }, flush() { flushes += 1; } }, contract, { isCancelled() { checks += 1; return checks === 7; } }), (error) => error.code === 'SELECT_CANCELLED');
  assert.ok(bytes > 56); assert.equal(flushes, 0);

  checks = 0; flushes = 0;
  assert.throws(() => evaluate(request, { write() {}, flush() { flushes += 1; } }, contract, { isCancelled() { checks += 1; return checks === 12; } }), (error) => error.code === 'SELECT_CANCELLED');
  assert.equal(flushes, 0);
});

test('first middle last and flush sink faults expose no returned summary', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  for (const failCall of [0, 3, 6]) {
    let calls = 0;
    assert.throws(() => evaluate(request, { write() { if (calls++ === failCall) throw new Error('injected'); }, flush() {} }, contract), (error) => error.code === 'SELECT_SINK_FAILED');
  }
  assert.throws(() => evaluate(request, { write() {}, flush() { throw new Error('injected'); } }, contract), (error) => error.code === 'SELECT_SINK_FAILED');
  assert.throws(() => evaluate(request, { write() { return true; }, flush() {} }, contract), (error) => error.code === 'SELECT_SINK_INVALID');
});

test('sink receives private copies and cannot mutate the returned projection digest', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  const summary = evaluate(request, { write(fragment) { fragment.fill(0); }, flush() {} }, contract);
  assert.equal(summary.outputProjectionDigest, vector.expected.summary.outputProjectionDigest);
});

test('source throw, short, long, and digest mismatch are fixed failures with no flush', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  const throwingGetter = Object.create(null, { [Symbol.iterator]: { get() { throw new Error('private source getter detail'); } } });
  assert.throws(() => evaluate({ ...request, metadata: throwingGetter }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_SOURCE_FAILED');
  const throwingFactory = { [Symbol.iterator]() { throw new Error('private source construction detail'); } };
  assert.throws(() => evaluate({ ...request, metadata: throwingFactory }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_SOURCE_FAILED');
  assert.throws(() => metadataProjectionDigest(throwingFactory, 0, contract), (error) => error.code === 'SELECT_SOURCE_FAILED');
  const throwing = { *[Symbol.iterator]() { yield vector.metadata[0]; throw new Error('private source detail'); } };
  assert.throws(() => evaluate({ ...request, metadata: throwing }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_SOURCE_FAILED');
  assert.throws(() => evaluate({ ...request, metadata: vector.metadata.slice(0, -1) }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_METADATA_COUNT_MISMATCH');
  const extra = { ...vector.metadata.at(-1), ordinal: vector.metadata.length, path: 'ZZZZ/Other.bin' };
  assert.throws(() => evaluate({ ...request, metadata: [...vector.metadata, extra] }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_METADATA_COUNT_MISMATCH');
  let flushes = 0;
  assert.throws(() => evaluate({ ...request, expectedMetadataProjectionDigest: 'ff'.repeat(32) }, { write() {}, flush() { flushes += 1; } }, contract), (error) => error.code === 'SELECT_METADATA_DIGEST_MISMATCH');
  assert.equal(flushes, 0);
});

test('hostile iterator-result traps are source failures and malformed shapes are source-invalid', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  const iterable = (result) => ({ [Symbol.iterator]() { return { next: result }; } });
  const hostile = [
    () => Object.defineProperty({}, 'done', { get() { throw new Error('HOSTILE_DONE_DETAIL'); } }),
    () => Object.defineProperties({}, {
      done: { value: false }, value: { get() { throw new Error('HOSTILE_VALUE_DETAIL'); } },
    }),
    () => new Proxy({ done: false, value: vector.metadata[0] }, {
      getOwnPropertyDescriptor(target, property) {
        if (property === 'value') throw new Error('HOSTILE_HAS_OWN_DETAIL');
        return Reflect.getOwnPropertyDescriptor(target, property);
      },
    }),
  ];
  for (const next of hostile) {
    const source = iterable(next);
    assert.throws(() => evaluate({ ...request, metadata: source }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_SOURCE_FAILED');
    assert.throws(() => metadataProjectionDigest(source, 1, contract), (error) => error.code === 'SELECT_SOURCE_FAILED');
  }
  for (const next of [() => null, () => ({ done: false }), () => ({ done: 'false', value: vector.metadata[0] })]) {
    const source = iterable(next);
    assert.throws(() => evaluate({ ...request, metadata: source }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_SOURCE_INVALID');
    assert.throws(() => metadataProjectionDigest(source, 1, contract), (error) => error.code === 'SELECT_SOURCE_INVALID');
  }
});

test('noncanonical caller shapes and malformed record identities fail with fixed codes', () => {
  const vector = golden.cases[0]; const { request } = prepared(vector);
  assert.throws(() => evaluate({ ...request, callerExtension: true }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_INPUT_INVALID');
  assert.throws(() => evaluate({ ...request, bindings: { ...request.bindings, callerExtension: true } }, { write() {}, flush() {} }, contract), (error) => error.code === 'SELECT_BINDING_INVALID');
  assert.throws(() => selectionSpecDigest({ ...vector.spec, callerExtension: true }, vector.bindings, contract), (error) => error.code === 'SELECT_SPEC_INVALID');
  const malformed = [{ ...vector.metadata[0], entryDigest: 'not-a-digest' }];
  assert.throws(() => metadataProjectionDigest(malformed, 1, contract), (error) => error.code === 'SELECT_INPUT_INVALID');
});

test('all byte and collision ceilings accept exact use and reject one byte over', () => {
  const path = Array.from({ length: 17 }, () => 'a'.repeat(240)).join('/');
  assert.equal(Buffer.byteLength(path), 4_096);
  const bindings = { snapshotDigest: '11'.repeat(32), settingsDigest: '22'.repeat(32), consistencyTokenDigest: '33'.repeat(32), pathProfile: 'path.opengamevcs/linux@1', caseMode: 'case-sensitive', platform: 'linux' };
  const spec = { schemaVersion: 'ogvcs.selective-sync/workspace-selection-spec/v1', version: 1, defaultMaterialization: 'absent-by-spec', rules: [{ ordinal: 0, match: 'exact', path, materialization: 'full' }] };
  const metadata = [{ ordinal: 0, path, entryDigest: '44'.repeat(32), content: { digest: '55'.repeat(32), logicalBytes: contract.limits.logicalBytesMaximum } }];
  const vector = { spec, bindings, metadata }; const base = { ...contract, limits: { ...contract.limits } };
  const projection = metadataProjectionDigest(metadata, 1, base);
  assert.equal(projection.bytes, contract.limits.inputRecordBytesMaximum);
  const repository = referenceCollisionKeys(path, bindings.caseMode, bindings.pathProfile);
  const ruleBytes = 8 + 1 + 8 + Buffer.byteLength(path) + 1;
  const collisionTotal = Buffer.byteLength(repository.repositoryKey) * 2 + Buffer.byteLength(repository.platformKey) * 2;
  const run = (limits) => {
    const candidate = { ...base, limits: { ...base.limits, ...limits } };
    const metadataProjection = metadataProjectionDigest(metadata, 1, candidate);
    const specDigest = selectionSpecDigest(spec, bindings, candidate);
    let bytes = 0; let maximum = 0;
    const summary = evaluate({ spec, bindings, metadata, expectedSpecDigest: specDigest.toString('hex'), expectedMetadataProjectionDigest: metadataProjection.digest.toString('hex'), declaredRecordCount: 1 }, { write(fragment) { bytes += fragment.length; maximum = Math.max(maximum, fragment.length); }, flush() {} }, candidate);
    return { summary, bytes, maximum };
  };
  const exact = run({ collisionKeyBytesMaximum: Math.max(Buffer.byteLength(repository.repositoryKey), Buffer.byteLength(repository.platformKey)), collisionKeyBytesTotalMaximum: collisionTotal, compiledRuleBytesMaximum: ruleBytes, inputRecordBytesMaximum: projection.bytes });
  assert.equal(exact.maximum, contract.limits.outputRecordBytesMaximum);
  assert.equal(exact.summary.outputBytes, exact.bytes);
  for (const [name, exactValue, code] of [
    ['collisionKeyBytesMaximum', Math.max(Buffer.byteLength(repository.repositoryKey), Buffer.byteLength(repository.platformKey)), 'SELECT_COLLISION_KEY_LIMIT'],
    ['collisionKeyBytesTotalMaximum', collisionTotal, 'SELECT_COLLISION_KEY_TOTAL_LIMIT'],
    ['compiledRuleBytesMaximum', ruleBytes, 'SELECT_COMPILED_RULE_LIMIT'],
    ['inputRecordBytesMaximum', projection.bytes, 'SELECT_INPUT_RECORD_LIMIT'],
    ['metadataBytesMaximum', projection.bytes, 'SELECT_METADATA_BYTES_LIMIT'],
    ['outputRecordBytesMaximum', exact.maximum, 'SELECT_OUTPUT_RECORD_LIMIT'],
    ['sinkFragmentBytesMaximum', exact.maximum, 'SELECT_SINK_FRAGMENT_LIMIT'],
    ['outputBytesMaximum', exact.summary.outputBytes, 'SELECT_OUTPUT_BYTES_LIMIT'],
  ]) assert.throws(() => run({ [name]: exactValue - 1 }), (error) => error.code === code, name);
  assert.equal(calculateGolden({ ...vector, caseId: 'max-shape' }, contract).summary.fullLogicalBytes, contract.limits.logicalBytesMaximum);
  const tooLarge = structuredClone(metadata); tooLarge[0].content.logicalBytes += 1;
  assert.throws(() => metadataProjectionDigest(tooLarge, 1, contract), (error) => error.code === 'SELECT_LOGICAL_BYTES_LIMIT');
});

test('rule count ceiling and hardened projection decoder reject plus one/unsafe u64', () => {
  const bindings = golden.cases[1].bindings;
  const rules = Array.from({ length: contract.limits.rulesMaximum }, (_, ordinal) => ({ ordinal, match: 'exact', path: `Rule/${String(ordinal).padStart(4, '0')}`, materialization: 'full' }));
  const spec = { schemaVersion: 'ogvcs.selective-sync/workspace-selection-spec/v1', version: 1, defaultMaterialization: 'absent-by-spec', rules };
  assert.match(selectionSpecDigest(spec, bindings, contract).toString('hex'), /^[0-9a-f]{64}$/u);
  assert.throws(() => selectionSpecDigest({ ...spec, rules: [...rules, { ordinal: rules.length, match: 'exact', path: 'Rule/plus', materialization: 'full' }] }, bindings, contract), (error) => error.code === 'SELECT_SPEC_INVALID');
  const malicious = Buffer.concat([Buffer.from('OGVCS-SELECT-V1\0'), Buffer.alloc(8, 0xff), Buffer.alloc(32)]);
  assert.throws(() => decodeProjection(malicious), (error) => error.code === 'SELECT_PROJECTION_INVALID');
  const hostile = new Proxy({}, { get() { throw new Error('HOSTILE_PROJECTION_DETAIL'); } });
  assert.throws(() => decodeProjection(hostile), (error) => error.code === 'SELECT_PROJECTION_INVALID');
});
