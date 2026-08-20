import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  Digest, FileId, MAX_FILE_ID_ALLOCATION_ATTEMPTS, ObjectRef, OgvcsError, ProfileRef, REGISTRY_FILES,
  RegistrySnapshot, allocateFileId,
  bundledRegistryDirectory, decodeCanonical, decodeFirst, decodeMetadata, decodeSequence,
  encodeCanonical, encodeMetadata, hashConflictPreimage,
  hashLogicalRecord, hashObject, loadRegistryDirectory, parseCanonicalRegistryJson,
  profileDecision, registryFromEvolutionSnapshot, registrySetDigest, scanMetadata, sha256Digest, toHex,
  reproduceConflictId,
  validateBundleItem, validateConflictPreimage, validateKnownSchema, validateLogicalRecord,
  validateRegistrySet, verifyLogicalBundle
} from '../src/index.js';

const SPEC = resolve(import.meta.dirname, '../../../../spec/repository-format/v1');
const VECTORS = join(SPEC, 'vectors');
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const binary = path => readFile(path);
const expectCode = (fn, code) => assert.throws(fn, error => error instanceof OgvcsError && error.code === code);

test('every malformed deterministic-CBOR vector has its stable class', async () => {
  const index = await json(join(VECTORS, 'malformed/index.json'));
  const vocabulary = await json(join(SPEC, 'errors.json'));
  const classes = new Map(vocabulary.errors.map(error => [error.code, error.class]));
  for (const vector of index.explicitCases) {
    const payload = await binary(join(VECTORS, vector.artifact));
    assert.throws(() => decodeCanonical(payload), error => error instanceof OgvcsError &&
      error.code === vector.expected.code && error.errorClass === classes.get(vector.expected.code));
  }
});

test('canonical text is restricted to the frozen Unicode 15.0 repertoire before NFC', async () => {
  const accepted = await binary(join(VECTORS, 'unicode/cases/age-15-assigned.cbor'));
  const value = decodeCanonical(accepted);
  assert.equal(typeof value, 'string');
  assert.deepEqual(Buffer.from(encodeCanonical(value)), accepted);
  for (const artifact of [
    'unicode-age-newer-composition-pair.cbor',
    'unicode-age-newer-decomposed.cbor',
    'unicode-age-newer-canonical.cbor',
    'unicode-age-frozen-unassigned.cbor'
  ]) {
    const payload = await binary(join(VECTORS, 'malformed', artifact));
    expectCode(() => decodeCanonical(payload), 'CBOR_NON_CANONICAL');
  }
});

test('every normative proper-prefix truncation selects the declared layer-1 result', async () => {
  const recipe = await json(join(VECTORS, 'mutations/truncation.json'));
  const cache = new Map();
  const sourceBytes = async path => {
    if (!cache.has(path)) cache.set(path, new Uint8Array(await binary(join(VECTORS, path))));
    return cache.get(path);
  };
  let executed = 0;
  for (const source of recipe.sources) {
    const complete = await sourceBytes(source.source);
    const offset = source.byteOffset ?? 0;
    const item = complete.subarray(offset, offset + source.byteLength);
    assert.equal(item.length, source.byteLength, source.source);
    for (let prefix = source.prefixes.fromInclusive; prefix <= source.prefixes.toInclusive; prefix += 1) {
      assert.throws(() => decodeCanonical(item.subarray(0, prefix)), error => error instanceof OgvcsError &&
        error.code === source.expected.code && error.layer === source.expected.layer,
      `${source.category}:${prefix}`);
      executed += 1;
    }
  }
  const sequence = await sourceBytes(recipe.wholeSequence.source);
  for (const range of recipe.wholeSequence.ranges) {
    for (let prefix = range.fromInclusive; prefix <= range.toInclusive; prefix += 1) {
      assert.throws(() => verifyLogicalBundle(sequence.subarray(0, prefix), { semantic: false }), error => error instanceof OgvcsError &&
        error.code === range.expected.code && error.layer === range.expected.layer,
      `whole-sequence:${prefix}`);
      executed += 1;
    }
  }
  assert.equal(executed, recipe.totalCases);
});

test('the public error vocabulary preserves every normative class', async () => {
  const vocabulary = await json(join(SPEC, 'errors.json'));
  for (const entry of vocabulary.errors) {
    assert.equal(new OgvcsError(entry.code).errorClass, entry.class, entry.code);
  }
});

test('all metadata object vectors reproduce canonical bytes and ObjectIDs', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const index = await json(join(VECTORS, 'objects/index.json'));
  for (const vector of index.objects) {
    const payload = await binary(join(VECTORS, vector.payloadPath));
    const ref = hashObject(vector.kind, payload, { registry: registry.kindNames });
    assert.equal(toHex(ref.digest), vector.objectId, vector.name);
    assert.equal(ref.toString(), `ogvcs:v1:${vector.name}:sha256:${vector.objectId}`);
    if (vector.kind !== 1) {
      const decoded = decodeMetadata(payload, { semantic: false });
      assert.equal(decoded.kind, vector.kind);
      assert.equal(toHex(encodeCanonical(decoded.value)), toHex(payload));
    }
  }
});

test('all logical records reproduce canonical bytes and identities', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const index = await json(join(VECTORS, 'logical-records/index.json'));
  for (const vector of index.records) {
    const payload = await binary(join(VECTORS, vector.payloadPath));
    const value = decodeCanonical(payload);
    assert.equal(validateLogicalRecord(value, { registry, operation: 'conformance' }).type, vector.type);
    assert.equal(toHex(encodeCanonical(value)), toHex(payload));
    assert.equal(toHex(hashLogicalRecord(vector.type, value).bytes), vector.identity);
  }
});

test('all keyed conflict preimages reproduce their domain-separated IDs', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const index = await json(join(VECTORS, 'conflicts/index.json'));
  for (const vector of index.combinations) {
    const payload = await binary(join(VECTORS, vector.keyedPayloadPath));
    const value = decodeCanonical(payload);
    validateConflictPreimage(value, { registry, operation: 'conformance' });
    assert.equal(toHex(encodeCanonical(value)), toHex(payload));
    assert.equal(toHex(hashConflictPreimage(payload).bytes), vector.conflictId);
    assert.equal(toHex(reproduceConflictId(value).bytes), vector.conflictId);
  }
});

test('current bundle item shapes round-trip without making closure claims', async () => {
  const payload = await binary(join(VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'));
  const index = await json(join(VECTORS, 'logical-bundles/index.json'));
  const { values, slices } = decodeSequence(payload, { maxBytes: 536_871_424 });
  assert.equal(values.length, index.valid.itemCount);
  assert.deepEqual(slices.map(item => item.length), index.valid.itemBytes);
  values.forEach(value => validateBundleItem(value, { semantic: false }));
  assert.deepEqual(Buffer.concat(values.map(value => encodeCanonical(value))), payload);
});

test('layer-two codec routes require an explicit semantic false selector', async () => {
  const metadata = await binary(join(VECTORS, 'objects/03-tree.cbor'));
  const bundle = await binary(join(VECTORS, 'logical-bundles/valid-supplied-closure.cborseq'));
  for (const invoke of [
    () => decodeMetadata(metadata),
    () => validateKnownSchema(decodeCanonical(metadata), 3),
    () => verifyLogicalBundle(bundle)
  ]) {
    assert.throws(invoke, error => error instanceof OgvcsError &&
      error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1 &&
      error.stage === 'configured-resource-preflight');
  }
  assert.equal(decodeMetadata(metadata, { semantic: false }).highestLayer, 2);
  assert.equal(verifyLogicalBundle(bundle, { semantic: false }).highestLayer, 2);
});

test('typed references have exact binary parsers and canonical text forms', () => {
  const digest = new Uint8Array(32).fill(0xab);
  const typed = Digest.fromMap(new Map([[0, 1], [1, digest]]));
  assert.deepEqual(Digest.fromMap(typed.toMap()).bytes, digest);

  const ref = new ObjectRef(3, digest);
  assert.equal(ObjectRef.parse(ref.toString()).toString(), ref.toString());
  expectCode(() => ObjectRef.parse(ref.toString().toUpperCase()), 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED');
  expectCode(() => ObjectRef.parse(`${ref} `), 'SCHEMA_FIELD_INVALID');
  expectCode(() => ObjectRef.parse(`${ref}`.replace('tree', 'raw-chunk')), 'OBJECT_KIND_UNSUPPORTED');
  expectCode(() => ObjectRef.parse(`${ref}`.slice(0, -1)), 'SCHEMA_FIELD_INVALID');
  expectCode(() => ObjectRef.parse(`${ref}`.replace(':v1:', ':v2:')), 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED');
  expectCode(() => ObjectRef.parse(`${ref}`.replace(':sha256:', ':sha512:')), 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED');
  expectCode(() => ObjectRef.parse(`ogvcs:${':'.repeat(1_000_000)}`), 'SCHEMA_FIELD_INVALID');
  assert.throws(() => new ObjectRef(42, digest, new Map([[42, 'evil']])), error =>
    error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1 &&
    error.stage === 'configured-resource-preflight');
  const unsupportedAlgorithm = ref.toMap();
  unsupportedAlgorithm.set(2, 2);
  expectCode(() => ObjectRef.fromMap(unsupportedAlgorithm), 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED');

  const profile = ProfileRef.parse('path.test/opaque@1');
  assert.equal(ProfileRef.fromMap(profile.toMap()).toString(), 'path.test/opaque@1');
  for (const bad of ['Path.test/opaque@1', 'path/opaque@1', 'path.test/opaque@01', 'path.test/opaque@0',
    'path.test/opaque@+1', `path.test/opaque@${'9'.repeat(100_000)}`, 'path.test/a--b@1']) {
    expectCode(() => ProfileRef.parse(bad), 'SCHEMA_FIELD_INVALID');
  }
  const fileId = FileId.parse(`fid:${'12'.repeat(16)}`);
  assert.equal(fileId.toString(), `fid:${'12'.repeat(16)}`);
  expectCode(() => FileId.parse(`fid:${'00'.repeat(16)}`), 'FILEID_ZERO');

  const digestView = typed.bytes;
  const referenceView = ref.digest;
  const fileIdView = fileId.bytes;
  digestView[0] = 0;
  referenceView[0] = 0;
  fileIdView[0] = 0;
  assert.equal(toHex(typed.bytes), 'ab'.repeat(32));
  assert.equal(ref.toString(), `ogvcs:v1:tree:sha256:${'ab'.repeat(32)}`);
  assert.equal(fileId.toString(), `fid:${'12'.repeat(16)}`);
});

test('identity codecs reject caller-forged assignment collections before hashing', () => {
  const digest = new Uint8Array(32).fill(0xab);
  const forgedKinds = new Map([[3, 'evil']]);
  assert.throws(() => ObjectRef.parse(`ogvcs:v1:evil:sha256:${'ab'.repeat(32)}`, forgedKinds), error =>
    error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1 &&
    error.stage === 'configured-resource-preflight');
  assert.throws(() => hashObject(3, encodeCanonical(new Map([[0, 1], [1, 3], [2, []]])), {
    registry: forgedKinds
  }), error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1);
  assert.throws(() => hashLogicalRecord(42, encodeCanonical(new Map([[0, 1], [1, 42]])), {
    registry: new Set([42])
  }), error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1);
  const partial = new RegistrySnapshot({
    objectKinds: [{ code: 42, name: 'evil', textToken: 'evil' }],
    logicalRecordTypes: [{ code: 42, name: 'evil' }]
  });
  assert.throws(() => hashObject(42, new Uint8Array(), { registry: partial.kindNames }), error =>
    error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1);
  assert.throws(() => hashLogicalRecord(42, new Uint8Array(), {
    registry: partial.logicalRecordTypeCodes
  }), error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1);
  assert.equal(new ObjectRef(3, digest).toString(), `ogvcs:v1:tree:sha256:${'ab'.repeat(32)}`);
});

test('unsupported required features remain scan/hash/forwardable but fail semantics', async () => {
  const live = await loadRegistryDirectory(join(SPEC, 'registries'));
  const payload = await binary(join(VECTORS, 'registries/unknown-required-feature.cbor'));
  const old = live;
  const documents = structuredClone(Object.fromEntries(live.documents));
  const [unknownFeature] = scanMetadata(payload).requiredFeatures;
  documents['required-features.json'].entries.push({
    behavior: 'no-op: preserve the registered base-kind semantics',
    code: unknownFeature,
    name: 'vector-required-feature',
    state: 'ratified'
  });
  documents['required-features.json'].unassigned = [
    ...(unknownFeature > 1 ? [{ from: 1, to: unknownFeature - 1 }] : []),
    { from: unknownFeature + 1, to: 0xffff_ffff }
  ];
  const newer = validateRegistrySet(documents);
  const scanned = scanMetadata(payload);
  assert.equal(scanned.highestLayer, 1);
  assert.deepEqual(scanned.payload, payload);
  expectCode(() => decodeMetadata(payload, { registry: old, operation: 'conformance' }), 'REQUIRED_FEATURE_UNSUPPORTED');
  assert.equal(decodeMetadata(payload, { registry: newer, operation: 'conformance' }).highestLayer, 3);
  const unknownKind = encodeCanonical(new Map([[0, 1], [1, 65535], [2, []], [16, true]]));
  const opaque = scanMetadata(unknownKind);
  assert.equal(opaque.kind, 65535); assert.equal(opaque.objectId, undefined);
  assert.equal(opaque.identityDigest.algorithm, 1); assert.equal(opaque.identityDigest.bytes.length, 32);
  expectCode(() => decodeMetadata(unknownKind, { registry: old, operation: 'conformance' }), 'OBJECT_KIND_UNSUPPORTED');
});

test('unknown canonical optional extensions are byte-preserved losslessly', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const payload = await binary(join(VECTORS, 'registries/unknown-optional-extension.cbor'));
  const decoded = decodeMetadata(payload, { registry, operation: 'conformance' });
  assert.equal(toHex(encodeCanonical(decoded.value)), toHex(payload));
  assert.equal(toHex(sha256Digest(payload).bytes), '3d3854b7a1584d4e07092c1e1d0c227f57fecdb75d5caa944dc3b91d9cb34122');
});

test('metadata encoding depth-preflights hostile extension values before schema traversal', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const payload = await binary(join(VECTORS, 'objects/06-repository-descriptor.cbor'));
  const value = decodeCanonical(payload);
  let nested = true;
  for (let depth = 0; depth < 20_000; depth += 1) nested = [nested];
  value.set(3, new Map([['extension.test/deep@1', nested]]));
  assert.throws(
    () => encodeMetadata(value, { registry, operation: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'LIMIT_NESTING' && error.layer === 1
  );
  for (const invalid of [[], true, 1, 'x', new Uint8Array([1])]) {
    assert.throws(
      () => encodeMetadata(invalid, { registry, operation: 'conformance' }),
      error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 2
    );
  }
});

test('framing forwards common-envelope schema defects until layer two', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const original = decodeCanonical(await binary(join(VECTORS, 'objects/06-repository-descriptor.cbor')));
  const cases = [
    [value => value.set(4, true), 'SCHEMA_FIELD_UNKNOWN'],
    [value => value.set(3, new Map([['invalid extension key', true]])), 'EXTENSION_KEY_INVALID'],
    [value => value.set(2, [2, 1]), 'SCHEMA_FIELD_INVALID']
  ];
  for (const [mutate, code] of cases) {
    const changed = new Map(original);
    mutate(changed);
    const payload = encodeCanonical(changed);
    assert.equal(scanMetadata(payload).highestLayer, 1, code);
    assert.throws(
      () => decodeMetadata(payload, { semantic: false }),
      error => error instanceof OgvcsError && error.code === code && error.layer === 2,
      code
    );
  }
});

test('framing enforces extension resource ceilings even for an unknown object kind', () => {
  for (const invalid of [true, new Map()]) {
    const payload = encodeCanonical(new Map([[0, 1], [1, 65_535], [2, []], [3, invalid], [16, true]]));
    assert.throws(() => scanMetadata(payload),
      error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1);
  }
  const extensions = new Map();
  for (let index = 0; index < 129; index++) {
    extensions.set(`extension.test/item-${String(index).padStart(3, '0')}@1`, true);
  }
  const count = encodeCanonical(new Map([[0, 1], [1, 65_535], [2, []], [3, extensions], [16, true]]));
  assert.throws(() => scanMetadata(count),
    error => error instanceof OgvcsError && error.code === 'LIMIT_COUNT' && error.layer === 1);

  const aggregate = encodeCanonical(new Map([
    [0, 1], [1, 65_535], [2, []],
    [3, new Map([
      ['extension.test/left@1', new Uint8Array(8_388_609)],
      ['extension.test/right@1', new Uint8Array(8_388_609)]
    ])],
    [16, true]
  ]));
  assert.throws(() => scanMetadata(aggregate),
    error => error instanceof OgvcsError && error.code === 'LIMIT_EXTENSION_BYTES' && error.layer === 1);
});

test('conformance profile rules run only at semantic layer three', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const snapshot = new Map(decodeCanonical(await binary(join(VECTORS, 'objects/07-snapshot.cbor'))));
  const policy = new Map(snapshot.get(26));
  policy.set(2, 2);
  snapshot.set(26, policy);
  const payload = encodeCanonical(snapshot);
  assert.equal(decodeMetadata(payload, { semantic: false }).highestLayer, 2);
  assert.throws(
    () => decodeMetadata(payload, { registry, operation: 'conformance' }),
    error => error instanceof OgvcsError && error.code === 'PROFILE_STATE_FORBIDDEN' &&
      error.layer === 3 && error.stage === 'registry-semantics'
  );
});

test('all current profile-family positives and negatives route through shape validation', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const index = await json(join(VECTORS, 'profiles/index.json'));
  const validateArtifact = async artifact => {
    const payload = await binary(join(VECTORS, artifact)); const value = decodeCanonical(payload);
    if (artifact.includes('bundle-root')) return validateBundleItem(value, {
      registry, operation: 'conformance'
    });
    if (artifact.includes('logical-records')) return validateLogicalRecord(value, {
      registry, operation: 'conformance'
    });
    return decodeMetadata(payload, { semantic: false });
  };
  for (const vector of index.validFamilyUses) await validateArtifact(vector.artifact);
  for (const artifact of ['profiles/fixture-descriptor.cbor', 'profiles/fixture-tree.cbor', 'profiles/fixture-group-set.cbor']) {
    const payload = await binary(join(VECTORS, artifact));
    assert.equal(decodeMetadata(payload, { semantic: false }).highestLayer, 2);
  }
  const annotationB = await binary(join(VECTORS, 'invariants/annotation-b.cbor'));
  assert.equal(validateLogicalRecord(decodeCanonical(annotationB), {
    registry, operation: 'conformance'
  }).type, 8);
  for (const vector of index.wrongFamilyUses) await assert.rejects(
    Promise.resolve().then(() => validateArtifact(vector.artifact)),
    error => error instanceof OgvcsError && error.code === vector.expected.code
  );
});

test('group members and external keys use their normative tuple comparators', async () => {
  const value = decodeCanonical(await binary(join(VECTORS, 'objects/05-asset-group-set.cbor')));
  const group = value.get(17)[0];
  const role = id => new Map([[0, 'group-role.test'], [1, id], [2, 1]]);
  const externalProfile = new Map([[0, 'external-key.test'], [1, 'opaque'], [2, 1]]);
  const firstMember = new Map([[0, new Uint8Array(16).fill(0xff)], [1, role('a')]]);
  const secondMember = new Map([[0, new Uint8Array(16).fill(1)], [1, role('b')]]);
  group.set(3, [firstMember, secondMember]);
  group.set(4, [
    new Map([[0, externalProfile], [1, Uint8Array.of(0, 0)]]),
    new Map([[0, externalProfile], [1, Uint8Array.of(0xff)]])
  ]);
  assert.equal(decodeMetadata(encodeCanonical(value), { semantic: false }).kind, 5);

  group.set(3, [secondMember, firstMember]);
  expectCode(() => decodeMetadata(encodeCanonical(value), { semantic: false }), 'SCHEMA_FIELD_INVALID');
  group.set(3, [firstMember, secondMember]);
  group.set(4, [...group.get(4)].reverse());
  expectCode(() => decodeMetadata(encodeCanonical(value), { semantic: false }), 'SCHEMA_FIELD_INVALID');
});

test('registry loading enforces canonical JSON and read/write state decisions', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  assert.equal(registry.objectKinds.size, 11);
  assert.equal(registry.hashAlgorithms.size, 1);
  assert.equal(registry.commonFields.size, 4);
  assert.ok(registry.kindFields.size > 300);
  assert.equal(registry.entryKinds.size, 4);
  assert.equal(registry.entryModes.size, 4);
  assert.equal(registry.documents.size, REGISTRY_FILES.length);
  assert.ok(registry.semanticEnums.has('operation'));
  assert.equal(registry.objectKinds.set, undefined);
  assert.throws(() => { registry.objectKinds.get(1).state = 'deprecated'; }, TypeError);
  assert.equal(registry.objectKinds.get(1).state, 'ratified');
  assert.throws(() => { registry.documents.get('object-kinds.json').entries[0].payload = 'changed'; }, TypeError);
  const oldDocument = await json(join(VECTORS, 'registries/old-snapshot.json'));
  const old = registryFromEvolutionSnapshot(oldDocument);
  assert.equal(profileDecision(old, 'profile-state.test/ratified@1', 'production-write').state, 'ratified');
  assert.equal(profileDecision(old, 'profile-state.test/deprecated@1', 'read').state, 'deprecated');
  assert.equal(profileDecision(old, 'profile-state.test/deprecated@1', 'conformance').state, 'deprecated');
  assert.equal(profileDecision(old, 'profile-state.test/conformance@1', 'conformance').state, 'conformance-only');
  expectCode(() => profileDecision(old, 'profile-state.test/reserved@1', 'read'), 'PROFILE_STATE_FORBIDDEN');
  expectCode(() => profileDecision(old, 'profile-state.test/deprecated@1', 'production-write'), 'PROFILE_STATE_FORBIDDEN');
  expectCode(() => profileDecision(old, 'profile-state.test/conformance@1', 'production-write'), 'PROFILE_CONFORMANCE_ONLY');
  expectCode(() => profileDecision(old, 'profile-state.test/conformance@1', 'read'), 'PROFILE_CONFORMANCE_ONLY');
  expectCode(() => profileDecision(old, 'profile-state.test/unknown@1', 'read'), 'PROFILE_UNKNOWN');
  expectCode(() => profileDecision(old, 'profile-state.test/ratified@1', 'invalid-operation'), 'SCHEMA_FIELD_INVALID');
  expectCode(() => parseCanonicalRegistryJson('{"b":1,"a":2}\n'), 'REGISTRY_INVALID');
  expectCode(() => parseCanonicalRegistryJson('{"a":1,"a":1}\n'), 'REGISTRY_INVALID');
  expectCode(() => parseCanonicalRegistryJson(Buffer.from('\ufeff{}\n')), 'REGISTRY_INVALID');
  expectCode(() => parseCanonicalRegistryJson(`${'{"a":'.repeat(1_000)}0${'}'.repeat(1_000)}\n`),
    'REGISTRY_INVALID');
});

test('registry files bind exact authorities and nonempty coded-entry names', async () => {
  const docs = Object.fromEntries(await Promise.all(REGISTRY_FILES.map(async file =>
    [file, await json(join(SPEC, 'registries', file))])));
  assert.equal(validateRegistrySet(docs).objectKinds.size, 11);

  const relabelled = structuredClone(docs);
  relabelled['object-kinds.json'].registry = 'ogvcs.repository-format.profiles';
  expectCode(() => validateRegistrySet(relabelled), 'REGISTRY_INVALID');

  const unnamed = structuredClone(docs);
  unnamed['hash-algorithms.json'].entries[0].name = '';
  expectCode(() => validateRegistrySet(unnamed), 'REGISTRY_INVALID');

  const reassigned = structuredClone(docs);
  reassigned['object-kinds.json'].entries[0].payload = 'deterministic-cbor';
  expectCode(() => validateRegistrySet(reassigned), 'REGISTRY_INVALID');

  const removed = structuredClone(docs);
  removed['logical-record-types.json'].entries.shift();
  expectCode(() => validateRegistrySet(removed), 'REGISTRY_INVALID');

  const deprecated = structuredClone(docs);
  deprecated['object-kinds.json'].entries[0].state = 'deprecated';
  assert.equal(validateRegistrySet(deprecated).objectKinds.get(1).state, 'deprecated');

  const limitWithoutCode = structuredClone(docs);
  limitWithoutCode['limits.json'].entries.push({ name: 'zzz', unit: 'bytes', value: 1 });
  expectCode(() => validateRegistrySet(limitWithoutCode), 'REGISTRY_INVALID');

  const excessiveRanges = structuredClone(docs);
  excessiveRanges['object-kinds.json'].unassigned = Array.from({ length: 130_000 }, (_, index) => ({
    from: 12 + index * 2,
    to: 12 + index * 2
  }));
  expectCode(() => validateRegistrySet(excessiveRanges), 'REGISTRY_INVALID');

  for (const [file, entry] of [
    ['object-kinds.json', { code: 12, name: 'new-kind', state: 'ratified', textToken: 'new-kind' }],
    ['hash-algorithms.json', { code: 2, name: 'sha-next', state: 'ratified' }],
    ['logical-record-types.json', { code: 10, name: 'new-record', state: 'ratified' }]
  ]) {
    const malformed = structuredClone(docs);
    malformed[file].entries.push(entry);
    malformed[file].unassigned[0].from = entry.code + 1;
    expectCode(() => validateRegistrySet(malformed), 'REGISTRY_INVALID');
  }

  const additive = structuredClone(docs);
  additive['required-features.json'].entries.push({
    behavior: 'validate the unchanged registered base kind semantics', code: 1,
    name: 'additive-feature', state: 'ratified'
  });
  additive['required-features.json'].unassigned[0].from = 2;
  assert.equal(validateRegistrySet(additive).requiredFeatures.get(1).name, 'additive-feature');
});

test('the packaged registry snapshot is complete and has the normative fingerprint', async () => {
  const bundled = await loadRegistryDirectory(bundledRegistryDirectory());
  assert.equal(bundled.objectKinds.size, 11);
  assert.equal(await registrySetDigest(bundledRegistryDirectory()), '6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6');
});

test('tree basenames and opaque pending identifiers reject forbidden zero/dot forms', async () => {
  const tree = decodeCanonical(await binary(join(VECTORS, 'objects/03-tree.cbor')));
  tree.get(17)[0].set(0, '.');
  expectCode(() => decodeMetadata(encodeCanonical(tree), { semantic: false }), 'PATH_CORE_INVALID');
  tree.get(17)[0].set(0, '\0');
  expectCode(() => decodeMetadata(encodeCanonical(tree), { semantic: false }), 'PATH_CORE_INVALID');

  const pending = decodeCanonical(await binary(join(VECTORS, 'logical-records/06-pending-change-reference.cbor')));
  pending.set(17, new Uint8Array(16));
  expectCode(() => validateLogicalRecord(pending, { semantic: false }), 'SCHEMA_FIELD_INVALID');
});

test('single-bit changes never preserve the original object identity', async () => {
  const index = await json(join(VECTORS, 'objects/index.json'));
  for (const vector of index.objects) {
    const original = new Uint8Array(await binary(join(VECTORS, vector.payloadPath)));
    if (original.length === 0) continue;
    for (let byte = 0; byte < original.length; byte++) {
      for (let bit = 0; bit < 8; bit++) {
        const changed = original.slice(); changed[byte] ^= 1 << bit;
        try {
          assert.notEqual(toHex(hashObject(vector.kind, changed).digest), vector.objectId);
        } catch (error) {
          assert.ok(error instanceof OgvcsError, `unexpected mutation error for ${vector.name} byte ${byte} bit ${bit}`);
        }
      }
    }
  }
});

test('FileID allocation uses injected entropy, retries zero/collisions, and exhausts', async () => {
  const zero = new Uint8Array(16); const collision = new Uint8Array(16).fill(1); const winner = new Uint8Array(16).fill(2);
  const candidates = [zero, collision, winner]; let calls = 0;
  const allocated = await allocateFileId({ entropy: () => candidates[calls++], isConsumed: value => value[0] === 1, maxAttempts: 3 });
  assert.equal(allocated.toString(), `fid:${'02'.repeat(16)}`); assert.equal(calls, 3);
  await assert.rejects(allocateFileId({ entropy: () => collision, isConsumed: () => true, maxAttempts: 2 }),
    error => error.code === 'FILEID_ALLOCATION_EXHAUSTED' && error.layer === 3);
  await assert.rejects(allocateFileId({ entropy: () => { throw new Error('unavailable'); } }),
    error => error.code === 'FILEID_ENTROPY_UNAVAILABLE' && error.layer === 3);
  await assert.rejects(allocateFileId({ entropy: () => { const error = new Error('device'); error.code = 'EIO'; throw error; } }),
    error => error instanceof OgvcsError && error.code === 'FILEID_ENTROPY_UNAVAILABLE' && error.layer === 3);
  await assert.rejects(allocateFileId({ entropy: () => new Uint8Array(15) }),
    error => error instanceof OgvcsError && error.code === 'FILEID_ENTROPY_UNAVAILABLE' && error.layer === 3);
  await assert.rejects(allocateFileId({ maxAttempts: 0 }), error => error.code === 'SCHEMA_FIELD_INVALID');
  await assert.rejects(allocateFileId({ maxAttempts: MAX_FILE_ID_ALLOCATION_ATTEMPTS + 1 }), error => error.code === 'SCHEMA_FIELD_INVALID');
  const native = await allocateFileId(); assert.equal(native.bytes.length, 16); assert.ok(native.bytes.some(byte => byte));
});

test('configured framing limits only reduce accepted work', () => {
  const text = encodeCanonical('1234');
  expectCode(() => decodeCanonical(text, { maxValueBytes: 3 }), 'LIMIT_VALUE_BYTES');
  const nested = encodeCanonical([[[[true]]]]);
  expectCode(() => decodeCanonical(nested, { maxDepth: 3 }), 'LIMIT_NESTING');
  let boundary = true;
  for (let depth = 0; depth < 32; depth++) boundary = [boundary];
  assert.deepEqual(decodeCanonical(encodeCanonical(boundary)), boundary);
  const depth33 = [boundary];
  expectCode(() => decodeCanonical(encodeCanonical(depth33, { maxDepth: 99 }), { maxDepth: 99 }), 'LIMIT_NESTING');
  const count = encodeCanonical([1, 2, 3]);
  expectCode(() => decodeCanonical(count, { maxContainerItems: 2 }), 'LIMIT_COUNT');
  expectCode(() => decodeCanonical(count, { maxBytes: 3 }), 'LIMIT_METADATA_BYTES');
  expectCode(() => scanMetadata(count, { maxContainerItems: 0 }), 'LIMIT_COUNT');
  expectCode(() => scanMetadata(encodeCanonical(new Map([[0, 1], [1, 65_535], [2, []]])), { maxWorkingBytes: 1 }), 'LIMIT_MEMORY');
  expectCode(() => hashObject(1, new Uint8Array(5), { maxChunkBytes: 4 }), 'LIMIT_CHUNK_BYTES');
  expectCode(() => encodeCanonical('\ud800'), 'CBOR_NON_CANONICAL');
  expectCode(() => encodeCanonical(new Map([[0, ['safe', '\ud800']]])), 'CBOR_NON_CANONICAL');
  expectCode(() => encodeCanonical([1, 2, 3], { maxContainerItems: 2 }), 'LIMIT_COUNT');
  const largeValue = encodeCanonical(new Uint8Array(1_000_001));
  assert.equal(decodeCanonical(largeValue).length, 1_000_001);

  const manifestBoundary = 1_048_576;
  const boundaryArray = new Uint8Array(5 + manifestBoundary);
  boundaryArray[0] = 0x9a;
  new DataView(boundaryArray.buffer).setUint32(1, manifestBoundary);
  boundaryArray.fill(0xf4, 5);
  assert.equal(decodeCanonical(boundaryArray).length, manifestBoundary);

  const oversizedFirstItem = new Uint8Array(27);
  oversizedFirstItem.set([0x58, 0x18]);
  expectCode(() => decodeFirst(oversizedFirstItem, { maxBytes: 3 }), 'LIMIT_METADATA_BYTES');

  const aboveHardContainer = Uint8Array.of(0x9a, 0x00, 0x10, 0x00, 0x01);
  expectCode(() => decodeCanonical(aboveHardContainer, { maxContainerItems: 2_000_000 }), 'LIMIT_COUNT');
});
