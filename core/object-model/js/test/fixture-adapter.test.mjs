import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createRequest, generateFixture, verifyFixture } from '@opengamevcs/fixture-generator';
import { encodeLogicalBundle, verifyLogicalBundle } from '../src/bundle.js';
import { OgvcsError } from '../src/errors.js';
import { adaptFixture, prepareFixtureAdapterLedger } from '../src/fixture-adapter.js';
import { loadBundledRegistry } from '../src/registry.js';

const PROFILES = ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio'];
const TARGET_EMPTY = async () => false;

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-object-adapter-'));
  t.after(() => rm(directory, { force: true, maxRetries: process.platform === 'win32' ? 10 : 0, recursive: true, retryDelay: 100 }));
  return directory;
}

function request(profile, destination, overrides = {}) {
  return createRequest({
    destination,
    extensions: {
      'generation.large-file-mode': overrides.largeFileMode ?? (profile === 'large-binary' ? 'full' : 'virtual'),
      'generation.materialization': overrides.materialization ?? 'full'
    },
    ...(profile === 'unity-like' ? { featureFlags: { 'negative-cases': overrides.negativeCases ?? false } } : {}),
    profile: { id: profile, version: '2.0.0' },
    scale: {
      historyOperationCount: overrides.historyOperationCount ?? 8,
      largeFileBytes: overrides.largeFileBytes ?? (profile === 'large-binary' ? 1024 * 1024 : 0),
      maxDepth: 5,
      pathCount: overrides.pathCount ?? 6
    },
    seed: overrides.seed ?? `object-adapter-${profile}`
  });
}

function objectFingerprint(result) {
  return result.objects.map(item => `${item.ref}:${Buffer.from(item.payload).toString('hex')}`);
}

test('public adapter maps all five profile-v2 fixtures and retries byte-identically', async (t) => {
  const cwd = await temporaryDirectory(t);
  const registry = await loadBundledRegistry();
  for (const profile of PROFILES) {
    const destination = `fixtures/${profile}`;
    await generateFixture(request(profile, destination), { cwd });
    let ledger;
    const first = await adaptFixture(destination, {
      cwd,
      ...(profile === 'large-binary' ? { largeFileVersion: 2 } : {}),
      isTargetFileIdConsumed: TARGET_EMPTY,
      persistLedger: async value => { ledger = value; },
      registry
    });
    assert.ok(ledger, `${profile}: ledger was not persisted before adaptation`);
    assert.deepEqual(Object.keys(ledger).sort(), ['directoryIds', 'fileIds', 'groupIds', 'importMappings',
      'repositoryId', 'requestDigest', 'revisionSnapshots', 'schemaVersion']);
    assert.equal(Object.keys(ledger.importMappings).length, 6);
    assert.deepEqual(ledger.revisionSnapshots, {});
    assert.equal(first.summary.fixtureProfile, `${profile}@2.0.0`);
    assert.equal(first.summary.files, 6);
    assert.equal(first.summary.logicalRecords, 8);
    assert.equal(first.logicalRecords.length, 8);
    assert.equal(first.roots.filter(root => root.kind === 2).length, 8);

    const bundle = encodeLogicalBundle({ objects: first.objects, logicalRecords: first.logicalRecords, roots: first.roots }, { registry });
    const verification = verifyLogicalBundle(bundle, { registry });
    assert.equal(verification.highestLayer, 2);
    assert.equal(verification.objectCount, first.objects.length);
    assert.equal(verification.logicalRecordCount, 8);

    let persistedAgain = false;
    const retry = await adaptFixture(destination, {
      cwd,
      ledger,
      ...(profile === 'large-binary' ? { largeFileVersion: 2 } : {}),
      isTargetFileIdConsumed: TARGET_EMPTY,
      persistLedger: async () => { persistedAgain = true; },
      registry
    });
    assert.equal(persistedAgain, false, `${profile}: complete ledger was unexpectedly rewritten`);
    assert.equal(retry.rootTree.toString(), first.rootTree.toString());
    assert.equal(retry.groupSet?.toString(), first.groupSet?.toString());
    assert.deepEqual(objectFingerprint(retry), objectFingerprint(first));
  }
});

test('adapter fails closed for an unpersisted ledger and unavailable content', async (t) => {
  const cwd = await temporaryDirectory(t);
  await generateFixture(request('code-heavy', 'full'), { cwd });
  await assert.rejects(adaptFixture('full', { cwd }), error => error instanceof OgvcsError && error.code === 'FIXTURE_MAPPING_MISSING');

  let ledger;
  await adaptFixture('full', { cwd, isTargetFileIdConsumed: TARGET_EMPTY, persistLedger: async value => { ledger = value; } });
  await generateFixture(request('code-heavy', 'index-only', { materialization: 'index-only' }), { cwd });
  let indexLedger;
  await assert.rejects(adaptFixture('index-only', {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    persistLedger: async value => { indexLedger = value; }
  }), error => error instanceof OgvcsError && error.code === 'FIXTURE_CONTENT_UNAVAILABLE');
  assert.ok(indexLedger);
  assert.ok(ledger);
});

test('adapter refuses to reinterpret profile-v2 workload events as native history', async (t) => {
  const cwd = await temporaryDirectory(t);
  await generateFixture(request('code-heavy', 'events-only'), { cwd });
  let persisted = false;
  await assert.rejects(adaptFixture('events-only', {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    persistLedger: async () => { persisted = true; },
    requireNativeHistoryBindings: true
  }), error => error instanceof OgvcsError &&
    error.code === 'FIXTURE_NATIVE_BINDING_MISSING' && error.layer === 3);
  assert.equal(persisted, false, 'native-history preflight must run before ledger persistence');
  await assert.rejects(adaptFixture('events-only', {
    cwd,
    requireNativeHistoryBindings: 'yes'
  }), error => error instanceof OgvcsError && error.code === 'SCHEMA_FIELD_INVALID' && error.layer === 2);
});

test('adapter preserves declared Unity negative cases as normative group failures', async (t) => {
  const cwd = await temporaryDirectory(t);
  await generateFixture(request('unity-like', 'negative', { negativeCases: true, pathCount: 16 }), { cwd });
  let ledger;
  await assert.rejects(adaptFixture('negative', {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    persistLedger: async value => { ledger = value; }
  }), error => error instanceof OgvcsError && ['GROUP_REQUIRED_ROLE_MISSING', 'GROUP_EXTERNAL_KEY_DUPLICATE'].includes(error.code));
  assert.ok(ledger);
});

test('adapter enforces every aggregate input, state, output, and time ceiling before unbounded retention', async (t) => {
  const cwd = await temporaryDirectory(t);
  await generateFixture(request('unity-like', 'bounded', { pathCount: 6 }), { cwd });
  const cases = [
    ['inputBytes', 0, 'LIMIT_MEMORY'],
    ['inventoryRecords', 5, 'LIMIT_COUNT'],
    ['operationRecords', 7, 'LIMIT_COUNT'],
    ['groups', 0, 'LIMIT_COUNT'],
    ['mappings', 1, 'LIMIT_COUNT'],
    ['objects', 1, 'LIMIT_COUNT'],
    ['manifestParts', 0, 'LIMIT_COUNT'],
    ['treeNodes', 1, 'LIMIT_COUNT'],
    ['durationMilliseconds', 0, 'LIMIT_TIME']
  ];
  for (const [name, value, code] of cases) {
    await assert.rejects(adaptFixture('bounded', {
      cwd,
      isTargetFileIdConsumed: TARGET_EMPTY,
      limits: { [name]: value },
      persistLedger: async () => {}
    }), error => error instanceof OgvcsError && error.code === code, name);
  }
  await assert.rejects(adaptFixture('bounded', {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    maxRetainedBytes: 0,
    persistLedger: async () => {}
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_MEMORY');

  let verifierCalled = false;
  await assert.rejects(adaptFixture('bounded', {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    limits: { inventoryRecords: 5 },
    verifyFixture: async () => { verifierCalled = true; throw new Error('must not run'); },
    persistLedger: async () => {}
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_COUNT');
  assert.equal(verifierCalled, false, 'adapter request limits must preflight before the external deep verifier');
});

test('adapter deadline aborts a non-settling external boundary with LIMIT_TIME', async t => {
  const cwd = await temporaryDirectory(t);
  await generateFixture(request('code-heavy', 'deadline'), { cwd });
  let signal;
  const started = Date.now();
  await assert.rejects(adaptFixture('deadline', {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    limits: { durationMilliseconds: 100 },
    persistLedger: async () => {},
    verifyFixture: async (_destination, options) => {
      signal = options.signal;
      await new Promise(() => {});
    }
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_TIME' && error.layer === 1);
  assert.ok(signal instanceof AbortSignal);
  assert.equal(signal.aborted, true);
  assert.ok(Date.now() - started < 2_000, 'deadline did not bound the callback wait');
});

test('adapter deadline bounds injected filesystem opens and propagates its signal', async () => {
  let signal;
  await assert.rejects(adaptFixture('never-opened', {
    fileSystem: {
      createReadStream() { throw new Error('must not create a stream'); },
      open(_path, _flags, options) {
        signal = options.signal;
        return new Promise(() => {});
      }
    },
    limits: { durationMilliseconds: 25 }
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_TIME' &&
    error.layer === 1 && error.stage === 'configured-resource-preflight');
  assert.ok(signal instanceof AbortSignal);
  assert.equal(signal.aborted, true);
});

test('public ledger preparation count-preflights repeated hostile collections', async () => {
  let inventoryRead = false;
  const inventory = { get fileId() { inventoryRead = true; throw new Error('unread'); }, logicalPath: 'x' };
  await assert.rejects(prepareFixtureAdapterLedger({
    manifest: { requestDigest: '41'.repeat(32) }, inventory: [inventory, inventory], groups: []
  }, {
    limits: { inventoryRecords: 1 }
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_COUNT' &&
    error.stage === 'configured-resource-preflight');
  assert.equal(inventoryRead, false);

  let groupRead = false;
  const group = { get id() { groupRead = true; throw new Error('unread'); } };
  await assert.rejects(prepareFixtureAdapterLedger({
    manifest: { requestDigest: '41'.repeat(32) }, inventory: [], groups: [group, group]
  }, {
    limits: { groups: 1 }
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_COUNT');
  assert.equal(groupRead, false);
});

test('public ledger preparation bounds portable paths before prefix construction', async () => {
  for (const logicalPath of [
    `${new Array(257).fill('a').join('/')}.bin`,
    `${new Array(20).fill('a'.repeat(220)).join('/')}.bin`
  ]) {
    await assert.rejects(prepareFixtureAdapterLedger({
      manifest: { requestDigest: '41'.repeat(32) },
      inventory: [{ fileId: '31'.repeat(16), logicalPath }],
      groups: []
    }), error => error instanceof OgvcsError && error.code === 'FIXTURE_SEMANTIC_INVALID');
  }
});

test('ledger mapping values are shallow-validated before structured cloning', async () => {
  let nested = { value: 'not-a-file-id' };
  for (let depth = 0; depth < 1_000; depth += 1) nested = { nested };
  await assert.rejects(prepareFixtureAdapterLedger({
    manifest: { requestDigest: '41'.repeat(32) }, inventory: [], groups: []
  }, {
    ledger: {
      schemaVersion: 'ogvcs.fixture-adapter/ledger/v1',
      requestDigest: '41'.repeat(32),
      repositoryId: '51'.repeat(16),
      directoryIds: { asset: nested },
      fileIds: {}, groupIds: {}, revisionSnapshots: {}, importMappings: {}
    }
  }), error => error instanceof OgvcsError && error.code === 'FIXTURE_MAPPING_MISSING');
});

test('adapter binds the exact groups bytes it consumes to the verified manifest', async (t) => {
  const cwd = await temporaryDirectory(t);
  const destination = 'bound-inputs';
  await generateFixture(request('unity-like', destination), { cwd });
  let mutated = false;
  await assert.rejects(adaptFixture(destination, {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    persistLedger: async () => {},
    verifyFixture: async (name, options) => {
      const result = await verifyFixture(name, options);
      if (!mutated) {
        const groupsPath = join(cwd, destination, 'groups.json');
        const groups = JSON.parse(await readFile(groupsPath, 'utf8'));
        groups.push({ id: 'swapped-after-verification' });
        await writeFile(groupsPath, `${JSON.stringify(groups)}\n`);
        mutated = true;
      }
      return result;
    }
  }), error => error instanceof OgvcsError && error.code === 'FIXTURE_SCHEMA_UNSUPPORTED');
  assert.equal(mutated, true);
});

test('post-verifier deeply nested groups fail with a typed adapter error', async t => {
  const cwd = await temporaryDirectory(t);
  const destination = 'deep-groups';
  await generateFixture(request('unity-like', destination), { cwd });
  await assert.rejects(adaptFixture(destination, {
    cwd,
    isTargetFileIdConsumed: TARGET_EMPTY,
    persistLedger: async () => {},
    verifyFixture: async (name, options) => {
      const result = await verifyFixture(name, options);
      let nested = true;
      for (let depth = 0; depth < 512; depth += 1) nested = [nested];
      const groupsPath = join(cwd, destination, 'groups.json');
      await writeFile(groupsPath, JSON.stringify([{ id: 'deep', nested }]));
      return result;
    }
  }), error => error instanceof OgvcsError && error.code === 'FIXTURE_SEMANTIC_INVALID');
});

test('adapter allocation retries zero and an already-ledgered FileID before persisting a fresh ID', async () => {
  const existing = '21'.repeat(16);
  const fresh = '22'.repeat(16);
  const requestedSource = '31'.repeat(16);
  const existingSource = '32'.repeat(16);
  const candidates = [new Uint8Array(16), Uint8Array.from({ length: 16 }, () => 0x21),
    Uint8Array.from({ length: 16 }, () => 0x22)];
  let calls = 0;
  let persisted;
  const result = await prepareFixtureAdapterLedger({
    manifest: { requestDigest: '41'.repeat(32) },
    inventory: [{ fileId: requestedSource, logicalPath: 'asset.bin' }],
    groups: []
  }, {
    allocationEntropy: async () => candidates[calls++],
    isTargetFileIdConsumed: TARGET_EMPTY,
    ledger: {
      schemaVersion: 'ogvcs.fixture-adapter/ledger/v1',
      requestDigest: '41'.repeat(32),
      repositoryId: '51'.repeat(16),
      directoryIds: {},
      fileIds: { [existingSource]: existing },
      groupIds: {},
      revisionSnapshots: {},
      importMappings: {}
    },
    persistLedger: async value => { persisted = value; }
  });
  assert.equal(calls, 3);
  assert.equal(result.ledger.fileIds[requestedSource], fresh);
  assert.equal(persisted.fileIds[requestedSource], fresh);
});

test('adapter retries a GroupID candidate already present in the ledger', async () => {
  const existing = '21'.repeat(16);
  const fresh = '22'.repeat(16);
  const requestedSource = '31'.repeat(16);
  const existingSource = '32'.repeat(16);
  const candidates = [
    Uint8Array.from({ length: 16 }, () => 0x21),
    Uint8Array.from({ length: 16 }, () => 0x22)
  ];
  let calls = 0;
  const result = await prepareFixtureAdapterLedger({
    manifest: { requestDigest: '41'.repeat(32) },
    inventory: [],
    groups: [{ id: requestedSource }, { id: existingSource }]
  }, {
    allocationEntropy: async () => candidates[calls++],
    isTargetFileIdConsumed: TARGET_EMPTY,
    ledger: {
      schemaVersion: 'ogvcs.fixture-adapter/ledger/v1',
      requestDigest: '41'.repeat(32),
      repositoryId: '51'.repeat(16),
      directoryIds: {},
      fileIds: {},
      groupIds: { [existingSource]: existing },
      revisionSnapshots: {},
      importMappings: {}
    },
    persistLedger: async () => {}
  });
  assert.equal(calls, 2);
  assert.equal(result.ledger.groupIds[requestedSource], fresh);
  assert.notEqual(result.ledger.groupIds[requestedSource], result.ledger.groupIds[existingSource]);
});

test('adapter rejects target-repository FileID consumption before ledger persistence', async () => {
  const requestedSource = '31'.repeat(16);
  const candidate = '44'.repeat(16);
  const ledger = {
    schemaVersion: 'ogvcs.fixture-adapter/ledger/v1',
    requestDigest: '41'.repeat(32),
    repositoryId: '51'.repeat(16),
    directoryIds: {},
    fileIds: {},
    groupIds: {},
    revisionSnapshots: {},
    importMappings: {}
  };
  const original = structuredClone(ledger);
  let persisted = false;
  await assert.rejects(prepareFixtureAdapterLedger({
    manifest: { requestDigest: ledger.requestDigest },
    inventory: [{ fileId: requestedSource, logicalPath: 'asset.bin' }],
    groups: []
  }, {
    allocateId: async () => candidate,
    isTargetFileIdConsumed: async ({ fileId, ownerKind, ownerKey }) => {
      assert.equal(fileId, `fid:${candidate}`);
      assert.equal(ownerKind, 'import');
      assert.equal(ownerKey, `${ledger.requestDigest}:${requestedSource}`);
      return true;
    },
    ledger,
    persistLedger: async () => { persisted = true; }
  }), error => error instanceof OgvcsError && error.code === 'FILEID_IMPORT_MAPPING_CONFLICT' && error.layer === 3);
  assert.equal(persisted, false);
  assert.deepEqual(ledger, original);
});

test('adapter preserves hostile-but-valid mapping keys as own properties across retry', async () => {
  const requestDigest = '41'.repeat(32);
  const source = '31'.repeat(16);
  let allocation = 0;
  let persisted;
  const result = await prepareFixtureAdapterLedger({
    manifest: { requestDigest },
    inventory: [{ fileId: source, logicalPath: '__proto__/constructor/toString.bin' }],
    groups: [{ id: '__proto__' }, { id: 'constructor' }, { id: 'toString' }]
  }, {
    allocateId: async () => (++allocation).toString(16).padStart(32, '0'),
    isTargetFileIdConsumed: TARGET_EMPTY,
    ledger: {
      schemaVersion: 'ogvcs.fixture-adapter/ledger/v1',
      requestDigest,
      repositoryId: '51'.repeat(16),
      directoryIds: {},
      fileIds: {},
      groupIds: {},
      revisionSnapshots: {},
      importMappings: {}
    },
    persistLedger: async value => { persisted = value; }
  });

  assert.equal(allocation, 6);
  for (const key of ['__proto__', '__proto__/constructor']) {
    assert.equal(Object.hasOwn(result.ledger.directoryIds, key), true, key);
    assert.equal(typeof result.ledger.directoryIds[key], 'string');
  }
  for (const key of ['__proto__', 'constructor', 'toString']) {
    assert.equal(Object.hasOwn(result.ledger.groupIds, key), true, key);
    assert.equal(typeof result.ledger.groupIds[key], 'string');
  }
  assert.ok(persisted);

  let persistedAgain = false;
  const retry = await prepareFixtureAdapterLedger({
    manifest: { requestDigest },
    inventory: [{ fileId: source, logicalPath: '__proto__/constructor/toString.bin' }],
    groups: [{ id: '__proto__' }, { id: 'constructor' }, { id: 'toString' }]
  }, {
    allocateId: async () => { throw new Error('complete ledger must not allocate'); },
    isTargetFileIdConsumed: TARGET_EMPTY,
    ledger: persisted,
    persistLedger: async () => { persistedAgain = true; }
  });
  assert.equal(retry.changed, false);
  assert.equal(persistedAgain, false);
  assert.deepEqual(retry.ledger, persisted);
});
