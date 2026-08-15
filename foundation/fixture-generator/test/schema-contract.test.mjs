import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { checkpointDocument, createChains } from '../src/checkpoint.mjs';
import {
  createRequest,
  generateFixture,
  getProfile,
  listProfiles,
  verifyFixture,
} from '../src/index.mjs';
import {
  assertSchemaDocument,
  validateSchemaDocument,
} from '../src/schema-validator.mjs';
import { temporaryDirectory } from './test-helpers.mjs';

function mutable(value) {
  return JSON.parse(JSON.stringify(value));
}

function schemaRejects(name, value, pattern) {
  const issues = validateSchemaDocument(name, value);
  assert.ok(issues.length > 0, `${name} unexpectedly accepted an invalid document`);
  if (pattern) assert.match(issues.map(({ path: issuePath }) => issuePath).join('\n'), pattern);
}

test('cross-schema references resolve by standards-compliant absolute schema IDs', async () => {
  const manifestSchema = JSON.parse(await readFile(
    new URL('../schemas/FixtureManifest.schema.json', import.meta.url),
    'utf8',
  ));
  const groupSchema = JSON.parse(await readFile(
    new URL('../schemas/GroupRelationships.schema.json', import.meta.url),
    'utf8',
  ));
  assert.equal(
    new URL(manifestSchema.properties.groups.$ref, manifestSchema.$id).href,
    groupSchema.$id,
  );
});

test('canonical requests and profile-dependent flags are bidirectionally closed', () => {
  const profiles = listProfiles();
  assert.equal(profiles.length, 5);
  for (const { id, version } of profiles) {
    assert.equal(version, '2.0.0');
    const request = createRequest({
      destination: `fixtures/${id}`,
      extensions: {
        'generation.large-file-mode': 'virtual',
        'generation.materialization': 'index-only',
      },
      profile: { id, version },
      scale: { historyOperationCount: 3, largeFileBytes: 0, maxDepth: 3, pathCount: 4 },
      seed: `schema-contract-${id}`,
    });
    assert.deepEqual(validateSchemaDocument('FixtureRequest', request), []);
    assert.deepEqual(createRequest(request), request, `${id} schema-valid request was not accepted by runtime`);
    assert.deepEqual(validateSchemaDocument('WorkloadProfile', getProfile(id, version)), []);
  }

  const codeRequest = mutable(createRequest({
    destination: 'fixtures/code',
    profile: { id: 'code-heavy', version: '2.0.0' },
    scale: { historyOperationCount: 1, largeFileBytes: 0, maxDepth: 2, pathCount: 1 },
  }));
  codeRequest.featureFlags.maps = true;
  schemaRejects('FixtureRequest', codeRequest, /featureFlags\.maps/u);
  assert.throws(() => createRequest(codeRequest), /featureFlags.*maps|unknown field/iu);

  const codeWithUnityNegativeCases = mutable(createRequest({
    destination: 'fixtures/code-negative-cases',
    profile: { id: 'code-heavy', version: '2.0.0' },
    scale: { historyOperationCount: 1, largeFileBytes: 0, maxDepth: 2, pathCount: 1 },
  }));
  codeWithUnityNegativeCases.featureFlags['negative-cases'] = true;
  schemaRejects('FixtureRequest', codeWithUnityNegativeCases, /featureFlags\.negative-cases/u);
  assert.throws(() => createRequest(codeWithUnityNegativeCases), /featureFlags.*negative-cases|unknown field/iu);

  const unityRequest = createRequest({
    destination: 'fixtures/unity-negative-cases',
    featureFlags: { 'negative-cases': false },
    profile: { id: 'unity-like', version: '2.0.0' },
    scale: { historyOperationCount: 1, largeFileBytes: 0, maxDepth: 2, pathCount: 1 },
  });
  assert.equal(unityRequest.featureFlags['negative-cases'], false);
  assert.deepEqual(validateSchemaDocument('FixtureRequest', unityRequest), []);

  const unrealRequest = mutable(createRequest({
    destination: 'fixtures/unreal',
    profile: { id: 'unreal-like', version: '2.0.0' },
    scale: { historyOperationCount: 1, largeFileBytes: 0, maxDepth: 2, pathCount: 1 },
  }));
  unrealRequest.featureFlags.executables = true;
  schemaRejects('FixtureRequest', unrealRequest, /featureFlags\.executables/u);
  assert.throws(() => createRequest(unrealRequest), /featureFlags.*executables|unknown field/iu);
});

test('request schema and runtime enforce the same version, bound, extension, seed, and destination edges', () => {
  const boundary = createRequest({
    destination: 'fixtures/boundary',
    profile: { id: 'code-heavy', version: '2.0.0' },
    resourceLimits: { maximumPhysicalBytes: 42 },
    scale: {
      historyOperationCount: 10_000_000,
      largeFileBytes: 1_099_511_627_776,
      maxDepth: 64,
      pathCount: 10_000_000,
    },
    seed: 'NFC-Caf\u00e9',
  });
  assert.deepEqual(validateSchemaDocument('FixtureRequest', boundary), []);
  assert.equal(boundary.resourceLimits.maximumPhysicalBytes, 42);

  const mutations = [
    ['profile.version', (document) => { document.profile.version = '1.0.0'; }],
    ['scale.maxDepth minimum', (document) => { document.scale.maxDepth = 1; }],
    ['scale.maxDepth', (document) => { document.scale.maxDepth = 65; }],
    ['scale.historyOperationCount', (document) => { document.scale.historyOperationCount = 10_000_001; }],
    ['extensions.future', (document) => { document.extensions['generation.future'] = true; }],
    ['destination traversal', (document) => { document.destination = '../escape'; }],
    ['destination controls', (document) => { document.destination = 'fixtures/bad\u0001path'; }],
    ['destination normalization', (document) => { document.destination = 'fixtures/Cafe\u0301'; }],
    ['seed controls', (document) => { document.seed = 'bad\u007fseed'; }],
    ['seed normalization', (document) => { document.seed = 'Cafe\u0301'; }],
  ];
  for (const [label, mutate] of mutations) {
    const document = mutable(boundary);
    mutate(document);
    schemaRejects('FixtureRequest', document);
    assert.throws(() => createRequest(document), undefined, label);
  }
});

test('request schema and runtime count seed characters identically and reject unpaired surrogates', () => {
  const astralSeed = String.fromCodePoint(0x1f600).repeat(600);
  const accepted = createRequest({ seed: astralSeed });
  assert.equal([...accepted.seed].length, 600);
  assert.deepEqual(validateSchemaDocument('FixtureRequest', accepted), []);

  const invalidSeeds = [
    String.fromCodePoint(0x1f600).repeat(1025),
    `lone-high-${String.fromCharCode(0xd800)}`,
    `lone-low-${String.fromCharCode(0xdfff)}`,
  ];
  for (const seed of invalidSeeds) {
    const document = mutable(accepted);
    document.seed = seed;
    assert.ok(validateSchemaDocument('FixtureRequest', document).some(({ path }) => path === '$.seed'));
    assert.throws(() => createRequest({ seed }));
  }
});

test('generated and returned public documents validate, while missing contract fields do not', async (t) => {
  const cwd = await temporaryDirectory(t, 'ogvcs-schema-roundtrip-');
  const request = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.checkpoint-every': 2,
      'generation.large-file-mode': 'stream-verified',
      'generation.materialization': 'index-only',
    },
    profile: { id: 'global-studio', version: '2.0.0' },
    scale: { historyOperationCount: 12, largeFileBytes: 4096, maxDepth: 4, pathCount: 8 },
    seed: 'schema-roundtrip-v2',
  });
  await generateFixture(request, { cwd });

  const fixture = path.join(cwd, 'fixture');
  const manifest = JSON.parse(await readFile(path.join(fixture, 'manifest.json'), 'utf8'));
  const storedRequest = JSON.parse(await readFile(path.join(fixture, 'fixture-request.json'), 'utf8'));
  const profile = JSON.parse(await readFile(path.join(fixture, 'workload-profile.json'), 'utf8'));
  const scenario = JSON.parse(await readFile(path.join(fixture, 'scenario.json'), 'utf8'));
  const groups = JSON.parse(await readFile(path.join(fixture, 'groups.json'), 'utf8'));
  const descriptor = JSON.parse(await readFile(path.join(fixture, 'large-file.json'), 'utf8'));
  const inventory = (await readFile(path.join(fixture, 'inventory.ndjson'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line));
  const verification = await verifyFixture('fixture', { cwd, deep: true });

  assertSchemaDocument('FixtureManifest', manifest);
  assertSchemaDocument('FixtureRequest', storedRequest);
  assertSchemaDocument('WorkloadProfile', profile);
  assertSchemaDocument('OperationScenario', scenario);
  assertSchemaDocument('GroupRelationships', groups);
  assertSchemaDocument('LargeFileDescriptor', descriptor);
  inventory.forEach((record) => assertSchemaDocument('InventoryRecord', record));
  assertSchemaDocument('VerificationResult', verification);

  const checkpoint = checkpointDocument({
    chains: createChains(),
    completedItems: 0,
    completedLogicalBytes: 0,
    nextItemIndex: 0,
    phase: 'paths',
    requestDigest: 'a'.repeat(64),
    sequence: 1,
    stageId: 'b'.repeat(32),
  });
  assertSchemaDocument('GenerationCheckpoint', checkpoint);

  for (const [name, document, remove] of [
    ['FixtureManifest', manifest, 'manifestDigest'],
    ['FixtureManifest', manifest, 'operationScenario'],
    ['FixtureManifest', manifest, 'extensions'],
    ['GenerationCheckpoint', checkpoint, 'extensions'],
  ]) {
    const invalid = mutable(document);
    delete invalid[remove];
    schemaRejects(name, invalid, new RegExp(remove));
  }

  const badCheckpoint = mutable(checkpoint);
  badCheckpoint.extensions['generation.phase'] = 'unknown';
  schemaRejects('GenerationCheckpoint', badCheckpoint, /generation\\\.phase/u);

  const badInventory = mutable(inventory[0]);
  badInventory.content.representation = 'semantic-v2';
  schemaRejects('InventoryRecord', badInventory, /content/u);

  const badGroups = mutable(groups);
  badGroups[0].members.push('../escape');
  schemaRejects('GroupRelationships', badGroups, /members/u);

  const badDescriptor = mutable(descriptor);
  delete badDescriptor.physical.streamedLogicalBytes;
  schemaRejects('LargeFileDescriptor', badDescriptor, /streamedLogicalBytes|physical/u);
});
