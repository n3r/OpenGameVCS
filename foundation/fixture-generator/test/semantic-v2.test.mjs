import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalDigest } from '../src/canonical.mjs';
import { deterministicChunks } from '../src/content.mjs';
import {
  contentChunksForRecord,
  createGroups,
  createOperation,
  createPathRecord,
  historyShape,
  largeFileRecipe,
  largeVersionChunks,
  scenarioEnvelope,
} from '../src/model.mjs';
import { materializeLargeFile, verifyLargeFile, writeFully } from '../src/materialize.mjs';
import { getProfile } from '../src/profiles.mjs';
import { assertSchemaDocument, validateSchemaDocument } from '../src/schema-validator.mjs';

function fixtureRequest(profileId, options = {}) {
  const profile = getProfile(profileId);
  const featureFlags = Object.fromEntries(profile.features.map((feature) => [feature, true]));
  if (profileId === 'unity-like') featureFlags['negative-cases'] = true;
  return {
    destination: 'fixture',
    extensions: {
      'generation.checkpoint-every': 100,
      'generation.compression-class': 'incompressible',
      'generation.duplication-permille': 1000,
      'generation.edit-locality-permille': 900,
      'generation.large-file-mode': options.largeFileMode ?? 'virtual',
      'generation.materialization': 'index-only',
      'generation.materialized-path-limit': 0,
      'generation.mutable-versions': options.mutableVersions ?? 3,
    },
    featureFlags: { ...featureFlags, ...options.featureFlags },
    profile: { id: profileId, version: profile.version },
    scale: {
      historyOperationCount: options.historyOperationCount ?? 80,
      largeFileBytes: options.largeFileBytes ?? 0,
      maxDepth: options.maxDepth ?? 12,
      pathCount: options.pathCount ?? 128,
    },
    seed: options.seed ?? `semantic-${profileId}`,
  };
}

test('materialization retries legal short writes and rejects zero progress', async () => {
  const calls = [];
  const handle = {
    async write(bytes, offset, length, position) {
      const bytesWritten = Math.min(3, length);
      calls.push({ bytesWritten, offset, position });
      return { bytesWritten };
    },
  };
  await writeFully(handle, Buffer.alloc(8), 11);
  assert.deepEqual(calls, [
    { bytesWritten: 3, offset: 0, position: 11 },
    { bytesWritten: 3, offset: 3, position: 14 },
    { bytesWritten: 2, offset: 6, position: 17 },
  ]);
  await assert.rejects(
    writeFully({ async write() { return { bytesWritten: 0 }; } }, Buffer.alloc(1)),
    /made no progress/,
  );
});

function bytesFor(request, record, version = record.content.version) {
  return Buffer.concat([...contentChunksForRecord(request, record, { chunkSize: 7, version })]);
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

test('AES-CTR v2 content is chunk-independent, range-addressable, and has a fixed vector', () => {
  const options = { compressionClass: 'incompressible', seed: 'v2-vector', size: 200_003, stream: 'asset/v2' };
  const whole = Buffer.concat([...deterministicChunks({ ...options, chunkSize: 65_537 })]);
  const fragments = Buffer.concat([...deterministicChunks({ ...options, chunkSize: 997 })]);
  const resumed = Buffer.concat([...deterministicChunks({ ...options, chunkSize: 7_919, start: 91_117 })]);
  assert.deepEqual(fragments, whole);
  assert.deepEqual(resumed, whole.subarray(91_117));
  assert.equal(digest(whole), '39ee30b9c432da1f5dae19d31f8daa4551fb14bcc0d8ec99f57b0080c6f5ad03');
});

test('every emitted v2 workload profile and operation scenario satisfies its public schema', () => {
  for (const profileId of ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio']) {
    const profile = getProfile(profileId);
    assert.equal(profile.version, '2.0.0');
    assertSchemaDocument('WorkloadProfile', profile);
    const request = fixtureRequest(profileId, { historyOperationCount: profile.operationKinds.length });
    const operations = Array.from(
      { length: request.scale.historyOperationCount },
      (_, sequence) => createOperation(request, profile, sequence),
    );
    assertSchemaDocument('OperationScenario', scenarioEnvelope(request, profile, operations, '0'.repeat(64)));
  }
});

test('structured profiles materialize valid deterministic formats and byte-backed version deltas', () => {
  const codeRequest = fixtureRequest('code-heavy');
  const codeProfile = getProfile('code-heavy');
  const source = createPathRecord(codeRequest, codeProfile, 0);
  assertSchemaDocument('InventoryRecord', source);
  assert.match(bytesFor(codeRequest, source).toString(), /int fixture_0\(void\)/);
  assert.doesNotThrow(() => JSON.parse(bytesFor(codeRequest, createPathRecord(codeRequest, codeProfile, 5)).toString()));
  assert.equal(source.content.versions.length, 2);
  for (const version of source.content.versions) {
    const bytes = bytesFor(codeRequest, source, version.version);
    assert.equal(digest(bytes), version.digest);
    assert.equal(bytes.length, version.logicalBytes);
  }
  assert.notEqual(source.content.versions[0].digest, source.content.versions[1].digest);

  const unrealRequest = fixtureRequest('unreal-like');
  const unrealProfile = getProfile('unreal-like');
  const packageRecord = createPathRecord(unrealRequest, unrealProfile, 0);
  const sourceRecord = createPathRecord(unrealRequest, unrealProfile, 4);
  const configRecord = createPathRecord(unrealRequest, unrealProfile, 6);
  const jsonConfigRecord = createPathRecord(unrealRequest, unrealProfile, 7);
  assert.match(bytesFor(unrealRequest, packageRecord).toString('ascii'), /^OGVCS-UASSET-V2/);
  assert.match(bytesFor(unrealRequest, sourceRecord).toString(), /int Fixture_4/);
  assert.match(bytesFor(unrealRequest, configRecord).toString(), /^\[Fixture\.Package\.6\]/);
  assert.doesNotThrow(() => JSON.parse(bytesFor(unrealRequest, jsonConfigRecord).toString()));

  const unityRequest = fixtureRequest('unity-like');
  const unityProfile = getProfile('unity-like');
  assert.match(bytesFor(unityRequest, createPathRecord(unityRequest, unityProfile, 0)).toString(), /^%YAML 1\.1/);
  assert.match(bytesFor(unityRequest, createPathRecord(unityRequest, unityProfile, 4)).toString('ascii'), /^OGVCS-UNITY-IMPORT-V2/);
});

test('zero-byte large-binary requests classify index zero as an ordinary binary version', () => {
  const profile = getProfile('large-binary');
  const ordinary = createPathRecord(
    fixtureRequest('large-binary', { largeFileBytes: 0, pathCount: 1 }),
    profile,
    0,
  );
  assert.equal(ordinary.role, 'binary-version');
  assert.equal(ordinary.content.algorithm, 'sha256');

  const mutable = createPathRecord(
    fixtureRequest('large-binary', { largeFileBytes: 1, pathCount: 1 }),
    profile,
    0,
  );
  assert.equal(mutable.role, 'mutable-large-file');
  assert.equal(mutable.content.algorithm, 'sha256-recipe-v2');
});

test('Unity negatives are real relationships: absent meta and duplicate GUID across groups', () => {
  const request = fixtureRequest('unity-like', { pathCount: 100 });
  const profile = getProfile('unity-like');
  const missingAsset = createPathRecord(request, profile, 14);
  const missingReplacement = createPathRecord(request, profile, 15);
  assert.equal(missingAsset.negativeCase, 'missing-sidecar');
  assert.equal(missingReplacement.role, 'negative-evidence');
  assert.ok(!missingReplacement.logicalPath.endsWith('.meta'));
  assert.equal(missingReplacement.group, undefined);

  const firstDuplicateAsset = createPathRecord(request, profile, 24);
  const secondDuplicateAsset = createPathRecord(request, profile, 26);
  assert.notEqual(firstDuplicateAsset.group.id, secondDuplicateAsset.group.id);
  assert.equal(firstDuplicateAsset.syntheticGuid, secondDuplicateAsset.syntheticGuid);
  const firstMeta = bytesFor(request, createPathRecord(request, profile, 25)).toString();
  const secondMeta = bytesFor(request, createPathRecord(request, profile, 27)).toString();
  assert.match(firstMeta, new RegExp(`guid: ${firstDuplicateAsset.syntheticGuid}`));
  assert.match(secondMeta, new RegExp(`guid: ${firstDuplicateAsset.syntheticGuid}`));
});

test('Unity pair-disabled mode suppresses sidecar GUID and negative relationship metadata', () => {
  const request = fixtureRequest('unity-like', {
    featureFlags: { 'asset-meta-pairs': false },
    pathCount: 100,
  });
  const profile = getProfile('unity-like');
  const records = Array.from(
    { length: request.scale.pathCount },
    (_, index) => createPathRecord(request, profile, index),
  );
  assert.deepEqual(createGroups(request, profile), []);
  assert.ok(records.every((record) => (
    record.group === undefined
    && record.negativeCase === undefined
    && record.syntheticGuid === undefined
    && record.role !== 'meta'
    && !record.logicalPath.endsWith('.meta')
  )));
  for (const record of records) assertSchemaDocument('InventoryRecord', record);
});

test('truncated Unity and Unreal relationship families never advertise incomplete ordinary pairs', () => {
  const unityProfile = getProfile('unity-like');
  for (const pathCount of [1, 3]) {
    const request = fixtureRequest('unity-like', { pathCount });
    const tail = createPathRecord(request, unityProfile, pathCount - 1);
    assert.equal(tail.group, undefined);
    assert.equal(tail.syntheticGuid, undefined);
    assert.equal(tail.negativeCase, undefined);
    assert.ok(createGroups(request, unityProfile).every(({ members }) => members.length === 2));
  }

  const unrealProfile = getProfile('unreal-like');
  const onePath = fixtureRequest('unreal-like', { pathCount: 1 });
  assert.equal(createPathRecord(onePath, unrealProfile, 0).group, undefined);
  assert.deepEqual(createGroups(onePath, unrealProfile), []);
  const partialMap = fixtureRequest('unreal-like', { pathCount: 3 });
  assert.equal(createPathRecord(partialMap, unrealProfile, 2).group, undefined);
  assert.deepEqual(createGroups(partialMap, unrealProfile).map(({ members }) => members.length), [2]);
});

test('manifest history shape replays distinct branches, roots, merges, and ancestry depth', () => {
  const codeProfile = getProfile('code-heavy');
  const code = fixtureRequest('code-heavy', {
    historyOperationCount: codeProfile.operationKinds.length * 2,
  });
  assert.deepEqual(historyShape(code, codeProfile), {
    branchCount: 3,
    maximumDepth: 2,
    mergeCount: 2,
    rootCount: 2,
  });
  assert.deepEqual(historyShape(
    fixtureRequest('code-heavy', { historyOperationCount: 0 }),
    codeProfile,
  ), { branchCount: 1, maximumDepth: 0, mergeCount: 0, rootCount: 0 });

  const globalProfile = getProfile('global-studio');
  assert.deepEqual(historyShape(
    fixtureRequest('global-studio', { historyOperationCount: 0 }),
    globalProfile,
  ), { branchCount: 5, maximumDepth: 1, mergeCount: 0, rootCount: 1 });
  const submitted = historyShape(fixtureRequest('global-studio', {
    featureFlags: { 'lock-lifecycle': false },
    historyOperationCount: 40,
  }), globalProfile);
  assert.equal(submitted.branchCount, 5);
  assert.equal(submitted.rootCount, 1);
  assert.ok(submitted.maximumDepth > 1);
});

test('maximum-size history replay stays streaming and checks its runtime budget', () => {
  const profile = getProfile('code-heavy');
  const request = fixtureRequest('code-heavy', { historyOperationCount: 10_000_000 });
  let checks = 0;
  const stopped = new Error('bounded history replay stop');
  assert.throws(
    () => historyShape(request, profile, {
      checkRuntime(phase) {
        assert.equal(phase, 'history-shape-replay');
        checks += 1;
        if (checks === 3) throw stopped;
      },
    }),
    (error) => error === stopped,
  );
  assert.equal(checks, 3);
});

test('every advertised feature flag changes a relevant path, group, operation, scenario, or recipe artifact', () => {
  for (const profileId of ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio']) {
    const profile = getProfile(profileId);
    for (const feature of profile.features) {
      const on = fixtureRequest(profileId, { largeFileBytes: 262_144 });
      const off = fixtureRequest(profileId, { featureFlags: { [feature]: false }, largeFileBytes: 262_144 });
      const fingerprint = (request) => canonicalDigest({
        groups: createGroups(request, profile),
        operations: Array.from({ length: request.scale.historyOperationCount }, (_, sequence) => createOperation(request, profile, sequence)),
        paths: Array.from({ length: Math.min(128, request.scale.pathCount) }, (_, index) => createPathRecord(request, profile, index)),
        recipe: largeFileRecipe(request, createPathRecord(request, profile, 0).logicalPath),
        scenario: scenarioEnvelope(request, profile, [], '0'.repeat(64)),
      }, 'ogvcs.fixture/feature-effect-test/v2');
      assert.notEqual(fingerprint(on), fingerprint(off), `${profileId}.${feature} must affect an artifact`);
    }
  }
});

test('bounded groups never leave dangling IDs above the former 10k boundary', () => {
  const request = fixtureRequest('unity-like', { pathCount: 20_005 });
  const profile = getProfile('unity-like');
  const groups = createGroups(request, profile);
  assertSchemaDocument('GroupRelationships', groups);
  assert.equal(groups.length, 10_000);
  const declared = new Set(groups.map(({ id }) => id));
  for (let index = 0; index < request.scale.pathCount; index += 1) {
    const record = createPathRecord(request, profile, index);
    if (record.group) assert.ok(declared.has(record.group.id), `dangling group at record ${index}`);
  }
  assert.ok(createPathRecord(request, profile, 19_999).group);
  assert.equal(createPathRecord(request, profile, 20_000).group, undefined);
});

test('operation cycles preserve branch, lock, submit, review, sync, CI, and interruption semantics', () => {
  const request = fixtureRequest('global-studio');
  const profile = getProfile('global-studio');
  const operations = Array.from({ length: profile.operationKinds.length }, (_, sequence) => createOperation(request, profile, sequence));
  const byKind = Object.fromEntries(operations.map((operation) => [operation.kind, operation]));
  assert.equal(byKind['lock-acquire'].parameters['lock-id'], byKind['lock-conflict'].parameters['lock-id']);
  assert.equal(byKind['lock-acquire'].parameters['lock-id'], byKind['lock-loss'].parameters['lock-id']);
  assert.equal(byKind['lock-acquire'].actor, byKind['lock-conflict'].parameters.holder);
  assert.equal(byKind['lock-conflict'].actor, byKind['lock-conflict'].parameters.contender);
  assert.deepEqual(byKind.submit.expectedOutcome, { code: 'lock-not-held', status: 'rejected' });
  assert.equal(byKind['lock-loss'].expectedOutcome.status, 'succeeded');
  assert.equal(byKind['lock-loss'].parameters['submit-policy'], 'reject-until-reacquired');
  assert.equal(byKind['branch-update'].relatedTarget, `branches/${byKind['branch-update'].parameters['target-branch']}`);
  assert.equal(byKind.submit.parameters.atomic, true);
  assert.ok(byKind.review.parameters.reviewers.length > 0);
  assert.ok(byKind['selective-sync'].parameters.includes.length > 0);
  assert.equal(byKind['ci-materialize'].parameters['clean-workspace'], true);
  assert.equal(byKind.interrupt.parameters.recovery, 'resume-with-retry-key');

  const noLossRequest = fixtureRequest('global-studio', { featureFlags: { 'lock-lifecycle': false } });
  const noLossOperations = Array.from(
    { length: profile.operationKinds.length },
    (_, sequence) => createOperation(noLossRequest, profile, sequence),
  );
  const noLossSubmit = noLossOperations.find(({ kind }) => kind === 'submit');
  assert.deepEqual(noLossSubmit.expectedOutcome, { code: 'submitted', status: 'succeeded' });
});

test('long operation histories keep revision, branch, and submitted-change references replayable', () => {
  const profile = getProfile('code-heavy');
  const request = fixtureRequest('code-heavy', {
    historyOperationCount: profile.operationKinds.length * 20,
  });
  const operations = Array.from(
    { length: request.scale.historyOperationCount },
    (_, sequence) => createOperation(request, profile, sequence),
  );
  const scenario = scenarioEnvelope(request, profile, operations, '0'.repeat(64));
  const state = scenario.extensions['state-model'];
  assert.equal(state.algorithm, 'path-file-id-revision-branch-state-v2');
  const revisions = new Set(state.revisions.map(({ revision }) => revision));
  const branches = new Map(state.branches.map(({ head, name }) => [name, head]));
  const createdBranches = new Set();
  for (const operation of operations) {
    const parameters = operation.parameters;
    if (operation.kind === 'create') {
      assert.equal(revisions.has(parameters['result-revision']), false);
      revisions.add(parameters['result-revision']);
      branches.set('main', parameters['result-revision']);
    } else if (operation.kind === 'edit') {
      assert.ok(revisions.has(parameters['base-revision']));
      assert.equal(branches.get('main'), parameters['base-revision']);
      revisions.add(parameters['result-revision']);
      branches.set('main', parameters['result-revision']);
    } else if (operation.kind === 'branch') {
      assert.ok(revisions.has(parameters['from-revision']));
      assert.equal(branches.get(parameters['source-branch']), parameters['from-revision']);
      assert.equal(branches.has(parameters['target-branch']), false);
      branches.set(parameters['target-branch'], parameters['from-revision']);
      createdBranches.add(parameters['target-branch']);
    } else if (operation.kind === 'merge') {
      assert.ok(createdBranches.has(parameters['source-branch']));
      assert.equal(branches.get(parameters['source-branch']), parameters['common-base']);
      assert.ok(revisions.has(parameters['common-base']));
    } else if (operation.kind === 'delete') {
      assert.ok(revisions.has(parameters['base-revision']));
    }
  }
  assert.equal(createdBranches.size, 20);

  const branchesDisabled = fixtureRequest('code-heavy', {
    featureFlags: { branches: false },
    historyOperationCount: 80,
  });
  const withoutBranches = Array.from(
    { length: branchesDisabled.scale.historyOperationCount },
    (_, sequence) => createOperation(branchesDisabled, profile, sequence),
  );
  assert.ok(withoutBranches.every(({ kind }) => kind !== 'branch' && kind !== 'merge'));

  const editsDisabled = fixtureRequest('code-heavy', {
    featureFlags: { 'text-edits': false },
    historyOperationCount: 12,
  });
  const withoutEdits = Array.from(
    { length: editsDisabled.scale.historyOperationCount },
    (_, sequence) => createOperation(editsDisabled, profile, sequence),
  );
  assert.ok(withoutEdits.every(({ kind }) => kind !== 'edit'));
  for (const operation of withoutEdits.slice(0, 6)) {
    const revision = operation.parameters['from-revision']
      ?? operation.parameters['common-base']
      ?? operation.parameters['base-revision'];
    if (revision !== undefined) assert.equal(revision, 'change-00000000-r1');
  }

  const globalProfile = getProfile('global-studio');
  for (const lockLifecycle of [true, false]) {
    const globalRequest = fixtureRequest('global-studio', {
      featureFlags: { 'lock-lifecycle': lockLifecycle },
      historyOperationCount: globalProfile.operationKinds.length * 4,
    });
    const globalOperations = Array.from(
      { length: globalRequest.scale.historyOperationCount },
      (_, sequence) => createOperation(globalRequest, globalProfile, sequence),
    );
    const globalScenario = scenarioEnvelope(
      globalRequest,
      globalProfile,
      globalOperations,
      '0'.repeat(64),
    );
    const globalState = globalScenario.extensions['state-model'];
    const knownRevisions = new Set(globalState.revisions.map(({ revision }) => revision));
    const committed = new Set(globalState.changes.map(({ id }) => id));
    const globalBranches = new Map(globalState.branches.map(({ head, name }) => [name, head]));
    for (const operation of globalOperations) {
      const parameters = operation.parameters;
      if (operation.kind === 'selective-sync') {
        assert.ok(knownRevisions.has(parameters['revision-selector']));
      } else if (operation.kind === 'ci-materialize') {
        assert.ok(knownRevisions.has(parameters.revision));
      } else if (operation.kind === 'branch-update') {
        assert.equal(globalBranches.get(parameters['target-branch']), parameters['expected-head']);
        globalBranches.set(
          parameters['target-branch'],
          globalBranches.get(parameters['source-branch']),
        );
      } else if (operation.kind === 'submit') {
        assert.ok(parameters['parent-change'] === 'root' || committed.has(parameters['parent-change']));
        if (operation.expectedOutcome.status === 'succeeded') {
          committed.add(parameters['change-id']);
        } else {
          assert.equal(parameters['parent-change'], 'root');
        }
      }
    }
  }
});

test('operation stream applies coherent path/FileID transitions and declares every outcome', () => {
  for (const profileId of ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio']) {
    const request = fixtureRequest(profileId, { historyOperationCount: 2 * getProfile(profileId).operationKinds.length });
    const profile = getProfile(profileId);
    const operations = Array.from(
      { length: request.scale.historyOperationCount },
      (_, sequence) => createOperation(request, profile, sequence),
    );
    const scenario = scenarioEnvelope(request, profile, operations, '0'.repeat(64));
    const files = new Map(scenario.extensions['state-model'].files.map((file) => [file.logicalPath, file.fileId]));
    const tombstones = new Set();
    for (const operation of operations) {
      assert.ok(['succeeded', 'rejected'].includes(operation.expectedOutcome.status));
      assert.match(operation.fileId.source ?? operation.fileId.result, /^[0-9a-f]{32}$/);
      const current = files.get(operation.target);
      if (operation.kind === 'create') {
        assert.equal(current, undefined);
        assert.equal(operation.fileId.source, null);
        files.set(operation.target, operation.fileId.result);
      } else if (operation.kind === 'copy') {
        assert.equal(current, operation.fileId.source);
        assert.notEqual(operation.fileId.source, operation.fileId.result);
        assert.equal(files.has(operation.relatedTarget), false);
        files.set(operation.relatedTarget, operation.fileId.result);
      } else if (operation.kind === 'move' || operation.kind === 'rename') {
        assert.equal(current, operation.fileId.source);
        assert.equal(operation.fileId.source, operation.fileId.result);
        assert.equal(files.has(operation.relatedTarget), false);
        files.delete(operation.target);
        files.set(operation.relatedTarget, operation.fileId.result);
      } else if (operation.kind === 'delete') {
        assert.equal(current, operation.fileId.source);
        assert.equal(operation.fileId.result, null);
        files.delete(operation.target);
        tombstones.add(operation.fileId.source);
      } else if (operation.fileId.semantics === 'tombstone-observed') {
        assert.equal(current, undefined);
        assert.ok(tombstones.has(operation.fileId.source));
      } else {
        assert.equal(current, operation.fileId.source);
        assert.equal(operation.fileId.source, operation.fileId.result);
      }
    }
  }
});

test('public operation schema rejects wrong kind parameters and conditional targets', () => {
  const request = fixtureRequest('code-heavy');
  const profile = getProfile('code-heavy');
  const valid = createOperation(request, profile, 0);
  const issuesFor = (operation) => validateSchemaDocument(
    'OperationScenario',
    scenarioEnvelope(request, profile, [operation], '0'.repeat(64)),
  );

  const missingParameter = structuredClone(valid);
  delete missingParameter.parameters['result-revision'];
  assert.ok(issuesFor(missingParameter).some(({ keyword }) => keyword === 'oneOf'));

  const extraParameter = structuredClone(valid);
  extraParameter.parameters['base-revision'] = 'change-00000000-r1';
  assert.ok(issuesFor(extraParameter).some(({ keyword }) => keyword === 'oneOf'));

  const rename = createOperation(request, profile, 4);
  delete rename.relatedTarget;
  assert.ok(issuesFor(rename).some(({ keyword }) => keyword === 'required'));

  const spuriousNetwork = structuredClone(valid);
  spuriousNetwork.networkCondition = 'link-1';
  assert.ok(issuesFor(spuriousNetwork).some(({ keyword }) => keyword === 'falseSchema'));

  const codeOperations = Array.from(
    { length: profile.operationKinds.length },
    (_, sequence) => createOperation(request, profile, sequence),
  );
  const unityRequest = fixtureRequest('unity-like');
  const unityProfile = getProfile('unity-like');
  const largeRequest = fixtureRequest('large-binary');
  const largeProfile = getProfile('large-binary');
  const nullInvalidCases = [
    [codeOperations.find(({ kind }) => kind === 'create'), 'result'],
    [codeOperations.find(({ kind }) => kind === 'edit'), 'source'],
    [codeOperations.find(({ kind }) => kind === 'copy'), 'source'],
    [createOperation(unityRequest, unityProfile, 2), 'source'],
    [codeOperations.find(({ kind }) => kind === 'rename'), 'result'],
    [codeOperations.find(({ kind }) => kind === 'delete'), 'source'],
    [codeOperations.find(({ kind }) => kind === 'branch'), 'result'],
    [createOperation(largeRequest, largeProfile, 3), 'result'],
  ];
  for (const [operation, field] of nullInvalidCases) {
    const mutated = structuredClone(operation);
    mutated.fileId[field] = null;
    assert.ok(
      issuesFor(mutated).some(({ keyword }) => keyword === 'oneOf'),
      `${operation.kind} must reject null fileId.${field}`,
    );
  }

  const tombstoneSubmit = createOperation(unityRequest, unityProfile, 4);
  assert.equal(tombstoneSubmit.fileId.semantics, 'tombstone-observed');
  tombstoneSubmit.fileId.result = tombstoneSubmit.fileId.source;
  assert.ok(
    issuesFor(tombstoneSubmit).some(({ keyword }) => keyword === 'oneOf'),
    'tombstone-observed submit must require a null result FileID',
  );
});

test('scenario identities, ACL decisions, and profile path prefixes are coherent', () => {
  const request = fixtureRequest('global-studio');
  const profile = getProfile('global-studio');
  const operations = Array.from({ length: profile.operationKinds.length }, (_, sequence) => createOperation(request, profile, sequence));
  const first = scenarioEnvelope(request, profile, operations, '0'.repeat(64));
  const second = scenarioEnvelope(request, profile, operations, '0'.repeat(64));
  assert.deepEqual(first, second);
  const participantIds = new Set(first.participants.map(({ id }) => id));
  const identities = first.extensions['identity-model'].identities;
  assert.deepEqual(new Set(identities.map(({ id }) => id)), participantIds);
  for (const identity of identities) {
    assert.equal(first.participants.find(({ id }) => id === identity.id).site, identity.site);
  }
  const populatedGroups = new Set(identities.flatMap(({ groups }) => groups));
  for (const rule of first.extensions['acl-model'].rules) assert.ok(populatedGroups.has(rule.principal));
  const groupsByActor = new Map(identities.map(({ groups, id }) => [id, new Set(groups)]));
  for (const operation of operations) {
    const matchingRule = first.extensions['acl-model'].rules.find((rule) => (
      rule.actions.includes(operation.authorization.action)
      && groupsByActor.get(operation.actor).has(rule.principal)
      && (rule.pathPrefix === '' || operation.target === rule.pathPrefix || operation.target.startsWith(`${rule.pathPrefix}/`))
    ));
    assert.ok(matchingRule, `${operation.kind} must have an allowing ACL rule`);
    assert.equal(operation.authorization.decision, 'allow');
    assert.equal(operation.authorization.matchedPrincipal, matchingRule.principal);
    assert.equal(operation.authorization.matchedPathPrefix, matchingRule.pathPrefix);
  }
});

test('every profile preserves rooted ACL-coherent operation paths at minimum depth', () => {
  for (const profileId of ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio']) {
    const profile = getProfile(profileId);
    const request = fixtureRequest(profileId, {
      historyOperationCount: profile.operationKinds.length,
      maxDepth: 2,
    });
    const operations = Array.from(
      { length: request.scale.historyOperationCount },
      (_, sequence) => createOperation(request, profile, sequence),
    );
    const scenario = scenarioEnvelope(request, profile, operations, '0'.repeat(64));
    const groupsByActor = new Map(scenario.extensions['identity-model'].identities.map(
      ({ groups, id }) => [id, new Set(groups)],
    ));
    for (const operation of operations) {
      assert.ok(operation.target.includes('/'), `${profileId}:${operation.kind} target must retain a root`);
      assert.ok(operation.target.split('/').length <= request.scale.maxDepth);
      if (operation.relatedTarget !== undefined) {
        assert.ok(!operation.relatedTarget.includes('undefined'));
        assert.ok(operation.relatedTarget.split('/').length <= request.scale.maxDepth);
      }
      const matchingRule = scenario.extensions['acl-model'].rules.find((rule) => (
        rule.actions.includes(operation.authorization.action)
        && groupsByActor.get(operation.actor).has(rule.principal)
        && (rule.pathPrefix === ''
          || operation.target === rule.pathPrefix
          || operation.target.startsWith(`${rule.pathPrefix}/`))
      ));
      assert.ok(matchingRule, `${profileId}:${operation.kind} must match an ACL rule`);
      assert.equal(operation.authorization.matchedPrincipal, matchingRule.principal);
      assert.equal(operation.authorization.matchedPathPrefix, matchingRule.pathPrefix);
    }
    assertSchemaDocument(
      'OperationScenario',
      scenarioEnvelope(request, profile, operations, '0'.repeat(64)),
    );
  }
});

test('large recipes generate real version bytes with patch/reuse/locality semantics', () => {
  const request = fixtureRequest('large-binary', { largeFileBytes: 262_144 });
  const profile = getProfile('large-binary');
  const record = createPathRecord(request, profile, 0);
  const recipe = largeFileRecipe(request, record.logicalPath);
  const bytes = recipe.versions.map(({ version }) => Buffer.concat([...largeVersionChunks(request, recipe, version, { chunkSize: 8191 })]));
  assert.equal(bytes.length, 3);
  assert.ok(bytes.every((entry) => entry.length === request.scale.largeFileBytes));
  assert.notEqual(digest(bytes[0]), digest(bytes[1]));
  assert.notEqual(digest(bytes[1]), digest(bytes[2]));
  for (const version of recipe.versions.slice(1)) {
    assert.equal(version.baseVersion, version.version - 1);
    assert.ok(version.patches.length > 0);
    assert.ok(version.reusePermille > 0);
    assert.equal(version.editLocalityPermille, 900);
  }
});

for (const mode of ['sparse', 'full', 'stream-verified']) {
  test(`large-file ${mode} materialization round trips v2 descriptors and version digests`, async (t) => {
    const stage = await realpath(await mkdtemp(path.join(os.tmpdir(), `ogvcs-semantic-${mode}-`)));
    t.after(() => rm(stage, { force: true, recursive: true }));
    await mkdir(path.join(stage, 'files'));
    const request = fixtureRequest('large-binary', { largeFileBytes: 262_144, largeFileMode: mode });
    const profile = getProfile('large-binary');
    const record = createPathRecord(request, profile, 0);
    const descriptor = await materializeLargeFile(stage, request, record, { physicalBytes: 0 });
    assertSchemaDocument('LargeFileDescriptor', descriptor);
    const verified = await verifyLargeFile(stage, request, record, descriptor, { deep: true });
    assert.equal(verified.checked, true);
    if (mode === 'sparse') {
      const extents = descriptor.physical.extents;
      assert.equal(
        descriptor.physical.extentPayloadBytes,
        extents.reduce((total, extent) => total + extent.length, 0),
      );
      assert.equal(descriptor.physical.maximumAllocatedBytes, request.scale.largeFileBytes);
      assert.equal(descriptor.physical.physicalBytes, undefined);
      for (let index = 1; index < extents.length; index += 1) {
        assert.ok(extents[index - 1].offset + extents[index - 1].length <= extents[index].offset);
      }
    } else {
      assert.equal(descriptor.physical.versionDigests.length, 3);
      assert.ok(descriptor.physical.versionDigests.every((entry) => entry.bytes === request.scale.largeFileBytes));
    }
    if (mode === 'stream-verified') {
      assert.equal(descriptor.physical.physicalBytes, 0);
      assert.equal(descriptor.physical.streamedLogicalBytes, request.scale.largeFileBytes * 3);
    }
  });
}

test('deep full verification rejects a mutated historical version digest even with a recomputed descriptor digest', async (t) => {
  const stage = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ogvcs-semantic-mutation-')));
  t.after(() => rm(stage, { force: true, recursive: true }));
  await mkdir(path.join(stage, 'files'));
  const request = fixtureRequest('large-binary', { largeFileBytes: 131_072, largeFileMode: 'full' });
  const profile = getProfile('large-binary');
  const record = createPathRecord(request, profile, 0);
  const descriptor = await materializeLargeFile(stage, request, record, { physicalBytes: 0 });
  descriptor.physical.versionDigests[0].digest = '0'.repeat(64);
  const { descriptorDigest: ignored, ...body } = descriptor;
  descriptor.descriptorDigest = canonicalDigest(body, 'ogvcs.fixture/large-file-descriptor/v2');
  await assert.rejects(
    verifyLargeFile(stage, request, record, descriptor, { deep: true }),
    /version digests are invalid/,
  );
});
