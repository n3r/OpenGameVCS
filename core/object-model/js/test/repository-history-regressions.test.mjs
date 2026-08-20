import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  FileId, ObjectRef, OgvcsError, ProfileRef, RepositoryObjectLookup, expandTree,
  loadRegistryDirectory, validateAssetGroups, validateConflictSet, validateRepositoryCandidate,
  validateLifetimeAndImports, validateShelfRevision, validateSnapshotGraph
} from '../src/index.js';

const SPEC = resolve(import.meta.dirname, '../../../../spec/repository-format/v1');
const VECTORS = join(SPEC, 'vectors');
const error = (code, layer) => value => value instanceof OgvcsError && value.code === code &&
  (layer === undefined || value.layer === layer);

async function loadScenario(id) {
  const scenario = JSON.parse(await readFile(join(VECTORS, `scenarios/cases/${id}.json`), 'utf8'));
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const entries = [];
  for (const item of scenario.context.objectLookup) {
    entries.push([item.ref, new Uint8Array(await readFile(join(VECTORS, item.artifact.path)))]);
  }
  const lookup = new RepositoryObjectLookup(entries, {
    registry, mode: scenario.context.mode, semanticProfiles: true
  });
  return { scenario, lookup };
}

function context(scenario, lookup) {
  return {
    lookup,
    descriptor: scenario.context.repositoryDescriptor,
    designatedRoot: scenario.context.designatedRoot,
    lifetimeRecords: scenario.context.lifetimeRecords,
    workingLifetimeAdditions: scenario.context.workingLifetimeAdditions,
    importMappings: scenario.context.importMappings,
    caseMode: scenario.context.caseMode ?? 'case-sensitive',
    verifyContent: true
  };
}

function key(value) {
  return (value instanceof ObjectRef ? value : ObjectRef.fromMap(value)).toString();
}

function overridingLookup(base, replacements) {
  const replace = (reference, resolved) => {
    const replacement = replacements.get(key(reference));
    return replacement === undefined ? resolved : {
      ...resolved,
      value: structuredClone(replacement)
    };
  };
  return {
    get registry() { return base.registry; },
    get mode() { return base.mode; },
    get hardLimits() { return base.hardLimits; },
    checkpoint() { base.checkpoint(); },
    validateAll() { base.validateAll(); return this; },
    resolve(reference, kind) { return replace(reference, base.resolve(reference, kind)); },
    edge(reference, kind) { return replace(reference, base.edge(reference, kind)); }
  };
}

function accountingLookup(base, maximum = Number.MAX_SAFE_INTEGER) {
  let retained = 0;
  let peak = 0;
  const lookup = {
    get registry() { return base.registry; },
    get mode() { return base.mode; },
    get hardLimits() { return base.hardLimits; },
    checkpoint() { base.checkpoint(); },
    validateAll() { base.validateAll(); return this; },
    resolve(reference, kind) { return base.resolve(reference, kind); },
    edge(reference, kind) { return base.edge(reference, kind); },
    reserveDerived(bytes) {
      if (bytes > maximum - retained) throw new OgvcsError('LIMIT_MEMORY', { layer: 1 });
      retained += bytes; peak = Math.max(peak, retained);
    },
    releaseDerived(bytes) { retained -= bytes; assert.ok(retained >= 0); }
  };
  return { lookup, metrics: () => ({ peak, retained }) };
}

test('repository validation rejects a forged side-parent lookup authority', async () => {
  const loaded = await loadScenario('history-two-parent');
  const candidate = loaded.lookup.resolve(loaded.scenario.context.candidateSnapshot, 7).value;
  const sideParentRef = ObjectRef.fromMap(candidate.get(17)[1]);
  const sideParent = loaded.lookup.resolve(sideParentRef, 7).value;
  sideParent.set(18, new ObjectRef(3, new Uint8Array(32).fill(0xfe)).toMap());
  const lookup = overridingLookup(loaded.lookup, new Map([[sideParentRef.toString(), sideParent]]));

  assert.throws(() => validateRepositoryCandidate(
    loaded.scenario.context.candidateSnapshot,
    context(loaded.scenario, lookup)
  ), error('SCHEMA_FIELD_INVALID', 1));
});

test('snapshot validation rejects a forged lookup authority before graph work', async () => {
  const loaded = await loadScenario('history-second-root');
  const candidateRef = ObjectRef.parse(loaded.scenario.context.candidateSnapshot);
  const candidate = loaded.lookup.resolve(candidateRef, 7).value;
  candidate.set(16, new ObjectRef(6, new Uint8Array(32).fill(0xee)).toMap());
  const lookup = overridingLookup(loaded.lookup, new Map([[candidateRef.toString(), candidate]]));

  assert.throws(() => validateSnapshotGraph(
    candidateRef, context(loaded.scenario, lookup)
  ), error('SCHEMA_FIELD_INVALID', 1));
});

test('side-parent validation rejects a forged lookup authority before graph work', async () => {
  const loaded = await loadScenario('history-two-parent');
  const candidate = loaded.lookup.resolve(loaded.scenario.context.candidateSnapshot, 7).value;
  const sideRef = ObjectRef.fromMap(candidate.get(17)[1]);
  const side = loaded.lookup.resolve(sideRef, 7).value;
  side.set(16, new ObjectRef(6, new Uint8Array(32).fill(0xee)).toMap());
  side.set(17, []);
  const lookup = overridingLookup(loaded.lookup, new Map([[sideRef.toString(), side]]));

  assert.throws(() => validateSnapshotGraph(
    loaded.scenario.context.candidateSnapshot, context(loaded.scenario, lookup)
  ), error('SCHEMA_FIELD_INVALID', 1));
});

test('conflict validation rejects a forged lookup authority before subjects', async () => {
  const invalid = await loadScenario('error-conflict-subject-invalid');
  const unresolved = await loadScenario('conflict-unresolved-published');
  const conflictItem = invalid.scenario.context.objectLookup.find(item => item.ref.includes(':conflict-set:'));
  const unresolvedItem = unresolved.scenario.context.objectLookup.find(item => item.ref.includes(':conflict-set:'));
  const conflictRef = ObjectRef.parse(conflictItem.ref);
  const conflictSet = invalid.lookup.resolve(conflictRef, 11).value;
  const unresolvedSet = unresolved.lookup.resolve(unresolvedItem.ref, 11).value;
  conflictSet.get(17)[0].set(6, structuredClone(unresolvedSet.get(17)[0].get(6)));
  const lookup = overridingLookup(invalid.lookup, new Map([[conflictRef.toString(), conflictSet]]));

  assert.throws(() => validateConflictSet(
    conflictRef, lookup, invalid.scenario.context.repositoryDescriptor, { published: true }
  ), error('SCHEMA_FIELD_INVALID', 1));
});

test('shelf validation rejects a forged lookup authority before replay', async () => {
  const loaded = await loadScenario('shelf-revision-chain');
  const shelfItems = loaded.scenario.context.objectLookup.filter(item => item.ref.includes(':shelf-revision:'));
  const latestRef = shelfItems.map(item => ObjectRef.parse(item.ref)).find(reference =>
    loaded.lookup.resolve(reference, 8).value.get(18) === 2
  );
  const latest = loaded.lookup.resolve(latestRef, 8).value;
  const previousRef = ObjectRef.fromMap(latest.get(19));
  const previous = loaded.lookup.resolve(previousRef, 8).value;
  previous.set(22, new ObjectRef(3, new Uint8Array(32).fill(0xfd)).toMap());
  const lookup = overridingLookup(loaded.lookup, new Map([[previousRef.toString(), previous]]));

  assert.throws(() => validateShelfRevision(latestRef, {
    ...context(loaded.scenario, lookup), descriptor: latest.get(16)
  }), error('SCHEMA_FIELD_INVALID', 1));
});

test('historical replay rejects caller-forged accounting lookup wrappers', async () => {
  const history = await loadScenario('history-two-parent');
  const measuredHistory = accountingLookup(history.lookup);
  assert.throws(() => validateRepositoryCandidate(
    history.scenario.context.candidateSnapshot,
    context(history.scenario, measuredHistory.lookup)
  ), error('SCHEMA_FIELD_INVALID', 1));
  assert.equal(measuredHistory.metrics().retained, 0);
  assert.equal(measuredHistory.metrics().peak, 0);
});

test('change-set validation rejects a forged lookup authority before replay', async () => {
  const loaded = await loadScenario('transition-modify');
  const candidate = loaded.lookup.resolve(loaded.scenario.context.candidateSnapshot, 7).value;
  const changeRef = ObjectRef.fromMap(candidate.get(19));
  const changeSet = loaded.lookup.resolve(changeRef, 4).value;
  const operation = changeSet.get(18).find(value => value.get(1) === 2);
  assert.ok(operation);
  const before = new Map(operation.get(2));
  before.set(0, ['missing-source']);
  operation.set(2, before);
  const lookup = overridingLookup(loaded.lookup, new Map([[changeRef.toString(), changeSet]]));

  assert.throws(() => validateRepositoryCandidate(
    loaded.scenario.context.candidateSnapshot,
    context(loaded.scenario, lookup)
  ), error('SCHEMA_FIELD_INVALID', 1));
});

test('lifetime validation rejects a missing semantic lookup authority', () => {
  const descriptor = new ObjectRef(6, new Uint8Array(32).fill(0x61));
  const foreignDescriptor = new ObjectRef(6, new Uint8Array(32).fill(0xef));
  const changeRef = new ObjectRef(4, new Uint8Array(32).fill(0x62));
  const fileId = new Uint8Array(16).fill(0x63);
  const after = new Map([[2, fileId]]);
  const operation = new Map([[5, new Map([[0, foreignDescriptor.toMap()], [1, 1]])]]);

  assert.throws(() => validateLifetimeAndImports({
    descriptor,
    changeSetReference: changeRef,
    lifetimeRecords: [{
      fileId: Buffer.from(fileId).toString('hex'),
      firstChangeSet: changeRef,
      firstOperation: 0,
      origin: 'native-create'
    }],
    allocations: [{ after, operation, code: 1, sequence: 0 }]
  }), error('SCHEMA_FIELD_INVALID', 1));
});

test('fixture group role sets reject registered-but-unlisted roles', async () => {
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const groupProfile = new ProfileRef('fixture-group.opengamevcs.test', 'site', 2);
  const allowedRole = new ProfileRef('fixture-role.opengamevcs.test', 'primary', 2);
  const extraRole = new ProfileRef('fixture-role.opengamevcs.test', 'member', 2);
  const primary = new FileId(new Uint8Array(16).fill(0x11));
  const extra = new FileId(new Uint8Array(16).fill(0x22));
  const group = new Map([
    [0, new Uint8Array(16).fill(0x33)],
    [1, groupProfile.toMap()],
    [2, primary.bytes],
    [3, [
      new Map([[0, primary.bytes], [1, allowedRole.toMap()]]),
      new Map([[0, extra.bytes], [1, extraRole.toMap()]])
    ]],
    [4, []]
  ]);
  const rules = new Map([[groupProfile.toString(), {
    roles: [[allowedRole.toString(), 1, 1]]
  }]]);

  assert.throws(() => validateAssetGroups(
    [group], new Set([primary.toString(), extra.toString()]), {
      groupProfileRules: rules,
      registry,
      mode: 'conformance'
    }
  ), error('GROUP_REQUIRED_ROLE_MISSING', 3));
});

test('registered path profile semantics run after core joined-path validation', async () => {
  const loaded = await loadScenario('tree-path-profile');
  const tree = loaded.scenario.context.objectLookup.find(item =>
    item.artifact.path.includes('/tree-path-profile/tree.cbor')
  ).ref;
  assert.throws(() => expandTree(
    tree, loaded.lookup, loaded.scenario.context.repositoryDescriptor, { caseMode: 'case-sensitive' }
  ), error('PATH_PROFILE_INVALID', 3));
});
