import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { OgvcsError } from '../src/errors.js';
import { encodeCanonical } from '../src/cbor.js';
import { hashObject, sha256Digest } from '../src/hash.js';
import { loadRegistryDirectory } from '../src/registry.js';
import { decodeMetadata } from '../src/schema.js';
import { ObjectRef, ProfileRef } from '../src/types.js';
import {
  RepositoryObjectLookup, expandTree, replayChangeSet, validateAbstractReferenceGraph,
  validateAssetGroups, validateConflictSet, validateImportRequest, validateLifetimeAndImports, validateProvenanceGraph,
  validateRepositoryCandidate, validateShelfRevision, validateSnapshotGraph, verifyManifest
} from '../src/repository.js';

const SPEC = resolve(import.meta.dirname, '../../../../spec/repository-format/v1');
const VECTORS = join(SPEC, 'vectors');
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const expectCode = (fn, code) => assert.throws(fn, error => error instanceof OgvcsError && error.code === code);

async function loadScenario(id) {
  const scenario = await json(join(VECTORS, `scenarios/cases/${id}.json`));
  const registry = await loadRegistryDirectory(join(SPEC, 'registries'));
  const entries = [];
  for (const item of scenario.context.objectLookup) entries.push([item.ref, new Uint8Array(await readFile(join(VECTORS, item.artifact.path)))]);
  const lookup = new RepositoryObjectLookup(entries, { registry, mode: scenario.context.mode, semanticProfiles: true });
  return { scenario, lookup, registry };
}

function repositoryContext(scenario, lookup) {
  return {
    lookup,
    descriptor: scenario.context.repositoryDescriptor,
    designatedRoot: scenario.context.designatedRoot,
    lifetimeRecords: scenario.context.lifetimeRecords,
    workingLifetimeAdditions: scenario.context.workingLifetimeAdditions,
    importMappings: scenario.context.importMappings,
    verifyContent: true
  };
}

test('typed object lookup verifies identity, expected kind, schema, and missing objects', async () => {
  const { scenario, lookup } = await loadScenario('transition-create');
  assert.equal(lookup.validateAll().size, scenario.context.objectLookup.length);
  assert.equal(lookup.resolve(scenario.context.repositoryDescriptor, 6).value.get(1), 6);
  expectCode(() => lookup.resolve(scenario.context.repositoryDescriptor, 7), 'OBJECT_REFERENCE_KIND_MISMATCH');
  expectCode(() => lookup.resolve('ogvcs:v1:tree:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'), 'OBJECT_REFERENCE_MISSING');
  const item = scenario.context.objectLookup[0]; const bytes = new Uint8Array(await readFile(join(VECTORS, item.artifact.path))); bytes[bytes.length - 1] ^= 1;
  const corrupt = new RepositoryObjectLookup([[item.ref, bytes]]);
  expectCode(() => corrupt.resolve(item.ref), 'OBJECT_ID_MISMATCH');
});

test('typed object lookup never exposes its decoded cache or retained payload by alias', async () => {
  const loaded = await loadScenario('transition-create');
  const candidate = loaded.scenario.context.candidateSnapshot;
  const first = loaded.lookup.resolve(candidate, 7);
  const originalRoot = encodeCanonical(first.value.get(18));
  const originalParentCount = first.value.get(17).length;
  first.payload.fill(0);
  first.value.set(18, new Map());
  first.value.get(17).push(new Map());

  const second = loaded.lookup.resolve(candidate, 7);
  assert.notStrictEqual(first.value, second.value);
  assert.notStrictEqual(first.payload, second.payload);
  assert.equal(second.value.get(1), 7);
  assert.equal(second.value.get(17).length, originalParentCount);
  assert.deepEqual(encodeCanonical(second.value.get(18)), originalRoot);
  assert.notEqual(second.payload.every(byte => byte === 0), true);
  assert.doesNotThrow(() => validateRepositoryCandidate(candidate, repositoryContext(loaded.scenario, loaded.lookup)));
});

test('duplicate repository inputs remain count- and time-bounded before coalescing', () => {
  const payload = Uint8Array.of(1, 2, 3);
  const reference = hashObject(1, payload);
  function* repeated() { while (true) yield [reference, payload]; }
  assert.throws(() => new RepositoryObjectLookup(repeated(), {
    maxObjects: 2, maxBytes: 1_000, maxMemoryBytes: 1_000_000
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_COUNT' &&
    error.stage === 'configured-resource-preflight');

  let ticks = 0;
  assert.throws(() => new RepositoryObjectLookup([
    [reference, payload], [reference, payload]
  ], {
    maxTimeMs: 1, now: () => ticks++, maxBytes: 1_000, maxMemoryBytes: 1_000_000
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_TIME');
});

test('manifest verification checks chunk lengths, logical sum, and whole-file digest', async () => {
  const { scenario, lookup } = await loadScenario('transition-create');
  const manifest = scenario.context.objectLookup.find(item => item.ref.includes(':content-manifest:')).ref;
  assert.deepEqual(verifyManifest(manifest, lookup), { logicalLength: 24n, chunks: 2 });
  const cases = [
    ['manifest-chunk-length', 'MANIFEST_CHUNK_LENGTH_INVALID'],
    ['manifest-length-sum-mismatch', 'MANIFEST_LENGTH_MISMATCH'],
    ['manifest-corrupt-chunk', 'MANIFEST_FILE_DIGEST_MISMATCH']
  ];
  for (const [id, code] of cases) {
    const loaded = await loadScenario(id); const candidate = loaded.scenario.context.objectLookup.find(item => item.ref.includes(':content-manifest:')).ref;
    assert.throws(() => verifyManifest(candidate, loaded.lookup), error => error instanceof OgvcsError && error.code === code &&
      (id !== 'manifest-length-sum-mismatch' || error.layer === 2), id);
  }
});

test('manifest hashing discards resolved payloads between parts', () => {
  const partCount = 32;
  const partBytes = 64;
  const expected = new Uint8Array(partCount * partBytes);
  const references = [];
  const byReference = new Map();
  for (let index = 0; index < partCount; index++) {
    expected.fill(index + 1, index * partBytes, (index + 1) * partBytes);
    const reference = new ObjectRef(1, new Uint8Array(32).fill(index + 1));
    references.push(reference);
    byReference.set(reference.toString(), index + 1);
  }
  const manifest = new Map([
    [16, expected.length], [17, sha256Digest(expected).toMap()],
    [19, references.map(reference => new Map([[0, reference.toMap()], [1, partBytes]]))]
  ]);
  const manifestReference = new ObjectRef(2, new Uint8Array(32).fill(0xf0));
  const shared = new Uint8Array(partBytes);
  const lookup = {
    hardLimits: {}, checkpoint() {},
    resolve(value, kind) {
      const reference = value instanceof ObjectRef ? value : ObjectRef.fromMap(value);
      if (kind === 2) return { value: manifest };
      const fill = byReference.get(reference.toString());
      assert.ok(fill);
      shared.fill(fill);
      return { payload: shared };
    },
    edge(value, kind) { return this.resolve(value, kind); }
  };
  assert.deepEqual(verifyManifest(manifestReference, lookup), {
    logicalLength: BigInt(expected.length), chunks: partCount
  });
});

test('tree expansion binds descriptors and rejects duplicate FileIDs globally', async () => {
  const valid = await loadScenario('transition-create'); const snapshot = valid.lookup.resolve(valid.scenario.context.candidateSnapshot, 7).value;
  const expanded = expandTree(snapshot.get(18), valid.lookup, valid.scenario.context.repositoryDescriptor);
  assert.equal(expanded.entries.size, 1); assert.equal(expanded.fileIds.size, 1);
  const duplicate = await loadScenario('fileid-duplicate-expanded-tree');
  const duplicateTree = duplicate.scenario.context.objectLookup.find(item => item.ref.includes(':tree:')).ref;
  expectCode(() => expandTree(duplicateTree, duplicate.lookup, duplicate.scenario.context.repositoryDescriptor), 'FILEID_DUPLICATE_IN_TREE');

  for (const [id, code, artifact] of [
    ['fileid-zero', 'FILEID_ZERO', '/tree.cbor'],
    ['tree-entry-order', 'TREE_ENTRY_ORDER_INVALID', '/tree.cbor'],
    ['tree-entry-target', 'TREE_ENTRY_TARGET_INVALID', '/tree.cbor']
  ]) {
    const loaded = await loadScenario(id);
    const tree = loaded.scenario.context.objectLookup.find(item => item.artifact.path.endsWith(artifact) &&
      item.artifact.path.includes(`/${id}/`)).ref;
    assert.throws(
      () => loaded.lookup.resolve(tree, 3),
      error => error instanceof OgvcsError && error.code === code && error.layer === 2,
      id
    );
  }

  const tooLong = await loadScenario('tree-path-core');
  const root = tooLong.scenario.context.objectLookup.find(item => item.artifact.path.endsWith('/path-00.cbor')).ref;
  assert.throws(
    () => expandTree(root, tooLong.lookup, tooLong.scenario.context.repositoryDescriptor),
    error => error instanceof OgvcsError && error.code === 'PATH_CORE_INVALID' && error.layer === 3,
    'tree-path-core'
  );
});

test('expanded tree paths enforce the core segment-count and joined-byte ceilings', () => {
  const reference = (kind, serial) => {
    const digest = new Uint8Array(32);
    new DataView(digest.buffer).setUint32(28, serial, false);
    return new ObjectRef(kind, digest);
  };
  const fileId = serial => {
    const bytes = new Uint8Array(16);
    new DataView(bytes.buffer).setUint32(12, serial, false);
    return bytes;
  };
  const descriptor = reference(6, 1);
  const contentPolicy = new ProfileRef('content-policy.test', 'opaque', 1).toMap();
  const descriptorValue = new Map([[18, [contentPolicy]], [19, []], [20, []]]);
  const makeLookup = segments => {
    const trees = segments.map((_segment, index) => reference(3, index + 2));
    const values = new Map(); const leaf = reference(3, 1_000_000);
    for (let index = segments.length - 1; index >= 0; index--) {
      const child = index + 1 < trees.length ? trees[index + 1] : leaf;
      const entry = new Map([[0, segments[index]], [1, 1], [2, fileId(index + 1)],
        [3, 1], [4, child.toMap()], [5, 0], [6, contentPolicy]]);
      values.set(trees[index].toString(), new Map([[16, descriptor.toMap()], [17, [entry]]]));
    }
    values.set(leaf.toString(), new Map([[16, descriptor.toMap()], [17, []]]));
    return {
      root: trees[0],
      lookup: {
        resolve(value, kind) {
          const parsed = value instanceof ObjectRef ? value : ObjectRef.fromMap(value);
          if (kind === 6) return { value: descriptorValue };
          return { value: values.get(parsed.toString()) };
        },
        edge(value, kind) { return this.resolve(value, kind); }
      }
    };
  };
  const tooDeep = makeLookup(Array.from({ length: 257 }, (_value, index) => `d${index}`));
  expectCode(() => expandTree(tooDeep.root, tooDeep.lookup, descriptor), 'PATH_CORE_INVALID');
  const tooLong = makeLookup(Array.from({ length: 17 }, () => 'x'.repeat(255)));
  expectCode(() => expandTree(tooLong.root, tooLong.lookup, descriptor), 'PATH_CORE_INVALID');
  const bounded = makeLookup(['bounded']);
  expectCode(() => expandTree(bounded.root, bounded.lookup, descriptor, {
    maxMemoryBytes: 512
  }), 'LIMIT_MEMORY');
});

test('snapshot parent/root/base validation covers roots, merges, missing and cross-repository parents', async () => {
  for (const id of ['history-zero-parent-root','history-one-parent','history-two-parent','history-eight-parent']) {
    const loaded = await loadScenario(id); assert.ok(validateSnapshotGraph(loaded.scenario.context.candidateSnapshot, repositoryContext(loaded.scenario, loaded.lookup)).visited.size >= 1);
  }
  for (const [id,code,layer] of [['history-base-mismatch','CHANGESET_BASE_MISMATCH',3],['history-second-root','SNAPSHOT_ROOT_INVALID',3],['history-missing-parent','OBJECT_REFERENCE_MISSING',2],['history-duplicate-parent','SNAPSHOT_PARENT_DUPLICATE',2],['history-ninth-parent','SNAPSHOT_PARENT_COUNT_INVALID',2],['history-cross-repository-parent','SNAPSHOT_PARENT_CROSS_REPOSITORY',3]]) {
    const loaded = await loadScenario(id);
    assert.throws(
      () => validateSnapshotGraph(loaded.scenario.context.candidateSnapshot, repositoryContext(loaded.scenario, loaded.lookup)),
      error => error instanceof OgvcsError && error.code === code && error.layer === layer,
      id
    );
  }
});

test('all exact operation families replay to their declared snapshot state', async () => {
  const ids = ['transition-create','transition-modify','transition-copy','transition-move','transition-rename','transition-delete','transition-restore','transition-group-create','transition-group-update','transition-group-delete','transition-merge-resolution'];
  for (const id of ids) {
    const loaded = await loadScenario(id); let result; try { result = validateRepositoryCandidate(loaded.scenario.context.candidateSnapshot, repositoryContext(loaded.scenario, loaded.lookup)); } catch (error) { assert.fail(`${id}: ${error.code}`); } assert.equal(result.highestLayer, 3, id);
  }
});

test('replay rejects sequence, source, result, restore, and reuse failures with stable codes', async () => {
  const cases = [['transition-sequence-gap','CHANGESET_SEQUENCE_INVALID'],['fileid-move-source-forgery','FILEID_SOURCE_MISMATCH'],['transition-exact-result-mismatch','CHANGESET_RESULT_MISMATCH'],['fileid-restore-invalid-ancestry','FILEID_RESTORE_PROOF_INVALID'],['fileid-restore-source-forgery','FILEID_RESTORE_PROOF_INVALID'],['fileid-create-reuse','FILEID_ALREADY_CONSUMED'],['fileid-copy-reuse','FILEID_ALREADY_CONSUMED'],['fileid-cross-repository-proof','FILEID_CROSS_REPOSITORY_PROOF']];
  for (const [id,code] of cases) { const loaded=await loadScenario(id); assert.throws(()=>validateRepositoryCandidate(loaded.scenario.context.candidateSnapshot,repositoryContext(loaded.scenario,loaded.lookup)),error=>error instanceof OgvcsError&&error.code===code, id); }
});

test('lifetime/import evidence enforces origin coupling, mapping retry, and immutable working additions', async () => {
  const loaded = await loadScenario('transition-create'); const ctx = repositoryContext(loaded.scenario,loaded.lookup); const snapshot=loaded.lookup.resolve(loaded.scenario.context.candidateSnapshot,7).value;const change=loaded.lookup.resolve(snapshot.get(19),4).value;
  const base={entries:new Map(),groups:new Map()};const replayed=replayChangeSet(snapshot.get(19),base,ctx);assert.equal(replayed.allocations.length,1);
  expectCode(()=>validateLifetimeAndImports({...ctx,changeSetReference:snapshot.get(19),allocations:replayed.allocations,workingLifetimeAdditions:[]}), 'FILEID_LIFETIME_EVIDENCE_INVALID');
  const conflicting={...loaded.scenario.context.workingLifetimeAdditions[0],origin:'native-copy'};
  expectCode(()=>validateLifetimeAndImports({...ctx,changeSetReference:snapshot.get(19),allocations:replayed.allocations,workingLifetimeAdditions:[conflicting]}), 'FILEID_LIFETIME_EVIDENCE_INVALID');
  assert.equal(change.get(18)[0].get(1),1);

  const descriptor = new ObjectRef(6, new Uint8Array(32).fill(0x61));
  const changeSet = new ObjectRef(4, new Uint8Array(32).fill(0x62));
  const allocation = (byte, sequence) => ({
    after: new Map([[2, new Uint8Array(16).fill(byte)]]),
    code: 1,
    operation: new Map([[5, new Map([[0, descriptor.toMap()], [1, 1]])]]),
    sequence
  });
  const additions = [
    { fileId: '11'.repeat(16), firstChangeSet: changeSet.toString(), firstOperation: 1, origin: 'native-create' },
    { fileId: '22'.repeat(16), firstChangeSet: changeSet.toString(), firstOperation: 0, origin: 'native-create' }
  ];
  const orderedIndependently = validateLifetimeAndImports({
    allocations: [allocation(0x22, 0), allocation(0x11, 1)],
    changeSetReference: changeSet,
    descriptor,
    workingLifetimeAdditions: additions
  });
  assert.equal(orderedIndependently.working.length, 2);
  expectCode(() => validateLifetimeAndImports({
    allocations: [allocation(0x22, 0)],
    changeSetReference: changeSet,
    descriptor,
    workingLifetimeAdditions: [additions[1], additions[1]]
  }), 'FILEID_LIFETIME_EVIDENCE_INVALID');

  const deleting = await loadScenario('transition-delete');
  const deletingContext = repositoryContext(deleting.scenario, deleting.lookup);
  assert.ok(deletingContext.lifetimeRecords.length > 0);
  expectCode(() => validateRepositoryCandidate(
    deleting.scenario.context.candidateSnapshot,
    { ...deletingContext, lifetimeRecords: [] }
  ), 'FILEID_LIFETIME_EVIDENCE_INVALID');
});

test('conflict subjects, choices, custom driver, publication, and replay equality are mechanical', async () => {
  {const loaded=await loadScenario('conflict-mode-resolved');expectCode(()=>validateRepositoryCandidate(loaded.scenario.context.candidateSnapshot,repositoryContext(loaded.scenario,loaded.lookup)),'SCHEMA_FIELD_INVALID');}
  {const loaded=await loadScenario('conflict-id-mismatch');const conflict=loaded.scenario.context.objectLookup.find(item=>item.ref.includes(':conflict-set:')).ref;assert.throws(()=>validateConflictSet(conflict,loaded.lookup,loaded.scenario.context.repositoryDescriptor),error=>error instanceof OgvcsError&&error.code==='CONFLICT_ID_MISMATCH'&&error.layer===2);}
  for (const id of ['conflict-content-resolved','conflict-divergent-move-resolved','conflict-delete-modify-resolved','conflict-type-resolved','conflict-policy-resolved','conflict-group-resolved','conflict-path-collision-resolved','conflict-choice-base','conflict-choice-left','conflict-choice-right','conflict-choice-custom','conflict-custom-driver','conflict-choice-delete']) {
    const loaded=await loadScenario(id);let result;try{result=validateRepositoryCandidate(loaded.scenario.context.candidateSnapshot,repositoryContext(loaded.scenario,loaded.lookup));}catch(error){assert.fail(`${id}: ${error.code}`);}assert.equal(result.highestLayer,3,id);
  }
  {const loaded=await loadScenario('conflict-policy-resolved');const snapshot=loaded.lookup.resolve(loaded.scenario.context.candidateSnapshot,7).value;const set=loaded.lookup.resolve(snapshot.get(28),11).value;const record=set.get(17).find(item=>item.get(1)===6);const left=record.get(4).get(1).get(6);const right=record.get(5).get(1).get(6);assert.notDeepEqual(left,right);assert.ok([left,right].some(profile=>profile.get(1)==='alternate'));}
  for(const [id,code] of [['conflict-unresolved-published','CONFLICT_UNRESOLVED_PUBLISHED'],['conflict-resolution-mismatch','CONFLICT_RESOLUTION_MISMATCH']]){const loaded=await loadScenario(id);expectCode(()=>validateRepositoryCandidate(loaded.scenario.context.candidateSnapshot,repositoryContext(loaded.scenario,loaded.lookup)),code);}
});

test('group validation enforces membership, profile cardinality, and unique external keys', async () => {
  for(const [id,code] of [['group-member-invalid','GROUP_MEMBER_INVALID'],['group-membership-overlap','GROUP_MEMBERSHIP_OVERLAP'],['group-required-role-missing','GROUP_REQUIRED_ROLE_MISSING'],['group-external-key-duplicate','GROUP_EXTERNAL_KEY_DUPLICATE']]){const loaded=await loadScenario(id);assert.throws(()=>validateRepositoryCandidate(loaded.scenario.context.candidateSnapshot,repositoryContext(loaded.scenario,loaded.lookup)),error=>error instanceof OgvcsError&&error.code===code,id);}
  assert.equal(typeof validateAssetGroups,'function');
});

test('import retries require coherent immutable mapping and lifetime evidence', async () => {
  for(const [id,code] of [['fileid-import-lost-ack-retry',null],['fileid-import-conflict','FILEID_IMPORT_MAPPING_CONFLICT'],['fileid-import-native-collision','FILEID_IMPORT_MAPPING_CONFLICT']]){
    const loaded=await loadScenario(id);const artifact=loaded.scenario.inputs.find(item=>item.path.includes('/operations/'));const request=await json(join(VECTORS,artifact.path));const context=repositoryContext(loaded.scenario,loaded.lookup);
    if(code)expectCode(()=>validateImportRequest(request,context),code);else{const result=validateImportRequest(request,context);assert.equal(result.retry,true);assert.equal(result.fileId,`fid:${request.requestedFileId}`);}
  }

  const inFlight = await loadScenario('transition-create');
  const inFlightContext = repositoryContext(inFlight.scenario, inFlight.lookup);
  assert.equal(inFlightContext.workingLifetimeAdditions.length, 1);
  const unrelatedRequest = {
    schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
    operation: 'import-file-id',
    importerProfile: 'importer.test/fixture-adapter@1',
    sourceNamespaceDigest: '71'.repeat(32),
    sourceIdentityDigest: '72'.repeat(32),
    requestedFileId: '73'.repeat(16)
  };
  const fresh = validateImportRequest(unrelatedRequest, inFlightContext);
  assert.equal(fresh.retry, false);
  assert.equal(fresh.fileId, `fid:${unrelatedRequest.requestedFileId}`);
  expectCode(() => validateImportRequest({
    ...unrelatedRequest,
    requestedFileId: inFlightContext.workingLifetimeAdditions[0].fileId
  }, inFlightContext), 'FILEID_IMPORT_MAPPING_CONFLICT');
  expectCode(() => validateImportRequest(unrelatedRequest, {
    ...inFlightContext,
    workingLifetimeAdditions: [inFlightContext.workingLifetimeAdditions[0], inFlightContext.workingLifetimeAdditions[0]]
  }), 'FILEID_LIFETIME_EVIDENCE_INVALID');
});

test('configured graph guards fail with stable resource codes', async () => {
  const loaded=await loadScenario('transition-create');const item=loaded.scenario.context.objectLookup[0];const bytes=new Uint8Array(await readFile(join(VECTORS,item.artifact.path)));
  expectCode(()=>new RepositoryObjectLookup([[item.ref,bytes]],{maxObjects:0}).resolve(item.ref),'LIMIT_COUNT');
  expectCode(()=>new RepositoryObjectLookup([[item.ref,bytes]],{maxBytes:0}).resolve(item.ref),'LIMIT_MEMORY');
  expectCode(()=>new RepositoryObjectLookup([[item.ref,bytes]],{maxMemoryBytes:0,memoryBytes:()=>1}).resolve(item.ref),'LIMIT_MEMORY');
  expectCode(()=>new RepositoryObjectLookup([[item.ref,bytes]],{maxScratchBytes:0,scratchBytes:()=>1}).resolve(item.ref),'LIMIT_SCRATCH');
  let tick=0;expectCode(()=>new RepositoryObjectLookup([[item.ref,bytes]],{maxTimeMs:0,now:()=>tick++}).resolve(item.ref),'LIMIT_TIME');
  let clock = 0; const cached = new RepositoryObjectLookup([[item.ref, bytes]], { maxTimeMs: 0, now: () => clock }); cached.resolve(item.ref); clock = 1;
  assert.throws(() => cached.resolve(item.ref), error => error instanceof OgvcsError && error.code === 'LIMIT_TIME' && error.layer === 1);
  const chunk=loaded.scenario.context.objectLookup.find(entry=>entry.ref.includes(':chunk:'));const chunkBytes=new Uint8Array(await readFile(join(VECTORS,chunk.artifact.path)));expectCode(()=>new RepositoryObjectLookup([[chunk.ref,chunkBytes]],{maxChunkBytes:0}).resolve(chunk.ref),'LIMIT_CHUNK_BYTES');
});

test('shelf chains, unresolved conflicts, and provenance graphs enforce their graph rules', async () => {
  {const loaded=await loadScenario('shelf-revision-chain');const shelf=loaded.scenario.context.objectLookup.find(item=>item.ref.includes(':shelf-revision:')).ref;const descriptor=loaded.lookup.resolve(shelf,8).value.get(16);assert.ok(validateShelfRevision(shelf,{...repositoryContext(loaded.scenario,loaded.lookup),descriptor}).revision>=1);}
  {const loaded=await loadScenario('shelf-chain-invalid');const shelf=loaded.scenario.context.objectLookup.find(item=>item.ref.includes(':shelf-revision:')).ref;const descriptor=loaded.lookup.resolve(shelf,8).value.get(16);expectCode(()=>validateShelfRevision(shelf,{...repositoryContext(loaded.scenario,loaded.lookup),descriptor}),'SHELF_CHAIN_INVALID');}
  for (const id of ['conflict-content-unresolved-shelf','conflict-divergent-move-unresolved-shelf',
    'conflict-delete-modify-unresolved-shelf','conflict-type-unresolved-shelf',
    'conflict-policy-unresolved-shelf','conflict-group-unresolved-shelf','conflict-path-collision-unresolved-shelf']) {
    const loaded = await loadScenario(id);
    const shelf = loaded.scenario.context.objectLookup.find(item => item.artifact.path.endsWith('/unresolved-shelf.cbor')).ref;
    const descriptor = loaded.lookup.resolve(shelf, 8).value.get(16);
    assert.equal(validateShelfRevision(shelf, { ...repositoryContext(loaded.scenario, loaded.lookup), descriptor }).revision, 1, id);
  }
  const provenance=await loadScenario('provenance-acyclic');const snapshot=provenance.lookup.resolve(provenance.scenario.context.candidateSnapshot,7).value;assert.ok(validateProvenanceGraph(snapshot.get(27),provenance.lookup).visited.size>=1);

  const candidate = ObjectRef.parse(provenance.scenario.context.candidateSnapshot);
  const attestationValue = decodeMetadata(new Uint8Array(await readFile(join(VECTORS, 'objects/10-attestation.cbor'))), { semantic: false }).value;
  attestationValue.set(16, candidate.toMap());
  const attestationBytes = encodeCanonical(attestationValue);
  const attestationRef = hashObject(10, attestationBytes);
  const provenanceValue = decodeMetadata(new Uint8Array(await readFile(join(VECTORS, 'objects/09-provenance.cbor'))), { semantic: false }).value;
  provenanceValue.set(17, [attestationRef.toMap()]);
  const provenanceBytes = encodeCanonical(provenanceValue);
  const provenanceRef = hashObject(9, provenanceBytes);
  const backlinkLookup = new RepositoryObjectLookup(
    [[attestationRef, attestationBytes], [provenanceRef, provenanceBytes]],
    { registry: provenance.registry, mode: 'conformance', semanticProfiles: true }
  );
  assert.throws(
    () => validateProvenanceGraph([provenanceRef], backlinkLookup, { forbidden: [candidate] }),
    error => error instanceof OgvcsError && error.code === 'PROVENANCE_CYCLE' && error.layer === 3
  );
});

test('object-local attestation coupling is rejected at layer two', async () => {
  const loaded = await loadScenario('attestation-signature-shape');
  const attestation = loaded.scenario.context.objectLookup.find(item =>
    item.artifact.path.includes('/attestation-signature-shape/')
  ).ref;
  assert.throws(
    () => loaded.lookup.resolve(attestation, 10),
    error => error instanceof OgvcsError && error.code === 'ATTESTATION_SIGNATURE_SHAPE_INVALID' && error.layer === 2
  );
});

test('abstract reference graphs exercise bounded cycle detection without fake object bytes', async () => {
  for(const [id,code] of [['history-parent-cycle','SNAPSHOT_PARENT_CYCLE'],['provenance-cycle','PROVENANCE_CYCLE']]){const scenario=await json(join(VECTORS,`scenarios/cases/${id}.json`));const artifact=scenario.inputs.find(item=>item.mediaType.includes('abstract-reference-graph'));const graph=await json(join(VECTORS,artifact.path));expectCode(()=>validateAbstractReferenceGraph(graph,{maxEdges:10}),code);}
  const acyclic={schemaVersion:'ogvcs.repository-format/abstract-reference-graph/v1',assumedValidation:'canonical-framing-schema-and-identity-prevalidated',graphKind:'snapshot-parent',roots:['node-a'],nodes:[{id:'node-a',type:'snapshot',edges:[]}]};assert.deepEqual(validateAbstractReferenceGraph(acyclic),{highestLayer:3,nodes:1,edges:0});

  const unreachableEdge = {
    schemaVersion: 'ogvcs.repository-format/abstract-reference-graph/v1',
    assumedValidation: 'canonical-framing-schema-and-identity-prevalidated',
    graphKind: 'snapshot-parent', roots: ['node-a'],
    nodes: [
      { id: 'node-a', type: 'snapshot', edges: [] },
      { id: 'node-b', type: 'snapshot', edges: [{ kind: 'parent', target: 'node-c' }] },
      { id: 'node-c', type: 'snapshot', edges: [] }
    ]
  };
  expectCode(() => validateAbstractReferenceGraph(unreachableEdge, { maxEdges: 0 }), 'LIMIT_COUNT');
  let tick = 0;
  expectCode(() => validateAbstractReferenceGraph(unreachableEdge, {
    maxTimeMs: 3, now: () => tick++
  }), 'LIMIT_TIME');
  expectCode(() => validateAbstractReferenceGraph(unreachableEdge, {
    maxMemoryBytes: 1_600
  }), 'LIMIT_MEMORY');
});
