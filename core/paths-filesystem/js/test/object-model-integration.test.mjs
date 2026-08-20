import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  FileId, ObjectRef, ProfileRef, RepositoryObjectLookup, compareCanonicalBytes,
  decodeMetadata, decodeSequence, encodeCanonical, encodeLogicalBundle, encodeMetadata,
  expandTree, hashObject, loadBundledRegistry, verifyLogicalBundle,
} from '@opengamevcs/object-model';

import {
  createObjectModelPathProfileAdapter, objectModelPathProfileValidator
} from '../src/object-model.mjs';
import { evaluatePath } from '../src/path.mjs';

const BUNDLE = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors/logical-bundles/valid-all-families.cborseq');

test('case and Unicode rename round-trips canonical trees and bundles with FileID preserved', async () => {
  const registry = await loadBundledRegistry();
  const { values } = decodeSequence(await readFile(BUNDLE), { maxValueBytes: 536_871_424 });
  const objects = values.filter((item) => item.get(1) === 2).map((item) => ({ ref: ObjectRef.fromMap(item.get(3)), payload: item.get(4) }));
  const logicalRecords = values.filter((item) => item.get(1) === 3).map((item) => item.get(4));
  const roots = values.filter((item) => item.get(1) === 4).map((item) => ({
    kind: item.get(3), identity: item.get(3) === 1 ? ObjectRef.fromMap(item.get(4)) : item.get(4), role: ProfileRef.fromMap(item.get(5)),
  }));
  const baseObject = objects.find(({ ref, payload }) => ref.kind === 3 && decodeMetadata(payload, { semantic: false }).value.get(17).length === 4);
  const baseTree = decodeMetadata(baseObject.payload, { semantic: false }).value;
  const role = new ProfileRef('bundle-role.test', 'root', 1);

  function build(name) {
    const tree = structuredClone(baseTree);
    const entry = structuredClone(tree.get(17)[1]);
    entry.set(0, name);
    tree.set(17, [entry]);
    const payload = encodeMetadata(tree, { registry, operation: 'conformance' });
    const ref = hashObject(3, payload, { registry: registry.kindNames });
    const canonicalCompare = (left, right) => compareCanonicalBytes(
      encodeCanonical(left), encodeCanonical(right)
    );
    const orderedObjects = [...objects, { ref, payload }].sort((left, right) =>
      canonicalCompare(left.ref.toMap(), right.ref.toMap()));
    const orderedRoots = [...roots, { kind: 1, identity: ref, role }].sort((left, right) => {
      if (left.kind !== right.kind) return left.kind - right.kind;
      const identity = canonicalCompare(
        left.identity?.toMap?.() ?? left.identity,
        right.identity?.toMap?.() ?? right.identity
      );
      return identity || canonicalCompare(left.role.toMap(), right.role.toMap());
    });
    const bundle = encodeLogicalBundle({
      objects: orderedObjects, logicalRecords, roots: orderedRoots,
    }, { registry, operation: 'conformance' });
    assert.equal(verifyLogicalBundle(bundle, { registry, operation: 'conformance' }).highestLayer, 3);
    return { bundle, entry, payload, ref };
  }

  assert.equal(evaluatePath('Content/Cafe\u0301.uasset', { caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1' }).error, 'PATH_NOT_NFC');
  assert.deepEqual(objectModelPathProfileValidator({
    profile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive', segments: ['Content', 'CON']
  }), { accepted: false });
  assert.equal(objectModelPathProfileValidator({
    profile: 'path.opengamevcs/linux@1', caseMode: 'case-sensitive', segments: ['Content', 'CON']
  }).accepted, true);
  const folded = createObjectModelPathProfileAdapter({
    profile: 'path.opengamevcs/linux@1', caseMode: 'case-folded'
  });
  assert.equal(folded.validate({
    profile: folded.profile, caseMode: folded.caseMode, segments: ['Content', 'Hero']
  }).accepted, true);
  const before = build('Café.uasset');
  const after = build('CAFÉ.uasset');
  assert.equal(new FileId(before.entry.get(2)).toString(), new FileId(after.entry.get(2)).toString());
  assert.notEqual(before.ref.toString(), after.ref.toString());
  assert.notDeepEqual(Buffer.from(before.payload), Buffer.from(after.payload));
  assert.notDeepEqual(Buffer.from(before.bundle), Buffer.from(after.bundle));
});

test('the pinned OGVCS-004 adapter drives real object-model tree expansion', async () => {
  const registry = await loadBundledRegistry();
  const descriptor = decodeMetadata(new Uint8Array(await readFile(resolve(
    import.meta.dirname, '../../../../spec/repository-format/v1/vectors/objects/06-repository-descriptor.cbor'
  ))), { semantic: false }).value;
  descriptor.set(17, new ProfileRef('path.opengamevcs', 'linux', 1).toMap());
  const descriptorPayload = encodeMetadata(descriptor, { registry, operation: 'conformance' });
  const descriptorRef = hashObject(6, descriptorPayload, { registry: registry.kindNames });
  const seed = decodeMetadata(new Uint8Array(await readFile(resolve(
    import.meta.dirname, '../../../../spec/repository-format/v1/vectors/objects/03-tree.cbor'
  ))), { semantic: false }).value;
  const nondirectory = seed.get(17).find(entry => entry.get(1) !== 1);
  const manifestPayload = new Uint8Array(await readFile(resolve(
    import.meta.dirname, '../../../../spec/repository-format/v1/vectors/objects/02-content-manifest.cbor'
  )));
  const manifestRef = ObjectRef.fromMap(nondirectory.get(4));
  const treeValue = entries => new Map([
    [0, 1], [1, 3], [2, []], [16, descriptorRef.toMap()], [17, entries]
  ]);
  const makeEntry = (name, fill) => {
    const entry = structuredClone(nondirectory);
    entry.set(0, name);
    entry.set(2, new Uint8Array(16).fill(fill));
    return entry;
  };
  const invoke = (entries, adapter, caseMode) => {
    const tree = treeValue(entries);
    const payload = encodeMetadata(tree, { registry, operation: 'conformance' });
    const treeRef = hashObject(3, payload, { registry: registry.kindNames });
    const lookup = new RepositoryObjectLookup([
      [descriptorRef, descriptorPayload], [treeRef, payload], [manifestRef, manifestPayload]
    ], { registry, mode: 'conformance', semanticProfiles: true });
    return expandTree(treeRef, lookup, descriptorRef, {
      caseMode, validatePathProfile: adapter, verifyContent: false
    });
  };
  const sensitive = createObjectModelPathProfileAdapter({
    profile: 'path.opengamevcs/linux@1', caseMode: 'case-sensitive'
  });
  assert.equal(invoke([], sensitive, 'case-sensitive').entries.size, 0);
  assert.equal(invoke([makeEntry('A', 1), makeEntry('a', 2)], sensitive, 'case-sensitive').entries.size, 2);
  const folded = createObjectModelPathProfileAdapter({
    profile: 'path.opengamevcs/linux@1', caseMode: 'case-folded'
  });
  assert.throws(() => invoke([makeEntry('A', 1), makeEntry('a', 2)], folded, 'case-folded'),
    error => error?.code === 'PATH_PROFILE_INVALID');
  assert.throws(() => invoke([makeEntry('safe', 3)], undefined, 'case-sensitive'),
    error => error?.code === 'PATH_PROFILE_INVALID');
  assert.throws(() => invoke([makeEntry('safe', 3)], folded, 'case-sensitive'),
    error => error?.code === 'PATH_PROFILE_INVALID');
  assert.throws(() => invoke([], sensitive, undefined), error =>
    error?.code === 'SCHEMA_FIELD_INVALID' && error.layer === 1);
});
