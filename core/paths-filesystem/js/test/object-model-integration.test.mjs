import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  FileId, ObjectRef, ProfileRef, decodeMetadata, decodeSequence, encodeLogicalBundle,
  encodeMetadata, hashObject, loadBundledRegistry, verifyLogicalBundle,
} from '@opengamevcs/object-model';

import { objectModelPathProfileValidator } from '../src/object-model.mjs';
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
    const payload = encodeMetadata(tree, { semantic: false });
    const ref = hashObject(3, payload, { registry: registry.kindNames });
    const bundle = encodeLogicalBundle({
      objects: [...objects, { ref, payload }], logicalRecords,
      roots: [...roots, { kind: 1, identity: ref, role }],
    }, { registry, mode: 'conformance' });
    assert.equal(verifyLogicalBundle(bundle, { registry, mode: 'conformance' }).highestLayer, 2);
    return { bundle, entry, payload, ref };
  }

  assert.equal(evaluatePath('Content/Cafe\u0301.uasset', { caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1' }).error, 'PATH_NOT_NFC');
  assert.equal(objectModelPathProfileValidator({ profile: 'path.opengamevcs/portable@1', segments: ['Content', 'CON'] }).error, 'PATH_PLATFORM_FORBIDDEN');
  assert.equal(objectModelPathProfileValidator({ profile: 'path.opengamevcs/linux@1', segments: ['Content', 'CON'] }).accepted, true);
  const before = build('Café.uasset');
  const after = build('CAFÉ.uasset');
  assert.equal(new FileId(before.entry.get(2)).toString(), new FileId(after.entry.get(2)).toString());
  assert.notEqual(before.ref.toString(), after.ref.toString());
  assert.notDeepEqual(Buffer.from(before.payload), Buffer.from(after.payload));
  assert.notDeepEqual(Buffer.from(before.bundle), Buffer.from(after.bundle));
});
