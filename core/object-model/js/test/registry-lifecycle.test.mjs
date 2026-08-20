import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  OgvcsError, RegistrySnapshot, decodeCanonical, encodeMetadata, loadBundledRegistry,
  registryAssignmentDecision, validateRegistrySet
} from '../src/index.js';

const VECTORS = resolve(import.meta.dirname, '../../../../spec/repository-format/v1/vectors');
const error = code => value => value instanceof OgvcsError && value.code === code && value.layer === 3;

function registryWithExtension(live, state) {
  const documents = structuredClone(Object.fromEntries(live.documents));
  documents['extensions.json'].entries.push({
    namespace: 'extension-state.test', id: 'known', major: 1, state
  });
  return validateRegistrySet(documents);
}

test('registry assignment lifecycle implements every state-operation combination', () => {
  const operations = ['read', 'conformance', 'production-write'];
  const expected = new Map([
    ['ratified', [undefined, undefined, undefined]],
    ['deprecated', [undefined, undefined, 'PROFILE_STATE_FORBIDDEN']],
    ['conformance-only', ['PROFILE_CONFORMANCE_ONLY', undefined, 'PROFILE_CONFORMANCE_ONLY']],
    ['reserved', ['PROFILE_STATE_FORBIDDEN', 'PROFILE_STATE_FORBIDDEN', 'PROFILE_STATE_FORBIDDEN']]
  ]);
  let executed = 0;
  for (const [state, outcomes] of expected) {
    const registry = new RegistrySnapshot({
      extensions: [{ namespace: 'extension-state.test', id: 'known', major: 1, state }]
    });
    for (let index = 0; index < operations.length; index += 1) {
      const invoke = () => registryAssignmentDecision(
        registry, 'extensions', 'extension-state.test/known@1', operations[index]
      );
      if (outcomes[index] === undefined) assert.equal(invoke().state, state);
      else assert.throws(invoke, error(outcomes[index]));
      executed += 1;
    }
  }
  assert.equal(executed, 12);
});

test('the shared lifecycle primitive dispatches every assignment collection', () => {
  const registry = new RegistrySnapshot({
    objectKinds: [{ code: 1, name: 'chunk', state: 'ratified' }],
    hashAlgorithms: [{ code: 1, name: 'sha256', state: 'ratified' }],
    commonFields: [{ code: 0, name: 'format', state: 'ratified' }],
    kindFields: [{ cddlRule: 'content-manifest', code: 16, name: 'length', state: 'ratified' }],
    entryKinds: [{ code: 1, name: 'directory', state: 'ratified' }],
    entryModes: [{ code: 1, name: 'directory', state: 'ratified' }],
    requiredFeatures: [{ code: 1, name: 'feature', state: 'ratified' }],
    extensions: [{ namespace: 'extension-state.test', id: 'known', major: 1, state: 'ratified' }],
    profiles: [{ namespace: 'profile-state.test', id: 'known', major: 1,
      state: 'ratified', productionWriteAllowed: true }],
    logicalRecordTypes: [{ code: 1, name: 'root', state: 'ratified' }],
    semanticEnums: [{ name: 'operation', entries: [{ code: 1, name: 'create', state: 'ratified' }] }]
  });
  const selections = [
    ['object-kinds', 1], ['hash-algorithms', 1], ['common-fields', 0],
    ['kind-fields', 'content-manifest\0' + 16], ['entry-kinds', 1], ['entry-modes', 1],
    ['required-features', 1], ['extensions', 'extension-state.test/known@1'],
    ['profiles', 'profile-state.test/known@1'], ['logical-record-types', 1],
    ['semantic-enums/operation', 1]
  ];
  for (const [collection, key] of selections) {
    assert.equal(registryAssignmentDecision(registry, collection, key, 'production-write').state, 'ratified');
  }
  assert.equal(selections.length, 11);
});

test('metadata production writes enforce known extension lifecycle but preserve unknown optional extensions', async () => {
  const live = await loadBundledRegistry();
  const value = decodeCanonical(new Uint8Array(await readFile(resolve(
    VECTORS, 'objects/03-tree-child.cbor'
  ))));
  value.set(3, new Map([['extension-state.test/known@1', true]]));
  const deprecated = registryWithExtension(live, 'deprecated');
  assert.throws(() => encodeMetadata(value, {
    registry: deprecated, operation: 'production-write'
  }), error('PROFILE_STATE_FORBIDDEN'));
  assert.ok(encodeMetadata(value, { registry: deprecated, operation: 'conformance' }).length > 0);

  value.set(3, new Map([['extension-state.test/opaque@1', new Uint8Array([1, 2, 3])]]));
  assert.ok(encodeMetadata(value, {
    registry: deprecated, operation: 'production-write'
  }).length > 0);
});
