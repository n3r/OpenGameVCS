import assert from 'node:assert/strict';
import test from 'node:test';

import { ProtocolSchemaValidator, canonicalJson } from '../src/index.mjs';

const CHILD = {
  $id: 'https://schemas.opengamevcs.org/protocol/v1/child.schema.json',
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  additionalProperties: false,
  properties: {
    schemaVersion: { const: 'ogvcs.protocol/child/v1' },
    token: { type: 'string', minLength: 1, maxLength: 8, pattern: '^[a-z]+$', 'x-ogvcs-maxUtf8Bytes': 8 },
  },
  required: ['schemaVersion', 'token'],
};

const PARENT = {
  $id: 'https://schemas.opengamevcs.org/protocol/v1/parent.schema.json',
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  type: 'object',
  additionalProperties: false,
  properties: {
    schemaVersion: { const: 'ogvcs.protocol/parent/v1' },
    child: { $ref: CHILD.$id },
    values: { type: 'array', minItems: 1, maxItems: 3, uniqueItems: true, items: { type: 'integer', minimum: 0, maximum: 9 } },
    choice: { oneOf: [{ const: 'a' }, { const: 'b' }] },
  },
  required: ['schemaVersion', 'child', 'values', 'choice'],
};

test('verified schema set resolves names, ids, and schemaVersion values', () => {
  const validator = new ProtocolSchemaValidator({ 'child.schema.json': CHILD, 'parent.schema.json': PARENT });
  const value = {
    schemaVersion: 'ogvcs.protocol/parent/v1',
    child: { schemaVersion: 'ogvcs.protocol/child/v1', token: 'valid' },
    values: [1, 2],
    choice: 'a',
  };
  for (const selector of ['parent.schema.json', PARENT.$id, 'ogvcs.protocol/parent/v1']) {
    const result = validator.validate(value, selector);
    assert.equal(canonicalJson(result), canonicalJson(value));
    assert.equal(Object.isFrozen(result), true);
  }
});

test('closed schema rejects unknown, missing, duplicate, type, pattern and range faults', () => {
  const validator = new ProtocolSchemaValidator({ child: CHILD, parent: PARENT });
  const base = {
    schemaVersion: 'ogvcs.protocol/parent/v1',
    child: { schemaVersion: 'ogvcs.protocol/child/v1', token: 'valid' },
    values: [1, 2],
    choice: 'a',
  };
  for (const bad of [
    { ...base, unknown: true },
    { ...base, child: { schemaVersion: 'ogvcs.protocol/child/v1' } },
    { ...base, child: { ...base.child, token: 'INVALID' } },
    { ...base, values: [1, 1] },
    { ...base, values: [10] },
    { ...base, choice: 'c' },
  ]) assert.throws(() => validator.validate(bad, 'ogvcs.protocol/parent/v1'), (error) => error.code === 'PROTOCOL_INPUT_INVALID');
});

test('schema constructor fails closed on unsupported keywords and unresolved references', () => {
  assert.throws(() => new ProtocolSchemaValidator({ bad: { $id: 'urn:bad', type: 'string', mystery: true } }), /unsupported/u);
  assert.throws(() => new ProtocolSchemaValidator({ bad: { $id: 'urn:bad', $ref: 'urn:missing' } }), /unresolved/u);
});

test('schema validator owns an immutable bounded clone of the complete inventory', () => {
  const child = structuredClone(CHILD);
  const parent = structuredClone(PARENT);
  const inventory = new Map([['child', child], ['parent', parent]]);
  const validator = new ProtocolSchemaValidator(inventory);
  child.properties.token.maxLength = 1;
  parent.properties.values.items.maximum = 0;
  inventory.clear();
  assert.doesNotThrow(() => validator.validate({
    schemaVersion: 'ogvcs.protocol/parent/v1',
    child: { schemaVersion: 'ogvcs.protocol/child/v1', token: 'valid' },
    values: [1, 2],
    choice: 'a',
  }, 'parent'));
  const owned = validator.schema('parent');
  assert.equal(Object.isFrozen(owned), true);
  assert.equal(Object.isFrozen(owned.properties.values.items), true);
  assert.throws(() => { owned.properties.values.items.maximum = 0; }, TypeError);
});

test('recursive references stop at a bounded schema-evaluation ceiling', () => {
  const validator = new ProtocolSchemaValidator({ recursive: { $id: 'urn:recursive', $ref: '#' } });
  assert.throws(() => validator.validate(null, 'recursive'), /recursion ceiling/u);
});
