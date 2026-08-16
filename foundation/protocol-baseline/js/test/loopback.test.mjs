import assert from 'node:assert/strict';
import test from 'node:test';

import { BoundedLoopbackServer, createBoundedLoopback, ProtocolSchemaValidator } from '../src/index.mjs';

const requestSchema = {
  $id: 'https://schemas.opengamevcs.org/protocol/v1/request-envelope.schema.json',
  type: 'object', additionalProperties: false,
  properties: { schemaVersion: { const: 'ogvcs.protocol/request/v1' }, value: { type: 'integer' } },
  required: ['schemaVersion', 'value'],
};
const responseSchema = {
  $id: 'https://schemas.opengamevcs.org/protocol/v1/response-envelope.schema.json',
  type: 'object', additionalProperties: false,
  properties: { schemaVersion: { const: 'ogvcs.protocol/response/v1' }, value: { type: 'integer' } },
  required: ['schemaVersion', 'value'],
};
const contract = { validator: new ProtocolSchemaValidator(new Map([
  ['request-envelope.schema.json', requestSchema],
  ['response-envelope.schema.json', responseSchema],
])) };
const schemaOptions = { requestSchema: 'request-envelope.schema.json', responseSchema: 'response-envelope.schema.json' };

test('bounded loopback serializes across the public envelope boundary', async () => {
  let calls = 0;
  const { client } = createBoundedLoopback({ contract, ...schemaOptions, handler: async (request) => {
    calls += 1;
    return { schemaVersion: 'ogvcs.protocol/response/v1', value: request.value + 1 };
  } });
  const response = await client.call({ value: 1, schemaVersion: 'ogvcs.protocol/request/v1' });
  assert.equal(response.value, 2);
  assert.equal(calls, 1);
});

test('malformed, duplicate, unknown, and oversized requests never reach the handler', async () => {
  let calls = 0;
  const server = new BoundedLoopbackServer({ contract, ...schemaOptions, maxRequestBytes: 128, handler: async () => { calls += 1; return {}; } });
  await assert.rejects(() => server.exchange('{"schemaVersion":"ogvcs.protocol/request/v1","schemaVersion":"ogvcs.protocol/request/v1","value":1}'), /duplicate/u);
  await assert.rejects(() => server.exchange('{"extra":1,"schemaVersion":"ogvcs.protocol/request/v1","value":1}'), /registered property/u);
  await assert.rejects(() => server.exchange(Buffer.alloc(129, 0x20)), /byte ceiling/u);
  assert.equal(calls, 0);
});

test('response schema and deadline failures do not become trusted client results', async () => {
  const invalid = createBoundedLoopback({ contract, ...schemaOptions, handler: async () => ({ schemaVersion: 'ogvcs.protocol/response/v1', value: 'wrong' }) });
  await assert.rejects(() => invalid.client.call({ schemaVersion: 'ogvcs.protocol/request/v1', value: 1 }), /wrong type/u);

  const timed = createBoundedLoopback({ contract, ...schemaOptions, handler: async () => new Promise(() => {}) });
  await assert.rejects(() => timed.client.call({ schemaVersion: 'ogvcs.protocol/request/v1', value: 1 }, { timeoutMs: 2 }), /deadline/u);
});
