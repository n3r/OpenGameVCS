import assert from 'node:assert/strict';
import test from 'node:test';

import {
  Deadline,
  ProtocolBaselineError,
  canonicalJson,
  parseCanonicalJson,
  parseJson,
} from '../src/index.mjs';

test('RFC 8785 emission sorts UTF-16 keys and emits ECMAScript numbers', () => {
  assert.equal(canonicalJson({ z: -0, a: 1.5, '\ud83d\ude00': true, '\u20ac': false }), '{"a":1.5,"z":0,"€":false,"😀":true}');
  assert.deepEqual({ ...parseCanonicalJson('{"a":1,"b":[true,null]}') }, { a: 1, b: [true, null] });
});

test('safe parser accepts duplicate-free noncanonical I-JSON but canonical parser does not', () => {
  assert.deepEqual({ ...parseJson(' { "b" : 2, "a" : 1 } ') }, { b: 2, a: 1 });
  assert.throws(() => parseCanonicalJson(' {"a":1}'), (error) => error instanceof ProtocolBaselineError && error.code === 'PROTOCOL_INPUT_INVALID');
  assert.throws(() => parseJson('{"a":1,"a":1}'), /duplicate key/u);
});

test('safe parser rejects invalid UTF-8, unsafe integers, invalid Unicode, and resource abuse', () => {
  assert.throws(() => parseJson(Buffer.from([0xc3, 0x28])), /UTF-8/u);
  assert.throws(() => parseJson('9007199254740992'), /I-JSON/u);
  assert.throws(() => parseJson('"\\ud800"'), /Unicode/u);
  assert.throws(() => parseJson(`${'['.repeat(65)}0${']'.repeat(65)}`), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
  assert.throws(() => parseJson('"abcdef"', { maxStringBytes: 5 }), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
});

test('emitter refuses accessors, proxies, sparse arrays, cycles, and host objects', () => {
  const accessor = {};
  Object.defineProperty(accessor, 'value', { enumerable: true, get() { throw new Error('must not execute'); } });
  assert.throws(() => canonicalJson(accessor), /accessor/u);
  assert.throws(() => canonicalJson(new Proxy({}, {})), /proxy/u);
  assert.throws(() => canonicalJson(new Array(1)), /dense/u);
  assert.throws(() => canonicalJson(new Date()), /I-JSON domain/u);
  const cycle = {};
  cycle.self = cycle;
  assert.throws(() => canonicalJson(cycle, { maxNodes: 32 }), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
});

test('configured limits and cooperative deadlines cannot exceed hard maxima', () => {
  assert.throws(() => canonicalJson({}, { maxBytes: 4 * 1024 * 1024 + 1 }), /supported range/u);
  let now = 0;
  assert.throws(() => canonicalJson(Array.from({ length: 2_000 }, (_, index) => index), {
    timeoutMs: 2,
    now: () => ++now,
  }), (error) => error.code === 'PROTOCOL_DEADLINE_EXCEEDED');
});

test('cancellation is distinct from deadline expiry before and during host work', async () => {
  const preAborted = new AbortController();
  preAborted.abort();
  assert.throws(() => new Deadline({ signal: preAborted.signal }).checkpoint(), (error) => error.code === 'PROTOCOL_CANCELLED');

  const midFlight = new AbortController();
  const deadline = new Deadline({ signal: midFlight.signal, timeoutMs: 1_000 });
  const pending = deadline.race(new Promise(() => {}), 'blocked test host call');
  queueMicrotask(() => midFlight.abort());
  await assert.rejects(() => pending, (error) => error.code === 'PROTOCOL_CANCELLED');

  let now = 0;
  assert.throws(() => new Deadline({ timeoutMs: 1, now: () => now++ }).checkpoint(), (error) => error.code === 'PROTOCOL_DEADLINE_EXCEEDED');
});

test('serialized runtime errors never disclose caller-controlled diagnostics', () => {
  const marker = 'protected/path/policy/grant-must-not-appear';
  const error = new ProtocolBaselineError('PROTOCOL_INPUT_INVALID', marker, { details: { path: marker } });
  assert.deepEqual(error.toJSON(), { code: 'PROTOCOL_INPUT_INVALID', safeClass: 'input', preMutation: true });
  assert.doesNotMatch(JSON.stringify(error.toJSON()), /protected|policy|grant/u);
});
