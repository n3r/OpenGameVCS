import assert from 'node:assert/strict';
import test from 'node:test';

import {
  loadProtocolContract,
  ProtocolBaselineError,
  ProtocolProblemCatalog,
  ProtocolSemanticError,
  RUNTIME_TO_WIRE,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

const correlationId = 'correlation-0001';

test('closed problems are emitted only from registry-owned safe fields', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const catalog = new ProtocolProblemCatalog(contract);
  const problem = catalog.create('CURSOR_GAP', {
    correlationId,
    parameters: [{ name: 'gapClass', value: 'retention-gap' }],
  });
  assert.deepEqual(Object.keys(problem), ['code', 'correlationId', 'parameters', 'retryable', 'status', 'title', 'type']);
  assert.equal(problem.status, 409);
  assert.equal(problem.retryable, false);
  assert.equal(problem.parameters[0].name, 'gapClass');
  assert.equal(JSON.stringify(problem).includes('detail'), false);
});

test('unknown codes, arbitrary parameters, duplicates, status drift, and retry drift reject', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const catalog = new ProtocolProblemCatalog(contract);
  assert.throws(() => catalog.create('SECRET_ERROR', { correlationId }), /not registered/u);
  assert.throws(() => catalog.create('AUTHORIZATION_DENIED', { correlationId, parameters: [{ name: 'conflictClass', value: 'secret' }] }), /not permitted/u);
  assert.throws(() => catalog.create('CURSOR_GAP', { correlationId, parameters: [{ name: 'gapClass', value: 'retention-gap' }, { name: 'gapClass', value: 'generation-changed' }] }), /not permitted/u);
  assert.throws(() => catalog.create('CURSOR_GAP', { correlationId, parameters: [{ name: 'gapClass', value: 'private/path' }] }), /closed domain/u);
  assert.throws(() => catalog.create('CURSOR_GAP', { correlationId, parameters: [{ name: 'currentGeneration', value: '7' }] }), /not permitted/u);
  const problem = catalog.create('PROTOCOL_LIMIT_EXCEEDED', { correlationId, parameters: [{ name: 'retryAfterMs', value: '100' }] });
  assert.throws(() => catalog.validate(problem, { status: 400 }), /status.*disagree/u);
  assert.throws(() => catalog.validate(problem, { status: 413, retryAfterMs: 101 }), /retry metadata/u);
  let traps = 0;
  assert.throws(
    () => catalog.validate(problem, new Proxy({}, {
      ownKeys() { traps += 1; throw new Error('HTTP metadata trap'); },
    })),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );
  assert.equal(traps, 0);

  const hostileParameters = new Proxy([], {
    getPrototypeOf() { traps += 1; throw new Error('parameter trap'); },
  });
  assert.throws(
    () => catalog.create('CURSOR_GAP', { correlationId, parameters: hostileParameters }),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );
  assert.equal(traps, 0);
});

test('retryAfterMs accepts only its canonical bounded decimal domain', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const catalog = new ProtocolProblemCatalog(contract);
  for (const value of ['0', '1', '86400000']) {
    assert.equal(catalog.create('PROTOCOL_LIMIT_EXCEEDED', { correlationId, parameters: [{ name: 'retryAfterMs', value }] }).parameters[0].value, value);
  }
  for (const value of ['00', '01', '86400001', '99999999', 1, 'POLICY_MARKER_private']) {
    assert.throws(() => catalog.create('PROTOCOL_LIMIT_EXCEEDED', { correlationId, parameters: [{ name: 'retryAfterMs', value }] }), /closed domain|not permitted/u);
  }
});

test('response envelopes keep success and failure alternatives closed', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const catalog = new ProtocolProblemCatalog(contract);
  const failure = catalog.response('AUTHORIZATION_DENIED', { correlationId });
  assert.equal(failure.success, false);
  assert.equal(failure.problem.code, 'AUTHORIZATION_DENIED');
  const success = catalog.success(correlationId, { value: 'public' });
  assert.equal(success.success, true);
  assert.equal(success.body.value, 'public');
  assert.throws(() => catalog.validate({ ...failure.problem, detail: 'secret' }), /registered property/u);
});

test('every registered semantic and runtime failure maps without message parsing', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const catalog = new ProtocolProblemCatalog(contract);
  for (const entry of contract.registries['error-codes'].entries) {
    const problem = catalog.fromRuntimeError(new ProtocolSemanticError(entry.name, `PRIVATE_MARKER_${entry.name}`), { correlationId });
    assert.equal(problem.code, entry.name);
    assert.equal(JSON.stringify(problem).includes('PRIVATE_MARKER'), false);
  }
  for (const [runtimeCode, wireCode] of Object.entries(RUNTIME_TO_WIRE)) {
    const problem = catalog.fromRuntimeError(new ProtocolBaselineError(runtimeCode, `PRIVATE_RUNTIME_MARKER_${runtimeCode}`), { correlationId });
    assert.equal(problem.code, wireCode);
    assert.equal(JSON.stringify(problem).includes('PRIVATE_RUNTIME_MARKER'), false);
  }
});

test('Retry-After has exactly one canonical delta-seconds representation', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const catalog = new ProtocolProblemCatalog(contract);
  const problem = catalog.create('PROTOCOL_LIMIT_EXCEEDED', {
    correlationId,
    parameters: [{ name: 'retryAfterMs', value: '1001' }],
  });
  assert.deepEqual(catalog.responseHeaders(problem), [{ name: 'Retry-After', value: '2' }]);
  assert.equal(catalog.validate(problem, { headers: [{ name: 'retry-after', value: '2' }] }).code, 'PROTOCOL_LIMIT_EXCEEDED');
  for (const headers of [
    [],
    [{ name: 'Retry-After', value: '2' }, { name: 'retry-after', value: '2' }],
    [{ name: 'Retry-After', value: '1' }],
    [{ name: 'Retry-After', value: '02' }],
    [{ name: 'Retry-After', value: 'Sun, 16 Aug 2026 00:00:00 GMT' }],
  ]) assert.throws(() => catalog.validate(problem, { headers }), /Retry-After|disagree/u);
  const noRetry = catalog.create('AUTHORIZATION_DENIED', { correlationId });
  assert.throws(() => catalog.validate(noRetry, { headers: [{ name: 'Retry-After', value: '1' }] }), /Retry-After/u);
});
