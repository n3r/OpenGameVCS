import assert from 'node:assert/strict';
import test from 'node:test';

import { runExternalDriverConformance, startExternalDriver } from '../src/index.mjs';
import { contract, driver } from './helpers.mjs';

test('external driver executes negotiated lifecycle with complete ordered trace', async () => {
  const authority = await contract(); const result = await runExternalDriverConformance(driver(), authority, { timeoutMs: 30_000 });
  assert.equal(result.failed, 0); assert.equal(result.faultObserved, true); assert.equal(result.results.length, 9);
  assert.deepEqual(result.results.map(({ trace }) => trace[0].sequence), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
});

test('incompatible and malformed drivers fail before mutation', async () => {
  const authority = await contract();
  await assert.rejects(startExternalDriver(driver('--incompatible'), authority, { timeoutMs: 5_000 }), (error) => error.code === 'HARNESS_NEGOTIATION_INCOMPATIBLE');
  await assert.rejects(startExternalDriver(driver('--malformed-hello'), authority, { timeoutMs: 5_000 }), (error) => error.code === 'HARNESS_PROTOCOL_MALFORMED');
  await assert.rejects(startExternalDriver(driver('--oversized-hello'), authority, { timeoutMs: 5_000 }), (error) => error.code === 'HARNESS_LIMIT_EXCEEDED');
});

test('retry uses the same command identity, captures both attempts, and mutates once', async () => {
  const authority = await contract(); const session = await startExternalDriver(driver('--retry-once-operation', 'run-task'), authority, { timeoutMs: 30_000 });
  await session.command('configure', { cacheState: 'cold', networkProfile: 'loopback-simulated' });
  await session.command('start', {});
  const result = await session.command('run-task', { taskId: 'setup', input: { idempotencyKey: 'driver-retry-task-v1' } });
  await session.close();
  const attempts = session.results.filter(({ id }) => id === result.id);
  assert.deepEqual(attempts.map(({ code }) => code), ['HARNESS_RETRYABLE', 'HARNESS_OK']);
  assert.equal(attempts[0].mutationCount, 0); assert.equal(attempts[1].mutationCount, 1);
});

test('driver lifecycle rejects tasks before configuration/start as retryable typed results', async () => {
  const authority = await contract(); const session = await startExternalDriver(driver(), authority, { timeoutMs: 30_000 });
  const result = await session.command('run-task', { taskId: 'setup', input: { idempotencyKey: 'driver-early-task-v1' } });
  assert.deepEqual({ result: result.result, code: result.code, retryable: result.retryable, preMutation: result.preMutation }, { result: 'reject', code: 'HARNESS_TASK_INCOMPLETE', retryable: true, preMutation: true });
  await session.close();
});

test('hostile command preflight is typed and does not consume a command identity', async () => {
  const authority = await contract(); const session = await startExternalDriver(driver(), authority, { timeoutMs: 30_000 });
  let traps = 0;
  const payload = new Proxy({}, { ownKeys() { traps += 1; throw new Error('must not execute'); } });
  await assert.rejects(session.command('configure', payload), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(traps, 0);
  const configured = await session.command('configure', { cacheState: 'cold', networkProfile: 'loopback-simulated' });
  assert.equal(configured.id, 'command-000002');
  await session.close();
});

test('pre-cancelled driver startup rejects before spawning the adapter', async () => {
  const authority = await contract();
  const controller = new AbortController(); controller.abort();
  await assert.rejects(startExternalDriver(['ogvcs-driver-command-that-must-not-spawn'], authority, { signal: controller.signal }), (error) => error.code === 'HARNESS_CANCELLED');
});
