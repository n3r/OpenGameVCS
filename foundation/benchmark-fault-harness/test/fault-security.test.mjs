import assert from 'node:assert/strict';
import test from 'node:test';

import { FakeRepositoryService, FaultScheduler, checkRepositoryInvariants, createFaultSchedule, proveFaultDeterminism, runBrokenServiceSelfTest, runFaultMatrix, runSecurityNegativeSuites } from '../src/index.mjs';
import { contract } from './helpers.mjs';

test('all durable boundaries reject before/after/error faults without invariant loss', async () => {
  const authority = await contract();
  const matrix = await runFaultMatrix(authority, { seed: 'fault-test-v1' });
  assert.equal(matrix.rows.length, 36); assert.equal(matrix.schedules.length, 36); assert.equal(matrix.failed, 0);
  assert.equal(matrix.rows.every((row) => row.injected && row.taskStatus === 'incomplete' && row.invariantPassed), true);
  const proof = proveFaultDeterminism(authority, 'fault-test-v1'); assert.equal(proof.deterministic, true);
});

test('intentionally broken services and security/path negatives prove checkers are non-vacuous', async () => {
  const authority = await contract();
  const [broken, security] = await Promise.all([runBrokenServiceSelfTest(authority), runSecurityNegativeSuites()]);
  assert.equal(broken.cases.length, 7); assert.equal(broken.missed, 0); assert.equal(broken.cases.every(({ detected }) => detected), true);
  assert.deepEqual({ authorizationFailed: security.authorization.failed, enumeration: security.enumerationDetected, workspace: security.workspaceEscapeDetected, misses: security.misses }, { authorizationFailed: 0, enumeration: true, workspace: true, misses: 0 });
});

test('post-mutation incomplete task replay is idempotent and retry accounting stays consistent', async () => {
  const service = new FakeRepositoryService();
  await service.executeTask('setup', { idempotencyKey: 'idempotent-setup-v1' });
  const missingHead = await service.executeTask('submit', { idempotencyKey: 'missing-expected-head-v1' });
  assert.deepEqual({ status: missingHead.status, code: missingHead.code, mutationCount: missingHead.mutationCount }, { status: 'failed', code: 'HARNESS_INPUT_INVALID', mutationCount: 0 });
  const schedule = createFaultSchedule('post-mutation-replay-v1', ['metadata.commit'], { count: 1, actions: ['crash-after'], shuffle: false });
  service.setFaultScheduler(new FaultScheduler(schedule));
  const input = { idempotencyKey: 'idempotent-submit-v1', expectedHead: 'root', actor: 'operator-a', authorized: true, fileId: '00000000000000000000000000000001', logicalBytes: 4096, uniqueBytes: 3072 };
  const first = await service.executeTask('submit', input); const afterFirst = service.snapshotDigest();
  const retry = await service.executeTask('submit', input);
  const secondRetry = await service.executeTask('submit', input);
  assert.equal(first.status, 'incomplete'); assert.ok(first.mutationCount > 0);
  assert.deepEqual({ status: retry.status, code: retry.code, mutationCount: retry.mutationCount, retries: retry.retries, metricRetries: retry.metrics.retries }, { status: first.status, code: first.code, mutationCount: 0, retries: 1, metricRetries: 1 });
  assert.deepEqual({ mutationCount: secondRetry.mutationCount, retries: secondRetry.retries, metricRetries: secondRetry.metrics.retries }, { mutationCount: 0, retries: 2, metricRetries: 2 });
  assert.equal(service.snapshotDigest(), afterFirst);
});

test('fake service rejects hostile task records without invoking caller code', async () => {
  const service = new FakeRepositoryService();
  let trapCalls = 0;
  const input = new Proxy({}, { get() { trapCalls += 1; throw new Error('task input trap must not run'); } });
  await assert.rejects(service.executeTask('setup', input), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(trapCalls, 0); assert.equal(service.mutationCount(), 0);
  let invariantTrapCalls = 0;
  const invariantProxy = new Proxy({}, { get() { invariantTrapCalls += 1; throw new Error('invariant trap must not run'); } });
  assert.throws(() => checkRepositoryInvariants(invariantProxy), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(invariantTrapCalls, 0);
  let schedulerTrapCalls = 0;
  const scheduler = new FaultScheduler(createFaultSchedule('hostile-scheduler-v1', ['durable.write'], { count: 1 }));
  const schedulerProxy = new Proxy(scheduler, { get() { schedulerTrapCalls += 1; throw new Error('scheduler trap must not run'); } });
  assert.throws(() => service.setFaultScheduler(schedulerProxy), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(schedulerTrapCalls, 0);
});
