import assert from 'node:assert/strict';
import test from 'node:test';

import {
  DeterministicRandom,
  FaultScheduler,
  canonicalJson,
  createFaultSchedule,
  deepFreeze,
  loadReferenceCorpus,
  medianAbsoluteDeviation,
  nearestRank,
  redactPublicData,
  summarizeSamples,
} from '../src/index.mjs';

test('reference corpus destinations are bounded relative paths before filesystem access', async () => {
  for (const destination of ['../escape', '/absolute', 'nested//empty', 'nested/./dot', 'nested/../parent', 'windows\\escape']) {
    await assert.rejects(loadReferenceCorpus('/definitely-not-read', destination), (error) => error.code === 'HARNESS_INPUT_INVALID');
  }
});

function sample(id, wall, overrides = {}) {
  return { id, taskId: 'status', corpusId: 'code-heavy', cacheState: 'cold', networkProfile: 'loopback-simulated', status: 'success', wallMicroseconds: wall, cpuMicroseconds: 1, peakMemoryBytes: 1, diskReadBytes: 2, diskWriteBytes: 3, networkReadBytes: 4, networkWriteBytes: 5, logicalBytes: 100, uniqueBytes: 50, retries: 0, assertions: [{ id: 'ok', passed: true }], ...overrides };
}

test('canonical data and redaction reject caller code without invoking it', () => {
  let trapCalls = 0;
  const proxy = new Proxy({}, { ownKeys() { trapCalls += 1; throw new Error('must not run'); } });
  assert.throws(() => canonicalJson(proxy), /Proxy/u);
  assert.throws(() => redactPublicData(proxy), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(trapCalls, 0);
  let getterCalls = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'accessToken', { enumerable: true, get() { getterCalls += 1; return 'secret'; } });
  assert.throws(() => redactPublicData(accessor), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(getterCalls, 0);
  const child = { mutable: true }; const shallowFrozen = Object.freeze({ child });
  deepFreeze(shallowFrozen); assert.equal(Object.isFrozen(child), true);
  const scheduleProxy = new Proxy({}, { ownKeys() { trapCalls += 1; throw new Error('must not run'); } });
  assert.throws(() => new FaultScheduler(scheduleProxy), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const pointsProxy = new Proxy([], { get() { trapCalls += 1; throw new Error('must not run'); } });
  assert.throws(() => createFaultSchedule('safe-seed', pointsProxy), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.throws(() => new DeterministicRandom('safe-seed').shuffle(pointsProxy), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(trapCalls, 0);
});

test('redaction removes credentials and hashes partner identities', () => {
  const source = { accessToken: 'never-publish', nested: { partnerId: 'studio-a', safe: 'ok' } };
  Object.defineProperty(source, '__proto__', { enumerable: true, value: { retained: true } });
  const result = redactPublicData(source);
  assert.deepEqual(result, { value: { ['__proto__']: { retained: true }, nested: { partnerId: `sha256:${result.value.nested.partnerId.slice(7)}`, safe: 'ok' } }, credentialsRemoved: 1, partnerIdentifiersHashed: 1 });
  assert.equal(Object.hasOwn(result.value, '__proto__'), true);
  assert.equal(Object.getPrototypeOf(result.value), Object.prototype);
  assert.doesNotMatch(JSON.stringify(result), /never-publish|studio-a/u);
});

test('PRNG, nearest-rank percentiles, dispersion, and byte accounting are deterministic', () => {
  assert.throws(() => new DeterministicRandom('\uD800'), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const left = new DeterministicRandom('fixed-seed'); const right = new DeterministicRandom('fixed-seed');
  assert.deepEqual(left.bytes(128), right.bytes(128));
  assert.deepEqual(left.shuffle([1, 2, 3, 4]), right.shuffle([1, 2, 3, 4]));
  assert.equal(nearestRank([40, 10, 20, 30], 95), 40);
  assert.equal(medianAbsoluteDeviation([10, 20, 30]), 10);
  const [summary] = summarizeSamples([sample('a', 10), sample('b', 30), sample('c', 20, { status: 'failed', assertions: [{ id: 'ok', passed: false }] })]);
  assert.deepEqual({ count: summary.sampleCount, succeeded: summary.succeeded, failed: summary.failed, p50: summary.durationMicroseconds.p50, p99: summary.durationMicroseconds.p99, mad: summary.durationMicroseconds.medianAbsoluteDeviation, logical: summary.bytes.logical, ratio: summary.bytes.logicalUniqueRatioMilli, correctness: summary.correctnessFailures }, { count: 3, succeeded: 2, failed: 1, p50: 10, p99: 30, mad: 10, logical: 300, ratio: 2000, correctness: 1 });
});
