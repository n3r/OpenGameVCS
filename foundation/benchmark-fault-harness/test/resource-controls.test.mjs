import assert from 'node:assert/strict';
import test from 'node:test';
import { setTimeout as wait } from 'node:timers/promises';

import { DeterministicCacheController, FakeRepositoryService, HarnessDeadline, NetworkController, measureHarnessOverhead, runBenchmarkMatrix, validateHarnessOverhead } from '../src/index.mjs';
import { contract, fixedMeasurement, FIXED_OVERHEAD } from './helpers.mjs';

const profile = { id: 'test-network', mode: 'simulated', rttMs: 20, bandwidthBytesPerSecond: 1_000_000, lossPartsPerMillion: 0, interruptionEvery: 0, duplicateEvery: 0, reorderWindow: 0 };

test('cache controls expose four independent observable states and reset counters', () => {
  const cache = new DeterministicCacheController();
  const cold = cache.prepare('cold'); cache.read(128); const coldRead = cache.inspect();
  const local = cache.prepare('warm-local-cache'); cache.read(128); const localRead = cache.inspect();
  const regional = cache.prepare('warm-regional-cache'); cache.read(128); const regionalRead = cache.inspect();
  const mixed = cache.prepare('mixed-cache');
  assert.deepEqual([cold.localBytes, local.localBytes > 0, regional.regionalBytes > 0, mixed.localBytes > 0 && mixed.regionalBytes > 0], [0, true, true, true]);
  assert.equal(coldRead.originBytes, 128); assert.equal(localRead.localHits, 1); assert.equal(regionalRead.regionalHits, 1); assert.equal(mixed.reads, 0);
  const bounded = new DeterministicCacheController({ maxBytes: 1 });
  const baseline = bounded.prepare('cold');
  assert.throws(() => bounded.read(2), (error) => error.code === 'HARNESS_LIMIT_EXCEEDED');
  assert.deepEqual(bounded.inspect(), baseline);
  assert.equal(bounded.read(1).originBytes, 1);
});

test('network cancellation rolls back accounting and privilege requires an isolated adapter', async () => {
  const network = new NetworkController(profile);
  const controller = new AbortController();
  const pending = network.transfer(1024, 'send', controller.signal); controller.abort();
  await assert.rejects(pending, (error) => error.code === 'HARNESS_CANCELLED');
  assert.equal(network.inspect().sentBytes, 0);
  const baseline = network.inspect();
  assert.throws(() => network.planTransfer(Number.MAX_SAFE_INTEGER), (error) => error.code === 'HARNESS_LIMIT_EXCEEDED');
  assert.deepEqual(network.inspect(), baseline);
  assert.throws(() => new NetworkController({ ...profile, id: 'privileged', mode: 'privileged' }), (error) => error.code === 'HARNESS_PRIVILEGE_REQUIRED');
  let applied = 0; let reset = 0;
  const privileged = new NetworkController({ ...profile, id: 'privileged', mode: 'privileged' }, { allowPrivileged: true, adapter: { isolated: true, apply() { applied += 1; }, reset() { reset += 1; } } });
  privileged.reset(); assert.deepEqual([applied, reset], [1, 1]);
  let failedApplyReset = 0;
  assert.throws(() => new NetworkController({ ...profile, id: 'privileged', mode: 'privileged' }, { allowPrivileged: true, adapter: { isolated: true, apply() { throw new Error('partial apply'); }, reset() { failedApplyReset += 1; } } }), (error) => error.code === 'HARNESS_IO');
  assert.equal(failedApplyReset, 1);
  let asyncApplyReset = 0;
  assert.throws(() => new NetworkController({ ...profile, id: 'privileged', mode: 'privileged' }, { allowPrivileged: true, adapter: { isolated: true, apply() { return Promise.resolve(); }, reset() { asyncApplyReset += 1; } } }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(asyncApplyReset, 1);
});

test('deadlines abort their shared signal and overhead above five percent is corrected', async () => {
  const deadline = new HarnessDeadline({ timeoutMs: 5 });
  await assert.rejects(deadline.race(new Promise(() => {}), 'never'), (error) => error.code === 'HARNESS_DEADLINE_EXCEEDED');
  assert.equal(deadline.signal.aborted, true);
  assert.throws(() => new HarnessDeadline({ now() { throw new Error('host clock failed'); } }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const overhead = await measureHarnessOverhead({ baselineMicroseconds: [100, 100, 100, 100, 100], wrappedMicroseconds: [106, 106, 106, 106, 106] });
  assert.deepEqual(overhead, { measuredBasisPoints: 600, correctionApplied: true, correctionMicroseconds: 6, method: 'measured-and-corrected' });
  assert.throws(() => validateHarnessOverhead({ measuredBasisPoints: 600, correctionApplied: false, correctionMicroseconds: 0, method: 'measured-below-threshold' }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.deepEqual(validateHarnessOverhead({ measuredBasisPoints: 600, correctionApplied: false, correctionMicroseconds: 0, method: 'reported-uncorrected' }), { measuredBasisPoints: 600, correctionApplied: false, correctionMicroseconds: 0, method: 'reported-uncorrected' });
});

test('matrix retention and all active cache lanes share one memory ceiling', async () => {
  const authority = await contract();
  const corpora = ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'].map((id) => ({
    id, verified: true, logicalBytes: 4096, requestDigest: 'a'.repeat(64), manifestDigest: 'b'.repeat(64), profile: { id, version: '2.0.0' },
  }));
  await assert.rejects(runBenchmarkMatrix({
    contract: authority, corpora, harnessProfile: 'local-smoke', maxWorkingMemoryBytes: 800_000,
    measurementFactory: () => fixedMeasurement(), overhead: FIXED_OVERHEAD, simulateNetworkDelay: false,
  }), (error) => error.code === 'HARNESS_LIMIT_EXCEEDED');
});

test('matrix failure drains every started execution lane before returning', async () => {
  const authority = await contract();
  const corpora = ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'].map((id) => ({
    id, verified: true, logicalBytes: 4096, requestDigest: 'a'.repeat(64), manifestDigest: 'b'.repeat(64), profile: { id, version: '2.0.0' },
  }));
  let active = 0; let completed = 0; let releaseSecondStart;
  const secondStarted = new Promise((resolve) => { releaseSecondStart = resolve; });
  await assert.rejects(runBenchmarkMatrix({
    contract: authority, corpora, harnessProfile: 'local-smoke', concurrency: 2,
    measurementFactory: () => fixedMeasurement(), overhead: FIXED_OVERHEAD, simulateNetworkDelay: false,
    serviceFactory: ({ unitIndex }) => {
      const service = new FakeRepositoryService();
      return {
        snapshot: () => service.snapshot(),
        async executeTask(...arguments_) {
          active += 1;
          try {
            if (unitIndex === 0) { await secondStarted; throw new Error('deterministic lane failure'); }
            if (unitIndex === 1) { releaseSecondStart(); await wait(25); }
            return await service.executeTask(...arguments_);
          } finally { active -= 1; completed += 1; }
        },
      };
    },
  }), /deterministic lane failure/u);
  assert.equal(active, 0);
  const completedAtReturn = completed;
  await wait(40);
  assert.equal(completed, completedAtReturn);
});
