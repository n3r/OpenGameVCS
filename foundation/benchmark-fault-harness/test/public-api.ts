import {
  BenchmarkHarnessError,
  DeterministicCacheController,
  HarnessDeadline,
  NetworkController,
  canonicalDigest,
  createFaultSchedule,
  loadBenchmarkContract,
  planHarnessMatrix,
  redactPublicData,
  type CacheState,
  type HarnessCode,
  type NetworkProfile,
} from '@opengamevcs/benchmark-fault-harness';

const code: HarnessCode = 'HARNESS_OK';
const state: CacheState = 'warm-local-cache';
const digest: string = canonicalDigest({ code });
const schedule = createFaultSchedule('type-smoke', ['branch.cas']);
const cache = new DeterministicCacheController();
cache.prepare(state);
const profile: NetworkProfile = { id: 'test', mode: 'simulated', rttMs: 20, bandwidthBytesPerSecond: 1_000_000, lossPartsPerMillion: 0, interruptionEvery: 0, duplicateEvery: 0, reorderWindow: 0 };
new NetworkController(profile, { simulateDelay: false }).planTransfer(32);
const deadline: AbortSignal = new HarnessDeadline().signal;
const redacted = redactPublicData({ operatorId: 'example' });
void [digest, schedule, deadline, redacted, BenchmarkHarnessError];

const contract = await loadBenchmarkContract();
planHarnessMatrix(contract);
