import { fileURLToPath } from 'node:url';

import { loadBenchmarkContract } from '../src/contract.mjs';

export const CONTRACT_ROOT = fileURLToPath(new URL('../../../spec/benchmark-fault/v1/', import.meta.url));
export const FAKE_DRIVER = fileURLToPath(new URL('../bin/ogvcs-benchmark-fake-driver.mjs', import.meta.url));

export function contract() { return loadBenchmarkContract({ root: CONTRACT_ROOT, cache: false }); }
export function driver(...flags) { return [process.execPath, FAKE_DRIVER, '--contract', CONTRACT_ROOT, ...flags]; }
export function fixedMeasurement() {
  let wall = 0n; let user = 0;
  return { clock: () => { wall += 1_000_000n; return wall; }, cpu: () => { user += 500; return { user, system: 0 }; }, memory: () => 1_048_576, sampleIntervalMs: 1_000 };
}
export const FIXED_OVERHEAD = Object.freeze({ measuredBasisPoints: 0, correctionApplied: false, correctionMicroseconds: 0, method: 'measured-below-threshold' });
