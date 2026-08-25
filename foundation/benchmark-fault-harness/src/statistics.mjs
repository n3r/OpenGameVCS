import { codeUnitCompare, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { HARNESS_LIMITS, checkedAdd } from './limits.mjs';
import { snapshotData } from './input.mjs';

function sortedIntegers(values, label) {
  values = snapshotData(values, label);
  if (!Array.isArray(values) || values.some((value) => !Number.isSafeInteger(value) || value < 0)) harnessFail('HARNESS_INPUT_INVALID', `${label} must contain non-negative safe integers`);
  return [...values].sort((a, b) => a - b);
}

export function nearestRank(values, percentile) {
  const sorted = sortedIntegers(values, 'percentile samples');
  if (sorted.length === 0) return 0;
  if (!Number.isSafeInteger(percentile) || percentile < 1 || percentile > 100) harnessFail('HARNESS_INPUT_INVALID', 'percentile is invalid');
  return rankSorted(sorted, percentile);
}

function rankSorted(sorted, percentile) { return sorted[Math.max(0, Math.ceil(percentile * sorted.length / 100) - 1)]; }

function median(values) {
  const sorted = sortedIntegers(values, 'median samples');
  if (sorted.length === 0) return 0;
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle] : Math.floor((sorted[middle - 1] + sorted[middle]) / 2);
}

export function medianAbsoluteDeviation(values) {
  const center = median(values);
  return median(values.map((value) => Math.abs(value - center)));
}

function sum(samples, field) { return samples.reduce((total, sample) => checkedAdd(total, sample[field], field), 0); }

export function summarizeSamples(samples) {
  samples = snapshotData(samples, 'summary samples');
  if (!Array.isArray(samples) || samples.length < 1 || samples.length > HARNESS_LIMITS.maxSamples) harnessFail('HARNESS_INPUT_INVALID', 'summary requires a bounded nonempty sample set');
  const groups = new Map();
  for (const sample of samples) {
    if (!sample || typeof sample.taskId !== 'string' || typeof sample.corpusId !== 'string' || typeof sample.cacheState !== 'string' || typeof sample.networkProfile !== 'string' || !['success', 'failed', 'incomplete'].includes(sample.status) || !Array.isArray(sample.assertions)) harnessFail('HARNESS_INPUT_INVALID', 'summary sample shape is invalid');
    const key = [sample.taskId, sample.corpusId, sample.cacheState, sample.networkProfile].join('\0');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(sample);
  }
  return deepFreeze([...groups.values()].map((rows) => {
    const first = rows[0];
    const successful = rows.filter(({ status }) => status === 'success');
    const durations = sortedIntegers(successful.map(({ wallMicroseconds }) => wallMicroseconds), 'duration samples');
    const logical = sum(rows, 'logicalBytes');
    const unique = sum(rows, 'uniqueBytes');
    if (unique === 0 && logical !== 0) harnessFail('HARNESS_INPUT_INVALID', 'nonempty logical samples require nonzero unique bytes');
    const ratio = unique === 0 ? 0n : BigInt(logical) * 1000n / BigInt(unique);
    if (ratio > BigInt(Number.MAX_SAFE_INTEGER)) harnessFail('HARNESS_LIMIT_EXCEEDED', 'logical/unique ratio exceeds the safe integer range');
    return {
      schemaVersion: 'ogvcs.benchmark/task-summary/v1',
      taskId: first.taskId, corpusId: first.corpusId, cacheState: first.cacheState, networkProfile: first.networkProfile,
      sampleCount: rows.length, succeeded: successful.length, failed: rows.filter(({ status }) => status === 'failed').length, incomplete: rows.filter(({ status }) => status === 'incomplete').length, retries: sum(rows, 'retries'),
      durationMicroseconds: { p50: durations.length ? rankSorted(durations, 50) : 0, p95: durations.length ? rankSorted(durations, 95) : 0, p99: durations.length ? rankSorted(durations, 99) : 0, minimum: durations[0] ?? 0, maximum: durations.at(-1) ?? 0, medianAbsoluteDeviation: medianAbsoluteDeviation(durations) },
      bytes: { diskRead: sum(rows, 'diskReadBytes'), diskWrite: sum(rows, 'diskWriteBytes'), networkRead: sum(rows, 'networkReadBytes'), networkWrite: sum(rows, 'networkWriteBytes'), logical, unique, logicalUniqueRatioMilli: Number(ratio) },
      correctnessFailures: rows.reduce((count, row) => count + row.assertions.filter(({ passed }) => !passed).length, 0),
      successRatePartsPerMillion: Math.floor(successful.length * 1_000_000 / rows.length),
    };
  }).sort((a, b) => codeUnitCompare(`${a.taskId}\0${a.corpusId}\0${a.cacheState}\0${a.networkProfile}`, `${b.taskId}\0${b.corpusId}\0${b.cacheState}\0${b.networkProfile}`)));
}
