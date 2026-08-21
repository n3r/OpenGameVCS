import { deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';

function probe(operation, label) {
  try { return operation(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', `${label} probe failed`, { cause: error }); }
}

export function validateHarnessOverhead(value) {
  if (!value || !Number.isSafeInteger(value.measuredBasisPoints) || value.measuredBasisPoints < 0 || typeof value.correctionApplied !== 'boolean' || !Number.isSafeInteger(value.correctionMicroseconds) || value.correctionMicroseconds < 0 || !['measured-below-threshold', 'measured-and-corrected', 'reported-uncorrected'].includes(value.method)) harnessFail('HARNESS_INPUT_INVALID', 'measurement overhead evidence is invalid');
  const corrected = value.method === 'measured-and-corrected';
  const below = value.method === 'measured-below-threshold';
  if (value.correctionApplied !== corrected || corrected && (value.measuredBasisPoints <= 500 || value.correctionMicroseconds < 1) || !corrected && value.correctionMicroseconds !== 0 || below !== (value.measuredBasisPoints <= 500)) harnessFail('HARNESS_INPUT_INVALID', 'measurement overhead evidence is internally inconsistent');
  return deepFreeze({ measuredBasisPoints: value.measuredBasisPoints, correctionApplied: value.correctionApplied, correctionMicroseconds: value.correctionMicroseconds, method: value.method });
}

export async function measureTask(operation, options = {}) {
  if (typeof operation !== 'function') harnessFail('HARNESS_INPUT_INVALID', 'measured operation must be callable');
  const clock = options.clock ?? (() => process.hrtime.bigint());
  const cpu = options.cpu ?? (() => process.cpuUsage());
  const memory = options.memory ?? (() => process.memoryUsage().rss);
  if (typeof clock !== 'function' || typeof cpu !== 'function' || typeof memory !== 'function') harnessFail('HARNESS_INPUT_INVALID', 'measurement probes must be callable');
  const sampleIntervalMs = options.sampleIntervalMs ?? 5;
  if (!Number.isSafeInteger(sampleIntervalMs) || sampleIntervalMs < 1 || sampleIntervalMs > 1000) harnessFail('HARNESS_INPUT_INVALID', 'measurement sample interval is invalid');
  const startedWall = probe(clock, 'measurement clock'); const startedCpu = probe(cpu, 'measurement CPU'); const startedMemory = probe(memory, 'measurement memory');
  if (typeof startedWall !== 'bigint' || startedWall < 0n || !startedCpu || !Number.isSafeInteger(startedCpu.user) || startedCpu.user < 0 || !Number.isSafeInteger(startedCpu.system) || startedCpu.system < 0 || !Number.isSafeInteger(startedMemory) || startedMemory < 0) harnessFail('HARNESS_INPUT_INVALID', 'measurement probe returned an invalid value');
  let peakMemoryBytes = startedMemory; let monitorError;
  const interval = setInterval(() => {
    try {
      const current = probe(memory, 'measurement memory');
      if (!Number.isSafeInteger(current) || current < 0) throw new TypeError('memory probe returned an invalid value');
      peakMemoryBytes = Math.max(peakMemoryBytes, current);
    } catch (error) { monitorError ??= error; }
  }, sampleIntervalMs);
  interval.unref?.();
  let value; let operationError;
  try { value = await operation(); } catch (error) { operationError = error; }
  finally { clearInterval(interval); }
  const endedWall = probe(clock, 'measurement clock'); const endedCpu = probe(cpu, 'measurement CPU'); const endedMemory = probe(memory, 'measurement memory');
  if (typeof endedWall !== 'bigint' || endedWall < startedWall || !endedCpu || !Number.isSafeInteger(endedCpu.user) || endedCpu.user < startedCpu.user || !Number.isSafeInteger(endedCpu.system) || endedCpu.system < startedCpu.system || !Number.isSafeInteger(endedMemory) || endedMemory < 0 || monitorError) harnessFail('HARNESS_INPUT_INVALID', 'measurement probe returned an invalid value', { cause: monitorError });
  peakMemoryBytes = Math.max(peakMemoryBytes, endedMemory);
  if (operationError) throw operationError;
  const wallMicroseconds = Number((endedWall - startedWall) / 1000n);
  const cpuMicroseconds = Math.max(0, endedCpu.user - startedCpu.user + endedCpu.system - startedCpu.system);
  if (!Number.isSafeInteger(wallMicroseconds) || wallMicroseconds < 0 || !Number.isSafeInteger(cpuMicroseconds)) harnessFail('HARNESS_LIMIT_EXCEEDED', 'measurement counter exceeds safe integer bounds');
  return deepFreeze({ value, wallMicroseconds, cpuMicroseconds, peakMemoryBytes });
}

export async function measureHarnessOverhead(options = {}) {
  if (Array.isArray(options.baselineMicroseconds) || Array.isArray(options.wrappedMicroseconds)) {
    return overhead(options.baselineMicroseconds, options.wrappedMicroseconds);
  }
  const iterations = options.iterations ?? 25;
  if (!Number.isSafeInteger(iterations) || iterations < 5 || iterations > 1000) harnessFail('HARNESS_INPUT_INVALID', 'overhead iteration count is invalid');
  const baseline = []; const wrapped = [];
  for (let index = 0; index < iterations; index += 1) {
    const start = process.hrtime.bigint();
    await Promise.resolve(index);
    baseline.push(Math.max(1, Number((process.hrtime.bigint() - start) / 1000n)));
    const measured = await measureTask(() => Promise.resolve(index));
    wrapped.push(Math.max(1, measured.wallMicroseconds));
  }
  return overhead(baseline, wrapped);
}

function median(values) {
  if (!Array.isArray(values) || values.length < 1 || values.some((value) => !Number.isSafeInteger(value) || value < 0)) harnessFail('HARNESS_INPUT_INVALID', 'overhead samples are invalid');
  const sorted = [...values].sort((a, b) => a - b); const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : Math.floor((sorted[middle - 1] + sorted[middle]) / 2);
}

function overhead(baseline, wrapped) {
  if (baseline.length !== wrapped.length) harnessFail('HARNESS_INPUT_INVALID', 'overhead sample counts differ');
  const raw = Math.max(1, median(baseline)); const instrumented = median(wrapped);
  const basisPoints = BigInt(Math.max(0, instrumented - raw)) * 10_000n / BigInt(raw);
  if (basisPoints > BigInt(Number.MAX_SAFE_INTEGER)) harnessFail('HARNESS_LIMIT_EXCEEDED', 'overhead ratio exceeds the safe integer range');
  const measuredBasisPoints = Number(basisPoints);
  const correctionApplied = measuredBasisPoints > 500;
  return validateHarnessOverhead({ measuredBasisPoints, correctionApplied, correctionMicroseconds: correctionApplied ? Math.max(0, instrumented - raw) : 0, method: correctionApplied ? 'measured-and-corrected' : 'measured-below-threshold' });
}
