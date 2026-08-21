import { harnessFail } from './errors.mjs';
import { performance } from 'node:perf_hooks';

export const HARNESS_LIMITS = Object.freeze({
  maxControlMessageBytes: 1_048_576,
  maxCorpora: 64,
  maxFaultEvents: 4_096,
  maxIterations: 1_000,
  maxResultBundleBytes: 67_108_864,
  maxSamples: 100_000,
  maxStreamBytes: 67_108_864,
  maxTaskTimeMs: 120_000,
  maxTasks: 64,
  maxThresholds: 4_096,
  maxTraceEvents: 4_096,
  maxWorkingMemoryBytes: 268_435_456,
});

export function boundedInteger(value, fallback, maximum, name, minimum = 1) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) harnessFail('HARNESS_INPUT_INVALID', `${name} is outside its configured range`);
  return result;
}

export function checkedAdd(left, right, label = 'counter') {
  const result = left + right;
  if (!Number.isSafeInteger(left) || left < 0 || !Number.isSafeInteger(right) || right < 0 || !Number.isSafeInteger(result)) harnessFail('HARNESS_LIMIT_EXCEEDED', `${label} exceeds the safe integer range`);
  return result;
}

export class HarnessDeadline {
  #deadline;
  #now;
  #externalSignal;
  #controller = new AbortController();
  #state = 'active';
  #readClock() {
    let value;
    try { value = this.#now(); } catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'deadline clock failed', { cause: error }); }
    if (!Number.isFinite(value)) harnessFail('HARNESS_INPUT_INVALID', 'deadline clock returned an invalid value');
    return value;
  }
  constructor(options = {}) {
    const timeout = boundedInteger(options.timeoutMs, HARNESS_LIMITS.maxTaskTimeMs, HARNESS_LIMITS.maxTaskTimeMs, 'timeoutMs');
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) harnessFail('HARNESS_INPUT_INVALID', 'deadline signal must be an AbortSignal');
    this.#now = options.now ?? (() => performance.now());
    if (typeof this.#now !== 'function') harnessFail('HARNESS_INPUT_INVALID', 'deadline clock must be callable');
    const started = this.#readClock();
    this.#deadline = started + timeout;
    if (!Number.isFinite(this.#deadline)) harnessFail('HARNESS_INPUT_INVALID', 'deadline clock exceeds the supported range');
    this.#externalSignal = options.signal;
    this.signal = this.#controller.signal;
    if (this.#externalSignal?.aborted) this.#cancel();
  }
  #expire() { if (this.#state === 'active') { this.#state = 'deadline'; this.#controller.abort(Object.freeze({ kind: 'deadline' })); } }
  #cancel() { if (this.#state === 'active') { this.#state = 'cancelled'; this.#controller.abort(Object.freeze({ kind: 'cancelled' })); } }
  checkpoint() {
    if (this.#externalSignal?.aborted) this.#cancel();
    if (this.#state === 'cancelled') harnessFail('HARNESS_CANCELLED', 'benchmark harness operation was cancelled');
    if (this.#state === 'deadline') harnessFail('HARNESS_DEADLINE_EXCEEDED', 'benchmark harness deadline exceeded');
    const now = this.#readClock();
    if (now >= this.#deadline) { this.#expire(); harnessFail('HARNESS_DEADLINE_EXCEEDED', 'benchmark harness deadline exceeded'); }
  }
  remaining() { this.checkpoint(); return Math.max(1, Math.ceil(this.#deadline - this.#readClock())); }
  async race(promise, label = 'operation') {
    this.checkpoint();
    let timeout;
    let abortListener;
    const deadlineBoundary = Object.freeze({ kind: 'deadline' });
    const cancellationBoundary = Object.freeze({ kind: 'cancelled' });
    const expiry = new Promise((_, reject) => {
      timeout = setTimeout(() => { this.#expire(); reject(deadlineBoundary); }, this.remaining());
      if (this.#externalSignal) {
        abortListener = () => { this.#cancel(); reject(cancellationBoundary); };
        this.#externalSignal.addEventListener('abort', abortListener, { once: true });
        if (this.#externalSignal.aborted) abortListener();
      }
    });
    try {
      const value = await Promise.race([Promise.resolve(promise), expiry]);
      this.checkpoint();
      return value;
    }
    catch (error) {
      if (error === deadlineBoundary) harnessFail('HARNESS_DEADLINE_EXCEEDED', `benchmark ${label} exceeded its deadline`);
      if (error === cancellationBoundary) harnessFail('HARNESS_CANCELLED', `benchmark ${label} was cancelled`);
      throw error;
    } finally {
      clearTimeout(timeout);
      if (abortListener) this.#externalSignal.removeEventListener('abort', abortListener);
    }
  }
}
