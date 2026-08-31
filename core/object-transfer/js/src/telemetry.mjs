import { transferError } from './errors.mjs';

const KEYS = [
  'backend', 'bytes', 'durationMs', 'integrity', 'operation', 'outcome',
  'parts', 'quota', 'resume', 'retries',
].sort().join('\0');
const SAFE_NAME = /^[a-z][a-z0-9-]{0,63}$/u;

function count(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    transferError('TRANSFER_INPUT_INVALID', `${label} metric is invalid`);
  }
  return value;
}

export class BoundedTransferTelemetry {
  #series = new Map();

  constructor({ seriesMaximum = 128 } = {}) {
    if (!Number.isSafeInteger(seriesMaximum) || seriesMaximum < 1 || seriesMaximum > 1024) {
      transferError('TRANSFER_INPUT_INVALID', 'telemetry series bound is invalid');
    }
    this.seriesMaximum = seriesMaximum;
  }

  observe(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
        || Object.keys(value).sort().join('\0') !== KEYS
        || !SAFE_NAME.test(value.operation ?? '') || !['filesystem', 's3-compatible', 'service'].includes(value.backend)
        || !['success', 'denied', 'limited', 'retry', 'integrity', 'failure'].includes(value.outcome)
        || !['none', 'staging', 'durable-unique', 'request-rate', 'transfer-bytes'].includes(value.quota)
        || !['none', 'verified', 'failed'].includes(value.integrity)) {
      transferError('TRANSFER_INPUT_INVALID', 'transfer telemetry observation is invalid');
    }
    const observation = Object.freeze({
      operation: value.operation,
      backend: value.backend,
      outcome: value.outcome,
      quota: value.quota,
      integrity: value.integrity,
      bytes: count(value.bytes, 1_099_511_627_776, 'byte'),
      durationMs: count(value.durationMs, 86_400_000, 'duration'),
      retries: count(value.retries, 1024, 'retry'),
      resume: count(value.resume, 1, 'resume'),
      parts: count(value.parts, 100_000, 'part'),
    });
    const key = [observation.operation, observation.backend, observation.outcome,
      observation.quota, observation.integrity].join('\0');
    let series = this.#series.get(key);
    if (!series) {
      if (this.#series.size >= this.seriesMaximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'telemetry series bound exceeded');
      series = {
        operation: observation.operation,
        backend: observation.backend,
        outcome: observation.outcome,
        quota: observation.quota,
        integrity: observation.integrity,
        observations: 0,
        bytes: 0,
        durationMs: 0,
        retries: 0,
        resumes: 0,
        parts: 0,
      };
      this.#series.set(key, series);
    }
    for (const field of ['bytes', 'durationMs', 'retries', 'parts']) {
      if (!Number.isSafeInteger(series[field] + observation[field])) transferError('TRANSFER_LIMIT_EXCEEDED', 'telemetry counter overflowed');
      series[field] += observation[field];
    }
    if (!Number.isSafeInteger(series.observations + 1)
        || !Number.isSafeInteger(series.resumes + observation.resume)) {
      transferError('TRANSFER_LIMIT_EXCEEDED', 'telemetry counter overflowed');
    }
    series.observations += 1;
    series.resumes += observation.resume;
  }

  snapshot() {
    const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
    return Object.freeze([...this.#series.values()]
      .map((series) => Object.freeze({ ...series }))
      .sort((left, right) => compare(
        `${left.operation}\0${left.backend}\0${left.outcome}`,
        `${right.operation}\0${right.backend}\0${right.outcome}`,
      )));
  }
}

export function nullTransferTelemetry() {
  return Object.freeze({ observe() {} });
}
