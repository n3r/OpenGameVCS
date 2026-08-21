export const HARNESS_ERROR_CODES = Object.freeze([
  'HARNESS_OK',
  'HARNESS_INPUT_INVALID',
  'HARNESS_LIMIT_EXCEEDED',
  'HARNESS_NEGOTIATION_INCOMPATIBLE',
  'HARNESS_PROTOCOL_MALFORMED',
  'HARNESS_DRIVER_FAILED',
  'HARNESS_RETRYABLE',
  'HARNESS_TASK_INCOMPLETE',
  'HARNESS_ASSERTION_FAILED',
  'HARNESS_FAULT_INVARIANT_FAILED',
  'HARNESS_THRESHOLD_FAILED',
  'HARNESS_BUNDLE_INVALID',
  'HARNESS_CACHE_STATE_INVALID',
  'HARNESS_PRIVILEGE_REQUIRED',
  'HARNESS_DEADLINE_EXCEEDED',
  'HARNESS_CANCELLED',
  'HARNESS_IO',
]);

const CODE_SET = new Set(HARNESS_ERROR_CODES);

export class BenchmarkHarnessError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'BenchmarkHarnessError';
    this.code = code;
    if (options.details !== undefined) this.details = Object.freeze({ ...options.details });
  }
}

export function harnessFail(code, message, options) {
  if (!CODE_SET.has(code) || code === 'HARNESS_OK') throw new TypeError('invalid benchmark harness error code');
  throw new BenchmarkHarnessError(code, message, options);
}

export function asHarnessError(error, fallback = 'HARNESS_DRIVER_FAILED') {
  if (error instanceof BenchmarkHarnessError) return error;
  return new BenchmarkHarnessError(fallback, 'benchmark harness operation failed', { cause: error });
}
