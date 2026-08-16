import { performance } from 'node:perf_hooks';
import { OgvcsError, fail } from './errors.js';

const U64_MAX = 0xffff_ffff_ffff_ffffn;

export function asBytes(value, layer = 2, stage) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  fail('SCHEMA_FIELD_INVALID', { layer, stage });
}

export function asCount(value, maximum, code = 'LIMIT_COUNT', layer = 1) {
  if (!Number.isSafeInteger(value) || value < 0) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  if (value > maximum) fail(code, {
    layer,
    stage: layer === 1 ? 'configured-resource-preflight' : undefined
  });
  return value;
}

export function asLimit(value, fallback) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < 0) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return selected;
}

export function cborHeader(major, value) {
  let n;
  try { n = typeof value === 'bigint' ? value : BigInt(value); } catch {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  if (!Number.isInteger(major) || major < 0 || major > 7 || n < 0n || n > U64_MAX) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  if (n < 24n) return Uint8Array.of((major << 5) | Number(n));
  let size;
  let additional;
  if (n <= 0xffn) [size, additional] = [1, 24];
  else if (n <= 0xffffn) [size, additional] = [2, 25];
  else if (n <= 0xffff_ffffn) [size, additional] = [4, 26];
  else [size, additional] = [8, 27];
  const result = new Uint8Array(size + 1);
  result[0] = (major << 5) | additional;
  for (let offset = size; offset > 0; offset -= 1) {
    result[offset] = Number(n & 0xffn);
    n >>= 8n;
  }
  return result;
}

export function compareBytes(left, right) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}

export function exactMap(value, keys) {
  if (!(value instanceof Map) || value.size !== keys.length || keys.some(key => !value.has(key))) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  return value;
}

export class ResourceGuard {
  #started = performance.now();
  #maxTimeMs;
  #maxMemoryBytes;
  #controller = new AbortController();

  constructor({ maxTimeMs, maxMemoryBytes }) {
    this.#maxTimeMs = asLimit(maxTimeMs, Number.MAX_SAFE_INTEGER);
    this.#maxMemoryBytes = asLimit(maxMemoryBytes, 67_108_864);
  }

  time() {
    if (this.#maxTimeMs === 0 || performance.now() - this.#started > this.#maxTimeMs) {
      const error = this.#controller.signal.reason instanceof OgvcsError
        ? this.#controller.signal.reason : new OgvcsError('LIMIT_TIME', { layer: 1 });
      if (!this.#controller.signal.aborted) this.#controller.abort(error);
      throw error;
    }
  }

  /** Race one external await against the shared deadline and pass its AbortSignal. */
  async wait(callback) {
    if (typeof callback !== 'function') fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    this.time();
    const operation = Promise.resolve().then(() => callback(this.#controller.signal));
    // The unbounded default should not install a multi-century timer.
    if (this.#maxTimeMs === Number.MAX_SAFE_INTEGER) {
      const result = await operation;
      this.time();
      return result;
    }
    const remaining = this.#maxTimeMs - (performance.now() - this.#started);
    const error = new OgvcsError('LIMIT_TIME', { layer: 1 });
    let timer;
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        if (!this.#controller.signal.aborted) this.#controller.abort(error);
        reject(error);
      }, Math.max(1, Math.ceil(remaining)));
    });
    try {
      const result = await Promise.race([operation, timeout]);
      this.time();
      return result;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Start best-effort cleanup after the deadline without exposing a late rejection. */
  cleanup(callback) {
    if (typeof callback !== 'function') fail('SCHEMA_FIELD_INVALID', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    const operation = Promise.resolve().then(() => callback(this.#controller.signal));
    operation.catch(() => {});
    return operation;
  }

  memory(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    if (bytes > this.#maxMemoryBytes) fail('LIMIT_MEMORY', { layer: 1 });
  }

  elapsedMilliseconds() { return performance.now() - this.#started; }
  get maxMemoryBytes() { return this.#maxMemoryBytes; }
  get signal() { return this.#controller.signal; }
}

async function waitForDrain(sink, signal) {
  if (typeof sink.once !== 'function') fail('SCHEMA_FIELD_INVALID', {
    layer: 1, stage: 'configured-resource-preflight'
  });
  await new Promise((resolve, reject) => {
    const cleanup = () => {
      sink.off?.('drain', drained);
      sink.off?.('error', failed);
      signal?.removeEventListener('abort', aborted);
    };
    const drained = () => { cleanup(); resolve(); };
    const failed = cause => { cleanup(); reject(cause); };
    const aborted = () => { cleanup(); reject(signal.reason ?? new OgvcsError('LIMIT_TIME', { layer: 1 })); };
    if (signal?.aborted) { aborted(); return; }
    sink.once('drain', drained);
    sink.once('error', failed);
    signal?.addEventListener('abort', aborted, { once: true });
  });
}

/**
 * Writes every byte even when a FileHandle-like writer reports a short write.
 * Node stream `false` means the complete chunk was accepted with backpressure,
 * so it is drained rather than retried.
 */
export async function writeFully(sink, value, { guard } = {}) {
  const bytes = asBytes(value, 1, 'configured-resource-preflight');
  if (typeof sink !== 'function' && typeof sink?.write !== 'function') {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  let offset = 0;
  while (offset < bytes.length) {
    const part = bytes.subarray(offset);
    const callback = typeof sink === 'function';
    const invoke = signal => callback ? sink(part, { signal }) : sink.write(part);
    const result = guard ? await guard.wait(invoke) : await invoke(undefined);
    if (result === false) {
      if (guard) await guard.wait(signal => waitForDrain(sink, signal));
      else await waitForDrain(sink);
      offset = bytes.length;
      continue;
    }
    let written;
    if (!callback && typeof result === 'number') written = result;
    else if (result && typeof result === 'object' && Number.isSafeInteger(result.bytesWritten)) written = result.bytesWritten;
    else written = part.length;
    if (!Number.isSafeInteger(written) || written <= 0 || written > part.length) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    offset += written;
  }
}

export function toAsyncIterable(value) {
  if (value?.[Symbol.asyncIterator] || value?.[Symbol.iterator]) return value;
  fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}

/**
 * Drive a caller-owned iterator through the shared deadline. Iterator methods
 * receive the signal as an optional protocol value; built-in iterators ignore
 * it, while cooperative sources can cancel their pending work.
 */
export async function* guardedAsyncIterable(value, guard) {
  const source = toAsyncIterable(value);
  const iterator = source[Symbol.asyncIterator]?.() ?? source[Symbol.iterator]?.();
  if (!iterator || typeof iterator.next !== 'function') fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  let completed = false;
  try {
    while (true) {
      const step = await guard.wait(signal => iterator.next({ signal }));
      if (!step || typeof step !== 'object') fail('SCHEMA_FIELD_INVALID', { layer: 2 });
      if (step.done) { completed = true; return; }
      yield step.value;
    }
  } finally {
    if (!completed && typeof iterator.return === 'function') {
      if (guard.signal.aborted) guard.cleanup(signal => iterator.return({ signal }));
      else await guard.wait(signal => iterator.return({ signal }));
    }
  }
}

export function checkedBigUint(value, maximum, code = 'SCHEMA_FIELD_INVALID', minimum = 0n) {
  if ((typeof value !== 'number' || !Number.isSafeInteger(value)) && typeof value !== 'bigint') {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const result = BigInt(value);
  if (result < minimum || result > maximum) fail(code, { layer: 2 });
  return result;
}
