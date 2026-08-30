import { pathFail } from './errors.mjs';

export class OperationGuard {
  #deadline;
  #operations = 0;
  #maximumOperations;

  constructor(options = {}) {
    const maxTimeMs = options.maxTimeMs ?? 30_000;
    const maxOperations = options.maxOperations ?? 100_000;
    if (!Number.isSafeInteger(maxTimeMs) || maxTimeMs < 0 || !Number.isSafeInteger(maxOperations) || maxOperations < 1) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'configuration' });
    this.#deadline = Date.now() + maxTimeMs;
    this.#maximumOperations = maxOperations;
  }

  checkpoint(count = 1) {
    if (!Number.isSafeInteger(count) || count < 0) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'operations' });
    this.#operations += count;
    if (this.#operations > this.#maximumOperations) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'operations' });
    if (Date.now() > this.#deadline) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'time' });
  }

  async boundary(promiseOrFactory, signalAware = false) {
    this.checkpoint();
    const remaining = this.#deadline - Date.now();
    if (remaining < 0) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'time' });
    if (!signalAware) {
      const result = await (typeof promiseOrFactory === 'function' ? promiseOrFactory(undefined) : promiseOrFactory);
      this.checkpoint(0);
      return result;
    }
    const controller = new AbortController();
    let timer;
    const operation = Promise.resolve().then(() => typeof promiseOrFactory === 'function' ? promiseOrFactory(controller.signal) : promiseOrFactory);
    operation.catch(() => {});
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        try { pathFail('LIMIT_EXCEEDED', undefined, { resource: 'time' }); } catch (error) { reject(error); }
      }, remaining + 1);
    });
    try { return await Promise.race([operation, timeout]); }
    finally { clearTimeout(timer); }
  }

  async hook(hooks, name, context = Object.freeze({})) {
    if (hooks?.boundary === undefined) return;
    if (typeof hooks.boundary !== 'function') pathFail('PATH_INPUT_INVALID');
    await this.boundary((signal) => hooks.boundary(name, context, signal), true);
  }
}

export function boundedBytes(value, maximum, resource = 'bytes') {
  if (!Number.isSafeInteger(maximum) || maximum < 0) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'configuration' });
  let length;
  if (typeof value === 'string') length = Buffer.byteLength(value, 'utf8');
  else if (value instanceof ArrayBuffer) length = value.byteLength;
  else if (ArrayBuffer.isView(value)) length = value.byteLength;
  else pathFail('PATH_INPUT_INVALID');
  if (length > maximum) pathFail('LIMIT_EXCEEDED', undefined, { resource });
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  const view = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return Buffer.from(view);
}
