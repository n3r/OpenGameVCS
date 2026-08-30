import { performance } from 'node:perf_hooks';
import { fail, normalizeError } from './errors.mjs';

function validateSignal(signal) {
  if (signal === undefined) return;
  try {
    if (!signal || typeof signal.aborted !== 'boolean' ||
        typeof signal.addEventListener !== 'function' ||
        typeof signal.removeEventListener !== 'function') {
      fail('CHUNK_RESOURCE_INVALID', { resource: 'cancellation' });
    }
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_RESOURCE_INVALID', { resource: 'cancellation' });
  }
}

export function createOperationControl({ signal, maxElapsedMilliseconds } = {}) {
  validateSignal(signal);
  if (maxElapsedMilliseconds !== undefined &&
      (!Number.isSafeInteger(maxElapsedMilliseconds) || maxElapsedMilliseconds < 0)) {
    fail('CHUNK_RESOURCE_INVALID', { resource: 'deadline' });
  }

  const started = performance.now();
  const controller = new AbortController();
  let expired = false;
  let disposed = false;
  let timer;
  const cancel = () => controller.abort();
  if (signal !== undefined) {
    if (signal.aborted) cancel();
    else signal.addEventListener('abort', cancel, { once: true });
  }
  if (maxElapsedMilliseconds !== undefined) {
    timer = setTimeout(() => {
      expired = true;
      controller.abort();
    }, Math.min(maxElapsedMilliseconds, 0x7fff_ffff));
    timer.unref?.();
  }

  function check() {
    if (disposed) fail('CHUNK_SESSION_FAILED');
    let externallyAborted = false;
    try { externallyAborted = signal?.aborted ?? false; }
    catch (cause) {
      throw normalizeError(cause, 'CHUNK_RESOURCE_INVALID', { resource: 'cancellation' });
    }
    if (externallyAborted || controller.signal.aborted) {
      fail('CHUNK_RESOURCE_EXHAUSTED', {
        resource: expired ? 'deadline' : 'cancellation',
      });
    }
    if (maxElapsedMilliseconds !== undefined &&
        performance.now() - started >= maxElapsedMilliseconds) {
      expired = true;
      controller.abort();
      fail('CHUNK_RESOURCE_EXHAUSTED', { resource: 'deadline' });
    }
  }

  async function wait(operation, fallbackCode, details = {}) {
    check();
    const performed = Promise.resolve().then(operation)
      .catch((cause) => { throw normalizeError(cause, fallbackCode, details); });
    if (signal === undefined && maxElapsedMilliseconds === undefined) return performed;
    let rejectAbort;
    const aborted = new Promise((resolve, reject) => { rejectAbort = reject; });
    const onAbort = () => rejectAbort(normalizeError(
      undefined,
      'CHUNK_RESOURCE_EXHAUSTED',
      { resource: expired ? 'deadline' : 'cancellation' },
    ));
    controller.signal.addEventListener('abort', onAbort, { once: true });
    if (controller.signal.aborted) onAbort();
    try {
      return await Promise.race([performed, aborted]);
    } finally {
      controller.signal.removeEventListener('abort', onAbort);
    }
  }

  return Object.freeze({
    check,
    context: Object.freeze({ signal: controller.signal }),
    dispose() {
      if (disposed) return;
      disposed = true;
      if (timer !== undefined) clearTimeout(timer);
      try { signal?.removeEventListener('abort', cancel); } catch {}
    },
    wait,
  });
}
