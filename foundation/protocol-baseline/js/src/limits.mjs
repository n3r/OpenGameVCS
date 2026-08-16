import { performance } from 'node:perf_hooks';

import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';

export const HARD_LIMITS = Object.freeze({
  jsonBytes: 1024 * 1024,
  jsonDepth: 64,
  jsonNodes: 100_000,
  jsonStringBytes: 64 * 1024,
  jsonKeyBytes: 256,
  objectMembers: 256,
  arrayItems: 4096,
  collectionItems: 100_000,
  schemaSteps: 1_000_000,
  manifestArtifacts: 4096,
  assetBytes: 8 * 1024 * 1024,
  contractBytes: 64 * 1024 * 1024,
  streamLineBytes: 1024 * 1024,
  streamBytes: 64 * 1024 * 1024,
  streamFrames: 100_000,
  stateEntries: 100_000,
  stateBytes: 64 * 1024 * 1024,
  stateTtlMs: 7 * 24 * 60 * 60 * 1000,
  controlMessageBytes: 1024 * 1024,
  canonicalInputBytes: 1024 * 1024,
  extensionEntries: 32,
  capabilityItems: 128,
  errorParameters: 16,
  pageItems: 1000,
  cursorBytes: 1024,
  idempotencyKeyBytes: 256,
  receiptBytes: 16 * 1024,
  grantBytes: 16 * 1024,
  transferRangeBytes: 1024 * 1024 * 1024,
  headerBytes: 32 * 1024,
  correlationIdBytes: 128,
  operationBytes: 256,
  safeParameterBytes: 1024,
  deadlineHorizonMs: 24 * 60 * 60 * 1000,
  receiptLifetimeMs: 5 * 60 * 1000,
  cursorLifetimeMs: 24 * 60 * 60 * 1000,
  registryEntries: 4096,
  adapterCases: 1024,
  adapterStdoutBytes: 64 * 1024 * 1024,
  adapterStderrBytes: 8 * 1024 * 1024,
  adapterLineBytes: 4 * 1024 * 1024,
  timeoutMs: 120_000,
});

export const PROTOCOL_LIMITS_BY_NAME = Object.freeze({
  maxControlMessageBytes: HARD_LIMITS.controlMessageBytes,
  maxCanonicalInputBytes: HARD_LIMITS.canonicalInputBytes,
  maxJsonDepth: HARD_LIMITS.jsonDepth,
  maxJsonNodes: HARD_LIMITS.jsonNodes,
  maxObjectMembers: HARD_LIMITS.objectMembers,
  maxArrayItems: HARD_LIMITS.arrayItems,
  maxStringUtf8Bytes: HARD_LIMITS.jsonStringBytes,
  maxExtensionEntries: HARD_LIMITS.extensionEntries,
  maxCapabilityItems: HARD_LIMITS.capabilityItems,
  maxErrorParameters: HARD_LIMITS.errorParameters,
  maxPageItems: HARD_LIMITS.pageItems,
  maxJsonlFrameBytes: HARD_LIMITS.streamLineBytes,
  maxJsonlFrames: HARD_LIMITS.streamFrames,
  maxCursorBytes: HARD_LIMITS.cursorBytes,
  maxIdempotencyKeyBytes: HARD_LIMITS.idempotencyKeyBytes,
  maxReceiptBytes: HARD_LIMITS.receiptBytes,
  maxGrantBytes: HARD_LIMITS.grantBytes,
  maxTransferRangeBytes: HARD_LIMITS.transferRangeBytes,
  maxHeaderBytes: HARD_LIMITS.headerBytes,
  maxCorrelationIdBytes: HARD_LIMITS.correlationIdBytes,
  maxOperationBytes: HARD_LIMITS.operationBytes,
  maxRunnerCases: HARD_LIMITS.adapterCases,
  maxSafeParameterBytes: HARD_LIMITS.safeParameterBytes,
  maxDeadlineHorizonMs: HARD_LIMITS.deadlineHorizonMs,
  maxReceiptLifetimeMs: HARD_LIMITS.receiptLifetimeMs,
  maxCursorLifetimeMs: HARD_LIMITS.cursorLifetimeMs,
  maxRegistryEntries: HARD_LIMITS.registryEntries,
  maxJsonKeyUtf8Bytes: HARD_LIMITS.jsonKeyBytes,
  maxJsonCollectionItems: HARD_LIMITS.collectionItems,
  maxJsonlStreamBytes: HARD_LIMITS.streamBytes,
  maxWorkingMemoryBytes: HARD_LIMITS.stateBytes,
  maxOperationTimeMs: HARD_LIMITS.timeoutMs,
  maxSchemaEvaluationSteps: HARD_LIMITS.schemaSteps,
  maxContractArtifacts: HARD_LIMITS.manifestArtifacts,
  maxContractBytes: HARD_LIMITS.contractBytes,
});

export function boundedInteger(value, fallback, maximum, label, options = {}) {
  const result = value ?? fallback;
  const minimum = options.minimum ?? 1;
  if (!Number.isSafeInteger(result) || result < minimum || result > maximum) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is outside its supported range`);
  }
  return result;
}

export class Deadline {
  #controller;
  #expiresAt;
  #now;

  constructor(options = {}) {
    const timeoutMs = boundedInteger(options.timeoutMs, HARD_LIMITS.timeoutMs, HARD_LIMITS.timeoutMs, 'timeoutMs');
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'deadline signal must be an AbortSignal');
    }
    this.#controller = new AbortController();
    if (options.signal?.aborted) this.#controller.abort(Object.freeze({ kind: 'cancelled' }));
    else options.signal?.addEventListener('abort', () => this.#controller.abort(Object.freeze({ kind: 'cancelled' })), { once: true });
    this.#now = options.now ?? (() => performance.now());
    if (typeof this.#now !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'deadline clock must be callable');
    const start = this.#now();
    if (!Number.isFinite(start)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'deadline clock returned an invalid value');
    this.#expiresAt = start + timeoutMs;
  }

  checkpoint() {
    if (this.#controller.signal.aborted) {
      const code = this.#controller.signal.reason?.kind === 'deadline'
        ? RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED
        : RUNTIME_ERROR_CODES.CANCELLED;
      protocolError(code, code === RUNTIME_ERROR_CODES.CANCELLED ? 'protocol operation was cancelled' : 'protocol operation exceeded its deadline');
    }
    const now = this.#now();
    if (!Number.isFinite(now) || now >= this.#expiresAt) {
      this.#controller.abort(Object.freeze({ kind: 'deadline' }));
      protocolError(RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED, 'protocol operation exceeded its deadline');
    }
  }

  get signal() {
    return this.#controller.signal;
  }

  remainingMs() {
    this.checkpoint();
    return Math.max(1, Math.ceil(this.#expiresAt - this.#now()));
  }

  async race(promise, label = 'protocol host operation') {
    this.checkpoint();
    let timer;
    let abortListener;
    const deadlineBoundary = Object.freeze({ kind: 'deadline' });
    const cancelledBoundary = Object.freeze({ kind: 'cancelled' });
    const boundary = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        this.#controller.abort(deadlineBoundary);
        reject(deadlineBoundary);
      }, this.remainingMs());
      abortListener = () => reject(this.#controller.signal.reason?.kind === 'deadline' ? deadlineBoundary : cancelledBoundary);
      this.#controller.signal.addEventListener('abort', abortListener, { once: true });
    });
    try {
      const result = await Promise.race([Promise.resolve(promise), boundary]);
      this.checkpoint();
      return result;
    } catch (error) {
      if (error === deadlineBoundary) {
        protocolError(RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED, `${label} exceeded its deadline`, { cause: error });
      }
      if (error === cancelledBoundary) protocolError(RUNTIME_ERROR_CODES.CANCELLED, `${label} was cancelled`, { cause: error });
      throw error;
    } finally {
      clearTimeout(timer);
      if (abortListener) this.#controller.signal.removeEventListener('abort', abortListener);
    }
  }
}

export function deadlineFrom(options = {}) {
  if (options.deadline instanceof Deadline) return options.deadline;
  return new Deadline(options);
}
