import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { types } from 'node:util';
import {
  canonicalJson,
  isReferenceJobDeadlineCurrent,
  isDigest,
  isId,
  parseAndVerifyToolManifest,
  referenceJobFingerprint,
  safeResult,
  sha256,
  snapshotAcquisitionRequest,
  snapshotReferenceJobForReplay,
  snapshotTrustedManifestKeys,
  validateJobManifestBinding,
} from './reference-contract.mjs';
import { parseOutputFrame } from './output-frame.mjs';
import {
  isPinnedFileOperationAborted,
  openPinnedImmutableFile,
  ReferenceStateStore,
} from './reference-state.mjs';

const CATALOG_KEYS = Object.freeze(['manifestBytes', 'toolPath']);
const SOURCE_KEYS = Object.freeze(['acquire', 'credential', 'maximumBytes', 'sourceId']);
const TERMINAL_STATES = new Set(['denied', 'validated']);
const MAXIMUM_INPUT_BYTES = 256 * 1024 * 1024;
const MAXIMUM_QUEUE_DEPTH = 64;
const ACQUISITION_SETTLEMENT_MILLISECONDS = 1_000;
const MAXIMUM_PROVENANCE_BYTES = 64 * 1024;
const POSTSTART_SINGLETON_DIAGNOSTIC_EVENTS = Object.freeze([
  'OUTPUT_FRAME_INVALID',
  'TRUSTED_OUTPUT_SHIM_REJECTED',
]);
const WORKER_FAILURE_CLASSES = Object.freeze([
  'ACTIVATION_CONTROL',
  'CONTROL',
  'ENTRYPOINT',
  'INPUT_READ',
  'OUTPUT_WRITE',
  'STDERR',
  'STDOUT',
  'TOOL_EXITED',
]);
const WORKER_FAILURE_EVENTS = Object.freeze(WORKER_FAILURE_CLASSES.map((failureClass) => `WORKER_FAILURE_${failureClass}`));
const VERIFIED_WORKER_FAILURE_CLASSES = Object.freeze([...WORKER_FAILURE_CLASSES, 'NONZERO']);
const VERIFIED_WORKER_FAILURE_EVENTS = Object.freeze(VERIFIED_WORKER_FAILURE_CLASSES.map((failureClass) => `WORKER_FAILURE_${failureClass}`));
const PRESTART_INSPECT_MISMATCHES = Object.freeze([
  'anchor-running',
  'config-content',
  'config-image',
  'config-io',
  'config-labels',
  'config-process',
  'effective-mounts',
  'host-capabilities',
  'host-devices',
  'host-lifecycle',
  'host-logging',
  'host-mounts',
  'host-namespaces',
  'host-network',
  'host-resources',
  'host-root',
  'host-runtime',
  'host-security',
  'host-tmpfs',
  'host-ulimits',
  'identity',
  'inspect-response',
  'inspect-shape',
  'network-attachment',
  'output-volume',
  'state',
]);
const PRESTART_DIAGNOSTIC_EVENTS = Object.freeze(PRESTART_INSPECT_MISMATCHES.map((mismatch) => `PRESTART_INSPECT_${mismatch.replaceAll('-', '_').toUpperCase()}`));
const DIAGNOSTIC_REQUEST_KEYS = Object.freeze(['evidenceBytes', 'evidenceHmacKey', 'evidenceKeyId', 'result']);
const RESULT_KEYS = Object.freeze(['cleanupReceiptDigest', 'code', 'jobId', 'outputDigest', 'provenanceDigest', 'schemaVersion', 'status']);
const PROVENANCE_PAYLOAD_KEYS = Object.freeze([
  'actorDigest',
  'brokerVersion',
  'cleanupReceiptDigest',
  'completedAtUnixMs',
  'frameBytes',
  'inputDigest',
  'jobFingerprint',
  'jobId',
  'manifestDigest',
  'optionsDigest',
  'outputBytes',
  'outputDigest',
  'outputRecords',
  'resourcePolicyDigest',
  'runtimeDigest',
  'sandboxVersion',
  'schemaVersion',
  'seccompProfileDigest',
  'securityEvents',
  'startedAtUnixMs',
  'toolDigest',
  'validationCode',
]);
const PROVENANCE_KEYS = Object.freeze([
  'actorDigest',
  'brokerVersion',
  'cleanupReceiptDigest',
  'completedAtUnixMs',
  'evidenceKeyId',
  'evidenceMacSha256',
  'frameBytes',
  'inputDigest',
  'jobFingerprint',
  'jobId',
  'manifestDigest',
  'optionsDigest',
  'outputBytes',
  'outputDigest',
  'outputRecords',
  'resourcePolicyDigest',
  'runtimeDigest',
  'sandboxVersion',
  'schemaVersion',
  'seccompProfileDigest',
  'securityEvents',
  'startedAtUnixMs',
  'toolDigest',
  'validationCode',
]);
const services = new WeakSet();

const exactRecord = (source, keys) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Object.keys(descriptors).sort().join('\0') !== keys.join('\0')) return null;
    if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable || !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set'))) return null;
    return Object.freeze(Object.fromEntries(keys.map((key) => [key, descriptors[key].value])));
  } catch { return null; }
};

const snapshotSources = (source) => {
  if (!Array.isArray(source) || source.length < 1 || source.length > 64) throw new TypeError('acquisition source catalog is invalid');
  const values = new Map();
  for (const entrySource of source) {
    const entry = exactRecord(entrySource, SOURCE_KEYS);
    if (!entry || !isId(entry.sourceId) || values.has(entry.sourceId) || typeof entry.acquire !== 'function' || types.isProxy(entry.acquire) || !Number.isSafeInteger(entry.maximumBytes) || entry.maximumBytes < 1 || entry.maximumBytes > MAXIMUM_INPUT_BYTES || !(typeof entry.credential === 'string' ? entry.credential.length > 0 && Buffer.byteLength(entry.credential) <= 16 * 1024 : Buffer.isBuffer(entry.credential) && Object.getPrototypeOf(entry.credential) === Buffer.prototype && entry.credential.length > 0 && entry.credential.length <= 16 * 1024)) throw new TypeError('acquisition source entry is invalid');
    values.set(entry.sourceId, Object.freeze({ ...entry, credential: Buffer.isBuffer(entry.credential) ? Buffer.from(entry.credential) : entry.credential }));
  }
  return values;
};

const snapshotCatalog = ({ entries, trustedKeys, nowUnixMs }) => {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 256) throw new TypeError('tool manifest catalog is invalid');
  const catalog = new Map();
  for (const entrySource of entries) {
    const entry = exactRecord(entrySource, CATALOG_KEYS);
    const manifest = entry && parseAndVerifyToolManifest({ manifestBytes: entry.manifestBytes, trustedKeys, nowUnixMs });
    if (!manifest || typeof entry.toolPath !== 'string' || catalog.has(manifest.manifestDigest)) throw new TypeError('tool manifest catalog entry is invalid');
    catalog.set(manifest.manifestDigest, Object.freeze({ manifest, manifestBytes: Buffer.from(entry.manifestBytes), toolPath: entry.toolPath }));
  }
  return catalog;
};

const boundedAcquisition = async ({ operation, controller, deadlineMilliseconds }) => {
  let timer;
  const completion = Promise.resolve().then(operation).then(
    (value) => Object.freeze({ value }),
    () => Object.freeze({ failed: true }),
  );
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => { controller.abort(); resolve(Object.freeze({ timedOut: true })); }, deadlineMilliseconds);
  });
  const first = await Promise.race([completion, deadline]);
  clearTimeout(timer);
  if (!first.timedOut) return first;
  const settled = await Promise.race([
    completion,
    new Promise((resolve) => setTimeout(() => resolve(Object.freeze({ unsettled: true })), ACQUISITION_SETTLEMENT_MILLISECONDS)),
  ]);
  return settled.unsettled ? Object.freeze({ containmentFailure: true }) : Object.freeze({ timedOut: true });
};

const resultFromStored = (record) => record?.result ? Object.freeze({ ...record.result }) : null;

const safeErrorMessage = (error) => {
  try {
    if (error === null || typeof error !== 'object' || types.isProxy(error)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
    return descriptor && Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'string' ? descriptor.value : null;
  } catch { return null; }
};

const safeInspectEvent = (message) => {
  const index = PRESTART_INSPECT_MISMATCHES.findIndex((mismatch) => message === `SANDBOX_INSPECT_MISMATCH:${mismatch}`);
  return index < 0 ? null : PRESTART_DIAGNOSTIC_EVENTS[index];
};

const workerFailureEvent = (failureClass) => {
  const index = typeof failureClass === 'string' ? WORKER_FAILURE_CLASSES.indexOf(failureClass) : -1;
  return index < 0 ? null : WORKER_FAILURE_EVENTS[index];
};

const evidenceMacSha256 = (key, payload) => createHmac('sha256', key)
  .update('OGVCS-SANDBOX-EVIDENCE-V1\0', 'utf8')
  .update(canonicalJson(payload), 'utf8')
  .digest('hex');

export const authenticatedResultDiagnostic = (source) => {
  try {
    const request = exactRecord(source, DIAGNOSTIC_REQUEST_KEYS);
    if (!request
      || !Buffer.isBuffer(request.evidenceBytes)
      || Object.getPrototypeOf(request.evidenceBytes) !== Buffer.prototype
      || request.evidenceBytes.length < 1
      || request.evidenceBytes.length > MAXIMUM_PROVENANCE_BYTES
      || !Buffer.isBuffer(request.evidenceHmacKey)
      || Object.getPrototypeOf(request.evidenceHmacKey) !== Buffer.prototype
      || request.evidenceHmacKey.length !== 32
      || !isId(request.evidenceKeyId)) return 'none';
    const result = exactRecord(request.result, RESULT_KEYS);
    const validatedResult = result?.code === 'VALIDATED'
      && result.status === 'validated'
      && isDigest(result.outputDigest);
    const deniedResult = ['SANDBOX_UNAVAILABLE', 'SANDBOX_VALIDATION_FAILED'].includes(result?.code)
      && result.status === 'denied'
      && result.outputDigest === null;
    if (!result
      || result.schemaVersion !== 'ogvcs.untrusted-sandbox/reference-result/v1'
      || (!validatedResult && !deniedResult)
      || !isId(result.jobId)
      || !isDigest(result.provenanceDigest)
      || sha256(request.evidenceBytes) !== result.provenanceDigest) return 'none';
    const text = request.evidenceBytes.toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(request.evidenceBytes) || !text.endsWith('\n')) return 'none';
    const parsed = JSON.parse(text.slice(0, -1));
    if (`${canonicalJson(parsed)}\n` !== text) return 'none';
    const provenance = exactRecord(parsed, PROVENANCE_KEYS);
    if (!provenance
      || provenance.schemaVersion !== 'ogvcs.untrusted-sandbox/provenance/v1'
      || provenance.jobId !== result.jobId
      || provenance.validationCode !== result.code
      || provenance.outputDigest !== result.outputDigest
      || provenance.cleanupReceiptDigest !== result.cleanupReceiptDigest
      || !isDigest(provenance.cleanupReceiptDigest)
      || provenance.evidenceKeyId !== request.evidenceKeyId
      || !isDigest(provenance.evidenceMacSha256)) return 'none';
    const payload = Object.fromEntries(PROVENANCE_PAYLOAD_KEYS.map((key) => [key, provenance[key]]));
    const expectedMac = Buffer.from(evidenceMacSha256(request.evidenceHmacKey, payload), 'hex');
    const suppliedMac = Buffer.from(provenance.evidenceMacSha256, 'hex');
    if (suppliedMac.length !== expectedMac.length || !timingSafeEqual(suppliedMac, expectedMac)) return 'none';
    if (!Array.isArray(provenance.securityEvents)) return 'none';
    if (validatedResult) return provenance.securityEvents.length === 0
      && provenance.outputRecords === 0
      && provenance.outputBytes === 0
      ? 'VALIDATED_EMPTY_OUTPUT'
      : 'none';
    if (result.code === 'SANDBOX_VALIDATION_FAILED') {
      if (provenance.securityEvents.length === 1 && POSTSTART_SINGLETON_DIAGNOSTIC_EVENTS.includes(provenance.securityEvents[0])) return provenance.securityEvents[0];
      if (provenance.securityEvents.length !== 2 || provenance.securityEvents[0] !== 'WORKER_FAILED') return 'none';
      const detailIndex = VERIFIED_WORKER_FAILURE_EVENTS.indexOf(provenance.securityEvents[1]);
      return detailIndex < 0 ? 'none' : `WORKER_FAILED:${VERIFIED_WORKER_FAILURE_CLASSES[detailIndex]}`;
    }
    return provenance.securityEvents.length === 2
      && PRESTART_DIAGNOSTIC_EVENTS.includes(provenance.securityEvents[0])
      && provenance.securityEvents[1] === 'REFERENCE_INTERNAL_FAILURE' ? provenance.securityEvents[0] : 'none';
  } catch { return 'none'; }
};

export class ReferenceSandboxService {
  #adapter;
  #catalog;
  #trustedKeys;
  #sources;
  #state;
  #clock;
  #evidenceKey;
  #evidenceKeyId;
  #active = new Map();
  #queue = Promise.resolve();
  #queueDepth = 0;
  #poisoned = false;
  #closed = false;
  #faults;
  #metrics = { cancelled: 0, denied: 0, resourceKills: 0, securityViolations: 0, validated: 0 };

  static async open({ adapter, stateRoot, manifestCatalog, trustedManifestKeys, acquisitionSources, evidenceHmacKey, evidenceHmacKeyId, clock = Date.now, faults = null }) {
    if (!adapter || typeof adapter.verifyRuntimeImage !== 'function' || typeof adapter.runTool !== 'function' || typeof adapter.collectOutput !== 'function' || typeof adapter.discardVolume !== 'function' || !isDigest(adapter.seccompDigest) || typeof clock !== 'function' || types.isProxy(clock) || !Buffer.isBuffer(evidenceHmacKey) || Object.getPrototypeOf(evidenceHmacKey) !== Buffer.prototype || evidenceHmacKey.length !== 32 || !isId(evidenceHmacKeyId)) throw new TypeError('reference sandbox service configuration is invalid');
    const nowUnixMs = clock();
    if (!Number.isSafeInteger(nowUnixMs) || nowUnixMs < 0) throw new TypeError('reference sandbox clock is invalid');
    const trustedKeys = snapshotTrustedManifestKeys(trustedManifestKeys);
    const catalog = snapshotCatalog({ entries: manifestCatalog, trustedKeys, nowUnixMs });
    const sources = snapshotSources(acquisitionSources);
    const state = await ReferenceStateStore.open(stateRoot);
    try {
      await state.recoverInterrupted(nowUnixMs);
      await state.reconcileRevocations(nowUnixMs);
      for (const entry of catalog.values()) {
        const pinned = await openPinnedImmutableFile(entry.toolPath, entry.manifest.toolDigest, MAXIMUM_INPUT_BYTES, { executable: true });
        await pinned.handle.close();
        if (!await adapter.verifyRuntimeImage(entry.manifest.runtimeImage, entry.manifest.runtimeContractSha256)) throw new Error('signed runtime image is unavailable or differs');
      }
      const service = new ReferenceSandboxService({ adapter, catalog, trustedKeys, sources, state, clock, evidenceHmacKey, evidenceHmacKeyId, faults });
      services.add(service);
      return service;
    } catch (error) {
      await state.close().catch(() => {});
      throw error;
    }
  }

  constructor({ adapter, catalog, trustedKeys, sources, state, clock, evidenceHmacKey, evidenceHmacKeyId, faults }) {
    this.#adapter = adapter; this.#catalog = catalog; this.#trustedKeys = trustedKeys; this.#sources = sources; this.#state = state; this.#clock = clock; this.#evidenceKey = Buffer.from(evidenceHmacKey); this.#evidenceKeyId = evidenceHmacKeyId; this.#faults = faults;
  }

  #now() {
    const value = this.#clock();
    if (!Number.isSafeInteger(value) || value < 0) { this.#poisoned = true; throw new Error('reference sandbox clock failed'); }
    return value;
  }

  #fault(name) {
    if (this.#faults?.has(name)) {
      this.#faults.delete(name);
      throw new Error(`injected-${name}`);
    }
  }

  async #currentManifest(entry) {
    return parseAndVerifyToolManifest({ manifestBytes: entry.manifestBytes, trustedKeys: this.#trustedKeys, nowUnixMs: this.#now() });
  }

  async #revoked(manifest) {
    const [tool, runtime] = await Promise.all([
      this.#state.readRevocation('tool', manifest.toolDigest),
      this.#state.readRevocation('runtime', manifest.runtimeDigest),
    ]);
    return (tool && tool.throughGeneration >= manifest.generation) || (runtime && runtime.throughGeneration >= manifest.generation);
  }

  #authenticateEvidence(payload) {
    return evidenceMacSha256(this.#evidenceKey, payload);
  }

  async #finalize({ base, code, output = null, outputTemporary = null, securityEvents, startedAtUnixMs }) {
    const completedAtUnixMs = this.#now();
    const cleanup = Object.freeze({
      containerSettled: true,
      outputVolumeRemoved: true,
      scratchDestroyed: true,
      stagedInputRetained: true,
      schemaVersion: 'ogvcs.untrusted-sandbox/cleanup-receipt/v1',
      jobId: base.jobId,
      completedAtUnixMs,
    });
    const cleanupDigest = sha256(Buffer.from(`${canonicalJson(cleanup)}\n`, 'utf8'));
    await this.#state.writeEvidence(cleanupDigest, cleanup);
    const provenancePayload = Object.freeze({
      actorDigest: base.actorDigest,
      brokerVersion: 'linux-reference-v1',
      cleanupReceiptDigest: cleanupDigest,
      completedAtUnixMs,
      frameBytes: output?.frameBytes ?? 0,
      inputDigest: base.inputDigest,
      jobFingerprint: base.fingerprint,
      jobId: base.jobId,
      manifestDigest: base.manifestDigest,
      optionsDigest: base.optionsDigest,
      outputBytes: output?.bytes ?? 0,
      outputDigest: output?.outputDigest ?? null,
      outputRecords: output?.records ?? 0,
      resourcePolicyDigest: base.resourcePolicyDigest,
      runtimeDigest: base.runtimeDigest,
      sandboxVersion: 'linux-oci-v1',
      schemaVersion: 'ogvcs.untrusted-sandbox/provenance/v1',
      seccompProfileDigest: this.#adapter.seccompDigest,
      securityEvents: Object.freeze([...securityEvents].sort()),
      startedAtUnixMs,
      toolDigest: base.toolDigest,
      validationCode: code,
    });
    const provenance = Object.freeze({ ...provenancePayload, evidenceKeyId: this.#evidenceKeyId, evidenceMacSha256: this.#authenticateEvidence(provenancePayload) });
    const provenanceDigest = sha256(Buffer.from(`${canonicalJson(provenance)}\n`, 'utf8'));
    await this.#state.writeEvidence(provenanceDigest, provenance);
    this.#fault('before-output-commit');
    if (code === 'VALIDATED') {
      await this.#state.commitOutput(base.jobId, outputTemporary);
      this.#fault('after-output-commit');
    } else if (outputTemporary) await rm(outputTemporary, { recursive: true, force: true });
    const result = safeResult({ jobId: base.jobId, code, outputDigest: output?.outputDigest ?? null, provenanceDigest, cleanupReceiptDigest: cleanupDigest });
    await this.#state.writeJob({ ...base, completedAtUnixMs, result, securityEvents: [...securityEvents].sort(), state: code === 'VALIDATED' ? 'validated' : 'denied' });
    if (code === 'VALIDATED') this.#metrics.validated += 1; else this.#metrics.denied += 1;
    if (code === 'SANDBOX_CANCELLED') this.#metrics.cancelled += 1;
    if (['SANDBOX_OUTPUT_LIMIT', 'SANDBOX_RESOURCE_LIMIT', 'SANDBOX_TIMEOUT'].includes(code)) this.#metrics.resourceKills += 1;
    this.#metrics.securityViolations += securityEvents.length;
    return result;
  }

  async #execute({ base, job, acquisition, entry, controller }) {
    const startedAtUnixMs = this.#now();
    const securityEvents = [];
    let outputTemporary = null;
    let volume = null;
    try {
      if (job.deadlineUnixMs <= startedAtUnixMs) return await this.#finalize({ base, code: 'SANDBOX_TIMEOUT', securityEvents: ['DEADLINE_EXPIRED_BEFORE_ACQUISITION'], startedAtUnixMs });
      const manifest = await this.#currentManifest(entry);
      if (!manifest || !validateJobManifestBinding(job, manifest)) return await this.#finalize({ base, code: 'SANDBOX_PROTOCOL_INVALID', securityEvents: ['MANIFEST_BINDING_INVALID'], startedAtUnixMs });
      if (await this.#revoked(manifest)) return await this.#finalize({ base, code: 'SANDBOX_REVOKED', securityEvents: ['TOOL_OR_RUNTIME_REVOKED'], startedAtUnixMs });
      const source = this.#sources.get(acquisition.sourceId);
      if (!source || acquisition.maximumBytes > source.maximumBytes) return await this.#finalize({ base, code: 'SANDBOX_PROTOCOL_INVALID', securityEvents: ['ACQUISITION_SOURCE_DENIED'], startedAtUnixMs });
      await this.#state.writeJob({ ...base, startedAtUnixMs, state: 'acquiring' });
      const remaining = Math.max(1, Math.min(job.deadlineUnixMs - this.#now(), manifest.resourcePolicy.elapsedMilliseconds));
      const acquired = await boundedAcquisition({
        controller,
        deadlineMilliseconds: remaining,
        operation: async () => {
          const bytes = await source.acquire(Object.freeze({
            actorDigest: job.actorDigest,
            credential: source.credential,
            objectIdDigest: acquisition.objectIdDigest,
            purpose: job.purpose,
          }), controller.signal);
          return this.#state.stageInput({ expectedDigest: job.inputDigest, maximumBytes: acquisition.maximumBytes, source: bytes });
        },
      });
      if (acquired.containmentFailure) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      if (acquired.failed || acquired.timedOut || controller.signal.aborted) return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ACQUISITION_ABORTED'], startedAtUnixMs });
      const staged = acquired.value;
      await this.#state.writeJob({ ...base, stagedBytes: staged.bytes, startedAtUnixMs, state: 'staged' });
      this.#fault('after-stage');
      const current = await this.#currentManifest(entry);
      if (!current || !validateJobManifestBinding(job, current) || await this.#revoked(current)) return await this.#finalize({ base, code: 'SANDBOX_REVOKED', securityEvents: ['AUTHORITY_CHANGED_BEFORE_LAUNCH'], startedAtUnixMs });
      if (!await this.#adapter.verifyRuntimeImage(current.runtimeImage, current.runtimeContractSha256)) return await this.#finalize({ base, code: 'SANDBOX_UNAVAILABLE', securityEvents: ['RUNTIME_IMAGE_UNAVAILABLE'], startedAtUnixMs });
      if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ALIAS_MATERIALIZATION_ABORTED'], startedAtUnixMs });
      const continuePinnedFileOperation = () => !controller.signal.aborted && job.deadlineUnixMs > this.#now();
      const finalizePinnedFileAbort = () => this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['PINNED_FILE_OPERATION_ABORTED'], startedAtUnixMs });
      let input;
      try { input = await openPinnedImmutableFile(staged.path, job.inputDigest, acquisition.maximumBytes, { continueRead: continuePinnedFileOperation }); } catch (error) {
        if (isPinnedFileOperationAborted(error)) return await finalizePinnedFileAbort();
        throw error;
      }
      let tool;
      try { tool = await openPinnedImmutableFile(entry.toolPath, current.toolDigest, MAXIMUM_INPUT_BYTES, { continueRead: continuePinnedFileOperation, executable: true }); } catch (error) {
        await input.handle.close().catch(() => {});
        if (isPinnedFileOperationAborted(error)) return await finalizePinnedFileAbort();
        throw error;
      }
      const jobBytes = Buffer.from(canonicalJson(job), 'utf8');
      const jobDigest = sha256(jobBytes);
      let jobSourceHandle;
      try { jobSourceHandle = await this.#state.createEphemeralPinnedFile('job', jobBytes); } catch (error) { await Promise.allSettled([input.handle.close(), tool.handle.close()]); throw error; }
      const aliases = [];
      const materializeAlias = async (handle, digest, maximumBytes, options = {}) => {
        try { return await this.#state.materializePinnedAlias(handle, digest, maximumBytes, { ...options, continueCopy: continuePinnedFileOperation }); } catch (error) {
          if (isPinnedFileOperationAborted(error)) return null;
          throw error;
        }
      };
      try {
        const inputAlias = await materializeAlias(input.handle, job.inputDigest, acquisition.maximumBytes);
        if (!inputAlias) return await finalizePinnedFileAbort();
        aliases.push(inputAlias);
        if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ALIAS_MATERIALIZATION_ABORTED'], startedAtUnixMs });
        const jobAlias = await materializeAlias(jobSourceHandle, jobDigest, 1024 * 1024);
        if (!jobAlias) return await finalizePinnedFileAbort();
        aliases.push(jobAlias);
        if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ALIAS_MATERIALIZATION_ABORTED'], startedAtUnixMs });
        const toolAlias = await materializeAlias(tool.handle, current.toolDigest, MAXIMUM_INPUT_BYTES, { executable: true });
        if (!toolAlias) return await finalizePinnedFileAbort();
        aliases.push(toolAlias);
        if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ALIAS_MATERIALIZATION_ABORTED'], startedAtUnixMs });
        await this.#state.writeJob({ ...base, stagedBytes: staged.bytes, startedAtUnixMs, state: 'running' });
        const run = await this.#adapter.runTool({ runtimeImage: current.runtimeImage, policy: current.resourcePolicy, inputHandle: inputAlias.handle, jobHandle: jobAlias.handle, jobId: job.jobId, toolHandle: toolAlias.handle, signal: controller.signal });
        volume = run.volume;
        let aliasesValid = true;
        let verificationAborted = false;
        const verification = await Promise.allSettled([
          this.#state.verifyPinnedAlias(inputAlias.handle, job.inputDigest, acquisition.maximumBytes, { continueRead: continuePinnedFileOperation }),
          this.#state.verifyPinnedAlias(jobAlias.handle, jobDigest, 1024 * 1024, { continueRead: continuePinnedFileOperation }),
          this.#state.verifyPinnedAlias(toolAlias.handle, current.toolDigest, MAXIMUM_INPUT_BYTES, { continueRead: continuePinnedFileOperation, executable: true }),
        ]);
        if (verification.some((result) => result.status === 'rejected')) {
          verificationAborted = verification.some((result) => result.status === 'rejected' && isPinnedFileOperationAborted(result.reason));
          aliasesValid = false;
        } else {
          const [inputAfter, jobAfter, toolAfter] = verification.map((result) => result.value);
          aliasesValid = inputAfter.digest === job.inputDigest && jobAfter.digest === jobDigest && toolAfter.digest === current.toolDigest;
        }
        if (verificationAborted) { if (volume) await this.#adapter.discardVolume(volume); volume = null; return await finalizePinnedFileAbort(); }
        if (!aliasesValid) { securityEvents.push('PINNED_BYTES_CHANGED'); if (volume) await this.#adapter.discardVolume(volume); volume = null; return await this.#finalize({ base, code: 'SANDBOX_VALIDATION_FAILED', securityEvents, startedAtUnixMs }); }
        if (run.kind !== 'success') {
          if (volume) await this.#adapter.discardVolume(volume);
          volume = null;
          const codes = { cancelled: 'SANDBOX_CANCELLED', failed: 'SANDBOX_VALIDATION_FAILED', 'output-limit': 'SANDBOX_OUTPUT_LIMIT', 'resource-limit': 'SANDBOX_RESOURCE_LIMIT', timeout: 'SANDBOX_TIMEOUT' };
          if (run.kind === 'failed') {
            securityEvents.push('WORKER_FAILED');
            const detailEvent = workerFailureEvent(run.failureClass);
            if (detailEvent) securityEvents.push(detailEvent);
          } else securityEvents.push(`WORKER_${run.kind.toUpperCase().replace('-', '_')}`);
          return await this.#finalize({ base, code: codes[run.kind] ?? 'SANDBOX_UNAVAILABLE', securityEvents, startedAtUnixMs });
        }
      } finally {
        const settled = await Promise.allSettled([
          ...aliases.map((alias) => this.#state.removePinnedAlias(alias.handle)),
          input.handle.close(),
          tool.handle.close(),
          jobSourceHandle.close(),
        ]);
        if (settled.some((result) => result.status === 'rejected')) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      }
      this.#fault('after-worker');
      await this.#state.writeJob({ ...base, stagedBytes: staged.bytes, startedAtUnixMs, state: 'validating' });
      const channelSecret = randomBytes(32);
      const bindingDigest = channelSecret.toString('hex');
      const bindingBytes = Buffer.from(bindingDigest, 'ascii');
      const bindingAliasDigest = sha256(bindingBytes);
      let bindingSourceHandle = null;
      let bindingAlias = null;
      let aliasSettlementFailed = false;
      let output;
      const framePath = this.#state.path('temporary', `frame.${job.jobId}.${randomBytes(12).toString('hex')}`);
      const maximumFrameBytes = current.resourcePolicy.outputBytes + current.resourcePolicy.fanout * (1 + 12 + 32 + 4096) + 53;
      try {
        try {
          bindingSourceHandle = await this.#state.createEphemeralPinnedFile('frame-binding', bindingBytes);
          if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) {
            await this.#adapter.discardVolume(volume); volume = null;
            return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ALIAS_MATERIALIZATION_ABORTED'], startedAtUnixMs });
          }
          bindingAlias = await materializeAlias(bindingSourceHandle, bindingAliasDigest, 1024 * 1024);
          if (!bindingAlias) {
            await this.#adapter.discardVolume(volume); volume = null;
            return await finalizePinnedFileAbort();
          }
          if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) {
            await this.#adapter.discardVolume(volume); volume = null;
            return await this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', securityEvents: ['ALIAS_MATERIALIZATION_ABORTED'], startedAtUnixMs });
          }
          // Retain service ownership until the adapter resolves. The real
          // adapter makes discard idempotent only for this exact previously
          // branded-and-settled volume, so either a pre-settlement exception is
          // cleaned here or a post-settlement exception verifies the tombstone
          // without issuing a second Docker cleanup.
          const collected = await this.#adapter.collectOutput({ runtimeImage: current.runtimeImage, policy: current.resourcePolicy, volume, bindingHandle: bindingAlias.handle, framePath, jobId: job.jobId, maximumFrameBytes });
          volume = null;
          let bindingValid = true;
          let bindingVerificationAborted = false;
          try { bindingValid = (await this.#state.verifyPinnedAlias(bindingAlias.handle, bindingAliasDigest, 1024 * 1024, { continueRead: continuePinnedFileOperation })).digest === bindingAliasDigest; } catch (error) { bindingVerificationAborted = isPinnedFileOperationAborted(error); bindingValid = false; }
          if (bindingVerificationAborted) return await finalizePinnedFileAbort();
          if (!bindingValid) return await this.#finalize({ base, code: 'SANDBOX_VALIDATION_FAILED', securityEvents: ['PINNED_BYTES_CHANGED'], startedAtUnixMs });
          if (collected.kind !== 'success') return await this.#finalize({ base, code: collected.kind === 'output-limit' ? 'SANDBOX_OUTPUT_LIMIT' : 'SANDBOX_VALIDATION_FAILED', securityEvents: ['TRUSTED_OUTPUT_SHIM_REJECTED'], startedAtUnixMs });
        } finally {
          channelSecret.fill(0);
          const settled = await Promise.allSettled([
            bindingAlias ? this.#state.removePinnedAlias(bindingAlias.handle) : Promise.resolve(),
            bindingSourceHandle ? bindingSourceHandle.close() : Promise.resolve(),
          ]);
          if (settled.some((result) => result.status === 'rejected')) { aliasSettlementFailed = true; this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
        }
        outputTemporary = await this.#state.createOutputTemporary(job.jobId);
        try {
          output = await parseOutputFrame({
            bindingDigest,
            framePath,
            maximumBytes: current.resourcePolicy.outputBytes,
            maximumFileBytes: current.outputPolicy.maximumFileBytes,
            maximumRecords: current.resourcePolicy.fanout,
            outputRoot: outputTemporary,
            outputType: current.outputPolicy.allowedTypes[0],
          });
        } catch {
          securityEvents.push('OUTPUT_FRAME_INVALID');
          return await this.#finalize({ base, code: 'SANDBOX_VALIDATION_FAILED', outputTemporary, securityEvents, startedAtUnixMs });
        }
      } finally {
        try { await rm(framePath, { force: true }); } catch (error) { if (!aliasSettlementFailed) throw error; }
      }
      this.#fault('after-validation');
      await this.#state.writeJob({ ...base, stagedBytes: staged.bytes, startedAtUnixMs, state: 'committing' });
      return await this.#state.serial(async () => {
        const finalManifest = await this.#currentManifest(entry);
        if (!finalManifest || !validateJobManifestBinding(job, finalManifest) || await this.#revoked(finalManifest)) {
          securityEvents.push('AUTHORITY_CHANGED_BEFORE_COMMIT');
          return this.#finalize({ base, code: 'SANDBOX_REVOKED', outputTemporary, securityEvents, startedAtUnixMs });
        }
        if (controller.signal.aborted || job.deadlineUnixMs <= this.#now()) return this.#finalize({ base, code: controller.signal.aborted ? 'SANDBOX_CANCELLED' : 'SANDBOX_TIMEOUT', outputTemporary, securityEvents: ['FINALIZATION_ABORTED'], startedAtUnixMs });
        return this.#finalize({ base, code: 'VALIDATED', output, outputTemporary, securityEvents, startedAtUnixMs });
      });
    } catch (error) {
      if (volume) await this.#adapter.discardVolume(volume).catch(() => { this.#poisoned = true; });
      if (outputTemporary) await rm(outputTemporary, { recursive: true, force: true }).catch(() => {});
      await this.#state.removeOutput(base.jobId).catch(() => { this.#poisoned = true; });
      const errorMessage = safeErrorMessage(error);
      if (errorMessage === 'SANDBOX_SETTLEMENT_UNCONFIRMED' || this.#poisoned) { this.#poisoned = true; throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED'); }
      const inspectEvent = safeInspectEvent(errorMessage);
      if (inspectEvent) securityEvents.push(inspectEvent);
      securityEvents.push('REFERENCE_INTERNAL_FAILURE');
      return this.#finalize({ base, code: 'SANDBOX_UNAVAILABLE', securityEvents, startedAtUnixMs });
    }
  }

  async run(jobSource, acquisitionSource) {
    if (this.#closed || this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const nowUnixMs = this.#now();
    const job = snapshotReferenceJobForReplay(jobSource);
    const acquisition = job && snapshotAcquisitionRequest(acquisitionSource, MAXIMUM_INPUT_BYTES);
    if (!job || !acquisition) return safeResult({ jobId: job?.jobId ?? 'invalid', code: 'SANDBOX_PROTOCOL_INVALID' });
    const entry = this.#catalog.get(job.manifestDigest);
    if (!entry || !validateJobManifestBinding(job, entry.manifest)) return safeResult({ jobId: job.jobId, code: 'SANDBOX_PROTOCOL_INVALID' });
    const fingerprint = referenceJobFingerprint(job, acquisition);
    const active = this.#active.get(job.idempotencyKey);
    if (active) return active.fingerprint === fingerprint ? active.promise : safeResult({ jobId: job.jobId, code: 'SANDBOX_PROTOCOL_INVALID' });
    const reservation = await this.#state.serial(async () => {
      const concurrent = this.#active.get(job.idempotencyKey);
      if (concurrent) return concurrent.fingerprint === fingerprint ? Object.freeze({ active: concurrent }) : Object.freeze({ mismatch: true });
      const [idempotency, existingJob] = await Promise.all([this.#state.readIdempotency(job.idempotencyKey), this.#state.readJob(job.jobId)]);
      if (idempotency) {
        if (idempotency.fingerprint !== fingerprint || idempotency.jobId !== job.jobId) return Object.freeze({ mismatch: true });
        const stored = await this.#state.readJob(idempotency.jobId);
        if (TERMINAL_STATES.has(stored?.state)) return Object.freeze({ result: resultFromStored(stored) });
        return Object.freeze({ orphaned: true });
      }
      if (existingJob) {
        if (existingJob.fingerprint !== fingerprint) return Object.freeze({ mismatch: true });
        if (TERMINAL_STATES.has(existingJob.state)) {
          if (!idempotency) await this.#state.writeIdempotency(job.idempotencyKey, { fingerprint, jobId: job.jobId, schemaVersion: 'ogvcs.untrusted-sandbox/idempotency/v1' });
          return Object.freeze({ result: resultFromStored(existingJob) });
        }
      }
      if (!isReferenceJobDeadlineCurrent(job, nowUnixMs)) return Object.freeze({ deadlineInvalid: true });
      if (this.#queueDepth >= MAXIMUM_QUEUE_DEPTH) return Object.freeze({ queueFull: true });
      const base = Object.freeze({
        actorDigest: job.actorDigest,
        fingerprint,
        idempotencyKey: job.idempotencyKey,
        inputDigest: job.inputDigest,
        jobId: job.jobId,
        manifestDigest: job.manifestDigest,
        manifestGeneration: entry.manifest.generation,
        optionsDigest: job.optionsDigest,
        resourcePolicyDigest: job.resourcePolicyDigest,
        runtimeDigest: job.runtimeDigest,
        schemaVersion: 'ogvcs.untrusted-sandbox/job-state/v1',
        toolDigest: job.toolDigest,
      });
      await this.#state.writeJob({ ...base, queuedAtUnixMs: nowUnixMs, state: 'queued' });
      await this.#state.writeIdempotency(job.idempotencyKey, { fingerprint, jobId: job.jobId, schemaVersion: 'ogvcs.untrusted-sandbox/idempotency/v1' });
      const controller = new AbortController();
      let resolvePromise; let rejectPromise;
      const promise = new Promise((resolve, reject) => { resolvePromise = resolve; rejectPromise = reject; });
      const activeReservation = Object.freeze({ controller, fingerprint, job, promise, rejectPromise, resolvePromise });
      this.#active.set(job.idempotencyKey, activeReservation);
      this.#queueDepth += 1;
      return Object.freeze({ active: activeReservation, base, created: true });
    });
    if (reservation.mismatch || reservation.deadlineInvalid) return safeResult({ jobId: job.jobId, code: 'SANDBOX_PROTOCOL_INVALID' });
    if (reservation.result) return reservation.result;
    if (reservation.queueFull || reservation.orphaned) return safeResult({ jobId: job.jobId, code: 'SANDBOX_UNAVAILABLE' });
    if (!reservation.created) return reservation.active.promise;
    const activeReservation = reservation.active;
    const task = this.#queue.then(() => this.#execute({ base: reservation.base, job, acquisition, entry, controller: activeReservation.controller })).finally(() => {
      this.#queueDepth -= 1;
      if (this.#active.get(job.idempotencyKey) === activeReservation) this.#active.delete(job.idempotencyKey);
    });
    this.#queue = task.catch(() => {});
    task.then(activeReservation.resolvePromise, activeReservation.rejectPromise);
    return activeReservation.promise;
  }

  cancel(jobId) {
    if (!isId(jobId)) return false;
    for (const active of this.#active.values()) {
      if (active.job.jobId === jobId) { active.controller.abort(); return true; }
    }
    return false;
  }

  async revoke({ kind, digest, throughGeneration, reasonCode }) {
    if (this.#closed || this.#poisoned) throw new Error('SANDBOX_SETTLEMENT_UNCONFIRMED');
    const nowUnixMs = this.#now();
    const receipt = await this.#state.serial(async () => {
      const prior = await this.#state.readRevocation(kind, digest);
      if (prior && prior.throughGeneration >= throughGeneration) return prior;
      const affectedCompletedJobs = await this.#state.countCompletedForDigest(kind, digest, throughGeneration);
      const record = Object.freeze({ affectedCompletedJobs, digest, kind, reasonCode, revokedAtUnixMs: nowUnixMs, schemaVersion: 'ogvcs.untrusted-sandbox/revocation/v1', throughGeneration });
      await this.#state.writeRevocation(record);
      await this.#state.quarantineCompletedForDigest(kind, digest, throughGeneration, nowUnixMs);
      return record;
    });
    for (const active of this.#active.values()) {
      const manifest = this.#catalog.get(active.job.manifestDigest)?.manifest;
      if ((kind === 'tool' ? active.job.toolDigest : active.job.runtimeDigest) === digest && manifest?.generation <= receipt.throughGeneration) active.controller.abort();
    }
    return Object.freeze({ affectedCompletedJobs: receipt.affectedCompletedJobs, digest, kind, reasonCode: receipt.reasonCode, schemaVersion: 'ogvcs.untrusted-sandbox/revocation-receipt/v1', throughGeneration: receipt.throughGeneration });
  }

  health() {
    return Object.freeze({
      closed: this.#closed,
      poisoned: this.#poisoned,
      queueDepth: this.#queueDepth,
      schemaVersion: 'ogvcs.untrusted-sandbox/health/v1',
      ...this.#metrics,
    });
  }

  async close() {
    if (this.#closed) return;
    for (const active of this.#active.values()) active.controller.abort();
    await this.#queue;
    this.#closed = true;
    this.#evidenceKey.fill(0);
    await this.#state.close();
  }
}

export const isReferenceSandboxService = (value) => services.has(value);
