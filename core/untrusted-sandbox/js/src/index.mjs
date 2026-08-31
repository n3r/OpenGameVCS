import { createHash } from 'node:crypto';
import { types } from 'node:util';
import { validateRepositoryPath } from '@opengamevcs/path-filesystem';
import { candidateLauncherParts } from './internal/capability.mjs';

const DIGEST = /^[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9._:-]{1,128}$/u;
const JOB_KEYS = Object.freeze(['idempotencyKey', 'inputDigest', 'jobId', 'outputSchema', 'purpose', 'resourceClass', 'runtimeDigest', 'schemaVersion', 'toolDigest']);
const STAGED_KEYS = Object.freeze(['handle', 'inputDigest']);
const OUTPUT_KEYS = Object.freeze(['outputs', 'schemaVersion']);
const OUTPUT_ITEM_KEYS = Object.freeze(['digest', 'path', 'type']);
const PROCESS_KEYS = Object.freeze(['exit', 'kill', 'stderr', 'stdout', 'terminate']);
const EXIT_KEYS = Object.freeze(['code', 'signal']);

const canonicalJson = (value) => value === null || typeof value !== 'object'
  ? JSON.stringify(value)
  : Array.isArray(value)
    ? `[${value.map(canonicalJson).join(',')}]`
    : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
const result = (jobId, code) => Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-result/v1', jobId, status: code === 'VALIDATED' ? 'validated' : 'denied', code, outputDigest: null });
const exact = (source, keys) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Object.keys(descriptors).sort().join(',') !== keys.join(',')) return null;
    if (Object.values(descriptors).some((descriptor) => !Object.hasOwn(descriptor, 'value') || Object.hasOwn(descriptor, 'get') || Object.hasOwn(descriptor, 'set'))) return null;
    return descriptors;
  } catch { return null; }
};
const snapshotJob = (source) => {
  const data = exact(source, JOB_KEYS); if (!data) return null;
  const job = Object.freeze(Object.fromEntries(JOB_KEYS.map((key) => [key, data[key].value])));
  return job.schemaVersion === 'ogvcs.untrusted-sandbox/parser-job/v1'
    && typeof job.jobId === 'string' && ID.test(job.jobId)
    && typeof job.idempotencyKey === 'string' && ID.test(job.idempotencyKey)
    && ['toolDigest', 'runtimeDigest', 'inputDigest'].every((key) => typeof job[key] === 'string' && DIGEST.test(job[key]))
    && job.resourceClass === 'parser-default' && job.outputSchema === 'ogvcs.untrusted-sandbox/parser-output/v1'
    && typeof job.purpose === 'string' && [...job.purpose].length > 0 && [...job.purpose].length <= 128 ? job : null;
};
const snapshotStaged = (source, inputDigest) => {
  const data = exact(source, STAGED_KEYS); if (!data) return null;
  const staged = Object.freeze({ handle: data.handle.value, inputDigest: data.inputDigest.value });
  return typeof staged.handle === 'string' && ID.test(staged.handle) && staged.inputDigest === inputDigest ? staged : null;
};
const within = async (operation, milliseconds) => {
  const controller = new AbortController(); let timer;
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => {
      resolve(Object.freeze({ timedOut: true }));
      setImmediate(() => { try { controller.abort(); } catch {} });
    }, milliseconds);
  });
  try {
    return await Promise.race([
      Promise.resolve().then(() => operation(controller.signal)).then((value) => Object.freeze({ value }), () => Object.freeze({ failed: true })),
      deadline,
    ]);
  } finally { clearTimeout(timer); }
};
const never = () => new Promise(() => {});
const portablePath = (path) => {
  if (typeof path !== 'string') return false;
  try { return validateRepositoryPath(path, { profile: 'path.opengamevcs/portable@1' }).canonical === path; } catch { return false; }
};
const parseOutput = (bytes, maximumRecords) => {
  try {
    const text = bytes.toString('utf8'); if (!Buffer.from(text, 'utf8').equals(bytes)) return null;
    const value = JSON.parse(text); const data = exact(value, OUTPUT_KEYS);
    if (!data || data.schemaVersion.value !== 'ogvcs.untrusted-sandbox/parser-output/v1' || !Array.isArray(data.outputs.value) || data.outputs.value.length > maximumRecords) return null;
    const outputs = [];
    for (const item of data.outputs.value) {
      const fields = exact(item, OUTPUT_ITEM_KEYS); if (!fields) return null;
      const copy = Object.freeze({ digest: fields.digest.value, path: fields.path.value, type: fields.type.value });
      if (typeof copy.digest !== 'string' || !DIGEST.test(copy.digest) || typeof copy.type !== 'string' || [...copy.type].length < 1 || [...copy.type].length > 64 || !portablePath(copy.path)) return null;
      outputs.push(copy);
    }
    const canonical = Buffer.from(canonicalJson({ outputs, schemaVersion: data.schemaVersion.value }), 'utf8');
    return canonical.equals(bytes) ? Object.freeze(outputs) : null;
  } catch { return null; }
};
const dataMethod = (source, key) => {
  if ((typeof source !== 'object' && typeof source !== 'function') || source === null || types.isProxy(source)) return null;
  try {
    let owner = source;
    for (let depth = 0; owner !== null && depth < 64; depth += 1) {
      if (types.isProxy(owner)) return null;
      const descriptor = Object.getOwnPropertyDescriptor(owner, key);
      if (descriptor) return Object.hasOwn(descriptor, 'value') && typeof descriptor.value === 'function' && !types.isProxy(descriptor.value) ? descriptor.value : null;
      owner = Object.getPrototypeOf(owner);
    }
  } catch {}
  return null;
};
const snapshotIterator = (source) => {
  const iterate = dataMethod(source, Symbol.asyncIterator); if (!iterate) return null;
  try {
    const receiver = Reflect.apply(iterate, source, []);
    if ((typeof receiver !== 'object' && typeof receiver !== 'function') || receiver === null || types.isProxy(receiver)) return null;
    const next = dataMethod(receiver, 'next');
    return next ? Object.freeze({ next, receiver }) : null;
  } catch { return null; }
};
const copyChunk = (source) => {
  try {
    if (source === null || typeof source !== 'object' || types.isProxy(source) || !Buffer.isBuffer(source) || Object.getPrototypeOf(source) !== Buffer.prototype) return null;
    return Buffer.from(source);
  } catch { return null; }
};
const drain = async (iterator, maximum, discardNonempty = false) => {
  try {
    const chunks = []; let length = 0;
    while (true) {
      const pending = Reflect.apply(iterator.next, iterator.receiver, []); if (!types.isPromise(pending) || types.isProxy(pending)) return Object.freeze({ kind: 'invalid' });
      const step = exact(await pending, Object.freeze(['done', 'value'])); if (!step || typeof step.done.value !== 'boolean') return Object.freeze({ kind: 'invalid' });
      if (step.done.value) return Object.freeze({ kind: 'bytes', bytes: discardNonempty ? Buffer.alloc(0) : Buffer.concat(chunks) });
      const bytes = copyChunk(step.value.value); if (!bytes) return Object.freeze({ kind: 'invalid' });
      if (bytes.length > maximum - length) return Object.freeze({ kind: 'overflow' });
      length += bytes.length;
      if (discardNonempty && bytes.length > 0) return Object.freeze({ kind: 'nonempty' });
      if (!discardNonempty) chunks.push(bytes);
    }
  } catch { return Object.freeze({ kind: 'invalid' }); }
};
const snapshotExit = (source) => {
  const data = exact(source, EXIT_KEYS);
  return data && data.code.value === 0 && data.signal.value === null;
};
const snapshotProcess = (source) => {
  const data = exact(source, PROCESS_KEYS); if (!data) return null;
  const terminate = data.terminate.value; const kill = data.kill.value; const exit = data.exit.value;
  if (typeof terminate !== 'function' || types.isProxy(terminate) || typeof kill !== 'function' || types.isProxy(kill) || !types.isPromise(exit) || types.isProxy(exit)) return null;
  const stdout = snapshotIterator(data.stdout.value); const stderr = snapshotIterator(data.stderr.value);
  return stdout && stderr ? Object.freeze({ exit, kill, stderr, stdout, terminate }) : null;
};
const observe = async (process, maximum) => {
  const stdout = drain(process.stdout, maximum); const stderr = drain(process.stderr, maximum, true);
  const exit = process.exit.then((value) => Object.freeze({ kind: snapshotExit(value) ? 'success' : 'failed' }), () => Object.freeze({ kind: 'failed' }));
  const completed = Promise.all([stdout, stderr, exit]).then(([out, err, ended]) => Object.freeze({ out, err, exit: ended }));
  return Promise.race([
    completed,
    stdout.then((value) => value.kind === 'bytes' ? never() : Object.freeze({ out: value })),
    stderr.then((value) => value.kind === 'bytes' ? never() : Object.freeze({ err: value })),
    exit.then((value) => value.kind === 'success' ? never() : Object.freeze({ exit: value })),
  ]);
};
const stop = async (process, graceMilliseconds) => {
  const settled = process.exit.then(() => true, () => false);
  await within((signal) => Reflect.apply(process.terminate, undefined, [signal]), graceMilliseconds);
  if ((await within(() => settled, graceMilliseconds)).value === true) return true;
  await within((signal) => Reflect.apply(process.kill, undefined, [signal]), graceMilliseconds);
  return (await within(() => settled, graceMilliseconds)).value === true;
};
class CandidateContainmentError extends Error {
  constructor() { super('candidate launcher could not prove process settlement'); this.name = 'CandidateContainmentError'; this.code = 'SANDBOX_SETTLEMENT_UNCONFIRMED'; this.stack = `${this.name}: ${this.message}`; Object.freeze(this); }
}

/** Candidate-only test broker. It is not a production credential authority. */
export class CandidateCredentialBroker {
  #credential; #acquire; #deadlineMilliseconds;
  constructor({ credential, acquire, deadlineMilliseconds = 1_000 }) {
    if (typeof credential !== 'string' || credential.length === 0 || typeof acquire !== 'function' || types.isProxy(acquire) || !Number.isSafeInteger(deadlineMilliseconds) || deadlineMilliseconds < 1 || deadlineMilliseconds > 60_000) throw new TypeError('candidate broker configuration is invalid');
    this.#credential = credential; this.#acquire = acquire; this.#deadlineMilliseconds = deadlineMilliseconds; Object.freeze(this);
  }
  async stage(jobSource) {
    const job = snapshotJob(jobSource); if (!job) return null;
    const request = Object.freeze({ inputDigest: job.inputDigest, purpose: job.purpose, credential: this.#credential });
    const outcome = await within((signal) => this.#acquire(request, signal), this.#deadlineMilliseconds);
    if (outcome.timedOut || outcome.failed) return null;
    return snapshotStaged(outcome.value, job.inputDigest);
  }
}

/** Candidate-only supervisor. A real OS-enforcing launcher is intentionally absent. */
export class CandidateSandboxSupervisor {
  #parts; #maxInputBytes; #maxOutputBytes; #maxOutputRecords; #maxMemoryBytes; #deadlineMilliseconds; #terminationGraceMilliseconds; #poisoned = false;
  constructor({ candidateLauncher, maxInputBytes = 65_536, maxOutputBytes = 262_144, maxOutputRecords = 10_000, maxMemoryBytes = 512 * 1024 * 1024, deadlineMilliseconds = 10_000, terminationGraceMilliseconds = 250 }) {
    const parts = candidateLauncherParts(candidateLauncher);
    if (!parts || ![maxInputBytes, maxOutputBytes, maxOutputRecords, maxMemoryBytes, deadlineMilliseconds, terminationGraceMilliseconds].every((value) => Number.isSafeInteger(value) && value > 0) || maxInputBytes > 256 * 1024 * 1024 || maxOutputRecords > 10_000 || maxOutputBytes > 256 * 1024 * 1024 || maxMemoryBytes > 512 * 1024 * 1024 || deadlineMilliseconds > 60_000 || terminationGraceMilliseconds > 60_000) throw new TypeError('candidate supervisor configuration is invalid');
    this.#parts = parts; this.#maxInputBytes = maxInputBytes; this.#maxOutputBytes = maxOutputBytes; this.#maxOutputRecords = maxOutputRecords; this.#maxMemoryBytes = maxMemoryBytes; this.#deadlineMilliseconds = deadlineMilliseconds; this.#terminationGraceMilliseconds = terminationGraceMilliseconds; Object.freeze(this);
  }
  async #denyAfterStop(process, jobId, code) {
    if (await stop(process, this.#terminationGraceMilliseconds)) return result(jobId, code);
    this.#poisoned = true; throw new CandidateContainmentError();
  }
  async run(jobSource, stagedSource) {
    if (this.#poisoned) throw new CandidateContainmentError();
    const job = snapshotJob(jobSource); const staged = job && snapshotStaged(stagedSource, job.inputDigest);
    if (!job || !staged) return result(job?.jobId ?? 'invalid', 'SANDBOX_PROTOCOL_INVALID');
    if (Object.values(this.#parts.assertedControls).some((value) => value !== true)) return result(job.jobId, 'SANDBOX_UNAVAILABLE');
    const stdin = Buffer.from(canonicalJson({ inputDigest: staged.inputDigest, inputHandle: staged.handle, schemaVersion: 'ogvcs.untrusted-sandbox/parser-input/v1' }), 'utf8');
    if (stdin.length > this.#maxInputBytes) return result(job.jobId, 'SANDBOX_PROTOCOL_INVALID');
    const request = Object.freeze({ job, stdin, environment: Object.freeze({}), arguments: Object.freeze([]), limits: Object.freeze({ deadlineMilliseconds: this.#deadlineMilliseconds, maxMemoryBytes: this.#maxMemoryBytes, maxOutputBytes: this.#maxOutputBytes, maxOutputRecords: this.#maxOutputRecords }) });
    const launch = await within((signal) => this.#parts.launch(request, signal), this.#deadlineMilliseconds);
    if (launch.timedOut || launch.failed) return result(job.jobId, 'SANDBOX_UNAVAILABLE');
    const processOutcome = await within(() => snapshotProcess(launch.value), this.#deadlineMilliseconds);
    const process = processOutcome.value;
    if (processOutcome.timedOut || processOutcome.failed || !process) { this.#poisoned = true; throw new CandidateContainmentError(); }
    const outcome = await within(() => observe(process, this.#maxOutputBytes), this.#deadlineMilliseconds);
    if (outcome.timedOut) return this.#denyAfterStop(process, job.jobId, 'SANDBOX_TIMEOUT');
    const observed = outcome.value;
    if (observed?.out?.kind === 'overflow' || observed?.err?.kind === 'overflow') return this.#denyAfterStop(process, job.jobId, 'SANDBOX_OUTPUT_LIMIT');
    if (observed?.err?.kind === 'nonempty') return this.#denyAfterStop(process, job.jobId, 'SANDBOX_VALIDATION_FAILED');
    if (outcome.failed || !observed || observed.out?.kind !== 'bytes' || observed.err?.kind !== 'bytes' || observed.exit?.kind !== 'success') return this.#denyAfterStop(process, job.jobId, 'SANDBOX_VALIDATION_FAILED');
    const output = parseOutput(observed.out.bytes, this.#maxOutputRecords); if (!output) return result(job.jobId, 'SANDBOX_VALIDATION_FAILED');
    return Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-result/v1', jobId: job.jobId, status: 'validated', code: 'VALIDATED', outputDigest: createHash('sha256').update(observed.out.bytes).digest('hex') });
  }
}
