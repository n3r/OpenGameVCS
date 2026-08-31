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
  return job.schemaVersion === 'ogvcs.untrusted-sandbox/parser-job/v1' && ID.test(job.jobId) && ID.test(job.idempotencyKey)
    && ['toolDigest', 'runtimeDigest', 'inputDigest'].every((key) => typeof job[key] === 'string' && DIGEST.test(job[key]))
    && job.resourceClass === 'parser-default' && job.outputSchema === 'ogvcs.untrusted-sandbox/parser-output/v1'
    && typeof job.purpose === 'string' && job.purpose.length > 0 && job.purpose.length <= 128 ? job : null;
};
const snapshotStaged = (source, inputDigest) => {
  const data = exact(source, STAGED_KEYS); if (!data) return null;
  const staged = Object.freeze({ handle: data.handle.value, inputDigest: data.inputDigest.value });
  return typeof staged.handle === 'string' && ID.test(staged.handle) && staged.inputDigest === inputDigest ? staged : null;
};
const within = async (operation, milliseconds) => {
  const controller = new AbortController(); let timer;
  const deadline = new Promise((resolve) => { timer = setTimeout(() => { controller.abort(); resolve(Object.freeze({ timedOut: true })); }, milliseconds); });
  try { return await Promise.race([Promise.resolve().then(() => operation(controller.signal)).then((value) => Object.freeze({ value }), () => Object.freeze({ failed: true })), deadline]); }
  finally { clearTimeout(timer); }
};
const never = () => new Promise(() => {});
const portablePath = (path) => {
  if (typeof path !== 'string') return false;
  try { return validateRepositoryPath(path, { profile: 'path.opengamevcs/portable@1' }).canonical === path; } catch { return false; }
};
const parseOutput = (bytes) => {
  try {
    const text = bytes.toString('utf8'); if (!Buffer.from(text, 'utf8').equals(bytes)) return null;
    const value = JSON.parse(text); const data = exact(value, OUTPUT_KEYS); if (!data || data.schemaVersion.value !== 'ogvcs.untrusted-sandbox/parser-output/v1' || !Array.isArray(data.outputs.value)) return null;
    const outputs = [];
    for (const item of data.outputs.value) {
      const fields = exact(item, OUTPUT_ITEM_KEYS); if (!fields) return null;
      const copy = { digest: fields.digest.value, type: fields.type.value, path: fields.path.value };
      if (typeof copy.digest !== 'string' || !DIGEST.test(copy.digest) || typeof copy.type !== 'string' || copy.type.length < 1 || copy.type.length > 64 || !portablePath(copy.path)) return null;
      outputs.push(Object.freeze(copy));
    }
    const canonical = Buffer.from(JSON.stringify({ schemaVersion: value.schemaVersion, outputs }), 'utf8');
    return canonical.equals(bytes) ? Object.freeze(outputs) : null;
  } catch { return null; }
};
const drain = async (stream, maximum) => {
  try { const chunks = []; let length = 0; for await (const chunk of stream) { const bytes = Buffer.from(chunk); length += bytes.length; if (length > maximum) return Object.freeze({ kind: 'overflow' }); chunks.push(bytes); } return Object.freeze({ kind: 'bytes', bytes: Buffer.concat(chunks) }); } catch { return Object.freeze({ kind: 'invalid' }); }
};
const snapshotExit = (source) => {
  const data = exact(source, Object.freeze(['code', 'signal']));
  return data && data.code.value === 0 && data.signal.value === null;
};
const snapshotProcess = (source) => {
  const data = exact(source, Object.freeze(['exit', 'kill', 'stderr', 'stdout', 'terminate'])); if (!data) return null;
  const process = Object.freeze(Object.fromEntries(Object.keys(data).map((key) => [key, data[key].value])));
  return typeof process.terminate === 'function' && typeof process.kill === 'function' && process.stdout?.[Symbol.asyncIterator] && process.stderr?.[Symbol.asyncIterator] && process.exit && typeof process.exit.then === 'function' ? process : null;
};
const stop = async (process, graceMilliseconds) => {
  const settled = Promise.resolve(process.exit).then(() => true, () => false);
  await within((signal) => process.terminate(signal), graceMilliseconds);
  if ((await within(() => settled, graceMilliseconds)).value === true) return;
  await within((signal) => process.kill(signal), graceMilliseconds);
  await within(() => settled, graceMilliseconds);
};

/** Candidate-only test broker. It is not a production credential authority. */
export class CandidateCredentialBroker {
  #credential; #acquire; #deadlineMilliseconds;
  constructor({ credential, acquire, deadlineMilliseconds = 1_000 }) {
    if (typeof credential !== 'string' || credential.length === 0 || typeof acquire !== 'function' || !Number.isSafeInteger(deadlineMilliseconds) || deadlineMilliseconds < 1) throw new TypeError('candidate broker configuration is invalid');
    this.#credential = credential; this.#acquire = acquire; this.#deadlineMilliseconds = deadlineMilliseconds;
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
  constructor({ candidateLauncher, maxInputBytes = 65_536, maxOutputBytes = 262_144, maxMemoryBytes = 512 * 1024 * 1024, deadlineMilliseconds = 10_000, terminationGraceMilliseconds = 250 }) {
    if (!candidateLauncher || !candidateLauncherParts(candidateLauncher) || ![maxInputBytes, maxOutputBytes, maxMemoryBytes, deadlineMilliseconds, terminationGraceMilliseconds].every((value) => Number.isSafeInteger(value) && value > 0)) throw new TypeError('candidate supervisor configuration is invalid');
    this.parts = candidateLauncherParts(candidateLauncher); this.maxInputBytes = maxInputBytes; this.maxOutputBytes = maxOutputBytes; this.maxMemoryBytes = maxMemoryBytes; this.deadlineMilliseconds = deadlineMilliseconds; this.terminationGraceMilliseconds = terminationGraceMilliseconds;
  }
  async run(jobSource, stagedSource) {
    const job = snapshotJob(jobSource); const staged = job && snapshotStaged(stagedSource, job.inputDigest);
    if (!job || !staged) return result(job?.jobId ?? 'invalid', 'SANDBOX_PROTOCOL_INVALID');
    if (Object.values(this.parts.assertedControls).some((value) => value !== true)) return result(job.jobId, 'SANDBOX_UNAVAILABLE');
    const stdin = Buffer.from(JSON.stringify({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-input/v1', inputHandle: staged.handle, inputDigest: staged.inputDigest }), 'utf8');
    if (stdin.length > this.maxInputBytes) return result(job.jobId, 'SANDBOX_PROTOCOL_INVALID');
    const request = Object.freeze({ job, stdin, environment: Object.freeze({}), arguments: Object.freeze([]), limits: Object.freeze({ deadlineMilliseconds: this.deadlineMilliseconds, maxOutputBytes: this.maxOutputBytes, maxMemoryBytes: this.maxMemoryBytes }) });
    const launch = await within((signal) => this.parts.launch(request, signal), this.deadlineMilliseconds);
    if (launch.timedOut || launch.failed) return result(job.jobId, 'SANDBOX_UNAVAILABLE');
    const process = snapshotProcess(launch.value); if (!process) return result(job.jobId, 'SANDBOX_PROTOCOL_INVALID');
    const stdout = drain(process.stdout, this.maxOutputBytes); const stderr = drain(process.stderr, this.maxOutputBytes);
    const completed = Promise.all([stdout, stderr, Promise.resolve(process.exit).then((exit) => Object.freeze({ kind: snapshotExit(exit) ? 'success' : 'failed' }), () => Object.freeze({ kind: 'failed' }))]).then(([out, err, exit]) => Object.freeze({ out, err, exit }));
    const observed = Promise.race([completed, stdout.then((value) => value.kind === 'overflow' ? Object.freeze({ out: value }) : never()), stderr.then((value) => value.kind === 'overflow' || (value.kind === 'bytes' && value.bytes.length > 0) ? Object.freeze({ err: value }) : never())]);
    const outcome = await within(() => observed, this.deadlineMilliseconds);
    if (outcome.timedOut) { await stop(process, this.terminationGraceMilliseconds); return result(job.jobId, 'SANDBOX_TIMEOUT'); }
    const observedValue = outcome.value;
    if (observedValue?.out?.kind === 'overflow' || observedValue?.err?.kind === 'overflow') { await stop(process, this.terminationGraceMilliseconds); return result(job.jobId, 'SANDBOX_OUTPUT_LIMIT'); }
    if (observedValue?.err?.kind === 'bytes' && observedValue.err.bytes.length > 0) { await stop(process, this.terminationGraceMilliseconds); return result(job.jobId, 'SANDBOX_VALIDATION_FAILED'); }
    if (!observedValue || observedValue.out?.kind !== 'bytes' || observedValue.err?.kind !== 'bytes' || observedValue.exit?.kind !== 'success') { await stop(process, this.terminationGraceMilliseconds); return result(job.jobId, 'SANDBOX_VALIDATION_FAILED'); }
    const output = parseOutput(observedValue.out.bytes); if (!output) return result(job.jobId, 'SANDBOX_VALIDATION_FAILED');
    return Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-result/v1', jobId: job.jobId, status: 'validated', code: 'VALIDATED', outputDigest: createHash('sha256').update(observedValue.out.bytes).digest('hex') });
  }
}
