import { createHash } from 'node:crypto';

const DIGEST = /^[0-9a-f]{64}$/u;
const ID = /^[A-Za-z0-9._:-]{1,128}$/u;
const REQUIRED = Object.freeze(['networkDenied', 'credentialFree', 'readOnlyInput', 'isolatedScratch', 'cpuLimited', 'memoryLimited', 'processLimited']);
const code = (jobId, value) => Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-result/v1', jobId, status: value === 'VALIDATED' ? 'validated' : 'denied', code: value, outputDigest: null });
const safeJob = (job) => job && typeof job === 'object' && !Array.isArray(job)
  && Object.keys(job).sort().join(',') === 'idempotencyKey,inputDigest,jobId,outputSchema,purpose,resourceClass,runtimeDigest,schemaVersion,toolDigest'
  && job.schemaVersion === 'ogvcs.untrusted-sandbox/parser-job/v1' && ID.test(job.jobId) && ID.test(job.idempotencyKey)
  && ['toolDigest', 'runtimeDigest', 'inputDigest'].every((name) => DIGEST.test(job[name]))
  && job.resourceClass === 'parser-default' && job.outputSchema === 'ogvcs.untrusted-sandbox/parser-output/v1'
  && typeof job.purpose === 'string' && job.purpose.length > 0 && job.purpose.length <= 128;

export class CredentialBroker {
  #credential; #acquire;
  constructor({ credential, acquire }) { if (typeof credential !== 'string' || !credential || typeof acquire !== 'function') throw new TypeError('broker configuration is invalid'); this.#credential = credential; this.#acquire = acquire; }
  async stage(job) { if (!safeJob(job)) return null; const staged = await this.#acquire({ inputDigest: job.inputDigest, purpose: job.purpose, credential: this.#credential }); if (!staged || staged.inputDigest !== job.inputDigest || !ID.test(staged.handle ?? '')) return null; return Object.freeze({ handle: staged.handle, inputDigest: job.inputDigest }); }
}

export class SandboxSupervisor {
  constructor({ launcher, maxInputBytes = 65_536, maxOutputBytes = 262_144, maxMemoryBytes = 512 * 1024 * 1024, deadlineMilliseconds = 10_000 }) {
    if (!launcher || typeof launcher.start !== 'function' || !Number.isSafeInteger(maxInputBytes) || !Number.isSafeInteger(maxOutputBytes) || !Number.isSafeInteger(maxMemoryBytes) || !Number.isSafeInteger(deadlineMilliseconds) || maxInputBytes < 1 || maxOutputBytes < 1 || maxMemoryBytes < 1 || deadlineMilliseconds < 1) throw new TypeError('sandbox supervisor configuration is invalid');
    this.launcher = launcher; this.maxInputBytes = maxInputBytes; this.maxOutputBytes = maxOutputBytes; this.maxMemoryBytes = maxMemoryBytes; this.deadlineMilliseconds = deadlineMilliseconds;
  }
  async run(job, staged) {
    if (!safeJob(job) || !staged || staged.inputDigest !== job.inputDigest || !ID.test(staged.handle ?? '')) return code(job?.jobId ?? 'invalid', 'SANDBOX_PROTOCOL_INVALID');
    const controls = this.launcher.controls?.() ?? {}; if (REQUIRED.some((name) => controls[name] !== true)) return code(job.jobId, 'SANDBOX_UNAVAILABLE');
    const stdin = Buffer.from(JSON.stringify({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-input/v1', inputHandle: staged.handle, inputDigest: staged.inputDigest }));
    if (stdin.length > this.maxInputBytes) return code(job.jobId, 'SANDBOX_PROTOCOL_INVALID');
    let process;
    try { process = await this.launcher.start(Object.freeze({ job: structuredClone(job), stdin, environment: Object.freeze({}), arguments: Object.freeze([]), limits: Object.freeze({ deadlineMilliseconds: this.deadlineMilliseconds, maxOutputBytes: this.maxOutputBytes, maxMemoryBytes: this.maxMemoryBytes }) })); } catch { return code(job.jobId, 'SANDBOX_UNAVAILABLE'); }
    if (!process || !process.stdout || typeof process.terminate !== 'function') return code(job.jobId, 'SANDBOX_PROTOCOL_INVALID');
    let timeout; const deadline = new Promise((resolve) => { timeout = setTimeout(() => resolve('timeout'), this.deadlineMilliseconds); });
    const output = (async () => { try { const chunks = []; let length = 0; for await (const chunk of process.stdout) { const bytes = Buffer.from(chunk); length += bytes.length; if (length > this.maxOutputBytes) return 'overflow'; chunks.push(bytes); } const text = Buffer.concat(chunks).toString('utf8'); const value = JSON.parse(text); if (!value || Object.keys(value).sort().join(',') !== 'outputs,schemaVersion' || value.schemaVersion !== 'ogvcs.untrusted-sandbox/parser-output/v1' || !Array.isArray(value.outputs) || value.outputs.some((item) => !DIGEST.test(item?.digest ?? '') || typeof item.type !== 'string' || item.type.length > 64 || typeof item.path !== 'string' || item.path.startsWith('/') || item.path.includes('..') || item.path.includes('\\'))) return 'invalid'; return { digest: createHash('sha256').update(Buffer.concat(chunks)).digest('hex') }; } catch { return 'invalid'; } })();
    const result = await Promise.race([output, deadline]); clearTimeout(timeout); if (result === 'timeout') { try { await process.terminate(); } catch {} return code(job.jobId, 'SANDBOX_TIMEOUT'); } if (result === 'overflow') { try { await process.terminate(); } catch {} return code(job.jobId, 'SANDBOX_OUTPUT_LIMIT'); } if (result === 'invalid') return code(job.jobId, 'SANDBOX_VALIDATION_FAILED'); return Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-result/v1', jobId: job.jobId, status: 'validated', code: 'VALIDATED', outputDigest: result.digest });
  }
}
