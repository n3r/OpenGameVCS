import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { CandidateCredentialBroker, CandidateSandboxSupervisor } from '../src/index.mjs';
import { FakeCandidateLauncher, requiredControls } from '../src/testing.mjs';
import { validateSandboxContract } from '../../../../spec/untrusted-sandbox/v1/validate-spec.mjs';

const vectors = JSON.parse(await readFile(new URL('../../../../spec/untrusted-sandbox/v1/vectors/canaries.json', import.meta.url)));
const jobSchema = JSON.parse(await readFile(new URL('../../../../spec/untrusted-sandbox/v1/schemas/ParserJob.schema.json', import.meta.url)));
const outputSchema = JSON.parse(await readFile(new URL('../../../../spec/untrusted-sandbox/v1/schemas/ParserOutput.schema.json', import.meta.url)));
const resultSchema = JSON.parse(await readFile(new URL('../../../../spec/untrusted-sandbox/v1/schemas/ParserResult.schema.json', import.meta.url)));
const job = Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-job/v1', jobId: 'vector.1', toolDigest: 'a'.repeat(64), runtimeDigest: 'b'.repeat(64), inputDigest: 'c'.repeat(64), resourceClass: 'parser-default', outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1', idempotencyKey: 'vector.1', purpose: 'parse' });
const staged = Object.freeze({ handle: 'opaque.handle.1', inputDigest: job.inputDigest });
const valid = `{"outputs":[{"digest":"${'d'.repeat(64)}","path":"tree/file","type":"tree"}],"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1"}`;

const setupFor = async (scenario) => {
  if (scenario === 'missing-control') return { launcher: new FakeCandidateLauncher({ assertedControls: { ...requiredControls(), networkDenied: false } }) };
  if (scenario === 'stdout-flood') return { launcher: new FakeCandidateLauncher({ stdout: ['x'.repeat(32)] }), options: { maxOutputBytes: 8 }, verify: (launcher) => assert.equal(launcher.terminated, 1) };
  if (scenario === 'traversal') return { launcher: new FakeCandidateLauncher({ stdout: [valid.replace('tree/file', '../secret')] }) };
  if (scenario === 'drive-path') return { launcher: new FakeCandidateLauncher({ stdout: [valid.replace('tree/file', 'C:/host')] }) };
  if (scenario === 'unc-path') return { launcher: new FakeCandidateLauncher({ stdout: [valid.replace('tree/file', '//server/share')] }) };
  if (scenario === 'duplicate-json') return { launcher: new FakeCandidateLauncher({ stdout: ['{"outputs":[],"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1"}'] }) };
  if (scenario === 'extra-output-field') return { launcher: new FakeCandidateLauncher({ stdout: [valid.replace('"path":"tree/file"', '"extra":true,"path":"tree/file"')] }) };
  if (scenario === 'nonzero-exit') return { launcher: new FakeCandidateLauncher({ stdout: [valid], exit: Promise.resolve({ code: 1, signal: null }) }) };
  if (scenario === 'stderr-secret') return { launcher: new FakeCandidateLauncher({ stdout: [valid], stderr: ['test-only-secret-canary'] }) };
  if (scenario === 'stalled-launch') {
    let settled = false;
    return {
      launcher: new FakeCandidateLauncher({ start: async (_request, signal) => new Promise((_resolve, reject) => signal.addEventListener('abort', () => setTimeout(() => { settled = true; reject(new Error('safe vector settlement')); }, 2), { once: true })) }),
      options: { deadlineMilliseconds: 5, terminationGraceMilliseconds: 50 },
      verify: () => assert.equal(settled, true),
    };
  }
  if (scenario === 'stalled-read') {
    const forever = new Promise(() => {}); let settle;
    const exit = new Promise((resolve) => { settle = resolve; });
    return { launcher: new FakeCandidateLauncher({ stdout: (async function* () { await forever; }()), exit, kill: async () => { settle({ code: null, signal: 'SIGKILL' }); } }), options: { deadlineMilliseconds: 5, terminationGraceMilliseconds: 2 }, verify: (launcher) => { assert.equal(launcher.terminated, 1); assert.equal(launcher.killed, 1); } };
  }
  if (scenario === 'credential-canary') {
    const canary = 'vector-broker-secret-canary'; let acquired = false; const launcher = new FakeCandidateLauncher({ stdout: [valid] });
    const broker = new CandidateCredentialBroker({ credential: canary, acquire: async ({ credential, inputDigest }) => { acquired = credential === canary; return { handle: 'opaque.handle.1', inputDigest }; } });
    return { launcher, staged: await broker.stage(job), verify: () => { assert.equal(acquired, true); assert.equal(JSON.stringify(launcher.requests[0]).includes(canary), false); } };
  }
  throw new Error(`unknown vector scenario: ${scenario}`);
};

test('authenticated canary inventory dispatches and proves every expected outcome', async () => {
  await validateSandboxContract();
  for (const vector of vectors.cases) {
    const setup = await setupFor(vector.scenario);
    const value = await new CandidateSandboxSupervisor({ candidateLauncher: setup.launcher.capability, ...setup.options }).run(job, setup.staged ?? staged);
    assert.equal(value.code, vector.expectedCode, vector.id); setup.verify?.(setup.launcher);
  }
});

test('runtime required records and result combinations stay aligned with the authenticated schemas', async () => {
  assert.deepEqual(Object.keys(job).sort(), [...jobSchema.required].sort());
  assert.deepEqual(Object.keys(JSON.parse(valid)).sort(), [...outputSchema.required].sort());
  assert.deepEqual(Object.keys(JSON.parse(valid).outputs[0]).sort(), [...outputSchema.properties.outputs.items.required].sort());
  for (const key of jobSchema.required) {
    const candidate = { ...job }; delete candidate[key];
    assert.equal((await new CandidateSandboxSupervisor({ candidateLauncher: new FakeCandidateLauncher().capability }).run(candidate, staged)).code, 'SANDBOX_PROTOCOL_INVALID', key);
  }
  for (const key of outputSchema.properties.outputs.items.required) {
    const candidate = { digest: 'd'.repeat(64), path: 'tree/file', type: 'tree' }; delete candidate[key];
    const stdout = JSON.stringify({ outputs: [candidate], schemaVersion: outputSchema.properties.schemaVersion.const });
    assert.equal((await new CandidateSandboxSupervisor({ candidateLauncher: new FakeCandidateLauncher({ stdout: [stdout] }).capability }).run(job, staged)).code, 'SANDBOX_VALIDATION_FAILED', key);
  }
  const accepted = await new CandidateSandboxSupervisor({ candidateLauncher: new FakeCandidateLauncher({ stdout: [valid] }).capability }).run(job, staged);
  const denied = await new CandidateSandboxSupervisor({ candidateLauncher: new FakeCandidateLauncher({ assertedControls: { ...requiredControls(), networkDenied: false } }).capability }).run(job, staged);
  for (const value of [accepted, denied]) assert.deepEqual(Object.keys(value).sort(), [...resultSchema.required].sort());
  assert.deepEqual({ status: accepted.status, code: accepted.code, digest: typeof accepted.outputDigest }, { status: 'validated', code: 'VALIDATED', digest: 'string' });
  assert.deepEqual({ status: denied.status, code: denied.code, digest: denied.outputDigest }, { status: 'denied', code: 'SANDBOX_UNAVAILABLE', digest: null });
});
