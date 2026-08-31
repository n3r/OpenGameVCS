import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { CandidateCredentialBroker, CandidateSandboxSupervisor } from '../src/index.mjs';
import { FakeCandidateLauncher, requiredControls } from '../src/testing.mjs';
import { validateSandboxContract } from '../../../../spec/untrusted-sandbox/v1/validate-spec.mjs';

const vectors = JSON.parse(await readFile(new URL('../../../../spec/untrusted-sandbox/v1/vectors/canaries.json', import.meta.url)));
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
  if (scenario === 'stalled-launch') return { launcher: new FakeCandidateLauncher({ start: async () => new Promise(() => {}) }), options: { deadlineMilliseconds: 5 } };
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
