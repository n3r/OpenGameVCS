import assert from 'node:assert/strict';
import test from 'node:test';
import * as runtime from '../src/index.mjs';
import { CandidateCredentialBroker, CandidateSandboxSupervisor } from '../src/index.mjs';
import { FakeCandidateLauncher, requiredControls } from '../src/testing.mjs';

const job = Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-job/v1', jobId: 'job.1', toolDigest: 'a'.repeat(64), runtimeDigest: 'b'.repeat(64), inputDigest: 'c'.repeat(64), resourceClass: 'parser-default', outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1', idempotencyKey: 'idempotency.1', purpose: 'parse' });
const staged = () => ({ handle: 'opaque.handle.1', inputDigest: job.inputDigest });
const supervisor = (launcher, options = {}) => new CandidateSandboxSupervisor({ candidateLauncher: launcher.capability, ...options });
const output = (path = 'tree/file') => `{"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","outputs":[{"digest":"${'d'.repeat(64)}","type":"tree","path":"${path}"}]}`;

test('broker credential never enters parser environment, argv, stdin, or handle', async () => {
  const canary = 'broker-secret-canary'; const broker = new CandidateCredentialBroker({ credential: canary, acquire: async ({ credential, inputDigest }) => ({ handle: credential === canary ? 'opaque.handle.1' : '', inputDigest }) }); const launcher = new FakeCandidateLauncher();
  const result = await supervisor(launcher).run(job, await broker.stage(job)); const request = launcher.requests[0];
  assert.equal(result.code, 'VALIDATED'); assert.deepEqual(request.environment, {}); assert.deepEqual(request.arguments, []); assert.equal(request.stdin.toString().includes(canary), false); assert.equal(JSON.stringify(request).includes(canary), false);
});
test('stalled broker acquisition is deadline-bounded', async () => {
  const broker = new CandidateCredentialBroker({ credential: 'test-only', deadlineMilliseconds: 5, acquire: async () => new Promise(() => {}) });
  assert.equal(await broker.stage(job), null);
});
test('stalled launcher start is deadline-bounded', async () => {
  const launcher = new FakeCandidateLauncher({ start: async () => new Promise(() => {}) });
  assert.equal((await supervisor(launcher, { deadlineMilliseconds: 5 }).run(job, staged())).code, 'SANDBOX_UNAVAILABLE');
});
test('missing controls and unbranded launchers fail closed', async () => {
  const launcher = new FakeCandidateLauncher({ assertedControls: { ...requiredControls(), networkDenied: false } });
  assert.throws(() => new CandidateSandboxSupervisor({ candidateLauncher: {} }), TypeError);
  assert.equal((await supervisor(launcher).run(job, staged())).code, 'SANDBOX_UNAVAILABLE'); assert.equal(launcher.requests.length, 0);
});
test('candidate runtime exposes no production-named constructor and snapshots controls once', async () => {
  assert.deepEqual(Object.keys(runtime).sort(), ['CandidateCredentialBroker', 'CandidateSandboxSupervisor']);
  let invoked = false; const accessor = { ...requiredControls() }; Object.defineProperty(accessor, 'networkDenied', { enumerable: true, get() { invoked = true; return true; } });
  assert.throws(() => new FakeCandidateLauncher({ assertedControls: accessor }), TypeError); assert.equal(invoked, false);
  assert.throws(() => new FakeCandidateLauncher({ assertedControls: new Proxy(requiredControls(), {}) }), TypeError);
  const mutable = { ...requiredControls() }; const launcher = new FakeCandidateLauncher({ assertedControls: mutable }); mutable.networkDenied = false;
  assert.equal((await supervisor(launcher).run(job, staged())).code, 'VALIDATED');
});
test('getter, proxy, and later mutation cannot alter a snapped job or staged grant', async () => {
  let invoked = false; const getter = { ...job }; Object.defineProperty(getter, 'jobId', { enumerable: true, get() { invoked = true; return job.jobId; } });
  const launcher = new FakeCandidateLauncher(); assert.equal((await supervisor(launcher).run(getter, staged())).code, 'SANDBOX_PROTOCOL_INVALID'); assert.equal(invoked, false);
  assert.equal((await supervisor(launcher).run(new Proxy({ ...job }, {}), staged())).code, 'SANDBOX_PROTOCOL_INVALID');
  let stagedGetter = false; const accessorStaged = { ...staged() }; Object.defineProperty(accessorStaged, 'handle', { enumerable: true, get() { stagedGetter = true; return 'opaque.handle.1'; } });
  assert.equal((await supervisor(launcher).run(job, accessorStaged)).code, 'SANDBOX_PROTOCOL_INVALID'); assert.equal(stagedGetter, false);
  assert.equal((await supervisor(launcher).run(job, new Proxy(staged(), {}))).code, 'SANDBOX_PROTOCOL_INVALID');
  const mutable = { ...job }; const pending = supervisor(launcher).run(mutable, staged()); mutable.jobId = 'changed'; const accepted = await pending;
  assert.equal(accepted.jobId, job.jobId); assert.equal(accepted.code, 'VALIDATED');
});
test('bounded shutdown attempts TERM then KILL and never waits forever', async () => {
  const forever = new Promise(() => {}); const launcher = new FakeCandidateLauncher({ stdout: (async function* () { await forever; }()), exit: forever, terminate: async () => forever, kill: async () => forever });
  const result = await supervisor(launcher, { deadlineMilliseconds: 5, terminationGraceMilliseconds: 2 }).run(job, staged());
  assert.equal(result.code, 'SANDBOX_TIMEOUT'); assert.equal(launcher.terminated, 1); assert.equal(launcher.killed, 1);
});
test('nonzero or signalled exit and stderr are never accepted', async () => {
  const nonzero = new FakeCandidateLauncher({ stdout: [output()], exit: Promise.resolve({ code: 1, signal: null }) });
  const signalled = new FakeCandidateLauncher({ stdout: [output()], exit: Promise.resolve({ code: 0, signal: 'SIGKILL' }) });
  const stderr = new FakeCandidateLauncher({ stdout: [output()], stderr: ['parser secret /private/x'] });
  assert.equal((await supervisor(nonzero).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
  assert.equal((await supervisor(signalled).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
  assert.equal((await supervisor(stderr).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
});
test('only canonical closed JSON and OGVCS-004 portable output paths are accepted', async () => {
  const invalid = [
    '{"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","outputs":[]}',
    '{"outputs":[],"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1"}',
    output('../secret'), output('C:/host'), output('//server/share'),
    `{"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","outputs":[{"digest":"${'d'.repeat(64)}","type":"tree","path":"tree/file","extra":true}]}`,
  ];
  for (const stdout of invalid) assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [stdout] })).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
  assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [output()] })).run(job, staged())).code, 'VALIDATED');
});
