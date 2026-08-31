import assert from 'node:assert/strict';
import test from 'node:test';
import * as runtime from '../src/index.mjs';
import { CandidateCredentialBroker, CandidateSandboxSupervisor } from '../src/index.mjs';
import { FakeCandidateLauncher, requiredControls } from '../src/testing.mjs';

const job = Object.freeze({ schemaVersion: 'ogvcs.untrusted-sandbox/parser-job/v1', jobId: 'job.1', toolDigest: 'a'.repeat(64), runtimeDigest: 'b'.repeat(64), inputDigest: 'c'.repeat(64), resourceClass: 'parser-default', outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1', idempotencyKey: 'idempotency.1', purpose: 'parse' });
const staged = () => ({ handle: 'opaque.handle.1', inputDigest: job.inputDigest });
const supervisor = (launcher, options = {}) => new CandidateSandboxSupervisor({ candidateLauncher: launcher.capability, ...options });
const item = (path = 'tree/file') => ({ digest: 'd'.repeat(64), path, type: 'tree' });
const output = (path = 'tree/file') => JSON.stringify({ outputs: [item(path)], schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' });
const containmentFailure = (error) => error?.code === 'SANDBOX_SETTLEMENT_UNCONFIRMED' && !error.message.includes('/') && !error.stack.includes('/');

test('broker credential never enters canonical parser environment, argv, stdin, or handle', async () => {
  const canary = 'broker-secret-canary';
  const broker = new CandidateCredentialBroker({ credential: canary, acquire: async ({ credential, inputDigest }) => ({ handle: credential === canary ? 'opaque.handle.1' : '', inputDigest }) });
  const launcher = new FakeCandidateLauncher(); const value = await supervisor(launcher).run(job, await broker.stage(job)); const request = launcher.requests[0];
  assert.equal(value.code, 'VALIDATED'); assert.deepEqual(request.environment, {}); assert.deepEqual(request.arguments, []); assert.equal(request.stdin.toString(), `{"inputDigest":"${job.inputDigest}","inputHandle":"opaque.handle.1","schemaVersion":"ogvcs.untrusted-sandbox/parser-input/v1"}`); assert.equal(JSON.stringify(request).includes(canary), false);
});

test('stalled broker acquisition and launcher start are deadline-bounded', async () => {
  const broker = new CandidateCredentialBroker({ credential: 'test-only', deadlineMilliseconds: 5, acquire: async () => new Promise(() => {}) });
  assert.equal(await broker.stage(job), null);
  const launcher = new FakeCandidateLauncher({ start: async () => new Promise(() => {}) });
  assert.equal((await supervisor(launcher, { deadlineMilliseconds: 5 }).run(job, staged())).code, 'SANDBOX_UNAVAILABLE');
  assert.throws(() => new CandidateCredentialBroker({ credential: 'test-only', acquire: async () => null, deadlineMilliseconds: 60_001 }), TypeError);
  assert.throws(() => supervisor(new FakeCandidateLauncher(), { terminationGraceMilliseconds: 60_001 }), TypeError);
});

test('missing controls, unbranded launchers, and public field replacement fail closed', async () => {
  const missing = new FakeCandidateLauncher({ assertedControls: { ...requiredControls(), networkDenied: false } });
  assert.throws(() => new CandidateSandboxSupervisor({ candidateLauncher: {} }), TypeError);
  assert.equal((await supervisor(missing).run(job, staged())).code, 'SANDBOX_UNAVAILABLE'); assert.equal(missing.requests.length, 0);
  const branded = new FakeCandidateLauncher(); const injected = new FakeCandidateLauncher(); const subject = supervisor(branded);
  assert.throws(() => { subject.parts = { ...injected.capability }; }, TypeError);
  assert.equal((await subject.run(job, staged())).code, 'VALIDATED'); assert.equal(branded.requests.length, 1); assert.equal(injected.requests.length, 0);
});

test('candidate runtime exposes no production-named constructor and snapshots controls once', async () => {
  assert.deepEqual(Object.keys(runtime).sort(), ['CandidateCredentialBroker', 'CandidateSandboxSupervisor']);
  let invoked = false; const accessor = { ...requiredControls() }; Object.defineProperty(accessor, 'networkDenied', { enumerable: true, get() { invoked = true; return true; } });
  assert.throws(() => new FakeCandidateLauncher({ assertedControls: accessor }), TypeError); assert.equal(invoked, false);
  assert.throws(() => new FakeCandidateLauncher({ assertedControls: new Proxy(requiredControls(), {}) }), TypeError);
  const mutable = { ...requiredControls() }; const launcher = new FakeCandidateLauncher({ assertedControls: mutable }); mutable.networkDenied = false;
  assert.equal((await supervisor(launcher).run(job, staged())).code, 'VALIDATED');
});

test('getter, proxy, nested coercion, and later mutation cannot alter job or staged snapshots', async () => {
  let invoked = false; const getter = { ...job }; Object.defineProperty(getter, 'jobId', { enumerable: true, get() { invoked = true; return job.jobId; } });
  const launcher = new FakeCandidateLauncher(); assert.equal((await supervisor(launcher).run(getter, staged())).code, 'SANDBOX_PROTOCOL_INVALID'); assert.equal(invoked, false);
  assert.equal((await supervisor(launcher).run(new Proxy({ ...job }, {}), staged())).code, 'SANDBOX_PROTOCOL_INVALID');
  let stagedGetter = false; const accessorStaged = { ...staged() }; Object.defineProperty(accessorStaged, 'handle', { enumerable: true, get() { stagedGetter = true; return 'opaque.handle.1'; } });
  assert.equal((await supervisor(launcher).run(job, accessorStaged)).code, 'SANDBOX_PROTOCOL_INVALID'); assert.equal(stagedGetter, false);
  assert.equal((await supervisor(launcher).run(job, new Proxy(staged(), {}))).code, 'SANDBOX_PROTOCOL_INVALID');
  let nestedRead = false; const nested = new Proxy({}, { get() { nestedRead = true; return () => job.jobId; } });
  assert.equal((await supervisor(launcher).run({ ...job, jobId: nested }, staged())).code, 'SANDBOX_PROTOCOL_INVALID'); assert.equal(nestedRead, false);
  const mutable = { ...job }; const pending = supervisor(launcher).run(mutable, staged()); mutable.jobId = 'changed'; const accepted = await pending;
  assert.equal(accepted.jobId, job.jobId); assert.equal(accepted.code, 'VALIDATED');
});

test('timeout cleanup performs TERM then KILL and returns only after exit settlement', async () => {
  const forever = new Promise(() => {}); let settle;
  const exit = new Promise((resolve) => { settle = resolve; });
  const launcher = new FakeCandidateLauncher({ stdout: (async function* () { await forever; }()), exit, terminate: async () => {}, kill: async () => { settle({ code: null, signal: 'SIGKILL' }); } });
  const value = await supervisor(launcher, { deadlineMilliseconds: 5, terminationGraceMilliseconds: 2 }).run(job, staged());
  assert.equal(value.code, 'SANDBOX_TIMEOUT'); assert.equal(launcher.terminated, 1); assert.equal(launcher.killed, 1);
});

test('unsettled post-KILL process rejects boundedly and poisons the supervisor', async () => {
  const forever = new Promise(() => {});
  const launcher = new FakeCandidateLauncher({ stdout: (async function* () { await forever; }()), exit: forever, terminate: async () => forever, kill: async () => forever });
  const subject = supervisor(launcher, { deadlineMilliseconds: 5, terminationGraceMilliseconds: 2 });
  await assert.rejects(subject.run(job, staged()), containmentFailure);
  assert.equal(launcher.terminated, 1); assert.equal(launcher.killed, 1);
  await assert.rejects(subject.run(job, staged()), containmentFailure); assert.equal(launcher.requests.length, 1);
});

test('process, stream, thenable, and exit records reject accessors and proxies without invoking them', async () => {
  let processGetter = false; const accessorProcess = { stdout: null, stderr: null, exit: Promise.resolve({ code: 0, signal: null }), terminate: async () => {}, kill: async () => {} };
  Object.defineProperty(accessorProcess, 'stdout', { enumerable: true, get() { processGetter = true; return null; } });
  await assert.rejects(supervisor(new FakeCandidateLauncher({ start: async () => accessorProcess })).run(job, staged()), containmentFailure); assert.equal(processGetter, false);

  let streamRead = false; const streamProxy = new Proxy({}, { get() { streamRead = true; return undefined; } });
  const proxyProcess = Object.freeze({ stdout: streamProxy, stderr: (async function* () {})(), exit: Promise.resolve({ code: 0, signal: null }), terminate: async () => {}, kill: async () => {} });
  await assert.rejects(supervisor(new FakeCandidateLauncher({ start: async () => proxyProcess })).run(job, staged()), containmentFailure); assert.equal(streamRead, false);

  let thenRead = false; const thenable = {}; Object.defineProperty(thenable, 'then', { get() { thenRead = true; return () => {}; } });
  const thenableProcess = Object.freeze({ stdout: (async function* () {})(), stderr: (async function* () {})(), exit: thenable, terminate: async () => {}, kill: async () => {} });
  await assert.rejects(supervisor(new FakeCandidateLauncher({ start: async () => thenableProcess })).run(job, staged()), containmentFailure); assert.equal(thenRead, false);

  let exitGetter = false; const exitRecord = { code: 0, signal: null }; Object.defineProperty(exitRecord, 'signal', { enumerable: true, get() { exitGetter = true; return null; } });
  assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [output()], exit: Promise.resolve(exitRecord) })).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED'); assert.equal(exitGetter, false);
});

test('nonzero or signalled exit and any stderr are never accepted or disclosed', async () => {
  const nonzero = new FakeCandidateLauncher({ stdout: [output()], exit: Promise.resolve({ code: 1, signal: null }) });
  const signalled = new FakeCandidateLauncher({ stdout: [output()], exit: Promise.resolve({ code: 0, signal: 'SIGKILL' }) });
  const stderr = new FakeCandidateLauncher({ stdout: [output()], stderr: ['parser secret /private/x'] });
  assert.equal((await supervisor(nonzero).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
  assert.equal((await supervisor(signalled).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
  const denied = await supervisor(stderr).run(job, staged()); assert.equal(denied.code, 'SANDBOX_VALIDATION_FAILED'); assert.equal(JSON.stringify(denied).includes('parser secret'), false);
});

test('only sorted canonical, duplicate-free, closed output JSON is accepted', async () => {
  const invalid = [
    `{"outputs":[],"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1"}`,
    '{"schemaVersion":"ogvcs.untrusted-sandbox/parser-output/v1","outputs":[]}',
    JSON.stringify({ extra: true, outputs: [], schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' }),
    JSON.stringify({ outputs: [{ ...item(), extra: true }], schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' }),
  ];
  for (const stdout of invalid) assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [stdout] })).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED');
  assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [output()] })).run(job, staged())).code, 'VALIDATED');
});

test('OGVCS-004 portable paths reject traversal, POSIX roots, Windows drives, UNC, devices, and backslashes', async () => {
  const invalid = ['../secret', '/host', 'C:/host', 'C:\\host', '//server/share', '\\\\server\\share', '\\\\?\\C:\\host', 'tree\\file', 'tree/CON'];
  for (const path of invalid) assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [output(path)] })).run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED', path);
  assert.equal((await supervisor(new FakeCandidateLauncher({ stdout: [output('tree/file')] })).run(job, staged())).code, 'VALIDATED');
});

test('closed output record count is enforced and carried in immutable launch limits', async () => {
  const stdout = JSON.stringify({ outputs: [item('tree/a'), item('tree/b')], schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' });
  const launcher = new FakeCandidateLauncher({ stdout: [stdout] }); const subject = supervisor(launcher, { maxOutputRecords: 1 });
  assert.equal((await subject.run(job, staged())).code, 'SANDBOX_VALIDATION_FAILED'); assert.equal(launcher.requests[0].limits.maxOutputRecords, 1); assert.equal(Object.isFrozen(launcher.requests[0].limits), true);
});
