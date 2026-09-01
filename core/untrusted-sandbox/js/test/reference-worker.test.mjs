import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, mkdtemp, mkdir, open, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  createdContainerInspectMismatch,
  DockerReferenceAdapter,
  isPrestartImageDiagnostic,
  isRegularPinnedFileHandleForTesting,
  postNonzeroFailureDispositionForTesting,
  prestartImageDiagnostic,
  runtimeImageInspectMismatch,
  validateCreatedContainerInspect,
  validateOutputVolumeInspect,
  validateRuntimeImageInspect,
  workerFailureClassForTesting,
} from '../src/internal/docker-reference.mjs';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, parseAndVerifyToolManifest, sha256, snapshotTrustedManifestKeys } from '../src/internal/reference-contract.mjs';
import { authenticatedResultDiagnostic, ReferenceSandboxService } from '../src/internal/reference-service.mjs';
import { ReferenceStateStore } from '../src/internal/reference-state.mjs';
import * as linuxBoundary from '../src/linux.mjs';

const MAGIC = Buffer.from([0x4f, 0x47, 0x56, 0x43, 0x53, 0x42, 0x31, 0x00]);
const RUNTIME_DIGEST = 'b'.repeat(64);
const SECCOMP_DIGEST = 'e'.repeat(64);
const ACTOR_DIGEST = 'a'.repeat(64);
const OPTIONS_DIGEST = 'c'.repeat(64);
const OBJECT_ID_DIGEST = 'd'.repeat(64);
const referenceStateTest = process.platform === 'win32' ? test.skip : test;

test('Linux reference export remains candidate-named until live controls are verified', () => {
  assert.equal(Object.hasOwn(linuxBoundary, 'openLinuxReferenceSandbox'), false);
  assert.equal(typeof linuxBoundary.openLinuxReferenceSandboxCandidate, 'function');
  assert.equal(typeof linuxBoundary.probeLinuxReferenceSandbox, 'function');
});

test('non-Linux hosts keep the Linux state boundary fail closed while portable tests remain runnable', async (context) => {
  if (process.platform === 'linux') { context.skip('Linux admission is covered by the live reference lane'); return; }
  assert.deepEqual(await linuxBoundary.probeLinuxReferenceSandbox({ dockerBinary: '/not/consulted' }), { available: false, code: 'SANDBOX_UNAVAILABLE', profile: 'linux-reference-v1' });
  await assert.rejects(linuxBoundary.openLinuxReferenceSandboxCandidate(Object.freeze({})), (error) => error?.code === 'SANDBOX_UNAVAILABLE');
});

test('pre-admission image diagnostics are closed and never copy hostile details', () => {
  const authorizedDiagnostics = Object.freeze([
    'PRESTART_IMAGE_IDENTITY',
    'PRESTART_IMAGE_PLATFORM',
    'PRESTART_IMAGE_ROOTFS',
    'PRESTART_IMAGE_SIZE',
    'PRESTART_IMAGE_CONFIG_ENV',
    'PRESTART_IMAGE_CONFIG_COMMAND',
    'PRESTART_IMAGE_CONFIG_VOLUME',
    'PRESTART_IMAGE_CONFIG_HEALTH',
    'PRESTART_IMAGE_CONFIG_USER_WORKDIR',
    'PRESTART_IMAGE_CONFIG_LABELS',
    'PRESTART_IMAGE_INSPECT_SHAPE',
  ]);
  for (const value of authorizedDiagnostics) assert.equal(isPrestartImageDiagnostic(value), true, value);
  for (const retired of [
    'PRESTART_IMAGE_CONTROL',
    'PRESTART_IMAGE_CONFIG_EXPOSED_PORTS',
    'PRESTART_IMAGE_CONFIG_SHAPE',
  ]) assert.equal(isPrestartImageDiagnostic(retired), false, retired);

  const diagnostic = 'PRESTART_IMAGE_CONFIG_ENV';
  for (const hostile of [
    diagnostic,
    'PRESTART_IMAGE_CONFIG_ENV_RAW_/home/runner/secret',
    'PRESTART_IMAGE_CONFIG_ENV\nSECRET=value',
    'PRESTART_IMAGE_UNKNOWN',
    new String(diagnostic),
    null,
  ]) {
    const error = new linuxBoundary.LinuxReferenceUnavailableError(hostile);
    assert.equal(error.code, 'SANDBOX_UNAVAILABLE');
    assert.equal(error.message, 'required Linux reference sandbox controls are unavailable');
    assert.equal(error.stack, 'LinuxReferenceUnavailableError: required Linux reference sandbox controls are unavailable');
    assert.equal(error.diagnostic, null);
    assert.equal(JSON.stringify(error).includes('SECRET'), false);
    assert.equal(JSON.stringify(error).includes('/home/runner'), false);
  }
  assert.equal(prestartImageDiagnostic(new Error('runtime image admission failed: SECRET=/host/path')), null);
  assert.equal(prestartImageDiagnostic(Object.assign(new Error('runtime image admission failed'), { diagnostic })), null);
  assert.equal(prestartImageDiagnostic(new Proxy(new Error('hostile'), { get() { throw new Error('trap'); } })), null);
});

test('Docker hardening leaves PID mode empty for the engine private namespace', async () => {
  const source = await readFile(new URL('../src/internal/docker-reference.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /['"`]--pid(?:=|['"`])/u);
  assert.match(source, /bind-recursive=writable/u);
  assert.doesNotMatch(source, /bind-recursive=disabled/u);
});

referenceStateTest('held mount admission accepts only open regular pinned file descriptors', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-sandbox-held-fd-'));
  const filePath = join(root, 'regular');
  await writeFile(filePath, Buffer.from('pinned'));
  const file = await open(filePath, 'r');
  const directory = await open(root, 'r');
  try {
    assert.equal(isRegularPinnedFileHandleForTesting(file), true);
    assert.equal(isRegularPinnedFileHandleForTesting(directory), false);
    assert.equal(isRegularPinnedFileHandleForTesting({ fd: directory.fd }), false);
    assert.equal(isRegularPinnedFileHandleForTesting(new Proxy(file, {})), false);
    await file.close();
    assert.equal(isRegularPinnedFileHandleForTesting(file), false);
  } finally {
    await file.close().catch(() => {});
    await directory.close();
    await rm(root, { recursive: true, force: true });
  }
});

const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };
const u64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes; };
const readHandle = async (handle) => {
  const details = await handle.stat(); const bytes = Buffer.alloc(details.size); let offset = 0;
  while (offset < bytes.length) { const value = await handle.read(bytes, offset, bytes.length - offset, offset); if (value.bytesRead === 0) throw new Error('fixture handle ended early'); offset += value.bytesRead; }
  return bytes;
};
const outputFrame = (binding, files, tamper = null) => {
  const aggregate = createHash('sha256'); const parts = [];
  const append = (bytes) => { aggregate.update(bytes); parts.push(bytes); };
  append(MAGIC); append(Buffer.from(binding, 'hex'));
  let total = 0;
  for (const file of [...files].sort((left, right) => Buffer.compare(Buffer.from(left.path, 'utf8'), Buffer.from(right.path, 'utf8')))) {
    const path = Buffer.from(file.path, 'utf8'); const content = Buffer.from(file.content);
    append(Buffer.from([1])); append(Buffer.concat([u32(path.length), u64(content.length)])); append(createHash('sha256').update(content).digest()); append(path); append(content); total += content.length;
  }
  append(Buffer.concat([Buffer.from([0xff]), u32(files.length), u64(total)]));
  const digest = aggregate.digest();
  parts.push(tamper === 'terminal' ? Buffer.alloc(32, 0) : digest);
  if (tamper === 'binding') parts[1] = Buffer.alloc(32, 0);
  return Buffer.concat(parts);
};

const authenticatedEvidenceBytes = (source, evidenceHmacKey) => {
  const { evidenceKeyId, evidenceMacSha256: ignoredMac, ...payload } = source;
  assert.equal(typeof ignoredMac, 'string');
  const evidenceMacSha256 = createHmac('sha256', evidenceHmacKey)
    .update('OGVCS-SANDBOX-EVIDENCE-V1\0', 'utf8')
    .update(canonicalJson(payload), 'utf8')
    .digest('hex');
  return Buffer.from(`${canonicalJson({ ...payload, evidenceKeyId, evidenceMacSha256 })}\n`, 'utf8');
};

class FakeContainerAdapter {
  constructor({ collectKind = null, failureClass = null, gate = null, inspectMismatch = null, runKind = null, tamper = null } = {}) { this.seccompDigest = SECCOMP_DIGEST; this.collectKind = collectKind; this.failureClass = failureClass; this.gate = gate; this.inspectMismatch = inspectMismatch; this.runKind = runKind; this.tamper = tamper; this.runs = 0; this.collections = 0; this.discards = 0; this.parserSawBinding = false; this.modes = []; }
  async verifyRuntimeImage(image, contract) { return image === `sha256:${RUNTIME_DIGEST}` && contract === LINUX_RUNTIME_CONTRACT_SHA256; }
  async runTool({ inputHandle, jobHandle, toolHandle, signal }) {
    this.runs += 1;
    if (this.inspectMismatch) throw new Error(`SANDBOX_INSPECT_MISMATCH:${this.inspectMismatch}`);
    this.parserSawBinding ||= Object.keys(arguments[0]).includes('bindingHandle');
    this.modes.push((await inputHandle.stat()).mode & 0o777, (await jobHandle.stat()).mode & 0o777, (await toolHandle.stat()).mode & 0o777);
    const command = (await readHandle(inputHandle)).toString('utf8');
    if (this.gate && !signal.aborted) await Promise.race([this.gate.promise, new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }))]);
    if (signal.aborted) return Object.freeze({ kind: 'cancelled', volume: `volume.${this.runs}` });
    if (this.runKind) return Object.freeze(this.runKind === 'failed' ? { failureClass: this.failureClass, kind: this.runKind, volume: `volume.${this.runs}` } : { kind: this.runKind, volume: `volume.${this.runs}` });
    if (command === 'timeout') return Object.freeze({ kind: 'timeout', volume: `volume.${this.runs}` });
    const path = command === 'converter' ? 'preview/result' : 'import/result';
    return Object.freeze({ kind: 'success', volume: Object.freeze({ files: Object.freeze([{ content: Buffer.from(command), path }]) }) });
  }
  async collectOutput({ volume, bindingHandle, framePath }) {
    this.collections += 1; const binding = (await readHandle(bindingHandle)).toString('ascii');
    if (this.collectKind) return Object.freeze({ frameBytes: 0, kind: this.collectKind });
    await writeFile(framePath, outputFrame(binding, volume.files, this.tamper), { flag: 'wx', mode: 0o600 });
    return Object.freeze({ frameBytes: (await stat(framePath)).size, kind: 'success' });
  }
  async discardVolume() { this.discards += 1; }
}

const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };

const workerExecuteResult = (overrides = {}) => Object.freeze({
  code: 1,
  kind: 'exit',
  signal: null,
  stderr: Buffer.alloc(0),
  stdout: Buffer.alloc(0),
  stdoutBytes: 0,
  ...overrides,
});

const postNonzeroInspectResult = ({ id, name, state, ...containerOverrides }, executeOverrides = {}) => {
  const stdout = Buffer.from(JSON.stringify([{ Id: id, Name: `/${name}`, State: state, ...containerOverrides }]));
  return workerExecuteResult({ code: 0, stdout, stdoutBytes: stdout.length, ...executeOverrides });
};

const makeManifest = ({ privateKey, publicKey, toolDigest, nowUnixMs, resourcePolicy = null }) => {
  const policy = resourcePolicy ?? Object.freeze({ cpuMilliseconds: 1_000, elapsedMilliseconds: 10_000, fanout: 16, memoryBytes: 64 * 1024 * 1024, outputBytes: 1024 * 1024, processes: 4, profileId: 'linux-reference-v1', scratchBytes: 2 * 1024 * 1024 });
  const unsigned = Object.freeze({
    expiresAtUnixMs: nowUnixMs + 60 * 60 * 1000,
    generation: 1,
    issuedAtUnixMs: nowUnixMs - 1_000,
    manifestId: 'dummy.importer.v1',
    outputPolicy: Object.freeze({ allowedTypes: Object.freeze(['conformance.record']), maximumFileBytes: 1024 * 1024, schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' }),
    resourcePolicy: policy,
    runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256,
    runtimeDigest: RUNTIME_DIGEST,
    runtimeImage: `sha256:${RUNTIME_DIGEST}`,
    schemaVersion: 'ogvcs.untrusted-sandbox/tool-runtime-manifest/v1',
    signingKeyId: 'test.signer.1',
    toolClass: 'import-parser',
    toolDigest,
  });
  const signatureEd25519 = sign(null, Buffer.from(canonicalJson(unsigned), 'utf8'), privateKey).toString('base64url');
  const bytes = Buffer.from(canonicalJson({ ...unsigned, signatureEd25519 }), 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes), policyDigest: sha256(Buffer.from(canonicalJson(policy), 'utf8')), publicKey });
};

const withFixture = async (operation, { adapter = new FakeContainerAdapter(), faults = null, acquireGate = null, clock = Date.now, resourcePolicy = null } = {}) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-sandbox-reference-')); await chmod(root, 0o700);
  const toolPath = join(root, 'dummy-tool'); await writeFile(toolPath, Buffer.from('dummy-tool-v1'), { mode: 0o555 }); await chmod(toolPath, 0o555);
  const toolDigest = sha256(await readFile(toolPath));
  const nowUnixMs = clock();
  const keys = generateKeyPairSync('ed25519');
  const manifest = makeManifest({ ...keys, nowUnixMs, resourcePolicy, toolDigest });
  const evidenceHmacKey = Buffer.alloc(32, 0x5a);
  const evidenceKeyId = 'test.evidence.1';
  let acquisitions = 0; let credentialObserved = false;
  const source = Object.freeze({
    acquire: async ({ credential }) => { acquisitions += 1; credentialObserved ||= credential === 'broker-secret-canary'; if (acquireGate) await acquireGate.promise; return Buffer.from('importer'); },
    credential: 'broker-secret-canary', maximumBytes: 1024, sourceId: 'fixture.source',
  });
  const configuration = {
    acquisitionSources: [source], adapter, evidenceHmacKey, evidenceHmacKeyId: evidenceKeyId, faults,
    manifestCatalog: [{ manifestBytes: manifest.bytes, toolPath }], stateRoot: join(root, 'state'), trustedManifestKeys: { 'test.signer.1': keys.publicKey }, clock,
  };
  let service = await ReferenceSandboxService.open(configuration);
  const jobFor = (suffix = '1', overrides = {}) => Object.freeze({
    actorDigest: ACTOR_DIGEST, deadlineUnixMs: clock() + 9_000, idempotencyKey: `idempotency.${suffix}`, inputDigest: sha256(Buffer.from('importer')), jobId: `job.${suffix}`, manifestDigest: manifest.digest, optionsDigest: OPTIONS_DIGEST,
    outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1', purpose: 'conformance', resourcePolicyDigest: manifest.policyDigest, runtimeDigest: RUNTIME_DIGEST, schemaVersion: 'ogvcs.untrusted-sandbox/reference-job/v1', toolDigest, ...overrides,
  });
  const acquisition = Object.freeze({ maximumBytes: 1024, objectIdDigest: OBJECT_ID_DIGEST, schemaVersion: 'ogvcs.untrusted-sandbox/acquisition-request/v1', sourceId: 'fixture.source' });
  const fixture = {
    acquisition,
    adapter,
    evidenceHmacKey,
    evidenceKeyId,
    get acquisitions() { return acquisitions; },
    get credentialObserved() { return credentialObserved; },
    jobFor,
    manifest,
    async restart() { await service.close(); service = await ReferenceSandboxService.open(configuration); },
    root,
    get service() { return service; },
  };
  try { return await operation(fixture); }
  finally { await service.close().catch(() => {}); await rm(root, { recursive: true, force: true }); }
};

referenceStateTest('signed manifest, credential-free held-FD mounts, frame channel, provenance, and idempotency are exact', async () => {
  await withFixture(async (fixture) => {
    const job = fixture.jobFor();
    const first = await fixture.service.run(job, fixture.acquisition);
    const replay = await fixture.service.run(job, fixture.acquisition);
    assert.equal(first.code, 'VALIDATED'); assert.deepEqual(replay, first);
    assert.equal(fixture.acquisitions, 1); assert.equal(fixture.adapter.runs, 1); assert.equal(fixture.adapter.collections, 1);
    assert.equal(fixture.credentialObserved, true); assert.equal(fixture.adapter.parserSawBinding, false);
    assert.deepEqual(fixture.adapter.modes, [0o444, 0o444, 0o555]);
    const mismatch = await fixture.service.run(fixture.jobFor('1', { optionsDigest: 'f'.repeat(64) }), fixture.acquisition);
    assert.equal(mismatch.code, 'SANDBOX_PROTOCOL_INVALID'); assert.equal(fixture.adapter.runs, 1);
    const evidence = await Promise.all((await readdir(join(fixture.root, 'state/evidence'))).map((name) => readFile(join(fixture.root, 'state/evidence', name), 'utf8')));
    assert.equal(evidence.some((value) => value.includes('broker-secret-canary')), false);
    assert.equal(evidence.some((value) => value.includes('evidenceMacSha256')), true);
  });
});

test('worker failure subclasses derive only from an exact bounded execute result', () => {
  for (const [source, expected] of [
    [workerExecuteResult({ code: 63 }), 'INPUT_READ'],
    [workerExecuteResult({ code: 64 }), 'OUTPUT_WRITE'],
    [workerExecuteResult({ code: 126, stderr: Buffer.from('bounded') }), 'ENTRYPOINT'],
    [workerExecuteResult({ code: 127, stdout: Buffer.from('bounded'), stdoutBytes: 7 }), 'ENTRYPOINT'],
    [workerExecuteResult({ code: 1 }), 'NONZERO'],
    [workerExecuteResult({ code: 255 }), 'NONZERO'],
    [workerExecuteResult({ code: 0, stdout: Buffer.from('bounded'), stdoutBytes: 7 }), 'STDOUT'],
    [workerExecuteResult({ code: 0, stderr: Buffer.from('bounded') }), 'STDERR'],
    [workerExecuteResult({ code: 0 }), 'CONTROL'],
    [workerExecuteResult({ code: 0, stderr: Buffer.from('raw /home/runner/private'), stdout: Buffer.from('id=container-secret'), stdoutBytes: 19 }), 'CONTROL'],
    [workerExecuteResult({ code: 918273 }), 'CONTROL'],
    [workerExecuteResult({ code: 63, signal: 'SIGKILL' }), 'CONTROL'],
    [workerExecuteResult({ code: 63, stdout: Buffer.from('x') }), 'CONTROL'],
    [workerExecuteResult({ kind: 'timeout' }), 'CONTROL'],
    [Object.freeze({ kind: 'spawn-failed' }), 'CONTROL'],
    [{ ...workerExecuteResult({ code: 63 }) }, 'CONTROL'],
    [Object.freeze({ ...workerExecuteResult({ code: 63 }), rawPath: '/home/runner/private' }), 'CONTROL'],
    [new Proxy(workerExecuteResult({ code: 63 }), {}), 'CONTROL'],
  ]) assert.equal(workerFailureClassForTesting(source), expected);

  const accessor = {
    kind: 'exit', signal: null, stderr: Buffer.alloc(0), stdout: Buffer.alloc(0), stdoutBytes: 0,
  };
  Object.defineProperty(accessor, 'code', { enumerable: true, get() { throw new Error('SECRET=/home/runner/private'); } });
  assert.equal(workerFailureClassForTesting(Object.freeze(accessor)), 'CONTROL');
});

test('post-NONZERO inspection emits only closed semantic classes and poisons every mismatch', () => {
  const id = '1'.repeat(64);
  const name = `ogvcs-sandbox-${'2'.repeat(24)}`;
  const start = workerExecuteResult({ code: 1, stderr: Buffer.from('hostile raw /home/runner/private container.246810') });
  const state = { Dead: false, Error: 'hostile daemon detail /var/lib/docker/secret', ExitCode: 128, OOMKilled: false, Paused: false, Pid: 0, Restarting: false, Running: false, Status: 'created' };
  const silent = { stderr: Buffer.alloc(0) };
  const disposition = (stateOverrides = {}, inspectOverrides = {}, startOverrides = {}) => postNonzeroFailureDispositionForTesting(
    workerExecuteResult({ ...start, ...startOverrides }),
    postNonzeroInspectResult({ id, name, state: { ...state, ...stateOverrides } }, inspectOverrides),
    id,
    name,
  );
  assert.deepEqual(disposition(), { failureClass: 'ACTIVATION_CONTROL', kind: 'failed', poison: false });
  assert.deepEqual(disposition({ Error: '', ExitCode: 1, Status: 'exited' }, {}, silent), { failureClass: 'TOOL_EXITED', kind: 'failed', poison: false });
  assert.deepEqual(disposition({ Error: '', ExitCode: 255, Status: 'exited' }, {}, { code: 255, ...silent }), { failureClass: 'TOOL_EXITED', kind: 'failed', poison: false });
  assert.deepEqual(disposition({ Error: '', ExitCode: 137, OOMKilled: true, Status: 'exited' }, {}, { code: 137, ...silent }), { failureClass: null, kind: 'resource-limit', poison: false });
  assert.deepEqual(disposition({ Error: '', ExitCode: 137, Status: 'exited' }, {}, { code: 137, ...silent }), { failureClass: null, kind: 'resource-limit', poison: false });
  assert.deepEqual(disposition({ Error: '', ExitCode: 152, Status: 'exited' }, {}, { code: 152, ...silent }), { failureClass: null, kind: 'resource-limit', poison: false });
  for (const actual of [disposition(), disposition({ Error: '', ExitCode: 1, Status: 'exited' }, {}, silent), disposition({ Error: '', ExitCode: 255, Status: 'exited' }, {}, { code: 255, ...silent }), disposition({ Error: '', ExitCode: 137, OOMKilled: true, Status: 'exited' }, {}, { code: 137, ...silent })]) {
    const exposed = JSON.stringify(actual);
    assert.equal(Object.isFrozen(actual), true);
    for (const secret of ['128', '255', '/home/runner', '/var/lib/docker', '246810', id, name]) assert.equal(exposed.includes(secret), false);
  }

  const poison = Object.freeze({ failureClass: 'CONTROL', kind: 'failed', poison: true });
  for (const actual of [
    disposition({ Status: 'running' }),
    disposition({ ExitCode: -1 }),
    disposition({ ExitCode: 256 }),
    disposition({ ExitCode: 1.5 }),
    disposition({ ExitCode: '1' }),
    disposition({ OOMKilled: 'false' }),
    disposition({ Error: null }),
    disposition({ Error: '' }),
    disposition({ ExitCode: 0 }),
    disposition({ OOMKilled: true }),
    disposition({ Dead: true }),
    disposition({ Paused: true }),
    disposition({ Pid: 1 }),
    disposition({ Restarting: true }),
    disposition({ Running: true }),
    disposition({}, {}, { code: 2 }),
    disposition({}, {}, { stdout: Buffer.from('x'), stdoutBytes: 1 }),
    disposition({}, {}, { stderr: Buffer.alloc(0) }),
    disposition({ Error: '', ExitCode: 1, Status: 'exited' }),
    disposition({ Error: 'daemon failure', ExitCode: 2, Status: 'exited' }),
    disposition({ Error: '', ExitCode: 2, Status: 'exited' }),
    disposition({ Error: '', ExitCode: 1, OOMKilled: true, Status: 'exited' }, {}, silent),
    disposition({ Error: '', ExitCode: 137, OOMKilled: true, Status: 'exited' }, {}, { code: 137 }),
    disposition({ Error: '', ExitCode: 1, Status: 'exited' }, {}, { stdout: Buffer.from('x'), stdoutBytes: 1, ...silent }),
    disposition({ Error: '', ExitCode: 1, Status: 'exited' }, {}, { code: 255 }),
    disposition({ Error: '', ExitCode: 63, Status: 'exited' }, {}, { code: 63, stderr: Buffer.alloc(0) }),
    disposition({ Error: '', ExitCode: 126, Status: 'exited' }, {}, { code: 126 }),
  ]) assert.deepEqual(actual, poison);

  const validInspect = postNonzeroInspectResult({ id, name, state });
  const malformedBytes = Buffer.from('{"SECRET":"/home/runner/private"}');
  const multiple = Buffer.from(JSON.stringify([{ Id: id, Name: `/${name}`, State: state }, { Id: id, Name: `/${name}`, State: state }]));
  for (const inspected of [
    workerExecuteResult({ code: 1, stderr: Buffer.from('SECRET=/home/runner/private') }),
    workerExecuteResult({ code: 0, stdout: malformedBytes, stdoutBytes: malformedBytes.length }),
    workerExecuteResult({ code: 0, stdout: multiple, stdoutBytes: multiple.length }),
    postNonzeroInspectResult({ id, name, state }, { stderr: Buffer.from('SECRET=/home/runner/private') }),
    postNonzeroInspectResult({ id: '3'.repeat(64), name, state }),
    postNonzeroInspectResult({ id, name: `ogvcs-sandbox-${'4'.repeat(24)}`, state }),
    postNonzeroInspectResult({ id, name, state: null }),
    Object.freeze({ kind: 'timeout' }),
    { ...validInspect },
    new Proxy(validInspect, {}),
  ]) assert.deepEqual(postNonzeroFailureDispositionForTesting(start, inspected, id, name), poison);
  assert.deepEqual(postNonzeroFailureDispositionForTesting(start, validInspect, `${'5'.repeat(64)}`, name), poison);
  assert.deepEqual(postNonzeroFailureDispositionForTesting(start, validInspect, id, `ogvcs-sandbox-${'6'.repeat(24)}`), poison);
});

referenceStateTest('post-start diagnostics require exact authenticated provenance and expose only closed stages', async () => {
  const workerCases = Object.freeze(['ACTIVATION_CONTROL', 'CONTROL', 'ENTRYPOINT', 'INPUT_READ', 'OUTPUT_WRITE', 'STDERR', 'STDOUT', 'TOOL_EXITED'].map((failureClass) => Object.freeze({
    adapter: new FakeContainerAdapter({ failureClass, runKind: 'failed' }),
    diagnostic: `WORKER_FAILED:${failureClass}`,
    events: Object.freeze(['WORKER_FAILED', `WORKER_FAILURE_${failureClass}`]),
  })));
  const cases = Object.freeze([
    ...workerCases,
    Object.freeze({ adapter: new FakeContainerAdapter({ collectKind: 'failed' }), diagnostic: 'TRUSTED_OUTPUT_SHIM_REJECTED', events: Object.freeze(['TRUSTED_OUTPUT_SHIM_REJECTED']) }),
    Object.freeze({ adapter: new FakeContainerAdapter({ tamper: 'terminal' }), diagnostic: 'OUTPUT_FRAME_INVALID', events: Object.freeze(['OUTPUT_FRAME_INVALID']) }),
  ]);
  for (const entry of cases) {
    await withFixture(async (fixture) => {
      const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
      assert.equal(result.code, 'SANDBOX_VALIDATION_FAILED');
      const evidenceBytes = await readFile(join(fixture.root, 'state/evidence', `${result.provenanceDigest}.json`));
      const request = { evidenceBytes, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result };
      assert.equal(authenticatedResultDiagnostic(request), entry.diagnostic);
      assert.equal(authenticatedResultDiagnostic({ ...request, evidenceHmacKey: Buffer.alloc(32, 0x11) }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, evidenceKeyId: 'test.evidence.substitution' }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: { ...result, code: 'VALIDATED', status: 'validated' } }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: { ...result, status: 'validated' } }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: { ...result, outputDigest: '7'.repeat(64) } }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: { ...result, cleanupReceiptDigest: '8'.repeat(64) } }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: { ...result, jobId: 'job.substitution' } }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: { ...result, raw: '/home/runner/private' } }), 'none');
      assert.equal(authenticatedResultDiagnostic({ ...request, result: new Proxy(result, { get() { throw new Error('SECRET=/home/runner/private'); } }) }), 'none');
      assert.equal(authenticatedResultDiagnostic(new Proxy(request, { get() { throw new Error('SECRET=/home/runner/private'); } })), 'none');

      const provenance = JSON.parse(evidenceBytes.toString('utf8'));
      assert.deepEqual(provenance.securityEvents, entry.events);
      const tampered = Buffer.from(`${canonicalJson({ ...provenance, securityEvents: ['OUTPUT_FRAME_INVALID', 'WORKER_FAILED'] })}\n`, 'utf8');
      assert.equal(authenticatedResultDiagnostic({ ...request, evidenceBytes: tampered, result: { ...result, provenanceDigest: sha256(tampered) } }), 'none');
      const nonCanonical = Buffer.from(`${JSON.stringify(provenance, null, 2)}\n`, 'utf8');
      assert.equal(authenticatedResultDiagnostic({ ...request, evidenceBytes: nonCanonical, result: { ...result, provenanceDigest: sha256(nonCanonical) } }), 'none');

      for (const securityEvents of [
        [...entry.events, ...entry.events],
        [...entry.events, 'SECRET=/home/runner/private'],
        ['SECRET=/home/runner/private'],
      ]) {
        const hostileBytes = authenticatedEvidenceBytes({ ...provenance, securityEvents }, fixture.evidenceHmacKey);
        const diagnostic = authenticatedResultDiagnostic({ ...request, evidenceBytes: hostileBytes, result: { ...result, provenanceDigest: sha256(hostileBytes) } });
        assert.equal(diagnostic, 'none');
        assert.equal(diagnostic.includes('SECRET'), false);
        assert.equal(diagnostic.includes('/home/runner'), false);
      }
    }, { adapter: entry.adapter });
  }
});

referenceStateTest('authenticated worker detail rejects mixed, duplicate, unknown, raw, identifier, and exit-code variants', async () => {
  await withFixture(async (fixture) => {
    const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    const evidenceBytes = await readFile(join(fixture.root, 'state/evidence', `${result.provenanceDigest}.json`));
    const provenance = JSON.parse(evidenceBytes.toString('utf8'));
    const request = { evidenceBytes, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result };
    assert.equal(authenticatedResultDiagnostic(request), 'WORKER_FAILED:INPUT_READ');
    for (const securityEvents of [
      ['WORKER_FAILED'],
      ['WORKER_FAILURE_INPUT_READ'],
      ['WORKER_FAILURE_INPUT_READ', 'WORKER_FAILED'],
      ['WORKER_FAILED', 'WORKER_FAILURE_INPUT_READ', 'WORKER_FAILURE_INPUT_READ'],
      ['WORKER_FAILED', 'WORKER_FAILURE_UNKNOWN'],
      ['WORKER_FAILED', 'WORKER_FAILURE_CODE_63'],
      ['WORKER_FAILED', 'WORKER_FAILURE_RAW_/home/runner/private'],
      ['WORKER_FAILED', 'WORKER_FAILURE_CONTAINER_246810'],
      ['WORKER_FAILED', 'OUTPUT_FRAME_INVALID'],
      ['WORKER_FAILED', 'WORKER_FAILURE_CONTROL', 'TRUSTED_OUTPUT_SHIM_REJECTED'],
    ]) {
      const hostileBytes = authenticatedEvidenceBytes({ ...provenance, securityEvents }, fixture.evidenceHmacKey);
      const diagnostic = authenticatedResultDiagnostic({ ...request, evidenceBytes: hostileBytes, result: { ...result, provenanceDigest: sha256(hostileBytes) } });
      assert.equal(diagnostic, 'none');
      assert.equal(diagnostic.includes('SECRET'), false);
      assert.equal(diagnostic.includes('/home/runner'), false);
      assert.equal(diagnostic.includes('246810'), false);
      assert.equal(diagnostic.includes('63'), false);
    }
  }, { adapter: new FakeContainerAdapter({ failureClass: 'INPUT_READ', runKind: 'failed' }) });
});

referenceStateTest('legacy authenticated NONZERO evidence remains verifiable but is no longer emitted', async () => {
  await withFixture(async (fixture) => {
    const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    const evidenceBytes = await readFile(join(fixture.root, 'state/evidence', `${result.provenanceDigest}.json`));
    const provenance = JSON.parse(evidenceBytes.toString('utf8'));
    assert.deepEqual(provenance.securityEvents, ['WORKER_FAILED']);
    const legacyBytes = authenticatedEvidenceBytes({ ...provenance, securityEvents: ['WORKER_FAILED', 'WORKER_FAILURE_NONZERO'] }, fixture.evidenceHmacKey);
    const legacyResult = { ...result, provenanceDigest: sha256(legacyBytes) };
    assert.equal(authenticatedResultDiagnostic({ evidenceBytes: legacyBytes, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result: legacyResult }), 'WORKER_FAILED:NONZERO');
    const tampered = Buffer.from(legacyBytes);
    tampered[tampered.length - 2] ^= 1;
    assert.equal(authenticatedResultDiagnostic({ evidenceBytes: tampered, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result: { ...legacyResult, provenanceDigest: sha256(tampered) } }), 'none');
  }, { adapter: new FakeContainerAdapter({ failureClass: 'NONZERO', runKind: 'failed' }) });
});

referenceStateTest('hostile adapter failure details are dropped rather than persisted or reflected', async () => {
  for (const failureClass of [
    'NONZERO',
    'WORKER_FAILURE_INPUT_READ',
    'INPUT_READ:/home/runner/private',
    'CODE_63',
    'container.246810',
    63,
    new String('INPUT_READ'),
    new Proxy(Object.freeze({ value: 'INPUT_READ' }), {}),
  ]) {
    await withFixture(async (fixture) => {
      const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
      assert.equal(result.code, 'SANDBOX_VALIDATION_FAILED');
      const evidenceBytes = await readFile(join(fixture.root, 'state/evidence', `${result.provenanceDigest}.json`));
      const provenance = JSON.parse(evidenceBytes.toString('utf8'));
      assert.deepEqual(provenance.securityEvents, ['WORKER_FAILED']);
      const diagnostic = authenticatedResultDiagnostic({ evidenceBytes, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result });
      assert.equal(diagnostic, 'none');
      assert.equal(evidenceBytes.includes(Buffer.from('/home/runner')), false);
      assert.equal(evidenceBytes.includes(Buffer.from('container.246810')), false);
      assert.equal(evidenceBytes.includes(Buffer.from('CODE_63')), false);
    }, { adapter: new FakeContainerAdapter({ failureClass, runKind: 'failed' }) });
  }
});

referenceStateTest('forced concurrent identical calls join one acquisition, container, validation, and commit', async () => {
  const gate = deferred();
  await withFixture(async (fixture) => {
    const job = fixture.jobFor();
    const first = fixture.service.run(job, fixture.acquisition);
    while (fixture.acquisitions === 0) await new Promise((resolve) => setImmediate(resolve));
    const second = fixture.service.run(job, fixture.acquisition);
    gate.resolve();
    const [left, right] = await Promise.all([first, second]);
    assert.deepEqual(left, right); assert.equal(left.code, 'VALIDATED');
    assert.equal(fixture.acquisitions, 1); assert.equal(fixture.adapter.runs, 1); assert.equal(fixture.adapter.collections, 1);
  }, { acquireGate: gate });
});

referenceStateTest('durable admission bounds distinct queued jobs without partial overflow state', async () => {
  const gate = deferred();
  await withFixture(async (fixture) => {
    const admitted = Array.from({ length: 64 }, (_, index) => fixture.service.run(fixture.jobFor(`queue.${index}`), fixture.acquisition));
    while (fixture.service.health().queueDepth !== 64) await new Promise((resolve) => setImmediate(resolve));
    const overflow = await fixture.service.run(fixture.jobFor('queue.overflow'), fixture.acquisition);
    assert.equal(overflow.code, 'SANDBOX_UNAVAILABLE');
    await assert.rejects(stat(join(fixture.root, 'state/jobs/job.queue.overflow.json')), (error) => error?.code === 'ENOENT');
    for (let index = 1; index < 64; index += 1) assert.equal(fixture.service.cancel(`job.queue.${index}`), true);
    gate.resolve();
    const results = await Promise.all(admitted);
    assert.equal(results.filter((result) => result.code === 'VALIDATED').length, 1);
    assert.equal(results.filter((result) => result.code === 'SANDBOX_CANCELLED').length, 63);
    assert.equal(fixture.service.health().queueDepth, 0);
    assert.equal(fixture.adapter.runs, 1);
  }, { acquireGate: gate });
});

referenceStateTest('revocation blocks new work, counts prior validated jobs, and frame tamper publishes nothing', async () => {
  await withFixture(async (fixture) => {
    const priorJob = fixture.jobFor('first');
    assert.equal((await fixture.service.run(priorJob, fixture.acquisition)).code, 'VALIDATED');
    const receipt = await fixture.service.revoke({ digest: fixture.jobFor().toolDigest, kind: 'tool', reasonCode: 'vulnerable.tool', throughGeneration: 1 });
    assert.equal(receipt.affectedCompletedJobs, 1);
    assert.equal((await fixture.service.run(priorJob, fixture.acquisition)).code, 'SANDBOX_REVOKED');
    await assert.rejects(stat(join(fixture.root, 'state/outputs/job.first')), (error) => error?.code === 'ENOENT');
    assert.equal((await readdir(join(fixture.root, 'state/quarantine'))).length, 1);
    const denied = await fixture.service.run(fixture.jobFor('second'), fixture.acquisition);
    assert.equal(denied.code, 'SANDBOX_REVOKED'); assert.equal(fixture.adapter.runs, 1);
  });
  await withFixture(async (fixture) => {
    const denied = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    assert.equal(denied.code, 'SANDBOX_VALIDATION_FAILED');
    await assert.rejects(stat(join(fixture.root, 'state/outputs/job.1')));
  }, { adapter: new FakeContainerAdapter({ tamper: 'terminal' }) });
});

referenceStateTest('cancellation and bounded failures leave the next job healthy', async () => {
  const gate = deferred(); const adapter = new FakeContainerAdapter({ gate });
  await withFixture(async (fixture) => {
    const pending = fixture.service.run(fixture.jobFor('cancelled'), fixture.acquisition);
    while (fixture.adapter.runs === 0) await new Promise((resolve) => setImmediate(resolve));
    assert.equal(fixture.service.cancel('job.cancelled'), true);
    assert.equal((await pending).code, 'SANDBOX_CANCELLED');
    gate.resolve(); fixture.adapter.gate = null;
    const clean = await fixture.service.run(fixture.jobFor('clean'), fixture.acquisition);
    assert.equal(clean.code, 'VALIDATED'); assert.equal(fixture.service.health().poisoned, false);
  }, { adapter });
});

referenceStateTest('state recovery denies interrupted work and output commit never replaces a prior bundle', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-sandbox-state-')); await chmod(root, 0o700);
  try {
    let store = await ReferenceStateStore.open(root);
    await store.writeJob({ fingerprint: 'a'.repeat(64), jobId: 'interrupted', schemaVersion: 'ogvcs.untrusted-sandbox/job-state/v1', securityEvents: [], state: 'running' });
    await store.close();
    store = await ReferenceStateStore.open(root);
    assert.deepEqual(await store.recoverInterrupted(Date.now()), ['interrupted']);
    assert.equal((await store.readJob('interrupted')).result.code, 'SANDBOX_UNAVAILABLE');
    const first = await store.createOutputTemporary('stable'); await writeFile(join(first, 'value'), 'first');
    await store.commitOutput('stable', first);
    await store.close();
    store = await ReferenceStateStore.open(root);
    assert.equal(await readFile(join(root, 'outputs/stable/bundle/value'), 'utf8'), 'first');
    const second = await store.createOutputTemporary('stable'); await writeFile(join(second, 'value'), 'second');
    await assert.rejects(store.commitOutput('stable', second), (error) => error?.code === 'EEXIST');
    assert.equal(await readFile(join(root, 'outputs/stable/bundle/value'), 'utf8'), 'first');
    await store.close();
  } finally { await rm(root, { recursive: true, force: true }); }
});

referenceStateTest('fault after durable output rename rolls back publication and records one denied result', async () => {
  await withFixture(async (fixture) => {
    const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    assert.equal(result.code, 'SANDBOX_UNAVAILABLE');
    await assert.rejects(stat(join(fixture.root, 'state/outputs/job.1')), (error) => error?.code === 'ENOENT');
    const record = JSON.parse(await readFile(join(fixture.root, 'state/jobs/job.1.json'), 'utf8'));
    assert.equal(record.state, 'denied');
    assert.equal(record.result.code, 'SANDBOX_UNAVAILABLE');
  }, { faults: new Set(['after-output-commit']) });
});

referenceStateTest('pre-start inspect mismatch publishes only a bounded field diagnostic and no output', async () => {
  await withFixture(async (fixture) => {
    const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    assert.equal(result.code, 'SANDBOX_UNAVAILABLE');
    const evidenceBytes = await readFile(join(fixture.root, 'state/evidence', `${result.provenanceDigest}.json`));
    const request = { evidenceBytes, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result };
    assert.equal(authenticatedResultDiagnostic(request), 'PRESTART_INSPECT_HOST_RUNTIME');
    const provenance = JSON.parse(evidenceBytes.toString('utf8'));
    for (const securityEvents of [
      ['PRESTART_INSPECT_HOST_RUNTIME'],
      ['PRESTART_INSPECT_HOST_RUNTIME', 'REFERENCE_INTERNAL_FAILURE', 'REFERENCE_INTERNAL_FAILURE'],
      ['PRESTART_INSPECT_RAW_HOST_PATH', 'REFERENCE_INTERNAL_FAILURE'],
      ['PRESTART_INSPECT_HOST_RUNTIME', 'SECRET=/home/runner/private'],
    ]) {
      const hostileBytes = authenticatedEvidenceBytes({ ...provenance, securityEvents }, fixture.evidenceHmacKey);
      assert.equal(authenticatedResultDiagnostic({ ...request, evidenceBytes: hostileBytes, result: { ...result, provenanceDigest: sha256(hostileBytes) } }), 'none');
    }
    const reports = (await Promise.all((await readdir(join(fixture.root, 'state/evidence'))).map((name) => readFile(join(fixture.root, 'state/evidence', name), 'utf8')))).join('\n');
    assert.match(reports, /PRESTART_INSPECT_HOST_RUNTIME/u);
    assert.equal(reports.includes(fixture.root), false);
    await assert.rejects(stat(join(fixture.root, 'state/outputs/job.1')), (error) => error?.code === 'ENOENT');
  }, { adapter: new FakeContainerAdapter({ inspectMismatch: 'host-runtime' }) });
  await withFixture(async (fixture) => {
    const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    assert.equal(result.code, 'SANDBOX_UNAVAILABLE');
    const evidenceBytes = await readFile(join(fixture.root, 'state/evidence', `${result.provenanceDigest}.json`));
    assert.equal(authenticatedResultDiagnostic({ evidenceBytes, evidenceHmacKey: fixture.evidenceHmacKey, evidenceKeyId: fixture.evidenceKeyId, result }), 'none');
    assert.equal(evidenceBytes.includes(Buffer.from('SECRET')), false);
    assert.equal(evidenceBytes.includes(Buffer.from('/home/runner')), false);
  }, { adapter: new FakeContainerAdapter({ inspectMismatch: 'host-runtime-SECRET-/home/runner' }) });
});

referenceStateTest('a durable terminal result replays exactly after restart even after its execution deadline', async () => {
  let nowUnixMs = Date.now();
  const clock = () => nowUnixMs;
  await withFixture(async (fixture) => {
    const job = fixture.jobFor('expired-replay', { deadlineUnixMs: nowUnixMs + 1_000 });
    const first = await fixture.service.run(job, fixture.acquisition);
    assert.equal(first.code, 'VALIDATED');
    const acquisitions = fixture.acquisitions;
    nowUnixMs += 2_000;
    await fixture.restart();
    assert.deepEqual(await fixture.service.run(job, fixture.acquisition), first);
    assert.equal(fixture.acquisitions, acquisitions);
    const freshExpired = fixture.jobFor('fresh-expired', { deadlineUnixMs: nowUnixMs - 1 });
    assert.equal((await fixture.service.run(freshExpired, fixture.acquisition)).code, 'SANDBOX_PROTOCOL_INVALID');
  }, { clock });
});

test('signed CPU policy admits only exact whole seconds from one through thirty', () => {
  const nowUnixMs = Date.now();
  const keys = generateKeyPairSync('ed25519');
  const toolDigest = '4'.repeat(64);
  const base = { cpuMilliseconds: 1_000, elapsedMilliseconds: 10_000, fanout: 16, memoryBytes: 64 * 1024 * 1024, outputBytes: 1024 * 1024, processes: 4, profileId: 'linux-reference-v1', scratchBytes: 2 * 1024 * 1024 };
  const trustedKeys = snapshotTrustedManifestKeys({ 'test.signer.1': keys.publicKey });
  for (const cpuMilliseconds of [1_000, 30_000]) {
    const manifest = makeManifest({ ...keys, nowUnixMs, resourcePolicy: Object.freeze({ ...base, cpuMilliseconds }), toolDigest });
    assert.notEqual(parseAndVerifyToolManifest({ manifestBytes: manifest.bytes, nowUnixMs, trustedKeys }), null);
  }
  for (const cpuMilliseconds of [1, 999, 1_001, 30_001]) {
    const manifest = makeManifest({ ...keys, nowUnixMs, resourcePolicy: Object.freeze({ ...base, cpuMilliseconds }), toolDigest });
    assert.equal(parseAndVerifyToolManifest({ manifestBytes: manifest.bytes, nowUnixMs, trustedKeys }), null);
  }
});

test('image admission rejects config, architecture, layer, label, and writable-volume substitutions', () => {
  const contract = LINUX_RUNTIME_CONTRACT_SHA256;
  const base = { Architecture: 'amd64', Config: { Cmd: null, Entrypoint: null, Env: null, ExposedPorts: null, Healthcheck: null, Labels: { 'org.opengamevcs.sandbox.runtime': 'linux-reference-v1', 'org.opengamevcs.sandbox.runtime-contract-sha256': contract }, User: '', Volumes: null, WorkingDir: '' }, Id: `sha256:${RUNTIME_DIGEST}`, Os: 'linux', RootFS: { Layers: ['sha256:layer'], Type: 'layers' }, Size: 1024 };
  assert.equal(validateRuntimeImageInspect(base, base.Id, contract), true);
  assert.equal(runtimeImageInspectMismatch(base, base.Id, contract), null);
  const omittedEmptyFields = structuredClone(base);
  for (const field of ['Cmd', 'Entrypoint', 'Env', 'ExposedPorts', 'Healthcheck', 'Volumes']) delete omittedEmptyFields.Config[field];
  assert.equal(validateRuntimeImageInspect(omittedEmptyFields, base.Id, contract), true);
  for (const [expected, mutate] of [
    ['identity', (value) => { value.Id = `sha256:${'f'.repeat(64)}`; }],
    ['platform', (value) => { value.Architecture = 'arm64'; }],
    ['rootfs', (value) => { value.RootFS.Layers.push('sha256:extra'); }],
    ['size', (value) => { value.Size = 0; }],
    ['inspect-shape', (value) => { value.Config = null; }],
    ['config-env', (value) => { value.Config.Env = ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']; }],
    ['config-command', (value) => { value.Config.Cmd = ['/bin/sh']; }],
    ['config-command', (value) => { value.Config.Entrypoint = ['/tool']; }],
    ['config-volume', (value) => { value.Config.Volumes = { '/data': {} }; }],
    ['config-health', (value) => { value.Config.Healthcheck = { Test: ['NONE'] }; }],
    ['config-command', (value) => { value.Config.ExposedPorts = { '80/tcp': {} }; }],
    ['config-user-workdir', (value) => { value.Config.User = '0'; }],
    ['config-user-workdir', (value) => { value.Config.WorkingDir = '/'; }],
    ['config-labels', (value) => { value.Config.Labels['extra'] = 'x'; }],
  ]) {
    const candidate = structuredClone(base); mutate(candidate);
    assert.equal(validateRuntimeImageInspect(candidate, base.Id, contract), false);
    assert.equal(runtimeImageInspectMismatch(candidate, base.Id, contract), expected);
  }
  assert.equal(runtimeImageInspectMismatch(new Proxy(base, { get() { throw new Error('SECRET=/host/path'); } }), base.Id, contract), 'inspect-shape');
});

referenceStateTest('runtime image admission brands only closed field mismatches and drops Docker details', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-image-admission-'));
  const contract = LINUX_RUNTIME_CONTRACT_SHA256;
  const base = { Architecture: 'amd64', Config: { Cmd: null, Entrypoint: null, Env: ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'], ExposedPorts: null, Healthcheck: null, Labels: { 'org.opengamevcs.sandbox.runtime': 'linux-reference-v1', 'org.opengamevcs.sandbox.runtime-contract-sha256': contract }, User: '', Volumes: null, WorkingDir: '' }, Id: `sha256:${RUNTIME_DIGEST}`, Os: 'linux', RootFS: { Layers: ['sha256:layer'], Type: 'layers' }, Size: 1024 };
  const executable = async (name, body) => {
    const path = join(root, name);
    await writeFile(path, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
    await chmod(path, 0o555);
    return path;
  };
  try {
    const mismatchBinary = await executable('docker-mismatch', `printf '%s' '${JSON.stringify([base])}'`);
    const mismatchAdapter = new DockerReferenceAdapter(mismatchBinary, '/not-consulted', 'e'.repeat(64), '{}');
    await assert.rejects(mismatchAdapter.verifyRuntimeImage(base.Id, contract), (error) => {
      assert.equal(error?.message, 'runtime image admission failed');
      assert.equal(prestartImageDiagnostic(error), 'PRESTART_IMAGE_CONFIG_ENV');
      assert.equal(String(error).includes('PATH='), false);
      return true;
    });

    const malformedBinary = await executable('docker-malformed', "printf '%s' '{\"SECRET\":\"/home/runner/private\"}'");
    const malformedAdapter = new DockerReferenceAdapter(malformedBinary, '/not-consulted', 'e'.repeat(64), '{}');
    await assert.rejects(malformedAdapter.verifyRuntimeImage(base.Id, contract), (error) => {
      assert.equal(error?.message, 'runtime image admission failed');
      assert.equal(prestartImageDiagnostic(error), 'PRESTART_IMAGE_INSPECT_SHAPE');
      assert.equal(String(error).includes('SECRET'), false);
      assert.equal(String(error).includes('/home/runner'), false);
      return true;
    });

    const controlBinary = await executable('docker-control', "printf '%s' 'SECRET=/home/runner/private' >&2\nexit 7");
    const controlAdapter = new DockerReferenceAdapter(controlBinary, '/not-consulted', 'e'.repeat(64), '{}');
    await assert.rejects(controlAdapter.verifyRuntimeImage(base.Id, contract), (error) => {
      assert.equal(error?.message, 'runtime image admission failed');
      assert.equal(prestartImageDiagnostic(error), null);
      assert.equal(String(error).includes('SECRET'), false);
      assert.equal(String(error).includes('/home/runner'), false);
      return true;
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('pre-start inspection binds every role mount and effective isolation control', () => {
  const policy = { cpuMilliseconds: 1_000, memoryBytes: 64 * 1024 * 1024, outputBytes: 2 * 1024 * 1024, processes: 4, scratchBytes: 2 * 1024 * 1024 };
  const seccomp = canonicalJson({ defaultAction: 'SCMP_ACT_ERRNO', syscalls: [] });
  const expected = {
    entrypoint: '/tool/program',
    fileMounts: [
      { source: '/proc/123/fd/10', target: '/input/payload' },
      { source: '/proc/123/fd/11', target: '/input/job' },
      { source: '/proc/123/fd/12', target: '/tool/program' },
    ],
    id: '1'.repeat(64), jobId: 'job.fixture', name: 'ogvcs-sandbox-fixture', outputReadonly: false, policy, role: 'parser',
    runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256, runtimeImage: `sha256:${RUNTIME_DIGEST}`, seccompCanonical: seccomp, volume: 'ogvcs-sandbox-volume', volumeMountpoint: '/var/lib/docker/volumes/fixture/_data',
  };
  const hostMounts = expected.fileMounts.map((mount) => ({ BindOptions: { Propagation: 'rprivate', ReadOnlyNonRecursive: true }, ReadOnly: true, Source: mount.source, Target: mount.target, Type: 'bind' }));
  hostMounts.push({ Source: expected.volume, Target: '/output', Type: 'volume', VolumeOptions: { NoCopy: true } });
  const effectiveMounts = expected.fileMounts.map((mount) => ({ Destination: mount.target, Mode: 'ro', Propagation: 'rprivate', RW: false, Source: mount.source, Type: 'bind' }));
  effectiveMounts.push({ Destination: '/output', Driver: 'local', Mode: 'z', Name: expected.volume, Propagation: '', RW: true, Source: expected.volumeMountpoint, Type: 'volume' });
  const container = {
    Args: [], Config: { Cmd: null, Domainname: '', Entrypoint: ['/tool/program'], Env: null, ExposedPorts: null, Healthcheck: null, Hostname: 'ogvcs-worker', Image: expected.runtimeImage, Labels: { 'org.opengamevcs.sandbox.job': expected.jobId, 'org.opengamevcs.sandbox.role': expected.role, 'org.opengamevcs.sandbox.runtime': 'linux-reference-v1', 'org.opengamevcs.sandbox.runtime-contract-sha256': LINUX_RUNTIME_CONTRACT_SHA256 }, OpenStdin: false, StdinOnce: false, StopTimeout: 1, Tty: false, User: '65532:65532', Volumes: null, WorkingDir: '/scratch' },
    HostConfig: { AutoRemove: false, Binds: null, CapAdd: null, CapDrop: ['ALL'], CgroupnsMode: 'private', CpuPeriod: 0, CpuQuota: 0, CpuShares: 0, DeviceCgroupRules: null, DeviceRequests: null, Devices: null, Dns: null, DnsOptions: null, DnsSearch: null, ExtraHosts: null, GroupAdd: null, Init: null, IpcMode: 'none', Links: null, LogConfig: { Config: {}, Type: 'none' }, MaskedPaths: ['/proc/acpi', '/proc/asound', '/proc/interrupts', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/sched_debug', '/proc/scsi', '/proc/timer_list', '/proc/timer_stats', '/sys/firmware'], Memory: policy.memoryBytes, MemoryReservation: 0, MemorySwap: policy.memoryBytes, Mounts: hostMounts, NanoCpus: 1_000_000_000, NetworkMode: 'none', OomKillDisable: false, PidMode: '', PidsLimit: policy.processes, PortBindings: {}, Privileged: false, PublishAllPorts: false, ReadonlyPaths: ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'], ReadonlyRootfs: true, RestartPolicy: { MaximumRetryCount: 0, Name: 'no' }, Runtime: 'runc', SecurityOpt: ['no-new-privileges=true', `seccomp=${seccomp}`], Sysctls: null, Tmpfs: { '/scratch': `rw,nosuid,nodev,noexec,size=${policy.scratchBytes},uid=65532,gid=65532,mode=0700` }, UsernsMode: '', UTSMode: '', Ulimits: [{ Hard: 1, Name: 'cpu', Soft: 1 }, { Hard: policy.outputBytes, Name: 'fsize', Soft: policy.outputBytes }, { Hard: 64, Name: 'nofile', Soft: 64 }], VolumesFrom: null },
    Id: expected.id, Mounts: effectiveMounts, Name: `/${expected.name}`, NetworkSettings: { Networks: { none: {} } }, Path: '/tool/program', State: { Paused: false, Pid: 0, Restarting: false, Running: false, Status: 'created' },
  };
  assert.equal(validateCreatedContainerInspect(container, expected), true);
  const legacyExplicitNetworkDisabled = structuredClone(container);
  legacyExplicitNetworkDisabled.Config.NetworkDisabled = false;
  assert.equal(validateCreatedContainerInspect(legacyExplicitNetworkDisabled, expected), true);
  const legacyExplicitWritableMount = structuredClone(container);
  Object.assign(legacyExplicitWritableMount.HostConfig.Mounts.at(-1), { Consistency: '', ReadOnly: false });
  Object.assign(legacyExplicitWritableMount.HostConfig.Mounts.at(-1).VolumeOptions, { DriverConfig: null, Labels: null, Subpath: '' });
  for (const mount of legacyExplicitWritableMount.HostConfig.Mounts.slice(0, -1)) {
    mount.Consistency = 'default';
    Object.assign(mount.BindOptions, { CreateMountpoint: false, NonRecursive: false, ReadOnlyForceRecursive: false, ReadOnlyNonRecursive: true });
  }
  assert.equal(validateCreatedContainerInspect(legacyExplicitWritableMount, expected), true);
  const legacyOmittedEffectiveModes = structuredClone(container);
  for (const mount of legacyOmittedEffectiveModes.Mounts) delete mount.Mode;
  delete legacyOmittedEffectiveModes.Mounts.at(-1).Propagation;
  assert.equal(validateCreatedContainerInspect(legacyOmittedEffectiveModes, expected), true);
  const legacyEmptyEffectiveModes = structuredClone(container);
  for (const mount of legacyEmptyEffectiveModes.Mounts) mount.Mode = '';
  for (const mount of legacyEmptyEffectiveModes.Mounts.slice(0, -1)) Object.assign(mount, { Driver: '', Name: '' });
  assert.equal(validateCreatedContainerInspect(legacyEmptyEffectiveModes, expected), true);
  const detached = structuredClone(container); detached.NetworkSettings.Networks = {};
  assert.equal(validateCreatedContainerInspect(detached, expected), true);
  for (const mutate of [
    (value) => { value.State.Running = true; },
    (value) => { value.HostConfig.NetworkMode = 'bridge'; },
    (value) => { value.NetworkSettings.Networks = { bridge: {} }; },
    (value) => { value.HostConfig.ReadonlyRootfs = false; },
    (value) => { value.HostConfig.ReadonlyPaths.splice(0, 1); },
    (value) => { value.HostConfig.MaskedPaths.splice(0, 1); },
    (value) => { value.HostConfig.CapDrop = []; },
    (value) => { value.HostConfig.SecurityOpt[1] = 'seccomp={"defaultAction":"SCMP_ACT_ALLOW"}'; },
    (value) => { value.HostConfig.SecurityOpt.push('no-new-privileges=true'); },
    (value) => { value.HostConfig.CgroupnsMode = 'host'; },
    (value) => { value.HostConfig.IpcMode = 'host'; },
    (value) => { value.HostConfig.UsernsMode = 'host'; },
    (value) => { value.HostConfig.Runtime = 'io.containerd.alt.v2'; },
    (value) => { value.HostConfig.OomKillDisable = true; },
    (value) => { value.HostConfig.Init = true; },
    (value) => { value.Config.User = '0:0'; },
    (value) => { value.HostConfig.Privileged = true; },
    (value) => { value.HostConfig.Devices = [{ PathOnHost: '/dev/null' }]; },
    (value) => { value.HostConfig.PortBindings = { '80/tcp': [{ HostPort: '80' }] }; },
    (value) => { value.HostConfig.RestartPolicy.Name = 'always'; },
    (value) => { value.HostConfig.Memory += 1; },
    (value) => { value.HostConfig.MemorySwap += 1; },
    (value) => { value.HostConfig.PidsLimit += 1; },
    (value) => { value.HostConfig.NanoCpus = 0; },
    (value) => { value.HostConfig.Ulimits[0].Hard += 1; },
    (value) => { value.HostConfig.Tmpfs['/scratch'] = 'rw'; },
    (value) => { value.HostConfig.Mounts[0].Type = 'volume'; },
    (value) => { value.HostConfig.Mounts[0].Target = '/input/substitution'; },
    (value) => { value.HostConfig.Mounts[0].Source = '/tmp/substitution'; },
    (value) => { value.HostConfig.Mounts[0].ReadOnly = false; },
    (value) => { value.HostConfig.Mounts[0].Consistency = 'cached'; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.Propagation = 'rshared'; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.NonRecursive = true; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.NonRecursive = null; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.CreateMountpoint = true; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.CreateMountpoint = null; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.ReadOnlyNonRecursive = false; },
    (value) => { delete value.HostConfig.Mounts[0].BindOptions.ReadOnlyNonRecursive; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.ReadOnlyForceRecursive = true; },
    (value) => { value.HostConfig.Mounts[0].BindOptions.ReadOnlyForceRecursive = null; },
    (value) => { value.Mounts[0].Propagation = 'rshared'; },
    (value) => { value.HostConfig.Mounts.at(-1).Type = 'bind'; },
    (value) => { value.HostConfig.Mounts.at(-1).Target = '/output/substitution'; },
    (value) => { value.HostConfig.Mounts.at(-1).Source = 'ogvcs-sandbox-substitution'; },
    (value) => { value.HostConfig.Mounts.at(-1).ReadOnly = true; },
    (value) => { value.HostConfig.Mounts.at(-1).Consistency = 'cached'; },
    (value) => { value.HostConfig.Mounts.at(-1).VolumeOptions.NoCopy = false; },
    (value) => { delete value.HostConfig.Mounts.at(-1).VolumeOptions; },
    (value) => { value.HostConfig.Mounts.at(-1).VolumeOptions.Labels = { extra: 'x' }; },
    (value) => { value.HostConfig.Mounts.at(-1).VolumeOptions.DriverConfig = { Name: 'other', Options: {} }; },
    (value) => { value.HostConfig.Mounts.at(-1).VolumeOptions.Subpath = 'nested'; },
    (value) => { value.Mounts.push({ Destination: '/extra', RW: true, Type: 'bind' }); },
    (value) => { value.Mounts.at(-1).RW = false; },
    (value) => { value.Mounts.at(-1).Name = 'ogvcs-sandbox-substitution'; },
    (value) => { value.Mounts.at(-1).Driver = 'bind'; },
    (value) => { value.Mounts.at(-1).Source = '/var/lib/docker/volumes/substitution/_data'; },
    (value) => { value.Config.Env = ['SECRET=x']; },
    (value) => { value.Config.Entrypoint = ['/bin/sh']; },
    (value) => { value.Config.Labels['org.opengamevcs.sandbox.job'] = 'job.substituted'; },
    (value) => { value.Config.Labels['org.opengamevcs.sandbox.role'] = 'output-shim'; },
  ]) {
    const candidate = structuredClone(container); mutate(candidate);
    assert.equal(validateCreatedContainerInspect(candidate, expected), false);
  }
  const runtimeMismatch = structuredClone(container); runtimeMismatch.HostConfig.Runtime = 'io.containerd.alt.v2';
  assert.equal(createdContainerInspectMismatch(runtimeMismatch, expected), 'host-runtime');
  for (const hostile of [true, null, 0, 'false']) {
    const hostileWritableMount = structuredClone(container); hostileWritableMount.HostConfig.Mounts.at(-1).ReadOnly = hostile;
    assert.equal(createdContainerInspectMismatch(hostileWritableMount, expected), 'host-mounts', `output ReadOnly=${String(hostile)}`);
  }
  for (const [field, hostile] of [
    ['OpenStdin', true],
    ['StdinOnce', true],
    ['Tty', true],
    ['StopTimeout', 0],
    ['StopTimeout', 2],
    ['StopTimeout', null],
    ['StopTimeout', '1'],
    ['NetworkDisabled', true],
    ['NetworkDisabled', null],
    ['NetworkDisabled', 0],
    ['NetworkDisabled', 'false'],
  ]) {
    const hostileIo = structuredClone(container); hostileIo.Config[field] = hostile;
    assert.equal(createdContainerInspectMismatch(hostileIo, expected), 'config-io', `${field}=${String(hostile)}`);
  }
  for (const field of ['OpenStdin', 'StdinOnce', 'StopTimeout', 'Tty']) {
    const omittedIo = structuredClone(container); delete omittedIo.Config[field];
    assert.equal(createdContainerInspectMismatch(omittedIo, expected), 'config-io', `omitted ${field}`);
  }
  for (const pidMode of ['private', 'host', `container:${'a'.repeat(64)}`]) {
    const sharedOrInvalidPid = structuredClone(container); sharedOrInvalidPid.HostConfig.PidMode = pidMode;
    assert.equal(createdContainerInspectMismatch(sharedOrInvalidPid, expected), 'host-namespaces', pidMode);
  }
  const shimExpected = { ...expected, entrypoint: '/ogvcs-output-shim', fileMounts: [{ source: '/proc/123/fd/13', target: '/input/binding' }], outputReadonly: true, role: 'output-shim' };
  const shim = structuredClone(container);
  shim.Path = shimExpected.entrypoint;
  shim.Config.Entrypoint = [shimExpected.entrypoint];
  shim.Config.Labels['org.opengamevcs.sandbox.role'] = shimExpected.role;
  shim.HostConfig.Mounts = [{ BindOptions: { Propagation: 'rprivate', ReadOnlyNonRecursive: true }, ReadOnly: true, Source: shimExpected.fileMounts[0].source, Target: shimExpected.fileMounts[0].target, Type: 'bind' }, { ReadOnly: true, Source: expected.volume, Target: '/output', Type: 'volume', VolumeOptions: { NoCopy: true } }];
  shim.Mounts = [{ Destination: shimExpected.fileMounts[0].target, Mode: 'ro', Propagation: 'rprivate', RW: false, Source: shimExpected.fileMounts[0].source, Type: 'bind' }, { Destination: '/output', Driver: 'local', Mode: 'z', Name: expected.volume, Propagation: '', RW: false, Source: expected.volumeMountpoint, Type: 'volume' }];
  assert.equal(validateCreatedContainerInspect(shim, shimExpected), true);
  const legacyShimEffectiveMounts = structuredClone(shim);
  for (const mount of legacyShimEffectiveMounts.Mounts) delete mount.Mode;
  delete legacyShimEffectiveMounts.Mounts.at(-1).Propagation;
  assert.equal(validateCreatedContainerInspect(legacyShimEffectiveMounts, shimExpected), true);
  const assertEffectiveMountRejected = (base, roleExpected, label, mutate) => {
    const candidate = structuredClone(base);
    mutate(candidate, roleExpected);
    assert.equal(createdContainerInspectMismatch(candidate, roleExpected), 'effective-mounts', `${roleExpected.role}: ${label}`);
  };
  const hostileEffectiveMountMutations = [
    ['bind type', (value) => { value.Mounts[0].Type = 'volume'; }],
    ['bind source', (value) => { value.Mounts[0].Source = '/proc/123/fd/99'; }],
    ['bind destination', (value) => { value.Mounts[0].Destination = '/input/substitution'; }],
    ['bind writable', (value) => { value.Mounts[0].RW = true; }],
    ['bind propagation empty', (value) => { value.Mounts[0].Propagation = ''; }],
    ['bind propagation shared', (value) => { value.Mounts[0].Propagation = 'rshared'; }],
    ['bind mode writable', (value) => { value.Mounts[0].Mode = 'rw'; }],
    ['bind mode volume-label', (value) => { value.Mounts[0].Mode = 'z'; }],
    ['bind mode null', (value) => { value.Mounts[0].Mode = null; }],
    ['bind volume name', (value) => { value.Mounts[0].Name = 'ogvcs-sandbox-substitution'; }],
    ['bind volume driver', (value) => { value.Mounts[0].Driver = 'local'; }],
    ['output type', (value) => { value.Mounts.at(-1).Type = 'bind'; }],
    ['output source', (value) => { value.Mounts.at(-1).Source = '/var/lib/docker/volumes/substitution/_data'; }],
    ['output destination', (value) => { value.Mounts.at(-1).Destination = '/output/substitution'; }],
    ['output access', (value, roleExpected) => { value.Mounts.at(-1).RW = roleExpected.outputReadonly; }],
    ['output propagation private', (value) => { value.Mounts.at(-1).Propagation = 'rprivate'; }],
    ['output propagation null', (value) => { value.Mounts.at(-1).Propagation = null; }],
    ['output mode writable', (value) => { value.Mounts.at(-1).Mode = 'rw'; }],
    ['output mode readonly', (value) => { value.Mounts.at(-1).Mode = 'ro'; }],
    ['output mode null', (value) => { value.Mounts.at(-1).Mode = null; }],
    ['output name', (value) => { value.Mounts.at(-1).Name = 'ogvcs-sandbox-substitution'; }],
    ['output name missing', (value) => { delete value.Mounts.at(-1).Name; }],
    ['output driver', (value) => { value.Mounts.at(-1).Driver = 'bind'; }],
    ['output driver missing', (value) => { delete value.Mounts.at(-1).Driver; }],
  ];
  for (const [label, mutate] of hostileEffectiveMountMutations) {
    assertEffectiveMountRejected(container, expected, label, mutate);
    assertEffectiveMountRejected(shim, shimExpected, label, mutate);
  }
  for (const hostile of [undefined, false, null, 1, 'true']) {
    const hostileShimMount = structuredClone(shim);
    if (hostile === undefined) delete hostileShimMount.HostConfig.Mounts.at(-1).ReadOnly;
    else hostileShimMount.HostConfig.Mounts.at(-1).ReadOnly = hostile;
    assert.equal(createdContainerInspectMismatch(hostileShimMount, shimExpected), 'host-mounts', `shim ReadOnly=${String(hostile)}`);
  }
  const volume = { Driver: 'local', Labels: { 'org.opengamevcs.sandbox': 'reference-v1', 'org.opengamevcs.sandbox.job': expected.jobId, 'org.opengamevcs.sandbox.role': 'output-volume' }, Mountpoint: '/var/lib/docker/volumes/fixture/_data', Name: expected.volume, Options: { device: 'tmpfs', o: 'size=1,uid=65532,gid=65532,mode=0700,nosuid,nodev,noexec', type: 'tmpfs' }, Scope: 'local' };
  assert.equal(validateOutputVolumeInspect(volume, expected.volume, volume.Options.o, expected.jobId), true);
  assert.equal(validateOutputVolumeInspect({ ...volume, Driver: 'bind' }, expected.volume, volume.Options.o, expected.jobId), false);
  assert.equal(validateOutputVolumeInspect({ ...volume, Options: { ...volume.Options, o: 'size=2' } }, expected.volume, volume.Options.o, expected.jobId), false);
  assert.equal(validateOutputVolumeInspect({ ...volume, Labels: { ...volume.Labels, 'org.opengamevcs.sandbox.job': 'job.substituted' } }, expected.volume, volume.Options.o, expected.jobId), false);
});
