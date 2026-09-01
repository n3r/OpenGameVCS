import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { chmod, mkdtemp, mkdir, open, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { validateRuntimeImageInspect } from '../src/internal/docker-reference.mjs';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, sha256 } from '../src/internal/reference-contract.mjs';
import { ReferenceSandboxService } from '../src/internal/reference-service.mjs';
import { ReferenceStateStore } from '../src/internal/reference-state.mjs';
import * as linuxBoundary from '../src/linux.mjs';

const MAGIC = Buffer.from([0x4f, 0x47, 0x56, 0x43, 0x53, 0x42, 0x31, 0x00]);
const RUNTIME_DIGEST = 'b'.repeat(64);
const SECCOMP_DIGEST = 'e'.repeat(64);
const ACTOR_DIGEST = 'a'.repeat(64);
const OPTIONS_DIGEST = 'c'.repeat(64);
const OBJECT_ID_DIGEST = 'd'.repeat(64);

test('Linux reference export remains candidate-named until live controls are verified', () => {
  assert.equal(Object.hasOwn(linuxBoundary, 'openLinuxReferenceSandbox'), false);
  assert.equal(typeof linuxBoundary.openLinuxReferenceSandboxCandidate, 'function');
  assert.equal(typeof linuxBoundary.probeLinuxReferenceSandbox, 'function');
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

class FakeContainerAdapter {
  constructor({ gate = null, tamper = null } = {}) { this.seccompDigest = SECCOMP_DIGEST; this.gate = gate; this.tamper = tamper; this.runs = 0; this.collections = 0; this.discards = 0; this.parserSawBinding = false; this.modes = []; }
  async verifyRuntimeImage(image, contract) { return image === `sha256:${RUNTIME_DIGEST}` && contract === LINUX_RUNTIME_CONTRACT_SHA256; }
  async runTool({ inputHandle, jobHandle, toolHandle, signal }) {
    this.runs += 1;
    this.parserSawBinding ||= Object.keys(arguments[0]).includes('bindingHandle');
    this.modes.push((await inputHandle.stat()).mode & 0o777, (await jobHandle.stat()).mode & 0o777, (await toolHandle.stat()).mode & 0o777);
    const command = (await readHandle(inputHandle)).toString('utf8');
    if (this.gate && !signal.aborted) await Promise.race([this.gate.promise, new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }))]);
    if (signal.aborted) return Object.freeze({ kind: 'cancelled', volume: `volume.${this.runs}` });
    if (command === 'timeout') return Object.freeze({ kind: 'timeout', volume: `volume.${this.runs}` });
    const path = command === 'converter' ? 'preview/result' : 'import/result';
    return Object.freeze({ kind: 'success', volume: Object.freeze({ files: Object.freeze([{ content: Buffer.from(command), path }]) }) });
  }
  async collectOutput({ volume, bindingHandle, framePath }) {
    this.collections += 1; const binding = (await readHandle(bindingHandle)).toString('ascii');
    await writeFile(framePath, outputFrame(binding, volume.files, this.tamper), { flag: 'wx', mode: 0o600 });
    return Object.freeze({ frameBytes: (await stat(framePath)).size, kind: 'success' });
  }
  async discardVolume() { this.discards += 1; }
}

const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };

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

const withFixture = async (operation, { adapter = new FakeContainerAdapter(), faults = null, acquireGate = null } = {}) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-sandbox-reference-')); await chmod(root, 0o700);
  const toolPath = join(root, 'dummy-tool'); await writeFile(toolPath, Buffer.from('dummy-tool-v1'), { mode: 0o555 }); await chmod(toolPath, 0o555);
  const toolDigest = sha256(await readFile(toolPath));
  const nowUnixMs = Date.now();
  const keys = generateKeyPairSync('ed25519');
  const manifest = makeManifest({ ...keys, nowUnixMs, toolDigest });
  let acquisitions = 0; let credentialObserved = false;
  const source = Object.freeze({
    acquire: async ({ credential }) => { acquisitions += 1; credentialObserved ||= credential === 'broker-secret-canary'; if (acquireGate) await acquireGate.promise; return Buffer.from('importer'); },
    credential: 'broker-secret-canary', maximumBytes: 1024, sourceId: 'fixture.source',
  });
  const service = await ReferenceSandboxService.open({
    acquisitionSources: [source], adapter, evidenceHmacKey: Buffer.alloc(32, 0x5a), evidenceHmacKeyId: 'test.evidence.1', faults,
    manifestCatalog: [{ manifestBytes: manifest.bytes, toolPath }], stateRoot: join(root, 'state'), trustedManifestKeys: { 'test.signer.1': keys.publicKey },
  });
  const jobFor = (suffix = '1', overrides = {}) => Object.freeze({
    actorDigest: ACTOR_DIGEST, deadlineUnixMs: Date.now() + 9_000, idempotencyKey: `idempotency.${suffix}`, inputDigest: sha256(Buffer.from('importer')), jobId: `job.${suffix}`, manifestDigest: manifest.digest, optionsDigest: OPTIONS_DIGEST,
    outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1', purpose: 'conformance', resourcePolicyDigest: manifest.policyDigest, runtimeDigest: RUNTIME_DIGEST, schemaVersion: 'ogvcs.untrusted-sandbox/reference-job/v1', toolDigest, ...overrides,
  });
  const acquisition = Object.freeze({ maximumBytes: 1024, objectIdDigest: OBJECT_ID_DIGEST, schemaVersion: 'ogvcs.untrusted-sandbox/acquisition-request/v1', sourceId: 'fixture.source' });
  try { return await operation({ acquisition, adapter, get acquisitions() { return acquisitions; }, get credentialObserved() { return credentialObserved; }, jobFor, manifest, root, service }); }
  finally { await service.close().catch(() => {}); await rm(root, { recursive: true, force: true }); }
};

test('signed manifest, credential-free held-FD mounts, frame channel, provenance, and idempotency are exact', async () => {
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

test('forced concurrent identical calls join one acquisition, container, validation, and commit', async () => {
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

test('durable admission bounds distinct queued jobs without partial overflow state', async () => {
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

test('revocation blocks new work, counts prior validated jobs, and frame tamper publishes nothing', async () => {
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

test('cancellation and bounded failures leave the next job healthy', async () => {
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

test('state recovery denies interrupted work and output commit never replaces a prior bundle', async () => {
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

test('fault after durable output rename rolls back publication and records one denied result', async () => {
  await withFixture(async (fixture) => {
    const result = await fixture.service.run(fixture.jobFor(), fixture.acquisition);
    assert.equal(result.code, 'SANDBOX_UNAVAILABLE');
    await assert.rejects(stat(join(fixture.root, 'state/outputs/job.1')), (error) => error?.code === 'ENOENT');
    const record = JSON.parse(await readFile(join(fixture.root, 'state/jobs/job.1.json'), 'utf8'));
    assert.equal(record.state, 'denied');
    assert.equal(record.result.code, 'SANDBOX_UNAVAILABLE');
  }, { faults: new Set(['after-output-commit']) });
});

test('image admission rejects config, architecture, layer, label, and writable-volume substitutions', () => {
  const contract = LINUX_RUNTIME_CONTRACT_SHA256;
  const base = { Architecture: 'amd64', Config: { Cmd: null, Entrypoint: null, Env: null, ExposedPorts: null, Healthcheck: null, Labels: { 'org.opengamevcs.sandbox.runtime': 'linux-reference-v1', 'org.opengamevcs.sandbox.runtime-contract-sha256': contract }, User: '', Volumes: null, WorkingDir: '' }, Id: `sha256:${RUNTIME_DIGEST}`, Os: 'linux', RootFS: { Layers: ['sha256:layer'], Type: 'layers' }, Size: 1024 };
  assert.equal(validateRuntimeImageInspect(base, base.Id, contract), true);
  for (const mutate of [
    (value) => { value.Architecture = 'arm64'; },
    (value) => { value.Config.Env = ['SECRET=x']; },
    (value) => { value.Config.Cmd = ['/bin/sh']; },
    (value) => { value.Config.Entrypoint = ['/tool']; },
    (value) => { value.Config.Volumes = { '/data': {} }; },
    (value) => { value.Config.Healthcheck = { Test: ['NONE'] }; },
    (value) => { value.RootFS.Layers.push('sha256:extra'); },
    (value) => { value.Config.Labels['extra'] = 'x'; },
  ]) {
    const candidate = structuredClone(base); mutate(candidate);
    assert.equal(validateRuntimeImageInspect(candidate, base.Id, contract), false);
  }
});
