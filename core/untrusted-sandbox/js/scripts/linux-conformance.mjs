import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { chmod, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { LinuxReferenceUnavailableError, openLinuxReferenceSandboxCandidate, probeLinuxReferenceSandbox } from '../src/linux.mjs';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, sha256 } from '../src/internal/reference-contract.mjs';
import { authenticatedResultDiagnostic } from '../src/internal/reference-service.mjs';

const runtimeImage = process.env.OGVCS_SANDBOX_RUNTIME_IMAGE;
const dockerBinary = process.env.OGVCS_DOCKER_BINARY;
const toolPath = process.env.OGVCS_SANDBOX_CANARY_TOOL;
if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('live reference conformance requires Linux x86_64');
if (!/^sha256:[0-9a-f]{64}$/u.test(runtimeImage ?? '') || !isAbsolute(dockerBinary ?? '') || !isAbsolute(toolPath ?? '')) throw new Error('live reference conformance inputs are invalid');

const root = await mkdtemp(join(tmpdir(), 'ogvcs-linux-reference-'));
await chmod(root, 0o700);
const canonicalRoot = await realpath(root);
const stateRoot = join(canonicalRoot, 'state');
const nowUnixMs = Date.now();
const keys = generateKeyPairSync('ed25519');
const toolBytes = await readFile(toolPath);
const toolDigest = sha256(toolBytes);
const runtimeDigest = runtimeImage.slice('sha256:'.length);
const policy = Object.freeze({
  cpuMilliseconds: 1_000,
  elapsedMilliseconds: 5_000,
  fanout: 16,
  memoryBytes: 64 * 1024 * 1024,
  outputBytes: 2 * 1024 * 1024,
  processes: 4,
  profileId: 'linux-reference-v1',
  scratchBytes: 2 * 1024 * 1024,
});
const resourcePolicyDigest = sha256(Buffer.from(canonicalJson(policy), 'utf8'));

const signedManifest = (toolClass) => {
  const unsigned = Object.freeze({
    expiresAtUnixMs: nowUnixMs + 30 * 60 * 1_000,
    generation: 1,
    issuedAtUnixMs: nowUnixMs - 1_000,
    manifestId: `ogvcs.conformance.${toolClass}.v1`,
    outputPolicy: Object.freeze({ allowedTypes: Object.freeze(['conformance.record']), maximumFileBytes: 256 * 1024, schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' }),
    resourcePolicy: policy,
    runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256,
    runtimeDigest,
    runtimeImage,
    schemaVersion: 'ogvcs.untrusted-sandbox/tool-runtime-manifest/v1',
    signingKeyId: 'ogvcs.conformance.ephemeral.1',
    toolClass,
    toolDigest,
  });
  const signatureEd25519 = sign(null, Buffer.from(canonicalJson(unsigned), 'utf8'), keys.privateKey).toString('base64url');
  const bytes = Buffer.from(canonicalJson({ ...unsigned, signatureEd25519 }), 'utf8');
  return Object.freeze({ bytes, digest: sha256(bytes) });
};

const manifests = Object.freeze({ converter: signedManifest('converter'), importer: signedManifest('import-parser') });
const payloads = new Map();
const credential = `broker-secret-canary-${randomBytes(12).toString('hex')}`;
const evidenceHmacKey = randomBytes(32);
const evidenceKeyId = 'ogvcs.conformance.evidence.1';
let acquisitions = 0;
const source = Object.freeze({
  acquire: async ({ credential: presented, objectIdDigest }) => {
    acquisitions += 1;
    if (presented !== credential || !payloads.has(objectIdDigest)) throw new Error('acquisition authority differs');
    return Buffer.from(payloads.get(objectIdDigest));
  },
  credential,
  maximumBytes: 64,
  sourceId: 'ogvcs.conformance.source.1',
});
const configuration = Object.freeze({
  acquisitionSources: Object.freeze([source]),
  dockerBinary,
  evidenceHmacKey,
  evidenceHmacKeyId: evidenceKeyId,
  manifestCatalog: Object.freeze([
    Object.freeze({ manifestBytes: manifests.importer.bytes, toolPath }),
    Object.freeze({ manifestBytes: manifests.converter.bytes, toolPath }),
  ]),
  stateRoot,
  trustedManifestKeys: Object.freeze({ 'ogvcs.conformance.ephemeral.1': keys.publicKey }),
});

const probe = await probeLinuxReferenceSandbox({ dockerBinary });
assert.deepEqual(probe.available, true, 'required Docker/cgroup/seccomp controls must be admitted');

let serial = 0;
const descriptorFor = (command, { toolClass = 'importer', suffix = null } = {}) => {
  serial += 1;
  const bytes = Buffer.from(command, 'utf8');
  const inputDigest = sha256(bytes);
  payloads.set(inputDigest, bytes);
  const token = suffix ?? `${String(serial).padStart(3, '0')}.${command}`;
  const manifest = manifests[toolClass];
  return Object.freeze({
    acquisition: Object.freeze({ maximumBytes: 64, objectIdDigest: inputDigest, schemaVersion: 'ogvcs.untrusted-sandbox/acquisition-request/v1', sourceId: source.sourceId }),
    command,
    job: Object.freeze({
      actorDigest: 'a'.repeat(64),
      deadlineUnixMs: Date.now() + policy.elapsedMilliseconds,
      idempotencyKey: `linux.${token}`,
      inputDigest,
      jobId: `linux.${token}`,
      manifestDigest: manifest.digest,
      optionsDigest: 'b'.repeat(64),
      outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1',
      purpose: 'hostile-reference-conformance',
      resourcePolicyDigest,
      runtimeDigest,
      schemaVersion: 'ogvcs.untrusted-sandbox/reference-job/v1',
      toolDigest,
    }),
  });
};

const outputExpectation = Object.freeze({
  'clone-namespace': Object.freeze({ content: 'denied', path: 'evidence/clone-namespace' }),
  'clone3-namespace': Object.freeze({ content: 'denied', path: 'evidence/clone3-namespace' }),
  converter: Object.freeze({ content: 'dummy-convert', path: 'preview/result' }),
  credential: Object.freeze({ content: 'absent', path: 'evidence/credential' }),
  device: Object.freeze({ content: 'denied', path: 'evidence/device' }),
  host: Object.freeze({ content: 'absent', path: 'evidence/host' }),
  importer: Object.freeze({ content: 'dummy-import', path: 'import/result' }),
  namespace: Object.freeze({ content: 'denied', path: 'evidence/namespace' }),
  network: Object.freeze({ content: 'denied', path: 'evidence/network' }),
  sibling: Object.freeze({ content: 'absent', path: 'evidence/host' }),
  traversal: Object.freeze({ content: 'denied', path: 'evidence/traversal' }),
  undeclared: Object.freeze({ content: 'absent', path: 'evidence/host' }),
});

const readOutput = async (jobId, expected) => {
  const value = await readFile(join(stateRoot, 'outputs', jobId, 'bundle', expected.path), 'utf8');
  assert.equal(value, expected.content);
};

const assertNoOutput = async (jobId) => {
  await assert.rejects(stat(join(stateRoot, 'outputs', jobId)), (error) => error?.code === 'ENOENT');
};

const safeResultDiagnostic = async (result) => {
  if (!/^[0-9a-f]{64}$/u.test(result?.provenanceDigest ?? '')) return 'none';
  try {
    const evidenceBytes = await readFile(join(stateRoot, 'evidence', `${result.provenanceDigest}.json`));
    return authenticatedResultDiagnostic({ evidenceBytes, evidenceHmacKey, evidenceKeyId, result });
  } catch { return 'none'; }
};

const PRESTART_IMAGE_DIAGNOSTICS = Object.freeze([
  'PRESTART_IMAGE_CONFIG_COMMAND',
  'PRESTART_IMAGE_CONFIG_ENV',
  'PRESTART_IMAGE_CONFIG_HEALTH',
  'PRESTART_IMAGE_CONFIG_LABELS',
  'PRESTART_IMAGE_CONFIG_USER_WORKDIR',
  'PRESTART_IMAGE_CONFIG_VOLUME',
  'PRESTART_IMAGE_IDENTITY',
  'PRESTART_IMAGE_INSPECT_SHAPE',
  'PRESTART_IMAGE_PLATFORM',
  'PRESTART_IMAGE_ROOTFS',
  'PRESTART_IMAGE_SIZE',
]);

const safeOpenDiagnostic = (error) => {
  try {
    if (!(error instanceof LinuxReferenceUnavailableError)) return 'none';
    const descriptor = Object.getOwnPropertyDescriptor(error, 'diagnostic');
    return descriptor && Object.hasOwn(descriptor, 'value') && PRESTART_IMAGE_DIAGNOSTICS.includes(descriptor.value) ? descriptor.value : 'none';
  } catch { return 'none'; }
};

let service;
const evidence = [];
try {
  try {
    service = await openLinuxReferenceSandboxCandidate(configuration);
  } catch (error) {
    assert.fail(`reference candidate unavailable; safeOpenDiagnostic=${safeOpenDiagnostic(error)}`);
  }
  const run = async (command, expectedCode, options = {}) => {
    const descriptor = descriptorFor(command, options);
    const started = Date.now();
    const result = await service.run(descriptor.job, descriptor.acquisition);
    const elapsedMilliseconds = Date.now() - started;
    const diagnostic = result.code === expectedCode ? 'none' : await safeResultDiagnostic(result);
    assert.equal(result.code, expectedCode, `${command} result differs; safeResultDiagnostic=${diagnostic}`);
    assert(elapsedMilliseconds <= policy.elapsedMilliseconds + 5_000, `${command} exceeded cleanup envelope`);
    if (options.maximumElapsedMilliseconds !== undefined) assert(elapsedMilliseconds <= options.maximumElapsedMilliseconds, `${command} exceeded its canary-specific resource envelope`);
    if (expectedCode === 'VALIDATED') await readOutput(descriptor.job.jobId, outputExpectation[command]);
    else await assertNoOutput(descriptor.job.jobId);
    evidence.push(Object.freeze({ command, elapsedMilliseconds, resultCode: result.code }));
    return Object.freeze({ descriptor, result });
  };

  const importer = await run('importer', 'VALIDATED');
  await run('converter', 'VALIDATED', { toolClass: 'converter' });
  const acquiredAfterImporter = acquisitions;
  assert.deepEqual(await service.run(importer.descriptor.job, importer.descriptor.acquisition), importer.result);
  assert.equal(acquisitions, acquiredAfterImporter, 'idempotent replay reacquired bytes');

  const hostile = Object.freeze([
    ['network', 'VALIDATED'],
    ['credential', 'VALIDATED'],
    ['host', 'VALIDATED'],
    ['sibling', 'VALIDATED'],
    ['undeclared', 'VALIDATED'],
    ['traversal', 'VALIDATED'],
    ['device', 'VALIDATED'],
    ['namespace', 'VALIDATED'],
    ['clone-namespace', 'VALIDATED'],
    ['clone3-namespace', 'VALIDATED'],
    ['symlink', 'SANDBOX_VALIDATION_FAILED'],
    ['recursion', 'SANDBOX_VALIDATION_FAILED'],
    ['disk', 'SANDBOX_VALIDATION_FAILED'],
    ['bomb', 'SANDBOX_VALIDATION_FAILED'],
    ['hang', 'SANDBOX_TIMEOUT'],
    ['fork', 'SANDBOX_TIMEOUT'],
    ['memory', 'SANDBOX_RESOURCE_LIMIT'],
    ['stdout', 'SANDBOX_OUTPUT_LIMIT'],
    ['crash', 'SANDBOX_VALIDATION_FAILED'],
  ]);
  for (const [command, expectedCode] of hostile) {
    await run(command, expectedCode);
    await run('importer', 'VALIDATED');
    assert.equal(service.health().poisoned, false, `${command} poisoned the next-job boundary`);
  }
  await run('cpu', 'SANDBOX_RESOURCE_LIMIT', { maximumElapsedMilliseconds: policy.elapsedMilliseconds - 1 });
  await run('importer', 'VALIDATED');
  assert.equal(service.health().poisoned, false, 'CPU-limit settlement poisoned the next-job boundary');

  const cancellation = descriptorFor('hang', { suffix: 'cancel' });
  const pending = service.run(cancellation.job, cancellation.acquisition);
  const statePath = join(stateRoot, 'jobs', `${cancellation.job.jobId}.json`);
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const state = await readFile(statePath, 'utf8').then((value) => JSON.parse(value).state).catch(() => null);
    if (state === 'running') break;
    await delay(10);
  }
  assert.equal(service.cancel(cancellation.job.jobId), true);
  assert.equal((await pending).code, 'SANDBOX_CANCELLED');
  await run('importer', 'VALIDATED');

  const restart = descriptorFor('importer', { suffix: 'restart' });
  const restartResult = await service.run(restart.job, restart.acquisition);
  const acquisitionsBeforeRestart = acquisitions;
  await service.close(); service = null;
  service = await openLinuxReferenceSandboxCandidate(configuration);
  assert.deepEqual(await service.run(restart.job, restart.acquisition), restartResult);
  assert.equal(acquisitions, acquisitionsBeforeRestart, 'restart replay reacquired bytes');

  const revokeTarget = descriptorFor('importer', { suffix: 'revoke-prior' });
  assert.equal((await service.run(revokeTarget.job, revokeTarget.acquisition)).code, 'VALIDATED');
  const receipt = await service.revoke({ digest: toolDigest, kind: 'tool', reasonCode: 'conformance.revoked', throughGeneration: 1 });
  assert(receipt.affectedCompletedJobs >= 1);
  assert.equal((await service.run(revokeTarget.job, revokeTarget.acquisition)).code, 'SANDBOX_REVOKED');
  await assertNoOutput(revokeTarget.job.jobId);
  const revokeNew = descriptorFor('importer', { suffix: 'revoke-new' });
  assert.equal((await service.run(revokeNew.job, revokeNew.acquisition)).code, 'SANDBOX_REVOKED');

  const reports = (await Promise.all((await readdir(join(stateRoot, 'evidence'))).map((name) => readFile(join(stateRoot, 'evidence', name), 'utf8')))).join('\n');
  assert.equal(reports.includes(credential), false, 'credential entered durable evidence');
  const report = Object.freeze({ cases: Object.freeze(evidence), profile: 'linux-reference-v1', runtimeDigest, schemaVersion: 'ogvcs.untrusted-sandbox/linux-conformance-report/v1', seccompProfileSha256: probe.seccompProfileSha256 });
  const reportBytes = Buffer.from(`${canonicalJson(report)}\n`, 'utf8');
  const reportPath = process.env.OGVCS_SANDBOX_REPORT_PATH;
  if (reportPath !== undefined) {
    if (!isAbsolute(reportPath)) throw new Error('live reference report path must be absolute');
    await writeFile(reportPath, reportBytes, { flag: 'wx', mode: 0o600 });
  }
  process.stdout.write(reportBytes);
} finally {
  if (service) await service.close().catch(() => {});
  configuration.evidenceHmacKey.fill(0);
  await rm(canonicalRoot, { recursive: true, force: true });
}
