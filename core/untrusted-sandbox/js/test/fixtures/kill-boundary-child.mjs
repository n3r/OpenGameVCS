#!/usr/bin/env node

import { createHash, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { closeSync, fsyncSync, openSync, writeSync } from 'node:fs';
import { chmod, open, readFile, stat, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createReferenceServiceHardKillHookForTesting } from '../../src/testing.mjs';
import { LINUX_RUNTIME_CONTRACT_SHA256, canonicalJson, sha256 } from '../../src/internal/reference-contract.mjs';
import { ReferenceSandboxService } from '../../src/internal/reference-service.mjs';

const MAGIC = Buffer.from([0x4f, 0x47, 0x56, 0x43, 0x53, 0x42, 0x31, 0x00]);
const RUNTIME_DIGEST = 'b'.repeat(64);
const SECCOMP_DIGEST = 'e'.repeat(64);
const ACTOR_DIGEST = 'a'.repeat(64);
const OPTIONS_DIGEST = 'c'.repeat(64);
const OBJECT_ID_DIGEST = 'd'.repeat(64);
const FIXTURE_FILE = 'kill-boundary-fixture.json';
const MARKER_FILE = 'kill-boundary-reached';

const u32 = (value) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };
const u64 = (value) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes; };

const readHandle = async (handle) => {
  const details = await handle.stat();
  const bytes = Buffer.alloc(details.size);
  let offset = 0;
  while (offset < bytes.length) {
    const value = await handle.read(bytes, offset, bytes.length - offset, offset);
    if (value.bytesRead === 0) throw new Error('kill-boundary fixture handle ended early');
    offset += value.bytesRead;
  }
  return bytes;
};

const outputFrame = (binding, files) => {
  const aggregate = createHash('sha256');
  const parts = [];
  const append = (bytes) => { aggregate.update(bytes); parts.push(bytes); };
  append(MAGIC);
  append(Buffer.from(binding, 'hex'));
  let total = 0;
  for (const file of [...files].sort((left, right) => Buffer.compare(Buffer.from(left.path, 'utf8'), Buffer.from(right.path, 'utf8')))) {
    const path = Buffer.from(file.path, 'utf8');
    const content = Buffer.from(file.content);
    append(Buffer.from([1]));
    append(Buffer.concat([u32(path.length), u64(content.length)]));
    append(createHash('sha256').update(content).digest());
    append(path);
    append(content);
    total += content.length;
  }
  append(Buffer.concat([Buffer.from([0xff]), u32(files.length), u64(total)]));
  parts.push(aggregate.digest());
  return Buffer.concat(parts);
};

export class KillBoundaryFixtureAdapter {
  constructor({ reconciliationReport = null } = {}) {
    this.seccompDigest = SECCOMP_DIGEST;
    this.reconciliationReport = reconciliationReport;
    this.destructiveCalls = [];
    this.discardCalls = 0;
  }

  async verifyRuntimeImage(image, contract) {
    return image === `sha256:${RUNTIME_DIGEST}` && contract === LINUX_RUNTIME_CONTRACT_SHA256;
  }

  async reconcileDaemonOrphans() {
    return this.reconciliationReport ?? Object.freeze({
      diagnosticCodes: Object.freeze([]),
      resourceFingerprints: Object.freeze([]),
      schemaVersion: 'ogvcs.untrusted-sandbox/daemon-reconciliation/v1',
      status: 'settled',
    });
  }

  releaseDaemonAuthority() {}

  async runTool({ inputHandle }) {
    const command = (await readHandle(inputHandle)).toString('utf8');
    const path = command === 'converter' ? 'preview/result' : 'import/result';
    return Object.freeze({
      kind: 'success',
      volume: Object.freeze({ files: Object.freeze([Object.freeze({ content: Buffer.from(command), path })]) }),
    });
  }

  async collectOutput({ bindingHandle, framePath, volume }) {
    const binding = (await readHandle(bindingHandle)).toString('ascii');
    const frame = outputFrame(binding, volume.files);
    await writeFile(framePath, frame, { flag: 'wx', mode: 0o600 });
    return Object.freeze({ frameBytes: frame.length, kind: 'success' });
  }

  async discardVolume() { this.discardCalls += 1; }
}

const manifestFor = ({ nowUnixMs, privateKey, toolDigest }) => {
  const policy = Object.freeze({
    cpuMilliseconds: 1_000,
    elapsedMilliseconds: 10_000,
    fanout: 16,
    memoryBytes: 64 * 1024 * 1024,
    outputBytes: 1024 * 1024,
    processes: 4,
    profileId: 'linux-reference-v1',
    scratchBytes: 2 * 1024 * 1024,
  });
  const unsigned = Object.freeze({
    expiresAtUnixMs: nowUnixMs + 60 * 60 * 1_000,
    generation: 1,
    issuedAtUnixMs: nowUnixMs - 1_000,
    manifestId: 'kill.boundary.importer.v1',
    outputPolicy: Object.freeze({ allowedTypes: Object.freeze(['conformance.record']), maximumFileBytes: 1024 * 1024, schemaVersion: 'ogvcs.untrusted-sandbox/parser-output/v1' }),
    resourcePolicy: policy,
    runtimeContractSha256: LINUX_RUNTIME_CONTRACT_SHA256,
    runtimeDigest: RUNTIME_DIGEST,
    runtimeImage: `sha256:${RUNTIME_DIGEST}`,
    schemaVersion: 'ogvcs.untrusted-sandbox/tool-runtime-manifest/v1',
    signingKeyId: 'kill.boundary.signer.1',
    toolClass: 'import-parser',
    toolDigest,
  });
  const signatureEd25519 = sign(null, Buffer.from(canonicalJson(unsigned), 'utf8'), privateKey).toString('base64url');
  const bytes = Buffer.from(canonicalJson({ ...unsigned, signatureEd25519 }), 'utf8');
  return Object.freeze({
    bytes,
    digest: sha256(bytes),
    policyDigest: sha256(Buffer.from(canonicalJson(policy), 'utf8')),
  });
};

const durableWrite = async (path, bytes, mode) => {
  const handle = await open(path, 'wx', mode);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
};

export const createKillBoundaryFixture = async (root) => {
  await chmod(root, 0o700);
  const toolPath = join(root, 'dummy-tool');
  await durableWrite(toolPath, Buffer.from('dummy-tool-v1'), 0o555);
  await chmod(toolPath, 0o555);
  const toolDigest = sha256(await readFile(toolPath));
  const nowUnixMs = Date.now();
  const keys = generateKeyPairSync('ed25519');
  const manifest = manifestFor({ nowUnixMs, privateKey: keys.privateKey, toolDigest });
  const inputDigest = sha256(Buffer.from('importer'));
  const job = Object.freeze({
    actorDigest: ACTOR_DIGEST,
    deadlineUnixMs: nowUnixMs + 30 * 1_000,
    idempotencyKey: 'kill.boundary.1',
    inputDigest,
    jobId: 'kill.boundary.1',
    manifestDigest: manifest.digest,
    optionsDigest: OPTIONS_DIGEST,
    outputSchema: 'ogvcs.untrusted-sandbox/parser-output/v1',
    purpose: 'private-hard-kill-conformance',
    resourcePolicyDigest: manifest.policyDigest,
    runtimeDigest: RUNTIME_DIGEST,
    schemaVersion: 'ogvcs.untrusted-sandbox/reference-job/v1',
    toolDigest,
  });
  const fixture = Object.freeze({
    acquisition: Object.freeze({ maximumBytes: 1024, objectIdDigest: OBJECT_ID_DIGEST, schemaVersion: 'ogvcs.untrusted-sandbox/acquisition-request/v1', sourceId: 'kill.boundary.source' }),
    job,
    manifestBytesBase64: manifest.bytes.toString('base64'),
    publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    schemaVersion: 'ogvcs.untrusted-sandbox/kill-boundary-fixture/v1',
    toolPath,
  });
  await durableWrite(join(root, FIXTURE_FILE), Buffer.from(`${canonicalJson(fixture)}\n`, 'utf8'), 0o600);
  return fixture;
};

export const readKillBoundaryFixture = async (root) => JSON.parse(await readFile(join(root, FIXTURE_FILE), 'utf8'));

export const killBoundaryServiceConfiguration = ({ adapter, fixture, root, testHookCapability = null }) => ({
  acquisitionSources: [Object.freeze({
    acquire: async ({ credential }) => {
      if (credential !== 'kill-boundary-broker-canary') throw new Error('kill-boundary acquisition authority differs');
      return Buffer.from('importer');
    },
    credential: 'kill-boundary-broker-canary',
    maximumBytes: 1024,
    sourceId: 'kill.boundary.source',
  })],
  adapter,
  evidenceHmacKey: Buffer.alloc(32, 0x5a),
  evidenceHmacKeyId: 'kill.boundary.evidence.1',
  manifestCatalog: [{ manifestBytes: Buffer.from(fixture.manifestBytesBase64, 'base64'), toolPath: fixture.toolPath }],
  stateRoot: join(root, 'state'),
  testHookCapability,
  trustedManifestKeys: { 'kill.boundary.signer.1': createPublicKey(fixture.publicKeyPem) },
});

const durableMarker = (root, boundary) => {
  const descriptor = openSync(join(root, MARKER_FILE), 'wx', 0o600);
  try {
    writeSync(descriptor, Buffer.from(`${boundary}\n`, 'utf8'));
    fsyncSync(descriptor);
  } finally { closeSync(descriptor); }
  const directory = openSync(root, 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
};

const main = async () => {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--root' || args[2] !== '--boundary') throw new Error('usage: kill-boundary-child.mjs --root <root> --boundary <name>');
  const root = resolve(args[1]);
  const boundary = args[3];
  const fixture = await createKillBoundaryFixture(root);
  const adapter = new KillBoundaryFixtureAdapter();
  const testHookCapability = createReferenceServiceHardKillHookForTesting(boundary, () => durableMarker(root, boundary));
  const service = await ReferenceSandboxService.open(killBoundaryServiceConfiguration({ adapter, fixture, root, testHookCapability }));
  await service.run(fixture.job, fixture.acquisition);
  process.exitCode = 70;
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();

export const killBoundaryMarkerPath = (root) => join(root, MARKER_FILE);
export const outputBundlePath = (root) => join(root, 'state', 'outputs', 'kill.boundary.1', 'bundle', 'import', 'result');
export const outputBundleExists = async (root) => stat(outputBundlePath(root)).then((entry) => entry.isFile(), () => false);
