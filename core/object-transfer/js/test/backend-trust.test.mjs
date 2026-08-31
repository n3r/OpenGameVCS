import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { FilesystemObjectBackend } from '../src/backend.mjs';
import { backendCapabilities, trustedBackendPort } from '../src/backend-access.mjs';
import { captureTrustedBackend } from '../src/backend-port.mjs';
import { S3ObjectBackend } from '../src/s3-backend.mjs';
import { MemoryS3Service } from './helpers/memory-s3.mjs';

test('backend trust rejects structural objects, subclasses, proxies, and pre-construction prototype replacement', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-backend-trust-'));
  const structural = Object.fromEntries(['createIfAbsent', 'head', 'initialize', 'listByInternalPrefix', 'readRange', 'readVerifiedRange', 'safeDelete', 'verify'].map((name) => [name, async () => {}]));
  assert.throws(() => backendCapabilities(structural), { code: 'TRANSFER_INPUT_INVALID' });
  class DeepStructuralBackend {}
  for (const name of Object.keys(structural)) {
    Object.defineProperty(DeepStructuralBackend.prototype, name, {
      value: structural[name], writable: false, configurable: false,
    });
  }
  Object.freeze(DeepStructuralBackend.prototype);
  const deepStructural = new DeepStructuralBackend();
  const definition = Object.freeze({
    constructor: DeepStructuralBackend,
    prototype: DeepStructuralBackend.prototype,
    methods: Object.freeze(Object.fromEntries(Object.keys(structural).map((name) => [
      name, Object.getOwnPropertyDescriptor(DeepStructuralBackend.prototype, name).value,
    ]))),
  });
  captureTrustedBackend(deepStructural, {
    schemaVersion: 'ogvcs.object-transfer/backend-capabilities/v1',
    backendKind: 'filesystem',
    profile: 'forged/deep-import',
    objectBytesMaximum: 1,
    rangeBytesMaximum: 1,
    createIfAbsent: true,
    exactMetadata: true,
    wholeObjectVerification: true,
    verifiedRanges: true,
    boundedPrefixList: true,
    generationFencedDelete: true,
    multipartEtagIsDigest: false,
  }, definition);
  assert.throws(() => backendCapabilities(deepStructural), { code: 'TRANSFER_INPUT_INVALID' });
  class ForgedBackend extends FilesystemObjectBackend {}
  assert.throws(() => new ForgedBackend({ root }), { code: 'TRANSFER_INPUT_INVALID' });
  assert.throws(() => Object.defineProperty(FilesystemObjectBackend.prototype, 'head', { value: async () => ({ forged: true }) }), TypeError);
  const exact = new FilesystemObjectBackend({ root });
  assert.throws(() => backendCapabilities(new Proxy(exact, {})), { code: 'TRANSFER_INPUT_INVALID' });
});

test('captured backend ports ignore own/prototype replacement and cannot cross-dispatch instances', async () => {
  const firstRoot = await mkdtemp(join(tmpdir(), 'ogvcs-backend-trust-first-'));
  const secondRoot = await mkdtemp(join(tmpdir(), 'ogvcs-backend-trust-second-'));
  const first = new FilesystemObjectBackend({ root: firstRoot });
  const second = new FilesystemObjectBackend({ root: secondRoot });
  const firstPort = trustedBackendPort(first);
  const secondPort = trustedBackendPort(second);
  const forged = async () => { throw new Error('forged own method'); };
  Object.defineProperty(first, 'initialize', { value: forged, configurable: true });
  assert.throws(() => { FilesystemObjectBackend.prototype.initialize = forged; }, TypeError);
  await firstPort.initialize();
  await secondPort.initialize();
  assert.equal(await firstPort.head('a'.repeat(64)), null);
  assert.equal(await secondPort.head('a'.repeat(64)), null);
  assert.notEqual(firstPort.initialize, secondPort.initialize);
  assert.equal(Object.isFrozen(firstPort), true);
  assert.throws(() => { firstPort.head = secondPort.head; }, TypeError);
  const fake = new MemoryS3Service();
  const s3 = new S3ObjectBackend({
    endpoint: 'http://127.0.0.1:1', bucket: 'ogvcs-test', region: 'us-east-1',
    accessKeyId: 'trust-access', secretAccessKey: 'trust-secret-key-value',
    allowInsecureLoopback: true, createBucketForTests: true, fetch: fake.fetch,
  });
  const s3Port = trustedBackendPort(s3);
  const crossAdapter = { ...firstPort, verify: s3Port.verify };
  assert.throws(() => backendCapabilities(crossAdapter), { code: 'TRANSFER_INPUT_INVALID' });
});
