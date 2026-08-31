import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { semanticIdempotencyFingerprint } from '@opengamevcs/protocol-baseline';
import { S3ObjectBackend, signS3RequestV4 } from '../src/s3-backend.mjs';
import { ObjectTransferService } from '../src/service.mjs';
import { MemoryS3Service } from './helpers/memory-s3.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const bytes = Buffer.alloc(2048, 0x5a);
const objectId = hashObject(1, bytes).toString();
const key = sha('s3-test-key');
const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

function adapter(fake, options = {}) {
  return new S3ObjectBackend({
    endpoint: 'http://127.0.0.1:1',
    bucket: 'ogvcs-test',
    region: 'us-east-1',
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: secret,
    allowInsecureLoopback: true,
    createBucketForTests: true,
    fetch: fake.fetch,
    sleep: async () => {},
    ...options,
  });
}

test('SigV4 matches the published AWS S3 authorization-header vector exactly', () => {
  const signed = signS3RequestV4({
    url: new URL('https://examplebucket.s3.amazonaws.com/test.txt'),
    method: 'GET',
    headers: { range: 'bytes=0-9' },
    payloadSha256: MemoryS3Service.emptySha256,
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: secret,
    region: 'us-east-1',
    date: '20130524T000000Z',
  });
  assert.equal(signed.canonicalRequestSha256, '7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972');
  assert.equal(signed.signature, 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
  assert.equal(signed.headers.authorization, 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');

  const listed = signS3RequestV4({
    url: new URL('https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J'),
    method: 'GET',
    payloadSha256: MemoryS3Service.emptySha256,
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: secret,
    region: 'us-east-1',
    date: '20130524T000000Z',
  });
  assert.equal(listed.canonicalRequestSha256, 'df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7');
  assert.equal(listed.signature, '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7');
});

test('conditional create races and a lost acknowledgement converge only after read-back verification', async () => {
  const fake = new MemoryS3Service();
  const backend = adapter(fake);
  await backend.initialize();
  fake.responseLossAfterPut = 1;
  const repaired = await backend.createIfAbsent({ opaqueKey: key, objectId, length: bytes.length, source: bytes });
  assert.equal(repaired.created, false);
  assert.equal(repaired.durable, true);
  const raceKey = sha('s3-race-key');
  const results = await Promise.all([
    backend.createIfAbsent({ opaqueKey: raceKey, objectId, length: bytes.length, source: bytes }),
    backend.createIfAbsent({ opaqueKey: raceKey, objectId, length: bytes.length, source: bytes }),
  ]);
  assert.deepEqual(results.map(({ created }) => created).sort(), [false, true]);
  assert.equal(results[0].receiptSha256, results[1].receiptSha256);
  fake.assertNoCredentialLeak(secret);
});

test('corrupt acknowledgement, body, checksum metadata, and sharded pagination fail closed', async () => {
  const fake = new MemoryS3Service({ pageSize: 1 });
  const backend = adapter(fake);
  await backend.initialize();
  fake.corruptAfterPut = true;
  await assert.rejects(() => backend.createIfAbsent({ opaqueKey: key, objectId, length: bytes.length, source: bytes }), { code: 'TRANSFER_BACKEND_CORRUPT' });
  const cleanKey = sha('s3-clean-key');
  await backend.createIfAbsent({ opaqueKey: cleanKey, objectId, length: bytes.length, source: bytes });
  fake.corruptNextMetadata = true;
  await assert.rejects(() => backend.head(cleanKey), { code: 'TRANSFER_BACKEND_CORRUPT' });
  fake.corruptNextBody = true;
  await assert.rejects(() => backend.readVerifiedRange(cleanKey, 0, 32), { code: 'TRANSFER_BACKEND_CORRUPT' });
  assert.deepEqual([...(await backend.listByInternalPrefix(cleanKey.slice(0, 5), 1))], [cleanKey]);
});

test('S3 transport is HTTPS by default and deadlines/errors redact credentials and keys', async () => {
  assert.throws(() => new S3ObjectBackend({
    endpoint: 'http://s3.example.test', bucket: 'ogvcs-test', region: 'us-east-1',
    accessKeyId: 'access-key', secretAccessKey: 'a-secret-key-value',
  }), { code: 'TRANSFER_INPUT_INVALID' });
  const fake = new MemoryS3Service();
  fake.hang = true;
  const backend = adapter(fake, { deadlineMilliseconds: 100, retries: 0 });
  await assert.rejects(async () => backend.initialize(), (error) => {
    assert.equal(error.code, 'TRANSFER_BACKEND_IO');
    assert.equal(error.message.includes(secret), false);
    assert.equal(error.message.includes(key), false);
    return true;
  });
});

test('ObjectTransferService uses only the captured trusted S3 port through durable finalize/read', async () => {
  const fake = new MemoryS3Service();
  const backend = adapter(fake);
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-s3-service-'));
  const now = 1_800_000_000_000;
  const claims = {
    schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1', issuer: 'auth.example', keyId: 'key',
    keyGeneration: 1, authorityEpoch: 1, subject: 'actor', tenant: 'tenant', repository: 'repo',
    permission: 'content.upload', operation: 'upload', audience: 'objects.example', issuedAt: 1_799_999_999,
    expiresAt: 1_800_000_299, nonce: 's3-service', replay: 'idempotent', objectIds: [objectId], requestRoot: null,
  };
  const context = { issuer: 'auth.example', keyId: 'key', audience: 'objects.example', authorityEpoch: 1, keyGeneration: 1 };
  const service = await new ObjectTransferService({
    root,
    backend,
    backendSecret: Buffer.alloc(32, 9),
    authorizationPublicJwk: {},
    audience: 'objects.example',
    authorityEpoch: 1,
    keyGeneration: 1,
    issuer: 'auth.example',
    keyId: 'key',
    now: () => now,
    verifyGrant: async () => ({ result: 'allow', code: 'ALLOW_EXPLICIT' }),
  }).initialize();
  const startFingerprint = semanticIdempotencyFingerprint({ operation: 'start-upload', objectId, declaredLength: bytes.length, partSize: bytes.length });
  const started = await service.startUpload({
    objectId, declaredLength: bytes.length, partSize: bytes.length,
    idempotencyKey: `ik1.${now}.${now + 60000}.${Buffer.alloc(16, 1).toString('base64url')}`,
    idempotencyFingerprint: startFingerprint, grant: { claims }, context,
  });
  await service.uploadPart({ sessionId: started.sessionId, index: 0, bytes, sha256: sha(bytes), grant: { claims }, context });
  const receipt = await service.finalizeUpload({
    sessionId: started.sessionId,
    idempotencyKey: `ik1.${now}.${now + 60000}.${Buffer.alloc(16, 2).toString('base64url')}`,
    idempotencyFingerprint: semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId }),
    grant: { claims }, context,
  });
  assert.equal(receipt.state, 'available');
  const downloadClaims = { ...claims, permission: 'content.materialize', operation: 'download', nonce: 's3-download' };
  const downloaded = await service.readRange({ objectId, start: 0, endExclusive: 32, grant: { claims: downloadClaims }, context });
  assert.equal(downloaded.bytes.equals(bytes.subarray(0, 32)), true);
  assert.equal(service.backendCapabilities.backendKind, 's3-compatible');
});
