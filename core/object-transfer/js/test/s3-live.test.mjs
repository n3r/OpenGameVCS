import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { issueDeletePermit } from '../src/delete-permit.mjs';
import { S3ObjectBackend } from '../src/s3-backend.mjs';

const endpoint = process.env.OGVCS_S3_CONFORMANCE_ENDPOINT;
const enabled = typeof endpoint === 'string' && endpoint.length > 0;
const sha = (value) => createHash('sha256').update(value).digest('hex');

test('pinned live S3-compatible service passes bounded backend conformance', { skip: !enabled }, async () => {
  const backend = new S3ObjectBackend({
    endpoint,
    bucket: process.env.OGVCS_S3_CONFORMANCE_BUCKET,
    region: 'us-east-1',
    accessKeyId: process.env.OGVCS_S3_CONFORMANCE_ACCESS_KEY,
    secretAccessKey: process.env.OGVCS_S3_CONFORMANCE_SECRET_KEY,
    allowInsecureLoopback: true,
    createBucketForTests: true,
  });
  await backend.initialize();
  const bytes = Buffer.alloc(2048, 0x6d);
  const objectId = hashObject(1, bytes).toString();
  const key = sha('hosted-minio-object');
  const [left, right] = await Promise.all([
    backend.createIfAbsent({ opaqueKey: key, objectId, length: bytes.length, source: bytes }),
    backend.createIfAbsent({ opaqueKey: key, objectId, length: bytes.length, source: bytes }),
  ]);
  assert.deepEqual([left.created, right.created].sort(), [false, true]);
  assert.equal(left.receiptSha256, right.receiptSha256);
  assert.equal((await backend.readVerifiedRange(key, 7, 73)).bytes.equals(bytes.subarray(7, 73)), true);
  assert.deepEqual([...(await backend.listByInternalPrefix(key.slice(0, 7), 1))], [key]);
  const binding = {
    opaqueKey: key,
    objectId,
    length: bytes.length,
    priorReceiptSha256: left.receiptSha256,
    expectedGeneration: 2,
    authorityBindingSha256: sha('hosted-authority'),
  };
  const deleted = await backend.safeDelete({ permit: issueDeletePermit(binding) });
  assert.deepEqual(await backend.safeDelete({ permit: issueDeletePermit(binding) }), deleted);
  assert.equal(await backend.head(key), null);
});
