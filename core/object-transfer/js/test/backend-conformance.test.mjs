import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { FilesystemObjectBackend } from '../src/backend.mjs';
import { issueDeletePermit } from '../src/delete-permit.mjs';
import { S3ObjectBackend } from '../src/s3-backend.mjs';
import { MemoryS3Service } from './helpers/memory-s3.mjs';

const bytes = Buffer.from('shared immutable backend conformance fixture\n');
const objectId = hashObject(1, bytes).toString();
const sha = (value) => createHash('sha256').update(value).digest('hex');
const key = sha('tenant-alpha\0shared-object');
const secondKey = sha('tenant-beta\0shared-object');
const recoveryKey = sha('tenant-alpha\0response-loss-object');
const authority = sha('authority');

async function filesystemBackend() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-backend-conformance-fs-'));
  let loseAcknowledgement = false;
  const backend = await new FilesystemObjectBackend({
    root,
    fault: async (phase) => {
      if (loseAcknowledgement && phase === 'after-directory-sync') {
        loseAcknowledgement = false;
        throw new Error('simulated acknowledgement loss');
      }
    },
  }).initialize();
  return {
    backend,
    loseNextAcknowledgement: () => { loseAcknowledgement = true; },
    corruptBody: async (opaqueKey) => {
      const path = join(root, 'objects', opaqueKey.slice(0, 2), opaqueKey.slice(2, 4), `${opaqueKey}.obj`);
      const handle = await open(path, 'r+');
      try {
        const stat = await handle.stat();
        const byte = Buffer.alloc(1);
        await handle.read(byte, 0, 1, stat.size - 1);
        byte[0] ^= 1;
        await handle.write(byte, 0, 1, stat.size - 1);
        await handle.sync();
      } finally { await handle.close(); }
    },
  };
}

async function s3Backend() {
  const fake = new MemoryS3Service({ pageSize: 1 });
  const backend = new S3ObjectBackend({
    endpoint: 'http://127.0.0.1:1',
    bucket: 'ogvcs-test',
    region: 'us-east-1',
    accessKeyId: 'conformance-access',
    secretAccessKey: 'conformance-secret-key-value',
    allowInsecureLoopback: true,
    createBucketForTests: true,
    fetch: fake.fetch,
    sleep: async () => {},
    retries: 0,
  });
  await backend.initialize();
  return {
    backend,
    loseNextAcknowledgement: () => { fake.responseLossAfterPut = 1; },
    corruptBody: async (opaqueKey) => {
      const storageKey = [...fake.objects.keys()].find((value) => value.includes('/objects/') && value.endsWith(`/${opaqueKey}`));
      assert.equal(typeof storageKey, 'string');
      fake.corruptObjectBody(storageKey);
    },
  };
}

for (const [name, factory] of [['filesystem', filesystemBackend], ['s3-compatible', s3Backend]]) {
  test(`${name} passes the shared immutable backend behavior contract`, async () => {
    const { backend, loseNextAcknowledgement, corruptBody } = await factory();
    assert.equal(await backend.head(key), null);
    const first = await backend.createIfAbsent({ opaqueKey: key, objectId, length: bytes.length, source: bytes });
    assert.equal(first.created, true);
    assert.equal(first.durable, true);
    assert.equal(first.payloadSha256, sha(bytes));
    const replay = await backend.createIfAbsent({ opaqueKey: key, objectId, length: bytes.length, source: bytes });
    assert.equal(replay.created, false);
    assert.equal(replay.receiptSha256, first.receiptSha256);
    assert.equal((await backend.verify(key)).receiptSha256, first.receiptSha256);
    const range = await backend.readVerifiedRange(key, 3, 17);
    assert.equal(range.bytes.equals(bytes.subarray(3, 17)), true);
    assert.equal(range.contentSha256, sha(bytes.subarray(3, 17)));
    await backend.createIfAbsent({ opaqueKey: secondKey, objectId, length: bytes.length, source: bytes });
    loseNextAcknowledgement();
    await assert.rejects(() => backend.createIfAbsent({
      opaqueKey: recoveryKey, objectId, length: bytes.length, source: bytes,
    }), { code: 'TRANSFER_BACKEND_IO' });
    const recovered = await backend.createIfAbsent({
      opaqueKey: recoveryKey, objectId, length: bytes.length, source: bytes,
    });
    assert.equal(recovered.created, false);
    assert.equal(recovered.durable, true);
    assert.deepEqual([...(await backend.listByInternalPrefix(key.slice(0, 8), 2))], [key]);
    assert.deepEqual([...(await backend.listByInternalPrefix('', 3))], [key, recoveryKey, secondKey].sort());
    await assert.rejects(() => backend.listByInternalPrefix('', 2), { code: 'TRANSFER_LIMIT_EXCEEDED' });
    await assert.rejects(() => backend.readVerifiedRange(key, 0, bytes.length + 1), { code: 'TRANSFER_INPUT_INVALID' });
    await corruptBody(recoveryKey);
    await assert.rejects(() => backend.verify(recoveryKey), { code: 'TRANSFER_BACKEND_CORRUPT' });
    const binding = {
      opaqueKey: key,
      objectId,
      length: bytes.length,
      priorReceiptSha256: first.receiptSha256,
      expectedGeneration: 6,
      authorityBindingSha256: authority,
    };
    const deleted = await backend.safeDelete({ permit: issueDeletePermit(binding) });
    const deleteReplay = await backend.safeDelete({ permit: issueDeletePermit(binding) });
    assert.deepEqual(deleteReplay, deleted);
    assert.equal(await backend.head(key), null);
    assert.notEqual(await backend.head(secondKey), null);
    assert.deepEqual([...(await backend.listByInternalPrefix('', 2))], [recoveryKey, secondKey].sort());
  });
}
