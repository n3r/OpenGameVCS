import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { signConformanceGrant } from '@opengamevcs/authorization-contract';
import { semanticIdempotencyFingerprint } from '@opengamevcs/protocol-baseline';
import { ObjectTransferService, TRANSFER_LIMITS } from '../src/service.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const backendSecret = Buffer.alloc(32, 0x33);
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateJwk = privateKey.export({ format: 'jwk' });
const publicJwk = publicKey.export({ format: 'jwk' });
const now = 1_800_000_000_000;
const context = {
  issuer: 'auth.example', keyId: 'transfer-key', subject: 'artist-one', audience: 'objects.example',
  tenant: 'tenant-alpha', repository: 'game-main', authorityEpoch: 11, keyGeneration: 7,
};

function grant(operation, objectIds, nonce) {
  return signConformanceGrant({
    schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1',
    issuer: context.issuer,
    keyId: context.keyId,
    keyGeneration: context.keyGeneration,
    authorityEpoch: context.authorityEpoch,
    subject: context.subject,
    tenant: context.tenant,
    repository: context.repository,
    permission: operation === 'upload' ? 'content.upload' : 'content.materialize',
    operation,
    audience: context.audience,
    issuedAt: Math.floor(now / 1000) - 1,
    expiresAt: Math.floor(now / 1000) + 299,
    nonce,
    replay: 'idempotent',
    objectIds,
    requestRoot: null,
  }, privateJwk, { conformanceOnly: true });
}

function idempotency(label) {
  return `ik1.${now}.${now + 60000}.${Buffer.from(label.padEnd(16, 'x')).toString('base64url')}`;
}

async function upload(service, bytes, index) {
  const objectId = hashObject(1, bytes).toString();
  const uploadGrant = grant('upload', [objectId], `upload-${index}`);
  const startFingerprint = semanticIdempotencyFingerprint({
    operation: 'start-upload', objectId, declaredLength: bytes.length, partSize: bytes.length,
  });
  const started = await service.startUpload({
    objectId,
    declaredLength: bytes.length,
    partSize: bytes.length,
    idempotencyKey: idempotency(`start-${index}`),
    idempotencyFingerprint: startFingerprint,
    grant: uploadGrant,
    context,
  });
  await service.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes,
    sha256: sha(bytes),
    grant: uploadGrant,
    context,
  });
  await service.finalizeUpload({
    sessionId: started.sessionId,
    idempotencyKey: idempotency(`final-${index}`),
    idempotencyFingerprint: semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId }),
    grant: uploadGrant,
    context,
  });
  return objectId;
}

test('batch plans bind the exact grant/object set/root and disclose no partial hidden position', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-batch-download-'));
  const service = await new ObjectTransferService({
    root,
    backendSecret,
    authorizationPublicJwk: publicJwk,
    audience: context.audience,
    authorityEpoch: context.authorityEpoch,
    keyGeneration: context.keyGeneration,
    issuer: context.issuer,
    keyId: context.keyId,
    now: () => now,
  }).initialize();
  const payloads = [Buffer.from('batch-a'), Buffer.from('batch-bb'), Buffer.from('batch-ccc')];
  const objectIds = [];
  for (let index = 0; index < payloads.length; index += 1) objectIds.push(await upload(service, payloads[index], index));
  const sortedIds = [...objectIds].sort();
  const downloadGrant = grant('download', sortedIds, 'batch-download');
  const plan = await service.planBatchDownload({ objectIds: [...objectIds].reverse(), grant: downloadGrant, context });
  assert.deepEqual(plan.items.map(({ objectId }) => objectId), sortedIds);
  assert.equal(plan.items.every((item, index) => index === 0 || item.packOffset === plan.items[index - 1].packOffset + plan.items[index - 1].length), true);
  const selected = plan.items[1];
  const source = payloads[objectIds.indexOf(selected.objectId)];
  const range = await service.readBatchRange({ plan, itemIndex: 1, start: 1, endExclusive: source.length, grant: downloadGrant, context });
  assert.equal(range.bytes.equals(source.subarray(1)), true);
  await assert.rejects(() => service.readBatchRange({
    plan: { ...plan, planId: sha('tampered-plan') }, itemIndex: 0, start: 0, endExclusive: 1,
    grant: downloadGrant, context,
  }), { code: 'TRANSFER_AUTHORIZATION_DENIED' });
  await assert.rejects(() => service.planBatchDownload({ objectIds: [objectIds[0], objectIds[0]], grant: downloadGrant, context }), { code: 'TRANSFER_INPUT_INVALID' });
  const over = Array.from({ length: TRANSFER_LIMITS.batchMaximum + 1 }, (_, index) => `ogvcs:v1:chunk:sha256:${sha(`over-${index}`)}`);
  await assert.rejects(() => service.planBatchDownload({ objectIds: over, grant: downloadGrant, context }), { code: 'TRANSFER_INPUT_INVALID' });

  const keys = await service.backend.listByInternalPrefix('', 16);
  const byObject = new Map();
  for (const key of keys) byObject.set((await service.backend.verify(key)).objectId, key);
  for (const [position, objectId] of sortedIds.entries()) {
    const key = byObject.get(objectId);
    let lifecycle = await service.lifecycle.get(key);
    lifecycle = await service.lifecycle.compareAndSwap({
      opaqueKey: key,
      expectedGeneration: lifecycle.generation,
      expectedState: 'available',
      nextState: 'quarantined',
      authorityBindingSha256: lifecycle.authorityBindingSha256,
    });
    const hiddenGrant = grant('download', sortedIds, `hidden-${position}`);
    await assert.rejects(async () => service.planBatchDownload({ objectIds: sortedIds, grant: hiddenGrant, context }), (error) => {
      assert.equal(error.code, 'TRANSFER_AUTHORIZATION_DENIED');
      assert.equal(Object.hasOwn(error, 'items'), false);
      assert.equal(error.message.includes(String(position)), false);
      return true;
    });
    const visibleIndex = (position + 1) % plan.items.length;
    await assert.rejects(() => service.readBatchRange({
      plan,
      itemIndex: visibleIndex,
      start: 0,
      endExclusive: 1,
      grant: hiddenGrant,
      context,
    }), { code: 'TRANSFER_AUTHORIZATION_DENIED' });
    await service.lifecycle.compareAndSwap({
      opaqueKey: key,
      expectedGeneration: lifecycle.generation,
      expectedState: 'quarantined',
      nextState: 'available',
      backendReceipt: await service.backend.verify(key),
      authorityBindingSha256: lifecycle.authorityBindingSha256,
    });
  }
});
