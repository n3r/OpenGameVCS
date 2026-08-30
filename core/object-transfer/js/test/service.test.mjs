import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { requestRootForObjectIds, signConformanceGrant } from '@opengamevcs/authorization-contract';
import { canonicalBytes, semanticIdempotencyFingerprint } from '@opengamevcs/protocol-baseline';
import { ObjectTransferService } from '../src/index.mjs';
import { faultCase, hostileCase } from './vector-cases.mjs';

const resume = JSON.parse(await readFile(resolve(import.meta.dirname, '../../../../spec/object-transfer/v1/vectors/resume.json'))).cases.find(({ id }) => id === 'multipart-resume');
const secret = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex'); const bytes = Buffer.concat(resume.input.parts.map((part) => Buffer.from(part.bytesHex, 'hex'))); const objectId = hashObject(1, bytes).toString();
const { privateKey, publicKey } = generateKeyPairSync('ed25519'); const privateJwk = privateKey.export({ format: 'jwk' }); const publicJwk = publicKey.export({ format: 'jwk' }); let nowMs = 1_800_000_030_000;
const baseClaims = { schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1', issuer: 'auth.example', keyId: 'transfer-key', keyGeneration: 7, authorityEpoch: 11, subject: 'artist-one', tenant: 'tenant-alpha', repository: 'game-main', audience: 'objects.example', issuedAt: 1_800_000_000, expiresAt: 1_800_000_300, nonce: 'grant-one', replay: 'idempotent', objectIds: [], requestRoot: requestRootForObjectIds([objectId]) };
const context = { issuer: 'auth.example', keyId: 'transfer-key', subject: 'artist-one', audience: 'objects.example', tenant: 'tenant-alpha', repository: 'game-main', authorityEpoch: 11, keyGeneration: 7, now: 1_800_000_030, consumedNonces: [] };
const vectorStartKey = 'ik1.1800000000000.1800000060000.MDEyMzQ1Njc4OWFiY2RlZg';
function grant(operation, nonce = `grant-${operation}`) { return signConformanceGrant({ ...baseClaims, nonce, operation, permission: operation === 'upload' ? 'content.upload' : 'content.materialize' }, privateJwk, { conformanceOnly: true }); }
function key(label, sequence = 0) { const entropy = Buffer.from(`${label}-${sequence}`.padEnd(16, 'x')).toString('base64url'); return `ik1.${nowMs}.${nowMs + 60_000}.${entropy}`; }
function customGrant(claims) { return signConformanceGrant(claims, privateJwk, { conformanceOnly: true }); }
async function service(root, fault = async () => {}, options = {}) { return new ObjectTransferService({ root, backendSecret: secret, authorizationPublicJwk: publicJwk, audience: 'objects.example', authorityEpoch: 11, keyGeneration: 7, issuer: 'auth.example', keyId: 'transfer-key', now: () => nowMs, fault, ...options }).initialize(); }

test('multipart upload resumes across a new service, finalizes once, and serves an authorized verified range', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-service-')); let value = await service(root); const uploadGrant = grant('upload');
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: 8 }); const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: vectorStartKey, idempotencyFingerprint: startFingerprint, grant: uploadGrant, context }); assert.equal(started.sessionId, resume.expected.sessionId);
  for (const index of [0, 2, 1]) { const part = resume.input.parts[index]; await value.uploadPart({ sessionId: started.sessionId, index, bytes: Buffer.from(part.bytesHex, 'hex'), sha256: part.sha256, grant: uploadGrant, context }); }
  await writeFile(join(root, 'sessions', `.${started.sessionId}.json.${'a'.repeat(24)}.tmp`), Buffer.from('interrupted session state write'));
  value = await service(root); const refreshed = grant('upload', 'grant-upload-refreshed'); for (const index of [2, 3, 4]) { const part = resume.input.parts[index]; const result = await value.uploadPart({ sessionId: started.sessionId, index, bytes: Buffer.from(part.bytesHex, 'hex'), sha256: part.sha256, grant: refreshed, context }); assert.equal(result.replay, index === 2); }
  const finalizeFingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId }); const receipt = await value.finalizeUpload({ sessionId: started.sessionId, idempotencyKey: key('finalize', 1), idempotencyFingerprint: finalizeFingerprint, grant: refreshed, context }); assert.equal(receipt.state, 'available'); assert.equal(receipt.generation, 2);
  const replay = await value.finalizeUpload({ sessionId: started.sessionId, idempotencyKey: key('finalize', 1), idempotencyFingerprint: finalizeFingerprint, grant: refreshed, context }); assert.deepEqual(replay, receipt);
  const downloaded = await value.readRange({ objectId, start: 4, endExclusive: 17, grant: grant('download'), context }); assert.equal(downloaded.bytes.equals(bytes.subarray(4, 17)), true); assert.equal(downloaded.lifecycleReceipt.generation, 2);
});

test('a deleted generation can be reuploaded only through the lifecycle-controlled finalize path', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-reupload-'));
  const value = await service(root);
  const uploadGrant = grant('upload', 'grant-upload-initial');
  const startFingerprint = semanticIdempotencyFingerprint({
    declaredLength: bytes.length,
    objectId,
    operation: 'start-upload',
    partSize: bytes.length,
  });
  const started = await value.startUpload({
    objectId,
    declaredLength: bytes.length,
    partSize: bytes.length,
    idempotencyKey: key('reupload-start-initial'),
    idempotencyFingerprint: startFingerprint,
    grant: uploadGrant,
    context,
  });
  await value.uploadPart({
    sessionId: started.sessionId,
    index: 0,
    bytes,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    grant: uploadGrant,
    context,
  });
  const initialFinalizeFingerprint = semanticIdempotencyFingerprint({
    operation: 'finalize-upload',
    sessionId: started.sessionId,
  });
  const initialReceipt = await value.finalizeUpload({
    sessionId: started.sessionId,
    idempotencyKey: key('reupload-final-initial'),
    idempotencyFingerprint: initialFinalizeFingerprint,
    grant: uploadGrant,
    context,
  });
  let lifecycle = await value.lifecycle.get(initialReceipt.opaqueKey);
  lifecycle = await value.lifecycle.compareAndSwap({
    opaqueKey: initialReceipt.opaqueKey,
    expectedGeneration: lifecycle.generation,
    expectedState: 'available',
    nextState: 'quarantined',
    authorityBindingSha256: lifecycle.authorityBindingSha256,
  });
  const savedNow = nowMs;
  try {
    nowMs = lifecycle.retentionUntilUnixMs;
    lifecycle = await value.lifecycle.compareAndSwap({
      opaqueKey: initialReceipt.opaqueKey,
      expectedGeneration: lifecycle.generation,
      expectedState: 'quarantined',
      nextState: 'deleting',
      authorityBindingSha256: lifecycle.authorityBindingSha256,
    });
    lifecycle = await value.lifecycle.deleteAuthorized({
      opaqueKey: initialReceipt.opaqueKey,
      expectedGeneration: lifecycle.generation,
      authorityBindingSha256: lifecycle.authorityBindingSha256,
    });
  } finally {
    nowMs = savedNow;
  }
  assert.equal(lifecycle.state, 'deleted');
  assert.deepEqual(
    [...(await value.negotiateMissing({ objectIds: [objectId], grant: grant('upload', 'grant-upload-negotiate-after-delete'), context })).missing],
    [objectId],
  );
  const restarted = await value.startUpload({
    objectId,
    declaredLength: bytes.length,
    partSize: bytes.length,
    idempotencyKey: key('reupload-start-second'),
    idempotencyFingerprint: startFingerprint,
    grant: grant('upload', 'grant-upload-second'),
    context,
  });
  await value.uploadPart({
    sessionId: restarted.sessionId,
    index: 0,
    bytes,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    grant: grant('upload', 'grant-upload-second-part'),
    context,
  });
  const secondFinalizeFingerprint = semanticIdempotencyFingerprint({
    operation: 'finalize-upload',
    sessionId: restarted.sessionId,
  });
  const reopened = await value.finalizeUpload({
    sessionId: restarted.sessionId,
    idempotencyKey: key('reupload-final-second'),
    idempotencyFingerprint: secondFinalizeFingerprint,
    grant: grant('upload', 'grant-upload-second-finalize'),
    context,
  });
  assert.equal(reopened.state, 'available');
  assert.equal(reopened.generation, lifecycle.generation + 2);
  assert.equal((await value.backend.listByInternalPrefix()).length, 1);
  const downloaded = await value.readRange({
    objectId,
    start: 0,
    endExclusive: bytes.length,
    grant: grant('download', 'grant-download-reuploaded'),
    context,
  });
  assert.equal(downloaded.lifecycleReceipt.generation, reopened.generation);
});

test('stale epoch, wrong audience, conflicting part retry, and backend-only existence fail closed', async () => {
  const staleEpoch = hostileCase('stale-authority-epoch'); const wrongAudience = hostileCase('wrong-audience'); const crossTenant = hostileCase('cross-tenant-key-probe'); const conflictingPart = hostileCase('conflicting-part-retry'); const backendOnly = hostileCase('backend-only-object');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-hostile-')); const value = await service(root); const uploadGrant = grant('upload'); const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: 8 });
  await assert.rejects(() => value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: key('old'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context: { ...context, authorityEpoch: 10 } }), { code: staleEpoch.expected.code });
  await assert.rejects(() => value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: key('aud'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context: { ...context, audience: 'other.example' } }), { code: wrongAudience.expected.code });
  await assert.rejects(() => value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: key('tenant'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context: { ...context, tenant: crossTenant.input.contextTenant } }), { code: crossTenant.expected.code });
  await assert.rejects(() => value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: key('malformed'), idempotencyFingerprint: startFingerprint, grant: null, context }), { code: 'TRANSFER_AUTHORIZATION_DENIED' });
  await assert.rejects(() => value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: null, idempotencyFingerprint: startFingerprint, grant: uploadGrant, context }), { code: 'TRANSFER_INPUT_INVALID' });
  await value.backend.createIfAbsent({ opaqueKey: resume.expected.opaqueKey, objectId, length: bytes.length, source: bytes });
  const absentLifecycle = await value.negotiateMissing({ objectIds: [objectId], grant: uploadGrant, context }); assert.equal(absentLifecycle.missing.includes(objectId), backendOnly.expected.available === false);
  const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: 8, idempotencyKey: key('valid'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context }); const part = resume.input.parts[0]; await value.uploadPart({ sessionId: started.sessionId, index: 0, bytes: Buffer.from(part.bytesHex, 'hex'), sha256: part.sha256, grant: uploadGrant, context }); await assert.rejects(() => value.uploadPart({ sessionId: started.sessionId, index: 0, bytes: Buffer.alloc(8, 0xff), sha256: createHash('sha256').update(Buffer.alloc(8, 0xff)).digest('hex'), grant: uploadGrant, context }), { code: conflictingPart.expected.code });
  const missing = await value.negotiateMissing({ objectIds: [objectId], grant: uploadGrant, context }); assert.deepEqual([...missing.missing], [objectId]);
});

test('grant time and single-use replay are owned persistently by the service', async () => {
  const expiredVector = hostileCase('expired-server-clock-grant'); const replayVector = hostileCase('replayed-single-use-nonce');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-grant-authority-')); let value = await service(root);
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const expired = customGrant({
    ...baseClaims,
    issuedAt: 1_799_999_900,
    expiresAt: Math.floor(nowMs / 1000) - 1,
    nonce: 'expired-at-server-clock',
    operation: 'upload',
    permission: 'content.upload',
  });
  await assert.rejects(() => value.startUpload({
    objectId, declaredLength: bytes.length, partSize: bytes.length,
    idempotencyKey: key('expired-clock'), idempotencyFingerprint: startFingerprint,
    grant: expired,
    context: { ...context, now: 1_800_000_001 },
  }), { code: expiredVector.expected.code });

  const singleUse = customGrant({
    ...baseClaims,
    replay: 'single-use',
    nonce: 'persistent-single-use',
    operation: 'upload',
    permission: 'content.upload',
  });
  assert.deepEqual([...await value.negotiateMissing({ objectIds: [objectId], grant: singleUse, context }).then((result) => result.missing)], [objectId]);
  value = await service(root);
  await assert.rejects(() => value.negotiateMissing({ objectIds: [objectId], grant: singleUse, context: { ...context, consumedNonces: [] } }), { code: replayVector.expected.code });
});

test('an explicit signed object set authorizes its member without a request root', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-explicit-set-')); const value = await service(root);
  const explicit = customGrant({
    ...baseClaims,
    objectIds: [objectId],
    requestRoot: null,
    nonce: 'explicit-object-set',
    operation: 'upload',
    permission: 'content.upload',
  });
  const result = await value.negotiateMissing({ objectIds: [objectId], grant: explicit, context });
  assert.deepEqual([...result.missing], [objectId]);
  assert.equal(result.requestRoot, null);
  const outsideObjectId = hashObject(1, Buffer.from('outside explicit grant')).toString();
  await assert.rejects(
    () => value.negotiateMissing({ objectIds: [outsideObjectId], grant: explicit, context }),
    { code: 'TRANSFER_AUTHORIZATION_DENIED' },
  );
});

test('an expired recoverable session lock is taken over without losing verified parts', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-stale-lock-')); const value = await service(root);
  const uploadGrant = grant('upload');
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('stale-lock-start'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context });
  const lock = join(root, 'session-locks', `${started.sessionId}.lock`);
  await mkdir(lock, { mode: 0o700 });
  await writeFile(join(lock, 'owner.json'), canonicalBytes({
    schemaVersion: 'ogvcs.object-transfer/lock-owner/v1', token: 'a'.repeat(48), pid: 999999,
    acquiredAtUnixMs: nowMs - 10_000, expiresAtUnixMs: nowMs - 1,
  }));
  const result = await value.uploadPart({ sessionId: started.sessionId, index: 0, bytes, sha256: createHash('sha256').update(bytes).digest('hex'), grant: uploadGrant, context });
  assert.equal(result.replay, false);
});

test('persisted session state is schema-closed before authorization or mutation', async () => {
  const vector = hostileCase('corrupt-persisted-state');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-corrupt-session-')); const value = await service(root);
  const uploadGrant = grant('upload');
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('corrupt-session-start'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context });
  const path = join(root, 'sessions', `${started.sessionId}.json`);
  const record = JSON.parse(await readFile(path));
  record.untrusted = true;
  await writeFile(path, canonicalBytes(record));
  await assert.rejects(() => value.sessionStatus({ sessionId: started.sessionId, grant: uploadGrant, context }), { code: vector.expected.code });
});

test('durability/lifecycle response loss repairs on restart without a duplicate backend object', async () => {
  faultCase('after-available-before-response');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-fault-')); let throwAfterLifecycle = true; let value = await service(root, async (phase) => { if (phase === 'after-lifecycle-cas' && throwAfterLifecycle) { throwAfterLifecycle = false; throw new Error('simulated crash'); } }); const uploadGrant = grant('upload'); const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length }); const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('fault-start'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context }); await value.uploadPart({ sessionId: started.sessionId, index: 0, bytes, sha256: createHash('sha256').update(bytes).digest('hex'), grant: uploadGrant, context }); const finalFingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId }); await assert.rejects(() => value.finalizeUpload({ sessionId: started.sessionId, idempotencyKey: key('fault-final', 2), idempotencyFingerprint: finalFingerprint, grant: uploadGrant, context }), /simulated crash/u);
  value = await service(root); const repaired = await value.finalizeUpload({ sessionId: started.sessionId, idempotencyKey: key('fault-repair', 3), idempotencyFingerprint: finalFingerprint, grant: uploadGrant, context }); assert.equal(repaired.generation, 2); assert.equal((await value.backend.listByInternalPrefix()).length, 1);
  const lifecycle = await value.lifecycle.get(repaired.opaqueKey); assert.equal(lifecycle.state, 'available');
});

test('a quarantine race cannot return a false current-available receipt', async () => {
  faultCase('quarantine-races-finalize-response');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-race-')); let value; let race = true;
  value = await service(root, async (phase) => {
    if (phase !== 'after-lifecycle-cas' || !race) return;
    race = false;
    const [opaqueKey] = await value.backend.listByInternalPrefix();
    const current = await value.lifecycle.get(opaqueKey);
    await value.lifecycle.compareAndSwap({ opaqueKey, expectedGeneration: current.generation, expectedState: 'available', nextState: 'quarantined', authorityBindingSha256: current.authorityBindingSha256 });
  });
  const uploadGrant = grant('upload');
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('race-start'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context });
  await value.uploadPart({ sessionId: started.sessionId, index: 0, bytes, sha256: createHash('sha256').update(bytes).digest('hex'), grant: uploadGrant, context });
  const finalFingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId });
  await assert.rejects(() => value.finalizeUpload({ sessionId: started.sessionId, idempotencyKey: key('race-final', 4), idempotencyFingerprint: finalFingerprint, grant: uploadGrant, context }), { code: 'TRANSFER_LIFECYCLE_STALE' });
  const status = await value.sessionStatus({ sessionId: started.sessionId, grant: uploadGrant, context });
  assert.equal(status.state, 'open');
  assert.equal((await value.lifecycle.get(resume.expected.opaqueKey)).state, 'quarantined');
});

test('range verification and finalize replay both reject a newer quarantine generation', async () => {
  const rangeVector = hostileCase('range-quarantine-race'); const replayVector = hostileCase('stale-finalize-replay');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-current-generation-')); const value = await service(root);
  const uploadGrant = grant('upload');
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('current-start'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context });
  await value.uploadPart({ sessionId: started.sessionId, index: 0, bytes, sha256: createHash('sha256').update(bytes).digest('hex'), grant: uploadGrant, context });
  const finalFingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId });
  const finalArguments = { sessionId: started.sessionId, idempotencyKey: key('current-final'), idempotencyFingerprint: finalFingerprint, grant: uploadGrant, context };
  const receipt = await value.finalizeUpload(finalArguments);
  const originalRead = value.backend.readVerifiedRange.bind(value.backend);
  let quarantine = true;
  value.backend.readVerifiedRange = async (...arguments_) => {
    const range = await originalRead(...arguments_);
    if (quarantine) {
      quarantine = false;
      const current = await value.lifecycle.get(receipt.opaqueKey);
      await value.lifecycle.compareAndSwap({ opaqueKey: receipt.opaqueKey, expectedGeneration: current.generation, expectedState: 'available', nextState: 'quarantined', authorityBindingSha256: current.authorityBindingSha256 });
    }
    return range;
  };
  await assert.rejects(() => value.readRange({ objectId, start: 0, endExclusive: bytes.length, grant: grant('download', 'current-download'), context }), { code: rangeVector.expected.code });
  await assert.rejects(() => value.finalizeUpload(finalArguments), { code: replayVector.expected.code });
});

test('tenant session quotas isolate an authorized tenant before global exhaustion', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-tenant-quota-'));
  const secondBytes = Buffer.from('another tenant-scoped object');
  const secondObjectId = hashObject(1, secondBytes).toString();
  const ids = [objectId, secondObjectId];
  const uploadGrant = customGrant({
    ...baseClaims,
    requestRoot: requestRootForObjectIds(ids),
    nonce: 'tenant-quota',
    operation: 'upload',
    permission: 'content.upload',
  });
  const value = await service(root, async () => {}, { maxSessionsPerTenant: 1 });
  const firstFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const planContext = { ...context, requestObjectIds: ids };
  await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('tenant-quota-one'), idempotencyFingerprint: firstFingerprint, grant: uploadGrant, context: planContext });
  const secondFingerprint = semanticIdempotencyFingerprint({ declaredLength: secondBytes.length, objectId: secondObjectId, operation: 'start-upload', partSize: secondBytes.length });
  await assert.rejects(() => value.startUpload({ objectId: secondObjectId, declaredLength: secondBytes.length, partSize: secondBytes.length, idempotencyKey: key('tenant-quota-two'), idempotencyFingerprint: secondFingerprint, grant: uploadGrant, context: planContext }), { code: 'TRANSFER_LIMIT_EXCEEDED' });
});

test('finalized parts and session state are reclaimed only after the safety deadline', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-transfer-cleanup-')); let value = await service(root);
  const uploadGrant = grant('upload');
  const startFingerprint = semanticIdempotencyFingerprint({ declaredLength: bytes.length, objectId, operation: 'start-upload', partSize: bytes.length });
  const started = await value.startUpload({ objectId, declaredLength: bytes.length, partSize: bytes.length, idempotencyKey: key('cleanup-start'), idempotencyFingerprint: startFingerprint, grant: uploadGrant, context });
  await value.uploadPart({ sessionId: started.sessionId, index: 0, bytes, sha256: createHash('sha256').update(bytes).digest('hex'), grant: uploadGrant, context });
  const finalFingerprint = semanticIdempotencyFingerprint({ operation: 'finalize-upload', sessionId: started.sessionId });
  await value.finalizeUpload({ sessionId: started.sessionId, idempotencyKey: key('cleanup-final'), idempotencyFingerprint: finalFingerprint, grant: uploadGrant, context });
  const sessionPath = join(root, 'sessions', `${started.sessionId}.json`);
  const cleanupAfterUnixMs = JSON.parse(await readFile(sessionPath)).cleanupAfterUnixMs;
  const partsPath = join(root, 'parts', started.sessionId);
  assert.equal((await stat(partsPath)).isDirectory(), true);
  const abandonedTemporary = join(partsPath, `.0.${'f'.repeat(24)}.tmp`);
  await writeFile(abandonedTemporary, Buffer.from('abandoned'));
  value = await service(root);
  assert.equal(await stat(abandonedTemporary).catch(() => null), null);
  assert.equal((await stat(join(partsPath, '0.part'))).isFile(), true);
  const savedNow = nowMs;
  try {
    nowMs = cleanupAfterUnixMs + 1;
    value = await service(root);
    assert.equal(await stat(sessionPath).catch(() => null), null);
    assert.equal(await stat(partsPath).catch(() => null), null);
  } finally { nowMs = savedNow; }
});
