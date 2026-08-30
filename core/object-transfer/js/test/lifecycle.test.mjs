import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { canonicalBytes } from '@opengamevcs/protocol-baseline';
import { FilesystemObjectBackend, LifecycleStore } from '../src/index.mjs';
import { hostileCase } from './vector-cases.mjs';

const vectors = JSON.parse(await readFile(resolve(import.meta.dirname, '../../../../spec/object-transfer/v1/vectors/lifecycle.json')));
const chain = vectors.cases.find(({ id }) => id === 'complete-state-chain').expected;
const sha = (value) => createHash('sha256').update(canonicalBytes(value)).digest('hex');
const key = 'a'.repeat(64); const objectId = `ogvcs:v1:chunk:sha256:${'b'.repeat(64)}`; const authorityBindingSha256 = 'c'.repeat(64); const tenantScopeSha256 = 'e'.repeat(64);
const backendBase = { schemaVersion: 'ogvcs.object-transfer/backend-receipt/v1', opaqueKey: key, objectId, length: 4, payloadSha256: 'd'.repeat(64), durable: true };
const backendReceipt = { ...backendBase, receiptSha256: sha(backendBase) };

test('lifecycle follows only the frozen CAS generation chain', async () => {
  let now = 1_800_000_000_000;
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-'));
  const payload = Buffer.from('lifecycle state-chain fixture');
  const chainObjectId = hashObject(1, payload).toString();
  const backend = await new FilesystemObjectBackend({ root: join(root, 'backend') }).initialize();
  const durable = await backend.createIfAbsent({
    opaqueKey: key, objectId: chainObjectId, length: payload.length, source: payload,
  });
  const store = await new LifecycleStore({
    root: join(root, 'lifecycle'),
    now: () => now,
    deleteObject: (permit) => backend.safeDelete({ permit }),
  }).initialize();
  const records = [await store.createStaged({ opaqueKey: key, objectId: chainObjectId, length: payload.length, authorityBindingSha256, tenantScopeSha256 })];
  for (const [from, to] of [['staged', 'available'], ['available', 'quarantined'], ['quarantined', 'available'], ['available', 'quarantined'], ['quarantined', 'deleting']]) {
    now += to === 'deleting' ? 3_600_001 : 1;
    records.push(await store.compareAndSwap({ opaqueKey: key, expectedGeneration: records.at(-1).generation, expectedState: from, nextState: to, backendReceipt: to === 'available' ? durable : undefined, authorityBindingSha256 }));
  }
  records.push(await store.deleteAuthorized({
    opaqueKey: key,
    expectedGeneration: records.at(-1).generation,
    authorityBindingSha256,
  }));
  assert.deepEqual(records.map(({ state }) => state), chain.states); assert.deepEqual(records.map(({ generation }) => generation), chain.generations);
});

test('stale generations and transition shortcuts never mutate', async () => {
  const vector = hostileCase('stale-lifecycle-generation');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-stale-')); const store = await new LifecycleStore({ root, now: () => 1_800_000_000_000 }).initialize(); await store.createStaged({ opaqueKey: key, objectId, length: 4, authorityBindingSha256, tenantScopeSha256 });
  await assert.rejects(() => store.compareAndSwap({ opaqueKey: key, expectedGeneration: 2, expectedState: 'staged', nextState: 'available', backendReceipt, authorityBindingSha256 }), { code: vector.expected.code }); await assert.rejects(() => store.compareAndSwap({ opaqueKey: key, expectedGeneration: 1, expectedState: 'staged', nextState: 'deleted', authorityBindingSha256 }), { code: vector.expected.code }); assert.equal((await store.get(key)).generation, 1);
});

test('retention and authority are mandatory before a quarantined generation can delete', async () => {
  let now = 1_800_000_000_000; const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-retention-')); const store = await new LifecycleStore({ root, now: () => now }).initialize();
  let record = await store.createStaged({ opaqueKey: key, objectId, length: 4, authorityBindingSha256, tenantScopeSha256 });
  record = await store.compareAndSwap({ opaqueKey: key, expectedGeneration: record.generation, expectedState: 'staged', nextState: 'available', backendReceipt, authorityBindingSha256 });
  record = await store.compareAndSwap({ opaqueKey: key, expectedGeneration: record.generation, expectedState: 'available', nextState: 'quarantined', authorityBindingSha256 });
  await assert.rejects(() => store.compareAndSwap({ opaqueKey: key, expectedGeneration: record.generation, expectedState: 'quarantined', nextState: 'deleting', authorityBindingSha256 }), { code: 'TRANSFER_LIFECYCLE_STALE' });
  await assert.rejects(() => store.compareAndSwap({ opaqueKey: key, expectedGeneration: record.generation, expectedState: 'quarantined', nextState: 'deleting' }), { code: 'TRANSFER_INPUT_INVALID' });
  now = record.retentionUntilUnixMs;
  const deleting = await store.compareAndSwap({ opaqueKey: key, expectedGeneration: record.generation, expectedState: 'quarantined', nextState: 'deleting', authorityBindingSha256 });
  assert.equal(deleting.state, 'deleting');
});

test('expired lifecycle locks recover and persisted records remain schema-closed', async () => {
  let now = 1_800_000_000_000; const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-recovery-')); const store = await new LifecycleStore({ root, now: () => now }).initialize();
  const record = await store.createStaged({ opaqueKey: key, objectId, length: 4, authorityBindingSha256, tenantScopeSha256 });
  const lock = join(root, 'locks', `${key}.lock`);
  await mkdir(lock, { mode: 0o700 });
  await writeFile(join(lock, 'owner.json'), canonicalBytes({ schemaVersion: 'ogvcs.object-transfer/lock-owner/v1', token: 'a'.repeat(48), pid: 999999, acquiredAtUnixMs: now - 10_000, expiresAtUnixMs: now - 1 }));
  await writeFile(join(lock, `.owner.json.${'f'.repeat(24)}.tmp`), Buffer.from('interrupted-owner-write'));
  const available = await store.compareAndSwap({ opaqueKey: key, expectedGeneration: record.generation, expectedState: 'staged', nextState: 'available', backendReceipt, authorityBindingSha256 });
  assert.equal(available.state, 'available');
  const path = join(root, 'records', `${key}.json`);
  const corrupted = JSON.parse(await readFile(path)); corrupted.extra = true; await writeFile(path, canonicalBytes(corrupted));
  await assert.rejects(() => store.get(key), { code: 'TRANSFER_BACKEND_CORRUPT' });
});

test('lifecycle creation enforces its persisted record ceiling atomically', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-quota-'));
  const store = await new LifecycleStore({
    root,
    now: () => 1_800_000_000_000,
    recordsMaximum: 1,
  }).initialize();
  await store.createStaged({
    opaqueKey: key,
    objectId,
    length: 4,
    authorityBindingSha256,
    tenantScopeSha256,
  });
  await writeFile(
    join(root, 'records', `.${key}.json.${'a'.repeat(24)}.tmp`),
    Buffer.from('interrupted lifecycle state write'),
  );
  await assert.rejects(() => store.createStaged({
    opaqueKey: 'f'.repeat(64),
    objectId: `ogvcs:v1:chunk:sha256:${'9'.repeat(64)}`,
    length: 4,
    authorityBindingSha256,
    tenantScopeSha256,
  }), { code: 'TRANSFER_LIMIT_EXCEEDED' });
  assert.equal((await store.listBounded()).length, 1);
});

test('only a current deleting generation can issue a one-use delete permit and deletion replay repairs', async () => {
  let now = 1_800_000_000_000;
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-lifecycle-delete-permit-'));
  const backend = await new FilesystemObjectBackend({ root: join(root, 'backend') }).initialize();
  let loseResponse = true;
  const deleteObject = async (permit) => {
    const receipt = await backend.safeDelete({ permit });
    if (loseResponse) {
      loseResponse = false;
      throw new Error('simulated deletion response loss');
    }
    return receipt;
  };
  const store = await new LifecycleStore({
    root: join(root, 'lifecycle'),
    now: () => now,
    deleteObject,
  }).initialize();
  const payload = Buffer.from('authoritative delete permit fixture');
  const deleteObjectId = hashObject(1, payload).toString();
  const deleteKey = '9'.repeat(64);
  const durable = await backend.createIfAbsent({
    opaqueKey: deleteKey,
    objectId: deleteObjectId,
    length: payload.length,
    source: payload,
  });
  let record = await store.createStaged({
    opaqueKey: deleteKey,
    objectId: deleteObjectId,
    length: payload.length,
    authorityBindingSha256,
    tenantScopeSha256,
  });
  record = await store.compareAndSwap({
    opaqueKey: deleteKey,
    expectedGeneration: record.generation,
    expectedState: 'staged',
    nextState: 'available',
    backendReceipt: durable,
    authorityBindingSha256,
  });
  await assert.rejects(() => backend.safeDelete({
    opaqueKey: deleteKey,
    receiptSha256: durable.receiptSha256,
    expectedGeneration: record.generation,
    authorityBindingSha256,
  }), { code: 'TRANSFER_LIFECYCLE_STALE' });
  assert.equal((await backend.verify(deleteKey)).receiptSha256, durable.receiptSha256);
  record = await store.compareAndSwap({
    opaqueKey: deleteKey,
    expectedGeneration: record.generation,
    expectedState: 'available',
    nextState: 'quarantined',
    authorityBindingSha256,
  });
  now = record.retentionUntilUnixMs;
  record = await store.compareAndSwap({
    opaqueKey: deleteKey,
    expectedGeneration: record.generation,
    expectedState: 'quarantined',
    nextState: 'deleting',
    authorityBindingSha256,
  });
  await assert.rejects(() => store.deleteAuthorized({
    opaqueKey: deleteKey,
    expectedGeneration: record.generation,
    authorityBindingSha256,
  }), /simulated deletion response loss/u);
  assert.equal((await store.get(deleteKey)).state, 'deleting');
  await assert.rejects(() => backend.verify(deleteKey), { code: 'TRANSFER_BACKEND_CONFLICT' });
  const deleted = await store.deleteAuthorized({
    opaqueKey: deleteKey,
    expectedGeneration: record.generation,
    authorityBindingSha256,
  });
  assert.equal(deleted.state, 'deleted');
  assert.equal(deleted.generation, record.generation + 1);
  assert.match(deleted.deletionReceiptSha256, /^[0-9a-f]{64}$/u);
});
