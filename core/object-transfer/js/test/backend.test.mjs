import assert from 'node:assert/strict';
import { mkdtemp, open, readdir, readFile, rename, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { encodeCanonical, hashObject } from '@opengamevcs/object-model';
import { FilesystemObjectBackend, LifecycleStore } from '../src/index.mjs';
import { faultCase, hostileCase } from './vector-cases.mjs';

const CONTRACT = resolve(import.meta.dirname, '../../../../spec/object-transfer/v1');
const vectors = JSON.parse(await readFile(join(CONTRACT, 'vectors/backend.json')));
const create = vectors.cases.find(({ id }) => id === 'create-if-absent');
const range = vectors.cases.find(({ id }) => id === 'half-open-range');
const safeDelete = vectors.cases.find(({ id }) => id === 'safe-delete-receipt');

async function backend() { const root = await mkdtemp(join(tmpdir(), 'ogvcs-object-backend-')); return { root, value: await new FilesystemObjectBackend({ root }).initialize() }; }

test('filesystem backend creates once, verifies metadata, serves bounded ranges, lists, and safely deletes', async () => {
  const { value } = await backend(); const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const first = await value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }); assert.equal(first.created, true); assert.equal(first.receiptSha256.length, 64);
  const second = await value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }); assert.equal(second.created, false); assert.equal(second.receiptSha256, first.receiptSha256);
  const verified = await value.verify(create.expected.opaqueKey); assert.equal(verified.payloadSha256, create.expected.payloadSha256); assert.equal(verified.validatorTag, create.expected.validatorTag);
  const selected = await value.readRange(create.expected.opaqueKey, range.input.start, range.input.endExclusive); assert.equal(selected.bytes.toString('hex'), range.expected.bytesHex); assert.equal(selected.contentSha256, range.expected.contentSha256); assert.match(selected.contentDigest, /^sha-256=:[A-Za-z0-9+/]{43}=:/u);
  assert.deepEqual([...await value.listByInternalPrefix(create.expected.opaqueKey.slice(0, 8))], [create.expected.opaqueKey]);
  await assert.rejects(() => value.safeDelete({
    opaqueKey: create.expected.opaqueKey,
    receiptSha256: first.receiptSha256,
    expectedGeneration: 6,
    authorityBindingSha256: 'a'.repeat(64),
  }), { code: safeDelete.expected.rawCallerCode });
  assert.equal(safeDelete.expected.requiresAuthoritativeOneUsePermit, true);
  assert.equal(safeDelete.expected.responseLossReplay, true);
  assert.equal((await value.verify(create.expected.opaqueKey)).receiptSha256, first.receiptSha256);
});

test('deleted generations can only be recreated through an authoritative lifecycle reupload permit', async () => {
  let now = 1_800_000_000_000;
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-object-reupload-'));
  const value = await new FilesystemObjectBackend({ root: join(root, 'backend') }).initialize();
  const lifecycle = await new LifecycleStore({
    root: join(root, 'lifecycle'),
    now: () => now,
    deleteObject: (permit) => value.safeDelete({ permit }),
  }).initialize();
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const alternateAuthority = 'd'.repeat(64);
  const durable = await value.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
  });
  let record = await lifecycle.createStaged({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    authorityBindingSha256: 'c'.repeat(64),
    tenantScopeSha256: 'e'.repeat(64),
  });
  record = await lifecycle.compareAndSwap({
    opaqueKey: create.expected.opaqueKey,
    expectedGeneration: record.generation,
    expectedState: 'staged',
    nextState: 'available',
    backendReceipt: durable,
    authorityBindingSha256: 'c'.repeat(64),
  });
  record = await lifecycle.compareAndSwap({
    opaqueKey: create.expected.opaqueKey,
    expectedGeneration: record.generation,
    expectedState: 'available',
    nextState: 'quarantined',
    authorityBindingSha256: 'c'.repeat(64),
  });
  now = record.retentionUntilUnixMs;
  record = await lifecycle.compareAndSwap({
    opaqueKey: create.expected.opaqueKey,
    expectedGeneration: record.generation,
    expectedState: 'quarantined',
    nextState: 'deleting',
    authorityBindingSha256: 'c'.repeat(64),
  });
  const deleted = await lifecycle.deleteAuthorized({
    opaqueKey: create.expected.opaqueKey,
    expectedGeneration: record.generation,
    authorityBindingSha256: 'c'.repeat(64),
  });
  await assert.rejects(() => value.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
  }), { code: 'TRANSFER_BACKEND_CONFLICT' });
  const reuploadPermit = await lifecycle.issueReuploadPermit({
    opaqueKey: create.expected.opaqueKey,
    expectedGeneration: deleted.generation,
    nextAuthorityBindingSha256: alternateAuthority,
  });
  const reopened = await value.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
    reuploadPermit,
  });
  assert.equal(reopened.created, true);
  assert.equal(reopened.reopenReceipt.authorityBindingSha256, alternateAuthority);
  assert.equal(reopened.reopenReceipt.expectedDeletedGeneration, deleted.generation);
  const replay = await value.createIfAbsent({
    opaqueKey: create.expected.opaqueKey,
    objectId: create.input.objectId,
    length: bytes.length,
    source: bytes,
  });
  assert.equal(replay.created, false);
  assert.deepEqual(replay.reopenReceipt, reopened.reopenReceipt);
});

test('corrupt payload, unsafe key, and invalid range fail closed', async () => {
  const traversal = hostileCase('backend-key-traversal'); const corrupt = hostileCase('corrupt-stored-payload');
  const { root, value } = await backend(); const bytes = Buffer.from(create.input.bytesHex, 'hex'); await value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes });
  await assert.rejects(() => value.readRange(create.expected.opaqueKey, 1, 1), { code: 'TRANSFER_INPUT_INVALID' }); await assert.rejects(() => value.head(traversal.input.opaqueKey), { code: traversal.expected.code });
  const path = join(root, 'objects', create.expected.opaqueKey.slice(0, 2), create.expected.opaqueKey.slice(2, 4), `${create.expected.opaqueKey}.obj`); const handle = await open(path, 'r+'); try { const stat = await handle.stat(); const byte = Buffer.alloc(1); await handle.read(byte, 0, 1, stat.size - 1); byte[0] ^= 1; await handle.write(byte, 0, 1, stat.size - 1); await handle.sync(); } finally { await handle.close(); }
  await assert.rejects(() => value.verify(create.expected.opaqueKey), { code: corrupt.expected.code });
  await assert.rejects(() => value.readRange(create.expected.opaqueKey, 0, 1), { code: corrupt.expected.code });
});

test('EEXIST crash recovery syncs the target directory before a durable acknowledgement', async () => {
  const vector = faultCase('eexist-retry-directory-sync');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-object-eexist-sync-'));
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const phases = [];
  let inject = true;
  const value = await new FilesystemObjectBackend({ root, fault: async (phase) => {
    phases.push(phase);
    if (inject && phase === 'after-link') { inject = false; throw new Error('simulated crash after link'); }
  } }).initialize();
  await assert.rejects(() => value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }), { code: 'TRANSFER_BACKEND_IO' });
  phases.length = 0;
  const replay = await value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes });
  assert.equal(replay.created, vector.expected.createdOnRetry);
  assert.deepEqual(phases, ['before-file-sync', 'after-file-sync', 'after-directory-sync']);
});

test('public OGVCS-002 metadata validation accepts a valid schema and rejects identity-only bytes', async () => {
  const vector = hostileCase('malformed-metadata-identity');
  const { value } = await backend();
  const valid = await readFile(resolve(
    import.meta.dirname,
    '../../../../spec/repository-format/v1/vectors/objects/02-content-manifest.cbor',
  ));
  const validObjectId = hashObject(2, valid).toString();
  const accepted = await value.createIfAbsent({
    opaqueKey: 'e'.repeat(64), objectId: validObjectId, length: valid.length, source: valid,
  });
  assert.equal(accepted.objectId, validObjectId);
  const malformed = encodeCanonical(new Map([[0, 1], [1, 2]]));
  const objectId = hashObject(2, malformed).toString();
  await assert.rejects(() => value.createIfAbsent({
    opaqueKey: 'f'.repeat(64), objectId, length: malformed.length, source: malformed,
  }), { code: vector.expected.code });
  assert.equal(await value.head('f'.repeat(64)), null);
});

test('every durability fault is unacknowledged and a bounded retry converges on one verified object', async () => {
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  const cases = [faultCase('before-temp-file-sync'), faultCase('after-file-sync-before-link'), faultCase('after-link-before-directory-sync'), faultCase('after-durability-before-lifecycle-cas')];
  for (const { input: { phase } } of cases) {
    const root = await mkdtemp(join(tmpdir(), 'ogvcs-object-fault-'));
    let inject = true;
    const faulty = await new FilesystemObjectBackend({ root, fault: async (current) => { if (inject && current === phase) { inject = false; throw new Error(`fault:${phase}`); } } }).initialize();
    await assert.rejects(() => faulty.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }), { code: 'TRANSFER_BACKEND_IO' });
    const recovered = await new FilesystemObjectBackend({ root }).initialize();
    const receipt = await recovered.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes });
    assert.equal((await recovered.verify(create.expected.opaqueKey)).receiptSha256, receipt.receiptSha256);
    assert.deepEqual([...await recovered.listByInternalPrefix()], [create.expected.opaqueKey]);
  }
});

test('a symlinked object fanout fails closed without writing outside the backend', { skip: process.platform === 'win32' }, async () => {
  const vector = hostileCase('symlink-object-fanout');
  const { root, value } = await backend(); const outside = await mkdtemp(join(tmpdir(), 'ogvcs-object-outside-'));
  await symlink(outside, join(root, 'objects', create.expected.opaqueKey.slice(0, 2)), 'dir');
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  await assert.rejects(() => value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }), { code: vector.expected.code });
  assert.deepEqual(await readdir(outside), []);
});

test('replacing a pinned object ancestor with a symlink cannot escape the backend root', { skip: process.platform === 'win32' }, async () => {
  const vector = hostileCase('symlink-object-ancestor');
  const { root, value } = await backend(); const outside = await mkdtemp(join(tmpdir(), 'ogvcs-object-ancestor-outside-'));
  await rename(join(root, 'objects'), join(root, 'objects-original'));
  await symlink(outside, join(root, 'objects'), 'dir');
  const bytes = Buffer.from(create.input.bytesHex, 'hex');
  await assert.rejects(() => value.createIfAbsent({ opaqueKey: create.expected.opaqueKey, objectId: create.input.objectId, length: bytes.length, source: bytes }), { code: vector.expected.code });
  assert.deepEqual(await readdir(outside), []);
});

test('initialization reclaims only expired bounded backend temporaries', async () => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-object-temporary-cleanup-'));
  await new FilesystemObjectBackend({ root }).initialize();
  const stale = join(root, 'temporary', `${'a'.repeat(48)}.tmp`);
  await writeFile(stale, Buffer.from('crash residue'));
  const twoHoursAgo = new Date(Date.now() - 7_200_000);
  await utimes(stale, twoHoursAgo, twoHoursAgo);
  await new FilesystemObjectBackend({ root }).initialize();
  assert.deepEqual(await readdir(join(root, 'temporary')), []);
});
