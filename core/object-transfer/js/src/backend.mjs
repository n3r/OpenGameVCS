import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, open, opendir, unlink } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import {
  ObjectRef,
  Sha256Writer,
  createObjectHashWriter,
  decodeCanonical,
  equalBytes,
  validateKnownSchema,
} from '@opengamevcs/object-model';
import { canonicalBytes, rfc9530Sha256 } from '@opengamevcs/protocol-baseline';
import { consumeDeletePermit, consumeReuploadPermit } from './delete-permit.mjs';
import { captureTrustedBackend } from './backend-port.mjs';
import { mapIo, transferError } from './errors.mjs';
import {
  assertPinnedDirectory,
  atomicJsonWrite,
  pinPlainDirectory,
  pinPlainDirectoryIfExists,
  readExact,
  readJson,
  syncDirectory,
  withRecoverableDirectoryLock,
  writeAll,
} from './fs-util.mjs';

const MAGIC = Buffer.from('OGVCSOB1', 'ascii');
const FIXED_HEADER = 50;
const KEY = /^[0-9a-f]{64}$/u;
const SHA = KEY;
const METADATA_WORKING_BYTES = 67_108_864;
const DIRECTORY_ENTRIES_MAXIMUM = 4096;
const DELETION_HISTORY_MAXIMUM = 64;
const LEGACY_DELETE_INTENT_KEYS = [
  'authorityBindingSha256',
  'expectedGeneration',
  'opaqueKey',
  'priorReceiptSha256',
  'schemaVersion',
].sort().join('\0');
const BACKEND_FENCE_KEYS = ['deletions', 'opaqueKey', 'schemaVersion'].sort().join('\0');
const DELETION_ENTRY_KEYS = [
  'authorityBindingSha256',
  'deletedGeneration',
  'deletionReceiptSha256',
  'expectedDeletingGeneration',
  'length',
  'objectId',
  'priorReceiptSha256',
  'reopenAuthorityBindingSha256',
  'reopenReceiptSha256',
  'reopenedStagedGeneration',
].sort().join('\0');
export const FILESYSTEM_LIMITS = Object.freeze({
  objectBytesMaximum: 67_108_864,
  rangeBytesMaximum: 8_388_608,
  listMaximum: 4096,
  directoryEntriesMaximum: DIRECTORY_ENTRIES_MAXIMUM,
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
let FILESYSTEM_BACKEND_DEFINITION;
const FILESYSTEM_BACKEND_RECORDS = new WeakMap();

function opaqueKeyValue(value) {
  if (typeof value !== 'string' || !KEY.test(value)) transferError('TRANSFER_INPUT_INVALID', 'opaque backend key is invalid');
  return value;
}

function lengthValue(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    transferError('TRANSFER_LIMIT_EXCEEDED', `${label} is outside the configured bound`);
  }
  return value;
}

function positiveGeneration(value) {
  if (!Number.isSafeInteger(value) || value < 1) transferError('TRANSFER_INPUT_INVALID', 'delete generation is invalid');
  return value;
}

function canonicalObjectId(value, code = 'TRANSFER_BACKEND_CORRUPT') {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value) throw new TypeError('ObjectID is not canonical');
    return value;
  } catch (error) {
    transferError(code, 'backend lifecycle fence ObjectID is invalid', { cause: error });
  }
}

function deletionReceipt(binding) {
  const deletion = {
    schemaVersion: 'ogvcs.object-transfer/backend-delete-receipt/v1',
    opaqueKey: binding.opaqueKey,
    priorReceiptSha256: binding.priorReceiptSha256,
    expectedGeneration: binding.expectedGeneration,
    authorityBindingSha256: binding.authorityBindingSha256,
    deleted: true,
  };
  return Object.freeze({ ...deletion, receiptSha256: sha256(canonicalBytes(deletion)) });
}

function deletionEntry(binding) {
  const receipt = deletionReceipt(binding);
  return Object.freeze({
    objectId: canonicalObjectId(binding.objectId, 'TRANSFER_LIFECYCLE_STALE'),
    length: binding.length,
    expectedDeletingGeneration: binding.expectedGeneration,
    deletedGeneration: binding.expectedGeneration + 1,
    priorReceiptSha256: binding.priorReceiptSha256,
    authorityBindingSha256: binding.authorityBindingSha256,
    deletionReceiptSha256: receipt.receiptSha256,
    reopenedStagedGeneration: null,
    reopenAuthorityBindingSha256: null,
    reopenReceiptSha256: null,
  });
}

function reopenReceipt(binding) {
  const reopened = {
    schemaVersion: 'ogvcs.object-transfer/backend-reopen-receipt/v1',
    opaqueKey: binding.opaqueKey,
    objectId: binding.objectId,
    length: binding.length,
    expectedDeletedGeneration: binding.expectedDeletedGeneration,
    stagedGeneration: binding.expectedDeletedGeneration + 1,
    deletionReceiptSha256: binding.deletionReceiptSha256,
    authorityBindingSha256: binding.nextAuthorityBindingSha256,
    reopened: true,
  };
  return Object.freeze({ ...reopened, receiptSha256: sha256(canonicalBytes(reopened)) });
}

function reopenReceiptFromEntry(opaqueKey, entry) {
  if (entry.reopenedStagedGeneration === null
      || entry.reopenAuthorityBindingSha256 === null
      || entry.reopenReceiptSha256 === null) {
    return null;
  }
  const receipt = reopenReceipt({
    opaqueKey,
    objectId: entry.objectId,
    length: entry.length,
    expectedDeletedGeneration: entry.deletedGeneration,
    deletionReceiptSha256: entry.deletionReceiptSha256,
    nextAuthorityBindingSha256: entry.reopenAuthorityBindingSha256,
  });
  if (receipt.receiptSha256 !== entry.reopenReceiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle reopen receipt history differs');
  }
  return receipt;
}

function validateDeletionEntry(value, opaqueKey) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== DELETION_ENTRY_KEYS
      || !SHA.test(value.authorityBindingSha256 ?? '') || !SHA.test(value.priorReceiptSha256 ?? '')
      || !SHA.test(value.deletionReceiptSha256 ?? '')
      || !Number.isSafeInteger(value.expectedDeletingGeneration) || value.expectedDeletingGeneration < 1
      || value.deletedGeneration !== value.expectedDeletingGeneration + 1
      || !Number.isSafeInteger(value.length) || value.length < 0
      || value.length > FILESYSTEM_LIMITS.objectBytesMaximum) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle deletion history is invalid');
  }
  canonicalObjectId(value.objectId);
  const expected = deletionReceipt({
    opaqueKey,
    priorReceiptSha256: value.priorReceiptSha256,
    expectedGeneration: value.expectedDeletingGeneration,
    authorityBindingSha256: value.authorityBindingSha256,
  });
  if (value.deletionReceiptSha256 !== expected.receiptSha256) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle deletion receipt history differs');
  }
  const hasReopen = value.reopenedStagedGeneration !== null
    || value.reopenAuthorityBindingSha256 !== null || value.reopenReceiptSha256 !== null;
  if (hasReopen && (value.reopenedStagedGeneration !== value.deletedGeneration + 1
      || !SHA.test(value.reopenAuthorityBindingSha256 ?? '')
      || !SHA.test(value.reopenReceiptSha256 ?? ''))) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle reopen history is invalid');
  }
  if (!hasReopen && !(value.reopenedStagedGeneration === null
      && value.reopenAuthorityBindingSha256 === null && value.reopenReceiptSha256 === null)) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle reopen history is partial');
  }
  return Object.freeze(value);
}

function validateBackendFence(value, key, legacyBinding = null) {
  if (value && value.schemaVersion === 'ogvcs.object-transfer/backend-delete-intent/v1') {
    if (!legacyBinding || Object.keys(value).sort().join('\0') !== LEGACY_DELETE_INTENT_KEYS
        || value.opaqueKey !== key || value.priorReceiptSha256 !== legacyBinding.priorReceiptSha256
        || value.expectedGeneration !== legacyBinding.expectedGeneration
        || value.authorityBindingSha256 !== legacyBinding.authorityBindingSha256) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'legacy backend deletion intent cannot be migrated safely');
    }
    const receipt = deletionReceipt(value);
    return Object.freeze({
      value: Object.freeze({
        schemaVersion: 'ogvcs.object-transfer/backend-lifecycle-fence/v1',
        opaqueKey: key,
        deletions: Object.freeze([Object.freeze({
          objectId: canonicalObjectId(legacyBinding.objectId),
          length: legacyBinding.length,
          expectedDeletingGeneration: value.expectedGeneration,
          deletedGeneration: value.expectedGeneration + 1,
          priorReceiptSha256: value.priorReceiptSha256,
          authorityBindingSha256: value.authorityBindingSha256,
          deletionReceiptSha256: receipt.receiptSha256,
          reopenedStagedGeneration: null,
          reopenAuthorityBindingSha256: null,
          reopenReceiptSha256: null,
        })]),
      }),
      legacy: true,
    });
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== BACKEND_FENCE_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/backend-lifecycle-fence/v1'
      || value.opaqueKey !== key || !Array.isArray(value.deletions)
      || value.deletions.length < 1 || value.deletions.length > DELETION_HISTORY_MAXIMUM) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence is invalid');
  }
  const deletions = value.deletions.map((entry) => validateDeletionEntry(entry, key));
  for (let index = 1; index < deletions.length; index += 1) {
    const prior = deletions[index - 1];
    const current = deletions[index];
    if (prior.reopenedStagedGeneration === null
        || current.expectedDeletingGeneration <= prior.reopenedStagedGeneration) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'backend lifecycle fence generations are not monotonic');
    }
  }
  return Object.freeze({
    value: Object.freeze({ ...value, deletions: Object.freeze(deletions) }),
    legacy: false,
  });
}

function sourceOf(value) {
  if (value instanceof Uint8Array) return (async function* () { if (value.byteLength > 0) yield value; })();
  if (value?.[Symbol.asyncIterator]) return value;
  transferError('TRANSFER_INPUT_INVALID', 'object source must be bytes or an async iterable');
}

function objectModelFailure(error, message) {
  if (error?.code?.startsWith?.('TRANSFER_')) throw error;
  if (typeof error?.code === 'string') transferError('TRANSFER_BACKEND_CORRUPT', message, { cause: error });
  throw error;
}

function validateMetadata(reference, payload, maximum) {
  if (reference.kind === 1) return;
  try {
    const value = decodeCanonical(payload, {
      maxBytes: maximum,
      maxWorkingBytes: METADATA_WORKING_BYTES,
    });
    // The filesystem backend has no repository registry/operation authority;
    // validate the complete public layer-two OGVCS-002 schema explicitly.
    validateKnownSchema(value, reference.kind, {
      semantic: false,
      maxWorkingBytes: METADATA_WORKING_BYTES,
    });
  } catch (error) {
    objectModelFailure(error, 'metadata object is not canonical OGVCS-002 content');
  }
}

export class FilesystemObjectBackend {
  #fault;
  #rootPin;
  #objectsPin;
  #temporaryPin;
  #locksPin;
  #deleteIntentsPin;

  constructor({
    root,
    maxObjectBytes = FILESYSTEM_LIMITS.objectBytesMaximum,
    maxRangeBytes = FILESYSTEM_LIMITS.rangeBytesMaximum,
    fault = async () => {},
  } = {}) {
    if (new.target !== FilesystemObjectBackend) {
      transferError('TRANSFER_INPUT_INVALID', 'filesystem backend subclasses are not trusted adapters');
    }
    if (typeof root !== 'string' || !isAbsolute(root) || root.includes('\0')) {
      transferError('TRANSFER_INPUT_INVALID', 'filesystem backend root must be absolute');
    }
    if (typeof fault !== 'function') transferError('TRANSFER_INPUT_INVALID', 'fault hook must be callable');
    this.root = resolve(root);
    this.objectsRoot = join(this.root, 'objects');
    this.temporaryRoot = join(this.root, 'temporary');
    this.locksRoot = join(this.root, 'locks');
    this.deleteIntentsRoot = join(this.root, 'delete-intents');
    this.maxObjectBytes = lengthValue(maxObjectBytes, FILESYSTEM_LIMITS.objectBytesMaximum, 'maxObjectBytes');
    this.maxRangeBytes = lengthValue(maxRangeBytes, FILESYSTEM_LIMITS.rangeBytesMaximum, 'maxRangeBytes');
    this.#fault = fault;
    FILESYSTEM_BACKEND_RECORDS.set(this, captureTrustedBackend(this, {
      schemaVersion: 'ogvcs.object-transfer/backend-capabilities/v1',
      backendKind: 'filesystem',
      profile: 'storage.opengamevcs/filesystem@1',
      objectBytesMaximum: this.maxObjectBytes,
      rangeBytesMaximum: this.maxRangeBytes,
      createIfAbsent: true,
      exactMetadata: true,
      wholeObjectVerification: true,
      verifiedRanges: true,
      boundedPrefixList: true,
      generationFencedDelete: true,
      multipartEtagIsDigest: false,
    }, FILESYSTEM_BACKEND_DEFINITION));
  }

  async initialize({ parentPin = null } = {}) {
    this.#rootPin = await pinPlainDirectory(this.root, { parentPin });
    this.#objectsPin = await pinPlainDirectory(this.objectsRoot, { parentPin: this.#rootPin });
    this.#temporaryPin = await pinPlainDirectory(this.temporaryRoot, { parentPin: this.#rootPin });
    this.#locksPin = await pinPlainDirectory(this.locksRoot, { parentPin: this.#rootPin });
    this.#deleteIntentsPin = await pinPlainDirectory(this.deleteIntentsRoot, { parentPin: this.#rootPin });
    await this.#cleanupTemporary();
    return this;
  }

  async #cleanupTemporary() {
    let scanned = 0;
    let changed = false;
    const now = Date.now();
    await assertPinnedDirectory(this.#temporaryPin);
    const directory = await opendir(this.temporaryRoot);
    try {
      for await (const entry of directory) {
        scanned += 1;
        if (scanned > DIRECTORY_ENTRIES_MAXIMUM) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'backend temporary directory exceeds its scan bound');
        }
        if (!entry.isFile() || !/^[0-9a-f]{48}\.tmp$/u.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'backend temporary directory contains an unexpected entry');
        }
        const path = join(this.temporaryRoot, entry.name);
        let stat;
        try { stat = await lstat(path); } catch (error) {
          if (error?.code === 'ENOENT') continue;
          mapIo(error, 'backend temporary entry inspection failed');
        }
        if (!stat.isFile() || stat.isSymbolicLink()) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'backend temporary entry is not a plain file');
        }
        // The per-object lock lease is one hour. Retaining younger files avoids
        // deleting another process's in-flight create; older files cannot have
        // a valid owning lock and are crash residue.
        if (stat.mtimeMs + 3_600_000 <= now) {
          await assertPinnedDirectory(this.#temporaryPin);
          await unlink(path);
          changed = true;
        }
      }
    } finally { await directory.close().catch(() => {}); }
    if (changed) await syncDirectory(this.temporaryRoot, this.#temporaryPin);
  }

  async #assertRoots() {
    if (!this.#rootPin) transferError('TRANSFER_BACKEND_IO', 'filesystem backend is not initialized');
    await assertPinnedDirectory(this.#rootPin);
    await assertPinnedDirectory(this.#objectsPin);
    await assertPinnedDirectory(this.#temporaryPin);
    await assertPinnedDirectory(this.#locksPin);
    await assertPinnedDirectory(this.#deleteIntentsPin);
  }

  async #fanout(key, create) {
    await this.#assertRoots();
    const firstPath = join(this.objectsRoot, key.slice(0, 2));
    const firstPin = create
      ? await pinPlainDirectory(firstPath, { parentPin: this.#objectsPin })
      : await pinPlainDirectoryIfExists(firstPath, { parentPin: this.#objectsPin });
    if (!firstPin) return null;
    const secondPath = join(firstPath, key.slice(2, 4));
    const secondPin = create
      ? await pinPlainDirectory(secondPath, { parentPin: firstPin })
      : await pinPlainDirectoryIfExists(secondPath, { parentPin: firstPin });
    if (!secondPin) return null;
    await assertPinnedDirectory(this.#objectsPin);
    await assertPinnedDirectory(firstPin);
    await assertPinnedDirectory(secondPin);
    return Object.freeze({ directory: secondPath, directoryPin: secondPin, path: join(secondPath, `${key}.obj`) });
  }

  async #path(key, create = false) {
    return this.#fanout(opaqueKeyValue(key), create);
  }

  #fencePath(key) { return join(this.deleteIntentsRoot, `${opaqueKeyValue(key)}.json`); }

  async #readFence(key, legacyBinding = null) {
    const value = await readJson(this.#fencePath(key), 1024 * 1024, {
      directoryPin: this.#deleteIntentsPin,
    });
    return value === null ? null : validateBackendFence(value, key, legacyBinding);
  }

  async #writeFence(key, value, lockGuard) {
    await atomicJsonWrite(this.#fencePath(key), value, {
      directoryPin: this.#deleteIntentsPin,
      lockGuard,
    });
    return validateBackendFence(value, key).value;
  }

  async #header(handle, key) {
    const fixed = await readExact(handle, FIXED_HEADER, 0);
    if (!fixed.subarray(0, 8).equals(MAGIC)) transferError('TRANSFER_BACKEND_CORRUPT', 'stored object magic is invalid');
    const objectIdBytes = fixed.readUInt16BE(8);
    const length = Number(fixed.readBigUInt64BE(10));
    if (objectIdBytes < 1 || objectIdBytes > 144 || !Number.isSafeInteger(length) || length > this.maxObjectBytes) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'stored object header is invalid');
    }
    const objectId = (await readExact(handle, objectIdBytes, FIXED_HEADER)).toString('ascii');
    let reference;
    try { reference = ObjectRef.parse(objectId); }
    catch (error) { transferError('TRANSFER_BACKEND_CORRUPT', 'stored ObjectID is invalid', { cause: error }); }
    if (reference.toString() !== objectId) transferError('TRANSFER_BACKEND_CORRUPT', 'stored ObjectID is not canonical');
    const stat = await handle.stat();
    const payloadOffset = FIXED_HEADER + objectIdBytes;
    if (!stat.isFile() || stat.size !== payloadOffset + length) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'stored object length differs from its frame');
    }
    return Object.freeze({
      key,
      objectId,
      reference,
      length,
      payloadOffset,
      payloadSha256: fixed.subarray(18, 50).toString('hex'),
    });
  }

  #receipt(header) {
    const receipt = Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/backend-receipt/v1',
      opaqueKey: header.key,
      objectId: header.objectId,
      length: header.length,
      payloadSha256: header.payloadSha256,
      durable: true,
    });
    return Object.freeze({ ...receipt, receiptSha256: sha256(canonicalBytes(receipt)) });
  }

  async #withKeyLock(key, operation) {
    return withRecoverableDirectoryLock({
      rootPin: this.#locksPin,
      name: key,
      now: () => Date.now(),
      leaseMilliseconds: 3_600_000,
      busyCode: 'TRANSFER_BACKEND_CONFLICT',
      busyMessage: 'backend object is busy',
      operation,
    });
  }

  async createIfAbsent({ opaqueKey, objectId, length, source, reuploadPermit = null }) {
    const key = opaqueKeyValue(opaqueKey);
    return this.#withKeyLock(key, (lockGuard) => this.#createIfAbsentUnlocked({
      key,
      objectId,
      length,
      source,
      reuploadPermit,
      lockGuard,
    }));
  }

  async #createIfAbsentUnlocked({ key, objectId, length, source, reuploadPermit, lockGuard }) {
    lengthValue(length, this.maxObjectBytes, 'object length');
    let reference;
    try { reference = ObjectRef.parse(objectId); }
    catch (error) { transferError('TRANSFER_INPUT_INVALID', 'ObjectID is invalid', { cause: error }); }
    if (reference.toString() !== objectId) transferError('TRANSFER_INPUT_INVALID', 'ObjectID is not canonical');
    const reuploadBinding = reuploadPermit === null ? null : consumeReuploadPermit(reuploadPermit);
    const target = await this.#path(key, true);
    const tempPath = join(this.temporaryRoot, `${randomBytes(24).toString('hex')}.tmp`);
    let handle;
    let linked = false;
    try {
      await assertPinnedDirectory(this.#temporaryPin);
      handle = await open(tempPath, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0), 0o600);
      await assertPinnedDirectory(this.#temporaryPin);
      const objectText = Buffer.from(reference.toString(), 'ascii');
      const fixed = Buffer.alloc(FIXED_HEADER);
      MAGIC.copy(fixed);
      fixed.writeUInt16BE(objectText.length, 8);
      fixed.writeBigUInt64BE(BigInt(length), 10);
      await writeAll(handle, Buffer.concat([fixed, objectText]));
      const objectHash = createObjectHashWriter(reference.kind, {
        maxChunkBytes: this.maxObjectBytes,
        maxMetadataBytes: this.maxObjectBytes,
      });
      const payloadHash = new Sha256Writer();
      const metadata = reference.kind === 1 ? null : Buffer.alloc(length);
      let consumed = 0;
      for await (const input of sourceOf(source)) {
        if (!(input instanceof Uint8Array) || input.byteLength === 0) {
          transferError('TRANSFER_INPUT_INVALID', 'object source fragment is invalid');
        }
        const chunk = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
        if (chunk.length > length - consumed) transferError('TRANSFER_BACKEND_CORRUPT', 'object source exceeds declared length');
        if (metadata) chunk.copy(metadata, consumed);
        consumed += chunk.length;
        objectHash.update(chunk);
        payloadHash.update(chunk);
        await writeAll(handle, chunk);
      }
      if (consumed !== length) transferError('TRANSFER_BACKEND_CORRUPT', 'object source is shorter than declared length');
      const actual = objectHash.finish();
      if (!equalBytes(actual.digest, reference.digest)) transferError('TRANSFER_BACKEND_CORRUPT', 'object bytes do not match ObjectID');
      if (metadata) validateMetadata(reference, metadata, this.maxObjectBytes);
      const payloadSha256 = Buffer.from(payloadHash.finish().bytes);
      await writeAll(handle, payloadSha256, 18);
      await this.#fault('before-file-sync');
      await handle.sync();
      await this.#fault('after-file-sync');
      await handle.close();
      handle = undefined;
      await assertPinnedDirectory(this.#temporaryPin);
      await assertPinnedDirectory(target.directoryPin);
      const fence = await this.#readFence(key, {
        objectId: reference.toString(),
        length,
        priorReceiptSha256: null,
        expectedGeneration: null,
        authorityBindingSha256: null,
      });
      let reopenFromFence = null;
      let reopenBinding = null;
      if (fence) {
        const latest = fence.value.deletions.at(-1);
        if (latest.objectId !== reference.toString() || latest.length !== length) {
          transferError('TRANSFER_BACKEND_CONFLICT', 'backend object has an active deletion fence');
        }
        if (latest.reopenedStagedGeneration === null) {
          if (!reuploadBinding
              || reuploadBinding.opaqueKey !== key
              || reuploadBinding.objectId !== reference.toString()
              || reuploadBinding.length !== length
              || reuploadBinding.expectedDeletedGeneration !== latest.deletedGeneration
              || reuploadBinding.deletionReceiptSha256 !== latest.deletionReceiptSha256
              || reuploadBinding.priorAuthorityBindingSha256 !== latest.authorityBindingSha256) {
            transferError('TRANSFER_BACKEND_CONFLICT', 'backend object has an active deletion fence');
          }
          reopenBinding = reuploadBinding;
        } else {
          reopenFromFence = reopenReceiptFromEntry(key, latest);
        }
      } else if (reuploadBinding) {
        transferError('TRANSFER_LIFECYCLE_STALE', 'deleted-generation reupload permit is stale');
      }
      await lockGuard.assertOwned();
      try { await link(tempPath, target.path); linked = true; }
      catch (error) { if (error?.code !== 'EEXIST') throw error; }
      if (linked) await this.#fault('after-link');
      // EEXIST may be recovery of a prior crash after link and before fsync.
      // Always sync the target directory before issuing a durable receipt.
      await syncDirectory(target.directory, target.directoryPin);
      await lockGuard.assertOwned();
      await this.#fault('after-directory-sync');
      await unlink(tempPath).catch((error) => { if (error?.code !== 'ENOENT') throw error; });
      await syncDirectory(this.temporaryRoot, this.#temporaryPin);
      const verified = await this.#verifyUnlocked(key);
      if (verified.objectId !== reference.toString() || verified.length !== length) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'existing backend object differs');
      }
      if (reopenBinding) {
        const latest = fence.value.deletions.at(-1);
        const receipt = reopenReceipt(reopenBinding);
        await this.#writeFence(key, {
          schemaVersion: 'ogvcs.object-transfer/backend-lifecycle-fence/v1',
          opaqueKey: key,
          deletions: [
            ...fence.value.deletions.slice(0, -1),
            Object.freeze({
              ...latest,
              reopenedStagedGeneration: latest.deletedGeneration + 1,
              reopenAuthorityBindingSha256: reopenBinding.nextAuthorityBindingSha256,
              reopenReceiptSha256: receipt.receiptSha256,
            }),
          ],
        }, lockGuard);
        reopenFromFence = receipt;
      }
      return Object.freeze({ ...verified, created: linked, reopenReceipt: reopenFromFence });
    } catch (error) {
      await handle?.close().catch(() => {});
      const removed = await unlink(tempPath).then(() => true).catch(() => false);
      if (removed) await syncDirectory(this.temporaryRoot, this.#temporaryPin).catch(() => {});
      if (error?.code?.startsWith?.('TRANSFER_')) throw error;
      if (typeof error?.code === 'string' && !/^E[A-Z0-9]+$/u.test(error.code)) {
        transferError('TRANSFER_BACKEND_CORRUPT', 'object verification failed', { cause: error });
      }
      mapIo(error);
    }
  }

  async head(opaqueKey) {
    const key = opaqueKeyValue(opaqueKey);
    const target = await this.#path(key, false);
    if (!target) return null;
    let handle;
    try {
      await assertPinnedDirectory(target.directoryPin);
      handle = await open(target.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      await assertPinnedDirectory(target.directoryPin);
      const header = await this.#header(handle, key);
      return Object.freeze({ ...header, reference: undefined });
    } catch (error) {
      if (error?.code === 'ENOENT') return null;
      if (error?.code?.startsWith?.('TRANSFER_')) throw error;
      mapIo(error);
    } finally { await handle?.close().catch(() => {}); }
  }

  async #verifyHandle(handle, key, range = null) {
    const header = await this.#header(handle, key);
    if (range && (!Number.isSafeInteger(range.start) || !Number.isSafeInteger(range.endExclusive)
        || range.start < 0 || range.endExclusive <= range.start || range.endExclusive > header.length
        || range.endExclusive - range.start > this.maxRangeBytes)) {
      transferError('TRANSFER_INPUT_INVALID', 'range is invalid or exceeds its bound');
    }
    const objectHash = createObjectHashWriter(header.reference.kind, {
      maxChunkBytes: this.maxObjectBytes,
      maxMetadataBytes: this.maxObjectBytes,
    });
    const payloadHash = new Sha256Writer();
    const metadata = header.reference.kind === 1 ? null : Buffer.alloc(header.length);
    const selected = range ? Buffer.alloc(range.endExclusive - range.start) : null;
    let offset = 0;
    while (offset < header.length) {
      const take = Math.min(64 * 1024, header.length - offset);
      const chunk = await readExact(handle, take, header.payloadOffset + offset);
      if (metadata) chunk.copy(metadata, offset);
      if (selected) {
        const overlapStart = Math.max(offset, range.start);
        const overlapEnd = Math.min(offset + chunk.length, range.endExclusive);
        if (overlapStart < overlapEnd) {
          chunk.copy(selected, overlapStart - range.start, overlapStart - offset, overlapEnd - offset);
        }
      }
      objectHash.update(chunk);
      payloadHash.update(chunk);
      offset += chunk.length;
    }
    const actual = objectHash.finish();
    const payload = payloadHash.finish();
    if (!equalBytes(actual.digest, header.reference.digest)
        || Buffer.from(payload.bytes).toString('hex') !== header.payloadSha256) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'stored payload verification failed');
    }
    if (metadata) validateMetadata(header.reference, metadata, this.maxObjectBytes);
    const receipt = this.#receipt(header);
    const base = Object.freeze({ ...receipt, validatorTag: `sha256-${header.payloadSha256}` });
    if (!selected) return base;
    return Object.freeze({
      ...base,
      bytes: selected,
      start: range.start,
      endExclusive: range.endExclusive,
      totalLength: header.length,
      contentSha256: sha256(selected),
      contentDigest: rfc9530Sha256(selected, {
        maxBytes: this.maxRangeBytes,
        maxWorkingMemoryBytes: this.maxRangeBytes * 2,
      }),
    });
  }

  async #verifyUnlocked(key) {
    const target = await this.#path(key, false);
    if (!target) transferError('TRANSFER_BACKEND_CONFLICT', 'backend object is absent');
    let handle;
    try {
      await assertPinnedDirectory(target.directoryPin);
      handle = await open(target.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      await assertPinnedDirectory(target.directoryPin);
      return await this.#verifyHandle(handle, key);
    } catch (error) {
      if (error?.code === 'ENOENT') transferError('TRANSFER_BACKEND_CONFLICT', 'backend object is absent');
      if (error?.code?.startsWith?.('TRANSFER_')) throw error;
      if (typeof error?.code === 'string' && !/^E[A-Z0-9]+$/u.test(error.code)) {
        transferError('TRANSFER_BACKEND_CORRUPT', 'stored object is not valid OGVCS-002 content', { cause: error });
      }
      mapIo(error);
    } finally { await handle?.close().catch(() => {}); }
  }

  async verify(opaqueKey) { return this.#verifyUnlocked(opaqueKeyValue(opaqueKey)); }

  async readVerifiedRange(opaqueKey, start, endExclusive) {
    const key = opaqueKeyValue(opaqueKey);
    const target = await this.#path(key, false);
    if (!target) transferError('TRANSFER_BACKEND_CONFLICT', 'backend object is absent');
    let handle;
    try {
      await assertPinnedDirectory(target.directoryPin);
      handle = await open(target.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      await assertPinnedDirectory(target.directoryPin);
      return await this.#verifyHandle(handle, key, { start, endExclusive });
    } catch (error) {
      if (error?.code === 'ENOENT') transferError('TRANSFER_BACKEND_CONFLICT', 'backend object is absent');
      if (error?.code?.startsWith?.('TRANSFER_')) throw error;
      if (typeof error?.code === 'string' && !/^E[A-Z0-9]+$/u.test(error.code)) {
        transferError('TRANSFER_BACKEND_CORRUPT', 'stored object is not valid OGVCS-002 content', { cause: error });
      }
      mapIo(error);
    } finally { await handle?.close().catch(() => {}); }
  }

  async readRange(opaqueKey, start, endExclusive) {
    return this.readVerifiedRange(opaqueKey, start, endExclusive);
  }

  async safeDelete({ permit } = {}) {
    const binding = consumeDeletePermit(permit);
    const key = opaqueKeyValue(binding.opaqueKey);
    positiveGeneration(binding.expectedGeneration);
    if (!SHA.test(binding.priorReceiptSha256 ?? '') || !SHA.test(binding.authorityBindingSha256 ?? '')) {
      transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleting-generation permit binding is invalid');
    }
    return this.#withKeyLock(key, async (lockGuard) => {
      const persisted = await this.#readFence(key, {
        objectId: binding.objectId,
        length: binding.length,
        priorReceiptSha256: binding.priorReceiptSha256,
        expectedGeneration: binding.expectedGeneration,
        authorityBindingSha256: binding.authorityBindingSha256,
      });
      const latest = persisted?.value.deletions.at(-1) ?? null;
      const sameLatest = latest !== null
        && latest.objectId === binding.objectId
        && latest.length === binding.length
        && latest.expectedDeletingGeneration === binding.expectedGeneration
        && latest.priorReceiptSha256 === binding.priorReceiptSha256
        && latest.authorityBindingSha256 === binding.authorityBindingSha256;
      if (latest && !sameLatest && latest.reopenedStagedGeneration === null) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend object has an active deletion fence');
      }
      if (sameLatest && latest.reopenedStagedGeneration !== null) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'backend deletion permit is stale');
      }
      if (!sameLatest) {
        await this.#writeFence(key, {
          schemaVersion: 'ogvcs.object-transfer/backend-lifecycle-fence/v1',
          opaqueKey: key,
          deletions: persisted ? [...persisted.value.deletions, deletionEntry(binding)] : [deletionEntry(binding)],
        }, lockGuard);
      }
      let verified;
      try { verified = await this.#verifyUnlocked(key); }
      catch (error) {
        if (error?.code !== 'TRANSFER_BACKEND_CONFLICT') throw error;
        if (!sameLatest) {
          transferError('TRANSFER_BACKEND_CONFLICT', 'backend object disappeared before deletion');
        }
      }
      if (verified && verified.receiptSha256 !== binding.priorReceiptSha256) {
        transferError('TRANSFER_BACKEND_CONFLICT', 'delete receipt is stale');
      }
      if (verified) {
        const target = await this.#path(key, false);
        if (!target) transferError('TRANSFER_BACKEND_CONFLICT', 'backend object disappeared before deletion');
        try {
          await assertPinnedDirectory(target.directoryPin);
          await lockGuard.assertOwned();
          await unlink(target.path);
          await syncDirectory(target.directory, target.directoryPin);
          await lockGuard.assertOwned();
        } catch (error) {
          if (error?.code === 'ENOENT') transferError('TRANSFER_BACKEND_CONFLICT', 'backend object disappeared before deletion');
          if (error?.code?.startsWith?.('TRANSFER_')) throw error;
          mapIo(error);
        }
      }
      return deletionReceipt(binding);
    });
  }

  async listByInternalPrefix(prefix = '', maximum = FILESYSTEM_LIMITS.listMaximum) {
    if (typeof prefix !== 'string' || !/^[0-9a-f]{0,64}$/u.test(prefix)) {
      transferError('TRANSFER_INPUT_INVALID', 'internal prefix is invalid');
    }
    lengthValue(maximum, FILESYSTEM_LIMITS.listMaximum, 'list maximum');
    await this.#assertRoots();
    const result = [];
    const walk = async (path, depth, pin) => {
      await assertPinnedDirectory(pin);
      let count = 0;
      const directory = await opendir(path);
      try {
        for await (const entry of directory) {
          count += 1;
          if (count > DIRECTORY_ENTRIES_MAXIMUM) transferError('TRANSFER_LIMIT_EXCEEDED', 'backend directory exceeds its scan bound');
          if (depth < 2) {
            if (entry.isDirectory() && /^[0-9a-f]{2}$/u.test(entry.name)) {
              const childPath = join(path, entry.name);
              const childPin = await pinPlainDirectory(childPath, { create: false, parentPin: pin });
              await walk(childPath, depth + 1, childPin);
            }
            continue;
          }
          const match = entry.isFile() && /^([0-9a-f]{64})\.obj$/u.exec(entry.name);
          if (match && match[1].startsWith(prefix)) {
            result.push(match[1]);
            if (result.length > maximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'internal list exceeds its bound');
          }
        }
      } finally { await directory.close().catch(() => {}); }
      await assertPinnedDirectory(pin);
    };
    await walk(this.objectsRoot, 0, this.#objectsPin);
    return Object.freeze(result.sort());
  }
}

export function filesystemBackendRecord(instance) {
  return FILESYSTEM_BACKEND_RECORDS.get(instance) ?? null;
}

// Freeze the exact adapter method table during module evaluation, before an
// importer can replace a prototype method and have attacker code captured by
// the trusted backend port.
const FILESYSTEM_BACKEND_METHOD_NAMES = [
  'createIfAbsent', 'head', 'initialize', 'listByInternalPrefix', 'readRange',
  'readVerifiedRange', 'safeDelete', 'verify',
];
Object.freeze(FilesystemObjectBackend.prototype);
FILESYSTEM_BACKEND_DEFINITION = Object.freeze({
  constructor: FilesystemObjectBackend,
  prototype: FilesystemObjectBackend.prototype,
  methods: Object.freeze(Object.fromEntries(FILESYSTEM_BACKEND_METHOD_NAMES.map((method) => [
    method,
    Object.getOwnPropertyDescriptor(FilesystemObjectBackend.prototype, method).value,
  ]))),
});
