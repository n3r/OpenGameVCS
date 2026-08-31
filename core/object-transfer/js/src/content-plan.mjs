import { createHash, createHmac } from 'node:crypto';
import { opendir } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { ObjectRef, createObjectHashWriter, equalBytes } from '@opengamevcs/object-model';
import { canonicalBytes } from '@opengamevcs/protocol-baseline';
import { transferError } from './errors.mjs';
import {
  atomicJsonCreate,
  atomicJsonWrite,
  pinPlainDirectory,
  pinPlainDirectoryIfExists,
  readJson,
  withRecoverableDirectoryLock,
} from './fs-util.mjs';

const SHA = /^[0-9a-f]{64}$/u;
const REQUEST_ROOT = /^sha256:[0-9a-f]{64}$/u;
const MANIFEST_BYTES_MAXIMUM = 1024 * 1024;
const PAGE_BYTES_MAXIMUM = 256 * 1024;

export const CONTENT_TRANSFER_LIMITS = Object.freeze({
  logicalBytesMaximum: 107_374_182_400,
  canonicalObjectBytesMaximum: 67_108_864,
  chunksMaximum: 100_000,
  descriptorsPerPageMaximum: 256,
  pagesMaximum: 391,
  plansMaximum: 4096,
});

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const PLAN_QUOTA_LOCK = sha256('OGVCS-CONTENT-TRANSFER-PLAN-QUOTA-LOCK-V1');

function exactInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    transferError('TRANSFER_INPUT_INVALID', `${label} is outside the configured bound`);
  }
  return value;
}

function exactSha(value, label) {
  if (typeof value !== 'string' || !SHA.test(value)) transferError('TRANSFER_INPUT_INVALID', `${label} is invalid`);
  return value;
}

function exactObjectId(value) {
  try {
    const parsed = ObjectRef.parse(value);
    if (parsed.toString() !== value || parsed.kind !== 1) throw new TypeError('ObjectID is not a canonical chunk');
    return value;
  } catch (error) {
    transferError('TRANSFER_INPUT_INVALID', 'content-plan ObjectID is invalid', { cause: error });
  }
}

function descriptor(value, expectedIndex) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== 'index\0length\0objectId\0sha256'
      || value.index !== expectedIndex) {
    transferError('TRANSFER_INPUT_INVALID', 'content-plan chunk descriptor is invalid');
  }
  return Object.freeze({
    index: exactInteger(value.index, 0, CONTENT_TRANSFER_LIMITS.chunksMaximum - 1, 'chunk index'),
    objectId: exactObjectId(value.objectId),
    length: exactInteger(value.length, 1, CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum, 'chunk length'),
    sha256: exactSha(value.sha256, 'chunk checksum'),
  });
}

function validateManifest(value, planId) {
  const keys = [
    'chunkCount', 'createdAtUnixMs', 'descriptorSetSha256', 'grantBindingSha256',
    'logicalLength', 'pageCount', 'pages', 'planId', 'requestRoot', 'schemaVersion',
    'tenantScopeSha256', 'wholeFileSha256',
  ].sort().join('\0');
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== keys
      || value.schemaVersion !== 'ogvcs.object-transfer/content-transfer-plan/v1'
      || value.planId !== planId || !SHA.test(value.tenantScopeSha256 ?? '')
      || !SHA.test(value.grantBindingSha256 ?? '') || !SHA.test(value.wholeFileSha256 ?? '')
      || !SHA.test(value.descriptorSetSha256 ?? '')
      || !(value.requestRoot === null || REQUEST_ROOT.test(value.requestRoot ?? ''))
      || !Number.isSafeInteger(value.logicalLength) || value.logicalLength < 1
      || value.logicalLength > CONTENT_TRANSFER_LIMITS.logicalBytesMaximum
      || !Number.isSafeInteger(value.chunkCount) || value.chunkCount < 1
      || value.chunkCount > CONTENT_TRANSFER_LIMITS.chunksMaximum
      || !Number.isSafeInteger(value.pageCount) || value.pageCount < 1
      || value.pageCount > CONTENT_TRANSFER_LIMITS.pagesMaximum
      || !Number.isSafeInteger(value.createdAtUnixMs) || value.createdAtUnixMs < 0
      || !Array.isArray(value.pages) || value.pages.length !== value.pageCount) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan manifest is invalid');
  }
  let chunks = 0;
  for (let index = 0; index < value.pages.length; index += 1) {
    const page = value.pages[index];
    if (!page || typeof page !== 'object' || Array.isArray(page)
        || Object.keys(page).sort().join('\0') !== 'count\0page\0sha256'
        || page.page !== index || !SHA.test(page.sha256 ?? '')
        || !Number.isSafeInteger(page.count) || page.count < 1
        || page.count > CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan page index is invalid');
    }
    chunks += page.count;
  }
  if (chunks !== value.chunkCount) transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan chunk count differs');
  return Object.freeze({ ...value, pages: Object.freeze(value.pages.map(Object.freeze)) });
}

function validatePage(value, planId, expectedPage, expectedDigest = null) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== 'chunks\0page\0planId\0schemaVersion'
      || value.schemaVersion !== 'ogvcs.object-transfer/content-transfer-plan-page/v1'
      || value.planId !== planId || value.page !== expectedPage || !Array.isArray(value.chunks)
      || value.chunks.length < 1 || value.chunks.length > CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan page is invalid');
  }
  const chunks = value.chunks.map((item, offset) => descriptor(item,
    expectedPage * CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum + offset));
  const frozen = Object.freeze({ ...value, chunks: Object.freeze(chunks) });
  if (expectedDigest !== null && sha256(canonicalBytes(frozen)) !== expectedDigest) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan page digest differs');
  }
  return frozen;
}

function validateLedger(value, planId, page, pageCount) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== 'page\0planId\0schemaVersion\0verified'
      || value.schemaVersion !== 'ogvcs.object-transfer/content-transfer-ledger-page/v1'
      || value.planId !== planId || value.page !== page || !Array.isArray(value.verified)
      || value.verified.length > pageCount) {
    transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer ledger page is invalid');
  }
  let prior = -1;
  const verified = value.verified.map((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)
        || Object.keys(entry).sort().join('\0') !== 'index\0length\0objectId\0receiptSha256\0sha256'
        || !Number.isSafeInteger(entry.index) || entry.index <= prior
        || entry.index < page * CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum
        || entry.index >= page * CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum + pageCount
        || !SHA.test(entry.receiptSha256 ?? '')) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer ledger entry is invalid');
    }
    prior = entry.index;
    return Object.freeze({
      index: entry.index,
      objectId: exactObjectId(entry.objectId),
      length: exactInteger(entry.length, 1, CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum, 'verified chunk length'),
      sha256: exactSha(entry.sha256, 'verified chunk checksum'),
      receiptSha256: entry.receiptSha256,
    });
  });
  return Object.freeze({ ...value, verified: Object.freeze(verified) });
}

function asyncSource(value) {
  if (!value?.[Symbol.asyncIterator]) transferError('TRANSFER_INPUT_INVALID', 'content-plan chunks must be an async iterable');
  return value;
}

export class ContentTransferPlanStore {
  #rootPin;
  #plansPin;
  #locksPin;
  #secret;

  constructor({ root, planSecret, now = () => Date.now(), lockLeaseMilliseconds = 300_000 } = {}) {
    if (typeof root !== 'string' || !isAbsolute(root) || root.includes('\0')
        || !(planSecret instanceof Uint8Array) || planSecret.byteLength < 32
        || typeof now !== 'function') {
      transferError('TRANSFER_INPUT_INVALID', 'content-transfer plan store configuration is invalid');
    }
    this.root = resolve(root);
    this.plansRoot = join(this.root, 'plans');
    this.locksRoot = join(this.root, 'locks');
    this.now = now;
    this.lockLeaseMilliseconds = exactInteger(lockLeaseMilliseconds, 1_000, 86_400_000, 'content-plan lock lease');
    this.#secret = Buffer.from(planSecret);
  }

  async initialize() {
    this.#rootPin = await pinPlainDirectory(this.root);
    this.#plansPin = await pinPlainDirectory(this.plansRoot, { parentPin: this.#rootPin });
    this.#locksPin = await pinPlainDirectory(this.locksRoot, { parentPin: this.#rootPin });
    return this;
  }

  #id(binding) {
    return createHmac('sha256', this.#secret)
      .update('OGVCS-CONTENT-TRANSFER-PLAN-ID-V1\0')
      .update(canonicalBytes(binding)).digest('hex');
  }

  #planPath(planId) { return join(this.plansRoot, exactSha(planId, 'content-plan ID')); }
  #manifestPath(planId) { return join(this.#planPath(planId), 'manifest.json'); }
  #pagePath(planId, page) { return join(this.#planPath(planId), `page-${String(page).padStart(6, '0')}.json`); }
  #ledgerPath(planId, page) { return join(this.#planPath(planId), `ledger-${String(page).padStart(6, '0')}.json`); }

  async #withLock(planId, operation) {
    if (!this.#locksPin) transferError('TRANSFER_BACKEND_IO', 'content-transfer plan store is not initialized');
    return withRecoverableDirectoryLock({
      rootPin: this.#locksPin,
      name: exactSha(planId, 'content-plan ID'),
      now: this.now,
      leaseMilliseconds: this.lockLeaseMilliseconds,
      busyCode: 'TRANSFER_SESSION_STATE',
      busyMessage: 'content-transfer plan is busy',
      operation,
    });
  }

  async #pin(planId, create = false) {
    return pinPlainDirectory(this.#planPath(planId), { create, parentPin: this.#plansPin });
  }

  async #countPlansUnlocked() {
    let count = 0;
    const directory = await opendir(this.plansRoot);
    try {
      for await (const entry of directory) {
        count += 1;
        if (count > CONTENT_TRANSFER_LIMITS.plansMaximum) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'content-transfer plan catalog exceeds its bound');
        }
        if (!entry.isDirectory() || !SHA.test(entry.name)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan catalog contains an invalid entry');
        }
      }
    } finally { await directory.close().catch(() => {}); }
    return count;
  }

  async #manifest(planId, planPin = null) {
    const pin = planPin ?? await this.#pin(planId, false);
    const value = await readJson(this.#manifestPath(planId), MANIFEST_BYTES_MAXIMUM, { directoryPin: pin });
    if (value === null) transferError('TRANSFER_SESSION_STATE', 'content-transfer plan is absent');
    return validateManifest(value, planId);
  }

  async createPlan({
    tenantScopeSha256,
    grantBindingSha256,
    requestRoot,
    logicalLength,
    wholeFileSha256,
    chunks,
  } = {}) {
    const binding = Object.freeze({
      tenantScopeSha256: exactSha(tenantScopeSha256, 'tenant scope'),
      grantBindingSha256: exactSha(grantBindingSha256, 'grant binding'),
      requestRoot: requestRoot === null ? null : (REQUEST_ROOT.test(requestRoot ?? '') ? requestRoot
        : transferError('TRANSFER_INPUT_INVALID', 'request root is invalid')),
      logicalLength: exactInteger(logicalLength, 1, CONTENT_TRANSFER_LIMITS.logicalBytesMaximum, 'logical length'),
      wholeFileSha256: exactSha(wholeFileSha256, 'whole-file checksum'),
    });
    asyncSource(chunks);
    const planId = this.#id(binding);
    return this.#withLock(PLAN_QUOTA_LOCK, () => this.#withLock(planId, async (lockGuard) => {
      let planPin = await pinPlainDirectoryIfExists(this.#planPath(planId), { parentPin: this.#plansPin });
      if (!planPin) {
        if (await this.#countPlansUnlocked() >= CONTENT_TRANSFER_LIMITS.plansMaximum) {
          transferError('TRANSFER_LIMIT_EXCEEDED', 'content-transfer plan catalog exceeds its bound');
        }
        planPin = await this.#pin(planId, true);
      }
      const existing = await readJson(this.#manifestPath(planId), MANIFEST_BYTES_MAXIMUM, { directoryPin: planPin });
      if (existing !== null) {
        const manifest = validateManifest(existing, planId);
        for (const [key, value] of Object.entries(binding)) {
          if (manifest[key] !== value) transferError('TRANSFER_PART_CONFLICT', 'content-transfer plan replay differs');
        }
        return manifest;
      }
      const pages = [];
      const descriptorHash = createHash('sha256').update('OGVCS-CONTENT-TRANSFER-DESCRIPTORS-V1\0');
      let pageItems = [];
      let count = 0;
      let total = 0;
      const flush = async () => {
        if (pageItems.length === 0) return;
        const pageNumber = pages.length;
        if (pageNumber >= CONTENT_TRANSFER_LIMITS.pagesMaximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'content-transfer plan page bound exceeded');
        const value = Object.freeze({
          schemaVersion: 'ogvcs.object-transfer/content-transfer-plan-page/v1',
          planId,
          page: pageNumber,
          chunks: Object.freeze(pageItems),
        });
        const digest = sha256(canonicalBytes(value));
        const created = await atomicJsonCreate(this.#pagePath(planId, pageNumber), value, { directoryPin: planPin, lockGuard });
        if (!created) {
          const persisted = await readJson(this.#pagePath(planId, pageNumber), PAGE_BYTES_MAXIMUM, { directoryPin: planPin });
          if (sha256(canonicalBytes(persisted)) !== digest) transferError('TRANSFER_PART_CONFLICT', 'content-transfer plan partial replay differs');
        }
        pages.push(Object.freeze({ page: pageNumber, count: pageItems.length, sha256: digest }));
        pageItems = [];
      };
      for await (const input of chunks) {
        if (count >= CONTENT_TRANSFER_LIMITS.chunksMaximum) transferError('TRANSFER_LIMIT_EXCEEDED', 'content-transfer chunk count exceeds its bound');
        const item = descriptor(input, count);
        if (total > binding.logicalLength - item.length) transferError('TRANSFER_INPUT_INVALID', 'content-transfer chunks exceed logical length');
        total += item.length;
        descriptorHash.update(canonicalBytes(item));
        descriptorHash.update('\0');
        pageItems.push(item);
        count += 1;
        if (pageItems.length === CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum) await flush();
      }
      await flush();
      if (count < 1 || total !== binding.logicalLength) {
        transferError('TRANSFER_INPUT_INVALID', 'content-transfer chunks do not exactly cover logical length');
      }
      const manifest = validateManifest({
        schemaVersion: 'ogvcs.object-transfer/content-transfer-plan/v1',
        planId,
        ...binding,
        chunkCount: count,
        pageCount: pages.length,
        pages,
        descriptorSetSha256: descriptorHash.digest('hex'),
        createdAtUnixMs: this.now(),
      }, planId);
      await lockGuard.assertOwned();
      const created = await atomicJsonCreate(this.#manifestPath(planId), manifest, { directoryPin: planPin, lockGuard });
      if (!created) transferError('TRANSFER_PART_CONFLICT', 'content-transfer plan publication raced');
      return manifest;
    }));
  }

  async #page(planId, page, manifest, planPin) {
    exactInteger(page, 0, manifest.pageCount - 1, 'content-plan page');
    const value = await readJson(this.#pagePath(planId, page), PAGE_BYTES_MAXIMUM, { directoryPin: planPin });
    if (value === null) transferError('TRANSFER_BACKEND_CORRUPT', 'content-transfer plan page is absent');
    return validatePage(value, planId, page, manifest.pages[page].sha256);
  }

  async #ledger(planId, page, count, planPin) {
    const value = await readJson(this.#ledgerPath(planId, page), PAGE_BYTES_MAXIMUM, { directoryPin: planPin });
    if (value === null) return Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/content-transfer-ledger-page/v1',
      planId,
      page,
      verified: Object.freeze([]),
    });
    return validateLedger(value, planId, page, count);
  }

  async nextPending({ planId, page = 0, maximum = CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum } = {}) {
    exactInteger(maximum, 1, CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum, 'pending chunk maximum');
    const planPin = await this.#pin(planId, false);
    const manifest = await this.#manifest(planId, planPin);
    exactInteger(page, 0, manifest.pageCount - 1, 'content-plan page');
    const descriptors = await this.#page(planId, page, manifest, planPin);
    const ledger = await this.#ledger(planId, page, descriptors.chunks.length, planPin);
    const verified = new Set(ledger.verified.map(({ index }) => index));
    const allPending = descriptors.chunks.filter(({ index }) => !verified.has(index));
    const pending = allPending.slice(0, maximum);
    const status = await this.status(planId);
    return Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/content-transfer-pending-page/v1',
      planId,
      page,
      pending: Object.freeze(pending),
      nextPage: allPending.length > pending.length ? page
        : page + 1 < manifest.pageCount ? page + 1 : null,
      complete: status.complete,
    });
  }

  async recordVerified({ planId, index, objectId, length, sha256: checksum, receiptSha256 } = {}) {
    return this.#withLock(planId, async (lockGuard) => {
      const planPin = await this.#pin(planId, false);
      const manifest = await this.#manifest(planId, planPin);
      exactInteger(index, 0, manifest.chunkCount - 1, 'verified chunk index');
      const page = Math.floor(index / CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum);
      const descriptors = await this.#page(planId, page, manifest, planPin);
      const expected = descriptors.chunks[index % CONTENT_TRANSFER_LIMITS.descriptorsPerPageMaximum];
      const entry = Object.freeze({
        index,
        objectId: exactObjectId(objectId),
        length: exactInteger(length, 1, CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum, 'verified chunk length'),
        sha256: exactSha(checksum, 'verified chunk checksum'),
        receiptSha256: exactSha(receiptSha256, 'verified backend receipt'),
      });
      if (entry.objectId !== expected.objectId || entry.length !== expected.length || entry.sha256 !== expected.sha256) {
        transferError('TRANSFER_PART_CONFLICT', 'verified chunk differs from its sealed plan');
      }
      const ledger = await this.#ledger(planId, page, descriptors.chunks.length, planPin);
      const existing = ledger.verified.find((item) => item.index === index);
      if (existing) {
        if (Buffer.from(canonicalBytes(existing)).equals(Buffer.from(canonicalBytes(entry)))) return Object.freeze({ ...existing, replay: true });
        transferError('TRANSFER_PART_CONFLICT', 'verified chunk replay differs');
      }
      const updated = validateLedger({
        ...ledger,
        verified: [...ledger.verified, entry].sort((left, right) => left.index - right.index),
      }, planId, page, descriptors.chunks.length);
      await atomicJsonWrite(this.#ledgerPath(planId, page), updated, { directoryPin: planPin, lockGuard });
      return Object.freeze({ ...entry, replay: false });
    });
  }

  async status(planId) {
    const planPin = await this.#pin(planId, false);
    const manifest = await this.#manifest(planId, planPin);
    let verifiedChunks = 0;
    for (let page = 0; page < manifest.pageCount; page += 1) {
      const descriptors = await this.#page(planId, page, manifest, planPin);
      verifiedChunks += (await this.#ledger(planId, page, descriptors.chunks.length, planPin)).verified.length;
    }
    return Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/content-transfer-plan-status/v1',
      planId,
      logicalLength: manifest.logicalLength,
      chunkCount: manifest.chunkCount,
      verifiedChunks,
      pendingChunks: manifest.chunkCount - verifiedChunks,
      complete: verifiedChunks === manifest.chunkCount,
    });
  }

  async reconstruct({ planId, readVerifiedChunk, write } = {}) {
    if (typeof readVerifiedChunk !== 'function' || typeof write !== 'function') {
      transferError('TRANSFER_INPUT_INVALID', 'content reconstruction callbacks are invalid');
    }
    const planPin = await this.#pin(planId, false);
    const manifest = await this.#manifest(planId, planPin);
    const whole = createHash('sha256');
    let written = 0;
    for (let page = 0; page < manifest.pageCount; page += 1) {
      const descriptors = await this.#page(planId, page, manifest, planPin);
      const ledger = await this.#ledger(planId, page, descriptors.chunks.length, planPin);
      const verified = new Map(ledger.verified.map((entry) => [entry.index, entry]));
      for (const item of descriptors.chunks) {
        const proof = verified.get(item.index);
        if (!proof || proof.objectId !== item.objectId || proof.length !== item.length || proof.sha256 !== item.sha256) {
          transferError('TRANSFER_SESSION_STATE', 'content reconstruction has an unverified chunk');
        }
        const input = await readVerifiedChunk(item, proof);
        if (!(input instanceof Uint8Array) || input.byteLength !== item.length) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'reconstruction chunk length differs');
        }
        const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
        if (sha256(bytes) !== item.sha256) transferError('TRANSFER_BACKEND_CORRUPT', 'reconstruction chunk checksum differs');
        const reference = ObjectRef.parse(item.objectId);
        const objectHash = createObjectHashWriter(reference.kind, {
          maxChunkBytes: CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum,
          maxMetadataBytes: CONTENT_TRANSFER_LIMITS.canonicalObjectBytesMaximum,
        });
        objectHash.update(bytes);
        if (!equalBytes(objectHash.finish().digest, reference.digest)) {
          transferError('TRANSFER_BACKEND_CORRUPT', 'reconstruction chunk ObjectID differs');
        }
        whole.update(bytes);
        await write(bytes, Object.freeze({ index: item.index, offset: written }));
        written += bytes.length;
      }
    }
    const digest = whole.digest('hex');
    if (written !== manifest.logicalLength || digest !== manifest.wholeFileSha256) {
      transferError('TRANSFER_BACKEND_CORRUPT', 'reconstructed whole-file checksum differs');
    }
    return Object.freeze({
      schemaVersion: 'ogvcs.object-transfer/content-reconstruction-receipt/v1',
      planId,
      logicalLength: written,
      wholeFileSha256: digest,
      chunks: manifest.chunkCount,
    });
  }
}
