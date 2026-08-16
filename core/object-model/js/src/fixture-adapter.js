import { createHash } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';

import { encodeCanonical } from './cbor.js';
import { fail, OgvcsError } from './errors.js';
import { allocateFileId } from './fileid.js';
import { hashLogicalRecord, hashObject } from './hash.js';
import { loadBundledRegistry } from './registry.js';
import { validateAssetGroups } from './repository.js';
import { encodeMetadata, validateLogicalRecord } from './schema.js';
import { Digest, FileId, ObjectRef, ProfileRef, toHex } from './types.js';

const MAX_CONTROL_BYTES = 2 * 1024 * 1024;
const MAX_GROUP_BYTES = 128 * 1024 * 1024;
const MAX_NDJSON_LINE_BYTES = 64 * 1024;
const MAX_CHUNK_BYTES = 64 * 1024 * 1024;
const MAX_CANONICAL_JSON_DEPTH = 256;
const MAX_PORTABLE_PATH_BYTES = 4_096;
const MAX_PORTABLE_PATH_SEGMENTS = 256;
const MAX_PORTABLE_PATH_UTF16_UNITS = 32_767;
const DEFAULT_RETAINED_BYTES = 256 * 1024 * 1024;
const OBJECT_REFERENCE_OVERHEAD = 256;
const ADAPTER_HARD_LIMITS = Object.freeze({
  inputBytes: 64 * 1024 * 1024,
  inventoryRecords: 100_000,
  operationRecords: 100_000,
  groups: 100_000,
  mappings: 300_000,
  objects: 500_000,
  manifestParts: 65_536,
  treeNodes: 200_000,
  durationMilliseconds: 10 * 60 * 1000
});
const LEDGER_SCHEMA = 'ogvcs.fixture-adapter/ledger/v1';
const REQUEST_SCHEMA = 'ogvcs.fixture/request/v1';
const PROFILE_SCHEMA = 'ogvcs.fixture/workload-profile/v1';
const MANIFEST_SCHEMA = 'ogvcs.fixture/manifest/v1';
const PROFILE_VERSION = '2.0.0';
const DEFAULT_FILE_SYSTEM = Object.freeze({
  createReadStream,
  open: (filePath, flags, _options) => open(filePath, flags)
});

function adapterLimits(options) {
  const configured = options.limits ?? {};
  if (!configured || typeof configured !== 'object' || Array.isArray(configured)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const unknown = Object.keys(configured).filter(name => !(name in ADAPTER_HARD_LIMITS));
  if (unknown.length > 0) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return Object.freeze(Object.fromEntries(Object.entries(ADAPTER_HARD_LIMITS).map(([name, hard]) => {
    const value = configured[name] ?? hard;
    if (!Number.isSafeInteger(value) || value < 0 || value > hard) {
      fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    }
    return [name, value];
  })));
}

class AdapterBudget {
  constructor(limits) {
    this.limits = limits;
    this.started = process.hrtime.bigint();
    this.inputBytes = 0;
    this.controller = new AbortController();
  }
  remainingNanoseconds() {
    return BigInt(this.limits.durationMilliseconds) * 1_000_000n -
      (process.hrtime.bigint() - this.started);
  }
  checkTime() {
    if (this.remainingNanoseconds() <= 0n) {
      const error = new OgvcsError('LIMIT_TIME', { layer: 1 });
      if (!this.controller.signal.aborted) this.controller.abort(error);
      throw error;
    }
  }
  async wait(callback) {
    this.checkTime();
    const remaining = this.remainingNanoseconds();
    const milliseconds = Math.max(1, Number((remaining + 999_999n) / 1_000_000n));
    const error = new OgvcsError('LIMIT_TIME', { layer: 1 });
    let timer;
    const timeout = new Promise((resolvePromise, reject) => {
      timer = setTimeout(() => {
        reject(error);
        if (!this.controller.signal.aborted) this.controller.abort(error);
      }, milliseconds);
    });
    try {
      const result = await Promise.race([
        Promise.resolve().then(() => callback(this.controller.signal)),
        timeout
      ]);
      this.checkTime();
      return result;
    } finally {
      clearTimeout(timer);
    }
  }
  cleanup(callback) {
    const promise = Promise.resolve().then(() => callback(this.controller.signal));
    promise.catch(() => {});
    return promise;
  }
  addInputBytes(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.limits.inputBytes - this.inputBytes) {
      fail('LIMIT_MEMORY', { layer: 1 });
    }
    this.inputBytes += bytes;
    this.checkTime();
  }
  count(value, maximum) {
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail('LIMIT_COUNT', {
      layer: 1, stage: 'configured-resource-preflight'
    });
    this.checkTime();
  }
}

function adapterFileSystem(options) {
  const fileSystem = options.fileSystem ?? DEFAULT_FILE_SYSTEM;
  if (!fileSystem || typeof fileSystem.open !== 'function' ||
      typeof fileSystem.createReadStream !== 'function') {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  return fileSystem;
}

async function openBounded(fileSystem, filePath, flags, budget) {
  let pending;
  try {
    return await budget.wait(signal => {
      pending = Promise.resolve(fileSystem.open(filePath, flags, { signal }));
      return pending;
    });
  } catch (error) {
    // An open that settles after the deadline must not leak its handle. Cleanup
    // is best effort and deliberately detached from the already-selected error.
    pending?.then(handle => budget.cleanup(signal => handle?.close?.({ signal })), () => {});
    throw error;
  }
}

async function closeBounded(handle, budget) {
  if (!handle) return;
  if (budget.controller.signal.aborted) {
    budget.cleanup(signal => handle.close({ signal }));
    return;
  }
  await budget.wait(signal => handle.close({ signal }));
}

function fixtureFail(code = 'FIXTURE_SEMANTIC_INVALID') { fail(code, { layer: 3 }); }
function hexBytes(value, length, code = 'FIXTURE_MAPPING_MISSING') {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) fixtureFail(code);
  const bytes = Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16));
  if (bytes.every(byte => byte === 0)) fixtureFail(code);
  return bytes;
}
function sha256(value) { return new Uint8Array(createHash('sha256').update(value).digest()); }
function canonicalJson(value, depth = 0) {
  if (depth > MAX_CANONICAL_JSON_DEPTH) fixtureFail();
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fixtureFail();
    return Object.is(value, -0) ? '0' : String(value);
  }
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item, depth + 1)).join(',')}]`;
  if (!value || typeof value !== 'object') fixtureFail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fixtureFail();
  return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${canonicalJson(value[key], depth + 1)}`).join(',')}}`;
}
function canonicalFixtureDigest(value, domain) {
  return createHash('sha256').update(domain, 'ascii').update(Uint8Array.of(0))
    .update(canonicalJson(value), 'utf8').digest('hex');
}
function operationChainDigest(records) {
  const domain = 'ogvcs.fixture/operation-chain/v1';
  let digest = createHash('sha256').update(`${domain}\0`, 'utf8').digest();
  for (const { raw } of records) {
    digest = createHash('sha256').update(`${domain}\0`, 'utf8').update(digest).update(raw).update('\n').digest();
  }
  return digest.toString('hex');
}
function digestMap(bytes) { return new Digest(1, bytes).toMap(); }
function profile(namespace, id, major) { return new ProfileRef(namespace, id, major); }
function profileMap(namespace, id, major) { return profile(namespace, id, major).toMap(); }
function profileSort(values) {
  return [...values].sort((left, right) => Buffer.compare(Buffer.from(encodeCanonical(left)), Buffer.from(encodeCanonical(right))));
}
function exactObject(value, keys, code = 'FIXTURE_SEMANTIC_INVALID') {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) fixtureFail(code);
}
function portableSegments(value) {
  if (typeof value !== 'string' || value.normalize('NFC') !== value || value.startsWith('/') || value.includes('\\') || value.includes('\0')) fixtureFail();
  const utf8 = Buffer.from(value, 'utf8');
  if (utf8.toString('utf8') !== value || utf8.length > MAX_PORTABLE_PATH_BYTES ||
      value.length > MAX_PORTABLE_PATH_UTF16_UNITS) fixtureFail();
  const segments = value.split('/');
  if (segments.length > MAX_PORTABLE_PATH_SEGMENTS ||
      segments.some(item => item.length === 0 || item === '.' || item === '..' || Buffer.byteLength(item) > 255)) fixtureFail();
  return segments;
}
function fileIdText(value) { return value instanceof FileId ? value.toString() : new FileId(value).toString(); }

async function readRegularBounded(filePath, maximum, budget, fileSystem) {
  const handle = await openBounded(
    fileSystem, filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0), budget
  );
  try {
    const stat = await budget.wait(signal => handle.stat({ signal }));
    if (!stat.isFile() || stat.size > maximum) fixtureFail();
    budget?.addInputBytes(stat.size);
    const bytes = new Uint8Array(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await budget.wait(signal =>
        handle.read(bytes, offset, bytes.length - offset, offset, { signal }));
      if (bytesRead === 0) fixtureFail();
      offset += bytesRead;
    }
    if ((await budget.wait(signal => handle.stat({ signal }))).size !== stat.size) fixtureFail();
    return bytes;
  } finally {
    await closeBounded(handle, budget);
  }
}

async function readJson(filePath, maximum, budget, fileSystem) {
  const bytes = await readRegularBounded(filePath, maximum, budget, fileSystem);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fixtureFail(); }
}

async function readNdjson(filePath, maximumRecords, budget, fileSystem) {
  const handle = await openBounded(
    fileSystem, filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0), budget
  );
  const records = [];
  const digest = createHash('sha256');
  try {
    const stat = await budget.wait(signal => handle.stat({ signal })); if (!stat.isFile()) fixtureFail();
    budget.addInputBytes(stat.size);
    const input = Buffer.allocUnsafe(64 * 1024);
    const line = Buffer.allocUnsafe(MAX_NDJSON_LINE_BYTES);
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let position = 0; let length = 0;
    const finishLine = () => {
      if (length === 0) fixtureFail();
      const raw = Buffer.from(line.subarray(0, length));
      let value;
      try { value = JSON.parse(decoder.decode(raw)); } catch { fixtureFail(); }
      budget.count(records.length + 1, maximumRecords);
      records.push({ raw, value });
      length = 0;
    };
    while (position < stat.size) {
      const { bytesRead } = await budget.wait(signal => handle.read(
        input, 0, Math.min(input.length, stat.size - position), position, { signal }
      ));
      if (bytesRead === 0) fixtureFail();
      digest.update(input.subarray(0, bytesRead));
      position += bytesRead;
      for (let offset = 0; offset < bytesRead; offset++) {
        if (input[offset] === 0x0a) finishLine();
        else {
          if (length >= MAX_NDJSON_LINE_BYTES) fixtureFail();
          line[length++] = input[offset];
        }
      }
      budget.checkTime();
    }
    if (length !== 0) fixtureFail();
    if ((await budget.wait(signal => handle.stat({ signal }))).size !== stat.size) fixtureFail();
    return { digest: digest.digest('hex'), records };
  } finally {
    await closeBounded(handle, budget);
  }
}

function cloneLedger(value) {
  if (value === undefined) return undefined;
  try { return structuredClone(value); } catch { fixtureFail('FIXTURE_MAPPING_MISSING'); }
}
function sortedRecord(value) { return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right, 'en'))); }
function setOwn(record, key, value) {
  Object.defineProperty(record, key, { configurable: true, enumerable: true, value, writable: true });
}

function shallowMapping(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fixtureFail('FIXTURE_MAPPING_MISSING');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fixtureFail('FIXTURE_MAPPING_MISSING');
  return value;
}

function boundedMappingKey(value, code = 'FIXTURE_MAPPING_MISSING') {
  if (typeof value !== 'string' || value.length < 1 || value.normalize('NFC') !== value ||
      value.includes('\0') || Buffer.byteLength(value, 'utf8') > MAX_PORTABLE_PATH_BYTES) {
    fixtureFail(code);
  }
  return value;
}

function validateLedgerBeforeClone(value, requirements, limits, budget) {
  const fields = ['schemaVersion', 'requestDigest', 'repositoryId', 'directoryIds', 'fileIds',
    'groupIds', 'revisionSnapshots', 'importMappings'];
  exactObject(value, fields, 'FIXTURE_MAPPING_MISSING');
  const dictionaries = ['directoryIds', 'fileIds', 'groupIds', 'revisionSnapshots', 'importMappings'];
  for (const field of dictionaries) shallowMapping(value[field]);
  budget.count(Object.keys(value.directoryIds).length + Object.keys(value.fileIds).length +
    Object.keys(value.groupIds).length, limits.mappings);
  budget.count(Object.keys(value.revisionSnapshots).length, limits.operationRecords);
  budget.count(Object.keys(value.importMappings).length, limits.inventoryRecords);
  if (value.schemaVersion !== LEDGER_SCHEMA || value.requestDigest !== requirements.requestDigest ||
      !/^[0-9a-f]{64}$/.test(value.requestDigest) ||
      (value.repositoryId !== null && typeof value.repositoryId !== 'string')) {
    fixtureFail('FIXTURE_MAPPING_MISSING');
  }
  if (value.repositoryId !== null) hexBytes(value.repositoryId, 16, 'FIXTURE_MAPPING_MISSING');
  for (const [path, target] of Object.entries(value.directoryIds)) {
    portableSegments(path);
    hexBytes(target, 16, 'FIXTURE_MAPPING_MISSING');
  }
  for (const [source, target] of Object.entries(value.fileIds)) {
    hexBytes(source, 16, 'FIXTURE_MAPPING_MISSING');
    hexBytes(target, 16, 'FIXTURE_MAPPING_MISSING');
  }
  for (const [source, target] of Object.entries(value.groupIds)) {
    boundedMappingKey(source);
    hexBytes(target, 16, 'FIXTURE_MAPPING_MISSING');
  }
  for (const [revision, snapshot] of Object.entries(value.revisionSnapshots)) {
    boundedMappingKey(revision);
    if (typeof snapshot !== 'string') fixtureFail('FIXTURE_MAPPING_MISSING');
    try {
      if (ObjectRef.parse(snapshot).kind !== 7) fixtureFail('FIXTURE_MAPPING_MISSING');
    } catch (error) {
      if (error instanceof OgvcsError && error.code === 'FIXTURE_MAPPING_MISSING') throw error;
      fixtureFail('FIXTURE_MAPPING_MISSING');
    }
  }
  const prefix = `${requirements.requestDigest}:`;
  for (const [mappingKey, target] of Object.entries(value.importMappings)) {
    if (!mappingKey.startsWith(prefix)) fixtureFail('FIXTURE_MAPPING_MISSING');
    hexBytes(mappingKey.slice(prefix.length), 16, 'FIXTURE_MAPPING_MISSING');
    hexBytes(target, 16, 'FIXTURE_MAPPING_MISSING');
  }
  budget.checkTime();
}

function mappingRequirements(manifest, inventory, groups, budget) {
  const directories = new Set();
  for (const record of inventory) {
    const parts = portableSegments(record.logicalPath);
    for (let count = 1; count < parts.length; count++) {
      directories.add(parts.slice(0, count).join('/'));
      budget.count(directories.size, budget.limits.treeNodes);
    }
  }
  const files = new Set(inventory.map(record => record.fileId));
  const groupIds = new Set(groups.map(group => group.id));
  budget.count(directories.size + files.size + groupIds.size, budget.limits.mappings);
  return {
    directories: [...directories].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))),
    files: [...files].sort(),
    groups: [...groupIds].sort(),
    requestDigest: manifest.requestDigest
  };
}

async function allocatedHex(allocateId, allocationEntropy, kind, key, used, checkTarget, budget) {
  let candidate;
  if (allocateId) candidate = await budget.wait(signal => allocateId({ key, kind, signal }));
  else candidate = await allocateFileId({
    ...(allocationEntropy === undefined ? {} : {
      entropy: () => budget.wait(signal => allocationEntropy({ signal }))
    }),
    isConsumed: (_value, hexValue) => used.has(`fid:${hexValue}`)
  });
  const bytes = candidate instanceof FileId ? candidate.bytes
    : candidate instanceof Uint8Array ? new FileId(candidate).bytes
      : typeof candidate === 'string' ? FileId.parse(candidate.startsWith('fid:') ? candidate : `fid:${candidate}`).bytes
        : fixtureFail('FIXTURE_MAPPING_MISSING');
  const text = fileIdText(bytes);
  if (used.has(text)) fixtureFail('FIXTURE_MAPPING_MISSING');
  await checkTarget?.(text);
  used.add(text); return toHex(bytes);
}

/**
 * Complete and durably persist every mapping before object construction.
 * A missing persistence callback fails closed; no ephemeral deterministic ID
 * fallback is provided.
 */
export async function prepareFixtureAdapterLedger(input, options = {}) {
  const limits = options.adapterLimits ?? adapterLimits(options);
  const budget = options.adapterBudget ?? new AdapterBudget(limits);
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      !input.manifest || typeof input.manifest !== 'object' || Array.isArray(input.manifest) ||
      !Array.isArray(input.inventory) || !Array.isArray(input.groups)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const { manifest, inventory, groups } = input;
  // Count the public collections before mapping, splitting paths, or building
  // Sets. A repeated hostile entry cannot turn the convenience API into an
  // unbounded preflight walk.
  budget.count(inventory.length, limits.inventoryRecords);
  budget.count(groups.length, limits.groups);
  budget.checkTime();
  for (const record of inventory) {
    budget.checkTime();
    if (!record || typeof record !== 'object' || Array.isArray(record) ||
        typeof record.fileId !== 'string' || typeof record.logicalPath !== 'string') {
      fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    }
    hexBytes(record.fileId, 16, 'FIXTURE_SEMANTIC_INVALID');
    portableSegments(record.logicalPath);
  }
  for (const group of groups) {
    budget.checkTime();
    if (!group || typeof group !== 'object' || Array.isArray(group) ||
        typeof group.id !== 'string' || group.id.length === 0) {
      fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    }
    boundedMappingKey(group.id, 'FIXTURE_SEMANTIC_INVALID');
  }
  budget.checkTime();
  const requirements = mappingRequirements(manifest, inventory, groups, budget);
  const needsTargetFileIds = requirements.directories.length > 0 || requirements.files.length > 0;
  if (needsTargetFileIds && typeof options.isTargetFileIdConsumed !== 'function') {
    fixtureFail('FIXTURE_MAPPING_MISSING');
  }
  const checkTarget = async (fileId, ownerKind, ownerKey) => {
    let consumed;
    try {
      consumed = await budget.wait(signal => options.isTargetFileIdConsumed({
        fileId, ownerKind, ownerKey, signal
      }));
    }
    catch (error) {
      if (error instanceof OgvcsError && error.code === 'LIMIT_TIME') throw error;
      fixtureFail('FILEID_IMPORT_MAPPING_CONFLICT');
    }
    if (typeof consumed !== 'boolean') fixtureFail('FIXTURE_MAPPING_MISSING');
    if (consumed) fixtureFail('FILEID_IMPORT_MAPPING_CONFLICT');
  };
  const ledgerFields = ['schemaVersion', 'requestDigest', 'repositoryId', 'directoryIds', 'fileIds',
    'groupIds', 'revisionSnapshots', 'importMappings'];
  if (options.ledger !== undefined) {
    try { validateLedgerBeforeClone(options.ledger, requirements, limits, budget); }
    catch (error) {
      if (error instanceof OgvcsError) throw error;
      fixtureFail('FIXTURE_MAPPING_MISSING');
    }
  }
  let ledger = cloneLedger(options.ledger);
  let changed = false;
  if (ledger === undefined) {
    ledger = { schemaVersion: LEDGER_SCHEMA, requestDigest: requirements.requestDigest,
      repositoryId: null, directoryIds: {}, fileIds: {}, groupIds: {}, revisionSnapshots: {}, importMappings: {} };
    changed = true;
  }
  exactObject(ledger, ledgerFields, 'FIXTURE_MAPPING_MISSING');
  if (ledger.schemaVersion !== LEDGER_SCHEMA || ledger.requestDigest !== requirements.requestDigest ||
      !ledger.directoryIds || !ledger.fileIds || !ledger.groupIds || !ledger.revisionSnapshots ||
      !ledger.importMappings) fixtureFail('FIXTURE_MAPPING_MISSING');
  const usedFiles = new Set();
  for (const value of [...Object.values(ledger.directoryIds), ...Object.values(ledger.fileIds)]) {
    const text = fileIdText(hexBytes(value, 16));
    if (usedFiles.has(text)) fixtureFail('FIXTURE_MAPPING_MISSING');
    usedFiles.add(text);
  }
  const usedGroups = new Set();
  for (const value of Object.values(ledger.groupIds)) {
    const text = fileIdText(hexBytes(value, 16));
    if (usedGroups.has(text)) fixtureFail('FIXTURE_MAPPING_MISSING');
    usedGroups.add(text);
  }
  for (const [revision, snapshot] of Object.entries(ledger.revisionSnapshots)) {
    if (revision.length === 0) fixtureFail('FIXTURE_MAPPING_MISSING');
    try { if (ObjectRef.parse(snapshot).kind !== 7) fixtureFail('FIXTURE_MAPPING_MISSING'); }
    catch { fixtureFail('FIXTURE_MAPPING_MISSING'); }
  }
  for (const [mappingKey, target] of Object.entries(ledger.importMappings)) {
    const prefix = `${requirements.requestDigest}:`;
    if (!mappingKey.startsWith(prefix)) fixtureFail('FIXTURE_MAPPING_MISSING');
    const source = mappingKey.slice(prefix.length);
    hexBytes(source, 16, 'FIXTURE_MAPPING_MISSING');
    hexBytes(target, 16, 'FIXTURE_MAPPING_MISSING');
    if (!Object.hasOwn(ledger.fileIds, source) || ledger.fileIds[source] !== target) fixtureFail('FIXTURE_MAPPING_MISSING');
  }
  for (const [path, value] of Object.entries(ledger.directoryIds)) {
    await checkTarget(fileIdText(hexBytes(value, 16)), 'directory', `${requirements.requestDigest}:${path}`);
  }
  for (const [source, value] of Object.entries(ledger.fileIds)) {
    await checkTarget(fileIdText(hexBytes(value, 16)), 'import', `${requirements.requestDigest}:${source}`);
  }
  if (ledger.repositoryId === null) {
    ledger.repositoryId = await allocatedHex(options.allocateId, options.allocationEntropy,
      'repository', requirements.requestDigest, new Set(), undefined, budget);
    changed = true;
  }
  else hexBytes(ledger.repositoryId, 16);
  for (const path of requirements.directories) if (!Object.hasOwn(ledger.directoryIds, path)) {
    const allocated = await allocatedHex(options.allocateId, options.allocationEntropy, 'directory', path, usedFiles,
      fileId => checkTarget(fileId, 'directory', `${requirements.requestDigest}:${path}`), budget);
    setOwn(ledger.directoryIds, path, allocated); changed = true;
  }
  for (const source of requirements.files) {
    hexBytes(source, 16, 'FIXTURE_SEMANTIC_INVALID');
    if (!Object.hasOwn(ledger.fileIds, source)) {
      const allocated = await allocatedHex(options.allocateId, options.allocationEntropy, 'file', source, usedFiles,
        fileId => checkTarget(fileId, 'import', `${requirements.requestDigest}:${source}`), budget);
      setOwn(ledger.fileIds, source, allocated); changed = true;
    }
    const mappingKey = `${requirements.requestDigest}:${source}`;
    if (Object.hasOwn(ledger.importMappings, mappingKey)) {
      if (ledger.importMappings[mappingKey] !== ledger.fileIds[source]) fixtureFail('FIXTURE_MAPPING_MISSING');
    } else {
      setOwn(ledger.importMappings, mappingKey, ledger.fileIds[source]); changed = true;
    }
  }
  for (const source of requirements.groups) if (!Object.hasOwn(ledger.groupIds, source)) {
    const allocated = await allocatedHex(options.allocateId, options.allocationEntropy,
      'group', source, usedGroups, undefined, budget);
    setOwn(ledger.groupIds, source, allocated); changed = true;
  }
  ledger.directoryIds = sortedRecord(ledger.directoryIds);
  ledger.fileIds = sortedRecord(ledger.fileIds);
  ledger.groupIds = sortedRecord(ledger.groupIds);
  ledger.revisionSnapshots = sortedRecord(ledger.revisionSnapshots);
  ledger.importMappings = sortedRecord(ledger.importMappings);
  if (changed) {
    if (typeof options.persistLedger !== 'function') fixtureFail('FIXTURE_MAPPING_MISSING');
    await budget.wait(signal => options.persistLedger(structuredClone(ledger), { signal }));
  }
  return Object.freeze({ changed, ledger: structuredClone(ledger), requirements });
}

async function fixtureVerifier(options) {
  if (options.verifyFixture) return options.verifyFixture;
  try { return (await import('@opengamevcs/fixture-generator')).verifyFixture; }
  catch { fixtureFail('FIXTURE_SCHEMA_UNSUPPORTED'); }
}

async function loadVerifiedFixture(destination, options, limits, budget) {
  const fileSystem = adapterFileSystem(options);
  const directory = resolve(options.cwd ?? process.cwd(), ...portableSegments(destination));
  const request = await readJson(resolve(directory, 'fixture-request.json'), MAX_CONTROL_BYTES, budget, fileSystem);
  if (request.schemaVersion !== REQUEST_SCHEMA || request.profile?.version !== PROFILE_VERSION) {
    fixtureFail('FIXTURE_SCHEMA_UNSUPPORTED');
  }
  budget.count(request.scale?.pathCount, limits.inventoryRecords);
  budget.count(request.scale?.historyOperationCount, limits.operationRecords);
  const verify = await fixtureVerifier(options);
  let verification;
  try {
    verification = await budget.wait(signal => verify(destination, {
      cwd: options.cwd, deep: true, signal
    }));
  }
  catch (error) {
    if (error instanceof OgvcsError && error.code === 'LIMIT_TIME') throw error;
    if (error?.type === 'resource-limit') throw error;
    fixtureFail('FIXTURE_SEMANTIC_INVALID');
  }
  if (!verification?.verified || verification.status !== 'valid' || verification.mode !== 'full') fixtureFail('FIXTURE_SEMANTIC_INVALID');
  const [manifest, workload, groups] = await Promise.all([
    readJson(resolve(directory, 'manifest.json'), MAX_GROUP_BYTES, budget, fileSystem),
    readJson(resolve(directory, 'workload-profile.json'), MAX_CONTROL_BYTES, budget, fileSystem),
    readJson(resolve(directory, 'groups.json'), MAX_GROUP_BYTES, budget, fileSystem)
  ]);
  const { manifestDigest, ...manifestBody } = manifest;
  if (manifest.schemaVersion !== MANIFEST_SCHEMA || workload.schemaVersion !== PROFILE_SCHEMA ||
      workload.id !== request.profile.id || workload.version !== PROFILE_VERSION || manifest.profile?.id !== request.profile.id ||
      manifest.profile?.version !== PROFILE_VERSION || !Array.isArray(groups) ||
      manifest.inventory?.path !== 'inventory.ndjson' || manifest.extensions?.['artifacts.groups'] !== 'groups.json' ||
      canonicalFixtureDigest(request, 'ogvcs.fixture/request/v1') !== manifest.requestDigest ||
      canonicalFixtureDigest(manifestBody, 'ogvcs.fixture/manifest/v1') !== manifestDigest ||
      manifest.requestDigest !== verification.requestDigest || manifestDigest !== verification.manifestDigest ||
      canonicalFixtureDigest(groups, 'ogvcs.fixture/groups/v1') !== manifest.extensions['groups.digest']) {
    fixtureFail('FIXTURE_SCHEMA_UNSUPPORTED');
  }
  budget.count(groups.length, limits.groups);
  const inventory = await readNdjson(
    resolve(directory, 'inventory.ndjson'), limits.inventoryRecords, budget, fileSystem
  );
  const operations = await readNdjson(
    resolve(directory, 'operations.ndjson'), limits.operationRecords, budget, fileSystem
  );
  if (inventory.records.length !== request.scale.pathCount || operations.records.length !== request.scale.historyOperationCount ||
      inventory.digest !== manifest.inventory.digest || operationChainDigest(operations.records) !== manifest.digests.operations ||
      manifest.counts?.paths !== inventory.records.length || manifest.counts?.files !== inventory.records.length ||
      manifest.counts?.operations !== operations.records.length || manifest.counts?.groups !== groups.length) fixtureFail();
  return { destination, directory, groups, inventory: inventory.records.map(item => item.value), manifest,
    operationLines: operations.records, request, verification, verifier: verify, workload };
}

async function reverifyFixture(fixture, options, budget) {
  let result;
  try {
    result = await budget.wait(signal => fixture.verifier(fixture.destination, {
      cwd: options.cwd, deep: true, signal
    }));
  }
  catch (error) {
    if (error instanceof OgvcsError && error.code === 'LIMIT_TIME') throw error;
    if (error?.type === 'resource-limit') throw error;
    fixtureFail('FIXTURE_SEMANTIC_INVALID');
  }
  if (!result?.verified || result.status !== 'valid' || result.mode !== 'full' ||
      result.requestDigest !== fixture.verification.requestDigest || result.manifestDigest !== fixture.verification.manifestDigest) {
    fixtureFail('FIXTURE_SEMANTIC_INVALID');
  }
}

function contentPolicy(role) { return profileMap('fixture-content.opengamevcs.test', role, 2); }
function groupProfile(kind) { return profileMap('fixture-group.opengamevcs.test', kind, 2); }
function roleProfile(kind, role) {
  if (kind === 'package-sidecars') return profileMap('fixture-role.opengamevcs.test', role === 'package' ? 'package' : 'sidecar', 2);
  if (kind === 'map-external-actors') return profileMap('fixture-role.opengamevcs.test', role === 'map' ? 'map' : 'external-actor', 2);
  if (kind === 'asset-meta') return profileMap('fixture-role.opengamevcs.test', role === 'meta' ? 'meta' : 'primary', 2);
  return profileMap('fixture-role.opengamevcs.test', 'member', 2);
}

function createEmitter(registry, options, limits, budget) {
  const objects = new Map(); let retainedBytes = 0;
  const maximum = options.maxRetainedBytes ?? DEFAULT_RETAINED_BYTES;
  if (!Number.isSafeInteger(maximum) || maximum < 0 || maximum > DEFAULT_RETAINED_BYTES) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const external = options.objectSink;
  if (external !== undefined && (typeof external.write !== 'function' || typeof external.commit !== 'function' || typeof external.abort !== 'function')) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const record = (reference, payload) => {
    if (payload === undefined) return Object.freeze({ payload: undefined, ref: reference });
    const stored = payload.slice();
    return Object.freeze({ get payload() { return stored.slice(); }, ref: reference });
  };
  const emit = async (kind, payload) => {
    const reference = hashObject(kind, payload, { registry: registry.kindNames }); const key = reference.toString();
    if (objects.has(key)) return reference;
    budget.count(objects.size + 1, limits.objects);
    const retained = OBJECT_REFERENCE_OVERHEAD + (external ? 0 : payload.length);
    if (retained > maximum - retainedBytes) fail('LIMIT_MEMORY', { layer: 1 });
    retainedBytes += retained;
    if (external) {
      await budget.wait(signal => external.write({ kind, payload: payload.slice(), reference }, { signal }));
    }
    else {
      objects.set(key, record(reference, payload));
    }
    if (external) objects.set(key, record(reference));
    budget.checkTime();
    return reference;
  };
  return {
    abort: error => external === undefined ? undefined : budget.cleanup(signal => external.abort(error, { signal })),
    commit: summary => external === undefined ? undefined : budget.wait(signal => external.commit(summary, { signal })),
    emit, objects, retainedBytes: () => retainedBytes
  };
}

async function fileByteSource(filePath, expectedBytes, budget, fileSystem) {
  const handle = await openBounded(
    fileSystem, filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0), budget
  );
  try {
    const stat = await budget.wait(signal => handle.stat({ signal }));
    if (!stat.isFile() || BigInt(stat.size) !== BigInt(expectedBytes)) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
    const stream = fileSystem.createReadStream(filePath, { autoClose: false, fd: handle.fd });
    return { iterable: stream, close: signal => handle.close({ signal }) };
  } catch (error) {
    if (budget.controller.signal.aborted) budget.cleanup(signal => handle.close({ signal }));
    else {
      try { await budget.wait(signal => handle.close({ signal })); } catch {}
    }
    throw error;
  }
}

function checkedBoundaries(boundaries, logicalBytes, limits, budget) {
  if (!Array.isArray(boundaries)) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
  budget.count(boundaries.length, limits.manifestParts);
  let total = 0n;
  for (const value of boundaries) {
    if (!Number.isSafeInteger(value) || value <= 0 || value > MAX_CHUNK_BYTES) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
    total += BigInt(value);
  }
  if (total !== BigInt(logicalBytes) || (logicalBytes === 0 && boundaries.length !== 0)) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
  return boundaries;
}

async function contentManifest(record, fixture, descriptorReference, emitter, registry, options, limits, budget) {
  let logicalBytes = record.content.logicalBytes;
  let expectedDigest = record.content.digest;
  let canUseMaterialized = true;
  if (record.content.representation === 'large-version-recipe') {
    const descriptor = await readJson(
      resolve(fixture.directory, 'large-file.json'), MAX_CONTROL_BYTES, budget, adapterFileSystem(options)
    );
    const { descriptorDigest, ...descriptorBody } = descriptor;
    if (descriptorDigest !== fixture.manifest.extensions['large-file.descriptor-digest'] ||
        canonicalFixtureDigest(descriptorBody, 'ogvcs.fixture/large-file-descriptor/v2') !== descriptorDigest) {
      fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
    }
    const selected = options.largeFileVersion;
    if (!Number.isSafeInteger(selected) || selected < 0) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
    const version = descriptor.physical?.versionDigests?.find(item => item.version === selected);
    if (!version || version.bytes !== descriptor.logicalBytes) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
    logicalBytes = version.bytes; expectedDigest = version.digest;
    const latest = Math.max(...descriptor.physical.versionDigests.map(item => item.version));
    canUseMaterialized = descriptor.physical.mode === 'full' && selected === latest;
  }
  const configuredBoundaries = options.boundaries === undefined ? undefined :
    await budget.wait(signal => options.boundaries(record, { signal }));
  const boundaries = checkedBoundaries(configuredBoundaries ??
    (logicalBytes <= MAX_CHUNK_BYTES ? (logicalBytes === 0 ? [] : [logicalBytes]) : undefined),
  logicalBytes, limits, budget);
  let source = options.contentSource === undefined ? undefined : await budget.wait(signal =>
    options.contentSource({ descriptorReference, fixture, logicalBytes, record, signal }));
  let close;
  if (source === undefined && canUseMaterialized) {
    try {
      const opened = await fileByteSource(
        resolve(fixture.directory, 'files', ...portableSegments(record.logicalPath)),
        logicalBytes, budget, adapterFileSystem(options)
      );
      source = opened.iterable; close = opened.close;
    }
    catch (error) {
      if (error instanceof OgvcsError && error.errorClass === 'resource') throw error;
      fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
    }
  }
  if (!source?.[Symbol.asyncIterator] && !source?.[Symbol.iterator]) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
  const whole = createHash('sha256'); const parts = []; let boundaryIndex = 0;
  let target = boundaries[0] ?? 0; let chunk = Buffer.alloc(target); let filled = 0; let total = 0;
  const iterator = source[Symbol.asyncIterator]?.() ?? source[Symbol.iterator]?.();
  let exhausted = false;
  try {
    while (true) {
      const step = await budget.wait(() => iterator.next());
      if (!step || typeof step !== 'object') fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
      if (step.done) { exhausted = true; break; }
      const raw = step.value;
      const bytes = raw instanceof Uint8Array ? raw : fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
      budget.addInputBytes(bytes.length);
      let offset = 0; whole.update(bytes); total += bytes.length;
      if (total > logicalBytes) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
      while (offset < bytes.length) {
        if (boundaryIndex >= boundaries.length) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
        const take = Math.min(bytes.length - offset, target - filled);
        chunk.set(bytes.subarray(offset, offset + take), filled); filled += take; offset += take;
        if (filled === target) {
          const reference = await emitter.emit(1, chunk);
          parts.push(new Map([[0, reference.toMap()], [1, target]]));
          boundaryIndex++; target = boundaries[boundaryIndex] ?? 0; chunk = Buffer.alloc(target); filled = 0;
        }
      }
      budget.checkTime();
    }
  } finally {
    if (!exhausted && typeof iterator.return === 'function') {
      if (budget.controller.signal.aborted) budget.cleanup(() => iterator.return());
      else await budget.wait(() => iterator.return());
    }
    if (close) {
      if (budget.controller.signal.aborted) budget.cleanup(signal => close(signal));
      else await budget.wait(signal => close(signal));
    }
  }
  const actual = whole.digest('hex');
  if (total !== logicalBytes || boundaryIndex !== boundaries.length || actual !== expectedDigest) fixtureFail('FIXTURE_CONTENT_UNAVAILABLE');
  const manifest = new Map([[0, 1], [1, 2], [2, []], [16, logicalBytes], [17, digestMap(hexBytes(expectedDigest, 32, 'FIXTURE_CONTENT_UNAVAILABLE'))],
    [18, profileMap('chunking.test', 'external-boundaries', 1)], [19, parts]]);
  const payload = encodeMetadata(manifest, { registry }); return emitter.emit(2, payload);
}

function treeModel(inventory, manifests, ledger, limits, budget) {
  const root = { directories: new Map(), files: [] };
  let nodes = 1;
  for (const record of inventory) {
    const parts = portableSegments(record.logicalPath); let node = root;
    for (const segment of parts.slice(0, -1)) {
      if (!node.directories.has(segment)) {
        node.directories.set(segment, { directories: new Map(), files: [] });
        budget.count(++nodes, limits.treeNodes);
      }
      node = node.directories.get(segment);
    }
    node.files.push({ basename: parts.at(-1), record, reference: manifests.get(record.logicalPath) });
    budget.count(++nodes, limits.treeNodes);
  }
  return root;
}

async function emitTree(node, prefix, descriptor, ledger, emitter, registry) {
  const entries = [];
  for (const [basename, child] of node.directories) {
    const path = [...prefix, basename]; const reference = await emitTree(child, path, descriptor, ledger, emitter, registry);
    entries.push(new Map([[0, basename], [1, 1], [2, hexBytes(ledger.directoryIds[path.join('/')], 16)], [3, 1], [4, reference.toMap()], [5, 0], [6, profileMap('content-policy.test', 'opaque', 1)]]));
  }
  for (const item of node.files) {
    const kind = item.record.mode === '100644' ? 2 : item.record.mode === '100755' ? 3 : fixtureFail();
    entries.push(new Map([[0, item.basename], [1, kind], [2, hexBytes(ledger.fileIds[item.record.fileId], 16)], [3, kind],
      [4, item.reference.toMap()], [5, item.record.content.logicalBytes], [6, contentPolicy(item.record.role)]]));
  }
  entries.sort((left, right) => Buffer.compare(Buffer.from(left.get(0)), Buffer.from(right.get(0))));
  const value = new Map([[0, 1], [1, 3], [2, []], [16, descriptor.toMap()], [17, entries]]);
  return emitter.emit(3, encodeMetadata(value, { registry }));
}

function groupObjects(fixture, ledger) {
  const byPath = new Map(fixture.inventory.map(record => [record.logicalPath, record]));
  const fileIds = new Map();
  for (const record of fixture.inventory) fileIds.set(fileIdText(hexBytes(ledger.fileIds[record.fileId], 16)), record.logicalPath);
  const groups = [];
  for (const relationship of fixture.groups) {
    if (!relationship || typeof relationship.id !== 'string' || typeof relationship.kind !== 'string' || !Array.isArray(relationship.members) || relationship.members.length === 0) fixtureFail();
    const members = relationship.members.map(path => {
      const record = byPath.get(path); if (!record) fixtureFail();
      return new Map([[0, hexBytes(ledger.fileIds[record.fileId], 16)], [1, roleProfile(relationship.kind, record.role)]]);
    });
    members.sort((left, right) => {
      const profileOrder = Buffer.compare(Buffer.from(encodeCanonical(left.get(1))), Buffer.from(encodeCanonical(right.get(1))));
      return profileOrder || Buffer.compare(Buffer.from(left.get(0)), Buffer.from(right.get(0)));
    });
    const first = byPath.get(relationship.members[0]);
    const group = new Map([[0, hexBytes(ledger.groupIds[relationship.id], 16)], [1, groupProfile(relationship.kind)],
      [2, hexBytes(ledger.fileIds[first.fileId], 16)], [3, members]]);
    const synthetic = [...new Set(relationship.members.map(path => byPath.get(path)?.syntheticGuid).filter(Boolean))];
    if (synthetic.length > 1) fixtureFail();
    if (synthetic.length === 1) group.set(4, [new Map([[0, profileMap('fixture-key.opengamevcs.test', 'synthetic-guid', 2)], [1, hexBytes(synthetic[0], 16)]])]);
    groups.push(group);
  }
  groups.sort((left, right) => Buffer.compare(Buffer.from(left.get(0)), Buffer.from(right.get(0))));
  validateAssetGroups(new Map(groups.map(group => [toHex(group.get(0)), group])), fileIds);
  return groups;
}

function fixtureEvents(fixture, registry, limits, budget) {
  budget.count(fixture.operationLines.length, limits.operationRecords);
  const scenario = digestMap(hexBytes(fixture.manifest.operationScenario.digest, 32));
  return fixture.operationLines.map(({ raw, value }, sequence) => {
    if (value.sequence !== sequence || typeof value.kind !== 'string') fixtureFail();
    const record = new Map([[0, 1], [1, 9], [16, scenario], [17, sequence],
      [18, profileMap('fixture-event.opengamevcs.test', 'operation', 2)], [19, digestMap(sha256(raw))], [20, value.kind]]);
    validateLogicalRecord(record, { registry }); return record;
  });
}

/**
 * Verify and adapt one OGVCS-001 profile-v2 fixture through public artifacts.
 * This produces a supplied conformance closure and workload records, never a
 * snapshot, authoritative history, or fidelity/export claim.
 */
export async function adaptFixture(destination, options = {}) {
  if (options.requireNativeHistoryBindings !== undefined &&
      typeof options.requireNativeHistoryBindings !== 'boolean') {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const limits = adapterLimits(options);
  const budget = new AdapterBudget(limits);
  budget.checkTime();
  const fixture = await loadVerifiedFixture(destination, options, limits, budget);
  // Profile-v2 operation records intentionally describe workload events rather
  // than complete immutable repository transitions. Callers that require
  // native history must fail closed instead of interpreting those events as
  // snapshots or change sets. A future fixture schema can replace this guard
  // with a registered complete binding artifact.
  if (options.requireNativeHistoryBindings) fixtureFail('FIXTURE_NATIVE_BINDING_MISSING');
  const prepared = await prepareFixtureAdapterLedger(fixture, { ...options, adapterBudget: budget, adapterLimits: limits });
  const registry = options.registry ?? await loadBundledRegistry();
  const emitter = createEmitter(registry, options, limits, budget);
  try {
    const contentProfiles = new Map([['content-policy.test/opaque@1', profileMap('content-policy.test', 'opaque', 1)]]);
    for (const record of fixture.inventory) contentProfiles.set(`fixture-content.opengamevcs.test/${record.role}@2`, contentPolicy(record.role));
    const groupProfiles = new Map(fixture.groups.map(group => [`fixture-group.opengamevcs.test/${group.kind}@2`, groupProfile(group.kind)]));
    const descriptorValue = new Map([[0, 1], [1, 6], [2, []], [16, hexBytes(prepared.ledger.repositoryId, 16)],
      [17, profileMap('path.test', 'opaque', 1)], [18, profileSort(contentProfiles.values())], [19, profileSort(groupProfiles.values())],
      [20, [profileMap('chunking.test', 'external-boundaries', 1)]]]);
    const descriptor = await emitter.emit(6, encodeMetadata(descriptorValue, { registry }));
    const manifests = new Map();
    for (const record of fixture.inventory) {
      manifests.set(record.logicalPath, await contentManifest(record, fixture, descriptor, emitter, registry, options, limits, budget));
    }
    const rootTree = await emitTree(treeModel(fixture.inventory, manifests, prepared.ledger, limits, budget), [], descriptor, prepared.ledger, emitter, registry);
    const groupValues = groupObjects(fixture, prepared.ledger); let groupSet;
    if (groupValues.length > 0) {
      const value = new Map([[0, 1], [1, 5], [2, []], [16, descriptor.toMap()], [17, groupValues]]);
      groupSet = await emitter.emit(5, encodeMetadata(value, { registry }));
    }
    const logicalRecords = fixtureEvents(fixture, registry, limits, budget);
    const roots = [{ kind: 1, identity: rootTree, role: profile('bundle-role.test', 'root', 1) }];
    if (groupSet) roots.push({ kind: 1, identity: groupSet, role: profile('bundle-role.test', 'root', 1) });
    for (const record of logicalRecords) roots.push({
      kind: 2,
      identity: hashLogicalRecord(9, record),
      role: profile('bundle-role.test', 'root', 1)
    });
    budget.count(roots.length, limits.operationRecords + 2);
    const summary = Object.freeze({
      files: fixture.inventory.length,
      fixtureProfile: `${fixture.manifest.profile.id}@${fixture.manifest.profile.version}`,
      groups: fixture.groups.length,
      logicalRecords: logicalRecords.length,
      manifestDigest: fixture.manifest.manifestDigest,
      objects: emitter.objects.size,
      requestDigest: fixture.manifest.requestDigest,
      retainedBytes: emitter.retainedBytes()
    });
    // The first pass establishes the normative input contract. Reverification
    // immediately before sink commit prevents an observed workspace mutation
    // from turning staged adapter output into trusted output.
    await reverifyFixture(fixture, options, budget);
    await emitter.commit(summary);
    return Object.freeze({ descriptor, groupSet, ledger: prepared.ledger, logicalRecords,
      objects: Object.freeze([...emitter.objects.values()]), roots: Object.freeze(roots), rootTree, summary });
  } catch (error) {
    emitter.abort(error);
    throw error;
  }
}

export const FIXTURE_ADAPTER_LEDGER_SCHEMA = LEDGER_SCHEMA;
export const FIXTURE_ADAPTER_LIMITS = ADAPTER_HARD_LIMITS;
