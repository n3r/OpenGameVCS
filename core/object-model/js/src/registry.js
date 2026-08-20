import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fail } from './errors.js';
import { ProfileRef } from './types.js';
import { createKindNameAuthority, createLogicalTypeAuthority } from './assignment-authority.js';

export const REGISTRY_FILES = Object.freeze([
  'object-kinds.json', 'hash-algorithms.json', 'common-fields.json', 'kind-fields.json',
  'entry-kinds.json', 'entry-modes.json', 'required-features.json', 'extensions.json',
  'profiles.json', 'logical-record-types.json', 'semantic-enums.json', 'limits.json'
]);
const REGISTRY_IDENTIFIERS = Object.freeze({
  'object-kinds.json': 'ogvcs.repository-format.object-kinds',
  'hash-algorithms.json': 'ogvcs.repository-format.hash-algorithms',
  'common-fields.json': 'ogvcs.repository-format.common-fields',
  'kind-fields.json': 'ogvcs.repository-format.kind-fields',
  'entry-kinds.json': 'ogvcs.repository-format.entry-kinds',
  'entry-modes.json': 'ogvcs.repository-format.entry-modes',
  'required-features.json': 'ogvcs.repository-format.required-features',
  'extensions.json': 'ogvcs.repository-format.extensions',
  'profiles.json': 'ogvcs.repository-format.profiles',
  'logical-record-types.json': 'ogvcs.repository-format.logical-record-types',
  'semantic-enums.json': 'ogvcs.repository-format.semantic-enums',
  'limits.json': 'ogvcs.repository-format.hard-limits'
});
const MAX_REGISTRY_FILE_BYTES = 16_777_216;
const MAX_REGISTRY_SET_BYTES = 33_554_432;
const MAX_REGISTRY_JSON_DEPTH = 256;
const STATES = new Set(['reserved', 'conformance-only', 'ratified', 'deprecated']);
const UNITS = new Set(['bytes', 'edges', 'encoded-bytes', 'entries', 'entries-per-group',
  'items', 'levels', 'members-per-group', 'objects', 'operations', 'parents', 'records',
  'roots', 'segments', 'utf8-bytes', 'groups', 'chunks']);
const COMPLETE_REGISTRY_SNAPSHOTS = new WeakSet();
const COMPLETE_REGISTRY_TOKEN = Symbol('complete-registry-authority');

function invalid() { fail('REGISTRY_INVALID', { layer: 3 }); }
function validateProfileTuple(entry) { try { new ProfileRef(entry.namespace, entry.id, entry.major); } catch { invalid(); } }

let bundledDocuments;
function frozenRegistryDocuments() {
  if (bundledDocuments === undefined) {
    bundledDocuments = Object.freeze(Object.fromEntries(REGISTRY_FILES.map(file => [
      file,
      parseCanonicalRegistryJson(readFileSync(new URL(`../registries/${file}`, import.meta.url)))
    ])));
  }
  return bundledDocuments;
}

/** Returns the immutable format-v1 family for a known frozen profile. */
export function frozenProfileFamily(profile) {
  const key = profile instanceof ProfileRef ? profile.toString() : profile;
  if (typeof key !== 'string') return undefined;
  return frozenRegistryDocuments()['profiles.json'].entries.find(entry =>
    `${entry.namespace}/${entry.id}@${entry.major}` === key
  )?.family;
}

function normalizedJson(value) {
  if (Array.isArray(value)) return value.map(normalizedJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, normalizedJson(value[key])]));
  }
  return value;
}

function equalJson(left, right) {
  return JSON.stringify(normalizedJson(left)) === JSON.stringify(normalizedJson(right));
}

function withoutKeys(value, keys) {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.has(key)));
}

function assignmentKey(file, entry) {
  if (file === 'profiles.json' || file === 'extensions.json') return `${entry.namespace}/${entry.id}@${entry.major}`;
  if (file === 'kind-fields.json') return `${entry.cddlRule}\0${entry.code}`;
  if (file === 'limits.json') return entry.name;
  return entry.code;
}

function allowedLifecycle(previous, current) {
  if (previous === current) return true;
  return current === 'deprecated' && (previous === 'ratified' || previous === 'conformance-only');
}

function validateFrozenEntries(file, baseline, candidate) {
  const indexedCandidate = new Map(candidate.map(entry => [assignmentKey(file, entry), entry]));
  for (const previous of baseline) {
    const current = indexedCandidate.get(assignmentKey(file, previous));
    if (!current || !allowedLifecycle(previous.state, current.state) ||
        !equalJson(withoutKeys(previous, new Set(['state', 'productionWriteAllowed'])),
          withoutKeys(current, new Set(['state', 'productionWriteAllowed'])))) invalid();
  }
}

function validateFrozenAssignments(documents) {
  const baseline = frozenRegistryDocuments();
  for (const file of REGISTRY_FILES) {
    const previous = baseline[file]; const current = documents[file];
    if (!equalJson(withoutKeys(previous, new Set(['entries', 'domains', 'unassigned'])),
      withoutKeys(current, new Set(['entries', 'domains', 'unassigned'])))) invalid();
    if (file === 'semantic-enums.json') {
      const currentDomains = new Map(current.domains.map(domain => [domain.name, domain]));
      for (const previousDomain of previous.domains) {
        const currentDomain = currentDomains.get(previousDomain.name);
        if (!currentDomain || !equalJson(withoutKeys(previousDomain, new Set(['entries', 'unassigned'])),
          withoutKeys(currentDomain, new Set(['entries', 'unassigned'])))) invalid();
        validateFrozenEntries(file, previousDomain.entries, currentDomain.entries);
      }
    } else {
      validateFrozenEntries(file, previous.entries, current.entries);
    }
  }
}

function immutableJson(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(immutableJson));
  if (value && typeof value === 'object') {
    return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, immutableJson(item)])));
  }
  return value;
}

function readOnlySet(values) {
  const set = new Set(values);
  const view = {
    get size() { return set.size; },
    has(value) { return set.has(value); },
    values() { return set.values(); },
    [Symbol.iterator]() { return set[Symbol.iterator](); }
  };
  return Object.freeze(view);
}

function validateJsonDepth(value) {
  const stack = [[value, 1]];
  while (stack.length > 0) {
    const [current, depth] = stack.pop();
    if (!current || typeof current !== 'object') continue;
    if (depth > MAX_REGISTRY_JSON_DEPTH) invalid();
    for (const child of Array.isArray(current) ? current : Object.values(current)) {
      if (child && typeof child === 'object') stack.push([child, depth + 1]);
    }
  }
}

function readOnlyMap(entries) {
  const map = new Map(entries);
  const view = {
    get size() { return map.size; },
    get(key) { return map.get(key); },
    has(key) { return map.has(key); },
    entries() { return map.entries(); },
    keys() { return map.keys(); },
    values() { return map.values(); },
    forEach(callback, thisArg) {
      map.forEach((value, key) => callback.call(thisArg, value, key, view));
    },
    [Symbol.iterator]() { return map[Symbol.iterator](); }
  };
  return Object.freeze(view);
}

function indexed(entries, key) {
  return readOnlyMap(entries.map(entry => {
    const frozen = immutableJson(entry);
    return [key(frozen), frozen];
  }));
}

export function parseCanonicalRegistryJson(source) {
  if (source instanceof Uint8Array) {
    if (source.length >= 3 && source[0] === 0xef && source[1] === 0xbb && source[2] === 0xbf) invalid();
    try { source = new TextDecoder('utf-8', { fatal: true }).decode(source); } catch { invalid(); }
  }
  if (typeof source !== 'string' || source.startsWith('\ufeff') || source.includes('\r') || !source.endsWith('\n') ||
      Buffer.byteLength(source, 'utf8') > MAX_REGISTRY_FILE_BYTES) invalid();
  let value;
  try { value = JSON.parse(source); } catch { invalid(); }
  validateJsonDepth(value);
  let canonical;
  try { canonical = JSON.stringify(value, null, 2); } catch { invalid(); }
  if (`${canonical}\n` !== source) invalid();
  return value;
}

function orderedUnique(entries, selector) {
  let previous;
  const seen = new Set();
  for (const entry of entries) {
    const key = selector(entry);
    if (seen.has(key) || (previous !== undefined && previous >= key)) invalid();
    seen.add(key); previous = key;
  }
}

function exactEntry(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  if (required.some(key => !Object.hasOwn(value, key)) || keys.some(key => !allowed.has(key))) invalid();
}

function nonemptyString(value) {
  if (typeof value !== 'string' || value.length === 0) invalid();
}

function integerList(value, { nonempty = false } = {}) {
  if (!Array.isArray(value) || (nonempty && value.length === 0) ||
      value.some(item => !Number.isSafeInteger(item) || item < 0)) invalid();
  for (let index = 1; index < value.length; index += 1) if (value[index - 1] >= value[index]) invalid();
}

function validateWireShape(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length === 0) invalid();
  for (const [key, item] of Object.entries(value)) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(key)) invalid();
    nonemptyString(item);
  }
}

function validateEntryShape(file, entry) {
  if (file === 'object-kinds.json') {
    exactEntry(entry, ['code', 'name', 'payload', 'state', 'textToken']);
    if (!['raw-bytes', 'deterministic-cbor'].includes(entry.payload) ||
        typeof entry.textToken !== 'string' || Buffer.byteLength(entry.textToken, 'utf8') > 63 ||
        !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(entry.textToken)) invalid();
  } else if (file === 'hash-algorithms.json') {
    exactEntry(entry, ['code', 'digestBytes', 'name', 'state']);
    if (!Number.isSafeInteger(entry.digestBytes) || entry.digestBytes < 1 || entry.digestBytes > 65_535) invalid();
  } else if (file === 'common-fields.json') {
    exactEntry(entry, ['code', 'name', 'required', 'state', 'type']);
    if (typeof entry.required !== 'boolean') invalid();
    nonemptyString(entry.type);
  } else if (file === 'kind-fields.json') {
    exactEntry(entry, ['cddlRule', 'code', 'name', 'requirement', 'scope', 'state', 'type'],
      ['itemType', 'logicalRecordType', 'objectKind']);
    for (const key of ['cddlRule', 'name', 'scope', 'type']) nonemptyString(entry[key]);
    if (entry.scope !== `repository-format.cddl#${entry.cddlRule}` ||
        !['required', 'optional', 'conditional'].includes(entry.requirement) ||
        !Number.isSafeInteger(entry.code) || entry.code < 0 || entry.code > 4095) invalid();
    const discriminators = ['itemType', 'logicalRecordType', 'objectKind'].filter(key => Object.hasOwn(entry, key));
    if (discriminators.length > 1 || discriminators.some(key => !Number.isSafeInteger(entry[key]) || entry[key] < 1)) invalid();
  } else if (file === 'entry-kinds.json') {
    exactEntry(entry, ['allowedModeCodes', 'code', 'name', 'state', 'targetKind']);
    integerList(entry.allowedModeCodes, { nonempty: true }); nonemptyString(entry.targetKind);
  } else if (file === 'entry-modes.json') {
    exactEntry(entry, ['allowedEntryKindCodes', 'code', 'name', 'portableMode', 'state']);
    integerList(entry.allowedEntryKindCodes, { nonempty: true });
    if (typeof entry.portableMode !== 'string' || !/^[0-7]{6}$/.test(entry.portableMode)) invalid();
  } else if (file === 'required-features.json') {
    exactEntry(entry, ['code', 'name', 'state'], ['behavior']);
    if (Object.hasOwn(entry, 'behavior')) nonemptyString(entry.behavior);
  } else if (file === 'extensions.json') {
    exactEntry(entry, ['id', 'major', 'namespace', 'state']);
  } else if (file === 'profiles.json') {
    exactEntry(entry, ['family', 'id', 'major', 'namespace', 'owner', 'productionWriteAllowed', 'state']);
    nonemptyString(entry.owner);
  } else if (file === 'logical-record-types.json') {
    exactEntry(entry, ['code', 'name', 'state'], ['wireShape']);
    if (Object.hasOwn(entry, 'wireShape')) validateWireShape(entry.wireShape);
    if (entry.code >= 10 && !Object.hasOwn(entry, 'wireShape')) invalid();
  } else if (file === 'limits.json') {
    exactEntry(entry, ['errorCode', 'name', 'unit', 'value']);
    if (typeof entry.errorCode !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(entry.errorCode)) invalid();
  }
}

function checkRanges(document, file) {
  const maximums = {
    'common-fields.json': 15,
    'entry-kinds.json': 65_535,
    'entry-modes.json': 65_535,
    'hash-algorithms.json': 65_535,
    'kind-fields.json': 4_095,
    'logical-record-types.json': 65_535,
    'object-kinds.json': 65_535,
    'required-features.json': 0xffff_ffff
  };
  const maximum = maximums[file] ?? Number.MAX_SAFE_INTEGER;
  const ranges = [...(document.reserved ?? []), ...(document.unassigned ?? [])].sort((a, b) => a.from - b.from);
  let end = -1;
  for (const range of ranges) {
    if (!Number.isSafeInteger(range.from) || !Number.isSafeInteger(range.to) || range.from > range.to ||
        range.from <= end || range.to > maximum) invalid();
    end = range.to;
  }
  for (const entry of document.entries ?? []) {
    if (entry.code !== undefined && !Number.isSafeInteger(entry.code)) invalid();
    if (Number.isSafeInteger(entry.code) && (entry.code < 0 ||
        (ranges.length > 0 && entry.code > end) ||
        ranges.some(range => entry.code >= range.from && entry.code <= range.to))) invalid();
  }
}

function validateDocument(file, document) {
  if (!document || typeof document !== 'object' || document.formatVersion !== 1 || document.registryVersion !== 1) invalid();
  if (document.registry === 'ogvcs.repository-format.semantic-enums') {
    if (!Array.isArray(document.domains)) invalid();
    const domainNames = new Set();
    for (const domain of document.domains) {
      if (!domain || typeof domain.name !== 'string' || domainNames.has(domain.name) || !Array.isArray(domain.entries)) invalid();
      domainNames.add(domain.name);
      orderedUnique(domain.entries, entry => String(entry.code).padStart(20, '0'));
      const names = new Set();
      exactEntry(domain, ['entries', 'name']);
      for (const entry of domain.entries) {
        exactEntry(entry, ['code', 'name', 'state']);
        if (!Number.isSafeInteger(entry.code) || entry.code < 0 || typeof entry.name !== 'string' || entry.name.length === 0 ||
            names.has(entry.name) || !STATES.has(entry.state)) invalid();
        names.add(entry.name);
      }
    }
    return;
  }
  if (!Array.isArray(document.entries)) invalid();
  for (const entry of document.entries) validateEntryShape(file, entry);
  for (const entry of document.entries) if (entry.state !== undefined && !STATES.has(entry.state)) invalid();
  if (document.entries.every(entry => entry.code !== undefined) && document.registry !== 'ogvcs.repository-format.kind-fields') {
    orderedUnique(document.entries, entry => String(entry.code).padStart(20, '0'));
    const names = new Set();
    for (const entry of document.entries) {
      if (typeof entry.name !== 'string' || entry.name.length === 0 || names.has(entry.name)) invalid();
      names.add(entry.name);
    }
  }
  checkRanges(document, file);
  if (document.registry === 'ogvcs.repository-format.kind-fields') {
    orderedUnique(document.entries, entry => `${entry.cddlRule}\0${String(entry.code).padStart(5, '0')}`);
    const names = new Set();
    for (const entry of document.entries) {
      if (typeof entry.name !== 'string' || entry.name.length === 0) invalid();
      const key = `${entry.cddlRule}\0${entry.name}`; if (names.has(key)) invalid(); names.add(key);
    }
  }
}

export class RegistrySnapshot {
  constructor({
    objectKinds = [], hashAlgorithms = [], commonFields = [], kindFields = [], entryKinds = [], entryModes = [],
    profiles = [], requiredFeatures = [], extensions = [], limits = [], logicalRecordTypes = [], semanticEnums = [],
    documents = []
  }, authorityToken) {
    this.objectKinds = indexed(objectKinds, entry => entry.code);
    const kindNames = [...this.objectKinds].map(([code, entry]) => [code, entry.textToken ?? entry.name]);
    this.kindNames = authorityToken === COMPLETE_REGISTRY_TOKEN
      ? createKindNameAuthority(kindNames)
      : readOnlyMap(kindNames);
    this.hashAlgorithms = indexed(hashAlgorithms, entry => entry.code);
    this.commonFields = indexed(commonFields, entry => entry.code);
    this.kindFields = indexed(kindFields, entry => `${entry.cddlRule}\0${entry.code}`);
    this.entryKinds = indexed(entryKinds, entry => entry.code);
    this.entryModes = indexed(entryModes, entry => entry.code);
    this.profiles = indexed(profiles, entry => `${entry.namespace}/${entry.id}@${entry.major}`);
    this.requiredFeatures = indexed(requiredFeatures, entry => entry.code);
    this.extensions = indexed(extensions, entry => `${entry.namespace}/${entry.id}@${entry.major}`);
    this.limits = indexed(limits, entry => entry.name);
    this.logicalRecordTypes = indexed(logicalRecordTypes, entry => entry.code);
    const logicalTypeCodes = logicalRecordTypes.map(entry => entry.code);
    this.logicalRecordTypeCodes = authorityToken === COMPLETE_REGISTRY_TOKEN
      ? createLogicalTypeAuthority(logicalTypeCodes)
      : readOnlySet(logicalTypeCodes);
    this.semanticEnums = readOnlyMap(semanticEnums.map(domain => {
      const frozenDomain = immutableJson(domain);
      return [frozenDomain.name, readOnlyMap(frozenDomain.entries.map(entry => [entry.code, entry]))];
    }));
    this.documents = readOnlyMap(documents.map(([name, document]) => [name, immutableJson(document)]));
    Object.freeze(this);
  }
}

export function isCompleteRegistrySnapshot(value) {
  try {
    return value instanceof RegistrySnapshot && COMPLETE_REGISTRY_SNAPSHOTS.has(value) &&
      Object.getPrototypeOf(value) === RegistrySnapshot.prototype && Object.isFrozen(value);
  } catch {
    return false;
  }
}

export function validateRegistrySet(documents) {
  const docs = documents instanceof Map ? Object.fromEntries(documents) : documents;
  if (!docs || typeof docs !== 'object') invalid();
  if (Object.keys(docs).length !== REGISTRY_FILES.length) invalid();
  for (const file of REGISTRY_FILES) {
    if (!Object.hasOwn(docs, file) || docs[file]?.registry !== REGISTRY_IDENTIFIERS[file]) invalid();
    validateDocument(file, docs[file]);
  }
  const objectKinds = docs['object-kinds.json'];
  const profiles = docs['profiles.json'];
  orderedUnique(profiles.entries, entry => `${entry.namespace}\0${entry.id}\0${String(entry.major).padStart(10, '0')}`);
  for (const entry of profiles.entries) {
    validateProfileTuple(entry);
    if (typeof entry.family !== 'string' || entry.family.length === 0 || !STATES.has(entry.state) ||
        entry.productionWriteAllowed !== (entry.state === 'ratified')) invalid();
  }
  const extensions = docs['extensions.json'];
  orderedUnique(extensions.entries, entry => `${entry.namespace}\0${entry.id}\0${String(entry.major).padStart(10, '0')}`);
  for (const entry of extensions.entries) { validateProfileTuple(entry); if (!STATES.has(entry.state)) invalid(); }
  const tokens = new Set();
  for (const entry of objectKinds.entries) {
    if (typeof entry.textToken !== 'string' || entry.textToken.length === 0 || tokens.has(entry.textToken)) invalid();
    tokens.add(entry.textToken);
  }
  const entryKinds = new Map(docs['entry-kinds.json'].entries.map(entry => [entry.code, entry]));
  const modes = new Map(docs['entry-modes.json'].entries.map(entry => [entry.code, entry]));
  for (const entry of entryKinds.values()) {
    if (![...objectKinds.entries].some(kind => kind.name === entry.targetKind)) invalid();
    for (const code of entry.allowedModeCodes) if (!modes.get(code)?.allowedEntryKindCodes.includes(entry.code)) invalid();
  }
  for (const mode of modes.values()) for (const code of mode.allowedEntryKindCodes) if (!entryKinds.get(code)?.allowedModeCodes.includes(mode.code)) invalid();
  for (const entry of docs['common-fields.json'].entries) if (entry.code < 0 || entry.code > 15) invalid();
  if (docs['common-fields.json'].kindFieldRange?.from !== 16 || docs['common-fields.json'].kindFieldRange?.to !== 4095) invalid();
  const limitNames = new Set();
  for (const entry of docs['limits.json'].entries) {
    if (typeof entry.name !== 'string' || entry.name.length === 0 || !Number.isSafeInteger(entry.value) ||
        entry.value <= 0 || limitNames.has(entry.name) || !UNITS.has(entry.unit) ||
        typeof entry.errorCode !== 'string' || entry.errorCode.length === 0) invalid();
    limitNames.add(entry.name);
  }
  validateFrozenAssignments(docs);
  const snapshot = new RegistrySnapshot({
    objectKinds: objectKinds.entries,
    hashAlgorithms: docs['hash-algorithms.json'].entries,
    commonFields: docs['common-fields.json'].entries,
    kindFields: docs['kind-fields.json'].entries,
    entryKinds: docs['entry-kinds.json'].entries,
    entryModes: docs['entry-modes.json'].entries,
    profiles: profiles.entries,
    requiredFeatures: docs['required-features.json'].entries,
    extensions: docs['extensions.json'].entries, limits: docs['limits.json'].entries,
    logicalRecordTypes: docs['logical-record-types.json'].entries,
    semanticEnums: docs['semantic-enums.json'].domains,
    documents: REGISTRY_FILES.map(file => [file, docs[file]])
  }, COMPLETE_REGISTRY_TOKEN);
  COMPLETE_REGISTRY_SNAPSHOTS.add(snapshot);
  return snapshot;
}

async function readRegistryFile(path, maximumBytes) {
  let handle;
  try {
    handle = await open(path, 'r');
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maximumBytes) invalid();
    const chunks = [];
    let total = 0;
    while (true) {
      const buffer = Buffer.allocUnsafe(Math.min(65_536, maximumBytes - total + 1));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximumBytes) invalid();
      chunks.push(buffer.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    if (error?.code === 'REGISTRY_INVALID') throw error;
    invalid();
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function loadRegistryDirectory(directory) {
  const docs = {};
  let total = 0;
  for (const file of REGISTRY_FILES) {
    const contents = await readRegistryFile(join(directory, file), Math.min(MAX_REGISTRY_FILE_BYTES, MAX_REGISTRY_SET_BYTES - total));
    total += contents.length;
    docs[file] = parseCanonicalRegistryJson(contents);
  }
  return validateRegistrySet(docs);
}

export async function registrySetDigest(directory) {
  const hash = createHash('sha256');
  hash.update(Buffer.from('OpenGameVCS registry set\0', 'ascii'));
  hash.update(Buffer.from([0, 1]));
  let total = 0;
  for (const file of REGISTRY_FILES) {
    const registryPath = `registries/${file}`;
    const pathBytes = Buffer.from(registryPath, 'utf8');
    const contents = await readRegistryFile(join(directory, file), Math.min(MAX_REGISTRY_FILE_BYTES, MAX_REGISTRY_SET_BYTES - total));
    total += contents.length;
    const pathLength = Buffer.alloc(4);
    pathLength.writeUInt32BE(pathBytes.length);
    const fileLength = Buffer.alloc(8);
    fileLength.writeBigUInt64BE(BigInt(contents.length));
    hash.update(pathLength);
    hash.update(pathBytes);
    hash.update(fileLength);
    hash.update(contents);
  }
  return hash.digest('hex');
}

export function bundledRegistryDirectory() {
  return fileURLToPath(new URL('../registries/', import.meta.url));
}

export async function loadBundledRegistry() {
  return loadRegistryDirectory(bundledRegistryDirectory());
}

export function registryFromEvolutionSnapshot(document) {
  if (!document || document.formatVersion !== 1) invalid();
  const profiles = document.profiles?.entries ?? [];
  orderedUnique(profiles, entry => `${entry.namespace}\0${entry.id}\0${String(entry.major).padStart(10, '0')}`);
  for (const entry of profiles) {
    validateProfileTuple(entry);
    if (!STATES.has(entry.state) || entry.productionWriteAllowed !== (entry.state === 'ratified')) invalid();
  }
  return new RegistrySnapshot({ profiles, requiredFeatures: document.requiredFeatures?.entries ?? [], extensions: document.extensions?.entries ?? [] });
}

const ASSIGNMENT_COLLECTIONS = Object.freeze({
  'object-kinds': 'objectKinds',
  'hash-algorithms': 'hashAlgorithms',
  'common-fields': 'commonFields',
  'kind-fields': 'kindFields',
  'entry-kinds': 'entryKinds',
  'entry-modes': 'entryModes',
  'required-features': 'requiredFeatures',
  extensions: 'extensions',
  profiles: 'profiles',
  'logical-record-types': 'logicalRecordTypes'
});

function assignmentUnknown(collection) {
  if (collection === 'object-kinds') fail('OBJECT_KIND_UNSUPPORTED', { layer: 2 });
  if (collection === 'logical-record-types') fail('LOGICAL_RECORD_TYPE_UNSUPPORTED', { layer: 2 });
  if (collection === 'required-features') fail('REQUIRED_FEATURE_UNSUPPORTED', { layer: 3 });
  if (collection === 'profiles' || collection === 'extensions') fail('PROFILE_UNKNOWN', { layer: 3 });
  fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}

/** Apply the exhaustive registry-state truth table to one selected assignment. */
export function registryAssignmentDecision(registry, collection, key, operation = 'read') {
  if (!['read', 'conformance', 'production-write'].includes(operation)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  let assignments;
  if (typeof collection === 'string' && collection.startsWith('semantic-enums/')) {
    assignments = registry?.semanticEnums?.get(collection.slice('semantic-enums/'.length));
  } else assignments = registry?.[ASSIGNMENT_COLLECTIONS[collection]];
  if (!assignments?.get) fail('REGISTRY_INVALID', { layer: 3 });
  const entry = assignments.get(key);
  if (!entry) assignmentUnknown(collection);
  if (entry.state === 'reserved') fail('PROFILE_STATE_FORBIDDEN', { layer: 3 });
  const newWrite = operation === 'production-write';
  if (entry.state === 'deprecated' && newWrite) fail('PROFILE_STATE_FORBIDDEN', { layer: 3 });
  if (entry.state === 'conformance-only' && operation !== 'conformance') fail('PROFILE_CONFORMANCE_ONLY', { layer: 3 });
  if (!STATES.has(entry.state)) fail('REGISTRY_INVALID', { layer: 3 });
  return entry;
}

export function profileDecision(registry, profile, operation = 'read') {
  const ref = profile instanceof ProfileRef ? profile : ProfileRef.parse(profile);
  const entry = registryAssignmentDecision(registry, 'profiles', ref.toString(), operation);
  const newWrite = operation === 'production-write';
  if (newWrite && entry.productionWriteAllowed !== true) {
    fail(entry.state === 'conformance-only' ? 'PROFILE_CONFORMANCE_ONLY' : 'PROFILE_STATE_FORBIDDEN', { layer: 3 });
  }
  return entry;
}

export function requiredFeatureDecision(registry, code, operation = 'read') {
  const entry = registryAssignmentDecision(registry, 'required-features', code, operation);
  if (entry.state !== 'ratified' && entry.state !== 'deprecated' && entry.state !== 'conformance-only') {
    fail('REQUIRED_FEATURE_UNSUPPORTED', { layer: 3 });
  }
  return entry;
}
