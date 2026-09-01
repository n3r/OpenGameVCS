#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const PATH_ROOT = dirname(require.resolve('@opengamevcs/path-contract-v1/package.json'));
const encoder = new TextEncoder();
const MAGIC = Buffer.from('OGVCS-SELECT-V1\0', 'ascii');
const DOMAINS = Object.freeze({
  bindings: Buffer.from('OpenGameVCS selective sync evaluation bindings v1\0'),
  metadata: Buffer.from('OpenGameVCS selective sync metadata projection v1\0'),
  output: Buffer.from('OpenGameVCS selective sync output projection v1\0'),
  spec: Buffer.from('OpenGameVCS selective sync spec v1\0'),
});
const MATERIALIZATION = Object.freeze({ full: 1, 'metadata-only': 2, 'absent-by-spec': 3 });
const MATERIALIZATION_BY_CODE = Object.freeze(['invalid', 'full', 'metadata-only', 'absent-by-spec']);
const MATCH = Object.freeze({ exact: 1, subtree: 2 });
const CASE_MODE = Object.freeze({ 'case-sensitive': 1, 'case-folded': 2 });
const PLATFORM = Object.freeze({ linux: 1, macos: 2, windows: 3 });
const BINDING_KEYS = Object.freeze(['snapshotDigest', 'settingsDigest', 'consistencyTokenDigest', 'pathProfile', 'caseMode', 'platform']);
const CONTENT_KEYS = Object.freeze(['digest', 'logicalBytes']);
const EVALUATION_KEYS = Object.freeze(['spec', 'bindings', 'metadata', 'expectedSpecDigest', 'expectedMetadataProjectionDigest', 'declaredRecordCount']);
const RECORD_KEYS = Object.freeze(['ordinal', 'path', 'entryDigest', 'content']);
const RULE_KEYS = Object.freeze(['ordinal', 'match', 'path', 'materialization']);
const SPEC_KEYS = Object.freeze(['schemaVersion', 'version', 'defaultMaterialization', 'rules']);
const CORE_PATH_LIMITS = Object.freeze({ segmentUtf8Bytes: 255, joinedUtf8Bytes: 4096, depth: 256 });
const WINDOWS_FORBIDDEN = /[<>:"\\|?*]/u;
const OPERATIONAL_CONTROL = /[\u0000-\u001f\u007f]/u;
const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
  'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³',
]);

export class SelectionReferenceError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = (code) => { throw new SelectionReferenceError(code); };
const snapshotObject = (value, keys, code) => {
  let actual; let prototype;
  try { actual = Object.keys(value ?? {}).sort(); prototype = Object.getPrototypeOf(value); } catch { fail(code); }
  const expected = [...keys].sort();
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || prototype !== Object.prototype || actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) fail(code);
  const snapshot = {};
  try { for (const key of keys) snapshot[key] = value[key]; } catch { fail(code); }
  return snapshot;
};
const sha256 = (chunks) => {
  const hash = createHash('sha256');
  for (const chunk of chunks) hash.update(chunk);
  return hash.digest();
};
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256Hex = (bytes) => hex(sha256([bytes]));
const canonical = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
};
const digestBytes = (value, code = 'SELECT_BINDING_INVALID') => {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/u.test(value)) fail(code);
  return Buffer.from(value, 'hex');
};
const u64 = (value) => {
  if (!Number.isSafeInteger(value) || value < 0) fail('SELECT_INPUT_INVALID');
  const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes;
};
const text = (value) => {
  if (typeof value !== 'string') fail('SELECT_INPUT_INVALID');
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.toString('utf8') !== value) fail('SELECT_INPUT_INVALID');
  return Buffer.concat([u64(bytes.length), bytes]);
};
const contentFrame = (content, limits) => {
  if (content === null) return Buffer.from([0]);
  if (content === undefined || !Number.isSafeInteger(content.logicalBytes)
      || content.logicalBytes < 0) fail('SELECT_INPUT_INVALID');
  if (content.logicalBytes > limits.logicalBytesMaximum) fail('SELECT_LOGICAL_BYTES_LIMIT');
  return Buffer.concat([Buffer.from([1]), digestBytes(content.digest), u64(content.logicalBytes)]);
};
const normalizeRecord = (value, limits) => {
  const record = snapshotObject(value, RECORD_KEYS, 'SELECT_INPUT_INVALID');
  if (!Number.isSafeInteger(record.ordinal) || record.ordinal < 0 || typeof record.path !== 'string') fail('SELECT_INPUT_INVALID');
  digestBytes(record.entryDigest, 'SELECT_INPUT_INVALID');
  if (record.content !== null) {
    const content = snapshotObject(record.content, CONTENT_KEYS, 'SELECT_INPUT_INVALID');
    digestBytes(content.digest, 'SELECT_INPUT_INVALID');
    if (!Number.isSafeInteger(content.logicalBytes) || content.logicalBytes < 0) fail('SELECT_INPUT_INVALID');
    if (content.logicalBytes > limits.logicalBytesMaximum) fail('SELECT_LOGICAL_BYTES_LIMIT');
    record.content = content;
  }
  return record;
};
const normalizeBindings = (value) => {
  const bindings = snapshotObject(value, BINDING_KEYS, 'SELECT_BINDING_INVALID');
  digestBytes(bindings.snapshotDigest); digestBytes(bindings.settingsDigest); digestBytes(bindings.consistencyTokenDigest);
  if (typeof bindings.pathProfile !== 'string' || !(bindings.caseMode in CASE_MODE)
      || !(bindings.platform in PLATFORM)) fail('SELECT_BINDING_INVALID');
  return bindings;
};
const recordFrame = (record, limits) => {
  const bytes = Buffer.concat([u64(record.ordinal), text(record.path), digestBytes(record.entryDigest), contentFrame(record.content, limits)]);
  if (bytes.length > limits.inputRecordBytesMaximum) fail('SELECT_INPUT_RECORD_LIMIT');
  return bytes;
};
const outputRecordFrame = (record, materialization, limits) => {
  const selectedContent = materialization === 'full' ? record.content : null;
  const bytes = Buffer.concat([u64(record.ordinal), text(record.path), Buffer.from([MATERIALIZATION[materialization]]), contentFrame(selectedContent, limits)]);
  if (bytes.length > limits.outputRecordBytesMaximum) fail('SELECT_OUTPUT_RECORD_LIMIT');
  if (bytes.length > limits.sinkFragmentBytesMaximum) fail('SELECT_SINK_FRAGMENT_LIMIT');
  return bytes;
};
const sourceIterator = (source) => {
  let factory;
  try { factory = source?.[Symbol.iterator]; } catch { fail('SELECT_SOURCE_FAILED'); }
  if (typeof factory !== 'function') fail('SELECT_SOURCE_INVALID');
  let iterator;
  try { iterator = factory.call(source); } catch { fail('SELECT_SOURCE_FAILED'); }
  if (iterator === null || typeof iterator !== 'object') fail('SELECT_SOURCE_INVALID');
  let next;
  try { next = iterator.next; } catch { fail('SELECT_SOURCE_FAILED'); }
  if (typeof next !== 'function') fail('SELECT_SOURCE_INVALID');
  return { iterator, next };
};
const sourceNext = ({ iterator, next }) => {
  let result;
  try { result = next.call(iterator); } catch { fail('SELECT_SOURCE_FAILED'); }
  if (result === null || typeof result !== 'object') fail('SELECT_SOURCE_INVALID');
  let hasDone; let done;
  try { hasDone = Object.hasOwn(result, 'done'); done = result.done; } catch { fail('SELECT_SOURCE_FAILED'); }
  if (!hasDone || (done !== true && done !== false)) fail('SELECT_SOURCE_INVALID');
  if (done) return { done: true };
  let hasValue;
  try { hasValue = Object.hasOwn(result, 'value'); } catch { fail('SELECT_SOURCE_FAILED'); }
  if (!hasValue) fail('SELECT_SOURCE_INVALID');
  return { done: false, result };
};
const sourceValue = (step) => {
  try { return step.result.value; } catch { fail('SELECT_SOURCE_FAILED'); }
};
const pathManifestBytes = await readFile(resolve(PATH_ROOT, 'manifest.json'));
const pathManifest = JSON.parse(pathManifestBytes);
const profileRegistryBytes = await readFile(resolve(PATH_ROOT, 'registries/platform-profiles.json'));
const profiles = JSON.parse(profileRegistryBytes).entries;
const caseFoldingBytes = await readFile(resolve(PATH_ROOT, 'data/CaseFolding-16.0.0.txt'));

function assertUnicodeScalarString(value) {
  if (typeof value !== 'string') throw new TypeError('path must be a string');
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('path contains an unpaired surrogate');
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError('path contains an unpaired surrogate');
    }
  }
}

function parseCaseFolding(bytes) {
  const mappings = new Map();
  for (const line of bytes.toString('utf8').split('\n')) {
    const body = line.split('#', 1)[0].trim();
    if (!body) continue;
    const match = /^([0-9A-F]{4,6});\s*([CFST]);\s*([0-9A-F ]+);$/u.exec(body);
    if (match === null) throw new Error('pinned Unicode case-folding data is malformed');
    const [, sourceHex, status, mappingHex] = match;
    if (status !== 'C' && status !== 'F') continue;
    const source = Number.parseInt(sourceHex, 16);
    if (mappings.has(source)) throw new Error('pinned Unicode case-folding data has a duplicate');
    mappings.set(source, Object.freeze(mappingHex.trim().split(/ +/u).map((part) => Number.parseInt(part, 16))));
  }
  return mappings;
}

const caseFolding = parseCaseFolding(caseFoldingBytes);
const caseFold = (value) => {
  assertUnicodeScalarString(value);
  let result = '';
  for (const scalar of value) {
    const mapping = caseFolding.get(scalar.codePointAt(0));
    result += mapping === undefined ? scalar : String.fromCodePoint(...mapping);
  }
  return result;
};
const profileByRef = (profileRef) => profiles.find((profile) => profile.profile === profileRef);
const windowsDevice = (segment) => WINDOWS_DEVICE_NAMES.has(segment.split('.', 1)[0].toUpperCase());
const encodeKeySegments = (segments) => segments.map((segment) => {
  const bytes = Buffer.from(segment, 'utf8');
  return `${bytes.length.toString(16).padStart(4, '0')}:${bytes.toString('hex')}`;
}).join('/');

function pathCollisionKeys(input, caseMode, profileRef) {
  const profile = profileByRef(profileRef);
  if (profile === undefined || typeof input !== 'string' || input.length === 0 || input.startsWith('/')) return { accepted: false };
  const segments = input.split('/');
  if (segments.length === 0 || segments.length > CORE_PATH_LIMITS.depth || segments.length > profile.limits.depth) return { accepted: false };
  let joinedUtf8 = Math.max(0, segments.length - 1); let joinedUtf16 = Math.max(0, segments.length - 1);
  for (const segment of segments) {
    try { assertUnicodeScalarString(segment); } catch { return { accepted: false }; }
    if (segment.length === 0 || segment === '.' || segment === '..' || segment.includes('/')
        || segment.includes('\\') || segment.includes('\0') || segment.normalize('NFC') !== segment) return { accepted: false };
    const bytes = Buffer.byteLength(segment);
    if (bytes > CORE_PATH_LIMITS.segmentUtf8Bytes || bytes > profile.limits.segmentUtf8Bytes
        || segment.length > profile.limits.segmentUtf16Units) return { accepted: false };
    joinedUtf8 += bytes; joinedUtf16 += segment.length;
    if (OPERATIONAL_CONTROL.test(segment) || caseFold(segment) === '.ogvcs') return { accepted: false };
    if (profile.rules.windowsNames) {
      if (WINDOWS_FORBIDDEN.test(segment) || /[. ]$/u.test(segment) || windowsDevice(segment)) return { accepted: false };
    } else if (profile.rules.macosColon && segment.includes(':')) return { accepted: false };
  }
  if (joinedUtf8 > CORE_PATH_LIMITS.joinedUtf8Bytes || joinedUtf8 > profile.limits.joinedUtf8Bytes
      || joinedUtf16 > profile.limits.joinedUtf16Units) return { accepted: false };
  if (caseMode !== 'case-sensitive' && caseMode !== 'case-folded') return { accepted: false };
  const repositorySegments = caseMode === 'case-folded' ? segments.map(caseFold) : segments;
  const platformSegments = profile.rules.platformCaseFold ? segments.map(caseFold) : segments;
  return {
    accepted: true,
    canonical: segments.join('/'),
    repositoryKey: `ogvcs-path-key-v1:${caseMode}:${encodeKeySegments(repositorySegments)}`,
    platformKey: `ogvcs-platform-key-v1:${profileRef}:${encodeKeySegments(platformSegments)}`,
  };
}

export function referenceCollisionKeys(input, caseMode, profileRef) {
  return pathCollisionKeys(input, caseMode, profileRef);
}

function loadContract(value) {
  if (value?.schemaVersion !== 'ogvcs.selective-sync/kernel-contract/v1') fail('SELECT_CONTRACT_INVALID');
  const pin = value.predecessorPins?.path;
  const caseArtifact = pathManifest.artifacts?.find(({ path }) => path === 'data/CaseFolding-16.0.0.txt');
  const profileArtifact = pathManifest.artifacts?.find(({ path }) => path === 'registries/platform-profiles.json');
  if (pin?.manifestSha256 !== sha256Hex(pathManifestBytes)
      || pin.registrySetSha256 !== pathManifest.registrySetSha256
      || pin.unicodeVersion !== pathManifest.unicode?.version
      || pin.unicodeCaseFoldingSha256 !== sha256Hex(caseFoldingBytes)
      || caseArtifact?.sha256 !== sha256Hex(caseFoldingBytes)
      || profileArtifact?.sha256 !== sha256Hex(profileRegistryBytes)) fail('SELECT_CONTRACT_INVALID');
  return value;
}

function canonicalSpecFrames(spec, contract) {
  const snapshot = snapshotObject(spec, SPEC_KEYS, 'SELECT_SPEC_INVALID');
  if (snapshot.schemaVersion !== contract.selection.schemaVersion || snapshot.version !== 1
      || !(snapshot.defaultMaterialization in MATERIALIZATION) || !Array.isArray(snapshot.rules)
      || snapshot.rules.length > contract.limits.rulesMaximum) fail('SELECT_SPEC_INVALID');
  const frames = [DOMAINS.spec, text(snapshot.schemaVersion), u64(snapshot.version), Buffer.from([MATERIALIZATION[snapshot.defaultMaterialization]]), u64(snapshot.rules.length)];
  let total = 0;
  let collisionKeyBytes = 0;
  const repositorySpellings = new Map(); const platformSpellings = new Map(); const scoped = new Set();
  const exact = new Map(); const subtree = new Map();
  for (let index = 0; index < snapshot.rules.length; index += 1) {
    const rule = snapshotObject(snapshot.rules[index], RULE_KEYS, 'SELECT_SPEC_INVALID');
    if (rule?.ordinal !== index || !(rule.match in MATCH) || !(rule.materialization in MATERIALIZATION)) fail('SELECT_SPEC_INVALID');
    const keys = pathCollisionKeys(rule.path, contract.__caseMode, contract.__pathProfile);
    if (!keys.accepted) fail('SELECT_PATH_INVALID');
    if (Buffer.byteLength(keys.repositoryKey) > contract.limits.collisionKeyBytesMaximum
        || Buffer.byteLength(keys.platformKey) > contract.limits.collisionKeyBytesMaximum) fail('SELECT_COLLISION_KEY_LIMIT');
    collisionKeyBytes += Buffer.byteLength(keys.repositoryKey) + Buffer.byteLength(keys.platformKey);
    if (collisionKeyBytes > contract.limits.collisionKeyBytesTotalMaximum) fail('SELECT_COLLISION_KEY_TOTAL_LIMIT');
    const scopedKey = `${rule.match}\0${keys.repositoryKey}`;
    if (scoped.has(scopedKey)) fail('SELECT_RULE_DUPLICATE');
    scoped.add(scopedKey);
    const priorRepository = repositorySpellings.get(keys.repositoryKey);
    const priorPlatform = platformSpellings.get(keys.platformKey);
    if ((priorRepository !== undefined && priorRepository !== keys.canonical)
        || (priorPlatform !== undefined && priorPlatform !== keys.canonical)) fail('SELECT_PATH_COLLISION');
    repositorySpellings.set(keys.repositoryKey, keys.canonical); platformSpellings.set(keys.platformKey, keys.canonical);
    const frame = Buffer.concat([u64(rule.ordinal), Buffer.from([MATCH[rule.match]]), text(keys.canonical), Buffer.from([MATERIALIZATION[rule.materialization]])]);
    if (frame.length > contract.limits.ruleBytesMaximum) fail('SELECT_RULE_LIMIT');
    total += frame.length;
    if (total > contract.limits.compiledRuleBytesMaximum) fail('SELECT_COMPILED_RULE_LIMIT');
    (rule.match === 'exact' ? exact : subtree).set(keys.repositoryKey, { ordinal: rule.ordinal, materialization: rule.materialization });
    frames.push(frame);
  }
  return { digest: sha256(frames), exact, subtree, collisionKeyBytes, defaultMaterialization: snapshot.defaultMaterialization };
}

function chooseMaterialization(repositoryKey, compiled, fallback) {
  let choice = { ordinal: -1, materialization: fallback };
  const exact = compiled.exact.get(repositoryKey);
  const prefixes = [repositoryKey];
  for (let index = repositoryKey.indexOf('/'); index >= 0; index = repositoryKey.indexOf('/', index + 1)) prefixes.push(repositoryKey.slice(0, index));
  for (const prefix of prefixes) {
    const candidate = compiled.subtree.get(prefix);
    if (candidate !== undefined && candidate.ordinal > choice.ordinal) choice = candidate;
  }
  if (exact !== undefined && exact.ordinal > choice.ordinal) choice = exact;
  return choice.materialization;
}

export function metadataProjectionDigest(records, declaredCount, contractValue) {
  const contract = loadContract(contractValue); const hash = createHash('sha256');
  if (!Number.isSafeInteger(declaredCount) || declaredCount < 0) fail('SELECT_INPUT_INVALID');
  if (declaredCount > contract.limits.metadataRecordsMaximum) fail('SELECT_METADATA_COUNT_LIMIT');
  hash.update(DOMAINS.metadata); hash.update(u64(declaredCount)); let count = 0; let bytes = 0;
  const source = sourceIterator(records);
  while (true) {
    const step = sourceNext(source);
    if (step.done) break;
    if (count >= declaredCount) fail('SELECT_METADATA_COUNT_MISMATCH');
    const record = normalizeRecord(sourceValue(step), contract.limits);
    if (count >= contract.limits.metadataRecordsMaximum) fail('SELECT_METADATA_COUNT_LIMIT');
    if (record.ordinal !== count) fail('SELECT_METADATA_ORDINAL_INVALID');
    const frame = recordFrame(record, contract.limits); bytes += frame.length;
    if (bytes > contract.limits.metadataBytesMaximum) fail('SELECT_METADATA_BYTES_LIMIT');
    hash.update(frame); count += 1;
  }
  if (count !== declaredCount) fail('SELECT_METADATA_COUNT_MISMATCH');
  return { bytes, count, digest: hash.digest() };
}

export function selectionSpecDigest(spec, bindings, contractValue) {
  const snapshot = normalizeBindings(bindings);
  const contract = { ...loadContract(contractValue), __caseMode: snapshot.caseMode, __pathProfile: snapshot.pathProfile };
  return canonicalSpecFrames(spec, contract).digest;
}

function bindingDigest(bindings, specDigestValue, metadataDigestValue, recordCount) {
  if (!(bindings.caseMode in CASE_MODE) || !(bindings.platform in PLATFORM)) fail('SELECT_BINDING_INVALID');
  return sha256([
    DOMAINS.bindings, digestBytes(bindings.snapshotDigest), digestBytes(bindings.settingsDigest),
    digestBytes(bindings.consistencyTokenDigest), text(bindings.pathProfile), Buffer.from([CASE_MODE[bindings.caseMode]]),
    Buffer.from([PLATFORM[bindings.platform]]), specDigestValue, metadataDigestValue, u64(recordCount),
  ]);
}

export function evaluate(requestValue, sink, contractValue, control = { isCancelled: () => false }) {
  const base = loadContract(contractValue);
  const request = snapshotObject(requestValue, EVALUATION_KEYS, 'SELECT_INPUT_INVALID');
  const { spec, metadata, expectedSpecDigest, expectedMetadataProjectionDigest, declaredRecordCount } = request;
  const bindings = normalizeBindings(request.bindings);
  let sinkWrite; let sinkFlush; let cancellationCheck;
  try { sinkWrite = sink?.write; sinkFlush = sink?.flush; cancellationCheck = control?.isCancelled; } catch { fail('SELECT_ADAPTER_INVALID'); }
  if (typeof sinkWrite !== 'function' || typeof sinkFlush !== 'function' || typeof cancellationCheck !== 'function') fail('SELECT_ADAPTER_INVALID');
  const checkCancellation = () => {
    let cancelled;
    try { cancelled = cancellationCheck.call(control); } catch { fail('SELECT_ADAPTER_INVALID'); }
    if (cancelled !== true && cancelled !== false) fail('SELECT_ADAPTER_INVALID');
    if (cancelled) fail('SELECT_CANCELLED');
  };
  if (!Array.isArray(base.selection.platformCompatibility?.[bindings.pathProfile])
      || !base.selection.platformCompatibility[bindings.pathProfile].includes(bindings.platform)) fail('SELECT_PLATFORM_PROFILE_MISMATCH');
  if (!Number.isSafeInteger(declaredRecordCount) || declaredRecordCount < 0
      || declaredRecordCount > base.limits.metadataRecordsMaximum) fail('SELECT_METADATA_COUNT_LIMIT');
  const contract = { ...base, __caseMode: bindings.caseMode, __pathProfile: bindings.pathProfile };
  const compiled = canonicalSpecFrames(spec, contract);
  if (!compiled.digest.equals(digestBytes(expectedSpecDigest))) fail('SELECT_SPEC_DIGEST_MISMATCH');
  const expectedMetadata = digestBytes(expectedMetadataProjectionDigest);
  const binding = bindingDigest(bindings, compiled.digest, expectedMetadata, declaredRecordCount);
  const outputHash = createHash('sha256'); outputHash.update(DOMAINS.output);
  let outputBytes = 0;
  const emit = (bytes) => {
    if (bytes.length > base.limits.sinkFragmentBytesMaximum) fail('SELECT_SINK_FRAGMENT_LIMIT');
    const nextBytes = outputBytes + bytes.length; if (nextBytes > base.limits.outputBytesMaximum) fail('SELECT_OUTPUT_BYTES_LIMIT');
    const privateFragment = Buffer.from(bytes); outputHash.update(privateFragment);
    let returned;
    try { returned = sinkWrite.call(sink, Buffer.from(privateFragment)); } catch { fail('SELECT_SINK_FAILED'); }
    if (returned !== undefined) fail('SELECT_SINK_INVALID');
    outputBytes = nextBytes;
  };
  checkCancellation();
  emit(MAGIC); emit(u64(declaredRecordCount)); emit(binding);
  const metadataHash = createHash('sha256'); metadataHash.update(DOMAINS.metadata); metadataHash.update(u64(declaredRecordCount));
  const platformSpellings = new Map(); let previousRepositoryKey = null; let collisionKeyBytes = compiled.collisionKeyBytes;
  let count = 0; let metadataBytes = 0; let fullCount = 0; let metadataOnlyCount = 0; let absentBySpecCount = 0; let fullContentCount = 0; let fullLogicalBytes = 0;
  const source = sourceIterator(metadata);
  while (true) {
    checkCancellation();
    const step = sourceNext(source);
    checkCancellation();
    if (step.done) break;
    if (count >= declaredRecordCount) fail('SELECT_METADATA_COUNT_MISMATCH');
    const record = normalizeRecord(sourceValue(step), base.limits);
    if (count >= base.limits.metadataRecordsMaximum) fail('SELECT_METADATA_COUNT_LIMIT');
    if (record.ordinal !== count) fail('SELECT_METADATA_ORDINAL_INVALID');
    const keys = pathCollisionKeys(record.path, bindings.caseMode, bindings.pathProfile);
    if (!keys.accepted) fail('SELECT_PATH_INVALID');
    if (Buffer.byteLength(keys.repositoryKey) > base.limits.collisionKeyBytesMaximum
        || Buffer.byteLength(keys.platformKey) > base.limits.collisionKeyBytesMaximum) fail('SELECT_COLLISION_KEY_LIMIT');
    collisionKeyBytes += Buffer.byteLength(keys.repositoryKey) + Buffer.byteLength(keys.platformKey);
    if (collisionKeyBytes > base.limits.collisionKeyBytesTotalMaximum) fail('SELECT_COLLISION_KEY_TOTAL_LIMIT');
    if (previousRepositoryKey !== null && previousRepositoryKey >= keys.repositoryKey) {
      if (previousRepositoryKey === keys.repositoryKey) fail('SELECT_PATH_COLLISION');
      fail('SELECT_METADATA_ORDER_INVALID');
    }
    previousRepositoryKey = keys.repositoryKey;
    const prior = platformSpellings.get(keys.platformKey);
    if (prior !== undefined) fail('SELECT_PATH_COLLISION');
    platformSpellings.set(keys.platformKey, keys.canonical);
    const frame = recordFrame(record, base.limits); metadataBytes += frame.length;
    if (metadataBytes > base.limits.metadataBytesMaximum) fail('SELECT_METADATA_BYTES_LIMIT');
    metadataHash.update(frame);
    const materialization = chooseMaterialization(keys.repositoryKey, compiled, compiled.defaultMaterialization);
    if (materialization === 'full') { fullCount += 1; if (record.content !== null) { fullContentCount += 1; fullLogicalBytes += record.content.logicalBytes; if (!Number.isSafeInteger(fullLogicalBytes) || fullLogicalBytes > base.limits.fullLogicalBytesMaximum) fail('SELECT_LEDGER_LIMIT'); } }
    else if (materialization === 'metadata-only') metadataOnlyCount += 1;
    else absentBySpecCount += 1;
    emit(outputRecordFrame(record, materialization, base.limits)); count += 1;
  }
  if (count !== declaredRecordCount) fail('SELECT_METADATA_COUNT_MISMATCH');
  const actualMetadata = metadataHash.digest();
  if (!actualMetadata.equals(expectedMetadata)) fail('SELECT_METADATA_DIGEST_MISMATCH');
  checkCancellation();
  let flushed;
  try { flushed = sinkFlush.call(sink); } catch { fail('SELECT_SINK_FAILED'); }
  if (flushed !== undefined) fail('SELECT_SINK_INVALID');
  return Object.freeze({
    bindingsDigest: hex(binding), metadataProjectionDigest: hex(actualMetadata), outputProjectionDigest: hex(outputHash.digest()),
    recordCount: count, fullCount, metadataOnlyCount, absentBySpecCount, fullContentCount, fullLogicalBytes,
    metadataBytes, outputBytes,
  });
}

export function decodeProjection(bytes) {
  let input;
  try { input = Buffer.from(bytes); } catch { fail('SELECT_PROJECTION_INVALID'); }
  let offset = 0;
  const take = (count) => { if (offset + count > input.length) fail('SELECT_PROJECTION_INVALID'); const value = input.subarray(offset, offset + count); offset += count; return value; };
  const readSafeU64 = () => { const value = take(8).readBigUInt64BE(); if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail('SELECT_PROJECTION_INVALID'); return Number(value); };
  if (!take(MAGIC.length).equals(MAGIC)) fail('SELECT_PROJECTION_INVALID');
  const count = readSafeU64(); if (count > 100_000) fail('SELECT_PROJECTION_INVALID');
  const bindingsDigest = hex(take(32)); const records = [];
  for (let ordinal = 0; ordinal < count; ordinal += 1) {
    const actualOrdinal = readSafeU64(); if (actualOrdinal !== ordinal) fail('SELECT_PROJECTION_INVALID');
    const length = readSafeU64(); if (length > 4_096 || length > input.length - offset) fail('SELECT_PROJECTION_INVALID');
    const pathBytes = take(length); const path = pathBytes.toString('utf8'); if (!Buffer.from(path).equals(pathBytes)) fail('SELECT_PROJECTION_INVALID');
    const materialization = MATERIALIZATION_BY_CODE[take(1)[0]]; if (materialization === undefined || materialization === 'invalid') fail('SELECT_PROJECTION_INVALID');
    const tag = take(1)[0]; let content = null;
    if (tag === 1) content = { digest: hex(take(32)), logicalBytes: readSafeU64() };
    else if (tag !== 0) fail('SELECT_PROJECTION_INVALID');
    if (materialization !== 'full' && content !== null) fail('SELECT_PROJECTION_INVALID');
    records.push({ ordinal: actualOrdinal, path, materialization, content });
  }
  if (offset !== input.length) fail('SELECT_PROJECTION_INVALID');
  return { bindingsDigest, records };
}

export function calculateGolden(vector, contract) {
  const specDigestValue = selectionSpecDigest(vector.spec, vector.bindings, contract);
  const metadataProjection = metadataProjectionDigest(vector.metadata, vector.metadata.length, contract);
  const chunks = []; const sink = { write(bytes) { chunks.push(Buffer.from(bytes)); }, flush() {} };
  const summary = evaluate({
    spec: vector.spec, bindings: vector.bindings, metadata: vector.metadata,
    expectedSpecDigest: hex(specDigestValue), expectedMetadataProjectionDigest: hex(metadataProjection.digest),
    declaredRecordCount: vector.metadata.length,
  }, sink, contract);
  const projection = Buffer.concat(chunks); const decoded = decodeProjection(projection);
  return {
    specDigest: hex(specDigestValue), metadataProjectionDigest: hex(metadataProjection.digest),
    projectionHex: hex(projection), summary,
    classes: decoded.records.map(({ materialization, content }) => ({ materialization, contentPresent: content !== null })),
  };
}

async function main() {
  const contract = JSON.parse(await readFile(resolve(ROOT, 'contract.json'), 'utf8'));
  const golden = JSON.parse(await readFile(resolve(ROOT, 'vectors/golden.json'), 'utf8'));
  if (process.argv[2] === '--emit-source') {
    process.stdout.write(`${JSON.stringify({ schemaVersion: golden.schemaVersion, cases: golden.cases.map((vector) => ({ caseId: vector.caseId, expected: calculateGolden(vector, contract) })) })}\n`);
    return;
  }
  if (process.argv.length !== 2) throw new Error('usage: node scripts/reference.mjs [--emit-source]');
  for (const vector of golden.cases) {
    const actual = calculateGolden(vector, contract);
    if (canonical(actual) !== canonical(vector.expected)) throw new Error(`${vector.caseId}: differs from independent Node evaluation`);
    if (actual.classes.some(({ materialization, contentPresent }) => materialization !== 'full' && contentPresent)) throw new Error(`${vector.caseId}: excluded class carries content identity`);
  }
  process.stdout.write(`checked ${golden.cases.length} selective-sync golden cases with independent Node evaluator\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();
