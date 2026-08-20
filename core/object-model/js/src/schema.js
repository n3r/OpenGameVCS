import { decodeCanonical, encodeCanonical } from './cbor.js';
import { OgvcsError, errorPrecedence, fail as throwFailure } from './errors.js';
import { configuredHardLimit, enforceHardLimit, hardLimitMaximum } from './hard-limits.js';
import { Digest, FileId, KIND_NAMES, ObjectRef, ProfileRef, equalBytes } from './types.js';
import { hashConflictPreimage, hashLogicalRecord, hashObject, hashOpaqueObject, sha256Digest } from './hash.js';
import {
  frozenProfileFamily, profileDecision, registryAssignmentDecision, requiredFeatureDecision
} from './registry.js';
import {
  codecValidationContext, registrySnapshot, writerValidationContext
} from './validation-mode.js';
import { isUnicode15String } from './unicode-age.js';

const MAX = Object.freeze({
  value: hardLimitMaximum('generic-text-or-byte-value-bytes'),
  message: hardLimitMaximum('snapshot-message-bytes'),
  extensions: hardLimitMaximum('extensions-per-object'),
  extensionBytes: hardLimitMaximum('extension-aggregate-bytes-per-object'),
  segment: hardLimitMaximum('path-segment-bytes'),
  path: hardLimitMaximum('path-bytes'),
  pathSegments: hardLimitMaximum('path-segments'),
  treeEntries: hardLimitMaximum('tree-entries'),
  parents: hardLimitMaximum('snapshot-parents'),
  operations: hardLimitMaximum('change-set-operations'),
  groups: hardLimitMaximum('asset-groups'),
  members: hardLimitMaximum('asset-group-members'),
  chunks: hardLimitMaximum('manifest-chunks'),
  chunkBytes: hardLimitMaximum('chunk-payload-bytes'),
  logical: BigInt(hardLimitMaximum('logical-file-bytes')),
  metadataBytes: hardLimitMaximum('metadata-payload-bytes'),
  nesting: hardLimitMaximum('cbor-nesting-depth')
});
const FAMILIES = Object.freeze({
  path: ['path'], content: ['content-policy', 'fixture-content-policy'],
  group: ['group', 'fixture-group'], role: ['group-role', 'fixture-group-role'],
  external: ['external-key', 'fixture-external-key'], identity: ['identity'], importer: ['importer'],
  policy: ['policy'], provenance: ['provenance'], predicate: ['attestation-predicate'],
  signature: ['signature'], annotation: ['annotation-payload'], bundleRole: ['bundle-root-role'],
  fixtureEvent: ['fixture-event'], chunking: ['chunking'], conflictDriver: ['conflict-driver']
});
const FIXTURE_OPERATIONS = new Set(['branch', 'branch-update', 'ci-materialize', 'copy', 'create', 'delete',
  'edit', 'interrupt', 'lock-acquire', 'lock-conflict', 'lock-loss', 'merge', 'move', 'network-condition',
  'rename', 'review', 'selective-sync', 'submit']);
const OBJECT_RULES = Object.freeze({
  2: 'content-manifest', 3: 'tree', 4: 'change-set', 5: 'group-set', 6: 'repository-descriptor',
  7: 'snapshot', 8: 'shelf-revision', 9: 'provenance', 10: 'attestation', 11: 'conflict-set'
});
const LOGICAL_RULES = Object.freeze({
  1: 'repository-root-record', 2: 'mutable-ref-record', 3: 'shelf-pointer-record',
  4: 'fileid-lifetime-record', 5: 'import-mapping-record', 6: 'pending-change-reference-record',
  7: 'lock-reference-record', 8: 'annotation-record', 9: 'fixture-event-record'
});
const BUNDLE_RULES = Object.freeze({
  1: 'bundle-header', 2: 'bundle-object', 3: 'bundle-logical-record', 4: 'bundle-root', 5: 'bundle-trailer'
});
// One ranked error candidate plus the non-recursive validator frame. The
// collector remains constant-space regardless of how many caller fields fail,
// but its fixed workspace is still admitted before caller-owned input is read.
const KNOWN_SCHEMA_WORKING_BYTES = 512;

const knownSchemaCollectors = [];

function currentKnownSchemaCollector() {
  return knownSchemaCollectors.at(-1);
}

class KnownSchemaTerminal extends Error {
  constructor(error) { super(error.code); this.error = error; }
}

function recordKnownSchema(error, stage = 5) {
  if (stage === 0) throw new KnownSchemaTerminal(error);
  const collector = currentKnownSchemaCollector();
  const candidate = { error, stage };
  if (!collector.best || stage < collector.best.stage ||
      (stage === collector.best.stage &&
       errorPrecedence(error.code) < errorPrecedence(collector.best.error.code))) {
    collector.best = candidate;
  }
}

function fail(code, details) {
  if (currentKnownSchemaCollector() && details?.layer === 2) {
    const { collectorStage = 5, ...errorDetails } = details;
    errorDetails.stage ??= code === 'CONFLICT_ID_MISMATCH' ? 'declared-identity' : 'known-schema';
    recordKnownSchema(new OgvcsError(code, errorDetails), collectorStage);
    return false;
  }
  if (details?.layer === 2) {
    details = { ...details, stage: details.stage ??
      (code === 'CONFLICT_ID_MISMATCH' ? 'declared-identity' : 'known-schema') };
  }
  throwFailure(code, details);
}

function collectKnownSchema(callback) {
  const collector = { best: undefined };
  knownSchemaCollectors.push(collector);
  try {
    callback();
  } catch (error) {
    if (error instanceof KnownSchemaTerminal) collector.best = { error: error.error, stage: 0 };
    else if (error instanceof OgvcsError && error.layer === 2) recordKnownSchema(error, 5);
    else throw error;
  } finally {
    knownSchemaCollectors.pop();
  }
  if (collector.best) throw collector.best.error;
}

function captureKnownSchema(callback, fallback) {
  try { return callback(); }
  catch (error) {
    if (currentKnownSchemaCollector() && error instanceof OgvcsError && error.layer === 2) {
      recordKnownSchema(error, 5);
      return fallback;
    }
    throw error;
  }
}

// Comparators and derived hashes sometimes encode a field after its shape has
// already failed. Those encodes operate on validator placeholders rather than
// original wire input, so translate their synthetic CBOR error back into the
// known-schema failure that made the computation impossible.
function captureSchemaComputation(callback, fallback) {
  try { return callback(); }
  catch (error) {
    if (currentKnownSchemaCollector() && error instanceof OgvcsError) {
      invalid();
      return fallback;
    }
    throw error;
  }
}

function asBig(value) {
  if ((typeof value !== 'number' || !Number.isSafeInteger(value)) && typeof value !== 'bigint') {
    invalid(); return 0n;
  }
  return BigInt(value);
}
function uint(value, maximum = 0xffff_ffff_ffff_ffffn, minimum = 0n, code = 'SCHEMA_FIELD_INVALID') {
  const n = asBig(value);
  if (n < minimum || n > BigInt(maximum)) fail(code, { layer: 2 });
  return n;
}
function sint(value) { const n = asBig(value); if (n < -0x8000_0000_0000_0000n || n > 0x7fff_ffff_ffff_ffffn) invalid(); return n; }
function invalid() { fail('SCHEMA_FIELD_INVALID', { layer: 2 }); }
function bytes(value, min = 0, max = MAX.value, code = 'SCHEMA_FIELD_INVALID') {
  if (!(value instanceof Uint8Array)) { fail(code, { layer: 2 }); return new Uint8Array(Math.max(0, min)); }
  if (value.length < min) fail(code, { layer: 2 });
  if (value.length > max) fail(max === MAX.value ? 'LIMIT_VALUE_BYTES' : code,
    { layer: 2, collectorStage: max === MAX.value ? 0 : 5 });
  return value;
}
function opaqueId(value) { const parsed = bytes(value, 16, 16); if (parsed.every(byte => byte === 0)) invalid(); return parsed; }
function fileId(value) {
  const parsed = bytes(value, 16, 16);
  return captureKnownSchema(() => new FileId(parsed), new FileId(Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)));
}
function digest(value) { return bytes(value, 32, 32); }
function text(value, min = 0, max = MAX.value, code = 'SCHEMA_FIELD_INVALID') {
  if (typeof value !== 'string') { fail(code, { layer: 2 }); return ''; }
  if (!isUnicode15String(value) || value.normalize('NFC') !== value) fail(code, { layer: 2 });
  const length = Buffer.byteLength(value);
  if (length < min) fail(code, { layer: 2 });
  if (length > max) fail(max === MAX.message ? 'LIMIT_VALUE_BYTES' : code,
    { layer: 2, collectorStage: 0 });
  return value;
}
function array(value, min = 0, max = Number.MAX_SAFE_INTEGER, code = 'LIMIT_COUNT') {
  if (!Array.isArray(value)) { invalid(); return []; }
  if (value.length < min) invalid();
  if (value.length > max) fail(code, { layer: 2, collectorStage: 0 });
  return value;
}
function exact(value, required, optional = []) {
  if (!(value instanceof Map)) { invalid(); return new Map(); }
  for (const key of required) if (!value.has(key)) invalid();
  const allowed = new Set([...required, ...optional]);
  for (const key of value.keys()) if (!allowed.has(key)) fail('SCHEMA_FIELD_UNKNOWN', { layer: 2 });
  return value;
}
function selection(context, collection, key) {
  if (context?.registry && context.semantic !== false) {
    const semanticPrefix = 'semantic-enums/';
    const maps = {
      'object-kinds': context.registry.objectKinds,
      'hash-algorithms': context.registry.hashAlgorithms,
      'common-fields': context.registry.commonFields,
      'kind-fields': context.registry.kindFields,
      'entry-kinds': context.registry.entryKinds,
      'entry-modes': context.registry.entryModes,
      'logical-record-types': context.registry.logicalRecordTypes,
      extensions: context.registry.extensions
    };
    const assignments = collection.startsWith(semanticPrefix)
      ? context.registry.semanticEnums?.get(collection.slice(semanticPrefix.length))
      : maps[collection];
    // Evolution snapshots may intentionally contain only the registries under
    // test. An omitted (empty) authority makes no lifecycle claim.
    if (assignments?.size === 0 || assignments === undefined) return;
    context.assignments.push([collection, key]);
  }
}
function enumValue(value, allowed, context, domain) {
  const n = Number(uint(value));
  if (!allowed.includes(n)) {
    invalid();
    return allowed[0];
  }
  if (domain) selection(context, `semantic-enums/${domain}`, n);
  return n;
}

function contextMaximum(context, name) {
  return configuredHardLimit(name, context?.hardLimits?.[name]);
}

function optionMaximum(options, name, legacy) {
  return Math.min(
    configuredHardLimit(name, options?.hardLimits?.[name]),
    configuredHardLimit(name, legacy)
  );
}

function contextLimit(context, name, value, code, layer = 2) {
  try {
    const diagnosticStage = layer === 1
      ? (code === 'BUNDLE_BUDGET_EXCEEDED' ? 'configured-resource-preflight' : 'canonical-framing')
      : 'known-schema';
    return enforceHardLimit(undefined, name, value, {
      maximum: context?.hardLimits?.[name], code, layer, stage: diagnosticStage
    });
  } catch (error) {
    if (currentKnownSchemaCollector() && error instanceof OgvcsError && error.layer === 2) {
      const unsigned = (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) ||
        (typeof value === 'bigint' && value >= 0n);
      recordKnownSchema(error, unsigned ? 0 : 5);
      return undefined;
    }
    throw error;
  }
}

function encodedSort(values, unique = true, code = 'SCHEMA_FIELD_INVALID') {
  let previous;
  for (const value of values) {
    const current = captureSchemaComputation(() => encodeCanonical(value), new Uint8Array());
    if (previous && Buffer.compare(previous, current) >= (unique ? 0 : 1)) fail(code, { layer: 2 });
    previous = current;
  }
}
function byteSort(values, selector, code = 'SCHEMA_FIELD_INVALID') {
  let previous;
  for (const value of values) {
    let current;
    try { current = selector(value); }
    catch (error) {
      if (error instanceof TypeError && currentKnownSchemaCollector()) { invalid(); continue; }
      throw error;
    }
    if (!(current instanceof Uint8Array)) { invalid(); continue; }
    if (previous && Buffer.compare(previous, current) >= 0) fail(code, { layer: 2 });
    previous = Buffer.from(current);
  }
}

function tupleCompare(left, right) {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length ||
      left.some(part => !(part instanceof Uint8Array)) || right.some(part => !(part instanceof Uint8Array))) {
    invalid(); return 0;
  }
  for (let index = 0; index < left.length; index++) {
    const order = Buffer.compare(left[index], right[index]);
    if (order !== 0) return order;
  }
  return 0;
}

function tupleSort(values, selector, code = 'SCHEMA_FIELD_INVALID') {
  let previous;
  for (const value of values) {
    let current;
    try { current = selector(value); }
    catch (error) {
      if (error instanceof TypeError && currentKnownSchemaCollector()) { invalid(); continue; }
      throw error;
    }
    if (!Array.isArray(current) || current.some(part => !(part instanceof Uint8Array))) {
      invalid(); continue;
    }
    if (previous && tupleCompare(previous, current) >= 0) fail(code, { layer: 2 });
    previous = current.map(part => part.slice());
  }
}

const DUMMY_DIGEST = new Digest(1, new Uint8Array(32));
const DUMMY_PROFILE = new ProfileRef('profile.invalid', 'invalid', 1);
function typedDigest(value) {
  return captureKnownSchema(() => Digest.fromMap(value), DUMMY_DIGEST);
}
function objectRef(value, kind) {
  const fallback = new ObjectRef(kind ?? 1, new Uint8Array(32));
  const ref = captureKnownSchema(() => ObjectRef.fromMap(value), fallback);
  if (kind !== undefined && ref.kind !== kind) fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2 });
  return ref;
}
function profile(value, families, context) {
  const ref = captureKnownSchema(() => ProfileRef.fromMap(value), DUMMY_PROFILE);
  if (context.registry) {
    const entry = context.registry.profiles.get(ref.toString());
    if (entry && families && !families.includes(entry.family)) invalid();
  } else if (families) {
    const family = frozenProfileFamily(ref);
    if (family !== undefined && !families.includes(family)) invalid();
  }
  context.profiles.push(ref);
  return ref;
}
function profileList(value, min, families, context) {
  const list = array(value, min);
  encodedSort(list);
  for (const item of list) profile(item, families, context);
  return list;
}
function path(value, context) {
  const list = array(value, 1, contextMaximum(context, 'path-segments'), 'PATH_CORE_INVALID');
  let joined = list.length - 1;
  for (const segment of list) {
    joined += Buffer.byteLength(pathSegment(segment, context));
  }
  contextLimit(context, 'path-bytes', joined, 'PATH_CORE_INVALID');
  return list;
}
function pathSegment(value, context) {
  const segment = text(value, 1, contextMaximum(context, 'path-segment-bytes'), 'PATH_CORE_INVALID');
  if (segment === '.' || segment === '..' || segment.includes('/') || segment.includes('\0')) {
    fail('PATH_CORE_INVALID', { layer: 2 });
  }
  return segment;
}
function identity(value, context) {
  value = exact(value, [0, 1], [2]); profile(value.get(0), FAMILIES.identity, context); bytes(value.get(1), 1);
  if (value.has(2)) text(value.get(2));
}
function policy(value, context) {
  value = exact(value, [0, 1, 2, 3]); const p = profile(value.get(0), FAMILIES.policy, context);
  uint(value.get(1)); const decision = enumValue(value.get(2), [1, 2], context, 'policy-decision'); typedDigest(value.get(3));
  context.policyResults.push({ profile: p, decision });
}
function extensionValue(value) {
  if (typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint' || value instanceof Uint8Array) return;
  if (Array.isArray(value)) { for (const item of value) extensionValue(item); return; }
  if (value instanceof Map) { for (const [key, item] of value) { uint(key); extensionValue(item); } return; }
  invalid();
}
function extensions(value, context) {
  if (!(value instanceof Map)) { invalid(); return; }
  if (value.size === 0) invalid();
  contextLimit(context, 'extensions-per-object', value.size, 'LIMIT_COUNT');
  let total = 0;
  for (const [key, item] of value) {
    let ref;
    try { ref = ProfileRef.parse(key); }
    catch (error) {
      if (!(error instanceof OgvcsError) || error.layer !== 2) throw error;
      fail('EXTENSION_KEY_INVALID', { layer: 2 });
      ref = DUMMY_PROFILE;
    }
    // Unknown optional extensions are deliberately opaque and byte-preserved;
    // lifecycle applies only once this registry recognizes the assignment.
    if (context.registry?.extensions?.has(ref.toString())) selection(context, 'extensions', ref.toString());
    extensionValue(item);
    total += captureSchemaComputation(() => encodeCanonical(item), new Uint8Array()).length;
  }
  contextLimit(context, 'extension-aggregate-bytes-per-object', total, 'LIMIT_EXTENSION_BYTES');
}

function common(value, expectedKind, context) {
  if (!(value instanceof Map)) { invalid(); return; }
  if (value.get(0) !== 1 || value.get(1) !== expectedKind || !value.has(2)) invalid();
  const features = array(value.get(2));
  let last = -1n;
  for (const feature of features) { const n = uint(feature, 0xffff_ffffn); if (n <= last) invalid(); last = n; context.features.push(Number(n)); }
  if (value.has(3)) extensions(value.get(3), context);
  for (const key of value.keys()) {
    const n = uint(key, 4095n);
    if (n >= 4n && n <= 15n) fail('SCHEMA_FIELD_UNKNOWN', { layer: 2 });
  }
  for (const key of [0, 1, 2, 3]) if (value.has(key)) selection(context, 'common-fields', key);
}

function framingCommon(value, context) {
  if (!(value instanceof Map) || value.get(0) !== 1 ||
      !Number.isInteger(value.get(1)) || value.get(1) < 1 || value.get(1) > 65_535 ||
      !Array.isArray(value.get(2))) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  for (const feature of value.get(2)) {
    if (!Number.isInteger(feature) || feature < 0 || feature > 0xffff_ffff) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    }
    context.features.push(feature);
  }
  if (value.has(3)) {
    if (!(value.get(3) instanceof Map) || value.get(3).size === 0) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    }
    contextLimit(context, 'extensions-per-object', value.get(3).size, 'LIMIT_COUNT', 1);
    let aggregate = 0;
    for (const extensionValue of value.get(3).values()) {
      aggregate += encodeCanonical(extensionValue).length;
      contextLimit(context, 'extension-aggregate-bytes-per-object', aggregate, 'LIMIT_EXTENSION_BYTES', 1);
    }
  }
}
function commonExact(value, kind, required, optional, context) {
  common(value, kind, context);
  value = exact(value, [0, 1, 2, ...required], [3, ...optional]);
  const rule = OBJECT_RULES[kind];
  for (const key of [...required, ...optional]) {
    if (value.has(key)) selection(context, 'kind-fields', `${rule}\0${key}`);
  }
  return value;
}

function chunkPart(value, context) {
  value = exact(value, [0, 1]); objectRef(value.get(0), 1);
  contextLimit(context, 'chunk-payload-bytes', value.get(1), 'MANIFEST_CHUNK_LENGTH_INVALID');
  uint(value.get(1), MAX.chunkBytes, 1n, 'MANIFEST_CHUNK_LENGTH_INVALID');
}
function treeEntry(value, context) {
  value = exact(value, [0, 1, 2, 3, 4, 5, 6]); pathSegment(value.get(0), context);
  const kind = enumValue(value.get(1), [1, 2, 3, 4]); fileId(value.get(2));
  const mode = Number(uint(value.get(3)));
  if (mode !== kind) fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  selection(context, 'entry-kinds', kind); selection(context, 'entry-modes', mode);
  objectRef(value.get(4), kind === 1 ? 3 : 2);
  contextLimit(context, 'logical-file-bytes', value.get(5), 'LIMIT_LOGICAL_BYTES');
  const size = uint(value.get(5), MAX.logical, 0n, 'LIMIT_LOGICAL_BYTES');
  if (kind === 1 && size !== 0n) fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  profile(value.get(6), FAMILIES.content, context);
}
function entryState(value, context) {
  value = exact(value, [0, 1, 2, 3, 5, 6], [4]); path(value.get(0), context);
  const kind = enumValue(value.get(1), [1, 2, 3, 4]); fileId(value.get(2));
  const mode = Number(uint(value.get(3)));
  if (mode !== kind) fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  selection(context, 'entry-kinds', kind); selection(context, 'entry-modes', mode);
  if ((kind === 1) !== !value.has(4)) fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  if (value.has(4)) objectRef(value.get(4), 2);
  contextLimit(context, 'logical-file-bytes', value.get(5), 'LIMIT_LOGICAL_BYTES');
  const size = uint(value.get(5), MAX.logical, 0n, 'LIMIT_LOGICAL_BYTES');
  if (kind === 1 && size !== 0n) fail('TREE_ENTRY_TARGET_INVALID', { layer: 2 });
  profile(value.get(6), FAMILIES.content, context);
}
function allocationProof(value, context) {
  value = exact(value, [0, 1], [2]); objectRef(value.get(0), 6);
  const kind = enumValue(value.get(1), [1, 2], context, 'allocation-kind');
  if ((kind === 2) !== value.has(2)) invalid(); if (value.has(2)) digest(value.get(2));
}
function restoreProof(value, context) { value = exact(value, [0, 1, 2, 3]); objectRef(value.get(0), 6); objectRef(value.get(1), 7); path(value.get(2), context); objectRef(value.get(3), 7); }
function member(value, context) { value = exact(value, [0, 1]); fileId(value.get(0)); profile(value.get(1), FAMILIES.role, context); }
function externalKey(value, context) { value = exact(value, [0, 1]); profile(value.get(0), FAMILIES.external, context); bytes(value.get(1), 1); }
function assetGroup(value, context) {
  value = exact(value, [0, 1, 2, 3], [4]); opaqueId(value.get(0)); profile(value.get(1), FAMILIES.group, context); fileId(value.get(2));
  const members = array(value.get(3), 1, contextMaximum(context, 'asset-group-members'));
  for (const item of members) member(item, context);
  tupleSort(members, item => [
    captureSchemaComputation(() => encodeCanonical(item.get(1)), new Uint8Array()), item.get(0)
  ]);
  if (value.has(4)) {
    const keys = array(value.get(4));
    for (const item of keys) externalKey(item, context);
    tupleSort(keys, item => [
      captureSchemaComputation(() => encodeCanonical(item.get(0)), new Uint8Array()), item.get(1)
    ]);
  }
}
function operation(value, sequence, context) {
  if (!(value instanceof Map)) { invalid(); return; }
  const code = enumValue(value.get(1), [1,2,3,4,5,6,7,8,9,10,11], context, 'operation');
  const shapes = { 1:[[0,1,3,5],[]], 2:[[0,1,2,3],[]], 3:[[0,1,3,4,5],[]],
    4:[[0,1,2,3],[]], 5:[[0,1,2,3],[]], 6:[[0,1,2],[]], 7:[[0,1,3,6],[]],
    8:[[0,1,8],[]], 9:[[0,1,7,8],[]], 10:[[0,1,7],[]], 11:[[0,1,9,10],[11]] };
  exact(value, ...(shapes[code] ?? [[0, 1], []]));
  if (value.get(0) !== sequence) fail('CHANGESET_SEQUENCE_INVALID', { layer: 2 });
  for (const key of [2,3,4]) if (value.has(key)) entryState(value.get(key), context);
  if (value.has(5)) allocationProof(value.get(5), context); if (value.has(6)) restoreProof(value.get(6), context);
  for (const key of [7,8]) if (value.has(key)) assetGroup(value.get(key), context);
  if (code === 11) { digest(value.get(9)); const subject = enumValue(value.get(10), [1,2], context, 'conflict-subject-kind'); if (value.has(11)) subject === 1 ? entryState(value.get(11), context) : assetGroup(value.get(11), context); }
}
function conflictSide(value, context) {
  if (!(value instanceof Map)) { invalid(); return; } const kind = enumValue(value.get(0), [1,2], context, 'conflict-side-kind');
  if (kind === 1) { exact(value, [0,1]); entryState(value.get(1), context); }
  else { exact(value, [0,2]); assetGroup(value.get(2), context); }
}
function conflictResolution(value, context) {
  if (!(value instanceof Map)) { invalid(); return; } const state = enumValue(value.get(0), [0,1], context, 'conflict-resolution-state');
  if (state === 0) { exact(value, [0]); return; }
  const choice = enumValue(value.get(1), [1,2,3,4,5], context, 'conflict-resolution-choice');
  if (choice >= 1 && choice <= 3) {
    exact(value, [0,1,2]); conflictSide(value.get(2), context); return;
  }
  if (choice === 4) { exact(value, [0,1]); return; }
  exact(value, [0,1,2,3]); conflictSide(value.get(2), context);
  profile(value.get(3), FAMILIES.conflictDriver, context);
}
function conflictSubject(value, context) {
  if (!Array.isArray(value)) { invalid(); return 1; }
  const kind = enumValue(value[0], [1,2], context, 'conflict-subject-kind');
  if (kind === 1) {
    if (value.length !== 3) invalid();
    const ids = array(value[1]); if (ids.length < 1 || ids.length > 3) invalid();
    byteSort(ids, item => { fileId(item); return item; });
    const paths = array(value[2]); if (paths.length < 1 || paths.length > 3) invalid();
    for (const item of paths) path(item, context);
    encodedSort(paths);
  } else {
    if (value.length !== 2) invalid();
    opaqueId(value[1]);
  }
  return kind;
}
function conflictPreimage(value, context) {
  value = exact(value, [0,1], [2,3,4]); enumValue(value.get(0), [1,2,3,4,6,7,8], context, 'conflict-kind');
  conflictSubject(value.get(1), context);
  for (const key of [2,3,4]) if (value.has(key)) conflictSide(value.get(key), context);
}
function conflictRecord(value, context) {
  value = exact(value, [0,1,2,6], [3,4,5]); digest(value.get(0)); enumValue(value.get(1), [1,2,3,4,6,7,8], context, 'conflict-kind');
  conflictSubject(value.get(2), context);
  for (const key of [3,4,5]) if (value.has(key)) conflictSide(value.get(key), context); conflictResolution(value.get(6), context);
  const preimage = new Map([[0, value.get(1)], [1, value.get(2)]]);
  for (const [recordKey, preimageKey] of [[3,2],[4,3],[5,4]]) {
    if (value.has(recordKey)) preimage.set(preimageKey, value.get(recordKey));
  }
  const computed = captureSchemaComputation(() => hashConflictPreimage(preimage).bytes, new Uint8Array(32));
  if (!equalBytes(value.get(0), computed)) {
    fail('CONFLICT_ID_MISMATCH', { layer: 2 });
  }
}

const OBJECT_VALIDATORS = {
  2(value, context) {
    value = commonExact(value, 2, [16, 17, 18, 19], [], context);
    contextLimit(context, 'logical-file-bytes', value.get(16), 'LIMIT_LOGICAL_BYTES');
    const logical = uint(value.get(16), MAX.logical, 0n, 'LIMIT_LOGICAL_BYTES');
    typedDigest(value.get(17));
    profile(value.get(18), FAMILIES.chunking, context);
    const chunks = array(value.get(19), 0, contextMaximum(context, 'manifest-chunks'));
    let sum = 0n;
    for (const item of chunks) {
      chunkPart(item, context);
      sum += uint(item instanceof Map ? item.get(1) : undefined);
      contextLimit(context, 'logical-file-bytes', sum, 'LIMIT_LOGICAL_BYTES');
    }
    if (sum !== logical || (logical === 0n && chunks.length !== 0)) {
      fail('MANIFEST_LENGTH_MISMATCH', { layer: 2 });
    }
  },
  3(value, context) {
    value = commonExact(value, 3, [16, 17], [], context);
    objectRef(value.get(16), 6);
    const entries = array(value.get(17), 0, contextMaximum(context, 'tree-entries'));
    byteSort(entries, item => Buffer.from(pathSegment(item.get(0), context)), 'TREE_ENTRY_ORDER_INVALID');
    for (const item of entries) treeEntry(item, context);
  },
  4(value, context) {
    value = commonExact(value, 4, [16, 18], [17], context);
    objectRef(value.get(16), 6);
    if (value.has(17)) objectRef(value.get(17), 7);
    const operations = array(value.get(18), 0, contextMaximum(context, 'change-set-operations'));
    operations.forEach((item, index) => operation(item, index, context));
  },
  5(value, context) {
    value = commonExact(value, 5, [16, 17], [], context);
    objectRef(value.get(16), 6);
    const groups = array(value.get(17), 0, contextMaximum(context, 'asset-groups'));
    for (const group of groups) assetGroup(group, context);
    byteSort(groups, item => item.get(0));
  },
  6(value, context) {
    value = commonExact(value, 6, [16, 17, 18, 19], [20], context);
    opaqueId(value.get(16));
    profile(value.get(17), FAMILIES.path, context);
    profileList(value.get(18), 1, FAMILIES.content, context);
    profileList(value.get(19), 0, FAMILIES.group, context);
    if (value.has(20)) {
      const list = profileList(value.get(20), 0, FAMILIES.chunking, context);
      if (list.length === 0) invalid();
    }
  },
  7(value, context) {
    value = commonExact(value, 7, [16, 17, 18, 19, 21, 22, 23, 24, 25, 26], [20, 27, 28], context);
    objectRef(value.get(16), 6);
    const parents = array(value.get(17), 0, contextMaximum(context, 'snapshot-parents'),
      'SNAPSHOT_PARENT_COUNT_INVALID');
    const parentIds = new Set();
    for (const ref of parents) {
      const parsed = objectRef(ref, 7);
      const key = Buffer.from(parsed.digest).toString('hex');
      if (parentIds.has(key)) fail('SNAPSHOT_PARENT_DUPLICATE', { layer: 2 });
      parentIds.add(key);
    }
    objectRef(value.get(18), 3);
    objectRef(value.get(19), 4);
    if (value.has(20)) objectRef(value.get(20), 5);
    identity(value.get(21), context);
    identity(value.get(22), context);
    sint(value.get(23));
    sint(value.get(24));
    const message = text(value.get(25));
    contextLimit(context, 'snapshot-message-bytes', Buffer.byteLength(message), 'LIMIT_VALUE_BYTES');
    policy(value.get(26), context);
    if (value.has(27)) {
      const refs = array(value.get(27));
      encodedSort(refs);
      for (const ref of refs) objectRef(ref, 9);
    }
    if (value.has(28)) objectRef(value.get(28), 11);
  },
  8(value, context) {
    value = commonExact(value, 8, [16, 17, 18, 20, 21, 22, 25, 26, 27, 28], [19, 23, 24, 29], context);
    objectRef(value.get(16), 6);
    opaqueId(value.get(17));
    const revision = uint(value.get(18), 0xffff_ffffn, 1n);
    if ((revision === 1n) !== !value.has(19)) invalid();
    if (value.has(19)) objectRef(value.get(19), 8);
    objectRef(value.get(20), 7);
    objectRef(value.get(21), 4);
    objectRef(value.get(22), 3);
    if (value.has(23)) objectRef(value.get(23), 5);
    if (value.has(24)) objectRef(value.get(24), 11);
    identity(value.get(25), context);
    sint(value.get(26));
    const message = text(value.get(27));
    contextLimit(context, 'snapshot-message-bytes', Buffer.byteLength(message), 'LIMIT_VALUE_BYTES');
    policy(value.get(28), context);
    if (value.has(29)) {
      const refs = array(value.get(29));
      encodedSort(refs);
      for (const ref of refs) objectRef(ref, 9);
    }
  },
  9(value, context) {
    value = commonExact(value, 9, [16, 17, 18], [19], context);
    profile(value.get(16), FAMILIES.provenance, context);
    const refs = array(value.get(17));
    encodedSort(refs);
    for (const ref of refs) objectRef(ref);
    const claim = typedDigest(value.get(18));
    if (value.has(19)) {
      const statement = bytes(value.get(19));
      if (!equalBytes(claim.bytes, sha256Digest(statement).bytes)) invalid();
    }
  },
  10(value, context) {
    value = commonExact(value, 10, [16, 17, 18, 19, 20], [21, 22], context);
    objectRef(value.get(16));
    profile(value.get(17), FAMILIES.predicate, context);
    identity(value.get(18), context);
    sint(value.get(19));
    bytes(value.get(20));
    if (value.has(21)) profile(value.get(21), FAMILIES.signature, context);
    if (value.has(22)) bytes(value.get(22), 1);
    if (value.has(21) !== value.has(22)) fail('ATTESTATION_SIGNATURE_SHAPE_INVALID', { layer: 2 });
  },
  11(value, context) {
    value = commonExact(value, 11, [16, 17], [], context);
    objectRef(value.get(16), 6);
    const records = array(value.get(17), 1);
    for (const record of records) conflictRecord(record, context);
    byteSort(records, item => item.get(0));
  },
};

function context(options) {
  return {
    registry: options.registry,
    hardLimits: options.hardLimits ?? {},
    operation: options.operation,
    semantic: options.semantic,
    assignments: [],
    profiles: [], features: [], policyResults: []
  };
}

function semanticContext(options) {
  return context(semanticOptions(options));
}

function semanticOptions(options) {
  const semantic = codecValidationContext(options);
  return { ...options, ...semantic };
}

const REGISTRY_ERRORS = new Set([
  'REQUIRED_FEATURE_UNSUPPORTED', 'PROFILE_UNKNOWN',
  'PROFILE_CONFORMANCE_ONLY', 'PROFILE_STATE_FORBIDDEN'
]);

function applyRegistrySemantics(ctx) {
  if (!ctx.registry || ctx.semantic === false) return;
  let selected;
  const observe = callback => {
    try { callback(); } catch (error) {
      if (!REGISTRY_ERRORS.has(error?.code)) throw error;
      if (!selected || errorPrecedence(error.code) < errorPrecedence(selected.code)) selected = error;
    }
  };
  for (const [collection, key] of ctx.assignments) {
    observe(() => registryAssignmentDecision(ctx.registry, collection, key, ctx.operation));
  }
  for (const feature of ctx.features) {
    observe(() => requiredFeatureDecision(ctx.registry, feature, ctx.operation));
  }
  for (const ref of ctx.profiles) observe(() => profileDecision(ctx.registry, ref, ctx.operation));
  if (selected) throw selected;
  for (const policyResult of ctx.policyResults) {
    if (policyResult.profile.toString() === 'policy.test/allow@1' && policyResult.decision !== 1) {
      fail('PROFILE_STATE_FORBIDDEN', { layer: 3 });
    }
  }
}
export function validateKnownSchema(value, expectedKind, options = {}) {
  options = semanticOptions(options);
  const maxWorkingBytes = options.maxWorkingBytes ?? 67_108_864;
  if (!Number.isSafeInteger(maxWorkingBytes) || maxWorkingBytes < 0) {
    throwFailure('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (maxWorkingBytes < KNOWN_SCHEMA_WORKING_BYTES) {
    throwFailure('LIMIT_MEMORY', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const kind = expectedKind ?? value?.get?.(1);
  if (!OBJECT_VALIDATORS[kind]) fail('OBJECT_KIND_UNSUPPORTED', { layer: 2 });
  collectKnownSchema(() => OBJECT_VALIDATORS[kind](value, context({ ...options, semantic: false })));
  const ctx = semanticContext(options);
  OBJECT_VALIDATORS[kind](value, ctx);
  selection(ctx, 'object-kinds', kind);
  selection(ctx, 'hash-algorithms', 1);
  applyRegistrySemantics(ctx);
  return { kind, profiles: ctx.profiles, requiredFeatures: ctx.features, policyResults: ctx.policyResults };
}

function scanMetadataCore(payload, options = {}) {
  if (!(payload instanceof Uint8Array)) invalid();
  const maxBytes=optionMaximum(options,'metadata-payload-bytes',options.maxBytes);
  enforceHardLimit(undefined,'metadata-payload-bytes',payload.length,{maximum:maxBytes,code:'LIMIT_METADATA_BYTES',layer:1});
  const value=decodeCanonical(payload,{maxBytes,
    maxDepth:optionMaximum(options,'cbor-nesting-depth',options.maxDepth),
    maxValueBytes:optionMaximum(options,'generic-text-or-byte-value-bytes',options.maxValueBytes),
    maxContainerItems:optionMaximum(options,'manifest-chunks',options.maxContainerItems),
    maxWorkingBytes:Math.min(options.maxWorkingBytes??67_108_864,67_108_864)});
  const ctx=context({ ...options, registry: undefined, operation: undefined, semantic: false });
  framingCommon(value,ctx);
  const kind=value.get(1); const names=KIND_NAMES;
  let objectId; let identityDigest;
  if(options.computeId!==false){
    if(names.has(kind)){objectId=hashObject(kind,payload,{registry:names,maxMetadataBytes:maxBytes});identityDigest=new Digest(1,objectId.digest);}
    else identityDigest=hashOpaqueObject(kind,payload,{maxBytes});
  }
  return {highestLayer:1,kind,requiredFeatures:ctx.features,value,payload:payload.slice(),objectId,identityDigest};
}

export function scanMetadata(payload, options = {}) {
  if (options.registry !== undefined || options.operation !== undefined) {
    throwFailure('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return scanMetadataCore(payload, options);
}

export function decodeMetadata(payload, options = {}) {
  options = semanticOptions(options);
  const scan=scanMetadataCore(payload,options); const result=validateKnownSchema(scan.value,scan.kind,options);
  if(options.semantic===false)return {...scan,...result,highestLayer:2};
  if(!options.registry) return {...scan,...result,highestLayer:2};
  return {...scan,...result,highestLayer:3};
}

export function encodeMetadata(value, options={}) {
  const semantic = writerValidationContext(options.operation, options.registry);
  options = { ...options, ...semantic, semantic: true };
  // Establish depth, value, container, working-memory, and canonical-key
  // failures before schema helpers traverse caller-owned extension values.
  const encoded = encodeCanonical(value, {
    ...options,
    maxBytes: optionMaximum(options,'metadata-payload-bytes',options.maxBytes),
    maxDepth: optionMaximum(options,'cbor-nesting-depth',options.maxDepth),
    maxValueBytes: optionMaximum(options,'generic-text-or-byte-value-bytes',options.maxValueBytes),
    maxContainerItems: optionMaximum(options,'manifest-chunks',options.maxContainerItems)
  });
  if (!(value instanceof Map)) invalid();
  validateKnownSchema(value, undefined, options);
  return encoded;
}

export function validateConflictPreimage(value, options = {}) {
  options = semanticOptions(options);
  collectKnownSchema(() => conflictPreimage(value, context({ ...options, semantic: false })));
  const ctx = semanticContext(options);
  conflictPreimage(value, ctx);
  applyRegistrySemantics(ctx);
  return { profiles: ctx.profiles };
}

const LOGICAL_SHAPES={1:[[0,1,16,17],[]],2:[[0,1,16,17,18,19,20],[]],3:[[0,1,16,17,18,19],[]],4:[[0,1,16,17,18,19,20],[21]],5:[[0,1,16,17,18,19,20,21],[]],6:[[0,1,16,17,18,19],[20]],7:[[0,1,16,17,18,19,20],[]],8:[[0,1,16,17,18],[]],9:[[0,1,16,17,18,19,20],[]]};
function logicalRecordShape(input, ctx) {
  if (!(input instanceof Map)) invalid();
  let value = input instanceof Map ? input : new Map();
  if (value.get(0) !== 1) invalid();
  const typeValue = Number(uint(value.get(1)));
  if (![1,2,3,4,5,6,7,8,9].includes(typeValue)) {
    fail('LOGICAL_RECORD_TYPE_UNSUPPORTED', { layer: 2 });
    return 0;
  }
  const type = typeValue;
  value = exact(value, ...LOGICAL_SHAPES[type]);
  for (const key of value.keys()) selection(ctx, 'kind-fields', `${LOGICAL_RULES[type]}\0${key}`);
  if (type <= 7) objectRef(value.get(16), 6);
  if (type === 1) objectRef(value.get(17), 7);
  else if (type === 2) {
    enumValue(value.get(17), [1,2], ctx, 'ref-kind');
    text(value.get(18), 1);
    objectRef(value.get(19), 7);
    uint(value.get(20));
  } else if (type === 3) {
    opaqueId(value.get(17));
    objectRef(value.get(18), 8);
    uint(value.get(19));
  } else if (type === 4) {
    fileId(value.get(17));
    const origin = enumValue(value.get(18), [1,2,3], ctx, 'lifetime-origin');
    objectRef(value.get(19), 4);
    uint(value.get(20));
    if ((origin === 3) !== value.has(21)) invalid();
    if (value.has(21)) digest(value.get(21));
  } else if (type === 5) {
    profile(value.get(17), FAMILIES.importer, ctx);
    digest(value.get(18));
    digest(value.get(19));
    fileId(value.get(20));
    enumValue(value.get(21), [1,2,3], ctx, 'import-state');
  } else if (type === 6) {
    opaqueId(value.get(17));
    objectRef(value.get(18), 7);
    objectRef(value.get(19), 4);
    if (value.has(20)) objectRef(value.get(20), 11);
  } else if (type === 7) {
    const target = enumValue(value.get(17), [1,2], ctx, 'lock-target-kind');
    if (target === 1) fileId(value.get(18)); else opaqueId(value.get(18));
    objectRef(value.get(19), 7);
    uint(value.get(20));
  } else if (type === 8) {
    objectRef(value.get(16));
    profile(value.get(17), FAMILIES.annotation, ctx);
    bytes(value.get(18));
  } else {
    typedDigest(value.get(16));
    uint(value.get(17));
    profile(value.get(18), FAMILIES.fixtureEvent, ctx);
    typedDigest(value.get(19));
    if (typeof value.get(20) !== 'string' || !FIXTURE_OPERATIONS.has(value.get(20))) invalid();
  }
  selection(ctx, 'logical-record-types', type);
  selection(ctx, 'hash-algorithms', 1);
  return type;
}

export function validateLogicalRecord(value, options = {}) {
  options = semanticOptions(options);
  collectKnownSchema(() => logicalRecordShape(value, context({ ...options, semantic: false })));
  const ctx = semanticContext(options);
  const type = logicalRecordShape(value, ctx);
  applyRegistrySemantics(ctx);
  return { type, profiles: ctx.profiles };
}

const BUNDLE_LIMITS={
  0:BigInt(hardLimitMaximum('bundle-sequence-bytes')),
  1:BigInt(hardLimitMaximum('bundle-largest-item-bytes')),
  2:BigInt(hardLimitMaximum('bundle-traversal-edges')),
  3:BigInt(hardLimitMaximum('bundle-index-entries'))
};
function bundleItemShape(input, ctx) {
  if (!(input instanceof Map) || input.get(0) !== 1) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  let value = input;
  const type = enumValue(value.get(1), [1,2,3,4,5], ctx, 'bundle-item-type');
  if (type === 1) {
    value = exact(value, [0,1,2,3,4,5,6]);
    uint(value.get(2));
    for (const key of [3,4,5]) uint(value.get(key));
    if (value.get(2) !== 1) fail('BUNDLE_MODE_UNSUPPORTED', { layer: 1 });
    selection(ctx, 'semantic-enums/bundle-mode', 1);
    contextLimit(ctx, 'bundle-objects', value.get(3), 'BUNDLE_BUDGET_EXCEEDED', 1);
    contextLimit(ctx, 'bundle-logical-records', value.get(4), 'BUNDLE_BUDGET_EXCEEDED', 1);
    contextLimit(ctx, 'bundle-roots', value.get(5), 'BUNDLE_BUDGET_EXCEEDED', 1);
    if (!(value.get(6) instanceof Map)) invalid();
    const declarations = exact(value.get(6), [0,1,2,3]);
    const names = ['bundle-sequence-bytes', 'bundle-largest-item-bytes',
      'bundle-traversal-edges', 'bundle-index-entries'];
    for (const [key, maximum] of Object.entries(BUNDLE_LIMITS)) {
      const index = Number(key);
      contextLimit(ctx, names[index], declarations.get(index), 'BUNDLE_BUDGET_EXCEEDED', 1);
      uint(declarations.get(index), maximum, 0n, 'BUNDLE_BUDGET_EXCEEDED');
    }
  } else if (type === 2) {
    value = exact(value, [0,1,2,3,4]);
    uint(value.get(2));
    objectRef(value.get(3));
    const payload = bytes(value.get(4));
    contextLimit(ctx, 'bundle-largest-item-bytes', payload.length, 'BUNDLE_BUDGET_EXCEEDED', 1);
  } else if (type === 3) {
    value = exact(value, [0,1,2,3,4]);
    uint(value.get(2));
    typedDigest(value.get(3));
    logicalRecordShape(value.get(4), ctx);
  } else if (type === 4) {
    value = exact(value, [0,1,2,3,4,5]);
    uint(value.get(2));
    const rootKindValue = Number(uint(value.get(3)));
    const rootKind = [1, 2].includes(rootKindValue) ? rootKindValue : undefined;
    if (rootKind === undefined) fail('BUNDLE_ROOT_INVALID', { layer: 2 });
    else {
      selection(ctx, 'semantic-enums/bundle-root-kind', rootKind);
      if (rootKind === 1) objectRef(value.get(4)); else typedDigest(value.get(4));
    }
    profile(value.get(5), FAMILIES.bundleRole, ctx);
  } else {
    value = exact(value, [0,1,2,3,4,5,6]);
    contextLimit(ctx, 'bundle-objects', value.get(2), 'BUNDLE_BUDGET_EXCEEDED', 1);
    contextLimit(ctx, 'bundle-logical-records', value.get(3), 'BUNDLE_BUDGET_EXCEEDED', 1);
    contextLimit(ctx, 'bundle-roots', value.get(4), 'BUNDLE_BUDGET_EXCEEDED', 1);
    contextLimit(ctx, 'bundle-total-items', value.get(5), 'BUNDLE_BUDGET_EXCEEDED', 1);
    for (const key of [2,3,4]) uint(value.get(key));
    uint(value.get(5), hardLimitMaximum('bundle-total-items'), 2n, 'BUNDLE_BUDGET_EXCEEDED');
    typedDigest(value.get(6));
  }
  for (const key of value.keys()) selection(ctx, 'kind-fields', `${BUNDLE_RULES[type]}\0${key}`);
  selection(ctx, 'hash-algorithms', 1);
  return type;
}

export function validateBundleItem(value, options = {}) {
  options = semanticOptions(options);
  collectKnownSchema(() => bundleItemShape(value, context({ ...options, semantic: false })));
  const ctx = semanticContext(options);
  const type = bundleItemShape(value, ctx);
  applyRegistrySemantics(ctx);
  return { type, profiles: ctx.profiles };
}

export function reproduceLogicalRecordIdentity(value){const {type}=validateLogicalRecord(value,{semantic:false});return hashLogicalRecord(type,value);}
export function reproduceConflictId(value){validateConflictPreimage(value,{semantic:false});return hashConflictPreimage(value);}
