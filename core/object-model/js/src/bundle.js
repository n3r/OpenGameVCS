import { decodeSequence, encodeCanonical, encodeCanonicalChunks } from './cbor.js';
import { compareErrorPrecedence, fail, OgvcsError } from './errors.js';
import {
  createBundleTranscriptHashWriter, createLogicalRecordHashWriter, createObjectHashWriter,
  createOpaqueObjectHashWriter, hashBundleTranscript, hashLogicalRecord, hashOpaqueObject,
  verifyObjectId
} from './hash.js';
import { configuredHardLimit, enforceHardLimit, hardLimitMaximum } from './hard-limits.js';
import { profileDecision, registryAssignmentDecision, requiredFeatureDecision } from './registry.js';
import { decodeMetadata, validateBundleItem, validateKnownSchema, validateLogicalRecord } from './schema.js';
import { ResourceGuard, cborHeader, guardedAsyncIterable, toAsyncIterable, writeFully } from './scale-util.js';
import { Digest, KIND_NAMES, ObjectRef, ProfileRef, equalBytes, toHex } from './types.js';
import { codecValidationContext, registryValidationContext, writerValidationContext } from './validation-mode.js';

const BUNDLE_LIMIT_NAMES = Object.freeze({
  sequenceBytes: 'bundle-sequence-bytes',
  itemBytes: 'bundle-largest-item-bytes',
  objects: 'bundle-objects',
  logicalRecords: 'bundle-logical-records',
  roots: 'bundle-roots',
  items: 'bundle-total-items',
  traversalEdges: 'bundle-traversal-edges',
  indexEntries: 'bundle-index-entries'
});
const HARD = Object.freeze(Object.fromEntries(Object.entries(BUNDLE_LIMIT_NAMES)
  .map(([key, name]) => [key, hardLimitMaximum(name)])));
const MAX_CONTAINER_ITEMS = hardLimitMaximum('manifest-chunks');
const MAX_NESTING_DEPTH = hardLimitMaximum('cbor-nesting-depth');
const IN_MEMORY = Object.freeze({
  sequenceBytes: 134_217_728,
  itemBytes: 67_108_864,
  objects: 100_000,
  logicalRecords: 100_000,
  roots: 200_000,
  items: 400_002,
  traversalEdges: 5_000_000,
  indexEntries: 200_000,
  memoryBytes: 536_870_912
});

function uint(value, maximum = Number.MAX_SAFE_INTEGER, overflowCode = 'SCHEMA_FIELD_INVALID') {
  if ((typeof value !== 'number' || !Number.isSafeInteger(value)) && typeof value !== 'bigint') {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  const result = BigInt(value);
  if (result < 0n) fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  if (result > BigInt(maximum)) fail(overflowCode, { layer: 1,
    stage: overflowCode === 'BUNDLE_BUDGET_EXCEEDED'
      ? 'configured-resource-preflight' : 'canonical-framing' });
  return result;
}

function compareBytes(left, right) { return Buffer.compare(Buffer.from(left), Buffer.from(right)); }
function compareTuple(left, right) {
  for (let index = 0; index < left.length; index++) {
    const order = compareBytes(left[index], right[index]);
    if (order !== 0) return order;
  }
  return 0;
}

function deferredStageCollector(layer, stage) {
  let selected;
  return Object.freeze({
    observe(callback) {
      try { return callback(); }
      catch (error) {
        if (!(error instanceof OgvcsError) || error.errorClass === 'resource' ||
            error.layer !== layer || error.stage !== stage) throw error;
        if (!selected || compareErrorPrecedence(error, selected) < 0) selected = error;
        return undefined;
      }
    },
    throwSelected() { if (selected) throw selected; }
  });
}
function refKey(ref) { return `${ref.kind}:${toHex(ref.digest)}`; }
function digestKey(digest) { return toHex(digest.bytes); }
function asRef(value, names = KIND_NAMES) { return ObjectRef.fromMap(value, names); }

function exactBundleMap(value, keys) {
  if (!(value instanceof Map) || value.size !== keys.length || keys.some(key => !value.has(key))) {
    fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  }
  return value;
}

function rawTypedDigest(value) {
  exactBundleMap(value, [0, 1]);
  if (value.get(0) !== 1 || !(value.get(1) instanceof Uint8Array) || value.get(1).length !== 32) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  return value.get(1);
}

function rawObjectRef(value) {
  exactBundleMap(value, [0, 1, 2, 3]);
  if (value.get(0) !== 1 || value.get(2) !== 1) {
    fail('OBJECT_REFERENCE_FORMAT_UNSUPPORTED', { layer: 1 });
  }
  const kind = Number(uint(value.get(1), 65_535));
  if (kind < 1 || !(value.get(3) instanceof Uint8Array) || value.get(3).length !== 32) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  return { kind, digest: value.get(3) };
}

function rawLogicalType(record) {
  if (!(record instanceof Map) || !record.has(1)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
  }
  const raw = record.get(1);
  const numeric = uint(raw);
  const hashable = numeric >= 1n && numeric <= 65_535n;
  const type = hashable ? Number(numeric) : undefined;
  return {
    hashable,
    sortKey: hashable ? Uint8Array.of(type >>> 8, type & 255) : encodeCanonical(raw),
    type
  };
}

function* stateReferences(state) {
  // AssetGroup values also have field 4 (external keys). Only an EntryState
  // has a path array at field 0; never reinterpret group data as ObjectRefs.
  if (state instanceof Map && Array.isArray(state.get(0)) && state.has(4)) yield state.get(4);
}

function* groupSideReferences(side) {
  if (!(side instanceof Map)) return;
  if (side.get(0) === 1) yield* stateReferences(side.get(1));
}

function* operationReferences(operation) {
  for (const key of [2, 3, 4, 11]) if (operation.has(key)) yield* stateReferences(operation.get(key));
  if (operation.has(5)) yield operation.get(5).get(0);
  if (operation.has(6)) {
    const proof = operation.get(6);
    yield proof.get(0); yield proof.get(1); yield proof.get(3);
  }
}

/** Iterates every outbound ObjectRef field occurrence in its wire order. */
export function* iterateObjectReferences(kind, value) {
  const ref = item => ObjectRef.fromMap(item);
  if (kind === 2) for (const part of value.get(19)) yield ref(part.get(0));
  else if (kind === 3) {
    yield ref(value.get(16));
    for (const entry of value.get(17)) yield ref(entry.get(4));
  } else if (kind === 4) {
    yield ref(value.get(16)); if (value.has(17)) yield ref(value.get(17));
    for (const operation of value.get(18)) {
      for (const item of operationReferences(operation)) yield ref(item);
    }
  } else if (kind === 5) yield ref(value.get(16));
  else if (kind === 7) {
    yield ref(value.get(16)); for (const parent of value.get(17)) yield ref(parent);
    yield ref(value.get(18)); yield ref(value.get(19));
    for (const key of [20, 28]) if (value.has(key)) yield ref(value.get(key));
    if (value.has(27)) for (const provenance of value.get(27)) yield ref(provenance);
  } else if (kind === 8) {
    yield ref(value.get(16)); if (value.has(19)) yield ref(value.get(19));
    yield ref(value.get(20)); yield ref(value.get(21)); yield ref(value.get(22));
    for (const key of [23, 24]) if (value.has(key)) yield ref(value.get(key));
    if (value.has(29)) for (const provenance of value.get(29)) yield ref(provenance);
  } else if (kind === 9) for (const input of value.get(17)) yield ref(input);
  else if (kind === 10) yield ref(value.get(16));
  else if (kind === 11) {
    yield ref(value.get(16));
    for (const record of value.get(17)) {
      for (const key of [3, 4, 5]) if (record.has(key)) {
        for (const item of groupSideReferences(record.get(key))) yield ref(item);
      }
      const resolution = record.get(6);
      if (resolution.get(0) === 1 && resolution.has(2)) {
        for (const item of groupSideReferences(resolution.get(2))) yield ref(item);
      }
    }
  }
}

/** Returns every outbound ObjectRef field occurrence in its wire order. */
export function objectReferences(kind, value) { return [...iterateObjectReferences(kind, value)]; }

export function* iterateLogicalRecordReferences(type, value) {
  const ref = item => ObjectRef.fromMap(item);
  if (type <= 7) yield ref(value.get(16));
  if (type === 1) yield ref(value.get(17));
  else if (type === 2) yield ref(value.get(19));
  else if (type === 3) yield ref(value.get(18));
  else if (type === 4) yield ref(value.get(19));
  else if (type === 6) {
    yield ref(value.get(18)); yield ref(value.get(19)); if (value.has(20)) yield ref(value.get(20));
  } else if (type === 7) yield ref(value.get(19));
  else if (type === 8) yield ref(value.get(16));
}

export function logicalRecordReferences(type, value) { return [...iterateLogicalRecordReferences(type, value)]; }

function configured(options) {
  const result = {};
  for (const [key, name] of Object.entries(BUNDLE_LIMIT_NAMES)) {
    const named = configuredHardLimit(name, options.hardLimits?.[name]);
    result[key] = configuredHardLimit(name, options[key] ?? named);
  }
  return result;
}

function configuredInMemory(options) {
  const bounded = configured(options);
  for (const [name, maximum] of Object.entries(IN_MEMORY)) {
    if (name !== 'memoryBytes') bounded[name] = Math.min(bounded[name], maximum);
  }
  return bounded;
}

const SEMANTIC_ERROR_RANK = new Map([
  ['REQUIRED_FEATURE_UNSUPPORTED', 0],
  ['PROFILE_UNKNOWN', 1],
  ['PROFILE_CONFORMANCE_ONLY', 2],
  ['PROFILE_STATE_FORBIDDEN', 3]
]);

/** Selects registry-semantic failures in frozen error-catalogue order. */
export function validateCollectedSemantics(registry, requiredFeatures, profiles, operation, policyResults = []) {
  const semantic = registryValidationContext(operation, registry);
  registry = semantic.registry;
  if (!registry) return;
  const normalizedOperation = semantic.operation;
  let selected;
  const observe = callback => {
    try { callback(); } catch (error) {
      if (!(error instanceof OgvcsError) || !SEMANTIC_ERROR_RANK.has(error.code)) throw error;
      if (!selected || SEMANTIC_ERROR_RANK.get(error.code) < SEMANTIC_ERROR_RANK.get(selected.code)) selected = error;
    }
  };
  for (const feature of requiredFeatures) {
    observe(() => requiredFeatureDecision(registry, feature, normalizedOperation));
  }
  for (const profile of profiles) observe(() => profileDecision(registry, profile, normalizedOperation));
  for (const policyResult of policyResults) {
    if (registry.profiles.has(policyResult.profile.toString()) &&
        policyResult.profile.toString() === 'policy.test/allow@1' && policyResult.decision !== 1) {
      fail('PROFILE_STATE_FORBIDDEN', { layer: 3 });
    }
  }
  if (selected) throw selected;
}

function checkProfileList(profiles, registry, operation) {
  validateCollectedSemantics(registry, [], profiles, operation);
}

function declaredObject(item, names) {
  if (!item || !(item.payload instanceof Uint8Array)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return item.ref instanceof ObjectRef ? item.ref : asRef(item.ref, names);
}

function verifyDeclaredObjectIdentity(ref, payload, names, options) {
  const limitName = ref.kind === 1 ? 'chunk-payload-bytes' : 'metadata-payload-bytes';
  const maximum = configuredHardLimit(limitName, options.hardLimits?.[limitName]);
  enforceHardLimit(undefined, limitName, payload.length, { maximum, layer: 1 });
  if (names.has(ref.kind)) {
    verifyObjectId(ref, payload, ref.kind === 1
      ? { maxChunkBytes: maximum, registry: names }
      : { maxMetadataBytes: maximum, registry: names });
    return maximum;
  }
  const actual = hashOpaqueObject(ref.kind, payload, { maxBytes: maximum });
  if (!equalBytes(ref.digest, actual.bytes)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
  return maximum;
}

function preflightObjectOrder(objects, names) {
  const refs = [];
  let previous;
  for (const item of objects) {
    const reference = declaredObject(item, names);
    const sortKey = encodeCanonical(reference.toMap());
    if (previous) {
      const order = compareBytes(previous, sortKey);
      if (order >= 0) {
        fail(order === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID', { layer: 1 });
      }
    }
    refs.push(reference);
    previous = sortKey;
  }
  return refs;
}

function preflightLogicalOrder(records) {
  let previous;
  for (const record of records) {
    const raw = rawLogicalType(record);
    if (!raw.hashable) continue;
    const identity = hashLogicalRecord(raw.type, encodeCanonical(record));
    const sortKey = [Uint8Array.of(raw.type >>> 8, raw.type & 255), identity.bytes];
    if (previous) {
      const order = compareTuple(previous, sortKey);
      if (order >= 0) {
        fail(order === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID', { layer: 1 });
      }
    }
    previous = sortKey;
  }
}

function normalizedObject(item, names, options, deferred = undefined) {
  const ref = declaredObject(item, names);
  const operation = options.operation;
  const declaredIdentity = deferred?.declaredIdentity;
  const knownSchema = deferred?.knownSchema;
  const registrySemantics = deferred?.registrySemantics;
  const verifyIdentity = () => verifyDeclaredObjectIdentity(ref, item.payload, names, options);
  const maximum = declaredIdentity ? declaredIdentity.observe(verifyIdentity) : verifyIdentity();
  if (options.registry) {
    const observeRegistry = callback => knownSchema
      ? knownSchema.observe(() => registrySemantics
        ? registrySemantics.observe(callback) : callback())
      : registrySemantics ? registrySemantics.observe(callback) : callback();
    observeRegistry(() => registryAssignmentDecision(options.registry, 'object-kinds', ref.kind, operation));
    observeRegistry(() => registryAssignmentDecision(options.registry, 'hash-algorithms', 1, operation));
  }
  let value;
  if (ref.kind !== 1) {
    const decode = () => decodeMetadata(item.payload, {
      semantic: false, hardLimits: options.hardLimits
    });
    const decoded = knownSchema ? knownSchema.observe(decode) : decode();
    if (decoded) {
      const checkKind = () => {
        if (decoded.kind !== ref.kind) {
          fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
        }
      };
      if (knownSchema) knownSchema.observe(checkKind);
      else checkKind();
      if (options.registry) {
        const validateSemantics = () => validateKnownSchema(decoded.value, decoded.kind, {
          registry: options.registry, hardLimits: options.hardLimits, operation
        });
        if (registrySemantics) registrySemantics.observe(validateSemantics);
        else validateSemantics();
      }
      value = decoded.value;
    }
  }
  return { ref, payload: item.payload.slice(), value };
}

function normalizedRoot(item, names) {
  if (!item || (item.kind !== 1 && item.kind !== 2)) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'known-schema' });
  }
  const identity = item.kind === 1
    ? (item.identity instanceof ObjectRef ? item.identity : asRef(item.identity, names))
    : (item.identity instanceof Digest ? item.identity : Digest.fromMap(item.identity));
  const role = item.role instanceof ProfileRef ? item.role : ProfileRef.fromMap(item.role);
  return { kind: item.kind, identity, role };
}

function bundleEncode(value) {
  return encodeCanonical(value, {
    maxBytes: HARD.itemBytes,
    maxValueBytes: HARD.itemBytes,
    maxContainerItems: MAX_CONTAINER_ITEMS,
    maxDepth: MAX_NESTING_DEPTH
  });
}

function joined(parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function conservativeValueBytes(value, maximum, active = new Set()) {
  let bytes = 16;
  if (typeof value === 'string') bytes += value.length * 2 + Buffer.byteLength(value);
  else if (value instanceof Uint8Array || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    bytes += value.byteLength;
  } else if (Array.isArray(value)) {
    bytes += value.length * 16 + 32;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) fail('LIMIT_MEMORY', { layer: 1 });
    if (active.has(value)) fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    active.add(value);
    try { for (const item of value) bytes += conservativeValueBytes(item, maximum - bytes, active); }
    finally { active.delete(value); }
  } else if (value instanceof Map) {
    bytes += value.size * 64 + 32;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) fail('LIMIT_MEMORY', { layer: 1 });
    if (active.has(value)) fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    active.add(value);
    try {
      for (const [key, item] of value) {
        bytes += conservativeValueBytes(key, maximum - bytes, active);
        bytes += conservativeValueBytes(item, maximum - bytes, active);
      }
    } finally { active.delete(value); }
  } else if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    bytes += keys.length * 64 + 32;
    if (!Number.isSafeInteger(bytes) || bytes > maximum) fail('LIMIT_MEMORY', { layer: 1 });
    if (active.has(value)) fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    active.add(value);
    try { for (const key of keys) bytes += conservativeValueBytes(value[key], maximum - bytes, active); }
    finally { active.delete(value); }
  }
  if (!Number.isSafeInteger(bytes) || bytes > maximum) fail('LIMIT_MEMORY', { layer: 1 });
  return bytes;
}

function boundedCanonicalBytes(value, maximum) {
  let bytes = 0;
  for (const part of encodeCanonicalChunks(value, {
    maxBytes: HARD.itemBytes,
    maxValueBytes: HARD.itemBytes,
    maxContainerItems: MAX_CONTAINER_ITEMS,
    maxDepth: MAX_NESTING_DEPTH,
    maxWorkingBytes: maximum,
    chunkBytes: Math.max(1, Math.min(65_536, maximum || 1))
  })) {
    if (part.length > maximum - bytes) fail('LIMIT_MEMORY', { layer: 1 });
    bytes += part.length;
  }
  return bytes;
}

// Measures the retained representation a canonical decoder would construct,
// without decoding strings or allocating arrays/maps. Malformed/non-item raw
// bytes (including ordinary chunk payloads) have no decoded representation;
// their payload copy is still charged separately by the caller.
function measuredDecodedBytes(input, maximum) {
  let offset = 0;
  let retained = 0;
  let exceeded = false;
  const charge = count => {
    if (!Number.isSafeInteger(count) || count < 0 || count > maximum - retained) {
      exceeded = true;
      return false;
    }
    retained += count;
    return true;
  };
  const takeArgument = ai => {
    if (ai < 24) return ai;
    const size = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : 0;
    if (size === 0 || size > input.length - offset) return undefined;
    let value = 0n;
    for (let index = 0; index < size; index++) value = (value << 8n) | BigInt(input[offset++]);
    return value > BigInt(Number.MAX_SAFE_INTEGER) ? undefined : Number(value);
  };
  const item = depth => {
    if (exceeded || offset >= input.length || depth > MAX_NESTING_DEPTH) return false;
    const first = input[offset++];
    const major = first >>> 5;
    const ai = first & 31;
    if (major === 7) return ai === 20 || ai === 21;
    if (major === 6 || ai === 31) return false;
    const argument = takeArgument(ai);
    if (argument === undefined) return false;
    if (major <= 1) return true;
    if (major === 2 || major === 3) {
      if (argument > input.length - offset) return false;
      offset += argument;
      return charge((major === 2 ? argument : argument * 2) + 32);
    }
    if (major === 4 || major === 5) {
      const values = major === 4 ? argument : argument * 2;
      // Every child consumes at least one byte, so reject impossible declared
      // counts without entering an attacker-sized loop.
      if (!Number.isSafeInteger(values) || values > input.length - offset ||
          !charge(argument * (major === 4 ? 64 : 128))) return false;
      for (let index = 0; index < values; index++) if (!item(depth + 1)) return false;
      return true;
    }
    return false;
  };
  const valid = item(1) && offset === input.length;
  return exceeded ? maximum + 1 : valid ? retained : 0;
}

function planCount(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return value;
}

function bundleWritePlan(plan, limits) {
  if (!plan || typeof plan !== 'object' || !plan.budget || typeof plan.budget !== 'object') {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const objectCount = planCount(plan.objectCount);
  const logicalRecordCount = planCount(plan.logicalRecordCount);
  const rootCount = planCount(plan.rootCount);
  const budget = Object.freeze({
    sequenceBytes: planCount(plan.budget.sequenceBytes),
    largestItemBytes: planCount(plan.budget.largestItemBytes),
    traversalEdges: planCount(plan.budget.traversalEdges),
    indexEntries: planCount(plan.budget.indexEntries)
  });
  const items = objectCount + logicalRecordCount + rootCount + 2;
  const indexEntries = objectCount + logicalRecordCount;
  if (!Number.isSafeInteger(items)) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const check = (key, value) => enforceHardLimit(undefined, BUNDLE_LIMIT_NAMES[key], value, {
    maximum: limits[key], code: 'BUNDLE_BUDGET_EXCEEDED', layer: 1,
    stage: 'configured-resource-preflight'
  });
  check('objects', objectCount);
  check('logicalRecords', logicalRecordCount);
  check('roots', rootCount);
  check('items', items);
  check('sequenceBytes', budget.sequenceBytes);
  check('itemBytes', budget.largestItemBytes);
  check('traversalEdges', budget.traversalEdges);
  check('indexEntries', budget.indexEntries);
  check('indexEntries', indexEntries);
  if (indexEntries > budget.indexEntries) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }
  return Object.freeze({ objectCount, logicalRecordCount, rootCount, budget });
}

function headerFor(plan) {
  return new Map([
    [0, 1], [1, 1], [2, 1], [3, plan.objectCount], [4, plan.logicalRecordCount], [5, plan.rootCount],
    [6, new Map([[0, plan.budget.sequenceBytes], [1, plan.budget.largestItemBytes],
      [2, plan.budget.traversalEdges], [3, plan.budget.indexEntries]])]
  ]);
}

function trailerFor(plan, digest) {
  return new Map([
    [0, 1], [1, 5], [2, plan.objectCount], [3, plan.logicalRecordCount], [4, plan.rootCount],
    [5, plan.objectCount + plan.logicalRecordCount + plan.rootCount + 2], [6, digest.toMap()]
  ]);
}

function objectPrefix(ordinal, reference, payloadLength) {
  return joined([
    Uint8Array.of(0xa5, 0x00, 0x01, 0x01, 0x02, 0x02), cborHeader(0, ordinal), Uint8Array.of(0x03),
    encodeCanonical(reference.toMap()), Uint8Array.of(0x04), cborHeader(2, payloadLength)
  ]);
}

function logicalPrefix(ordinal, identity) {
  return joined([
    Uint8Array.of(0xa5, 0x00, 0x01, 0x01, 0x03, 0x02), cborHeader(0, ordinal), Uint8Array.of(0x03),
    encodeCanonical(identity.toMap()), Uint8Array.of(0x04)
  ]);
}

function rootBytes(ordinal, root) {
  return bundleEncode(new Map([
    [0, 1], [1, 4], [2, ordinal], [3, root.kind], [4, root.identity.toMap()], [5, root.role.toMap()]
  ]));
}

/**
 * Writes an already-ordered logical bundle without retaining the sequence or
 * graph. The immutable header plan is supplied up front; each section may be
 * an Iterable or AsyncIterable and only the current item is retained.
 * Successful emission proves wire integrity only. Call a supplied-closure
 * verifier before treating the result as a valid bundle.
 */
export async function writeOrderedLogicalBundle({
  plan, objects = [], logicalRecords = [], roots = [], sink, ...options
}) {
  const semantic = writerValidationContext(options.operation, options.registry);
  if (options.semanticValidator !== undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  options = { ...options, ...semantic };
  const limits = configured(options);
  const frozenPlan = bundleWritePlan(plan, limits);
  const maxMemoryBytes = options.maxMemoryBytes ?? 67_108_864;
  const guard = new ResourceGuard({
    maxTimeMs: options.maxTimeMs ?? 600_000,
    maxMemoryBytes
  });
  const names = options.registry?.kindNames ?? KIND_NAMES;
  const operation = semantic.operation;
  const declaredIdentity = deferredStageCollector(1, 'declared-identity');
  const knownSchema = deferredStageCollector(2, 'known-schema');
  const registrySemantics = deferredStageCollector(3, 'registry-semantics');
  const header = bundleEncode(headerFor(frozenPlan));
  const dummyTrailer = bundleEncode(trailerFor(frozenPlan, new Digest(1, new Uint8Array(32))));
  if (header.length > limits.itemBytes || dummyTrailer.length > limits.itemBytes) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (header.length > frozenPlan.budget.largestItemBytes ||
      dummyTrailer.length > frozenPlan.budget.largestItemBytes ||
      header.length + dummyTrailer.length > frozenPlan.budget.sequenceBytes) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }
  const transcript = createBundleTranscriptHashWriter({ maxBytes: frozenPlan.budget.sequenceBytes });
  let bytes = 0; let items = 0; let largestItemBytes = 0; let traversalEdges = 0;
  const emitKnownLength = async (length, parts, includeTranscript = true, reserveTrailer = true) => {
    guard.time();
    if (length > limits.itemBytes ||
        bytes + length + (reserveTrailer ? dummyTrailer.length : 0) > limits.sequenceBytes) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
    }
    if (length > frozenPlan.budget.largestItemBytes ||
        bytes + length + (reserveTrailer ? dummyTrailer.length : 0) > frozenPlan.budget.sequenceBytes) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
    }
    let emitted = 0;
    for (const part of parts) {
      guard.time();
      guard.memory(part.length);
      await writeFully(sink, part, { guard });
      if (includeTranscript) transcript.update(part);
      emitted += part.length;
    }
    if (emitted !== length) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    bytes += length; items++; largestItemBytes = Math.max(largestItemBytes, length);
  };
  const emit = async (parts, includeTranscript = true, reserveTrailer = true) => {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    await emitKnownLength(length, parts, includeTranscript, reserveTrailer);
  };
  await emit([header]);

  let previousObject;
  let objectCount = 0;
  for await (const item of guardedAsyncIterable(toAsyncIterable(objects), guard)) {
    if (objectCount >= frozenPlan.objectCount || !item || !(item.payload instanceof Uint8Array)) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    }
    const reference = item.ref instanceof ObjectRef ? item.ref : asRef(item.ref, names);
    const sortKey = encodeCanonical(reference.toMap());
    if (previousObject) {
      const order = compareBytes(previousObject, sortKey);
      if (order >= 0) fail(order === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    }
    const limitName = reference.kind === 1 ? 'chunk-payload-bytes' : 'metadata-payload-bytes';
    const maximum = configuredHardLimit(limitName, options.hardLimits?.[limitName]);
    enforceHardLimit(undefined, limitName, item.payload.length, { maximum, layer: 1 });
    const retainedEstimate = reference.kind === 1
      ? item.payload.length
      : item.payload.length * 16 + 512;
    if (!Number.isSafeInteger(retainedEstimate)) fail('LIMIT_MEMORY', { layer: 1 });
    guard.memory(retainedEstimate);
    declaredIdentity.observe(() => verifyDeclaredObjectIdentity(
      reference, item.payload, names, options));
    let edges = 0;
    if (reference.kind !== 1) {
      const decoded = knownSchema.observe(() => decodeMetadata(item.payload, {
        semantic: false, hardLimits: options.hardLimits
      }));
      if (decoded) {
        if (decoded.kind !== reference.kind) {
          knownSchema.observe(() => fail('OBJECT_REFERENCE_KIND_MISMATCH', {
            layer: 2, stage: 'known-schema'
          }));
        }
        if (options.registry) registrySemantics.observe(() => validateKnownSchema(
          decoded.value, decoded.kind, {
            registry: options.registry, hardLimits: options.hardLimits, operation
          }));
        for (const _reference of iterateObjectReferences(decoded.kind, decoded.value)) edges++;
      }
    }
    if (options.registry) {
      knownSchema.observe(() => registrySemantics.observe(() =>
        registryAssignmentDecision(options.registry, 'object-kinds', reference.kind, operation)));
      knownSchema.observe(() => registrySemantics.observe(() =>
        registryAssignmentDecision(options.registry, 'hash-algorithms', 1, operation)));
    }
    if (traversalEdges + edges > limits.traversalEdges) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
    }
    if (traversalEdges + edges > frozenPlan.budget.traversalEdges) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
    }
    const prefix = objectPrefix(objectCount, reference, item.payload.length);
    const replayWriter = names.has(reference.kind)
      ? createObjectHashWriter(reference.kind, {
        registry: names,
        maxChunkBytes: configuredHardLimit('chunk-payload-bytes', options.hardLimits?.['chunk-payload-bytes']),
        maxMetadataBytes: configuredHardLimit('metadata-payload-bytes', options.hardLimits?.['metadata-payload-bytes'])
      })
      : createOpaqueObjectHashWriter(reference.kind, { maxBytes: maximum });
    const payloadChunkBytes = Math.max(1, Math.min(65_536, Math.floor(maxMemoryBytes / 4) || 1));
    function* objectParts() {
      yield prefix;
      for (let offset = 0; offset < item.payload.length; offset += payloadChunkBytes) {
        const part = item.payload.slice(offset, Math.min(offset + payloadChunkBytes, item.payload.length));
        replayWriter.update(part);
        yield part;
      }
    }
    await emitKnownLength(prefix.length + item.payload.length, objectParts());
    const replayIdentity = replayWriter.finish();
    declaredIdentity.observe(() => {
      const digest = replayIdentity instanceof ObjectRef ? replayIdentity.digest : replayIdentity.bytes;
      if (!equalBytes(digest, reference.digest)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
    });
    previousObject = sortKey; traversalEdges += edges; objectCount++;
  }
  if (objectCount !== frozenPlan.objectCount) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });

  let previousLogical;
  let logicalRecordCount = 0;
  for await (const record of guardedAsyncIterable(toAsyncIterable(logicalRecords), guard)) {
    if (logicalRecordCount >= frozenPlan.logicalRecordCount) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    guard.time();
    const raw = rawLogicalType(record);
    if (!raw.hashable) {
      // Without a bounded numeric record type no identity/sort key can be
      // derived, so this is not a safely continuable item.
      validateLogicalRecord(record, { semantic: false, hardLimits: options.hardLimits });
      fail('SCHEMA_FIELD_INVALID', { layer: 2, stage: 'known-schema' });
    }
    const encodingOptions = {
      maxBytes: Math.min(
        configuredHardLimit('metadata-payload-bytes', options.hardLimits?.['metadata-payload-bytes']),
        frozenPlan.budget.largestItemBytes,
        limits.itemBytes
      ),
      maxValueBytes: configuredHardLimit(
        'generic-text-or-byte-value-bytes', options.hardLimits?.['generic-text-or-byte-value-bytes']
      ),
      maxContainerItems: MAX_CONTAINER_ITEMS,
      maxDepth: Math.max(1, configuredHardLimit(
        'cbor-nesting-depth', options.hardLimits?.['cbor-nesting-depth']
      ) - 1),
      maxWorkingBytes: maxMemoryBytes,
      chunkBytes: Math.max(1, Math.min(65_536, Math.floor(maxMemoryBytes / 4) || 1))
    };
    const identityWriter = createLogicalRecordHashWriter(raw.type, {
      registry: options.registry?.logicalRecordTypeCodes,
      maxBytes: encodingOptions.maxBytes
    });
    let recordBytes = 0;
    for (const part of encodeCanonicalChunks(record, encodingOptions)) {
      guard.time();
      guard.memory(part.length);
      identityWriter.update(part);
      recordBytes += part.length;
    }
    const identity = identityWriter.finish();
    const validation = knownSchema.observe(() => validateLogicalRecord(record, {
      semantic: false, hardLimits: options.hardLimits
    }));
    let edges = 0;
    if (validation) {
      for (const _reference of iterateLogicalRecordReferences(validation.type, record)) edges++;
    }
    const sortKey = [Uint8Array.of(raw.type >>> 8, raw.type & 255), identity.bytes];
    if (previousLogical) {
      const order = compareTuple(previousLogical, sortKey);
      if (order >= 0) fail(order === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    }
    if (options.registry && validation) registrySemantics.observe(() => {
      const semanticValidation = validateLogicalRecord(record, {
        registry: options.registry, hardLimits: options.hardLimits, operation
      });
      checkProfileList(semanticValidation.profiles, options.registry, operation);
    });
    if (traversalEdges + edges > limits.traversalEdges) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
    }
    if (traversalEdges + edges > frozenPlan.budget.traversalEdges) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
    }
    const prefix = logicalPrefix(logicalRecordCount, identity);
    const replayWriter = createLogicalRecordHashWriter(raw.type, {
      registry: options.registry?.logicalRecordTypeCodes,
      maxBytes: encodingOptions.maxBytes
    });
    function* encodedRecordParts() {
      yield prefix;
      for (const part of encodeCanonicalChunks(record, encodingOptions)) {
        replayWriter.update(part);
        yield part;
      }
    }
    await emitKnownLength(prefix.length + recordBytes, encodedRecordParts());
    const replayIdentity = replayWriter.finish();
    declaredIdentity.observe(() => {
      if (!equalBytes(replayIdentity.bytes, identity.bytes)) {
        fail('BUNDLE_RECORD_ID_MISMATCH', { layer: 1 });
      }
    });
    previousLogical = sortKey; traversalEdges += edges; logicalRecordCount++;
  }
  if (logicalRecordCount !== frozenPlan.logicalRecordCount) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });

  let previousRoot;
  let previousRootIdentity;
  let rootCount = 0; let objectRoots = 0; let logicalRoots = 0;
  for await (const raw of guardedAsyncIterable(toAsyncIterable(roots), guard)) {
    if (rootCount >= frozenPlan.rootCount) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const root = normalizedRoot(raw, names);
    const identityBytes = encodeCanonical(root.identity.toMap());
    const roleBytes = encodeCanonical(root.role.toMap());
    const sortKey = [Uint8Array.of(root.kind), identityBytes, roleBytes];
    const identityKey = [Uint8Array.of(root.kind), identityBytes];
    if (previousRoot && compareTuple(previousRoot, sortKey) >= 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    if (previousRootIdentity && compareTuple(previousRootIdentity, identityKey) === 0) {
      fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1 });
    }
    if (options.registry) registrySemantics.observe(() =>
      checkProfileList([root.role], options.registry, operation));
    await emit([rootBytes(rootCount, root)]);
    if (root.kind === 1) objectRoots++; else logicalRoots++;
    previousRoot = sortKey; previousRootIdentity = identityKey; rootCount++;
  }
  if (rootCount !== frozenPlan.rootCount) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  declaredIdentity.throwSelected();
  knownSchema.throwSelected();
  if ((objectCount > 0 && objectRoots === 0) || logicalRoots !== logicalRecordCount) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  registrySemantics.throwSelected();

  const transcriptDigest = transcript.finish();
  const trailer = bundleEncode(trailerFor(frozenPlan, transcriptDigest));
  if (trailer.length !== dummyTrailer.length) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  await emit([trailer], false, false);
  if (typeof sink?.flush === 'function') {
    await guard.wait(signal => sink.flush({ signal }));
  }
  return Object.freeze({
    bytes, items, largestItemBytes, objectCount, logicalRecordCount, rootCount, traversalEdges,
    indexEntries: objectCount + logicalRecordCount, transcriptDigest: toHex(transcriptDigest.bytes)
  });
}

/**
 * Freezes the only claim that format-v1 logical-bundle bytes can make.
 * Fidelity, projection, and export classification belong to OGVCS-033 and
 * cannot be attached to this supplied-closure container.
 */
export function validateBundleClaim(claim) {
  if (typeof claim !== 'string' || claim.length === 0) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  if (claim !== 'supplied-closure') fail('BUNDLE_EXPORT_CLAIM_FORBIDDEN', { layer: 3 });
  return 'supplied-closure';
}

/** Builds the deterministic in-memory supplied-closure representation. */
export function encodeLogicalBundle({ objects = [], logicalRecords = [], roots = [] }, options = {}) {
  const semantic = writerValidationContext(options.operation, options.registry);
  if (options.semanticValidator !== undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  options = { ...options, ...semantic };
  if (!Array.isArray(objects) || !Array.isArray(logicalRecords) || !Array.isArray(roots)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const limits = configuredInMemory(options);
  const maxMemoryBytes = options.maxMemoryBytes ?? IN_MEMORY.memoryBytes;
  if (!Number.isSafeInteger(maxMemoryBytes) || maxMemoryBytes < 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (objects.length > limits.objects || logicalRecords.length > limits.logicalRecords ||
      roots.length > limits.roots || objects.length + logicalRecords.length + roots.length + 2 > limits.items) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  let inputPayloadBytes = 0;
  let decodedPayloadBytes = 0;
  for (const item of objects) {
    if (!(item?.payload instanceof Uint8Array) || item.payload.length > limits.sequenceBytes - inputPayloadBytes) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
    }
    inputPayloadBytes += item.payload.length;
    const decoded = measuredDecodedBytes(item.payload, maxMemoryBytes - decodedPayloadBytes);
    if (decoded > maxMemoryBytes - decodedPayloadBytes) fail('LIMIT_MEMORY', { layer: 1 });
    decodedPayloadBytes += decoded;
  }
  // The convenience encoder necessarily retains normalized payload copies,
  // encoded item bytes, the concatenated sequence, and verification state.
  // Reject a conservative lower bound before reading refs, normalizing maps,
  // copying payloads, or producing any bytes. Large callers should use the
  // ordered sink writer, whose memory is bounded per item.
  let logicalInputBytes = 0;
  for (const record of logicalRecords) {
    conservativeValueBytes(record, maxMemoryBytes);
    const bytes = boundedCanonicalBytes(record, maxMemoryBytes);
    if (bytes > maxMemoryBytes - logicalInputBytes) fail('LIMIT_MEMORY', { layer: 1 });
    logicalInputBytes += bytes;
  }
  let rootInputBytes = 0;
  for (const root of roots) {
    const bytes = conservativeValueBytes(root, maxMemoryBytes);
    if (bytes > maxMemoryBytes - rootInputBytes) fail('LIMIT_MEMORY', { layer: 1 });
    rootInputBytes += bytes;
  }
  const recordCount = BigInt(objects.length + logicalRecords.length + roots.length + 2);
  const minimumWorkingBytes = BigInt(inputPayloadBytes) * 3n +
    BigInt(decodedPayloadBytes) * 2n +
    BigInt(logicalInputBytes + rootInputBytes) * 3n +
    recordCount * 2_048n;
  if (minimumWorkingBytes > BigInt(maxMemoryBytes)) fail('LIMIT_MEMORY', { layer: 1 });
  const names = options.registry?.kindNames ?? KIND_NAMES;
  const operation = semantic.operation;
  preflightObjectOrder(objects, names);
  const declaredIdentity = deferredStageCollector(1, 'declared-identity');
  const knownSchema = deferredStageCollector(2, 'known-schema');
  const registrySemantics = deferredStageCollector(3, 'registry-semantics');
  const normalizedObjects = objects.map(item => normalizedObject(item, names, options, {
    declaredIdentity, knownSchema, registrySemantics
  }));
  const objectItems = normalizedObjects.map((item, ordinal) => new Map([
    [0, 1], [1, 2], [2, ordinal], [3, item.ref.toMap()], [4, item.payload]
  ]));

  preflightLogicalOrder(logicalRecords);
  const normalizedLogical = logicalRecords.map(record => {
    const validation = validateLogicalRecord(record, {
      registry: options.registry, hardLimits: options.hardLimits, operation
    });
    checkProfileList(validation.profiles, options.registry, operation);
    return { type: validation.type, record, identity: hashLogicalRecord(validation.type, encodeCanonical(record)) };
  });
  for (let index = 1; index < normalizedLogical.length; index++) {
    const left = normalizedLogical[index - 1]; const right = normalizedLogical[index];
    const order = compareTuple(
      [Uint8Array.of(left.type >>> 8, left.type & 255), left.identity.bytes],
      [Uint8Array.of(right.type >>> 8, right.type & 255), right.identity.bytes]
    );
    if (order >= 0) fail(order === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  }
  const logicalItems = normalizedLogical.map((item, ordinal) => new Map([
    [0, 1], [1, 3], [2, ordinal], [3, item.identity.toMap()], [4, item.record]
  ]));

  const normalizedRoots = roots.map(item => normalizedRoot(item, names));
  for (let index = 1; index < normalizedRoots.length; index++) {
    const left = normalizedRoots[index - 1]; const right = normalizedRoots[index];
    const order = compareTuple(
      [Uint8Array.of(left.kind), encodeCanonical(left.identity.toMap()), encodeCanonical(left.role.toMap())],
      [Uint8Array.of(right.kind), encodeCanonical(right.identity.toMap()), encodeCanonical(right.role.toMap())]
    );
    if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const sameIdentity = left.kind === right.kind && equalBytes(
      left.kind === 1 ? left.identity.digest : left.identity.bytes,
      right.kind === 1 ? right.identity.digest : right.identity.bytes
    );
    if (sameIdentity) fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1 });
  }
  declaredIdentity.throwSelected();
  knownSchema.throwSelected();
  registrySemantics.throwSelected();
  const rootItems = normalizedRoots.map((item, ordinal) => new Map([
    [0, 1], [1, 4], [2, ordinal], [3, item.kind], [4, item.identity.toMap()], [5, item.role.toMap()]
  ]));

  let traversalEdges = 0;
  for (const item of normalizedObjects) {
    if (item.value) for (const _reference of iterateObjectReferences(item.ref.kind, item.value)) traversalEdges++;
  }
  for (const item of normalizedLogical) {
    for (const _reference of iterateLogicalRecordReferences(item.type, item.record)) traversalEdges++;
  }
  const indexEntries = normalizedObjects.length + normalizedLogical.length;
  const declaredTraversalEdges = options.declaredTraversalEdges ?? traversalEdges;
  const declaredIndexEntries = options.declaredIndexEntries ?? indexEntries;
  if (!Number.isSafeInteger(declaredTraversalEdges) ||
      declaredTraversalEdges > limits.traversalEdges || !Number.isSafeInteger(declaredIndexEntries) ||
      declaredIndexEntries > limits.indexEntries) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (declaredTraversalEdges < traversalEdges || declaredIndexEntries < indexEntries) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }
  const bodyItems = [...objectItems, ...logicalItems, ...rootItems];
  let declaredBytes = 0;
  let declaredLargest = 0;
  let finalBytes;
  for (let iteration = 0; iteration < 12; iteration++) {
    const header = new Map([
      [0, 1], [1, 1], [2, 1], [3, normalizedObjects.length], [4, normalizedLogical.length], [5, normalizedRoots.length],
      [6, new Map([[0, declaredBytes], [1, declaredLargest], [2, declaredTraversalEdges], [3, declaredIndexEntries]])]
    ]);
    const prefixValues = [header, ...bodyItems];
    const prefixBytes = prefixValues.map(bundleEncode);
    const transcript = hashBundleTranscript(prefixBytes);
    const trailer = new Map([
      [0, 1], [1, 5], [2, normalizedObjects.length], [3, normalizedLogical.length], [4, normalizedRoots.length],
      [5, prefixValues.length + 1], [6, transcript.toMap()]
    ]);
    const all = [...prefixBytes, bundleEncode(trailer)];
    const nextBytes = all.reduce((sum, item) => sum + item.length, 0);
    let nextLargest = 0;
    for (const item of all) nextLargest = Math.max(nextLargest, item.length);
    if (nextBytes > limits.sequenceBytes || nextLargest > limits.itemBytes) {
      fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
    }
    finalBytes = Buffer.concat(all);
    if (nextBytes === declaredBytes && nextLargest === declaredLargest) break;
    declaredBytes = nextBytes; declaredLargest = nextLargest;
    if (iteration === 11) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  }
  // Normalized payload copies/decoded metadata and item/index wrappers remain
  // live while the independent verifier decodes the finished sequence. Give
  // that verifier only the genuinely remaining aggregate budget.
  const retainedBeforeVerify = inputPayloadBytes + decodedPayloadBytes +
    Number(recordCount) * 1_536;
  if (!Number.isSafeInteger(retainedBeforeVerify) || retainedBeforeVerify > maxMemoryBytes) {
    fail('LIMIT_MEMORY', { layer: 1 });
  }
  verifyLogicalBundle(finalBytes, {
    ...options,
    maxMemoryBytes: maxMemoryBytes - retainedBeforeVerify
  });
  return new Uint8Array(finalBytes);
}

/**
 * Validates an in-memory logical-bundle sequence through supplied-closure
 * semantics. For multi-gigabyte inputs use the streaming/spooled verifier;
 * this entry point deliberately obeys the caller's finite `sequenceBytes` cap.
 */
export function verifyLogicalBundle(input, options = {}) {
  const semantic = codecValidationContext(options);
  if (options.semanticValidator !== undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  options = { ...options, ...semantic };
  if (!(input instanceof Uint8Array)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const limits = configuredInMemory(options);
  const operation = semantic.operation;
  if (input.length > limits.sequenceBytes) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const maxMemoryBytes = options.maxMemoryBytes ?? IN_MEMORY.memoryBytes;
  if (!Number.isSafeInteger(maxMemoryBytes) || maxMemoryBytes < 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const guard = new ResourceGuard({ maxTimeMs: options.maxTimeMs, maxMemoryBytes });
  guard.time();
  if (input.length > maxMemoryBytes) fail('LIMIT_MEMORY', { layer: 1 });
  const { values, slices, retainedBytes } = decodeSequence(input, {
    maxBytes: limits.sequenceBytes,
    maxDepth: configuredHardLimit('cbor-nesting-depth', options.hardLimits?.['cbor-nesting-depth']),
    maxContainerItems: MAX_CONTAINER_ITEMS,
    maxValueBytes: Math.min(limits.itemBytes, HARD.itemBytes),
    maxWorkingBytes: maxMemoryBytes - input.length
  });
  if (retainedBytes > maxMemoryBytes - input.length) fail('LIMIT_MEMORY', { layer: 1 });
  let retainedMemory = input.length + retainedBytes;
  const retain = bytes => {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxMemoryBytes - retainedMemory) {
      fail('LIMIT_MEMORY', { layer: 1 });
    }
    retainedMemory += bytes;
    guard.memory(retainedMemory);
  };
  const checkTransient = bytes => {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxMemoryBytes - retainedMemory) {
      fail('LIMIT_MEMORY', { layer: 1 });
    }
    guard.memory(retainedMemory + bytes);
  };
  guard.time();
  if (values.length < 2 || values.length > limits.items) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });

  const header = values[0];
  const trailer = values.at(-1);
  if (!(header instanceof Map) || !(trailer instanceof Map) || header.get(1) !== 1 || trailer.get(1) !== 5) {
    fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  }
  exactBundleMap(header, [0, 1, 2, 3, 4, 5, 6]);
  exactBundleMap(trailer, [0, 1, 2, 3, 4, 5, 6]);
  if (header.get(2) !== 1) fail('BUNDLE_MODE_UNSUPPORTED', { layer: 1 });
  const objectCount = Number(uint(header.get(3), limits.objects, 'BUNDLE_BUDGET_EXCEEDED'));
  const logicalCount = Number(uint(header.get(4), limits.logicalRecords, 'BUNDLE_BUDGET_EXCEEDED'));
  const rootCount = Number(uint(header.get(5), limits.roots, 'BUNDLE_BUDGET_EXCEEDED'));
  if (values.length !== objectCount + logicalCount + rootCount + 2) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
  for (let index = 0; index < values.length; index++) {
    guard.time();
    const expectedType = index === 0 ? 1
      : index <= objectCount ? 2
        : index <= objectCount + logicalCount ? 3
          : index <= objectCount + logicalCount + rootCount ? 4 : 5;
    if (!(values[index] instanceof Map) || values[index].get(1) !== expectedType) {
      fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    }
    if (expectedType === 2 || expectedType === 3) exactBundleMap(values[index], [0, 1, 2, 3, 4]);
    else if (expectedType === 4) exactBundleMap(values[index], [0, 1, 2, 3, 4, 5]);
  }

  const declarations = header.get(6);
  exactBundleMap(declarations, [0, 1, 2, 3]);
  const declaredBytes = uint(declarations.get(0), limits.sequenceBytes, 'BUNDLE_BUDGET_EXCEEDED');
  const declaredLargest = uint(declarations.get(1), limits.itemBytes, 'BUNDLE_BUDGET_EXCEEDED');
  const declaredEdges = uint(declarations.get(2), limits.traversalEdges, 'BUNDLE_BUDGET_EXCEEDED');
  const declaredIndex = uint(declarations.get(3), limits.indexEntries, 'BUNDLE_BUDGET_EXCEEDED');
  let largestItem = 0;
  for (const item of slices) largestItem = Math.max(largestItem, item.length);
  const indexEntries = objectCount + logicalCount;
  if (indexEntries > limits.indexEntries) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }

  // Complete every safely discoverable layer-1 ordering and identity check
  // before authenticating the transcript or entering known-kind schema.
  let layerOneDuplicate = false;
  let layerOnePreviousObject;
  for (let ordinal = 0; ordinal < objectCount; ordinal++) {
    guard.time();
    const item = values[1 + ordinal];
    if (uint(item.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const sortKey = encodeCanonical(item.get(3));
    if (layerOnePreviousObject) {
      const order = compareBytes(layerOnePreviousObject, sortKey);
      if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
      if (order === 0) layerOneDuplicate = true;
    }
    layerOnePreviousObject = sortKey;
  }
  let layerOnePreviousLogical;
  for (let ordinal = 0; ordinal < logicalCount; ordinal++) {
    guard.time();
    const item = values[1 + objectCount + ordinal];
    if (!(item instanceof Map) || uint(item.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const identity = rawTypedDigest(item.get(3));
    const record = item.get(4);
    const recordType = rawLogicalType(record);
    const sortKey = [recordType.sortKey, identity];
    if (recordType.hashable && layerOnePreviousLogical) {
      const order = compareTuple(layerOnePreviousLogical, sortKey);
      if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
      if (order === 0) layerOneDuplicate = true;
    }
    layerOnePreviousLogical = recordType.hashable ? sortKey : undefined;
  }
  let layerOnePreviousRoot;
  let layerOnePreviousRootIdentity;
  for (let ordinal = 0; ordinal < rootCount; ordinal++) {
    guard.time();
    const item = values[1 + objectCount + logicalCount + ordinal];
    if (!(item instanceof Map) || uint(item.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const rootKindBytes = encodeCanonical(item.get(3));
    const identityBytes = encodeCanonical(item.get(4));
    const roleBytes = encodeCanonical(item.get(5));
    const sortKey = [rootKindBytes, identityBytes, roleBytes];
    const identityKey = [rootKindBytes, identityBytes];
    if (layerOnePreviousRoot) {
      const order = compareTuple(layerOnePreviousRoot, sortKey);
      if (order > 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
      if (order === 0) layerOneDuplicate = true;
    }
    if (layerOnePreviousRootIdentity && compareTuple(layerOnePreviousRootIdentity, identityKey) === 0) {
      layerOneDuplicate = true;
    }
    layerOnePreviousRoot = sortKey;
    layerOnePreviousRootIdentity = identityKey;
  }
  if (layerOneDuplicate) fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1 });

  // Identity is a distinct layer-1 stage after the complete sequence-order
  // pass. A later out-of-order item is therefore never hidden by an earlier
  // payload digest mismatch.
  for (let ordinal = 0; ordinal < objectCount; ordinal++) {
    guard.time();
    const item = values[1 + ordinal];
    const reference = rawObjectRef(item.get(3));
    if (!(item.get(4) instanceof Uint8Array)) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'canonical-framing' });
    }
    const limitName = reference.kind === 1 ? 'chunk-payload-bytes' : 'metadata-payload-bytes';
    const maximum = configuredHardLimit(limitName, options.hardLimits?.[limitName]);
    enforceHardLimit(undefined, limitName, item.get(4).length, { maximum, layer: 1 });
    const actual = hashOpaqueObject(reference.kind, item.get(4), {
      maxBytes: maximum
    });
    if (!equalBytes(reference.digest, actual.bytes)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
  }
  for (let ordinal = 0; ordinal < logicalCount; ordinal++) {
    guard.time();
    const item = values[1 + objectCount + ordinal];
    const identity = rawTypedDigest(item.get(3));
    const record = item.get(4);
    const recordType = rawLogicalType(record);
    if (!recordType.hashable) continue;
    const actual = hashLogicalRecord(recordType.type, encodeCanonical(record));
    if (!equalBytes(identity, actual.bytes)) fail('BUNDLE_RECORD_ID_MISMATCH', { layer: 1 });
  }

  if (uint(trailer.get(2)) !== BigInt(objectCount) || uint(trailer.get(3)) !== BigInt(logicalCount) ||
      uint(trailer.get(4)) !== BigInt(rootCount) || uint(trailer.get(5)) !== BigInt(values.length)) {
    fail('BUNDLE_TRAILER_MISMATCH', { layer: 1 });
  }
  const trailerDigest = rawTypedDigest(trailer.get(6));
  const transcript = hashBundleTranscript(slices.slice(0, -1));
  if (!equalBytes(trailerDigest, transcript.bytes)) fail('BUNDLE_TRAILER_MISMATCH', { layer: 1 });

  // These actual values are authenticated and available without interpreting
  // any layer-2 object schema. Lowest-layer-first precedence therefore makes
  // declared accounting terminal here, before root/closure diagnostics.
  if (BigInt(input.length) > declaredBytes || BigInt(largestItem) > declaredLargest ||
      BigInt(indexEntries) > declaredIndex) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }

  // Discover every independently safe known-schema failure before selecting
  // one. The per-item decoded object is discarded immediately, so collection
  // is constant-space even for the in-memory entry point.
  const knownSchema = deferredStageCollector(2, 'known-schema');
  knownSchema.observe(() => validateBundleItem(header, {
    hardLimits: options.hardLimits, semantic: false
  }));
  knownSchema.observe(() => validateBundleItem(trailer, {
    hardLimits: options.hardLimits, semantic: false
  }));
  for (let ordinal = 0; ordinal < objectCount; ordinal++) {
    guard.time();
    const item = values[1 + ordinal];
    knownSchema.observe(() => validateBundleItem(item, {
      hardLimits: options.hardLimits, semantic: false
    }));
    const raw = rawObjectRef(item.get(3));
    if (raw.kind === 1) continue;
    const payload = item.get(4);
    checkTransient(payload.length);
    const decoded = knownSchema.observe(() => decodeMetadata(payload, {
      hardLimits: options.hardLimits,
      semantic: false,
      maxWorkingBytes: maxMemoryBytes - retainedMemory - payload.length
    }));
    if (decoded && decoded.kind !== raw.kind) knownSchema.observe(() => fail(
      'OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' }
    ));
  }
  for (let ordinal = 0; ordinal < logicalCount; ordinal++) {
    guard.time();
    const item = values[1 + objectCount + ordinal];
    knownSchema.observe(() => validateBundleItem(item, {
      hardLimits: options.hardLimits, semantic: false
    }));
    knownSchema.observe(() => validateLogicalRecord(item.get(4), {
      hardLimits: options.hardLimits, semantic: false
    }));
  }
  for (let ordinal = 0; ordinal < rootCount; ordinal++) {
    guard.time();
    knownSchema.observe(() => validateBundleItem(values[1 + objectCount + logicalCount + ordinal], {
      hardLimits: options.hardLimits, semantic: false
    }));
  }
  knownSchema.throwSelected();

  const names = options.registry?.kindNames ?? KIND_NAMES;
  const objects = new Map();
  const objectsByDigest = new Map();
  let previousObject;
  for (let ordinal = 0; ordinal < objectCount; ordinal++) {
    guard.time();
    const item = values[1 + ordinal];
    validateBundleItem(item, {
      hardLimits: options.hardLimits, semantic: false
    });
    if (uint(item.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const ref = asRef(item.get(3), names);
    const sortKey = encodeCanonical(item.get(3));
    if (previousObject && compareBytes(previousObject, sortKey) >= 0) {
      const code = compareBytes(previousObject, sortKey) === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID';
      fail(code, { layer: 1 });
    }
    previousObject = sortKey;
    const key = refKey(ref);
    if (objects.has(key)) fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1 });
    const payload = item.get(4);
    verifyObjectId(ref, payload, ref.kind === 1
      ? { maxChunkBytes: configuredHardLimit('chunk-payload-bytes', options.hardLimits?.['chunk-payload-bytes']) }
      : { maxMetadataBytes: configuredHardLimit('metadata-payload-bytes', options.hardLimits?.['metadata-payload-bytes']) });
    let decoded;
    if (ref.kind !== 1) {
      checkTransient(payload.length);
      const remaining = maxMemoryBytes - retainedMemory - payload.length;
      decoded = decodeMetadata(payload, {
        hardLimits: options.hardLimits,
        semantic: false,
        maxWorkingBytes: remaining
      });
      if (decoded.kind !== ref.kind) {
        fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
      }
      const valueBytes = conservativeValueBytes(decoded.value, maxMemoryBytes - retainedMemory);
      retain(valueBytes);
    }
    retain(384 + key.length * 2);
    const object = { ref, payload, value: decoded?.value };
    objects.set(key, object);
    const rawDigestKey = toHex(ref.digest);
    if (!objectsByDigest.has(rawDigestKey)) {
      retain(160 + rawDigestKey.length * 2);
      objectsByDigest.set(rawDigestKey, object);
    }
  }

  const logicalRecords = new Map();
  let previousLogical;
  for (let ordinal = 0; ordinal < logicalCount; ordinal++) {
    guard.time();
    const item = values[1 + objectCount + ordinal];
    if (uint(item.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const identity = Digest.fromMap(item.get(3));
    const record = item.get(4);
    const result = validateLogicalRecord(record, {
      hardLimits: options.hardLimits, semantic: false
    });
    const sortKey = [Uint8Array.of(result.type >>> 8, result.type & 255), identity.bytes];
    if (previousLogical && compareTuple(previousLogical, sortKey) >= 0) {
      const code = compareTuple(previousLogical, sortKey) === 0 ? 'BUNDLE_DUPLICATE_IDENTITY' : 'BUNDLE_SEQUENCE_INVALID';
      fail(code, { layer: 1 });
    }
    previousLogical = sortKey;
    const key = digestKey(identity);
    if (logicalRecords.has(key)) fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1 });
    retain(320 + key.length * 2);
    logicalRecords.set(key, { identity, type: result.type, value: record });
  }

  const roots = [];
  const rootIdentities = new Set();
  const objectRoots = [];
  const logicalRootKeys = new Set();
  let previousRoot;
  for (let ordinal = 0; ordinal < rootCount; ordinal++) {
    guard.time();
    const item = values[1 + objectCount + logicalCount + ordinal];
    validateBundleItem(item, {
      hardLimits: options.hardLimits, semantic: false
    });
    if (uint(item.get(2)) !== BigInt(ordinal)) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    const rootKind = Number(item.get(3));
    const identity = rootKind === 1 ? asRef(item.get(4), names) : Digest.fromMap(item.get(4));
    const role = ProfileRef.fromMap(item.get(5));
    const sortKey = [Uint8Array.of(rootKind), encodeCanonical(item.get(4)), encodeCanonical(item.get(5))];
    if (previousRoot && compareTuple(previousRoot, sortKey) >= 0) fail('BUNDLE_SEQUENCE_INVALID', { layer: 1 });
    previousRoot = sortKey;
    const identityKey = rootKind === 1 ? `o:${refKey(identity)}` : `l:${digestKey(identity)}`;
    if (rootIdentities.has(identityKey)) fail('BUNDLE_DUPLICATE_IDENTITY', { layer: 1 });
    rootIdentities.add(identityKey);
    retain(320 + identityKey.length * 2);
    const root = { kind: rootKind, identity, role };
    roots.push(root);
    if (rootKind === 1) objectRoots.push(root);
    else logicalRootKeys.add(digestKey(identity));
  }

  validateBundleItem(trailer, {
    hardLimits: options.hardLimits, semantic: false
  });

  let traversalEdges = 0;
  for (const object of objects.values()) {
    guard.time();
    if (object.value) for (const _reference of objectReferences(object.ref.kind, object.value)) {
      traversalEdges++;
      guard.time();
    }
  }
  for (const record of logicalRecords.values()) {
    guard.time();
    for (const _reference of logicalRecordReferences(record.type, record.value)) {
      traversalEdges++;
      guard.time();
    }
  }
  if (traversalEdges > limits.traversalEdges) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (BigInt(traversalEdges) > declaredEdges) {
    fail('BUNDLE_BUDGET_EXCEEDED', { layer: 1, stage: 'declared-accounting' });
  }

  if (objects.size > 0 && objectRoots.length === 0) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  if (logicalRootKeys.size !== logicalRecords.size) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  for (const identity of logicalRootKeys) if (!logicalRecords.has(identity)) {
    fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  for (const identity of logicalRecords.keys()) {
    guard.time();
    if (!logicalRootKeys.has(identity)) {
      fail('BUNDLE_ROOT_INVALID', { layer: 2, stage: 'closure-and-reference-resolution' });
    }
  }
  const reached = new Set();
  const traverse = seed => {
    const stack = [seed];
    checkTransient(128);
    while (stack.length > 0) {
      guard.time();
      const ref = stack.pop();
      const key = refKey(ref);
      if (reached.has(key)) continue;
      const object = objects.get(key);
      if (!object) {
        const sameDigest = objectsByDigest.get(toHex(ref.digest));
        if (sameDigest) fail('OBJECT_REFERENCE_KIND_MISMATCH', {
          layer: 2, stage: 'closure-and-reference-resolution'
        });
        fail('BUNDLE_CLOSURE_MISSING', { layer: 2 });
      }
      retain(160 + key.length * 2);
      reached.add(key);
      if (object.value) for (const child of objectReferences(object.ref.kind, object.value)) {
        checkTransient((stack.length + 1) * 128);
        stack.push(child);
      }
    }
  };
  for (const root of objectRoots) traverse(root.identity);
  for (const record of logicalRecords.values()) {
    for (const ref of logicalRecordReferences(record.type, record.value)) traverse(ref);
  }
  if (reached.size !== objects.size) fail('BUNDLE_CLOSURE_EXTRA', { layer: 2 });

  // Registry lifecycle/policy is the final stage. Re-run already proven
  // schemas one at a time and retain only the catalogue-best failure.
  if (options.registry) {
    const registrySemantics = deferredStageCollector(3, 'registry-semantics');
    for (const item of values) registrySemantics.observe(() => validateBundleItem(item, {
      registry: options.registry, hardLimits: options.hardLimits, operation
    }));
    for (const object of objects.values()) {
      if (object.ref.kind === 1) {
        registrySemantics.observe(() => {
        registryAssignmentDecision(options.registry, 'object-kinds', 1, operation);
        registryAssignmentDecision(options.registry, 'hash-algorithms', 1, operation);
        });
      } else {
        registrySemantics.observe(() => validateKnownSchema(object.value, object.ref.kind, {
          registry: options.registry, hardLimits: options.hardLimits, operation
        }));
      }
    }
    for (const record of logicalRecords.values()) registrySemantics.observe(() =>
      validateLogicalRecord(record.value, {
        registry: options.registry, hardLimits: options.hardLimits, operation
      }));
    registrySemantics.throwSelected();
  }
  return Object.freeze({
    highestLayer: options.registry ? 3 : 2,
    bytes: input.length,
    items: values.length,
    objectCount,
    logicalRecordCount: logicalCount,
    rootCount,
    traversalEdges,
    indexEntries,
    transcriptDigest: toHex(transcript.bytes)
  });
}
