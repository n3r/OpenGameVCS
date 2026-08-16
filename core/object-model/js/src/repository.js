import { createHash } from 'node:crypto';
import { iterateObjectReferences } from './bundle.js';
import { decodeMetadata, scanMetadata, validateKnownSchema } from './schema.js';
import { encodeCanonical } from './cbor.js';
import { OgvcsError, compareErrorPrecedence, fail } from './errors.js';
import { configuredHardLimit, enforceHardLimit, hardLimitMaximum } from './hard-limits.js';
import { hashConflictPreimage, hashOpaqueObject, verifyObjectId } from './hash.js';
import { profileDecision, registryAssignmentDecision } from './registry.js';
import { FileId, ObjectRef, ProfileRef, equalBytes } from './types.js';

const IMPORT_DOMAIN = Buffer.from('OpenGameVCS import mapping\0', 'ascii');
const MAX_UINT64 = 0xffff_ffff_ffff_ffffn;
export const REPOSITORY_VALIDATION_LIMITS = Object.freeze({
  maxObjects: 100_000,
  maxBytes: 134_217_728,
  maxChunkBytes: hardLimitMaximum('chunk-payload-bytes'),
  maxEdges: 1_000_000,
  maxMemoryBytes: 1_073_741_824,
  maxScratchBytes: 1_073_741_824,
  maxTimeMs: 600_000
});

function schemaFail() { fail('SCHEMA_FIELD_INVALID', { layer: 2 }); }
let repositoryStageCollector;
function semanticFail(code) {
  if (repositoryStageCollector) {
    repositoryStageCollector.push(new OgvcsError(code, { layer: 3 }));
    return false;
  }
  fail(code, { layer: 3 });
}
function collectRepositoryStage(callback) {
  if (repositoryStageCollector) return callback();
  const failures = [];
  repositoryStageCollector = failures;
  let result;
  try { result = callback(); }
  finally { repositoryStageCollector = undefined; }
  if (failures.length > 0) {
    failures.sort(compareErrorPrecedence);
    throw failures[0];
  }
  return result;
}
function asMap(value) { if (!(value instanceof Map)) schemaFail(); return value; }
function asArray(value) { if (!Array.isArray(value)) schemaFail(); return value; }
function asUint(value, max = MAX_UINT64) {
  if ((typeof value !== 'number' || !Number.isSafeInteger(value)) && typeof value !== 'bigint') schemaFail();
  const result = BigInt(value); if (result < 0n || result > max) schemaFail(); return result;
}
function hex(value) { return Buffer.from(value).toString('hex'); }
function cloneBytes(value) { return value instanceof Uint8Array ? value.slice() : value; }
function cloneValue(value) {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value instanceof Map) return new Map([...value].map(([key, item]) => [cloneValue(key), cloneValue(item)]));
  return value;
}
function cloneResolved(value) {
  return Object.freeze({
    reference: value.reference,
    payload: value.payload.slice(),
    value: cloneValue(value.value)
  });
}
function sameValue(left, right) { return equalBytes(encodeCanonical(left), encodeCanonical(right)); }
function ref(value, expectedKind) {
  const result = value instanceof ObjectRef ? value : typeof value === 'string' ? ObjectRef.parse(value) : ObjectRef.fromMap(value);
  if (expectedKind !== undefined && result.kind !== expectedKind) {
    fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'closure-and-reference-resolution' });
  }
  return result;
}
function refKey(value) { return ref(value).toString(); }
function sameRef(left, right) { return refKey(left) === refKey(right); }
function fileId(value) {
  if (value instanceof FileId) return value;
  if (typeof value === 'string') return FileId.parse(value.startsWith('fid:') ? value : `fid:${value}`);
  return new FileId(value);
}
function fileKey(value) { return fileId(value).toString(); }
function pathKey(value) { return hex(encodeCanonical(value)); }
function pathParts(value) { return asArray(value).map(item => item); }
function parentParts(value) { const parts = pathParts(value); return parts.slice(0, -1); }
function basename(value) { const parts = pathParts(value); return parts[parts.length - 1]; }
function startsWithPath(path, prefix) {
  return prefix.length <= path.length && prefix.every((part, index) => part === path[index]);
}
function validateComposedPath(path, hardLimits = {}) {
  if (path.length < 1) semanticFail('PATH_CORE_INVALID');
  enforceHardLimit(undefined, 'path-segments', path.length, {
    maximum: hardLimits['path-segments'], code: 'PATH_CORE_INVALID', layer: 3
  });
  let joinedBytes = path.length - 1;
  for (const segment of path) {
    if (typeof segment !== 'string' || segment.normalize('NFC') !== segment ||
        segment === '.' || segment === '..' || segment.includes('/') || segment.includes('\0')) {
      semanticFail('PATH_CORE_INVALID');
    }
    const bytes = Buffer.byteLength(segment, 'utf8');
    if (bytes < 1) semanticFail('PATH_CORE_INVALID');
    enforceHardLimit(undefined, 'path-segment-bytes', bytes, {
      maximum: hardLimits['path-segment-bytes'], code: 'PATH_CORE_INVALID', layer: 3
    });
    joinedBytes += bytes;
    enforceHardLimit(undefined, 'path-bytes', joinedBytes, {
      maximum: hardLimits['path-bytes'], code: 'PATH_CORE_INVALID', layer: 3
    });
  }
}
function compareText(left, right) { return Buffer.compare(Buffer.from(left), Buffer.from(right)); }
function profileText(value) { return (value instanceof ProfileRef ? value : ProfileRef.fromMap(value)).toString(); }
function groupKey(group) { return hex(asMap(group).get(0)); }
function stateFileKey(state) { return fileKey(asMap(state).get(2)); }
function statePath(state) { return pathParts(asMap(state).get(0)); }
function statePathKey(state) { return pathKey(asMap(state).get(0)); }
function conflictIdKey(value) { return hex(value); }
function decodeHex(value, bytes) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) schemaFail();
  return Uint8Array.from(value.match(/../g), item => Number.parseInt(item, 16));
}

function configuredLimit(value, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 0) schemaFail();
  return value;
}

function makeGuard(options = {}) {
  const start = (options.now ?? Date.now)();
  const maxTimeMs = configuredLimit(options.maxTimeMs, REPOSITORY_VALIDATION_LIMITS.maxTimeMs);
  const maxObjects = configuredLimit(options.maxObjects, REPOSITORY_VALIDATION_LIMITS.maxObjects);
  const maxBytes = configuredLimit(options.maxBytes, REPOSITORY_VALIDATION_LIMITS.maxBytes);
  const maxEdges = configuredLimit(options.maxEdges, REPOSITORY_VALIDATION_LIMITS.maxEdges);
  const maxMemoryBytes = configuredLimit(options.maxMemoryBytes, REPOSITORY_VALIDATION_LIMITS.maxMemoryBytes);
  const maxScratchBytes = configuredLimit(options.maxScratchBytes, REPOSITORY_VALIDATION_LIMITS.maxScratchBytes);
  let objects = 0; let bytes = 0; let edges = 0; let retainedBytes = 0;
  const check = () => {
    if ((options.now ?? Date.now)() - start > maxTimeMs) fail('LIMIT_TIME', { layer: 1 });
    const memory = options.memoryBytes?.(); if (memory !== undefined && memory > maxMemoryBytes) fail('LIMIT_MEMORY', { layer: 1 });
    const scratch = options.scratchBytes?.(); if (scratch !== undefined && scratch > maxScratchBytes) fail('LIMIT_SCRATCH', { layer: 1 });
  };
  return Object.freeze({
    object(length = 0, isChunk = false) {
      objects++;
      bytes += length;
      const estimate = length * (isChunk ? 4 : 16) + 512;
      if (!Number.isSafeInteger(estimate)) fail('LIMIT_MEMORY', { layer: 1 });
      retainedBytes += estimate;
      if (objects > maxObjects) fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
      if (bytes > maxBytes) fail('LIMIT_MEMORY', { layer: 1 });
      if (retainedBytes > maxMemoryBytes) fail('LIMIT_MEMORY', { layer: 1 });
      check();
    },
    edge() {
      edges++;
      if (edges > maxEdges) fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
      check();
    },
    reserve(bytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxMemoryBytes - retainedBytes) {
        fail('LIMIT_MEMORY', { layer: 1 });
      }
      retainedBytes += bytes;
      check();
    },
    release(bytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > retainedBytes) schemaFail();
      retainedBytes -= bytes;
    },
    transient(bytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxMemoryBytes - retainedBytes) {
        fail('LIMIT_MEMORY', { layer: 1 });
      }
      check();
    },
    remainingMemory() { return maxMemoryBytes - retainedBytes; },
    check,
    summary() { return Object.freeze({ objects, bytes, edges, retainedBytes }); }
  });
}

function collectLookupFailure(failures, callback) {
  try { return callback(); }
  catch (error) {
    if (!(error instanceof OgvcsError) || error.errorClass === 'resource') throw error;
    failures.push(error);
    return undefined;
  }
}

function throwSelectedLookupFailure(failures) {
  if (failures.length === 0) return;
  failures.sort(compareErrorPrecedence);
  throw failures[0];
}

/** Pure identity/schema lookup. This is bounded by caller hooks, not yet a streaming graph store. */
export class RepositoryObjectLookup {
  #entries = new Map();
  #options;
  #guard;

  constructor(entries = [], options = {}) {
    this.#options = options;
    this.#guard = makeGuard(options);
    const iterable = entries instanceof Map ? entries.entries() : entries;
    for (const entry of iterable) {
      const [identity, payload] = Array.isArray(entry) ? entry : [entry.reference ?? entry.ref, entry.payload];
      const parsed = ref(identity); const key = parsed.toString();
      if (!(payload instanceof Uint8Array)) schemaFail();
      const limitName = parsed.kind === 1 ? 'chunk-payload-bytes' : 'metadata-payload-bytes';
      const namedMaximum = configuredHardLimit(limitName, options.hardLimits?.[limitName]);
      const maximum = configuredHardLimit(limitName,
        parsed.kind === 1 ? options.maxChunkBytes ?? namedMaximum : namedMaximum);
      enforceHardLimit(undefined, limitName, payload.length, { maximum, layer: 1 });
      // Charge and checkpoint every supplied entry before duplicate coalescing.
      // Otherwise an unbounded iterable of the same valid pair bypasses both
      // the receiver count and elapsed-time budgets.
      this.#guard.object(payload.length, parsed.kind === 1);
      if (this.#entries.has(key)) {
        if (!equalBytes(this.#entries.get(key).payload, payload)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
        continue;
      }
      this.#entries.set(key, Object.freeze({ reference: parsed, payload: payload.slice() }));
    }
  }

  get size() { return this.#entries.size; }
  get guardSummary() { return this.#guard.summary(); }
  get registry() { return this.#options.registry; }
  get mode() { return this.#options.mode ?? 'conformance'; }
  get hardLimits() { return this.#options.hardLimits ?? {}; }
  checkpoint() { this.#guard.check(); }
  reserveDerived(bytes) { this.#guard.reserve(bytes); }
  releaseDerived(bytes) { this.#guard.release(bytes); }

  #metadataWorkingBytes(payloadBytes, { returnedClone = false } = {}) {
    // scanMetadata retains one payload copy in addition to its decoded graph.
    // resolve also returns a payload copy and a deep copy of that graph. Bind
    // the decoder to the exact remaining operation budget before any of those
    // allocations instead of inferring heap cost from compact wire length.
    const payloadCopies = returnedClone ? 2 : 1;
    const fixed = payloadBytes * payloadCopies + 1_024;
    if (!Number.isSafeInteger(fixed)) fail('LIMIT_MEMORY', { layer: 1 });
    const remaining = this.#guard.remainingMemory();
    if (fixed > remaining) fail('LIMIT_MEMORY', { layer: 1 });
    const decodedCopies = returnedClone ? 2 : 1;
    const working = Math.floor((remaining - fixed) / decodedCopies);
    if (working < 1) fail('LIMIT_MEMORY', { layer: 1 });
    return working;
  }

  #scan(entry, options = {}) {
    return scanMetadata(entry.payload, {
      registry: this.#options.registry,
      hardLimits: this.#options.hardLimits,
      computeId: false,
      maxWorkingBytes: this.#metadataWorkingBytes(entry.payload.length, options)
    });
  }

  resolve(reference, expectedKind) {
    this.#guard.check();
    const parsed = ref(reference, expectedKind); const key = parsed.toString();
    const entry = this.#entries.get(key); if (!entry) fail('OBJECT_REFERENCE_MISSING', { layer: 2 });
    if (parsed.kind === 1) {
      const namedMaximum = configuredHardLimit(
        'chunk-payload-bytes', this.#options.hardLimits?.['chunk-payload-bytes']
      );
      const configuredChunkLimit = configuredHardLimit(
        'chunk-payload-bytes', this.#options.maxChunkBytes ?? namedMaximum
      );
      enforceHardLimit(undefined, 'chunk-payload-bytes', entry.payload.length,
        { maximum: configuredChunkLimit, layer: 1 });
    }
    verifyObjectId(parsed, entry.payload, parsed.kind === 1
      ? { maxChunkBytes: configuredHardLimit(
        'chunk-payload-bytes', this.#options.maxChunkBytes ?? configuredHardLimit(
          'chunk-payload-bytes', this.#options.hardLimits?.['chunk-payload-bytes']
        )
      ) }
      : { maxMetadataBytes: configuredHardLimit(
        'metadata-payload-bytes', this.#options.hardLimits?.['metadata-payload-bytes']
      ) });
    if (this.#options.registry) {
      const operation = this.#options.mode === 'production' ? 'production-write' : 'conformance';
      registryAssignmentDecision(this.#options.registry, 'object-kinds', parsed.kind, operation);
      registryAssignmentDecision(this.#options.registry, 'hash-algorithms', 1, operation);
    }
    if (parsed.kind === 1) {
      const transientBytes = entry.payload.length * 2 + 512;
      this.#guard.transient(transientBytes);
      return Object.freeze({
        reference: parsed,
        payload: entry.payload.slice(),
        value: entry.payload.slice()
      });
    }
    {
      const decoded = decodeMetadata(entry.payload, {
        registry: this.#options.registry,
        hardLimits: this.#options.hardLimits,
        semantic: this.#options.semanticProfiles !== false,
        operation: this.#options.mode === 'production' ? 'production-write' : 'conformance',
        maxWorkingBytes: this.#metadataWorkingBytes(entry.payload.length, { returnedClone: true })
      });
      if (decoded.kind !== parsed.kind) {
        fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
      }
      return cloneResolved(Object.freeze({ reference: parsed, payload: entry.payload, value: decoded.value }));
    }
  }

  validateAll() {
    const entries = [...this.#entries.values()].sort((left, right) => Buffer.compare(encodeCanonical(left.reference.toMap()), encodeCanonical(right.reference.toMap())));
    const phaseOneFailures = [];

    // Phase 1 is whole-set framing and identity. A later corrupt identity must
    // never be hidden by an earlier object's layer-2 schema failure.
    for (const entry of entries) {
      this.#guard.check();
      const parsed = entry.reference;
      collectLookupFailure(phaseOneFailures, () => {
        if (parsed.kind === 1) {
          const maximum = configuredHardLimit(
            'chunk-payload-bytes', this.#options.maxChunkBytes ?? configuredHardLimit(
              'chunk-payload-bytes', this.#options.hardLimits?.['chunk-payload-bytes']
            )
          );
          verifyObjectId(parsed, entry.payload, { maxChunkBytes: maximum });
          return;
        }
        const maximum = configuredHardLimit(
          'metadata-payload-bytes', this.#options.hardLimits?.['metadata-payload-bytes']
        );
        const actual = hashOpaqueObject(parsed.kind, entry.payload, { maxBytes: maximum });
        if (!equalBytes(parsed.digest, actual.bytes)) fail('OBJECT_ID_MISMATCH', { layer: 1 });
      });
      if (parsed.kind !== 1) {
        // Framing is a whole-set phase, but its decoded graphs and payload
        // copies are item-local. Discard each scan before advancing so compact
        // containers cannot accumulate outside the configured memory bound.
        collectLookupFailure(phaseOneFailures, () => this.#scan(entry));
      }
    }
    throwSelectedLookupFailure(phaseOneFailures);

    // Phase 2 validates every independently decoded schema before selecting a
    // failure by the frozen catalogue. Resource failures remain terminal.
    const phaseTwoFailures = [];
    for (const entry of entries) {
      if (entry.reference.kind === 1) continue;
      const scan = collectLookupFailure(phaseTwoFailures, () => this.#scan(entry));
      if (!scan) continue;
      collectLookupFailure(phaseTwoFailures, () => validateKnownSchema(scan.value, scan.kind, {
        registry: this.#options.registry,
        hardLimits: this.#options.hardLimits,
        semantic: false,
        operation: this.#options.mode === 'production' ? 'production-write' : 'conformance'
      }));
      if (scan.kind !== entry.reference.kind) {
        phaseTwoFailures.push(new OgvcsError('OBJECT_REFERENCE_KIND_MISMATCH', {
          layer: 2, stage: 'known-schema'
        }));
      }
    }
    throwSelectedLookupFailure(phaseTwoFailures);

    // Phase 3 applies operation-aware registry semantics only after the entire
    // lookup has passed framing, identity, and known-schema validation. It is
    // also a whole-set phase so catalogue order is independent of ref sorting.
    const phaseThreeFailures = [];
    for (const entry of entries) {
      const parsed = entry.reference;
      if (this.#options.registry) {
        const operation = this.#options.mode === 'production' ? 'production-write' : 'conformance';
        collectLookupFailure(phaseThreeFailures, () =>
          registryAssignmentDecision(this.#options.registry, 'object-kinds', parsed.kind, operation));
        collectLookupFailure(phaseThreeFailures, () =>
          registryAssignmentDecision(this.#options.registry, 'hash-algorithms', 1, operation));
      }
      if (parsed.kind !== 1) {
        const scan = collectLookupFailure(phaseThreeFailures, () => this.#scan(entry));
        if (!scan) continue;
        collectLookupFailure(phaseThreeFailures, () => validateKnownSchema(scan.value, parsed.kind, {
          registry: this.#options.registry,
          hardLimits: this.#options.hardLimits,
          semantic: this.#options.semanticProfiles !== false,
          operation: this.#options.mode === 'production' ? 'production-write' : 'conformance'
        }));
      }
    }
    throwSelectedLookupFailure(phaseThreeFailures);
    return this;
  }
  edge(reference, expectedKind) { this.#guard.edge(); return this.resolve(reference, expectedKind); }
}

export function createRepositoryObjectLookup(entries, options) { return new RepositoryObjectLookup(entries, options); }

export function verifyManifest(reference, lookup) {
  const object = lookup.resolve(reference, 2); const manifest = object.value;
  const hardLimits = lookup.hardLimits ?? {};
  const logicalMaximum = configuredHardLimit('logical-file-bytes', hardLimits['logical-file-bytes']);
  const chunkMaximum = configuredHardLimit('chunk-payload-bytes', hardLimits['chunk-payload-bytes']);
  const partMaximum = configuredHardLimit('manifest-chunks', hardLimits['manifest-chunks']);
  const declared = asUint(manifest.get(16));
  enforceHardLimit(undefined, 'logical-file-bytes', declared,
    { maximum: logicalMaximum, code: 'LIMIT_LOGICAL_BYTES', layer: 2 });
  const parts = asArray(manifest.get(19));
  enforceHardLimit(undefined, 'manifest-chunks', parts.length,
    { maximum: partMaximum, code: 'LIMIT_COUNT', layer: 2 });
  let sum = 0n;
  // Resolve the complete reference set before content semantics so a missing
  // later chunk remains a layer-two failure. Do not retain returned payloads:
  // a manifest can legally repeat the maximum-size chunk over a million times.
  for (const part of parts) {
    lookup.checkpoint?.();
    const map = asMap(part); const length = asUint(map.get(1));
    enforceHardLimit(undefined, 'chunk-payload-bytes', length,
      { maximum: chunkMaximum, code: 'MANIFEST_CHUNK_LENGTH_INVALID', layer: 2 });
    sum += length;
    enforceHardLimit(undefined, 'logical-file-bytes', sum,
      { maximum: logicalMaximum, code: 'LIMIT_LOGICAL_BYTES', layer: 2 });
    lookup.edge(map.get(0), 1);
  }
  const digest = createHash('sha256');
  // Resolve again and consume one payload at a time. This second pass does not
  // count another graph edge; the occurrence was charged in the first pass.
  for (const part of parts) {
    lookup.checkpoint?.();
    const map = asMap(part); const length = asUint(map.get(1));
    const chunk = lookup.resolve(map.get(0), 1).payload;
    if (length === 0n) semanticFail('MANIFEST_CHUNK_LENGTH_INVALID');
    if (BigInt(chunk.length) !== length) semanticFail('MANIFEST_CHUNK_LENGTH_INVALID');
    digest.update(chunk);
  }
  if (sum !== declared || (declared === 0n && parts.length !== 0)) {
    fail('MANIFEST_LENGTH_MISMATCH', { layer: 2 });
  }
  const expected = asMap(manifest.get(17)).get(1);
  if (!equalBytes(new Uint8Array(digest.digest()), expected)) semanticFail('MANIFEST_FILE_DIGEST_MISMATCH');
  return Object.freeze({ logicalLength: declared, chunks: parts.length });
}

function descriptorProfiles(descriptor) {
  return {
    path: descriptor.has(17) ? profileText(descriptor.get(17)) : undefined,
    content: new Set(asArray(descriptor.get(18)).map(profileText)),
    groups: new Set(asArray(descriptor.get(19)).map(profileText)),
    chunks: new Set(descriptor.has(20) ? asArray(descriptor.get(20)).map(profileText) : [])
  };
}

function entryStateFromTree(path, entry) {
  const state = new Map([[0, path], [1, entry.get(1)], [2, cloneBytes(entry.get(2))], [3, entry.get(3)]]);
  if (entry.get(1) !== 1) state.set(4, cloneValue(entry.get(4)));
  state.set(5, entry.get(5)); state.set(6, cloneValue(entry.get(6))); return state;
}

function derivedBuildReservation(lookup, options = {}) {
  const shared = typeof lookup.reserveDerived === 'function' &&
    typeof lookup.releaseDerived === 'function';
  const local = shared ? undefined : makeGuard(options);
  let retained = 0;
  return Object.freeze({
    reserve(bytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > Number.MAX_SAFE_INTEGER - retained) {
        fail('LIMIT_MEMORY', { layer: 1 });
      }
      if (local) local.reserve(bytes); else lookup.reserveDerived(bytes);
      retained += bytes;
    },
    release() {
      if (retained === 0) return;
      if (local) local.release(retained); else lookup.releaseDerived(retained);
      retained = 0;
    }
  });
}

function derivedValueBytes(value, fixed = 256) {
  const encoded = encodeCanonical(value);
  const bytes = encoded.length * 4 + fixed;
  if (!Number.isSafeInteger(bytes)) fail('LIMIT_MEMORY', { layer: 1 });
  return bytes;
}

export function expandTree(rootReference, lookup, descriptorReference, options = {}) {
  const descriptorRef = ref(descriptorReference, 6); const descriptor = lookup.resolve(descriptorRef, 6).value;
  const hardLimits = options.hardLimits ?? lookup.hardLimits ?? {};
  const treeMaximum = configuredHardLimit('tree-entries', hardLimits['tree-entries']);
  const logicalMaximum = configuredHardLimit('logical-file-bytes', hardLimits['logical-file-bytes']);
  const reservation = derivedBuildReservation(lookup, options);
  reservation.reserve(512);
  const allowed = descriptorProfiles(descriptor); const entries = new Map(); const fileIds = new Map();
  const visiting = new Set();
  let pathProfileChecked = false;
  const validatePathProfile = path => {
    if (allowed.path === undefined) return;
    if (!pathProfileChecked && lookup.registry) {
      const operation = lookup.mode === 'production' ? 'production-write' : 'conformance';
      const decision = profileDecision(lookup.registry, allowed.path, operation);
      if (decision.family !== 'path') schemaFail();
      pathProfileChecked = true;
    }
    if (allowed.path === 'path.test/opaque@1') return;
    if (allowed.path === 'path.test/reject-reserved@1') {
      if (path.includes('reserved')) semanticFail('PATH_PROFILE_INVALID');
      return;
    }
    fail('PROFILE_UNKNOWN', { layer: 3 });
  };
  const walk = (treeReference, prefix) => {
    const key = refKey(treeReference); if (visiting.has(key)) semanticFail('PROVENANCE_CYCLE');
    reservation.reserve(256 + key.length * 2);
    visiting.add(key); const tree = lookup.edge(treeReference, 3).value;
    if (!sameRef(tree.get(16), descriptorRef)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
    const treeEntries = asArray(tree.get(17));
    enforceHardLimit(undefined, 'tree-entries', treeEntries.length,
      { maximum: treeMaximum, code: 'LIMIT_COUNT', layer: 2 });
    for (const raw of treeEntries) {
      lookup.checkpoint?.();
      const entry = asMap(raw); const path = [...prefix, entry.get(0)];
      validateComposedPath(path, hardLimits); validatePathProfile(path);
      reservation.reserve(derivedValueBytes([path, entry], 640));
      const state = entryStateFromTree(path, entry);
      const pkey = pathKey(path); if (entries.has(pkey)) semanticFail('CHANGESET_TRANSITION_INVALID');
      const fkey = stateFileKey(state); if (fileIds.has(fkey)) semanticFail('FILEID_DUPLICATE_IN_TREE');
      fileIds.set(fkey, pkey); entries.set(pkey, state);
      if (!allowed.content.has(profileText(entry.get(6)))) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
      if (entry.get(1) === 1) walk(entry.get(4), path);
      else {
        const manifest = lookup.edge(entry.get(4), 2).value;
        if (!allowed.chunks.has(profileText(manifest.get(18)))) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
        let checked;
        if (options.verifyContent === false) {
          const logicalLength = asUint(manifest.get(16));
          enforceHardLimit(undefined, 'logical-file-bytes', logicalLength,
            { maximum: logicalMaximum, code: 'LIMIT_LOGICAL_BYTES', layer: 2 });
          checked = { logicalLength };
        } else checked = verifyManifest(entry.get(4), lookup);
        const entryLength = asUint(entry.get(5));
        enforceHardLimit(undefined, 'logical-file-bytes', entryLength,
          { maximum: logicalMaximum, code: 'LIMIT_LOGICAL_BYTES', layer: 2 });
        if (checked.logicalLength !== entryLength) semanticFail('TREE_ENTRY_TARGET_INVALID');
      }
    }
    visiting.delete(key);
  };
  try {
    walk(rootReference, []);
    return Object.freeze({ descriptor: descriptorRef, descriptorValue: descriptor, entries, fileIds });
  } finally {
    // Successful return transfers the derived maps to the caller. Repository
    // replay reserves retained state separately; direct callers still receive
    // a fully bounded construction without double-counting the returned value.
    reservation.release();
  }
}

function emptyGroups() { return new Map(); }
function groupsFromSet(reference, lookup, descriptorReference) {
  if (!reference) return emptyGroups();
  const reservation = derivedBuildReservation(lookup);
  reservation.reserve(256);
  try {
    const set = lookup.edge(reference, 5).value;
    if (!sameRef(set.get(16), descriptorReference)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
    const descriptor = lookup.resolve(descriptorReference, 6).value;
    const allowed = descriptorProfiles(descriptor).groups;
    const groups = asArray(set.get(17));
    enforceHardLimit(undefined, 'asset-groups', groups.length, {
      maximum: lookup.hardLimits?.['asset-groups'], code: 'LIMIT_COUNT', layer: 2
    });
    for (const group of groups) {
      lookup.checkpoint?.();
      enforceHardLimit(undefined, 'asset-group-members', asArray(group.get(3)).length, {
        maximum: lookup.hardLimits?.['asset-group-members'], code: 'LIMIT_COUNT', layer: 2
      });
      if (!allowed.has(profileText(group.get(1)))) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
      reservation.reserve(derivedValueBytes(group, 384));
    }
    return new Map(groups.map(group => [groupKey(group), cloneValue(group)]));
  } finally {
    reservation.release();
  }
}
function cloneState(state, checkpoint = () => {}) {
  const entries = new Map(); const groups = new Map();
  for (const [key, value] of state.entries) { checkpoint(); entries.set(key, cloneValue(value)); }
  for (const [key, value] of state.groups) { checkpoint(); groups.set(key, cloneValue(value)); }
  return { entries, groups };
}
function stateMemoryBytes(state, checkpoint = () => {}) {
  let bytes = 256;
  const add = value => {
    checkpoint();
    const encoded = encodeCanonical(value);
    const retained = encoded.length * 4 + 256;
    if (!Number.isSafeInteger(retained) || retained > Number.MAX_SAFE_INTEGER - bytes) {
      fail('LIMIT_MEMORY', { layer: 1 });
    }
    bytes += retained;
  };
  for (const value of state.entries.values()) add(value);
  for (const value of state.groups.values()) add(value);
  return bytes;
}
function replayWorkingMemoryBytes(changeSetReference, base, context) {
  const changeSet = context.lookup.resolve(changeSetReference, 4).value;
  const operations = asArray(changeSet.get(18));
  let bytes = 512 + (base.entries.size + base.groups.size) * 192;
  const add = value => {
    context.lookup.checkpoint?.();
    const encoded = encodeCanonical(value);
    const retained = encoded.length * 4 + 512;
    if (!Number.isSafeInteger(retained) || retained > Number.MAX_SAFE_INTEGER - bytes) {
      fail('LIMIT_MEMORY', { layer: 1 });
    }
    bytes += retained;
  };
  for (const operation of operations) {
    if (bytes > Number.MAX_SAFE_INTEGER - 384) fail('LIMIT_MEMORY', { layer: 1 });
    bytes += 384;
    // Every value that replay may clone or retain in allocation/restoration
    // evidence is reserved before cloneState or the first operation executes.
    for (const key of [3, 8, 11]) if (operation.has(key)) add(operation.get(key));
  }
  return bytes;
}
function reserveState(lookup, bytes) { lookup.reserveDerived?.(bytes); }
function releaseState(lookup, bytes) { lookup.releaseDerived?.(bytes); }
function getExact(entries, expected, code = 'CHANGESET_TRANSITION_INVALID') {
  const current = entries.get(statePathKey(expected)); if (!current || !sameValue(current, expected)) semanticFail(code); return current;
}
function requireAbsent(entries, state) { if (entries.has(statePathKey(state))) semanticFail('CHANGESET_TRANSITION_INVALID'); }
function requireParent(entries, state) {
  const parent = parentParts(state.get(0)); if (parent.length === 0) return;
  const value = entries.get(pathKey(parent)); if (!value || value.get(1) !== 1) semanticFail('CHANGESET_TRANSITION_INVALID');
}
function sameExcept(left, right, ignored) {
  const a = cloneValue(left); const b = cloneValue(right); for (const key of ignored) { a.delete(key); b.delete(key); } return sameValue(a, b);
}
function descendants(entries, prefix, checkpoint = () => {}) {
  const result = [];
  for (const state of entries.values()) {
    checkpoint(); const path = statePath(state);
    if (path.length > prefix.length && startsWithPath(path, prefix)) result.push(state);
  }
  return result;
}
function replacePrefix(entries, before, after, checkpoint = () => {}) {
  const affected = [entries.get(pathKey(before)), ...descendants(entries, before, checkpoint)].filter(Boolean);
  const oldKeys = new Set(affected.map(statePathKey));
  for (const state of affected) {
    checkpoint();
    const nextPath = [...after, ...statePath(state).slice(before.length)]; const key = pathKey(nextPath);
    if (entries.has(key) && !oldKeys.has(key)) semanticFail('CHANGESET_TRANSITION_INVALID');
  }
  for (const state of affected) entries.delete(statePathKey(state));
  for (const state of affected) { state.set(0, [...after, ...statePath(state).slice(before.length)]); entries.set(statePathKey(state), state); }
}

function snapshotObject(reference, lookup) { return lookup.edge(reference, 7).value; }
function isAncestor(ancestor, descendant, lookup, allowSelf = true) {
  const target = refKey(ancestor); const start = refKey(descendant); if (allowSelf && target === start) return true;
  const seen = new Set(); const stack = [descendant];
  while (stack.length) {
    lookup.checkpoint?.();
    const current = stack.pop(); const key = refKey(current); if (seen.has(key)) continue; seen.add(key);
    for (const parent of snapshotObject(current, lookup).get(17)) { if (refKey(parent) === target) return true; stack.push(parent); }
  }
  return false;
}

function stateAtSnapshot(snapshotReference, lookup, descriptorReference, options) {
  const snapshot = snapshotObject(snapshotReference, lookup); if (!sameRef(snapshot.get(16), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
  const tree = expandTree(snapshot.get(18), lookup, descriptorReference, options);
  return { entries: tree.entries, groups: groupsFromSet(snapshot.get(20), lookup, descriptorReference) };
}

function validateRestore(operation, after, baseSnapshot, lookup, descriptorReference, options) {
  const proof = operation.get(6); if (!sameRef(proof.get(0), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
  if (!baseSnapshot) semanticFail('FILEID_RESTORE_PROOF_INVALID');
  const source = proof.get(1); const sourcePath = proof.get(2); const deleted = proof.get(3);
  if (!isAncestor(source, deleted, lookup, false) || !isAncestor(deleted, baseSnapshot, lookup, true)) semanticFail('FILEID_RESTORE_PROOF_INVALID');
  const sourceState = stateAtSnapshot(source, lookup, descriptorReference, options).entries.get(pathKey(sourcePath));
  if (!sourceState || !sameValue(sourceState, after)) semanticFail('FILEID_RESTORE_PROOF_INVALID');
  const deleteSnapshot = snapshotObject(deleted, lookup);
  if (!sameRef(deleteSnapshot.get(16), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
  const changeSet = lookup.edge(deleteSnapshot.get(19), 4).value;
  const matching = changeSet.get(18).some(op => op.get(1) === 6 && sameValue(op.get(2), sourceState));
  if (!matching) semanticFail('FILEID_RESTORE_PROOF_INVALID');
}

function findConflict(conflictSet, id) { return conflictSet?.get(17).find(record => equalBytes(record.get(0), id)); }
function resolutionResult(record) {
  const resolution = record.get(6); if (resolution.get(0) === 0) return { unresolved: true };
  const choice = resolution.get(1); if (choice === 4) return { delete: true };
  return { side: resolution.get(2) };
}

function clearConflictSubject(state, record, checkpoint = () => {}) {
  const subject = record.get(2);
  if (subject[0] === 2) {
    state.groups.delete(hex(subject[1]));
    return;
  }
  const ids = new Set(subject[1].map(fileKey));
  const paths = new Set(subject[2].map(pathKey));
  const pathCollision = record.get(1) === 8;
  for (const [key, entry] of state.entries) {
    checkpoint();
    if (paths.has(key) || (!pathCollision && ids.has(stateFileKey(entry)))) state.entries.delete(key);
  }
}

function applyConflictResolution(state, record, operation, checkpoint = () => {}) {
  const result = resolutionResult(record);
  if (result.unresolved) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
  const subjectKind = operation.get(10);
  if (subjectKind !== record.get(2)[0]) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
  clearConflictSubject(state, record, checkpoint);
  if (result.delete) {
    if (operation.has(11)) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
    return;
  }
  const sideValue = result.side.get(subjectKind === 1 ? 1 : 2);
  if (!operation.has(11) || !sameValue(operation.get(11), sideValue)) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
  if (subjectKind === 1) state.entries.set(statePathKey(sideValue), cloneValue(sideValue));
  else state.groups.set(groupKey(sideValue), cloneValue(sideValue));
}

function preflightDeclaredTransitions(operations) {
  for (let sequence = 0; sequence < operations.length; sequence += 1) {
    const operation = operations[sequence];
    if (Number(operation.get(0)) !== sequence) {
      fail('CHANGESET_SEQUENCE_INVALID', { layer: 2 });
    }
    const code = operation.get(1);
    if (code === 2) {
      const before = operation.get(2); const after = operation.get(3);
      if (statePathKey(before) !== statePathKey(after) ||
          stateFileKey(before) !== stateFileKey(after) || sameValue(before, after)) {
        semanticFail('CHANGESET_TRANSITION_INVALID');
      }
    } else if (code === 3) {
      const after = operation.get(3); const source = operation.get(4);
      if (source.get(1) === 1 || stateFileKey(source) === stateFileKey(after) ||
          !sameExcept(source, after, [0, 2])) semanticFail('CHANGESET_TRANSITION_INVALID');
    } else if (code === 4 || code === 5) {
      const before = operation.get(2); const after = operation.get(3);
      const invalidRelationship = code === 4
        ? pathKey(parentParts(before.get(0))) === pathKey(parentParts(after.get(0))) ||
          basename(before.get(0)) !== basename(after.get(0))
        : pathKey(parentParts(before.get(0))) !== pathKey(parentParts(after.get(0))) ||
          basename(before.get(0)) === basename(after.get(0));
      if (!sameExcept(before, after, [0]) || invalidRelationship ||
          (before.get(1) === 1 && startsWithPath(statePath(after), statePath(before)))) {
        semanticFail('CHANGESET_TRANSITION_INVALID');
      }
    }
  }
}

export function replayChangeSet(changeSetReference, base, context) {
  const { lookup, descriptor } = context; const changeSetRef = ref(changeSetReference, 4); const changeSet = lookup.resolve(changeSetRef, 4).value;
  if (!sameRef(changeSet.get(16), descriptor)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
  const operations = asArray(changeSet.get(18));
  enforceHardLimit(undefined, 'change-set-operations', operations.length, {
    maximum: (context.hardLimits ?? lookup.hardLimits)?.['change-set-operations'],
    code: 'LIMIT_COUNT', layer: 2
  });
  preflightDeclaredTransitions(operations);
  const checkpoint = () => lookup.checkpoint?.();
  const state = cloneState(base, checkpoint); const allocations = []; const restorations = [];
  for (let sequence = 0; sequence < operations.length; sequence++) {
    checkpoint();
    const operation = operations[sequence];
    if (Number(operation.get(0)) !== sequence) fail('CHANGESET_SEQUENCE_INVALID', { layer: 2 });
    const code = operation.get(1);
    if (code === 1) {
      const after = operation.get(3); requireAbsent(state.entries, after); requireParent(state.entries, after); state.entries.set(statePathKey(after), cloneValue(after)); allocations.push({ operation, sequence, after, code });
    } else if (code === 2) {
      const before = operation.get(2); const after = operation.get(3); getExact(state.entries, before, 'FILEID_SOURCE_MISMATCH');
      if (statePathKey(before) !== statePathKey(after) || stateFileKey(before) !== stateFileKey(after) || sameValue(before, after)) semanticFail('CHANGESET_TRANSITION_INVALID');
      state.entries.set(statePathKey(after), cloneValue(after));
    } else if (code === 3) {
      const after = operation.get(3); const source = operation.get(4); getExact(state.entries, source, 'FILEID_SOURCE_MISMATCH'); requireAbsent(state.entries, after); requireParent(state.entries, after);
      if (source.get(1) === 1 || stateFileKey(source) === stateFileKey(after) || !sameExcept(source, after, [0, 2])) semanticFail('CHANGESET_TRANSITION_INVALID');
      state.entries.set(statePathKey(after), cloneValue(after)); allocations.push({ operation, sequence, after, code });
    } else if (code === 4 || code === 5) {
      const before = operation.get(2); const after = operation.get(3); getExact(state.entries, before, 'FILEID_SOURCE_MISMATCH'); requireAbsent(state.entries, after); requireParent(state.entries, after);
      if (!sameExcept(before, after, [0]) || (code === 4 ? pathKey(parentParts(before.get(0))) === pathKey(parentParts(after.get(0))) || basename(before.get(0)) !== basename(after.get(0)) : pathKey(parentParts(before.get(0))) !== pathKey(parentParts(after.get(0))) || basename(before.get(0)) === basename(after.get(0)))) semanticFail('CHANGESET_TRANSITION_INVALID');
      if (before.get(1) === 1 && startsWithPath(statePath(after), statePath(before))) semanticFail('CHANGESET_TRANSITION_INVALID');
      if (before.get(1) === 1) replacePrefix(state.entries, statePath(before), statePath(after), checkpoint);
      else { state.entries.delete(statePathKey(before)); state.entries.set(statePathKey(after), cloneValue(after)); }
    } else if (code === 6) {
      const before = operation.get(2); getExact(state.entries, before, 'FILEID_SOURCE_MISMATCH'); if (before.get(1) === 1 && descendants(state.entries, statePath(before), checkpoint).length) semanticFail('CHANGESET_TRANSITION_INVALID'); state.entries.delete(statePathKey(before));
    } else if (code === 7) {
      const after = operation.get(3);
      let duplicateFileId = false; for (const item of state.entries.values()) { checkpoint(); if (stateFileKey(item) === stateFileKey(after)) { duplicateFileId = true; break; } }
      if (state.entries.has(statePathKey(after)) || duplicateFileId) semanticFail('FILEID_RESTORE_PROOF_INVALID');
      requireParent(state.entries, after);
      validateRestore(operation, after, changeSet.get(17), lookup, descriptor, context);
      state.entries.set(statePathKey(after), cloneValue(after));
      restorations.push({ operation, sequence, after });
    } else if (code === 8) {
      const after = operation.get(8); const key = groupKey(after); if (state.groups.has(key)) semanticFail('CHANGESET_TRANSITION_INVALID'); state.groups.set(key, cloneValue(after));
    } else if (code === 9) {
      const before = operation.get(7); const after = operation.get(8); const key = groupKey(before); const current = state.groups.get(key); if (!current || !sameValue(current, before) || groupKey(after) !== key) semanticFail('CHANGESET_TRANSITION_INVALID'); state.groups.set(key, cloneValue(after));
    } else if (code === 10) {
      const before = operation.get(7); const key = groupKey(before); const current = state.groups.get(key); if (!current || !sameValue(current, before)) semanticFail('CHANGESET_TRANSITION_INVALID'); state.groups.delete(key);
    } else if (code === 11) {
      const record = findConflict(context.conflictSet, operation.get(9));
      if (!record) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
      applyConflictResolution(state, record, operation, checkpoint);
    } else semanticFail('CHANGESET_TRANSITION_INVALID');
  }
  const lifetimeEntries = new Map();
  for (const entry of base.entries?.values?.() ?? []) { checkpoint(); lifetimeEntries.set(stateFileKey(entry), entry); }
  for (const entry of state.entries.values()) { checkpoint(); lifetimeEntries.set(stateFileKey(entry), entry); }
  const lifetimeContext = {
    ...context,
    changeSetReference: changeSetRef,
    allocations,
    restorations,
    entries: lifetimeEntries
  };
  if (context.historicalReplay === true) validateHistoricalLifetimeAndImports(lifetimeContext);
  else validateLifetimeAndImports(lifetimeContext);
  return Object.freeze({ ...state, allocations, restorations });
}

function normalizeLifetime(value) {
  if (value instanceof Map) return {
    descriptor: ref(value.get(16), 6),
    fileId: fileKey(value.get(17)),
    origin: value.get(18),
    firstChangeSet: ref(value.get(19), 4),
    firstOperation: Number(asUint(value.get(20))),
    importMappingKey: value.has(21) ? hex(value.get(21)) : undefined
  };
  const origins = { 'native-create': 1, 'native-copy': 2, import: 3 };
  const mappingKey = value.importMappingKey === undefined ? undefined : hex(decodeHex(value.importMappingKey, 32));
  return {
    descriptor: value.descriptor === undefined ? undefined : ref(value.descriptor, 6),
    fileId: fileKey(value.fileId),
    origin: origins[value.origin] ?? value.origin,
    firstChangeSet: ref(value.firstChangeSet, 4),
    firstOperation: Number(asUint(value.firstOperation)),
    importMappingKey: mappingKey
  };
}
function normalizeImport(value) {
  if (value instanceof Map) return {
    descriptor: ref(value.get(16), 6),
    importer: profileText(value.get(17)),
    namespace: hex(value.get(18)),
    identity: hex(value.get(19)),
    fileId: fileKey(value.get(20)),
    state: value.get(21)
  };
  return {
    descriptor: value.descriptor === undefined ? undefined : ref(value.descriptor, 6),
    importer: profileText(ProfileRef.parse(value.importerProfile)),
    namespace: hex(decodeHex(value.sourceNamespaceDigest, 32)),
    identity: hex(decodeHex(value.sourceIdentityDigest, 32)),
    mappingKey: value.mappingKey === undefined ? undefined : hex(decodeHex(value.mappingKey, 32)),
    fileId: fileKey(value.fileId),
    state: typeof value.state === 'string' ? ({ reserved: 1, materialized: 2, published: 3 })[value.state] : value.state
  };
}
function importMappingKey(descriptor, mapping) {
  const profile = ProfileRef.parse(mapping.importer).toMap(); const namespace = decodeHex(mapping.namespace, 32); const identity = decodeHex(mapping.identity, 32);
  const payload = encodeCanonical([ref(descriptor, 6).toMap(), profile, namespace, identity]); const hash = createHash('sha256'); hash.update(IMPORT_DOMAIN); hash.update(Uint8Array.of(0, 1)); hash.update(payload); return hash.digest('hex');
}

function lifetimeOperation(record, context) {
  if (record.descriptor && !sameRef(record.descriptor, context.descriptor)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  if ((record.origin === 3) !== (record.importMappingKey !== undefined)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  if (![1, 2, 3].includes(record.origin)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  const changeSet = context.lookup?.resolve(record.firstChangeSet, 4).value;
  if (!changeSet || !sameRef(changeSet.get(16), context.descriptor)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  const operation = changeSet.get(18)[record.firstOperation];
  if (!operation || Number(operation.get(0)) !== record.firstOperation || ![1, 3].includes(operation.get(1))) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  const after = operation.get(3); const proof = operation.get(5);
  if (stateFileKey(after) !== record.fileId || !sameRef(proof.get(0), context.descriptor)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  const allocationKind = proof.get(1); const expectedOrigin = allocationKind === 2 ? 3 : operation.get(1) === 1 ? 1 : 2;
  if (record.origin !== expectedOrigin) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  const proofKey = proof.has(2) ? hex(proof.get(2)) : undefined;
  if (proofKey !== record.importMappingKey) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  return operation;
}

function validateLifetimeAndImportsInternal(context, { allowUnrelatedWorking = false } = {}) {
  const checkpoint = () => context.lookup?.checkpoint?.();
  const prior = new Map();
  for (const raw of context.lifetimeRecords ?? []) { checkpoint(); const record = normalizeLifetime(raw); if (prior.has(record.fileId)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID'); prior.set(record.fileId, record); }
  const mappings = new Map(); const mappingsByKey = new Map(); const mappedFiles = new Map();
  for (const raw of context.importMappings ?? []) {
    checkpoint();
    const mapping = normalizeImport(raw);
    if (mapping.descriptor && !sameRef(mapping.descriptor, context.descriptor)) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    if (![1, 2, 3].includes(mapping.state)) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    const key = importMappingKey(context.descriptor, mapping); if (mapping.mappingKey && mapping.mappingKey !== key) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    const tuple = `${mapping.importer}\0${mapping.namespace}\0${mapping.identity}`;
    const previous = mappings.get(tuple); if (previous) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    const owner = mappedFiles.get(mapping.fileId); if (owner && owner !== tuple) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    const normalized = { ...mapping, key, tuple };
    mappings.set(tuple, normalized); mappingsByKey.set(key, normalized); mappedFiles.set(mapping.fileId, tuple);
  }
  for (const mapping of mappings.values()) {
    checkpoint();
    const evidence = prior.get(mapping.fileId);
    if (evidence && (evidence.origin !== 3 || evidence.importMappingKey !== mapping.key)) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
  }
  const expected = new Map();
  const nativeAllocations = new Set();
  // Consumption/duplication is independent of proof provenance and ranks
  // before cross-repository evidence failures at the same semantic stage.
  for (const allocation of context.allocations ?? []) {
    checkpoint();
    const proof = allocation.operation.get(5);
    if (proof.get(1) === 2) continue;
    const id = stateFileKey(allocation.after);
    if (prior.has(id) || nativeAllocations.has(id)) semanticFail('FILEID_ALREADY_CONSUMED');
    nativeAllocations.add(id);
  }
  for (const allocation of context.allocations ?? []) {
    checkpoint();
    const id = stateFileKey(allocation.after);
    const proof = allocation.operation.get(5); if (!sameRef(proof.get(0), context.descriptor)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
    const allocationKind = proof.get(1); const origin = allocationKind === 2 ? 3 : allocation.code === 1 ? 1 : 2;
    const mappingKey = proof.has(2) ? hex(proof.get(2)) : undefined;
    if (origin === 3) {
      const mapping = mappingsByKey.get(mappingKey); if (!mapping || mapping.fileId !== id) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
      const evidence = prior.get(id);
      if (!evidence || evidence.origin !== 3 || evidence.importMappingKey !== mappingKey || !sameRef(evidence.firstChangeSet, context.changeSetReference) || evidence.firstOperation !== allocation.sequence) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
      continue;
    }
    if (prior.has(id) || expected.has(id)) semanticFail('FILEID_ALREADY_CONSUMED');
    expected.set(id, { fileId: id, origin, firstChangeSet: ref(context.changeSetReference, 4), firstOperation: allocation.sequence, importMappingKey: mappingKey });
  }
  const working = [];
  for (const value of context.workingLifetimeAdditions ?? []) { checkpoint(); working.push(normalizeLifetime(value)); }
  const workingById = new Map();
  for (const record of working) {
    checkpoint();
    if (workingById.has(record.fileId) || prior.has(record.fileId) ||
        ![1, 2].includes(record.origin) || record.importMappingKey !== undefined ||
        (record.descriptor && !sameRef(record.descriptor, context.descriptor))) {
      semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
    }
    workingById.set(record.fileId, record);
  }
  if (!allowUnrelatedWorking && workingById.size !== expected.size) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  for (const [id, left] of expected) {
    checkpoint();
    const right = workingById.get(id);
    if (!right) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
    if ((right.descriptor && !sameRef(right.descriptor, context.descriptor)) || left.fileId !== right.fileId || left.origin !== right.origin || !sameRef(left.firstChangeSet, right.firstChangeSet) || left.firstOperation !== right.firstOperation || left.importMappingKey !== right.importMappingKey) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  }
  for (const state of context.entries?.values?.() ?? []) {
    checkpoint();
    const id = stateFileKey(state); if (!prior.has(id) && !workingById.has(id)) {
      // Existing base entries need lifetime evidence only when the caller requests a complete lifetime check.
      if (context.requireCompleteLifetime === true) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
    }
  }
  for (const restoration of context.restorations ?? []) {
    checkpoint();
    if (!prior.has(stateFileKey(restoration.after))) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  }
  for (const record of prior.values()) { checkpoint(); lifetimeOperation(record, context); }
  for (const mapping of mappings.values()) {
    checkpoint();
    const evidence = prior.get(mapping.fileId);
    if (!evidence || evidence.origin !== 3 || evidence.importMappingKey !== mapping.key) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  }
  return Object.freeze({ prior, working, mappings, mappingsByKey });
}

function validateHistoricalLifetimeAndImports(context) {
  const checkpoint = () => context.lookup?.checkpoint?.();
  const validated = validateLifetimeAndImportsInternal({
    ...context,
    allocations: [],
    restorations: [],
    entries: undefined,
    workingLifetimeAdditions: []
  }, { allowUnrelatedWorking: true });
  const allocated = new Set();
  for (const allocation of context.allocations ?? []) {
    checkpoint();
    const id = stateFileKey(allocation.after);
    if (allocated.has(id)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
    allocated.add(id);
    const proof = allocation.operation.get(5);
    if (!sameRef(proof.get(0), context.descriptor)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
    const allocationKind = proof.get(1);
    const origin = allocationKind === 2 ? 3 : allocation.code === 1 ? 1 : 2;
    const mappingKey = proof.has(2) ? hex(proof.get(2)) : undefined;
    const evidence = validated.prior.get(id);
    if (!evidence || evidence.origin !== origin ||
        !sameRef(evidence.firstChangeSet, context.changeSetReference) ||
        evidence.firstOperation !== allocation.sequence || evidence.importMappingKey !== mappingKey) {
      semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
    }
    if (origin === 3) {
      const mapping = validated.mappingsByKey.get(mappingKey);
      if (!mapping || mapping.fileId !== id) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    }
  }
  for (const restoration of context.restorations ?? []) {
    checkpoint();
    if (!validated.prior.has(stateFileKey(restoration.after))) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  }
  for (const entry of context.entries?.values?.() ?? []) {
    checkpoint();
    if (!validated.prior.has(stateFileKey(entry))) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');
  }
  return validated;
}

export function validateLifetimeAndImports(context) {
  return validateLifetimeAndImportsInternal(context);
}

/** Validate an idempotent import allocation request without mutating registry state. */
export function validateImportRequest(request, context) {
  if (!request || request.schema !== 'ogvcs.repository-format.v1.fileid-operation-input.v1' || request.operation !== 'import-file-id' || Object.keys(request).some(key => !['schema','operation','importerProfile','sourceNamespaceDigest','sourceIdentityDigest','requestedFileId'].includes(key))) schemaFail();
  const importerRef = ProfileRef.parse(request.importerProfile); const importer = profileText(importerRef);
  if (context.lookup?.registry) {
    const profile = context.lookup.registry.profiles.get(importer);
    if (profile?.family !== 'importer') schemaFail();
    profileDecision(context.lookup.registry, importerRef, context.lookup.mode === 'production' ? 'production-write' : 'conformance');
  }
  const namespace = hex(decodeHex(request.sourceNamespaceDigest, 32));
  const identity = hex(decodeHex(request.sourceIdentityDigest, 32));
  const requestedFileId = fileKey(request.requestedFileId);
  const validated = validateLifetimeAndImportsInternal(
    { ...context, allocations: [], workingLifetimeAdditions: context.workingLifetimeAdditions ?? [] },
    { allowUnrelatedWorking: true }
  );
  const tuple = `${importer}\0${namespace}\0${identity}`;
  const key = importMappingKey(context.descriptor, { importer, namespace, identity });
  const existing = validated.mappings.get(tuple);
  if (existing) {
    if (existing.fileId !== requestedFileId || existing.key !== key) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    return Object.freeze({ fileId: requestedFileId, mappingKey: key, state: existing.state, retry: true });
  }
  if (validated.prior.has(requestedFileId) || validated.working.some(record => record.fileId === requestedFileId)) {
    semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
  }
  if ([...validated.mappings.values()].some(mapping => mapping.fileId === requestedFileId)) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
  return Object.freeze({ fileId: requestedFileId, mappingKey: key, state: 1, retry: false });
}

function sideValue(side) { return side?.get(side.get(0) === 1 ? 1 : 2); }
function sideMatchesEntry(side, ids, paths) { if (!side || side.get(0) !== 1) return false; const state = side.get(1); return ids.includes(stateFileKey(state)) && paths.includes(statePathKey(state)); }
function sideMatchesGroup(side, id) { return side?.get(0) === 2 && groupKey(side.get(2)) === id; }

export function validateConflictSet(reference, lookup, descriptor, options = {}) {
  return collectRepositoryStage(() => validateConflictSetStage(reference, lookup, descriptor, options));
}

function validateConflictSetStage(reference, lookup, descriptor, options) {
  if (!reference) return Object.freeze({ records: [], byId: new Map() });
  const set = lookup.resolve(reference, 11).value; if (!sameRef(set.get(16), descriptor)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
  const byId = new Map();
  for (const record of set.get(17)) {
    lookup.checkpoint?.();
    const preimage = new Map([[0, record.get(1)], [1, record.get(2)]]);
    for (const [source, target] of [[3, 2], [4, 3], [5, 4]]) if (record.has(source)) preimage.set(target, record.get(source));
    if (!equalBytes(record.get(0), hashConflictPreimage(preimage).bytes)) {
      fail('CONFLICT_ID_MISMATCH', { layer: 2 });
    }
    const id = conflictIdKey(record.get(0)); byId.set(id, record); const kind = record.get(1); const subject = record.get(2); const subjectKind = subject[0];
    const base = record.get(3); const left = record.get(4); const right = record.get(5);
    if (subjectKind === 1) {
      const ids = subject[1].map(fileKey); const paths = subject[2].map(pathKey); const all = side => sideMatchesEntry(side, ids, paths);
      const baseOk = all(base); const leftOk = all(left); const rightOk = all(right);
      if (kind === 1 && !(ids.length===1&&paths.length===1&&baseOk&&leftOk&&rightOk&&!sameValue(sideValue(left).get(4),sideValue(right).get(4)))) semanticFail('CONFLICT_SUBJECT_INVALID');
      if (kind === 2 && !(ids.length===1&&paths.length>=2&&baseOk&&leftOk&&rightOk&&statePathKey(sideValue(left))!==statePathKey(sideValue(right)))) semanticFail('CONFLICT_SUBJECT_INVALID');
      if (kind === 3 && !(ids.length===1&&paths.length===1&&baseOk&&((!left&&rightOk)||(leftOk&&!right))&& !sameValue(sideValue(left??right),sideValue(base)))) semanticFail('CONFLICT_SUBJECT_INVALID');
      if (kind === 4 && !(ids.length===1&&paths.length===1&&baseOk&&leftOk&&rightOk&&sideValue(left).get(1)!==sideValue(right).get(1))) semanticFail('CONFLICT_SUBJECT_INVALID');
      if (kind === 6 && !(ids.length===1&&paths.length===1&&baseOk&&leftOk&&rightOk&&!sameValue(sideValue(left).get(6),sideValue(right).get(6)))) semanticFail('CONFLICT_SUBJECT_INVALID');
      if (kind === 8 && !(ids.length>=2&&paths.length===1&&leftOk&&rightOk&&stateFileKey(sideValue(left))!==stateFileKey(sideValue(right))&&(!base||baseOk))) semanticFail('CONFLICT_SUBJECT_INVALID');
      if (kind === 7) semanticFail('CONFLICT_SUBJECT_INVALID');
    } else {
      const id = hex(subject[1]); if (kind !== 7 || !sideMatchesGroup(base,id) || (!left&&!right) || (left&&!sideMatchesGroup(left,id)) || (right&&!sideMatchesGroup(right,id)) || (left&&right&&sameValue(left,right))) semanticFail('CONFLICT_SUBJECT_INVALID');
    }
    const resolution = record.get(6); if (resolution.get(0) === 0) { if (options.published) semanticFail('CONFLICT_UNRESOLVED_PUBLISHED'); continue; }
    const choice = resolution.get(1); if (choice <= 3) { const selected = record.get(choice + 2); if (!selected || !sameValue(selected,resolution.get(2))) semanticFail('CONFLICT_RESOLUTION_MISMATCH'); }
    if (resolution.get(2) && resolution.get(2).get(0) !== subjectKind) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
  }
  return Object.freeze({ records: set.get(17), byId });
}

function validateConflictOperations(records, operations, lookup) {
  const counts = new Map();
  for (const operation of operations) {
    lookup?.checkpoint?.();
    if (operation.get(1) !== 11) continue;
    const key = conflictIdKey(operation.get(9)); counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (const record of records) {
    lookup?.checkpoint?.();
    const resolved = record.get(6).get(0) === 1;
    if ((counts.get(conflictIdKey(record.get(0))) ?? 0) !== (resolved ? 1 : 0)) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
  }
}

const FIXTURE_GROUP_RULES = new Map([
  ['fixture-group.opengamevcs.test/package-sidecars@2', { roles: [['fixture-role.opengamevcs.test/package@2', 1, 1], ['fixture-role.opengamevcs.test/sidecar@2', 1, Number.POSITIVE_INFINITY]] }],
  ['fixture-group.opengamevcs.test/map-external-actors@2', { roles: [['fixture-role.opengamevcs.test/map@2', 1, 1], ['fixture-role.opengamevcs.test/external-actor@2', 1, Number.POSITIVE_INFINITY]] }],
  ['fixture-group.opengamevcs.test/asset-meta@2', { roles: [['fixture-role.opengamevcs.test/primary@2', 1, 1], ['fixture-role.opengamevcs.test/meta@2', 1, 1]] }],
  ['fixture-group.opengamevcs.test/binary-version-family@2', { roles: [['fixture-role.opengamevcs.test/member@2', 1, Number.POSITIVE_INFINITY]] }],
  ['fixture-group.opengamevcs.test/site@2', { roles: [['fixture-role.opengamevcs.test/member@2', 1, Number.POSITIVE_INFINITY]] }],
  ['fixture-group.opengamevcs.test/team@2', { roles: [['fixture-role.opengamevcs.test/member@2', 1, Number.POSITIVE_INFINITY]] }],
  ['fixture-group.opengamevcs.test/asset@2', { roles: [['fixture-role.opengamevcs.test/member@2', 1, Number.POSITIVE_INFINITY]] }]
]);
const FIXTURE_UNIQUE_EXTERNAL_KEYS = new Set(['fixture-key.opengamevcs.test/synthetic-guid@2']);

function configuredGroupRule(profile, options) {
  const configured = options.groupProfileRules;
  return configured?.get?.(profile) ?? configured?.[profile] ?? FIXTURE_GROUP_RULES.get(profile);
}

/** Validate core membership plus registered role and external-key semantics. */
export function validateAssetGroups(groups, fileIds, options = {}) {
  return collectRepositoryStage(() => validateAssetGroupsStage(groups, fileIds, options));
}

function validateAssetGroupsStage(groups, fileIds, options) {
  const values = groups instanceof Map ? groups.values() : groups;
  const hardLimits = options.hardLimits ?? options.lookup?.hardLimits ?? {};
  const groupMaximum = configuredHardLimit('asset-groups', hardLimits['asset-groups']);
  const memberMaximum = configuredHardLimit('asset-group-members', hardLimits['asset-group-members']);
  const declaredGroups = groups instanceof Map ? groups.size : Array.isArray(groups) ? groups.length : undefined;
  if (declaredGroups !== undefined) enforceHardLimit(undefined, 'asset-groups', declaredGroups,
    { maximum: groupMaximum, code: 'LIMIT_COUNT', layer: 2 });
  const hasFileId = id => fileIds?.has?.(id) === true;
  const membership = new Map();
  const externalOwners = new Map();
  const uniqueSchemes = new Set([...(options.uniqueExternalKeyProfiles ?? []), ...FIXTURE_UNIQUE_EXTERNAL_KEYS]);
  let groupCount = 0;
  for (const group of values) {
    options.lookup?.checkpoint?.();
    groupCount++;
    enforceHardLimit(undefined, 'asset-groups', groupCount,
      { maximum: groupMaximum, code: 'LIMIT_COUNT', layer: 2 });
    const members = asArray(group.get(3));
    enforceHardLimit(undefined, 'asset-group-members', members.length,
      { maximum: memberMaximum, code: 'LIMIT_COUNT', layer: 2 });
    const primary = fileKey(group.get(2)); const local = new Set();
    if (!members.some(member => fileKey(member.get(0)) === primary)) semanticFail('GROUP_MEMBER_INVALID');
    const roleCounts = new Map();
    for (const member of members) {
      options.lookup?.checkpoint?.();
      const id = fileKey(member.get(0));
      if (local.has(id) || !hasFileId(id)) semanticFail('GROUP_MEMBER_INVALID');
      local.add(id);
      if (membership.has(id)) semanticFail('GROUP_MEMBERSHIP_OVERLAP');
      membership.set(id, groupKey(group));
      const role = profileText(member.get(1)); roleCounts.set(role, (roleCounts.get(role) ?? 0) + 1);
    }
    const rule = configuredGroupRule(profileText(group.get(1)), options);
    const allowedRoles = rule ? new Set(rule.roles.map(([role]) => role)) : undefined;
    if (allowedRoles && [...roleCounts.keys()].some(role => !allowedRoles.has(role))) {
      semanticFail('GROUP_REQUIRED_ROLE_MISSING');
    }
    for (const [role, minimum = 0, maximum = Number.POSITIVE_INFINITY] of rule?.roles ?? []) {
      options.lookup?.checkpoint?.();
      const count = roleCounts.get(role) ?? 0;
      if (count < minimum || count > maximum) semanticFail('GROUP_REQUIRED_ROLE_MISSING');
    }
    for (const external of group.get(4) ?? []) {
      options.lookup?.checkpoint?.();
      const scheme = profileText(external.get(0));
      if (!uniqueSchemes.has(scheme) && !rule?.uniqueExternalKeyProfiles?.includes?.(scheme)) continue;
      const key = `${scheme}\0${hex(external.get(1))}`; const owner = externalOwners.get(key);
      if (owner && owner !== groupKey(group)) semanticFail('GROUP_EXTERNAL_KEY_DUPLICATE');
      externalOwners.set(key, groupKey(group));
    }
  }
  return Object.freeze({ groups: membership.size === 0 ? 0 : [...new Set(membership.values())].length, members: membership.size });
}

function compareStateToSnapshot(state, snapshot, lookup, descriptor, options) {
  const expectedTree = expandTree(snapshot.get(18), lookup, descriptor, options); const expectedGroups = groupsFromSet(snapshot.get(20), lookup, descriptor);
  if (state.entries.size !== expectedTree.entries.size || state.groups.size !== expectedGroups.size) semanticFail('CHANGESET_RESULT_MISMATCH');
  for (const [key, value] of state.entries) { lookup.checkpoint?.(); if (!expectedTree.entries.has(key) || !sameValue(value, expectedTree.entries.get(key))) semanticFail('CHANGESET_RESULT_MISMATCH'); }
  for (const [key, value] of state.groups) { lookup.checkpoint?.(); if (!expectedGroups.has(key) || !sameValue(value, expectedGroups.get(key))) semanticFail('CHANGESET_RESULT_MISMATCH'); }
  validateAssetGroups(state.groups, expectedTree.fileIds, { ...options, lookup });
}

function preflightSnapshotRepositoryStage(candidate, descriptor, designatedRoot, lookup) {
  return collectRepositoryStage(() => {
    const seen = new Set();
    const stack = [candidate];
    while (stack.length > 0) {
      lookup.checkpoint?.();
      const reference = stack.pop();
      const key = refKey(reference);
      if (seen.has(key)) continue;
      seen.add(key);
      const snapshot = lookup.resolve(reference, 7).value;
      const parents = snapshot.get(17);
      // Catalogue order is global across the reachable graph: root validity is
      // independent of descriptor/base coherence and ranks before both.
      if (key === refKey(designatedRoot) ? parents.length !== 0 : parents.length === 0) {
        semanticFail('SNAPSHOT_ROOT_INVALID');
      }
      if (!sameRef(snapshot.get(16), descriptor)) semanticFail('SNAPSHOT_PARENT_CROSS_REPOSITORY');
      const changeSet = lookup.resolve(snapshot.get(19), 4).value;
      const base = changeSet.get(17);
      if ((parents.length === 0) !== !base || (parents.length > 0 && !sameRef(base, parents[0]))) {
        semanticFail('CHANGESET_BASE_MISMATCH');
      }
      for (const parent of parents) stack.push(parent);
    }
  });
}

export function validateSnapshotGraph(candidateReference, context) {
  context.lookup.validateAll();
  const candidate = ref(candidateReference, 7); const descriptor = ref(context.descriptor, 6); const designatedRoot = ref(context.designatedRoot, 7); const visiting = new Set(); const visited = new Set(); const order = [];
  preflightSnapshotRepositoryStage(candidate, descriptor, designatedRoot, context.lookup);
  const stack = [{ reference: candidate }];
  while (stack.length) {
    context.lookup.checkpoint?.();
    const frame = stack[stack.length - 1]; const key = refKey(frame.reference);
    if (!frame.snapshot) {
      if (visiting.has(key)) semanticFail('SNAPSHOT_PARENT_CYCLE');
      if (visited.has(key)) { stack.pop(); continue; }
      visiting.add(key); frame.snapshot = snapshotObject(frame.reference, context.lookup); frame.parent = 0;
      const parents = frame.snapshot.get(17);
      if (key === refKey(designatedRoot) ? parents.length !== 0 : parents.length === 0) semanticFail('SNAPSHOT_ROOT_INVALID');
      if (!sameRef(frame.snapshot.get(16), descriptor)) semanticFail('SNAPSHOT_PARENT_CROSS_REPOSITORY');
    }
    const parents = frame.snapshot.get(17);
    if (frame.parent < parents.length) {
      const parent = parents[frame.parent++]; const parentKey = refKey(parent);
      if (visiting.has(parentKey)) semanticFail('SNAPSHOT_PARENT_CYCLE');
      if (!visited.has(parentKey)) stack.push({ reference: parent });
      continue;
    }
    const changeSet = context.lookup.edge(frame.snapshot.get(19), 4).value; const base = changeSet.get(17);
    if ((parents.length === 0) !== !base || (parents.length > 0 && !sameRef(base, parents[0]))) semanticFail('CHANGESET_BASE_MISMATCH');
    visiting.delete(key); visited.add(key); order.push(frame.reference); stack.pop();
  }
  if (!visited.has(refKey(designatedRoot))) semanticFail('SNAPSHOT_ROOT_INVALID');
  return Object.freeze({ visited, order: Object.freeze(order) });
}

export function validateProvenanceGraph(references, lookup, options = {}) {
  const visiting = new Set(); const visited = new Set(); const forbidden = new Set((options.forbidden ?? []).map(refKey));
  for (const root of references ?? []) {
    const rootRef = ref(root, 9); if (visited.has(refKey(rootRef))) continue;
    const stack = [{ reference: rootRef }];
    while (stack.length) {
      lookup.checkpoint?.();
      const frame = stack[stack.length - 1]; const key = refKey(frame.reference);
      if (!frame.inputs) {
        if (forbidden.has(key) || visiting.has(key)) semanticFail('PROVENANCE_CYCLE');
        if (visited.has(key)) { stack.pop(); continue; }
        visiting.add(key); const parsed = ref(frame.reference); const object = lookup.edge(parsed).value;
        frame.inputs = iterateObjectReferences(parsed.kind, object); frame.input = 0;
      }
      const next = frame.inputs.next();
      if (!next.done) {
        frame.input++;
        const input = next.value; const inputKey = refKey(input);
        if (forbidden.has(inputKey) || visiting.has(inputKey)) semanticFail('PROVENANCE_CYCLE');
        if (!visited.has(inputKey)) stack.push({ reference: input });
        continue;
      }
      visiting.delete(key); visited.add(key); stack.pop();
    }
  }
  return Object.freeze({ visited });
}

export function validateShelfRevision(reference, context) {
  context.lookup.validateAll();
  const shelfRef = ref(reference, 8); const shelf = context.lookup.resolve(shelfRef, 8).value; if (!sameRef(shelf.get(16), context.descriptor)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
  const revision = Number(shelf.get(18));
  let current = shelf; let currentRef = shelfRef; let expectedRevision = revision;
  const seen = new Set([refKey(shelfRef)]); const chain = [{ reference: shelfRef, value: shelf }];
  while (true) {
    context.lookup.checkpoint?.();
    if (Number(current.get(18)) !== expectedRevision) semanticFail('SHELF_CHAIN_INVALID');
    if (expectedRevision === 1) { if (current.has(19)) semanticFail('SHELF_CHAIN_INVALID'); break; }
    if (!current.has(19)) semanticFail('SHELF_CHAIN_INVALID');
    const previousRef = ref(current.get(19), 8); const key = refKey(previousRef); if (seen.has(key)) semanticFail('SHELF_CHAIN_INVALID'); seen.add(key);
    const previous = context.lookup.edge(previousRef, 8).value;
    if (!sameRef(previous.get(16), context.descriptor) || !equalBytes(previous.get(17), shelf.get(17))) semanticFail('SHELF_CHAIN_INVALID');
    current = previous; currentRef = previousRef; chain.push({ reference: currentRef, value: current }); expectedRevision--;
  }
  chain.reverse();
  const baseUses = new Map();
  for (const item of chain) {
    const key = refKey(item.value.get(20));
    baseUses.set(key, (baseUses.get(key) ?? 0) + 1);
  }
  const baseStates = new Map();
  let requestedConflicts = 0;
  for (const item of chain) {
    context.lookup.checkpoint?.();
    const value = item.value; const baseKey = refKey(value.get(20));
    let retainedBase = baseStates.get(baseKey);
    if (!retainedBase) {
      const baseSnapshot = snapshotObject(value.get(20), context.lookup);
      if (!sameRef(baseSnapshot.get(16), context.descriptor)) semanticFail('SNAPSHOT_PARENT_CROSS_REPOSITORY');
      const baseTree = expandTree(baseSnapshot.get(18), context.lookup, context.descriptor, context);
      const base = { entries: baseTree.entries, groups: groupsFromSet(baseSnapshot.get(20), context.lookup, context.descriptor) };
      const bytes = stateMemoryBytes(base, () => context.lookup.checkpoint?.());
      reserveState(context.lookup, bytes);
      retainedBase = { state: base, bytes };
      baseStates.set(baseKey, retainedBase);
    }
    const changeSet = context.lookup.resolve(value.get(21), 4).value;
    if (!changeSet.has(17) || !sameRef(changeSet.get(17), value.get(20))) semanticFail('CHANGESET_BASE_MISMATCH');
    const conflicts = validateConflictSet(value.get(24), context.lookup, context.descriptor, { published: false });
    const replayGrowth = replayWorkingMemoryBytes(value.get(21), retainedBase.state, context);
    const replayReservation = retainedBase.bytes + replayGrowth;
    reserveState(context.lookup, replayReservation);
    try {
      const replayed = replayChangeSet(value.get(21), retainedBase.state, {
        ...context,
        requireCompleteLifetime: true,
        historicalReplay: !sameRef(item.reference, shelfRef),
        conflictSet: value.has(24) ? context.lookup.resolve(value.get(24), 11).value : undefined
      });
      stateMemoryBytes(replayed, () => context.lookup.checkpoint?.());
      validateConflictOperations(conflicts.records, changeSet.get(18), context.lookup);
      const synthetic = new Map([[18, value.get(22)]]); if (value.has(23)) synthetic.set(20, value.get(23));
      compareStateToSnapshot(replayed, synthetic, context.lookup, context.descriptor, context);
      validateProvenanceGraph(value.get(29) ?? [], context.lookup, { forbidden: [item.reference] });
      if (sameRef(item.reference, shelfRef)) requestedConflicts = conflicts.records.length;
    } finally {
      releaseState(context.lookup, replayReservation);
    }
    const remainingUses = baseUses.get(baseKey) - 1;
    baseUses.set(baseKey, remainingUses);
    if (remainingUses === 0) {
      releaseState(context.lookup, retainedBase.bytes);
      baseStates.delete(baseKey);
    }
  }
  return Object.freeze({ revision, conflicts: requestedConflicts });
}

export function validateRepositoryCandidate(candidateReference, context) {
  const candidate = ref(candidateReference, 7); const descriptor = ref(context.descriptor, 6);
  const graph = validateSnapshotGraph(candidate, { ...context, descriptor });
  const firstParentUses = new Map();
  for (const snapshotRef of graph.order) {
    context.lookup.checkpoint?.();
    const parents = context.lookup.resolve(snapshotRef, 7).value.get(17);
    if (parents.length > 0) {
      const key = refKey(parents[0]);
      firstParentUses.set(key, (firstParentUses.get(key) ?? 0) + 1);
    }
  }
  const states = new Map();
  let candidateEntries = 0; let candidateGroups = 0; let candidateConflicts = 0;
  for (const snapshotRef of graph.order) {
    context.lookup.checkpoint?.();
    const snapshot = context.lookup.resolve(snapshotRef, 7).value; const parents = snapshot.get(17);
    const parentKey = parents.length === 0 ? undefined : refKey(parents[0]);
    const retainedBase = parentKey === undefined ? undefined : states.get(parentKey);
    const base = retainedBase?.state ?? (parents.length === 0 ? { entries: new Map(), groups: new Map() } : undefined);
    if (!base) semanticFail('CHANGESET_BASE_MISMATCH');
    const conflicts = validateConflictSet(snapshot.get(28), context.lookup, descriptor, { published: true });
    const baseCloneBytes = retainedBase?.bytes ?? stateMemoryBytes(base, () => context.lookup.checkpoint?.());
    const replayGrowth = replayWorkingMemoryBytes(snapshot.get(19), base, context);
    let replayReservation = baseCloneBytes + replayGrowth;
    reserveState(context.lookup, replayReservation);
    let retainedReplay;
    try {
      const replayed = replayChangeSet(snapshot.get(19), base, {
        ...context,
        descriptor,
        requireCompleteLifetime: true,
        historicalReplay: !sameRef(snapshotRef, candidate),
        conflictSet: snapshot.has(28) ? context.lookup.resolve(snapshot.get(28), 11).value : undefined
      });
      const actualReplayBytes = stateMemoryBytes(replayed, () => context.lookup.checkpoint?.());
      compareStateToSnapshot(replayed, snapshot, context.lookup, descriptor, context);
      const operations = context.lookup.resolve(snapshot.get(19), 4).value.get(18);
      validateConflictOperations(conflicts.records, operations, context.lookup);
      validateProvenanceGraph(snapshot.get(27) ?? [], context.lookup, { forbidden: [snapshotRef] });
      const snapshotKey = refKey(snapshotRef);
      if ((firstParentUses.get(snapshotKey) ?? 0) > 0) {
        if (actualReplayBytes > replayReservation) reserveState(context.lookup, actualReplayBytes - replayReservation);
        else releaseState(context.lookup, replayReservation - actualReplayBytes);
        replayReservation = actualReplayBytes;
        retainedReplay = { entries: replayed.entries, groups: replayed.groups };
        states.set(snapshotKey, { state: retainedReplay, bytes: replayReservation });
        replayReservation = 0;
      }
      if (sameRef(snapshotRef, candidate)) {
        candidateEntries = replayed.entries.size;
        candidateGroups = replayed.groups.size;
        candidateConflicts = conflicts.records.length;
      }
    } finally {
      if (replayReservation > 0) releaseState(context.lookup, replayReservation);
    }
    if (parentKey !== undefined) {
      const remaining = firstParentUses.get(parentKey) - 1;
      firstParentUses.set(parentKey, remaining);
      if (remaining === 0) {
        const released = states.get(parentKey);
        if (released) {
          releaseState(context.lookup, released.bytes);
          states.delete(parentKey);
        }
      }
    }
  }
  return Object.freeze({
    highestLayer: 3,
    entries: candidateEntries,
    groups: candidateGroups,
    conflicts: candidateConflicts
  });
}

export function validateAbstractReferenceGraph(graph, options = {}) {
  if (!graph || Object.keys(graph).sort().join(',') !== 'assumedValidation,graphKind,nodes,roots,schemaVersion' || graph.schemaVersion !== 'ogvcs.repository-format/abstract-reference-graph/v1' || graph.assumedValidation !== 'canonical-framing-schema-and-identity-prevalidated') schemaFail();
  const expected = graph.graphKind === 'snapshot-parent' ? { type:'snapshot',edge:'parent',code:'SNAPSHOT_PARENT_CYCLE' } : graph.graphKind === 'provenance-input' ? { type:'provenance',edge:'provenance-input',code:'PROVENANCE_CYCLE' } : null; if (!expected) schemaFail();
  if (!Array.isArray(graph.nodes) || graph.nodes.length === 0 || !Array.isArray(graph.roots) || graph.roots.length === 0) schemaFail();
  const nodes = new Map(); const guard = makeGuard(options); let previous;
  for (const node of graph.nodes) {
    if (!node || Object.keys(node).sort().join(',') !== 'edges,id,type' || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(node.id) || node.type !== expected.type || !Array.isArray(node.edges) || nodes.has(node.id) || (previous && compareText(previous,node.id)>=0)) schemaFail();
    previous=node.id; nodes.set(node.id,node); guard.object();
  }
  for (const node of nodes.values()) {
    let prior;
    for (const edge of node.edges) {
      // Charge every supplied edge, including edges on unreachable nodes,
      // before inspecting its shape. Reachability is semantic output, not a
      // permission to bypass receiver count/time/memory ceilings.
      guard.edge();
      const targetBytes = typeof edge?.target === 'string' ? edge.target.length * 2 : 0;
      guard.reserve(128 + targetBytes);
      if (!edge || Object.keys(edge).sort().join(',') !== 'kind,target' || edge.kind !== expected.edge || !nodes.has(edge.target) || (prior && compareText(`${prior.kind}\0${prior.target}`,`${edge.kind}\0${edge.target}`)>=0)) schemaFail();
      prior=edge;
    }
  }
  previous=undefined; for(const root of graph.roots){if(typeof root!=='string'||!nodes.has(root)||(previous&&compareText(previous,root)>=0))schemaFail();previous=root;}
  const visiting=new Set();const visited=new Set();
  for (const root of graph.roots) {
    if (visited.has(root)) continue;
    visiting.add(root); const stack = [{ id: root, edge: 0 }];
    while (stack.length) {
      const frame = stack[stack.length - 1]; const edges = nodes.get(frame.id).edges;
      if (frame.edge === edges.length) { visiting.delete(frame.id); visited.add(frame.id); stack.pop(); continue; }
      const target = edges[frame.edge++].target;
      if (visiting.has(target)) semanticFail(expected.code);
      if (!visited.has(target)) { visiting.add(target); stack.push({ id: target, edge: 0 }); }
    }
  }
  return Object.freeze({highestLayer:3,nodes:visited.size,edges:guard.summary().edges});
}
