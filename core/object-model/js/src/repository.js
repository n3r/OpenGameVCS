import { createHash } from 'node:crypto';
import { types as nodeTypes } from 'node:util';
import { iterateObjectReferences } from './bundle.js';
import {
  decodeMetadata, scanMetadata, validateKnownSchema, validateLogicalRecord
} from './schema.js';
import { canonicalEncodedLength, encodeCanonical } from './cbor.js';
import { OgvcsError, compareErrorPrecedence, fail } from './errors.js';
import { configuredHardLimit, enforceHardLimit, hardLimitMaximum } from './hard-limits.js';
import { hashConflictPreimage, hashOpaqueObject, verifyObjectId } from './hash.js';
import { profileDecision, registryAssignmentDecision } from './registry.js';
import { FileId, ObjectRef, ProfileRef, equalBytes } from './types.js';
import {
  registrySnapshot, semanticValidationContext, validationMode, validationOperation
} from './validation-mode.js';
import { isUnicode15String } from './unicode-age.js';

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
const SEMANTIC_LOOKUPS = new WeakSet();
const LOOKUP_OPERATION = Symbol('repository-operation');
const LOOKUP_SCRATCH = Symbol('repository-scratch');
const LOOKUP_FINISH_REGISTRY = Symbol('repository-finish-registry');
const LOOKUP_PREFLIGHT_ALL_L2 = Symbol('repository-preflight-all-layer-two');
const LOOKUP_FINISH_ALL_REGISTRY = Symbol('repository-finish-all-registry');

function schemaFail() { fail('SCHEMA_FIELD_INVALID', { layer: 2 }); }
const repositoryStageCollectors = [];
function currentRepositoryStageCollector() { return repositoryStageCollectors.at(-1); }
function semanticFail(code) {
  const collector = currentRepositoryStageCollector();
  if (collector) {
    const error = new OgvcsError(code, { layer: 3 });
    if (!collector.best || compareErrorPrecedence(error, collector.best) < 0) collector.best = error;
    return false;
  }
  fail(code, { layer: 3 });
}
function collectRepositoryStage(callback) {
  const collector = { best: undefined };
  repositoryStageCollectors.push(collector);
  let result;
  try { result = callback(); }
  finally { repositoryStageCollectors.pop(); }
  if (collector.best) throw collector.best;
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
    if (typeof segment !== 'string' || !isUnicode15String(segment) || segment.normalize('NFC') !== segment ||
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
function validAbstractNodeId(value, guard) {
  if (typeof value !== 'string' || value.length === 0) return false;
  let afterDash = true;
  for (let index = 0; index < value.length; index++) {
    if ((index & 1023) === 0) guard.check();
    const code = value.charCodeAt(index);
    const alphaNumeric = (code >= 0x61 && code <= 0x7a) || (code >= 0x30 && code <= 0x39);
    if (alphaNumeric) {
      afterDash = false;
    } else if (code === 0x2d && !afterDash) {
      afterDash = true;
    } else {
      return false;
    }
  }
  return !afterDash;
}
function compareAbstractNodeId(left, right, guard) {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index++) {
    if ((index & 1023) === 0) guard.check();
    const difference = left.charCodeAt(index) - right.charCodeAt(index);
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
}
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
  let clock = () => performance.now();
  let clockDescriptor;
  try {
    clockDescriptor = Object.getOwnPropertyDescriptor(options, 'now');
  } catch {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (clockDescriptor !== undefined) {
    if (!Object.hasOwn(clockDescriptor, 'value') || typeof clockDescriptor.value !== 'function') {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    clock = clockDescriptor.value;
  }
  let start;
  try { start = clock(); }
  catch { fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' }); }
  if (typeof start !== 'number' || !Number.isFinite(start) || start < 0) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  let last = start;
  const maxTimeMs = configuredLimit(options.maxTimeMs, REPOSITORY_VALIDATION_LIMITS.maxTimeMs);
  const maxObjects = configuredLimit(options.maxObjects, REPOSITORY_VALIDATION_LIMITS.maxObjects);
  const maxBytes = configuredLimit(options.maxBytes, REPOSITORY_VALIDATION_LIMITS.maxBytes);
  const maxEdges = configuredLimit(options.maxEdges, REPOSITORY_VALIDATION_LIMITS.maxEdges);
  const maxMemoryBytes = configuredLimit(options.maxMemoryBytes, REPOSITORY_VALIDATION_LIMITS.maxMemoryBytes);
  const maxScratchBytes = configuredLimit(options.maxScratchBytes, REPOSITORY_VALIDATION_LIMITS.maxScratchBytes);
  let objects = 0; let bytes = 0; let edges = 0; let retainedBytes = 0; let scratchBytes = 0;
  let operationDepth = 0; let operationBaseline;
  const check = () => {
    let current;
    try { current = clock(); }
    catch { fail('LIMIT_TIME', { layer: 1, stage: 'configured-resource-preflight' }); }
    if (typeof current !== 'number' || !Number.isFinite(current) || current < last) {
      fail('LIMIT_TIME', { layer: 1, stage: 'configured-resource-preflight' });
    }
    last = current;
    if (maxTimeMs === 0 || current - start > maxTimeMs) {
      fail('LIMIT_TIME', { layer: 1, stage: 'configured-resource-preflight' });
    }
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
    scratch(bytes) {
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxScratchBytes - scratchBytes) {
        fail('LIMIT_SCRATCH', { layer: 1, stage: 'configured-resource-preflight' });
      }
      scratchBytes += bytes;
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
    beginOperation() {
      if (operationDepth === 0) operationBaseline = Object.freeze({ edges, scratchBytes });
      operationDepth += 1;
    },
    endOperation() {
      if (operationDepth < 1 || operationBaseline === undefined) schemaFail();
      operationDepth -= 1;
      if (operationDepth === 0) {
        ({ edges, scratchBytes } = operationBaseline);
        operationBaseline = undefined;
      }
    },
    check,
    summary() { return Object.freeze({ objects, bytes, edges, retainedBytes, scratchBytes }); }
  });
}

function collectLookupFailure(selection, callback) {
  try { return callback(); }
  catch (error) {
    if (!(error instanceof OgvcsError) || error.errorClass === 'resource') throw error;
    if (!selection.best || compareErrorPrecedence(error, selection.best) < 0) selection.best = error;
    return undefined;
  }
}

function throwSelectedLookupFailure(selection) {
  if (selection.best) throw selection.best;
}

/** Pure identity/schema lookup. This is bounded by caller hooks, not yet a streaming graph store. */
export class RepositoryObjectLookup {
  #entries = new Map();
  #options;
  #guard;
  #operationDepth = 0;
  #deferredLookupFailure;

  constructor(entries = [], options = {}) {
    let semantic;
    const layerTwo = options.semanticProfiles === false;
    if (layerTwo) {
      if (options.registry !== undefined || options.mode !== undefined || options.operation !== undefined) {
        fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
      }
      semantic = { registry: undefined, mode: undefined, operation: undefined };
    } else semantic = semanticValidationContext(options.mode, options.registry, {
        requireRegistry: true,
        requireMode: options.registry !== undefined
      });
    this.#options = {
      ...options,
      ...semantic,
      modeExplicit: options.semanticProfiles !== false && options.mode !== undefined
    };
    // Authority and selector errors outrank same-stage resource failures and
    // must be selected before clock hooks or caller-owned object iterables.
    this.#guard = makeGuard(options);
    // A zero configured time budget is an immediate preflight failure even
    // when the supplied object iterable is empty.
    this.#guard.check();
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
    SEMANTIC_LOOKUPS.add(this);
  }

  get size() { return this.#entries.size; }
  get guardSummary() { return this.#guard.summary(); }
  get registry() { return this.#options.registry; }
  get mode() { return this.#options.mode; }
  get operation() { return this.#options.operation; }
  get modeExplicit() { return this.#options.modeExplicit; }
  get semanticProfilesEnabled() {
    return this.#options.registry !== undefined && this.#options.semanticProfiles !== false;
  }
  get hardLimits() { return this.#options.hardLimits ?? {}; }
  checkpoint() { this.#guard.check(); }
  reserveDerived(bytes) { this.#guard.reserve(bytes); }
  releaseDerived(bytes) { this.#guard.release(bytes); }
  [LOOKUP_SCRATCH](bytes) { this.#guard.scratch(bytes); }
  [LOOKUP_OPERATION](callback) {
    const outer = this.#operationDepth === 0;
    if (outer) this.#deferredLookupFailure = undefined;
    this.#operationDepth += 1;
    this.#guard.beginOperation();
    let result;
    let callbackError;
    try {
      try { result = callback(); } catch (error) { callbackError = error; }
      if (outer && this.#deferredLookupFailure &&
          (callbackError === undefined ||
           (callbackError instanceof OgvcsError &&
            compareErrorPrecedence(this.#deferredLookupFailure, callbackError) < 0))) {
        callbackError = this.#deferredLookupFailure;
      }
      if (callbackError !== undefined) throw callbackError;
      return result;
    } finally {
      this.#guard.endOperation();
      this.#operationDepth -= 1;
      if (outer) this.#deferredLookupFailure = undefined;
    }
  }

  [LOOKUP_FINISH_REGISTRY]() {
    if (this.#operationDepth < 1) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    const error = this.#deferredLookupFailure;
    this.#deferredLookupFailure = undefined;
    if (error) throw error;
  }

  #observeLookupSemantics(callback) {
    try {
      callback();
      return true;
    } catch (error) {
      if (this.#operationDepth < 1 || !(error instanceof OgvcsError) ||
          error.layer !== 3 || error.stage !== 'registry-semantics') throw error;
      if (!this.#deferredLookupFailure ||
          compareErrorPrecedence(error, this.#deferredLookupFailure) < 0) {
        this.#deferredLookupFailure = error;
      }
      return false;
    }
  }

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
      const operation = this.#options.operation;
      this.#observeLookupSemantics(() =>
        registryAssignmentDecision(this.#options.registry, 'object-kinds', parsed.kind, operation));
      this.#observeLookupSemantics(() =>
        registryAssignmentDecision(this.#options.registry, 'hash-algorithms', 1, operation));
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
        hardLimits: this.#options.hardLimits,
        semantic: false,
        maxWorkingBytes: this.#metadataWorkingBytes(entry.payload.length, { returnedClone: true })
      });
      if (decoded.kind !== parsed.kind) {
        fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
      }
      if (this.#options.registry !== undefined && this.#options.semanticProfiles !== false) {
        this.#observeLookupSemantics(() => validateKnownSchema(decoded.value, decoded.kind, {
          registry: this.#options.registry,
          operation: this.#options.operation,
          hardLimits: this.#options.hardLimits
        }));
      }
      return cloneResolved(Object.freeze({ reference: parsed, payload: entry.payload, value: decoded.value }));
    }
  }

  [LOOKUP_PREFLIGHT_ALL_L2]() {
    const entries = this.#entries.values();
    const phaseOneFailures = { best: undefined };

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
    const phaseTwoFailures = { best: undefined };
    for (const entry of this.#entries.values()) {
      if (entry.reference.kind === 1) continue;
      const scan = collectLookupFailure(phaseTwoFailures, () => this.#scan(entry));
      if (!scan) continue;
      collectLookupFailure(phaseTwoFailures, () => validateKnownSchema(scan.value, scan.kind, {
        hardLimits: this.#options.hardLimits,
        semantic: false
      }));
      if (scan.kind !== entry.reference.kind) {
        collectLookupFailure(phaseTwoFailures, () => {
          throw new OgvcsError('OBJECT_REFERENCE_KIND_MISMATCH', {
            layer: 2, stage: 'known-schema'
          });
        });
      }
    }
    throwSelectedLookupFailure(phaseTwoFailures);

  }

  [LOOKUP_FINISH_ALL_REGISTRY]() {
    // Phase 3 applies operation-aware registry semantics only after the entire
    // lookup has passed framing, identity, and known-schema validation. It is
    // also a whole-set phase so catalogue order is independent of ref sorting.
    const phaseThreeFailures = { best: undefined };
    for (const entry of this.#entries.values()) {
      const parsed = entry.reference;
      if (this.#options.registry) {
        const operation = this.#options.operation;
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
          semantic: this.#options.registry !== undefined && this.#options.semanticProfiles !== false,
          operation: this.#options.operation
        }));
      }
    }
    throwSelectedLookupFailure(phaseThreeFailures);
    // Any registry failure deferred while discovering the route closure is a
    // subset of this whole-supplied phase. Clear it only after the complete
    // catalogue-ranked phase succeeds.
    this.#deferredLookupFailure = undefined;
  }

  validateAll() {
    this[LOOKUP_PREFLIGHT_ALL_L2]();
    this[LOOKUP_FINISH_ALL_REGISTRY]();
    return this;
  }
  edge(reference, expectedKind) { this.#guard.edge(); return this.resolve(reference, expectedKind); }
}
Object.freeze(RepositoryObjectLookup.prototype);

export function createRepositoryObjectLookup(entries, options) { return new RepositoryObjectLookup(entries, options); }

/**
 * Require the authenticated registry authority before any layer-three
 * repository work. A registry-free RepositoryObjectLookup remains useful for
 * explicit framing, identity, and known-schema work through layer two only.
 */
function requireSemanticLookup(lookup) {
  let exact = false;
  try {
    exact = lookup !== null && typeof lookup === 'object' && SEMANTIC_LOOKUPS.has(lookup) &&
      Object.getPrototypeOf(lookup) === RepositoryObjectLookup.prototype &&
      Reflect.ownKeys(lookup).length === 0;
  } catch {
    exact = false;
  }
  if (!exact) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  registrySnapshot(lookup.registry, { required: true });
  if (lookup.semanticProfilesEnabled !== true || lookup.modeExplicit !== true) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const operation = validationOperation(validationMode(lookup.mode));
  if (lookup.operation !== undefined && lookup.operation !== operation) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return lookup;
}

export function verifyManifest(reference, lookup) {
  requireSemanticLookup(lookup);
  return lookup[LOOKUP_OPERATION](() => {
  const lookupFailures = { best: undefined };
  const object = collectLookupFailure(lookupFailures, () => lookup.resolve(reference, 2));
  if (!object) throwSelectedLookupFailure(lookupFailures);
  const closure = manifestClosure(object, lookup, lookupFailures);
  throwSelectedLookupFailure(lookupFailures);
  lookup[LOOKUP_FINISH_REGISTRY]();
  return verifyManifestRepository(closure, lookup);
  });
}

function manifestClosure(object, lookup, lookupFailures = { best: undefined }) {
  const manifest = object.value;
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
    const observed = collectLookupFailure(lookupFailures, () => {
      const map = asMap(part); const length = asUint(map.get(1));
      enforceHardLimit(undefined, 'chunk-payload-bytes', length,
        { maximum: chunkMaximum, code: 'MANIFEST_CHUNK_LENGTH_INVALID', layer: 2 });
      return Object.freeze({ map, length });
    });
    if (observed === undefined) continue;
    sum += observed.length;
    enforceHardLimit(undefined, 'logical-file-bytes', sum,
      { maximum: logicalMaximum, code: 'LIMIT_LOGICAL_BYTES', layer: 2 });
    // Reference resolution is ranked independently from the already-known
    // part shape/length. A missing edge must not erase that part from the
    // declared-length transcript and manufacture a higher-ranked mismatch.
    collectLookupFailure(lookupFailures, () => lookup.edge(observed.map.get(0), 1));
  }
  collectLookupFailure(lookupFailures, () => {
    if (sum !== declared || (declared === 0n && parts.length !== 0)) {
      fail('MANIFEST_LENGTH_MISMATCH', { layer: 2 });
    }
  });
  return Object.freeze({ declared, manifest, parts });
}

function verifyManifestRepository(closure, lookup) {
  const { declared, manifest, parts } = closure;
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
  const expected = asMap(manifest.get(17)).get(1);
  if (!equalBytes(new Uint8Array(digest.digest()), expected)) semanticFail('MANIFEST_FILE_DIGEST_MISMATCH');
  return Object.freeze({ logicalLength: declared, chunks: parts.length });
}

function descriptorProfileSet(value, reservation, checkpoint) {
  const profiles = new Set();
  for (const raw of asArray(value)) {
    checkpoint();
    const profile = profileText(raw);
    if (profiles.has(profile)) continue;
    reservation.reserve(retainedValueBytes(profile, checkpoint) + 192);
    profiles.add(profile);
  }
  return profiles;
}

function descriptorProfiles(descriptor, reservation, checkpoint = () => {}) {
  let path;
  if (descriptor.has(17)) {
    checkpoint();
    path = profileText(descriptor.get(17));
    reservation.reserve(retainedValueBytes(path, checkpoint) + 192);
  }
  return {
    path,
    content: descriptorProfileSet(descriptor.get(18), reservation, checkpoint),
    groups: descriptorProfileSet(descriptor.get(19), reservation, checkpoint),
    chunks: descriptor.has(20)
      ? descriptorProfileSet(descriptor.get(20), reservation, checkpoint)
      : new Set()
  };
}

function entryStateFromTree(path, entry) {
  const state = new Map([[0, path], [1, entry.get(1)], [2, cloneBytes(entry.get(2))], [3, entry.get(3)]]);
  if (entry.get(1) !== 1) state.set(4, cloneValue(entry.get(4)));
  state.set(5, entry.get(5)); state.set(6, cloneValue(entry.get(6))); return state;
}

function derivedBuildReservation(lookup, options = {}) {
  const shared = typeof lookup?.reserveDerived === 'function' &&
    typeof lookup?.releaseDerived === 'function';
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
    },
    lease() {
      const bytes = retained;
      retained = 0;
      let released = false;
      return Object.freeze({
        bytes,
        release() {
          if (released || bytes === 0) return;
          released = true;
          if (local) local.release(bytes); else lookup.releaseDerived(bytes);
        }
      });
    }
  });
}

function derivedValueBytes(value, fixed = 256, checkpoint = () => {}) {
  const retained = retainedValueBytes(value, checkpoint);
  const bytes = retained * 2 + fixed;
  if (!Number.isSafeInteger(bytes)) fail('LIMIT_MEMORY', { layer: 1 });
  return bytes;
}

function exactPathProfileAdapter(value, profile, caseMode) {
  try {
    if (!value || typeof value !== 'object') throw new TypeError('missing adapter');
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError('invalid adapter');
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.length !== 3 || !keys.includes('profile') || !keys.includes('caseMode') ||
        !keys.includes('validate') ||
        keys.some(key => typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value'))) {
      throw new TypeError('adapter must contain exact data properties');
    }
    const selected = descriptors.profile.value;
    const selectedCaseMode = descriptors.caseMode.value;
    const validate = descriptors.validate.value;
    if (selected !== profile || selectedCaseMode !== caseMode || typeof validate !== 'function') {
      throw new TypeError('adapter pin mismatch');
    }
    return Object.freeze({ profile: selected, caseMode: selectedCaseMode, validate });
  } catch {
    semanticFail('PATH_PROFILE_INVALID');
    return undefined;
  }
}

function exactPathProfileDecision(rawDecision) {
  try {
    if (!rawDecision || typeof rawDecision !== 'object') throw new TypeError('invalid decision');
    const prototype = Object.getPrototypeOf(rawDecision);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError('invalid decision');
    const descriptors = Object.getOwnPropertyDescriptors(rawDecision);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some(key => typeof key !== 'string' ||
        !['accepted', 'repositoryKey', 'platformKey'].includes(key) ||
        !Object.hasOwn(descriptors[key], 'value'))) {
      throw new TypeError('decision must contain only data properties');
    }
    const accepted = descriptors.accepted?.value;
    if (accepted === false && keys.length === 1) return Object.freeze({ accepted: false });
    if (accepted !== true || keys.length !== 3 || !descriptors.repositoryKey || !descriptors.platformKey) {
      throw new TypeError('accepted decision requires both collision keys');
    }
    return Object.freeze({
      accepted: true,
      repositoryKey: descriptors.repositoryKey.value,
      platformKey: descriptors.platformKey.value
    });
  } catch {
    semanticFail('PATH_PROFILE_INVALID');
    return undefined;
  }
}

function validPathProfileKey(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 65_536 ||
      !isUnicode15String(value)) return false;
  let scalars = 0;
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0);
    if (codePoint >= 0xd800 && codePoint <= 0xdfff) return false;
    scalars += 1;
    if (scalars > 32_768) return false;
  }
  return true;
}

function pathProfileKeyRetainedBytes(value) {
  const storage = Math.max(Buffer.byteLength(value, 'utf8'), value.length * 2);
  const retained = storage + 256;
  if (!Number.isSafeInteger(retained)) fail('LIMIT_MEMORY', { layer: 1 });
  return retained;
}

function leasedExpansion(value, reservation) {
  const lease = reservation.lease();
  Object.defineProperties(value, {
    retainedBytes: { value: lease.bytes, enumerable: true },
    release: { value: lease.release, enumerable: false }
  });
  return Object.freeze(value);
}

function repositoryCaseMode(value) {
  if (value !== 'case-sensitive' && value !== 'case-folded') {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return value;
}

function requireRepositoryContext(context) {
  requireSemanticLookup(context?.lookup);
  repositoryCaseMode(context?.caseMode);
  return context;
}

function expandTreeOwned(rootReference, lookup, descriptorReference, options = {}) {
  const caseMode = repositoryCaseMode(options.caseMode);
  requireSemanticLookup(lookup);
  const descriptorRef = ref(descriptorReference, 6);
  const lookupFailures = { best: undefined };
  const descriptorObject = collectLookupFailure(
    lookupFailures, () => lookup.resolve(descriptorRef, 6)
  );
  const descriptor = descriptorObject?.value;
  const hardLimits = options.hardLimits ?? lookup.hardLimits ?? {};
  const treeMaximum = configuredHardLimit('tree-entries', hardLimits['tree-entries']);
  const logicalMaximum = configuredHardLimit('logical-file-bytes', hardLimits['logical-file-bytes']);
  const reservation = derivedBuildReservation(lookup, options);
  reservation.reserve(512);
  const checkpoint = () => lookup.checkpoint?.();
  let allowed;
  const entries = new Map(); const fileIds = new Map();
  const observedEntries = [];
  const observedTreeDescriptors = [];
  const deferredRepositoryCodes = [];
  const visiting = new Set();
  const pathProfileRepositoryKeys = new Map(); const pathProfilePlatformKeys = new Map();
  let pathProfileChecked = false;
  let externalPathProfile;
  const validatePathProfile = path => {
    if (allowed.path === undefined) return;
    if (!pathProfileChecked && lookup.registry) {
      const operation = lookup.operation ?? validationOperation(lookup.mode);
      const decision = profileDecision(lookup.registry, allowed.path, operation);
      if (decision.family !== 'path') schemaFail();
      pathProfileChecked = true;
    }
    if (allowed.path === 'path.test/opaque@1') return;
    if (allowed.path === 'path.test/reject-reserved@1') {
      if (path.includes('reserved')) semanticFail('PATH_PROFILE_INVALID');
      return;
    }
    if (externalPathProfile) {
      let rawDecision;
      try {
        rawDecision = externalPathProfile.validate(Object.freeze({
          profile: allowed.path,
          caseMode,
          segments: Object.freeze([...path])
        }));
      } catch {
        semanticFail('PATH_PROFILE_INVALID');
        return;
      }
      const decision = exactPathProfileDecision(rawDecision);
      if (!decision || decision.accepted !== true) {
        semanticFail('PATH_PROFILE_INVALID');
        return;
      }
      if (!validPathProfileKey(decision.repositoryKey) || !validPathProfileKey(decision.platformKey) ||
          pathProfileRepositoryKeys.has(decision.repositoryKey) ||
          pathProfilePlatformKeys.has(decision.platformKey)) {
        semanticFail('PATH_PROFILE_INVALID');
        return;
      }
      const retained = pathProfileKeyRetainedBytes(decision.repositoryKey) +
        pathProfileKeyRetainedBytes(decision.platformKey);
      if (!Number.isSafeInteger(retained)) fail('LIMIT_MEMORY', { layer: 1 });
      reservation.reserve(retained);
      pathProfileRepositoryKeys.set(decision.repositoryKey, true);
      pathProfilePlatformKeys.set(decision.platformKey, true);
      return;
    }
    if (allowed.path.startsWith('path.opengamevcs/')) {
      semanticFail('PATH_PROFILE_INVALID');
      return;
    }
    fail('PROFILE_UNKNOWN', { layer: 3 });
  };
  try {
    // Discover the complete tree/content closure without using the native call
    // stack. Path semantics deliberately run only after this L2 phase, so a
    // hostile deep chain must remain resource-bounded and return a typed error
    // rather than overflowing JavaScript recursion first.
    const stack = [{ reference: rootReference, prefix: [], entries: undefined, index: 0, key: undefined }];
    while (stack.length > 0) {
      checkpoint();
      const frame = stack[stack.length - 1];
      if (frame.entries === undefined) {
        const key = refKey(frame.reference);
        if (visiting.has(key)) {
          deferredRepositoryCodes.push('PROVENANCE_CYCLE');
          stack.pop();
          continue;
        }
        reservation.reserve(256 + key.length * 2);
        visiting.add(key);
        frame.key = key;
        const resolvedTree = collectLookupFailure(
          lookupFailures, () => lookup.edge(frame.reference, 3)
        );
        if (!resolvedTree) {
          visiting.delete(frame.key);
          stack.pop();
          continue;
        }
        const tree = resolvedTree.value;
        collectLookupFailure(lookupFailures, () => lookup.edge(tree.get(16), 6));
        observedTreeDescriptors.push(tree.get(16));
        frame.entries = collectLookupFailure(lookupFailures, () => asArray(tree.get(17)));
        if (!frame.entries) {
          visiting.delete(frame.key);
          stack.pop();
          continue;
        }
        enforceHardLimit(undefined, 'tree-entries', frame.entries.length,
          { maximum: treeMaximum, code: 'LIMIT_COUNT', layer: 2 });
      }
      if (frame.index >= frame.entries.length) {
        visiting.delete(frame.key);
        stack.pop();
        continue;
      }
      const entry = collectLookupFailure(
        lookupFailures, () => asMap(frame.entries[frame.index++])
      );
      if (!entry) continue;
      // Charge the retained path copy, observation, and state projection before
      // copying the prefix. The wrapper array is constant-size and only lends
      // caller-owned values to the allocation-free retained-size walk.
      reservation.reserve(derivedValueBytes([frame.prefix, entry], 640, checkpoint));
      const projection = collectLookupFailure(lookupFailures, () => {
        const path = [...frame.prefix, entry.get(0)];
        return { path, state: entryStateFromTree(path, entry) };
      });
      if (!projection) continue;
      const { path, state } = projection;
      lookup[LOOKUP_SCRATCH](canonicalEncodedLength(state));
      const observation = { entry, path, state, manifest: undefined };
      observedEntries.push(observation);
      if (entry.get(1) === 1) {
        reservation.reserve(192);
        stack.push({ reference: entry.get(4), prefix: path, entries: undefined, index: 0, key: undefined });
      } else {
        const manifestObject = collectLookupFailure(
          lookupFailures, () => lookup.edge(entry.get(4), 2)
        );
        if (!manifestObject) continue;
        const logicalLength = asUint(manifestObject.value.get(16));
        enforceHardLimit(undefined, 'logical-file-bytes', logicalLength,
          { maximum: logicalMaximum, code: 'LIMIT_LOGICAL_BYTES', layer: 2 });
        observation.manifest = options.verifyContent === false
          ? Object.freeze({ declared: logicalLength, manifest: manifestObject.value, parts: undefined })
          : manifestClosure(manifestObject, lookup, lookupFailures);
      }
    }
    throwSelectedLookupFailure(lookupFailures);
    lookup[LOOKUP_FINISH_REGISTRY]();
    allowed = descriptorProfiles(descriptor, reservation, checkpoint);
    collectRepositoryStage(() => {
      for (const code of deferredRepositoryCodes) semanticFail(code);
      for (const actual of observedTreeDescriptors) {
        if (!sameRef(actual, descriptorRef)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
      }
      if (allowed.path !== undefined && !allowed.path.startsWith('path.test/')) {
        externalPathProfile = exactPathProfileAdapter(
          options.validatePathProfile, allowed.path, caseMode
        );
      }
      for (const observation of observedEntries) {
        const { entry, path, state } = observation;
        try { validateComposedPath(path, hardLimits); }
        catch (error) {
          if (!(error instanceof OgvcsError) || error.layer !== 3 ||
              error.stage !== 'repository-semantics') throw error;
          semanticFail(error.code);
        }
        validatePathProfile(path);
        const pkey = pathKey(path);
        if (entries.has(pkey)) semanticFail('CHANGESET_TRANSITION_INVALID');
        const fkey = stateFileKey(state);
        if (fileIds.has(fkey)) semanticFail('FILEID_DUPLICATE_IN_TREE');
        if (!entries.has(pkey)) entries.set(pkey, state);
        if (!fileIds.has(fkey)) fileIds.set(fkey, pkey);
        if (!allowed.content.has(profileText(entry.get(6)))) {
          semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
        }
        if (observation.manifest !== undefined) {
          const manifest = observation.manifest.manifest;
          if (!allowed.chunks.has(profileText(manifest.get(18)))) {
            semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
          }
          const checked = observation.manifest.parts === undefined
            ? { logicalLength: observation.manifest.declared }
            : verifyManifestRepository(observation.manifest, lookup);
          if (checked.logicalLength !== asUint(entry.get(5))) {
            semanticFail('TREE_ENTRY_TARGET_INVALID');
          }
        }
      }
    });
    return leasedExpansion({
      descriptor: descriptorRef, descriptorValue: descriptor, entries, fileIds
    }, reservation);
  } finally {
    // On success leasedExpansion transfers the retained-memory charge to the
    // returned result. Internal consumers release it when the maps stop being
    // live; direct callers receive the same explicit release boundary.
    reservation.release();
  }
}

/**
 * Expand one tree under a bounded operation. Returned maps become
 * caller-owned at the successful return boundary; high-level repository
 * validators use expandTreeOwned so simultaneous derived state stays charged.
 */
export function expandTree(rootReference, lookup, descriptorReference, options = {}) {
  requireSemanticLookup(lookup);
  repositoryCaseMode(options.caseMode);
  return lookup[LOOKUP_OPERATION](() => {
    const owned = expandTreeOwned(rootReference, lookup, descriptorReference, options);
    const result = Object.freeze({
      descriptor: owned.descriptor,
      descriptorValue: owned.descriptorValue,
      entries: owned.entries,
      fileIds: owned.fileIds
    });
    owned.release();
    return result;
  });
}

function emptyGroups() {
  return Object.freeze({ groups: new Map(), retainedBytes: 0, release() {} });
}
function groupsFromSet(reference, lookup, descriptorReference) {
  if (!reference) return emptyGroups();
  const reservation = derivedBuildReservation(lookup);
  reservation.reserve(256);
  try {
    const set = lookup.edge(reference, 5).value;
    if (!sameRef(set.get(16), descriptorReference)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
    const descriptor = lookup.resolve(descriptorReference, 6).value;
    const checkpoint = () => lookup.checkpoint?.();
    const allowed = descriptorProfiles(descriptor, reservation, checkpoint).groups;
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
      reservation.reserve(derivedValueBytes(group, 384, checkpoint));
    }
    const lease = reservation.lease();
    return Object.freeze({
      groups: new Map(groups.map(group => [groupKey(group), cloneValue(group)])),
      retainedBytes: lease.bytes,
      release: lease.release
    });
  } finally {
    reservation.release();
  }
}
function cloneState(state, checkpoint = () => {}) {
  if (!(state?.entries instanceof Map) || !(state?.groups instanceof Map)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const entries = new Map(); const groups = new Map();
  for (const [key, value] of state.entries) { checkpoint(); entries.set(key, cloneValue(value)); }
  for (const [key, value] of state.groups) { checkpoint(); groups.set(key, cloneValue(value)); }
  return { entries, groups };
}
function retainedValueBytes(value, checkpoint = () => {}, depth = 0) {
  checkpoint();
  if (depth > 256) fail('LIMIT_MEMORY', { layer: 1 });
  if (value === null || value === undefined || typeof value === 'boolean' ||
      typeof value === 'number' || typeof value === 'bigint') return 32;
  if (typeof value === 'string') {
    const storage = Math.max(value.length * 2, Buffer.byteLength(value, 'utf8'));
    if (!Number.isSafeInteger(storage)) fail('LIMIT_MEMORY', { layer: 1 });
    return storage + 128;
  }
  if (value instanceof Uint8Array) {
    const bytes = value.length * 2 + 128;
    if (!Number.isSafeInteger(bytes)) fail('LIMIT_MEMORY', { layer: 1 });
    return bytes;
  }
  let bytes;
  if (Array.isArray(value)) {
    bytes = 128 + value.length * 16;
    if (!Number.isSafeInteger(bytes)) fail('LIMIT_MEMORY', { layer: 1 });
    for (const item of value) {
      const retained = retainedValueBytes(item, checkpoint, depth + 1);
      if (retained > Number.MAX_SAFE_INTEGER - bytes) fail('LIMIT_MEMORY', { layer: 1 });
      bytes += retained;
    }
    return bytes;
  }
  if (value instanceof Map) {
    bytes = 256 + value.size * 64;
    if (!Number.isSafeInteger(bytes)) fail('LIMIT_MEMORY', { layer: 1 });
    for (const [key, item] of value) {
      for (const part of [key, item]) {
        const retained = retainedValueBytes(part, checkpoint, depth + 1);
        if (retained > Number.MAX_SAFE_INTEGER - bytes) fail('LIMIT_MEMORY', { layer: 1 });
        bytes += retained;
      }
    }
    return bytes;
  }
  if (typeof value === 'object') {
    let descriptors;
    try { descriptors = Object.getOwnPropertyDescriptors(value); }
    catch { fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' }); }
    const keys = Reflect.ownKeys(descriptors);
    bytes = 256 + keys.length * 64;
    if (!Number.isSafeInteger(bytes)) fail('LIMIT_MEMORY', { layer: 1 });
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (typeof key !== 'string' || !Object.hasOwn(descriptor, 'value')) {
        fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
      }
      for (const part of [key, descriptor.value]) {
        const retained = retainedValueBytes(part, checkpoint, depth + 1);
        if (retained > Number.MAX_SAFE_INTEGER - bytes) fail('LIMIT_MEMORY', { layer: 1 });
        bytes += retained;
      }
    }
    return bytes;
  }
  fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
}
function stateMemoryBytes(state, checkpoint = () => {}) {
  if (!(state?.entries instanceof Map) || !(state?.groups instanceof Map)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  let bytes = 256;
  const add = value => {
    const retained = retainedValueBytes(value, checkpoint) + 256;
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
    const retained = retainedValueBytes(value, () => context.lookup.checkpoint?.()) + 512;
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
function requireFileIdAbsent(entries, state, checkpoint = () => {}, code = 'FILEID_ALREADY_CONSUMED') {
  const expected = stateFileKey(state);
  for (const current of entries.values()) {
    checkpoint();
    if (stateFileKey(current) === expected) semanticFail(code);
  }
}
function requireParent(entries, state) {
  const parent = parentParts(state.get(0)); if (parent.length === 0) return;
  const value = entries.get(pathKey(parent)); if (!value || value.get(1) !== 1) semanticFail('CHANGESET_TRANSITION_INVALID');
}
function checkpointStructure(value, checkpoint, depth = 0) {
  checkpoint();
  if (depth > 256) schemaFail();
  if (Array.isArray(value)) {
    for (const item of value) checkpointStructure(item, checkpoint, depth + 1);
  } else if (value instanceof Map) {
    for (const [key, item] of value) {
      checkpointStructure(key, checkpoint, depth + 1);
      checkpointStructure(item, checkpoint, depth + 1);
    }
  }
}
function sameExcept(left, right, ignored, checkpoint = () => {}) {
  checkpointStructure(left, checkpoint);
  checkpointStructure(right, checkpoint);
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
  const reservation = derivedBuildReservation(lookup);
  reservation.reserve(256 + start.length * 2);
  const seen = new Set(); const stack = [descendant];
  try {
  while (stack.length) {
    lookup.checkpoint?.();
    const current = stack.pop(); const key = refKey(current); if (seen.has(key)) continue;
    reservation.reserve(256 + key.length * 2); seen.add(key);
    for (const parent of snapshotObject(current, lookup).get(17)) {
      lookup.checkpoint?.();
      const parentKey = refKey(parent); if (parentKey === target) return true;
      reservation.reserve(192 + parentKey.length * 2); stack.push(parent);
    }
  }
  return false;
  } finally {
    reservation.release();
  }
}

function expandedState(treeReference, groupReference, lookup, descriptorReference, options) {
  const tree = expandTreeOwned(treeReference, lookup, descriptorReference, options);
  let groups;
  try {
    groups = groupsFromSet(groupReference, lookup, descriptorReference);
  } catch (error) {
    tree.release();
    throw error;
  }
  let released = false;
  return Object.freeze({
    entries: tree.entries,
    groups: groups.groups,
    fileIds: tree.fileIds,
    retainedBytes: tree.retainedBytes + groups.retainedBytes,
    release() {
      if (released) return;
      released = true;
      groups.release();
      tree.release();
    }
  });
}

function stateAtSnapshot(snapshotReference, lookup, descriptorReference, options) {
  const snapshot = snapshotObject(snapshotReference, lookup); if (!sameRef(snapshot.get(16), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
  return expandedState(
    snapshot.get(18), snapshot.get(20), lookup, descriptorReference, options
  );
}

function validateRestore(operation, after, baseSnapshot, lookup, descriptorReference, options) {
  const proof = operation.get(6); if (!sameRef(proof.get(0), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
  if (!baseSnapshot) semanticFail('FILEID_RESTORE_PROOF_INVALID');
  const sourceSnapshot = proof.get(1); const sourcePath = proof.get(2); const deleted = proof.get(3);
  if (!isAncestor(sourceSnapshot, deleted, lookup, false) || !isAncestor(deleted, baseSnapshot, lookup, true)) semanticFail('FILEID_RESTORE_PROOF_INVALID');
  const source = stateAtSnapshot(sourceSnapshot, lookup, descriptorReference, options);
  try {
    const sourceState = source.entries.get(pathKey(sourcePath));
    if (!sourceState || !sameValue(sourceState, after)) semanticFail('FILEID_RESTORE_PROOF_INVALID');
    const deleteSnapshot = snapshotObject(deleted, lookup);
    if (!sameRef(deleteSnapshot.get(16), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
    const changeSet = lookup.edge(deleteSnapshot.get(19), 4).value;
    if (!sameRef(changeSet.get(16), descriptorReference)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
    let matching = false;
    for (const candidate of changeSet.get(18)) {
      lookup.checkpoint?.();
      if (candidate.get(1) === 6 && sameValue(candidate.get(2), sourceState)) {
        matching = true;
        break;
      }
    }
    if (!matching) semanticFail('FILEID_RESTORE_PROOF_INVALID');
  } finally {
    source.release();
  }
}

function findConflict(conflictSet, id, checkpoint = () => {}) {
  for (const record of conflictSet?.get(17) ?? []) {
    checkpoint();
    if (equalBytes(record.get(0), id)) return record;
  }
  return undefined;
}
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

function preflightDeclaredTransitions(operations, checkpoint = () => {}) {
  for (let sequence = 0; sequence < operations.length; sequence += 1) {
    checkpoint();
    const operation = operations[sequence];
    if (Number(operation.get(0)) !== sequence) {
      fail('CHANGESET_SEQUENCE_INVALID', { layer: 2 });
    }
    const code = operation.get(1);
    if (code === 2) {
      const before = operation.get(2); const after = operation.get(3);
      checkpointStructure(before, checkpoint); checkpointStructure(after, checkpoint);
      if (statePathKey(before) !== statePathKey(after) ||
          stateFileKey(before) !== stateFileKey(after) || sameValue(before, after)) {
        semanticFail('CHANGESET_TRANSITION_INVALID');
      }
    } else if (code === 3) {
      const after = operation.get(3); const source = operation.get(4);
      checkpointStructure(source, checkpoint); checkpointStructure(after, checkpoint);
      if (source.get(1) === 1 || stateFileKey(source) === stateFileKey(after) ||
          !sameExcept(source, after, [0, 2], checkpoint)) semanticFail('CHANGESET_TRANSITION_INVALID');
    } else if (code === 4 || code === 5) {
      const before = operation.get(2); const after = operation.get(3);
      checkpointStructure(before, checkpoint); checkpointStructure(after, checkpoint);
      const invalidRelationship = code === 4
        ? pathKey(parentParts(before.get(0))) === pathKey(parentParts(after.get(0))) ||
          basename(before.get(0)) !== basename(after.get(0))
        : pathKey(parentParts(before.get(0))) !== pathKey(parentParts(after.get(0))) ||
          basename(before.get(0)) === basename(after.get(0));
      if (!sameExcept(before, after, [0], checkpoint) || invalidRelationship ||
          (before.get(1) === 1 && startsWithPath(statePath(after), statePath(before)))) {
        semanticFail('CHANGESET_TRANSITION_INVALID');
      }
    }
  }
}

function preflightReplayClosure(changeSet, operations, context) {
  const reservation = derivedBuildReservation(context.lookup, context);
  reservation.reserve(512);
  const lookupFailures = { best: undefined };
  const scheduled = new Set();
  const stack = [];
  const enqueue = (value, expectedKind) => {
    const reference = ref(value, expectedKind);
    const key = refKey(reference);
    if (scheduled.has(key)) return;
    reservation.reserve(256 + key.length * 2);
    scheduled.add(key);
    stack.push(reference);
  };
  const enqueueEntryState = state => {
    const map = asMap(state);
    if (!map.has(4)) return;
    enqueue(map.get(4), asUint(map.get(1)) === 1n ? 3 : 2);
  };
  const enqueueChangeSet = value => {
    enqueue(value.get(16), 6);
    if (value.has(17)) enqueue(value.get(17), 7);
    for (const operation of asArray(value.get(18))) {
      context.lookup.checkpoint?.();
      for (const key of [2, 3, 4]) {
        if (operation.has(key)) enqueueEntryState(operation.get(key));
      }
      if (operation.get(10) === 1 && operation.has(11)) {
        enqueueEntryState(operation.get(11));
      }
      if (operation.has(5)) {
        const allocationProof = asMap(operation.get(5));
        enqueue(allocationProof.get(0), 6);
      }
      if (operation.get(1) === 7 && operation.has(6)) {
        const proof = asMap(operation.get(6));
        enqueue(proof.get(0), 6);
        for (const key of [1, 3]) if (proof.has(key)) enqueue(proof.get(key), 7);
      }
    }
  };
  try {
    enqueue(context.descriptor, 6);
    enqueueChangeSet(changeSet);
    while (stack.length > 0) {
      context.lookup.checkpoint?.();
      const reference = stack.pop();
      const resolved = collectLookupFailure(
        lookupFailures, () => context.lookup.edge(reference, reference.kind)
      );
      if (!resolved) continue;
      const value = resolved.value;
      if (reference.kind === 7) {
        enqueue(value.get(16), 6);
        for (const parent of asArray(value.get(17))) enqueue(parent, 7);
        enqueue(value.get(18), 3);
        enqueue(value.get(19), 4);
        if (value.has(20)) enqueue(value.get(20), 5);
      } else if (reference.kind === 4) {
        enqueueChangeSet(value);
      } else if (reference.kind === 3) {
        enqueue(value.get(16), 6);
        for (const rawEntry of asArray(value.get(17))) {
          const entry = asMap(rawEntry);
          enqueue(entry.get(4), entry.get(1) === 1 ? 3 : 2);
        }
      } else if (reference.kind === 2 && context.verifyContent !== false) {
        for (const rawPart of asArray(value.get(19))) {
          enqueue(asMap(rawPart).get(0), 1);
        }
      } else if (reference.kind === 5) {
        enqueue(value.get(16), 6);
      }
    }
    throwSelectedLookupFailure(lookupFailures);
  } finally {
    reservation.release();
  }
}

function replayChangeSetInternal(changeSetReference, base, context) {
  requireRepositoryContext(context);
  const { lookup, descriptor } = context; const changeSetRef = ref(changeSetReference, 4); const changeSet = lookup.resolve(changeSetRef, 4).value;
  const operations = asArray(changeSet.get(18));
  enforceHardLimit(undefined, 'change-set-operations', operations.length, {
    maximum: (context.hardLimits ?? lookup.hardLimits)?.['change-set-operations'],
    code: 'LIMIT_COUNT', layer: 2
  });
  const checkpoint = () => lookup.checkpoint?.();
  preflightReplayClosure(changeSet, operations, context);
  lookup[LOOKUP_FINISH_REGISTRY]();
  if (!sameRef(changeSet.get(16), descriptor)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
  preflightDeclaredTransitions(operations, checkpoint);
  const immutableBaseReservation = derivedBuildReservation(lookup, context);
  const immutableBaseFileIds = new Set();
  try {
  for (const entry of base.entries?.values?.() ?? []) {
    checkpoint();
    const key = stateFileKey(entry);
    if (!immutableBaseFileIds.has(key)) immutableBaseReservation.reserve(256 + key.length * 2);
    immutableBaseFileIds.add(key);
  }
  const state = cloneState(base, checkpoint); const allocations = []; const restorations = [];
  for (let sequence = 0; sequence < operations.length; sequence++) {
    checkpoint();
    const operation = operations[sequence];
    if (Number(operation.get(0)) !== sequence) fail('CHANGESET_SEQUENCE_INVALID', { layer: 2 });
    const code = operation.get(1);
    if (code === 1) {
      const after = operation.get(3); requireAbsent(state.entries, after);
      requireFileIdAbsent(state.entries, after, checkpoint);
      requireParent(state.entries, after); state.entries.set(statePathKey(after), cloneValue(after)); allocations.push({ operation, sequence, after, code });
    } else if (code === 2) {
      const before = operation.get(2); const after = operation.get(3); getExact(state.entries, before, 'FILEID_SOURCE_MISMATCH');
      if (statePathKey(before) !== statePathKey(after) || stateFileKey(before) !== stateFileKey(after) || sameValue(before, after)) semanticFail('CHANGESET_TRANSITION_INVALID');
      state.entries.set(statePathKey(after), cloneValue(after));
    } else if (code === 3) {
      const after = operation.get(3); const source = operation.get(4); getExact(state.entries, source, 'FILEID_SOURCE_MISMATCH'); requireAbsent(state.entries, after);
      requireFileIdAbsent(state.entries, after, checkpoint);
      requireParent(state.entries, after);
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
      if (state.entries.has(statePathKey(after))) semanticFail('FILEID_RESTORE_PROOF_INVALID');
      if (immutableBaseFileIds.has(stateFileKey(after))) semanticFail('FILEID_RESTORE_PROOF_INVALID');
      requireFileIdAbsent(state.entries, after, checkpoint, 'FILEID_RESTORE_PROOF_INVALID');
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
      const record = findConflict(context.conflictSet, operation.get(9), checkpoint);
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
  } finally {
    immutableBaseReservation.release();
  }
}

export function replayChangeSet(changeSetReference, base, context) {
  requireRepositoryContext(context);
  return context.lookup[LOOKUP_OPERATION](() => {
  const checkpoint = () => context.lookup.checkpoint?.();
  const baseBytes = stateMemoryBytes(base, checkpoint);
  const growthBytes = replayWorkingMemoryBytes(changeSetReference, base, context);
  if (growthBytes > Number.MAX_SAFE_INTEGER - baseBytes) fail('LIMIT_MEMORY', { layer: 1 });
  const reservation = baseBytes + growthBytes;
  reserveState(context.lookup, reservation);
  try {
    return replayChangeSetInternal(changeSetReference, base, context);
  } finally {
    releaseState(context.lookup, reservation);
  }
  });
}

function lifetimeChangeSetRef(value) {
  const result = ref(value);
  if (result.kind !== 4) {
    fail('OBJECT_REFERENCE_KIND_MISMATCH', { layer: 2, stage: 'known-schema' });
  }
  return result;
}

function exactPlainRecord(value, requiredKeys, optionalKeys = []) {
  if (!value || typeof value !== 'object' || nodeTypes.isProxy(value)) schemaFail();
  let prototype; let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    schemaFail();
  }
  if (prototype !== Object.prototype && prototype !== null) schemaFail();
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.length < requiredKeys.length ||
      requiredKeys.some(key => !Object.hasOwn(descriptors, key)) ||
      keys.some(key => typeof key !== 'string' || !allowed.has(key) ||
        !Object.hasOwn(descriptors[key], 'value'))) schemaFail();
  return Object.freeze(Object.fromEntries(keys.map(key => [key, descriptors[key].value])));
}

function preflightLifetimeRow(value) {
  if (nodeTypes.isProxy(value)) schemaFail();
  if (value instanceof Map) {
    const validated = validateLogicalRecord(value, { semantic: false });
    if (validated.type !== 4) schemaFail();
    return;
  }
  exactPlainRecord(value,
    ['fileId', 'firstChangeSet', 'firstOperation', 'origin'],
    ['descriptor', 'importMappingKey']);
}

function preflightImportMappingRow(value) {
  if (nodeTypes.isProxy(value)) schemaFail();
  if (value instanceof Map) {
    const validated = validateLogicalRecord(value, { semantic: false });
    if (validated.type !== 5) schemaFail();
    return;
  }
  exactPlainRecord(value, [
    'descriptor', 'fileId', 'importerProfile', 'mappingKey', 'sourceIdentityDigest',
    'sourceNamespaceDigest', 'state'
  ]);
}

function normalizeLifetime(value) {
  if (value instanceof Map) {
    const validated = validateLogicalRecord(value, { semantic: false });
    if (validated.type !== 4) schemaFail();
    return {
      descriptor: ref(value.get(16), 6),
      fileId: fileKey(value.get(17)),
      origin: value.get(18),
      firstChangeSet: lifetimeChangeSetRef(value.get(19)),
      firstOperation: Number(asUint(value.get(20))),
      importMappingKey: value.has(21) ? hex(value.get(21)) : undefined
    };
  }
  const row = exactPlainRecord(value,
    ['fileId', 'firstChangeSet', 'firstOperation', 'origin'],
    ['descriptor', 'importMappingKey']);
  const origins = { 'native-create': 1, 'native-copy': 2, import: 3 };
  const mappingKey = row.importMappingKey === undefined ? undefined : hex(decodeHex(row.importMappingKey, 32));
  return {
    descriptor: row.descriptor === undefined ? undefined : ref(row.descriptor, 6),
    fileId: fileKey(row.fileId),
    origin: origins[row.origin] ?? row.origin,
    firstChangeSet: lifetimeChangeSetRef(row.firstChangeSet),
    firstOperation: Number(asUint(row.firstOperation)),
    importMappingKey: mappingKey
  };
}
function normalizeImport(value) {
  if (value instanceof Map) {
    const validated = validateLogicalRecord(value, { semantic: false });
    if (validated.type !== 5) schemaFail();
    return {
      descriptor: ref(value.get(16), 6),
      importer: profileText(value.get(17)),
      namespace: hex(value.get(18)),
      identity: hex(value.get(19)),
      fileId: fileKey(value.get(20)),
      state: value.get(21),
      serializedMapping: true
    };
  }
  const row = exactPlainRecord(value, [
    'descriptor', 'fileId', 'importerProfile', 'mappingKey', 'sourceIdentityDigest',
    'sourceNamespaceDigest', 'state'
  ]);
  return {
    descriptor: ref(row.descriptor, 6),
    importer: profileText(ProfileRef.parse(row.importerProfile)),
    namespace: hex(decodeHex(row.sourceNamespaceDigest, 32)),
    identity: hex(decodeHex(row.sourceIdentityDigest, 32)),
    mappingKey: hex(decodeHex(row.mappingKey, 32)),
    fileId: fileKey(row.fileId),
    state: typeof row.state === 'string' ? ({ reserved: 1, materialized: 2, published: 3 })[row.state] : row.state
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

function lifetimeWorkspaceBytes(context, checkpoint) {
  let bytes = 2_048;
  const add = value => {
    const retained = retainedValueBytes(value, checkpoint) + 512;
    if (retained > Number.MAX_SAFE_INTEGER - bytes) fail('LIMIT_MEMORY', { layer: 1 });
    bytes += retained;
  };
  for (const collection of [
    context.lifetimeRecords ?? [], context.importMappings ?? [], context.allocations ?? [],
    context.workingLifetimeAdditions ?? [], context.restorations ?? []
  ]) {
    for (const value of collection) add(value);
  }
  for (const value of context.entries?.values?.() ?? []) add(value);
  return bytes;
}

function validateLifetimeAndImportsInternal(context, {
  allowUnrelatedWorking = false,
  requestImporter
} = {}) {
  const checkpoint = () => context.lookup?.checkpoint?.();
  // Prove every raw row is inert and exact before any resource traversal can
  // consult an accessor/Proxy or any later registry/repository decision can
  // hide a malformed row. The subsequent size pass is therefore data-only.
  for (const raw of context.lifetimeRecords ?? []) { checkpoint(); preflightLifetimeRow(raw); }
  for (const raw of context.importMappings ?? []) { checkpoint(); preflightImportMappingRow(raw); }
  for (const raw of context.workingLifetimeAdditions ?? []) { checkpoint(); preflightLifetimeRow(raw); }
  const reservation = derivedBuildReservation(context.lookup, context);
  reservation.reserve(lifetimeWorkspaceBytes(context, checkpoint));
  let completed = false;
  try {
  // Snapshot every caller-controlled row before registry or repository
  // semantics. This is the raw authenticated-state boundary: a later malformed
  // row or wrong profile family must not be hidden by an earlier lifecycle or
  // duplicate/mapping decision.
  const priorInputs = [];
  for (const raw of context.lifetimeRecords ?? []) { checkpoint(); priorInputs.push(normalizeLifetime(raw)); }
  const mappingInputs = [];
  for (const raw of context.importMappings ?? []) { checkpoint(); mappingInputs.push(normalizeImport(raw)); }
  const workingInputs = [];
  for (const raw of context.workingLifetimeAdditions ?? []) { checkpoint(); workingInputs.push(normalizeLifetime(raw)); }

  const mappingProfiles = [];
  for (const mapping of mappingInputs) {
    checkpoint();
    if (mapping.descriptor === undefined ||
        (mapping.serializedMapping !== true && mapping.mappingKey === undefined)) schemaFail();
    const importer = ProfileRef.parse(mapping.importer);
    const known = context.lookup.registry.profiles.get(importer.toString());
    if (known !== undefined && known.family !== 'importer') schemaFail();
    mappingProfiles.push(importer);
  }
  if (requestImporter !== undefined) {
    const known = context.lookup.registry.profiles.get(requestImporter.toString());
    if (known !== undefined && known.family !== 'importer') schemaFail();
  }
  let missingLifetimeEvidence = false;
  for (const record of [...priorInputs, ...workingInputs]) {
    checkpoint();
    try { context.lookup.resolve(record.firstChangeSet, 4); }
    catch (error) {
      if (error instanceof OgvcsError && error.code === 'OBJECT_REFERENCE_MISSING') {
        missingLifetimeEvidence = true;
        continue;
      }
      throw error;
    }
  }
  for (const importer of mappingProfiles) {
    checkpoint();
    profileDecision(context.lookup.registry, importer,
      context.lookup.operation ?? validationOperation(context.lookup.mode));
  }
  if (requestImporter !== undefined) {
    checkpoint();
    profileDecision(context.lookup.registry, requestImporter,
      context.lookup.operation ?? validationOperation(context.lookup.mode));
  }
  context.lookup[LOOKUP_FINISH_REGISTRY]();
  if (missingLifetimeEvidence) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID');

  const prior = new Map();
  for (const record of priorInputs) { checkpoint(); if (prior.has(record.fileId)) semanticFail('FILEID_LIFETIME_EVIDENCE_INVALID'); prior.set(record.fileId, record); }
  const mappings = new Map(); const mappingsByKey = new Map(); const mappedFiles = new Map();
  for (const mapping of mappingInputs) {
    checkpoint();
    if (!sameRef(mapping.descriptor, context.descriptor)) semanticFail('FILEID_CROSS_REPOSITORY_PROOF');
    if (![1, 2, 3].includes(mapping.state)) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    const key = importMappingKey(context.descriptor, mapping);
    if (mapping.mappingKey !== undefined && mapping.mappingKey !== key) {
      semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    }
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
  const working = workingInputs;
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
  const lease = reservation.lease();
  completed = true;
  return Object.freeze({ prior, working, workingById, mappings, mappingsByKey, mappedFiles,
    retainedBytes: lease.bytes, release: lease.release });
  } finally {
    if (!completed) reservation.release();
  }
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
  try {
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
  } finally {
    validated.release();
  }
}

export function validateLifetimeAndImports(context) {
  requireRepositoryContext(context);
  return context.lookup[LOOKUP_OPERATION](() => {
  const validated = validateLifetimeAndImportsInternal(context);
  validated.release();
  return validated;
  });
}

/** Validate an idempotent import allocation request without mutating registry state. */
export function validateImportRequest(request, context) {
  requireRepositoryContext(context);
  return context.lookup[LOOKUP_OPERATION](() => {
  if (!request || typeof request !== 'object') schemaFail();
  let descriptors; let prototype;
  try {
    descriptors = Object.getOwnPropertyDescriptors(request);
    prototype = Object.getPrototypeOf(request);
  }
  catch { schemaFail(); }
  const allowedKeys = ['schema','operation','importerProfile','sourceNamespaceDigest',
    'sourceIdentityDigest','requestedFileId'];
  const keys = Reflect.ownKeys(descriptors);
  if (prototype !== Object.prototype ||
      keys.some(key => typeof key !== 'string' || !allowedKeys.includes(key) ||
        !Object.hasOwn(descriptors[key], 'value'))) schemaFail();
  const field = key => descriptors[key]?.value;
  if (field('schema') !== 'ogvcs.repository-format.v1.fileid-operation-input.v1' ||
      field('operation') !== 'import-file-id') schemaFail();
  const importerRef = ProfileRef.parse(field('importerProfile'));
  const importer = profileText(importerRef);
  // Finish every raw L2 projection before lifecycle. In particular, malformed
  // digest/FileID fields must outrank a conformance-only importer profile.
  const namespace = hex(decodeHex(field('sourceNamespaceDigest'), 32));
  const identity = hex(decodeHex(field('sourceIdentityDigest'), 32));
  const requestedFileId = fileKey(field('requestedFileId'));
  const validated = validateLifetimeAndImportsInternal(
    { ...context, allocations: [], workingLifetimeAdditions: context.workingLifetimeAdditions ?? [] },
    { allowUnrelatedWorking: true, requestImporter: importerRef }
  );
  try {
  const tuple = `${importer}\0${namespace}\0${identity}`;
  const key = importMappingKey(context.descriptor, { importer, namespace, identity });
  const existing = validated.mappings.get(tuple);
  if (existing) {
    if (existing.fileId !== requestedFileId || existing.key !== key) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
    return Object.freeze({ fileId: requestedFileId, mappingKey: key, state: existing.state, retry: true });
  }
  if (validated.prior.has(requestedFileId) || validated.workingById.has(requestedFileId)) {
    semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
  }
  if (validated.mappedFiles.has(requestedFileId)) semanticFail('FILEID_IMPORT_MAPPING_CONFLICT');
  return Object.freeze({ fileId: requestedFileId, mappingKey: key, state: 1, retry: false });
  } finally {
    validated.release();
  }
  });
}

function sideValue(side) { return side?.get(side.get(0) === 1 ? 1 : 2); }
function sideMatchesEntry(side, ids, paths) { if (!side || side.get(0) !== 1) return false; const state = side.get(1); return ids.includes(stateFileKey(state)) && paths.includes(statePathKey(state)); }
function sideMatchesGroup(side, id) { return side?.get(0) === 2 && groupKey(side.get(2)) === id; }

function resolveConflictEntryTarget(side, lookup, lookupFailures) {
  if (!side || side.get(0) !== 1) return;
  const state = asMap(side.get(1));
  if (!state.has(4)) return;
  const kind = asUint(state.get(1));
  collectLookupFailure(
    lookupFailures, () => lookup.edge(state.get(4), kind === 1n ? 3 : 2)
  );
}

export function validateConflictSet(reference, lookup, descriptor, options = {}) {
  requireSemanticLookup(lookup);
  return lookup[LOOKUP_OPERATION](() => {
  const owned = validateConflictSetOwned(reference, lookup, descriptor, options);
  try {
    return Object.freeze({ records: owned.records });
  } finally {
    // A direct result crosses the operation boundary and becomes caller-owned.
    // Composite repository validators retain the private lease instead.
    owned.release();
  }
  });
}

function validateConflictSetOwned(reference, lookup, descriptor, options = {}) {
  requireSemanticLookup(lookup);
  let owned;
  try {
    collectRepositoryStage(() => {
      owned = validateConflictSetStageOwned(reference, lookup, descriptor, options);
      return owned;
    });
    return owned;
  } catch (error) {
    owned?.release();
    throw error;
  }
}

function validateConflictSetStageOwned(reference, lookup, descriptor, options) {
  const reservation = derivedBuildReservation(lookup, options);
  let completed = false;
  try {
  if (!reference) {
    const lease = reservation.lease();
    completed = true;
    return Object.freeze({
      conflictSet: undefined,
      records: Object.freeze([]),
      retainedBytes: lease.bytes,
      release: lease.release
    });
  }
  const set = lookup.resolve(reference, 11).value;
  const lookupFailures = { best: undefined };
  // The repository descriptor is part of the direct conflict route's L2
  // closure, not merely a value compared during repository semantics.  An
  // absent or wrong-kind descriptor must therefore win before any record or
  // profile lifecycle decision.
  collectLookupFailure(lookupFailures, () => lookup.edge(ref(descriptor, 6), 6));
  collectLookupFailure(lookupFailures, () => lookup.edge(ref(set.get(16), 6), 6));
  const checkpoint = () => lookup.checkpoint?.();
  // The resolved conflict graph remains live while replay, state comparison,
  // and resolution-count validation run. Retain one conservative owned charge
  // for that complete graph before building any secondary conflict indexes.
  reservation.reserve(derivedValueBytes(set, 512, checkpoint));
  // Conflict closure is intentionally shallow: authenticate every direct
  // EntryState target occurrence, but do not traverse a target manifest's
  // chunks. Complete this L2 pass before descriptor/profile/replay semantics.
  for (const record of set.get(17)) {
    lookup.checkpoint?.();
    for (const key of [3, 4, 5]) {
      if (record.has(key)) resolveConflictEntryTarget(record.get(key), lookup, lookupFailures);
    }
    const resolution = record.get(6);
    if (resolution?.has(2)) {
      resolveConflictEntryTarget(resolution.get(2), lookup, lookupFailures);
    }
  }
  throwSelectedLookupFailure(lookupFailures);
  lookup[LOOKUP_FINISH_REGISTRY]();
  if (!sameRef(set.get(16), descriptor)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
  for (const record of set.get(17)) {
    lookup.checkpoint?.();
    const workspace = derivedBuildReservation(lookup);
    // Every identity/subject helper below constructs Map, Array, path-key and
    // hex-key views. Charge a conservative transient projection before the
    // first clone or canonical encoding, then release it per record.
    workspace.reserve(retainedValueBytes(record, () => lookup.checkpoint?.()) * 3 + 1_024);
    try {
    const preimage = new Map([[0, record.get(1)], [1, record.get(2)]]);
    for (const [source, target] of [[3, 2], [4, 3], [5, 4]]) if (record.has(source)) preimage.set(target, record.get(source));
    if (!equalBytes(record.get(0), hashConflictPreimage(preimage).bytes)) {
      fail('CONFLICT_ID_MISMATCH', { layer: 2 });
    }
    const kind = record.get(1); const subject = record.get(2); const subjectKind = subject[0];
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
    } finally {
      workspace.release();
    }
  }
  const lease = reservation.lease();
  completed = true;
  return Object.freeze({
    conflictSet: set,
    records: set.get(17),
    retainedBytes: lease.bytes,
    release: lease.release
  });
  } finally {
    if (!completed) reservation.release();
  }
}

function validateConflictOperations(records, operations, lookup) {
  const reservation = derivedBuildReservation(lookup);
  reservation.reserve(256);
  try {
  const counts = new Map();
  for (const operation of operations) {
    lookup?.checkpoint?.();
    if (operation.get(1) !== 11) continue;
    const key = conflictIdKey(operation.get(9));
    if (!counts.has(key)) reservation.reserve(256 + key.length * 2);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (const record of records) {
    lookup?.checkpoint?.();
    const resolved = record.get(6).get(0) === 1;
    if ((counts.get(conflictIdKey(record.get(0))) ?? 0) !== (resolved ? 1 : 0)) semanticFail('CONFLICT_RESOLUTION_MISMATCH');
  }
  } finally {
    reservation.release();
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

function configuredGroupFail() {
  fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
}

const ASSET_GROUP_OPTION_KEYS = Object.freeze([
  'lookup', 'registry', 'mode', 'operation', 'hardLimits',
  'groupProfileRules', 'uniqueExternalKeyProfiles',
  'now', 'memoryBytes', 'scratchBytes', 'maxTimeMs', 'maxObjects', 'maxBytes',
  'maxChunkBytes', 'maxEdges', 'maxMemoryBytes', 'maxScratchBytes'
]);

function inertAssetGroupOptions(value) {
  try {
    if (!value || typeof value !== 'object' || nodeTypes.isProxy(value)) configuredGroupFail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) configuredGroupFail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some(key =>
      typeof key !== 'string' || !ASSET_GROUP_OPTION_KEYS.includes(key) ||
      !Object.hasOwn(descriptors[key], 'value'))) configuredGroupFail();
    const result = {};
    for (const key of ASSET_GROUP_OPTION_KEYS) {
      const descriptor = descriptors[key];
      if (descriptor === undefined) continue;
      result[key] = descriptor.value;
    }
    if (result.hardLimits !== undefined) {
      const hardLimits = result.hardLimits;
      if (!hardLimits || typeof hardLimits !== 'object' || nodeTypes.isProxy(hardLimits)) {
        configuredGroupFail();
      }
      const prototype = Object.getPrototypeOf(hardLimits);
      if (prototype !== Object.prototype && prototype !== null) configuredGroupFail();
      const descriptors = Object.getOwnPropertyDescriptors(hardLimits);
      const allowed = ['asset-groups', 'asset-group-members'];
      if (Reflect.ownKeys(descriptors).some(key =>
        typeof key !== 'string' || !allowed.includes(key) ||
        !Object.hasOwn(descriptors[key], 'value'))) configuredGroupFail();
      const snapshot = {};
      for (const key of allowed) {
        const descriptor = descriptors[key];
        if (descriptor === undefined) continue;
        snapshot[key] = descriptor.value;
      }
      result.hardLimits = Object.freeze(snapshot);
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof OgvcsError) throw error;
    configuredGroupFail();
  }
}

function inertConfiguredArray(value, reservation, checkpoint) {
  try {
    if (nodeTypes.isProxy(value) || !Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Array.prototype) configuredGroupFail();
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    const length = lengthDescriptor?.value;
    if (!Number.isSafeInteger(length) || length < 0) configuredGroupFail();
    if (length > REPOSITORY_VALIDATION_LIMITS.maxObjects) {
      fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
    }
    reservation.reserve(length * 64 + 64);
    const result = [];
    for (let index = 0; index < length; index += 1) {
      checkpoint();
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) configuredGroupFail();
      result.push(descriptor.value);
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof OgvcsError) throw error;
    configuredGroupFail();
  }
}

function configuredProfileText(value) {
  try {
    if (nodeTypes.isProxy(value)) configuredGroupFail();
    if (typeof value === 'string') return ProfileRef.parse(value).toString();
    if (!value || Object.getPrototypeOf(value) !== ProfileRef.prototype) configuredGroupFail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const fields = ['namespace', 'id', 'major'];
    if (Reflect.ownKeys(descriptors).length !== fields.length || fields.some(key =>
      !Object.hasOwn(descriptors[key] ?? {}, 'value'))) configuredGroupFail();
    const namespace = descriptors.namespace;
    const id = descriptors.id;
    const major = descriptors.major;
    if (![namespace, id, major].every(descriptor => descriptor && Object.hasOwn(descriptor, 'value'))) {
      configuredGroupFail();
    }
    return new ProfileRef(namespace.value, id.value, major.value).toString();
  } catch {
    configuredGroupFail();
  }
}

function inertConfiguredRule(value, reservation, checkpoint) {
  try {
    if (!value || typeof value !== 'object' || nodeTypes.isProxy(value)) configuredGroupFail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) configuredGroupFail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const allowed = ['roles', 'uniqueExternalKeyProfiles'];
    if (Reflect.ownKeys(descriptors).some(key =>
      typeof key !== 'string' || !allowed.includes(key) ||
      !Object.hasOwn(descriptors[key], 'value'))) configuredGroupFail();
    const rolesDescriptor = descriptors.roles;
    const uniqueDescriptor = descriptors.uniqueExternalKeyProfiles;
    const rawRoles = inertConfiguredArray(rolesDescriptor?.value ?? [], reservation, checkpoint);
    const roles = [];
    for (const rawRole of rawRoles) {
      checkpoint();
      const tuple = inertConfiguredArray(rawRole, reservation, checkpoint);
      if (tuple.length < 1 || tuple.length > 3) configuredGroupFail();
      const role = configuredProfileText(tuple[0]);
      const minimum = tuple[1] ?? 0;
      const maximum = tuple[2] ?? Number.POSITIVE_INFINITY;
      if (!Number.isSafeInteger(minimum) || minimum < 0 ||
          (maximum !== Number.POSITIVE_INFINITY &&
           (!Number.isSafeInteger(maximum) || maximum < minimum))) configuredGroupFail();
      reservation.reserve(role.length * 2 + 128);
      roles.push(Object.freeze([role, minimum, maximum]));
    }
    const rawUnique = inertConfiguredArray(uniqueDescriptor?.value ?? [], reservation, checkpoint);
    const uniqueExternalKeyProfiles = [];
    for (const raw of rawUnique) {
      checkpoint();
      const profile = configuredProfileText(raw);
      reservation.reserve(profile.length * 2 + 64);
      uniqueExternalKeyProfiles.push(profile);
    }
    return Object.freeze({
      roles: Object.freeze(roles),
      uniqueExternalKeyProfiles: Object.freeze(uniqueExternalKeyProfiles)
    });
  } catch (error) {
    if (error instanceof OgvcsError) throw error;
    configuredGroupFail();
  }
}

function inertAssetGroupConfiguration(options, reservation, checkpoint) {
  const rules = new Map();
  const addRule = (profile, rawRule) => {
    const normalizedProfile = configuredProfileText(profile);
    const rule = inertConfiguredRule(rawRule, reservation, checkpoint);
    reservation.reserve(normalizedProfile.length * 2 + 192);
    rules.set(normalizedProfile, rule);
  };
  for (const [profile, rule] of FIXTURE_GROUP_RULES) addRule(profile, rule);
  const configuredRules = options.groupProfileRules;
  if (configuredRules !== undefined) {
    try {
      if (nodeTypes.isProxy(configuredRules)) configuredGroupFail();
      Map.prototype.entries.call(configuredRules);
      if (Object.getPrototypeOf(configuredRules) !== Map.prototype ||
          Reflect.ownKeys(configuredRules).length !== 0) configuredGroupFail();
      const size = Object.getOwnPropertyDescriptor(Map.prototype, 'size').get.call(configuredRules);
      if (size > REPOSITORY_VALIDATION_LIMITS.maxObjects) {
        fail('LIMIT_COUNT', { layer: 1, stage: 'configured-resource-preflight' });
      }
      reservation.reserve(size * 128 + 64);
      for (const [profile, rule] of Map.prototype.entries.call(configuredRules)) {
        checkpoint();
        addRule(profile, rule);
      }
    } catch (error) {
      if (error instanceof OgvcsError) throw error;
      configuredGroupFail();
    }
  }
  const uniqueExternalKeyProfiles = new Set(FIXTURE_UNIQUE_EXTERNAL_KEYS);
  const configuredUnique = options.uniqueExternalKeyProfiles === undefined
    ? []
    : inertConfiguredArray(options.uniqueExternalKeyProfiles, reservation, checkpoint);
  for (const raw of configuredUnique) {
    checkpoint();
    const profile = configuredProfileText(raw);
    if (!uniqueExternalKeyProfiles.has(profile)) {
      reservation.reserve(profile.length * 2 + 192);
      uniqueExternalKeyProfiles.add(profile);
    }
  }
  return Object.freeze({ rules, uniqueExternalKeyProfiles });
}

function exactInertGroupMap(value) {
  try {
    if (nodeTypes.isProxy(value)) schemaFail();
    // Brand-check first. Map.prototype rejects Proxy receivers without
    // consulting their getPrototypeOf/ownKeys traps.
    Map.prototype.entries.call(value);
    if (Object.getPrototypeOf(value) !== Map.prototype || Reflect.ownKeys(value).length !== 0) {
      schemaFail();
    }
    return value;
  } catch (error) {
    if (error instanceof OgvcsError) throw error;
    schemaFail();
  }
}

function exactInertGroupArray(value) {
  try {
    if (nodeTypes.isProxy(value) || !Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Array.prototype) schemaFail();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const length = descriptors.length?.value;
    if (!Number.isSafeInteger(length) || length < 0 ||
        Reflect.ownKeys(descriptors).some(key => {
          if (key === 'length') return false;
          if (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key)) return true;
          const index = Number(key);
          return index >= length || !Object.hasOwn(descriptors[key], 'value');
        })) schemaFail();
    const result = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) schemaFail();
      result.push(descriptor.value);
    }
    return Object.freeze(result);
  } catch (error) {
    if (error instanceof OgvcsError) throw error;
    schemaFail();
  }
}

function exactInertGroupCollection(value, reservation, checkpoint) {
  if (nodeTypes.isProxy(value)) schemaFail();
  if (value instanceof Map) {
    exactInertGroupMap(value);
    const size = value.size;
    reservation.reserve(size * 192);
    const result = [];
    for (const group of Map.prototype.values.call(value)) {
      checkpoint();
      result.push(group);
    }
    return Object.freeze(result);
  }
  return exactInertGroupArray(value);
}

function exactInertFileIdAuthority(value) {
  if (nodeTypes.isProxy(value)) schemaFail();
  try {
    if (value instanceof Set) {
      Set.prototype.values.call(value);
      if (Object.getPrototypeOf(value) !== Set.prototype || Reflect.ownKeys(value).length !== 0) {
        schemaFail();
      }
      return id => Set.prototype.has.call(value, id);
    }
    if (value instanceof Map) {
      exactInertGroupMap(value);
      return id => Map.prototype.has.call(value, id);
    }
  } catch (error) {
    if (error instanceof OgvcsError) throw error;
    schemaFail();
  }
  schemaFail();
}

function requireProfileFamilyBeforeLifecycle(registry, profile, families) {
  const known = registry.profiles.get(profile.toString());
  if (known !== undefined && !families.includes(known.family)) schemaFail();
}

/** Validate core membership plus registered role and external-key semantics. */
export function validateAssetGroups(groups, fileIds, options = {}) {
  options = inertAssetGroupOptions(options);
  let semantic;
  if (options.lookup !== undefined) {
    requireSemanticLookup(options.lookup);
    semantic = {
      registry: options.lookup.registry,
      operation: options.lookup.operation,
      mode: options.lookup.mode
    };
  } else {
    semantic = semanticValidationContext(options.mode, options.registry, {
      requireRegistry: true,
      requireMode: true
    });
  }
  return collectRepositoryStage(() => validateAssetGroupsStage(
    groups, fileIds, { ...options, ...semantic }
  ));
}

function validateAssetGroupsStage(groups, fileIds, options) {
  const reservation = derivedBuildReservation(options.lookup, options);
  reservation.reserve(512);
  try {
  const checkpoint = () => options.lookup?.checkpoint?.();
  const configuration = inertAssetGroupConfiguration(options, reservation, checkpoint);
  const hardLimits = options.hardLimits ?? options.lookup?.hardLimits ?? {};
  const groupMaximum = configuredHardLimit('asset-groups', hardLimits['asset-groups']);
  const memberMaximum = configuredHardLimit('asset-group-members', hardLimits['asset-group-members']);
  const rawValues = exactInertGroupCollection(
    groups, reservation, checkpoint
  );
  const declaredGroups = rawValues.length;
  enforceHardLimit(undefined, 'asset-groups', declaredGroups,
    { maximum: groupMaximum, code: 'LIMIT_COUNT', layer: 2 });
  const hasFileId = exactInertFileIdAuthority(fileIds);
  const membership = new Map();
  const externalOwners = new Map();
  const uniqueSchemes = configuration.uniqueExternalKeyProfiles;
  const groupsWithMembers = new Set();
  // Freeze the complete caller-controlled shape/family layer before the first
  // lifecycle decision. This prevents an early conformance-only group from
  // hiding a malformed or wrong-family later group and prevents Proxy/accessor
  // code from running during repository semantics.
  const values = [];
  const lifecycleProfiles = [];
  for (const rawGroup of rawValues) {
    options.lookup?.checkpoint?.();
    const group = exactInertGroupMap(rawGroup);
    const members = exactInertGroupArray(group.get(3));
    const externalKeys = exactInertGroupArray(group.get(4) ?? []);
    enforceHardLimit(undefined, 'asset-group-members', members.length,
      { maximum: memberMaximum, code: 'LIMIT_COUNT', layer: 2 });
    groupKey(group);
    fileKey(group.get(2));
    const groupProfile = ProfileRef.fromMap(exactInertGroupMap(group.get(1)));
    requireProfileFamilyBeforeLifecycle(options.registry, groupProfile, ['group', 'fixture-group']);
    lifecycleProfiles.push(groupProfile);
    for (const rawMember of members) {
      const member = exactInertGroupMap(rawMember);
      fileKey(member.get(0));
      const role = ProfileRef.fromMap(exactInertGroupMap(member.get(1)));
      requireProfileFamilyBeforeLifecycle(options.registry, role, ['group-role', 'fixture-group-role']);
      lifecycleProfiles.push(role);
    }
    for (const rawExternal of externalKeys) {
      const external = exactInertGroupMap(rawExternal);
      const scheme = ProfileRef.fromMap(exactInertGroupMap(external.get(0)));
      requireProfileFamilyBeforeLifecycle(options.registry, scheme,
        ['external-key', 'fixture-external-key']);
      hex(external.get(1));
      lifecycleProfiles.push(scheme);
    }
    reservation.reserve(retainedValueBytes(group, () => options.lookup?.checkpoint?.()) + 512);
    values.push(group);
  }
  for (const profile of lifecycleProfiles) {
    options.lookup?.checkpoint?.();
    profileDecision(options.registry, profile, options.operation);
  }
  let groupCount = 0;
  for (const group of values) {
    options.lookup?.checkpoint?.();
    groupCount++;
    enforceHardLimit(undefined, 'asset-groups', groupCount,
      { maximum: groupMaximum, code: 'LIMIT_COUNT', layer: 2 });
    const members = asArray(group.get(3));
    enforceHardLimit(undefined, 'asset-group-members', members.length,
      { maximum: memberMaximum, code: 'LIMIT_COUNT', layer: 2 });
    const groupProfile = ProfileRef.fromMap(group.get(1));
    const groupDecision = profileDecision(options.registry, groupProfile, options.operation);
    if (!['group', 'fixture-group'].includes(groupDecision.family)) schemaFail();
    const primary = fileKey(group.get(2)); const local = new Set();
    let primaryPresent = false;
    for (const member of members) {
      options.lookup?.checkpoint?.();
      reservation.reserve(retainedValueBytes(member, () => options.lookup?.checkpoint?.()) + 256);
      if (fileKey(member.get(0)) === primary) primaryPresent = true;
    }
    if (!primaryPresent) semanticFail('GROUP_MEMBER_INVALID');
    const roleCounts = new Map();
    for (const member of members) {
      options.lookup?.checkpoint?.();
      // FileID/path/owner keys are derived strings retained in three indexes.
      // Reserve before any conversion or Set insertion.
      reservation.reserve(retainedValueBytes(member, () => options.lookup?.checkpoint?.()) + 768);
      const id = fileKey(member.get(0));
      if (local.has(id) || !hasFileId(id)) semanticFail('GROUP_MEMBER_INVALID');
      local.add(id);
      if (membership.has(id)) semanticFail('GROUP_MEMBERSHIP_OVERLAP');
      const owner = groupKey(group);
      membership.set(id, owner);
      groupsWithMembers.add(owner);
      const roleRef = ProfileRef.fromMap(member.get(1));
      const roleDecision = profileDecision(options.registry, roleRef, options.operation);
      if (!['group-role', 'fixture-group-role'].includes(roleDecision.family)) schemaFail();
      const role = roleRef.toString();
      if (!roleCounts.has(role)) reservation.reserve(192 + role.length * 2);
      roleCounts.set(role, (roleCounts.get(role) ?? 0) + 1);
    }
    const rule = configuration.rules.get(groupProfile.toString());
    const allowedRoles = rule ? new Set() : undefined;
    const ruleUniqueSchemes = rule ? new Set() : undefined;
    for (const roleRule of rule?.roles ?? []) {
      options.lookup?.checkpoint?.();
      const role = roleRule?.[0];
      if (typeof role !== 'string') {
        fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
      }
      if (!allowedRoles.has(role)) {
        reservation.reserve(retainedValueBytes(role, () => options.lookup?.checkpoint?.()) + 192);
        allowedRoles.add(role);
      }
    }
    for (const configured of rule?.uniqueExternalKeyProfiles ?? []) {
      options.lookup?.checkpoint?.();
      if (typeof configured !== 'string') {
        fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
      }
      if (!ruleUniqueSchemes.has(configured)) {
        reservation.reserve(retainedValueBytes(configured, () => options.lookup?.checkpoint?.()) + 192);
        ruleUniqueSchemes.add(configured);
      }
    }
    if (allowedRoles) {
      for (const role of roleCounts.keys()) {
        options.lookup?.checkpoint?.();
        if (!allowedRoles.has(role)) semanticFail('GROUP_REQUIRED_ROLE_MISSING');
      }
    }
    for (const [role, minimum = 0, maximum = Number.POSITIVE_INFINITY] of rule?.roles ?? []) {
      options.lookup?.checkpoint?.();
      const count = roleCounts.get(role) ?? 0;
      if (count < minimum || count > maximum) semanticFail('GROUP_REQUIRED_ROLE_MISSING');
    }
    for (const external of group.get(4) ?? []) {
      options.lookup?.checkpoint?.();
      // The collision tuple concatenates profile and hex-encoded opaque bytes.
      // Bound its string/storage cost before either conversion allocates.
      reservation.reserve(retainedValueBytes(external, () => options.lookup?.checkpoint?.()) * 2 + 512);
      const schemeRef = ProfileRef.fromMap(external.get(0));
      const schemeDecision = profileDecision(options.registry, schemeRef, options.operation);
      if (!['external-key', 'fixture-external-key'].includes(schemeDecision.family)) schemaFail();
      const scheme = schemeRef.toString();
      if (!uniqueSchemes.has(scheme) && !ruleUniqueSchemes?.has(scheme)) continue;
      const key = `${scheme}\0${hex(external.get(1))}`; const owner = externalOwners.get(key);
      if (owner && owner !== groupKey(group)) semanticFail('GROUP_EXTERNAL_KEY_DUPLICATE');
      externalOwners.set(key, groupKey(group));
    }
  }
  return Object.freeze({ groups: groupsWithMembers.size, members: membership.size });
  } finally {
    reservation.release();
  }
}

function compareStateToSnapshot(state, snapshot, lookup, descriptor, options) {
  const expected = expandedState(
    snapshot.get(18), snapshot.get(20), lookup, descriptor, options
  );
  try {
    if (state.entries.size !== expected.entries.size || state.groups.size !== expected.groups.size) semanticFail('CHANGESET_RESULT_MISMATCH');
    for (const [key, value] of state.entries) { lookup.checkpoint?.(); if (!expected.entries.has(key) || !sameValue(value, expected.entries.get(key))) semanticFail('CHANGESET_RESULT_MISMATCH'); }
    for (const [key, value] of state.groups) { lookup.checkpoint?.(); if (!expected.groups.has(key) || !sameValue(value, expected.groups.get(key))) semanticFail('CHANGESET_RESULT_MISMATCH'); }
    // The asset-group validator owns a closed configured-authority record.
    // RepositoryContext carries many unrelated replay/tree fields, so project
    // only the two optional group policies plus the already authenticated
    // lookup instead of widening that public boundary with a context spread.
    const groupOptions = { lookup };
    if (options.groupProfileRules !== undefined) {
      groupOptions.groupProfileRules = options.groupProfileRules;
    }
    if (options.uniqueExternalKeyProfiles !== undefined) {
      groupOptions.uniqueExternalKeyProfiles = options.uniqueExternalKeyProfiles;
    }
    validateAssetGroups(state.groups, expected.fileIds, groupOptions);
  } finally {
    expected.release();
  }
}

function preflightSnapshotRepositoryStage(candidate, descriptor, designatedRoot, lookup) {
  return collectRepositoryStage(() => {
    const reservation = derivedBuildReservation(lookup);
    reservation.reserve(512);
    try {
    const seen = new Set();
    const stack = [candidate];
    while (stack.length > 0) {
      lookup.checkpoint?.();
      const reference = stack.pop();
      const key = refKey(reference);
      if (seen.has(key)) continue;
      reservation.reserve(256 + key.length * 2);
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
      for (const parent of parents) {
        reservation.reserve(192);
        stack.push(parent);
      }
    }
    } finally {
      reservation.release();
    }
  });
}

function validateSnapshotGraphOwned(candidateReference, context) {
  requireRepositoryContext(context);
  const candidate = ref(candidateReference, 7); const descriptor = ref(context.descriptor, 6); const designatedRoot = ref(context.designatedRoot, 7); const visiting = new Set(); const visited = new Set(); const order = [];
  // Route-specific L2 closure: snapshots, every parent, the authenticated
  // descriptor, and each snapshot's change-set. Do not validate unrelated
  // supplied objects, and do not enter root/base/cycle semantics until the
  // complete reached set has passed its registry phase.
  const closureReservation = derivedBuildReservation(context.lookup, context);
  closureReservation.reserve(512);
  try {
    const lookupFailures = { best: undefined };
    collectLookupFailure(lookupFailures, () => context.lookup.resolve(descriptor, 6));
    const reached = new Set();
    const closureStack = [candidate];
    while (closureStack.length > 0) {
      context.lookup.checkpoint?.();
      const reference = closureStack.pop();
      const key = refKey(reference);
      if (reached.has(key)) continue;
      closureReservation.reserve(320 + key.length * 2);
      reached.add(key);
      const resolved = collectLookupFailure(
        lookupFailures, () => context.lookup.edge(reference, 7)
      );
      if (!resolved) continue;
      const snapshot = resolved.value;
      // Descriptor membership is a route edge, not merely a later repository
      // equality check. Resolve every reached snapshot's declared descriptor
      // during the complete L2 phase so an absent foreign descriptor cannot
      // be hidden by SNAPSHOT_PARENT_CROSS_REPOSITORY.
      collectLookupFailure(lookupFailures, () => context.lookup.edge(snapshot.get(16), 6));
      collectLookupFailure(lookupFailures, () => context.lookup.edge(snapshot.get(19), 4));
      for (const parent of snapshot.get(17)) {
        context.lookup.checkpoint?.();
        closureReservation.reserve(192);
        closureStack.push(parent);
      }
    }
    throwSelectedLookupFailure(lookupFailures);
    context.lookup[LOOKUP_FINISH_REGISTRY]();
  } finally {
    closureReservation.release();
  }
  preflightSnapshotRepositoryStage(candidate, descriptor, designatedRoot, context.lookup);
  const reservation = derivedBuildReservation(context.lookup, context);
  reservation.reserve(1_024);
  const stack = [{ reference: candidate }];
  let completed = false;
  try {
  while (stack.length) {
    context.lookup.checkpoint?.();
    const frame = stack[stack.length - 1]; const key = refKey(frame.reference);
    if (!frame.snapshot) {
      if (visiting.has(key)) semanticFail('SNAPSHOT_PARENT_CYCLE');
      if (visited.has(key)) { stack.pop(); continue; }
      reservation.reserve(384 + key.length * 2);
      visiting.add(key); frame.snapshot = snapshotObject(frame.reference, context.lookup); frame.parent = 0;
      const parents = frame.snapshot.get(17);
      if (key === refKey(designatedRoot) ? parents.length !== 0 : parents.length === 0) semanticFail('SNAPSHOT_ROOT_INVALID');
      if (!sameRef(frame.snapshot.get(16), descriptor)) semanticFail('SNAPSHOT_PARENT_CROSS_REPOSITORY');
    }
    const parents = frame.snapshot.get(17);
    if (frame.parent < parents.length) {
      const parent = parents[frame.parent++]; const parentKey = refKey(parent);
      if (visiting.has(parentKey)) semanticFail('SNAPSHOT_PARENT_CYCLE');
      if (!visited.has(parentKey)) {
        reservation.reserve(192);
        stack.push({ reference: parent });
      }
      continue;
    }
    const changeSet = context.lookup.edge(frame.snapshot.get(19), 4).value; const base = changeSet.get(17);
    if ((parents.length === 0) !== !base || (parents.length > 0 && !sameRef(base, parents[0]))) semanticFail('CHANGESET_BASE_MISMATCH');
    visiting.delete(key); visited.add(key); order.push(frame.reference); stack.pop();
  }
  if (!visited.has(refKey(designatedRoot))) semanticFail('SNAPSHOT_ROOT_INVALID');
  const lease = reservation.lease();
  completed = true;
  return Object.freeze({
    visited,
    order: Object.freeze(order),
    retainedBytes: lease.bytes,
    release: lease.release
  });
  } finally {
    if (!completed) reservation.release();
  }
}

export function validateSnapshotGraph(candidateReference, context) {
  requireRepositoryContext(context);
  return context.lookup[LOOKUP_OPERATION](() => {
  const owned = validateSnapshotGraphOwned(candidateReference, context);
  try {
    return Object.freeze({ visited: owned.visited, order: owned.order });
  } finally {
    // The public result crosses the operation boundary and becomes
    // caller-owned. Internal composite validators retain the owned lease.
    owned.release();
  }
  });
}

export function validateProvenanceGraph(references, lookup, options = {}) {
  requireSemanticLookup(lookup);
  return lookup[LOOKUP_OPERATION](() => {
  const reservation = derivedBuildReservation(lookup, options);
  reservation.reserve(1_024);
  try {
  const forbidden = new Set();
  for (const value of options.forbidden ?? []) {
    lookup.checkpoint?.();
    const key = refKey(value);
    if (!forbidden.has(key)) reservation.reserve(256 + key.length * 2);
    forbidden.add(key);
  }
  const roots = [];
  const reached = new Set();
  const adjacency = new Map();
  const lookupFailures = { best: undefined };
  for (const root of references ?? []) {
    lookup.checkpoint?.();
    // Charge the caller-provided root inventory before reference parsing or
    // the visited fast path; duplicate roots remain bounded input work.
    reservation.reserve(192);
    const rootRef = ref(root, 9);
    roots.push(rootRef);
  }
  const closureStack = [...roots];
  while (closureStack.length > 0) {
    lookup.checkpoint?.();
    const reference = closureStack.pop();
    const key = refKey(reference);
    if (reached.has(key) || forbidden.has(key)) continue;
    reservation.reserve(384 + key.length * 2);
    reached.add(key);
    const parsed = ref(reference);
    const resolved = collectLookupFailure(lookupFailures, () => lookup.edge(parsed));
    if (!resolved) continue;
    const object = resolved.value;
    const inputs = [];
    for (const input of iterateObjectReferences(parsed.kind, object)) {
      lookup.checkpoint?.();
      const inputKey = refKey(input);
      reservation.reserve(192 + inputKey.length * 2);
      inputs.push(input);
      if (!forbidden.has(inputKey) && !reached.has(inputKey)) closureStack.push(input);
    }
    adjacency.set(key, Object.freeze(inputs));
  }
  throwSelectedLookupFailure(lookupFailures);
  lookup[LOOKUP_FINISH_REGISTRY]();

  const visiting = new Set(); const visited = new Set();
  for (const rootRef of roots) {
    if (visited.has(refKey(rootRef))) continue;
    const stack = [{ reference: rootRef, input: 0 }];
    while (stack.length) {
      lookup.checkpoint?.();
      const frame = stack[stack.length - 1]; const key = refKey(frame.reference);
      if (frame.input === 0) {
        if (forbidden.has(key) || visiting.has(key)) semanticFail('PROVENANCE_CYCLE');
        if (visited.has(key)) { stack.pop(); continue; }
        visiting.add(key);
      }
      const inputs = adjacency.get(key) ?? [];
      if (frame.input < inputs.length) {
        const input = inputs[frame.input++]; const inputKey = refKey(input);
        if (forbidden.has(inputKey) || visiting.has(inputKey)) semanticFail('PROVENANCE_CYCLE');
        if (!visited.has(inputKey)) {
          stack.push({ reference: input, input: 0 });
        }
        continue;
      }
      visiting.delete(key); visited.add(key); stack.pop();
    }
  }
  return Object.freeze({ visited });
  } finally {
    reservation.release();
  }
  });
}

export function validateShelfRevision(reference, context) {
  requireRepositoryContext(context);
  if (context.verifyContent !== true) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return context.lookup[LOOKUP_OPERATION](() => {
  const workspace = derivedBuildReservation(context.lookup, context);
  workspace.reserve(1_024);
  try {
  const shelfRef = ref(reference, 8);
  // Shelf validation is an exact reached-set boundary. Discover the complete
  // shelf chain and every content/replay dependency it can consume before the
  // registry and repository phases, while deliberately ignoring unrelated
  // objects supplied in the lookup.
  preflightCandidateClosure(shelfRef, context, workspace);
  context.lookup[LOOKUP_FINISH_REGISTRY]();
  const shelf = context.lookup.resolve(shelfRef, 8).value; if (!sameRef(shelf.get(16), context.descriptor)) semanticFail('REPOSITORY_DESCRIPTOR_MISMATCH');
  const revision = Number(shelf.get(18));
  let current = shelf; let currentRef = shelfRef; let expectedRevision = revision;
  const seen = new Set([refKey(shelfRef)]); const chain = [{ reference: shelfRef, value: shelf }];
  while (true) {
    context.lookup.checkpoint?.();
    if (Number(current.get(18)) !== expectedRevision) semanticFail('SHELF_CHAIN_INVALID');
    if (expectedRevision === 1) { if (current.has(19)) semanticFail('SHELF_CHAIN_INVALID'); break; }
    if (!current.has(19)) semanticFail('SHELF_CHAIN_INVALID');
    const previousRef = ref(current.get(19), 8); const key = refKey(previousRef); if (seen.has(key)) semanticFail('SHELF_CHAIN_INVALID');
    workspace.reserve(512 + key.length * 2);
    seen.add(key);
    const previous = context.lookup.edge(previousRef, 8).value;
    if (!sameRef(previous.get(16), context.descriptor) || !equalBytes(previous.get(17), shelf.get(17))) semanticFail('SHELF_CHAIN_INVALID');
    current = previous; currentRef = previousRef; chain.push({ reference: currentRef, value: current }); expectedRevision--;
  }
  chain.reverse();
  const baseUses = new Map();
  for (const item of chain) {
    const key = refKey(item.value.get(20));
    if (!baseUses.has(key)) workspace.reserve(256 + key.length * 2);
    baseUses.set(key, (baseUses.get(key) ?? 0) + 1);
  }
  const baseStates = new Map();
  let requestedConflicts = 0;
  try {
    for (const item of chain) {
      context.lookup.checkpoint?.();
      const value = item.value; const baseKey = refKey(value.get(20));
      let retainedBase = baseStates.get(baseKey);
      if (!retainedBase) {
        const baseSnapshot = snapshotObject(value.get(20), context.lookup);
        if (!sameRef(baseSnapshot.get(16), context.descriptor)) semanticFail('SNAPSHOT_PARENT_CROSS_REPOSITORY');
        const materialized = expandedState(
          baseSnapshot.get(18), baseSnapshot.get(20), context.lookup, context.descriptor, context
        );
        let bytes;
        try {
          bytes = stateMemoryBytes(materialized, () => context.lookup.checkpoint?.());
        } catch (error) {
          materialized.release();
          throw error;
        }
        retainedBase = { state: materialized, bytes, release: materialized.release };
        workspace.reserve(256 + baseKey.length * 2);
        baseStates.set(baseKey, retainedBase);
      }
      const changeSet = context.lookup.resolve(value.get(21), 4).value;
      if (!changeSet.has(17) || !sameRef(changeSet.get(17), value.get(20))) semanticFail('CHANGESET_BASE_MISMATCH');
      const conflicts = validateConflictSetOwned(
        value.get(24), context.lookup, context.descriptor, { published: false }
      );
      try {
        const replayGrowth = replayWorkingMemoryBytes(value.get(21), retainedBase.state, context);
        const replayReservation = retainedBase.bytes + replayGrowth;
        reserveState(context.lookup, replayReservation);
        try {
        const replayed = replayChangeSetInternal(value.get(21), retainedBase.state, {
          ...context,
          requireCompleteLifetime: true,
          historicalReplay: !sameRef(item.reference, shelfRef),
          conflictSet: conflicts.conflictSet
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
      } finally {
        conflicts.release();
      }
      const remainingUses = baseUses.get(baseKey) - 1;
      baseUses.set(baseKey, remainingUses);
      if (remainingUses === 0) {
        retainedBase.release();
        baseStates.delete(baseKey);
      }
    }
  } finally {
    for (const retained of baseStates.values()) retained.release();
    baseStates.clear();
  }
  return Object.freeze({ revision, conflicts: requestedConflicts });
  } finally {
    workspace.release();
  }
  });
}

function preflightCandidateClosure(candidate, context, reservation) {
  const reached = new Set();
  const stack = [candidate];
  const lookupFailures = { best: undefined };
  while (stack.length > 0) {
    context.lookup.checkpoint?.();
    const reference = ref(stack.pop());
    const key = refKey(reference);
    if (reached.has(key)) continue;
    reservation.reserve(384 + key.length * 2);
    reached.add(key);
    const object = collectLookupFailure(
      lookupFailures, () => context.lookup.edge(reference)
    );
    if (!object) continue;
    for (const outbound of iterateObjectReferences(reference.kind, object.value)) {
      context.lookup.checkpoint?.();
      reservation.reserve(192);
      stack.push(outbound);
    }
  }
  throwSelectedLookupFailure(lookupFailures);
}

export function validateRepositoryCandidate(candidateReference, context) {
  requireRepositoryContext(context);
  if (context.verifyContent !== true) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return context.lookup[LOOKUP_OPERATION](() => {
  const workspace = derivedBuildReservation(context.lookup, context);
  workspace.reserve(1_024);
  let graph;
  try {
  const candidate = ref(candidateReference, 7); const descriptor = ref(context.descriptor, 6);
  // Candidate validation is the whole-supplied S boundary. First rank every
  // supplied identity/schema error, then discover the candidate's complete
  // content closure, and only then enter the whole registry and repository
  // phases. Nested helpers may safely call their registry boundary afterward;
  // the deferred set is already empty and the reached objects are cached.
  context.lookup[LOOKUP_PREFLIGHT_ALL_L2]();
  preflightCandidateClosure(candidate, context, workspace);
  context.lookup[LOOKUP_FINISH_ALL_REGISTRY]();
  graph = validateSnapshotGraphOwned(candidate, { ...context, descriptor });
  const firstParentUses = new Map();
  for (const snapshotRef of graph.order) {
    context.lookup.checkpoint?.();
    workspace.reserve(384);
    const parents = context.lookup.resolve(snapshotRef, 7).value.get(17);
    if (parents.length > 0) {
      const key = refKey(parents[0]);
      if (!firstParentUses.has(key)) workspace.reserve(256 + key.length * 2);
      firstParentUses.set(key, (firstParentUses.get(key) ?? 0) + 1);
    }
  }
  const states = new Map();
  let candidateEntries = 0; let candidateGroups = 0; let candidateConflicts = 0;
  try {
    for (const snapshotRef of graph.order) {
    context.lookup.checkpoint?.();
    const snapshot = context.lookup.resolve(snapshotRef, 7).value; const parents = snapshot.get(17);
    const parentKey = parents.length === 0 ? undefined : refKey(parents[0]);
    const retainedBase = parentKey === undefined ? undefined : states.get(parentKey);
    const base = retainedBase?.state ?? (parents.length === 0 ? { entries: new Map(), groups: new Map() } : undefined);
    if (!base) semanticFail('CHANGESET_BASE_MISMATCH');
    const conflicts = validateConflictSetOwned(
      snapshot.get(28), context.lookup, descriptor, { published: true }
    );
    try {
      const baseCloneBytes = retainedBase?.bytes ?? stateMemoryBytes(
        base, () => context.lookup.checkpoint?.()
      );
      const replayGrowth = replayWorkingMemoryBytes(snapshot.get(19), base, context);
      let replayReservation = baseCloneBytes + replayGrowth;
      reserveState(context.lookup, replayReservation);
      let retainedReplay;
      try {
      const replayed = replayChangeSetInternal(snapshot.get(19), base, {
        ...context,
        descriptor,
        requireCompleteLifetime: true,
        historicalReplay: !sameRef(snapshotRef, candidate),
        conflictSet: conflicts.conflictSet
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
        workspace.reserve(256 + snapshotKey.length * 2);
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
    } finally {
      conflicts.release();
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
  } finally {
    for (const retained of states.values()) releaseState(context.lookup, retained.bytes);
    states.clear();
  }
  return Object.freeze({
    highestLayer: 3,
    entries: candidateEntries,
    groups: candidateGroups,
    conflicts: candidateConflicts
  });
  } finally {
    graph?.release();
    workspace.release();
  }
  });
}

export function validateAbstractReferenceGraph(graph, options = {}) {
  const guard = makeGuard(options);
  // Configured-resource authority precedes every caller graph read.
  guard.check();
  if (!graph || Object.keys(graph).sort().join(',') !== 'assumedValidation,graphKind,nodes,roots,schemaVersion' || graph.schemaVersion !== 'ogvcs.repository-format/abstract-reference-graph/v1' || graph.assumedValidation !== 'canonical-framing-schema-and-identity-prevalidated') schemaFail();
  const expected = graph.graphKind === 'snapshot-parent' ? { type:'snapshot',edge:'parent',code:'SNAPSHOT_PARENT_CYCLE' } : graph.graphKind === 'provenance-input' ? { type:'provenance',edge:'provenance-input',code:'PROVENANCE_CYCLE' } : null; if (!expected) schemaFail();
  if (!Array.isArray(graph.nodes) || graph.nodes.length === 0 || !Array.isArray(graph.roots) || graph.roots.length === 0) schemaFail();
  const nodes = new Map(); let previous;
  for (const node of graph.nodes) {
    guard.object();
    const nodeId = node?.id;
    const nodeIdBytes = typeof nodeId === 'string' ? nodeId.length * 2 : 0;
    guard.reserve(256 + nodeIdBytes);
    if (!node || Object.keys(node).sort().join(',') !== 'edges,id,type' || !validAbstractNodeId(nodeId, guard) || node.type !== expected.type || !Array.isArray(node.edges) || nodes.has(nodeId) || (previous && compareAbstractNodeId(previous,nodeId,guard)>=0)) schemaFail();
    previous=node.id; nodes.set(node.id,node);
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
      if (!edge || Object.keys(edge).sort().join(',') !== 'kind,target' || edge.kind !== expected.edge || typeof edge.target !== 'string' || !nodes.has(edge.target) || (prior !== undefined && compareAbstractNodeId(prior, edge.target, guard)>=0)) schemaFail();
      prior=edge.target;
    }
  }
  previous=undefined;
  for (const root of graph.roots) {
    guard.check();
    const rootBytes = typeof root === 'string' ? root.length * 2 : 0;
    guard.reserve(128 + rootBytes);
    if (typeof root !== 'string' || !nodes.has(root) || (previous && compareAbstractNodeId(previous,root,guard)>=0)) schemaFail();
    previous=root;
  }
  const visiting=new Set();const visited=new Set();
  for (const root of graph.roots) {
    if (visited.has(root)) continue;
    guard.reserve(384 + root.length * 2);
    visiting.add(root); const stack = [{ id: root, edge: 0 }];
    while (stack.length) {
      guard.check();
      const frame = stack[stack.length - 1]; const edges = nodes.get(frame.id).edges;
      if (frame.edge === edges.length) { visiting.delete(frame.id); visited.add(frame.id); stack.pop(); continue; }
      const target = edges[frame.edge++].target;
      if (visiting.has(target)) semanticFail(expected.code);
      if (!visited.has(target)) { guard.reserve(384 + target.length * 2); visiting.add(target); stack.push({ id: target, edge: 0 }); }
    }
  }
  return Object.freeze({highestLayer:3,nodes:visited.size,edges:guard.summary().edges});
}
