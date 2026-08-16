const CLASSES = new Map([
  ['CBOR_TRUNCATED', 'encoding'], ['CBOR_NON_CANONICAL', 'encoding'],
  ['CBOR_TRAILING_BYTES', 'encoding'], ['SCHEMA_FIELD_INVALID', 'schema'],
  ['SCHEMA_FIELD_UNKNOWN', 'schema'], ['LIMIT_METADATA_BYTES', 'resource'],
  ['LIMIT_CHUNK_BYTES', 'resource'], ['LIMIT_NESTING', 'resource'],
  ['LIMIT_COUNT', 'resource'], ['LIMIT_MEMORY', 'resource'],
  ['LIMIT_SCRATCH', 'resource'], ['LIMIT_TIME', 'resource'],
  ['LIMIT_VALUE_BYTES', 'resource'], ['LIMIT_EXTENSION_BYTES', 'resource'],
  ['LIMIT_LOGICAL_BYTES', 'resource'], ['OBJECT_ID_MISMATCH', 'identity'],
  ['OBJECT_REFERENCE_FORMAT_UNSUPPORTED', 'unsupported'],
  ['OBJECT_REFERENCE_KIND_MISMATCH', 'graph'],
  ['OBJECT_REFERENCE_MISSING', 'graph'],
  ['REQUIRED_FEATURE_UNSUPPORTED', 'unsupported'], ['PROFILE_UNKNOWN', 'unsupported'],
  ['PROFILE_CONFORMANCE_ONLY', 'unsupported'], ['PROFILE_STATE_FORBIDDEN', 'unsupported'],
  ['REPOSITORY_DESCRIPTOR_MISMATCH', 'repository'],
  ['OBJECT_KIND_UNSUPPORTED', 'unsupported'], ['REGISTRY_INVALID', 'schema'],
  ['EXTENSION_KEY_INVALID', 'schema'], ['LOGICAL_RECORD_TYPE_UNSUPPORTED', 'unsupported'],
  ['MANIFEST_CHUNK_LENGTH_INVALID', 'content'], ['MANIFEST_LENGTH_MISMATCH', 'content'],
  ['MANIFEST_FILE_DIGEST_MISMATCH', 'content'],
  ['TREE_ENTRY_ORDER_INVALID', 'tree'], ['TREE_ENTRY_TARGET_INVALID', 'tree'],
  ['PATH_CORE_INVALID', 'path'], ['PATH_PROFILE_INVALID', 'path'],
  ['SNAPSHOT_ROOT_INVALID', 'history'], ['SNAPSHOT_PARENT_COUNT_INVALID', 'history'],
  ['SNAPSHOT_PARENT_DUPLICATE', 'history'], ['SNAPSHOT_PARENT_CYCLE', 'history'],
  ['SNAPSHOT_PARENT_CROSS_REPOSITORY', 'history'], ['CHANGESET_BASE_MISMATCH', 'history'],
  ['CHANGESET_SEQUENCE_INVALID', 'transition'], ['CHANGESET_TRANSITION_INVALID', 'transition'],
  ['CHANGESET_RESULT_MISMATCH', 'transition'], ['FILEID_ZERO', 'fileid'],
  ['FILEID_DUPLICATE_IN_TREE', 'fileid'], ['FILEID_ALREADY_CONSUMED', 'collision'],
  ['FILEID_SOURCE_MISMATCH', 'fileid'], ['FILEID_RESTORE_PROOF_INVALID', 'fileid'],
  ['FILEID_CROSS_REPOSITORY_PROOF', 'fileid'], ['FILEID_IMPORT_MAPPING_CONFLICT', 'collision'],
  ['FILEID_ALLOCATION_COLLISION', 'collision'], ['FILEID_ENTROPY_UNAVAILABLE', 'resource'],
  ['FILEID_ALLOCATION_EXHAUSTED', 'collision'], ['FILEID_LIFETIME_EVIDENCE_INVALID', 'fileid'],
  ['GROUP_MEMBER_INVALID', 'group'], ['GROUP_MEMBERSHIP_OVERLAP', 'group'],
  ['GROUP_REQUIRED_ROLE_MISSING', 'group'], ['GROUP_EXTERNAL_KEY_DUPLICATE', 'group'],
  ['CONFLICT_ID_MISMATCH', 'conflict'], ['CONFLICT_UNRESOLVED_PUBLISHED', 'conflict'],
  ['CONFLICT_RESOLUTION_MISMATCH', 'conflict'], ['SHELF_CHAIN_INVALID', 'shelf'],
  ['PROVENANCE_CYCLE', 'graph'],
  ['ATTESTATION_SIGNATURE_SHAPE_INVALID', 'attestation'],
  ['CONFLICT_SUBJECT_INVALID', 'conflict'],
  ['BUNDLE_SEQUENCE_INVALID', 'bundle'], ['BUNDLE_BUDGET_EXCEEDED', 'resource'],
  ['BUNDLE_RECORD_ID_MISMATCH', 'bundle'], ['BUNDLE_TRAILER_MISMATCH', 'bundle'],
  ['BUNDLE_DUPLICATE_IDENTITY', 'bundle'], ['BUNDLE_CLOSURE_MISSING', 'bundle'],
  ['BUNDLE_CLOSURE_EXTRA', 'bundle'], ['BUNDLE_ROOT_INVALID', 'bundle'],
  ['BUNDLE_EXPORT_CLAIM_FORBIDDEN', 'boundary'], ['BUNDLE_MODE_UNSUPPORTED', 'capability'],
  ['FIXTURE_SCHEMA_UNSUPPORTED', 'fixture'], ['FIXTURE_SEMANTIC_INVALID', 'fixture'],
  ['FIXTURE_MAPPING_MISSING', 'fixture'], ['FIXTURE_CONTENT_UNAVAILABLE', 'fixture'],
  ['FIXTURE_NATIVE_BINDING_MISSING', 'fixture']
]);
const PRECEDENCE = new Map([...CLASSES.keys()].map((code, index) => [code, index]));
export const ERROR_STAGE_ORDER = Object.freeze([
  'configured-resource-preflight',
  'canonical-framing',
  'sequence-shape-and-order',
  'declared-identity',
  'transcript-authentication',
  'known-schema',
  'closure-and-reference-resolution',
  'declared-accounting',
  'registry-semantics',
  'repository-semantics'
]);
const STAGE_PRECEDENCE = new Map(ERROR_STAGE_ORDER.map((stage, index) => [stage, index]));
const SITE_ROWS = Object.freeze([
  ['canonical-framing', 1, ['CBOR_TRUNCATED', 'CBOR_NON_CANONICAL', 'CBOR_TRAILING_BYTES', 'SCHEMA_FIELD_INVALID', 'LIMIT_NESTING', 'LIMIT_COUNT', 'LIMIT_VALUE_BYTES', 'LIMIT_EXTENSION_BYTES']],
  ['closure-and-reference-resolution', 2, ['OBJECT_REFERENCE_KIND_MISMATCH', 'OBJECT_REFERENCE_MISSING', 'BUNDLE_CLOSURE_MISSING', 'BUNDLE_CLOSURE_EXTRA', 'BUNDLE_ROOT_INVALID']],
  ['closure-and-reference-resolution', 3, ['FIXTURE_MAPPING_MISSING', 'FIXTURE_CONTENT_UNAVAILABLE']],
  ['configured-resource-preflight', 1, ['SCHEMA_FIELD_INVALID', 'LIMIT_METADATA_BYTES', 'LIMIT_CHUNK_BYTES', 'LIMIT_COUNT', 'LIMIT_MEMORY', 'LIMIT_SCRATCH', 'LIMIT_TIME', 'BUNDLE_BUDGET_EXCEEDED']],
  ['declared-accounting', 1, ['BUNDLE_BUDGET_EXCEEDED']],
  ['declared-identity', 1, ['OBJECT_ID_MISMATCH', 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED', 'BUNDLE_RECORD_ID_MISMATCH']],
  ['declared-identity', 2, ['CONFLICT_ID_MISMATCH']],
  ['known-schema', 2, ['SCHEMA_FIELD_INVALID', 'SCHEMA_FIELD_UNKNOWN', 'LIMIT_COUNT', 'LIMIT_VALUE_BYTES', 'LIMIT_EXTENSION_BYTES', 'LIMIT_LOGICAL_BYTES', 'OBJECT_REFERENCE_FORMAT_UNSUPPORTED', 'OBJECT_REFERENCE_KIND_MISMATCH', 'OBJECT_KIND_UNSUPPORTED', 'EXTENSION_KEY_INVALID', 'LOGICAL_RECORD_TYPE_UNSUPPORTED', 'MANIFEST_CHUNK_LENGTH_INVALID', 'MANIFEST_LENGTH_MISMATCH', 'TREE_ENTRY_ORDER_INVALID', 'TREE_ENTRY_TARGET_INVALID', 'PATH_CORE_INVALID', 'SNAPSHOT_PARENT_COUNT_INVALID', 'SNAPSHOT_PARENT_DUPLICATE', 'CHANGESET_SEQUENCE_INVALID', 'FILEID_ZERO', 'ATTESTATION_SIGNATURE_SHAPE_INVALID', 'BUNDLE_ROOT_INVALID']],
  ['registry-semantics', 3, ['REQUIRED_FEATURE_UNSUPPORTED', 'PROFILE_UNKNOWN', 'PROFILE_CONFORMANCE_ONLY', 'PROFILE_STATE_FORBIDDEN', 'REGISTRY_INVALID', 'FIXTURE_SCHEMA_UNSUPPORTED']],
  ['repository-semantics', 3, ['REPOSITORY_DESCRIPTOR_MISMATCH', 'MANIFEST_CHUNK_LENGTH_INVALID', 'MANIFEST_FILE_DIGEST_MISMATCH', 'TREE_ENTRY_TARGET_INVALID', 'PATH_CORE_INVALID', 'PATH_PROFILE_INVALID', 'SNAPSHOT_ROOT_INVALID', 'SNAPSHOT_PARENT_CYCLE', 'SNAPSHOT_PARENT_CROSS_REPOSITORY', 'CHANGESET_BASE_MISMATCH', 'CHANGESET_TRANSITION_INVALID', 'CHANGESET_RESULT_MISMATCH', 'FILEID_DUPLICATE_IN_TREE', 'FILEID_ALREADY_CONSUMED', 'FILEID_SOURCE_MISMATCH', 'FILEID_RESTORE_PROOF_INVALID', 'FILEID_CROSS_REPOSITORY_PROOF', 'FILEID_IMPORT_MAPPING_CONFLICT', 'FILEID_ALLOCATION_COLLISION', 'FILEID_ENTROPY_UNAVAILABLE', 'FILEID_ALLOCATION_EXHAUSTED', 'FILEID_LIFETIME_EVIDENCE_INVALID', 'GROUP_MEMBER_INVALID', 'GROUP_MEMBERSHIP_OVERLAP', 'GROUP_REQUIRED_ROLE_MISSING', 'GROUP_EXTERNAL_KEY_DUPLICATE', 'CONFLICT_UNRESOLVED_PUBLISHED', 'CONFLICT_RESOLUTION_MISMATCH', 'SHELF_CHAIN_INVALID', 'PROVENANCE_CYCLE', 'CONFLICT_SUBJECT_INVALID', 'BUNDLE_EXPORT_CLAIM_FORBIDDEN', 'FIXTURE_SEMANTIC_INVALID', 'FIXTURE_NATIVE_BINDING_MISSING']],
  ['sequence-shape-and-order', 1, ['BUNDLE_SEQUENCE_INVALID', 'BUNDLE_DUPLICATE_IDENTITY', 'BUNDLE_MODE_UNSUPPORTED']],
  ['transcript-authentication', 1, ['BUNDLE_TRAILER_MISMATCH']]
]);
const SITES = new Map([...CLASSES.keys()].map(code => [code, new Map()]));
for (const [stage, layer, codes] of SITE_ROWS) {
  for (const code of codes) {
    const byLayer = SITES.get(code);
    const stages = byLayer.get(layer) ?? [];
    stages.push(stage);
    byLayer.set(layer, stages);
  }
}

/** Returns the frozen errors.json catalogue position for deterministic selection. */
export function errorPrecedence(code) {
  return PRECEDENCE.get(code) ?? Number.MAX_SAFE_INTEGER;
}

export function errorStagePrecedence(stage) {
  return STAGE_PRECEDENCE.get(stage) ?? Number.MAX_SAFE_INTEGER;
}

export function errorSites(code) {
  const sites = [];
  for (const [layer, stages] of SITES.get(code) ?? []) {
    for (const stage of stages) sites.push(Object.freeze({ layer, stage }));
  }
  return Object.freeze(sites);
}

export function compareErrorPrecedence(left, right) {
  const layer = (left?.layer ?? Number.MAX_SAFE_INTEGER) - (right?.layer ?? Number.MAX_SAFE_INTEGER);
  if (layer !== 0) return layer;
  const stage = errorStagePrecedence(left?.stage) - errorStagePrecedence(right?.stage);
  if (stage !== 0) return stage;
  const code = errorPrecedence(left?.code) - errorPrecedence(right?.code);
  if (code !== 0) return code;
  return (left?.offset ?? Number.MAX_SAFE_INTEGER) - (right?.offset ?? Number.MAX_SAFE_INTEGER);
}

export class OgvcsError extends Error {
  constructor(code, { layer, stage, offset, cause } = {}) {
    super(code, cause ? { cause } : undefined);
    this.name = 'OgvcsError';
    this.code = code;
    this.errorClass = CLASSES.get(code) ?? 'unknown';
    if (layer !== undefined) {
      this.layer = layer;
      const candidates = SITES.get(code)?.get(layer) ?? [];
      if (stage === undefined && candidates.length === 1) stage = candidates[0];
      else if (stage === undefined && candidates.length > 1) {
        throw new TypeError(`diagnostic stage required for ${code}@${layer}`);
      } else if (stage !== undefined && !candidates.includes(stage)) {
        throw new TypeError(`invalid diagnostic site ${code}@${layer}:${stage}`);
      } else if (stage === undefined && CLASSES.has(code)) {
        throw new TypeError(`invalid diagnostic layer ${code}@${layer}`);
      }
    }
    if (stage !== undefined) this.stage = stage;
    if (offset !== undefined) this.offset = offset;
  }
}

export function fail(code, details) {
  throw new OgvcsError(code, details);
}

export function isOgvcsError(value, code) {
  return value instanceof OgvcsError && (code === undefined || value.code === code);
}
