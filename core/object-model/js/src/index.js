export { ERROR_STAGE_ORDER, OgvcsError, compareErrorPrecedence, errorPrecedence,
  errorSites, errorStagePrecedence, isOgvcsError } from './errors.js';
export { decodeCanonical, decodeFirst, decodeSequence, encodeCanonical, encodeCanonicalChunks,
  writeCanonical, compareCanonicalBytes } from './cbor.js';
export { Digest, FileId, ObjectRef, ProfileRef, KIND_NAMES, equalBytes, toHex } from './types.js';
export { Sha256Writer, createObjectHashWriter, createOpaqueObjectHashWriter,
  createLogicalRecordHashWriter, createConflictHashWriter, createBundleTranscriptHashWriter,
  hashByteIterable, hashObject, hashOpaqueObject, hashLogicalRecord, hashConflictPreimage,
  hashBundleTranscript, verifyObjectId, sha256Digest } from './hash.js';
export { visitLogicalBundle } from './bundle-stream.js';
export { REGISTRY_FILES, RegistrySnapshot, loadRegistryDirectory, parseCanonicalRegistryJson,
  profileDecision, registryAssignmentDecision, registryFromEvolutionSnapshot, requiredFeatureDecision, validateRegistrySet,
  bundledRegistryDirectory, loadBundledRegistry, registrySetDigest } from './registry.js';
export { decodeMetadata, encodeMetadata, reproduceConflictId, reproduceLogicalRecordIdentity,
  scanMetadata, validateBundleItem, validateConflictPreimage, validateKnownSchema, validateLogicalRecord } from './schema.js';
export { allocateFileId, validateFileIdAllocation, MAX_FILE_ID_ALLOCATION_ATTEMPTS } from './fileid.js';
export { configuredHardLimit, enforceHardLimit, evaluateHardLimit, hardLimitMaximum,
  HARD_LIMIT_NAMES } from './hard-limits.js';
export { encodeLogicalBundle, logicalRecordReferences, objectReferences, validateBundleClaim,
  verifyLogicalBundle, writeOrderedLogicalBundle } from './bundle.js';
export { LOGICAL_BUNDLE_STREAM_LIMITS, verifyLogicalBundleFile, verifyLogicalBundleStream } from './bundle-spool.js';
export { RepositoryObjectLookup, REPOSITORY_VALIDATION_LIMITS, createRepositoryObjectLookup, verifyManifest, expandTree,
  replayChangeSet, validateLifetimeAndImports, validateImportRequest, validateConflictSet,
  validateAssetGroups, validateSnapshotGraph, validateProvenanceGraph, validateShelfRevision,
  validateRepositoryCandidate, validateAbstractReferenceGraph } from './repository.js';
export { CLI_EXIT, CLI_HELP, runCli } from './cli.js';
export { adaptFixture, FIXTURE_ADAPTER_LEDGER_SCHEMA, FIXTURE_ADAPTER_LIMITS,
  prepareFixtureAdapterLedger } from './fixture-adapter.js';
export { TREE_STREAM_LIMITS, createDiskFileIdIndex, verifyTreeFile, writeOrderedTree, writeSortedTree } from './tree-stream.js';
export { MANIFEST_STREAM_LIMITS, writeContentManifest } from './manifest-stream.js';
