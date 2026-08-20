//! Dependency-minimal, clean-room codec for OpenGameVCS repository format v1.
#![forbid(unsafe_code)]

mod bundle_claim;
mod bundle_stream;
mod bundle_verify;
mod bundle_write;
mod cbor;
mod error;
mod file_id;
mod file_identity;
mod hard_limits;
mod hash;
mod manifest_stream;
mod metadata;
mod refs;
mod registry;
mod repository;
mod schema;
mod tree_stream;
mod unicode_age;
mod unicode_age_table;

pub use bundle_claim::validate_bundle_claim;
pub use bundle_stream::{
    visit_logical_bundle, BundleItemInfo, BundleLimits, BundleSummary, BundleVisitor,
};
pub use bundle_verify::{
    verify_logical_bundle_file, verify_logical_bundle_stream, LogicalBundleScratchMetrics,
    LogicalBundleVerifyAuthority, LogicalBundleVerifyLimits, LogicalBundleVerifyOptions,
    LogicalBundleVerifySummary,
};
pub use bundle_write::{
    LogicalBundleBudget, LogicalBundleWriteLimits, LogicalBundleWriteOptions,
    LogicalBundleWritePlan, LogicalBundleWriteSummary, LogicalBundleWriter,
};
pub use cbor::{
    decode_canonical, encode_canonical, encode_canonical_to, encode_canonical_with_limits, Cbor,
    Limits,
};
pub use error::{Error, ErrorCode, Result, ValidationStage};
pub use file_id::{
    allocate_file_id, allocate_file_id_with, validate_file_id_allocation, EntropySource,
    FileIdAllocationRequest, MAX_FILE_ID_ALLOCATION_ATTEMPTS,
};
pub use hard_limits::{
    configured_hard_limit, enforce_hard_limit, enforce_hard_limit_with_ceiling,
    evaluate_hard_limit, hard_limit_maximum, HardLimitCeilings, HardLimitDecision,
    HARD_LIMIT_NAMES,
};
pub use hash::{
    conflict_id, hash_chunk, logical_record_id, object_id, opaque_object_digest, sha256,
    BundleTranscriptHashWriter, ConflictHashWriter, Digest, LogicalRecordHashWriter,
    ObjectHashWriter, OpaqueObjectHashWriter, Sha256Writer,
};
pub use manifest_stream::{
    encode_and_verify_content_manifest_stream, encode_content_manifest_stream, ManifestChunkSource,
    ManifestStreamLimits, ManifestStreamPart, ManifestStreamSummary,
};
pub use metadata::{
    decode_metadata, encode_metadata, MetadataDecodeOptions, MetadataDecodeSummary,
    MetadataEncodeOptions, MetadataEncodeSummary,
};
pub use refs::{FileId, ObjectKind, ObjectRef, ProfileRef, TypedDigest};
pub use registry::{
    ExtensionRegistryEntry, FeatureRegistryEntry, LimitRegistryEntry, LogicalRecordRegistryEntry,
    ObjectKindRegistryEntry, Operation, Registry, RegistryAssignment, RegistryEntry, RegistryState,
    SemanticEnumRegistryEntry, BUNDLED_REGISTRY_SET_DIGEST, REGISTRY_FILES,
};
pub use repository::{
    expand_tree, expand_tree_with_path_profile_validator, import_mapping_key, replay_change_set,
    validate_abstract_reference_graph, validate_asset_groups,
    validate_asset_groups_with_hard_limits, validate_asset_groups_with_limits,
    validate_conflict_set, validate_import_request, validate_lifetime_and_imports,
    validate_provenance_graph, validate_repository_candidate, validate_semantic_object,
    validate_shelf_revision, validate_snapshot_graph, verify_manifest, AbstractGraphSummary,
    AllocationEvidence, AssetGroup, ConflictSummary, EntryState, GroupProfileRule,
    GroupRoleCardinality, GroupValidationSummary, ImportDecision, ImportMapping, ImportRequest,
    ImportState, LifetimeOrigin, LifetimeRecord, ManifestSummary, PathCaseMode,
    PathProfileDecision, PathProfileValidator, ProvenanceGraphSummary, ReplaySummary,
    RepositoryContext, RepositoryLimits, RepositoryObjectLookup, RepositoryState,
    RepositoryValidationSummary, ResolvedObject, ResourceSummary, SemanticObjectValidation,
    SnapshotGraphSummary, TreeExpansion, ValidationMode,
};
pub use schema::{
    scan_metadata, scan_metadata_with_hard_limits, validate_conflict_preimage,
    validate_conflict_preimage_with_hard_limits, validate_logical_record,
    validate_logical_record_with_hard_limits, validate_metadata_schema,
    validate_metadata_schema_with_limits, FramingScan, MetadataObject,
};
pub use tree_stream::{
    encode_ordered_tree, encode_ordered_tree_with_features, encode_tree_with_scratch,
    encode_tree_with_scratch_and_features, verify_tree_stream, TreeFileIdIndex,
    TreeFileIdScratchIndex, TreeFileIdTransaction, TreeScratchMetrics, TreeStreamEntry,
    TreeStreamLimits, TreeStreamSummary,
};
