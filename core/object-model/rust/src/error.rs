use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// Frozen validation stage from `errors.json`.
///
/// Layers remain the coarse interoperability boundary. Stages order failures
/// within a layer and identify the exact diagnostic site used by a validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ValidationStage {
    ConfiguredResourcePreflight,
    CanonicalFraming,
    SequenceShapeAndOrder,
    DeclaredIdentity,
    TranscriptAuthentication,
    KnownSchema,
    ClosureAndReferenceResolution,
    DeclaredAccounting,
    RegistrySemantics,
    RepositorySemantics,
}

impl ValidationStage {
    pub const ALL: &'static [Self] = &[
        Self::ConfiguredResourcePreflight,
        Self::CanonicalFraming,
        Self::SequenceShapeAndOrder,
        Self::DeclaredIdentity,
        Self::TranscriptAuthentication,
        Self::KnownSchema,
        Self::ClosureAndReferenceResolution,
        Self::DeclaredAccounting,
        Self::RegistrySemantics,
        Self::RepositorySemantics,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfiguredResourcePreflight => "configured-resource-preflight",
            Self::CanonicalFraming => "canonical-framing",
            Self::SequenceShapeAndOrder => "sequence-shape-and-order",
            Self::DeclaredIdentity => "declared-identity",
            Self::TranscriptAuthentication => "transcript-authentication",
            Self::KnownSchema => "known-schema",
            Self::ClosureAndReferenceResolution => "closure-and-reference-resolution",
            Self::DeclaredAccounting => "declared-accounting",
            Self::RegistrySemantics => "registry-semantics",
            Self::RepositorySemantics => "repository-semantics",
        }
    }

    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::ConfiguredResourcePreflight => 0,
            Self::CanonicalFraming => 1,
            Self::SequenceShapeAndOrder => 2,
            Self::DeclaredIdentity => 3,
            Self::TranscriptAuthentication => 4,
            Self::KnownSchema => 5,
            Self::ClosureAndReferenceResolution => 6,
            Self::DeclaredAccounting => 7,
            Self::RegistrySemantics => 8,
            Self::RepositorySemantics => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    CborTruncated,
    CborNonCanonical,
    CborTrailingBytes,
    SchemaFieldInvalid,
    SchemaFieldUnknown,
    LimitMetadataBytes,
    LimitChunkBytes,
    LimitNesting,
    LimitCount,
    LimitMemory,
    LimitScratch,
    LimitTime,
    LimitValueBytes,
    LimitExtensionBytes,
    LimitLogicalBytes,
    ObjectIdMismatch,
    ObjectReferenceFormatUnsupported,
    ObjectReferenceKindMismatch,
    ObjectReferenceMissing,
    RequiredFeatureUnsupported,
    ProfileUnknown,
    ProfileConformanceOnly,
    RepositoryDescriptorMismatch,
    ObjectKindUnsupported,
    ProfileStateForbidden,
    RegistryInvalid,
    ExtensionKeyInvalid,
    LogicalRecordTypeUnsupported,
    ManifestChunkLengthInvalid,
    ManifestLengthMismatch,
    ManifestFileDigestMismatch,
    TreeEntryOrderInvalid,
    TreeEntryTargetInvalid,
    PathCoreInvalid,
    PathProfileInvalid,
    SnapshotRootInvalid,
    SnapshotParentCountInvalid,
    SnapshotParentDuplicate,
    SnapshotParentCycle,
    SnapshotParentCrossRepository,
    ChangeSetBaseMismatch,
    ChangeSetSequenceInvalid,
    ChangeSetTransitionInvalid,
    ChangeSetResultMismatch,
    FileIdZero,
    FileIdDuplicateInTree,
    FileIdAlreadyConsumed,
    FileIdSourceMismatch,
    FileIdRestoreProofInvalid,
    FileIdCrossRepositoryProof,
    FileIdImportMappingConflict,
    FileIdAllocationCollision,
    FileIdEntropyUnavailable,
    FileIdAllocationExhausted,
    FileIdLifetimeEvidenceInvalid,
    GroupMemberInvalid,
    GroupMembershipOverlap,
    GroupRequiredRoleMissing,
    GroupExternalKeyDuplicate,
    ConflictIdMismatch,
    ConflictUnresolvedPublished,
    ConflictResolutionMismatch,
    ShelfChainInvalid,
    ProvenanceCycle,
    AttestationSignatureShapeInvalid,
    ConflictSubjectInvalid,
    BundleSequenceInvalid,
    BundleBudgetExceeded,
    BundleRecordIdMismatch,
    BundleTrailerMismatch,
    BundleDuplicateIdentity,
    BundleClosureMissing,
    BundleClosureExtra,
    BundleRootInvalid,
    BundleExportClaimForbidden,
    BundleModeUnsupported,
    FixtureSchemaUnsupported,
    FixtureSemanticInvalid,
    FixtureMappingMissing,
    FixtureContentUnavailable,
    FixtureNativeBindingMissing,
}

impl ErrorCode {
    pub const ALL: &'static [Self] = &[
        Self::CborTruncated,
        Self::CborNonCanonical,
        Self::CborTrailingBytes,
        Self::SchemaFieldInvalid,
        Self::SchemaFieldUnknown,
        Self::LimitMetadataBytes,
        Self::LimitChunkBytes,
        Self::LimitNesting,
        Self::LimitCount,
        Self::LimitMemory,
        Self::LimitScratch,
        Self::LimitTime,
        Self::LimitValueBytes,
        Self::LimitExtensionBytes,
        Self::LimitLogicalBytes,
        Self::ObjectIdMismatch,
        Self::ObjectReferenceFormatUnsupported,
        Self::ObjectReferenceKindMismatch,
        Self::ObjectReferenceMissing,
        Self::RequiredFeatureUnsupported,
        Self::ProfileUnknown,
        Self::ProfileConformanceOnly,
        Self::RepositoryDescriptorMismatch,
        Self::ObjectKindUnsupported,
        Self::ProfileStateForbidden,
        Self::RegistryInvalid,
        Self::ExtensionKeyInvalid,
        Self::LogicalRecordTypeUnsupported,
        Self::ManifestChunkLengthInvalid,
        Self::ManifestLengthMismatch,
        Self::ManifestFileDigestMismatch,
        Self::TreeEntryOrderInvalid,
        Self::TreeEntryTargetInvalid,
        Self::PathCoreInvalid,
        Self::PathProfileInvalid,
        Self::SnapshotRootInvalid,
        Self::SnapshotParentCountInvalid,
        Self::SnapshotParentDuplicate,
        Self::SnapshotParentCycle,
        Self::SnapshotParentCrossRepository,
        Self::ChangeSetBaseMismatch,
        Self::ChangeSetSequenceInvalid,
        Self::ChangeSetTransitionInvalid,
        Self::ChangeSetResultMismatch,
        Self::FileIdZero,
        Self::FileIdDuplicateInTree,
        Self::FileIdAlreadyConsumed,
        Self::FileIdSourceMismatch,
        Self::FileIdRestoreProofInvalid,
        Self::FileIdCrossRepositoryProof,
        Self::FileIdImportMappingConflict,
        Self::FileIdAllocationCollision,
        Self::FileIdEntropyUnavailable,
        Self::FileIdAllocationExhausted,
        Self::FileIdLifetimeEvidenceInvalid,
        Self::GroupMemberInvalid,
        Self::GroupMembershipOverlap,
        Self::GroupRequiredRoleMissing,
        Self::GroupExternalKeyDuplicate,
        Self::ConflictIdMismatch,
        Self::ConflictUnresolvedPublished,
        Self::ConflictResolutionMismatch,
        Self::ShelfChainInvalid,
        Self::ProvenanceCycle,
        Self::AttestationSignatureShapeInvalid,
        Self::ConflictSubjectInvalid,
        Self::BundleSequenceInvalid,
        Self::BundleBudgetExceeded,
        Self::BundleRecordIdMismatch,
        Self::BundleTrailerMismatch,
        Self::BundleDuplicateIdentity,
        Self::BundleClosureMissing,
        Self::BundleClosureExtra,
        Self::BundleRootInvalid,
        Self::BundleExportClaimForbidden,
        Self::BundleModeUnsupported,
        Self::FixtureSchemaUnsupported,
        Self::FixtureSemanticInvalid,
        Self::FixtureMappingMissing,
        Self::FixtureContentUnavailable,
        Self::FixtureNativeBindingMissing,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CborTruncated => "CBOR_TRUNCATED",
            Self::CborNonCanonical => "CBOR_NON_CANONICAL",
            Self::CborTrailingBytes => "CBOR_TRAILING_BYTES",
            Self::SchemaFieldInvalid => "SCHEMA_FIELD_INVALID",
            Self::SchemaFieldUnknown => "SCHEMA_FIELD_UNKNOWN",
            Self::LimitMetadataBytes => "LIMIT_METADATA_BYTES",
            Self::LimitChunkBytes => "LIMIT_CHUNK_BYTES",
            Self::LimitNesting => "LIMIT_NESTING",
            Self::LimitCount => "LIMIT_COUNT",
            Self::LimitMemory => "LIMIT_MEMORY",
            Self::LimitScratch => "LIMIT_SCRATCH",
            Self::LimitTime => "LIMIT_TIME",
            Self::LimitValueBytes => "LIMIT_VALUE_BYTES",
            Self::LimitExtensionBytes => "LIMIT_EXTENSION_BYTES",
            Self::LimitLogicalBytes => "LIMIT_LOGICAL_BYTES",
            Self::ObjectIdMismatch => "OBJECT_ID_MISMATCH",
            Self::ObjectReferenceFormatUnsupported => "OBJECT_REFERENCE_FORMAT_UNSUPPORTED",
            Self::ObjectReferenceKindMismatch => "OBJECT_REFERENCE_KIND_MISMATCH",
            Self::ObjectReferenceMissing => "OBJECT_REFERENCE_MISSING",
            Self::RequiredFeatureUnsupported => "REQUIRED_FEATURE_UNSUPPORTED",
            Self::ProfileUnknown => "PROFILE_UNKNOWN",
            Self::ProfileConformanceOnly => "PROFILE_CONFORMANCE_ONLY",
            Self::RepositoryDescriptorMismatch => "REPOSITORY_DESCRIPTOR_MISMATCH",
            Self::ObjectKindUnsupported => "OBJECT_KIND_UNSUPPORTED",
            Self::ProfileStateForbidden => "PROFILE_STATE_FORBIDDEN",
            Self::RegistryInvalid => "REGISTRY_INVALID",
            Self::ExtensionKeyInvalid => "EXTENSION_KEY_INVALID",
            Self::LogicalRecordTypeUnsupported => "LOGICAL_RECORD_TYPE_UNSUPPORTED",
            Self::ManifestChunkLengthInvalid => "MANIFEST_CHUNK_LENGTH_INVALID",
            Self::ManifestLengthMismatch => "MANIFEST_LENGTH_MISMATCH",
            Self::ManifestFileDigestMismatch => "MANIFEST_FILE_DIGEST_MISMATCH",
            Self::TreeEntryOrderInvalid => "TREE_ENTRY_ORDER_INVALID",
            Self::TreeEntryTargetInvalid => "TREE_ENTRY_TARGET_INVALID",
            Self::PathCoreInvalid => "PATH_CORE_INVALID",
            Self::PathProfileInvalid => "PATH_PROFILE_INVALID",
            Self::SnapshotRootInvalid => "SNAPSHOT_ROOT_INVALID",
            Self::SnapshotParentCountInvalid => "SNAPSHOT_PARENT_COUNT_INVALID",
            Self::SnapshotParentDuplicate => "SNAPSHOT_PARENT_DUPLICATE",
            Self::SnapshotParentCycle => "SNAPSHOT_PARENT_CYCLE",
            Self::SnapshotParentCrossRepository => "SNAPSHOT_PARENT_CROSS_REPOSITORY",
            Self::ChangeSetBaseMismatch => "CHANGESET_BASE_MISMATCH",
            Self::ChangeSetSequenceInvalid => "CHANGESET_SEQUENCE_INVALID",
            Self::ChangeSetTransitionInvalid => "CHANGESET_TRANSITION_INVALID",
            Self::ChangeSetResultMismatch => "CHANGESET_RESULT_MISMATCH",
            Self::FileIdZero => "FILEID_ZERO",
            Self::FileIdDuplicateInTree => "FILEID_DUPLICATE_IN_TREE",
            Self::FileIdAlreadyConsumed => "FILEID_ALREADY_CONSUMED",
            Self::FileIdSourceMismatch => "FILEID_SOURCE_MISMATCH",
            Self::FileIdRestoreProofInvalid => "FILEID_RESTORE_PROOF_INVALID",
            Self::FileIdCrossRepositoryProof => "FILEID_CROSS_REPOSITORY_PROOF",
            Self::FileIdImportMappingConflict => "FILEID_IMPORT_MAPPING_CONFLICT",
            Self::FileIdAllocationCollision => "FILEID_ALLOCATION_COLLISION",
            Self::FileIdEntropyUnavailable => "FILEID_ENTROPY_UNAVAILABLE",
            Self::FileIdAllocationExhausted => "FILEID_ALLOCATION_EXHAUSTED",
            Self::FileIdLifetimeEvidenceInvalid => "FILEID_LIFETIME_EVIDENCE_INVALID",
            Self::GroupMemberInvalid => "GROUP_MEMBER_INVALID",
            Self::GroupMembershipOverlap => "GROUP_MEMBERSHIP_OVERLAP",
            Self::GroupRequiredRoleMissing => "GROUP_REQUIRED_ROLE_MISSING",
            Self::GroupExternalKeyDuplicate => "GROUP_EXTERNAL_KEY_DUPLICATE",
            Self::ConflictIdMismatch => "CONFLICT_ID_MISMATCH",
            Self::ConflictUnresolvedPublished => "CONFLICT_UNRESOLVED_PUBLISHED",
            Self::ConflictResolutionMismatch => "CONFLICT_RESOLUTION_MISMATCH",
            Self::ShelfChainInvalid => "SHELF_CHAIN_INVALID",
            Self::ProvenanceCycle => "PROVENANCE_CYCLE",
            Self::AttestationSignatureShapeInvalid => "ATTESTATION_SIGNATURE_SHAPE_INVALID",
            Self::ConflictSubjectInvalid => "CONFLICT_SUBJECT_INVALID",
            Self::BundleSequenceInvalid => "BUNDLE_SEQUENCE_INVALID",
            Self::BundleBudgetExceeded => "BUNDLE_BUDGET_EXCEEDED",
            Self::BundleRecordIdMismatch => "BUNDLE_RECORD_ID_MISMATCH",
            Self::BundleTrailerMismatch => "BUNDLE_TRAILER_MISMATCH",
            Self::BundleDuplicateIdentity => "BUNDLE_DUPLICATE_IDENTITY",
            Self::BundleClosureMissing => "BUNDLE_CLOSURE_MISSING",
            Self::BundleClosureExtra => "BUNDLE_CLOSURE_EXTRA",
            Self::BundleRootInvalid => "BUNDLE_ROOT_INVALID",
            Self::BundleExportClaimForbidden => "BUNDLE_EXPORT_CLAIM_FORBIDDEN",
            Self::BundleModeUnsupported => "BUNDLE_MODE_UNSUPPORTED",
            Self::FixtureSchemaUnsupported => "FIXTURE_SCHEMA_UNSUPPORTED",
            Self::FixtureSemanticInvalid => "FIXTURE_SEMANTIC_INVALID",
            Self::FixtureMappingMissing => "FIXTURE_MAPPING_MISSING",
            Self::FixtureContentUnavailable => "FIXTURE_CONTENT_UNAVAILABLE",
            Self::FixtureNativeBindingMissing => "FIXTURE_NATIVE_BINDING_MISSING",
        }
    }

    /// Default validation layer for this stable code. Call sites whose code is
    /// context-sensitive (notably configured resources and typed references in
    /// bundle framing) override this with [`Error::with_layer`].
    pub const fn default_layer(self) -> u8 {
        match self {
            Self::CborTruncated
            | Self::CborNonCanonical
            | Self::CborTrailingBytes
            | Self::LimitMetadataBytes
            | Self::LimitChunkBytes
            | Self::LimitNesting
            | Self::LimitCount
            | Self::LimitMemory
            | Self::LimitScratch
            | Self::LimitTime
            | Self::LimitValueBytes
            | Self::LimitExtensionBytes
            | Self::ObjectIdMismatch
            | Self::BundleSequenceInvalid
            | Self::BundleBudgetExceeded
            | Self::BundleRecordIdMismatch
            | Self::BundleTrailerMismatch
            | Self::BundleDuplicateIdentity
            | Self::BundleModeUnsupported => 1,
            Self::SchemaFieldInvalid
            | Self::SchemaFieldUnknown
            | Self::LimitLogicalBytes
            | Self::ObjectReferenceFormatUnsupported
            | Self::ObjectReferenceKindMismatch
            | Self::ObjectReferenceMissing
            | Self::ObjectKindUnsupported
            | Self::ExtensionKeyInvalid
            | Self::LogicalRecordTypeUnsupported
            | Self::ManifestChunkLengthInvalid
            | Self::ManifestLengthMismatch
            | Self::TreeEntryOrderInvalid
            | Self::TreeEntryTargetInvalid
            | Self::PathCoreInvalid
            | Self::SnapshotParentCountInvalid
            | Self::SnapshotParentDuplicate
            | Self::ChangeSetSequenceInvalid
            | Self::FileIdZero
            | Self::ConflictIdMismatch
            | Self::AttestationSignatureShapeInvalid
            | Self::BundleClosureMissing
            | Self::BundleClosureExtra
            | Self::BundleRootInvalid => 2,
            Self::RequiredFeatureUnsupported
            | Self::ProfileUnknown
            | Self::ProfileConformanceOnly
            | Self::RepositoryDescriptorMismatch
            | Self::ProfileStateForbidden
            | Self::RegistryInvalid
            | Self::ManifestFileDigestMismatch
            | Self::PathProfileInvalid
            | Self::SnapshotRootInvalid
            | Self::SnapshotParentCycle
            | Self::SnapshotParentCrossRepository
            | Self::ChangeSetBaseMismatch
            | Self::ChangeSetTransitionInvalid
            | Self::ChangeSetResultMismatch
            | Self::FileIdDuplicateInTree
            | Self::FileIdAlreadyConsumed
            | Self::FileIdSourceMismatch
            | Self::FileIdRestoreProofInvalid
            | Self::FileIdCrossRepositoryProof
            | Self::FileIdImportMappingConflict
            | Self::FileIdAllocationCollision
            | Self::FileIdEntropyUnavailable
            | Self::FileIdAllocationExhausted
            | Self::FileIdLifetimeEvidenceInvalid
            | Self::GroupMemberInvalid
            | Self::GroupMembershipOverlap
            | Self::GroupRequiredRoleMissing
            | Self::GroupExternalKeyDuplicate
            | Self::ConflictUnresolvedPublished
            | Self::ConflictResolutionMismatch
            | Self::ShelfChainInvalid
            | Self::ProvenanceCycle
            | Self::ConflictSubjectInvalid
            | Self::BundleExportClaimForbidden
            | Self::FixtureSchemaUnsupported
            | Self::FixtureSemanticInvalid
            | Self::FixtureMappingMissing
            | Self::FixtureContentUnavailable
            | Self::FixtureNativeBindingMissing => 3,
        }
    }

    /// Returns the stage when `(code, layer)` names exactly one frozen site.
    /// Ambiguous pairs require an explicit [`Error::with_stage`] at the call
    /// site.
    pub const fn default_stage(self, layer: u8) -> Option<ValidationStage> {
        if matches!(
            (self, layer),
            (Self::SchemaFieldInvalid, 1)
                | (Self::LimitCount, 1)
                | (Self::ObjectReferenceKindMismatch, 2)
                | (Self::BundleBudgetExceeded, 1)
                | (Self::BundleRootInvalid, 2)
        ) {
            return None;
        }
        let stage = self.preferred_stage(layer);
        if self.supports_site(layer, stage) {
            Some(stage)
        } else {
            None
        }
    }

    /// Whether this exact `(code, layer, stage)` site is registered by the
    /// frozen diagnostic catalogue.
    pub const fn supports_site(self, layer: u8, stage: ValidationStage) -> bool {
        use ValidationStage as Stage;
        match stage {
            Stage::ConfiguredResourcePreflight => {
                layer == 1
                    && matches!(
                        self,
                        Self::SchemaFieldInvalid
                            | Self::LimitMetadataBytes
                            | Self::LimitChunkBytes
                            | Self::LimitCount
                            | Self::LimitMemory
                            | Self::LimitScratch
                            | Self::LimitTime
                            | Self::BundleBudgetExceeded
                    )
            }
            Stage::CanonicalFraming => {
                layer == 1
                    && matches!(
                        self,
                        Self::CborTruncated
                            | Self::CborNonCanonical
                            | Self::CborTrailingBytes
                            | Self::SchemaFieldInvalid
                            | Self::LimitNesting
                            | Self::LimitCount
                            | Self::LimitValueBytes
                            | Self::LimitExtensionBytes
                    )
            }
            Stage::SequenceShapeAndOrder => {
                layer == 1
                    && matches!(
                        self,
                        Self::BundleSequenceInvalid
                            | Self::BundleDuplicateIdentity
                            | Self::BundleModeUnsupported
                    )
            }
            Stage::DeclaredIdentity => {
                matches!(
                    (self, layer),
                    (Self::ObjectIdMismatch, 1)
                        | (Self::ObjectReferenceFormatUnsupported, 1)
                        | (Self::BundleRecordIdMismatch, 1)
                        | (Self::ConflictIdMismatch, 2)
                )
            }
            Stage::TranscriptAuthentication => {
                layer == 1 && matches!(self, Self::BundleTrailerMismatch)
            }
            Stage::KnownSchema => {
                layer == 2
                    && matches!(
                        self,
                        Self::SchemaFieldInvalid
                            | Self::SchemaFieldUnknown
                            | Self::LimitCount
                            | Self::LimitValueBytes
                            | Self::LimitExtensionBytes
                            | Self::LimitLogicalBytes
                            | Self::ObjectReferenceFormatUnsupported
                            | Self::ObjectReferenceKindMismatch
                            | Self::ObjectKindUnsupported
                            | Self::ExtensionKeyInvalid
                            | Self::LogicalRecordTypeUnsupported
                            | Self::ManifestChunkLengthInvalid
                            | Self::ManifestLengthMismatch
                            | Self::TreeEntryOrderInvalid
                            | Self::TreeEntryTargetInvalid
                            | Self::PathCoreInvalid
                            | Self::SnapshotParentCountInvalid
                            | Self::SnapshotParentDuplicate
                            | Self::ChangeSetSequenceInvalid
                            | Self::FileIdZero
                            | Self::AttestationSignatureShapeInvalid
                            | Self::BundleRootInvalid
                    )
            }
            Stage::ClosureAndReferenceResolution => matches!(
                (self, layer),
                (Self::ObjectReferenceKindMismatch, 2)
                    | (Self::ObjectReferenceMissing, 2)
                    | (Self::BundleClosureMissing, 2)
                    | (Self::BundleClosureExtra, 2)
                    | (Self::BundleRootInvalid, 2)
                    | (Self::FixtureMappingMissing, 3)
                    | (Self::FixtureContentUnavailable, 3)
            ),
            Stage::DeclaredAccounting => layer == 1 && matches!(self, Self::BundleBudgetExceeded),
            Stage::RegistrySemantics => {
                layer == 3
                    && matches!(
                        self,
                        Self::RequiredFeatureUnsupported
                            | Self::ProfileUnknown
                            | Self::ProfileConformanceOnly
                            | Self::ProfileStateForbidden
                            | Self::RegistryInvalid
                            | Self::FixtureSchemaUnsupported
                    )
            }
            Stage::RepositorySemantics => {
                layer == 3
                    && matches!(
                        self,
                        Self::RepositoryDescriptorMismatch
                            | Self::ManifestChunkLengthInvalid
                            | Self::ManifestFileDigestMismatch
                            | Self::TreeEntryTargetInvalid
                            | Self::PathCoreInvalid
                            | Self::PathProfileInvalid
                            | Self::SnapshotRootInvalid
                            | Self::SnapshotParentCycle
                            | Self::SnapshotParentCrossRepository
                            | Self::ChangeSetBaseMismatch
                            | Self::ChangeSetTransitionInvalid
                            | Self::ChangeSetResultMismatch
                            | Self::FileIdDuplicateInTree
                            | Self::FileIdAlreadyConsumed
                            | Self::FileIdSourceMismatch
                            | Self::FileIdRestoreProofInvalid
                            | Self::FileIdCrossRepositoryProof
                            | Self::FileIdImportMappingConflict
                            | Self::FileIdAllocationCollision
                            | Self::FileIdEntropyUnavailable
                            | Self::FileIdAllocationExhausted
                            | Self::FileIdLifetimeEvidenceInvalid
                            | Self::GroupMemberInvalid
                            | Self::GroupMembershipOverlap
                            | Self::GroupRequiredRoleMissing
                            | Self::GroupExternalKeyDuplicate
                            | Self::ConflictUnresolvedPublished
                            | Self::ConflictResolutionMismatch
                            | Self::ShelfChainInvalid
                            | Self::ProvenanceCycle
                            | Self::ConflictSubjectInvalid
                            | Self::BundleExportClaimForbidden
                            | Self::FixtureSemanticInvalid
                            | Self::FixtureNativeBindingMissing
                    )
            }
        }
    }

    const fn preferred_stage(self, layer: u8) -> ValidationStage {
        use ValidationStage as Stage;
        match (self, layer) {
            (Self::SchemaFieldInvalid, 1) => Stage::CanonicalFraming,
            (Self::LimitCount, 1) | (Self::BundleBudgetExceeded, 1) => {
                Stage::ConfiguredResourcePreflight
            }
            (Self::ObjectReferenceKindMismatch, 2) | (Self::BundleRootInvalid, 2) => {
                Stage::KnownSchema
            }
            _ if matches!(
                self,
                Self::CborTruncated
                    | Self::CborNonCanonical
                    | Self::CborTrailingBytes
                    | Self::LimitNesting
                    | Self::LimitValueBytes
                    | Self::LimitExtensionBytes
            ) && layer == 1 =>
            {
                Stage::CanonicalFraming
            }
            _ if matches!(
                self,
                Self::LimitMetadataBytes
                    | Self::LimitChunkBytes
                    | Self::LimitMemory
                    | Self::LimitScratch
                    | Self::LimitTime
            ) && layer == 1 =>
            {
                Stage::ConfiguredResourcePreflight
            }
            _ if matches!(
                self,
                Self::BundleSequenceInvalid
                    | Self::BundleDuplicateIdentity
                    | Self::BundleModeUnsupported
            ) && layer == 1 =>
            {
                Stage::SequenceShapeAndOrder
            }
            _ if matches!(
                (self, layer),
                (Self::ObjectIdMismatch, 1)
                    | (Self::ObjectReferenceFormatUnsupported, 1)
                    | (Self::BundleRecordIdMismatch, 1)
                    | (Self::ConflictIdMismatch, 2)
            ) =>
            {
                Stage::DeclaredIdentity
            }
            (Self::BundleTrailerMismatch, 1) => Stage::TranscriptAuthentication,
            _ if layer == 2
                && matches!(
                    self,
                    Self::SchemaFieldInvalid
                        | Self::SchemaFieldUnknown
                        | Self::LimitCount
                        | Self::LimitValueBytes
                        | Self::LimitExtensionBytes
                        | Self::LimitLogicalBytes
                        | Self::ObjectReferenceFormatUnsupported
                        | Self::ObjectKindUnsupported
                        | Self::ExtensionKeyInvalid
                        | Self::LogicalRecordTypeUnsupported
                        | Self::ManifestChunkLengthInvalid
                        | Self::ManifestLengthMismatch
                        | Self::TreeEntryOrderInvalid
                        | Self::TreeEntryTargetInvalid
                        | Self::PathCoreInvalid
                        | Self::SnapshotParentCountInvalid
                        | Self::SnapshotParentDuplicate
                        | Self::ChangeSetSequenceInvalid
                        | Self::FileIdZero
                        | Self::AttestationSignatureShapeInvalid
                ) =>
            {
                Stage::KnownSchema
            }
            _ if matches!(
                (self, layer),
                (Self::ObjectReferenceMissing, 2)
                    | (Self::BundleClosureMissing, 2)
                    | (Self::BundleClosureExtra, 2)
                    | (Self::FixtureMappingMissing, 3)
                    | (Self::FixtureContentUnavailable, 3)
            ) =>
            {
                Stage::ClosureAndReferenceResolution
            }
            _ if layer == 3
                && matches!(
                    self,
                    Self::RequiredFeatureUnsupported
                        | Self::ProfileUnknown
                        | Self::ProfileConformanceOnly
                        | Self::ProfileStateForbidden
                        | Self::RegistryInvalid
                        | Self::FixtureSchemaUnsupported
                ) =>
            {
                Stage::RegistrySemantics
            }
            _ => Stage::RepositorySemantics,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: ErrorCode,
    pub layer: u8,
    pub stage: ValidationStage,
    pub offset: Option<usize>,
}

impl Error {
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            layer: code.default_layer(),
            stage: code.preferred_stage(code.default_layer()),
            offset: None,
        }
    }

    pub const fn at(code: ErrorCode, offset: usize) -> Self {
        Self {
            code,
            layer: code.default_layer(),
            stage: code.preferred_stage(code.default_layer()),
            offset: Some(offset),
        }
    }

    pub const fn with_layer(mut self, layer: u8) -> Self {
        self.layer = layer;
        if !self.code.supports_site(layer, self.stage) {
            self.stage = self.code.preferred_stage(layer);
        }
        self
    }

    /// Selects one of the frozen sites for an ambiguous `(code, layer)` pair.
    pub const fn with_stage(mut self, stage: ValidationStage) -> Self {
        self.stage = stage;
        self
    }

    pub const fn is_registered_site(&self) -> bool {
        self.code.supports_site(self.layer, self.stage)
    }

    pub(crate) const fn precedence_key(&self) -> (u8, u8, u8) {
        (self.layer, self.stage.rank(), self.code as u8)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(offset) => write!(
                f,
                "{} at layer {} stage {} byte {}",
                self.code.as_str(),
                self.layer,
                self.stage.as_str(),
                offset
            ),
            None => write!(
                f,
                "{} at layer {} stage {}",
                self.code.as_str(),
                self.layer,
                self.stage.as_str()
            ),
        }
    }
}

impl std::error::Error for Error {}
