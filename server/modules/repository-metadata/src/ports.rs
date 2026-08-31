use crate::{
    AuthorizationContext, AuthorizationResource, CommitSequence, ConsistencyToken,
    FileHistoryWrite, FileIdExpectedState, FileIdImportReservation, FileIdReservation,
    FileIdReservationOutcome, IdempotencyReservation, IdempotencyReservationOutcome,
    MetadataPermission, NativeFileIdReservation, ObjectPutOutcome, ObjectRef, ObjectWrite,
    OutboxEvent, ReferenceCasRequest, ReferenceCasResult, RepositoryCreate, RepositoryId, Result,
    SnapshotWrite, TransactionCapability, TransactionOptions, TreeEntryWrite,
};
use ogvcs_object_model::{
    scan_metadata, validate_semantic_object, Limits, Operation, PathProfileValidator, ProfileRef,
    Registry, ValidationMode,
};

pub trait AuthorizedView {
    /// Revalidates the signer/adapter output against the complete claims used
    /// for this exact operation.  Returning a broader repository view is not
    /// sufficient for a path- or identity-specific read.
    fn permits(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> bool;
}

pub trait AuthorizationPort {
    type AuthorizedView: AuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> Result<Self::AuthorizedView>;
}

pub trait ObjectValidationPort {
    fn validate(&self, write: &ObjectWrite<'_>) -> Result<()>;

    fn registry(&self) -> Registry;

    fn validation_mode(&self) -> ValidationMode;

    fn path_profile_validator(&self) -> Option<&dyn PathProfileValidator> {
        None
    }

    /// Supplies immutable chunk bytes owned by OGVCS-005/010 for complete
    /// candidate validation.  The built-in production validator deliberately
    /// has no persistence integration and therefore fails closed.
    fn resolve_chunk(&self, _reference: ObjectRef) -> Result<Vec<u8>> {
        Err(crate::DomainError::new(
            crate::DomainErrorCode::ObjectInvalid,
        ))
    }

    fn validate_profile(&self, profile: &ProfileRef, family: &str) -> Result<()> {
        let operation = match self.validation_mode() {
            ValidationMode::Read => Operation::Read,
            ValidationMode::Conformance => Operation::ConformanceWrite,
            ValidationMode::Production => Operation::ProductionWrite,
        };
        self.registry()
            .check_profile(profile, family, operation)
            .map_err(|_| crate::DomainError::new(crate::DomainErrorCode::ObjectInvalid))
    }

    fn validate_repository_profiles(
        &self,
        path_profile: &ProfileRef,
        platform_profile: &ProfileRef,
        content_policy_profile: &ProfileRef,
    ) -> Result<()> {
        self.validate_profile(path_profile, "path")?;
        self.validate_profile(platform_profile, "path")?;
        self.validate_profile(content_policy_profile, "content-policy")
    }
}

/// Complete bundled OGVCS-002 authority in production-write lifecycle mode.
#[derive(Clone, Debug)]
pub struct ProductionObjectValidator {
    registry: Registry,
}

impl Default for ProductionObjectValidator {
    fn default() -> Self {
        Self {
            registry: Registry::bundled(),
        }
    }
}

impl ObjectValidationPort for ProductionObjectValidator {
    fn validate(&self, write: &ObjectWrite<'_>) -> Result<()> {
        let object = scan_metadata(write.canonical_bytes, Limits::METADATA)
            .map_err(|_| crate::DomainError::new(crate::DomainErrorCode::ObjectInvalid))?;
        let semantic =
            validate_semantic_object(&object, &self.registry, ValidationMode::Production)
                .map_err(|_| crate::DomainError::new(crate::DomainErrorCode::ObjectInvalid))?;
        if semantic.kind != write.object_ref.kind {
            return Err(crate::DomainError::new(
                crate::DomainErrorCode::ObjectInvalid,
            ));
        }
        Ok(())
    }

    fn registry(&self) -> Registry {
        self.registry.clone()
    }

    fn validation_mode(&self) -> ValidationMode {
        ValidationMode::Production
    }
}

/// Safe production default until OGVCS-009 supplies an authorization adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthorization;

#[derive(Clone, Copy, Debug, Default)]
pub struct DeniedAuthorizedView;

impl AuthorizedView for DeniedAuthorizedView {
    fn permits(
        &self,
        _context: &AuthorizationContext,
        _permission: MetadataPermission,
        _resource: &AuthorizationResource,
    ) -> bool {
        false
    }
}

impl AuthorizationPort for DenyAllAuthorization {
    type AuthorizedView = DeniedAuthorizedView;

    fn authorize(
        &self,
        _context: &AuthorizationContext,
        _permission: MetadataPermission,
        _resource: &AuthorizationResource,
    ) -> Result<Self::AuthorizedView> {
        Err(crate::DomainError::new(
            crate::DomainErrorCode::MetadataNotFoundOrDenied,
        ))
    }
}

/// Transaction-bound operations used by OGVCS-006 and the OGVCS-010 submit
/// coordinator. Adapters must implement all methods on one database transaction.
pub trait MetadataTransaction {
    fn create_repository(&mut self, request: RepositoryCreate<'_>) -> Result<()>;
    fn put_object(&mut self, write: ObjectWrite<'_>) -> Result<ObjectPutOutcome>;
    fn index_tree_entry(&mut self, entry: TreeEntryWrite) -> Result<()>;
    fn index_snapshot(&mut self, snapshot: SnapshotWrite) -> Result<()>;
    fn append_file_history(&mut self, history: FileHistoryWrite) -> Result<()>;
    /// Reserves a native create/copy lifetime. Restore requires the future
    /// proof-bound OGVCS-002/010 API and import uses `reserve_imported_file_id`.
    fn reserve_file_id(&mut self, reservation: FileIdReservation) -> Result<()>;
    /// Consumes an authenticated `file-id.allocate` receipt and registers its
    /// exact FileID. Create/copy callers must use this method.
    fn register_allocated_file_id(&mut self, reservation: NativeFileIdReservation) -> Result<()>;
    fn reserve_imported_file_id(
        &mut self,
        reservation: FileIdImportReservation,
    ) -> Result<FileIdReservationOutcome>;
    fn activate_file_id(
        &mut self,
        repository_id: RepositoryId,
        file_id: crate::FileId,
    ) -> Result<()>;
    fn tombstone_file_id(
        &mut self,
        repository_id: RepositoryId,
        file_id: crate::FileId,
        expected_state: FileIdExpectedState,
    ) -> Result<()>;
    fn reserve_idempotency(
        &mut self,
        reservation: IdempotencyReservation,
    ) -> Result<IdempotencyReservationOutcome>;
    fn commit_idempotency(
        &mut self,
        reservation: &IdempotencyReservation,
        safe_result: serde_json::Value,
    ) -> Result<()>;
    fn compare_and_swap_reference(
        &mut self,
        request: ReferenceCasRequest,
    ) -> Result<ReferenceCasResult>;
    fn append_outbox(&mut self, event: OutboxEvent) -> Result<()>;
    fn issue_consistency_token(&mut self, minimum: CommitSequence) -> Result<ConsistencyToken>;
    fn commit(self) -> Result<CommitSequence>;
    fn rollback(self) -> Result<()>;
}

pub trait MetadataStore {
    type Transaction<'store>: MetadataTransaction
    where
        Self: 'store;

    fn begin_authorized(
        &mut self,
        context: &AuthorizationContext,
        capability: TransactionCapability,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<Self::Transaction<'_>>;
}
