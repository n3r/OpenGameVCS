use crate::{
    AuthorizationContext, CommitSequence, ConsistencyToken, FileHistoryWrite,
    FileIdImportReservation, FileIdReservation, FileIdReservationOutcome, IdempotencyReservation,
    IdempotencyReservationOutcome, ObjectPutOutcome, ObjectWrite, OutboxEvent,
    ReferenceCasRequest, ReferenceCasResult, RepositoryCreate, RepositoryId, Result, SnapshotWrite,
    TransactionOptions, TreeEntryWrite,
};
use ogvcs_object_model::{
    scan_metadata, validate_semantic_object, Limits, Registry, ValidationMode,
};

pub trait AuthorizationPort {
    type AuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: &'static str,
        resource_type: &'static str,
        repository_id: RepositoryId,
    ) -> Result<Self::AuthorizedView>;
}

pub trait ObjectValidationPort {
    fn validate(&self, write: &ObjectWrite<'_>) -> Result<()>;
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
        let semantic = validate_semantic_object(&object, &self.registry, ValidationMode::Production)
            .map_err(|_| crate::DomainError::new(crate::DomainErrorCode::ObjectInvalid))?;
        if semantic.kind != write.object_ref.kind {
            return Err(crate::DomainError::new(
                crate::DomainErrorCode::ObjectInvalid,
            ));
        }
        Ok(())
    }
}

/// Safe production default until OGVCS-009 supplies an authorization adapter.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllAuthorization;

impl AuthorizationPort for DenyAllAuthorization {
    type AuthorizedView = ();

    fn authorize(
        &self,
        _context: &AuthorizationContext,
        _permission: &'static str,
        _resource_type: &'static str,
        _repository_id: RepositoryId,
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
    fn reserve_file_id(&mut self, reservation: FileIdReservation) -> Result<()>;
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
    fn issue_consistency_token(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        minimum: CommitSequence,
    ) -> Result<ConsistencyToken>;
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
        permission: &'static str,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<Self::Transaction<'_>>;
}
