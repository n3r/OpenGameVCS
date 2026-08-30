//! OGVCS-006 repository metadata domain and transaction boundary.
//!
//! HTTP remains disabled until a later protocol release binds the domain
//! errors. This crate does include the reference PostgreSQL adapter and the
//! transaction-composable API used by the OGVCS-010 submit coordinator.
#![forbid(unsafe_code)]

mod error;
mod migration;
mod migration_runner;
mod ports;
mod postgres;
mod types;

pub use error::{DomainError, DomainErrorCode, Result};
pub use migration::{Migration, MigrationPhase, MIGRATIONS};
pub use migration_runner::{
    run_migrations, verify_schema_compatibility, MigrationRunOptions, MigrationRunReport,
};
pub use ogvcs_object_model::{FileId, ObjectRef};
pub use ports::{
    AuthorizationPort, AuthorizedView, DeniedAuthorizedView, DenyAllAuthorization, MetadataStore,
    MetadataTransaction, ObjectValidationPort, ProductionObjectValidator,
};
pub use postgres::{PostgresMetadataStore, PostgresMetadataTransaction};
pub use types::{
    AuthorizationContext, AuthorizationResource, CaseMode, CommitSequence, ConsistencyToken,
    CursorToken, FileHistoryRecord, FileHistoryWrite, FileIdExpectedState, FileIdImportReservation,
    FileIdOrigin, FileIdOwnerKind, FileIdReservation, FileIdReservationOutcome,
    IdempotencyReservation, IdempotencyReservationOutcome, MetadataObjectRecord,
    MetadataPermission, ObjectPutOutcome, ObjectWrite, OutboxClaimRequest, OutboxEvent,
    OutboxEventRecord, OutboxLeaseAction, OutboxLeaseRecord, OutboxReleaseRequest, Page,
    PageRequest, ProjectId, ReferenceCasRequest, ReferenceCasResult, ReferenceExpected,
    ReferenceFilter, ReferenceKind, ReferenceName, ReferenceRecord, RepositoryCreate, RepositoryId,
    RepositorySettings, SnapshotWrite, TenantId, TransactionCapability, TransactionOptions,
    TreeEntryRecord, TreeEntryWrite,
};
