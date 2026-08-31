//! OGVCS-006 repository metadata domain and transaction boundary.
//!
//! HTTP remains disabled until a later protocol release binds the domain
//! errors. This crate does include the reference PostgreSQL adapter and the
//! transaction-composable API used by the OGVCS-010 submit coordinator.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(feature = "legacy-test-adapter"),
    doc = r#"
The caller-context compatibility store is intentionally absent from default
production builds:

```compile_fail
use ogvcs_repository_metadata::PostgresMetadataStore;

let _ = PostgresMetadataStore::connect("postgresql://example.invalid/db");
```

The legacy committed-status disclosure and transaction inspection projection
are absent as well:

```compile_fail
use ogvcs_repository_metadata::PostgresMetadataStore;

let _ = PostgresMetadataStore::idempotency_status;
```

```compile_fail
use ogvcs_repository_metadata::{
    DeniedAuthorizedView, PostgresMetadataTransaction, ProductionObjectValidator,
};

fn inspect(
    transaction: &PostgresMetadataTransaction<
        '_,
        ProductionObjectValidator,
        DeniedAuthorizedView,
    >,
) {
    let _ = transaction.authorized_view();
}
```
"#
)]

mod error;
mod lifecycle;
mod migration;
mod migration_runner;
mod ports;
mod postgres;
mod types;

pub use error::{DomainError, DomainErrorCode, Result};
#[cfg(feature = "legacy-test-adapter")]
pub use lifecycle::{
    aggregate_chunk_count, aggregate_plan_digest, AggregateChunkCommitment, AggregatePlanChunk,
    AggregatePublicationPlan, LifecycleApplicationReceipt, LifecycleCapability,
    LifecycleDirectCommand, LifecycleHealth, LifecycleHealthObservation, LifecycleObjectBinding,
    LifecycleQuarantineRequest, LifecycleReceiptKind, LifecycleReceiptWrite, LifecycleState,
    StagedLifecycleObject, AGGREGATE_OBJECTS_MAXIMUM, DIRECT_OBJECTS_MAXIMUM,
    LIFECYCLE_CONTRACT_VERSION, OBJECT_TRANSFER_ARTIFACT_SET_SHA256,
    OBJECT_TRANSFER_MANIFEST_SHA256, PLAN_CHUNK_BYTES_MAXIMUM, PLAN_CHUNK_ITEMS_MAXIMUM,
};
pub use migration::{Migration, MigrationPhase, MIGRATIONS};
pub use migration_runner::{
    run_migrations, verify_schema_compatibility, MigrationRunOptions, MigrationRunReport,
};
pub use ogvcs_object_model::{FileId, ObjectRef};
pub use ports::{
    AuthorizationPort, AuthorizedView, DeniedAuthorizedView, DenyAllAuthorization, MetadataStore,
    MetadataTransaction, ObjectValidationPort, ProductionObjectValidator,
};
#[cfg(feature = "legacy-test-adapter")]
pub use postgres::PostgresLifecyclePlanWriter;
pub use postgres::{
    IdentityBoundPostgresMetadataStore, IdentityMetadataAuthorizedView, PostgresMetadataStore,
    PostgresMetadataTransaction,
};
pub use types::{
    AllocationReceipt, AncestryRecord, AuthorizationContext, AuthorizationResource, CaseMode,
    CommitSequence, ConsistencyToken, CursorToken, FileHistoryRecord, FileHistoryWrite,
    FileIdAllocation, FileIdExpectedState, FileIdImportReservation, FileIdOrigin, FileIdOwnerKind,
    FileIdReservation, FileIdReservationOutcome, HistoryIncompleteReason, HistoryPage,
    IdempotencyReservation, IdempotencyReservationOutcome, IdempotencyStatus, MetadataHttpResponse,
    MetadataObjectRecord, MetadataPermission, NativeFileIdReservation, ObjectPutOutcome,
    ObjectWrite, OutboxClaimRequest, OutboxEvent, OutboxEventRecord, OutboxLeaseAction,
    OutboxLeaseRecord, OutboxReleaseRequest, Page, PageRequest, PageState, ProjectId,
    ReferenceCasRequest, ReferenceCasResult, ReferenceExpected, ReferenceFilter, ReferenceKind,
    ReferenceName, ReferenceRecord, RepositoryCreate, RepositoryId, RepositoryRecord,
    RepositorySettings, SnapshotWrite, TenantId, TransactionCapability,
    TransactionCredentialRequest, TransactionOptions, TreeEntryRecord, TreeEntryWrite,
};
