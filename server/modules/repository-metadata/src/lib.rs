//! OGVCS-006 repository metadata domain and transaction boundary.
//!
//! OGVCS-041 route and envelope assignments are authenticated, but production
//! network registration remains empty. The first sealed PostgreSQL dispatcher
//! accepts only negotiation-verified `repository.get-settings` and
//! `reference.read` requests, retains its OGVCS-009 decision through commit,
//! and constructs success only after commit. It is an adapter-internal
//! candidate, not an HTTP/authentication carrier or protocol authority. This
//! crate also includes the transaction-composable API used by the OGVCS-010
//! submit coordinator.
//!
//! A syntax-only request cannot enter the production read dispatcher:
//!
//! ```compile_fail
//! use ogvcs_repository_metadata::{
//!     MetadataOperationRequest, PostgresMetadataReadDispatcher,
//!     TransactionCredentialRequest,
//! };
//!
//! fn bypass(
//!     dispatcher: &mut PostgresMetadataReadDispatcher,
//!     request: MetadataOperationRequest,
//!     credentials: TransactionCredentialRequest<'_>,
//! ) {
//!     let _ = dispatcher.dispatch_verified_read(request, credentials);
//! }
//! ```
//!
//! Success-envelope construction and its committed authorization brand remain
//! private to the adapter:
//!
//! ```compile_fail
//! use ogvcs_repository_metadata::MetadataResponseEnvelope;
//!
//! let _ = MetadataResponseEnvelope::success_for_committed_dispatch;
//! ```
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
mod service;
mod types;

pub use error::{DomainError, DomainErrorCode, Result};
pub use lifecycle::LifecycleApplicationReceipt;
#[cfg(feature = "legacy-test-adapter")]
pub use lifecycle::{
    aggregate_chunk_count, aggregate_plan_digest, AggregateChunkCommitment, AggregatePlanChunk,
    AggregatePublicationPlan, LifecycleCapability, LifecycleDirectCommand, LifecycleHealth,
    LifecycleHealthObservation, LifecycleObjectBinding, LifecycleQuarantineRequest,
    LifecycleReceiptKind, LifecycleReceiptWrite, LifecycleState, StagedLifecycleObject,
    AGGREGATE_OBJECTS_MAXIMUM, AUTHORIZATION_MANIFEST_SHA256, DIRECT_OBJECTS_MAXIMUM,
    LIFECYCLE_CONTRACT_ARTIFACT_SET_SHA256, LIFECYCLE_CONTRACT_SHA256, LIFECYCLE_CONTRACT_VERSION,
    OBJECT_TRANSFER_ARTIFACT_SET_SHA256, OBJECT_TRANSFER_MANIFEST_SHA256, PLAN_CHUNK_BYTES_MAXIMUM,
    PLAN_CHUNK_ITEMS_MAXIMUM,
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
pub use postgres::AtomicSubmitFaultForTest;
#[cfg(feature = "legacy-test-adapter")]
pub use postgres::PostgresLifecyclePlanWriter;
pub use postgres::{
    AggregateLifecycleApplicationReceipt, AggregateLifecycleApplyRequest,
    IdentityBoundPostgresMetadataStore, IdentityMetadataAuthorizedView,
    PostgresMetadataReadDispatcher, PostgresMetadataStore, PostgresMetadataTransaction,
    PreallocatedCreationSubmitFinalizeRequest, PreallocatedCreationSubmitIntent,
    PreallocatedCreationSubmitIntentRequest, PreallocatedCreationSubmitOutcome,
    PreallocatedCreationSubmitPreflight, PreallocatedCreationSubmitPreflightRequest,
    PreallocatedCreationSubmitReconciliation,
};
pub use service::{
    network_transport_descriptors, AdmittedMetadataRoute, MetadataNegotiationKeyProvider,
    MetadataNegotiationKeyRing, MetadataNegotiationPrincipal, MetadataOperation,
    MetadataOperationClass, MetadataOperationDescriptor, MetadataOperationExposure,
    MetadataOperationRequest, MetadataPayloadCarrier, MetadataProtocolProblem,
    MetadataResponseEnvelope, MetadataServerCorrelationId, MetadataServiceBoundaryError,
    MetadataStreamBinding, MetadataTransportDescriptor, MetadataTransportError,
    MetadataTransportRequest, NegotiationVerifiedMetadataRequest, NegotiationVerifiedMetadataRoute,
    ServicePageRequest, METADATA_CONTROL_MEDIA_TYPE, METADATA_OPERATION_DESCRIPTORS,
    METADATA_PROTOCOL_PROFILE, METADATA_RESPONSE_MEDIA_TYPE, METADATA_SERVICE_CONTRACT_VERSION,
    METADATA_SERVICE_MANIFEST_SHA256, METADATA_SERVICE_OPERATION_COUNT,
    METADATA_SERVICE_REQUEST_SCHEMA, METADATA_SERVICE_RESPONSE_SCHEMA,
    METADATA_SERVICE_RESULT_BODY_SCHEMA, METADATA_TRANSPORT_DESCRIPTORS,
    OGVCS_041_CONTROL_PROFILE_SHA256, OGVCS_041_ERROR_REGISTRY_SHA256, OGVCS_041_MANIFEST_SHA256,
    OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256, OGVCS_041_PROBLEM_DETAILS_SHA256,
    OGVCS_041_REGISTRY_SET_SHA256, OGVCS_041_REQUEST_ENVELOPE_SHA256,
    OGVCS_041_RESPONSE_ENVELOPE_SHA256, PUBLIC_CANONICAL_METADATA_BYTES_MAXIMUM,
    PUBLIC_HISTORY_DEPTH_MAXIMUM, PUBLIC_OUTBOX_CLAIM_ITEMS_MAXIMUM, PUBLIC_PAGE_ITEMS_MAXIMUM,
    PUBLIC_TOKEN_TTL_SECONDS_MAXIMUM,
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
