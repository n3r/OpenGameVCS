//! OGVCS-006 repository metadata domain and transaction boundary.
//!
//! This crate intentionally contains no HTTP or PostgreSQL driver. It freezes
//! the transaction-composable module API and authenticates the SQL migration
//! contract before a concrete adapter is added.
#![forbid(unsafe_code)]

mod error;
mod migration;
mod ports;
mod types;

pub use error::{DomainError, DomainErrorCode, Result};
pub use migration::{Migration, MigrationPhase, MIGRATIONS};
pub use ogvcs_object_model::{FileId, ObjectRef};
pub use ports::{AuthorizationPort, MetadataStore, MetadataTransaction};
pub use types::{
    AuthorizationContext, CaseMode, CommitSequence, ConsistencyToken, FileIdOrigin,
    FileIdOwnerKind, FileIdReservation, ObjectPutOutcome, ObjectWrite, OutboxEvent,
    ReferenceCasRequest, ReferenceCasResult, ReferenceExpected, ReferenceKind,
    ReferenceName, RepositoryId, RepositorySettings, TenantId, TransactionOptions,
};
