//! OGVCS-009 same-transaction identity, authorization, and decision participant.
//!
//! The production boundary borrows a caller-owned live `postgres::Transaction`
//! for authorization, exact batch recheck, and ordinary decision commitment.
//! It never returns or owns that transaction. Any denial, validation failure,
//! currentness failure, or storage error deliberately aborts the PostgreSQL
//! transaction so a caller can only roll it back.
#![forbid(unsafe_code)]

mod canonical;
mod error;
mod migration;
mod migration_runner;
mod model;
mod participant;
mod policy;

pub use error::{ParticipantError, ParticipantErrorCode, Result};
pub use migration::{Migration, MigrationPhase, MIGRATIONS};
pub use migration_runner::{
    run_migrations, verify_schema_compatibility, MigrationRunOptions, MigrationRunReport,
};
pub use model::{
    AuthorizationResource, AuthorizedResourceBatch, CredentialRevocation, CredentialScope,
    DecisionChainVerification, DecisionCommitmentRequest, EpochPromotion, PolicyDocument,
    PolicyReplacement, PolicyRule, PrivilegedAuditContext, PrivilegedAuditDetails,
    PrivilegedAuditEvent, RuleSubjects, TransactionAuthorizationRequest, TransactionAuthorizedView,
    TransactionBatchRecheck, TransactionCredentialEvidence, TransactionDecisionCommitment,
    MAXIMUM_BATCH_RESOURCES, MAXIMUM_DECISION_CHAIN_SCAN, MAXIMUM_DECISION_RESULT_BYTES,
    PRIVILEGED_AUDIT_EVENT_SCHEMA, TRANSACTION_AUTHORIZED_VIEW_SCHEMA,
    TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA, TRANSACTION_DECISION_COMMITMENT_SCHEMA,
};
pub use participant::{
    PostgresTransactionAuthorizationParticipant, TransactionAuthorizationParticipant,
};
