//! OGVCS-009 same-transaction identity, authorization, and decision participant.
//!
//! The production boundary borrows a caller-owned live `postgres::Transaction`
//! for authorization, exact batch recheck, and ordinary decision commitment.
//! It never returns or owns that transaction. Any operation-level denial,
//! validation failure, currentness failure, or storage error deliberately
//! aborts the PostgreSQL transaction so a caller can only roll it back. The
//! authorized-page primitive treats per-candidate policy denial as a private
//! visibility bit; every other page fault still poisons the transaction.
#![forbid(unsafe_code)]

mod aggregate;
mod canonical;
mod error;
mod migration;
mod migration_runner;
mod model;
mod participant;
mod policy;

pub use aggregate::{
    AggregateAuthorizationReceipt, AggregateHmacKeyProvider, AggregatePlanHandle,
    AggregatePlanRequest, AggregateReceiptConsumption, AggregateReceiptConsumptionRequest,
    AggregateResourceDigestProjection, AggregateSigningKeyRegistration, AggregateUploadProgress,
    HmacSha256KeyRing, PostgresAggregateAuthorizationParticipant, RepositoryContractBinding,
    RepositoryContractBindingRequest, AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA,
    AGGREGATE_PLAN_HANDLE_SCHEMA, AGGREGATE_RESOURCE_DIGEST_PROJECTION_ALGORITHM,
    AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY, AGGREGATE_SUBMIT_PERMISSION,
    MAXIMUM_AGGREGATE_CHUNK_BYTES, MAXIMUM_AGGREGATE_CHUNK_ITEMS,
    MAXIMUM_AGGREGATE_PLAN_TTL_SECONDS, MAXIMUM_AGGREGATE_RESOURCES,
};
pub use error::{ParticipantError, ParticipantErrorCode, Result};
pub use migration::{Migration, MigrationPhase, MIGRATIONS};
pub use migration_runner::{
    run_migrations, verify_schema_compatibility, MigrationRunOptions, MigrationRunReport,
};
pub use model::{
    AuthorizationResource, AuthorizedResourceBatch, AuthorizedResourceBatchItem,
    CredentialRevocation, CredentialScope, DecisionChainVerification, DecisionCommitmentRequest,
    EpochPromotion, PolicyDocument, PolicyReplacement, PolicyRule, PrivilegedAuditContext,
    PrivilegedAuditDetails, PrivilegedAuditEvent, RuleSubjects,
    TransactionAuthorizationPageCandidate, TransactionAuthorizationRequest,
    TransactionAuthorizedPage, TransactionAuthorizedPageQuery, TransactionAuthorizedPageRequest,
    TransactionAuthorizedView, TransactionBatchRecheck, TransactionCredentialEvidence,
    TransactionDecisionCommitment, VerifiedTransactionAuthorizedPage,
    AUTHORIZED_RESOURCE_BATCH_SCHEMA, MAXIMUM_AUTHORIZATION_PAGE_CANDIDATES,
    MAXIMUM_AUTHORIZED_PAGE_RESULTS, MAXIMUM_BATCH_RESOURCES, MAXIMUM_DECISION_CHAIN_SCAN,
    MAXIMUM_DECISION_RESULT_BYTES, PRIVILEGED_AUDIT_EVENT_SCHEMA,
    TRANSACTION_AUTHORIZED_PAGE_QUERY_SCHEMA, TRANSACTION_AUTHORIZED_PAGE_SCHEMA,
    TRANSACTION_AUTHORIZED_VIEW_SCHEMA, TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA,
    TRANSACTION_DECISION_COMMITMENT_SCHEMA,
};
pub use participant::{
    PostgresTransactionAuthorizationParticipant, TransactionAuthorizationParticipant,
};
