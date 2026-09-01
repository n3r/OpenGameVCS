use super::*;
use crate::lifecycle::domain_digest;
use ogvcs_identity_policy_audit_postgres::{
    AggregateAuthorizationReceipt, AggregateReceiptConsumptionRequest,
    AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY, AGGREGATE_SUBMIT_PERMISSION,
};

const OPERATION_DIGEST_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-OPERATION-V1";
const OPERATION_SET_INITIAL_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-OPERATION-SET-INITIAL-V1";
const OPERATION_SET_STEP_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-OPERATION-SET-STEP-V1";
const OPERATION_SET_FINAL_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-OPERATION-SET-FINAL-V1";
const SUBMIT_FINGERPRINT_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-FINGERPRINT-V1";
const INTENT_DIGEST_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-INTENT-V1";
const PREFLIGHT_DIGEST_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-PREFLIGHT-V1";
const FILE_ID_CONSUMPTION_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-FILEID-CONSUMPTION-V1";
const AUDIT_EVIDENCE_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-INTERNAL-AUDIT-V1";
const RESULT_DIGEST_DOMAIN: &[u8] = b"OGVCS-PRIVATE-SUBMIT-RESULT-V1";
const RECONCILIATION_COMMITMENT_DOMAIN: &[u8] =
    b"OGVCS-PRIVATE-SUBMIT-RECONCILIATION-COMMITMENT-V1";
const RECONCILIATION_OBSERVATION_DOMAIN: &[u8] =
    b"OGVCS-PRIVATE-SUBMIT-RECONCILIATION-OBSERVATION-V1";
const MAXIMUM_PRIVATE_SUBMIT_OPERATIONS: usize = 1_000;

/// Private candidate request. This is intentionally not a general finalize
/// protocol: the sealed candidate must contain one to 1,000 create/copy/import
/// first-consumption operations and no other operation kind.
pub struct PreallocatedCreationSubmitIntentRequest<'a> {
    pub authorization: &'a AggregateAuthorizationReceipt,
    pub lifecycle_plan_id: [u8; 16],
    pub expected_head: ObjectRef,
    pub expected_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreallocatedCreationSubmitIntent {
    intent_id: [u8; 16],
    lifecycle_plan_id: [u8; 16],
    repository_id: RepositoryId,
    reference_name: String,
    expected_head: ObjectRef,
    expected_generation: u64,
    candidate_snapshot: ObjectRef,
    candidate_change_set_digest: [u8; 32],
    operation_count: u16,
    operation_set_digest: [u8; 32],
    intent_digest: [u8; 32],
    expires_at: SystemTime,
}

impl PreallocatedCreationSubmitIntent {
    pub const fn intent_id(&self) -> &[u8; 16] {
        &self.intent_id
    }

    pub const fn lifecycle_plan_id(&self) -> &[u8; 16] {
        &self.lifecycle_plan_id
    }

    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    pub fn reference_name(&self) -> &str {
        &self.reference_name
    }

    pub const fn expected_head(&self) -> ObjectRef {
        self.expected_head
    }

    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    pub const fn candidate_snapshot(&self) -> ObjectRef {
        self.candidate_snapshot
    }

    pub const fn candidate_change_set_digest(&self) -> &[u8; 32] {
        &self.candidate_change_set_digest
    }

    pub const fn operation_count(&self) -> u16 {
        self.operation_count
    }

    pub const fn operation_set_digest(&self) -> &[u8; 32] {
        &self.operation_set_digest
    }

    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }

    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

pub struct PreallocatedCreationSubmitPreflightRequest<'a> {
    pub intent_id: [u8; 16],
    pub authorization: &'a AggregateAuthorizationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreallocatedCreationSubmitPreflight {
    preflight_id: [u8; 16],
    revision: u64,
    branch_matches: bool,
    preflight_digest: [u8; 32],
    expires_at: SystemTime,
}

impl PreallocatedCreationSubmitPreflight {
    pub const fn preflight_id(&self) -> &[u8; 16] {
        &self.preflight_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn branch_matches(&self) -> bool {
        self.branch_matches
    }

    pub const fn preflight_digest(&self) -> &[u8; 32] {
        &self.preflight_digest
    }

    pub const fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
}

pub struct PreallocatedCreationSubmitFinalizeRequest<'a> {
    pub intent_id: [u8; 16],
    pub authorization: &'a AggregateAuthorizationReceipt,
    pub consumption_id: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreallocatedCreationSubmitOutcome {
    intent_id: [u8; 16],
    application_id: [u8; 16],
    lifecycle_receipt_digest: [u8; 32],
    identity_plan_id: String,
    consumption_id: String,
    operation_digest: [u8; 32],
    old_head: ObjectRef,
    new_head: ObjectRef,
    branch_generation: u64,
    commit_sequence: u64,
    authority_epoch: u64,
    audit_correlation_id: [u8; 16],
    outbox_event_id: [u8; 16],
    consistency_token: String,
    consistency_token_digest: [u8; 32],
    result_digest: [u8; 32],
    reconciliation_commitment_digest: [u8; 32],
    replayed: bool,
}

impl PreallocatedCreationSubmitOutcome {
    pub const fn intent_id(&self) -> &[u8; 16] {
        &self.intent_id
    }

    pub const fn application_id(&self) -> &[u8; 16] {
        &self.application_id
    }

    pub const fn lifecycle_receipt_digest(&self) -> &[u8; 32] {
        &self.lifecycle_receipt_digest
    }

    pub fn identity_plan_id(&self) -> &str {
        &self.identity_plan_id
    }

    pub fn consumption_id(&self) -> &str {
        &self.consumption_id
    }

    pub const fn operation_digest(&self) -> &[u8; 32] {
        &self.operation_digest
    }

    pub const fn old_head(&self) -> ObjectRef {
        self.old_head
    }

    pub const fn new_head(&self) -> ObjectRef {
        self.new_head
    }

    pub const fn branch_generation(&self) -> u64 {
        self.branch_generation
    }

    pub const fn commit_sequence(&self) -> u64 {
        self.commit_sequence
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn audit_correlation_id(&self) -> &[u8; 16] {
        &self.audit_correlation_id
    }

    pub const fn outbox_event_id(&self) -> &[u8; 16] {
        &self.outbox_event_id
    }

    pub fn consistency_token(&self) -> &str {
        &self.consistency_token
    }

    pub const fn consistency_token_digest(&self) -> &[u8; 32] {
        &self.consistency_token_digest
    }

    pub const fn result_digest(&self) -> &[u8; 32] {
        &self.result_digest
    }

    pub const fn reconciliation_commitment_digest(&self) -> &[u8; 32] {
        &self.reconciliation_commitment_digest
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreallocatedCreationSubmitReconciliation {
    Committed(Box<PreallocatedCreationSubmitOutcome>),
    UnknownRecovering { observation_digest: [u8; 32] },
}

#[cfg(feature = "legacy-test-adapter")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicSubmitFaultForTest {
    BeforeBridge,
    AfterBridge,
    AfterFileIdConsumption,
    AfterSnapshotMarker,
    AfterBranchCas,
    AfterAudit,
    AfterOutboxEvent,
    AfterConsistencyToken,
    AfterFinalOutcome,
    AfterReconciliation,
    /// Test boundary after reconciliation is written but before the
    /// transaction returns to the caller-owned commit path. This does not
    /// simulate a PostgreSQL commit-I/O failure.
    BeforeCommit,
}

/// Private live-harness boundary used to stop a real PostgreSQL transaction
/// while the disposable server is hard-killed. This surface is absent unless
/// the repository's legacy test adapter feature is selected.
#[cfg(feature = "legacy-test-adapter")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicSubmitRestartBoundaryForTest {
    BeforeBridge,
    AfterBridge,
    AfterFileIdConsumption,
    AfterSnapshotMarker,
    AfterBranchCas,
    AfterAudit,
    AfterOutboxEvent,
    AfterConsistencyToken,
    AfterFinalOutcome,
    AfterReconciliation,
    BeforeCommit,
    CommitIo,
    AfterCommitBeforeResponse,
}

#[cfg(feature = "legacy-test-adapter")]
impl AtomicSubmitRestartBoundaryForTest {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeforeBridge => "before-bridge",
            Self::AfterBridge => "after-bridge",
            Self::AfterFileIdConsumption => "after-file-id-consumption",
            Self::AfterSnapshotMarker => "after-snapshot-marker",
            Self::AfterBranchCas => "after-branch-cas",
            Self::AfterAudit => "after-audit",
            Self::AfterOutboxEvent => "after-outbox-event",
            Self::AfterConsistencyToken => "after-consistency-token",
            Self::AfterFinalOutcome => "after-final-outcome",
            Self::AfterReconciliation => "after-reconciliation",
            Self::BeforeCommit => "before-commit",
            Self::CommitIo => "commit-io",
            Self::AfterCommitBeforeResponse => "after-commit-before-response",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomicSubmitFault {
    None,
    BeforeBridge,
    AfterBridge,
    AfterFileIdConsumption,
    AfterSnapshotMarker,
    AfterBranchCas,
    AfterAudit,
    AfterOutboxEvent,
    AfterConsistencyToken,
    AfterFinalOutcome,
    AfterReconciliation,
    BeforeCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomicSubmitControl {
    Fault(AtomicSubmitFault),
    #[cfg(feature = "legacy-test-adapter")]
    Restart {
        boundary: AtomicSubmitRestartBoundaryForTest,
        rendezvous_seconds: u16,
    },
}

#[derive(Clone, Debug)]
struct SealedSubmitPlan {
    lifecycle_plan_id: Uuid,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    publication: ObjectRef,
    authorization_reference: String,
    authorization_snapshot: String,
    subject_digest: [u8; 32],
    authorization_epoch: u64,
    lifecycle_plan_digest: [u8; 32],
    authenticated_scope_digest: [u8; 32],
    idempotency_operation: String,
    idempotency_key: String,
    semantic_fingerprint: [u8; 32],
    object_count: u32,
    identity_plan_id: Option<String>,
    identity_decision_digest: Option<[u8; 32]>,
    identity_resource_projection_digest: Option<[u8; 32]>,
    expires_at: SystemTime,
}

#[derive(Clone, Debug)]
struct IntentOperation {
    ordinal: u16,
    operation_kind: String,
    file_id: [u8; 16],
    path: Vec<u8>,
    prior_owner_kind: String,
    prior_owner_id: String,
    operation_digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct IntentRecord {
    intent: PreallocatedCreationSubmitIntent,
    plan: SealedSubmitPlan,
    tenant_id: TenantId,
    authenticated_scope_digest: [u8; 32],
}

impl<A, V> IdentityBoundPostgresMetadataStore<A, V> {
    pub fn create_preallocated_creation_submit_intent(
        &mut self,
        request: PreallocatedCreationSubmitIntentRequest<'_>,
    ) -> Result<PreallocatedCreationSubmitIntent> {
        crate::verify_schema_compatibility(&mut self.store.client)?;
        if request.expected_head.kind != ObjectKind::Snapshot
            || request.expected_generation == 0
            || request.expected_generation > crate::lifecycle::MAXIMUM_SAFE_GENERATION
        {
            return Err(denied());
        }
        let PostgresMetadataStore {
            client,
            aggregate_authorization,
            ..
        } = &mut self.store;
        let participant = aggregate_authorization.as_ref().ok_or_else(denied)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let result = create_intent_transaction(&mut transaction, participant, &request);
        match result {
            Ok(intent) => {
                transaction.commit().map_err(database_error)?;
                Ok(intent)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error)
            }
        }
    }

    pub fn preflight_preallocated_creation_submit(
        &mut self,
        request: PreallocatedCreationSubmitPreflightRequest<'_>,
    ) -> Result<PreallocatedCreationSubmitPreflight> {
        crate::verify_schema_compatibility(&mut self.store.client)?;
        let PostgresMetadataStore {
            client,
            aggregate_authorization,
            ..
        } = &mut self.store;
        let participant = aggregate_authorization.as_ref().ok_or_else(denied)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let result = preflight_transaction(&mut transaction, participant, &request);
        match result {
            Ok(preflight) => {
                transaction.commit().map_err(database_error)?;
                Ok(preflight)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error)
            }
        }
    }

    pub fn finalize_preallocated_creation_submit(
        &mut self,
        request: PreallocatedCreationSubmitFinalizeRequest<'_>,
    ) -> Result<PreallocatedCreationSubmitOutcome> {
        self.finalize_preallocated_creation_submit_inner(
            request,
            AtomicSubmitControl::Fault(AtomicSubmitFault::None),
            false,
        )
    }

    pub fn reconcile_preallocated_creation_submit(
        &mut self,
        request: PreallocatedCreationSubmitFinalizeRequest<'_>,
    ) -> Result<PreallocatedCreationSubmitReconciliation> {
        crate::verify_schema_compatibility(&mut self.store.client)?;
        let PostgresMetadataStore {
            client,
            aggregate_authorization,
            ..
        } = &mut self.store;
        let participant = aggregate_authorization.as_ref().ok_or_else(denied)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let result = reconcile_transaction(&mut transaction, participant, &request);
        match result {
            Ok(observation) => {
                transaction.commit().map_err(database_error)?;
                Ok(observation)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error)
            }
        }
    }

    fn finalize_preallocated_creation_submit_inner(
        &mut self,
        request: PreallocatedCreationSubmitFinalizeRequest<'_>,
        control: AtomicSubmitControl,
        lose_response_after_commit: bool,
    ) -> Result<PreallocatedCreationSubmitOutcome> {
        crate::verify_schema_compatibility(&mut self.store.client)?;
        let PostgresMetadataStore {
            client,
            aggregate_authorization,
            ..
        } = &mut self.store;
        let participant = aggregate_authorization.as_ref().ok_or_else(denied)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let result = finalize_transaction(&mut transaction, participant, &request, control);
        match result {
            Ok(outcome) => {
                #[cfg(feature = "legacy-test-adapter")]
                arm_commit_io_restart_rendezvous(&mut transaction, request.intent_id, control)?;
                transaction.commit().map_err(database_error)?;
                #[cfg(feature = "legacy-test-adapter")]
                await_after_commit_restart_rendezvous(client, control)?;
                if lose_response_after_commit {
                    Err(DomainError::new(DomainErrorCode::TransactionRetryExhausted))
                } else {
                    Ok(outcome)
                }
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error)
            }
        }
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn finalize_preallocated_creation_submit_with_fault_for_test(
        &mut self,
        request: PreallocatedCreationSubmitFinalizeRequest<'_>,
        fault: AtomicSubmitFaultForTest,
    ) -> Result<PreallocatedCreationSubmitOutcome> {
        let fault = match fault {
            AtomicSubmitFaultForTest::BeforeBridge => AtomicSubmitFault::BeforeBridge,
            AtomicSubmitFaultForTest::AfterBridge => AtomicSubmitFault::AfterBridge,
            AtomicSubmitFaultForTest::AfterFileIdConsumption => {
                AtomicSubmitFault::AfterFileIdConsumption
            }
            AtomicSubmitFaultForTest::AfterSnapshotMarker => AtomicSubmitFault::AfterSnapshotMarker,
            AtomicSubmitFaultForTest::AfterBranchCas => AtomicSubmitFault::AfterBranchCas,
            AtomicSubmitFaultForTest::AfterAudit => AtomicSubmitFault::AfterAudit,
            AtomicSubmitFaultForTest::AfterOutboxEvent => AtomicSubmitFault::AfterOutboxEvent,
            AtomicSubmitFaultForTest::AfterConsistencyToken => {
                AtomicSubmitFault::AfterConsistencyToken
            }
            AtomicSubmitFaultForTest::AfterFinalOutcome => AtomicSubmitFault::AfterFinalOutcome,
            AtomicSubmitFaultForTest::AfterReconciliation => AtomicSubmitFault::AfterReconciliation,
            AtomicSubmitFaultForTest::BeforeCommit => AtomicSubmitFault::BeforeCommit,
        };
        self.finalize_preallocated_creation_submit_inner(
            request,
            AtomicSubmitControl::Fault(fault),
            false,
        )
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn finalize_preallocated_creation_submit_with_lost_response_for_test(
        &mut self,
        request: PreallocatedCreationSubmitFinalizeRequest<'_>,
    ) -> Result<PreallocatedCreationSubmitOutcome> {
        self.finalize_preallocated_creation_submit_inner(
            request,
            AtomicSubmitControl::Fault(AtomicSubmitFault::None),
            true,
        )
    }

    /// Runs one exact live-harness rendezvous. The caller must arrange the
    /// disposable PostgreSQL supervisor and, for `CommitIo`, the test-only
    /// deferred trigger. No environment or process control enters the library.
    #[cfg(feature = "legacy-test-adapter")]
    pub fn finalize_preallocated_creation_submit_with_restart_rendezvous_for_test(
        &mut self,
        request: PreallocatedCreationSubmitFinalizeRequest<'_>,
        boundary: AtomicSubmitRestartBoundaryForTest,
        rendezvous_seconds: u16,
    ) -> Result<PreallocatedCreationSubmitOutcome> {
        if !(1..=300).contains(&rendezvous_seconds) {
            return Err(denied());
        }
        self.finalize_preallocated_creation_submit_inner(
            request,
            AtomicSubmitControl::Restart {
                boundary,
                rendezvous_seconds,
            },
            false,
        )
    }

    /// Returns true only if PostgreSQL incorrectly permits commit after a
    /// caller catches a crate-private bridge error.
    #[cfg(feature = "legacy-test-adapter")]
    pub fn caught_bridge_error_commits_for_test(
        &mut self,
        request: AggregateLifecycleApplyRequest<'_>,
    ) -> Result<bool> {
        crate::verify_schema_compatibility(&mut self.store.client)?;
        let PostgresMetadataStore {
            client,
            aggregate_authorization,
            ..
        } = &mut self.store;
        let participant = aggregate_authorization.as_ref().ok_or_else(denied)?;
        let before: i64 = client
            .query_one(
                "SELECT COALESCE(sum(applied_sequence), 0)::bigint
                 FROM ogvcs_metadata.repository_commit_sequences",
                &[],
            )
            .map_err(database_error)?
            .get(0);
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let _ = apply_aggregate_lifecycle_publication_in_transaction(
            &mut transaction,
            participant,
            &request,
        );
        let _ = transaction.execute(
            "UPDATE ogvcs_metadata.repository_commit_sequences
             SET applied_sequence = applied_sequence + 1000",
            &[],
        );
        let _ = transaction.commit();
        let after: i64 = client
            .query_one(
                "SELECT COALESCE(sum(applied_sequence), 0)::bigint
                 FROM ogvcs_metadata.repository_commit_sequences",
                &[],
            )
            .map_err(database_error)?
            .get(0);
        Ok(after != before)
    }
}

fn create_intent_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    request: &PreallocatedCreationSubmitIntentRequest<'_>,
) -> Result<PreallocatedCreationSubmitIntent> {
    participant
        .verify_receipt_current(transaction, request.authorization)
        .map_err(|_| denied())?;
    let plan = load_sealed_submit_plan(transaction, request.lifecycle_plan_id, false)?;
    verify_receipt_plan_binding(request.authorization, &plan)?;
    if plan.publication.kind != ObjectKind::Snapshot
        || plan.idempotency_operation != "submit.finalize"
        || plan.expires_at <= server_now(transaction)?
    {
        return Err(denied());
    }

    if let Some(existing) = load_intent_by_plan(transaction, plan.lifecycle_plan_id, false)? {
        if existing.intent.expected_head != request.expected_head
            || existing.intent.expected_generation != request.expected_generation
            || existing.plan.subject_digest != plan.subject_digest
            || existing.plan.lifecycle_plan_digest != plan.lifecycle_plan_digest
        {
            return Err(denied());
        }
        return Ok(existing.intent);
    }

    // Intent creation is advisory: finalization owns the exact branch lock and
    // CAS. Keep this as an MVCC observation so the participant's repository
    // advisory lock is never held while waiting behind a concurrent finalizer.
    let branch = transaction
        .query_opt(
            "SELECT target_snapshot_digest, generation
             FROM ogvcs_metadata.references
             WHERE repository_id = $1 AND reference_kind = 'branch' AND reference_name = $2",
            &[&uuid(plan.repository_id), &plan.authorization_reference],
        )
        .map_err(database_error)?
        .ok_or_else(denied)?;
    if digest32(branch.get(0))? != request.expected_head.digest
        || positive_u64(branch.get(1))? != request.expected_generation
    {
        return Err(denied());
    }

    let candidate_change_set_digest =
        candidate_change_set_digest(transaction, plan.repository_id, plan.publication.digest)?;
    let mut operations = load_candidate_operations(
        transaction,
        plan.repository_id,
        plan.publication.digest,
        candidate_change_set_digest,
    )?;
    if operations.is_empty() || operations.len() > MAXIMUM_PRIVATE_SUBMIT_OPERATIONS {
        return Err(denied());
    }
    for operation in &mut operations {
        operation.operation_digest = submit_operation_digest(operation);
    }
    let operation_set_digest = submit_operation_set_digest(&operations);
    let submit_fingerprint = submit_fingerprint(
        &plan,
        request.expected_head,
        request.expected_generation,
        candidate_change_set_digest,
        operation_set_digest,
        operations.len(),
    );
    let intent_id = random_public_uuid()?;
    let intent_digest = submit_intent_digest(
        intent_id,
        &plan,
        request.expected_head,
        request.expected_generation,
        candidate_change_set_digest,
        submit_fingerprint,
        operation_set_digest,
        operations.len(),
    );

    insert_intent_operations(
        transaction,
        intent_id,
        plan.repository_id,
        plan.publication.digest,
        &operations,
    )?;
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_intents
             (intent_id, tenant_id, repository_id, lifecycle_plan_id,
              reference_name, expected_head_digest, expected_generation,
              candidate_snapshot_digest, candidate_change_set_digest,
              lifecycle_plan_digest, authenticated_scope_digest,
              idempotency_operation, idempotency_key,
              lifecycle_semantic_fingerprint, submit_fingerprint,
              operation_count, operation_set_digest, intent_digest, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                     'submit.finalize', $12, $13, $14, $15, $16, $17, $18)",
            &[
                &Uuid::from_bytes(intent_id),
                &uuid(plan.tenant_id),
                &uuid(plan.repository_id),
                &plan.lifecycle_plan_id,
                &plan.authorization_reference,
                &&request.expected_head.digest[..],
                &(request.expected_generation as i64),
                &&plan.publication.digest[..],
                &&candidate_change_set_digest[..],
                &&plan.lifecycle_plan_digest[..],
                &&plan.authenticated_scope_digest[..],
                &plan.idempotency_key,
                &&plan.semantic_fingerprint[..],
                &&submit_fingerprint[..],
                &(operations.len() as i32),
                &&operation_set_digest[..],
                &&intent_digest[..],
                &plan.expires_at,
            ],
        )
        .map_err(database_error)?;
    if inserted != 1 {
        return Err(denied());
    }
    Ok(PreallocatedCreationSubmitIntent {
        intent_id,
        lifecycle_plan_id: *plan.lifecycle_plan_id.as_bytes(),
        repository_id: plan.repository_id,
        reference_name: plan.authorization_reference,
        expected_head: request.expected_head,
        expected_generation: request.expected_generation,
        candidate_snapshot: plan.publication,
        candidate_change_set_digest,
        operation_count: u16::try_from(operations.len()).map_err(|_| denied())?,
        operation_set_digest,
        intent_digest,
        expires_at: plan.expires_at,
    })
}

fn preflight_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    request: &PreallocatedCreationSubmitPreflightRequest<'_>,
) -> Result<PreallocatedCreationSubmitPreflight> {
    // This advisory lock is derived only from the opaque intent UUID and does
    // not inspect durable state. Acquire it before the participant's
    // repository-scoped lock to match finalize/reconcile lock order.
    lock_submit_intent(transaction, request.intent_id)?;
    participant
        .verify_receipt_current(transaction, request.authorization)
        .map_err(|_| denied())?;
    let intent = load_intent(transaction, request.intent_id, false)?;
    verify_receipt_plan_binding(request.authorization, &intent.plan)?;
    if intent.intent.expires_at <= server_now(transaction)? {
        return Err(denied());
    }
    // Preflight never reserves a head. A plain MVCC observation avoids holding
    // the repository authorization lock while waiting on finalize's branch
    // row; finalize repeats the exact locked comparison before any commit.
    let branch = transaction
        .query_opt(
            "SELECT target_snapshot_digest, generation
             FROM ogvcs_metadata.references
             WHERE repository_id = $1 AND reference_kind = 'branch' AND reference_name = $2",
            &[
                &uuid(intent.intent.repository_id),
                &intent.intent.reference_name,
            ],
        )
        .map_err(database_error)?
        .ok_or_else(denied)?;
    let observed_head = digest32(branch.get(0))?;
    let observed_generation = positive_u64(branch.get(1))?;
    let branch_matches = observed_head == intent.intent.expected_head.digest
        && observed_generation == intent.intent.expected_generation;
    let revision: u64 = transaction
        .query_one(
            "SELECT COALESCE(max(preflight_revision), 0) + 1
             FROM ogvcs_metadata.submit_preflights WHERE intent_id = $1",
            &[&Uuid::from_bytes(request.intent_id)],
        )
        .map_err(database_error)
        .and_then(|row| positive_u64(row.get(0)))?;
    let preflight_id = random_public_uuid()?;
    let digest = digest_framed(
        PREFLIGHT_DIGEST_DOMAIN,
        &[
            &request.intent_id,
            &preflight_id,
            &revision.to_be_bytes(),
            &observed_head,
            &observed_generation.to_be_bytes(),
            &[u8::from(branch_matches)],
            &intent.plan.lifecycle_plan_digest,
            &intent.intent.operation_set_digest,
        ],
    );
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_preflights
             (preflight_id, intent_id, preflight_revision, observed_head_digest,
              observed_generation, branch_matches, lifecycle_plan_digest,
              operation_set_digest, mutable_checks_repeat, preflight_digest, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9, $10)",
            &[
                &Uuid::from_bytes(preflight_id),
                &Uuid::from_bytes(request.intent_id),
                &(revision as i64),
                &&observed_head[..],
                &(observed_generation as i64),
                &branch_matches,
                &&intent.plan.lifecycle_plan_digest[..],
                &&intent.intent.operation_set_digest[..],
                &&digest[..],
                &intent.intent.expires_at,
            ],
        )
        .map_err(database_error)?;
    Ok(PreallocatedCreationSubmitPreflight {
        preflight_id,
        revision,
        branch_matches,
        preflight_digest: digest,
        expires_at: intent.intent.expires_at,
    })
}

fn finalize_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    request: &PreallocatedCreationSubmitFinalizeRequest<'_>,
    control: AtomicSubmitControl,
) -> Result<PreallocatedCreationSubmitOutcome> {
    if !valid_atomic_consumption_id(request.consumption_id) {
        return Err(denied());
    }
    lock_submit_intent(transaction, request.intent_id)?;
    let intent = load_intent(transaction, request.intent_id, false)?;
    if let Some(mut outcome) = load_outcome(transaction, request.intent_id)? {
        if request.consumption_id != outcome.consumption_id {
            return Err(denied());
        }
        revalidate_outcome_consumption(transaction, participant, request.authorization, &outcome)?;
        outcome.replayed = true;
        return Ok(outcome);
    }
    verify_receipt_plan_binding(request.authorization, &intent.plan)?;
    if intent.intent.expires_at <= server_now(transaction)? {
        return Err(denied());
    }

    // Deterministic coordinator lock order: submit intent -> exact branch ->
    // FileIDs in canonical (repository, FileID) order -> aggregate bridge. The
    // bridge then owns its existing aggregate-receipt and lifecycle lock order.
    // The FileID query restores operation ordinal before deriving or persisting
    // ordered submit evidence.
    lock_and_validate_branch(transaction, &intent)?;
    let operations = lock_and_validate_file_ids(transaction, &intent)?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::BeforeBridge)?;
    let lifecycle = apply_aggregate_lifecycle_publication_in_transaction(
        transaction,
        participant,
        &AggregateLifecycleApplyRequest {
            authorization: request.authorization,
            lifecycle_plan_id: *intent.plan.lifecycle_plan_id.as_bytes(),
            consumption_id: request.consumption_id,
        },
    )?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterBridge)?;

    apply_file_id_first_consumptions(transaction, &intent, &operations, &lifecycle)?;
    reach_atomic_submit_boundary(
        transaction,
        control,
        AtomicSubmitFault::AfterFileIdConsumption,
    )?;
    let sequence = lifecycle.lifecycle().commit_sequence;
    let marked = transaction
        .execute(
            "UPDATE ogvcs_metadata.snapshots
             SET published_commit_sequence = $3
             WHERE repository_id = $1 AND snapshot_digest = $2
               AND published_commit_sequence IS NULL",
            &[
                &uuid(intent.intent.repository_id),
                &&intent.intent.candidate_snapshot.digest[..],
                &(sequence as i64),
            ],
        )
        .map_err(database_error)?;
    if marked != 1 {
        return Err(denied());
    }
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterSnapshotMarker)?;
    let next_generation = intent
        .intent
        .expected_generation
        .checked_add(1)
        .filter(|value| *value <= crate::lifecycle::MAXIMUM_SAFE_GENERATION)
        .ok_or_else(denied)?;
    let advanced = transaction
        .execute(
            "UPDATE ogvcs_metadata.references
             SET target_snapshot_digest = $5, generation = $6,
                 commit_sequence = $7, updated_at = clock_timestamp()
             WHERE repository_id = $1 AND reference_kind = 'branch'
               AND reference_name = $2 AND target_snapshot_digest = $3
               AND generation = $4 AND commit_sequence < $7
               AND EXISTS (
                   SELECT 1 FROM ogvcs_metadata.snapshots
                   WHERE repository_id = $1 AND snapshot_digest = $5
                     AND published_commit_sequence = $7)",
            &[
                &uuid(intent.intent.repository_id),
                &intent.intent.reference_name,
                &&intent.intent.expected_head.digest[..],
                &(intent.intent.expected_generation as i64),
                &&intent.intent.candidate_snapshot.digest[..],
                &(next_generation as i64),
                &(sequence as i64),
            ],
        )
        .map_err(database_error)?;
    if advanced != 1 {
        return Err(denied());
    }
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterBranchCas)?;

    let audit_correlation_id = random_public_uuid()?;
    let subject_digest = decode_hex32(request.authorization.subject_digest())?;
    let audit_digest = digest_framed(
        AUDIT_EVIDENCE_DOMAIN,
        &[
            &request.intent_id,
            lifecycle.lifecycle().application_id.as_slice(),
            &subject_digest,
            &request.authorization.authority_epoch().to_be_bytes(),
            lifecycle.operation_digest(),
            &intent.intent.intent_digest,
        ],
    );
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_internal_audit_evidence
             (audit_correlation_id, intent_id, application_id, event_class,
              subject_digest, authority_epoch, protected_event_digest)
             VALUES ($1, $2, $3, 'internal.submit-committed-candidate/v1', $4, $5, $6)",
            &[
                &Uuid::from_bytes(audit_correlation_id),
                &Uuid::from_bytes(request.intent_id),
                &Uuid::from_bytes(lifecycle.lifecycle().application_id),
                &&subject_digest[..],
                &(request.authorization.authority_epoch() as i64),
                &&audit_digest[..],
            ],
        )
        .map_err(database_error)?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterAudit)?;

    let outbox_event_id = random_public_uuid()?;
    let resource_opaque_id = opaque_token("rr1.")?;
    let safe_payload = json!({
        "class": "private-preallocated-creation-submit-candidate",
        "schemaVersion": 1
    });
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.outbox_events
             (event_id, tenant_id, repository_id, commit_sequence, event_type,
              event_version, correlation_id, resource_type, resource_opaque_id, safe_payload)
             VALUES ($1, $2, $3, $4, 'internal.submit-committed-candidate', 1,
                     $5, 'reference', $6, $7)",
            &[
                &Uuid::from_bytes(outbox_event_id),
                &uuid(intent.tenant_id),
                &uuid(intent.intent.repository_id),
                &(sequence as i64),
                &Uuid::from_bytes(audit_correlation_id),
                &resource_opaque_id,
                &Json(&safe_payload),
            ],
        )
        .map_err(database_error)?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterOutboxEvent)?;
    let consistency_token = opaque_token("ct1.")?;
    let consistency_token_digest: [u8; 32] = Sha256::digest(consistency_token.as_bytes()).into();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.consistency_tokens
             (token_digest, subject_digest, tenant_id, repository_id,
              minimum_commit_sequence, authorization_epoch,
              authenticated_scope_digest, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp(),
                     LEAST($8, clock_timestamp() + interval '5 minutes'))",
            &[
                &&consistency_token_digest[..],
                &&subject_digest[..],
                &uuid(intent.tenant_id),
                &uuid(intent.intent.repository_id),
                &(sequence as i64),
                &(request.authorization.authority_epoch() as i64),
                &&intent.authenticated_scope_digest[..],
                &intent.intent.expires_at,
            ],
        )
        .map_err(database_error)?;
    reach_atomic_submit_boundary(
        transaction,
        control,
        AtomicSubmitFault::AfterConsistencyToken,
    )?;

    let result_digest = submit_result_digest(
        &intent,
        &lifecycle,
        request.consumption_id,
        next_generation,
        audit_correlation_id,
        outbox_event_id,
        consistency_token_digest,
    );
    let reconciliation_commitment_digest = digest_framed(
        RECONCILIATION_COMMITMENT_DOMAIN,
        &[
            &request.intent_id,
            &result_digest,
            &request.authorization.authority_epoch().to_be_bytes(),
            &sequence.to_be_bytes(),
        ],
    );
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_final_outcomes
             (intent_id, application_id, identity_plan_id, consumption_id,
              operation_digest, old_head_digest, new_head_digest,
              branch_generation, commit_sequence, authority_epoch,
              audit_correlation_id, outbox_event_id, consistency_token,
              consistency_token_digest, result_digest,
              reconciliation_commitment_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     $11, $12, $13, $14, $15, $16)",
            &[
                &Uuid::from_bytes(request.intent_id),
                &Uuid::from_bytes(lifecycle.lifecycle().application_id),
                &lifecycle.identity_plan_id(),
                &request.consumption_id,
                &&lifecycle.operation_digest()[..],
                &&intent.intent.expected_head.digest[..],
                &&intent.intent.candidate_snapshot.digest[..],
                &(next_generation as i64),
                &(sequence as i64),
                &(request.authorization.authority_epoch() as i64),
                &Uuid::from_bytes(audit_correlation_id),
                &Uuid::from_bytes(outbox_event_id),
                &consistency_token,
                &&consistency_token_digest[..],
                &&result_digest[..],
                &&reconciliation_commitment_digest[..],
            ],
        )
        .map_err(database_error)?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterFinalOutcome)?;
    insert_reconciliation_record(
        transaction,
        request.intent_id,
        Some(result_digest),
        Some(request.authorization.authority_epoch()),
    )?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::AfterReconciliation)?;
    reach_atomic_submit_boundary(transaction, control, AtomicSubmitFault::BeforeCommit)?;
    Ok(PreallocatedCreationSubmitOutcome {
        intent_id: request.intent_id,
        application_id: lifecycle.lifecycle().application_id,
        lifecycle_receipt_digest: lifecycle.lifecycle().receipt_digest,
        identity_plan_id: lifecycle.identity_plan_id().to_owned(),
        consumption_id: request.consumption_id.to_owned(),
        operation_digest: *lifecycle.operation_digest(),
        old_head: intent.intent.expected_head,
        new_head: intent.intent.candidate_snapshot,
        branch_generation: next_generation,
        commit_sequence: sequence,
        authority_epoch: request.authorization.authority_epoch(),
        audit_correlation_id,
        outbox_event_id,
        consistency_token,
        consistency_token_digest,
        result_digest,
        reconciliation_commitment_digest,
        replayed: false,
    })
}

fn reach_atomic_submit_boundary(
    _transaction: &mut Transaction<'_>,
    control: AtomicSubmitControl,
    boundary: AtomicSubmitFault,
) -> Result<()> {
    match control {
        AtomicSubmitControl::Fault(fault) if fault == boundary => Err(denied()),
        #[cfg(feature = "legacy-test-adapter")]
        AtomicSubmitControl::Restart {
            boundary: restart_boundary,
            rendezvous_seconds,
        } if restart_boundary.atomic_fault() == Some(boundary) => {
            await_transaction_restart_rendezvous(_transaction, restart_boundary, rendezvous_seconds)
        }
        _ => Ok(()),
    }
}

#[cfg(feature = "legacy-test-adapter")]
impl AtomicSubmitRestartBoundaryForTest {
    const fn atomic_fault(self) -> Option<AtomicSubmitFault> {
        Some(match self {
            Self::BeforeBridge => AtomicSubmitFault::BeforeBridge,
            Self::AfterBridge => AtomicSubmitFault::AfterBridge,
            Self::AfterFileIdConsumption => AtomicSubmitFault::AfterFileIdConsumption,
            Self::AfterSnapshotMarker => AtomicSubmitFault::AfterSnapshotMarker,
            Self::AfterBranchCas => AtomicSubmitFault::AfterBranchCas,
            Self::AfterAudit => AtomicSubmitFault::AfterAudit,
            Self::AfterOutboxEvent => AtomicSubmitFault::AfterOutboxEvent,
            Self::AfterConsistencyToken => AtomicSubmitFault::AfterConsistencyToken,
            Self::AfterFinalOutcome => AtomicSubmitFault::AfterFinalOutcome,
            Self::AfterReconciliation => AtomicSubmitFault::AfterReconciliation,
            Self::BeforeCommit => AtomicSubmitFault::BeforeCommit,
            Self::CommitIo | Self::AfterCommitBeforeResponse => return None,
        })
    }

    fn application_name(self) -> String {
        format!("ogvcs.restart.{}", self.name())
    }
}

#[cfg(feature = "legacy-test-adapter")]
fn await_transaction_restart_rendezvous(
    transaction: &mut Transaction<'_>,
    boundary: AtomicSubmitRestartBoundaryForTest,
    rendezvous_seconds: u16,
) -> Result<()> {
    transaction
        .query_one(
            "SELECT set_config('application_name', $1, TRUE),
                    pg_sleep($2::double precision)",
            &[&boundary.application_name(), &f64::from(rendezvous_seconds)],
        )
        .map_err(database_error)?;
    Err(denied())
}

#[cfg(feature = "legacy-test-adapter")]
fn arm_commit_io_restart_rendezvous(
    transaction: &mut Transaction<'_>,
    intent_id: [u8; 16],
    control: AtomicSubmitControl,
) -> Result<()> {
    let AtomicSubmitControl::Restart {
        boundary: AtomicSubmitRestartBoundaryForTest::CommitIo,
        rendezvous_seconds,
    } = control
    else {
        return Ok(());
    };
    transaction
        .query_one(
            "SELECT set_config('application_name', $1, TRUE),
                    set_config('ogvcs.restart_commit_sleep_seconds', $2, TRUE)",
            &[
                &AtomicSubmitRestartBoundaryForTest::CommitIo.application_name(),
                &rendezvous_seconds.to_string(),
            ],
        )
        .map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO ogvcs_restart_test.commit_rendezvous (intent_id) VALUES ($1)",
            &[&Uuid::from_bytes(intent_id)],
        )
        .map_err(database_error)?;
    Ok(())
}

#[cfg(feature = "legacy-test-adapter")]
fn await_after_commit_restart_rendezvous(
    client: &mut Client,
    control: AtomicSubmitControl,
) -> Result<()> {
    let AtomicSubmitControl::Restart {
        boundary: AtomicSubmitRestartBoundaryForTest::AfterCommitBeforeResponse,
        rendezvous_seconds,
    } = control
    else {
        return Ok(());
    };
    client
        .query_one(
            "SELECT set_config('application_name', $1, FALSE),
                    pg_sleep($2::double precision)",
            &[
                &AtomicSubmitRestartBoundaryForTest::AfterCommitBeforeResponse.application_name(),
                &f64::from(rendezvous_seconds),
            ],
        )
        .map_err(database_error)?;
    Err(denied())
}

fn reconcile_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    request: &PreallocatedCreationSubmitFinalizeRequest<'_>,
) -> Result<PreallocatedCreationSubmitReconciliation> {
    if !valid_atomic_consumption_id(request.consumption_id) {
        return Err(denied());
    }
    lock_submit_intent(transaction, request.intent_id)?;
    let intent = load_intent(transaction, request.intent_id, false)?;
    if let Some(mut outcome) = load_outcome(transaction, request.intent_id)? {
        if request.consumption_id != outcome.consumption_id {
            return Err(denied());
        }
        revalidate_outcome_consumption(transaction, participant, request.authorization, &outcome)?;
        outcome.replayed = true;
        insert_reconciliation_record(
            transaction,
            request.intent_id,
            Some(outcome.result_digest),
            Some(outcome.authority_epoch),
        )?;
        return Ok(PreallocatedCreationSubmitReconciliation::Committed(
            Box::new(outcome),
        ));
    }
    participant
        .verify_receipt_current(transaction, request.authorization)
        .map_err(|_| denied())?;
    verify_receipt_plan_binding(request.authorization, &intent.plan)?;
    let observation_digest =
        insert_reconciliation_record(transaction, request.intent_id, None, None)?;
    Ok(PreallocatedCreationSubmitReconciliation::UnknownRecovering { observation_digest })
}

fn load_sealed_submit_plan(
    transaction: &mut Transaction<'_>,
    plan_id: [u8; 16],
    lock: bool,
) -> Result<SealedSubmitPlan> {
    let lock_clause = if lock {
        "FOR SHARE OF plan, seal, identity"
    } else {
        ""
    };
    let sql = format!(
        "SELECT plan.plan_id, plan.tenant_id, plan.repository_id,
                plan.publication_kind, plan.publication_digest,
                plan.authorization_reference, plan.authorization_snapshot,
                plan.subject_digest, plan.authorization_epoch,
                seal.plan_digest, plan.idempotency_scope_digest,
                plan.idempotency_operation, plan.idempotency_key,
                plan.semantic_fingerprint, seal.object_count, plan.expires_at,
                identity.identity_plan_id, identity.identity_decision_digest,
                identity.identity_resource_projection_digest,
                seal.object_count = plan.declared_object_count
                  AND seal.chunk_count = plan.declared_chunk_count
                  AND seal.encoded_bytes = plan.declared_encoded_bytes
                  AND seal.plan_digest = plan.declared_plan_digest
                  AND identity.object_count = seal.object_count
                  AND identity.lifecycle_plan_digest = seal.plan_digest
         FROM ogvcs_metadata.lifecycle_publication_plans AS plan
         JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal USING (plan_id)
         JOIN ogvcs_metadata.lifecycle_aggregate_identity_seals AS identity
           ON identity.lifecycle_plan_id = plan.plan_id
         WHERE plan.plan_id = $1 {lock_clause}"
    );
    let row = transaction
        .query_opt(&sql, &[&Uuid::from_bytes(plan_id)])
        .map_err(database_error)?
        .ok_or_else(denied)?;
    if !row.get::<_, bool>(19) {
        return Err(denied());
    }
    let publication = object_ref(object_kind(row.get(3))?, row.get(4))?;
    let authorization_reference = row.get::<_, Option<String>>(5).ok_or_else(denied)?;
    let authorization_snapshot = row.get::<_, Option<String>>(6).ok_or_else(denied)?;
    if authorization_snapshot != publication.to_string() {
        return Err(denied());
    }
    let object_count = u32::try_from(row.get::<_, i32>(14)).map_err(|_| denied())?;
    if object_count == 0 {
        return Err(denied());
    }
    Ok(SealedSubmitPlan {
        lifecycle_plan_id: row.get(0),
        tenant_id: TenantId::from_bytes(*row.get::<_, Uuid>(1).as_bytes()),
        repository_id: RepositoryId::from_bytes(*row.get::<_, Uuid>(2).as_bytes()),
        publication,
        authorization_reference,
        authorization_snapshot,
        subject_digest: digest32(row.get(7))?,
        authorization_epoch: positive_u64(row.get(8))?,
        lifecycle_plan_digest: digest32(row.get(9))?,
        authenticated_scope_digest: digest32(row.get(10))?,
        idempotency_operation: row.get(11),
        idempotency_key: row.get(12),
        semantic_fingerprint: digest32(row.get(13))?,
        object_count,
        identity_plan_id: Some(row.get(16)),
        identity_decision_digest: Some(digest32(row.get(17))?),
        identity_resource_projection_digest: Some(digest32(row.get(18))?),
        expires_at: row.get(15),
    })
}

fn verify_receipt_plan_binding(
    receipt: &AggregateAuthorizationReceipt,
    plan: &SealedSubmitPlan,
) -> Result<()> {
    let metadata_tenant = Uuid::parse_str(receipt.metadata_tenant_id()).map_err(|_| denied())?;
    let metadata_repository =
        Uuid::parse_str(receipt.metadata_repository_id()).map_err(|_| denied())?;
    let identity_plan_id = plan.identity_plan_id.as_deref().ok_or_else(denied)?;
    let identity_decision_digest = plan.identity_decision_digest.ok_or_else(denied)?;
    let identity_resource_projection_digest = plan
        .identity_resource_projection_digest
        .ok_or_else(denied)?;
    let exact = receipt.plan_id() == identity_plan_id
        && decode_hex32(receipt.decision_digest())? == identity_decision_digest
        && decode_hex32(receipt.resource_digest_projection_digest())?
            == identity_resource_projection_digest
        && metadata_tenant.as_bytes() == plan.tenant_id.as_bytes()
        && metadata_repository.as_bytes() == plan.repository_id.as_bytes()
        && decode_hex32(receipt.subject_digest())? == plan.subject_digest
        && decode_hex32(receipt.authenticated_scope_digest())? == plan.authenticated_scope_digest
        && receipt.authority_epoch() == plan.authorization_epoch
        && receipt.permission() == AGGREGATE_SUBMIT_PERMISSION
        && receipt.capability() == AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY
        && receipt.reference() == Some(plan.authorization_reference.as_str())
        && receipt.snapshot() == Some(plan.authorization_snapshot.as_str())
        && receipt.resource_count() == plan.object_count as usize;
    if exact {
        Ok(())
    } else {
        Err(denied())
    }
}

fn candidate_change_set_digest(
    transaction: &mut Transaction<'_>,
    repository_id: RepositoryId,
    snapshot_digest: [u8; 32],
) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = transaction
        .query_one(
            "SELECT canonical_bytes FROM ogvcs_metadata.metadata_objects
             WHERE repository_id = $1 AND object_kind = 7 AND digest_algorithm = 1
               AND object_digest = $2",
            &[&uuid(repository_id), &&snapshot_digest[..]],
        )
        .map_err(database_error)?
        .get(0);
    let value = decode_canonical(&bytes, Limits::METADATA).map_err(|_| denied())?;
    let change = cbor_field(&value, 19)
        .and_then(|value| ObjectRef::from_cbor(value).ok())
        .filter(|reference| reference.kind == ObjectKind::ChangeSet)
        .ok_or_else(denied)?;
    let exists: bool = transaction
        .query_one(
            "SELECT EXISTS (
               SELECT 1 FROM ogvcs_metadata.object_edges
               WHERE repository_id = $1 AND source_kind = 7 AND source_digest = $2
                 AND target_kind = 4 AND target_digest = $3)",
            &[
                &uuid(repository_id),
                &&snapshot_digest[..],
                &&change.digest[..],
            ],
        )
        .map_err(database_error)?
        .get(0);
    if exists {
        Ok(change.digest)
    } else {
        Err(denied())
    }
}

fn load_candidate_operations(
    transaction: &mut Transaction<'_>,
    repository_id: RepositoryId,
    snapshot_digest: [u8; 32],
    change_set_digest: [u8; 32],
) -> Result<Vec<IntentOperation>> {
    let rows = transaction
        .query(
            "SELECT history.operation_ordinal, history.operation_kind,
                    history.file_id, history.repository_path_utf8,
                    registry.state::text, registry.origin::text,
                    registry.owner_kind::text, registry.owner_id,
                    registry.first_change_set_digest, registry.first_operation,
                    CASE WHEN history.operation_kind = 'import' THEN EXISTS (
                        SELECT 1 FROM ogvcs_metadata.file_id_import_mappings AS mapping
                        WHERE mapping.repository_id = history.repository_id
                          AND mapping.file_id = history.file_id)
                    ELSE TRUE END
             FROM ogvcs_metadata.file_path_history AS history
             JOIN ogvcs_metadata.file_id_registry AS registry
               ON registry.repository_id = history.repository_id
              AND registry.file_id = history.file_id
             WHERE history.repository_id = $1 AND history.snapshot_digest = $2
             ORDER BY history.operation_ordinal
             LIMIT 1001",
            &[&uuid(repository_id), &&snapshot_digest[..]],
        )
        .map_err(database_error)?;
    if rows.len() > MAXIMUM_PRIVATE_SUBMIT_OPERATIONS {
        return Err(denied());
    }
    let mut operations = Vec::with_capacity(rows.len());
    for (expected, row) in rows.into_iter().enumerate() {
        let ordinal = usize::try_from(row.get::<_, i32>(0)).map_err(|_| denied())?;
        let operation_kind: String = row.get(1);
        let state: String = row.get(4);
        let origin: String = row.get(5);
        let prior_owner_kind: String = row.get(6);
        let prior_owner_id: String = row.get(7);
        let first_change_set_digest = digest32(row.get(8))?;
        let first_operation = usize::try_from(row.get::<_, i32>(9)).map_err(|_| denied())?;
        let import_mapping: bool = row.get(10);
        if ordinal != expected
            || !matches!(operation_kind.as_str(), "create" | "copy" | "import")
            || state != "active"
            || origin != operation_kind
            || !matches!(prior_owner_kind.as_str(), "draft" | "shelf")
            || prior_owner_id.is_empty()
            || prior_owner_id.len() > 256
            || first_change_set_digest != change_set_digest
            || first_operation != ordinal
            || !import_mapping
        {
            return Err(denied());
        }
        let file_id: [u8; 16] = row.get::<_, Vec<u8>>(2).try_into().map_err(|_| denied())?;
        let path: Vec<u8> = row.get(3);
        if file_id == [0; 16] || path.is_empty() || path.len() > 4_096 {
            return Err(denied());
        }
        operations.push(IntentOperation {
            ordinal: u16::try_from(ordinal).map_err(|_| denied())?,
            operation_kind,
            file_id,
            path,
            prior_owner_kind,
            prior_owner_id,
            operation_digest: [0; 32],
        });
    }
    Ok(operations)
}

fn insert_intent_operations(
    transaction: &mut Transaction<'_>,
    intent_id: [u8; 16],
    repository_id: RepositoryId,
    candidate_snapshot_digest: [u8; 32],
    operations: &[IntentOperation],
) -> Result<()> {
    let ordinals: Vec<i32> = operations
        .iter()
        .map(|operation| i32::from(operation.ordinal))
        .collect();
    let kinds: Vec<&str> = operations
        .iter()
        .map(|operation| operation.operation_kind.as_str())
        .collect();
    let file_ids: Vec<&[u8]> = operations
        .iter()
        .map(|operation| operation.file_id.as_slice())
        .collect();
    let paths: Vec<&[u8]> = operations
        .iter()
        .map(|operation| operation.path.as_slice())
        .collect();
    let owner_kinds: Vec<&str> = operations
        .iter()
        .map(|operation| operation.prior_owner_kind.as_str())
        .collect();
    let owner_ids: Vec<&str> = operations
        .iter()
        .map(|operation| operation.prior_owner_id.as_str())
        .collect();
    let digests: Vec<&[u8]> = operations
        .iter()
        .map(|operation| operation.operation_digest.as_slice())
        .collect();
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_intent_operations
             (intent_id, repository_id, candidate_snapshot_digest,
              operation_ordinal, operation_kind, file_id, repository_path_utf8,
              prior_owner_kind, prior_owner_id, operation_digest)
             SELECT $1, $2, $3, input.ordinal, input.kind, input.file_id,
                    input.path, input.owner_kind, input.owner_id, input.digest
             FROM unnest($4::int4[], $5::text[], $6::bytea[], $7::bytea[],
                         $8::text[], $9::text[], $10::bytea[])
                  AS input(ordinal, kind, file_id, path, owner_kind, owner_id, digest)
             ORDER BY input.ordinal",
            &[
                &Uuid::from_bytes(intent_id),
                &uuid(repository_id),
                &&candidate_snapshot_digest[..],
                &ordinals,
                &kinds,
                &file_ids,
                &paths,
                &owner_kinds,
                &owner_ids,
                &digests,
            ],
        )
        .map_err(database_error)?;
    if inserted == operations.len() as u64 {
        Ok(())
    } else {
        Err(denied())
    }
}

fn lock_submit_intent(transaction: &mut Transaction<'_>, intent_id: [u8; 16]) -> Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("private-submit:{}", Uuid::from_bytes(intent_id))],
        )
        .map_err(database_error)?;
    Ok(())
}

fn load_intent_by_plan(
    transaction: &mut Transaction<'_>,
    plan_id: Uuid,
    lock: bool,
) -> Result<Option<IntentRecord>> {
    let row = transaction
        .query_opt(
            "SELECT intent_id FROM ogvcs_metadata.submit_intents
             WHERE lifecycle_plan_id = $1",
            &[&plan_id],
        )
        .map_err(database_error)?;
    row.map(|row| {
        let intent_id = *row.get::<_, Uuid>(0).as_bytes();
        load_intent(transaction, intent_id, lock)
    })
    .transpose()
}

fn load_intent(
    transaction: &mut Transaction<'_>,
    intent_id: [u8; 16],
    lock: bool,
) -> Result<IntentRecord> {
    let lock_clause = if lock { "FOR UPDATE OF intent" } else { "" };
    let sql = format!(
        "SELECT intent.intent_id, intent.tenant_id, intent.repository_id,
                intent.lifecycle_plan_id, intent.reference_name,
                intent.expected_head_digest, intent.expected_generation,
                intent.candidate_snapshot_digest, intent.candidate_change_set_digest,
                intent.lifecycle_plan_digest, intent.authenticated_scope_digest,
                intent.idempotency_key, intent.lifecycle_semantic_fingerprint,
                intent.submit_fingerprint, intent.operation_count,
                intent.operation_set_digest, intent.intent_digest, intent.expires_at,
                plan.subject_digest, plan.authorization_epoch, plan.authorization_snapshot,
                seal.object_count, identity.identity_plan_id,
                identity.identity_decision_digest,
                identity.identity_resource_projection_digest,
                identity.lifecycle_plan_id IS NULL OR (
                  identity.object_count = seal.object_count
                  AND identity.lifecycle_plan_digest = seal.plan_digest)
         FROM ogvcs_metadata.submit_intents AS intent
         JOIN ogvcs_metadata.lifecycle_publication_plans AS plan
           ON plan.plan_id = intent.lifecycle_plan_id
         JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal
           ON seal.plan_id = plan.plan_id
         LEFT JOIN ogvcs_metadata.lifecycle_aggregate_identity_seals AS identity
           ON identity.lifecycle_plan_id = plan.plan_id
         WHERE intent.intent_id = $1 {lock_clause}"
    );
    let row = transaction
        .query_opt(&sql, &[&Uuid::from_bytes(intent_id)])
        .map_err(database_error)?
        .ok_or_else(denied)?;
    let tenant_id = TenantId::from_bytes(*row.get::<_, Uuid>(1).as_bytes());
    let repository_id = RepositoryId::from_bytes(*row.get::<_, Uuid>(2).as_bytes());
    let lifecycle_plan_id: Uuid = row.get(3);
    let reference_name: String = row.get(4);
    let expected_head = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: digest32(row.get(5))?,
    };
    let expected_generation = positive_u64(row.get(6))?;
    let publication = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: digest32(row.get(7))?,
    };
    let candidate_change_set_digest = digest32(row.get(8))?;
    let lifecycle_plan_digest = digest32(row.get(9))?;
    let authenticated_scope_digest = digest32(row.get(10))?;
    let idempotency_key: String = row.get(11);
    let lifecycle_semantic_fingerprint = digest32(row.get(12))?;
    let stored_submit_fingerprint = digest32(row.get(13))?;
    let operation_count = u16::try_from(row.get::<_, i32>(14)).map_err(|_| denied())?;
    let operation_set_digest = digest32(row.get(15))?;
    let intent_digest = digest32(row.get(16))?;
    let expires_at: SystemTime = row.get(17);
    let subject_digest = digest32(row.get(18))?;
    let authorization_epoch = positive_u64(row.get(19))?;
    let authorization_snapshot: String = row.get::<_, Option<String>>(20).ok_or_else(denied)?;
    let object_count = u32::try_from(row.get::<_, i32>(21)).map_err(|_| denied())?;
    // v13 intentionally does not fabricate mappings for historical committed
    // applications. Preserve that outcome-replay path, but leave an absent
    // mapping as None so every pending/fresh operation fails closed in
    // verify_receipt_plan_binding.
    let identity_plan_id: Option<String> = row.get(22);
    let identity_decision_digest = row
        .get::<_, Option<Vec<u8>>>(23)
        .map(digest32)
        .transpose()?;
    let identity_resource_projection_digest = row
        .get::<_, Option<Vec<u8>>>(24)
        .map(digest32)
        .transpose()?;
    if !row.get::<_, bool>(25)
        || identity_plan_id.is_some() != identity_decision_digest.is_some()
        || identity_plan_id.is_some() != identity_resource_projection_digest.is_some()
    {
        return Err(denied());
    }
    let intent = PreallocatedCreationSubmitIntent {
        intent_id,
        lifecycle_plan_id: *lifecycle_plan_id.as_bytes(),
        repository_id,
        reference_name: reference_name.clone(),
        expected_head,
        expected_generation,
        candidate_snapshot: publication,
        candidate_change_set_digest,
        operation_count,
        operation_set_digest,
        intent_digest,
        expires_at,
    };
    let plan = SealedSubmitPlan {
        lifecycle_plan_id,
        tenant_id,
        repository_id,
        publication,
        authorization_reference: reference_name,
        authorization_snapshot,
        subject_digest,
        authorization_epoch,
        lifecycle_plan_digest,
        authenticated_scope_digest,
        idempotency_operation: "submit.finalize".to_owned(),
        idempotency_key: idempotency_key.clone(),
        semantic_fingerprint: lifecycle_semantic_fingerprint,
        object_count,
        identity_plan_id,
        identity_decision_digest,
        identity_resource_projection_digest,
        expires_at,
    };
    let expected_submit_fingerprint = submit_fingerprint(
        &plan,
        intent.expected_head,
        intent.expected_generation,
        intent.candidate_change_set_digest,
        intent.operation_set_digest,
        usize::from(intent.operation_count),
    );
    let expected_intent_digest = submit_intent_digest(
        intent.intent_id,
        &plan,
        intent.expected_head,
        intent.expected_generation,
        intent.candidate_change_set_digest,
        stored_submit_fingerprint,
        intent.operation_set_digest,
        usize::from(intent.operation_count),
    );
    if stored_submit_fingerprint != expected_submit_fingerprint
        || intent.intent_digest != expected_intent_digest
    {
        return Err(denied());
    }
    Ok(IntentRecord {
        intent,
        plan,
        tenant_id,
        authenticated_scope_digest,
    })
}

fn lock_and_validate_branch(
    transaction: &mut Transaction<'_>,
    intent: &IntentRecord,
) -> Result<()> {
    let row = transaction
        .query_opt(
            "SELECT target_snapshot_digest, generation
             FROM ogvcs_metadata.references
             WHERE repository_id = $1 AND reference_kind = 'branch' AND reference_name = $2
             FOR UPDATE",
            &[
                &uuid(intent.intent.repository_id),
                &intent.intent.reference_name,
            ],
        )
        .map_err(database_error)?
        .ok_or_else(denied)?;
    if digest32(row.get(0))? == intent.intent.expected_head.digest
        && positive_u64(row.get(1))? == intent.intent.expected_generation
    {
        Ok(())
    } else {
        Err(denied())
    }
}

fn lock_and_validate_file_ids(
    transaction: &mut Transaction<'_>,
    intent: &IntentRecord,
) -> Result<Vec<IntentOperation>> {
    let rows = transaction
        .query(
            "WITH locked AS MATERIALIZED (
                 SELECT operation.operation_ordinal, operation.operation_kind,
                        operation.file_id, operation.repository_path_utf8,
                        operation.prior_owner_kind, operation.prior_owner_id,
                        operation.operation_digest,
                        registry.state::text AS state,
                        registry.origin::text AS origin,
                        registry.owner_kind::text AS current_owner_kind,
                        registry.owner_id AS current_owner_id,
                        registry.first_change_set_digest,
                        registry.first_operation,
                        NOT EXISTS (
                            SELECT 1
                            FROM ogvcs_metadata.submit_file_id_consumptions AS prior
                            WHERE prior.repository_id = operation.repository_id
                              AND prior.file_id = operation.file_id
                        ) AS unconsumed
                 FROM ogvcs_metadata.submit_intent_operations AS operation
                 JOIN ogvcs_metadata.file_id_registry AS registry
                   ON registry.repository_id = operation.repository_id
                  AND registry.file_id = operation.file_id
                 WHERE operation.intent_id = $1
                 ORDER BY operation.repository_id, operation.file_id
                 FOR UPDATE OF registry
             )
             SELECT operation_ordinal, operation_kind, file_id,
                    repository_path_utf8, prior_owner_kind, prior_owner_id,
                    operation_digest, state, origin, current_owner_kind,
                    current_owner_id, first_change_set_digest, first_operation,
                    unconsumed
             FROM locked
             ORDER BY operation_ordinal",
            &[&Uuid::from_bytes(intent.intent.intent_id)],
        )
        .map_err(database_error)?;
    if rows.len() != usize::from(intent.intent.operation_count) {
        return Err(denied());
    }
    let mut operations = Vec::with_capacity(rows.len());
    for (expected, row) in rows.into_iter().enumerate() {
        let ordinal = usize::try_from(row.get::<_, i32>(0)).map_err(|_| denied())?;
        let operation_kind: String = row.get(1);
        let file_id: [u8; 16] = row.get::<_, Vec<u8>>(2).try_into().map_err(|_| denied())?;
        let path: Vec<u8> = row.get(3);
        let prior_owner_kind: String = row.get(4);
        let prior_owner_id: String = row.get(5);
        let operation_digest = digest32(row.get(6))?;
        let state: String = row.get(7);
        let origin: String = row.get(8);
        let current_owner_kind: String = row.get(9);
        let current_owner_id: String = row.get(10);
        let first_change_set_digest = digest32(row.get(11))?;
        let first_operation = usize::try_from(row.get::<_, i32>(12)).map_err(|_| denied())?;
        let unconsumed: bool = row.get(13);
        let operation = IntentOperation {
            ordinal: u16::try_from(ordinal).map_err(|_| denied())?,
            operation_kind,
            file_id,
            path,
            prior_owner_kind,
            prior_owner_id,
            operation_digest,
        };
        if ordinal != expected
            || operation.operation_digest != submit_operation_digest(&operation)
            || state != "active"
            || origin != operation.operation_kind
            || current_owner_kind != operation.prior_owner_kind
            || current_owner_id != operation.prior_owner_id
            || first_change_set_digest != intent.intent.candidate_change_set_digest
            || first_operation != ordinal
            || !unconsumed
        {
            return Err(denied());
        }
        operations.push(operation);
    }
    if submit_operation_set_digest(&operations) != intent.intent.operation_set_digest {
        return Err(denied());
    }
    Ok(operations)
}

fn apply_file_id_first_consumptions(
    transaction: &mut Transaction<'_>,
    intent: &IntentRecord,
    operations: &[IntentOperation],
    lifecycle: &AggregateLifecycleApplicationReceipt,
) -> Result<()> {
    let result_owner_id = encode_hex(&intent.intent.candidate_snapshot.digest);
    let updated = transaction
        .execute(
            "WITH ordered AS MATERIALIZED (
                 SELECT operation_ordinal, repository_id, file_id,
                        operation_kind, prior_owner_kind, prior_owner_id
                 FROM ogvcs_metadata.submit_intent_operations
                 WHERE intent_id = $1 ORDER BY operation_ordinal)
             UPDATE ogvcs_metadata.file_id_registry AS registry
             SET owner_kind = 'published', owner_id = $2
             FROM ordered
             WHERE registry.repository_id = ordered.repository_id
               AND registry.file_id = ordered.file_id
               AND registry.state = 'active'
               AND registry.origin::text = ordered.operation_kind
               AND registry.owner_kind::text = ordered.prior_owner_kind
               AND registry.owner_id = ordered.prior_owner_id
               AND registry.first_change_set_digest = $3
               AND registry.first_operation = ordered.operation_ordinal",
            &[
                &Uuid::from_bytes(intent.intent.intent_id),
                &result_owner_id,
                &&intent.intent.candidate_change_set_digest[..],
            ],
        )
        .map_err(database_error)?;
    if updated != operations.len() as u64 {
        return Err(denied());
    }
    let mut ordinals = Vec::with_capacity(operations.len());
    let mut kinds = Vec::with_capacity(operations.len());
    let mut file_ids = Vec::with_capacity(operations.len());
    let mut owner_kinds = Vec::with_capacity(operations.len());
    let mut owner_ids = Vec::with_capacity(operations.len());
    let mut consumption_digests = Vec::with_capacity(operations.len());
    for operation in operations {
        ordinals.push(i32::from(operation.ordinal));
        kinds.push(operation.operation_kind.clone());
        file_ids.push(operation.file_id.to_vec());
        owner_kinds.push(operation.prior_owner_kind.clone());
        owner_ids.push(operation.prior_owner_id.clone());
        consumption_digests.push(
            digest_framed(
                FILE_ID_CONSUMPTION_DOMAIN,
                &[
                    &intent.intent.intent_id,
                    lifecycle.lifecycle().application_id.as_slice(),
                    &u64::from(operation.ordinal).to_be_bytes(),
                    operation.operation_kind.as_bytes(),
                    &operation.file_id,
                    operation.prior_owner_kind.as_bytes(),
                    operation.prior_owner_id.as_bytes(),
                    result_owner_id.as_bytes(),
                    &operation.operation_digest,
                ],
            )
            .to_vec(),
        );
    }
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_file_id_consumptions
             (intent_id, operation_ordinal, repository_id,
              candidate_snapshot_digest, file_id, operation_kind,
              prior_owner_kind, prior_owner_id, result_owner_kind,
              result_owner_id, application_id, consumption_digest)
             SELECT $1, input.ordinal, $2, $3, input.file_id, input.kind,
                    input.owner_kind, input.owner_id, 'published', $4, $5, input.digest
             FROM unnest($6::int4[], $7::text[], $8::bytea[], $9::text[],
                         $10::text[], $11::bytea[])
                  AS input(ordinal, kind, file_id, owner_kind, owner_id, digest)
             ORDER BY input.ordinal",
            &[
                &Uuid::from_bytes(intent.intent.intent_id),
                &uuid(intent.intent.repository_id),
                &&intent.intent.candidate_snapshot.digest[..],
                &result_owner_id,
                &Uuid::from_bytes(lifecycle.lifecycle().application_id),
                &ordinals,
                &kinds,
                &file_ids,
                &owner_kinds,
                &owner_ids,
                &consumption_digests,
            ],
        )
        .map_err(database_error)?;
    if inserted == operations.len() as u64 {
        Ok(())
    } else {
        Err(denied())
    }
}

fn load_outcome(
    transaction: &mut Transaction<'_>,
    intent_id: [u8; 16],
) -> Result<Option<PreallocatedCreationSubmitOutcome>> {
    transaction
        .query_opt(
            "SELECT outcome.application_id, application.receipt_digest,
                    outcome.identity_plan_id, outcome.consumption_id,
                    outcome.operation_digest, outcome.old_head_digest,
                    outcome.new_head_digest, outcome.branch_generation,
                    outcome.commit_sequence, outcome.authority_epoch,
                    outcome.audit_correlation_id, outcome.outbox_event_id,
                    outcome.consistency_token, outcome.consistency_token_digest,
                    outcome.result_digest, outcome.reconciliation_commitment_digest
             FROM ogvcs_metadata.submit_final_outcomes AS outcome
             JOIN ogvcs_metadata.lifecycle_applications AS application
               ON application.application_id = outcome.application_id
             WHERE outcome.intent_id = $1",
            &[&Uuid::from_bytes(intent_id)],
        )
        .map_err(database_error)?
        .map(|row| {
            Ok(PreallocatedCreationSubmitOutcome {
                intent_id,
                application_id: *row.get::<_, Uuid>(0).as_bytes(),
                lifecycle_receipt_digest: digest32(row.get(1))?,
                identity_plan_id: row.get(2),
                consumption_id: row.get(3),
                operation_digest: digest32(row.get(4))?,
                old_head: ObjectRef {
                    kind: ObjectKind::Snapshot,
                    digest: digest32(row.get(5))?,
                },
                new_head: ObjectRef {
                    kind: ObjectKind::Snapshot,
                    digest: digest32(row.get(6))?,
                },
                branch_generation: positive_u64(row.get(7))?,
                commit_sequence: positive_u64(row.get(8))?,
                authority_epoch: positive_u64(row.get(9))?,
                audit_correlation_id: *row.get::<_, Uuid>(10).as_bytes(),
                outbox_event_id: *row.get::<_, Uuid>(11).as_bytes(),
                consistency_token: row.get(12),
                consistency_token_digest: digest32(row.get(13))?,
                result_digest: digest32(row.get(14))?,
                reconciliation_commitment_digest: digest32(row.get(15))?,
                replayed: false,
            })
        })
        .transpose()
}

fn revalidate_outcome_consumption(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    receipt: &AggregateAuthorizationReceipt,
    outcome: &PreallocatedCreationSubmitOutcome,
) -> Result<()> {
    if receipt.plan_id() != outcome.identity_plan_id {
        return Err(denied());
    }
    let operation_digest = encode_hex(&outcome.operation_digest);
    let consumption = participant
        .revalidate_consumption(
            transaction,
            receipt,
            &AggregateReceiptConsumptionRequest {
                consumption_id: &outcome.consumption_id,
                operation_digest: &operation_digest,
            },
        )
        .map_err(|_| denied())?;
    if consumption.plan_id() == outcome.identity_plan_id
        && consumption.consumption_id() == outcome.consumption_id
        && consumption.operation_digest() == operation_digest
    {
        Ok(())
    } else {
        Err(denied())
    }
}

fn insert_reconciliation_record(
    transaction: &mut Transaction<'_>,
    intent_id: [u8; 16],
    outcome_digest: Option<[u8; 32]>,
    authority_epoch: Option<u64>,
) -> Result<[u8; 32]> {
    let reconciliation_id = random_public_uuid()?;
    let result = if outcome_digest.is_some() {
        "committed"
    } else {
        "unknown-recovering"
    };
    let authority_epoch_bytes = authority_epoch.map(u64::to_be_bytes);
    let observation_digest = digest_framed_optional(
        RECONCILIATION_OBSERVATION_DOMAIN,
        &[
            Some(intent_id.as_slice()),
            Some(reconciliation_id.as_slice()),
            Some(result.as_bytes()),
            outcome_digest.as_ref().map(|value| value.as_slice()),
            authority_epoch_bytes.as_ref().map(|value| value.as_slice()),
        ],
    );
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.submit_reconciliation_records
             (reconciliation_id, intent_id, observed_result, outcome_digest,
              authority_epoch, observation_digest)
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &Uuid::from_bytes(reconciliation_id),
                &Uuid::from_bytes(intent_id),
                &result,
                &outcome_digest.map(|value| value.to_vec()),
                &authority_epoch.map(|value| value as i64),
                &&observation_digest[..],
            ],
        )
        .map_err(database_error)?;
    Ok(observation_digest)
}

fn submit_operation_digest(operation: &IntentOperation) -> [u8; 32] {
    digest_framed(
        OPERATION_DIGEST_DOMAIN,
        &[
            &u64::from(operation.ordinal).to_be_bytes(),
            operation.operation_kind.as_bytes(),
            &operation.file_id,
            &operation.path,
            operation.prior_owner_kind.as_bytes(),
            operation.prior_owner_id.as_bytes(),
        ],
    )
}

fn submit_operation_set_digest(operations: &[IntentOperation]) -> [u8; 32] {
    let mut chain = domain_digest(OPERATION_SET_INITIAL_DOMAIN, &[]);
    for operation in operations {
        chain = digest_framed(
            OPERATION_SET_STEP_DOMAIN,
            &[&chain, &operation.operation_digest],
        );
    }
    digest_framed(
        OPERATION_SET_FINAL_DOMAIN,
        &[&(operations.len() as u64).to_be_bytes(), &chain],
    )
}

fn submit_fingerprint(
    plan: &SealedSubmitPlan,
    expected_head: ObjectRef,
    expected_generation: u64,
    candidate_change_set_digest: [u8; 32],
    operation_set_digest: [u8; 32],
    operation_count: usize,
) -> [u8; 32] {
    digest_framed(
        SUBMIT_FINGERPRINT_DOMAIN,
        &[
            plan.lifecycle_plan_id.as_bytes(),
            &plan.lifecycle_plan_digest,
            plan.repository_id.as_bytes(),
            plan.authorization_reference.as_bytes(),
            &expected_head.digest,
            &expected_generation.to_be_bytes(),
            &plan.publication.digest,
            &candidate_change_set_digest,
            &plan.authenticated_scope_digest,
            &plan.semantic_fingerprint,
            &(operation_count as u64).to_be_bytes(),
            &operation_set_digest,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn submit_intent_digest(
    intent_id: [u8; 16],
    plan: &SealedSubmitPlan,
    expected_head: ObjectRef,
    expected_generation: u64,
    candidate_change_set_digest: [u8; 32],
    submit_fingerprint: [u8; 32],
    operation_set_digest: [u8; 32],
    operation_count: usize,
) -> [u8; 32] {
    digest_framed(
        INTENT_DIGEST_DOMAIN,
        &[
            &intent_id,
            plan.lifecycle_plan_id.as_bytes(),
            plan.tenant_id.as_bytes(),
            plan.repository_id.as_bytes(),
            plan.authorization_reference.as_bytes(),
            &expected_head.digest,
            &expected_generation.to_be_bytes(),
            &plan.publication.digest,
            &candidate_change_set_digest,
            &plan.lifecycle_plan_digest,
            &plan.authenticated_scope_digest,
            plan.idempotency_operation.as_bytes(),
            plan.idempotency_key.as_bytes(),
            &plan.semantic_fingerprint,
            &submit_fingerprint,
            &(operation_count as u64).to_be_bytes(),
            &operation_set_digest,
            &system_time_epoch_seconds(plan.expires_at).to_be_bytes(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn submit_result_digest(
    intent: &IntentRecord,
    lifecycle: &AggregateLifecycleApplicationReceipt,
    consumption_id: &str,
    next_generation: u64,
    audit_correlation_id: [u8; 16],
    outbox_event_id: [u8; 16],
    consistency_token_digest: [u8; 32],
) -> [u8; 32] {
    digest_framed(
        RESULT_DIGEST_DOMAIN,
        &[
            &intent.intent.intent_id,
            lifecycle.lifecycle().application_id.as_slice(),
            lifecycle.lifecycle().receipt_digest.as_slice(),
            lifecycle.identity_plan_id().as_bytes(),
            consumption_id.as_bytes(),
            lifecycle.operation_digest(),
            &intent.intent.expected_head.digest,
            &intent.intent.candidate_snapshot.digest,
            &next_generation.to_be_bytes(),
            &lifecycle.lifecycle().commit_sequence.to_be_bytes(),
            &intent.plan.authorization_epoch.to_be_bytes(),
            &audit_correlation_id,
            &outbox_event_id,
            &consistency_token_digest,
            &intent.intent.operation_set_digest,
        ],
    )
}

fn digest_framed(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

fn digest_framed_optional(domain: &[u8], fields: &[Option<&[u8]>]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    for field in fields {
        match field {
            Some(field) => {
                hash.update([1]);
                hash.update((field.len() as u64).to_be_bytes());
                hash.update(field);
            }
            None => hash.update([0]),
        }
    }
    hash.finalize().into()
}

fn server_now(transaction: &mut Transaction<'_>) -> Result<SystemTime> {
    transaction
        .query_one("SELECT clock_timestamp()", &[])
        .map_err(database_error)
        .map(|row| row.get(0))
}

fn system_time_epoch_seconds(value: SystemTime) -> u64 {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn valid_atomic_consumption_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=256).contains(&bytes.len())
        && bytes.iter().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'.'
                    | b'_'
                    | b':'
                    | b'-'
            )
        })
}

fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(denied());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(denied()),
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn digest32(value: Vec<u8>) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| denied())
}

fn denied() -> DomainError {
    DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)
}
