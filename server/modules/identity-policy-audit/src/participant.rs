use std::collections::HashSet;

use postgres::{error::SqlState, Row, Transaction};
use serde::Serialize;
use serde_json::Value;

use crate::canonical::{
    bounded_json, canonical_bytes, decode_digest, digest_json, digest_matches, hex, sha256,
    valid_id, valid_opaque, DECISION_COMMITMENT_DOMAIN, IDENTITY_CREDENTIAL_DOMAIN,
    IDENTITY_SUBJECT_DOMAIN,
};
use crate::migration_runner::verify_schema_in_transaction;
use crate::model::{BoundRequest, TransactionBinding, ViewParts};
use crate::policy::{evaluate_allow, validate_policy, ActorFacts, RequestFacts};
use crate::{
    AuthorizationResource, AuthorizedResourceBatch, CredentialScope, DecisionChainVerification,
    DecisionCommitmentRequest, ParticipantError, ParticipantErrorCode, PolicyDocument, Result,
    TransactionAuthorizationRequest, TransactionAuthorizedView, TransactionBatchRecheck,
    TransactionCredentialEvidence, TransactionDecisionCommitment, MAXIMUM_BATCH_RESOURCES,
    MAXIMUM_DECISION_CHAIN_SCAN, MAXIMUM_DECISION_RESULT_BYTES,
    TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA, TRANSACTION_DECISION_COMMITMENT_SCHEMA,
};

const VIEW_SEAL_DOMAIN: &[u8] = b"OGVCS-IDENTITY-TRANSACTION-VIEW-SEAL-V1\0";
const COMMITMENT_ID_DOMAIN: &[u8] = b"OGVCS-IDENTITY-DECISION-COMMITMENT-ID-V1\0";

pub trait TransactionAuthorizationParticipant {
    fn authorize(
        &self,
        transaction: &mut Transaction<'_>,
        request: &TransactionAuthorizationRequest<'_>,
    ) -> Result<TransactionAuthorizedView>;

    fn recheck_batch(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
        request: &TransactionBatchRecheck<'_>,
    ) -> Result<AuthorizedResourceBatch>;

    fn append_decision_commitment(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
        request: &DecisionCommitmentRequest<'_>,
    ) -> Result<TransactionDecisionCommitment>;
}

pub struct PostgresTransactionAuthorizationParticipant {
    instance_key: [u8; 32],
}

impl std::fmt::Debug for PostgresTransactionAuthorizationParticipant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresTransactionAuthorizationParticipant")
            .finish_non_exhaustive()
    }
}

impl PostgresTransactionAuthorizationParticipant {
    pub fn new() -> Result<Self> {
        let mut instance_key = [0_u8; 32];
        getrandom::getrandom(&mut instance_key)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        Ok(Self { instance_key })
    }

    pub fn verify_decision_chain(
        &self,
        transaction: &mut Transaction<'_>,
        tenant: &str,
        maximum_records: usize,
    ) -> Result<DecisionChainVerification> {
        let result = self.verify_decision_chain_inner(transaction, tenant, maximum_records);
        poison_on_error(transaction, result)
    }

    fn authorize_inner(
        &self,
        transaction: &mut Transaction<'_>,
        request: &TransactionAuthorizationRequest<'_>,
    ) -> Result<TransactionAuthorizedView> {
        verify_schema_in_transaction(transaction)?;
        if request.credential_presentation.is_empty()
            || request.credential_presentation.len() > 1_024
        {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        let binding = transaction_binding(transaction)?;
        let transaction_id = self.new_transaction_id(&binding)?;
        let presentation_digest = sha256(&[
            IDENTITY_CREDENTIAL_DOMAIN,
            request.credential_presentation.as_bytes(),
        ]);
        let credential = load_credential_by_presentation(transaction, &presentation_digest)?;
        if credential.tenant != request.tenant {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        let policy = load_policy(transaction, request.tenant, request.repository)?;
        currentness(&credential, &policy)?;
        let request_facts = RequestFacts {
            request_id: request.request_id,
            tenant: request.tenant,
            repository: request.repository,
            permission: request.permission,
            reason: request.reason,
            resource: request.resource,
            reference: request.reference,
            snapshot: request.snapshot,
        };
        let decision = evaluate_allow(
            &policy.document,
            &credential.actor,
            &credential.scope,
            request_facts,
        )?;
        let evidence = evidence(&credential, &policy, &presentation_digest)?;
        let evidence_digest = hex(&digest_json(&evidence)?);
        let mut view = TransactionAuthorizedView::from_parts(ViewParts {
            transaction_id,
            evidence_digest,
            subject_digest: evidence.subject_digest().to_owned(),
            authenticated_scope_digest: evidence.authenticated_scope_digest().to_owned(),
            request_fingerprint: decision.request_fingerprint,
            decision_digest: decision.decision_digest,
            tenant: request.tenant.to_owned(),
            repository: request.repository.to_owned(),
            permission: request.permission.to_owned(),
            authority_epoch: evidence.authority_epoch(),
            credential_generation: evidence.credential_generation(),
            policy_generation: evidence.policy_generation(),
            expires_at: evidence.expires_at(),
            evidence,
            request: BoundRequest {
                request_id: request.request_id.to_owned(),
                reason: request.reason.map(str::to_owned),
                reference: request.reference.map(str::to_owned),
                snapshot: request.snapshot.map(str::to_owned),
                resource: request.resource.clone(),
            },
            binding,
        });
        view.set_seal(self.view_seal(&view)?);
        Ok(view)
    }

    fn recheck_batch_inner(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
        request: &TransactionBatchRecheck<'_>,
    ) -> Result<AuthorizedResourceBatch> {
        verify_schema_in_transaction(transaction)?;
        self.verify_view_binding(transaction, view)?;
        validate_batch_size(request.resources)?;
        if request.tenant != view.tenant()
            || request.repository != view.repository()
            || request.permission != view.permission()
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        let resources = canonical_resource_set(request.resources)?;
        let reference = batch_reference(
            view.request.reference.as_deref(),
            request.reference,
            &resources,
        )?;
        let current = self.revalidate_view(transaction, view)?;
        let decision_digests = evaluate_complete_set(&resources, |resource| {
            evaluate_allow(
                &current.policy.document,
                &current.credential.actor,
                &current.credential.scope,
                RequestFacts {
                    request_id: &view.request.request_id,
                    tenant: view.tenant(),
                    repository: view.repository(),
                    permission: view.permission(),
                    reason: view.request.reason.as_deref(),
                    resource,
                    reference: reference.as_deref(),
                    snapshot: view.request.snapshot.as_deref(),
                },
            )
            .map(|decision| decision.decision_digest)
        })?;
        let resource_set_digest = hex(&digest_json(&resources)?);
        Ok(AuthorizedResourceBatch::new(
            view.transaction_id().to_owned(),
            resource_set_digest,
            decision_digests,
        ))
    }

    fn append_decision_commitment_inner(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
        request: &DecisionCommitmentRequest<'_>,
    ) -> Result<TransactionDecisionCommitment> {
        if !valid_opaque(request.correlation_id) {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        self.recheck_batch_inner(
            transaction,
            view,
            &TransactionBatchRecheck {
                tenant: request.tenant,
                repository: request.repository,
                permission: request.permission,
                reference: request.reference,
                resources: request.resources,
            },
        )?;
        let result_bytes =
            bounded_json(request.result, MAXIMUM_DECISION_RESULT_BYTES, 8, 256, 1_024)?;
        let result_digest = hex(&sha256(&[&result_bytes]));
        let canonical_resources = canonical_resource_set(request.resources)?;
        let resource_set_digest = hex(&digest_json(&canonical_resources)?);

        transaction
            .execute(
                "INSERT INTO ogvcs_identity.decision_chain_heads
                 (tenant_id, sequence, tail_hash) VALUES ($1, 0, NULL)
                 ON CONFLICT (tenant_id) DO NOTHING",
                &[&view.tenant()],
            )
            .map_err(database_error)?;
        let head = transaction
            .query_one(
                "SELECT sequence, tail_hash
                 FROM ogvcs_identity.decision_chain_heads
                 WHERE tenant_id = $1 FOR UPDATE",
                &[&view.tenant()],
            )
            .map_err(database_error)?;
        let prior_sequence: i64 = head.get(0);
        let prior_hash: Option<Vec<u8>> = head.get(1);
        if prior_sequence < 0 || (prior_sequence == 0) != prior_hash.is_none() {
            return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
        }
        if prior_sequence > 0 {
            let tail = transaction
                .query_opt(
                    "SELECT record_hash
                     FROM ogvcs_identity.transaction_decision_commitments
                     WHERE tenant_id = $1 AND sequence = $2",
                    &[&view.tenant(), &prior_sequence],
                )
                .map_err(database_error)?
                .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?;
            let actual: Vec<u8> = tail.get(0);
            if prior_hash
                .as_deref()
                .is_none_or(|expected| !digest_matches(expected, &actual))
            {
                return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
            }
        }
        let sequence = u64::try_from(prior_sequence)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::LimitExceeded))?;
        let previous_hash = prior_hash.as_deref().map(hex);
        let id_seed = canonical_bytes(&serde_json::json!({
            "transactionId": view.transaction_id(),
            "correlationId": request.correlation_id,
            "tenant": view.tenant(),
            "repository": view.repository(),
            "sequence": sequence,
            "decisionDigest": view.decision_digest(),
            "resourceSetDigest": resource_set_digest,
            "resultDigest": result_digest,
        }))?;
        let commitment_id = format!(
            "decision.{}",
            hex(&sha256(&[COMMITMENT_ID_DOMAIN, &id_seed]))
        );
        let mut commitment = TransactionDecisionCommitment {
            schema_version: TRANSACTION_DECISION_COMMITMENT_SCHEMA,
            commitment_id,
            transaction_id: view.transaction_id().to_owned(),
            correlation_id: request.correlation_id.to_owned(),
            tenant: view.tenant().to_owned(),
            repository: view.repository().to_owned(),
            authority_epoch: view.authority_epoch(),
            decision_digest: view.decision_digest().to_owned(),
            resource_set_digest,
            result_digest,
            sequence,
            previous_hash,
            record_hash: String::new(),
        };
        commitment.record_hash = record_hash(&commitment)?;
        insert_commitment(transaction, &commitment)?;
        let next_hash = decode_digest(commitment.record_hash())?;
        let updated = transaction
            .execute(
                "UPDATE ogvcs_identity.decision_chain_heads
                 SET sequence = $2, tail_hash = $3
                 WHERE tenant_id = $1 AND sequence = $4
                   AND tail_hash IS NOT DISTINCT FROM $5",
                &[
                    &view.tenant(),
                    &(sequence as i64),
                    &&next_hash[..],
                    &prior_sequence,
                    &prior_hash.as_deref(),
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        Ok(commitment)
    }

    fn revalidate_view(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
    ) -> Result<LoadedCurrent> {
        let presentation_digest = decode_digest(view.evidence.presentation_digest())?;
        let credential = load_credential_by_identity(
            transaction,
            view.evidence.tenant(),
            view.evidence.credential_id(),
            view.evidence.credential_generation(),
            &presentation_digest,
        )?;
        let policy = load_policy(transaction, view.tenant(), view.repository())?;
        currentness(&credential, &policy)?;
        if policy.document.generation != view.policy_generation() {
            return Err(ParticipantError::new(
                ParticipantErrorCode::PolicyGenerationMismatch,
            ));
        }
        let current_evidence = evidence(&credential, &policy, &presentation_digest)?;
        let evidence_digest = hex(&digest_json(&current_evidence)?);
        if current_evidence != view.evidence
            || evidence_digest != view.evidence_digest()
            || current_evidence.subject_digest() != view.subject_digest()
            || current_evidence.authenticated_scope_digest() != view.authenticated_scope_digest()
            || current_evidence.authority_epoch() != view.authority_epoch()
            || current_evidence.credential_generation() != view.credential_generation()
            || current_evidence.expires_at() != view.expires_at()
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        let original = evaluate_allow(
            &policy.document,
            &credential.actor,
            &credential.scope,
            RequestFacts {
                request_id: &view.request.request_id,
                tenant: view.tenant(),
                repository: view.repository(),
                permission: view.permission(),
                reason: view.request.reason.as_deref(),
                resource: &view.request.resource,
                reference: view.request.reference.as_deref(),
                snapshot: view.request.snapshot.as_deref(),
            },
        )?;
        if original.request_fingerprint != view.request_fingerprint()
            || original.decision_digest != view.decision_digest()
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        Ok(LoadedCurrent { credential, policy })
    }

    fn verify_view_binding(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
    ) -> Result<()> {
        let actual = transaction_binding(transaction)?;
        if actual != view.binding {
            return Err(ParticipantError::new(
                ParticipantErrorCode::TransactionMismatch,
            ));
        }
        let expected = self.view_seal(view)?;
        if !digest_matches(&expected, &view.seal) {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        Ok(())
    }

    fn view_seal(&self, view: &TransactionAuthorizedView) -> Result<[u8; 32]> {
        let neutral = canonical_bytes(&view.neutral_clone())?;
        Ok(sha256(&[
            VIEW_SEAL_DOMAIN,
            &self.instance_key,
            &view.binding.backend_pid.to_be_bytes(),
            &view.binding.transaction_xid.to_be_bytes(),
            &neutral,
        ]))
    }

    /// The transaction identity is minted by this authority and sealed to the
    /// database transaction.  Callers supply neither an ID nor the database
    /// binding, so they cannot transplant an authorized view between writes.
    fn new_transaction_id(&self, binding: &TransactionBinding) -> Result<String> {
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        Ok(format!(
            "tx.{}",
            hex(&sha256(&[
                b"OGVCS-IDENTITY-TRANSACTION-ID-V1\\0",
                &self.instance_key,
                &binding.backend_pid.to_be_bytes(),
                &binding.transaction_xid.to_be_bytes(),
                &nonce,
            ]))
        ))
    }

    fn verify_decision_chain_inner(
        &self,
        transaction: &mut Transaction<'_>,
        tenant: &str,
        maximum_records: usize,
    ) -> Result<DecisionChainVerification> {
        verify_schema_in_transaction(transaction)?;
        if !valid_id(tenant) {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        if maximum_records == 0 || maximum_records > MAXIMUM_DECISION_CHAIN_SCAN {
            return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
        }
        let head = transaction
            .query_opt(
                "SELECT sequence, tail_hash
                 FROM ogvcs_identity.decision_chain_heads
                 WHERE tenant_id = $1 FOR SHARE",
                &[&tenant],
            )
            .map_err(database_error)?;
        let rows = transaction
            .query(
                "SELECT commitment_id, transaction_id, correlation_id, tenant_id,
                        repository_id, authority_epoch, decision_digest,
                        resource_set_digest, result_digest, sequence,
                        previous_hash, record_hash
                 FROM ogvcs_identity.transaction_decision_commitments
                 WHERE tenant_id = $1 ORDER BY sequence
                 LIMIT $2",
                &[&tenant, &((maximum_records + 1) as i64)],
            )
            .map_err(database_error)?;
        if rows.len() > maximum_records {
            return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
        }
        let mut previous: Option<String> = None;
        for (index, row) in rows.iter().enumerate() {
            let commitment = commitment_from_row(row)?;
            if commitment.sequence() != (index + 1) as u64
                || commitment.previous_hash() != previous.as_deref()
                || record_hash(&commitment)? != commitment.record_hash()
            {
                return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
            }
            previous = Some(commitment.record_hash().to_owned());
        }
        match head {
            None if rows.is_empty() => Ok(DecisionChainVerification::new(0, None)),
            Some(head) => {
                let sequence: i64 = head.get(0);
                let tail: Option<Vec<u8>> = head.get(1);
                if usize::try_from(sequence).ok() != Some(rows.len())
                    || tail.as_deref().map(hex) != previous
                {
                    return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
                }
                Ok(DecisionChainVerification::new(rows.len(), previous))
            }
            None => Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity)),
        }
    }
}

impl TransactionAuthorizationParticipant for PostgresTransactionAuthorizationParticipant {
    fn authorize(
        &self,
        transaction: &mut Transaction<'_>,
        request: &TransactionAuthorizationRequest<'_>,
    ) -> Result<TransactionAuthorizedView> {
        let result = self.authorize_inner(transaction, request);
        poison_on_error(transaction, result)
    }

    fn recheck_batch(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
        request: &TransactionBatchRecheck<'_>,
    ) -> Result<AuthorizedResourceBatch> {
        let result = self.recheck_batch_inner(transaction, view, request);
        poison_on_error(transaction, result)
    }

    fn append_decision_commitment(
        &self,
        transaction: &mut Transaction<'_>,
        view: &TransactionAuthorizedView,
        request: &DecisionCommitmentRequest<'_>,
    ) -> Result<TransactionDecisionCommitment> {
        let result = self.append_decision_commitment_inner(transaction, view, request);
        poison_on_error(transaction, result)
    }
}

struct CredentialRecord {
    tenant: String,
    credential_id: String,
    credential_generation: u64,
    presentation_digest: [u8; 32],
    subject_digest: [u8; 32],
    actor: ActorFacts,
    authority_epoch: u64,
    current_authority_epoch: u64,
    issued_at: u64,
    expires_at: u64,
    state: String,
    now: u64,
    scope: CredentialScope,
    scope_digest: [u8; 32],
}

struct CurrentPolicy {
    document: PolicyDocument,
}

struct LoadedCurrent {
    credential: CredentialRecord,
    policy: CurrentPolicy,
}

fn load_credential_by_presentation(
    transaction: &mut Transaction<'_>,
    presentation_digest: &[u8; 32],
) -> Result<CredentialRecord> {
    let row = transaction
        .query_opt(
            "SELECT c.tenant_id, c.credential_id, c.credential_generation,
                    c.presentation_digest, c.subject_id, c.subject_digest,
                    c.actor_class, c.credential_class, c.groups_json,
                    c.authority_epoch,
                    extract(epoch FROM c.issued_at)::bigint,
                    extract(epoch FROM c.expires_at)::bigint,
                    c.state, c.scope_json, c.scope_digest,
                    a.authority_epoch,
                    extract(epoch FROM clock_timestamp())::bigint
             FROM ogvcs_identity.credentials c
             JOIN ogvcs_identity.authority_states a USING (tenant_id)
             WHERE c.presentation_digest = $1
             FOR SHARE OF c, a",
            &[&&presentation_digest[..]],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    credential_from_row(row)
}

fn load_credential_by_identity(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    credential_id: &str,
    credential_generation: u64,
    presentation_digest: &[u8; 32],
) -> Result<CredentialRecord> {
    let generation = i64::try_from(credential_generation)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    let row = transaction
        .query_opt(
            "SELECT c.tenant_id, c.credential_id, c.credential_generation,
                    c.presentation_digest, c.subject_id, c.subject_digest,
                    c.actor_class, c.credential_class, c.groups_json,
                    c.authority_epoch,
                    extract(epoch FROM c.issued_at)::bigint,
                    extract(epoch FROM c.expires_at)::bigint,
                    c.state, c.scope_json, c.scope_digest,
                    a.authority_epoch,
                    extract(epoch FROM clock_timestamp())::bigint
             FROM ogvcs_identity.credentials c
             JOIN ogvcs_identity.authority_states a USING (tenant_id)
             WHERE c.tenant_id = $1 AND c.credential_id = $2
               AND c.credential_generation = $3 AND c.presentation_digest = $4
             FOR SHARE OF c, a",
            &[
                &tenant,
                &credential_id,
                &generation,
                &&presentation_digest[..],
            ],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    credential_from_row(row)
}

fn credential_from_row(row: Row) -> Result<CredentialRecord> {
    let tenant: String = row.get(0);
    let credential_id: String = row.get(1);
    let credential_generation = positive(row.get(2))?;
    let presentation_digest = row_digest(&row, 3)?;
    let subject_id: String = row.get(4);
    let subject_digest = row_digest(&row, 5)?;
    let actor_class: String = row.get(6);
    let credential_class: String = row.get(7);
    let groups_value: Value = row.get(8);
    let groups: Vec<String> = serde_json::from_value(groups_value)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let authority_epoch = positive(row.get(9))?;
    let issued_at = nonnegative(row.get(10))?;
    let expires_at = positive(row.get(11))?;
    let state: String = row.get(12);
    let scope_value: Value = row.get(13);
    let scope: CredentialScope = serde_json::from_value(scope_value)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let scope_digest = row_digest(&row, 14)?;
    let current_authority_epoch = positive(row.get(15))?;
    let now = nonnegative(row.get(16))?;
    if !valid_id(&tenant)
        || !valid_id(&credential_id)
        || !valid_id(&subject_id)
        || !matches!(actor_class.as_str(), "human" | "service" | "administrator")
        || !matches!(credential_class.as_str(), "session" | "service-token")
        || groups.len() > 64
        || groups.iter().any(|group| !valid_id(group))
        || groups.iter().collect::<HashSet<_>>().len() != groups.len()
        || !matches!(state.as_str(), "active" | "revoked")
        || issued_at >= expires_at
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    let expected_subject = sha256(&[IDENTITY_SUBJECT_DOMAIN, subject_id.as_bytes()]);
    let expected_scope = digest_json(&scope)?;
    if !digest_matches(&expected_subject, &subject_digest)
        || !digest_matches(&expected_scope, &scope_digest)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    Ok(CredentialRecord {
        tenant,
        credential_id,
        credential_generation,
        presentation_digest,
        subject_digest,
        actor: ActorFacts {
            id: subject_id,
            class: actor_class,
            groups,
            credential_class,
            credential_generation,
            authority_epoch,
        },
        authority_epoch,
        current_authority_epoch,
        issued_at,
        expires_at,
        state,
        now,
        scope,
        scope_digest,
    })
}

fn load_policy(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
) -> Result<CurrentPolicy> {
    let row = transaction
        .query_opt(
            "SELECT pv.policy_generation, pv.authority_epoch, pv.policy_id,
                    pv.policy_version, pv.path_profile, pv.case_mode,
                    pv.policy_json, pv.policy_digest
             FROM ogvcs_identity.current_policies cp
             JOIN ogvcs_identity.policy_versions pv
               ON pv.tenant_id = cp.tenant_id
              AND pv.repository_id = cp.repository_id
              AND pv.policy_generation = cp.policy_generation
             WHERE cp.tenant_id = $1 AND cp.repository_id = $2
             FOR SHARE OF cp, pv",
            &[&tenant, &repository],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let generation = positive(row.get(0))?;
    let authority_epoch = positive(row.get(1))?;
    let policy_id: String = row.get(2);
    let policy_version: String = row.get(3);
    let path_profile: String = row.get(4);
    let case_mode: String = row.get(5);
    let value: Value = row.get(6);
    let digest = row_digest(&row, 7)?;
    let document: PolicyDocument = serde_json::from_value(value)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    validate_policy(&document)?;
    let expected = digest_json(&document)?;
    if document.generation != generation
        || document.authority_epoch != authority_epoch
        || document.id != policy_id
        || document.version != policy_version
        || document.path_profile != path_profile
        || document.case_mode != case_mode
        || !digest_matches(&expected, &digest)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    Ok(CurrentPolicy { document })
}

fn currentness(credential: &CredentialRecord, policy: &CurrentPolicy) -> Result<()> {
    if credential.state != "active" || credential.now >= credential.expires_at {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    if credential.authority_epoch != credential.current_authority_epoch
        || policy.document.authority_epoch != credential.current_authority_epoch
    {
        return Err(ParticipantError::new(ParticipantErrorCode::EpochStale));
    }
    Ok(())
}

fn evidence(
    credential: &CredentialRecord,
    policy: &CurrentPolicy,
    presentation_digest: &[u8; 32],
) -> Result<TransactionCredentialEvidence> {
    if !digest_matches(&credential.presentation_digest, presentation_digest) {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    Ok(TransactionCredentialEvidence {
        schema_version: TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA,
        presentation_digest: hex(presentation_digest),
        credential_id: credential.credential_id.clone(),
        credential_generation: credential.credential_generation,
        subject_digest: hex(&credential.subject_digest),
        tenant: credential.tenant.clone(),
        authority_epoch: credential.authority_epoch,
        policy_generation: policy.document.generation,
        issued_at: credential.issued_at,
        expires_at: credential.expires_at,
        authenticated_scope_digest: hex(&credential.scope_digest),
    })
}

fn transaction_binding(transaction: &mut Transaction<'_>) -> Result<TransactionBinding> {
    let row = transaction
        .query_one("SELECT pg_backend_pid(), txid_current()::bigint", &[])
        .map_err(database_error)?;
    Ok(TransactionBinding {
        backend_pid: row.get(0),
        transaction_xid: row.get(1),
    })
}

fn canonical_resource_set(
    resources: &[AuthorizationResource],
) -> Result<Vec<AuthorizationResource>> {
    let mut entries: Vec<_> = resources
        .iter()
        .cloned()
        .map(|resource| canonical_bytes(&resource).map(|bytes| (bytes, resource)))
        .collect::<Result<_>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    Ok(entries.into_iter().map(|(_, resource)| resource).collect())
}

fn validate_batch_size(resources: &[AuthorizationResource]) -> Result<()> {
    if resources.is_empty() || resources.len() > MAXIMUM_BATCH_RESOURCES {
        Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded))
    } else {
        Ok(())
    }
}

fn batch_reference(
    view_reference: Option<&str>,
    requested_reference: Option<&str>,
    resources: &[AuthorizationResource],
) -> Result<Option<String>> {
    if view_reference.is_some_and(|reference| Some(reference) != requested_reference) {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    let mut resource_references = resources
        .iter()
        .filter(|resource| resource.resource_type == "reference")
        .map(|resource| {
            resource
                .name
                .as_deref()
                .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::InputInvalid))
        });
    let first = resource_references.next().transpose()?;
    if resource_references.any(|reference| reference.is_err() || reference.ok() != first) {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    if first.is_some() && requested_reference != first {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    if view_reference.is_none() && requested_reference != first {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    Ok(requested_reference.map(str::to_owned))
}

fn evaluate_complete_set<T, E>(
    resources: &[AuthorizationResource],
    mut evaluate: impl FnMut(&AuthorizationResource) -> std::result::Result<T, E>,
) -> std::result::Result<Vec<T>, E> {
    let mut values = Vec::with_capacity(resources.len());
    let mut first_error = None;
    for resource in resources {
        match evaluate(resource) {
            Ok(value) => values.push(value),
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(values),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitmentCore<'a> {
    schema_version: &'a str,
    commitment_id: &'a str,
    transaction_id: &'a str,
    correlation_id: &'a str,
    tenant: &'a str,
    repository: &'a str,
    authority_epoch: u64,
    decision_digest: &'a str,
    resource_set_digest: &'a str,
    result_digest: &'a str,
    sequence: u64,
    previous_hash: Option<&'a str>,
}

fn record_hash(commitment: &TransactionDecisionCommitment) -> Result<String> {
    let core = CommitmentCore {
        schema_version: commitment.schema_version,
        commitment_id: commitment.commitment_id(),
        transaction_id: commitment.transaction_id(),
        correlation_id: commitment.correlation_id(),
        tenant: commitment.tenant(),
        repository: commitment.repository(),
        authority_epoch: commitment.authority_epoch(),
        decision_digest: commitment.decision_digest(),
        resource_set_digest: commitment.resource_set_digest(),
        result_digest: commitment.result_digest(),
        sequence: commitment.sequence(),
        previous_hash: commitment.previous_hash(),
    };
    Ok(hex(&sha256(&[
        DECISION_COMMITMENT_DOMAIN,
        &canonical_bytes(&core)?,
    ])))
}

fn insert_commitment(
    transaction: &mut Transaction<'_>,
    commitment: &TransactionDecisionCommitment,
) -> Result<()> {
    let decision = decode_digest(commitment.decision_digest())?;
    let resources = decode_digest(commitment.resource_set_digest())?;
    let result = decode_digest(commitment.result_digest())?;
    let previous = commitment.previous_hash().map(decode_digest).transpose()?;
    let record = decode_digest(commitment.record_hash())?;
    let inserted = transaction.execute(
        "INSERT INTO ogvcs_identity.transaction_decision_commitments
         (commitment_id, transaction_id, correlation_id, tenant_id,
          repository_id, authority_epoch, decision_digest,
          resource_set_digest, result_digest, sequence, previous_hash,
          record_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        &[
            &commitment.commitment_id(),
            &commitment.transaction_id(),
            &commitment.correlation_id(),
            &commitment.tenant(),
            &commitment.repository(),
            &(commitment.authority_epoch() as i64),
            &&decision[..],
            &&resources[..],
            &&result[..],
            &(commitment.sequence() as i64),
            &previous.as_ref().map(|value| &value[..]),
            &&record[..],
        ],
    );
    match inserted {
        Ok(1) => Ok(()),
        Ok(_) => Err(ParticipantError::new(ParticipantErrorCode::StateConflict)),
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            Err(ParticipantError::new(ParticipantErrorCode::StateConflict))
        }
        Err(_) => Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        )),
    }
}

fn commitment_from_row(row: &Row) -> Result<TransactionDecisionCommitment> {
    Ok(TransactionDecisionCommitment {
        schema_version: TRANSACTION_DECISION_COMMITMENT_SCHEMA,
        commitment_id: row.get(0),
        transaction_id: row.get(1),
        correlation_id: row.get(2),
        tenant: row.get(3),
        repository: row.get(4),
        authority_epoch: positive(row.get(5))?,
        decision_digest: hex(&row_digest(row, 6)?),
        resource_set_digest: hex(&row_digest(row, 7)?),
        result_digest: hex(&row_digest(row, 8)?),
        sequence: positive(row.get(9))?,
        previous_hash: row
            .get::<_, Option<Vec<u8>>>(10)
            .map(|value| fixed_digest(&value).map(|value| hex(&value)))
            .transpose()?,
        record_hash: hex(&row_digest(row, 11)?),
    })
}

fn row_digest(row: &Row, index: usize) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(index);
    fixed_digest(&bytes)
}

fn fixed_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))
}

fn positive(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
}

fn nonnegative(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
}

fn database_error(_error: postgres::Error) -> ParticipantError {
    ParticipantError::new(ParticipantErrorCode::PolicyUnavailable)
}

pub(crate) fn poison_on_error<T>(
    transaction: &mut Transaction<'_>,
    result: Result<T>,
) -> Result<T> {
    if result.is_err() {
        // A PostgreSQL error aborts the transaction. This explicit raising
        // function also poisons pure validation/denial paths, so callers cannot
        // ignore a denied result and continue mutating through another module.
        let _ = transaction.simple_query("SELECT ogvcs_identity.poison_transaction()");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        batch_reference, canonical_resource_set, digest_json, evaluate_complete_set, hex,
        validate_batch_size,
    };
    use crate::model::{BoundRequest, TransactionBinding, ViewParts};
    use crate::{
        AuthorizationResource, AuthorizedResourceBatch, TransactionAuthorizedView,
        TransactionCredentialEvidence, TransactionDecisionCommitment,
        AUTHORIZED_RESOURCE_BATCH_SCHEMA, TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA,
        TRANSACTION_DECISION_COMMITMENT_SCHEMA,
    };

    #[test]
    fn resource_batches_are_canonical_and_duplicates_fail_closed() {
        let first = AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some("a".to_owned()),
            file_id: None,
            object_id: None,
            name: None,
        };
        let second = AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some("b".to_owned()),
            file_id: None,
            object_id: None,
            name: None,
        };
        let ordered = canonical_resource_set(&[second.clone(), first.clone()]).unwrap();
        assert_eq!(ordered, vec![first.clone(), second]);
        assert!(canonical_resource_set(&[first.clone(), first]).is_err());
    }

    #[test]
    fn batch_evaluation_visits_the_complete_canonical_set_before_denial() {
        let resources = (0..4)
            .map(|index| AuthorizationResource {
                resource_type: "path".to_owned(),
                path: Some(format!("Game/{index}.asset")),
                file_id: None,
                object_id: None,
                name: None,
            })
            .collect::<Vec<_>>();
        let mut visited = Vec::new();
        let result: std::result::Result<Vec<_>, usize> =
            evaluate_complete_set(&resources, |resource| {
                let index = resource
                    .path
                    .as_deref()
                    .unwrap()
                    .strip_prefix("Game/")
                    .unwrap()
                    .strip_suffix(".asset")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                visited.push(index);
                if index == 0 || index == 2 {
                    Err(index)
                } else {
                    Ok(index)
                }
            });
        assert_eq!(result, Err(0));
        assert_eq!(visited, vec![0, 1, 2, 3]);
    }

    #[test]
    fn transaction_batch_retains_the_exact_one_thousand_resource_cap() {
        let resource = AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some("Game/Public.asset".to_owned()),
            file_id: None,
            object_id: None,
            name: None,
        };
        assert!(validate_batch_size(&vec![resource.clone(); 1_000]).is_ok());
        assert!(validate_batch_size(&vec![resource; 1_001]).is_err());
        assert!(validate_batch_size(&[]).is_err());
    }

    #[test]
    fn late_bound_reference_requires_the_exact_reference_resource() {
        let reference = AuthorizationResource {
            resource_type: "reference".to_owned(),
            path: None,
            file_id: None,
            object_id: None,
            name: Some("main".to_owned()),
        };
        let path = AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some("Game/Public.asset".to_owned()),
            file_id: None,
            object_id: None,
            name: None,
        };
        assert_eq!(
            batch_reference(None, Some("main"), &[reference.clone(), path.clone()]).unwrap(),
            Some("main".to_owned())
        );
        assert!(batch_reference(None, Some("other"), &[reference.clone(), path.clone()]).is_err());
        assert!(batch_reference(None, None, &[reference.clone(), path]).is_err());
        assert!(batch_reference(Some("main"), Some("other"), &[reference]).is_err());
    }

    #[test]
    fn neutral_records_serialize_the_exact_schema_versions() {
        let resource = AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some("a".to_owned()),
            file_id: None,
            object_id: None,
            name: None,
        };
        let evidence = TransactionCredentialEvidence {
            schema_version: TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA,
            presentation_digest: "a".repeat(64),
            credential_id: "credential".to_owned(),
            credential_generation: 1,
            subject_digest: "b".repeat(64),
            tenant: "tenant".to_owned(),
            authority_epoch: 1,
            policy_generation: 1,
            issued_at: 0,
            expires_at: 1,
            authenticated_scope_digest: "c".repeat(64),
        };
        let view = TransactionAuthorizedView::from_parts(ViewParts {
            transaction_id: "tx.1".to_owned(),
            evidence_digest: "d".repeat(64),
            subject_digest: evidence.subject_digest().to_owned(),
            authenticated_scope_digest: evidence.authenticated_scope_digest().to_owned(),
            request_fingerprint: "e".repeat(64),
            decision_digest: "f".repeat(64),
            tenant: "tenant".to_owned(),
            repository: "repository".to_owned(),
            permission: "metadata.read".to_owned(),
            authority_epoch: 1,
            credential_generation: 1,
            policy_generation: 1,
            expires_at: 1,
            evidence: evidence.clone(),
            request: BoundRequest {
                request_id: "request".to_owned(),
                reason: None,
                reference: None,
                snapshot: None,
                resource,
            },
            binding: TransactionBinding {
                backend_pid: 1,
                transaction_xid: 1,
            },
        });
        let commitment = TransactionDecisionCommitment {
            schema_version: TRANSACTION_DECISION_COMMITMENT_SCHEMA,
            commitment_id: "decision.1".to_owned(),
            transaction_id: "tx.1".to_owned(),
            correlation_id: "correlation".to_owned(),
            tenant: "tenant".to_owned(),
            repository: "repository".to_owned(),
            authority_epoch: 1,
            decision_digest: "f".repeat(64),
            resource_set_digest: "0".repeat(64),
            result_digest: "1".repeat(64),
            sequence: 1,
            previous_hash: None,
            record_hash: "2".repeat(64),
        };
        let evidence_json = serde_json::to_value(evidence).unwrap();
        let view_json = serde_json::to_value(view).unwrap();
        let commitment_json = serde_json::to_value(commitment).unwrap();
        assert_eq!(
            evidence_json["schemaVersion"],
            TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA
        );
        assert_eq!(
            view_json["schemaVersion"],
            crate::TRANSACTION_AUTHORIZED_VIEW_SCHEMA
        );
        assert_eq!(
            commitment_json["schemaVersion"],
            TRANSACTION_DECISION_COMMITMENT_SCHEMA
        );
    }

    #[test]
    fn authorized_batch_matches_the_neutral_golden_bytes_and_order() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../spec/identity-policy-audit/v1/vectors/authorized-resource-batch-golden.json"
        ))
        .unwrap();
        let inputs: Vec<AuthorizationResource> =
            serde_json::from_value(golden["inputResources"].clone()).unwrap();
        let resources = canonical_resource_set(&inputs).unwrap();
        let paths: Vec<_> = resources
            .iter()
            .map(|resource| resource.path.as_deref())
            .collect();
        assert_eq!(
            paths,
            vec![Some("Game/Alpha.asset"), Some("Game/Zeta.asset")]
        );
        let items = golden["batch"]["items"].as_array().unwrap();
        let batch = AuthorizedResourceBatch::new(
            golden["batch"]["transactionId"]
                .as_str()
                .unwrap()
                .to_owned(),
            hex(&digest_json(&resources).unwrap()),
            items
                .iter()
                .map(|item| item["decisionDigest"].as_str().unwrap().to_owned())
                .collect(),
        );
        let actual = String::from_utf8(crate::canonical::canonical_bytes(&batch).unwrap()).unwrap();
        assert_eq!(
            AuthorizedResourceBatch::schema_version(),
            AUTHORIZED_RESOURCE_BATCH_SCHEMA
        );
        assert_eq!(actual, golden["canonicalJson"].as_str().unwrap());
    }
}
