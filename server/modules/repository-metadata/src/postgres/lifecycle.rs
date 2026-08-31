// The persistence port is deliberately dormant in default builds until the
// owning service participants can pass authenticated lifecycle authority.
#![allow(dead_code)]

use super::*;
#[cfg(feature = "legacy-test-adapter")]
use crate::lifecycle::LifecycleQuarantineRequest;
use crate::lifecycle::{
    aggregate_plan_digest, application_receipt_digest, domain_digest, lifecycle_contract_digest,
    protected_fact_digest, AggregateChunkCommitment, AggregatePlanChunk, AggregatePublicationPlan,
    LifecycleApplicationReceipt, LifecycleCapability, LifecycleDirectCommand, LifecycleHealth,
    LifecycleHealthObservation, LifecycleObjectBinding, LifecycleReceiptKind,
    LifecycleReceiptWrite, LifecycleState, StagedLifecycleObject, MAXIMUM_SAFE_GENERATION,
};
use postgres::fallible_iterator::FallibleIterator;

#[derive(Clone, Debug)]
struct LockedLifecycleRow {
    state: LifecycleState,
    generation: u64,
    health: LifecycleHealth,
    health_generation: Option<u64>,
    health_observation_digest: Option<[u8; 32]>,
    authority_binding_digest: [u8; 32],
    backend_receipt_digest: Option<[u8; 32]>,
    verification_receipt_digest: Option<[u8; 32]>,
    deletion_receipt_digest: Option<[u8; 32]>,
    retention_elapsed: bool,
}

#[derive(Clone, Debug)]
struct DirectTransition {
    prior_state: LifecycleState,
    prior_generation: u64,
    next_state: LifecycleState,
    next_generation: u64,
    next_health: LifecycleHealth,
    next_health_generation: Option<u64>,
    next_health_observation_digest: Option<[u8; 32]>,
    next_backend_receipt_digest: Option<[u8; 32]>,
    next_verification_receipt_digest: Option<[u8; 32]>,
    next_deletion_receipt_digest: Option<[u8; 32]>,
    consumed_receipt: Option<([u8; 32], LifecycleReceiptKind, &'static str)>,
    fact_receipt: Option<[u8; 32]>,
    result_class: &'static str,
    reachability_recorded: bool,
}

impl<A, V> PostgresMetadataStore<A, V> {
    fn register_staged_lifecycle_inner(&mut self, object: &StagedLifecycleObject) -> Result<()> {
        if !object.is_valid() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        crate::verify_schema_compatibility(&mut self.client)?;
        let repository_id = uuid(object.repository_id);
        let tenant_id = uuid(object.tenant_id);
        let inserted = self
            .client
            .execute(
                "INSERT INTO ogvcs_metadata.object_lifecycle
                 (tenant_id, repository_id, opaque_key, object_kind, object_digest,
                  object_length, tenant_scope_digest, state, generation, health,
                  health_generation, health_observation_digest, authority_binding_digest,
                  backend_receipt_digest, verification_receipt_digest, deletion_receipt_digest,
                  retention_until)
                 SELECT $1, $2, $3, $4, $5, $6, $7, 'staged', 1,
                        'not-applicable', NULL, NULL, $8, NULL, NULL, NULL, $9
                 WHERE EXISTS (
                    SELECT 1 FROM ogvcs_metadata.repositories
                    WHERE repository_id = $2 AND tenant_id = $1
                 )
                 ON CONFLICT DO NOTHING",
                &[
                    &tenant_id,
                    &repository_id,
                    &&object.opaque_key[..],
                    &(object.object_ref.kind.code() as i16),
                    &&object.object_ref.digest[..],
                    &(object.object_length as i64),
                    &&object.tenant_scope_digest[..],
                    &&object.authority_binding_digest[..],
                    &object.retention_until,
                ],
            )
            .map_err(lifecycle_nondisclosure_database_error)?;
        if inserted == 1 {
            return Ok(());
        }
        let exact: bool = self
            .client
            .query_opt(
                "SELECT tenant_id = $1 AND object_kind = $4 AND object_digest = $5
                        AND object_length = $6 AND tenant_scope_digest = $7
                        AND state = 'staged' AND generation = 1
                        AND health = 'not-applicable' AND health_generation IS NULL
                        AND health_observation_digest IS NULL
                        AND authority_binding_digest = $8
                        AND backend_receipt_digest IS NULL
                        AND verification_receipt_digest IS NULL
                        AND deletion_receipt_digest IS NULL
                        AND retention_until = $9
                 FROM ogvcs_metadata.object_lifecycle
                 WHERE repository_id = $2 AND opaque_key = $3",
                &[
                    &tenant_id,
                    &repository_id,
                    &&object.opaque_key[..],
                    &(object.object_ref.kind.code() as i16),
                    &&object.object_ref.digest[..],
                    &(object.object_length as i64),
                    &&object.tenant_scope_digest[..],
                    &&object.authority_binding_digest[..],
                    &object.retention_until,
                ],
            )
            .map_err(database_error)?
            .is_some_and(|row| row.get(0));
        if exact {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
        }
    }

    fn persist_lifecycle_receipt_inner(&mut self, receipt: &LifecycleReceiptWrite) -> Result<()> {
        if !receipt.is_valid() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        crate::verify_schema_compatibility(&mut self.client)?;
        let inserted = self
            .client
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_receipts
                 (receipt_digest, receipt_kind, tenant_id, repository_id, opaque_key,
                  object_kind, object_digest, expected_state, expected_generation,
                  target_state, target_generation, authority_binding_digest,
                  health_result, health_generation, lifecycle_contract_digest, evidence_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, $16)
                 ON CONFLICT DO NOTHING",
                &[
                    &&receipt.receipt_digest[..],
                    &receipt.kind.as_str(),
                    &uuid(receipt.tenant_id),
                    &uuid(receipt.repository_id),
                    &&receipt.opaque_key[..],
                    &(receipt.object_ref.kind.code() as i16),
                    &&receipt.object_ref.digest[..],
                    &receipt.expected_state.as_str(),
                    &(receipt.expected_generation as i64),
                    &receipt.target_state.as_str(),
                    &(receipt.target_generation as i64),
                    &&receipt.authority_binding_digest[..],
                    &receipt.health_result.map(LifecycleHealth::as_str),
                    &receipt.health_generation.map(|value| value as i64),
                    &&lifecycle_contract_digest()[..],
                    &&receipt.evidence_digest[..],
                ],
            )
            .map_err(database_error)?;
        if inserted == 1 {
            return Ok(());
        }
        let exact: bool = self
            .client
            .query_opt(
                "SELECT receipt_kind = $2 AND tenant_id = $3 AND repository_id = $4
                        AND opaque_key = $5 AND object_kind = $6 AND object_digest = $7
                        AND expected_state = $8 AND expected_generation = $9
                        AND target_state = $10 AND target_generation = $11
                        AND authority_binding_digest = $12
                        AND health_result IS NOT DISTINCT FROM $13
                        AND health_generation IS NOT DISTINCT FROM $14
                        AND lifecycle_contract_digest = $15 AND evidence_digest = $16
                 FROM ogvcs_metadata.lifecycle_receipts WHERE receipt_digest = $1",
                &[
                    &&receipt.receipt_digest[..],
                    &receipt.kind.as_str(),
                    &uuid(receipt.tenant_id),
                    &uuid(receipt.repository_id),
                    &&receipt.opaque_key[..],
                    &(receipt.object_ref.kind.code() as i16),
                    &&receipt.object_ref.digest[..],
                    &receipt.expected_state.as_str(),
                    &(receipt.expected_generation as i64),
                    &receipt.target_state.as_str(),
                    &(receipt.target_generation as i64),
                    &&receipt.authority_binding_digest[..],
                    &receipt.health_result.map(LifecycleHealth::as_str),
                    &receipt.health_generation.map(|value| value as i64),
                    &&lifecycle_contract_digest()[..],
                    &&receipt.evidence_digest[..],
                ],
            )
            .map_err(database_error)?
            .is_some_and(|row| row.get(0));
        if exact {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
        }
    }

    fn record_lifecycle_health_inner(
        &mut self,
        observation: &LifecycleHealthObservation,
    ) -> Result<()> {
        if !observation.is_valid() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        crate::verify_schema_compatibility(&mut self.client)?;
        let mut transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let updated = transaction
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle AS lifecycle
                 SET health = $11, health_generation = $12,
                     health_observation_digest = $13, updated_at = clock_timestamp()
                 WHERE lifecycle.tenant_id = $1 AND lifecycle.repository_id = $2
                   AND lifecycle.opaque_key = $3 AND lifecycle.object_kind = $4
                   AND lifecycle.object_digest = $5 AND lifecycle.state = $6
                   AND lifecycle.generation = $7 AND lifecycle.health = $8
                   AND lifecycle.health_generation IS NOT DISTINCT FROM $9
                   AND lifecycle.health_observation_digest IS NOT DISTINCT FROM $10
                   AND lifecycle.authority_binding_digest = $14
                   AND EXISTS (
                     SELECT 1 FROM ogvcs_metadata.lifecycle_receipts AS receipt
                     WHERE receipt.receipt_digest = $13
                       AND receipt.receipt_kind = 'health-observation'
                       AND receipt.repository_id = $2 AND receipt.tenant_id = $1
                       AND receipt.opaque_key = $3 AND receipt.object_kind = $4
                       AND receipt.object_digest = $5 AND receipt.expected_state = $6
                       AND receipt.expected_generation = $7
                       AND receipt.target_state = $6 AND receipt.target_generation = $7
                       AND receipt.health_result = $11 AND receipt.health_generation = $12
                       AND receipt.authority_binding_digest = $14
                   )",
                &[
                    &uuid(observation.tenant_id),
                    &uuid(observation.repository_id),
                    &&observation.opaque_key[..],
                    &(observation.object_ref.kind.code() as i16),
                    &&observation.object_ref.digest[..],
                    &observation.expected_state.as_str(),
                    &(observation.expected_generation as i64),
                    &observation.expected_health.as_str(),
                    &observation
                        .expected_health_generation
                        .map(|value| value as i64),
                    &observation
                        .expected_health_observation_digest
                        .map(|value| value.to_vec()),
                    &observation.next_health.as_str(),
                    &(observation.next_health_generation as i64),
                    &&observation.observation_receipt_digest[..],
                    &&observation.authority_binding_digest[..],
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        transaction.commit().map_err(database_error)
    }

    /// Test-only quarantine setup. Production GC stays closed until OGVCS-018
    /// supplies a branded same-transaction current-root proof for legacy and
    /// v9 reachability alike.
    #[cfg(feature = "legacy-test-adapter")]
    fn quarantine_lifecycle_for_test_inner(
        &mut self,
        request: &LifecycleQuarantineRequest,
    ) -> Result<()> {
        if !request.is_valid() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        crate::verify_schema_compatibility(&mut self.client)?;
        let mut transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let legacy_reference_exists: bool = transaction
            .query_one(
                "SELECT EXISTS (
                    SELECT 1 FROM ogvcs_metadata.references WHERE repository_id = $1
                 )",
                &[&uuid(request.repository_id)],
            )
            .map_err(database_error)?
            .get(0);
        if legacy_reference_exists {
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let updated = transaction
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle AS lifecycle
                 SET state = 'quarantined', generation = generation + 1,
                     retention_until = $11, updated_at = clock_timestamp()
                 WHERE tenant_id = $1 AND repository_id = $2 AND opaque_key = $3
                   AND object_kind = $4 AND object_digest = $5
                   AND state = 'available' AND generation = $6 AND health = $7
                   AND health_generation IS NOT DISTINCT FROM $8
                   AND health_observation_digest IS NOT DISTINCT FROM $9
                   AND authority_binding_digest = $10
                   AND NOT EXISTS (
                     SELECT 1 FROM ogvcs_metadata.lifecycle_publication_reachability AS reachability
                     WHERE reachability.repository_id = lifecycle.repository_id
                       AND reachability.opaque_key = lifecycle.opaque_key
                   )",
                &[
                    &uuid(request.tenant_id),
                    &uuid(request.repository_id),
                    &&request.opaque_key[..],
                    &(request.object_ref.kind.code() as i16),
                    &&request.object_ref.digest[..],
                    &(request.expected_generation as i64),
                    &request.expected_health.as_str(),
                    &request.expected_health_generation.map(|value| value as i64),
                    &request
                        .current_health_observation_digest
                        .map(|value| value.to_vec()),
                    &&request.authority_binding_digest[..],
                    &request.retention_until,
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        transaction.commit().map_err(database_error)
    }

    fn begin_lifecycle_plan_inner(
        &mut self,
        plan: AggregatePublicationPlan,
    ) -> Result<PostgresLifecyclePlanWriter<'_>> {
        if !plan.structural_commitment_valid() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        crate::verify_schema_compatibility(&mut self.client)?;
        let mut transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_publication_plans
                 (plan_id, tenant_id, repository_id, publication_kind, publication_digest,
                  subject_digest, authorization_epoch, authority_contract_digest,
                  structural_commitment_digest, lifecycle_contract_digest, candidate_digest,
                  declared_plan_digest, idempotency_scope_digest, idempotency_operation,
                  idempotency_key, semantic_fingerprint, declared_object_count,
                  declared_chunk_count, declared_encoded_bytes, expires_at)
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                        $13, $14, $15, $16, $17, $18, $19,
                        clock_timestamp() + interval '1 day'
                 WHERE EXISTS (
                    SELECT 1 FROM ogvcs_metadata.repositories
                    WHERE repository_id = $3 AND tenant_id = $2
                 )",
                &[
                    &Uuid::from_bytes(plan.plan_id),
                    &uuid(plan.tenant_id),
                    &uuid(plan.repository_id),
                    &(plan.publication_ref.kind.code() as i16),
                    &&plan.publication_ref.digest[..],
                    &&plan.subject_digest[..],
                    &(plan.authorization_epoch as i64),
                    &&plan.authority_contract_digest[..],
                    &&plan.structural_commitment_digest[..],
                    &&lifecycle_contract_digest()[..],
                    &&plan.candidate_digest[..],
                    &&plan.declared_plan_digest[..],
                    &&plan.idempotency_scope_digest[..],
                    &plan.idempotency.operation,
                    &plan.idempotency.key,
                    &&plan.idempotency.semantic_fingerprint[..],
                    &(plan.declared_object_count as i32),
                    &(plan.declared_chunk_count as i32),
                    &(plan.declared_encoded_bytes as i64),
                ],
            )
            .map_err(lifecycle_nondisclosure_database_error)?;
        if inserted != 1 {
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        Ok(PostgresLifecyclePlanWriter {
            transaction: Some(transaction),
            plan,
            commitments: Vec::new(),
            object_count: 0,
            encoded_bytes: 0,
            last_opaque_key: None,
            failed: false,
        })
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn register_staged_lifecycle_for_test(
        &mut self,
        object: &StagedLifecycleObject,
    ) -> Result<()> {
        self.register_staged_lifecycle_inner(object)
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn persist_lifecycle_receipt_for_test(
        &mut self,
        receipt: &LifecycleReceiptWrite,
    ) -> Result<()> {
        self.persist_lifecycle_receipt_inner(receipt)
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn record_lifecycle_health_for_test(
        &mut self,
        observation: &LifecycleHealthObservation,
    ) -> Result<()> {
        self.record_lifecycle_health_inner(observation)
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn quarantine_lifecycle_for_test(
        &mut self,
        request: &LifecycleQuarantineRequest,
    ) -> Result<()> {
        self.quarantine_lifecycle_for_test_inner(request)
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn begin_lifecycle_plan_for_test(
        &mut self,
        plan: AggregatePublicationPlan,
    ) -> Result<PostgresLifecyclePlanWriter<'_>> {
        self.begin_lifecycle_plan_inner(plan)
    }
}

/// Owns the raw PostgreSQL plan transaction. Callers can stream at most one
/// bounded chunk at a time but cannot extract or use that transaction.
pub struct PostgresLifecyclePlanWriter<'a> {
    transaction: Option<Transaction<'a>>,
    plan: AggregatePublicationPlan,
    commitments: Vec<AggregateChunkCommitment>,
    object_count: u32,
    encoded_bytes: u64,
    last_opaque_key: Option<[u8; 32]>,
    failed: bool,
}

impl PostgresLifecyclePlanWriter<'_> {
    pub fn append_chunk(&mut self, chunk: AggregatePlanChunk) -> Result<()> {
        if self.failed {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let canonical =
            AggregatePlanChunk::new(chunk.plan_id, chunk.chunk_ordinal, chunk.items.clone())?;
        let expected_count =
            usize::try_from((self.plan.declared_object_count - self.object_count).min(1_000))
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if canonical != chunk
            || chunk.plan_id != self.plan.plan_id
            || usize::from(chunk.chunk_ordinal) != self.commitments.len()
            || chunk.items.len() != expected_count
            || self
                .last_opaque_key
                .is_some_and(|key| key >= chunk.items[0].opaque_key)
        {
            self.failed = true;
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let transaction = self
            .transaction
            .as_mut()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_publication_plan_chunks
                 (plan_id, chunk_ordinal, first_item_ordinal, item_count,
                  encoded_bytes, encoded_payload, chunk_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &Uuid::from_bytes(chunk.plan_id),
                    &(chunk.chunk_ordinal as i32),
                    &(chunk.first_item_ordinal as i32),
                    &(chunk.items.len() as i32),
                    &(chunk.encoded_bytes as i32),
                    &chunk.encoded_payload,
                    &&chunk.chunk_digest[..],
                ],
            )
            .map_err(database_error)?;
        let item_count = chunk.items.len();
        let mut item_ordinals = Vec::with_capacity(item_count);
        let mut global_ordinals = Vec::with_capacity(item_count);
        let mut opaque_keys = Vec::with_capacity(item_count);
        let mut object_kinds = Vec::with_capacity(item_count);
        let mut object_digests = Vec::with_capacity(item_count);
        let mut expected_states = Vec::with_capacity(item_count);
        let mut expected_generations = Vec::with_capacity(item_count);
        let mut expected_health = Vec::with_capacity(item_count);
        let mut expected_health_generations = Vec::with_capacity(item_count);
        let mut current_health_observations = Vec::with_capacity(item_count);
        let mut authority_bindings = Vec::with_capacity(item_count);
        let mut current_backend_receipts = Vec::with_capacity(item_count);
        let mut current_verification_receipts = Vec::with_capacity(item_count);
        let mut transition_verification_receipts = Vec::with_capacity(item_count);
        let mut resource_opaque_digests = Vec::with_capacity(item_count);
        let mut item_digests = Vec::with_capacity(item_count);
        for (index, item) in chunk.items.iter().enumerate() {
            item_ordinals.push(index as i32);
            global_ordinals.push((chunk.first_item_ordinal as usize + index) as i32);
            opaque_keys.push(item.opaque_key.to_vec());
            object_kinds.push(item.object_ref.kind.code() as i16);
            object_digests.push(item.object_ref.digest.to_vec());
            expected_states.push(item.expected_state.as_str().to_owned());
            expected_generations.push(item.expected_generation as i64);
            expected_health.push(item.expected_health.as_str().to_owned());
            expected_health_generations.push(
                item.expected_health_generation
                    .map(|value| value as i64)
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            );
            current_health_observations.push(
                item.current_health_observation_digest
                    .map(|value| value.to_vec())
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            );
            authority_bindings.push(item.authority_binding_digest.to_vec());
            current_backend_receipts.push(
                item.current_backend_receipt_digest
                    .map(|value| value.to_vec())
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            );
            current_verification_receipts.push(
                item.current_verification_receipt_digest
                    .map(|value| value.to_vec()),
            );
            transition_verification_receipts.push(
                item.transition_verification_receipt_digest
                    .map(|value| value.to_vec()),
            );
            resource_opaque_digests.push(item.resource_opaque_digest.to_vec());
            item_digests
                .push(domain_digest(b"OGVCS-LIFECYCLE-PLAN-ITEM-V1", &item.encoded()).to_vec());
        }
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_publication_plan_items
                 (plan_id, chunk_ordinal, item_ordinal, global_ordinal, opaque_key,
                  object_kind, object_digest, expected_state, expected_generation,
                  expected_health, expected_health_generation,
                  current_health_observation_digest, authority_binding_digest,
                  current_backend_receipt_digest, current_verification_receipt_digest,
                  transition_verification_receipt_digest, resource_opaque_digest, item_digest)
                 SELECT $1, $2, input.item_ordinal, input.global_ordinal, input.opaque_key,
                        input.object_kind, input.object_digest, input.expected_state,
                        input.expected_generation, input.expected_health,
                        input.expected_health_generation,
                        input.current_health_observation_digest,
                        input.authority_binding_digest, input.current_backend_receipt_digest,
                        input.current_verification_receipt_digest,
                        input.transition_verification_receipt_digest,
                        input.resource_opaque_digest, input.item_digest
                 FROM unnest(
                    $3::integer[], $4::integer[], $5::bytea[], $6::smallint[],
                    $7::bytea[], $8::text[], $9::bigint[], $10::text[], $11::bigint[],
                    $12::bytea[], $13::bytea[], $14::bytea[], $15::bytea[],
                    $16::bytea[], $17::bytea[], $18::bytea[]
                 ) AS input(
                    item_ordinal, global_ordinal, opaque_key, object_kind, object_digest,
                    expected_state, expected_generation, expected_health,
                    expected_health_generation, current_health_observation_digest,
                    authority_binding_digest, current_backend_receipt_digest,
                    current_verification_receipt_digest,
                    transition_verification_receipt_digest, resource_opaque_digest,
                    item_digest
                 )",
                &[
                    &Uuid::from_bytes(chunk.plan_id),
                    &(chunk.chunk_ordinal as i32),
                    &item_ordinals,
                    &global_ordinals,
                    &opaque_keys,
                    &object_kinds,
                    &object_digests,
                    &expected_states,
                    &expected_generations,
                    &expected_health,
                    &expected_health_generations,
                    &current_health_observations,
                    &authority_bindings,
                    &current_backend_receipts,
                    &current_verification_receipts,
                    &transition_verification_receipts,
                    &resource_opaque_digests,
                    &item_digests,
                ],
            )
            .map_err(database_error)?;
        if inserted != item_count as u64 {
            self.failed = true;
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        self.object_count += chunk.items.len() as u32;
        self.encoded_bytes += u64::from(chunk.encoded_bytes);
        self.last_opaque_key = chunk.items.last().map(|item| item.opaque_key);
        self.commitments.push(AggregateChunkCommitment {
            chunk_ordinal: chunk.chunk_ordinal,
            item_count: chunk.items.len() as u16,
            encoded_bytes: chunk.encoded_bytes,
            chunk_digest: chunk.chunk_digest,
        });
        Ok(())
    }

    pub fn seal(mut self) -> Result<[u8; 32]> {
        if self.failed
            || self.object_count != self.plan.declared_object_count
            || self.encoded_bytes != self.plan.declared_encoded_bytes
            || self.commitments.len() != usize::from(self.plan.declared_chunk_count)
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let transaction = self
            .transaction
            .as_mut()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let stored = {
            let plan_id = Uuid::from_bytes(self.plan.plan_id);
            let mut rows = transaction
                .query_raw(
                    "SELECT chunk_ordinal, item_count, encoded_bytes, encoded_payload, chunk_digest
                     FROM ogvcs_metadata.lifecycle_publication_plan_chunks
                     WHERE plan_id = $1 ORDER BY chunk_ordinal",
                    [&plan_id],
                )
                .map_err(database_error)?;
            let mut stored = Vec::with_capacity(self.commitments.len());
            while let Some(row) = rows.next().map_err(database_error)? {
                let ordinal = u16::try_from(row.get::<_, i32>(0))
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                let item_count = u16::try_from(row.get::<_, i32>(1))
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                let encoded_bytes = u32::try_from(row.get::<_, i32>(2))
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                let payload: Vec<u8> = row.get(3);
                let digest = digest32(row.get(4))?;
                if payload.len() != encoded_bytes as usize
                    || digest != domain_digest(b"OGVCS-LIFECYCLE-PLAN-CHUNK-V1", &payload)
                {
                    return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                }
                stored.push(AggregateChunkCommitment {
                    chunk_ordinal: ordinal,
                    item_count,
                    encoded_bytes,
                    chunk_digest: digest,
                });
            }
            stored
        };
        if stored != self.commitments {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let global_order_valid: bool = transaction
            .query_one(
                "SELECT count(*) = $2
                        AND count(DISTINCT opaque_key) = $2
                        AND count(DISTINCT (object_kind, object_digest)) = $2
                        AND COALESCE(bool_and(previous_key IS NULL OR previous_key < opaque_key), false)
                 FROM (
                    SELECT opaque_key,
                           lag(opaque_key) OVER (ORDER BY global_ordinal) AS previous_key,
                           object_kind, object_digest
                    FROM ogvcs_metadata.lifecycle_publication_plan_items
                    WHERE plan_id = $1
                 ) AS ordered_items",
                &[
                    &Uuid::from_bytes(self.plan.plan_id),
                    &(self.plan.declared_object_count as i64),
                ],
            )
            .map_err(database_error)?
            .get(0);
        let plan_digest = aggregate_plan_digest(&self.plan, &stored)?;
        if !global_order_valid || plan_digest != self.plan.declared_plan_digest {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_publication_plan_seals
                 (plan_id, object_count, chunk_count, encoded_bytes, plan_digest)
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &Uuid::from_bytes(self.plan.plan_id),
                    &(self.object_count as i32),
                    &(self.commitments.len() as i32),
                    &(self.encoded_bytes as i64),
                    &&plan_digest[..],
                ],
            )
            .map_err(database_error)?;
        self.transaction
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?
            .commit()
            .map_err(database_error)?;
        Ok(plan_digest)
    }
}

impl<'a, V: ObjectValidationPort, View: AuthorizedView> PostgresMetadataTransaction<'a, V, View> {
    fn apply_lifecycle_direct_inner(
        &mut self,
        command: &LifecycleDirectCommand,
    ) -> Result<LifecycleApplicationReceipt> {
        let result = self.apply_lifecycle_direct_checked(command);
        if result.is_err() {
            self.failed = true;
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        result
    }

    fn apply_lifecycle_direct_checked(
        &mut self,
        command: &LifecycleDirectCommand,
    ) -> Result<LifecycleApplicationReceipt> {
        self.require_capability(&[TransactionCapability::Publish])?;
        if command.capability != LifecycleCapability::SubmitConsumePublication
            || !command.integrity_valid()
            || command.repository_id != self.authorized_repository_id
            || command.tenant_id != self.authorization_context.tenant_id
            || command.subject_digest != self.authorization_context.subject_digest
            || command.authorization_epoch != self.authorization_context.authorization_epoch
            || command.idempotency_scope_digest != self.authenticated_scope_digest
            || self.pending_idempotency.as_ref().is_none_or(|pending| {
                pending.operation != command.idempotency.operation
                    || pending.key != command.idempotency.key
                    || pending.semantic_fingerprint != command.idempotency.semantic_fingerprint
            })
        {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let transaction_digest = domain_digest(
            b"OGVCS-LIFECYCLE-TRANSACTION-ID-V1",
            command.transaction_id.as_bytes(),
        );
        let lock_identity = format!(
            "lifecycle:{}:{}:{}",
            hex_bytes(&command.idempotency_scope_digest),
            command.capability.operation(),
            hex_bytes(&transaction_digest)
        );
        self.transaction()?
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&lock_identity],
            )
            .map_err(database_error)?;

        let mut rows = Vec::with_capacity(command.objects.len());
        for object in &command.objects {
            let row = self
                .transaction()?
                .query_opt(
                    "SELECT state, generation, health, health_generation,
                            health_observation_digest, authority_binding_digest,
                            backend_receipt_digest, verification_receipt_digest,
                            deletion_receipt_digest,
                            retention_until <= clock_timestamp()
                     FROM ogvcs_metadata.object_lifecycle
                     WHERE tenant_id = $1 AND repository_id = $2 AND opaque_key = $3
                       AND object_kind = $4 AND object_digest = $5
                     FOR UPDATE",
                    &[
                        &uuid(command.tenant_id),
                        &uuid(command.repository_id),
                        &&object.opaque_key[..],
                        &(object.object_ref.kind.code() as i16),
                        &&object.object_ref.digest[..],
                    ],
                )
                .map_err(database_error)?
                .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
            rows.push(locked_lifecycle_row(&row)?);
        }
        if command.capability == LifecycleCapability::GcAcquireDeleting {
            let legacy_or_reachable: bool = self
                .transaction()?
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM ogvcs_metadata.references WHERE repository_id = $1
                     ) OR EXISTS (
                         SELECT 1
                         FROM ogvcs_metadata.lifecycle_publication_reachability AS reachability
                         WHERE reachability.repository_id = $1
                           AND reachability.opaque_key = ANY($2)
                     )",
                    &[
                        &uuid(command.repository_id),
                        &command
                            .objects
                            .iter()
                            .map(|object| object.opaque_key.to_vec())
                            .collect::<Vec<_>>(),
                    ],
                )
                .map_err(database_error)?
                .get(0);
            if legacy_or_reachable {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
        }

        let mut transitions = Vec::with_capacity(command.objects.len());
        for (object, row) in command.objects.iter().zip(&rows) {
            if !current_binding_matches(object, row) {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
            let transition = direct_transition(command.capability, object, row)?;
            validate_transition_receipts(
                self.transaction()?,
                command.tenant_id,
                command.repository_id,
                object,
                &transition,
            )?;
            transitions.push(transition);
        }

        let application_id = random_public_uuid()?;
        let sequence = self.begin_mutation(command.repository_id)?;
        let mut facts = Vec::with_capacity(command.objects.len());
        let mut protected_bytes = Vec::with_capacity(command.objects.len() * 80);
        for (object, transition) in command.objects.iter().zip(&transitions) {
            let fact_digest = protected_fact_digest(
                command,
                object,
                transition.next_state,
                transition.next_generation,
                transition.fact_receipt,
            );
            let audit_correlation_id = random_public_uuid()?;
            let outbox_event_id = random_public_uuid()?;
            protected_bytes.extend_from_slice(&fact_digest);
            protected_bytes.extend_from_slice(&audit_correlation_id);
            protected_bytes.extend_from_slice(&outbox_event_id);
            facts.push((fact_digest, audit_correlation_id, outbox_event_id));
        }
        let protected_result_digest = domain_digest(
            b"OGVCS-LIFECYCLE-DIRECT-PROTECTED-RESULT-V1",
            &protected_bytes,
        );
        let receipt_digest = application_receipt_digest(
            application_id,
            command.repository_id,
            sequence.get(),
            command.capability,
            command.lifecycle_plan_digest,
            command.objects.len() as u32,
            protected_result_digest,
        );
        let publication_kind = command
            .publication_ref
            .map(|reference| reference.kind.code() as i16);
        let publication_digest = command
            .publication_ref
            .map(|reference| reference.digest.to_vec());
        let candidate_digest = command
            .publication_ref
            .map(|reference| reference.digest.to_vec());
        self.transaction()?
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_applications
                 (application_id, receipt_kind, receipt_digest, application_kind,
                  capability, operation, transaction_id, transaction_id_digest, plan_id,
                  tenant_id, repository_id, subject_digest, authorization_epoch,
                  context_digest, authority_contract_digest, lifecycle_contract_digest,
                  candidate_digest, publication_kind, publication_digest, root_proof_digest,
                  lifecycle_plan_digest, idempotency_scope_digest, idempotency_operation,
                  idempotency_key, semantic_fingerprint, object_count,
                  protected_result_digest, commit_sequence)
                 VALUES ($1, 'ogvcs.lifecycle-application/v1', $2, 'direct', $3, $4,
                         $5, $6, NULL, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                         $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)",
                &[
                    &Uuid::from_bytes(application_id),
                    &&receipt_digest[..],
                    &command.capability.as_str(),
                    &command.capability.operation(),
                    &command.transaction_id,
                    &&transaction_digest[..],
                    &uuid(command.tenant_id),
                    &uuid(command.repository_id),
                    &&command.subject_digest[..],
                    &(command.authorization_epoch as i64),
                    &&command.context_digest[..],
                    &&command.authority_contract_digest[..],
                    &&lifecycle_contract_digest()[..],
                    &candidate_digest,
                    &publication_kind,
                    &publication_digest,
                    &command.root_proof_digest.map(|value| value.to_vec()),
                    &&command.lifecycle_plan_digest[..],
                    &&command.idempotency_scope_digest[..],
                    &command.idempotency.operation,
                    &command.idempotency.key,
                    &&command.idempotency.semantic_fingerprint[..],
                    &(command.objects.len() as i32),
                    &&protected_result_digest[..],
                    &(sequence.get() as i64),
                ],
            )
            .map_err(database_error)?;

        for (ordinal, ((object, transition), fact)) in command
            .objects
            .iter()
            .zip(&transitions)
            .zip(&facts)
            .enumerate()
        {
            if let Some((receipt, kind, purpose)) = transition.consumed_receipt {
                let inserted = self
                    .transaction()?
                    .execute(
                        "INSERT INTO ogvcs_metadata.lifecycle_receipt_consumptions
                         (receipt_digest, receipt_kind, repository_id, opaque_key, purpose,
                          expected_generation, application_id)
                         VALUES ($1, $2, $3, $4, $5, $6, $7)",
                        &[
                            &&receipt[..],
                            &kind.as_str(),
                            &uuid(command.repository_id),
                            &&object.opaque_key[..],
                            &purpose,
                            &(object.expected_generation as i64),
                            &Uuid::from_bytes(application_id),
                        ],
                    )
                    .map_err(database_error)?;
                if inserted != 1 {
                    return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
                }
            }
            let updated = self
                .transaction()?
                .execute(
                    "UPDATE ogvcs_metadata.object_lifecycle
                     SET state = $6, generation = $7, health = $8,
                         health_generation = $9, health_observation_digest = $10,
                         backend_receipt_digest = $11, verification_receipt_digest = $12,
                         deletion_receipt_digest = $13, last_application_id = $14,
                         last_commit_sequence = $15, updated_at = clock_timestamp()
                     WHERE repository_id = $1 AND opaque_key = $2
                       AND state = $3 AND generation = $4
                       AND authority_binding_digest = $5",
                    &[
                        &uuid(command.repository_id),
                        &&object.opaque_key[..],
                        &transition.prior_state.as_str(),
                        &(transition.prior_generation as i64),
                        &&object.authority_binding_digest[..],
                        &transition.next_state.as_str(),
                        &(transition.next_generation as i64),
                        &transition.next_health.as_str(),
                        &transition.next_health_generation.map(|value| value as i64),
                        &transition
                            .next_health_observation_digest
                            .map(|value| value.to_vec()),
                        &transition
                            .next_backend_receipt_digest
                            .map(|value| value.to_vec()),
                        &transition
                            .next_verification_receipt_digest
                            .map(|value| value.to_vec()),
                        &transition
                            .next_deletion_receipt_digest
                            .map(|value| value.to_vec()),
                        &Uuid::from_bytes(application_id),
                        &(sequence.get() as i64),
                    ],
                )
                .map_err(database_error)?;
            if updated != 1 {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
            if let Some(publication) = command.publication_ref {
                let mut link = Vec::with_capacity(112);
                link.extend_from_slice(&application_id);
                link.extend_from_slice(&publication.kind.code().to_be_bytes());
                link.extend_from_slice(&publication.digest);
                link.extend_from_slice(&object.opaque_key);
                link.extend_from_slice(&transition.next_generation.to_be_bytes());
                let link_digest = domain_digest(b"OGVCS-LIFECYCLE-REACHABILITY-V1", &link);
                self.transaction()?
                    .execute(
                        "INSERT INTO ogvcs_metadata.lifecycle_publication_reachability
                         (repository_id, publication_kind, publication_digest, opaque_key,
                          lifecycle_generation, link_digest, application_id, commit_sequence)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        &[
                            &uuid(command.repository_id),
                            &(publication.kind.code() as i16),
                            &&publication.digest[..],
                            &&object.opaque_key[..],
                            &(transition.next_generation as i64),
                            &&link_digest[..],
                            &Uuid::from_bytes(application_id),
                            &(sequence.get() as i64),
                        ],
                    )
                    .map_err(database_error)?;
            }
            if command.capability == LifecycleCapability::GcAcquireDeleting {
                let root_proof = command
                    .root_proof_digest
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                let mut permit_binding = Vec::with_capacity(112);
                permit_binding.extend_from_slice(&application_id);
                permit_binding.extend_from_slice(&object.opaque_key);
                permit_binding.extend_from_slice(&transition.next_generation.to_be_bytes());
                permit_binding.extend_from_slice(&object.authority_binding_digest);
                let backend_permit_digest =
                    domain_digest(b"OGVCS-LIFECYCLE-BACKEND-DELETE-PERMIT-V1", &permit_binding);
                self.transaction()?
                    .execute(
                        "INSERT INTO ogvcs_metadata.lifecycle_deletion_fences
                         (repository_id, opaque_key, prior_generation, deleting_generation,
                          root_proof_digest, authority_contract_digest,
                          authority_binding_digest, backend_permit_digest,
                          acquired_application_id, acquired_commit_sequence)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                        &[
                            &uuid(command.repository_id),
                            &&object.opaque_key[..],
                            &(transition.prior_generation as i64),
                            &(transition.next_generation as i64),
                            &&root_proof[..],
                            &&command.authority_contract_digest[..],
                            &&object.authority_binding_digest[..],
                            &&backend_permit_digest[..],
                            &Uuid::from_bytes(application_id),
                            &(sequence.get() as i64),
                        ],
                    )
                    .map_err(database_error)?;
            }
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.lifecycle_transaction_facts
                     (application_id, fact_ordinal, resource_opaque_digest, opaque_key,
                      object_kind, object_digest, prior_state, prior_generation,
                      next_state, next_generation, health_generation, reachability_recorded,
                      receipt_digest, result_class, fact_digest, audit_correlation_id,
                      outbox_event_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                             $12, $13, $14, $15, $16, $17)",
                    &[
                        &Uuid::from_bytes(application_id),
                        &(ordinal as i32),
                        &&object.resource_opaque_digest[..],
                        &&object.opaque_key[..],
                        &(object.object_ref.kind.code() as i16),
                        &&object.object_ref.digest[..],
                        &transition.prior_state.as_str(),
                        &(transition.prior_generation as i64),
                        &transition.next_state.as_str(),
                        &(transition.next_generation as i64),
                        &transition.next_health_generation.map(|value| value as i64),
                        &transition.reachability_recorded,
                        &transition.fact_receipt.map(|value| value.to_vec()),
                        &transition.result_class,
                        &&fact.0[..],
                        &Uuid::from_bytes(fact.1),
                        &Uuid::from_bytes(fact.2),
                    ],
                )
                .map_err(database_error)?;
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.lifecycle_internal_outbox
                     (event_id, application_id, fact_ordinal, aggregate_event,
                      protected_fact_digest)
                     VALUES ($1, $2, $3, false, $4)",
                    &[
                        &Uuid::from_bytes(fact.2),
                        &Uuid::from_bytes(application_id),
                        &(ordinal as i32),
                        &&fact.0[..],
                    ],
                )
                .map_err(database_error)?;
        }
        Ok(LifecycleApplicationReceipt {
            application_id,
            receipt_digest,
            commit_sequence: sequence.get(),
            object_count: command.objects.len() as u32,
            protected_result_digest,
        })
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn lifecycle_authenticated_scope_digest_for_test(&self) -> [u8; 32] {
        self.authenticated_scope_digest
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn apply_lifecycle_direct_for_test(
        &mut self,
        command: &LifecycleDirectCommand,
    ) -> Result<LifecycleApplicationReceipt> {
        self.apply_lifecycle_direct_inner(command)
    }
}

fn locked_lifecycle_row(row: &Row) -> Result<LockedLifecycleRow> {
    Ok(LockedLifecycleRow {
        state: parse_state(row.get(0))?,
        generation: positive_u64(row.get(1))?,
        health: parse_health(row.get(2))?,
        health_generation: row.get::<_, Option<i64>>(3).map(positive_u64).transpose()?,
        health_observation_digest: optional_digest32(row.get(4))?,
        authority_binding_digest: digest32(row.get(5))?,
        backend_receipt_digest: optional_digest32(row.get(6))?,
        verification_receipt_digest: optional_digest32(row.get(7))?,
        deletion_receipt_digest: optional_digest32(row.get(8))?,
        retention_elapsed: row.get(9),
    })
}

fn current_binding_matches(object: &LifecycleObjectBinding, row: &LockedLifecycleRow) -> bool {
    row.state == object.expected_state
        && row.generation == object.expected_generation
        && row.health == object.expected_health
        && row.health_generation == object.expected_health_generation
        && row.health_observation_digest == object.current_health_observation_digest
        && row.authority_binding_digest == object.authority_binding_digest
        && row.backend_receipt_digest == object.current_backend_receipt_digest
        && row.verification_receipt_digest == object.current_verification_receipt_digest
        && row.deletion_receipt_digest == object.current_deletion_receipt_digest
}

fn direct_transition(
    capability: LifecycleCapability,
    object: &LifecycleObjectBinding,
    row: &LockedLifecycleRow,
) -> Result<DirectTransition> {
    let advance = |generation: u64| {
        generation
            .checked_add(1)
            .filter(|value| *value <= MAXIMUM_SAFE_GENERATION)
            .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
    };
    let transition = match capability {
        LifecycleCapability::SubmitConsumePublication => {
            if object.expected_state == LifecycleState::Available {
                DirectTransition {
                    prior_state: row.state,
                    prior_generation: row.generation,
                    next_state: row.state,
                    next_generation: row.generation,
                    next_health: row.health,
                    next_health_generation: row.health_generation,
                    next_health_observation_digest: row.health_observation_digest,
                    next_backend_receipt_digest: row.backend_receipt_digest,
                    next_verification_receipt_digest: row.verification_receipt_digest,
                    next_deletion_receipt_digest: row.deletion_receipt_digest,
                    consumed_receipt: None,
                    fact_receipt: row.backend_receipt_digest,
                    result_class: "publication-linked",
                    reachability_recorded: true,
                }
            } else {
                let receipt = object
                    .transition_verification_receipt_digest
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                DirectTransition {
                    prior_state: row.state,
                    prior_generation: row.generation,
                    next_state: LifecycleState::Available,
                    next_generation: advance(row.generation)?,
                    next_health: row.health,
                    next_health_generation: row.health_generation,
                    next_health_observation_digest: row.health_observation_digest,
                    next_backend_receipt_digest: row.backend_receipt_digest,
                    next_verification_receipt_digest: Some(receipt),
                    next_deletion_receipt_digest: None,
                    consumed_receipt: Some((
                        receipt,
                        LifecycleReceiptKind::ProductionVerification,
                        "publication-revival",
                    )),
                    fact_receipt: Some(receipt),
                    result_class: "quarantine-revived-and-linked",
                    reachability_recorded: true,
                }
            }
        }
        LifecycleCapability::GcAcquireDeleting => {
            if !row.retention_elapsed {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
            DirectTransition {
                prior_state: row.state,
                prior_generation: row.generation,
                next_state: LifecycleState::Deleting,
                next_generation: advance(row.generation)?,
                next_health: LifecycleHealth::NotApplicable,
                next_health_generation: None,
                next_health_observation_digest: None,
                next_backend_receipt_digest: row.backend_receipt_digest,
                next_verification_receipt_digest: row.verification_receipt_digest,
                next_deletion_receipt_digest: None,
                consumed_receipt: None,
                fact_receipt: row.backend_receipt_digest,
                result_class: "deleting-acquired",
                reachability_recorded: false,
            }
        }
        LifecycleCapability::GcCompleteDeletion => {
            let receipt = object
                .transition_deletion_receipt_digest
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            DirectTransition {
                prior_state: row.state,
                prior_generation: row.generation,
                next_state: LifecycleState::Deleted,
                next_generation: advance(row.generation)?,
                next_health: LifecycleHealth::NotApplicable,
                next_health_generation: None,
                next_health_observation_digest: None,
                next_backend_receipt_digest: row.backend_receipt_digest,
                next_verification_receipt_digest: row.verification_receipt_digest,
                next_deletion_receipt_digest: Some(receipt),
                consumed_receipt: Some((
                    receipt,
                    LifecycleReceiptKind::BackendDeletion,
                    "deletion-completion",
                )),
                fact_receipt: Some(receipt),
                result_class: "deletion-recorded",
                reachability_recorded: false,
            }
        }
        LifecycleCapability::TransferReverifyDeleted => {
            let receipt = object
                .transition_verification_receipt_digest
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            DirectTransition {
                prior_state: row.state,
                prior_generation: row.generation,
                next_state: LifecycleState::Staged,
                next_generation: advance(row.generation)?,
                next_health: LifecycleHealth::NotApplicable,
                next_health_generation: None,
                next_health_observation_digest: None,
                next_backend_receipt_digest: None,
                next_verification_receipt_digest: None,
                next_deletion_receipt_digest: None,
                consumed_receipt: Some((
                    receipt,
                    LifecycleReceiptKind::BackendReopen,
                    "deleted-generation-reopen",
                )),
                fact_receipt: Some(receipt),
                result_class: "deleted-generation-reopened",
                reachability_recorded: false,
            }
        }
        LifecycleCapability::TransferRecordAvailable => {
            let backend = object
                .transition_backend_receipt_digest
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let verification = object.transition_verification_receipt_digest;
            DirectTransition {
                prior_state: row.state,
                prior_generation: row.generation,
                next_state: LifecycleState::Available,
                next_generation: advance(row.generation)?,
                next_health: LifecycleHealth::NotApplicable,
                next_health_generation: None,
                next_health_observation_digest: None,
                next_backend_receipt_digest: Some(backend),
                next_verification_receipt_digest: verification,
                next_deletion_receipt_digest: None,
                consumed_receipt: verification.map(|receipt| {
                    (
                        receipt,
                        LifecycleReceiptKind::ProductionVerification,
                        "content-manifest-availability",
                    )
                }),
                fact_receipt: verification.or(Some(backend)),
                result_class: "availability-recorded",
                reachability_recorded: false,
            }
        }
    };
    Ok(transition)
}

fn validate_transition_receipts(
    transaction: &mut Transaction<'_>,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    object: &LifecycleObjectBinding,
    transition: &DirectTransition,
) -> Result<()> {
    let requirements = [
        object.transition_backend_receipt_digest.map(|digest| {
            (
                digest,
                LifecycleReceiptKind::BackendDurable,
                LifecycleState::Staged,
                LifecycleState::Available,
            )
        }),
        object.transition_verification_receipt_digest.map(|digest| {
            let kind = if object.expected_state == LifecycleState::Deleted {
                LifecycleReceiptKind::BackendReopen
            } else {
                LifecycleReceiptKind::ProductionVerification
            };
            (digest, kind, object.expected_state, transition.next_state)
        }),
        object.transition_deletion_receipt_digest.map(|digest| {
            (
                digest,
                LifecycleReceiptKind::BackendDeletion,
                LifecycleState::Deleting,
                LifecycleState::Deleted,
            )
        }),
    ];
    for requirement in requirements.into_iter().flatten() {
        let valid: bool = transaction
            .query_opt(
                "SELECT receipt_kind = $2 AND tenant_id = $3 AND repository_id = $4
                        AND opaque_key = $5 AND object_kind = $6 AND object_digest = $7
                        AND expected_state = $8 AND expected_generation = $9
                        AND target_state = $10 AND target_generation = $11
                        AND authority_binding_digest = $12
                        AND lifecycle_contract_digest = $13
                 FROM ogvcs_metadata.lifecycle_receipts WHERE receipt_digest = $1",
                &[
                    &&requirement.0[..],
                    &requirement.1.as_str(),
                    &uuid(tenant_id),
                    &uuid(repository_id),
                    &&object.opaque_key[..],
                    &(object.object_ref.kind.code() as i16),
                    &&object.object_ref.digest[..],
                    &requirement.2.as_str(),
                    &(object.expected_generation as i64),
                    &requirement.3.as_str(),
                    &(transition.next_generation as i64),
                    &&object.authority_binding_digest[..],
                    &&lifecycle_contract_digest()[..],
                ],
            )
            .map_err(database_error)?
            .is_some_and(|row| row.get(0));
        if !valid {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
    }
    Ok(())
}

fn parse_state(value: String) -> Result<LifecycleState> {
    match value.as_str() {
        "staged" => Ok(LifecycleState::Staged),
        "available" => Ok(LifecycleState::Available),
        "quarantined" => Ok(LifecycleState::Quarantined),
        "deleting" => Ok(LifecycleState::Deleting),
        "deleted" => Ok(LifecycleState::Deleted),
        _ => Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)),
    }
}

fn parse_health(value: String) -> Result<LifecycleHealth> {
    match value.as_str() {
        "not-applicable" => Ok(LifecycleHealth::NotApplicable),
        "healthy" => Ok(LifecycleHealth::Healthy),
        "unhealthy" => Ok(LifecycleHealth::Unhealthy),
        _ => Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)),
    }
}

fn digest32(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
}

fn optional_digest32(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    value.map(digest32).transpose()
}

fn lifecycle_nondisclosure_database_error(error: postgres::Error) -> DomainError {
    if error
        .as_db_error()
        .is_some_and(|error| matches!(error.code().code(), "40001" | "40P01"))
    {
        database_error(error)
    } else {
        DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ogvcs_object_model::ObjectKind;

    fn quarantined_unhealthy() -> (LifecycleObjectBinding, LockedLifecycleRow) {
        let object = LifecycleObjectBinding {
            opaque_key: [1; 32],
            object_ref: ObjectRef {
                kind: ObjectKind::Chunk,
                digest: [2; 32],
            },
            expected_state: LifecycleState::Quarantined,
            expected_generation: 3,
            expected_health: LifecycleHealth::Unhealthy,
            expected_health_generation: Some(2),
            current_health_observation_digest: Some([3; 32]),
            authority_binding_digest: [4; 32],
            current_backend_receipt_digest: Some([5; 32]),
            current_verification_receipt_digest: None,
            current_deletion_receipt_digest: None,
            transition_backend_receipt_digest: None,
            transition_verification_receipt_digest: None,
            transition_deletion_receipt_digest: None,
            resource_opaque_digest: [6; 32],
        };
        let row = LockedLifecycleRow {
            state: LifecycleState::Quarantined,
            generation: 3,
            health: LifecycleHealth::Unhealthy,
            health_generation: Some(2),
            health_observation_digest: Some([3; 32]),
            authority_binding_digest: [4; 32],
            backend_receipt_digest: Some([5; 32]),
            verification_receipt_digest: None,
            deletion_receipt_digest: None,
            retention_elapsed: false,
        };
        (object, row)
    }

    #[test]
    fn unhealthy_quarantine_is_reclaimable_only_after_retention() {
        let (object, mut row) = quarantined_unhealthy();
        assert!(direct_transition(LifecycleCapability::GcAcquireDeleting, &object, &row).is_err());
        row.retention_elapsed = true;
        let transition =
            direct_transition(LifecycleCapability::GcAcquireDeleting, &object, &row).unwrap();
        assert_eq!(transition.next_state, LifecycleState::Deleting);
        assert_eq!(transition.next_health, LifecycleHealth::NotApplicable);
        assert_eq!(transition.next_health_observation_digest, None);
    }
}
