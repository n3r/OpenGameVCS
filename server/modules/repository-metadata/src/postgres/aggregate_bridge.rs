use super::*;
use crate::lifecycle::{
    application_receipt_digest, domain_digest, lifecycle_contract_digest,
    LifecycleApplicationReceipt, LifecycleCapability, AUTHORIZATION_MANIFEST_SHA256,
    LIFECYCLE_CONTRACT_ARTIFACT_SET_SHA256, LIFECYCLE_CONTRACT_SHA256,
    OBJECT_TRANSFER_ARTIFACT_SET_SHA256, OBJECT_TRANSFER_MANIFEST_SHA256, PLAN_CHUNK_ITEMS_MAXIMUM,
};
use ogvcs_identity_policy_audit_postgres::{
    AggregateAuthorizationReceipt, AggregateReceiptConsumption, AggregateReceiptConsumptionRequest,
    AggregateResourceDigestProjection, AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY,
    AGGREGATE_SUBMIT_PERMISSION, MAXIMUM_AGGREGATE_RESOURCES,
};

const BRIDGE_OPERATION_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AUTHORIZED-OPERATION-V1";
const BRIDGE_FACT_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-FACT-V1";
const BRIDGE_AUDIT_ID_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-AUDIT-ID-V1";
const BRIDGE_OUTBOX_ID_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-OUTBOX-ID-V1";
const BRIDGE_AGGREGATE_OUTBOX_ID_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-RESULT-OUTBOX-ID-V1";
const BRIDGE_AGGREGATE_OUTBOX_DIGEST_DOMAIN: &[u8] =
    b"OGVCS-LIFECYCLE-AGGREGATE-RESULT-OUTBOX-DIGEST-V1";
const BRIDGE_REACHABILITY_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-REACHABILITY-V1";
const BRIDGE_PROTECTED_INITIAL_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-PROTECTED-INITIAL-V1";
const BRIDGE_PROTECTED_STEP_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-PROTECTED-STEP-V1";
const BRIDGE_PROTECTED_FINAL_DOMAIN: &[u8] = b"OGVCS-LIFECYCLE-AGGREGATE-PROTECTED-FINAL-V1";

/// The only production request that may enter the aggregate lifecycle apply
/// path. The receipt remains opaque; the bridge revalidates and consumes it.
pub struct AggregateLifecycleApplyRequest<'a> {
    pub authorization: &'a AggregateAuthorizationReceipt,
    pub lifecycle_plan_id: [u8; 16],
    pub consumption_id: &'a str,
}

/// One aggregate result. Per-resource decisions and resource identities are
/// deliberately absent from the public surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateLifecycleApplicationReceipt {
    lifecycle: LifecycleApplicationReceipt,
    identity_plan_id: String,
    consumption_id: String,
    operation_digest: [u8; 32],
    projection_page_count: u32,
    protected_result_page_count: u32,
    application_write_batch_count: u32,
    maximum_materialized_item_count: u16,
}

impl AggregateLifecycleApplicationReceipt {
    pub const fn lifecycle(&self) -> &LifecycleApplicationReceipt {
        &self.lifecycle
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

    /// Number of bounded keyset pages used to reconstruct the authorization
    /// projection from sealed lifecycle rows.
    pub const fn projection_page_count(&self) -> u32 {
        self.projection_page_count
    }

    /// Number of bounded keyset pages used for the protected-result pass.
    pub const fn protected_result_page_count(&self) -> u32 {
        self.protected_result_page_count
    }

    /// Number of bounded write batches used for facts, reachability, and
    /// item-level outbox evidence.
    pub const fn application_write_batch_count(&self) -> u32 {
        self.application_write_batch_count
    }

    /// Largest item batch materialized by the bridge. This is always at most
    /// [`PLAN_CHUNK_ITEMS_MAXIMUM`].
    pub const fn maximum_materialized_item_count(&self) -> u16 {
        self.maximum_materialized_item_count
    }
}

struct ProjectionScan {
    projection: AggregateResourceDigestProjection,
    page_count: u32,
    maximum_page_items: u16,
}

#[derive(Clone, Copy)]
struct BoundedPass {
    page_count: u32,
    maximum_page_items: u16,
}

struct ProtectedResult {
    digest: [u8; 32],
    pass: BoundedPass,
}

#[derive(Clone, Debug)]
struct BridgePlan {
    plan_id: Uuid,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    publication: ObjectRef,
    authorization_reference: String,
    authorization_snapshot: String,
    subject_digest: [u8; 32],
    authorization_epoch: u64,
    authority_contract_digest: [u8; 32],
    lifecycle_contract_digest: [u8; 32],
    candidate_digest: [u8; 32],
    plan_digest: [u8; 32],
    idempotency_scope_digest: [u8; 32],
    idempotency_operation: String,
    idempotency_key: String,
    semantic_fingerprint: [u8; 32],
    object_count: u32,
    chunk_count: u16,
    encoded_bytes: u64,
    expires_at: SystemTime,
}

#[derive(Clone, Debug)]
struct ReceiptFacts {
    subject_digest: [u8; 32],
    scope_digest: [u8; 32],
    policy_digest: [u8; 32],
    settings_digest: [u8; 32],
    reason_digest: [u8; 32],
    resource_set_digest: [u8; 32],
    projection_digest: [u8; 32],
    decision_digest: [u8; 32],
    plan_nonce: [u8; 32],
    signer_fingerprint: [u8; 32],
}

#[derive(Clone, Debug)]
struct BridgeItem {
    ordinal: u32,
    resource_digest: [u8; 32],
    opaque_key: [u8; 32],
    object_kind: i16,
    object_digest: [u8; 32],
    prior_state: String,
    prior_generation: u64,
    health_generation: u64,
    transition_receipt: Option<[u8; 32]>,
    item_digest: [u8; 32],
}

impl BridgeItem {
    fn next_generation(&self) -> Result<u64> {
        if self.prior_state == "quarantined" {
            self.prior_generation
                .checked_add(1)
                .filter(|generation| *generation <= crate::lifecycle::MAXIMUM_SAFE_GENERATION)
                .ok_or_else(denied)
        } else if self.prior_state == "available" {
            Ok(self.prior_generation)
        } else {
            Err(denied())
        }
    }

    fn result_class(&self) -> &'static str {
        if self.prior_state == "quarantined" {
            "quarantine-revived-and-linked"
        } else {
            "publication-linked"
        }
    }
}

/// This brand has no public constructor. It can exist only after the identity
/// participant has verified current authority and inserted one-use evidence
/// in the caller-owned transaction.
struct AggregateLifecycleAuthorization {
    consumption: AggregateReceiptConsumption,
    operation_digest: [u8; 32],
}

#[derive(Clone, Copy, Default)]
struct BridgeFaultInjection {
    fail_after_consume: bool,
    corrupt_application_context: bool,
}

impl<A, V> IdentityBoundPostgresMetadataStore<A, V> {
    pub fn apply_aggregate_lifecycle_publication(
        &mut self,
        request: AggregateLifecycleApplyRequest<'_>,
    ) -> Result<AggregateLifecycleApplicationReceipt> {
        self.apply_aggregate_lifecycle_publication_inner(request, BridgeFaultInjection::default())
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn apply_aggregate_lifecycle_publication_with_post_consume_failure_for_test(
        &mut self,
        request: AggregateLifecycleApplyRequest<'_>,
    ) -> Result<AggregateLifecycleApplicationReceipt> {
        self.apply_aggregate_lifecycle_publication_inner(
            request,
            BridgeFaultInjection {
                fail_after_consume: true,
                ..BridgeFaultInjection::default()
            },
        )
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn apply_aggregate_lifecycle_publication_with_wrong_context_for_test(
        &mut self,
        request: AggregateLifecycleApplyRequest<'_>,
    ) -> Result<AggregateLifecycleApplicationReceipt> {
        self.apply_aggregate_lifecycle_publication_inner(
            request,
            BridgeFaultInjection {
                corrupt_application_context: true,
                ..BridgeFaultInjection::default()
            },
        )
    }

    fn apply_aggregate_lifecycle_publication_inner(
        &mut self,
        request: AggregateLifecycleApplyRequest<'_>,
        fault: BridgeFaultInjection,
    ) -> Result<AggregateLifecycleApplicationReceipt> {
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
        let result = bridge_transaction(&mut transaction, participant, &request, fault);
        match result {
            Ok(receipt) => {
                transaction.commit().map_err(|_| denied())?;
                Ok(receipt)
            }
            Err(_) => {
                let _ = transaction.rollback();
                Err(denied())
            }
        }
    }
}

/// Crate-private composition port for the branded atomic-submit coordinator.
/// The caller owns the only commit. Every error explicitly aborts PostgreSQL
/// transaction state so catching it cannot permit a partial commit.
pub(crate) fn apply_aggregate_lifecycle_publication_in_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    request: &AggregateLifecycleApplyRequest<'_>,
) -> Result<AggregateLifecycleApplicationReceipt> {
    let result = bridge_transaction(
        transaction,
        participant,
        request,
        BridgeFaultInjection::default(),
    );
    if result.is_err() {
        poison_caller_owned_transaction(transaction);
    }
    result
}

fn bridge_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresAggregateAuthorizationParticipant,
    request: &AggregateLifecycleApplyRequest<'_>,
    fault: BridgeFaultInjection,
) -> Result<AggregateLifecycleApplicationReceipt> {
    require_serializable_transaction(transaction)?;
    if !valid_consumption_id(request.consumption_id) {
        return Err(denied());
    }
    let plan = load_bridge_plan(transaction, request.lifecycle_plan_id)?;
    let projection_scan = reconstruct_projection(transaction, &plan)?;
    let facts = validate_receipt_and_current_settings(
        transaction,
        &plan,
        request.authorization,
        &projection_scan.projection,
    )?;
    let operation_digest =
        bridge_operation_digest(&plan, request.authorization, &facts, request.consumption_id)?;
    let operation_digest_hex = hex_bytes(&operation_digest);
    let consumption = participant
        .consume_receipt(
            transaction,
            request.authorization,
            &AggregateReceiptConsumptionRequest {
                consumption_id: request.consumption_id,
                operation_digest: &operation_digest_hex,
            },
        )
        .map_err(|_| denied())?;
    let authorization = AggregateLifecycleAuthorization {
        consumption,
        operation_digest,
    };
    if fault.fail_after_consume {
        return Err(denied());
    }
    apply_authorized_plan(
        transaction,
        &plan,
        &facts,
        &authorization,
        projection_scan.page_count,
        projection_scan.maximum_page_items,
        fault,
    )
}

fn require_serializable_transaction(transaction: &mut Transaction<'_>) -> Result<()> {
    let isolation: String = transaction
        .query_one("SHOW transaction_isolation", &[])
        .map_err(database_error)?
        .get(0);
    if isolation == "serializable" {
        Ok(())
    } else {
        Err(denied())
    }
}

fn poison_caller_owned_transaction(transaction: &mut Transaction<'_>) {
    let _ = transaction.batch_execute("SELECT 1 / 0");
}

fn load_bridge_plan(
    transaction: &mut Transaction<'_>,
    requested_plan_id: [u8; 16],
) -> Result<BridgePlan> {
    if !valid_public_uuid(&requested_plan_id) {
        return Err(denied());
    }
    let row = transaction
        .query_opt(
            "SELECT plan.plan_id, plan.tenant_id, plan.repository_id,
                    plan.publication_kind, plan.publication_digest,
                    plan.authorization_reference, plan.authorization_snapshot,
                    plan.subject_digest, plan.authorization_epoch,
                    plan.authority_contract_digest, plan.lifecycle_contract_digest,
                    plan.candidate_digest, seal.plan_digest,
                    plan.idempotency_scope_digest, plan.idempotency_operation,
                    plan.idempotency_key, plan.semantic_fingerprint,
                    seal.object_count, seal.chunk_count, seal.encoded_bytes,
                    plan.expires_at,
                    seal.object_count = plan.declared_object_count
                    AND seal.chunk_count = plan.declared_chunk_count
                    AND seal.encoded_bytes = plan.declared_encoded_bytes
                    AND seal.plan_digest = plan.declared_plan_digest
                    AND plan.expires_at > clock_timestamp()
             FROM ogvcs_metadata.lifecycle_publication_plans AS plan
             JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal
               ON seal.plan_id = plan.plan_id
             WHERE plan.plan_id = $1
             FOR SHARE OF plan, seal",
            &[&Uuid::from_bytes(requested_plan_id)],
        )
        .map_err(database_error)?
        .ok_or_else(denied)?;
    if !row.get::<_, bool>(21) {
        return Err(denied());
    }
    let publication = object_ref(object_kind(row.get(3))?, row.get(4))?;
    let authorization_reference = row.get::<_, Option<String>>(5).ok_or_else(denied)?;
    let authorization_snapshot = row.get::<_, Option<String>>(6).ok_or_else(denied)?;
    let object_count = u32::try_from(row.get::<_, i32>(17)).map_err(|_| denied())?;
    let chunk_count = u16::try_from(row.get::<_, i32>(18)).map_err(|_| denied())?;
    let encoded_bytes = positive_u64(row.get(19))?;
    if object_count == 0
        || object_count as usize > MAXIMUM_AGGREGATE_RESOURCES
        || chunk_count == 0
        || usize::from(chunk_count) != (object_count as usize).div_ceil(PLAN_CHUNK_ITEMS_MAXIMUM)
        || authorization_snapshot != publication.to_string()
    {
        return Err(denied());
    }
    Ok(BridgePlan {
        plan_id: row.get(0),
        tenant_id: TenantId::from_bytes(*row.get::<_, Uuid>(1).as_bytes()),
        repository_id: RepositoryId::from_bytes(*row.get::<_, Uuid>(2).as_bytes()),
        publication,
        authorization_reference,
        authorization_snapshot,
        subject_digest: digest32(row.get(7))?,
        authorization_epoch: positive_u64(row.get(8))?,
        authority_contract_digest: digest32(row.get(9))?,
        lifecycle_contract_digest: digest32(row.get(10))?,
        candidate_digest: digest32(row.get(11))?,
        plan_digest: digest32(row.get(12))?,
        idempotency_scope_digest: digest32(row.get(13))?,
        idempotency_operation: row.get(14),
        idempotency_key: row.get(15),
        semantic_fingerprint: digest32(row.get(16))?,
        object_count,
        chunk_count,
        encoded_bytes,
        expires_at: row.get(20),
    })
}

fn reconstruct_projection(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
) -> Result<ProjectionScan> {
    let mut projection = AggregateResourceDigestProjection::new();
    let mut next_ordinal = 0_u32;
    let mut page_count = 0_u32;
    let mut maximum_page_items = 0_u16;
    while next_ordinal < plan.object_count {
        let rows = transaction
            .query(
                "SELECT global_ordinal, resource_opaque_digest
                 FROM ogvcs_metadata.lifecycle_publication_plan_items
                 WHERE plan_id = $1 AND global_ordinal >= $2
                 ORDER BY global_ordinal
                 LIMIT $3",
                &[
                    &plan.plan_id,
                    &(next_ordinal as i32),
                    &(PLAN_CHUNK_ITEMS_MAXIMUM as i64),
                ],
            )
            .map_err(database_error)?;
        if rows.is_empty() {
            return Err(denied());
        }
        page_count = page_count.checked_add(1).ok_or_else(denied)?;
        maximum_page_items =
            maximum_page_items.max(u16::try_from(rows.len()).map_err(|_| denied())?);
        for row in rows {
            let ordinal = u32::try_from(row.get::<_, i32>(0)).map_err(|_| denied())?;
            if ordinal != next_ordinal || ordinal >= plan.object_count {
                return Err(denied());
            }
            let digest: Vec<u8> = row.get(1);
            projection.push(&digest).map_err(|_| denied())?;
            next_ordinal += 1;
        }
    }
    let extra = transaction
        .query_opt(
            "SELECT 1 FROM ogvcs_metadata.lifecycle_publication_plan_items
             WHERE plan_id = $1 AND global_ordinal >= $2 LIMIT 1",
            &[&plan.plan_id, &(plan.object_count as i32)],
        )
        .map_err(database_error)?;
    if extra.is_some() || projection.count() != plan.object_count as usize {
        return Err(denied());
    }
    Ok(ProjectionScan {
        projection,
        page_count,
        maximum_page_items,
    })
}

fn validate_receipt_and_current_settings(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
    receipt: &AggregateAuthorizationReceipt,
    projection: &AggregateResourceDigestProjection,
) -> Result<ReceiptFacts> {
    let settings = transaction
        .query_opt(
            "SELECT repository.tenant_id, settings.settings_generation,
                    settings.descriptor_digest, settings.path_profile,
                    settings.case_mode
             FROM ogvcs_metadata.repositories AS repository
             JOIN ogvcs_metadata.repository_settings AS settings USING (repository_id)
             WHERE repository.repository_id = $1 AND repository.tenant_id = $2
             FOR SHARE OF repository, settings",
            &[&uuid(plan.repository_id), &uuid(plan.tenant_id)],
        )
        .map_err(database_error)?
        .ok_or_else(denied)?;
    let metadata_tenant = settings.get::<_, Uuid>(0);
    let settings_generation = positive_u64(settings.get(1))?;
    let settings_digest = digest32(settings.get(2))?;
    let path_profile: String = settings.get(3);
    let case_mode: String = settings.get(4);
    let subject_digest = decode_identity_digest(receipt.subject_digest())?;
    let scope_digest = decode_identity_digest(receipt.authenticated_scope_digest())?;
    let policy_digest = decode_identity_digest(receipt.policy_digest())?;
    let receipt_settings_digest = decode_identity_digest(receipt.settings_descriptor_digest())?;
    let reason_digest = decode_identity_digest(receipt.reason_digest())?;
    let resource_set_digest = decode_identity_digest(receipt.resource_set_digest())?;
    let projection_digest = decode_identity_digest(receipt.resource_digest_projection_digest())?;
    let decision_digest = decode_identity_digest(receipt.decision_digest())?;
    let plan_nonce = decode_identity_digest(receipt.plan_nonce())?;
    let signer_fingerprint = decode_identity_digest(receipt.signer_key_fingerprint())?;
    let reconstructed_projection = projection.finish().map_err(|_| denied())?;
    let metadata_tenant_id = Uuid::parse_str(receipt.metadata_tenant_id()).map_err(|_| denied())?;
    let metadata_repository_id =
        Uuid::parse_str(receipt.metadata_repository_id()).map_err(|_| denied())?;
    let expected_authority_contract = decode_identity_digest(AUTHORIZATION_MANIFEST_SHA256)?;
    let expected_lifecycle_contract = lifecycle_contract_digest();
    if !receipt_numbers_fit_postgres(receipt)
        || receipt.expires_at() <= receipt.issued_at()
        || receipt.tenant() != identity_tenant_id(plan.tenant_id)
        || receipt.repository() != identity_repository_id(plan.repository_id)
        || metadata_tenant_id != metadata_tenant
        || metadata_tenant_id != uuid(plan.tenant_id)
        || metadata_repository_id != uuid(plan.repository_id)
        || subject_digest != plan.subject_digest
        || scope_digest != plan.idempotency_scope_digest
        || receipt.authority_epoch() != plan.authorization_epoch
        || receipt.permission() != AGGREGATE_SUBMIT_PERMISSION
        || receipt.capability() != AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY
        || receipt.reference() != Some(plan.authorization_reference.as_str())
        || receipt.snapshot() != Some(plan.authorization_snapshot.as_str())
        || receipt.resource_count() != plan.object_count as usize
        || receipt.resource_digest_projection_digest() != reconstructed_projection
        || receipt.settings_generation() != settings_generation
        || receipt_settings_digest != settings_digest
        || receipt.path_profile() != path_profile
        || receipt.case_mode() != case_mode
        || plan.idempotency_operation != LifecycleCapability::SubmitConsumePublication.operation()
        || plan.authority_contract_digest != expected_authority_contract
        || plan.lifecycle_contract_digest != expected_lifecycle_contract
        || SystemTime::now() >= plan.expires_at
    {
        return Err(denied());
    }
    Ok(ReceiptFacts {
        subject_digest,
        scope_digest,
        policy_digest,
        settings_digest,
        reason_digest,
        resource_set_digest,
        projection_digest,
        decision_digest,
        plan_nonce,
        signer_fingerprint,
    })
}

fn bridge_operation_digest(
    plan: &BridgePlan,
    receipt: &AggregateAuthorizationReceipt,
    facts: &ReceiptFacts,
    consumption_id: &str,
) -> Result<[u8; 32]> {
    let identity_resource_count = u64::try_from(receipt.resource_count()).map_err(|_| denied())?;
    let lifecycle_expiry = plan
        .expires_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| denied())?;
    Ok(bridge_operation_digest_from_fields(&[
        BridgeOperationField::Required(AggregateAuthorizationReceipt::schema_version().as_bytes()),
        BridgeOperationField::Required(receipt.plan_id().as_bytes()),
        BridgeOperationField::Required(&facts.decision_digest),
        BridgeOperationField::Required(receipt.tenant().as_bytes()),
        BridgeOperationField::Required(receipt.repository().as_bytes()),
        BridgeOperationField::Required(plan.tenant_id.as_bytes()),
        BridgeOperationField::Required(plan.repository_id.as_bytes()),
        BridgeOperationField::Required(plan.plan_id.as_bytes()),
        BridgeOperationField::Required(&plan.plan_digest),
        BridgeOperationField::U64(identity_resource_count),
        BridgeOperationField::U64(u64::from(plan.object_count)),
        BridgeOperationField::U64(u64::from(plan.chunk_count)),
        BridgeOperationField::U64(plan.encoded_bytes),
        BridgeOperationField::U64(lifecycle_expiry.as_secs()),
        BridgeOperationField::U32(lifecycle_expiry.subsec_nanos()),
        BridgeOperationField::U16(plan.publication.kind.code()),
        BridgeOperationField::Required(&plan.publication.digest),
        BridgeOperationField::Required(&plan.candidate_digest),
        BridgeOperationField::Required(&plan.authority_contract_digest),
        BridgeOperationField::Required(OBJECT_TRANSFER_MANIFEST_SHA256.as_bytes()),
        BridgeOperationField::Required(OBJECT_TRANSFER_ARTIFACT_SET_SHA256.as_bytes()),
        BridgeOperationField::Required(LIFECYCLE_CONTRACT_SHA256.as_bytes()),
        BridgeOperationField::Required(LIFECYCLE_CONTRACT_ARTIFACT_SET_SHA256.as_bytes()),
        BridgeOperationField::Required(&facts.subject_digest),
        BridgeOperationField::Required(&facts.scope_digest),
        BridgeOperationField::U64(receipt.credential_generation()),
        BridgeOperationField::U64(receipt.authority_epoch()),
        BridgeOperationField::U64(receipt.security_epoch()),
        BridgeOperationField::U64(receipt.policy_generation()),
        BridgeOperationField::Required(&facts.policy_digest),
        BridgeOperationField::U64(receipt.settings_generation()),
        BridgeOperationField::Required(&facts.settings_digest),
        BridgeOperationField::Required(receipt.path_profile().as_bytes()),
        BridgeOperationField::Required(receipt.case_mode().as_bytes()),
        BridgeOperationField::Required(receipt.permission().as_bytes()),
        BridgeOperationField::Required(receipt.capability().as_bytes()),
        BridgeOperationField::Optional(receipt.reference().map(str::as_bytes)),
        BridgeOperationField::Optional(receipt.snapshot().map(str::as_bytes)),
        BridgeOperationField::Required(&facts.reason_digest),
        BridgeOperationField::Required(&facts.resource_set_digest),
        BridgeOperationField::Required(&facts.projection_digest),
        BridgeOperationField::Required(&facts.plan_nonce),
        BridgeOperationField::Required(plan.idempotency_operation.as_bytes()),
        BridgeOperationField::Required(plan.idempotency_key.as_bytes()),
        BridgeOperationField::Required(&plan.idempotency_scope_digest),
        BridgeOperationField::Required(&plan.semantic_fingerprint),
        BridgeOperationField::Required(consumption_id.as_bytes()),
        BridgeOperationField::U64(receipt.issued_at()),
        BridgeOperationField::U64(receipt.expires_at()),
        BridgeOperationField::U64(receipt.signer_key_generation()),
        BridgeOperationField::Required(receipt.signer_key_reference().as_bytes()),
        BridgeOperationField::Required(&facts.signer_fingerprint),
    ]))
}

enum BridgeOperationField<'a> {
    Required(&'a [u8]),
    Optional(Option<&'a [u8]>),
    U64(u64),
    U32(u32),
    U16(u16),
}

fn bridge_operation_digest_from_fields(fields: &[BridgeOperationField<'_>]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(2_048);
    for field in fields {
        match field {
            BridgeOperationField::Required(value) => bridge_field(&mut bytes, value),
            BridgeOperationField::Optional(value) => bridge_optional_field(&mut bytes, *value),
            BridgeOperationField::U64(value) => bridge_field(&mut bytes, &value.to_be_bytes()),
            BridgeOperationField::U32(value) => bridge_field(&mut bytes, &value.to_be_bytes()),
            BridgeOperationField::U16(value) => bridge_field(&mut bytes, &value.to_be_bytes()),
        }
    }
    domain_digest(BRIDGE_OPERATION_DOMAIN, &bytes)
}

fn apply_authorized_plan(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
    receipt: &ReceiptFacts,
    authorization: &AggregateLifecycleAuthorization,
    projection_page_count: u32,
    projection_maximum_page_items: u16,
    fault: BridgeFaultInjection,
) -> Result<AggregateLifecycleApplicationReceipt> {
    if authorization.consumption.plan_id() != authorization.consumption.authorization().plan_id()
        || authorization.consumption.operation_digest()
            != hex_bytes(&authorization.operation_digest)
    {
        return Err(denied());
    }
    let lock_identity = format!("lifecycle-aggregate:{}", plan.plan_id);
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&lock_identity],
        )
        .map_err(database_error)?;
    let current: bool = transaction
        .query_one(
            "SELECT ogvcs_metadata.lock_and_validate_lifecycle_publication_plan($1)",
            &[&plan.plan_id],
        )
        .map_err(database_error)?
        .get(0);
    if !current {
        return Err(denied());
    }

    let application_id = random_public_uuid()?;
    let sequence = transaction
        .query_opt(
            "UPDATE ogvcs_metadata.repository_commit_sequences
             SET applied_sequence = applied_sequence + 1
             WHERE repository_id = $1
             RETURNING applied_sequence",
            &[&uuid(plan.repository_id)],
        )
        .map_err(database_error)?
        .ok_or_else(denied)
        .and_then(|row| positive_u64(row.get(0)))?;
    let protected_result = protected_result_digest(
        transaction,
        plan,
        application_id,
        authorization.operation_digest,
    )?;
    let protected_result_digest = protected_result.digest;
    let application_receipt = application_receipt_digest(
        application_id,
        plan.repository_id,
        sequence,
        LifecycleCapability::SubmitConsumePublication,
        plan.plan_digest,
        plan.object_count,
        protected_result_digest,
    );
    let application_context_digest = if fault.corrupt_application_context {
        [authorization.operation_digest[0] ^ 1; 32]
    } else {
        authorization.operation_digest
    };
    let inserted = transaction
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
             VALUES ($1, 'ogvcs.lifecycle-application/v1', $2, 'aggregate',
                     'submit.consume-publication', 'submit.finalize', NULL, NULL, $3,
                     $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL,
                     $14, $15, $16, $17, $18, $19, $20, $21)",
            &[
                &Uuid::from_bytes(application_id),
                &&application_receipt[..],
                &plan.plan_id,
                &uuid(plan.tenant_id),
                &uuid(plan.repository_id),
                &&plan.subject_digest[..],
                &(plan.authorization_epoch as i64),
                &&application_context_digest[..],
                &&plan.authority_contract_digest[..],
                &&plan.lifecycle_contract_digest[..],
                &&plan.candidate_digest[..],
                &(plan.publication.kind.code() as i16),
                &&plan.publication.digest[..],
                &&plan.plan_digest[..],
                &&plan.idempotency_scope_digest[..],
                &plan.idempotency_operation,
                &plan.idempotency_key,
                &&plan.semantic_fingerprint[..],
                &(plan.object_count as i32),
                &&protected_result_digest[..],
                &(sequence as i64),
            ],
        )
        .map_err(database_error)?;
    if inserted != 1 {
        return Err(denied());
    }

    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_receipt_consumptions
             (receipt_digest, receipt_kind, repository_id, opaque_key, purpose,
              expected_generation, application_id)
             SELECT item.transition_verification_receipt_digest,
                    'production-verification', plan.repository_id, item.opaque_key,
                    'publication-revival', item.expected_generation, $2
             FROM ogvcs_metadata.lifecycle_publication_plan_items AS item
             JOIN ogvcs_metadata.lifecycle_publication_plans AS plan USING (plan_id)
             WHERE item.plan_id = $1 AND item.expected_state = 'quarantined'",
            &[&plan.plan_id, &Uuid::from_bytes(application_id)],
        )
        .map_err(database_error)?;

    let updated = transaction
        .execute(
            "UPDATE ogvcs_metadata.object_lifecycle AS lifecycle
             SET state = 'available',
                 generation = CASE WHEN item.expected_state = 'quarantined'
                                   THEN item.expected_generation + 1
                                   ELSE item.expected_generation END,
                 verification_receipt_digest = CASE
                     WHEN item.expected_state = 'quarantined'
                     THEN item.transition_verification_receipt_digest
                     ELSE lifecycle.verification_receipt_digest END,
                 last_application_id = $2, last_commit_sequence = $3,
                 updated_at = clock_timestamp()
             FROM ogvcs_metadata.lifecycle_publication_plan_items AS item
             WHERE item.plan_id = $1
               AND lifecycle.tenant_id = $4
               AND lifecycle.repository_id = $5
               AND lifecycle.opaque_key = item.opaque_key
               AND lifecycle.object_kind = item.object_kind
               AND lifecycle.object_digest = item.object_digest
               AND lifecycle.state = item.expected_state
               AND lifecycle.generation = item.expected_generation
               AND lifecycle.health = item.expected_health
               AND lifecycle.health_generation = item.expected_health_generation
               AND lifecycle.health_observation_digest
                   = item.current_health_observation_digest
               AND lifecycle.authority_binding_digest = item.authority_binding_digest
               AND lifecycle.backend_receipt_digest = item.current_backend_receipt_digest
               AND lifecycle.verification_receipt_digest
                   IS NOT DISTINCT FROM item.current_verification_receipt_digest",
            &[
                &plan.plan_id,
                &Uuid::from_bytes(application_id),
                &(sequence as i64),
                &uuid(plan.tenant_id),
                &uuid(plan.repository_id),
            ],
        )
        .map_err(database_error)?;
    if updated != u64::from(plan.object_count) {
        return Err(denied());
    }

    let write_pass = insert_application_items(
        transaction,
        plan,
        application_id,
        sequence,
        authorization.operation_digest,
    )?;
    insert_aggregate_outbox(
        transaction,
        application_id,
        plan.object_count,
        authorization.operation_digest,
        protected_result_digest,
    )?;
    insert_authorization_evidence(transaction, plan, receipt, authorization, application_id)?;

    let lifecycle = LifecycleApplicationReceipt {
        application_id,
        receipt_digest: application_receipt,
        commit_sequence: sequence,
        object_count: plan.object_count,
        protected_result_digest,
    };
    Ok(AggregateLifecycleApplicationReceipt {
        lifecycle,
        identity_plan_id: authorization.consumption.plan_id().to_owned(),
        consumption_id: authorization.consumption.consumption_id().to_owned(),
        operation_digest: authorization.operation_digest,
        projection_page_count,
        protected_result_page_count: protected_result.pass.page_count,
        application_write_batch_count: write_pass.page_count,
        maximum_materialized_item_count: projection_maximum_page_items
            .max(protected_result.pass.maximum_page_items)
            .max(write_pass.maximum_page_items),
    })
}

fn protected_result_digest(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
    application_id: [u8; 16],
    operation_digest: [u8; 32],
) -> Result<ProtectedResult> {
    let mut chain = domain_digest(BRIDGE_PROTECTED_INITIAL_DOMAIN, &operation_digest);
    let mut next = 0_u32;
    let mut page_count = 0_u32;
    let mut maximum_page_items = 0_u16;
    while next < plan.object_count {
        let items = load_item_batch(transaction, plan.plan_id, next)?;
        if items.is_empty() {
            return Err(denied());
        }
        page_count = page_count.checked_add(1).ok_or_else(denied)?;
        maximum_page_items =
            maximum_page_items.max(u16::try_from(items.len()).map_err(|_| denied())?);
        for item in items {
            if item.ordinal != next {
                return Err(denied());
            }
            let fact = aggregate_fact_digest(&item, application_id, operation_digest)?;
            let audit = deterministic_uuid(BRIDGE_AUDIT_ID_DOMAIN, &fact);
            let outbox = deterministic_uuid(BRIDGE_OUTBOX_ID_DOMAIN, &fact);
            chain = domain_digest(
                BRIDGE_PROTECTED_STEP_DOMAIN,
                &[chain.as_slice(), fact.as_slice(), &audit, &outbox].concat(),
            );
            next += 1;
        }
    }
    Ok(ProtectedResult {
        digest: domain_digest(
            BRIDGE_PROTECTED_FINAL_DOMAIN,
            &[
                u64::from(plan.object_count).to_be_bytes().as_slice(),
                chain.as_slice(),
            ]
            .concat(),
        ),
        pass: BoundedPass {
            page_count,
            maximum_page_items,
        },
    })
}

fn insert_application_items(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
    application_id: [u8; 16],
    sequence: u64,
    operation_digest: [u8; 32],
) -> Result<BoundedPass> {
    let mut next = 0_u32;
    let mut page_count = 0_u32;
    let mut maximum_page_items = 0_u16;
    while next < plan.object_count {
        let items = load_item_batch(transaction, plan.plan_id, next)?;
        if items.is_empty() || items[0].ordinal != next {
            return Err(denied());
        }
        page_count = page_count.checked_add(1).ok_or_else(denied)?;
        maximum_page_items =
            maximum_page_items.max(u16::try_from(items.len()).map_err(|_| denied())?);
        insert_item_batch(
            transaction,
            plan,
            application_id,
            sequence,
            operation_digest,
            &items,
        )?;
        next = next.checked_add(items.len() as u32).ok_or_else(denied)?;
    }
    Ok(BoundedPass {
        page_count,
        maximum_page_items,
    })
}

fn load_item_batch(
    transaction: &mut Transaction<'_>,
    plan_id: Uuid,
    first_ordinal: u32,
) -> Result<Vec<BridgeItem>> {
    let rows = transaction
        .query(
            "SELECT global_ordinal, resource_opaque_digest, opaque_key,
                    object_kind, object_digest, expected_state, expected_generation,
                    expected_health_generation,
                    transition_verification_receipt_digest, item_digest
             FROM ogvcs_metadata.lifecycle_publication_plan_items
             WHERE plan_id = $1 AND global_ordinal >= $2
             ORDER BY global_ordinal LIMIT $3",
            &[
                &plan_id,
                &(first_ordinal as i32),
                &(PLAN_CHUNK_ITEMS_MAXIMUM as i64),
            ],
        )
        .map_err(database_error)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(BridgeItem {
            ordinal: u32::try_from(row.get::<_, i32>(0)).map_err(|_| denied())?,
            resource_digest: digest32(row.get(1))?,
            opaque_key: digest32(row.get(2))?,
            object_kind: row.get(3),
            object_digest: digest32(row.get(4))?,
            prior_state: row.get(5),
            prior_generation: positive_u64(row.get(6))?,
            health_generation: positive_u64(row.get(7))?,
            transition_receipt: optional_digest32(row.get(8))?,
            item_digest: digest32(row.get(9))?,
        });
    }
    Ok(items)
}

fn insert_item_batch(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
    application_id: [u8; 16],
    sequence: u64,
    operation_digest: [u8; 32],
    items: &[BridgeItem],
) -> Result<()> {
    if items.is_empty() || items.len() > PLAN_CHUNK_ITEMS_MAXIMUM {
        return Err(denied());
    }
    let mut ordinals = Vec::with_capacity(items.len());
    let mut resource_digests = Vec::with_capacity(items.len());
    let mut opaque_keys = Vec::with_capacity(items.len());
    let mut object_kinds = Vec::with_capacity(items.len());
    let mut object_digests = Vec::with_capacity(items.len());
    let mut prior_states = Vec::with_capacity(items.len());
    let mut prior_generations = Vec::with_capacity(items.len());
    let mut next_generations = Vec::with_capacity(items.len());
    let mut health_generations = Vec::with_capacity(items.len());
    let mut receipts = Vec::with_capacity(items.len());
    let mut result_classes = Vec::with_capacity(items.len());
    let mut fact_digests = Vec::with_capacity(items.len());
    let mut audit_ids = Vec::with_capacity(items.len());
    let mut outbox_ids = Vec::with_capacity(items.len());
    let mut link_digests = Vec::with_capacity(items.len());
    for item in items {
        let next_generation = item.next_generation()?;
        let fact = aggregate_fact_digest(item, application_id, operation_digest)?;
        let audit = deterministic_uuid(BRIDGE_AUDIT_ID_DOMAIN, &fact);
        let outbox = deterministic_uuid(BRIDGE_OUTBOX_ID_DOMAIN, &fact);
        let link = reachability_digest(
            application_id,
            plan.publication,
            item.opaque_key,
            next_generation,
            fact,
        );
        ordinals.push(item.ordinal as i32);
        resource_digests.push(item.resource_digest.to_vec());
        opaque_keys.push(item.opaque_key.to_vec());
        object_kinds.push(item.object_kind);
        object_digests.push(item.object_digest.to_vec());
        prior_states.push(item.prior_state.clone());
        prior_generations.push(item.prior_generation as i64);
        next_generations.push(next_generation as i64);
        health_generations.push(item.health_generation as i64);
        receipts.push(item.transition_receipt.map(|value| value.to_vec()));
        result_classes.push(item.result_class().to_owned());
        fact_digests.push(fact.to_vec());
        audit_ids.push(Uuid::from_bytes(audit));
        outbox_ids.push(Uuid::from_bytes(outbox));
        link_digests.push(link.to_vec());
    }
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_transaction_facts
             (application_id, fact_ordinal, resource_opaque_digest, opaque_key,
              object_kind, object_digest, prior_state, prior_generation,
              next_state, next_generation, health_generation, reachability_recorded,
              receipt_digest, result_class, fact_digest, audit_correlation_id,
              outbox_event_id)
             SELECT $1, input.fact_ordinal, input.resource_digest, input.opaque_key,
                    input.object_kind, input.object_digest, input.prior_state,
                    input.prior_generation, 'available', input.next_generation,
                    input.health_generation, true, input.receipt_digest, input.result_class,
                    input.fact_digest, input.audit_id, input.outbox_id
             FROM unnest($2::integer[], $3::bytea[], $4::bytea[], $5::smallint[],
                         $6::bytea[], $7::text[], $8::bigint[], $9::bigint[],
                         $10::bigint[], $11::bytea[], $12::text[], $13::bytea[],
                         $14::uuid[], $15::uuid[])
                  AS input(fact_ordinal, resource_digest, opaque_key, object_kind,
                     object_digest, prior_state, prior_generation, next_generation,
                     health_generation, receipt_digest, result_class, fact_digest,
                     audit_id, outbox_id)",
            &[
                &Uuid::from_bytes(application_id),
                &ordinals,
                &resource_digests,
                &opaque_keys,
                &object_kinds,
                &object_digests,
                &prior_states,
                &prior_generations,
                &next_generations,
                &health_generations,
                &receipts,
                &result_classes,
                &fact_digests,
                &audit_ids,
                &outbox_ids,
            ],
        )
        .map_err(database_error)?;
    if inserted != items.len() as u64 {
        return Err(denied());
    }
    let reached = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_publication_reachability
             (repository_id, publication_kind, publication_digest, opaque_key,
              lifecycle_generation, link_digest, application_id, commit_sequence)
             SELECT $1, $2, $3, input.opaque_key, input.next_generation,
                    input.link_digest, $4, $5
             FROM unnest($6::bytea[], $7::bigint[], $8::bytea[])
                  AS input(opaque_key, next_generation, link_digest)",
            &[
                &uuid(plan.repository_id),
                &(plan.publication.kind.code() as i16),
                &&plan.publication.digest[..],
                &Uuid::from_bytes(application_id),
                &(sequence as i64),
                &opaque_keys,
                &next_generations,
                &link_digests,
            ],
        )
        .map_err(database_error)?;
    if reached != items.len() as u64 {
        return Err(denied());
    }
    let emitted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_internal_outbox
             (event_id, application_id, fact_ordinal, aggregate_event,
              protected_fact_digest)
             SELECT input.event_id, $1, input.fact_ordinal, false, input.fact_digest
             FROM unnest($2::uuid[], $3::integer[], $4::bytea[])
                  AS input(event_id, fact_ordinal, fact_digest)",
            &[
                &Uuid::from_bytes(application_id),
                &outbox_ids,
                &ordinals,
                &fact_digests,
            ],
        )
        .map_err(database_error)?;
    if emitted != items.len() as u64 {
        return Err(denied());
    }
    Ok(())
}

fn insert_authorization_evidence(
    transaction: &mut Transaction<'_>,
    plan: &BridgePlan,
    facts: &ReceiptFacts,
    authorization: &AggregateLifecycleAuthorization,
    application_id: [u8; 16],
) -> Result<()> {
    let receipt = authorization.consumption.authorization();
    let lifecycle_manifest = decode_identity_digest(LIFECYCLE_CONTRACT_SHA256)?;
    let lifecycle_artifacts = decode_identity_digest(LIFECYCLE_CONTRACT_ARTIFACT_SET_SHA256)?;
    let manifest = decode_identity_digest(OBJECT_TRANSFER_MANIFEST_SHA256)?;
    let artifacts = decode_identity_digest(OBJECT_TRANSFER_ARTIFACT_SET_SHA256)?;
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_aggregate_authorization_evidence
             (application_id, lifecycle_plan_id, identity_plan_id, consumption_id,
              operation_digest, identity_decision_digest,
              identity_plan_nonce, metadata_tenant_id, metadata_repository_id, subject_digest,
              authenticated_scope_digest, credential_generation, authority_epoch,
              security_epoch, policy_generation, policy_digest, settings_generation,
              settings_descriptor_digest, path_profile, case_mode, permission,
              capability, authorization_reference, authorization_snapshot,
              reason_digest, resource_count, resource_set_digest,
              resource_digest_projection_digest, signer_key_generation,
              signer_key_reference, signer_key_fingerprint, identity_issued_at_epoch,
              identity_expires_at_epoch, lifecycle_plan_digest,
              lifecycle_chunk_count, lifecycle_encoded_bytes, lifecycle_expires_at,
              lifecycle_contract_manifest_digest,
              lifecycle_contract_artifact_set_digest,
              object_transfer_manifest_digest, object_transfer_artifact_set_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                     $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
                     $23, $24, $25, $26, $27, $28, $29, $30, $31, $32,
                     $33, $34, $35, $36, $37, $38, $39, $40, $41)",
            &[
                &Uuid::from_bytes(application_id),
                &plan.plan_id,
                &authorization.consumption.plan_id(),
                &authorization.consumption.consumption_id(),
                &&authorization.operation_digest[..],
                &&facts.decision_digest[..],
                &&facts.plan_nonce[..],
                &uuid(plan.tenant_id),
                &uuid(plan.repository_id),
                &&facts.subject_digest[..],
                &&facts.scope_digest[..],
                &(receipt.credential_generation() as i64),
                &(receipt.authority_epoch() as i64),
                &(receipt.security_epoch() as i64),
                &(receipt.policy_generation() as i64),
                &&facts.policy_digest[..],
                &(receipt.settings_generation() as i64),
                &&facts.settings_digest[..],
                &receipt.path_profile(),
                &receipt.case_mode(),
                &receipt.permission(),
                &receipt.capability(),
                &plan.authorization_reference,
                &plan.authorization_snapshot,
                &&facts.reason_digest[..],
                &(plan.object_count as i32),
                &&facts.resource_set_digest[..],
                &&facts.projection_digest[..],
                &(receipt.signer_key_generation() as i64),
                &receipt.signer_key_reference(),
                &&facts.signer_fingerprint[..],
                &(receipt.issued_at() as i64),
                &(receipt.expires_at() as i64),
                &&plan.plan_digest[..],
                &(plan.chunk_count as i32),
                &(plan.encoded_bytes as i64),
                &plan.expires_at,
                &&lifecycle_manifest[..],
                &&lifecycle_artifacts[..],
                &&manifest[..],
                &&artifacts[..],
            ],
        )
        .map_err(database_error)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(denied())
    }
}

fn insert_aggregate_outbox(
    transaction: &mut Transaction<'_>,
    application_id: [u8; 16],
    object_count: u32,
    operation_digest: [u8; 32],
    protected_result_digest: [u8; 32],
) -> Result<()> {
    let binding = [
        operation_digest.as_slice(),
        protected_result_digest.as_slice(),
        &u64::from(object_count).to_be_bytes(),
    ]
    .concat();
    let event_id = deterministic_uuid(BRIDGE_AGGREGATE_OUTBOX_ID_DOMAIN, &binding);
    let event_digest = domain_digest(BRIDGE_AGGREGATE_OUTBOX_DIGEST_DOMAIN, &binding);
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_internal_outbox
             (event_id, application_id, fact_ordinal, aggregate_event,
              protected_fact_digest)
             VALUES ($1, $2, NULL, true, $3)",
            &[
                &Uuid::from_bytes(event_id),
                &Uuid::from_bytes(application_id),
                &&event_digest[..],
            ],
        )
        .map_err(database_error)?;
    if inserted == 1 {
        Ok(())
    } else {
        Err(denied())
    }
}

fn aggregate_fact_digest(
    item: &BridgeItem,
    application_id: [u8; 16],
    operation_digest: [u8; 32],
) -> Result<[u8; 32]> {
    let mut bytes = Vec::with_capacity(384);
    bridge_field(&mut bytes, &application_id);
    bridge_field(&mut bytes, &operation_digest);
    bridge_field(&mut bytes, &u64::from(item.ordinal).to_be_bytes());
    bridge_field(&mut bytes, &item.resource_digest);
    bridge_field(&mut bytes, &item.opaque_key);
    bridge_field(&mut bytes, &item.object_kind.to_be_bytes());
    bridge_field(&mut bytes, &item.object_digest);
    bridge_field(&mut bytes, item.prior_state.as_bytes());
    bridge_field(&mut bytes, &item.prior_generation.to_be_bytes());
    bridge_field(&mut bytes, b"available");
    bridge_field(&mut bytes, &item.next_generation()?.to_be_bytes());
    bridge_field(&mut bytes, &item.health_generation.to_be_bytes());
    bridge_optional_field(
        &mut bytes,
        item.transition_receipt.as_ref().map(<[u8; 32]>::as_slice),
    );
    bridge_field(&mut bytes, &item.item_digest);
    Ok(domain_digest(BRIDGE_FACT_DOMAIN, &bytes))
}

fn reachability_digest(
    application_id: [u8; 16],
    publication: ObjectRef,
    opaque_key: [u8; 32],
    generation: u64,
    fact_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(160);
    bridge_field(&mut bytes, &application_id);
    bridge_field(&mut bytes, &publication.kind.code().to_be_bytes());
    bridge_field(&mut bytes, &publication.digest);
    bridge_field(&mut bytes, &opaque_key);
    bridge_field(&mut bytes, &generation.to_be_bytes());
    bridge_field(&mut bytes, &fact_digest);
    domain_digest(BRIDGE_REACHABILITY_DOMAIN, &bytes)
}

fn deterministic_uuid(domain: &[u8], binding: &[u8]) -> [u8; 16] {
    let digest = domain_digest(domain, binding);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

fn bridge_field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn bridge_optional_field(bytes: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bridge_field(bytes, value);
        }
        None => bytes.push(0),
    }
}

fn digest32(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn optional_digest32(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    value.map(digest32).transpose()
}

fn denied() -> DomainError {
    DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)
}

fn receipt_numbers_fit_postgres(receipt: &AggregateAuthorizationReceipt) -> bool {
    [
        receipt.credential_generation(),
        receipt.authority_epoch(),
        receipt.security_epoch(),
        receipt.policy_generation(),
        receipt.settings_generation(),
        receipt.signer_key_generation(),
        receipt.issued_at(),
        receipt.expires_at(),
    ]
    .into_iter()
    .all(|value| i64::try_from(value).is_ok())
}

fn valid_consumption_id(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    const BRIDGE_CONTRACT: &str = include_str!("../../contracts/lifecycle-bridge/v1/contract.json");
    const BRIDGE_OPERATION_VECTOR: &str =
        include_str!("../../contracts/lifecycle-bridge/v1/vectors/operation-digest.json");

    fn golden_hex(value: &str, length: usize) -> Vec<u8> {
        assert_eq!(value.len(), length * 2);
        assert!(value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        (0..value.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
            .collect()
    }

    fn golden_unsigned(value: &serde_json::Value, width: usize) -> u64 {
        let integer = value
            .as_u64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
            .expect("golden integer");
        let maximum = match width {
            8 => u64::MAX,
            4 => u64::from(u32::MAX),
            2 => u64::from(u16::MAX),
            _ => panic!("unsupported unsigned width"),
        };
        assert!(integer <= maximum);
        integer
    }

    enum GoldenBridgeOperationField {
        Required(Vec<u8>),
        Optional(Option<Vec<u8>>),
        U64(u64),
        U32(u32),
        U16(u16),
    }

    impl GoldenBridgeOperationField {
        fn as_runtime_field(&self) -> BridgeOperationField<'_> {
            match self {
                Self::Required(value) => BridgeOperationField::Required(value),
                Self::Optional(value) => BridgeOperationField::Optional(value.as_deref()),
                Self::U64(value) => BridgeOperationField::U64(*value),
                Self::U32(value) => BridgeOperationField::U32(*value),
                Self::U16(value) => BridgeOperationField::U16(*value),
            }
        }
    }

    fn golden_operation_fields(
        contract: &serde_json::Value,
        input: &serde_json::Value,
    ) -> Vec<GoldenBridgeOperationField> {
        let mut fields = Vec::new();
        for descriptor in contract["operationDigest"]["orderedFields"]
            .as_array()
            .expect("ordered fields")
        {
            let binding = descriptor["binding"].as_str().expect("binding");
            let mut value = &input[binding];
            if let Some(component) = descriptor
                .get("component")
                .and_then(serde_json::Value::as_str)
            {
                value = &value[match component {
                    "unix-seconds" => "unixSeconds",
                    "nanoseconds" => "nanoseconds",
                    _ => panic!("unknown timestamp component"),
                }];
            }
            let field_type = descriptor["type"].as_str().expect("field type");
            if field_type == "optional-utf8" {
                fields.push(match value.as_str() {
                    Some(text) => {
                        GoldenBridgeOperationField::Optional(Some(text.as_bytes().to_vec()))
                    }
                    None if value.is_null() => GoldenBridgeOperationField::Optional(None),
                    None => panic!("optional field is not string/null"),
                });
                continue;
            }
            let field = match field_type {
                "utf8" => GoldenBridgeOperationField::Required(
                    value.as_str().expect("UTF-8 field").as_bytes().to_vec(),
                ),
                "sha256-raw" => GoldenBridgeOperationField::Required(golden_hex(
                    value.as_str().expect("raw digest"),
                    32,
                )),
                "sha256-hex-utf8" => {
                    let text = value.as_str().expect("hex digest");
                    let _ = golden_hex(text, 32);
                    GoldenBridgeOperationField::Required(text.as_bytes().to_vec())
                }
                "uuid-raw" => {
                    let text = value.as_str().expect("UUID");
                    let parsed = Uuid::parse_str(text).expect("canonical UUID");
                    assert_eq!(parsed.hyphenated().to_string(), text);
                    GoldenBridgeOperationField::Required(parsed.as_bytes().to_vec())
                }
                "u64-be" => GoldenBridgeOperationField::U64(golden_unsigned(value, 8)),
                "u32-be" => GoldenBridgeOperationField::U32(
                    u32::try_from(golden_unsigned(value, 4)).unwrap(),
                ),
                "u16-be" => GoldenBridgeOperationField::U16(
                    u16::try_from(golden_unsigned(value, 2)).unwrap(),
                ),
                _ => panic!("unknown golden field type"),
            };
            fields.push(field);
        }
        fields
    }

    fn golden_operation_digest(
        contract: &serde_json::Value,
        input: &serde_json::Value,
    ) -> [u8; 32] {
        let domain = contract["operationDigest"]["domainUtf8"]
            .as_str()
            .expect("domain");
        assert_eq!(domain.as_bytes(), BRIDGE_OPERATION_DOMAIN);
        let fields = golden_operation_fields(contract, input);
        assert_eq!(fields.len(), 52);
        let runtime_fields = fields
            .iter()
            .map(GoldenBridgeOperationField::as_runtime_field)
            .collect::<Vec<_>>();
        bridge_operation_digest_from_fields(&runtime_fields)
    }

    #[test]
    fn deterministic_ids_are_public_uuids_and_domain_separated() {
        let audit = deterministic_uuid(BRIDGE_AUDIT_ID_DOMAIN, &[7; 32]);
        let outbox = deterministic_uuid(BRIDGE_OUTBOX_ID_DOMAIN, &[7; 32]);
        assert!(valid_public_uuid(&audit));
        assert!(valid_public_uuid(&outbox));
        assert_ne!(audit, outbox);
    }

    #[test]
    fn aggregate_limit_is_exact_without_allocating_the_limit() {
        assert_eq!(MAXIMUM_AGGREGATE_RESOURCES, 100_000);
        assert_eq!(100_000_usize.div_ceil(PLAN_CHUNK_ITEMS_MAXIMUM), 100);
    }

    #[test]
    fn consumption_id_boundary_is_exact_and_ascii_only() {
        assert!(valid_consumption_id("a"));
        assert!(valid_consumption_id(&"a".repeat(256)));
        for invalid in ["", "slash/is-not-valid", "non-ascii-é", &"a".repeat(257)] {
            assert!(!valid_consumption_id(invalid));
        }
    }

    #[test]
    fn language_neutral_operation_digest_golden_vector_recomputes() {
        let contract: serde_json::Value = serde_json::from_str(BRIDGE_CONTRACT).unwrap();
        let vector: serde_json::Value = serde_json::from_str(BRIDGE_OPERATION_VECTOR).unwrap();
        let expected = vector["expectedOperationDigestSha256"]
            .as_str()
            .expect("expected digest");
        let recomputed = golden_operation_digest(&contract, &vector["input"]);
        assert_eq!(hex_bytes(&recomputed), expected);

        let mut tampered = vector["input"].clone();
        tampered["consumption-id"] = serde_json::Value::String("tampered".to_owned());
        assert_ne!(golden_operation_digest(&contract, &tampered), recomputed);
    }
}
