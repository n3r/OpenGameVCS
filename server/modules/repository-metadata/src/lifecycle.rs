// This prerequisite stays private until the OGVCS-008/009/010 coordinators
// supply their authenticated authority handles; default builds intentionally
// have no caller-reachable lifecycle entry point yet.
#![allow(dead_code)]

use crate::{
    DomainError, DomainErrorCode, IdempotencyReservation, ObjectRef, RepositoryId, Result, TenantId,
};
use ogvcs_object_model::ObjectKind;
use sha2::{Digest, Sha256};

pub const LIFECYCLE_CONTRACT_VERSION: &str = "0.1.0-rc.5";
pub const OBJECT_TRANSFER_MANIFEST_SHA256: &str =
    "a9b175b7e24568cc48b6c233238173a6527fcb2926e5e70852dc02f417debdb0";
pub const OBJECT_TRANSFER_ARTIFACT_SET_SHA256: &str =
    "8da6186ae30137fe2f0943568b82a0a1c43e4638e01085d63457f836785ee5d8";
pub const DIRECT_OBJECTS_MAXIMUM: usize = 1_024;
pub const AGGREGATE_OBJECTS_MAXIMUM: u32 = 100_000;
pub const PLAN_CHUNK_ITEMS_MAXIMUM: usize = 1_000;
pub const PLAN_CHUNK_BYTES_MAXIMUM: usize = 1_048_576;
pub const PLAN_ENCODED_BYTES_MAXIMUM: u64 = 104_857_600;
pub const DIRECT_CONTEXT_BYTES_MAXIMUM: usize = 1_048_576;
pub const MAXIMUM_SAFE_GENERATION: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Staged,
    Available,
    Quarantined,
    Deleting,
    Deleted,
}

impl LifecycleState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Available => "available",
            Self::Quarantined => "quarantined",
            Self::Deleting => "deleting",
            Self::Deleted => "deleted",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleHealth {
    NotApplicable,
    Healthy,
    Unhealthy,
}

impl LifecycleHealth {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }

    pub const fn valid_generation(self, generation: Option<u64>) -> bool {
        matches!(self, Self::NotApplicable) == generation.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleCapability {
    SubmitConsumePublication,
    GcAcquireDeleting,
    GcCompleteDeletion,
    TransferReverifyDeleted,
    TransferRecordAvailable,
}

impl LifecycleCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubmitConsumePublication => "submit.consume-publication",
            Self::GcAcquireDeleting => "gc.acquire-deleting",
            Self::GcCompleteDeletion => "gc.complete-deletion",
            Self::TransferReverifyDeleted => "transfer.reverify-deleted",
            Self::TransferRecordAvailable => "transfer.record-available",
        }
    }

    pub const fn operation(self) -> &'static str {
        match self {
            Self::SubmitConsumePublication => "submit.finalize",
            Self::GcAcquireDeleting => "gc.acquire-deleting",
            Self::GcCompleteDeletion => "gc.complete-deletion",
            Self::TransferReverifyDeleted => "transfer.reverify-deleted",
            Self::TransferRecordAvailable => "transfer.record-available",
        }
    }

    pub const fn records_reachability(self) -> bool {
        matches!(self, Self::SubmitConsumePublication)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleReceiptKind {
    BackendDurable,
    ProductionVerification,
    HealthObservation,
    BackendDeletion,
    BackendReopen,
}

impl LifecycleReceiptKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackendDurable => "backend-durable",
            Self::ProductionVerification => "production-verification",
            Self::HealthObservation => "health-observation",
            Self::BackendDeletion => "backend-deletion",
            Self::BackendReopen => "backend-reopen",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReceiptWrite {
    pub receipt_digest: [u8; 32],
    pub kind: LifecycleReceiptKind,
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub expected_state: LifecycleState,
    pub expected_generation: u64,
    pub target_state: LifecycleState,
    pub target_generation: u64,
    pub authority_binding_digest: [u8; 32],
    pub health_result: Option<LifecycleHealth>,
    pub health_generation: Option<u64>,
    pub evidence_digest: [u8; 32],
}

impl LifecycleReceiptWrite {
    pub fn is_valid(&self) -> bool {
        if self.expected_generation == 0
            || self.target_generation == 0
            || self.expected_generation > MAXIMUM_SAFE_GENERATION
            || self.target_generation > MAXIMUM_SAFE_GENERATION
        {
            return false;
        }
        let transition_valid = match self.kind {
            LifecycleReceiptKind::BackendDurable => {
                self.expected_state == LifecycleState::Staged
                    && self.target_state == LifecycleState::Available
                    && self.target_generation == self.expected_generation + 1
                    && self.health_result.is_none()
                    && self.health_generation.is_none()
            }
            LifecycleReceiptKind::ProductionVerification => {
                matches!(
                    self.expected_state,
                    LifecycleState::Staged | LifecycleState::Quarantined
                ) && self.target_state == LifecycleState::Available
                    && self.target_generation == self.expected_generation + 1
                    && self.health_result.is_none()
                    && self.health_generation.is_none()
            }
            LifecycleReceiptKind::HealthObservation => {
                matches!(
                    self.expected_state,
                    LifecycleState::Available | LifecycleState::Quarantined
                ) && self.target_state == self.expected_state
                    && self.target_generation == self.expected_generation
                    && matches!(
                        self.health_result,
                        Some(LifecycleHealth::Healthy | LifecycleHealth::Unhealthy)
                    )
                    && self.health_generation.is_some_and(|generation| {
                        generation > 0 && generation <= MAXIMUM_SAFE_GENERATION
                    })
            }
            LifecycleReceiptKind::BackendDeletion => {
                self.expected_state == LifecycleState::Deleting
                    && self.target_state == LifecycleState::Deleted
                    && self.target_generation == self.expected_generation + 1
                    && self.health_result.is_none()
                    && self.health_generation.is_none()
            }
            LifecycleReceiptKind::BackendReopen => {
                self.expected_state == LifecycleState::Deleted
                    && self.target_state == LifecycleState::Staged
                    && self.target_generation == self.expected_generation + 1
                    && self.health_result.is_none()
                    && self.health_generation.is_none()
            }
        };
        transition_valid && self.evidence_digest == self.binding_digest()
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        field(&mut bytes, &self.receipt_digest);
        field(&mut bytes, self.kind.as_str().as_bytes());
        field(&mut bytes, self.tenant_id.as_bytes());
        field(&mut bytes, self.repository_id.as_bytes());
        field(&mut bytes, &self.opaque_key);
        object_field(&mut bytes, self.object_ref);
        field(&mut bytes, self.expected_state.as_str().as_bytes());
        field(&mut bytes, &self.expected_generation.to_be_bytes());
        field(&mut bytes, self.target_state.as_str().as_bytes());
        field(&mut bytes, &self.target_generation.to_be_bytes());
        field(&mut bytes, &self.authority_binding_digest);
        match self.health_result {
            Some(health) => {
                bytes.push(1);
                field(&mut bytes, health.as_str().as_bytes());
            }
            None => bytes.push(0),
        }
        optional_u64_field(&mut bytes, self.health_generation);
        domain_digest(b"OGVCS-LIFECYCLE-PERSISTED-RECEIPT-V1", &bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedLifecycleObject {
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub object_length: u64,
    pub tenant_scope_digest: [u8; 32],
    pub authority_binding_digest: [u8; 32],
    pub retention_until: std::time::SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleHealthObservation {
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub expected_state: LifecycleState,
    pub expected_generation: u64,
    pub expected_health: LifecycleHealth,
    pub expected_health_generation: Option<u64>,
    pub expected_health_observation_digest: Option<[u8; 32]>,
    pub next_health: LifecycleHealth,
    pub next_health_generation: u64,
    pub authority_binding_digest: [u8; 32],
    pub observation_receipt_digest: [u8; 32],
}

impl LifecycleHealthObservation {
    pub fn is_valid(&self) -> bool {
        matches!(
            self.expected_state,
            LifecycleState::Available | LifecycleState::Quarantined
        ) && self.expected_generation > 0
            && self.expected_generation <= MAXIMUM_SAFE_GENERATION
            && self
                .expected_health
                .valid_generation(self.expected_health_generation)
            && (self.expected_health == LifecycleHealth::NotApplicable)
                == self.expected_health_observation_digest.is_none()
            && matches!(
                self.next_health,
                LifecycleHealth::Healthy | LifecycleHealth::Unhealthy
            )
            && self.next_health_generation > 0
            && self.next_health_generation <= MAXIMUM_SAFE_GENERATION
            && self.next_health_generation
                == self
                    .expected_health_generation
                    .unwrap_or(0)
                    .saturating_add(1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleQuarantineRequest {
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub expected_generation: u64,
    pub expected_health: LifecycleHealth,
    pub expected_health_generation: Option<u64>,
    pub current_health_observation_digest: Option<[u8; 32]>,
    pub authority_binding_digest: [u8; 32],
    pub root_proof_digest: [u8; 32],
    pub retention_until: std::time::SystemTime,
}

impl LifecycleQuarantineRequest {
    pub fn is_valid(&self) -> bool {
        self.expected_generation > 0
            && self.expected_generation < MAXIMUM_SAFE_GENERATION
            && self
                .expected_health
                .valid_generation(self.expected_health_generation)
            && (self.expected_health == LifecycleHealth::NotApplicable)
                == self.current_health_observation_digest.is_none()
            && self
                .retention_until
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .is_ok()
    }
}

impl StagedLifecycleObject {
    pub fn is_valid(&self) -> bool {
        self.object_length <= 67_108_864
            && self
                .retention_until
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleObjectBinding {
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub expected_state: LifecycleState,
    pub expected_generation: u64,
    pub expected_health: LifecycleHealth,
    pub expected_health_generation: Option<u64>,
    pub current_health_observation_digest: Option<[u8; 32]>,
    pub authority_binding_digest: [u8; 32],
    pub current_backend_receipt_digest: Option<[u8; 32]>,
    pub current_verification_receipt_digest: Option<[u8; 32]>,
    pub current_deletion_receipt_digest: Option<[u8; 32]>,
    pub transition_backend_receipt_digest: Option<[u8; 32]>,
    pub transition_verification_receipt_digest: Option<[u8; 32]>,
    pub transition_deletion_receipt_digest: Option<[u8; 32]>,
    pub resource_opaque_digest: [u8; 32],
}

impl LifecycleObjectBinding {
    fn valid_for(&self, capability: LifecycleCapability) -> bool {
        if self.expected_generation == 0
            || self.expected_generation > MAXIMUM_SAFE_GENERATION
            || !self
                .expected_health
                .valid_generation(self.expected_health_generation)
            || (self.expected_health == LifecycleHealth::NotApplicable)
                != self.current_health_observation_digest.is_none()
            || (self.object_ref.kind == ObjectKind::ContentManifest
                && self.expected_state != LifecycleState::Staged
                && self.current_verification_receipt_digest.is_none())
        {
            return false;
        }
        match capability {
            LifecycleCapability::SubmitConsumePublication => {
                matches!(
                    self.expected_state,
                    LifecycleState::Available | LifecycleState::Quarantined
                ) && self.expected_health == LifecycleHealth::Healthy
                    && self.current_backend_receipt_digest.is_some()
                    && self.current_deletion_receipt_digest.is_none()
                    && self.transition_backend_receipt_digest.is_none()
                    && self.transition_deletion_receipt_digest.is_none()
                    && (self.expected_state == LifecycleState::Quarantined)
                        == self.transition_verification_receipt_digest.is_some()
            }
            LifecycleCapability::GcAcquireDeleting => {
                self.expected_state == LifecycleState::Quarantined
                    && matches!(
                        self.expected_health,
                        LifecycleHealth::Healthy | LifecycleHealth::Unhealthy
                    )
                    && self.current_backend_receipt_digest.is_some()
                    && self.current_deletion_receipt_digest.is_none()
                    && self.transition_backend_receipt_digest.is_none()
                    && self.transition_verification_receipt_digest.is_none()
                    && self.transition_deletion_receipt_digest.is_none()
            }
            LifecycleCapability::GcCompleteDeletion => {
                self.expected_state == LifecycleState::Deleting
                    && self.expected_health == LifecycleHealth::NotApplicable
                    && self.current_backend_receipt_digest.is_some()
                    && self.current_deletion_receipt_digest.is_none()
                    && self.transition_backend_receipt_digest.is_none()
                    && self.transition_verification_receipt_digest.is_none()
                    && self.transition_deletion_receipt_digest.is_some()
            }
            LifecycleCapability::TransferReverifyDeleted => {
                self.expected_state == LifecycleState::Deleted
                    && self.expected_health == LifecycleHealth::NotApplicable
                    && self.current_backend_receipt_digest.is_some()
                    && self.current_deletion_receipt_digest.is_some()
                    && self.transition_backend_receipt_digest.is_none()
                    && self.transition_verification_receipt_digest.is_some()
                    && self.transition_deletion_receipt_digest.is_none()
            }
            LifecycleCapability::TransferRecordAvailable => {
                self.expected_state == LifecycleState::Staged
                    && self.expected_health == LifecycleHealth::NotApplicable
                    && self.current_backend_receipt_digest.is_none()
                    && self.current_verification_receipt_digest.is_none()
                    && self.current_deletion_receipt_digest.is_none()
                    && self.transition_backend_receipt_digest.is_some()
                    && self.transition_deletion_receipt_digest.is_none()
                    && (self.object_ref.kind == ObjectKind::ContentManifest)
                        == self.transition_verification_receipt_digest.is_some()
            }
        }
    }

    pub(crate) fn encoded(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(288);
        field(&mut bytes, &self.opaque_key);
        object_field(&mut bytes, self.object_ref);
        field(&mut bytes, self.expected_state.as_str().as_bytes());
        field(&mut bytes, &self.expected_generation.to_be_bytes());
        field(&mut bytes, self.expected_health.as_str().as_bytes());
        optional_u64_field(&mut bytes, self.expected_health_generation);
        optional_digest_field(&mut bytes, self.current_health_observation_digest);
        field(&mut bytes, &self.authority_binding_digest);
        optional_digest_field(&mut bytes, self.current_backend_receipt_digest);
        optional_digest_field(&mut bytes, self.current_verification_receipt_digest);
        optional_digest_field(&mut bytes, self.current_deletion_receipt_digest);
        optional_digest_field(&mut bytes, self.transition_backend_receipt_digest);
        optional_digest_field(&mut bytes, self.transition_verification_receipt_digest);
        optional_digest_field(&mut bytes, self.transition_deletion_receipt_digest);
        field(&mut bytes, &self.resource_opaque_digest);
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleDirectCommand {
    pub transaction_id: String,
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub subject_digest: [u8; 32],
    pub authorization_epoch: u64,
    pub capability: LifecycleCapability,
    pub authority_contract_digest: [u8; 32],
    pub publication_ref: Option<ObjectRef>,
    pub root_proof_digest: Option<[u8; 32]>,
    pub idempotency_scope_digest: [u8; 32],
    pub idempotency: IdempotencyReservation,
    pub objects: Vec<LifecycleObjectBinding>,
    pub context_digest: [u8; 32],
    pub lifecycle_plan_digest: [u8; 32],
    structural_commitment_digest: [u8; 32],
}

impl LifecycleDirectCommand {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        transaction_id: String,
        tenant_id: TenantId,
        repository_id: RepositoryId,
        subject_digest: [u8; 32],
        authorization_epoch: u64,
        capability: LifecycleCapability,
        authority_contract_digest: [u8; 32],
        publication_ref: Option<ObjectRef>,
        root_proof_digest: Option<[u8; 32]>,
        idempotency_scope_digest: [u8; 32],
        idempotency: IdempotencyReservation,
        objects: Vec<LifecycleObjectBinding>,
    ) -> Result<Self> {
        if !valid_transaction_id(&transaction_id)
            || authorization_epoch == 0
            || authorization_epoch > MAXIMUM_SAFE_GENERATION
            || objects.is_empty()
            || objects.len() > DIRECT_OBJECTS_MAXIMUM
            || !idempotency.is_valid()
            || idempotency.operation != capability.operation()
            || (capability.records_reachability() != publication_ref.is_some())
            || (matches!(
                capability,
                LifecycleCapability::GcAcquireDeleting | LifecycleCapability::GcCompleteDeletion
            ) != root_proof_digest.is_some())
            || objects.iter().any(|object| !object.valid_for(capability))
            || objects
                .windows(2)
                .any(|pair| pair[0].opaque_key >= pair[1].opaque_key)
        {
            return invalid();
        }
        let mut command = Self {
            transaction_id,
            tenant_id,
            repository_id,
            subject_digest,
            authorization_epoch,
            capability,
            authority_contract_digest,
            publication_ref,
            root_proof_digest,
            idempotency_scope_digest,
            idempotency,
            objects,
            context_digest: [0; 32],
            lifecycle_plan_digest: [0; 32],
            structural_commitment_digest: [0; 32],
        };
        let encoded = command.encoded(false);
        if encoded.len() > DIRECT_CONTEXT_BYTES_MAXIMUM {
            return invalid();
        }
        command.context_digest = domain_digest(b"OGVCS-LIFECYCLE-DIRECT-CONTEXT-V1", &encoded);
        command.lifecycle_plan_digest = domain_digest(b"OGVCS-LIFECYCLE-DIRECT-PLAN-V1", &encoded);
        let mut sealed = Vec::with_capacity(64);
        sealed.extend_from_slice(&command.context_digest);
        sealed.extend_from_slice(&command.lifecycle_plan_digest);
        sealed.extend_from_slice(&idempotency_scope_digest);
        command.structural_commitment_digest =
            domain_digest(b"OGVCS-LIFECYCLE-DIRECT-STRUCTURAL-COMMITMENT-V1", &sealed);
        Ok(command)
    }

    fn encoded(&self, include_digests: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        field(&mut bytes, OBJECT_TRANSFER_MANIFEST_SHA256.as_bytes());
        field(&mut bytes, self.transaction_id.as_bytes());
        field(&mut bytes, self.tenant_id.as_bytes());
        field(&mut bytes, self.repository_id.as_bytes());
        field(&mut bytes, &self.subject_digest);
        field(&mut bytes, &self.authorization_epoch.to_be_bytes());
        field(&mut bytes, self.capability.as_str().as_bytes());
        field(&mut bytes, &self.authority_contract_digest);
        optional_object_field(&mut bytes, self.publication_ref);
        optional_digest_field(&mut bytes, self.root_proof_digest);
        field(&mut bytes, &self.idempotency_scope_digest);
        field(&mut bytes, self.idempotency.operation.as_bytes());
        field(&mut bytes, self.idempotency.key.as_bytes());
        field(&mut bytes, &self.idempotency.semantic_fingerprint);
        field(&mut bytes, &(self.objects.len() as u64).to_be_bytes());
        for object in &self.objects {
            field(&mut bytes, &object.encoded());
        }
        if include_digests {
            field(&mut bytes, &self.context_digest);
            field(&mut bytes, &self.lifecycle_plan_digest);
            field(&mut bytes, &self.structural_commitment_digest);
        }
        bytes
    }

    pub(crate) fn integrity_valid(&self) -> bool {
        let encoded = self.encoded(false);
        encoded.len() <= DIRECT_CONTEXT_BYTES_MAXIMUM
            && self.context_digest == domain_digest(b"OGVCS-LIFECYCLE-DIRECT-CONTEXT-V1", &encoded)
            && self.lifecycle_plan_digest
                == domain_digest(b"OGVCS-LIFECYCLE-DIRECT-PLAN-V1", &encoded)
            && self.structural_commitment_digest
                == domain_digest(
                    b"OGVCS-LIFECYCLE-DIRECT-STRUCTURAL-COMMITMENT-V1",
                    &[
                        self.context_digest.as_slice(),
                        self.lifecycle_plan_digest.as_slice(),
                        self.idempotency_scope_digest.as_slice(),
                    ]
                    .concat(),
                )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatePublicationPlan {
    pub plan_id: [u8; 16],
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub publication_ref: ObjectRef,
    pub subject_digest: [u8; 32],
    pub authorization_epoch: u64,
    pub authority_contract_digest: [u8; 32],
    pub candidate_digest: [u8; 32],
    pub declared_plan_digest: [u8; 32],
    pub idempotency_scope_digest: [u8; 32],
    pub idempotency: IdempotencyReservation,
    pub declared_object_count: u32,
    pub declared_chunk_count: u16,
    pub declared_encoded_bytes: u64,
    pub(crate) structural_commitment_digest: [u8; 32],
}

impl AggregatePublicationPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: [u8; 16],
        tenant_id: TenantId,
        repository_id: RepositoryId,
        publication_ref: ObjectRef,
        subject_digest: [u8; 32],
        authorization_epoch: u64,
        authority_contract_digest: [u8; 32],
        candidate_digest: [u8; 32],
        declared_plan_digest: [u8; 32],
        idempotency_scope_digest: [u8; 32],
        idempotency: IdempotencyReservation,
        declared_object_count: u32,
        declared_encoded_bytes: u64,
    ) -> Result<Self> {
        let chunk_count = aggregate_chunk_count(declared_object_count)
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if !valid_public_uuid(&plan_id)
            || authorization_epoch == 0
            || authorization_epoch > MAXIMUM_SAFE_GENERATION
            || declared_encoded_bytes == 0
            || declared_encoded_bytes > PLAN_ENCODED_BYTES_MAXIMUM
            || !idempotency.is_valid()
            || idempotency.operation != LifecycleCapability::SubmitConsumePublication.operation()
        {
            return invalid();
        }
        let mut plan = Self {
            plan_id,
            tenant_id,
            repository_id,
            publication_ref,
            subject_digest,
            authorization_epoch,
            authority_contract_digest,
            candidate_digest,
            declared_plan_digest,
            idempotency_scope_digest,
            idempotency,
            declared_object_count,
            declared_chunk_count: chunk_count,
            declared_encoded_bytes,
            structural_commitment_digest: [0; 32],
        };
        plan.structural_commitment_digest = domain_digest(
            b"OGVCS-LIFECYCLE-AGGREGATE-STRUCTURAL-COMMITMENT-V1",
            &plan.structural_commitment_payload(),
        );
        Ok(plan)
    }

    pub(crate) fn digest_prefix(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        field(&mut bytes, OBJECT_TRANSFER_MANIFEST_SHA256.as_bytes());
        field(&mut bytes, &self.plan_id);
        field(&mut bytes, self.tenant_id.as_bytes());
        field(&mut bytes, self.repository_id.as_bytes());
        object_field(&mut bytes, self.publication_ref);
        field(&mut bytes, &self.subject_digest);
        field(&mut bytes, &self.authorization_epoch.to_be_bytes());
        field(&mut bytes, &self.authority_contract_digest);
        field(&mut bytes, &self.candidate_digest);
        field(&mut bytes, &self.idempotency_scope_digest);
        field(&mut bytes, self.idempotency.operation.as_bytes());
        field(&mut bytes, self.idempotency.key.as_bytes());
        field(&mut bytes, &self.idempotency.semantic_fingerprint);
        field(
            &mut bytes,
            &u64::from(self.declared_object_count).to_be_bytes(),
        );
        field(
            &mut bytes,
            &u64::from(self.declared_chunk_count).to_be_bytes(),
        );
        field(&mut bytes, &self.declared_encoded_bytes.to_be_bytes());
        bytes
    }

    pub(crate) fn structural_commitment_valid(&self) -> bool {
        self.structural_commitment_digest
            == domain_digest(
                b"OGVCS-LIFECYCLE-AGGREGATE-STRUCTURAL-COMMITMENT-V1",
                &self.structural_commitment_payload(),
            )
    }

    fn structural_commitment_payload(&self) -> Vec<u8> {
        let mut bytes = self.digest_prefix();
        field(&mut bytes, &self.declared_plan_digest);
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregatePlanChunk {
    pub plan_id: [u8; 16],
    pub chunk_ordinal: u16,
    pub first_item_ordinal: u32,
    pub encoded_bytes: u32,
    pub encoded_payload: Vec<u8>,
    pub chunk_digest: [u8; 32],
    pub items: Vec<LifecycleObjectBinding>,
}

impl AggregatePlanChunk {
    pub fn new(
        plan_id: [u8; 16],
        chunk_ordinal: u16,
        items: Vec<LifecycleObjectBinding>,
    ) -> Result<Self> {
        if !valid_public_uuid(&plan_id)
            || chunk_ordinal >= 100
            || items.is_empty()
            || items.len() > PLAN_CHUNK_ITEMS_MAXIMUM
            || items
                .iter()
                .any(|item| !item.valid_for(LifecycleCapability::SubmitConsumePublication))
            || items
                .windows(2)
                .any(|pair| pair[0].opaque_key >= pair[1].opaque_key)
        {
            return invalid();
        }
        let first_item_ordinal = u32::from(chunk_ordinal) * 1_000;
        let mut encoded = Vec::new();
        field(&mut encoded, &plan_id);
        field(&mut encoded, &u64::from(chunk_ordinal).to_be_bytes());
        for (index, item) in items.iter().enumerate() {
            field(
                &mut encoded,
                &u64::from(first_item_ordinal + index as u32).to_be_bytes(),
            );
            field(&mut encoded, &item.encoded());
        }
        if encoded.is_empty() || encoded.len() > PLAN_CHUNK_BYTES_MAXIMUM {
            return invalid();
        }
        Ok(Self {
            plan_id,
            chunk_ordinal,
            first_item_ordinal,
            encoded_bytes: encoded.len() as u32,
            chunk_digest: domain_digest(b"OGVCS-LIFECYCLE-PLAN-CHUNK-V1", &encoded),
            encoded_payload: encoded,
            items,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateChunkCommitment {
    pub chunk_ordinal: u16,
    pub item_count: u16,
    pub encoded_bytes: u32,
    pub chunk_digest: [u8; 32],
}

pub fn aggregate_plan_digest(
    plan: &AggregatePublicationPlan,
    chunks: &[AggregateChunkCommitment],
) -> Result<[u8; 32]> {
    if chunks.len() != usize::from(plan.declared_chunk_count)
        || chunks.iter().enumerate().any(|(index, chunk)| {
            usize::from(chunk.chunk_ordinal) != index
                || chunk.item_count == 0
                || usize::from(chunk.item_count) > PLAN_CHUNK_ITEMS_MAXIMUM
                || chunk.encoded_bytes == 0
                || chunk.encoded_bytes as usize > PLAN_CHUNK_BYTES_MAXIMUM
                || (index + 1 < chunks.len()
                    && usize::from(chunk.item_count) != PLAN_CHUNK_ITEMS_MAXIMUM)
        })
    {
        return invalid();
    }
    let count: u64 = chunks.iter().map(|chunk| u64::from(chunk.item_count)).sum();
    let bytes: u64 = chunks
        .iter()
        .map(|chunk| u64::from(chunk.encoded_bytes))
        .sum();
    if count != u64::from(plan.declared_object_count) || bytes != plan.declared_encoded_bytes {
        return invalid();
    }
    let mut encoded = plan.digest_prefix();
    for chunk in chunks {
        field(&mut encoded, &u64::from(chunk.chunk_ordinal).to_be_bytes());
        field(&mut encoded, &u64::from(chunk.item_count).to_be_bytes());
        field(&mut encoded, &u64::from(chunk.encoded_bytes).to_be_bytes());
        field(&mut encoded, &chunk.chunk_digest);
    }
    Ok(domain_digest(
        b"OGVCS-LIFECYCLE-AGGREGATE-PLAN-V1",
        &encoded,
    ))
}

pub const fn aggregate_chunk_count(object_count: u32) -> Option<u16> {
    if object_count == 0 || object_count > AGGREGATE_OBJECTS_MAXIMUM {
        None
    } else {
        Some(((object_count + 999) / 1_000) as u16)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleApplicationReceipt {
    pub application_id: [u8; 16],
    pub receipt_digest: [u8; 32],
    pub commit_sequence: u64,
    pub object_count: u32,
    pub protected_result_digest: [u8; 32],
}

pub(crate) fn lifecycle_contract_digest() -> [u8; 32] {
    hex32(OBJECT_TRANSFER_MANIFEST_SHA256).expect("pinned manifest digest is valid")
}

pub(crate) fn protected_fact_digest(
    command: &LifecycleDirectCommand,
    object: &LifecycleObjectBinding,
    next_state: LifecycleState,
    next_generation: u64,
    receipt_digest: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    field(&mut bytes, command.transaction_id.as_bytes());
    field(&mut bytes, command.capability.as_str().as_bytes());
    field(&mut bytes, command.tenant_id.as_bytes());
    field(&mut bytes, command.repository_id.as_bytes());
    field(&mut bytes, &command.authorization_epoch.to_be_bytes());
    field(&mut bytes, &object.resource_opaque_digest);
    field(&mut bytes, object.expected_state.as_str().as_bytes());
    field(&mut bytes, &object.expected_generation.to_be_bytes());
    field(&mut bytes, next_state.as_str().as_bytes());
    field(&mut bytes, &next_generation.to_be_bytes());
    optional_digest_field(&mut bytes, receipt_digest);
    domain_digest(b"OGVCS-LIFECYCLE-TRANSACTION-FACT-V1", &bytes)
}

pub(crate) fn application_receipt_digest(
    application_id: [u8; 16],
    repository_id: RepositoryId,
    commit_sequence: u64,
    capability: LifecycleCapability,
    plan_digest: [u8; 32],
    object_count: u32,
    protected_result_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    field(&mut bytes, &application_id);
    field(&mut bytes, repository_id.as_bytes());
    field(&mut bytes, &commit_sequence.to_be_bytes());
    field(&mut bytes, capability.as_str().as_bytes());
    field(&mut bytes, &plan_digest);
    field(&mut bytes, &u64::from(object_count).to_be_bytes());
    field(&mut bytes, &protected_result_digest);
    domain_digest(b"OGVCS-LIFECYCLE-APPLICATION-RECEIPT-V1", &bytes)
}

pub(crate) fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(bytes);
    digest.finalize().into()
}

fn optional_digest_field(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            field(bytes, &value);
        }
        None => bytes.push(0),
    }
}

fn optional_u64_field(bytes: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            bytes.push(1);
            field(bytes, &value.to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn optional_object_field(bytes: &mut Vec<u8>, value: Option<ObjectRef>) {
    match value {
        Some(value) => {
            bytes.push(1);
            object_field(bytes, value);
        }
        None => bytes.push(0),
    }
}

fn object_field(bytes: &mut Vec<u8>, value: ObjectRef) {
    field(bytes, &value.kind.code().to_be_bytes());
    field(bytes, &value.digest);
}

fn field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn valid_transaction_id(value: &str) -> bool {
    value.strip_prefix("ltx1.").is_some_and(|payload| {
        payload.len() == 43
            && payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    })
}

fn valid_public_uuid(value: &[u8; 16]) -> bool {
    matches!(value[6] >> 4, 1..=8) && value[8] & 0xc0 == 0x80
}

fn hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut result = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        result[index] = high << 4 | low;
    }
    Some(result)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn invalid<T>() -> Result<T> {
    Err(DomainError::new(DomainErrorCode::ObjectInvalid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn reservation(operation: &str) -> IdempotencyReservation {
        let issued_at = SystemTime::now() - Duration::from_secs(1);
        let expires_at = issued_at + Duration::from_secs(60);
        let issued_ms = issued_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let expires_ms = expires_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        IdempotencyReservation {
            operation: operation.to_owned(),
            key: format!("ik1.{issued_ms}.{expires_ms}.{}", "A".repeat(22)),
            semantic_fingerprint: [7; 32],
            issued_at,
            expires_at,
        }
    }

    fn object(key: u8) -> LifecycleObjectBinding {
        LifecycleObjectBinding {
            opaque_key: [key; 32],
            object_ref: ObjectRef {
                kind: ObjectKind::Chunk,
                digest: [key; 32],
            },
            expected_state: LifecycleState::Available,
            expected_generation: 2,
            expected_health: LifecycleHealth::Healthy,
            expected_health_generation: Some(1),
            current_health_observation_digest: Some([2; 32]),
            authority_binding_digest: [3; 32],
            current_backend_receipt_digest: Some([4; 32]),
            current_verification_receipt_digest: None,
            current_deletion_receipt_digest: None,
            transition_backend_receipt_digest: None,
            transition_verification_receipt_digest: None,
            transition_deletion_receipt_digest: None,
            resource_opaque_digest: [5; 32],
        }
    }

    #[test]
    fn direct_bounds_and_sorting_are_closed() {
        let args = |objects| {
            LifecycleDirectCommand::seal(
                format!("ltx1.{}", "A".repeat(43)),
                TenantId::from_bytes([1; 16]),
                RepositoryId::from_bytes([2; 16]),
                [3; 32],
                1,
                LifecycleCapability::SubmitConsumePublication,
                [4; 32],
                Some(ObjectRef {
                    kind: ObjectKind::Snapshot,
                    digest: [5; 32],
                }),
                None,
                [6; 32],
                reservation("submit.finalize"),
                objects,
            )
        };
        assert!(args(Vec::new()).is_err());
        assert!(args(vec![object(1)]).is_ok());
        let exact_maximum = (0_u32..1_024)
            .map(|index| {
                let mut value = object(1);
                value.opaque_key = [0; 32];
                value.opaque_key[28..].copy_from_slice(&index.to_be_bytes());
                value.object_ref.digest = value.opaque_key;
                value
            })
            .collect();
        assert!(args(exact_maximum).is_ok());
        assert!(
            args(
                (0..=255)
                    .cycle()
                    .take(1_024)
                    .enumerate()
                    .map(|(index, _)| {
                        let mut value = object(1);
                        value.opaque_key = domain_digest(b"key", &index.to_be_bytes());
                        value
                    })
                    .collect::<Vec<_>>()
            )
            .is_err(),
            "unsorted input is rejected"
        );
        assert!(args(vec![object(1); 1_025]).is_err());
    }

    #[test]
    fn aggregate_declared_boundaries_are_exact_without_scale_allocation() {
        assert_eq!(aggregate_chunk_count(99_999), Some(100));
        assert_eq!(aggregate_chunk_count(100_000), Some(100));
        assert_eq!(aggregate_chunk_count(100_001), None);
        assert_eq!(aggregate_chunk_count(0), None);
    }

    #[test]
    fn aggregate_chunks_reject_order_ordinal_count_and_payload_tamper() {
        let plan_id = [0x10, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
        let first = object(1);
        let second = object(2);
        assert!(AggregatePlanChunk::new(plan_id, 0, vec![first.clone(), second.clone()]).is_ok());
        assert!(AggregatePlanChunk::new(plan_id, 0, vec![second, first.clone()]).is_err());
        assert!(AggregatePlanChunk::new(plan_id, 0, vec![first.clone(), first]).is_err());
        assert!(AggregatePlanChunk::new(plan_id, 100, vec![object(1)]).is_err());

        let too_many = (0_u32..1_001)
            .map(|index| {
                let mut item = object(1);
                item.opaque_key = [0; 32];
                item.opaque_key[28..].copy_from_slice(&index.to_be_bytes());
                item.object_ref.digest = item.opaque_key;
                item
            })
            .collect();
        assert!(AggregatePlanChunk::new(plan_id, 0, too_many).is_err());

        let canonical = AggregatePlanChunk::new(plan_id, 0, vec![object(1)]).unwrap();
        let mut tampered = canonical.clone();
        tampered.encoded_payload[0] ^= 1;
        assert_ne!(canonical, tampered);
        let mut substituted = canonical.clone();
        substituted.items[0].resource_opaque_digest[0] ^= 1;
        assert_ne!(
            AggregatePlanChunk::new(plan_id, 0, substituted.items.clone()).unwrap(),
            substituted
        );
    }

    #[test]
    fn aggregate_plan_commitments_enforce_exact_ordinals_counts_and_bytes() {
        let plan_id = [0x10, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 3];
        let items = (0_u32..1_001)
            .map(|index| {
                let mut item = object(1);
                item.opaque_key = [0; 32];
                item.opaque_key[28..].copy_from_slice(&index.to_be_bytes());
                item.object_ref.digest = item.opaque_key;
                item
            })
            .collect::<Vec<_>>();
        let first = AggregatePlanChunk::new(plan_id, 0, items[..1_000].to_vec()).unwrap();
        let second = AggregatePlanChunk::new(plan_id, 1, items[1_000..].to_vec()).unwrap();
        let encoded_bytes = u64::from(first.encoded_bytes) + u64::from(second.encoded_bytes);
        let plan = AggregatePublicationPlan::new(
            plan_id,
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            ObjectRef {
                kind: ObjectKind::Snapshot,
                digest: [3; 32],
            },
            [4; 32],
            1,
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            reservation("submit.finalize"),
            1_001,
            encoded_bytes,
        )
        .unwrap();
        let commitments = [
            AggregateChunkCommitment {
                chunk_ordinal: 0,
                item_count: 1_000,
                encoded_bytes: first.encoded_bytes,
                chunk_digest: first.chunk_digest,
            },
            AggregateChunkCommitment {
                chunk_ordinal: 1,
                item_count: 1,
                encoded_bytes: second.encoded_bytes,
                chunk_digest: second.chunk_digest,
            },
        ];
        assert!(aggregate_plan_digest(&plan, &commitments).is_ok());
        let mut wrong_ordinal = commitments;
        wrong_ordinal[1].chunk_ordinal = 2;
        assert!(aggregate_plan_digest(&plan, &wrong_ordinal).is_err());
        let mut wrong_non_final_count = commitments;
        wrong_non_final_count[0].item_count = 999;
        assert!(aggregate_plan_digest(&plan, &wrong_non_final_count).is_err());
        let mut wrong_bytes = commitments;
        wrong_bytes[1].encoded_bytes += 1;
        assert!(aggregate_plan_digest(&plan, &wrong_bytes).is_err());
    }

    #[test]
    fn corrected_health_axis_allows_available_without_an_observation() {
        assert!(LifecycleHealth::NotApplicable.valid_generation(None));
        assert!(LifecycleHealth::Healthy.valid_generation(Some(1)));
        assert!(LifecycleHealth::Unhealthy.valid_generation(Some(9)));
        assert!(!LifecycleHealth::NotApplicable.valid_generation(Some(1)));
        assert!(!LifecycleHealth::Healthy.valid_generation(None));
    }

    #[test]
    fn health_observation_cas_binds_the_exact_prior_observation() {
        let mut observation = LifecycleHealthObservation {
            tenant_id: TenantId::from_bytes([1; 16]),
            repository_id: RepositoryId::from_bytes([2; 16]),
            opaque_key: [3; 32],
            object_ref: ObjectRef {
                kind: ObjectKind::Chunk,
                digest: [4; 32],
            },
            expected_state: LifecycleState::Available,
            expected_generation: 2,
            expected_health: LifecycleHealth::Healthy,
            expected_health_generation: Some(1),
            expected_health_observation_digest: None,
            next_health: LifecycleHealth::Unhealthy,
            next_health_generation: 2,
            authority_binding_digest: [5; 32],
            observation_receipt_digest: [6; 32],
        };
        assert!(!observation.is_valid());
        observation.expected_health_observation_digest = Some([7; 32]);
        assert!(observation.is_valid());
    }

    #[test]
    fn gc_accepts_exact_unhealthy_quarantine_but_submit_does_not() {
        let mut quarantined = object(1);
        quarantined.expected_state = LifecycleState::Quarantined;
        quarantined.expected_health = LifecycleHealth::Unhealthy;
        quarantined.expected_health_generation = Some(2);
        quarantined.current_health_observation_digest = Some([9; 32]);
        assert!(LifecycleDirectCommand::seal(
            format!("ltx1.{}", "B".repeat(43)),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            [3; 32],
            1,
            LifecycleCapability::GcAcquireDeleting,
            [4; 32],
            None,
            Some([5; 32]),
            [6; 32],
            reservation("gc.acquire-deleting"),
            vec![quarantined.clone()],
        )
        .is_ok());
        assert!(LifecycleDirectCommand::seal(
            format!("ltx1.{}", "C".repeat(43)),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            [3; 32],
            1,
            LifecycleCapability::SubmitConsumePublication,
            [4; 32],
            Some(ObjectRef {
                kind: ObjectKind::Snapshot,
                digest: [5; 32],
            }),
            None,
            [6; 32],
            reservation("submit.finalize"),
            vec![quarantined],
        )
        .is_err());
    }

    #[test]
    fn aggregate_structural_commitment_binds_declared_plan_digest() {
        let mut plan = AggregatePublicationPlan::new(
            [0x10, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1],
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
            ObjectRef {
                kind: ObjectKind::Snapshot,
                digest: [3; 32],
            },
            [4; 32],
            1,
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            reservation("submit.finalize"),
            1,
            512,
        )
        .unwrap();
        assert!(plan.structural_commitment_valid());
        plan.declared_plan_digest[0] ^= 1;
        assert!(!plan.structural_commitment_valid());
    }

    #[test]
    fn pinned_transfer_manifest_digest_is_exact() {
        assert_eq!(
            hex32(OBJECT_TRANSFER_MANIFEST_SHA256).unwrap(),
            lifecycle_contract_digest()
        );
        assert_eq!(OBJECT_TRANSFER_ARTIFACT_SET_SHA256.len(), 64);
    }
}
