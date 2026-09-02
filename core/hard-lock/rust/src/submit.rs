use std::collections::{BTreeMap, BTreeSet};

use ogvcs_object_model::{ObjectKind, ObjectRef};

use crate::digest::{Digest, DigestBuilder};
use crate::target::{
    bounded_target_input_work, digest_target_input, normalize_target, NormalizedTarget,
};
use crate::{
    ClaimProof, LockModel, PermissionAssignment, ScopeBinding, SubjectId, SuppliedDecision,
    SuppliedPermissionFact, TransitionControl, WorkspaceId, WORK_UNITS_HARD_MAXIMUM,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitPlanBinding {
    pub intent_id: [u8; 16],
    pub expected_head: ObjectRef,
    pub candidate_snapshot: ObjectRef,
    pub operation_set_digest: Digest,
    pub lifecycle_plan_digest: Digest,
    pub identity_plan_digest: Digest,
    pub identity_decision_digest: Digest,
    pub identity_resource_projection_digest: Digest,
    pub authenticated_scope_digest: Digest,
    pub subject_digest: Digest,
    pub authority_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitChangeFact {
    pub target: crate::TargetInput,
    /// An opaque, caller-supplied policy fact. This crate does not decide
    /// whether a target requires a lock.
    pub supplied_requires_hard_lock: bool,
    pub requirement_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitValidationRequest {
    pub scope: ScopeBinding,
    pub authority_epoch: u64,
    pub subject: SubjectId,
    pub workspace: WorkspaceId,
    pub permission: SuppliedPermissionFact,
    pub plan: SubmitPlanBinding,
    pub changes: Vec<SubmitChangeFact>,
    pub presented_proofs: Vec<ClaimProof>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitValidationControl {
    pub cancelled: bool,
    pub maximum_work_units: u64,
}

impl Default for SubmitValidationControl {
    fn default() -> Self {
        Self {
            cancelled: false,
            maximum_work_units: WORK_UNITS_HARD_MAXIMUM,
        }
    }
}

impl From<TransitionControl> for SubmitValidationControl {
    fn from(control: TransitionControl) -> Self {
        Self {
            cancelled: control.cancelled,
            maximum_work_units: control.maximum_work_units,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SubmitValidationClass {
    Compatible = 1,
    Cancelled = 2,
    ResourceLimit = 3,
    StaleAuthority = 4,
    InvalidInput = 5,
    SuppliedFactRejected = 6,
    LockConflict = 7,
    MissingCurrentProof = 8,
    StaleProof = 9,
    ExtraneousProof = 10,
}

impl SubmitValidationClass {
    const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitValidationReceipt {
    pub class: SubmitValidationClass,
    pub request_digest: Digest,
    pub lock_set_digest: Digest,
    pub authority_epoch: u64,
    /// The model's supplied time for the lock snapshot that was checked. This
    /// is an observation label, not proof that the caller supplied fresh time.
    pub server_time: u64,
    pub event_head: Digest,
    pub state_commitment: Digest,
    pub work_units: u64,
    pub digest: Digest,
}

impl LockModel {
    /// Validates caller-supplied submit facts against the current in-memory
    /// lock snapshot at the model's already-supplied `server_time`. This method
    /// is pure: it never advances time, establishes freshness, grants
    /// permission, changes a lock, advances a branch, or consumes a proof.
    pub fn validate_submit_facts(
        &self,
        request: &SubmitValidationRequest,
        control: SubmitValidationControl,
    ) -> SubmitValidationReceipt {
        let initial_work = match bounded_submit_request_work(request) {
            Ok(work) if work <= control.maximum_work_units => work,
            _ => {
                return submit_receipt(
                    self,
                    oversize_submit_request_digest(request),
                    SubmitValidationClass::ResourceLimit,
                    [0; 32],
                    0,
                )
            }
        };
        let request_digest = submit_request_digest(request);
        let mut work = initial_work;
        let finish = |class, lock_set_digest, work_units| {
            submit_receipt(self, request_digest, class, lock_set_digest, work_units)
        };
        if control.cancelled {
            return finish(SubmitValidationClass::Cancelled, [0; 32], work);
        }
        if control.maximum_work_units == 0 || control.maximum_work_units > WORK_UNITS_HARD_MAXIMUM {
            return finish(SubmitValidationClass::ResourceLimit, [0; 32], work);
        }
        if request.authority_epoch != self.authority_epoch
            || request.plan.authority_epoch != self.authority_epoch
        {
            return finish(SubmitValidationClass::StaleAuthority, [0; 32], work);
        }
        if request.scope != self.scope {
            return finish(SubmitValidationClass::InvalidInput, [0; 32], work);
        }
        if !submit_permission_valid(self, request) {
            return finish(SubmitValidationClass::SuppliedFactRejected, [0; 32], work);
        }
        if !valid_plan(request)
            || request.changes.is_empty()
            || request.changes.len() > self.limits.submit_targets
            || request.presented_proofs.len() > self.limits.submit_targets
        {
            return finish(SubmitValidationClass::InvalidInput, [0; 32], work);
        }
        let proofs_by_claim = request
            .presented_proofs
            .iter()
            .map(|proof| (proof.claim_id, proof))
            .collect::<BTreeMap<_, _>>();
        if proofs_by_claim.len() != request.presented_proofs.len() {
            return finish(SubmitValidationClass::InvalidInput, [0; 32], work);
        }

        let mut normalized = Vec::<(&SubmitChangeFact, NormalizedTarget)>::new();
        for change in &request.changes {
            if charge(
                &mut work,
                1_u64.saturating_add(change.target.expansion.members.len() as u64),
                control.maximum_work_units,
            )
            .is_err()
            {
                return finish(SubmitValidationClass::ResourceLimit, [0; 32], work);
            }
            if change.requirement_digest == [0; 32] {
                return finish(SubmitValidationClass::InvalidInput, [0; 32], work);
            }
            let Ok(target) = normalize_target(&change.target, self.path_profile, self.case_mode)
            else {
                return finish(SubmitValidationClass::InvalidInput, [0; 32], work);
            };
            normalized.push((change, target));
        }

        let mut used_claims = BTreeSet::new();
        let mut lock_set = DigestBuilder::new(b"OGVCS-PRIVATE-SUBMIT-LOCK-SET-V1");
        lock_set.u64(normalized.len() as u64);
        for (change, target) in &normalized {
            lock_set.fixed(target.digest());
            lock_set.boolean(change.supplied_requires_hard_lock);
            lock_set.fixed(&change.requirement_digest);
            let mut matched = None;
            for record in self.hard_locks.values() {
                if charge(
                    &mut work,
                    target.overlap_work(&record.target),
                    control.maximum_work_units,
                )
                .is_err()
                {
                    return finish(SubmitValidationClass::ResourceLimit, [0; 32], work);
                }
                if target.overlaps(&record.target) {
                    if matched.is_some() {
                        return finish(SubmitValidationClass::LockConflict, [0; 32], work);
                    }
                    matched = Some(record);
                }
            }

            let Some(record) = matched else {
                if change.supplied_requires_hard_lock {
                    return finish(SubmitValidationClass::MissingCurrentProof, [0; 32], work);
                }
                lock_set.u8(0);
                continue;
            };
            if record.owner != request.subject || record.workspace != request.workspace {
                return finish(SubmitValidationClass::LockConflict, [0; 32], work);
            }
            let Some(proof) = proofs_by_claim.get(&record.claim_id).copied() else {
                return finish(SubmitValidationClass::MissingCurrentProof, [0; 32], work);
            };
            if proof.authority_epoch != self.authority_epoch
                || proof.generation != record.generation
                || proof.receipt_digest != record.receipt_digest
            {
                return finish(SubmitValidationClass::StaleProof, [0; 32], work);
            }
            used_claims.insert(record.claim_id);
            lock_set.u8(1);
            lock_set.fixed(record.claim_id.as_bytes());
            lock_set.u64(record.generation);
            lock_set.fixed(&record.receipt_digest);
        }

        if request
            .presented_proofs
            .iter()
            .any(|proof| !used_claims.contains(&proof.claim_id))
        {
            return finish(SubmitValidationClass::ExtraneousProof, [0; 32], work);
        }
        finish(SubmitValidationClass::Compatible, lock_set.finish(), work)
    }
}

fn submit_permission_valid(model: &LockModel, request: &SubmitValidationRequest) -> bool {
    request.permission.permission == PermissionAssignment::Submit
        && request.permission.decision == SuppliedDecision::Affirmed
        && request.permission.authority_epoch == model.authority_epoch
        && request.permission.policy_generation > 0
        && request.permission.subject == request.subject
        && request.permission.scope_commitment == model.scope.commitment()
        && request.permission.decision_digest != [0; 32]
}

fn valid_plan(request: &SubmitValidationRequest) -> bool {
    request.plan.intent_id != [0; 16]
        && request.plan.expected_head.kind == ObjectKind::Snapshot
        && request.plan.candidate_snapshot.kind == ObjectKind::Snapshot
        && request.plan.operation_set_digest != [0; 32]
        && request.plan.lifecycle_plan_digest != [0; 32]
        && request.plan.identity_plan_digest != [0; 32]
        && request.plan.identity_decision_digest != [0; 32]
        && request.plan.identity_resource_projection_digest != [0; 32]
        && request.plan.authenticated_scope_digest == request.scope.commitment()
        && request.plan.subject_digest == *request.subject.as_bytes()
}

fn charge(used: &mut u64, amount: u64, maximum: u64) -> Result<(), ()> {
    let next = used.checked_add(amount).ok_or(())?;
    if next > maximum {
        return Err(());
    }
    *used = next;
    Ok(())
}

fn bounded_submit_request_work(request: &SubmitValidationRequest) -> Result<u64, ()> {
    if request.changes.len() > crate::SUBMIT_TARGETS_HARD_MAXIMUM + 1
        || request.presented_proofs.len() > crate::SUBMIT_TARGETS_HARD_MAXIMUM + 1
    {
        return Err(());
    }
    let mut work = 1_u64
        .checked_add(request.presented_proofs.len() as u64)
        .ok_or(())?;
    for change in &request.changes {
        work = work
            .checked_add(bounded_target_input_work(&change.target)?)
            .ok_or(())?;
    }
    Ok(work)
}

fn oversize_submit_request_digest(request: &SubmitValidationRequest) -> Digest {
    let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-SUBMIT-LOCK-OVERSIZE-V1");
    digest.fixed(&request.scope.commitment());
    digest.u64(request.authority_epoch);
    digest.fixed(request.subject.as_bytes());
    digest.fixed(request.workspace.as_bytes());
    digest.u64(request.changes.len() as u64);
    digest.u64(request.presented_proofs.len() as u64);
    digest.finish()
}

fn submit_request_digest(request: &SubmitValidationRequest) -> Digest {
    let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-SUBMIT-LOCK-VALIDATION-REQUEST-V1");
    digest.fixed(&request.scope.commitment());
    digest.u64(request.authority_epoch);
    digest.fixed(request.subject.as_bytes());
    digest.fixed(request.workspace.as_bytes());
    digest.fixed(&request.permission.digest());
    digest_plan(&mut digest, request.plan);
    digest.u64(request.changes.len() as u64);
    for change in &request.changes {
        digest.fixed(&digest_target_input(&change.target));
        digest.boolean(change.supplied_requires_hard_lock);
        digest.fixed(&change.requirement_digest);
    }
    digest.u64(request.presented_proofs.len() as u64);
    for proof in &request.presented_proofs {
        digest.fixed(proof.claim_id.as_bytes());
        digest.u64(proof.authority_epoch);
        digest.u64(proof.generation);
        digest.fixed(&proof.receipt_digest);
    }
    digest.finish()
}

fn digest_plan(digest: &mut DigestBuilder, plan: SubmitPlanBinding) {
    digest.fixed(&plan.intent_id);
    digest_object(digest, plan.expected_head);
    digest_object(digest, plan.candidate_snapshot);
    digest.fixed(&plan.operation_set_digest);
    digest.fixed(&plan.lifecycle_plan_digest);
    digest.fixed(&plan.identity_plan_digest);
    digest.fixed(&plan.identity_decision_digest);
    digest.fixed(&plan.identity_resource_projection_digest);
    digest.fixed(&plan.authenticated_scope_digest);
    digest.fixed(&plan.subject_digest);
    digest.u64(plan.authority_epoch);
}

fn digest_object(digest: &mut DigestBuilder, object: ObjectRef) {
    digest.u16(object.kind.code());
    digest.fixed(&object.digest);
}

fn submit_receipt(
    model: &LockModel,
    request_digest: Digest,
    class: SubmitValidationClass,
    lock_set_digest: Digest,
    work_units: u64,
) -> SubmitValidationReceipt {
    let state_commitment = model.state_commitment();
    let event_head = model.event_head();
    let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-SUBMIT-LOCK-VALIDATION-RECEIPT-V1");
    digest.u16(class.code());
    digest.fixed(&request_digest);
    digest.fixed(&lock_set_digest);
    digest.u64(model.authority_epoch);
    digest.u64(model.server_time);
    digest.fixed(&event_head);
    digest.fixed(&state_commitment);
    digest.u64(work_units);
    SubmitValidationReceipt {
        class,
        request_digest,
        lock_set_digest,
        authority_epoch: model.authority_epoch,
        server_time: model.server_time,
        event_head,
        state_commitment,
        work_units,
        digest: digest.finish(),
    }
}
