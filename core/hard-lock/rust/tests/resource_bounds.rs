mod common;

use common::*;
use ogvcs_hard_lock_model::*;
use ogvcs_path_contract::CaseMode;

#[test]
fn active_lock_capacity_returns_recorded_outcome_without_replacing_owner() {
    let limits = ModelLimits {
        active_hard_locks: 1,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                subject(10),
                workspace(10),
                file_target(file(20), "Assets/A.uasset", 1),
            )],
        )
        .unwrap();
    let second = state
        .apply_batch(
            context(101),
            vec![acquire(
                2,
                subject(11),
                workspace(11),
                file_target(file(21), "Assets/B.uasset", 1),
            )],
        )
        .unwrap();
    assert_eq!(recorded(&second, 0).outcome, OutcomeClass::CapacityReached);
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn idempotency_capacity_failure_is_atomic() {
    let limits = ModelLimits {
        idempotency_records: 1,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                subject(10),
                workspace(10),
                file_target(file(20), "Assets/A.uasset", 1),
            )],
        )
        .unwrap();
    let before = state.state_commitment();
    let result = state.apply_batch(
        context(101),
        vec![acquire(
            2,
            subject(11),
            workspace(11),
            file_target(file(21), "Assets/B.uasset", 1),
        )],
    );
    assert_eq!(result, Err(BatchError::IdempotencyCapacity));
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn event_capacity_failure_rolls_back_lock_mutation_and_idempotency() {
    let limits = ModelLimits {
        event_commitments: 1,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                subject(10),
                workspace(10),
                file_target(file(20), "Assets/A.uasset", 1),
            )],
        )
        .unwrap();
    let before = state.state_commitment();
    let result = state.apply_batch(
        context(101),
        vec![acquire(
            2,
            subject(11),
            workspace(11),
            file_target(file(21), "Assets/B.uasset", 1),
        )],
    );
    assert_eq!(result, Err(BatchError::EventCapacity));
    assert_eq!(state.state_commitment(), before);
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn notice_capacity_failure_rolls_back_release_and_all_partial_notices() {
    let limits = ModelLimits {
        notice_commitments: 1,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    let owner = subject(10);
    let workspace_id = workspace(10);
    let target = file_target(file(20), "Assets/A.uasset", 1);
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(1, owner, workspace_id, target.clone())],
        )
        .unwrap();
    let proof = recorded(&acquired, 0).claim_proof().unwrap();
    state
        .apply_batch(
            context(101),
            vec![
                Command::Wait(WaitRequest {
                    meta: meta(2, subject(11), PermissionAssignment::LockCreate),
                    subject: subject(11),
                    workspace: workspace(11),
                    target: target.clone(),
                    lease_ticks: 30,
                }),
                Command::Wait(WaitRequest {
                    meta: meta(3, subject(12), PermissionAssignment::LockCreate),
                    subject: subject(12),
                    workspace: workspace(12),
                    target,
                    lease_ticks: 30,
                }),
            ],
        )
        .unwrap();
    let before = state.state_commitment();
    let result = state.apply_batch(
        context(101),
        vec![Command::Release(ReleaseRequest {
            meta: meta(4, owner, PermissionAssignment::LockCreate),
            owner,
            workspace: workspace_id,
            proof,
        })],
    );
    assert_eq!(result, Err(BatchError::NoticeCapacity));
    assert_eq!(state.state_commitment(), before);
    assert_eq!(state.active_hard_lock_count(), 1);
    assert_eq!(state.wait_subscription_count(), 2);
    assert!(state.notices().is_empty());
}

#[test]
fn grossly_oversized_target_is_rejected_before_unbounded_commitment_work() {
    let target = TargetInput {
        target: LockTarget::Prefix("A".repeat(4_098)),
        expansion: TargetExpansion {
            schema_version: TARGET_EXPANSION_VERSION,
            view_generation: 1,
            policy_version: 0,
            policy_digest: [0; 32],
            members: Vec::new(),
        },
    };
    let mut state = model();
    let before = state.state_commitment();
    let result = state.apply_batch(
        context(101),
        vec![acquire(1, subject(10), workspace(10), target)],
    );
    assert_eq!(result, Err(BatchError::WorkLimit));
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn grossly_oversized_submit_projection_returns_bounded_resource_result() {
    let actor = subject(10);
    let changes = (0..=SUBMIT_TARGETS_HARD_MAXIMUM + 1)
        .map(|index| SubmitChangeFact {
            target: file_target(
                file_number((index + 1) as u16),
                &format!("Code/{index}.rs"),
                1,
            ),
            supplied_requires_hard_lock: false,
            requirement_digest: bytes32(80),
        })
        .collect();
    let request = SubmitValidationRequest {
        scope: scope(),
        authority_epoch: 7,
        subject: actor,
        workspace: workspace(10),
        permission: permission(actor, PermissionAssignment::Submit, true),
        plan: SubmitPlanBinding {
            intent_id: bytes16(70),
            expected_head: snapshot(10),
            candidate_snapshot: snapshot(11),
            operation_set_digest: bytes32(71),
            lifecycle_plan_digest: bytes32(72),
            identity_plan_digest: bytes32(73),
            identity_decision_digest: bytes32(74),
            identity_resource_projection_digest: bytes32(75),
            authenticated_scope_digest: scope().commitment(),
            subject_digest: *actor.as_bytes(),
            authority_epoch: 7,
        },
        changes,
        presented_proofs: Vec::new(),
    };
    let state = model();
    let before = state.state_commitment();
    let result = state.validate_submit_facts(&request, SubmitValidationControl::default());
    assert_eq!(result.class, SubmitValidationClass::ResourceLimit);
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn waiter_and_advisory_retained_caps_admit_exactly_the_configured_count() {
    let limits = ModelLimits {
        active_advisory_intents: 1,
        wait_subscriptions: 1,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    let locked_target = file_target(file(20), "Assets/Locked.uasset", 1);
    state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                subject(10),
                workspace(10),
                locked_target.clone(),
            )],
        )
        .unwrap();
    let waits = state
        .apply_batch(
            context(101),
            vec![
                Command::Wait(WaitRequest {
                    meta: meta(2, subject(11), PermissionAssignment::LockCreate),
                    subject: subject(11),
                    workspace: workspace(11),
                    target: locked_target.clone(),
                    lease_ticks: 20,
                }),
                Command::Wait(WaitRequest {
                    meta: meta(3, subject(12), PermissionAssignment::LockCreate),
                    subject: subject(12),
                    workspace: workspace(12),
                    target: locked_target,
                    lease_ticks: 20,
                }),
            ],
        )
        .unwrap();
    let wait_classes = waits
        .results
        .iter()
        .map(|result| result.receipt().unwrap().outcome)
        .collect::<Vec<_>>();
    assert!(wait_classes.contains(&OutcomeClass::Waiting));
    assert!(wait_classes.contains(&OutcomeClass::CapacityReached));
    assert_eq!(state.wait_subscription_count(), 1);

    let advisories = state
        .apply_batch(
            context(101),
            vec![
                advisory(
                    4,
                    subject(13),
                    workspace(13),
                    file_target(file(21), "Code/A.txt", 1),
                ),
                advisory(
                    5,
                    subject(14),
                    workspace(14),
                    file_target(file(22), "Code/B.txt", 1),
                ),
            ],
        )
        .unwrap();
    let advisory_classes = advisories
        .results
        .iter()
        .map(|result| result.receipt().unwrap().outcome)
        .collect::<Vec<_>>();
    assert!(advisory_classes.contains(&OutcomeClass::AdvisoryRecorded));
    assert!(advisory_classes.contains(&OutcomeClass::CapacityReached));
    assert_eq!(state.active_advisory_count(), 1);
}

#[test]
fn batch_limit_accepts_exact_count_and_rejects_maximum_plus_one_atomically() {
    let limits = ModelLimits {
        batch_requests: 2,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    let exact = state
        .apply_batch(
            context(101),
            vec![
                Command::Expire(ExpiryRequest {
                    idempotency_key: key(1),
                    scope: scope(),
                }),
                Command::Expire(ExpiryRequest {
                    idempotency_key: key(2),
                    scope: scope(),
                }),
            ],
        )
        .unwrap();
    assert_eq!(exact.results.len(), 2);

    let before = state.state_commitment();
    let over = state.apply_batch(
        context(101),
        vec![
            Command::Expire(ExpiryRequest {
                idempotency_key: key(3),
                scope: scope(),
            }),
            Command::Expire(ExpiryRequest {
                idempotency_key: key(4),
                scope: scope(),
            }),
            Command::Expire(ExpiryRequest {
                idempotency_key: key(5),
                scope: scope(),
            }),
        ],
    );
    assert_eq!(over, Err(BatchError::BatchLimit));
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn configured_reason_bound_accepts_exact_bytes_and_rejects_plus_one() {
    let limits = ModelLimits {
        reason_bytes: 4,
        ..ModelLimits::default()
    };
    let owner = subject(10);
    let admin = subject(50);

    let mut exact_state = model_with(CaseMode::Sensitive, limits);
    let exact_acquire = exact_state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                owner,
                workspace(10),
                file_target(file(20), "Assets/A.uasset", 1),
            )],
        )
        .unwrap();
    let exact_proof = recorded(&exact_acquire, 0).claim_proof().unwrap();
    let exact = exact_state
        .apply_batch(
            context(101),
            vec![Command::Break(BreakRequest {
                meta: meta(2, admin, PermissionAssignment::LockForceUnlock),
                actor: admin,
                selector: BreakSelector {
                    claim_id: exact_proof.claim_id,
                    authority_epoch: exact_proof.authority_epoch,
                    generation: exact_proof.generation,
                },
                reason: "1234".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(recorded(&exact, 0).outcome, OutcomeClass::Broken);

    let mut over_state = model_with(CaseMode::Sensitive, limits);
    let over_acquire = over_state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                owner,
                workspace(10),
                file_target(file(20), "Assets/A.uasset", 1),
            )],
        )
        .unwrap();
    let over_proof = recorded(&over_acquire, 0).claim_proof().unwrap();
    let over = over_state
        .apply_batch(
            context(101),
            vec![Command::Break(BreakRequest {
                meta: meta(2, admin, PermissionAssignment::LockForceUnlock),
                actor: admin,
                selector: BreakSelector {
                    claim_id: over_proof.claim_id,
                    authority_epoch: over_proof.authority_epoch,
                    generation: over_proof.generation,
                },
                reason: "12345".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(recorded(&over, 0).outcome, OutcomeClass::InvalidRequest);
    assert_eq!(over_state.active_hard_lock_count(), 1);
}

#[test]
fn fault_adapter_preserves_batch_limit_precedence_and_prior_state() {
    let limits = ModelLimits {
        batch_requests: 1,
        ..ModelLimits::default()
    };
    let mut state = model_with(CaseMode::Sensitive, limits);
    let before = state.state_commitment();
    let result = state.apply_batch_with_fault(
        context(101),
        vec![
            Command::Expire(ExpiryRequest {
                idempotency_key: key(1),
                scope: scope(),
            }),
            Command::Expire(ExpiryRequest {
                idempotency_key: key(2),
                scope: scope(),
            }),
        ],
        FaultInjection {
            boundary: FaultBoundary::EventPublication,
            action: FaultAction::CrashBefore,
        },
    );
    assert_eq!(result, Err(BatchError::BatchLimit));
    assert_eq!(state.state_commitment(), before);
}
