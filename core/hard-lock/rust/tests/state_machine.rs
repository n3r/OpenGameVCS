mod common;

use common::*;
use ogvcs_hard_lock_model::*;
use ogvcs_path_contract::CaseMode;

#[test]
fn simultaneous_acquire_has_one_order_independent_winner() {
    let actor_a = subject(10);
    let actor_b = subject(11);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let left = acquire(1, actor_a, workspace(10), target.clone());
    let right = acquire(2, actor_b, workspace(11), target);

    let mut first = model();
    let first_result = first
        .apply_batch(context(101), vec![left.clone(), right.clone()])
        .unwrap();
    let mut second = model();
    let second_result = second.apply_batch(context(101), vec![right, left]).unwrap();

    let mut first_classes = first_result
        .results
        .iter()
        .map(|result| result.receipt().unwrap().outcome)
        .collect::<Vec<_>>();
    let mut second_classes = second_result
        .results
        .iter()
        .map(|result| result.receipt().unwrap().outcome)
        .collect::<Vec<_>>();
    first_classes.sort_by_key(|class| class.code());
    second_classes.sort_by_key(|class| class.code());
    assert_eq!(
        first_classes,
        vec![OutcomeClass::Granted, OutcomeClass::Conflict]
    );
    assert_eq!(first_classes, second_classes);
    assert_eq!(first.state_commitment(), second.state_commitment());
    assert_eq!(first.active_hard_lock_count(), 1);
}

#[test]
fn identical_acquire_replays_exact_receipt_and_changed_key_reuse_is_inert() {
    let actor = subject(10);
    let command = acquire(
        1,
        actor,
        workspace(10),
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let mut state = model();
    let first = state
        .apply_batch(context(101), vec![command.clone()])
        .unwrap();
    let first_receipt = recorded(&first, 0);
    let events = state.events().len();
    let replay = state.apply_batch(context(101), vec![command]).unwrap();
    assert_eq!(recorded(&replay, 0), first_receipt);
    assert!(matches!(
        replay.results[0],
        OperationResult::Recorded { replayed: true, .. }
    ));
    assert_eq!(state.events().len(), events);

    let before = state.state_commitment();
    let changed = acquire(
        1,
        actor,
        workspace(10),
        file_target(file(21), "Assets/Other.uasset", 1),
    );
    let reused = state.apply_batch(context(101), vec![changed]).unwrap();
    assert_eq!(reused.results, vec![OperationResult::KeyReuse]);
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn one_batch_rejects_different_requests_under_one_key_without_mutation() {
    let actor = subject(10);
    let mut state = model();
    let before = state.state_commitment();
    let result = state.apply_batch(
        context(101),
        vec![
            acquire(
                1,
                actor,
                workspace(10),
                file_target(file(20), "Assets/A.uasset", 1),
            ),
            acquire(
                1,
                actor,
                workspace(10),
                file_target(file(21), "Assets/B.uasset", 1),
            ),
        ],
    );
    assert_eq!(result, Err(BatchError::ConflictingBatchKey));
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn file_id_lock_survives_move_even_when_path_changes() {
    let mut state = model();
    let file_id = file(20);
    let first = acquire(
        1,
        subject(10),
        workspace(10),
        file_target(file_id, "Assets/Old/Hero.uasset", 1),
    );
    let moved = acquire(
        2,
        subject(11),
        workspace(11),
        file_target(file_id, "Assets/New/Hero.uasset", 2),
    );
    let result = state.apply_batch(context(101), vec![first, moved]).unwrap();
    let classes = result
        .results
        .iter()
        .map(|value| value.receipt().unwrap().outcome)
        .collect::<Vec<_>>();
    assert!(classes.contains(&OutcomeClass::Granted));
    assert!(classes.contains(&OutcomeClass::Conflict));
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn deleted_file_identity_does_not_capture_recreated_path_identity() {
    let mut state = model();
    let path = "Assets/Recreated.uasset";
    let first = acquire(
        1,
        subject(10),
        workspace(10),
        file_target(file(20), path, 1),
    );
    let recreated = acquire(
        2,
        subject(11),
        workspace(11),
        file_target(file(21), path, 2),
    );
    let result = state
        .apply_batch(context(101), vec![first, recreated])
        .unwrap();
    assert_eq!(
        result
            .results
            .iter()
            .filter(|value| value.receipt().unwrap().outcome == OutcomeClass::Granted)
            .count(),
        2
    );
    assert_eq!(state.active_hard_lock_count(), 2);

    let prefix = acquire(
        3,
        subject(12),
        workspace(12),
        prefix_target("Assets", &[(file(21), path)], 2),
    );
    assert_eq!(
        recorded(&state.apply_batch(context(101), vec![prefix]).unwrap(), 0).outcome,
        OutcomeClass::Conflict
    );
}

#[test]
fn folded_prefix_conflicts_across_case_spelling() {
    let mut state = model_with(CaseMode::Folded, ModelLimits::default());
    let prefix = acquire(
        1,
        subject(10),
        workspace(10),
        prefix_target("Assets/Characters", &[], 1),
    );
    let file_lock = acquire(
        2,
        subject(11),
        workspace(11),
        file_target(file(20), "assets/characters/Hero.uasset", 1),
    );
    let result = state
        .apply_batch(context(101), vec![prefix, file_lock])
        .unwrap();
    let classes = result
        .results
        .iter()
        .map(|value| value.receipt().unwrap().outcome)
        .collect::<Vec<_>>();
    assert!(classes.contains(&OutcomeClass::Granted));
    assert!(classes.contains(&OutcomeClass::Conflict));
}

#[test]
fn unicode_nfc_is_accepted_and_decomposed_spelling_fails_closed() {
    let actor = subject(10);
    let mut state = model();
    let canonical = acquire(
        1,
        actor,
        workspace(10),
        file_target(file(20), "Assets/Café.uasset", 1),
    );
    assert_eq!(
        recorded(
            &state.apply_batch(context(101), vec![canonical]).unwrap(),
            0
        )
        .outcome,
        OutcomeClass::Granted
    );
    let decomposed = acquire(
        2,
        actor,
        workspace(10),
        file_target(file(21), "Assets/Cafe\u{301}.uasset", 1),
    );
    assert_eq!(
        recorded(
            &state.apply_batch(context(101), vec![decomposed]).unwrap(),
            0
        )
        .outcome,
        OutcomeClass::InvalidRequest
    );
}

#[test]
fn asset_group_accepts_exact_maximum_and_rejects_maximum_plus_one() {
    let exact = (1..=ASSET_GROUP_MEMBERS_MAXIMUM)
        .map(|index| ExpandedMember {
            file_id: file_number(index as u16),
            canonical_path: format!("Assets/Group/{index}.uasset"),
        })
        .collect::<Vec<_>>();
    let mut over = exact.clone();
    over.push(ExpandedMember {
        file_id: file_number((ASSET_GROUP_MEMBERS_MAXIMUM + 1) as u16),
        canonical_path: "Assets/Group/overflow.uasset".to_owned(),
    });
    let actor = subject(10);
    let mut exact_model = model();
    assert_eq!(
        recorded(
            &exact_model
                .apply_batch(
                    context(101),
                    vec![acquire(1, actor, workspace(10), group_target(8, 3, exact))],
                )
                .unwrap(),
            0,
        )
        .outcome,
        OutcomeClass::Granted
    );
    let mut over_model = model();
    assert_eq!(
        recorded(
            &over_model
                .apply_batch(
                    context(101),
                    vec![acquire(1, actor, workspace(10), group_target(8, 3, over))],
                )
                .unwrap(),
            0,
        )
        .outcome,
        OutcomeClass::InvalidRequest
    );
}

#[test]
fn renew_rotates_generation_and_stale_release_cannot_mutate() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                actor,
                workspace_id,
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let first_proof = recorded(&acquired, 0).claim_proof().unwrap();
    let renewed = state
        .apply_batch(
            context(102),
            vec![Command::Renew(RenewRequest {
                meta: meta(2, actor, PermissionAssignment::LockCreate),
                owner: actor,
                workspace: workspace_id,
                proof: first_proof,
                lease_ticks: 30,
            })],
        )
        .unwrap();
    let current_proof = recorded(&renewed, 0).claim_proof().unwrap();
    assert!(current_proof.generation > first_proof.generation);

    let stale = state
        .apply_batch(
            context(102),
            vec![Command::Release(ReleaseRequest {
                meta: meta(3, actor, PermissionAssignment::LockCreate),
                owner: actor,
                workspace: workspace_id,
                proof: first_proof,
            })],
        )
        .unwrap();
    assert_eq!(recorded(&stale, 0).outcome, OutcomeClass::StaleFence);
    assert_eq!(state.active_hard_lock_count(), 1);

    let released = state
        .apply_batch(
            context(102),
            vec![Command::Release(ReleaseRequest {
                meta: meta(4, actor, PermissionAssignment::LockCreate),
                owner: actor,
                workspace: workspace_id,
                proof: current_proof,
            })],
        )
        .unwrap();
    assert_eq!(recorded(&released, 0).outcome, OutcomeClass::Released);
    assert_eq!(state.active_hard_lock_count(), 0);
}

#[test]
fn transfer_requires_reason_and_supplied_fact_and_fences_old_workspace() {
    let actor = subject(10);
    let first_workspace = workspace(10);
    let second_workspace = workspace(11);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                actor,
                first_workspace,
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let proof = recorded(&acquired, 0).claim_proof().unwrap();

    let missing_reason = state
        .apply_batch(
            context(101),
            vec![Command::Transfer(TransferRequest {
                meta: meta(2, actor, PermissionAssignment::LockCreate),
                owner: actor,
                from_workspace: first_workspace,
                to_workspace: second_workspace,
                proof,
                lease_ticks: 20,
                reason: "   ".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&missing_reason, 0).outcome,
        OutcomeClass::InvalidRequest
    );

    let mut denied_meta = meta(3, actor, PermissionAssignment::LockCreate);
    denied_meta.permission.decision = SuppliedDecision::NotAffirmed;
    let denied = state
        .apply_batch(
            context(101),
            vec![Command::Transfer(TransferRequest {
                meta: denied_meta,
                owner: actor,
                from_workspace: first_workspace,
                to_workspace: second_workspace,
                proof,
                lease_ticks: 20,
                reason: "handoff".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&denied, 0).outcome,
        OutcomeClass::SuppliedFactRejected
    );

    let transferred = state
        .apply_batch(
            context(101),
            vec![Command::Transfer(TransferRequest {
                meta: meta(4, actor, PermissionAssignment::LockCreate),
                owner: actor,
                from_workspace: first_workspace,
                to_workspace: second_workspace,
                proof,
                lease_ticks: 20,
                reason: "handoff".to_owned(),
            })],
        )
        .unwrap();
    let current = recorded(&transferred, 0).claim_proof().unwrap();
    assert!(current.generation > proof.generation);
    let stale = state
        .apply_batch(
            context(101),
            vec![Command::Renew(RenewRequest {
                meta: meta(5, actor, PermissionAssignment::LockCreate),
                owner: actor,
                workspace: first_workspace,
                proof,
                lease_ticks: 20,
            })],
        )
        .unwrap();
    assert_eq!(recorded(&stale, 0).outcome, OutcomeClass::StaleFence);
}

#[test]
fn break_requires_force_assignment_nonempty_reason_and_current_generation() {
    let owner = subject(10);
    let admin = subject(50);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                owner,
                workspace(10),
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let proof = recorded(&acquired, 0).claim_proof().unwrap();
    let selector = BreakSelector {
        claim_id: proof.claim_id,
        authority_epoch: proof.authority_epoch,
        generation: proof.generation,
    };

    let wrong_permission = state
        .apply_batch(
            context(101),
            vec![Command::Break(BreakRequest {
                meta: meta(2, admin, PermissionAssignment::LockCreate),
                actor: admin,
                selector,
                reason: "abandoned".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&wrong_permission, 0).outcome,
        OutcomeClass::SuppliedFactRejected
    );
    let stale = state
        .apply_batch(
            context(101),
            vec![Command::Break(BreakRequest {
                meta: meta(3, admin, PermissionAssignment::LockForceUnlock),
                actor: admin,
                selector: BreakSelector {
                    generation: selector.generation + 1,
                    ..selector
                },
                reason: "abandoned".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(recorded(&stale, 0).outcome, OutcomeClass::StaleFence);
    let broken = state
        .apply_batch(
            context(101),
            vec![Command::Break(BreakRequest {
                meta: meta(4, admin, PermissionAssignment::LockForceUnlock),
                actor: admin,
                selector,
                reason: "abandoned".to_owned(),
            })],
        )
        .unwrap();
    assert_eq!(recorded(&broken, 0).outcome, OutcomeClass::Broken);
    assert_eq!(state.active_hard_lock_count(), 0);
}

#[test]
fn expiry_at_server_tick_allows_takeover_and_old_proof_is_inert() {
    let first_actor = subject(10);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(100),
            vec![acquire(
                1,
                first_actor,
                workspace(10),
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let proof = recorded(&acquired, 0).claim_proof().unwrap();
    let takeover = state
        .apply_batch(
            context(120),
            vec![
                Command::Expire(ExpiryRequest {
                    idempotency_key: key(2),
                    scope: scope(),
                }),
                acquire(
                    3,
                    subject(11),
                    workspace(11),
                    file_target(file(20), "Assets/Hero.uasset", 2),
                ),
            ],
        )
        .unwrap();
    assert!(takeover
        .results
        .iter()
        .any(|result| result.receipt().unwrap().outcome == OutcomeClass::Granted));
    assert_eq!(state.active_hard_lock_count(), 1);
    let stale_release = state
        .apply_batch(
            context(120),
            vec![Command::Release(ReleaseRequest {
                meta: meta(4, first_actor, PermissionAssignment::LockCreate),
                owner: first_actor,
                workspace: workspace(10),
                proof,
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&stale_release, 0).outcome,
        OutcomeClass::NotApplied
    );
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn wait_never_reserves_and_release_produces_only_advisory_notice() {
    let owner = subject(10);
    let waiter = subject(11);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(1, owner, workspace(10), target.clone())],
        )
        .unwrap();
    let proof = recorded(&acquired, 0).claim_proof().unwrap();
    let waited = state
        .apply_batch(
            context(101),
            vec![Command::Wait(WaitRequest {
                meta: meta(2, waiter, PermissionAssignment::LockCreate),
                subject: waiter,
                workspace: workspace(11),
                target: target.clone(),
                lease_ticks: 30,
            })],
        )
        .unwrap();
    assert_eq!(recorded(&waited, 0).outcome, OutcomeClass::Waiting);
    assert_eq!(state.active_hard_lock_count(), 1);
    assert_eq!(state.wait_subscription_count(), 1);

    state
        .apply_batch(
            context(101),
            vec![Command::Release(ReleaseRequest {
                meta: meta(3, owner, PermissionAssignment::LockCreate),
                owner,
                workspace: workspace(10),
                proof,
            })],
        )
        .unwrap();
    assert_eq!(state.active_hard_lock_count(), 0);
    assert_eq!(state.wait_subscription_count(), 0);
    assert_eq!(state.notices().len(), 1);

    let result = state
        .apply_batch(
            context(101),
            vec![
                acquire(4, waiter, workspace(11), target.clone()),
                acquire(5, subject(12), workspace(12), target),
            ],
        )
        .unwrap();
    assert_eq!(
        result
            .results
            .iter()
            .filter(|result| result.receipt().unwrap().outcome == OutcomeClass::Granted)
            .count(),
        1
    );
}

#[test]
fn advisory_intents_are_concurrent_and_do_not_block_hard_lock() {
    let target = file_target(file(20), "Code/mergeable.txt", 1);
    let mut state = model();
    let advisory_result = state
        .apply_batch(
            context(101),
            vec![
                advisory(1, subject(10), workspace(10), target.clone()),
                advisory(2, subject(11), workspace(11), target.clone()),
            ],
        )
        .unwrap();
    assert_eq!(state.active_advisory_count(), 2);
    assert!(advisory_result.results.iter().all(|result| matches!(
        result.receipt().unwrap().outcome,
        OutcomeClass::AdvisoryRecorded | OutcomeClass::AdvisoryRecordedWithOverlap
    )));
    let hard = state
        .apply_batch(
            context(101),
            vec![acquire(3, subject(12), workspace(12), target)],
        )
        .unwrap();
    assert_eq!(
        recorded(&hard, 0).outcome,
        OutcomeClass::GrantedAdvisoryPresent
    );
}

#[test]
fn cancellation_and_work_exhaustion_leave_state_unchanged() {
    let command = acquire(
        1,
        subject(10),
        workspace(10),
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let mut state = model();
    let before = state.state_commitment();
    let cancelled = state.apply_batch(
        TransitionContext {
            authority_epoch: 7,
            server_time: 101,
            control: TransitionControl {
                cancelled: true,
                maximum_work_units: 100,
            },
        },
        vec![command.clone()],
    );
    assert_eq!(cancelled, Err(BatchError::Cancelled));
    assert_eq!(state.state_commitment(), before);
    let limited = state.apply_batch(
        TransitionContext {
            authority_epoch: 7,
            server_time: 101,
            control: TransitionControl {
                cancelled: false,
                maximum_work_units: 1,
            },
        },
        vec![command],
    );
    assert_eq!(limited, Err(BatchError::WorkLimit));
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn epoch_promotion_expires_claims_and_rejects_old_epoch_messages() {
    let actor = subject(10);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                actor,
                workspace(10),
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let old_proof = recorded(&acquired, 0).claim_proof().unwrap();
    let promoted = state
        .promote_epoch(8, 105, TransitionControl::default())
        .unwrap();
    assert_eq!(promoted.prior_epoch, 7);
    assert_eq!(promoted.new_epoch, 8);
    assert_eq!(state.active_hard_lock_count(), 0);
    let old = state.apply_batch(
        context(105),
        vec![Command::Expire(ExpiryRequest {
            idempotency_key: key(2),
            scope: scope(),
        })],
    );
    assert_eq!(old, Err(BatchError::StaleAuthorityEpoch));

    let mut current_meta = meta(3, actor, PermissionAssignment::LockCreate);
    current_meta.permission.authority_epoch = 8;
    let old_proof_under_new_context = state
        .apply_batch(
            TransitionContext {
                authority_epoch: 8,
                server_time: 105,
                control: TransitionControl::default(),
            },
            vec![Command::Release(ReleaseRequest {
                meta: current_meta,
                owner: actor,
                workspace: workspace(10),
                proof: old_proof,
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&old_proof_under_new_context, 0).outcome,
        OutcomeClass::NotApplied
    );
    assert_eq!(state.active_hard_lock_count(), 0);
}

#[test]
fn event_chain_and_receipt_commitments_are_stable_and_linked() {
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![acquire(
                1,
                subject(10),
                workspace(10),
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let receipt = recorded(&result, 0);
    assert_ne!(receipt.digest, [0; 32]);
    assert_eq!(receipt.event_digest, state.events().last().unwrap().digest);
    assert_eq!(state.events()[0].previous_digest, [0; 32]);
    for pair in state.events().windows(2) {
        assert_eq!(pair[1].previous_digest, pair[0].digest);
        assert!(pair[1].sequence > pair[0].sequence);
    }
}

#[test]
fn state_event_and_receipt_commitments_bind_immutable_model_configuration() {
    let command = acquire(
        1,
        subject(10),
        workspace(10),
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let mut sensitive = model_with(CaseMode::Sensitive, ModelLimits::default());
    let mut folded = model_with(CaseMode::Folded, ModelLimits::default());
    assert_ne!(sensitive.state_commitment(), folded.state_commitment());

    let sensitive_result = sensitive
        .apply_batch(context(101), vec![command.clone()])
        .unwrap();
    let folded_result = folded.apply_batch(context(101), vec![command]).unwrap();
    let sensitive_receipt = recorded(&sensitive_result, 0);
    let folded_receipt = recorded(&folded_result, 0);
    assert_ne!(sensitive_receipt.claim_id, folded_receipt.claim_id);
    assert_ne!(sensitive_receipt.event_digest, folded_receipt.event_digest);
    assert_ne!(sensitive_receipt.digest, folded_receipt.digest);
    assert_ne!(sensitive.state_commitment(), folded.state_commitment());

    let limited = model_with(
        CaseMode::Sensitive,
        ModelLimits {
            active_hard_locks: 1,
            ..ModelLimits::default()
        },
    );
    assert_ne!(model().state_commitment(), limited.state_commitment());
}
