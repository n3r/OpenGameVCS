mod common;

use common::*;
use ogvcs_hard_lock_model::*;

fn assert_exact_replay(first: OperationReceipt, replay: &BatchReceipt) {
    assert_eq!(recorded(replay, 0), first);
    assert!(matches!(
        replay.results[0],
        OperationResult::Recorded { replayed: true, .. }
    ));
}

#[test]
fn reordered_acquire_renew_transfer_and_break_replays_never_revert_state() {
    let owner = subject(10);
    let admin = subject(50);
    let workspace_a = workspace(10);
    let workspace_b = workspace(11);
    let acquire_command = acquire(
        1,
        owner,
        workspace_a,
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let mut state = model();
    let acquire_result = state
        .apply_batch(context(101), vec![acquire_command.clone()])
        .unwrap();
    let acquire_receipt = recorded(&acquire_result, 0);
    let first_proof = acquire_receipt.claim_proof().unwrap();

    let renew_command = Command::Renew(RenewRequest {
        meta: meta(2, owner, PermissionAssignment::LockCreate),
        owner,
        workspace: workspace_a,
        proof: first_proof,
        lease_ticks: 30,
    });
    let renew_result = state
        .apply_batch(context(102), vec![renew_command.clone()])
        .unwrap();
    let renew_receipt = recorded(&renew_result, 0);
    let renewed_proof = renew_receipt.claim_proof().unwrap();

    let acquire_replay = state
        .apply_batch(context(102), vec![acquire_command])
        .unwrap();
    assert_exact_replay(acquire_receipt, &acquire_replay);
    assert_eq!(state.active_hard_lock_count(), 1);

    let transfer_command = Command::Transfer(TransferRequest {
        meta: meta(3, owner, PermissionAssignment::LockCreate),
        owner,
        from_workspace: workspace_a,
        to_workspace: workspace_b,
        proof: renewed_proof,
        lease_ticks: 30,
        reason: "same-owner workspace handoff".to_owned(),
    });
    let transfer_result = state
        .apply_batch(context(103), vec![transfer_command.clone()])
        .unwrap();
    let transfer_receipt = recorded(&transfer_result, 0);
    let transferred_proof = transfer_receipt.claim_proof().unwrap();

    let renew_replay = state
        .apply_batch(context(103), vec![renew_command])
        .unwrap();
    assert_exact_replay(renew_receipt, &renew_replay);
    let stale_workspace = state
        .apply_batch(
            context(103),
            vec![Command::Release(ReleaseRequest {
                meta: meta(4, owner, PermissionAssignment::LockCreate),
                owner,
                workspace: workspace_a,
                proof: transferred_proof,
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&stale_workspace, 0).outcome,
        OutcomeClass::StaleFence
    );

    let break_command = Command::Break(BreakRequest {
        meta: meta(5, admin, PermissionAssignment::LockForceUnlock),
        actor: admin,
        selector: BreakSelector {
            claim_id: transferred_proof.claim_id,
            authority_epoch: transferred_proof.authority_epoch,
            generation: transferred_proof.generation,
        },
        reason: "owner confirmed abandonment".to_owned(),
    });
    let break_result = state
        .apply_batch(context(103), vec![break_command.clone()])
        .unwrap();
    let break_receipt = recorded(&break_result, 0);
    assert_eq!(state.active_hard_lock_count(), 0);

    let transfer_replay = state
        .apply_batch(context(103), vec![transfer_command])
        .unwrap();
    assert_exact_replay(transfer_receipt, &transfer_replay);
    assert_eq!(state.active_hard_lock_count(), 0);
    let break_replay = state
        .apply_batch(context(103), vec![break_command])
        .unwrap();
    assert_exact_replay(break_receipt, &break_replay);
}

#[test]
fn release_replay_after_takeover_does_not_release_later_generation() {
    let owner = subject(10);
    let workspace_id = workspace(10);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let mut state = model();
    let acquired = state
        .apply_batch(
            context(101),
            vec![acquire(1, owner, workspace_id, target.clone())],
        )
        .unwrap();
    let proof = recorded(&acquired, 0).claim_proof().unwrap();
    let release_command = Command::Release(ReleaseRequest {
        meta: meta(2, owner, PermissionAssignment::LockCreate),
        owner,
        workspace: workspace_id,
        proof,
    });
    let released = state
        .apply_batch(context(101), vec![release_command.clone()])
        .unwrap();
    let release_receipt = recorded(&released, 0);
    state
        .apply_batch(
            context(101),
            vec![acquire(3, subject(11), workspace(11), target)],
        )
        .unwrap();
    let replay = state
        .apply_batch(context(101), vec![release_command])
        .unwrap();
    assert_exact_replay(release_receipt, &replay);
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn wait_replay_after_notice_never_recreates_subscription_or_reserves_lock() {
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
    let wait_command = Command::Wait(WaitRequest {
        meta: meta(2, waiter, PermissionAssignment::LockCreate),
        subject: waiter,
        workspace: workspace(11),
        target,
        lease_ticks: 30,
    });
    let waited = state
        .apply_batch(context(101), vec![wait_command.clone()])
        .unwrap();
    let wait_receipt = recorded(&waited, 0);
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
    assert_eq!(state.wait_subscription_count(), 0);
    let replay = state.apply_batch(context(101), vec![wait_command]).unwrap();
    assert_exact_replay(wait_receipt, &replay);
    assert_eq!(state.wait_subscription_count(), 0);
    assert_eq!(state.active_hard_lock_count(), 0);
}

#[test]
fn advisory_replay_after_end_never_resurrects_intent() {
    let owner = subject(10);
    let workspace_id = workspace(10);
    let begin_command = advisory(
        1,
        owner,
        workspace_id,
        file_target(file(20), "Code/main.rs", 1),
    );
    let mut state = model();
    let began = state
        .apply_batch(context(101), vec![begin_command.clone()])
        .unwrap();
    let begin_receipt = recorded(&began, 0);
    let proof = begin_receipt.claim_proof().unwrap();
    state
        .apply_batch(
            context(101),
            vec![Command::EndAdvisory(EndAdvisoryRequest {
                meta: meta(2, owner, PermissionAssignment::LockCreate),
                owner,
                workspace: workspace_id,
                proof,
            })],
        )
        .unwrap();
    assert_eq!(state.active_advisory_count(), 0);
    let replay = state
        .apply_batch(context(101), vec![begin_command])
        .unwrap();
    assert_exact_replay(begin_receipt, &replay);
    assert_eq!(state.active_advisory_count(), 0);
}

#[test]
fn expiry_request_replays_exactly_without_duplicate_event() {
    let mut state = model();
    state
        .apply_batch(
            context(100),
            vec![acquire(
                1,
                subject(10),
                workspace(10),
                file_target(file(20), "Assets/Hero.uasset", 1),
            )],
        )
        .unwrap();
    let expiry = Command::Expire(ExpiryRequest {
        idempotency_key: key(2),
        scope: scope(),
    });
    let first = state
        .apply_batch(context(120), vec![expiry.clone()])
        .unwrap();
    let first_receipt = recorded(&first, 0);
    let event_count = state.events().len();
    let replay = state.apply_batch(context(120), vec![expiry]).unwrap();
    assert_exact_replay(first_receipt, &replay);
    assert_eq!(state.events().len(), event_count);
    assert_eq!(state.active_hard_lock_count(), 0);
}

#[test]
fn acquire_replay_after_natural_expiry_returns_history_without_resurrection() {
    let command = acquire(
        1,
        subject(10),
        workspace(10),
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let mut state = model();
    let acquired = state
        .apply_batch(context(100), vec![command.clone()])
        .unwrap();
    let original = recorded(&acquired, 0);
    state
        .apply_batch(
            context(120),
            vec![Command::Expire(ExpiryRequest {
                idempotency_key: key(2),
                scope: scope(),
            })],
        )
        .unwrap();
    assert_eq!(state.active_hard_lock_count(), 0);

    let event_count = state.events().len();
    let replay = state.apply_batch(context(120), vec![command]).unwrap();
    assert_exact_replay(original, &replay);
    assert_eq!(original.server_time, 100);
    assert_eq!(recorded(&replay, 0).server_time, 100);
    assert_eq!(replay.server_time, 120);
    assert_eq!(state.active_hard_lock_count(), 0);
    assert_eq!(state.events().len(), event_count);
}
