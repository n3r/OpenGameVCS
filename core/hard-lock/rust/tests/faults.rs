mod common;

use common::*;
use ogvcs_hard_lock_model::*;

fn command() -> Command {
    acquire(
        1,
        subject(10),
        workspace(10),
        file_target(file(20), "Assets/Hero.uasset", 1),
    )
}

#[test]
fn fault_boundary_assignments_match_frozen_harness_registry() {
    assert_eq!(
        FaultBoundary::PolicyDecision.registry_id(),
        "policy.decision"
    );
    assert_eq!(FaultBoundary::LockMutation.registry_id(), "lock.mutation");
    assert_eq!(
        FaultBoundary::MetadataCommit.registry_id(),
        "metadata.commit"
    );
    assert_eq!(
        FaultBoundary::EventPublication.registry_id(),
        "event.publish"
    );
}

#[test]
fn precommit_fault_actions_leave_exact_prior_state() {
    for boundary in [FaultBoundary::PolicyDecision, FaultBoundary::LockMutation] {
        for action in [
            FaultAction::CrashBefore,
            FaultAction::CrashAfter,
            FaultAction::Error,
        ] {
            let mut state = model();
            let before = state.state_commitment();
            let result = state.apply_batch_with_fault(
                context(101),
                vec![command()],
                FaultInjection { boundary, action },
            );
            assert_eq!(result, Err(BatchError::InjectedBeforeCommit));
            assert_eq!(state.state_commitment(), before);
            assert_eq!(state.active_hard_lock_count(), 0);
        }
    }
}

#[test]
fn metadata_error_and_crash_before_commit_leave_prior_state() {
    for action in [FaultAction::CrashBefore, FaultAction::Error] {
        let mut state = model();
        let before = state.state_commitment();
        let result = state.apply_batch_with_fault(
            context(101),
            vec![command()],
            FaultInjection {
                boundary: FaultBoundary::MetadataCommit,
                action,
            },
        );
        assert_eq!(result, Err(BatchError::InjectedBeforeCommit));
        assert_eq!(state.state_commitment(), before);
    }
}

#[test]
fn crash_after_metadata_commit_is_ambiguous_but_identical_retry_recovers() {
    let mut state = model();
    let request = command();
    let disposition = state
        .apply_batch_with_fault(
            context(101),
            vec![request.clone()],
            FaultInjection {
                boundary: FaultBoundary::MetadataCommit,
                action: FaultAction::CrashAfter,
            },
        )
        .unwrap();
    assert!(matches!(
        disposition,
        ApplyDisposition::AmbiguousAfterCommit { .. }
    ));
    assert_eq!(state.active_hard_lock_count(), 1);
    let events = state.events().len();
    let replay = state.apply_batch(context(101), vec![request]).unwrap();
    assert!(matches!(
        replay.results[0],
        OperationResult::Recorded { replayed: true, .. }
    ));
    assert_eq!(state.events().len(), events);
}

#[test]
fn event_publication_fault_never_rolls_back_committed_lock_or_splits_owner() {
    for action in [
        FaultAction::CrashBefore,
        FaultAction::CrashAfter,
        FaultAction::Error,
    ] {
        let mut state = model();
        let disposition = state
            .apply_batch_with_fault(
                context(101),
                vec![command()],
                FaultInjection {
                    boundary: FaultBoundary::EventPublication,
                    action,
                },
            )
            .unwrap();
        assert!(matches!(
            disposition,
            ApplyDisposition::AmbiguousAfterCommit { .. }
        ));
        assert_eq!(state.active_hard_lock_count(), 1);
        let contender = state
            .apply_batch(
                context(101),
                vec![acquire(
                    2,
                    subject(11),
                    workspace(11),
                    file_target(file(20), "Assets/Hero.uasset", 1),
                )],
            )
            .unwrap();
        assert_eq!(recorded(&contender, 0).outcome, OutcomeClass::Conflict);
        assert_eq!(state.active_hard_lock_count(), 1);
    }
}

#[test]
fn failed_fault_attempt_can_retry_without_hidden_partial_idempotency_record() {
    let mut state = model();
    state
        .apply_batch_with_fault(
            context(101),
            vec![command()],
            FaultInjection {
                boundary: FaultBoundary::LockMutation,
                action: FaultAction::CrashAfter,
            },
        )
        .unwrap_err();
    let retried = state.apply_batch(context(101), vec![command()]).unwrap();
    assert_eq!(recorded(&retried, 0).outcome, OutcomeClass::Granted);
    assert!(matches!(
        retried.results[0],
        OperationResult::Recorded {
            replayed: false,
            ..
        }
    ));
}
