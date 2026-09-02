mod common;

use common::*;
use ogvcs_hard_lock_model::*;

fn plan(actor: SubjectId) -> SubmitPlanBinding {
    SubmitPlanBinding {
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
    }
}

fn submit_request(
    actor: SubjectId,
    workspace_id: WorkspaceId,
    changes: Vec<SubmitChangeFact>,
    proofs: Vec<ClaimProof>,
) -> SubmitValidationRequest {
    SubmitValidationRequest {
        scope: scope(),
        authority_epoch: 7,
        subject: actor,
        workspace: workspace_id,
        permission: permission(actor, PermissionAssignment::Submit, true),
        plan: plan(actor),
        changes,
        presented_proofs: proofs,
    }
}

fn change(target: TargetInput, required: bool, value: u8) -> SubmitChangeFact {
    SubmitChangeFact {
        target,
        supplied_requires_hard_lock: required,
        requirement_digest: bytes32(value),
    }
}

fn acquire_proof(
    state: &mut LockModel,
    actor: SubjectId,
    workspace_id: WorkspaceId,
    target: TargetInput,
) -> ClaimProof {
    let result = state
        .apply_batch(context(101), vec![acquire(1, actor, workspace_id, target)])
        .unwrap();
    recorded(&result, 0).claim_proof().unwrap()
}

#[test]
fn current_owned_proof_validates_without_mutating_lock_or_event_state() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let mut state = model();
    let proof = acquire_proof(&mut state, actor, workspace_id, target.clone());
    let before = state.state_commitment();
    let events = state.events().len();
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace_id,
            vec![change(target, true, 80)],
            vec![proof],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::Compatible);
    assert_eq!(result.server_time, state.server_time());
    assert_ne!(result.lock_set_digest, [0; 32]);
    assert_eq!(state.state_commitment(), before);
    assert_eq!(state.events().len(), events);
}

#[test]
fn required_target_without_active_lock_fails_with_missing_proof() {
    let actor = subject(10);
    let state = model();
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace(10),
            vec![change(
                file_target(file(20), "Assets/Hero.uasset", 1),
                true,
                80,
            )],
            vec![],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::MissingCurrentProof);
}

#[test]
fn supplied_nonrequired_target_without_lock_is_compatible_but_not_authorized() {
    let actor = subject(10);
    let state = model();
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace(10),
            vec![change(file_target(file(20), "Code/main.rs", 1), false, 80)],
            vec![],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::Compatible);
}

#[test]
fn lock_owned_by_another_opaque_subject_is_a_privacy_neutral_conflict() {
    let owner = subject(10);
    let submitter = subject(11);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let mut state = model();
    let proof = acquire_proof(&mut state, owner, workspace(10), target.clone());
    let result = state.validate_submit_facts(
        &submit_request(
            submitter,
            workspace(11),
            vec![change(target, true, 80)],
            vec![proof],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::LockConflict);
}

#[test]
fn stale_generation_proof_is_rejected_after_renewal() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let mut state = model();
    let stale = acquire_proof(&mut state, actor, workspace_id, target.clone());
    state
        .apply_batch(
            context(102),
            vec![Command::Renew(RenewRequest {
                meta: meta(2, actor, PermissionAssignment::LockCreate),
                owner: actor,
                workspace: workspace_id,
                proof: stale,
                lease_ticks: 30,
            })],
        )
        .unwrap();
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace_id,
            vec![change(target, true, 80)],
            vec![stale],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::StaleProof);
}

#[test]
fn submit_assignment_is_only_an_opaque_supplied_fact_and_nonaffirmed_fails() {
    let actor = subject(10);
    let mut request = submit_request(
        actor,
        workspace(10),
        vec![change(file_target(file(20), "Code/main.rs", 1), false, 80)],
        vec![],
    );
    request.permission.decision = SuppliedDecision::NotAffirmed;
    let state = model();
    assert_eq!(
        state
            .validate_submit_facts(&request, SubmitValidationControl::default())
            .class,
        SubmitValidationClass::SuppliedFactRejected
    );
    request.permission.decision = SuppliedDecision::Affirmed;
    request.permission.permission = PermissionAssignment::LockCreate;
    assert_eq!(
        state
            .validate_submit_facts(&request, SubmitValidationControl::default())
            .class,
        SubmitValidationClass::SuppliedFactRejected
    );
}

#[test]
fn plan_binding_substitution_fails_before_lock_lookup() {
    let actor = subject(10);
    let mut request = submit_request(
        actor,
        workspace(10),
        vec![change(
            file_target(file(20), "Assets/Hero.uasset", 1),
            true,
            80,
        )],
        vec![],
    );
    request.plan.identity_resource_projection_digest = [0; 32];
    let state = model();
    assert_eq!(
        state
            .validate_submit_facts(&request, SubmitValidationControl::default())
            .class,
        SubmitValidationClass::InvalidInput
    );
}

#[test]
fn unused_presented_proof_is_rejected_as_extraneous() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let mut state = model();
    let proof = acquire_proof(
        &mut state,
        actor,
        workspace_id,
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace_id,
            vec![change(file_target(file(21), "Code/main.rs", 1), false, 80)],
            vec![proof],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::ExtraneousProof);
}

#[test]
fn file_id_move_uses_same_current_proof_even_with_new_path_projection() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let file_id = file(20);
    let mut state = model();
    let proof = acquire_proof(
        &mut state,
        actor,
        workspace_id,
        file_target(file_id, "Assets/Old/Hero.uasset", 1),
    );
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace_id,
            vec![change(
                file_target(file_id, "Assets/New/Hero.uasset", 2),
                true,
                80,
            )],
            vec![proof],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::Compatible);
}

#[test]
fn recreated_path_with_new_file_id_does_not_consume_old_file_proof() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let mut state = model();
    let old_proof = acquire_proof(
        &mut state,
        actor,
        workspace_id,
        file_target(file(20), "Assets/Hero.uasset", 1),
    );
    let required = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace_id,
            vec![change(
                file_target(file(21), "Assets/Hero.uasset", 2),
                true,
                80,
            )],
            vec![old_proof],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(required.class, SubmitValidationClass::MissingCurrentProof);
}

#[test]
fn prefix_lock_covers_changed_file_target() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let file_id = file(20);
    let mut state = model();
    let proof = acquire_proof(
        &mut state,
        actor,
        workspace_id,
        prefix_target("Assets", &[(file_id, "Assets/Hero.uasset")], 1),
    );
    let result = state.validate_submit_facts(
        &submit_request(
            actor,
            workspace_id,
            vec![change(
                file_target(file_id, "Assets/Hero.uasset", 1),
                true,
                80,
            )],
            vec![proof],
        ),
        SubmitValidationControl::default(),
    );
    assert_eq!(result.class, SubmitValidationClass::Compatible);
}

#[test]
fn cancellation_and_resource_limit_return_commitments_without_mutation() {
    let actor = subject(10);
    let state = model();
    let request = submit_request(
        actor,
        workspace(10),
        vec![change(
            file_target(file(20), "Assets/Hero.uasset", 1),
            false,
            80,
        )],
        vec![],
    );
    let before = state.state_commitment();
    let cancelled = state.validate_submit_facts(
        &request,
        SubmitValidationControl {
            cancelled: true,
            maximum_work_units: 100,
        },
    );
    assert_eq!(cancelled.class, SubmitValidationClass::Cancelled);
    assert!(cancelled.work_units > 0);
    assert!(cancelled.work_units <= 100);
    let limited = state.validate_submit_facts(
        &request,
        SubmitValidationControl {
            cancelled: false,
            maximum_work_units: 1,
        },
    );
    assert_eq!(limited.class, SubmitValidationClass::ResourceLimit);
    assert_eq!(state.state_commitment(), before);
}

#[test]
fn old_epoch_submit_fact_is_stale_after_promotion() {
    let actor = subject(10);
    let request = submit_request(
        actor,
        workspace(10),
        vec![change(
            file_target(file(20), "Assets/Hero.uasset", 1),
            false,
            80,
        )],
        vec![],
    );
    let mut state = model();
    state
        .promote_epoch(8, 101, TransitionControl::default())
        .unwrap();
    assert_eq!(
        state
            .validate_submit_facts(&request, SubmitValidationControl::default())
            .class,
        SubmitValidationClass::StaleAuthority
    );
}

#[test]
fn submit_work_admission_succeeds_at_exact_cost_and_never_reports_over_budget() {
    let actor = subject(10);
    let workspace_id = workspace(10);
    let target = file_target(file(20), "Assets/Hero.uasset", 1);
    let mut state = model();
    let proof = acquire_proof(&mut state, actor, workspace_id, target.clone());
    let request = submit_request(
        actor,
        workspace_id,
        vec![change(target, true, 80)],
        vec![proof],
    );
    let measured = state.validate_submit_facts(&request, SubmitValidationControl::default());
    assert_eq!(measured.class, SubmitValidationClass::Compatible);
    assert!(measured.work_units > 0);

    let exact = state.validate_submit_facts(
        &request,
        SubmitValidationControl {
            cancelled: false,
            maximum_work_units: measured.work_units,
        },
    );
    assert_eq!(exact.class, SubmitValidationClass::Compatible);
    assert_eq!(exact.work_units, measured.work_units);

    let maximum = measured.work_units - 1;
    let limited = state.validate_submit_facts(
        &request,
        SubmitValidationControl {
            cancelled: false,
            maximum_work_units: maximum,
        },
    );
    assert_eq!(limited.class, SubmitValidationClass::ResourceLimit);
    assert!(limited.work_units <= maximum);
}
