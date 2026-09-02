use core::cell::Cell;

use ogvcs_cli_evidence_validator::{
    validate_evidence, ArtifactVerification, Cancellation, CapabilityFact, Commitment,
    CompatibilityEvidence, CompatibilityStatus, ContractRoute, Error, EvidenceContext,
    IdentityBinding, MaterializationEvidence, NeverCancelled, ParticipantBinding, RecoveryClass,
    RedactionStatus, SafeResultClass, ScenarioPhase, SelectionLimits, SnapshotFact, StepEvidence,
    TranscriptDisposition, ValidationLimits, Version, WorkspaceBinding, CANONICAL_COMPONENTS,
    CANONICAL_PHASES, COMPONENT_COUNT, MAX_EXCLUDED_ITEMS, MAX_RETAINED_BYTES, MAX_SELECTED_BYTES,
    MAX_SELECTED_ITEMS, MAX_WORK_UNITS, REPORT_SCHEMA_VERSION, STEP_COUNT,
    VALIDATOR_RETAINED_BYTES,
};
use ogvcs_object_model::{ObjectKind, ObjectRef};

fn commitment(seed: u8) -> Commitment {
    Commitment([seed; 32])
}

fn version(patch: u16) -> Version {
    Version {
        major: 1,
        minor: 0,
        patch,
        prerelease: 0,
    }
}

fn snapshot(seed: u8) -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [seed; 32],
    }
}

fn context() -> EvidenceContext {
    EvidenceContext {
        schema_version: REPORT_SCHEMA_VERSION,
        scenario_seed_commitment: commitment(1),
        monotonic_clock_commitment: commitment(2),
        primary: ParticipantBinding {
            workspace: WorkspaceBinding([3; 32]),
            identity: IdentityBinding([4; 32]),
        },
        secondary: ParticipantBinding {
            workspace: WorkspaceBinding([5; 32]),
            identity: IdentityBinding([6; 32]),
        },
        materialization: MaterializationEvidence {
            primary_selection_commitment: commitment(7),
            secondary_selection_commitment: commitment(8),
            selected_root_commitment: commitment(9),
            exact_byte_verification_commitment: commitment(10),
            selected_item_count: 5,
            selected_byte_count: 16_384,
            excluded_nonmaterialized_count: 7,
        },
        redaction: RedactionStatus::AllowlistVerified,
    }
}

fn components() -> [CompatibilityEvidence; COMPONENT_COUNT] {
    core::array::from_fn(|index| CompatibilityEvidence {
        component: CANONICAL_COMPONENTS[index],
        artifact_commitment: commitment(20 + index as u8),
        artifact_version: version(index as u16 + 1),
        component_commitment: commitment(40 + index as u8),
        component_version: version(index as u16 + 11),
        protocol_commitment: commitment(70),
        protocol_version: version(21),
        format_commitment: commitment(71),
        format_version: version(22),
        capability_set_commitment: commitment(80 + index as u8),
        artifact_verification: ArtifactVerification::ChecksumAndProvenanceVerified,
        compatibility: CompatibilityStatus::DeclaredCompatible,
        route: ContractRoute::PublicVersioned,
    })
}

fn steps() -> [StepEvidence; STEP_COUNT] {
    let committed = snapshot(0xa5);
    core::array::from_fn(|index| {
        let phase = CANONICAL_PHASES[index];
        let snapshot = match phase {
            ScenarioPhase::AtomicSubmit => SnapshotFact::Submitted(committed),
            ScenarioPhase::SubmitResultRecovery => SnapshotFact::SubmitResolved(committed),
            ScenarioPhase::SecondarySelectiveFetch => SnapshotFact::Fetched(committed),
            ScenarioPhase::SnapshotByteVerification => SnapshotFact::BytesVerified(committed),
            _ => SnapshotFact::None,
        };
        StepEvidence {
            phase,
            request_commitment: commitment(100 + index as u8),
            result_commitment: commitment(140 + index as u8),
            started_tick: 1_000 + index as u64 * 10,
            finished_tick: 1_005 + index as u64 * 10,
            result: SafeResultClass::Succeeded,
            recovery: RecoveryClass::None,
            capability: if phase.mutates_state() {
                CapabilityFact::VerifiedBeforeMutation
            } else {
                CapabilityFact::NotAMutation
            },
            route: ContractRoute::PublicVersioned,
            snapshot,
        }
    })
}

fn mark_not_run_after(evidence: &mut [StepEvidence], terminal_index: usize) {
    for step in &mut evidence[terminal_index + 1..] {
        step.request_commitment = Commitment([0; 32]);
        step.result_commitment = Commitment([0; 32]);
        step.started_tick = 0;
        step.finished_tick = 0;
        step.result = SafeResultClass::NotRunAfterSafeStop;
        step.recovery = RecoveryClass::None;
        step.capability = CapabilityFact::NotAMutation;
        step.snapshot = SnapshotFact::None;
    }
}

fn validate(
    context: &EvidenceContext,
    components: &[CompatibilityEvidence],
    steps: &[StepEvidence],
    limits: ValidationLimits,
) -> Result<ogvcs_cli_evidence_validator::ValidationSummary, Error> {
    validate_evidence(context, components, steps, limits, &NeverCancelled)
}

fn digest_for(
    context: &EvidenceContext,
    components: &[CompatibilityEvidence],
    steps: &[StepEvidence],
) -> [u8; 32] {
    validate(context, components, steps, ValidationLimits::fixed())
        .unwrap()
        .report_digest
        .0
}

#[test]
fn canonical_report_validates_with_fixed_summary() {
    let summary = validate(
        &context(),
        &components(),
        &steps(),
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_eq!(
        summary.disposition,
        TranscriptDisposition::AllStepsSucceededOrRecovered
    );
    assert_eq!(summary.committed_snapshot, Some(snapshot(0xa5)));
    assert_eq!(summary.first_tick, 1_000);
    assert_eq!(summary.final_tick, 1_155);
    assert_eq!(summary.elapsed_ticks, 155);
    assert_eq!(summary.component_records, COMPONENT_COUNT as u64);
    assert_eq!(summary.step_records, STEP_COUNT as u64);
    assert_eq!(summary.executed_steps, STEP_COUNT as u64);
    assert_eq!(summary.work_units, MAX_WORK_UNITS);
    assert_eq!(summary.peak_retained_bytes, VALIDATOR_RETAINED_BYTES);
}

#[test]
fn canonical_digest_is_deterministic() {
    let first = validate(
        &context(),
        &components(),
        &steps(),
        ValidationLimits::fixed(),
    )
    .unwrap();
    let second = validate(
        &context(),
        &components(),
        &steps(),
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_eq!(first.report_digest, second.report_digest);
}

#[test]
fn canonical_digest_matches_known_answer() {
    let summary = validate(
        &context(),
        &components(),
        &steps(),
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_eq!(
        hex(summary.report_digest.0),
        "274826a1cb6c0f7987c064efb8d118abb626fbd1ea4f156a1c4b55eae9f5d1e9"
    );
}

#[test]
fn a_single_semantic_change_changes_the_digest() {
    let baseline = validate(
        &context(),
        &components(),
        &steps(),
        ValidationLimits::fixed(),
    )
    .unwrap();
    let mut changed = steps();
    changed[0].result_commitment = commitment(250);
    let changed = validate(
        &context(),
        &components(),
        &changed,
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_ne!(baseline.report_digest, changed.report_digest);
}

#[test]
fn every_variable_accepted_field_is_bound_into_the_digest() {
    let baseline_context = context();
    let baseline_components = components();
    let baseline_steps = steps();
    let baseline = digest_for(&baseline_context, &baseline_components, &baseline_steps);

    macro_rules! assert_changed {
        ($context:expr, $components:expr, $steps:expr) => {
            assert_ne!(baseline, digest_for(&$context, &$components, &$steps));
        };
    }

    let mut changed_context = baseline_context;
    changed_context.scenario_seed_commitment.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.monotonic_clock_commitment.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.primary.workspace.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.primary.identity.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.secondary.workspace.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.secondary.identity.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context
        .materialization
        .primary_selection_commitment
        .0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context
        .materialization
        .secondary_selection_commitment
        .0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.materialization.selected_root_commitment.0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context
        .materialization
        .exact_byte_verification_commitment
        .0[0] ^= 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.materialization.selected_item_count += 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context.materialization.selected_byte_count += 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);
    changed_context = baseline_context;
    changed_context
        .materialization
        .excluded_nonmaterialized_count += 1;
    assert_changed!(changed_context, baseline_components, baseline_steps);

    for index in 0..COMPONENT_COUNT {
        let mut changed = baseline_components;
        changed[index].artifact_commitment.0[0] ^= 1;
        assert_changed!(baseline_context, changed, baseline_steps);
        changed = baseline_components;
        changed[index].artifact_version.patch += 100;
        assert_changed!(baseline_context, changed, baseline_steps);
        changed = baseline_components;
        changed[index].component_commitment.0[0] ^= 1;
        assert_changed!(baseline_context, changed, baseline_steps);
        changed = baseline_components;
        changed[index].component_version.patch += 100;
        assert_changed!(baseline_context, changed, baseline_steps);
        changed = baseline_components;
        changed[index].capability_set_commitment.0[0] ^= 1;
        assert_changed!(baseline_context, changed, baseline_steps);
    }

    let mut changed_components = baseline_components;
    for component in &mut changed_components {
        component.protocol_commitment.0[0] ^= 1;
    }
    assert_changed!(baseline_context, changed_components, baseline_steps);
    changed_components = baseline_components;
    for component in &mut changed_components {
        component.protocol_version.patch += 1;
    }
    assert_changed!(baseline_context, changed_components, baseline_steps);
    changed_components = baseline_components;
    for component in &mut changed_components {
        component.format_commitment.0[0] ^= 1;
    }
    assert_changed!(baseline_context, changed_components, baseline_steps);
    changed_components = baseline_components;
    for component in &mut changed_components {
        component.format_version.patch += 1;
    }
    assert_changed!(baseline_context, changed_components, baseline_steps);

    for index in 0..STEP_COUNT {
        let mut changed = baseline_steps;
        changed[index].request_commitment.0[0] ^= 1;
        assert_changed!(baseline_context, baseline_components, changed);
        changed = baseline_steps;
        changed[index].result_commitment.0[0] ^= 1;
        assert_changed!(baseline_context, baseline_components, changed);
        changed = baseline_steps;
        changed[index].started_tick += 1;
        assert_changed!(baseline_context, baseline_components, changed);
        changed = baseline_steps;
        changed[index].finished_tick += 1;
        assert_changed!(baseline_context, baseline_components, changed);
    }

    let mut changed_steps = baseline_steps;
    changed_steps[0].result = SafeResultClass::RecoveredLocalWorkPreservedAndSucceeded;
    changed_steps[0].recovery = RecoveryClass::RetrySameRequest;
    assert_changed!(baseline_context, baseline_components, changed_steps);
    changed_steps = baseline_steps;
    let changed_snapshot = snapshot(0xb6);
    changed_steps[9].snapshot = SnapshotFact::Submitted(changed_snapshot);
    changed_steps[10].snapshot = SnapshotFact::SubmitResolved(changed_snapshot);
    changed_steps[13].snapshot = SnapshotFact::Fetched(changed_snapshot);
    changed_steps[14].snapshot = SnapshotFact::BytesVerified(changed_snapshot);
    assert_changed!(baseline_context, baseline_components, changed_steps);
}

#[test]
fn operational_acceptance_limits_do_not_change_the_report_digest() {
    let baseline = validate(
        &context(),
        &components(),
        &steps(),
        ValidationLimits::fixed(),
    )
    .unwrap();
    let mut tighter = ValidationLimits::fixed();
    tighter.max_retained_bytes = VALIDATOR_RETAINED_BYTES;
    tighter.selection.max_selected_items = 5;
    tighter.selection.max_selected_bytes = 16_384;
    tighter.selection.max_excluded_items = 7;
    let bounded = validate(&context(), &components(), &steps(), tighter).unwrap();
    assert_eq!(baseline.report_digest, bounded.report_digest);
}

#[test]
fn component_cardinality_exact_succeeds_and_max_plus_one_fails() {
    let exact = components();
    assert!(validate(&context(), &exact, &steps(), ValidationLimits::fixed()).is_ok());
    let mut extra = exact.to_vec();
    extra.push(exact[0]);
    assert_eq!(
        validate(&context(), &extra, &steps(), ValidationLimits::fixed()),
        Err(Error::ComponentCountInvalid)
    );
}

#[test]
fn component_cardinality_short_fails_before_order() {
    assert_eq!(
        validate(
            &context(),
            &components()[..COMPONENT_COUNT - 1],
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::ComponentCountInvalid)
    );
}

#[test]
fn step_cardinality_exact_succeeds_and_max_plus_one_fails() {
    let exact = steps();
    assert!(validate(&context(), &components(), &exact, ValidationLimits::fixed()).is_ok());
    let mut extra = exact.to_vec();
    extra.push(exact[0]);
    assert_eq!(
        validate(&context(), &components(), &extra, ValidationLimits::fixed()),
        Err(Error::StepCountInvalid)
    );
}

#[test]
fn step_cardinality_short_fails_before_order() {
    assert_eq!(
        validate(
            &context(),
            &components(),
            &steps()[..STEP_COUNT - 1],
            ValidationLimits::fixed()
        ),
        Err(Error::StepCountInvalid)
    );
}

#[test]
fn component_order_is_exact() {
    let mut evidence = components();
    evidence.swap(2, 3);
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::ComponentOrderInvalid)
    );
}

#[test]
fn step_order_is_exact() {
    let mut evidence = steps();
    evidence.swap(7, 8);
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::StepOrderInvalid)
    );
}

#[test]
fn artifact_verification_is_mandatory() {
    let mut evidence = components();
    evidence[0].artifact_verification = ArtifactVerification::Unverified;
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::ArtifactNotVerified)
    );
}

#[test]
fn declared_compatibility_is_mandatory() {
    let mut evidence = components();
    evidence[0].compatibility = CompatibilityStatus::Unsupported;
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::CompatibilityRejected)
    );
}

#[test]
fn component_private_fallback_is_rejected() {
    let mut evidence = components();
    evidence[0].route = ContractRoute::PrivateFallback;
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::PrivateFallbackForbidden)
    );
}

#[test]
fn step_private_fallback_is_rejected() {
    let mut evidence = steps();
    evidence[7].route = ContractRoute::PrivateFallback;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::PrivateFallbackForbidden)
    );
}

#[test]
fn protocol_commitment_and_version_are_shared() {
    let mut evidence = components();
    evidence[4].protocol_version.patch += 1;
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::ProtocolCompatibilityMismatch)
    );
}

#[test]
fn format_commitment_and_version_are_shared() {
    let mut evidence = components();
    evidence[4].format_commitment = commitment(99);
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::FormatCompatibilityMismatch)
    );
}

#[test]
fn all_zero_versions_are_rejected() {
    let mut evidence = components();
    evidence[0].component_version = Version {
        major: 0,
        minor: 0,
        patch: 0,
        prerelease: 0,
    };
    assert_eq!(
        validate(&context(), &evidence, &steps(), ValidationLimits::fixed()),
        Err(Error::VersionInvalid)
    );
}

#[test]
fn prerelease_number_is_a_valid_nonzero_version() {
    let mut evidence = components();
    for item in &mut evidence {
        item.protocol_version = Version {
            major: 0,
            minor: 0,
            patch: 0,
            prerelease: 1,
        };
    }
    assert!(validate(&context(), &evidence, &steps(), ValidationLimits::fixed()).is_ok());
}

#[test]
fn mutating_step_requires_prechecked_capability() {
    let mut evidence = steps();
    evidence[2].capability = CapabilityFact::NotAMutation;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::CapabilityFactMismatch)
    );
}

#[test]
fn nonmutating_step_cannot_claim_mutation() {
    let mut evidence = steps();
    evidence[7].capability = CapabilityFact::VerifiedBeforeMutation;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::CapabilityFactMismatch)
    );
}

#[test]
fn timings_require_finish_not_before_start() {
    let mut evidence = steps();
    evidence[3].finished_tick = evidence[3].started_tick - 1;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::TimingNotMonotonic)
    );
}

#[test]
fn timings_require_global_monotonicity() {
    let mut evidence = steps();
    evidence[3].started_tick = evidence[2].finished_tick - 1;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::TimingNotMonotonic)
    );
}

#[test]
fn zero_duration_is_monotonic() {
    let mut evidence = steps();
    evidence[0].finished_tick = evidence[0].started_tick;
    assert!(validate(
        &context(),
        &components(),
        &evidence,
        ValidationLimits::fixed()
    )
    .is_ok());
}

#[test]
fn full_u64_monotonic_timing_is_portable_and_overflow_safe() {
    let mut evidence = steps();
    let first = u64::MAX - (2 * STEP_COUNT as u64 - 1);
    for (index, step) in evidence.iter_mut().enumerate() {
        step.started_tick = first + 2 * index as u64;
        step.finished_tick = step.started_tick + 1;
    }
    let summary = validate(
        &context(),
        &components(),
        &evidence,
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_eq!(summary.first_tick, first);
    assert_eq!(summary.final_tick, u64::MAX);
    assert_eq!(summary.elapsed_ticks, 2 * STEP_COUNT as u64 - 1);
}

#[test]
fn success_cannot_name_a_recovery() {
    let mut evidence = steps();
    evidence[0].recovery = RecoveryClass::RetrySameRequest;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::ResultRecoveryMismatch)
    );
}

#[test]
fn recovered_result_requires_a_recovery() {
    let mut evidence = steps();
    evidence[0].result = SafeResultClass::RecoveredLocalWorkPreservedAndSucceeded;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::ResultRecoveryMismatch)
    );
}

#[test]
fn cancellation_result_requires_resume_recovery() {
    let mut evidence = steps();
    evidence[0].result = SafeResultClass::CancelledLocalWorkPreserved;
    evidence[0].recovery = RecoveryClass::RetrySameRequest;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::ResultRecoveryMismatch)
    );
}

fn expected_recovery_phase(recovery: RecoveryClass, phase: ScenarioPhase) -> bool {
    match recovery {
        RecoveryClass::None
        | RecoveryClass::RetrySameRequest
        | RecoveryClass::ResumeAfterCancellation => true,
        RecoveryClass::ResolveOriginalSubmit | RecoveryClass::RefreshBranchAndRestage => matches!(
            phase,
            ScenarioPhase::AtomicSubmit | ScenarioPhase::SubmitResultRecovery
        ),
        RecoveryClass::Reauthenticate => matches!(
            phase,
            ScenarioPhase::PrimaryAuthentication
                | ScenarioPhase::RepositoryBootstrap
                | ScenarioPhase::PrimaryWorkspaceCreate
                | ScenarioPhase::PrimarySelectiveSync
                | ScenarioPhase::PrimaryStatus
                | ScenarioPhase::PrimaryHardLockEdit
                | ScenarioPhase::AtomicSubmit
                | ScenarioPhase::SubmitResultRecovery
                | ScenarioPhase::SecondaryAuthentication
                | ScenarioPhase::SecondaryWorkspaceCreate
                | ScenarioPhase::SecondarySelectiveFetch
        ),
        RecoveryClass::ReacquireLock => matches!(
            phase,
            ScenarioPhase::PrimaryHardLockEdit | ScenarioPhase::AtomicSubmit
        ),
        RecoveryClass::RefetchVerifiedContent => matches!(
            phase,
            ScenarioPhase::PrimarySelectiveSync
                | ScenarioPhase::SecondarySelectiveFetch
                | ScenarioPhase::SnapshotByteVerification
        ),
        RecoveryClass::FreeDiskAndResume => matches!(
            phase,
            ScenarioPhase::CleanHostInstall
                | ScenarioPhase::PrimaryWorkspaceCreate
                | ScenarioPhase::PrimarySelectiveSync
                | ScenarioPhase::PrimaryHardLockEdit
                | ScenarioPhase::AtomicSubmit
                | ScenarioPhase::SecondaryWorkspaceCreate
                | ScenarioPhase::SecondarySelectiveFetch
                | ScenarioPhase::RedactedEvidenceFinalize
        ),
    }
}

#[test]
fn recovery_phase_matrix_is_exhaustive() {
    const RECOVERIES: [RecoveryClass; 8] = [
        RecoveryClass::RetrySameRequest,
        RecoveryClass::ResolveOriginalSubmit,
        RecoveryClass::Reauthenticate,
        RecoveryClass::RefreshBranchAndRestage,
        RecoveryClass::ReacquireLock,
        RecoveryClass::RefetchVerifiedContent,
        RecoveryClass::FreeDiskAndResume,
        RecoveryClass::ResumeAfterCancellation,
    ];
    const EXPECTED_ALLOWED_PHASES: [usize; 8] = [16, 2, 11, 2, 2, 3, 8, 16];

    for (recovery_index, recovery) in RECOVERIES.into_iter().enumerate() {
        let mut allowed_phases = 0;
        for (index, phase) in CANONICAL_PHASES.into_iter().enumerate() {
            let mut evidence = steps();
            evidence[index].recovery = recovery;
            if recovery == RecoveryClass::ResumeAfterCancellation {
                evidence[index].result = SafeResultClass::CancelledLocalWorkPreserved;
                evidence[index].snapshot = SnapshotFact::None;
                mark_not_run_after(&mut evidence, index);
            } else {
                evidence[index].result = SafeResultClass::RecoveredLocalWorkPreservedAndSucceeded;
            }

            let actual = validate(
                &context(),
                &components(),
                &evidence,
                ValidationLimits::fixed(),
            );
            if expected_recovery_phase(recovery, phase) {
                allowed_phases += 1;
                assert!(
                    actual.is_ok(),
                    "expected {recovery:?} to be allowed for {phase:?}, got {actual:?}"
                );
            } else {
                assert_eq!(
                    actual,
                    Err(Error::RecoveryPhaseMismatch),
                    "expected {recovery:?} to be rejected for {phase:?}"
                );
            }
        }
        assert_eq!(allowed_phases, EXPECTED_ALLOWED_PHASES[recovery_index]);
    }
}

#[test]
fn submit_resolution_recovery_is_phase_scoped() {
    let mut evidence = steps();
    evidence[0].result = SafeResultClass::RecoveredLocalWorkPreservedAndSucceeded;
    evidence[0].recovery = RecoveryClass::ResolveOriginalSubmit;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::RecoveryPhaseMismatch)
    );
}

#[test]
fn recovered_submit_can_bind_the_same_snapshot() {
    let mut evidence = steps();
    evidence[9].result = SafeResultClass::RecoveredLocalWorkPreservedAndSucceeded;
    evidence[9].recovery = RecoveryClass::ResolveOriginalSubmit;
    let summary = validate(
        &context(),
        &components(),
        &evidence,
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_eq!(
        summary.disposition,
        TranscriptDisposition::AllStepsSucceededOrRecovered
    );
}

#[test]
fn safe_terminal_result_produces_an_incomplete_disposition() {
    let mut evidence = steps();
    evidence[7].result = SafeResultClass::FailedClosedNoMutation;
    evidence[7].recovery = RecoveryClass::RetrySameRequest;
    mark_not_run_after(&mut evidence, 7);
    let summary = validate(
        &context(),
        &components(),
        &evidence,
        ValidationLimits::fixed(),
    )
    .unwrap();
    assert_eq!(
        summary.disposition,
        TranscriptDisposition::SafeTerminalResultPresent
    );
    assert_eq!(summary.first_tick, 1_000);
    assert_eq!(summary.final_tick, 1_075);
    assert_eq!(summary.elapsed_ticks, 75);
    assert_eq!(summary.component_records, COMPONENT_COUNT as u64);
    assert_eq!(summary.step_records, STEP_COUNT as u64);
    assert_eq!(summary.executed_steps, 8);
}

#[test]
fn skipped_steps_require_canonical_absent_evidence() {
    let mut evidence = steps();
    evidence[7].result = SafeResultClass::FailedClosedNoMutation;
    evidence[7].recovery = RecoveryClass::RetrySameRequest;
    mark_not_run_after(&mut evidence, 7);
    evidence[8].request_commitment = commitment(108);
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SkippedStepEvidenceInvalid)
    );
    evidence[8].request_commitment = Commitment([0; 32]);
    evidence[8].started_tick = 1_080;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SkippedStepEvidenceInvalid)
    );
}

#[test]
fn completed_step_after_a_safe_stop_is_rejected() {
    let mut evidence = steps();
    evidence[7].result = SafeResultClass::FailedClosedNoMutation;
    evidence[7].recovery = RecoveryClass::RetrySameRequest;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::StepAfterTerminalResult)
    );
}

#[test]
fn not_run_result_requires_a_prior_safe_stop() {
    let mut evidence = steps();
    evidence[0].result = SafeResultClass::NotRunAfterSafeStop;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::StepAfterTerminalResult)
    );
}

#[test]
fn noncompletion_step_cannot_claim_a_snapshot() {
    let mut evidence = steps();
    evidence[9].result = SafeResultClass::FailedClosedNoMutation;
    evidence[9].recovery = RecoveryClass::ResolveOriginalSubmit;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SnapshotFactMismatch)
    );
}

#[test]
fn completed_snapshot_phase_requires_its_exact_fact() {
    let mut evidence = steps();
    evidence[9].snapshot = SnapshotFact::None;
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SnapshotFactMismatch)
    );
}

#[test]
fn snapshot_fact_is_phase_typed() {
    let mut evidence = steps();
    evidence[9].snapshot = SnapshotFact::Fetched(snapshot(0xa5));
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SnapshotFactMismatch)
    );
}

#[test]
fn snapshot_reference_uses_ogvcs_002_kind() {
    let mut evidence = steps();
    evidence[9].snapshot = SnapshotFact::Submitted(ObjectRef {
        kind: ObjectKind::Tree,
        digest: [0xa5; 32],
    });
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SnapshotKindInvalid)
    );
}

#[test]
fn submit_fetch_and_verification_snapshot_must_match() {
    let mut evidence = steps();
    evidence[13].snapshot = SnapshotFact::Fetched(snapshot(0xb6));
    assert_eq!(
        validate(
            &context(),
            &components(),
            &evidence,
            ValidationLimits::fixed()
        ),
        Err(Error::SnapshotIdentityMismatch)
    );
}

#[test]
fn participant_workspaces_cannot_alias() {
    let mut evidence = context();
    evidence.secondary.workspace = evidence.primary.workspace;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::ParticipantBindingAliased)
    );
}

#[test]
fn participant_identities_cannot_alias() {
    let mut evidence = context();
    evidence.secondary.identity = evidence.primary.identity;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::ParticipantBindingAliased)
    );
}

#[test]
fn participant_binding_kinds_cannot_alias() {
    let mut evidence = context();
    evidence.secondary.identity = IdentityBinding(evidence.primary.workspace.0);
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::ParticipantBindingAliased)
    );
}

#[test]
fn selections_must_be_distinct_opaque_commitments() {
    let mut evidence = context();
    evidence.materialization.secondary_selection_commitment =
        evidence.materialization.primary_selection_commitment;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SelectionBindingAliased)
    );
}

#[test]
fn materialization_commitment_purposes_cannot_alias() {
    let mut evidence = context();
    evidence.materialization.selected_root_commitment =
        evidence.materialization.primary_selection_commitment;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SelectionBindingAliased)
    );
}

#[test]
fn selected_and_excluded_counts_are_nonzero() {
    let mut evidence = context();
    evidence.materialization.excluded_nonmaterialized_count = 0;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SelectionCountInvalid)
    );
}

#[test]
fn redaction_must_be_allowlist_verified() {
    let mut evidence = context();
    evidence.redaction = RedactionStatus::Unverified;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::RedactionNotVerified)
    );
    evidence.redaction = RedactionStatus::SensitiveMaterialDetected;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::RedactionNotVerified)
    );
}

#[test]
fn opaque_bindings_are_redacted_from_debug_output() {
    let rendered = format!("{:?}", context());
    assert!(rendered.contains("Commitment([REDACTED])"));
    assert!(rendered.contains("WorkspaceBinding([REDACTED])"));
    assert!(rendered.contains("IdentityBinding([REDACTED])"));
    assert!(!rendered.contains("[1, 1, 1"));
    assert!(!rendered.contains("[3, 3, 3"));
    assert!(!rendered.contains("[4, 4, 4"));
}

#[test]
fn zero_commitment_is_rejected() {
    let mut evidence = context();
    evidence.monotonic_clock_commitment = Commitment([0; 32]);
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::CommitmentInvalid)
    );
}

#[test]
fn schema_version_is_exact() {
    let mut evidence = context();
    evidence.schema_version += 1;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SchemaVersionUnsupported)
    );
}

#[test]
fn selected_item_bound_exact_succeeds_and_max_plus_one_fails() {
    let mut evidence = context();
    evidence.materialization.selected_item_count = MAX_SELECTED_ITEMS;
    assert!(validate(
        &evidence,
        &components(),
        &steps(),
        ValidationLimits::fixed()
    )
    .is_ok());
    evidence.materialization.selected_item_count = MAX_SELECTED_ITEMS + 1;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SelectionLimitExceeded)
    );
}

#[test]
fn selected_byte_bound_exact_succeeds_and_max_plus_one_fails() {
    let mut evidence = context();
    evidence.materialization.selected_byte_count = MAX_SELECTED_BYTES;
    assert!(validate(
        &evidence,
        &components(),
        &steps(),
        ValidationLimits::fixed()
    )
    .is_ok());
    evidence.materialization.selected_byte_count = MAX_SELECTED_BYTES + 1;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SelectionLimitExceeded)
    );
}

#[test]
fn excluded_count_bound_exact_succeeds_and_max_plus_one_fails() {
    let mut evidence = context();
    evidence.materialization.excluded_nonmaterialized_count = MAX_EXCLUDED_ITEMS;
    assert!(validate(
        &evidence,
        &components(),
        &steps(),
        ValidationLimits::fixed()
    )
    .is_ok());
    evidence.materialization.excluded_nonmaterialized_count = MAX_EXCLUDED_ITEMS + 1;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::SelectionLimitExceeded)
    );
}

#[test]
fn selection_limit_configuration_max_plus_one_fails() {
    let mut limits = ValidationLimits::fixed();
    limits.selection = SelectionLimits {
        max_selected_items: MAX_SELECTED_ITEMS + 1,
        ..limits.selection
    };
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::LimitExceedsHardMaximum)
    );
}

#[test]
fn selection_addition_is_checked() {
    let mut evidence = context();
    evidence.materialization.selected_item_count = u64::MAX;
    evidence.materialization.excluded_nonmaterialized_count = 1;
    assert_eq!(
        validate(
            &evidence,
            &components(),
            &steps(),
            ValidationLimits::fixed()
        ),
        Err(Error::ArithmeticOverflow)
    );
}

#[test]
fn work_bound_exact_succeeds_and_one_less_fails() {
    let exact = ValidationLimits::fixed();
    assert_eq!(exact.max_work_units, MAX_WORK_UNITS);
    assert!(validate(&context(), &components(), &steps(), exact).is_ok());
    let mut short = exact;
    short.max_work_units -= 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), short),
        Err(Error::WorkLimitExceeded)
    );
}

#[test]
fn work_bound_max_plus_one_is_rejected() {
    let mut limits = ValidationLimits::fixed();
    limits.max_work_units = MAX_WORK_UNITS + 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::LimitExceedsHardMaximum)
    );
}

#[test]
fn retained_memory_exact_succeeds_and_one_less_fails() {
    let mut exact = ValidationLimits::fixed();
    exact.max_retained_bytes = VALIDATOR_RETAINED_BYTES;
    assert!(validate(&context(), &components(), &steps(), exact).is_ok());
    let mut short = exact;
    short.max_retained_bytes -= 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), short),
        Err(Error::RetainedMemoryLimitExceeded)
    );
}

#[test]
fn retained_memory_max_plus_one_is_rejected() {
    let mut limits = ValidationLimits::fixed();
    limits.max_retained_bytes = MAX_RETAINED_BYTES + 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::LimitExceedsHardMaximum)
    );
}

#[test]
fn component_and_step_limit_max_plus_one_are_rejected() {
    let mut limits = ValidationLimits::fixed();
    limits.max_components = COMPONENT_COUNT as u64 + 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::LimitExceedsHardMaximum)
    );
    limits = ValidationLimits::fixed();
    limits.max_steps = STEP_COUNT as u64 + 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::LimitExceedsHardMaximum)
    );
}

#[test]
fn component_and_step_limits_below_fixed_counts_fail() {
    let mut limits = ValidationLimits::fixed();
    limits.max_components -= 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::CountExceedsLimit)
    );
    limits = ValidationLimits::fixed();
    limits.max_steps -= 1;
    assert_eq!(
        validate(&context(), &components(), &steps(), limits),
        Err(Error::CountExceedsLimit)
    );
}

struct CancelAfter {
    remaining_successful_checks: Cell<u64>,
}

impl Cancellation for CancelAfter {
    fn is_cancelled(&self) -> bool {
        let remaining = self.remaining_successful_checks.get();
        if remaining == 0 {
            true
        } else {
            self.remaining_successful_checks.set(remaining - 1);
            false
        }
    }
}

#[test]
fn cancellation_before_validation_returns_no_summary() {
    let cancellation = CancelAfter {
        remaining_successful_checks: Cell::new(0),
    };
    assert_eq!(
        validate_evidence(
            &context(),
            &components(),
            &steps(),
            ValidationLimits::fixed(),
            &cancellation
        ),
        Err(Error::Cancelled)
    );
}

#[test]
fn cancellation_during_components_returns_no_summary() {
    let cancellation = CancelAfter {
        remaining_successful_checks: Cell::new(4),
    };
    assert_eq!(
        validate_evidence(
            &context(),
            &components(),
            &steps(),
            ValidationLimits::fixed(),
            &cancellation
        ),
        Err(Error::Cancelled)
    );
}

#[test]
fn cancellation_during_steps_returns_no_summary() {
    let cancellation = CancelAfter {
        remaining_successful_checks: Cell::new(12),
    };
    assert_eq!(
        validate_evidence(
            &context(),
            &components(),
            &steps(),
            ValidationLimits::fixed(),
            &cancellation
        ),
        Err(Error::Cancelled)
    );
}

#[test]
fn final_cancellation_fence_returns_no_summary() {
    let cancellation = CancelAfter {
        remaining_successful_checks: Cell::new(1 + COMPONENT_COUNT as u64 + STEP_COUNT as u64),
    };
    assert_eq!(
        validate_evidence(
            &context(),
            &components(),
            &steps(),
            ValidationLimits::fixed(),
            &cancellation
        ),
        Err(Error::Cancelled)
    );
}

#[test]
fn cancellation_after_digest_before_release_returns_no_summary() {
    let cancellation = CancelAfter {
        remaining_successful_checks: Cell::new(2 + COMPONENT_COUNT as u64 + STEP_COUNT as u64),
    };
    assert_eq!(
        validate_evidence(
            &context(),
            &components(),
            &steps(),
            ValidationLimits::fixed(),
            &cancellation
        ),
        Err(Error::Cancelled)
    );
}

fn hex(bytes: [u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(ALPHABET[(byte >> 4) as usize] as char);
        output.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    output
}
