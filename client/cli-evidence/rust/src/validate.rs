use ogvcs_object_model::{ObjectKind, ObjectRef};

use crate::transcript::Transcript;
use crate::{
    ArtifactVerification, Cancellation, CapabilityFact, Commitment, CompatibilityEvidence,
    CompatibilityStatus, ContractRoute, Error, EvidenceContext, RecoveryClass, RedactionStatus,
    Result, SafeResultClass, ScenarioPhase, SnapshotFact, StepEvidence, TranscriptDisposition,
    ValidationLimits, ValidationSummary, Version, CANONICAL_COMPONENTS, CANONICAL_PHASES,
    COMPONENT_COUNT, MAX_EXCLUDED_ITEMS, MAX_RETAINED_BYTES, MAX_SELECTED_BYTES,
    MAX_SELECTED_ITEMS, MAX_WORK_UNITS, REPORT_SCHEMA_VERSION, STEP_COUNT,
    VALIDATOR_RETAINED_BYTES,
};

const HEADER_WORK: u64 = 12;
const COMPONENT_WORK: u64 = 11;
const STEP_WORK: u64 = 13;
const FINAL_WORK: u64 = 12;

struct WorkBudget {
    remaining: u64,
    used: u64,
}

impl WorkBudget {
    fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            used: 0,
        }
    }

    fn charge(&mut self, amount: u64) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(Error::WorkLimitExceeded)?;
        self.used = self
            .used
            .checked_add(amount)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(())
    }
}

pub fn validate_evidence<C: Cancellation>(
    context: &EvidenceContext,
    components: &[CompatibilityEvidence],
    steps: &[StepEvidence],
    limits: ValidationLimits,
    cancellation: &C,
) -> Result<ValidationSummary> {
    validate_limits(limits)?;
    if components.len() != COMPONENT_COUNT {
        return Err(Error::ComponentCountInvalid);
    }
    if steps.len() != STEP_COUNT {
        return Err(Error::StepCountInvalid);
    }
    if components.len() as u64 > limits.max_components || steps.len() as u64 > limits.max_steps {
        return Err(Error::CountExceedsLimit);
    }
    check_cancelled(cancellation)?;

    let mut budget = WorkBudget::new(limits.max_work_units);
    budget.charge(HEADER_WORK)?;
    validate_context(context, limits)?;
    let mut transcript = Transcript::new();
    hash_context(&mut transcript, context);

    let mut expected_protocol: Option<(Commitment, Version)> = None;
    let mut expected_format: Option<(Commitment, Version)> = None;
    for (index, evidence) in components.iter().enumerate() {
        check_cancelled(cancellation)?;
        budget.charge(COMPONENT_WORK)?;
        validate_component(
            index,
            evidence,
            &mut expected_protocol,
            &mut expected_format,
        )?;
        hash_component(&mut transcript, evidence);
    }

    let mut prior_finish = None;
    let mut first_tick = None;
    let mut snapshots: [Option<ObjectRef>; 4] = [None; 4];
    let mut has_safe_terminal = false;
    let mut terminal_seen = false;
    let mut executed_steps = 0_u64;
    for (index, step) in steps.iter().enumerate() {
        check_cancelled(cancellation)?;
        budget.charge(STEP_WORK)?;
        validate_step(index, step, prior_finish, terminal_seen, &mut snapshots)?;
        if step.result != SafeResultClass::NotRunAfterSafeStop {
            executed_steps = executed_steps
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
            first_tick.get_or_insert(step.started_tick);
            prior_finish = Some(step.finished_tick);
        }
        if matches!(
            step.result,
            SafeResultClass::FailedClosedNoMutation | SafeResultClass::CancelledLocalWorkPreserved
        ) {
            terminal_seen = true;
            has_safe_terminal = true;
        }
        hash_step(&mut transcript, step);
    }

    check_cancelled(cancellation)?;
    budget.charge(FINAL_WORK)?;
    let disposition = if has_safe_terminal {
        TranscriptDisposition::SafeTerminalResultPresent
    } else {
        if snapshots.iter().any(Option::is_none) {
            return Err(Error::SnapshotFactMismatch);
        }
        TranscriptDisposition::AllStepsSucceededOrRecovered
    };
    let committed_snapshot = common_snapshot(&snapshots)?;
    let first_tick = first_tick.ok_or(Error::StepCountInvalid)?;
    let final_tick = prior_finish.ok_or(Error::StepCountInvalid)?;
    let elapsed_ticks = final_tick
        .checked_sub(first_tick)
        .ok_or(Error::ArithmeticOverflow)?;
    transcript.section(4);
    transcript.u8(match disposition {
        TranscriptDisposition::AllStepsSucceededOrRecovered => 1,
        TranscriptDisposition::SafeTerminalResultPresent => 2,
    });
    transcript.u64(budget.used);
    transcript.u64(VALIDATOR_RETAINED_BYTES);
    transcript.u64(components.len() as u64);
    transcript.u64(steps.len() as u64);
    transcript.u64(executed_steps);
    transcript.u64(first_tick);
    transcript.u64(final_tick);
    transcript.u64(elapsed_ticks);
    match committed_snapshot {
        Some(reference) => transcript.snapshot(5, reference.kind.code(), reference.digest),
        None => transcript.u8(0),
    }

    let report_digest = transcript.finish();
    check_cancelled(cancellation)?;

    Ok(ValidationSummary {
        report_digest,
        disposition,
        committed_snapshot,
        first_tick,
        final_tick,
        elapsed_ticks,
        component_records: components.len() as u64,
        step_records: steps.len() as u64,
        executed_steps,
        work_units: budget.used,
        peak_retained_bytes: VALIDATOR_RETAINED_BYTES,
    })
}

fn validate_limits(limits: ValidationLimits) -> Result<()> {
    if limits.max_components > COMPONENT_COUNT as u64
        || limits.max_steps > STEP_COUNT as u64
        || limits.max_work_units > MAX_WORK_UNITS
        || limits.max_retained_bytes > MAX_RETAINED_BYTES
        || limits.selection.max_selected_items > MAX_SELECTED_ITEMS
        || limits.selection.max_selected_bytes > MAX_SELECTED_BYTES
        || limits.selection.max_excluded_items > MAX_EXCLUDED_ITEMS
    {
        return Err(Error::LimitExceedsHardMaximum);
    }
    if limits.max_retained_bytes < VALIDATOR_RETAINED_BYTES {
        return Err(Error::RetainedMemoryLimitExceeded);
    }
    Ok(())
}

fn validate_context(context: &EvidenceContext, limits: ValidationLimits) -> Result<()> {
    if context.schema_version != REPORT_SCHEMA_VERSION {
        return Err(Error::SchemaVersionUnsupported);
    }
    validate_commitment(context.scenario_seed_commitment)?;
    validate_commitment(context.monotonic_clock_commitment)?;
    validate_nonzero(&context.primary.workspace.0)?;
    validate_nonzero(&context.primary.identity.0)?;
    validate_nonzero(&context.secondary.workspace.0)?;
    validate_nonzero(&context.secondary.identity.0)?;
    if context.primary.workspace == context.secondary.workspace
        || context.primary.identity == context.secondary.identity
        || context.primary.workspace.0 == context.primary.identity.0
        || context.primary.workspace.0 == context.secondary.identity.0
        || context.secondary.workspace.0 == context.primary.identity.0
        || context.secondary.workspace.0 == context.secondary.identity.0
    {
        return Err(Error::ParticipantBindingAliased);
    }
    let materialization = context.materialization;
    validate_commitment(materialization.primary_selection_commitment)?;
    validate_commitment(materialization.secondary_selection_commitment)?;
    validate_commitment(materialization.selected_root_commitment)?;
    validate_commitment(materialization.exact_byte_verification_commitment)?;
    if materialization.primary_selection_commitment
        == materialization.secondary_selection_commitment
        || materialization.primary_selection_commitment == materialization.selected_root_commitment
        || materialization.primary_selection_commitment
            == materialization.exact_byte_verification_commitment
        || materialization.secondary_selection_commitment
            == materialization.selected_root_commitment
        || materialization.secondary_selection_commitment
            == materialization.exact_byte_verification_commitment
        || materialization.selected_root_commitment
            == materialization.exact_byte_verification_commitment
    {
        return Err(Error::SelectionBindingAliased);
    }
    if materialization.selected_item_count == 0
        || materialization.selected_byte_count == 0
        || materialization.excluded_nonmaterialized_count == 0
    {
        return Err(Error::SelectionCountInvalid);
    }
    let declared_items = materialization
        .selected_item_count
        .checked_add(materialization.excluded_nonmaterialized_count)
        .ok_or(Error::ArithmeticOverflow)?;
    if materialization.selected_item_count > limits.selection.max_selected_items
        || materialization.selected_byte_count > limits.selection.max_selected_bytes
        || materialization.excluded_nonmaterialized_count > limits.selection.max_excluded_items
        || declared_items
            > limits
                .selection
                .max_selected_items
                .checked_add(limits.selection.max_excluded_items)
                .ok_or(Error::ArithmeticOverflow)?
    {
        return Err(Error::SelectionLimitExceeded);
    }
    if context.redaction != RedactionStatus::AllowlistVerified {
        return Err(Error::RedactionNotVerified);
    }
    Ok(())
}

fn validate_component(
    index: usize,
    evidence: &CompatibilityEvidence,
    expected_protocol: &mut Option<(Commitment, Version)>,
    expected_format: &mut Option<(Commitment, Version)>,
) -> Result<()> {
    if evidence.component != CANONICAL_COMPONENTS[index] {
        return Err(Error::ComponentOrderInvalid);
    }
    validate_commitment(evidence.artifact_commitment)?;
    validate_commitment(evidence.component_commitment)?;
    validate_commitment(evidence.protocol_commitment)?;
    validate_commitment(evidence.format_commitment)?;
    validate_commitment(evidence.capability_set_commitment)?;
    validate_version(evidence.artifact_version)?;
    validate_version(evidence.component_version)?;
    validate_version(evidence.protocol_version)?;
    validate_version(evidence.format_version)?;
    if evidence.artifact_verification != ArtifactVerification::ChecksumAndProvenanceVerified {
        return Err(Error::ArtifactNotVerified);
    }
    if evidence.compatibility != CompatibilityStatus::DeclaredCompatible {
        return Err(Error::CompatibilityRejected);
    }
    if evidence.route != ContractRoute::PublicVersioned {
        return Err(Error::PrivateFallbackForbidden);
    }

    let protocol = (evidence.protocol_commitment, evidence.protocol_version);
    match expected_protocol {
        Some(expected) if *expected != protocol => {
            return Err(Error::ProtocolCompatibilityMismatch)
        }
        None => *expected_protocol = Some(protocol),
        _ => {}
    }
    let format = (evidence.format_commitment, evidence.format_version);
    match expected_format {
        Some(expected) if *expected != format => return Err(Error::FormatCompatibilityMismatch),
        None => *expected_format = Some(format),
        _ => {}
    }
    Ok(())
}

fn validate_step(
    index: usize,
    step: &StepEvidence,
    prior_finish: Option<u64>,
    terminal_seen: bool,
    snapshots: &mut [Option<ObjectRef>; 4],
) -> Result<()> {
    if step.phase != CANONICAL_PHASES[index] {
        return Err(Error::StepOrderInvalid);
    }
    if step.result == SafeResultClass::NotRunAfterSafeStop {
        if !terminal_seen {
            return Err(Error::StepAfterTerminalResult);
        }
        validate_result_recovery(step)?;
        if step.request_commitment.0 != [0; 32]
            || step.result_commitment.0 != [0; 32]
            || step.started_tick != 0
            || step.finished_tick != 0
            || step.capability != CapabilityFact::NotAMutation
            || step.snapshot != SnapshotFact::None
        {
            return Err(Error::SkippedStepEvidenceInvalid);
        }
        if step.route != ContractRoute::PublicVersioned {
            return Err(Error::PrivateFallbackForbidden);
        }
        return Ok(());
    }
    validate_commitment(step.request_commitment)?;
    validate_commitment(step.result_commitment)?;
    if step.finished_tick < step.started_tick
        || prior_finish.is_some_and(|prior| step.started_tick < prior)
    {
        return Err(Error::TimingNotMonotonic);
    }
    validate_result_recovery(step)?;
    if terminal_seen {
        return Err(Error::StepAfterTerminalResult);
    }
    if step.route != ContractRoute::PublicVersioned {
        return Err(Error::PrivateFallbackForbidden);
    }
    let expected_capability = if step.phase.mutates_state() {
        CapabilityFact::VerifiedBeforeMutation
    } else {
        CapabilityFact::NotAMutation
    };
    if step.capability != expected_capability {
        return Err(Error::CapabilityFactMismatch);
    }
    validate_snapshot_fact(step, snapshots)
}

fn validate_result_recovery(step: &StepEvidence) -> Result<()> {
    match (step.result, step.recovery) {
        (SafeResultClass::Succeeded, RecoveryClass::None) => {}
        (SafeResultClass::RecoveredLocalWorkPreservedAndSucceeded, recovery)
        | (SafeResultClass::FailedClosedNoMutation, recovery)
            if recovery != RecoveryClass::None => {}
        (SafeResultClass::CancelledLocalWorkPreserved, RecoveryClass::ResumeAfterCancellation) => {}
        (SafeResultClass::NotRunAfterSafeStop, RecoveryClass::None) => {}
        _ => return Err(Error::ResultRecoveryMismatch),
    }
    if !recovery_allowed_for_phase(step.recovery, step.phase) {
        return Err(Error::RecoveryPhaseMismatch);
    }
    Ok(())
}

const fn recovery_allowed_for_phase(recovery: RecoveryClass, phase: ScenarioPhase) -> bool {
    match recovery {
        RecoveryClass::None
        | RecoveryClass::RetrySameRequest
        | RecoveryClass::ResumeAfterCancellation => true,
        RecoveryClass::ResolveOriginalSubmit => matches!(
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
        RecoveryClass::RefreshBranchAndRestage => matches!(
            phase,
            ScenarioPhase::AtomicSubmit | ScenarioPhase::SubmitResultRecovery
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

fn validate_snapshot_fact(
    step: &StepEvidence,
    snapshots: &mut [Option<ObjectRef>; 4],
) -> Result<()> {
    if !step.result.completed() {
        return if step.snapshot == SnapshotFact::None {
            Ok(())
        } else {
            Err(Error::SnapshotFactMismatch)
        };
    }
    let (slot, reference) = match (step.phase, step.snapshot) {
        (ScenarioPhase::AtomicSubmit, SnapshotFact::Submitted(reference)) => (0, reference),
        (ScenarioPhase::SubmitResultRecovery, SnapshotFact::SubmitResolved(reference)) => {
            (1, reference)
        }
        (ScenarioPhase::SecondarySelectiveFetch, SnapshotFact::Fetched(reference)) => {
            (2, reference)
        }
        (ScenarioPhase::SnapshotByteVerification, SnapshotFact::BytesVerified(reference)) => {
            (3, reference)
        }
        (
            ScenarioPhase::AtomicSubmit
            | ScenarioPhase::SubmitResultRecovery
            | ScenarioPhase::SecondarySelectiveFetch
            | ScenarioPhase::SnapshotByteVerification,
            _,
        ) => return Err(Error::SnapshotFactMismatch),
        (_, SnapshotFact::None) => return Ok(()),
        _ => return Err(Error::SnapshotFactMismatch),
    };
    if reference.kind != ObjectKind::Snapshot {
        return Err(Error::SnapshotKindInvalid);
    }
    snapshots[slot] = Some(reference);
    Ok(())
}

fn common_snapshot(snapshots: &[Option<ObjectRef>; 4]) -> Result<Option<ObjectRef>> {
    let mut common = None;
    for reference in snapshots.iter().flatten().copied() {
        match common {
            Some(expected) if expected != reference => return Err(Error::SnapshotIdentityMismatch),
            None => common = Some(reference),
            _ => {}
        }
    }
    Ok(common)
}

fn validate_commitment(commitment: Commitment) -> Result<()> {
    validate_nonzero(&commitment.0)
}

fn validate_nonzero(bytes: &[u8; 32]) -> Result<()> {
    if *bytes == [0; 32] {
        Err(Error::CommitmentInvalid)
    } else {
        Ok(())
    }
}

fn validate_version(version: Version) -> Result<()> {
    if version.major == 0 && version.minor == 0 && version.patch == 0 && version.prerelease == 0 {
        Err(Error::VersionInvalid)
    } else {
        Ok(())
    }
}

fn check_cancelled<C: Cancellation>(cancellation: &C) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(Error::Cancelled)
    } else {
        Ok(())
    }
}

fn hash_context(transcript: &mut Transcript, context: &EvidenceContext) {
    transcript.section(1);
    transcript.u16(context.schema_version);
    transcript.commitment(context.scenario_seed_commitment);
    transcript.commitment(context.monotonic_clock_commitment);
    transcript.workspace(context.primary.workspace);
    transcript.identity(context.primary.identity);
    transcript.workspace(context.secondary.workspace);
    transcript.identity(context.secondary.identity);
    let materialization = context.materialization;
    transcript.commitment(materialization.primary_selection_commitment);
    transcript.commitment(materialization.secondary_selection_commitment);
    transcript.commitment(materialization.selected_root_commitment);
    transcript.commitment(materialization.exact_byte_verification_commitment);
    transcript.u64(materialization.selected_item_count);
    transcript.u64(materialization.selected_byte_count);
    transcript.u64(materialization.excluded_nonmaterialized_count);
    transcript.u8(context.redaction as u8);
}

fn hash_component(transcript: &mut Transcript, evidence: &CompatibilityEvidence) {
    transcript.section(2);
    transcript.u8(evidence.component as u8);
    transcript.commitment(evidence.artifact_commitment);
    transcript.version(evidence.artifact_version);
    transcript.commitment(evidence.component_commitment);
    transcript.version(evidence.component_version);
    transcript.commitment(evidence.protocol_commitment);
    transcript.version(evidence.protocol_version);
    transcript.commitment(evidence.format_commitment);
    transcript.version(evidence.format_version);
    transcript.commitment(evidence.capability_set_commitment);
    transcript.u8(evidence.artifact_verification as u8);
    transcript.u8(evidence.compatibility as u8);
    transcript.u8(evidence.route as u8);
}

fn hash_step(transcript: &mut Transcript, step: &StepEvidence) {
    transcript.section(3);
    transcript.u8(step.phase as u8);
    transcript.commitment(step.request_commitment);
    transcript.commitment(step.result_commitment);
    transcript.u64(step.started_tick);
    transcript.u64(step.finished_tick);
    transcript.u8(step.result as u8);
    transcript.u8(step.recovery as u8);
    transcript.u8(step.capability as u8);
    transcript.u8(step.route as u8);
    match step.snapshot {
        SnapshotFact::None => transcript.u8(0),
        SnapshotFact::Submitted(reference) => {
            transcript.snapshot(1, reference.kind.code(), reference.digest)
        }
        SnapshotFact::SubmitResolved(reference) => {
            transcript.snapshot(2, reference.kind.code(), reference.digest)
        }
        SnapshotFact::Fetched(reference) => {
            transcript.snapshot(3, reference.kind.code(), reference.digest)
        }
        SnapshotFact::BytesVerified(reference) => {
            transcript.snapshot(4, reference.kind.code(), reference.digest)
        }
    }
}
