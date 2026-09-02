use core::{fmt, mem::size_of};

use ogvcs_object_model::ObjectRef;
use sha2::Sha256;

pub const REPORT_SCHEMA_VERSION: u16 = 1;
pub const COMPONENT_COUNT: usize = 8;
pub const STEP_COUNT: usize = 16;
pub const MAX_WORK_UNITS: u64 = 320;
pub const MAX_RETAINED_BYTES: u64 = 1_024;
pub const MAX_SELECTED_ITEMS: u64 = 1_000_000;
pub const MAX_SELECTED_BYTES: u64 = 1_u64 << 50;
pub const MAX_EXCLUDED_ITEMS: u64 = 1_000_000;

/// Cross-platform fixed reservation for the digest state, four Snapshot
/// references, compatibility pairs, timing/counters, and scalar bookkeeping.
/// Input records remain caller-owned and are borrowed one at a time.
pub const VALIDATOR_RETAINED_BYTES: u64 = 768;

const _: () = assert!(
    size_of::<Sha256>() as u64
        + size_of::<[Option<ObjectRef>; 4]>() as u64
        + 2 * size_of::<Option<(Commitment, Version)>>() as u64
        + size_of::<[u64; 24]>() as u64
        + 128
        <= VALIDATOR_RETAINED_BYTES
);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Commitment(pub [u8; 32]);

impl fmt::Debug for Commitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Commitment([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WorkspaceBinding(pub [u8; 32]);

impl fmt::Debug for WorkspaceBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkspaceBinding([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IdentityBinding(pub [u8; 32]);

impl fmt::Debug for IdentityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityBinding([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub prerelease: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Component {
    NativeCli = 1,
    StarterDeployment = 2,
    ProtocolBaseline = 3,
    WorkspaceLifecycle = 4,
    WorkspaceStatus = 5,
    SelectiveSync = 6,
    HardLock = 7,
    AtomicSubmit = 8,
}

pub const CANONICAL_COMPONENTS: [Component; COMPONENT_COUNT] = [
    Component::NativeCli,
    Component::StarterDeployment,
    Component::ProtocolBaseline,
    Component::WorkspaceLifecycle,
    Component::WorkspaceStatus,
    Component::SelectiveSync,
    Component::HardLock,
    Component::AtomicSubmit,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactVerification {
    ChecksumAndProvenanceVerified = 1,
    Unverified = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CompatibilityStatus {
    DeclaredCompatible = 1,
    Unsupported = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ContractRoute {
    PublicVersioned = 1,
    PrivateFallback = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityEvidence {
    pub component: Component,
    pub artifact_commitment: Commitment,
    pub artifact_version: Version,
    pub component_commitment: Commitment,
    pub component_version: Version,
    pub protocol_commitment: Commitment,
    pub protocol_version: Version,
    pub format_commitment: Commitment,
    pub format_version: Version,
    pub capability_set_commitment: Commitment,
    pub artifact_verification: ArtifactVerification,
    pub compatibility: CompatibilityStatus,
    pub route: ContractRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScenarioPhase {
    ArtifactVerification = 1,
    CompatibilityPreflight = 2,
    CleanHostInstall = 3,
    PrimaryAuthentication = 4,
    RepositoryBootstrap = 5,
    PrimaryWorkspaceCreate = 6,
    PrimarySelectiveSync = 7,
    PrimaryStatus = 8,
    PrimaryHardLockEdit = 9,
    AtomicSubmit = 10,
    SubmitResultRecovery = 11,
    SecondaryAuthentication = 12,
    SecondaryWorkspaceCreate = 13,
    SecondarySelectiveFetch = 14,
    SnapshotByteVerification = 15,
    RedactedEvidenceFinalize = 16,
}

impl ScenarioPhase {
    pub const fn mutates_state(self) -> bool {
        matches!(
            self,
            Self::CleanHostInstall
                | Self::RepositoryBootstrap
                | Self::PrimaryWorkspaceCreate
                | Self::PrimarySelectiveSync
                | Self::PrimaryHardLockEdit
                | Self::AtomicSubmit
                | Self::SecondaryWorkspaceCreate
                | Self::SecondarySelectiveFetch
        )
    }
}

pub const CANONICAL_PHASES: [ScenarioPhase; STEP_COUNT] = [
    ScenarioPhase::ArtifactVerification,
    ScenarioPhase::CompatibilityPreflight,
    ScenarioPhase::CleanHostInstall,
    ScenarioPhase::PrimaryAuthentication,
    ScenarioPhase::RepositoryBootstrap,
    ScenarioPhase::PrimaryWorkspaceCreate,
    ScenarioPhase::PrimarySelectiveSync,
    ScenarioPhase::PrimaryStatus,
    ScenarioPhase::PrimaryHardLockEdit,
    ScenarioPhase::AtomicSubmit,
    ScenarioPhase::SubmitResultRecovery,
    ScenarioPhase::SecondaryAuthentication,
    ScenarioPhase::SecondaryWorkspaceCreate,
    ScenarioPhase::SecondarySelectiveFetch,
    ScenarioPhase::SnapshotByteVerification,
    ScenarioPhase::RedactedEvidenceFinalize,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SafeResultClass {
    Succeeded = 1,
    RecoveredLocalWorkPreservedAndSucceeded = 2,
    FailedClosedNoMutation = 3,
    CancelledLocalWorkPreserved = 4,
    NotRunAfterSafeStop = 5,
}

impl SafeResultClass {
    pub const fn completed(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::RecoveredLocalWorkPreservedAndSucceeded
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RecoveryClass {
    None = 0,
    RetrySameRequest = 1,
    ResolveOriginalSubmit = 2,
    Reauthenticate = 3,
    RefreshBranchAndRestage = 4,
    ReacquireLock = 5,
    RefetchVerifiedContent = 6,
    FreeDiskAndResume = 7,
    ResumeAfterCancellation = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CapabilityFact {
    NotAMutation = 1,
    VerifiedBeforeMutation = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotFact {
    None,
    Submitted(ObjectRef),
    SubmitResolved(ObjectRef),
    Fetched(ObjectRef),
    BytesVerified(ObjectRef),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepEvidence {
    pub phase: ScenarioPhase,
    pub request_commitment: Commitment,
    pub result_commitment: Commitment,
    pub started_tick: u64,
    pub finished_tick: u64,
    pub result: SafeResultClass,
    pub recovery: RecoveryClass,
    pub capability: CapabilityFact,
    pub route: ContractRoute,
    pub snapshot: SnapshotFact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParticipantBinding {
    pub workspace: WorkspaceBinding,
    pub identity: IdentityBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaterializationEvidence {
    pub primary_selection_commitment: Commitment,
    pub secondary_selection_commitment: Commitment,
    pub selected_root_commitment: Commitment,
    pub exact_byte_verification_commitment: Commitment,
    pub selected_item_count: u64,
    pub selected_byte_count: u64,
    pub excluded_nonmaterialized_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RedactionStatus {
    AllowlistVerified = 1,
    Unverified = 2,
    SensitiveMaterialDetected = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceContext {
    pub schema_version: u16,
    pub scenario_seed_commitment: Commitment,
    pub monotonic_clock_commitment: Commitment,
    pub primary: ParticipantBinding,
    pub secondary: ParticipantBinding,
    pub materialization: MaterializationEvidence,
    pub redaction: RedactionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectionLimits {
    pub max_selected_items: u64,
    pub max_selected_bytes: u64,
    pub max_excluded_items: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationLimits {
    pub max_components: u64,
    pub max_steps: u64,
    pub max_work_units: u64,
    pub max_retained_bytes: u64,
    pub selection: SelectionLimits,
}

impl ValidationLimits {
    pub const fn fixed() -> Self {
        Self {
            max_components: COMPONENT_COUNT as u64,
            max_steps: STEP_COUNT as u64,
            max_work_units: MAX_WORK_UNITS,
            max_retained_bytes: MAX_RETAINED_BYTES,
            selection: SelectionLimits {
                max_selected_items: MAX_SELECTED_ITEMS,
                max_selected_bytes: MAX_SELECTED_BYTES,
                max_excluded_items: MAX_EXCLUDED_ITEMS,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptDisposition {
    AllStepsSucceededOrRecovered,
    SafeTerminalResultPresent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationSummary {
    pub report_digest: ReportDigest,
    pub disposition: TranscriptDisposition,
    pub committed_snapshot: Option<ObjectRef>,
    pub first_tick: u64,
    pub final_tick: u64,
    pub elapsed_ticks: u64,
    pub component_records: u64,
    pub step_records: u64,
    pub executed_steps: u64,
    pub work_units: u64,
    pub peak_retained_bytes: u64,
}

pub trait Cancellation {
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Cancelled,
    LimitExceedsHardMaximum,
    CountExceedsLimit,
    ComponentCountInvalid,
    StepCountInvalid,
    WorkLimitExceeded,
    RetainedMemoryLimitExceeded,
    SelectionLimitExceeded,
    ArithmeticOverflow,
    SchemaVersionUnsupported,
    CommitmentInvalid,
    VersionInvalid,
    ParticipantBindingAliased,
    SelectionBindingAliased,
    SelectionCountInvalid,
    RedactionNotVerified,
    ComponentOrderInvalid,
    ArtifactNotVerified,
    CompatibilityRejected,
    PrivateFallbackForbidden,
    ProtocolCompatibilityMismatch,
    FormatCompatibilityMismatch,
    StepOrderInvalid,
    TimingNotMonotonic,
    ResultRecoveryMismatch,
    StepAfterTerminalResult,
    SkippedStepEvidenceInvalid,
    RecoveryPhaseMismatch,
    CapabilityFactMismatch,
    SnapshotFactMismatch,
    SnapshotKindInvalid,
    SnapshotIdentityMismatch,
}

pub type Result<T> = core::result::Result<T, Error>;
