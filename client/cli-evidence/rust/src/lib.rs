//! Bounded validation for caller-supplied OGVCS-043 compatibility and journey
//! evidence. This crate is private, pure, and deliberately has no execution or
//! I/O adapter.
#![forbid(unsafe_code)]

mod model;
mod starter_preflight;
mod transcript;
mod validate;

pub use model::{
    ArtifactVerification, Cancellation, CapabilityFact, Commitment, CompatibilityEvidence,
    CompatibilityStatus, Component, ContractRoute, Error, EvidenceContext, IdentityBinding,
    MaterializationEvidence, NeverCancelled, ParticipantBinding, RecoveryClass, RedactionStatus,
    ReportDigest, Result, SafeResultClass, ScenarioPhase, SelectionLimits, SnapshotFact,
    StepEvidence, TranscriptDisposition, ValidationLimits, ValidationSummary, Version,
    WorkspaceBinding, CANONICAL_COMPONENTS, CANONICAL_PHASES, COMPONENT_COUNT, MAX_EXCLUDED_ITEMS,
    MAX_RETAINED_BYTES, MAX_SELECTED_BYTES, MAX_SELECTED_ITEMS, MAX_WORK_UNITS,
    REPORT_SCHEMA_VERSION, STEP_COUNT, VALIDATOR_RETAINED_BYTES,
};
pub use starter_preflight::{
    compose_starter_deployment_preflight, StarterDeploymentPreflightError,
    StarterDeploymentPreflightProjection, StarterPreflightCompositionLimits,
    STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES, STARTER_PREFLIGHT_COMPOSITION_VERSION,
    STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS, STARTER_PREFLIGHT_TOTAL_RETAINED_BYTES_HARD_MAXIMUM,
    STARTER_PREFLIGHT_TOTAL_WORK_UNITS_HARD_MAXIMUM,
};
pub use validate::validate_evidence;
