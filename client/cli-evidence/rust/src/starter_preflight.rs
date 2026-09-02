//! Route-less source composition for the supplied-fact OGVCS-021 starter
//! deployment preflight. This module calls the predecessor builder directly;
//! it does not accept a report, produce scenario evidence, or establish a
//! route, artifact provenance, authorization, or mutation capability.

use core::{fmt, mem::size_of};
use std::sync::atomic::{AtomicBool, Ordering};

use ogvcs_deployment_preflight::{
    build_deployment_preflight, DeploymentConfig, PreflightControl, PreflightError,
    PreflightEvaluation, PreflightLimits, PreflightObservation, PREFLIGHT_VERSION,
    RETAINED_BYTES_HARD_MAXIMUM as PREFLIGHT_RETAINED_BYTES_HARD_MAXIMUM,
    WORK_UNITS_HARD_MAXIMUM as PREFLIGHT_WORK_UNITS_HARD_MAXIMUM,
};
use sha2::{Digest, Sha256};

use crate::Commitment;

const REQUEST_DOMAIN: &[u8] = b"OpenGameVCS R1 CLI starter deployment preflight request\0v1\0";
const PROJECTION_DOMAIN: &[u8] = b"OpenGameVCS R1 CLI starter deployment composition\0v1\0";
const PREFLIGHT_RETAINED_BYTES_MINIMUM: u64 = 512;
const _: () = assert!(PREFLIGHT_VERSION == 2);

pub const STARTER_PREFLIGHT_COMPOSITION_VERSION: u16 = 1;
/// Fixed logical work retained by this projection layer in addition to the
/// predecessor's bounded charge.
pub const STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS: u64 = 12;
/// Conservative fixed reservation for one hash state and the returned
/// fixed-width projection. The predecessor accounts for its report separately.
pub const STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES: u64 = 512;
pub const STARTER_PREFLIGHT_TOTAL_WORK_UNITS_HARD_MAXIMUM: u64 =
    PREFLIGHT_WORK_UNITS_HARD_MAXIMUM + STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS;
pub const STARTER_PREFLIGHT_TOTAL_RETAINED_BYTES_HARD_MAXIMUM: u64 =
    PREFLIGHT_RETAINED_BYTES_HARD_MAXIMUM + STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES;

/// Caller-selected operational envelope. These limits are not projection
/// semantics and therefore are not hashed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StarterPreflightCompositionLimits {
    pub max_work_units: u64,
    pub max_retained_bytes: u64,
}

impl StarterPreflightCompositionLimits {
    pub const fn fixed() -> Self {
        Self {
            max_work_units: STARTER_PREFLIGHT_TOTAL_WORK_UNITS_HARD_MAXIMUM,
            max_retained_bytes: STARTER_PREFLIGHT_TOTAL_RETAINED_BYTES_HARD_MAXIMUM,
        }
    }
}

/// Fixed-width source projection for one structurally ready supplied-fact
/// deployment preflight. It deliberately cannot convert into a compatibility
/// component or scenario step. Its fields are private so safe downstream code
/// can inspect, but cannot construct or alter, a projection without this
/// module executing and rechecking OGVCS-021.
///
/// ```compile_fail,E0451
/// use ogvcs_cli_evidence_validator::{
///     Commitment, StarterDeploymentPreflightProjection,
/// };
///
/// fn forge(
///     trusted: StarterDeploymentPreflightProjection,
/// ) -> StarterDeploymentPreflightProjection {
///     StarterDeploymentPreflightProjection {
///         projection_digest: Commitment([0; 32]),
///         ..trusted
///     }
/// }
/// ```
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StarterDeploymentPreflightProjection {
    version: u16,
    deployment_commitment: Commitment,
    artifact_set_commitment: Commitment,
    compatibility_set_commitment: Commitment,
    configuration_generation_commitment: Commitment,
    configuration_digest: Commitment,
    observation_digest: Commitment,
    request_commitment: Commitment,
    result_commitment: Commitment,
    observation_captured_at_unix_seconds: u64,
    evaluated_at_unix_seconds: u64,
    maximum_observation_age_seconds: u64,
    predecessor_work_units: u64,
    predecessor_retained_bytes: u64,
    total_work_units: u64,
    peak_retained_bytes: u64,
    projection_digest: Commitment,
}

impl StarterDeploymentPreflightProjection {
    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn deployment_commitment(&self) -> Commitment {
        self.deployment_commitment
    }

    pub const fn artifact_set_commitment(&self) -> Commitment {
        self.artifact_set_commitment
    }

    pub const fn compatibility_set_commitment(&self) -> Commitment {
        self.compatibility_set_commitment
    }

    pub const fn configuration_generation_commitment(&self) -> Commitment {
        self.configuration_generation_commitment
    }

    pub const fn configuration_digest(&self) -> Commitment {
        self.configuration_digest
    }

    pub const fn observation_digest(&self) -> Commitment {
        self.observation_digest
    }

    pub const fn request_commitment(&self) -> Commitment {
        self.request_commitment
    }

    pub const fn result_commitment(&self) -> Commitment {
        self.result_commitment
    }

    pub const fn observation_captured_at_unix_seconds(&self) -> u64 {
        self.observation_captured_at_unix_seconds
    }

    pub const fn evaluated_at_unix_seconds(&self) -> u64 {
        self.evaluated_at_unix_seconds
    }

    pub const fn maximum_observation_age_seconds(&self) -> u64 {
        self.maximum_observation_age_seconds
    }

    pub const fn predecessor_work_units(&self) -> u64 {
        self.predecessor_work_units
    }

    pub const fn predecessor_retained_bytes(&self) -> u64 {
        self.predecessor_retained_bytes
    }

    pub const fn total_work_units(&self) -> u64 {
        self.total_work_units
    }

    pub const fn peak_retained_bytes(&self) -> u64 {
        self.peak_retained_bytes
    }

    pub const fn projection_digest(&self) -> Commitment {
        self.projection_digest
    }
}

impl fmt::Debug for StarterDeploymentPreflightProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StarterDeploymentPreflightProjection")
            .field("version", &self.version)
            .field("bindings", &"<redacted>")
            .field("predecessor_work_units", &self.predecessor_work_units)
            .field(
                "predecessor_retained_bytes",
                &self.predecessor_retained_bytes,
            )
            .field("total_work_units", &self.total_work_units)
            .field("peak_retained_bytes", &self.peak_retained_bytes)
            .finish()
    }
}

const _: () = assert!(
    size_of::<Sha256>() as u64 + size_of::<StarterDeploymentPreflightProjection>() as u64
        <= STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES
);

/// Fail-closed source-composition result. Every error returns no commitment or
/// partial projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StarterDeploymentPreflightError {
    InvalidLimits,
    Cancelled,
    Preflight(PreflightError),
    PreflightBindingInvalid,
    DeploymentNotReady,
    AccountingOverflow,
}

/// Calls the OGVCS-021 builder over the supplied configuration and observation
/// and returns a projection only for a structurally bound, live, ready result.
///
/// The inputs contain only the predecessor's bounded supplied facts and opaque
/// secret-reference commitments; this function performs no I/O or inspection.
pub fn compose_starter_deployment_preflight(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
    limits: StarterPreflightCompositionLimits,
    cancellation: &AtomicBool,
) -> Result<StarterDeploymentPreflightProjection, StarterDeploymentPreflightError> {
    compose_starter_deployment_preflight_inner(
        config,
        observation,
        evaluation,
        limits,
        cancellation,
        |_| {},
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionCancellationStage {
    Initial,
    LimitsAdmitted,
    PreflightCompleted,
    BindingAccepted,
    AccountingAdmitted,
    RequestFinalized,
    ProjectionFinalized,
}

fn compose_starter_deployment_preflight_inner(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
    limits: StarterPreflightCompositionLimits,
    cancellation: &AtomicBool,
    mut checkpoint: impl FnMut(CompositionCancellationStage),
) -> Result<StarterDeploymentPreflightProjection, StarterDeploymentPreflightError> {
    checkpoint(CompositionCancellationStage::Initial);
    check_cancelled(cancellation)?;
    let predecessor_limits = predecessor_limits(limits)?;
    checkpoint(CompositionCancellationStage::LimitsAdmitted);
    check_cancelled(cancellation)?;

    let report = build_deployment_preflight(
        config,
        observation,
        evaluation,
        predecessor_limits,
        PreflightControl::with_cancellation(cancellation),
    )
    .map_err(map_preflight_error)?;
    checkpoint(CompositionCancellationStage::PreflightCompleted);
    check_cancelled(cancellation)?;

    if !report.has_valid_binding() || report.version != PREFLIGHT_VERSION {
        return Err(StarterDeploymentPreflightError::PreflightBindingInvalid);
    }
    if !report.live || !report.ready || !report.reasons.is_empty() {
        return Err(StarterDeploymentPreflightError::DeploymentNotReady);
    }
    checkpoint(CompositionCancellationStage::BindingAccepted);
    check_cancelled(cancellation)?;

    let total_work_units = report
        .work_units
        .checked_add(STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS)
        .ok_or(StarterDeploymentPreflightError::AccountingOverflow)?;
    let peak_retained_bytes = report
        .retained_bytes
        .checked_add(STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES)
        .ok_or(StarterDeploymentPreflightError::AccountingOverflow)?;
    if total_work_units > limits.max_work_units || peak_retained_bytes > limits.max_retained_bytes {
        return Err(StarterDeploymentPreflightError::InvalidLimits);
    }
    checkpoint(CompositionCancellationStage::AccountingAdmitted);
    check_cancelled(cancellation)?;

    let deployment_commitment = Commitment(config.deployment);
    let artifact_set_commitment = Commitment(config.artifact_set);
    let compatibility_set_commitment = Commitment(config.compatibility_set);
    let configuration_generation_commitment = Commitment(config.configuration_generation);
    let configuration_digest = Commitment(report.configuration_digest);
    let observation_digest = Commitment(report.observation_digest);
    let request_commitment = request_commitment(
        deployment_commitment,
        artifact_set_commitment,
        compatibility_set_commitment,
        configuration_generation_commitment,
        configuration_digest,
        observation_digest,
        report.observation_captured_at_unix_seconds,
        report.evaluated_at_unix_seconds,
        report.maximum_observation_age_seconds,
    );
    checkpoint(CompositionCancellationStage::RequestFinalized);
    check_cancelled(cancellation)?;

    let result_commitment = Commitment(report.report_digest);
    let projection_digest = projection_digest(
        deployment_commitment,
        artifact_set_commitment,
        compatibility_set_commitment,
        configuration_generation_commitment,
        configuration_digest,
        observation_digest,
        request_commitment,
        result_commitment,
        report.observation_captured_at_unix_seconds,
        report.evaluated_at_unix_seconds,
        report.maximum_observation_age_seconds,
        report.work_units,
        report.retained_bytes,
        total_work_units,
        peak_retained_bytes,
    );
    checkpoint(CompositionCancellationStage::ProjectionFinalized);
    check_cancelled(cancellation)?;

    Ok(StarterDeploymentPreflightProjection {
        version: STARTER_PREFLIGHT_COMPOSITION_VERSION,
        deployment_commitment,
        artifact_set_commitment,
        compatibility_set_commitment,
        configuration_generation_commitment,
        configuration_digest,
        observation_digest,
        request_commitment,
        result_commitment,
        observation_captured_at_unix_seconds: report.observation_captured_at_unix_seconds,
        evaluated_at_unix_seconds: report.evaluated_at_unix_seconds,
        maximum_observation_age_seconds: report.maximum_observation_age_seconds,
        predecessor_work_units: report.work_units,
        predecessor_retained_bytes: report.retained_bytes,
        total_work_units,
        peak_retained_bytes,
        projection_digest,
    })
}

fn predecessor_limits(
    limits: StarterPreflightCompositionLimits,
) -> Result<PreflightLimits, StarterDeploymentPreflightError> {
    if limits.max_work_units <= STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS
        || limits.max_work_units > STARTER_PREFLIGHT_TOTAL_WORK_UNITS_HARD_MAXIMUM
        || limits.max_retained_bytes
            < STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES + PREFLIGHT_RETAINED_BYTES_MINIMUM
        || limits.max_retained_bytes > STARTER_PREFLIGHT_TOTAL_RETAINED_BYTES_HARD_MAXIMUM
    {
        return Err(StarterDeploymentPreflightError::InvalidLimits);
    }
    Ok(PreflightLimits {
        max_work_units: limits.max_work_units - STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS,
        max_retained_bytes: limits.max_retained_bytes
            - STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES,
    })
}

fn map_preflight_error(error: PreflightError) -> StarterDeploymentPreflightError {
    match error {
        PreflightError::Cancelled => StarterDeploymentPreflightError::Cancelled,
        other => StarterDeploymentPreflightError::Preflight(other),
    }
}

fn check_cancelled(cancellation: &AtomicBool) -> Result<(), StarterDeploymentPreflightError> {
    if cancellation.load(Ordering::Acquire) {
        Err(StarterDeploymentPreflightError::Cancelled)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn request_commitment(
    deployment: Commitment,
    artifact_set: Commitment,
    compatibility_set: Commitment,
    configuration_generation: Commitment,
    configuration_digest: Commitment,
    observation_digest: Commitment,
    observation_captured_at_unix_seconds: u64,
    evaluated_at_unix_seconds: u64,
    maximum_observation_age_seconds: u64,
) -> Commitment {
    let mut writer = ProjectionWriter::new(REQUEST_DOMAIN);
    writer.u16(STARTER_PREFLIGHT_COMPOSITION_VERSION);
    writer.u16(PREFLIGHT_VERSION);
    writer.commitment(deployment);
    writer.commitment(artifact_set);
    writer.commitment(compatibility_set);
    writer.commitment(configuration_generation);
    writer.commitment(configuration_digest);
    writer.commitment(observation_digest);
    writer.u64(observation_captured_at_unix_seconds);
    writer.u64(evaluated_at_unix_seconds);
    writer.u64(maximum_observation_age_seconds);
    writer.finish()
}

#[allow(clippy::too_many_arguments)]
fn projection_digest(
    deployment: Commitment,
    artifact_set: Commitment,
    compatibility_set: Commitment,
    configuration_generation: Commitment,
    configuration_digest: Commitment,
    observation_digest: Commitment,
    request_commitment: Commitment,
    result_commitment: Commitment,
    observation_captured_at_unix_seconds: u64,
    evaluated_at_unix_seconds: u64,
    maximum_observation_age_seconds: u64,
    predecessor_work_units: u64,
    predecessor_retained_bytes: u64,
    total_work_units: u64,
    peak_retained_bytes: u64,
) -> Commitment {
    let mut writer = ProjectionWriter::new(PROJECTION_DOMAIN);
    writer.u16(STARTER_PREFLIGHT_COMPOSITION_VERSION);
    writer.commitment(deployment);
    writer.commitment(artifact_set);
    writer.commitment(compatibility_set);
    writer.commitment(configuration_generation);
    writer.commitment(configuration_digest);
    writer.commitment(observation_digest);
    writer.commitment(request_commitment);
    writer.commitment(result_commitment);
    writer.u64(observation_captured_at_unix_seconds);
    writer.u64(evaluated_at_unix_seconds);
    writer.u64(maximum_observation_age_seconds);
    writer.u64(predecessor_work_units);
    writer.u64(predecessor_retained_bytes);
    writer.u64(total_work_units);
    writer.u64(peak_retained_bytes);
    writer.u8(1);
    writer.finish()
}

struct ProjectionWriter(Sha256);

impl ProjectionWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update((domain.len() as u64).to_be_bytes());
        hash.update(domain);
        Self(hash)
    }

    fn u8(&mut self, value: u8) {
        self.0.update([0x01, value]);
    }

    fn u16(&mut self, value: u16) {
        self.0.update([0x02]);
        self.0.update(value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update([0x03]);
        self.0.update(value.to_be_bytes());
    }

    fn commitment(&mut self, value: Commitment) {
        self.0.update([0x20, 0x00, 0x00, 0x00, 0x20]);
        self.0.update(value.0);
    }

    fn finish(self) -> Commitment {
        Commitment(self.0.finalize().into())
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use ogvcs_deployment_preflight::{
        DependencyKind, DependencyObservation, DependencyState, DurableDataPolicy, Exposure,
        ListenerConfig, ListenerRole, MigrationClass, MigrationIntent, SecretBinding,
        SecretProvider, SecretPurpose, ServiceAccount, ServiceRole,
    };

    fn config() -> DeploymentConfig {
        DeploymentConfig {
            version: PREFLIGHT_VERSION,
            deployment: [1; 32],
            artifact_set: [2; 32],
            compatibility_set: [3; 32],
            configuration_generation: [4; 32],
            telemetry_enabled_by_default: false,
            vendor_check_in_required: false,
            durable_data_policy: DurableDataPolicy::PreserveByDefault,
            listeners: vec![
                ListenerConfig {
                    role: ListenerRole::Api,
                    exposure: Exposure::PrivateNetwork,
                    port: 443,
                    tls: true,
                },
                ListenerConfig {
                    role: ListenerRole::Admin,
                    exposure: Exposure::Loopback,
                    port: 9443,
                    tls: true,
                },
                ListenerConfig {
                    role: ListenerRole::Metrics,
                    exposure: Exposure::Loopback,
                    port: 9090,
                    tls: false,
                },
            ],
            secrets: [
                SecretPurpose::Metadata,
                SecretPurpose::ObjectStorage,
                SecretPurpose::IdentitySigning,
                SecretPurpose::BackupEncryption,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, purpose)| SecretBinding {
                purpose,
                provider: SecretProvider::ExternalProvider,
                reference_commitment: [10 + index as u8; 32],
                access_restricted: true,
                embedded_in_public_config: false,
                included_in_diagnostics: false,
            })
            .collect(),
            service_accounts: [
                ServiceRole::ControlPlane,
                ServiceRole::Worker,
                ServiceRole::Administration,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, role)| ServiceAccount {
                role,
                principal_commitment: [20 + index as u8; 32],
                privileged_root: false,
                interactive_login: false,
            })
            .collect(),
        }
    }

    fn observation() -> PreflightObservation {
        PreflightObservation {
            captured_at_unix_seconds: 1_800_000_000,
            process_alive: true,
            compatibility_set: [3; 32],
            configuration_generation: [4; 32],
            dependencies: [
                DependencyKind::Metadata,
                DependencyKind::ObjectStorage,
                DependencyKind::Identity,
                DependencyKind::Verifier,
                DependencyKind::Backup,
                DependencyKind::Capacity,
                DependencyKind::Schema,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, kind)| DependencyObservation {
                kind,
                state: DependencyState::Healthy,
                generation_commitment: [30 + index as u8; 32],
            })
            .collect(),
            migration: MigrationIntent {
                current_schema: 9,
                target_schema: 9,
                class: MigrationClass::None,
            },
            backup_gate: None,
        }
    }

    #[test]
    fn every_outer_release_fence_observes_cancellation() {
        let stages = [
            CompositionCancellationStage::Initial,
            CompositionCancellationStage::LimitsAdmitted,
            CompositionCancellationStage::PreflightCompleted,
            CompositionCancellationStage::BindingAccepted,
            CompositionCancellationStage::AccountingAdmitted,
            CompositionCancellationStage::RequestFinalized,
            CompositionCancellationStage::ProjectionFinalized,
        ];
        for target in stages {
            let cancellation = AtomicBool::new(false);
            let result = compose_starter_deployment_preflight_inner(
                &config(),
                &observation(),
                PreflightEvaluation {
                    evaluated_at_unix_seconds: 1_800_000_100,
                    maximum_observation_age_seconds: 300,
                },
                StarterPreflightCompositionLimits::fixed(),
                &cancellation,
                |stage| {
                    if stage == target {
                        cancellation.store(true, Ordering::Release);
                    }
                },
            );
            assert_eq!(result, Err(StarterDeploymentPreflightError::Cancelled));
        }
    }
}
