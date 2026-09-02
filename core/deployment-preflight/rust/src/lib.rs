//! Private, bounded OGVCS-021 deployment configuration and readiness
//! preflight candidate. All environment observations are caller-supplied facts.
#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use sha2::{Digest as _, Sha256};

const _: () = assert!(usize::BITS <= u64::BITS);

pub type Commitment = [u8; 32];

pub const PREFLIGHT_VERSION: u16 = 2;
pub const LISTENER_COUNT: usize = 3;
pub const SECRET_COUNT: usize = 4;
pub const SERVICE_ACCOUNT_COUNT: usize = 3;
pub const DEPENDENCY_COUNT: usize = 7;
pub const WORK_UNITS_HARD_MAXIMUM: u64 = 19;
pub const RETAINED_BYTES_HARD_MAXIMUM: u64 = 640;
pub const OBSERVATION_AGE_SECONDS_HARD_MAXIMUM: u64 = 300;

const RETAINED_BASE_CHARGE: u64 = 512;
const RETAINED_REASON_CHARGE: u64 = 16;
const WORK_UNITS_WITHOUT_BACKUP_GATE: u64 = 18;
const CONFIG_DOMAIN: &[u8] = b"OGVCS-PRIVATE-DEPLOYMENT-CONFIG-V2";
const OBSERVATION_DOMAIN: &[u8] = b"OGVCS-PRIVATE-DEPLOYMENT-OBSERVATION-V2";
const REPORT_DOMAIN: &[u8] = b"OGVCS-PRIVATE-DEPLOYMENT-PREFLIGHT-REPORT-V2";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ListenerRole {
    Api = 1,
    Admin = 2,
    Metrics = 3,
}

impl ListenerRole {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Exposure {
    Loopback = 1,
    PrivateNetwork = 2,
    Public = 3,
}

impl Exposure {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ListenerConfig {
    pub role: ListenerRole,
    pub exposure: Exposure,
    pub port: u16,
    pub tls: bool,
}

impl fmt::Debug for ListenerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerConfig")
            .field("role", &self.role)
            .field("listener", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SecretPurpose {
    Metadata = 1,
    ObjectStorage = 2,
    IdentitySigning = 3,
    BackupEncryption = 4,
}

impl SecretPurpose {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SecretProvider {
    ProtectedFile = 1,
    ExternalProvider = 2,
}

impl SecretProvider {
    const fn code(self) -> u8 {
        self as u8
    }
}

/// Opaque reference plus caller-supplied access facts. This value never carries
/// secret bytes and does not prove filesystem/provider enforcement.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecretBinding {
    pub purpose: SecretPurpose,
    pub provider: SecretProvider,
    pub reference_commitment: Commitment,
    pub access_restricted: bool,
    pub embedded_in_public_config: bool,
    pub included_in_diagnostics: bool,
}

impl fmt::Debug for SecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBinding")
            .field("purpose", &self.purpose)
            .field("provider", &self.provider)
            .field("binding", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ServiceRole {
    ControlPlane = 1,
    Worker = 2,
    Administration = 3,
}

impl ServiceRole {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ServiceAccount {
    pub role: ServiceRole,
    pub principal_commitment: Commitment,
    pub privileged_root: bool,
    pub interactive_login: bool,
}

impl fmt::Debug for ServiceAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceAccount")
            .field("role", &self.role)
            .field("account", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableDataPolicy {
    PreserveByDefault,
    RemoveByDefault,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeploymentConfig {
    pub version: u16,
    pub deployment: Commitment,
    pub artifact_set: Commitment,
    pub compatibility_set: Commitment,
    pub configuration_generation: Commitment,
    pub telemetry_enabled_by_default: bool,
    pub vendor_check_in_required: bool,
    pub durable_data_policy: DurableDataPolicy,
    pub listeners: Vec<ListenerConfig>,
    pub secrets: Vec<SecretBinding>,
    pub service_accounts: Vec<ServiceAccount>,
}

impl fmt::Debug for DeploymentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentConfig")
            .field("version", &self.version)
            .field("configuration", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum DependencyKind {
    Metadata = 1,
    ObjectStorage = 2,
    Identity = 3,
    Verifier = 4,
    Backup = 5,
    Capacity = 6,
    Schema = 7,
}

impl DependencyKind {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DependencyState {
    Healthy = 1,
    Degraded = 2,
    Unavailable = 3,
    Incompatible = 4,
    Stale = 5,
}

impl DependencyState {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DependencyObservation {
    pub kind: DependencyKind,
    pub state: DependencyState,
    pub generation_commitment: Commitment,
}

impl fmt::Debug for DependencyObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DependencyObservation")
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("generation", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MigrationClass {
    None = 1,
    Compatible = 2,
    Irreversible = 3,
}

impl MigrationClass {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationIntent {
    pub current_schema: u64,
    pub target_schema: u64,
    pub class: MigrationClass,
}

/// Supplied bindings only. The OGVCS-017/018 implementations must establish
/// the actual verifier and backup authority outside this crate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackupGateEvidence {
    pub deployment: Commitment,
    pub artifact_set: Commitment,
    pub compatibility_set: Commitment,
    pub configuration_generation: Commitment,
    pub source_schema: u64,
    pub target_schema: u64,
    pub metadata_generation: Commitment,
    pub object_storage_generation: Commitment,
    pub verifier_generation: Commitment,
    pub backup_generation: Commitment,
    pub schema_generation: Commitment,
    pub backup_manifest: Commitment,
    pub verified_backup_manifest: Commitment,
    pub verification_report: Commitment,
    pub source_storage: Commitment,
    pub source_credential_scope: Commitment,
    pub target_storage: Commitment,
    pub target_credential_scope: Commitment,
    pub retention_policy: Commitment,
    pub encryption_policy: Commitment,
    pub captured_at_unix_seconds: u64,
    pub retention_until_unix_seconds: u64,
}

impl fmt::Debug for BackupGateEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupGateEvidence")
            .field("evidence", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PreflightObservation {
    pub captured_at_unix_seconds: u64,
    pub process_alive: bool,
    pub compatibility_set: Commitment,
    pub configuration_generation: Commitment,
    pub dependencies: Vec<DependencyObservation>,
    pub migration: MigrationIntent,
    pub backup_gate: Option<BackupGateEvidence>,
}

impl fmt::Debug for PreflightObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreflightObservation")
            .field("observation", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreflightEvaluation {
    pub evaluated_at_unix_seconds: u64,
    pub maximum_observation_age_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum SafeReasonCode {
    ProcessNotLive = 1,
    MetadataDegraded = 101,
    MetadataUnavailable = 102,
    MetadataIncompatible = 103,
    MetadataStale = 104,
    ObjectStorageDegraded = 201,
    ObjectStorageUnavailable = 202,
    ObjectStorageIncompatible = 203,
    ObjectStorageStale = 204,
    IdentityDegraded = 301,
    IdentityUnavailable = 302,
    IdentityIncompatible = 303,
    IdentityStale = 304,
    VerifierDegraded = 401,
    VerifierUnavailable = 402,
    VerifierIncompatible = 403,
    VerifierStale = 404,
    BackupDegraded = 501,
    BackupUnavailable = 502,
    BackupIncompatible = 503,
    BackupStale = 504,
    CapacityDegraded = 601,
    CapacityUnavailable = 602,
    CapacityIncompatible = 603,
    CapacityStale = 604,
    SchemaDegraded = 701,
    SchemaUnavailable = 702,
    SchemaIncompatible = 703,
    SchemaStale = 704,
}

impl SafeReasonCode {
    const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreflightLimits {
    pub max_work_units: u64,
    pub max_retained_bytes: u64,
}

impl Default for PreflightLimits {
    fn default() -> Self {
        Self {
            max_work_units: WORK_UNITS_HARD_MAXIMUM,
            max_retained_bytes: RETAINED_BYTES_HARD_MAXIMUM,
        }
    }
}

impl PreflightLimits {
    const fn valid(self) -> bool {
        self.max_work_units > 0
            && self.max_work_units <= WORK_UNITS_HARD_MAXIMUM
            && self.max_retained_bytes >= RETAINED_BASE_CHARGE
            && self.max_retained_bytes <= RETAINED_BYTES_HARD_MAXIMUM
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PreflightControl<'a> {
    cancellation: Option<&'a AtomicBool>,
}

impl<'a> PreflightControl<'a> {
    pub const fn with_cancellation(cancellation: &'a AtomicBool) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn check(self) -> Result<(), PreflightError> {
        if self
            .cancellation
            .is_some_and(|value| value.load(Ordering::Acquire))
        {
            Err(PreflightError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CancellationStage {
    Initial,
    WorkAdmitted,
    ConfigurationValidated,
    ObservationValidated,
    DependencyObservation,
    RetainedChargeAdmitted,
    BeforeResultAllocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightError {
    InvalidLimits,
    Cancelled,
    InvalidConfiguration,
    ListenerSet,
    SecretSet,
    ServiceAccountSet,
    ObservationSet,
    CompatibilityMismatch,
    ObservationTimeInvalid,
    MigrationInvalid,
    BackupGateInvalid,
    WorkLimit,
    MemoryLimit,
    AccountingOverflow,
}

impl PreflightError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimits => "DEPLOYMENT_PREFLIGHT_LIMITS_INVALID",
            Self::Cancelled => "DEPLOYMENT_PREFLIGHT_CANCELLED",
            Self::InvalidConfiguration => "DEPLOYMENT_CONFIGURATION_INVALID",
            Self::ListenerSet => "DEPLOYMENT_LISTENER_SET_INVALID",
            Self::SecretSet => "DEPLOYMENT_SECRET_SET_INVALID",
            Self::ServiceAccountSet => "DEPLOYMENT_SERVICE_ACCOUNT_SET_INVALID",
            Self::ObservationSet => "DEPLOYMENT_OBSERVATION_SET_INVALID",
            Self::CompatibilityMismatch => "DEPLOYMENT_COMPATIBILITY_MISMATCH",
            Self::ObservationTimeInvalid => "DEPLOYMENT_OBSERVATION_TIME_INVALID",
            Self::MigrationInvalid => "DEPLOYMENT_MIGRATION_INVALID",
            Self::BackupGateInvalid => "DEPLOYMENT_BACKUP_GATE_INVALID",
            Self::WorkLimit => "DEPLOYMENT_PREFLIGHT_WORK_LIMIT",
            Self::MemoryLimit => "DEPLOYMENT_PREFLIGHT_MEMORY_LIMIT",
            Self::AccountingOverflow => "DEPLOYMENT_PREFLIGHT_ACCOUNTING_OVERFLOW",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeploymentPreflightReport {
    pub version: u16,
    pub configuration_digest: Commitment,
    pub observation_digest: Commitment,
    pub observation_captured_at_unix_seconds: u64,
    pub evaluated_at_unix_seconds: u64,
    pub maximum_observation_age_seconds: u64,
    pub live: bool,
    pub ready: bool,
    pub backup_gate_evidence_present: bool,
    pub reasons: Vec<SafeReasonCode>,
    pub work_units: u64,
    pub retained_bytes: u64,
    pub report_digest: Commitment,
}

impl fmt::Debug for DeploymentPreflightReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentPreflightReport")
            .field("bindings", &"<redacted>")
            .field("live", &self.live)
            .field("ready", &self.ready)
            .field("reasons", &self.reasons)
            .field("work_units", &self.work_units)
            .field("retained_bytes", &self.retained_bytes)
            .finish()
    }
}

impl DeploymentPreflightReport {
    /// Reconstructs only the report's structural checksum. It does not
    /// authenticate the supplied configuration or observations.
    pub fn has_valid_binding(&self) -> bool {
        let Ok(reason_count) = u64::try_from(self.reasons.len()) else {
            return false;
        };
        self.version == PREFLIGHT_VERSION
            && valid_reason_shape(self.live, &self.reasons)
            && self.ready == (self.live && self.reasons.is_empty())
            && self.observation_captured_at_unix_seconds != 0
            && self.evaluated_at_unix_seconds >= self.observation_captured_at_unix_seconds
            && self.maximum_observation_age_seconds > 0
            && self.maximum_observation_age_seconds <= OBSERVATION_AGE_SECONDS_HARD_MAXIMUM
            && self
                .evaluated_at_unix_seconds
                .checked_sub(self.observation_captured_at_unix_seconds)
                .is_some_and(|age| age <= self.maximum_observation_age_seconds)
            && WORK_UNITS_WITHOUT_BACKUP_GATE
                .checked_add(u64::from(self.backup_gate_evidence_present))
                .is_some_and(|value| value == self.work_units)
            && retained_charge(reason_count).is_ok_and(|value| value == self.retained_bytes)
            && self.retained_bytes <= RETAINED_BYTES_HARD_MAXIMUM
            && self.report_digest
                == digest_report_fields(
                    self.version,
                    self.configuration_digest,
                    self.observation_digest,
                    self.observation_captured_at_unix_seconds,
                    self.evaluated_at_unix_seconds,
                    self.maximum_observation_age_seconds,
                    self.live,
                    self.ready,
                    self.backup_gate_evidence_present,
                    &self.reasons,
                    reason_count,
                    self.work_units,
                    self.retained_bytes,
                )
    }
}

pub fn build_deployment_preflight(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
    limits: PreflightLimits,
    control: PreflightControl<'_>,
) -> Result<DeploymentPreflightReport, PreflightError> {
    build_deployment_preflight_inner(config, observation, evaluation, limits, control, |_| {})
}

fn build_deployment_preflight_inner(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
    limits: PreflightLimits,
    control: PreflightControl<'_>,
    mut checkpoint: impl FnMut(CancellationStage),
) -> Result<DeploymentPreflightReport, PreflightError> {
    if !limits.valid() {
        return Err(PreflightError::InvalidLimits);
    }
    checkpoint(CancellationStage::Initial);
    control.check()?;
    validate_input_shapes(config, observation)?;
    let backup_gate_evidence_present = observation.backup_gate.is_some();
    let work_units = WORK_UNITS_WITHOUT_BACKUP_GATE
        .checked_add(u64::from(backup_gate_evidence_present))
        .ok_or(PreflightError::AccountingOverflow)?;
    if work_units > limits.max_work_units {
        return Err(PreflightError::WorkLimit);
    }
    checkpoint(CancellationStage::WorkAdmitted);
    control.check()?;
    validate_config(config)?;
    checkpoint(CancellationStage::ConfigurationValidated);
    control.check()?;
    validate_observation(config, observation, evaluation)?;
    checkpoint(CancellationStage::ObservationValidated);
    control.check()?;

    let mut reason_buffer = [SafeReasonCode::ProcessNotLive; DEPENDENCY_COUNT + 1];
    let mut reason_count = 0usize;
    if !observation.process_alive {
        reason_count += 1;
    }
    for dependency in &observation.dependencies {
        checkpoint(CancellationStage::DependencyObservation);
        control.check()?;
        if let Some(reason) = dependency_reason(dependency.kind, dependency.state) {
            reason_buffer[reason_count] = reason;
            reason_count += 1;
        }
    }
    let reason_count_u64 =
        u64::try_from(reason_count).map_err(|_| PreflightError::AccountingOverflow)?;
    let retained_bytes = retained_charge(reason_count_u64)?;
    if retained_bytes > limits.max_retained_bytes {
        return Err(PreflightError::MemoryLimit);
    }
    checkpoint(CancellationStage::RetainedChargeAdmitted);
    control.check()?;

    let reasons = &reason_buffer[..reason_count];
    let configuration_digest = digest_configuration(config);
    let observation_digest = digest_observation(observation);
    let live = observation.process_alive;
    let ready = live && reasons.is_empty();
    let report_digest = digest_report_fields(
        PREFLIGHT_VERSION,
        configuration_digest,
        observation_digest,
        observation.captured_at_unix_seconds,
        evaluation.evaluated_at_unix_seconds,
        evaluation.maximum_observation_age_seconds,
        live,
        ready,
        backup_gate_evidence_present,
        reasons,
        reason_count_u64,
        work_units,
        retained_bytes,
    );
    checkpoint(CancellationStage::BeforeResultAllocation);
    control.check()?;
    let reasons = reasons.to_vec();
    Ok(DeploymentPreflightReport {
        version: PREFLIGHT_VERSION,
        configuration_digest,
        observation_digest,
        observation_captured_at_unix_seconds: observation.captured_at_unix_seconds,
        evaluated_at_unix_seconds: evaluation.evaluated_at_unix_seconds,
        maximum_observation_age_seconds: evaluation.maximum_observation_age_seconds,
        live,
        ready,
        backup_gate_evidence_present,
        reasons,
        work_units,
        retained_bytes,
        report_digest,
    })
}

fn validate_input_shapes(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
) -> Result<(), PreflightError> {
    if config.listeners.len() != LISTENER_COUNT {
        return Err(PreflightError::ListenerSet);
    }
    if config.secrets.len() != SECRET_COUNT {
        return Err(PreflightError::SecretSet);
    }
    if config.service_accounts.len() != SERVICE_ACCOUNT_COUNT {
        return Err(PreflightError::ServiceAccountSet);
    }
    if observation.dependencies.len() != DEPENDENCY_COUNT {
        return Err(PreflightError::ObservationSet);
    }
    Ok(())
}

fn validate_config(config: &DeploymentConfig) -> Result<(), PreflightError> {
    if config.version != PREFLIGHT_VERSION
        || commitments(&[
            config.deployment,
            config.artifact_set,
            config.compatibility_set,
            config.configuration_generation,
        ])
        .is_err()
        || config.telemetry_enabled_by_default
        || config.vendor_check_in_required
        || config.durable_data_policy != DurableDataPolicy::PreserveByDefault
    {
        return Err(PreflightError::InvalidConfiguration);
    }

    let listener_roles = [
        ListenerRole::Api,
        ListenerRole::Admin,
        ListenerRole::Metrics,
    ];
    if config
        .listeners
        .iter()
        .map(|listener| listener.role)
        .ne(listener_roles)
    {
        return Err(PreflightError::ListenerSet);
    }
    for (index, listener) in config.listeners.iter().enumerate() {
        if listener.port == 0
            || config.listeners[..index]
                .iter()
                .any(|prior| prior.port == listener.port)
            || (listener.exposure != Exposure::Loopback && !listener.tls)
            || (listener.role != ListenerRole::Api && listener.exposure != Exposure::Loopback)
        {
            return Err(PreflightError::ListenerSet);
        }
    }

    let secret_purposes = [
        SecretPurpose::Metadata,
        SecretPurpose::ObjectStorage,
        SecretPurpose::IdentitySigning,
        SecretPurpose::BackupEncryption,
    ];
    if config
        .secrets
        .iter()
        .map(|secret| secret.purpose)
        .ne(secret_purposes)
        || config.secrets.iter().enumerate().any(|(index, secret)| {
            secret.reference_commitment == [0; 32]
                || config.secrets[..index]
                    .iter()
                    .any(|prior| prior.reference_commitment == secret.reference_commitment)
                || !secret.access_restricted
                || secret.embedded_in_public_config
                || secret.included_in_diagnostics
        })
    {
        return Err(PreflightError::SecretSet);
    }

    let roles = [
        ServiceRole::ControlPlane,
        ServiceRole::Worker,
        ServiceRole::Administration,
    ];
    if config
        .service_accounts
        .iter()
        .map(|account| account.role)
        .ne(roles)
        || config
            .service_accounts
            .iter()
            .enumerate()
            .any(|(index, account)| {
                account.principal_commitment == [0; 32]
                    || config.service_accounts[..index]
                        .iter()
                        .any(|prior| prior.principal_commitment == account.principal_commitment)
                    || account.privileged_root
                    || account.interactive_login
            })
    {
        return Err(PreflightError::ServiceAccountSet);
    }
    Ok(())
}

fn validate_observation(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
) -> Result<(), PreflightError> {
    if observation.configuration_generation != config.configuration_generation {
        return Err(PreflightError::ObservationSet);
    }
    if observation.compatibility_set != config.compatibility_set {
        return Err(PreflightError::CompatibilityMismatch);
    }
    let kinds = [
        DependencyKind::Metadata,
        DependencyKind::ObjectStorage,
        DependencyKind::Identity,
        DependencyKind::Verifier,
        DependencyKind::Backup,
        DependencyKind::Capacity,
        DependencyKind::Schema,
    ];
    if observation
        .dependencies
        .iter()
        .map(|dependency| dependency.kind)
        .ne(kinds)
        || observation
            .dependencies
            .iter()
            .any(|dependency| dependency.generation_commitment == [0; 32])
    {
        return Err(PreflightError::ObservationSet);
    }

    if observation.captured_at_unix_seconds == 0
        || evaluation.evaluated_at_unix_seconds == 0
        || evaluation.maximum_observation_age_seconds == 0
        || evaluation.maximum_observation_age_seconds > OBSERVATION_AGE_SECONDS_HARD_MAXIMUM
        || observation.captured_at_unix_seconds > evaluation.evaluated_at_unix_seconds
        || evaluation
            .evaluated_at_unix_seconds
            .checked_sub(observation.captured_at_unix_seconds)
            .is_none_or(|age| age > evaluation.maximum_observation_age_seconds)
    {
        return Err(PreflightError::ObservationTimeInvalid);
    }

    if observation.migration.current_schema == 0 || observation.migration.target_schema == 0 {
        return Err(PreflightError::MigrationInvalid);
    }
    match observation.migration.class {
        MigrationClass::None
            if observation.migration.current_schema != observation.migration.target_schema =>
        {
            return Err(PreflightError::MigrationInvalid)
        }
        MigrationClass::Compatible | MigrationClass::Irreversible
            if observation.migration.target_schema <= observation.migration.current_schema =>
        {
            return Err(PreflightError::MigrationInvalid)
        }
        _ => {}
    }

    if observation.migration.class != MigrationClass::Irreversible
        && observation.backup_gate.is_some()
    {
        return Err(PreflightError::BackupGateInvalid);
    }
    if observation.migration.class == MigrationClass::Irreversible
        && observation.backup_gate.is_none()
    {
        return Err(PreflightError::BackupGateInvalid);
    }
    if let Some(backup) = observation.backup_gate {
        let commitments = [
            backup.deployment,
            backup.artifact_set,
            backup.compatibility_set,
            backup.configuration_generation,
            backup.metadata_generation,
            backup.object_storage_generation,
            backup.verifier_generation,
            backup.backup_generation,
            backup.schema_generation,
            backup.backup_manifest,
            backup.verified_backup_manifest,
            backup.verification_report,
            backup.source_storage,
            backup.source_credential_scope,
            backup.target_storage,
            backup.target_credential_scope,
            backup.retention_policy,
            backup.encryption_policy,
        ];
        if commitments.iter().any(|value| *value == [0; 32])
            || backup.deployment != config.deployment
            || backup.artifact_set != config.artifact_set
            || backup.compatibility_set != config.compatibility_set
            || backup.configuration_generation != config.configuration_generation
            || backup.source_schema != observation.migration.current_schema
            || backup.target_schema != observation.migration.target_schema
            || backup.metadata_generation != observation.dependencies[0].generation_commitment
            || backup.object_storage_generation != observation.dependencies[1].generation_commitment
            || backup.verifier_generation != observation.dependencies[3].generation_commitment
            || backup.backup_generation != observation.dependencies[4].generation_commitment
            || backup.schema_generation != observation.dependencies[6].generation_commitment
            || backup.verified_backup_manifest != backup.backup_manifest
            || backup.source_storage == backup.target_storage
            || backup.source_credential_scope == backup.target_credential_scope
            || backup.captured_at_unix_seconds == 0
            || backup.captured_at_unix_seconds > observation.captured_at_unix_seconds
            || backup.retention_until_unix_seconds <= evaluation.evaluated_at_unix_seconds
        {
            return Err(PreflightError::BackupGateInvalid);
        }
    }
    Ok(())
}

fn dependency_reason(kind: DependencyKind, state: DependencyState) -> Option<SafeReasonCode> {
    use DependencyKind as K;
    use DependencyState as S;
    use SafeReasonCode as R;
    match (kind, state) {
        (_, S::Healthy) => None,
        (K::Metadata, S::Degraded) => Some(R::MetadataDegraded),
        (K::Metadata, S::Unavailable) => Some(R::MetadataUnavailable),
        (K::Metadata, S::Incompatible) => Some(R::MetadataIncompatible),
        (K::Metadata, S::Stale) => Some(R::MetadataStale),
        (K::ObjectStorage, S::Degraded) => Some(R::ObjectStorageDegraded),
        (K::ObjectStorage, S::Unavailable) => Some(R::ObjectStorageUnavailable),
        (K::ObjectStorage, S::Incompatible) => Some(R::ObjectStorageIncompatible),
        (K::ObjectStorage, S::Stale) => Some(R::ObjectStorageStale),
        (K::Identity, S::Degraded) => Some(R::IdentityDegraded),
        (K::Identity, S::Unavailable) => Some(R::IdentityUnavailable),
        (K::Identity, S::Incompatible) => Some(R::IdentityIncompatible),
        (K::Identity, S::Stale) => Some(R::IdentityStale),
        (K::Verifier, S::Degraded) => Some(R::VerifierDegraded),
        (K::Verifier, S::Unavailable) => Some(R::VerifierUnavailable),
        (K::Verifier, S::Incompatible) => Some(R::VerifierIncompatible),
        (K::Verifier, S::Stale) => Some(R::VerifierStale),
        (K::Backup, S::Degraded) => Some(R::BackupDegraded),
        (K::Backup, S::Unavailable) => Some(R::BackupUnavailable),
        (K::Backup, S::Incompatible) => Some(R::BackupIncompatible),
        (K::Backup, S::Stale) => Some(R::BackupStale),
        (K::Capacity, S::Degraded) => Some(R::CapacityDegraded),
        (K::Capacity, S::Unavailable) => Some(R::CapacityUnavailable),
        (K::Capacity, S::Incompatible) => Some(R::CapacityIncompatible),
        (K::Capacity, S::Stale) => Some(R::CapacityStale),
        (K::Schema, S::Degraded) => Some(R::SchemaDegraded),
        (K::Schema, S::Unavailable) => Some(R::SchemaUnavailable),
        (K::Schema, S::Incompatible) => Some(R::SchemaIncompatible),
        (K::Schema, S::Stale) => Some(R::SchemaStale),
    }
}

fn valid_reason_shape(live: bool, reasons: &[SafeReasonCode]) -> bool {
    if reasons.len() > DEPENDENCY_COUNT + 1
        || !reasons.windows(2).all(|pair| pair[0] < pair[1])
        || (reasons.first() == Some(&SafeReasonCode::ProcessNotLive)) == live
    {
        return false;
    }

    let mut dependency_seen = [false; DEPENDENCY_COUNT];
    for reason in reasons {
        if *reason == SafeReasonCode::ProcessNotLive {
            continue;
        }
        let group = usize::from(reason.code() / 100);
        let Some(index) = group.checked_sub(1) else {
            return false;
        };
        if index >= DEPENDENCY_COUNT || dependency_seen[index] {
            return false;
        }
        dependency_seen[index] = true;
    }
    true
}

fn commitments(values: &[Commitment]) -> Result<(), PreflightError> {
    if values.iter().any(|value| *value == [0; 32]) {
        Err(PreflightError::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn retained_charge(reason_count: u64) -> Result<u64, PreflightError> {
    reason_count
        .checked_mul(RETAINED_REASON_CHARGE)
        .and_then(|value| value.checked_add(RETAINED_BASE_CHARGE))
        .ok_or(PreflightError::AccountingOverflow)
}

fn digest_configuration(config: &DeploymentConfig) -> Commitment {
    let mut writer = domain_writer(CONFIG_DOMAIN);
    writer.u16(config.version);
    writer.field(&config.deployment);
    writer.field(&config.artifact_set);
    writer.field(&config.compatibility_set);
    writer.field(&config.configuration_generation);
    writer.boolean(config.telemetry_enabled_by_default);
    writer.boolean(config.vendor_check_in_required);
    writer.u8(match config.durable_data_policy {
        DurableDataPolicy::PreserveByDefault => 1,
        DurableDataPolicy::RemoveByDefault => 2,
    });
    writer.u64(3);
    for listener in &config.listeners {
        writer.u8(listener.role.code());
        writer.u8(listener.exposure.code());
        writer.u16(listener.port);
        writer.boolean(listener.tls);
    }
    writer.u64(4);
    for secret in &config.secrets {
        writer.u8(secret.purpose.code());
        writer.u8(secret.provider.code());
        writer.field(&secret.reference_commitment);
        writer.boolean(secret.access_restricted);
        writer.boolean(secret.embedded_in_public_config);
        writer.boolean(secret.included_in_diagnostics);
    }
    writer.u64(3);
    for account in &config.service_accounts {
        writer.u8(account.role.code());
        writer.field(&account.principal_commitment);
        writer.boolean(account.privileged_root);
        writer.boolean(account.interactive_login);
    }
    writer.finish()
}

fn digest_observation(observation: &PreflightObservation) -> Commitment {
    let mut writer = domain_writer(OBSERVATION_DOMAIN);
    writer.u64(observation.captured_at_unix_seconds);
    writer.boolean(observation.process_alive);
    writer.field(&observation.compatibility_set);
    writer.field(&observation.configuration_generation);
    writer.u64(7);
    for dependency in &observation.dependencies {
        writer.u8(dependency.kind.code());
        writer.u8(dependency.state.code());
        writer.field(&dependency.generation_commitment);
    }
    writer.u64(observation.migration.current_schema);
    writer.u64(observation.migration.target_schema);
    writer.u8(observation.migration.class.code());
    writer.boolean(observation.backup_gate.is_some());
    if let Some(backup) = observation.backup_gate {
        writer.field(&backup.deployment);
        writer.field(&backup.artifact_set);
        writer.field(&backup.compatibility_set);
        writer.field(&backup.configuration_generation);
        writer.u64(backup.source_schema);
        writer.u64(backup.target_schema);
        writer.field(&backup.metadata_generation);
        writer.field(&backup.object_storage_generation);
        writer.field(&backup.verifier_generation);
        writer.field(&backup.backup_generation);
        writer.field(&backup.schema_generation);
        writer.field(&backup.backup_manifest);
        writer.field(&backup.verified_backup_manifest);
        writer.field(&backup.verification_report);
        writer.field(&backup.source_storage);
        writer.field(&backup.source_credential_scope);
        writer.field(&backup.target_storage);
        writer.field(&backup.target_credential_scope);
        writer.field(&backup.retention_policy);
        writer.field(&backup.encryption_policy);
        writer.u64(backup.captured_at_unix_seconds);
        writer.u64(backup.retention_until_unix_seconds);
    }
    writer.finish()
}

#[allow(clippy::too_many_arguments)]
fn digest_report_fields(
    version: u16,
    configuration_digest: Commitment,
    observation_digest: Commitment,
    observation_captured_at_unix_seconds: u64,
    evaluated_at_unix_seconds: u64,
    maximum_observation_age_seconds: u64,
    live: bool,
    ready: bool,
    backup_gate_evidence_present: bool,
    reasons: &[SafeReasonCode],
    reason_count: u64,
    work_units: u64,
    retained_bytes: u64,
) -> Commitment {
    let mut writer = domain_writer(REPORT_DOMAIN);
    writer.u16(version);
    writer.field(&configuration_digest);
    writer.field(&observation_digest);
    writer.u64(observation_captured_at_unix_seconds);
    writer.u64(evaluated_at_unix_seconds);
    writer.u64(maximum_observation_age_seconds);
    writer.boolean(live);
    writer.boolean(ready);
    writer.boolean(backup_gate_evidence_present);
    writer.u64(reason_count);
    for reason in reasons {
        writer.u16(reason.code());
    }
    writer.u64(work_units);
    writer.u64(retained_bytes);
    writer.finish()
}

fn domain_writer(domain: &[u8]) -> Sha256Writer {
    let mut writer = Sha256Writer::default();
    writer.field(domain);
    writer
}

#[derive(Default)]
struct Sha256Writer(Sha256);

impl Sha256Writer {
    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u16(&mut self, value: u16) {
        self.0.update(value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn boolean(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn field(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.update(value);
    }

    fn finish(self) -> Commitment {
        self.0.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                provider: if index == 0 {
                    SecretProvider::ProtectedFile
                } else {
                    SecretProvider::ExternalProvider
                },
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

    fn evaluation() -> PreflightEvaluation {
        PreflightEvaluation {
            evaluated_at_unix_seconds: 1_800_000_100,
            maximum_observation_age_seconds: OBSERVATION_AGE_SECONDS_HARD_MAXIMUM,
        }
    }

    fn backup_gate() -> BackupGateEvidence {
        BackupGateEvidence {
            deployment: [1; 32],
            artifact_set: [2; 32],
            compatibility_set: [3; 32],
            configuration_generation: [4; 32],
            source_schema: 9,
            target_schema: 10,
            metadata_generation: [30; 32],
            object_storage_generation: [31; 32],
            verifier_generation: [33; 32],
            backup_generation: [34; 32],
            schema_generation: [36; 32],
            backup_manifest: [41; 32],
            verified_backup_manifest: [41; 32],
            verification_report: [42; 32],
            source_storage: [43; 32],
            source_credential_scope: [44; 32],
            target_storage: [45; 32],
            target_credential_scope: [46; 32],
            retention_policy: [47; 32],
            encryption_policy: [48; 32],
            captured_at_unix_seconds: 1_799_999_000,
            retention_until_unix_seconds: 1_800_100_000,
        }
    }

    fn irreversible_observation() -> PreflightObservation {
        let mut observed = observation();
        observed.migration = MigrationIntent {
            current_schema: 9,
            target_schema: 10,
            class: MigrationClass::Irreversible,
        };
        observed.backup_gate = Some(backup_gate());
        observed
    }

    fn build(
        config: DeploymentConfig,
        observation: PreflightObservation,
    ) -> Result<DeploymentPreflightReport, PreflightError> {
        build_deployment_preflight(
            &config,
            &observation,
            evaluation(),
            PreflightLimits::default(),
            PreflightControl::default(),
        )
    }

    fn reseal_report(report: &mut DeploymentPreflightReport) {
        let reason_count = u64::try_from(report.reasons.len()).unwrap();
        report.report_digest = digest_report_fields(
            report.version,
            report.configuration_digest,
            report.observation_digest,
            report.observation_captured_at_unix_seconds,
            report.evaluated_at_unix_seconds,
            report.maximum_observation_age_seconds,
            report.live,
            report.ready,
            report.backup_gate_evidence_present,
            &report.reasons,
            reason_count,
            report.work_units,
            report.retained_bytes,
        );
    }

    fn projected_report_digest(report: &DeploymentPreflightReport) -> Commitment {
        digest_report_fields(
            report.version,
            report.configuration_digest,
            report.observation_digest,
            report.observation_captured_at_unix_seconds,
            report.evaluated_at_unix_seconds,
            report.maximum_observation_age_seconds,
            report.live,
            report.ready,
            report.backup_gate_evidence_present,
            &report.reasons,
            u64::try_from(report.reasons.len()).unwrap(),
            report.work_units,
            report.retained_bytes,
        )
    }

    fn assert_config_projection_changes(change: impl FnOnce(&mut DeploymentConfig)) {
        let original = digest_configuration(&config());
        let mut changed = config();
        change(&mut changed);
        assert_ne!(digest_configuration(&changed), original);
    }

    fn assert_observation_projection_changes(change: impl FnOnce(&mut PreflightObservation)) {
        let original = digest_observation(&observation());
        let mut changed = observation();
        change(&mut changed);
        assert_ne!(digest_observation(&changed), original);
    }

    #[test]
    fn healthy_exact_topology_has_a_deterministic_known_answer() {
        let first = build(config(), observation()).unwrap();
        let second = build(config(), observation()).unwrap();
        assert_eq!(first, second);
        assert!(first.live);
        assert!(first.ready);
        assert!(!first.backup_gate_evidence_present);
        assert!(first.reasons.is_empty());
        assert_eq!(first.work_units, 18);
        assert_eq!(first.retained_bytes, RETAINED_BASE_CHARGE);
        assert_eq!(
            first.configuration_digest,
            [
                98, 93, 130, 32, 87, 217, 44, 124, 220, 237, 83, 64, 83, 230, 93, 129, 0, 126, 204,
                146, 222, 247, 44, 82, 219, 187, 61, 161, 108, 89, 103, 247,
            ]
        );
        assert_eq!(
            first.observation_digest,
            [
                106, 81, 245, 57, 4, 43, 77, 125, 176, 167, 217, 198, 99, 213, 17, 102, 13, 9, 89,
                54, 221, 119, 209, 194, 71, 16, 111, 93, 215, 127, 119, 127,
            ]
        );
        assert_eq!(
            first.report_digest,
            [
                209, 36, 32, 64, 22, 29, 229, 169, 248, 65, 245, 206, 153, 227, 241, 28, 112, 184,
                253, 183, 109, 81, 180, 212, 42, 90, 238, 135, 83, 27, 7, 55,
            ]
        );
        assert!(first.has_valid_binding());
    }

    #[test]
    fn irreversible_gate_has_a_v2_deterministic_known_answer() {
        let report = build(config(), irreversible_observation()).unwrap();
        assert!(report.ready);
        assert!(report.backup_gate_evidence_present);
        assert_eq!(report.work_units, WORK_UNITS_HARD_MAXIMUM);
        assert_eq!(
            report.observation_digest,
            [
                28, 156, 174, 249, 154, 189, 35, 38, 84, 221, 54, 116, 234, 166, 230, 39, 208, 116,
                188, 211, 12, 134, 104, 147, 113, 124, 185, 55, 168, 122, 177, 227,
            ]
        );
        assert_eq!(
            report.report_digest,
            [
                119, 162, 220, 241, 160, 110, 215, 196, 1, 229, 134, 62, 114, 11, 19, 166, 225, 6,
                194, 186, 75, 71, 163, 154, 182, 98, 60, 156, 206, 26, 163, 162,
            ]
        );
        assert!(report.has_valid_binding());
    }

    #[test]
    fn liveness_is_independent_from_dependency_readiness_and_reasons_are_closed() {
        let mut observed = observation();
        observed.dependencies[1].state = DependencyState::Unavailable;
        observed.dependencies[5].state = DependencyState::Degraded;
        let report = build(config(), observed).unwrap();
        assert!(report.live);
        assert!(!report.ready);
        assert_eq!(
            report.reasons,
            [
                SafeReasonCode::ObjectStorageUnavailable,
                SafeReasonCode::CapacityDegraded,
            ]
        );

        let mut observed = observation();
        observed.process_alive = false;
        let report = build(config(), observed).unwrap();
        assert!(!report.live);
        assert!(!report.ready);
        assert_eq!(report.reasons, [SafeReasonCode::ProcessNotLive]);
    }

    #[test]
    fn listener_exposure_and_ports_fail_closed() {
        let mut duplicate = config();
        duplicate.listeners[2].port = duplicate.listeners[1].port;
        assert_eq!(
            build(duplicate, observation()),
            Err(PreflightError::ListenerSet)
        );

        let mut cleartext = config();
        cleartext.listeners[0].tls = false;
        assert_eq!(
            build(cleartext, observation()),
            Err(PreflightError::ListenerSet)
        );

        let mut exposed_admin = config();
        exposed_admin.listeners[1].exposure = Exposure::PrivateNetwork;
        assert_eq!(
            build(exposed_admin, observation()),
            Err(PreflightError::ListenerSet)
        );
    }

    #[test]
    fn secret_and_service_account_facts_reject_unsafe_shapes() {
        let mut secret = config();
        secret.secrets[0].included_in_diagnostics = true;
        assert_eq!(build(secret, observation()), Err(PreflightError::SecretSet));

        let mut aliased_secret = config();
        aliased_secret.secrets[3].reference_commitment =
            aliased_secret.secrets[0].reference_commitment;
        assert_eq!(
            build(aliased_secret, observation()),
            Err(PreflightError::SecretSet)
        );

        let mut account = config();
        account.service_accounts[1].principal_commitment =
            account.service_accounts[0].principal_commitment;
        assert_eq!(
            build(account, observation()),
            Err(PreflightError::ServiceAccountSet)
        );

        let mut invalid_defaults = config();
        invalid_defaults.telemetry_enabled_by_default = true;
        assert_eq!(
            build(invalid_defaults, observation()),
            Err(PreflightError::InvalidConfiguration)
        );

        for debug in [
            format!("{:?}", config()),
            format!("{:?}", observation()),
            format!("{:?}", backup_gate()),
            format!("{:?}", build(config(), observation()).unwrap()),
        ] {
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains("[1, 1, 1"));
            assert!(!debug.contains("[10, 10, 10"));
            assert!(!debug.contains("[41, 41, 41"));
        }
    }

    #[test]
    fn observations_require_exact_order_generation_and_compatibility() {
        let mut reordered = observation();
        reordered.dependencies.swap(0, 1);
        assert_eq!(
            build(config(), reordered),
            Err(PreflightError::ObservationSet)
        );

        let mut stale = observation();
        stale.configuration_generation = [99; 32];
        assert_eq!(build(config(), stale), Err(PreflightError::ObservationSet));

        let mut incompatible = observation();
        incompatible.compatibility_set = [98; 32];
        assert_eq!(
            build(config(), incompatible),
            Err(PreflightError::CompatibilityMismatch)
        );
    }

    #[test]
    fn every_fixed_collection_rejects_missing_and_maximum_plus_one_before_traversal() {
        let mut missing_listener = config();
        missing_listener.listeners.pop();
        assert_eq!(
            build(missing_listener, observation()),
            Err(PreflightError::ListenerSet)
        );
        let mut extra_listener = config();
        extra_listener.listeners.push(extra_listener.listeners[0]);
        assert_eq!(
            build(extra_listener, observation()),
            Err(PreflightError::ListenerSet)
        );

        let mut missing_secret = config();
        missing_secret.secrets.pop();
        assert_eq!(
            build(missing_secret, observation()),
            Err(PreflightError::SecretSet)
        );
        let mut extra_secret = config();
        extra_secret.secrets.push(extra_secret.secrets[0]);
        assert_eq!(
            build(extra_secret, observation()),
            Err(PreflightError::SecretSet)
        );

        let mut missing_account = config();
        missing_account.service_accounts.pop();
        assert_eq!(
            build(missing_account, observation()),
            Err(PreflightError::ServiceAccountSet)
        );
        let mut extra_account = config();
        extra_account
            .service_accounts
            .push(extra_account.service_accounts[0]);
        assert_eq!(
            build(extra_account, observation()),
            Err(PreflightError::ServiceAccountSet)
        );

        let mut missing_dependency = observation();
        missing_dependency.dependencies.pop();
        assert_eq!(
            build(config(), missing_dependency),
            Err(PreflightError::ObservationSet)
        );
        let mut extra_dependency = observation();
        extra_dependency
            .dependencies
            .push(extra_dependency.dependencies[0]);
        assert_eq!(
            build(config(), extra_dependency),
            Err(PreflightError::ObservationSet)
        );
    }

    #[test]
    fn all_dependency_reason_classes_are_exact_and_sorted() {
        for index in 0..DEPENDENCY_COUNT {
            for state in [
                DependencyState::Degraded,
                DependencyState::Unavailable,
                DependencyState::Incompatible,
                DependencyState::Stale,
            ] {
                let mut observed = observation();
                observed.dependencies[index].state = state;
                let expected = dependency_reason(observed.dependencies[index].kind, state).unwrap();
                let report = build(config(), observed).unwrap();
                assert_eq!(report.reasons, [expected]);
                assert!(!report.ready);
                assert!(report.has_valid_binding());
            }
        }

        let mut observed = observation();
        observed.process_alive = false;
        for dependency in &mut observed.dependencies {
            dependency.state = DependencyState::Unavailable;
        }
        let report = build(config(), observed).unwrap();
        assert_eq!(report.reasons.len(), DEPENDENCY_COUNT + 1);
        assert!(report.reasons.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(report.retained_bytes, RETAINED_BYTES_HARD_MAXIMUM);
    }

    #[test]
    fn evaluation_time_and_backup_retention_have_exact_causal_edges() {
        let mut exact = evaluation();
        exact.evaluated_at_unix_seconds =
            observation().captured_at_unix_seconds + OBSERVATION_AGE_SECONDS_HARD_MAXIMUM;
        assert!(build_deployment_preflight(
            &config(),
            &observation(),
            exact,
            PreflightLimits::default(),
            PreflightControl::default(),
        )
        .is_ok());

        let mut too_old = exact;
        too_old.evaluated_at_unix_seconds += 1;
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &observation(),
                too_old,
                PreflightLimits::default(),
                PreflightControl::default(),
            ),
            Err(PreflightError::ObservationTimeInvalid)
        );

        let mut future = observation();
        future.captured_at_unix_seconds = evaluation().evaluated_at_unix_seconds + 1;
        assert_eq!(
            build(config(), future),
            Err(PreflightError::ObservationTimeInvalid)
        );

        let mut zero_age = evaluation();
        zero_age.maximum_observation_age_seconds = 0;
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &observation(),
                zero_age,
                PreflightLimits::default(),
                PreflightControl::default(),
            ),
            Err(PreflightError::ObservationTimeInvalid)
        );

        let mut observed = irreversible_observation();
        observed
            .backup_gate
            .as_mut()
            .unwrap()
            .retention_until_unix_seconds = evaluation().evaluated_at_unix_seconds;
        assert_eq!(
            build(config(), observed.clone()),
            Err(PreflightError::BackupGateInvalid)
        );
        observed
            .backup_gate
            .as_mut()
            .unwrap()
            .retention_until_unix_seconds += 1;
        assert!(build(config(), observed).is_ok());

        let mut maximum_time = observation();
        maximum_time.captured_at_unix_seconds = u64::MAX - OBSERVATION_AGE_SECONDS_HARD_MAXIMUM;
        assert!(build_deployment_preflight(
            &config(),
            &maximum_time,
            PreflightEvaluation {
                evaluated_at_unix_seconds: u64::MAX,
                maximum_observation_age_seconds: OBSERVATION_AGE_SECONDS_HARD_MAXIMUM,
            },
            PreflightLimits::default(),
            PreflightControl::default(),
        )
        .is_ok());

        let mut maximum_retention = irreversible_observation();
        maximum_retention.captured_at_unix_seconds = u64::MAX - 1;
        let backup = maximum_retention.backup_gate.as_mut().unwrap();
        backup.captured_at_unix_seconds = u64::MAX - 2;
        backup.retention_until_unix_seconds = u64::MAX;
        let maximum_evaluation = PreflightEvaluation {
            evaluated_at_unix_seconds: u64::MAX - 1,
            maximum_observation_age_seconds: 1,
        };
        assert!(build_deployment_preflight(
            &config(),
            &maximum_retention,
            maximum_evaluation,
            PreflightLimits::default(),
            PreflightControl::default(),
        )
        .is_ok());
    }

    #[test]
    fn irreversible_backup_gate_binds_scope_source_state_and_verification_subject() {
        macro_rules! reject_gate_change {
            ($field:ident, $value:expr) => {{
                let mut observed = irreversible_observation();
                observed.backup_gate.as_mut().unwrap().$field = $value;
                assert_eq!(
                    build(config(), observed),
                    Err(PreflightError::BackupGateInvalid),
                    "field {} must be checked",
                    stringify!($field)
                );
            }};
        }

        reject_gate_change!(deployment, [90; 32]);
        reject_gate_change!(artifact_set, [90; 32]);
        reject_gate_change!(compatibility_set, [90; 32]);
        reject_gate_change!(configuration_generation, [90; 32]);
        reject_gate_change!(source_schema, 8);
        reject_gate_change!(target_schema, 11);
        reject_gate_change!(metadata_generation, [90; 32]);
        reject_gate_change!(object_storage_generation, [90; 32]);
        reject_gate_change!(verifier_generation, [90; 32]);
        reject_gate_change!(backup_generation, [90; 32]);
        reject_gate_change!(schema_generation, [90; 32]);
        reject_gate_change!(verified_backup_manifest, [90; 32]);

        let mut aliased_storage = irreversible_observation();
        let source = aliased_storage.backup_gate.unwrap().source_storage;
        aliased_storage.backup_gate.as_mut().unwrap().target_storage = source;
        assert_eq!(
            build(config(), aliased_storage),
            Err(PreflightError::BackupGateInvalid)
        );

        let mut aliased_credentials = irreversible_observation();
        let source = aliased_credentials
            .backup_gate
            .unwrap()
            .source_credential_scope;
        aliased_credentials
            .backup_gate
            .as_mut()
            .unwrap()
            .target_credential_scope = source;
        assert_eq!(
            build(config(), aliased_credentials),
            Err(PreflightError::BackupGateInvalid)
        );

        let mut future_capture = irreversible_observation();
        future_capture
            .backup_gate
            .as_mut()
            .unwrap()
            .captured_at_unix_seconds = future_capture.captured_at_unix_seconds + 1;
        assert_eq!(
            build(config(), future_capture),
            Err(PreflightError::BackupGateInvalid)
        );

        let mut unused = observation();
        unused.backup_gate = Some(backup_gate());
        assert_eq!(
            build(config(), unused),
            Err(PreflightError::BackupGateInvalid)
        );
    }

    #[test]
    fn input_shapes_reject_before_configured_work_and_schema_downgrade_rejects() {
        let mut oversized = config();
        oversized.listeners.push(oversized.listeners[0]);
        assert_eq!(
            build_deployment_preflight(
                &oversized,
                &observation(),
                evaluation(),
                PreflightLimits {
                    max_work_units: 1,
                    ..PreflightLimits::default()
                },
                PreflightControl::default(),
            ),
            Err(PreflightError::ListenerSet)
        );

        let mut zero = observation();
        zero.migration.current_schema = 0;
        zero.migration.target_schema = 0;
        assert_eq!(build(config(), zero), Err(PreflightError::MigrationInvalid));

        let mut downgrade = observation();
        downgrade.migration = MigrationIntent {
            current_schema: 10,
            target_schema: 9,
            class: MigrationClass::Compatible,
        };
        assert_eq!(
            build(config(), downgrade),
            Err(PreflightError::MigrationInvalid)
        );
    }

    #[test]
    fn validation_error_precedence_is_stable_and_admission_first() {
        let cancellation = AtomicBool::new(true);
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &observation(),
                evaluation(),
                PreflightLimits {
                    max_work_units: WORK_UNITS_HARD_MAXIMUM + 1,
                    ..PreflightLimits::default()
                },
                PreflightControl::with_cancellation(&cancellation),
            ),
            Err(PreflightError::InvalidLimits)
        );

        let mut bad_shape = config();
        bad_shape.listeners.clear();
        assert_eq!(
            build_deployment_preflight(
                &bad_shape,
                &observation(),
                evaluation(),
                PreflightLimits::default(),
                PreflightControl::with_cancellation(&cancellation),
            ),
            Err(PreflightError::Cancelled)
        );

        let mut invalid_config = config();
        invalid_config.telemetry_enabled_by_default = true;
        let mut invalid_observation = observation();
        invalid_observation.configuration_generation = [90; 32];
        assert_eq!(
            build_deployment_preflight(
                &invalid_config,
                &invalid_observation,
                evaluation(),
                PreflightLimits {
                    max_work_units: WORK_UNITS_WITHOUT_BACKUP_GATE - 1,
                    ..PreflightLimits::default()
                },
                PreflightControl::default(),
            ),
            Err(PreflightError::WorkLimit)
        );
        assert_eq!(
            build(invalid_config, invalid_observation),
            Err(PreflightError::InvalidConfiguration)
        );

        let mut mismatched = observation();
        mismatched.compatibility_set = [90; 32];
        mismatched.captured_at_unix_seconds = evaluation().evaluated_at_unix_seconds + 1;
        assert_eq!(
            build(config(), mismatched),
            Err(PreflightError::CompatibilityMismatch)
        );

        let mut bad_time_and_migration = observation();
        bad_time_and_migration.captured_at_unix_seconds =
            evaluation().evaluated_at_unix_seconds + 1;
        bad_time_and_migration.migration.current_schema = 0;
        assert_eq!(
            build(config(), bad_time_and_migration),
            Err(PreflightError::ObservationTimeInvalid)
        );
    }

    #[test]
    fn irreversible_migration_requires_current_retained_verified_backup_facts() {
        let mut missing = observation();
        missing.migration = MigrationIntent {
            current_schema: 9,
            target_schema: 10,
            class: MigrationClass::Irreversible,
        };
        assert_eq!(
            build(config(), missing.clone()),
            Err(PreflightError::BackupGateInvalid)
        );

        missing.backup_gate = Some(backup_gate());
        let report = build(config(), missing.clone()).unwrap();
        assert!(report.ready);
        assert!(report.backup_gate_evidence_present);

        missing
            .backup_gate
            .as_mut()
            .unwrap()
            .retention_until_unix_seconds = missing.captured_at_unix_seconds;
        assert_eq!(
            build(config(), missing),
            Err(PreflightError::BackupGateInvalid)
        );
    }

    #[test]
    fn configured_work_memory_and_cancellation_limits_are_atomic() {
        let cancellation = AtomicBool::new(true);
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &observation(),
                evaluation(),
                PreflightLimits::default(),
                PreflightControl::with_cancellation(&cancellation),
            ),
            Err(PreflightError::Cancelled)
        );
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &observation(),
                evaluation(),
                PreflightLimits {
                    max_work_units: 17,
                    ..PreflightLimits::default()
                },
                PreflightControl::default(),
            ),
            Err(PreflightError::WorkLimit)
        );
        assert!(build_deployment_preflight(
            &config(),
            &observation(),
            evaluation(),
            PreflightLimits {
                max_work_units: 18,
                ..PreflightLimits::default()
            },
            PreflightControl::default(),
        )
        .is_ok());
        let mut observed = observation();
        observed.dependencies[0].state = DependencyState::Unavailable;
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &observed,
                evaluation(),
                PreflightLimits {
                    max_retained_bytes: RETAINED_BASE_CHARGE,
                    ..PreflightLimits::default()
                },
                PreflightControl::default(),
            ),
            Err(PreflightError::MemoryLimit)
        );
        assert!(build_deployment_preflight(
            &config(),
            &observed,
            evaluation(),
            PreflightLimits {
                max_retained_bytes: RETAINED_BASE_CHARGE + RETAINED_REASON_CHARGE,
                ..PreflightLimits::default()
            },
            PreflightControl::default(),
        )
        .is_ok());

        for limits in [
            PreflightLimits {
                max_work_units: WORK_UNITS_HARD_MAXIMUM + 1,
                ..PreflightLimits::default()
            },
            PreflightLimits {
                max_retained_bytes: RETAINED_BYTES_HARD_MAXIMUM + 1,
                ..PreflightLimits::default()
            },
        ] {
            assert_eq!(
                build_deployment_preflight(
                    &config(),
                    &observation(),
                    evaluation(),
                    limits,
                    PreflightControl::default(),
                ),
                Err(PreflightError::InvalidLimits)
            );
        }

        assert_eq!(
            build_deployment_preflight(
                &config(),
                &irreversible_observation(),
                evaluation(),
                PreflightLimits {
                    max_work_units: WORK_UNITS_HARD_MAXIMUM - 1,
                    ..PreflightLimits::default()
                },
                PreflightControl::default(),
            ),
            Err(PreflightError::WorkLimit)
        );
        let maximum_work = build(config(), irreversible_observation()).unwrap();
        assert_eq!(maximum_work.work_units, WORK_UNITS_HARD_MAXIMUM);

        let mut maximum_reasons = observation();
        maximum_reasons.process_alive = false;
        for dependency in &mut maximum_reasons.dependencies {
            dependency.state = DependencyState::Unavailable;
        }
        assert_eq!(
            build_deployment_preflight(
                &config(),
                &maximum_reasons,
                evaluation(),
                PreflightLimits {
                    max_retained_bytes: RETAINED_BYTES_HARD_MAXIMUM - 1,
                    ..PreflightLimits::default()
                },
                PreflightControl::default(),
            ),
            Err(PreflightError::MemoryLimit)
        );
        let maximum_memory = build(config(), maximum_reasons).unwrap();
        assert_eq!(maximum_memory.retained_bytes, RETAINED_BYTES_HARD_MAXIMUM);
    }

    #[test]
    fn cancellation_after_hashing_still_precedes_result_allocation() {
        let cancellation = AtomicBool::new(false);
        let result = build_deployment_preflight_inner(
            &config(),
            &observation(),
            evaluation(),
            PreflightLimits::default(),
            PreflightControl::with_cancellation(&cancellation),
            |stage| {
                if stage == CancellationStage::BeforeResultAllocation {
                    cancellation.store(true, Ordering::Release);
                }
            },
        );
        assert_eq!(result, Err(PreflightError::Cancelled));
    }

    #[test]
    fn every_configuration_observation_and_report_projection_field_is_bound() {
        assert_config_projection_changes(|value| value.version += 1);
        assert_config_projection_changes(|value| value.deployment = [70; 32]);
        assert_config_projection_changes(|value| value.artifact_set = [70; 32]);
        assert_config_projection_changes(|value| value.compatibility_set = [70; 32]);
        assert_config_projection_changes(|value| value.configuration_generation = [70; 32]);
        assert_config_projection_changes(|value| value.telemetry_enabled_by_default = true);
        assert_config_projection_changes(|value| value.vendor_check_in_required = true);
        assert_config_projection_changes(|value| {
            value.durable_data_policy = DurableDataPolicy::RemoveByDefault;
        });
        assert_config_projection_changes(|value| value.listeners.push(value.listeners[0]));
        assert_config_projection_changes(|value| value.listeners[0].role = ListenerRole::Admin);
        assert_config_projection_changes(|value| value.listeners[0].exposure = Exposure::Public);
        assert_config_projection_changes(|value| value.listeners[0].port += 1);
        assert_config_projection_changes(|value| value.listeners[0].tls = false);
        assert_config_projection_changes(|value| value.secrets.push(value.secrets[0]));
        assert_config_projection_changes(|value| {
            value.secrets[0].purpose = SecretPurpose::ObjectStorage;
        });
        assert_config_projection_changes(|value| {
            value.secrets[0].provider = SecretProvider::ExternalProvider;
        });
        assert_config_projection_changes(|value| {
            value.secrets[0].reference_commitment = [70; 32];
        });
        assert_config_projection_changes(|value| value.secrets[0].access_restricted = false);
        assert_config_projection_changes(|value| {
            value.secrets[0].embedded_in_public_config = true;
        });
        assert_config_projection_changes(|value| {
            value.secrets[0].included_in_diagnostics = true;
        });
        assert_config_projection_changes(|value| {
            value.service_accounts.push(value.service_accounts[0]);
        });
        assert_config_projection_changes(|value| {
            value.service_accounts[0].role = ServiceRole::Worker;
        });
        assert_config_projection_changes(|value| {
            value.service_accounts[0].principal_commitment = [70; 32];
        });
        assert_config_projection_changes(|value| {
            value.service_accounts[0].privileged_root = true;
        });
        assert_config_projection_changes(|value| {
            value.service_accounts[0].interactive_login = true;
        });

        assert_observation_projection_changes(|value| value.captured_at_unix_seconds += 1);
        assert_observation_projection_changes(|value| value.process_alive = false);
        assert_observation_projection_changes(|value| value.compatibility_set = [70; 32]);
        assert_observation_projection_changes(|value| {
            value.configuration_generation = [70; 32];
        });
        assert_observation_projection_changes(|value| {
            value.dependencies.push(value.dependencies[0]);
        });
        assert_observation_projection_changes(|value| {
            value.dependencies[0].kind = DependencyKind::ObjectStorage;
        });
        assert_observation_projection_changes(|value| {
            value.dependencies[0].state = DependencyState::Degraded;
        });
        assert_observation_projection_changes(|value| {
            value.dependencies[0].generation_commitment = [70; 32];
        });
        assert_observation_projection_changes(|value| value.migration.current_schema += 1);
        assert_observation_projection_changes(|value| value.migration.target_schema += 1);
        assert_observation_projection_changes(|value| {
            value.migration.class = MigrationClass::Compatible;
        });
        assert_observation_projection_changes(|value| value.backup_gate = Some(backup_gate()));

        let original = digest_observation(&irreversible_observation());
        macro_rules! assert_backup_projection {
            ($field:ident, $value:expr) => {{
                let mut changed = irreversible_observation();
                changed.backup_gate.as_mut().unwrap().$field = $value;
                assert_ne!(
                    digest_observation(&changed),
                    original,
                    "{}",
                    stringify!($field)
                );
            }};
        }
        assert_backup_projection!(deployment, [70; 32]);
        assert_backup_projection!(artifact_set, [70; 32]);
        assert_backup_projection!(compatibility_set, [70; 32]);
        assert_backup_projection!(configuration_generation, [70; 32]);
        assert_backup_projection!(source_schema, 8);
        assert_backup_projection!(target_schema, 11);
        assert_backup_projection!(metadata_generation, [70; 32]);
        assert_backup_projection!(object_storage_generation, [70; 32]);
        assert_backup_projection!(verifier_generation, [70; 32]);
        assert_backup_projection!(backup_generation, [70; 32]);
        assert_backup_projection!(schema_generation, [70; 32]);
        assert_backup_projection!(backup_manifest, [70; 32]);
        assert_backup_projection!(verified_backup_manifest, [70; 32]);
        assert_backup_projection!(verification_report, [70; 32]);
        assert_backup_projection!(source_storage, [70; 32]);
        assert_backup_projection!(source_credential_scope, [70; 32]);
        assert_backup_projection!(target_storage, [70; 32]);
        assert_backup_projection!(target_credential_scope, [70; 32]);
        assert_backup_projection!(retention_policy, [70; 32]);
        assert_backup_projection!(encryption_policy, [70; 32]);
        assert_backup_projection!(captured_at_unix_seconds, 1_799_999_001);
        assert_backup_projection!(retention_until_unix_seconds, 1_800_100_001);

        let report = build(config(), observation()).unwrap();
        assert_eq!(report.report_digest, projected_report_digest(&report));
        macro_rules! assert_report_projection {
            ($change:expr) => {{
                let mut changed = report.clone();
                $change(&mut changed);
                assert_ne!(projected_report_digest(&changed), report.report_digest);
            }};
        }
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value.version += 1);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .configuration_digest =
            [70; 32]);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .observation_digest =
            [70; 32]);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .observation_captured_at_unix_seconds +=
            1);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .evaluated_at_unix_seconds +=
            1);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .maximum_observation_age_seconds -=
            1);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value.live = false);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value.ready = false);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .backup_gate_evidence_present =
            true);
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value
            .reasons
            .push(SafeReasonCode::MetadataDegraded));
        assert_report_projection!(|value: &mut DeploymentPreflightReport| value.work_units += 1);
        assert_report_projection!(
            |value: &mut DeploymentPreflightReport| value.retained_bytes += 1
        );
    }

    #[test]
    fn structural_self_check_detects_report_tampering_only() {
        let mut report = build(config(), observation()).unwrap();
        assert!(report.has_valid_binding());
        report.work_units += 1;
        assert!(!report.has_valid_binding());

        let mut report = build(config(), observation()).unwrap();
        report.work_units += 1;
        reseal_report(&mut report);
        assert!(!report.has_valid_binding());

        let mut report = build(config(), observation()).unwrap();
        report.configuration_digest = [88; 32];
        reseal_report(&mut report);
        assert!(report.has_valid_binding());

        let mut report = build(config(), observation()).unwrap();
        report.ready = false;
        reseal_report(&mut report);
        assert!(!report.has_valid_binding());

        let mut observed = observation();
        observed.dependencies[0].state = DependencyState::Unavailable;
        let mut report = build(config(), observed).unwrap();
        report.reasons = vec![
            SafeReasonCode::MetadataDegraded,
            SafeReasonCode::MetadataUnavailable,
        ];
        report.retained_bytes = retained_charge(2).unwrap();
        reseal_report(&mut report);
        assert!(!report.has_valid_binding());

        let mut report = build(config(), observation()).unwrap();
        report.observation_captured_at_unix_seconds = report.evaluated_at_unix_seconds + 1;
        reseal_report(&mut report);
        assert!(!report.has_valid_binding());
    }
}
