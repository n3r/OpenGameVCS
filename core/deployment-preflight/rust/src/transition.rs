use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    digest_configuration, domain_writer, validate_config, validate_config_shape, Commitment,
    DeploymentConfig, PreflightError,
};

pub const TRANSITION_VERSION: u16 = 1;
pub const TRANSITION_WORK_UNITS: u64 = 21;
pub const TRANSITION_WORK_UNITS_HARD_MAXIMUM: u64 = TRANSITION_WORK_UNITS;
pub const TRANSITION_RETAINED_BYTES: u64 = 192;
pub const TRANSITION_RETAINED_BYTES_HARD_MAXIMUM: u64 = TRANSITION_RETAINED_BYTES;

const TRANSITION_DOMAIN: &[u8] = b"OGVCS-PRIVATE-DEPLOYMENT-CONFIG-TRANSITION-V1";
const CONFIGURATION_ITEMS_PER_SIDE: u64 = 10;
const KNOWN_CHANGE_BITS: u16 = ConfigurationChange::ArtifactSet.bit()
    | ConfigurationChange::CompatibilitySet.bit()
    | ConfigurationChange::ConfigurationGeneration.bit()
    | ConfigurationChange::Listeners.bit()
    | ConfigurationChange::SecretBindings.bit()
    | ConfigurationChange::ServiceAccounts.bit();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ConfigurationChange {
    ArtifactSet = 1 << 0,
    CompatibilitySet = 1 << 1,
    ConfigurationGeneration = 1 << 2,
    Listeners = 1 << 3,
    SecretBindings = 1 << 4,
    ServiceAccounts = 1 << 5,
}

impl ConfigurationChange {
    const fn bit(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ConfigurationChangeSet(u16);

impl ConfigurationChangeSet {
    const EMPTY: Self = Self(0);

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn contains(self, change: ConfigurationChange) -> bool {
        self.0 & change.bit() != 0
    }

    fn insert(&mut self, change: ConfigurationChange) {
        self.0 |= change.bit();
    }

    const fn has_only_known_bits(self) -> bool {
        self.0 & !KNOWN_CHANGE_BITS == 0
    }

    const fn requires_external_deployment_procedure(self) -> bool {
        self.contains(ConfigurationChange::ArtifactSet)
            || self.contains(ConfigurationChange::CompatibilitySet)
    }
}

impl fmt::Debug for ConfigurationChangeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigurationChangeSet")
            .field("changes", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransitionDisposition {
    NoChangeObserved = 1,
    FullRestartRequired = 2,
    ExternalDeploymentProcedureRequired = 3,
}

impl TransitionDisposition {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionLimits {
    pub max_work_units: u64,
    pub max_retained_bytes: u64,
}

impl Default for TransitionLimits {
    fn default() -> Self {
        Self {
            max_work_units: TRANSITION_WORK_UNITS_HARD_MAXIMUM,
            max_retained_bytes: TRANSITION_RETAINED_BYTES_HARD_MAXIMUM,
        }
    }
}

impl TransitionLimits {
    const fn valid(self) -> bool {
        self.max_work_units > 0
            && self.max_work_units <= TRANSITION_WORK_UNITS_HARD_MAXIMUM
            && self.max_retained_bytes > 0
            && self.max_retained_bytes <= TRANSITION_RETAINED_BYTES_HARD_MAXIMUM
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TransitionControl<'a> {
    cancellation: Option<&'a AtomicBool>,
}

impl<'a> TransitionControl<'a> {
    pub const fn with_cancellation(cancellation: &'a AtomicBool) -> Self {
        Self {
            cancellation: Some(cancellation),
        }
    }

    fn check(self) -> Result<(), TransitionError> {
        if self
            .cancellation
            .is_some_and(|value| value.load(Ordering::Acquire))
        {
            Err(TransitionError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationSide {
    Prior,
    Replacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionError {
    InvalidLimits,
    Cancelled,
    ConfigurationInvalid {
        side: ConfigurationSide,
        source: PreflightError,
    },
    WorkLimit,
    MemoryLimit,
    AccountingOverflow,
    DeploymentBindingChanged,
    ConfigurationGenerationReused,
    UnclassifiedChange,
}

impl TransitionError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimits => "DEPLOYMENT_TRANSITION_LIMITS_INVALID",
            Self::Cancelled => "DEPLOYMENT_TRANSITION_CANCELLED",
            Self::ConfigurationInvalid {
                side: ConfigurationSide::Prior,
                ..
            } => "DEPLOYMENT_TRANSITION_PRIOR_CONFIGURATION_INVALID",
            Self::ConfigurationInvalid {
                side: ConfigurationSide::Replacement,
                ..
            } => "DEPLOYMENT_TRANSITION_REPLACEMENT_CONFIGURATION_INVALID",
            Self::WorkLimit => "DEPLOYMENT_TRANSITION_WORK_LIMIT",
            Self::MemoryLimit => "DEPLOYMENT_TRANSITION_MEMORY_LIMIT",
            Self::AccountingOverflow => "DEPLOYMENT_TRANSITION_ACCOUNTING_OVERFLOW",
            Self::DeploymentBindingChanged => "DEPLOYMENT_TRANSITION_DEPLOYMENT_CHANGED",
            Self::ConfigurationGenerationReused => {
                "DEPLOYMENT_TRANSITION_CONFIGURATION_GENERATION_REUSED"
            }
            Self::UnclassifiedChange => "DEPLOYMENT_TRANSITION_CHANGE_UNCLASSIFIED",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeploymentConfigTransitionAssessment {
    pub version: u16,
    pub prior_configuration_digest: Commitment,
    pub replacement_configuration_digest: Commitment,
    pub changes: ConfigurationChangeSet,
    pub disposition: TransitionDisposition,
    pub work_units: u64,
    pub retained_bytes: u64,
    pub assessment_digest: Commitment,
}

impl fmt::Debug for DeploymentConfigTransitionAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentConfigTransitionAssessment")
            .field("bindings", &"<redacted>")
            .field("changes", &"<redacted>")
            .field("disposition", &self.disposition)
            .field("work_units", &self.work_units)
            .field("retained_bytes", &self.retained_bytes)
            .finish()
    }
}

impl DeploymentConfigTransitionAssessment {
    /// Reconstructs only this assessment's structural checksum. It does not
    /// authenticate either supplied configuration or authorize an operation.
    pub fn has_valid_binding(&self) -> bool {
        let Some(expected_disposition) = disposition_for(self.changes) else {
            return false;
        };
        let digest_relationship_is_valid = if self.changes.is_empty() {
            self.prior_configuration_digest == self.replacement_configuration_digest
        } else {
            self.prior_configuration_digest != self.replacement_configuration_digest
        };
        self.version == TRANSITION_VERSION
            && self.prior_configuration_digest != [0; 32]
            && self.replacement_configuration_digest != [0; 32]
            && digest_relationship_is_valid
            && self.disposition == expected_disposition
            && self.work_units == TRANSITION_WORK_UNITS
            && self.retained_bytes == TRANSITION_RETAINED_BYTES
            && self.assessment_digest
                == digest_assessment_fields(
                    self.version,
                    self.prior_configuration_digest,
                    self.replacement_configuration_digest,
                    self.changes,
                    self.disposition,
                    self.work_units,
                    self.retained_bytes,
                )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionCancellationStage {
    Initial,
    WorkAdmitted,
    PriorConfigurationValidated,
    ReplacementConfigurationValidated,
    Classified,
    RetainedChargeAdmitted,
    BeforeResult,
}

pub fn assess_deployment_config_transition(
    prior: &DeploymentConfig,
    replacement: &DeploymentConfig,
    limits: TransitionLimits,
    control: TransitionControl<'_>,
) -> Result<DeploymentConfigTransitionAssessment, TransitionError> {
    assess_deployment_config_transition_inner(prior, replacement, limits, control, |_| {})
}

fn assess_deployment_config_transition_inner(
    prior: &DeploymentConfig,
    replacement: &DeploymentConfig,
    limits: TransitionLimits,
    control: TransitionControl<'_>,
    mut checkpoint: impl FnMut(TransitionCancellationStage),
) -> Result<DeploymentConfigTransitionAssessment, TransitionError> {
    if !limits.valid() {
        return Err(TransitionError::InvalidLimits);
    }
    checkpoint(TransitionCancellationStage::Initial);
    control.check()?;

    validate_config_shape(prior).map_err(|source| TransitionError::ConfigurationInvalid {
        side: ConfigurationSide::Prior,
        source,
    })?;
    validate_config_shape(replacement).map_err(|source| TransitionError::ConfigurationInvalid {
        side: ConfigurationSide::Replacement,
        source,
    })?;

    let work_units = transition_work_units(prior, replacement)?;
    if work_units > limits.max_work_units {
        return Err(TransitionError::WorkLimit);
    }
    checkpoint(TransitionCancellationStage::WorkAdmitted);
    control.check()?;

    validate_config(prior).map_err(|source| TransitionError::ConfigurationInvalid {
        side: ConfigurationSide::Prior,
        source,
    })?;
    checkpoint(TransitionCancellationStage::PriorConfigurationValidated);
    control.check()?;

    validate_config(replacement).map_err(|source| TransitionError::ConfigurationInvalid {
        side: ConfigurationSide::Replacement,
        source,
    })?;
    checkpoint(TransitionCancellationStage::ReplacementConfigurationValidated);
    control.check()?;

    if prior.deployment != replacement.deployment {
        return Err(TransitionError::DeploymentBindingChanged);
    }

    let changes = classify_changes(prior, replacement);
    if !changes.is_empty() && !changes.contains(ConfigurationChange::ConfigurationGeneration) {
        return Err(TransitionError::ConfigurationGenerationReused);
    }
    if changes.is_empty() && prior != replacement {
        return Err(TransitionError::UnclassifiedChange);
    }
    let disposition = disposition_for(changes).ok_or(TransitionError::UnclassifiedChange)?;
    checkpoint(TransitionCancellationStage::Classified);
    control.check()?;

    if TRANSITION_RETAINED_BYTES > limits.max_retained_bytes {
        return Err(TransitionError::MemoryLimit);
    }
    checkpoint(TransitionCancellationStage::RetainedChargeAdmitted);
    control.check()?;

    let prior_configuration_digest = digest_configuration(prior);
    let replacement_configuration_digest = digest_configuration(replacement);
    let assessment_digest = digest_assessment_fields(
        TRANSITION_VERSION,
        prior_configuration_digest,
        replacement_configuration_digest,
        changes,
        disposition,
        work_units,
        TRANSITION_RETAINED_BYTES,
    );
    checkpoint(TransitionCancellationStage::BeforeResult);
    control.check()?;

    Ok(DeploymentConfigTransitionAssessment {
        version: TRANSITION_VERSION,
        prior_configuration_digest,
        replacement_configuration_digest,
        changes,
        disposition,
        work_units,
        retained_bytes: TRANSITION_RETAINED_BYTES,
        assessment_digest,
    })
}

fn transition_work_units(
    prior: &DeploymentConfig,
    replacement: &DeploymentConfig,
) -> Result<u64, TransitionError> {
    let prior_items = u64::try_from(
        prior
            .listeners
            .len()
            .checked_add(prior.secrets.len())
            .and_then(|count| count.checked_add(prior.service_accounts.len()))
            .ok_or(TransitionError::AccountingOverflow)?,
    )
    .map_err(|_| TransitionError::AccountingOverflow)?;
    let replacement_items = u64::try_from(
        replacement
            .listeners
            .len()
            .checked_add(replacement.secrets.len())
            .and_then(|count| count.checked_add(replacement.service_accounts.len()))
            .ok_or(TransitionError::AccountingOverflow)?,
    )
    .map_err(|_| TransitionError::AccountingOverflow)?;
    debug_assert_eq!(prior_items, CONFIGURATION_ITEMS_PER_SIDE);
    debug_assert_eq!(replacement_items, CONFIGURATION_ITEMS_PER_SIDE);
    checked_work_charge(prior_items, replacement_items)
}

fn checked_work_charge(prior_items: u64, replacement_items: u64) -> Result<u64, TransitionError> {
    1_u64
        .checked_add(prior_items)
        .and_then(|value| value.checked_add(replacement_items))
        .ok_or(TransitionError::AccountingOverflow)
}

fn classify_changes(
    prior: &DeploymentConfig,
    replacement: &DeploymentConfig,
) -> ConfigurationChangeSet {
    let mut changes = ConfigurationChangeSet::EMPTY;
    if prior.artifact_set != replacement.artifact_set {
        changes.insert(ConfigurationChange::ArtifactSet);
    }
    if prior.compatibility_set != replacement.compatibility_set {
        changes.insert(ConfigurationChange::CompatibilitySet);
    }
    if prior.configuration_generation != replacement.configuration_generation {
        changes.insert(ConfigurationChange::ConfigurationGeneration);
    }
    if prior.listeners != replacement.listeners {
        changes.insert(ConfigurationChange::Listeners);
    }
    if prior.secrets != replacement.secrets {
        changes.insert(ConfigurationChange::SecretBindings);
    }
    if prior.service_accounts != replacement.service_accounts {
        changes.insert(ConfigurationChange::ServiceAccounts);
    }
    changes
}

const fn disposition_for(changes: ConfigurationChangeSet) -> Option<TransitionDisposition> {
    if !changes.has_only_known_bits() {
        None
    } else if changes.is_empty() {
        Some(TransitionDisposition::NoChangeObserved)
    } else if !changes.contains(ConfigurationChange::ConfigurationGeneration) {
        None
    } else if changes.requires_external_deployment_procedure() {
        Some(TransitionDisposition::ExternalDeploymentProcedureRequired)
    } else {
        Some(TransitionDisposition::FullRestartRequired)
    }
}

#[allow(clippy::too_many_arguments)]
fn digest_assessment_fields(
    version: u16,
    prior_configuration_digest: Commitment,
    replacement_configuration_digest: Commitment,
    changes: ConfigurationChangeSet,
    disposition: TransitionDisposition,
    work_units: u64,
    retained_bytes: u64,
) -> Commitment {
    let mut writer = domain_writer(TRANSITION_DOMAIN);
    writer.u16(version);
    writer.field(&prior_configuration_digest);
    writer.field(&replacement_configuration_digest);
    writer.u16(changes.0);
    writer.u8(disposition.code());
    writer.u64(work_units);
    writer.u64(retained_bytes);
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DurableDataPolicy, Exposure, ListenerConfig, ListenerRole, SecretBinding, SecretProvider,
        SecretPurpose, ServiceAccount, ServiceRole, PREFLIGHT_VERSION,
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

    fn assess(
        prior: &DeploymentConfig,
        replacement: &DeploymentConfig,
    ) -> Result<DeploymentConfigTransitionAssessment, TransitionError> {
        assess_deployment_config_transition(
            prior,
            replacement,
            TransitionLimits::default(),
            TransitionControl::default(),
        )
    }

    fn replacement() -> DeploymentConfig {
        let mut replacement = config();
        replacement.configuration_generation = [40; 32];
        replacement
    }

    fn reseal(report: &mut DeploymentConfigTransitionAssessment) {
        report.assessment_digest = digest_assessment_fields(
            report.version,
            report.prior_configuration_digest,
            report.replacement_configuration_digest,
            report.changes,
            report.disposition,
            report.work_units,
            report.retained_bytes,
        );
    }

    #[test]
    fn exact_no_change_is_deterministic_and_structurally_bound() {
        let first = assess(&config(), &config()).unwrap();
        let second = assess(&config(), &config()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.disposition, TransitionDisposition::NoChangeObserved);
        assert!(first.changes.is_empty());
        assert_eq!(first.work_units, TRANSITION_WORK_UNITS);
        assert_eq!(first.retained_bytes, TRANSITION_RETAINED_BYTES);
        assert_eq!(
            first.assessment_digest,
            [
                98, 177, 209, 37, 161, 116, 251, 81, 5, 44, 2, 112, 224, 77, 92, 65, 38, 213, 188,
                129, 253, 118, 113, 153, 51, 218, 138, 11, 21, 223, 152, 38,
            ]
        );
        assert!(first.has_valid_binding());
    }

    #[test]
    fn runtime_changes_require_a_full_restart_and_distinct_generation() {
        let mut generation_only = replacement();
        let assessment = assess(&config(), &generation_only).unwrap();
        assert_eq!(
            assessment.disposition,
            TransitionDisposition::FullRestartRequired
        );
        assert!(assessment
            .changes
            .contains(ConfigurationChange::ConfigurationGeneration));

        generation_only.listeners[0].port = 444;
        let assessment = assess(&config(), &generation_only).unwrap();
        assert_eq!(
            assessment.disposition,
            TransitionDisposition::FullRestartRequired
        );
        assert!(assessment.changes.contains(ConfigurationChange::Listeners));

        let mut secret = replacement();
        secret.secrets[0].provider = SecretProvider::ExternalProvider;
        secret.secrets[0].reference_commitment = [50; 32];
        let assessment = assess(&config(), &secret).unwrap();
        assert_eq!(
            assessment.disposition,
            TransitionDisposition::FullRestartRequired
        );
        assert!(assessment
            .changes
            .contains(ConfigurationChange::SecretBindings));

        let mut principal = replacement();
        principal.service_accounts[0].principal_commitment = [51; 32];
        let assessment = assess(&config(), &principal).unwrap();
        assert_eq!(
            assessment.disposition,
            TransitionDisposition::FullRestartRequired
        );
        assert!(assessment
            .changes
            .contains(ConfigurationChange::ServiceAccounts));

        let mut reused = config();
        reused.listeners[0].port = 444;
        assert_eq!(
            assess(&config(), &reused),
            Err(TransitionError::ConfigurationGenerationReused)
        );
    }

    #[test]
    fn artifact_or_compatibility_changes_require_an_external_deployment_procedure() {
        let mut artifact = replacement();
        artifact.artifact_set = [60; 32];
        let assessment = assess(&config(), &artifact).unwrap();
        assert_eq!(
            assessment.disposition,
            TransitionDisposition::ExternalDeploymentProcedureRequired
        );
        assert!(assessment
            .changes
            .contains(ConfigurationChange::ArtifactSet));

        let mut compatibility = replacement();
        compatibility.compatibility_set = [61; 32];
        compatibility.listeners[0].port = 444;
        let assessment = assess(&config(), &compatibility).unwrap();
        assert_eq!(
            assessment.disposition,
            TransitionDisposition::ExternalDeploymentProcedureRequired
        );
        assert!(assessment
            .changes
            .contains(ConfigurationChange::CompatibilitySet));
        assert!(assessment.changes.contains(ConfigurationChange::Listeners));
    }

    #[test]
    fn deployment_substitution_and_direction_changes_fail_or_bind_distinctly() {
        let mut different_deployment = replacement();
        different_deployment.deployment = [70; 32];
        assert_eq!(
            assess(&config(), &different_deployment),
            Err(TransitionError::DeploymentBindingChanged)
        );

        let forward = assess(&config(), &replacement()).unwrap();
        let reverse = assess(&replacement(), &config()).unwrap();
        assert_eq!(forward.disposition, reverse.disposition);
        assert_eq!(forward.changes, reverse.changes);
        assert_ne!(forward.assessment_digest, reverse.assessment_digest);
    }

    #[test]
    fn both_configuration_sides_are_validated_before_classification() {
        let mut prior_listeners = config();
        prior_listeners.listeners.push(prior_listeners.listeners[0]);
        let mut prior_secrets = config();
        prior_secrets.secrets.push(prior_secrets.secrets[0]);
        let mut prior_accounts = config();
        prior_accounts
            .service_accounts
            .push(prior_accounts.service_accounts[0]);
        for (prior, source) in [
            (prior_listeners, PreflightError::ListenerSet),
            (prior_secrets, PreflightError::SecretSet),
            (prior_accounts, PreflightError::ServiceAccountSet),
        ] {
            assert_eq!(
                assess(&prior, &replacement()),
                Err(TransitionError::ConfigurationInvalid {
                    side: ConfigurationSide::Prior,
                    source,
                })
            );
        }

        let mut replacement_listeners = replacement();
        replacement_listeners
            .listeners
            .push(replacement_listeners.listeners[0]);
        let mut replacement_secrets = replacement();
        replacement_secrets
            .secrets
            .push(replacement_secrets.secrets[0]);
        let mut replacement_accounts = replacement();
        replacement_accounts
            .service_accounts
            .push(replacement_accounts.service_accounts[0]);
        for (replacement, source) in [
            (replacement_listeners, PreflightError::ListenerSet),
            (replacement_secrets, PreflightError::SecretSet),
            (replacement_accounts, PreflightError::ServiceAccountSet),
        ] {
            assert_eq!(
                assess(&config(), &replacement),
                Err(TransitionError::ConfigurationInvalid {
                    side: ConfigurationSide::Replacement,
                    source,
                })
            );
        }

        let mut reordered_accounts = replacement();
        reordered_accounts.service_accounts.swap(0, 1);
        assert_eq!(
            assess(&config(), &reordered_accounts),
            Err(TransitionError::ConfigurationInvalid {
                side: ConfigurationSide::Replacement,
                source: PreflightError::ServiceAccountSet,
            })
        );

        let mut zero_generation = replacement();
        zero_generation.configuration_generation = [0; 32];
        assert_eq!(
            assess(&config(), &zero_generation),
            Err(TransitionError::ConfigurationInvalid {
                side: ConfigurationSide::Replacement,
                source: PreflightError::InvalidConfiguration,
            })
        );
    }

    #[test]
    fn error_precedence_is_stable_and_admission_first() {
        let cancellation = AtomicBool::new(true);
        assert_eq!(
            assess_deployment_config_transition(
                &config(),
                &replacement(),
                TransitionLimits {
                    max_work_units: TRANSITION_WORK_UNITS_HARD_MAXIMUM + 1,
                    ..TransitionLimits::default()
                },
                TransitionControl::with_cancellation(&cancellation),
            ),
            Err(TransitionError::InvalidLimits)
        );

        let mut bad_shape = config();
        bad_shape.listeners.clear();
        assert_eq!(
            assess_deployment_config_transition(
                &bad_shape,
                &replacement(),
                TransitionLimits::default(),
                TransitionControl::with_cancellation(&cancellation),
            ),
            Err(TransitionError::Cancelled)
        );

        let mut invalid_prior = config();
        invalid_prior.telemetry_enabled_by_default = true;
        assert_eq!(
            assess_deployment_config_transition(
                &invalid_prior,
                &replacement(),
                TransitionLimits {
                    max_work_units: TRANSITION_WORK_UNITS - 1,
                    ..TransitionLimits::default()
                },
                TransitionControl::default(),
            ),
            Err(TransitionError::WorkLimit)
        );

        let mut invalid_replacement = replacement();
        invalid_replacement.vendor_check_in_required = true;
        assert_eq!(
            assess(&invalid_prior, &invalid_replacement),
            Err(TransitionError::ConfigurationInvalid {
                side: ConfigurationSide::Prior,
                source: PreflightError::InvalidConfiguration,
            })
        );

        let mut deployment_and_generation = config();
        deployment_and_generation.deployment = [90; 32];
        deployment_and_generation.listeners[0].port = 444;
        assert_eq!(
            assess(&config(), &deployment_and_generation),
            Err(TransitionError::DeploymentBindingChanged)
        );
    }

    #[test]
    fn limits_checked_arithmetic_and_cancellation_fail_closed() {
        assert_eq!(
            assess_deployment_config_transition(
                &config(),
                &replacement(),
                TransitionLimits {
                    max_work_units: TRANSITION_WORK_UNITS - 1,
                    ..TransitionLimits::default()
                },
                TransitionControl::default(),
            ),
            Err(TransitionError::WorkLimit)
        );
        assert_eq!(
            assess_deployment_config_transition(
                &config(),
                &replacement(),
                TransitionLimits {
                    max_retained_bytes: TRANSITION_RETAINED_BYTES - 1,
                    ..TransitionLimits::default()
                },
                TransitionControl::default(),
            ),
            Err(TransitionError::MemoryLimit)
        );
        for limits in [
            TransitionLimits {
                max_work_units: TRANSITION_WORK_UNITS_HARD_MAXIMUM + 1,
                ..TransitionLimits::default()
            },
            TransitionLimits {
                max_retained_bytes: TRANSITION_RETAINED_BYTES_HARD_MAXIMUM + 1,
                ..TransitionLimits::default()
            },
            TransitionLimits {
                max_work_units: 0,
                ..TransitionLimits::default()
            },
            TransitionLimits {
                max_retained_bytes: 0,
                ..TransitionLimits::default()
            },
        ] {
            assert_eq!(
                assess_deployment_config_transition(
                    &config(),
                    &replacement(),
                    limits,
                    TransitionControl::default(),
                ),
                Err(TransitionError::InvalidLimits)
            );
        }
        assert_eq!(
            checked_work_charge(u64::MAX, 0),
            Err(TransitionError::AccountingOverflow)
        );

        let cancellation = AtomicBool::new(true);
        assert_eq!(
            assess_deployment_config_transition(
                &config(),
                &replacement(),
                TransitionLimits::default(),
                TransitionControl::with_cancellation(&cancellation),
            ),
            Err(TransitionError::Cancelled)
        );
    }

    #[test]
    fn every_cancellation_checkpoint_precedes_a_result() {
        let stages = [
            TransitionCancellationStage::Initial,
            TransitionCancellationStage::WorkAdmitted,
            TransitionCancellationStage::PriorConfigurationValidated,
            TransitionCancellationStage::ReplacementConfigurationValidated,
            TransitionCancellationStage::Classified,
            TransitionCancellationStage::RetainedChargeAdmitted,
            TransitionCancellationStage::BeforeResult,
        ];
        for target in stages {
            let cancellation = AtomicBool::new(false);
            let result = assess_deployment_config_transition_inner(
                &config(),
                &replacement(),
                TransitionLimits::default(),
                TransitionControl::with_cancellation(&cancellation),
                |stage| {
                    if stage == target {
                        cancellation.store(true, Ordering::Release);
                    }
                },
            );
            assert_eq!(result, Err(TransitionError::Cancelled), "{target:?}");
        }
    }

    #[test]
    fn report_projection_rejects_field_substitution_and_debug_is_redacted() {
        let report = assess(&config(), &replacement()).unwrap();
        assert!(report.has_valid_binding());

        macro_rules! reject_report_change {
            ($change:expr) => {{
                let mut changed = report.clone();
                $change(&mut changed);
                assert!(!changed.has_valid_binding());
            }};
        }
        reject_report_change!(
            |value: &mut DeploymentConfigTransitionAssessment| value.version += 1
        );
        reject_report_change!(|value: &mut DeploymentConfigTransitionAssessment| value
            .prior_configuration_digest =
            [80; 32]);
        reject_report_change!(|value: &mut DeploymentConfigTransitionAssessment| value
            .replacement_configuration_digest =
            [81; 32]);
        reject_report_change!(
            |value: &mut DeploymentConfigTransitionAssessment| value.changes =
                ConfigurationChangeSet::EMPTY
        );
        reject_report_change!(|value: &mut DeploymentConfigTransitionAssessment| value
            .disposition =
            TransitionDisposition::NoChangeObserved);
        reject_report_change!(|value: &mut DeploymentConfigTransitionAssessment| value
            .work_units -=
            1);
        reject_report_change!(|value: &mut DeploymentConfigTransitionAssessment| value
            .retained_bytes -=
            1);
        reject_report_change!(|value: &mut DeploymentConfigTransitionAssessment| value
            .assessment_digest =
            [82; 32]);

        let mut missing_generation = report.clone();
        missing_generation.changes = ConfigurationChangeSet(ConfigurationChange::Listeners.bit());
        reseal(&mut missing_generation);
        assert!(!missing_generation.has_valid_binding());

        let mut unknown_change = report.clone();
        unknown_change.changes = ConfigurationChangeSet(1 << 15);
        reseal(&mut unknown_change);
        assert!(!unknown_change.has_valid_binding());

        let mut false_no_change = report.clone();
        false_no_change.changes = ConfigurationChangeSet::EMPTY;
        false_no_change.disposition = TransitionDisposition::NoChangeObserved;
        reseal(&mut false_no_change);
        assert!(!false_no_change.has_valid_binding());

        let debug = format!("{report:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[98, 93"));
        assert!(!debug.contains("ConfigurationGeneration"));
    }
}
