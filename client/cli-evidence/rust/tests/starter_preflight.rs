use std::sync::atomic::AtomicBool;

use ogvcs_cli_evidence_validator::{
    compose_starter_deployment_preflight, Commitment, StarterDeploymentPreflightError,
    StarterPreflightCompositionLimits, STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES,
    STARTER_PREFLIGHT_COMPOSITION_VERSION, STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS,
    STARTER_PREFLIGHT_TOTAL_RETAINED_BYTES_HARD_MAXIMUM,
    STARTER_PREFLIGHT_TOTAL_WORK_UNITS_HARD_MAXIMUM,
};
use ogvcs_deployment_preflight::{
    BackupGateEvidence, DependencyKind, DependencyObservation, DependencyState, DeploymentConfig,
    DurableDataPolicy, Exposure, ListenerConfig, ListenerRole, MigrationClass, MigrationIntent,
    PreflightError, PreflightEvaluation, PreflightObservation, SecretBinding, SecretProvider,
    SecretPurpose, ServiceAccount, ServiceRole, OBSERVATION_AGE_SECONDS_HARD_MAXIMUM,
    PREFLIGHT_VERSION,
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

fn compose_with(
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
    limits: StarterPreflightCompositionLimits,
) -> Result<
    ogvcs_cli_evidence_validator::StarterDeploymentPreflightProjection,
    StarterDeploymentPreflightError,
> {
    compose_starter_deployment_preflight(
        config,
        observation,
        evaluation,
        limits,
        &AtomicBool::new(false),
    )
}

fn canonical() -> ogvcs_cli_evidence_validator::StarterDeploymentPreflightProjection {
    compose_with(
        &config(),
        &observation(),
        evaluation(),
        StarterPreflightCompositionLimits::fixed(),
    )
    .unwrap()
}

#[test]
fn healthy_projection_is_exact_deterministic_and_source_bound() {
    let first = canonical();
    let second = canonical();
    assert_eq!(first, second);
    assert_eq!(first.version(), STARTER_PREFLIGHT_COMPOSITION_VERSION);
    assert_eq!(first.deployment_commitment(), Commitment([1; 32]));
    assert_eq!(first.artifact_set_commitment(), Commitment([2; 32]));
    assert_eq!(first.compatibility_set_commitment(), Commitment([3; 32]));
    assert_eq!(
        first.configuration_generation_commitment(),
        Commitment([4; 32])
    );
    assert_eq!(first.observation_captured_at_unix_seconds(), 1_800_000_000);
    assert_eq!(first.evaluated_at_unix_seconds(), 1_800_000_100);
    assert_eq!(
        first.maximum_observation_age_seconds(),
        OBSERVATION_AGE_SECONDS_HARD_MAXIMUM
    );
    assert_eq!(first.predecessor_work_units(), 18);
    assert_eq!(first.predecessor_retained_bytes(), 512);
    assert_eq!(first.total_work_units(), 30);
    assert_eq!(first.peak_retained_bytes(), 1_024);
    assert_eq!(
        first.result_commitment(),
        Commitment([
            209, 36, 32, 64, 22, 29, 229, 169, 248, 65, 245, 206, 153, 227, 241, 28, 112, 184, 253,
            183, 109, 81, 180, 212, 42, 90, 238, 135, 83, 27, 7, 55,
        ])
    );
    assert_eq!(
        hex(first.projection_digest().0),
        "a906acfab0b49927f9c91ac05ed75b0dece2e87bce7c4ee71816e5963a80992d"
    );
}

#[test]
fn irreversible_backup_gate_uses_the_exact_maximum_work_boundary() {
    let report = compose_with(
        &config(),
        &irreversible_observation(),
        evaluation(),
        StarterPreflightCompositionLimits::fixed(),
    )
    .unwrap();
    assert_eq!(report.predecessor_work_units(), 19);
    assert_eq!(report.total_work_units(), 31);
    assert_eq!(report.peak_retained_bytes(), 1_024);
    assert_eq!(
        report.result_commitment(),
        Commitment([
            119, 162, 220, 241, 160, 110, 215, 196, 1, 229, 134, 62, 114, 11, 19, 166, 225, 6, 194,
            186, 75, 71, 163, 154, 182, 98, 60, 156, 206, 26, 163, 162,
        ])
    );
}

#[test]
fn all_nonhealthy_and_nonlive_results_return_no_projection() {
    for index in 0..7 {
        for state in [
            DependencyState::Degraded,
            DependencyState::Unavailable,
            DependencyState::Incompatible,
            DependencyState::Stale,
        ] {
            let mut observed = observation();
            observed.dependencies[index].state = state;
            assert_eq!(
                compose_with(
                    &config(),
                    &observed,
                    evaluation(),
                    StarterPreflightCompositionLimits::fixed(),
                ),
                Err(StarterDeploymentPreflightError::DeploymentNotReady)
            );
        }
    }

    let mut observed = observation();
    observed.process_alive = false;
    assert_eq!(
        compose_with(
            &config(),
            &observed,
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::DeploymentNotReady)
    );
}

#[test]
fn predecessor_rejections_remain_typed_and_fail_closed() {
    let mut unsafe_config = config();
    unsafe_config.listeners[0].tls = false;
    assert_eq!(
        compose_with(
            &unsafe_config,
            &observation(),
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::ListenerSet
        ))
    );

    let mut incompatible = observation();
    incompatible.compatibility_set = [99; 32];
    assert_eq!(
        compose_with(
            &config(),
            &incompatible,
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::CompatibilityMismatch
        ))
    );

    let mut stale_generation = observation();
    stale_generation.configuration_generation = [98; 32];
    assert_eq!(
        compose_with(
            &config(),
            &stale_generation,
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::ObservationSet
        ))
    );

    let stale_evaluation = PreflightEvaluation {
        evaluated_at_unix_seconds: 1_800_000_301,
        maximum_observation_age_seconds: OBSERVATION_AGE_SECONDS_HARD_MAXIMUM,
    };
    assert_eq!(
        compose_with(
            &config(),
            &observation(),
            stale_evaluation,
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::ObservationTimeInvalid
        ))
    );

    let mut missing_backup = irreversible_observation();
    missing_backup.backup_gate = None;
    assert_eq!(
        compose_with(
            &config(),
            &missing_backup,
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::BackupGateInvalid
        ))
    );
}

#[test]
fn bounds_are_exact_and_larger_or_insufficient_envelopes_fail() {
    assert_eq!(STARTER_PREFLIGHT_COMPOSITION_WORK_UNITS, 12);
    assert_eq!(STARTER_PREFLIGHT_COMPOSITION_RETAINED_BYTES, 512);
    assert_eq!(STARTER_PREFLIGHT_TOTAL_WORK_UNITS_HARD_MAXIMUM, 31);
    assert_eq!(STARTER_PREFLIGHT_TOTAL_RETAINED_BYTES_HARD_MAXIMUM, 1_152);

    let no_backup_exact = StarterPreflightCompositionLimits {
        max_work_units: 30,
        max_retained_bytes: 1_024,
    };
    let exact_projection =
        compose_with(&config(), &observation(), evaluation(), no_backup_exact).unwrap();
    assert_eq!(exact_projection.total_work_units(), 30);
    assert_eq!(exact_projection, canonical());

    let backup_exact = StarterPreflightCompositionLimits {
        max_work_units: 31,
        max_retained_bytes: 1_024,
    };
    assert_eq!(
        compose_with(
            &config(),
            &irreversible_observation(),
            evaluation(),
            backup_exact,
        )
        .unwrap()
        .total_work_units(),
        31
    );

    assert_eq!(
        compose_with(
            &config(),
            &observation(),
            evaluation(),
            StarterPreflightCompositionLimits {
                max_work_units: 29,
                max_retained_bytes: 1_024,
            },
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::WorkLimit
        ))
    );
    assert_eq!(
        compose_with(
            &config(),
            &irreversible_observation(),
            evaluation(),
            no_backup_exact,
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::WorkLimit
        ))
    );

    for limits in [
        StarterPreflightCompositionLimits {
            max_work_units: 32,
            max_retained_bytes: 1_152,
        },
        StarterPreflightCompositionLimits {
            max_work_units: 31,
            max_retained_bytes: 1_153,
        },
        StarterPreflightCompositionLimits {
            max_work_units: 31,
            max_retained_bytes: 1_023,
        },
    ] {
        assert_eq!(
            compose_with(&config(), &observation(), evaluation(), limits),
            Err(StarterDeploymentPreflightError::InvalidLimits)
        );
    }

    let mut every_reason = observation();
    every_reason.process_alive = false;
    for dependency in &mut every_reason.dependencies {
        dependency.state = DependencyState::Unavailable;
    }
    assert_eq!(
        compose_with(
            &config(),
            &every_reason,
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
        ),
        Err(StarterDeploymentPreflightError::DeploymentNotReady)
    );
    assert_eq!(
        compose_with(
            &config(),
            &every_reason,
            evaluation(),
            StarterPreflightCompositionLimits {
                max_work_units: 31,
                max_retained_bytes: 1_151,
            },
        ),
        Err(StarterDeploymentPreflightError::Preflight(
            PreflightError::MemoryLimit
        ))
    );
}

#[test]
fn every_exported_source_binding_and_time_is_digest_bound() {
    let baseline = canonical();

    let mut changed_config = config();
    changed_config.deployment = [91; 32];
    assert_changed(&baseline, &changed_config, &observation(), evaluation());

    changed_config = config();
    changed_config.artifact_set = [92; 32];
    assert_changed(&baseline, &changed_config, &observation(), evaluation());

    changed_config = config();
    changed_config.compatibility_set = [93; 32];
    let mut changed_observation = observation();
    changed_observation.compatibility_set = [93; 32];
    assert_changed(
        &baseline,
        &changed_config,
        &changed_observation,
        evaluation(),
    );

    changed_config = config();
    changed_config.configuration_generation = [94; 32];
    changed_observation = observation();
    changed_observation.configuration_generation = [94; 32];
    assert_changed(
        &baseline,
        &changed_config,
        &changed_observation,
        evaluation(),
    );

    changed_observation = observation();
    changed_observation.dependencies[0].generation_commitment = [95; 32];
    assert_changed(&baseline, &config(), &changed_observation, evaluation());

    changed_observation = observation();
    changed_observation.captured_at_unix_seconds += 1;
    assert_changed(&baseline, &config(), &changed_observation, evaluation());

    let mut changed_evaluation = evaluation();
    changed_evaluation.evaluated_at_unix_seconds += 1;
    assert_changed(&baseline, &config(), &observation(), changed_evaluation);

    changed_evaluation = evaluation();
    changed_evaluation.maximum_observation_age_seconds -= 1;
    assert_changed(&baseline, &config(), &observation(), changed_evaluation);
}

fn assert_changed(
    baseline: &ogvcs_cli_evidence_validator::StarterDeploymentPreflightProjection,
    config: &DeploymentConfig,
    observation: &PreflightObservation,
    evaluation: PreflightEvaluation,
) {
    let changed = compose_with(
        config,
        observation,
        evaluation,
        StarterPreflightCompositionLimits::fixed(),
    )
    .unwrap();
    assert_ne!(changed.request_commitment(), baseline.request_commitment());
    assert_ne!(changed.result_commitment(), baseline.result_commitment());
    assert_ne!(changed.projection_digest(), baseline.projection_digest());
}

#[test]
fn cancellation_and_debug_output_release_no_projection_bindings() {
    let cancellation = AtomicBool::new(true);
    assert_eq!(
        compose_starter_deployment_preflight(
            &config(),
            &observation(),
            evaluation(),
            StarterPreflightCompositionLimits::fixed(),
            &cancellation,
        ),
        Err(StarterDeploymentPreflightError::Cancelled)
    );

    let debug = format!("{:?}", canonical());
    assert!(debug.contains("bindings: \"<redacted>\""));
    for raw in ["[1, 1, 1", "[2, 2, 2", "[3, 3, 3", "[4, 4, 4"] {
        assert!(!debug.contains(raw));
    }
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
