#![allow(dead_code)]

use ogvcs_object_model::{FileId, ObjectKind, ObjectRef};
use ogvcs_path_contract::{path_collision_keys_with_options, CaseMode, PathProfile};
use ogvcs_selective_sync_kernel::{
    CacheProbeOutcome, CacheProbeRecord, ContentIdentity, DryRunAction, DryRunBindings,
    DryRunError, DryRunFullIdentity, DryRunPlanner, DryRunRequiredObject, DryRunSummary,
    DryRunTargetRecord, EvaluationControl, HostPlatform, IteratorPlanSource, LocalObservation,
    Materialization, RetainedCurrentState, RetainedWorkspaceRecord,
};

pub fn file_id(value: u64) -> FileId {
    let mut bytes = [0u8; 16];
    bytes[8..].copy_from_slice(&(value + 1).to_be_bytes());
    FileId::new(bytes).unwrap()
}

pub const fn object(kind: ObjectKind, byte: u8) -> ObjectRef {
    ObjectRef {
        kind,
        digest: [byte; 32],
    }
}

pub fn full_identity(file: u64, byte: u8, logical_bytes: u64) -> DryRunFullIdentity {
    DryRunFullIdentity {
        file_id: file_id(file),
        entry_digest: [byte.wrapping_add(1); 32],
        manifest: object(ObjectKind::ContentManifest, byte),
        content: ContentIdentity {
            digest: [byte.wrapping_add(2); 32],
            logical_bytes,
        },
    }
}

pub fn target_full(ordinal: u64, path: &str, identity: DryRunFullIdentity) -> DryRunTargetRecord {
    DryRunTargetRecord {
        ordinal,
        path: path.to_owned(),
        materialization: Materialization::Full,
        identity: Some(identity),
    }
}

pub fn target_state(
    ordinal: u64,
    path: &str,
    materialization: Materialization,
) -> DryRunTargetRecord {
    assert_ne!(materialization, Materialization::Full);
    DryRunTargetRecord {
        ordinal,
        path: path.to_owned(),
        materialization,
        identity: None,
    }
}

pub fn current_full(
    ordinal: u64,
    path: &str,
    identity: DryRunFullIdentity,
    observation: LocalObservation,
) -> RetainedWorkspaceRecord {
    RetainedWorkspaceRecord {
        ordinal,
        path: path.to_owned(),
        state: RetainedCurrentState::Full {
            identity,
            observation,
        },
    }
}

pub fn current_metadata(
    ordinal: u64,
    path: &str,
    ordinary_path_obstruction: bool,
) -> RetainedWorkspaceRecord {
    RetainedWorkspaceRecord {
        ordinal,
        path: path.to_owned(),
        state: RetainedCurrentState::MetadataOnly {
            ordinary_path_obstruction,
        },
    }
}

pub fn current_untracked(ordinal: u64, path: &str) -> RetainedWorkspaceRecord {
    RetainedWorkspaceRecord {
        ordinal,
        path: path.to_owned(),
        state: RetainedCurrentState::Untracked,
    }
}

pub fn closure(
    values: &[(ObjectRef, u64, CacheProbeOutcome)],
) -> (Vec<DryRunRequiredObject>, Vec<CacheProbeRecord>) {
    let mut values = values.to_vec();
    values.sort_by_key(|(object, _, _)| *object);
    let required = values
        .iter()
        .enumerate()
        .map(
            |(ordinal, (object, payload_bytes, _))| DryRunRequiredObject {
                ordinal: ordinal as u64,
                object: *object,
                payload_bytes: *payload_bytes,
            },
        )
        .collect();
    let probes = values
        .iter()
        .enumerate()
        .map(
            |(ordinal, (object, payload_bytes, outcome))| CacheProbeRecord {
                ordinal: ordinal as u64,
                object: *object,
                payload_bytes: *payload_bytes,
                outcome: *outcome,
            },
        )
        .collect();
    (required, probes)
}

pub fn bindings(
    targets: usize,
    currents: usize,
    objects: usize,
) -> Result<DryRunBindings, DryRunError> {
    DryRunBindings::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        "path.opengamevcs/linux@1",
        CaseMode::Sensitive,
        HostPlatform::Linux,
        targets as u64,
        currents as u64,
        objects as u64,
        objects as u64,
    )
}

pub fn order_targets(mut records: Vec<DryRunTargetRecord>) -> Vec<DryRunTargetRecord> {
    let profile = PathProfile::parse("path.opengamevcs/linux@1").unwrap();
    records.sort_by_key(|record| {
        path_collision_keys_with_options(&record.path, profile, CaseMode::Sensitive)
            .unwrap()
            .repository_key()
            .as_str()
            .to_owned()
    });
    for (ordinal, record) in records.iter_mut().enumerate() {
        record.ordinal = ordinal as u64;
    }
    records
}

pub fn order_currents(mut records: Vec<RetainedWorkspaceRecord>) -> Vec<RetainedWorkspaceRecord> {
    let profile = PathProfile::parse("path.opengamevcs/linux@1").unwrap();
    records.sort_by_key(|record| {
        path_collision_keys_with_options(&record.path, profile, CaseMode::Sensitive)
            .unwrap()
            .repository_key()
            .as_str()
            .to_owned()
    });
    for (ordinal, record) in records.iter_mut().enumerate() {
        record.ordinal = ordinal as u64;
    }
    records
}

pub fn run(
    targets: Vec<DryRunTargetRecord>,
    currents: Vec<RetainedWorkspaceRecord>,
    required: Vec<DryRunRequiredObject>,
    probes: Vec<CacheProbeRecord>,
) -> Result<(DryRunSummary, Vec<DryRunAction>), DryRunError> {
    let planner = DryRunPlanner::new(bindings(targets.len(), currents.len(), required.len())?);
    let mut target_source = IteratorPlanSource::new(targets.into_iter());
    let mut current_source = IteratorPlanSource::new(currents.into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut actions = Vec::new();
    let summary = planner.plan(
        &mut target_source,
        &mut current_source,
        &mut object_source,
        &mut cache_source,
        &mut actions,
        &EvaluationControl::default(),
    )?;
    Ok((summary, actions))
}
