mod support;

use std::{marker::PhantomData, sync::Arc};

use ogvcs_object_model::ObjectKind;
use ogvcs_path_contract::{path_collision_keys_with_options, CaseMode, PathProfile};
use ogvcs_selective_sync_kernel::{
    BlockerKind, CacheProbeOutcome, CacheProbeRecord, CandidateActionKind,
    CandidateMaterializationState, DryRunAction, DryRunActionSink, DryRunBindings, DryRunError,
    DryRunPlanner, DryRunRequiredObject, DryRunSummary, DryRunTargetRecord, EvaluationControl,
    HostPlatform, IteratorPlanSource, LocalObservation, Materialization, PlanSource,
    RetainedWorkspaceRecord, DRY_RUN_LEDGER_BYTES_MAXIMUM, LOGICAL_BYTES_MAXIMUM,
    METADATA_RECORDS_MAXIMUM, REQUIRED_OBJECTS_MAXIMUM,
};

use support::{
    bindings, closure, current_full, current_metadata, current_untracked, full_identity, object,
    order_currents, run, target_full, target_state,
};

struct CancellingTargetSource {
    record: Option<DryRunTargetRecord>,
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl PlanSource<DryRunTargetRecord> for CancellingTargetSource {
    type Error = ();

    fn next_record(&mut self) -> Result<Option<DryRunTargetRecord>, Self::Error> {
        self.flag.store(true, std::sync::atomic::Ordering::Release);
        Ok(self.record.take())
    }
}

struct AlwaysFail<T>(PhantomData<T>);

impl<T> PlanSource<T> for AlwaysFail<T> {
    type Error = ();

    fn next_record(&mut self) -> Result<Option<T>, Self::Error> {
        Err(())
    }
}

struct FailingSink {
    calls: usize,
    fail_at: usize,
}

#[derive(Default)]
struct FinishFailingSink {
    calls: usize,
}

impl DryRunActionSink for FinishFailingSink {
    type Error = ();

    fn emit(&mut self, _action: &DryRunAction) -> Result<(), Self::Error> {
        self.calls += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        Err(())
    }
}

struct CancellingFinishSink {
    calls: usize,
    flag: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Default)]
struct FinishTrackingSink {
    calls: u64,
    finished: bool,
}

impl DryRunActionSink for CancellingFinishSink {
    type Error = ();

    fn emit(&mut self, _action: &DryRunAction) -> Result<(), Self::Error> {
        self.calls += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        self.flag.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}

impl DryRunActionSink for FailingSink {
    type Error = ();

    fn emit(&mut self, _action: &DryRunAction) -> Result<(), Self::Error> {
        if self.calls == self.fail_at {
            return Err(());
        }
        self.calls += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl DryRunActionSink for FinishTrackingSink {
    type Error = ();

    fn emit(&mut self, _action: &DryRunAction) -> Result<(), Self::Error> {
        self.calls += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        self.finished = true;
        Ok(())
    }
}

#[test]
fn cancellation_and_source_failure_return_no_actions_or_summary() {
    let identity = full_identity(1, 10, 10);
    let target = target_full(0, "Cancel/Hero.bin", identity);
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::Miss)]);
    let planner = DryRunPlanner::new(bindings(1, 0, 1).unwrap());
    let control = EvaluationControl::default();
    let mut target_source = CancellingTargetSource {
        record: Some(target),
        flag: control.cancellation_flag(),
    };
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut actions = Vec::new();
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut actions,
            &control,
        ),
        Err(DryRunError::Cancelled)
    );
    assert!(actions.is_empty());

    let planner = DryRunPlanner::new(bindings(0, 1, 0).unwrap());
    let mut target_source = IteratorPlanSource::new(Vec::<DryRunTargetRecord>::new().into_iter());
    let mut current_source = AlwaysFail::<RetainedWorkspaceRecord>(PhantomData);
    let mut object_source = IteratorPlanSource::new(Vec::<DryRunRequiredObject>::new().into_iter());
    let mut cache_source = IteratorPlanSource::new(Vec::<CacheProbeRecord>::new().into_iter());
    let mut actions = Vec::new();
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut actions,
            &EvaluationControl::default(),
        ),
        Err(DryRunError::SourceFailed)
    );
    assert!(actions.is_empty());
}

#[test]
fn sink_failure_makes_prior_candidate_actions_discard_only() {
    let identity = full_identity(2, 11, 11);
    let targets = vec![
        target_state(0, "Sink/Metadata", Materialization::MetadataOnly),
        target_full(1, "Sink/Payload.bin", identity),
    ];
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::VerifiedHit)]);
    let planner = DryRunPlanner::new(bindings(2, 0, 1).unwrap());
    let mut target_source = IteratorPlanSource::new(targets.into_iter());
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut sink = FailingSink {
        calls: 0,
        fail_at: 1,
    };
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut sink,
            &EvaluationControl::default(),
        ),
        Err(DryRunError::SinkFailed)
    );
    assert_eq!(sink.calls, 1);
}

#[test]
fn sink_finish_failure_and_finish_time_cancellation_return_no_summary() {
    let targets = vec![target_state(
        0,
        "Sink/Finish.meta",
        Materialization::MetadataOnly,
    )];
    let planner = DryRunPlanner::new(bindings(1, 0, 0).unwrap());
    let mut target_source = IteratorPlanSource::new(targets.clone().into_iter());
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(Vec::<DryRunRequiredObject>::new().into_iter());
    let mut cache_source = IteratorPlanSource::new(Vec::<CacheProbeRecord>::new().into_iter());
    let mut failing_sink = FinishFailingSink::default();
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut failing_sink,
            &EvaluationControl::default(),
        ),
        Err(DryRunError::SinkFailed)
    );
    assert_eq!(failing_sink.calls, 1);

    let control = EvaluationControl::default();
    let mut target_source = IteratorPlanSource::new(targets.into_iter());
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(Vec::<DryRunRequiredObject>::new().into_iter());
    let mut cache_source = IteratorPlanSource::new(Vec::<CacheProbeRecord>::new().into_iter());
    let mut cancelling_sink = CancellingFinishSink {
        calls: 0,
        flag: control.cancellation_flag(),
    };
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut cancelling_sink,
            &control,
        ),
        Err(DryRunError::Cancelled)
    );
    assert_eq!(cancelling_sink.calls, 1);
}

fn run_windows_case(
    current: RetainedWorkspaceRecord,
) -> Result<(DryRunSummary, Vec<DryRunAction>), DryRunError> {
    let identity = full_identity(80, 120, 256);
    let targets = vec![target_full(0, "Case/Foo.bin", identity)];
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::Miss)]);
    let planner = DryRunPlanner::new(DryRunBindings::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        "path.opengamevcs/windows@1",
        CaseMode::Sensitive,
        HostPlatform::Windows,
        1,
        1,
        1,
        1,
    )?);
    let mut target_source = IteratorPlanSource::new(targets.into_iter());
    let mut current_source = IteratorPlanSource::new(vec![current].into_iter());
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

fn run_windows_state_case(
    target: DryRunTargetRecord,
    current: RetainedWorkspaceRecord,
) -> Result<(DryRunSummary, Vec<DryRunAction>), DryRunError> {
    let planner = DryRunPlanner::new(DryRunBindings::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        "path.opengamevcs/windows@1",
        CaseMode::Sensitive,
        HostPlatform::Windows,
        1,
        1,
        0,
        0,
    )?);
    let mut target_source = IteratorPlanSource::new(vec![target].into_iter());
    let mut current_source = IteratorPlanSource::new(vec![current].into_iter());
    let mut object_source = IteratorPlanSource::new(Vec::<DryRunRequiredObject>::new().into_iter());
    let mut cache_source = IteratorPlanSource::new(Vec::<CacheProbeRecord>::new().into_iter());
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

#[test]
fn hostile_order_identity_cache_and_manifest_claims_fail_closed() {
    let identity = full_identity(3, 12, 12);
    let unsorted = vec![
        target_full(0, "Z/Last.bin", identity),
        target_state(1, "A/First.bin", Materialization::AbsentBySpec),
    ];
    assert_eq!(
        run(unsorted, vec![], vec![], vec![]),
        Err(DryRunError::PathOrderInvalid)
    );

    let metadata_with_identity = DryRunTargetRecord {
        ordinal: 0,
        path: "Bad/Metadata.bin".to_owned(),
        materialization: Materialization::MetadataOnly,
        identity: Some(identity),
    };
    assert_eq!(
        run(vec![metadata_with_identity], vec![], vec![], vec![]),
        Err(DryRunError::MetadataStateInvalid)
    );

    let target = vec![target_full(0, "Bad/Cache.bin", identity)];
    let required = vec![DryRunRequiredObject {
        ordinal: 0,
        object: identity.manifest,
        payload_bytes: 64,
    }];
    let probes = vec![CacheProbeRecord {
        ordinal: 0,
        object: identity.manifest,
        payload_bytes: 63,
        outcome: CacheProbeOutcome::VerifiedHit,
    }];
    assert_eq!(
        run(target.clone(), vec![], required, probes),
        Err(DryRunError::CacheProbeMismatch)
    );
    assert_eq!(
        run(target, vec![], vec![], vec![]),
        Err(DryRunError::RequiredManifestMissing)
    );

    let wrong_kind = object(ObjectKind::Snapshot, 1);
    let required = vec![DryRunRequiredObject {
        ordinal: 0,
        object: wrong_kind,
        payload_bytes: 1,
    }];
    let probes = vec![CacheProbeRecord {
        ordinal: 0,
        object: wrong_kind,
        payload_bytes: 1,
        outcome: CacheProbeOutcome::Miss,
    }];
    let planner = DryRunPlanner::new(bindings(0, 0, 1).unwrap());
    let mut target_source = IteratorPlanSource::new(Vec::<DryRunTargetRecord>::new().into_iter());
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut actions = Vec::new();
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut actions,
            &EvaluationControl::default(),
        ),
        Err(DryRunError::ObjectInvalid)
    );
    assert!(actions.is_empty());
}

#[test]
fn untracked_ancestor_is_an_explicit_blocker_never_an_implicit_overwrite() {
    let identity = full_identity(4, 13, 13);
    let targets = vec![target_full(0, "Tree/Hero.bin", identity)];
    let currents = vec![current_untracked(0, "Tree")];
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::Miss)]);
    let (summary, actions) = run(targets, currents, required, probes).unwrap();
    assert_eq!(summary.conflicts, 1);
    assert_eq!(actions[0].kind, CandidateActionKind::Conflict);
    assert_eq!(actions[0].blocker_path.as_deref(), Some("Tree"));
    assert!(!actions[0].may_write_ordinary_file());
}

#[test]
fn later_untracked_descendant_is_not_masked_by_an_earlier_tracked_descendant() {
    let identity = full_identity(41, 14, 140);
    let targets = vec![target_full(0, "Tree", identity)];
    let currents = order_currents(vec![
        current_full(
            0,
            "Tree/a.bin",
            full_identity(42, 15, 15),
            LocalObservation::Pristine,
        ),
        current_untracked(1, "Tree/z.bin"),
    ]);
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::Miss)]);
    let (summary, actions) = run(targets, currents, required, probes).unwrap();
    let target_action = actions
        .iter()
        .find(|action| action.path == "Tree")
        .expect("target action");
    assert_eq!(summary.conflicts, 1);
    assert_eq!(target_action.kind, CandidateActionKind::Conflict);
    assert_eq!(
        target_action.blocker,
        Some(BlockerKind::UntrackedObstruction)
    );
    assert_eq!(target_action.blocker_path.as_deref(), Some("Tree/z.bin"));
}

#[test]
fn platform_alias_descendant_index_skips_unrelated_tracked_rows() {
    let identity = full_identity(43, 16, 160);
    let targets = vec![target_full(0, "Tree", identity)];
    let currents = vec![
        current_full(
            0,
            "tree/a.bin",
            full_identity(44, 17, 17),
            LocalObservation::Pristine,
        ),
        current_untracked(1, "tree/z.bin"),
    ];
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::Miss)]);
    let planner = DryRunPlanner::new(
        DryRunBindings::new(
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            "path.opengamevcs/windows@1",
            CaseMode::Sensitive,
            HostPlatform::Windows,
            1,
            2,
            1,
            1,
        )
        .unwrap(),
    );
    let mut target_source = IteratorPlanSource::new(targets.into_iter());
    let mut current_source = IteratorPlanSource::new(currents.into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut actions = Vec::new();
    let summary = planner
        .plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut actions,
            &EvaluationControl::default(),
        )
        .unwrap();
    let target_action = actions
        .iter()
        .find(|action| action.path == "Tree")
        .expect("target action");
    assert_eq!(summary.conflicts, 1);
    assert_eq!(target_action.kind, CandidateActionKind::Conflict);
    assert_eq!(target_action.blocker_path.as_deref(), Some("tree/z.bin"));
}

#[test]
fn cross_projection_platform_aliases_fail_closed_but_same_file_id_moves() {
    let cases = [
        (
            current_untracked(0, "Case/foo.bin"),
            BlockerKind::UntrackedObstruction,
        ),
        (
            current_full(
                0,
                "Case/foo.bin",
                full_identity(81, 121, 128),
                LocalObservation::Modified,
            ),
            BlockerKind::LocallyModified,
        ),
        (
            current_full(
                0,
                "Case/foo.bin",
                full_identity(82, 122, 128),
                LocalObservation::Obstructed,
            ),
            BlockerKind::LocalObstruction,
        ),
    ];
    for (current, expected_blocker) in cases {
        let (summary, actions) = run_windows_case(current).unwrap();
        assert_eq!(summary.conflicts, 1);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].kind, CandidateActionKind::Conflict);
        assert_eq!(actions[0].blocker, Some(expected_blocker));
        assert_eq!(actions[0].blocker_path.as_deref(), Some("Case/foo.bin"));
        assert_eq!(actions[0].source_path.as_deref(), Some("Case/foo.bin"));
    }

    let (summary, actions) = run_windows_case(current_full(
        0,
        "Case/foo.bin",
        full_identity(83, 123, 128),
        LocalObservation::Pristine,
    ))
    .unwrap();
    assert_eq!(summary.updates, 1);
    assert_eq!(summary.deletes, 0);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, CandidateActionKind::Update);
    assert_eq!(actions[0].source_path.as_deref(), Some("Case/foo.bin"));

    let target_identity = full_identity(80, 120, 256);
    let (summary, actions) = run_windows_case(current_full(
        0,
        "Case/foo.bin",
        target_identity,
        LocalObservation::Pristine,
    ))
    .unwrap();
    assert_eq!(summary.conflicts, 0);
    assert_eq!(summary.moves_or_equivalents, 1);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, CandidateActionKind::MoveOrEquivalent);
    assert_eq!(actions[0].source_path.as_deref(), Some("Case/foo.bin"));
    assert_eq!(actions[0].workspace_write_bytes, 0);
    assert!(!actions[0].may_write_ordinary_file());
}

#[test]
fn platform_alias_and_file_id_source_have_one_action_owner_in_target_order() {
    let run_case = |move_path: &str| {
        let source_identity = full_identity(90, 130, 100);
        let mut alias_replacement = full_identity(91, 131, 100);
        alias_replacement.manifest = source_identity.manifest;
        alias_replacement.content = source_identity.content;
        let mut targets = vec![
            target_full(0, "Case/Foo.bin", alias_replacement),
            target_full(0, move_path, source_identity),
        ];
        let profile = PathProfile::parse("path.opengamevcs/windows@1").unwrap();
        targets.sort_by_key(|record| {
            path_collision_keys_with_options(&record.path, profile, CaseMode::Sensitive)
                .unwrap()
                .repository_key()
                .as_str()
                .to_owned()
        });
        for (ordinal, record) in targets.iter_mut().enumerate() {
            record.ordinal = ordinal as u64;
        }
        let currents = vec![current_full(
            0,
            "Case/foo.bin",
            source_identity,
            LocalObservation::Pristine,
        )];
        let (required, probes) =
            closure(&[(source_identity.manifest, 64, CacheProbeOutcome::VerifiedHit)]);
        let planner = DryRunPlanner::new(
            DryRunBindings::new(
                [0x11; 32],
                [0x22; 32],
                [0x33; 32],
                "path.opengamevcs/windows@1",
                CaseMode::Sensitive,
                HostPlatform::Windows,
                2,
                1,
                1,
                1,
            )
            .unwrap(),
        );
        let mut target_source = IteratorPlanSource::new(targets.into_iter());
        let mut current_source = IteratorPlanSource::new(currents.into_iter());
        let mut object_source = IteratorPlanSource::new(required.into_iter());
        let mut cache_source = IteratorPlanSource::new(probes.into_iter());
        let mut actions = Vec::new();
        let summary = planner
            .plan(
                &mut target_source,
                &mut current_source,
                &mut object_source,
                &mut cache_source,
                &mut actions,
                &EvaluationControl::default(),
            )
            .unwrap();
        (summary, actions)
    };

    for (move_path, first_path, reused_path, staged_path, reused_kind) in [
        (
            "Move/Elsewhere.bin",
            "Case/Foo.bin",
            "Case/Foo.bin",
            "Move/Elsewhere.bin",
            CandidateActionKind::Update,
        ),
        (
            "A/Elsewhere.bin",
            "A/Elsewhere.bin",
            "A/Elsewhere.bin",
            "Case/Foo.bin",
            CandidateActionKind::MoveOrEquivalent,
        ),
    ] {
        let (summary, actions) = run_case(move_path);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].path, first_path);
        assert_eq!(summary.ledgers.current_tracked_baseline_bytes, 100);
        assert_eq!(summary.ledgers.target_full_logical_bytes, 200);
        assert_eq!(summary.ledgers.reusable_workspace_bytes, 100);
        assert_eq!(summary.ledgers.workspace_stage_bytes, 100);
        assert_eq!(summary.ledgers.retired_tracked_baseline_bytes, 0);
        let reused = actions
            .iter()
            .find(|action| action.path == reused_path)
            .unwrap();
        let staged = actions
            .iter()
            .find(|action| action.path == staged_path)
            .unwrap();
        assert_eq!(reused.kind, reused_kind);
        assert_eq!(reused.workspace_write_bytes, 0);
        assert_eq!(reused.source_path.as_deref(), Some("Case/foo.bin"));
        assert_eq!(staged.kind, CandidateActionKind::Add);
        assert_eq!(staged.from, CandidateMaterializationState::Absent);
        assert_eq!(staged.workspace_write_bytes, 100);
        assert!(staged.source_path.is_none());
        assert_eq!(
            actions
                .iter()
                .filter(|action| action.source_path.as_deref() == Some("Case/foo.bin"))
                .count(),
            1,
            "a current row has exactly one emitted action owner"
        );
    }
}

#[test]
fn platform_alias_state_transitions_are_consumed_once_and_absence_stays_residual() {
    let (summary, actions) = run_windows_state_case(
        target_state(0, "Case/Foo.bin", Materialization::MetadataOnly),
        current_metadata(0, "Case/foo.bin", false),
    )
    .unwrap();
    assert_eq!(summary.materialization_state_changes, 1);
    assert_eq!(summary.deletes, 0);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, CandidateActionKind::MaterializationState);
    assert_eq!(actions[0].from, CandidateMaterializationState::MetadataOnly);
    assert_eq!(actions[0].to, CandidateMaterializationState::MetadataOnly);
    assert_eq!(actions[0].source_path.as_deref(), Some("Case/foo.bin"));
    assert!(!actions[0].may_write_ordinary_file());
    assert!(!actions[0].may_delete_ordinary_file());

    let (summary, actions) = run_windows_state_case(
        target_state(0, "Case/Foo.bin", Materialization::AbsentBySpec),
        current_full(
            0,
            "Case/foo.bin",
            full_identity(84, 124, 128),
            LocalObservation::Pristine,
        ),
    )
    .unwrap();
    assert_eq!(summary.deletes, 1);
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, CandidateActionKind::Delete);
    assert_eq!(actions[0].path, "Case/foo.bin");
    assert!(actions[0].source_path.is_none());
}

#[test]
fn obstruction_indexes_are_included_in_retained_memory_accounting() {
    let path = "Memory/Obstruction.bin";
    let (plain, _) = run(
        vec![],
        vec![current_metadata(0, path, false)],
        vec![],
        vec![],
    )
    .unwrap();
    let (obstructed, _) = run(vec![], vec![current_untracked(0, path)], vec![], vec![]).unwrap();
    let profile = PathProfile::parse("path.opengamevcs/linux@1").unwrap();
    let keys = path_collision_keys_with_options(path, profile, CaseMode::Sensitive).unwrap();
    let indexed_key_bytes =
        (keys.repository_key().as_str().len() + keys.platform_key().len()) as u64;
    assert!(
        obstructed.retained_bytes_peak >= plain.retained_bytes_peak + indexed_key_bytes,
        "obstruction indexes must be admitted to the planner budget"
    );
}

#[test]
fn metadata_obstruction_to_absent_is_index_only_and_preserves_the_ordinary_path() {
    let target = vec![target_state(
        0,
        "Metadata/Preserved.bin",
        Materialization::AbsentBySpec,
    )];
    let current = vec![current_metadata(0, "Metadata/Preserved.bin", true)];
    let (summary, actions) = run(target, current, vec![], vec![]).unwrap();
    assert_eq!(summary.materialization_state_changes, 1);
    assert_eq!(actions[0].kind, CandidateActionKind::MaterializationState);
    assert_eq!(
        actions[0].from,
        CandidateMaterializationState::MetadataOnlyObstructed
    );
    assert!(!actions[0].may_write_ordinary_file());
    assert!(!actions[0].may_delete_ordinary_file());
}

#[test]
fn move_destination_retirement_is_counted_and_any_local_obstruction_blocks() {
    let target_identity = full_identity(20, 30, 100);
    let destination_identity = full_identity(21, 31, 200);
    let target = vec![target_full(0, "Move/B.bin", target_identity)];
    let pristine = order_currents(vec![
        current_full(0, "Move/A.bin", target_identity, LocalObservation::Pristine),
        current_full(
            1,
            "Move/B.bin",
            destination_identity,
            LocalObservation::Pristine,
        ),
    ]);
    let (required, probes) =
        closure(&[(target_identity.manifest, 64, CacheProbeOutcome::VerifiedHit)]);
    let (summary, actions) =
        run(target.clone(), pristine, required.clone(), probes.clone()).unwrap();
    assert_eq!(actions[0].kind, CandidateActionKind::MoveOrEquivalent);
    assert_eq!(summary.ledgers.current_tracked_baseline_bytes, 300);
    assert_eq!(summary.ledgers.reusable_workspace_bytes, 100);
    assert_eq!(summary.ledgers.retired_tracked_baseline_bytes, 200);

    let modified_destination = order_currents(vec![
        current_full(0, "Move/A.bin", target_identity, LocalObservation::Pristine),
        current_full(
            1,
            "Move/B.bin",
            destination_identity,
            LocalObservation::Modified,
        ),
    ]);
    let (_, actions) = run(
        target.clone(),
        modified_destination,
        required.clone(),
        probes.clone(),
    )
    .unwrap();
    assert_eq!(actions[0].kind, CandidateActionKind::Conflict);
    assert_eq!(actions[0].blocker_path.as_deref(), Some("Move/B.bin"));

    let untracked_destination = order_currents(vec![
        current_full(0, "Move/A.bin", target_identity, LocalObservation::Pristine),
        current_untracked(1, "Move/B.bin"),
    ]);
    let (_, actions) = run(target, untracked_destination, required, probes).unwrap();
    assert_eq!(actions[0].kind, CandidateActionKind::Conflict);
    assert_eq!(actions[0].blocker_path.as_deref(), Some("Move/B.bin"));
}

#[test]
fn exact_numeric_ceilings_reject_plus_one_and_aggregate_overflow() {
    assert_eq!(
        DryRunBindings::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "path.opengamevcs/linux@1",
            CaseMode::Sensitive,
            HostPlatform::Linux,
            METADATA_RECORDS_MAXIMUM + 1,
            0,
            0,
            0,
        )
        .unwrap_err(),
        DryRunError::TargetCountLimit
    );
    assert_eq!(
        DryRunBindings::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "path.opengamevcs/linux@1",
            CaseMode::Sensitive,
            HostPlatform::Linux,
            0,
            0,
            REQUIRED_OBJECTS_MAXIMUM + 1,
            REQUIRED_OBJECTS_MAXIMUM + 1,
        )
        .unwrap_err(),
        DryRunError::RequiredObjectCountLimit
    );

    let logical = ogvcs_selective_sync_kernel::LOGICAL_BYTES_MAXIMUM;
    let count = DRY_RUN_LEDGER_BYTES_MAXIMUM / logical + 1;
    let targets = (0..count).map(|ordinal| {
        target_full(
            ordinal,
            &format!("Overflow/{ordinal:05}.bin"),
            full_identity(ordinal, 14, logical),
        )
    });
    let planner = DryRunPlanner::new(bindings(count as usize, 0, 0).unwrap());
    let mut target_source = IteratorPlanSource::new(targets);
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(Vec::<DryRunRequiredObject>::new().into_iter());
    let mut cache_source = IteratorPlanSource::new(Vec::<CacheProbeRecord>::new().into_iter());
    let mut actions = Vec::new();
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut actions,
            &EvaluationControl::default(),
        ),
        Err(DryRunError::LedgerLimit)
    );
    assert!(actions.is_empty());
}

#[test]
fn final_ledger_failure_happens_before_sink_finish() {
    let full_rows = DRY_RUN_LEDGER_BYTES_MAXIMUM / LOGICAL_BYTES_MAXIMUM;
    let remainder = DRY_RUN_LEDGER_BYTES_MAXIMUM % LOGICAL_BYTES_MAXIMUM;
    let target_count = full_rows + u64::from(remainder > 0);
    let targets = (0..target_count).map(|ordinal| {
        target_full(
            ordinal,
            &format!("Ledger/{ordinal:05}.bin"),
            full_identity(
                ordinal,
                150,
                if ordinal < full_rows {
                    LOGICAL_BYTES_MAXIMUM
                } else {
                    remainder
                },
            ),
        )
    });
    let manifest = full_identity(0, 150, LOGICAL_BYTES_MAXIMUM).manifest;
    let required = vec![DryRunRequiredObject {
        ordinal: 0,
        object: manifest,
        payload_bytes: 1,
    }];
    let probes = vec![CacheProbeRecord {
        ordinal: 0,
        object: manifest,
        payload_bytes: 1,
        outcome: CacheProbeOutcome::Miss,
    }];
    let planner = DryRunPlanner::new(bindings(target_count as usize, 0, 1).unwrap());
    let mut target_source = IteratorPlanSource::new(targets);
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut sink = FinishTrackingSink::default();
    assert_eq!(
        planner.plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut sink,
            &EvaluationControl::default(),
        ),
        Err(DryRunError::LedgerLimit)
    );
    assert_eq!(sink.calls, target_count);
    assert!(!sink.finished, "invalid ledgers must not finalize the sink");
}

#[test]
fn modified_residual_delete_is_a_conflict() {
    let current = vec![current_full(
        0,
        "Delete/Modified.bin",
        full_identity(5, 15, 15),
        LocalObservation::Modified,
    )];
    let (summary, actions) = run(vec![], current, vec![], vec![]).unwrap();
    assert_eq!(summary.conflicts, 1);
    assert_eq!(actions[0].kind, CandidateActionKind::Conflict);
}
