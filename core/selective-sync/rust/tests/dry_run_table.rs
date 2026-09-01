mod support;

use ogvcs_object_model::{ObjectKind, ObjectRef};
use ogvcs_selective_sync_kernel::{
    CacheProbeOutcome, CandidateActionKind, Materialization, MutationKind,
};

use support::{
    closure, current_full, current_untracked, full_identity, object, order_currents, order_targets,
    run, target_full, target_state,
};

#[test]
fn current_target_table_reports_every_candidate_action_and_exact_ledger() {
    let hero = full_identity(1, 10, 1_000);
    let hero_fbx = full_identity(2, 20, 2_000);
    let sidecar = full_identity(4, 40, 100);
    let modified = full_identity(6, 60, 300);
    let obstructed = full_identity(7, 70, 400);
    let targets = order_targets(vec![
        target_state(0, "Game/CI/Build.meta", Materialization::MetadataOnly),
        target_full(1, "Game/Hero/Hero.asset", hero),
        target_full(2, "Game/Hero/Hero.fbx", hero_fbx),
        target_state(3, "Game/Hero/Preview.png", Materialization::AbsentBySpec),
        target_full(4, "Game/Hero/Sidecar.json", sidecar),
        target_state(5, "Game/MetaOnly.asset", Materialization::MetadataOnly),
        target_full(6, "Game/Modified.asset", modified),
        target_full(7, "Game/Obstructed.asset", obstructed),
    ]);
    let currents = order_currents(vec![
        current_full(
            0,
            "Game/Hero/Hero.fbx",
            full_identity(2, 21, 1_500),
            ogvcs_selective_sync_kernel::LocalObservation::Pristine,
        ),
        current_full(
            1,
            "Game/Hero/Preview.png",
            full_identity(3, 30, 50),
            ogvcs_selective_sync_kernel::LocalObservation::Pristine,
        ),
        current_full(
            2,
            "Game/MetaOnly.asset",
            full_identity(5, 50, 25),
            ogvcs_selective_sync_kernel::LocalObservation::Pristine,
        ),
        current_full(
            3,
            "Game/Modified.asset",
            full_identity(6, 61, 250),
            ogvcs_selective_sync_kernel::LocalObservation::Modified,
        ),
        current_untracked(4, "Game/Obstructed.asset"),
        current_full(
            5,
            "Game/OldHero.asset",
            hero,
            ogvcs_selective_sync_kernel::LocalObservation::Pristine,
        ),
    ]);
    let closure_rows = [
        (
            object(ObjectKind::Chunk, 1),
            1_000,
            CacheProbeOutcome::VerifiedHit,
        ),
        (object(ObjectKind::Chunk, 2), 2_000, CacheProbeOutcome::Miss),
        (hero.manifest, 64, CacheProbeOutcome::VerifiedHit),
        (hero_fbx.manifest, 64, CacheProbeOutcome::Miss),
        (sidecar.manifest, 64, CacheProbeOutcome::VerifiedHit),
        (modified.manifest, 64, CacheProbeOutcome::Miss),
        (obstructed.manifest, 64, CacheProbeOutcome::Miss),
    ];
    let (required, probes) = closure(&closure_rows);
    let (summary, actions) = run(targets, currents, required, probes).unwrap();

    assert_eq!(summary.actions, 8);
    assert_eq!(summary.adds, 1);
    assert_eq!(summary.updates, 1);
    assert_eq!(summary.deletes, 1);
    assert_eq!(summary.moves_or_equivalents, 1);
    assert_eq!(summary.materialization_state_changes, 2);
    assert_eq!(summary.conflicts, 2);
    assert_eq!(summary.blockers, 2);
    assert_eq!(summary.ledgers.target_full_logical_bytes, 3_800);
    assert_eq!(summary.ledgers.current_tracked_baseline_bytes, 2_825);
    assert_eq!(summary.ledgers.reusable_workspace_bytes, 1_000);
    assert_eq!(summary.ledgers.workspace_stage_bytes, 2_800);
    assert_eq!(summary.ledgers.retired_tracked_baseline_bytes, 1_825);
    assert_eq!(summary.ledgers.required_object_bytes, 3_320);
    assert_eq!(summary.ledgers.cache_hit_bytes, 1_128);
    assert_eq!(summary.ledgers.cache_miss_bytes, 2_192);
    assert_eq!(summary.ledgers.expected_transfer_bytes, 2_192);
    assert_eq!(summary.ledgers.disk_payload_reservation_bytes, 4_992);

    let find = |path: &str| actions.iter().find(|action| action.path == path).unwrap();
    assert_eq!(
        find("Game/CI/Build.meta").kind,
        CandidateActionKind::MaterializationState
    );
    assert_eq!(
        find("Game/Hero/Hero.asset").kind,
        CandidateActionKind::MoveOrEquivalent
    );
    assert_eq!(
        find("Game/Hero/Hero.asset").source_path.as_deref(),
        Some("Game/OldHero.asset")
    );
    assert_eq!(find("Game/Hero/Hero.fbx").kind, CandidateActionKind::Update);
    assert_eq!(
        find("Game/Hero/Preview.png").kind,
        CandidateActionKind::Delete
    );
    assert_eq!(
        find("Game/Hero/Sidecar.json").kind,
        CandidateActionKind::Add
    );
    assert_eq!(
        find("Game/MetaOnly.asset").kind,
        CandidateActionKind::MaterializationState
    );
    assert_eq!(
        find("Game/Modified.asset").blocked_mutation,
        Some(MutationKind::Update)
    );
    assert_eq!(
        find("Game/Obstructed.asset").blocked_mutation,
        Some(MutationKind::Add)
    );
    assert!(actions
        .iter()
        .filter(|action| {
            action.kind == CandidateActionKind::MaterializationState
                || action.kind == CandidateActionKind::Conflict
        })
        .all(|action| !action.may_write_ordinary_file()));
}

#[test]
fn persona_like_include_exclude_results_request_zero_excluded_payload() {
    struct Persona {
        name: &'static str,
        targets: Vec<ogvcs_selective_sync_kernel::DryRunTargetRecord>,
        included_manifest: ObjectRef,
        logical_bytes: u64,
        expected_metadata_actions: u64,
    }

    let personas = [
        Persona {
            name: "artist",
            targets: order_targets(vec![
                target_state(0, "Assets/Derived", Materialization::MetadataOnly),
                target_full(1, "Assets/Hero.asset", full_identity(10, 80, 800)),
                target_state(2, "Assets/Other.asset", Materialization::AbsentBySpec),
            ]),
            included_manifest: object(ObjectKind::ContentManifest, 80),
            logical_bytes: 800,
            expected_metadata_actions: 1,
        },
        Persona {
            name: "developer",
            targets: order_targets(vec![
                target_state(0, "Assets", Materialization::MetadataOnly),
                target_state(1, "Generated", Materialization::AbsentBySpec),
                target_full(2, "Source/Game.cpp", full_identity(11, 81, 810)),
            ]),
            included_manifest: object(ObjectKind::ContentManifest, 81),
            logical_bytes: 810,
            expected_metadata_actions: 1,
        },
        Persona {
            name: "ci",
            targets: order_targets(vec![
                target_full(0, "Build/Recipe.json", full_identity(12, 82, 820)),
                target_state(1, "EditorOnly", Materialization::AbsentBySpec),
                target_state(2, "Source", Materialization::MetadataOnly),
            ]),
            included_manifest: object(ObjectKind::ContentManifest, 82),
            logical_bytes: 820,
            expected_metadata_actions: 1,
        },
    ];

    for persona in personas {
        let (required, probes) =
            closure(&[(persona.included_manifest, 64, CacheProbeOutcome::Miss)]);
        let (summary, actions) = run(persona.targets, vec![], required, probes).unwrap();
        assert_eq!(summary.adds, 1, "{}", persona.name);
        assert_eq!(
            summary.materialization_state_changes, persona.expected_metadata_actions,
            "{}",
            persona.name
        );
        assert_eq!(
            summary.ledgers.target_full_logical_bytes, persona.logical_bytes,
            "{}",
            persona.name
        );
        assert_eq!(summary.required_objects, 1, "{}", persona.name);
        assert_eq!(
            summary.ledgers.expected_transfer_bytes, 64,
            "{}",
            persona.name
        );
        assert_eq!(
            actions
                .iter()
                .filter(|action| action.may_write_ordinary_file())
                .count(),
            1,
            "{}",
            persona.name
        );
    }
}
