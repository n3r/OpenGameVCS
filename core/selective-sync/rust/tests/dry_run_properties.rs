mod support;

use ogvcs_object_model::ObjectKind;
use ogvcs_selective_sync_kernel::{
    CacheProbeOutcome, CandidateActionKind, DryRunAction, DryRunActionSink, DryRunPlanner,
    EvaluationControl, IteratorPlanSource, LocalObservation, RetainedCurrentState,
    RetainedWorkspaceRecord,
};

use support::{
    bindings, closure, current_full, current_metadata, current_untracked, full_identity, run,
    target_full,
};

#[test]
fn generated_state_matrix_is_deterministic_and_never_silently_mutates_obstructions() {
    for seed in 0..24u64 {
        let mut targets = Vec::new();
        let mut currents = Vec::new();
        let mut closure_rows = Vec::new();
        let mut obstructed_paths = Vec::new();
        for index in 0..18u64 {
            let path = format!("Property/{index:03}.bin");
            let byte = u8::try_from(index + 20).unwrap();
            let target_identity = full_identity(index, byte, 100 + index);
            targets.push(target_full(index, &path, target_identity));
            closure_rows.push((
                target_identity.manifest,
                64,
                if (seed + index) % 2 == 0 {
                    CacheProbeOutcome::VerifiedHit
                } else {
                    CacheProbeOutcome::Miss
                },
            ));
            let state = (seed + index) % 6;
            let current = match state {
                0 => current_full(index, &path, target_identity, LocalObservation::Pristine),
                1 => current_full(
                    index,
                    &path,
                    full_identity(index, byte.wrapping_add(80), 90 + index),
                    LocalObservation::Pristine,
                ),
                2 => {
                    obstructed_paths.push(path.clone());
                    current_full(
                        index,
                        &path,
                        full_identity(index, byte.wrapping_add(80), 90 + index),
                        LocalObservation::Modified,
                    )
                }
                3 => {
                    obstructed_paths.push(path.clone());
                    current_untracked(index, &path)
                }
                4 => current_metadata(index, &path, false),
                _ => current_full(index, &path, target_identity, LocalObservation::Missing),
            };
            currents.push(current);
        }
        let (required, probes) = closure(&closure_rows);
        let first = run(
            targets.clone(),
            currents.clone(),
            required.clone(),
            probes.clone(),
        )
        .unwrap();
        let second = run(targets, currents, required, probes).unwrap();
        assert_eq!(first, second, "seed {seed}");
        let (summary, actions) = first;
        assert_eq!(
            summary.ledgers.cache_hit_bytes + summary.ledgers.cache_miss_bytes,
            summary.ledgers.required_object_bytes,
            "seed {seed}"
        );
        assert_eq!(
            summary.ledgers.expected_transfer_bytes, summary.ledgers.cache_miss_bytes,
            "seed {seed}"
        );
        for path in obstructed_paths {
            let action = actions
                .iter()
                .find(|action| action.path == path)
                .expect("obstruction must be reported");
            assert_eq!(action.kind, CandidateActionKind::Conflict, "seed {seed}");
            assert!(!action.may_write_ordinary_file(), "seed {seed}");
        }
        assert!(actions
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
    }
}

#[test]
fn untrusted_warm_and_cold_probe_claims_change_only_arithmetic_not_candidate_actions() {
    let identity = full_identity(40, 90, 4_096);
    let targets = vec![target_full(0, "Warm/Hero.bin", identity)];
    let objects = [
        (ogvcs_selective_sync_kernel::DryRunRequiredObject {
            ordinal: 0,
            object: ogvcs_object_model::ObjectRef {
                kind: ObjectKind::Chunk,
                digest: [1; 32],
            },
            payload_bytes: 4_096,
        }),
        (ogvcs_selective_sync_kernel::DryRunRequiredObject {
            ordinal: 1,
            object: identity.manifest,
            payload_bytes: 64,
        }),
    ];
    // `VerifiedHit` is a caller claim, not a byte-verification callback or an
    // authorization brand. The planner can only bind and add its arithmetic.
    let cold = objects
        .iter()
        .map(|record| ogvcs_selective_sync_kernel::CacheProbeRecord {
            ordinal: record.ordinal,
            object: record.object,
            payload_bytes: record.payload_bytes,
            outcome: CacheProbeOutcome::Miss,
        })
        .collect();
    let warm = objects
        .iter()
        .map(|record| ogvcs_selective_sync_kernel::CacheProbeRecord {
            ordinal: record.ordinal,
            object: record.object,
            payload_bytes: record.payload_bytes,
            outcome: CacheProbeOutcome::VerifiedHit,
        })
        .collect();
    let (cold_summary, cold_actions) =
        run(targets.clone(), vec![], objects.to_vec(), cold).unwrap();
    let (warm_summary, warm_actions) = run(targets, vec![], objects.to_vec(), warm).unwrap();
    assert_eq!(cold_actions, warm_actions);
    assert_eq!(
        cold_summary.action_projection_digest,
        warm_summary.action_projection_digest
    );
    assert_eq!(cold_summary.ledgers.expected_transfer_bytes, 4_160);
    assert_eq!(warm_summary.ledgers.expected_transfer_bytes, 0);
    assert_eq!(warm_summary.ledgers.cache_hit_bytes, 4_160);
}

#[test]
fn permission_hidden_omission_is_structurally_indistinguishable_from_absence() {
    let current = vec![RetainedWorkspaceRecord {
        ordinal: 0,
        path: "Known/FormerlyVisible.asset".to_owned(),
        state: RetainedCurrentState::Full {
            identity: full_identity(50, 100, 512),
            observation: LocalObservation::Pristine,
        },
    }];
    // Both adapters expose the same filtered target projection. There is no
    // omission-reason field through which the planner could distinguish a
    // nonexistent target from a now-hidden target or reveal a replacement.
    let ordinary_absence = run(vec![], current.clone(), vec![], vec![]).unwrap();
    let permission_hidden = run(vec![], current, vec![], vec![]).unwrap();
    assert_eq!(ordinary_absence, permission_hidden);
    assert_eq!(ordinary_absence.0.deletes, 1);
    assert_eq!(ordinary_absence.1[0].path, "Known/FormerlyVisible.asset");
    assert!(ordinary_absence.1[0].source_path.is_none());
}

#[derive(Default)]
struct CountingSink {
    actions: u64,
}

impl DryRunActionSink for CountingSink {
    type Error = ();

    fn emit(&mut self, _action: &DryRunAction) -> Result<(), Self::Error> {
        self.actions += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn planner_peak_excludes_and_does_not_depend_on_sink_owned_retention() {
    let identity = full_identity(60, 110, 1_024);
    let targets = vec![target_full(0, "Memory/Hero.bin", identity)];
    let (required, probes) = closure(&[(identity.manifest, 64, CacheProbeOutcome::VerifiedHit)]);
    let (retaining_summary, retaining_actions) =
        run(targets.clone(), vec![], required.clone(), probes.clone()).unwrap();

    let planner = DryRunPlanner::new(bindings(1, 0, 1).unwrap());
    let mut target_source = IteratorPlanSource::new(targets.into_iter());
    let mut current_source =
        IteratorPlanSource::new(Vec::<RetainedWorkspaceRecord>::new().into_iter());
    let mut object_source = IteratorPlanSource::new(required.into_iter());
    let mut cache_source = IteratorPlanSource::new(probes.into_iter());
    let mut counting_sink = CountingSink::default();
    let counting_summary = planner
        .plan(
            &mut target_source,
            &mut current_source,
            &mut object_source,
            &mut cache_source,
            &mut counting_sink,
            &EvaluationControl::default(),
        )
        .unwrap();
    assert_eq!(counting_sink.actions, retaining_actions.len() as u64);
    assert_eq!(
        counting_summary.retained_bytes_peak,
        retaining_summary.retained_bytes_peak
    );
    assert_eq!(
        counting_summary.action_projection_digest,
        retaining_summary.action_projection_digest
    );
}
