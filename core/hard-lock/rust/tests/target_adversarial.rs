mod common;

use common::*;
use ogvcs_hard_lock_model::*;

fn outcome_for(target: TargetInput) -> OutcomeClass {
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![acquire(1, subject(10), workspace(10), target)],
        )
        .unwrap();
    recorded(&result, 0).outcome
}

#[test]
fn unknown_expansion_version_fails_closed() {
    let mut target = file_target(file(20), "Assets/Hero.uasset", 1);
    target.expansion.schema_version = TARGET_EXPANSION_VERSION + 1;
    assert_eq!(outcome_for(target), OutcomeClass::InvalidRequest);
}

#[test]
fn zero_view_generation_fails_closed() {
    let target = file_target(file(20), "Assets/Hero.uasset", 0);
    assert_eq!(outcome_for(target), OutcomeClass::InvalidRequest);
}

#[test]
fn supplied_permission_rejection_precedes_target_diagnostics() {
    let actor = subject(10);
    let mut denied_meta = meta(1, actor, PermissionAssignment::LockCreate);
    denied_meta.permission.decision = SuppliedDecision::NotAffirmed;
    let mut target = file_target(file(20), "Assets/Hero.uasset", 0);
    target.expansion.schema_version = TARGET_EXPANSION_VERSION + 1;
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![Command::Acquire(AcquireRequest {
                meta: denied_meta,
                owner: actor,
                workspace: workspace(10),
                base_snapshot: snapshot(10),
                target,
                lease_ticks: 20,
            })],
        )
        .unwrap();
    assert_eq!(
        recorded(&result, 0).outcome,
        OutcomeClass::SuppliedFactRejected
    );
}

#[test]
fn group_policy_version_or_digest_substitution_fails_closed() {
    let member = ExpandedMember {
        file_id: file(20),
        canonical_path: "Assets/Hero.uasset".to_owned(),
    };
    let mut wrong_version = group_target(8, 3, vec![member.clone()]);
    wrong_version.expansion.policy_version = 4;
    assert_eq!(outcome_for(wrong_version), OutcomeClass::InvalidRequest);
    let mut zero_digest = group_target(8, 3, vec![member]);
    zero_digest.expansion.policy_digest = [0; 32];
    assert_eq!(outcome_for(zero_digest), OutcomeClass::InvalidRequest);
}

#[test]
fn duplicate_file_id_and_folded_path_collision_are_ambiguous() {
    let duplicate_id = group_target(
        8,
        3,
        vec![
            ExpandedMember {
                file_id: file(20),
                canonical_path: "Assets/A.uasset".to_owned(),
            },
            ExpandedMember {
                file_id: file(20),
                canonical_path: "Assets/B.uasset".to_owned(),
            },
        ],
    );
    assert_eq!(outcome_for(duplicate_id), OutcomeClass::InvalidRequest);

    let collision = group_target(
        8,
        3,
        vec![
            ExpandedMember {
                file_id: file(20),
                canonical_path: "Assets/Hero.uasset".to_owned(),
            },
            ExpandedMember {
                file_id: file(21),
                canonical_path: "assets/hero.uasset".to_owned(),
            },
        ],
    );
    let mut folded = model_with(
        ogvcs_path_contract::CaseMode::Folded,
        ModelLimits::default(),
    );
    let result = folded
        .apply_batch(
            context(101),
            vec![acquire(1, subject(10), workspace(10), collision)],
        )
        .unwrap();
    assert_eq!(recorded(&result, 0).outcome, OutcomeClass::InvalidRequest);
}

#[test]
fn prefix_expansion_member_outside_prefix_fails_closed() {
    let target = prefix_target(
        "Assets/Characters",
        &[(file(20), "Assets/Maps/Arena.umap")],
        1,
    );
    assert_eq!(outcome_for(target), OutcomeClass::InvalidRequest);
}

#[test]
fn same_asset_group_identity_conflicts_even_when_supplied_projection_changes() {
    let first = group_target(
        8,
        3,
        vec![ExpandedMember {
            file_id: file(20),
            canonical_path: "Assets/A.uasset".to_owned(),
        }],
    );
    let second = group_target(
        8,
        4,
        vec![ExpandedMember {
            file_id: file(21),
            canonical_path: "Assets/B.uasset".to_owned(),
        }],
    );
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![
                acquire(1, subject(10), workspace(10), first),
                acquire(2, subject(11), workspace(11), second),
            ],
        )
        .unwrap();
    assert_eq!(
        result
            .results
            .iter()
            .filter(|result| result.receipt().unwrap().outcome == OutcomeClass::Granted)
            .count(),
        1
    );
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn group_member_conflicts_with_direct_file_lock() {
    let file_id = file(20);
    let group = group_target(
        8,
        3,
        vec![ExpandedMember {
            file_id,
            canonical_path: "Assets/Hero.uasset".to_owned(),
        }],
    );
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![
                acquire(1, subject(10), workspace(10), group),
                acquire(
                    2,
                    subject(11),
                    workspace(11),
                    file_target(file_id, "Assets/Hero.uasset", 1),
                ),
            ],
        )
        .unwrap();
    assert!(result
        .results
        .iter()
        .any(|result| result.receipt().unwrap().outcome == OutcomeClass::Conflict));
}

#[test]
fn group_members_overlap_other_groups_and_ancestor_prefixes() {
    let shared_file = file(20);
    let first_group = group_target(
        8,
        3,
        vec![ExpandedMember {
            file_id: shared_file,
            canonical_path: "Assets/Characters/Hero.uasset".to_owned(),
        }],
    );
    let second_group = group_target(
        9,
        3,
        vec![ExpandedMember {
            file_id: shared_file,
            canonical_path: "Assets/Characters/Hero.uasset".to_owned(),
        }],
    );
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![
                acquire(1, subject(10), workspace(10), first_group),
                acquire(2, subject(11), workspace(11), second_group),
                acquire(
                    3,
                    subject(12),
                    workspace(12),
                    prefix_target("Assets", &[], 1),
                ),
            ],
        )
        .unwrap();
    assert_eq!(
        result
            .results
            .iter()
            .filter(|result| result.receipt().unwrap().outcome == OutcomeClass::Granted)
            .count(),
        1
    );
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn nested_prefixes_conflict_without_member_expansion() {
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![
                acquire(
                    1,
                    subject(10),
                    workspace(10),
                    prefix_target("Assets", &[], 1),
                ),
                acquire(
                    2,
                    subject(11),
                    workspace(11),
                    prefix_target("Assets/Characters", &[], 1),
                ),
            ],
        )
        .unwrap();
    assert_eq!(
        result
            .results
            .iter()
            .filter(|result| result.receipt().unwrap().outcome == OutcomeClass::Granted)
            .count(),
        1
    );
}

#[test]
fn two_repository_root_prefixes_conflict_without_member_expansion() {
    let mut state = model();
    let result = state
        .apply_batch(
            context(101),
            vec![
                acquire(1, subject(10), workspace(10), prefix_target("", &[], 1)),
                acquire(2, subject(11), workspace(11), prefix_target("", &[], 1)),
            ],
        )
        .unwrap();
    assert_eq!(
        result
            .results
            .iter()
            .filter(|result| result.receipt().unwrap().outcome == OutcomeClass::Granted)
            .count(),
        1
    );
    assert_eq!(state.active_hard_lock_count(), 1);
}

#[test]
fn prefix_expansion_accepts_exact_member_limit_and_rejects_limit_plus_one() {
    let exact = (1..=PREFIX_EXPANSION_MEMBERS_MAXIMUM)
        .map(|index| {
            (
                file_number(index as u16),
                format!("Assets/Prefix/{index}.uasset"),
            )
        })
        .collect::<Vec<_>>();
    let exact_refs = exact
        .iter()
        .map(|(file_id, path)| (*file_id, path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        outcome_for(prefix_target("Assets", &exact_refs, 1)),
        OutcomeClass::Granted
    );

    let mut over = exact;
    over.push((
        file_number((PREFIX_EXPANSION_MEMBERS_MAXIMUM + 1) as u16),
        "Assets/Prefix/overflow.uasset".to_owned(),
    ));
    let over_refs = over
        .iter()
        .map(|(file_id, path)| (*file_id, path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        outcome_for(prefix_target("Assets", &over_refs, 1)),
        OutcomeClass::InvalidRequest
    );
}

#[test]
fn target_path_accepts_exact_byte_limit_and_rejects_limit_plus_one() {
    let exact_path = (0..17)
        .map(|_| "a".repeat(240))
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(exact_path.len(), 4_096);
    assert_eq!(
        outcome_for(prefix_target(&exact_path, &[], 1)),
        OutcomeClass::Granted
    );

    let mut over_segments = (0..16).map(|_| "a".repeat(240)).collect::<Vec<_>>();
    over_segments.push("a".repeat(241));
    let over_path = over_segments.join("/");
    assert_eq!(over_path.len(), 4_097);
    assert_eq!(
        outcome_for(prefix_target(&over_path, &[], 1)),
        OutcomeClass::InvalidRequest
    );
}
