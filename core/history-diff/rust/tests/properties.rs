#![allow(clippy::field_reassign_with_default)]

mod support;

use std::collections::BTreeMap;

use ogvcs_history_diff_kernel::{
    diff_page, DiffRecord, DiffRequest, Limits, OperationControl, PresenceChange,
};
use ogvcs_path_contract::CaseMode;
use support::{file_id, EntrySpec, Store};

fn generated_case(seed: u8) -> (Store, DiffRequest) {
    let mut store = Store::new();
    let first = store.manifest(seed.wrapping_add(1), 10);
    let second = store.manifest(seed.wrapping_add(2), 20);
    let mut before_entries = Vec::new();
    let mut after_entries = Vec::new();
    for ordinal in 1u8..=12 {
        let id = file_id(u128::from(ordinal));
        if ordinal.wrapping_add(seed) % 3 != 0 {
            before_entries.push(EntrySpec::file(
                &format!("file-{ordinal:02}.bin"),
                id,
                first,
                10,
            ));
        }
        if ordinal.wrapping_add(seed) % 4 != 0 {
            let renamed = ordinal.wrapping_add(seed) % 5 == 0;
            let changed = ordinal.wrapping_add(seed) % 2 == 0;
            after_entries.push(EntrySpec::file(
                &if renamed {
                    format!("renamed-{ordinal:02}.bin")
                } else {
                    format!("file-{ordinal:02}.bin")
                },
                id,
                if changed { second } else { first },
                if changed { 20 } else { 10 },
            ));
        }
    }
    let before_tree = store.tree(before_entries);
    let after_tree = store.tree(after_entries);
    let before = store.snapshot(seed.wrapping_add(40), vec![], before_tree);
    let after = store.snapshot(seed.wrapping_add(80), vec![], after_tree);
    let request = DiffRequest {
        before_snapshot: before,
        after_snapshot: after,
        repository_descriptor: store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    (store, request)
}

fn run(store: &Store, request: DiffRequest) -> Vec<DiffRecord> {
    diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap()
    .records
}

#[test]
fn deterministic_generated_corpus_repeats_exactly() {
    for seed in 1..=32 {
        let (store, request) = generated_case(seed);
        assert_eq!(run(&store, request), run(&store, request), "seed {seed}");
    }
}

#[test]
fn reverse_diff_is_presence_and_projection_symmetric() {
    for seed in 1..=32 {
        let (store, request) = generated_case(seed);
        let forward = run(&store, request)
            .into_iter()
            .map(|record| (*record.file_id.as_bytes(), record))
            .collect::<BTreeMap<_, _>>();
        let reverse = run(
            &store,
            DiffRequest {
                before_snapshot: request.after_snapshot,
                after_snapshot: request.before_snapshot,
                ..request
            },
        )
        .into_iter()
        .map(|record| (*record.file_id.as_bytes(), record))
        .collect::<BTreeMap<_, _>>();
        assert_eq!(forward.len(), reverse.len(), "seed {seed}");
        for (file_id, left) in forward {
            let right = reverse.get(&file_id).unwrap();
            assert_eq!(left.before, right.after, "seed {seed}");
            assert_eq!(left.after, right.before, "seed {seed}");
            assert_eq!(left.changes, right.changes, "seed {seed}");
            assert_eq!(left.move_hint, right.move_hint, "seed {seed}");
            assert_eq!(
                (left.presence, right.presence),
                match left.presence {
                    PresenceChange::Added => (PresenceChange::Added, PresenceChange::Deleted),
                    PresenceChange::Deleted => (PresenceChange::Deleted, PresenceChange::Added),
                    PresenceChange::Retained => {
                        (PresenceChange::Retained, PresenceChange::Retained)
                    }
                },
                "seed {seed}"
            );
        }
    }
}

#[test]
fn every_page_size_from_one_through_corpus_length_preserves_order() {
    let (store, request) = generated_case(7);
    let expected = run(&store, request);
    for page_size in 1..=u64::try_from(expected.len()).unwrap() {
        let mut limits = Limits::default();
        limits.page_records = page_size;
        let mut cursor = None;
        let mut actual = Vec::new();
        loop {
            let page = diff_page(
                &mut store.source(),
                request,
                limits,
                &OperationControl::default(),
                cursor.as_ref(),
            )
            .unwrap();
            actual.extend(page.records);
            if page.complete {
                break;
            }
            cursor = page.next;
        }
        assert_eq!(actual, expected, "page size {page_size}");
    }
}
