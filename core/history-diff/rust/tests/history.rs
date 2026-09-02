#![allow(clippy::field_reassign_with_default)]

mod support;

use ogvcs_history_diff_kernel::{
    history_page, CorruptKind, FailureKind, HistoryCursor, HistoryRequest, LimitKind, Limits,
    OperationControl,
};
use support::Store;

fn merge_history() -> (Store, HistoryRequest, Vec<ogvcs_object_model::ObjectRef>) {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let root = store.snapshot(1, vec![], tree);
    let left = store.snapshot(2, vec![root], tree);
    let right = store.snapshot(3, vec![root], tree);
    let merge = store.snapshot(4, vec![left, right], tree);
    let request = HistoryRequest {
        start_snapshot: merge,
        repository_descriptor: store.descriptor,
        designated_root: root,
    };
    (store, request, vec![root, left, right, merge])
}

#[test]
fn ordered_merge_dag_convergence_is_valid_and_deduplicated() {
    let (store, request, expected) = merge_history();
    let mut source = store.source();
    let page = history_page(
        &mut source,
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert!(page.complete);
    assert_eq!(
        page.records
            .iter()
            .map(|record| record.snapshot)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(page.ledger.emitted_records, 4);
    assert_eq!(page.ledger.snapshot_edges, 4);
    assert_eq!(page.ledger.charged_memory_bytes, 0);
}

#[test]
fn history_pages_resume_on_fresh_source_and_equal_single_page() {
    let (store, request, expected) = merge_history();
    let mut limits = Limits::default();
    limits.page_records = 1;
    let mut cursor = None;
    let mut observed = Vec::new();
    let ledger = loop {
        let mut source = store.source();
        let page = history_page(
            &mut source,
            request,
            limits,
            &OperationControl::default(),
            cursor.as_ref(),
        )
        .unwrap();
        observed.extend(page.records.iter().map(|record| record.snapshot));
        if page.complete {
            assert!(page.next.is_none());
            break page.ledger;
        }
        cursor = page.next;
    };
    assert_eq!(observed, expected);
    assert_eq!(ledger.emitted_records, 4);
    assert!(ledger.cursor_bytes_encoded > 0);
    assert!(ledger.cursor_bytes_decoded > 0);
    assert_eq!(ledger.charged_memory_bytes, 0);
}

#[test]
fn history_cursor_rejects_byte_tamper_and_option_drift() {
    let (store, request, _) = merge_history();
    let mut limits = Limits::default();
    limits.page_records = 1;
    let mut source = store.source();
    let first = history_page(
        &mut source,
        request,
        limits,
        &OperationControl::default(),
        None,
    )
    .unwrap();
    let cursor = first.next.unwrap();
    let replay_one = history_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap();
    let replay_two = history_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap();
    assert_eq!(replay_one, replay_two);
    let mut bytes = cursor.as_bytes().to_vec();
    let index = bytes.len() / 2;
    bytes[index] ^= 0x01;
    let corrupted = HistoryCursor::from_bytes(&bytes, limits.max_cursor_bytes).unwrap();
    let error = history_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        Some(&corrupted),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Corrupt(CorruptKind::Cursor));

    let mut changed = limits;
    changed.page_records = 2;
    let error = history_page(
        &mut store.source(),
        request,
        changed,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::CursorOptionsMismatch);

    let substituted = HistoryRequest {
        start_snapshot: request.designated_root,
        ..request
    };
    let error = history_page(
        &mut store.source(),
        substituted,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::CursorOptionsMismatch);
}

#[test]
fn duplicate_parent_and_second_root_fail_closed() {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let root = store.snapshot(1, vec![], tree);
    let duplicate = store.snapshot(2, vec![root, root], tree);
    let request = HistoryRequest {
        start_snapshot: duplicate,
        repository_descriptor: store.descriptor,
        designated_root: root,
    };
    let error = history_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Corrupt(CorruptKind::SnapshotParentDuplicate)
    );

    let other_root = store.snapshot(3, vec![], tree);
    let request = HistoryRequest {
        start_snapshot: other_root,
        repository_descriptor: store.descriptor,
        designated_root: root,
    };
    let error = history_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Corrupt(CorruptKind::SnapshotSecondRoot)
    );
}

#[test]
fn history_depth_and_cursor_limits_are_explicit() {
    let (store, request, _) = merge_history();
    let mut depth_limits = Limits::default();
    depth_limits.max_history_snapshots = 2;
    let error = history_page(
        &mut store.source(),
        request,
        depth_limits,
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Limit(LimitKind::HistorySnapshots));

    let mut cursor_limits = Limits::default();
    cursor_limits.page_records = 1;
    cursor_limits.max_cursor_bytes = 256;
    cursor_limits.max_charged_memory_bytes = 64 * 1024 * 1024;
    let error = history_page(
        &mut store.source(),
        request,
        cursor_limits,
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Limit(LimitKind::CursorBytes));

    let mut measured = Limits::default();
    measured.page_records = 1;
    let cursor_bytes = history_page(
        &mut store.source(),
        request,
        measured,
        &OperationControl::default(),
        None,
    )
    .unwrap()
    .next
    .unwrap()
    .as_bytes()
    .len() as u64;
    measured.max_cursor_bytes = cursor_bytes;
    assert!(history_page(
        &mut store.source(),
        request,
        measured,
        &OperationControl::default(),
        None,
    )
    .unwrap()
    .next
    .is_some());
    measured.max_cursor_bytes = cursor_bytes - 1;
    assert_eq!(
        history_page(
            &mut store.source(),
            request,
            measured,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::CursorBytes)
    );
}

#[test]
fn deep_history_stack_comparisons_are_charged_and_obey_the_exact_work_limit() {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let root = store.snapshot(1, vec![], tree);
    let mut start = root;
    for tag in 2..=16 {
        start = store.snapshot(tag, vec![start], tree);
    }
    let request = HistoryRequest {
        start_snapshot: start,
        repository_descriptor: store.descriptor,
        designated_root: root,
    };
    let baseline = history_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert_eq!(baseline.ledger.comparisons, (1u64..16).sum::<u64>());

    let mut exact = Limits::default();
    exact.max_history_snapshots = 16;
    exact.max_work_units = baseline.ledger.work_units;
    assert!(history_page(
        &mut store.source(),
        request,
        exact,
        &OperationControl::default(),
        None,
    )
    .is_ok());

    let history_plus_one = Limits {
        max_history_snapshots: 15,
        ..exact
    };
    assert_eq!(
        history_page(
            &mut store.source(),
            request,
            history_plus_one,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::HistorySnapshots)
    );

    exact.max_work_units -= 1;
    assert_eq!(
        history_page(
            &mut store.source(),
            request,
            exact,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::WorkUnits)
    );
}

#[test]
fn history_rechecks_generation_after_the_last_snapshot_read() {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let root = store.snapshot(1, vec![], tree);
    let child = store.snapshot(2, vec![root], tree);
    let request = HistoryRequest {
        start_snapshot: child,
        repository_descriptor: store.descriptor,
        designated_root: root,
    };
    let mut source = store.source();
    // Initial capture + opening fence + two fences for each of descriptor,
    // child and root + the final release fence.
    source.flip_generation_on_call = Some(9);
    let error = history_page(
        &mut source,
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::GenerationChanged);
}

#[test]
fn eight_parent_fanout_is_deterministic_and_ninth_parent_fails_closed() {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let root = store.snapshot(1, vec![], tree);
    let parents = (2u8..=9)
        .map(|tag| store.snapshot(tag, vec![root], tree))
        .collect::<Vec<_>>();
    let merge = store.snapshot(10, parents.clone(), tree);
    let mut limits = Limits::default();
    limits.max_history_snapshots = 10;
    let page = history_page(
        &mut store.source(),
        HistoryRequest {
            start_snapshot: merge,
            repository_descriptor: store.descriptor,
            designated_root: root,
        },
        limits,
        &OperationControl::default(),
        None,
    )
    .unwrap();
    let mut expected = vec![root];
    expected.extend(parents.iter().copied());
    expected.push(merge);
    assert_eq!(
        page.records
            .iter()
            .map(|record| record.snapshot)
            .collect::<Vec<_>>(),
        expected
    );

    let mut nine_parents = parents;
    nine_parents.push(root);
    let invalid = store.snapshot(11, nine_parents, tree);
    let error = history_page(
        &mut store.source(),
        HistoryRequest {
            start_snapshot: invalid,
            repository_descriptor: store.descriptor,
            designated_root: root,
        },
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Corrupt(CorruptKind::KnownSchema));
}
