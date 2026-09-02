#![allow(clippy::field_reassign_with_default)]

mod support;

use ogvcs_history_diff_kernel::{
    diff_page, AmbiguousKind, ChangeFlags, CorruptKind, DiffCursor, DiffRequest, FailureKind,
    Limits, MoveHint, OperationControl, PresenceChange,
};
use ogvcs_object_model::{FileId, ObjectRef};
use ogvcs_path_contract::CaseMode;
use support::{file_id, EntrySpec, Store};

fn representative_diff() -> (Store, DiffRequest) {
    let mut store = Store::new();
    let old_manifest = store.manifest(1, 10);
    let new_manifest = store.manifest(2, 20);
    let small_manifest = store.manifest(3, 4);
    let before_leaf = store.tree(vec![
        EntrySpec::file("deleted.bin", file_id(2), old_manifest, 10),
        EntrySpec::file("old.txt", file_id(1), old_manifest, 10),
    ]);
    let after_leaf = store.tree(vec![
        EntrySpec::file("added.bin", file_id(3), small_manifest, 4),
        EntrySpec::file("new.txt", file_id(1), new_manifest, 20),
    ]);
    let before_root = store.tree(vec![
        EntrySpec::directory("Old", file_id(10), before_leaf),
        EntrySpec::file("policy.bin", file_id(5), small_manifest, 4),
        EntrySpec::file("type.bin", file_id(4), old_manifest, 10),
    ]);
    let after_root = store.tree(vec![
        EntrySpec::directory("New", file_id(10), after_leaf),
        EntrySpec::file("policy.bin", file_id(5), small_manifest, 4)
            .with_policy("content-policy.test/alternate@1"),
        EntrySpec::typed("type.bin", file_id(4), old_manifest, 10, 3),
    ]);
    let before = store.snapshot(11, vec![], before_root);
    let after = store.snapshot(12, vec![], after_root);
    let request = DiffRequest {
        before_snapshot: before,
        after_snapshot: after,
        repository_descriptor: store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    (store, request)
}

fn collect_paged(
    store: &Store,
    request: DiffRequest,
    mut limits: Limits,
) -> Vec<ogvcs_history_diff_kernel::DiffRecord> {
    limits.page_records = 2;
    let mut cursor = None;
    let mut records = Vec::new();
    loop {
        let page = diff_page(
            &mut store.source(),
            request,
            limits,
            &OperationControl::default(),
            cursor.as_ref(),
        )
        .unwrap();
        records.extend(page.records);
        if page.complete {
            break;
        }
        cursor = page.next;
    }
    records
}

#[test]
fn golden_diff_classifies_presence_metadata_content_type_mode_policy_and_moves() {
    let (store, request) = representative_diff();
    let page = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert!(page.complete);
    assert_eq!(page.path_profile, "path.opengamevcs/portable@1");
    assert_eq!(page.records.len(), 6);
    let by_id = page
        .records
        .iter()
        .map(|record| (*record.file_id.as_bytes(), record))
        .collect::<std::collections::BTreeMap<_, _>>();

    let moved = by_id.get(file_id(1).as_bytes()).unwrap();
    assert_eq!(moved.presence, PresenceChange::Retained);
    assert_eq!(moved.move_hint, MoveHint::Move);
    assert!(moved.changes.contains(ChangeFlags::CONTENT_MANIFEST));
    assert!(moved.changes.contains(ChangeFlags::LOGICAL_SIZE));
    assert!(moved.changes.contains(ChangeFlags::PATH));
    assert_eq!(moved.before.as_ref().unwrap().path, "Old/old.txt");
    assert_eq!(moved.after.as_ref().unwrap().path, "New/new.txt");

    assert_eq!(
        by_id.get(file_id(2).as_bytes()).unwrap().presence,
        PresenceChange::Deleted
    );
    assert_eq!(
        by_id.get(file_id(3).as_bytes()).unwrap().presence,
        PresenceChange::Added
    );
    let typed = by_id.get(file_id(4).as_bytes()).unwrap();
    assert!(typed.changes.contains(ChangeFlags::ENTRY_TYPE));
    assert!(typed.changes.contains(ChangeFlags::MODE));
    let policy = by_id.get(file_id(5).as_bytes()).unwrap();
    assert_eq!(policy.changes.bits(), ChangeFlags::CONTENT_POLICY);
    let directory = by_id.get(file_id(10).as_bytes()).unwrap();
    assert!(directory.changes.contains(ChangeFlags::TREE_METADATA));
    assert!(directory.changes.contains(ChangeFlags::PATH));
    assert_eq!(directory.move_hint, MoveHint::Rename);
    assert_eq!(page.ledger.emitted_records, 6);
    assert_eq!(page.ledger.charged_memory_bytes, 0);
}

#[test]
fn diff_pagination_and_fresh_process_restart_equal_single_page() {
    let (store, request) = representative_diff();
    let single = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap()
    .records;
    let paged = collect_paged(&store, request, Limits::default());
    assert_eq!(paged, single);
}

#[test]
fn diff_cursor_rejects_tamper_and_options_mismatch() {
    let (store, request) = representative_diff();
    let mut limits = Limits::default();
    limits.page_records = 1;
    let first = diff_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        None,
    )
    .unwrap();
    let cursor = first.next.unwrap();
    let replay_one = diff_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap();
    let replay_two = diff_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap();
    assert_eq!(replay_one, replay_two);
    let mut bytes = cursor.as_bytes().to_vec();
    let index = bytes.len() / 3;
    bytes[index] ^= 0x80;
    let corrupt = DiffCursor::from_bytes(&bytes, limits.max_cursor_bytes).unwrap();
    let error = diff_page(
        &mut store.source(),
        request,
        limits,
        &OperationControl::default(),
        Some(&corrupt),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Corrupt(CorruptKind::Cursor));

    let mut changed = limits;
    changed.page_records = 2;
    let error = diff_page(
        &mut store.source(),
        request,
        changed,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::CursorOptionsMismatch);

    let substituted = DiffRequest {
        before_snapshot: request.after_snapshot,
        after_snapshot: request.before_snapshot,
        ..request
    };
    let error = diff_page(
        &mut store.source(),
        substituted,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::CursorOptionsMismatch);
}

fn simple_request(
    store: &mut Store,
    before_entries: Vec<EntrySpec>,
    after_entries: Vec<EntrySpec>,
    mode: CaseMode,
) -> DiffRequest {
    let before_tree = store.tree(before_entries);
    let after_tree = store.tree(after_entries);
    let before = store.snapshot(21, vec![], before_tree);
    let after = store.snapshot(22, vec![], after_tree);
    DiffRequest {
        before_snapshot: before,
        after_snapshot: after,
        repository_descriptor: store.descriptor,
        case_mode: mode,
    }
}

#[test]
fn duplicate_file_id_and_platform_alias_fail_closed_before_output() {
    let mut store = Store::new();
    let manifest = store.manifest(1, 1);
    let request = simple_request(
        &mut store,
        vec![],
        vec![
            EntrySpec::file("a", file_id(1), manifest, 1),
            EntrySpec::file("b", file_id(1), manifest, 1),
        ],
        CaseMode::Sensitive,
    );
    let error = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Ambiguous(AmbiguousKind::DuplicateFileId)
    );

    let mut store = Store::new();
    let manifest = store.manifest(2, 1);
    let request = simple_request(
        &mut store,
        vec![],
        vec![
            EntrySpec::file("Foo", file_id(1), manifest, 1),
            EntrySpec::file("foo", file_id(2), manifest, 1),
        ],
        CaseMode::Folded,
    );
    let error = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert!(matches!(
        error.kind,
        FailureKind::Ambiguous(AmbiguousKind::RepositoryPathCollision)
            | FailureKind::Ambiguous(AmbiguousKind::PlatformPathCollision)
    ));

    let mut store = Store::new();
    let manifest = store.manifest(3, 1);
    let request = simple_request(
        &mut store,
        vec![],
        vec![
            EntrySpec::file("Straße", file_id(1), manifest, 1),
            EntrySpec::file("STRASSE", file_id(2), manifest, 1),
        ],
        CaseMode::Sensitive,
    );
    let error = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Ambiguous(AmbiguousKind::PlatformPathCollision)
    );
}

#[test]
fn shared_tree_reference_is_not_silently_expanded_twice() {
    let mut store = Store::new();
    let shared = store.tree(vec![]);
    let request = simple_request(
        &mut store,
        vec![],
        vec![
            EntrySpec::directory("A", file_id(1), shared),
            EntrySpec::directory("B", file_id(2), shared),
        ],
        CaseMode::Sensitive,
    );
    let error = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Ambiguous(AmbiguousKind::SharedTree)
    );
}

#[test]
fn identical_snapshots_have_an_empty_complete_diff() {
    let (store, mut request) = representative_diff();
    request.after_snapshot = request.before_snapshot;
    let page = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert!(page.complete);
    assert!(page.records.is_empty());
}

#[test]
fn manifest_length_and_descriptor_profile_membership_are_graph_invariants() {
    let mut store = Store::new();
    let manifest = store.manifest(7, 8);
    let request = simple_request(
        &mut store,
        vec![],
        vec![EntrySpec::file("wrong-size.bin", file_id(1), manifest, 7)],
        CaseMode::Sensitive,
    );
    let error = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Corrupt(CorruptKind::TreeEntryTarget)
    );
    assert_eq!(error.reference, Some(manifest));

    let mut store = Store::with_repository_profiles(
        0x45,
        &["content-policy.test/opaque@1"],
        &["chunking.test/external-boundaries@1"],
    );
    let manifest = store.manifest(8, 8);
    let request = simple_request(
        &mut store,
        vec![],
        vec![EntrySpec::file("policy.bin", file_id(2), manifest, 8)
            .with_policy("content-policy.test/alternate@1")],
        CaseMode::Sensitive,
    );
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            Limits::default(),
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Corrupt(CorruptKind::RepositoryDescriptor)
    );

    let mut store = Store::with_repository_profiles(0x46, &["content-policy.test/opaque@1"], &[]);
    let manifest = store.manifest(9, 8);
    let request = simple_request(
        &mut store,
        vec![],
        vec![EntrySpec::file(
            "chunk-profile.bin",
            file_id(3),
            manifest,
            8,
        )],
        CaseMode::Sensitive,
    );
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            Limits::default(),
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Corrupt(CorruptKind::RepositoryDescriptor)
    );
}

#[test]
fn crossing_directory_and_file_types_reports_both_target_domains() {
    let mut store = Store::new();
    let empty_tree = store.tree(vec![]);
    let manifest = store.manifest(10, 4);
    let request = simple_request(
        &mut store,
        vec![EntrySpec::directory("asset", file_id(1), empty_tree)],
        vec![EntrySpec::file("asset", file_id(1), manifest, 4)],
        CaseMode::Sensitive,
    );
    let page = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    let record = page.records.first().unwrap();
    assert!(record.changes.contains(ChangeFlags::TREE_METADATA));
    assert!(record.changes.contains(ChangeFlags::CONTENT_MANIFEST));
    assert!(record.changes.contains(ChangeFlags::ENTRY_TYPE));
}

#[test]
fn case_only_same_file_id_change_is_a_conservative_rename_hint() {
    let mut store = Store::new();
    let manifest = store.manifest(12, 1);
    let request = simple_request(
        &mut store,
        vec![EntrySpec::file("Readme.txt", file_id(1), manifest, 1)],
        vec![EntrySpec::file("README.txt", file_id(1), manifest, 1)],
        CaseMode::Sensitive,
    );
    let page = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].move_hint, MoveHint::Rename);
    assert_eq!(page.records[0].changes.bits(), ChangeFlags::PATH);
}

#[test]
fn configured_tree_and_diff_counts_accept_exact_maximum_and_reject_maximum_plus_one() {
    let mut store = Store::new();
    let manifest = store.manifest(11, 1);
    let request = simple_request(
        &mut store,
        vec![],
        vec![
            EntrySpec::file("a", file_id(1), manifest, 1),
            EntrySpec::file("b", file_id(2), manifest, 1),
        ],
        CaseMode::Sensitive,
    );
    let mut exact = Limits::default();
    exact.max_tree_entries = 2;
    exact.max_diff_records = 2;
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            exact,
            &OperationControl::default(),
            None,
        )
        .unwrap()
        .records
        .len(),
        2
    );

    let mut tree_plus_one = exact;
    tree_plus_one.max_tree_entries = 1;
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            tree_plus_one,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(ogvcs_history_diff_kernel::LimitKind::TreeEntries)
    );

    let mut diff_plus_one = exact;
    diff_plus_one.max_diff_records = 1;
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            diff_plus_one,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(ogvcs_history_diff_kernel::LimitKind::DiffRecords)
    );

    let mut nested_store = Store::new();
    let child = nested_store.tree(vec![]);
    let before_tree = nested_store.tree(vec![]);
    let after_tree = nested_store.tree(vec![EntrySpec::directory("directory", file_id(9), child)]);
    let nested_request = DiffRequest {
        before_snapshot: nested_store.snapshot(31, vec![], before_tree),
        after_snapshot: nested_store.snapshot(32, vec![], after_tree),
        repository_descriptor: nested_store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    let tree_object_exact = Limits {
        max_tree_objects: 2,
        ..Limits::default()
    };
    assert!(diff_page(
        &mut nested_store.source(),
        nested_request,
        tree_object_exact,
        &OperationControl::default(),
        None,
    )
    .is_ok());
    let tree_object_plus_one = Limits {
        max_tree_objects: 1,
        ..tree_object_exact
    };
    assert_eq!(
        diff_page(
            &mut nested_store.source(),
            nested_request,
            tree_object_plus_one,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(ogvcs_history_diff_kernel::LimitKind::TreeObjects)
    );
}

fn _assert_types(_: FileId, _: ObjectRef) {}
