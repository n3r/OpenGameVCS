#![allow(clippy::field_reassign_with_default)]

mod support;

use std::sync::{atomic::AtomicBool, Arc};

use ogvcs_history_diff_kernel::{
    diff_page, history_page, AmbiguousKind, CorruptKind, DiffRequest, FailureKind, HistoryRequest,
    LimitKind, Limits, OperationControl,
};
use ogvcs_path_contract::CaseMode;
use support::{file_id, EntrySpec, Store};

fn one_file_diff() -> (Store, DiffRequest, ogvcs_object_model::ObjectRef) {
    let mut store = Store::new();
    let manifest = store.manifest(4, 8);
    let before_tree = store.tree(vec![]);
    let after_tree = store.tree(vec![
        EntrySpec::file("asset.bin", file_id(1), manifest, 8),
        EntrySpec::file("sidecar.bin", file_id(2), manifest, 8),
    ]);
    let before = store.snapshot(1, vec![], before_tree);
    let after = store.snapshot(2, vec![], after_tree);
    let request = DiffRequest {
        before_snapshot: before,
        after_snapshot: after,
        repository_descriptor: store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    (store, request, manifest)
}

#[test]
fn missing_ambiguous_and_byte_limited_objects_are_distinct() {
    let (store, request, manifest) = one_file_diff();
    let mut missing = store.source();
    missing.objects.remove(&manifest);
    assert!(matches!(
        diff_page(
            &mut missing,
            request,
            Limits::default(),
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Missing(_)
    ));

    let mut ambiguous = store.source();
    ambiguous.ambiguous.insert(manifest);
    assert_eq!(
        diff_page(
            &mut ambiguous,
            request,
            Limits::default(),
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Ambiguous(AmbiguousKind::Source)
    );

    let mut limited = store.source();
    limited.byte_limited.insert(manifest);
    assert_eq!(
        diff_page(
            &mut limited,
            request,
            Limits::default(),
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::ObjectBytes)
    );
}

#[test]
fn corrupted_canonical_bytes_never_produce_a_partial_diff() {
    let (store, request, manifest) = one_file_diff();
    let mut source = store.source();
    let payload = source.objects.get_mut(&manifest).unwrap();
    let index = payload.len() / 2;
    payload[index] ^= 1;
    let error = diff_page(
        &mut source,
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        FailureKind::Corrupt(CorruptKind::ObjectIdentity)
    );
}

#[test]
fn generation_change_before_during_and_after_read_fails_closed() {
    let (store, request, _) = one_file_diff();
    for flip in [2, 4, 8, 15] {
        let mut source = store.source();
        source.flip_generation_on_call = Some(flip);
        let error = diff_page(
            &mut source,
            request,
            Limits::default(),
            &OperationControl::default(),
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind, FailureKind::GenerationChanged, "flip {flip}");
    }

    let mut source = store.source();
    source.object_generation = Some([0x73; 32]);
    let error = diff_page(
        &mut source,
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::GenerationChanged);
    assert_eq!(source.reads, 1);
}

#[test]
fn cancellation_is_terminal_and_emits_no_page_or_cursor() {
    let (store, request, _) = one_file_diff();
    let flag = Arc::new(AtomicBool::new(true));
    let control = OperationControl::with_cancellation(flag);
    let error = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &control,
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Cancelled);

    let mut failing_source = store.source();
    failing_source.fail_generation = true;
    let error = diff_page(
        &mut failing_source,
        request,
        Limits::default(),
        &control,
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Cancelled);
    assert_eq!(failing_source.generation_calls, 0);
}

#[test]
fn source_vec_capacity_above_contract_cap_is_rejected() {
    let (store, request, _) = one_file_diff();
    let mut source = store.source();
    source.spare_capacity.insert(store.descriptor);
    let mut limits = Limits::default();
    limits.max_object_bytes = 512;
    limits.max_cursor_bytes = 4_096;
    limits.max_charged_memory_bytes = 8_192;
    limits.max_decode_working_bytes = 512;
    let error = diff_page(
        &mut source,
        request,
        limits,
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::Limit(LimitKind::ObjectBytes));
}

#[test]
fn source_read_byte_entry_and_work_limits_have_typed_outcomes() {
    let (store, request, _) = one_file_diff();
    let mut reads = Limits::default();
    reads.max_source_reads = 2;
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            reads,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::SourceReads)
    );

    let mut bytes = Limits::default();
    bytes.max_source_bytes = 32;
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            bytes,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::SourceBytes)
    );

    let mut entries = Limits::default();
    entries.max_tree_entries = 1;
    let (mut many_store, _, _) = one_file_diff();
    let manifest = many_store.manifest(9, 1);
    let before_tree = many_store.tree(vec![]);
    let after_tree = many_store.tree(vec![
        EntrySpec::file("a", file_id(11), manifest, 1),
        EntrySpec::file("b", file_id(12), manifest, 1),
    ]);
    let before = many_store.snapshot(31, vec![], before_tree);
    let after = many_store.snapshot(32, vec![], after_tree);
    let many_request = DiffRequest {
        before_snapshot: before,
        after_snapshot: after,
        repository_descriptor: many_store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    assert_eq!(
        diff_page(
            &mut many_store.source(),
            many_request,
            entries,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::TreeEntries)
    );

    let mut work = Limits::default();
    work.max_work_units = 2;
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            work,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::WorkUnits)
    );
}

#[test]
fn source_object_byte_and_work_limits_accept_exact_maxima_and_reject_maximum_plus_one() {
    let (store, request, _) = one_file_diff();
    let baseline = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    let largest_object = store
        .objects
        .values()
        .map(Vec::len)
        .max()
        .unwrap_or_default() as u64;
    let exact = Limits {
        max_source_reads: baseline.ledger.source_reads,
        max_source_bytes: baseline.ledger.source_bytes,
        max_object_bytes: largest_object,
        max_work_units: baseline.ledger.work_units,
        ..Limits::default()
    };
    assert!(diff_page(
        &mut store.source(),
        request,
        exact,
        &OperationControl::default(),
        None,
    )
    .is_ok());

    for (changed, expected) in [
        (
            Limits {
                max_source_reads: exact.max_source_reads - 1,
                ..exact
            },
            LimitKind::SourceReads,
        ),
        (
            Limits {
                max_source_bytes: exact.max_source_bytes - 1,
                ..exact
            },
            LimitKind::SourceBytes,
        ),
        (
            Limits {
                max_object_bytes: exact.max_object_bytes - 1,
                ..exact
            },
            LimitKind::ObjectBytes,
        ),
        (
            Limits {
                max_work_units: exact.max_work_units - 1,
                ..exact
            },
            LimitKind::WorkUnits,
        ),
    ] {
        assert_eq!(
            diff_page(
                &mut store.source(),
                request,
                changed,
                &OperationControl::default(),
                None,
            )
            .unwrap_err()
            .kind,
            FailureKind::Limit(expected)
        );
    }

    let overflowed = Limits {
        max_object_bytes: u64::MAX,
        ..Limits::default()
    };
    let mut source = store.source();
    assert_eq!(
        diff_page(
            &mut source,
            request,
            overflowed,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::Configuration)
    );
    assert_eq!(source.generation_calls, 0);
}

#[test]
fn configured_decode_working_memory_has_an_exact_typed_boundary() {
    let (store, request, _) = one_file_diff();
    let mut lower = 1u64;
    let mut upper = 64 * 1024u64;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let limits = Limits {
            max_decode_working_bytes: middle,
            ..Limits::default()
        };
        match diff_page(
            &mut store.source(),
            request,
            limits,
            &OperationControl::default(),
            None,
        ) {
            Ok(_) => upper = middle,
            Err(error) => {
                assert_eq!(error.kind, FailureKind::Limit(LimitKind::ChargedMemory));
                lower = middle + 1;
            }
        }
    }

    let exact = Limits {
        max_decode_working_bytes: lower,
        ..Limits::default()
    };
    assert!(diff_page(
        &mut store.source(),
        request,
        exact,
        &OperationControl::default(),
        None,
    )
    .is_ok());
    assert!(lower > 1);
    let below = Limits {
        max_decode_working_bytes: lower - 1,
        ..exact
    };
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            below,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::ChargedMemory)
    );
}

#[test]
fn charged_memory_ceiling_accepts_the_exact_admission_peak_and_rejects_one_less() {
    let mut store = Store::new();
    let manifest = store.manifest(18, 1);
    let before_tree = store.tree(vec![]);
    let after_tree = store.tree(
        (0u128..64)
            .map(|index| {
                EntrySpec::file(
                    &format!("file-{index:03}.bin"),
                    file_id(index + 1),
                    manifest,
                    1,
                )
            })
            .collect(),
    );
    let request = DiffRequest {
        before_snapshot: store.snapshot(1, vec![], before_tree),
        after_snapshot: store.snapshot(2, vec![], after_tree),
        repository_descriptor: store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    let largest_object = store
        .objects
        .values()
        .map(Vec::len)
        .max()
        .unwrap_or_default() as u64;
    let template = Limits {
        max_object_bytes: largest_object,
        max_cursor_bytes: 256,
        ..Limits::default()
    };
    let minimum_configuration = largest_object * 2 + template.max_decode_working_bytes + 4_096;
    let mut lower = minimum_configuration;
    let mut upper = 64 * 1024 * 1024;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        let limits = Limits {
            max_charged_memory_bytes: middle,
            ..template
        };
        match diff_page(
            &mut store.source(),
            request,
            limits,
            &OperationControl::default(),
            None,
        ) {
            Ok(_) => upper = middle,
            Err(error) => {
                assert_eq!(error.kind, FailureKind::Limit(LimitKind::ChargedMemory));
                lower = middle + 1;
            }
        }
    }
    assert!(lower > minimum_configuration);
    let exact = Limits {
        max_charged_memory_bytes: lower,
        ..template
    };
    assert!(diff_page(
        &mut store.source(),
        request,
        exact,
        &OperationControl::default(),
        None,
    )
    .is_ok());
    let below = Limits {
        max_charged_memory_bytes: lower - 1,
        ..exact
    };
    assert_eq!(
        diff_page(
            &mut store.source(),
            request,
            below,
            &OperationControl::default(),
            None,
        )
        .unwrap_err()
        .kind,
        FailureKind::Limit(LimitKind::ChargedMemory)
    );
}

#[test]
fn exact_empty_diff_ledger_counts_every_generation_and_object_read() {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let snapshot = store.snapshot(1, vec![], tree);
    let request = DiffRequest {
        before_snapshot: snapshot,
        after_snapshot: snapshot,
        repository_descriptor: store.descriptor,
        case_mode: CaseMode::Sensitive,
    };
    let page = diff_page(
        &mut store.source(),
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert_eq!(page.ledger.source_reads, 5);
    assert_eq!(page.ledger.metadata_objects, 5);
    assert_eq!(page.ledger.generation_checks, 13);
    assert_eq!(page.ledger.tree_entries, 0);
    assert_eq!(page.ledger.emitted_records, 0);
}

#[test]
fn resumed_cursor_rechecks_generation_before_releasing_records() {
    let (store, request, _) = one_file_diff();
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
    let mut changed = store.source();
    changed.generation = [0x91; 32];
    let error = diff_page(
        &mut changed,
        request,
        limits,
        &OperationControl::default(),
        Some(&cursor),
    )
    .unwrap_err();
    assert_eq!(error.kind, FailureKind::GenerationChanged);
}

#[test]
fn wrong_repository_descriptor_snapshot_is_corrupt_not_empty() {
    let (mut store, request, _) = one_file_diff();
    let mut foreign = Store::with_repository_tag(0x55);
    let foreign_tree = foreign.tree(vec![]);
    let foreign_snapshot = foreign.snapshot(8, vec![], foreign_tree);
    store.objects.extend(foreign.objects);
    let request = DiffRequest {
        after_snapshot: foreign_snapshot,
        ..request
    };
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
        FailureKind::Corrupt(CorruptKind::RepositoryDescriptor)
    );
}

#[test]
fn history_missing_parent_is_not_treated_as_truncated_success() {
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
    source.objects.remove(&root);
    let error = history_page(
        &mut source,
        request,
        Limits::default(),
        &OperationControl::default(),
        None,
    )
    .unwrap_err();
    assert!(matches!(error.kind, FailureKind::Missing(_)));
}

#[test]
fn semantic_one_node_limits_do_not_redefine_cbor_container_shape() {
    let mut store = Store::new();
    let tree = store.tree(vec![]);
    let snapshot = store.snapshot(1, vec![], tree);
    let mut limits = Limits::default();
    limits.max_history_snapshots = 1;
    limits.max_tree_objects = 1;
    limits.max_tree_entries = 1;
    let history = history_page(
        &mut store.source(),
        HistoryRequest {
            start_snapshot: snapshot,
            repository_descriptor: store.descriptor,
            designated_root: snapshot,
        },
        limits,
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert!(history.complete);
    assert_eq!(history.records.len(), 1);

    let diff = diff_page(
        &mut store.source(),
        DiffRequest {
            before_snapshot: snapshot,
            after_snapshot: snapshot,
            repository_descriptor: store.descriptor,
            case_mode: CaseMode::Sensitive,
        },
        limits,
        &OperationControl::default(),
        None,
    )
    .unwrap();
    assert!(diff.complete);
    assert!(diff.records.is_empty());
}
