mod support;

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ogvcs_git_import_preflight::*;
use support::*;

fn error_code(
    records: Vec<ImportRecord>,
    objects: BTreeMap<LfsObjectId, Vec<u8>>,
    limits: ImportLimits,
) -> ImportPreflightErrorCode {
    run_fixture(records, objects, &policy(), limits)
        .unwrap_err()
        .code()
}

fn assert_expected_rejected_before_source(expected: ExpectedInventory, limits: ImportLimits) {
    let (records, objects) = ready_fixture();
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            limits,
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
    assert_eq!(inventory.calls(), 0);
    assert_eq!(lfs.reads.get(), 0);
    assert_eq!(authority.calls.get(), 0);
    assert_eq!(authority.generation_calls.get(), 0);
}

#[test]
fn ready_inventory_is_verified_and_composes_ogvcs_002_mapping() {
    let (records, objects) = ready_fixture();
    let report = run_fixture(records, objects, &policy(), ImportLimits::default()).unwrap();
    assert!(report.ready);
    assert_eq!(report.counts.items, 5);
    assert_eq!(report.counts.lfs_pointers, 1);
    assert_eq!(report.counts.lfs_objects, 1);
    assert_eq!(report.lfs_bytes_verified, 6);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].logical_bytes, 6);
    assert!(report.entries[0].lfs_object.is_some());
    assert_eq!(report.mappings.len(), 1);
    assert_eq!(
        report.mappings[0].mapping.file_id,
        FileId::new([0x61; 16]).unwrap()
    );
    assert_eq!(report.mappings[0].mapping.state, ImportState::Reserved);
    assert!(report.findings.is_empty());
    assert_eq!(report.source_generation, SOURCE_GENERATION);
    assert_eq!(report.lfs_generation, LFS_GENERATION);
    assert_eq!(report.mapping_generation, MAPPING_GENERATION);
}

#[test]
fn exact_duplicate_target_path_is_a_collision_even_when_path_digests_match() {
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "same/path".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(2),
            path: "same/path".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"y".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "same/path"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(2), "same/path"),
            request: mapping_request(0x52, 0x62),
        },
    ];
    let report = run_fixture(records, BTreeMap::new(), &policy(), ImportLimits::default()).unwrap();
    assert!(!report.ready);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::RepositoryPathCollision));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.kind == FindingKind::PlatformPathCollision));
}

#[test]
fn declared_item_max_plus_one_fails_during_pre_admission() {
    let (records, objects) = ready_fixture();
    let mut exact = ImportLimits {
        items_maximum: 5,
        ..ImportLimits::default()
    };
    assert!(run_fixture(records.clone(), objects.clone(), &policy(), exact).is_ok());
    exact.items_maximum = 4;
    assert_eq!(
        error_code(records, objects, exact),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
}

#[test]
fn relationship_and_git_byte_limits_are_exact() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut exact = ImportLimits {
        relationships_maximum: expected.counts.relationships,
        git_bytes_maximum: expected.git_bytes,
        ..ImportLimits::default()
    };
    assert!(run_fixture(records.clone(), objects.clone(), &policy(), exact).is_ok());
    exact.relationships_maximum = 0;
    assert_eq!(
        error_code(records.clone(), objects.clone(), exact),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
    exact.relationships_maximum = expected.counts.relationships;
    exact.git_bytes_maximum = expected.git_bytes - 1;
    assert_eq!(
        error_code(records, objects, exact),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
}

#[test]
fn lfs_size_and_cumulative_limits_are_exact() {
    let (records, objects) = ready_fixture();
    let mut exact = ImportLimits {
        lfs_object_bytes_maximum: 6,
        lfs_bytes_maximum: 6,
        ..ImportLimits::default()
    };
    assert!(run_fixture(records.clone(), objects.clone(), &policy(), exact).is_ok());
    exact.lfs_objects_maximum = 0;
    assert_eq!(
        error_code(records.clone(), objects.clone(), exact),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
    exact.lfs_objects_maximum = 1;
    exact.lfs_object_bytes_maximum = 5;
    assert_eq!(
        error_code(records.clone(), objects.clone(), exact),
        ImportPreflightErrorCode::LimitLfsObjectBytes
    );
    exact.lfs_object_bytes_maximum = 6;
    exact.lfs_bytes_maximum = 5;
    assert_eq!(
        error_code(records, objects, exact),
        ImportPreflightErrorCode::LimitLfsBytes
    );
}

#[test]
fn input_mapping_and_work_limits_fail_closed() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut limits = ImportLimits {
        input_bytes_maximum: expected.input_bytes,
        mappings_maximum: 1,
        ..ImportLimits::default()
    };
    let exact_report = run_fixture(records.clone(), objects.clone(), &policy(), limits).unwrap();
    limits.input_bytes_maximum = expected.input_bytes - 1;
    assert_eq!(
        error_code(records.clone(), objects.clone(), limits),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
    limits.mappings_maximum = 0;
    limits.input_bytes_maximum = expected.input_bytes;
    assert_eq!(
        error_code(records.clone(), objects.clone(), limits),
        ImportPreflightErrorCode::ExpectedInventoryInvalid
    );
    limits.mappings_maximum = 1;
    limits.work_units_maximum = exact_report.work_units;
    assert!(run_fixture(records.clone(), objects.clone(), &policy(), limits).is_ok());
    limits.work_units_maximum = exact_report.work_units - 1;
    assert_eq!(
        error_code(records, objects, limits),
        ImportPreflightErrorCode::LimitWork
    );
}

#[test]
fn unordered_and_duplicate_records_are_distinct_errors() {
    let (mut records, objects) = ready_fixture();
    records.swap(0, 1);
    assert_eq!(
        error_code(records, objects.clone(), ImportLimits::default()),
        ImportPreflightErrorCode::InventoryUnordered
    );
    let duplicate = vec![
        ImportRecord::Ref {
            name: "refs/heads/main".to_owned(),
            target: sha1(1),
        },
        ImportRecord::Ref {
            name: "refs/heads/main".to_owned(),
            target: sha1(1),
        },
    ];
    assert_eq!(
        error_code(duplicate, objects, ImportLimits::default()),
        ImportPreflightErrorCode::InventoryDuplicate
    );
}

#[test]
fn invalid_ref_and_probe_contract_are_rejected() {
    let invalid_ref = vec![ImportRecord::Ref {
        name: "main".to_owned(),
        target: sha1(1),
    }];
    assert_eq!(
        error_code(invalid_ref, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::SourceContractViolation
    );
    let invalid_probe = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "a".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 2,
            pointer_probe: vec![b'x'],
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "a"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    assert_eq!(
        error_code(invalid_probe, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::SourceContractViolation
    );

    let lock_ref = vec![ImportRecord::Ref {
        name: "refs/heads/main.lock".to_owned(),
        target: sha1(1),
    }];
    assert_eq!(
        error_code(lock_ref, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::SourceContractViolation
    );
}

#[test]
fn required_lfs_never_substitutes_ordinary_blob() {
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "asset.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 8,
            pointer_probe: b"ordinary".to_vec(),
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "asset.bin"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    assert_eq!(
        error_code(records, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::PointerRequired
    );
}

#[test]
fn required_empty_file_uses_the_official_pass_through_rule() {
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "empty.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 0,
            pointer_probe: Vec::new(),
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "empty.bin"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let report = run_fixture(records, BTreeMap::new(), &policy(), ImportLimits::default()).unwrap();
    assert!(report.ready);
    assert_eq!(report.counts.lfs_pointers, 0);
    assert_eq!(report.counts.lfs_objects, 0);
    assert_eq!(report.entries[0].logical_bytes, 0);
    assert_eq!(report.entries[0].lfs_object, None);
}

#[test]
fn canonical_pointer_text_at_an_ordinary_regular_path_is_preserved() {
    let pointer = canonical_pointer(b"deliberate pointer-looking text");
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "notes/pointer.txt".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer.clone(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "notes/pointer.txt"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let report = run_fixture(records, BTreeMap::new(), &policy(), ImportLimits::default()).unwrap();
    assert!(report.ready);
    assert_eq!(report.counts.lfs_pointers, 0);
    assert_eq!(report.counts.lfs_objects, 0);
    assert_eq!(report.lfs_bytes_verified, 0);
    assert_eq!(report.entries[0].logical_bytes, pointer.len() as u64);
    assert_eq!(report.entries[0].lfs_object, None);
}

#[test]
fn symlink_target_bytes_bypass_lfs_and_reject_a_tracked_disposition() {
    let pointer = canonical_pointer(b"not the symlink target");
    let ordinary = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "link".to_owned(),
            mode: GitEntryMode::Symlink,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer.clone(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "link"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let mut symlink_policy = policy();
    symlink_policy.permit_symlink_inventory = true;
    let report = run_fixture(
        ordinary,
        BTreeMap::new(),
        &symlink_policy,
        ImportLimits::default(),
    )
    .unwrap();
    assert!(report.ready);
    assert_eq!(report.counts.lfs_pointers, 0);
    assert_eq!(report.entries[0].logical_bytes, pointer.len() as u64);
    assert_eq!(report.entries[0].lfs_object, None);

    let invalid = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "link".to_owned(),
            mode: GitEntryMode::Symlink,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer,
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "link"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    assert_eq!(
        error_code(invalid, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::SourceContractViolation
    );
}

#[test]
fn one_blob_can_be_ordinary_at_one_path_and_lfs_tracked_at_another() {
    let content = b"external payload".to_vec();
    let pointer = canonical_pointer(&content);
    let parsed = match classify_lfs_pointer(&pointer).unwrap() {
        PointerClassification::Canonical(pointer) => pointer,
        PointerClassification::NotPointer => unreachable!(),
    };
    let mut records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "ordinary.ptr".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer.clone(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(1),
            path: "tracked.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer.clone(),
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "ordinary.ptr"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "tracked.bin"),
            request: mapping_request(0x52, 0x62),
        },
    ];
    records.sort_by_key(ImportRecord::key);
    let report = run_fixture(
        records,
        BTreeMap::from([(parsed.oid, content.clone())]),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();
    assert!(report.ready);
    assert_eq!(report.counts.blobs, 1);
    assert_eq!(report.counts.blob_occurrences, 2);
    assert_eq!(report.counts.lfs_pointers, 1);
    assert_eq!(report.counts.lfs_objects, 1);
    assert_eq!(report.git_bytes, pointer.len() as u64);
    assert_eq!(report.entries[0].logical_bytes, pointer.len() as u64);
    assert_eq!(report.entries[0].lfs_object, None);
    assert_eq!(report.entries[1].logical_bytes, content.len() as u64);
    assert_eq!(report.entries[1].lfs_object, Some(parsed.oid));
    assert_ne!(
        report.mappings[0].mapping.file_id,
        report.mappings[1].mapping.file_id
    );
}

#[test]
fn malformed_advertised_pointer_never_becomes_ordinary_blob() {
    let pointer = b"version https://git-lfs.github.com/spec/v1\nsize 1\n".to_vec();
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "asset.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer,
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "asset.bin"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    assert_eq!(
        error_code(records, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::PointerMalformed
    );
}

#[test]
fn oversized_blob_uses_empty_probe_and_is_never_treated_as_a_pointer() {
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "asset.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1_024,
            pointer_probe: Vec::new(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "asset.bin"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let report = run_fixture(records, BTreeMap::new(), &policy(), ImportLimits::default()).unwrap();
    assert_eq!(report.counts.lfs_pointers, 0);
    assert_eq!(report.entries[0].logical_bytes, 1_024);
}

#[test]
fn missing_ambiguous_short_extra_and_corrupt_lfs_are_distinct() {
    let (records, objects) = ready_fixture();
    assert_eq!(
        error_code(records.clone(), BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::LfsObjectMissing
    );

    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    lfs.ambiguous = true;
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default()
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::LfsObjectAmbiguous
    );

    let oid = *objects.keys().next().unwrap();
    let short = BTreeMap::from([(oid, b"hello".to_vec())]);
    assert_eq!(
        error_code(records.clone(), short, ImportLimits::default()),
        ImportPreflightErrorCode::LfsObjectSizeMismatch
    );
    let extra = BTreeMap::from([(oid, b"hello\n!".to_vec())]);
    assert_eq!(
        error_code(records.clone(), extra, ImportLimits::default()),
        ImportPreflightErrorCode::LfsObjectSizeMismatch
    );
    let corrupt = BTreeMap::from([(oid, b"jello\n".to_vec())]);
    assert_eq!(
        error_code(records, corrupt, ImportLimits::default()),
        ImportPreflightErrorCode::LfsObjectDigestMismatch
    );
}

#[test]
fn lfs_source_overreport_and_failure_are_contract_errors() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    lfs.overreport = true;
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default()
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceContractViolation
    );

    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    lfs.fail_at_read = Some(1);
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default()
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceFailure
    );
}

#[test]
fn shared_lfs_object_is_streamed_once_and_pointer_count_remains_two() {
    let (mut records, objects) = ready_fixture();
    let first_blob = records[3].clone();
    let ImportRecord::Entry { pointer_probe, .. } = first_blob else {
        unreachable!()
    };
    records.insert(
        4,
        ImportRecord::Entry {
            id: sha1(4),
            path: "Assets/copy.txt".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer_probe.len() as u64,
            pointer_probe,
            lfs: LfsDisposition::Required,
        },
    );
    records.push(ImportRecord::Mapping {
        occurrence: occurrence(sha1(4), "Assets/copy.txt"),
        request: mapping_request(0x52, 0x62),
    });
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    let report = preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        &policy(),
        ImportLimits::default(),
        expected,
        &OperationControl::default(),
    )
    .unwrap();
    assert_eq!(report.counts.lfs_pointers, 2);
    assert_eq!(report.counts.lfs_objects, 1);
    assert_eq!(lfs.reads.get(), 2);
}

#[test]
fn shared_lfs_oid_with_conflicting_declared_sizes_fails_closed() {
    let content = b"hello\n".to_vec();
    let oid = digest(&content);
    let first = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 6\n",
        hex(&oid)
    )
    .into_bytes();
    let second = format!(
        "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 7\n",
        hex(&oid)
    )
    .into_bytes();
    let lfs_oid = LfsObjectId::from_bytes(oid);
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "one".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: first.len() as u64,
            pointer_probe: first,
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Entry {
            id: sha1(2),
            path: "two".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: second.len() as u64,
            pointer_probe: second,
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(2), "two"),
            request: mapping_request(0x52, 0x62),
        },
    ];
    assert_eq!(
        error_code(
            records,
            BTreeMap::from([(lfs_oid, content)]),
            ImportLimits::default(),
        ),
        ImportPreflightErrorCode::LfsPointerConflict
    );
}

#[test]
fn path_mode_and_extension_policy_produce_bounded_blockers() {
    let content = b"encrypted".to_vec();
    let pointer = extension_pointer(&content);
    let parsed = match classify_lfs_pointer(&pointer).unwrap() {
        PointerClassification::Canonical(pointer) => pointer,
        PointerClassification::NotPointer => unreachable!(),
    };
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "Assets/Foo.txt".to_owned(),
            mode: GitEntryMode::Executable,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(2),
            path: "assets/foo.txt".to_owned(),
            mode: GitEntryMode::Symlink,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(3),
            path: "Cafe\u{301}/bad".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer,
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Entry {
            id: sha1(4),
            path: "vendor/submodule".to_owned(),
            mode: GitEntryMode::Submodule,
            encoded_bytes: 0,
            pointer_probe: Vec::new(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "Assets/Foo.txt"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(2), "assets/foo.txt"),
            request: mapping_request(0x52, 0x62),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(3), "Cafe\u{301}/bad"),
            request: mapping_request(0x53, 0x63),
        },
    ];
    let objects = BTreeMap::from([(parsed.oid, content)]);
    let report = run_fixture(records, objects, &policy(), ImportLimits::default()).unwrap();
    assert!(!report.ready);
    let kinds: Vec<_> = report.findings.iter().map(|finding| finding.kind).collect();
    assert!(kinds.contains(&FindingKind::ExecutableBlocked));
    assert!(kinds.contains(&FindingKind::SymlinkBlocked));
    assert!(kinds.contains(&FindingKind::SubmoduleBlocked));
    assert!(kinds.contains(&FindingKind::PathInvalid));
    assert!(kinds.contains(&FindingKind::RepositoryPathCollision));
    assert!(kinds.contains(&FindingKind::PlatformPathCollision));
    assert!(kinds.contains(&FindingKind::LfsExtensionBlocked));
}

#[test]
fn finding_limit_is_checked_before_retaining_max_plus_one() {
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "Cafe\u{301}/bad".to_owned(),
            mode: GitEntryMode::Executable,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "Cafe\u{301}/bad"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let baseline = run_fixture(
        records.clone(),
        BTreeMap::new(),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();
    let mut limits = ImportLimits {
        findings_maximum: baseline.findings.len() as u64,
        ..ImportLimits::default()
    };
    assert!(run_fixture(records.clone(), BTreeMap::new(), &policy(), limits).is_ok());
    limits.findings_maximum -= 1;
    assert_eq!(
        error_code(records, BTreeMap::new(), limits),
        ImportPreflightErrorCode::LimitFindings
    );
}

#[test]
fn source_and_all_three_generation_drifts_fail_closed() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone()).drift_after(1);
    let mut lfs = MapLfs::new(objects.clone());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default()
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceGenerationChanged
    );

    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    lfs.drift_after_read = Some(1);
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default()
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceGenerationChanged
    );

    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    authority.drift_after_decision = true;
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default()
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceGenerationChanged
    );
}

#[test]
fn cancellation_precedes_source_access() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records).fail_at(1);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    let flag = Arc::new(AtomicBool::new(true));
    let control = OperationControl::with_cancellation(flag);
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &control
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::Cancelled
    );
}

#[test]
fn invalid_limits_precede_cancellation_and_external_calls() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records).fail_at(1);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    let control = OperationControl::with_cancellation(Arc::new(AtomicBool::new(true)));
    let limits = ImportLimits {
        read_chunk_bytes: 0,
        ..ImportLimits::default()
    };
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            limits,
            expected,
            &control
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::LimitsInvalid
    );
}

#[test]
fn mapping_authority_failure_key_forgery_and_new_id_substitution_are_rejected() {
    let (records, objects) = ready_fixture();
    for scenario in 0..3 {
        let expected = expectation(&records);
        let mut inventory = VecInventory::new(records.clone());
        let mut lfs = MapLfs::new(objects.clone());
        let mut authority = Authority::new(&policy());
        let expected_code = match scenario {
            0 => {
                authority.fail = true;
                ImportPreflightErrorCode::MappingAuthorityFailure
            }
            1 => {
                authority.corrupt_key = true;
                ImportPreflightErrorCode::MappingKeyMismatch
            }
            _ => {
                authority.replacement_file_id = Some(FileId::new([0x71; 16]).unwrap());
                ImportPreflightErrorCode::MappingDecisionMismatch
            }
        };
        assert_eq!(
            preflight_git_import(
                &mut inventory,
                &mut lfs,
                &mut authority,
                &policy(),
                ImportLimits::default(),
                expected,
                &OperationControl::default()
            )
            .unwrap_err()
            .code(),
            expected_code
        );
    }
}

#[test]
fn retry_requires_the_requested_file_id_but_may_reuse_an_advanced_state() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    let mut authority = Authority::new(&policy());
    authority.retry = true;
    authority.state = ImportState::Published;
    let report = preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        &policy(),
        ImportLimits::default(),
        expected,
        &OperationControl::default(),
    )
    .unwrap();
    assert!(report.mappings[0].retry);
    assert_eq!(report.mappings[0].mapping.state, ImportState::Published);
    assert_eq!(
        report.mappings[0].mapping.file_id,
        FileId::new([0x61; 16]).unwrap()
    );

    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    authority.retry = true;
    authority.replacement_file_id = Some(FileId::new([0x71; 16]).unwrap());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::MappingDecisionMismatch
    );
}

#[test]
fn non_retry_decision_cannot_claim_materialized_or_published_state() {
    for state in [ImportState::Materialized, ImportState::Published] {
        let (records, objects) = ready_fixture();
        let expected = expectation(&records);
        let mut inventory = VecInventory::new(records);
        let mut lfs = MapLfs::new(objects);
        let mut authority = Authority::new(&policy());
        authority.state = state;
        assert_eq!(
            preflight_git_import(
                &mut inventory,
                &mut lfs,
                &mut authority,
                &policy(),
                ImportLimits::default(),
                expected,
                &OperationControl::default(),
            )
            .unwrap_err()
            .code(),
            ImportPreflightErrorCode::MappingDecisionMismatch
        );
    }
}

#[test]
fn duplicate_source_identity_and_file_id_alias_are_rejected() {
    let duplicate_source = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "one".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(2),
            path: "two".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"y".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(2), "two"),
            request: mapping_request(0x51, 0x62),
        },
    ];
    assert_eq!(
        error_code(duplicate_source, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::MappingSourceDuplicate
    );
    let alias = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "one".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(2),
            path: "two".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"y".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(2), "two"),
            request: mapping_request(0x52, 0x61),
        },
    ];
    assert_eq!(
        error_code(alias, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::MappingFileIdConflict
    );
}

#[test]
fn mapping_must_reference_an_inventoried_blob_and_every_blob_is_reconciled() {
    let entry = ImportRecord::Entry {
        id: sha1(1),
        path: "one".to_owned(),
        mode: GitEntryMode::Regular,
        encoded_bytes: 1,
        pointer_probe: b"x".to_vec(),
        lfs: LfsDisposition::Ordinary,
    };
    let mapping = ImportRecord::Mapping {
        occurrence: occurrence(sha1(1), "one"),
        request: mapping_request(0x51, 0x61),
    };
    let expected = expectation(&[entry.clone(), mapping.clone()]);
    let mut inventory = VecInventory::new(vec![mapping]);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::MappingSourceMissing
    );

    let expected = expectation(&[
        entry.clone(),
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
    ]);
    let mut inventory = VecInventory::new(vec![entry]);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::ReconciliationMismatch
    );
}

#[test]
fn missing_mapping_finding_limit_precedes_temporary_retention() {
    let entries = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "one".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(2),
            path: "two".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"y".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
    ];
    let complete = vec![
        entries[0].clone(),
        entries[1].clone(),
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(2), "two"),
            request: mapping_request(0x52, 0x62),
        },
    ];
    for findings_maximum in [0, 1] {
        let expected = expectation(&complete);
        let mut inventory = VecInventory::new(entries.clone());
        let mut lfs = MapLfs::new(BTreeMap::new());
        let mut authority = Authority::new(&policy());
        let limits = ImportLimits {
            findings_maximum,
            ..ImportLimits::default()
        };
        assert_eq!(
            preflight_git_import(
                &mut inventory,
                &mut lfs,
                &mut authority,
                &policy(),
                limits,
                expected,
                &OperationControl::default(),
            )
            .unwrap_err()
            .code(),
            ImportPreflightErrorCode::LimitFindings
        );
    }
}

#[test]
fn policy_profile_and_namespace_bind_every_mapping_request() {
    let mut wrong_profile = mapping_request(0x51, 0x61);
    wrong_profile.importer_profile = ProfileRef::new("importer.test", "other", 1).unwrap();
    let entry = ImportRecord::Entry {
        id: sha1(1),
        path: "one".to_owned(),
        mode: GitEntryMode::Regular,
        encoded_bytes: 1,
        pointer_probe: b"x".to_vec(),
        lfs: LfsDisposition::Ordinary,
    };
    let records = vec![
        entry.clone(),
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: wrong_profile,
        },
    ];
    assert_eq!(
        error_code(records, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::MappingDecisionMismatch
    );
    let mut wrong_namespace = mapping_request(0x51, 0x61);
    wrong_namespace.source_namespace_digest = [0xff; 32];
    let records = vec![
        entry,
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: wrong_namespace,
        },
    ];
    assert_eq!(
        error_code(records, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::MappingDecisionMismatch
    );
}

#[test]
fn every_reconciliation_field_is_bound() {
    let (records, objects) = ready_fixture();
    let baseline = expectation(&records);
    for scenario in 0..4 {
        let mut expected = baseline;
        match scenario {
            0 => {
                expected.counts.items += 1;
                expected.counts.refs += 1;
            }
            1 => expected.git_bytes += 1,
            2 => expected.input_bytes += 1,
            _ => expected.inventory_digest[0] ^= 0xff,
        }
        let mut inventory = VecInventory::new(records.clone());
        let mut lfs = MapLfs::new(objects.clone());
        let mut authority = Authority::new(&policy());
        assert_eq!(
            preflight_git_import(
                &mut inventory,
                &mut lfs,
                &mut authority,
                &policy(),
                ImportLimits::default(),
                expected,
                &OperationControl::default()
            )
            .unwrap_err()
            .code(),
            ImportPreflightErrorCode::ReconciliationMismatch
        );
    }
}

#[test]
fn report_digest_binds_every_configured_limit() {
    let (records, objects) = ready_fixture();
    let baseline = run_fixture(
        records.clone(),
        objects.clone(),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();
    for scenario in 0..14 {
        let mut limits = ImportLimits::default();
        match scenario {
            0 => limits.items_maximum += 1,
            1 => limits.relationships_maximum += 1,
            2 => limits.git_bytes_maximum += 1,
            3 => limits.input_bytes_maximum += 1,
            4 => limits.lfs_objects_maximum += 1,
            5 => limits.lfs_object_bytes_maximum += 1,
            6 => limits.lfs_bytes_maximum += 1,
            7 => limits.mappings_maximum += 1,
            8 => limits.findings_maximum += 1,
            9 => limits.work_units_maximum += 1,
            10 => limits.retained_bytes_maximum += 1,
            11 => limits.path_bytes_maximum += 1,
            12 => limits.ref_name_bytes_maximum -= 1,
            _ => limits.read_chunk_bytes -= 1,
        }
        let changed = run_fixture(records.clone(), objects.clone(), &policy(), limits).unwrap();
        assert_ne!(
            baseline.report_digest, changed.report_digest,
            "scenario {scenario}"
        );
    }
}

#[test]
fn report_digest_independently_binds_measured_work_and_peak_retention() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    let mut authority = Authority::new(&policy());
    let baseline = preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        &policy(),
        ImportLimits::default(),
        expected,
        &OperationControl::default(),
    )
    .unwrap();

    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    lfs.maximum_read_bytes = Some(1);
    let mut authority = Authority::new(&policy());
    let more_work = preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        &policy(),
        ImportLimits::default(),
        expected,
        &OperationControl::default(),
    )
    .unwrap();
    assert_eq!(baseline.inventory_digest, more_work.inventory_digest);
    assert_eq!(baseline.mapping_digest, more_work.mapping_digest);
    assert_eq!(baseline.peak_retained_bytes, more_work.peak_retained_bytes);
    assert_ne!(baseline.work_units, more_work.work_units);
    assert_ne!(baseline.report_digest, more_work.report_digest);

    let mut retained_records = records;
    let ImportRecord::Ref { name, .. } = &mut retained_records[0] else {
        unreachable!();
    };
    let mut retained_name = String::with_capacity(REF_NAME_BYTES_HARD_MAXIMUM);
    retained_name.push_str(name);
    *name = retained_name;
    let retained = run_fixture(
        retained_records,
        objects,
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();
    assert_eq!(baseline.inventory_digest, retained.inventory_digest);
    assert_eq!(baseline.mapping_digest, retained.mapping_digest);
    assert_eq!(baseline.work_units, retained.work_units);
    assert_ne!(baseline.peak_retained_bytes, retained.peak_retained_bytes);
    assert_ne!(baseline.report_digest, retained.report_digest);
}

#[test]
fn report_digest_binds_all_three_generations() {
    let (records, objects) = ready_fixture();
    let first = run_fixture(
        records.clone(),
        objects.clone(),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();
    let generation = [0xa5; 32];
    let mut expected = expectation(&records);
    expected.source_generation = generation;
    expected.lfs_generation = generation;
    expected.mapping_generation = generation;
    let mut inventory = VecInventory::new(records).with_generation(generation);
    let mut lfs = MapLfs::new(objects);
    lfs.generation = generation;
    let mut authority = Authority::new(&policy());
    authority.generation = generation;
    let second = preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        &policy(),
        ImportLimits::default(),
        expected,
        &OperationControl::default(),
    )
    .unwrap();
    assert_ne!(first.report_digest, second.report_digest);
    assert_eq!(second.source_generation, generation);
    assert_eq!(second.lfs_generation, generation);
    assert_eq!(second.mapping_generation, generation);
}

#[test]
fn reused_blob_object_has_two_path_bound_mappings_and_is_charged_once() {
    let content = b"shared\n".to_vec();
    let pointer = canonical_pointer(&content);
    let lfs_oid = match classify_lfs_pointer(&pointer).unwrap() {
        PointerClassification::Canonical(pointer) => pointer.oid,
        PointerClassification::NotPointer => unreachable!(),
    };
    let mut records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "Assets/one.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer.clone(),
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Entry {
            id: sha1(1),
            path: "Assets/two.bin".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: pointer.len() as u64,
            pointer_probe: pointer.clone(),
            lfs: LfsDisposition::Required,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "Assets/one.bin"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "Assets/two.bin"),
            request: mapping_request(0x52, 0x62),
        },
    ];
    records.sort_by_key(ImportRecord::key);
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(BTreeMap::from([(lfs_oid, content)]));
    let mut authority = Authority::new(&policy());
    let report = preflight_git_import(
        &mut inventory,
        &mut lfs,
        &mut authority,
        &policy(),
        ImportLimits::default(),
        expected,
        &OperationControl::default(),
    )
    .unwrap();
    assert_eq!(report.counts.entries, 2);
    assert_eq!(report.counts.blob_occurrences, 2);
    assert_eq!(report.counts.blobs, 1);
    assert_eq!(report.counts.lfs_pointers, 1);
    assert_eq!(report.counts.lfs_objects, 1);
    assert_eq!(report.counts.mappings, 2);
    assert_eq!(report.git_bytes, pointer.len() as u64);
    assert_eq!(report.entries.len(), 2);
    assert_eq!(report.mappings.len(), 2);
    assert_ne!(
        report.mappings[0].mapping.file_id,
        report.mappings[1].mapping.file_id
    );
    assert_ne!(
        report.mappings[0].occurrence.path_digest(),
        report.mappings[1].occurrence.path_digest()
    );
    assert_eq!(lfs.reads.get(), 2);
}

#[test]
fn repeated_blob_object_metadata_must_be_identical() {
    let mut records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "one".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Entry {
            id: sha1(1),
            path: "two".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"y".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "two"),
            request: mapping_request(0x52, 0x62),
        },
    ];
    records.sort_by_key(ImportRecord::key);
    assert_eq!(
        error_code(records, BTreeMap::new(), ImportLimits::default()),
        ImportPreflightErrorCode::BlobObjectConflict
    );
}

#[test]
fn duplicate_and_extra_occurrence_mappings_fail_closed() {
    let entry = ImportRecord::Entry {
        id: sha1(1),
        path: "one".to_owned(),
        mode: GitEntryMode::Regular,
        encoded_bytes: 1,
        pointer_probe: b"x".to_vec(),
        lfs: LfsDisposition::Ordinary,
    };
    let mapping = ImportRecord::Mapping {
        occurrence: occurrence(sha1(1), "one"),
        request: mapping_request(0x51, 0x61),
    };
    let expected = expectation(&[entry.clone(), mapping.clone()]);
    let mut duplicate = vec![entry.clone(), mapping.clone(), mapping];
    duplicate.sort_by_key(ImportRecord::key);
    let mut inventory = VecInventory::new(duplicate);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::InventoryDuplicate
    );

    let valid_mapping = ImportRecord::Mapping {
        occurrence: occurrence(sha1(1), "one"),
        request: mapping_request(0x51, 0x61),
    };
    let expected = expectation(&[entry.clone(), valid_mapping.clone()]);
    let extra_mapping = ImportRecord::Mapping {
        occurrence: occurrence(sha1(1), "not-one"),
        request: mapping_request(0x52, 0x62),
    };
    let mut overmapped = vec![entry, valid_mapping, extra_mapping];
    overmapped.sort_by_key(ImportRecord::key);
    let mut inventory = VecInventory::new(overmapped);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::MappingSourceMissing
    );
}

#[test]
fn gitlink_is_an_entry_to_a_commit_not_a_blob_or_lfs_pointer() {
    let records = vec![ImportRecord::Entry {
        id: sha1(1),
        path: "vendor/module".to_owned(),
        mode: GitEntryMode::Submodule,
        encoded_bytes: 0,
        pointer_probe: Vec::new(),
        lfs: LfsDisposition::Ordinary,
    }];
    let report = run_fixture(records, BTreeMap::new(), &policy(), ImportLimits::default()).unwrap();
    assert_eq!(report.counts.entries, 1);
    assert_eq!(report.counts.blobs, 0);
    assert_eq!(report.counts.blob_occurrences, 0);
    assert_eq!(report.counts.mappings, 0);
    assert_eq!(report.counts.lfs_pointers, 0);
    assert_eq!(report.git_bytes, 0);
    assert_eq!(report.entries[0].mode, GitEntryMode::Submodule);
    assert!(!report.ready);
    assert_eq!(report.findings[0].kind, FindingKind::SubmoduleBlocked);
}

#[test]
fn expected_inventory_invariants_and_declared_limits_precede_source_entry() {
    let (records, _) = ready_fixture();
    let baseline = expectation(&records);

    let mut invalid = baseline;
    invalid.counts.items += 1;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    for field in 0..4 {
        let mut invalid = baseline;
        match field {
            0 => invalid.source_generation = [0; 32],
            1 => invalid.lfs_generation = [0; 32],
            2 => invalid.mapping_generation = [0; 32],
            _ => invalid.inventory_digest = [0; 32],
        }
        assert_expected_rejected_before_source(invalid, ImportLimits::default());
    }

    let mut invalid = baseline;
    invalid.counts.mappings = 0;
    invalid.counts.items -= 1;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    let mut invalid = baseline;
    invalid.counts.lfs_pointers = invalid.counts.blobs + 1;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    let mut invalid = baseline;
    invalid.counts.lfs_objects = invalid.counts.lfs_pointers + 1;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    let mut invalid = baseline;
    invalid.counts.blobs = invalid.counts.blob_occurrences + 1;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    let mut invalid = baseline;
    invalid.counts.blobs = 0;
    invalid.counts.lfs_pointers = 0;
    invalid.counts.lfs_objects = 0;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    let mut invalid = baseline;
    invalid.counts.lfs_objects = 0;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    let mut invalid = baseline;
    invalid.counts.blob_occurrences = invalid.counts.entries + 1;
    invalid.counts.mappings = invalid.counts.blob_occurrences;
    invalid.counts.items += 1;
    assert_expected_rejected_before_source(invalid, ImportLimits::default());

    for limits in [
        ImportLimits {
            items_maximum: baseline.counts.items - 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            relationships_maximum: baseline.counts.relationships - 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            git_bytes_maximum: baseline.git_bytes - 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            input_bytes_maximum: baseline.input_bytes - 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            lfs_objects_maximum: baseline.counts.lfs_objects - 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            mappings_maximum: baseline.counts.mappings - 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            work_units_maximum: baseline.counts.items
                + baseline.counts.relationships
                + baseline.counts.mappings,
            ..ImportLimits::default()
        },
    ] {
        assert_expected_rejected_before_source(baseline, limits);
    }
}

#[test]
fn raw_field_length_and_capacity_are_rejected_before_hashing_or_authority_calls() {
    let mut oversized_ref = "refs/heads/".to_owned();
    oversized_ref.push_str(&"a".repeat(REF_NAME_BYTES_HARD_MAXIMUM));
    let records = vec![ImportRecord::Ref {
        name: oversized_ref,
        target: sha1(1),
    }];
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceContractViolation
    );
    assert_eq!(inventory.calls(), 1);
    assert_eq!(authority.calls.get(), 0);

    let oversized_path = "a".repeat(ImportLimits::default().path_bytes_maximum + 1);
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: oversized_path.clone(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: b"x".to_vec(),
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), &oversized_path),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceContractViolation
    );
    assert_eq!(inventory.calls(), 1);
    assert_eq!(authority.calls.get(), 0);

    let mut probe = Vec::with_capacity(GIT_LFS_POINTER_BYTES_MAXIMUM + 1);
    probe.push(b'x');
    let records = vec![
        ImportRecord::Entry {
            id: sha1(1),
            path: "one".to_owned(),
            mode: GitEntryMode::Regular,
            encoded_bytes: 1,
            pointer_probe: probe,
            lfs: LfsDisposition::Ordinary,
        },
        ImportRecord::Mapping {
            occurrence: occurrence(sha1(1), "one"),
            request: mapping_request(0x51, 0x61),
        },
    ];
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(BTreeMap::new());
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceContractViolation
    );
    assert_eq!(inventory.calls(), 1);
    assert_eq!(lfs.reads.get(), 0);
    assert_eq!(authority.calls.get(), 0);
}

#[test]
fn opaque_profile_string_capacity_is_normalized_before_retention() {
    let (baseline_records, objects) = ready_fixture();
    let baseline = run_fixture(
        baseline_records,
        objects.clone(),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();

    let (mut records, _) = ready_fixture();
    let ImportRecord::Mapping { request, .. } = &mut records[4] else {
        unreachable!();
    };
    let mut namespace = String::with_capacity(1_000_000);
    namespace.push_str("importer.test");
    let mut id = String::with_capacity(1_000_000);
    id.push_str("fixture-adapter");
    request.importer_profile = ProfileRef::new(namespace, id, 1).unwrap();
    let report = run_fixture(records, objects, &policy(), ImportLimits::default()).unwrap();
    assert_eq!(report.inventory_digest, baseline.inventory_digest);
    assert_eq!(report.mapping_digest, baseline.mapping_digest);
    assert_eq!(report.peak_retained_bytes, baseline.peak_retained_bytes);
    assert_eq!(report.report_digest, baseline.report_digest);
}

#[test]
fn final_generation_and_cancellation_fence_runs_after_report_hashing() {
    let (records, objects) = ready_fixture();
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records.clone());
    let mut lfs = MapLfs::new(objects.clone());
    let mut authority = Authority::new(&policy());
    authority.drift_at_generation_call = Some(5);
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::SourceGenerationChanged
    );

    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    let cancellation = Arc::new(AtomicBool::new(false));
    authority.cancel_at_generation_call = Some((5, Arc::clone(&cancellation)));
    let control = OperationControl::with_cancellation(cancellation);
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &control,
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::Cancelled
    );
}

#[test]
fn source_identity_is_an_opaque_bound_claim_not_a_derived_occurrence_identity() {
    let (first_records, objects) = ready_fixture();
    let first = run_fixture(
        first_records,
        objects.clone(),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();

    let (mut second_records, _) = ready_fixture();
    let ImportRecord::Mapping { request, .. } = &mut second_records[4] else {
        unreachable!();
    };
    request.source_identity_digest = [0x52; 32];
    let second = run_fixture(second_records, objects, &policy(), ImportLimits::default()).unwrap();
    assert_eq!(first.mappings[0].occurrence, second.mappings[0].occurrence);
    assert_ne!(
        first.mappings[0].mapping.source_identity_digest,
        second.mappings[0].mapping.source_identity_digest
    );
    assert_ne!(first.mapping_digest, second.mapping_digest);
    assert_ne!(first.report_digest, second.report_digest);
}

#[test]
fn zero_mapping_identity_digest_is_rejected_before_authority_lookup() {
    let (mut records, objects) = ready_fixture();
    let ImportRecord::Mapping { request, .. } = &mut records[4] else {
        unreachable!();
    };
    request.source_identity_digest = [0; 32];
    let expected = expectation(&records);
    let mut inventory = VecInventory::new(records);
    let mut lfs = MapLfs::new(objects);
    let mut authority = Authority::new(&policy());
    assert_eq!(
        preflight_git_import(
            &mut inventory,
            &mut lfs,
            &mut authority,
            &policy(),
            ImportLimits::default(),
            expected,
            &OperationControl::default(),
        )
        .unwrap_err()
        .code(),
        ImportPreflightErrorCode::MappingDecisionMismatch
    );
    assert_eq!(authority.calls.get(), 0);
}

#[test]
fn invalid_descriptor_policy_is_rejected() {
    let (records, objects) = ready_fixture();
    let mut invalid = policy();
    invalid.descriptor.kind = ObjectKind::Snapshot;
    assert_eq!(
        run_fixture(records, objects, &invalid, ImportLimits::default())
            .unwrap_err()
            .code(),
        ImportPreflightErrorCode::PolicyInvalid
    );

    for scenario in 0..2 {
        let (records, objects) = ready_fixture();
        let mut invalid = policy();
        if scenario == 0 {
            invalid.descriptor.digest = [0; 32];
        } else {
            invalid.source_namespace_digest = [0; 32];
        }
        assert_eq!(
            run_fixture(records, objects, &invalid, ImportLimits::default())
                .unwrap_err()
                .code(),
            ImportPreflightErrorCode::PolicyInvalid
        );
    }
}

#[test]
fn hard_ceiling_and_retained_ceiling_are_enforced() {
    let (records, objects) = ready_fixture();
    let exact_hard = ImportLimits {
        items_maximum: ITEMS_HARD_MAXIMUM,
        relationships_maximum: RELATIONSHIPS_HARD_MAXIMUM,
        git_bytes_maximum: GIT_BYTES_HARD_MAXIMUM,
        input_bytes_maximum: INPUT_BYTES_HARD_MAXIMUM,
        lfs_objects_maximum: ITEMS_HARD_MAXIMUM,
        lfs_object_bytes_maximum: LFS_BYTES_HARD_MAXIMUM,
        lfs_bytes_maximum: LFS_BYTES_HARD_MAXIMUM,
        mappings_maximum: ITEMS_HARD_MAXIMUM,
        findings_maximum: ITEMS_HARD_MAXIMUM,
        work_units_maximum: WORK_UNITS_HARD_MAXIMUM,
        retained_bytes_maximum: RETAINED_BYTES_HARD_MAXIMUM,
        path_bytes_maximum: PATH_BYTES_HARD_MAXIMUM,
        ref_name_bytes_maximum: REF_NAME_BYTES_HARD_MAXIMUM,
        read_chunk_bytes: READ_CHUNK_BYTES_HARD_MAXIMUM,
    };
    assert!(run_fixture(records.clone(), objects.clone(), &policy(), exact_hard).is_ok());

    let invalid_limits = [
        ImportLimits {
            items_maximum: ITEMS_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            relationships_maximum: RELATIONSHIPS_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            git_bytes_maximum: GIT_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            input_bytes_maximum: INPUT_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            lfs_objects_maximum: ITEMS_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            lfs_object_bytes_maximum: LFS_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            lfs_bytes_maximum: LFS_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            mappings_maximum: ITEMS_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            findings_maximum: ITEMS_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            work_units_maximum: WORK_UNITS_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            retained_bytes_maximum: RETAINED_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            path_bytes_maximum: PATH_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            ref_name_bytes_maximum: REF_NAME_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
        ImportLimits {
            read_chunk_bytes: READ_CHUNK_BYTES_HARD_MAXIMUM + 1,
            ..ImportLimits::default()
        },
    ];
    for invalid in invalid_limits {
        assert_eq!(
            error_code(records.clone(), objects.clone(), invalid),
            ImportPreflightErrorCode::LimitsInvalid
        );
    }

    let zero_required_limits = [
        ImportLimits {
            items_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            git_bytes_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            input_bytes_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            lfs_bytes_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            work_units_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            retained_bytes_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            path_bytes_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            ref_name_bytes_maximum: 0,
            ..ImportLimits::default()
        },
        ImportLimits {
            read_chunk_bytes: 0,
            ..ImportLimits::default()
        },
    ];
    for invalid in zero_required_limits {
        assert_eq!(
            error_code(records.clone(), objects.clone(), invalid),
            ImportPreflightErrorCode::LimitsInvalid
        );
    }

    let baseline = run_fixture(
        records.clone(),
        objects.clone(),
        &policy(),
        ImportLimits::default(),
    )
    .unwrap();
    let exact = ImportLimits {
        retained_bytes_maximum: baseline.peak_retained_bytes,
        ..ImportLimits::default()
    };
    assert!(run_fixture(records.clone(), objects.clone(), &policy(), exact).is_ok());
    let tiny = ImportLimits {
        retained_bytes_maximum: baseline.peak_retained_bytes - 1,
        ..ImportLimits::default()
    };
    assert_eq!(
        error_code(records, objects, tiny),
        ImportPreflightErrorCode::LimitRetainedBytes
    );
}
