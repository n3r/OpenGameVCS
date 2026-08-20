use std::{
    cell::{Cell, RefCell},
    fs,
    io::{self, Write},
    rc::Rc,
    str::FromStr,
    thread,
    time::Duration,
};

use ogvcs_object_model::{
    decode_canonical, logical_record_id, object_id, opaque_object_digest, Cbor, ErrorCode, Limits,
    LogicalBundleBudget, LogicalBundleWriteLimits, LogicalBundleWriteOptions,
    LogicalBundleWritePlan, LogicalBundleWriter, ObjectKind, ObjectRef, Operation, ProfileRef, Registry,
    TypedDigest, ValidationStage,
};

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn read(relative: &str) -> Vec<u8> {
    fs::read(format!("{VECTOR_ROOT}/{relative}")).unwrap()
}

fn object(kind: ObjectKind, path: &str) -> (ObjectRef, Vec<u8>) {
    let payload = read(path);
    let reference = ObjectRef {
        kind,
        digest: object_id(kind, &payload).unwrap(),
    };
    (reference, payload)
}

fn all_objects() -> Vec<(ObjectRef, Vec<u8>)> {
    let mut objects = vec![
        object(ObjectKind::Chunk, "objects/01-chunk.bin"),
        object(
            ObjectKind::ContentManifest,
            "objects/02-content-manifest.cbor",
        ),
        object(ObjectKind::Tree, "objects/03-tree.cbor"),
        object(ObjectKind::Tree, "objects/03-tree-child.cbor"),
        object(ObjectKind::ChangeSet, "objects/04-change-set.cbor"),
        object(ObjectKind::AssetGroupSet, "objects/05-asset-group-set.cbor"),
        object(
            ObjectKind::RepositoryDescriptor,
            "objects/06-repository-descriptor.cbor",
        ),
        object(ObjectKind::Snapshot, "objects/07-snapshot.cbor"),
        object(ObjectKind::ShelfRevision, "objects/08-shelf-revision.cbor"),
        object(ObjectKind::Provenance, "objects/09-provenance.cbor"),
        object(ObjectKind::Attestation, "objects/10-attestation.cbor"),
        object(ObjectKind::ConflictSet, "objects/11-conflict-set.cbor"),
    ];
    objects.sort_unstable_by_key(|(reference, _)| *reference);
    objects
}

fn logical_records() -> Vec<Cbor> {
    (1..=9)
        .map(|record_type| {
            decode_canonical(
                &read(&format!(
                    "logical-records/{record_type:02}-{}.cbor",
                    [
                        "repository-root",
                        "mutable-ref",
                        "shelf-pointer",
                        "file-id-lifetime",
                        "import-mapping",
                        "pending-change-reference",
                        "lock-reference",
                        "annotation",
                        "fixture-event",
                    ][record_type - 1]
                )),
                Limits::METADATA,
            )
            .unwrap()
        })
        .collect()
}

fn role() -> ProfileRef {
    ProfileRef::from_str("bundle-role.test/root@1").unwrap()
}

fn plan(
    object_count: u64,
    logical_record_count: u64,
    root_count: u64,
    sequence_bytes: u64,
    largest_item_bytes: u64,
    traversal_edges: u64,
) -> LogicalBundleWritePlan {
    LogicalBundleWritePlan {
        object_count,
        logical_record_count,
        root_count,
        budget: LogicalBundleBudget {
            sequence_bytes,
            largest_item_bytes,
            traversal_edges,
            index_entries: object_count + logical_record_count,
        },
    }
}

fn roomy_plan(
    object_count: u64,
    logical_record_count: u64,
    root_count: u64,
) -> LogicalBundleWritePlan {
    plan(
        object_count,
        logical_record_count,
        root_count,
        1_000_000,
        100_000,
        1_000,
    )
}

#[test]
fn writer_independently_reproduces_every_valid_checked_in_bundle() {
    let registry = Registry::bundled();
    let bundle_role = role();

    let mut supplied = Vec::new();
    let supplied_summary;
    {
        let objects = all_objects();
        let selected = [&objects[0], &objects[1]];
        let annotation = logical_records().swap_remove(7);
        let mut writer = LogicalBundleWriter::new(
            &mut supplied,
            plan(2, 1, 2, 666, 236, 16),
            LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
        )
        .unwrap();
        for (reference, payload) in selected {
            writer.write_object(*reference, payload).unwrap();
        }
        let annotation_id = writer.write_logical_record(&annotation).unwrap();
        writer
            .write_object_root(objects[1].0, &bundle_role)
            .unwrap();
        writer
            .write_logical_record_root(annotation_id, &bundle_role)
            .unwrap();
        supplied_summary = writer.finish().unwrap();
    }
    assert_eq!(
        supplied,
        read("logical-bundles/valid-supplied-closure.cborseq")
    );
    assert_eq!(supplied_summary.bytes, 666);
    assert_eq!(supplied_summary.items, 7);
    assert_eq!(supplied_summary.largest_item_bytes, 236);
    assert_eq!(supplied_summary.traversal_edges, 3);
    assert_eq!(
        supplied_summary.transcript_digest,
        hex("c302bd2f60d259e6859ce677e2d2f08133d53236abaa4de82c5fa868b020735c")
    );

    let mut all_families = Vec::new();
    {
        let objects = all_objects();
        let records = logical_records();
        let mut writer = LogicalBundleWriter::new(
            &mut all_families,
            plan(12, 9, 20, 9_056, 2_034, 60),
            LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
        )
        .unwrap();
        for (reference, payload) in &objects {
            writer.write_object(*reference, payload).unwrap();
        }
        let mut logical_ids = Vec::new();
        for record in &records {
            logical_ids.push(writer.write_logical_record(record).unwrap());
        }
        let mut previous_kind = None;
        for (reference, _) in &objects {
            if previous_kind != Some(reference.kind) {
                writer.write_object_root(*reference, &bundle_role).unwrap();
                previous_kind = Some(reference.kind);
            }
        }
        logical_ids.sort_unstable_by_key(|identity| *identity.digest());
        for identity in logical_ids {
            writer
                .write_logical_record_root(identity, &bundle_role)
                .unwrap();
        }
        let summary = writer.finish().unwrap();
        assert_eq!((summary.items, summary.traversal_edges), (43, 60));
    }
    assert_eq!(
        all_families,
        read("logical-bundles/valid-all-families.cborseq")
    );

    let mut multiple_roots = Vec::new();
    {
        let objects = all_objects();
        let selected = [&objects[0], &objects[1]];
        let mut writer = LogicalBundleWriter::new(
            &mut multiple_roots,
            plan(2, 0, 2, 538, 236, 16),
            LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
        )
        .unwrap();
        for (reference, payload) in selected {
            writer.write_object(*reference, payload).unwrap();
        }
        writer
            .write_object_root(objects[0].0, &bundle_role)
            .unwrap();
        writer
            .write_object_root(objects[1].0, &bundle_role)
            .unwrap();
        writer.finish().unwrap();
    }
    assert_eq!(
        multiple_roots,
        read("logical-bundles/scenario-bundle-multi-root-disambiguation.cborseq")
    );

    let mut empty = Vec::new();
    {
        let mut writer = LogicalBundleWriter::new(
            &mut empty,
            plan(0, 0, 0, 77, 52, 16),
            LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
        )
        .unwrap();
        writer.finish().unwrap();
    }
    assert_eq!(
        empty,
        read("logical-bundles/scenario-bundle-zero-sections.cborseq")
    );
}

#[test]
fn writer_rejects_malformed_id_order_duplicate_count_and_root_inputs() {
    let registry = Registry::bundled();
    let bundle_role = role();
    let objects = all_objects();

    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(2, 0, 1),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    assert_eq!(
        writer
            .write_object_root(objects[1].0, &bundle_role)
            .unwrap_err()
            .code,
        ErrorCode::BundleSequenceInvalid
    );
    assert_eq!(
        writer
            .write_object(objects[1].0, &objects[1].1)
            .unwrap_err()
            .code,
        ErrorCode::BundleSequenceInvalid
    );
    assert_eq!(writer.finish().unwrap_err().code, ErrorCode::BundleSequenceInvalid);

    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(2, 0, 1),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_object(objects[1].0, &objects[1].1).unwrap();
    assert_eq!(
        writer
            .write_object(objects[0].0, &objects[0].1)
            .unwrap_err()
            .code,
        ErrorCode::BundleSequenceInvalid
    );

    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(2, 0, 1),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_object(objects[0].0, &objects[0].1).unwrap();
    assert_eq!(
        writer
            .write_object(objects[0].0, &objects[0].1)
            .unwrap_err()
            .code,
        ErrorCode::BundleDuplicateIdentity
    );

    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(1, 0, 0),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    let mut wrong_reference = objects[0].0;
    wrong_reference.digest[0] ^= 1;
    writer.write_object(wrong_reference, &objects[0].1).unwrap();
    assert_eq!(
        writer.finish().unwrap_err().code,
        ErrorCode::ObjectIdMismatch
    );

    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(1, 0, 0),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    let wrong_kind = ObjectRef {
        kind: ObjectKind::Tree,
        digest: opaque_object_digest(ObjectKind::Tree.code(), &objects[1].1).unwrap(),
    };
    writer.write_object(wrong_kind, &objects[1].1).unwrap();
    assert_eq!(
        writer.finish().unwrap_err().code,
        ErrorCode::ObjectReferenceKindMismatch
    );

    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(1, 0, 1),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();

    let malformed_payload = [0xa1];
    let malformed_reference = ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest: opaque_object_digest(ObjectKind::ContentManifest.code(), &malformed_payload)
            .unwrap(),
    };
    assert_eq!(
        writer
            .write_object(malformed_reference, &malformed_payload)
            .unwrap_err()
            .code,
        ErrorCode::CborTruncated
    );

    let malformed_record = Cbor::UInt(1);
    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(0, 1, 1),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    assert_eq!(
        writer
            .write_logical_record(&malformed_record)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );

    let records = logical_records();
    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(0, 2, 2),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_logical_record(&records[1]).unwrap();
    assert_eq!(
        writer.write_logical_record(&records[0]).unwrap_err().code,
        ErrorCode::BundleSequenceInvalid
    );

    let logical_identity = TypedDigest::sha256([0x55; 32]);
    let mut output = Vec::new();
    let mut writer = LogicalBundleWriter::new(
        &mut output,
        roomy_plan(0, 0, 2),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer
        .write_logical_record_root(logical_identity, &bundle_role)
        .unwrap();
    assert_eq!(
        writer
            .write_object_root(objects[0].0, &bundle_role)
            .unwrap_err()
            .code,
        ErrorCode::BundleSequenceInvalid
    );
}

#[test]
fn writer_enforces_declarations_and_configured_resource_ceilings() {
    let registry = Registry::bundled();
    let objects = all_objects();

    let mut too_few_indexes = roomy_plan(1, 1, 2);
    too_few_indexes.budget.index_entries = 1;
    let error = LogicalBundleWriter::new(
        Vec::new(),
        too_few_indexes,
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .err()
    .unwrap();
    assert_eq!(
        (error.code, error.stage),
        (
            ErrorCode::BundleBudgetExceeded,
            ValidationStage::DeclaredAccounting
        )
    );

    let too_small = plan(0, 0, 0, 76, 52, 0);
    let error = LogicalBundleWriter::new(
        Vec::new(),
        too_small,
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .err()
    .unwrap();
    assert_eq!(
        (error.code, error.stage),
        (
            ErrorCode::BundleBudgetExceeded,
            ValidationStage::DeclaredAccounting
        )
    );

    let mut options = LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite);
    options.limits.chunk_bytes = objects[0].1.len() - 1;
    let mut writer = LogicalBundleWriter::new(Vec::new(), roomy_plan(1, 0, 1), options).unwrap();
    assert_eq!(
        writer
            .write_object(objects[0].0, &objects[0].1)
            .unwrap_err()
            .code,
        ErrorCode::LimitChunkBytes
    );

    let mut edge_plan = roomy_plan(2, 0, 1);
    edge_plan.budget.traversal_edges = 1;
    let mut writer = LogicalBundleWriter::new(
        Vec::new(),
        edge_plan,
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_object(objects[0].0, &objects[0].1).unwrap();
    let error = writer
        .write_object(objects[1].0, &objects[1].1)
        .unwrap_err();
    assert_eq!(
        (error.code, error.stage),
        (
            ErrorCode::BundleBudgetExceeded,
            ValidationStage::DeclaredAccounting
        )
    );

    let mut options = LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite);
    options.limits = LogicalBundleWriteLimits {
        item_bytes: 100,
        ..LogicalBundleWriteLimits::default()
    };
    let constrained = LogicalBundleWritePlan {
        budget: LogicalBundleBudget {
            largest_item_bytes: 100,
            ..roomy_plan(1, 0, 1).budget
        },
        ..roomy_plan(1, 0, 1)
    };
    let mut writer = LogicalBundleWriter::new(Vec::new(), constrained, options).unwrap();
    let error = writer
        .write_object(objects[1].0, &objects[1].1)
        .unwrap_err();
    assert_eq!(
        (error.code, error.stage),
        (
            ErrorCode::BundleBudgetExceeded,
            ValidationStage::ConfiguredResourcePreflight
        )
    );
}

#[test]
fn writer_checks_root_profile_family_and_write_mode_before_emission() {
    let registry = Registry::bundled();
    let objects = all_objects();

    let mut writer = LogicalBundleWriter::new(
        Vec::new(),
        roomy_plan(1, 0, 1),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_object(objects[0].0, &objects[0].1).unwrap();
    writer
        .write_object_root(
            objects[0].0,
            &ProfileRef::from_str("path.test/opaque@1").unwrap(),
        )
        .unwrap();
    assert_eq!(writer.finish().unwrap_err().code, ErrorCode::SchemaFieldInvalid);

    let options = LogicalBundleWriteOptions::new(&registry, Operation::ProductionWrite);
    let mut writer = LogicalBundleWriter::new(Vec::new(), roomy_plan(1, 0, 1), options).unwrap();
    writer.write_object(objects[0].0, &objects[0].1).unwrap();
    writer.write_object_root(objects[0].0, &role()).unwrap();
    assert_eq!(
        writer.finish().unwrap_err().code,
        ErrorCode::ProfileConformanceOnly
    );
}

#[test]
fn writer_ranks_complete_section_order_identity_schema_and_lifecycle() {
    let registry = Registry::bundled();
    let objects = all_objects();

    // A safely decoded layer-two object defect is staged so the later
    // layer-one declared identity failure can be selected at finish.
    let tree_payload = objects
        .iter()
        .find(|(reference, _)| reference.kind == ObjectKind::Tree)
        .unwrap()
        .1
        .clone();
    let wrong_kind = ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest: opaque_object_digest(ObjectKind::ContentManifest.code(), &tree_payload).unwrap(),
    };
    let mut bad_identity = ObjectRef {
        kind: ObjectKind::Tree,
        digest: opaque_object_digest(ObjectKind::Tree.code(), &tree_payload).unwrap(),
    };
    bad_identity.digest = [0xff; 32];
    let mut writer = LogicalBundleWriter::new(
        Vec::new(),
        roomy_plan(2, 0, 0),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_object(wrong_kind, &tree_payload).unwrap();
    writer.write_object(bad_identity, &tree_payload).unwrap();
    let error = writer.finish().unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::ObjectIdMismatch,
            1,
            ValidationStage::DeclaredIdentity
        )
    );

    // A hashable record with an early schema defect cannot hide a later
    // descending logical-record sort key.
    let mut malformed = logical_records().swap_remove(7);
    let Cbor::Map(fields) = &mut malformed else {
        panic!("annotation must be a map");
    };
    fields.push((Cbor::UInt(999), Cbor::UInt(1)));
    let records = logical_records();
    let mut writer = LogicalBundleWriter::new(
        Vec::new(),
        roomy_plan(0, 2, 0),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_logical_record(&malformed).unwrap();
    assert_eq!(
        writer.write_logical_record(&records[6]).unwrap_err().code,
        ErrorCode::BundleSequenceInvalid
    );

    // Root-role lifecycle is likewise staged until a later root has had its
    // phase and canonical order checked.
    let mut writer = LogicalBundleWriter::new(
        Vec::new(),
        roomy_plan(2, 0, 2),
        LogicalBundleWriteOptions::new(&registry, Operation::ProductionWrite),
    )
    .unwrap();
    writer.write_object(objects[0].0, &objects[0].1).unwrap();
    writer.write_object(objects[1].0, &objects[1].1).unwrap();
    writer.write_object_root(objects[1].0, &role()).unwrap();
    assert_eq!(
        writer
            .write_object_root(objects[0].0, &ProfileRef::from_str("bundle-role.test/root@1").unwrap())
            .unwrap_err()
            .code,
        ErrorCode::BundleSequenceInvalid
    );
}

#[derive(Default)]
struct OneByteWriter(Vec<u8>);

impl Write for OneByteWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let take = bytes.len().min(1);
        self.0.extend_from_slice(&bytes[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ZeroWriter;

impl Write for ZeroWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Ok(0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ObservedWriter(Rc<RefCell<Vec<u8>>>);

impl Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn bundle_writer_rejects_read_and_partial_authority_before_sink_output() {
    for (registry, operation) in [
        (Registry::bundled(), Operation::Read),
        (
            Registry::load([], []).unwrap(),
            Operation::ConformanceWrite,
        ),
    ] {
        let observed = Rc::new(RefCell::new(Vec::new()));
        let error = LogicalBundleWriter::new(
            ObservedWriter(observed.clone()),
            roomy_plan(0, 0, 0),
            LogicalBundleWriteOptions::new(&registry, operation),
        )
        .err()
        .unwrap();
        assert_eq!(
            (error.code, error.layer, error.stage),
            (
                ErrorCode::SchemaFieldInvalid,
                1,
                ValidationStage::ConfiguredResourcePreflight,
            )
        );
        assert!(observed.borrow().is_empty());
    }
}

#[derive(Clone, Default)]
struct SlowReturningWriter {
    bytes: Rc<RefCell<Vec<u8>>>,
    calls: Rc<Cell<usize>>,
}

impl Write for SlowReturningWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        thread::sleep(Duration::from_millis(75));
        self.bytes.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_handles_short_writes_and_poisoning_without_silent_truncation() {
    let registry = Registry::bundled();
    let mut writer = LogicalBundleWriter::new(
        OneByteWriter::default(),
        plan(0, 0, 0, 77, 52, 16),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.finish().unwrap();
    assert_eq!(
        writer.into_inner().0,
        read("logical-bundles/scenario-bundle-zero-sections.cborseq")
    );

    assert_eq!(
        LogicalBundleWriter::new(
            ZeroWriter,
            plan(0, 0, 0, 77, 52, 16),
            LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn writer_checks_elapsed_time_after_a_slow_returning_write() {
    let registry = Registry::bundled();
    let output = SlowReturningWriter::default();
    let observed = output.clone();
    let mut options = LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite);
    options.limits.max_elapsed = Duration::from_millis(25);
    let error = LogicalBundleWriter::new(output, plan(0, 0, 0, 77, 52, 0), options)
        .err()
        .unwrap();
    assert!(observed.calls.get() > 0);
    assert!(!observed.bytes.borrow().is_empty());
    assert_eq!((error.code, error.layer), (ErrorCode::LimitTime, 1));
}

#[test]
fn writer_enforces_memory_and_time_before_item_emission() {
    let registry = Registry::bundled();
    let conflict = object(ObjectKind::ConflictSet, "objects/11-conflict-set.cbor");
    let mut options = LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite);
    options.limits.max_memory_bytes = 8_192;

    let mut expected_header = Vec::new();
    {
        let _writer =
            LogicalBundleWriter::new(&mut expected_header, roomy_plan(1, 0, 1), options).unwrap();
    }
    let mut actual = Vec::new();
    {
        let mut writer =
            LogicalBundleWriter::new(&mut actual, roomy_plan(1, 0, 1), options).unwrap();
        assert_eq!(
            writer
                .write_object(conflict.0, &conflict.1)
                .unwrap_err()
                .code,
            ErrorCode::LimitMemory
        );
    }
    assert_eq!(actual, expected_header);

    let mut annotation = logical_records().swap_remove(7);
    let Cbor::Map(fields) = &mut annotation else {
        panic!("annotation must be a map");
    };
    fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(18))
        .unwrap()
        .1 = Cbor::Bytes(vec![0; 16_384]);
    let mut actual = Vec::new();
    {
        let mut writer =
            LogicalBundleWriter::new(&mut actual, roomy_plan(0, 1, 1), options).unwrap();
        assert_eq!(
            writer.write_logical_record(&annotation).unwrap_err().code,
            ErrorCode::LimitMemory
        );
    }
    let mut expected_header = Vec::new();
    {
        let _writer =
            LogicalBundleWriter::new(&mut expected_header, roomy_plan(0, 1, 1), options).unwrap();
    }
    assert_eq!(actual, expected_header);

    let observed = ObservedWriter::default();
    let bytes = Rc::clone(&observed.0);
    let mut time_options = LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite);
    time_options.limits.max_elapsed = Duration::ZERO;
    assert_eq!(
        LogicalBundleWriter::new(observed, roomy_plan(0, 0, 0), time_options)
            .err()
            .unwrap()
            .code,
        ErrorCode::LimitTime
    );
    assert!(bytes.borrow().is_empty());
}

#[test]
fn object_logical_and_root_identities_are_computed_from_exact_canonical_bytes() {
    let registry = Registry::bundled();
    let bundle_role = role();
    let objects = all_objects();
    let annotation_bytes = read("logical-records/08-annotation.cbor");
    let annotation = decode_canonical(&annotation_bytes, Limits::METADATA).unwrap();
    let expected_identity = logical_record_id(8, &annotation_bytes).unwrap();

    let mut writer = LogicalBundleWriter::new(
        Vec::new(),
        roomy_plan(2, 1, 2),
        LogicalBundleWriteOptions::new(&registry, Operation::ConformanceWrite),
    )
    .unwrap();
    writer.write_object(objects[0].0, &objects[0].1).unwrap();
    writer.write_object(objects[1].0, &objects[1].1).unwrap();
    let actual_identity = writer.write_logical_record(&annotation).unwrap();
    assert_eq!(actual_identity.digest(), &expected_identity);
    writer
        .write_object_root(objects[1].0, &bundle_role)
        .unwrap();
    writer
        .write_logical_record_root(actual_identity, &bundle_role)
        .unwrap();
    let summary = writer.finish().unwrap();
    assert_eq!(
        (
            summary.object_count,
            summary.logical_record_count,
            summary.root_count,
            summary.index_entries,
        ),
        (2, 1, 2, 3)
    );
}

fn hex(text: &str) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let nibble = |value| match value {
            b'0'..=b'9' => value - b'0',
            _ => value - b'a' + 10,
        };
        *slot = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    output
}
