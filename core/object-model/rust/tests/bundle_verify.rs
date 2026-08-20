use std::{
    cell::Cell,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    rc::Rc,
    thread,
    time::Duration,
};

use ogvcs_object_model::{
    decode_canonical, encode_canonical_with_limits, object_id, opaque_object_digest,
    verify_logical_bundle_file, verify_logical_bundle_stream, visit_logical_bundle, BundleItemInfo,
    BundleLimits, BundleTranscriptHashWriter, BundleVisitor, Cbor, ErrorCode, Limits,
    LogicalBundleVerifyLimits, LogicalBundleVerifyOptions, ObjectKind, ObjectRef, Operation,
    ProfileRef, Registry, TypedDigest, ValidationStage,
};

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn read(relative: &str) -> Vec<u8> {
    fs::read(format!("{VECTOR_ROOT}/{relative}")).unwrap()
}

fn hex(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let nibble = |value| match value {
            b'0'..=b'9' => value - b'0',
            _ => value - b'a' + 10,
        };
        *slot = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    out
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let suffix = hex_lower(&nonce);
        let path = std::env::temp_dir().join(format!("ogvcs-rust-{label}-{suffix}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn assert_empty(&self) {
        assert_eq!(fs::read_dir(&self.0).unwrap().count(), 0);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn verify(name: &str) -> Result<ogvcs_object_model::LogicalBundleVerifySummary, ErrorCode> {
    let scratch = Scratch::new(name);
    let registry = Registry::bundled();
    let result = verify_logical_bundle_stream(
        Cursor::new(read(&format!("logical-bundles/{name}.cborseq"))),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .map_err(|error| error.code);
    scratch.assert_empty();
    result
}

fn encoded(value: &Cbor) -> Vec<u8> {
    encode_canonical_with_limits(value, Limits::BUNDLE_ITEM).unwrap()
}

#[derive(Default)]
struct ItemOffsets(Vec<BundleItemInfo>);

impl BundleVisitor for ItemOffsets {
    fn item_end(&mut self, info: BundleItemInfo) -> ogvcs_object_model::Result<()> {
        self.0.push(info);
        Ok(())
    }
}

struct SlowReturningReader<R> {
    inner: R,
    calls: Rc<Cell<usize>>,
}

struct MustNotRead;

impl Read for MustNotRead {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        panic!("registry authority must be rejected before reading input")
    }
}

impl<R: Read> Read for SlowReturningReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        thread::sleep(Duration::from_millis(75));
        self.inner.read(buffer)
    }
}

fn field(value: &Cbor, key: u64) -> Cbor {
    let Cbor::Map(fields) = value else {
        panic!("bundle item must be a map");
    };
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == Cbor::UInt(key)).then(|| value.clone()))
        .unwrap()
}

fn set_field(value: &mut Cbor, key: u64, replacement: Cbor) {
    let Cbor::Map(fields) = value else {
        panic!("bundle item must be a map");
    };
    fields
        .iter_mut()
        .find(|(candidate, _)| *candidate == Cbor::UInt(key))
        .unwrap()
        .1 = replacement;
}

fn single_chunk_bundle(payload: &[u8]) -> Vec<u8> {
    let reference = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, payload).unwrap(),
    };
    single_chunk_bundle_with_references(payload, reference.to_cbor(), reference.to_cbor())
}

fn single_chunk_bundle_with_references(
    payload: &[u8],
    object_reference: Cbor,
    root_reference: Cbor,
) -> Vec<u8> {
    single_chunk_bundle_with_item_payload(
        object_reference,
        root_reference,
        Cbor::Bytes(payload.to_vec()),
    )
}

fn single_chunk_bundle_with_item_payload(
    object_reference: Cbor,
    root_reference: Cbor,
    item_payload: Cbor,
) -> Vec<u8> {
    let role = ProfileRef::new("bundle-role.test", "root", 1).unwrap();
    let object = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(2)),
        (Cbor::UInt(2), Cbor::UInt(0)),
        (Cbor::UInt(3), object_reference),
        (Cbor::UInt(4), item_payload),
    ]);
    let root = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(4)),
        (Cbor::UInt(2), Cbor::UInt(0)),
        (Cbor::UInt(3), Cbor::UInt(1)),
        (Cbor::UInt(4), root_reference),
        (Cbor::UInt(5), role.to_cbor()),
    ]);
    authenticated_single_object_bundle(object, root)
}

fn authenticated_single_object_bundle(object: Cbor, root: Cbor) -> Vec<u8> {
    let body = [encoded(&object), encoded(&root)];
    let mut declared_bytes = 0u64;
    let mut declared_largest = 0u64;
    for _ in 0..12 {
        let header = encoded(&Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(1)),
            (Cbor::UInt(2), Cbor::UInt(1)),
            (Cbor::UInt(3), Cbor::UInt(1)),
            (Cbor::UInt(4), Cbor::UInt(0)),
            (Cbor::UInt(5), Cbor::UInt(1)),
            (
                Cbor::UInt(6),
                Cbor::Map(vec![
                    (Cbor::UInt(0), Cbor::UInt(declared_bytes)),
                    (Cbor::UInt(1), Cbor::UInt(declared_largest)),
                    (Cbor::UInt(2), Cbor::UInt(0)),
                    (Cbor::UInt(3), Cbor::UInt(1)),
                ]),
            ),
        ]));
        let mut transcript = BundleTranscriptHashWriter::new(2_199_023_255_552);
        transcript.update(&header).unwrap();
        for item in &body {
            transcript.update(item).unwrap();
        }
        let digest = *transcript.finish().unwrap().digest();
        let trailer = encoded(&Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(5)),
            (Cbor::UInt(2), Cbor::UInt(1)),
            (Cbor::UInt(3), Cbor::UInt(0)),
            (Cbor::UInt(4), Cbor::UInt(1)),
            (Cbor::UInt(5), Cbor::UInt(4)),
            (Cbor::UInt(6), TypedDigest::sha256(digest).to_cbor()),
        ]));
        let next_bytes =
            (header.len() + body.iter().map(Vec::len).sum::<usize>() + trailer.len()) as u64;
        let next_largest = *[header.len(), body[0].len(), body[1].len(), trailer.len()]
            .iter()
            .max()
            .unwrap() as u64;
        if next_bytes == declared_bytes && next_largest == declared_largest {
            let mut bundle = header;
            for item in &body {
                bundle.extend_from_slice(item);
            }
            bundle.extend_from_slice(&trailer);
            return bundle;
        }
        declared_bytes = next_bytes;
        declared_largest = next_largest;
    }
    panic!("bundle declarations did not converge")
}

fn reauthenticate_items(values: &mut [Cbor]) -> Vec<u8> {
    let trailer_index = values.len() - 1;
    let encoded_prefix = values[..trailer_index]
        .iter()
        .map(encoded)
        .collect::<Vec<_>>();
    let mut transcript = BundleTranscriptHashWriter::new(2_199_023_255_552);
    for item in &encoded_prefix {
        transcript.update(item).unwrap();
    }
    let digest = *transcript.finish().unwrap().digest();
    set_field(
        &mut values[trailer_index],
        6,
        TypedDigest::sha256(digest).to_cbor(),
    );
    values.iter().flat_map(encoded).collect()
}

fn reauthenticate_with_actual_declarations(values: &mut [Cbor]) -> Vec<u8> {
    for _ in 0..16 {
        let encoded_bundle = reauthenticate_items(values);
        let encoded_items = values.iter().map(encoded).collect::<Vec<_>>();
        let total = encoded_bundle.len() as u64;
        let largest = encoded_items.iter().map(Vec::len).max().unwrap() as u64;
        let mut declarations = field(&values[0], 6);
        let previous = (field(&declarations, 0), field(&declarations, 1));
        set_field(&mut declarations, 0, Cbor::UInt(total));
        set_field(&mut declarations, 1, Cbor::UInt(largest));
        set_field(&mut values[0], 6, declarations);
        if previous == (Cbor::UInt(total), Cbor::UInt(largest)) {
            return reauthenticate_items(values);
        }
    }
    panic!("bundle declarations did not converge")
}

fn decoded_bundle_items(bytes: &[u8]) -> Vec<Cbor> {
    let mut offsets = ItemOffsets::default();
    visit_logical_bundle(Cursor::new(bytes), &mut offsets, BundleLimits::HARD).unwrap();
    offsets
        .0
        .iter()
        .map(|item| {
            decode_canonical(
                &bytes[item.offset..item.offset + item.bytes],
                Limits::BUNDLE_ITEM,
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn embedded_bundle_object_refs_are_layer_one_but_standalone_refs_remain_layer_two() {
    let payload = b"authenticated envelope reference";
    let reference = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, payload).unwrap(),
    };
    let valid = reference.to_cbor();
    let mut missing_digest = valid.clone();
    let Cbor::Map(fields) = &mut missing_digest else {
        panic!("object reference")
    };
    fields.retain(|(key, _)| key != &Cbor::UInt(3));
    let mut wrong_algorithm = valid.clone();
    set_field(&mut wrong_algorithm, 2, Cbor::UInt(2));

    for invalid_kind in [0, u16::MAX as u64 + 1] {
        let mut invalid_reference = valid.clone();
        set_field(&mut invalid_reference, 1, Cbor::UInt(invalid_kind));
        let scratch = Scratch::new("object-ref-kind-domain-layer");
        let registry = Registry::bundled();
        let error = verify_logical_bundle_stream(
            Cursor::new(single_chunk_bundle_with_references(
                payload,
                invalid_reference,
                valid.clone(),
            )),
            LogicalBundleVerifyOptions::semantic(
                scratch.path(),
                &registry,
                Operation::ConformanceWrite,
            ),
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer),
            (ErrorCode::SchemaFieldInvalid, 1),
            "kind {invalid_kind}"
        );
        scratch.assert_empty();
    }

    let mut unknown_reference = valid.clone();
    set_field(&mut unknown_reference, 1, Cbor::UInt(99));
    set_field(
        &mut unknown_reference,
        3,
        Cbor::Bytes(opaque_object_digest(99, payload).unwrap().to_vec()),
    );
    let scratch = Scratch::new("object-ref-unknown-kind-layer");
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(single_chunk_bundle_with_references(
            payload,
            unknown_reference,
            valid.clone(),
        )),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::ObjectKindUnsupported, 2)
    );
    scratch.assert_empty();

    for (label, object_reference, root_reference, expected) in [
        (
            "object-ref-shape-layer",
            missing_digest.clone(),
            valid.clone(),
            ErrorCode::SchemaFieldInvalid,
        ),
        (
            "object-ref-algorithm-layer",
            wrong_algorithm.clone(),
            valid.clone(),
            ErrorCode::ObjectReferenceFormatUnsupported,
        ),
        (
            "root-ref-shape-layer",
            valid.clone(),
            missing_digest,
            ErrorCode::SchemaFieldInvalid,
        ),
        (
            "root-ref-algorithm-layer",
            valid.clone(),
            wrong_algorithm.clone(),
            ErrorCode::ObjectReferenceFormatUnsupported,
        ),
    ] {
        let scratch = Scratch::new(label);
        let registry = Registry::bundled();
        let error = verify_logical_bundle_stream(
            Cursor::new(single_chunk_bundle_with_references(
                payload,
                object_reference,
                root_reference,
            )),
            LogicalBundleVerifyOptions::semantic(
                scratch.path(),
                &registry,
                Operation::ConformanceWrite,
            ),
        )
        .unwrap_err();
        assert_eq!((error.code, error.layer), (expected, 1), "{label}");
        scratch.assert_empty();
    }

    let scratch = Scratch::new("object-payload-shape-layer");
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(single_chunk_bundle_with_item_payload(
            valid.clone(),
            valid.clone(),
            Cbor::Bool(false),
        )),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::SchemaFieldInvalid, 1)
    );
    scratch.assert_empty();

    let standalone = ObjectRef::from_cbor(&wrong_algorithm).unwrap_err();
    assert_eq!(
        (standalone.code, standalone.layer),
        (ErrorCode::ObjectReferenceFormatUnsupported, 2)
    );
}

#[test]
fn malformed_bundle_item_maps_are_sequence_errors_for_direct_and_spooled_readers() {
    let payload = b"authenticated malformed item";
    let reference = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, payload).unwrap(),
    };
    let role = ProfileRef::new("bundle-role.test", "root", 1).unwrap();
    let root = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(4)),
        (Cbor::UInt(2), Cbor::UInt(0)),
        (Cbor::UInt(3), Cbor::UInt(1)),
        (Cbor::UInt(4), reference.to_cbor()),
        (Cbor::UInt(5), role.to_cbor()),
    ]);
    let malformed = [
        ("non-map", Cbor::Bool(false)),
        (
            "undersized-map",
            Cbor::Map(vec![(Cbor::UInt(0), Cbor::UInt(1))]),
        ),
        (
            "unknown-item-type",
            Cbor::Map(vec![
                (Cbor::UInt(0), Cbor::UInt(1)),
                (Cbor::UInt(1), Cbor::UInt(99)),
            ]),
        ),
        (
            "wrong-field-count",
            Cbor::Map(vec![
                (Cbor::UInt(0), Cbor::UInt(1)),
                (Cbor::UInt(1), Cbor::UInt(2)),
                (Cbor::UInt(2), Cbor::UInt(0)),
                (Cbor::UInt(3), reference.to_cbor()),
            ]),
        ),
    ];
    let registry = Registry::bundled();
    for (label, item) in malformed {
        let mut visitor = ItemOffsets::default();
        let error = visit_logical_bundle(
            Cursor::new(encoded(&item)),
            &mut visitor,
            BundleLimits::HARD,
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer),
            (ErrorCode::BundleSequenceInvalid, 1),
            "direct {label}"
        );

        let scratch = Scratch::new(label);
        let error = verify_logical_bundle_stream(
            Cursor::new(authenticated_single_object_bundle(item, root.clone())),
            LogicalBundleVerifyOptions::semantic(
                scratch.path(),
                &registry,
                Operation::ConformanceWrite,
            ),
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer),
            (ErrorCode::BundleSequenceInvalid, 1),
            "spooled {label}"
        );
        scratch.assert_empty();
    }
}

#[test]
fn valid_vectors_match_cross_language_summaries() {
    let supplied = verify("valid-supplied-closure").unwrap();
    assert_eq!(supplied.highest_layer, 3);
    assert_eq!(supplied.bytes, 666);
    assert_eq!(supplied.items, 7);
    assert_eq!(supplied.object_count, 2);
    assert_eq!(supplied.logical_record_count, 1);
    assert_eq!(supplied.root_count, 2);
    assert_eq!(supplied.traversal_edges, 3);
    assert_eq!(supplied.index_entries, 3);
    assert_eq!(
        supplied.transcript_digest,
        hex("c302bd2f60d259e6859ce677e2d2f08133d53236abaa4de82c5fa868b020735c")
    );
    assert!(supplied.scratch.peak_scratch_bytes > supplied.bytes);
    assert!(supplied.scratch.scratch_files >= 8);

    let all = verify("valid-all-families").unwrap();
    assert_eq!(
        (
            all.bytes,
            all.items,
            all.object_count,
            all.logical_record_count,
            all.root_count,
            all.traversal_edges,
            all.index_entries,
        ),
        (9_056, 43, 12, 9, 20, 60, 21)
    );
    assert_eq!(
        all.transcript_digest,
        hex("5ad143d1abf6bffa643ad76316a92ecf43fcb4cf71dd444c19967158ea697542")
    );

    let empty = verify("scenario-bundle-zero-sections").unwrap();
    assert_eq!(
        (
            empty.bytes,
            empty.items,
            empty.object_count,
            empty.logical_record_count,
            empty.root_count,
            empty.traversal_edges,
            empty.index_entries,
        ),
        (77, 2, 0, 0, 0, 0, 0)
    );

    let disambiguated = verify("scenario-bundle-multi-root-disambiguation").unwrap();
    assert_eq!(
        (
            disambiguated.bytes,
            disambiguated.items,
            disambiguated.object_count,
            disambiguated.logical_record_count,
            disambiguated.root_count,
            disambiguated.traversal_edges,
            disambiguated.index_entries,
        ),
        (538, 6, 2, 0, 2, 2, 2)
    );
}

#[test]
fn supplied_closure_has_explicit_layer_two_and_semantic_entry_points() {
    let bytes = read("logical-bundles/valid-supplied-closure.cborseq");
    let scratch = Scratch::new("explicit-layer-two");
    let summary = verify_logical_bundle_stream(
        Cursor::new(bytes),
        LogicalBundleVerifyOptions::layer2(scratch.path()),
    )
    .unwrap();
    assert_eq!(summary.highest_layer, 2);
    scratch.assert_empty();

    let partial = Registry::load([], []).unwrap();
    let scratch = Scratch::new("partial-authority-preflight");
    let error = verify_logical_bundle_stream(
        MustNotRead,
        LogicalBundleVerifyOptions::semantic(scratch.path(), &partial, Operation::ConformanceWrite),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight,
        )
    );
    scratch.assert_empty();
}

#[test]
fn every_frozen_invalid_bundle_has_its_normative_error() {
    let cases = [
        ("invalid-section-order", ErrorCode::BundleSequenceInvalid),
        (
            "invalid-duplicate-identity",
            ErrorCode::BundleDuplicateIdentity,
        ),
        ("invalid-closure-missing", ErrorCode::BundleClosureMissing),
        ("invalid-closure-extra", ErrorCode::BundleClosureExtra),
        (
            "invalid-reference-wrong-kind",
            ErrorCode::ObjectReferenceKindMismatch,
        ),
        ("invalid-trailer-mismatch", ErrorCode::BundleTrailerMismatch),
        ("scenario-bundle-budget", ErrorCode::BundleBudgetExceeded),
        ("scenario-bundle-count", ErrorCode::BundleSequenceInvalid),
        ("scenario-bundle-eof", ErrorCode::BundleSequenceInvalid),
        ("scenario-bundle-mode", ErrorCode::BundleModeUnsupported),
        ("scenario-bundle-object-id", ErrorCode::ObjectIdMismatch),
        ("scenario-bundle-ordinal", ErrorCode::BundleSequenceInvalid),
        (
            "scenario-bundle-record-id",
            ErrorCode::BundleRecordIdMismatch,
        ),
        ("scenario-bundle-root-invalid", ErrorCode::BundleRootInvalid),
    ];
    for (name, expected) in cases {
        assert_eq!(verify(name).unwrap_err(), expected, "{name}");
    }
}

#[test]
fn missing_required_object_or_logical_root_is_a_layer_two_shape_failure() {
    let scratch = Scratch::new("bundle-root-layer");
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(read("logical-bundles/scenario-bundle-root-invalid.cborseq")),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::BundleRootInvalid,
            2,
            ValidationStage::ClosureAndReferenceResolution
        )
    );
    scratch.assert_empty();
}

#[test]
fn sequence_order_failure_outranks_an_earlier_duplicate_identity() {
    let original = read("logical-bundles/valid-all-families.cborseq");
    let mut offsets = ItemOffsets::default();
    visit_logical_bundle(Cursor::new(&original), &mut offsets, BundleLimits::HARD).unwrap();
    let mut values: Vec<Cbor> = offsets
        .0
        .iter()
        .map(|item| {
            decode_canonical(
                &original[item.offset..item.offset + item.bytes],
                Limits::BUNDLE_ITEM,
            )
            .unwrap()
        })
        .collect();

    let first_reference = field(&values[1], 3);
    let first_payload = field(&values[1], 4);
    set_field(&mut values[2], 3, first_reference);
    set_field(&mut values[2], 4, first_payload);
    let third_reference = field(&values[3], 3);
    let third_payload = field(&values[3], 4);
    let fourth_reference = field(&values[4], 3);
    let fourth_payload = field(&values[4], 4);
    set_field(&mut values[3], 3, fourth_reference);
    set_field(&mut values[3], 4, fourth_payload);
    set_field(&mut values[4], 3, third_reference);
    set_field(&mut values[4], 4, third_payload);

    let changed: Vec<u8> = values.iter().flat_map(encoded).collect();
    let scratch = Scratch::new("sequence-before-duplicate");
    let registry = Registry::bundled();
    assert_eq!(
        verify_logical_bundle_stream(
            Cursor::new(changed),
            LogicalBundleVerifyOptions::semantic(
                scratch.path(),
                &registry,
                Operation::ConformanceWrite
            ),
        )
        .unwrap_err()
        .code,
        ErrorCode::BundleSequenceInvalid
    );
    scratch.assert_empty();
}

#[test]
fn sequence_order_failure_outranks_too_small_sender_declarations() {
    let original = read("logical-bundles/valid-all-families.cborseq");
    let mut offsets = ItemOffsets::default();
    visit_logical_bundle(Cursor::new(&original), &mut offsets, BundleLimits::HARD).unwrap();
    let mut values: Vec<Cbor> = offsets
        .0
        .iter()
        .map(|item| {
            decode_canonical(
                &original[item.offset..item.offset + item.bytes],
                Limits::BUNDLE_ITEM,
            )
            .unwrap()
        })
        .collect();

    let mut declared = field(&values[0], 6);
    set_field(&mut declared, 0, Cbor::UInt(0));
    set_field(&mut values[0], 6, declared);
    values.swap(1, 2);

    let changed: Vec<u8> = values.iter().flat_map(encoded).collect();
    let scratch = Scratch::new("sequence-before-declared-budget");
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(changed),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer),
        (ErrorCode::BundleSequenceInvalid, 1)
    );
    scratch.assert_empty();
}

#[test]
fn opaque_sequence_pass_outranks_object_ref_and_root_schema_failures() {
    let original = read("logical-bundles/valid-all-families.cborseq");
    let mut values = decoded_bundle_items(&original);
    let mut unsupported = field(&values[1], 3);
    set_field(&mut unsupported, 2, Cbor::UInt(2));
    set_field(&mut values[1], 3, unsupported);
    let left_reference = field(&values[2], 3);
    let left_payload = field(&values[2], 4);
    let right_reference = field(&values[3], 3);
    let right_payload = field(&values[3], 4);
    assert!(encoded(&left_reference) < encoded(&right_reference));
    set_field(&mut values[2], 3, right_reference);
    set_field(&mut values[2], 4, right_payload);
    set_field(&mut values[3], 3, left_reference);
    set_field(&mut values[3], 4, left_payload);
    let scratch = Scratch::new("opaque-ref-before-reversal");
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(values.iter().flat_map(encoded).collect::<Vec<_>>()),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::BundleSequenceInvalid,
            1,
            ValidationStage::SequenceShapeAndOrder
        )
    );
    scratch.assert_empty();

    let payload = b"root-stage-order";
    let reference = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: object_id(ObjectKind::Chunk, payload).unwrap(),
    };
    let original = single_chunk_bundle(payload);
    let mut stale = decoded_bundle_items(&original);
    set_field(&mut stale[2], 3, Cbor::UInt(99));
    let scratch = Scratch::new("invalid-root-before-stale-trailer");
    let error = verify_logical_bundle_stream(
        Cursor::new(stale.iter().flat_map(encoded).collect::<Vec<_>>()),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::BundleTrailerMismatch,
            1,
            ValidationStage::TranscriptAuthentication
        )
    );
    scratch.assert_empty();

    let mut duplicate = decoded_bundle_items(&single_chunk_bundle_with_references(
        payload,
        reference.to_cbor(),
        reference.to_cbor(),
    ));
    set_field(&mut duplicate[0], 5, Cbor::UInt(2));
    set_field(&mut duplicate[2], 3, Cbor::UInt(99));
    let mut second_root = duplicate[2].clone();
    set_field(&mut second_root, 2, Cbor::UInt(1));
    duplicate.insert(3, second_root);
    set_field(&mut duplicate[4], 4, Cbor::UInt(2));
    set_field(&mut duplicate[4], 5, Cbor::UInt(5));
    let authenticated = reauthenticate_with_actual_declarations(&mut duplicate);
    let scratch = Scratch::new("invalid-root-before-duplicate");
    let error = verify_logical_bundle_stream(
        Cursor::new(authenticated),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::BundleDuplicateIdentity,
            1,
            ValidationStage::SequenceShapeAndOrder
        )
    );
    scratch.assert_empty();
}

#[test]
fn known_schema_errors_are_ranked_across_all_authenticated_objects() {
    let original = read("logical-bundles/valid-all-families.cborseq");
    let mut values = decoded_bundle_items(&original);
    let mut descriptor = decode_canonical(
        &read("objects/06-repository-descriptor.cbor"),
        Limits::METADATA,
    )
    .unwrap();
    let mut invalid = descriptor.clone();
    set_field(&mut invalid, 16, Cbor::UInt(0));
    let invalid_payload = encoded(&invalid);
    let invalid_reference = ObjectRef {
        kind: ObjectKind::RepositoryDescriptor,
        digest: object_id(ObjectKind::RepositoryDescriptor, &invalid_payload).unwrap(),
    };
    let (unknown_payload, unknown_reference) = (0u64..)
        .find_map(|nonce| {
            let Cbor::Map(fields) = &mut descriptor else {
                unreachable!()
            };
            fields.retain(|(key, _)| key != &Cbor::UInt(4_095));
            fields.push((Cbor::UInt(4_095), Cbor::UInt(nonce)));
            let payload = encoded(&descriptor);
            let reference = ObjectRef {
                kind: ObjectKind::RepositoryDescriptor,
                digest: object_id(ObjectKind::RepositoryDescriptor, &payload).unwrap(),
            };
            (encoded(&reference.to_cbor()) < encoded(&invalid_reference.to_cbor()))
                .then_some((payload, reference))
        })
        .expect("a deterministic unknown-field digest sorts first");
    let object_item = |reference: ObjectRef, payload: Vec<u8>| {
        Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(2)),
            (Cbor::UInt(2), Cbor::UInt(0)),
            (Cbor::UInt(3), reference.to_cbor()),
            (Cbor::UInt(4), Cbor::Bytes(payload)),
        ])
    };
    values[1] = object_item(unknown_reference, unknown_payload);
    values[2] = object_item(invalid_reference, invalid_payload);
    let object_count = match field(&values[0], 3) {
        Cbor::UInt(count) => count as usize,
        _ => unreachable!(),
    };
    values[1..=object_count].sort_by_key(|item| encoded(&field(item, 3)));
    for (ordinal, item) in values[1..=object_count].iter_mut().enumerate() {
        set_field(item, 2, Cbor::UInt(ordinal as u64));
    }
    let authenticated = reauthenticate_with_actual_declarations(&mut values);
    let scratch = Scratch::new("bundle-wide-known-schema-ranking");
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(authenticated),
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            2,
            ValidationStage::KnownSchema
        )
    );
    scratch.assert_empty();
}

#[test]
fn authenticated_declared_accounting_outranks_closure_and_deferred_registry_errors() {
    let original = read("logical-bundles/valid-supplied-closure.cborseq");
    let mut offsets = ItemOffsets::default();
    visit_logical_bundle(Cursor::new(&original), &mut offsets, BundleLimits::HARD).unwrap();
    let values = offsets
        .0
        .iter()
        .map(|item| {
            decode_canonical(
                &original[item.offset..item.offset + item.bytes],
                Limits::BUNDLE_ITEM,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    for label in ["closure", "registry"] {
        let mut changed = values.clone();
        let mut declarations = field(&changed[0], 6);
        set_field(&mut declarations, 3, Cbor::UInt(0));
        set_field(&mut changed[0], 6, declarations);
        let root = changed
            .iter_mut()
            .find(|item| field(item, 1) == Cbor::UInt(4))
            .unwrap();
        if label == "closure" {
            let mut missing = ObjectRef::from_cbor(&field(root, 4)).unwrap();
            missing.digest = [0xff; 32];
            set_field(root, 4, missing.to_cbor());
        } else {
            set_field(
                root,
                5,
                ProfileRef::new("bundle-role.test", "unknown", 1)
                    .unwrap()
                    .to_cbor(),
            );
        }
        let authenticated = reauthenticate_items(&mut changed);
        let scratch = Scratch::new(&format!("declared-before-{label}"));
        let registry = Registry::bundled();
        let error = verify_logical_bundle_stream(
            Cursor::new(authenticated),
            LogicalBundleVerifyOptions::semantic(
                scratch.path(),
                &registry,
                Operation::ConformanceWrite,
            ),
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer, error.stage),
            (
                ErrorCode::BundleBudgetExceeded,
                1,
                ValidationStage::DeclaredAccounting
            ),
            "{label}"
        );
        scratch.assert_empty();
    }
}

#[test]
fn selected_header_identity_payload_and_trailer_mutations_never_validate() {
    let original = read("logical-bundles/valid-supplied-closure.cborseq");
    let registry = Registry::bundled();
    let positions = [
        0,
        24,
        96,
        original.len() / 2,
        original.len() - 34,
        original.len() - 1,
    ];
    for position in positions {
        let scratch = Scratch::new("mutation");
        let mut changed = original.clone();
        changed[position] ^= 1;
        assert!(
            verify_logical_bundle_stream(
                Cursor::new(changed),
                LogicalBundleVerifyOptions::semantic(
                    scratch.path(),
                    &registry,
                    Operation::ConformanceWrite
                ),
            )
            .is_err(),
            "mutation at {position}"
        );
        scratch.assert_empty();
    }
}

#[test]
fn file_entry_point_and_all_proper_prefixes_are_bounded_and_cleaned() {
    let source = format!("{VECTOR_ROOT}/logical-bundles/valid-supplied-closure.cborseq");
    let scratch = Scratch::new("file");
    let registry = Registry::bundled();
    let result = verify_logical_bundle_file(
        source,
        LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap();
    assert_eq!(result.bytes, 666);
    scratch.assert_empty();

    let bytes = read("logical-bundles/valid-supplied-closure.cborseq");
    for prefix in 1..bytes.len() {
        let scratch = Scratch::new("prefix");
        let error = verify_logical_bundle_stream(
            Cursor::new(&bytes[..prefix]),
            LogicalBundleVerifyOptions::semantic(
                scratch.path(),
                &registry,
                Operation::ConformanceWrite,
            ),
        )
        .unwrap_err();
        assert!(
            matches!(
                error.code,
                ErrorCode::CborTruncated | ErrorCode::BundleSequenceInvalid
            ),
            "prefix {prefix}: {}",
            error.code.as_str()
        );
        scratch.assert_empty();
    }
}

#[test]
fn configured_memory_scratch_time_and_sequence_limits_are_typed_and_cleaned() {
    let bytes = read("logical-bundles/valid-supplied-closure.cborseq");
    let registry = Registry::bundled();

    let scratch = Scratch::new("memory-limit");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_decoded_item_bytes = 32;
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(&bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::LimitMemory
    );
    scratch.assert_empty();

    for (label, configure) in [
        ("object-limit", 0u8),
        ("traversal-limit", 1u8),
        ("index-limit", 2u8),
    ] {
        let scratch = Scratch::new(label);
        let mut options = LogicalBundleVerifyOptions::semantic(
            scratch.path(),
            &registry,
            Operation::ConformanceWrite,
        );
        match configure {
            0 => options.limits.objects = 1,
            1 => options.limits.traversal_edges = 2,
            _ => options.limits.index_entries = 2,
        }
        assert_eq!(
            verify_logical_bundle_stream(Cursor::new(&bytes), options)
                .unwrap_err()
                .code,
            ErrorCode::BundleBudgetExceeded,
            "{label}"
        );
        scratch.assert_empty();
    }

    let scratch = Scratch::new("scratch-limit");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_scratch_bytes = 64;
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(&bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::LimitScratch
    );
    scratch.assert_empty();

    let scratch = Scratch::new("time-limit");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_elapsed = Some(Duration::ZERO);
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(&bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::LimitTime
    );
    scratch.assert_empty();

    let scratch = Scratch::new("base-memory-limit");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_memory_bytes = 4_095;
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(&bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::LimitMemory
    );
    scratch.assert_empty();

    let scratch = Scratch::new("sequence-limit");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.sequence_bytes = bytes.len() as u64 - 1;
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(&bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::BundleBudgetExceeded
    );
    scratch.assert_empty();
}

#[test]
fn compact_item_decode_uses_only_memory_remaining_after_spool_buffers() {
    // One-byte integer encodings expand to owned enum slots. The decoded
    // metadata value fits the nominal 80 KiB ceiling alone, but not alongside
    // the live sorter, read buffers, spooled payload, and scanner raw copy.
    let payload = encoded(&Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(6)),
        (Cbor::UInt(2), Cbor::Array(Vec::new())),
        (Cbor::UInt(4_095), Cbor::Array(vec![Cbor::UInt(0); 1_000])),
    ]));
    let reference = ObjectRef {
        kind: ObjectKind::RepositoryDescriptor,
        digest: object_id(ObjectKind::RepositoryDescriptor, &payload).unwrap(),
    };
    let object = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(2)),
        (Cbor::UInt(2), Cbor::UInt(0)),
        (Cbor::UInt(3), reference.to_cbor()),
        (Cbor::UInt(4), Cbor::Bytes(payload)),
    ]);
    let root = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(4)),
        (Cbor::UInt(2), Cbor::UInt(0)),
        (Cbor::UInt(3), Cbor::UInt(1)),
        (Cbor::UInt(4), reference.to_cbor()),
        (
            Cbor::UInt(5),
            ProfileRef::new("bundle-role.test", "root", 1)
                .unwrap()
                .to_cbor(),
        ),
    ]);
    let authenticated = authenticated_single_object_bundle(object, root);

    let scratch = Scratch::new("compact-item-memory");
    let registry = Registry::bundled();
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_memory_bytes = 80_000;
    options.limits.max_run_bytes = 4_096;
    options.limits.max_open_runs = 2;
    options.limits.read_chunk_bytes = 1_024;
    options.limits.max_decoded_item_bytes = 8_192;
    let error = verify_logical_bundle_stream(Cursor::new(authenticated), options).unwrap_err();
    assert_eq!((error.code, error.layer), (ErrorCode::LimitMemory, 1));
    scratch.assert_empty();
}

#[test]
fn verifier_checks_elapsed_time_after_a_slow_returning_read() {
    let bytes = read("logical-bundles/scenario-bundle-zero-sections.cborseq");
    let calls = Rc::new(Cell::new(0));
    let reader = SlowReturningReader {
        inner: Cursor::new(bytes),
        calls: calls.clone(),
    };
    let scratch = Scratch::new("slow-returning-read");
    let registry = Registry::bundled();
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_elapsed = Some(Duration::from_millis(25));
    let error = verify_logical_bundle_stream(reader, options).unwrap_err();
    assert!(calls.get() > 0);
    assert_eq!((error.code, error.layer), (ErrorCode::LimitTime, 1));
    scratch.assert_empty();
}

#[test]
fn chunk_payloads_stream_without_consuming_the_decoded_item_budget() {
    let payload = vec![0x5a; 128 * 1024];
    let bundle = single_chunk_bundle(&payload);
    let scratch = Scratch::new("streamed-chunk");
    let registry = Registry::bundled();
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_decoded_item_bytes = 128;
    options.limits.max_scratch_bytes = 2 * 1024 * 1024;
    let summary = verify_logical_bundle_stream(Cursor::new(bundle), options).unwrap();
    assert_eq!(summary.object_count, 1);
    assert_eq!(summary.traversal_edges, 0);
    scratch.assert_empty();
}

#[test]
fn production_mode_rejects_conformance_only_bundle_profiles() {
    let bytes = read("logical-bundles/valid-supplied-closure.cborseq");
    let scratch = Scratch::new("production-profile");
    let registry = Registry::bundled();
    let options =
        LogicalBundleVerifyOptions::semantic(scratch.path(), &registry, Operation::ProductionWrite);
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::ProfileConformanceOnly
    );
    scratch.assert_empty();
}

#[test]
fn invalid_limit_configuration_is_not_treated_as_input_failure() {
    let bytes = read("logical-bundles/scenario-bundle-zero-sections.cborseq");
    let registry = Registry::bundled();
    let scratch = Scratch::new("bad-config");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits = LogicalBundleVerifyLimits {
        max_open_runs: 1,
        ..LogicalBundleVerifyLimits::default()
    };
    assert_eq!(
        verify_logical_bundle_stream(Cursor::new(bytes), options)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );
    scratch.assert_empty();

    assert_eq!(
        LogicalBundleVerifyLimits::default().max_decoded_item_bytes,
        29_242_720
    );

    let scratch = Scratch::new("open-run-cap");
    let mut options = LogicalBundleVerifyOptions::semantic(
        scratch.path(),
        &registry,
        Operation::ConformanceWrite,
    );
    options.limits.max_open_runs = usize::MAX;
    verify_logical_bundle_stream(
        Cursor::new(read(
            "logical-bundles/scenario-bundle-zero-sections.cborseq",
        )),
        options,
    )
    .unwrap();
    scratch.assert_empty();
}

#[cfg(unix)]
#[test]
fn symlink_scratch_roots_are_rejected_without_touching_the_target() {
    use std::os::unix::fs::symlink;

    let target = Scratch::new("symlink-target");
    let link_parent = Scratch::new("symlink-parent");
    let link = link_parent.path().join("scratch-link");
    symlink(target.path(), &link).unwrap();
    let registry = Registry::bundled();
    let error = verify_logical_bundle_stream(
        Cursor::new(read(
            "logical-bundles/scenario-bundle-zero-sections.cborseq",
        )),
        LogicalBundleVerifyOptions::semantic(&link, &registry, Operation::ConformanceWrite),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );
    target.assert_empty();
    fs::remove_file(link).unwrap();
}

#[cfg(unix)]
#[test]
fn symlink_bundle_files_are_not_followed() {
    use std::os::unix::fs::symlink;

    let directory = Scratch::new("input-symlink");
    let scratch_path = directory.path().join("scratch");
    fs::create_dir(&scratch_path).unwrap();
    let target = directory.path().join("target.cborseq");
    let link = directory.path().join("link.cborseq");
    fs::write(
        &target,
        read("logical-bundles/scenario-bundle-zero-sections.cborseq"),
    )
    .unwrap();
    symlink(&target, &link).unwrap();
    let registry = Registry::bundled();
    let error = verify_logical_bundle_file(
        &link,
        LogicalBundleVerifyOptions::semantic(&scratch_path, &registry, Operation::ConformanceWrite),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );
    fs::remove_file(link).unwrap();
    fs::remove_file(target).unwrap();
    fs::remove_dir(scratch_path).unwrap();
    directory.assert_empty();
}

#[test]
fn file_and_scratch_boundaries_are_configured_resource_preflight() {
    let directory = Scratch::new("file-and-scratch-boundaries");
    let scratch_path = directory.path().join("scratch");
    fs::create_dir(&scratch_path).unwrap();
    let registry = Registry::bundled();
    for path in [
        directory.path().join("missing.cborseq"),
        directory.path().to_owned(),
    ] {
        let error = verify_logical_bundle_file(
            path,
            LogicalBundleVerifyOptions::semantic(
                &scratch_path,
                &registry,
                Operation::ConformanceWrite,
            ),
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer, error.stage),
            (
                ErrorCode::SchemaFieldInvalid,
                1,
                ValidationStage::ConfiguredResourcePreflight
            )
        );
    }

    let missing_scratch = directory.path().join("missing-scratch");
    let error = verify_logical_bundle_stream(
        Cursor::new(read(
            "logical-bundles/scenario-bundle-zero-sections.cborseq",
        )),
        LogicalBundleVerifyOptions::semantic(
            &missing_scratch,
            &registry,
            Operation::ConformanceWrite,
        ),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.layer, error.stage),
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight
        )
    );
    fs::remove_dir(scratch_path).unwrap();
    directory.assert_empty();
}
