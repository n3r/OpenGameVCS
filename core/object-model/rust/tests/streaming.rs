use std::io::{self, Cursor, Read, Write};

use ogvcs_object_model::*;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn read_vector(relative: &str) -> Vec<u8> {
    std::fs::read(format!("{VECTOR_ROOT}/{relative}")).unwrap()
}

#[derive(Default)]
struct PartialWriter {
    bytes: Vec<u8>,
    largest: usize,
}

impl Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(997);
        self.largest = self.largest.max(count);
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ChunkedRead<R> {
    inner: R,
    maximum: usize,
}

impl<R: Read> Read for ChunkedRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(self.maximum);
        self.inner.read(&mut bytes[..length])
    }
}

#[test]
fn streaming_encoder_matches_collector_without_output_accumulation() {
    let value = Cbor::Map(vec![
        (
            Cbor::UInt(24),
            Cbor::Bytes((0..200_000).map(|i| (i % 251) as u8).collect()),
        ),
        (
            Cbor::UInt(1),
            Cbor::Array(vec![
                Cbor::Bool(true),
                Cbor::Text("streaming".into()),
                Cbor::Map(vec![
                    (Cbor::UInt(0), Cbor::NInt(-12)),
                    (Cbor::UInt(1), Cbor::UInt(1 << 54)),
                ]),
            ]),
        ),
    ]);
    let expected = encode_canonical(&value).unwrap();
    let mut writer = PartialWriter::default();
    let written = encode_canonical_to(&value, &mut writer, Limits::METADATA).unwrap();
    assert_eq!(written, expected.len());
    assert_eq!(writer.bytes, expected);
    assert!(writer.largest <= 997);

    let reduced = Limits {
        max_input_bytes: expected.len() - 1,
        ..Limits::METADATA
    };
    assert_eq!(
        encode_canonical_to(&value, io::sink(), reduced)
            .unwrap_err()
            .code,
        ErrorCode::LimitMetadataBytes
    );
}

#[test]
fn streaming_encoder_preflights_all_format_and_working_set_failures() {
    let invalid_negative = Cbor::Array(vec![Cbor::UInt(1), Cbor::NInt(0)]);
    let mut output = Vec::new();
    assert_eq!(
        encode_canonical_to(&invalid_negative, &mut output, Limits::METADATA)
            .unwrap_err()
            .code,
        ErrorCode::SchemaFieldInvalid
    );
    assert!(output.is_empty());

    let mut deep_key = Cbor::UInt(0);
    for _ in 0..16 {
        deep_key = Cbor::Array(vec![deep_key]);
    }
    let deep_map_key = Cbor::Map(vec![(deep_key, Cbor::Bool(true))]);
    assert_eq!(
        encode_canonical_to(
            &deep_map_key,
            &mut output,
            Limits {
                max_nesting: 4,
                ..Limits::METADATA
            },
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitNesting
    );
    assert!(output.is_empty());

    let duplicate_nested_key = Cbor::Array(vec![
        Cbor::UInt(1),
        Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(0), Cbor::UInt(2)),
        ]),
    ]);
    assert_eq!(
        encode_canonical_to(&duplicate_nested_key, &mut output, Limits::METADATA,)
            .unwrap_err()
            .code,
        ErrorCode::CborNonCanonical
    );
    assert!(output.is_empty());

    let oversized = Cbor::Array(vec![Cbor::Bytes(vec![0; 32])]);
    assert_eq!(
        encode_canonical_to(
            &oversized,
            &mut output,
            Limits {
                max_input_bytes: 8,
                ..Limits::METADATA
            },
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitMetadataBytes
    );
    assert!(output.is_empty());

    let key_heavy = Cbor::Map(vec![
        (Cbor::Bytes(vec![1; 8]), Cbor::UInt(1)),
        (Cbor::Bytes(vec![2; 8]), Cbor::UInt(2)),
    ]);
    assert_eq!(
        encode_canonical_to(
            &key_heavy,
            &mut output,
            Limits {
                max_working_bytes: 128,
                ..Limits::METADATA
            },
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitMemory
    );
    assert!(output.is_empty());

    let nested_keys = Cbor::Map(vec![(
        Cbor::UInt(0),
        Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::Bool(true)),
            (Cbor::UInt(1), Cbor::Bool(false)),
        ]),
    )]);
    assert_eq!(
        encode_canonical_to(
            &nested_keys,
            &mut output,
            Limits {
                max_working_bytes: 150,
                ..Limits::METADATA
            },
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitMemory
    );
    assert!(output.is_empty());

    let retained = encode_canonical(&Cbor::Array(vec![Cbor::UInt(1); 20])).unwrap();
    assert_eq!(
        decode_canonical(
            &retained,
            Limits {
                max_working_bytes: 1,
                ..Limits::METADATA
            },
        )
        .unwrap_err()
        .code,
        ErrorCode::LimitMemory
    );
}

#[test]
fn all_incremental_hash_writers_are_chunk_boundary_invariant() {
    let payload: Vec<u8> = (0..262_177)
        .map(|index| ((index * 17) % 251) as u8)
        .collect();
    for size in [1, 3, 63, 64, 65, 4093] {
        let mut writer = Sha256Writer::new();
        for chunk in payload.chunks(size) {
            writer.update(chunk);
        }
        assert_eq!(writer.finish(), sha256(&payload));
    }

    let mut bundle = BundleTranscriptHashWriter::new(2_199_023_255_552);
    for chunk in payload.chunks(31) {
        bundle.update(chunk).unwrap();
    }
    let streamed = *bundle.finish().unwrap().digest();
    let mut whole = BundleTranscriptHashWriter::new(2_199_023_255_552);
    whole.update(&payload).unwrap();
    assert_eq!(streamed, *whole.finish().unwrap().digest());
}

#[test]
fn durable_hashing_is_registered_and_discriminator_bound() {
    let tree = read_vector("objects/03-tree.cbor");
    let decoded = decode_canonical(&tree, Limits::METADATA).unwrap();
    let mut reencoded = Vec::new();
    encode_canonical_to(&decoded, &mut reencoded, Limits::METADATA).unwrap();
    assert_eq!(reencoded, tree);
    let expected = object_id(ObjectKind::Tree, &tree).unwrap();
    let mut writer = ObjectHashWriter::new(ObjectKind::Tree, 67_108_864, 536_870_912);
    for chunk in tree.chunks(7) {
        writer.update(chunk).unwrap();
    }
    assert_eq!(writer.finish().unwrap().digest, expected);

    let mut wrong = ObjectHashWriter::new(ObjectKind::ContentManifest, 67_108_864, 536_870_912);
    wrong.update(&tree).unwrap();
    assert_eq!(
        wrong.finish().unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );

    let opaque = opaque_object_digest(65_535, &tree).unwrap();
    assert_ne!(opaque, expected);
    assert_eq!(
        OpaqueObjectHashWriter::new(0, 1024).err().unwrap().code,
        ErrorCode::SchemaFieldInvalid
    );

    let logical = read_vector("logical-records/02-mutable-ref.cbor");
    let expected = logical_record_id(2, &logical).unwrap();
    let mut logical_writer = LogicalRecordHashWriter::new(2, 536_870_912).unwrap();
    for chunk in logical.chunks(3) {
        logical_writer.update(chunk).unwrap();
    }
    assert_eq!(*logical_writer.finish().unwrap().digest(), expected);
    assert_eq!(
        LogicalRecordHashWriter::new(42, 1024).err().unwrap().code,
        ErrorCode::LogicalRecordTypeUnsupported
    );
    let mut wrong_logical = LogicalRecordHashWriter::new(1, 1024 * 1024).unwrap();
    wrong_logical.update(&logical).unwrap();
    assert_eq!(
        wrong_logical.finish().unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[derive(Default)]
struct CountingVisitor {
    payload: usize,
    largest: usize,
}

impl BundleVisitor for CountingVisitor {
    fn object_payload_chunk(&mut self, _index: usize, _kind: u16, bytes: &[u8]) -> Result<()> {
        self.payload += bytes.len();
        self.largest = self.largest.max(bytes.len());
        Ok(())
    }
}

fn object_item(kind: u64, payload: Vec<u8>) -> Vec<u8> {
    let value = Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(2)),
        (Cbor::UInt(2), Cbor::UInt(0)),
        (
            Cbor::UInt(3),
            Cbor::Map(vec![
                (Cbor::UInt(0), Cbor::UInt(1)),
                (Cbor::UInt(1), Cbor::UInt(kind)),
                (Cbor::UInt(2), Cbor::UInt(1)),
                (Cbor::UInt(3), Cbor::Bytes(vec![0; 32])),
            ]),
        ),
        (Cbor::UInt(4), Cbor::Bytes(payload)),
    ]);
    encode_canonical_with_limits(&value, Limits::BUNDLE_ITEM).unwrap()
}

fn declared_object_item(kind: u64, length: u32) -> Vec<u8> {
    let reference = encode_canonical(&Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(kind)),
        (Cbor::UInt(2), Cbor::UInt(1)),
        (Cbor::UInt(3), Cbor::Bytes(vec![0; 32])),
    ]))
    .unwrap();
    let mut out = vec![0xa5, 0x00, 0x01, 0x01, 0x02, 0x02, 0x00, 0x03];
    out.extend_from_slice(&reference);
    out.extend_from_slice(&[0x04, 0x5a]);
    out.extend_from_slice(&length.to_be_bytes());
    out
}

fn nested_map_key_item(depth: usize) -> Vec<u8> {
    let mut value = Cbor::UInt(0);
    for _ in 0..depth {
        value = Cbor::Map(vec![(value, Cbor::UInt(0))]);
    }
    encode_canonical_with_limits(
        &Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(3)),
            (Cbor::UInt(2), Cbor::UInt(0)),
            (Cbor::UInt(3), Cbor::Bytes(vec![0; 32])),
            (Cbor::UInt(4), value),
        ]),
        Limits::BUNDLE_ITEM,
    )
    .unwrap()
}

#[test]
fn bundle_reader_admits_aggregate_nested_map_key_capture_capacity_before_allocation() {
    let encoded = nested_map_key_item(8);
    let reduced = BundleLimits {
        max_value_bytes: 64,
        max_capture_bytes: 511,
        max_nesting: 10,
        ..BundleLimits::HARD
    };
    let mut visitor = CountingVisitor::default();
    let error = visit_logical_bundle(Cursor::new(&encoded), &mut visitor, reduced).unwrap_err();
    assert_eq!(error.code, ErrorCode::LimitMemory);
    assert_eq!(error.layer, 1);
    assert_eq!(error.stage, ValidationStage::ConfiguredResourcePreflight);

    let admitted = BundleLimits {
        max_capture_bytes: 512,
        ..reduced
    };
    assert_eq!(
        visit_logical_bundle(Cursor::new(&encoded), &mut visitor, admitted).unwrap(),
        BundleSummary {
            items: 1,
            bytes: encoded.len(),
        }
    );
}

#[test]
fn bundle_read_visitor_streams_payload_and_distinguishes_contextual_limits() {
    let payload: Vec<u8> = (0..170_000).map(|index| (index % 251) as u8).collect();
    let encoded = object_item(1, payload.clone());
    let reader = ChunkedRead {
        inner: Cursor::new(&encoded),
        maximum: 4093,
    };
    let mut visitor = CountingVisitor::default();
    assert_eq!(
        visit_logical_bundle(reader, &mut visitor, BundleLimits::HARD).unwrap(),
        BundleSummary {
            items: 1,
            bytes: encoded.len()
        }
    );
    assert_eq!(visitor.payload, payload.len());
    assert!(visitor.largest <= 65_536);

    let over_chunk = declared_object_item(1, 67_108_865);
    let mut visitor = CountingVisitor::default();
    assert_eq!(
        visit_logical_bundle(Cursor::new(over_chunk), &mut visitor, BundleLimits::HARD)
            .unwrap_err()
            .code,
        ErrorCode::CborTruncated
    );

    let metadata = declared_object_item(2, 67_108_865);
    assert_eq!(
        visit_logical_bundle(Cursor::new(&metadata), &mut visitor, BundleLimits::HARD)
            .unwrap_err()
            .code,
        ErrorCode::CborTruncated
    );
    let reduced = BundleLimits {
        max_metadata_bytes: 1024,
        ..BundleLimits::HARD
    };
    assert_eq!(
        visit_logical_bundle(Cursor::new(metadata), &mut visitor, reduced)
            .unwrap_err()
            .code,
        ErrorCode::CborTruncated
    );
}
