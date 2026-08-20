use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

use ogvcs_object_model::{
    logical_record_id, object_id, scan_metadata, validate_logical_record, validate_metadata_schema,
    verify_logical_bundle_stream, visit_logical_bundle, BundleItemInfo, BundleLimits,
    BundleTranscriptHashWriter, BundleVisitor, ErrorCode, Limits, LogicalBundleVerifyOptions,
    ObjectKind, Operation, Registry,
};
use serde_json::{json, Value};

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

fn read(relative: &str) -> Vec<u8> {
    fs::read(format!("{VECTOR_ROOT}/{relative}")).unwrap()
}

fn document(relative: &str) -> Value {
    serde_json::from_slice(&read(relative)).unwrap()
}

fn hex(text: &str) -> [u8; 32] {
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("non-lowercase-hex identity"),
        };
        *slot = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn mutate(original: &[u8], byte_offset: usize, bit_index: u8) -> Vec<u8> {
    assert!(byte_offset < original.len());
    assert!(bit_index < 8);
    let mut changed = original.to_vec();
    changed[byte_offset] ^= 1 << bit_index;
    assert_eq!(changed[byte_offset] ^ original[byte_offset], 1 << bit_index);
    changed
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let suffix = hex_lower(&nonce);
        let path = std::env::temp_dir().join(format!("ogvcs-mutation-baseline-{suffix}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

#[derive(Default)]
struct ItemCapture {
    items: Vec<BundleItemInfo>,
}

impl BundleVisitor for ItemCapture {
    fn item_end(&mut self, info: BundleItemInfo) -> ogvcs_object_model::Result<()> {
        self.items.push(info);
        Ok(())
    }
}

#[derive(Clone)]
struct FrozenBundle {
    items: Vec<BundleItemInfo>,
    header: Vec<u8>,
    trailer: Vec<u8>,
    transcript: [u8; 32],
    bytes: usize,
}

impl FrozenBundle {
    fn from_validated(bytes: &[u8]) -> Self {
        let registry = Registry::bundled();
        let scratch = Scratch::new();
        let verified = verify_logical_bundle_stream(
            Cursor::new(bytes),
            LogicalBundleVerifyOptions::semantic(scratch.path(), &registry, Operation::ConformanceWrite),
        )
        .unwrap();
        assert_eq!(verified.bytes as usize, bytes.len());
        assert_eq!(verified.items, 7);
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);

        let mut capture = ItemCapture::default();
        let framed =
            visit_logical_bundle(Cursor::new(bytes), &mut capture, BundleLimits::HARD).unwrap();
        assert_eq!(framed.items, capture.items.len());
        assert_eq!(framed.bytes, bytes.len());
        let header = capture.items[0];
        let trailer = *capture.items.last().unwrap();
        assert_eq!(header.item_type, 1);
        assert_eq!(trailer.item_type, 5);

        let mut transcript = BundleTranscriptHashWriter::new(bytes.len());
        transcript.update(&bytes[..trailer.offset]).unwrap();
        let transcript = *transcript.finish().unwrap().digest();
        assert_eq!(transcript, verified.transcript_digest);
        Self {
            items: capture.items,
            header: bytes[header.offset..header.offset + header.bytes].to_vec(),
            trailer: bytes[trailer.offset..trailer.offset + trailer.bytes].to_vec(),
            transcript,
            bytes: bytes.len(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BundleRejection {
    Framing,
    Declaration,
    Transcript,
}

/// Executes the public bounded framing and transcript primitives against the
/// already high-level-validated frozen bundle. A changed header/trailer must
/// violate its original declaration; changed pre-trailer bytes must either
/// alter framing or fail the original trailer's transcript digest.
fn reject_under_frozen_declarations(
    changed: &[u8],
    frozen: &FrozenBundle,
) -> Option<BundleRejection> {
    let mut capture = ItemCapture::default();
    let summary = match visit_logical_bundle(Cursor::new(changed), &mut capture, BundleLimits::HARD)
    {
        Ok(summary) => summary,
        Err(_) => return Some(BundleRejection::Framing),
    };
    if summary.bytes != frozen.bytes
        || summary.items != frozen.items.len()
        || capture.items != frozen.items
    {
        return Some(BundleRejection::Declaration);
    }
    let header = capture.items[0];
    let trailer = *capture.items.last().unwrap();
    if changed[header.offset..header.offset + header.bytes] != frozen.header {
        return Some(BundleRejection::Declaration);
    }
    if changed[trailer.offset..trailer.offset + trailer.bytes] != frozen.trailer {
        return Some(BundleRejection::Declaration);
    }
    let mut transcript = BundleTranscriptHashWriter::new(changed.len());
    transcript.update(&changed[..trailer.offset]).unwrap();
    if transcript.finish().unwrap().digest() != &frozen.transcript {
        return Some(BundleRejection::Transcript);
    }
    None
}

#[derive(Clone)]
struct IndexedSource {
    source: String,
    category: &'static str,
    identity: [u8; 32],
    kind: Option<ObjectKind>,
    record_type: Option<u16>,
}

#[test]
fn cross_kind_tree_to_conflict_mutation_returns_a_stable_schema_error() {
    let mut changed = read("objects/03-tree.cbor");
    changed[4] ^= 1 << 3;
    let scanned = scan_metadata(&changed, Limits::METADATA).unwrap();
    assert_eq!(scanned.framing().numeric_kind, 11);
    assert_eq!(
        validate_metadata_schema(&scanned).unwrap_err().code,
        ErrorCode::SchemaFieldInvalid
    );
}

#[test]
fn all_58520_frozen_single_bit_recipes_execute_through_public_validation_apis() {
    let recipe = document("mutations/single-bit.json");
    assert_eq!(
        recipe["schema"],
        "ogvcs.repository-format.v1.single-bit-mutation-recipes.v1"
    );
    assert_eq!(
        recipe["algorithm"],
        json!({
            "bitNumbering": "bitIndex 0 is mask 0x01 and bitIndex 7 is mask 0x80",
            "id": "ogvcs.systematic-single-bit-xor",
            "operation": "for byteOffset in [0,byteLength), then bitIndex in [0,8), clone the selected byte range and XOR byte[byteOffset] with (1 << bitIndex)",
            "order": ["source catalogue order", "ascending byteOffset", "ascending bitIndex"],
            "version": 1
        })
    );
    assert_eq!(
        recipe["invariants"],
        json!({
            "bundleItem": "apply canonical framing first; if framing succeeds, item/record/object identity and then transcript verification use the original declarations",
            "bundleSequence": "apply canonical item framing, section/order/count/ordinal/mode/budget and embedded identity checks in normative layer order; if those pass, require BUNDLE_TRAILER_MISMATCH because the original trailer transcript digest cannot authenticate changed pre-trailer bytes",
            "objectOrLogicalRecord": "apply canonical framing before identity; a canonical changed payload must recompute a digest different from declaredIdentity and fail identityFailure"
        })
    );

    let object_index = document("objects/index.json");
    let logical_index = document("logical-records/index.json");
    let mut indexed = Vec::new();
    for entry in object_index["objects"].as_array().unwrap() {
        let kind = ObjectKind::from_code(entry["kind"].as_u64().unwrap()).unwrap();
        indexed.push(IndexedSource {
            source: entry["payloadPath"].as_str().unwrap().to_owned(),
            category: if kind == ObjectKind::Chunk {
                "raw-object"
            } else {
                "metadata-object"
            },
            identity: hex(entry["objectId"].as_str().unwrap()),
            kind: Some(kind),
            record_type: None,
        });
    }
    for entry in logical_index["records"].as_array().unwrap() {
        indexed.push(IndexedSource {
            source: entry["payloadPath"].as_str().unwrap().to_owned(),
            category: "logical-record",
            identity: hex(entry["identity"].as_str().unwrap()),
            kind: None,
            record_type: Some(entry["type"].as_u64().unwrap() as u16),
        });
    }

    let sources = recipe["sources"].as_array().unwrap();
    assert_eq!(sources.len(), indexed.len());
    let mut source_cases = 0u64;
    let mut source_framing_rejections = 0u64;
    let mut source_identity_rejections = 0u64;
    for (source_index, (source, expected)) in sources.iter().zip(&indexed).enumerate() {
        assert_eq!(source["source"], expected.source, "source {source_index}");
        assert_eq!(
            source["category"], expected.category,
            "source {source_index}"
        );
        assert_eq!(
            source["declaredIdentity"],
            hex_lower(&expected.identity),
            "source {source_index}"
        );
        assert_eq!(
            source["identityFailure"],
            if expected.kind.is_some() {
                "OBJECT_ID_MISMATCH"
            } else {
                "BUNDLE_RECORD_ID_MISMATCH"
            }
        );
        let original = read(&expected.source);
        assert_eq!(
            source["byteLength"].as_u64().unwrap() as usize,
            original.len()
        );
        if let Some(kind) = expected.kind {
            assert_eq!(object_id(kind, &original).unwrap(), expected.identity);
            if kind != ObjectKind::Chunk {
                let object = scan_metadata(&original, Limits::METADATA).unwrap();
                assert_eq!(validate_metadata_schema(&object).unwrap(), kind);
            }
        } else {
            let record_type = expected.record_type.unwrap();
            assert_eq!(
                validate_logical_record(&original, Limits::METADATA).unwrap(),
                record_type
            );
            assert_eq!(
                logical_record_id(record_type, &original).unwrap(),
                expected.identity
            );
        }

        for byte_offset in 0..original.len() {
            for bit_index in 0..8 {
                let changed = mutate(&original, byte_offset, bit_index);
                let identity = if let Some(kind) = expected.kind {
                    if kind == ObjectKind::Chunk {
                        Some(object_id(kind, &changed).unwrap())
                    } else {
                        scan_metadata(&changed, Limits::METADATA)
                            .and_then(|object| {
                                let actual_kind = validate_metadata_schema(&object)?;
                                if actual_kind != kind {
                                    return Err(ogvcs_object_model::Error::new(
                                        ErrorCode::ObjectReferenceKindMismatch,
                                    ));
                                }
                                object_id(kind, &changed)
                            })
                            .ok()
                    }
                } else {
                    validate_logical_record(&changed, Limits::METADATA)
                        .and_then(|record_type| logical_record_id(record_type, &changed))
                        .ok()
                };
                if let Some(identity) = identity {
                    assert_ne!(
                        identity, expected.identity,
                        "{}:{byte_offset}:{bit_index} preserved its frozen identity",
                        expected.source
                    );
                    source_identity_rejections += 1;
                } else {
                    source_framing_rejections += 1;
                }
                source_cases += 1;
            }
        }
    }

    let whole = &recipe["wholeSequence"];
    assert_eq!(whole["category"], "bundle-sequence");
    assert_eq!(
        whole["source"],
        "logical-bundles/valid-supplied-closure.cborseq"
    );
    let bundle = read(whole["source"].as_str().unwrap());
    assert_eq!(whole["byteLength"].as_u64().unwrap() as usize, bundle.len());
    let frozen = FrozenBundle::from_validated(&bundle);

    let selected_items = [0usize, 1, 3, 4, 6];
    let categories = [
        "bundle-header",
        "bundle-object",
        "bundle-logical-record",
        "bundle-root",
        "bundle-trailer",
    ];
    let expected_types = [1u16, 2, 3, 4, 5];
    let shapes = recipe["bundleItemShapes"].as_array().unwrap();
    assert_eq!(shapes.len(), selected_items.len());
    for (shape_index, shape) in shapes.iter().enumerate() {
        let item = frozen.items[selected_items[shape_index]];
        assert_eq!(shape["source"], whole["source"]);
        assert_eq!(shape["category"], categories[shape_index]);
        assert_eq!(shape["byteOffset"].as_u64().unwrap() as usize, item.offset);
        assert_eq!(shape["byteLength"].as_u64().unwrap() as usize, item.bytes);
        assert_eq!(item.item_type, expected_types[shape_index]);
    }

    let declared_source_cases: u64 = sources
        .iter()
        .map(|source| source["byteLength"].as_u64().unwrap() * 8)
        .sum();
    let declared_item_cases: u64 = shapes
        .iter()
        .map(|shape| shape["byteLength"].as_u64().unwrap() * 8)
        .sum();
    let declared_whole_cases = whole["byteLength"].as_u64().unwrap() * 8;
    assert_eq!(declared_source_cases, 50_360);
    assert_eq!(declared_item_cases, 2_832);
    assert_eq!(declared_whole_cases, 5_328);
    assert_eq!(
        declared_source_cases + declared_item_cases + declared_whole_cases,
        recipe["totalCases"].as_u64().unwrap()
    );

    let mut bundle_item_cases = 0u64;
    let mut whole_sequence_cases = 0u64;
    let mut bundle_rejections = [0u64; 3];
    for shape in shapes {
        let base = shape["byteOffset"].as_u64().unwrap() as usize;
        let length = shape["byteLength"].as_u64().unwrap() as usize;
        assert!(base + length <= bundle.len());
        for relative_offset in 0..length {
            for bit_index in 0..8 {
                let changed = mutate(&bundle, base + relative_offset, bit_index);
                let rejection = reject_under_frozen_declarations(&changed, &frozen).unwrap_or_else(
                    || {
                        panic!(
                            "{}:{relative_offset}:{bit_index} authenticated under frozen declarations",
                            shape["category"]
                        )
                    },
                );
                bundle_rejections[rejection as usize] += 1;
                bundle_item_cases += 1;
            }
        }
    }
    for byte_offset in 0..bundle.len() {
        for bit_index in 0..8 {
            let changed = mutate(&bundle, byte_offset, bit_index);
            let rejection =
                reject_under_frozen_declarations(&changed, &frozen).unwrap_or_else(|| {
                    panic!(
                    "bundle-sequence:{byte_offset}:{bit_index} authenticated under frozen trailer"
                )
                });
            bundle_rejections[rejection as usize] += 1;
            whole_sequence_cases += 1;
        }
    }

    assert_eq!(source_cases, declared_source_cases);
    assert_eq!(
        source_framing_rejections + source_identity_rejections,
        source_cases
    );
    assert_eq!(bundle_item_cases, declared_item_cases);
    assert_eq!(whole_sequence_cases, declared_whole_cases);
    assert_eq!(bundle_rejections.iter().sum::<u64>(), 8_160);
    let executed = source_cases + bundle_item_cases + whole_sequence_cases;
    assert_eq!(executed, recipe["totalCases"].as_u64().unwrap());
    assert_eq!(executed, 58_520);
    println!(
        "mutation execution: language=rust executed={executed} source={source_cases} source_framing={source_framing_rejections} source_identity={source_identity_rejections} bundle_items={bundle_item_cases} whole_sequence={whole_sequence_cases} bundle_framing={} bundle_declaration={} bundle_transcript={}",
        bundle_rejections[BundleRejection::Framing as usize],
        bundle_rejections[BundleRejection::Declaration as usize],
        bundle_rejections[BundleRejection::Transcript as usize]
    );
}
