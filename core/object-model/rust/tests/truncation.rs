use std::io::Cursor;

use ogvcs_object_model::*;
use serde_json::Value;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";

#[derive(Default)]
struct NoopVisitor;

impl BundleVisitor for NoopVisitor {}

fn expected_code(value: &Value) -> ErrorCode {
    match value["expected"]["code"].as_str().unwrap() {
        "CBOR_TRUNCATED" => ErrorCode::CborTruncated,
        "BUNDLE_SEQUENCE_INVALID" => ErrorCode::BundleSequenceInvalid,
        other => panic!("unexpected recipe code {other}"),
    }
}

#[test]
fn all_7303_frozen_proper_prefixes_obey_physical_eof_precedence() {
    let recipe: Value = serde_json::from_slice(
        &std::fs::read(format!("{VECTOR_ROOT}/mutations/truncation.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        recipe["schema"],
        "ogvcs.repository-format.v1.truncation-recipes.v1"
    );
    assert_eq!(recipe["totalCases"], 7_303);
    let mut executed = 0u64;

    for source in recipe["sources"].as_array().unwrap() {
        let complete = std::fs::read(format!(
            "{VECTOR_ROOT}/{}",
            source["source"].as_str().unwrap()
        ))
        .unwrap();
        let offset = source
            .get("byteOffset")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let length = source["byteLength"].as_u64().unwrap() as usize;
        assert!(offset + length <= complete.len());
        let item = &complete[offset..offset + length];
        let from = source["prefixes"]["fromInclusive"].as_u64().unwrap() as usize;
        let to = source["prefixes"]["toInclusive"].as_u64().unwrap() as usize;
        let expected = expected_code(source);
        for prefix in from..=to {
            let bytes = &item[..prefix];
            let actual = match source["category"].as_str().unwrap() {
                "metadata-object" => {
                    scan_metadata(bytes, Limits::METADATA)
                        .map(|_| ())
                        .unwrap_err()
                        .code
                }
                "logical-record" => {
                    validate_logical_record(bytes, Limits::METADATA)
                        .map(|_| ())
                        .unwrap_err()
                        .code
                }
                category if category.starts_with("bundle-") => {
                    if bytes.is_empty() {
                        ErrorCode::CborTruncated
                    } else {
                        let mut visitor = NoopVisitor;
                        visit_logical_bundle(Cursor::new(bytes), &mut visitor, BundleLimits::HARD)
                            .map(|_| ErrorCode::CborTruncated)
                            .unwrap_or_else(|error| error.code)
                    }
                }
                category => panic!("unknown truncation category {category}"),
            };
            assert_eq!(
                actual, expected,
                "{} category {} offset {offset} prefix {prefix}",
                source["source"], source["category"]
            );
            executed += 1;
        }
    }

    let whole = &recipe["wholeSequence"];
    let complete = std::fs::read(format!(
        "{VECTOR_ROOT}/{}",
        whole["source"].as_str().unwrap()
    ))
    .unwrap();
    assert_eq!(
        complete.len(),
        whole["byteLength"].as_u64().unwrap() as usize
    );
    for prefix in 0..complete.len() {
        let expected = whole["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|range| {
                let from = range["fromInclusive"].as_u64().unwrap() as usize;
                let to = range["toInclusive"].as_u64().unwrap() as usize;
                (from..=to).contains(&prefix)
            })
            .map(expected_code)
            .expect("every proper sequence prefix is classified");
        let mut visitor = NoopVisitor;
        let actual = match visit_logical_bundle(
            Cursor::new(&complete[..prefix]),
            &mut visitor,
            BundleLimits::HARD,
        ) {
            Ok(_) => ErrorCode::BundleSequenceInvalid,
            Err(error) => error.code,
        };
        assert_eq!(actual, expected, "whole bundle prefix {prefix}");
        executed += 1;
    }
    assert_eq!(executed, 7_303);
}

fn declared_object_item(kind: u64, length: u32, payload: &[u8]) -> Vec<u8> {
    let reference = encode_canonical(&Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(kind)),
        (Cbor::UInt(2), Cbor::UInt(1)),
        (Cbor::UInt(3), Cbor::Bytes(vec![0; 32])),
    ]))
    .unwrap();
    let mut output = vec![0xa5, 0x00, 0x01, 0x01, 0x02, 0x02, 0x00, 0x03];
    output.extend_from_slice(&reference);
    output.push(0x04);
    if length <= u16::MAX.into() {
        output.push(0x59);
        output.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        output.push(0x5a);
        output.extend_from_slice(&length.to_be_bytes());
    }
    output.extend_from_slice(payload);
    output
}

#[test]
fn absent_or_partial_declared_content_is_truncated_but_complete_over_limit_content_is_limit() {
    let limits = BundleLimits {
        max_metadata_bytes: 1_024,
        ..BundleLimits::HARD
    };
    for present in [0, 1, 1_024, 2_047] {
        let bytes = declared_object_item(2, 2_048, &vec![0; present]);
        let mut visitor = NoopVisitor;
        assert_eq!(
            visit_logical_bundle(Cursor::new(bytes), &mut visitor, limits)
                .unwrap_err()
                .code,
            ErrorCode::CborTruncated,
            "physical bytes {present}"
        );
    }
    let bytes = declared_object_item(2, 2_048, &vec![0; 2_048]);
    let mut visitor = NoopVisitor;
    assert_eq!(
        visit_logical_bundle(Cursor::new(bytes), &mut visitor, limits)
            .unwrap_err()
            .code,
        ErrorCode::LimitMetadataBytes
    );

    let chunk_limits = BundleLimits {
        max_chunk_bytes: 1_024,
        ..BundleLimits::HARD
    };
    let absent = declared_object_item(1, 2_048, &[]);
    assert_eq!(
        visit_logical_bundle(Cursor::new(absent), &mut visitor, chunk_limits)
            .unwrap_err()
            .code,
        ErrorCode::CborTruncated
    );
    let present = declared_object_item(1, 2_048, &vec![0; 2_048]);
    assert_eq!(
        visit_logical_bundle(Cursor::new(present), &mut visitor, chunk_limits)
            .unwrap_err()
            .code,
        ErrorCode::LimitChunkBytes
    );
}
