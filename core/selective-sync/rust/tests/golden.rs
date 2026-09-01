use std::io::Cursor;

use ogvcs_path_contract::CaseMode;
use ogvcs_selective_sync_kernel::{
    selection_spec_digest, ContentIdentity, EvaluationBindings, EvaluationControl, HostPlatform,
    IteratorMetadataSource, MatchKind, Materialization, MetadataProjectionBuilder, MetadataRecord,
    SelectionKernel, SelectionRule, SelectionSpec,
};
use serde_json::Value;

const GOLDEN: &str = include_str!("golden.json");

fn digest(value: &Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    assert_eq!(text.len(), 64);
    let mut result = [0; 32];
    for (index, output) in result.iter_mut().enumerate() {
        *output = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    result
}

fn decode_hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().unwrap();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn materialization(value: &Value) -> Materialization {
    match value.as_str().unwrap() {
        "full" => Materialization::Full,
        "metadata-only" => Materialization::MetadataOnly,
        "absent-by-spec" => Materialization::AbsentBySpec,
        other => panic!("unknown materialization {other}"),
    }
}

fn match_kind(value: &Value) -> MatchKind {
    match value.as_str().unwrap() {
        "exact" => MatchKind::Exact,
        "subtree" => MatchKind::Subtree,
        other => panic!("unknown match kind {other}"),
    }
}

fn case_mode(value: &Value) -> CaseMode {
    match value.as_str().unwrap() {
        "case-sensitive" => CaseMode::Sensitive,
        "case-folded" => CaseMode::Folded,
        other => panic!("unknown case mode {other}"),
    }
}

fn platform(value: &Value) -> HostPlatform {
    match value.as_str().unwrap() {
        "linux" => HostPlatform::Linux,
        "macos" => HostPlatform::Macos,
        "windows" => HostPlatform::Windows,
        other => panic!("unknown platform {other}"),
    }
}

fn record(value: &Value) -> MetadataRecord {
    MetadataRecord {
        ordinal: value["ordinal"].as_u64().unwrap(),
        path: value["path"].as_str().unwrap().to_owned(),
        entry_digest: digest(&value["entryDigest"]),
        content: if value["content"].is_null() {
            None
        } else {
            Some(ContentIdentity {
                digest: digest(&value["content"]["digest"]),
                logical_bytes: value["content"]["logicalBytes"].as_u64().unwrap(),
            })
        },
    }
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let end = *offset + 8;
    let value = u64::from_be_bytes(bytes[*offset..end].try_into().unwrap());
    *offset = end;
    value
}

fn projection_classes(bytes: &[u8]) -> Vec<(Materialization, bool)> {
    assert_eq!(&bytes[..16], b"OGVCS-SELECT-V1\0");
    let mut offset = 16;
    let count = read_u64(bytes, &mut offset);
    offset += 32;
    let mut classes = Vec::new();
    for ordinal in 0..count {
        assert_eq!(read_u64(bytes, &mut offset), ordinal);
        let path_bytes = read_u64(bytes, &mut offset) as usize;
        offset += path_bytes;
        let class = match bytes[offset] {
            1 => Materialization::Full,
            2 => Materialization::MetadataOnly,
            3 => Materialization::AbsentBySpec,
            other => panic!("unknown class {other}"),
        };
        offset += 1;
        let present = bytes[offset] == 1;
        offset += 1;
        if present {
            offset += 40;
        }
        classes.push((class, present));
    }
    assert_eq!(offset, bytes.len());
    classes
}

#[test]
fn rust_runtime_matches_every_independent_node_golden_byte_for_byte() {
    let golden: Value = serde_json::from_str(GOLDEN).unwrap();
    for vector in golden["cases"].as_array().unwrap() {
        let spec_value = &vector["spec"];
        let spec = SelectionSpec::from_rules(
            materialization(&spec_value["defaultMaterialization"]),
            spec_value["rules"].as_array().unwrap().iter().map(|rule| {
                SelectionRule::new(
                    rule["ordinal"].as_u64().unwrap(),
                    match_kind(&rule["match"]),
                    rule["path"].as_str().unwrap(),
                    materialization(&rule["materialization"]),
                )
            }),
        )
        .unwrap();
        let values: Vec<_> = vector["metadata"]
            .as_array()
            .unwrap()
            .iter()
            .map(record)
            .collect();
        let binding_value = &vector["bindings"];
        let mode = case_mode(&binding_value["caseMode"]);
        let host = platform(&binding_value["platform"]);
        let profile = binding_value["pathProfile"].as_str().unwrap();
        let actual_spec_digest = selection_spec_digest(&spec, profile, mode, host).unwrap();
        assert_eq!(
            actual_spec_digest,
            digest(&vector["expected"]["specDigest"])
        );
        let mut projection = MetadataProjectionBuilder::new(values.len() as u64).unwrap();
        for item in &values {
            projection.push(item).unwrap();
        }
        let projection = projection.finish().unwrap();
        assert_eq!(
            projection.digest,
            digest(&vector["expected"]["metadataProjectionDigest"])
        );
        let bindings = EvaluationBindings::new(
            digest(&binding_value["snapshotDigest"]),
            digest(&binding_value["settingsDigest"]),
            digest(&binding_value["consistencyTokenDigest"]),
            profile,
            mode,
            host,
            actual_spec_digest,
            projection.digest,
            values.len() as u64,
        )
        .unwrap();
        let kernel = SelectionKernel::new(bindings, spec).unwrap();
        let mut source = IteratorMetadataSource::new(values.into_iter());
        let mut bytes = Cursor::new(Vec::new());
        let summary = kernel
            .evaluate(&mut source, &mut bytes, &EvaluationControl::default())
            .unwrap();
        let bytes = bytes.into_inner();
        assert_eq!(bytes, decode_hex(&vector["expected"]["projectionHex"]));
        let expected = &vector["expected"]["summary"];
        assert_eq!(summary.bindings_digest, digest(&expected["bindingsDigest"]));
        assert_eq!(
            summary.output_projection_digest,
            digest(&expected["outputProjectionDigest"])
        );
        assert_eq!(
            summary.record_count,
            expected["recordCount"].as_u64().unwrap()
        );
        assert_eq!(summary.full_count, expected["fullCount"].as_u64().unwrap());
        assert_eq!(
            summary.metadata_only_count,
            expected["metadataOnlyCount"].as_u64().unwrap()
        );
        assert_eq!(
            summary.absent_by_spec_count,
            expected["absentBySpecCount"].as_u64().unwrap()
        );
        assert_eq!(
            summary.full_content_count,
            expected["fullContentCount"].as_u64().unwrap()
        );
        assert_eq!(
            summary.full_logical_bytes,
            expected["fullLogicalBytes"].as_u64().unwrap()
        );
        let expected_classes: Vec<_> = vector["expected"]["classes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    materialization(&entry["materialization"]),
                    entry["contentPresent"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(projection_classes(&bytes), expected_classes);
        assert!(projection_classes(&bytes)
            .iter()
            .all(|(class, present)| *class == Materialization::Full || !present));
    }
}
