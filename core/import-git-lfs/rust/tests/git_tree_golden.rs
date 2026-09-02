use ogvcs_git_import_preflight::{
    decode_git_tree_frame, GitObjectFormat, GitTreeFrame, GitTreeLimits, OperationControl,
};
use ogvcs_object_model::sha256;
use serde_json::Value;

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("golden hexadecimal is invalid"),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn text<'a>(value: &'a Value, member: &str) -> &'a str {
    value[member].as_str().expect("golden text member")
}

fn number(value: &Value, member: &str) -> u64 {
    value[member].as_u64().expect("golden integer member")
}

#[test]
fn independent_json_golden_freezes_both_object_widths_and_commitments() {
    let golden: Value = serde_json::from_str(include_str!("git-tree-golden.json"))
        .expect("valid Git tree golden JSON");
    assert_eq!(
        golden["schemaVersion"],
        "ogvcs.git-tree-frame/private-golden/v1"
    );
    let cases = golden["cases"].as_array().expect("golden cases");
    assert_eq!(cases.len(), 2);
    for case in cases {
        let bytes = decode_hex(text(case, "frameHex"));
        assert_eq!(encode_hex(&sha256(&bytes)), text(case, "stagedSha256"));
        let object_format = match text(case, "objectFormat") {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            value => panic!("unexpected object format {value}"),
        };
        let projection = decode_git_tree_frame(
            GitTreeFrame {
                bytes: &bytes,
                staged_sha256: sha256(&bytes),
                object_format,
            },
            GitTreeLimits::default(),
            &OperationControl::default(),
        )
        .expect("golden frame decodes");
        assert_eq!(
            encode_hex(&projection.request_commitment()),
            text(case, "requestCommitmentSha256")
        );
        assert_eq!(
            encode_hex(&projection.projection_commitment()),
            text(case, "projectionCommitmentSha256")
        );

        let ledger = &case["ledger"];
        assert_eq!(
            projection.ledger().frame_bytes,
            number(ledger, "frameBytes")
        );
        assert_eq!(
            projection.ledger().payload_bytes,
            number(ledger, "payloadBytes")
        );
        assert_eq!(projection.ledger().entries, number(ledger, "entries"));
        assert_eq!(projection.ledger().name_bytes, number(ledger, "nameBytes"));
        assert_eq!(projection.ledger().work_units, number(ledger, "workUnits"));
        assert_eq!(
            projection.ledger().cancellation_checks,
            number(ledger, "cancellationChecks")
        );
        assert_eq!(
            projection.ledger().admitted_retained_bytes,
            number(ledger, "admittedRetainedBytes")
        );

        let expected_entries = case["entries"].as_array().expect("golden entries");
        assert_eq!(projection.entries().len(), expected_entries.len());
        for (actual, expected) in projection.entries().iter().zip(expected_entries) {
            assert_eq!(actual.mode().canonical_octal(), text(expected, "mode"));
            assert_eq!(encode_hex(actual.name()), text(expected, "nameHex"));
            assert_eq!(actual.object_id().to_string(), text(expected, "objectId"));
        }
    }
}
