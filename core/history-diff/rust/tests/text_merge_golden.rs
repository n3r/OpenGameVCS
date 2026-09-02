use ogvcs_history_diff_kernel::{
    merge_text_three_way, OperationControl, TextMergeAlgorithm, TextMergeConflictKind,
    TextMergeInput, TextMergeOptions, TextMergeOutcome, TextMergeRequest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn text<'a>(value: &'a Value, member: &str) -> &'a str {
    value[member].as_str().unwrap()
}

#[test]
fn independent_json_golden_freezes_clean_and_conflict_commitments() {
    let vector: Value =
        serde_json::from_str(include_str!("text-merge-golden.json")).expect("valid golden JSON");
    assert_eq!(
        vector["schemaVersion"],
        "ogvcs.text-merge/private-golden/v1"
    );
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let base = text(case, "base").as_bytes();
        let ours = text(case, "ours").as_bytes();
        let theirs = text(case, "theirs").as_bytes();
        let outcome = merge_text_three_way(
            TextMergeRequest {
                algorithm: TextMergeAlgorithm::LineDiff3V1,
                options: TextMergeOptions::default(),
                base: TextMergeInput {
                    bytes: base,
                    digest: digest(base),
                },
                ours: TextMergeInput {
                    bytes: ours,
                    digest: digest(ours),
                },
                theirs: TextMergeInput {
                    bytes: theirs,
                    digest: digest(theirs),
                },
            },
            &OperationControl::default(),
        )
        .unwrap();
        match (text(case, "outcome"), outcome) {
            ("clean", TextMergeOutcome::Clean(clean)) => {
                assert_eq!(clean.output(), text(case, "output").as_bytes());
                assert_eq!(
                    hex(&clean.request_commitment()),
                    text(case, "requestCommitmentSha256")
                );
                assert_eq!(hex(&clean.output_digest()), text(case, "outputSha256"));
                assert_eq!(
                    hex(&clean.output_commitment()),
                    text(case, "outputCommitmentSha256")
                );
            }
            ("conflict", TextMergeOutcome::Conflict(conflicted)) => {
                assert_eq!(
                    hex(&conflicted.request_commitment()),
                    text(case, "requestCommitmentSha256")
                );
                assert_eq!(
                    hex(&conflicted.conflict_commitment()),
                    text(case, "conflictCommitmentSha256")
                );
                let expected = case["conflicts"].as_array().unwrap();
                assert_eq!(conflicted.conflicts().len(), expected.len());
                for (actual, expected) in conflicted.conflicts().iter().zip(expected) {
                    assert_eq!(actual.kind(), TextMergeConflictKind::ConcurrentInsertion);
                    assert_eq!(
                        actual.base_start_line(),
                        u32::try_from(expected["baseStartLine"].as_u64().unwrap()).unwrap()
                    );
                    assert_eq!(
                        actual.base_end_line(),
                        u32::try_from(expected["baseEndLine"].as_u64().unwrap()).unwrap()
                    );
                    for (actual, member) in [
                        (actual.base(), "base"),
                        (actual.ours(), "ours"),
                        (actual.theirs(), "theirs"),
                    ] {
                        assert_eq!(
                            actual.line_count(),
                            u32::try_from(expected[member]["lineCount"].as_u64().unwrap()).unwrap()
                        );
                        assert_eq!(
                            actual.byte_count(),
                            expected[member]["byteCount"].as_u64().unwrap()
                        );
                        assert_eq!(hex(&actual.digest()), text(&expected[member], "sha256"));
                    }
                }
            }
            (expected, actual) => panic!("unexpected golden outcome {expected}: {actual:?}"),
        }
    }
}
