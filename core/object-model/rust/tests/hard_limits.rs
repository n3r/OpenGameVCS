use ogvcs_object_model::{
    enforce_hard_limit, evaluate_hard_limit, hard_limit_maximum, ErrorCode, HardLimitCeilings,
    Registry, ValidationStage, HARD_LIMIT_NAMES,
};
use serde_json::Value;

const CONSTRUCTORS: &str =
    include_str!("../../../../spec/repository-format/v1/vectors/limits/virtual-constructors.json");

fn error_code(value: &str) -> ErrorCode {
    match value {
        "BUNDLE_BUDGET_EXCEEDED" => ErrorCode::BundleBudgetExceeded,
        "LIMIT_CHUNK_BYTES" => ErrorCode::LimitChunkBytes,
        "LIMIT_COUNT" => ErrorCode::LimitCount,
        "LIMIT_EXTENSION_BYTES" => ErrorCode::LimitExtensionBytes,
        "LIMIT_LOGICAL_BYTES" => ErrorCode::LimitLogicalBytes,
        "LIMIT_METADATA_BYTES" => ErrorCode::LimitMetadataBytes,
        "LIMIT_NESTING" => ErrorCode::LimitNesting,
        "LIMIT_VALUE_BYTES" => ErrorCode::LimitValueBytes,
        "PATH_CORE_INVALID" => ErrorCode::PathCoreInvalid,
        "SNAPSHOT_PARENT_COUNT_INVALID" => ErrorCode::SnapshotParentCountInvalid,
        other => panic!("unexpected limit error code {other}"),
    }
}

fn validation_stage(value: &str) -> ValidationStage {
    ValidationStage::ALL
        .iter()
        .copied()
        .find(|stage| stage.as_str() == value)
        .unwrap_or_else(|| panic!("unexpected validation stage {value}"))
}

#[test]
fn all_fifty_normative_max_and_max_plus_one_constructors_execute() {
    let document: Value = serde_json::from_str(CONSTRUCTORS).expect("constructor JSON");
    let cases = document["cases"].as_array().expect("cases");
    let registry = Registry::bundled();
    let mut seen = std::collections::BTreeMap::<&str, std::collections::BTreeSet<&str>>::new();
    assert_eq!(cases.len(), 50);
    assert_eq!(HARD_LIMIT_NAMES.len(), 25);
    for item in cases {
        assert_eq!(
            item["algorithm"]["id"],
            "ogvcs.virtual-boundary-constructor"
        );
        assert_eq!(item["algorithm"]["version"], 1);
        let name = item["case"].as_str().expect("case");
        let name: &'static str = HARD_LIMIT_NAMES
            .iter()
            .copied()
            .find(|candidate| *candidate == name)
            .expect("registered limit name");
        let value = item["valueDecimal"]
            .as_str()
            .expect("decimal")
            .parse::<u64>()
            .expect("u64 limit value");
        let decision = evaluate_hard_limit(&registry, name, value).expect("valid preflight");
        let accepted = item["expected"]["result"] == "accept";
        assert_eq!(decision.accepted, accepted, "{name}");
        let expected_code = item["expected"]["code"].as_str().map(error_code);
        assert_eq!(decision.code, expected_code, "{name}");
        let expected_layer = item["expected"]["layer"]
            .as_u64()
            .or_else(|| item["expected"]["highestLayer"].as_u64())
            .expect("layer") as u8;
        assert_eq!(decision.layer, expected_layer, "{name}");
        let expected_stage = item["expected"]["stage"].as_str().map(validation_stage);
        if !accepted {
            assert_eq!(Some(decision.stage), expected_stage, "{name}");
        }
        let enforced = enforce_hard_limit(name, value);
        if accepted {
            let enforced = enforced.expect("maximum accepted by production authority");
            assert_eq!(enforced.maximum, decision.maximum, "{name}");
            assert_eq!(enforced.effective_maximum, decision.maximum, "{name}");
        } else {
            let error = enforced.expect_err("maximum-plus-one rejected by production authority");
            assert_eq!(error.code, expected_code.expect("rejection code"), "{name}");
            assert_eq!(error.layer, expected_layer, "{name}");
            assert_eq!(Some(error.stage), expected_stage, "{name}");
        }
        seen.entry(name)
            .or_default()
            .insert(item["variant"].as_str().expect("variant"));
    }
    assert_eq!(seen.len(), HARD_LIMIT_NAMES.len());
    for variants in seen.values() {
        assert_eq!(
            variants.iter().copied().collect::<Vec<_>>(),
            ["maximum", "maximum-plus-one"]
        );
    }
}

#[test]
fn all_twenty_five_configured_ceilings_only_reduce_the_frozen_authority() {
    for name in HARD_LIMIT_NAMES {
        let hard = hard_limit_maximum(name).unwrap();
        let reduced = hard.min(7);
        let ceilings = HardLimitCeilings::HARD
            .with_limit(name, reduced)
            .expect("known family");
        let accepted = ceilings.enforce(name, reduced).expect("reduced maximum");
        assert_eq!(accepted.maximum, hard, "{name}");
        assert_eq!(accepted.effective_maximum, reduced, "{name}");
        let error = ceilings
            .enforce(name, reduced + 1)
            .expect_err("reduced maximum plus one");
        let frozen = evaluate_hard_limit(&Registry::bundled(), name, hard + 1).unwrap();
        assert_eq!(
            error.code,
            frozen.code.expect("frozen rejection code"),
            "{name}"
        );
        assert_eq!(error.layer, frozen.layer, "{name}");
        assert_eq!(error.stage, frozen.stage, "{name}");

        let raised = HardLimitCeilings::HARD
            .with_limit(name, hard.saturating_add(1))
            .unwrap();
        assert_eq!(raised.maximum(name).unwrap(), hard, "{name}");
    }
}
