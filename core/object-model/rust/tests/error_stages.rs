use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use ogvcs_object_model::{Error, ErrorCode, ValidationStage};
use serde_json::Value;

fn errors_document() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/repository-format/v1/errors.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn stage(value: &str) -> ValidationStage {
    ValidationStage::ALL
        .iter()
        .copied()
        .find(|stage| stage.as_str() == value)
        .unwrap()
}

#[test]
fn rust_error_sites_exactly_match_the_frozen_catalogue() {
    let document = errors_document();
    assert_eq!(
        document["schemaVersion"],
        "ogvcs.repository-format/errors/v1"
    );
    let entries = document["errors"].as_array().unwrap();
    assert_eq!(entries.len(), 81);
    assert_eq!(ErrorCode::ALL.len(), 81);
    assert_eq!(
        document["precedence"]["stageOrder"]
            .as_array()
            .unwrap()
            .iter()
            .map(|stage| stage.as_str().unwrap())
            .collect::<Vec<_>>(),
        ValidationStage::ALL
            .iter()
            .map(|stage| stage.as_str())
            .collect::<Vec<_>>()
    );

    let mut catalogue = BTreeSet::new();
    let mut pair_stages = BTreeMap::<(String, u8), BTreeSet<String>>::new();
    let mut codes = BTreeSet::new();
    let mut site_objects = 0usize;
    for entry in entries {
        let code_name = entry["code"].as_str().unwrap();
        let code = ErrorCode::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == code_name)
            .unwrap_or_else(|| panic!("missing Rust code {code_name}"));
        assert!(codes.insert(code_name.to_owned()), "duplicate {code_name}");
        for site in entry["sites"].as_array().unwrap() {
            site_objects += 1;
            let stage_name = site["stage"].as_str().unwrap();
            let stage = stage(stage_name);
            for layer in site["layers"].as_array().unwrap() {
                let layer = layer.as_u64().unwrap() as u8;
                assert!(
                    code.supports_site(layer, stage),
                    "{code_name}@{layer}:{stage_name}"
                );
                assert!(catalogue.insert((code_name.to_owned(), layer, stage_name.to_owned())));
                pair_stages
                    .entry((code_name.to_owned(), layer))
                    .or_default()
                    .insert(stage_name.to_owned());
            }
        }
    }
    assert_eq!(site_objects, 94);
    assert_eq!(codes.len(), ErrorCode::ALL.len());
    for ((code_name, layer), stages) in &pair_stages {
        let code = ErrorCode::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == code_name)
            .unwrap();
        if stages.len() == 1 {
            assert_eq!(
                code.default_stage(*layer).map(ValidationStage::as_str),
                stages.first().map(String::as_str),
                "{code_name}@{layer}"
            );
        } else {
            assert_eq!(code.default_stage(*layer), None, "{code_name}@{layer}");
        }
    }

    let mut rust_sites = BTreeSet::new();
    for code in ErrorCode::ALL {
        let default = Error::new(*code);
        assert!(
            default.is_registered_site(),
            "default for {}",
            code.as_str()
        );
        for layer in 1..=3 {
            for stage in ValidationStage::ALL {
                if code.supports_site(layer, *stage) {
                    rust_sites.insert((code.as_str().to_owned(), layer, stage.as_str().to_owned()));
                }
            }
        }
    }
    assert_eq!(rust_sites, catalogue);
}

#[test]
fn ambiguous_pairs_require_valid_explicit_stage_selection() {
    let pairs = [
        (
            ErrorCode::SchemaFieldInvalid,
            1,
            ValidationStage::ConfiguredResourcePreflight,
            ValidationStage::CanonicalFraming,
        ),
        (
            ErrorCode::LimitCount,
            1,
            ValidationStage::ConfiguredResourcePreflight,
            ValidationStage::CanonicalFraming,
        ),
        (
            ErrorCode::ObjectReferenceKindMismatch,
            2,
            ValidationStage::KnownSchema,
            ValidationStage::ClosureAndReferenceResolution,
        ),
        (
            ErrorCode::BundleBudgetExceeded,
            1,
            ValidationStage::ConfiguredResourcePreflight,
            ValidationStage::DeclaredAccounting,
        ),
        (
            ErrorCode::BundleRootInvalid,
            2,
            ValidationStage::KnownSchema,
            ValidationStage::ClosureAndReferenceResolution,
        ),
    ];
    for (code, layer, first, second) in pairs {
        assert_eq!(code.default_stage(layer), None);
        for stage in [first, second] {
            let error = Error::new(code).with_layer(layer).with_stage(stage);
            assert!(error.is_registered_site());
            assert_eq!(error.stage, stage);
        }
    }

    assert_eq!(
        Error::new(ErrorCode::ConflictIdMismatch).stage,
        ValidationStage::DeclaredIdentity
    );
    assert_eq!(
        Error::new(ErrorCode::ChangeSetSequenceInvalid).stage,
        ValidationStage::KnownSchema
    );
    assert_eq!(
        Error::new(ErrorCode::ManifestLengthMismatch).stage,
        ValidationStage::KnownSchema
    );
}
