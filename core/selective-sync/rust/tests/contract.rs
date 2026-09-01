use ogvcs_selective_sync_kernel::{
    SelectionError, CONTRACT_ARTIFACT_SET_SHA256, CONTRACT_MANIFEST_SHA256, CONTRACT_VERSION,
    ERROR_REGISTRY_SHA256, GOLDEN_VECTORS_SHA256, PATH_CONTRACT_MANIFEST_SHA256,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;

const ERRORS: &str = include_str!("errors.json");
const GOLDEN: &str = include_str!("golden.json");

fn sha256(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

#[test]
fn generated_binding_pins_exact_contract_path_errors_and_vectors() {
    assert_eq!(CONTRACT_VERSION, "0.1.0-rc.1");
    for digest in [
        CONTRACT_MANIFEST_SHA256,
        CONTRACT_ARTIFACT_SET_SHA256,
        PATH_CONTRACT_MANIFEST_SHA256,
        ERROR_REGISTRY_SHA256,
        GOLDEN_VECTORS_SHA256,
    ] {
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_eq!(sha256(ERRORS.as_bytes()), ERROR_REGISTRY_SHA256);
    assert_eq!(sha256(GOLDEN.as_bytes()), GOLDEN_VECTORS_SHA256);
    let errors: Value = serde_json::from_str(ERRORS).unwrap();
    let registered: Vec<_> = errors["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["name"].as_str().unwrap())
        .collect();
    let runtime: Vec<_> = SelectionError::ALL
        .iter()
        .map(|error| error.code())
        .collect();
    assert_eq!(runtime, registered);
}
