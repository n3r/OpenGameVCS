use std::{fs, path::PathBuf, process::Command};

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors";
const REGISTRY_ROOT: &str = "../../../spec/repository-format/v1/registries";

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

struct OutputDirectory(PathBuf);

impl OutputDirectory {
    fn new() -> Self {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).unwrap();
        let suffix = hex_lower(&nonce);
        let path = std::env::temp_dir().join(format!("ogvcs-rust-report-{suffix}"));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for OutputDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn conformance_report_executes_every_applicable_non_scale_scenario() {
    let directory = OutputDirectory::new();
    let report_path = directory.0.join("report.json");
    let result = Command::new(env!("CARGO_BIN_EXE_object_model_scenario_report"))
        .env_remove("OGVCS_IMPLEMENTATION_ARTIFACT")
        .env_remove("OGVCS_FORMAT_ARTIFACT")
        .args([
            "--conformance",
            "--vectors",
            VECTOR_ROOT,
            "--registries",
            REGISTRY_ROOT,
            "--output",
        ])
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(report["schema"], "ogvcs.object-model.conformance-report/v1");
    assert_eq!(report["implementation"], "ogvcs-object-model/rust");
    assert_eq!(
        report["artifact"],
        serde_json::json!({
            "name": "ogvcs-object-model",
            "type": "workspace",
            "version": "0.1.0"
        })
    );
    assert_eq!(
        report["formatArtifact"],
        serde_json::json!({
            "name": "@opengamevcs/repository-format-v1",
            "type": "workspace",
            "version": "0.1.0"
        })
    );
    assert!(report["runtime"]
        .as_str()
        .is_some_and(|runtime| runtime.starts_with("rustc ")));
    assert_eq!(report["conformance"]["objects"]["count"], 11);
    assert_eq!(report["conformance"]["logicalRecords"]["count"], 9);
    assert_eq!(report["conformance"]["bundles"]["count"], 3);
    let scenarios = &report["conformance"]["scenarios"];
    assert_eq!(scenarios["scenarios"], 235);
    assert_eq!(scenarios["executed"], 228);
    assert_eq!(scenarios["failed"], 0);
    assert_eq!(scenarios["inventoryOnly"], 2);
    assert_eq!(scenarios["notApplicable"], 5);
    assert_eq!(
        scenarios["rows"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["status"] == "not-applicable")
            .count(),
        5
    );
    for row in scenarios["rows"].as_array().unwrap() {
        if row["expected"]["result"] == "reject" {
            let expected_stage = row["expected"]["stage"]
                .as_str()
                .expect("reject expectation requires stage");
            assert_eq!(
                row["actual"]["stage"].as_str(),
                Some(expected_stage),
                "{}",
                row["scenarioId"]
            );
        }
    }
}
