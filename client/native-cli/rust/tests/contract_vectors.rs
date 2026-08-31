use ogvcs_local_cli::{
    CONTRACT_ARTIFACT_SET_SHA256, CONTRACT_MANIFEST_SHA256, CONTRACT_VECTOR_SHA256,
    EXIT_CLASS_CODES,
};
use sha2::{Digest, Sha256};

const VECTORS: &[u8] = include_bytes!("contract-v1.json");

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[test]
fn generated_contract_binding_authenticates_the_synced_vectors_and_exit_registry() {
    assert_eq!(hex(&Sha256::digest(VECTORS)), CONTRACT_VECTOR_SHA256);
    assert_eq!(CONTRACT_MANIFEST_SHA256.len(), 64);
    assert_eq!(CONTRACT_ARTIFACT_SET_SHA256.len(), 64);
    assert_eq!(
        EXIT_CLASS_CODES,
        &[
            ("success", 0),
            ("input", 2),
            ("workspace", 3),
            ("unsupported", 4),
            ("cancelled", 5),
            ("interaction-required", 6),
            ("unavailable", 7),
            ("internal", 70),
        ]
    );
}

#[cfg(not(windows))]
mod local_vectors {
    use super::*;
    use ogvcs_local_cli::{
        check_authentication, create_workspace, diagnostics_preview, open_workspace,
        resolve_config, CancelAt, CancellationPoint, ConfigInputs, ConfigLayer, CredentialProvider,
        CredentialStatus, NeverCancel, WorkspaceBindingInput,
    };
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "ogvcs011-vector-{}-{}-{}",
                label,
                std::process::id(),
                nonce
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Provider(CredentialStatus);

    impl CredentialProvider for Provider {
        fn status(&self) -> CredentialStatus {
            self.0
        }
    }

    fn vectors() -> Value {
        serde_json::from_slice(VECTORS).unwrap()
    }

    fn case<'a>(vectors: &'a Value, id: &str) -> &'a Value {
        vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap()
    }

    fn layer(value: &Value) -> ConfigLayer {
        ConfigLayer {
            endpoint: value
                .get("endpoint")
                .and_then(Value::as_str)
                .map(str::to_owned),
            profile: value
                .get("profile")
                .and_then(Value::as_str)
                .map(str::to_owned),
            output: value
                .get("output")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }

    fn binding(value: &Value) -> WorkspaceBindingInput {
        WorkspaceBindingInput {
            repository_declaration_digest: value["repositoryDeclarationDigest"]
                .as_str()
                .unwrap()
                .to_owned(),
            branch_declaration_digest: value["branchDeclarationDigest"]
                .as_str()
                .unwrap()
                .to_owned(),
            baseline_declaration_digest: value["baselineDeclarationDigest"]
                .as_str()
                .unwrap()
                .to_owned(),
            spec_declaration_digest: value["specDeclarationDigest"].as_str().unwrap().to_owned(),
        }
    }

    #[test]
    fn synced_contract_vectors_execute_against_the_public_local_api() {
        let vectors = vectors();

        let config_case = case(&vectors, "config-precedence-source-report");
        let config_directory = TestDirectory::new("config");
        let workspace_path = config_directory.0.join("workspace.json");
        let user_path = config_directory.0.join("user.json");
        let system_path = config_directory.0.join("system.json");
        fs::write(
            &workspace_path,
            serde_json::to_vec(&config_case["input"]["workspace"]).unwrap(),
        )
        .unwrap();
        fs::write(
            &user_path,
            serde_json::to_vec(&config_case["input"]["userProfile"]).unwrap(),
        )
        .unwrap();
        fs::write(
            &system_path,
            serde_json::to_vec(&config_case["input"]["systemDefault"]).unwrap(),
        )
        .unwrap();
        let mut environment = BTreeMap::new();
        for (field, name) in [
            ("endpoint", "OGVCS_ENDPOINT"),
            ("profile", "OGVCS_PROFILE"),
            ("output", "OGVCS_OUTPUT"),
        ] {
            if let Some(value) = config_case["input"]["environment"][field].as_str() {
                environment.insert(name.to_owned(), value.to_owned());
            }
        }
        let resolved = resolve_config(&ConfigInputs {
            flags: layer(&config_case["input"]["flags"]),
            environment,
            workspace_config: Some(workspace_path),
            user_config: Some(user_path),
            system_config: Some(system_path),
        })
        .unwrap();
        assert_eq!(
            resolved.as_json()["endpoint"],
            config_case["expected"]["endpoint"]
        );
        assert_eq!(
            resolved.as_json()["profile"],
            config_case["expected"]["profile"]
        );
        assert_eq!(
            resolved.as_json()["output"],
            config_case["expected"]["output"]
        );

        let secret_case = case(&vectors, "secret-like-config-rejected");
        let secret_path = config_directory.0.join("secret.json");
        fs::write(
            &secret_path,
            serde_json::to_vec(&secret_case["input"]["configuration"]).unwrap(),
        )
        .unwrap();
        let secret_error = resolve_config(&ConfigInputs {
            user_config: Some(secret_path),
            ..ConfigInputs::default()
        })
        .unwrap_err();
        assert_eq!(secret_error.code, secret_case["expected"]["code"]);
        assert!(!secret_error
            .message
            .contains(secret_case["expected"]["forbidden"].as_str().unwrap()));

        let raw_case = case(&vectors, "raw-declaration-rejected");
        let raw_directory = TestDirectory::new("raw");
        let raw_error =
            create_workspace(&raw_directory.0, binding(&raw_case["input"]), &NeverCancel)
                .unwrap_err();
        assert_eq!(raw_error.code, raw_case["expected"]["code"]);
        assert!(!raw_directory.0.join(".ogvcs").exists());

        let valid_binding = WorkspaceBindingInput {
            repository_declaration_digest: "a".repeat(64),
            branch_declaration_digest: "b".repeat(64),
            baseline_declaration_digest: "c".repeat(64),
            spec_declaration_digest: "d".repeat(64),
        };
        let cancellation_case = case(&vectors, "cancel-after-control-publish");
        let cancelled_directory = TestDirectory::new("cancelled");
        let cancelled = create_workspace(
            &cancelled_directory.0,
            valid_binding.clone(),
            &CancelAt(CancellationPoint::AfterControlPublish),
        )
        .unwrap_err();
        assert_eq!(cancelled.code, cancellation_case["expected"]["code"]);
        assert_eq!(
            cancelled.data["remoteDurableState"],
            cancellation_case["expected"]["remoteDurableState"]
        );
        assert_eq!(
            fs::read_to_string(cancelled_directory.0.join(".ogvcs/initialization.json"))
                .map(|text| serde_json::from_str::<Value>(&text).unwrap()["state"].clone())
                .unwrap(),
            cancellation_case["expected"]["markerState"]
        );

        let auth_case = case(&vectors, "noninteractive-provider-unavailable");
        let auth =
            check_authentication(&Provider(CredentialStatus::Unavailable), true).unwrap_err();
        assert_eq!(auth.code, auth_case["expected"]["code"]);
        assert_eq!(auth.data["prompted"], auth_case["expected"]["prompted"]);

        let diagnostic_case = case(&vectors, "diagnostic-redaction");
        let diagnostic_directory = TestDirectory::new("diagnostic-secret-path");
        create_workspace(&diagnostic_directory.0, valid_binding, &NeverCancel).unwrap();
        let diagnostic_config = resolve_config(&ConfigInputs {
            flags: ConfigLayer {
                endpoint: Some(
                    diagnostic_case["input"]["endpoint"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ),
                profile: Some(
                    diagnostic_case["input"]["profile"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ),
                output: None,
            },
            ..ConfigInputs::default()
        })
        .unwrap();
        let preview = diagnostics_preview(
            &diagnostic_directory.0,
            &diagnostic_config,
            &Provider(CredentialStatus::HeadlessRequired),
        )
        .unwrap();
        assert_eq!(preview["schema"], diagnostic_case["expected"]["schema"]);
        assert_eq!(
            preview["redactionPolicy"],
            diagnostic_case["expected"]["redactionPolicy"]
        );
        let rendered = serde_json::to_string(&preview).unwrap();
        assert!(!rendered.contains(diagnostic_directory.0.to_string_lossy().as_ref()));
        for field in [
            "endpoint",
            "profile",
            "repositoryDeclarationDigest",
            "branchDeclarationDigest",
            "baselineDeclarationDigest",
            "specDeclarationDigest",
        ] {
            assert!(!rendered.contains(diagnostic_case["input"][field].as_str().unwrap()));
        }
        assert_eq!(
            open_workspace(&diagnostic_directory.0).unwrap().schema,
            "ogvcs.cli-workspace/workspace-report/v1"
        );
        assert!(resolved.machine_output());
    }
}
