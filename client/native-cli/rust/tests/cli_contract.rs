use serde_json::Value;
use std::env;
#[cfg(not(windows))]
use std::fs;
use std::process::{Command, Output};

#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
#[cfg(not(windows))]
use std::path::PathBuf;

#[cfg(not(windows))]
struct TestDirectory {
    path: PathBuf,
}

#[cfg(not(windows))]
impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = env::temp_dir().join(format!("ogvcs011-cli-{}-{}", label, std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir(&path).unwrap();
        #[cfg(not(windows))]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self { path }
    }
}

#[cfg(not(windows))]
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn invoke(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ogvcs"))
        .args(arguments)
        .env_remove("OGVCS_ENDPOINT")
        .env_remove("OGVCS_PROFILE")
        .env_remove("OGVCS_OUTPUT")
        .output()
        .unwrap()
}

fn machine(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn binary_emits_versioned_machine_results_and_never_prompts_noninteractive_auth() {
    let config = invoke(&["--format", "json", "config", "show"]);
    assert_eq!(config.status.code(), Some(0));
    let result = machine(&config);
    assert_eq!(result["schema"], "ogvcs.cli-workspace/result/v1");
    assert_eq!(result["contractVersion"], "0.1.0-rc.1");
    assert_eq!(result["contractManifestSha256"].as_str().unwrap().len(), 64);
    assert_eq!(result["exitClass"], "success");
    assert_eq!(result["data"]["endpoint"]["source"], "system-default");

    let auth = invoke(&["--format", "json", "--non-interactive", "auth", "check"]);
    assert_eq!(auth.status.code(), Some(6));
    let failure = machine(&auth);
    assert_eq!(failure["ok"], false);
    assert_eq!(failure["exitClass"], "interaction-required");
    assert_eq!(failure["code"], "AUTHENTICATION_REQUIRED");
    assert_eq!(failure["data"]["prompted"], false);
    assert!(auth.stderr.is_empty());

    let human_override = Command::new(env!("CARGO_BIN_EXE_ogvcs"))
        .args(["--format", "human", "--non-interactive", "auth", "check"])
        .env("OGVCS_OUTPUT", "json")
        .env_remove("OGVCS_ENDPOINT")
        .env_remove("OGVCS_PROFILE")
        .output()
        .unwrap();
    assert_eq!(human_override.status.code(), Some(6));
    assert!(human_override.stdout.is_empty());
    assert!(String::from_utf8(human_override.stderr)
        .unwrap()
        .contains("error[AUTHENTICATION_REQUIRED]"));
}

#[cfg(not(windows))]
#[test]
fn binary_workspace_and_diagnostic_results_do_not_emit_raw_root_or_declarations() {
    let directory = TestDirectory::new("redaction-root-secret");
    let root = directory.path.to_string_lossy().into_owned();
    let create = invoke(&[
        "--format",
        "json",
        "workspace",
        "create",
        "--root",
        &root,
        "--repository-declaration-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--branch-declaration-digest",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--baseline-declaration-digest",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--spec-declaration-digest",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ]);
    assert_eq!(create.status.code(), Some(0));
    let created = machine(&create);
    let rendered = serde_json::to_string(&created).unwrap();
    assert_eq!(created["code"], "WORKSPACE_CREATED");
    assert_eq!(
        created["data"]["schema"],
        "ogvcs.cli-workspace/workspace-report/v1"
    );
    assert_eq!(
        created["data"]["bindingVerification"],
        "unverified-local-declaration"
    );
    assert!(!rendered.contains(&root));
    assert!(!rendered.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    let preview = invoke(&[
        "--format",
        "json",
        "diagnostics",
        "preview",
        "--root",
        &root,
    ]);
    assert_eq!(preview.status.code(), Some(0));
    let diagnostic = machine(&preview);
    let diagnostic_rendered = serde_json::to_string(&diagnostic).unwrap();
    assert_eq!(
        diagnostic["data"]["redactionPolicy"],
        "v1-no-paths-identities-or-secrets"
    );
    assert!(!diagnostic_rendered.contains(&root));
    assert!(!diagnostic_rendered
        .contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    let created_diagnostic = invoke(&[
        "--format",
        "json",
        "diagnostics",
        "create",
        "--root",
        &root,
        "--name",
        "support.json",
    ]);
    assert_eq!(created_diagnostic.status.code(), Some(0));
    let written = machine(&created_diagnostic);
    assert_eq!(written["data"]["preview"], false);
    assert_eq!(written["data"]["written"], true);
    assert_eq!(written["data"]["workspaceState"], "ready");
    assert_eq!(written["data"]["artifactName"], "support.json");
    assert_eq!(
        written["data"]["artifactDigest"].as_str().unwrap().len(),
        64
    );
}

#[cfg(windows)]
#[test]
fn binary_workspace_commands_fail_closed_without_an_acl_adapter() {
    let root = env::temp_dir().to_string_lossy().into_owned();
    let output = invoke(&[
        "--format",
        "json",
        "workspace",
        "create",
        "--root",
        &root,
        "--repository-declaration-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--branch-declaration-digest",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--baseline-declaration-digest",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--spec-declaration-digest",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    ]);
    assert_eq!(output.status.code(), Some(4));
    let result = machine(&output);
    assert_eq!(result["code"], "WORKSPACE_SAFETY_UNSUPPORTED");
    assert_eq!(result["exitClass"], "unsupported");
}
