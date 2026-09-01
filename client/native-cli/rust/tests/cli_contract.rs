use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = env::temp_dir().join(format!("ogvcs011-cli-{}-{}", label, std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir(&path).unwrap();
        #[cfg(not(windows))]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        #[cfg(windows)]
        protect_test_directory(&path);
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(windows)]
fn protect_test_directory(path: &std::path::Path) {
    let identity = String::from_utf8(Command::new("whoami").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let owner_status = Command::new("icacls")
        .arg(path)
        .args(["/setowner", &identity])
        .status()
        .unwrap();
    assert!(owner_status.success());
    let status = Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("{identity}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .status()
        .unwrap();
    assert!(status.success());
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
    assert_eq!(result["contractVersion"], ogvcs_local_cli::CONTRACT_VERSION);
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

#[test]
fn binary_remote_boundary_fails_closed_without_emitting_paths_locators_or_secrets() {
    let directory = TestDirectory::new("redaction-root-secret");
    let root = directory.path.to_string_lossy().into_owned();
    let locator = "repo:private-redaction-locator";
    let secret = "must-never-appear-secret-material";
    let create = Command::new(env!("CARGO_BIN_EXE_ogvcs"))
        .args([
            "--format",
            "json",
            "--non-interactive",
            "workspace",
            "create",
            "--root",
            &root,
            "--repository",
            locator,
            "--branch",
            "main",
            "--credential-env",
            "OGVCS_TOKEN_TEST_ONLY",
        ])
        .env("OGVCS_TOKEN_TEST_ONLY", secret)
        .env_remove("OGVCS_ENDPOINT")
        .env_remove("OGVCS_PROFILE")
        .env_remove("OGVCS_OUTPUT")
        .output()
        .unwrap();
    assert_eq!(
        create.status.code(),
        Some(7),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    let result = machine(&create);
    let rendered = serde_json::to_string(&result).unwrap();
    assert_eq!(result["code"], "PUBLIC_ROUTE_UNAVAILABLE");
    assert_eq!(result["data"]["mutationStarted"], false);
    assert!(!directory.path.join(".ogvcs").exists());
    for needle in [&root, locator, secret] {
        assert!(!rendered.contains(needle));
    }
}
