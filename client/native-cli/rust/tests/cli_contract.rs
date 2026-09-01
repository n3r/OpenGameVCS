use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;

// The renderer applies CliResult's numeric limits as strict UTF-8 byte bounds.
// Its labels therefore keep every plain-log line below this implementation
// ceiling without wrapping, cursor movement, or terminal-width detection.
const MAX_PLAIN_LOG_LINE_BYTES: usize = 384;
const TERMINAL_ENVIRONMENT_KEYS: &[&str] = &[
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLORTERM",
    "FORCE_COLOR",
    "NO_COLOR",
    "TERM",
];

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

fn invocation(arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ogvcs"));
    command
        .args(arguments)
        .env_remove("OGVCS_ENDPOINT")
        .env_remove("OGVCS_PROFILE")
        .env_remove("OGVCS_OUTPUT");
    for key in TERMINAL_ENVIRONMENT_KEYS {
        command.env_remove(key);
    }
    command
}

fn invoke(arguments: &[&str]) -> Output {
    invocation(arguments).output().unwrap()
}

fn invoke_with_terminal_environment(arguments: &[&str], environment: &[(&str, &str)]) -> Output {
    let mut command = invocation(arguments);
    command.envs(environment.iter().copied());
    command.output().unwrap()
}

fn assert_plain_log(bytes: &[u8], expected_lines: usize) {
    let text = std::str::from_utf8(bytes).expect("plain output must be UTF-8");
    assert!(
        text.ends_with('\n'),
        "plain output must end with one newline"
    );
    assert!(
        !text.contains('\r'),
        "plain output must not contain CR controls"
    );
    assert!(
        !text.contains('\u{1b}'),
        "plain output must not contain ANSI escapes"
    );
    let lines: Vec<_> = text.strip_suffix('\n').unwrap().split('\n').collect();
    assert_eq!(
        lines.len(),
        expected_lines,
        "unexpected plain-log line count"
    );
    for line in lines {
        assert!(
            !line.is_empty(),
            "plain-log lines must be labeled and nonempty"
        );
        assert!(
            line.len() <= MAX_PLAIN_LOG_LINE_BYTES,
            "plain-log line exceeds the bounded implementation ceiling"
        );
        assert!(
            line.chars().all(|character| !character.is_control()),
            "plain-log line contains a terminal control character"
        );
    }
}

fn assert_same_output(actual: &Output, expected: &Output) {
    assert_eq!(actual.status.code(), expected.status.code());
    assert_eq!(actual.stdout, expected.stdout);
    assert_eq!(actual.stderr, expected.stderr);
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

    let human_override = invocation(&["--format", "human", "--non-interactive", "auth", "check"])
        .env("OGVCS_OUTPUT", "json")
        .output()
        .unwrap();
    assert_eq!(human_override.status.code(), Some(6));
    assert!(human_override.stdout.is_empty());
    assert!(String::from_utf8(human_override.stderr)
        .unwrap()
        .contains("error[AUTHENTICATION_REQUIRED]"));
}

#[test]
fn binary_plain_logs_are_color_free_ordered_bounded_and_environment_invariant() {
    const HUMAN_FAILURE: &str = concat!(
        "error[AUTHENTICATION_REQUIRED]: Authentication is required in noninteractive mode.\n",
        "Next step: Configure a supported credential provider before rerunning this command.\n",
    );
    const HUMAN_SUCCESS: &str =
        concat!("ok[CONFIG_RESOLVED]: The effective nonsecret configuration was resolved.\n",);
    const MACHINE_FAILURE: &str = concat!(
        "{\"code\":\"AUTHENTICATION_REQUIRED\",",
        "\"contractManifestSha256\":\"44080958394ac47bb12ae43b6fd897f14a7d0ada98b68f8b0474afed8b18e4ad\",",
        "\"contractVersion\":\"0.2.0-rc.2\",",
        "\"data\":{\"credentialStatus\":\"unavailable\",\"prompted\":false},",
        "\"exitClass\":\"interaction-required\",",
        "\"message\":\"Authentication is required in noninteractive mode.\",",
        "\"nextStep\":\"Configure a supported credential provider before rerunning this command.\",",
        "\"ok\":false,\"schema\":\"ogvcs.cli-workspace/result/v1\"}\n",
    );
    let terminal_environments: &[&[(&str, &str)]] = &[
        &[],
        &[("TERM", "dumb"), ("NO_COLOR", "1")],
        &[
            ("TERM", "xterm-256color"),
            ("COLORTERM", "truecolor"),
            ("CLICOLOR", "1"),
            ("CLICOLOR_FORCE", "1"),
            ("FORCE_COLOR", "3"),
        ],
        &[
            ("TERM", "xterm-256color"),
            ("NO_COLOR", "1"),
            ("CLICOLOR_FORCE", "1"),
            ("FORCE_COLOR", "3"),
        ],
    ];

    let canonical_failure = invoke_with_terminal_environment(
        &["--format", "human", "--non-interactive", "auth", "check"],
        terminal_environments[0],
    );
    assert_eq!(canonical_failure.status.code(), Some(6));
    assert!(canonical_failure.stdout.is_empty());
    assert_eq!(canonical_failure.stderr, HUMAN_FAILURE.as_bytes());
    assert_plain_log(&canonical_failure.stderr, 2);

    let canonical_success = invoke_with_terminal_environment(
        &["--format", "human", "config", "show"],
        terminal_environments[0],
    );
    assert_eq!(canonical_success.status.code(), Some(0));
    assert!(canonical_success.stderr.is_empty());
    assert_eq!(canonical_success.stdout, HUMAN_SUCCESS.as_bytes());
    assert_plain_log(&canonical_success.stdout, 1);

    let canonical_machine = invoke_with_terminal_environment(
        &["--format", "json", "--non-interactive", "auth", "check"],
        terminal_environments[0],
    );
    assert_eq!(canonical_machine.status.code(), Some(6));
    assert!(canonical_machine.stderr.is_empty());
    assert_eq!(canonical_machine.stdout, MACHINE_FAILURE.as_bytes());
    let canonical_value = machine(&canonical_machine);
    assert_eq!(canonical_value["code"], "AUTHENTICATION_REQUIRED");
    assert_eq!(
        canonical_value["nextStep"],
        "Configure a supported credential provider before rerunning this command."
    );

    // Command::output pipes both streams and supplies no interactive stdin.
    // Exact equality across contradictory color hints proves that neither the
    // plain-log nor machine path branches on terminal decoration state.
    for environment in terminal_environments.iter().skip(1) {
        let failure = invoke_with_terminal_environment(
            &["--format", "human", "--non-interactive", "auth", "check"],
            environment,
        );
        assert_same_output(&failure, &canonical_failure);
        assert_plain_log(&failure.stderr, 2);

        let success =
            invoke_with_terminal_environment(&["--format", "human", "config", "show"], environment);
        assert_same_output(&success, &canonical_success);
        assert_plain_log(&success.stdout, 1);

        let machine_output = invoke_with_terminal_environment(
            &["--format", "json", "--non-interactive", "auth", "check"],
            environment,
        );
        assert_same_output(&machine_output, &canonical_machine);
        assert_eq!(machine(&machine_output), canonical_value);
    }
}

#[test]
fn binary_remote_boundary_fails_closed_without_emitting_paths_locators_or_secrets() {
    let directory = TestDirectory::new("redaction-root-secret");
    let root = directory.path.to_string_lossy().into_owned();
    let locator = "repo:private-redaction-locator";
    let secret = "must-never-appear-secret-material";
    let create = invocation(&[
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

    let human_create = invocation(&[
        "--format",
        "human",
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
    .env("TERM", "xterm-256color")
    .env("NO_COLOR", "1")
    .env("CLICOLOR_FORCE", "1")
    .env("FORCE_COLOR", "3")
    .env("OGVCS_TOKEN_TEST_ONLY", secret)
    .output()
    .unwrap();
    assert_eq!(human_create.status.code(), Some(7));
    assert!(human_create.stdout.is_empty());
    assert_eq!(
        human_create.stderr,
        concat!(
            "error[PUBLIC_ROUTE_UNAVAILABLE]: An owning public service route is not available in this build.\n",
            "Next step: Install an adapter for the published OGVCS service contract before retrying.\n",
        )
        .as_bytes(),
    );
    assert_plain_log(&human_create.stderr, 2);
    let human_rendered = String::from_utf8(human_create.stderr).unwrap();
    for needle in [&root, locator, secret] {
        assert!(!human_rendered.contains(needle));
    }
    assert!(!directory.path.join(".ogvcs").exists());
}
