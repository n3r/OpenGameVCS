#![deny(warnings)]

use ogvcs_local_cli::production::{
    configure_verified_workspace, create_verified_workspace,
    remove_verified_workspace_with_progress, stage_add, AuthenticationRequest,
    AuthenticationSession, AuthenticationTransport, Cancellation, CapabilityOffer,
    CapabilitySelection, DiscardProgress, FileIdAllocationReceipt, NeverCancelled, OperationPhase,
    OsCredentialProvider, OsCredentialStore, PresentedFileIdAllocation, ProgressEvent,
    ProgressSink, RemoveWorkspaceOptions, RepositoryDiscovery, RepositoryDiscoveryRequest,
    RepositoryPublicRoutes, SecretMaterial, StageAddRequest, VerifiedBinding,
    WorkspaceConfigureRequest, WorkspaceCreateRequest, AUTHORIZATION_CONTRACT,
    AUTHORIZATION_REGISTRY_SHA256, EVENT_VERSION, FILE_ID_ALLOCATION_SCHEMA,
    MESSAGE_SCHEMA_VERSION, PATH_CONTRACT, PATH_REGISTRY_SHA256, PROTOCOL_REGISTRY_SET_SHA256,
    PROTOCOL_VERSION, REPOSITORY_FORMAT, REPOSITORY_REGISTRY_SHA256, REQUIRED_PROTOCOL_FEATURES,
    TRANSFER_PROFILE,
};
use ogvcs_local_cli::CliError;
use serde_json::json;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::io::Write;
#[cfg(not(windows))]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

const HARD_EXIT_CODE: i32 = 86;
const SIGNAL_WAIT_MAXIMUM: Duration = Duration::from_secs(15);

struct FixedStore;

impl OsCredentialStore for FixedStore {
    fn load(&self, _: &str) -> Result<SecretMaterial, CliError> {
        SecretMaterial::new(b"hermetic-test-only-secret".to_vec())
    }
}

#[derive(Default)]
struct FixtureRoutes;

impl AuthenticationTransport for FixtureRoutes {
    fn authenticate(
        &mut self,
        request: &AuthenticationRequest,
        secret: &SecretMaterial,
        _: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError> {
        assert_eq!(request.endpoint, "https://hermetic.invalid");
        assert_eq!(secret.expose_to_transport(), b"hermetic-test-only-secret");
        Ok(AuthenticationSession {
            subject_digest: "1".repeat(64),
            session_digest: "2".repeat(64),
            authority_epoch: 7,
            security_epoch: 9,
            expires_at_unix_ms: now_ms() + 3_600_000,
        })
    }
}

impl RepositoryPublicRoutes for FixtureRoutes {
    fn authentication_transport(&mut self) -> &mut dyn AuthenticationTransport {
        self
    }

    fn discover_repository(
        &mut self,
        _: &AuthenticationSession,
        request: &RepositoryDiscoveryRequest,
        _: &dyn Cancellation,
        _: &mut dyn ProgressSink,
    ) -> Result<RepositoryDiscovery, CliError> {
        Ok(RepositoryDiscovery {
            repository_id_hex: "00000000000040008000000000000002".to_owned(),
            branch: request.branch.clone(),
            baseline: format!("ogvcs:v1:snapshot:sha256:{}", "4".repeat(64)),
            case_mode: "case-folded".to_owned(),
            path_profile: "path.opengamevcs/portable@1".to_owned(),
            repository_settings_digest: "5".repeat(64),
        })
    }

    fn negotiate_capabilities(
        &mut self,
        _: &AuthenticationSession,
        discovery: &RepositoryDiscovery,
        offer: &CapabilityOffer,
        _: &dyn Cancellation,
        _: &mut dyn ProgressSink,
    ) -> Result<CapabilitySelection, CliError> {
        assert_eq!(offer.protocol_version, PROTOCOL_VERSION);
        assert_eq!(offer.required_features, REQUIRED_PROTOCOL_FEATURES);
        Ok(selection(&discovery.path_profile))
    }

    fn validate_binding(
        &mut self,
        session: &AuthenticationSession,
        binding: &VerifiedBinding,
        _: &dyn Cancellation,
    ) -> Result<(), CliError> {
        assert_eq!(session.subject_digest, binding.subject_digest);
        assert_eq!(binding.verification, "public-service-verified");
        Ok(())
    }

    fn present_preallocated_file_id(
        &mut self,
        _: &AuthenticationSession,
        binding: &VerifiedBinding,
        repository_path_key: &str,
        _: &dyn Cancellation,
    ) -> Result<PresentedFileIdAllocation, CliError> {
        assert!(repository_path_key.starts_with("ogvcs-path-key-v1:"));
        Ok(PresentedFileIdAllocation {
            allocation_schema_version: FILE_ID_ALLOCATION_SCHEMA.to_owned(),
            repository_id: repository_uuid(&binding.repository_id_hex),
            repository_path_key: repository_path_key.to_owned(),
            file_id: "fid:00000000000000000000000000000001".to_owned(),
            allocation_receipt: FileIdAllocationReceipt::new(format!("far1.{}", "A".repeat(43)))?,
            allocation_idempotency_key_sha256: "6".repeat(64),
            expires_at_unix_ms: now_ms() + 3_600_000,
        })
    }

    fn resolve_file_id(
        &mut self,
        _: &AuthenticationSession,
        _: &VerifiedBinding,
        repository_path_key: &str,
        _: &dyn Cancellation,
    ) -> Result<String, CliError> {
        assert!(repository_path_key.starts_with("ogvcs-path-key-v1:"));
        Ok("fid:00000000000000000000000000000002".to_owned())
    }
}

struct ExitOnPhase(OperationPhase);

impl ProgressSink for ExitOnPhase {
    fn emit(&mut self, event: &ProgressEvent) -> Result<(), CliError> {
        if event.phase == self.0 {
            process::exit(HARD_EXIT_CODE);
        }
        Ok(())
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_millis(),
    )
    .expect("current time fits u64")
}

fn selection(path_profile: &str) -> CapabilitySelection {
    CapabilitySelection {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        message_schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
        repository_format: REPOSITORY_FORMAT.to_owned(),
        authorization_contract: AUTHORIZATION_CONTRACT.to_owned(),
        authorization_registry_sha256: AUTHORIZATION_REGISTRY_SHA256.to_owned(),
        path_contract: PATH_CONTRACT.to_owned(),
        path_profile: path_profile.to_owned(),
        path_registry_sha256: PATH_REGISTRY_SHA256.to_owned(),
        event_version: EVENT_VERSION.to_owned(),
        transfer_profile: TRANSFER_PROFILE.to_owned(),
        protocol_registry_set_sha256: PROTOCOL_REGISTRY_SET_SHA256.to_owned(),
        repository_registry_sha256: REPOSITORY_REGISTRY_SHA256.to_owned(),
        required_features: REQUIRED_PROTOCOL_FEATURES
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        receipt_sha256: "a".repeat(64),
        expires_at_unix_ms: now_ms() + 3_600_000,
    }
}

fn repository_uuid(hex: &str) -> String {
    assert_eq!(hex.len(), 32);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn authentication() -> AuthenticationRequest {
    AuthenticationRequest {
        endpoint: "https://hermetic.invalid".to_owned(),
        profile: "hermetic".to_owned(),
        non_interactive: true,
    }
}

fn create_ready(root: &Path) -> Result<(), CliError> {
    let provider = OsCredentialProvider::new(&FixedStore);
    create_verified_workspace(
        &WorkspaceCreateRequest {
            root: root.to_path_buf(),
            repository_locator: "repo:hermetic".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut FixtureRoutes,
        &NeverCancelled,
        &mut DiscardProgress,
    )?;
    Ok(())
}

fn create_crash(root: &Path) -> Result<(), CliError> {
    let provider = OsCredentialProvider::new(&FixedStore);
    create_verified_workspace(
        &WorkspaceCreateRequest {
            root: root.to_path_buf(),
            repository_locator: "repo:hermetic".to_owned(),
            branch: "main".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut FixtureRoutes,
        &NeverCancelled,
        &mut ExitOnPhase(OperationPhase::Journal),
    )?;
    unreachable!("create journal exit boundary was not reached")
}

fn configure_crash(root: &Path) -> Result<(), CliError> {
    create_ready(root)?;
    let provider = OsCredentialProvider::new(&FixedStore);
    configure_verified_workspace(
        &WorkspaceConfigureRequest {
            root: root.to_path_buf(),
            repository_locator: "repo:hermetic".to_owned(),
            branch: "dev".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut FixtureRoutes,
        &NeverCancelled,
        &mut ExitOnPhase(OperationPhase::Journal),
    )?;
    unreachable!("configure journal exit boundary was not reached")
}

fn stage_add_crash(root: &Path) -> Result<(), CliError> {
    create_ready(root)?;
    fs::create_dir(root.join("Game")).expect("create fixture Game directory");
    fs::write(root.join("Game/new.bin"), b"hermetic-input").expect("write fixture input");
    let provider = OsCredentialProvider::new(&FixedStore);
    stage_add(
        &StageAddRequest {
            root: root.to_path_buf(),
            repository_path: "Game/new.bin".to_owned(),
            authentication: authentication(),
        },
        &provider,
        &mut FixtureRoutes,
        &NeverCancelled,
        &mut ExitOnPhase(OperationPhase::Journal),
    )?;
    unreachable!("stage-add journal exit boundary was not reached")
}

fn remove_crash(root: &Path, phase: OperationPhase) -> Result<(), CliError> {
    create_ready(root)?;
    remove_verified_workspace_with_progress(
        root,
        RemoveWorkspaceOptions {
            confirmed: true,
            non_interactive: true,
        },
        &NeverCancelled,
        &mut ExitOnPhase(phase),
    )?;
    unreachable!("remove exit boundary was not reached")
}

fn prepare_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() {
        return Err("ROOT_NOT_ABSOLUTE".to_owned());
    }
    fs::create_dir(root).map_err(|_| "ROOT_CREATE_FAILED".to_owned())?;
    #[cfg(not(windows))]
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|_| "ROOT_PROTECT_FAILED".to_owned())?;
    #[cfg(windows)]
    protect_windows_root(root)?;
    Ok(())
}

#[cfg(windows)]
fn protect_windows_root(root: &Path) -> Result<(), String> {
    let identity = String::from_utf8(
        Command::new("whoami")
            .output()
            .map_err(|_| "WINDOWS_IDENTITY_FAILED".to_owned())?
            .stdout,
    )
    .map_err(|_| "WINDOWS_IDENTITY_FAILED".to_owned())?
    .trim()
    .to_owned();
    if identity.is_empty() {
        return Err("WINDOWS_IDENTITY_FAILED".to_owned());
    }
    let owner = Command::new("icacls")
        .arg(root)
        .args(["/setowner", &identity])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "WINDOWS_ROOT_PROTECT_FAILED".to_owned())?;
    let protected = Command::new("icacls")
        .arg(root)
        .args([
            "/inheritance:r",
            "/grant:r",
            &format!("{identity}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "WINDOWS_ROOT_PROTECT_FAILED".to_owned())?;
    if !owner.success() || !protected.success() {
        return Err("WINDOWS_ROOT_PROTECT_FAILED".to_owned());
    }
    Ok(())
}

fn write_signal_ready(path: &Path) -> Result<(), String> {
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "SIGNAL_READY_FAILED".to_owned())?;
    file.sync_all()
        .map_err(|_| "SIGNAL_READY_FAILED".to_owned())
}

#[cfg(windows)]
fn wait_for_path(path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + SIGNAL_WAIT_MAXIMUM;
    while Instant::now() < deadline {
        if path.is_file() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Err("SIGNAL_READY_TIMEOUT".to_owned())
}

fn signal_child(ready: &Path) -> Result<(), String> {
    let cancellation = ogvcs_local_cli::production::ProcessSignalCancellation::install()
        .map_err(|_| "SIGNAL_INSTALL_FAILED".to_owned())?;
    write_signal_ready(ready)?;
    let deadline = Instant::now() + SIGNAL_WAIT_MAXIMUM;
    while Instant::now() < deadline && !cancellation.is_cancelled() {
        thread::sleep(Duration::from_millis(10));
    }
    if !cancellation.is_cancelled() {
        return Err("SIGNAL_DELIVERY_TIMEOUT".to_owned());
    }
    let error = cancellation
        .check("hermetic-signal")
        .expect_err("cancelled source returns an error");
    if error.data != json!({"phase": "hermetic-signal"}) {
        return Err("SIGNAL_RESULT_INVALID".to_owned());
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "code": error.code,
            "exitClass": error.exit_class,
            // This synchronized controller has not invoked a remote route; it
            // owns the narrower durable-state assertion that generic
            // Cancellation deliberately cannot make.
            "data": {
                "phase": "hermetic-signal",
                "remoteDurableState": "unchanged"
            },
        }))
        .expect("signal result serializes")
    );
    Ok(())
}

#[cfg(windows)]
fn windows_signal_parent(ready: &Path) -> Result<(), String> {
    let executable = env::current_exe().map_err(|_| "SIGNAL_EXECUTABLE_FAILED".to_owned())?;
    let mut child = Command::new(executable);
    child
        .args([OsString::from("signal-child"), ready.as_os_str().to_owned()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    child.creation_flags(CREATE_NEW_PROCESS_GROUP);
    let mut child = child
        .spawn()
        .map_err(|_| "SIGNAL_CHILD_START_FAILED".to_owned())?;
    if let Err(error) = wait_for_path(ready) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    // SAFETY: the child is an active console process-group leader created by
    // this helper, and CTRL_BREAK is scoped to that exact process group.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) } == 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("SIGNAL_DELIVERY_FAILED".to_owned());
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "SIGNAL_CHILD_WAIT_FAILED".to_owned())?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("SIGNAL_CHILD_FAILED".to_owned());
    }
    std::io::stdout()
        .write_all(&output.stdout)
        .map_err(|_| "SIGNAL_RESULT_WRITE_FAILED".to_owned())?;
    Ok(())
}

fn require_action_and_path() -> Result<(String, PathBuf), String> {
    let mut arguments = env::args_os().skip(1);
    let action = arguments
        .next()
        .ok_or_else(|| "ARGUMENTS_INVALID".to_owned())?
        .into_string()
        .map_err(|_| "ARGUMENTS_INVALID".to_owned())?;
    let path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "ARGUMENTS_INVALID".to_owned())?;
    if arguments.next().is_some() {
        return Err("ARGUMENTS_INVALID".to_owned());
    }
    Ok((action, path))
}

fn run() -> Result<(), String> {
    let (action, path) = require_action_and_path()?;
    match action.as_str() {
        "signal-child" => return signal_child(&path),
        #[cfg(windows)]
        "signal-windows" => return windows_signal_parent(&path),
        _ => prepare_root(&path)?,
    }
    let result = match action.as_str() {
        "empty-root" => Ok(()),
        "ready" => create_ready(&path),
        "crash-create-journal" => create_crash(&path),
        "crash-configure-journal" => configure_crash(&path),
        "crash-stage-add-journal" => stage_add_crash(&path),
        "crash-remove-journal" => remove_crash(&path, OperationPhase::Journal),
        "crash-remove-mutation" => remove_crash(&path, OperationPhase::Mutation),
        _ => return Err("ACTION_INVALID".to_owned()),
    };
    result.map_err(|error| error.code.to_owned())?;
    println!("{{\"ok\":true}}");
    Ok(())
}

fn main() {
    if let Err(code) = run() {
        eprintln!("fixture[{code}]");
        process::exit(70);
    }
}
