//! Local-only, fail-closed primitives for the OGVCS-011 candidate CLI.
//!
//! This crate deliberately owns no network protocol, server identity, working
//! tree mutation, or secret retrieval. See the package README for the boundary.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(windows))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub const CONTRACT_VERSION: &str = "0.1.0-rc.1";
pub const RESULT_SCHEMA: &str = "ogvcs.cli-workspace/result/v1";
pub const CONFIG_SCHEMA: &str = "ogvcs.cli-workspace/config-resolution/v1";
pub const WORKSPACE_SCHEMA: &str = "ogvcs.cli-workspace/workspace/v1";
pub const DIAGNOSTIC_SCHEMA: &str = "ogvcs.cli-workspace/diagnostic-preview/v1";

const WORKSPACE_FORMAT_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 32 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitClass {
    Success,
    Input,
    Workspace,
    Unsupported,
    Cancelled,
    InteractionRequired,
    Unavailable,
    Internal,
}

impl ExitClass {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Input => 2,
            Self::Workspace => 3,
            Self::Unsupported => 4,
            Self::Cancelled => 5,
            Self::InteractionRequired => 6,
            Self::Unavailable => 7,
            Self::Internal => 70,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CliError {
    pub exit_class: ExitClass,
    pub code: &'static str,
    pub message: &'static str,
    pub next_step: &'static str,
    pub data: Value,
}

impl CliError {
    fn new(
        exit_class: ExitClass,
        code: &'static str,
        message: &'static str,
        next_step: &'static str,
    ) -> Self {
        Self {
            exit_class,
            code,
            message,
            next_step,
            data: json!({}),
        }
    }

    fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }
}

fn input_error() -> CliError {
    CliError::new(
        ExitClass::Input,
        "INPUT_INVALID",
        "The command input is not valid for this local-only candidate.",
        "Use --help to choose a supported command and provide bounded, nonsecret values.",
    )
}

fn config_error() -> CliError {
    CliError::new(
        ExitClass::Input,
        "CONFIG_INVALID",
        "A configuration source is malformed, unsupported, or contains a secret-like field.",
        "Remove secret fields and use endpoint, profile, and output values from the v1 contract.",
    )
}

fn workspace_error(code: &'static str, message: &'static str, next_step: &'static str) -> CliError {
    CliError::new(ExitClass::Workspace, code, message, next_step)
}

#[cfg(windows)]
fn unsupported_workspace_error() -> CliError {
    CliError::new(
        ExitClass::Unsupported,
        "WORKSPACE_SAFETY_UNSUPPORTED",
        "This platform cannot make the candidate's required private-workspace safety check.",
        "Use a supported private filesystem or wait for the platform ACL adapter contract.",
    )
}

fn cancelled_error() -> CliError {
    CliError::new(
        ExitClass::Cancelled,
        "OPERATION_CANCELLED",
        "The local metadata operation was cancelled before remote state could change.",
        "Run workspace recover before retrying if a recovery marker is present.",
    )
    .with_data(json!({"remoteDurableState": "unchanged"}))
}

#[derive(Clone, Debug)]
pub struct ProcessOutcome {
    pub machine: bool,
    pub ok: bool,
    pub exit_code: i32,
    pub code: String,
    pub message: String,
    pub next_step: String,
    pub exit_class: ExitClass,
    pub data: Value,
}

impl ProcessOutcome {
    fn success(machine: bool, code: &'static str, message: &'static str, data: Value) -> Self {
        Self {
            machine,
            ok: true,
            exit_code: ExitClass::Success.exit_code(),
            code: code.to_owned(),
            message: message.to_owned(),
            next_step: "No further local action is required.".to_owned(),
            exit_class: ExitClass::Success,
            data,
        }
    }

    fn failure(machine: bool, error: CliError) -> Self {
        Self {
            machine,
            ok: false,
            exit_code: error.exit_class.exit_code(),
            code: error.code.to_owned(),
            message: error.message.to_owned(),
            next_step: error.next_step.to_owned(),
            exit_class: error.exit_class,
            data: error.data,
        }
    }

    pub fn render_machine(&self) -> String {
        let envelope = json!({
            "schema": RESULT_SCHEMA,
            "contractVersion": CONTRACT_VERSION,
            "ok": self.ok,
            "exitClass": self.exit_class,
            "code": self.code,
            "message": self.message,
            "nextStep": self.next_step,
            "data": self.data,
        });
        serde_json::to_string(&envelope).unwrap_or_else(|_| {
            "{\"schema\":\"ogvcs.cli-workspace/result/v1\",\"contractVersion\":\"0.1.0-rc.1\",\"ok\":false,\"exitClass\":\"internal\",\"code\":\"INTERNAL_SERIALIZATION\",\"message\":\"The candidate could not serialize a result.\",\"nextStep\":\"Retry with a supported local command.\",\"data\":{}}".to_owned()
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigSource {
    Flag,
    Environment,
    Workspace,
    UserProfile,
    SystemDefault,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourcedValue {
    pub value: String,
    pub source: ConfigSource,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedConfig {
    pub schema: &'static str,
    pub contract_version: &'static str,
    pub endpoint: SourcedValue,
    pub profile: SourcedValue,
    pub output: SourcedValue,
}

impl ResolvedConfig {
    pub fn machine_output(&self) -> bool {
        self.output.value == "json"
    }

    pub fn as_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConfigLayer {
    pub endpoint: Option<String>,
    pub profile: Option<String>,
    pub output: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigInputs {
    pub flags: ConfigLayer,
    pub environment: BTreeMap<String, String>,
    pub workspace_config: Option<PathBuf>,
    pub user_config: Option<PathBuf>,
    pub system_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskConfigLayer {
    endpoint: Option<String>,
    profile: Option<String>,
    output: Option<String>,
}

impl From<DiskConfigLayer> for ConfigLayer {
    fn from(value: DiskConfigLayer) -> Self {
        Self {
            endpoint: value.endpoint,
            profile: value.profile,
            output: value.output,
        }
    }
}

pub fn resolve_config(inputs: &ConfigInputs) -> Result<ResolvedConfig, CliError> {
    let environment = ConfigLayer {
        endpoint: inputs.environment.get("OGVCS_ENDPOINT").cloned(),
        profile: inputs.environment.get("OGVCS_PROFILE").cloned(),
        output: inputs.environment.get("OGVCS_OUTPUT").cloned(),
    };
    let workspace = load_config(inputs.workspace_config.as_deref())?;
    let user = load_config(inputs.user_config.as_deref())?;
    let system_file = load_config(inputs.system_config.as_deref())?;
    let defaults = ConfigLayer {
        endpoint: Some("https://localhost".to_owned()),
        profile: Some("default".to_owned()),
        output: Some("human".to_owned()),
    };
    let system = ConfigLayer {
        endpoint: system_file.endpoint.or(defaults.endpoint),
        profile: system_file.profile.or(defaults.profile),
        output: system_file.output.or(defaults.output),
    };

    Ok(ResolvedConfig {
        schema: CONFIG_SCHEMA,
        contract_version: CONTRACT_VERSION,
        endpoint: resolve_string(
            &inputs.flags.endpoint,
            &environment.endpoint,
            &workspace.endpoint,
            &user.endpoint,
            &system.endpoint,
            validate_endpoint,
        )?,
        profile: resolve_string(
            &inputs.flags.profile,
            &environment.profile,
            &workspace.profile,
            &user.profile,
            &system.profile,
            validate_profile,
        )?,
        output: resolve_string(
            &inputs.flags.output,
            &environment.output,
            &workspace.output,
            &user.output,
            &system.output,
            validate_output,
        )?,
    })
}

fn resolve_string<F>(
    flag: &Option<String>,
    environment: &Option<String>,
    workspace: &Option<String>,
    user: &Option<String>,
    system: &Option<String>,
    validate: F,
) -> Result<SourcedValue, CliError>
where
    F: Fn(&str) -> Result<(), CliError>,
{
    let (value, source) = if let Some(value) = flag {
        (value, ConfigSource::Flag)
    } else if let Some(value) = environment {
        (value, ConfigSource::Environment)
    } else if let Some(value) = workspace {
        (value, ConfigSource::Workspace)
    } else if let Some(value) = user {
        (value, ConfigSource::UserProfile)
    } else if let Some(value) = system {
        (value, ConfigSource::SystemDefault)
    } else {
        return Err(config_error());
    };
    validate(value)?;
    Ok(SourcedValue {
        value: value.clone(),
        source,
    })
}

fn load_config(path: Option<&Path>) -> Result<ConfigLayer, CliError> {
    let Some(path) = path else {
        return Ok(ConfigLayer::default());
    };
    let bytes = read_config_bounded(path)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| config_error())?;
    reject_secret_keys(&value)?;
    let layer: DiskConfigLayer = serde_json::from_value(value).map_err(|_| config_error())?;
    Ok(layer.into())
}

fn read_config_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    #[cfg(windows)]
    {
        let metadata = fs::symlink_metadata(path).map_err(|_| config_error())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(config_error());
        }
        let bytes = fs::read(path).map_err(|_| config_error())?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(config_error());
        }
        Ok(bytes)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(path).map_err(|_| config_error())?;
        let metadata = file.metadata().map_err(|_| config_error())?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(config_error());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        let mut limited = Read::take(&mut file, MAX_CONFIG_BYTES + 1);
        Read::read_to_end(&mut limited, &mut bytes).map_err(|_| config_error())?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(config_error());
        }
        Ok(bytes)
    }
}

fn reject_secret_keys(value: &Value) -> Result<(), CliError> {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let normalized = key.to_ascii_lowercase();
                if [
                    "token",
                    "secret",
                    "credential",
                    "password",
                    "authorization",
                    "cookie",
                    "key",
                ]
                .iter()
                .any(|needle| normalized.contains(needle))
                {
                    return Err(config_error());
                }
                reject_secret_keys(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_secret_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_endpoint(value: &str) -> Result<(), CliError> {
    if value.len() > 512
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.contains('\\')
    {
        return Err(config_error());
    }
    let Some((scheme, remainder)) = value.split_once("://") else {
        return Err(config_error());
    };
    if !matches!(scheme, "http" | "https") || remainder.is_empty() {
        return Err(config_error());
    }
    let host = remainder.split('/').next().unwrap_or_default();
    if host.is_empty() || host.starts_with(':') {
        return Err(config_error());
    }
    Ok(())
}

fn validate_profile(value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(config_error());
    }
    Ok(())
}

fn validate_output(value: &str) -> Result<(), CliError> {
    if matches!(value, "human" | "json") {
        Ok(())
    } else {
        Err(config_error())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialStatus {
    Available,
    Unavailable,
    HeadlessRequired,
}

/// A provider deliberately returns only safe availability state. It has no API
/// that can expose or serialize a raw credential in this candidate.
pub trait CredentialProvider {
    fn status(&self) -> CredentialStatus;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableCredentialProvider;

impl CredentialProvider for UnavailableCredentialProvider {
    fn status(&self) -> CredentialStatus {
        CredentialStatus::Unavailable
    }
}

pub fn check_authentication(
    provider: &dyn CredentialProvider,
    non_interactive: bool,
) -> Result<Value, CliError> {
    match provider.status() {
        CredentialStatus::Available => Ok(json!({"credentialStatus": "available"})),
        CredentialStatus::Unavailable | CredentialStatus::HeadlessRequired if non_interactive => {
            Err(CliError::new(
                ExitClass::InteractionRequired,
                "AUTHENTICATION_REQUIRED",
                "Authentication is required in noninteractive mode.",
                "Configure a supported credential provider before rerunning this command.",
            )
            .with_data(json!({"credentialStatus": "unavailable", "prompted": false})))
        }
        CredentialStatus::Unavailable | CredentialStatus::HeadlessRequired => Err(CliError::new(
            ExitClass::InteractionRequired,
            "INTERACTION_REQUIRED",
            "Authentication requires an interactive credential provider.",
            "Configure a supported credential provider; this candidate does not prompt.",
        )
        .with_data(json!({"credentialStatus": "unavailable", "prompted": false}))),
    }
}

#[derive(Clone, Debug)]
pub struct WorkspaceBindingInput {
    pub repository_declaration_digest: String,
    pub branch_declaration_digest: String,
    pub baseline_declaration_digest: String,
    pub spec_declaration_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationPoint {
    BeforeStaging,
    AfterStaging,
    AfterControlPublish,
}

pub trait CancellationProbe {
    fn cancelled(&self, point: CancellationPoint) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancel;

impl CancellationProbe for NeverCancel {
    fn cancelled(&self, _: CancellationPoint) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CancelAt(pub CancellationPoint);

impl CancellationProbe for CancelAt {
    fn cancelled(&self, point: CancellationPoint) -> bool {
        self.0 == point
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceReport {
    pub schema: &'static str,
    pub contract_version: &'static str,
    pub state: &'static str,
    pub root_digest: String,
    pub workspace_id_digest: String,
    pub binding_verification: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkspaceMetadata {
    schema: String,
    format_version: u32,
    state: WorkspaceState,
    workspace_id: String,
    root_digest: String,
    binding: LocalBinding,
    created_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WorkspaceState {
    Staging,
    Ready,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalBinding {
    repository_declaration_digest: String,
    branch_declaration_digest: String,
    baseline_declaration_digest: String,
    spec_declaration_digest: String,
    verification: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitializationMarker {
    schema: String,
    format_version: u32,
    state: String,
    workspace_id: String,
    root_digest: String,
}

pub fn create_workspace(
    requested_root: &Path,
    binding: WorkspaceBindingInput,
    cancellation: &dyn CancellationProbe,
) -> Result<WorkspaceReport, CliError> {
    validate_binding(&binding)?;
    let root = validated_root(requested_root)?;
    let root_digest = digest_path(&root);
    let control = control_path(&root);
    match fs::symlink_metadata(&control) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(workspace_error(
                    "UNSAFE_WORKSPACE",
                    "The workspace control directory is a symlink or unsafe object.",
                    "Remove the unsafe control directory only after inspecting it outside this CLI.",
                ));
            }
            return Err(workspace_error(
                "WORKSPACE_EXISTS",
                "A workspace control directory already exists at this root.",
                "Open or recover the existing workspace instead of creating another one.",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(workspace_error(
                "WORKSPACE_CREATE_UNAVAILABLE",
                "The workspace control directory could not be inspected safely.",
                "Check private filesystem ownership and retry workspace creation.",
            ));
        }
    }
    if cancellation.cancelled(CancellationPoint::BeforeStaging) {
        return Err(cancelled_error());
    }

    let workspace_id = format!("wsl1.{}", random_hex(32)?);
    let stage = root.join(format!(".ogvcs-init-v1-{}", random_hex(16)?));
    create_private_directory(&stage)?;
    let metadata = WorkspaceMetadata {
        schema: WORKSPACE_SCHEMA.to_owned(),
        format_version: WORKSPACE_FORMAT_VERSION,
        state: WorkspaceState::Staging,
        workspace_id: workspace_id.clone(),
        root_digest: root_digest.clone(),
        binding: LocalBinding {
            repository_declaration_digest: binding.repository_declaration_digest,
            branch_declaration_digest: binding.branch_declaration_digest,
            baseline_declaration_digest: binding.baseline_declaration_digest,
            spec_declaration_digest: binding.spec_declaration_digest,
            verification: "unverified-local-declaration".to_owned(),
        },
        created_at_unix_ms: now_unix_ms()?,
    };
    let marker = InitializationMarker {
        schema: "ogvcs.cli-workspace/initialization/v1".to_owned(),
        format_version: WORKSPACE_FORMAT_VERSION,
        state: "initializing".to_owned(),
        workspace_id: workspace_id.clone(),
        root_digest: root_digest.clone(),
    };
    write_json_new(&stage.join("workspace.json"), &metadata)?;
    write_json_new(&stage.join("initialization.json"), &marker)?;
    sync_directory(&stage)?;

    if cancellation.cancelled(CancellationPoint::AfterStaging) {
        let _ = fs::remove_dir_all(&stage);
        return Err(cancelled_error());
    }

    fs::rename(&stage, &control).map_err(|_| {
        workspace_error(
            "WORKSPACE_CREATE_UNAVAILABLE",
            "The workspace metadata could not be published atomically.",
            "Retry on a private local filesystem after checking for an existing workspace.",
        )
    })?;
    sync_directory(&root)?;

    if cancellation.cancelled(CancellationPoint::AfterControlPublish) {
        return Err(cancelled_error());
    }

    let ready = WorkspaceMetadata {
        state: WorkspaceState::Ready,
        ..metadata
    };
    let completed_marker = InitializationMarker {
        state: "complete".to_owned(),
        ..marker
    };
    if write_json_atomic(&control.join("workspace.json"), &ready).is_err()
        || write_json_atomic(&control.join("initialization.json"), &completed_marker).is_err()
    {
        return Err(workspace_error(
            "WORKSPACE_RECOVERY_REQUIRED",
            "Workspace initialization was interrupted after local metadata publication.",
            "Run workspace recover before using this workspace.",
        ));
    }

    report_from_metadata(&ready)
}

pub fn open_workspace(requested_root: &Path) -> Result<WorkspaceReport, CliError> {
    let root = validated_root(requested_root)?;
    let control = checked_control_directory(&root)?;
    let metadata = read_workspace_metadata(&control)?;
    validate_workspace_metadata(&metadata, &digest_path(&root))?;
    let marker = initialization_marker(&control)?.ok_or_else(|| {
        workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is missing its required initialization record.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )
    })?;
    validate_marker(&marker, &metadata)?;
    if marker.state == "initializing" {
        return Err(workspace_error(
            "WORKSPACE_RECOVERY_REQUIRED",
            "Workspace initialization has a valid recovery marker.",
            "Run workspace recover before using this workspace.",
        ));
    }
    if metadata.state != WorkspaceState::Ready || marker.state != "complete" {
        return Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is not in a usable ready state.",
            "Recover only a workspace with a valid initialization marker; otherwise recreate it safely.",
        ));
    }
    report_from_metadata(&metadata)
}

pub fn recover_workspace(requested_root: &Path) -> Result<WorkspaceReport, CliError> {
    let root = validated_root(requested_root)?;
    let control = checked_control_directory(&root)?;
    let mut metadata = read_workspace_metadata(&control)?;
    validate_workspace_metadata(&metadata, &digest_path(&root))?;
    let marker = initialization_marker(&control)?.ok_or_else(|| {
        workspace_error(
            "WORKSPACE_RECOVERY_NOT_NEEDED",
            "This workspace has no valid recovery marker.",
            "Use workspace open, or inspect the workspace before attempting recovery.",
        )
    })?;
    validate_marker(&marker, &metadata)?;
    if marker.state == "complete" && metadata.state == WorkspaceState::Ready {
        return report_from_metadata(&metadata);
    }
    if marker.state == "complete" {
        return Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is inconsistent with its completed initialization record.",
            "Recreate the workspace safely instead of promoting inconsistent metadata.",
        ));
    }
    if metadata.state == WorkspaceState::Staging {
        metadata.state = WorkspaceState::Ready;
        write_json_atomic(&control.join("workspace.json"), &metadata)?;
    }
    let completed_marker = InitializationMarker {
        state: "complete".to_owned(),
        ..marker
    };
    write_json_atomic(&control.join("initialization.json"), &completed_marker)?;
    report_from_metadata(&metadata)
}

pub fn diagnostics_preview(
    requested_root: &Path,
    config: &ResolvedConfig,
    provider: &dyn CredentialProvider,
) -> Result<Value, CliError> {
    let root = validated_root(requested_root)?;
    let report = open_workspace(&root)?;
    Ok(json!({
        "schema": DIAGNOSTIC_SCHEMA,
        "contractVersion": CONTRACT_VERSION,
        "preview": true,
        "written": false,
        "workspaceState": report.state,
        "workspaceRootDigest": report.root_digest,
        "workspaceIdDigest": report.workspace_id_digest,
        "endpointDigest": digest_text(&config.endpoint.value),
        "endpointScheme": endpoint_scheme(&config.endpoint.value),
        "configSources": {
            "endpoint": config.endpoint.source,
            "profile": config.profile.source,
            "output": config.output.source,
        },
        "credentialStatus": provider.status(),
        "redactionPolicy": "v1-no-paths-identities-or-secrets",
    }))
}

pub fn create_diagnostics(
    requested_root: &Path,
    name: &str,
    config: &ResolvedConfig,
    provider: &dyn CredentialProvider,
) -> Result<Value, CliError> {
    validate_diagnostic_name(name)?;
    let root = validated_root(requested_root)?;
    let control = checked_control_directory(&root)?;
    let _ = open_workspace(&root)?;
    let diagnostics = control.join("diagnostics");
    if !diagnostics.exists() {
        create_private_directory(&diagnostics)?;
        sync_directory(&control)?;
    }
    ensure_private_directory(&diagnostics)?;
    let preview = diagnostics_preview(&root, config, provider)?;
    let destination = diagnostics.join(name);
    if destination.exists() {
        return Err(workspace_error(
            "DIAGNOSTIC_EXISTS",
            "A diagnostic artifact with that safe name already exists.",
            "Choose a new artifact name or inspect the existing local diagnostic.",
        ));
    }
    let mut artifact = preview;
    let fields = artifact.as_object_mut().ok_or_else(internal_error)?;
    fields.insert("preview".to_owned(), Value::Bool(false));
    fields.insert("written".to_owned(), Value::Bool(true));
    fields.insert("artifactName".to_owned(), Value::String(name.to_owned()));
    write_json_new(&destination, &artifact)?;
    sync_directory(&diagnostics)?;
    let bytes = serde_json::to_vec(&artifact).map_err(|_| internal_error())?;
    artifact.as_object_mut().ok_or_else(internal_error)?.insert(
        "artifactDigest".to_owned(),
        Value::String(digest_bytes(&bytes)),
    );
    Ok(artifact)
}

fn validate_diagnostic_name(name: &str) -> Result<(), CliError> {
    if name.is_empty()
        || name.len() > 64
        || name == "."
        || name == ".."
        || name.contains("..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(input_error());
    }
    Ok(())
}

fn validate_binding(binding: &WorkspaceBindingInput) -> Result<(), CliError> {
    for hint in [
        &binding.repository_declaration_digest,
        &binding.branch_declaration_digest,
        &binding.baseline_declaration_digest,
        &binding.spec_declaration_digest,
    ] {
        if !valid_digest(hint) {
            return Err(input_error());
        }
    }
    Ok(())
}

fn report_from_metadata(metadata: &WorkspaceMetadata) -> Result<WorkspaceReport, CliError> {
    Ok(WorkspaceReport {
        schema: WORKSPACE_SCHEMA,
        contract_version: CONTRACT_VERSION,
        state: match metadata.state {
            WorkspaceState::Ready => "ready",
            WorkspaceState::Staging => "staging",
        },
        root_digest: metadata.root_digest.clone(),
        workspace_id_digest: digest_text(&metadata.workspace_id),
        binding_verification: "unverified-local-declaration",
    })
}

fn validated_root(requested_root: &Path) -> Result<PathBuf, CliError> {
    #[cfg(windows)]
    {
        let _ = requested_root;
        return Err(unsupported_workspace_error());
    }
    #[cfg(not(windows))]
    {
        if !requested_root.is_absolute() {
            return Err(input_error());
        }
        let original = fs::symlink_metadata(requested_root).map_err(|_| {
            workspace_error(
                "WORKSPACE_ROOT_UNAVAILABLE",
                "The workspace root is unavailable.",
                "Create a private existing directory and pass its absolute path.",
            )
        })?;
        if original.file_type().is_symlink() || !original.is_dir() {
            return Err(workspace_error(
                "UNSAFE_WORKSPACE",
                "The workspace root is a symlink or is not a directory.",
                "Use an owned private directory that is not a symlink.",
            ));
        }
        let root = fs::canonicalize(requested_root).map_err(|_| {
            workspace_error(
                "WORKSPACE_ROOT_UNAVAILABLE",
                "The workspace root is unavailable.",
                "Create a private existing directory and pass its absolute path.",
            )
        })?;
        ensure_private_directory(&root)?;
        Ok(root)
    }
}

fn control_path(root: &Path) -> PathBuf {
    root.join(".ogvcs")
}

fn checked_control_directory(root: &Path) -> Result<PathBuf, CliError> {
    let control = control_path(root);
    let metadata = fs::symlink_metadata(&control).map_err(|_| {
        workspace_error(
            "WORKSPACE_NOT_FOUND",
            "No local workspace metadata exists at this root.",
            "Run workspace create with a private local directory first.",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(workspace_error(
            "UNSAFE_WORKSPACE",
            "The workspace control directory is a symlink or unsafe object.",
            "Remove the unsafe control directory only after inspecting it outside this CLI.",
        ));
    }
    ensure_private_directory(&control)?;
    Ok(control)
}

fn read_workspace_metadata(control: &Path) -> Result<WorkspaceMetadata, CliError> {
    let path = control.join("workspace.json");
    let bytes = read_bounded(&path, MAX_METADATA_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| {
        workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is malformed or uses an unsupported format.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )
    })
}

fn initialization_marker(control: &Path) -> Result<Option<InitializationMarker>, CliError> {
    let path = control.join("initialization.json");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_bounded(&path, MAX_METADATA_BYTES)?;
            let marker = serde_json::from_slice(&bytes).map_err(|_| {
                workspace_error(
                    "WORKSPACE_METADATA_INVALID",
                    "Workspace metadata is malformed or uses an unsupported format.",
                    "Recover a valid initialization marker or recreate the workspace safely.",
                )
            })?;
            Ok(Some(marker))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is malformed or uses an unsupported format.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )),
    }
}

fn validate_workspace_metadata(
    metadata: &WorkspaceMetadata,
    root_digest: &str,
) -> Result<(), CliError> {
    let valid = metadata.schema == WORKSPACE_SCHEMA
        && metadata.format_version == WORKSPACE_FORMAT_VERSION
        && valid_workspace_id(&metadata.workspace_id)
        && valid_digest(&metadata.root_digest)
        && metadata.root_digest == root_digest
        && metadata.created_at_unix_ms > 0
        && metadata.binding.verification == "unverified-local-declaration"
        && valid_digest(&metadata.binding.repository_declaration_digest)
        && valid_digest(&metadata.binding.branch_declaration_digest)
        && valid_digest(&metadata.binding.baseline_declaration_digest)
        && valid_digest(&metadata.binding.spec_declaration_digest);
    if valid {
        Ok(())
    } else {
        Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is malformed or does not belong to this root.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        ))
    }
}

fn validate_marker(
    marker: &InitializationMarker,
    metadata: &WorkspaceMetadata,
) -> Result<(), CliError> {
    if marker.schema == "ogvcs.cli-workspace/initialization/v1"
        && marker.format_version == WORKSPACE_FORMAT_VERSION
        && matches!(marker.state.as_str(), "initializing" | "complete")
        && marker.workspace_id == metadata.workspace_id
        && marker.root_digest == metadata.root_digest
    {
        Ok(())
    } else {
        Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is malformed or uses an unsupported format.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        ))
    }
}

fn valid_workspace_id(value: &str) -> bool {
    value.len() == 69
        && value.starts_with("wsl1.")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn create_private_directory(path: &Path) -> Result<(), CliError> {
    fs::create_dir(path).map_err(|_| {
        workspace_error(
            "WORKSPACE_CREATE_UNAVAILABLE",
            "Private workspace metadata could not be created.",
            "Retry on an owned private local filesystem.",
        )
    })?;
    #[cfg(not(windows))]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
        workspace_error(
            "WORKSPACE_CREATE_UNAVAILABLE",
            "Private workspace metadata could not be created.",
            "Retry on an owned private local filesystem.",
        )
    })?;
    ensure_private_directory(path)
}

fn ensure_private_directory(path: &Path) -> Result<(), CliError> {
    #[cfg(windows)]
    {
        let _ = path;
        return Err(unsupported_workspace_error());
    }
    #[cfg(not(windows))]
    {
        let _ = open_private_directory(path)?;
        Ok(())
    }
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, CliError> {
    let mut file = open_private_regular_file(path)?;
    let metadata = file.metadata().map_err(|_| {
        workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is missing or unsafe.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )
    })?;
    if metadata.len() > maximum {
        return Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata exceeds the candidate's bounded format limit.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut limited = Read::take(&mut file, maximum + 1);
    Read::read_to_end(&mut limited, &mut bytes).map_err(|_| {
        workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is missing or unsafe.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )
    })?;
    if bytes.len() as u64 > maximum {
        return Err(workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata exceeds the candidate's bounded format limit.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        ));
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn open_private_directory(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| {
        workspace_error(
            "UNSAFE_WORKSPACE",
            "Workspace ownership or permissions are unsafe.",
            "Use an owned directory with no group or other access.",
        )
    })?;
    let metadata = file.metadata().map_err(|_| {
        workspace_error(
            "UNSAFE_WORKSPACE",
            "Workspace ownership or permissions are unsafe.",
            "Use an owned directory with no group or other access.",
        )
    })?;
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
        return Err(workspace_error(
            "UNSAFE_WORKSPACE",
            "Workspace ownership or permissions are unsafe.",
            "Use an owned directory with no group or other access.",
        ));
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_private_regular_file(path: &Path) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|_| {
        workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is missing or unsafe.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )
    })?;
    let metadata = file.metadata().map_err(|_| {
        workspace_error(
            "WORKSPACE_METADATA_INVALID",
            "Workspace metadata is missing or unsafe.",
            "Recover a valid initialization marker or recreate the workspace safely.",
        )
    })?;
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
        return Err(workspace_error(
            "UNSAFE_WORKSPACE",
            "Workspace metadata ownership or permissions are unsafe.",
            "Use an owned workspace with no group or other access.",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_private_regular_file(_: &Path) -> Result<File, CliError> {
    Err(unsupported_workspace_error())
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let bytes = serde_json::to_vec(value).map_err(|_| internal_error())?;
    let mut file = create_private_file(path, true)?;
    file.write_all(&bytes)
        .map_err(|_| write_workspace_error())?;
    file.write_all(b"\n").map_err(|_| write_workspace_error())?;
    file.sync_all().map_err(|_| write_workspace_error())?;
    Ok(())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(internal_error)?;
    ensure_private_directory(parent)?;
    let temporary = parent.join(format!(".workspace-v1-{}.tmp", random_hex(16)?));
    let result = (|| {
        let bytes = serde_json::to_vec(value).map_err(|_| internal_error())?;
        let mut file = create_private_file(&temporary, true)?;
        file.write_all(&bytes)
            .map_err(|_| write_workspace_error())?;
        file.write_all(b"\n").map_err(|_| write_workspace_error())?;
        file.sync_all().map_err(|_| write_workspace_error())?;
        fs::rename(&temporary, path).map_err(|_| write_workspace_error())?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn create_private_file(path: &Path, create_new: bool) -> Result<File, CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(create_new);
    #[cfg(not(windows))]
    options.mode(0o600);
    options.open(path).map_err(|_| write_workspace_error())
}

fn write_workspace_error() -> CliError {
    workspace_error(
        "WORKSPACE_WRITE_UNAVAILABLE",
        "Local workspace metadata could not be written safely.",
        "Check private filesystem ownership and run workspace recover if initialization was published.",
    )
}

fn sync_directory(path: &Path) -> Result<(), CliError> {
    #[cfg(windows)]
    {
        let _ = path;
        return Err(unsupported_workspace_error());
    }
    #[cfg(not(windows))]
    {
        open_private_directory(path)
            .and_then(|directory| directory.sync_all().map_err(|_| write_workspace_error()))
    }
}

fn random_hex(bytes: usize) -> Result<String, CliError> {
    let mut random = vec![0_u8; bytes];
    getrandom::getrandom(&mut random).map_err(|_| {
        CliError::new(
            ExitClass::Unavailable,
            "LOCAL_RANDOM_UNAVAILABLE",
            "The local random source is unavailable.",
            "Retry after the operating system random source is available.",
        )
    })?;
    Ok(hex(&random))
}

fn now_unix_ms() -> Result<u64, CliError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        CliError::new(
            ExitClass::Unavailable,
            "LOCAL_CLOCK_UNAVAILABLE",
            "The local clock cannot provide a valid workspace timestamp.",
            "Correct the local system clock and retry workspace creation.",
        )
    })?;
    u64::try_from(duration.as_millis()).map_err(|_| {
        CliError::new(
            ExitClass::Unavailable,
            "LOCAL_CLOCK_UNAVAILABLE",
            "The local clock cannot provide a valid workspace timestamp.",
            "Correct the local system clock and retry workspace creation.",
        )
    })
}

fn digest_path(path: &Path) -> String {
    digest_bytes(path.as_os_str().to_string_lossy().as_bytes())
}

fn digest_text(value: &str) -> String {
    digest_bytes(value.as_bytes())
}

fn digest_bytes(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex(&hasher.finalize())
}

fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn endpoint_scheme(endpoint: &str) -> &'static str {
    if endpoint.starts_with("https://") {
        "https"
    } else {
        "http"
    }
}

fn internal_error() -> CliError {
    CliError::new(
        ExitClass::Internal,
        "INTERNAL_ERROR",
        "The local candidate encountered an internal failure.",
        "Retry the bounded local command; if it persists, create a redacted diagnostic preview.",
    )
}

#[derive(Clone, Debug, Default)]
struct GlobalOptions {
    non_interactive: bool,
    config: ConfigInputs,
    command: Vec<String>,
}

fn parse_global(args: &[String]) -> Result<GlobalOptions, CliError> {
    let mut parsed = GlobalOptions::default();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--non-interactive" => {
                if parsed.non_interactive {
                    return Err(input_error());
                }
                parsed.non_interactive = true;
                index += 1;
            }
            "--format" => {
                let value = args.get(index + 1).ok_or_else(input_error)?;
                if parsed.config.flags.output.is_some() {
                    return Err(input_error());
                }
                parsed.config.flags.output = Some(value.clone());
                index += 2;
            }
            "--endpoint" => {
                let value = args.get(index + 1).ok_or_else(input_error)?;
                if parsed.config.flags.endpoint.is_some() {
                    return Err(input_error());
                }
                parsed.config.flags.endpoint = Some(value.clone());
                index += 2;
            }
            "--profile" => {
                let value = args.get(index + 1).ok_or_else(input_error)?;
                if parsed.config.flags.profile.is_some() {
                    return Err(input_error());
                }
                parsed.config.flags.profile = Some(value.clone());
                index += 2;
            }
            "--workspace-config" => {
                let value = args.get(index + 1).ok_or_else(input_error)?;
                if parsed.config.workspace_config.is_some() {
                    return Err(input_error());
                }
                parsed.config.workspace_config = Some(PathBuf::from(value));
                index += 2;
            }
            "--user-config" => {
                let value = args.get(index + 1).ok_or_else(input_error)?;
                if parsed.config.user_config.is_some() {
                    return Err(input_error());
                }
                parsed.config.user_config = Some(PathBuf::from(value));
                index += 2;
            }
            "--system-config" => {
                let value = args.get(index + 1).ok_or_else(input_error)?;
                if parsed.config.system_config.is_some() {
                    return Err(input_error());
                }
                parsed.config.system_config = Some(PathBuf::from(value));
                index += 2;
            }
            _ => {
                parsed.command.push(args[index].clone());
                index += 1;
            }
        }
    }
    parsed.config.environment = environment_config();
    Ok(parsed)
}

fn environment_config() -> BTreeMap<String, String> {
    ["OGVCS_ENDPOINT", "OGVCS_PROFILE", "OGVCS_OUTPUT"]
        .into_iter()
        .filter_map(|name| env::var(name).ok().map(|value| (name.to_owned(), value)))
        .collect()
}

pub fn run_process<I>(args: I) -> ProcessOutcome
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let machine_hint = requested_machine_output(&args);
    let provider = UnavailableCredentialProvider;
    run_with_provider(&args, &provider)
        .unwrap_or_else(|error| ProcessOutcome::failure(machine_hint, error))
}

pub fn run_with_provider(
    args: &[String],
    provider: &dyn CredentialProvider,
) -> Result<ProcessOutcome, CliError> {
    let parsed = parse_global(args)?;
    let config = resolve_config(&parsed.config)?;
    let machine = config.machine_output();
    let command = parsed.command.as_slice();
    let (code, message, data) = match command {
        [first] if first == "--help" || first == "help" => (
            "HELP",
            "Supported local candidate commands are available.",
            json!({
                "commands": [
                    "config show",
                    "auth check",
                    "workspace create",
                    "workspace open",
                    "workspace recover",
                    "diagnostics preview",
                    "diagnostics create"
                ],
                "unsupported": ["sync", "submit", "status", "locks", "working-tree-mutation"]
            }),
        ),
        [first, second] if first == "config" && second == "show" => (
            "CONFIG_RESOLVED",
            "The effective nonsecret configuration was resolved.",
            config.as_json(),
        ),
        [first, second] if first == "auth" && second == "check" => {
            let data = check_authentication(provider, parsed.non_interactive)?;
            (
                "AUTHENTICATION_AVAILABLE",
                "Credential availability was checked without prompting.",
                data,
            )
        }
        [first, second, rest @ ..] if first == "workspace" && second == "create" => {
            let values = named_values(
                rest,
                &[
                    "root",
                    "repository-declaration-digest",
                    "branch-declaration-digest",
                    "baseline-declaration-digest",
                    "spec-declaration-digest",
                ],
            )?;
            let root = required_value(&values, "root")?;
            let binding = WorkspaceBindingInput {
                repository_declaration_digest: required_value(
                    &values,
                    "repository-declaration-digest",
                )?
                .to_owned(),
                branch_declaration_digest: required_value(&values, "branch-declaration-digest")?
                    .to_owned(),
                baseline_declaration_digest: required_value(
                    &values,
                    "baseline-declaration-digest",
                )?
                .to_owned(),
                spec_declaration_digest: required_value(&values, "spec-declaration-digest")?
                    .to_owned(),
            };
            let report = create_workspace(Path::new(root), binding, &NeverCancel)?;
            (
                "WORKSPACE_CREATED",
                "Private local workspace metadata was created atomically.",
                serde_json::to_value(report).map_err(|_| internal_error())?,
            )
        }
        [first, second, rest @ ..] if first == "workspace" && second == "open" => {
            let values = named_values(rest, &["root"])?;
            let report = open_workspace(Path::new(required_value(&values, "root")?))?;
            (
                "WORKSPACE_OPEN",
                "Private local workspace metadata was opened.",
                serde_json::to_value(report).map_err(|_| internal_error())?,
            )
        }
        [first, second, rest @ ..] if first == "workspace" && second == "recover" => {
            let values = named_values(rest, &["root"])?;
            let report = recover_workspace(Path::new(required_value(&values, "root")?))?;
            (
                "WORKSPACE_RECOVERED",
                "Private local workspace metadata was recovered.",
                serde_json::to_value(report).map_err(|_| internal_error())?,
            )
        }
        [first, second, rest @ ..] if first == "diagnostics" && second == "preview" => {
            let values = named_values(rest, &["root"])?;
            let data = diagnostics_preview(
                Path::new(required_value(&values, "root")?),
                &config,
                provider,
            )?;
            (
                "DIAGNOSTICS_PREVIEW",
                "A redacted diagnostic preview was prepared without writing a bundle.",
                data,
            )
        }
        [first, second, rest @ ..] if first == "diagnostics" && second == "create" => {
            let values = named_values(rest, &["root", "name"])?;
            let data = create_diagnostics(
                Path::new(required_value(&values, "root")?),
                required_value(&values, "name")?,
                &config,
                provider,
            )?;
            (
                "DIAGNOSTICS_CREATED",
                "A redacted diagnostic artifact was created explicitly.",
                data,
            )
        }
        _ => return Err(input_error()),
    };
    Ok(ProcessOutcome::success(machine, code, message, data))
}

fn requested_machine_output(args: &[String]) -> bool {
    args.windows(2)
        .any(|pair| pair[0] == "--format" && pair[1] == "json")
        || env::var("OGVCS_OUTPUT").ok().as_deref() == Some("json")
}

fn named_values(
    values: &[String],
    accepted: &[&str],
) -> Result<BTreeMap<String, String>, CliError> {
    let mut parsed = BTreeMap::new();
    let mut index = 0;
    while index < values.len() {
        let Some(name) = values[index].strip_prefix("--") else {
            return Err(input_error());
        };
        if !accepted.contains(&name) {
            return Err(input_error());
        }
        let value = values.get(index + 1).ok_or_else(input_error)?;
        if value.starts_with("--") || parsed.insert(name.to_owned(), value.clone()).is_some() {
            return Err(input_error());
        }
        index += 2;
    }
    Ok(parsed)
}

fn required_value<'a>(
    values: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, CliError> {
    values.get(name).map(String::as_str).ok_or_else(input_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(not(windows))]
    #[derive(Clone, Copy)]
    struct TestProvider(CredentialStatus);

    #[cfg(not(windows))]
    impl CredentialProvider for TestProvider {
        fn status(&self) -> CredentialStatus {
            self.0
        }
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path =
                env::temp_dir().join(format!("ogvcs011-{}-{}", label, random_hex(12).unwrap()));
            fs::create_dir(&path).unwrap();
            #[cfg(not(windows))]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(not(windows))]
    fn binding() -> WorkspaceBindingInput {
        WorkspaceBindingInput {
            repository_declaration_digest: "a".repeat(64),
            branch_declaration_digest: "b".repeat(64),
            baseline_declaration_digest: "c".repeat(64),
            spec_declaration_digest: "d".repeat(64),
        }
    }

    #[test]
    fn configuration_precedence_and_sources_are_fieldwise() {
        let directory = TestDirectory::new("config-precedence");
        let workspace = directory.path.join("workspace.json");
        let user = directory.path.join("user.json");
        let system = directory.path.join("system.json");
        fs::write(
            &workspace,
            r#"{"endpoint":"https://workspace.example","profile":"workspace","output":"human"}"#,
        )
        .unwrap();
        fs::write(
            &user,
            r#"{"endpoint":"https://user.example","profile":"user","output":"json"}"#,
        )
        .unwrap();
        fs::write(
            &system,
            r#"{"endpoint":"https://system.example","profile":"system","output":"human"}"#,
        )
        .unwrap();
        let mut environment = BTreeMap::new();
        environment.insert(
            "OGVCS_ENDPOINT".to_owned(),
            "https://environment.example".to_owned(),
        );
        environment.insert("OGVCS_PROFILE".to_owned(), "environment".to_owned());
        let result = resolve_config(&ConfigInputs {
            flags: ConfigLayer {
                endpoint: Some("https://flag.example".to_owned()),
                profile: None,
                output: Some("json".to_owned()),
            },
            environment,
            workspace_config: Some(workspace),
            user_config: Some(user),
            system_config: Some(system),
        })
        .unwrap();
        assert_eq!(result.endpoint.value, "https://flag.example");
        assert_eq!(result.endpoint.source, ConfigSource::Flag);
        assert_eq!(result.profile.value, "environment");
        assert_eq!(result.profile.source, ConfigSource::Environment);
        assert_eq!(result.output.value, "json");
        assert_eq!(result.output.source, ConfigSource::Flag);
    }

    #[test]
    fn secret_like_configuration_is_rejected_before_reporting() {
        let directory = TestDirectory::new("secret-config");
        let config = directory.path.join("config.json");
        fs::write(
            &config,
            r#"{"endpoint":"https://safe.example","token":"not-for-output"}"#,
        )
        .unwrap();
        let error = resolve_config(&ConfigInputs {
            user_config: Some(config),
            ..ConfigInputs::default()
        })
        .unwrap_err();
        assert_eq!(error.code, "CONFIG_INVALID");
        assert!(!error.message.contains("not-for-output"));
    }

    #[cfg(not(windows))]
    #[test]
    fn workspace_create_open_and_recovery_are_atomic_and_redacted() {
        let directory = TestDirectory::new("recovery");
        let cancelled = create_workspace(
            &directory.path,
            binding(),
            &CancelAt(CancellationPoint::AfterControlPublish),
        )
        .unwrap_err();
        assert_eq!(cancelled.code, "OPERATION_CANCELLED");
        assert_eq!(cancelled.data["remoteDurableState"], "unchanged");
        assert_eq!(
            open_workspace(&directory.path).unwrap_err().code,
            "WORKSPACE_RECOVERY_REQUIRED"
        );
        let recovered = recover_workspace(&directory.path).unwrap();
        assert_eq!(recovered.state, "ready");
        assert_ne!(recovered.workspace_id_digest, "a".repeat(64));
        assert_eq!(open_workspace(&directory.path).unwrap().state, "ready");
        assert_eq!(recover_workspace(&directory.path).unwrap().state, "ready");
    }

    #[cfg(not(windows))]
    #[test]
    fn cancellation_before_or_during_staging_never_publishes_a_workspace() {
        for point in [
            CancellationPoint::BeforeStaging,
            CancellationPoint::AfterStaging,
        ] {
            let directory = TestDirectory::new("cancel-early");
            let error = create_workspace(&directory.path, binding(), &CancelAt(point)).unwrap_err();
            assert_eq!(error.code, "OPERATION_CANCELLED");
            assert!(!directory.path.join(".ogvcs").exists());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn raw_declarations_are_rejected_before_workspace_creation() {
        let directory = TestDirectory::new("raw-declaration");
        let mut input = binding();
        input.repository_declaration_digest = "raw-declaration".to_owned();
        let error = create_workspace(&directory.path, input, &NeverCancel).unwrap_err();
        assert_eq!(error.code, "INPUT_INVALID");
        assert!(!directory.path.join(".ogvcs").exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn diagnostics_and_noninteractive_auth_do_not_expose_identity_path_or_secret() {
        let directory = TestDirectory::new("redaction-secret-needle");
        create_workspace(&directory.path, binding(), &NeverCancel).unwrap();
        let config = resolve_config(&ConfigInputs::default()).unwrap();
        let preview = diagnostics_preview(
            &directory.path,
            &config,
            &TestProvider(CredentialStatus::HeadlessRequired),
        )
        .unwrap();
        let rendered = serde_json::to_string(&preview).unwrap();
        assert!(!rendered.contains("redaction-secret-needle"));
        assert!(!rendered.contains(directory.path.to_string_lossy().as_ref()));
        assert!(!rendered.contains(&"a".repeat(64)));
        let error =
            check_authentication(&TestProvider(CredentialStatus::Unavailable), true).unwrap_err();
        assert_eq!(error.code, "AUTHENTICATION_REQUIRED");
        assert_eq!(error.data["prompted"], false);
    }

    #[cfg(not(windows))]
    #[test]
    fn hostile_control_symlink_and_malformed_recovery_marker_fail_closed() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new("hostile");
        let outside = TestDirectory::new("outside");
        symlink(&outside.path, directory.path.join(".ogvcs")).unwrap();
        assert_eq!(
            open_workspace(&directory.path).unwrap_err().code,
            "UNSAFE_WORKSPACE"
        );
        fs::remove_file(directory.path.join(".ogvcs")).unwrap();
        create_workspace(&directory.path, binding(), &NeverCancel).unwrap();
        let marker = directory.path.join(".ogvcs").join("initialization.json");
        fs::write(&marker, b"not-json").unwrap();
        #[cfg(not(windows))]
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            open_workspace(&directory.path).unwrap_err().code,
            "WORKSPACE_METADATA_INVALID"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn explicit_diagnostic_creation_is_private_and_preview_does_not_write() {
        let directory = TestDirectory::new("diagnostic-write");
        create_workspace(&directory.path, binding(), &NeverCancel).unwrap();
        let metadata =
            fs::read_to_string(directory.path.join(".ogvcs").join("workspace.json")).unwrap();
        assert!(metadata.contains(&"a".repeat(64)));
        assert!(metadata.contains(&"c".repeat(64)));
        assert!(metadata.contains("repositoryDeclarationDigest"));
        let journal =
            fs::read_to_string(directory.path.join(".ogvcs").join("initialization.json")).unwrap();
        assert!(journal.contains("\"state\":\"complete\""));
        let config = resolve_config(&ConfigInputs::default()).unwrap();
        let preview = diagnostics_preview(
            &directory.path,
            &config,
            &TestProvider(CredentialStatus::Available),
        )
        .unwrap();
        assert_eq!(preview["written"], false);
        assert!(!directory.path.join(".ogvcs").join("diagnostics").exists());
        let created = create_diagnostics(
            &directory.path,
            "support.json",
            &config,
            &TestProvider(CredentialStatus::Available),
        )
        .unwrap();
        assert_eq!(created["written"], true);
        let artifact = fs::read_to_string(
            directory
                .path
                .join(".ogvcs")
                .join("diagnostics")
                .join("support.json"),
        )
        .unwrap();
        assert!(!artifact.contains("diagnostic-write"));
        assert!(!artifact.contains(&"a".repeat(64)));
    }
}
