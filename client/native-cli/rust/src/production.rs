//! Production-oriented OGVCS-011 local foundation.
//!
//! Network ownership remains behind explicit public ports. The first-party
//! binary installs `UnavailablePublicRoutes`, so it cannot turn local caller
//! declarations into a verified workspace until OGVCS-006/008/009 publish and
//! bind their routes. Tests and downstream adapters can implement these ports
//! without gaining access to private database types.

use super::{
    digest_bytes, digest_path, digest_text, input_error, internal_error, now_unix_ms, random_hex,
    read_bounded, sync_directory, valid_digest, validated_root, workspace_error, CliError,
    CredentialStatus, ExitClass,
};
use ogvcs_object_model::{FileId, ObjectKind, ObjectRef};
use ogvcs_path_contract::{path_collision_keys, CaseMode, PathProfile};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{compiler_fence, AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(not(windows))]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

pub const VERIFIED_WORKSPACE_FORMAT_VERSION: u32 = 2;
pub const VERIFIED_WORKSPACE_SCHEMA: &str = "ogvcs.cli-workspace/verified-workspace/v2";
pub const VERIFIED_WORKSPACE_REPORT_SCHEMA: &str =
    "ogvcs.cli-workspace/verified-workspace-report/v2";
pub const STAGING_SCHEMA: &str = "ogvcs.cli-workspace/staging/v1";
pub const PROGRESS_SCHEMA: &str = "ogvcs.cli-workspace/progress/v1";
pub const MAX_STAGED_INTENTS: usize = 10_000;
pub const MAX_LIST_ROOTS: usize = 1_024;
const MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;

pub const PROTOCOL_VERSION: &str = "ogvcs.control.https-json@1";
pub const MESSAGE_SCHEMA_VERSION: &str = "ogvcs.protocol.schema@1";
pub const REPOSITORY_FORMAT: &str = "ogvcs.repository-format@1";
pub const AUTHORIZATION_CONTRACT: &str = "ogvcs.authorization@1";
pub const PATH_CONTRACT: &str = "ogvcs.path-filesystem@1";
pub const EVENT_VERSION: &str = "ogvcs.events.base@1";
pub const TRANSFER_PROFILE: &str = "ogvcs.transfer.range-resume-probe@1";
pub const PORTABLE_PATH_PROFILE: &str = "path.opengamevcs/portable@1";
pub const AUTHORIZATION_REGISTRY_SHA256: &str =
    "293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc";
pub const PATH_REGISTRY_SHA256: &str =
    "bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42";
pub const PROTOCOL_REGISTRY_SET_SHA256: &str =
    "2b1913f9451b9f99966a24942a262846f07662b17cbb41ad6eea6474c23b4352";
pub const REPOSITORY_REGISTRY_SHA256: &str =
    "6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6";
pub const FILE_ID_ALLOCATION_SCHEMA: &str = "ogvcs.repository-metadata/file-id-allocation/v1";
pub const REQUIRED_PROTOCOL_FEATURES: &[&str] = &[
    "ogvcs.receipt.hmac-sha256@1",
    "ogvcs.stream.explicit-terminal@1",
    "ogvcs.idempotency.semantic-jcs@1",
];

fn route_unavailable(route: &'static str) -> CliError {
    CliError::new(
        ExitClass::Unavailable,
        "PUBLIC_ROUTE_UNAVAILABLE",
        "An owning public service route is not available in this build.",
        "Install an adapter for the published OGVCS service contract before retrying.",
    )
    .with_data(json!({"route": route, "mutationStarted": false}))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRequest {
    pub endpoint: String,
    pub profile: String,
    pub non_interactive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationSession {
    pub subject_digest: String,
    pub session_digest: String,
    pub authority_epoch: u64,
    pub security_epoch: u64,
    pub expires_at_unix_ms: u64,
}

/// Secret bytes are intentionally non-Clone, non-Debug, and non-serializable.
/// They are overwritten on drop. A transport adapter may inspect them only
/// during the synchronous authentication invocation.
pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CliError> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 || bytes.contains(&0) {
            return Err(CliError::new(
                ExitClass::InteractionRequired,
                "CREDENTIAL_INVALID",
                "The configured credential provider returned an invalid secret.",
                "Repair or rotate the credential in the selected secure provider.",
            ));
        }
        Ok(Self(bytes))
    }

    pub fn expose_to_transport(&self) -> &[u8] {
        &self.0
    }

    fn zeroize(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: each pointer is valid and exclusively borrowed; volatile
            // writes plus the compiler fence prevent dead-store elimination.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub trait AuthenticationTransport {
    fn authenticate(
        &mut self,
        request: &AuthenticationRequest,
        secret: &SecretMaterial,
        cancellation: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError>;
}

pub trait SecureCredentialProvider {
    fn kind(&self) -> &'static str;
    fn status(&self) -> CredentialStatus;
    fn invoke(
        &self,
        request: &AuthenticationRequest,
        transport: &mut dyn AuthenticationTransport,
        cancellation: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError>;
}

#[derive(Default)]
pub struct UnavailableSecureCredentialProvider;

impl SecureCredentialProvider for UnavailableSecureCredentialProvider {
    fn kind(&self) -> &'static str {
        "unavailable"
    }

    fn status(&self) -> CredentialStatus {
        CredentialStatus::Unavailable
    }

    fn invoke(
        &self,
        _: &AuthenticationRequest,
        _: &mut dyn AuthenticationTransport,
        _: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError> {
        Err(authentication_required())
    }
}

/// Explicit headless provider. The secret is read from the named environment
/// variable only inside `invoke`, never accepted as a command-line value.
pub struct HeadlessEnvironmentProvider {
    variable: String,
}

impl HeadlessEnvironmentProvider {
    pub fn new(variable: String) -> Result<Self, CliError> {
        if variable.len() < 13
            || variable.len() > 96
            || !variable.starts_with("OGVCS_TOKEN_")
            || !variable
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(input_error());
        }
        Ok(Self { variable })
    }
}

impl SecureCredentialProvider for HeadlessEnvironmentProvider {
    fn kind(&self) -> &'static str {
        "explicit-headless-environment"
    }

    fn status(&self) -> CredentialStatus {
        if env::var_os(&self.variable).is_some() {
            CredentialStatus::Available
        } else {
            CredentialStatus::HeadlessRequired
        }
    }

    fn invoke(
        &self,
        request: &AuthenticationRequest,
        transport: &mut dyn AuthenticationTransport,
        cancellation: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError> {
        cancellation.check("authentication")?;
        let value = env::var_os(&self.variable).ok_or_else(authentication_required)?;
        let bytes = os_string_secret_bytes(value)?;
        let secret = SecretMaterial::new(bytes)?;
        transport.authenticate(request, &secret, cancellation)
    }
}

pub trait OsCredentialStore {
    fn load(&self, profile: &str) -> Result<SecretMaterial, CliError>;
}

pub struct OsCredentialProvider<'a> {
    store: &'a dyn OsCredentialStore,
}

impl<'a> OsCredentialProvider<'a> {
    pub const fn new(store: &'a dyn OsCredentialStore) -> Self {
        Self { store }
    }
}

impl SecureCredentialProvider for OsCredentialProvider<'_> {
    fn kind(&self) -> &'static str {
        "os-credential-store"
    }

    fn status(&self) -> CredentialStatus {
        CredentialStatus::Available
    }

    fn invoke(
        &self,
        request: &AuthenticationRequest,
        transport: &mut dyn AuthenticationTransport,
        cancellation: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError> {
        cancellation.check("authentication")?;
        let secret = self.store.load(&request.profile)?;
        transport.authenticate(request, &secret, cancellation)
    }
}

fn os_string_secret_bytes(value: std::ffi::OsString) -> Result<Vec<u8>, CliError> {
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(value.into_vec())
    }
    #[cfg(windows)]
    {
        value.into_string().map(String::into_bytes).map_err(|_| {
            CliError::new(
                ExitClass::InteractionRequired,
                "CREDENTIAL_INVALID",
                "The configured headless credential is not valid Unicode text.",
                "Rotate the credential through a provider that can supply bounded UTF-8 bytes.",
            )
        })
    }
}

fn authentication_required() -> CliError {
    CliError::new(
        ExitClass::InteractionRequired,
        "AUTHENTICATION_REQUIRED",
        "The selected credential provider has no usable credential.",
        "Provision the selected OS or explicit headless credential provider and retry.",
    )
    .with_data(json!({"prompted": false}))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryDiscoveryRequest {
    pub repository_locator: String,
    pub branch: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryDiscovery {
    pub repository_id_hex: String,
    pub branch: String,
    pub baseline: String,
    pub case_mode: String,
    pub path_profile: String,
    pub repository_settings_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityOffer {
    pub protocol_version: &'static str,
    pub message_schema_version: &'static str,
    pub repository_format: &'static str,
    pub authorization_contract: &'static str,
    pub path_contract: &'static str,
    pub path_profile: String,
    pub event_version: &'static str,
    pub transfer_profile: &'static str,
    pub required_features: Vec<&'static str>,
}

impl CapabilityOffer {
    pub fn for_repository(discovery: &RepositoryDiscovery) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            message_schema_version: MESSAGE_SCHEMA_VERSION,
            repository_format: REPOSITORY_FORMAT,
            authorization_contract: AUTHORIZATION_CONTRACT,
            path_contract: PATH_CONTRACT,
            path_profile: discovery.path_profile.clone(),
            event_version: EVENT_VERSION,
            transfer_profile: TRANSFER_PROFILE,
            required_features: REQUIRED_PROTOCOL_FEATURES.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySelection {
    pub protocol_version: String,
    pub message_schema_version: String,
    pub repository_format: String,
    pub authorization_contract: String,
    pub authorization_registry_sha256: String,
    pub path_contract: String,
    pub path_profile: String,
    pub path_registry_sha256: String,
    pub event_version: String,
    pub transfer_profile: String,
    pub protocol_registry_set_sha256: String,
    pub repository_registry_sha256: String,
    pub required_features: Vec<String>,
    pub receipt_sha256: String,
    pub expires_at_unix_ms: u64,
}

/// OGVCS-006 allocation authority retained for the later first registration.
///
/// Debug output is always redacted, and the public type is neither cloneable
/// nor serializable. It can only be transferred into the private,
/// owner-checked staging journal for retention across process exits.
#[derive(Eq, PartialEq)]
pub struct FileIdAllocationReceipt(String);

impl FileIdAllocationReceipt {
    pub fn new(value: String) -> Result<Self, CliError> {
        if valid_allocation_receipt(&value) {
            Ok(Self(value))
        } else {
            Err(incompatible_service_facts())
        }
    }

    /// Exposes the opaque receipt only to a future OGVCS-006 registration
    /// adapter. It must never be included in human/JSON diagnostics.
    pub fn expose_to_registration(&self) -> &str {
        &self.0
    }

    fn zeroize(&mut self) {
        zeroize_string(&mut self.0);
    }

    fn into_persisted(mut self) -> PersistedFileIdAllocationReceipt {
        PersistedFileIdAllocationReceipt(std::mem::take(&mut self.0))
    }
}

impl fmt::Debug for FileIdAllocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FileIdAllocationReceipt(<redacted>)")
    }
}

impl Drop for FileIdAllocationReceipt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Serializable only through the private staging-state type. The public
/// handoff receipt deliberately implements neither `Clone` nor `Serialize`.
#[derive(Eq, PartialEq)]
struct PersistedFileIdAllocationReceipt(String);

impl PersistedFileIdAllocationReceipt {
    fn expose_to_registration(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PersistedFileIdAllocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PersistedFileIdAllocationReceipt(<redacted>)")
    }
}

impl Serialize for PersistedFileIdAllocationReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PersistedFileIdAllocationReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if valid_allocation_receipt(&value) {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(
                "invalid OGVCS-006 FileID allocation receipt",
            ))
        }
    }
}

impl Drop for PersistedFileIdAllocationReceipt {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
}

fn zeroize_string(value: &mut str) {
    // SAFETY: the string is exclusively borrowed, and overwriting its existing
    // UTF-8 bytes with zero does not change length/capacity or violate UTF-8.
    for byte in unsafe { value.as_bytes_mut() } {
        // SAFETY: every pointer is valid and exclusively borrowed.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// A completed OGVCS-006 allocation presented by its owning predecessor.
///
/// This is a handoff envelope, not a newly assigned wire result. The exact
/// idempotency key remains with the allocation owner; only its digest crosses
/// this boundary so the private journal can bind the retained receipt without
/// exposing or trying to recover the predecessor mutation itself.
#[derive(Debug, Eq, PartialEq)]
pub struct PresentedFileIdAllocation {
    pub allocation_schema_version: String,
    pub repository_id: String,
    pub repository_path_key: String,
    pub file_id: String,
    pub allocation_receipt: FileIdAllocationReceipt,
    pub allocation_idempotency_key_sha256: String,
    pub expires_at_unix_ms: u64,
}

pub trait RepositoryPublicRoutes: AuthenticationTransport {
    fn authentication_transport(&mut self) -> &mut dyn AuthenticationTransport;

    fn discover_repository(
        &mut self,
        session: &AuthenticationSession,
        request: &RepositoryDiscoveryRequest,
        cancellation: &dyn Cancellation,
        progress: &mut dyn ProgressSink,
    ) -> Result<RepositoryDiscovery, CliError>;

    fn negotiate_capabilities(
        &mut self,
        session: &AuthenticationSession,
        discovery: &RepositoryDiscovery,
        offer: &CapabilityOffer,
        cancellation: &dyn Cancellation,
        progress: &mut dyn ProgressSink,
    ) -> Result<CapabilitySelection, CliError>;

    fn validate_binding(
        &mut self,
        session: &AuthenticationSession,
        binding: &VerifiedBinding,
        cancellation: &dyn Cancellation,
    ) -> Result<(), CliError>;

    /// Presents a previously completed FileID allocation without mutation.
    ///
    /// Implementations MUST NOT call `file-id.allocate` from this method. The
    /// owner of that idempotent mutation must reconcile request/lost-response
    /// outcomes before handing this complete artifact to local staging.
    fn present_preallocated_file_id(
        &mut self,
        session: &AuthenticationSession,
        binding: &VerifiedBinding,
        repository_path_key: &str,
        cancellation: &dyn Cancellation,
    ) -> Result<PresentedFileIdAllocation, CliError>;

    fn resolve_file_id(
        &mut self,
        session: &AuthenticationSession,
        binding: &VerifiedBinding,
        repository_path_key: &str,
        cancellation: &dyn Cancellation,
    ) -> Result<String, CliError>;
}

#[derive(Default)]
pub struct UnavailablePublicRoutes;

impl AuthenticationTransport for UnavailablePublicRoutes {
    fn authenticate(
        &mut self,
        _: &AuthenticationRequest,
        _: &SecretMaterial,
        _: &dyn Cancellation,
    ) -> Result<AuthenticationSession, CliError> {
        Err(route_unavailable("identity.authenticate"))
    }
}

impl RepositoryPublicRoutes for UnavailablePublicRoutes {
    fn authentication_transport(&mut self) -> &mut dyn AuthenticationTransport {
        self
    }

    fn discover_repository(
        &mut self,
        _: &AuthenticationSession,
        _: &RepositoryDiscoveryRequest,
        _: &dyn Cancellation,
        _: &mut dyn ProgressSink,
    ) -> Result<RepositoryDiscovery, CliError> {
        Err(route_unavailable("metadata.repository-discover"))
    }

    fn negotiate_capabilities(
        &mut self,
        _: &AuthenticationSession,
        _: &RepositoryDiscovery,
        _: &CapabilityOffer,
        _: &dyn Cancellation,
        _: &mut dyn ProgressSink,
    ) -> Result<CapabilitySelection, CliError> {
        Err(route_unavailable("protocol.negotiate"))
    }

    fn validate_binding(
        &mut self,
        _: &AuthenticationSession,
        _: &VerifiedBinding,
        _: &dyn Cancellation,
    ) -> Result<(), CliError> {
        Err(route_unavailable("metadata.binding-validate"))
    }

    fn present_preallocated_file_id(
        &mut self,
        _: &AuthenticationSession,
        _: &VerifiedBinding,
        _: &str,
        _: &dyn Cancellation,
    ) -> Result<PresentedFileIdAllocation, CliError> {
        Err(CliError::new(
            ExitClass::Unavailable,
            "FILE_ID_ALLOCATION_HANDOFF_UNAVAILABLE",
            "No completed OGVCS-006 FileID allocation was presented to local staging.",
            "Allocate and reconcile the FileID through its owning public adapter, then retry with the complete receipt-bearing handoff.",
        )
        .with_data(json!({"interface": "file-id-allocation-handoff/v1", "mutationStarted": false, "remoteDurableState": "unchanged-by-this-command"})))
    }

    fn resolve_file_id(
        &mut self,
        _: &AuthenticationSession,
        _: &VerifiedBinding,
        _: &str,
        _: &dyn Cancellation,
    ) -> Result<String, CliError> {
        Err(route_unavailable("metadata.file-id-resolve"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationPhase {
    Authentication,
    Discovery,
    Negotiation,
    Preflight,
    Journal,
    Mutation,
    Recovery,
    Complete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub schema: &'static str,
    pub phase: OperationPhase,
    pub completed_items: u64,
    pub total_items: Option<u64>,
    pub completed_bytes: u64,
    pub total_bytes: Option<u64>,
    pub resume_token: Option<String>,
}

impl ProgressEvent {
    fn phase(phase: OperationPhase, completed_items: u64, total_items: Option<u64>) -> Self {
        Self {
            schema: PROGRESS_SCHEMA,
            phase,
            completed_items,
            total_items,
            completed_bytes: 0,
            total_bytes: None,
            resume_token: None,
        }
    }
}

pub trait ProgressSink {
    fn emit(&mut self, event: &ProgressEvent) -> Result<(), CliError>;
}

#[derive(Default)]
pub struct DiscardProgress;

impl ProgressSink for DiscardProgress {
    fn emit(&mut self, _: &ProgressEvent) -> Result<(), CliError> {
        Ok(())
    }
}

pub trait Cancellation {
    fn is_cancelled(&self) -> bool;

    fn check(&self, phase: &'static str) -> Result<(), CliError> {
        if self.is_cancelled() {
            Err(CliError::new(
                ExitClass::Cancelled,
                "OPERATION_CANCELLED",
                "The operation was cancelled at a recoverable boundary.",
                "Run workspace recover before retrying when a resume token was reported.",
            )
            .with_data(json!({"phase": phase})))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Cancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

struct MutationLock {
    file: File,
}

impl MutationLock {
    fn acquire(root: &Path) -> Result<Self, CliError> {
        let path = root.join(".ogvcs-mutation-v2.lock");
        #[cfg(not(windows))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options
                .open(&path)
                .map_err(|_| workspace_write_unavailable())?
        };
        #[cfg(windows)]
        let file = super::windows_security::open_or_create_private_lock(&path)
            .map_err(|_| workspace_write_unavailable())?;
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata().map_err(|_| workspace_write_unavailable())?;
            // SAFETY: geteuid has no preconditions.
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(unsafe_path());
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| workspace_write_unavailable())?;
            super::ensure_no_extended_acl(&file)?;
            // SAFETY: file owns a valid descriptor and flock is process-safe.
            if unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } != 0
            {
                return Err(workspace_busy());
            }
        }
        #[cfg(windows)]
        {
            use std::mem::zeroed;
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
            };
            use windows_sys::Win32::System::IO::OVERLAPPED;
            // SAFETY: file handle and zeroed OVERLAPPED for offset zero are valid.
            let mut overlapped: OVERLAPPED = unsafe { zeroed() };
            if unsafe {
                LockFileEx(
                    file.as_raw_handle() as _,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut overlapped,
                )
            } == 0
            {
                return Err(workspace_busy());
            }
        }
        Ok(Self { file })
    }
}

impl Drop for MutationLock {
    fn drop(&mut self) {
        #[cfg(not(windows))]
        {
            // SAFETY: file descriptor remains live through this call.
            unsafe {
                libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
            }
        }
        #[cfg(windows)]
        {
            use std::mem::zeroed;
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
            use windows_sys::Win32::System::IO::OVERLAPPED;
            // SAFETY: file handle remains live and matches the locked range.
            let mut overlapped: OVERLAPPED = unsafe { zeroed() };
            unsafe {
                UnlockFileEx(self.file.as_raw_handle() as _, 0, 1, 0, &mut overlapped);
            }
        }
    }
}

fn workspace_busy() -> CliError {
    workspace_error(
        "WORKSPACE_BUSY",
        "Another process owns the exclusive local workspace mutation lock.",
        "Wait for that operation to finish or recover after the owning process exits.",
    )
}

static PROCESS_CANCELLED: AtomicBool = AtomicBool::new(false);

/// Cancellation source installed by the binary. SIGINT/SIGTERM on Unix and
/// Ctrl-C/Ctrl-Break/close on Windows only set an atomic flag; recovery work is
/// performed by ordinary command code at the next declared boundary.
pub struct ProcessSignalCancellation;

impl ProcessSignalCancellation {
    pub fn install() -> Result<Self, CliError> {
        PROCESS_CANCELLED.store(false, Ordering::SeqCst);
        install_signal_handlers()?;
        Ok(Self)
    }
}

impl Cancellation for ProcessSignalCancellation {
    fn is_cancelled(&self) -> bool {
        PROCESS_CANCELLED.load(Ordering::SeqCst)
    }
}

#[cfg(not(windows))]
extern "C" fn unix_cancel_handler(_: libc::c_int) {
    PROCESS_CANCELLED.store(true, Ordering::SeqCst);
}

#[cfg(not(windows))]
fn install_signal_handlers() -> Result<(), CliError> {
    // SAFETY: the handler is async-signal-safe and only stores to an atomic.
    let interrupt =
        unsafe { libc::signal(libc::SIGINT, unix_cancel_handler as libc::sighandler_t) };
    // SAFETY: same handler and invariant as above.
    let terminate =
        unsafe { libc::signal(libc::SIGTERM, unix_cancel_handler as libc::sighandler_t) };
    if interrupt == libc::SIG_ERR || terminate == libc::SIG_ERR {
        Err(CliError::new(
            ExitClass::Unavailable,
            "SIGNAL_HANDLER_UNAVAILABLE",
            "The process could not install recoverable cancellation handlers.",
            "Retry in a supported terminal or invoke the library with an explicit cancellation source.",
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
unsafe extern "system" fn windows_cancel_handler(kind: u32) -> i32 {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    if matches!(
        kind,
        CTRL_C_EVENT
            | CTRL_BREAK_EVENT
            | CTRL_CLOSE_EVENT
            | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT
    ) {
        PROCESS_CANCELLED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

#[cfg(windows)]
fn install_signal_handlers() -> Result<(), CliError> {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    // SAFETY: the static handler has the required ABI and process lifetime.
    if unsafe { SetConsoleCtrlHandler(Some(windows_cancel_handler), 1) } == 0 {
        Err(CliError::new(
            ExitClass::Unavailable,
            "SIGNAL_HANDLER_UNAVAILABLE",
            "The process could not install recoverable cancellation handlers.",
            "Retry in a supported console or invoke the library with an explicit cancellation source.",
        ))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedBinding {
    pub repository_id_hex: String,
    pub branch: String,
    pub baseline: String,
    pub case_mode: String,
    pub path_profile: String,
    pub repository_settings_digest: String,
    pub negotiation: CapabilitySelection,
    pub subject_digest: String,
    pub authority_epoch: u64,
    pub security_epoch: u64,
    pub verification: String,
}

fn validate_authentication_session(session: &AuthenticationSession) -> Result<(), CliError> {
    if !valid_digest(&session.subject_digest)
        || !valid_digest(&session.session_digest)
        || session.authority_epoch == 0
        || session.security_epoch == 0
        || session.expires_at_unix_ms <= now_unix_ms()?
    {
        return Err(CliError::new(
            ExitClass::Unavailable,
            "AUTHENTICATION_FACTS_INVALID",
            "The authentication route returned invalid or expired session facts.",
            "Reauthenticate through a compatible OGVCS-009 public route.",
        ));
    }
    Ok(())
}

fn validate_discovery(discovery: &RepositoryDiscovery) -> Result<(), CliError> {
    if repository_uuid_from_hex(&discovery.repository_id_hex).is_none()
        || discovery.branch.is_empty()
        || discovery.branch.len() > 512
        || discovery.branch.contains('\0')
        || !valid_digest(&discovery.repository_settings_digest)
        || CaseMode::parse(&discovery.case_mode).is_err()
        || discovery.path_profile != PORTABLE_PATH_PROFILE
        || PathProfile::parse(&discovery.path_profile).is_err()
    {
        return Err(incompatible_service_facts());
    }
    let baseline =
        ObjectRef::from_str(&discovery.baseline).map_err(|_| incompatible_service_facts())?;
    if baseline.kind != ObjectKind::Snapshot {
        return Err(incompatible_service_facts());
    }
    Ok(())
}

fn validate_selection(
    selection: &CapabilitySelection,
    discovery: &RepositoryDiscovery,
) -> Result<(), CliError> {
    validate_selection_shape(selection, discovery, true)
}

fn validate_selection_shape(
    selection: &CapabilitySelection,
    discovery: &RepositoryDiscovery,
    require_unexpired_receipt: bool,
) -> Result<(), CliError> {
    let required: BTreeSet<_> = REQUIRED_PROTOCOL_FEATURES.iter().copied().collect();
    let selected: BTreeSet<_> = selection
        .required_features
        .iter()
        .map(String::as_str)
        .collect();
    let exact = selection.protocol_version == PROTOCOL_VERSION
        && selection.message_schema_version == MESSAGE_SCHEMA_VERSION
        && selection.repository_format == REPOSITORY_FORMAT
        && selection.authorization_contract == AUTHORIZATION_CONTRACT
        && selection.path_contract == PATH_CONTRACT
        && selection.path_profile == discovery.path_profile
        && selection.event_version == EVENT_VERSION
        && selection.transfer_profile == TRANSFER_PROFILE
        && selected == required
        && selection.authorization_registry_sha256 == AUTHORIZATION_REGISTRY_SHA256
        && selection.path_registry_sha256 == PATH_REGISTRY_SHA256
        && selection.protocol_registry_set_sha256 == PROTOCOL_REGISTRY_SET_SHA256
        && selection.repository_registry_sha256 == REPOSITORY_REGISTRY_SHA256
        && valid_digest(&selection.receipt_sha256)
        && selection.expires_at_unix_ms > 0
        && (!require_unexpired_receipt || selection.expires_at_unix_ms > now_unix_ms()?);
    if exact {
        Ok(())
    } else {
        Err(CliError::new(
            ExitClass::Unsupported,
            "CAPABILITY_SKEW",
            "The server and client did not negotiate the required capability tuple.",
            "Upgrade the client/server pair or select a repository with a supported immutable profile.",
        )
        .with_data(json!({"mutationStarted": false})))
    }
}

fn incompatible_service_facts() -> CliError {
    CliError::new(
        ExitClass::Unsupported,
        "SERVICE_FACTS_INVALID",
        "A public service route returned malformed or incompatible repository facts.",
        "Verify the OGVCS-006/008/009 adapter and retry without local mutation.",
    )
    .with_data(json!({"mutationStarted": false}))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum VerifiedWorkspaceState {
    Initializing,
    Ready,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifiedWorkspaceMetadata {
    schema: String,
    format_version: u32,
    state: VerifiedWorkspaceState,
    workspace_id: String,
    root_digest: String,
    binding: VerifiedBinding,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkspaceJournal {
    schema: String,
    format_version: u32,
    operation: String,
    state: String,
    workspace_id: String,
    root_digest: String,
    prior_metadata_digest: Option<String>,
    desired_metadata_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemovalRecord {
    schema: String,
    format_version: u32,
    root_digest: String,
    workspace_id_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedWorkspaceReport {
    pub schema: &'static str,
    pub state: &'static str,
    pub root_digest: String,
    pub workspace_id_digest: String,
    pub repository_id_digest: String,
    pub branch_digest: String,
    pub baseline: String,
    pub binding_verification: &'static str,
    pub capability_receipt_sha256: String,
    pub staged_intents: usize,
}

pub const VERIFIED_DIAGNOSTIC_SCHEMA: &str = "ogvcs.cli-workspace/verified-diagnostic-preview/v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedDiagnosticPreview {
    pub schema: &'static str,
    pub preview: bool,
    pub written: bool,
    pub workspace_state: &'static str,
    pub workspace_root_digest: String,
    pub workspace_id_digest: String,
    pub repository_id_digest: String,
    pub branch_digest: String,
    pub staged_intents: usize,
    pub credential_provider_kind: &'static str,
    pub credential_status: CredentialStatus,
    pub endpoint_scheme: &'static str,
    pub authorization_registry_sha256: &'static str,
    pub path_registry_sha256: &'static str,
    pub protocol_registry_set_sha256: &'static str,
    pub repository_registry_sha256: &'static str,
    pub redaction_policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_digest: Option<String>,
}

pub fn preview_verified_diagnostics(
    root: &Path,
    endpoint: &str,
    provider: &dyn SecureCredentialProvider,
) -> Result<VerifiedDiagnosticPreview, CliError> {
    let root = validated_root(root)?;
    let metadata = read_ready_metadata(&root)?;
    let staging = read_staging_state(&root)?;
    let endpoint_scheme = if endpoint.starts_with("https://") {
        "https"
    } else if endpoint.starts_with("http://") {
        "http"
    } else {
        return Err(input_error());
    };
    Ok(VerifiedDiagnosticPreview {
        schema: VERIFIED_DIAGNOSTIC_SCHEMA,
        preview: true,
        written: false,
        workspace_state: "ready",
        workspace_root_digest: metadata.root_digest,
        workspace_id_digest: digest_text(&metadata.workspace_id),
        repository_id_digest: digest_text(&metadata.binding.repository_id_hex),
        branch_digest: digest_text(&metadata.binding.branch),
        staged_intents: staging.intents.len(),
        credential_provider_kind: provider.kind(),
        credential_status: provider.status(),
        endpoint_scheme,
        authorization_registry_sha256: AUTHORIZATION_REGISTRY_SHA256,
        path_registry_sha256: PATH_REGISTRY_SHA256,
        protocol_registry_set_sha256: PROTOCOL_REGISTRY_SET_SHA256,
        repository_registry_sha256: REPOSITORY_REGISTRY_SHA256,
        redaction_policy: "v2-no-paths-locators-identities-endpoints-or-secrets",
        artifact_name: None,
        artifact_digest: None,
    })
}

pub fn create_verified_diagnostics(
    root: &Path,
    artifact_name: &str,
    endpoint: &str,
    provider: &dyn SecureCredentialProvider,
) -> Result<VerifiedDiagnosticPreview, CliError> {
    if artifact_name.is_empty()
        || artifact_name.len() > 64
        || artifact_name.starts_with('.')
        || !artifact_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(input_error());
    }
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    let mut artifact = preview_verified_diagnostics(&root, endpoint, provider)?;
    artifact.preview = false;
    artifact.written = true;
    let bytes = serde_json::to_vec(&artifact).map_err(|_| internal_error())?;
    let diagnostics = checked_control(&root)?.join("diagnostics-v2");
    match fs::symlink_metadata(&diagnostics) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_dir() => {
            super::ensure_private_directory(&diagnostics)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            super::create_private_directory(&diagnostics)?;
            sync_directory(&checked_control(&root)?)?;
        }
        _ => return Err(unsafe_path()),
    }
    let destination = diagnostics.join(artifact_name);
    super::write_json_new(&destination, &artifact)?;
    sync_directory(&diagnostics)?;
    artifact.artifact_name = Some(artifact_name.to_owned());
    artifact.artifact_digest = Some(digest_bytes(&bytes));
    Ok(artifact)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceCreateRequest {
    pub root: PathBuf,
    pub repository_locator: String,
    pub branch: String,
    pub authentication: AuthenticationRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceConfigureRequest {
    pub root: PathBuf,
    pub repository_locator: String,
    pub branch: String,
    pub authentication: AuthenticationRequest,
}

pub fn create_verified_workspace(
    request: &WorkspaceCreateRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<VerifiedWorkspaceReport, CliError> {
    validate_remote_request(
        &request.repository_locator,
        &request.branch,
        &request.authentication,
    )?;
    let root = validated_root(&request.root)?;
    if removal_record_path(&root).exists() || removal_tombstone_path(&root).exists() {
        return Err(recovery_required());
    }
    if control_path(&root).exists() {
        return Err(workspace_error(
            "WORKSPACE_EXISTS",
            "A workspace control directory already exists at this root.",
            "Open, recover, or remove the existing workspace before creating another one.",
        ));
    }
    progress.emit(&ProgressEvent::phase(
        OperationPhase::Authentication,
        0,
        Some(4),
    ))?;
    cancellation.check("before-authentication")?;
    let session = provider.invoke(
        &request.authentication,
        routes.authentication_transport(),
        cancellation,
    )?;
    validate_authentication_session(&session)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Discovery, 1, Some(4)))?;
    let discovery = routes.discover_repository(
        &session,
        &RepositoryDiscoveryRequest {
            repository_locator: request.repository_locator.clone(),
            branch: request.branch.clone(),
        },
        cancellation,
        progress,
    )?;
    validate_discovery(&discovery)?;
    if discovery.branch != request.branch {
        return Err(incompatible_service_facts());
    }
    cancellation.check("before-negotiation")?;
    progress.emit(&ProgressEvent::phase(
        OperationPhase::Negotiation,
        2,
        Some(4),
    ))?;
    let selection = routes.negotiate_capabilities(
        &session,
        &discovery,
        &CapabilityOffer::for_repository(&discovery),
        cancellation,
        progress,
    )?;
    validate_selection(&selection, &discovery)?;
    let binding = binding_from_service(&session, discovery, selection);
    routes.validate_binding(&session, &binding, cancellation)?;
    cancellation.check("before-local-publication")?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Preflight, 3, Some(4)))?;
    let _lock = MutationLock::acquire(&root)?;
    if removal_record_path(&root).exists() || removal_tombstone_path(&root).exists() {
        return Err(recovery_required());
    }
    if control_path(&root).exists() {
        return Err(workspace_error(
            "WORKSPACE_EXISTS",
            "A workspace control directory already exists at this root.",
            "Open, recover, or remove the existing workspace before creating another one.",
        ));
    }
    publish_verified_workspace(&root, binding, cancellation, progress)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Complete, 4, Some(4)))?;
    open_verified_workspace(&root)
}

fn binding_from_service(
    session: &AuthenticationSession,
    discovery: RepositoryDiscovery,
    negotiation: CapabilitySelection,
) -> VerifiedBinding {
    VerifiedBinding {
        repository_id_hex: discovery.repository_id_hex,
        branch: discovery.branch,
        baseline: discovery.baseline,
        case_mode: discovery.case_mode,
        path_profile: discovery.path_profile,
        repository_settings_digest: discovery.repository_settings_digest,
        negotiation,
        subject_digest: session.subject_digest.clone(),
        authority_epoch: session.authority_epoch,
        security_epoch: session.security_epoch,
        verification: "public-service-verified".to_owned(),
    }
}

fn validate_remote_request(
    repository_locator: &str,
    branch: &str,
    authentication: &AuthenticationRequest,
) -> Result<(), CliError> {
    if repository_locator.is_empty()
        || repository_locator.len() > 512
        || repository_locator.contains('\0')
        || branch.is_empty()
        || branch.len() > 512
        || branch.contains('\0')
        || authentication.endpoint.len() > 512
        || authentication.profile.is_empty()
        || authentication.profile.len() > 64
    {
        return Err(input_error());
    }
    Ok(())
}

fn publish_verified_workspace(
    root: &Path,
    binding: VerifiedBinding,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<(), CliError> {
    let workspace_id = format!("wsv2.{}", random_hex(32)?);
    let root_digest = digest_path(root);
    let created_at = now_unix_ms()?;
    let stage = root.join(format!(".ogvcs-init-v2-{}", random_hex(16)?));
    super::create_private_directory(&stage)?;
    let metadata = VerifiedWorkspaceMetadata {
        schema: VERIFIED_WORKSPACE_SCHEMA.to_owned(),
        format_version: VERIFIED_WORKSPACE_FORMAT_VERSION,
        state: VerifiedWorkspaceState::Initializing,
        workspace_id: workspace_id.clone(),
        root_digest: root_digest.clone(),
        binding,
        created_at_unix_ms: created_at,
        updated_at_unix_ms: created_at,
    };
    let desired = VerifiedWorkspaceMetadata {
        state: VerifiedWorkspaceState::Ready,
        ..metadata.clone()
    };
    let journal = WorkspaceJournal {
        schema: "ogvcs.cli-workspace/workspace-journal/v2".to_owned(),
        format_version: VERIFIED_WORKSPACE_FORMAT_VERSION,
        operation: "create".to_owned(),
        state: "prepared".to_owned(),
        workspace_id,
        root_digest,
        prior_metadata_digest: None,
        desired_metadata_digest: json_digest(&desired)?,
    };
    super::write_json_new(&stage.join("workspace-v2.json"), &metadata)?;
    super::write_json_new(&stage.join("pending-workspace-v2.json"), &desired)?;
    super::write_json_new(&stage.join("journal-v2.json"), &journal)?;
    super::write_json_new(&stage.join("staging-v1.json"), &StagingState::empty())?;
    sync_directory(&stage)?;
    if cancellation.is_cancelled() {
        safe_remove_initialization_stage(&stage)?;
        return Err(cancelled_local("before-control-publication", None));
    }
    fs::rename(&stage, control_path(root))
        .map_err(|error| workspace_write_io_error("workspace-control-publish", &error))?;
    sync_directory(root)?;
    progress.emit(&ProgressEvent {
        resume_token: Some(digest_text("workspace-recover")),
        ..ProgressEvent::phase(OperationPhase::Journal, 3, Some(4))
    })?;
    if cancellation.is_cancelled() {
        return Err(cancelled_local(
            "after-control-publication",
            Some(digest_text("workspace-recover")),
        ));
    }
    complete_pending_workspace(root)
}

pub fn open_verified_workspace(root: &Path) -> Result<VerifiedWorkspaceReport, CliError> {
    let root = validated_root(root)?;
    let metadata = read_ready_metadata(&root)?;
    let staging = read_staging_state(&root)?;
    if staging
        .intents
        .iter()
        .any(|intent| intent.state == IntentState::Prepared)
    {
        return Err(workspace_error(
            "WORKSPACE_RECOVERY_REQUIRED",
            "The workspace has a prepared local file operation.",
            "Run workspace recover before using this workspace.",
        ));
    }
    report(&metadata, staging.intents.len())
}

pub fn recover_verified_workspace(
    root: &Path,
    progress: &mut dyn ProgressSink,
) -> Result<VerifiedWorkspaceReport, CliError> {
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    if let Some(removed) = reconcile_removal(&root)? {
        return Err(workspace_error(
            "WORKSPACE_REMOVED",
            "An interrupted local workspace removal was completed safely.",
            "Create a new verified workspace if this root should be used again.",
        )
        .with_data(serde_json::to_value(removed).map_err(|_| internal_error())?));
    }
    progress.emit(&ProgressEvent::phase(OperationPhase::Recovery, 0, Some(2)))?;
    let metadata = read_verified_metadata(&root)?;
    validate_verified_metadata_common(&metadata, &root)?;
    let journal = read_workspace_journal(&root)?;
    validate_workspace_journal(&journal, &metadata)?;
    if journal.state == "prepared" {
        complete_pending_workspace(&root)?;
    } else {
        cleanup_completed_pending(&root, &metadata, &journal)?;
    }
    recover_staging(&root)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Complete, 2, Some(2)))?;
    open_verified_workspace(&root)
}

pub fn configure_verified_workspace(
    request: &WorkspaceConfigureRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<VerifiedWorkspaceReport, CliError> {
    validate_remote_request(
        &request.repository_locator,
        &request.branch,
        &request.authentication,
    )?;
    let root = validated_root(&request.root)?;
    let _lock = MutationLock::acquire(&root)?;
    let current = read_ready_metadata(&root)?;
    if !read_staging_state(&root)?.intents.is_empty() {
        return Err(workspace_error(
            "WORKSPACE_HAS_STAGED_INTENTS",
            "A workspace with staged intents cannot change its verified binding.",
            "Revert or publish the staged intents before configuring another branch.",
        ));
    }
    progress.emit(&ProgressEvent::phase(
        OperationPhase::Authentication,
        0,
        Some(4),
    ))?;
    let session = provider.invoke(
        &request.authentication,
        routes.authentication_transport(),
        cancellation,
    )?;
    validate_authentication_session(&session)?;
    let discovery = routes.discover_repository(
        &session,
        &RepositoryDiscoveryRequest {
            repository_locator: request.repository_locator.clone(),
            branch: request.branch.clone(),
        },
        cancellation,
        progress,
    )?;
    validate_discovery(&discovery)?;
    if discovery.branch != request.branch
        || discovery.repository_id_hex != current.binding.repository_id_hex
    {
        return Err(CliError::new(
            ExitClass::Unsupported,
            "REPOSITORY_REBIND_FORBIDDEN",
            "Workspace configure cannot change the repository identity.",
            "Create a separate workspace for a different repository.",
        ));
    }
    let selection = routes.negotiate_capabilities(
        &session,
        &discovery,
        &CapabilityOffer::for_repository(&discovery),
        cancellation,
        progress,
    )?;
    validate_selection(&selection, &discovery)?;
    let binding = binding_from_service(&session, discovery, selection);
    routes.validate_binding(&session, &binding, cancellation)?;
    cancellation.check("before-configure-journal")?;
    let desired = VerifiedWorkspaceMetadata {
        state: VerifiedWorkspaceState::Ready,
        binding,
        updated_at_unix_ms: now_unix_ms()?,
        ..current.clone()
    };
    let prior_digest = json_digest(&current)?;
    let desired_digest = json_digest(&desired)?;
    let journal = WorkspaceJournal {
        schema: "ogvcs.cli-workspace/workspace-journal/v2".to_owned(),
        format_version: VERIFIED_WORKSPACE_FORMAT_VERSION,
        operation: "configure".to_owned(),
        state: "prepared".to_owned(),
        workspace_id: current.workspace_id.clone(),
        root_digest: current.root_digest.clone(),
        prior_metadata_digest: Some(prior_digest),
        desired_metadata_digest: desired_digest,
    };
    let control = checked_control(&root)?;
    super::write_json_atomic(&control.join("pending-workspace-v2.json"), &desired)?;
    super::write_json_atomic(&control.join("journal-v2.json"), &journal)?;
    progress.emit(&ProgressEvent {
        resume_token: Some(digest_text("workspace-recover")),
        ..ProgressEvent::phase(OperationPhase::Journal, 3, Some(4))
    })?;
    if cancellation.is_cancelled() {
        return Err(cancelled_local(
            "after-configure-journal",
            Some(digest_text("workspace-recover")),
        ));
    }
    complete_pending_workspace(&root)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Complete, 4, Some(4)))?;
    open_verified_workspace(&root)
}

pub fn list_verified_workspaces(
    roots: &[PathBuf],
) -> Result<Vec<VerifiedWorkspaceReport>, CliError> {
    if roots.len() > MAX_LIST_ROOTS {
        return Err(input_error());
    }
    let mut reports = Vec::with_capacity(roots.len());
    let mut unique = BTreeSet::new();
    for root in roots {
        let report = open_verified_workspace(root)?;
        if !unique.insert(report.root_digest.clone()) {
            return Err(input_error());
        }
        reports.push(report);
    }
    reports.sort_by(|left, right| left.root_digest.cmp(&right.root_digest));
    Ok(reports)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoveWorkspaceOptions {
    pub confirmed: bool,
    pub non_interactive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveWorkspaceReport {
    pub root_digest: String,
    pub workspace_id_digest: String,
    pub removed: bool,
    pub remote_durable_state: &'static str,
}

pub fn remove_verified_workspace(
    root: &Path,
    options: RemoveWorkspaceOptions,
    cancellation: &dyn Cancellation,
) -> Result<RemoveWorkspaceReport, CliError> {
    remove_verified_workspace_with_progress(root, options, cancellation, &mut DiscardProgress)
}

pub fn remove_verified_workspace_with_progress(
    root: &Path,
    options: RemoveWorkspaceOptions,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<RemoveWorkspaceReport, CliError> {
    if !options.confirmed {
        return Err(CliError::new(
            ExitClass::InteractionRequired,
            "DESTRUCTIVE_CONFIRMATION_REQUIRED",
            "Removing local workspace metadata requires explicit confirmation.",
            "Pass the explicit confirmation flag after reviewing staged state.",
        )
        .with_data(json!({"prompted": false, "nonInteractive": options.non_interactive})));
    }
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    if let Some(removed) = reconcile_removal(&root)? {
        return Ok(removed);
    }
    let metadata = read_ready_metadata(&root)?;
    let staging = read_staging_state(&root)?;
    if !staging.intents.is_empty() {
        return Err(workspace_error(
            "WORKSPACE_HAS_STAGED_INTENTS",
            "Workspace metadata cannot be removed while local intents are staged.",
            "Revert or publish every staged intent before removing the workspace.",
        ));
    }
    cancellation.check("before-workspace-remove")?;
    let removal = RemoveWorkspaceReport {
        root_digest: metadata.root_digest,
        workspace_id_digest: digest_text(&metadata.workspace_id),
        removed: true,
        remote_durable_state: "unchanged",
    };
    let record = RemovalRecord {
        schema: "ogvcs.cli-workspace/removal-record/v2".to_owned(),
        format_version: VERIFIED_WORKSPACE_FORMAT_VERSION,
        root_digest: removal.root_digest.clone(),
        workspace_id_digest: removal.workspace_id_digest.clone(),
    };
    super::write_json_new(&removal_record_path(&root), &record)?;
    sync_directory(&root)?;
    progress.emit(&ProgressEvent {
        resume_token: Some(digest_text("workspace-recover")),
        ..ProgressEvent::phase(OperationPhase::Journal, 0, Some(2))
    })?;
    let control = control_path(&root);
    let tombstone = removal_tombstone_path(&root);
    fs::rename(&control, &tombstone)
        .map_err(|error| workspace_write_io_error("workspace-control-detach", &error))?;
    sync_directory(&root)?;
    progress.emit(&ProgressEvent {
        resume_token: Some(digest_text("workspace-recover")),
        ..ProgressEvent::phase(OperationPhase::Mutation, 1, Some(2))
    })?;
    // Detachment is the irreversible commit point. Cancellation is deliberately
    // ignored after it so the API never reports a resumable token for a control
    // directory that `workspace recover` cannot open.
    validate_removal_tree(&tombstone, 64)?;
    fs::remove_dir_all(&tombstone).map_err(|_| workspace_write_unavailable())?;
    fs::remove_file(removal_record_path(&root)).map_err(|_| workspace_write_unavailable())?;
    sync_directory(&root)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Complete, 2, Some(2)))?;
    Ok(removal)
}

fn removal_record_path(root: &Path) -> PathBuf {
    root.join(".ogvcs-remove-v2.json")
}

fn removal_tombstone_path(root: &Path) -> PathBuf {
    root.join(".ogvcs-removed-v2")
}

fn reconcile_removal(root: &Path) -> Result<Option<RemoveWorkspaceReport>, CliError> {
    let record_path = removal_record_path(root);
    let tombstone = removal_tombstone_path(root);
    let control = control_path(root);
    let record_exists = safe_regular_presence(&record_path)?;
    let tombstone_exists = safe_directory_presence(&tombstone)?;
    let control_exists = safe_directory_presence(&control)?;
    if !record_exists {
        return if tombstone_exists {
            Err(recovery_conflict())
        } else {
            Ok(None)
        };
    }
    let record: RemovalRecord = read_json_private(&record_path, MAX_STATE_BYTES)?;
    if record.schema != "ogvcs.cli-workspace/removal-record/v2"
        || record.format_version != VERIFIED_WORKSPACE_FORMAT_VERSION
        || record.root_digest != digest_path(root)
        || !valid_digest(&record.workspace_id_digest)
    {
        return Err(metadata_invalid());
    }
    if control_exists && tombstone_exists {
        return Err(recovery_conflict());
    }
    if control_exists {
        let metadata = read_ready_metadata(root)?;
        if digest_text(&metadata.workspace_id) != record.workspace_id_digest {
            return Err(metadata_invalid());
        }
        fs::remove_file(&record_path).map_err(|_| workspace_write_unavailable())?;
        sync_directory(root)?;
        return Ok(None);
    }
    if tombstone_exists {
        validate_removal_tree(&tombstone, 64)?;
        fs::remove_dir_all(&tombstone).map_err(|_| workspace_write_unavailable())?;
    }
    fs::remove_file(&record_path).map_err(|_| workspace_write_unavailable())?;
    sync_directory(root)?;
    Ok(Some(RemoveWorkspaceReport {
        root_digest: record.root_digest,
        workspace_id_digest: record.workspace_id_digest,
        removed: true,
        remote_durable_state: "unchanged",
    }))
}

fn safe_regular_presence(path: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        _ => Err(recovery_conflict()),
    }
}

fn safe_directory_presence(path: &Path) -> Result<bool, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_dir() => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        _ => Err(recovery_conflict()),
    }
}

fn complete_pending_workspace(root: &Path) -> Result<(), CliError> {
    let control = checked_control(root)?;
    let pending: VerifiedWorkspaceMetadata =
        read_json_private(&control.join("pending-workspace-v2.json"), MAX_STATE_BYTES)?;
    validate_verified_metadata_common(&pending, root)?;
    let mut journal = read_workspace_journal(root)?;
    if journal.state != "prepared"
        || journal.desired_metadata_digest != json_digest(&pending)?
        || journal.workspace_id != pending.workspace_id
        || journal.root_digest != pending.root_digest
    {
        return Err(metadata_invalid());
    }
    super::write_json_atomic(&control.join("workspace-v2.json"), &pending)?;
    journal.state = "complete".to_owned();
    super::write_json_atomic(&control.join("journal-v2.json"), &journal)?;
    fs::remove_file(control.join("pending-workspace-v2.json"))
        .map_err(|_| workspace_write_unavailable())?;
    sync_directory(&control)
}

fn cleanup_completed_pending(
    root: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    journal: &WorkspaceJournal,
) -> Result<(), CliError> {
    if journal.state != "complete" || journal.desired_metadata_digest != json_digest(metadata)? {
        return Err(metadata_invalid());
    }
    let pending_path = checked_control(root)?.join("pending-workspace-v2.json");
    match fs::symlink_metadata(&pending_path) {
        Ok(_) => {
            let pending: VerifiedWorkspaceMetadata =
                read_json_private(&pending_path, MAX_STATE_BYTES)?;
            validate_verified_metadata_common(&pending, root)?;
            if json_digest(&pending)? != journal.desired_metadata_digest {
                return Err(metadata_invalid());
            }
            fs::remove_file(&pending_path).map_err(|_| workspace_write_unavailable())?;
            sync_directory(&checked_control(root)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(metadata_invalid()),
    }
}

fn read_verified_metadata(root: &Path) -> Result<VerifiedWorkspaceMetadata, CliError> {
    let control = checked_control(root)?;
    read_json_private(&control.join("workspace-v2.json"), MAX_STATE_BYTES)
}

fn read_workspace_journal(root: &Path) -> Result<WorkspaceJournal, CliError> {
    let control = checked_control(root)?;
    read_json_private(&control.join("journal-v2.json"), MAX_STATE_BYTES)
}

fn read_ready_metadata(root: &Path) -> Result<VerifiedWorkspaceMetadata, CliError> {
    let metadata = read_verified_metadata(root)?;
    validate_verified_metadata(&metadata, root)?;
    let journal = read_workspace_journal(root)?;
    validate_workspace_journal(&journal, &metadata)?;
    if journal.state != "complete" {
        return Err(recovery_required());
    }
    let pending = checked_control(root)?.join("pending-workspace-v2.json");
    match fs::symlink_metadata(&pending) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(metadata),
        Ok(_) => Err(recovery_required()),
        Err(_) => Err(metadata_invalid()),
    }
}

fn validate_verified_metadata(
    metadata: &VerifiedWorkspaceMetadata,
    root: &Path,
) -> Result<(), CliError> {
    validate_verified_metadata_common(metadata, root)?;
    if metadata.state != VerifiedWorkspaceState::Ready {
        return Err(workspace_error(
            "WORKSPACE_RECOVERY_REQUIRED",
            "Verified workspace metadata is not ready.",
            "Run workspace recover before using this workspace.",
        ));
    }
    Ok(())
}

fn validate_verified_metadata_common(
    metadata: &VerifiedWorkspaceMetadata,
    root: &Path,
) -> Result<(), CliError> {
    let valid = metadata.schema == VERIFIED_WORKSPACE_SCHEMA
        && metadata.format_version == VERIFIED_WORKSPACE_FORMAT_VERSION
        && metadata.workspace_id.starts_with("wsv2.")
        && metadata.workspace_id.len() == 69
        && metadata.workspace_id[5..].bytes().all(is_lower_hex)
        && metadata.root_digest == digest_path(root)
        && metadata.created_at_unix_ms > 0
        && metadata.updated_at_unix_ms >= metadata.created_at_unix_ms
        && metadata.binding.verification == "public-service-verified";
    if !valid {
        return Err(metadata_invalid());
    }
    validate_binding(&metadata.binding)
}

fn validate_binding(binding: &VerifiedBinding) -> Result<(), CliError> {
    let discovery = RepositoryDiscovery {
        repository_id_hex: binding.repository_id_hex.clone(),
        branch: binding.branch.clone(),
        baseline: binding.baseline.clone(),
        case_mode: binding.case_mode.clone(),
        path_profile: binding.path_profile.clone(),
        repository_settings_digest: binding.repository_settings_digest.clone(),
    };
    validate_discovery(&discovery)?;
    validate_selection_shape(&binding.negotiation, &discovery, false)?;
    if !valid_digest(&binding.subject_digest)
        || binding.authority_epoch == 0
        || binding.security_epoch == 0
    {
        return Err(metadata_invalid());
    }
    Ok(())
}

fn validate_workspace_journal(
    journal: &WorkspaceJournal,
    metadata: &VerifiedWorkspaceMetadata,
) -> Result<(), CliError> {
    let operation_shape = match journal.operation.as_str() {
        "create" => journal.prior_metadata_digest.is_none(),
        "configure" => journal.prior_metadata_digest.is_some(),
        _ => false,
    };
    if journal.schema != "ogvcs.cli-workspace/workspace-journal/v2"
        || journal.format_version != VERIFIED_WORKSPACE_FORMAT_VERSION
        || !operation_shape
        || !matches!(journal.state.as_str(), "prepared" | "complete")
        || journal.workspace_id != metadata.workspace_id
        || journal.root_digest != metadata.root_digest
        || !valid_digest(&journal.desired_metadata_digest)
        || journal
            .prior_metadata_digest
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
    {
        return Err(metadata_invalid());
    }
    let current_digest = json_digest(metadata)?;
    match journal.state.as_str() {
        "complete"
            if metadata.state == VerifiedWorkspaceState::Ready
                && journal.desired_metadata_digest == current_digest =>
        {
            Ok(())
        }
        "prepared"
            if journal.operation == "create"
                && metadata.state == VerifiedWorkspaceState::Initializing =>
        {
            Ok(())
        }
        "prepared"
            if journal.operation == "configure"
                && metadata.state == VerifiedWorkspaceState::Ready
                && journal.prior_metadata_digest.as_deref() == Some(current_digest.as_str()) =>
        {
            Ok(())
        }
        _ => Err(metadata_invalid()),
    }
}

fn report(
    metadata: &VerifiedWorkspaceMetadata,
    staged_intents: usize,
) -> Result<VerifiedWorkspaceReport, CliError> {
    if metadata.state != VerifiedWorkspaceState::Ready {
        return Err(metadata_invalid());
    }
    Ok(VerifiedWorkspaceReport {
        schema: VERIFIED_WORKSPACE_REPORT_SCHEMA,
        state: "ready",
        root_digest: metadata.root_digest.clone(),
        workspace_id_digest: digest_text(&metadata.workspace_id),
        repository_id_digest: digest_text(&metadata.binding.repository_id_hex),
        branch_digest: digest_text(&metadata.binding.branch),
        baseline: metadata.binding.baseline.clone(),
        binding_verification: "public-service-verified",
        capability_receipt_sha256: metadata.binding.negotiation.receipt_sha256.clone(),
        staged_intents,
    })
}

fn control_path(root: &Path) -> PathBuf {
    root.join(".ogvcs")
}

fn checked_control(root: &Path) -> Result<PathBuf, CliError> {
    super::checked_control_directory(root)
}

fn read_json_private<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum: u64,
) -> Result<T, CliError> {
    let bytes = read_bounded(path, maximum)?;
    serde_json::from_slice(&bytes).map_err(|_| metadata_invalid())
}

fn json_digest<T: Serialize>(value: &T) -> Result<String, CliError> {
    let bytes = serde_json::to_vec(value).map_err(|_| internal_error())?;
    Ok(digest_bytes(&bytes))
}

fn metadata_invalid() -> CliError {
    workspace_error(
        "WORKSPACE_METADATA_INVALID",
        "Workspace metadata is malformed, unsafe, expired, or incompatible.",
        "Recover a valid journal or recreate the workspace through verified public routes.",
    )
}

fn recovery_required() -> CliError {
    workspace_error(
        "WORKSPACE_RECOVERY_REQUIRED",
        "The verified workspace has an incomplete recoverable operation.",
        "Run workspace recover before using or mutating this workspace.",
    )
}

fn workspace_write_unavailable() -> CliError {
    workspace_error(
        "WORKSPACE_WRITE_UNAVAILABLE",
        "Local workspace metadata could not be committed safely.",
        "Check filesystem ownership and run workspace recover before retrying.",
    )
}

fn workspace_write_io_error(operation: &'static str, error: &io::Error) -> CliError {
    workspace_write_unavailable().with_data(json!({
        "ioErrorCode": error.raw_os_error(),
        "operation": operation
    }))
}

fn cancelled_local(phase: &'static str, resume_token: Option<String>) -> CliError {
    CliError::new(
        ExitClass::Cancelled,
        "OPERATION_CANCELLED",
        "The operation was cancelled at a recoverable local boundary.",
        "Run workspace recover before retrying when a resume token is present.",
    )
    .with_data(json!({
        "phase": phase,
        "resumeToken": resume_token,
        "remoteDurableState": "unchanged-after-preflight"
    }))
}

fn safe_remove_initialization_stage(stage: &Path) -> Result<(), CliError> {
    validate_removal_tree(stage, 16)?;
    fs::remove_dir_all(stage).map_err(|_| workspace_write_unavailable())
}

fn validate_removal_tree(root: &Path, maximum_entries: usize) -> Result<(), CliError> {
    let mut pending = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(path) = pending.pop() {
        seen = seen.checked_add(1).ok_or_else(input_error)?;
        if seen > maximum_entries {
            return Err(workspace_error(
                "WORKSPACE_REMOVE_UNSAFE",
                "Workspace metadata contains more objects than the bounded removal policy allows.",
                "Inspect the control directory manually before retrying.",
            ));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| metadata_invalid())?;
        if is_link_or_reparse(&metadata) {
            return Err(workspace_error(
                "WORKSPACE_REMOVE_UNSAFE",
                "Workspace metadata contains a link or reparse point.",
                "Inspect the control directory manually; this CLI will not traverse it.",
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|_| metadata_invalid())? {
                pending.push(entry.map_err(|_| metadata_invalid())?.path());
            }
        } else if !metadata.is_file() {
            return Err(metadata_invalid());
        }
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        metadata.file_attributes() & 0x0000_0400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntentKind {
    Add,
    Move,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum IntentState {
    Prepared,
    Applied,
    Reverting,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StagedIntent {
    intent_id: String,
    kind: IntentKind,
    state: IntentState,
    file_id: String,
    allocation_receipt: Option<PersistedFileIdAllocationReceipt>,
    allocation_idempotency_key_sha256: Option<String>,
    allocation_expires_at_unix_ms: Option<u64>,
    source_path: Option<String>,
    destination_path: Option<String>,
    source_repository_key: Option<String>,
    destination_repository_key: Option<String>,
    trash_name: Option<String>,
    created_at_unix_ms: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StagingState {
    schema: String,
    format_version: u32,
    generation: u64,
    intents: Vec<StagedIntent>,
}

impl StagingState {
    fn empty() -> Self {
        Self {
            schema: STAGING_SCHEMA.to_owned(),
            format_version: 1,
            generation: 0,
            intents: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentReport {
    pub intent_id: String,
    pub kind: IntentKind,
    pub state: &'static str,
    pub file_id_digest: String,
    pub allocation_receipt_digest: Option<String>,
    pub allocation_idempotency_key_digest: Option<String>,
    pub source_path_digest: Option<String>,
    pub destination_path_digest: Option<String>,
    pub uploads_started: bool,
    pub submit_started: bool,
    pub remote_durable_state: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageAddRequest {
    pub root: PathBuf,
    pub repository_path: String,
    pub authentication: AuthenticationRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageMoveRequest {
    pub root: PathBuf,
    pub source_repository_path: String,
    pub destination_repository_path: String,
    pub authentication: AuthenticationRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageDeleteRequest {
    pub root: PathBuf,
    pub repository_path: String,
    pub authentication: AuthenticationRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevertIntentRequest {
    pub root: PathBuf,
    pub intent_id: String,
    pub authentication: AuthenticationRequest,
}

pub fn stage_add(
    request: &StageAddRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<IntentReport, CliError> {
    let (root, metadata, session, _lock) = prepare_staging(
        &request.root,
        &request.authentication,
        provider,
        routes,
        cancellation,
        progress,
    )?;
    let path = validated_repository_path(&metadata.binding, &request.repository_path)?;
    let local = confined_existing_regular_file(&root, &path.canonical)?;
    let size = local.metadata().map_err(|_| unsafe_path())?.len();
    let allocation = routes.present_preallocated_file_id(
        &session,
        &metadata.binding,
        &path.repository_key,
        cancellation,
    )?;
    validate_presented_file_id_allocation(&allocation, &metadata.binding, &path.repository_key)?;
    let intent = StagedIntent {
        intent_id: new_intent_id()?,
        kind: IntentKind::Add,
        state: IntentState::Prepared,
        file_id: allocation.file_id,
        allocation_receipt: Some(allocation.allocation_receipt.into_persisted()),
        allocation_idempotency_key_sha256: Some(allocation.allocation_idempotency_key_sha256),
        allocation_expires_at_unix_ms: Some(allocation.expires_at_unix_ms),
        source_path: None,
        destination_path: Some(path.canonical),
        source_repository_key: None,
        destination_repository_key: Some(path.repository_key),
        trash_name: None,
        created_at_unix_ms: now_unix_ms()?,
    };
    apply_prepared_intent(&root, intent, cancellation, progress, Some(size))
}

pub fn stage_move(
    request: &StageMoveRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<IntentReport, CliError> {
    let (root, metadata, session, _lock) = prepare_staging(
        &request.root,
        &request.authentication,
        provider,
        routes,
        cancellation,
        progress,
    )?;
    let source = validated_repository_path(&metadata.binding, &request.source_repository_path)?;
    let destination =
        validated_repository_path(&metadata.binding, &request.destination_repository_path)?;
    if source.canonical == destination.canonical {
        return Err(input_error());
    }
    let _ = confined_existing_regular_file(&root, &source.canonical)?;
    confined_absent_destination(&root, &destination.canonical)?;
    ensure_native_mutation_available()?;
    let file_id = routes.resolve_file_id(
        &session,
        &metadata.binding,
        &source.repository_key,
        cancellation,
    )?;
    validate_file_id(&file_id)?;
    let intent = StagedIntent {
        intent_id: new_intent_id()?,
        kind: IntentKind::Move,
        state: IntentState::Prepared,
        file_id,
        allocation_receipt: None,
        allocation_idempotency_key_sha256: None,
        allocation_expires_at_unix_ms: None,
        source_path: Some(source.canonical),
        destination_path: Some(destination.canonical),
        source_repository_key: Some(source.repository_key),
        destination_repository_key: Some(destination.repository_key),
        trash_name: None,
        created_at_unix_ms: now_unix_ms()?,
    };
    apply_prepared_intent(&root, intent, cancellation, progress, None)
}

pub fn stage_delete(
    request: &StageDeleteRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<IntentReport, CliError> {
    let (root, metadata, session, _lock) = prepare_staging(
        &request.root,
        &request.authentication,
        provider,
        routes,
        cancellation,
        progress,
    )?;
    let source = validated_repository_path(&metadata.binding, &request.repository_path)?;
    let _ = confined_existing_regular_file(&root, &source.canonical)?;
    ensure_native_mutation_available()?;
    let file_id = routes.resolve_file_id(
        &session,
        &metadata.binding,
        &source.repository_key,
        cancellation,
    )?;
    validate_file_id(&file_id)?;
    let intent_id = new_intent_id()?;
    let intent = StagedIntent {
        trash_name: Some(format!("{}.deleted", intent_id)),
        intent_id,
        kind: IntentKind::Delete,
        state: IntentState::Prepared,
        file_id,
        allocation_receipt: None,
        allocation_idempotency_key_sha256: None,
        allocation_expires_at_unix_ms: None,
        source_path: Some(source.canonical),
        destination_path: None,
        source_repository_key: Some(source.repository_key),
        destination_repository_key: None,
        created_at_unix_ms: now_unix_ms()?,
    };
    apply_prepared_intent(&root, intent, cancellation, progress, None)
}

pub fn revert_staged_intent(
    request: &RevertIntentRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<IntentReport, CliError> {
    if !valid_intent_id(&request.intent_id) {
        return Err(input_error());
    }
    let (root, metadata, _, _lock) = prepare_staging(
        &request.root,
        &request.authentication,
        provider,
        routes,
        cancellation,
        progress,
    )?;
    let mut staging = read_staging_state(&root)?;
    let index = staging
        .intents
        .iter()
        .position(|intent| intent.intent_id == request.intent_id)
        .ok_or_else(|| {
            workspace_error(
                "STAGED_INTENT_NOT_FOUND",
                "The requested local staged intent does not exist.",
                "List staged intents and retry with an existing resume token.",
            )
        })?;
    if staging.intents[index].state != IntentState::Applied {
        return Err(workspace_error(
            "WORKSPACE_RECOVERY_REQUIRED",
            "The staged intent is not in an applied state.",
            "Run workspace recover before reverting it.",
        ));
    }
    validate_intent(&staging.intents[index], &metadata.binding)?;
    if staging.intents[index].kind != IntentKind::Add {
        ensure_native_mutation_available()?;
    }
    staging.intents[index].state = IntentState::Reverting;
    staging.generation = checked_generation(staging.generation)?;
    write_staging_state(&root, &staging)?;
    let report = intent_report(&staging.intents[index]);
    if cancellation.is_cancelled() {
        return Err(cancelled_local(
            "after-revert-journal",
            Some(request.intent_id.clone()),
        ));
    }
    reverse_intent(&root, &staging.intents[index])?;
    staging.intents.remove(index);
    staging.generation = checked_generation(staging.generation)?;
    write_staging_state(&root, &staging)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Complete, 1, Some(1)))?;
    Ok(IntentReport {
        state: "reverted",
        ..report
    })
}

pub fn list_staged_intents(root: &Path) -> Result<Vec<IntentReport>, CliError> {
    let root = validated_root(root)?;
    let metadata = read_ready_metadata(&root)?;
    let staging = read_staging_state(&root)?;
    staging
        .intents
        .iter()
        .map(|intent| {
            validate_intent(intent, &metadata.binding)?;
            Ok(intent_report(intent))
        })
        .collect()
}

fn prepare_staging(
    root: &Path,
    authentication: &AuthenticationRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<
    (
        PathBuf,
        VerifiedWorkspaceMetadata,
        AuthenticationSession,
        MutationLock,
    ),
    CliError,
> {
    if authentication.endpoint.len() > 512
        || authentication.profile.is_empty()
        || authentication.profile.len() > 64
    {
        return Err(input_error());
    }
    let root = validated_root(root)?;
    let lock = MutationLock::acquire(&root)?;
    let metadata = read_ready_metadata(&root)?;
    let staging = read_staging_state(&root)?;
    if staging
        .intents
        .iter()
        .any(|intent| intent.state != IntentState::Applied)
    {
        return Err(workspace_error(
            "WORKSPACE_RECOVERY_REQUIRED",
            "A local file operation has not reached a stable boundary.",
            "Run workspace recover before staging another operation.",
        ));
    }
    progress.emit(&ProgressEvent::phase(
        OperationPhase::Authentication,
        0,
        Some(3),
    ))?;
    let session = provider.invoke(
        authentication,
        routes.authentication_transport(),
        cancellation,
    )?;
    validate_authentication_session(&session)?;
    routes.validate_binding(&session, &metadata.binding, cancellation)?;
    cancellation.check("before-path-preflight")?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Preflight, 1, Some(3)))?;
    Ok((root, metadata, session, lock))
}

#[derive(Clone, Debug)]
struct ValidatedRepositoryPath {
    canonical: String,
    repository_key: String,
}

fn validated_repository_path(
    binding: &VerifiedBinding,
    path: &str,
) -> Result<ValidatedRepositoryPath, CliError> {
    let keys =
        path_collision_keys(path, &binding.path_profile, &binding.case_mode).map_err(|error| {
            CliError::new(
                ExitClass::Input,
                "PATH_PREFLIGHT_REJECTED",
                "The repository path violates the pinned OGVCS-004 contract.",
                "Choose an NFC, relative, platform-compatible path inside the workspace.",
            )
            .with_data(json!({"pathErrorCode": error.code().as_str()}))
        })?;
    Ok(ValidatedRepositoryPath {
        canonical: keys.path().canonical().to_owned(),
        repository_key: keys.repository_key().as_str().to_owned(),
    })
}

fn apply_prepared_intent(
    root: &Path,
    intent: StagedIntent,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
    bytes: Option<u64>,
) -> Result<IntentReport, CliError> {
    let metadata = read_ready_metadata(root)?;
    validate_intent(&intent, &metadata.binding)?;
    let mut staging = read_staging_state(root)?;
    if staging.intents.len() >= MAX_STAGED_INTENTS {
        return Err(workspace_error(
            "STAGING_LIMIT_EXCEEDED",
            "The bounded local staging journal is full.",
            "Publish or revert existing intents before staging more paths.",
        ));
    }
    reject_staging_collision(&staging, &intent)?;
    staging.intents.push(intent);
    staging.generation = checked_generation(staging.generation)?;
    write_staging_state(root, &staging)?;
    let index = staging.intents.len() - 1;
    let resume_token = staging.intents[index].intent_id.clone();
    progress.emit(&ProgressEvent {
        resume_token: Some(resume_token.clone()),
        completed_bytes: bytes.unwrap_or(0),
        total_bytes: bytes,
        ..ProgressEvent::phase(OperationPhase::Journal, 2, Some(3))
    })?;
    if cancellation.is_cancelled() {
        return Err(cancelled_local("after-staging-journal", Some(resume_token)));
    }
    apply_intent_filesystem(root, &staging.intents[index])?;
    staging.intents[index].state = IntentState::Applied;
    staging.generation = checked_generation(staging.generation)?;
    write_staging_state(root, &staging)?;
    progress.emit(&ProgressEvent::phase(OperationPhase::Complete, 3, Some(3)))?;
    Ok(intent_report(&staging.intents[index]))
}

fn apply_intent_filesystem(root: &Path, intent: &StagedIntent) -> Result<(), CliError> {
    match intent.kind {
        IntentKind::Add => {
            let destination = required_intent_path(&intent.destination_path)?;
            let _ = confined_existing_regular_file(root, destination)?;
        }
        IntentKind::Move => {
            let source_name = required_intent_path(&intent.source_path)?;
            rename_repository_paths(
                root,
                source_name,
                required_intent_path(&intent.destination_path)?,
            )?;
        }
        IntentKind::Delete => {
            let source_name = required_intent_path(&intent.source_path)?;
            let _ = checked_trash(root)?;
            rename_repository_to_trash(root, source_name, required_trash_name(intent)?)?;
        }
    }
    Ok(())
}

fn reverse_intent(root: &Path, intent: &StagedIntent) -> Result<(), CliError> {
    match intent.kind {
        IntentKind::Add => Ok(()),
        IntentKind::Move => {
            let current_name = required_intent_path(&intent.destination_path)?;
            rename_repository_paths(
                root,
                current_name,
                required_intent_path(&intent.source_path)?,
            )
        }
        IntentKind::Delete => rename_trash_to_repository(
            root,
            required_trash_name(intent)?,
            required_intent_path(&intent.source_path)?,
        ),
    }
}

fn recover_staging(root: &Path) -> Result<(), CliError> {
    let metadata = read_ready_metadata(root)?;
    let mut staging = read_staging_state(root)?;
    let mut changed = false;
    let mut remove = Vec::new();
    for (index, intent) in staging.intents.iter_mut().enumerate() {
        validate_intent(intent, &metadata.binding)?;
        match intent.state {
            IntentState::Applied => {}
            IntentState::Prepared => {
                recover_prepared_intent(root, intent)?;
                intent.state = IntentState::Applied;
                changed = true;
            }
            IntentState::Reverting => {
                recover_reverting_intent(root, intent)?;
                remove.push(index);
                changed = true;
            }
        }
    }
    for index in remove.into_iter().rev() {
        staging.intents.remove(index);
    }
    if changed {
        staging.generation = checked_generation(staging.generation)?;
        write_staging_state(root, &staging)?;
    }
    Ok(())
}

fn recover_prepared_intent(root: &Path, intent: &StagedIntent) -> Result<(), CliError> {
    match intent.kind {
        IntentKind::Add => {
            let _ = confined_existing_regular_file(
                root,
                required_intent_path(&intent.destination_path)?,
            )?;
            Ok(())
        }
        IntentKind::Move => {
            let source = required_intent_path(&intent.source_path)?;
            let destination = required_intent_path(&intent.destination_path)?;
            match (
                repository_regular_exists(root, source)?,
                repository_regular_exists(root, destination)?,
            ) {
                (true, false) => apply_intent_filesystem(root, intent),
                (false, true) => Ok(()),
                _ => Err(recovery_conflict()),
            }
        }
        IntentKind::Delete => {
            let source = required_intent_path(&intent.source_path)?;
            let _ = checked_trash(root)?;
            match (
                repository_regular_exists(root, source)?,
                trash_regular_exists(root, required_trash_name(intent)?)?,
            ) {
                (true, false) => apply_intent_filesystem(root, intent),
                (false, true) => Ok(()),
                _ => Err(recovery_conflict()),
            }
        }
    }
}

fn recover_reverting_intent(root: &Path, intent: &StagedIntent) -> Result<(), CliError> {
    match intent.kind {
        IntentKind::Add => Ok(()),
        IntentKind::Move => {
            let original = required_intent_path(&intent.source_path)?;
            let current = required_intent_path(&intent.destination_path)?;
            match (
                repository_regular_exists(root, original)?,
                repository_regular_exists(root, current)?,
            ) {
                (true, false) => Ok(()),
                (false, true) => reverse_intent(root, intent),
                _ => Err(recovery_conflict()),
            }
        }
        IntentKind::Delete => {
            let original = required_intent_path(&intent.source_path)?;
            let _ = checked_trash(root)?;
            match (
                repository_regular_exists(root, original)?,
                trash_regular_exists(root, required_trash_name(intent)?)?,
            ) {
                (true, false) => Ok(()),
                (false, true) => reverse_intent(root, intent),
                _ => Err(recovery_conflict()),
            }
        }
    }
}

fn read_staging_state(root: &Path) -> Result<StagingState, CliError> {
    let state: StagingState = read_json_private(
        &checked_control(root)?.join("staging-v1.json"),
        MAX_STATE_BYTES,
    )?;
    if state.schema != STAGING_SCHEMA
        || state.format_version != 1
        || state.intents.len() > MAX_STAGED_INTENTS
    {
        return Err(metadata_invalid());
    }
    Ok(state)
}

fn write_staging_state(root: &Path, state: &StagingState) -> Result<(), CliError> {
    if state.intents.len() > MAX_STAGED_INTENTS {
        return Err(metadata_invalid());
    }
    super::write_json_atomic(&checked_control(root)?.join("staging-v1.json"), state)
}

fn validate_intent(intent: &StagedIntent, binding: &VerifiedBinding) -> Result<(), CliError> {
    if !valid_intent_id(&intent.intent_id)
        || FileId::from_str(&intent.file_id).is_err()
        || intent.created_at_unix_ms == 0
        || intent
            .trash_name
            .as_deref()
            .is_some_and(|name| !valid_trash_name(name))
    {
        return Err(metadata_invalid());
    }
    for path in [
        intent.source_path.as_deref(),
        intent.destination_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = validated_repository_path(binding, path)?;
    }
    match intent.kind {
        IntentKind::Add
            if intent.source_path.is_none()
                && intent.destination_path.is_some()
                && intent.source_repository_key.is_none()
                && intent.destination_repository_key.is_some()
                && intent.trash_name.is_none()
                && intent.allocation_receipt.is_some()
                && intent
                    .allocation_idempotency_key_sha256
                    .as_deref()
                    .is_some_and(valid_digest)
                && intent
                    .allocation_expires_at_unix_ms
                    .is_some_and(|expires_at| expires_at > 0) => {}
        IntentKind::Move
            if intent.source_path.is_some()
                && intent.destination_path.is_some()
                && intent.source_repository_key.is_some()
                && intent.destination_repository_key.is_some()
                && intent.trash_name.is_none()
                && intent.allocation_receipt.is_none()
                && intent.allocation_idempotency_key_sha256.is_none()
                && intent.allocation_expires_at_unix_ms.is_none() => {}
        IntentKind::Delete
            if intent.source_path.is_some()
                && intent.destination_path.is_none()
                && intent.source_repository_key.is_some()
                && intent.destination_repository_key.is_none()
                && intent.trash_name.is_some()
                && intent.allocation_receipt.is_none()
                && intent.allocation_idempotency_key_sha256.is_none()
                && intent.allocation_expires_at_unix_ms.is_none() => {}
        _ => return Err(metadata_invalid()),
    }
    Ok(())
}

fn reject_staging_collision(
    state: &StagingState,
    candidate: &StagedIntent,
) -> Result<(), CliError> {
    let keys: BTreeSet<_> = candidate
        .source_repository_key
        .iter()
        .chain(candidate.destination_repository_key.iter())
        .collect();
    for intent in &state.intents {
        if intent
            .source_repository_key
            .iter()
            .chain(intent.destination_repository_key.iter())
            .any(|key| keys.contains(key))
        {
            return Err(workspace_error(
                "STAGED_PATH_CONFLICT",
                "A staged intent already owns the same repository path identity.",
                "Revert the existing intent before staging a conflicting path.",
            ));
        }
    }
    Ok(())
}

fn intent_report(intent: &StagedIntent) -> IntentReport {
    IntentReport {
        intent_id: intent.intent_id.clone(),
        kind: intent.kind,
        state: match intent.state {
            IntentState::Prepared => "prepared",
            IntentState::Applied => "applied",
            IntentState::Reverting => "reverting",
        },
        file_id_digest: digest_text(&intent.file_id),
        allocation_receipt_digest: intent
            .allocation_receipt
            .as_ref()
            .map(|receipt| digest_text(receipt.expose_to_registration())),
        allocation_idempotency_key_digest: intent.allocation_idempotency_key_sha256.clone(),
        source_path_digest: intent.source_path.as_deref().map(digest_text),
        destination_path_digest: intent.destination_path.as_deref().map(digest_text),
        uploads_started: false,
        submit_started: false,
        remote_durable_state: "unchanged",
    }
}

fn validate_presented_file_id_allocation(
    allocation: &PresentedFileIdAllocation,
    binding: &VerifiedBinding,
    repository_path_key: &str,
) -> Result<(), CliError> {
    if allocation.allocation_schema_version != FILE_ID_ALLOCATION_SCHEMA
        || repository_uuid_from_hex(&binding.repository_id_hex).as_deref()
            != Some(allocation.repository_id.as_str())
        || allocation.repository_path_key != repository_path_key
        || !valid_digest(&allocation.allocation_idempotency_key_sha256)
        || allocation.expires_at_unix_ms <= now_unix_ms()?
    {
        return Err(incompatible_service_facts());
    }
    validate_file_id(&allocation.file_id)
}

fn repository_uuid_from_hex(value: &str) -> Option<String> {
    if value.len() != 32
        || !value.bytes().all(is_lower_hex)
        || !matches!(value.as_bytes()[12], b'1'..=b'8')
        || !matches!(value.as_bytes()[16], b'8' | b'9' | b'a' | b'b')
    {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..]
    ))
}

fn validate_file_id(value: &str) -> Result<(), CliError> {
    FileId::from_str(value)
        .map(|_| ())
        .map_err(|_| incompatible_service_facts())
}

fn valid_allocation_receipt(value: &str) -> bool {
    value.len() == 48
        && value.starts_with("far1.")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn new_intent_id() -> Result<String, CliError> {
    Ok(format!("wsi1.{}", random_hex(32)?))
}

fn valid_intent_id(value: &str) -> bool {
    value.len() == 69 && value.starts_with("wsi1.") && value[5..].bytes().all(is_lower_hex)
}

fn valid_trash_name(value: &str) -> bool {
    value.len() == 77
        && value.ends_with(".deleted")
        && valid_intent_id(value.strip_suffix(".deleted").unwrap_or_default())
}

fn required_intent_path(path: &Option<String>) -> Result<&str, CliError> {
    path.as_deref().ok_or_else(metadata_invalid)
}

fn required_trash_name(intent: &StagedIntent) -> Result<&str, CliError> {
    intent
        .trash_name
        .as_deref()
        .filter(|value| valid_trash_name(value))
        .ok_or_else(metadata_invalid)
}

fn checked_generation(value: u64) -> Result<u64, CliError> {
    value.checked_add(1).ok_or_else(metadata_invalid)
}

fn joined_path(root: &Path, canonical: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for segment in canonical.split('/') {
        path.push(segment);
    }
    path
}

fn confined_existing_regular_file(root: &Path, canonical: &str) -> Result<File, CliError> {
    #[cfg(not(windows))]
    {
        use std::os::fd::FromRawFd;
        let components: Vec<_> = canonical.split('/').collect();
        let (parent, name) = open_relative_parent(root, &components)?;
        // SAFETY: parent is a live directory descriptor and name has no NUL.
        let descriptor = unsafe {
            libc::openat(
                std::os::fd::AsRawFd::as_raw_fd(&parent),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(unsafe_path());
        }
        // SAFETY: descriptor is newly owned by this function.
        let file = unsafe { File::from_raw_fd(descriptor) };
        if !file.metadata().map_err(|_| unsafe_path())?.is_file() {
            return Err(unsafe_path());
        }
        Ok(file)
    }
    #[cfg(windows)]
    {
        inspect_ancestors(root, canonical, true)?;
        let path = joined_path(root, canonical);
        let metadata = fs::symlink_metadata(&path).map_err(|_| unsafe_path())?;
        if is_link_or_reparse(&metadata) || !metadata.is_file() {
            return Err(unsafe_path());
        }
        let canonical_path = fs::canonicalize(&path).map_err(|_| unsafe_path())?;
        if !canonical_path.starts_with(root) {
            return Err(unsafe_path());
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(not(windows))]
        options.custom_flags(libc::O_NOFOLLOW);
        #[cfg(windows)]
        options.custom_flags(0x0020_0000);
        options.open(path).map_err(|_| unsafe_path())
    }
}

fn confined_absent_destination(root: &Path, canonical: &str) -> Result<PathBuf, CliError> {
    #[cfg(not(windows))]
    {
        let components: Vec<_> = canonical.split('/').collect();
        if relative_regular_exists(root, &components)? {
            return Err(unsafe_path());
        }
        Ok(joined_path(root, canonical))
    }
    #[cfg(windows)]
    {
        inspect_ancestors(root, canonical, false)?;
        let path = joined_path(root, canonical);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
            _ => Err(unsafe_path()),
        }
    }
}

#[cfg(windows)]
fn inspect_ancestors(root: &Path, canonical: &str, include_final: bool) -> Result<(), CliError> {
    let segments: Vec<_> = canonical.split('/').collect();
    let end = if include_final {
        segments.len()
    } else {
        segments.len().saturating_sub(1)
    };
    let mut current = root.to_path_buf();
    for segment in segments.into_iter().take(end) {
        current.push(segment);
        let metadata = fs::symlink_metadata(&current).map_err(|_| unsafe_path())?;
        if is_link_or_reparse(&metadata)
            || (current != joined_path(root, canonical) && !metadata.is_dir())
        {
            return Err(unsafe_path());
        }
    }
    Ok(())
}

fn checked_trash(root: &Path) -> Result<PathBuf, CliError> {
    let control = checked_control(root)?;
    let trash = control.join("trash-v1");
    match fs::symlink_metadata(&trash) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_dir() => {
            super::ensure_private_directory(&trash)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            super::create_private_directory(&trash)?;
            sync_directory(&control)?;
        }
        _ => return Err(unsafe_path()),
    }
    Ok(trash)
}

fn ensure_native_mutation_available() -> Result<(), CliError> {
    #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
    {
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err(CliError::new(
            ExitClass::Unsupported,
            "LOCAL_MUTATION_ADAPTER_UNAVAILABLE",
            "This build has no atomic no-replace native rename/delete adapter.",
            "Use add-only staging or install a supported OGVCS-004 native mutation adapter.",
        )
        .with_data(json!({"mutationStarted": false})))
    }
}

fn repository_regular_exists(root: &Path, canonical: &str) -> Result<bool, CliError> {
    #[cfg(not(windows))]
    {
        let components: Vec<_> = canonical.split('/').collect();
        relative_regular_exists(root, &components)
    }
    #[cfg(windows)]
    {
        let path = joined_path(root, canonical);
        match fs::symlink_metadata(path) {
            Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            _ => Err(unsafe_path()),
        }
    }
}

fn trash_regular_exists(root: &Path, name: &str) -> Result<bool, CliError> {
    #[cfg(not(windows))]
    {
        relative_regular_exists(root, &[".ogvcs", "trash-v1", name])
    }
    #[cfg(windows)]
    {
        let path = checked_trash(root)?.join(name);
        match fs::symlink_metadata(path) {
            Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            _ => Err(unsafe_path()),
        }
    }
}

fn rename_repository_paths(root: &Path, source: &str, destination: &str) -> Result<(), CliError> {
    #[cfg(not(windows))]
    {
        let source: Vec<_> = source.split('/').collect();
        let destination: Vec<_> = destination.split('/').collect();
        rename_relative(root, &source, &destination)
    }
    #[cfg(windows)]
    {
        super::windows_security::rename_confined_noreplace(root, source, destination)
            .map_err(|_| unsafe_path())
    }
}

fn rename_repository_to_trash(root: &Path, source: &str, trash: &str) -> Result<(), CliError> {
    #[cfg(not(windows))]
    {
        let source: Vec<_> = source.split('/').collect();
        rename_relative(root, &source, &[".ogvcs", "trash-v1", trash])
    }
    #[cfg(windows)]
    {
        super::windows_security::rename_confined_noreplace(
            root,
            source,
            &format!(".ogvcs/trash-v1/{trash}"),
        )
        .map_err(|_| unsafe_path())
    }
}

fn rename_trash_to_repository(root: &Path, trash: &str, destination: &str) -> Result<(), CliError> {
    #[cfg(not(windows))]
    {
        let destination: Vec<_> = destination.split('/').collect();
        rename_relative(root, &[".ogvcs", "trash-v1", trash], &destination)
    }
    #[cfg(windows)]
    {
        super::windows_security::rename_confined_noreplace(
            root,
            &format!(".ogvcs/trash-v1/{trash}"),
            destination,
        )
        .map_err(|_| unsafe_path())
    }
}

#[cfg(not(windows))]
fn open_relative_parent(
    root: &Path,
    components: &[&str],
) -> Result<(File, std::ffi::CString), CliError> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    if components.is_empty() {
        return Err(unsafe_path());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directory = options.open(root).map_err(|_| unsafe_path())?;
    for component in &components[..components.len() - 1] {
        let name = CString::new(component.as_bytes()).map_err(|_| unsafe_path())?;
        // SAFETY: directory is live and name is terminated with no interior NUL.
        let descriptor = unsafe {
            libc::openat(
                std::os::fd::AsRawFd::as_raw_fd(&directory),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(unsafe_path());
        }
        // SAFETY: descriptor is newly owned by this function.
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    let name =
        CString::new(components[components.len() - 1].as_bytes()).map_err(|_| unsafe_path())?;
    Ok((directory, name))
}

#[cfg(not(windows))]
fn relative_regular_exists(root: &Path, components: &[&str]) -> Result<bool, CliError> {
    let (parent, name) = open_relative_parent(root, components)?;
    // SAFETY: the stat buffer and pinned parent/name pair are valid.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    let status = unsafe {
        libc::fstatat(
            std::os::fd::AsRawFd::as_raw_fd(&parent),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        if metadata.st_mode & libc::S_IFMT == libc::S_IFREG {
            Ok(true)
        } else {
            Err(unsafe_path())
        }
    } else if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(unsafe_path())
    }
}

#[cfg(not(windows))]
fn rename_relative(root: &Path, source: &[&str], destination: &[&str]) -> Result<(), CliError> {
    let (source_parent, source_name) = open_relative_parent(root, source)?;
    let (destination_parent, destination_name) = open_relative_parent(root, destination)?;
    if !relative_regular_exists_from_parent(&source_parent, &source_name)?
        || relative_regular_exists_from_parent(&destination_parent, &destination_name)?
    {
        return Err(unsafe_path());
    }
    #[cfg(test)]
    run_rename_race_hook();
    platform_rename_noreplace(
        &source_parent,
        &source_name,
        &destination_parent,
        &destination_name,
    )
    .map_err(|_| unsafe_path())?;
    source_parent
        .sync_all()
        .map_err(|_| workspace_write_unavailable())?;
    destination_parent
        .sync_all()
        .map_err(|_| workspace_write_unavailable())
}

#[cfg(all(test, not(windows)))]
static RENAME_RACE_HOOK: std::sync::Mutex<
    Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>,
> = std::sync::Mutex::new(None);

#[cfg(all(test, not(windows)))]
fn run_rename_race_hook() {
    let barriers = RENAME_RACE_HOOK
        .lock()
        .expect("rename race hook lock")
        .take();
    if let Some((precheck_complete, destination_installed)) = barriers {
        precheck_complete.wait();
        destination_installed.wait();
    }
}

#[cfg(target_os = "linux")]
fn platform_rename_noreplace(
    source_parent: &File,
    source_name: &std::ffi::CStr,
    destination_parent: &File,
    destination_name: &std::ffi::CStr,
) -> io::Result<()> {
    // SAFETY: both parent descriptors remain pinned and both names are
    // terminated relative names. RENAME_NOREPLACE makes the absence proof
    // part of the kernel mutation instead of a racy userspace precheck.
    let status = unsafe {
        libc::renameat2(
            std::os::fd::AsRawFd::as_raw_fd(source_parent),
            source_name.as_ptr(),
            std::os::fd::AsRawFd::as_raw_fd(destination_parent),
            destination_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn platform_rename_noreplace(
    source_parent: &File,
    source_name: &std::ffi::CStr,
    destination_parent: &File,
    destination_name: &std::ffi::CStr,
) -> io::Result<()> {
    // SAFETY: both parent descriptors remain pinned and both names are
    // terminated relative names. RENAME_EXCL atomically forbids replacement.
    let status = unsafe {
        libc::renameatx_np(
            std::os::fd::AsRawFd::as_raw_fd(source_parent),
            source_name.as_ptr(),
            std::os::fd::AsRawFd::as_raw_fd(destination_parent),
            destination_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(not(windows), not(any(target_os = "linux", target_os = "macos"))))]
fn platform_rename_noreplace(
    _: &File,
    _: &std::ffi::CStr,
    _: &File,
    _: &std::ffi::CStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace rename unavailable",
    ))
}

#[cfg(not(windows))]
fn relative_regular_exists_from_parent(
    parent: &File,
    name: &std::ffi::CStr,
) -> Result<bool, CliError> {
    // SAFETY: the stat buffer and pinned parent/name pair are valid.
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    let status = unsafe {
        libc::fstatat(
            std::os::fd::AsRawFd::as_raw_fd(parent),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        if metadata.st_mode & libc::S_IFMT == libc::S_IFREG {
            Ok(true)
        } else {
            Err(unsafe_path())
        }
    } else if io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(unsafe_path())
    }
}

fn unsafe_path() -> CliError {
    workspace_error(
        "UNSAFE_WORKSPACE_PATH",
        "A local path is missing, escapes the workspace, or crosses a link/reparse point.",
        "Remove the unsafe namespace object and retry with an OGVCS-004-valid repository path.",
    )
}

fn recovery_conflict() -> CliError {
    workspace_error(
        "WORKSPACE_RECOVERY_CONFLICT",
        "A prepared local operation has an ambiguous filesystem state.",
        "Preserve the workspace and inspect both redacted operation endpoints before manual repair.",
    )
}

#[cfg(test)]
mod secret_tests {
    use super::*;

    #[test]
    fn explicit_zeroization_overwrites_every_secret_byte() {
        let mut secret = SecretMaterial::new(b"redaction-secret-needle".to_vec()).unwrap();
        secret.zeroize();
        assert!(secret.expose_to_transport().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn allocation_receipt_debug_is_redacted_and_zeroization_overwrites_bytes() {
        let needle = format!("far1.{}", "A".repeat(43));
        let mut receipt = FileIdAllocationReceipt::new(needle.clone()).unwrap();
        assert!(!format!("{receipt:?}").contains(&needle));
        receipt.zeroize();
        assert!(receipt.0.as_bytes().iter().all(|byte| *byte == 0));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn atomic_rename_never_overwrites_a_destination_installed_after_precheck() {
        use std::sync::Barrier;
        use std::thread;

        let root = env::temp_dir().join(format!(
            "ogvcs-rename-race-{}-{}",
            std::process::id(),
            random_hex(8).unwrap()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("source.bin"), b"source").unwrap();

        let precheck_complete = Arc::new(Barrier::new(2));
        let destination_installed = Arc::new(Barrier::new(2));
        *RENAME_RACE_HOOK.lock().unwrap() =
            Some((precheck_complete.clone(), destination_installed.clone()));
        let worker_root = root.clone();
        let worker = thread::spawn(move || {
            rename_relative(&worker_root, &["source.bin"], &["destination.bin"])
        });
        precheck_complete.wait();
        fs::write(root.join("destination.bin"), b"racing-destination").unwrap();
        destination_installed.wait();
        let error = worker.join().unwrap().unwrap_err();
        assert_eq!(error.code, "UNSAFE_WORKSPACE_PATH");
        assert_eq!(fs::read(root.join("source.bin")).unwrap(), b"source");
        assert_eq!(
            fs::read(root.join("destination.bin")).unwrap(),
            b"racing-destination"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
