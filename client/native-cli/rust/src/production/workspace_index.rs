//! Durable, bounded OGVCS-012 workspace-index candidate.
//!
//! The on-disk format is private local state, not a public wire protocol.  An
//! authoritative baseline can enter only through `RepositoryPublicRoutes`, and
//! an authoritative clean result additionally requires a trusted native
//! watcher continuity boundary.  The first-party binary installs neither
//! boundary today, so it remains fail-closed and continues to advertise
//! `status` as unsupported.

use super::{
    checked_control, confined_existing_regular_file, is_link_or_reparse, joined_path, json_digest,
    read_ready_metadata, validate_authentication_session, AuthenticationRequest,
    AuthenticationSession, Cancellation, MutationLock, ProgressSink, RepositoryPublicRoutes,
    SecureCredentialProvider, VerifiedBinding, VerifiedWorkspaceMetadata,
};
use crate::{
    digest_bytes, digest_text, input_error, internal_error, now_unix_ms, random_hex,
    sync_directory, valid_digest, validated_root, workspace_error, CliError, ExitClass,
};
use ogvcs_object_model::{FileId, ObjectKind, ObjectRef};
use ogvcs_path_contract::path_collision_keys;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

mod retention;

pub use retention::{
    compact_workspace_index, WorkspaceIndexCompactionReport, BASE_RETAINED_GENERATIONS,
    MAX_AUTHENTICATED_GENERATIONS, MAX_COMPACTION_GENERATIONS_PER_RUN, MAX_READER_LEASES,
    WORKSPACE_INDEX_COMPACTION_REPORT_SCHEMA,
};

#[cfg(not(windows))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

pub const WORKSPACE_INDEX_SCHEMA: &str = "ogvcs.workspace-index/active/v1";
pub const WORKSPACE_INDEX_REPORT_SCHEMA: &str = "ogvcs.workspace-index/report/v1";
pub const WORKSPACE_STATUS_SCHEMA: &str = "ogvcs.workspace-index/status-page/v1";
pub const BASELINE_RECEIPT_SCHEMA: &str = "ogvcs.workspace-index/baseline-receipt/v1";
pub const WORKSPACE_INDEX_CONTRACT_VERSION: &str = "0.1.0-rc.3";
const WORKSPACE_INDEX_GENERATION_FORMAT_VERSION: &str = "0.1.0-rc.1";
pub const WORKSPACE_INDEX_CONTRACT_SHA256: &str =
    "8b2f8281a34b1805760eb4c674bb9a5068b791a8486316beb8e9b237eed213f8";
pub const WORKSPACE_INDEX_CONTRACT_ARTIFACT_SET_SHA256: &str =
    "fcbb718537a382ecedc6a7e39ec409669d1d10e54aeb70b4b209e41cc83fb3f2";
pub const MAX_BASELINE_ENTRIES: u64 = 10_000_000;
pub const MAX_BASELINE_CHUNK_ITEMS: usize = 1_000;
pub const MAX_BASELINE_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_WATCH_EVENTS: u64 = 100_000;
pub const MAX_WATCH_CHUNK_ITEMS: usize = 1_000;
pub const MAX_WATCH_CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_STATUS_PAGE_ITEMS: usize = 1_000;
pub const MAX_IGNORE_RULES: usize = 2_000;

const MAX_ENTRY_BYTES: usize = 16 * 1024;
const MAX_FINDING_BYTES: usize = 16 * 1024;
const MAX_EVENT_BYTES: usize = 16 * 1024;
const MAX_STATUS_CANDIDATES: usize = 1_100_000;
const MAX_CONTROL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVENTS_BYTES: u64 = 128 * 1024 * 1024;
const LOOKUP_RECORD_BYTES: u64 = 76;
const ORDERED_BASELINE_DOMAIN: &[u8] = b"ogvcs.workspace-index/baseline-ordered/v1\0";
const WATCH_RECORD_DOMAIN: &[u8] = b"ogvcs.workspace-index/watch-record/v1\0";
const STATUS_CURSOR_DOMAIN: &[u8] = b"ogvcs.workspace-index/status-cursor-hmac/v2\0";
const CURSOR_KEY_NAME: &str = "cursor-hmac-key-v1.bin";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineMaterialization {
    Full,
    MetadataOnly,
    AbsentBySpec,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceBaselineEntry {
    pub repository_path: String,
    pub file_id: String,
    pub content_manifest: String,
    pub content_sha256: String,
    pub content_bytes: u64,
    pub executable: bool,
    pub materialization: BaselineMaterialization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IgnoreSource {
    Repository,
    Local,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IgnoreAction {
    Ignore,
    Include,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IgnorePatternKind {
    Exact,
    Subtree,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceIgnoreRule {
    pub rule_id: String,
    pub source: IgnoreSource,
    pub action: IgnoreAction,
    pub pattern_kind: IgnorePatternKind,
    pub repository_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceBaselineReceipt {
    pub schema: String,
    pub repository_id_hex: String,
    pub baseline: String,
    pub repository_settings_digest: String,
    pub path_profile: String,
    pub case_mode: String,
    pub entry_count: u64,
    pub ordered_entries_sha256: String,
    pub repository_ignore_rules: Vec<WorkspaceIgnoreRule>,
    pub repository_ignore_rules_sha256: String,
}

pub trait WorkspaceBaselineSink {
    /// Accepts one strictly bounded, ordered chunk. Implementations validate
    /// the complete chunk before writing any member.
    fn append_chunk(&mut self, entries: &[WorkspaceBaselineEntry]) -> Result<(), CliError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceWatchEventKind {
    Created,
    Modified,
    Deleted,
    Renamed,
    Metadata,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceWatchEvent {
    pub kind: WorkspaceWatchEventKind,
    pub repository_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_repository_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceWatchBatch {
    pub session_id: String,
    pub prior_cursor: String,
    pub cursor: String,
    pub events: Vec<WorkspaceWatchEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceWatcherStart {
    pub adapter: String,
    pub session_id: String,
    pub resume_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceWatcherCheckpoint {
    adapter: String,
    session_id: String,
    cursor: String,
    continuity_proven: bool,
    resume_supported: bool,
}

impl WorkspaceWatcherCheckpoint {
    /// The only production-callable constructor until first-party native
    /// watcher authorities land. It is deliberately incapable of minting a
    /// clean continuity proof.
    pub fn unsupported(start: &WorkspaceWatcherStart, cursor: String) -> Result<Self, CliError> {
        if !valid_bounded_opaque(&cursor, 512) {
            return Err(input_error());
        }
        Ok(Self {
            adapter: start.adapter.clone(),
            session_id: start.session_id.clone(),
            cursor,
            continuity_proven: false,
            resume_supported: false,
        })
    }
}

pub trait WorkspaceWatchEventSink {
    fn append_watch_chunk(&mut self, events: &[WorkspaceWatchEvent]) -> Result<(), CliError>;
}

pub trait WorkspaceWatchBatchSink {
    /// Commits one exact session/cursor-linked batch using the active
    /// generation's append-sync-state publication order.
    fn append_watch_batch(&mut self, batch: &WorkspaceWatchBatch) -> Result<(), CliError>;
}

/// Trust boundary for USN/FSEvents/inotify continuity. A production adapter
/// must subscribe before reconciliation, stream every queued event through the
/// bounded sink, and return a durable cursor only after its native barrier.
pub trait WorkspaceWatcherAuthority {
    fn begin_reconciliation(
        &mut self,
        root: &Path,
        binding: &VerifiedBinding,
    ) -> Result<WorkspaceWatcherStart, CliError>;

    fn finish_reconciliation(
        &mut self,
        start: &WorkspaceWatcherStart,
        sink: &mut dyn WorkspaceWatchEventSink,
    ) -> Result<WorkspaceWatcherCheckpoint, CliError>;

    /// Advances an already-open native session to an exact status-time
    /// barrier. The default cannot mint continuity, so third-party and
    /// unavailable implementations remain fail-degraded until a built-in
    /// native authority lands.
    fn fence_status(
        &mut self,
        _: &Path,
        _: &VerifiedBinding,
        start: &WorkspaceWatcherStart,
        _: &mut dyn WorkspaceWatchBatchSink,
    ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
        WorkspaceWatcherCheckpoint::unsupported(
            start,
            start
                .resume_cursor
                .clone()
                .unwrap_or_else(|| "unsupported".to_owned()),
        )
    }
}

#[derive(Default)]
pub struct UnavailableWorkspaceWatcher;

impl WorkspaceWatcherAuthority for UnavailableWorkspaceWatcher {
    fn begin_reconciliation(
        &mut self,
        _: &Path,
        _: &VerifiedBinding,
    ) -> Result<WorkspaceWatcherStart, CliError> {
        Ok(WorkspaceWatcherStart {
            adapter: "portable-fs-watch".to_owned(),
            session_id: format!("portable.{}", random_hex(16)?),
            resume_cursor: None,
        })
    }

    fn finish_reconciliation(
        &mut self,
        start: &WorkspaceWatcherStart,
        _: &mut dyn WorkspaceWatchEventSink,
    ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
        WorkspaceWatcherCheckpoint::unsupported(start, "unsupported".to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceIndexBuildRequest {
    pub root: PathBuf,
    pub authentication: AuthenticationRequest,
    pub local_ignore_rules: Vec<WorkspaceIgnoreRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIndexReport {
    pub schema: &'static str,
    pub generation: u64,
    pub generation_digest: String,
    pub baseline_entry_count: u64,
    pub initial_finding_count: u64,
    pub queued_event_count: u64,
    pub authoritative_clean: bool,
    pub reconciliation_required: bool,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceStatus {
    Modified,
    Added,
    Deleted,
    MovedRenamedHint,
    TypeModeChanged,
    Untracked,
    Ignored,
    Conflicted,
    MetadataOnly,
    AbsentBySpec,
    InaccessibleError,
}

impl WorkspaceStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Modified => "modified",
            Self::Added => "added",
            Self::Deleted => "deleted",
            Self::MovedRenamedHint => "moved-renamed-hint",
            Self::TypeModeChanged => "type-mode-changed",
            Self::Untracked => "untracked",
            Self::Ignored => "ignored",
            Self::Conflicted => "conflicted",
            Self::MetadataOnly => "metadata-only",
            Self::AbsentBySpec => "absent-by-spec",
            Self::InaccessibleError => "inaccessible-error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreExplanation {
    pub rule_id: String,
    pub source: IgnoreSource,
    pub action: IgnoreAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceStatusItem {
    pub repository_path: String,
    pub status: WorkspaceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_repository_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore: Option<IgnoreExplanation>,
    pub content_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceStatusPageRequest {
    pub root: PathBuf,
    pub cursor: Option<String>,
    pub limit: usize,
    pub filter: WorkspaceStatusFilter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceStatusFilter {
    pub include_ignored: bool,
    pub include_materialization_state: bool,
}

impl Default for WorkspaceStatusFilter {
    fn default() -> Self {
        Self {
            include_ignored: true,
            include_materialization_state: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceStatusPage {
    pub schema: &'static str,
    pub generation: u64,
    pub complete: bool,
    pub authoritative_clean: bool,
    pub reconciliation_required: bool,
    pub reason: String,
    pub candidate_count: u64,
    pub status_counts: BTreeMap<String, u64>,
    pub items: Vec<WorkspaceStatusItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusCursorPayload {
    schema: String,
    generation_id: String,
    active_sha256: String,
    watcher_payload_sha256: String,
    watcher_cursor: String,
    watcher_authority_sha256: String,
    watcher_event_count: u64,
    watcher_event_bytes: u64,
    watcher_event_tail_sha256: String,
    staging_generation: u64,
    staging_state_sha256: String,
    repository_settings_digest: String,
    path_profile: String,
    case_mode: String,
    repository_ignore_rules_sha256: String,
    local_ignore_rules_sha256: String,
    filter_sha256: String,
    after_repository_path: String,
    after_platform_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusCursor {
    payload: StatusCursorPayload,
    mac_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WatcherCursorAuthorityBinding<'a> {
    schema: &'static str,
    generation_id: &'a str,
    adapter: &'a str,
    session_id: &'a str,
    continuity_proven: bool,
    resume_supported: bool,
    session_open: bool,
    reconciliation_required: bool,
    reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fingerprint {
    bytes: u64,
    modified_nanos: i128,
    identity_digest: String,
    executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndexEntryDisk {
    repository_path: String,
    repository_key: String,
    platform_key: String,
    platform_key_sha256: String,
    file_id: String,
    content_manifest: String,
    content_sha256: String,
    content_bytes: u64,
    executable: bool,
    materialization: BaselineMaterialization,
    verified_fingerprint: Option<Fingerprint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FindingDisk {
    repository_path: String,
    status_hint: WorkspaceStatus,
    prior_repository_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WatchRecordCore {
    sequence: u64,
    event: WorkspaceWatchEvent,
    previous_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WatchRecord {
    core: WatchRecordCore,
    record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileSeal {
    name: String,
    bytes: u64,
    sha256: String,
    metadata_fingerprint_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationSealPayload {
    schema: String,
    generation_id: String,
    generation: u64,
    entry_count: u64,
    finding_count: u64,
    entries: FileSeal,
    lookup: FileSeal,
    findings: FileSeal,
    ignores: FileSeal,
    events_name: String,
    ordered_entries_sha256: String,
    repository_ignore_rules_sha256: String,
    local_ignore_rules_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationSeal {
    payload: GenerationSealPayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivePayload {
    schema: String,
    contract_version: String,
    generation_id: String,
    generation: u64,
    generation_seal_sha256: String,
    workspace_id_digest: String,
    repository_id_hex: String,
    branch: String,
    baseline: String,
    repository_settings_digest: String,
    path_profile: String,
    case_mode: String,
    created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveManifest {
    payload: ActivePayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WatcherStatePayload {
    schema: String,
    generation_id: String,
    adapter: String,
    session_id: String,
    cursor: String,
    continuity_proven: bool,
    resume_supported: bool,
    session_open: bool,
    reconciliation_required: bool,
    reason: String,
    event_count: u64,
    event_bytes: u64,
    event_tail_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WatcherState {
    payload: WatcherStatePayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransitionPayload {
    schema: String,
    generation_id: String,
    prior_active_sha256: Option<String>,
    artifact_names: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Transition {
    payload: TransitionPayload,
    payload_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IgnoreFile {
    schema: String,
    repository_rules: Vec<WorkspaceIgnoreRule>,
    local_rules: Vec<WorkspaceIgnoreRule>,
}

fn index_error(code: &'static str, message: &'static str, next: &'static str) -> CliError {
    workspace_error(code, message, next)
}

fn index_invalid() -> CliError {
    index_error(
        "WORKSPACE_INDEX_INVALID",
        "The durable workspace index is malformed, corrupt, or unsafe.",
        "Run the authenticated workspace index rebuild; local files will be preserved.",
    )
}

fn index_recovery_required() -> CliError {
    index_error(
        "WORKSPACE_INDEX_RECOVERY_REQUIRED",
        "A workspace index generation transition did not reach a stable boundary.",
        "Run workspace index recovery before requesting status.",
    )
}

fn index_write_unavailable() -> CliError {
    index_error(
        "WORKSPACE_INDEX_WRITE_UNAVAILABLE",
        "The durable workspace index could not be committed safely.",
        "Check private filesystem ownership and run workspace index recovery.",
    )
}

fn index_limit(code: &'static str) -> CliError {
    CliError::new(
        ExitClass::Input,
        code,
        "A bounded workspace index input exceeded its exact limit.",
        "Split input into canonical chunks within the advertised item and byte bounds.",
    )
}

fn hex_bytes(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn finalize_hasher(hasher: Sha256) -> String {
    hex_bytes(&hasher.finalize())
}

fn payload_wrapper<T>(payload: T) -> Result<(T, String), CliError>
where
    T: Serialize,
{
    let digest = json_digest(&payload)?;
    Ok((payload, digest))
}

fn validate_wrapped<T: Serialize>(payload: &T, digest: &str) -> Result<(), CliError> {
    if valid_digest(digest) && json_digest(payload)? == digest {
        Ok(())
    } else {
        Err(index_invalid())
    }
}

fn valid_generation_id(value: &str) -> bool {
    value.len() == 67
        && value.starts_with("g1.")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_bounded_opaque(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn checked_index_directory(root: &Path) -> Result<PathBuf, CliError> {
    let control = checked_control(root)?;
    let index = control.join("workspace-index-v1");
    match fs::symlink_metadata(&index) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_dir() => {
            crate::ensure_private_directory(&index)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::create_private_directory(&index)?;
            sync_directory(&control)?;
        }
        _ => return Err(index_invalid()),
    }
    Ok(index)
}

fn existing_index_directory(root: &Path) -> Result<PathBuf, CliError> {
    let control = checked_control(root)?;
    let index = control.join("workspace-index-v1");
    let metadata = fs::symlink_metadata(&index).map_err(|_| index_invalid())?;
    if is_link_or_reparse(&metadata) || !metadata.is_dir() {
        return Err(index_invalid());
    }
    crate::ensure_private_directory(&index)?;
    Ok(index)
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<u64, CliError> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| internal_error())?;
    bytes.push(b'\n');
    let mut file = crate::create_private_file(path, true)?;
    file.write_all(&bytes)
        .map_err(|_| index_write_unavailable())?;
    file.sync_all().map_err(|_| index_write_unavailable())?;
    u64::try_from(bytes.len()).map_err(|_| internal_error())
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    crate::write_json_atomic(path, value).map_err(|_| index_write_unavailable())
}

fn read_json_private<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum: u64,
) -> Result<T, CliError> {
    let bytes = crate::read_bounded(path, maximum).map_err(|_| index_invalid())?;
    serde_json::from_slice(&bytes).map_err(|_| index_invalid())
}

fn open_private_file(path: &Path) -> Result<File, CliError> {
    crate::open_private_regular_file(path).map_err(|_| index_invalid())
}

fn create_artifact(index: &Path, name: &str) -> Result<File, CliError> {
    if !valid_artifact_name(name) {
        return Err(internal_error());
    }
    crate::create_private_file(&index.join(name), true).map_err(|_| index_write_unavailable())
}

fn ensure_cursor_key(index: &Path) -> Result<[u8; 32], CliError> {
    let path = index.join(CURSOR_KEY_NAME);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {
            read_cursor_key(index)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).map_err(|_| index_write_unavailable())?;
            let mut file =
                crate::create_private_file(&path, true).map_err(|_| index_write_unavailable())?;
            file.write_all(&key)
                .map_err(|_| index_write_unavailable())?;
            file.sync_all().map_err(|_| index_write_unavailable())?;
            sync_directory(index)?;
            Ok(key)
        }
        _ => Err(index_invalid()),
    }
}

fn read_cursor_key(index: &Path) -> Result<[u8; 32], CliError> {
    let mut file = open_private_file(&index.join(CURSOR_KEY_NAME))?;
    if file.metadata().map_err(|_| index_invalid())?.len() != 32 {
        return Err(index_invalid());
    }
    let mut key = [0u8; 32];
    file.read_exact(&mut key).map_err(|_| index_invalid())?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(|_| index_invalid())? != 0 {
        return Err(index_invalid());
    }
    Ok(key)
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> String {
    let mut inner_key = [0x36u8; 64];
    let mut outer_key = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(STATUS_CURSOR_DOMAIN);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    finalize_hasher(outer)
}

fn constant_time_digest_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn valid_artifact_name(value: &str) -> bool {
    value.len() >= 8
        && value.len() <= 128
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn artifact_names(generation_id: &str) -> Vec<String> {
    [
        "entries", "lookup", "findings", "ignores", "events", "watcher", "seal",
    ]
    .into_iter()
    .map(|kind| format!("{kind}-{generation_id}.v1"))
    .collect()
}

struct GenerationWriter {
    root: PathBuf,
    index: PathBuf,
    metadata: VerifiedWorkspaceMetadata,
    generation_id: String,
    generation: u64,
    names: Vec<String>,
    transition_path: PathBuf,
    entries: File,
    lookup: File,
    findings: File,
    ignores: File,
    events: File,
    entries_hasher: Sha256,
    lookup_hasher: Sha256,
    findings_hasher: Sha256,
    ignores_hasher: Sha256,
    ordered_hasher: Sha256,
    entries_bytes: u64,
    lookup_bytes: u64,
    findings_bytes: u64,
    ignores_bytes: u64,
    event_bytes: u64,
    entry_count: u64,
    finding_count: u64,
    event_count: u64,
    event_tail_sha256: String,
    prior_sort_key: Option<(String, String)>,
    prior_repository_key: Option<String>,
    local_ignore_rules: Vec<WorkspaceIgnoreRule>,
    reconciliation_prepared: bool,
    committed: bool,
    abandoned_for_test: bool,
}

struct PreparedGeneration {
    provisional_seal: GenerationSealPayload,
}

impl GenerationWriter {
    fn begin(
        root: &Path,
        metadata: VerifiedWorkspaceMetadata,
        local_ignore_rules: Vec<WorkspaceIgnoreRule>,
    ) -> Result<Self, CliError> {
        validate_ignore_rules(&local_ignore_rules, IgnoreSource::Local, &metadata.binding)?;
        let index = checked_index_directory(root)?;
        let _ = ensure_cursor_key(&index)?;
        if index.join("transition.json").exists() {
            return Err(index_recovery_required());
        }
        if retention::compaction_pending(&index)? {
            return Err(index_recovery_required());
        }
        let prior_active = read_optional_active(&index)?;
        if let Some(active) = &prior_active {
            retention::ensure_generation_capacity(&index, &metadata, active)?;
        }
        let generation = prior_active.as_ref().map_or(Ok(1), |active| {
            active
                .payload
                .generation
                .checked_add(1)
                .ok_or_else(index_invalid)
        })?;
        let generation_id = format!("g1.{}", random_hex(32)?);
        let names = artifact_names(&generation_id);
        let transition_payload = TransitionPayload {
            schema: "ogvcs.workspace-index/transition/v1".to_owned(),
            generation_id: generation_id.clone(),
            prior_active_sha256: prior_active.map(|active| active.payload_sha256),
            artifact_names: names.clone(),
        };
        let (payload, payload_sha256) = payload_wrapper(transition_payload)?;
        let transition = Transition {
            payload,
            payload_sha256,
        };
        let transition_path = index.join("transition.json");
        write_json_new(&transition_path, &transition)?;
        sync_directory(&index)?;
        if crash_now(CrashPoint::TransitionPublished) {
            return Err(injected_crash());
        }

        let result = (|| {
            Ok(Self {
                root: root.to_path_buf(),
                index: index.clone(),
                metadata,
                generation_id,
                generation,
                entries: create_artifact(&index, &names[0])?,
                lookup: create_artifact(&index, &names[1])?,
                findings: create_artifact(&index, &names[2])?,
                ignores: create_artifact(&index, &names[3])?,
                events: create_artifact(&index, &names[4])?,
                names,
                transition_path,
                entries_hasher: Sha256::new(),
                lookup_hasher: Sha256::new(),
                findings_hasher: Sha256::new(),
                ignores_hasher: Sha256::new(),
                ordered_hasher: {
                    let mut hasher = Sha256::new();
                    hasher.update(ORDERED_BASELINE_DOMAIN);
                    hasher
                },
                entries_bytes: 0,
                lookup_bytes: 0,
                findings_bytes: 0,
                ignores_bytes: 0,
                event_bytes: 0,
                entry_count: 0,
                finding_count: 0,
                event_count: 0,
                event_tail_sha256: EMPTY_SHA256.to_owned(),
                prior_sort_key: None,
                prior_repository_key: None,
                local_ignore_rules,
                reconciliation_prepared: false,
                committed: false,
                abandoned_for_test: false,
            })
        })();
        if result.is_err() {
            let _ = recover_transition_at(&index);
        }
        result
    }

    fn validate_chunk(&self, entries: &[WorkspaceBaselineEntry]) -> Result<(), CliError> {
        if entries.is_empty() || entries.len() > MAX_BASELINE_CHUNK_ITEMS {
            return Err(index_limit("WORKSPACE_INDEX_CHUNK_LIMIT"));
        }
        if self
            .entry_count
            .checked_add(u64::try_from(entries.len()).map_err(|_| internal_error())?)
            .is_none_or(|total| total > MAX_BASELINE_ENTRIES)
        {
            return Err(index_limit("WORKSPACE_INDEX_ENTRY_LIMIT"));
        }
        let mut bytes = 0usize;
        let mut prior = self.prior_sort_key.clone();
        let mut prior_repository = self.prior_repository_key.clone();
        for entry in entries {
            let encoded = serde_json::to_vec(entry).map_err(|_| input_error())?;
            if encoded.len() > MAX_ENTRY_BYTES {
                return Err(index_limit("WORKSPACE_INDEX_ENTRY_BYTES"));
            }
            bytes = bytes
                .checked_add(encoded.len() + 8)
                .ok_or_else(|| index_limit("WORKSPACE_INDEX_CHUNK_BYTES"))?;
            if bytes > MAX_BASELINE_CHUNK_BYTES {
                return Err(index_limit("WORKSPACE_INDEX_CHUNK_BYTES"));
            }
            let validated = validate_baseline_entry(entry, &self.metadata.binding)?;
            let sort = (
                digest_text(validated.platform_key.as_str()),
                validated.platform_key.clone(),
            );
            if prior.as_ref().is_some_and(|value| value >= &sort) {
                return Err(index_error(
                    "WORKSPACE_INDEX_ORDER_INVALID",
                    "Baseline entries are duplicated, colliding, or not in canonical platform-key order.",
                    "Stream the complete baseline ordered by platform-key SHA-256 then full platform key.",
                ));
            }
            if prior_repository
                .as_ref()
                .is_some_and(|value| value == &validated.repository_key)
            {
                return Err(index_error(
                    "WORKSPACE_INDEX_PATH_COLLISION",
                    "Two baseline entries resolve to the same repository path identity.",
                    "Repair the immutable baseline under its exact path profile and case mode.",
                ));
            }
            prior = Some(sort);
            prior_repository = Some(validated.repository_key);
        }
        Ok(())
    }

    fn append_one(&mut self, entry: &WorkspaceBaselineEntry) -> Result<(), CliError> {
        let validated = validate_baseline_entry(entry, &self.metadata.binding)?;
        let raw = serde_json::to_vec(entry).map_err(|_| internal_error())?;
        self.ordered_hasher.update(
            u64::try_from(raw.len())
                .map_err(|_| internal_error())?
                .to_be_bytes(),
        );
        self.ordered_hasher.update(&raw);

        let observed = probe_regular_file(&self.root, &entry.repository_path)?;
        let (verified_fingerprint, finding) = classify_baseline_observation(entry, observed);
        let disk = IndexEntryDisk {
            repository_path: entry.repository_path.clone(),
            repository_key: validated.repository_key.clone(),
            platform_key: validated.platform_key.clone(),
            platform_key_sha256: digest_text(&validated.platform_key),
            file_id: entry.file_id.clone(),
            content_manifest: entry.content_manifest.clone(),
            content_sha256: entry.content_sha256.clone(),
            content_bytes: entry.content_bytes,
            executable: entry.executable,
            materialization: entry.materialization,
            verified_fingerprint,
        };
        let mut line = serde_json::to_vec(&disk).map_err(|_| internal_error())?;
        if line.len() > MAX_ENTRY_BYTES {
            return Err(index_limit("WORKSPACE_INDEX_ENTRY_BYTES"));
        }
        line.push(b'\n');
        let offset = self.entries_bytes;
        let length = u32::try_from(line.len()).map_err(|_| internal_error())?;
        let line_sha = Sha256::digest(&line);
        self.entries
            .write_all(&line)
            .map_err(|_| index_write_unavailable())?;
        self.entries_hasher.update(&line);
        self.entries_bytes = self
            .entries_bytes
            .checked_add(u64::from(length))
            .ok_or_else(index_invalid)?;

        let key = Sha256::digest(validated.platform_key.as_bytes());
        let mut record = [0u8; LOOKUP_RECORD_BYTES as usize];
        record[..32].copy_from_slice(&key);
        record[32..40].copy_from_slice(&offset.to_be_bytes());
        record[40..44].copy_from_slice(&length.to_be_bytes());
        record[44..76].copy_from_slice(&line_sha);
        self.lookup
            .write_all(&record)
            .map_err(|_| index_write_unavailable())?;
        self.lookup_hasher.update(record);
        self.lookup_bytes = self
            .lookup_bytes
            .checked_add(LOOKUP_RECORD_BYTES)
            .ok_or_else(index_invalid)?;
        self.entry_count = self.entry_count.checked_add(1).ok_or_else(index_invalid)?;
        self.prior_sort_key = Some((digest_text(&validated.platform_key), validated.platform_key));
        self.prior_repository_key = Some(validated.repository_key);
        if let Some(status) = finding {
            self.append_finding(FindingDisk {
                repository_path: entry.repository_path.clone(),
                status_hint: status,
                prior_repository_path: None,
            })?;
        }
        Ok(())
    }

    fn append_finding(&mut self, finding: FindingDisk) -> Result<(), CliError> {
        if self.finding_count >= MAX_BASELINE_ENTRIES {
            return Err(index_limit("WORKSPACE_INDEX_FINDING_LIMIT"));
        }
        let mut line = serde_json::to_vec(&finding).map_err(|_| internal_error())?;
        if line.len() > MAX_FINDING_BYTES {
            return Err(index_limit("WORKSPACE_INDEX_FINDING_BYTES"));
        }
        line.push(b'\n');
        self.findings
            .write_all(&line)
            .map_err(|_| index_write_unavailable())?;
        self.findings_hasher.update(&line);
        self.findings_bytes = self
            .findings_bytes
            .checked_add(u64::try_from(line.len()).map_err(|_| internal_error())?)
            .ok_or_else(index_invalid)?;
        self.finding_count = self
            .finding_count
            .checked_add(1)
            .ok_or_else(index_invalid)?;
        Ok(())
    }

    fn write_ignores(
        &mut self,
        repository_rules: Vec<WorkspaceIgnoreRule>,
    ) -> Result<IgnoreFile, CliError> {
        validate_ignore_rules(
            &repository_rules,
            IgnoreSource::Repository,
            &self.metadata.binding,
        )?;
        let ignores = IgnoreFile {
            schema: "ogvcs.workspace-index/ignore-rules/v1".to_owned(),
            repository_rules,
            local_rules: self.local_ignore_rules.clone(),
        };
        let mut bytes = serde_json::to_vec(&ignores).map_err(|_| internal_error())?;
        if bytes.len() > MAX_CONTROL_BYTES as usize {
            return Err(index_limit("WORKSPACE_INDEX_IGNORE_BYTES"));
        }
        bytes.push(b'\n');
        self.ignores
            .write_all(&bytes)
            .map_err(|_| index_write_unavailable())?;
        self.ignores_hasher.update(&bytes);
        self.ignores_bytes = u64::try_from(bytes.len()).map_err(|_| internal_error())?;
        Ok(ignores)
    }

    fn ordered_entries_sha256(&self) -> String {
        finalize_hasher(self.ordered_hasher.clone())
    }

    fn append_watch_events(&mut self, events: &[WorkspaceWatchEvent]) -> Result<(), CliError> {
        validate_watch_chunk(events, &self.metadata.binding)?;
        let next_count = self
            .event_count
            .checked_add(u64::try_from(events.len()).map_err(|_| internal_error())?)
            .ok_or_else(index_invalid)?;
        if next_count > MAX_WATCH_EVENTS {
            return Err(index_limit("WORKSPACE_WATCH_EVENT_LIMIT"));
        }
        let mut encoded = Vec::with_capacity(events.len());
        let mut total_bytes = 0usize;
        let mut previous = self.event_tail_sha256.clone();
        let mut sequence = self.event_count;
        for event in events {
            sequence = sequence.checked_add(1).ok_or_else(index_invalid)?;
            let core = WatchRecordCore {
                sequence,
                event: event.clone(),
                previous_sha256: previous,
            };
            let core_bytes = serde_json::to_vec(&core).map_err(|_| internal_error())?;
            let mut hasher = Sha256::new();
            hasher.update(WATCH_RECORD_DOMAIN);
            hasher.update(
                u64::try_from(core_bytes.len())
                    .map_err(|_| internal_error())?
                    .to_be_bytes(),
            );
            hasher.update(&core_bytes);
            let record = WatchRecord {
                core,
                record_sha256: finalize_hasher(hasher),
            };
            previous = record.record_sha256.clone();
            let mut line = serde_json::to_vec(&record).map_err(|_| internal_error())?;
            if line.len() > MAX_EVENT_BYTES {
                return Err(index_limit("WORKSPACE_WATCH_EVENT_BYTES"));
            }
            line.push(b'\n');
            total_bytes = total_bytes
                .checked_add(line.len())
                .ok_or_else(|| index_limit("WORKSPACE_WATCH_CHUNK_BYTES"))?;
            if total_bytes > MAX_WATCH_CHUNK_BYTES {
                return Err(index_limit("WORKSPACE_WATCH_CHUNK_BYTES"));
            }
            encoded.push(line);
        }
        let resulting_bytes = self
            .event_bytes
            .checked_add(u64::try_from(total_bytes).map_err(|_| internal_error())?)
            .ok_or_else(index_invalid)?;
        if resulting_bytes > MAX_EVENTS_BYTES {
            return Err(index_limit("WORKSPACE_WATCH_JOURNAL_BYTES"));
        }
        for line in encoded {
            self.events
                .write_all(&line)
                .map_err(|_| index_write_unavailable())?;
        }
        self.event_count = next_count;
        self.event_bytes = resulting_bytes;
        self.event_tail_sha256 = previous;
        Ok(())
    }
}

impl WorkspaceBaselineSink for GenerationWriter {
    fn append_chunk(&mut self, entries: &[WorkspaceBaselineEntry]) -> Result<(), CliError> {
        if self.reconciliation_prepared {
            return Err(index_invalid());
        }
        self.validate_chunk(entries)?;
        for entry in entries {
            self.append_one(entry)?;
        }
        Ok(())
    }
}

impl WorkspaceWatchEventSink for GenerationWriter {
    fn append_watch_chunk(&mut self, events: &[WorkspaceWatchEvent]) -> Result<(), CliError> {
        if !self.reconciliation_prepared {
            return Err(index_invalid());
        }
        self.append_watch_events(events)
    }
}

impl Drop for GenerationWriter {
    fn drop(&mut self) {
        if !self.committed && !self.abandoned_for_test {
            let _ = recover_transition_at(&self.index);
        }
    }
}

struct ValidatedBaselinePath {
    repository_key: String,
    platform_key: String,
}

fn validate_baseline_entry(
    entry: &WorkspaceBaselineEntry,
    binding: &VerifiedBinding,
) -> Result<ValidatedBaselinePath, CliError> {
    let keys = path_collision_keys(
        &entry.repository_path,
        &binding.path_profile,
        &binding.case_mode,
    )
    .map_err(|_| input_error())?;
    let file_id = FileId::from_str(&entry.file_id).map_err(|_| input_error())?;
    let manifest = ObjectRef::from_str(&entry.content_manifest).map_err(|_| input_error())?;
    if file_id.to_string() != entry.file_id
        || manifest.kind != ObjectKind::ContentManifest
        || manifest.to_string() != entry.content_manifest
        || !valid_digest(&entry.content_sha256)
    {
        return Err(input_error());
    }
    Ok(ValidatedBaselinePath {
        repository_key: keys.repository_key().as_str().to_owned(),
        platform_key: keys.platform_key().to_owned(),
    })
}

fn validate_ignore_rules(
    rules: &[WorkspaceIgnoreRule],
    source: IgnoreSource,
    binding: &VerifiedBinding,
) -> Result<(), CliError> {
    if rules.len() > MAX_IGNORE_RULES {
        return Err(index_limit("WORKSPACE_INDEX_IGNORE_LIMIT"));
    }
    let mut ids = BTreeSet::new();
    for rule in rules {
        if rule.source != source
            || !valid_bounded_opaque(&rule.rule_id, 128)
            || !ids.insert(rule.rule_id.as_str())
            || path_collision_keys(
                &rule.repository_path,
                &binding.path_profile,
                &binding.case_mode,
            )
            .is_err()
        {
            return Err(input_error());
        }
    }
    Ok(())
}

fn ignore_rules_digest(rules: &[WorkspaceIgnoreRule]) -> Result<String, CliError> {
    json_digest(&rules)
}

fn validate_watch_chunk(
    events: &[WorkspaceWatchEvent],
    binding: &VerifiedBinding,
) -> Result<(), CliError> {
    if events.is_empty() || events.len() > MAX_WATCH_CHUNK_ITEMS {
        return Err(index_limit("WORKSPACE_WATCH_CHUNK_LIMIT"));
    }
    let mut total = 0usize;
    for event in events {
        let encoded = serde_json::to_vec(event).map_err(|_| input_error())?;
        total = total
            .checked_add(encoded.len())
            .ok_or_else(|| index_limit("WORKSPACE_WATCH_CHUNK_BYTES"))?;
        if encoded.len() > MAX_EVENT_BYTES || total > MAX_WATCH_CHUNK_BYTES {
            return Err(index_limit("WORKSPACE_WATCH_CHUNK_BYTES"));
        }
        path_collision_keys(
            &event.repository_path,
            &binding.path_profile,
            &binding.case_mode,
        )
        .map_err(|_| input_error())?;
        match (event.kind, event.prior_repository_path.as_deref()) {
            (WorkspaceWatchEventKind::Renamed, Some(prior)) => {
                path_collision_keys(prior, &binding.path_profile, &binding.case_mode)
                    .map_err(|_| input_error())?;
                if prior == event.repository_path {
                    return Err(input_error());
                }
            }
            (WorkspaceWatchEventKind::Renamed, None) => return Err(input_error()),
            (_, Some(_)) => return Err(input_error()),
            _ => {}
        }
    }
    Ok(())
}

enum FileProbe {
    Absent,
    Regular {
        fingerprint: Fingerprint,
        content_sha256: String,
    },
    Other,
    Inaccessible,
}

fn probe_regular_file(root: &Path, repository_path: &str) -> Result<FileProbe, CliError> {
    let path = joined_path(root, repository_path);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(FileProbe::Absent),
        Err(_) => return Ok(FileProbe::Inaccessible),
    };
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Ok(FileProbe::Other);
    }
    let mut file = match confined_existing_regular_file(root, repository_path) {
        Ok(file) => file,
        Err(_) => return Ok(FileProbe::Inaccessible),
    };
    let before = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Ok(FileProbe::Inaccessible),
    };
    let before_fingerprint = fingerprint(&file, &before)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(_) => return Ok(FileProbe::Inaccessible),
        };
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let after = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Ok(FileProbe::Inaccessible),
    };
    let after_fingerprint = fingerprint(&file, &after)?;
    if before_fingerprint != after_fingerprint {
        return Ok(FileProbe::Inaccessible);
    }
    Ok(FileProbe::Regular {
        fingerprint: after_fingerprint,
        content_sha256: finalize_hasher(hasher),
    })
}

fn fingerprint(file: &File, metadata: &fs::Metadata) -> Result<Fingerprint, CliError> {
    #[cfg(not(windows))]
    {
        let _ = file;
        let modified_nanos = i128::from(metadata.mtime())
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(i128::from(metadata.mtime_nsec())))
            .ok_or_else(index_invalid)?;
        let identity_digest = digest_text(&format!(
            "unix:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec()
        ));
        Ok(Fingerprint {
            bytes: metadata.len(),
            modified_nanos,
            identity_digest,
            executable: metadata.mode() & 0o111 != 0,
        })
    }
    #[cfg(windows)]
    {
        let (volume_serial, file_index) =
            crate::windows_security::file_identity(file).map_err(|_| index_invalid())?;
        let identity_digest = digest_text(&format!(
            "windows:{volume_serial}:{file_index}:{}",
            metadata.creation_time()
        ));
        Ok(Fingerprint {
            bytes: metadata.file_size(),
            modified_nanos: i128::from(metadata.last_write_time()) * 100,
            identity_digest,
            executable: false,
        })
    }
}

fn artifact_metadata_fingerprint(path: &Path) -> Result<String, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| index_invalid())?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(index_invalid());
    }
    let file = open_private_file(path)?;
    let opened = file.metadata().map_err(|_| index_invalid())?;
    json_digest(&fingerprint(&file, &opened)?)
}

fn classify_baseline_observation(
    entry: &WorkspaceBaselineEntry,
    observed: FileProbe,
) -> (Option<Fingerprint>, Option<WorkspaceStatus>) {
    match (&entry.materialization, observed) {
        (BaselineMaterialization::Full, FileProbe::Absent) => {
            (None, Some(WorkspaceStatus::Deleted))
        }
        (BaselineMaterialization::Full, FileProbe::Other) => {
            (None, Some(WorkspaceStatus::TypeModeChanged))
        }
        (BaselineMaterialization::Full, FileProbe::Inaccessible) => {
            (None, Some(WorkspaceStatus::InaccessibleError))
        }
        (
            BaselineMaterialization::Full,
            FileProbe::Regular {
                fingerprint,
                content_sha256,
            },
        ) => {
            let status = if fingerprint.bytes != entry.content_bytes
                || content_sha256 != entry.content_sha256
            {
                Some(WorkspaceStatus::Modified)
            } else if fingerprint.executable != entry.executable {
                Some(WorkspaceStatus::TypeModeChanged)
            } else {
                None
            };
            (Some(fingerprint), status)
        }
        (BaselineMaterialization::MetadataOnly, FileProbe::Absent) => {
            (None, Some(WorkspaceStatus::MetadataOnly))
        }
        (BaselineMaterialization::AbsentBySpec, FileProbe::Absent) => {
            (None, Some(WorkspaceStatus::AbsentBySpec))
        }
        (BaselineMaterialization::MetadataOnly, FileProbe::Inaccessible)
        | (BaselineMaterialization::AbsentBySpec, FileProbe::Inaccessible) => {
            (None, Some(WorkspaceStatus::InaccessibleError))
        }
        (BaselineMaterialization::MetadataOnly, FileProbe::Other)
        | (BaselineMaterialization::AbsentBySpec, FileProbe::Other) => {
            (None, Some(WorkspaceStatus::TypeModeChanged))
        }
        (BaselineMaterialization::MetadataOnly, FileProbe::Regular { fingerprint, .. }) => {
            (Some(fingerprint), Some(WorkspaceStatus::MetadataOnly))
        }
        (BaselineMaterialization::AbsentBySpec, FileProbe::Regular { fingerprint, .. }) => {
            (Some(fingerprint), Some(WorkspaceStatus::Modified))
        }
    }
}

struct LookupReader {
    entries: File,
    lookup: File,
    entry_count: u64,
    entries_bytes: u64,
}

impl LookupReader {
    fn open(index: &Path, seal: &GenerationSealPayload) -> Result<Self, CliError> {
        Ok(Self {
            entries: open_private_file(&index.join(&seal.entries.name))?,
            lookup: open_private_file(&index.join(&seal.lookup.name))?,
            entry_count: seal.entry_count,
            entries_bytes: seal.entries.bytes,
        })
    }

    fn find(
        &mut self,
        repository_path: &str,
        binding: &VerifiedBinding,
    ) -> Result<Option<IndexEntryDisk>, CliError> {
        let keys = path_collision_keys(repository_path, &binding.path_profile, &binding.case_mode)
            .map_err(|_| input_error())?;
        let target = Sha256::digest(keys.platform_key().as_bytes());
        let mut low = 0u64;
        let mut high = self.entry_count;
        while low < high {
            let middle = low + (high - low) / 2;
            let record = self.record(middle)?;
            if record[..32] < target[..] {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let mut index = low;
        let mut collision_count = 0usize;
        while index < self.entry_count {
            let record = self.record(index)?;
            if record[..32] != target[..] {
                break;
            }
            collision_count += 1;
            if collision_count > 32 {
                return Err(index_invalid());
            }
            let entry = self.entry_from_record(&record)?;
            let full_match = entry.repository_path == repository_path
                && entry.platform_key == keys.platform_key()
                && entry.repository_key == keys.repository_key().as_str()
                && entry.platform_key_sha256 == hex_bytes(&target);
            if full_match {
                return Ok(Some(entry));
            }
            index += 1;
        }
        Ok(None)
    }

    fn record(&mut self, index: u64) -> Result<[u8; LOOKUP_RECORD_BYTES as usize], CliError> {
        let offset = index
            .checked_mul(LOOKUP_RECORD_BYTES)
            .ok_or_else(index_invalid)?;
        self.lookup
            .seek(SeekFrom::Start(offset))
            .map_err(|_| index_invalid())?;
        let mut record = [0u8; LOOKUP_RECORD_BYTES as usize];
        self.lookup
            .read_exact(&mut record)
            .map_err(|_| index_invalid())?;
        Ok(record)
    }

    fn entry_from_record(
        &mut self,
        record: &[u8; LOOKUP_RECORD_BYTES as usize],
    ) -> Result<IndexEntryDisk, CliError> {
        let offset = u64::from_be_bytes(record[32..40].try_into().map_err(|_| index_invalid())?);
        let length = u32::from_be_bytes(record[40..44].try_into().map_err(|_| index_invalid())?);
        let length_u64 = u64::from(length);
        if length == 0
            || length as usize > MAX_ENTRY_BYTES + 1
            || offset
                .checked_add(length_u64)
                .is_none_or(|end| end > self.entries_bytes)
        {
            return Err(index_invalid());
        }
        self.entries
            .seek(SeekFrom::Start(offset))
            .map_err(|_| index_invalid())?;
        let mut line = vec![0u8; length as usize];
        self.entries
            .read_exact(&mut line)
            .map_err(|_| index_invalid())?;
        if line.last() != Some(&b'\n') || Sha256::digest(&line)[..] != record[44..76] {
            return Err(index_invalid());
        }
        line.pop();
        serde_json::from_slice(&line).map_err(|_| index_invalid())
    }
}

fn append_untracked_findings(
    writer: &mut GenerationWriter,
    seal_view: &GenerationSealPayload,
    ignores: &IgnoreFile,
) -> Result<(), CliError> {
    writer
        .entries
        .sync_data()
        .map_err(|_| index_write_unavailable())?;
    writer
        .lookup
        .sync_data()
        .map_err(|_| index_write_unavailable())?;
    let mut lookup = LookupReader::open(&writer.index, seal_view)?;
    scan_directory_for_untracked(
        &writer.root.clone(),
        "",
        &writer.metadata.binding.clone(),
        ignores,
        &mut lookup,
        writer,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_directory_for_untracked(
    directory: &Path,
    relative: &str,
    binding: &VerifiedBinding,
    ignores: &IgnoreFile,
    lookup: &mut LookupReader,
    writer: &mut GenerationWriter,
    depth: usize,
) -> Result<(), CliError> {
    if depth > 256 {
        return Err(index_invalid());
    }
    let entries = fs::read_dir(directory).map_err(|_| index_invalid())?;
    for result in entries {
        let entry = match result {
            Ok(entry) => entry,
            Err(_) => return Err(index_invalid()),
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(name) => {
                let diagnostic = digest_bytes(name.to_string_lossy().as_bytes());
                writer.append_finding(FindingDisk {
                    repository_path: format!("inaccessible-{diagnostic}"),
                    status_hint: WorkspaceStatus::InaccessibleError,
                    prior_repository_path: None,
                })?;
                continue;
            }
        };
        if relative.is_empty() && (name == ".ogvcs" || name == ".ogvcs-mutation-v2.lock") {
            continue;
        }
        let canonical = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        if path_collision_keys(&canonical, &binding.path_profile, &binding.case_mode).is_err() {
            writer.append_finding(FindingDisk {
                repository_path: canonical,
                status_hint: WorkspaceStatus::InaccessibleError,
                prior_repository_path: None,
            })?;
            continue;
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => {
                writer.append_finding(FindingDisk {
                    repository_path: canonical,
                    status_hint: WorkspaceStatus::InaccessibleError,
                    prior_repository_path: None,
                })?;
                continue;
            }
        };
        if is_link_or_reparse(&metadata) {
            writer.append_finding(FindingDisk {
                repository_path: canonical,
                status_hint: WorkspaceStatus::InaccessibleError,
                prior_repository_path: None,
            })?;
        } else if metadata.is_dir() {
            scan_directory_for_untracked(
                &entry.path(),
                &canonical,
                binding,
                ignores,
                lookup,
                writer,
                depth + 1,
            )?;
        } else if metadata.is_file() && lookup.find(&canonical, binding)?.is_none() {
            let (ignored, _) = ignored_by(&canonical, ignores);
            writer.append_finding(FindingDisk {
                repository_path: canonical,
                status_hint: if ignored {
                    WorkspaceStatus::Ignored
                } else {
                    WorkspaceStatus::Untracked
                },
                prior_repository_path: None,
            })?;
        } else if !metadata.is_file() {
            writer.append_finding(FindingDisk {
                repository_path: canonical,
                status_hint: WorkspaceStatus::InaccessibleError,
                prior_repository_path: None,
            })?;
        }
    }
    Ok(())
}

fn ignored_by(path: &str, ignores: &IgnoreFile) -> (bool, Option<IgnoreExplanation>) {
    let mut decision = None;
    for source in [IgnoreSource::Repository, IgnoreSource::Local] {
        let rules = match source {
            IgnoreSource::Repository => &ignores.repository_rules,
            IgnoreSource::Local => &ignores.local_rules,
        };
        for rule in rules {
            let matches = match rule.pattern_kind {
                IgnorePatternKind::Exact => path == rule.repository_path,
                IgnorePatternKind::Subtree => {
                    path == rule.repository_path
                        || path
                            .strip_prefix(&rule.repository_path)
                            .is_some_and(|suffix| suffix.starts_with('/'))
                }
            };
            if matches {
                decision = Some(IgnoreExplanation {
                    rule_id: rule.rule_id.clone(),
                    source: rule.source,
                    action: rule.action,
                });
            }
        }
    }
    let ignored = decision
        .as_ref()
        .is_some_and(|explanation| explanation.action == IgnoreAction::Ignore);
    (ignored, decision)
}

fn validate_baseline_receipt(
    receipt: &WorkspaceBaselineReceipt,
    writer: &GenerationWriter,
) -> Result<(), CliError> {
    let binding = &writer.metadata.binding;
    if receipt.schema != BASELINE_RECEIPT_SCHEMA
        || receipt.repository_id_hex != binding.repository_id_hex
        || receipt.baseline != binding.baseline
        || receipt.repository_settings_digest != binding.repository_settings_digest
        || receipt.path_profile != binding.path_profile
        || receipt.case_mode != binding.case_mode
        || receipt.entry_count != writer.entry_count
        || receipt.entry_count == 0
        || receipt.ordered_entries_sha256 != writer.ordered_entries_sha256()
        || !valid_digest(&receipt.ordered_entries_sha256)
        || receipt.repository_ignore_rules_sha256
            != ignore_rules_digest(&receipt.repository_ignore_rules)?
        || !valid_digest(&receipt.repository_ignore_rules_sha256)
    {
        return Err(index_error(
            "WORKSPACE_BASELINE_RECEIPT_INVALID",
            "The streamed baseline receipt does not bind the complete verified workspace baseline.",
            "Retry through a current OGVCS-006/007 baseline adapter.",
        ));
    }
    validate_ignore_rules(
        &receipt.repository_ignore_rules,
        IgnoreSource::Repository,
        binding,
    )
}

fn validate_watcher_start(start: &WorkspaceWatcherStart) -> Result<(), CliError> {
    if !valid_bounded_opaque(&start.adapter, 64)
        || !valid_bounded_opaque(&start.session_id, 128)
        || start
            .resume_cursor
            .as_deref()
            .is_some_and(|cursor| !valid_bounded_opaque(cursor, 512))
    {
        return Err(index_invalid());
    }
    Ok(())
}

fn validate_watcher_checkpoint(
    start: &WorkspaceWatcherStart,
    checkpoint: &WorkspaceWatcherCheckpoint,
) -> Result<(), CliError> {
    if checkpoint.adapter != start.adapter
        || checkpoint.session_id != start.session_id
        || !valid_bounded_opaque(&checkpoint.cursor, 512)
        || checkpoint.continuity_proven && !native_adapter_matches_host(&checkpoint.adapter)
        || checkpoint.continuity_proven && !checkpoint.resume_supported
    {
        return Err(index_error(
            "WORKSPACE_WATCHER_PROOF_INVALID",
            "The watcher adapter returned an invalid or cross-platform continuity checkpoint.",
            "Force reconciliation through the native watcher adapter for this host.",
        ));
    }
    Ok(())
}

fn native_adapter_matches_host(adapter: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        adapter == "linux-inotify"
    }
    #[cfg(target_os = "macos")]
    {
        adapter == "macos-fsevents"
    }
    #[cfg(windows)]
    {
        adapter == "windows-usn"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = adapter;
        false
    }
}

impl GenerationWriter {
    /// Completes every filesystem observation before the watcher authority is
    /// allowed to drain to its final native barrier. Once prepared, baseline
    /// entries can no longer be appended and only watcher events may advance.
    fn prepare_reconciliation(
        &mut self,
        receipt: WorkspaceBaselineReceipt,
    ) -> Result<PreparedGeneration, CliError> {
        if self.reconciliation_prepared {
            return Err(index_invalid());
        }
        validate_baseline_receipt(&receipt, self)?;
        let repository_ignore_digest = receipt.repository_ignore_rules_sha256.clone();
        let local_ignore_digest = ignore_rules_digest(&self.local_ignore_rules)?;
        let ignores = self.write_ignores(receipt.repository_ignore_rules)?;

        let provisional_seal = GenerationSealPayload {
            schema: "ogvcs.workspace-index/generation-seal/v1".to_owned(),
            generation_id: self.generation_id.clone(),
            generation: self.generation,
            entry_count: self.entry_count,
            finding_count: self.finding_count,
            entries: FileSeal {
                name: self.names[0].clone(),
                bytes: self.entries_bytes,
                sha256: String::new(),
                metadata_fingerprint_sha256: String::new(),
            },
            lookup: FileSeal {
                name: self.names[1].clone(),
                bytes: self.lookup_bytes,
                sha256: String::new(),
                metadata_fingerprint_sha256: String::new(),
            },
            findings: FileSeal {
                name: self.names[2].clone(),
                bytes: self.findings_bytes,
                sha256: String::new(),
                metadata_fingerprint_sha256: String::new(),
            },
            ignores: FileSeal {
                name: self.names[3].clone(),
                bytes: self.ignores_bytes,
                sha256: String::new(),
                metadata_fingerprint_sha256: String::new(),
            },
            events_name: self.names[4].clone(),
            ordered_entries_sha256: receipt.ordered_entries_sha256,
            repository_ignore_rules_sha256: repository_ignore_digest,
            local_ignore_rules_sha256: local_ignore_digest,
        };
        append_untracked_findings(self, &provisional_seal, &ignores)?;
        self.reconciliation_prepared = true;
        Ok(PreparedGeneration { provisional_seal })
    }

    fn finish(
        mut self,
        prepared: PreparedGeneration,
        checkpoint: WorkspaceWatcherCheckpoint,
    ) -> Result<WorkspaceIndexReport, CliError> {
        if !self.reconciliation_prepared
            || prepared.provisional_seal.generation_id != self.generation_id
            || prepared.provisional_seal.generation != self.generation
        {
            return Err(index_invalid());
        }
        let provisional_seal = prepared.provisional_seal;
        validate_watcher_checkpoint(
            &WorkspaceWatcherStart {
                adapter: checkpoint.adapter.clone(),
                session_id: checkpoint.session_id.clone(),
                resume_cursor: None,
            },
            &checkpoint,
        )?;

        for file in [
            &self.entries,
            &self.lookup,
            &self.findings,
            &self.ignores,
            &self.events,
        ] {
            file.sync_all().map_err(|_| index_write_unavailable())?;
        }
        if crash_now(CrashPoint::ArtifactsSynced) {
            self.abandoned_for_test = true;
            return Err(injected_crash());
        }

        let seal_payload = GenerationSealPayload {
            finding_count: self.finding_count,
            entries: FileSeal {
                sha256: finalize_hasher(self.entries_hasher.clone()),
                metadata_fingerprint_sha256: artifact_metadata_fingerprint(
                    &self.index.join(&self.names[0]),
                )?,
                ..provisional_seal.entries
            },
            lookup: FileSeal {
                sha256: finalize_hasher(self.lookup_hasher.clone()),
                metadata_fingerprint_sha256: artifact_metadata_fingerprint(
                    &self.index.join(&self.names[1]),
                )?,
                ..provisional_seal.lookup
            },
            findings: FileSeal {
                bytes: self.findings_bytes,
                sha256: finalize_hasher(self.findings_hasher.clone()),
                metadata_fingerprint_sha256: artifact_metadata_fingerprint(
                    &self.index.join(&self.names[2]),
                )?,
                ..provisional_seal.findings
            },
            ignores: FileSeal {
                sha256: finalize_hasher(self.ignores_hasher.clone()),
                metadata_fingerprint_sha256: artifact_metadata_fingerprint(
                    &self.index.join(&self.names[3]),
                )?,
                ..provisional_seal.ignores
            },
            ..provisional_seal
        };
        let (payload, payload_sha256) = payload_wrapper(seal_payload)?;
        let seal = GenerationSeal {
            payload,
            payload_sha256,
        };
        write_json_new(&self.index.join(&self.names[6]), &seal)?;
        sync_directory(&self.index)?;
        if crash_now(CrashPoint::SealSynced) {
            self.abandoned_for_test = true;
            return Err(injected_crash());
        }

        let continuity = checkpoint.continuity_proven;
        let reconciliation_required = !continuity;
        let reason = if continuity {
            "current-native-cursor"
        } else {
            "unsupported-resume"
        };
        let watcher_payload = WatcherStatePayload {
            schema: "ogvcs.workspace-index/watcher-state/v1".to_owned(),
            generation_id: self.generation_id.clone(),
            adapter: checkpoint.adapter,
            session_id: checkpoint.session_id,
            cursor: checkpoint.cursor,
            continuity_proven: continuity,
            resume_supported: checkpoint.resume_supported,
            session_open: continuity,
            reconciliation_required,
            reason: reason.to_owned(),
            event_count: self.event_count,
            event_bytes: self.event_bytes,
            event_tail_sha256: self.event_tail_sha256.clone(),
        };
        let (payload, payload_sha256) = payload_wrapper(watcher_payload)?;
        write_json_atomic(
            &self.index.join(&self.names[5]),
            &WatcherState {
                payload,
                payload_sha256,
            },
        )?;

        let active_payload = ActivePayload {
            schema: WORKSPACE_INDEX_SCHEMA.to_owned(),
            contract_version: WORKSPACE_INDEX_GENERATION_FORMAT_VERSION.to_owned(),
            generation_id: self.generation_id.clone(),
            generation: self.generation,
            generation_seal_sha256: seal.payload_sha256.clone(),
            workspace_id_digest: digest_text(&self.metadata.workspace_id),
            repository_id_hex: self.metadata.binding.repository_id_hex.clone(),
            branch: self.metadata.binding.branch.clone(),
            baseline: self.metadata.binding.baseline.clone(),
            repository_settings_digest: self.metadata.binding.repository_settings_digest.clone(),
            path_profile: self.metadata.binding.path_profile.clone(),
            case_mode: self.metadata.binding.case_mode.clone(),
            created_at_unix_ms: now_unix_ms()?,
        };
        let (payload, payload_sha256) = payload_wrapper(active_payload)?;
        let active = ActiveManifest {
            payload,
            payload_sha256,
        };
        write_json_atomic(&self.index.join("active.json"), &active)?;
        sync_directory(&self.index)?;
        if crash_now(CrashPoint::ActivePublished) {
            self.abandoned_for_test = true;
            return Err(injected_crash());
        }
        retention::observe_active_generation(&self.index, &self.metadata, &active)?;
        fs::remove_file(&self.transition_path).map_err(|_| index_write_unavailable())?;
        sync_directory(&self.index)?;
        self.committed = true;
        Ok(WorkspaceIndexReport {
            schema: WORKSPACE_INDEX_REPORT_SCHEMA,
            generation: self.generation,
            generation_digest: active.payload_sha256,
            baseline_entry_count: self.entry_count,
            initial_finding_count: self.finding_count,
            queued_event_count: self.event_count,
            authoritative_clean: continuity && self.finding_count == 0 && self.event_count == 0,
            reconciliation_required,
            reason: reason.to_owned(),
        })
    }
}

pub fn rebuild_workspace_index(
    request: &WorkspaceIndexBuildRequest,
    provider: &dyn SecureCredentialProvider,
    routes: &mut dyn RepositoryPublicRoutes,
    watcher: &mut dyn WorkspaceWatcherAuthority,
    cancellation: &dyn Cancellation,
    progress: &mut dyn ProgressSink,
) -> Result<WorkspaceIndexReport, CliError> {
    if request.authentication.endpoint.len() > 512
        || request.authentication.profile.is_empty()
        || request.authentication.profile.len() > 64
    {
        return Err(input_error());
    }
    let root = validated_root(&request.root)?;
    let initial_metadata = read_ready_metadata(&root)?;
    let session = provider.invoke(
        &request.authentication,
        routes.authentication_transport(),
        cancellation,
    )?;
    validate_authentication_session(&session)?;
    validate_index_session(&session, &initial_metadata.binding)?;
    routes.validate_binding(&session, &initial_metadata.binding, cancellation)?;
    let watcher_start = watcher.begin_reconciliation(&root, &initial_metadata.binding)?;
    validate_watcher_start(&watcher_start)?;
    cancellation.check("before-workspace-index-lock")?;
    let _lock = MutationLock::acquire(&root)?;
    let metadata = read_ready_metadata(&root)?;
    if json_digest(&metadata)? != json_digest(&initial_metadata)? {
        return Err(index_error(
            "WORKSPACE_INDEX_BINDING_STALE",
            "The verified workspace binding changed during index preflight.",
            "Restart the authenticated index rebuild against the current baseline.",
        ));
    }
    if existing_transition(&root)? {
        return Err(index_recovery_required());
    }
    let mut writer =
        GenerationWriter::begin(&root, metadata.clone(), request.local_ignore_rules.clone())?;
    let receipt = match routes.stream_workspace_baseline(
        &session,
        &metadata.binding,
        &mut writer,
        cancellation,
        progress,
    ) {
        Ok(receipt) => receipt,
        Err(error) => return Err(error),
    };
    cancellation.check("after-workspace-baseline-stream")?;
    let prepared = writer.prepare_reconciliation(receipt)?;
    let checkpoint = watcher.finish_reconciliation(&watcher_start, &mut writer)?;
    validate_watcher_checkpoint(&watcher_start, &checkpoint)?;
    writer.finish(prepared, checkpoint)
}

fn validate_index_session(
    session: &AuthenticationSession,
    binding: &VerifiedBinding,
) -> Result<(), CliError> {
    if session.subject_digest != binding.subject_digest
        || session.authority_epoch != binding.authority_epoch
        || session.security_epoch != binding.security_epoch
    {
        Err(index_error(
            "WORKSPACE_INDEX_AUTHORITY_STALE",
            "The authenticated subject or authority epochs do not match the verified workspace binding.",
            "Reconfigure the workspace through current public authority before rebuilding the index.",
        ))
    } else {
        Ok(())
    }
}

fn existing_transition(root: &Path) -> Result<bool, CliError> {
    let index = checked_index_directory(root)?;
    match fs::symlink_metadata(index.join("transition.json")) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        _ => Err(index_invalid()),
    }
}

fn read_optional_active(index: &Path) -> Result<Option<ActiveManifest>, CliError> {
    let path = index.join("active.json");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {
            let active: ActiveManifest = read_json_private(&path, MAX_CONTROL_BYTES)?;
            validate_wrapped(&active.payload, &active.payload_sha256)?;
            validate_active_shape(&active)?;
            Ok(Some(active))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        _ => Err(index_invalid()),
    }
}

fn validate_active_shape(active: &ActiveManifest) -> Result<(), CliError> {
    let payload = &active.payload;
    if payload.schema != WORKSPACE_INDEX_SCHEMA
        || payload.contract_version != WORKSPACE_INDEX_GENERATION_FORMAT_VERSION
        || !valid_generation_id(&payload.generation_id)
        || payload.generation == 0
        || !valid_digest(&payload.generation_seal_sha256)
        || !valid_digest(&payload.workspace_id_digest)
        || !valid_digest(&payload.repository_settings_digest)
        || payload.created_at_unix_ms == 0
    {
        return Err(index_invalid());
    }
    Ok(())
}

fn load_active(
    root: &Path,
    allow_transition: bool,
) -> Result<
    (
        PathBuf,
        VerifiedWorkspaceMetadata,
        ActiveManifest,
        GenerationSeal,
        WatcherState,
        IgnoreFile,
    ),
    CliError,
> {
    let metadata = read_ready_metadata(root)?;
    let index = existing_index_directory(root)?;
    if !allow_transition
        && (index.join("transition.json").exists() || retention::compaction_pending(&index)?)
    {
        return Err(index_recovery_required());
    }
    let active = read_optional_active(&index)?.ok_or_else(index_invalid)?;
    validate_active_binding(&active, &metadata)?;
    let seal_path = index.join(format!("seal-{}.v1", active.payload.generation_id));
    let seal: GenerationSeal = read_json_private(&seal_path, MAX_CONTROL_BYTES)?;
    validate_wrapped(&seal.payload, &seal.payload_sha256)?;
    if seal.payload_sha256 != active.payload.generation_seal_sha256 {
        return Err(index_invalid());
    }
    validate_seal_quick(&index, &seal)?;
    let watcher: WatcherState = read_json_private(
        &index.join(format!("watcher-{}.v1", active.payload.generation_id)),
        MAX_CONTROL_BYTES,
    )?;
    validate_wrapped(&watcher.payload, &watcher.payload_sha256)?;
    validate_watcher_state(&index, &seal, &watcher)?;
    let ignores: IgnoreFile = read_json_private(
        &index.join(&seal.payload.ignores.name),
        seal.payload.ignores.bytes,
    )?;
    validate_ignore_file(&ignores, &seal.payload, &metadata.binding)?;
    Ok((index, metadata, active, seal, watcher, ignores))
}

fn validate_active_binding(
    active: &ActiveManifest,
    metadata: &VerifiedWorkspaceMetadata,
) -> Result<(), CliError> {
    let binding = &metadata.binding;
    if active.payload.workspace_id_digest != digest_text(&metadata.workspace_id)
        || active.payload.repository_id_hex != binding.repository_id_hex
        || active.payload.branch != binding.branch
        || active.payload.baseline != binding.baseline
        || active.payload.repository_settings_digest != binding.repository_settings_digest
        || active.payload.path_profile != binding.path_profile
        || active.payload.case_mode != binding.case_mode
    {
        return Err(index_error(
            "WORKSPACE_INDEX_BINDING_STALE",
            "The active index is not bound to the current workspace baseline and path settings.",
            "Rebuild the index from the current authenticated baseline.",
        ));
    }
    Ok(())
}

fn validate_seal_quick(index: &Path, seal: &GenerationSeal) -> Result<(), CliError> {
    let payload = &seal.payload;
    if payload.schema != "ogvcs.workspace-index/generation-seal/v1"
        || !valid_generation_id(&payload.generation_id)
        || payload.generation == 0
        || payload.entry_count == 0
        || payload.entry_count > MAX_BASELINE_ENTRIES
        || payload.finding_count > MAX_BASELINE_ENTRIES
        || payload.lookup.bytes
            != payload
                .entry_count
                .checked_mul(LOOKUP_RECORD_BYTES)
                .ok_or_else(index_invalid)?
        || payload.ordered_entries_sha256.len() != 64
        || !valid_digest(&payload.ordered_entries_sha256)
        || !valid_digest(&payload.repository_ignore_rules_sha256)
        || !valid_digest(&payload.local_ignore_rules_sha256)
        || !valid_artifact_name(&payload.events_name)
    {
        return Err(index_invalid());
    }
    let expected = artifact_names(&payload.generation_id);
    if payload.entries.name != expected[0]
        || payload.lookup.name != expected[1]
        || payload.findings.name != expected[2]
        || payload.ignores.name != expected[3]
        || payload.events_name != expected[4]
    {
        return Err(index_invalid());
    }
    for artifact in [
        &payload.entries,
        &payload.lookup,
        &payload.findings,
        &payload.ignores,
    ] {
        if !valid_digest(&artifact.sha256)
            || !valid_digest(&artifact.metadata_fingerprint_sha256)
            || artifact_metadata_fingerprint(&index.join(&artifact.name))?
                != artifact.metadata_fingerprint_sha256
            || fs::symlink_metadata(index.join(&artifact.name))
                .ok()
                .filter(|metadata| !is_link_or_reparse(metadata) && metadata.is_file())
                .is_none_or(|metadata| metadata.len() != artifact.bytes)
        {
            return Err(index_invalid());
        }
    }
    let events =
        fs::symlink_metadata(index.join(&payload.events_name)).map_err(|_| index_invalid())?;
    if is_link_or_reparse(&events) || !events.is_file() {
        return Err(index_invalid());
    }
    Ok(())
}

fn validate_watcher_state(
    index: &Path,
    seal: &GenerationSeal,
    state: &WatcherState,
) -> Result<(), CliError> {
    let payload = &state.payload;
    if payload.schema != "ogvcs.workspace-index/watcher-state/v1"
        || payload.generation_id != seal.payload.generation_id
        || !valid_bounded_opaque(&payload.adapter, 64)
        || !valid_bounded_opaque(&payload.session_id, 128)
        || !valid_bounded_opaque(&payload.cursor, 512)
        || !valid_digest(&payload.event_tail_sha256)
        || payload.event_count > MAX_WATCH_EVENTS
        || payload.event_bytes > MAX_EVENTS_BYTES
        || !watcher_liveness_shape_is_coherent(payload)
        || (watcher_state_is_authoritative(payload)
            && !native_adapter_matches_host(&payload.adapter))
    {
        return Err(index_invalid());
    }
    let metadata =
        fs::symlink_metadata(index.join(&seal.payload.events_name)).map_err(|_| index_invalid())?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() || metadata.len() != payload.event_bytes
    {
        return Err(index_invalid());
    }
    Ok(())
}

fn watcher_state_is_authoritative(payload: &WatcherStatePayload) -> bool {
    payload.continuity_proven
        && payload.resume_supported
        && payload.session_open
        && !payload.reconciliation_required
}

fn watcher_liveness_shape_is_coherent(payload: &WatcherStatePayload) -> bool {
    watcher_state_is_authoritative(payload)
        || (!payload.continuity_proven && !payload.session_open && payload.reconciliation_required)
}

fn validate_ignore_file(
    ignores: &IgnoreFile,
    seal: &GenerationSealPayload,
    binding: &VerifiedBinding,
) -> Result<(), CliError> {
    if ignores.schema != "ogvcs.workspace-index/ignore-rules/v1"
        || ignore_rules_digest(&ignores.repository_rules)? != seal.repository_ignore_rules_sha256
        || ignore_rules_digest(&ignores.local_rules)? != seal.local_ignore_rules_sha256
    {
        return Err(index_invalid());
    }
    validate_ignore_rules(&ignores.repository_rules, IgnoreSource::Repository, binding)?;
    validate_ignore_rules(&ignores.local_rules, IgnoreSource::Local, binding)
}

fn hash_file(path: &Path) -> Result<String, CliError> {
    let mut file = open_private_file(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| index_invalid())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(finalize_hasher(hasher))
}

pub fn verify_workspace_index(root: &Path) -> Result<WorkspaceIndexReport, CliError> {
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    let (index, _, active, seal, watcher, _) = load_active(&root, false)?;
    verify_loaded_workspace_index(&index, &active, &seal, &watcher)
}

fn verify_loaded_workspace_index(
    index: &Path,
    active: &ActiveManifest,
    seal: &GenerationSeal,
    watcher: &WatcherState,
) -> Result<WorkspaceIndexReport, CliError> {
    let _ = read_cursor_key(index)?;
    for artifact in [
        &seal.payload.entries,
        &seal.payload.lookup,
        &seal.payload.findings,
        &seal.payload.ignores,
    ] {
        if hash_file(&index.join(&artifact.name))? != artifact.sha256 {
            return Err(index_invalid());
        }
    }
    validate_lookup_order(index, &seal.payload)?;
    validate_watch_records(index, &seal.payload, &watcher.payload)?;
    Ok(report_from_loaded(active, seal, watcher))
}

fn validate_lookup_order(index: &Path, seal: &GenerationSealPayload) -> Result<(), CliError> {
    let mut lookup = open_private_file(&index.join(&seal.lookup.name))?;
    let mut previous: Option<[u8; 32]> = None;
    for _ in 0..seal.entry_count {
        let mut record = [0u8; LOOKUP_RECORD_BYTES as usize];
        lookup
            .read_exact(&mut record)
            .map_err(|_| index_invalid())?;
        let current: [u8; 32] = record[..32].try_into().map_err(|_| index_invalid())?;
        if previous.is_some_and(|value| value > current) {
            return Err(index_invalid());
        }
        previous = Some(current);
    }
    let mut extra = [0u8; 1];
    if lookup.read(&mut extra).map_err(|_| index_invalid())? != 0 {
        return Err(index_invalid());
    }
    Ok(())
}

fn validate_watch_records(
    index: &Path,
    seal: &GenerationSealPayload,
    state: &WatcherStatePayload,
) -> Result<Vec<WatchRecord>, CliError> {
    let file = open_private_file(&index.join(&seal.events_name))?;
    let reader = BufReader::new(file);
    let mut records = Vec::with_capacity(usize::try_from(state.event_count).unwrap_or(0));
    let mut previous = EMPTY_SHA256.to_owned();
    let mut bytes = 0u64;
    for (ordinal, result) in reader.split(b'\n').enumerate() {
        let mut line = result.map_err(|_| index_invalid())?;
        if line.is_empty() && ordinal as u64 == state.event_count {
            continue;
        }
        if line.len() > MAX_EVENT_BYTES {
            return Err(index_invalid());
        }
        line.push(b'\n');
        bytes = bytes
            .checked_add(u64::try_from(line.len()).map_err(|_| index_invalid())?)
            .ok_or_else(index_invalid)?;
        line.pop();
        let record: WatchRecord = serde_json::from_slice(&line).map_err(|_| index_invalid())?;
        if record.core.sequence != ordinal as u64 + 1 || record.core.previous_sha256 != previous {
            return Err(index_invalid());
        }
        validate_watch_record_digest(&record)?;
        previous = record.record_sha256.clone();
        records.push(record);
    }
    if records.len() as u64 != state.event_count
        || bytes != state.event_bytes
        || previous != state.event_tail_sha256
    {
        return Err(index_invalid());
    }
    Ok(records)
}

fn validate_watch_record_digest(record: &WatchRecord) -> Result<(), CliError> {
    let core = serde_json::to_vec(&record.core).map_err(|_| index_invalid())?;
    let mut hasher = Sha256::new();
    hasher.update(WATCH_RECORD_DOMAIN);
    hasher.update(
        u64::try_from(core.len())
            .map_err(|_| index_invalid())?
            .to_be_bytes(),
    );
    hasher.update(core);
    if finalize_hasher(hasher) != record.record_sha256 {
        return Err(index_invalid());
    }
    Ok(())
}

fn report_from_loaded(
    active: &ActiveManifest,
    seal: &GenerationSeal,
    watcher: &WatcherState,
) -> WorkspaceIndexReport {
    let complete = watcher_state_is_authoritative(&watcher.payload);
    WorkspaceIndexReport {
        schema: WORKSPACE_INDEX_REPORT_SCHEMA,
        generation: active.payload.generation,
        generation_digest: active.payload_sha256.clone(),
        baseline_entry_count: seal.payload.entry_count,
        initial_finding_count: seal.payload.finding_count,
        queued_event_count: watcher.payload.event_count,
        authoritative_clean: complete
            && seal.payload.finding_count == 0
            && watcher.payload.event_count == 0,
        reconciliation_required: watcher.payload.reconciliation_required,
        reason: watcher.payload.reason.clone(),
    }
}

fn revalidate_status_snapshot(
    root: &Path,
    snapshot: &StatusSnapshotIdentity<'_>,
    watcher: &mut WatcherState,
    authority: &mut dyn WorkspaceWatcherAuthority,
) -> Result<(), CliError> {
    let _lock = MutationLock::acquire(root)?;
    let (current_index, current_metadata, current_active, current_seal, mut current_watcher, _) =
        load_active(root, false)?;
    if current_index != snapshot.index
        || json_digest(&current_metadata)? != json_digest(snapshot.metadata)?
        || current_seal.payload_sha256 != snapshot.seal.payload_sha256
    {
        return Err(index_error(
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED",
            "The workspace-index authority changed while status was being classified.",
            "Restart status from its first page against the current sealed generation.",
        ));
    }
    if current_active.payload.generation != snapshot.active.payload.generation
        || current_active.payload.generation_id != snapshot.active.payload.generation_id
        || current_active.payload_sha256 != snapshot.active.payload_sha256
    {
        return Err(index_error(
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED",
            "The active workspace-index generation changed while status was being classified.",
            "Restart status from its first page against the new sealed generation.",
        ));
    }
    if current_watcher.payload_sha256 != watcher.payload_sha256
        || current_watcher.payload.event_count != watcher.payload.event_count
        || current_watcher.payload.event_bytes != watcher.payload.event_bytes
        || current_watcher.payload.event_tail_sha256 != watcher.payload.event_tail_sha256
    {
        return Err(index_error(
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED",
            "The durable watcher journal changed while status was being classified.",
            "Restart status from its first page against the current watcher cursor.",
        ));
    }
    let current_staging = read_validated_staging_snapshot(root, &current_metadata.binding)?;
    if current_staging.state.generation != snapshot.staging_generation
        || current_staging.state_sha256 != snapshot.staging_state_sha256
    {
        return Err(index_error(
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED",
            "The durable staging snapshot changed while status was being classified.",
            "Restart status from its first page against the current staging journal.",
        ));
    }
    fence_status_locked(
        root,
        snapshot.index,
        &current_metadata,
        &current_active,
        &current_seal,
        &mut current_watcher,
        authority,
    )?;
    validate_watcher_state(snapshot.index, &current_seal, &current_watcher)?;
    if current_watcher.payload.event_count != watcher.payload.event_count
        || current_watcher.payload.event_bytes != watcher.payload.event_bytes
        || current_watcher.payload.event_tail_sha256 != watcher.payload.event_tail_sha256
    {
        return Err(index_error(
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED",
            "The final native watcher barrier drained a change after status classification began.",
            "Restart status from its first page against the newly journaled watcher transcript.",
        ));
    }
    let final_staging = read_validated_staging_snapshot(root, &current_metadata.binding)?;
    if final_staging.state.generation != snapshot.staging_generation
        || final_staging.state_sha256 != snapshot.staging_state_sha256
    {
        return Err(index_error(
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED",
            "The durable staging snapshot changed before the final watcher barrier completed.",
            "Restart status from its first page against the current staging journal.",
        ));
    }
    // A trusted native authority may advance a volume-global cursor without
    // yielding a repository event. The transcript remains the classified
    // snapshot, so bind the returned page to this exact final cursor/payload.
    // Cursor decoding accepts that authenticated prior cursor only while the
    // generation, staging/filter inputs, watcher authority, and complete event
    // transcript remain exact; this prevents idle advances from livelocking
    // pagination without admitting a missed repository event.
    *watcher = current_watcher;
    Ok(())
}

fn open_events_append(path: &Path) -> Result<File, CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| index_invalid())?;
    if is_link_or_reparse(&metadata) || !metadata.is_file() {
        return Err(index_invalid());
    }
    let mut options = OpenOptions::new();
    options.append(true);
    #[cfg(not(windows))]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    #[cfg(windows)]
    options.custom_flags(0x0020_0000);
    let file = options.open(path).map_err(|_| index_invalid())?;
    let opened = file.metadata().map_err(|_| index_invalid())?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(index_invalid());
    }
    Ok(file)
}

pub fn record_workspace_change_batch(
    root: &Path,
    batch: &WorkspaceWatchBatch,
) -> Result<WorkspaceIndexReport, CliError> {
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    let (index, metadata, active, seal, mut watcher, _) = load_active(&root, false)?;
    append_watch_batch_locked(&index, &metadata, &active, &seal, &mut watcher, batch)?;
    Ok(report_from_loaded(&active, &seal, &watcher))
}

fn append_watch_batch_locked(
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
    seal: &GenerationSeal,
    watcher: &mut WatcherState,
    batch: &WorkspaceWatchBatch,
) -> Result<(), CliError> {
    if !valid_bounded_opaque(&batch.session_id, 128)
        || !valid_bounded_opaque(&batch.prior_cursor, 512)
        || !valid_bounded_opaque(&batch.cursor, 512)
        || batch.cursor == batch.prior_cursor
    {
        return Err(input_error());
    }
    validate_watch_chunk(&batch.events, &metadata.binding)?;
    if !watcher.payload.session_open
        || watcher.payload.session_id != batch.session_id
        || watcher.payload.cursor != batch.prior_cursor
    {
        persist_degraded_state(index, watcher, "cursor-gap", true)?;
        return Err(index_error(
            "WORKSPACE_WATCHER_CURSOR_GAP",
            "The watcher cursor or session does not continue the durable journal.",
            "Force a full workspace reconciliation before reporting clean status.",
        ));
    }
    let count = watcher
        .payload
        .event_count
        .checked_add(u64::try_from(batch.events.len()).map_err(|_| internal_error())?)
        .ok_or_else(index_invalid)?;
    let encoded = encode_watch_records(
        &batch.events,
        watcher.payload.event_count,
        &watcher.payload.event_tail_sha256,
    )?;
    let bytes = watcher
        .payload
        .event_bytes
        .checked_add(
            u64::try_from(encoded.iter().map(|(_, line)| line.len()).sum::<usize>())
                .map_err(|_| internal_error())?,
        )
        .ok_or_else(index_invalid)?;
    if count > MAX_WATCH_EVENTS || bytes > MAX_EVENTS_BYTES {
        persist_degraded_state(index, watcher, "overflow", true)?;
        return Err(index_limit("WORKSPACE_WATCH_EVENT_LIMIT"));
    }
    let events_path = index.join(&seal.payload.events_name);
    let mut events = open_events_append(&events_path)?;
    for (_, line) in &encoded {
        events
            .write_all(line)
            .map_err(|_| index_write_unavailable())?;
    }
    events.sync_all().map_err(|_| index_write_unavailable())?;
    if journal_state_fault_now() {
        return Err(index_error(
            "WORKSPACE_WATCHER_INJECTED_STATE_FAULT",
            "The test interrupted watcher publication after the journal sync.",
            "Force authenticated reconciliation; the appended tail must not be ignored.",
        ));
    }
    watcher.payload.event_count = count;
    watcher.payload.event_bytes = bytes;
    watcher.payload.event_tail_sha256 = encoded
        .last()
        .map(|(digest, _)| digest.clone())
        .unwrap_or_else(|| watcher.payload.event_tail_sha256.clone());
    watcher.payload.cursor = batch.cursor.clone();
    watcher.payload.reason = "journaled-change".to_owned();
    watcher.payload_sha256 = json_digest(&watcher.payload)?;
    write_json_atomic(
        &index.join(format!("watcher-{}.v1", active.payload.generation_id)),
        &watcher,
    )?;
    sync_directory(index)?;
    Ok(())
}

struct StatusFenceSink<'a> {
    index: &'a Path,
    metadata: &'a VerifiedWorkspaceMetadata,
    active: &'a ActiveManifest,
    seal: &'a GenerationSeal,
    watcher: &'a mut WatcherState,
}

impl WorkspaceWatchBatchSink for StatusFenceSink<'_> {
    fn append_watch_batch(&mut self, batch: &WorkspaceWatchBatch) -> Result<(), CliError> {
        append_watch_batch_locked(
            self.index,
            self.metadata,
            self.active,
            self.seal,
            self.watcher,
            batch,
        )
    }
}

fn encode_watch_records(
    events: &[WorkspaceWatchEvent],
    starting_sequence: u64,
    starting_digest: &str,
) -> Result<Vec<(String, Vec<u8>)>, CliError> {
    let mut encoded = Vec::with_capacity(events.len());
    let mut sequence = starting_sequence;
    let mut previous = starting_digest.to_owned();
    let mut total = 0usize;
    for event in events {
        sequence = sequence.checked_add(1).ok_or_else(index_invalid)?;
        let core = WatchRecordCore {
            sequence,
            event: event.clone(),
            previous_sha256: previous,
        };
        let core_bytes = serde_json::to_vec(&core).map_err(|_| internal_error())?;
        let mut hasher = Sha256::new();
        hasher.update(WATCH_RECORD_DOMAIN);
        hasher.update(
            u64::try_from(core_bytes.len())
                .map_err(|_| internal_error())?
                .to_be_bytes(),
        );
        hasher.update(core_bytes);
        let digest = finalize_hasher(hasher);
        let record = WatchRecord {
            core,
            record_sha256: digest.clone(),
        };
        let mut line = serde_json::to_vec(&record).map_err(|_| internal_error())?;
        if line.len() > MAX_EVENT_BYTES {
            return Err(index_limit("WORKSPACE_WATCH_EVENT_BYTES"));
        }
        line.push(b'\n');
        total = total
            .checked_add(line.len())
            .ok_or_else(|| index_limit("WORKSPACE_WATCH_CHUNK_BYTES"))?;
        if total > MAX_WATCH_CHUNK_BYTES {
            return Err(index_limit("WORKSPACE_WATCH_CHUNK_BYTES"));
        }
        previous = digest.clone();
        encoded.push((digest, line));
    }
    Ok(encoded)
}

fn persist_degraded_state(
    index: &Path,
    watcher: &mut WatcherState,
    reason: &str,
    close_session: bool,
) -> Result<(), CliError> {
    watcher.payload.continuity_proven = false;
    watcher.payload.reconciliation_required = true;
    watcher.payload.reason = reason.to_owned();
    if close_session {
        watcher.payload.session_open = false;
    }
    watcher.payload_sha256 = json_digest(&watcher.payload)?;
    write_json_atomic(
        &index.join(format!("watcher-{}.v1", watcher.payload.generation_id)),
        watcher,
    )?;
    sync_directory(index)
}

#[derive(Clone)]
struct StatusCandidate {
    path: String,
    prior_path: Option<String>,
    hint: WorkspaceStatus,
    event_kind: Option<WorkspaceWatchEventKind>,
    saw_created: bool,
    saw_deleted: bool,
    staged_file_id: Option<String>,
}

fn bounded_status_candidate(
    candidates: &mut BTreeMap<(String, String), StatusCandidate>,
    key: (String, String),
    candidate: StatusCandidate,
    limit: usize,
) -> Result<&mut StatusCandidate, CliError> {
    if !candidates.contains_key(&key) && candidates.len() >= limit {
        return Err(index_invalid());
    }
    Ok(candidates.entry(key).or_insert(candidate))
}

fn bounded_replace_status_candidate(
    candidates: &mut BTreeMap<(String, String), StatusCandidate>,
    key: (String, String),
    candidate: StatusCandidate,
    limit: usize,
) -> Result<(), CliError> {
    if !candidates.contains_key(&key) && candidates.len() >= limit {
        return Err(index_invalid());
    }
    candidates.insert(key, candidate);
    Ok(())
}

struct ValidatedStagingSnapshot {
    state: super::StagingState,
    state_sha256: String,
}

struct StatusSnapshotIdentity<'a> {
    index: &'a Path,
    metadata: &'a VerifiedWorkspaceMetadata,
    active: &'a ActiveManifest,
    seal: &'a GenerationSeal,
    staging_generation: u64,
    staging_state_sha256: &'a str,
}

struct StatusCursorContext<'a> {
    active: &'a ActiveManifest,
    seal: &'a GenerationSealPayload,
    watcher: &'a WatcherState,
    staging_generation: u64,
    staging_state_sha256: &'a str,
    binding: &'a VerifiedBinding,
    filter_sha256: &'a str,
}

fn read_validated_staging_snapshot(
    root: &Path,
    binding: &VerifiedBinding,
) -> Result<ValidatedStagingSnapshot, CliError> {
    let state = super::read_staging_state(root)?;
    for intent in &state.intents {
        super::validate_intent(intent, binding)?;
        if intent.state != super::IntentState::Applied {
            return Err(index_recovery_required());
        }
    }
    let state_sha256 = json_digest(&state)?;
    Ok(ValidatedStagingSnapshot {
        state,
        state_sha256,
    })
}

fn persist_status_checkpoint(
    index: &Path,
    watcher: &mut WatcherState,
    checkpoint: WorkspaceWatcherCheckpoint,
) -> Result<(), CliError> {
    watcher.payload.adapter = checkpoint.adapter;
    watcher.payload.session_id = checkpoint.session_id;
    watcher.payload.cursor = checkpoint.cursor;
    watcher.payload.continuity_proven = true;
    watcher.payload.resume_supported = true;
    watcher.payload.session_open = true;
    watcher.payload.reconciliation_required = false;
    watcher.payload.reason = "current-native-cursor".to_owned();
    watcher.payload_sha256 = json_digest(&watcher.payload)?;
    write_json_atomic(
        &index.join(format!("watcher-{}.v1", watcher.payload.generation_id)),
        watcher,
    )?;
    sync_directory(index)
}

fn fence_status_locked(
    root: &Path,
    index: &Path,
    metadata: &VerifiedWorkspaceMetadata,
    active: &ActiveManifest,
    seal: &GenerationSeal,
    watcher: &mut WatcherState,
    authority: &mut dyn WorkspaceWatcherAuthority,
) -> Result<(), CliError> {
    if !watcher_state_is_authoritative(&watcher.payload) {
        return Ok(());
    }
    let start = WorkspaceWatcherStart {
        adapter: watcher.payload.adapter.clone(),
        session_id: watcher.payload.session_id.clone(),
        resume_cursor: Some(watcher.payload.cursor.clone()),
    };
    validate_watcher_start(&start)?;
    let result = {
        let mut sink = StatusFenceSink {
            index,
            metadata,
            active,
            seal,
            watcher,
        };
        authority.fence_status(root, &metadata.binding, &start, &mut sink)
    };
    match result {
        Ok(checkpoint) => match validate_watcher_checkpoint(&start, &checkpoint) {
            Ok(()) if checkpoint.continuity_proven && checkpoint.resume_supported => {
                persist_status_checkpoint(index, watcher, checkpoint)
            }
            Ok(()) => persist_degraded_state(index, watcher, "status-fence-unavailable", true),
            Err(_) => persist_degraded_state(index, watcher, "status-fence-invalid", true),
        },
        Err(_) if watcher.payload.reconciliation_required && !watcher.payload.session_open => {
            Ok(())
        }
        Err(_) => persist_degraded_state(index, watcher, "status-fence-failed", true),
    }
}

pub fn workspace_status_page(
    request: &WorkspaceStatusPageRequest,
) -> Result<WorkspaceStatusPage, CliError> {
    let mut watcher = UnavailableWorkspaceWatcher;
    workspace_status_page_fenced(request, &mut watcher)
}

fn workspace_status_page_fenced(
    request: &WorkspaceStatusPageRequest,
    watcher_authority: &mut dyn WorkspaceWatcherAuthority,
) -> Result<WorkspaceStatusPage, CliError> {
    if request.limit == 0 || request.limit > MAX_STATUS_PAGE_ITEMS {
        return Err(input_error());
    }
    let root = validated_root(&request.root)?;
    // A published transition means a writer has already stopped admitting
    // events to the old generation.  Serving that generation here could
    // therefore declare a concurrently changed workspace clean.  Status is
    // deliberately unavailable until recovery removes the transition or the
    // new sealed generation becomes active.
    let (index, metadata, active, seal, mut watcher, ignores, staging, _lease) = {
        let _lock = MutationLock::acquire(&root)?;
        let (index, metadata, active, seal, mut watcher, ignores) = load_active(&root, false)?;
        // This is the sole active-generation writer lease for the fence. Every
        // appended batch is journal-sync/state-published under MutationLock,
        // and pre-existing readers detect it through final payload revalidation.
        fence_status_locked(
            &root,
            &index,
            &metadata,
            &active,
            &seal,
            &mut watcher,
            watcher_authority,
        )?;
        let staging = read_validated_staging_snapshot(&root, &metadata.binding)?;
        let lease = retention::acquire_generation_read_lease(&index, &metadata, &active)?;
        (
            index, metadata, active, seal, watcher, ignores, staging, lease,
        )
    };
    let snapshot = StatusSnapshotIdentity {
        index: &index,
        metadata: &metadata,
        active: &active,
        seal: &seal,
        staging_generation: staging.state.generation,
        staging_state_sha256: &staging.state_sha256,
    };
    status_after_load_hook(&index);
    let cursor_key = read_cursor_key(&index)?;
    let filter_sha256 = json_digest(&request.filter)?;
    let after_key = {
        let context = StatusCursorContext {
            active: &active,
            seal: &seal.payload,
            watcher: &watcher,
            staging_generation: staging.state.generation,
            staging_state_sha256: &staging.state_sha256,
            binding: &metadata.binding,
            filter_sha256: &filter_sha256,
        };
        request
            .cursor
            .as_deref()
            .map(|cursor| decode_status_cursor(cursor, &context, &cursor_key))
            .transpose()?
    };
    let mut complete = watcher_state_is_authoritative(&watcher.payload);
    let mut reason = watcher.payload.reason.clone();
    if seal.payload.finding_count == 0
        && watcher.payload.event_count == 0
        && staging.state.intents.is_empty()
    {
        revalidate_status_snapshot(&root, &snapshot, &mut watcher, watcher_authority)?;
        complete = watcher_state_is_authoritative(&watcher.payload);
        reason = watcher.payload.reason.clone();
        return Ok(WorkspaceStatusPage {
            schema: WORKSPACE_STATUS_SCHEMA,
            generation: active.payload.generation,
            complete,
            authoritative_clean: complete,
            reconciliation_required: !complete,
            reason,
            candidate_count: 0,
            status_counts: BTreeMap::new(),
            items: Vec::new(),
            next_cursor: None,
        });
    }
    let mut candidates: BTreeMap<(String, String), StatusCandidate> = BTreeMap::new();
    read_findings(&index, &seal.payload, &metadata.binding, &mut candidates)?;
    let records = validate_watch_records(&index, &seal.payload, &watcher.payload)?;
    for record in records {
        merge_event_candidate(&metadata.binding, &mut candidates, &record.core.event)?;
    }
    if candidates.len() > MAX_STATUS_CANDIDATES {
        return Err(index_invalid());
    }
    merge_staged_candidates(&metadata.binding, &mut candidates, &staging.state)?;
    if candidates.len() > MAX_STATUS_CANDIDATES {
        return Err(index_invalid());
    }
    let mut lookup = LookupReader::open(&index, &seal.payload)?;
    let mut status_counts = BTreeMap::new();
    let mut items = Vec::with_capacity(request.limit);
    let mut total = 0u64;
    let mut has_more = false;
    for (sort_key, candidate) in candidates {
        let classified =
            classify_status_candidate(&root, &metadata.binding, &ignores, &mut lookup, candidate)?;
        if classified.requires_reconciliation {
            complete = false;
            reason = "deleted-path-descendants-unproven".to_owned();
        }
        let Some(item) = classified.item else {
            continue;
        };
        if (!request.filter.include_ignored && item.status == WorkspaceStatus::Ignored)
            || (!request.filter.include_materialization_state
                && matches!(
                    item.status,
                    WorkspaceStatus::MetadataOnly | WorkspaceStatus::AbsentBySpec
                ))
        {
            continue;
        }
        total = total.checked_add(1).ok_or_else(index_invalid)?;
        *status_counts
            .entry(item.status.as_str().to_owned())
            .or_insert(0) += 1;
        if after_key.as_ref().is_some_and(|after| &sort_key <= after) {
            continue;
        }
        if items.len() < request.limit {
            items.push(item);
        } else {
            has_more = true;
        }
    }
    revalidate_status_snapshot(&root, &snapshot, &mut watcher, watcher_authority)?;
    if !watcher_state_is_authoritative(&watcher.payload) {
        complete = false;
        reason = watcher.payload.reason.clone();
    }
    let next_cursor = if has_more {
        items
            .last()
            .map(|item| {
                encode_status_cursor(
                    &StatusCursorContext {
                        active: &active,
                        seal: &seal.payload,
                        watcher: &watcher,
                        staging_generation: staging.state.generation,
                        staging_state_sha256: &staging.state_sha256,
                        binding: &metadata.binding,
                        filter_sha256: &filter_sha256,
                    },
                    &item.repository_path,
                    &cursor_key,
                )
            })
            .transpose()?
    } else {
        None
    };
    Ok(WorkspaceStatusPage {
        schema: WORKSPACE_STATUS_SCHEMA,
        generation: active.payload.generation,
        complete,
        authoritative_clean: complete && total == 0,
        reconciliation_required: !complete,
        reason,
        candidate_count: total,
        status_counts,
        items,
        next_cursor,
    })
}

fn watcher_cursor_authority_digest(watcher: &WatcherState) -> Result<String, CliError> {
    json_digest(&WatcherCursorAuthorityBinding {
        schema: "ogvcs.workspace-index/status-cursor-watcher-authority/v1",
        generation_id: &watcher.payload.generation_id,
        adapter: &watcher.payload.adapter,
        session_id: &watcher.payload.session_id,
        continuity_proven: watcher.payload.continuity_proven,
        resume_supported: watcher.payload.resume_supported,
        session_open: watcher.payload.session_open,
        reconciliation_required: watcher.payload.reconciliation_required,
        reason: &watcher.payload.reason,
    })
}

fn encode_status_cursor(
    context: &StatusCursorContext<'_>,
    after_path: &str,
    key: &[u8; 32],
) -> Result<String, CliError> {
    let (after_platform_key, _) = status_sort_key(after_path, context.binding)?;
    let payload = StatusCursorPayload {
        schema: "ogvcs.workspace-index/status-cursor/v2".to_owned(),
        generation_id: context.active.payload.generation_id.clone(),
        active_sha256: context.active.payload_sha256.clone(),
        watcher_payload_sha256: context.watcher.payload_sha256.clone(),
        watcher_cursor: context.watcher.payload.cursor.clone(),
        watcher_authority_sha256: watcher_cursor_authority_digest(context.watcher)?,
        watcher_event_count: context.watcher.payload.event_count,
        watcher_event_bytes: context.watcher.payload.event_bytes,
        watcher_event_tail_sha256: context.watcher.payload.event_tail_sha256.clone(),
        staging_generation: context.staging_generation,
        staging_state_sha256: context.staging_state_sha256.to_owned(),
        repository_settings_digest: context.binding.repository_settings_digest.clone(),
        path_profile: context.binding.path_profile.clone(),
        case_mode: context.binding.case_mode.clone(),
        repository_ignore_rules_sha256: context.seal.repository_ignore_rules_sha256.clone(),
        local_ignore_rules_sha256: context.seal.local_ignore_rules_sha256.clone(),
        filter_sha256: context.filter_sha256.to_owned(),
        after_repository_path: after_path.to_owned(),
        after_platform_key,
    };
    let payload_bytes = serde_json::to_vec(&payload).map_err(|_| internal_error())?;
    let mac_sha256 = hmac_sha256(key, &payload_bytes);
    let bytes = serde_json::to_vec(&StatusCursor {
        payload,
        mac_sha256,
    })
    .map_err(|_| internal_error())?;
    Ok(hex_bytes(&bytes))
}

fn decode_status_cursor(
    encoded: &str,
    context: &StatusCursorContext<'_>,
    key: &[u8; 32],
) -> Result<(String, String), CliError> {
    if encoded.is_empty() || encoded.len() > 32 * 1024 || encoded.len() % 2 != 0 {
        return Err(input_error());
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(input_error)?;
        let low = hex_nibble(pair[1]).ok_or_else(input_error)?;
        bytes.push((high << 4) | low);
    }
    let cursor: StatusCursor = serde_json::from_slice(&bytes).map_err(|_| input_error())?;
    let payload_bytes = serde_json::to_vec(&cursor.payload).map_err(|_| input_error())?;
    if !valid_digest(&cursor.mac_sha256)
        || !constant_time_digest_eq(&cursor.mac_sha256, &hmac_sha256(key, &payload_bytes))
    {
        return Err(input_error());
    }
    let expected_key = status_sort_key(&cursor.payload.after_repository_path, context.binding)?;
    let watcher_authority_sha256 = watcher_cursor_authority_digest(context.watcher)?;
    if cursor.payload.schema != "ogvcs.workspace-index/status-cursor/v2"
        || cursor.payload.generation_id != context.active.payload.generation_id
        || cursor.payload.active_sha256 != context.active.payload_sha256
        || !valid_digest(&cursor.payload.watcher_payload_sha256)
        || !valid_bounded_opaque(&cursor.payload.watcher_cursor, 512)
        || !valid_digest(&cursor.payload.watcher_authority_sha256)
        || cursor.payload.watcher_authority_sha256 != watcher_authority_sha256
        || cursor.payload.watcher_event_count != context.watcher.payload.event_count
        || cursor.payload.watcher_event_bytes != context.watcher.payload.event_bytes
        || cursor.payload.watcher_event_tail_sha256 != context.watcher.payload.event_tail_sha256
        || cursor.payload.staging_generation != context.staging_generation
        || cursor.payload.staging_state_sha256 != context.staging_state_sha256
        || cursor.payload.repository_settings_digest != context.binding.repository_settings_digest
        || cursor.payload.path_profile != context.binding.path_profile
        || cursor.payload.case_mode != context.binding.case_mode
        || cursor.payload.repository_ignore_rules_sha256
            != context.seal.repository_ignore_rules_sha256
        || cursor.payload.local_ignore_rules_sha256 != context.seal.local_ignore_rules_sha256
        || cursor.payload.filter_sha256 != context.filter_sha256
        || cursor.payload.after_platform_key != expected_key.0
    {
        return Err(index_error(
            "WORKSPACE_STATUS_CURSOR_STALE",
            "The status cursor does not bind the current generation, watcher transcript, staging snapshot, settings, and filter.",
            "Restart status paging from the first page.",
        ));
    }
    Ok(expected_key)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn status_sort_key(path: &str, binding: &VerifiedBinding) -> Result<(String, String), CliError> {
    let keys = path_collision_keys(path, &binding.path_profile, &binding.case_mode)
        .map_err(|_| input_error())?;
    Ok((keys.platform_key().to_owned(), path.to_owned()))
}

fn read_findings(
    index: &Path,
    seal: &GenerationSealPayload,
    binding: &VerifiedBinding,
    candidates: &mut BTreeMap<(String, String), StatusCandidate>,
) -> Result<(), CliError> {
    let file = open_private_file(&index.join(&seal.findings.name))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut count = 0u64;
    while reader
        .read_until(b'\n', &mut line)
        .map_err(|_| index_invalid())?
        != 0
    {
        if line.last() != Some(&b'\n') || line.len() > MAX_FINDING_BYTES + 1 {
            return Err(index_invalid());
        }
        line.pop();
        let finding: FindingDisk = serde_json::from_slice(&line).map_err(|_| index_invalid())?;
        let key = status_sort_key(&finding.repository_path, binding)?;
        bounded_replace_status_candidate(
            candidates,
            key,
            StatusCandidate {
                path: finding.repository_path,
                prior_path: finding.prior_repository_path,
                hint: finding.status_hint,
                event_kind: None,
                saw_created: false,
                saw_deleted: false,
                staged_file_id: None,
            },
            MAX_STATUS_CANDIDATES,
        )?;
        count = count.checked_add(1).ok_or_else(index_invalid)?;
        line.clear();
    }
    if count != seal.finding_count {
        return Err(index_invalid());
    }
    Ok(())
}

fn merge_event_candidate(
    binding: &VerifiedBinding,
    candidates: &mut BTreeMap<(String, String), StatusCandidate>,
    event: &WorkspaceWatchEvent,
) -> Result<(), CliError> {
    let key = status_sort_key(&event.repository_path, binding)?;
    let candidate = bounded_status_candidate(
        candidates,
        key,
        StatusCandidate {
            path: event.repository_path.clone(),
            prior_path: None,
            hint: WorkspaceStatus::Untracked,
            event_kind: None,
            saw_created: false,
            saw_deleted: false,
            staged_file_id: None,
        },
        MAX_STATUS_CANDIDATES,
    )?;
    candidate.prior_path = event
        .prior_repository_path
        .clone()
        .or(candidate.prior_path.clone());
    candidate.hint = match event.kind {
        WorkspaceWatchEventKind::Conflict => WorkspaceStatus::Conflicted,
        WorkspaceWatchEventKind::Renamed => WorkspaceStatus::MovedRenamedHint,
        WorkspaceWatchEventKind::Metadata => WorkspaceStatus::TypeModeChanged,
        WorkspaceWatchEventKind::Created => WorkspaceStatus::Untracked,
        WorkspaceWatchEventKind::Modified => WorkspaceStatus::Modified,
        WorkspaceWatchEventKind::Deleted => WorkspaceStatus::Deleted,
    };
    candidate.event_kind = Some(event.kind);
    candidate.saw_created |= event.kind == WorkspaceWatchEventKind::Created;
    candidate.saw_deleted |= event.kind == WorkspaceWatchEventKind::Deleted;
    if let Some(prior) = &event.prior_repository_path {
        let prior_key = status_sort_key(prior, binding)?;
        bounded_status_candidate(
            candidates,
            prior_key,
            StatusCandidate {
                path: prior.clone(),
                prior_path: None,
                hint: WorkspaceStatus::Deleted,
                event_kind: Some(WorkspaceWatchEventKind::Deleted),
                saw_created: false,
                saw_deleted: true,
                staged_file_id: None,
            },
            MAX_STATUS_CANDIDATES,
        )?;
    }
    Ok(())
}

fn merge_staged_candidates(
    binding: &VerifiedBinding,
    candidates: &mut BTreeMap<(String, String), StatusCandidate>,
    staging: &super::StagingState,
) -> Result<(), CliError> {
    for intent in &staging.intents {
        let (event, bound_paths): (WorkspaceWatchEvent, Vec<&str>) = match intent.kind {
            super::IntentKind::Add => {
                let destination = intent
                    .destination_path
                    .as_deref()
                    .ok_or_else(index_invalid)?;
                (
                    WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Created,
                        repository_path: destination.to_owned(),
                        prior_repository_path: None,
                    },
                    vec![destination],
                )
            }
            super::IntentKind::Move => {
                let source = intent.source_path.as_deref().ok_or_else(index_invalid)?;
                let destination = intent
                    .destination_path
                    .as_deref()
                    .ok_or_else(index_invalid)?;
                (
                    WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Renamed,
                        repository_path: destination.to_owned(),
                        prior_repository_path: Some(source.to_owned()),
                    },
                    vec![source, destination],
                )
            }
            super::IntentKind::Delete => {
                let source = intent.source_path.as_deref().ok_or_else(index_invalid)?;
                (
                    WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Deleted,
                        repository_path: source.to_owned(),
                        prior_repository_path: None,
                    },
                    vec![source],
                )
            }
        };
        merge_event_candidate(binding, candidates, &event)?;
        for path in bound_paths {
            let key = status_sort_key(path, binding)?;
            let candidate = candidates.get_mut(&key).ok_or_else(index_invalid)?;
            candidate.staged_file_id = Some(intent.file_id.clone());
        }
    }
    Ok(())
}

struct ClassifiedStatus {
    item: Option<WorkspaceStatusItem>,
    requires_reconciliation: bool,
}

fn classify_status_candidate(
    root: &Path,
    binding: &VerifiedBinding,
    ignores: &IgnoreFile,
    lookup: &mut LookupReader,
    candidate: StatusCandidate,
) -> Result<ClassifiedStatus, CliError> {
    let baseline = lookup.find(&candidate.path, binding)?;
    if candidate.event_kind == Some(WorkspaceWatchEventKind::Conflict) {
        return Ok(ClassifiedStatus {
            item: Some(status_item(
                candidate,
                WorkspaceStatus::Conflicted,
                baseline.as_ref(),
                None,
                false,
            )),
            requires_reconciliation: false,
        });
    }
    if let Some(entry) = baseline.as_ref() {
        let baseline_entry = WorkspaceBaselineEntry {
            repository_path: entry.repository_path.clone(),
            file_id: entry.file_id.clone(),
            content_manifest: entry.content_manifest.clone(),
            content_sha256: entry.content_sha256.clone(),
            content_bytes: entry.content_bytes,
            executable: entry.executable,
            materialization: entry.materialization,
        };
        let probe = probe_regular_file(root, &candidate.path)?;
        let content_verified = matches!(probe, FileProbe::Regular { .. });
        let (_, status) = classify_baseline_observation(&baseline_entry, probe);
        let status =
            if candidate.event_kind == Some(WorkspaceWatchEventKind::Renamed) && status.is_some() {
                Some(WorkspaceStatus::MovedRenamedHint)
            } else {
                status
            };
        return Ok(ClassifiedStatus {
            item: status.map(|status| {
                status_item(candidate, status, baseline.as_ref(), None, content_verified)
            }),
            requires_reconciliation: false,
        });
    }
    let probe = probe_regular_file(root, &candidate.path)?;
    let content_verified = matches!(probe, FileProbe::Regular { .. });
    let (ignored, explanation) = ignored_by(&candidate.path, ignores);
    let status = match probe {
        FileProbe::Absent if candidate.saw_created && candidate.saw_deleted => {
            return Ok(ClassifiedStatus {
                item: None,
                requires_reconciliation: false,
            });
        }
        FileProbe::Absent if candidate.event_kind == Some(WorkspaceWatchEventKind::Deleted) => {
            let requires_reconciliation = candidate.staged_file_id.is_none();
            return Ok(ClassifiedStatus {
                item: Some(status_item(
                    candidate,
                    WorkspaceStatus::Deleted,
                    None,
                    None,
                    false,
                )),
                requires_reconciliation,
            });
        }
        FileProbe::Absent => {
            return Ok(ClassifiedStatus {
                item: None,
                requires_reconciliation: false,
            });
        }
        FileProbe::Inaccessible => WorkspaceStatus::InaccessibleError,
        FileProbe::Other => WorkspaceStatus::TypeModeChanged,
        FileProbe::Regular { .. } if ignored => WorkspaceStatus::Ignored,
        FileProbe::Regular { .. }
            if candidate.event_kind == Some(WorkspaceWatchEventKind::Renamed) =>
        {
            WorkspaceStatus::MovedRenamedHint
        }
        FileProbe::Regular { .. }
            if candidate.event_kind == Some(WorkspaceWatchEventKind::Created) =>
        {
            WorkspaceStatus::Added
        }
        FileProbe::Regular { .. } => candidate.hint.max(WorkspaceStatus::Untracked),
    };
    Ok(ClassifiedStatus {
        item: Some(status_item(
            candidate,
            status,
            None,
            explanation,
            content_verified,
        )),
        requires_reconciliation: false,
    })
}

fn status_item(
    candidate: StatusCandidate,
    status: WorkspaceStatus,
    baseline: Option<&IndexEntryDisk>,
    ignore: Option<IgnoreExplanation>,
    content_verified: bool,
) -> WorkspaceStatusItem {
    let file_id = baseline
        .map(|entry| entry.file_id.clone())
        .or_else(|| candidate.staged_file_id.clone());
    WorkspaceStatusItem {
        repository_path: candidate.path,
        status,
        prior_repository_path: candidate.prior_path,
        file_id,
        ignore,
        content_verified,
    }
}

pub fn recover_workspace_index(root: &Path) -> Result<Option<WorkspaceIndexReport>, CliError> {
    let root = validated_root(root)?;
    let _lock = MutationLock::acquire(&root)?;
    let index = checked_index_directory(&root)?;
    if existing_transition(&root)? && retention::compaction_pending(&index)? {
        return Err(index_invalid());
    }
    recover_transition_at(&index)?;
    let Some(active) = read_optional_active(&index)? else {
        return Ok(None);
    };
    let metadata = read_ready_metadata(&root)?;
    validate_active_binding(&active, &metadata)?;
    retention::recover_compaction_at(&index, &metadata, &active)?;
    retention::observe_active_generation(&index, &metadata, &active)?;
    let seal: GenerationSeal = read_json_private(
        &index.join(format!("seal-{}.v1", active.payload.generation_id)),
        MAX_CONTROL_BYTES,
    )?;
    validate_wrapped(&seal.payload, &seal.payload_sha256)?;
    validate_seal_quick(&index, &seal)?;
    let mut watcher: WatcherState = read_json_private(
        &index.join(format!("watcher-{}.v1", active.payload.generation_id)),
        MAX_CONTROL_BYTES,
    )?;
    validate_wrapped(&watcher.payload, &watcher.payload_sha256)?;
    validate_watcher_state(&index, &seal, &watcher)?;
    if watcher.payload.session_open {
        persist_degraded_state(&index, &mut watcher, "unclean-shutdown", true)?;
    }
    Ok(Some(report_from_loaded(&active, &seal, &watcher)))
}

fn recover_transition_at(index: &Path) -> Result<(), CliError> {
    let transition_path = index.join("transition.json");
    let transition: Transition = match fs::symlink_metadata(&transition_path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {
            read_json_private(&transition_path, MAX_CONTROL_BYTES)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        _ => return Err(index_invalid()),
    };
    validate_wrapped(&transition.payload, &transition.payload_sha256)?;
    if transition.payload.schema != "ogvcs.workspace-index/transition/v1"
        || !valid_generation_id(&transition.payload.generation_id)
        || transition.payload.artifact_names != artifact_names(&transition.payload.generation_id)
        || transition
            .payload
            .prior_active_sha256
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
    {
        return Err(index_invalid());
    }
    let active = read_optional_active(index)?;
    let committed = active
        .as_ref()
        .is_some_and(|active| active.payload.generation_id == transition.payload.generation_id);
    if !committed {
        for name in &transition.payload.artifact_names {
            let path = index.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {
                    fs::remove_file(&path).map_err(|_| index_write_unavailable())?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(index_invalid()),
            }
        }
        reconcile_watcher_after_aborted_transition(index, active.as_ref())?;
    }
    fs::remove_file(&transition_path).map_err(|_| index_write_unavailable())?;
    sync_directory(index)
}

fn reconcile_watcher_after_aborted_transition(
    index: &Path,
    active: Option<&ActiveManifest>,
) -> Result<(), CliError> {
    let state_path = active
        .map(|active| index.join(format!("watcher-{}.v1", active.payload.generation_id)))
        .unwrap_or_else(|| index.join("watcher-orphan.v1"));
    let state: Option<WatcherState> = match fs::symlink_metadata(&state_path) {
        Ok(metadata) if !is_link_or_reparse(&metadata) && metadata.is_file() => {
            Some(read_json_private(&state_path, MAX_CONTROL_BYTES)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        _ => return Err(index_invalid()),
    };
    match (active, state) {
        (Some(active), Some(mut state))
            if state.payload.generation_id == active.payload.generation_id =>
        {
            validate_wrapped(&state.payload, &state.payload_sha256)?;
            persist_degraded_state(index, &mut state, "unclean-shutdown", true)
        }
        (Some(active), _) => {
            let seal: GenerationSeal = read_json_private(
                &index.join(format!("seal-{}.v1", active.payload.generation_id)),
                MAX_CONTROL_BYTES,
            )?;
            let payload = WatcherStatePayload {
                schema: "ogvcs.workspace-index/watcher-state/v1".to_owned(),
                generation_id: active.payload.generation_id.clone(),
                adapter: "recovery".to_owned(),
                session_id: "recovery".to_owned(),
                cursor: "unknown".to_owned(),
                continuity_proven: false,
                resume_supported: false,
                session_open: false,
                reconciliation_required: true,
                reason: "unclean-shutdown".to_owned(),
                event_count: 0,
                event_bytes: fs::metadata(index.join(&seal.payload.events_name))
                    .map_err(|_| index_invalid())?
                    .len(),
                event_tail_sha256: EMPTY_SHA256.to_owned(),
            };
            // A non-empty orphan journal cannot be reconstructed without its
            // prior state; fail instead of publishing a false empty chain.
            if payload.event_bytes != 0 {
                return Err(index_invalid());
            }
            let (payload, payload_sha256) = payload_wrapper(payload)?;
            write_json_atomic(
                &state_path,
                &WatcherState {
                    payload,
                    payload_sha256,
                },
            )
        }
        (None, Some(state)) => {
            validate_wrapped(&state.payload, &state.payload_sha256)?;
            fs::remove_file(&state_path).map_err(|_| index_write_unavailable())?;
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

pub fn repair_workspace_index(
    root: &Path,
    watcher: &mut dyn WorkspaceWatcherAuthority,
    cancellation: &dyn Cancellation,
) -> Result<WorkspaceIndexReport, CliError> {
    let root = validated_root(root)?;
    let metadata_before = read_ready_metadata(&root)?;
    let watcher_start = watcher.begin_reconciliation(&root, &metadata_before.binding)?;
    validate_watcher_start(&watcher_start)?;
    let _lock = MutationLock::acquire(&root)?;
    let (index, metadata, old_active, old_seal, old_watcher, ignores) = load_active(&root, false)?;
    if json_digest(&metadata_before)? != json_digest(&metadata)? {
        return Err(index_error(
            "WORKSPACE_INDEX_BINDING_STALE",
            "The verified workspace binding changed before index repair.",
            "Restart repair against the current authenticated baseline.",
        ));
    }
    // Verify and consume the exact same active generation while retaining the
    // single mutation lock. A corrupt baseline cannot become repair authority,
    // and another writer cannot replace it between verification and reseal.
    verify_loaded_workspace_index(&index, &old_active, &old_seal, &old_watcher)?;
    let mut writer = GenerationWriter::begin(&root, metadata.clone(), ignores.local_rules.clone())?;
    let file = open_private_file(&index.join(&old_seal.payload.entries.name))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut chunk = Vec::with_capacity(MAX_BASELINE_CHUNK_ITEMS);
    let mut count = 0u64;
    while reader
        .read_until(b'\n', &mut line)
        .map_err(|_| index_invalid())?
        != 0
    {
        cancellation.check("workspace-index-repair-stream")?;
        if line.last() != Some(&b'\n') || line.len() > MAX_ENTRY_BYTES + 1 {
            return Err(index_invalid());
        }
        line.pop();
        let entry: IndexEntryDisk = serde_json::from_slice(&line).map_err(|_| index_invalid())?;
        chunk.push(WorkspaceBaselineEntry {
            repository_path: entry.repository_path,
            file_id: entry.file_id,
            content_manifest: entry.content_manifest,
            content_sha256: entry.content_sha256,
            content_bytes: entry.content_bytes,
            executable: entry.executable,
            materialization: entry.materialization,
        });
        count = count.checked_add(1).ok_or_else(index_invalid)?;
        if chunk.len() == MAX_BASELINE_CHUNK_ITEMS {
            writer.append_chunk(&chunk)?;
            chunk.clear();
        }
        line.clear();
    }
    if !chunk.is_empty() {
        writer.append_chunk(&chunk)?;
    }
    if count != old_seal.payload.entry_count {
        return Err(index_invalid());
    }
    let receipt = WorkspaceBaselineReceipt {
        schema: BASELINE_RECEIPT_SCHEMA.to_owned(),
        repository_id_hex: metadata.binding.repository_id_hex.clone(),
        baseline: metadata.binding.baseline.clone(),
        repository_settings_digest: metadata.binding.repository_settings_digest.clone(),
        path_profile: metadata.binding.path_profile.clone(),
        case_mode: metadata.binding.case_mode.clone(),
        entry_count: count,
        ordered_entries_sha256: writer.ordered_entries_sha256(),
        repository_ignore_rules_sha256: ignore_rules_digest(&ignores.repository_rules)?,
        repository_ignore_rules: ignores.repository_rules,
    };
    let prepared = writer.prepare_reconciliation(receipt)?;
    let checkpoint = watcher.finish_reconciliation(&watcher_start, &mut writer)?;
    validate_watcher_checkpoint(&watcher_start, &checkpoint)?;
    writer.finish(prepared, checkpoint)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashPoint {
    TransitionPublished = 1,
    ArtifactsSynced = 2,
    SealSynced = 3,
    ActivePublished = 4,
}

#[cfg(test)]
thread_local! {
    static CRASH_POINT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static JOURNAL_STATE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
struct StatusAfterLoadHook {
    index: PathBuf,
    entered: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
static STATUS_AFTER_LOAD_HOOK: std::sync::Mutex<Option<StatusAfterLoadHook>> =
    std::sync::Mutex::new(None);

fn status_after_load_hook(index: &Path) {
    #[cfg(test)]
    if let Some(hook) = {
        let mut hook = STATUS_AFTER_LOAD_HOOK.lock().unwrap();
        if hook
            .as_ref()
            .is_some_and(|expected| expected.index == index)
        {
            hook.take()
        } else {
            None
        }
    } {
        hook.entered.wait();
        hook.release.wait();
    }

    #[cfg(not(test))]
    let _ = index;
}

fn crash_now(point: CrashPoint) -> bool {
    #[cfg(test)]
    {
        CRASH_POINT.with(|value| {
            if value.get() == point as u8 {
                value.set(0);
                true
            } else {
                false
            }
        })
    }
    #[cfg(not(test))]
    {
        let _ = point;
        false
    }
}

fn injected_crash() -> CliError {
    index_error(
        "WORKSPACE_INDEX_INJECTED_CRASH",
        "The test interrupted an index generation at a durable crash boundary.",
        "Run workspace index recovery before retrying.",
    )
}

fn journal_state_fault_now() -> bool {
    #[cfg(test)]
    {
        JOURNAL_STATE_FAULT.with(|value| value.replace(false))
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
fn set_crash_point(point: CrashPoint) {
    CRASH_POINT.with(|value| value.set(point as u8));
}

#[cfg(test)]
fn set_journal_state_fault() {
    JOURNAL_STATE_FAULT.with(|value| value.set(true));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production::{
        AuthenticationTransport, CapabilityOffer, CapabilitySelection, DiscardProgress,
        FileIdAllocationReceipt, NeverCancelled, PresentedFileIdAllocation, RepositoryDiscovery,
        RepositoryDiscoveryRequest, AUTHORIZATION_CONTRACT, AUTHORIZATION_REGISTRY_SHA256,
        EVENT_VERSION, FILE_ID_ALLOCATION_SCHEMA, MESSAGE_SCHEMA_VERSION, PATH_CONTRACT,
        PATH_REGISTRY_SHA256, PROTOCOL_REGISTRY_SET_SHA256, PROTOCOL_VERSION, REPOSITORY_FORMAT,
        REPOSITORY_REGISTRY_SHA256, REQUIRED_PROTOCOL_FEATURES, TRANSFER_PROFILE,
    };
    use crate::CredentialStatus;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Instant;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ContractArtifact {
        path: String,
        bytes: u64,
        sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct ContractManifest {
        schema: String,
        contract_version: String,
        artifact_set_sha256: String,
        counts: ContractCounts,
        artifacts: Vec<ContractArtifact>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ContractCounts {
        artifacts: u64,
        vectors: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CursorVector {
        schema: String,
        key_hex: String,
        payload: StatusCursorPayload,
        expected_mac_sha256: String,
    }

    #[cfg(not(windows))]
    use std::os::unix::fs::PermissionsExt;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "ogvcs012-{label}-{}-{}",
                std::process::id(),
                random_hex(8).unwrap()
            ));
            #[cfg(not(windows))]
            {
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            #[cfg(windows)]
            crate::windows_security::create_new_private_directory(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }

        fn write(&self, repository_path: &str, bytes: &[u8]) {
            let path = joined_path(&self.0, repository_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, bytes).unwrap();
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_file(self.0.join(".ogvcs-mutation-v2.lock"));
        }
    }

    fn selection() -> CapabilitySelection {
        CapabilitySelection {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            message_schema_version: MESSAGE_SCHEMA_VERSION.to_owned(),
            repository_format: REPOSITORY_FORMAT.to_owned(),
            authorization_contract: AUTHORIZATION_CONTRACT.to_owned(),
            authorization_registry_sha256: AUTHORIZATION_REGISTRY_SHA256.to_owned(),
            path_contract: PATH_CONTRACT.to_owned(),
            path_profile: super::super::PORTABLE_PATH_PROFILE.to_owned(),
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
            expires_at_unix_ms: now_unix_ms().unwrap() + 3_600_000,
        }
    }

    fn binding() -> VerifiedBinding {
        VerifiedBinding {
            repository_id_hex: "00000000000040008000000000000002".to_owned(),
            branch: "main".to_owned(),
            baseline: format!("ogvcs:v1:snapshot:sha256:{}", "4".repeat(64)),
            case_mode: "case-folded".to_owned(),
            path_profile: super::super::PORTABLE_PATH_PROFILE.to_owned(),
            repository_settings_digest: "5".repeat(64),
            negotiation: selection(),
            subject_digest: "1".repeat(64),
            authority_epoch: 7,
            security_epoch: 9,
            verification: "public-service-verified".to_owned(),
        }
    }

    #[test]
    fn authenticated_candidate_contract_and_cursor_vector_match_runtime() {
        const CONTRACT: &[u8] = include_bytes!("../../contracts/workspace-index/v1/contract.json");
        const README: &[u8] = include_bytes!("../../contracts/workspace-index/v1/README.md");
        const GENERATOR: &[u8] =
            include_bytes!("../../contracts/workspace-index/v1/scripts/generate.mjs");
        const VALIDATOR: &[u8] = include_bytes!("../../contracts/workspace-index/v1/validate.mjs");
        const VECTOR: &[u8] =
            include_bytes!("../../contracts/workspace-index/v1/vectors/status-cursor-hmac.json");
        const RETENTION_VECTOR: &[u8] =
            include_bytes!("../../contracts/workspace-index/v1/vectors/retention-hmac.json");
        const MANIFEST: &[u8] = include_bytes!("../../contracts/workspace-index/v1/manifest.json");

        let manifest: ContractManifest = serde_json::from_slice(MANIFEST).unwrap();
        assert_eq!(
            manifest.schema,
            "ogvcs.workspace-index/private-contract-manifest/v1"
        );
        assert_eq!(manifest.contract_version, WORKSPACE_INDEX_CONTRACT_VERSION);
        assert_eq!(manifest.counts.artifacts, 6);
        assert_eq!(manifest.counts.vectors, 2);
        assert_eq!(manifest.artifacts.len(), 6);
        for artifact in &manifest.artifacts {
            let bytes: &[u8] = match artifact.path.as_str() {
                "README.md" => README,
                "contract.json" => CONTRACT,
                "scripts/generate.mjs" => GENERATOR,
                "validate.mjs" => VALIDATOR,
                "vectors/retention-hmac.json" => RETENTION_VECTOR,
                "vectors/status-cursor-hmac.json" => VECTOR,
                path => panic!("unexpected contract artifact: {path}"),
            };
            assert_eq!(artifact.bytes, bytes.len() as u64);
            assert_eq!(artifact.sha256, digest_bytes(bytes));
        }
        let mut records = serde_json::to_vec(&manifest.artifacts).unwrap();
        records.push(b'\n');
        assert_eq!(manifest.artifact_set_sha256, digest_bytes(&records));
        assert_eq!(
            manifest.artifact_set_sha256,
            WORKSPACE_INDEX_CONTRACT_ARTIFACT_SET_SHA256
        );
        assert_eq!(digest_bytes(CONTRACT), WORKSPACE_INDEX_CONTRACT_SHA256);

        let contract: serde_json::Value = serde_json::from_slice(CONTRACT).unwrap();
        assert_eq!(
            contract["contractVersion"],
            WORKSPACE_INDEX_CONTRACT_VERSION
        );
        assert_eq!(
            contract["privateCandidateClaims"]["readerSafeGenerationGcImplemented"],
            true
        );
        assert!(contract["publicClaims"]
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == false));

        let vector: CursorVector = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(
            vector.schema,
            "ogvcs.workspace-index/status-cursor-hmac-vector/v2"
        );
        let key_bytes = vector
            .key_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                Ok((hex_nibble(pair[0]).ok_or_else(input_error)? << 4)
                    | hex_nibble(pair[1]).ok_or_else(input_error)?)
            })
            .collect::<Result<Vec<_>, CliError>>()
            .unwrap();
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let payload = serde_json::to_vec(&vector.payload).unwrap();
        assert_eq!(hmac_sha256(&key, &payload), vector.expected_mac_sha256);
    }

    #[test]
    fn v1_status_cursor_shape_and_schema_are_rejected_under_v2() {
        const VECTOR: &[u8] =
            include_bytes!("../../contracts/workspace-index/v1/vectors/status-cursor-hmac.json");
        let mut vector: CursorVector = serde_json::from_slice(VECTOR).unwrap();
        let key_bytes = vector
            .key_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]).unwrap() << 4) | hex_nibble(pair[1]).unwrap())
            .collect::<Vec<_>>();
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let mut binding = binding();
        binding.repository_settings_digest = "2".repeat(64);
        let active = ActiveManifest {
            payload: ActivePayload {
                schema: WORKSPACE_INDEX_SCHEMA.to_owned(),
                contract_version: WORKSPACE_INDEX_GENERATION_FORMAT_VERSION.to_owned(),
                generation_id: vector.payload.generation_id.clone(),
                generation: 1,
                generation_seal_sha256: "9".repeat(64),
                workspace_id_digest: "a".repeat(64),
                repository_id_hex: binding.repository_id_hex.clone(),
                branch: binding.branch.clone(),
                baseline: binding.baseline.clone(),
                repository_settings_digest: binding.repository_settings_digest.clone(),
                path_profile: binding.path_profile.clone(),
                case_mode: binding.case_mode.clone(),
                created_at_unix_ms: 1,
            },
            payload_sha256: vector.payload.active_sha256.clone(),
        };
        let artifact = |name: &str| FileSeal {
            name: name.to_owned(),
            bytes: 0,
            sha256: EMPTY_SHA256.to_owned(),
            metadata_fingerprint_sha256: "a".repeat(64),
        };
        let seal = GenerationSealPayload {
            schema: "ogvcs.workspace-index/generation-seal/v1".to_owned(),
            generation_id: vector.payload.generation_id.clone(),
            generation: 1,
            entry_count: 1,
            finding_count: 0,
            entries: artifact("entries"),
            lookup: artifact("lookup"),
            findings: artifact("findings"),
            ignores: artifact("ignores"),
            events_name: "events".to_owned(),
            ordered_entries_sha256: "b".repeat(64),
            repository_ignore_rules_sha256: "3".repeat(64),
            local_ignore_rules_sha256: "4".repeat(64),
        };
        let watcher = WatcherState {
            payload: WatcherStatePayload {
                schema: "ogvcs.workspace-index/watcher-state/v1".to_owned(),
                generation_id: vector.payload.generation_id.clone(),
                adapter: host_adapter().to_owned(),
                session_id: "session.vector".to_owned(),
                cursor: vector.payload.watcher_cursor.clone(),
                continuity_proven: true,
                resume_supported: true,
                session_open: true,
                reconciliation_required: false,
                reason: "current-native-cursor".to_owned(),
                event_count: vector.payload.watcher_event_count,
                event_bytes: vector.payload.watcher_event_bytes,
                event_tail_sha256: vector.payload.watcher_event_tail_sha256.clone(),
            },
            payload_sha256: vector.payload.watcher_payload_sha256.clone(),
        };

        vector.payload.schema = "ogvcs.workspace-index/status-cursor/v1".to_owned();
        let payload = serde_json::to_vec(&vector.payload).unwrap();
        // Independently calculated with Node over the v1 schema plus the
        // current v2 HMAC domain. A valid MAC cannot upgrade old semantics.
        let independent_mac = "cf71969691d2db8be06ae2d936bc243853a94289f2b63441d76b180022603326";
        assert_eq!(hmac_sha256(&key, &payload), independent_mac);
        let encoded = hex_bytes(
            &serde_json::to_vec(&StatusCursor {
                payload: vector.payload.clone(),
                mac_sha256: independent_mac.to_owned(),
            })
            .unwrap(),
        );
        assert_eq!(
            decode_status_cursor(
                &encoded,
                &StatusCursorContext {
                    active: &active,
                    seal: &seal,
                    watcher: &watcher,
                    staging_generation: 9,
                    staging_state_sha256: &"8".repeat(64),
                    binding: &binding,
                    filter_sha256: &"5".repeat(64),
                },
                &key,
            )
            .unwrap_err()
            .code,
            "WORKSPACE_STATUS_CURSOR_STALE"
        );

        let old_payload = serde_json::json!({
            "schema": "ogvcs.workspace-index/status-cursor/v1",
            "generationId": active.payload.generation_id.clone(),
            "activeSha256": active.payload_sha256.clone(),
            "repositorySettingsDigest": binding.repository_settings_digest.clone(),
            "pathProfile": binding.path_profile.clone(),
            "caseMode": binding.case_mode.clone(),
            "repositoryIgnoreRulesSha256": seal.repository_ignore_rules_sha256.clone(),
            "localIgnoreRulesSha256": seal.local_ignore_rules_sha256.clone(),
            "filterSha256": "5".repeat(64),
            "afterRepositoryPath": "Game/Textures/Hero.DDS",
            "afterPlatformKey": "game/textures/hero.dds"
        });
        let old_payload_bytes = serde_json::to_vec(&old_payload).unwrap();
        let old_shape = serde_json::json!({
            "payload": old_payload,
            "macSha256": hmac_sha256(&key, &old_payload_bytes)
        });
        let encoded = hex_bytes(&serde_json::to_vec(&old_shape).unwrap());
        assert_eq!(
            decode_status_cursor(
                &encoded,
                &StatusCursorContext {
                    active: &active,
                    seal: &seal,
                    watcher: &watcher,
                    staging_generation: 9,
                    staging_state_sha256: &"8".repeat(64),
                    binding: &binding,
                    filter_sha256: &"5".repeat(64),
                },
                &key,
            )
            .unwrap_err()
            .code,
            "INPUT_INVALID"
        );
    }

    fn initialize_workspace(root: &Path) {
        super::super::publish_verified_workspace(
            root,
            binding(),
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();
    }

    fn session() -> AuthenticationSession {
        AuthenticationSession {
            subject_digest: "1".repeat(64),
            session_digest: "2".repeat(64),
            authority_epoch: 7,
            security_epoch: 9,
            expires_at_unix_ms: now_unix_ms().unwrap() + 3_600_000,
        }
    }

    struct TestProvider;

    impl SecureCredentialProvider for TestProvider {
        fn kind(&self) -> &'static str {
            "test"
        }

        fn status(&self) -> CredentialStatus {
            CredentialStatus::Available
        }

        fn invoke(
            &self,
            _: &AuthenticationRequest,
            _: &mut dyn AuthenticationTransport,
            _: &dyn Cancellation,
        ) -> Result<AuthenticationSession, CliError> {
            Ok(session())
        }
    }

    struct TestRoutes {
        entries: Vec<WorkspaceBaselineEntry>,
        repository_rules: Vec<WorkspaceIgnoreRule>,
        chunk_items: usize,
        entered: Option<Arc<Barrier>>,
        release: Option<Arc<Barrier>>,
    }

    impl TestRoutes {
        fn new(mut entries: Vec<WorkspaceBaselineEntry>) -> Self {
            sort_entries(&mut entries);
            Self {
                entries,
                repository_rules: Vec::new(),
                chunk_items: 17,
                entered: None,
                release: None,
            }
        }
    }

    impl AuthenticationTransport for TestRoutes {
        fn authenticate(
            &mut self,
            _: &AuthenticationRequest,
            _: &super::super::SecretMaterial,
            _: &dyn Cancellation,
        ) -> Result<AuthenticationSession, CliError> {
            Ok(session())
        }
    }

    impl RepositoryPublicRoutes for TestRoutes {
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
            unreachable!()
        }

        fn negotiate_capabilities(
            &mut self,
            _: &AuthenticationSession,
            _: &RepositoryDiscovery,
            _: &CapabilityOffer,
            _: &dyn Cancellation,
            _: &mut dyn ProgressSink,
        ) -> Result<CapabilitySelection, CliError> {
            unreachable!()
        }

        fn validate_binding(
            &mut self,
            _: &AuthenticationSession,
            actual: &VerifiedBinding,
            _: &dyn Cancellation,
        ) -> Result<(), CliError> {
            assert_eq!(actual.repository_id_hex, binding().repository_id_hex);
            Ok(())
        }

        fn present_preallocated_file_id(
            &mut self,
            _: &AuthenticationSession,
            _: &VerifiedBinding,
            repository_path_key: &str,
            _: &dyn Cancellation,
        ) -> Result<PresentedFileIdAllocation, CliError> {
            Ok(PresentedFileIdAllocation {
                allocation_schema_version: FILE_ID_ALLOCATION_SCHEMA.to_owned(),
                repository_id: "00000000-0000-4000-8000-000000000002".to_owned(),
                repository_path_key: repository_path_key.to_owned(),
                file_id: "fid:00000000000000000000000000000001".to_owned(),
                allocation_receipt: FileIdAllocationReceipt::new(format!(
                    "far1.{}",
                    "A".repeat(43)
                ))?,
                allocation_idempotency_key_sha256: "6".repeat(64),
                expires_at_unix_ms: now_unix_ms()? + 3_600_000,
            })
        }

        fn resolve_file_id(
            &mut self,
            _: &AuthenticationSession,
            _: &VerifiedBinding,
            _: &str,
            _: &dyn Cancellation,
        ) -> Result<String, CliError> {
            Ok("fid:00000000000000000000000000000002".to_owned())
        }

        fn stream_workspace_baseline(
            &mut self,
            _: &AuthenticationSession,
            actual: &VerifiedBinding,
            sink: &mut dyn WorkspaceBaselineSink,
            _: &dyn Cancellation,
            _: &mut dyn ProgressSink,
        ) -> Result<WorkspaceBaselineReceipt, CliError> {
            if let Some(barrier) = &self.entered {
                barrier.wait();
            }
            if let Some(barrier) = &self.release {
                barrier.wait();
            }
            for chunk in self.entries.chunks(self.chunk_items) {
                sink.append_chunk(chunk)?;
            }
            Ok(receipt(
                actual,
                &self.entries,
                self.repository_rules.clone(),
            ))
        }
    }

    struct TestWatcher {
        continuity: bool,
        queued: Vec<WorkspaceWatchEvent>,
        cursor: String,
        fence_batches: Vec<WorkspaceWatchBatch>,
        fence_session_id: Option<String>,
        fence_cursor: Option<String>,
        fence_error: bool,
    }

    impl Default for TestWatcher {
        fn default() -> Self {
            Self {
                continuity: true,
                queued: Vec::new(),
                cursor: "cursor.1".to_owned(),
                fence_batches: Vec::new(),
                fence_session_id: None,
                fence_cursor: None,
                fence_error: false,
            }
        }
    }

    impl WorkspaceWatcherAuthority for TestWatcher {
        fn begin_reconciliation(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
        ) -> Result<WorkspaceWatcherStart, CliError> {
            Ok(WorkspaceWatcherStart {
                adapter: host_adapter().to_owned(),
                session_id: "session.1".to_owned(),
                resume_cursor: None,
            })
        }

        fn finish_reconciliation(
            &mut self,
            start: &WorkspaceWatcherStart,
            sink: &mut dyn WorkspaceWatchEventSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            for chunk in self.queued.chunks(MAX_WATCH_CHUNK_ITEMS) {
                sink.append_watch_chunk(chunk)?;
            }
            Ok(WorkspaceWatcherCheckpoint {
                adapter: start.adapter.clone(),
                session_id: start.session_id.clone(),
                cursor: self.cursor.clone(),
                continuity_proven: self.continuity,
                resume_supported: self.continuity,
            })
        }

        fn fence_status(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
            start: &WorkspaceWatcherStart,
            sink: &mut dyn WorkspaceWatchBatchSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            if self.fence_error {
                return Err(index_invalid());
            }
            let batches = std::mem::take(&mut self.fence_batches);
            for batch in &batches {
                sink.append_watch_batch(batch)?;
            }
            let cursor = self
                .fence_cursor
                .clone()
                .or_else(|| batches.last().map(|batch| batch.cursor.clone()))
                .or_else(|| start.resume_cursor.clone())
                .unwrap_or_else(|| self.cursor.clone());
            Ok(WorkspaceWatcherCheckpoint {
                adapter: start.adapter.clone(),
                session_id: self
                    .fence_session_id
                    .clone()
                    .unwrap_or_else(|| start.session_id.clone()),
                cursor,
                continuity_proven: self.continuity,
                resume_supported: self.continuity,
            })
        }
    }

    struct BlockingWatcher {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    impl WorkspaceWatcherAuthority for BlockingWatcher {
        fn begin_reconciliation(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
        ) -> Result<WorkspaceWatcherStart, CliError> {
            Ok(WorkspaceWatcherStart {
                adapter: host_adapter().to_owned(),
                session_id: "blocking.session".to_owned(),
                resume_cursor: None,
            })
        }

        fn finish_reconciliation(
            &mut self,
            start: &WorkspaceWatcherStart,
            _: &mut dyn WorkspaceWatchEventSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            self.entered.wait();
            self.release.wait();
            Ok(WorkspaceWatcherCheckpoint {
                adapter: start.adapter.clone(),
                session_id: start.session_id.clone(),
                cursor: "blocking.cursor".to_owned(),
                continuity_proven: true,
                resume_supported: true,
            })
        }
    }

    struct OrderingWatcher {
        root: PathBuf,
    }

    impl WorkspaceWatcherAuthority for OrderingWatcher {
        fn begin_reconciliation(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
        ) -> Result<WorkspaceWatcherStart, CliError> {
            fs::create_dir_all(self.root.join("Untracked")).unwrap();
            fs::write(self.root.join("Untracked/during-subscribe.bin"), b"early").unwrap();
            Ok(WorkspaceWatcherStart {
                adapter: host_adapter().to_owned(),
                session_id: "ordering.session".to_owned(),
                resume_cursor: None,
            })
        }

        fn finish_reconciliation(
            &mut self,
            start: &WorkspaceWatcherStart,
            sink: &mut dyn WorkspaceWatchEventSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            // This append is accepted only after the complete scan has sealed
            // its candidate set. The later filesystem mutation is therefore
            // covered solely by the final watcher drain.
            fs::write(self.root.join("Untracked/during-barrier.bin"), b"late").unwrap();
            sink.append_watch_chunk(&[WorkspaceWatchEvent {
                kind: WorkspaceWatchEventKind::Created,
                repository_path: "Untracked/during-barrier.bin".to_owned(),
                prior_repository_path: None,
            }])?;
            Ok(WorkspaceWatcherCheckpoint {
                adapter: start.adapter.clone(),
                session_id: start.session_id.clone(),
                cursor: "ordering.cursor".to_owned(),
                continuity_proven: true,
                resume_supported: true,
            })
        }
    }

    struct WithheldStatusWatcher {
        fences: u8,
    }

    impl WorkspaceWatcherAuthority for WithheldStatusWatcher {
        fn begin_reconciliation(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
        ) -> Result<WorkspaceWatcherStart, CliError> {
            unreachable!()
        }

        fn finish_reconciliation(
            &mut self,
            _: &WorkspaceWatcherStart,
            _: &mut dyn WorkspaceWatchEventSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            unreachable!()
        }

        fn fence_status(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
            start: &WorkspaceWatcherStart,
            sink: &mut dyn WorkspaceWatchBatchSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            self.fences += 1;
            let cursor = if self.fences == 1 {
                start.resume_cursor.clone().unwrap()
            } else {
                let prior = start.resume_cursor.clone().unwrap();
                let cursor = "cursor.withheld".to_owned();
                sink.append_watch_batch(&WorkspaceWatchBatch {
                    session_id: start.session_id.clone(),
                    prior_cursor: prior,
                    cursor: cursor.clone(),
                    events: vec![WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Modified,
                        repository_path: "Game/value.bin".to_owned(),
                        prior_repository_path: None,
                    }],
                })?;
                cursor
            };
            Ok(WorkspaceWatcherCheckpoint {
                adapter: start.adapter.clone(),
                session_id: start.session_id.clone(),
                cursor,
                continuity_proven: true,
                resume_supported: true,
            })
        }
    }

    struct IdleAdvanceWatcher {
        fences: u8,
    }

    impl WorkspaceWatcherAuthority for IdleAdvanceWatcher {
        fn begin_reconciliation(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
        ) -> Result<WorkspaceWatcherStart, CliError> {
            unreachable!()
        }

        fn finish_reconciliation(
            &mut self,
            _: &WorkspaceWatcherStart,
            _: &mut dyn WorkspaceWatchEventSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            unreachable!()
        }

        fn fence_status(
            &mut self,
            _: &Path,
            _: &VerifiedBinding,
            start: &WorkspaceWatcherStart,
            _: &mut dyn WorkspaceWatchBatchSink,
        ) -> Result<WorkspaceWatcherCheckpoint, CliError> {
            self.fences += 1;
            Ok(WorkspaceWatcherCheckpoint {
                adapter: start.adapter.clone(),
                session_id: start.session_id.clone(),
                cursor: format!("idle.cursor.{}", self.fences),
                continuity_proven: true,
                resume_supported: true,
            })
        }
    }

    fn host_adapter() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "linux-inotify"
        }
        #[cfg(target_os = "macos")]
        {
            "macos-fsevents"
        }
        #[cfg(windows)]
        {
            "windows-usn"
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            "unsupported"
        }
    }

    fn request(root: &Path) -> WorkspaceIndexBuildRequest {
        WorkspaceIndexBuildRequest {
            root: root.to_path_buf(),
            authentication: AuthenticationRequest {
                endpoint: "https://service.example".to_owned(),
                profile: "test".to_owned(),
                non_interactive: true,
            },
            local_ignore_rules: Vec::new(),
        }
    }

    fn build(
        root: &Path,
        routes: &mut TestRoutes,
        watcher: &mut TestWatcher,
    ) -> WorkspaceIndexReport {
        rebuild_workspace_index(
            &request(root),
            &TestProvider,
            routes,
            watcher,
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap()
    }

    fn baseline_entry(
        ordinal: u128,
        path: &str,
        bytes: &[u8],
        materialization: BaselineMaterialization,
    ) -> WorkspaceBaselineEntry {
        WorkspaceBaselineEntry {
            repository_path: path.to_owned(),
            file_id: format!("fid:{:032x}", ordinal + 1),
            content_manifest: format!("ogvcs:v1:content-manifest:sha256:{:064x}", ordinal + 1),
            content_sha256: digest_bytes(bytes),
            content_bytes: bytes.len() as u64,
            executable: false,
            materialization,
        }
    }

    fn sort_entries(entries: &mut [WorkspaceBaselineEntry]) {
        let binding = binding();
        entries.sort_by_key(|entry| {
            let keys = path_collision_keys(
                &entry.repository_path,
                &binding.path_profile,
                &binding.case_mode,
            )
            .unwrap();
            (
                digest_text(keys.platform_key()),
                keys.platform_key().to_owned(),
            )
        });
    }

    fn ordered_digest(entries: &[WorkspaceBaselineEntry]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ORDERED_BASELINE_DOMAIN);
        for entry in entries {
            let bytes = serde_json::to_vec(entry).unwrap();
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        finalize_hasher(hasher)
    }

    fn receipt(
        binding: &VerifiedBinding,
        entries: &[WorkspaceBaselineEntry],
        rules: Vec<WorkspaceIgnoreRule>,
    ) -> WorkspaceBaselineReceipt {
        WorkspaceBaselineReceipt {
            schema: BASELINE_RECEIPT_SCHEMA.to_owned(),
            repository_id_hex: binding.repository_id_hex.clone(),
            baseline: binding.baseline.clone(),
            repository_settings_digest: binding.repository_settings_digest.clone(),
            path_profile: binding.path_profile.clone(),
            case_mode: binding.case_mode.clone(),
            entry_count: entries.len() as u64,
            ordered_entries_sha256: ordered_digest(entries),
            repository_ignore_rules_sha256: ignore_rules_digest(&rules).unwrap(),
            repository_ignore_rules: rules,
        }
    }

    fn status_request(root: &Path, limit: usize) -> WorkspaceStatusPageRequest {
        WorkspaceStatusPageRequest {
            root: root.to_path_buf(),
            cursor: None,
            limit,
            filter: WorkspaceStatusFilter::default(),
        }
    }

    fn test_status_page(
        request: &WorkspaceStatusPageRequest,
    ) -> Result<WorkspaceStatusPage, CliError> {
        workspace_status_page_fenced(request, &mut TestWatcher::default())
    }

    fn acquire_test_read_lease(root: &Path) -> retention::GenerationReadLease {
        let _lock = MutationLock::acquire(root).unwrap();
        let (index, metadata, active, _, _, _) = load_active(root, false).unwrap();
        retention::acquire_generation_read_lease(&index, &metadata, &active).unwrap()
    }

    fn build_one_file_generation(root: &TestRoot) -> WorkspaceIndexReport {
        let bytes = b"stable local content";
        root.write("Assets/lease.bin", bytes);
        let mut routes = TestRoutes::new(vec![baseline_entry(
            900,
            "Assets/lease.bin",
            bytes,
            BaselineMaterialization::Full,
        )]);
        build(&root.0, &mut routes, &mut TestWatcher::default())
    }

    fn generation_artifacts_exist(root: &Path, generation_id: &str) -> bool {
        let index = root.join(".ogvcs/workspace-index-v1");
        artifact_names(generation_id)
            .iter()
            .all(|name| index.join(name).is_file())
    }

    mod repair_equivalence {
        use super::*;

        #[derive(Clone)]
        struct OracleFixture {
            baseline: Vec<WorkspaceBaselineEntry>,
            repository_rules: Vec<WorkspaceIgnoreRule>,
            local_rules: Vec<WorkspaceIgnoreRule>,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        struct PreservedNode {
            path: String,
            kind: &'static str,
            bytes: Vec<u8>,
            modified: Option<std::time::SystemTime>,
            readonly: bool,
            mode: u32,
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        struct OracleStatus {
            items: Vec<WorkspaceStatusItem>,
            status_counts: BTreeMap<String, u64>,
        }

        #[derive(Clone, Copy, Debug)]
        enum CorruptionClass {
            ActivePointer,
            GenerationSeal,
            Entries,
            Lookup,
            Findings,
            IgnoreSnapshot,
            WatcherState,
            EventChain,
            RetentionHistory,
            CursorKey,
            ReaderLease,
            TransitionControl,
            CompactionControl,
        }

        fn oracle_path(root: &Path, repository_path: &str) -> PathBuf {
            repository_path
                .split('/')
                .fold(root.to_path_buf(), |path, segment| path.join(segment))
        }

        fn oracle_sha256(bytes: &[u8]) -> String {
            let digest = Sha256::digest(bytes);
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut encoded = String::with_capacity(digest.len() * 2);
            for byte in digest {
                encoded.push(HEX[usize::from(byte >> 4)] as char);
                encoded.push(HEX[usize::from(byte & 0x0f)] as char);
            }
            encoded
        }

        fn oracle_executable(metadata: &fs::Metadata) -> bool {
            #[cfg(not(windows))]
            {
                metadata.permissions().mode() & 0o111 != 0
            }
            #[cfg(windows)]
            {
                let _ = metadata;
                false
            }
        }

        fn preserved_mode(metadata: &fs::Metadata) -> u32 {
            #[cfg(not(windows))]
            {
                metadata.permissions().mode()
            }
            #[cfg(windows)]
            {
                u32::from(metadata.permissions().readonly())
            }
        }

        fn snapshot_preserved_nodes(root: &Path) -> Vec<PreservedNode> {
            fn visit(directory: &Path, relative: &str, out: &mut Vec<PreservedNode>) {
                let mut entries = fs::read_dir(directory)
                    .unwrap()
                    .map(|entry| entry.unwrap())
                    .collect::<Vec<_>>();
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    let name = entry.file_name().into_string().unwrap();
                    let path = if relative.is_empty() {
                        name
                    } else {
                        format!("{relative}/{name}")
                    };
                    if path == ".ogvcs/workspace-index-v1" {
                        continue;
                    }
                    let absolute = entry.path();
                    let metadata = fs::symlink_metadata(&absolute).unwrap();
                    let (kind, bytes) = if metadata.file_type().is_symlink() {
                        (
                            "symlink",
                            fs::read_link(&absolute)
                                .unwrap()
                                .to_string_lossy()
                                .as_bytes()
                                .to_vec(),
                        )
                    } else if metadata.is_dir() {
                        ("directory", Vec::new())
                    } else if metadata.is_file() {
                        ("file", fs::read(&absolute).unwrap())
                    } else {
                        ("other", Vec::new())
                    };
                    out.push(PreservedNode {
                        path: path.clone(),
                        kind,
                        bytes,
                        modified: metadata.modified().ok(),
                        readonly: metadata.permissions().readonly(),
                        mode: preserved_mode(&metadata),
                    });
                    if metadata.is_dir() {
                        visit(&absolute, &path, out);
                    }
                }
            }

            let mut nodes = Vec::new();
            visit(root, "", &mut nodes);
            nodes
        }

        fn oracle_ignore(path: &str, fixture: &OracleFixture) -> (bool, Option<IgnoreExplanation>) {
            let mut decision = None;
            for rules in [&fixture.repository_rules, &fixture.local_rules] {
                for rule in rules {
                    let matches = match rule.pattern_kind {
                        IgnorePatternKind::Exact => path == rule.repository_path,
                        IgnorePatternKind::Subtree => {
                            path == rule.repository_path
                                || path
                                    .strip_prefix(&rule.repository_path)
                                    .is_some_and(|suffix| suffix.starts_with('/'))
                        }
                    };
                    if matches {
                        decision = Some(IgnoreExplanation {
                            rule_id: rule.rule_id.clone(),
                            source: rule.source,
                            action: rule.action,
                        });
                    }
                }
            }
            let ignored = decision
                .as_ref()
                .is_some_and(|rule| rule.action == IgnoreAction::Ignore);
            (ignored, decision)
        }

        fn oracle_baseline_item(
            root: &Path,
            entry: &WorkspaceBaselineEntry,
        ) -> Option<WorkspaceStatusItem> {
            let observed = fs::symlink_metadata(oracle_path(root, &entry.repository_path));
            let (status, content_verified) = match observed {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match entry.materialization {
                        BaselineMaterialization::Full => (WorkspaceStatus::Deleted, false),
                        BaselineMaterialization::MetadataOnly => {
                            (WorkspaceStatus::MetadataOnly, false)
                        }
                        BaselineMaterialization::AbsentBySpec => {
                            (WorkspaceStatus::AbsentBySpec, false)
                        }
                    }
                }
                Err(_) => (WorkspaceStatus::InaccessibleError, false),
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    (WorkspaceStatus::TypeModeChanged, false)
                }
                Ok(metadata) => {
                    let bytes = match fs::read(oracle_path(root, &entry.repository_path)) {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            return Some(WorkspaceStatusItem {
                                repository_path: entry.repository_path.clone(),
                                status: WorkspaceStatus::InaccessibleError,
                                prior_repository_path: None,
                                file_id: Some(entry.file_id.clone()),
                                ignore: None,
                                content_verified: false,
                            });
                        }
                    };
                    match entry.materialization {
                        BaselineMaterialization::Full
                            if bytes.len() as u64 != entry.content_bytes
                                || oracle_sha256(&bytes) != entry.content_sha256 =>
                        {
                            (WorkspaceStatus::Modified, true)
                        }
                        BaselineMaterialization::Full
                            if oracle_executable(&metadata) != entry.executable =>
                        {
                            (WorkspaceStatus::TypeModeChanged, true)
                        }
                        BaselineMaterialization::Full => return None,
                        BaselineMaterialization::MetadataOnly => {
                            (WorkspaceStatus::MetadataOnly, true)
                        }
                        BaselineMaterialization::AbsentBySpec => (WorkspaceStatus::Modified, true),
                    }
                }
            };
            Some(WorkspaceStatusItem {
                repository_path: entry.repository_path.clone(),
                status,
                prior_repository_path: None,
                file_id: Some(entry.file_id.clone()),
                ignore: None,
                content_verified,
            })
        }

        fn independent_full_scan_oracle(root: &Path, fixture: &OracleFixture) -> OracleStatus {
            fn visit_files(
                directory: &Path,
                relative: &str,
                observed: &mut BTreeMap<String, fs::Metadata>,
            ) {
                let mut entries = fs::read_dir(directory)
                    .unwrap()
                    .map(|entry| entry.unwrap())
                    .collect::<Vec<_>>();
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    let name = entry.file_name().into_string().unwrap();
                    if relative.is_empty()
                        && (name == ".ogvcs" || name == ".ogvcs-mutation-v2.lock")
                    {
                        continue;
                    }
                    let path = if relative.is_empty() {
                        name
                    } else {
                        format!("{relative}/{name}")
                    };
                    let metadata = fs::symlink_metadata(entry.path()).unwrap();
                    if metadata.is_dir() && !metadata.file_type().is_symlink() {
                        visit_files(&entry.path(), &path, observed);
                    } else {
                        observed.insert(path, metadata);
                    }
                }
            }

            let baseline_by_path = fixture
                .baseline
                .iter()
                .map(|entry| (entry.repository_path.as_str(), entry))
                .collect::<BTreeMap<_, _>>();
            let mut items = fixture
                .baseline
                .iter()
                .filter_map(|entry| oracle_baseline_item(root, entry))
                .collect::<Vec<_>>();
            let mut observed = BTreeMap::new();
            visit_files(root, "", &mut observed);
            for (path, metadata) in observed {
                if baseline_by_path.contains_key(path.as_str()) {
                    continue;
                }
                let (ignored, explanation) = oracle_ignore(&path, fixture);
                let (status, content_verified) = if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || fs::read(oracle_path(root, &path)).is_err()
                {
                    (WorkspaceStatus::InaccessibleError, false)
                } else if ignored {
                    (WorkspaceStatus::Ignored, true)
                } else {
                    (WorkspaceStatus::Untracked, true)
                };
                items.push(WorkspaceStatusItem {
                    repository_path: path,
                    status,
                    prior_repository_path: None,
                    file_id: None,
                    ignore: explanation,
                    content_verified,
                });
            }
            let binding = binding();
            items.sort_by_key(|item| {
                let keys = path_collision_keys(
                    &item.repository_path,
                    &binding.path_profile,
                    &binding.case_mode,
                )
                .unwrap();
                (keys.platform_key().to_owned(), item.repository_path.clone())
            });
            let mut status_counts = BTreeMap::new();
            for item in &items {
                *status_counts
                    .entry(item.status.as_str().to_owned())
                    .or_insert(0) += 1;
            }
            OracleStatus {
                items,
                status_counts,
            }
        }

        fn fixture(root: &TestRoot) -> OracleFixture {
            root.write("Game/clean.bin", b"clean");
            root.write("Game/modified.bin", b"locally changed");
            fs::create_dir_all(root.0.join("Game/type.bin")).unwrap();
            root.write("Virtual/present.bin", b"materialized unexpectedly");
            root.write("Loose/untracked.bin", b"untracked");
            root.write("Cache/ignored.bin", b"ignored");
            root.write("Cache/keep.bin", b"included locally");
            for ordinal in 0..23u8 {
                let path = format!("Bulk/item-{ordinal:03}.bin");
                let bytes = format!("local-{ordinal:03}");
                root.write(&path, bytes.as_bytes());
            }
            initialize_workspace(&root.0);
            OracleFixture {
                baseline: vec![
                    baseline_entry(1, "Game/clean.bin", b"clean", BaselineMaterialization::Full),
                    baseline_entry(
                        2,
                        "Game/modified.bin",
                        b"baseline",
                        BaselineMaterialization::Full,
                    ),
                    baseline_entry(
                        3,
                        "Game/deleted.bin",
                        b"deleted",
                        BaselineMaterialization::Full,
                    ),
                    baseline_entry(4, "Game/type.bin", b"file", BaselineMaterialization::Full),
                    baseline_entry(
                        5,
                        "Virtual/metadata.bin",
                        b"metadata",
                        BaselineMaterialization::MetadataOnly,
                    ),
                    baseline_entry(
                        6,
                        "Virtual/absent.bin",
                        b"absent",
                        BaselineMaterialization::AbsentBySpec,
                    ),
                    baseline_entry(
                        7,
                        "Virtual/present.bin",
                        b"absent",
                        BaselineMaterialization::AbsentBySpec,
                    ),
                ],
                repository_rules: vec![WorkspaceIgnoreRule {
                    rule_id: "repository-cache".to_owned(),
                    source: IgnoreSource::Repository,
                    action: IgnoreAction::Ignore,
                    pattern_kind: IgnorePatternKind::Subtree,
                    repository_path: "Cache".to_owned(),
                }],
                local_rules: vec![WorkspaceIgnoreRule {
                    rule_id: "local-cache-keep".to_owned(),
                    source: IgnoreSource::Local,
                    action: IgnoreAction::Include,
                    pattern_kind: IgnorePatternKind::Exact,
                    repository_path: "Cache/keep.bin".to_owned(),
                }],
            }
        }

        fn authenticated_rebuild(
            root: &Path,
            fixture: &OracleFixture,
            continuity: bool,
        ) -> Result<WorkspaceIndexReport, CliError> {
            let mut routes = TestRoutes::new(fixture.baseline.clone());
            routes.repository_rules = fixture.repository_rules.clone();
            routes.chunk_items = 3;
            let mut request = request(root);
            request.local_ignore_rules = fixture.local_rules.clone();
            let mut watcher = TestWatcher {
                continuity,
                queued: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Game/modified.bin".to_owned(),
                    prior_repository_path: None,
                }],
                ..TestWatcher::default()
            };
            rebuild_workspace_index(
                &request,
                &TestProvider,
                &mut routes,
                &mut watcher,
                &NeverCancelled,
                &mut DiscardProgress,
            )
        }

        fn collect_pages(root: &Path, limit: usize) -> Vec<WorkspaceStatusPage> {
            let mut pages = Vec::new();
            let mut cursor = None;
            loop {
                let mut request = status_request(root, limit);
                request.cursor = cursor;
                let page = test_status_page(&request).unwrap();
                assert!(page.items.len() <= limit);
                cursor = page.next_cursor.clone();
                pages.push(page);
                assert!(pages.len() <= MAX_STATUS_CANDIDATES / limit + 2);
                if cursor.is_none() {
                    break;
                }
            }
            pages
        }

        fn assert_complete_stream_matches_oracle(
            root: &Path,
            oracle: &OracleStatus,
            page_limit: usize,
            complete: bool,
            reason: &str,
        ) {
            let pages = collect_pages(root, page_limit);
            let expected_pages = oracle.items.len().div_ceil(page_limit).max(1);
            assert_eq!(pages.len(), expected_pages);
            let generation = pages[0].generation;
            for (ordinal, page) in pages.iter().enumerate() {
                assert_eq!(page.generation, generation);
                assert_eq!(page.candidate_count, oracle.items.len() as u64);
                assert_eq!(page.status_counts, oracle.status_counts);
                assert_eq!(page.complete, complete);
                assert_eq!(page.reconciliation_required, !complete);
                assert!(!page.authoritative_clean);
                assert_eq!(page.reason, reason);
                assert_eq!(page.next_cursor.is_some(), ordinal + 1 < pages.len());
            }
            let actual = pages
                .iter()
                .flat_map(|page| page.items.clone())
                .collect::<Vec<_>>();
            assert_eq!(actual, oracle.items);
            // The same stable authority and filesystem must emit the exact
            // same pages and opaque cursors on a second complete traversal.
            assert_eq!(collect_pages(root, page_limit), pages);
        }

        fn flip_first_byte(path: &Path) {
            let mut bytes = fs::read(path).unwrap();
            assert!(!bytes.is_empty());
            bytes[0] ^= 1;
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }

        fn write_corrupt_control(path: &Path) {
            let mut file = crate::create_private_file(path, true).unwrap();
            file.write_all(b"{corrupt-control\n").unwrap();
            file.sync_all().unwrap();
            sync_directory(path.parent().unwrap()).unwrap();
        }

        fn corrupt(root: &Path, class: CorruptionClass) {
            let index = existing_index_directory(root).unwrap();
            let active = read_optional_active(&index).unwrap().unwrap();
            let seal: GenerationSeal = read_json_private(
                &index.join(format!("seal-{}.v1", active.payload.generation_id)),
                MAX_CONTROL_BYTES,
            )
            .unwrap();
            let path = match class {
                CorruptionClass::ActivePointer => index.join("active.json"),
                CorruptionClass::GenerationSeal => {
                    index.join(format!("seal-{}.v1", active.payload.generation_id))
                }
                CorruptionClass::Entries => index.join(&seal.payload.entries.name),
                CorruptionClass::Lookup => index.join(&seal.payload.lookup.name),
                CorruptionClass::Findings => index.join(&seal.payload.findings.name),
                CorruptionClass::IgnoreSnapshot => index.join(&seal.payload.ignores.name),
                CorruptionClass::WatcherState => {
                    index.join(format!("watcher-{}.v1", active.payload.generation_id))
                }
                CorruptionClass::EventChain => index.join(&seal.payload.events_name),
                CorruptionClass::RetentionHistory => index.join("retention-v1.json"),
                CorruptionClass::CursorKey => index.join(CURSOR_KEY_NAME),
                CorruptionClass::ReaderLease => {
                    let lease = acquire_test_read_lease(root);
                    let path = lease.path_for_test().to_path_buf();
                    lease.abandon_for_test();
                    path
                }
                CorruptionClass::TransitionControl => {
                    let path = index.join("transition.json");
                    write_corrupt_control(&path);
                    return;
                }
                CorruptionClass::CompactionControl => {
                    let path = index.join("compaction-v1.json");
                    write_corrupt_control(&path);
                    return;
                }
            };
            flip_first_byte(&path);
            sync_directory(path.parent().unwrap()).unwrap();
        }

        fn index_names(root: &Path) -> Vec<String> {
            let index = existing_index_directory(root).unwrap();
            let mut names = fs::read_dir(index)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect::<Vec<_>>();
            names.sort();
            names
        }

        #[test]
        fn status_candidate_memory_bound_is_enforced_before_distinct_admission() {
            let candidate = |path: &str| StatusCandidate {
                path: path.to_owned(),
                prior_path: None,
                hint: WorkspaceStatus::Untracked,
                event_kind: None,
                saw_created: false,
                saw_deleted: false,
                staged_file_id: None,
            };
            let mut candidates = BTreeMap::new();
            for path in ["a", "b"] {
                bounded_status_candidate(
                    &mut candidates,
                    (path.to_owned(), path.to_owned()),
                    candidate(path),
                    2,
                )
                .unwrap();
            }
            // Reusing an existing key at the exact bound is not another
            // allocation, while the first distinct over-limit key is rejected.
            bounded_status_candidate(
                &mut candidates,
                ("a".to_owned(), "a".to_owned()),
                candidate("a"),
                2,
            )
            .unwrap();
            let error = match bounded_status_candidate(
                &mut candidates,
                ("c".to_owned(), "c".to_owned()),
                candidate("c"),
                2,
            ) {
                Ok(_) => panic!("distinct over-limit candidate was admitted"),
                Err(error) => error,
            };
            assert_eq!(error.code, "WORKSPACE_INDEX_INVALID");
            assert_eq!(candidates.len(), 2);

            // Sealed findings historically use last-record-wins replacement.
            // Preserve that compatibility while enforcing the same bound
            // before the first distinct allocation.
            bounded_replace_status_candidate(
                &mut candidates,
                ("a".to_owned(), "a".to_owned()),
                candidate("replacement"),
                2,
            )
            .unwrap();
            assert_eq!(
                candidates
                    .get(&("a".to_owned(), "a".to_owned()))
                    .unwrap()
                    .path,
                "replacement"
            );
            let error = bounded_replace_status_candidate(
                &mut candidates,
                ("d".to_owned(), "d".to_owned()),
                candidate("d"),
                2,
            )
            .unwrap_err();
            assert_eq!(error.code, "WORKSPACE_INDEX_INVALID");
            assert_eq!(candidates.len(), 2);
        }

        #[test]
        fn repair_matches_an_independent_full_scan_across_complete_bounded_pages() {
            let root = TestRoot::new("repair-independent-oracle");
            let fixture = fixture(&root);
            let initial = authenticated_rebuild(&root.0, &fixture, true).unwrap();
            let oracle = independent_full_scan_oracle(&root.0, &fixture);
            assert!(oracle.items.len() > 23);
            let before = snapshot_preserved_nodes(&root.0);
            for invalid_limit in [0, MAX_STATUS_PAGE_ITEMS + 1] {
                assert_eq!(
                    test_status_page(&status_request(&root.0, invalid_limit))
                        .unwrap_err()
                        .code,
                    "INPUT_INVALID"
                );
            }

            let repaired =
                repair_workspace_index(&root.0, &mut TestWatcher::default(), &NeverCancelled)
                    .unwrap();
            assert_eq!(repaired.generation, initial.generation + 1);
            assert_eq!(repaired.queued_event_count, 0);
            assert_eq!(snapshot_preserved_nodes(&root.0), before);
            assert_complete_stream_matches_oracle(
                &root.0,
                &oracle,
                7,
                true,
                "current-native-cursor",
            );
            assert_eq!(snapshot_preserved_nodes(&root.0), before);
            verify_workspace_index(&root.0).unwrap();
        }

        #[test]
        fn repair_preserves_degraded_watcher_uncertainty_while_matching_the_oracle() {
            let root = TestRoot::new("repair-independent-degraded");
            let fixture = fixture(&root);
            authenticated_rebuild(&root.0, &fixture, false).unwrap();
            let oracle = independent_full_scan_oracle(&root.0, &fixture);
            let before = snapshot_preserved_nodes(&root.0);

            let mut degraded = TestWatcher {
                continuity: false,
                ..TestWatcher::default()
            };
            let repaired = repair_workspace_index(&root.0, &mut degraded, &NeverCancelled).unwrap();
            assert!(repaired.reconciliation_required);
            assert!(!repaired.authoritative_clean);
            assert_eq!(repaired.reason, "unsupported-resume");
            assert_complete_stream_matches_oracle(
                &root.0,
                &oracle,
                11,
                false,
                "unsupported-resume",
            );
            assert_eq!(snapshot_preserved_nodes(&root.0), before);
        }

        #[test]
        fn authenticated_rebuild_replaces_only_reconstructible_corrupt_watcher_artifacts() {
            for class in [CorruptionClass::WatcherState, CorruptionClass::EventChain] {
                let root = TestRoot::new(&format!("repair-reconstructible-{class:?}"));
                let fixture = fixture(&root);
                let initial = authenticated_rebuild(&root.0, &fixture, true).unwrap();
                let oracle = independent_full_scan_oracle(&root.0, &fixture);
                let before = snapshot_preserved_nodes(&root.0);
                corrupt(&root.0, class);

                assert_eq!(
                    repair_workspace_index(&root.0, &mut TestWatcher::default(), &NeverCancelled,)
                        .unwrap_err()
                        .code,
                    "WORKSPACE_INDEX_INVALID",
                    "class={class:?}"
                );
                assert!(test_status_page(&status_request(&root.0, 7)).is_err());
                let rebuilt = authenticated_rebuild(&root.0, &fixture, true).unwrap();
                assert_eq!(rebuilt.generation, initial.generation + 1);
                assert_eq!(snapshot_preserved_nodes(&root.0), before);
                assert_complete_stream_matches_oracle(
                    &root.0,
                    &oracle,
                    7,
                    true,
                    "current-native-cursor",
                );
                assert_eq!(snapshot_preserved_nodes(&root.0), before);
                verify_workspace_index(&root.0).unwrap();
            }
        }

        #[test]
        fn non_reconstructible_corruption_fails_closed_before_a_new_generation() {
            let cases = [
                (CorruptionClass::ActivePointer, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::GenerationSeal, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::Entries, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::Lookup, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::Findings, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::IgnoreSnapshot, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::RetentionHistory, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::CursorKey, "WORKSPACE_INDEX_INVALID"),
                (CorruptionClass::ReaderLease, "WORKSPACE_INDEX_INVALID"),
                (
                    CorruptionClass::TransitionControl,
                    "WORKSPACE_INDEX_RECOVERY_REQUIRED",
                ),
                (
                    CorruptionClass::CompactionControl,
                    "WORKSPACE_INDEX_RECOVERY_REQUIRED",
                ),
            ];
            for (class, expected) in cases {
                let root = TestRoot::new(&format!("repair-fail-closed-{class:?}"));
                let fixture = fixture(&root);
                authenticated_rebuild(&root.0, &fixture, true).unwrap();
                let before = snapshot_preserved_nodes(&root.0);
                corrupt(&root.0, class);
                let names = index_names(&root.0);

                assert_eq!(
                    repair_workspace_index(&root.0, &mut TestWatcher::default(), &NeverCancelled,)
                        .unwrap_err()
                        .code,
                    expected,
                    "repair class={class:?}"
                );
                assert_eq!(
                    authenticated_rebuild(&root.0, &fixture, true)
                        .unwrap_err()
                        .code,
                    expected,
                    "rebuild class={class:?}"
                );
                assert!(
                    test_status_page(&status_request(&root.0, 7)).is_err(),
                    "status class={class:?}"
                );
                if matches!(
                    class,
                    CorruptionClass::TransitionControl | CorruptionClass::CompactionControl
                ) {
                    assert_eq!(
                        recover_workspace_index(&root.0).unwrap_err().code,
                        "WORKSPACE_INDEX_INVALID",
                        "recovery class={class:?}"
                    );
                }
                assert_eq!(index_names(&root.0), names, "class={class:?}");
                assert_eq!(snapshot_preserved_nodes(&root.0), before, "class={class:?}");
            }
        }
    }

    #[test]
    fn rebuild_classifies_complete_set_and_pages_with_bound_cursor() {
        let root = TestRoot::new("status");
        root.write("Game/clean.bin", b"clean");
        root.write("Game/modified.bin", b"changed");
        root.write("Game/type.bin", b"type");
        root.write("Loose/untracked.bin", b"untracked");
        root.write("Cache/ignored.bin", b"ignored");
        root.write("Moves/new.bin", b"move");
        root.write("Conflicts/conflict.bin", b"conflict");
        root.write("Added/new.bin", b"added");
        initialize_workspace(&root.0);

        #[cfg(not(windows))]
        fs::set_permissions(
            root.0.join("Game/type.bin"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let mut routes = TestRoutes::new(vec![
            baseline_entry(1, "Game/clean.bin", b"clean", BaselineMaterialization::Full),
            baseline_entry(
                2,
                "Game/modified.bin",
                b"expected",
                BaselineMaterialization::Full,
            ),
            baseline_entry(
                3,
                "Game/deleted.bin",
                b"gone",
                BaselineMaterialization::Full,
            ),
            baseline_entry(4, "Game/type.bin", b"type", BaselineMaterialization::Full),
            baseline_entry(
                5,
                "Virtual/metadata.bin",
                b"meta",
                BaselineMaterialization::MetadataOnly,
            ),
            baseline_entry(
                6,
                "Virtual/absent.bin",
                b"absent",
                BaselineMaterialization::AbsentBySpec,
            ),
            baseline_entry(7, "Moves/old.bin", b"move", BaselineMaterialization::Full),
        ]);
        routes.repository_rules = vec![WorkspaceIgnoreRule {
            rule_id: "repo-cache".to_owned(),
            source: IgnoreSource::Repository,
            action: IgnoreAction::Ignore,
            pattern_kind: IgnorePatternKind::Subtree,
            repository_path: "Cache".to_owned(),
        }];
        let mut watcher = TestWatcher {
            queued: vec![
                WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Renamed,
                    repository_path: "Moves/new.bin".to_owned(),
                    prior_repository_path: Some("Moves/old.bin".to_owned()),
                },
                WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Conflict,
                    repository_path: "Conflicts/conflict.bin".to_owned(),
                    prior_repository_path: None,
                },
                WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Created,
                    repository_path: "Added/new.bin".to_owned(),
                    prior_repository_path: None,
                },
            ],
            ..TestWatcher::default()
        };
        let report = build(&root.0, &mut routes, &mut watcher);
        assert!(report.initial_finding_count >= 7);
        assert!(!report.authoritative_clean);

        let first = test_status_page(&status_request(&root.0, 3)).unwrap();
        assert!(first.complete);
        assert!(!first.authoritative_clean);
        assert_eq!(first.items.len(), 3);
        assert!(first.next_cursor.is_some());
        for expected in [
            "modified",
            "added",
            "deleted",
            "untracked",
            "ignored",
            "metadata-only",
            "absent-by-spec",
            "moved-renamed-hint",
            "conflicted",
        ] {
            assert!(
                first.status_counts.contains_key(expected),
                "missing {expected}"
            );
        }
        #[cfg(not(windows))]
        assert!(first.status_counts.contains_key("type-mode-changed"));

        let mut second_request = status_request(&root.0, 100);
        second_request.cursor = first.next_cursor.clone();
        let second = test_status_page(&second_request).unwrap();
        assert!(!second.items.is_empty());
        let mut changed_filter = second_request.clone();
        changed_filter.filter.include_ignored = false;
        let error = test_status_page(&changed_filter).unwrap_err();
        assert_eq!(error.code, "WORKSPACE_STATUS_CURSOR_STALE");

        let (index, metadata, active, seal, watcher, _) = load_active(&root.0, false).unwrap();
        let staging = read_validated_staging_snapshot(&root.0, &metadata.binding).unwrap();
        let key = read_cursor_key(&index).unwrap();
        let mut changed_ignores = seal.payload.clone();
        changed_ignores.local_ignore_rules_sha256 = "f".repeat(64);
        assert_eq!(
            decode_status_cursor(
                first.next_cursor.as_deref().unwrap(),
                &StatusCursorContext {
                    active: &active,
                    seal: &changed_ignores,
                    watcher: &watcher,
                    staging_generation: staging.state.generation,
                    staging_state_sha256: &staging.state_sha256,
                    binding: &metadata.binding,
                    filter_sha256: &json_digest(&WorkspaceStatusFilter::default()).unwrap(),
                },
                &key,
            )
            .unwrap_err()
            .code,
            "WORKSPACE_STATUS_CURSOR_STALE"
        );

        let mut tampered = second_request;
        tampered.cursor.as_mut().unwrap().replace_range(0..2, "00");
        assert!(test_status_page(&tampered).is_err());
        verify_workspace_index(&root.0).unwrap();
    }

    #[test]
    fn portable_watcher_never_claims_authoritative_clean() {
        let root = TestRoot::new("portable-degraded");
        root.write("Game/clean.bin", b"clean");
        initialize_workspace(&root.0);
        let mut routes = TestRoutes::new(vec![baseline_entry(
            1,
            "Game/clean.bin",
            b"clean",
            BaselineMaterialization::Full,
        )]);
        let report = rebuild_workspace_index(
            &request(&root.0),
            &TestProvider,
            &mut routes,
            &mut UnavailableWorkspaceWatcher,
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();
        assert!(report.reconciliation_required);
        assert!(!report.authoritative_clean);
        assert_eq!(report.reason, "unsupported-resume");
        let status = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(!status.complete);
        assert!(!status.authoritative_clean);
    }

    #[test]
    fn closed_but_continuous_watcher_state_cannot_bypass_public_fence() {
        let root = TestRoot::new("closed-continuous-status");
        root.write("Game/clean.bin", b"clean");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/clean.bin",
                b"clean",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );

        {
            let _lock = MutationLock::acquire(&root.0).unwrap();
            let (index, _, active, _, mut watcher, _) = load_active(&root.0, false).unwrap();
            assert!(watcher_state_is_authoritative(&watcher.payload));
            watcher.payload.session_open = false;
            watcher.payload_sha256 = json_digest(&watcher.payload).unwrap();
            write_json_atomic(
                &index.join(format!("watcher-{}.v1", active.payload.generation_id)),
                &watcher,
            )
            .unwrap();
            sync_directory(&index).unwrap();
        }

        assert_eq!(
            workspace_status_page(&status_request(&root.0, 100))
                .unwrap_err()
                .code,
            "WORKSPACE_INDEX_INVALID"
        );
        assert_eq!(fs::read(root.0.join("Game/clean.bin")).unwrap(), b"clean");
    }

    #[test]
    fn scan_completes_before_final_barrier_and_covers_both_sides() {
        let root = TestRoot::new("scan-before-barrier");
        root.write("Game/tracked.bin", b"tracked");
        initialize_workspace(&root.0);
        let mut routes = TestRoutes::new(vec![baseline_entry(
            1,
            "Game/tracked.bin",
            b"tracked",
            BaselineMaterialization::Full,
        )]);
        let report = rebuild_workspace_index(
            &request(&root.0),
            &TestProvider,
            &mut routes,
            &mut OrderingWatcher {
                root: root.0.clone(),
            },
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();
        assert_eq!(report.initial_finding_count, 1);
        assert_eq!(report.queued_event_count, 1);

        let status = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(status.complete);
        assert!(status.items.iter().any(|item| {
            item.repository_path == "Untracked/during-subscribe.bin"
                && item.status == WorkspaceStatus::Untracked
        }));
        assert!(status.items.iter().any(|item| {
            item.repository_path == "Untracked/during-barrier.bin"
                && item.status == WorkspaceStatus::Added
        }));

        let lock = MutationLock::acquire(&root.0).unwrap();
        let mut premature =
            GenerationWriter::begin(&root.0, read_ready_metadata(&root.0).unwrap(), Vec::new())
                .unwrap();
        assert_eq!(
            premature
                .append_watch_chunk(&[WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Created,
                    repository_path: "Untracked/too-early.bin".to_owned(),
                    prior_repository_path: None,
                }])
                .unwrap_err()
                .code,
            "WORKSPACE_INDEX_INVALID"
        );
        drop(premature);
        drop(lock);
    }

    #[test]
    fn status_fence_appends_missed_event_before_classification() {
        let root = TestRoot::new("status-fence-event");
        root.write("Game/value.bin", b"old");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/value.bin",
                b"old",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );
        fs::write(root.0.join("Game/value.bin"), b"new").unwrap();
        let mut authority = TestWatcher {
            fence_batches: vec![WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Game/value.bin".to_owned(),
                    prior_repository_path: None,
                }],
            }],
            ..TestWatcher::default()
        };
        let page =
            workspace_status_page_fenced(&status_request(&root.0, 100), &mut authority).unwrap();
        assert!(page.complete);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].status, WorkspaceStatus::Modified);
        let (_, _, _, _, watcher, _) = load_active(&root.0, false).unwrap();
        assert_eq!(watcher.payload.cursor, "cursor.2");
        assert_eq!(watcher.payload.event_count, 1);
        assert_eq!(watcher.payload.reason, "current-native-cursor");
    }

    #[test]
    fn final_native_barrier_rejects_event_withheld_during_clean_scan() {
        let root = TestRoot::new("final-status-fence");
        root.write("Game/value.bin", b"old");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/value.bin",
                b"old",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *STATUS_AFTER_LOAD_HOOK.lock().unwrap() = Some(StatusAfterLoadHook {
            index: existing_index_directory(&root.0).unwrap(),
            entered: entered.clone(),
            release: release.clone(),
        });
        let worker_root = root.0.clone();
        let worker = thread::spawn(move || {
            workspace_status_page_fenced(
                &status_request(&worker_root, 100),
                &mut WithheldStatusWatcher { fences: 0 },
            )
        });
        entered.wait();
        fs::write(root.0.join("Game/value.bin"), b"new").unwrap();
        release.wait();
        assert_eq!(
            worker.join().unwrap().unwrap_err().code,
            "WORKSPACE_STATUS_SNAPSHOT_CHANGED"
        );
        let (_, _, _, _, watcher, _) = load_active(&root.0, false).unwrap();
        assert_eq!(watcher.payload.event_count, 1);
        assert_eq!(watcher.payload.cursor, "cursor.withheld");

        let retry = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(!retry.authoritative_clean);
        assert_eq!(retry.items.len(), 1);
        assert_eq!(retry.items[0].status, WorkspaceStatus::Modified);
    }

    #[test]
    fn unsupported_status_fence_closes_but_does_not_relabel_clean_session() {
        let root = TestRoot::new("unsupported-status-fence");
        root.write("Game/value.bin", b"value");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/value.bin",
                b"value",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );
        let (_, _, _, _, before, _) = load_active(&root.0, false).unwrap();
        assert_eq!(before.payload.reason, "current-native-cursor");

        let page = workspace_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(!page.complete);
        assert!(!page.authoritative_clean);
        assert_eq!(page.reason, "status-fence-unavailable");
        let (_, _, _, _, after, _) = load_active(&root.0, false).unwrap();
        assert!(!after.payload.continuity_proven);
        assert!(!after.payload.session_open);
        assert_eq!(after.payload.cursor, before.payload.cursor);
        assert_eq!(after.payload.session_id, before.payload.session_id);
        assert_eq!(after.payload.reason, "status-fence-unavailable");

        let digest = after.payload_sha256;
        let second = workspace_status_page(&status_request(&root.0, 100)).unwrap();
        assert_eq!(second.reason, "status-fence-unavailable");
        let (_, _, _, _, stable, _) = load_active(&root.0, false).unwrap();
        assert_eq!(stable.payload_sha256, digest);
    }

    #[test]
    fn status_fence_gap_and_session_substitution_fail_degraded() {
        let gap_root = TestRoot::new("status-fence-gap");
        gap_root.write("Game/value.bin", b"value");
        initialize_workspace(&gap_root.0);
        let entry = baseline_entry(1, "Game/value.bin", b"value", BaselineMaterialization::Full);
        build(
            &gap_root.0,
            &mut TestRoutes::new(vec![entry.clone()]),
            &mut TestWatcher::default(),
        );
        let mut gap = TestWatcher {
            fence_batches: vec![WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "forged.cursor".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Game/value.bin".to_owned(),
                    prior_repository_path: None,
                }],
            }],
            ..TestWatcher::default()
        };
        let page =
            workspace_status_page_fenced(&status_request(&gap_root.0, 100), &mut gap).unwrap();
        assert!(!page.complete);
        assert_eq!(page.reason, "cursor-gap");

        let substitute_root = TestRoot::new("status-fence-substitution");
        substitute_root.write("Game/value.bin", b"value");
        initialize_workspace(&substitute_root.0);
        build(
            &substitute_root.0,
            &mut TestRoutes::new(vec![entry]),
            &mut TestWatcher::default(),
        );
        let mut substitute = TestWatcher {
            fence_session_id: Some("forged.session".to_owned()),
            ..TestWatcher::default()
        };
        let page =
            workspace_status_page_fenced(&status_request(&substitute_root.0, 100), &mut substitute)
                .unwrap();
        assert!(!page.complete);
        assert_eq!(page.reason, "status-fence-invalid");
        let (_, _, _, _, watcher, _) = load_active(&substitute_root.0, false).unwrap();
        assert!(!watcher.payload.session_open);
        assert_eq!(watcher.payload.cursor, "cursor.1");
    }

    #[test]
    fn page_cursor_rejects_watcher_append_between_pages() {
        let root = TestRoot::new("page-watcher-snapshot");
        root.write("Game/a.bin", b"changed-a");
        root.write("Game/b.bin", b"changed-b");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![
                baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full),
                baseline_entry(2, "Game/b.bin", b"b", BaselineMaterialization::Full),
            ]),
            &mut TestWatcher::default(),
        );
        let first = test_status_page(&status_request(&root.0, 1)).unwrap();
        let mut second_request = status_request(&root.0, 100);
        second_request.cursor = first.next_cursor;
        // This sorts before the already-returned `Game/a.bin`; accepting the
        // old cursor would permanently omit it from the paginated result.
        root.write("Aardvark/new.bin", b"new");
        let mut authority = TestWatcher {
            fence_batches: vec![WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Created,
                    repository_path: "Aardvark/new.bin".to_owned(),
                    prior_repository_path: None,
                }],
            }],
            ..TestWatcher::default()
        };
        assert_eq!(
            workspace_status_page_fenced(&second_request, &mut authority)
                .unwrap_err()
                .code,
            "WORKSPACE_STATUS_CURSOR_STALE"
        );
        let (_, _, _, _, watcher, _) = load_active(&root.0, false).unwrap();
        assert_eq!(watcher.payload.event_count, 1);
        assert_eq!(watcher.payload.cursor, "cursor.2");
    }

    #[test]
    fn idle_final_cursor_advance_is_bound_to_returned_page() {
        let root = TestRoot::new("idle-final-cursor");
        root.write("Game/a.bin", b"changed-a");
        root.write("Game/b.bin", b"changed-b");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![
                baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full),
                baseline_entry(2, "Game/b.bin", b"b", BaselineMaterialization::Full),
            ]),
            &mut TestWatcher::default(),
        );
        let mut authority = IdleAdvanceWatcher { fences: 0 };
        let first =
            workspace_status_page_fenced(&status_request(&root.0, 1), &mut authority).unwrap();
        let encoded = first.next_cursor.clone().unwrap();
        let bytes = encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]).unwrap() << 4) | hex_nibble(pair[1]).unwrap())
            .collect::<Vec<_>>();
        let cursor: StatusCursor = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cursor.payload.watcher_cursor, "idle.cursor.2");
        assert_eq!(cursor.payload.watcher_event_count, 0);

        let mut next = status_request(&root.0, 100);
        next.cursor = Some(encoded);
        let second = workspace_status_page_fenced(&next, &mut authority).unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(second.next_cursor.is_none());
        assert_eq!(authority.fences, 4);
        let (_, _, _, _, watcher, _) = load_active(&root.0, false).unwrap();
        assert_eq!(watcher.payload.cursor, "idle.cursor.4");
        assert_eq!(watcher.payload.event_count, 0);
    }

    #[test]
    fn page_cursor_rejects_watcher_authority_change_with_unchanged_transcript() {
        let root = TestRoot::new("page-watcher-authority");
        root.write("Game/a.bin", b"changed-a");
        root.write("Game/b.bin", b"changed-b");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![
                baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full),
                baseline_entry(2, "Game/b.bin", b"b", BaselineMaterialization::Full),
            ]),
            &mut TestWatcher::default(),
        );
        let first = test_status_page(&status_request(&root.0, 1)).unwrap();
        let mut next = status_request(&root.0, 100);
        next.cursor = first.next_cursor;

        {
            let _lock = MutationLock::acquire(&root.0).unwrap();
            let (index, _, active, _, mut watcher, _) = load_active(&root.0, false).unwrap();
            assert_eq!(watcher.payload.event_count, 0);
            assert_eq!(watcher.payload.event_bytes, 0);
            watcher.payload.session_id = "session.2".to_owned();
            watcher.payload_sha256 = json_digest(&watcher.payload).unwrap();
            write_json_atomic(
                &index.join(format!("watcher-{}.v1", active.payload.generation_id)),
                &watcher,
            )
            .unwrap();
            sync_directory(&index).unwrap();
        }

        assert_eq!(
            test_status_page(&next).unwrap_err().code,
            "WORKSPACE_STATUS_CURSOR_STALE"
        );
        let (_, _, _, _, watcher, _) = load_active(&root.0, false).unwrap();
        assert_eq!(watcher.payload.session_id, "session.2");
        assert_eq!(watcher.payload.event_count, 0);
        assert_eq!(watcher.payload.event_bytes, 0);
        assert_eq!(watcher.payload.event_tail_sha256, EMPTY_SHA256);
    }

    #[test]
    fn page_cursor_rejects_earlier_staging_snapshot_between_pages() {
        let root = TestRoot::new("page-staging-snapshot");
        root.write("Game/a.bin", b"changed-a");
        root.write("Game/b.bin", b"changed-b");
        initialize_workspace(&root.0);
        let mut routes = TestRoutes::new(vec![
            baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full),
            baseline_entry(2, "Game/b.bin", b"b", BaselineMaterialization::Full),
        ]);
        build(&root.0, &mut routes, &mut TestWatcher::default());
        let first = test_status_page(&status_request(&root.0, 1)).unwrap();
        let mut next = status_request(&root.0, 100);
        next.cursor = first.next_cursor;

        root.write("Aardvark/staged.bin", b"new");
        super::super::stage_add(
            &super::super::StageAddRequest {
                root: root.0.clone(),
                repository_path: "Aardvark/staged.bin".to_owned(),
                authentication: request(&root.0).authentication,
            },
            &TestProvider,
            &mut routes,
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();
        assert_eq!(
            test_status_page(&next).unwrap_err().code,
            "WORKSPACE_STATUS_CURSOR_STALE"
        );
    }

    #[test]
    fn applied_staging_seeds_add_move_delete_without_watcher_delivery() {
        let root = TestRoot::new("staging-status-candidates");
        root.write("Tracked/move-source.bin", b"move");
        root.write("Tracked/delete-source.bin", b"delete");
        initialize_workspace(&root.0);
        let entries = vec![
            baseline_entry(
                1,
                "Tracked/move-source.bin",
                b"move",
                BaselineMaterialization::Full,
            ),
            baseline_entry(
                2,
                "Tracked/delete-source.bin",
                b"delete",
                BaselineMaterialization::Full,
            ),
        ];
        let mut routes = TestRoutes::new(entries);
        build(&root.0, &mut routes, &mut TestWatcher::default());
        root.write("Added/new.bin", b"add");
        fs::create_dir(root.0.join("Moved")).unwrap();
        let authentication = request(&root.0).authentication;
        super::super::stage_add(
            &super::super::StageAddRequest {
                root: root.0.clone(),
                repository_path: "Added/new.bin".to_owned(),
                authentication: authentication.clone(),
            },
            &TestProvider,
            &mut routes,
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();
        super::super::stage_move(
            &super::super::StageMoveRequest {
                root: root.0.clone(),
                source_repository_path: "Tracked/move-source.bin".to_owned(),
                destination_repository_path: "Moved/move-destination.bin".to_owned(),
                authentication: authentication.clone(),
            },
            &TestProvider,
            &mut routes,
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();
        super::super::stage_delete(
            &super::super::StageDeleteRequest {
                root: root.0.clone(),
                repository_path: "Tracked/delete-source.bin".to_owned(),
                authentication,
            },
            &TestProvider,
            &mut routes,
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap();

        let page = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(page.complete);
        assert_eq!(page.candidate_count, 4);
        assert!(page.items.iter().any(|item| {
            item.repository_path == "Added/new.bin"
                && item.status == WorkspaceStatus::Added
                && item.file_id.as_deref() == Some("fid:00000000000000000000000000000001")
        }));
        assert!(page.items.iter().any(|item| {
            item.repository_path == "Moved/move-destination.bin"
                && item.prior_repository_path.as_deref() == Some("Tracked/move-source.bin")
                && item.status == WorkspaceStatus::MovedRenamedHint
                && item.file_id.as_deref() == Some("fid:00000000000000000000000000000002")
        }));
        for deleted in ["Tracked/move-source.bin", "Tracked/delete-source.bin"] {
            assert!(page.items.iter().any(|item| {
                item.repository_path == deleted && item.status == WorkspaceStatus::Deleted
            }));
        }
        let (_, _, _, _, watcher, _) = load_active(&root.0, false).unwrap();
        assert_eq!(watcher.payload.event_count, 0);
    }

    #[test]
    fn journal_gap_and_oversized_chunks_fail_closed_before_append() {
        let root = TestRoot::new("journal-bounds");
        root.write("Game/clean.bin", b"clean");
        initialize_workspace(&root.0);
        let mut routes = TestRoutes::new(vec![baseline_entry(
            1,
            "Game/clean.bin",
            b"clean",
            BaselineMaterialization::Full,
        )]);
        build(&root.0, &mut routes, &mut TestWatcher::default());
        let oversized = WorkspaceWatchBatch {
            session_id: "session.1".to_owned(),
            prior_cursor: "cursor.1".to_owned(),
            cursor: "cursor.2".to_owned(),
            events: (0..=MAX_WATCH_CHUNK_ITEMS)
                .map(|index| WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: format!("Game/{index:04}.bin"),
                    prior_repository_path: None,
                })
                .collect(),
        };
        let error = record_workspace_change_batch(&root.0, &oversized).unwrap_err();
        assert_eq!(error.code, "WORKSPACE_WATCH_CHUNK_LIMIT");
        let before = verify_workspace_index(&root.0).unwrap();
        assert_eq!(before.queued_event_count, 0);

        let gap = WorkspaceWatchBatch {
            session_id: "session.1".to_owned(),
            prior_cursor: "wrong".to_owned(),
            cursor: "cursor.2".to_owned(),
            events: vec![WorkspaceWatchEvent {
                kind: WorkspaceWatchEventKind::Modified,
                repository_path: "Game/clean.bin".to_owned(),
                prior_repository_path: None,
            }],
        };
        let error = record_workspace_change_batch(&root.0, &gap).unwrap_err();
        assert_eq!(error.code, "WORKSPACE_WATCHER_CURSOR_GAP");
        let degraded = verify_workspace_index(&root.0).unwrap();
        assert!(degraded.reconciliation_required);
        assert_eq!(degraded.queued_event_count, 0);
    }

    #[test]
    fn deleted_directory_is_conservative_but_transient_untracked_delete_is_clean() {
        let root = TestRoot::new("deleted-directory");
        root.write("Tracked/sub/file.bin", b"tracked");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Tracked/sub/file.bin",
                b"tracked",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );
        fs::remove_dir_all(root.0.join("Tracked")).unwrap();
        record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Deleted,
                    repository_path: "Tracked".to_owned(),
                    prior_repository_path: None,
                }],
            },
        )
        .unwrap();
        let status = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(!status.complete);
        assert!(!status.authoritative_clean);
        assert!(status.reconciliation_required);
        assert_eq!(status.reason, "deleted-path-descendants-unproven");
        assert!(status.items.iter().any(
            |item| item.repository_path == "Tracked" && item.status == WorkspaceStatus::Deleted
        ));

        // A create+delete pair in one continuous native session proves this
        // exact path was transient and never part of the immutable baseline.
        let repaired =
            repair_workspace_index(&root.0, &mut TestWatcher::default(), &NeverCancelled).unwrap();
        assert!(!repaired.authoritative_clean); // tracked descendant remains deleted
        record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![
                    WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Created,
                        repository_path: "Transient.tmp".to_owned(),
                        prior_repository_path: None,
                    },
                    WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Deleted,
                        repository_path: "Transient.tmp".to_owned(),
                        prior_repository_path: None,
                    },
                ],
            },
        )
        .unwrap();
        let status = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(status.complete);
        assert!(status
            .items
            .iter()
            .all(|item| item.repository_path != "Transient.tmp"));
    }

    #[test]
    fn synced_journal_tail_without_state_publication_is_never_ignored() {
        let root = TestRoot::new("journal-state-fault");
        root.write("Game/a.bin", b"a");
        initialize_workspace(&root.0);
        let entry = baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full);
        build(
            &root.0,
            &mut TestRoutes::new(vec![entry.clone()]),
            &mut TestWatcher::default(),
        );
        set_journal_state_fault();
        let error = record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Game/a.bin".to_owned(),
                    prior_repository_path: None,
                }],
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "WORKSPACE_WATCHER_INJECTED_STATE_FAULT");
        assert_eq!(
            test_status_page(&status_request(&root.0, 100))
                .unwrap_err()
                .code,
            "WORKSPACE_INDEX_INVALID"
        );
        assert_eq!(
            recover_workspace_index(&root.0).unwrap_err().code,
            "WORKSPACE_INDEX_INVALID"
        );
        // Authenticated rebuild publishes a fresh generation and never treats
        // the orphan tail as a clean continuation of the old generation.
        let rebuilt = build(
            &root.0,
            &mut TestRoutes::new(vec![entry]),
            &mut TestWatcher::default(),
        );
        assert_eq!(rebuilt.generation, 2);
        assert!(rebuilt.authoritative_clean);
    }

    #[test]
    fn event_touched_file_is_hashed_and_never_declared_clean_from_metadata_alone() {
        let root = TestRoot::new("timestamp-spoof");
        root.write("Game/value.bin", b"AAAA");
        initialize_workspace(&root.0);
        let mut routes = TestRoutes::new(vec![baseline_entry(
            1,
            "Game/value.bin",
            b"AAAA",
            BaselineMaterialization::Full,
        )]);
        build(&root.0, &mut routes, &mut TestWatcher::default());
        #[cfg(not(windows))]
        let original = fs::metadata(root.0.join("Game/value.bin")).unwrap();
        fs::write(root.0.join("Game/value.bin"), b"BBBB").unwrap();
        #[cfg(not(windows))]
        restore_file_times(&root.0.join("Game/value.bin"), &original);
        record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Game/value.bin".to_owned(),
                    prior_repository_path: None,
                }],
            },
        )
        .unwrap();
        let status = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert_eq!(status.items.len(), 1);
        assert_eq!(status.items[0].status, WorkspaceStatus::Modified);
        assert!(status.items[0].content_verified);
        assert!(!status.authoritative_clean);
    }

    #[cfg(not(windows))]
    fn restore_file_times(path: &Path, metadata: &fs::Metadata) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: metadata.atime(),
                tv_nsec: metadata.atime_nsec(),
            },
            libc::timespec {
                tv_sec: metadata.mtime(),
                tv_nsec: metadata.mtime_nsec(),
            },
        ];
        // SAFETY: the path is NUL-terminated and the two timespec values are valid.
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), 0) },
            0
        );
    }

    #[test]
    fn every_generation_crash_boundary_recovers_exactly_old_or_new_active() {
        let root = TestRoot::new("crash-boundaries");
        root.write("Game/value.bin", b"value");
        initialize_workspace(&root.0);
        let entry = baseline_entry(1, "Game/value.bin", b"value", BaselineMaterialization::Full);
        let first = build(
            &root.0,
            &mut TestRoutes::new(vec![entry.clone()]),
            &mut TestWatcher::default(),
        );
        assert_eq!(first.generation, 1);

        for point in [
            CrashPoint::TransitionPublished,
            CrashPoint::ArtifactsSynced,
            CrashPoint::SealSynced,
        ] {
            set_crash_point(point);
            let error = rebuild_workspace_index(
                &request(&root.0),
                &TestProvider,
                &mut TestRoutes::new(vec![entry.clone()]),
                &mut TestWatcher::default(),
                &NeverCancelled,
                &mut DiscardProgress,
            )
            .unwrap_err();
            assert_eq!(error.code, "WORKSPACE_INDEX_INJECTED_CRASH");
            let recovered = recover_workspace_index(&root.0).unwrap().unwrap();
            assert_eq!(recovered.generation, 1);
            assert!(recovered.reconciliation_required);
        }

        set_crash_point(CrashPoint::ActivePublished);
        let error = rebuild_workspace_index(
            &request(&root.0),
            &TestProvider,
            &mut TestRoutes::new(vec![entry]),
            &mut TestWatcher::default(),
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap_err();
        assert_eq!(error.code, "WORKSPACE_INDEX_INJECTED_CRASH");
        let recovered = recover_workspace_index(&root.0).unwrap().unwrap();
        assert_eq!(recovered.generation, 2);
        assert!(recovered.reconciliation_required);

        let index = existing_index_directory(&root.0).unwrap();
        let active = read_optional_active(&index).unwrap().unwrap();
        let name = format!("entries-{}.v1", active.payload.generation_id);
        let before = fs::read(index.join(&name)).unwrap();
        assert!(create_artifact(&index, &name).is_err());
        assert_eq!(fs::read(index.join(name)).unwrap(), before);
    }

    #[test]
    fn concurrent_status_fails_closed_during_transition_then_observes_new_generation() {
        let root = TestRoot::new("concurrent-old-new");
        root.write("Game/value.bin", b"value");
        initialize_workspace(&root.0);
        let entry = baseline_entry(1, "Game/value.bin", b"value", BaselineMaterialization::Full);
        let first = build(
            &root.0,
            &mut TestRoutes::new(vec![entry.clone()]),
            &mut TestWatcher::default(),
        );
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_root = root.0.clone();
        let worker_entered = entered.clone();
        let worker_release = release.clone();
        let worker = thread::spawn(move || {
            let mut routes = TestRoutes::new(vec![entry]);
            routes.entered = Some(worker_entered);
            routes.release = Some(worker_release);
            build(&worker_root, &mut routes, &mut TestWatcher::default())
        });
        entered.wait();
        root.write("Game/value.bin", b"changed");
        let during = test_status_page(&status_request(&root.0, 100)).unwrap_err();
        assert_eq!(during.code, "WORKSPACE_BUSY");
        release.wait();
        let second = worker.join().unwrap();
        let after = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert_eq!(after.generation, second.generation);
        assert_eq!(second.generation, first.generation + 1);
        assert!(!after.authoritative_clean);
        assert_eq!(after.items.len(), 1);
        assert_eq!(after.items[0].status, WorkspaceStatus::Modified);
    }

    #[test]
    fn status_final_barrier_fails_busy_when_transition_races_clean_return() {
        let root = TestRoot::new("status-after-load-seqlock");
        root.write("Game/value.bin", b"value");
        initialize_workspace(&root.0);
        let entry = baseline_entry(1, "Game/value.bin", b"value", BaselineMaterialization::Full);
        let first = build(
            &root.0,
            &mut TestRoutes::new(vec![entry.clone()]),
            &mut TestWatcher::default(),
        );
        assert!(first.authoritative_clean);

        let status_entered = Arc::new(Barrier::new(2));
        let status_release = Arc::new(Barrier::new(2));
        let expected_index = existing_index_directory(&root.0).unwrap();
        *STATUS_AFTER_LOAD_HOOK.lock().unwrap() = Some(StatusAfterLoadHook {
            index: expected_index,
            entered: status_entered.clone(),
            release: status_release.clone(),
        });
        let status_root = root.0.clone();
        let status_worker =
            thread::spawn(move || test_status_page(&status_request(&status_root, 100)));
        status_entered.wait();

        let writer_entered = Arc::new(Barrier::new(2));
        let writer_release = Arc::new(Barrier::new(2));
        let writer_root = root.0.clone();
        let writer_entered_clone = writer_entered.clone();
        let writer_release_clone = writer_release.clone();
        let writer = thread::spawn(move || {
            let mut routes = TestRoutes::new(vec![entry]);
            routes.entered = Some(writer_entered_clone);
            routes.release = Some(writer_release_clone);
            build(&writer_root, &mut routes, &mut TestWatcher::default())
        });
        writer_entered.wait();
        root.write("Game/value.bin", b"changed");

        status_release.wait();
        let error = status_worker.join().unwrap().unwrap_err();
        assert_eq!(error.code, "WORKSPACE_BUSY");

        writer_release.wait();
        let second = writer.join().unwrap();
        assert_eq!(second.generation, first.generation + 1);
        let after = test_status_page(&status_request(&root.0, 100)).unwrap();
        assert!(!after.authoritative_clean);
        assert_eq!(after.items.len(), 1);
        assert_eq!(after.items[0].status, WorkspaceStatus::Modified);
    }

    #[test]
    fn lookup_digest_match_never_substitutes_a_different_full_path() {
        let root = TestRoot::new("lookup-collision");
        root.write("Game/a.bin", b"a");
        root.write("Game/b.bin", b"b");
        initialize_workspace(&root.0);
        let mut routes = TestRoutes::new(vec![
            baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full),
            baseline_entry(2, "Game/b.bin", b"b", BaselineMaterialization::Full),
        ]);
        build(&root.0, &mut routes, &mut TestWatcher::default());
        let (index, metadata, _, seal, _, _) = load_active(&root.0, false).unwrap();
        let lookup_path = index.join(&seal.payload.lookup.name);
        let mut reader = LookupReader::open(&index, &seal.payload).unwrap();
        let first_record = reader.record(0).unwrap();
        let second_record = reader.record(1).unwrap();
        let first_path = reader
            .entry_from_record(&first_record)
            .unwrap()
            .repository_path;
        let (mut wrong, mut correct) = if first_path == "Game/b.bin" {
            (second_record, first_record)
        } else {
            (first_record, second_record)
        };
        let target_keys = path_collision_keys(
            "Game/b.bin",
            &metadata.binding.path_profile,
            &metadata.binding.case_mode,
        )
        .unwrap();
        let target = Sha256::digest(target_keys.platform_key().as_bytes());
        // Put the target digest on the first, different path record. Lookup
        // must inspect and reject that full-path mismatch before returning b.
        wrong[..32].copy_from_slice(&target);
        correct[..32].copy_from_slice(&target);
        let mut bytes = Vec::with_capacity(LOOKUP_RECORD_BYTES as usize * 2);
        bytes.extend_from_slice(&wrong);
        bytes.extend_from_slice(&correct);
        fs::write(&lookup_path, bytes).unwrap();
        reader.lookup = open_private_file(&lookup_path).unwrap();
        let found = reader
            .find("Game/b.bin", &metadata.binding)
            .unwrap()
            .unwrap();
        assert_eq!(found.repository_path, "Game/b.bin");
        assert_eq!(found.platform_key, target_keys.platform_key());
        assert_eq!(found.repository_key, target_keys.repository_key().as_str());
        assert!(reader
            .find("Game/a.bin", &metadata.binding)
            .unwrap()
            .is_none());
    }

    #[test]
    fn current_case_profile_settings_and_cursor_generation_are_exact() {
        let root = TestRoot::new("binding-stale");
        root.write("Game/a.bin", b"a");
        root.write("Loose/one.bin", b"one");
        root.write("Loose/two.bin", b"two");
        initialize_workspace(&root.0);
        let entry = baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full);
        build(
            &root.0,
            &mut TestRoutes::new(vec![entry.clone()]),
            &mut TestWatcher::default(),
        );
        let first_page = test_status_page(&status_request(&root.0, 1)).unwrap();
        let cursor = first_page.next_cursor.unwrap();
        let index = existing_index_directory(&root.0).unwrap();
        let original = read_optional_active(&index).unwrap().unwrap();

        for mutation in 0..3 {
            let mut changed = original.clone();
            match mutation {
                0 => changed.payload.case_mode = "case-sensitive".to_owned(),
                1 => changed.payload.path_profile = "path.opengamevcs/linux@1".to_owned(),
                _ => changed.payload.repository_settings_digest = "9".repeat(64),
            }
            changed.payload_sha256 = json_digest(&changed.payload).unwrap();
            write_json_atomic(&index.join("active.json"), &changed).unwrap();
            let error = test_status_page(&status_request(&root.0, 10)).unwrap_err();
            assert_eq!(error.code, "WORKSPACE_INDEX_BINDING_STALE");
        }
        write_json_atomic(&index.join("active.json"), &original).unwrap();
        build(
            &root.0,
            &mut TestRoutes::new(vec![entry]),
            &mut TestWatcher::default(),
        );
        let mut stale_cursor = status_request(&root.0, 10);
        stale_cursor.cursor = Some(cursor);
        let error = test_status_page(&stale_cursor).unwrap_err();
        assert_eq!(error.code, "WORKSPACE_STATUS_CURSOR_STALE");
    }

    #[cfg(not(windows))]
    #[test]
    fn links_at_index_and_generation_artifacts_fail_closed() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("links");
        root.write("Game/a.bin", b"a");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/a.bin",
                b"a",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );
        let index = existing_index_directory(&root.0).unwrap();
        let active = read_optional_active(&index).unwrap().unwrap();
        let seal: GenerationSeal = read_json_private(
            &index.join(format!("seal-{}.v1", active.payload.generation_id)),
            MAX_CONTROL_BYTES,
        )
        .unwrap();
        for name in [
            seal.payload.entries.name.clone(),
            seal.payload.lookup.name.clone(),
            seal.payload.events_name.clone(),
        ] {
            let path = index.join(&name);
            let backup = index.join(format!("backup-{name}"));
            fs::rename(&path, &backup).unwrap();
            symlink(&backup, &path).unwrap();
            assert!(test_status_page(&status_request(&root.0, 10)).is_err());
            fs::remove_file(&path).unwrap();
            fs::rename(&backup, &path).unwrap();
        }

        let control = root.0.join(".ogvcs");
        let moved = control.join("workspace-index-v1-backup");
        fs::rename(&index, &moved).unwrap();
        symlink(&moved, &index).unwrap();
        assert!(test_status_page(&status_request(&root.0, 10)).is_err());
        fs::remove_file(&index).unwrap();
        fs::rename(moved, index).unwrap();
    }

    #[test]
    fn same_length_generation_corruption_cannot_produce_warm_clean() {
        let root = TestRoot::new("same-length-corruption");
        root.write("Game/a.bin", b"a");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/a.bin",
                b"a",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );
        assert!(
            test_status_page(&status_request(&root.0, 10))
                .unwrap()
                .authoritative_clean
        );
        let (index, _, _, seal, _, _) = load_active(&root.0, false).unwrap();
        let entries_path = index.join(&seal.payload.entries.name);
        let mut bytes = fs::read(&entries_path).unwrap();
        let offset = bytes.len() / 2;
        bytes[offset] ^= 1;
        fs::write(entries_path, bytes).unwrap();
        assert_eq!(
            test_status_page(&status_request(&root.0, 10))
                .unwrap_err()
                .code,
            "WORKSPACE_INDEX_INVALID"
        );
    }

    #[test]
    fn repair_switches_generation_without_modifying_workspace_files() {
        let root = TestRoot::new("repair-preserves");
        root.write("Game/a.bin", b"a");
        initialize_workspace(&root.0);
        let entry = baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full);
        build(
            &root.0,
            &mut TestRoutes::new(vec![entry]),
            &mut TestWatcher::default(),
        );
        record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Game/a.bin".to_owned(),
                    prior_repository_path: None,
                }],
            },
        )
        .unwrap();
        let index = existing_index_directory(&root.0).unwrap();
        let prior_active = read_optional_active(&index).unwrap().unwrap();
        let prior_events = index.join(format!("events-{}.v1", prior_active.payload.generation_id));
        let before = fs::read(root.0.join("Game/a.bin")).unwrap();
        let repaired =
            repair_workspace_index(&root.0, &mut TestWatcher::default(), &NeverCancelled).unwrap();
        assert_eq!(repaired.queued_event_count, 0);
        assert_eq!(fs::read(root.0.join("Game/a.bin")).unwrap(), before);
        // Repair does not implicitly compact. Retention is an explicit bounded
        // operation so callers can observe and recover every deletion intent.
        assert!(prior_events.is_file());
        assert!(
            test_status_page(&status_request(&root.0, 100))
                .unwrap()
                .authoritative_clean
        );
    }

    #[test]
    fn active_reader_lease_pins_old_generation_until_drop_then_compacts() {
        let root = TestRoot::new("reader-pin");
        initialize_workspace(&root.0);
        let first = build_one_file_generation(&root);
        let index = existing_index_directory(&root.0).unwrap();
        let first_active = read_optional_active(&index).unwrap().unwrap();
        assert_eq!(first.generation, 1);
        let lease = acquire_test_read_lease(&root.0);

        build_one_file_generation(&root);
        build_one_file_generation(&root);
        let pinned = compact_workspace_index(&root.0).unwrap();
        assert_eq!(pinned.removed_generations, 0);
        assert_eq!(pinned.pinned_generations, 3);
        assert!(generation_artifacts_exist(
            &root.0,
            &first_active.payload.generation_id
        ));

        drop(lease);
        let compacted = compact_workspace_index(&root.0).unwrap();
        assert_eq!(compacted.removed_generations, 1);
        assert_eq!(compacted.removed_artifacts, 7);
        assert_eq!(compacted.retained_generations, 2);
        assert!(!generation_artifacts_exist(
            &root.0,
            &first_active.payload.generation_id
        ));
        assert_eq!(
            fs::read(root.0.join("Assets/lease.bin")).unwrap(),
            b"stable local content"
        );
        verify_workspace_index(&root.0).unwrap();
    }

    #[test]
    fn abandoned_reader_lease_expires_on_logical_epoch_and_is_reclaimed() {
        let root = TestRoot::new("reader-expiry");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        let index = existing_index_directory(&root.0).unwrap();
        let first_active = read_optional_active(&index).unwrap().unwrap();
        acquire_test_read_lease(&root.0).abandon_for_test();
        build_one_file_generation(&root);
        build_one_file_generation(&root);

        let report = compact_workspace_index(&root.0).unwrap();
        assert_eq!(report.reclaimed_leases, 1);
        assert_eq!(report.removed_generations, 1);
        assert!(!generation_artifacts_exist(
            &root.0,
            &first_active.payload.generation_id
        ));
        let lease_directory = index.join("reader-leases-v1");
        assert_eq!(fs::read_dir(lease_directory).unwrap().count(), 0);
    }

    #[test]
    fn owner_authenticated_cross_workspace_or_repository_lease_fails_before_delete() {
        for (workspace_digest, repository_id) in [
            ("8".repeat(64), binding().repository_id_hex),
            (digest_text("different-workspace"), "f".repeat(32)),
        ] {
            let root = TestRoot::new("cross-binding-lease");
            initialize_workspace(&root.0);
            build_one_file_generation(&root);
            let index = existing_index_directory(&root.0).unwrap();
            let first_active = read_optional_active(&index).unwrap().unwrap();
            let lease = acquire_test_read_lease(&root.0);
            let lease_path = lease.path_for_test().to_path_buf();
            lease.abandon_for_test();
            build_one_file_generation(&root);
            build_one_file_generation(&root);
            retention::rewrite_lease_binding_for_test(
                &index,
                &lease_path,
                &workspace_digest,
                &repository_id,
            );

            assert_eq!(
                compact_workspace_index(&root.0).unwrap_err().code,
                "WORKSPACE_INDEX_INVALID"
            );
            assert!(generation_artifacts_exist(
                &root.0,
                &first_active.payload.generation_id
            ));
            assert!(!index.join("compaction-v1.json").exists());
        }
    }

    #[test]
    fn forged_lease_mac_and_unknown_root_control_fail_before_compaction_intent() {
        for case in ["forged-lease-mac", "unknown-root-control"] {
            let root = TestRoot::new(case);
            initialize_workspace(&root.0);
            build_one_file_generation(&root);
            let index = existing_index_directory(&root.0).unwrap();
            let first_active = read_optional_active(&index).unwrap().unwrap();
            if case == "forged-lease-mac" {
                let lease = acquire_test_read_lease(&root.0);
                let lease_path = lease.path_for_test().to_path_buf();
                lease.abandon_for_test();
                build_one_file_generation(&root);
                build_one_file_generation(&root);
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&lease_path).unwrap()).unwrap();
                value["macSha256"] = serde_json::Value::String("0".repeat(64));
                let mut file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&lease_path)
                    .unwrap();
                serde_json::to_writer(&mut file, &value).unwrap();
                file.write_all(b"\n").unwrap();
                file.sync_all().unwrap();
            } else {
                build_one_file_generation(&root);
                build_one_file_generation(&root);
            }
            if case == "unknown-root-control" {
                let path = index.join("retention-unknown.json");
                let mut file = crate::create_private_file(&path, true).unwrap();
                file.write_all(b"{}\n").unwrap();
                file.sync_all().unwrap();
                sync_directory(&index).unwrap();
            }
            assert_eq!(
                compact_workspace_index(&root.0).unwrap_err().code,
                "WORKSPACE_INDEX_INVALID"
            );
            assert!(!index.join("compaction-v1.json").exists());
            assert!(generation_artifacts_exist(
                &root.0,
                &first_active.payload.generation_id
            ));
        }
    }

    #[test]
    fn malformed_retention_control_fails_before_epoch_or_intent_publication() {
        let root = TestRoot::new("malformed-retention-control");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        let index = existing_index_directory(&root.0).unwrap();
        let first_generation_id = {
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(index.join("retention-v1.json")).unwrap())
                    .unwrap();
            state["payload"]["generations"][0]["generationId"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let state_path = index.join("retention-v1.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let epoch = state["payload"]["epoch"].as_u64().unwrap();
        state["macSha256"] = serde_json::Value::String("f".repeat(64));
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&state_path)
            .unwrap();
        serde_json::to_writer(&mut file, &state).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            compact_workspace_index(&root.0).unwrap_err().code,
            "WORKSPACE_INDEX_INVALID"
        );
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(after["payload"]["epoch"].as_u64().unwrap(), epoch);
        assert!(!index.join("compaction-v1.json").exists());
        assert!(generation_artifacts_exist(&root.0, &first_generation_id));
    }

    #[test]
    fn reader_lease_admission_is_exactly_bounded_at_127_128_and_129() {
        let root = TestRoot::new("lease-limit");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        let _lock = MutationLock::acquire(&root.0).unwrap();
        let (index, metadata, active, _, _, _) = load_active(&root.0, false).unwrap();
        let mut leases = Vec::new();
        for _ in 0..127 {
            leases.push(
                retention::acquire_generation_read_lease(&index, &metadata, &active).unwrap(),
            );
        }
        assert_eq!(
            fs::read_dir(index.join("reader-leases-v1"))
                .unwrap()
                .count(),
            127
        );
        leases.push(retention::acquire_generation_read_lease(&index, &metadata, &active).unwrap());
        assert_eq!(leases.len(), MAX_READER_LEASES);
        assert_eq!(
            retention::acquire_generation_read_lease(&index, &metadata, &active)
                .err()
                .unwrap()
                .code,
            "WORKSPACE_INDEX_READER_LEASE_LIMIT"
        );
        assert_eq!(
            fs::read_dir(index.join("reader-leases-v1"))
                .unwrap()
                .count(),
            128
        );
        drop(leases);
        assert_eq!(
            fs::read_dir(index.join("reader-leases-v1"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn status_page_releases_lease_and_next_page_cursor_may_fail_stale() {
        let root = TestRoot::new("page-lease-lifetime");
        root.write("Game/a.bin", b"changed-a");
        root.write("Game/b.bin", b"changed-b");
        initialize_workspace(&root.0);
        let entries = vec![
            baseline_entry(1, "Game/a.bin", b"a", BaselineMaterialization::Full),
            baseline_entry(2, "Game/b.bin", b"b", BaselineMaterialization::Full),
        ];
        build(
            &root.0,
            &mut TestRoutes::new(entries.clone()),
            &mut TestWatcher::default(),
        );
        let first = test_status_page(&status_request(&root.0, 1)).unwrap();
        let cursor = first.next_cursor.unwrap();
        let index = existing_index_directory(&root.0).unwrap();
        assert_eq!(
            fs::read_dir(index.join("reader-leases-v1"))
                .unwrap()
                .count(),
            0
        );

        build(
            &root.0,
            &mut TestRoutes::new(entries),
            &mut TestWatcher::default(),
        );
        let mut next = status_request(&root.0, 1);
        next.cursor = Some(cursor);
        assert_eq!(
            test_status_page(&next).unwrap_err().code,
            "WORKSPACE_STATUS_CURSOR_STALE"
        );
        assert_eq!(
            fs::read_dir(index.join("reader-leases-v1"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn generation_history_capacity_is_reserved_before_next_transition() {
        let root = TestRoot::new("generation-history-limit");
        initialize_workspace(&root.0);
        for expected in 1..=MAX_AUTHENTICATED_GENERATIONS {
            assert_eq!(build_one_file_generation(&root).generation, expected as u64);
        }
        let index = existing_index_directory(&root.0).unwrap();
        let before = read_optional_active(&index).unwrap().unwrap();
        let mut routes = TestRoutes::new(vec![baseline_entry(
            900,
            "Assets/lease.bin",
            b"stable local content",
            BaselineMaterialization::Full,
        )]);
        let error = rebuild_workspace_index(
            &request(&root.0),
            &TestProvider,
            &mut routes,
            &mut TestWatcher::default(),
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap_err();
        assert_eq!(error.code, "WORKSPACE_INDEX_GENERATION_HISTORY_LIMIT");
        assert_eq!(read_optional_active(&index).unwrap().unwrap(), before);
        assert!(!index.join("transition.json").exists());

        let compacted = compact_workspace_index(&root.0).unwrap();
        assert_eq!(
            compacted.removed_generations,
            MAX_COMPACTION_GENERATIONS_PER_RUN as u64
        );
        assert!(compacted.more_pending);
        assert_eq!(
            build_one_file_generation(&root).generation,
            MAX_AUTHENTICATED_GENERATIONS as u64 + 1
        );
    }

    #[test]
    fn every_compaction_crash_boundary_recovers_without_false_clean_or_content_delete() {
        use retention::RetentionCrashPoint;

        for point in [
            RetentionCrashPoint::EpochPublished,
            RetentionCrashPoint::IntentPublished,
            RetentionCrashPoint::LeaseDirectorySynced,
            RetentionCrashPoint::GenerationRemoved,
            RetentionCrashPoint::GenerationDirectorySynced,
            RetentionCrashPoint::StatePublished,
            RetentionCrashPoint::IntentRemoved,
        ] {
            let root = TestRoot::new(&format!("compaction-crash-{point:?}"));
            initialize_workspace(&root.0);
            build_one_file_generation(&root);
            acquire_test_read_lease(&root.0).abandon_for_test();
            build_one_file_generation(&root);
            build_one_file_generation(&root);
            let index = existing_index_directory(&root.0).unwrap();
            let current = read_optional_active(&index).unwrap().unwrap();
            let key_before = fs::read(root.0.join("Assets/lease.bin")).unwrap();

            retention::set_retention_crash_point(point);
            assert_eq!(
                compact_workspace_index(&root.0).unwrap_err().code,
                "WORKSPACE_INDEX_COMPACTION_INJECTED_CRASH"
            );
            for _ in 0..2 {
                let recovered = recover_workspace_index(&root.0).unwrap().unwrap();
                assert_eq!(recovered.generation, current.payload.generation);
            }
            compact_workspace_index(&root.0).unwrap();
            let after = read_optional_active(&index).unwrap().unwrap();
            assert_eq!(after, current);
            assert_eq!(
                fs::read(root.0.join("Assets/lease.bin")).unwrap(),
                key_before
            );
            assert!(!index.join("compaction-v1.json").exists());
            verify_workspace_index(&root.0).unwrap();
        }
    }

    #[test]
    fn post_state_compaction_recovery_rejects_a_reappearing_candidate_artifact() {
        let root = TestRoot::new("post-state-reappearing-candidate");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        let index = existing_index_directory(&root.0).unwrap();
        let candidate_id = read_optional_active(&index)
            .unwrap()
            .unwrap()
            .payload
            .generation_id;
        build_one_file_generation(&root);
        let current = build_one_file_generation(&root);
        let content_before = fs::read(root.0.join("Assets/lease.bin")).unwrap();

        retention::set_retention_crash_point(retention::RetentionCrashPoint::StatePublished);
        assert_eq!(
            compact_workspace_index(&root.0).unwrap_err().code,
            "WORKSPACE_INDEX_COMPACTION_INJECTED_CRASH"
        );
        let name = format!("entries-{candidate_id}.v1");
        let mut unexpected = create_artifact(&index, &name).unwrap();
        unexpected.write_all(b"unexpected").unwrap();
        unexpected.sync_all().unwrap();
        drop(unexpected);
        sync_directory(&index).unwrap();

        assert_eq!(
            recover_workspace_index(&root.0).unwrap_err().code,
            "WORKSPACE_INDEX_INVALID"
        );
        assert!(index.join(name).exists());
        assert_eq!(
            read_optional_active(&index)
                .unwrap()
                .unwrap()
                .payload
                .generation,
            current.generation
        );
        assert_eq!(
            fs::read(root.0.join("Assets/lease.bin")).unwrap(),
            content_before
        );
    }

    #[test]
    fn lease_publication_crash_is_reclaimable_without_reading_deleted_generation() {
        let root = TestRoot::new("lease-publication-crash");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        retention::set_retention_crash_point(retention::RetentionCrashPoint::LeasePublished);
        assert_eq!(
            test_status_page(&status_request(&root.0, 10))
                .unwrap_err()
                .code,
            "WORKSPACE_INDEX_COMPACTION_INJECTED_CRASH"
        );
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        let report = compact_workspace_index(&root.0).unwrap();
        assert_eq!(report.reclaimed_leases, 1);
        verify_workspace_index(&root.0).unwrap();
    }

    #[test]
    fn aborted_transition_keeps_authenticated_numeric_predecessor() {
        let root = TestRoot::new("aborted-transition-predecessor");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        let index = existing_index_directory(&root.0).unwrap();
        let state: serde_json::Value =
            read_json_private(&index.join("retention-v1.json"), MAX_CONTROL_BYTES).unwrap();
        let generations = state["payload"]["generations"].as_array().unwrap();
        let predecessor_id = generations[generations.len() - 2]["generationId"]
            .as_str()
            .unwrap()
            .to_owned();
        let oldest_id = generations[0]["generationId"].as_str().unwrap().to_owned();

        set_crash_point(CrashPoint::TransitionPublished);
        let mut routes = TestRoutes::new(vec![baseline_entry(
            900,
            "Assets/lease.bin",
            b"stable local content",
            BaselineMaterialization::Full,
        )]);
        assert_eq!(
            rebuild_workspace_index(
                &request(&root.0),
                &TestProvider,
                &mut routes,
                &mut TestWatcher::default(),
                &NeverCancelled,
                &mut DiscardProgress,
            )
            .unwrap_err()
            .code,
            "WORKSPACE_INDEX_INJECTED_CRASH"
        );
        recover_workspace_index(&root.0).unwrap().unwrap();
        let report = compact_workspace_index(&root.0).unwrap();
        assert_eq!(report.removed_generations, 1);
        assert!(generation_artifacts_exist(&root.0, &predecessor_id));
        assert!(!generation_artifacts_exist(&root.0, &oldest_id));
    }

    #[test]
    fn repair_and_compaction_serialize_deterministically_on_mutation_lock() {
        let root = TestRoot::new("repair-compaction-race");
        initialize_workspace(&root.0);
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        build_one_file_generation(&root);
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let repair_root = root.0.clone();
        let repair_entered = Arc::clone(&entered);
        let repair_release = Arc::clone(&release);
        let repair = thread::spawn(move || {
            repair_workspace_index(
                &repair_root,
                &mut BlockingWatcher {
                    entered: repair_entered,
                    release: repair_release,
                },
                &NeverCancelled,
            )
        });
        entered.wait();
        assert_eq!(
            compact_workspace_index(&root.0).unwrap_err().code,
            "WORKSPACE_BUSY"
        );
        assert_eq!(
            record_workspace_change_batch(
                &root.0,
                &WorkspaceWatchBatch {
                    session_id: "session.1".to_owned(),
                    prior_cursor: "cursor.1".to_owned(),
                    cursor: "cursor.race".to_owned(),
                    events: vec![WorkspaceWatchEvent {
                        kind: WorkspaceWatchEventKind::Modified,
                        repository_path: "Assets/lease.bin".to_owned(),
                        prior_repository_path: None,
                    }],
                },
            )
            .unwrap_err()
            .code,
            "WORKSPACE_BUSY"
        );
        release.wait();
        assert_eq!(repair.join().unwrap().unwrap().generation, 4);
        assert!(
            compact_workspace_index(&root.0)
                .unwrap()
                .removed_generations
                > 0
        );
        verify_workspace_index(&root.0).unwrap();
    }

    #[test]
    fn case_collision_and_noncanonical_chunk_leave_active_generation_unchanged() {
        let root = TestRoot::new("case-collision");
        root.write("Game/base.bin", b"base");
        initialize_workspace(&root.0);
        let base = baseline_entry(1, "Game/base.bin", b"base", BaselineMaterialization::Full);
        let first = build(
            &root.0,
            &mut TestRoutes::new(vec![base]),
            &mut TestWatcher::default(),
        );
        let mut routes = TestRoutes::new(vec![
            baseline_entry(2, "Game/Foo.bin", b"x", BaselineMaterialization::Full),
            baseline_entry(3, "Game/foo.bin", b"y", BaselineMaterialization::Full),
        ]);
        let error = rebuild_workspace_index(
            &request(&root.0),
            &TestProvider,
            &mut routes,
            &mut TestWatcher::default(),
            &NeverCancelled,
            &mut DiscardProgress,
        )
        .unwrap_err();
        assert!(matches!(
            error.code,
            "WORKSPACE_INDEX_ORDER_INVALID" | "WORKSPACE_INDEX_PATH_COLLISION"
        ));
        recover_workspace_index(&root.0).unwrap();
        let current = test_status_page(&status_request(&root.0, 10)).unwrap();
        assert_eq!(current.generation, first.generation);

        let index = existing_index_directory(&root.0).unwrap();
        let mut writer =
            GenerationWriter::begin(&root.0, read_ready_metadata(&root.0).unwrap(), Vec::new())
                .unwrap();
        let mut entries = vec![
            baseline_entry(5, "Game/z.bin", b"z", BaselineMaterialization::Full),
            baseline_entry(4, "Game/a.bin", b"a", BaselineMaterialization::Full),
        ];
        sort_entries(&mut entries);
        entries.reverse();
        assert_eq!(
            writer.append_chunk(&entries).unwrap_err().code,
            "WORKSPACE_INDEX_ORDER_INVALID"
        );
        drop(writer);
        recover_transition_at(&index).unwrap();
    }

    #[test]
    #[ignore = "exact 100000-event durability/new-generation proof; bounded release gate"]
    fn exact_100000_watch_events_plus_one_and_new_generation_are_bounded() {
        let root = TestRoot::new("exact-watch-limit");
        root.write("Game/base.bin", b"base");
        initialize_workspace(&root.0);
        build(
            &root.0,
            &mut TestRoutes::new(vec![baseline_entry(
                1,
                "Game/base.bin",
                b"base",
                BaselineMaterialization::Full,
            )]),
            &mut TestWatcher::default(),
        );
        let started = Instant::now();
        let mut prior = "cursor.1".to_owned();
        for chunk in 0..100u64 {
            let cursor = format!("cursor.{}", chunk + 2);
            let events: Vec<_> = (0..MAX_WATCH_CHUNK_ITEMS)
                .map(|item| WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: format!("Scale/{chunk:03}-{item:04}.bin"),
                    prior_repository_path: None,
                })
                .collect();
            let report = record_workspace_change_batch(
                &root.0,
                &WorkspaceWatchBatch {
                    session_id: "session.1".to_owned(),
                    prior_cursor: prior,
                    cursor: cursor.clone(),
                    events,
                },
            )
            .unwrap();
            prior = cursor;
            assert_eq!(report.queued_event_count, (chunk + 1) * 1_000);
        }
        let error = record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: prior,
                cursor: "cursor.overflow".to_owned(),
                events: vec![WorkspaceWatchEvent {
                    kind: WorkspaceWatchEventKind::Modified,
                    repository_path: "Scale/overflow.bin".to_owned(),
                    prior_repository_path: None,
                }],
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "WORKSPACE_WATCH_EVENT_LIMIT");
        let verified = verify_workspace_index(&root.0).unwrap();
        assert_eq!(verified.queued_event_count, 100_000);
        assert!(verified.reconciliation_required);
        let repaired =
            repair_workspace_index(&root.0, &mut TestWatcher::default(), &NeverCancelled).unwrap();
        assert_eq!(repaired.queued_event_count, 0);
        eprintln!(
            "exact-watch-limit events=100000 batches=100 elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }

    #[test]
    #[ignore = "exact 1000-change status latency proof; bounded release gate"]
    fn exact_1000_changed_files_status_is_bounded() {
        let root = TestRoot::new("exact-1000-status");
        initialize_workspace(&root.0);
        let mut entries = Vec::with_capacity(1_000);
        for ordinal in 0..1_000u128 {
            let path = format!("Scale/file-{ordinal:04}.bin");
            root.write(&path, b"AAAAAAAA");
            entries.push(baseline_entry(
                ordinal + 1,
                &path,
                b"AAAAAAAA",
                BaselineMaterialization::Full,
            ));
        }
        build(
            &root.0,
            &mut TestRoutes::new(entries),
            &mut TestWatcher::default(),
        );
        let mut events = Vec::with_capacity(1_000);
        for ordinal in 0..1_000u128 {
            let path = format!("Scale/file-{ordinal:04}.bin");
            fs::write(joined_path(&root.0, &path), b"BBBBBBBB").unwrap();
            events.push(WorkspaceWatchEvent {
                kind: WorkspaceWatchEventKind::Modified,
                repository_path: path,
                prior_repository_path: None,
            });
        }
        record_workspace_change_batch(
            &root.0,
            &WorkspaceWatchBatch {
                session_id: "session.1".to_owned(),
                prior_cursor: "cursor.1".to_owned(),
                cursor: "cursor.2".to_owned(),
                events,
            },
        )
        .unwrap();
        let started = Instant::now();
        let status = test_status_page(&status_request(&root.0, 1_000)).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(status.items.len(), 1_000);
        assert_eq!(status.status_counts.get("modified"), Some(&1_000));
        assert!(status.items.iter().all(|item| item.content_verified));
        assert!(elapsed.as_secs_f64() < 5.0, "elapsed={elapsed:?}");
        eprintln!(
            "exact-status changed=1000 elapsed_ms={}",
            elapsed.as_millis()
        );
    }
}
