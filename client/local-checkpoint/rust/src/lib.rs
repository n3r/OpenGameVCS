//! Private, unwired, bounded local-checkpoint metadata candidate for OGVCS-014.
//!
//! This crate owns no public CLI or network route. It records already-supplied
//! canonical identities and never grants authorization, lock authority, cache
//! availability, or permission to overwrite workspace content.
#![forbid(unsafe_code)]

use ogvcs_chunking_manifest::{LOGICAL_MAXIMUM, MAXIMUM};
use ogvcs_object_model::{sha256, FileId, ObjectKind, ObjectRef, Sha256Writer};
use ogvcs_path_contract::{path_collision_keys_with_options, CaseMode, PathProfile};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
};
#[cfg(windows)]
use std::os::windows::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
};

pub const RECORD_SCHEMA: &str = "ogvcs.local-checkpoint/record/v1";
pub const INTENT_SCHEMA: &str = "ogvcs.local-checkpoint/create-intent/v1";
pub const COMPLETE_SCHEMA: &str = "ogvcs.local-checkpoint/complete-manifest/v1";
pub const LOCK_AUTHORITY_STATE: &str = "historical-untrusted-exclusivity-unverified";

pub const CHECKPOINTS_MAXIMUM: usize = 10_000;
pub const OPERATIONS_MAXIMUM: usize = 10_000;
pub const CHUNK_REFERENCES_MAXIMUM: usize = 100_000;
pub const LOCK_RECEIPTS_MAXIMUM: usize = 10_000;
pub const MESSAGE_BYTES_MAXIMUM: usize = 16_384;
pub const PATH_BYTES_TOTAL_MAXIMUM: u64 = 67_108_864;
pub const RECORD_BYTES_MAXIMUM: u64 = 67_108_864;
pub const STORE_RECORD_BYTES_MAXIMUM: u64 = 268_435_456;
pub const GRAPH_DEPTH_MAXIMUM: usize = 1_024;
const SMALL_METADATA_BYTES_MAXIMUM: u64 = 65_536;
const MAXIMUM_ARTIFACTS_PER_ENTRY: usize = 8;

const STORE_DIRECTORY: &str = "local-checkpoints-v1";
const ENTRIES_DIRECTORY: &str = "entries";
const INTENT_FILE: &str = "intent-v1.json";
const RECORD_FILE: &str = "record-v1.json";
const COMPLETE_FILE: &str = "complete-v1.json";

const CHECKPOINT_ID_DOMAIN: &[u8] = b"OpenGameVCS local checkpoint record\0";
const INTENT_INTEGRITY_DOMAIN: &[u8] = b"OpenGameVCS local checkpoint intent\0";
const COMPLETE_INTEGRITY_DOMAIN: &[u8] = b"OpenGameVCS local checkpoint complete\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointErrorCode {
    RootUnsafe,
    NamespaceUnsafe,
    NamespaceCorrupt,
    InputInvalid,
    BindingInvalid,
    OperationInvalid,
    ObjectKindInvalid,
    CountExceeded,
    BytesExceeded,
    LogicalOverflow,
    AlreadyExists,
    NotFound,
    Incomplete,
    IntegrityMismatch,
    ParentMissing,
    ParentBindingMismatch,
    ParentCycle,
    GraphDepthExceeded,
    ConcurrentMutation,
    Io,
    InjectedCrash,
}

impl CheckpointErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootUnsafe => "CHECKPOINT_ROOT_UNSAFE",
            Self::NamespaceUnsafe => "CHECKPOINT_NAMESPACE_UNSAFE",
            Self::NamespaceCorrupt => "CHECKPOINT_NAMESPACE_CORRUPT",
            Self::InputInvalid => "CHECKPOINT_INPUT_INVALID",
            Self::BindingInvalid => "CHECKPOINT_BINDING_INVALID",
            Self::OperationInvalid => "CHECKPOINT_OPERATION_INVALID",
            Self::ObjectKindInvalid => "CHECKPOINT_OBJECT_KIND_INVALID",
            Self::CountExceeded => "CHECKPOINT_COUNT_EXCEEDED",
            Self::BytesExceeded => "CHECKPOINT_BYTES_EXCEEDED",
            Self::LogicalOverflow => "CHECKPOINT_LOGICAL_OVERFLOW",
            Self::AlreadyExists => "CHECKPOINT_ALREADY_EXISTS",
            Self::NotFound => "CHECKPOINT_NOT_FOUND",
            Self::Incomplete => "CHECKPOINT_INCOMPLETE",
            Self::IntegrityMismatch => "CHECKPOINT_INTEGRITY_MISMATCH",
            Self::ParentMissing => "CHECKPOINT_PARENT_MISSING",
            Self::ParentBindingMismatch => "CHECKPOINT_PARENT_BINDING_MISMATCH",
            Self::ParentCycle => "CHECKPOINT_PARENT_CYCLE",
            Self::GraphDepthExceeded => "CHECKPOINT_GRAPH_DEPTH_EXCEEDED",
            Self::ConcurrentMutation => "CHECKPOINT_CONCURRENT_MUTATION",
            Self::Io => "CHECKPOINT_IO_FAILURE",
            Self::InjectedCrash => "CHECKPOINT_INJECTED_CRASH",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointError {
    code: CheckpointErrorCode,
    context: &'static str,
}

impl CheckpointError {
    const fn new(code: CheckpointErrorCode, context: &'static str) -> Self {
        Self { code, context }
    }

    pub const fn code(&self) -> CheckpointErrorCode {
        self.code
    }

    pub const fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.code.as_str(), self.context)
    }
}

impl std::error::Error for CheckpointError {}

pub type Result<T> = std::result::Result<T, CheckpointError>;

fn error(code: CheckpointErrorCode, context: &'static str) -> CheckpointError {
    CheckpointError::new(code, context)
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CheckpointId([u8; 32]);

impl CheckpointId {
    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }

    fn directory_name(self) -> String {
        encode_hex(&self.0)
    }

    fn from_directory_name(value: &str) -> Result<Self> {
        if value.len() != 64 || !value.bytes().all(is_lower_hex) {
            return Err(error(CheckpointErrorCode::NamespaceCorrupt, "entry-name"));
        }
        Ok(Self(decode_hex::<32>(value)?))
    }
}

impl fmt::Display for CheckpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "lcp:v1:sha256:{}", encode_hex(&self.0))
    }
}

impl FromStr for CheckpointId {
    type Err = CheckpointError;

    fn from_str(value: &str) -> Result<Self> {
        let body = value
            .strip_prefix("lcp:v1:sha256:")
            .ok_or_else(|| error(CheckpointErrorCode::InputInvalid, "checkpoint-id-prefix"))?;
        if body.len() != 64 || !body.bytes().all(is_lower_hex) {
            return Err(error(
                CheckpointErrorCode::InputInvalid,
                "checkpoint-id-digest",
            ));
        }
        Ok(Self(decode_hex::<32>(body)?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointBindings {
    pub repository: ObjectRef,
    pub base_snapshot: ObjectRef,
    pub workspace_id: [u8; 32],
    pub spec_digest: [u8; 32],
    pub path_profile: String,
    pub case_mode: CaseMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    Add,
    Modify,
    Copy,
    Move,
    Delete,
}

impl OperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Modify => "modify",
            Self::Copy => "copy",
            Self::Move => "move",
            Self::Delete => "delete",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "add" => Ok(Self::Add),
            "modify" => Ok(Self::Modify),
            "copy" => Ok(Self::Copy),
            "move" => Ok(Self::Move),
            "delete" => Ok(Self::Delete),
            _ => Err(error(
                CheckpointErrorCode::OperationInvalid,
                "operation-kind",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalChunkBinding {
    pub chunk: ObjectRef,
    pub logical_length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalContentBinding {
    pub manifest: ObjectRef,
    pub whole_file_digest: [u8; 32],
    pub logical_length: u64,
    pub chunks: Vec<CanonicalChunkBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointOperation {
    pub ordinal: u32,
    pub kind: OperationKind,
    pub file_id: FileId,
    pub source_path: Option<String>,
    pub destination_path: Option<String>,
    pub content: Option<CanonicalContentBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalLockReceipt {
    pub path: String,
    pub receipt_digest: [u8; 32],
    pub observed_lease_expires_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockReceiptSnapshot {
    pub captured_at_unix_ms: u64,
    pub receipts: Vec<HistoricalLockReceipt>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockAuthorityState {
    HistoricalUntrustedExclusivityUnverified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointCreateRequest {
    pub parent: Option<CheckpointId>,
    pub bindings: CheckpointBindings,
    pub operations: Vec<CheckpointOperation>,
    pub message: String,
    pub created_at_unix_ms: u64,
    pub lock_receipts: LockReceiptSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub id: CheckpointId,
    pub parent: Option<CheckpointId>,
    pub bindings: CheckpointBindings,
    pub operations: Vec<CheckpointOperation>,
    pub message: String,
    pub created_at_unix_ms: u64,
    pub lock_receipts: LockReceiptSnapshot,
    pub lock_authority: LockAuthorityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointSummary {
    pub id: CheckpointId,
    pub parent: Option<CheckpointId>,
    pub created_at_unix_ms: u64,
    pub message: String,
    pub operation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationReport {
    pub id: CheckpointId,
    pub chain_depth: usize,
    pub operation_count: usize,
    pub chunk_reference_count: usize,
    pub record_sha256: [u8; 32],
    pub lock_authority: LockAuthorityState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationBoundary {
    EntryDirectorySynced,
    IntentFileSynced,
    IntentDirectorySynced,
    RecordFileSynced,
    RecordDirectorySynced,
    ManifestFileSynced,
    ManifestDirectorySynced,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicationControl {
    pub stop_after: Option<PublicationBoundary>,
}

impl PublicationControl {
    fn reached(self, boundary: PublicationBoundary) -> Result<()> {
        if self.stop_after == Some(boundary) {
            Err(error(
                CheckpointErrorCode::InjectedCrash,
                "publication-boundary",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDisposition {
    RecoveredComplete,
    IncompleteReported,
    CorruptReported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryItem {
    pub entry_name: String,
    pub checkpoint_id: Option<CheckpointId>,
    pub disposition: RecoveryDisposition,
    pub reason: CheckpointErrorCode,
}

#[derive(Debug)]
pub struct CheckpointStore {
    workspace_root: PathBuf,
    control_root: PathBuf,
    store_root: PathBuf,
    entries_root: PathBuf,
}

#[derive(Clone, Debug)]
struct LoadedCheckpoint {
    checkpoint: Checkpoint,
    record_sha256: [u8; 32],
    record_bytes: u64,
    intent_integrity_sha256: [u8; 32],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskBindings {
    repository: String,
    base_snapshot: String,
    workspace_id_sha256: String,
    spec_sha256: String,
    path_profile: String,
    case_mode: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskChunkBinding {
    chunk: String,
    logical_length: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskContentBinding {
    manifest: String,
    whole_file_sha256: String,
    logical_length: u64,
    chunks: Vec<DiskChunkBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskOperation {
    ordinal: u32,
    kind: String,
    file_id: String,
    source_path: Option<String>,
    destination_path: Option<String>,
    content: Option<DiskContentBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskLockReceipt {
    path: String,
    receipt_sha256: String,
    observed_lease_expires_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskLockSnapshot {
    captured_at_unix_ms: u64,
    authority_state: String,
    receipts: Vec<DiskLockReceipt>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskRecord {
    schema: String,
    parent: Option<String>,
    bindings: DiskBindings,
    operations: Vec<DiskOperation>,
    message: String,
    created_at_unix_ms: u64,
    lock_receipts: DiskLockSnapshot,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskIntentPayload {
    schema: String,
    checkpoint_id: String,
    record_sha256: String,
    record_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskIntent {
    payload: DiskIntentPayload,
    integrity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskCompletePayload {
    schema: String,
    checkpoint_id: String,
    record_sha256: String,
    record_bytes: u64,
    intent_integrity_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskComplete {
    payload: DiskCompletePayload,
    integrity_sha256: String,
}

impl CheckpointStore {
    /// Opens the fixed checkpoint namespace under an already established
    /// workspace control directory. No caller-selected relative metadata path
    /// is accepted.
    pub fn open(workspace_root: &Path) -> Result<Self> {
        reject_link_or_non_directory(workspace_root, false, "workspace-root")?;
        let workspace_root = fs::canonicalize(workspace_root)
            .map_err(|_| error(CheckpointErrorCode::RootUnsafe, "workspace-canonicalize"))?;
        reject_link_or_non_directory(&workspace_root, false, "workspace-root")?;

        let control_root = workspace_root.join(".ogvcs");
        reject_link_or_non_directory(&control_root, true, "workspace-control")?;

        let store_root = control_root.join(STORE_DIRECTORY);
        ensure_private_child_directory(&control_root, &store_root)?;
        let entries_root = store_root.join(ENTRIES_DIRECTORY);
        ensure_private_child_directory(&store_root, &entries_root)?;

        let store = Self {
            workspace_root,
            control_root,
            store_root,
            entries_root,
        };
        store.revalidate_namespace()?;
        Ok(store)
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn create(
        &self,
        request: &CheckpointCreateRequest,
        control: PublicationControl,
    ) -> Result<Checkpoint> {
        self.revalidate_namespace()?;
        validate_request(request)?;
        self.validate_parent(request.parent, &request.bindings)?;

        let disk_record = disk_record_from_request(request);
        let record_bytes = canonical_json(&disk_record)?;
        if record_bytes.len() as u64 > RECORD_BYTES_MAXIMUM {
            return Err(error(CheckpointErrorCode::BytesExceeded, "record-bytes"));
        }
        let checkpoint_id = checkpoint_id(&record_bytes);
        let record_sha256 = sha256(&record_bytes);
        let intent = build_intent(checkpoint_id, record_sha256, record_bytes.len() as u64)?;
        let intent_bytes = canonical_json(&intent)?;
        self.revalidate_namespace()?;
        let existing_entries = scan_entry_names(&self.entries_root)?;
        validate_creatable_entry_namespace(&existing_entries)?;
        ensure_new_checkpoint_capacity(existing_entries.len())?;
        let entry = self.entries_root.join(checkpoint_id.directory_name());
        create_private_directory_new(&entry).map_err(|failure| {
            if failure.code() == CheckpointErrorCode::AlreadyExists {
                match reject_link_or_non_directory(&entry, true, "checkpoint-entry") {
                    Ok(()) => error(CheckpointErrorCode::AlreadyExists, "checkpoint-entry"),
                    Err(unsafe_entry) => unsafe_entry,
                }
            } else {
                failure
            }
        })?;
        self.revalidate_namespace()?;
        reject_link_or_non_directory(&entry, true, "checkpoint-entry")?;
        sync_directory(&entry)?;
        sync_directory(&self.entries_root)?;
        control.reached(PublicationBoundary::EntryDirectorySynced)?;

        self.write_boundary_file(
            &entry,
            INTENT_FILE,
            &intent_bytes,
            PublicationBoundary::IntentFileSynced,
            PublicationBoundary::IntentDirectorySynced,
            control,
        )?;
        self.write_boundary_file(
            &entry,
            RECORD_FILE,
            &record_bytes,
            PublicationBoundary::RecordFileSynced,
            PublicationBoundary::RecordDirectorySynced,
            control,
        )?;

        // Re-read from the safe namespace immediately before publication. The
        // intent, exact canonical record, ID, digest, length, parent, and all
        // bindings must still agree and there may be no unknown artifact.
        let loaded = self.preflight_recoverable(&entry, checkpoint_id)?;
        self.validate_parent(loaded.checkpoint.parent, &loaded.checkpoint.bindings)?;
        self.revalidate_entry_for_mutation(&entry)?;
        require_artifacts(&entry, &[INTENT_FILE, RECORD_FILE])?;
        sync_recoverable_artifacts(&entry)?;
        let loaded = self.preflight_recoverable(&entry, checkpoint_id)?;
        self.validate_parent(loaded.checkpoint.parent, &loaded.checkpoint.bindings)?;
        let complete = build_complete(
            checkpoint_id,
            loaded.record_sha256,
            loaded.record_bytes,
            loaded.intent_integrity_sha256,
        )?;
        let complete_bytes = canonical_json(&complete)?;
        self.write_boundary_file(
            &entry,
            COMPLETE_FILE,
            &complete_bytes,
            PublicationBoundary::ManifestFileSynced,
            PublicationBoundary::ManifestDirectorySynced,
            control,
        )?;
        self.show(checkpoint_id)
    }

    /// Lists only integrity-checked, complete checkpoints. Incomplete and
    /// corrupt namespaces are intentionally handled by `recover_incomplete`.
    pub fn list(&self) -> Result<Vec<CheckpointSummary>> {
        self.revalidate_namespace()?;
        let entries = scan_entry_names(&self.entries_root)?;
        let mut loaded_entries = Vec::new();
        let mut total_record_bytes = 0u64;
        for entry in entries {
            let Some(id) = entry.id else {
                return Err(error(CheckpointErrorCode::NamespaceCorrupt, "entry-name"));
            };
            if !entry.safe_directory {
                return Err(error(
                    CheckpointErrorCode::NamespaceUnsafe,
                    "entry-directory",
                ));
            }
            let path = self.entries_root.join(&entry.name);
            let artifacts = artifact_names(&path)?;
            if !artifacts.contains(COMPLETE_FILE) {
                continue;
            }
            require_artifact_set(&artifacts, &[INTENT_FILE, RECORD_FILE, COMPLETE_FILE])?;
            let record_size = safe_file_length(&path.join(RECORD_FILE), RECORD_BYTES_MAXIMUM)?;
            charge_store_record_bytes(&mut total_record_bytes, record_size)?;
            let loaded = self.read_complete_entry(&path, id)?;
            loaded_entries.push(loaded);
        }
        let complete = collect_loaded_graph(loaded_entries)?;
        validate_loaded_graph(&complete)?;
        Ok(complete
            .into_values()
            .map(|loaded| CheckpointSummary {
                id: loaded.checkpoint.id,
                parent: loaded.checkpoint.parent,
                created_at_unix_ms: loaded.checkpoint.created_at_unix_ms,
                message: loaded.checkpoint.message,
                operation_count: loaded.checkpoint.operations.len(),
            })
            .collect())
    }

    pub fn show(&self, checkpoint_id: CheckpointId) -> Result<Checkpoint> {
        Ok(self.load_verified_chain(checkpoint_id)?.0.checkpoint)
    }

    pub fn verify(&self, checkpoint_id: CheckpointId) -> Result<VerificationReport> {
        let (loaded, chain_depth) = self.load_verified_chain(checkpoint_id)?;
        let chunk_reference_count = loaded
            .checkpoint
            .operations
            .iter()
            .filter_map(|operation| operation.content.as_ref())
            .try_fold(0usize, |total, content| {
                total
                    .checked_add(content.chunks.len())
                    .ok_or_else(|| error(CheckpointErrorCode::CountExceeded, "chunk-count"))
            })?;
        Ok(VerificationReport {
            id: loaded.checkpoint.id,
            chain_depth,
            operation_count: loaded.checkpoint.operations.len(),
            chunk_reference_count,
            record_sha256: loaded.record_sha256,
            lock_authority: loaded.checkpoint.lock_authority,
        })
    }

    /// Scans every bounded entry in deterministic name order. An exact intact
    /// intent plus record may be completed by a create-new manifest; every
    /// other incomplete/corrupt shape is reported without deletion, rename,
    /// or any access to ordinary workspace bytes.
    pub fn recover_incomplete(&self, control: PublicationControl) -> Result<Vec<RecoveryItem>> {
        self.revalidate_namespace()?;
        let scanned_entries = scan_entry_names(&self.entries_root)?;
        // Re-establish the parent-directory barrier for any entry name that
        // survived an unclean stop before the original parent sync returned.
        sync_directory(&self.entries_root)?;
        let mut report = Vec::new();
        for scanned in scanned_entries {
            let mut item = RecoveryItem {
                entry_name: scanned.display_name.clone(),
                checkpoint_id: scanned.id,
                disposition: RecoveryDisposition::CorruptReported,
                reason: CheckpointErrorCode::NamespaceCorrupt,
            };
            let Some(id) = scanned.id else {
                report.push(item);
                continue;
            };
            if !scanned.safe_directory {
                item.reason = CheckpointErrorCode::NamespaceUnsafe;
                report.push(item);
                continue;
            }
            let entry = self.entries_root.join(&scanned.name);
            let artifacts = match artifact_names(&entry) {
                Ok(names) => names,
                Err(failure) => {
                    item.reason = failure.code();
                    report.push(item);
                    continue;
                }
            };
            if artifacts.contains(COMPLETE_FILE) {
                match require_artifact_set(&artifacts, &[INTENT_FILE, RECORD_FILE, COMPLETE_FILE])
                    .and_then(|_| self.load_verified_chain(id).map(|_| ()))
                {
                    Ok(_) => {
                        // A file or manifest may have survived a failed sync
                        // or a crash before its directory entry was durable.
                        // Re-sync all exact artifacts, the directory, and the
                        // chain before omitting this entry from the report.
                        sync_complete_artifacts(&entry)?;
                        let _ = self.load_verified_chain(id)?;
                        continue;
                    }
                    Err(failure) => {
                        item.reason = failure.code();
                        report.push(item);
                        continue;
                    }
                }
            }
            if artifacts.is_empty() {
                item.disposition = RecoveryDisposition::IncompleteReported;
                item.reason = CheckpointErrorCode::Incomplete;
                report.push(item);
                continue;
            }
            let intent_only = expected_artifact_set(&[INTENT_FILE]);
            if artifacts == intent_only {
                match read_intent(&entry.join(INTENT_FILE))
                    .and_then(|intent| validate_pending_intent(&intent, id))
                {
                    Ok(()) => {
                        item.disposition = RecoveryDisposition::IncompleteReported;
                        item.reason = CheckpointErrorCode::Incomplete;
                    }
                    Err(failure) => item.reason = failure.code(),
                }
                report.push(item);
                continue;
            }
            if artifacts != expected_artifact_set(&[INTENT_FILE, RECORD_FILE]) {
                report.push(item);
                continue;
            }
            let loaded = match self.preflight_recoverable(&entry, id) {
                Ok(loaded) => loaded,
                Err(failure) => {
                    item.reason = failure.code();
                    report.push(item);
                    continue;
                }
            };
            if let Err(failure) =
                self.validate_parent(loaded.checkpoint.parent, &loaded.checkpoint.bindings)
            {
                item.reason = failure.code();
                report.push(item);
                continue;
            }
            // Repeat every safety and artifact check at the mutation boundary.
            self.revalidate_entry_for_mutation(&entry)?;
            require_artifacts(&entry, &[INTENT_FILE, RECORD_FILE])?;
            sync_recoverable_artifacts(&entry)?;
            let loaded = self.preflight_recoverable(&entry, id)?;
            self.validate_parent(loaded.checkpoint.parent, &loaded.checkpoint.bindings)?;
            let complete = build_complete(
                id,
                loaded.record_sha256,
                loaded.record_bytes,
                loaded.intent_integrity_sha256,
            )?;
            let complete_bytes = canonical_json(&complete)?;
            self.write_boundary_file(
                &entry,
                COMPLETE_FILE,
                &complete_bytes,
                PublicationBoundary::ManifestFileSynced,
                PublicationBoundary::ManifestDirectorySynced,
                control,
            )?;
            let _ = self.load_verified_chain(id)?;
            item.disposition = RecoveryDisposition::RecoveredComplete;
            item.reason = CheckpointErrorCode::Incomplete;
            report.push(item);
        }
        Ok(report)
    }

    fn write_boundary_file(
        &self,
        entry: &Path,
        name: &str,
        bytes: &[u8],
        file_boundary: PublicationBoundary,
        directory_boundary: PublicationBoundary,
        control: PublicationControl,
    ) -> Result<()> {
        self.revalidate_entry_for_mutation(entry)?;
        let path = entry.join(name);
        write_new_private_file(&path, bytes)?;
        control.reached(file_boundary)?;
        self.revalidate_entry_for_mutation(entry)?;
        reject_link_or_non_regular_file(&path, "published-artifact")?;
        sync_directory(entry)?;
        control.reached(directory_boundary)
    }

    fn preflight_recoverable(
        &self,
        entry: &Path,
        expected_id: CheckpointId,
    ) -> Result<LoadedCheckpoint> {
        self.revalidate_entry_for_mutation(entry)?;
        require_artifacts(entry, &[INTENT_FILE, RECORD_FILE])?;
        let intent = read_intent(&entry.join(INTENT_FILE))?;
        let record_bytes = read_safe_file(&entry.join(RECORD_FILE), RECORD_BYTES_MAXIMUM)?;
        verify_intent_record(&intent, expected_id, &record_bytes)?;
        let checkpoint = decode_record(expected_id, &record_bytes)?;
        Ok(LoadedCheckpoint {
            checkpoint,
            record_sha256: sha256(&record_bytes),
            record_bytes: record_bytes.len() as u64,
            intent_integrity_sha256: decode_hex::<32>(&intent.integrity_sha256)?,
        })
    }

    fn read_complete_entry(
        &self,
        entry: &Path,
        expected_id: CheckpointId,
    ) -> Result<LoadedCheckpoint> {
        reject_link_or_non_directory(entry, true, "checkpoint-entry")?;
        let artifacts = artifact_names(entry)?;
        if !artifacts.contains(COMPLETE_FILE) {
            return Err(error(
                CheckpointErrorCode::Incomplete,
                "complete-manifest-missing",
            ));
        }
        require_artifact_set(&artifacts, &[INTENT_FILE, RECORD_FILE, COMPLETE_FILE])?;
        let intent = read_intent(&entry.join(INTENT_FILE))?;
        let record_bytes = read_safe_file(&entry.join(RECORD_FILE), RECORD_BYTES_MAXIMUM)?;
        verify_intent_record(&intent, expected_id, &record_bytes)?;
        let complete = read_complete(&entry.join(COMPLETE_FILE))?;
        verify_complete_manifest(&complete, &intent, expected_id, &record_bytes)?;
        let checkpoint = decode_record(expected_id, &record_bytes)?;
        Ok(LoadedCheckpoint {
            checkpoint,
            record_sha256: sha256(&record_bytes),
            record_bytes: record_bytes.len() as u64,
            intent_integrity_sha256: decode_hex::<32>(&intent.integrity_sha256)?,
        })
    }

    fn load_verified_chain(
        &self,
        checkpoint_id: CheckpointId,
    ) -> Result<(LoadedCheckpoint, usize)> {
        self.revalidate_namespace()?;
        let mut current = checkpoint_id;
        let mut seen = BTreeSet::new();
        let mut depth = 0usize;
        let mut first = None;
        let mut child_bindings: Option<CheckpointBindings> = None;
        loop {
            if depth >= GRAPH_DEPTH_MAXIMUM {
                return Err(error(
                    CheckpointErrorCode::GraphDepthExceeded,
                    "parent-chain",
                ));
            }
            if !seen.insert(current) {
                return Err(error(CheckpointErrorCode::ParentCycle, "parent-chain"));
            }
            let entry = self.entries_root.join(current.directory_name());
            match fs::symlink_metadata(&entry) {
                Ok(_) => {}
                Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
                    return Err(error(
                        if depth == 0 {
                            CheckpointErrorCode::NotFound
                        } else {
                            CheckpointErrorCode::ParentMissing
                        },
                        "checkpoint-entry",
                    ));
                }
                Err(_) => {
                    return Err(error(CheckpointErrorCode::Io, "checkpoint-entry-metadata"));
                }
            }
            let loaded = self
                .read_complete_entry(&entry, current)
                .map_err(|failure| {
                    if depth > 0
                        && matches!(
                            failure.code(),
                            CheckpointErrorCode::NotFound | CheckpointErrorCode::Incomplete
                        )
                    {
                        error(CheckpointErrorCode::ParentMissing, "parent-entry")
                    } else {
                        failure
                    }
                })?;
            if let Some(bindings) = &child_bindings {
                if bindings != &loaded.checkpoint.bindings {
                    return Err(error(
                        CheckpointErrorCode::ParentBindingMismatch,
                        "parent-bindings",
                    ));
                }
            }
            if first.is_none() {
                first = Some(loaded.clone());
            }
            depth += 1;
            match loaded.checkpoint.parent {
                Some(parent) if parent == current => {
                    return Err(error(CheckpointErrorCode::ParentCycle, "self-parent"));
                }
                Some(parent) => {
                    child_bindings = Some(loaded.checkpoint.bindings);
                    current = parent;
                }
                None => break,
            }
        }
        Ok((first.expect("chain contains requested checkpoint"), depth))
    }

    fn validate_parent(
        &self,
        parent: Option<CheckpointId>,
        child_bindings: &CheckpointBindings,
    ) -> Result<()> {
        let Some(parent) = parent else {
            return Ok(());
        };
        let (parent_checkpoint, parent_depth) =
            self.load_verified_chain(parent).map_err(|failure| {
                if matches!(
                    failure.code(),
                    CheckpointErrorCode::NotFound | CheckpointErrorCode::Incomplete
                ) {
                    error(CheckpointErrorCode::ParentMissing, "parent-entry")
                } else {
                    failure
                }
            })?;
        ensure_child_chain_depth(parent_depth)?;
        if &parent_checkpoint.checkpoint.bindings != child_bindings {
            return Err(error(
                CheckpointErrorCode::ParentBindingMismatch,
                "parent-bindings",
            ));
        }
        Ok(())
    }

    fn revalidate_namespace(&self) -> Result<()> {
        reject_link_or_non_directory(&self.workspace_root, false, "workspace-root")?;
        reject_link_or_non_directory(&self.control_root, true, "workspace-control")?;
        reject_link_or_non_directory(&self.store_root, true, "checkpoint-store")?;
        reject_link_or_non_directory(&self.entries_root, true, "checkpoint-entries")?;
        if self.control_root.parent() != Some(self.workspace_root.as_path())
            || self.store_root.parent() != Some(self.control_root.as_path())
            || self.entries_root.parent() != Some(self.store_root.as_path())
        {
            return Err(error(
                CheckpointErrorCode::NamespaceUnsafe,
                "fixed-namespace",
            ));
        }
        Ok(())
    }

    fn revalidate_entry_for_mutation(&self, entry: &Path) -> Result<()> {
        self.revalidate_namespace()?;
        if entry.parent() != Some(self.entries_root.as_path()) {
            return Err(error(CheckpointErrorCode::NamespaceUnsafe, "entry-parent"));
        }
        let name = entry
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| error(CheckpointErrorCode::NamespaceUnsafe, "entry-name"))?;
        let _ = CheckpointId::from_directory_name(name)?;
        reject_link_or_non_directory(entry, true, "checkpoint-entry")
    }
}

fn validate_request(request: &CheckpointCreateRequest) -> Result<()> {
    validate_bindings(&request.bindings)?;
    if request.message.as_bytes().len() > MESSAGE_BYTES_MAXIMUM
        || request.message.as_bytes().contains(&0)
    {
        return Err(error(
            CheckpointErrorCode::BytesExceeded,
            "checkpoint-message",
        ));
    }
    if request.operations.len() > OPERATIONS_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::CountExceeded,
            "checkpoint-operations",
        ));
    }
    if request.lock_receipts.receipts.len() > LOCK_RECEIPTS_MAXIMUM {
        return Err(error(CheckpointErrorCode::CountExceeded, "lock-receipts"));
    }

    let profile = PathProfile::parse(&request.bindings.path_profile).map_err(|_| {
        error(
            CheckpointErrorCode::BindingInvalid,
            "checkpoint-path-profile",
        )
    })?;
    let mut expected_ordinal = 0u32;
    let mut total_chunks = 0usize;
    let mut total_paths = 0u64;
    let mut created_file_ids = BTreeSet::new();
    let mut known_chunk_lengths = BTreeMap::new();
    let mut known_manifest_projections = BTreeMap::new();
    for operation in &request.operations {
        if operation.ordinal != expected_ordinal {
            return Err(error(
                CheckpointErrorCode::OperationInvalid,
                "operation-order",
            ));
        }
        expected_ordinal = expected_ordinal.checked_add(1).ok_or_else(|| {
            error(
                CheckpointErrorCode::CountExceeded,
                "operation-order-overflow",
            )
        })?;
        validate_operation_shape(operation)?;
        for path in [
            operation.source_path.as_deref(),
            operation.destination_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_repository_path(path, profile, request.bindings.case_mode)?;
            charge_path_bytes(&mut total_paths, path.len())?;
        }
        if matches!(operation.kind, OperationKind::Add | OperationKind::Copy)
            && !created_file_ids.insert(operation.file_id)
        {
            return Err(error(
                CheckpointErrorCode::OperationInvalid,
                "created-file-id-duplicate",
            ));
        }
        if let Some(content) = &operation.content {
            validate_content(content, &mut known_chunk_lengths)?;
            if known_manifest_projections
                .insert(content.manifest, content.clone())
                .is_some_and(|previous| previous != *content)
            {
                return Err(error(
                    CheckpointErrorCode::OperationInvalid,
                    "content-manifest-projection-conflict",
                ));
            }
            total_chunks = total_chunks
                .checked_add(content.chunks.len())
                .ok_or_else(|| error(CheckpointErrorCode::CountExceeded, "chunk-count"))?;
            if total_chunks > CHUNK_REFERENCES_MAXIMUM {
                return Err(error(CheckpointErrorCode::CountExceeded, "chunk-count"));
            }
        }
    }

    let mut lock_repository_paths = BTreeSet::new();
    let mut lock_platform_paths = BTreeSet::new();
    for receipt in &request.lock_receipts.receipts {
        let keys = validate_repository_path(&receipt.path, profile, request.bindings.case_mode)?;
        charge_path_bytes(&mut total_paths, receipt.path.len())?;
        if !lock_repository_paths.insert(keys.repository_key().as_str().to_owned())
            || !lock_platform_paths.insert(keys.platform_key().to_owned())
        {
            return Err(error(
                CheckpointErrorCode::InputInvalid,
                "lock-path-duplicate",
            ));
        }
    }
    Ok(())
}

fn ensure_new_checkpoint_capacity(existing: usize) -> Result<()> {
    if existing >= CHECKPOINTS_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::CountExceeded,
            "checkpoint-count",
        ));
    }
    Ok(())
}

fn validate_creatable_entry_namespace(entries: &[ScannedEntry]) -> Result<()> {
    for entry in entries {
        if entry.id.is_none() {
            return Err(error(CheckpointErrorCode::NamespaceCorrupt, "entry-name"));
        }
        if !entry.safe_directory {
            return Err(error(
                CheckpointErrorCode::NamespaceUnsafe,
                "entry-directory",
            ));
        }
    }
    Ok(())
}

fn ensure_child_chain_depth(parent_depth: usize) -> Result<()> {
    if parent_depth >= GRAPH_DEPTH_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::GraphDepthExceeded,
            "parent-chain",
        ));
    }
    Ok(())
}

fn charge_path_bytes(total: &mut u64, bytes: usize) -> Result<()> {
    *total = total
        .checked_add(bytes as u64)
        .ok_or_else(|| error(CheckpointErrorCode::BytesExceeded, "path-bytes"))?;
    if *total > PATH_BYTES_TOTAL_MAXIMUM {
        return Err(error(CheckpointErrorCode::BytesExceeded, "path-bytes"));
    }
    Ok(())
}

fn charge_store_record_bytes(total: &mut u64, bytes: u64) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| error(CheckpointErrorCode::BytesExceeded, "store-record-bytes"))?;
    if *total > STORE_RECORD_BYTES_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::BytesExceeded,
            "store-record-bytes",
        ));
    }
    Ok(())
}

fn validate_bindings(bindings: &CheckpointBindings) -> Result<()> {
    if bindings.repository.kind != ObjectKind::RepositoryDescriptor
        || bindings.base_snapshot.kind != ObjectKind::Snapshot
    {
        return Err(error(
            CheckpointErrorCode::ObjectKindInvalid,
            "checkpoint-bindings",
        ));
    }
    if bindings.workspace_id == [0; 32] || bindings.spec_digest == [0; 32] {
        return Err(error(
            CheckpointErrorCode::BindingInvalid,
            "zero-binding-digest",
        ));
    }
    PathProfile::parse(&bindings.path_profile).map_err(|_| {
        error(
            CheckpointErrorCode::BindingInvalid,
            "checkpoint-path-profile",
        )
    })?;
    Ok(())
}

fn validate_operation_shape(operation: &CheckpointOperation) -> Result<()> {
    let shape_valid = match operation.kind {
        OperationKind::Add => {
            operation.source_path.is_none()
                && operation.destination_path.is_some()
                && operation.content.is_some()
        }
        OperationKind::Modify => {
            operation.source_path.is_some()
                && operation.source_path == operation.destination_path
                && operation.content.is_some()
        }
        OperationKind::Copy | OperationKind::Move => {
            operation.source_path.is_some()
                && operation.destination_path.is_some()
                && operation.source_path != operation.destination_path
                && operation.content.is_some()
        }
        OperationKind::Delete => {
            operation.source_path.is_some()
                && operation.destination_path.is_none()
                && operation.content.is_none()
        }
    };
    if !shape_valid {
        return Err(error(
            CheckpointErrorCode::OperationInvalid,
            "operation-shape",
        ));
    }
    Ok(())
}

fn validate_content(
    content: &CanonicalContentBinding,
    known_chunk_lengths: &mut BTreeMap<ObjectRef, u64>,
) -> Result<()> {
    if content.manifest.kind != ObjectKind::ContentManifest {
        return Err(error(
            CheckpointErrorCode::ObjectKindInvalid,
            "content-manifest",
        ));
    }
    if content.chunks.len() > CHUNK_REFERENCES_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::CountExceeded,
            "content-chunk-count",
        ));
    }
    if content.logical_length > LOGICAL_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::LogicalOverflow,
            "content-logical-length",
        ));
    }
    let mut sum = 0u64;
    for part in &content.chunks {
        if part.chunk.kind != ObjectKind::Chunk {
            return Err(error(
                CheckpointErrorCode::ObjectKindInvalid,
                "content-chunk",
            ));
        }
        if part.logical_length == 0 || part.logical_length > MAXIMUM as u64 {
            return Err(error(
                CheckpointErrorCode::OperationInvalid,
                "content-chunk-length",
            ));
        }
        if known_chunk_lengths
            .insert(part.chunk, part.logical_length)
            .is_some_and(|previous| previous != part.logical_length)
        {
            return Err(error(
                CheckpointErrorCode::OperationInvalid,
                "content-chunk-length-conflict",
            ));
        }
        sum = sum
            .checked_add(part.logical_length)
            .ok_or_else(|| error(CheckpointErrorCode::LogicalOverflow, "content-chunk-sum"))?;
        if sum > LOGICAL_MAXIMUM {
            return Err(error(
                CheckpointErrorCode::LogicalOverflow,
                "content-chunk-sum",
            ));
        }
    }
    if sum != content.logical_length || (content.logical_length == 0 && !content.chunks.is_empty())
    {
        return Err(error(
            CheckpointErrorCode::OperationInvalid,
            "content-length-mismatch",
        ));
    }
    Ok(())
}

fn validate_repository_path(
    path: &str,
    profile: PathProfile,
    case_mode: CaseMode,
) -> Result<ogvcs_path_contract::PathCollisionKeys> {
    let keys = path_collision_keys_with_options(path, profile, case_mode)
        .map_err(|_| error(CheckpointErrorCode::OperationInvalid, "repository-path"))?;
    if keys.path().canonical() != path {
        return Err(error(
            CheckpointErrorCode::OperationInvalid,
            "repository-path-canonical",
        ));
    }
    Ok(keys)
}

fn disk_record_from_request(request: &CheckpointCreateRequest) -> DiskRecord {
    DiskRecord {
        schema: RECORD_SCHEMA.to_owned(),
        parent: request.parent.map(|parent| parent.to_string()),
        bindings: DiskBindings {
            repository: request.bindings.repository.to_string(),
            base_snapshot: request.bindings.base_snapshot.to_string(),
            workspace_id_sha256: encode_hex(&request.bindings.workspace_id),
            spec_sha256: encode_hex(&request.bindings.spec_digest),
            path_profile: request.bindings.path_profile.clone(),
            case_mode: request.bindings.case_mode.as_str().to_owned(),
        },
        operations: request
            .operations
            .iter()
            .map(|operation| DiskOperation {
                ordinal: operation.ordinal,
                kind: operation.kind.as_str().to_owned(),
                file_id: operation.file_id.to_string(),
                source_path: operation.source_path.clone(),
                destination_path: operation.destination_path.clone(),
                content: operation
                    .content
                    .as_ref()
                    .map(|content| DiskContentBinding {
                        manifest: content.manifest.to_string(),
                        whole_file_sha256: encode_hex(&content.whole_file_digest),
                        logical_length: content.logical_length,
                        chunks: content
                            .chunks
                            .iter()
                            .map(|part| DiskChunkBinding {
                                chunk: part.chunk.to_string(),
                                logical_length: part.logical_length,
                            })
                            .collect(),
                    }),
            })
            .collect(),
        message: request.message.clone(),
        created_at_unix_ms: request.created_at_unix_ms,
        lock_receipts: DiskLockSnapshot {
            captured_at_unix_ms: request.lock_receipts.captured_at_unix_ms,
            authority_state: LOCK_AUTHORITY_STATE.to_owned(),
            receipts: request
                .lock_receipts
                .receipts
                .iter()
                .map(|receipt| DiskLockReceipt {
                    path: receipt.path.clone(),
                    receipt_sha256: encode_hex(&receipt.receipt_digest),
                    observed_lease_expires_unix_ms: receipt.observed_lease_expires_unix_ms,
                })
                .collect(),
        },
    }
}

fn decode_record(id: CheckpointId, bytes: &[u8]) -> Result<Checkpoint> {
    let disk: DiskRecord = parse_canonical_json(bytes, RECORD_BYTES_MAXIMUM)?;
    if disk.schema != RECORD_SCHEMA || disk.lock_receipts.authority_state != LOCK_AUTHORITY_STATE {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "record-schema",
        ));
    }
    let bindings = CheckpointBindings {
        repository: ObjectRef::from_str(&disk.bindings.repository)
            .map_err(|_| error(CheckpointErrorCode::BindingInvalid, "repository-reference"))?,
        base_snapshot: ObjectRef::from_str(&disk.bindings.base_snapshot)
            .map_err(|_| error(CheckpointErrorCode::BindingInvalid, "snapshot-reference"))?,
        workspace_id: decode_hex::<32>(&disk.bindings.workspace_id_sha256)?,
        spec_digest: decode_hex::<32>(&disk.bindings.spec_sha256)?,
        path_profile: disk.bindings.path_profile,
        case_mode: CaseMode::parse(&disk.bindings.case_mode)
            .map_err(|_| error(CheckpointErrorCode::BindingInvalid, "case-mode"))?,
    };
    let operations = disk
        .operations
        .into_iter()
        .map(|operation| {
            Ok(CheckpointOperation {
                ordinal: operation.ordinal,
                kind: OperationKind::parse(&operation.kind)?,
                file_id: FileId::from_str(&operation.file_id).map_err(|_| {
                    error(CheckpointErrorCode::OperationInvalid, "operation-file-id")
                })?,
                source_path: operation.source_path,
                destination_path: operation.destination_path,
                content: operation
                    .content
                    .map(|content| {
                        Ok(CanonicalContentBinding {
                            manifest: ObjectRef::from_str(&content.manifest).map_err(|_| {
                                error(CheckpointErrorCode::OperationInvalid, "manifest-reference")
                            })?,
                            whole_file_digest: decode_hex::<32>(&content.whole_file_sha256)?,
                            logical_length: content.logical_length,
                            chunks: content
                                .chunks
                                .into_iter()
                                .map(|part| {
                                    Ok(CanonicalChunkBinding {
                                        chunk: ObjectRef::from_str(&part.chunk).map_err(|_| {
                                            error(
                                                CheckpointErrorCode::OperationInvalid,
                                                "chunk-reference",
                                            )
                                        })?,
                                        logical_length: part.logical_length,
                                    })
                                })
                                .collect::<Result<Vec<_>>>()?,
                        })
                    })
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let lock_receipts = LockReceiptSnapshot {
        captured_at_unix_ms: disk.lock_receipts.captured_at_unix_ms,
        receipts: disk
            .lock_receipts
            .receipts
            .into_iter()
            .map(|receipt| {
                Ok(HistoricalLockReceipt {
                    path: receipt.path,
                    receipt_digest: decode_hex::<32>(&receipt.receipt_sha256)?,
                    observed_lease_expires_unix_ms: receipt.observed_lease_expires_unix_ms,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let request = CheckpointCreateRequest {
        parent: disk
            .parent
            .map(|parent| CheckpointId::from_str(&parent))
            .transpose()?,
        bindings,
        operations,
        message: disk.message,
        created_at_unix_ms: disk.created_at_unix_ms,
        lock_receipts,
    };
    validate_request(&request)?;
    Ok(Checkpoint {
        id,
        parent: request.parent,
        bindings: request.bindings,
        operations: request.operations,
        message: request.message,
        created_at_unix_ms: request.created_at_unix_ms,
        lock_receipts: request.lock_receipts,
        lock_authority: LockAuthorityState::HistoricalUntrustedExclusivityUnverified,
    })
}

fn build_intent(
    checkpoint_id: CheckpointId,
    record_sha256: [u8; 32],
    record_bytes: u64,
) -> Result<DiskIntent> {
    let payload = DiskIntentPayload {
        schema: INTENT_SCHEMA.to_owned(),
        checkpoint_id: checkpoint_id.to_string(),
        record_sha256: encode_hex(&record_sha256),
        record_bytes,
    };
    let payload_bytes = canonical_json(&payload)?;
    Ok(DiskIntent {
        payload,
        integrity_sha256: encode_hex(&domain_hash(INTENT_INTEGRITY_DOMAIN, &payload_bytes)),
    })
}

fn build_complete(
    checkpoint_id: CheckpointId,
    record_sha256: [u8; 32],
    record_bytes: u64,
    intent_integrity_sha256: [u8; 32],
) -> Result<DiskComplete> {
    let payload = DiskCompletePayload {
        schema: COMPLETE_SCHEMA.to_owned(),
        checkpoint_id: checkpoint_id.to_string(),
        record_sha256: encode_hex(&record_sha256),
        record_bytes,
        intent_integrity_sha256: encode_hex(&intent_integrity_sha256),
    };
    let payload_bytes = canonical_json(&payload)?;
    Ok(DiskComplete {
        payload,
        integrity_sha256: encode_hex(&domain_hash(COMPLETE_INTEGRITY_DOMAIN, &payload_bytes)),
    })
}

fn read_intent(path: &Path) -> Result<DiskIntent> {
    let bytes = read_safe_file(path, SMALL_METADATA_BYTES_MAXIMUM)?;
    let intent: DiskIntent = parse_canonical_json(&bytes, SMALL_METADATA_BYTES_MAXIMUM)?;
    if intent.payload.schema != INTENT_SCHEMA {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "intent-schema",
        ));
    }
    let payload_bytes = canonical_json(&intent.payload)?;
    let expected = domain_hash(INTENT_INTEGRITY_DOMAIN, &payload_bytes);
    if decode_hex::<32>(&intent.integrity_sha256)? != expected {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "intent-integrity",
        ));
    }
    Ok(intent)
}

fn validate_pending_intent(intent: &DiskIntent, expected_id: CheckpointId) -> Result<()> {
    if CheckpointId::from_str(&intent.payload.checkpoint_id)? != expected_id {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "intent-checkpoint-binding",
        ));
    }
    let _ = decode_hex::<32>(&intent.payload.record_sha256)?;
    if intent.payload.record_bytes == 0 || intent.payload.record_bytes > RECORD_BYTES_MAXIMUM {
        return Err(error(
            CheckpointErrorCode::BytesExceeded,
            "intent-record-bytes",
        ));
    }
    Ok(())
}

fn read_complete(path: &Path) -> Result<DiskComplete> {
    let bytes = read_safe_file(path, SMALL_METADATA_BYTES_MAXIMUM)?;
    let complete: DiskComplete = parse_canonical_json(&bytes, SMALL_METADATA_BYTES_MAXIMUM)?;
    if complete.payload.schema != COMPLETE_SCHEMA {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "complete-schema",
        ));
    }
    let payload_bytes = canonical_json(&complete.payload)?;
    let expected = domain_hash(COMPLETE_INTEGRITY_DOMAIN, &payload_bytes);
    if decode_hex::<32>(&complete.integrity_sha256)? != expected {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "complete-integrity",
        ));
    }
    Ok(complete)
}

fn verify_intent_record(
    intent: &DiskIntent,
    expected_id: CheckpointId,
    record_bytes: &[u8],
) -> Result<()> {
    let intent_id = CheckpointId::from_str(&intent.payload.checkpoint_id)?;
    let actual_id = checkpoint_id(record_bytes);
    let actual_sha256 = sha256(record_bytes);
    if intent_id != expected_id
        || actual_id != expected_id
        || decode_hex::<32>(&intent.payload.record_sha256)? != actual_sha256
        || intent.payload.record_bytes != record_bytes.len() as u64
    {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "intent-record-binding",
        ));
    }
    Ok(())
}

fn verify_complete_manifest(
    complete: &DiskComplete,
    intent: &DiskIntent,
    expected_id: CheckpointId,
    record_bytes: &[u8],
) -> Result<()> {
    if CheckpointId::from_str(&complete.payload.checkpoint_id)? != expected_id
        || complete.payload.record_sha256 != intent.payload.record_sha256
        || complete.payload.record_bytes != intent.payload.record_bytes
        || complete.payload.intent_integrity_sha256 != intent.integrity_sha256
        || complete.payload.record_bytes != record_bytes.len() as u64
        || decode_hex::<32>(&complete.payload.record_sha256)? != sha256(record_bytes)
    {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "complete-record-binding",
        ));
    }
    Ok(())
}

fn checkpoint_id(record_bytes: &[u8]) -> CheckpointId {
    CheckpointId(domain_hash(CHECKPOINT_ID_DOMAIN, record_bytes))
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut writer = Sha256Writer::new();
    writer.update(domain);
    writer.update(&1u16.to_be_bytes());
    writer.update(payload);
    writer.finish()
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|_| error(CheckpointErrorCode::InputInvalid, "metadata-encode"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn parse_canonical_json<T>(bytes: &[u8], maximum: u64) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if bytes.len() as u64 > maximum || !bytes.ends_with(b"\n") {
        return Err(error(
            CheckpointErrorCode::BytesExceeded,
            "metadata-framing",
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| error(CheckpointErrorCode::IntegrityMismatch, "metadata-decode"))?;
    if canonical_json(&value)? != bytes {
        return Err(error(
            CheckpointErrorCode::IntegrityMismatch,
            "metadata-canonical-json",
        ));
    }
    Ok(value)
}

#[derive(Debug)]
struct ScannedEntry {
    name: OsString,
    display_name: String,
    sort_key: Vec<u8>,
    id: Option<CheckpointId>,
    safe_directory: bool,
}

fn scan_entry_names(entries_root: &Path) -> Result<Vec<ScannedEntry>> {
    reject_link_or_non_directory(entries_root, true, "checkpoint-entries")?;
    let mut entries = Vec::new();
    let iterator =
        fs::read_dir(entries_root).map_err(|_| error(CheckpointErrorCode::Io, "entries-read"))?;
    for item in iterator {
        if entries.len() >= CHECKPOINTS_MAXIMUM {
            return Err(error(
                CheckpointErrorCode::CountExceeded,
                "checkpoint-count",
            ));
        }
        let item = item.map_err(|_| error(CheckpointErrorCode::Io, "entry-read"))?;
        let name = item.file_name();
        let sort_key = os_name_sort_key(&name);
        let id = name
            .to_str()
            .and_then(|value| CheckpointId::from_directory_name(value).ok());
        let display_name = id
            .map(CheckpointId::directory_name)
            .unwrap_or_else(|| format!("os-name-hex:{}", encode_hex(&sort_key)));
        let safe_directory =
            reject_link_or_non_directory(&item.path(), true, "checkpoint-entry").is_ok();
        entries.push(ScannedEntry {
            name,
            display_name,
            sort_key,
            id,
            safe_directory,
        });
    }
    entries.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));
    Ok(entries)
}

fn os_name_sort_key(name: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    let raw = name.as_bytes().to_vec();
    #[cfg(windows)]
    let raw = name
        .encode_wide()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    #[cfg(not(any(unix, windows)))]
    let raw = name.to_string_lossy().as_bytes().to_vec();

    raw
}

fn artifact_names(entry: &Path) -> Result<BTreeSet<String>> {
    reject_link_or_non_directory(entry, true, "checkpoint-entry")?;
    let mut names = BTreeSet::new();
    let iterator =
        fs::read_dir(entry).map_err(|_| error(CheckpointErrorCode::Io, "artifact-read"))?;
    for item in iterator {
        if names.len() >= MAXIMUM_ARTIFACTS_PER_ENTRY {
            return Err(error(
                CheckpointErrorCode::NamespaceCorrupt,
                "artifact-count",
            ));
        }
        let item = item.map_err(|_| error(CheckpointErrorCode::Io, "artifact-read"))?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| error(CheckpointErrorCode::NamespaceCorrupt, "artifact-name"))?;
        let metadata = fs::symlink_metadata(item.path())
            .map_err(|_| error(CheckpointErrorCode::Io, "artifact-metadata"))?;
        if !metadata.file_type().is_file() || metadata_is_reparse_point(&metadata) {
            return Err(error(
                CheckpointErrorCode::NamespaceUnsafe,
                "artifact-file-type",
            ));
        }
        if !names.insert(name) {
            return Err(error(
                CheckpointErrorCode::NamespaceCorrupt,
                "artifact-duplicate",
            ));
        }
    }
    Ok(names)
}

fn expected_artifact_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn require_artifact_set(actual: &BTreeSet<String>, expected: &[&str]) -> Result<()> {
    if actual != &expected_artifact_set(expected) {
        return Err(error(CheckpointErrorCode::NamespaceCorrupt, "artifact-set"));
    }
    Ok(())
}

fn require_artifacts(entry: &Path, expected: &[&str]) -> Result<()> {
    let actual = artifact_names(entry)?;
    require_artifact_set(&actual, expected)
}

fn validate_loaded_graph(complete: &BTreeMap<CheckpointId, LoadedCheckpoint>) -> Result<()> {
    for (id, loaded) in complete {
        if loaded.checkpoint.id != *id {
            return Err(error(
                CheckpointErrorCode::NamespaceCorrupt,
                "duplicate-or-mismatched-id",
            ));
        }
        let mut current = *id;
        let mut seen = BTreeSet::new();
        let mut depth = 0usize;
        let bindings = &loaded.checkpoint.bindings;
        loop {
            if depth >= GRAPH_DEPTH_MAXIMUM {
                return Err(error(
                    CheckpointErrorCode::GraphDepthExceeded,
                    "parent-graph",
                ));
            }
            if !seen.insert(current) {
                return Err(error(CheckpointErrorCode::ParentCycle, "parent-graph"));
            }
            let node = complete
                .get(&current)
                .ok_or_else(|| error(CheckpointErrorCode::ParentMissing, "parent-graph"))?;
            if &node.checkpoint.bindings != bindings {
                return Err(error(
                    CheckpointErrorCode::ParentBindingMismatch,
                    "parent-graph",
                ));
            }
            depth += 1;
            match node.checkpoint.parent {
                Some(parent) if parent == current => {
                    return Err(error(CheckpointErrorCode::ParentCycle, "self-parent"));
                }
                Some(parent) => current = parent,
                None => break,
            }
        }
    }
    Ok(())
}

fn collect_loaded_graph(
    records: impl IntoIterator<Item = LoadedCheckpoint>,
) -> Result<BTreeMap<CheckpointId, LoadedCheckpoint>> {
    let mut complete = BTreeMap::new();
    for loaded in records {
        let id = loaded.checkpoint.id;
        if complete.insert(id, loaded).is_some() {
            return Err(error(
                CheckpointErrorCode::NamespaceCorrupt,
                "duplicate-checkpoint-id",
            ));
        }
    }
    Ok(complete)
}

fn ensure_private_child_directory(parent: &Path, child: &Path) -> Result<()> {
    reject_link_or_non_directory(parent, true, "directory-parent")?;
    if child.parent() != Some(parent) {
        return Err(error(
            CheckpointErrorCode::NamespaceUnsafe,
            "directory-parent",
        ));
    }
    match fs::symlink_metadata(child) {
        Ok(_) => reject_link_or_non_directory(child, true, "private-directory"),
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory_new(child)?;
            reject_link_or_non_directory(parent, true, "directory-parent")?;
            reject_link_or_non_directory(child, true, "private-directory")?;
            sync_directory(child)?;
            sync_directory(parent)
        }
        Err(_) => Err(error(CheckpointErrorCode::Io, "directory-metadata")),
    }
}

fn create_private_directory_new(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error(CheckpointErrorCode::NamespaceUnsafe, "directory-parent"))?;
    reject_link_or_non_directory(parent, true, "directory-parent")?;
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|failure| directory_create_error(&failure))?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path).map_err(|failure| directory_create_error(&failure))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| error(CheckpointErrorCode::Io, "directory-permissions"))?;
    reject_link_or_non_directory(path, true, "created-directory")
}

fn directory_create_error(failure: &std::io::Error) -> CheckpointError {
    error(
        if failure.kind() == std::io::ErrorKind::AlreadyExists {
            CheckpointErrorCode::AlreadyExists
        } else {
            CheckpointErrorCode::Io
        },
        "directory-create",
    )
}

fn reject_link_or_non_directory(path: &Path, _private: bool, context: &'static str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| error(CheckpointErrorCode::RootUnsafe, context))?;
    if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
        return Err(error(CheckpointErrorCode::NamespaceUnsafe, context));
    }
    #[cfg(unix)]
    if _private && metadata.mode() & 0o7777 != 0o700 {
        return Err(error(CheckpointErrorCode::NamespaceUnsafe, context));
    }
    Ok(())
}

fn reject_link_or_non_regular_file(path: &Path, context: &'static str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| error(CheckpointErrorCode::Io, context))?;
    if !metadata.file_type().is_file() || metadata_is_reparse_point(&metadata) {
        return Err(error(CheckpointErrorCode::NamespaceUnsafe, context));
    }
    #[cfg(unix)]
    if metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1 {
        return Err(error(CheckpointErrorCode::NamespaceUnsafe, context));
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error(CheckpointErrorCode::NamespaceUnsafe, "artifact-parent"))?;
    reject_link_or_non_directory(parent, true, "artifact-parent")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path).map_err(|failure| {
        error(
            if failure.kind() == std::io::ErrorKind::AlreadyExists {
                CheckpointErrorCode::ConcurrentMutation
            } else {
                CheckpointErrorCode::Io
            },
            "artifact-create",
        )
    })?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-permissions"))?;
    file.write_all(bytes)
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-write"))?;
    file.sync_all()
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-sync"))?;
    #[cfg(windows)]
    require_windows_single_link(&file)?;
    drop(file);
    reject_link_or_non_regular_file(path, "artifact-after-write")
}

fn safe_file_length(path: &Path, maximum: u64) -> Result<u64> {
    reject_link_or_non_regular_file(path, "artifact-length")?;
    let length = fs::symlink_metadata(path)
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-length"))?
        .len();
    if length > maximum {
        return Err(error(CheckpointErrorCode::BytesExceeded, "artifact-length"));
    }
    Ok(length)
}

fn sync_recoverable_artifacts(entry: &Path) -> Result<()> {
    sync_existing_private_file(&entry.join(INTENT_FILE), SMALL_METADATA_BYTES_MAXIMUM)?;
    sync_existing_private_file(&entry.join(RECORD_FILE), RECORD_BYTES_MAXIMUM)?;
    sync_directory(entry)
}

fn sync_complete_artifacts(entry: &Path) -> Result<()> {
    sync_recoverable_artifacts(entry)?;
    sync_existing_private_file(&entry.join(COMPLETE_FILE), SMALL_METADATA_BYTES_MAXIMUM)?;
    sync_directory(entry)
}

fn sync_existing_private_file(path: &Path, maximum: u64) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| error(CheckpointErrorCode::NamespaceUnsafe, "artifact-parent"))?;
    reject_link_or_non_directory(parent, true, "artifact-parent")?;
    reject_link_or_non_regular_file(path, "artifact-sync-existing")?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-sync-open"))?;
    let _ = validate_open_artifact_handle(&file, maximum)?;
    file.sync_all()
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-sync-existing"))?;
    let _ = validate_open_artifact_handle(&file, maximum)?;
    drop(file);
    reject_link_or_non_regular_file(path, "artifact-after-sync")
}

fn read_safe_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let parent = path
        .parent()
        .ok_or_else(|| error(CheckpointErrorCode::NamespaceUnsafe, "artifact-parent"))?;
    reject_link_or_non_directory(parent, true, "artifact-parent")?;
    reject_link_or_non_regular_file(path, "artifact-read")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-open"))?;
    let initial_length = validate_open_artifact_handle(&file, maximum)?;
    let take = maximum
        .checked_add(1)
        .ok_or_else(|| error(CheckpointErrorCode::BytesExceeded, "artifact-limit"))?;
    let mut bytes = Vec::new();
    (&file)
        .take(take)
        .read_to_end(&mut bytes)
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-read"))?;
    if bytes.len() as u64 > maximum {
        return Err(error(CheckpointErrorCode::BytesExceeded, "artifact-read"));
    }
    let final_length = validate_open_artifact_handle(&file, maximum)?;
    if initial_length != final_length || final_length != bytes.len() as u64 {
        return Err(error(
            CheckpointErrorCode::ConcurrentMutation,
            "artifact-read-length",
        ));
    }
    drop(file);
    reject_link_or_non_regular_file(path, "artifact-after-read")?;
    Ok(bytes)
}

fn validate_open_artifact_handle(file: &fs::File, maximum: u64) -> Result<u64> {
    let handle_metadata = file
        .metadata()
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-handle-metadata"))?;
    if !handle_metadata.file_type().is_file() || metadata_is_reparse_point(&handle_metadata) {
        return Err(error(
            CheckpointErrorCode::NamespaceUnsafe,
            "artifact-handle",
        ));
    }
    if handle_metadata.len() > maximum {
        return Err(error(
            CheckpointErrorCode::BytesExceeded,
            "artifact-handle-length",
        ));
    }
    #[cfg(unix)]
    if handle_metadata.mode() & 0o7777 != 0o600 || handle_metadata.nlink() != 1 {
        return Err(error(
            CheckpointErrorCode::NamespaceUnsafe,
            "artifact-handle",
        ));
    }
    #[cfg(windows)]
    require_windows_single_link(file)?;
    Ok(handle_metadata.len())
}

#[cfg(windows)]
fn require_windows_single_link(file: &fs::File) -> Result<()> {
    let information = winapi_util::file::information(file)
        .map_err(|_| error(CheckpointErrorCode::Io, "artifact-handle-links"))?;
    if information.number_of_links() != 1 {
        return Err(error(
            CheckpointErrorCode::NamespaceUnsafe,
            "artifact-hard-link",
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    reject_link_or_non_directory(path, true, "directory-sync")?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    }
    let directory = options
        .open(path)
        .map_err(|_| error(CheckpointErrorCode::Io, "directory-open"))?;
    let metadata = directory
        .metadata()
        .map_err(|_| error(CheckpointErrorCode::Io, "directory-handle-metadata"))?;
    if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
        return Err(error(
            CheckpointErrorCode::NamespaceUnsafe,
            "directory-handle",
        ));
    }
    directory
        .sync_all()
        .map_err(|_| error(CheckpointErrorCode::Io, "directory-sync"))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(is_lower_hex) {
        return Err(error(CheckpointErrorCode::InputInvalid, "hex-value"));
    }
    let mut decoded = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(error(CheckpointErrorCode::InputInvalid, "hex-value")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestWorkspace {
        path: PathBuf,
    }

    impl TestWorkspace {
        fn new(label: &str) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ogvcs-local-checkpoint-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let control = path.join(".ogvcs");
            fs::create_dir(&control).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).unwrap();
            Self { path }
        }

        fn store(&self) -> CheckpointStore {
            CheckpointStore::open(&self.path).unwrap()
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn object(kind: ObjectKind, value: u8) -> ObjectRef {
        ObjectRef {
            kind,
            digest: [value; 32],
        }
    }

    fn file_id(value: u8) -> FileId {
        let mut bytes = [0u8; 16];
        bytes[15] = value.max(1);
        FileId::new(bytes).unwrap()
    }

    fn bindings(seed: u8) -> CheckpointBindings {
        CheckpointBindings {
            repository: object(ObjectKind::RepositoryDescriptor, seed),
            base_snapshot: object(ObjectKind::Snapshot, seed.wrapping_add(1)),
            workspace_id: [seed.wrapping_add(2); 32],
            spec_digest: [seed.wrapping_add(3); 32],
            path_profile: "path.opengamevcs/linux@1".to_owned(),
            case_mode: CaseMode::Sensitive,
        }
    }

    fn content(seed: u8) -> CanonicalContentBinding {
        CanonicalContentBinding {
            manifest: object(ObjectKind::ContentManifest, seed),
            whole_file_digest: [seed.wrapping_add(1); 32],
            logical_length: 7,
            chunks: vec![
                CanonicalChunkBinding {
                    chunk: object(ObjectKind::Chunk, seed.wrapping_add(2)),
                    logical_length: 3,
                },
                CanonicalChunkBinding {
                    chunk: object(ObjectKind::Chunk, seed.wrapping_add(3)),
                    logical_length: 4,
                },
            ],
        }
    }

    fn request(
        parent: Option<CheckpointId>,
        checkpoint_bindings: CheckpointBindings,
        seed: u8,
    ) -> CheckpointCreateRequest {
        CheckpointCreateRequest {
            parent,
            bindings: checkpoint_bindings,
            operations: vec![CheckpointOperation {
                ordinal: 0,
                kind: OperationKind::Add,
                file_id: file_id(seed),
                source_path: None,
                destination_path: Some(format!("Content/file-{seed}.bin")),
                content: Some(content(seed)),
            }],
            message: format!("checkpoint {seed}"),
            created_at_unix_ms: 1_800_000_000_000 + u64::from(seed),
            lock_receipts: LockReceiptSnapshot {
                captured_at_unix_ms: 1_800_000_000_000 + u64::from(seed),
                receipts: vec![HistoricalLockReceipt {
                    path: format!("Content/file-{seed}.bin"),
                    receipt_digest: [seed.wrapping_add(4); 32],
                    observed_lease_expires_unix_ms: Some(1_800_000_060_000 + u64::from(seed)),
                }],
            },
        }
    }

    fn request_id(value: &CheckpointCreateRequest) -> CheckpointId {
        let record = disk_record_from_request(value);
        checkpoint_id(&canonical_json(&record).unwrap())
    }

    fn all_boundaries() -> [PublicationBoundary; 7] {
        [
            PublicationBoundary::EntryDirectorySynced,
            PublicationBoundary::IntentFileSynced,
            PublicationBoundary::IntentDirectorySynced,
            PublicationBoundary::RecordFileSynced,
            PublicationBoundary::RecordDirectorySynced,
            PublicationBoundary::ManifestFileSynced,
            PublicationBoundary::ManifestDirectorySynced,
        ]
    }

    #[test]
    fn complete_checkpoint_is_deterministic_listed_shown_and_verified() {
        let workspace = TestWorkspace::new("complete");
        let store = workspace.store();
        let request = request(None, bindings(11), 11);
        let expected_id = request_id(&request);
        assert_eq!(
            expected_id.to_string(),
            "lcp:v1:sha256:0a65d00f0d7c832a39a4232d418d43520141e3e11f9213646f7f4023b3c4d18f"
        );
        let checkpoint = store
            .create(&request, PublicationControl::default())
            .unwrap();
        assert_eq!(checkpoint.id, expected_id);
        assert_eq!(
            checkpoint.lock_authority,
            LockAuthorityState::HistoricalUntrustedExclusivityUnverified
        );
        assert_eq!(store.show(expected_id).unwrap(), checkpoint);
        assert_eq!(store.list().unwrap().len(), 1);
        let report = store.verify(expected_id).unwrap();
        assert_eq!(report.chain_depth, 1);
        assert_eq!(report.operation_count, 1);
        assert_eq!(report.chunk_reference_count, 2);
        assert_eq!(request_id(&request), expected_id);
        assert!(store
            .recover_incomplete(PublicationControl::default())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn every_publication_boundary_preserves_prior_and_recovery_never_overwrites_workspace() {
        for boundary in all_boundaries() {
            let workspace = TestWorkspace::new("crash-matrix");
            let user_file = workspace.path.join("newer-work.bin");
            fs::write(&user_file, b"newer-uncheckpointed-bytes").unwrap();
            let store = workspace.store();
            let root_request = request(None, bindings(21), 21);
            let root = store
                .create(&root_request, PublicationControl::default())
                .unwrap();
            let child_request = request(Some(root.id), root.bindings.clone(), 22);
            let child_id = request_id(&child_request);
            let failure = store
                .create(
                    &child_request,
                    PublicationControl {
                        stop_after: Some(boundary),
                    },
                )
                .unwrap_err();
            assert_eq!(failure.code(), CheckpointErrorCode::InjectedCrash);
            assert_eq!(store.show(root.id).unwrap(), root);
            assert_eq!(fs::read(&user_file).unwrap(), b"newer-uncheckpointed-bytes");

            let recovery = store
                .recover_incomplete(PublicationControl::default())
                .unwrap();
            assert_eq!(fs::read(&user_file).unwrap(), b"newer-uncheckpointed-bytes");
            match boundary {
                PublicationBoundary::EntryDirectorySynced => {
                    assert_eq!(recovery.len(), 1);
                    assert_eq!(
                        recovery[0].disposition,
                        RecoveryDisposition::IncompleteReported
                    );
                    assert_eq!(store.list().unwrap().len(), 1);
                }
                PublicationBoundary::IntentFileSynced
                | PublicationBoundary::IntentDirectorySynced => {
                    assert_eq!(recovery.len(), 1);
                    assert_eq!(
                        recovery[0].disposition,
                        RecoveryDisposition::IncompleteReported
                    );
                    assert_eq!(store.list().unwrap().len(), 1);
                }
                PublicationBoundary::RecordFileSynced
                | PublicationBoundary::RecordDirectorySynced => {
                    assert_eq!(recovery.len(), 1);
                    assert_eq!(
                        recovery[0].disposition,
                        RecoveryDisposition::RecoveredComplete
                    );
                    assert_eq!(store.show(child_id).unwrap().parent, Some(root.id));
                    assert_eq!(store.list().unwrap().len(), 2);
                }
                PublicationBoundary::ManifestFileSynced
                | PublicationBoundary::ManifestDirectorySynced => {
                    assert!(recovery.is_empty());
                    assert_eq!(store.show(child_id).unwrap().parent, Some(root.id));
                    assert_eq!(store.list().unwrap().len(), 2);
                }
            }
        }
    }

    #[test]
    fn record_corruption_is_detected_without_hiding_an_unrelated_complete_parent() {
        let workspace = TestWorkspace::new("corrupt-record");
        let store = workspace.store();
        let root = store
            .create(
                &request(None, bindings(31), 31),
                PublicationControl::default(),
            )
            .unwrap();
        let child = store
            .create(
                &request(Some(root.id), root.bindings.clone(), 32),
                PublicationControl::default(),
            )
            .unwrap();
        let record = store
            .entries_root
            .join(child.id.directory_name())
            .join(RECORD_FILE);
        let mut bytes = fs::read(&record).unwrap();
        let index = bytes.iter().position(|byte| *byte == b'c').unwrap();
        bytes[index] ^= 1;
        fs::write(&record, bytes).unwrap();
        assert_eq!(
            store.show(child.id).unwrap_err().code(),
            CheckpointErrorCode::IntegrityMismatch
        );
        assert_eq!(store.show(root.id).unwrap(), root);
        assert_eq!(
            store.list().unwrap_err().code(),
            CheckpointErrorCode::IntegrityMismatch
        );
        let recovery = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            recovery[0].disposition,
            RecoveryDisposition::CorruptReported
        );
    }

    #[test]
    fn recovery_refuses_unknown_artifact_before_manifest_seal() {
        let workspace = TestWorkspace::new("unknown-artifact");
        let store = workspace.store();
        let value = request(None, bindings(41), 41);
        let id = request_id(&value);
        let failure = store
            .create(
                &value,
                PublicationControl {
                    stop_after: Some(PublicationBoundary::RecordDirectorySynced),
                },
            )
            .unwrap_err();
        assert_eq!(failure.code(), CheckpointErrorCode::InjectedCrash);
        let extra = store
            .entries_root
            .join(id.directory_name())
            .join("foreign.bin");
        fs::write(&extra, b"foreign").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&extra, fs::Permissions::from_mode(0o600)).unwrap();
        let report = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].disposition, RecoveryDisposition::CorruptReported);
        assert!(!store
            .entries_root
            .join(id.directory_name())
            .join(COMPLETE_FILE)
            .exists());
    }

    #[test]
    fn recovery_rejects_integrity_valid_intent_bound_to_another_entry() {
        let workspace = TestWorkspace::new("substituted-intent");
        let store = workspace.store();
        let value = request(None, bindings(42), 42);
        let id = request_id(&value);
        store
            .create(
                &value,
                PublicationControl {
                    stop_after: Some(PublicationBoundary::IntentDirectorySynced),
                },
            )
            .unwrap_err();
        let intent_path = store
            .entries_root
            .join(id.directory_name())
            .join(INTENT_FILE);
        let substituted = build_intent(CheckpointId([0xaa; 32]), [0xbb; 32], 17).unwrap();
        fs::write(&intent_path, canonical_json(&substituted).unwrap()).unwrap();

        let report = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].checkpoint_id, Some(id));
        assert_eq!(report[0].disposition, RecoveryDisposition::CorruptReported);
        assert_eq!(report[0].reason, CheckpointErrorCode::IntegrityMismatch);
        assert!(!intent_path.parent().unwrap().join(COMPLETE_FILE).exists());
    }

    #[test]
    fn recovery_reports_complete_child_when_its_parent_chain_is_corrupt() {
        let workspace = TestWorkspace::new("corrupt-parent-chain");
        let store = workspace.store();
        let parent = store
            .create(
                &request(None, bindings(43), 43),
                PublicationControl::default(),
            )
            .unwrap();
        let child = store
            .create(
                &request(Some(parent.id), parent.bindings.clone(), 44),
                PublicationControl::default(),
            )
            .unwrap();
        let parent_record = store
            .entries_root
            .join(parent.id.directory_name())
            .join(RECORD_FILE);
        let mut bytes = fs::read(&parent_record).unwrap();
        bytes[0] ^= 1;
        fs::write(parent_record, bytes).unwrap();

        let report = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        let child_item = report
            .iter()
            .find(|item| item.checkpoint_id == Some(child.id))
            .expect("complete child with corrupt ancestry must be reported");
        assert_eq!(child_item.disposition, RecoveryDisposition::CorruptReported);
        assert_eq!(child_item.reason, CheckpointErrorCode::IntegrityMismatch);
        assert!(report
            .iter()
            .any(|item| item.checkpoint_id == Some(parent.id)));
    }

    #[test]
    fn missing_and_binding_mismatched_parents_fail_before_entry_creation() {
        let workspace = TestWorkspace::new("parent-failures");
        let store = workspace.store();
        let missing = CheckpointId([0x99; 32]);
        let missing_request = request(Some(missing), bindings(51), 51);
        assert_eq!(
            store
                .create(&missing_request, PublicationControl::default())
                .unwrap_err()
                .code(),
            CheckpointErrorCode::ParentMissing
        );
        let incomplete_parent = request(None, bindings(50), 50);
        let incomplete_parent_id = request_id(&incomplete_parent);
        store
            .create(
                &incomplete_parent,
                PublicationControl {
                    stop_after: Some(PublicationBoundary::RecordDirectorySynced),
                },
            )
            .unwrap_err();
        let incomplete_child = request(
            Some(incomplete_parent_id),
            incomplete_parent.bindings.clone(),
            51,
        );
        assert_eq!(
            store
                .create(&incomplete_child, PublicationControl::default())
                .unwrap_err()
                .code(),
            CheckpointErrorCode::ParentMissing
        );
        let root = store
            .create(
                &request(None, bindings(52), 52),
                PublicationControl::default(),
            )
            .unwrap();
        let mismatch = request(Some(root.id), bindings(53), 53);
        assert_eq!(
            store
                .create(&mismatch, PublicationControl::default())
                .unwrap_err()
                .code(),
            CheckpointErrorCode::ParentBindingMismatch
        );
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn operation_path_object_and_bounds_fail_closed() {
        let mut invalid_path = request(None, bindings(61), 61);
        invalid_path.operations[0].destination_path = Some("../escape.bin".to_owned());
        assert_eq!(
            validate_request(&invalid_path).unwrap_err().code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut wrong_manifest = request(None, bindings(62), 62);
        wrong_manifest.operations[0]
            .content
            .as_mut()
            .unwrap()
            .manifest = object(ObjectKind::Chunk, 1);
        assert_eq!(
            validate_request(&wrong_manifest).unwrap_err().code(),
            CheckpointErrorCode::ObjectKindInvalid
        );

        let mut message = request(None, bindings(63), 63);
        message.message = "x".repeat(MESSAGE_BYTES_MAXIMUM);
        validate_request(&message).unwrap();
        message.message.push('x');
        assert_eq!(
            validate_request(&message).unwrap_err().code(),
            CheckpointErrorCode::BytesExceeded
        );

        let mut operations = request(None, bindings(64), 64);
        operations.operations = (0..OPERATIONS_MAXIMUM)
            .map(|ordinal| CheckpointOperation {
                ordinal: ordinal as u32,
                kind: OperationKind::Delete,
                file_id: file_id((ordinal % 254 + 1) as u8),
                source_path: Some(format!("Content/{ordinal}.bin")),
                destination_path: None,
                content: None,
            })
            .collect();
        validate_request(&operations).unwrap();
        operations.operations.push(CheckpointOperation {
            ordinal: OPERATIONS_MAXIMUM as u32,
            kind: OperationKind::Delete,
            file_id: file_id(1),
            source_path: Some("Content/plus-one.bin".to_owned()),
            destination_path: None,
            content: None,
        });
        assert_eq!(
            validate_request(&operations).unwrap_err().code(),
            CheckpointErrorCode::CountExceeded
        );

        let mut chunks = request(None, bindings(65), 65);
        let content = chunks.operations[0].content.as_mut().unwrap();
        content.chunks = (0..CHUNK_REFERENCES_MAXIMUM)
            .map(|_| CanonicalChunkBinding {
                chunk: object(ObjectKind::Chunk, 7),
                logical_length: MAXIMUM as u64,
            })
            .collect();
        content.logical_length = (CHUNK_REFERENCES_MAXIMUM as u64) * (MAXIMUM as u64);
        validate_request(&chunks).unwrap();
        let content = chunks.operations[0].content.as_mut().unwrap();
        content.chunks.push(CanonicalChunkBinding {
            chunk: object(ObjectKind::Chunk, 7),
            logical_length: MAXIMUM as u64,
        });
        content.logical_length += MAXIMUM as u64;
        assert_eq!(
            validate_request(&chunks).unwrap_err().code(),
            CheckpointErrorCode::CountExceeded
        );

        let mut receipts = request(None, bindings(66), 66);
        receipts.lock_receipts.receipts = (0..LOCK_RECEIPTS_MAXIMUM)
            .map(|index| HistoricalLockReceipt {
                path: format!("Content/lock-{index}.bin"),
                receipt_digest: [1; 32],
                observed_lease_expires_unix_ms: None,
            })
            .collect();
        validate_request(&receipts).unwrap();
        receipts.lock_receipts.receipts.push(HistoricalLockReceipt {
            path: "Content/lock-plus-one.bin".to_owned(),
            receipt_digest: [1; 32],
            observed_lease_expires_unix_ms: None,
        });
        assert_eq!(
            validate_request(&receipts).unwrap_err().code(),
            CheckpointErrorCode::CountExceeded
        );

        let mut alias_bindings = bindings(67);
        alias_bindings.path_profile = "path.opengamevcs/windows@1".to_owned();
        let mut aliases = request(None, alias_bindings, 67);
        aliases.lock_receipts.receipts = vec![
            HistoricalLockReceipt {
                path: "Content/Foo.bin".to_owned(),
                receipt_digest: [1; 32],
                observed_lease_expires_unix_ms: None,
            },
            HistoricalLockReceipt {
                path: "Content/foo.bin".to_owned(),
                receipt_digest: [2; 32],
                observed_lease_expires_unix_ms: None,
            },
        ];
        assert_eq!(
            validate_request(&aliases).unwrap_err().code(),
            CheckpointErrorCode::InputInvalid
        );

        let mut noncanonical_unicode = request(None, bindings(68), 68);
        noncanonical_unicode.operations[0].destination_path =
            Some("Content/Cafe\u{301}.bin".to_owned());
        assert_eq!(
            validate_request(&noncanonical_unicode).unwrap_err().code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut reserved_control = request(None, bindings(69), 69);
        reserved_control.operations[0].destination_path = Some(".OGVCS/file.bin".to_owned());
        assert_eq!(
            validate_request(&reserved_control).unwrap_err().code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut chunk_length = request(None, bindings(70), 70);
        let chunk_content = chunk_length.operations[0].content.as_mut().unwrap();
        chunk_content.logical_length = MAXIMUM as u64;
        chunk_content.chunks = vec![CanonicalChunkBinding {
            chunk: object(ObjectKind::Chunk, 70),
            logical_length: MAXIMUM as u64,
        }];
        validate_request(&chunk_length).unwrap();
        let chunk_content = chunk_length.operations[0].content.as_mut().unwrap();
        chunk_content.logical_length = MAXIMUM as u64 + 1;
        chunk_content.chunks[0].logical_length = MAXIMUM as u64 + 1;
        assert_eq!(
            validate_request(&chunk_length).unwrap_err().code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut repeated_length_conflict = request(None, bindings(71), 71);
        let conflict_content = repeated_length_conflict.operations[0]
            .content
            .as_mut()
            .unwrap();
        let repeated = object(ObjectKind::Chunk, 71);
        conflict_content.logical_length = 3;
        conflict_content.chunks = vec![
            CanonicalChunkBinding {
                chunk: repeated,
                logical_length: 1,
            },
            CanonicalChunkBinding {
                chunk: repeated,
                logical_length: 2,
            },
        ];
        assert_eq!(
            validate_request(&repeated_length_conflict)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut manifest_projection_conflict = request(None, bindings(72), 72);
        let mut second = manifest_projection_conflict.operations[0].clone();
        second.ordinal = 1;
        second.file_id = file_id(73);
        second.destination_path = Some("Content/manifest-conflict.bin".to_owned());
        second.content.as_mut().unwrap().whole_file_digest = [0xee; 32];
        manifest_projection_conflict.operations.push(second);
        assert_eq!(
            validate_request(&manifest_projection_conflict)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut cross_manifest_chunk_conflict = request(None, bindings(74), 74);
        let mut second = cross_manifest_chunk_conflict.operations[0].clone();
        second.ordinal = 1;
        second.file_id = file_id(75);
        second.destination_path = Some("Content/chunk-conflict.bin".to_owned());
        let second_content = second.content.as_mut().unwrap();
        second_content.manifest = object(ObjectKind::ContentManifest, 0xf0);
        second_content.logical_length = 8;
        second_content.chunks[0].logical_length = 4;
        cross_manifest_chunk_conflict.operations.push(second);
        assert_eq!(
            validate_request(&cross_manifest_chunk_conflict)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::OperationInvalid
        );

        let mut logical_overflow = request(None, bindings(76), 76);
        logical_overflow.operations[0]
            .content
            .as_mut()
            .unwrap()
            .logical_length = LOGICAL_MAXIMUM + 1;
        assert_eq!(
            validate_request(&logical_overflow).unwrap_err().code(),
            CheckpointErrorCode::LogicalOverflow
        );
    }

    #[test]
    fn exact_capacity_depth_path_and_raw_record_byte_edges_fail_closed() {
        ensure_new_checkpoint_capacity(CHECKPOINTS_MAXIMUM - 1).unwrap();
        assert_eq!(
            ensure_new_checkpoint_capacity(CHECKPOINTS_MAXIMUM)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::CountExceeded
        );
        ensure_child_chain_depth(GRAPH_DEPTH_MAXIMUM - 1).unwrap();
        assert_eq!(
            ensure_child_chain_depth(GRAPH_DEPTH_MAXIMUM)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::GraphDepthExceeded
        );

        let mut path_bytes = PATH_BYTES_TOTAL_MAXIMUM - 1;
        charge_path_bytes(&mut path_bytes, 1).unwrap();
        assert_eq!(path_bytes, PATH_BYTES_TOTAL_MAXIMUM);
        assert_eq!(
            charge_path_bytes(&mut path_bytes, 1).unwrap_err().code(),
            CheckpointErrorCode::BytesExceeded
        );

        let mut store_record_bytes = STORE_RECORD_BYTES_MAXIMUM - 1;
        charge_store_record_bytes(&mut store_record_bytes, 1).unwrap();
        assert_eq!(store_record_bytes, STORE_RECORD_BYTES_MAXIMUM);
        assert_eq!(
            charge_store_record_bytes(&mut store_record_bytes, 1)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::BytesExceeded
        );

        let workspace = TestWorkspace::new("raw-record-bound");
        let store = workspace.store();
        let sparse = store.store_root.join("raw-record-bound.bin");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sparse)
            .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&sparse, fs::Permissions::from_mode(0o600)).unwrap();
        file.set_len(RECORD_BYTES_MAXIMUM).unwrap();
        assert_eq!(
            safe_file_length(&sparse, RECORD_BYTES_MAXIMUM).unwrap(),
            RECORD_BYTES_MAXIMUM
        );
        file.set_len(RECORD_BYTES_MAXIMUM + 1).unwrap();
        assert_eq!(
            safe_file_length(&sparse, RECORD_BYTES_MAXIMUM)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::BytesExceeded
        );
        assert_eq!(
            read_safe_file(&sparse, RECORD_BYTES_MAXIMUM)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::BytesExceeded
        );
    }

    fn abstract_loaded(
        id: CheckpointId,
        parent: Option<CheckpointId>,
        value_bindings: CheckpointBindings,
    ) -> LoadedCheckpoint {
        LoadedCheckpoint {
            checkpoint: Checkpoint {
                id,
                parent,
                bindings: value_bindings,
                operations: Vec::new(),
                message: String::new(),
                created_at_unix_ms: 0,
                lock_receipts: LockReceiptSnapshot {
                    captured_at_unix_ms: 0,
                    receipts: Vec::new(),
                },
                lock_authority: LockAuthorityState::HistoricalUntrustedExclusivityUnverified,
            },
            record_sha256: [0; 32],
            record_bytes: 0,
            intent_integrity_sha256: [0; 32],
        }
    }

    fn abstract_id(value: usize) -> CheckpointId {
        let mut digest = [0u8; 32];
        digest[24..].copy_from_slice(&(value as u64).to_be_bytes());
        CheckpointId(digest)
    }

    #[test]
    fn abstract_parent_graph_rejects_cycle_missing_duplicate_identity_and_depth() {
        let shared = bindings(71);
        let first = abstract_id(1);
        let second = abstract_id(2);
        let mut cycle = BTreeMap::new();
        cycle.insert(first, abstract_loaded(first, Some(second), shared.clone()));
        cycle.insert(second, abstract_loaded(second, Some(first), shared.clone()));
        assert_eq!(
            validate_loaded_graph(&cycle).unwrap_err().code(),
            CheckpointErrorCode::ParentCycle
        );

        let mut self_parent = BTreeMap::new();
        self_parent.insert(first, abstract_loaded(first, Some(first), shared.clone()));
        assert_eq!(
            validate_loaded_graph(&self_parent).unwrap_err().code(),
            CheckpointErrorCode::ParentCycle
        );

        let mut missing = BTreeMap::new();
        missing.insert(first, abstract_loaded(first, Some(second), shared.clone()));
        assert_eq!(
            validate_loaded_graph(&missing).unwrap_err().code(),
            CheckpointErrorCode::ParentMissing
        );

        let mut mismatched_identity = BTreeMap::new();
        mismatched_identity.insert(first, abstract_loaded(second, None, shared.clone()));
        assert_eq!(
            validate_loaded_graph(&mismatched_identity)
                .unwrap_err()
                .code(),
            CheckpointErrorCode::NamespaceCorrupt
        );

        let duplicate = abstract_loaded(first, None, shared.clone());
        assert_eq!(
            collect_loaded_graph([duplicate.clone(), duplicate])
                .unwrap_err()
                .code(),
            CheckpointErrorCode::NamespaceCorrupt
        );

        let mut bounded_depth = BTreeMap::new();
        for index in 0..GRAPH_DEPTH_MAXIMUM {
            let id = abstract_id(index + 10);
            let parent = (index + 1 < GRAPH_DEPTH_MAXIMUM).then(|| abstract_id(index + 11));
            bounded_depth.insert(id, abstract_loaded(id, parent, shared.clone()));
        }
        validate_loaded_graph(&bounded_depth).unwrap();
        let mut deep = bounded_depth;
        let previous_tail = abstract_id(GRAPH_DEPTH_MAXIMUM + 9);
        let new_tail = abstract_id(GRAPH_DEPTH_MAXIMUM + 10);
        deep.get_mut(&previous_tail).unwrap().checkpoint.parent = Some(new_tail);
        deep.insert(new_tail, abstract_loaded(new_tail, None, shared.clone()));
        assert_eq!(
            validate_loaded_graph(&deep).unwrap_err().code(),
            CheckpointErrorCode::GraphDepthExceeded
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_store_and_artifact_are_rejected() {
        use std::os::unix::fs::symlink;

        let workspace = TestWorkspace::new("symlink-store");
        let outside = workspace.path.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(
            &outside,
            workspace.path.join(".ogvcs").join(STORE_DIRECTORY),
        )
        .unwrap();
        assert_eq!(
            CheckpointStore::open(&workspace.path).unwrap_err().code(),
            CheckpointErrorCode::NamespaceUnsafe
        );

        let workspace = TestWorkspace::new("symlink-entry");
        let store = workspace.store();
        let value = request(None, bindings(80), 80);
        let id = request_id(&value);
        let outside = workspace.path.join("outside-entry");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&outside, store.entries_root.join(id.directory_name())).unwrap();
        assert_eq!(
            store
                .create(&value, PublicationControl::default())
                .unwrap_err()
                .code(),
            CheckpointErrorCode::NamespaceUnsafe
        );
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
        fs::remove_dir(&outside).unwrap();
        assert_eq!(
            store.show(id).unwrap_err().code(),
            CheckpointErrorCode::NamespaceUnsafe
        );

        let workspace = TestWorkspace::new("symlink-artifact");
        let store = workspace.store();
        let value = request(None, bindings(81), 81);
        let id = request_id(&value);
        store
            .create(
                &value,
                PublicationControl {
                    stop_after: Some(PublicationBoundary::IntentDirectorySynced),
                },
            )
            .unwrap_err();
        let entry = store.entries_root.join(id.directory_name());
        fs::remove_file(entry.join(INTENT_FILE)).unwrap();
        let user_file = workspace.path.join("user.bin");
        fs::write(&user_file, b"do-not-follow").unwrap();
        symlink(&user_file, entry.join(INTENT_FILE)).unwrap();
        let recovery = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].reason, CheckpointErrorCode::NamespaceUnsafe);
        assert_eq!(fs::read(user_file).unwrap(), b"do-not-follow");
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_artifact_is_rejected_before_metadata_read() {
        let workspace = TestWorkspace::new("hardlink-artifact");
        let store = workspace.store();
        let value = request(None, bindings(82), 82);
        let id = request_id(&value);
        store
            .create(
                &value,
                PublicationControl {
                    stop_after: Some(PublicationBoundary::IntentDirectorySynced),
                },
            )
            .unwrap_err();
        let entry = store.entries_root.join(id.directory_name());
        fs::remove_file(entry.join(INTENT_FILE)).unwrap();
        let user_file = workspace.path.join("user-hardlink.bin");
        fs::write(&user_file, b"ordinary-workspace-bytes").unwrap();
        fs::set_permissions(&user_file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&user_file, entry.join(INTENT_FILE)).unwrap();

        let recovery = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].reason, CheckpointErrorCode::NamespaceUnsafe);
        assert_eq!(fs::read(user_file).unwrap(), b"ordinary-workspace-bytes");
    }

    #[cfg(unix)]
    #[test]
    fn arbitrary_entry_name_is_reported_with_a_safe_lossless_projection() {
        let workspace = TestWorkspace::new("arbitrary-entry");
        let store = workspace.store();
        let invalid_name = OsString::from("\n");
        let invalid_entry = store.entries_root.join(&invalid_name);
        fs::create_dir(&invalid_entry).unwrap();
        fs::set_permissions(&invalid_entry, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            store
                .create(
                    &request(None, bindings(83), 83),
                    PublicationControl::default(),
                )
                .unwrap_err()
                .code(),
            CheckpointErrorCode::NamespaceCorrupt
        );

        let recovery = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].entry_name, "os-name-hex:0a");
        assert_eq!(recovery[0].checkpoint_id, None);
        assert_eq!(
            recovery[0].disposition,
            RecoveryDisposition::CorruptReported
        );
        assert_eq!(recovery[0].reason, CheckpointErrorCode::NamespaceCorrupt);
        assert_eq!(
            store.list().unwrap_err().code(),
            CheckpointErrorCode::NamespaceCorrupt
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_entry_name_is_reported_without_lossy_path_access() {
        use std::os::unix::ffi::OsStringExt;

        let workspace = TestWorkspace::new("non-utf8-entry");
        let store = workspace.store();
        let invalid_name = OsString::from_vec(vec![0xff]);
        let invalid_entry = store.entries_root.join(&invalid_name);
        fs::create_dir(&invalid_entry).unwrap();
        fs::set_permissions(&invalid_entry, fs::Permissions::from_mode(0o700)).unwrap();

        let recovery = store
            .recover_incomplete(PublicationControl::default())
            .unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].entry_name, "os-name-hex:ff");
        assert_eq!(recovery[0].checkpoint_id, None);
        assert_eq!(
            recovery[0].disposition,
            RecoveryDisposition::CorruptReported
        );
        assert_eq!(recovery[0].reason, CheckpointErrorCode::NamespaceCorrupt);
    }
}
