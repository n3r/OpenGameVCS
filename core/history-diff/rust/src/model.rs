use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ogvcs_object_model::{FileId, ObjectRef, ProfileRef};
use ogvcs_path_contract::CaseMode;

pub type Generation = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRead {
    pub generation: Generation,
    pub outcome: ObjectReadOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectReadOutcome {
    Found(Vec<u8>),
    Missing,
    Ambiguous,
    ByteLimit { declared_bytes: u64 },
}

/// Private immutable-object seam. A source must honor `maximum_bytes` for both
/// the returned `Vec` length and capacity. Its generation marker identifies one
/// immutable caller-preauthorized view, must not be reused for a distinct view,
/// and must atomically identify every returned object's view. It is not an
/// authorization brand.
pub trait ImmutableObjectSource {
    type Error;

    fn generation(&mut self) -> std::result::Result<Generation, Self::Error>;

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> std::result::Result<ObjectRead, Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct OperationControl {
    cancellation: Arc<AtomicBool>,
}

impl OperationControl {
    pub fn with_cancellation(cancellation: Arc<AtomicBool>) -> Self {
        Self { cancellation }
    }

    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancellation)
    }

    pub fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub page_records: u64,
    pub max_history_snapshots: u64,
    pub max_tree_objects: u64,
    pub max_tree_entries: u64,
    pub max_diff_records: u64,
    pub max_source_reads: u64,
    pub max_source_bytes: u64,
    pub max_object_bytes: u64,
    pub max_work_units: u64,
    pub max_cursor_bytes: u64,
    pub max_charged_memory_bytes: u64,
    pub max_decode_working_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            page_records: 10_000,
            max_history_snapshots: 100_000,
            max_tree_objects: 100_000,
            max_tree_entries: 100_000,
            max_diff_records: 200_000,
            max_source_reads: 300_000,
            max_source_bytes: 512 * 1024 * 1024,
            max_object_bytes: 16 * 1024 * 1024,
            max_work_units: 2_000_000,
            max_cursor_bytes: 128 * 1024 * 1024,
            max_charged_memory_bytes: 256 * 1024 * 1024,
            max_decode_working_bytes: 16 * 1024 * 1024,
        }
    }
}

impl Limits {
    pub(crate) fn is_valid(self) -> bool {
        let minimum_memory = self
            .max_object_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.max_decode_working_bytes))
            .and_then(|value| value.checked_add(4_096));
        self.page_records > 0
            && self.max_history_snapshots > 0
            && self.max_tree_objects > 0
            && self.max_tree_entries > 0
            && self.max_diff_records > 0
            && self.max_source_reads > 0
            && self.max_source_bytes > 0
            && self.max_object_bytes > 0
            && self.max_work_units > 0
            && self.max_cursor_bytes >= 256
            && self.max_decode_working_bytes > 0
            && minimum_memory.is_some_and(|minimum| {
                self.max_charged_memory_bytes >= minimum
                    && self.max_cursor_bytes <= self.max_charged_memory_bytes
            })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkLedger {
    pub generation_checks: u64,
    pub cancellation_checks: u64,
    pub source_reads: u64,
    pub source_bytes: u64,
    pub metadata_objects: u64,
    pub snapshot_edges: u64,
    pub tree_edges: u64,
    pub tree_entries: u64,
    pub comparisons: u64,
    pub emitted_records: u64,
    pub cursor_bytes_encoded: u64,
    pub cursor_bytes_decoded: u64,
    pub cursor_records_decoded: u64,
    pub work_units: u64,
    pub charged_memory_bytes: u64,
    pub peak_charged_memory_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingKind {
    Object,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmbiguousKind {
    Source,
    DuplicateFileId,
    DuplicatePath,
    RepositoryPathCollision,
    PlatformPathCollision,
    SharedTree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorruptKind {
    ObjectIdentity,
    CanonicalFraming,
    KnownSchema,
    SemanticProfile,
    ReferenceKind,
    RepositoryDescriptor,
    SnapshotRoot,
    SnapshotParentDuplicate,
    SnapshotParentCycle,
    SnapshotSecondRoot,
    TreeCycle,
    TreeEntryTarget,
    Path,
    Cursor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    Configuration,
    ObjectBytes,
    SourceReads,
    SourceBytes,
    HistorySnapshots,
    TreeObjects,
    TreeEntries,
    DiffRecords,
    WorkUnits,
    CursorBytes,
    ChargedMemory,
    Arithmetic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    Missing(MissingKind),
    Ambiguous(AmbiguousKind),
    Corrupt(CorruptKind),
    Limit(LimitKind),
    GenerationChanged,
    Cancelled,
    SourceFailure,
    CursorOptionsMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub kind: FailureKind,
    pub reference: Option<ObjectRef>,
}

impl Failure {
    pub(crate) const fn new(kind: FailureKind) -> Self {
        Self {
            kind,
            reference: None,
        }
    }

    pub(crate) const fn for_reference(kind: FailureKind, reference: ObjectRef) -> Self {
        Self {
            kind,
            reference: Some(reference),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl std::error::Error for Failure {}

pub type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRequest {
    pub start_snapshot: ObjectRef,
    pub repository_descriptor: ObjectRef,
    pub designated_root: ObjectRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiffRequest {
    pub before_snapshot: ObjectRef,
    pub after_snapshot: ObjectRef,
    pub repository_descriptor: ObjectRef,
    pub case_mode: CaseMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRecord {
    pub snapshot: ObjectRef,
    pub root_tree: ObjectRef,
    pub parent_count: u8,
    pub depth: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryView {
    pub path: String,
    pub entry_kind: u8,
    pub mode: u8,
    pub target: ObjectRef,
    pub logical_bytes: u64,
    pub content_policy: ProfileRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceChange {
    Added,
    Deleted,
    Retained,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChangeFlags(u16);

impl ChangeFlags {
    pub const CONTENT_MANIFEST: u16 = 1 << 0;
    pub const TREE_METADATA: u16 = 1 << 1;
    pub const ENTRY_TYPE: u16 = 1 << 2;
    pub const MODE: u16 = 1 << 3;
    pub const CONTENT_POLICY: u16 = 1 << 4;
    pub const LOGICAL_SIZE: u16 = 1 << 5;
    pub const PATH: u16 = 1 << 6;

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    pub(crate) const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !0x7f == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub(crate) fn insert(&mut self, flag: u16) {
        self.0 |= flag;
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MoveHint {
    None,
    Rename,
    Move,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffRecord {
    pub file_id: FileId,
    pub before: Option<EntryView>,
    pub after: Option<EntryView>,
    pub presence: PresenceChange,
    pub changes: ChangeFlags,
    pub move_hint: MoveHint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryCursor(pub(crate) Vec<u8>);

impl HistoryCursor {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8], maximum_bytes: u64) -> Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
            return Err(Failure::new(FailureKind::Limit(LimitKind::CursorBytes)));
        }
        Ok(Self(bytes.to_vec()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffCursor(pub(crate) Vec<u8>);

impl DiffCursor {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8], maximum_bytes: u64) -> Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum_bytes {
            return Err(Failure::new(FailureKind::Limit(LimitKind::CursorBytes)));
        }
        Ok(Self(bytes.to_vec()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryPage {
    pub generation: Generation,
    pub records: Vec<HistoryRecord>,
    pub next: Option<HistoryCursor>,
    pub complete: bool,
    pub ledger: WorkLedger,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiffPage {
    pub generation: Generation,
    pub path_profile: String,
    pub records: Vec<DiffRecord>,
    pub next: Option<DiffCursor>,
    pub complete: bool,
    pub ledger: WorkLedger,
}
