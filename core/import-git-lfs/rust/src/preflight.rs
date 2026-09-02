use std::collections::BTreeMap;
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ogvcs_object_model::{
    import_mapping_key, FileId, ImportDecision, ImportMapping, ImportRequest, ObjectKind,
    ObjectRef, ProfileRef, Sha256Writer,
};
use ogvcs_path_contract::{path_collision_keys_with_options, CaseMode, PathProfile};

use crate::{
    classify_lfs_pointer, GitObjectId, LfsObjectId, LfsPointer, PointerClassification,
    PointerErrorCode, GIT_LFS_POINTER_BYTES_MAXIMUM,
};

const INVENTORY_DOMAIN: &[u8] = b"opengamevcs/git-import/source-inventory/v1\0";
const POLICY_DOMAIN: &[u8] = b"opengamevcs/git-import/policy/v1\0";
const MAPPING_DOMAIN: &[u8] = b"opengamevcs/git-import/mapping-plan/v1\0";
const REPORT_DOMAIN: &[u8] = b"opengamevcs/git-import/preflight-report/v1\0";
const PATH_DOMAIN: &[u8] = b"opengamevcs/git-import/path-diagnostic/v1\0";
const BLOB_PROBE_DOMAIN: &[u8] = b"opengamevcs/git-import/blob-probe/v1\0";

pub const ITEMS_HARD_MAXIMUM: u64 = 1_000_000;
pub const RELATIONSHIPS_HARD_MAXIMUM: u64 = 16_000_000;
pub const GIT_BYTES_HARD_MAXIMUM: u64 = 1_099_511_627_776;
pub const INPUT_BYTES_HARD_MAXIMUM: u64 = 68_719_476_736;
pub const LFS_BYTES_HARD_MAXIMUM: u64 = 8_796_093_022_208;
pub const RETAINED_BYTES_HARD_MAXIMUM: u64 = 536_870_912;
pub const WORK_UNITS_HARD_MAXIMUM: u64 = 64_000_000;
pub const READ_CHUNK_BYTES_HARD_MAXIMUM: usize = 65_536;
pub const PATH_BYTES_HARD_MAXIMUM: usize = 32_768;
pub const REF_NAME_BYTES_HARD_MAXIMUM: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitEntryMode {
    Regular,
    Executable,
    Symlink,
    Submodule,
}

impl GitEntryMode {
    const fn code(self) -> u32 {
        match self {
            Self::Regular => 0o100644,
            Self::Executable => 0o100755,
            Self::Symlink => 0o120000,
            Self::Submodule => 0o160000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LfsDisposition {
    /// Preserve the Git blob bytes exactly at this occurrence. This is a
    /// caller-supplied commitment, not proof that `.gitattributes` was parsed.
    Ordinary,
    /// Resolve only a canonical Git LFS pointer at a regular/executable path.
    /// This is likewise a caller-supplied attribute commitment.
    Required,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ImportRecord {
    Ref {
        name: String,
        target: GitObjectId,
    },
    Commit {
        id: GitObjectId,
        encoded_bytes: u64,
        parent_count: u32,
    },
    Tree {
        id: GitObjectId,
        encoded_bytes: u64,
        entry_count: u64,
    },
    Entry {
        id: GitObjectId,
        path: String,
        mode: GitEntryMode,
        encoded_bytes: u64,
        pointer_probe: Vec<u8>,
        lfs: LfsDisposition,
    },
    Mapping {
        occurrence: SourceOccurrence,
        request: ImportRequest,
    },
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub enum ImportRecordKey {
    Ref(String),
    Commit(GitObjectId),
    Tree(GitObjectId),
    Entry(GitObjectId, String),
    Mapping(SourceOccurrence),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SourceOccurrence {
    source_object: GitObjectId,
    path_digest: [u8; 32],
}

impl SourceOccurrence {
    /// Construct an occurrence commitment supplied by the inventory adapter.
    /// This binds a Git object to a validated target-path digest inside this
    /// preflight only. It is deliberately not a derivation of, or an
    /// authenticated relationship to, `ImportRequest::source_identity_digest`.
    pub const fn new(source_object: GitObjectId, path_digest: [u8; 32]) -> Self {
        Self {
            source_object,
            path_digest,
        }
    }

    pub const fn source_object(self) -> GitObjectId {
        self.source_object
    }

    pub const fn path_digest(self) -> [u8; 32] {
        self.path_digest
    }
}

impl ImportRecord {
    pub fn key(&self) -> ImportRecordKey {
        match self {
            Self::Ref { name, .. } => ImportRecordKey::Ref(name.clone()),
            Self::Commit { id, .. } => ImportRecordKey::Commit(*id),
            Self::Tree { id, .. } => ImportRecordKey::Tree(*id),
            Self::Entry { id, path, .. } => ImportRecordKey::Entry(*id, path.clone()),
            Self::Mapping { occurrence, .. } => ImportRecordKey::Mapping(*occurrence),
        }
    }
}

pub trait InventorySource {
    type Error;

    /// A stable, caller-defined generation for the already-staged projection.
    fn generation(&self) -> [u8; 32];

    fn next_record(&mut self) -> Result<Option<ImportRecord>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportReadStatus {
    Data(usize),
    Missing,
    Ambiguous,
}

pub trait LfsContentSource {
    type Error;

    /// A stable generation for the staged LFS object set.
    fn generation(&self) -> [u8; 32];

    /// Copy bytes beginning at `offset` into `buffer`. Returning `Data(0)` is
    /// EOF. Implementations must never report more bytes than the buffer holds.
    fn read(
        &mut self,
        oid: LfsObjectId,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<ImportReadStatus, Self::Error>;
}

pub trait MappingAuthority {
    type Error;

    /// A stable generation for the OGVCS-002 repository authority view.
    fn generation(&self) -> [u8; 32];

    /// This method is a read-only, side-effect-free lookup over one pinned
    /// authority view. It must not reserve, persist, publish, or otherwise
    /// mutate product state. Production adapters are expected to obtain a
    /// caller-supplied OGVCS-002 `validate_import_request` decision before any
    /// later authorized write; this private crate emits only an in-memory plan.
    fn decide(&self, request: &ImportRequest) -> Result<ImportDecision, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportPolicy {
    pub descriptor: ObjectRef,
    pub importer_profile: ProfileRef,
    pub source_namespace_digest: [u8; 32],
    pub path_profile: PathProfile,
    pub case_mode: CaseMode,
    pub permit_executable: bool,
    pub permit_symlink_inventory: bool,
    pub permit_submodule_inventory: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportLimits {
    pub items_maximum: u64,
    pub relationships_maximum: u64,
    pub git_bytes_maximum: u64,
    pub input_bytes_maximum: u64,
    pub lfs_objects_maximum: u64,
    pub lfs_object_bytes_maximum: u64,
    pub lfs_bytes_maximum: u64,
    pub mappings_maximum: u64,
    pub findings_maximum: u64,
    pub work_units_maximum: u64,
    pub retained_bytes_maximum: u64,
    pub path_bytes_maximum: usize,
    pub ref_name_bytes_maximum: usize,
    pub read_chunk_bytes: usize,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            items_maximum: 100_000,
            relationships_maximum: 1_000_000,
            git_bytes_maximum: 17_179_869_184,
            input_bytes_maximum: 1_073_741_824,
            lfs_objects_maximum: 100_000,
            lfs_object_bytes_maximum: 68_719_476_736,
            lfs_bytes_maximum: 1_099_511_627_776,
            mappings_maximum: 100_000,
            findings_maximum: 100_000,
            work_units_maximum: 4_000_000,
            retained_bytes_maximum: 134_217_728,
            path_bytes_maximum: 16_384,
            ref_name_bytes_maximum: 1_024,
            read_chunk_bytes: 65_536,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InventoryCounts {
    pub items: u64,
    pub refs: u64,
    pub commits: u64,
    pub trees: u64,
    pub entries: u64,
    pub blobs: u64,
    pub blob_occurrences: u64,
    pub mappings: u64,
    pub relationships: u64,
    pub lfs_pointers: u64,
    pub lfs_objects: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedInventory {
    pub source_generation: [u8; 32],
    pub lfs_generation: [u8; 32],
    pub mapping_generation: [u8; 32],
    pub counts: InventoryCounts,
    pub git_bytes: u64,
    pub input_bytes: u64,
    pub inventory_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingKind {
    PathInvalid,
    RepositoryPathCollision,
    PlatformPathCollision,
    ExecutableBlocked,
    SymlinkBlocked,
    SubmoduleBlocked,
    LfsExtensionBlocked,
    MappingMissing,
}

impl FindingKind {
    const fn code(self) -> u8 {
        match self {
            Self::PathInvalid => 1,
            Self::RepositoryPathCollision => 2,
            Self::PlatformPathCollision => 3,
            Self::ExecutableBlocked => 4,
            Self::SymlinkBlocked => 5,
            Self::SubmoduleBlocked => 6,
            Self::LfsExtensionBlocked => 7,
            Self::MappingMissing => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finding {
    pub kind: FindingKind,
    pub source_object: GitObjectId,
    pub path_digest: [u8; 32],
    pub conflicting_path_digest: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedImport {
    pub source_object: GitObjectId,
    pub path_digest: [u8; 32],
    pub mode: GitEntryMode,
    pub logical_bytes: u64,
    pub lfs_object: Option<LfsObjectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MappingPlan {
    pub occurrence: SourceOccurrence,
    pub mapping: ImportMapping,
    pub retry: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportPreflightReport {
    pub ready: bool,
    pub source_generation: [u8; 32],
    pub lfs_generation: [u8; 32],
    pub mapping_generation: [u8; 32],
    pub counts: InventoryCounts,
    pub git_bytes: u64,
    pub lfs_bytes_verified: u64,
    pub input_bytes: u64,
    pub work_units: u64,
    pub peak_retained_bytes: u64,
    pub inventory_digest: [u8; 32],
    pub policy_digest: [u8; 32],
    pub mapping_digest: [u8; 32],
    pub report_digest: [u8; 32],
    pub entries: Vec<PreparedImport>,
    pub mappings: Vec<MappingPlan>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportPreflightErrorCode {
    PolicyInvalid,
    LimitsInvalid,
    ExpectedInventoryInvalid,
    Cancelled,
    SourceFailure,
    SourceGenerationChanged,
    SourceContractViolation,
    InventoryUnordered,
    InventoryDuplicate,
    PointerMalformed,
    PointerNonCanonical,
    PointerRequired,
    LfsObjectMissing,
    LfsObjectAmbiguous,
    LfsObjectSizeMismatch,
    LfsObjectDigestMismatch,
    LfsPointerConflict,
    BlobObjectConflict,
    MappingAuthorityFailure,
    MappingDecisionMismatch,
    MappingKeyMismatch,
    MappingSourceDuplicate,
    MappingSourceMissing,
    MappingOccurrenceDuplicate,
    MappingFileIdConflict,
    ReconciliationMismatch,
    LimitItems,
    LimitRelationships,
    LimitGitBytes,
    LimitLfsObjects,
    LimitLfsObjectBytes,
    LimitLfsBytes,
    LimitMappings,
    LimitFindings,
    LimitWork,
    LimitRetainedBytes,
    LimitInputBytes,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportPreflightError {
    code: ImportPreflightErrorCode,
}

impl ImportPreflightError {
    const fn new(code: ImportPreflightErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> ImportPreflightErrorCode {
        self.code
    }
}

impl fmt::Display for ImportPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.code)
    }
}

impl std::error::Error for ImportPreflightError {}

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

    fn check(&self) -> Result<(), ImportPreflightError> {
        if self.cancellation.load(Ordering::Acquire) {
            Err(ImportPreflightError::new(
                ImportPreflightErrorCode::Cancelled,
            ))
        } else {
            Ok(())
        }
    }
}

struct Ledger {
    limits: ImportLimits,
    work: u64,
    retained: u64,
    peak_retained: u64,
    input: u64,
}

impl Ledger {
    fn new(limits: ImportLimits) -> Self {
        Self {
            limits,
            work: 0,
            retained: 0,
            peak_retained: 0,
            input: 0,
        }
    }

    fn work(&mut self, units: u64) -> Result<(), ImportPreflightError> {
        self.work = checked_add(self.work, units)?;
        enforce(
            self.work,
            self.limits.work_units_maximum,
            ImportPreflightErrorCode::LimitWork,
        )
    }

    fn input(&mut self, bytes: u64) -> Result<(), ImportPreflightError> {
        self.input = checked_add(self.input, bytes)?;
        enforce(
            self.input,
            self.limits.input_bytes_maximum,
            ImportPreflightErrorCode::LimitInputBytes,
        )
    }

    fn reserve(&mut self, bytes: u64) -> Result<(), ImportPreflightError> {
        self.retained = checked_add(self.retained, bytes)?;
        enforce(
            self.retained,
            self.limits.retained_bytes_maximum,
            ImportPreflightErrorCode::LimitRetainedBytes,
        )?;
        self.peak_retained = self.peak_retained.max(self.retained);
        Ok(())
    }

    fn release(&mut self, bytes: u64) -> Result<(), ImportPreflightError> {
        self.retained = self.retained.checked_sub(bytes).ok_or_else(|| {
            ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow)
        })?;
        Ok(())
    }
}

struct PreflightState {
    counts: InventoryCounts,
    git_bytes: u64,
    lfs_bytes: u64,
    inventory_hash: Sha256Writer,
    mapping_hash: Sha256Writer,
    entries: Vec<PreparedImport>,
    mappings: Vec<MappingPlan>,
    findings: Vec<Finding>,
    previous_key: Option<ImportRecordKey>,
    previous_key_bytes: u64,
    repository_paths: BTreeMap<String, ([u8; 32], GitObjectId)>,
    platform_paths: BTreeMap<String, ([u8; 32], GitObjectId)>,
    verified_lfs: BTreeMap<LfsObjectId, u64>,
    mapping_sources: BTreeMap<[u8; 32], (SourceOccurrence, FileId)>,
    mapping_file_ids: BTreeMap<FileId, [u8; 32]>,
    blob_objects: BTreeMap<GitObjectId, BlobMetadata>,
    blob_occurrences: BTreeMap<SourceOccurrence, ()>,
    mapped_occurrences: BTreeMap<SourceOccurrence, ()>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct BlobMetadata {
    encoded_bytes: u64,
    probe_digest: [u8; 32],
    lfs_discovered: bool,
}

impl PreflightState {
    fn new() -> Self {
        let mut inventory_hash = Sha256Writer::new();
        inventory_hash.update(INVENTORY_DOMAIN);
        let mut mapping_hash = Sha256Writer::new();
        mapping_hash.update(MAPPING_DOMAIN);
        Self {
            counts: InventoryCounts::default(),
            git_bytes: 0,
            lfs_bytes: 0,
            inventory_hash,
            mapping_hash,
            entries: Vec::new(),
            mappings: Vec::new(),
            findings: Vec::new(),
            previous_key: None,
            previous_key_bytes: 0,
            repository_paths: BTreeMap::new(),
            platform_paths: BTreeMap::new(),
            verified_lfs: BTreeMap::new(),
            mapping_sources: BTreeMap::new(),
            mapping_file_ids: BTreeMap::new(),
            blob_objects: BTreeMap::new(),
            blob_occurrences: BTreeMap::new(),
            mapped_occurrences: BTreeMap::new(),
        }
    }
}

pub fn preflight_git_import<I, L, M>(
    inventory: &mut I,
    lfs_source: &mut L,
    mapping_authority: &mut M,
    policy: &ImportPolicy,
    limits: ImportLimits,
    expected: ExpectedInventory,
    control: &OperationControl,
) -> Result<ImportPreflightReport, ImportPreflightError>
where
    I: InventorySource,
    L: LfsContentSource,
    M: MappingAuthority,
{
    validate_limits(limits)?;
    validate_policy(policy)?;
    validate_expected_inventory(expected, limits)?;
    control.check()?;
    check_generation(inventory.generation(), expected.source_generation)?;
    check_generation(lfs_source.generation(), expected.lfs_generation)?;
    check_generation(mapping_authority.generation(), expected.mapping_generation)?;
    control.check()?;

    let mut ledger = Ledger::new(limits);
    let mut state = PreflightState::new();
    loop {
        control.check()?;
        ledger.work(1)?;
        let record = inventory
            .next_record()
            .map_err(|_| ImportPreflightError::new(ImportPreflightErrorCode::SourceFailure))?;
        check_generation(inventory.generation(), expected.source_generation)?;
        control.check()?;
        let Some(mut record) = record else { break };
        state.counts.items = checked_add(state.counts.items, 1)?;
        enforce(
            state.counts.items,
            limits.items_maximum,
            ImportPreflightErrorCode::LimitItems,
        )?;
        normalize_and_validate_record_shape(&mut record, limits)?;
        let record_bytes = record_input_bytes(&record)?;
        let transient_bytes = record_retained_bytes(&record)?;
        ledger.reserve(transient_bytes)?;
        ledger.input(record_bytes)?;
        ledger.work(input_work_units(record_bytes)?)?;
        control.check()?;
        update_inventory_hash(&mut state.inventory_hash, &record)?;
        enforce_record_order(&record, &mut state, &mut ledger)?;
        process_record(
            record,
            lfs_source,
            mapping_authority,
            policy,
            expected,
            control,
            &mut state,
            &mut ledger,
        )?;
        ledger.release(transient_bytes)?;
    }
    control.check()?;
    check_generation(inventory.generation(), expected.source_generation)?;
    check_generation(lfs_source.generation(), expected.lfs_generation)?;
    check_generation(mapping_authority.generation(), expected.mapping_generation)?;
    control.check()?;

    add_missing_mapping_findings(&mut state, &mut ledger, control)?;

    let inventory_digest = state.inventory_hash.clone().finish();
    if state.counts != expected.counts
        || state.git_bytes != expected.git_bytes
        || ledger.input != expected.input_bytes
        || inventory_digest != expected.inventory_digest
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::ReconciliationMismatch,
        ));
    }
    let sort_work = comparison_sort_work(state.findings.len())?;
    ledger.work(sort_work)?;
    control.check()?;
    state.findings.sort_unstable_by_key(|finding| {
        (
            finding.kind,
            finding.source_object,
            finding.path_digest,
            finding.conflicting_path_digest,
        )
    });
    let policy_digest = hash_policy(policy);
    let mapping_digest = state.mapping_hash.clone().finish();
    let report_work = checked_add(
        checked_add(state.entries.len() as u64, state.mappings.len() as u64)?,
        checked_add(state.findings.len() as u64, 1)?,
    )?;
    ledger.work(report_work)?;
    control.check()?;
    let report_digest = hash_report(
        &state,
        inventory_digest,
        policy_digest,
        mapping_digest,
        ledger.input,
        ledger.work,
        ledger.peak_retained,
        limits,
        expected,
    );
    control.check()?;
    check_generation(inventory.generation(), expected.source_generation)?;
    check_generation(lfs_source.generation(), expected.lfs_generation)?;
    check_generation(mapping_authority.generation(), expected.mapping_generation)?;
    control.check()?;
    Ok(ImportPreflightReport {
        ready: state.findings.is_empty(),
        source_generation: expected.source_generation,
        lfs_generation: expected.lfs_generation,
        mapping_generation: expected.mapping_generation,
        counts: state.counts,
        git_bytes: state.git_bytes,
        lfs_bytes_verified: state.lfs_bytes,
        input_bytes: ledger.input,
        work_units: ledger.work,
        peak_retained_bytes: ledger.peak_retained,
        inventory_digest,
        policy_digest,
        mapping_digest,
        report_digest,
        entries: state.entries,
        mappings: state.mappings,
        findings: state.findings,
    })
}

#[allow(clippy::too_many_arguments)]
fn process_record<L, M>(
    record: ImportRecord,
    lfs_source: &mut L,
    mapping_authority: &mut M,
    policy: &ImportPolicy,
    expected: ExpectedInventory,
    control: &OperationControl,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError>
where
    L: LfsContentSource,
    M: MappingAuthority,
{
    match record {
        ImportRecord::Ref { name, .. } => {
            validate_ref_name(&name, ledger.limits.ref_name_bytes_maximum)?;
            state.counts.refs = checked_add(state.counts.refs, 1)?;
        }
        ImportRecord::Commit {
            encoded_bytes,
            parent_count,
            ..
        } => {
            state.counts.commits = checked_add(state.counts.commits, 1)?;
            add_git_bytes(state, encoded_bytes, ledger.limits.git_bytes_maximum)?;
            add_relationships(state, u64::from(parent_count), ledger)?;
        }
        ImportRecord::Tree {
            encoded_bytes,
            entry_count,
            ..
        } => {
            state.counts.trees = checked_add(state.counts.trees, 1)?;
            add_git_bytes(state, encoded_bytes, ledger.limits.git_bytes_maximum)?;
            add_relationships(state, entry_count, ledger)?;
        }
        ImportRecord::Entry {
            id,
            path,
            mode,
            encoded_bytes,
            pointer_probe,
            lfs,
        } => process_entry(
            id,
            &path,
            mode,
            encoded_bytes,
            &pointer_probe,
            lfs,
            lfs_source,
            policy,
            expected.lfs_generation,
            control,
            state,
            ledger,
        )?,
        ImportRecord::Mapping {
            occurrence,
            request,
        } => process_mapping(
            occurrence,
            request,
            mapping_authority,
            policy,
            expected.mapping_generation,
            control,
            state,
            ledger,
        )?,
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn process_entry<L: LfsContentSource>(
    id: GitObjectId,
    path: &str,
    mode: GitEntryMode,
    encoded_bytes: u64,
    pointer_probe: &[u8],
    disposition: LfsDisposition,
    lfs_source: &mut L,
    policy: &ImportPolicy,
    expected_generation: [u8; 32],
    control: &OperationControl,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    state.counts.entries = checked_add(state.counts.entries, 1)?;
    let path_digest = hash_path(path);
    inspect_path(id, path, path_digest, policy, state, ledger)?;
    inspect_mode(id, mode, path_digest, policy, state, ledger)?;

    if mode == GitEntryMode::Submodule {
        ledger.reserve(512)?;
        state.entries.push(PreparedImport {
            source_object: id,
            path_digest,
            mode,
            logical_bytes: 0,
            lfs_object: None,
        });
        return Ok(());
    }

    state.counts.blob_occurrences = checked_add(state.counts.blob_occurrences, 1)?;
    let occurrence = SourceOccurrence::new(id, path_digest);
    if state.blob_occurrences.contains_key(&occurrence) {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::InventoryDuplicate,
        ));
    }
    ledger.reserve(96)?;
    state.blob_occurrences.insert(occurrence, ());

    let probe_digest = hash_blob_probe(pointer_probe)?;
    let mut metadata = if let Some(previous) = state.blob_objects.get(&id).copied() {
        if previous.encoded_bytes != encoded_bytes || previous.probe_digest != probe_digest {
            return Err(ImportPreflightError::new(
                ImportPreflightErrorCode::BlobObjectConflict,
            ));
        }
        previous
    } else {
        state.counts.blobs = checked_add(state.counts.blobs, 1)?;
        add_git_bytes(state, encoded_bytes, ledger.limits.git_bytes_maximum)?;

        let metadata = BlobMetadata {
            encoded_bytes,
            probe_digest,
            lfs_discovered: false,
        };
        ledger.reserve(160)?;
        state.blob_objects.insert(id, metadata);
        metadata
    };

    // Git applies working-tree conversion only to regular entries; symlink
    // target blobs are materialized verbatim. Ordinary regular entries also
    // remain exact Git bytes even when their contents resemble a pointer.
    let (logical_bytes, lfs_object, has_extensions) = match disposition {
        LfsDisposition::Ordinary => (metadata.encoded_bytes, None, false),
        LfsDisposition::Required => {
            if mode == GitEntryMode::Symlink {
                return Err(ImportPreflightError::new(
                    ImportPreflightErrorCode::SourceContractViolation,
                ));
            }
            let classification = classify_lfs_pointer(pointer_probe).map_err(|error| {
                ImportPreflightError::new(match error.code() {
                    PointerErrorCode::NonCanonical => ImportPreflightErrorCode::PointerNonCanonical,
                    _ => ImportPreflightErrorCode::PointerMalformed,
                })
            })?;
            match classification {
                PointerClassification::NotPointer => {
                    if metadata.encoded_bytes != 0 {
                        return Err(ImportPreflightError::new(
                            ImportPreflightErrorCode::PointerRequired,
                        ));
                    }
                    (0, None, false)
                }
                PointerClassification::Canonical(pointer) => {
                    if !metadata.lfs_discovered {
                        state.counts.lfs_pointers = checked_add(state.counts.lfs_pointers, 1)?;
                        metadata.lfs_discovered = true;
                        state.blob_objects.insert(id, metadata);
                    }
                    verify_lfs_object(
                        &pointer,
                        lfs_source,
                        expected_generation,
                        control,
                        state,
                        ledger,
                    )?;
                    (
                        pointer.size,
                        Some(pointer.oid),
                        !pointer.extensions.is_empty(),
                    )
                }
            }
        }
    };
    if has_extensions {
        push_finding(
            Finding {
                kind: FindingKind::LfsExtensionBlocked,
                source_object: id,
                path_digest,
                conflicting_path_digest: None,
            },
            state,
            ledger,
        )?;
    }
    ledger.reserve(512)?;
    state.entries.push(PreparedImport {
        source_object: id,
        path_digest,
        mode,
        logical_bytes,
        lfs_object,
    });
    Ok(())
}

fn verify_lfs_object<L: LfsContentSource>(
    pointer: &LfsPointer,
    source: &mut L,
    expected_generation: [u8; 32],
    control: &OperationControl,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    enforce(
        pointer.size,
        ledger.limits.lfs_object_bytes_maximum,
        ImportPreflightErrorCode::LimitLfsObjectBytes,
    )?;
    if let Some(previous_size) = state.verified_lfs.get(&pointer.oid) {
        if *previous_size != pointer.size {
            return Err(ImportPreflightError::new(
                ImportPreflightErrorCode::LfsPointerConflict,
            ));
        }
        return Ok(());
    }
    let next_object_count = checked_add(state.counts.lfs_objects, 1)?;
    enforce(
        next_object_count,
        ledger.limits.lfs_objects_maximum,
        ImportPreflightErrorCode::LimitLfsObjects,
    )?;
    let next_lfs_bytes = checked_add(state.lfs_bytes, pointer.size)?;
    enforce(
        next_lfs_bytes,
        ledger.limits.lfs_bytes_maximum,
        ImportPreflightErrorCode::LimitLfsBytes,
    )?;
    control.check()?;
    check_generation(source.generation(), expected_generation)?;
    let chunk_bytes = ledger.limits.read_chunk_bytes;
    ledger.reserve(chunk_bytes as u64)?;
    let mut buffer = vec![0; chunk_bytes];
    let mut hash = Sha256Writer::new();
    let mut offset = 0u64;
    while offset < pointer.size {
        control.check()?;
        check_generation(source.generation(), expected_generation)?;
        ledger.work(1)?;
        let remaining = pointer.size - offset;
        let requested = usize::try_from(remaining.min(chunk_bytes as u64))
            .map_err(|_| ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow))?;
        let read = source
            .read(pointer.oid, offset, &mut buffer[..requested])
            .map_err(|_| ImportPreflightError::new(ImportPreflightErrorCode::SourceFailure))?;
        control.check()?;
        let count = read_count(read, requested)?;
        if count == 0 {
            return Err(ImportPreflightError::new(
                ImportPreflightErrorCode::LfsObjectSizeMismatch,
            ));
        }
        hash.update(&buffer[..count]);
        offset = checked_add(offset, count as u64)?;
    }
    control.check()?;
    check_generation(source.generation(), expected_generation)?;
    ledger.work(1)?;
    let trailer = source
        .read(pointer.oid, offset, &mut buffer[..1])
        .map_err(|_| ImportPreflightError::new(ImportPreflightErrorCode::SourceFailure))?;
    control.check()?;
    if read_count(trailer, 1)? != 0 {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::LfsObjectSizeMismatch,
        ));
    }
    check_generation(source.generation(), expected_generation)?;
    if hash.finish() != *pointer.oid.as_bytes() {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::LfsObjectDigestMismatch,
        ));
    }
    ledger.release(chunk_bytes as u64)?;
    ledger.reserve(96)?;
    state.verified_lfs.insert(pointer.oid, pointer.size);
    state.counts.lfs_objects = next_object_count;
    state.lfs_bytes = next_lfs_bytes;
    Ok(())
}

fn read_count(status: ImportReadStatus, capacity: usize) -> Result<usize, ImportPreflightError> {
    match status {
        ImportReadStatus::Data(count) if count <= capacity => Ok(count),
        ImportReadStatus::Data(_) => Err(ImportPreflightError::new(
            ImportPreflightErrorCode::SourceContractViolation,
        )),
        ImportReadStatus::Missing => Err(ImportPreflightError::new(
            ImportPreflightErrorCode::LfsObjectMissing,
        )),
        ImportReadStatus::Ambiguous => Err(ImportPreflightError::new(
            ImportPreflightErrorCode::LfsObjectAmbiguous,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn process_mapping<M: MappingAuthority>(
    occurrence: SourceOccurrence,
    request: ImportRequest,
    authority: &M,
    policy: &ImportPolicy,
    expected_generation: [u8; 32],
    control: &OperationControl,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    state.counts.mappings = checked_add(state.counts.mappings, 1)?;
    enforce(
        state.counts.mappings,
        ledger.limits.mappings_maximum,
        ImportPreflightErrorCode::LimitMappings,
    )?;
    if request.importer_profile != policy.importer_profile
        || request.source_namespace_digest != policy.source_namespace_digest
        || request.source_identity_digest == [0; 32]
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::MappingDecisionMismatch,
        ));
    }
    if state.mapped_occurrences.contains_key(&occurrence) {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::MappingOccurrenceDuplicate,
        ));
    }
    if state
        .mapping_sources
        .contains_key(&request.source_identity_digest)
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::MappingSourceDuplicate,
        ));
    }
    if !state.blob_occurrences.contains_key(&occurrence) {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::MappingSourceMissing,
        ));
    }
    control.check()?;
    check_generation(authority.generation(), expected_generation)?;
    ledger.work(1)?;
    let decision = authority.decide(&request).map_err(|_| {
        ImportPreflightError::new(ImportPreflightErrorCode::MappingAuthorityFailure)
    })?;
    check_generation(authority.generation(), expected_generation)?;
    control.check()?;
    if decision.file_id != request.requested_file_id
        || (!decision.retry && decision.state != ogvcs_object_model::ImportState::Reserved)
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::MappingDecisionMismatch,
        ));
    }
    if let Some(previous_source) = state.mapping_file_ids.get(&decision.file_id) {
        if previous_source != &request.source_identity_digest {
            return Err(ImportPreflightError::new(
                ImportPreflightErrorCode::MappingFileIdConflict,
            ));
        }
    }
    ledger.reserve(
        1_536
            + request.importer_profile.namespace().len() as u64
            + request.importer_profile.id().len() as u64,
    )?;
    let mapping = ImportMapping {
        descriptor: policy.descriptor,
        importer_profile: request.importer_profile.clone(),
        source_namespace_digest: request.source_namespace_digest,
        source_identity_digest: request.source_identity_digest,
        file_id: decision.file_id,
        state: decision.state,
        declared_mapping_key: decision.mapping_key,
    };
    let derived = import_mapping_key(policy.descriptor, &mapping).map_err(|_| {
        ImportPreflightError::new(ImportPreflightErrorCode::MappingDecisionMismatch)
    })?;
    if derived != decision.mapping_key {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::MappingKeyMismatch,
        ));
    }
    state.mapping_hash.update(&[1]);
    hash_git_oid(&mut state.mapping_hash, occurrence.source_object());
    state.mapping_hash.update(&occurrence.path_digest());
    hash_profile(&mut state.mapping_hash, &mapping.importer_profile);
    state.mapping_hash.update(&mapping.source_namespace_digest);
    state.mapping_hash.update(&mapping.source_identity_digest);
    state.mapping_hash.update(mapping.file_id.as_bytes());
    state
        .mapping_hash
        .update(&[import_state_code(mapping.state)]);
    state.mapping_hash.update(&mapping.declared_mapping_key);
    state.mapping_hash.update(&[u8::from(decision.retry)]);
    state.mapping_sources.insert(
        request.source_identity_digest,
        (occurrence, decision.file_id),
    );
    state
        .mapping_file_ids
        .insert(decision.file_id, request.source_identity_digest);
    ledger.reserve(96)?;
    state.mapped_occurrences.insert(occurrence, ());
    state.mappings.push(MappingPlan {
        occurrence,
        mapping,
        retry: decision.retry,
    });
    Ok(())
}

fn add_missing_mapping_findings(
    state: &mut PreflightState,
    ledger: &mut Ledger,
    control: &OperationControl,
) -> Result<(), ImportPreflightError> {
    let mut missing_count = 0u64;
    for occurrence in state.blob_occurrences.keys() {
        control.check()?;
        ledger.work(1)?;
        if !state.mapped_occurrences.contains_key(occurrence) {
            missing_count = checked_add(missing_count, 1)?;
        }
    }
    let combined_findings = checked_add(state.findings.len() as u64, missing_count)?;
    enforce(
        combined_findings,
        ledger.limits.findings_maximum,
        ImportPreflightErrorCode::LimitFindings,
    )?;
    let temporary_bytes = missing_count
        .checked_mul(96)
        .ok_or_else(|| ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow))?;
    ledger.reserve(temporary_bytes)?;
    let mut missing = Vec::with_capacity(missing_count as usize);
    for occurrence in state.blob_occurrences.keys() {
        control.check()?;
        ledger.work(1)?;
        if !state.mapped_occurrences.contains_key(occurrence) {
            missing.push(*occurrence);
        }
    }
    for occurrence in missing {
        control.check()?;
        ledger.work(1)?;
        push_finding(
            Finding {
                kind: FindingKind::MappingMissing,
                source_object: occurrence.source_object(),
                path_digest: occurrence.path_digest(),
                conflicting_path_digest: None,
            },
            state,
            ledger,
        )?;
    }
    ledger.release(temporary_bytes)?;
    Ok(())
}

fn inspect_path(
    id: GitObjectId,
    path: &str,
    digest: [u8; 32],
    policy: &ImportPolicy,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    let keys = match path_collision_keys_with_options(path, policy.path_profile, policy.case_mode) {
        Ok(keys) => keys,
        Err(_) => {
            return push_finding(
                Finding {
                    kind: FindingKind::PathInvalid,
                    source_object: id,
                    path_digest: digest,
                    conflicting_path_digest: None,
                },
                state,
                ledger,
            )
        }
    };
    insert_collision_key(
        keys.repository_key().as_str(),
        digest,
        id,
        FindingKind::RepositoryPathCollision,
        true,
        state,
        ledger,
    )?;
    insert_collision_key(
        keys.platform_key(),
        digest,
        id,
        FindingKind::PlatformPathCollision,
        false,
        state,
        ledger,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_collision_key(
    key: &str,
    digest: [u8; 32],
    id: GitObjectId,
    finding_kind: FindingKind,
    repository: bool,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    let existing = if repository {
        state.repository_paths.get(key)
    } else {
        state.platform_paths.get(key)
    };
    if let Some((first_digest, _)) = existing {
        return push_finding(
            Finding {
                kind: finding_kind,
                source_object: id,
                path_digest: digest,
                conflicting_path_digest: Some(*first_digest),
            },
            state,
            ledger,
        );
    }
    ledger.reserve(96 + key.len() as u64)?;
    if repository {
        state.repository_paths.insert(key.to_owned(), (digest, id));
    } else {
        state.platform_paths.insert(key.to_owned(), (digest, id));
    }
    Ok(())
}

fn inspect_mode(
    id: GitObjectId,
    mode: GitEntryMode,
    path_digest: [u8; 32],
    policy: &ImportPolicy,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    let kind = match mode {
        GitEntryMode::Regular => None,
        GitEntryMode::Executable if !policy.permit_executable => {
            Some(FindingKind::ExecutableBlocked)
        }
        GitEntryMode::Symlink if !policy.permit_symlink_inventory => {
            Some(FindingKind::SymlinkBlocked)
        }
        GitEntryMode::Submodule if !policy.permit_submodule_inventory => {
            Some(FindingKind::SubmoduleBlocked)
        }
        _ => None,
    };
    if let Some(kind) = kind {
        push_finding(
            Finding {
                kind,
                source_object: id,
                path_digest,
                conflicting_path_digest: None,
            },
            state,
            ledger,
        )?;
    }
    Ok(())
}

fn push_finding(
    finding: Finding,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    let count = checked_add(state.findings.len() as u64, 1)?;
    enforce(
        count,
        ledger.limits.findings_maximum,
        ImportPreflightErrorCode::LimitFindings,
    )?;
    ledger.reserve(512)?;
    state.findings.push(finding);
    Ok(())
}

fn enforce_record_order(
    record: &ImportRecord,
    state: &mut PreflightState,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    let key_bytes = record_key_input_bytes(record)?;
    ledger.reserve(key_bytes)?;
    let key = record.key();
    if let Some(previous) = state.previous_key.as_ref() {
        if previous == &key {
            return Err(ImportPreflightError::new(
                ImportPreflightErrorCode::InventoryDuplicate,
            ));
        }
        if previous > &key {
            return Err(ImportPreflightError::new(
                ImportPreflightErrorCode::InventoryUnordered,
            ));
        }
    }
    ledger.release(state.previous_key_bytes)?;
    state.previous_key = Some(key);
    state.previous_key_bytes = key_bytes;
    Ok(())
}

fn add_git_bytes(
    state: &mut PreflightState,
    bytes: u64,
    maximum: u64,
) -> Result<(), ImportPreflightError> {
    state.git_bytes = checked_add(state.git_bytes, bytes)?;
    enforce(
        state.git_bytes,
        maximum,
        ImportPreflightErrorCode::LimitGitBytes,
    )
}

fn add_relationships(
    state: &mut PreflightState,
    count: u64,
    ledger: &mut Ledger,
) -> Result<(), ImportPreflightError> {
    state.counts.relationships = checked_add(state.counts.relationships, count)?;
    enforce(
        state.counts.relationships,
        ledger.limits.relationships_maximum,
        ImportPreflightErrorCode::LimitRelationships,
    )?;
    ledger.work(count)
}

fn validate_limits(limits: ImportLimits) -> Result<(), ImportPreflightError> {
    if limits.items_maximum == 0
        || limits.items_maximum > ITEMS_HARD_MAXIMUM
        || limits.relationships_maximum > RELATIONSHIPS_HARD_MAXIMUM
        || limits.git_bytes_maximum == 0
        || limits.git_bytes_maximum > GIT_BYTES_HARD_MAXIMUM
        || limits.input_bytes_maximum == 0
        || limits.input_bytes_maximum > INPUT_BYTES_HARD_MAXIMUM
        || limits.lfs_objects_maximum > ITEMS_HARD_MAXIMUM
        || limits.lfs_object_bytes_maximum > LFS_BYTES_HARD_MAXIMUM
        || limits.lfs_bytes_maximum == 0
        || limits.lfs_bytes_maximum > LFS_BYTES_HARD_MAXIMUM
        || limits.mappings_maximum > ITEMS_HARD_MAXIMUM
        || limits.findings_maximum > ITEMS_HARD_MAXIMUM
        || limits.work_units_maximum == 0
        || limits.work_units_maximum > WORK_UNITS_HARD_MAXIMUM
        || limits.retained_bytes_maximum == 0
        || limits.retained_bytes_maximum > RETAINED_BYTES_HARD_MAXIMUM
        || limits.path_bytes_maximum == 0
        || limits.path_bytes_maximum > PATH_BYTES_HARD_MAXIMUM
        || limits.ref_name_bytes_maximum == 0
        || limits.ref_name_bytes_maximum > REF_NAME_BYTES_HARD_MAXIMUM
        || limits.read_chunk_bytes == 0
        || limits.read_chunk_bytes > READ_CHUNK_BYTES_HARD_MAXIMUM
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::LimitsInvalid,
        ));
    }
    Ok(())
}

fn validate_expected_inventory(
    expected: ExpectedInventory,
    limits: ImportLimits,
) -> Result<(), ImportPreflightError> {
    let invalid = || ImportPreflightError::new(ImportPreflightErrorCode::ExpectedInventoryInvalid);
    let category_items = expected
        .counts
        .refs
        .checked_add(expected.counts.commits)
        .and_then(|value| value.checked_add(expected.counts.trees))
        .and_then(|value| value.checked_add(expected.counts.entries))
        .and_then(|value| value.checked_add(expected.counts.mappings))
        .ok_or_else(invalid)?;
    if expected.counts.items != category_items
        || expected.source_generation == [0; 32]
        || expected.lfs_generation == [0; 32]
        || expected.mapping_generation == [0; 32]
        || expected.inventory_digest == [0; 32]
        || expected.counts.blob_occurrences > expected.counts.entries
        || expected.counts.blobs > expected.counts.blob_occurrences
        || (expected.counts.blob_occurrences > 0 && expected.counts.blobs == 0)
        || expected.counts.mappings != expected.counts.blob_occurrences
        || expected.counts.lfs_pointers > expected.counts.blobs
        || expected.counts.lfs_objects > expected.counts.lfs_pointers
        || (expected.counts.lfs_pointers > 0 && expected.counts.lfs_objects == 0)
        || expected.counts.items > limits.items_maximum
        || expected.counts.relationships > limits.relationships_maximum
        || expected.counts.lfs_objects > limits.lfs_objects_maximum
        || expected.counts.mappings > limits.mappings_maximum
        || expected.git_bytes > limits.git_bytes_maximum
        || expected.input_bytes > limits.input_bytes_maximum
    {
        return Err(invalid());
    }
    let minimum_work = expected
        .counts
        .items
        .checked_add(1)
        .and_then(|value| value.checked_add(expected.counts.relationships))
        .and_then(|value| value.checked_add(expected.counts.mappings))
        .ok_or_else(invalid)?;
    if minimum_work > limits.work_units_maximum {
        return Err(invalid());
    }
    Ok(())
}

fn validate_policy(policy: &ImportPolicy) -> Result<(), ImportPreflightError> {
    if policy.descriptor.kind != ObjectKind::RepositoryDescriptor
        || policy.descriptor.digest == [0; 32]
        || policy.source_namespace_digest == [0; 32]
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::PolicyInvalid,
        ));
    }
    Ok(())
}

fn validate_ref_name(name: &str, maximum: usize) -> Result<(), ImportPreflightError> {
    if name.is_empty()
        || name.len() > maximum
        || !name.starts_with("refs/")
        || name.ends_with('/')
        || name.ends_with('.')
        || name.contains("//")
        || name.contains("..")
        || name.contains("@{")
        || name
            .split('/')
            .any(|component| component.starts_with('.') || component.ends_with(".lock"))
        || name.bytes().any(|byte| {
            byte <= b' '
                || byte == 0x7f
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        return Err(ImportPreflightError::new(
            ImportPreflightErrorCode::SourceContractViolation,
        ));
    }
    Ok(())
}

fn normalize_and_validate_record_shape(
    record: &mut ImportRecord,
    limits: ImportLimits,
) -> Result<(), ImportPreflightError> {
    match record {
        ImportRecord::Ref { name, .. } => {
            if name.capacity() > limits.ref_name_bytes_maximum {
                Err(ImportPreflightError::new(
                    ImportPreflightErrorCode::SourceContractViolation,
                ))
            } else {
                validate_ref_name(name, limits.ref_name_bytes_maximum)
            }
        }
        ImportRecord::Entry {
            path,
            mode,
            encoded_bytes,
            pointer_probe,
            lfs,
            ..
        } => {
            let submodule_invalid = *mode == GitEntryMode::Submodule
                && (*encoded_bytes != 0
                    || !pointer_probe.is_empty()
                    || *lfs != LfsDisposition::Ordinary);
            let symlink_invalid =
                *mode == GitEntryMode::Symlink && *lfs != LfsDisposition::Ordinary;
            let blob_probe_invalid = *mode != GitEntryMode::Submodule
                && ((*encoded_bytes <= GIT_LFS_POINTER_BYTES_MAXIMUM as u64
                    && pointer_probe.len() as u64 != *encoded_bytes)
                    || (*encoded_bytes > GIT_LFS_POINTER_BYTES_MAXIMUM as u64
                        && !pointer_probe.is_empty()));
            if path.len() > limits.path_bytes_maximum
                || path.capacity() > limits.path_bytes_maximum
                || pointer_probe.len() > GIT_LFS_POINTER_BYTES_MAXIMUM
                || pointer_probe.capacity() > GIT_LFS_POINTER_BYTES_MAXIMUM
                || submodule_invalid
                || blob_probe_invalid
                || symlink_invalid
            {
                Err(ImportPreflightError::new(
                    ImportPreflightErrorCode::SourceContractViolation,
                ))
            } else {
                Ok(())
            }
        }
        ImportRecord::Mapping { request, .. } => {
            request.importer_profile = ProfileRef::new(
                request.importer_profile.namespace().to_owned(),
                request.importer_profile.id().to_owned(),
                request.importer_profile.major(),
            )
            .map_err(|_| {
                ImportPreflightError::new(ImportPreflightErrorCode::SourceContractViolation)
            })?;
            Ok(())
        }
        ImportRecord::Commit { .. } | ImportRecord::Tree { .. } => Ok(()),
    }
}

fn check_generation(actual: [u8; 32], expected: [u8; 32]) -> Result<(), ImportPreflightError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ImportPreflightError::new(
            ImportPreflightErrorCode::SourceGenerationChanged,
        ))
    }
}

fn enforce(
    actual: u64,
    maximum: u64,
    code: ImportPreflightErrorCode,
) -> Result<(), ImportPreflightError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(ImportPreflightError::new(code))
    }
}

fn checked_add(left: u64, right: u64) -> Result<u64, ImportPreflightError> {
    left.checked_add(right)
        .ok_or_else(|| ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow))
}

fn input_work_units(bytes: u64) -> Result<u64, ImportPreflightError> {
    checked_add(bytes, 1_023).map(|rounded| rounded / 1_024)
}

fn comparison_sort_work(len: usize) -> Result<u64, ImportPreflightError> {
    if len <= 1 {
        return Ok(0);
    }
    let len = u64::try_from(len)
        .map_err(|_| ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow))?;
    let levels = u64::from(u64::BITS - (len - 1).leading_zeros());
    len.checked_mul(levels)
        .ok_or_else(|| ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow))
}

fn record_key_input_bytes(record: &ImportRecord) -> Result<u64, ImportPreflightError> {
    Ok(match record {
        ImportRecord::Ref { name, .. } => checked_add(64, name.len() as u64)?,
        ImportRecord::Commit { id, .. } | ImportRecord::Tree { id, .. } => {
            64 + id.byte_len() as u64
        }
        ImportRecord::Entry { id, path, .. } => {
            checked_add(64 + id.byte_len() as u64, path.len() as u64)?
        }
        ImportRecord::Mapping { occurrence, .. } => {
            128 + occurrence.source_object().byte_len() as u64
        }
    })
}

fn record_input_bytes(record: &ImportRecord) -> Result<u64, ImportPreflightError> {
    let base = 16u64;
    match record {
        ImportRecord::Ref { name, target } => checked_add(
            checked_add(base, name.len() as u64)?,
            target.byte_len() as u64,
        ),
        ImportRecord::Commit { id, .. } | ImportRecord::Tree { id, .. } => {
            checked_add(base + 16, id.byte_len() as u64)
        }
        ImportRecord::Entry {
            id,
            path,
            pointer_probe,
            ..
        } => checked_add(
            checked_add(base + 24 + id.byte_len() as u64, path.len() as u64)?,
            pointer_probe.len() as u64,
        ),
        ImportRecord::Mapping {
            occurrence,
            request,
        } => checked_add(
            base + 144 + occurrence.source_object().byte_len() as u64,
            checked_add(
                request.importer_profile.namespace().len() as u64,
                request.importer_profile.id().len() as u64,
            )?,
        ),
    }
}

fn record_retained_bytes(record: &ImportRecord) -> Result<u64, ImportPreflightError> {
    Ok(match record {
        ImportRecord::Ref { name, .. } => name.capacity() as u64,
        ImportRecord::Commit { .. } | ImportRecord::Tree { .. } => 0,
        ImportRecord::Entry {
            path,
            pointer_probe,
            ..
        } => checked_add(path.capacity() as u64, pointer_probe.capacity() as u64)?,
        ImportRecord::Mapping { request, .. } => checked_add(
            request.importer_profile.namespace().len() as u64,
            request.importer_profile.id().len() as u64,
        )?,
    })
}

fn update_inventory_hash(
    hash: &mut Sha256Writer,
    record: &ImportRecord,
) -> Result<(), ImportPreflightError> {
    match record {
        ImportRecord::Ref { name, target } => {
            hash.update(&[1]);
            hash_len_bytes(hash, name.as_bytes())?;
            hash_git_oid(hash, *target);
        }
        ImportRecord::Commit {
            id,
            encoded_bytes,
            parent_count,
        } => {
            hash.update(&[2]);
            hash_git_oid(hash, *id);
            hash.update(&encoded_bytes.to_be_bytes());
            hash.update(&parent_count.to_be_bytes());
        }
        ImportRecord::Tree {
            id,
            encoded_bytes,
            entry_count,
        } => {
            hash.update(&[3]);
            hash_git_oid(hash, *id);
            hash.update(&encoded_bytes.to_be_bytes());
            hash.update(&entry_count.to_be_bytes());
        }
        ImportRecord::Entry {
            id,
            path,
            mode,
            encoded_bytes,
            pointer_probe,
            lfs,
        } => {
            hash.update(&[4]);
            hash_git_oid(hash, *id);
            hash_len_bytes(hash, path.as_bytes())?;
            hash.update(&mode.code().to_be_bytes());
            hash.update(&encoded_bytes.to_be_bytes());
            hash_len_bytes(hash, pointer_probe)?;
            hash.update(&[match lfs {
                LfsDisposition::Ordinary => 0,
                LfsDisposition::Required => 1,
            }]);
        }
        ImportRecord::Mapping {
            occurrence,
            request,
        } => {
            hash.update(&[5]);
            hash_git_oid(hash, occurrence.source_object());
            hash.update(&occurrence.path_digest());
            hash_profile(hash, &request.importer_profile);
            hash.update(&request.source_namespace_digest);
            hash.update(&request.source_identity_digest);
            hash.update(request.requested_file_id.as_bytes());
        }
    }
    Ok(())
}

fn hash_policy(policy: &ImportPolicy) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(POLICY_DOMAIN);
    hash.update(&policy.descriptor.digest);
    hash_profile(&mut hash, &policy.importer_profile);
    hash.update(&policy.source_namespace_digest);
    hash.update(&[policy.path_profile.code()]);
    hash.update(&[match policy.case_mode {
        CaseMode::Sensitive => 0,
        CaseMode::Folded => 1,
    }]);
    hash.update(&[
        u8::from(policy.permit_executable),
        u8::from(policy.permit_symlink_inventory),
        u8::from(policy.permit_submodule_inventory),
    ]);
    hash.finish()
}

#[allow(clippy::too_many_arguments)]
fn hash_report(
    state: &PreflightState,
    inventory_digest: [u8; 32],
    policy_digest: [u8; 32],
    mapping_digest: [u8; 32],
    input_bytes: u64,
    work_units: u64,
    peak_retained_bytes: u64,
    limits: ImportLimits,
    expected: ExpectedInventory,
) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(REPORT_DOMAIN);
    hash.update(&inventory_digest);
    hash.update(&policy_digest);
    hash.update(&mapping_digest);
    hash.update(&expected.source_generation);
    hash.update(&expected.lfs_generation);
    hash.update(&expected.mapping_generation);
    for value in [
        state.counts.items,
        state.counts.refs,
        state.counts.commits,
        state.counts.trees,
        state.counts.entries,
        state.counts.blobs,
        state.counts.blob_occurrences,
        state.counts.mappings,
        state.counts.relationships,
        state.counts.lfs_pointers,
        state.counts.lfs_objects,
        state.git_bytes,
        state.lfs_bytes,
        input_bytes,
        work_units,
        peak_retained_bytes,
    ] {
        hash.update(&value.to_be_bytes());
    }
    for value in [
        limits.items_maximum,
        limits.relationships_maximum,
        limits.git_bytes_maximum,
        limits.input_bytes_maximum,
        limits.lfs_objects_maximum,
        limits.lfs_object_bytes_maximum,
        limits.lfs_bytes_maximum,
        limits.mappings_maximum,
        limits.findings_maximum,
        limits.work_units_maximum,
        limits.retained_bytes_maximum,
        limits.path_bytes_maximum as u64,
        limits.ref_name_bytes_maximum as u64,
        limits.read_chunk_bytes as u64,
    ] {
        hash.update(&value.to_be_bytes());
    }
    hash.update(&[u8::from(state.findings.is_empty())]);
    hash.update(&(state.entries.len() as u64).to_be_bytes());
    for entry in &state.entries {
        hash_git_oid(&mut hash, entry.source_object);
        hash.update(&entry.path_digest);
        hash.update(&entry.mode.code().to_be_bytes());
        hash.update(&entry.logical_bytes.to_be_bytes());
        match entry.lfs_object {
            Some(oid) => {
                hash.update(&[1]);
                hash.update(oid.as_bytes());
            }
            None => hash.update(&[0]),
        }
    }
    hash.update(&(state.mappings.len() as u64).to_be_bytes());
    for plan in &state.mappings {
        hash_git_oid(&mut hash, plan.occurrence.source_object());
        hash.update(&plan.occurrence.path_digest());
        hash.update(&plan.mapping.descriptor.digest);
        hash_profile(&mut hash, &plan.mapping.importer_profile);
        hash.update(&plan.mapping.source_namespace_digest);
        hash.update(&plan.mapping.source_identity_digest);
        hash.update(plan.mapping.file_id.as_bytes());
        hash.update(&[import_state_code(plan.mapping.state)]);
        hash.update(&plan.mapping.declared_mapping_key);
        hash.update(&[u8::from(plan.retry)]);
    }
    hash.update(&(state.findings.len() as u64).to_be_bytes());
    for finding in &state.findings {
        hash.update(&[finding.kind.code()]);
        hash_git_oid(&mut hash, finding.source_object);
        hash.update(&finding.path_digest);
        match finding.conflicting_path_digest {
            Some(other) => {
                hash.update(&[1]);
                hash.update(&other);
            }
            None => hash.update(&[0]),
        }
    }
    hash.finish()
}

fn hash_path(path: &str) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(PATH_DOMAIN);
    hash.update(&(path.len() as u64).to_be_bytes());
    hash.update(path.as_bytes());
    hash.finish()
}

fn hash_blob_probe(bytes: &[u8]) -> Result<[u8; 32], ImportPreflightError> {
    let mut hash = Sha256Writer::new();
    hash.update(BLOB_PROBE_DOMAIN);
    hash_len_bytes(&mut hash, bytes)?;
    Ok(hash.finish())
}

fn hash_git_oid(hash: &mut Sha256Writer, oid: GitObjectId) {
    let (tag, bytes) = oid.tagged_bytes();
    hash.update(&[tag]);
    hash.update(bytes);
}

fn hash_profile(hash: &mut Sha256Writer, profile: &ProfileRef) {
    hash.update(&(profile.namespace().len() as u64).to_be_bytes());
    hash.update(profile.namespace().as_bytes());
    hash.update(&(profile.id().len() as u64).to_be_bytes());
    hash.update(profile.id().as_bytes());
    hash.update(&profile.major().to_be_bytes());
}

fn hash_len_bytes(hash: &mut Sha256Writer, bytes: &[u8]) -> Result<(), ImportPreflightError> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| ImportPreflightError::new(ImportPreflightErrorCode::ArithmeticOverflow))?;
    hash.update(&len.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

fn import_state_code(state: ogvcs_object_model::ImportState) -> u8 {
    match state {
        ogvcs_object_model::ImportState::Reserved => 1,
        ogvcs_object_model::ImportState::Materialized => 2,
        ogvcs_object_model::ImportState::Published => 3,
    }
}
