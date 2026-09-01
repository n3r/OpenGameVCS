//! Private, pure OGVCS-013 current-versus-target dry-run candidate.
//!
//! This module deliberately defines no wire schema, operation brand, grant,
//! receipt, or filesystem executor. Inputs and emitted actions remain
//! untrusted until every source reaches EOF, the action sink finishes, and a
//! summary is returned. Even a completed summary is only arithmetic over the
//! supplied private projections; it cannot authorize mutation.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
};

use ogvcs_chunking_manifest::{CHUNK_COUNT_MAXIMUM, MANIFEST_BYTES_MAXIMUM, MAXIMUM};
use ogvcs_object_model::{FileId, ObjectKind, ObjectRef};
use ogvcs_path_contract::{path_collision_keys_with_options, CaseMode, PathProfile};
use sha2::{Digest as _, Sha256};

use crate::{
    platform_matches, ContentIdentity, EvaluationControl, HostPlatform, Materialization,
    ProjectionDigest, FULL_LOGICAL_BYTES_MAXIMUM, LOGICAL_BYTES_MAXIMUM, METADATA_RECORDS_MAXIMUM,
};

pub const REQUIRED_OBJECTS_MAXIMUM: u64 = CHUNK_COUNT_MAXIMUM as u64 + METADATA_RECORDS_MAXIMUM;
pub const CACHE_PROBES_MAXIMUM: u64 = REQUIRED_OBJECTS_MAXIMUM;
pub const DRY_RUN_ACTIONS_MAXIMUM: u64 = METADATA_RECORDS_MAXIMUM * 2;
pub const DRY_RUN_INPUT_BYTES_MAXIMUM: u64 = 1_073_741_824;
pub const DRY_RUN_RETAINED_BYTES_MAXIMUM: u64 = 268_435_456;
pub const DRY_RUN_LEDGER_BYTES_MAXIMUM: u64 = FULL_LOGICAL_BYTES_MAXIMUM;

const TARGET_DOMAIN: &[u8] = b"OpenGameVCS selective sync dry-run target projection rc.1\0";
const CURRENT_DOMAIN: &[u8] = b"OpenGameVCS selective sync dry-run current projection rc.1\0";
const REQUIRED_DOMAIN: &[u8] = b"OpenGameVCS selective sync dry-run object closure rc.1\0";
const CACHE_DOMAIN: &[u8] = b"OpenGameVCS selective sync dry-run cache probes rc.1\0";
const BINDINGS_DOMAIN: &[u8] = b"OpenGameVCS selective sync dry-run bindings rc.1\0";
const ACTION_DOMAIN: &[u8] = b"OpenGameVCS selective sync dry-run actions rc.1\0";
const RETAINED_RECORD_OVERHEAD: u64 = 640;
const RETAINED_FILE_ID_OVERHEAD: u64 = 96;
const RETAINED_MANIFEST_OVERHEAD: u64 = 80;
const RETAINED_PLATFORM_LOOKUP_OVERHEAD: u64 = 96;
const RETAINED_OBSTRUCTION_INDEX_OVERHEAD: u64 = 192;
const RETAINED_CURRENT_OWNER_OVERHEAD: u64 = 96;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DryRunError {
    ActionCountLimit,
    BindingInvalid,
    CacheCountLimit,
    CacheCountMismatch,
    CacheProbeMismatch,
    Cancelled,
    CurrentCountLimit,
    CurrentCountMismatch,
    DuplicateFileId,
    IdentityInvalid,
    InputBytesLimit,
    LedgerLimit,
    MetadataStateInvalid,
    ObjectInvalid,
    PathCollision,
    PathInvalid,
    PathOrderInvalid,
    PlatformProfileMismatch,
    RequiredManifestMissing,
    RequiredObjectCountLimit,
    RequiredObjectCountMismatch,
    RequiredObjectOrderInvalid,
    RetainedMemoryLimit,
    SinkFailed,
    SourceFailed,
    TargetCountLimit,
    TargetCountMismatch,
}

impl DryRunError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ActionCountLimit => "DRY_RUN_ACTION_COUNT_LIMIT",
            Self::BindingInvalid => "DRY_RUN_BINDING_INVALID",
            Self::CacheCountLimit => "DRY_RUN_CACHE_COUNT_LIMIT",
            Self::CacheCountMismatch => "DRY_RUN_CACHE_COUNT_MISMATCH",
            Self::CacheProbeMismatch => "DRY_RUN_CACHE_PROBE_MISMATCH",
            Self::Cancelled => "DRY_RUN_CANCELLED",
            Self::CurrentCountLimit => "DRY_RUN_CURRENT_COUNT_LIMIT",
            Self::CurrentCountMismatch => "DRY_RUN_CURRENT_COUNT_MISMATCH",
            Self::DuplicateFileId => "DRY_RUN_DUPLICATE_FILE_ID",
            Self::IdentityInvalid => "DRY_RUN_IDENTITY_INVALID",
            Self::InputBytesLimit => "DRY_RUN_INPUT_BYTES_LIMIT",
            Self::LedgerLimit => "DRY_RUN_LEDGER_LIMIT",
            Self::MetadataStateInvalid => "DRY_RUN_METADATA_STATE_INVALID",
            Self::ObjectInvalid => "DRY_RUN_OBJECT_INVALID",
            Self::PathCollision => "DRY_RUN_PATH_COLLISION",
            Self::PathInvalid => "DRY_RUN_PATH_INVALID",
            Self::PathOrderInvalid => "DRY_RUN_PATH_ORDER_INVALID",
            Self::PlatformProfileMismatch => "DRY_RUN_PLATFORM_PROFILE_MISMATCH",
            Self::RequiredManifestMissing => "DRY_RUN_REQUIRED_MANIFEST_MISSING",
            Self::RequiredObjectCountLimit => "DRY_RUN_REQUIRED_OBJECT_COUNT_LIMIT",
            Self::RequiredObjectCountMismatch => "DRY_RUN_REQUIRED_OBJECT_COUNT_MISMATCH",
            Self::RequiredObjectOrderInvalid => "DRY_RUN_REQUIRED_OBJECT_ORDER_INVALID",
            Self::RetainedMemoryLimit => "DRY_RUN_RETAINED_MEMORY_LIMIT",
            Self::SinkFailed => "DRY_RUN_SINK_FAILED",
            Self::SourceFailed => "DRY_RUN_SOURCE_FAILED",
            Self::TargetCountLimit => "DRY_RUN_TARGET_COUNT_LIMIT",
            Self::TargetCountMismatch => "DRY_RUN_TARGET_COUNT_MISMATCH",
        }
    }
}

impl std::fmt::Display for DryRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DryRunError {}

pub type PlanSourceError<T> = std::result::Result<Option<T>, DryRunError>;
type Result<T> = std::result::Result<T, DryRunError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DryRunFullIdentity {
    pub file_id: FileId,
    /// OGVCS-002 tree-entry projection commitment supplied by the private
    /// target/current adapter. The planner does not decode or authenticate it.
    pub entry_digest: ProjectionDigest,
    /// OGVCS-002 `content-manifest` object identity.
    pub manifest: ObjectRef,
    /// OGVCS-007 whole-file digest and declared logical length.
    pub content: ContentIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunTargetRecord {
    pub ordinal: u64,
    pub path: String,
    pub materialization: Materialization,
    /// Present only for `full`. Metadata-only and absent rows deliberately
    /// carry no entry/content identity and therefore cannot request payload.
    pub identity: Option<DryRunFullIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalObservation {
    Pristine,
    Modified,
    Missing,
    Obstructed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedCurrentState {
    Full {
        identity: DryRunFullIdentity,
        observation: LocalObservation,
    },
    MetadataOnly {
        /// True when an ordinary untracked object exists at a metadata-only
        /// index path. The planner never treats that object as materialized.
        ordinary_path_obstruction: bool,
    },
    Untracked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedWorkspaceRecord {
    pub ordinal: u64,
    pub path: String,
    pub state: RetainedCurrentState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DryRunRequiredObject {
    pub ordinal: u64,
    pub object: ObjectRef,
    pub payload_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheProbeOutcome {
    VerifiedHit,
    Miss,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheProbeRecord {
    pub ordinal: u64,
    pub object: ObjectRef,
    pub payload_bytes: u64,
    pub outcome: CacheProbeOutcome,
}

pub trait PlanSource<T> {
    type Error;
    fn next_record(&mut self) -> std::result::Result<Option<T>, Self::Error>;
}

pub struct IteratorPlanSource<I> {
    iterator: I,
}

impl<I> IteratorPlanSource<I> {
    pub const fn new(iterator: I) -> Self {
        Self { iterator }
    }
}

impl<I, T> PlanSource<T> for IteratorPlanSource<I>
where
    I: Iterator<Item = T>,
{
    type Error = Infallible;

    fn next_record(&mut self) -> std::result::Result<Option<T>, Self::Error> {
        Ok(self.iterator.next())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateActionKind {
    Add,
    Update,
    Delete,
    MoveOrEquivalent,
    MaterializationState,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    Add,
    Update,
    Delete,
    MoveOrEquivalent,
    MaterializationState,
}

impl From<MutationKind> for CandidateActionKind {
    fn from(value: MutationKind) -> Self {
        match value {
            MutationKind::Add => Self::Add,
            MutationKind::Update => Self::Update,
            MutationKind::Delete => Self::Delete,
            MutationKind::MoveOrEquivalent => Self::MoveOrEquivalent,
            MutationKind::MaterializationState => Self::MaterializationState,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateMaterializationState {
    Absent,
    MetadataOnly,
    FullPresent,
    FullMissing,
    Untracked,
    Obstructed,
    MetadataOnlyObstructed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockerKind {
    LocallyModified,
    UntrackedObstruction,
    LocalObstruction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunAction {
    pub sequence: u64,
    pub kind: CandidateActionKind,
    pub path: String,
    /// Current repository spelling associated with a stable-ID move or a
    /// cross-projection platform alias. `None` means the current and target
    /// repository keys are identical, no distinct current row is involved, or
    /// this target conservatively stages from absent state because an earlier
    /// target-order action owns the otherwise matching current row.
    pub source_path: Option<String>,
    pub from: CandidateMaterializationState,
    pub to: CandidateMaterializationState,
    pub blocked_mutation: Option<MutationKind>,
    pub blocker: Option<BlockerKind>,
    pub blocker_path: Option<String>,
    pub target_logical_bytes: u64,
    pub workspace_write_bytes: u64,
}

impl DryRunAction {
    /// Whether this candidate action would stage ordinary-file payload bytes if
    /// a future, separately authorized executor accepted it. Reused-payload
    /// moves, conflicts, and metadata-only actions return false.
    pub fn may_write_ordinary_file(&self) -> bool {
        self.kind != CandidateActionKind::Conflict
            && self.to == CandidateMaterializationState::FullPresent
            && self.workspace_write_bytes > 0
    }

    /// Whether the primary target-path transition directly retires a tracked
    /// ordinary file. This preview-only predicate does not classify source or
    /// destination effects of `MoveOrEquivalent`; those require a future
    /// executor's dependency preflight. In particular, metadata-only index
    /// removal with a preserved untracked obstruction returns false.
    pub fn may_delete_ordinary_file(&self) -> bool {
        self.kind != CandidateActionKind::Conflict
            && matches!(
                (self.kind, self.from, self.to),
                (
                    CandidateActionKind::Delete,
                    CandidateMaterializationState::FullPresent,
                    CandidateMaterializationState::Absent
                ) | (
                    CandidateActionKind::MaterializationState,
                    CandidateMaterializationState::FullPresent,
                    CandidateMaterializationState::MetadataOnly
                        | CandidateMaterializationState::Absent
                )
            )
    }
}

/// Receives one bounded action at a time. Source adapters and sink-owned
/// retention are outside `DryRunSummary::retained_bytes_peak`; a sink that
/// retains actions must impose its own byte ceiling. The planner emits at most
/// `DRY_RUN_ACTIONS_MAXIMUM` calls and retains no emitted action afterward.
pub trait DryRunActionSink {
    type Error;
    fn emit(&mut self, action: &DryRunAction) -> std::result::Result<(), Self::Error>;
    fn finish(&mut self) -> std::result::Result<(), Self::Error>;
}

impl DryRunActionSink for Vec<DryRunAction> {
    type Error = Infallible;

    fn emit(&mut self, action: &DryRunAction) -> std::result::Result<(), Self::Error> {
        self.push(action.clone());
        Ok(())
    }

    fn finish(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DryRunLedgers {
    pub target_full_logical_bytes: u64,
    pub current_tracked_baseline_bytes: u64,
    pub reusable_workspace_bytes: u64,
    pub workspace_stage_bytes: u64,
    pub retired_tracked_baseline_bytes: u64,
    pub required_object_bytes: u64,
    pub cache_hit_bytes: u64,
    pub cache_miss_bytes: u64,
    pub expected_transfer_bytes: u64,
    /// Exact sum of `workspace_stage_bytes + cache_miss_bytes` under this
    /// candidate's conservative same-volume payload model. It intentionally
    /// excludes filesystem allocation overhead and never asserts free space.
    pub disk_payload_reservation_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DryRunSummary {
    pub bindings_digest: ProjectionDigest,
    pub target_projection_digest: ProjectionDigest,
    pub current_projection_digest: ProjectionDigest,
    pub required_object_projection_digest: ProjectionDigest,
    pub cache_projection_digest: ProjectionDigest,
    pub action_projection_digest: ProjectionDigest,
    pub target_records: u64,
    pub current_records: u64,
    pub required_objects: u64,
    pub cache_probes: u64,
    pub actions: u64,
    pub adds: u64,
    pub updates: u64,
    pub deletes: u64,
    pub moves_or_equivalents: u64,
    pub materialization_state_changes: u64,
    pub conflicts: u64,
    pub blockers: u64,
    /// Conservative peak for planner-owned maps/keys only. It excludes source
    /// adapter buffers, allocator measurements, temporary working values, and
    /// any action copies retained by the caller's sink.
    pub retained_bytes_peak: u64,
    /// Deterministic modeled bytes for the four typed record streams. This is
    /// not a raw framing parser or a measurement of source-adapter buffers.
    pub input_bytes: u64,
    pub ledgers: DryRunLedgers,
}

#[derive(Clone, Debug)]
pub struct DryRunBindings {
    snapshot_digest: ProjectionDigest,
    current_generation_digest: ProjectionDigest,
    selection_projection_digest: ProjectionDigest,
    path_profile: PathProfile,
    case_mode: CaseMode,
    platform: HostPlatform,
    target_count: u64,
    current_count: u64,
    required_object_count: u64,
    cache_probe_count: u64,
}

impl DryRunBindings {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_digest: ProjectionDigest,
        current_generation_digest: ProjectionDigest,
        selection_projection_digest: ProjectionDigest,
        path_profile: &str,
        case_mode: CaseMode,
        platform: HostPlatform,
        target_count: u64,
        current_count: u64,
        required_object_count: u64,
        cache_probe_count: u64,
    ) -> Result<Self> {
        let path_profile =
            PathProfile::parse(path_profile).map_err(|_| DryRunError::BindingInvalid)?;
        if !platform_matches(path_profile, platform) {
            return Err(DryRunError::PlatformProfileMismatch);
        }
        if target_count > METADATA_RECORDS_MAXIMUM {
            return Err(DryRunError::TargetCountLimit);
        }
        if current_count > METADATA_RECORDS_MAXIMUM {
            return Err(DryRunError::CurrentCountLimit);
        }
        if required_object_count > REQUIRED_OBJECTS_MAXIMUM {
            return Err(DryRunError::RequiredObjectCountLimit);
        }
        if cache_probe_count > CACHE_PROBES_MAXIMUM {
            return Err(DryRunError::CacheCountLimit);
        }
        if required_object_count != cache_probe_count {
            return Err(DryRunError::CacheCountMismatch);
        }
        Ok(Self {
            snapshot_digest,
            current_generation_digest,
            selection_projection_digest,
            path_profile,
            case_mode,
            platform,
            target_count,
            current_count,
            required_object_count,
            cache_probe_count,
        })
    }
}

pub struct DryRunPlanner {
    bindings_digest: ProjectionDigest,
    bindings: DryRunBindings,
}

impl DryRunPlanner {
    pub fn new(bindings: DryRunBindings) -> Self {
        let bindings_digest = bindings_digest(&bindings);
        Self {
            bindings_digest,
            bindings,
        }
    }

    /// Consumes every private input and only then begins emitting candidate
    /// actions. Any error means all emitted actions are discard-only. A
    /// successful summary still carries no mutation or authorization brand.
    pub fn plan<T, C, O, P, W>(
        &self,
        target: &mut T,
        current: &mut C,
        required_objects: &mut O,
        cache_probes: &mut P,
        sink: &mut W,
        control: &EvaluationControl,
    ) -> Result<DryRunSummary>
    where
        T: PlanSource<DryRunTargetRecord>,
        C: PlanSource<RetainedWorkspaceRecord>,
        O: PlanSource<DryRunRequiredObject>,
        P: PlanSource<CacheProbeRecord>,
        W: DryRunActionSink,
    {
        check_control(control)?;
        let mut memory = MemoryBudget::default();
        let mut input_bytes = 0u64;
        let mut targets = read_targets(
            target,
            &self.bindings,
            &mut memory,
            &mut input_bytes,
            control,
        )?;
        let currents = read_current(
            current,
            &self.bindings,
            &mut memory,
            &mut input_bytes,
            control,
        )?;
        let object_projection = read_required_and_cache(
            required_objects,
            cache_probes,
            &self.bindings,
            &mut targets.required_manifests,
            &mut input_bytes,
            control,
        )?;
        if !targets.required_manifests.is_empty() {
            return Err(DryRunError::RequiredManifestMissing);
        }

        check_control(control)?;
        let mut actions = ActionAccumulator::new(self.bindings_digest);
        let mut reusable_workspace_bytes = 0u64;
        let mut current_owners = BTreeSet::new();
        for (repository_key, target_record) in &targets.by_path {
            check_control(control)?;
            plan_target_record(
                repository_key,
                target_record,
                &currents,
                &self.bindings,
                &mut actions,
                &mut reusable_workspace_bytes,
                &mut current_owners,
                sink,
            )?;
        }
        for (repository_key, current_record) in &currents.by_path {
            check_control(control)?;
            if targets.by_path.contains_key(repository_key)
                || current_file_id(current_record)
                    .is_some_and(|file_id| targets.by_file_id.contains_key(&file_id))
                || target_occupies_platform_path(current_record, &targets, &self.bindings)?
            {
                continue;
            }
            plan_residual_current(current_record, &mut actions, sink)?;
        }
        check_control(control)?;
        let workspace_stage_bytes = targets
            .target_full_logical_bytes
            .checked_sub(reusable_workspace_bytes)
            .ok_or(DryRunError::LedgerLimit)?;
        let retired_tracked_baseline_bytes = currents
            .current_tracked_baseline_bytes
            .checked_sub(reusable_workspace_bytes)
            .ok_or(DryRunError::LedgerLimit)?;
        let disk_payload_reservation_bytes =
            ledger_add(workspace_stage_bytes, object_projection.cache_miss_bytes)?;
        let action_projection_digest = actions.finish();
        sink.finish().map_err(|_| DryRunError::SinkFailed)?;
        check_control(control)?;
        Ok(DryRunSummary {
            bindings_digest: self.bindings_digest,
            target_projection_digest: targets.digest,
            current_projection_digest: currents.digest,
            required_object_projection_digest: object_projection.required_digest,
            cache_projection_digest: object_projection.cache_digest,
            action_projection_digest,
            target_records: self.bindings.target_count,
            current_records: self.bindings.current_count,
            required_objects: self.bindings.required_object_count,
            cache_probes: self.bindings.cache_probe_count,
            actions: actions.actions,
            adds: actions.adds,
            updates: actions.updates,
            deletes: actions.deletes,
            moves_or_equivalents: actions.moves,
            materialization_state_changes: actions.materialization,
            conflicts: actions.conflicts,
            blockers: actions.conflicts,
            retained_bytes_peak: memory.peak,
            input_bytes,
            ledgers: DryRunLedgers {
                target_full_logical_bytes: targets.target_full_logical_bytes,
                current_tracked_baseline_bytes: currents.current_tracked_baseline_bytes,
                reusable_workspace_bytes,
                workspace_stage_bytes,
                retired_tracked_baseline_bytes,
                required_object_bytes: object_projection.required_bytes,
                cache_hit_bytes: object_projection.cache_hit_bytes,
                cache_miss_bytes: object_projection.cache_miss_bytes,
                expected_transfer_bytes: object_projection.cache_miss_bytes,
                disk_payload_reservation_bytes,
            },
        })
    }
}

#[derive(Default)]
struct MemoryBudget {
    retained: u64,
    peak: u64,
}

impl MemoryBudget {
    fn reserve(&mut self, bytes: u64) -> Result<()> {
        self.retained = self
            .retained
            .checked_add(bytes)
            .ok_or(DryRunError::RetainedMemoryLimit)?;
        if self.retained > DRY_RUN_RETAINED_BYTES_MAXIMUM {
            return Err(DryRunError::RetainedMemoryLimit);
        }
        self.peak = self.peak.max(self.retained);
        Ok(())
    }
}

struct TargetInputs {
    by_path: BTreeMap<String, DryRunTargetRecord>,
    by_platform: BTreeMap<String, Materialization>,
    by_file_id: BTreeMap<FileId, String>,
    required_manifests: BTreeSet<ObjectRef>,
    digest: ProjectionDigest,
    target_full_logical_bytes: u64,
}

struct CurrentInputs {
    by_path: BTreeMap<String, RetainedWorkspaceRecord>,
    by_platform: BTreeMap<String, String>,
    by_file_id: BTreeMap<FileId, String>,
    obstructions_by_path: BTreeSet<String>,
    obstructions_by_platform: BTreeSet<String>,
    digest: ProjectionDigest,
    current_tracked_baseline_bytes: u64,
}

struct ObjectProjection {
    required_digest: ProjectionDigest,
    cache_digest: ProjectionDigest,
    required_bytes: u64,
    cache_hit_bytes: u64,
    cache_miss_bytes: u64,
}

fn read_targets<S>(
    source: &mut S,
    bindings: &DryRunBindings,
    memory: &mut MemoryBudget,
    input_bytes: &mut u64,
    control: &EvaluationControl,
) -> Result<TargetInputs>
where
    S: PlanSource<DryRunTargetRecord>,
{
    let mut hasher = projection_hasher(TARGET_DOMAIN, bindings.target_count);
    let mut by_path = BTreeMap::new();
    let mut by_platform = BTreeMap::new();
    let mut by_file_id = BTreeMap::new();
    let mut required_manifests = BTreeSet::new();
    let mut previous_key: Option<String> = None;
    let mut target_full_logical_bytes = 0u64;
    for ordinal in 0..bindings.target_count {
        check_control(control)?;
        let record = source
            .next_record()
            .map_err(|_| DryRunError::SourceFailed)?
            .ok_or(DryRunError::TargetCountMismatch)?;
        if record.ordinal != ordinal {
            return Err(DryRunError::TargetCountMismatch);
        }
        let (repository_key, platform_key) =
            validate_path(&record.path, bindings.path_profile, bindings.case_mode)?;
        validate_path_order(&mut previous_key, &repository_key)?;
        if by_platform.contains_key(&platform_key) {
            return Err(DryRunError::PathCollision);
        }
        let full = validate_target_state(&record)?;
        if full.is_some_and(|identity| by_file_id.contains_key(&identity.file_id)) {
            return Err(DryRunError::DuplicateFileId);
        }
        let retains_manifest =
            full.is_some_and(|identity| !required_manifests.contains(&identity.manifest));
        hash_target(&mut hasher, &record);
        account_input(input_bytes, target_frame_bytes(&record)?)?;
        memory.reserve(
            RETAINED_RECORD_OVERHEAD
                + (repository_key.len() + record.path.len() + platform_key.len()) as u64,
        )?;
        if let Some(identity) = full {
            memory.reserve(RETAINED_FILE_ID_OVERHEAD + repository_key.len() as u64)?;
            if retains_manifest {
                memory.reserve(RETAINED_MANIFEST_OVERHEAD)?;
            }
            target_full_logical_bytes =
                ledger_add(target_full_logical_bytes, identity.content.logical_bytes)?;
            by_file_id.insert(identity.file_id, repository_key.clone());
            if retains_manifest {
                required_manifests.insert(identity.manifest);
            }
        }
        by_platform.insert(platform_key, record.materialization);
        if by_path.insert(repository_key, record).is_some() {
            return Err(DryRunError::PathCollision);
        }
    }
    check_control(control)?;
    if source
        .next_record()
        .map_err(|_| DryRunError::SourceFailed)?
        .is_some()
    {
        return Err(DryRunError::TargetCountMismatch);
    }
    Ok(TargetInputs {
        by_path,
        by_platform,
        by_file_id,
        required_manifests,
        digest: finalize(hasher),
        target_full_logical_bytes,
    })
}

fn read_current<S>(
    source: &mut S,
    bindings: &DryRunBindings,
    memory: &mut MemoryBudget,
    input_bytes: &mut u64,
    control: &EvaluationControl,
) -> Result<CurrentInputs>
where
    S: PlanSource<RetainedWorkspaceRecord>,
{
    let mut hasher = projection_hasher(CURRENT_DOMAIN, bindings.current_count);
    let mut by_path = BTreeMap::new();
    let mut by_platform = BTreeMap::new();
    let mut by_file_id = BTreeMap::new();
    let mut obstructions_by_path = BTreeSet::new();
    let mut obstructions_by_platform = BTreeSet::new();
    let mut previous_key: Option<String> = None;
    let mut current_tracked_baseline_bytes = 0u64;
    for ordinal in 0..bindings.current_count {
        check_control(control)?;
        let record = source
            .next_record()
            .map_err(|_| DryRunError::SourceFailed)?
            .ok_or(DryRunError::CurrentCountMismatch)?;
        if record.ordinal != ordinal {
            return Err(DryRunError::CurrentCountMismatch);
        }
        let (repository_key, platform_key) =
            validate_path(&record.path, bindings.path_profile, bindings.case_mode)?;
        validate_path_order(&mut previous_key, &repository_key)?;
        if by_platform.contains_key(&platform_key) {
            return Err(DryRunError::PathCollision);
        }
        validate_current_state(&record.state)?;
        if current_file_id(&record).is_some_and(|file_id| by_file_id.contains_key(&file_id)) {
            return Err(DryRunError::DuplicateFileId);
        }
        let obstruction = record_obstruction(&record);
        hash_current(&mut hasher, &record);
        account_input(input_bytes, current_frame_bytes(&record)?)?;
        memory.reserve(
            RETAINED_RECORD_OVERHEAD
                + (repository_key.len() + record.path.len() + platform_key.len()) as u64,
        )?;
        memory.reserve(RETAINED_PLATFORM_LOOKUP_OVERHEAD + repository_key.len() as u64)?;
        if obstruction.is_some() {
            memory.reserve(
                RETAINED_OBSTRUCTION_INDEX_OVERHEAD
                    + (repository_key.len() + platform_key.len()) as u64,
            )?;
        }
        if let RetainedCurrentState::Full {
            identity,
            observation,
        } = record.state
        {
            memory.reserve(RETAINED_FILE_ID_OVERHEAD + repository_key.len() as u64)?;
            memory.reserve(RETAINED_CURRENT_OWNER_OVERHEAD)?;
            if observation != LocalObservation::Missing {
                current_tracked_baseline_bytes = ledger_add(
                    current_tracked_baseline_bytes,
                    identity.content.logical_bytes,
                )?;
            }
            by_file_id.insert(identity.file_id, repository_key.clone());
        }
        by_platform.insert(platform_key.clone(), repository_key.clone());
        if obstruction.is_some() {
            obstructions_by_path.insert(repository_key.clone());
            obstructions_by_platform.insert(platform_key);
        }
        if by_path.insert(repository_key, record).is_some() {
            return Err(DryRunError::PathCollision);
        }
    }
    check_control(control)?;
    if source
        .next_record()
        .map_err(|_| DryRunError::SourceFailed)?
        .is_some()
    {
        return Err(DryRunError::CurrentCountMismatch);
    }
    Ok(CurrentInputs {
        by_path,
        by_platform,
        by_file_id,
        obstructions_by_path,
        obstructions_by_platform,
        digest: finalize(hasher),
        current_tracked_baseline_bytes,
    })
}

fn read_required_and_cache<O, P>(
    objects: &mut O,
    probes: &mut P,
    bindings: &DryRunBindings,
    required_manifests: &mut BTreeSet<ObjectRef>,
    input_bytes: &mut u64,
    control: &EvaluationControl,
) -> Result<ObjectProjection>
where
    O: PlanSource<DryRunRequiredObject>,
    P: PlanSource<CacheProbeRecord>,
{
    let mut required_hasher = projection_hasher(REQUIRED_DOMAIN, bindings.required_object_count);
    let mut cache_hasher = projection_hasher(CACHE_DOMAIN, bindings.cache_probe_count);
    let mut previous_object: Option<ObjectRef> = None;
    let mut required_bytes = 0u64;
    let mut cache_hit_bytes = 0u64;
    let mut cache_miss_bytes = 0u64;
    for ordinal in 0..bindings.required_object_count {
        check_control(control)?;
        let object = objects
            .next_record()
            .map_err(|_| DryRunError::SourceFailed)?
            .ok_or(DryRunError::RequiredObjectCountMismatch)?;
        let probe = probes
            .next_record()
            .map_err(|_| DryRunError::SourceFailed)?
            .ok_or(DryRunError::CacheCountMismatch)?;
        if object.ordinal != ordinal || probe.ordinal != ordinal {
            return Err(DryRunError::RequiredObjectCountMismatch);
        }
        if previous_object.is_some_and(|previous| previous >= object.object) {
            return Err(DryRunError::RequiredObjectOrderInvalid);
        }
        validate_object(object.object, object.payload_bytes)?;
        if probe.object != object.object || probe.payload_bytes != object.payload_bytes {
            return Err(DryRunError::CacheProbeMismatch);
        }
        previous_object = Some(object.object);
        hash_required(&mut required_hasher, object);
        hash_cache(&mut cache_hasher, probe);
        account_input(input_bytes, 50)?;
        account_input(input_bytes, 51)?;
        required_bytes = ledger_add(required_bytes, object.payload_bytes)?;
        match probe.outcome {
            CacheProbeOutcome::VerifiedHit => {
                cache_hit_bytes = ledger_add(cache_hit_bytes, object.payload_bytes)?;
            }
            CacheProbeOutcome::Miss => {
                cache_miss_bytes = ledger_add(cache_miss_bytes, object.payload_bytes)?;
            }
        }
        if object.object.kind == ObjectKind::ContentManifest {
            required_manifests.remove(&object.object);
        }
    }
    check_control(control)?;
    if objects
        .next_record()
        .map_err(|_| DryRunError::SourceFailed)?
        .is_some()
    {
        return Err(DryRunError::RequiredObjectCountMismatch);
    }
    if probes
        .next_record()
        .map_err(|_| DryRunError::SourceFailed)?
        .is_some()
    {
        return Err(DryRunError::CacheCountMismatch);
    }
    Ok(ObjectProjection {
        required_digest: finalize(required_hasher),
        cache_digest: finalize(cache_hasher),
        required_bytes,
        cache_hit_bytes,
        cache_miss_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn plan_target_record<W: DryRunActionSink>(
    repository_key: &str,
    target: &DryRunTargetRecord,
    currents: &CurrentInputs,
    bindings: &DryRunBindings,
    actions: &mut ActionAccumulator,
    reusable_workspace_bytes: &mut u64,
    current_owners: &mut BTreeSet<FileId>,
    sink: &mut W,
) -> Result<()> {
    let current_at_repository_path = currents.by_path.get(repository_key);
    let current_at_platform_path = if current_at_repository_path.is_none()
        && target.materialization != Materialization::AbsentBySpec
    {
        current_for_platform_path(&target.path, currents, bindings)?
    } else {
        None
    };
    let unclaimed_current_at_path = current_at_repository_path.or(current_at_platform_path);
    match target.materialization {
        Materialization::AbsentBySpec => {
            if let Some(current) =
                claim_current_for_target(unclaimed_current_at_path, current_owners)
            {
                match current.state {
                    RetainedCurrentState::Full { observation, .. } => {
                        let blocker = observation_blocker(observation);
                        let mutation = MutationKind::Delete;
                        emit_candidate(
                            actions,
                            sink,
                            target.path.clone(),
                            None,
                            current_state(current.state),
                            CandidateMaterializationState::Absent,
                            mutation,
                            blocker.map(|kind| (kind, current.path.clone())),
                            0,
                            0,
                        )?;
                    }
                    RetainedCurrentState::MetadataOnly { .. } => {
                        emit_candidate(
                            actions,
                            sink,
                            target.path.clone(),
                            None,
                            current_state(current.state),
                            CandidateMaterializationState::Absent,
                            MutationKind::MaterializationState,
                            None,
                            0,
                            0,
                        )?;
                    }
                    RetainedCurrentState::Untracked => {}
                }
            }
        }
        Materialization::MetadataOnly => {
            match claim_current_for_target(unclaimed_current_at_path, current_owners) {
                None => emit_candidate(
                    actions,
                    sink,
                    target.path.clone(),
                    None,
                    CandidateMaterializationState::Absent,
                    CandidateMaterializationState::MetadataOnly,
                    MutationKind::MaterializationState,
                    None,
                    0,
                    0,
                )?,
                Some(current) => match current.state {
                    RetainedCurrentState::Full { observation, .. } => emit_candidate(
                        actions,
                        sink,
                        target.path.clone(),
                        current_at_platform_path.map(|record| record.path.clone()),
                        current_state(current.state),
                        CandidateMaterializationState::MetadataOnly,
                        MutationKind::MaterializationState,
                        observation_blocker(observation).map(|kind| (kind, current.path.clone())),
                        0,
                        0,
                    )?,
                    RetainedCurrentState::MetadataOnly {
                        ordinary_path_obstruction: false,
                    } => {
                        if let Some(source_path) = current_at_platform_path {
                            emit_candidate(
                                actions,
                                sink,
                                target.path.clone(),
                                Some(source_path.path.clone()),
                                CandidateMaterializationState::MetadataOnly,
                                CandidateMaterializationState::MetadataOnly,
                                MutationKind::MaterializationState,
                                None,
                                0,
                                0,
                            )?;
                        }
                    }
                    RetainedCurrentState::MetadataOnly {
                        ordinary_path_obstruction: true,
                    }
                    | RetainedCurrentState::Untracked => emit_candidate(
                        actions,
                        sink,
                        target.path.clone(),
                        current_at_platform_path.map(|record| record.path.clone()),
                        current_state(current.state),
                        CandidateMaterializationState::MetadataOnly,
                        MutationKind::MaterializationState,
                        Some((BlockerKind::UntrackedObstruction, current.path.clone())),
                        0,
                        0,
                    )?,
                },
            }
        }
        Materialization::Full => {
            let identity = target.identity.ok_or(DryRunError::MetadataStateInvalid)?;
            if let Some(source_key) = currents.by_file_id.get(&identity.file_id) {
                if source_key != repository_key {
                    let source = currents
                        .by_path
                        .get(source_key)
                        .ok_or(DryRunError::IdentityInvalid)?;
                    if claim_current_owner(source, current_owners) {
                        let destination = unclaimed_current_at_path.and_then(|record| {
                            if same_full_current(source, record)
                                || claim_current_owner(record, current_owners)
                            {
                                Some(record)
                            } else {
                                None
                            }
                        });
                        plan_move(
                            target,
                            identity,
                            source,
                            destination,
                            currents,
                            bindings,
                            actions,
                            reusable_workspace_bytes,
                            sink,
                        )?;
                        return Ok(());
                    }
                }
            }
            let current_at_path =
                claim_current_for_target(unclaimed_current_at_path, current_owners);
            let platform_alias_source = current_at_path
                .and(current_at_platform_path)
                .map(|record| record.path.clone());
            plan_full_at_path(
                target,
                identity,
                current_at_path,
                currents,
                bindings,
                actions,
                reusable_workspace_bytes,
                platform_alias_source,
                sink,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn plan_move<W: DryRunActionSink>(
    target: &DryRunTargetRecord,
    identity: DryRunFullIdentity,
    source: &RetainedWorkspaceRecord,
    destination: Option<&RetainedWorkspaceRecord>,
    currents: &CurrentInputs,
    bindings: &DryRunBindings,
    actions: &mut ActionAccumulator,
    reusable_workspace_bytes: &mut u64,
    sink: &mut W,
) -> Result<()> {
    let RetainedCurrentState::Full {
        identity: _,
        observation: source_observation,
    } = source.state
    else {
        return Err(DryRunError::IdentityInvalid);
    };
    let mut blocker =
        observation_blocker(source_observation).map(|kind| (kind, source.path.clone()));
    if blocker.is_none() {
        blocker = destination.and_then(destination_blocker);
    }
    if blocker.is_none() {
        blocker = find_path_obstruction(&target.path, currents, bindings)?;
    }
    let reusable = reusable_from(source, identity)
        || destination.is_some_and(|record| reusable_from(record, identity));
    if reusable {
        *reusable_workspace_bytes =
            ledger_add(*reusable_workspace_bytes, identity.content.logical_bytes)?;
    }
    emit_candidate(
        actions,
        sink,
        target.path.clone(),
        Some(source.path.clone()),
        current_state(source.state),
        CandidateMaterializationState::FullPresent,
        MutationKind::MoveOrEquivalent,
        blocker,
        identity.content.logical_bytes,
        if reusable {
            0
        } else {
            identity.content.logical_bytes
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_full_at_path<W: DryRunActionSink>(
    target: &DryRunTargetRecord,
    identity: DryRunFullIdentity,
    current: Option<&RetainedWorkspaceRecord>,
    currents: &CurrentInputs,
    bindings: &DryRunBindings,
    actions: &mut ActionAccumulator,
    reusable_workspace_bytes: &mut u64,
    source_path: Option<String>,
    sink: &mut W,
) -> Result<()> {
    match current {
        None => {
            let blocker = find_path_obstruction(&target.path, currents, bindings)?;
            emit_candidate(
                actions,
                sink,
                target.path.clone(),
                source_path.clone(),
                CandidateMaterializationState::Absent,
                CandidateMaterializationState::FullPresent,
                MutationKind::Add,
                blocker,
                identity.content.logical_bytes,
                identity.content.logical_bytes,
            )
        }
        Some(current) => match current.state {
            RetainedCurrentState::Untracked => emit_candidate(
                actions,
                sink,
                target.path.clone(),
                source_path.clone(),
                CandidateMaterializationState::Untracked,
                CandidateMaterializationState::FullPresent,
                MutationKind::Add,
                Some((BlockerKind::UntrackedObstruction, current.path.clone())),
                identity.content.logical_bytes,
                identity.content.logical_bytes,
            ),
            RetainedCurrentState::MetadataOnly {
                ordinary_path_obstruction,
            } => emit_candidate(
                actions,
                sink,
                target.path.clone(),
                source_path.clone(),
                current_state(current.state),
                CandidateMaterializationState::FullPresent,
                MutationKind::MaterializationState,
                ordinary_path_obstruction
                    .then(|| (BlockerKind::UntrackedObstruction, current.path.clone())),
                identity.content.logical_bytes,
                identity.content.logical_bytes,
            ),
            RetainedCurrentState::Full {
                identity: current_identity,
                observation,
            } => {
                let reusable = reusable_from(current, identity);
                if reusable {
                    *reusable_workspace_bytes =
                        ledger_add(*reusable_workspace_bytes, identity.content.logical_bytes)?;
                }
                let exact = current_identity == identity;
                if exact && observation == LocalObservation::Pristine {
                    return Ok(());
                }
                let mutation = if exact && observation == LocalObservation::Missing {
                    MutationKind::MaterializationState
                } else {
                    MutationKind::Update
                };
                let blocker = observation_blocker(observation)
                    .map(|kind| (kind, current.path.clone()))
                    .or(find_path_obstruction(&target.path, currents, bindings)?);
                emit_candidate(
                    actions,
                    sink,
                    target.path.clone(),
                    source_path,
                    current_state(current.state),
                    CandidateMaterializationState::FullPresent,
                    mutation,
                    blocker,
                    identity.content.logical_bytes,
                    if reusable {
                        0
                    } else {
                        identity.content.logical_bytes
                    },
                )
            }
        },
    }
}

fn plan_residual_current<W: DryRunActionSink>(
    current: &RetainedWorkspaceRecord,
    actions: &mut ActionAccumulator,
    sink: &mut W,
) -> Result<()> {
    match current.state {
        RetainedCurrentState::Full { observation, .. } => emit_candidate(
            actions,
            sink,
            current.path.clone(),
            None,
            current_state(current.state),
            CandidateMaterializationState::Absent,
            MutationKind::Delete,
            observation_blocker(observation).map(|kind| (kind, current.path.clone())),
            0,
            0,
        ),
        RetainedCurrentState::MetadataOnly { .. } => emit_candidate(
            actions,
            sink,
            current.path.clone(),
            None,
            current_state(current.state),
            CandidateMaterializationState::Absent,
            MutationKind::MaterializationState,
            None,
            0,
            0,
        ),
        RetainedCurrentState::Untracked => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_candidate<W: DryRunActionSink>(
    actions: &mut ActionAccumulator,
    sink: &mut W,
    path: String,
    source_path: Option<String>,
    from: CandidateMaterializationState,
    to: CandidateMaterializationState,
    mutation: MutationKind,
    blocker: Option<(BlockerKind, String)>,
    target_logical_bytes: u64,
    workspace_write_bytes: u64,
) -> Result<()> {
    let (kind, blocked_mutation, blocker_kind, blocker_path) = match blocker {
        None => (mutation.into(), None, None, None),
        Some((blocker, blocker_path)) => (
            CandidateActionKind::Conflict,
            Some(mutation),
            Some(blocker),
            Some(blocker_path),
        ),
    };
    let action = DryRunAction {
        sequence: actions.actions,
        kind,
        path,
        source_path,
        from,
        to,
        blocked_mutation,
        blocker: blocker_kind,
        blocker_path,
        target_logical_bytes,
        workspace_write_bytes,
    };
    actions.push(&action)?;
    sink.emit(&action).map_err(|_| DryRunError::SinkFailed)
}

struct ActionAccumulator {
    hasher: Sha256,
    actions: u64,
    adds: u64,
    updates: u64,
    deletes: u64,
    moves: u64,
    materialization: u64,
    conflicts: u64,
}

impl ActionAccumulator {
    fn new(bindings_digest: ProjectionDigest) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ACTION_DOMAIN);
        hasher.update(bindings_digest);
        Self {
            hasher,
            actions: 0,
            adds: 0,
            updates: 0,
            deletes: 0,
            moves: 0,
            materialization: 0,
            conflicts: 0,
        }
    }

    fn push(&mut self, action: &DryRunAction) -> Result<()> {
        if action.sequence != self.actions {
            return Err(DryRunError::IdentityInvalid);
        }
        if self.actions >= DRY_RUN_ACTIONS_MAXIMUM {
            return Err(DryRunError::ActionCountLimit);
        }
        hash_action(&mut self.hasher, action);
        self.actions = self
            .actions
            .checked_add(1)
            .ok_or(DryRunError::LedgerLimit)?;
        match action.kind {
            CandidateActionKind::Add => self.adds += 1,
            CandidateActionKind::Update => self.updates += 1,
            CandidateActionKind::Delete => self.deletes += 1,
            CandidateActionKind::MoveOrEquivalent => self.moves += 1,
            CandidateActionKind::MaterializationState => self.materialization += 1,
            CandidateActionKind::Conflict => self.conflicts += 1,
        }
        Ok(())
    }

    fn finish(&self) -> ProjectionDigest {
        let mut hasher = self.hasher.clone();
        hasher.update(self.actions.to_be_bytes());
        finalize(hasher)
    }
}

fn current_file_id(record: &RetainedWorkspaceRecord) -> Option<FileId> {
    match record.state {
        RetainedCurrentState::Full { identity, .. } => Some(identity.file_id),
        RetainedCurrentState::MetadataOnly { .. } | RetainedCurrentState::Untracked => None,
    }
}

fn claim_current_owner(
    current: &RetainedWorkspaceRecord,
    current_owners: &mut BTreeSet<FileId>,
) -> bool {
    current_file_id(current).is_none_or(|file_id| current_owners.insert(file_id))
}

fn claim_current_for_target<'a>(
    current: Option<&'a RetainedWorkspaceRecord>,
    current_owners: &mut BTreeSet<FileId>,
) -> Option<&'a RetainedWorkspaceRecord> {
    current.filter(|record| claim_current_owner(record, current_owners))
}

fn same_full_current(left: &RetainedWorkspaceRecord, right: &RetainedWorkspaceRecord) -> bool {
    current_file_id(left).is_some_and(|file_id| current_file_id(right) == Some(file_id))
}

fn current_for_platform_path<'a>(
    target_path: &str,
    currents: &'a CurrentInputs,
    bindings: &DryRunBindings,
) -> Result<Option<&'a RetainedWorkspaceRecord>> {
    let keys =
        path_collision_keys_with_options(target_path, bindings.path_profile, bindings.case_mode)
            .map_err(|_| DryRunError::PathInvalid)?;
    let Some(repository_key) = currents.by_platform.get(keys.platform_key()) else {
        return Ok(None);
    };
    currents
        .by_path
        .get(repository_key)
        .map(Some)
        .ok_or(DryRunError::IdentityInvalid)
}

fn target_occupies_platform_path(
    current: &RetainedWorkspaceRecord,
    targets: &TargetInputs,
    bindings: &DryRunBindings,
) -> Result<bool> {
    let keys =
        path_collision_keys_with_options(&current.path, bindings.path_profile, bindings.case_mode)
            .map_err(|_| DryRunError::PathInvalid)?;
    Ok(matches!(
        targets.by_platform.get(keys.platform_key()),
        Some(Materialization::Full | Materialization::MetadataOnly)
    ))
}

fn current_state(state: RetainedCurrentState) -> CandidateMaterializationState {
    match state {
        RetainedCurrentState::Full {
            observation: LocalObservation::Missing,
            ..
        } => CandidateMaterializationState::FullMissing,
        RetainedCurrentState::Full {
            observation: LocalObservation::Obstructed,
            ..
        } => CandidateMaterializationState::Obstructed,
        RetainedCurrentState::Full { .. } => CandidateMaterializationState::FullPresent,
        RetainedCurrentState::MetadataOnly {
            ordinary_path_obstruction: false,
        } => CandidateMaterializationState::MetadataOnly,
        RetainedCurrentState::MetadataOnly {
            ordinary_path_obstruction: true,
        } => CandidateMaterializationState::MetadataOnlyObstructed,
        RetainedCurrentState::Untracked => CandidateMaterializationState::Untracked,
    }
}

fn observation_blocker(observation: LocalObservation) -> Option<BlockerKind> {
    match observation {
        LocalObservation::Pristine | LocalObservation::Missing => None,
        LocalObservation::Modified => Some(BlockerKind::LocallyModified),
        LocalObservation::Obstructed => Some(BlockerKind::LocalObstruction),
    }
}

fn destination_blocker(record: &RetainedWorkspaceRecord) -> Option<(BlockerKind, String)> {
    Some((record_obstruction(record)?, record.path.clone()))
}

fn record_obstruction(record: &RetainedWorkspaceRecord) -> Option<BlockerKind> {
    match record.state {
        RetainedCurrentState::Untracked
        | RetainedCurrentState::MetadataOnly {
            ordinary_path_obstruction: true,
        } => Some(BlockerKind::UntrackedObstruction),
        RetainedCurrentState::Full { observation, .. } => observation_blocker(observation),
        RetainedCurrentState::MetadataOnly {
            ordinary_path_obstruction: false,
        } => None,
    }
}

fn find_path_obstruction(
    target_path: &str,
    currents: &CurrentInputs,
    bindings: &DryRunBindings,
) -> Result<Option<(BlockerKind, String)>> {
    for (index, byte) in target_path.as_bytes().iter().enumerate() {
        if *byte != b'/' {
            continue;
        }
        let prefix = &target_path[..index];
        let keys =
            path_collision_keys_with_options(prefix, bindings.path_profile, bindings.case_mode)
                .map_err(|_| DryRunError::PathInvalid)?;
        if let Some(blocker) =
            obstruction_for_repository_key(keys.repository_key().as_str(), currents)
        {
            return Ok(Some(blocker));
        }
        if let Some(blocker) = obstruction_for_platform_key(keys.platform_key(), currents) {
            return Ok(Some(blocker));
        }
    }
    let target_keys =
        path_collision_keys_with_options(target_path, bindings.path_profile, bindings.case_mode)
            .map_err(|_| DryRunError::PathInvalid)?;
    let repository_prefix = format!("{}/", target_keys.repository_key().as_str());
    if let Some(key) = first_descendant_key(&currents.obstructions_by_path, &repository_prefix) {
        return currents
            .by_path
            .get(key)
            .and_then(|record| {
                record_obstruction(record).map(|blocker| (blocker, record.path.clone()))
            })
            .map(Some)
            .ok_or(DryRunError::IdentityInvalid);
    }
    let platform_prefix = format!("{}/", target_keys.platform_key());
    if let Some(key) = first_descendant_key(&currents.obstructions_by_platform, &platform_prefix) {
        return obstruction_for_platform_key(key, currents)
            .map(Some)
            .ok_or(DryRunError::IdentityInvalid);
    }
    Ok(None)
}

fn obstruction_for_repository_key(
    repository_key: &str,
    currents: &CurrentInputs,
) -> Option<(BlockerKind, String)> {
    if !currents.obstructions_by_path.contains(repository_key) {
        return None;
    }
    let record = currents.by_path.get(repository_key)?;
    Some((record_obstruction(record)?, record.path.clone()))
}

fn obstruction_for_platform_key(
    platform_key: &str,
    currents: &CurrentInputs,
) -> Option<(BlockerKind, String)> {
    if !currents.obstructions_by_platform.contains(platform_key) {
        return None;
    }
    let repository_key = currents.by_platform.get(platform_key)?;
    let record = currents.by_path.get(repository_key)?;
    Some((record_obstruction(record)?, record.path.clone()))
}

fn first_descendant_key<'a>(index: &'a BTreeSet<String>, prefix: &str) -> Option<&'a str> {
    let candidate = index.range(prefix.to_owned()..).next()?;
    candidate.starts_with(prefix).then_some(candidate.as_str())
}

fn payload_equivalent(left: DryRunFullIdentity, right: DryRunFullIdentity) -> bool {
    left.manifest == right.manifest && left.content == right.content
}

fn reusable_from(current: &RetainedWorkspaceRecord, target: DryRunFullIdentity) -> bool {
    matches!(
        current.state,
        RetainedCurrentState::Full {
            identity,
            observation: LocalObservation::Pristine,
        } if payload_equivalent(identity, target)
    )
}

fn validate_target_state(record: &DryRunTargetRecord) -> Result<Option<DryRunFullIdentity>> {
    match (record.materialization, record.identity) {
        (Materialization::Full, Some(identity)) => {
            validate_full_identity(identity)?;
            Ok(Some(identity))
        }
        (Materialization::MetadataOnly | Materialization::AbsentBySpec, None) => Ok(None),
        _ => Err(DryRunError::MetadataStateInvalid),
    }
}

fn validate_current_state(state: &RetainedCurrentState) -> Result<()> {
    if let RetainedCurrentState::Full { identity, .. } = state {
        validate_full_identity(*identity)?;
    }
    Ok(())
}

fn validate_full_identity(identity: DryRunFullIdentity) -> Result<()> {
    if identity.manifest.kind != ObjectKind::ContentManifest
        || identity.content.logical_bytes > LOGICAL_BYTES_MAXIMUM
    {
        return Err(DryRunError::IdentityInvalid);
    }
    Ok(())
}

fn validate_object(object: ObjectRef, bytes: u64) -> Result<()> {
    let maximum = match object.kind {
        ObjectKind::Chunk => MAXIMUM as u64,
        ObjectKind::ContentManifest => MANIFEST_BYTES_MAXIMUM,
        _ => return Err(DryRunError::ObjectInvalid),
    };
    if bytes == 0 || bytes > maximum {
        return Err(DryRunError::ObjectInvalid);
    }
    Ok(())
}

fn validate_path(
    path: &str,
    profile: PathProfile,
    case_mode: CaseMode,
) -> Result<(String, String)> {
    let keys = path_collision_keys_with_options(path, profile, case_mode)
        .map_err(|_| DryRunError::PathInvalid)?;
    if keys.path().canonical() != path {
        return Err(DryRunError::PathInvalid);
    }
    Ok((
        keys.repository_key().as_str().to_owned(),
        keys.platform_key().to_owned(),
    ))
}

fn validate_path_order(previous: &mut Option<String>, current: &str) -> Result<()> {
    if previous.as_deref().is_some_and(|prior| prior >= current) {
        return Err(if previous.as_deref() == Some(current) {
            DryRunError::PathCollision
        } else {
            DryRunError::PathOrderInvalid
        });
    }
    *previous = Some(current.to_owned());
    Ok(())
}

fn check_control(control: &EvaluationControl) -> Result<()> {
    control.check().map_err(|_| DryRunError::Cancelled)
}

fn ledger_add(left: u64, right: u64) -> Result<u64> {
    let result = left.checked_add(right).ok_or(DryRunError::LedgerLimit)?;
    if result > DRY_RUN_LEDGER_BYTES_MAXIMUM {
        Err(DryRunError::LedgerLimit)
    } else {
        Ok(result)
    }
}

fn account_input(total: &mut u64, bytes: u64) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or(DryRunError::InputBytesLimit)?;
    if *total > DRY_RUN_INPUT_BYTES_MAXIMUM {
        Err(DryRunError::InputBytesLimit)
    } else {
        Ok(())
    }
}

fn projection_hasher(domain: &[u8], count: u64) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(count.to_be_bytes());
    hasher
}

fn bindings_digest(bindings: &DryRunBindings) -> ProjectionDigest {
    let mut hasher = Sha256::new();
    hasher.update(BINDINGS_DOMAIN);
    hasher.update(bindings.snapshot_digest);
    hasher.update(bindings.current_generation_digest);
    hasher.update(bindings.selection_projection_digest);
    update_text(&mut hasher, bindings.path_profile.as_str());
    hasher.update([match bindings.case_mode {
        CaseMode::Sensitive => 1,
        CaseMode::Folded => 2,
    }]);
    hasher.update([bindings.platform as u8]);
    hasher.update(bindings.target_count.to_be_bytes());
    hasher.update(bindings.current_count.to_be_bytes());
    hasher.update(bindings.required_object_count.to_be_bytes());
    hasher.update(bindings.cache_probe_count.to_be_bytes());
    finalize(hasher)
}

fn hash_target(hasher: &mut Sha256, record: &DryRunTargetRecord) {
    hasher.update(record.ordinal.to_be_bytes());
    update_text(hasher, &record.path);
    hasher.update([record.materialization as u8]);
    match record.identity {
        None => hasher.update([0]),
        Some(identity) => {
            hasher.update([1]);
            hash_identity(hasher, identity);
        }
    }
}

fn hash_current(hasher: &mut Sha256, record: &RetainedWorkspaceRecord) {
    hasher.update(record.ordinal.to_be_bytes());
    update_text(hasher, &record.path);
    match record.state {
        RetainedCurrentState::Full {
            identity,
            observation,
        } => {
            hasher.update([1, observation as u8]);
            hash_identity(hasher, identity);
        }
        RetainedCurrentState::MetadataOnly {
            ordinary_path_obstruction,
        } => hasher.update([2, u8::from(ordinary_path_obstruction)]),
        RetainedCurrentState::Untracked => hasher.update([3]),
    }
}

fn hash_identity(hasher: &mut Sha256, identity: DryRunFullIdentity) {
    hasher.update(identity.file_id.as_bytes());
    hasher.update(identity.entry_digest);
    hash_object(hasher, identity.manifest);
    hasher.update(identity.content.digest);
    hasher.update(identity.content.logical_bytes.to_be_bytes());
}

fn hash_required(hasher: &mut Sha256, record: DryRunRequiredObject) {
    hasher.update(record.ordinal.to_be_bytes());
    hash_object(hasher, record.object);
    hasher.update(record.payload_bytes.to_be_bytes());
}

fn hash_cache(hasher: &mut Sha256, record: CacheProbeRecord) {
    hasher.update(record.ordinal.to_be_bytes());
    hash_object(hasher, record.object);
    hasher.update(record.payload_bytes.to_be_bytes());
    hasher.update([match record.outcome {
        CacheProbeOutcome::VerifiedHit => 1,
        CacheProbeOutcome::Miss => 2,
    }]);
}

fn hash_object(hasher: &mut Sha256, object: ObjectRef) {
    hasher.update(object.kind.code().to_be_bytes());
    hasher.update(object.digest);
}

fn hash_action(hasher: &mut Sha256, action: &DryRunAction) {
    hasher.update(action.sequence.to_be_bytes());
    hasher.update([action.kind as u8]);
    update_text(hasher, &action.path);
    match action.source_path.as_deref() {
        None => hasher.update([0]),
        Some(path) => {
            hasher.update([1]);
            update_text(hasher, path);
        }
    }
    hasher.update([action.from as u8, action.to as u8]);
    hasher.update([action.blocked_mutation.map_or(0, |value| value as u8 + 1)]);
    hasher.update([action.blocker.map_or(0, |value| value as u8 + 1)]);
    match action.blocker_path.as_deref() {
        None => hasher.update([0]),
        Some(path) => {
            hasher.update([1]);
            update_text(hasher, path);
        }
    }
    hasher.update(action.target_logical_bytes.to_be_bytes());
    hasher.update(action.workspace_write_bytes.to_be_bytes());
}

fn target_frame_bytes(record: &DryRunTargetRecord) -> Result<u64> {
    let base = 18u64
        .checked_add(record.path.len() as u64)
        .ok_or(DryRunError::InputBytesLimit)?;
    Ok(base + if record.identity.is_some() { 124 } else { 0 })
}

fn current_frame_bytes(record: &RetainedWorkspaceRecord) -> Result<u64> {
    let base = 18u64
        .checked_add(record.path.len() as u64)
        .ok_or(DryRunError::InputBytesLimit)?;
    Ok(base
        + if matches!(record.state, RetainedCurrentState::Full { .. }) {
            124
        } else {
            1
        })
}

fn update_text(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_be_bytes());
    hasher.update(text.as_bytes());
}

fn finalize(hasher: Sha256) -> ProjectionDigest {
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_and_memory_bounds_are_closed_at_exact_values() {
        assert_eq!(
            ledger_add(0, DRY_RUN_LEDGER_BYTES_MAXIMUM),
            Ok(DRY_RUN_LEDGER_BYTES_MAXIMUM)
        );
        assert_eq!(
            ledger_add(DRY_RUN_LEDGER_BYTES_MAXIMUM, 1),
            Err(DryRunError::LedgerLimit)
        );
        let mut memory = MemoryBudget::default();
        assert_eq!(memory.reserve(DRY_RUN_RETAINED_BYTES_MAXIMUM), Ok(()));
        assert_eq!(memory.peak, DRY_RUN_RETAINED_BYTES_MAXIMUM);
        assert_eq!(memory.reserve(1), Err(DryRunError::RetainedMemoryLimit));
        let mut input = 0;
        assert_eq!(
            account_input(&mut input, DRY_RUN_INPUT_BYTES_MAXIMUM),
            Ok(())
        );
        assert_eq!(
            account_input(&mut input, 1),
            Err(DryRunError::InputBytesLimit)
        );
    }

    #[test]
    fn platform_and_obstruction_indexes_are_admitted_at_the_memory_boundary() {
        let path = "Memory/Obstruction.bin";
        let bindings = DryRunBindings::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "path.opengamevcs/linux@1",
            CaseMode::Sensitive,
            HostPlatform::Linux,
            0,
            1,
            0,
            0,
        )
        .unwrap();
        let (repository_key, platform_key) =
            validate_path(path, bindings.path_profile, bindings.case_mode).unwrap();
        let admission = RETAINED_RECORD_OVERHEAD
            + (repository_key.len() + path.len() + platform_key.len()) as u64
            + RETAINED_PLATFORM_LOOKUP_OVERHEAD
            + repository_key.len() as u64
            + RETAINED_OBSTRUCTION_INDEX_OVERHEAD
            + (repository_key.len() + platform_key.len()) as u64;
        let record = RetainedWorkspaceRecord {
            ordinal: 0,
            path: path.to_owned(),
            state: RetainedCurrentState::Untracked,
        };

        let mut source = IteratorPlanSource::new(vec![record.clone()].into_iter());
        let mut memory = MemoryBudget {
            retained: DRY_RUN_RETAINED_BYTES_MAXIMUM - admission,
            peak: DRY_RUN_RETAINED_BYTES_MAXIMUM - admission,
        };
        let mut input = 0;
        assert!(read_current(
            &mut source,
            &bindings,
            &mut memory,
            &mut input,
            &EvaluationControl::default(),
        )
        .is_ok());
        assert_eq!(memory.peak, DRY_RUN_RETAINED_BYTES_MAXIMUM);

        let mut source = IteratorPlanSource::new(vec![record].into_iter());
        let mut memory = MemoryBudget {
            retained: DRY_RUN_RETAINED_BYTES_MAXIMUM - admission + 1,
            peak: DRY_RUN_RETAINED_BYTES_MAXIMUM - admission + 1,
        };
        let mut input = 0;
        assert!(matches!(
            read_current(
                &mut source,
                &bindings,
                &mut memory,
                &mut input,
                &EvaluationControl::default(),
            ),
            Err(DryRunError::RetainedMemoryLimit)
        ));
    }
}
