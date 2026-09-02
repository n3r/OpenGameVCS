//! Private, bounded hard-lock and advisory edit-intent state model.
//!
//! This crate deliberately has no storage, clock, authorization, network,
//! filesystem, or submit-mutation adapter. Permission decisions, target/group
//! expansions, server time, and submit requirements are caller-supplied facts.
//! They are committed and fail closed, but are not authenticated here.
#![forbid(unsafe_code)]

mod digest;
mod submit;
mod target;

use std::collections::{BTreeMap, BTreeSet};

use digest::{digest16, Digest, DigestBuilder};
use ogvcs_object_model::{ObjectKind, ObjectRef};
use ogvcs_path_contract::{CaseMode, PathProfile};
use target::{bounded_target_input_work, digest_target_input, normalize_target, NormalizedTarget};

pub use submit::{
    SubmitChangeFact, SubmitPlanBinding, SubmitValidationClass, SubmitValidationControl,
    SubmitValidationReceipt, SubmitValidationRequest,
};
pub use target::{
    AssetGroupId, ExpandedMember, LockTarget, TargetError, TargetExpansion, TargetInput,
    ASSET_GROUP_MEMBERS_MAXIMUM, PREFIX_EXPANSION_MEMBERS_MAXIMUM, TARGET_EXPANSION_VERSION,
};

pub const MODEL_VERSION: u16 = 1;
pub const PERMISSION_LOCK_CREATE: u16 = 5;
pub const PERMISSION_SUBMIT: u16 = 6;
pub const PERMISSION_LOCK_FORCE_UNLOCK: u16 = 10;

pub const ACTIVE_HARD_LOCKS_HARD_MAXIMUM: usize = 1_024;
pub const ACTIVE_ADVISORY_INTENTS_HARD_MAXIMUM: usize = 4_096;
pub const WAIT_SUBSCRIPTIONS_HARD_MAXIMUM: usize = 4_096;
pub const NOTICE_COMMITMENTS_HARD_MAXIMUM: usize = 4_096;
pub const IDEMPOTENCY_RECORDS_HARD_MAXIMUM: usize = 16_384;
pub const EVENT_COMMITMENTS_HARD_MAXIMUM: usize = 32_768;
pub const BATCH_REQUESTS_HARD_MAXIMUM: usize = 128;
pub const SUBMIT_TARGETS_HARD_MAXIMUM: usize = 256;
pub const REASON_BYTES_HARD_MAXIMUM: usize = 512;
pub const LEASE_TICKS_HARD_MAXIMUM: u64 = 86_400;
pub const WORK_UNITS_HARD_MAXIMUM: u64 = 16_777_216;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    InvalidIdentifier,
    InvalidConfiguration,
}

// Keep the public identifiers distinct without exposing semantic strings.
macro_rules! identifier {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub fn new(value: [u8; $size]) -> Result<Self, ModelError> {
                if value == [0; $size] {
                    return Err(ModelError::InvalidIdentifier);
                }
                Ok(Self(value))
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }
        }
    };
}

identifier!(RepositoryId, 16);
identifier!(SubjectId, 32);
identifier!(WorkspaceId, 32);
identifier!(IdempotencyKey, 16);
identifier!(ClaimId, 16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeBinding {
    pub repository_id: RepositoryId,
    pub domain_digest: Digest,
}

impl ScopeBinding {
    pub fn commitment(&self) -> Digest {
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-SCOPE-V1");
        digest.fixed(self.repository_id.as_bytes());
        digest.fixed(&self.domain_digest);
        digest.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum PermissionAssignment {
    LockCreate = PERMISSION_LOCK_CREATE,
    Submit = PERMISSION_SUBMIT,
    LockForceUnlock = PERMISSION_LOCK_FORCE_UNLOCK,
}

impl PermissionAssignment {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuppliedDecision {
    Affirmed,
    NotAffirmed,
}

/// Opaque, caller-supplied OGVCS-003 assignment/result fact.
///
/// This value is neither signed nor evaluated by this crate. Production code
/// must obtain and authenticate it within its own decision boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuppliedPermissionFact {
    pub permission: PermissionAssignment,
    pub decision: SuppliedDecision,
    pub authority_epoch: u64,
    pub policy_generation: u64,
    pub subject: SubjectId,
    pub scope_commitment: Digest,
    pub decision_digest: Digest,
}

impl SuppliedPermissionFact {
    fn digest(&self) -> Digest {
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-SUPPLIED-PERMISSION-FACT-V1");
        digest.u16(self.permission.code());
        digest.u8(match self.decision {
            SuppliedDecision::Affirmed => 1,
            SuppliedDecision::NotAffirmed => 2,
        });
        digest.u64(self.authority_epoch);
        digest.u64(self.policy_generation);
        digest.fixed(self.subject.as_bytes());
        digest.fixed(&self.scope_commitment);
        digest.fixed(&self.decision_digest);
        digest.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestMeta {
    pub idempotency_key: IdempotencyKey,
    pub scope: ScopeBinding,
    pub permission: SuppliedPermissionFact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimProof {
    pub claim_id: ClaimId,
    pub authority_epoch: u64,
    pub generation: u64,
    pub receipt_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BreakSelector {
    pub claim_id: ClaimId,
    pub authority_epoch: u64,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireRequest {
    pub meta: RequestMeta,
    pub owner: SubjectId,
    pub workspace: WorkspaceId,
    pub base_snapshot: ObjectRef,
    pub target: TargetInput,
    pub lease_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewRequest {
    pub meta: RequestMeta,
    pub owner: SubjectId,
    pub workspace: WorkspaceId,
    pub proof: ClaimProof,
    pub lease_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseRequest {
    pub meta: RequestMeta,
    pub owner: SubjectId,
    pub workspace: WorkspaceId,
    pub proof: ClaimProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferRequest {
    pub meta: RequestMeta,
    pub owner: SubjectId,
    pub from_workspace: WorkspaceId,
    pub to_workspace: WorkspaceId,
    pub proof: ClaimProof,
    pub lease_ticks: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BreakRequest {
    pub meta: RequestMeta,
    pub actor: SubjectId,
    pub selector: BreakSelector,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiryRequest {
    pub idempotency_key: IdempotencyKey,
    pub scope: ScopeBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitRequest {
    pub meta: RequestMeta,
    pub subject: SubjectId,
    pub workspace: WorkspaceId,
    pub target: TargetInput,
    pub lease_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginAdvisoryRequest {
    pub meta: RequestMeta,
    pub owner: SubjectId,
    pub workspace: WorkspaceId,
    pub base_snapshot: ObjectRef,
    pub target: TargetInput,
    pub lease_ticks: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndAdvisoryRequest {
    pub meta: RequestMeta,
    pub owner: SubjectId,
    pub workspace: WorkspaceId,
    pub proof: ClaimProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Acquire(AcquireRequest),
    Renew(RenewRequest),
    Release(ReleaseRequest),
    Transfer(TransferRequest),
    Break(BreakRequest),
    Expire(ExpiryRequest),
    Wait(WaitRequest),
    BeginAdvisory(BeginAdvisoryRequest),
    EndAdvisory(EndAdvisoryRequest),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelLimits {
    pub active_hard_locks: usize,
    pub active_advisory_intents: usize,
    pub wait_subscriptions: usize,
    pub notice_commitments: usize,
    pub idempotency_records: usize,
    pub event_commitments: usize,
    pub batch_requests: usize,
    pub submit_targets: usize,
    pub reason_bytes: usize,
    pub minimum_lease_ticks: u64,
    pub maximum_lease_ticks: u64,
}

impl Default for ModelLimits {
    fn default() -> Self {
        Self {
            active_hard_locks: ACTIVE_HARD_LOCKS_HARD_MAXIMUM,
            active_advisory_intents: ACTIVE_ADVISORY_INTENTS_HARD_MAXIMUM,
            wait_subscriptions: WAIT_SUBSCRIPTIONS_HARD_MAXIMUM,
            notice_commitments: NOTICE_COMMITMENTS_HARD_MAXIMUM,
            idempotency_records: IDEMPOTENCY_RECORDS_HARD_MAXIMUM,
            event_commitments: EVENT_COMMITMENTS_HARD_MAXIMUM,
            batch_requests: BATCH_REQUESTS_HARD_MAXIMUM,
            submit_targets: SUBMIT_TARGETS_HARD_MAXIMUM,
            reason_bytes: REASON_BYTES_HARD_MAXIMUM,
            minimum_lease_ticks: 1,
            maximum_lease_ticks: LEASE_TICKS_HARD_MAXIMUM,
        }
    }
}

impl ModelLimits {
    fn valid(self) -> bool {
        self.active_hard_locks > 0
            && self.active_hard_locks <= ACTIVE_HARD_LOCKS_HARD_MAXIMUM
            && self.active_advisory_intents > 0
            && self.active_advisory_intents <= ACTIVE_ADVISORY_INTENTS_HARD_MAXIMUM
            && self.wait_subscriptions > 0
            && self.wait_subscriptions <= WAIT_SUBSCRIPTIONS_HARD_MAXIMUM
            && self.notice_commitments > 0
            && self.notice_commitments <= NOTICE_COMMITMENTS_HARD_MAXIMUM
            && self.idempotency_records > 0
            && self.idempotency_records <= IDEMPOTENCY_RECORDS_HARD_MAXIMUM
            && self.event_commitments > 0
            && self.event_commitments <= EVENT_COMMITMENTS_HARD_MAXIMUM
            && self.batch_requests > 0
            && self.batch_requests <= BATCH_REQUESTS_HARD_MAXIMUM
            && self.submit_targets > 0
            && self.submit_targets <= SUBMIT_TARGETS_HARD_MAXIMUM
            && self.reason_bytes > 0
            && self.reason_bytes <= REASON_BYTES_HARD_MAXIMUM
            && self.minimum_lease_ticks > 0
            && self.maximum_lease_ticks >= self.minimum_lease_ticks
            && self.maximum_lease_ticks <= LEASE_TICKS_HARD_MAXIMUM
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockModelConfig {
    pub scope: ScopeBinding,
    pub authority_epoch: u64,
    pub initial_server_time: u64,
    pub path_profile: PathProfile,
    pub case_mode: CaseMode,
    pub limits: ModelLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionControl {
    pub cancelled: bool,
    pub maximum_work_units: u64,
}

impl Default for TransitionControl {
    fn default() -> Self {
        Self {
            cancelled: false,
            maximum_work_units: WORK_UNITS_HARD_MAXIMUM,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionContext {
    pub authority_epoch: u64,
    pub server_time: u64,
    pub control: TransitionControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchError {
    EmptyBatch,
    BatchLimit,
    Cancelled,
    TimeRegressed,
    StaleAuthorityEpoch,
    WorkLimit,
    IdempotencyCapacity,
    EventCapacity,
    NoticeCapacity,
    ConflictingBatchKey,
    GenerationExhausted,
    InjectedBeforeCommit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum OutcomeClass {
    Granted = 1,
    GrantedAdvisoryPresent = 2,
    Renewed = 3,
    Released = 4,
    Transferred = 5,
    Broken = 6,
    ExpiryObserved = 7,
    Waiting = 8,
    Available = 9,
    AdvisoryRecorded = 10,
    AdvisoryRecordedWithOverlap = 11,
    AdvisoryEnded = 12,
    Conflict = 13,
    NotApplied = 14,
    StaleFence = 15,
    SuppliedFactRejected = 16,
    InvalidRequest = 17,
    CapacityReached = 18,
}

impl OutcomeClass {
    pub const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EventKind {
    Acquire = 1,
    Renew = 2,
    Release = 3,
    Transfer = 4,
    Break = 5,
    Expiry = 6,
    Wait = 7,
    WaitAvailable = 8,
    AdvisoryBegin = 9,
    AdvisoryEnd = 10,
    EpochPromoted = 11,
}

impl EventKind {
    const fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventCommitment {
    pub sequence: u64,
    pub kind: EventKind,
    pub outcome: OutcomeClass,
    pub previous_digest: Digest,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    pub operation: EventKind,
    pub outcome: OutcomeClass,
    pub request_digest: Digest,
    pub authority_epoch: u64,
    /// The supplied model time at which this immutable result was first
    /// recorded. On an idempotent replay this remains the original time; the
    /// enclosing `BatchReceipt::server_time` reports the later replay time.
    pub server_time: u64,
    pub claim_id: Option<ClaimId>,
    pub generation: Option<u64>,
    pub expires_at: Option<u64>,
    pub event_digest: Digest,
    pub digest: Digest,
}

impl OperationReceipt {
    pub fn claim_proof(&self) -> Option<ClaimProof> {
        Some(ClaimProof {
            claim_id: self.claim_id?,
            authority_epoch: self.authority_epoch,
            generation: self.generation?,
            receipt_digest: self.digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationResult {
    Recorded {
        receipt: OperationReceipt,
        replayed: bool,
    },
    KeyReuse,
}

impl OperationResult {
    pub const fn receipt(self) -> Option<OperationReceipt> {
        match self {
            Self::Recorded { receipt, .. } => Some(receipt),
            Self::KeyReuse => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    pub results: Vec<OperationResult>,
    pub authority_epoch: u64,
    pub server_time: u64,
    pub event_head: Digest,
    pub state_commitment: Digest,
    pub work_units: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailabilityNotice {
    pub wait_id: ClaimId,
    pub authority_epoch: u64,
    pub event_digest: Digest,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochPromotionReceipt {
    pub prior_epoch: u64,
    pub new_epoch: u64,
    pub server_time: u64,
    pub event_digest: Digest,
    pub digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultBoundary {
    PolicyDecision,
    LockMutation,
    MetadataCommit,
    EventPublication,
}

impl FaultBoundary {
    pub const fn registry_id(self) -> &'static str {
        match self {
            Self::PolicyDecision => "policy.decision",
            Self::LockMutation => "lock.mutation",
            Self::MetadataCommit => "metadata.commit",
            Self::EventPublication => "event.publish",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultAction {
    CrashBefore,
    CrashAfter,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultInjection {
    pub boundary: FaultBoundary,
    pub action: FaultAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyDisposition {
    Committed(BatchReceipt),
    AmbiguousAfterCommit {
        request_digests: Vec<Digest>,
        state_commitment: Digest,
    },
}

#[derive(Clone)]
struct HardLockRecord {
    claim_id: ClaimId,
    owner: SubjectId,
    workspace: WorkspaceId,
    base_snapshot: ObjectRef,
    target: NormalizedTarget,
    generation: u64,
    expires_at: u64,
    receipt_digest: Digest,
}

#[derive(Clone)]
struct AdvisoryRecord {
    claim_id: ClaimId,
    owner: SubjectId,
    workspace: WorkspaceId,
    base_snapshot: ObjectRef,
    target: NormalizedTarget,
    generation: u64,
    expires_at: u64,
    receipt_digest: Digest,
}

#[derive(Clone)]
struct WaitRecord {
    claim_id: ClaimId,
    subject: SubjectId,
    workspace: WorkspaceId,
    target: NormalizedTarget,
    generation: u64,
    expires_at: u64,
    receipt_digest: Digest,
}

#[derive(Clone, Copy)]
struct StoredResult {
    request_digest: Digest,
    receipt: OperationReceipt,
}

#[derive(Clone)]
pub struct LockModel {
    scope: ScopeBinding,
    authority_epoch: u64,
    server_time: u64,
    path_profile: PathProfile,
    case_mode: CaseMode,
    limits: ModelLimits,
    next_generation: u64,
    hard_locks: BTreeMap<ClaimId, HardLockRecord>,
    advisory: BTreeMap<ClaimId, AdvisoryRecord>,
    waits: BTreeMap<ClaimId, WaitRecord>,
    notices: Vec<AvailabilityNotice>,
    idempotency: BTreeMap<IdempotencyKey, StoredResult>,
    events: Vec<EventCommitment>,
}

#[derive(Clone, Copy)]
struct WorkCounter {
    used: u64,
    maximum: u64,
}

impl Command {
    fn bounded_raw_work(&self) -> Result<u64, ()> {
        let mut work = 1_u64;
        let target = match self {
            Self::Acquire(request) => Some(&request.target),
            Self::Wait(request) => Some(&request.target),
            Self::BeginAdvisory(request) => Some(&request.target),
            _ => None,
        };
        if let Some(target) = target {
            work = work
                .checked_add(bounded_target_input_work(target)?)
                .ok_or(())?;
        }
        let reason = match self {
            Self::Transfer(request) => Some(request.reason.as_str()),
            Self::Break(request) => Some(request.reason.as_str()),
            _ => None,
        };
        if let Some(reason) = reason {
            if reason.len() > REASON_BYTES_HARD_MAXIMUM + 1 {
                return Err(());
            }
            work = work.checked_add(reason.len() as u64).ok_or(())?;
        }
        Ok(work)
    }

    fn key(&self) -> IdempotencyKey {
        match self {
            Self::Acquire(request) => request.meta.idempotency_key,
            Self::Renew(request) => request.meta.idempotency_key,
            Self::Release(request) => request.meta.idempotency_key,
            Self::Transfer(request) => request.meta.idempotency_key,
            Self::Break(request) => request.meta.idempotency_key,
            Self::Expire(request) => request.idempotency_key,
            Self::Wait(request) => request.meta.idempotency_key,
            Self::BeginAdvisory(request) => request.meta.idempotency_key,
            Self::EndAdvisory(request) => request.meta.idempotency_key,
        }
    }

    fn scope(&self) -> ScopeBinding {
        match self {
            Self::Acquire(request) => request.meta.scope,
            Self::Renew(request) => request.meta.scope,
            Self::Release(request) => request.meta.scope,
            Self::Transfer(request) => request.meta.scope,
            Self::Break(request) => request.meta.scope,
            Self::Expire(request) => request.scope,
            Self::Wait(request) => request.meta.scope,
            Self::BeginAdvisory(request) => request.meta.scope,
            Self::EndAdvisory(request) => request.meta.scope,
        }
    }

    fn kind(&self) -> EventKind {
        match self {
            Self::Acquire(_) => EventKind::Acquire,
            Self::Renew(_) => EventKind::Renew,
            Self::Release(_) => EventKind::Release,
            Self::Transfer(_) => EventKind::Transfer,
            Self::Break(_) => EventKind::Break,
            Self::Expire(_) => EventKind::Expiry,
            Self::Wait(_) => EventKind::Wait,
            Self::BeginAdvisory(_) => EventKind::AdvisoryBegin,
            Self::EndAdvisory(_) => EventKind::AdvisoryEnd,
        }
    }

    pub fn commitment(&self) -> Digest {
        if self.bounded_raw_work().is_err() {
            let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-OVERSIZE-REQUEST-V1");
            digest.u16(self.kind().code());
            digest.fixed(self.key().as_bytes());
            digest.fixed(&self.scope().commitment());
            match self {
                Self::Acquire(request) => digest.u64(request.target.expansion.members.len() as u64),
                Self::Wait(request) => digest.u64(request.target.expansion.members.len() as u64),
                Self::BeginAdvisory(request) => {
                    digest.u64(request.target.expansion.members.len() as u64)
                }
                Self::Transfer(request) => digest.u64(request.reason.len() as u64),
                Self::Break(request) => digest.u64(request.reason.len() as u64),
                _ => digest.u64(0),
            }
            return digest.finish();
        }
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-REQUEST-V1");
        digest.u16(self.kind().code());
        digest.fixed(self.key().as_bytes());
        digest.fixed(&self.scope().commitment());
        match self {
            Self::Acquire(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.owner.as_bytes());
                digest.fixed(request.workspace.as_bytes());
                digest_object(&mut digest, request.base_snapshot);
                digest.fixed(&digest_target_input(&request.target));
                digest.u64(request.lease_ticks);
            }
            Self::Renew(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.owner.as_bytes());
                digest.fixed(request.workspace.as_bytes());
                digest_proof(&mut digest, request.proof);
                digest.u64(request.lease_ticks);
            }
            Self::Release(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.owner.as_bytes());
                digest.fixed(request.workspace.as_bytes());
                digest_proof(&mut digest, request.proof);
            }
            Self::Transfer(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.owner.as_bytes());
                digest.fixed(request.from_workspace.as_bytes());
                digest.fixed(request.to_workspace.as_bytes());
                digest_proof(&mut digest, request.proof);
                digest.u64(request.lease_ticks);
                digest.bytes(request.reason.as_bytes());
            }
            Self::Break(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.actor.as_bytes());
                digest.fixed(request.selector.claim_id.as_bytes());
                digest.u64(request.selector.authority_epoch);
                digest.u64(request.selector.generation);
                digest.bytes(request.reason.as_bytes());
            }
            Self::Expire(_) => {}
            Self::Wait(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.subject.as_bytes());
                digest.fixed(request.workspace.as_bytes());
                digest.fixed(&digest_target_input(&request.target));
                digest.u64(request.lease_ticks);
            }
            Self::BeginAdvisory(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.owner.as_bytes());
                digest.fixed(request.workspace.as_bytes());
                digest_object(&mut digest, request.base_snapshot);
                digest.fixed(&digest_target_input(&request.target));
                digest.u64(request.lease_ticks);
            }
            Self::EndAdvisory(request) => {
                digest_meta(&mut digest, &request.meta);
                digest.fixed(request.owner.as_bytes());
                digest.fixed(request.workspace.as_bytes());
                digest_proof(&mut digest, request.proof);
            }
        }
        digest.finish()
    }
}

fn digest_meta(digest: &mut DigestBuilder, meta: &RequestMeta) {
    digest.fixed(&meta.permission.digest());
}

fn digest_object(digest: &mut DigestBuilder, object: ObjectRef) {
    digest.u16(object.kind.code());
    digest.fixed(&object.digest);
}

fn digest_proof(digest: &mut DigestBuilder, proof: ClaimProof) {
    digest.fixed(proof.claim_id.as_bytes());
    digest.u64(proof.authority_epoch);
    digest.u64(proof.generation);
    digest.fixed(&proof.receipt_digest);
}

impl LockModel {
    pub fn new(config: LockModelConfig) -> Result<Self, ModelError> {
        if config.authority_epoch == 0
            || config.scope.domain_digest == [0; 32]
            || !config.limits.valid()
        {
            return Err(ModelError::InvalidConfiguration);
        }
        Ok(Self {
            scope: config.scope,
            authority_epoch: config.authority_epoch,
            server_time: config.initial_server_time,
            path_profile: config.path_profile,
            case_mode: config.case_mode,
            limits: config.limits,
            next_generation: 1,
            hard_locks: BTreeMap::new(),
            advisory: BTreeMap::new(),
            waits: BTreeMap::new(),
            notices: Vec::new(),
            idempotency: BTreeMap::new(),
            events: Vec::new(),
        })
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn server_time(&self) -> u64 {
        self.server_time
    }

    pub fn active_hard_lock_count(&self) -> usize {
        self.hard_locks.len()
    }

    pub fn active_advisory_count(&self) -> usize {
        self.advisory.len()
    }

    pub fn wait_subscription_count(&self) -> usize {
        self.waits.len()
    }

    pub fn events(&self) -> &[EventCommitment] {
        &self.events
    }

    pub fn notices(&self) -> &[AvailabilityNotice] {
        &self.notices
    }

    pub fn event_head(&self) -> Digest {
        self.events.last().map_or([0; 32], |event| event.digest)
    }

    fn configuration_commitment(&self) -> Digest {
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-CONFIGURATION-V1");
        digest.bytes(self.path_profile.as_str().as_bytes());
        digest.bytes(self.case_mode.as_str().as_bytes());
        digest.u64(self.limits.active_hard_locks as u64);
        digest.u64(self.limits.active_advisory_intents as u64);
        digest.u64(self.limits.wait_subscriptions as u64);
        digest.u64(self.limits.notice_commitments as u64);
        digest.u64(self.limits.idempotency_records as u64);
        digest.u64(self.limits.event_commitments as u64);
        digest.u64(self.limits.batch_requests as u64);
        digest.u64(self.limits.submit_targets as u64);
        digest.u64(self.limits.reason_bytes as u64);
        digest.u64(self.limits.minimum_lease_ticks);
        digest.u64(self.limits.maximum_lease_ticks);
        digest.finish()
    }

    pub fn state_commitment(&self) -> Digest {
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-STATE-V1");
        digest.u16(MODEL_VERSION);
        digest.fixed(&self.scope.commitment());
        digest.fixed(&self.configuration_commitment());
        digest.u64(self.authority_epoch);
        digest.u64(self.server_time);
        digest.u64(self.next_generation);
        digest.u64(self.hard_locks.len() as u64);
        for record in self.hard_locks.values() {
            digest_lock_record(&mut digest, record);
        }
        digest.u64(self.advisory.len() as u64);
        for record in self.advisory.values() {
            digest.fixed(record.claim_id.as_bytes());
            digest.fixed(record.owner.as_bytes());
            digest.fixed(record.workspace.as_bytes());
            digest_object(&mut digest, record.base_snapshot);
            digest.fixed(record.target.digest());
            digest.u64(record.generation);
            digest.u64(record.expires_at);
            digest.fixed(&record.receipt_digest);
        }
        digest.u64(self.waits.len() as u64);
        for record in self.waits.values() {
            digest.fixed(record.claim_id.as_bytes());
            digest.fixed(record.subject.as_bytes());
            digest.fixed(record.workspace.as_bytes());
            digest.fixed(record.target.digest());
            digest.u64(record.generation);
            digest.u64(record.expires_at);
            digest.fixed(&record.receipt_digest);
        }
        digest.u64(self.notices.len() as u64);
        for notice in &self.notices {
            digest.fixed(notice.wait_id.as_bytes());
            digest.u64(notice.authority_epoch);
            digest.fixed(&notice.event_digest);
            digest.fixed(&notice.digest);
        }
        digest.u64(self.idempotency.len() as u64);
        for (key, stored) in &self.idempotency {
            digest.fixed(key.as_bytes());
            digest.fixed(&stored.request_digest);
            digest.fixed(&stored.receipt.digest);
        }
        digest.u64(self.events.len() as u64);
        digest.fixed(&self.event_head());
        digest.finish()
    }

    pub fn apply_batch(
        &mut self,
        context: TransitionContext,
        commands: Vec<Command>,
    ) -> Result<BatchReceipt, BatchError> {
        self.apply_batch_inner(context, &commands)
    }

    pub fn apply_batch_with_fault(
        &mut self,
        context: TransitionContext,
        commands: Vec<Command>,
        fault: FaultInjection,
    ) -> Result<ApplyDisposition, BatchError> {
        if matches!(
            fault.boundary,
            FaultBoundary::PolicyDecision | FaultBoundary::LockMutation
        ) || (fault.boundary == FaultBoundary::MetadataCommit
            && matches!(fault.action, FaultAction::CrashBefore | FaultAction::Error))
        {
            return Err(BatchError::InjectedBeforeCommit);
        }
        let receipt = self.apply_batch_inner(context, &commands)?;
        // `apply_batch_inner` has now admitted the bounded batch and every raw
        // request shape. Computing ambiguity commitments after that admission
        // prevents the fault-only adapter from bypassing normal batch/work
        // ceilings on a request that could never commit.
        let request_digests = commands.iter().map(Command::commitment).collect::<Vec<_>>();
        if fault.boundary == FaultBoundary::MetadataCommit
            || fault.boundary == FaultBoundary::EventPublication
        {
            return Ok(ApplyDisposition::AmbiguousAfterCommit {
                request_digests,
                state_commitment: receipt.state_commitment,
            });
        }
        Ok(ApplyDisposition::Committed(receipt))
    }

    fn apply_batch_inner(
        &mut self,
        context: TransitionContext,
        commands: &[Command],
    ) -> Result<BatchReceipt, BatchError> {
        if commands.is_empty() {
            return Err(BatchError::EmptyBatch);
        }
        if commands.len() > self.limits.batch_requests {
            return Err(BatchError::BatchLimit);
        }
        if context.control.cancelled {
            return Err(BatchError::Cancelled);
        }
        if context.control.maximum_work_units == 0
            || context.control.maximum_work_units > WORK_UNITS_HARD_MAXIMUM
        {
            return Err(BatchError::WorkLimit);
        }
        if context.server_time < self.server_time {
            return Err(BatchError::TimeRegressed);
        }
        if context.authority_epoch != self.authority_epoch {
            return Err(BatchError::StaleAuthorityEpoch);
        }

        let mut raw_work = 0_u64;
        for command in commands {
            raw_work = raw_work
                .checked_add(
                    command
                        .bounded_raw_work()
                        .map_err(|_| BatchError::WorkLimit)?,
                )
                .ok_or(BatchError::WorkLimit)?;
            if raw_work > context.control.maximum_work_units {
                return Err(BatchError::WorkLimit);
            }
        }

        let request_digests = commands.iter().map(Command::commitment).collect::<Vec<_>>();
        let mut groups = BTreeMap::<IdempotencyKey, Vec<usize>>::new();
        for (index, command) in commands.iter().enumerate() {
            groups.entry(command.key()).or_default().push(index);
        }
        for indexes in groups.values() {
            if indexes
                .iter()
                .map(|index| request_digests[*index])
                .collect::<BTreeSet<_>>()
                .len()
                != 1
            {
                return Err(BatchError::ConflictingBatchKey);
            }
        }

        let new_keys = groups
            .keys()
            .filter(|key| !self.idempotency.contains_key(key))
            .count();
        if self.idempotency.len().saturating_add(new_keys) > self.limits.idempotency_records {
            return Err(BatchError::IdempotencyCapacity);
        }

        let mut candidate = self.clone();
        candidate.server_time = context.server_time;
        let mut work = WorkCounter {
            used: raw_work,
            maximum: context.control.maximum_work_units,
        };
        candidate.expire_due(&mut work)?;

        let mut ordered = groups
            .iter()
            .map(|(key, indexes)| (*key, indexes[0], request_digests[indexes[0]]))
            .collect::<Vec<_>>();
        ordered.sort_by_key(|(key, _, digest)| (*digest, *key));
        let mut results = vec![OperationResult::KeyReuse; commands.len()];

        for (key, representative, request_digest) in ordered {
            let indexes = &groups[&key];
            if let Some(stored) = candidate.idempotency.get(&key).copied() {
                let result = if stored.request_digest == request_digest {
                    OperationResult::Recorded {
                        receipt: stored.receipt,
                        replayed: true,
                    }
                } else {
                    OperationResult::KeyReuse
                };
                for index in indexes {
                    results[*index] = result;
                }
                continue;
            }

            let receipt =
                candidate.process_command(&commands[representative], request_digest, &mut work)?;
            candidate.idempotency.insert(
                key,
                StoredResult {
                    request_digest,
                    receipt,
                },
            );
            for index in indexes {
                results[*index] = OperationResult::Recorded {
                    receipt,
                    replayed: false,
                };
            }
        }

        let receipt = BatchReceipt {
            results,
            authority_epoch: candidate.authority_epoch,
            server_time: candidate.server_time,
            event_head: candidate.event_head(),
            state_commitment: candidate.state_commitment(),
            work_units: work.used,
        };
        *self = candidate;
        Ok(receipt)
    }
}

fn digest_lock_record(digest: &mut DigestBuilder, record: &HardLockRecord) {
    digest.fixed(record.claim_id.as_bytes());
    digest.fixed(record.owner.as_bytes());
    digest.fixed(record.workspace.as_bytes());
    digest_object(digest, record.base_snapshot);
    digest.fixed(record.target.digest());
    digest.u64(record.generation);
    digest.u64(record.expires_at);
    digest.fixed(&record.receipt_digest);
}

impl LockModel {
    fn process_command(
        &mut self,
        command: &Command,
        request_digest: Digest,
        work: &mut WorkCounter,
    ) -> Result<OperationReceipt, BatchError> {
        work.charge(1)?;
        if command.scope() != self.scope {
            return self.record_receipt(
                command.kind(),
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        match command {
            Command::Acquire(request) => self.acquire(request, request_digest, work),
            Command::Renew(request) => self.renew(request, request_digest),
            Command::Release(request) => self.release(request, request_digest, work),
            Command::Transfer(request) => self.transfer(request, request_digest),
            Command::Break(request) => self.break_lock(request, request_digest, work),
            Command::Expire(_) => self.record_receipt(
                EventKind::Expiry,
                OutcomeClass::ExpiryObserved,
                request_digest,
                None,
                None,
                None,
            ),
            Command::Wait(request) => self.wait(request, request_digest, work),
            Command::BeginAdvisory(request) => self.begin_advisory(request, request_digest, work),
            Command::EndAdvisory(request) => self.end_advisory(request, request_digest),
        }
    }

    fn acquire(
        &mut self,
        request: &AcquireRequest,
        request_digest: Digest,
        work: &mut WorkCounter,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.owner,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::Acquire,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        if !self.valid_lease(request.lease_ticks)
            || request.base_snapshot.kind != ObjectKind::Snapshot
        {
            return self.record_receipt(
                EventKind::Acquire,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(target) = self.normalized_target(&request.target, work)? else {
            return self.record_receipt(
                EventKind::Acquire,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        };
        if self.any_hard_overlap(&target, work)? {
            return self.record_receipt(
                EventKind::Acquire,
                OutcomeClass::Conflict,
                request_digest,
                None,
                None,
                None,
            );
        }
        if self.hard_locks.len() >= self.limits.active_hard_locks {
            return self.record_receipt(
                EventKind::Acquire,
                OutcomeClass::CapacityReached,
                request_digest,
                None,
                None,
                None,
            );
        }
        let advisory_present = self.any_advisory_overlap(&target, work)?;
        let generation = self.allocate_generation()?;
        let expires_at = self
            .server_time
            .checked_add(request.lease_ticks)
            .ok_or(BatchError::GenerationExhausted)?;
        let claim_id = self.allocate_claim_id(EventKind::Acquire, request_digest, generation)?;
        self.hard_locks.insert(
            claim_id,
            HardLockRecord {
                claim_id,
                owner: request.owner,
                workspace: request.workspace,
                base_snapshot: request.base_snapshot,
                target,
                generation,
                expires_at,
                receipt_digest: [0; 32],
            },
        );
        let outcome = if advisory_present {
            OutcomeClass::GrantedAdvisoryPresent
        } else {
            OutcomeClass::Granted
        };
        let receipt = self.record_receipt(
            EventKind::Acquire,
            outcome,
            request_digest,
            Some(claim_id),
            Some(generation),
            Some(expires_at),
        )?;
        if let Some(record) = self.hard_locks.get_mut(&claim_id) {
            record.receipt_digest = receipt.digest;
        }
        Ok(receipt)
    }

    fn renew(
        &mut self,
        request: &RenewRequest,
        request_digest: Digest,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.owner,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::Renew,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        if !self.valid_lease(request.lease_ticks) {
            return self.record_receipt(
                EventKind::Renew,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(record) = self.hard_locks.get(&request.proof.claim_id).cloned() else {
            return self.record_receipt(
                EventKind::Renew,
                OutcomeClass::NotApplied,
                request_digest,
                None,
                None,
                None,
            );
        };
        if !hard_proof_matches(
            &record,
            request.owner,
            request.workspace,
            request.proof,
            self.authority_epoch,
        ) {
            return self.record_receipt(
                EventKind::Renew,
                OutcomeClass::StaleFence,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                Some(record.expires_at),
            );
        }
        let generation = self.allocate_generation()?;
        let expires_at = self
            .server_time
            .checked_add(request.lease_ticks)
            .ok_or(BatchError::GenerationExhausted)?;
        let receipt = self.record_receipt(
            EventKind::Renew,
            OutcomeClass::Renewed,
            request_digest,
            Some(record.claim_id),
            Some(generation),
            Some(expires_at),
        )?;
        if let Some(current) = self.hard_locks.get_mut(&record.claim_id) {
            current.generation = generation;
            current.expires_at = expires_at;
            current.receipt_digest = receipt.digest;
        }
        Ok(receipt)
    }

    fn release(
        &mut self,
        request: &ReleaseRequest,
        request_digest: Digest,
        work: &mut WorkCounter,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.owner,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::Release,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(record) = self.hard_locks.get(&request.proof.claim_id).cloned() else {
            return self.record_receipt(
                EventKind::Release,
                OutcomeClass::NotApplied,
                request_digest,
                None,
                None,
                None,
            );
        };
        if !hard_proof_matches(
            &record,
            request.owner,
            request.workspace,
            request.proof,
            self.authority_epoch,
        ) {
            return self.record_receipt(
                EventKind::Release,
                OutcomeClass::StaleFence,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                Some(record.expires_at),
            );
        }
        self.hard_locks.remove(&record.claim_id);
        let receipt = self.record_receipt(
            EventKind::Release,
            OutcomeClass::Released,
            request_digest,
            Some(record.claim_id),
            Some(record.generation),
            None,
        )?;
        self.notify_available_waiters(work)?;
        Ok(receipt)
    }

    fn transfer(
        &mut self,
        request: &TransferRequest,
        request_digest: Digest,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.owner,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::Transfer,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        if !self.valid_lease(request.lease_ticks)
            || !self.valid_reason(&request.reason)
            || request.from_workspace == request.to_workspace
        {
            return self.record_receipt(
                EventKind::Transfer,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(record) = self.hard_locks.get(&request.proof.claim_id).cloned() else {
            return self.record_receipt(
                EventKind::Transfer,
                OutcomeClass::NotApplied,
                request_digest,
                None,
                None,
                None,
            );
        };
        if !hard_proof_matches(
            &record,
            request.owner,
            request.from_workspace,
            request.proof,
            self.authority_epoch,
        ) {
            return self.record_receipt(
                EventKind::Transfer,
                OutcomeClass::StaleFence,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                Some(record.expires_at),
            );
        }
        let generation = self.allocate_generation()?;
        let expires_at = self
            .server_time
            .checked_add(request.lease_ticks)
            .ok_or(BatchError::GenerationExhausted)?;
        let receipt = self.record_receipt(
            EventKind::Transfer,
            OutcomeClass::Transferred,
            request_digest,
            Some(record.claim_id),
            Some(generation),
            Some(expires_at),
        )?;
        if let Some(current) = self.hard_locks.get_mut(&record.claim_id) {
            current.workspace = request.to_workspace;
            current.generation = generation;
            current.expires_at = expires_at;
            current.receipt_digest = receipt.digest;
        }
        Ok(receipt)
    }

    fn break_lock(
        &mut self,
        request: &BreakRequest,
        request_digest: Digest,
        work: &mut WorkCounter,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.actor,
            PermissionAssignment::LockForceUnlock,
        ) {
            return self.record_receipt(
                EventKind::Break,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        if !self.valid_reason(&request.reason) {
            return self.record_receipt(
                EventKind::Break,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(record) = self.hard_locks.get(&request.selector.claim_id).cloned() else {
            return self.record_receipt(
                EventKind::Break,
                OutcomeClass::NotApplied,
                request_digest,
                None,
                None,
                None,
            );
        };
        if request.selector.authority_epoch != self.authority_epoch
            || request.selector.generation != record.generation
        {
            return self.record_receipt(
                EventKind::Break,
                OutcomeClass::StaleFence,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                Some(record.expires_at),
            );
        }
        self.hard_locks.remove(&record.claim_id);
        let receipt = self.record_receipt(
            EventKind::Break,
            OutcomeClass::Broken,
            request_digest,
            Some(record.claim_id),
            Some(record.generation),
            None,
        )?;
        self.notify_available_waiters(work)?;
        Ok(receipt)
    }

    fn wait(
        &mut self,
        request: &WaitRequest,
        request_digest: Digest,
        work: &mut WorkCounter,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.subject,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::Wait,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        if !self.valid_lease(request.lease_ticks) {
            return self.record_receipt(
                EventKind::Wait,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(target) = self.normalized_target(&request.target, work)? else {
            return self.record_receipt(
                EventKind::Wait,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        };
        if !self.any_hard_overlap(&target, work)? {
            return self.record_receipt(
                EventKind::Wait,
                OutcomeClass::Available,
                request_digest,
                None,
                None,
                None,
            );
        }
        if self.waits.len() >= self.limits.wait_subscriptions {
            return self.record_receipt(
                EventKind::Wait,
                OutcomeClass::CapacityReached,
                request_digest,
                None,
                None,
                None,
            );
        }
        let generation = self.allocate_generation()?;
        let expires_at = self
            .server_time
            .checked_add(request.lease_ticks)
            .ok_or(BatchError::GenerationExhausted)?;
        let claim_id = self.allocate_claim_id(EventKind::Wait, request_digest, generation)?;
        self.waits.insert(
            claim_id,
            WaitRecord {
                claim_id,
                subject: request.subject,
                workspace: request.workspace,
                target,
                generation,
                expires_at,
                receipt_digest: [0; 32],
            },
        );
        let receipt = self.record_receipt(
            EventKind::Wait,
            OutcomeClass::Waiting,
            request_digest,
            Some(claim_id),
            Some(generation),
            Some(expires_at),
        )?;
        if let Some(record) = self.waits.get_mut(&claim_id) {
            record.receipt_digest = receipt.digest;
        }
        Ok(receipt)
    }

    fn begin_advisory(
        &mut self,
        request: &BeginAdvisoryRequest,
        request_digest: Digest,
        work: &mut WorkCounter,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.owner,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::AdvisoryBegin,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        if !self.valid_lease(request.lease_ticks)
            || request.base_snapshot.kind != ObjectKind::Snapshot
        {
            return self.record_receipt(
                EventKind::AdvisoryBegin,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(target) = self.normalized_target(&request.target, work)? else {
            return self.record_receipt(
                EventKind::AdvisoryBegin,
                OutcomeClass::InvalidRequest,
                request_digest,
                None,
                None,
                None,
            );
        };
        if self.advisory.len() >= self.limits.active_advisory_intents {
            return self.record_receipt(
                EventKind::AdvisoryBegin,
                OutcomeClass::CapacityReached,
                request_digest,
                None,
                None,
                None,
            );
        }
        let overlap =
            self.any_hard_overlap(&target, work)? || self.any_advisory_overlap(&target, work)?;
        let generation = self.allocate_generation()?;
        let expires_at = self
            .server_time
            .checked_add(request.lease_ticks)
            .ok_or(BatchError::GenerationExhausted)?;
        let claim_id =
            self.allocate_claim_id(EventKind::AdvisoryBegin, request_digest, generation)?;
        self.advisory.insert(
            claim_id,
            AdvisoryRecord {
                claim_id,
                owner: request.owner,
                workspace: request.workspace,
                base_snapshot: request.base_snapshot,
                target,
                generation,
                expires_at,
                receipt_digest: [0; 32],
            },
        );
        let outcome = if overlap {
            OutcomeClass::AdvisoryRecordedWithOverlap
        } else {
            OutcomeClass::AdvisoryRecorded
        };
        let receipt = self.record_receipt(
            EventKind::AdvisoryBegin,
            outcome,
            request_digest,
            Some(claim_id),
            Some(generation),
            Some(expires_at),
        )?;
        if let Some(record) = self.advisory.get_mut(&claim_id) {
            record.receipt_digest = receipt.digest;
        }
        Ok(receipt)
    }

    fn end_advisory(
        &mut self,
        request: &EndAdvisoryRequest,
        request_digest: Digest,
    ) -> Result<OperationReceipt, BatchError> {
        if !self.permission_valid(
            &request.meta,
            request.owner,
            PermissionAssignment::LockCreate,
        ) {
            return self.record_receipt(
                EventKind::AdvisoryEnd,
                OutcomeClass::SuppliedFactRejected,
                request_digest,
                None,
                None,
                None,
            );
        }
        let Some(record) = self.advisory.get(&request.proof.claim_id).cloned() else {
            return self.record_receipt(
                EventKind::AdvisoryEnd,
                OutcomeClass::NotApplied,
                request_digest,
                None,
                None,
                None,
            );
        };
        if !advisory_proof_matches(
            &record,
            request.owner,
            request.workspace,
            request.proof,
            self.authority_epoch,
        ) {
            return self.record_receipt(
                EventKind::AdvisoryEnd,
                OutcomeClass::StaleFence,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                Some(record.expires_at),
            );
        }
        self.advisory.remove(&record.claim_id);
        self.record_receipt(
            EventKind::AdvisoryEnd,
            OutcomeClass::AdvisoryEnded,
            request_digest,
            Some(record.claim_id),
            Some(record.generation),
            None,
        )
    }

    fn normalized_target(
        &self,
        input: &TargetInput,
        work: &mut WorkCounter,
    ) -> Result<Option<NormalizedTarget>, BatchError> {
        work.charge(1_u64.saturating_add(input.expansion.members.len() as u64))?;
        Ok(normalize_target(input, self.path_profile, self.case_mode).ok())
    }

    fn any_hard_overlap(
        &self,
        target: &NormalizedTarget,
        work: &mut WorkCounter,
    ) -> Result<bool, BatchError> {
        for record in self.hard_locks.values() {
            work.charge(target.overlap_work(&record.target))?;
            if target.overlaps(&record.target) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn any_advisory_overlap(
        &self,
        target: &NormalizedTarget,
        work: &mut WorkCounter,
    ) -> Result<bool, BatchError> {
        for record in self.advisory.values() {
            work.charge(target.overlap_work(&record.target))?;
            if target.overlaps(&record.target) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn permission_valid(
        &self,
        meta: &RequestMeta,
        subject: SubjectId,
        assignment: PermissionAssignment,
    ) -> bool {
        meta.scope == self.scope
            && meta.permission.permission == assignment
            && meta.permission.decision == SuppliedDecision::Affirmed
            && meta.permission.authority_epoch == self.authority_epoch
            && meta.permission.policy_generation > 0
            && meta.permission.subject == subject
            && meta.permission.scope_commitment == self.scope.commitment()
            && meta.permission.decision_digest != [0; 32]
    }

    fn valid_lease(&self, lease_ticks: u64) -> bool {
        lease_ticks >= self.limits.minimum_lease_ticks
            && lease_ticks <= self.limits.maximum_lease_ticks
    }

    fn valid_reason(&self, reason: &str) -> bool {
        !reason.trim().is_empty() && reason.len() <= self.limits.reason_bytes
    }

    fn allocate_generation(&mut self) -> Result<u64, BatchError> {
        let generation = self.next_generation;
        if generation == 0 {
            return Err(BatchError::GenerationExhausted);
        }
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(BatchError::GenerationExhausted)?;
        Ok(generation)
    }

    fn allocate_claim_id(
        &self,
        kind: EventKind,
        request_digest: Digest,
        generation: u64,
    ) -> Result<ClaimId, BatchError> {
        let kind_bytes = kind.code().to_be_bytes();
        let epoch_bytes = self.authority_epoch.to_be_bytes();
        let generation_bytes = generation.to_be_bytes();
        let configuration = self.configuration_commitment();
        let value = digest16(
            b"OGVCS-PRIVATE-LOCK-CLAIM-ID-V1",
            &[
                &kind_bytes,
                &self.scope.commitment(),
                &configuration,
                &epoch_bytes,
                &generation_bytes,
                &request_digest,
            ],
        );
        let claim_id = ClaimId::new(value).map_err(|_| BatchError::GenerationExhausted)?;
        if self.hard_locks.contains_key(&claim_id)
            || self.advisory.contains_key(&claim_id)
            || self.waits.contains_key(&claim_id)
        {
            return Err(BatchError::GenerationExhausted);
        }
        Ok(claim_id)
    }

    fn record_receipt(
        &mut self,
        kind: EventKind,
        outcome: OutcomeClass,
        request_digest: Digest,
        claim_id: Option<ClaimId>,
        generation: Option<u64>,
        expires_at: Option<u64>,
    ) -> Result<OperationReceipt, BatchError> {
        let event = self.append_event(
            kind,
            outcome,
            request_digest,
            claim_id,
            generation,
            expires_at,
        )?;
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-RECEIPT-V1");
        digest.u16(MODEL_VERSION);
        digest.u16(kind.code());
        digest.u16(outcome.code());
        digest.fixed(&request_digest);
        digest.fixed(&self.scope.commitment());
        digest.fixed(&self.configuration_commitment());
        digest.u64(self.authority_epoch);
        digest.u64(self.server_time);
        digest.optional_fixed(claim_id.as_ref().map(|value| value.as_bytes().as_slice()));
        digest.boolean(generation.is_some());
        if let Some(value) = generation {
            digest.u64(value);
        }
        digest.boolean(expires_at.is_some());
        if let Some(value) = expires_at {
            digest.u64(value);
        }
        digest.fixed(&event.digest);
        let receipt_digest = digest.finish();
        Ok(OperationReceipt {
            operation: kind,
            outcome,
            request_digest,
            authority_epoch: self.authority_epoch,
            server_time: self.server_time,
            claim_id,
            generation,
            expires_at,
            event_digest: event.digest,
            digest: receipt_digest,
        })
    }

    fn append_event(
        &mut self,
        kind: EventKind,
        outcome: OutcomeClass,
        request_digest: Digest,
        claim_id: Option<ClaimId>,
        generation: Option<u64>,
        expires_at: Option<u64>,
    ) -> Result<EventCommitment, BatchError> {
        if self.events.len() >= self.limits.event_commitments {
            return Err(BatchError::EventCapacity);
        }
        let sequence = (self.events.len() as u64)
            .checked_add(1)
            .ok_or(BatchError::EventCapacity)?;
        let previous_digest = self.event_head();
        let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-EVENT-V1");
        digest.u16(MODEL_VERSION);
        digest.u64(sequence);
        digest.u16(kind.code());
        digest.u16(outcome.code());
        digest.fixed(&previous_digest);
        digest.fixed(&self.scope.commitment());
        digest.fixed(&self.configuration_commitment());
        digest.u64(self.authority_epoch);
        digest.u64(self.server_time);
        digest.fixed(&request_digest);
        digest.optional_fixed(claim_id.as_ref().map(|value| value.as_bytes().as_slice()));
        digest.boolean(generation.is_some());
        if let Some(value) = generation {
            digest.u64(value);
        }
        digest.boolean(expires_at.is_some());
        if let Some(value) = expires_at {
            digest.u64(value);
        }
        let event = EventCommitment {
            sequence,
            kind,
            outcome,
            previous_digest,
            digest: digest.finish(),
        };
        self.events.push(event);
        Ok(event)
    }
}

fn hard_proof_matches(
    record: &HardLockRecord,
    owner: SubjectId,
    workspace: WorkspaceId,
    proof: ClaimProof,
    authority_epoch: u64,
) -> bool {
    record.owner == owner
        && record.workspace == workspace
        && proof.claim_id == record.claim_id
        && proof.authority_epoch == authority_epoch
        && proof.generation == record.generation
        && proof.receipt_digest == record.receipt_digest
}

fn advisory_proof_matches(
    record: &AdvisoryRecord,
    owner: SubjectId,
    workspace: WorkspaceId,
    proof: ClaimProof,
    authority_epoch: u64,
) -> bool {
    record.owner == owner
        && record.workspace == workspace
        && proof.claim_id == record.claim_id
        && proof.authority_epoch == authority_epoch
        && proof.generation == record.generation
        && proof.receipt_digest == record.receipt_digest
}

impl LockModel {
    fn expire_due(&mut self, work: &mut WorkCounter) -> Result<(), BatchError> {
        let expired_waits = self
            .waits
            .iter()
            .filter_map(|(claim_id, record)| {
                (record.expires_at <= self.server_time).then_some(*claim_id)
            })
            .collect::<Vec<_>>();
        for claim_id in expired_waits {
            work.charge(1)?;
            let record = self
                .waits
                .remove(&claim_id)
                .expect("collected wait claim remains present");
            let request_digest = expiry_digest(
                b"wait",
                record.claim_id,
                record.generation,
                record.receipt_digest,
                record.target.digest(),
                self.server_time,
            );
            self.append_event(
                EventKind::Expiry,
                OutcomeClass::ExpiryObserved,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                None,
            )?;
        }

        let expired_advisory = self
            .advisory
            .iter()
            .filter_map(|(claim_id, record)| {
                (record.expires_at <= self.server_time).then_some(*claim_id)
            })
            .collect::<Vec<_>>();
        for claim_id in expired_advisory {
            work.charge(1)?;
            let record = self
                .advisory
                .remove(&claim_id)
                .expect("collected advisory claim remains present");
            let request_digest = expiry_digest(
                b"advisory",
                record.claim_id,
                record.generation,
                record.receipt_digest,
                record.target.digest(),
                self.server_time,
            );
            self.append_event(
                EventKind::Expiry,
                OutcomeClass::ExpiryObserved,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                None,
            )?;
        }

        let expired_hard = self
            .hard_locks
            .iter()
            .filter_map(|(claim_id, record)| {
                (record.expires_at <= self.server_time).then_some(*claim_id)
            })
            .collect::<Vec<_>>();
        let had_expired_hard = !expired_hard.is_empty();
        for claim_id in expired_hard {
            work.charge(1)?;
            let record = self
                .hard_locks
                .remove(&claim_id)
                .expect("collected hard-lock claim remains present");
            let request_digest = expiry_digest(
                b"hard",
                record.claim_id,
                record.generation,
                record.receipt_digest,
                record.target.digest(),
                self.server_time,
            );
            self.append_event(
                EventKind::Expiry,
                OutcomeClass::ExpiryObserved,
                request_digest,
                Some(record.claim_id),
                Some(record.generation),
                None,
            )?;
        }
        if had_expired_hard {
            self.notify_available_waiters(work)?;
        }
        Ok(())
    }

    fn notify_available_waiters(&mut self, work: &mut WorkCounter) -> Result<(), BatchError> {
        let wait_ids = self.waits.keys().copied().collect::<Vec<_>>();
        for wait_id in wait_ids {
            let Some(record) = self.waits.get(&wait_id).cloned() else {
                continue;
            };
            let mut blocked = false;
            for hard in self.hard_locks.values() {
                work.charge(record.target.overlap_work(&hard.target))?;
                if record.target.overlaps(&hard.target) {
                    blocked = true;
                    break;
                }
            }
            if blocked {
                continue;
            }
            if self.notices.len() >= self.limits.notice_commitments {
                return Err(BatchError::NoticeCapacity);
            }
            self.waits.remove(&wait_id);
            let mut request = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-WAIT-AVAILABLE-V1");
            request.fixed(wait_id.as_bytes());
            request.fixed(record.subject.as_bytes());
            request.fixed(record.workspace.as_bytes());
            request.fixed(record.target.digest());
            request.u64(record.generation);
            request.fixed(&record.receipt_digest);
            request.u64(self.authority_epoch);
            request.u64(self.server_time);
            let event = self.append_event(
                EventKind::WaitAvailable,
                OutcomeClass::Available,
                request.finish(),
                Some(wait_id),
                Some(record.generation),
                None,
            )?;
            let mut notice_digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-NOTICE-V1");
            notice_digest.fixed(wait_id.as_bytes());
            notice_digest.u64(self.authority_epoch);
            notice_digest.fixed(&event.digest);
            self.notices.push(AvailabilityNotice {
                wait_id,
                authority_epoch: self.authority_epoch,
                event_digest: event.digest,
                digest: notice_digest.finish(),
            });
        }
        Ok(())
    }

    pub fn promote_epoch(
        &mut self,
        new_epoch: u64,
        server_time: u64,
        control: TransitionControl,
    ) -> Result<EpochPromotionReceipt, BatchError> {
        if control.cancelled {
            return Err(BatchError::Cancelled);
        }
        if control.maximum_work_units == 0 || control.maximum_work_units > WORK_UNITS_HARD_MAXIMUM {
            return Err(BatchError::WorkLimit);
        }
        if server_time < self.server_time {
            return Err(BatchError::TimeRegressed);
        }
        if new_epoch <= self.authority_epoch {
            return Err(BatchError::StaleAuthorityEpoch);
        }
        let mut candidate = self.clone();
        candidate.server_time = server_time;
        let mut work = WorkCounter {
            used: 0,
            maximum: control.maximum_work_units,
        };
        let prior_epoch = candidate.authority_epoch;

        let waits = candidate.waits.values().cloned().collect::<Vec<_>>();
        let advisory = candidate.advisory.values().cloned().collect::<Vec<_>>();
        let hard_locks = candidate.hard_locks.values().cloned().collect::<Vec<_>>();
        for (label, claim_id, generation, receipt_digest, target_digest) in waits
            .iter()
            .map(|record| {
                (
                    b"wait".as_slice(),
                    record.claim_id,
                    record.generation,
                    record.receipt_digest,
                    *record.target.digest(),
                )
            })
            .chain(advisory.iter().map(|record| {
                (
                    b"advisory".as_slice(),
                    record.claim_id,
                    record.generation,
                    record.receipt_digest,
                    *record.target.digest(),
                )
            }))
            .chain(hard_locks.iter().map(|record| {
                (
                    b"hard".as_slice(),
                    record.claim_id,
                    record.generation,
                    record.receipt_digest,
                    *record.target.digest(),
                )
            }))
        {
            work.charge(1)?;
            let request_digest = expiry_digest(
                label,
                claim_id,
                generation,
                receipt_digest,
                &target_digest,
                server_time,
            );
            candidate.append_event(
                EventKind::Expiry,
                OutcomeClass::ExpiryObserved,
                request_digest,
                Some(claim_id),
                Some(generation),
                None,
            )?;
        }
        candidate.hard_locks.clear();
        candidate.advisory.clear();
        candidate.waits.clear();
        candidate.notices.clear();
        candidate.idempotency.clear();
        candidate.authority_epoch = new_epoch;

        work.charge(1)?;
        let mut request = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-EPOCH-PROMOTION-V1");
        request.fixed(&candidate.scope.commitment());
        request.u64(prior_epoch);
        request.u64(new_epoch);
        request.u64(server_time);
        let event = candidate.append_event(
            EventKind::EpochPromoted,
            OutcomeClass::ExpiryObserved,
            request.finish(),
            None,
            None,
            None,
        )?;
        let mut receipt = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-EPOCH-RECEIPT-V1");
        receipt.fixed(&candidate.scope.commitment());
        receipt.u64(prior_epoch);
        receipt.u64(new_epoch);
        receipt.u64(server_time);
        receipt.fixed(&event.digest);
        let result = EpochPromotionReceipt {
            prior_epoch,
            new_epoch,
            server_time,
            event_digest: event.digest,
            digest: receipt.finish(),
        };
        *self = candidate;
        Ok(result)
    }
}

fn expiry_digest(
    class: &[u8],
    claim_id: ClaimId,
    generation: u64,
    receipt_digest: Digest,
    target_digest: &Digest,
    server_time: u64,
) -> Digest {
    let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-NATURAL-EXPIRY-V1");
    digest.bytes(class);
    digest.fixed(claim_id.as_bytes());
    digest.u64(generation);
    digest.fixed(&receipt_digest);
    digest.fixed(target_digest);
    digest.u64(server_time);
    digest.finish()
}

impl WorkCounter {
    fn charge(&mut self, amount: u64) -> Result<(), BatchError> {
        let next = self.used.checked_add(amount).ok_or(BatchError::WorkLimit)?;
        if next > self.maximum {
            return Err(BatchError::WorkLimit);
        }
        self.used = next;
        Ok(())
    }
}
