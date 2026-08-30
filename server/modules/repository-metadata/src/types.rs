use ogvcs_object_model::{FileId, ObjectRef};
use serde_json::Value;
use std::time::SystemTime;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_id!(TenantId);
opaque_id!(RepositoryId);
opaque_id!(ProjectId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CommitSequence(u64);

impl CommitSequence {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseMode {
    CaseSensitive,
    CaseFolded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySettings {
    pub repository_format: String,
    pub required_features: Vec<u16>,
    pub case_mode: CaseMode,
    pub path_profile: String,
    pub platform_profile: String,
    pub content_policy_profile: String,
    pub structural_limits: Value,
    pub tenant_boundary: TenantId,
}

impl RepositorySettings {
    pub fn has_sorted_unique_features(&self) -> bool {
        self.required_features
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceKind {
    Branch,
    Tag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceName(String);

impl ReferenceName {
    pub fn new(value: String) -> Option<Self> {
        let length = value.len();
        (length > 0 && length <= 512 && !value.contains('\0')).then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceExpected {
    Absent,
    Present { target: ObjectRef, generation: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCasRequest {
    pub repository_id: RepositoryId,
    pub kind: ReferenceKind,
    pub name: ReferenceName,
    pub expected: ReferenceExpected,
    pub desired: Option<ObjectRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCasResult {
    pub prior: Option<ObjectRef>,
    pub current: Option<ObjectRef>,
    pub generation: u64,
    pub commit_sequence: CommitSequence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceRecord {
    pub kind: ReferenceKind,
    pub name: ReferenceName,
    pub target: ObjectRef,
    pub generation: u64,
    pub commit_sequence: CommitSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdOrigin {
    Create,
    Copy,
    Restore,
    Import,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdOwnerKind {
    Published,
    Draft,
    Shelf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdReservation {
    pub repository_id: RepositoryId,
    pub file_id: FileId,
    pub origin: FileIdOrigin,
    pub owner_kind: FileIdOwnerKind,
    pub owner_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdImportReservation {
    pub reservation: FileIdReservation,
    pub importer_profile: String,
    pub source_namespace_digest: [u8; 32],
    pub source_identity_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdReservationOutcome {
    Reserved,
    ExactImportReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdExpectedState {
    Reserved,
    Active,
}

impl FileIdExpectedState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectPutOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectWrite<'a> {
    pub repository_id: RepositoryId,
    pub object_ref: &'a ObjectRef,
    pub canonical_bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryCreate<'a> {
    pub repository_id: RepositoryId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub settings: RepositorySettings,
    pub descriptor: ObjectWrite<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntryWrite {
    pub repository_id: RepositoryId,
    pub tree: ObjectRef,
    pub ordinal: u32,
    pub basename_utf8: Vec<u8>,
    pub file_id: FileId,
    pub entry_kind: u16,
    pub target: ObjectRef,
    pub logical_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotWrite {
    pub repository_id: RepositoryId,
    pub snapshot: ObjectRef,
    pub root_tree: ObjectRef,
    pub parents: Vec<ObjectRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileHistoryWrite {
    pub repository_id: RepositoryId,
    pub snapshot: ObjectRef,
    pub operation_ordinal: u32,
    pub file_id: FileId,
    pub repository_path_utf8: Vec<u8>,
    pub operation_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsistencyToken(String);

impl ConsistencyToken {
    pub fn from_opaque(value: String) -> Option<Self> {
        let payload = value.strip_prefix("ct1.")?;
        (payload.len() == 43
            && payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
        .then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorToken(String);

impl CursorToken {
    pub fn from_opaque(value: String) -> Option<Self> {
        let payload = value.strip_prefix("cur1.")?;
        (payload.len() == 43
            && payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
        .then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub subject_digest: [u8; 32],
    pub tenant_id: TenantId,
    pub authorization_epoch: u64,
}

/// Canonical OGVCS-009 permissions consumed by repository metadata.  Callers
/// cannot invent adapter-specific permission strings at the database boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataPermission {
    Discover,
    MetadataRead,
    Submit,
    ServiceInternal,
}

impl MetadataPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::MetadataRead => "metadata.read",
            Self::Submit => "submit",
            Self::ServiceInternal => "service-internal",
        }
    }
}

/// Exact resource projection that an authorization decision must cover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationResource {
    Repository {
        repository_id: RepositoryId,
    },
    RepositoryTransaction {
        repository_id: RepositoryId,
        capability: TransactionCapability,
    },
    Reference {
        repository_id: RepositoryId,
        kind: ReferenceKind,
        name: ReferenceName,
    },
    ReferenceCollection {
        repository_id: RepositoryId,
    },
    TreePrefix {
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        tree: ObjectRef,
        prefix: Vec<String>,
    },
    TreeEntry {
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        tree: ObjectRef,
        repository_path: Vec<String>,
        file_id: FileId,
    },
    FileHistory {
        repository_id: RepositoryId,
        file_id: FileId,
    },
    FileHistoryEntry {
        repository_id: RepositoryId,
        file_id: FileId,
        snapshot: ObjectRef,
        repository_path_utf8: Vec<u8>,
    },
    OutboxCollection {
        tenant_id: TenantId,
    },
    OutboxDeliveryEvent {
        tenant_id: TenantId,
        event_id: [u8; 16],
    },
}

impl AuthorizationResource {
    pub const fn repository_id(&self) -> Option<RepositoryId> {
        match self {
            Self::Repository { repository_id }
            | Self::RepositoryTransaction { repository_id, .. }
            | Self::Reference { repository_id, .. }
            | Self::ReferenceCollection { repository_id }
            | Self::TreePrefix { repository_id, .. }
            | Self::TreeEntry { repository_id, .. }
            | Self::FileHistory { repository_id, .. }
            | Self::FileHistoryEntry { repository_id, .. } => Some(*repository_id),
            Self::OutboxCollection { .. } | Self::OutboxDeliveryEvent { .. } => None,
        }
    }
}

impl AuthorizationResource {
    pub const fn tenant_id(&self) -> Option<TenantId> {
        match self {
            Self::OutboxCollection { tenant_id } | Self::OutboxDeliveryEvent { tenant_id, .. } => {
                Some(*tenant_id)
            }
            _ => None,
        }
    }
}

/// Operation-level capability fixed when the transaction is opened.  All
/// mutation capabilities authorize through the canonical `submit` permission,
/// then restrict the methods usable on the returned transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionCapability {
    CreateRepository,
    PutObject,
    Publish,
    ReserveFileId,
    ImportFileId,
    RestoreFileId,
    TombstoneFileId,
    CompareAndSwapReference,
    IssueConsistencyToken,
}

impl TransactionCapability {
    pub const fn permission(self) -> MetadataPermission {
        match self {
            Self::IssueConsistencyToken => MetadataPermission::MetadataRead,
            Self::CreateRepository
            | Self::PutObject
            | Self::Publish
            | Self::ReserveFileId
            | Self::ImportFileId
            | Self::RestoreFileId
            | Self::TombstoneFileId
            | Self::CompareAndSwapReference => MetadataPermission::Submit,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateRepository => "repository.create",
            Self::PutObject => "object.put",
            Self::Publish => "repository.publish",
            Self::ReserveFileId => "file-id.register",
            Self::ImportFileId => "file-id.register-import",
            Self::RestoreFileId => "file-id.restore-proof",
            Self::TombstoneFileId => "file-id.tombstone",
            Self::CompareAndSwapReference => "reference.compare-and-swap",
            Self::IssueConsistencyToken => "consistency.issue-token",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionOptions {
    RepeatableRead,
    Serializable { maximum_retries: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEvent {
    pub event_id: [u8; 16],
    pub repository_id: RepositoryId,
    pub correlation_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxClaimRequest {
    pub consumer_id: String,
    pub maximum_items: u16,
    pub lease_seconds: u16,
}

impl OutboxClaimRequest {
    pub fn is_bounded(&self) -> bool {
        valid_consumer_id(&self.consumer_id)
            && self.maximum_items <= 1_000
            && self.lease_seconds <= 3_600
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxLeaseAction {
    pub consumer_id: String,
    pub event_id: [u8; 16],
    pub lease_id: [u8; 16],
}

impl OutboxLeaseAction {
    pub fn is_valid(&self) -> bool {
        valid_consumer_id(&self.consumer_id)
            && valid_public_uuid(&self.event_id)
            && valid_public_uuid(&self.lease_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxReleaseRequest {
    pub lease: OutboxLeaseAction,
    pub retry_after_seconds: u32,
}

impl OutboxReleaseRequest {
    pub fn is_bounded(&self) -> bool {
        self.lease.is_valid() && self.retry_after_seconds <= 86_400
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEventRecord {
    pub event_id: [u8; 16],
    pub event_type: String,
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub commit_sequence: CommitSequence,
    pub correlation_id: [u8; 16],
    pub resource_type: String,
    pub resource_opaque_id: String,
    pub safe_payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxLeaseRecord {
    pub lease_id: [u8; 16],
    pub consumer_id: String,
    pub lease_expires_at: SystemTime,
    pub delivery_attempt: u32,
    pub event: OutboxEventRecord,
}

fn valid_consumer_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.contains('\0')
}

fn valid_public_uuid(value: &[u8; 16]) -> bool {
    let version = value[6] >> 4;
    let variant = value[8] >> 6;
    (1..=8).contains(&version) && variant == 0b10
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyReservation {
    pub operation: String,
    pub key: String,
    pub semantic_fingerprint: [u8; 32],
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
}

impl IdempotencyReservation {
    pub fn is_valid(&self) -> bool {
        self.is_valid_at(SystemTime::now())
    }

    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        if now.duration_since(self.issued_at).is_err() {
            return false;
        }
        let Ok(remaining) = self.expires_at.duration_since(now) else {
            return false;
        };
        if remaining.is_zero() {
            return false;
        }
        let Some(issued_ms) = self
            .issued_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        else {
            return false;
        };
        let Some(expires_ms) = self
            .expires_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        else {
            return false;
        };
        if expires_ms <= issued_ms || expires_ms - issued_ms > 86_400_000 {
            return false;
        }
        let mut parts = self.key.split('.');
        let valid_number = |text: &str| {
            !text.is_empty()
                && text.len() <= 16
                && (text == "0" || !text.starts_with('0'))
                && text.bytes().all(|byte| byte.is_ascii_digit())
        };
        let prefix = parts.next();
        let issued = parts.next();
        let expires = parts.next();
        let entropy = parts.next();
        prefix == Some("ik1")
            && parts.next().is_none()
            && issued.is_some_and(valid_number)
            && expires.is_some_and(valid_number)
            && issued.and_then(|value| value.parse().ok()) == Some(issued_ms)
            && expires.and_then(|value| value.parse().ok()) == Some(expires_ms)
            && entropy.is_some_and(|value| {
                (22..=218).contains(&value.len())
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            })
            && (30..=256).contains(&self.key.len())
            && !self.operation.is_empty()
            && self.operation.len() <= 128
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyReservationOutcome {
    Reserved,
    CommittedReplay(Value),
    KeyReuseRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    pub limit: u16,
    pub cursor: Option<CursorToken>,
}

impl PageRequest {
    pub fn is_bounded(&self) -> bool {
        (1..=1000).contains(&self.limit)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<CursorToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntryRecord {
    pub ordinal: u32,
    pub basename_utf8: Vec<u8>,
    pub file_id: FileId,
    pub entry_kind: u16,
    pub target: ObjectRef,
    pub logical_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileHistoryRecord {
    pub snapshot: ObjectRef,
    pub operation_ordinal: u32,
    pub file_id: FileId,
    pub repository_path_utf8: Vec<u8>,
    pub operation_kind: String,
}
