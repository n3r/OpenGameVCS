use std::collections::BTreeSet;

pub use ogvcs_object_model::FileId;
use ogvcs_path_contract::{
    repository_path_key, repository_prefix, RepositoryPathKey, RepositoryPrefix,
};
pub use ogvcs_path_contract::{CaseMode, PathProfile};

use crate::client_hello::DecodedClientHello;
use crate::commitment::{CommitmentBuilder, Digest32};

pub const RAW_INPUT_BYTES_MAXIMUM: usize = 1_048_576;
pub const COLLECTION_ITEMS_MAXIMUM: usize = 256;
pub const VERSION_ITEMS_MAXIMUM: usize = 32;
pub const CAPABILITY_ITEMS_MAXIMUM: usize = 16;
pub const PATH_SELECTORS_MAXIMUM: usize = 256;
pub const STATUS_ITEMS_MAXIMUM: usize = 256;
pub const EVENT_PAGE_ITEMS_MAXIMUM: usize = 64;
pub const EVENT_QUEUE_ITEMS_MAXIMUM: usize = 256;
pub const WORK_UNITS_MAXIMUM: usize = 131_072;
pub const RETAINED_LOGICAL_BYTES_MAXIMUM: usize = 4_194_304;
pub const RETAINED_RECORDS_MAXIMUM: usize = 4_096;
pub const SESSION_RECORDS_MAXIMUM: usize = 256;
pub const CONSENT_RECORDS_MAXIMUM: usize = 256;
pub const REPLAY_RECORDS_MAXIMUM: usize = 1_024;
pub const IDEMPOTENCY_RECORDS_MAXIMUM: usize = 1_024;
pub const SUBSCRIPTION_RECORDS_MAXIMUM: usize = 64;
pub const HANDOFF_RECORDS_MAXIMUM: usize = 256;
pub const SESSION_TTL_MAXIMUM_MS: u64 = 300_000;
pub const CONSENT_TTL_MAXIMUM_MS: u64 = 86_400_000;
pub const IDEMPOTENCY_TTL_MAXIMUM_MS: u64 = 86_400_000;
pub const SUBSCRIPTION_TTL_MAXIMUM_MS: u64 = 3_600_000;
pub const CURSOR_TTL_MAXIMUM_MS: u64 = 300_000;
pub const HANDOFF_TTL_MAXIMUM_MS: u64 = 120_000;
pub const FRESHNESS_AGE_MAXIMUM_MS: u64 = 30_000;
pub const FRESHNESS_FUTURE_MAXIMUM_MS: u64 = 30_000;
pub const DEADLINE_HORIZON_MAXIMUM_MS: u64 = 300_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Cancelled,
    InputTooLarge,
    FrameInvalid,
    ItemLimit,
    WorkLimit,
    RetainedLimit,
    StateLimit,
    InvalidFact,
    InvalidIdentity,
    PathInvalid,
    BaselineMismatch,
    UnsupportedVersion,
    RequiredCapabilityUnavailable,
    EndpointUnverified,
    TranscriptUnverified,
    ReplayRejected,
    StaleGeneration,
    TimeOverflow,
    TimeReordered,
    NotYetValid,
    Expired,
    DeadlineExceeded,
    SessionUnknown,
    ConsentUnknown,
    ConsentRevoked,
    CapabilityDenied,
    ScopeDenied,
    StaleState,
    IdempotencyConflict,
    QueueFull,
    CursorInvalid,
    CursorExpired,
    CursorGap,
    SequenceInvalid,
    LockFactInvalid,
    HandoffUnverified,
    HandoffUsed,
    InvariantViolation,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "CANCELLED",
            Self::InputTooLarge => "INPUT_TOO_LARGE",
            Self::FrameInvalid => "FRAME_INVALID",
            Self::ItemLimit => "ITEM_LIMIT",
            Self::WorkLimit => "WORK_LIMIT",
            Self::RetainedLimit => "RETAINED_LIMIT",
            Self::StateLimit => "STATE_LIMIT",
            Self::InvalidFact => "INVALID_FACT",
            Self::InvalidIdentity => "INVALID_IDENTITY",
            Self::PathInvalid => "PATH_INVALID",
            Self::BaselineMismatch => "BASELINE_MISMATCH",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::RequiredCapabilityUnavailable => "REQUIRED_CAPABILITY_UNAVAILABLE",
            Self::EndpointUnverified => "ENDPOINT_UNVERIFIED",
            Self::TranscriptUnverified => "TRANSCRIPT_UNVERIFIED",
            Self::ReplayRejected => "REPLAY_REJECTED",
            Self::StaleGeneration => "STALE_GENERATION",
            Self::TimeOverflow => "TIME_OVERFLOW",
            Self::TimeReordered => "TIME_REORDERED",
            Self::NotYetValid => "NOT_YET_VALID",
            Self::Expired => "EXPIRED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::SessionUnknown => "SESSION_UNKNOWN",
            Self::ConsentUnknown => "CONSENT_UNKNOWN",
            Self::ConsentRevoked => "CONSENT_REVOKED",
            Self::CapabilityDenied => "CAPABILITY_DENIED",
            Self::ScopeDenied => "SCOPE_DENIED",
            Self::StaleState => "STALE_STATE",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::QueueFull => "QUEUE_FULL",
            Self::CursorInvalid => "CURSOR_INVALID",
            Self::CursorExpired => "CURSOR_EXPIRED",
            Self::CursorGap => "CURSOR_GAP",
            Self::SequenceInvalid => "SEQUENCE_INVALID",
            Self::LockFactInvalid => "LOCK_FACT_INVALID",
            Self::HandoffUnverified => "HANDOFF_UNVERIFIED",
            Self::HandoffUsed => "HANDOFF_USED",
            Self::InvariantViolation => "INVARIANT_VIOLATION",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    code: ErrorCode,
}

impl Error {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> ErrorCode {
        self.code
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationPoint {
    Preflight,
    BeforeCommit,
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
        point == self.0
    }
}

pub struct RawFrame<'a> {
    bytes: &'a [u8],
}

impl<'a> RawFrame<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn commitment(&self) -> Result<Digest32> {
        validate_raw_frame(self)
    }
}

pub(crate) fn validate_raw_frame(raw: &RawFrame<'_>) -> Result<Digest32> {
    if raw.len() > RAW_INPUT_BYTES_MAXIMUM {
        return Err(Error::new(ErrorCode::InputTooLarge));
    }
    let mut builder = CommitmentBuilder::new("raw-frame-v1");
    builder.bytes(raw.bytes);
    Ok(builder.finish())
}

pub(crate) fn check_cancel(
    cancellation: &dyn CancellationProbe,
    point: CancellationPoint,
) -> Result<()> {
    if cancellation.cancelled(point) {
        Err(Error::new(ErrorCode::Cancelled))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkBudget {
    used: usize,
}

impl WorkBudget {
    pub(crate) const fn new() -> Self {
        Self { used: 0 }
    }

    pub(crate) fn charge(&mut self, amount: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(amount)
            .ok_or_else(|| Error::new(ErrorCode::WorkLimit))?;
        if self.used > WORK_UNITS_MAXIMUM {
            return Err(Error::new(ErrorCode::WorkLimit));
        }
        Ok(())
    }

    pub(crate) fn product(&mut self, left: usize, right: usize) -> Result<()> {
        let amount = left
            .checked_mul(right)
            .ok_or_else(|| Error::new(ErrorCode::WorkLimit))?;
        self.charge(amount)
    }
}

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Digest32);

        impl $name {
            pub const fn new(value: Digest32) -> Self {
                Self(value)
            }

            pub const fn digest(self) -> Digest32 {
                self.0
            }
        }
    };
}

digest_type!(EndpointId);
digest_type!(InstallationId);
digest_type!(IntegrationId);
digest_type!(SessionId);
digest_type!(ConsentId);
digest_type!(WorkspaceId);
digest_type!(RepositoryId);
digest_type!(IdempotencyKey);
digest_type!(SubscriptionId);
digest_type!(EventId);
digest_type!(HandoffId);
digest_type!(TrustedClientId);
digest_type!(AssetGroupCommitment);
digest_type!(BaselineCommitment);
digest_type!(StateCommitment);
digest_type!(LockProofCommitment);
digest_type!(ConfirmationCommitment);

pub(crate) fn require_digest(value: Digest32) -> Result<()> {
    if value.is_zero() {
        Err(Error::new(ErrorCode::InvalidIdentity))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    ReadStatus,
    SyncMaterialize,
    StartEditLockFact,
    CheckpointHandoff,
    RevertHandoff,
    JobProgress,
    WorkspaceEvents,
    TrustedClientHandoff,
}

impl Capability {
    pub const fn code(self) -> u8 {
        match self {
            Self::ReadStatus => 1,
            Self::SyncMaterialize => 2,
            Self::StartEditLockFact => 3,
            Self::CheckpointHandoff => 4,
            Self::RevertHandoff => 5,
            Self::JobProgress => 6,
            Self::WorkspaceEvents => 7,
            Self::TrustedClientHandoff => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationOffer {
    pub versions: Vec<ProtocolVersion>,
    pub required_capabilities: Vec<Capability>,
    pub optional_capabilities: Vec<Capability>,
    pub public_protocol_manifest: Digest32,
}

impl NegotiationOffer {
    pub fn commitment(&self) -> Result<Digest32> {
        let (versions, required, optional) = validate_offer(self)?;
        let mut builder = CommitmentBuilder::new("negotiation-offer-v1");
        builder.digest(self.public_protocol_manifest);
        builder.usize(versions.len());
        for version in versions {
            builder.u16(version.major);
            builder.u16(version.minor);
        }
        builder.usize(required.len());
        for capability in required {
            builder.u8(capability.code());
        }
        builder.usize(optional.len());
        for capability in optional {
            builder.u8(capability.code());
        }
        Ok(builder.finish())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationSelection {
    pub version: ProtocolVersion,
    pub capabilities: Vec<Capability>,
    pub public_protocol_manifest: Digest32,
    pub client_offer_commitment: Digest32,
    pub agent_offer_commitment: Digest32,
    pub raw_frame_commitment: Digest32,
    pub selection_commitment: Digest32,
}

pub fn public_protocol_manifest_commitment() -> Result<Digest32> {
    Digest32::from_lower_hex(opengamevcs_protocol_v1::CONTRACT_MANIFEST_SHA256)
        .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))
}

pub(crate) fn negotiate_bound(
    client: &NegotiationOffer,
    agent: &NegotiationOffer,
    raw_frame_commitment: Digest32,
) -> Result<NegotiationSelection> {
    let expected_manifest = public_protocol_manifest_commitment()?;
    if client.public_protocol_manifest != expected_manifest
        || agent.public_protocol_manifest != expected_manifest
    {
        return Err(Error::new(ErrorCode::BaselineMismatch));
    }
    let (client_versions, client_required, client_optional) = validate_offer(client)?;
    let (agent_versions, agent_required, agent_optional) = validate_offer(agent)?;
    let mut work = WorkBudget::new();
    work.product(client_versions.len(), agent_versions.len())?;
    work.product(
        client_required.len() + client_optional.len(),
        agent_required.len() + agent_optional.len(),
    )?;
    let version = client_versions
        .iter()
        .rev()
        .find(|version| agent_versions.contains(version))
        .copied()
        .ok_or_else(|| Error::new(ErrorCode::UnsupportedVersion))?;

    let client_available: BTreeSet<_> = client_required
        .iter()
        .chain(client_optional.iter())
        .copied()
        .collect();
    let agent_available: BTreeSet<_> = agent_required
        .iter()
        .chain(agent_optional.iter())
        .copied()
        .collect();
    if !client_required.is_subset(&agent_available) || !agent_required.is_subset(&client_available)
    {
        return Err(Error::new(ErrorCode::RequiredCapabilityUnavailable));
    }
    let capabilities: Vec<_> = client_available
        .intersection(&agent_available)
        .copied()
        .collect();
    let client_offer_commitment = client.commitment()?;
    let agent_offer_commitment = agent.commitment()?;
    let mut builder = CommitmentBuilder::new("negotiation-selection-v1");
    builder.u16(version.major);
    builder.u16(version.minor);
    builder.digest(expected_manifest);
    builder.digest(client_offer_commitment);
    builder.digest(agent_offer_commitment);
    builder.digest(raw_frame_commitment);
    builder.usize(capabilities.len());
    for capability in &capabilities {
        builder.u8(capability.code());
    }
    let selection_commitment = builder.finish();
    Ok(NegotiationSelection {
        version,
        capabilities,
        public_protocol_manifest: expected_manifest,
        client_offer_commitment,
        agent_offer_commitment,
        raw_frame_commitment,
        selection_commitment,
    })
}

fn validate_offer(
    offer: &NegotiationOffer,
) -> Result<(
    BTreeSet<ProtocolVersion>,
    BTreeSet<Capability>,
    BTreeSet<Capability>,
)> {
    if offer.versions.is_empty() {
        return Err(Error::new(ErrorCode::UnsupportedVersion));
    }
    if offer.versions.len() > VERSION_ITEMS_MAXIMUM
        || offer.required_capabilities.len() > CAPABILITY_ITEMS_MAXIMUM
        || offer.optional_capabilities.len() > CAPABILITY_ITEMS_MAXIMUM
    {
        return Err(Error::new(ErrorCode::ItemLimit));
    }
    let versions: BTreeSet<_> = offer.versions.iter().copied().collect();
    let required: BTreeSet<_> = offer.required_capabilities.iter().copied().collect();
    let optional: BTreeSet<_> = offer.optional_capabilities.iter().copied().collect();
    if versions.len() != offer.versions.len()
        || required.len() != offer.required_capabilities.len()
        || optional.len() != offer.optional_capabilities.len()
        || !required.is_disjoint(&optional)
        || versions.iter().any(|version| version.major == 0)
    {
        return Err(Error::new(ErrorCode::InvalidFact));
    }
    Ok((versions, required, optional))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalVerdict {
    Verified,
    Rejected,
    NotEvaluated,
}

impl ExternalVerdict {
    pub const fn code(self) -> u8 {
        match self {
            Self::Verified => 1,
            Self::Rejected => 2,
            Self::NotEvaluated => 3,
        }
    }

    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallationIdentity {
    pub id: InstallationId,
    pub generation: u64,
    pub identity_commitment: Digest32,
}

impl InstallationIdentity {
    pub(crate) fn validate(&self) -> Result<()> {
        require_digest(self.id.digest())?;
        require_digest(self.identity_commitment)?;
        if self.generation == 0 {
            return Err(Error::new(ErrorCode::InvalidIdentity));
        }
        Ok(())
    }

    pub(crate) fn commit_into(&self, builder: &mut CommitmentBuilder) {
        builder.digest(self.id.digest());
        builder.u64(self.generation);
        builder.digest(self.identity_commitment);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointIdentity {
    pub id: EndpointId,
    pub installation_id: InstallationId,
    pub installation_generation: u64,
    pub endpoint_generation: u64,
    pub os_locality: ExternalVerdict,
    pub restrictive_access: ExternalVerdict,
    pub adapter_facts_commitment: Digest32,
}

impl EndpointIdentity {
    pub(crate) fn validate(&self) -> Result<()> {
        require_digest(self.id.digest())?;
        require_digest(self.installation_id.digest())?;
        require_digest(self.adapter_facts_commitment)?;
        if self.installation_generation == 0 || self.endpoint_generation == 0 {
            return Err(Error::new(ErrorCode::InvalidIdentity));
        }
        if !self.os_locality.is_verified() || !self.restrictive_access.is_verified() {
            return Err(Error::new(ErrorCode::EndpointUnverified));
        }
        Ok(())
    }

    pub(crate) fn commit_into(&self, builder: &mut CommitmentBuilder) {
        builder.digest(self.id.digest());
        builder.digest(self.installation_id.digest());
        builder.u64(self.installation_generation);
        builder.u64(self.endpoint_generation);
        builder.u8(self.os_locality.code());
        builder.u8(self.restrictive_access.code());
        builder.digest(self.adapter_facts_commitment);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationIdentity {
    pub id: IntegrationId,
    pub installation_id: InstallationId,
    pub manifest_commitment: Digest32,
    pub registration_generation: u64,
    pub external_registration: ExternalVerdict,
}

impl IntegrationIdentity {
    pub(crate) fn validate(&self) -> Result<()> {
        require_digest(self.id.digest())?;
        require_digest(self.installation_id.digest())?;
        require_digest(self.manifest_commitment)?;
        if self.registration_generation == 0 {
            return Err(Error::new(ErrorCode::InvalidIdentity));
        }
        if !self.external_registration.is_verified() {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        Ok(())
    }

    pub(crate) fn commit_into(&self, builder: &mut CommitmentBuilder) {
        builder.digest(self.id.digest());
        builder.digest(self.installation_id.digest());
        builder.digest(self.manifest_commitment);
        builder.u64(self.registration_generation);
        builder.u8(self.external_registration.code());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeContext {
    pub repository_id: RepositoryId,
    pub path_profile: PathProfile,
    pub case_mode: CaseMode,
}

impl ScopeContext {
    pub fn validate(self) -> Result<()> {
        require_digest(self.repository_id.digest())
    }

    fn commit_into(self, builder: &mut CommitmentBuilder) {
        builder.digest(self.repository_id.digest());
        builder.text(self.path_profile.as_str());
        builder.text(self.case_mode.as_str());
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedScopePath {
    context: ScopeContext,
    canonical: String,
    key: RepositoryPathKey,
}

impl std::fmt::Debug for ValidatedScopePath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedScopePath")
            .field("context", &self.context)
            .field("canonical", &"<redacted>")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl ValidatedScopePath {
    pub fn new(context: ScopeContext, path: &str) -> Result<Self> {
        context.validate()?;
        let key = repository_path_key(path, context.path_profile, context.case_mode)
            .map_err(|_| Error::new(ErrorCode::PathInvalid))?;
        Ok(Self {
            context,
            canonical: path.to_owned(),
            key,
        })
    }

    pub const fn context(&self) -> ScopeContext {
        self.context
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub(crate) fn key(&self) -> &RepositoryPathKey {
        &self.key
    }

    fn logical_bytes(&self) -> Result<usize> {
        96usize
            .checked_add(self.canonical.len())
            .and_then(|value| value.checked_add(self.key.as_str().len()))
            .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))
    }

    fn commit_into(&self, builder: &mut CommitmentBuilder) {
        self.context.commit_into(builder);
        builder.text(&self.canonical);
        builder.text(self.key.as_str());
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedScopePrefix {
    context: ScopeContext,
    canonical: String,
    prefix: RepositoryPrefix,
    non_root_key: Option<RepositoryPathKey>,
}

impl std::fmt::Debug for ValidatedScopePrefix {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedScopePrefix")
            .field("context", &self.context)
            .field("canonical", &"<redacted>")
            .field("range", &"<redacted>")
            .finish()
    }
}

impl ValidatedScopePrefix {
    pub fn new(context: ScopeContext, prefix: &str) -> Result<Self> {
        context.validate()?;
        let validated = repository_prefix(prefix, context.path_profile, context.case_mode)
            .map_err(|_| Error::new(ErrorCode::PathInvalid))?;
        let non_root_key = if prefix.is_empty() {
            None
        } else {
            Some(
                repository_path_key(prefix, context.path_profile, context.case_mode)
                    .map_err(|_| Error::new(ErrorCode::PathInvalid))?,
            )
        };
        Ok(Self {
            context,
            canonical: prefix.to_owned(),
            prefix: validated,
            non_root_key,
        })
    }

    pub const fn context(&self) -> ScopeContext {
        self.context
    }

    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    fn logical_bytes(&self) -> Result<usize> {
        let mut total = 128usize
            .checked_add(self.canonical.len())
            .and_then(|value| value.checked_add(self.prefix.lower_inclusive().len()))
            .and_then(|value| value.checked_add(self.prefix.upper_exclusive().len()))
            .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
        if let Some(key) = &self.non_root_key {
            total = total
                .checked_add(key.as_str().len())
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
        }
        Ok(total)
    }

    fn covers_path(&self, path: &ValidatedScopePath) -> bool {
        self.context == path.context && self.prefix.matches(path.key())
    }

    fn covers_prefix(&self, prefix: &Self) -> bool {
        if self.context != prefix.context {
            return false;
        }
        if self.canonical.is_empty() {
            return true;
        }
        prefix
            .non_root_key
            .as_ref()
            .is_some_and(|key| self.prefix.matches(key))
    }

    fn commit_into(&self, builder: &mut CommitmentBuilder) {
        self.context.commit_into(builder);
        builder.text(&self.canonical);
        builder.text(self.prefix.lower_inclusive());
        builder.text(self.prefix.upper_exclusive());
    }
}

#[derive(Clone, Copy)]
pub enum PathScopeInput<'a> {
    File(FileId),
    Exact(&'a str),
    Prefix(&'a str),
    AssetGroup(AssetGroupCommitment),
}

impl std::fmt::Debug for PathScopeInput<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::File(_) => "File",
            Self::Exact(_) => "Exact",
            Self::Prefix(_) => "Prefix",
            Self::AssetGroup(_) => "AssetGroup",
        };
        formatter.debug_tuple(kind).field(&"<redacted>").finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ScopeSelector {
    File(FileId),
    Exact(ValidatedScopePath),
    Prefix(ValidatedScopePrefix),
    AssetGroup(AssetGroupCommitment),
}

impl std::fmt::Debug for ScopeSelector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::File(_) => "File",
            Self::Exact(_) => "Exact",
            Self::Prefix(_) => "Prefix",
            Self::AssetGroup(_) => "AssetGroup",
        };
        formatter.debug_tuple(kind).field(&"<redacted>").finish()
    }
}

impl ScopeSelector {
    fn sort_key(&self) -> Vec<u8> {
        match self {
            Self::File(file_id) => {
                let mut key = Vec::with_capacity(17);
                key.push(1);
                key.extend_from_slice(file_id.as_bytes());
                key
            }
            Self::Exact(path) => {
                let mut key =
                    Vec::with_capacity(path.key.as_str().len() + path.canonical.len() + 2);
                key.push(2);
                key.extend_from_slice(path.key.as_str().as_bytes());
                key.push(0);
                key.extend_from_slice(path.canonical.as_bytes());
                key
            }
            Self::Prefix(prefix) => {
                let mut key = Vec::with_capacity(
                    prefix.prefix.lower_inclusive().len()
                        + prefix.prefix.upper_exclusive().len()
                        + prefix.canonical.len()
                        + 3,
                );
                key.push(3);
                key.extend_from_slice(prefix.prefix.lower_inclusive().as_bytes());
                key.push(0);
                key.extend_from_slice(prefix.prefix.upper_exclusive().as_bytes());
                key.push(0);
                key.extend_from_slice(prefix.canonical.as_bytes());
                key
            }
            Self::AssetGroup(group) => {
                let mut key = Vec::with_capacity(33);
                key.push(4);
                key.extend_from_slice(group.digest().as_bytes());
                key
            }
        }
    }

    fn semantically_equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(left), Self::File(right)) => left == right,
            (Self::Exact(left), Self::Exact(right)) => {
                left.context == right.context && left.key == right.key
            }
            (Self::Prefix(left), Self::Prefix(right)) => {
                left.context == right.context
                    && left.prefix.lower_inclusive() == right.prefix.lower_inclusive()
                    && left.prefix.upper_exclusive() == right.prefix.upper_exclusive()
            }
            (Self::AssetGroup(left), Self::AssetGroup(right)) => left == right,
            _ => false,
        }
    }

    fn logical_bytes(&self) -> Result<usize> {
        match self {
            Self::File(_) => Ok(17),
            Self::Exact(path) => path
                .logical_bytes()?
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge)),
            Self::Prefix(prefix) => prefix
                .logical_bytes()?
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge)),
            Self::AssetGroup(_) => Ok(33),
        }
    }

    fn commit_into(&self, builder: &mut CommitmentBuilder) {
        match self {
            Self::File(file_id) => {
                builder.u8(1);
                builder.bytes(file_id.as_bytes());
            }
            Self::Exact(path) => {
                builder.u8(2);
                path.commit_into(builder);
            }
            Self::Prefix(prefix) => {
                builder.u8(3);
                prefix.commit_into(builder);
            }
            Self::AssetGroup(group) => {
                builder.u8(4);
                builder.digest(group.digest());
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathScope {
    context: ScopeContext,
    selectors: Vec<ScopeSelector>,
    logical_bytes: usize,
    commitment: Digest32,
}

impl PathScope {
    pub fn new(
        context: ScopeContext,
        inputs: &[PathScopeInput<'_>],
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Self> {
        validate_raw_frame(raw)?;
        check_cancel(cancellation, CancellationPoint::Preflight)?;
        context.validate()?;
        if inputs.is_empty() || inputs.len() > PATH_SELECTORS_MAXIMUM {
            return Err(Error::new(ErrorCode::ItemLimit));
        }
        let mut work = WorkBudget::new();
        work.charge(inputs.len())?;
        work.product(inputs.len(), inputs.len())?;
        // Bound the caller-owned spellings before allocating canonical/key
        // strings for any selector. The exact retained-key accounting below
        // remains authoritative after OGVCS-004 validation and folding.
        let mut supplied_input_bytes = 96usize;
        for input in inputs {
            let minimum_logical_bytes = match input {
                PathScopeInput::File(_) => 17,
                PathScopeInput::Exact(path) => 97usize
                    .checked_add(path.len())
                    .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?,
                PathScopeInput::Prefix(prefix) => 129usize
                    .checked_add(prefix.len())
                    .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?,
                PathScopeInput::AssetGroup(_) => 33,
            };
            supplied_input_bytes = supplied_input_bytes
                .checked_add(minimum_logical_bytes)
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
            if supplied_input_bytes > RAW_INPUT_BYTES_MAXIMUM {
                return Err(Error::new(ErrorCode::InputTooLarge));
            }
        }
        let mut selectors = Vec::with_capacity(inputs.len());
        let mut supplied_logical_bytes = 96usize;
        for input in inputs {
            let selector = match input {
                PathScopeInput::File(file_id) => ScopeSelector::File(*file_id),
                PathScopeInput::Exact(path) => {
                    ScopeSelector::Exact(ValidatedScopePath::new(context, path)?)
                }
                PathScopeInput::Prefix(prefix) => {
                    ScopeSelector::Prefix(ValidatedScopePrefix::new(context, prefix)?)
                }
                PathScopeInput::AssetGroup(group) => {
                    require_digest(group.digest())?;
                    ScopeSelector::AssetGroup(*group)
                }
            };
            supplied_logical_bytes = supplied_logical_bytes
                .checked_add(selector.logical_bytes()?)
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
            if supplied_logical_bytes > RAW_INPUT_BYTES_MAXIMUM {
                return Err(Error::new(ErrorCode::InputTooLarge));
            }
            selectors.push(selector);
        }
        selectors.sort_by_key(ScopeSelector::sort_key);
        selectors.dedup_by(|left, right| left.semantically_equal(right));
        let snapshot = selectors.clone();
        selectors.retain(|candidate| {
            !snapshot.iter().any(|other| {
                if std::ptr::eq(candidate, other) || candidate == other {
                    return false;
                }
                match (candidate, other) {
                    (ScopeSelector::Exact(path), ScopeSelector::Prefix(prefix)) => {
                        prefix.covers_path(path)
                    }
                    (ScopeSelector::Prefix(prefix), ScopeSelector::Prefix(ancestor)) => {
                        ancestor.covers_prefix(prefix)
                    }
                    _ => false,
                }
            })
        });
        if selectors.is_empty() {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        let mut logical_bytes = 96usize;
        for selector in &selectors {
            logical_bytes = logical_bytes
                .checked_add(selector.logical_bytes()?)
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
        }
        if logical_bytes > RAW_INPUT_BYTES_MAXIMUM {
            return Err(Error::new(ErrorCode::InputTooLarge));
        }
        let mut builder = CommitmentBuilder::new("path-scope-v1");
        context.commit_into(&mut builder);
        builder.usize(selectors.len());
        for selector in &selectors {
            selector.commit_into(&mut builder);
        }
        let commitment = builder.finish();
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        Ok(Self {
            context,
            selectors,
            logical_bytes,
            commitment,
        })
    }

    pub const fn context(&self) -> ScopeContext {
        self.context
    }

    pub fn selectors(&self) -> &[ScopeSelector] {
        &self.selectors
    }

    pub fn selector_count(&self) -> usize {
        self.selectors.len()
    }

    pub const fn commitment(&self) -> Digest32 {
        self.commitment
    }

    pub fn is_narrower_than(&self, granted: &Self) -> Result<bool> {
        let mut work = WorkBudget::new();
        self.is_subset_of(granted, &mut work)
    }

    pub(crate) const fn logical_bytes(&self) -> usize {
        self.logical_bytes
    }

    pub(crate) fn is_subset_of(&self, granted: &Self, work: &mut WorkBudget) -> Result<bool> {
        if self.context != granted.context {
            return Ok(false);
        }
        work.product(self.selectors.len(), granted.selectors.len())?;
        Ok(self.selectors.iter().all(|requested| {
            granted
                .selectors
                .iter()
                .any(|grant| covers(grant, requested))
        }))
    }

    pub(crate) fn contains_status_item(
        &self,
        file_id: FileId,
        path: &ValidatedScopePath,
        work: &mut WorkBudget,
    ) -> Result<bool> {
        if self.context != path.context {
            return Ok(false);
        }
        work.charge(self.selectors.len())?;
        Ok(self.selectors.iter().any(|selector| match selector {
            ScopeSelector::File(candidate) => *candidate == file_id,
            ScopeSelector::Exact(exact) => exact.key == path.key,
            ScopeSelector::Prefix(prefix) => prefix.covers_path(path),
            _ => false,
        }))
    }
}

fn covers(grant: &ScopeSelector, requested: &ScopeSelector) -> bool {
    match (grant, requested) {
        (ScopeSelector::File(left), ScopeSelector::File(right)) => left == right,
        (ScopeSelector::AssetGroup(left), ScopeSelector::AssetGroup(right)) => left == right,
        (ScopeSelector::Exact(left), ScopeSelector::Exact(right)) => left.key == right.key,
        (ScopeSelector::Prefix(prefix), ScopeSelector::Exact(path)) => prefix.covers_path(path),
        (ScopeSelector::Prefix(left), ScopeSelector::Prefix(right)) => left.covers_prefix(right),
        _ => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshStateFacts {
    pub base: BaselineCommitment,
    pub current: StateCommitment,
    pub generation: u64,
    pub observed_at_ms: u64,
    pub valid_through_ms: u64,
}

impl FreshStateFacts {
    pub(crate) fn validate(&self, now_ms: u64) -> Result<()> {
        require_digest(self.base.digest())?;
        require_digest(self.current.digest())?;
        if self.generation == 0 {
            return Err(Error::new(ErrorCode::StaleState));
        }
        if self.observed_at_ms > now_ms {
            return Err(Error::new(ErrorCode::NotYetValid));
        }
        let age = now_ms
            .checked_sub(self.observed_at_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if age > FRESHNESS_AGE_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::StaleState));
        }
        if self.valid_through_ms < now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        let future = self
            .valid_through_ms
            .checked_sub(now_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if future > FRESHNESS_FUTURE_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        Ok(())
    }

    pub(crate) fn commit_into(&self, builder: &mut CommitmentBuilder) {
        builder.digest(self.base.digest());
        builder.digest(self.current.digest());
        builder.u64(self.generation);
        builder.u64(self.observed_at_ms);
        builder.u64(self.valid_through_ms);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockKnowledge {
    Granted {
        authority_epoch: u64,
        generation: u64,
        lease_expires_at_ms: u64,
        proof: LockProofCommitment,
    },
    Denied {
        decision_commitment: LockProofCommitment,
    },
    Lost {
        last_generation: u64,
        transition_commitment: LockProofCommitment,
    },
    Unknown {
        last_generation: Option<u64>,
        cause_commitment: LockProofCommitment,
    },
    Recoverable {
        last_generation: Option<u64>,
        recovery_commitment: LockProofCommitment,
    },
}

impl LockKnowledge {
    pub const fn state_code(&self) -> u8 {
        match self {
            Self::Granted { .. } => 1,
            Self::Denied { .. } => 2,
            Self::Lost { .. } => 3,
            Self::Unknown { .. } => 4,
            Self::Recoverable { .. } => 5,
        }
    }

    pub(crate) fn validate_shape(&self) -> Result<()> {
        match self {
            Self::Granted {
                authority_epoch,
                generation,
                proof,
                ..
            } => {
                require_digest(proof.digest())
                    .map_err(|_| Error::new(ErrorCode::LockFactInvalid))?;
                if *authority_epoch == 0 || *generation == 0 {
                    return Err(Error::new(ErrorCode::LockFactInvalid));
                }
            }
            Self::Denied {
                decision_commitment,
            } => require_digest(decision_commitment.digest())
                .map_err(|_| Error::new(ErrorCode::LockFactInvalid))?,
            Self::Lost {
                last_generation,
                transition_commitment,
            } => {
                require_digest(transition_commitment.digest())
                    .map_err(|_| Error::new(ErrorCode::LockFactInvalid))?;
                if *last_generation == 0 {
                    return Err(Error::new(ErrorCode::LockFactInvalid));
                }
            }
            Self::Unknown {
                last_generation,
                cause_commitment,
            }
            | Self::Recoverable {
                last_generation,
                recovery_commitment: cause_commitment,
            } => {
                require_digest(cause_commitment.digest())
                    .map_err(|_| Error::new(ErrorCode::LockFactInvalid))?;
                if last_generation == &Some(0) {
                    return Err(Error::new(ErrorCode::LockFactInvalid));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn validate_time(&self, now_ms: u64) -> Result<()> {
        if let Self::Granted {
            lease_expires_at_ms,
            ..
        } = self
        {
            if *lease_expires_at_ms <= now_ms {
                return Err(Error::new(ErrorCode::LockFactInvalid));
            }
        }
        Ok(())
    }

    pub(crate) fn validate(&self, now_ms: u64) -> Result<()> {
        self.validate_shape()?;
        self.validate_time(now_ms)
    }

    pub(crate) fn commit_into(&self, builder: &mut CommitmentBuilder) {
        builder.u8(self.state_code());
        match self {
            Self::Granted {
                authority_epoch,
                generation,
                lease_expires_at_ms,
                proof,
            } => {
                builder.u64(*authority_epoch);
                builder.u64(*generation);
                builder.u64(*lease_expires_at_ms);
                builder.digest(proof.digest());
            }
            Self::Denied {
                decision_commitment,
            } => builder.digest(decision_commitment.digest()),
            Self::Lost {
                last_generation,
                transition_commitment,
            } => {
                builder.u64(*last_generation);
                builder.digest(transition_commitment.digest());
            }
            Self::Unknown {
                last_generation,
                cause_commitment,
            } => {
                commit_optional_u64(builder, *last_generation);
                builder.digest(cause_commitment.digest());
            }
            Self::Recoverable {
                last_generation,
                recovery_commitment,
            } => {
                commit_optional_u64(builder, *last_generation);
                builder.digest(recovery_commitment.digest());
            }
        }
    }
}

fn commit_optional_u64(builder: &mut CommitmentBuilder, value: Option<u64>) {
    builder.bool(value.is_some());
    if let Some(value) = value {
        builder.u64(value);
    }
}

/// Facts established by the local endpoint/cryptographic adapter for one
/// already received client-hello frame.
///
/// The verdicts remain external facts. This crate only checks that they name
/// the exact frame it decoded and binds them into the retained transcript.
#[derive(Clone, Eq, PartialEq)]
pub struct HandshakeVerificationFacts {
    pub session_id: SessionId,
    pub installation: InstallationIdentity,
    pub endpoint: EndpointIdentity,
    pub integration: IntegrationIdentity,
    pub agent_challenge: [u8; 32],
    pub verifier_key_generation: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub challenge_response: ExternalVerdict,
    pub transcript_signature: ExternalVerdict,
    pub anti_downgrade: ExternalVerdict,
    pub verified_client_frame_commitment: Digest32,
    pub crypto_adapter_commitment: Digest32,
}

impl std::fmt::Debug for HandshakeVerificationFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandshakeVerificationFacts")
            .field("session_id", &self.session_id)
            .field("installation", &self.installation)
            .field("endpoint", &self.endpoint)
            .field("integration", &self.integration)
            .field("agent_challenge", &"<redacted>")
            .field("verifier_key_generation", &self.verifier_key_generation)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("challenge_response", &self.challenge_response)
            .field("transcript_signature", &self.transcript_signature)
            .field("anti_downgrade", &self.anti_downgrade)
            .field(
                "verified_client_frame_commitment",
                &self.verified_client_frame_commitment,
            )
            .field("crypto_adapter_commitment", &self.crypto_adapter_commitment)
            .finish()
    }
}

impl HandshakeVerificationFacts {
    pub(crate) fn validate_shape(&self, decoded: &DecodedClientHello) -> Result<()> {
        require_digest(self.session_id.digest())?;
        self.installation.validate()?;
        self.endpoint.validate()?;
        self.integration.validate()?;
        require_digest(self.verified_client_frame_commitment)?;
        require_digest(self.crypto_adapter_commitment)?;
        if self.verified_client_frame_commitment != decoded.raw_frame_commitment() {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        if self.agent_challenge == [0; 32]
            || decoded.client_challenge() == self.agent_challenge
            || self.verifier_key_generation == 0
        {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        if !self.challenge_response.is_verified()
            || !self.transcript_signature.is_verified()
            || !self.anti_downgrade.is_verified()
        {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        Ok(())
    }

    pub(crate) fn validate_time(&self, now_ms: u64) -> Result<()> {
        if self.issued_at_ms > now_ms {
            return Err(Error::new(ErrorCode::NotYetValid));
        }
        if self.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        let ttl = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if ttl > SESSION_TTL_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct HandshakeFacts {
    pub session_id: SessionId,
    pub installation: InstallationIdentity,
    pub endpoint: EndpointIdentity,
    pub integration: IntegrationIdentity,
    pub client_offer: NegotiationOffer,
    pub agent_offer: NegotiationOffer,
    pub client_challenge: [u8; 32],
    pub agent_challenge: [u8; 32],
    pub verifier_key_generation: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub challenge_response: ExternalVerdict,
    pub transcript_signature: ExternalVerdict,
    pub anti_downgrade: ExternalVerdict,
    pub verified_client_frame_commitment: Digest32,
    pub client_hello_semantic_commitment: Digest32,
    pub crypto_adapter_commitment: Digest32,
}

impl std::fmt::Debug for HandshakeFacts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HandshakeFacts")
            .field("session_id", &self.session_id)
            .field("installation", &self.installation)
            .field("endpoint", &self.endpoint)
            .field("integration", &self.integration)
            .field("client_offer", &self.client_offer)
            .field("agent_offer", &self.agent_offer)
            .field("client_challenge", &"<redacted>")
            .field("agent_challenge", &"<redacted>")
            .field("verifier_key_generation", &self.verifier_key_generation)
            .field("issued_at_ms", &self.issued_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("challenge_response", &self.challenge_response)
            .field("transcript_signature", &self.transcript_signature)
            .field("anti_downgrade", &self.anti_downgrade)
            .field(
                "verified_client_frame_commitment",
                &self.verified_client_frame_commitment,
            )
            .field(
                "client_hello_semantic_commitment",
                &self.client_hello_semantic_commitment,
            )
            .field("crypto_adapter_commitment", &self.crypto_adapter_commitment)
            .finish()
    }
}

impl HandshakeFacts {
    pub(crate) fn from_verified(
        verification: HandshakeVerificationFacts,
        decoded: DecodedClientHello,
        agent_offer: NegotiationOffer,
    ) -> Self {
        Self {
            session_id: verification.session_id,
            installation: verification.installation,
            endpoint: verification.endpoint,
            integration: verification.integration,
            client_offer: decoded.offer().clone(),
            agent_offer,
            client_challenge: decoded.client_challenge(),
            agent_challenge: verification.agent_challenge,
            verifier_key_generation: verification.verifier_key_generation,
            issued_at_ms: verification.issued_at_ms,
            expires_at_ms: verification.expires_at_ms,
            challenge_response: verification.challenge_response,
            transcript_signature: verification.transcript_signature,
            anti_downgrade: verification.anti_downgrade,
            verified_client_frame_commitment: verification.verified_client_frame_commitment,
            client_hello_semantic_commitment: decoded.semantic_commitment(),
            crypto_adapter_commitment: verification.crypto_adapter_commitment,
        }
    }

    pub(crate) fn validate_shape(&self) -> Result<()> {
        require_digest(self.session_id.digest())?;
        self.installation.validate()?;
        self.endpoint.validate()?;
        self.integration.validate()?;
        require_digest(self.verified_client_frame_commitment)?;
        require_digest(self.client_hello_semantic_commitment)?;
        require_digest(self.crypto_adapter_commitment)?;
        if self.client_challenge == [0; 32]
            || self.agent_challenge == [0; 32]
            || self.client_challenge == self.agent_challenge
            || self.verifier_key_generation == 0
        {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        if !self.challenge_response.is_verified()
            || !self.transcript_signature.is_verified()
            || !self.anti_downgrade.is_verified()
        {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        Ok(())
    }

    pub(crate) fn transcript_commitment(&self, selection: &NegotiationSelection) -> Digest32 {
        let mut builder = CommitmentBuilder::new("handshake-transcript-v1");
        builder.digest(self.session_id.digest());
        self.installation.commit_into(&mut builder);
        self.endpoint.commit_into(&mut builder);
        self.integration.commit_into(&mut builder);
        builder.digest(selection.selection_commitment);
        builder.bytes(&self.client_challenge);
        builder.bytes(&self.agent_challenge);
        builder.u64(self.verifier_key_generation);
        builder.u64(self.issued_at_ms);
        builder.u64(self.expires_at_ms);
        builder.u8(self.challenge_response.code());
        builder.u8(self.transcript_signature.code());
        builder.u8(self.anti_downgrade.code());
        builder.digest(self.verified_client_frame_commitment);
        builder.digest(self.client_hello_semantic_commitment);
        builder.digest(self.crypto_adapter_commitment);
        builder.finish()
    }

    pub(crate) fn challenge_replay_commitment(&self) -> Digest32 {
        let mut builder = CommitmentBuilder::new("handshake-challenge-replay-v1");
        builder.digest(self.installation.id.digest());
        builder.u64(self.installation.generation);
        builder.digest(self.endpoint.id.digest());
        builder.u64(self.endpoint.endpoint_generation);
        builder.digest(self.integration.id.digest());
        builder.u64(self.integration.registration_generation);
        builder.u64(self.verifier_key_generation);
        builder.bytes(&self.client_challenge);
        builder.bytes(&self.agent_challenge);
        builder.finish()
    }

    pub(crate) fn logical_bytes(&self, selection: &NegotiationSelection) -> Result<usize> {
        let client_versions = self
            .client_offer
            .versions
            .len()
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
        let agent_versions = self
            .agent_offer
            .versions
            .len()
            .checked_mul(4)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
        1_024usize
            .checked_add(client_versions)
            .and_then(|value| value.checked_add(self.client_offer.required_capabilities.len()))
            .and_then(|value| value.checked_add(self.client_offer.optional_capabilities.len()))
            .and_then(|value| value.checked_add(agent_versions))
            .and_then(|value| value.checked_add(self.agent_offer.required_capabilities.len()))
            .and_then(|value| value.checked_add(self.agent_offer.optional_capabilities.len()))
            .and_then(|value| value.checked_add(selection.capabilities.len()))
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentConfirmation {
    ExplicitUser,
    ExplicitAdministrator,
}

impl ConsentConfirmation {
    pub const fn code(self) -> u8 {
        match self {
            Self::ExplicitUser => 1,
            Self::ExplicitAdministrator => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentGrantFacts {
    pub consent_id: ConsentId,
    pub session_id: SessionId,
    pub integration_id: IntegrationId,
    pub workspace_id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub generation: u64,
    pub capabilities: Vec<Capability>,
    pub scope: PathScope,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub confirmation: ConsentConfirmation,
    pub external_consent_proof: ExternalVerdict,
    pub consent_proof_commitment: Digest32,
}

impl ConsentGrantFacts {
    pub(crate) fn validate(&self, now_ms: u64) -> Result<BTreeSet<Capability>> {
        require_digest(self.consent_id.digest())?;
        require_digest(self.session_id.digest())?;
        require_digest(self.integration_id.digest())?;
        require_digest(self.workspace_id.digest())?;
        require_digest(self.repository_id.digest())?;
        require_digest(self.consent_proof_commitment)?;
        if self.generation == 0
            || self.capabilities.is_empty()
            || self.capabilities.len() > CAPABILITY_ITEMS_MAXIMUM
            || self.scope.context.repository_id != self.repository_id
        {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        if !self.external_consent_proof.is_verified() {
            return Err(Error::new(ErrorCode::ConsentUnknown));
        }
        if self.issued_at_ms > now_ms {
            return Err(Error::new(ErrorCode::NotYetValid));
        }
        if self.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        let ttl = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if ttl > CONSENT_TTL_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        let capabilities: BTreeSet<_> = self.capabilities.iter().copied().collect();
        if capabilities.len() != self.capabilities.len() {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        Ok(capabilities)
    }

    pub(crate) fn commitment(
        &self,
        capabilities: &BTreeSet<Capability>,
        raw_frame_commitment: Digest32,
    ) -> Digest32 {
        let mut builder = CommitmentBuilder::new("consent-grant-v1");
        builder.digest(self.consent_id.digest());
        builder.digest(self.session_id.digest());
        builder.digest(self.integration_id.digest());
        builder.digest(self.workspace_id.digest());
        builder.digest(self.repository_id.digest());
        builder.u64(self.generation);
        builder.usize(capabilities.len());
        for capability in capabilities {
            builder.u8(capability.code());
        }
        builder.digest(self.scope.commitment());
        builder.u64(self.issued_at_ms);
        builder.u64(self.expires_at_ms);
        builder.u8(self.confirmation.code());
        builder.u8(self.external_consent_proof.code());
        builder.digest(self.consent_proof_commitment);
        builder.digest(raw_frame_commitment);
        builder.finish()
    }

    pub(crate) fn logical_bytes(&self) -> Result<usize> {
        320usize
            .checked_add(self.scope.logical_bytes())
            .and_then(|value| value.checked_add(self.capabilities.len()))
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    ReadStatus,
    SyncPlan,
    StartEditLockFact,
    CheckpointHandoff,
    RevertHandoff,
    JobProgressRead,
}

impl OperationKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::ReadStatus => 1,
            Self::SyncPlan => 2,
            Self::StartEditLockFact => 3,
            Self::CheckpointHandoff => 4,
            Self::RevertHandoff => 5,
            Self::JobProgressRead => 6,
        }
    }

    pub const fn capability(self) -> Capability {
        match self {
            Self::ReadStatus => Capability::ReadStatus,
            Self::SyncPlan => Capability::SyncMaterialize,
            Self::StartEditLockFact => Capability::StartEditLockFact,
            Self::CheckpointHandoff => Capability::CheckpointHandoff,
            Self::RevertHandoff => Capability::RevertHandoff,
            Self::JobProgressRead => Capability::JobProgress,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmationPolicy {
    None,
    TrustedDesktopRequired,
}

impl ConfirmationPolicy {
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 1,
            Self::TrustedDesktopRequired => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationFacts {
    pub session_id: SessionId,
    pub consent_id: ConsentId,
    pub integration_id: IntegrationId,
    pub workspace_id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub operation: OperationKind,
    pub scope: PathScope,
    pub fresh_state: FreshStateFacts,
    pub idempotency_key: IdempotencyKey,
    pub confirmation_policy: ConfirmationPolicy,
    pub lock_knowledge: Option<LockKnowledge>,
    pub deadline_ms: u64,
    pub idempotency_expires_at_ms: u64,
}

impl OperationFacts {
    pub(crate) fn validate_shape(&self) -> Result<()> {
        require_digest(self.session_id.digest())?;
        require_digest(self.consent_id.digest())?;
        require_digest(self.integration_id.digest())?;
        require_digest(self.workspace_id.digest())?;
        require_digest(self.repository_id.digest())?;
        require_digest(self.idempotency_key.digest())?;
        if self.scope.context.repository_id != self.repository_id {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        Ok(())
    }

    pub(crate) fn validate_time_and_lock(&self, now_ms: u64) -> Result<()> {
        self.fresh_state.validate(now_ms)?;
        if self.deadline_ms < now_ms {
            return Err(Error::new(ErrorCode::DeadlineExceeded));
        }
        let horizon = self
            .deadline_ms
            .checked_sub(now_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if horizon > DEADLINE_HORIZON_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        if self.idempotency_expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        let ttl = self
            .idempotency_expires_at_ms
            .checked_sub(now_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if ttl > IDEMPOTENCY_TTL_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        match (self.operation, self.lock_knowledge.as_ref()) {
            (OperationKind::StartEditLockFact, Some(lock)) => lock.validate(now_ms)?,
            (OperationKind::StartEditLockFact, None) => {
                return Err(Error::new(ErrorCode::LockFactInvalid));
            }
            (_, Some(_)) => return Err(Error::new(ErrorCode::LockFactInvalid)),
            (_, None) => {}
        }
        Ok(())
    }

    pub(crate) fn commitment(
        &self,
        consent_generation: u64,
        consent_grant_commitment: Digest32,
        raw_frame_commitment: Digest32,
    ) -> Digest32 {
        let mut builder = CommitmentBuilder::new("operation-envelope-v1");
        builder.digest(self.session_id.digest());
        builder.digest(self.consent_id.digest());
        builder.u64(consent_generation);
        builder.digest(consent_grant_commitment);
        builder.digest(self.integration_id.digest());
        builder.digest(self.workspace_id.digest());
        builder.digest(self.repository_id.digest());
        builder.u8(self.operation.code());
        builder.digest(self.scope.commitment());
        self.fresh_state.commit_into(&mut builder);
        builder.digest(self.idempotency_key.digest());
        builder.u8(self.confirmation_policy.code());
        builder.bool(self.lock_knowledge.is_some());
        if let Some(lock) = &self.lock_knowledge {
            lock.commit_into(&mut builder);
        }
        builder.u64(self.deadline_ms);
        builder.u64(self.idempotency_expires_at_ms);
        builder.digest(raw_frame_commitment);
        builder.finish()
    }

    pub(crate) fn logical_bytes(&self) -> Result<usize> {
        448usize
            .checked_add(self.scope.logical_bytes())
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusItemState {
    Clean,
    Modified,
    Added,
    Deleted,
    Conflicted,
    Unknown,
}

impl StatusItemState {
    pub const fn code(self) -> u8 {
        match self {
            Self::Clean => 1,
            Self::Modified => 2,
            Self::Added => 3,
            Self::Deleted => 4,
            Self::Conflicted => 5,
            Self::Unknown => 6,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StatusItemFact {
    pub file_id: FileId,
    pub path: ValidatedScopePath,
    pub state: StatusItemState,
    pub item_state_commitment: StateCommitment,
}

impl std::fmt::Debug for StatusItemFact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StatusItemFact")
            .field("file_id", &"<redacted>")
            .field("path", &self.path)
            .field("state", &self.state)
            .field("item_state_commitment", &self.item_state_commitment)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusContinuation {
    Complete,
    More {
        externally_scoped_cursor_commitment: Digest32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusBatchFacts {
    pub session_id: SessionId,
    pub consent_id: ConsentId,
    pub integration_id: IntegrationId,
    pub workspace_id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub query_scope: PathScope,
    pub fresh_state: FreshStateFacts,
    pub items: Vec<StatusItemFact>,
    pub continuation: StatusContinuation,
}

impl StatusBatchFacts {
    pub(crate) fn logical_bytes(&self) -> Result<usize> {
        let mut total = 384usize
            .checked_add(self.query_scope.logical_bytes())
            .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
        for item in &self.items {
            let path_bytes = item.path.logical_bytes()?;
            total = total
                .checked_add(81)
                .and_then(|value| value.checked_add(path_bytes))
                .ok_or_else(|| Error::new(ErrorCode::InputTooLarge))?;
        }
        if total > RAW_INPUT_BYTES_MAXIMUM {
            return Err(Error::new(ErrorCode::InputTooLarge));
        }
        Ok(total)
    }

    pub(crate) fn commitment(
        &self,
        consent_generation: u64,
        consent_grant_commitment: Digest32,
        raw_frame_commitment: Digest32,
    ) -> Digest32 {
        let mut builder = CommitmentBuilder::new("status-batch-v1");
        builder.digest(self.session_id.digest());
        builder.digest(self.consent_id.digest());
        builder.u64(consent_generation);
        builder.digest(consent_grant_commitment);
        builder.digest(self.integration_id.digest());
        builder.digest(self.workspace_id.digest());
        builder.digest(self.repository_id.digest());
        builder.digest(self.query_scope.commitment());
        self.fresh_state.commit_into(&mut builder);
        builder.usize(self.items.len());
        for item in &self.items {
            builder.bytes(item.file_id.as_bytes());
            item.path.commit_into(&mut builder);
            builder.u8(item.state.code());
            builder.digest(item.item_state_commitment.digest());
        }
        match self.continuation {
            StatusContinuation::Complete => builder.u8(1),
            StatusContinuation::More {
                externally_scoped_cursor_commitment,
            } => {
                builder.u8(2);
                builder.digest(externally_scoped_cursor_commitment);
            }
        }
        builder.digest(raw_frame_commitment);
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionFacts {
    pub subscription_id: SubscriptionId,
    pub session_id: SessionId,
    pub consent_id: ConsentId,
    pub integration_id: IntegrationId,
    pub workspace_id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub scope: PathScope,
    pub queue_capacity: usize,
    pub opened_at_ms: u64,
    pub expires_at_ms: u64,
    pub cursor_ttl_ms: u64,
    pub initial_state_commitment: StateCommitment,
}

impl SubscriptionFacts {
    pub(crate) fn validate(&self, now_ms: u64) -> Result<()> {
        require_digest(self.subscription_id.digest())?;
        require_digest(self.session_id.digest())?;
        require_digest(self.consent_id.digest())?;
        require_digest(self.integration_id.digest())?;
        require_digest(self.workspace_id.digest())?;
        require_digest(self.repository_id.digest())?;
        require_digest(self.initial_state_commitment.digest())?;
        if self.scope.context.repository_id != self.repository_id
            || self.queue_capacity == 0
            || self.queue_capacity > EVENT_QUEUE_ITEMS_MAXIMUM
            || self.opened_at_ms > now_ms
            || self.expires_at_ms <= now_ms
            || self.cursor_ttl_ms == 0
            || self.cursor_ttl_ms > CURSOR_TTL_MAXIMUM_MS
        {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        let ttl = self
            .expires_at_ms
            .checked_sub(self.opened_at_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if ttl > SUBSCRIPTION_TTL_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        Ok(())
    }

    pub(crate) fn commitment(
        &self,
        consent_generation: u64,
        consent_grant_commitment: Digest32,
        raw_frame_commitment: Digest32,
    ) -> Digest32 {
        let mut builder = CommitmentBuilder::new("subscription-v1");
        builder.digest(self.subscription_id.digest());
        builder.digest(self.session_id.digest());
        builder.digest(self.consent_id.digest());
        builder.u64(consent_generation);
        builder.digest(consent_grant_commitment);
        builder.digest(self.integration_id.digest());
        builder.digest(self.workspace_id.digest());
        builder.digest(self.repository_id.digest());
        builder.digest(self.scope.commitment());
        builder.usize(self.queue_capacity);
        builder.u64(self.opened_at_ms);
        builder.u64(self.expires_at_ms);
        builder.u64(self.cursor_ttl_ms);
        builder.digest(self.initial_state_commitment.digest());
        builder.digest(raw_frame_commitment);
        builder.finish()
    }

    pub(crate) fn logical_bytes(&self) -> Result<usize> {
        384usize
            .checked_add(self.scope.logical_bytes())
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    WorkspaceStatus,
    JobProgress,
    Lock(LockKnowledge),
}

impl EventKind {
    fn code(&self) -> u8 {
        match self {
            Self::WorkspaceStatus => 1,
            Self::JobProgress => 2,
            Self::Lock(_) => 3,
        }
    }

    pub(crate) fn validate_shape(&self) -> Result<()> {
        if let Self::Lock(lock) = self {
            lock.validate_shape()?;
        }
        Ok(())
    }

    pub(crate) fn validate_time(&self, now_ms: u64) -> Result<()> {
        if let Self::Lock(lock) = self {
            lock.validate_time(now_ms)?;
        }
        Ok(())
    }

    fn commit_into(&self, builder: &mut CommitmentBuilder) {
        builder.u8(self.code());
        if let Self::Lock(lock) = self {
            lock.commit_into(builder);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusEventFact {
    pub event_id: EventId,
    pub sequence: u64,
    pub scope: PathScope,
    pub kind: EventKind,
    pub fresh_state: FreshStateFacts,
    pub producer_commitment: Digest32,
}

impl StatusEventFact {
    pub(crate) fn validate_shape(&self) -> Result<()> {
        require_digest(self.event_id.digest())?;
        require_digest(self.producer_commitment)?;
        if self.sequence == 0 {
            return Err(Error::new(ErrorCode::SequenceInvalid));
        }
        self.kind.validate_shape()
    }

    pub(crate) fn validate_time(&self, now_ms: u64) -> Result<()> {
        self.kind.validate_time(now_ms)?;
        self.fresh_state.validate(now_ms)
    }

    pub(crate) fn commitment(
        &self,
        subscription_id: SubscriptionId,
        subscription_commitment: Digest32,
        caller_commitment: Digest32,
        raw_frame_commitment: Digest32,
    ) -> Digest32 {
        let mut builder = CommitmentBuilder::new("status-event-v1");
        builder.digest(subscription_id.digest());
        builder.digest(subscription_commitment);
        builder.digest(caller_commitment);
        builder.digest(self.event_id.digest());
        builder.u64(self.sequence);
        builder.digest(self.scope.commitment());
        self.kind.commit_into(&mut builder);
        self.fresh_state.commit_into(&mut builder);
        builder.digest(self.producer_commitment);
        builder.digest(raw_frame_commitment);
        builder.finish()
    }

    pub(crate) fn logical_bytes(&self) -> Result<usize> {
        320usize
            .checked_add(self.scope.logical_bytes())
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionCallerFacts {
    pub session_id: SessionId,
    pub session_transcript_commitment: Digest32,
    pub consent_id: ConsentId,
    pub consent_generation: u64,
    pub consent_grant_commitment: Digest32,
    pub integration_id: IntegrationId,
    pub workspace_id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub request_authentication: ExternalVerdict,
    pub request_authenticator_commitment: Digest32,
}

impl SubscriptionCallerFacts {
    pub(crate) fn validate(&self) -> Result<()> {
        require_digest(self.session_id.digest())?;
        require_digest(self.session_transcript_commitment)?;
        require_digest(self.consent_id.digest())?;
        require_digest(self.consent_grant_commitment)?;
        require_digest(self.integration_id.digest())?;
        require_digest(self.workspace_id.digest())?;
        require_digest(self.repository_id.digest())?;
        require_digest(self.request_authenticator_commitment)?;
        if self.consent_generation == 0 || !self.request_authentication.is_verified() {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        Ok(())
    }

    pub(crate) fn commitment(&self) -> Digest32 {
        let mut builder = CommitmentBuilder::new("subscription-caller-v1");
        builder.digest(self.session_id.digest());
        builder.digest(self.session_transcript_commitment);
        builder.digest(self.consent_id.digest());
        builder.u64(self.consent_generation);
        builder.digest(self.consent_grant_commitment);
        builder.digest(self.integration_id.digest());
        builder.digest(self.workspace_id.digest());
        builder.digest(self.repository_id.digest());
        builder.u8(self.request_authentication.code());
        builder.digest(self.request_authenticator_commitment);
        builder.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventCursor {
    pub subscription_id: SubscriptionId,
    pub subscription_generation: u64,
    pub position: u64,
    pub scope_commitment: Digest32,
    pub state_commitment: StateCommitment,
    pub expires_at_ms: u64,
    pub cursor_commitment: Digest32,
}

impl EventCursor {
    /// Recomputes the transparent, unkeyed integrity framing for these facts.
    ///
    /// This digest is not authentication, a MAC, or bearer authority.
    pub fn integrity_commitment(&self) -> Digest32 {
        let mut builder = CommitmentBuilder::new("event-cursor-v1");
        builder.digest(self.subscription_id.digest());
        builder.u64(self.subscription_generation);
        builder.u64(self.position);
        builder.digest(self.scope_commitment);
        builder.digest(self.state_commitment.digest());
        builder.u64(self.expires_at_ms);
        builder.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffAction {
    Submit,
    Review,
    DestructiveWorkspaceRecovery,
}

impl HandoffAction {
    pub const fn code(self) -> u8 {
        match self {
            Self::Submit => 1,
            Self::Review => 2,
            Self::DestructiveWorkspaceRecovery => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedHandoffFacts {
    pub handoff_id: HandoffId,
    pub session_id: SessionId,
    pub consent_id: ConsentId,
    pub integration_id: IntegrationId,
    pub installation_id: InstallationId,
    pub workspace_id: WorkspaceId,
    pub repository_id: RepositoryId,
    pub trusted_client_id: TrustedClientId,
    pub action: HandoffAction,
    pub scope: PathScope,
    pub fresh_state: FreshStateFacts,
    pub verifier_key_generation: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub trusted_desktop_confirmation: ExternalVerdict,
    pub signature_verification: ExternalVerdict,
    pub confirmation_commitment: ConfirmationCommitment,
    pub signature_envelope_commitment: Digest32,
}

impl TrustedHandoffFacts {
    pub(crate) fn validate(&self, now_ms: u64) -> Result<()> {
        require_digest(self.handoff_id.digest())?;
        require_digest(self.session_id.digest())?;
        require_digest(self.consent_id.digest())?;
        require_digest(self.integration_id.digest())?;
        require_digest(self.installation_id.digest())?;
        require_digest(self.workspace_id.digest())?;
        require_digest(self.repository_id.digest())?;
        require_digest(self.trusted_client_id.digest())?;
        require_digest(self.confirmation_commitment.digest())?;
        require_digest(self.signature_envelope_commitment)?;
        if self.scope.context.repository_id != self.repository_id
            || self.verifier_key_generation == 0
            || self.issued_at_ms > now_ms
            || self.expires_at_ms <= now_ms
        {
            return Err(Error::new(ErrorCode::HandoffUnverified));
        }
        if !self.trusted_desktop_confirmation.is_verified()
            || !self.signature_verification.is_verified()
        {
            return Err(Error::new(ErrorCode::HandoffUnverified));
        }
        let ttl = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?;
        if ttl > HANDOFF_TTL_MAXIMUM_MS {
            return Err(Error::new(ErrorCode::HandoffUnverified));
        }
        self.fresh_state.validate(now_ms)?;
        if self.fresh_state.observed_at_ms > self.issued_at_ms {
            return Err(Error::new(ErrorCode::HandoffUnverified));
        }
        Ok(())
    }

    pub(crate) fn commitment(
        &self,
        consent_generation: u64,
        consent_grant_commitment: Digest32,
        raw_frame_commitment: Digest32,
    ) -> Digest32 {
        let mut builder = CommitmentBuilder::new("trusted-handoff-v1");
        builder.digest(self.handoff_id.digest());
        builder.digest(self.session_id.digest());
        builder.digest(self.consent_id.digest());
        builder.u64(consent_generation);
        builder.digest(consent_grant_commitment);
        builder.digest(self.integration_id.digest());
        builder.digest(self.installation_id.digest());
        builder.digest(self.workspace_id.digest());
        builder.digest(self.repository_id.digest());
        builder.digest(self.trusted_client_id.digest());
        builder.u8(self.action.code());
        builder.digest(self.scope.commitment());
        self.fresh_state.commit_into(&mut builder);
        builder.u64(self.verifier_key_generation);
        builder.u64(self.issued_at_ms);
        builder.u64(self.expires_at_ms);
        builder.u8(self.trusted_desktop_confirmation.code());
        builder.u8(self.signature_verification.code());
        builder.digest(self.confirmation_commitment.digest());
        builder.digest(self.signature_envelope_commitment);
        builder.digest(raw_frame_commitment);
        builder.finish()
    }

    pub(crate) fn logical_bytes(&self) -> Result<usize> {
        576usize
            .checked_add(self.scope.logical_bytes())
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffConsumptionFacts {
    pub handoff_id: HandoffId,
    pub trusted_client_id: TrustedClientId,
    pub expected_handoff_commitment: Digest32,
    pub trusted_client_verification: ExternalVerdict,
    pub consumer_adapter_commitment: Digest32,
}

impl HandoffConsumptionFacts {
    pub(crate) fn validate(&self) -> Result<()> {
        require_digest(self.handoff_id.digest())?;
        require_digest(self.trusted_client_id.digest())?;
        require_digest(self.expected_handoff_commitment)?;
        require_digest(self.consumer_adapter_commitment)?;
        if !self.trusted_client_verification.is_verified() {
            return Err(Error::new(ErrorCode::HandoffUnverified));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationFacts {
    pub expected_installation: InstallationIdentity,
    pub replacement_installation: InstallationIdentity,
    pub replacement_endpoint: EndpointIdentity,
    pub expected_verifier_key_generation: u64,
    pub replacement_verifier_key_generation: u64,
    pub rotation_verification: ExternalVerdict,
    pub rotation_commitment: Digest32,
    pub effective_at_ms: u64,
}

impl RotationFacts {
    pub(crate) fn validate(&self, now_ms: u64) -> Result<()> {
        self.expected_installation.validate()?;
        self.replacement_installation.validate()?;
        self.replacement_endpoint.validate()?;
        require_digest(self.rotation_commitment)?;
        if !self.rotation_verification.is_verified() || self.effective_at_ms != now_ms {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        let next_installation = self
            .expected_installation
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
        let next_verifier = self
            .expected_verifier_key_generation
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
        if self.replacement_installation.generation != next_installation
            || self.replacement_verifier_key_generation != next_verifier
            || self.replacement_installation.id != self.expected_installation.id
            || self.replacement_installation.identity_commitment
                == self.expected_installation.identity_commitment
            || self.replacement_endpoint.installation_id != self.replacement_installation.id
            || self.replacement_endpoint.installation_generation
                != self.replacement_installation.generation
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        Ok(())
    }
}
