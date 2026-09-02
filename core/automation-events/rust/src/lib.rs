//! Private, bounded OGVCS-019 automation event and provenance contract seam.
//!
//! This crate validates caller-supplied commit, authorization, retention, and
//! delivery facts. It performs no authorization, transaction, persistence,
//! network, filesystem, branch resolution, cache, or workspace operation.
#![forbid(unsafe_code)]

use std::{collections::BTreeMap, fmt};

use hmac::{Hmac, Mac};
use ogvcs_object_model::{ObjectKind, ObjectRef, Sha256Writer};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub type Digest = [u8; 32];
pub type PublicId = [u8; 16];

pub const AUTOMATION_EVENT_VERSION: u16 = 1;
pub const CURSOR_VERSION: u16 = 1;
pub const WEBHOOK_VERSION: u16 = 1;
pub const BUILD_PROVENANCE_VERSION: u16 = 1;
pub const EVENT_PAYLOAD_BYTES_HARD_MAXIMUM: u64 = 262_144;
pub const REPLAY_PAGE_EVENTS_HARD_MAXIMUM: usize = 1_024;
pub const CURSOR_KEYS_HARD_MAXIMUM: usize = 4;
pub const CURSOR_TTL_MS_HARD_MAXIMUM: u64 = 604_800_000;
pub const WEBHOOK_KEYS_HARD_MAXIMUM: usize = 4;
pub const WEBHOOK_BODY_BYTES_HARD_MAXIMUM: u64 = 1_048_576;
pub const WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM: u64 = 300_000;
pub const REPLAY_GUARD_ENTRIES_HARD_MAXIMUM: usize = 8_192;
pub const REPLAY_GUARD_RETENTION_MS_HARD_MAXIMUM: u64 = 86_400_000;
pub const EVENT_SEQUENCE_HARD_MAXIMUM: u64 = u64::MAX - 1;

const EVENT_DOMAIN: &[u8] = b"OpenGameVCS private authorized automation event\0";
const CURSOR_DOMAIN: &[u8] = b"OpenGameVCS private automation cursor\0";
const WEBHOOK_DOMAIN: &[u8] = b"OpenGameVCS private automation webhook\0";
const PROVENANCE_DOMAIN: &[u8] = b"OpenGameVCS private build provenance\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationErrorCode {
    InputInvalid,
    LimitExceeded,
    AccountingOverflow,
    EventInvalid,
    EventGap,
    CursorInvalid,
    CursorScopeMismatch,
    CursorExpired,
    CursorStale,
    SignatureInvalid,
    TimestampInvalid,
    ReplayGuardFull,
    ReplayConflict,
    ProvenanceInvalid,
}

impl AutomationErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputInvalid => "AUTOMATION_INPUT_INVALID",
            Self::LimitExceeded => "AUTOMATION_LIMIT_EXCEEDED",
            Self::AccountingOverflow => "AUTOMATION_ACCOUNTING_OVERFLOW",
            Self::EventInvalid => "AUTOMATION_EVENT_INVALID",
            Self::EventGap => "AUTOMATION_EVENT_GAP",
            Self::CursorInvalid => "AUTOMATION_CURSOR_INVALID",
            Self::CursorScopeMismatch => "AUTOMATION_CURSOR_SCOPE_MISMATCH",
            Self::CursorExpired => "AUTOMATION_CURSOR_EXPIRED",
            Self::CursorStale => "AUTOMATION_CURSOR_STALE",
            Self::SignatureInvalid => "AUTOMATION_SIGNATURE_INVALID",
            Self::TimestampInvalid => "AUTOMATION_TIMESTAMP_INVALID",
            Self::ReplayGuardFull => "AUTOMATION_REPLAY_GUARD_FULL",
            Self::ReplayConflict => "AUTOMATION_REPLAY_CONFLICT",
            Self::ProvenanceInvalid => "AUTOMATION_PROVENANCE_INVALID",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationError {
    code: AutomationErrorCode,
    context: &'static str,
}

impl AutomationError {
    pub const fn code(&self) -> AutomationErrorCode {
        self.code
    }

    pub const fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for AutomationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.code.as_str(), self.context)
    }
}

impl std::error::Error for AutomationError {}

pub type Result<T> = std::result::Result<T, AutomationError>;

const fn failure(code: AutomationErrorCode, context: &'static str) -> AutomationError {
    AutomationError { code, context }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthorizationEvaluation {
    FrozenAtCommit = 1,
    ReevaluateAtDelivery = 2,
}

impl AuthorizationEvaluation {
    const fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommitBoundary {
    pub transaction_id: PublicId,
    pub acknowledgement_id: PublicId,
    pub state_commitment: Digest,
    pub outbox_commitment: Digest,
    pub committed_at_unix_ms: u64,
    pub acknowledged_at_unix_ms: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EventDraft {
    pub tenant: Digest,
    pub repository: Digest,
    pub repository_generation: u64,
    pub sequence: u64,
    pub commit: CommitBoundary,
    pub event_schema: Digest,
    pub event_kind: Digest,
    pub authorization_evaluation: AuthorizationEvaluation,
    pub authorization_policy: Digest,
    pub authorization_scope: Digest,
    pub authorization_epoch: u64,
    pub authorization_evaluated_at_unix_ms: u64,
    pub snapshot: Option<ObjectRef>,
    pub payload_digest: Digest,
    pub payload_bytes: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EventEnvelope {
    pub version: u16,
    pub event_id: Digest,
    pub draft: EventDraft,
}

impl fmt::Debug for EventEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventEnvelope")
            .field("version", &self.version)
            .field("event_id", &"<redacted>")
            .field("draft", &"<redacted>")
            .finish()
    }
}

impl EventEnvelope {
    pub fn verify(&self) -> Result<()> {
        validate_event_draft(&self.draft)?;
        if self.version != AUTOMATION_EVENT_VERSION || self.event_id != event_id(&self.draft) {
            return Err(failure(AutomationErrorCode::EventInvalid, "event-binding"));
        }
        Ok(())
    }
}

pub fn seal_event(draft: EventDraft) -> Result<EventEnvelope> {
    validate_event_draft(&draft)?;
    Ok(EventEnvelope {
        version: AUTOMATION_EVENT_VERSION,
        event_id: event_id(&draft),
        draft,
    })
}

fn validate_event_draft(draft: &EventDraft) -> Result<()> {
    if draft.repository_generation == 0
        || draft.sequence == 0
        || is_zero_id(&draft.commit.transaction_id)
        || is_zero_id(&draft.commit.acknowledgement_id)
        || draft.authorization_epoch == 0
    {
        return Err(failure(
            AutomationErrorCode::EventInvalid,
            "required-binding",
        ));
    }
    if draft.commit.acknowledged_at_unix_ms < draft.commit.committed_at_unix_ms {
        return Err(failure(AutomationErrorCode::EventInvalid, "event-time"));
    }
    match draft.authorization_evaluation {
        AuthorizationEvaluation::FrozenAtCommit
            if draft.authorization_evaluated_at_unix_ms > draft.commit.committed_at_unix_ms =>
        {
            return Err(failure(
                AutomationErrorCode::EventInvalid,
                "frozen-authorization-time",
            ));
        }
        AuthorizationEvaluation::ReevaluateAtDelivery
            if draft.authorization_evaluated_at_unix_ms < draft.commit.committed_at_unix_ms =>
        {
            return Err(failure(
                AutomationErrorCode::EventInvalid,
                "delivery-authorization-time",
            ));
        }
        _ => {}
    }
    if draft.sequence > EVENT_SEQUENCE_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "event-sequence",
        ));
    }
    if draft.payload_bytes > EVENT_PAYLOAD_BYTES_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "event-payload-bytes",
        ));
    }
    if let Some(snapshot) = draft.snapshot {
        if snapshot.kind != ObjectKind::Snapshot {
            return Err(failure(AutomationErrorCode::EventInvalid, "snapshot-kind"));
        }
    }
    Ok(())
}

fn event_id(draft: &EventDraft) -> Digest {
    let mut writer = domain_writer(EVENT_DOMAIN, AUTOMATION_EVENT_VERSION);
    put_digest(&mut writer, &draft.tenant);
    put_digest(&mut writer, &draft.repository);
    put_u64(&mut writer, draft.repository_generation);
    put_u64(&mut writer, draft.sequence);
    put_id(&mut writer, &draft.commit.transaction_id);
    put_id(&mut writer, &draft.commit.acknowledgement_id);
    put_digest(&mut writer, &draft.commit.state_commitment);
    put_digest(&mut writer, &draft.commit.outbox_commitment);
    put_u64(&mut writer, draft.commit.committed_at_unix_ms);
    put_u64(&mut writer, draft.commit.acknowledged_at_unix_ms);
    put_digest(&mut writer, &draft.event_schema);
    put_digest(&mut writer, &draft.event_kind);
    writer.update(&[draft.authorization_evaluation.code()]);
    put_digest(&mut writer, &draft.authorization_policy);
    put_digest(&mut writer, &draft.authorization_scope);
    put_u64(&mut writer, draft.authorization_epoch);
    put_u64(&mut writer, draft.authorization_evaluated_at_unix_ms);
    match draft.snapshot {
        Some(snapshot) => {
            writer.update(&[1]);
            put_u16(&mut writer, snapshot.kind.code());
            put_digest(&mut writer, &snapshot.digest);
        }
        None => writer.update(&[0]),
    }
    put_digest(&mut writer, &draft.payload_digest);
    put_u64(&mut writer, draft.payload_bytes);
    writer.finish()
}

pub struct CursorSigningKey {
    key_id: PublicId,
    secret: Digest,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
}

impl CursorSigningKey {
    pub fn new(
        key_id: PublicId,
        secret: Digest,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self> {
        validate_key(
            &key_id,
            &secret,
            not_before_unix_ms,
            not_after_unix_ms,
            "cursor-key",
        )?;
        Ok(Self {
            key_id,
            secret,
            not_before_unix_ms,
            not_after_unix_ms,
        })
    }

    pub const fn key_id(&self) -> PublicId {
        self.key_id
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CursorClaims {
    pub tenant: Digest,
    pub repository: Digest,
    pub authorization_scope: Digest,
    pub authority_epoch: u64,
    pub repository_generation: u64,
    pub next_sequence: u64,
    pub retained_floor_at_issue: u64,
    pub high_watermark_at_issue: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub key_id: PublicId,
}

impl fmt::Debug for CursorClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorClaims")
            .field("bindings", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CursorToken {
    pub version: u16,
    pub claims: CursorClaims,
    tag: Digest,
}

impl fmt::Debug for CursorToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CursorToken")
            .field("version", &self.version)
            .field("claims", &"<redacted>")
            .field("tag", &"<redacted>")
            .finish()
    }
}

impl CursorToken {
    pub const fn from_untrusted(version: u16, claims: CursorClaims, tag: Digest) -> Self {
        Self {
            version,
            claims,
            tag,
        }
    }

    pub const fn tag(&self) -> Digest {
        self.tag
    }
}

fn seal_cursor(claims: CursorClaims, key: &CursorSigningKey) -> Result<CursorToken> {
    validate_cursor_claims(&claims)?;
    if claims.key_id != key.key_id
        || claims.issued_at_unix_ms < key.not_before_unix_ms
        || claims.issued_at_unix_ms > key.not_after_unix_ms
    {
        return Err(failure(
            AutomationErrorCode::CursorInvalid,
            "cursor-signing-key",
        ));
    }
    Ok(CursorToken {
        version: CURSOR_VERSION,
        claims,
        tag: cursor_tag(&claims, &key.secret)?,
    })
}

pub fn verify_cursor(
    token: &CursorToken,
    keys: &[CursorSigningKey],
    now_unix_ms: u64,
) -> Result<CursorClaims> {
    validate_cursor_keys(keys)?;
    validate_cursor_claims(&token.claims)?;
    if token.version != CURSOR_VERSION {
        return Err(failure(
            AutomationErrorCode::CursorInvalid,
            "cursor-version",
        ));
    }
    let key = keys
        .iter()
        .find(|key| key.key_id == token.claims.key_id)
        .ok_or_else(|| failure(AutomationErrorCode::CursorInvalid, "cursor-key-id"))?;
    if token.claims.issued_at_unix_ms < key.not_before_unix_ms
        || token.claims.issued_at_unix_ms > key.not_after_unix_ms
    {
        return Err(failure(
            AutomationErrorCode::CursorInvalid,
            "cursor-key-window",
        ));
    }
    verify_mac(
        CURSOR_DOMAIN,
        CURSOR_VERSION,
        &key.secret,
        |mac| update_cursor_mac(mac, &token.claims),
        &token.tag,
        AutomationErrorCode::CursorInvalid,
        "cursor-tag",
    )?;
    if now_unix_ms < token.claims.issued_at_unix_ms {
        return Err(failure(
            AutomationErrorCode::CursorInvalid,
            "cursor-issued-in-future",
        ));
    }
    if now_unix_ms >= token.claims.expires_at_unix_ms {
        return Err(failure(AutomationErrorCode::CursorExpired, "cursor-expiry"));
    }
    Ok(token.claims)
}

fn validate_cursor_claims(claims: &CursorClaims) -> Result<()> {
    if claims.authority_epoch == 0
        || claims.repository_generation == 0
        || claims.next_sequence == 0
        || claims.retained_floor_at_issue == 0
        || claims.retained_floor_at_issue > claims.next_sequence
        || claims.high_watermark_at_issue > EVENT_SEQUENCE_HARD_MAXIMUM
        || claims
            .high_watermark_at_issue
            .checked_add(1)
            .is_none_or(|end| claims.retained_floor_at_issue > end || claims.next_sequence > end)
        || is_zero_id(&claims.key_id)
        || claims.expires_at_unix_ms <= claims.issued_at_unix_ms
        || claims
            .expires_at_unix_ms
            .checked_sub(claims.issued_at_unix_ms)
            .is_none_or(|ttl| ttl > CURSOR_TTL_MS_HARD_MAXIMUM)
    {
        return Err(failure(AutomationErrorCode::CursorInvalid, "cursor-claims"));
    }
    Ok(())
}

fn cursor_tag(claims: &CursorClaims, secret: &Digest) -> Result<Digest> {
    let mut mac = new_mac(CURSOR_DOMAIN, CURSOR_VERSION, secret)?;
    update_cursor_mac(&mut mac, claims);
    Ok(mac.finalize().into_bytes().into())
}

fn update_cursor_mac(mac: &mut HmacSha256, claims: &CursorClaims) {
    mac.update(&claims.tenant);
    mac.update(&claims.repository);
    mac.update(&claims.authorization_scope);
    mac.update(&claims.authority_epoch.to_be_bytes());
    mac.update(&claims.repository_generation.to_be_bytes());
    mac.update(&claims.next_sequence.to_be_bytes());
    mac.update(&claims.retained_floor_at_issue.to_be_bytes());
    mac.update(&claims.high_watermark_at_issue.to_be_bytes());
    mac.update(&claims.issued_at_unix_ms.to_be_bytes());
    mac.update(&claims.expires_at_unix_ms.to_be_bytes());
    mac.update(&claims.key_id);
}

#[derive(Clone, Copy)]
pub enum ReplayStart<'a> {
    Sequence(u64),
    Cursor(&'a CursorToken),
}

#[derive(Clone, Copy)]
pub struct ReplayRequest<'a> {
    pub tenant: Digest,
    pub repository: Digest,
    pub authorization_scope: Digest,
    pub authority_epoch: u64,
    pub repository_generation: u64,
    pub retained_floor: u64,
    pub high_watermark: u64,
    pub start: ReplayStart<'a>,
    pub page_limit: usize,
    pub cursor_ttl_ms: u64,
    pub now_unix_ms: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReplayPage {
    pub events: Vec<EventEnvelope>,
    pub next_cursor: CursorToken,
    pub delivered_from: u64,
    pub delivered_through: Option<u64>,
    pub caught_up: bool,
}

impl fmt::Debug for ReplayPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayPage")
            .field("events", &"<redacted>")
            .field("next_cursor", &"<redacted>")
            .field("range", &"<redacted>")
            .finish()
    }
}

pub fn replay_page(
    request: ReplayRequest<'_>,
    supplied_events: &[EventEnvelope],
    verification_keys: &[CursorSigningKey],
    signing_key: &CursorSigningKey,
) -> Result<ReplayPage> {
    validate_replay_request(&request)?;
    if supplied_events.len() > REPLAY_PAGE_EVENTS_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "supplied-replay-events",
        ));
    }
    validate_cursor_keys(verification_keys)?;
    let signing_key_present = verification_keys.iter().try_fold(false, |found, key| {
        if found {
            Ok(true)
        } else {
            cursor_keys_match(key, signing_key)
        }
    })?;
    if !signing_key_present {
        return Err(failure(
            AutomationErrorCode::CursorInvalid,
            "cursor-signing-key-absent",
        ));
    }

    let start = match request.start {
        ReplayStart::Sequence(0) => {
            return Err(failure(
                AutomationErrorCode::InputInvalid,
                "replay-start-sequence",
            ));
        }
        ReplayStart::Sequence(sequence) => sequence,
        ReplayStart::Cursor(token) => {
            let claims = verify_cursor(token, verification_keys, request.now_unix_ms)?;
            if claims.tenant != request.tenant
                || claims.repository != request.repository
                || claims.authorization_scope != request.authorization_scope
            {
                return Err(failure(
                    AutomationErrorCode::CursorScopeMismatch,
                    "cursor-scope",
                ));
            }
            if claims.authority_epoch != request.authority_epoch
                || claims.repository_generation != request.repository_generation
                || request.retained_floor < claims.retained_floor_at_issue
                || request.high_watermark < claims.high_watermark_at_issue
            {
                return Err(failure(
                    AutomationErrorCode::CursorStale,
                    "cursor-authority-state",
                ));
            }
            claims.next_sequence
        }
    };

    let end_exclusive = request
        .high_watermark
        .checked_add(1)
        .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "high-watermark"))?;
    if start < request.retained_floor {
        return Err(failure(
            AutomationErrorCode::CursorExpired,
            "retention-floor",
        ));
    }
    if start > end_exclusive {
        return Err(failure(AutomationErrorCode::CursorInvalid, "cursor-ahead"));
    }

    let available = end_exclusive
        .checked_sub(start)
        .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "replay-available"))?;
    let page_limit = u64::try_from(request.page_limit)
        .map_err(|_| failure(AutomationErrorCode::AccountingOverflow, "page-limit"))?;
    let delivered = available.min(page_limit);
    let expected_count = usize::try_from(delivered)
        .map_err(|_| failure(AutomationErrorCode::AccountingOverflow, "page-count"))?;
    if supplied_events.len() != expected_count {
        return Err(failure(
            AutomationErrorCode::EventGap,
            "replay-page-cardinality",
        ));
    }

    for (index, event) in supplied_events.iter().enumerate() {
        event.verify()?;
        if event.draft.commit.committed_at_unix_ms > request.now_unix_ms
            || event.draft.commit.acknowledged_at_unix_ms > request.now_unix_ms
            || event.draft.authorization_evaluated_at_unix_ms > request.now_unix_ms
        {
            return Err(failure(
                AutomationErrorCode::EventInvalid,
                "replay-event-time",
            ));
        }
        let offset = u64::try_from(index)
            .map_err(|_| failure(AutomationErrorCode::AccountingOverflow, "event-index"))?;
        let expected_sequence = start
            .checked_add(offset)
            .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "event-sequence"))?;
        if event.draft.tenant != request.tenant
            || event.draft.repository != request.repository
            || event.draft.authorization_scope != request.authorization_scope
            || event.draft.repository_generation != request.repository_generation
            || event.draft.sequence != expected_sequence
        {
            return Err(failure(
                AutomationErrorCode::EventGap,
                "replay-event-binding",
            ));
        }
    }

    let next_sequence = start
        .checked_add(delivered)
        .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "next-sequence"))?;
    let expires_at_unix_ms = request
        .now_unix_ms
        .checked_add(request.cursor_ttl_ms)
        .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "cursor-expiry"))?;
    let next_cursor = seal_cursor(
        CursorClaims {
            tenant: request.tenant,
            repository: request.repository,
            authorization_scope: request.authorization_scope,
            authority_epoch: request.authority_epoch,
            repository_generation: request.repository_generation,
            next_sequence,
            retained_floor_at_issue: request.retained_floor,
            high_watermark_at_issue: request.high_watermark,
            issued_at_unix_ms: request.now_unix_ms,
            expires_at_unix_ms,
            key_id: signing_key.key_id,
        },
        signing_key,
    )?;

    Ok(ReplayPage {
        events: supplied_events.to_vec(),
        next_cursor,
        delivered_from: start,
        delivered_through: (expected_count != 0).then_some(next_sequence - 1),
        caught_up: next_sequence == end_exclusive,
    })
}

fn validate_replay_request(request: &ReplayRequest<'_>) -> Result<()> {
    if request.authority_epoch == 0
        || request.repository_generation == 0
        || request.retained_floor == 0
    {
        return Err(failure(AutomationErrorCode::InputInvalid, "replay-window"));
    }
    if request.high_watermark > EVENT_SEQUENCE_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "replay-high-watermark",
        ));
    }
    let end_exclusive = request
        .high_watermark
        .checked_add(1)
        .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "high-watermark"))?;
    if request.retained_floor > end_exclusive {
        return Err(failure(AutomationErrorCode::InputInvalid, "replay-window"));
    }
    if request.page_limit == 0 || request.page_limit > REPLAY_PAGE_EVENTS_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "replay-page-events",
        ));
    }
    if request.cursor_ttl_ms == 0 || request.cursor_ttl_ms > CURSOR_TTL_MS_HARD_MAXIMUM {
        return Err(failure(AutomationErrorCode::LimitExceeded, "cursor-ttl"));
    }
    Ok(())
}

fn validate_cursor_keys(keys: &[CursorSigningKey]) -> Result<()> {
    if keys.is_empty() || keys.len() > CURSOR_KEYS_HARD_MAXIMUM {
        return Err(failure(AutomationErrorCode::LimitExceeded, "cursor-keys"));
    }
    for (index, key) in keys.iter().enumerate() {
        validate_key(
            &key.key_id,
            &key.secret,
            key.not_before_unix_ms,
            key.not_after_unix_ms,
            "cursor-key",
        )?;
        if keys[..index].iter().any(|prior| prior.key_id == key.key_id) {
            return Err(failure(
                AutomationErrorCode::CursorInvalid,
                "cursor-key-duplicate",
            ));
        }
    }
    Ok(())
}

fn cursor_keys_match(left: &CursorSigningKey, right: &CursorSigningKey) -> Result<bool> {
    if left.key_id != right.key_id
        || left.not_before_unix_ms != right.not_before_unix_ms
        || left.not_after_unix_ms != right.not_after_unix_ms
    {
        return Ok(false);
    }
    let claims = CursorClaims {
        tenant: [1; 32],
        repository: [2; 32],
        authorization_scope: [3; 32],
        authority_epoch: 1,
        repository_generation: 1,
        next_sequence: 1,
        retained_floor_at_issue: 1,
        high_watermark_at_issue: 0,
        issued_at_unix_ms: 0,
        expires_at_unix_ms: 1,
        key_id: left.key_id,
    };
    let expected = cursor_tag(&claims, &left.secret)?;
    let mut right_mac = new_mac(CURSOR_DOMAIN, CURSOR_VERSION, &right.secret)?;
    update_cursor_mac(&mut right_mac, &claims);
    Ok(right_mac.verify_slice(&expected).is_ok())
}

pub struct WebhookSigningKey {
    key_id: PublicId,
    secret: Digest,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
}

impl WebhookSigningKey {
    pub fn new(
        key_id: PublicId,
        secret: Digest,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self> {
        validate_key(
            &key_id,
            &secret,
            not_before_unix_ms,
            not_after_unix_ms,
            "webhook-key",
        )?;
        Ok(Self {
            key_id,
            secret,
            not_before_unix_ms,
            not_after_unix_ms,
        })
    }

    pub const fn key_id(&self) -> PublicId {
        self.key_id
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WebhookDeliveryInput {
    pub delivery_id: PublicId,
    pub attempt: u16,
    pub sent_at_unix_ms: u64,
    pub endpoint_scope: Digest,
    pub body_digest: Digest,
    pub body_bytes: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WebhookEnvelope {
    pub version: u16,
    pub event_id: Digest,
    pub tenant: Digest,
    pub repository: Digest,
    pub repository_generation: u64,
    pub sequence: u64,
    pub authorization_scope: Digest,
    pub delivery_id: PublicId,
    pub attempt: u16,
    pub sent_at_unix_ms: u64,
    pub endpoint_scope: Digest,
    pub body_digest: Digest,
    pub body_bytes: u64,
    pub key_id: PublicId,
    signature: Digest,
}

impl fmt::Debug for WebhookEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookEnvelope")
            .field("version", &self.version)
            .field("projection", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl WebhookEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub const fn from_untrusted(
        version: u16,
        event_id: Digest,
        tenant: Digest,
        repository: Digest,
        repository_generation: u64,
        sequence: u64,
        authorization_scope: Digest,
        delivery_id: PublicId,
        attempt: u16,
        sent_at_unix_ms: u64,
        endpoint_scope: Digest,
        body_digest: Digest,
        body_bytes: u64,
        key_id: PublicId,
        signature: Digest,
    ) -> Self {
        Self {
            version,
            event_id,
            tenant,
            repository,
            repository_generation,
            sequence,
            authorization_scope,
            delivery_id,
            attempt,
            sent_at_unix_ms,
            endpoint_scope,
            body_digest,
            body_bytes,
            key_id,
            signature,
        }
    }

    pub const fn signature(&self) -> Digest {
        self.signature
    }
}

pub fn sign_webhook(
    event: &EventEnvelope,
    input: WebhookDeliveryInput,
    key: &WebhookSigningKey,
) -> Result<WebhookEnvelope> {
    event.verify()?;
    validate_webhook_input(&input)?;
    validate_webhook_event_time(event, input.sent_at_unix_ms)?;
    if input.sent_at_unix_ms < key.not_before_unix_ms
        || input.sent_at_unix_ms > key.not_after_unix_ms
    {
        return Err(failure(
            AutomationErrorCode::TimestampInvalid,
            "webhook-key-window",
        ));
    }
    let mut envelope = WebhookEnvelope {
        version: WEBHOOK_VERSION,
        event_id: event.event_id,
        tenant: event.draft.tenant,
        repository: event.draft.repository,
        repository_generation: event.draft.repository_generation,
        sequence: event.draft.sequence,
        authorization_scope: event.draft.authorization_scope,
        delivery_id: input.delivery_id,
        attempt: input.attempt,
        sent_at_unix_ms: input.sent_at_unix_ms,
        endpoint_scope: input.endpoint_scope,
        body_digest: input.body_digest,
        body_bytes: input.body_bytes,
        key_id: key.key_id,
        signature: [0; 32],
    };
    envelope.signature = webhook_tag(&envelope, &key.secret)?;
    Ok(envelope)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    FirstSeen,
    Duplicate,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct ReplayKey {
    tenant: Digest,
    repository: Digest,
    authorization_scope: Digest,
    endpoint_scope: Digest,
    delivery_id: PublicId,
    attempt: u16,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReplayEntry {
    envelope: WebhookEnvelope,
    expires_at_unix_ms: u64,
}

pub struct DeliveryReplayGuard {
    maximum_entries: usize,
    retention_ms: u64,
    entries: BTreeMap<ReplayKey, ReplayEntry>,
}

impl fmt::Debug for DeliveryReplayGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryReplayGuard")
            .field("maximum_entries", &self.maximum_entries)
            .field("retention_ms", &self.retention_ms)
            .finish_non_exhaustive()
    }
}

impl DeliveryReplayGuard {
    pub fn new(maximum_entries: usize, retention_ms: u64) -> Result<Self> {
        if maximum_entries == 0 || maximum_entries > REPLAY_GUARD_ENTRIES_HARD_MAXIMUM {
            return Err(failure(
                AutomationErrorCode::LimitExceeded,
                "replay-guard-entries",
            ));
        }
        if retention_ms == 0 || retention_ms > REPLAY_GUARD_RETENTION_MS_HARD_MAXIMUM {
            return Err(failure(
                AutomationErrorCode::LimitExceeded,
                "replay-guard-retention",
            ));
        }
        Ok(Self {
            maximum_entries,
            retention_ms,
            entries: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn observe(
        &mut self,
        envelope: &WebhookEnvelope,
        now_unix_ms: u64,
    ) -> Result<ReplayDisposition> {
        let key = ReplayKey {
            tenant: envelope.tenant,
            repository: envelope.repository,
            authorization_scope: envelope.authorization_scope,
            endpoint_scope: envelope.endpoint_scope,
            delivery_id: envelope.delivery_id,
            attempt: envelope.attempt,
        };
        if let Some(entry) = self.entries.get(&key) {
            if entry.expires_at_unix_ms > now_unix_ms {
                if entry.envelope == *envelope {
                    return Ok(ReplayDisposition::Duplicate);
                }
                return Err(failure(
                    AutomationErrorCode::ReplayConflict,
                    "webhook-attempt-conflict",
                ));
            }
        }
        let expiry = now_unix_ms
            .checked_add(self.retention_ms)
            .ok_or_else(|| failure(AutomationErrorCode::AccountingOverflow, "replay-expiry"))?;
        let active_entries = self
            .entries
            .values()
            .filter(|entry| entry.expires_at_unix_ms > now_unix_ms)
            .count();
        if active_entries >= self.maximum_entries {
            return Err(failure(
                AutomationErrorCode::ReplayGuardFull,
                "replay-guard-capacity",
            ));
        }
        self.entries
            .retain(|_, entry| entry.expires_at_unix_ms > now_unix_ms);
        self.entries.insert(
            key,
            ReplayEntry {
                envelope: *envelope,
                expires_at_unix_ms: expiry,
            },
        );
        Ok(ReplayDisposition::FirstSeen)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WebhookVerification {
    pub replay: ReplayDisposition,
    pub event_id: Digest,
    pub delivery_id: PublicId,
    pub attempt: u16,
}

impl fmt::Debug for WebhookVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookVerification")
            .field("replay", &self.replay)
            .field("bindings", &"<redacted>")
            .finish()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_webhook(
    envelope: &WebhookEnvelope,
    expected_event: &EventEnvelope,
    expected_endpoint_scope: Digest,
    expected_body_digest: Digest,
    expected_body_bytes: u64,
    keys: &[WebhookSigningKey],
    now_unix_ms: u64,
    maximum_clock_skew_ms: u64,
    replay_guard: &mut DeliveryReplayGuard,
) -> Result<WebhookVerification> {
    expected_event.verify()?;
    validate_webhook_keys(keys)?;
    if maximum_clock_skew_ms > WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "webhook-clock-skew",
        ));
    }
    let minimum_replay_retention_ms = maximum_clock_skew_ms
        .checked_mul(2)
        .and_then(|window| window.checked_add(1))
        .ok_or_else(|| {
            failure(
                AutomationErrorCode::AccountingOverflow,
                "webhook-replay-window",
            )
        })?;
    if replay_guard.retention_ms < minimum_replay_retention_ms {
        return Err(failure(
            AutomationErrorCode::InputInvalid,
            "replay-guard-retention-window",
        ));
    }
    if expected_body_bytes > WEBHOOK_BODY_BYTES_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "expected-webhook-body-bytes",
        ));
    }
    if envelope.version != WEBHOOK_VERSION
        || is_zero_id(&envelope.delivery_id)
        || envelope.attempt == 0
        || envelope.body_bytes > WEBHOOK_BODY_BYTES_HARD_MAXIMUM
    {
        return Err(failure(
            AutomationErrorCode::SignatureInvalid,
            "webhook-binding",
        ));
    }
    let key = keys
        .iter()
        .find(|key| key.key_id == envelope.key_id)
        .ok_or_else(|| failure(AutomationErrorCode::SignatureInvalid, "webhook-key-id"))?;
    verify_mac(
        WEBHOOK_DOMAIN,
        WEBHOOK_VERSION,
        &key.secret,
        |mac| update_webhook_mac(mac, envelope),
        &envelope.signature,
        AutomationErrorCode::SignatureInvalid,
        "webhook-signature",
    )?;
    if envelope.event_id != expected_event.event_id
        || envelope.tenant != expected_event.draft.tenant
        || envelope.repository != expected_event.draft.repository
        || envelope.repository_generation != expected_event.draft.repository_generation
        || envelope.sequence != expected_event.draft.sequence
        || envelope.authorization_scope != expected_event.draft.authorization_scope
        || envelope.endpoint_scope != expected_endpoint_scope
        || envelope.body_digest != expected_body_digest
        || envelope.body_bytes != expected_body_bytes
    {
        return Err(failure(
            AutomationErrorCode::SignatureInvalid,
            "webhook-binding",
        ));
    }
    validate_webhook_event_time(expected_event, envelope.sent_at_unix_ms)?;
    if now_unix_ms.abs_diff(envelope.sent_at_unix_ms) > maximum_clock_skew_ms {
        return Err(failure(
            AutomationErrorCode::TimestampInvalid,
            "webhook-timestamp",
        ));
    }
    if envelope.sent_at_unix_ms < key.not_before_unix_ms
        || envelope.sent_at_unix_ms > key.not_after_unix_ms
    {
        return Err(failure(
            AutomationErrorCode::TimestampInvalid,
            "webhook-key-window",
        ));
    }
    let replay = replay_guard.observe(envelope, now_unix_ms)?;
    Ok(WebhookVerification {
        replay,
        event_id: envelope.event_id,
        delivery_id: envelope.delivery_id,
        attempt: envelope.attempt,
    })
}

fn validate_webhook_event_time(event: &EventEnvelope, sent_at_unix_ms: u64) -> Result<()> {
    if sent_at_unix_ms < event.draft.commit.committed_at_unix_ms
        || sent_at_unix_ms < event.draft.authorization_evaluated_at_unix_ms
    {
        return Err(failure(
            AutomationErrorCode::TimestampInvalid,
            "webhook-event-time",
        ));
    }
    Ok(())
}

fn validate_webhook_input(input: &WebhookDeliveryInput) -> Result<()> {
    if is_zero_id(&input.delivery_id) || input.attempt == 0 {
        return Err(failure(AutomationErrorCode::InputInvalid, "webhook-input"));
    }
    if input.body_bytes > WEBHOOK_BODY_BYTES_HARD_MAXIMUM {
        return Err(failure(
            AutomationErrorCode::LimitExceeded,
            "webhook-body-bytes",
        ));
    }
    Ok(())
}

fn validate_webhook_keys(keys: &[WebhookSigningKey]) -> Result<()> {
    if keys.is_empty() || keys.len() > WEBHOOK_KEYS_HARD_MAXIMUM {
        return Err(failure(AutomationErrorCode::LimitExceeded, "webhook-keys"));
    }
    for (index, key) in keys.iter().enumerate() {
        validate_key(
            &key.key_id,
            &key.secret,
            key.not_before_unix_ms,
            key.not_after_unix_ms,
            "webhook-key",
        )?;
        if keys[..index].iter().any(|prior| prior.key_id == key.key_id) {
            return Err(failure(
                AutomationErrorCode::SignatureInvalid,
                "webhook-key-duplicate",
            ));
        }
    }
    Ok(())
}

fn webhook_tag(envelope: &WebhookEnvelope, secret: &Digest) -> Result<Digest> {
    let mut mac = new_mac(WEBHOOK_DOMAIN, WEBHOOK_VERSION, secret)?;
    update_webhook_mac(&mut mac, envelope);
    Ok(mac.finalize().into_bytes().into())
}

fn update_webhook_mac(mac: &mut HmacSha256, envelope: &WebhookEnvelope) {
    mac.update(&envelope.event_id);
    mac.update(&envelope.tenant);
    mac.update(&envelope.repository);
    mac.update(&envelope.repository_generation.to_be_bytes());
    mac.update(&envelope.sequence.to_be_bytes());
    mac.update(&envelope.authorization_scope);
    mac.update(&envelope.delivery_id);
    mac.update(&envelope.attempt.to_be_bytes());
    mac.update(&envelope.sent_at_unix_ms.to_be_bytes());
    mac.update(&envelope.endpoint_scope);
    mac.update(&envelope.body_digest);
    mac.update(&envelope.body_bytes.to_be_bytes());
    mac.update(&envelope.key_id);
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BuildProvenanceInput {
    pub tenant: Digest,
    pub repository: Digest,
    pub snapshot: ObjectRef,
    pub selection_policy_digest: Digest,
    pub materialized_root_digest: Digest,
    pub client_version_digest: Digest,
    pub toolchain_digest: Digest,
    pub input_set_digest: Digest,
    pub build_result_digest: Option<Digest>,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BuildProvenance {
    pub version: u16,
    pub provenance_digest: Digest,
    pub input: BuildProvenanceInput,
}

impl fmt::Debug for BuildProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildProvenance")
            .field("version", &self.version)
            .field("provenance_digest", &"<redacted>")
            .field("input", &"<redacted>")
            .finish()
    }
}

impl BuildProvenance {
    pub fn verify(&self) -> Result<()> {
        validate_provenance_input(&self.input)?;
        if self.version != BUILD_PROVENANCE_VERSION
            || self.provenance_digest != provenance_digest(&self.input)
        {
            return Err(failure(
                AutomationErrorCode::ProvenanceInvalid,
                "provenance-binding",
            ));
        }
        Ok(())
    }
}

pub fn seal_build_provenance(input: BuildProvenanceInput) -> Result<BuildProvenance> {
    validate_provenance_input(&input)?;
    Ok(BuildProvenance {
        version: BUILD_PROVENANCE_VERSION,
        provenance_digest: provenance_digest(&input),
        input,
    })
}

fn validate_provenance_input(input: &BuildProvenanceInput) -> Result<()> {
    if input.snapshot.kind != ObjectKind::Snapshot
        || input.completed_at_unix_ms < input.started_at_unix_ms
    {
        return Err(failure(
            AutomationErrorCode::ProvenanceInvalid,
            "provenance-input",
        ));
    }
    Ok(())
}

fn provenance_digest(input: &BuildProvenanceInput) -> Digest {
    let mut writer = domain_writer(PROVENANCE_DOMAIN, BUILD_PROVENANCE_VERSION);
    put_digest(&mut writer, &input.tenant);
    put_digest(&mut writer, &input.repository);
    put_u16(&mut writer, input.snapshot.kind.code());
    put_digest(&mut writer, &input.snapshot.digest);
    put_digest(&mut writer, &input.selection_policy_digest);
    put_digest(&mut writer, &input.materialized_root_digest);
    put_digest(&mut writer, &input.client_version_digest);
    put_digest(&mut writer, &input.toolchain_digest);
    put_digest(&mut writer, &input.input_set_digest);
    match input.build_result_digest {
        Some(digest) => {
            writer.update(&[1]);
            put_digest(&mut writer, &digest);
        }
        None => writer.update(&[0]),
    }
    put_u64(&mut writer, input.started_at_unix_ms);
    put_u64(&mut writer, input.completed_at_unix_ms);
    writer.finish()
}

fn validate_key(
    key_id: &PublicId,
    secret: &Digest,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    context: &'static str,
) -> Result<()> {
    if is_zero_id(key_id) || is_zero_digest(secret) || not_after_unix_ms < not_before_unix_ms {
        return Err(failure(AutomationErrorCode::InputInvalid, context));
    }
    Ok(())
}

fn new_mac(domain: &[u8], version: u16, secret: &Digest) -> Result<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| failure(AutomationErrorCode::InputInvalid, "mac-key"))?;
    mac.update(domain);
    mac.update(&version.to_be_bytes());
    Ok(mac)
}

fn verify_mac(
    domain: &[u8],
    version: u16,
    secret: &Digest,
    update: impl FnOnce(&mut HmacSha256),
    expected: &Digest,
    code: AutomationErrorCode,
    context: &'static str,
) -> Result<()> {
    let mut mac = new_mac(domain, version, secret)?;
    update(&mut mac);
    mac.verify_slice(expected)
        .map_err(|_| failure(code, context))
}

fn domain_writer(domain: &[u8], version: u16) -> Sha256Writer {
    let mut writer = Sha256Writer::new();
    writer.update(domain);
    writer.update(&version.to_be_bytes());
    writer
}

fn put_u16(writer: &mut Sha256Writer, value: u16) {
    writer.update(&value.to_be_bytes());
}

fn put_u64(writer: &mut Sha256Writer, value: u64) {
    writer.update(&value.to_be_bytes());
}

fn put_id(writer: &mut Sha256Writer, value: &PublicId) {
    writer.update(value);
}

fn put_digest(writer: &mut Sha256Writer, value: &Digest) {
    writer.update(value);
}

fn is_zero_id(value: &PublicId) -> bool {
    value == &[0; 16]
}

fn is_zero_digest(value: &Digest) -> bool {
    value == &[0; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn digest(byte: u8) -> Digest {
        [byte; 32]
    }

    fn public_id(byte: u8) -> PublicId {
        [byte; 16]
    }

    fn cursor_key(byte: u8) -> CursorSigningKey {
        CursorSigningKey::new(public_id(byte), digest(byte), NOW - 10_000, NOW + 10_000).unwrap()
    }

    fn webhook_key(byte: u8, before: u64, after: u64) -> WebhookSigningKey {
        WebhookSigningKey::new(public_id(byte), digest(byte), before, after).unwrap()
    }

    fn draft(sequence: u64, scope: u8) -> EventDraft {
        EventDraft {
            tenant: digest(1),
            repository: digest(2),
            repository_generation: 7,
            sequence,
            commit: CommitBoundary {
                transaction_id: public_id(3),
                acknowledgement_id: public_id(4),
                state_commitment: digest(5),
                outbox_commitment: digest(6),
                committed_at_unix_ms: NOW - 500,
                acknowledged_at_unix_ms: NOW - 400,
            },
            event_schema: digest(7),
            event_kind: digest(8),
            authorization_evaluation: AuthorizationEvaluation::ReevaluateAtDelivery,
            authorization_policy: digest(9),
            authorization_scope: digest(scope),
            authorization_epoch: 11,
            authorization_evaluated_at_unix_ms: NOW - 300,
            snapshot: Some(ObjectRef {
                kind: ObjectKind::Snapshot,
                digest: digest(10),
            }),
            payload_digest: digest(11),
            payload_bytes: 128,
        }
    }

    fn event(sequence: u64, scope: u8) -> EventEnvelope {
        seal_event(draft(sequence, scope)).unwrap()
    }

    fn assert_event_binding_changes(mutator: impl FnOnce(&mut EventDraft)) {
        let original = event(1, 12).event_id;
        let mut changed = draft(1, 12);
        mutator(&mut changed);
        assert_ne!(seal_event(changed).unwrap().event_id, original);
    }

    fn replay_request(start: ReplayStart<'_>, high_watermark: u64) -> ReplayRequest<'_> {
        ReplayRequest {
            tenant: digest(1),
            repository: digest(2),
            authorization_scope: digest(12),
            authority_epoch: 17,
            repository_generation: 7,
            retained_floor: 1,
            high_watermark,
            start,
            page_limit: 2,
            cursor_ttl_ms: 5_000,
            now_unix_ms: NOW,
        }
    }

    fn assert_cursor_claim_tamper(
        token: CursorToken,
        key: &CursorSigningKey,
        mutator: impl FnOnce(&mut CursorClaims),
    ) {
        let mut claims = token.claims;
        mutator(&mut claims);
        let tampered = CursorToken::from_untrusted(token.version, claims, token.tag());
        assert_eq!(
            verify_cursor(&tampered, std::slice::from_ref(key), NOW)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorInvalid
        );
    }

    #[test]
    fn event_identity_is_deterministic_and_every_binding_is_checked() {
        let first = event(1, 12);
        assert_eq!(first, event(1, 12));
        first.verify().unwrap();
        assert_eq!(
            first.event_id,
            [
                0x4d, 0xe2, 0xf6, 0xaa, 0xf3, 0x82, 0xa9, 0x73, 0x1c, 0x78, 0x4e, 0x5c, 0x80, 0x7f,
                0x14, 0x8c, 0x4a, 0xaa, 0x45, 0xc0, 0xe4, 0x5e, 0x43, 0x52, 0x2c, 0xf8, 0x59, 0xef,
                0x45, 0xde, 0x62, 0xba,
            ]
        );

        assert_event_binding_changes(|value| value.tenant = digest(51));
        assert_event_binding_changes(|value| value.repository = digest(52));
        assert_event_binding_changes(|value| value.repository_generation += 1);
        assert_event_binding_changes(|value| value.sequence += 1);
        assert_event_binding_changes(|value| value.commit.transaction_id = public_id(53));
        assert_event_binding_changes(|value| value.commit.acknowledgement_id = public_id(54));
        assert_event_binding_changes(|value| value.commit.state_commitment = digest(55));
        assert_event_binding_changes(|value| value.commit.outbox_commitment = digest(56));
        assert_event_binding_changes(|value| value.commit.committed_at_unix_ms -= 1);
        assert_event_binding_changes(|value| value.commit.acknowledged_at_unix_ms += 1);
        assert_event_binding_changes(|value| value.event_schema = digest(57));
        assert_event_binding_changes(|value| value.event_kind = digest(58));
        assert_event_binding_changes(|value| {
            value.authorization_evaluation = AuthorizationEvaluation::FrozenAtCommit;
            value.authorization_evaluated_at_unix_ms = value.commit.committed_at_unix_ms;
        });
        assert_event_binding_changes(|value| value.authorization_policy = digest(59));
        assert_event_binding_changes(|value| value.authorization_scope = digest(60));
        assert_event_binding_changes(|value| value.authorization_epoch += 1);
        assert_event_binding_changes(|value| value.authorization_evaluated_at_unix_ms += 1);
        assert_event_binding_changes(|value| value.snapshot = None);
        assert_event_binding_changes(|value| {
            value.snapshot.as_mut().unwrap().digest = digest(61);
        });
        assert_event_binding_changes(|value| value.payload_digest = [0; 32]);
        assert_event_binding_changes(|value| value.payload_bytes += 1);

        let mut tampered = first;
        tampered.draft.sequence += 1;
        assert_eq!(
            tampered.verify().unwrap_err().code(),
            AutomationErrorCode::EventInvalid
        );
        tampered = first;
        tampered.event_id[0] ^= 1;
        assert_eq!(tampered.verify().unwrap_err().context(), "event-binding");
        tampered = first;
        tampered.version += 1;
        assert_eq!(tampered.verify().unwrap_err().context(), "event-binding");
    }

    #[test]
    fn event_shape_rejects_missing_commit_facts_kind_and_payload_plus_one() {
        let mut value = draft(1, 12);
        value.commit.transaction_id = [0; 16];
        assert_eq!(
            seal_event(value).unwrap_err().code(),
            AutomationErrorCode::EventInvalid
        );
        value = draft(1, 12);
        value.snapshot = Some(ObjectRef {
            kind: ObjectKind::Tree,
            digest: digest(10),
        });
        assert_eq!(seal_event(value).unwrap_err().context(), "snapshot-kind");
        value = draft(1, 12);
        value.payload_bytes = EVENT_PAYLOAD_BYTES_HARD_MAXIMUM;
        seal_event(value).unwrap();
        value.payload_bytes += 1;
        assert_eq!(
            seal_event(value).unwrap_err().code(),
            AutomationErrorCode::LimitExceeded
        );
    }

    #[test]
    fn event_authorization_time_and_sequence_edges_are_explicit() {
        let mut frozen = draft(1, 12);
        frozen.authorization_evaluation = AuthorizationEvaluation::FrozenAtCommit;
        frozen.authorization_evaluated_at_unix_ms = frozen.commit.committed_at_unix_ms;
        seal_event(frozen).unwrap();
        frozen.authorization_evaluated_at_unix_ms -= 1;
        seal_event(frozen).unwrap();
        frozen.authorization_evaluated_at_unix_ms = frozen.commit.committed_at_unix_ms + 1;
        assert_eq!(
            seal_event(frozen).unwrap_err().context(),
            "frozen-authorization-time"
        );

        let mut delivery = draft(1, 12);
        delivery.authorization_evaluated_at_unix_ms = delivery.commit.committed_at_unix_ms;
        let delivery_id = seal_event(delivery).unwrap().event_id;
        let mut same_time_frozen = delivery;
        same_time_frozen.authorization_evaluation = AuthorizationEvaluation::FrozenAtCommit;
        assert_ne!(seal_event(same_time_frozen).unwrap().event_id, delivery_id);
        delivery.authorization_evaluated_at_unix_ms -= 1;
        assert_eq!(
            seal_event(delivery).unwrap_err().context(),
            "delivery-authorization-time"
        );

        let mut maximum = draft(EVENT_SEQUENCE_HARD_MAXIMUM, 12);
        seal_event(maximum).unwrap();
        maximum.sequence = u64::MAX;
        assert_eq!(
            seal_event(maximum).unwrap_err().code(),
            AutomationErrorCode::LimitExceeded
        );
    }

    #[test]
    fn ogvcs002_snapshot_zero_digest_is_not_reinterpreted_as_a_sentinel() {
        let mut value = draft(1, 12);
        value.snapshot = Some(ObjectRef {
            kind: ObjectKind::Snapshot,
            digest: [0; 32],
        });
        seal_event(value).unwrap();
    }

    #[test]
    fn all_cryptographic_commitments_admit_the_zero_digest() {
        let mut value = draft(1, 12);
        value.tenant = [0; 32];
        value.repository = [0; 32];
        value.commit.state_commitment = [0; 32];
        value.commit.outbox_commitment = [0; 32];
        value.event_schema = [0; 32];
        value.event_kind = [0; 32];
        value.authorization_policy = [0; 32];
        value.authorization_scope = [0; 32];
        value.snapshot.as_mut().unwrap().digest = [0; 32];
        value.payload_digest = [0; 32];
        let event = seal_event(value).unwrap();

        let cursor_key = cursor_key(21);
        let page = replay_page(
            ReplayRequest {
                tenant: [0; 32],
                repository: [0; 32],
                authorization_scope: [0; 32],
                authority_epoch: 17,
                repository_generation: 7,
                retained_floor: 1,
                high_watermark: 1,
                start: ReplayStart::Sequence(1),
                page_limit: 1,
                cursor_ttl_ms: 1,
                now_unix_ms: NOW,
            },
            &[event],
            std::slice::from_ref(&cursor_key),
            &cursor_key,
        )
        .unwrap();
        assert_eq!(page.events.len(), 1);

        let webhook_key = webhook_key(41, NOW - 1, NOW + 1);
        let delivery = sign_webhook(
            &event,
            WebhookDeliveryInput {
                delivery_id: public_id(42),
                attempt: 1,
                sent_at_unix_ms: NOW,
                endpoint_scope: [0; 32],
                body_digest: [0; 32],
                body_bytes: 0,
            },
            &webhook_key,
        )
        .unwrap();
        let mut guard = DeliveryReplayGuard::new(1, 1).unwrap();
        verify_webhook(
            &delivery,
            &event,
            [0; 32],
            [0; 32],
            0,
            std::slice::from_ref(&webhook_key),
            NOW,
            0,
            &mut guard,
        )
        .unwrap();
    }

    #[test]
    fn replay_is_contiguous_bounded_and_returns_a_tail_cursor() {
        let key = cursor_key(21);
        let events = [event(1, 12), event(2, 12)];
        let first = replay_page(
            replay_request(ReplayStart::Sequence(1), 3),
            &events,
            std::slice::from_ref(&key),
            &key,
        )
        .unwrap();
        assert_eq!(first.delivered_through, Some(2));
        assert!(!first.caught_up);

        let tail = replay_page(
            replay_request(ReplayStart::Cursor(&first.next_cursor), 3),
            &[event(3, 12)],
            std::slice::from_ref(&key),
            &key,
        )
        .unwrap();
        assert_eq!(tail.delivered_through, Some(3));
        assert!(tail.caught_up);
        let poll = replay_page(
            replay_request(ReplayStart::Cursor(&tail.next_cursor), 3),
            &[],
            std::slice::from_ref(&key),
            &key,
        )
        .unwrap();
        assert!(poll.caught_up);
        assert_eq!(poll.delivered_through, None);
    }

    #[test]
    fn replay_rejects_missing_extra_reordered_cross_scope_and_tampered_events() {
        let key = cursor_key(21);
        let request = replay_request(ReplayStart::Sequence(1), 2);
        for supplied in [
            vec![event(1, 12)],
            vec![event(1, 12), event(2, 12), event(3, 12)],
            vec![event(2, 12), event(1, 12)],
            vec![event(1, 12), event(2, 13)],
        ] {
            assert_eq!(
                replay_page(request, &supplied, std::slice::from_ref(&key), &key)
                    .unwrap_err()
                    .code(),
                AutomationErrorCode::EventGap
            );
        }
        let mut tampered = event(2, 12);
        tampered.event_id[0] ^= 1;
        assert_eq!(
            replay_page(
                request,
                &[event(1, 12), tampered],
                std::slice::from_ref(&key),
                &key
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::EventInvalid
        );

        let mut future_draft = draft(1, 12);
        future_draft.authorization_evaluated_at_unix_ms = NOW + 1;
        let future_event = seal_event(future_draft).unwrap();
        assert_eq!(
            replay_page(
                replay_request(ReplayStart::Sequence(1), 1),
                &[future_event],
                std::slice::from_ref(&key),
                &key,
            )
            .unwrap_err()
            .context(),
            "replay-event-time"
        );

        let mut future_acknowledgement_draft = draft(1, 12);
        future_acknowledgement_draft.commit.acknowledged_at_unix_ms = NOW + 1;
        let future_acknowledgement_event = seal_event(future_acknowledgement_draft).unwrap();
        assert_eq!(
            replay_page(
                replay_request(ReplayStart::Sequence(1), 1),
                &[future_acknowledgement_event],
                std::slice::from_ref(&key),
                &key,
            )
            .unwrap_err()
            .context(),
            "replay-event-time"
        );
    }

    #[test]
    fn cursor_tamper_scope_expiry_generation_and_retention_are_fail_closed() {
        let key = cursor_key(21);
        let page = replay_page(
            replay_request(ReplayStart::Sequence(1), 1),
            &[event(1, 12)],
            std::slice::from_ref(&key),
            &key,
        )
        .unwrap();
        let token = page.next_cursor;
        verify_cursor(&token, std::slice::from_ref(&key), NOW).unwrap();
        assert_eq!(
            token.tag(),
            [
                0x98, 0x39, 0xd2, 0x0d, 0x28, 0xa8, 0xf2, 0x57, 0xbf, 0x71, 0xc7, 0x18, 0xf2, 0x5a,
                0x6f, 0x56, 0x6f, 0x3d, 0x35, 0x77, 0x0c, 0x08, 0xfe, 0x48, 0x10, 0x6b, 0x8b, 0xd8,
                0xc9, 0xcb, 0x04, 0x72,
            ]
        );

        assert_cursor_claim_tamper(token, &key, |claims| claims.tenant[0] ^= 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.repository[0] ^= 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.authorization_scope[0] ^= 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.authority_epoch += 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.repository_generation += 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.next_sequence += 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.retained_floor_at_issue += 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.high_watermark_at_issue += 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.issued_at_unix_ms -= 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.expires_at_unix_ms += 1);
        assert_cursor_claim_tamper(token, &key, |claims| claims.key_id[0] ^= 1);
        let wrong_version =
            CursorToken::from_untrusted(token.version + 1, token.claims, token.tag());
        assert_eq!(
            verify_cursor(&wrong_version, std::slice::from_ref(&key), NOW)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorInvalid
        );

        let mut claims = token.claims;
        claims.next_sequence += 1;
        let tampered = CursorToken::from_untrusted(token.version, claims, token.tag());
        assert_eq!(
            verify_cursor(&tampered, std::slice::from_ref(&key), NOW)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorInvalid
        );
        let mut forged_expiry_claims = token.claims;
        forged_expiry_claims.expires_at_unix_ms = NOW - 1;
        let forged_expiry =
            CursorToken::from_untrusted(token.version, forged_expiry_claims, token.tag());
        assert_eq!(
            verify_cursor(&forged_expiry, std::slice::from_ref(&key), NOW)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorInvalid
        );
        assert_eq!(
            verify_cursor(
                &token,
                std::slice::from_ref(&key),
                token.claims.expires_at_unix_ms
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::CursorExpired
        );
        assert_eq!(
            verify_cursor(&token, std::slice::from_ref(&key), NOW - 1)
                .unwrap_err()
                .context(),
            "cursor-issued-in-future"
        );

        let mut impossible_claims = token.claims;
        impossible_claims.retained_floor_at_issue = impossible_claims.next_sequence + 1;
        let impossible = CursorToken::from_untrusted(
            token.version,
            impossible_claims,
            cursor_tag(&impossible_claims, &key.secret).unwrap(),
        );
        assert_eq!(
            verify_cursor(&impossible, std::slice::from_ref(&key), NOW)
                .unwrap_err()
                .context(),
            "cursor-claims"
        );
        let mut impossible_high_claims = token.claims;
        impossible_high_claims.high_watermark_at_issue = 0;
        let impossible_high = CursorToken::from_untrusted(
            token.version,
            impossible_high_claims,
            cursor_tag(&impossible_high_claims, &key.secret).unwrap(),
        );
        assert_eq!(
            verify_cursor(&impossible_high, std::slice::from_ref(&key), NOW)
                .unwrap_err()
                .context(),
            "cursor-claims"
        );

        let mut wrong_scope = replay_request(ReplayStart::Cursor(&token), 1);
        wrong_scope.authorization_scope = digest(44);
        assert_eq!(
            replay_page(wrong_scope, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorScopeMismatch
        );
        let mut stale = replay_request(ReplayStart::Cursor(&token), 1);
        stale.repository_generation += 1;
        assert_eq!(
            replay_page(stale, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorStale
        );
        let mut stale_epoch = replay_request(ReplayStart::Cursor(&token), 1);
        stale_epoch.authority_epoch += 1;
        assert_eq!(
            replay_page(stale_epoch, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorStale
        );
        let regressed_high_watermark = replay_request(ReplayStart::Cursor(&token), 0);
        assert_eq!(
            replay_page(
                regressed_high_watermark,
                &[],
                std::slice::from_ref(&key),
                &key,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::CursorStale
        );
        let mut expired = replay_request(ReplayStart::Cursor(&token), 2);
        expired.retained_floor = 3;
        assert_eq!(
            replay_page(expired, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::CursorExpired
        );
    }

    #[test]
    fn replay_page_cursor_and_key_limits_accept_exact_and_reject_plus_one() {
        let key = cursor_key(21);
        let mut exact = replay_request(ReplayStart::Sequence(1), 0);
        exact.retained_floor = 1;
        exact.page_limit = REPLAY_PAGE_EVENTS_HARD_MAXIMUM;
        exact.cursor_ttl_ms = CURSOR_TTL_MS_HARD_MAXIMUM;
        replay_page(exact, &[], std::slice::from_ref(&key), &key).unwrap();

        let exact_events: Vec<_> = (1..=REPLAY_PAGE_EVENTS_HARD_MAXIMUM)
            .map(|sequence| event(u64::try_from(sequence).unwrap(), 12))
            .collect();
        let mut exact_page_request = replay_request(
            ReplayStart::Sequence(1),
            u64::try_from(REPLAY_PAGE_EVENTS_HARD_MAXIMUM).unwrap(),
        );
        exact_page_request.page_limit = REPLAY_PAGE_EVENTS_HARD_MAXIMUM;
        let exact_page = replay_page(
            exact_page_request,
            &exact_events,
            std::slice::from_ref(&key),
            &key,
        )
        .unwrap();
        assert_eq!(exact_page.events.len(), REPLAY_PAGE_EVENTS_HARD_MAXIMUM);
        assert!(exact_page.caught_up);

        exact.page_limit += 1;
        assert_eq!(
            replay_page(exact, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::LimitExceeded
        );
        let overlong_supplied = vec![event(1, 12); REPLAY_PAGE_EVENTS_HARD_MAXIMUM + 1];
        let mut bounded_request = replay_request(ReplayStart::Sequence(1), 1_025);
        bounded_request.page_limit = REPLAY_PAGE_EVENTS_HARD_MAXIMUM;
        assert_eq!(
            replay_page(
                bounded_request,
                &overlong_supplied,
                std::slice::from_ref(&key),
                &key,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::LimitExceeded
        );
        let keys: Vec<_> = (1..=CURSOR_KEYS_HARD_MAXIMUM)
            .map(|index| cursor_key(index as u8 + 30))
            .collect();
        verify_cursor(
            &seal_cursor(
                CursorClaims {
                    tenant: digest(1),
                    repository: digest(2),
                    authorization_scope: digest(12),
                    authority_epoch: 17,
                    repository_generation: 1,
                    next_sequence: 1,
                    retained_floor_at_issue: 1,
                    high_watermark_at_issue: 0,
                    issued_at_unix_ms: NOW,
                    expires_at_unix_ms: NOW + 1,
                    key_id: keys[0].key_id(),
                },
                &keys[0],
            )
            .unwrap(),
            &keys,
            NOW,
        )
        .unwrap();
        let mut plus_one = keys;
        plus_one.push(cursor_key(99));
        assert_eq!(
            validate_cursor_keys(&plus_one).unwrap_err().code(),
            AutomationErrorCode::LimitExceeded
        );

        let same_id_wrong_secret =
            CursorSigningKey::new(key.key_id(), digest(98), NOW - 10_000, NOW + 10_000).unwrap();
        assert_eq!(
            replay_page(
                replay_request(ReplayStart::Sequence(1), 0),
                &[],
                std::slice::from_ref(&key),
                &same_id_wrong_secret,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::CursorInvalid
        );
        let same_id_secret_wrong_window =
            CursorSigningKey::new(key.key_id(), digest(21), NOW - 9_999, NOW + 10_000).unwrap();
        assert_eq!(
            replay_page(
                replay_request(ReplayStart::Sequence(1), 0),
                &[],
                std::slice::from_ref(&key),
                &same_id_secret_wrong_window,
            )
            .unwrap_err()
            .context(),
            "cursor-signing-key-absent"
        );
        let exact_recreated =
            CursorSigningKey::new(key.key_id(), digest(21), NOW - 10_000, NOW + 10_000).unwrap();
        replay_page(
            replay_request(ReplayStart::Sequence(1), 0),
            &[],
            std::slice::from_ref(&key),
            &exact_recreated,
        )
        .unwrap();
        let duplicate_id_keys = [
            cursor_key(21),
            CursorSigningKey::new(public_id(21), digest(98), NOW - 10_000, NOW + 10_000).unwrap(),
        ];
        assert_eq!(
            validate_cursor_keys(&duplicate_id_keys)
                .unwrap_err()
                .context(),
            "cursor-key-duplicate"
        );
        assert_eq!(
            replay_page(
                replay_request(ReplayStart::Sequence(0), 0),
                &[],
                std::slice::from_ref(&key),
                &key,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::InputInvalid
        );

        let maximum_event = event(EVENT_SEQUENCE_HARD_MAXIMUM, 12);
        let mut maximum_request = replay_request(
            ReplayStart::Sequence(EVENT_SEQUENCE_HARD_MAXIMUM),
            EVENT_SEQUENCE_HARD_MAXIMUM,
        );
        maximum_request.retained_floor = EVENT_SEQUENCE_HARD_MAXIMUM;
        maximum_request.page_limit = 1;
        let maximum_page = replay_page(
            maximum_request,
            &[maximum_event],
            std::slice::from_ref(&key),
            &key,
        )
        .unwrap();
        assert_eq!(maximum_page.next_cursor.claims.next_sequence, u64::MAX);
        assert!(maximum_page.caught_up);

        let over_maximum = replay_request(ReplayStart::Sequence(1), u64::MAX);
        assert_eq!(
            replay_page(over_maximum, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::LimitExceeded
        );
        let mut zero_epoch = replay_request(ReplayStart::Sequence(1), 0);
        zero_epoch.authority_epoch = 0;
        assert_eq!(
            replay_page(zero_epoch, &[], std::slice::from_ref(&key), &key)
                .unwrap_err()
                .code(),
            AutomationErrorCode::InputInvalid
        );
    }

    fn webhook_input(delivery: u8, attempt: u16, sent: u64) -> WebhookDeliveryInput {
        WebhookDeliveryInput {
            delivery_id: public_id(delivery),
            attempt,
            sent_at_unix_ms: sent,
            endpoint_scope: digest(31),
            body_digest: digest(32),
            body_bytes: 512,
        }
    }

    fn assert_webhook_tamper_is_rejected(mutator: impl FnOnce(&mut WebhookEnvelope)) {
        let event = event(1, 12);
        let key = webhook_key(41, NOW - 10_000, NOW + 10_000);
        let mut delivery = sign_webhook(&event, webhook_input(42, 1, NOW), &key).unwrap();
        mutator(&mut delivery);
        let mut guard = DeliveryReplayGuard::new(4, 1_000).unwrap();
        assert_eq!(
            verify_webhook(
                &delivery,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW,
                100,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::SignatureInvalid
        );
        assert!(guard.is_empty());
    }

    #[test]
    fn webhook_signature_duplicate_forgery_staleness_and_body_binding_are_exact() {
        let event = event(1, 12);
        let key = webhook_key(41, NOW - 10_000, NOW + 10_000);
        let delivery = sign_webhook(&event, webhook_input(42, 1, NOW), &key).unwrap();
        assert_eq!(
            delivery.signature(),
            [
                0x2f, 0x03, 0x42, 0x5b, 0xfe, 0xe7, 0xa2, 0x01, 0x4f, 0x5e, 0xf0, 0xe3, 0xab, 0x2b,
                0x71, 0x66, 0x3e, 0x75, 0x7f, 0x49, 0xd0, 0x42, 0xa0, 0xb6, 0x05, 0x8e, 0xac, 0x02,
                0x28, 0x08, 0x0c, 0xc0,
            ]
        );
        let mut guard = DeliveryReplayGuard::new(4, 1_000).unwrap();
        let first = verify_webhook(
            &delivery,
            &event,
            digest(31),
            digest(32),
            512,
            std::slice::from_ref(&key),
            NOW,
            100,
            &mut guard,
        )
        .unwrap();
        assert_eq!(first.replay, ReplayDisposition::FirstSeen);
        let duplicate = verify_webhook(
            &delivery,
            &event,
            digest(31),
            digest(32),
            512,
            std::slice::from_ref(&key),
            NOW,
            100,
            &mut guard,
        )
        .unwrap();
        assert_eq!(duplicate.replay, ReplayDisposition::Duplicate);

        let forged = WebhookEnvelope::from_untrusted(
            delivery.version,
            delivery.event_id,
            delivery.tenant,
            delivery.repository,
            delivery.repository_generation,
            delivery.sequence,
            delivery.authorization_scope,
            delivery.delivery_id,
            delivery.attempt,
            delivery.sent_at_unix_ms,
            delivery.endpoint_scope,
            delivery.body_digest,
            delivery.body_bytes,
            delivery.key_id,
            digest(99),
        );
        assert_eq!(
            verify_webhook(
                &forged,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::SignatureInvalid
        );
        assert_eq!(guard.len(), 1);
        let mut forged_scope = delivery;
        forged_scope.endpoint_scope[0] ^= 1;
        assert_eq!(
            verify_webhook(
                &forged_scope,
                &event,
                digest(31),
                digest(33),
                512,
                std::slice::from_ref(&key),
                NOW + 101,
                100,
                &mut guard,
            )
            .unwrap_err()
            .context(),
            "webhook-signature"
        );
        assert_eq!(guard.len(), 1);
        assert_eq!(
            verify_webhook(
                &forged,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW + 101,
                100,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::SignatureInvalid
        );
        assert_eq!(
            verify_webhook(
                &delivery,
                &event,
                digest(31),
                digest(33),
                512,
                std::slice::from_ref(&key),
                NOW,
                100,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::SignatureInvalid
        );
        assert_eq!(
            verify_webhook(
                &delivery,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW + 101,
                100,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::TimestampInvalid
        );
    }

    #[test]
    fn webhook_cannot_precede_commit_or_declared_authorization_evaluation() {
        let delivery_event = event(1, 12);
        let key = webhook_key(41, NOW - 10_000, NOW + 10_000);
        let before_delivery_evaluation =
            delivery_event.draft.authorization_evaluated_at_unix_ms - 1;
        assert_eq!(
            sign_webhook(
                &delivery_event,
                webhook_input(43, 1, before_delivery_evaluation),
                &key,
            )
            .unwrap_err()
            .context(),
            "webhook-event-time"
        );

        let mut frozen_draft = draft(1, 12);
        frozen_draft.authorization_evaluation = AuthorizationEvaluation::FrozenAtCommit;
        frozen_draft.authorization_evaluated_at_unix_ms =
            frozen_draft.commit.committed_at_unix_ms - 1;
        let frozen_event = seal_event(frozen_draft).unwrap();
        assert_eq!(
            sign_webhook(
                &frozen_event,
                webhook_input(44, 1, frozen_event.draft.commit.committed_at_unix_ms - 1),
                &key,
            )
            .unwrap_err()
            .context(),
            "webhook-event-time"
        );

        let input = webhook_input(45, 1, before_delivery_evaluation);
        let mut signed_impossible = WebhookEnvelope::from_untrusted(
            WEBHOOK_VERSION,
            delivery_event.event_id,
            delivery_event.draft.tenant,
            delivery_event.draft.repository,
            delivery_event.draft.repository_generation,
            delivery_event.draft.sequence,
            delivery_event.draft.authorization_scope,
            input.delivery_id,
            input.attempt,
            input.sent_at_unix_ms,
            input.endpoint_scope,
            input.body_digest,
            input.body_bytes,
            key.key_id(),
            [0; 32],
        );
        signed_impossible.signature = webhook_tag(&signed_impossible, &key.secret).unwrap();
        let mut guard = DeliveryReplayGuard::new(1, 1).unwrap();
        assert_eq!(
            verify_webhook(
                &signed_impossible,
                &delivery_event,
                input.endpoint_scope,
                input.body_digest,
                input.body_bytes,
                std::slice::from_ref(&key),
                input.sent_at_unix_ms,
                0,
                &mut guard,
            )
            .unwrap_err()
            .context(),
            "webhook-event-time"
        );
        assert!(guard.is_empty());
    }

    #[test]
    fn every_webhook_projection_field_is_authenticated_before_replay_state() {
        assert_webhook_tamper_is_rejected(|value| value.version += 1);
        assert_webhook_tamper_is_rejected(|value| value.event_id[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.tenant[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.repository[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.repository_generation += 1);
        assert_webhook_tamper_is_rejected(|value| value.sequence += 1);
        assert_webhook_tamper_is_rejected(|value| value.authorization_scope[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.delivery_id[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.attempt += 1);
        assert_webhook_tamper_is_rejected(|value| value.sent_at_unix_ms += 1);
        assert_webhook_tamper_is_rejected(|value| value.endpoint_scope[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.body_digest[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.body_bytes += 1);
        assert_webhook_tamper_is_rejected(|value| value.key_id[0] ^= 1);
        assert_webhook_tamper_is_rejected(|value| value.signature[0] ^= 1);
    }

    #[test]
    fn replay_guard_scopes_ids_and_rejects_conflicting_attempt_envelopes() {
        let first_event = event(1, 12);
        let second_event = event(2, 12);
        let other_scope_event = event(1, 13);
        let key = webhook_key(41, NOW - 10_000, NOW + 10_000);
        let base_input = webhook_input(80, 1, NOW);
        let first = sign_webhook(&first_event, base_input, &key).unwrap();
        let mut guard = DeliveryReplayGuard::new(8, 1_000).unwrap();
        assert_eq!(
            verify_webhook(
                &first,
                &first_event,
                base_input.endpoint_scope,
                base_input.body_digest,
                base_input.body_bytes,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap()
            .replay,
            ReplayDisposition::FirstSeen
        );

        let mut other_endpoint_input = base_input;
        other_endpoint_input.endpoint_scope = digest(81);
        let other_endpoint = sign_webhook(&first_event, other_endpoint_input, &key).unwrap();
        assert_eq!(
            verify_webhook(
                &other_endpoint,
                &first_event,
                base_input.endpoint_scope,
                other_endpoint_input.body_digest,
                other_endpoint_input.body_bytes,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::SignatureInvalid
        );
        assert_eq!(guard.len(), 1);
        assert_eq!(
            verify_webhook(
                &other_endpoint,
                &first_event,
                other_endpoint_input.endpoint_scope,
                other_endpoint_input.body_digest,
                other_endpoint_input.body_bytes,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap()
            .replay,
            ReplayDisposition::FirstSeen
        );

        let other_scope = sign_webhook(&other_scope_event, base_input, &key).unwrap();
        assert_eq!(
            verify_webhook(
                &other_scope,
                &other_scope_event,
                base_input.endpoint_scope,
                base_input.body_digest,
                base_input.body_bytes,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap()
            .replay,
            ReplayDisposition::FirstSeen
        );
        assert_eq!(guard.len(), 3);

        let conflicting_event = sign_webhook(&second_event, base_input, &key).unwrap();
        assert_eq!(
            verify_webhook(
                &conflicting_event,
                &second_event,
                base_input.endpoint_scope,
                base_input.body_digest,
                base_input.body_bytes,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::ReplayConflict
        );
        assert_eq!(guard.len(), 3);

        let mut conflicting_body_input = base_input;
        conflicting_body_input.body_digest = digest(82);
        let conflicting_body = sign_webhook(&first_event, conflicting_body_input, &key).unwrap();
        assert_eq!(
            verify_webhook(
                &conflicting_body,
                &first_event,
                conflicting_body_input.endpoint_scope,
                conflicting_body_input.body_digest,
                conflicting_body_input.body_bytes,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::ReplayConflict
        );
        assert_eq!(guard.len(), 3);

        let second_attempt = sign_webhook(&first_event, webhook_input(80, 2, NOW), &key).unwrap();
        assert_eq!(second_attempt.event_id, first.event_id);
        assert_eq!(
            verify_webhook(
                &second_attempt,
                &first_event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap()
            .replay,
            ReplayDisposition::FirstSeen
        );
        assert_eq!(guard.len(), 4);
    }

    #[test]
    fn webhook_rotation_and_key_set_ambiguity_are_fail_closed() {
        let event = event(1, 12);
        let keys = [
            webhook_key(41, NOW - 10_000, NOW),
            webhook_key(42, NOW, NOW + 10_000),
        ];
        let old_delivery = sign_webhook(&event, webhook_input(50, 1, NOW), &keys[0]).unwrap();
        let new_delivery = sign_webhook(&event, webhook_input(51, 1, NOW), &keys[1]).unwrap();
        let mut guard = DeliveryReplayGuard::new(4, 1_000).unwrap();
        verify_webhook(
            &old_delivery,
            &event,
            digest(31),
            digest(32),
            512,
            &keys,
            NOW,
            0,
            &mut guard,
        )
        .unwrap();
        verify_webhook(
            &new_delivery,
            &event,
            digest(31),
            digest(32),
            512,
            &keys,
            NOW,
            0,
            &mut guard,
        )
        .unwrap();
        let duplicate_id_keys = [
            webhook_key(41, NOW - 10_000, NOW),
            webhook_key(41, NOW - 10_000, NOW),
        ];
        assert_eq!(
            validate_webhook_keys(&duplicate_id_keys)
                .unwrap_err()
                .code(),
            AutomationErrorCode::SignatureInvalid
        );
    }

    #[test]
    fn replay_guard_capacity_and_expiry_are_bounded_without_consuming_failures() {
        let event = event(1, 12);
        let key = webhook_key(41, NOW - 10_000, NOW + 10_000);
        let first = sign_webhook(&event, webhook_input(61, 1, NOW), &key).unwrap();
        let second = sign_webhook(&event, webhook_input(62, 1, NOW), &key).unwrap();
        let mut guard = DeliveryReplayGuard::new(1, 10).unwrap();
        verify_webhook(
            &first,
            &event,
            digest(31),
            digest(32),
            512,
            std::slice::from_ref(&key),
            NOW,
            0,
            &mut guard,
        )
        .unwrap();
        assert_eq!(
            verify_webhook(
                &second,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::ReplayGuardFull
        );
        assert_eq!(guard.len(), 1);
        let second_at_expiry = sign_webhook(&event, webhook_input(62, 1, NOW + 10), &key).unwrap();
        verify_webhook(
            &second_at_expiry,
            &event,
            digest(31),
            digest(32),
            512,
            std::slice::from_ref(&key),
            NOW + 10,
            0,
            &mut guard,
        )
        .unwrap();
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn replay_guard_expiry_overflow_fails_without_mutation() {
        let event = event(1, 12);
        let sent_at = u64::MAX - 1;
        let key = webhook_key(91, sent_at - 1, u64::MAX);
        let delivery = sign_webhook(&event, webhook_input(92, 1, sent_at), &key).unwrap();
        let mut guard = DeliveryReplayGuard::new(1, 2).unwrap();
        assert_eq!(
            verify_webhook(
                &delivery,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                sent_at,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::AccountingOverflow
        );
        assert!(guard.is_empty());
    }

    #[test]
    fn webhook_and_replay_guard_hard_limits_have_exact_edges() {
        let event = event(1, 12);
        let key = webhook_key(41, NOW - 10_000, NOW + 10_000);
        let mut input = webhook_input(70, 1, NOW);
        input.body_bytes = WEBHOOK_BODY_BYTES_HARD_MAXIMUM;
        sign_webhook(&event, input, &key).unwrap();
        let exact_delivery = sign_webhook(&event, input, &key).unwrap();
        let full_replay_window = WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM * 2 + 1;
        let mut guard = DeliveryReplayGuard::new(1, full_replay_window).unwrap();
        assert_eq!(
            verify_webhook(
                &exact_delivery,
                &event,
                input.endpoint_scope,
                input.body_digest,
                WEBHOOK_BODY_BYTES_HARD_MAXIMUM + 1,
                std::slice::from_ref(&key),
                NOW,
                0,
                &mut guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::LimitExceeded
        );
        assert!(guard.is_empty());
        let mut exact_body_guard = DeliveryReplayGuard::new(1, 1).unwrap();
        verify_webhook(
            &exact_delivery,
            &event,
            input.endpoint_scope,
            input.body_digest,
            WEBHOOK_BODY_BYTES_HARD_MAXIMUM,
            std::slice::from_ref(&key),
            NOW,
            0,
            &mut exact_body_guard,
        )
        .unwrap();

        let exact_clock_delivery = sign_webhook(&event, webhook_input(71, 1, NOW), &key).unwrap();
        let earliest = verify_webhook(
            &exact_clock_delivery,
            &event,
            digest(31),
            digest(32),
            512,
            std::slice::from_ref(&key),
            NOW - WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM,
            WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM,
            &mut guard,
        )
        .unwrap();
        assert_eq!(earliest.replay, ReplayDisposition::FirstSeen);
        let latest = verify_webhook(
            &exact_clock_delivery,
            &event,
            digest(31),
            digest(32),
            512,
            std::slice::from_ref(&key),
            NOW + WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM,
            WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM,
            &mut guard,
        )
        .unwrap();
        assert_eq!(latest.replay, ReplayDisposition::Duplicate);
        let mut insufficient_guard = DeliveryReplayGuard::new(1, full_replay_window - 1).unwrap();
        assert_eq!(
            verify_webhook(
                &exact_clock_delivery,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW,
                WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM,
                &mut insufficient_guard,
            )
            .unwrap_err()
            .context(),
            "replay-guard-retention-window"
        );
        assert!(insufficient_guard.is_empty());
        let mut unused_guard = DeliveryReplayGuard::new(1, 1).unwrap();
        assert_eq!(
            verify_webhook(
                &exact_clock_delivery,
                &event,
                digest(31),
                digest(32),
                512,
                std::slice::from_ref(&key),
                NOW,
                WEBHOOK_CLOCK_SKEW_MS_HARD_MAXIMUM + 1,
                &mut unused_guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::LimitExceeded
        );
        assert!(unused_guard.is_empty());

        let exact_keys: Vec<_> = (0..WEBHOOK_KEYS_HARD_MAXIMUM)
            .map(|index| webhook_key(100 + u8::try_from(index).unwrap(), NOW - 1, NOW + 1))
            .collect();
        let exact_key_delivery =
            sign_webhook(&event, webhook_input(72, 1, NOW), &exact_keys[0]).unwrap();
        let mut exact_key_guard = DeliveryReplayGuard::new(1, 1).unwrap();
        verify_webhook(
            &exact_key_delivery,
            &event,
            digest(31),
            digest(32),
            512,
            &exact_keys,
            NOW,
            0,
            &mut exact_key_guard,
        )
        .unwrap();
        let mut plus_one_keys = exact_keys;
        plus_one_keys.push(webhook_key(110, NOW - 1, NOW + 1));
        let mut plus_one_guard = DeliveryReplayGuard::new(1, 1).unwrap();
        assert_eq!(
            verify_webhook(
                &exact_key_delivery,
                &event,
                digest(31),
                digest(32),
                512,
                &plus_one_keys,
                NOW,
                0,
                &mut plus_one_guard,
            )
            .unwrap_err()
            .code(),
            AutomationErrorCode::LimitExceeded
        );
        assert!(plus_one_guard.is_empty());

        input.body_bytes += 1;
        assert_eq!(
            sign_webhook(&event, input, &key).unwrap_err().code(),
            AutomationErrorCode::LimitExceeded
        );
        DeliveryReplayGuard::new(
            REPLAY_GUARD_ENTRIES_HARD_MAXIMUM,
            REPLAY_GUARD_RETENTION_MS_HARD_MAXIMUM,
        )
        .unwrap();
        assert_eq!(
            DeliveryReplayGuard::new(REPLAY_GUARD_ENTRIES_HARD_MAXIMUM + 1, 1)
                .unwrap_err()
                .code(),
            AutomationErrorCode::LimitExceeded
        );
        assert_eq!(
            DeliveryReplayGuard::new(1, REPLAY_GUARD_RETENTION_MS_HARD_MAXIMUM + 1)
                .unwrap_err()
                .code(),
            AutomationErrorCode::LimitExceeded
        );
    }

    fn provenance_input() -> BuildProvenanceInput {
        BuildProvenanceInput {
            tenant: digest(1),
            repository: digest(2),
            snapshot: ObjectRef {
                kind: ObjectKind::Snapshot,
                digest: digest(3),
            },
            selection_policy_digest: digest(4),
            materialized_root_digest: digest(5),
            client_version_digest: digest(6),
            toolchain_digest: digest(7),
            input_set_digest: digest(8),
            build_result_digest: Some(digest(9)),
            started_at_unix_ms: NOW,
            completed_at_unix_ms: NOW + 1,
        }
    }

    fn assert_provenance_binding_changes(mutator: impl FnOnce(&mut BuildProvenanceInput)) {
        let original = seal_build_provenance(provenance_input())
            .unwrap()
            .provenance_digest;
        let mut changed = provenance_input();
        mutator(&mut changed);
        assert_ne!(
            seal_build_provenance(changed).unwrap().provenance_digest,
            original
        );
    }

    #[test]
    fn build_provenance_is_deterministic_and_self_checking() {
        let value = seal_build_provenance(provenance_input()).unwrap();
        assert_eq!(value, seal_build_provenance(provenance_input()).unwrap());
        value.verify().unwrap();
        assert_eq!(
            value.provenance_digest,
            [
                0x74, 0xa6, 0x58, 0xdc, 0xc9, 0xc5, 0xd2, 0x59, 0xd2, 0x97, 0x7e, 0xd4, 0xb1, 0x57,
                0x6c, 0xa8, 0x0e, 0xf0, 0x2b, 0x65, 0x40, 0xce, 0x87, 0x6e, 0x82, 0x85, 0xdc, 0x43,
                0x0b, 0x2c, 0xb3, 0xfb,
            ]
        );
        assert_provenance_binding_changes(|input| input.tenant = digest(51));
        assert_provenance_binding_changes(|input| input.repository = digest(52));
        assert_provenance_binding_changes(|input| input.snapshot.digest = digest(53));
        assert_provenance_binding_changes(|input| input.selection_policy_digest = digest(54));
        assert_provenance_binding_changes(|input| input.materialized_root_digest = digest(55));
        assert_provenance_binding_changes(|input| input.client_version_digest = digest(56));
        assert_provenance_binding_changes(|input| input.toolchain_digest = digest(57));
        assert_provenance_binding_changes(|input| input.input_set_digest = digest(58));
        assert_provenance_binding_changes(|input| input.build_result_digest = None);
        assert_provenance_binding_changes(|input| input.build_result_digest = Some(digest(59)));
        assert_provenance_binding_changes(|input| input.started_at_unix_ms -= 1);
        assert_provenance_binding_changes(|input| input.completed_at_unix_ms += 1);
        let mut tampered = value;
        tampered.input.completed_at_unix_ms += 1;
        assert_eq!(
            tampered.verify().unwrap_err().code(),
            AutomationErrorCode::ProvenanceInvalid
        );
        tampered = value;
        tampered.provenance_digest[0] ^= 1;
        assert_eq!(
            tampered.verify().unwrap_err().context(),
            "provenance-binding"
        );
        tampered = value;
        tampered.version += 1;
        assert_eq!(
            tampered.verify().unwrap_err().context(),
            "provenance-binding"
        );
    }

    #[test]
    fn provenance_requires_snapshot_and_accepts_zero_cryptographic_digests() {
        let mut input = provenance_input();
        input.snapshot.kind = ObjectKind::Tree;
        assert_eq!(
            seal_build_provenance(input).unwrap_err().code(),
            AutomationErrorCode::ProvenanceInvalid
        );
        input = provenance_input();
        input.tenant = [0; 32];
        input.repository = [0; 32];
        input.snapshot.digest = [0; 32];
        input.selection_policy_digest = [0; 32];
        input.materialized_root_digest = [0; 32];
        input.client_version_digest = [0; 32];
        input.toolchain_digest = [0; 32];
        input.input_set_digest = [0; 32];
        input.build_result_digest = Some([0; 32]);
        seal_build_provenance(input).unwrap();
    }

    #[test]
    fn signing_keys_are_domain_separated_non_cloneable_and_redacted() {
        let cursor = cursor_key(21);
        let webhook = webhook_key(21, NOW - 10, NOW + 10);
        assert_eq!(cursor.key_id(), webhook.key_id());
        let cursor_token = replay_page(
            replay_request(ReplayStart::Sequence(1), 0),
            &[],
            std::slice::from_ref(&cursor),
            &cursor,
        )
        .unwrap()
        .next_cursor;
        let webhook_envelope =
            sign_webhook(&event(1, 12), webhook_input(94, 1, NOW), &webhook).unwrap();
        assert!(format!("{cursor_token:?}").contains("<redacted>"));
        assert!(format!("{webhook_envelope:?}").contains("<redacted>"));
        assert!(format!("{:?}", event(1, 12)).contains("<redacted>"));
        assert!(
            format!("{:?}", seal_build_provenance(provenance_input()).unwrap())
                .contains("<redacted>")
        );
        assert_eq!(
            CursorSigningKey::new([0; 16], digest(1), 0, 1)
                .err()
                .unwrap()
                .code(),
            AutomationErrorCode::InputInvalid
        );
        assert_eq!(
            WebhookSigningKey::new(public_id(1), [0; 32], 0, 1)
                .err()
                .unwrap()
                .code(),
            AutomationErrorCode::InputInvalid
        );
        assert_eq!(
            CursorSigningKey::new(public_id(1), digest(1), 2, 1)
                .err()
                .unwrap()
                .code(),
            AutomationErrorCode::InputInvalid
        );
        assert_eq!(
            WebhookSigningKey::new(public_id(1), digest(1), 2, 1)
                .err()
                .unwrap()
                .code(),
            AutomationErrorCode::InputInvalid
        );
    }
}
