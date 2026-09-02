use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::client_hello::{decode_client_hello_after_preflight, preflight_client_hello};
use crate::commitment::{CommitmentBuilder, Digest32};
use crate::model::*;

const LEDGER_BASE_LOGICAL_BYTES: usize = 512;
const REPLAY_LOGICAL_BYTES: usize = 96;
const IDEMPOTENCY_BASE_LOGICAL_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerLimits {
    retained_logical_bytes_maximum: usize,
    retained_records_maximum: usize,
}

impl LedgerLimits {
    pub const HARD_MAXIMUM: Self = Self {
        retained_logical_bytes_maximum: RETAINED_LOGICAL_BYTES_MAXIMUM,
        retained_records_maximum: RETAINED_RECORDS_MAXIMUM,
    };

    pub fn narrowed(
        retained_logical_bytes_maximum: usize,
        retained_records_maximum: usize,
    ) -> Result<Self> {
        let limits = Self {
            retained_logical_bytes_maximum,
            retained_records_maximum,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub const fn retained_logical_bytes_maximum(self) -> usize {
        self.retained_logical_bytes_maximum
    }

    pub const fn retained_records_maximum(self) -> usize {
        self.retained_records_maximum
    }

    fn validate(self) -> Result<()> {
        if !(LEDGER_BASE_LOGICAL_BYTES..=RETAINED_LOGICAL_BYTES_MAXIMUM)
            .contains(&self.retained_logical_bytes_maximum)
            || self.retained_records_maximum == 0
            || self.retained_records_maximum > RETAINED_RECORDS_MAXIMUM
        {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        Ok(())
    }
}

impl Default for LedgerLimits {
    fn default() -> Self {
        Self::HARD_MAXIMUM
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionRecord {
    facts: HandshakeFacts,
    selection: NegotiationSelection,
    transcript_commitment: Digest32,
    logical_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsentRecord {
    facts: ConsentGrantFacts,
    capabilities: BTreeSet<Capability>,
    grant_commitment: Digest32,
    revoked: bool,
    revocation_commitment: Option<Digest32>,
    logical_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IdempotencyRecord {
    consent_generation: u64,
    consent_grant_commitment: Digest32,
    request_commitment: Digest32,
    receipt: OperationReceipt,
    expires_at_ms: u64,
    logical_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedEvent {
    facts: StatusEventFact,
    event_commitment: Digest32,
    issued_cursor_expires_at_ms: Option<u64>,
    logical_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SubscriptionRecord {
    facts: SubscriptionFacts,
    consent_generation: u64,
    consent_grant_commitment: Digest32,
    subscription_commitment: Digest32,
    generation: u64,
    next_sequence: u64,
    acknowledged_sequence: u64,
    acknowledged_state_commitment: StateCommitment,
    acknowledged_cursor_expires_at_ms: u64,
    max_delivered_sequence: u64,
    last_event_commitment: Option<Digest32>,
    queue: VecDeque<QueuedEvent>,
    logical_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HandoffRecord {
    facts: TrustedHandoffFacts,
    consent_generation: u64,
    consent_grant_commitment: Digest32,
    handoff_commitment: Digest32,
    consumed: bool,
    consumption_receipt: Option<Digest32>,
    logical_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub revision: u64,
    pub last_supplied_time_ms: u64,
    pub retained_logical_bytes: usize,
    pub session_records: usize,
    pub replay_records: usize,
    pub consent_records: usize,
    pub idempotency_records: usize,
    pub subscription_records: usize,
    pub queued_events: usize,
    pub handoff_records: usize,
    pub state_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerConfiguration {
    pub installation: InstallationIdentity,
    pub endpoint: EndpointIdentity,
    pub verifier_key_generation: u64,
    pub agent_support: NegotiationOffer,
    pub limits: LedgerLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentRevocationFacts {
    pub consent_id: ConsentId,
    pub expected_generation: u64,
    pub external_verification: ExternalVerdict,
    pub revocation_commitment: Digest32,
}

#[derive(Clone, Copy)]
struct AccessContext {
    consent_id: ConsentId,
    session_id: SessionId,
    integration_id: IntegrationId,
    workspace_id: WorkspaceId,
    repository_id: RepositoryId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionReceipt {
    pub session_id: SessionId,
    pub selection: NegotiationSelection,
    pub transcript_commitment: Digest32,
    pub expires_at_ms: u64,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsentReceipt {
    pub consent_id: ConsentId,
    pub generation: u64,
    pub grant_commitment: Digest32,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationAdmissionDisposition {
    Admitted,
    IdempotentReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    pub request_commitment: Digest32,
    pub operation: OperationKind,
    pub idempotency_key: IdempotencyKey,
    pub current_state_commitment: StateCommitment,
    pub lock_state_code: Option<u8>,
    pub admitted_at_ms: u64,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationAdmission {
    pub disposition: OperationAdmissionDisposition,
    pub receipt: OperationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusBatchReceipt {
    pub batch_commitment: Digest32,
    pub item_count: usize,
    pub complete: bool,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionReceipt {
    pub subscription_id: SubscriptionId,
    pub subscription_commitment: Digest32,
    pub initial_cursor: EventCursor,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventEnqueueDisposition {
    Enqueued,
    ExactDuplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventEnqueueReceipt {
    pub disposition: EventEnqueueDisposition,
    pub event_commitment: Digest32,
    pub next_sequence: u64,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventAckReceipt {
    pub subscription_id: SubscriptionId,
    pub cursor_commitment: Digest32,
    pub acknowledged_sequence: u64,
    pub removed_items: usize,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    pub events: Vec<StatusEventFact>,
    pub next_cursor: EventCursor,
    pub ledger_revision: u64,
    pub page_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffReceipt {
    pub handoff_id: HandoffId,
    pub handoff_commitment: Digest32,
    pub expires_at_ms: u64,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffConsumptionReceipt {
    pub handoff_id: HandoffId,
    pub handoff_commitment: Digest32,
    pub consumed_at_ms: u64,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotationReceipt {
    pub prior_installation_id: InstallationId,
    pub prior_installation_generation: u64,
    pub replacement_installation_id: InstallationId,
    pub replacement_installation_generation: u64,
    pub replacement_verifier_key_generation: u64,
    pub rotated_at_ms: u64,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReapReport {
    pub sessions: usize,
    pub replays: usize,
    pub consents: usize,
    pub idempotency: usize,
    pub subscriptions: usize,
    pub handoffs: usize,
    pub ledger_revision: u64,
    pub receipt_commitment: Digest32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAgentLedger {
    installation: InstallationIdentity,
    endpoint: EndpointIdentity,
    verifier_key_generation: u64,
    agent_support: NegotiationOffer,
    agent_support_commitment: Digest32,
    revision: u64,
    last_supplied_time_ms: u64,
    retained_logical_bytes: usize,
    limits: LedgerLimits,
    sessions: BTreeMap<SessionId, SessionRecord>,
    replay_ledger: BTreeMap<Digest32, u64>,
    consents: BTreeMap<ConsentId, ConsentRecord>,
    idempotency: BTreeMap<(IntegrationId, IdempotencyKey), IdempotencyRecord>,
    subscriptions: BTreeMap<SubscriptionId, SubscriptionRecord>,
    handoffs: BTreeMap<HandoffId, HandoffRecord>,
}

impl LocalAgentLedger {
    pub fn new(
        installation: InstallationIdentity,
        endpoint: EndpointIdentity,
        verifier_key_generation: u64,
        agent_support: NegotiationOffer,
        initial_time_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Self> {
        Self::new_with_limits(
            LedgerConfiguration {
                installation,
                endpoint,
                verifier_key_generation,
                agent_support,
                limits: LedgerLimits::default(),
            },
            initial_time_ms,
            raw,
            cancellation,
        )
    }

    pub fn new_with_limits(
        configuration: LedgerConfiguration,
        initial_time_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Self> {
        let LedgerConfiguration {
            installation,
            endpoint,
            verifier_key_generation,
            agent_support,
            limits,
        } = configuration;
        validate_raw_frame(raw)?;
        check_cancel(cancellation, CancellationPoint::Preflight)?;
        limits.validate()?;
        installation.validate()?;
        endpoint.validate()?;
        let expected_manifest = public_protocol_manifest_commitment()?;
        if agent_support.public_protocol_manifest != expected_manifest {
            return Err(Error::new(ErrorCode::BaselineMismatch));
        }
        let agent_support_commitment = agent_support.commitment()?;
        if verifier_key_generation == 0
            || endpoint.installation_id != installation.id
            || endpoint.installation_generation != installation.generation
        {
            return Err(Error::new(ErrorCode::InvalidIdentity));
        }
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        Ok(Self {
            installation,
            endpoint,
            verifier_key_generation,
            agent_support,
            agent_support_commitment,
            revision: 0,
            last_supplied_time_ms: initial_time_ms,
            retained_logical_bytes: LEDGER_BASE_LOGICAL_BYTES,
            limits,
            sessions: BTreeMap::new(),
            replay_ledger: BTreeMap::new(),
            consents: BTreeMap::new(),
            idempotency: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            handoffs: BTreeMap::new(),
        })
    }

    pub const fn installation(&self) -> &InstallationIdentity {
        &self.installation
    }

    pub const fn endpoint(&self) -> &EndpointIdentity {
        &self.endpoint
    }

    pub const fn verifier_key_generation(&self) -> u64 {
        self.verifier_key_generation
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            revision: self.revision,
            last_supplied_time_ms: self.last_supplied_time_ms,
            retained_logical_bytes: self.retained_logical_bytes,
            session_records: self.sessions.len(),
            replay_records: self.replay_ledger.len(),
            consent_records: self.consents.len(),
            idempotency_records: self.idempotency.len(),
            subscription_records: self.subscriptions.len(),
            queued_events: self
                .subscriptions
                .values()
                .map(|subscription| subscription.queue.len())
                .sum(),
            handoff_records: self.handoffs.len(),
            state_commitment: self.state_commitment(),
        }
    }

    fn state_commitment(&self) -> Digest32 {
        let mut builder = CommitmentBuilder::new("local-agent-ledger-state-v1");
        self.installation.commit_into(&mut builder);
        self.endpoint.commit_into(&mut builder);
        builder.u64(self.verifier_key_generation);
        builder.digest(self.agent_support_commitment);
        builder.u64(self.revision);
        builder.u64(self.last_supplied_time_ms);
        builder.usize(self.retained_logical_bytes);
        builder.usize(self.limits.retained_logical_bytes_maximum);
        builder.usize(self.limits.retained_records_maximum);
        builder.usize(self.sessions.len());
        for (id, record) in &self.sessions {
            builder.digest(id.digest());
            builder.digest(record.transcript_commitment);
            builder.digest(record.selection.selection_commitment);
            builder.u64(record.facts.expires_at_ms);
            builder.usize(record.logical_bytes);
        }
        builder.usize(self.replay_ledger.len());
        for (commitment, expiry) in &self.replay_ledger {
            builder.digest(*commitment);
            builder.u64(*expiry);
        }
        builder.usize(self.consents.len());
        for (id, record) in &self.consents {
            builder.digest(id.digest());
            builder.digest(record.grant_commitment);
            builder.bool(record.revoked);
            builder.bool(record.revocation_commitment.is_some());
            if let Some(commitment) = record.revocation_commitment {
                builder.digest(commitment);
            }
            builder.usize(record.logical_bytes);
        }
        builder.usize(self.idempotency.len());
        for ((integration, key), record) in &self.idempotency {
            builder.digest(integration.digest());
            builder.digest(key.digest());
            builder.u64(record.consent_generation);
            builder.digest(record.consent_grant_commitment);
            builder.digest(record.request_commitment);
            builder.digest(record.receipt.receipt_commitment);
            builder.u64(record.expires_at_ms);
            builder.usize(record.logical_bytes);
        }
        builder.usize(self.subscriptions.len());
        for (id, record) in &self.subscriptions {
            builder.digest(id.digest());
            builder.u64(record.consent_generation);
            builder.digest(record.consent_grant_commitment);
            builder.digest(record.subscription_commitment);
            builder.u64(record.generation);
            builder.u64(record.next_sequence);
            builder.u64(record.acknowledged_sequence);
            builder.digest(record.acknowledged_state_commitment.digest());
            builder.u64(record.acknowledged_cursor_expires_at_ms);
            builder.u64(record.max_delivered_sequence);
            builder.bool(record.last_event_commitment.is_some());
            if let Some(commitment) = record.last_event_commitment {
                builder.digest(commitment);
            }
            builder.usize(record.queue.len());
            for event in &record.queue {
                builder.digest(event.event_commitment);
                builder.bool(event.issued_cursor_expires_at_ms.is_some());
                if let Some(expiry) = event.issued_cursor_expires_at_ms {
                    builder.u64(expiry);
                }
                builder.usize(event.logical_bytes);
            }
            builder.usize(record.logical_bytes);
        }
        builder.usize(self.handoffs.len());
        for (id, record) in &self.handoffs {
            builder.digest(id.digest());
            builder.u64(record.consent_generation);
            builder.digest(record.consent_grant_commitment);
            builder.digest(record.handoff_commitment);
            builder.bool(record.consumed);
            builder.bool(record.consumption_receipt.is_some());
            if let Some(receipt) = record.consumption_receipt {
                builder.digest(receipt);
            }
            builder.usize(record.logical_bytes);
        }
        builder.finish()
    }

    fn preflight(
        &self,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Digest32> {
        let raw_commitment = validate_raw_frame(raw)?;
        check_cancel(cancellation, CancellationPoint::Preflight)?;
        if now_ms < self.last_supplied_time_ms {
            return Err(Error::new(ErrorCode::TimeReordered));
        }
        Ok(raw_commitment)
    }

    fn next_revision(&self) -> Result<u64> {
        self.revision
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))
    }

    fn commit_success(&mut self, now_ms: u64, revision: u64) {
        self.last_supplied_time_ms = now_ms;
        self.revision = revision;
    }

    fn record_count(&self) -> Result<usize> {
        let queued: usize =
            self.subscriptions
                .values()
                .try_fold(0usize, |count, subscription| {
                    count
                        .checked_add(subscription.queue.len())
                        .ok_or_else(|| Error::new(ErrorCode::StateLimit))
                })?;
        self.sessions
            .len()
            .checked_add(self.replay_ledger.len())
            .and_then(|count| count.checked_add(self.consents.len()))
            .and_then(|count| count.checked_add(self.idempotency.len()))
            .and_then(|count| count.checked_add(self.subscriptions.len()))
            .and_then(|count| count.checked_add(self.handoffs.len()))
            .and_then(|count| count.checked_add(queued))
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))
    }

    fn ensure_addition(&self, records: usize, bytes: usize) -> Result<usize> {
        let count = self
            .record_count()?
            .checked_add(records)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
        if count > self.limits.retained_records_maximum {
            return Err(Error::new(ErrorCode::StateLimit));
        }
        let retained = self
            .retained_logical_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
        if retained > self.limits.retained_logical_bytes_maximum {
            return Err(Error::new(ErrorCode::RetainedLimit));
        }
        Ok(retained)
    }

    pub fn establish_session(
        &mut self,
        verification: HandshakeVerificationFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<SessionReceipt> {
        let raw_frame_commitment = preflight_client_hello(raw)?;
        check_cancel(cancellation, CancellationPoint::Preflight)?;
        if now_ms < self.last_supplied_time_ms {
            return Err(Error::new(ErrorCode::TimeReordered));
        }
        let decoded = decode_client_hello_after_preflight(raw, raw_frame_commitment)?;
        verification.validate_shape(&decoded)?;
        verification.validate_time(now_ms)?;
        if verification.installation != self.installation
            || verification.endpoint != self.endpoint
            || verification.integration.installation_id != self.installation.id
            || verification.verifier_key_generation != self.verifier_key_generation
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        let selection = negotiate_bound(
            decoded.offer(),
            &self.agent_support,
            decoded.raw_frame_commitment(),
        )?;
        let facts =
            HandshakeFacts::from_verified(verification, decoded, self.agent_support.clone());
        facts.validate_shape()?;
        let transcript_commitment = facts.transcript_commitment(&selection);
        let challenge_replay_commitment = facts.challenge_replay_commitment();
        if self.sessions.contains_key(&facts.session_id)
            || self
                .replay_ledger
                .contains_key(&challenge_replay_commitment)
        {
            return Err(Error::new(ErrorCode::ReplayRejected));
        }
        if self.sessions.len() >= SESSION_RECORDS_MAXIMUM
            || self.replay_ledger.len() >= REPLAY_RECORDS_MAXIMUM
        {
            return Err(Error::new(ErrorCode::StateLimit));
        }
        let logical_bytes = facts.logical_bytes(&selection)?;
        let retained = self.ensure_addition(
            2,
            logical_bytes
                .checked_add(REPLAY_LOGICAL_BYTES)
                .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?,
        )?;
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("session-receipt-v1");
        builder.digest(facts.session_id.digest());
        builder.digest(selection.selection_commitment);
        builder.digest(transcript_commitment);
        builder.u64(facts.expires_at_ms);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = SessionReceipt {
            session_id: facts.session_id,
            selection: selection.clone(),
            transcript_commitment,
            expires_at_ms: facts.expires_at_ms,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.sessions.insert(
            facts.session_id,
            SessionRecord {
                facts: facts.clone(),
                selection,
                transcript_commitment,
                logical_bytes,
            },
        );
        self.replay_ledger
            .insert(challenge_replay_commitment, facts.expires_at_ms);
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn register_consent(
        &mut self,
        facts: ConsentGrantFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ConsentReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        let capabilities = facts.validate(now_ms)?;
        let session = self.active_session(facts.session_id, now_ms)?;
        if session.facts.integration.id != facts.integration_id
            || facts.session_id != session.facts.session_id
            || !capabilities
                .iter()
                .all(|capability| session.selection.capabilities.contains(capability))
        {
            return Err(Error::new(ErrorCode::CapabilityDenied));
        }
        if self.consents.contains_key(&facts.consent_id) {
            return Err(Error::new(ErrorCode::ReplayRejected));
        }
        if self.consents.len() >= CONSENT_RECORDS_MAXIMUM {
            return Err(Error::new(ErrorCode::StateLimit));
        }
        let logical_bytes = facts.logical_bytes()?;
        let retained = self.ensure_addition(1, logical_bytes)?;
        let grant_commitment = facts.commitment(&capabilities, raw_frame_commitment);
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("consent-registration-receipt-v1");
        builder.digest(facts.consent_id.digest());
        builder.u64(facts.generation);
        builder.digest(grant_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = ConsentReceipt {
            consent_id: facts.consent_id,
            generation: facts.generation,
            grant_commitment,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.consents.insert(
            facts.consent_id,
            ConsentRecord {
                facts,
                capabilities,
                grant_commitment,
                revoked: false,
                revocation_commitment: None,
                logical_bytes,
            },
        );
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn replace_consent(
        &mut self,
        facts: ConsentGrantFacts,
        expected_prior_commitment: Digest32,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ConsentReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        require_digest(expected_prior_commitment)?;
        let capabilities = facts.validate(now_ms)?;
        let session = self.active_session(facts.session_id, now_ms)?;
        if session.facts.integration.id != facts.integration_id
            || !capabilities
                .iter()
                .all(|capability| session.selection.capabilities.contains(capability))
        {
            return Err(Error::new(ErrorCode::CapabilityDenied));
        }
        let prior = self
            .consents
            .get(&facts.consent_id)
            .ok_or_else(|| Error::new(ErrorCode::ConsentUnknown))?;
        let expected_generation = prior
            .facts
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
        if prior.grant_commitment != expected_prior_commitment
            || facts.generation != expected_generation
            || prior.facts.integration_id != facts.integration_id
            || prior.facts.workspace_id != facts.workspace_id
            || prior.facts.repository_id != facts.repository_id
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        let logical_bytes = facts.logical_bytes()?;
        let without_prior = self
            .retained_logical_bytes
            .checked_sub(prior.logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        let retained = without_prior
            .checked_add(logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
        if retained > self.limits.retained_logical_bytes_maximum {
            return Err(Error::new(ErrorCode::RetainedLimit));
        }
        let grant_commitment = facts.commitment(&capabilities, raw_frame_commitment);
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("consent-replacement-receipt-v1");
        builder.digest(facts.consent_id.digest());
        builder.u64(facts.generation);
        builder.digest(expected_prior_commitment);
        builder.digest(grant_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = ConsentReceipt {
            consent_id: facts.consent_id,
            generation: facts.generation,
            grant_commitment,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.consents.insert(
            facts.consent_id,
            ConsentRecord {
                facts,
                capabilities,
                grant_commitment,
                revoked: false,
                revocation_commitment: None,
                logical_bytes,
            },
        );
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn revoke_consent(
        &mut self,
        facts: ConsentRevocationFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ConsentReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        require_digest(facts.consent_id.digest())?;
        require_digest(facts.revocation_commitment)?;
        if !facts.external_verification.is_verified() {
            return Err(Error::new(ErrorCode::ConsentUnknown));
        }
        let record = self
            .consents
            .get(&facts.consent_id)
            .ok_or_else(|| Error::new(ErrorCode::ConsentUnknown))?;
        if record.facts.generation != facts.expected_generation || record.revoked {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("consent-revocation-receipt-v1");
        builder.digest(facts.consent_id.digest());
        builder.u64(facts.expected_generation);
        builder.digest(record.grant_commitment);
        builder.digest(facts.revocation_commitment);
        builder.u8(facts.external_verification.code());
        builder.digest(raw_frame_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = ConsentReceipt {
            consent_id: facts.consent_id,
            generation: facts.expected_generation,
            grant_commitment: record.grant_commitment,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        let record = self
            .consents
            .get_mut(&facts.consent_id)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        record.revoked = true;
        record.revocation_commitment = Some(facts.revocation_commitment);
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    fn active_session(&self, session_id: SessionId, now_ms: u64) -> Result<&SessionRecord> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| Error::new(ErrorCode::SessionUnknown))?;
        if session.facts.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        if session.facts.installation != self.installation
            || session.facts.endpoint != self.endpoint
            || session.facts.verifier_key_generation != self.verifier_key_generation
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        Ok(session)
    }

    fn active_consent(
        &self,
        context: AccessContext,
        capability: Capability,
        now_ms: u64,
    ) -> Result<&ConsentRecord> {
        let session = self.active_session(context.session_id, now_ms)?;
        if session.facts.integration.id != context.integration_id {
            return Err(Error::new(ErrorCode::SessionUnknown));
        }
        let consent = self
            .consents
            .get(&context.consent_id)
            .ok_or_else(|| Error::new(ErrorCode::ConsentUnknown))?;
        if consent.revoked {
            return Err(Error::new(ErrorCode::ConsentRevoked));
        }
        if consent.facts.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        if consent.facts.session_id != context.session_id
            || consent.facts.integration_id != context.integration_id
            || consent.facts.workspace_id != context.workspace_id
            || consent.facts.repository_id != context.repository_id
        {
            return Err(Error::new(ErrorCode::ConsentUnknown));
        }
        if !consent.capabilities.contains(&capability) {
            return Err(Error::new(ErrorCode::CapabilityDenied));
        }
        Ok(consent)
    }

    pub fn admit_operation(
        &mut self,
        facts: OperationFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<OperationAdmission> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        facts.validate_shape()?;
        let idempotency_key = (facts.integration_id, facts.idempotency_key);
        let access = AccessContext {
            consent_id: facts.consent_id,
            session_id: facts.session_id,
            integration_id: facts.integration_id,
            workspace_id: facts.workspace_id,
            repository_id: facts.repository_id,
        };
        // Authorize and bind the current grant before revealing whether this
        // integration/idempotency key already exists.
        let consent = self.active_consent(access, facts.operation.capability(), now_ms)?;
        let consent_generation = consent.facts.generation;
        let consent_grant_commitment = consent.grant_commitment;
        let mut work = WorkBudget::new();
        if !facts.scope.is_subset_of(&consent.facts.scope, &mut work)? {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        let request_commitment = facts.commitment(
            consent_generation,
            consent_grant_commitment,
            raw_frame_commitment,
        );
        if let Some(existing) = self.idempotency.get(&idempotency_key) {
            if existing.consent_generation != consent_generation
                || existing.consent_grant_commitment != consent_grant_commitment
            {
                return Err(Error::new(ErrorCode::StaleGeneration));
            }
            if existing.request_commitment != request_commitment {
                return Err(Error::new(ErrorCode::IdempotencyConflict));
            }
            if existing.expires_at_ms <= now_ms {
                return Err(Error::new(ErrorCode::Expired));
            }
            let receipt = existing.receipt.clone();
            let revision = self.next_revision()?;
            check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
            self.commit_success(now_ms, revision);
            return Ok(OperationAdmission {
                disposition: OperationAdmissionDisposition::IdempotentReplay,
                receipt,
            });
        }
        facts.validate_time_and_lock(now_ms)?;
        if self.idempotency.len() >= IDEMPOTENCY_RECORDS_MAXIMUM {
            return Err(Error::new(ErrorCode::StateLimit));
        }
        let logical_bytes = IDEMPOTENCY_BASE_LOGICAL_BYTES
            .checked_add(facts.logical_bytes()?)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
        let retained = self.ensure_addition(1, logical_bytes)?;
        let revision = self.next_revision()?;
        let lock_state_code = facts.lock_knowledge.as_ref().map(LockKnowledge::state_code);
        let mut builder = CommitmentBuilder::new("operation-receipt-v1");
        builder.digest(request_commitment);
        builder.u8(facts.operation.code());
        builder.digest(facts.idempotency_key.digest());
        builder.digest(facts.fresh_state.current.digest());
        builder.bool(lock_state_code.is_some());
        if let Some(code) = lock_state_code {
            builder.u8(code);
        }
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = OperationReceipt {
            request_commitment,
            operation: facts.operation,
            idempotency_key: facts.idempotency_key,
            current_state_commitment: facts.fresh_state.current,
            lock_state_code,
            admitted_at_ms: now_ms,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.idempotency.insert(
            idempotency_key,
            IdempotencyRecord {
                consent_generation,
                consent_grant_commitment,
                request_commitment,
                receipt: receipt.clone(),
                expires_at_ms: facts.idempotency_expires_at_ms,
                logical_bytes,
            },
        );
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(OperationAdmission {
            disposition: OperationAdmissionDisposition::Admitted,
            receipt,
        })
    }

    pub fn validate_status_batch(
        &mut self,
        facts: &StatusBatchFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<StatusBatchReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        require_digest(facts.session_id.digest())?;
        require_digest(facts.consent_id.digest())?;
        require_digest(facts.integration_id.digest())?;
        require_digest(facts.workspace_id.digest())?;
        require_digest(facts.repository_id.digest())?;
        if facts.items.len() > STATUS_ITEMS_MAXIMUM {
            return Err(Error::new(ErrorCode::ItemLimit));
        }
        if facts.query_scope.context().repository_id != facts.repository_id {
            return Err(Error::new(ErrorCode::InvalidFact));
        }
        facts.logical_bytes()?;
        facts.fresh_state.validate(now_ms)?;
        if let StatusContinuation::More {
            externally_scoped_cursor_commitment,
        } = facts.continuation
        {
            require_digest(externally_scoped_cursor_commitment)
                .map_err(|_| Error::new(ErrorCode::CursorInvalid))?;
        }
        let consent = self.active_consent(
            AccessContext {
                consent_id: facts.consent_id,
                session_id: facts.session_id,
                integration_id: facts.integration_id,
                workspace_id: facts.workspace_id,
                repository_id: facts.repository_id,
            },
            Capability::ReadStatus,
            now_ms,
        )?;
        let mut work = WorkBudget::new();
        if !facts
            .query_scope
            .is_subset_of(&consent.facts.scope, &mut work)?
        {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        let consent_generation = consent.facts.generation;
        let consent_grant_commitment = consent.grant_commitment;
        let mut file_ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        work.charge(facts.items.len())?;
        for item in &facts.items {
            require_digest(item.item_state_commitment.digest())?;
            if item.path.context() != facts.query_scope.context()
                || !facts
                    .query_scope
                    .contains_status_item(item.file_id, &item.path, &mut work)?
                || !file_ids.insert(item.file_id)
                || !paths.insert(item.path.key().as_str())
            {
                return Err(Error::new(ErrorCode::ScopeDenied));
            }
        }
        let batch_commitment = facts.commitment(
            consent_generation,
            consent_grant_commitment,
            raw_frame_commitment,
        );
        let revision = self.next_revision()?;
        let complete = matches!(facts.continuation, StatusContinuation::Complete);
        let mut builder = CommitmentBuilder::new("status-batch-receipt-v1");
        builder.digest(batch_commitment);
        builder.usize(facts.items.len());
        builder.bool(complete);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = StatusBatchReceipt {
            batch_commitment,
            item_count: facts.items.len(),
            complete,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn open_subscription(
        &mut self,
        facts: SubscriptionFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<SubscriptionReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        facts.validate(now_ms)?;
        let consent = self.active_consent(
            AccessContext {
                consent_id: facts.consent_id,
                session_id: facts.session_id,
                integration_id: facts.integration_id,
                workspace_id: facts.workspace_id,
                repository_id: facts.repository_id,
            },
            Capability::WorkspaceEvents,
            now_ms,
        )?;
        let mut work = WorkBudget::new();
        if !facts.scope.is_subset_of(&consent.facts.scope, &mut work)? {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        let consent_generation = consent.facts.generation;
        let consent_grant_commitment = consent.grant_commitment;
        if self.subscriptions.contains_key(&facts.subscription_id) {
            return Err(Error::new(ErrorCode::ReplayRejected));
        }
        if self.subscriptions.len() >= SUBSCRIPTION_RECORDS_MAXIMUM {
            return Err(Error::new(ErrorCode::StateLimit));
        }
        let logical_bytes = facts.logical_bytes()?;
        let retained = self.ensure_addition(1, logical_bytes)?;
        let subscription_commitment = facts.commitment(
            consent_generation,
            consent_grant_commitment,
            raw_frame_commitment,
        );
        let cursor_expiry = now_ms
            .checked_add(facts.cursor_ttl_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?
            .min(facts.expires_at_ms);
        let mut initial_cursor = EventCursor {
            subscription_id: facts.subscription_id,
            subscription_generation: 1,
            position: 0,
            scope_commitment: facts.scope.commitment(),
            state_commitment: facts.initial_state_commitment,
            expires_at_ms: cursor_expiry,
            cursor_commitment: Digest32::ZERO,
        };
        initial_cursor.cursor_commitment = initial_cursor.integrity_commitment();
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("subscription-receipt-v1");
        builder.digest(facts.subscription_id.digest());
        builder.digest(subscription_commitment);
        builder.digest(initial_cursor.cursor_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = SubscriptionReceipt {
            subscription_id: facts.subscription_id,
            subscription_commitment,
            initial_cursor,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        let acknowledged_state_commitment = facts.initial_state_commitment;
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.subscriptions.insert(
            facts.subscription_id,
            SubscriptionRecord {
                facts,
                consent_generation,
                consent_grant_commitment,
                subscription_commitment,
                generation: 1,
                next_sequence: 1,
                acknowledged_sequence: 0,
                acknowledged_state_commitment,
                acknowledged_cursor_expires_at_ms: cursor_expiry,
                max_delivered_sequence: 0,
                last_event_commitment: None,
                queue: VecDeque::new(),
                logical_bytes,
            },
        );
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn enqueue_event(
        &mut self,
        caller: &SubscriptionCallerFacts,
        subscription_id: SubscriptionId,
        event: StatusEventFact,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<EventEnqueueReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        caller.validate()?;
        let caller_commitment = caller.commitment();
        require_digest(subscription_id.digest())?;
        event.validate_shape()?;
        let subscription = self
            .subscriptions
            .get(&subscription_id)
            .ok_or_else(|| Error::new(ErrorCode::CursorInvalid))?;
        let mut work = WorkBudget::new();
        self.validate_subscription_security(subscription, caller, now_ms, &mut work)?;
        if !event
            .scope
            .is_subset_of(&subscription.facts.scope, &mut work)?
        {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        let event_commitment = event.commitment(
            subscription_id,
            subscription.subscription_commitment,
            caller_commitment,
            raw_frame_commitment,
        );
        if event.sequence != subscription.next_sequence {
            if event.sequence
                == subscription
                    .next_sequence
                    .checked_sub(1)
                    .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?
                && subscription.last_event_commitment == Some(event_commitment)
            {
                let next_sequence = subscription.next_sequence;
                let revision = self.next_revision()?;
                let mut builder = CommitmentBuilder::new("event-enqueue-receipt-v1");
                builder.u8(2);
                builder.digest(event_commitment);
                builder.u64(next_sequence);
                builder.u64(now_ms);
                builder.u64(revision);
                let receipt_commitment = builder.finish();
                check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
                self.commit_success(now_ms, revision);
                return Ok(EventEnqueueReceipt {
                    disposition: EventEnqueueDisposition::ExactDuplicate,
                    event_commitment,
                    next_sequence,
                    ledger_revision: revision,
                    receipt_commitment,
                });
            }
            return Err(Error::new(ErrorCode::SequenceInvalid));
        }
        event.validate_time(now_ms)?;
        if subscription.queue.len() >= subscription.facts.queue_capacity {
            return Err(Error::new(ErrorCode::QueueFull));
        }
        let logical_bytes = event.logical_bytes()?;
        let retained = self.ensure_addition(1, logical_bytes)?;
        let next_sequence = subscription
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
        let subscription_logical_bytes = subscription
            .logical_bytes
            .checked_add(logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("event-enqueue-receipt-v1");
        builder.u8(1);
        builder.digest(event_commitment);
        builder.u64(next_sequence);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt_commitment = builder.finish();
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        let subscription = self
            .subscriptions
            .get_mut(&subscription_id)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        subscription.queue.push_back(QueuedEvent {
            facts: event,
            event_commitment,
            issued_cursor_expires_at_ms: None,
            logical_bytes,
        });
        subscription.next_sequence = next_sequence;
        subscription.last_event_commitment = Some(event_commitment);
        subscription.logical_bytes = subscription_logical_bytes;
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(EventEnqueueReceipt {
            disposition: EventEnqueueDisposition::Enqueued,
            event_commitment,
            next_sequence,
            ledger_revision: revision,
            receipt_commitment,
        })
    }

    pub fn poll_events(
        &mut self,
        caller: &SubscriptionCallerFacts,
        cursor: &EventCursor,
        maximum_items: usize,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<EventPage> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        caller.validate()?;
        let caller_commitment = caller.commitment();
        if maximum_items == 0 || maximum_items > EVENT_PAGE_ITEMS_MAXIMUM {
            return Err(Error::new(ErrorCode::ItemLimit));
        }
        let (
            events,
            event_commitments,
            position,
            state_commitment,
            cursor_expiry,
            issued_cursor_expiry,
            subscription_generation,
            scope_commitment,
            subscription_commitment,
        ) = {
            let subscription = self
                .subscriptions
                .get(&cursor.subscription_id)
                .ok_or_else(|| Error::new(ErrorCode::CursorInvalid))?;
            let mut work = WorkBudget::new();
            self.validate_subscription_security(subscription, caller, now_ms, &mut work)?;
            self.validate_cursor(cursor, subscription, now_ms, false)?;
            work.charge(subscription.queue.len())?;

            let mut events = Vec::with_capacity(maximum_items.min(subscription.queue.len()));
            let mut event_commitments =
                Vec::with_capacity(maximum_items.min(subscription.queue.len()));
            for event in subscription
                .queue
                .iter()
                .filter(|event| event.facts.sequence > cursor.position)
                .take(maximum_items)
            {
                events.push(event.facts.clone());
                event_commitments.push(event.event_commitment);
            }
            work.charge(events.len())?;
            let position = events
                .last()
                .map_or(cursor.position, |event| event.sequence);
            let state_commitment = events
                .last()
                .map_or(cursor.state_commitment, |event| event.fresh_state.current);
            let prior_issued_expiry = if position == subscription.acknowledged_sequence {
                Some(subscription.acknowledged_cursor_expires_at_ms)
            } else {
                subscription
                    .queue
                    .iter()
                    .find(|event| event.facts.sequence == position)
                    .and_then(|event| event.issued_cursor_expires_at_ms)
            };
            let (cursor_expiry, issued_cursor_expiry) = if position == cursor.position {
                (cursor.expires_at_ms, None)
            } else if prior_issued_expiry.is_some_and(|expiry| expiry > now_ms) {
                (prior_issued_expiry.unwrap_or(cursor.expires_at_ms), None)
            } else {
                let expiry = now_ms
                    .checked_add(subscription.facts.cursor_ttl_ms)
                    .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?
                    .min(subscription.facts.expires_at_ms);
                (expiry, Some(expiry))
            };
            (
                events,
                event_commitments,
                position,
                state_commitment,
                cursor_expiry,
                issued_cursor_expiry,
                subscription.generation,
                subscription.facts.scope.commitment(),
                subscription.subscription_commitment,
            )
        };
        let mut next_cursor = EventCursor {
            subscription_id: cursor.subscription_id,
            subscription_generation,
            position,
            scope_commitment,
            state_commitment,
            expires_at_ms: cursor_expiry,
            cursor_commitment: Digest32::ZERO,
        };
        next_cursor.cursor_commitment = next_cursor.integrity_commitment();
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("event-page-v1");
        builder.digest(subscription_commitment);
        builder.digest(caller_commitment);
        builder.digest(cursor.cursor_commitment);
        builder.usize(maximum_items);
        builder.usize(events.len());
        for event_commitment in event_commitments {
            builder.digest(event_commitment);
        }
        builder.digest(next_cursor.cursor_commitment);
        builder.digest(raw_frame_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let page_commitment = builder.finish();
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        let stored = self
            .subscriptions
            .get_mut(&cursor.subscription_id)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        if let Some(expiry) = issued_cursor_expiry {
            let event = stored
                .queue
                .iter_mut()
                .find(|event| event.facts.sequence == position)
                .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
            event.issued_cursor_expires_at_ms = Some(expiry);
        }
        stored.max_delivered_sequence = stored.max_delivered_sequence.max(position);
        self.commit_success(now_ms, revision);
        Ok(EventPage {
            events,
            next_cursor,
            ledger_revision: revision,
            page_commitment,
        })
    }

    pub fn acknowledge_events(
        &mut self,
        caller: &SubscriptionCallerFacts,
        cursor: &EventCursor,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<EventAckReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        caller.validate()?;
        let caller_commitment = caller.commitment();
        let (removed, removed_bytes, subscription_logical_bytes, subscription_commitment) = {
            let subscription = self
                .subscriptions
                .get(&cursor.subscription_id)
                .ok_or_else(|| Error::new(ErrorCode::CursorInvalid))?;
            let mut work = WorkBudget::new();
            self.validate_subscription_security(subscription, caller, now_ms, &mut work)?;
            self.validate_cursor(cursor, subscription, now_ms, true)?;
            work.charge(subscription.queue.len())?;
            let mut removed = 0usize;
            let mut removed_bytes = 0usize;
            for event in &subscription.queue {
                if event.facts.sequence <= cursor.position {
                    removed = removed
                        .checked_add(1)
                        .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
                    removed_bytes = removed_bytes
                        .checked_add(event.logical_bytes)
                        .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
                }
            }
            let subscription_logical_bytes = subscription
                .logical_bytes
                .checked_sub(removed_bytes)
                .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
            (
                removed,
                removed_bytes,
                subscription_logical_bytes,
                subscription.subscription_commitment,
            )
        };
        let retained = self
            .retained_logical_bytes
            .checked_sub(removed_bytes)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("event-ack-receipt-v1");
        builder.digest(cursor.subscription_id.digest());
        builder.digest(subscription_commitment);
        builder.digest(caller_commitment);
        builder.digest(cursor.cursor_commitment);
        builder.u64(cursor.position);
        builder.usize(removed);
        builder.digest(raw_frame_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = EventAckReceipt {
            subscription_id: cursor.subscription_id,
            cursor_commitment: cursor.cursor_commitment,
            acknowledged_sequence: cursor.position,
            removed_items: removed,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        let stored = self
            .subscriptions
            .get_mut(&cursor.subscription_id)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        for _ in 0..removed {
            stored.queue.pop_front();
        }
        stored.acknowledged_sequence = cursor.position;
        stored.acknowledged_state_commitment = cursor.state_commitment;
        stored.acknowledged_cursor_expires_at_ms = cursor.expires_at_ms;
        stored.logical_bytes = subscription_logical_bytes;
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    fn validate_subscription_security(
        &self,
        subscription: &SubscriptionRecord,
        caller: &SubscriptionCallerFacts,
        now_ms: u64,
        work: &mut WorkBudget,
    ) -> Result<()> {
        caller.validate()?;
        if subscription.facts.session_id != caller.session_id
            || subscription.facts.consent_id != caller.consent_id
            || subscription.facts.integration_id != caller.integration_id
            || subscription.facts.workspace_id != caller.workspace_id
            || subscription.facts.repository_id != caller.repository_id
        {
            return Err(Error::new(ErrorCode::CursorInvalid));
        }
        if subscription.facts.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        let session = self.active_session(caller.session_id, now_ms)?;
        if session.transcript_commitment != caller.session_transcript_commitment {
            return Err(Error::new(ErrorCode::TranscriptUnverified));
        }
        let consent = self.active_consent(
            AccessContext {
                consent_id: caller.consent_id,
                session_id: caller.session_id,
                integration_id: caller.integration_id,
                workspace_id: caller.workspace_id,
                repository_id: caller.repository_id,
            },
            Capability::WorkspaceEvents,
            now_ms,
        )?;
        if caller.consent_generation != subscription.consent_generation
            || caller.consent_grant_commitment != subscription.consent_grant_commitment
            || consent.facts.generation != caller.consent_generation
            || consent.grant_commitment != caller.consent_grant_commitment
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        if !subscription
            .facts
            .scope
            .is_subset_of(&consent.facts.scope, work)?
        {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        Ok(())
    }

    fn validate_cursor(
        &self,
        cursor: &EventCursor,
        subscription: &SubscriptionRecord,
        now_ms: u64,
        require_issued: bool,
    ) -> Result<()> {
        if cursor.cursor_commitment != cursor.integrity_commitment()
            || cursor.subscription_id != subscription.facts.subscription_id
            || cursor.subscription_generation != subscription.generation
            || cursor.scope_commitment != subscription.facts.scope.commitment()
        {
            return Err(Error::new(ErrorCode::CursorInvalid));
        }
        if cursor.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::CursorExpired));
        }
        let maximum_expiry = now_ms
            .checked_add(subscription.facts.cursor_ttl_ms)
            .ok_or_else(|| Error::new(ErrorCode::TimeOverflow))?
            .min(subscription.facts.expires_at_ms);
        if cursor.expires_at_ms > maximum_expiry {
            return Err(Error::new(ErrorCode::CursorInvalid));
        }
        if cursor.position < subscription.acknowledged_sequence {
            return Err(Error::new(ErrorCode::CursorGap));
        }
        if cursor.position > subscription.max_delivered_sequence
            || (require_issued && cursor.position == 0)
        {
            return Err(Error::new(ErrorCode::CursorInvalid));
        }
        let (expected_state, expected_expiry) =
            if cursor.position == subscription.acknowledged_sequence {
                (
                    Some(subscription.acknowledged_state_commitment),
                    Some(subscription.acknowledged_cursor_expires_at_ms),
                )
            } else {
                let event = subscription
                    .queue
                    .iter()
                    .find(|event| event.facts.sequence == cursor.position);
                (
                    event.map(|event| event.facts.fresh_state.current),
                    event.and_then(|event| event.issued_cursor_expires_at_ms),
                )
            };
        if expected_state != Some(cursor.state_commitment)
            || expected_expiry != Some(cursor.expires_at_ms)
        {
            return Err(Error::new(ErrorCode::CursorInvalid));
        }
        Ok(())
    }

    pub fn register_trusted_handoff(
        &mut self,
        facts: TrustedHandoffFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<HandoffReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        facts.validate(now_ms)?;
        if facts.installation_id != self.installation.id
            || facts.verifier_key_generation != self.verifier_key_generation
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        let consent = self.active_consent(
            AccessContext {
                consent_id: facts.consent_id,
                session_id: facts.session_id,
                integration_id: facts.integration_id,
                workspace_id: facts.workspace_id,
                repository_id: facts.repository_id,
            },
            Capability::TrustedClientHandoff,
            now_ms,
        )?;
        let mut work = WorkBudget::new();
        if !facts.scope.is_subset_of(&consent.facts.scope, &mut work)? {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        let consent_generation = consent.facts.generation;
        let consent_grant_commitment = consent.grant_commitment;
        if self.handoffs.contains_key(&facts.handoff_id) {
            return Err(Error::new(ErrorCode::ReplayRejected));
        }
        if self.handoffs.len() >= HANDOFF_RECORDS_MAXIMUM {
            return Err(Error::new(ErrorCode::StateLimit));
        }
        let logical_bytes = facts.logical_bytes()?;
        let retained = self.ensure_addition(1, logical_bytes)?;
        let handoff_commitment = facts.commitment(
            consent_generation,
            consent_grant_commitment,
            raw_frame_commitment,
        );
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("handoff-registration-receipt-v1");
        builder.digest(facts.handoff_id.digest());
        builder.digest(handoff_commitment);
        builder.u64(facts.expires_at_ms);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = HandoffReceipt {
            handoff_id: facts.handoff_id,
            handoff_commitment,
            expires_at_ms: facts.expires_at_ms,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.handoffs.insert(
            facts.handoff_id,
            HandoffRecord {
                facts,
                consent_generation,
                consent_grant_commitment,
                handoff_commitment,
                consumed: false,
                consumption_receipt: None,
                logical_bytes,
            },
        );
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn consume_trusted_handoff(
        &mut self,
        facts: &HandoffConsumptionFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<HandoffConsumptionReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        facts.validate()?;
        let record = self
            .handoffs
            .get(&facts.handoff_id)
            .ok_or_else(|| Error::new(ErrorCode::HandoffUnverified))?;
        if record.facts.trusted_client_id != facts.trusted_client_id
            || record.handoff_commitment != facts.expected_handoff_commitment
        {
            return Err(Error::new(ErrorCode::HandoffUnverified));
        }
        if record.facts.expires_at_ms <= now_ms {
            return Err(Error::new(ErrorCode::Expired));
        }
        if record.facts.installation_id != self.installation.id
            || record.facts.verifier_key_generation != self.verifier_key_generation
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        if record.consumed {
            return Err(Error::new(ErrorCode::HandoffUsed));
        }
        record.facts.fresh_state.validate(now_ms)?;
        let consent = self.active_consent(
            AccessContext {
                consent_id: record.facts.consent_id,
                session_id: record.facts.session_id,
                integration_id: record.facts.integration_id,
                workspace_id: record.facts.workspace_id,
                repository_id: record.facts.repository_id,
            },
            Capability::TrustedClientHandoff,
            now_ms,
        )?;
        if consent.facts.generation != record.consent_generation
            || consent.grant_commitment != record.consent_grant_commitment
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        let mut work = WorkBudget::new();
        if !record
            .facts
            .scope
            .is_subset_of(&consent.facts.scope, &mut work)?
        {
            return Err(Error::new(ErrorCode::ScopeDenied));
        }
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("handoff-consumption-receipt-v1");
        builder.digest(facts.handoff_id.digest());
        builder.digest(record.handoff_commitment);
        builder.digest(facts.trusted_client_id.digest());
        builder.u8(facts.trusted_client_verification.code());
        builder.digest(facts.consumer_adapter_commitment);
        builder.digest(raw_frame_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt = HandoffConsumptionReceipt {
            handoff_id: facts.handoff_id,
            handoff_commitment: record.handoff_commitment,
            consumed_at_ms: now_ms,
            ledger_revision: revision,
            receipt_commitment: builder.finish(),
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        let record = self
            .handoffs
            .get_mut(&facts.handoff_id)
            .ok_or_else(|| Error::new(ErrorCode::InvariantViolation))?;
        record.consumed = true;
        record.consumption_receipt = Some(receipt.receipt_commitment);
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn rotate_installation(
        &mut self,
        facts: RotationFacts,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<RotationReceipt> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        facts.validate(now_ms)?;
        let next_endpoint_generation = self
            .endpoint
            .endpoint_generation
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::StateLimit))?;
        if facts.expected_installation != self.installation
            || facts.expected_verifier_key_generation != self.verifier_key_generation
            || facts.replacement_endpoint.id != self.endpoint.id
            || facts.replacement_endpoint.endpoint_generation != next_endpoint_generation
        {
            return Err(Error::new(ErrorCode::StaleGeneration));
        }
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("installation-rotation-receipt-v1");
        facts.expected_installation.commit_into(&mut builder);
        self.endpoint.commit_into(&mut builder);
        facts.replacement_installation.commit_into(&mut builder);
        facts.replacement_endpoint.commit_into(&mut builder);
        builder.u64(facts.expected_verifier_key_generation);
        builder.u64(facts.replacement_verifier_key_generation);
        builder.u8(facts.rotation_verification.code());
        builder.digest(facts.rotation_commitment);
        builder.digest(raw_frame_commitment);
        builder.u64(facts.effective_at_ms);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt_commitment = builder.finish();
        let receipt = RotationReceipt {
            prior_installation_id: facts.expected_installation.id,
            prior_installation_generation: facts.expected_installation.generation,
            replacement_installation_id: facts.replacement_installation.id,
            replacement_installation_generation: facts.replacement_installation.generation,
            replacement_verifier_key_generation: facts.replacement_verifier_key_generation,
            rotated_at_ms: now_ms,
            ledger_revision: revision,
            receipt_commitment,
        };
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.installation = facts.replacement_installation;
        self.endpoint = facts.replacement_endpoint;
        self.verifier_key_generation = facts.replacement_verifier_key_generation;
        self.commit_success(now_ms, revision);
        Ok(receipt)
    }

    pub fn reap_expired(
        &mut self,
        now_ms: u64,
        raw: &RawFrame<'_>,
        cancellation: &dyn CancellationProbe,
    ) -> Result<ReapReport> {
        let raw_frame_commitment = self.preflight(now_ms, raw, cancellation)?;
        let prior_state_commitment = self.state_commitment();
        let mut work = WorkBudget::new();
        work.charge(self.record_count()?)?;

        let sessions: BTreeMap<_, _> = self
            .sessions
            .iter()
            .filter(|(_, record)| record.facts.expires_at_ms > now_ms)
            .map(|(id, record)| (*id, record.clone()))
            .collect();
        let replay_ledger: BTreeMap<_, _> = self
            .replay_ledger
            .iter()
            .filter(|(_, expiry)| **expiry > now_ms)
            .map(|(commitment, expiry)| (*commitment, *expiry))
            .collect();
        let consents: BTreeMap<_, _> = self
            .consents
            .iter()
            .filter(|(_, record)| record.facts.expires_at_ms > now_ms)
            .map(|(id, record)| (*id, record.clone()))
            .collect();
        let idempotency: BTreeMap<_, _> = self
            .idempotency
            .iter()
            .filter(|(_, record)| record.expires_at_ms > now_ms)
            .map(|(id, record)| (*id, record.clone()))
            .collect();
        let subscriptions: BTreeMap<_, _> = self
            .subscriptions
            .iter()
            .filter(|(_, record)| record.facts.expires_at_ms > now_ms)
            .map(|(id, record)| (*id, record.clone()))
            .collect();
        let handoffs: BTreeMap<_, _> = self
            .handoffs
            .iter()
            .filter(|(_, record)| record.facts.expires_at_ms > now_ms)
            .map(|(id, record)| (*id, record.clone()))
            .collect();

        let report_counts = (
            self.sessions.len() - sessions.len(),
            self.replay_ledger.len() - replay_ledger.len(),
            self.consents.len() - consents.len(),
            self.idempotency.len() - idempotency.len(),
            self.subscriptions.len() - subscriptions.len(),
            self.handoffs.len() - handoffs.len(),
        );
        let retained = recompute_retained_bytes(
            &sessions,
            &replay_ledger,
            &consents,
            &idempotency,
            &subscriptions,
            &handoffs,
        )?;
        if retained > self.limits.retained_logical_bytes_maximum {
            return Err(Error::new(ErrorCode::InvariantViolation));
        }
        let revision = self.next_revision()?;
        let mut builder = CommitmentBuilder::new("reap-receipt-v1");
        builder.digest(prior_state_commitment);
        builder.usize(report_counts.0);
        builder.usize(report_counts.1);
        builder.usize(report_counts.2);
        builder.usize(report_counts.3);
        builder.usize(report_counts.4);
        builder.usize(report_counts.5);
        builder.usize(retained);
        builder.digest(raw_frame_commitment);
        builder.u64(now_ms);
        builder.u64(revision);
        let receipt_commitment = builder.finish();
        check_cancel(cancellation, CancellationPoint::BeforeCommit)?;
        self.sessions = sessions;
        self.replay_ledger = replay_ledger;
        self.consents = consents;
        self.idempotency = idempotency;
        self.subscriptions = subscriptions;
        self.handoffs = handoffs;
        self.retained_logical_bytes = retained;
        self.commit_success(now_ms, revision);
        Ok(ReapReport {
            sessions: report_counts.0,
            replays: report_counts.1,
            consents: report_counts.2,
            idempotency: report_counts.3,
            subscriptions: report_counts.4,
            handoffs: report_counts.5,
            ledger_revision: revision,
            receipt_commitment,
        })
    }
}

fn recompute_retained_bytes(
    sessions: &BTreeMap<SessionId, SessionRecord>,
    replays: &BTreeMap<Digest32, u64>,
    consents: &BTreeMap<ConsentId, ConsentRecord>,
    idempotency: &BTreeMap<(IntegrationId, IdempotencyKey), IdempotencyRecord>,
    subscriptions: &BTreeMap<SubscriptionId, SubscriptionRecord>,
    handoffs: &BTreeMap<HandoffId, HandoffRecord>,
) -> Result<usize> {
    let mut retained = LEDGER_BASE_LOGICAL_BYTES;
    for record in sessions.values() {
        retained = retained
            .checked_add(record.logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
    }
    retained = retained
        .checked_add(
            replays
                .len()
                .checked_mul(REPLAY_LOGICAL_BYTES)
                .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?,
        )
        .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
    for record in consents.values() {
        retained = retained
            .checked_add(record.logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
    }
    for record in idempotency.values() {
        retained = retained
            .checked_add(record.logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
    }
    for record in subscriptions.values() {
        retained = retained
            .checked_add(record.logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
    }
    for record in handoffs.values() {
        retained = retained
            .checked_add(record.logical_bytes)
            .ok_or_else(|| Error::new(ErrorCode::RetainedLimit))?;
    }
    Ok(retained)
}
