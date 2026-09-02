//! Private, read-only replica comparison and disposition preview.

use std::fmt;

use ogvcs_object_model::{
    scan_metadata, validate_metadata_schema_with_limits, ErrorCode as ObjectModelErrorCode,
    Limits as CborLimits, ObjectHashWriter, ObjectKind, ObjectRef, OpaqueObjectHashWriter,
    Sha256Writer,
};

use crate::{BackendId, Generation, VerificationControl};

const ASSESSMENT_DOMAIN: &[u8] = b"OpenGameVCS replica assessment rc1\0";
const OBSERVATION_DOMAIN: &[u8] = b"OpenGameVCS replica observation rc1\0";
const VERIFICATION_DOMAIN: &[u8] = b"OpenGameVCS verified replica rc1\0";
const RESULT_BASE_CHARGE: u64 = 1_024;
const SORTED_CANDIDATE_CHARGE: u64 = 128;
const COPY_ASSESSMENT_CHARGE: u64 = 256;
const QUARANTINE_PREVIEW_CHARGE: u64 = 192;
const REPAIR_PREVIEW_CHARGE: u64 = 256;
const WORK_BLOCK_BYTES: u64 = 64 * 1_024;
const HARD_MAX_REPLICAS: u64 = 64;
const HARD_MAX_SINGLE_COPY_BYTES: u64 = 16 * 1_024 * 1_024;
const HARD_MAX_TOTAL_BYTES: u64 = 64 * 1_024 * 1_024;
const HARD_MAX_DECODE_WORKING_BYTES: u64 = 16 * 1_024 * 1_024;
const HARD_MAX_WORK_UNITS: u64 = 8_192;
const HARD_MAX_CHARGED_MEMORY_BYTES: u64 = 128 * 1_024 * 1_024;
const CHUNK_BYTE_PASSES: u64 = 3;
const METADATA_BYTE_PASSES: u64 = 5;

/// Caller-supplied, immutable observation for one exact backend copy.
///
/// Present bytes are independently checked by [`assess_replica_set`]. Missing,
/// ambiguous, and unavailable observations remain untrusted facts; this type
/// carries no storage-health or mutation authority.
#[derive(Clone, Copy)]
pub enum ReplicaCandidateObservation<'a> {
    Present {
        declared_bytes: u64,
        bytes: &'a [u8],
    },
    Missing,
    Ambiguous,
    Unavailable,
}

#[derive(Clone, Copy)]
pub struct ReplicaCandidate<'a> {
    pub backend: BackendId,
    pub observation: ReplicaCandidateObservation<'a>,
}

#[derive(Clone, Debug)]
pub struct ReplicaAssessmentLimits {
    pub max_replicas: u64,
    pub max_single_copy_bytes: u64,
    pub max_total_bytes: u64,
    pub max_work_units: u64,
    pub max_charged_memory_bytes: u64,
    pub max_decode_working_bytes: u64,
}

impl Default for ReplicaAssessmentLimits {
    fn default() -> Self {
        Self {
            max_replicas: 16,
            max_single_copy_bytes: HARD_MAX_SINGLE_COPY_BYTES,
            max_total_bytes: HARD_MAX_TOTAL_BYTES,
            max_work_units: HARD_MAX_WORK_UNITS,
            max_charged_memory_bytes: 96 * 1_024 * 1_024,
            max_decode_working_bytes: HARD_MAX_DECODE_WORKING_BYTES,
        }
    }
}

impl ReplicaAssessmentLimits {
    fn valid(&self) -> bool {
        self.max_replicas > 0
            && self.max_replicas <= HARD_MAX_REPLICAS
            && self.max_single_copy_bytes > 0
            && self.max_single_copy_bytes <= HARD_MAX_SINGLE_COPY_BYTES
            && self.max_total_bytes > 0
            && self.max_total_bytes <= HARD_MAX_TOTAL_BYTES
            && self.max_work_units > 0
            && self.max_work_units <= HARD_MAX_WORK_UNITS
            && self.max_charged_memory_bytes >= RESULT_BASE_CHARGE
            && self.max_charged_memory_bytes <= HARD_MAX_CHARGED_MEMORY_BYTES
            && self.max_decode_working_bytes > 0
            && self.max_decode_working_bytes <= HARD_MAX_DECODE_WORKING_BYTES
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaAssessmentError {
    InvalidLimits,
    EmptyReplicaSet,
    ReplicaLimit,
    DuplicateBackend,
    ByteLimit,
    WorkLimit,
    MemoryLimit,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReplicaCopyOutcome {
    Verified,
    Missing,
    SizeMismatch,
    DigestMismatch,
    FramingVersion,
    Ambiguous,
    Unavailable,
}

impl ReplicaCopyOutcome {
    const fn tag(self) -> u8 {
        match self {
            Self::Verified => 1,
            Self::Missing => 2,
            Self::SizeMismatch => 3,
            Self::DigestMismatch => 4,
            Self::FramingVersion => 5,
            Self::Ambiguous => 6,
            Self::Unavailable => 7,
        }
    }

    const fn is_corrupt_copy(self) -> bool {
        matches!(
            self,
            Self::SizeMismatch | Self::DigestMismatch | Self::FramingVersion
        )
    }

    const fn is_repair_target(self) -> bool {
        self.is_corrupt_copy() || matches!(self, Self::Missing)
    }
}

/// Internal commitment to local validation of supplied bytes under supplied
/// backend/generation labels. It is deliberately not exported as backend
/// provenance, freshness, storage-health evidence, or a write capability.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct SuppliedReplicaValidationCommitment([u8; 32]);

impl SuppliedReplicaValidationCommitment {
    const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Opaque commitment to one supplied backend observation, including the
/// generation, object, expected length, outcome, and (for present copies) the
/// declared/observed lengths and raw-byte digest. Raw digests are never
/// returned directly.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct SuppliedReplicaObservationCommitment([u8; 32]);

impl SuppliedReplicaObservationCommitment {
    const fn digest(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SuppliedReplicaObservationCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SuppliedReplicaObservationCommitment([REDACTED])")
    }
}

impl fmt::Debug for SuppliedReplicaValidationCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SuppliedReplicaValidationCommitment([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplicaCopyAssessment {
    backend: BackendId,
    outcome: ReplicaCopyOutcome,
    declared_bytes: Option<u64>,
    observed_bytes: Option<u64>,
    content_equivalence: Option<[u8; 32]>,
    observation: SuppliedReplicaObservationCommitment,
    validation: Option<SuppliedReplicaValidationCommitment>,
}

impl ReplicaCopyAssessment {
    pub const fn outcome(&self) -> ReplicaCopyOutcome {
        self.outcome
    }

    pub const fn declared_bytes(&self) -> Option<u64> {
        self.declared_bytes
    }

    pub const fn observed_bytes(&self) -> Option<u64> {
        self.observed_bytes
    }
}

impl fmt::Debug for ReplicaCopyAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicaCopyAssessment")
            .field("backend", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .field("declared_bytes", &self.declared_bytes)
            .field("observed_bytes", &self.observed_bytes)
            .field("observation", &self.observation)
            .field("validation", &self.validation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaDisposition {
    SingleVerifiedCopy,
    VerifiedAgreement,
    RepairCandidate,
    NoVerifiedSource,
    ReplicaDisagreementNoVerifiedSource,
    VerifiedIdentityConflict,
    Indeterminate,
}

impl ReplicaDisposition {
    const fn tag(self) -> u8 {
        match self {
            Self::SingleVerifiedCopy => 1,
            Self::VerifiedAgreement => 2,
            Self::RepairCandidate => 3,
            Self::NoVerifiedSource => 4,
            Self::ReplicaDisagreementNoVerifiedSource => 5,
            Self::VerifiedIdentityConflict => 6,
            Self::Indeterminate => 7,
        }
    }
}

/// Non-authoritative candidate for quarantining one observed corrupt copy.
/// A future mutation boundary must re-read, reverify, authorize, audit, and
/// compare-and-swap the exact backend generation before acting.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplicaQuarantinePreview {
    backend: BackendId,
    observed_outcome: ReplicaCopyOutcome,
    observation: SuppliedReplicaObservationCommitment,
}

impl ReplicaQuarantinePreview {
    pub const fn backend(&self) -> BackendId {
        self.backend
    }

    pub const fn observed_outcome(&self) -> ReplicaCopyOutcome {
        self.observed_outcome
    }
}

impl fmt::Debug for ReplicaQuarantinePreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicaQuarantinePreview")
            .field("backend", &"[REDACTED]")
            .field("observed_outcome", &self.observed_outcome)
            .field("observation", &self.observation)
            .finish()
    }
}

/// Non-authoritative candidate for copying from one locally validated supplied
/// source to one missing or corrupt destination. This is not permission to
/// read, quarantine, create, replace, publish, or mark either copy healthy.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplicaRepairPreview {
    source_backend: BackendId,
    source_validation: SuppliedReplicaValidationCommitment,
    destination_backend: BackendId,
    destination_outcome: ReplicaCopyOutcome,
    destination_observation: SuppliedReplicaObservationCommitment,
}

impl ReplicaRepairPreview {
    pub const fn source_backend(&self) -> BackendId {
        self.source_backend
    }

    pub const fn destination_backend(&self) -> BackendId {
        self.destination_backend
    }

    pub const fn destination_outcome(&self) -> ReplicaCopyOutcome {
        self.destination_outcome
    }
}

impl fmt::Debug for ReplicaRepairPreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicaRepairPreview")
            .field("source_backend", &"[REDACTED]")
            .field("source_validation", &self.source_validation)
            .field("destination_backend", &"[REDACTED]")
            .field("destination_outcome", &self.destination_outcome)
            .field("destination_observation", &self.destination_observation)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ReplicaAssessment {
    generation: Generation,
    reference: ObjectRef,
    expected_bytes: u64,
    disposition: ReplicaDisposition,
    copies: Vec<ReplicaCopyAssessment>,
    preferred_source: Option<BackendId>,
    quarantine_previews: Vec<ReplicaQuarantinePreview>,
    repair_previews: Vec<ReplicaRepairPreview>,
    binding_digest: [u8; 32],
}

impl ReplicaAssessment {
    pub const fn supplied_generation(&self) -> Generation {
        self.generation
    }

    pub const fn reference(&self) -> ObjectRef {
        self.reference
    }

    pub const fn supplied_expected_bytes(&self) -> u64 {
        self.expected_bytes
    }

    pub const fn disposition(&self) -> ReplicaDisposition {
        self.disposition
    }

    pub fn copy_count(&self) -> usize {
        self.copies.len()
    }

    pub fn copy_outcome_count(&self, outcome: ReplicaCopyOutcome) -> usize {
        self.copies
            .iter()
            .filter(|copy| copy.outcome == outcome)
            .count()
    }

    pub const fn preferred_source(&self) -> Option<BackendId> {
        self.preferred_source
    }

    pub fn quarantine_previews(&self) -> &[ReplicaQuarantinePreview] {
        &self.quarantine_previews
    }

    pub fn repair_previews(&self) -> &[ReplicaRepairPreview] {
        &self.repair_previews
    }

    pub const fn binding_sha256(&self) -> [u8; 32] {
        self.binding_digest
    }
}

impl fmt::Debug for ReplicaAssessment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplicaAssessment")
            .field("generation", &"[REDACTED]")
            .field("reference_kind", &self.reference.kind)
            .field("expected_bytes", &self.expected_bytes)
            .field("disposition", &self.disposition)
            .field("copy_count", &self.copies.len())
            .field("has_preferred_source", &self.preferred_source.is_some())
            .field("quarantine_preview_count", &self.quarantine_previews.len())
            .field("repair_preview_count", &self.repair_previews.len())
            .field("binding_digest", &"[REDACTED]")
            .finish()
    }
}

/// Locally validates a bounded, caller-supplied replica set and produces a
/// deterministic read-only disposition preview.
///
/// The function performs all count, byte, work, and result-memory preflights
/// before allocating or hashing. Candidates are sorted by opaque backend ID,
/// duplicates fail closed, and ambiguity/unavailability suppresses every
/// quarantine and repair preview. Present metadata must match its exact object
/// identity, canonical framing, schema, and kind; chunks must match the exact
/// chunk identity. The returned digest binds every observation and decision.
pub fn assess_replica_set(
    generation: Generation,
    reference: ObjectRef,
    expected_bytes: u64,
    candidates: &[ReplicaCandidate<'_>],
    limits: &ReplicaAssessmentLimits,
    control: &VerificationControl,
) -> Result<ReplicaAssessment, ReplicaAssessmentError> {
    preflight(reference, candidates, limits, control)?;

    let mut ordered = candidates.to_vec();
    ordered.sort_by_key(|candidate| candidate.backend);
    if ordered
        .windows(2)
        .any(|pair| pair[0].backend == pair[1].backend)
    {
        return Err(ReplicaAssessmentError::DuplicateBackend);
    }

    let mut copies = Vec::with_capacity(ordered.len());
    let mut verified_bytes: Option<&[u8]> = None;
    let mut verified_collision = false;
    for candidate in ordered.iter().copied() {
        checkpoint(control)?;
        let copy = assess_copy(
            generation,
            reference,
            expected_bytes,
            candidate,
            limits,
            control,
        )?;
        if copy.outcome == ReplicaCopyOutcome::Verified {
            let ReplicaCandidateObservation::Present { bytes, .. } = candidate.observation else {
                unreachable!("verified outcomes require present bytes")
            };
            if let Some(first) = verified_bytes {
                verified_collision |= !cancellable_equal(first, bytes, control)?;
            } else {
                verified_bytes = Some(bytes);
            }
        }
        copies.push(copy);
    }
    checkpoint(control)?;

    let verified_count = copies
        .iter()
        .filter(|copy| copy.outcome == ReplicaCopyOutcome::Verified)
        .count();
    let obstructed = copies.iter().any(|copy| {
        matches!(
            copy.outcome,
            ReplicaCopyOutcome::Ambiguous | ReplicaCopyOutcome::Unavailable
        )
    });
    let repair_target_count = copies
        .iter()
        .filter(|copy| copy.outcome.is_repair_target())
        .count();
    let corrupt_replica_disagreement =
        verified_count == 0 && present_copy_bytes_disagree(&copies, &ordered, control)?;

    let disposition = if verified_collision {
        ReplicaDisposition::VerifiedIdentityConflict
    } else if obstructed {
        ReplicaDisposition::Indeterminate
    } else if corrupt_replica_disagreement {
        ReplicaDisposition::ReplicaDisagreementNoVerifiedSource
    } else if verified_count == 0 {
        ReplicaDisposition::NoVerifiedSource
    } else if repair_target_count > 0 {
        ReplicaDisposition::RepairCandidate
    } else if verified_count == 1 {
        ReplicaDisposition::SingleVerifiedCopy
    } else {
        ReplicaDisposition::VerifiedAgreement
    };

    let previews_blocked = obstructed || verified_collision;
    let preferred = (!previews_blocked && verified_count > 0).then(|| {
        copies
            .iter()
            .find(|copy| copy.outcome == ReplicaCopyOutcome::Verified)
            .expect("verified count is nonzero")
    });
    let preferred_source = preferred.map(|copy| copy.backend);
    let preferred_validation = preferred.and_then(|copy| copy.validation);

    let mut quarantine_previews = Vec::new();
    let mut repair_previews = Vec::new();
    if !previews_blocked {
        for copy in &copies {
            if copy.outcome.is_corrupt_copy() {
                quarantine_previews.push(ReplicaQuarantinePreview {
                    backend: copy.backend,
                    observed_outcome: copy.outcome,
                    observation: copy.observation,
                });
            }
            if copy.outcome.is_repair_target() {
                if let (Some(source_backend), Some(source_validation)) =
                    (preferred_source, preferred_validation)
                {
                    repair_previews.push(ReplicaRepairPreview {
                        source_backend,
                        source_validation,
                        destination_backend: copy.backend,
                        destination_outcome: copy.outcome,
                        destination_observation: copy.observation,
                    });
                }
            }
        }
    }

    let mut assessment = ReplicaAssessment {
        generation,
        reference,
        expected_bytes,
        disposition,
        copies,
        preferred_source,
        quarantine_previews,
        repair_previews,
        binding_digest: [0; 32],
    };
    assessment.binding_digest = assessment_digest(&assessment);
    checkpoint(control)?;
    Ok(assessment)
}

fn present_copy_bytes_disagree(
    copies: &[ReplicaCopyAssessment],
    candidates: &[ReplicaCandidate<'_>],
    control: &VerificationControl,
) -> Result<bool, ReplicaAssessmentError> {
    let mut first_present = None;
    for (copy, candidate) in copies.iter().zip(candidates) {
        let Some(content_equivalence) = copy.content_equivalence else {
            continue;
        };
        let ReplicaCandidateObservation::Present { bytes, .. } = candidate.observation else {
            unreachable!("content equivalence requires present bytes")
        };
        let Some((first_equivalence, first_bytes)) = first_present else {
            first_present = Some((content_equivalence, bytes));
            continue;
        };
        if content_equivalence != first_equivalence
            || !cancellable_equal(first_bytes, bytes, control)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn preflight(
    reference: ObjectRef,
    candidates: &[ReplicaCandidate<'_>],
    limits: &ReplicaAssessmentLimits,
    control: &VerificationControl,
) -> Result<(), ReplicaAssessmentError> {
    if !limits.valid() {
        return Err(ReplicaAssessmentError::InvalidLimits);
    }
    checkpoint(control)?;
    let count =
        u64::try_from(candidates.len()).map_err(|_| ReplicaAssessmentError::ReplicaLimit)?;
    if count == 0 {
        return Err(ReplicaAssessmentError::EmptyReplicaSet);
    }
    if count > limits.max_replicas {
        return Err(ReplicaAssessmentError::ReplicaLimit);
    }

    let mut total_bytes = 0u64;
    let mut work_units = count;
    for candidate in candidates {
        let ReplicaCandidateObservation::Present { bytes, .. } = candidate.observation else {
            continue;
        };
        let bytes = u64::try_from(bytes.len()).map_err(|_| ReplicaAssessmentError::ByteLimit)?;
        if bytes > limits.max_single_copy_bytes {
            return Err(ReplicaAssessmentError::ByteLimit);
        }
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or(ReplicaAssessmentError::ByteLimit)?;
        if total_bytes > limits.max_total_bytes {
            return Err(ReplicaAssessmentError::ByteLimit);
        }
        let blocks = bytes
            .checked_add(WORK_BLOCK_BYTES - 1)
            .ok_or(ReplicaAssessmentError::WorkLimit)?
            / WORK_BLOCK_BYTES;
        let byte_passes = if reference.kind == ObjectKind::Chunk {
            CHUNK_BYTE_PASSES
        } else {
            METADATA_BYTE_PASSES
        };
        work_units = work_units
            .checked_add(
                blocks
                    .checked_mul(byte_passes)
                    .ok_or(ReplicaAssessmentError::WorkLimit)?,
            )
            .ok_or(ReplicaAssessmentError::WorkLimit)?;
        if work_units > limits.max_work_units {
            return Err(ReplicaAssessmentError::WorkLimit);
        }
    }

    let per_copy_charge = SORTED_CANDIDATE_CHARGE
        + COPY_ASSESSMENT_CHARGE
        + QUARANTINE_PREVIEW_CHARGE
        + REPAIR_PREVIEW_CHARGE;
    let decode_charge = if reference.kind == ObjectKind::Chunk {
        0
    } else {
        limits
            .max_single_copy_bytes
            .checked_mul(4)
            .and_then(|charge| charge.checked_add(limits.max_decode_working_bytes))
            .ok_or(ReplicaAssessmentError::MemoryLimit)?
    };
    let result_charge = RESULT_BASE_CHARGE
        .checked_add(
            count
                .checked_mul(per_copy_charge)
                .ok_or(ReplicaAssessmentError::MemoryLimit)?,
        )
        .and_then(|charge| charge.checked_add(decode_charge))
        .ok_or(ReplicaAssessmentError::MemoryLimit)?;
    if result_charge > limits.max_charged_memory_bytes {
        return Err(ReplicaAssessmentError::MemoryLimit);
    }
    checkpoint(control)
}

fn assess_copy(
    generation: Generation,
    reference: ObjectRef,
    expected_bytes: u64,
    candidate: ReplicaCandidate<'_>,
    limits: &ReplicaAssessmentLimits,
    control: &VerificationControl,
) -> Result<ReplicaCopyAssessment, ReplicaAssessmentError> {
    let context = CopyContext {
        generation,
        reference,
        expected_bytes,
        backend: candidate.backend,
    };
    let (declared_bytes, bytes) = match candidate.observation {
        ReplicaCandidateObservation::Missing => {
            return Ok(non_present(context, ReplicaCopyOutcome::Missing))
        }
        ReplicaCandidateObservation::Ambiguous => {
            return Ok(non_present(context, ReplicaCopyOutcome::Ambiguous))
        }
        ReplicaCandidateObservation::Unavailable => {
            return Ok(non_present(context, ReplicaCopyOutcome::Unavailable))
        }
        ReplicaCandidateObservation::Present {
            declared_bytes,
            bytes,
        } => (declared_bytes, bytes),
    };
    let observed_bytes = bytes.len() as u64;
    let raw_sha256 = cancellable_raw_sha256(bytes, control)?;
    let facts = PresentFacts {
        context,
        declared_bytes,
        observed_bytes,
        raw_sha256,
    };

    if declared_bytes != expected_bytes || observed_bytes != expected_bytes {
        return Ok(present(facts, ReplicaCopyOutcome::SizeMismatch, None));
    }

    let Some(observed_identity) =
        cancellable_identity_digest(reference.kind, bytes, limits.max_single_copy_bytes, control)?
    else {
        return Ok(present(facts, ReplicaCopyOutcome::FramingVersion, None));
    };
    if observed_identity != reference.digest {
        return Ok(present(facts, ReplicaCopyOutcome::DigestMismatch, None));
    }

    if reference.kind != ObjectKind::Chunk {
        let maximum = usize::try_from(limits.max_single_copy_bytes).unwrap_or(usize::MAX);
        let decode_working = usize::try_from(limits.max_decode_working_bytes).unwrap_or(usize::MAX);
        let scanned = match scan_metadata(
            bytes,
            CborLimits {
                max_input_bytes: maximum,
                max_value_bytes: maximum,
                max_nesting: CborLimits::METADATA.max_nesting,
                max_container_items: CborLimits::METADATA.max_container_items,
                max_working_bytes: decode_working,
            },
        ) {
            Ok(scanned) => scanned,
            Err(error) if error.code == ObjectModelErrorCode::LimitMemory => {
                return Err(ReplicaAssessmentError::MemoryLimit)
            }
            Err(_) => return Ok(present(facts, ReplicaCopyOutcome::FramingVersion, None)),
        };
        checkpoint(control)?;
        let kind = match validate_metadata_schema_with_limits(&scanned, decode_working) {
            Ok(kind) => kind,
            Err(error) if error.code == ObjectModelErrorCode::LimitMemory => {
                return Err(ReplicaAssessmentError::MemoryLimit)
            }
            Err(_) => return Ok(present(facts, ReplicaCopyOutcome::FramingVersion, None)),
        };
        checkpoint(control)?;
        if kind != reference.kind {
            return Ok(present(facts, ReplicaCopyOutcome::FramingVersion, None));
        }
    }
    checkpoint(control)?;

    let validation = SuppliedReplicaValidationCommitment(validation_digest(facts));
    Ok(present(
        facts,
        ReplicaCopyOutcome::Verified,
        Some(validation),
    ))
}

#[derive(Clone, Copy)]
struct CopyContext {
    generation: Generation,
    reference: ObjectRef,
    expected_bytes: u64,
    backend: BackendId,
}

#[derive(Clone, Copy)]
struct PresentFacts {
    context: CopyContext,
    declared_bytes: u64,
    observed_bytes: u64,
    raw_sha256: [u8; 32],
}

fn non_present(context: CopyContext, outcome: ReplicaCopyOutcome) -> ReplicaCopyAssessment {
    ReplicaCopyAssessment {
        backend: context.backend,
        outcome,
        declared_bytes: None,
        observed_bytes: None,
        content_equivalence: None,
        observation: SuppliedReplicaObservationCommitment(observation_digest(
            context, outcome, None, None, None,
        )),
        validation: None,
    }
}

fn present(
    facts: PresentFacts,
    outcome: ReplicaCopyOutcome,
    validation: Option<SuppliedReplicaValidationCommitment>,
) -> ReplicaCopyAssessment {
    ReplicaCopyAssessment {
        backend: facts.context.backend,
        outcome,
        declared_bytes: Some(facts.declared_bytes),
        observed_bytes: Some(facts.observed_bytes),
        content_equivalence: Some(facts.raw_sha256),
        observation: SuppliedReplicaObservationCommitment(observation_digest(
            facts.context,
            outcome,
            Some(facts.declared_bytes),
            Some(facts.observed_bytes),
            Some(facts.raw_sha256),
        )),
        validation,
    }
}

fn checkpoint(control: &VerificationControl) -> Result<(), ReplicaAssessmentError> {
    if control.is_cancelled() {
        Err(ReplicaAssessmentError::Cancelled)
    } else {
        Ok(())
    }
}

fn cancellable_raw_sha256(
    bytes: &[u8],
    control: &VerificationControl,
) -> Result<[u8; 32], ReplicaAssessmentError> {
    let mut hash = Sha256Writer::new();
    for chunk in bytes.chunks(WORK_BLOCK_BYTES as usize) {
        checkpoint(control)?;
        hash.update(chunk);
    }
    checkpoint(control)?;
    Ok(hash.finish())
}

fn cancellable_identity_digest(
    kind: ObjectKind,
    bytes: &[u8],
    maximum_bytes: u64,
    control: &VerificationControl,
) -> Result<Option<[u8; 32]>, ReplicaAssessmentError> {
    let maximum = usize::try_from(maximum_bytes).unwrap_or(usize::MAX);
    if kind == ObjectKind::Chunk {
        let mut hash = ObjectHashWriter::new(kind, maximum, maximum);
        for chunk in bytes.chunks(WORK_BLOCK_BYTES as usize) {
            checkpoint(control)?;
            if hash.update(chunk).is_err() {
                return Ok(None);
            }
        }
        checkpoint(control)?;
        return Ok(hash.finish().ok().map(|reference| reference.digest));
    }

    let mut hash = match OpaqueObjectHashWriter::new(kind.code(), maximum) {
        Ok(hash) => hash,
        Err(_) => return Ok(None),
    };
    for chunk in bytes.chunks(WORK_BLOCK_BYTES as usize) {
        checkpoint(control)?;
        if hash.update(chunk).is_err() {
            return Ok(None);
        }
    }
    checkpoint(control)?;
    Ok(hash.finish().ok())
}

fn cancellable_equal(
    first: &[u8],
    second: &[u8],
    control: &VerificationControl,
) -> Result<bool, ReplicaAssessmentError> {
    if first.len() != second.len() {
        return Ok(false);
    }
    for (left, right) in first
        .chunks(WORK_BLOCK_BYTES as usize)
        .zip(second.chunks(WORK_BLOCK_BYTES as usize))
    {
        checkpoint(control)?;
        if left != right {
            return Ok(false);
        }
    }
    checkpoint(control)?;
    Ok(true)
}

fn validation_digest(facts: PresentFacts) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(VERIFICATION_DOMAIN);
    hash.update(&facts.context.generation);
    hash.update(&facts.context.reference.kind.code().to_be_bytes());
    hash.update(&facts.context.reference.digest);
    hash.update(&facts.context.backend);
    hash.update(&facts.declared_bytes.to_be_bytes());
    hash.update(&facts.observed_bytes.to_be_bytes());
    hash.update(&facts.raw_sha256);
    hash.finish()
}

fn observation_digest(
    context: CopyContext,
    outcome: ReplicaCopyOutcome,
    declared_bytes: Option<u64>,
    observed_bytes: Option<u64>,
    raw_sha256: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(OBSERVATION_DOMAIN);
    hash.update(&context.generation);
    hash.update(&context.reference.kind.code().to_be_bytes());
    hash.update(&context.reference.digest);
    hash.update(&context.expected_bytes.to_be_bytes());
    hash.update(&context.backend);
    hash.update(&[outcome.tag()]);
    update_optional_u64(&mut hash, declared_bytes);
    update_optional_u64(&mut hash, observed_bytes);
    update_optional_digest(&mut hash, raw_sha256);
    hash.finish()
}

fn assessment_digest(assessment: &ReplicaAssessment) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(ASSESSMENT_DOMAIN);
    hash.update(&assessment.generation);
    hash.update(&assessment.reference.kind.code().to_be_bytes());
    hash.update(&assessment.reference.digest);
    hash.update(&assessment.expected_bytes.to_be_bytes());
    hash.update(&[assessment.disposition.tag()]);
    hash.update(&(assessment.copies.len() as u64).to_be_bytes());
    for copy in &assessment.copies {
        hash.update(&copy.backend);
        hash.update(&[copy.outcome.tag()]);
        update_optional_u64(&mut hash, copy.declared_bytes);
        update_optional_u64(&mut hash, copy.observed_bytes);
        hash.update(&copy.observation.digest());
        update_optional_digest(
            &mut hash,
            copy.validation
                .map(SuppliedReplicaValidationCommitment::digest),
        );
    }
    update_optional_digest(&mut hash, assessment.preferred_source);
    hash.update(&(assessment.quarantine_previews.len() as u64).to_be_bytes());
    for preview in &assessment.quarantine_previews {
        hash.update(&preview.backend);
        hash.update(&[preview.observed_outcome.tag()]);
        hash.update(&preview.observation.digest());
    }
    hash.update(&(assessment.repair_previews.len() as u64).to_be_bytes());
    for preview in &assessment.repair_previews {
        hash.update(&preview.source_backend);
        hash.update(&preview.source_validation.digest());
        hash.update(&preview.destination_backend);
        hash.update(&[preview.destination_outcome.tag()]);
        hash.update(&preview.destination_observation.digest());
    }
    hash.finish()
}

fn update_optional_u64(hash: &mut Sha256Writer, value: Option<u64>) {
    match value {
        Some(value) => {
            hash.update(&[1]);
            hash.update(&value.to_be_bytes());
        }
        None => hash.update(&[0]),
    }
}

fn update_optional_digest(hash: &mut Sha256Writer, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            hash.update(&[1]);
            hash.update(&value);
        }
        None => hash.update(&[0]),
    }
}
