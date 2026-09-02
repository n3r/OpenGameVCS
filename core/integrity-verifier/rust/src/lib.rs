//! Bounded, read-only OGVCS-017 content-closure verifier candidate.
#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ogvcs_chunking_manifest::{
    verify_manifest, ChunkError, ChunkSource, LedgerOptions, ManifestPart, OperationControl,
    VerifyOptions,
};
use ogvcs_object_model::{
    object_id, opaque_object_digest, scan_metadata, validate_metadata_schema_with_limits, Cbor,
    ErrorCode as ObjectModelErrorCode, Limits as CborLimits, ObjectKind, ObjectRef, Sha256Writer,
};

const CURSOR_DOMAIN: &[u8] = b"OpenGameVCS integrity cursor rc1\0";
const REPORT_DOMAIN: &[u8] = b"OpenGameVCS integrity report rc1\0";
const CURSOR_BASE_CHARGE: u64 = 1_024;
const PENDING_CHARGE: u64 = 128;
const OBJECT_SET_CHARGE: u64 = 96;
const EXPECTATION_CHARGE: u64 = 128;
const EDGE_CHARGE: u64 = 128;
const FINDING_CHARGE: u64 = 192;

pub type Generation = [u8; 32];
pub type BackendId = [u8; 32];

/// One immutable read result from the private candidate source boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRead {
    pub generation: Generation,
    pub outcome: ObjectReadOutcome,
}

/// Explicit source states. Ambiguity is never resolved by choosing a copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObjectReadOutcome {
    Found {
        backend: BackendId,
        declared_bytes: u64,
        bytes: Vec<u8>,
    },
    Missing,
    SourceAmbiguous,
    BackendAmbiguous,
    ByteLimit {
        declared_bytes: u64,
    },
}

/// Private, unpublished source seam used by this unwired verifier and tests.
///
/// Implementations must honor `maximum_bytes` for both the returned payload
/// length and the returned `Vec` capacity. An object whose allocation would
/// exceed that cap is represented by `ByteLimit` without returning payload
/// bytes. The verifier defensively rejects a source that violates either bound.
pub trait ImmutableObjectSource {
    type Error;

    fn generation(&mut self) -> std::result::Result<Generation, Self::Error>;

    fn read_object(
        &mut self,
        reference: &ObjectRef,
        maximum_bytes: u64,
    ) -> std::result::Result<ObjectRead, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingKind {
    MetadataReferenceMissing,
    ObjectMissing,
    SizeMismatch,
    DigestMismatch,
    FramingVersion,
    ManifestCorrupt,
    ChunkCorrupt,
    SourceAmbiguous,
    BackendAmbiguous,
    SourceFailure,
    GenerationChanged,
    Cancelled,
    CountLimit,
    ByteLimit,
    WorkLimit,
    MemoryLimit,
    FindingsTruncated,
    CoverageOverflow,
}

impl FindingKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::MetadataReferenceMissing => "INTEGRITY_METADATA_REFERENCE_MISSING",
            Self::ObjectMissing => "INTEGRITY_OBJECT_MISSING",
            Self::SizeMismatch => "INTEGRITY_SIZE_MISMATCH",
            Self::DigestMismatch => "INTEGRITY_DIGEST_MISMATCH",
            Self::FramingVersion => "INTEGRITY_FRAMING_VERSION",
            Self::ManifestCorrupt => "INTEGRITY_MANIFEST_CORRUPT",
            Self::ChunkCorrupt => "INTEGRITY_CHUNK_CORRUPT",
            Self::SourceAmbiguous => "INTEGRITY_SOURCE_AMBIGUOUS",
            Self::BackendAmbiguous => "INTEGRITY_BACKEND_AMBIGUOUS",
            Self::SourceFailure => "INTEGRITY_SOURCE_FAILURE",
            Self::GenerationChanged => "INTEGRITY_GENERATION_CHANGED",
            Self::Cancelled => "INTEGRITY_CANCELLED",
            Self::CountLimit => "INTEGRITY_COUNT_LIMIT",
            Self::ByteLimit => "INTEGRITY_BYTE_LIMIT",
            Self::WorkLimit => "INTEGRITY_WORK_LIMIT",
            Self::MemoryLimit => "INTEGRITY_MEMORY_LIMIT",
            Self::FindingsTruncated => "INTEGRITY_FINDINGS_TRUNCATED",
            Self::CoverageOverflow => "INTEGRITY_COVERAGE_OVERFLOW",
        }
    }

    pub const fn is_integrity_failure(self) -> bool {
        matches!(
            self,
            Self::MetadataReferenceMissing
                | Self::ObjectMissing
                | Self::SizeMismatch
                | Self::DigestMismatch
                | Self::FramingVersion
                | Self::ManifestCorrupt
                | Self::ChunkCorrupt
                | Self::SourceAmbiguous
                | Self::BackendAmbiguous
                | Self::SourceFailure
                | Self::GenerationChanged
                | Self::FindingsTruncated
                | Self::CoverageOverflow
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingLayer {
    Snapshot,
    Tree,
    FileVersion,
    Manifest,
    Chunk,
    Source,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FindingEvidence {
    None,
    Bytes {
        expected: u64,
        observed: u64,
    },
    Digest {
        expected: [u8; 32],
        observed: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Finding {
    pub kind: FindingKind,
    pub layer: FindingLayer,
    pub reference: Option<ObjectRef>,
    pub evidence: FindingEvidence,
}

impl Finding {
    fn simple(kind: FindingKind, layer: FindingLayer, reference: Option<ObjectRef>) -> Self {
        Self {
            kind,
            layer,
            reference,
            evidence: FindingEvidence::None,
        }
    }

    pub const fn expected_bytes(self) -> Option<u64> {
        match self.evidence {
            FindingEvidence::Bytes { expected, .. } => Some(expected),
            _ => None,
        }
    }

    pub const fn observed_bytes(self) -> Option<u64> {
        match self.evidence {
            FindingEvidence::Bytes { observed, .. } => Some(observed),
            _ => None,
        }
    }

    pub const fn expected_digest(self) -> Option<[u8; 32]> {
        match self.evidence {
            FindingEvidence::Digest { expected, .. } => Some(expected),
            _ => None,
        }
    }

    pub const fn observed_digest(self) -> Option<[u8; 32]> {
        match self.evidence {
            FindingEvidence::Digest { observed, .. } => Some(observed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CoverageLedger {
    pub metadata_objects_verified: u64,
    pub metadata_bytes_verified: u64,
    pub chunk_objects_verified: u64,
    pub chunk_bytes_verified: u64,
    pub file_versions_traversed: u64,
    pub logical_file_bytes: u64,
    pub manifest_parts_traversed: u64,
    pub graph_edges_traversed: u64,
    pub source_reads: u64,
    pub source_bytes_read: u64,
    pub work_units: u64,
    pub peak_charged_memory_bytes: u64,
}

impl CoverageLedger {
    pub const fn object_count(self) -> u64 {
        self.metadata_objects_verified + self.chunk_objects_verified
    }

    pub const fn object_bytes(self) -> u64 {
        self.metadata_bytes_verified + self.chunk_bytes_verified
    }
}

#[derive(Clone, Debug)]
pub struct VerificationLimits {
    pub max_page_metadata_objects: u64,
    pub max_page_source_reads: u64,
    pub max_page_source_bytes: u64,
    pub max_page_work_units: u64,
    pub max_object_bytes: u64,
    pub max_cursor_objects: u64,
    pub max_findings: u64,
    pub max_charged_memory_bytes: u64,
    pub max_decode_working_bytes: u64,
    pub max_manifest_index_bytes: u64,
    pub max_manifest_ledger_bytes: u64,
    pub max_chunk_fragment_bytes: usize,
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_page_metadata_objects: 10_000,
            max_page_source_reads: 100_000,
            max_page_source_bytes: 256 * 1024 * 1024,
            max_page_work_units: 1_000_000,
            max_object_bytes: 16 * 1024 * 1024,
            max_cursor_objects: 100_000,
            max_findings: 10_000,
            max_charged_memory_bytes: 256 * 1024 * 1024,
            max_decode_working_bytes: 16 * 1024 * 1024,
            max_manifest_index_bytes: 32 * 1024 * 1024,
            max_manifest_ledger_bytes: 8 * 1024 * 1024,
            max_chunk_fragment_bytes: 64 * 1024,
        }
    }
}

impl VerificationLimits {
    fn validate(&self) -> bool {
        self.max_page_metadata_objects > 0
            && self.max_page_source_reads > 0
            && self.max_page_source_bytes > 0
            && self.max_page_work_units > 0
            && self.max_object_bytes > 0
            && self.max_cursor_objects > 0
            && self.max_findings > 0
            && self.max_charged_memory_bytes >= CURSOR_BASE_CHARGE
            && self.max_decode_working_bytes > 0
            && self.max_manifest_index_bytes > 0
            && self.max_manifest_ledger_bytes > 0
            && self.max_chunk_fragment_bytes > 0
    }
}

#[derive(Clone, Debug, Default)]
pub struct VerificationControl {
    cancellation: Arc<AtomicBool>,
}

impl VerificationControl {
    pub fn with_cancellation(cancellation: Arc<AtomicBool>) -> Self {
        Self { cancellation }
    }

    pub fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancellation)
    }

    pub fn cancel(&self) {
        self.cancellation.store(true, Ordering::Release);
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    Complete,
    PageBoundary,
    LimitReached,
    ManifestRestartRequired,
    CoverageOverflow,
    Cancelled,
    SourceUnavailable,
    GenerationChanged,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingObject {
    reference: ObjectRef,
    layer: FindingLayer,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EdgeKey {
    parent: ObjectRef,
    ordinal: u64,
    child: ObjectRef,
}

#[derive(Clone, Debug)]
struct ManifestRestart {
    reference: ObjectRef,
    reason: FindingKind,
    recovery: ManifestRestartRecovery,
    failed_limits: VerificationLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManifestRestartRecovery {
    SourceReads,
    TransferBytes,
    PageTransferBytes,
    ObjectBytes,
    WorkUnits,
    FragmentWorkUnits,
    CursorObjects,
    ChargedMemory,
    DecodeWorking,
    ManifestIndex,
    ManifestLedger,
}

impl ManifestRestart {
    fn expanded_by(&self, limits: &VerificationLimits) -> bool {
        match self.recovery {
            ManifestRestartRecovery::SourceReads => {
                limits.max_page_source_reads > self.failed_limits.max_page_source_reads
            }
            ManifestRestartRecovery::TransferBytes => {
                limits.max_page_source_bytes > self.failed_limits.max_page_source_bytes
                    || limits.max_object_bytes > self.failed_limits.max_object_bytes
            }
            ManifestRestartRecovery::PageTransferBytes => {
                limits.max_page_source_bytes > self.failed_limits.max_page_source_bytes
            }
            ManifestRestartRecovery::ObjectBytes => {
                limits.max_object_bytes > self.failed_limits.max_object_bytes
            }
            ManifestRestartRecovery::WorkUnits => {
                limits.max_page_work_units > self.failed_limits.max_page_work_units
            }
            ManifestRestartRecovery::FragmentWorkUnits => {
                limits.max_page_work_units > self.failed_limits.max_page_work_units
                    || limits.max_chunk_fragment_bytes > self.failed_limits.max_chunk_fragment_bytes
            }
            ManifestRestartRecovery::CursorObjects => {
                limits.max_cursor_objects > self.failed_limits.max_cursor_objects
            }
            ManifestRestartRecovery::ChargedMemory => {
                limits.max_charged_memory_bytes > self.failed_limits.max_charged_memory_bytes
            }
            ManifestRestartRecovery::DecodeWorking => {
                limits.max_decode_working_bytes > self.failed_limits.max_decode_working_bytes
            }
            ManifestRestartRecovery::ManifestIndex => {
                limits.max_manifest_index_bytes > self.failed_limits.max_manifest_index_bytes
            }
            ManifestRestartRecovery::ManifestLedger => {
                limits.max_manifest_ledger_bytes > self.failed_limits.max_manifest_ledger_bytes
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerificationCursor {
    generation: Generation,
    root: ObjectRef,
    pending: VecDeque<PendingObject>,
    seen: BTreeSet<ObjectRef>,
    expected_lengths: BTreeMap<ObjectRef, BTreeSet<u64>>,
    covered: BTreeMap<ObjectRef, u64>,
    edges: BTreeSet<EdgeKey>,
    file_versions: BTreeSet<(ObjectRef, u64)>,
    manifest_restart: Option<ManifestRestart>,
    coverage_overflow: bool,
    findings: BTreeSet<Finding>,
    ledger: CoverageLedger,
}

impl VerificationCursor {
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    pub const fn root(&self) -> ObjectRef {
        self.root
    }

    pub fn findings(&self) -> impl ExactSizeIterator<Item = &Finding> {
        self.findings.iter()
    }

    pub const fn coverage(&self) -> CoverageLedger {
        self.ledger
    }

    pub fn charged_memory_bytes(&self) -> u64 {
        self.cursor_charge()
    }

    pub fn binding_digest(&self) -> [u8; 32] {
        state_digest(CURSOR_DOMAIN, self)
    }

    fn cursor_charge(&self) -> u64 {
        let expectation_values = self
            .expected_lengths
            .values()
            .map(|values| values.len() as u64)
            .sum::<u64>();
        CURSOR_BASE_CHARGE
            .saturating_add(self.pending.len() as u64 * PENDING_CHARGE)
            .saturating_add(self.seen.len() as u64 * OBJECT_SET_CHARGE)
            .saturating_add(self.covered.len() as u64 * OBJECT_SET_CHARGE)
            .saturating_add(expectation_values * EXPECTATION_CHARGE)
            .saturating_add(self.edges.len() as u64 * EDGE_CHARGE)
            .saturating_add(self.file_versions.len() as u64 * EDGE_CHARGE)
            // The fixed cursor charge reserves one fail-closed finding slot.
            .saturating_add(self.findings.len().saturating_sub(1) as u64 * FINDING_CHARGE)
    }

    fn observe_memory(&mut self, additional: u64) {
        self.ledger.peak_charged_memory_bytes = self
            .ledger
            .peak_charged_memory_bytes
            .max(self.cursor_charge().saturating_add(additional));
    }

    fn add_finding(&mut self, finding: Finding, limits: &VerificationLimits) {
        self.add_finding_with_reservation(finding, limits, 0);
    }

    fn add_finding_with_reservation(
        &mut self,
        finding: Finding,
        limits: &VerificationLimits,
        active_reservation: u64,
    ) {
        if self.findings.contains(&finding) {
            return;
        }
        let count_full = self.findings.len() as u64 >= limits.max_findings;
        let memory_full = !self.findings.is_empty()
            && self
                .cursor_charge()
                .checked_add(active_reservation)
                .and_then(|charge| charge.checked_add(FINDING_CHARGE))
                .is_none_or(|charge| charge > limits.max_charged_memory_bytes);
        if count_full || memory_full {
            let sentinel =
                Finding::simple(FindingKind::FindingsTruncated, FindingLayer::Source, None);
            if !self.findings.contains(&sentinel) {
                if let Some(last) = self.findings.iter().next_back().copied() {
                    self.findings.remove(&last);
                }
                self.findings.insert(sentinel);
            }
            self.observe_memory(active_reservation);
            return;
        }
        self.findings.insert(finding);
        self.observe_memory(active_reservation);
    }
}

#[derive(Clone, Debug)]
pub struct VerificationReport {
    pub generation: Generation,
    pub root: ObjectRef,
    pub coverage: CoverageLedger,
    pub findings: Vec<Finding>,
    pub intact: bool,
    pub transcript_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VerificationPage {
    pub status: VerificationStatus,
    pub cursor: VerificationCursor,
    pub report: Option<VerificationReport>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationStartFailure {
    pub finding: Finding,
}

#[derive(Default)]
struct PageBudget {
    metadata_objects: u64,
    source_reads: u64,
    source_bytes: u64,
    work_units: u64,
}

struct AdmittedObject {
    bytes: Vec<u8>,
    active_reservation: u64,
}

enum ProcessResult {
    Consumed,
    Pause(VerificationStatus, Finding, Option<ManifestRestartRecovery>),
}

impl ProcessResult {
    fn pause(status: VerificationStatus, finding: Finding) -> Self {
        Self::Pause(status, finding, None)
    }

    fn restart(
        status: VerificationStatus,
        finding: Finding,
        recovery: ManifestRestartRecovery,
    ) -> Self {
        Self::Pause(status, finding, Some(recovery))
    }
}

pub fn start_verification<S: ImmutableObjectSource>(
    root: ObjectRef,
    source: &mut S,
    limits: &VerificationLimits,
    control: &VerificationControl,
) -> Result<VerificationPage, VerificationStartFailure> {
    if !limits.validate() {
        return Err(VerificationStartFailure {
            finding: Finding::simple(FindingKind::MemoryLimit, FindingLayer::Source, None),
        });
    }
    if root.kind == ObjectKind::Snapshot {
        let initial_charge = CURSOR_BASE_CHARGE
            .checked_add(PENDING_CHARGE)
            .and_then(|value| value.checked_add(OBJECT_SET_CHARGE));
        if initial_charge.is_none_or(|charge| charge > limits.max_charged_memory_bytes) {
            return Err(VerificationStartFailure {
                finding: Finding::simple(FindingKind::MemoryLimit, FindingLayer::Source, None),
            });
        }
    }
    let generation = source.generation().map_err(|_| VerificationStartFailure {
        finding: Finding::simple(FindingKind::SourceFailure, FindingLayer::Source, None),
    })?;
    let mut cursor = VerificationCursor {
        generation,
        root,
        pending: VecDeque::new(),
        seen: BTreeSet::new(),
        expected_lengths: BTreeMap::new(),
        covered: BTreeMap::new(),
        edges: BTreeSet::new(),
        file_versions: BTreeSet::new(),
        manifest_restart: None,
        coverage_overflow: false,
        findings: BTreeSet::new(),
        ledger: CoverageLedger::default(),
    };
    if root.kind != ObjectKind::Snapshot {
        cursor.add_finding(
            Finding::simple(
                FindingKind::MetadataReferenceMissing,
                FindingLayer::Snapshot,
                Some(root),
            ),
            limits,
        );
    } else {
        cursor.pending.push_back(PendingObject {
            reference: root,
            layer: FindingLayer::Snapshot,
        });
        cursor.seen.insert(root);
    }
    cursor.observe_memory(0);
    run_page(cursor, source, limits, control)
}

pub fn resume_verification<S: ImmutableObjectSource>(
    cursor: VerificationCursor,
    source: &mut S,
    limits: &VerificationLimits,
    control: &VerificationControl,
) -> Result<VerificationPage, VerificationStartFailure> {
    if !limits.validate() {
        return Ok(page(VerificationStatus::LimitReached, cursor));
    }
    run_page(cursor, source, limits, control)
}

fn run_page<S: ImmutableObjectSource>(
    mut cursor: VerificationCursor,
    source: &mut S,
    limits: &VerificationLimits,
    control: &VerificationControl,
) -> Result<VerificationPage, VerificationStartFailure> {
    if cursor.pending.is_empty() {
        return Ok(complete_page(cursor, limits));
    }
    if cursor.coverage_overflow {
        return Ok(page(VerificationStatus::CoverageOverflow, cursor));
    }
    let observed_generation = match source.generation() {
        Ok(value) => value,
        Err(_) => {
            let finding = Finding::simple(FindingKind::SourceFailure, FindingLayer::Source, None);
            cursor.add_finding(finding, limits);
            return Ok(page(VerificationStatus::SourceUnavailable, cursor));
        }
    };
    if observed_generation != cursor.generation {
        let mut finding =
            Finding::simple(FindingKind::GenerationChanged, FindingLayer::Source, None);
        finding.evidence = FindingEvidence::Digest {
            expected: cursor.generation,
            observed: observed_generation,
        };
        cursor.add_finding(finding, limits);
        return Ok(page(VerificationStatus::GenerationChanged, cursor));
    }
    if control.is_cancelled() {
        let finding = Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None);
        cursor.add_finding(finding, limits);
        return Ok(page(VerificationStatus::Cancelled, cursor));
    }
    if cursor
        .manifest_restart
        .as_ref()
        .is_some_and(|restart| !restart.expanded_by(limits))
    {
        return Ok(page(VerificationStatus::ManifestRestartRequired, cursor));
    }
    if cursor.cursor_charge() > limits.max_charged_memory_bytes {
        let finding = Finding::simple(FindingKind::MemoryLimit, FindingLayer::Source, None);
        cursor.add_finding(finding, limits);
        return Ok(page(VerificationStatus::LimitReached, cursor));
    }
    cursor.manifest_restart = None;

    let mut budget = PageBudget::default();
    loop {
        if control.is_cancelled() {
            let finding = Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None);
            cursor.add_finding(finding, limits);
            return Ok(page(VerificationStatus::Cancelled, cursor));
        }
        if cursor.pending.is_empty() {
            return Ok(complete_page(cursor, limits));
        }
        if budget.metadata_objects >= limits.max_page_metadata_objects {
            return Ok(page(VerificationStatus::PageBoundary, cursor));
        }
        let pending = *cursor.pending.front().expect("nonempty pending queue");
        match process_pending(pending, &mut cursor, source, limits, control, &mut budget) {
            ProcessResult::Consumed => {
                cursor.pending.pop_front();
                budget.metadata_objects += 1;
            }
            ProcessResult::Pause(status, finding, recovery) => {
                if status == VerificationStatus::CoverageOverflow {
                    cursor.coverage_overflow = true;
                    cursor.add_finding(finding, limits);
                    return Ok(page(VerificationStatus::CoverageOverflow, cursor));
                }
                if pending.reference.kind == ObjectKind::ContentManifest
                    && status == VerificationStatus::LimitReached
                {
                    let recovery = recovery
                        .expect("every manifest resource limit identifies its recovery envelope");
                    cursor.manifest_restart = Some(ManifestRestart {
                        reference: pending.reference,
                        reason: finding.kind,
                        recovery,
                        failed_limits: limits.clone(),
                    });
                    cursor.add_finding(finding, limits);
                    return Ok(page(VerificationStatus::ManifestRestartRequired, cursor));
                }
                cursor.add_finding(finding, limits);
                return Ok(page(status, cursor));
            }
        }
    }
}

fn page(status: VerificationStatus, cursor: VerificationCursor) -> VerificationPage {
    VerificationPage {
        status,
        cursor,
        report: None,
    }
}

fn complete_page(mut cursor: VerificationCursor, limits: &VerificationLimits) -> VerificationPage {
    let report_reservation = (cursor.findings.len() as u64).checked_mul(FINDING_CHARGE);
    if cursor
        .cursor_charge()
        .checked_add(report_reservation.unwrap_or(u64::MAX))
        .is_none_or(|peak| peak > limits.max_charged_memory_bytes)
    {
        cursor.add_finding(
            Finding::simple(FindingKind::MemoryLimit, FindingLayer::Source, None),
            limits,
        );
        return page(VerificationStatus::LimitReached, cursor);
    }
    let report_reservation = report_reservation.expect("checked report reservation");
    cursor.observe_memory(report_reservation);
    let mut findings = Vec::with_capacity(cursor.findings.len());
    findings.extend(cursor.findings.iter().copied());
    let intact = findings
        .iter()
        .all(|finding| !finding.kind.is_integrity_failure());
    let report = VerificationReport {
        generation: cursor.generation,
        root: cursor.root,
        coverage: cursor.ledger,
        findings,
        intact,
        transcript_digest: state_digest(REPORT_DOMAIN, &cursor),
    };
    VerificationPage {
        status: VerificationStatus::Complete,
        cursor,
        report: Some(report),
    }
}

fn process_pending<S: ImmutableObjectSource>(
    pending: PendingObject,
    cursor: &mut VerificationCursor,
    source: &mut S,
    limits: &VerificationLimits,
    control: &VerificationControl,
    budget: &mut PageBudget,
) -> ProcessResult {
    let admitted = match read_object(pending, cursor, source, limits, control, budget) {
        Ok(Some(admitted)) => admitted,
        Ok(None) => return ProcessResult::Consumed,
        Err(result) => return result,
    };
    let bytes = &admitted.bytes;
    let active_reservation = admitted.active_reservation;

    let observed = match opaque_object_digest(pending.reference.kind.code(), bytes) {
        Ok(value) => value,
        Err(_) => {
            cursor.add_finding_with_reservation(
                Finding::simple(
                    FindingKind::FramingVersion,
                    pending.layer,
                    Some(pending.reference),
                ),
                limits,
                active_reservation,
            );
            return ProcessResult::Consumed;
        }
    };
    if observed != pending.reference.digest {
        let mut finding = Finding::simple(
            FindingKind::DigestMismatch,
            pending.layer,
            Some(pending.reference),
        );
        finding.evidence = FindingEvidence::Digest {
            expected: pending.reference.digest,
            observed,
        };
        cursor.add_finding_with_reservation(finding, limits, active_reservation);
        return ProcessResult::Consumed;
    }

    let decode_working = usize::try_from(limits.max_decode_working_bytes).unwrap_or(usize::MAX);
    let maximum = usize::try_from(limits.max_object_bytes).unwrap_or(usize::MAX);
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
        Ok(value) => value,
        Err(error) if error.code == ObjectModelErrorCode::LimitMemory => {
            return ProcessResult::restart(
                VerificationStatus::LimitReached,
                Finding::simple(
                    FindingKind::MemoryLimit,
                    pending.layer,
                    Some(pending.reference),
                ),
                ManifestRestartRecovery::DecodeWorking,
            );
        }
        Err(_) => {
            cursor.add_finding_with_reservation(
                Finding::simple(
                    FindingKind::FramingVersion,
                    pending.layer,
                    Some(pending.reference),
                ),
                limits,
                active_reservation,
            );
            return ProcessResult::Consumed;
        }
    };
    let kind = match validate_metadata_schema_with_limits(&scanned, decode_working) {
        Ok(value) => value,
        Err(error) if error.code == ObjectModelErrorCode::LimitMemory => {
            return ProcessResult::restart(
                VerificationStatus::LimitReached,
                Finding::simple(
                    FindingKind::MemoryLimit,
                    pending.layer,
                    Some(pending.reference),
                ),
                ManifestRestartRecovery::DecodeWorking,
            );
        }
        Err(_) => {
            let missing_layer = missing_required_graph_reference(scanned.value());
            let finding_kind = if missing_layer.is_some() {
                FindingKind::MetadataReferenceMissing
            } else {
                FindingKind::FramingVersion
            };
            cursor.add_finding_with_reservation(
                Finding::simple(
                    finding_kind,
                    missing_layer.unwrap_or(pending.layer),
                    Some(pending.reference),
                ),
                limits,
                active_reservation,
            );
            return ProcessResult::Consumed;
        }
    };
    if kind != pending.reference.kind {
        cursor.add_finding_with_reservation(
            Finding::simple(
                FindingKind::FramingVersion,
                pending.layer,
                Some(pending.reference),
            ),
            limits,
            active_reservation,
        );
        return ProcessResult::Consumed;
    }
    if control.is_cancelled() {
        return ProcessResult::pause(
            VerificationStatus::Cancelled,
            Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
        );
    }

    match kind {
        ObjectKind::Snapshot => process_snapshot(
            pending,
            scanned.value(),
            bytes.len(),
            active_reservation,
            cursor,
            limits,
            budget,
        ),
        ObjectKind::Tree => process_tree(
            pending,
            scanned.value(),
            bytes.len(),
            active_reservation,
            cursor,
            limits,
            budget,
        ),
        ObjectKind::ContentManifest => {
            // `verify_manifest` performs the authoritative OGVCS-007 parse.
            // Release the preliminary schema scan before admitting that second
            // decoder/index/ledger reservation.
            drop(scanned);
            process_manifest(pending, &admitted, cursor, source, limits, control, budget)
        }
        _ => {
            cursor.add_finding_with_reservation(
                Finding::simple(
                    FindingKind::FramingVersion,
                    pending.layer,
                    Some(pending.reference),
                ),
                limits,
                active_reservation,
            );
            ProcessResult::Consumed
        }
    }
}

fn read_object<S: ImmutableObjectSource>(
    pending: PendingObject,
    cursor: &mut VerificationCursor,
    source: &mut S,
    limits: &VerificationLimits,
    control: &VerificationControl,
    budget: &mut PageBudget,
) -> Result<Option<AdmittedObject>, ProcessResult> {
    if control.is_cancelled() {
        return Err(ProcessResult::pause(
            VerificationStatus::Cancelled,
            Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
        ));
    }
    let page_transfer_remaining = limits
        .max_page_source_bytes
        .saturating_sub(budget.source_bytes);
    let transfer_remaining = page_transfer_remaining.min(limits.max_object_bytes);
    if transfer_remaining == 0 {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::ByteLimit,
                pending.layer,
                Some(pending.reference),
            ),
            transfer_recovery(page_transfer_remaining, limits.max_object_bytes),
        ));
    }
    let Some(memory_available) = cursor
        .cursor_charge()
        .checked_add(limits.max_decode_working_bytes)
        .and_then(|base| limits.max_charged_memory_bytes.checked_sub(base))
    else {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                pending.layer,
                Some(pending.reference),
            ),
            ManifestRestartRecovery::ChargedMemory,
        ));
    };
    let memory_maximum = memory_available / 4;
    if memory_maximum == 0 {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                pending.layer,
                Some(pending.reference),
            ),
            ManifestRestartRecovery::ChargedMemory,
        ));
    }
    let memory_constrained = memory_maximum < transfer_remaining;
    let maximum_bytes = transfer_remaining.min(memory_maximum);
    charge_source_read(cursor, budget, limits)?;
    let read = match source.read_object(&pending.reference, maximum_bytes) {
        Ok(read) => read,
        Err(_) if control.is_cancelled() => {
            return Err(ProcessResult::pause(
                VerificationStatus::Cancelled,
                Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
            ));
        }
        Err(_) => {
            return Err(ProcessResult::pause(
                VerificationStatus::SourceUnavailable,
                Finding::simple(
                    FindingKind::SourceFailure,
                    FindingLayer::Source,
                    Some(pending.reference),
                ),
            ));
        }
    };
    if let ObjectReadOutcome::Found { bytes, .. } = &read.outcome {
        record_source_payload_bytes(cursor, budget, bytes.len() as u64)?;
        cursor.observe_memory(bytes.capacity() as u64);
    }
    if read.generation != cursor.generation {
        let mut finding = Finding::simple(
            FindingKind::GenerationChanged,
            FindingLayer::Source,
            Some(pending.reference),
        );
        finding.evidence = FindingEvidence::Digest {
            expected: cursor.generation,
            observed: read.generation,
        };
        return Err(ProcessResult::pause(
            VerificationStatus::GenerationChanged,
            finding,
        ));
    }
    if control.is_cancelled() {
        return Err(ProcessResult::pause(
            VerificationStatus::Cancelled,
            Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
        ));
    }
    match read.outcome {
        ObjectReadOutcome::Missing => {
            cursor.add_finding(
                Finding::simple(
                    FindingKind::ObjectMissing,
                    pending.layer,
                    Some(pending.reference),
                ),
                limits,
            );
            Ok(None)
        }
        ObjectReadOutcome::SourceAmbiguous => {
            cursor.add_finding(
                Finding::simple(
                    FindingKind::SourceAmbiguous,
                    FindingLayer::Source,
                    Some(pending.reference),
                ),
                limits,
            );
            Ok(None)
        }
        ObjectReadOutcome::BackendAmbiguous => {
            cursor.add_finding(
                Finding::simple(
                    FindingKind::BackendAmbiguous,
                    FindingLayer::Source,
                    Some(pending.reference),
                ),
                limits,
            );
            Ok(None)
        }
        ObjectReadOutcome::ByteLimit { declared_bytes } => {
            let mut finding = Finding::simple(
                if memory_constrained {
                    FindingKind::MemoryLimit
                } else {
                    FindingKind::ByteLimit
                },
                pending.layer,
                Some(pending.reference),
            );
            finding.evidence = FindingEvidence::Bytes {
                expected: maximum_bytes,
                observed: declared_bytes,
            };
            Err(ProcessResult::restart(
                VerificationStatus::LimitReached,
                finding,
                if memory_constrained {
                    ManifestRestartRecovery::ChargedMemory
                } else {
                    transfer_recovery(page_transfer_remaining, limits.max_object_bytes)
                },
            ))
        }
        ObjectReadOutcome::Found {
            backend: _,
            declared_bytes,
            bytes,
        } => {
            let observed_bytes = bytes.len() as u64;
            let observed_capacity = bytes.capacity() as u64;
            if observed_bytes > maximum_bytes || observed_capacity > maximum_bytes {
                let mut finding = Finding::simple(
                    FindingKind::SourceFailure,
                    FindingLayer::Source,
                    Some(pending.reference),
                );
                finding.evidence = FindingEvidence::Bytes {
                    expected: maximum_bytes,
                    observed: observed_bytes.max(observed_capacity),
                };
                return Err(ProcessResult::pause(
                    VerificationStatus::SourceUnavailable,
                    finding,
                ));
            }
            let decode_reservation = observed_capacity * 4 + limits.max_decode_working_bytes;
            cursor.observe_memory(decode_reservation);
            if declared_bytes != observed_bytes {
                let mut finding = Finding::simple(
                    FindingKind::SizeMismatch,
                    pending.layer,
                    Some(pending.reference),
                );
                finding.evidence = FindingEvidence::Bytes {
                    expected: declared_bytes,
                    observed: observed_bytes,
                };
                cursor.add_finding_with_reservation(finding, limits, decode_reservation);
                return Ok(None);
            }
            Ok(Some(AdmittedObject {
                bytes,
                active_reservation: decode_reservation,
            }))
        }
    }
}

fn record_source_payload_bytes(
    cursor: &mut VerificationCursor,
    budget: &mut PageBudget,
    observed_bytes: u64,
) -> Result<(), ProcessResult> {
    let Some(page_source_bytes) = budget.source_bytes.checked_add(observed_bytes) else {
        return Err(ProcessResult::pause(
            VerificationStatus::CoverageOverflow,
            Finding::simple(FindingKind::CoverageOverflow, FindingLayer::Source, None),
        ));
    };
    let Some(source_bytes_read) = cursor.ledger.source_bytes_read.checked_add(observed_bytes)
    else {
        return Err(ProcessResult::pause(
            VerificationStatus::CoverageOverflow,
            Finding::simple(FindingKind::CoverageOverflow, FindingLayer::Source, None),
        ));
    };
    budget.source_bytes = page_source_bytes;
    cursor.ledger.source_bytes_read = source_bytes_read;
    Ok(())
}

fn transfer_recovery(
    page_transfer_remaining: u64,
    max_object_bytes: u64,
) -> ManifestRestartRecovery {
    match page_transfer_remaining.cmp(&max_object_bytes) {
        std::cmp::Ordering::Less => ManifestRestartRecovery::PageTransferBytes,
        std::cmp::Ordering::Greater => ManifestRestartRecovery::ObjectBytes,
        std::cmp::Ordering::Equal => ManifestRestartRecovery::TransferBytes,
    }
}

fn charge_source_read(
    cursor: &mut VerificationCursor,
    budget: &mut PageBudget,
    limits: &VerificationLimits,
) -> Result<(), ProcessResult> {
    if budget.source_reads >= limits.max_page_source_reads {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(FindingKind::CountLimit, FindingLayer::Source, None),
            ManifestRestartRecovery::SourceReads,
        ));
    }
    let work = preflight_work(
        cursor,
        budget,
        limits,
        1,
        ManifestRestartRecovery::WorkUnits,
    )?;
    let Some(source_reads) = cursor.ledger.source_reads.checked_add(1) else {
        return Err(ProcessResult::pause(
            VerificationStatus::CoverageOverflow,
            Finding::simple(FindingKind::CoverageOverflow, FindingLayer::Source, None),
        ));
    };
    commit_work(cursor, budget, work);
    budget.source_reads += 1;
    cursor.ledger.source_reads = source_reads;
    Ok(())
}

#[derive(Clone, Copy)]
struct WorkAdmission {
    page_work_units: u64,
    total_work_units: u64,
}

fn preflight_work(
    cursor: &VerificationCursor,
    budget: &PageBudget,
    limits: &VerificationLimits,
    units: u64,
    recovery: ManifestRestartRecovery,
) -> Result<WorkAdmission, ProcessResult> {
    let page_work_units = budget.work_units.checked_add(units).ok_or_else(|| {
        ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(FindingKind::WorkLimit, FindingLayer::Source, None),
            recovery,
        )
    })?;
    if page_work_units > limits.max_page_work_units {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(FindingKind::WorkLimit, FindingLayer::Source, None),
            recovery,
        ));
    }
    let Some(total_work_units) = cursor.ledger.work_units.checked_add(units) else {
        return Err(ProcessResult::pause(
            VerificationStatus::CoverageOverflow,
            Finding::simple(FindingKind::CoverageOverflow, FindingLayer::Source, None),
        ));
    };
    Ok(WorkAdmission {
        page_work_units,
        total_work_units,
    })
}

fn commit_work(cursor: &mut VerificationCursor, budget: &mut PageBudget, admission: WorkAdmission) {
    budget.work_units = admission.page_work_units;
    cursor.ledger.work_units = admission.total_work_units;
}

fn charge_work(
    cursor: &mut VerificationCursor,
    budget: &mut PageBudget,
    limits: &VerificationLimits,
    units: u64,
) -> Result<(), ProcessResult> {
    let admission = preflight_work(
        cursor,
        budget,
        limits,
        units,
        ManifestRestartRecovery::FragmentWorkUnits,
    )?;
    commit_work(cursor, budget, admission);
    Ok(())
}

fn process_snapshot(
    pending: PendingObject,
    value: &Cbor,
    bytes: usize,
    active_reservation: u64,
    cursor: &mut VerificationCursor,
    limits: &VerificationLimits,
    budget: &mut PageBudget,
) -> ProcessResult {
    let Some(root) = field(value, 18).and_then(|value| ObjectRef::from_cbor(value).ok()) else {
        cursor.add_finding_with_reservation(
            Finding::simple(
                FindingKind::MetadataReferenceMissing,
                FindingLayer::Snapshot,
                Some(pending.reference),
            ),
            limits,
            active_reservation,
        );
        return ProcessResult::Consumed;
    };
    if root.kind != ObjectKind::Tree {
        cursor.add_finding_with_reservation(
            Finding::simple(
                FindingKind::MetadataReferenceMissing,
                FindingLayer::Snapshot,
                Some(pending.reference),
            ),
            limits,
            active_reservation,
        );
        return ProcessResult::Consumed;
    }
    if let Err(result) = stage_children(
        cursor,
        pending.reference,
        &[(0, root, FindingLayer::Tree, None)],
        limits,
        budget,
        active_reservation,
    ) {
        return result;
    }
    match record_covered(
        cursor,
        pending.reference,
        bytes as u64,
        limits,
        active_reservation,
    ) {
        Ok(()) => ProcessResult::Consumed,
        Err(result) => result,
    }
}

fn process_tree(
    pending: PendingObject,
    value: &Cbor,
    bytes: usize,
    active_reservation: u64,
    cursor: &mut VerificationCursor,
    limits: &VerificationLimits,
    budget: &mut PageBudget,
) -> ProcessResult {
    let Some(entries) = field(value, 17).and_then(as_array) else {
        cursor.add_finding_with_reservation(
            Finding::simple(
                FindingKind::MetadataReferenceMissing,
                FindingLayer::Tree,
                Some(pending.reference),
            ),
            limits,
            active_reservation,
        );
        return ProcessResult::Consumed;
    };
    let mut children = Vec::with_capacity(entries.len());
    for (ordinal, entry) in entries.iter().enumerate() {
        let Some(kind) = field(entry, 1).and_then(as_u64) else {
            cursor.add_finding_with_reservation(
                Finding::simple(
                    FindingKind::FramingVersion,
                    FindingLayer::FileVersion,
                    Some(pending.reference),
                ),
                limits,
                active_reservation,
            );
            return ProcessResult::Consumed;
        };
        let Some(target) = field(entry, 4).and_then(|value| ObjectRef::from_cbor(value).ok())
        else {
            cursor.add_finding_with_reservation(
                Finding::simple(
                    FindingKind::MetadataReferenceMissing,
                    FindingLayer::FileVersion,
                    Some(pending.reference),
                ),
                limits,
                active_reservation,
            );
            return ProcessResult::Consumed;
        };
        let Some(size) = field(entry, 5).and_then(as_u64) else {
            cursor.add_finding_with_reservation(
                Finding::simple(
                    FindingKind::SizeMismatch,
                    FindingLayer::FileVersion,
                    Some(target),
                ),
                limits,
                active_reservation,
            );
            return ProcessResult::Consumed;
        };
        let (layer, expected) = if kind == 1 {
            (FindingLayer::Tree, None)
        } else {
            (FindingLayer::Manifest, Some(size))
        };
        children.push((ordinal as u64, target, layer, expected));
    }
    let next_logical_file_bytes = checked_logical_file_bytes(
        cursor.ledger.logical_file_bytes,
        children.iter().filter_map(|(ordinal, _, layer, expected)| {
            (*layer == FindingLayer::Manifest
                && !cursor
                    .file_versions
                    .contains(&(pending.reference, *ordinal)))
            .then_some(expected.unwrap_or(0))
        }),
    );
    let Some(next_logical_file_bytes) = next_logical_file_bytes else {
        return ProcessResult::pause(
            VerificationStatus::CoverageOverflow,
            Finding::simple(
                FindingKind::CoverageOverflow,
                FindingLayer::FileVersion,
                Some(pending.reference),
            ),
        );
    };
    if let Err(result) = stage_children(
        cursor,
        pending.reference,
        &children,
        limits,
        budget,
        active_reservation,
    ) {
        return result;
    }
    for (ordinal, _target, layer, _expected) in &children {
        if *layer == FindingLayer::Manifest {
            cursor.file_versions.insert((pending.reference, *ordinal));
        }
    }
    cursor.ledger.file_versions_traversed = cursor.file_versions.len() as u64;
    cursor.ledger.logical_file_bytes = next_logical_file_bytes;
    cursor.observe_memory(active_reservation);
    match record_covered(
        cursor,
        pending.reference,
        bytes as u64,
        limits,
        active_reservation,
    ) {
        Ok(()) => ProcessResult::Consumed,
        Err(result) => result,
    }
}

fn checked_logical_file_bytes(
    current: u64,
    additions: impl IntoIterator<Item = u64>,
) -> Option<u64> {
    additions
        .into_iter()
        .try_fold(current, |total, value| total.checked_add(value))
}

fn stage_children(
    cursor: &mut VerificationCursor,
    parent: ObjectRef,
    children: &[(u64, ObjectRef, FindingLayer, Option<u64>)],
    limits: &VerificationLimits,
    budget: &mut PageBudget,
    active_reservation: u64,
) -> Result<(), ProcessResult> {
    let new_objects = children
        .iter()
        .filter(|(_, reference, _, _)| !cursor.seen.contains(reference))
        .map(|(_, reference, _, _)| *reference)
        .collect::<BTreeSet<_>>();
    if (cursor.seen.len() + new_objects.len()) as u64 > limits.max_cursor_objects {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(FindingKind::CountLimit, FindingLayer::Source, Some(parent)),
            ManifestRestartRecovery::CursorObjects,
        ));
    }
    let new_edges = children
        .iter()
        .filter(|(ordinal, child, _, _)| {
            !cursor.edges.contains(&EdgeKey {
                parent,
                ordinal: *ordinal,
                child: *child,
            })
        })
        .count() as u64;
    let new_expectations = children
        .iter()
        .filter(|(_, child, _, expected)| {
            expected.is_some()
                && !cursor
                    .expected_lengths
                    .get(child)
                    .is_some_and(|values| values.contains(&expected.expect("present")))
        })
        .count() as u64;
    let new_file_versions = children
        .iter()
        .filter(|(ordinal, _, layer, _)| {
            *layer == FindingLayer::Manifest && !cursor.file_versions.contains(&(parent, *ordinal))
        })
        .count() as u64;
    let work = preflight_work(
        cursor,
        budget,
        limits,
        new_edges,
        ManifestRestartRecovery::WorkUnits,
    )?;
    let predicted = cursor
        .cursor_charge()
        .checked_add(active_reservation)
        .and_then(|value| {
            value.checked_add(new_objects.len() as u64 * (OBJECT_SET_CHARGE + PENDING_CHARGE))
        })
        .and_then(|value| value.checked_add(new_edges * EDGE_CHARGE))
        .and_then(|value| value.checked_add(new_expectations * EXPECTATION_CHARGE))
        .and_then(|value| value.checked_add(new_file_versions * EDGE_CHARGE));
    if predicted.is_none_or(|peak| peak > limits.max_charged_memory_bytes) {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(FindingKind::MemoryLimit, FindingLayer::Source, Some(parent)),
            ManifestRestartRecovery::ChargedMemory,
        ));
    }
    commit_work(cursor, budget, work);
    for (ordinal, child, layer, expected) in children {
        if cursor.edges.insert(EdgeKey {
            parent,
            ordinal: *ordinal,
            child: *child,
        }) {
            cursor.ledger.graph_edges_traversed += 1;
        }
        if let Some(expected) = expected {
            cursor
                .expected_lengths
                .entry(*child)
                .or_default()
                .insert(*expected);
        }
        if cursor.seen.insert(*child) {
            cursor.pending.push_back(PendingObject {
                reference: *child,
                layer: *layer,
            });
        }
    }
    cursor.observe_memory(active_reservation);
    Ok(())
}

fn process_manifest<S: ImmutableObjectSource>(
    pending: PendingObject,
    object: &AdmittedObject,
    cursor: &mut VerificationCursor,
    source: &mut S,
    limits: &VerificationLimits,
    control: &VerificationControl,
    budget: &mut PageBudget,
) -> ProcessResult {
    let bytes = object.bytes.as_slice();
    let object_reservation = object.active_reservation;
    let ledger_memory = limits.max_manifest_ledger_bytes.min(64 * 1024 * 1024);
    let manifest_reservation = object_reservation
        .checked_add(limits.max_manifest_index_bytes)
        .and_then(|value| value.checked_add(ledger_memory));
    let Some(manifest_reservation) = manifest_reservation else {
        return ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                FindingLayer::Manifest,
                Some(pending.reference),
            ),
            ManifestRestartRecovery::ChargedMemory,
        );
    };
    if cursor
        .cursor_charge()
        .checked_add(manifest_reservation)
        .is_none_or(|peak| peak > limits.max_charged_memory_bytes)
    {
        return ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                FindingLayer::Manifest,
                Some(pending.reference),
            ),
            ManifestRestartRecovery::ChargedMemory,
        );
    }
    cursor.observe_memory(manifest_reservation);
    let options = VerifyOptions {
        max_manifest_bytes: usize::try_from(limits.max_object_bytes).unwrap_or(usize::MAX),
        max_decode_working_bytes: usize::try_from(limits.max_decode_working_bytes)
            .unwrap_or(usize::MAX),
        max_index_memory_bytes: limits.max_manifest_index_bytes,
        expected_manifest_object_id: Some(pending.reference.to_string()),
        ledger: LedgerOptions {
            max_memory_bytes: ledger_memory,
            max_scratch_bytes: 0,
            scratch_directory: std::env::temp_dir(),
        },
        control: OperationControl::with_cancellation(control.cancellation_flag(), None),
    };
    let mut adapter = VerifierChunkSource {
        parent: pending.reference,
        source,
        cursor,
        limits,
        control,
        budget,
        active_manifest_reservation: manifest_reservation,
        disposition: None,
    };
    let result = verify_manifest(bytes, &mut adapter, &options);
    if let Some(disposition) = adapter.disposition.take() {
        return match disposition {
            AdapterDisposition::Integrity(finding) => {
                adapter
                    .cursor
                    .add_finding_with_reservation(finding, limits, manifest_reservation);
                ProcessResult::Consumed
            }
            AdapterDisposition::Pause(status, finding, recovery) => {
                ProcessResult::Pause(status, finding, recovery)
            }
        };
    }
    if control.is_cancelled() {
        return ProcessResult::pause(
            VerificationStatus::Cancelled,
            Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
        );
    }
    match result {
        Ok(summary) => {
            if let Err(result) = record_covered(
                adapter.cursor,
                pending.reference,
                bytes.len() as u64,
                limits,
                manifest_reservation,
            ) {
                return result;
            }
            let mut previous = None;
            while let Some(expected) =
                next_expected_length(adapter.cursor, pending.reference, previous)
            {
                previous = Some(expected);
                if expected != summary.logical_bytes {
                    let mut finding = Finding::simple(
                        FindingKind::SizeMismatch,
                        FindingLayer::FileVersion,
                        Some(pending.reference),
                    );
                    finding.evidence = FindingEvidence::Bytes {
                        expected,
                        observed: summary.logical_bytes,
                    };
                    adapter.cursor.add_finding_with_reservation(
                        finding,
                        limits,
                        manifest_reservation,
                    );
                }
            }
            ProcessResult::Consumed
        }
        Err(error) => match classify_manifest_error(error) {
            ManifestErrorClass::Restart(kind, recovery) => ProcessResult::restart(
                VerificationStatus::LimitReached,
                Finding::simple(kind, FindingLayer::Manifest, Some(pending.reference)),
                recovery,
            ),
            ManifestErrorClass::SourceUnavailable(kind) => ProcessResult::pause(
                VerificationStatus::SourceUnavailable,
                Finding::simple(kind, FindingLayer::Source, Some(pending.reference)),
            ),
            ManifestErrorClass::Integrity(kind) => {
                adapter.cursor.add_finding_with_reservation(
                    Finding::simple(kind, FindingLayer::Manifest, Some(pending.reference)),
                    limits,
                    manifest_reservation,
                );
                ProcessResult::Consumed
            }
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManifestErrorClass {
    Integrity(FindingKind),
    Restart(FindingKind, ManifestRestartRecovery),
    SourceUnavailable(FindingKind),
}

fn classify_manifest_error(error: ChunkError) -> ManifestErrorClass {
    match error {
        ChunkError::ResourceExhausted => ManifestErrorClass::Restart(
            FindingKind::MemoryLimit,
            ManifestRestartRecovery::ManifestIndex,
        ),
        ChunkError::ScratchExhausted => ManifestErrorClass::Restart(
            FindingKind::MemoryLimit,
            ManifestRestartRecovery::ManifestLedger,
        ),
        ChunkError::ProfileUnsupported
        | ChunkError::ResourceInvalid
        | ChunkError::ResourceUnsupported
        | ChunkError::FingerprintInputInvalid
        | ChunkError::FragmentInvalid
        | ChunkError::PublicationFailed
        | ChunkError::SessionFailed
        | ChunkError::SessionFinished
        | ChunkError::SinkFailed
        | ChunkError::SinkInvalid
        | ChunkError::SourceInvalid
        | ChunkError::SourceMissing => {
            ManifestErrorClass::SourceUnavailable(FindingKind::SourceFailure)
        }
        // OGVCS-007 rejects manifest part-count ceilings as ManifestMismatch.
        // Its remaining CountExceeded route is a nonrecoverable ledger-counter
        // overflow, not something a larger verifier envelope can cure.
        ChunkError::CountExceeded => ManifestErrorClass::Integrity(FindingKind::ManifestCorrupt),
        _ => ManifestErrorClass::Integrity(FindingKind::ManifestCorrupt),
    }
}

fn next_expected_length(
    cursor: &VerificationCursor,
    reference: ObjectRef,
    previous: Option<u64>,
) -> Option<u64> {
    let values = cursor.expected_lengths.get(&reference)?;
    match previous {
        Some(previous) => values
            .range((
                std::ops::Bound::Excluded(previous),
                std::ops::Bound::Unbounded,
            ))
            .next()
            .copied(),
        None => values.first().copied(),
    }
}

enum AdapterDisposition {
    Integrity(Finding),
    Pause(VerificationStatus, Finding, Option<ManifestRestartRecovery>),
}

struct VerifierChunkSource<'a, S> {
    parent: ObjectRef,
    source: &'a mut S,
    cursor: &'a mut VerificationCursor,
    limits: &'a VerificationLimits,
    control: &'a VerificationControl,
    budget: &'a mut PageBudget,
    active_manifest_reservation: u64,
    disposition: Option<AdapterDisposition>,
}

impl<S: ImmutableObjectSource> ChunkSource for VerifierChunkSource<'_, S> {
    fn stream_chunk(
        &mut self,
        part: &ManifestPart,
        occurrence: usize,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError> {
        if self.control.is_cancelled() {
            self.disposition = Some(AdapterDisposition::Pause(
                VerificationStatus::Cancelled,
                Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
                None,
            ));
            return Err(ChunkError::ResourceExhausted);
        }
        if let Err(result) = record_manifest_edge(
            self.cursor,
            self.parent,
            occurrence as u64,
            part.reference,
            self.limits,
            self.budget,
            self.active_manifest_reservation,
        ) {
            self.disposition = Some(match result {
                ProcessResult::Pause(status, finding, recovery) => {
                    AdapterDisposition::Pause(status, finding, recovery)
                }
                ProcessResult::Consumed => unreachable!("edge admission does not consume"),
            });
            return Err(ChunkError::ResourceExhausted);
        }
        let page_transfer_remaining = self
            .limits
            .max_page_source_bytes
            .saturating_sub(self.budget.source_bytes);
        let transfer_remaining = page_transfer_remaining.min(self.limits.max_object_bytes);
        if transfer_remaining == 0 {
            self.disposition = Some(AdapterDisposition::Pause(
                VerificationStatus::LimitReached,
                Finding::simple(
                    FindingKind::ByteLimit,
                    FindingLayer::Chunk,
                    Some(part.reference),
                ),
                Some(transfer_recovery(
                    page_transfer_remaining,
                    self.limits.max_object_bytes,
                )),
            ));
            return Err(ChunkError::ResourceExhausted);
        }
        let Some(memory_available) = self
            .cursor
            .cursor_charge()
            .checked_add(self.active_manifest_reservation)
            .and_then(|base| self.limits.max_charged_memory_bytes.checked_sub(base))
        else {
            self.memory_limit(part.reference);
            return Err(ChunkError::ResourceExhausted);
        };
        if memory_available == 0 || part.length > memory_available {
            self.memory_limit(part.reference);
            return Err(ChunkError::ResourceExhausted);
        }
        let memory_constrained = memory_available < transfer_remaining;
        let maximum_bytes = transfer_remaining.min(memory_available);
        if part.length > maximum_bytes {
            let kind = if memory_constrained {
                FindingKind::MemoryLimit
            } else {
                FindingKind::ByteLimit
            };
            let mut finding = Finding::simple(kind, FindingLayer::Chunk, Some(part.reference));
            finding.evidence = FindingEvidence::Bytes {
                expected: maximum_bytes,
                observed: part.length,
            };
            self.disposition = Some(AdapterDisposition::Pause(
                VerificationStatus::LimitReached,
                finding,
                Some(if memory_constrained {
                    ManifestRestartRecovery::ChargedMemory
                } else {
                    transfer_recovery(page_transfer_remaining, self.limits.max_object_bytes)
                }),
            ));
            return Err(ChunkError::ResourceExhausted);
        }
        if let Err(result) = charge_source_read(self.cursor, self.budget, self.limits) {
            self.disposition = Some(match result {
                ProcessResult::Pause(status, finding, recovery) => {
                    AdapterDisposition::Pause(status, finding, recovery)
                }
                ProcessResult::Consumed => unreachable!("source budget does not consume"),
            });
            return Err(ChunkError::ResourceExhausted);
        }
        let read = match self.source.read_object(&part.reference, maximum_bytes) {
            Ok(read) => read,
            Err(_) if self.control.is_cancelled() => {
                self.disposition = Some(AdapterDisposition::Pause(
                    VerificationStatus::Cancelled,
                    Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
                    None,
                ));
                return Err(ChunkError::ResourceExhausted);
            }
            Err(_) => {
                self.disposition = Some(AdapterDisposition::Pause(
                    VerificationStatus::SourceUnavailable,
                    Finding::simple(
                        FindingKind::SourceFailure,
                        FindingLayer::Source,
                        Some(part.reference),
                    ),
                    None,
                ));
                return Err(ChunkError::SourceInvalid);
            }
        };
        if let ObjectReadOutcome::Found { bytes, .. } = &read.outcome {
            if let Err(result) =
                record_source_payload_bytes(self.cursor, self.budget, bytes.len() as u64)
            {
                self.disposition = Some(match result {
                    ProcessResult::Pause(status, finding, recovery) => {
                        AdapterDisposition::Pause(status, finding, recovery)
                    }
                    ProcessResult::Consumed => unreachable!("payload accounting does not consume"),
                });
                return Err(ChunkError::ResourceExhausted);
            }
            self.cursor.observe_memory(
                self.active_manifest_reservation
                    .saturating_add(bytes.capacity() as u64),
            );
        }
        if read.generation != self.cursor.generation {
            let mut finding = Finding::simple(
                FindingKind::GenerationChanged,
                FindingLayer::Source,
                Some(part.reference),
            );
            finding.evidence = FindingEvidence::Digest {
                expected: self.cursor.generation,
                observed: read.generation,
            };
            self.disposition = Some(AdapterDisposition::Pause(
                VerificationStatus::GenerationChanged,
                finding,
                None,
            ));
            return Err(ChunkError::SourceInvalid);
        }
        if self.control.is_cancelled() {
            self.disposition = Some(AdapterDisposition::Pause(
                VerificationStatus::Cancelled,
                Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
                None,
            ));
            return Err(ChunkError::ResourceExhausted);
        }
        let (declared_bytes, bytes) = match read.outcome {
            ObjectReadOutcome::Found {
                backend: _,
                declared_bytes,
                bytes,
            } => (declared_bytes, bytes),
            ObjectReadOutcome::Missing => {
                self.integrity(
                    FindingKind::ObjectMissing,
                    FindingLayer::Chunk,
                    part.reference,
                );
                return Err(ChunkError::SourceMissing);
            }
            ObjectReadOutcome::SourceAmbiguous => {
                self.integrity(
                    FindingKind::SourceAmbiguous,
                    FindingLayer::Source,
                    part.reference,
                );
                return Err(ChunkError::SourceInvalid);
            }
            ObjectReadOutcome::BackendAmbiguous => {
                self.integrity(
                    FindingKind::BackendAmbiguous,
                    FindingLayer::Source,
                    part.reference,
                );
                return Err(ChunkError::SourceInvalid);
            }
            ObjectReadOutcome::ByteLimit { declared_bytes } => {
                let mut finding = Finding::simple(
                    if memory_constrained {
                        FindingKind::MemoryLimit
                    } else {
                        FindingKind::ByteLimit
                    },
                    FindingLayer::Chunk,
                    Some(part.reference),
                );
                finding.evidence = FindingEvidence::Bytes {
                    expected: maximum_bytes,
                    observed: declared_bytes,
                };
                self.disposition = Some(AdapterDisposition::Pause(
                    VerificationStatus::LimitReached,
                    finding,
                    Some(if memory_constrained {
                        ManifestRestartRecovery::ChargedMemory
                    } else {
                        transfer_recovery(page_transfer_remaining, self.limits.max_object_bytes)
                    }),
                ));
                return Err(ChunkError::ResourceExhausted);
            }
        };
        let observed_bytes = bytes.len() as u64;
        let observed_capacity = bytes.capacity() as u64;
        if observed_bytes > maximum_bytes || observed_capacity > maximum_bytes {
            let mut finding = Finding::simple(
                FindingKind::SourceFailure,
                FindingLayer::Source,
                Some(part.reference),
            );
            finding.evidence = FindingEvidence::Bytes {
                expected: maximum_bytes,
                observed: observed_bytes.max(observed_capacity),
            };
            self.disposition = Some(AdapterDisposition::Pause(
                VerificationStatus::SourceUnavailable,
                finding,
                None,
            ));
            return Err(ChunkError::SourceInvalid);
        }
        let active_chunk_reservation = self
            .active_manifest_reservation
            .checked_add(observed_capacity)
            .expect("admitted manifest and chunk reservations fit");
        self.cursor.observe_memory(active_chunk_reservation);
        if declared_bytes != observed_bytes {
            let mut finding = Finding::simple(
                FindingKind::SizeMismatch,
                FindingLayer::Chunk,
                Some(part.reference),
            );
            finding.evidence = FindingEvidence::Bytes {
                expected: declared_bytes,
                observed: observed_bytes,
            };
            self.disposition = Some(AdapterDisposition::Integrity(finding));
            return Err(ChunkError::DigestMismatch);
        }
        if part.length != observed_bytes {
            let mut finding = Finding::simple(
                FindingKind::SizeMismatch,
                FindingLayer::Chunk,
                Some(part.reference),
            );
            finding.evidence = FindingEvidence::Bytes {
                expected: part.length,
                observed: observed_bytes,
            };
            self.disposition = Some(AdapterDisposition::Integrity(finding));
            return Err(ChunkError::DigestMismatch);
        }
        let observed_digest = match object_id(ObjectKind::Chunk, &bytes) {
            Ok(value) => value,
            Err(_) => {
                self.integrity(
                    FindingKind::ChunkCorrupt,
                    FindingLayer::Chunk,
                    part.reference,
                );
                return Err(ChunkError::DigestMismatch);
            }
        };
        if observed_digest != part.reference.digest {
            let mut finding = Finding::simple(
                FindingKind::DigestMismatch,
                FindingLayer::Chunk,
                Some(part.reference),
            );
            finding.evidence = FindingEvidence::Digest {
                expected: part.reference.digest,
                observed: observed_digest,
            };
            self.disposition = Some(AdapterDisposition::Integrity(finding));
            return Err(ChunkError::DigestMismatch);
        }
        for fragment in bytes.chunks(self.limits.max_chunk_fragment_bytes) {
            if self.control.is_cancelled() {
                self.disposition = Some(AdapterDisposition::Pause(
                    VerificationStatus::Cancelled,
                    Finding::simple(FindingKind::Cancelled, FindingLayer::Source, None),
                    None,
                ));
                return Err(ChunkError::ResourceExhausted);
            }
            if let Err(result) = charge_work(self.cursor, self.budget, self.limits, 1) {
                self.disposition = Some(match result {
                    ProcessResult::Pause(status, finding, recovery) => {
                        AdapterDisposition::Pause(status, finding, recovery)
                    }
                    ProcessResult::Consumed => unreachable!("work budget does not consume"),
                });
                return Err(ChunkError::ResourceExhausted);
            }
            consume(fragment)?;
        }
        if let Err(result) = record_covered(
            self.cursor,
            part.reference,
            observed_bytes,
            self.limits,
            active_chunk_reservation,
        ) {
            self.disposition = Some(match result {
                ProcessResult::Pause(status, finding, recovery) => {
                    AdapterDisposition::Pause(status, finding, recovery)
                }
                ProcessResult::Consumed => unreachable!("coverage admission does not consume"),
            });
            return Err(ChunkError::ResourceExhausted);
        }
        Ok(())
    }
}

impl<S> VerifierChunkSource<'_, S> {
    fn integrity(&mut self, kind: FindingKind, layer: FindingLayer, reference: ObjectRef) {
        self.disposition = Some(AdapterDisposition::Integrity(Finding::simple(
            kind,
            layer,
            Some(reference),
        )));
    }

    fn memory_limit(&mut self, reference: ObjectRef) {
        self.disposition = Some(AdapterDisposition::Pause(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                FindingLayer::Chunk,
                Some(reference),
            ),
            Some(ManifestRestartRecovery::ChargedMemory),
        ));
    }
}

fn record_manifest_edge(
    cursor: &mut VerificationCursor,
    parent: ObjectRef,
    ordinal: u64,
    child: ObjectRef,
    limits: &VerificationLimits,
    budget: &mut PageBudget,
    active_reservation: u64,
) -> Result<(), ProcessResult> {
    let edge = EdgeKey {
        parent,
        ordinal,
        child,
    };
    if cursor.edges.contains(&edge) {
        return Ok(());
    }
    let work = preflight_work(
        cursor,
        budget,
        limits,
        1,
        ManifestRestartRecovery::WorkUnits,
    )?;
    if cursor
        .cursor_charge()
        .checked_add(active_reservation)
        .and_then(|value| value.checked_add(EDGE_CHARGE))
        .is_none_or(|peak| peak > limits.max_charged_memory_bytes)
    {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                FindingLayer::Manifest,
                Some(parent),
            ),
            ManifestRestartRecovery::ChargedMemory,
        ));
    }
    cursor.edges.insert(edge);
    commit_work(cursor, budget, work);
    cursor.ledger.graph_edges_traversed += 1;
    cursor.ledger.manifest_parts_traversed += 1;
    cursor.observe_memory(active_reservation);
    Ok(())
}

fn record_covered(
    cursor: &mut VerificationCursor,
    reference: ObjectRef,
    bytes: u64,
    limits: &VerificationLimits,
    active_reservation: u64,
) -> Result<(), ProcessResult> {
    if cursor.covered.contains_key(&reference) {
        return Ok(());
    }
    let unique_identities = cursor.seen.len()
        + cursor
            .covered
            .keys()
            .filter(|candidate| !cursor.seen.contains(candidate))
            .count();
    if !cursor.seen.contains(&reference) && unique_identities as u64 >= limits.max_cursor_objects {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::CountLimit,
                layer_for(reference.kind),
                Some(reference),
            ),
            ManifestRestartRecovery::CursorObjects,
        ));
    }
    if cursor
        .cursor_charge()
        .checked_add(active_reservation)
        .and_then(|value| value.checked_add(OBJECT_SET_CHARGE))
        .is_none_or(|peak| peak > limits.max_charged_memory_bytes)
    {
        return Err(ProcessResult::restart(
            VerificationStatus::LimitReached,
            Finding::simple(
                FindingKind::MemoryLimit,
                layer_for(reference.kind),
                Some(reference),
            ),
            ManifestRestartRecovery::ChargedMemory,
        ));
    }
    cursor.covered.insert(reference, bytes);
    match reference.kind {
        ObjectKind::Chunk => {
            cursor.ledger.chunk_objects_verified += 1;
            cursor.ledger.chunk_bytes_verified += bytes;
        }
        _ => {
            cursor.ledger.metadata_objects_verified += 1;
            cursor.ledger.metadata_bytes_verified += bytes;
        }
    }
    cursor.observe_memory(active_reservation);
    Ok(())
}

fn layer_for(kind: ObjectKind) -> FindingLayer {
    match kind {
        ObjectKind::Snapshot => FindingLayer::Snapshot,
        ObjectKind::Tree => FindingLayer::Tree,
        ObjectKind::ContentManifest => FindingLayer::Manifest,
        ObjectKind::Chunk => FindingLayer::Chunk,
        _ => FindingLayer::Source,
    }
}

fn missing_required_graph_reference(value: &Cbor) -> Option<FindingLayer> {
    match field(value, 1).and_then(as_u64) {
        Some(7) => field(value, 18)
            .and_then(|value| ObjectRef::from_cbor(value).ok())
            .is_none()
            .then_some(FindingLayer::Snapshot),
        Some(3) => field(value, 17)
            .and_then(as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    field(entry, 4)
                        .and_then(|value| ObjectRef::from_cbor(value).ok())
                        .is_none()
                })
            })
            .then_some(FindingLayer::FileVersion),
        Some(2) => field(value, 19)
            .and_then(as_array)
            .is_some_and(|parts| {
                parts.iter().any(|part| {
                    field(part, 0)
                        .and_then(|value| ObjectRef::from_cbor(value).ok())
                        .is_none()
                })
            })
            .then_some(FindingLayer::Manifest),
        _ => None,
    }
}

fn field(value: &Cbor, key: u64) -> Option<&Cbor> {
    let Cbor::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate == &Cbor::UInt(key)).then_some(value))
}

fn as_array(value: &Cbor) -> Option<&[Cbor]> {
    match value {
        Cbor::Array(values) => Some(values),
        _ => None,
    }
}

fn as_u64(value: &Cbor) -> Option<u64> {
    match value {
        Cbor::UInt(value) => Some(*value),
        _ => None,
    }
}

fn state_digest(domain: &[u8], cursor: &VerificationCursor) -> [u8; 32] {
    let mut hash = Sha256Writer::new();
    hash.update(domain);
    hash.update(&cursor.generation);
    hash_reference(&mut hash, cursor.root);
    hash_u64(&mut hash, cursor.pending.len() as u64);
    for pending in &cursor.pending {
        hash_reference(&mut hash, pending.reference);
        hash_u64(&mut hash, pending.layer as u64);
    }
    hash_u64(&mut hash, cursor.seen.len() as u64);
    for reference in &cursor.seen {
        hash_reference(&mut hash, *reference);
    }
    hash_u64(&mut hash, cursor.expected_lengths.len() as u64);
    for (reference, values) in &cursor.expected_lengths {
        hash_reference(&mut hash, *reference);
        hash_u64(&mut hash, values.len() as u64);
        for value in values {
            hash_u64(&mut hash, *value);
        }
    }
    hash_u64(&mut hash, cursor.covered.len() as u64);
    for (reference, bytes) in &cursor.covered {
        hash_reference(&mut hash, *reference);
        hash_u64(&mut hash, *bytes);
    }
    hash_u64(&mut hash, cursor.edges.len() as u64);
    for edge in &cursor.edges {
        hash_reference(&mut hash, edge.parent);
        hash_u64(&mut hash, edge.ordinal);
        hash_reference(&mut hash, edge.child);
    }
    hash_u64(&mut hash, cursor.file_versions.len() as u64);
    for (tree, ordinal) in &cursor.file_versions {
        hash_reference(&mut hash, *tree);
        hash_u64(&mut hash, *ordinal);
    }
    hash.update(&[u8::from(cursor.coverage_overflow)]);
    match &cursor.manifest_restart {
        Some(restart) => {
            hash.update(&[1]);
            hash_reference(&mut hash, restart.reference);
            hash_u64(&mut hash, restart.reason as u64);
            hash_u64(&mut hash, restart.recovery as u64);
            for value in [
                restart.failed_limits.max_page_metadata_objects,
                restart.failed_limits.max_page_source_reads,
                restart.failed_limits.max_page_source_bytes,
                restart.failed_limits.max_page_work_units,
                restart.failed_limits.max_object_bytes,
                restart.failed_limits.max_cursor_objects,
                restart.failed_limits.max_findings,
                restart.failed_limits.max_charged_memory_bytes,
                restart.failed_limits.max_decode_working_bytes,
                restart.failed_limits.max_manifest_index_bytes,
                restart.failed_limits.max_manifest_ledger_bytes,
                restart.failed_limits.max_chunk_fragment_bytes as u64,
            ] {
                hash_u64(&mut hash, value);
            }
        }
        None => hash.update(&[0]),
    }
    hash_u64(&mut hash, cursor.findings.len() as u64);
    for finding in &cursor.findings {
        hash_u64(&mut hash, finding.kind as u64);
        hash_u64(&mut hash, finding.layer as u64);
        hash_optional_reference(&mut hash, finding.reference);
        match finding.evidence {
            FindingEvidence::None => hash.update(&[0]),
            FindingEvidence::Bytes { expected, observed } => {
                hash.update(&[1]);
                hash_u64(&mut hash, expected);
                hash_u64(&mut hash, observed);
            }
            FindingEvidence::Digest { expected, observed } => {
                hash.update(&[2]);
                hash.update(&expected);
                hash.update(&observed);
            }
        }
    }
    for value in [
        cursor.ledger.metadata_objects_verified,
        cursor.ledger.metadata_bytes_verified,
        cursor.ledger.chunk_objects_verified,
        cursor.ledger.chunk_bytes_verified,
        cursor.ledger.file_versions_traversed,
        cursor.ledger.logical_file_bytes,
        cursor.ledger.manifest_parts_traversed,
        cursor.ledger.graph_edges_traversed,
        cursor.ledger.source_reads,
        cursor.ledger.source_bytes_read,
        cursor.ledger.work_units,
        cursor.ledger.peak_charged_memory_bytes,
    ] {
        hash_u64(&mut hash, value);
    }
    hash.finish()
}

fn hash_reference(hash: &mut Sha256Writer, reference: ObjectRef) {
    hash.update(&reference.kind.code().to_be_bytes());
    hash.update(&reference.digest);
}

fn hash_optional_reference(hash: &mut Sha256Writer, reference: Option<ObjectRef>) {
    match reference {
        Some(reference) => {
            hash.update(&[1]);
            hash_reference(hash, reference);
        }
        None => hash.update(&[0]),
    }
}

fn hash_u64(hash: &mut Sha256Writer, value: u64) {
    hash.update(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kind: ObjectKind, byte: u8) -> ObjectRef {
        ObjectRef {
            kind,
            digest: [byte; 32],
        }
    }

    fn cursor() -> VerificationCursor {
        let root = reference(ObjectKind::Snapshot, 1);
        VerificationCursor {
            generation: [2; 32],
            root,
            pending: VecDeque::from([PendingObject {
                reference: root,
                layer: FindingLayer::Snapshot,
            }]),
            seen: BTreeSet::from([root]),
            expected_lengths: BTreeMap::new(),
            covered: BTreeMap::new(),
            edges: BTreeSet::new(),
            file_versions: BTreeSet::new(),
            manifest_restart: None,
            coverage_overflow: false,
            findings: BTreeSet::new(),
            ledger: CoverageLedger::default(),
        }
    }

    #[test]
    fn binding_digest_covers_file_version_keys() {
        let baseline = cursor();
        let mut changed = baseline.clone();
        changed
            .file_versions
            .insert((reference(ObjectKind::Tree, 3), 7));
        assert_ne!(baseline.binding_digest(), changed.binding_digest());
    }

    #[test]
    fn binding_digest_covers_terminal_coverage_overflow_state() {
        let baseline = cursor();
        let mut changed = baseline.clone();
        changed.coverage_overflow = true;
        assert_ne!(baseline.binding_digest(), changed.binding_digest());
    }

    #[test]
    fn binding_digest_covers_manifest_restart_recovery_class() {
        let mut index_limited = cursor();
        index_limited.manifest_restart = Some(ManifestRestart {
            reference: reference(ObjectKind::ContentManifest, 4),
            reason: FindingKind::MemoryLimit,
            recovery: ManifestRestartRecovery::ManifestIndex,
            failed_limits: VerificationLimits::default(),
        });
        let mut ledger_limited = index_limited.clone();
        ledger_limited
            .manifest_restart
            .as_mut()
            .expect("restart marker")
            .recovery = ManifestRestartRecovery::ManifestLedger;
        assert_ne!(
            index_limited.binding_digest(),
            ledger_limited.binding_digest()
        );
    }

    #[test]
    fn logical_file_byte_accounting_accepts_the_exact_boundary() {
        assert_eq!(
            checked_logical_file_bytes(u64::MAX - 5, [2, 3]),
            Some(u64::MAX)
        );
    }

    #[test]
    fn logical_file_byte_accounting_rejects_overflow() {
        assert_eq!(checked_logical_file_bytes(u64::MAX - 5, [2, 4]), None);
    }

    #[test]
    fn tree_overflow_returns_a_typed_terminal_outcome_before_graph_mutation() {
        let mut cursor = cursor();
        cursor.ledger.logical_file_bytes = u64::MAX - 5;
        let tree = reference(ObjectKind::Tree, 3);
        let manifest = reference(ObjectKind::ContentManifest, 4);
        let value = Cbor::Map(vec![(
            Cbor::UInt(17),
            Cbor::Array(vec![Cbor::Map(vec![
                (Cbor::UInt(1), Cbor::UInt(2)),
                (Cbor::UInt(4), manifest.to_cbor()),
                (Cbor::UInt(5), Cbor::UInt(6)),
            ])]),
        )]);
        let result = process_tree(
            PendingObject {
                reference: tree,
                layer: FindingLayer::Tree,
            },
            &value,
            0,
            0,
            &mut cursor,
            &VerificationLimits::default(),
            &mut PageBudget::default(),
        );
        match result {
            ProcessResult::Pause(status, finding, _) => {
                assert_eq!(status, VerificationStatus::CoverageOverflow);
                assert_eq!(finding.kind, FindingKind::CoverageOverflow);
                assert_eq!(finding.layer, FindingLayer::FileVersion);
            }
            ProcessResult::Consumed => panic!("overflow must not consume the tree"),
        }
        assert!(cursor.edges.is_empty());
        assert!(cursor.file_versions.is_empty());
        assert_eq!(cursor.ledger.logical_file_bytes, u64::MAX - 5);
    }

    #[test]
    fn shared_tree_object_coverage_uses_unique_entry_definitions() {
        let mut cursor = cursor();
        let tree = reference(ObjectKind::Tree, 3);
        let manifest = reference(ObjectKind::ContentManifest, 4);
        let value = Cbor::Map(vec![(
            Cbor::UInt(17),
            Cbor::Array(vec![Cbor::Map(vec![
                (Cbor::UInt(1), Cbor::UInt(2)),
                (Cbor::UInt(4), manifest.to_cbor()),
                (Cbor::UInt(5), Cbor::UInt(6)),
            ])]),
        )]);
        let pending = PendingObject {
            reference: tree,
            layer: FindingLayer::Tree,
        };
        let limits = VerificationLimits::default();
        let mut budget = PageBudget::default();
        assert!(matches!(
            process_tree(pending, &value, 10, 0, &mut cursor, &limits, &mut budget,),
            ProcessResult::Consumed
        ));
        assert!(matches!(
            process_tree(pending, &value, 10, 0, &mut cursor, &limits, &mut budget,),
            ProcessResult::Consumed
        ));
        assert_eq!(cursor.ledger.file_versions_traversed, 1);
        assert_eq!(cursor.ledger.logical_file_bytes, 6);
        assert_eq!(cursor.ledger.graph_edges_traversed, 1);
        assert_eq!(cursor.ledger.metadata_objects_verified, 1);
    }

    #[test]
    fn cancellation_is_bridged_into_empty_manifest_parsing() {
        struct NoReadSource;

        impl ImmutableObjectSource for NoReadSource {
            type Error = ();

            fn generation(&mut self) -> Result<Generation, Self::Error> {
                Ok([2; 32])
            }

            fn read_object(
                &mut self,
                _reference: &ObjectRef,
                _maximum_bytes: u64,
            ) -> Result<ObjectRead, Self::Error> {
                panic!("an empty manifest has no chunks")
            }
        }

        let manifest =
            ogvcs_chunking_manifest::chunk_bytes(&[], |_, _, _| Ok::<(), ChunkError>(()))
                .expect("empty manifest");
        let bytes = manifest.manifest.bytes;
        let reference = ObjectRef {
            kind: ObjectKind::ContentManifest,
            digest: object_id(ObjectKind::ContentManifest, &bytes).expect("manifest identity"),
        };
        let limits = VerificationLimits::default();
        let object = AdmittedObject {
            active_reservation: bytes.capacity() as u64 * 4 + limits.max_decode_working_bytes,
            bytes,
        };
        let control = VerificationControl::default();
        control.cancel();
        let result = process_manifest(
            PendingObject {
                reference,
                layer: FindingLayer::Manifest,
            },
            &object,
            &mut cursor(),
            &mut NoReadSource,
            &limits,
            &control,
            &mut PageBudget::default(),
        );
        match result {
            ProcessResult::Pause(status, finding, recovery) => {
                assert_eq!(status, VerificationStatus::Cancelled);
                assert_eq!(finding.kind, FindingKind::Cancelled);
                assert_eq!(recovery, None);
            }
            ProcessResult::Consumed => panic!("cancelled manifest must remain pending"),
        }
    }

    #[test]
    fn ogvcs007_counter_overflow_is_terminal_manifest_corruption() {
        assert_eq!(
            classify_manifest_error(ChunkError::CountExceeded),
            ManifestErrorClass::Integrity(FindingKind::ManifestCorrupt)
        );
    }

    #[test]
    fn ogvcs007_resource_failures_name_the_exact_recovery_envelope() {
        assert_eq!(
            classify_manifest_error(ChunkError::ResourceExhausted),
            ManifestErrorClass::Restart(
                FindingKind::MemoryLimit,
                ManifestRestartRecovery::ManifestIndex,
            )
        );
        assert_eq!(
            classify_manifest_error(ChunkError::ScratchExhausted),
            ManifestErrorClass::Restart(
                FindingKind::MemoryLimit,
                ManifestRestartRecovery::ManifestLedger,
            )
        );
    }

    #[test]
    fn ogvcs007_invalid_resource_configuration_is_not_corruption_or_restartable() {
        for error in [
            ChunkError::ProfileUnsupported,
            ChunkError::ResourceInvalid,
            ChunkError::ResourceUnsupported,
            ChunkError::SessionFailed,
            ChunkError::SourceInvalid,
            ChunkError::SourceMissing,
        ] {
            assert_eq!(
                classify_manifest_error(error),
                ManifestErrorClass::SourceUnavailable(FindingKind::SourceFailure)
            );
        }
    }

    #[test]
    fn finding_memory_exhaustion_uses_the_reserved_fail_closed_slot() {
        let mut cursor = cursor();
        let active_reservation = 1_000;
        let limits = VerificationLimits {
            max_charged_memory_bytes: cursor.cursor_charge() + active_reservation,
            ..VerificationLimits::default()
        };
        cursor.add_finding_with_reservation(
            Finding::simple(FindingKind::ObjectMissing, FindingLayer::Tree, None),
            &limits,
            active_reservation,
        );
        cursor.add_finding_with_reservation(
            Finding::simple(FindingKind::DigestMismatch, FindingLayer::Tree, None),
            &limits,
            active_reservation,
        );
        assert_eq!(cursor.findings.len(), 1);
        assert_eq!(
            cursor.findings.first().map(|finding| finding.kind),
            Some(FindingKind::FindingsTruncated)
        );
        assert!(cursor.cursor_charge() <= limits.max_charged_memory_bytes);
        assert!(cursor.ledger.peak_charged_memory_bytes <= limits.max_charged_memory_bytes);
    }
}
