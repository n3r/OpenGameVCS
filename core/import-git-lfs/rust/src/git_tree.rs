use std::{cmp::Ordering, fmt, mem::size_of};

use ogvcs_object_model::Sha256Writer;

use crate::{GitObjectId, OperationControl};

pub const GIT_TREE_ALGORITHM_VERSION: &str = "ogvcs.git-tree-frame/strict@1";
pub const GIT_TREE_FRAME_BYTES_HARD_MAXIMUM: u64 = 1_048_576;
pub const GIT_TREE_ENTRIES_HARD_MAXIMUM: u64 = 4_096;
pub const GIT_TREE_NAME_BYTES_HARD_MAXIMUM: u64 = 4_096;
pub const GIT_TREE_TOTAL_NAME_BYTES_HARD_MAXIMUM: u64 = 1_048_576;
pub const GIT_TREE_WORK_UNITS_HARD_MAXIMUM: u64 = 16_777_216;
pub const GIT_TREE_RETAINED_BYTES_HARD_MAXIMUM: u64 = 2_097_152;

const REQUEST_COMMITMENT_DOMAIN: &[u8] = b"OpenGameVCS Git tree frame request\0v1\0";
const PROJECTION_COMMITMENT_DOMAIN: &[u8] = b"OpenGameVCS Git tree projection\0v1\0";
const FIXED_RETAINED_BYTES: u64 = 1_024;
const ENTRY_RETAINED_BYTES: u64 = 64;
const DUPLICATE_CANDIDATE_RETAINED_BYTES: u64 = 8;
// Combined HFS validation/filtering and NTFS component/separator inspection
// cost at most four name traversals. The raw payload charge below covers one;
// these three additional charges cover the remainder.
const PROTECTED_NAME_WORK_MULTIPLIER: u64 = 3;
// These literal charges conservatively cover each commitment's fixed transcript.
const REQUEST_COMMITMENT_WORK: u64 = 192;
const PROJECTION_FIXED_WORK: u64 = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl GitObjectFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Sha1 => 1,
            Self::Sha256 => 2,
        }
    }

    const fn object_id_bytes(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitTreeLimits {
    pub frame_bytes_maximum: u64,
    pub entries_maximum: u64,
    pub name_bytes_maximum: u64,
    pub total_name_bytes_maximum: u64,
    pub work_units_maximum: u64,
    pub retained_bytes_maximum: u64,
}

impl Default for GitTreeLimits {
    fn default() -> Self {
        Self {
            frame_bytes_maximum: GIT_TREE_FRAME_BYTES_HARD_MAXIMUM,
            entries_maximum: GIT_TREE_ENTRIES_HARD_MAXIMUM,
            name_bytes_maximum: GIT_TREE_NAME_BYTES_HARD_MAXIMUM,
            total_name_bytes_maximum: GIT_TREE_TOTAL_NAME_BYTES_HARD_MAXIMUM,
            work_units_maximum: GIT_TREE_WORK_UNITS_HARD_MAXIMUM,
            retained_bytes_maximum: GIT_TREE_RETAINED_BYTES_HARD_MAXIMUM,
        }
    }
}

impl GitTreeLimits {
    fn validate(self) -> GitTreeResult<()> {
        for (value, hard_maximum) in [
            (self.frame_bytes_maximum, GIT_TREE_FRAME_BYTES_HARD_MAXIMUM),
            (self.entries_maximum, GIT_TREE_ENTRIES_HARD_MAXIMUM),
            (self.name_bytes_maximum, GIT_TREE_NAME_BYTES_HARD_MAXIMUM),
            (
                self.total_name_bytes_maximum,
                GIT_TREE_TOTAL_NAME_BYTES_HARD_MAXIMUM,
            ),
            (self.work_units_maximum, GIT_TREE_WORK_UNITS_HARD_MAXIMUM),
            (
                self.retained_bytes_maximum,
                GIT_TREE_RETAINED_BYTES_HARD_MAXIMUM,
            ),
        ] {
            if value == 0 || value > hard_maximum {
                return Err(git_tree_error(GitTreeErrorCode::InvalidLimits, None));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct GitTreeFrame<'a> {
    pub bytes: &'a [u8],
    pub staged_sha256: [u8; 32],
    pub object_format: GitObjectFormat,
}

impl fmt::Debug for GitTreeFrame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitTreeFrame")
            .field(
                "bytes",
                &format_args!("<redacted:{} bytes>", self.bytes.len()),
            )
            .field("staged_sha256", &"<redacted>")
            .field("object_format", &self.object_format)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitTreeEntryMode {
    Tree,
    Regular,
    Executable,
    Symlink,
    Gitlink,
}

impl GitTreeEntryMode {
    pub const fn canonical_octal(self) -> &'static str {
        match self {
            Self::Tree => "40000",
            Self::Regular => "100644",
            Self::Executable => "100755",
            Self::Symlink => "120000",
            Self::Gitlink => "160000",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Tree => 1,
            Self::Regular => 2,
            Self::Executable => 3,
            Self::Symlink => 4,
            Self::Gitlink => 5,
        }
    }

    const fn is_tree(self) -> bool {
        matches!(self, Self::Tree)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GitTreeEntry {
    mode: GitTreeEntryMode,
    name: Box<[u8]>,
    object_id: GitObjectId,
}

const _: () = assert!(size_of::<GitTreeEntry>() <= ENTRY_RETAINED_BYTES as usize);

impl GitTreeEntry {
    pub const fn mode(&self) -> GitTreeEntryMode {
        self.mode
    }

    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub const fn object_id(&self) -> GitObjectId {
        self.object_id
    }
}

impl fmt::Debug for GitTreeEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitTreeEntry")
            .field("mode", &self.mode)
            .field(
                "name",
                &format_args!("<redacted:{} bytes>", self.name.len()),
            )
            .field("object_id", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitTreeLedger {
    pub frame_bytes: u64,
    pub payload_bytes: u64,
    pub entries: u64,
    pub name_bytes: u64,
    pub work_units: u64,
    pub cancellation_checks: u64,
    pub admitted_retained_bytes: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GitTreeProjection {
    object_format: GitObjectFormat,
    staged_sha256: [u8; 32],
    request_commitment: [u8; 32],
    projection_commitment: [u8; 32],
    entries: Box<[GitTreeEntry]>,
    ledger: GitTreeLedger,
}

impl GitTreeProjection {
    pub const fn algorithm_version(&self) -> &'static str {
        GIT_TREE_ALGORITHM_VERSION
    }

    pub const fn object_format(&self) -> GitObjectFormat {
        self.object_format
    }

    pub const fn staged_sha256(&self) -> [u8; 32] {
        self.staged_sha256
    }

    pub const fn request_commitment(&self) -> [u8; 32] {
        self.request_commitment
    }

    pub const fn projection_commitment(&self) -> [u8; 32] {
        self.projection_commitment
    }

    pub fn entries(&self) -> &[GitTreeEntry] {
        &self.entries
    }

    pub const fn ledger(&self) -> GitTreeLedger {
        self.ledger
    }
}

impl fmt::Debug for GitTreeProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitTreeProjection")
            .field("object_format", &self.object_format)
            .field("staged_sha256", &"<redacted>")
            .field("request_commitment", &"<redacted>")
            .field("projection_commitment", &"<redacted>")
            .field(
                "entries",
                &format_args!("<redacted:{} entries>", self.entries.len()),
            )
            .field("ledger", &self.ledger)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitTreeErrorCode {
    InvalidLimits,
    LimitFrameBytes,
    LimitEntries,
    LimitNameBytes,
    LimitTotalNameBytes,
    LimitWork,
    LimitRetainedBytes,
    StagedDigestMismatch,
    HeaderFramingInvalid,
    HeaderTypeInvalid,
    HeaderSizeInvalid,
    ModeFramingInvalid,
    ModeUnsupported,
    NameInvalid,
    NameGitMetadataAlias,
    ObjectIdTruncated,
    ObjectIdZero,
    EntryDuplicate,
    EntryOrderInvalid,
    Cancelled,
    Arithmetic,
    InvariantViolation,
}

impl GitTreeErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLimits => "GIT_TREE_LIMITS_INVALID",
            Self::LimitFrameBytes => "GIT_TREE_FRAME_BYTES_LIMIT",
            Self::LimitEntries => "GIT_TREE_ENTRIES_LIMIT",
            Self::LimitNameBytes => "GIT_TREE_NAME_BYTES_LIMIT",
            Self::LimitTotalNameBytes => "GIT_TREE_TOTAL_NAME_BYTES_LIMIT",
            Self::LimitWork => "GIT_TREE_WORK_LIMIT",
            Self::LimitRetainedBytes => "GIT_TREE_RETAINED_BYTES_LIMIT",
            Self::StagedDigestMismatch => "GIT_TREE_STAGED_DIGEST_MISMATCH",
            Self::HeaderFramingInvalid => "GIT_TREE_HEADER_FRAMING_INVALID",
            Self::HeaderTypeInvalid => "GIT_TREE_HEADER_TYPE_INVALID",
            Self::HeaderSizeInvalid => "GIT_TREE_HEADER_SIZE_INVALID",
            Self::ModeFramingInvalid => "GIT_TREE_MODE_FRAMING_INVALID",
            Self::ModeUnsupported => "GIT_TREE_MODE_UNSUPPORTED",
            Self::NameInvalid => "GIT_TREE_NAME_INVALID",
            Self::NameGitMetadataAlias => "GIT_TREE_NAME_GIT_METADATA_ALIAS",
            Self::ObjectIdTruncated => "GIT_TREE_OBJECT_ID_TRUNCATED",
            Self::ObjectIdZero => "GIT_TREE_OBJECT_ID_ZERO",
            Self::EntryDuplicate => "GIT_TREE_ENTRY_DUPLICATE",
            Self::EntryOrderInvalid => "GIT_TREE_ENTRY_ORDER_INVALID",
            Self::Cancelled => "GIT_TREE_CANCELLED",
            Self::Arithmetic => "GIT_TREE_ARITHMETIC",
            Self::InvariantViolation => "GIT_TREE_INVARIANT_VIOLATION",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitTreeError {
    code: GitTreeErrorCode,
    entry_ordinal: Option<u32>,
}

impl GitTreeError {
    pub const fn code(self) -> GitTreeErrorCode {
        self.code
    }

    pub const fn entry_ordinal(self) -> Option<u32> {
        self.entry_ordinal
    }
}

impl fmt::Display for GitTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for GitTreeError {}

pub type GitTreeResult<T> = std::result::Result<T, GitTreeError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GitTreePhase {
    Start,
    Digest,
    Header,
    Prescan,
    Order,
    Materialize,
    Finalize,
}

struct Budget<'a> {
    limits: GitTreeLimits,
    probe: &'a mut dyn FnMut(GitTreePhase) -> bool,
    work_units: u64,
    cancellation_checks: u64,
}

impl Budget<'_> {
    fn check_cancel(&mut self, phase: GitTreePhase) -> GitTreeResult<()> {
        self.cancellation_checks = checked_add(self.cancellation_checks, 1)?;
        if (self.probe)(phase) {
            Err(git_tree_error(GitTreeErrorCode::Cancelled, None))
        } else {
            Ok(())
        }
    }

    fn work(&mut self, amount: u64) -> GitTreeResult<()> {
        let next = checked_add(self.work_units, amount)?;
        if next > self.limits.work_units_maximum {
            return Err(git_tree_error(GitTreeErrorCode::LimitWork, None));
        }
        self.work_units = next;
        Ok(())
    }

    fn ensure_work(&self, amount: u64) -> GitTreeResult<()> {
        let Some(next) = self.work_units.checked_add(amount) else {
            return Err(git_tree_error(GitTreeErrorCode::Arithmetic, None));
        };
        if next > self.limits.work_units_maximum {
            Err(git_tree_error(GitTreeErrorCode::LimitWork, None))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
struct ParsedEntry<'a> {
    mode: GitTreeEntryMode,
    name: &'a [u8],
    object_id: &'a [u8],
    name_start: usize,
    next: usize,
}

#[derive(Clone, Copy)]
struct DuplicateCandidate {
    name_start: u32,
    name_len: u32,
}

const _: () =
    assert!(size_of::<DuplicateCandidate>() <= DUPLICATE_CANDIDATE_RETAINED_BYTES as usize);

#[derive(Clone, Copy)]
struct ScanSummary {
    entries: u64,
    name_bytes: u64,
    retained_bytes: u64,
}

/// Decodes one already-inflated Git tree frame. This pure function performs no
/// decompression, object lookup, filesystem/network access, authorization,
/// sandbox execution, mapping, conversion, persistence, or publication. The
/// verified SHA-256 is a staging-byte commitment, not a Git object identity.
pub fn decode_git_tree_frame(
    frame: GitTreeFrame<'_>,
    limits: GitTreeLimits,
    control: &OperationControl,
) -> GitTreeResult<GitTreeProjection> {
    decode_git_tree_with_probe(frame, limits, &mut |_| control.is_cancelled())
}

fn decode_git_tree_with_probe(
    frame: GitTreeFrame<'_>,
    limits: GitTreeLimits,
    probe: &mut dyn FnMut(GitTreePhase) -> bool,
) -> GitTreeResult<GitTreeProjection> {
    limits.validate()?;
    let frame_bytes = u64::try_from(frame.bytes.len()).map_err(|_| arithmetic())?;
    if frame_bytes > limits.frame_bytes_maximum {
        return Err(git_tree_error(GitTreeErrorCode::LimitFrameBytes, None));
    }
    let mut budget = Budget {
        limits,
        probe,
        work_units: 0,
        cancellation_checks: 0,
    };
    budget.check_cancel(GitTreePhase::Start)?;
    let actual_digest = digest_bytes(frame.bytes, GitTreePhase::Digest, &mut budget)?;
    if actual_digest != frame.staged_sha256 {
        return Err(git_tree_error(GitTreeErrorCode::StagedDigestMismatch, None));
    }
    budget.work(REQUEST_COMMITMENT_WORK)?;
    let request_commitment = request_commitment(frame, limits)?;
    let payload = parse_header(frame.bytes, &mut budget)?;
    let scan = scan_payload_shape(payload, frame.object_format, limits, &mut budget)?;
    let payload_bytes = u64::try_from(payload.len()).map_err(|_| arithmetic())?;
    let object_id_bytes =
        u64::try_from(frame.object_format.object_id_bytes()).map_err(|_| arithmetic())?;
    let materialize_work = payload_bytes;
    let projection_work = checked_add(
        PROJECTION_FIXED_WORK,
        checked_add(
            scan.name_bytes,
            checked_mul(scan.entries, checked_add(object_id_bytes, 24)?)?,
        )?,
    )?;
    // One raw payload scan, adjacent comparisons bounded by aggregate names
    // plus one unit per entry, candidate-prefix comparisons bounded by aggregate
    // names, and four fixed branch/stack units per entry.
    let order_work_bound = checked_add(
        payload_bytes,
        checked_add(
            checked_mul(scan.name_bytes, 2)?,
            checked_mul(scan.entries, 5)?,
        )?,
    )?;
    budget.ensure_work(checked_add(
        order_work_bound,
        checked_add(materialize_work, projection_work)?,
    )?)?;
    let work_before_order = budget.work_units;
    validate_payload_order(
        payload,
        frame.object_format,
        limits,
        scan.entries,
        &mut budget,
    )?;
    let actual_order_work = budget
        .work_units
        .checked_sub(work_before_order)
        .ok_or_else(arithmetic)?;
    if actual_order_work > order_work_bound {
        return Err(git_tree_error(GitTreeErrorCode::InvariantViolation, None));
    }
    // Bind the full admitted allowance, rather than data-dependent slack, so a
    // replay using ledger.work_units as its exact maximum remains admissible.
    budget.work(
        order_work_bound
            .checked_sub(actual_order_work)
            .ok_or_else(arithmetic)?,
    )?;
    budget.ensure_work(checked_add(materialize_work, projection_work)?)?;
    budget.check_cancel(GitTreePhase::Materialize)?;
    budget.work(materialize_work)?;
    let entries = materialize_entries(
        payload,
        frame.object_format,
        limits,
        scan.entries,
        &mut budget,
    )?
    .into_boxed_slice();
    budget.check_cancel(GitTreePhase::Finalize)?;
    budget.work(projection_work)?;
    let final_cancellation_checks = checked_add(budget.cancellation_checks, 1)?;
    let ledger = GitTreeLedger {
        frame_bytes,
        payload_bytes,
        entries: scan.entries,
        name_bytes: scan.name_bytes,
        work_units: budget.work_units,
        cancellation_checks: final_cancellation_checks,
        admitted_retained_bytes: scan.retained_bytes,
    };
    let projection_commitment =
        projection_commitment(frame.object_format, request_commitment, &entries, ledger)?;
    budget.check_cancel(GitTreePhase::Finalize)?;
    if budget.cancellation_checks != ledger.cancellation_checks {
        return Err(git_tree_error(GitTreeErrorCode::InvariantViolation, None));
    }
    Ok(GitTreeProjection {
        object_format: frame.object_format,
        staged_sha256: frame.staged_sha256,
        request_commitment,
        projection_commitment,
        entries,
        ledger,
    })
}

fn digest_bytes(
    bytes: &[u8],
    phase: GitTreePhase,
    budget: &mut Budget<'_>,
) -> GitTreeResult<[u8; 32]> {
    let mut digest = Sha256Writer::new();
    for chunk in bytes.chunks(4_096) {
        budget.check_cancel(phase)?;
        budget.work(u64::try_from(chunk.len()).map_err(|_| arithmetic())?)?;
        digest.update(chunk);
    }
    if bytes.is_empty() {
        budget.check_cancel(phase)?;
    }
    Ok(digest.finish())
}

fn parse_header<'a>(bytes: &'a [u8], budget: &mut Budget<'_>) -> GitTreeResult<&'a [u8]> {
    budget.check_cancel(GitTreePhase::Header)?;
    if bytes.get(..4) != Some(&b"tree"[..]) {
        return Err(git_tree_error(GitTreeErrorCode::HeaderTypeInvalid, None));
    }
    if bytes.get(4) != Some(&b' ') {
        return Err(git_tree_error(GitTreeErrorCode::HeaderFramingInvalid, None));
    }
    let size_start = 5usize;
    let size_search_end = size_start
        .checked_add(21)
        .map(|end| end.min(bytes.len()))
        .ok_or_else(arithmetic)?;
    let Some(nul_offset) = bytes[size_start..size_search_end]
        .iter()
        .position(|byte| *byte == 0)
    else {
        return Err(git_tree_error(GitTreeErrorCode::HeaderFramingInvalid, None));
    };
    let nul = size_start.checked_add(nul_offset).ok_or_else(arithmetic)?;
    let size_bytes = &bytes[size_start..nul];
    if size_bytes.is_empty()
        || (size_bytes.len() > 1 && size_bytes[0] == b'0')
        || !size_bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(git_tree_error(GitTreeErrorCode::HeaderSizeInvalid, None));
    }
    let mut declared = 0u64;
    for byte in size_bytes {
        declared = declared
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or_else(|| git_tree_error(GitTreeErrorCode::HeaderSizeInvalid, None))?;
    }
    let payload_start = nul.checked_add(1).ok_or_else(arithmetic)?;
    let payload = bytes
        .get(payload_start..)
        .ok_or_else(|| git_tree_error(GitTreeErrorCode::HeaderFramingInvalid, None))?;
    if declared != u64::try_from(payload.len()).map_err(|_| arithmetic())? {
        return Err(git_tree_error(GitTreeErrorCode::HeaderSizeInvalid, None));
    }
    budget.work(u64::try_from(payload_start).map_err(|_| arithmetic())?)?;
    Ok(payload)
}

fn scan_payload_shape(
    payload: &[u8],
    format: GitObjectFormat,
    limits: GitTreeLimits,
    budget: &mut Budget<'_>,
) -> GitTreeResult<ScanSummary> {
    budget.check_cancel(GitTreePhase::Prescan)?;
    let mut position = 0usize;
    let mut entries = 0u64;
    let mut name_bytes = 0u64;
    while position < payload.len() {
        budget.check_cancel(GitTreePhase::Prescan)?;
        entries = checked_add(entries, 1)?;
        if entries > limits.entries_maximum {
            return Err(git_tree_error(GitTreeErrorCode::LimitEntries, None));
        }
        let ordinal = u32::try_from(entries - 1).map_err(|_| arithmetic())?;
        let entry = parse_entry(payload, position, format, limits, ordinal)?;
        let entry_name_bytes = u64::try_from(entry.name.len()).map_err(|_| arithmetic())?;
        budget.work(checked_mul(
            entry_name_bytes,
            PROTECTED_NAME_WORK_MULTIPLIER,
        )?)?;
        if is_hfs_dotgit(entry.name) || is_ntfs_dotgit(entry.name) {
            return Err(git_tree_error(
                GitTreeErrorCode::NameGitMetadataAlias,
                Some(ordinal),
            ));
        }
        name_bytes = checked_add(name_bytes, entry_name_bytes)?;
        if name_bytes > limits.total_name_bytes_maximum {
            return Err(git_tree_error(
                GitTreeErrorCode::LimitTotalNameBytes,
                Some(ordinal),
            ));
        }
        budget.work(u64::try_from(entry.next - position).map_err(|_| arithmetic())?)?;
        position = entry.next;
    }
    let entry_storage = checked_mul(entries, ENTRY_RETAINED_BYTES)?;
    let output_retained_bytes = checked_add(
        FIXED_RETAINED_BYTES,
        checked_add(entry_storage, name_bytes)?,
    )?;
    let candidate_retained_bytes = checked_add(
        FIXED_RETAINED_BYTES,
        checked_mul(entries, DUPLICATE_CANDIDATE_RETAINED_BYTES)?,
    )?;
    // Validation scratch is dropped before output allocation, so peak logical
    // retention is the maximum of these non-overlapping states, not their sum.
    let retained_bytes = output_retained_bytes.max(candidate_retained_bytes);
    if retained_bytes > limits.retained_bytes_maximum {
        return Err(git_tree_error(GitTreeErrorCode::LimitRetainedBytes, None));
    }
    Ok(ScanSummary {
        entries,
        name_bytes,
        retained_bytes,
    })
}

fn validate_payload_order<'a>(
    payload: &'a [u8],
    format: GitObjectFormat,
    limits: GitTreeLimits,
    expected_entries: u64,
    budget: &mut Budget<'_>,
) -> GitTreeResult<()> {
    budget.check_cancel(GitTreePhase::Order)?;
    let capacity = usize::try_from(expected_entries).map_err(|_| arithmetic())?;
    let mut duplicate_candidates: Vec<DuplicateCandidate> = Vec::with_capacity(capacity);
    let mut position = 0usize;
    let mut entries = 0u64;
    let mut previous: Option<ParsedEntry<'a>> = None;
    while position < payload.len() {
        budget.check_cancel(GitTreePhase::Order)?;
        let ordinal = u32::try_from(entries).map_err(|_| arithmetic())?;
        let entry = parse_entry(payload, position, format, limits, ordinal)?;
        budget.work(4)?;
        if let Some(prior) = previous {
            let comparison = git_tree_name_order(prior, entry)?;
            budget.work(comparison.compared)?;
            if comparison.same_name {
                return Err(git_tree_error(
                    GitTreeErrorCode::EntryDuplicate,
                    Some(ordinal),
                ));
            }
            if comparison.ordering != Ordering::Less {
                return Err(git_tree_error(
                    GitTreeErrorCode::EntryOrderInvalid,
                    Some(ordinal),
                ));
            }
            track_nonconsecutive_duplicate(
                prior,
                entry,
                comparison,
                payload,
                &mut duplicate_candidates,
                budget,
                ordinal,
            )?;
        }
        budget.work(u64::try_from(entry.next - position).map_err(|_| arithmetic())?)?;
        entries = checked_add(entries, 1)?;
        previous = Some(entry);
        position = entry.next;
    }
    if entries != expected_entries {
        return Err(git_tree_error(GitTreeErrorCode::InvariantViolation, None));
    }
    Ok(())
}

fn parse_entry(
    payload: &[u8],
    position: usize,
    format: GitObjectFormat,
    limits: GitTreeLimits,
    ordinal: u32,
) -> GitTreeResult<ParsedEntry<'_>> {
    let mode_search_end = position
        .checked_add(7)
        .map(|end| end.min(payload.len()))
        .ok_or_else(arithmetic)?;
    let Some(space_offset) = payload[position..mode_search_end]
        .iter()
        .position(|byte| *byte == b' ')
    else {
        return Err(git_tree_error(
            GitTreeErrorCode::ModeFramingInvalid,
            Some(ordinal),
        ));
    };
    let space = position.checked_add(space_offset).ok_or_else(arithmetic)?;
    let mode = parse_mode(&payload[position..space], ordinal)?;
    let name_start = space.checked_add(1).ok_or_else(arithmetic)?;
    let configured_name_maximum =
        usize::try_from(limits.name_bytes_maximum).map_err(|_| arithmetic())?;
    let name_search_end = name_start
        .checked_add(configured_name_maximum)
        .and_then(|end| end.checked_add(1))
        .map(|end| end.min(payload.len()))
        .ok_or_else(arithmetic)?;
    let Some(nul_offset) = payload[name_start..name_search_end]
        .iter()
        .position(|byte| *byte == 0)
    else {
        if payload.len().saturating_sub(name_start) > configured_name_maximum {
            return Err(git_tree_error(
                GitTreeErrorCode::LimitNameBytes,
                Some(ordinal),
            ));
        }
        return Err(git_tree_error(GitTreeErrorCode::NameInvalid, Some(ordinal)));
    };
    if nul_offset > configured_name_maximum {
        return Err(git_tree_error(
            GitTreeErrorCode::LimitNameBytes,
            Some(ordinal),
        ));
    }
    let nul = name_start.checked_add(nul_offset).ok_or_else(arithmetic)?;
    let name = &payload[name_start..nul];
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(git_tree_error(GitTreeErrorCode::NameInvalid, Some(ordinal)));
    }
    let object_id_start = nul.checked_add(1).ok_or_else(arithmetic)?;
    let object_id_end = object_id_start
        .checked_add(format.object_id_bytes())
        .ok_or_else(arithmetic)?;
    let Some(object_id) = payload.get(object_id_start..object_id_end) else {
        return Err(git_tree_error(
            GitTreeErrorCode::ObjectIdTruncated,
            Some(ordinal),
        ));
    };
    if object_id.iter().all(|byte| *byte == 0) {
        return Err(git_tree_error(
            GitTreeErrorCode::ObjectIdZero,
            Some(ordinal),
        ));
    }
    Ok(ParsedEntry {
        mode,
        name,
        object_id,
        name_start,
        next: object_id_end,
    })
}

fn parse_mode(bytes: &[u8], ordinal: u32) -> GitTreeResult<GitTreeEntryMode> {
    match bytes {
        b"40000" => Ok(GitTreeEntryMode::Tree),
        b"100644" => Ok(GitTreeEntryMode::Regular),
        b"100755" => Ok(GitTreeEntryMode::Executable),
        b"120000" => Ok(GitTreeEntryMode::Symlink),
        b"160000" => Ok(GitTreeEntryMode::Gitlink),
        _ if !bytes.is_empty() && bytes.iter().all(|byte| matches!(byte, b'0'..=b'7')) => Err(
            git_tree_error(GitTreeErrorCode::ModeUnsupported, Some(ordinal)),
        ),
        _ => Err(git_tree_error(
            GitTreeErrorCode::ModeFramingInvalid,
            Some(ordinal),
        )),
    }
}

fn is_ntfs_dotgit(name: &[u8]) -> bool {
    let mut component = name;
    loop {
        if is_ntfs_dotgit_component(component) {
            return true;
        }
        let Some(separator) = component.iter().position(|byte| *byte == b'\\') else {
            return false;
        };
        component = &component[separator + 1..];
    }
}

fn is_ntfs_dotgit_component(name: &[u8]) -> bool {
    let suffix = if name.len() >= 4 && name[0] == b'.' && name[1..4].eq_ignore_ascii_case(b"git") {
        &name[4..]
    } else if name.len() >= 5
        && name[..3].eq_ignore_ascii_case(b"git")
        && name[3] == b'~'
        && name[4] == b'1'
    {
        &name[5..]
    } else {
        return false;
    };
    for byte in suffix {
        if matches!(*byte, b'\\' | b'/' | b':') {
            return true;
        }
        if !matches!(*byte, b'.' | b' ') {
            return false;
        }
    }
    true
}

fn is_hfs_dotgit(name: &[u8]) -> bool {
    // Git's next_hfs_char treats the first malformed UTF-8 sequence as an end
    // marker. Preserve that behavior: malformed bytes after a complete `.git`
    // therefore still name the protected entry, while malformed bytes before
    // the complete needle cannot match it.
    let valid_bytes = match std::str::from_utf8(name) {
        Ok(_) => name,
        Err(error) => &name[..error.valid_up_to()],
    };
    let name = std::str::from_utf8(valid_bytes).expect("valid_up_to is valid UTF-8");
    let mut visible = name.chars().filter(|character| !is_hfs_ignored(*character));
    for expected in ['.', 'g', 'i', 't'] {
        let Some(actual) = visible.next() else {
            return false;
        };
        if actual.to_ascii_lowercase() != expected {
            return false;
        }
    }
    visible.next().is_none()
}

const fn is_hfs_ignored(character: char) -> bool {
    matches!(
        character,
        '\u{200c}'
            | '\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'
            | '\u{202b}'
            | '\u{202c}'
            | '\u{202d}'
            | '\u{202e}'
            | '\u{206a}'
            | '\u{206b}'
            | '\u{206c}'
            | '\u{206d}'
            | '\u{206e}'
            | '\u{206f}'
            | '\u{feff}'
    )
}

#[derive(Clone, Copy)]
struct TreeNameComparison {
    ordering: Ordering,
    compared: u64,
    prefix_equal: bool,
    same_name: bool,
    left_next: u8,
    right_next: u8,
}

fn git_tree_name_order(
    left: ParsedEntry<'_>,
    right: ParsedEntry<'_>,
) -> GitTreeResult<TreeNameComparison> {
    let shared = left.name.len().min(right.name.len());
    for index in 0..shared {
        match left.name[index].cmp(&right.name[index]) {
            Ordering::Equal => {}
            ordering => {
                return Ok(TreeNameComparison {
                    ordering,
                    compared: u64::try_from(index + 1).map_err(|_| arithmetic())?,
                    prefix_equal: false,
                    same_name: false,
                    left_next: 0,
                    right_next: 0,
                });
            }
        }
    }
    let left_next = if left.name.len() == shared {
        if left.mode.is_tree() {
            b'/'
        } else {
            0
        }
    } else {
        left.name[shared]
    };
    let right_next = if right.name.len() == shared {
        if right.mode.is_tree() {
            b'/'
        } else {
            0
        }
    } else {
        right.name[shared]
    };
    Ok(TreeNameComparison {
        ordering: left_next.cmp(&right_next),
        compared: checked_add(u64::try_from(shared).map_err(|_| arithmetic())?, 1)?,
        prefix_equal: true,
        same_name: left.name.len() == right.name.len(),
        left_next,
        right_next,
    })
}

fn track_nonconsecutive_duplicate(
    prior: ParsedEntry<'_>,
    current: ParsedEntry<'_>,
    comparison: TreeNameComparison,
    payload: &[u8],
    candidates: &mut Vec<DuplicateCandidate>,
    budget: &mut Budget<'_>,
    ordinal: u32,
) -> GitTreeResult<()> {
    if !comparison.prefix_equal {
        return Ok(());
    }
    if comparison.left_next == 0 && is_less_than_slash(comparison.right_next) {
        push_duplicate_candidate(candidates, duplicate_candidate(prior)?)?;
    } else if comparison.right_next == b'/' && is_less_than_slash(comparison.left_next) {
        while let Some(candidate) = candidates.pop() {
            budget.check_cancel(GitTreePhase::Order)?;
            let candidate_name = duplicate_candidate_name(candidate, payload)?;
            let (is_prefix, compared) = byte_prefix(candidate_name, current.name)?;
            budget.work(compared)?;
            if !is_prefix {
                continue;
            }
            let suffix = current
                .name
                .get(candidate_name.len()..)
                .ok_or_else(arithmetic)?;
            if suffix.is_empty() {
                return Err(git_tree_error(
                    GitTreeErrorCode::EntryDuplicate,
                    Some(ordinal),
                ));
            }
            if is_less_than_slash(suffix[0]) {
                push_duplicate_candidate(candidates, candidate)?;
                break;
            }
        }
    }
    Ok(())
}

const fn is_less_than_slash(byte: u8) -> bool {
    byte > 0 && byte < b'/'
}

fn duplicate_candidate(entry: ParsedEntry<'_>) -> GitTreeResult<DuplicateCandidate> {
    Ok(DuplicateCandidate {
        name_start: u32::try_from(entry.name_start).map_err(|_| arithmetic())?,
        name_len: u32::try_from(entry.name.len()).map_err(|_| arithmetic())?,
    })
}

fn duplicate_candidate_name(candidate: DuplicateCandidate, payload: &[u8]) -> GitTreeResult<&[u8]> {
    let start = usize::try_from(candidate.name_start).map_err(|_| arithmetic())?;
    let length = usize::try_from(candidate.name_len).map_err(|_| arithmetic())?;
    let end = start.checked_add(length).ok_or_else(arithmetic)?;
    payload
        .get(start..end)
        .ok_or_else(|| git_tree_error(GitTreeErrorCode::InvariantViolation, None))
}

fn push_duplicate_candidate(
    candidates: &mut Vec<DuplicateCandidate>,
    candidate: DuplicateCandidate,
) -> GitTreeResult<()> {
    if candidates.len() == candidates.capacity() {
        return Err(git_tree_error(GitTreeErrorCode::InvariantViolation, None));
    }
    candidates.push(candidate);
    Ok(())
}

fn byte_prefix(prefix: &[u8], value: &[u8]) -> GitTreeResult<(bool, u64)> {
    let shared = prefix.len().min(value.len());
    for index in 0..shared {
        if prefix[index] != value[index] {
            return Ok((false, u64::try_from(index + 1).map_err(|_| arithmetic())?));
        }
    }
    Ok((
        prefix.len() <= value.len(),
        u64::try_from(shared).map_err(|_| arithmetic())?,
    ))
}

fn materialize_entries(
    payload: &[u8],
    format: GitObjectFormat,
    limits: GitTreeLimits,
    expected_entries: u64,
    budget: &mut Budget<'_>,
) -> GitTreeResult<Vec<GitTreeEntry>> {
    let capacity = usize::try_from(expected_entries).map_err(|_| arithmetic())?;
    let mut entries = Vec::with_capacity(capacity);
    let mut position = 0usize;
    while position < payload.len() {
        budget.check_cancel(GitTreePhase::Materialize)?;
        let ordinal = u32::try_from(entries.len()).map_err(|_| arithmetic())?;
        let parsed = parse_entry(payload, position, format, limits, ordinal)?;
        entries.push(GitTreeEntry {
            mode: parsed.mode,
            name: parsed.name.to_vec().into_boxed_slice(),
            object_id: materialize_object_id(format, parsed.object_id, ordinal)?,
        });
        position = parsed.next;
    }
    if entries.len() != capacity {
        return Err(git_tree_error(GitTreeErrorCode::InvariantViolation, None));
    }
    Ok(entries)
}

fn materialize_object_id(
    format: GitObjectFormat,
    bytes: &[u8],
    ordinal: u32,
) -> GitTreeResult<GitObjectId> {
    match format {
        GitObjectFormat::Sha1 => {
            let value: [u8; 20] = bytes
                .try_into()
                .map_err(|_| git_tree_error(GitTreeErrorCode::ObjectIdTruncated, Some(ordinal)))?;
            GitObjectId::from_sha1(value)
                .map_err(|_| git_tree_error(GitTreeErrorCode::ObjectIdZero, Some(ordinal)))
        }
        GitObjectFormat::Sha256 => {
            let value: [u8; 32] = bytes
                .try_into()
                .map_err(|_| git_tree_error(GitTreeErrorCode::ObjectIdTruncated, Some(ordinal)))?;
            GitObjectId::from_sha256(value)
                .map_err(|_| git_tree_error(GitTreeErrorCode::ObjectIdZero, Some(ordinal)))
        }
    }
}

fn request_commitment(frame: GitTreeFrame<'_>, limits: GitTreeLimits) -> GitTreeResult<[u8; 32]> {
    let mut hash = Sha256Writer::new();
    hash.update(REQUEST_COMMITMENT_DOMAIN);
    hash.update(GIT_TREE_ALGORITHM_VERSION.as_bytes());
    hash.update(&[frame.object_format.tag()]);
    hash.update(
        &u64::try_from(frame.bytes.len())
            .map_err(|_| arithmetic())?
            .to_be_bytes(),
    );
    hash.update(&frame.staged_sha256);
    for value in [
        limits.frame_bytes_maximum,
        limits.entries_maximum,
        limits.name_bytes_maximum,
        limits.total_name_bytes_maximum,
        limits.work_units_maximum,
        limits.retained_bytes_maximum,
    ] {
        hash.update(&value.to_be_bytes());
    }
    Ok(hash.finish())
}

fn projection_commitment(
    format: GitObjectFormat,
    request_commitment: [u8; 32],
    entries: &[GitTreeEntry],
    ledger: GitTreeLedger,
) -> GitTreeResult<[u8; 32]> {
    let mut hash = Sha256Writer::new();
    hash.update(PROJECTION_COMMITMENT_DOMAIN);
    hash.update(&request_commitment);
    hash.update(&[format.tag()]);
    for value in [
        ledger.frame_bytes,
        ledger.payload_bytes,
        ledger.entries,
        ledger.name_bytes,
        ledger.work_units,
        ledger.cancellation_checks,
        ledger.admitted_retained_bytes,
    ] {
        hash.update(&value.to_be_bytes());
    }
    for entry in entries {
        hash.update(&[entry.mode.tag()]);
        hash.update(
            &u64::try_from(entry.name.len())
                .map_err(|_| arithmetic())?
                .to_be_bytes(),
        );
        hash.update(&entry.name);
        let (tag, bytes) = entry.object_id.tagged_bytes();
        hash.update(&[tag]);
        hash.update(bytes);
    }
    Ok(hash.finish())
}

fn checked_add(left: u64, right: u64) -> GitTreeResult<u64> {
    left.checked_add(right).ok_or_else(arithmetic)
}

fn checked_mul(left: u64, right: u64) -> GitTreeResult<u64> {
    left.checked_mul(right).ok_or_else(arithmetic)
}

fn git_tree_error(code: GitTreeErrorCode, entry_ordinal: Option<u32>) -> GitTreeError {
    GitTreeError {
        code,
        entry_ordinal,
    }
}

fn arithmetic() -> GitTreeError {
    git_tree_error(GitTreeErrorCode::Arithmetic, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"100644 alpha\0");
        payload.extend_from_slice(&[1; 20]);
        payload.extend_from_slice(b"100644 omega\0");
        payload.extend_from_slice(&[2; 20]);
        let mut frame = format!("tree {}\0", payload.len()).into_bytes();
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn cancellation_at_every_phase_returns_no_projection() {
        let bytes = frame();
        let input = GitTreeFrame {
            bytes: &bytes,
            staged_sha256: ogvcs_object_model::sha256(&bytes),
            object_format: GitObjectFormat::Sha1,
        };
        for (phase, occurrences) in [
            (GitTreePhase::Start, 1),
            (GitTreePhase::Digest, 1),
            (GitTreePhase::Header, 1),
            (GitTreePhase::Prescan, 3),
            (GitTreePhase::Order, 3),
            (GitTreePhase::Materialize, 3),
            (GitTreePhase::Finalize, 2),
        ] {
            for target in 1..=occurrences {
                let mut seen = 0;
                let error =
                    decode_git_tree_with_probe(input, GitTreeLimits::default(), &mut |observed| {
                        if observed != phase {
                            return false;
                        }
                        seen += 1;
                        seen == target
                    })
                    .expect_err("phase cancellation must fail closed");
                assert_eq!(
                    error.code(),
                    GitTreeErrorCode::Cancelled,
                    "{phase:?} occurrence {target}"
                );
            }
        }

        let large_bytes = vec![b'x'; 4_097];
        let large_input = GitTreeFrame {
            bytes: &large_bytes,
            staged_sha256: ogvcs_object_model::sha256(&large_bytes),
            object_format: GitObjectFormat::Sha1,
        };
        let mut digest_checks = 0;
        let error =
            decode_git_tree_with_probe(large_input, GitTreeLimits::default(), &mut |observed| {
                if observed != GitTreePhase::Digest {
                    return false;
                }
                digest_checks += 1;
                digest_checks == 2
            })
            .expect_err("later digest cancellation must fail closed");
        assert_eq!(error.code(), GitTreeErrorCode::Cancelled);

        let mut candidate_payload = Vec::new();
        candidate_payload.extend_from_slice(b"100644 foo\0");
        candidate_payload.extend_from_slice(&[1; 20]);
        candidate_payload.extend_from_slice(b"100644 foo.bar.baz\0");
        candidate_payload.extend_from_slice(&[2; 20]);
        candidate_payload.extend_from_slice(b"40000 foo.bar\0");
        candidate_payload.extend_from_slice(&[3; 20]);
        let mut candidate_bytes = format!("tree {}\0", candidate_payload.len()).into_bytes();
        candidate_bytes.extend_from_slice(&candidate_payload);
        let candidate_input = GitTreeFrame {
            bytes: &candidate_bytes,
            staged_sha256: ogvcs_object_model::sha256(&candidate_bytes),
            object_format: GitObjectFormat::Sha1,
        };
        let mut order_checks = 0;
        let error = decode_git_tree_with_probe(
            candidate_input,
            GitTreeLimits::default(),
            &mut |observed| {
                if observed != GitTreePhase::Order {
                    return false;
                }
                order_checks += 1;
                order_checks == 5
            },
        )
        .expect_err("candidate-pop cancellation must fail closed");
        assert_eq!(error.code(), GitTreeErrorCode::Cancelled);
    }
}
