use std::{collections::BTreeMap, fmt, mem::size_of, str};

use sha2::{Digest, Sha256};

use crate::OperationControl;

pub const TEXT_MERGE_ALGORITHM_VERSION: &str = "ogvcs.text-merge/line-diff3@1";
pub const TEXT_MERGE_INPUT_BYTES_MAXIMUM: u64 = 1_048_576;
pub const TEXT_MERGE_TOTAL_INPUT_BYTES_MAXIMUM: u64 = 3_145_728;
pub const TEXT_MERGE_LINES_PER_INPUT_MAXIMUM: u64 = 4_096;
pub const TEXT_MERGE_LINE_BYTES_MAXIMUM: u64 = 65_536;
pub const TEXT_MERGE_LCS_CELLS_MAXIMUM: u64 = 263_169;
pub const TEXT_MERGE_WORK_UNITS_MAXIMUM: u64 = 24_000_000;
pub const TEXT_MERGE_OUTPUT_BYTES_MAXIMUM: u64 = 3_145_728;
pub const TEXT_MERGE_CONFLICTS_MAXIMUM: u64 = 128;
pub const TEXT_MERGE_CHARGED_MEMORY_BYTES_MAXIMUM: u64 = 12_582_912;

const REQUEST_COMMITMENT_DOMAIN: &[u8] = b"ogvcs-text-merge-request-v1\0";
const OUTPUT_COMMITMENT_DOMAIN: &[u8] = b"ogvcs-text-merge-clean-v1\0";
const CONFLICT_COMMITMENT_DOMAIN: &[u8] = b"ogvcs-text-merge-conflict-v1\0";
const TOKEN_CHARGE: u64 = 256;
const FIXED_STATE_CHARGE: u64 = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeAlgorithm {
    LineDiff3V1,
}

impl TextMergeAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LineDiff3V1 => TEXT_MERGE_ALGORITHM_VERSION,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::LineDiff3V1 => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeLineEndings {
    ExactLf,
}

impl TextMergeLineEndings {
    const fn tag(self) -> u8 {
        match self {
            Self::ExactLf => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeWhitespace {
    Exact,
}

impl TextMergeWhitespace {
    const fn tag(self) -> u8 {
        match self {
            Self::Exact => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMergeOptions {
    pub line_endings: TextMergeLineEndings,
    pub whitespace: TextMergeWhitespace,
}

impl Default for TextMergeOptions {
    fn default() -> Self {
        Self {
            line_endings: TextMergeLineEndings::ExactLf,
            whitespace: TextMergeWhitespace::Exact,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeSide {
    Base,
    Ours,
    Theirs,
}

impl TextMergeSide {
    const fn tag(self) -> u8 {
        match self {
            Self::Base => 1,
            Self::Ours => 2,
            Self::Theirs => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMergeInput<'a> {
    pub bytes: &'a [u8],
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMergeRequest<'a> {
    pub algorithm: TextMergeAlgorithm,
    pub options: TextMergeOptions,
    pub base: TextMergeInput<'a>,
    pub ours: TextMergeInput<'a>,
    pub theirs: TextMergeInput<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeInputErrorKind {
    DigestMismatch,
    InvalidUtf8,
    BinaryControl,
    CarriageReturnForbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeLimitKind {
    InputBytes,
    TotalInputBytes,
    Lines,
    LineBytes,
    LcsCells,
    WorkUnits,
    OutputBytes,
    Conflicts,
    ChargedMemory,
    Arithmetic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeErrorKind {
    InvalidInput(TextMergeInputErrorKind),
    Limit(TextMergeLimitKind),
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMergeError {
    pub kind: TextMergeErrorKind,
    pub side: Option<TextMergeSide>,
}

impl fmt::Display for TextMergeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}", self.kind)
    }
}

impl std::error::Error for TextMergeError {}

pub type TextMergeResult<T> = std::result::Result<T, TextMergeError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TextMergeLedger {
    pub input_bytes: u64,
    pub input_lines: u64,
    pub lcs_cells: u64,
    pub work_units: u64,
    pub cancellation_checks: u64,
    pub admitted_peak_memory_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextMergeFragmentCommitment {
    line_count: u32,
    byte_count: u64,
    digest: [u8; 32],
}

impl TextMergeFragmentCommitment {
    pub const fn line_count(self) -> u32 {
        self.line_count
    }

    pub const fn byte_count(self) -> u64 {
        self.byte_count
    }

    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextMergeConflictKind {
    ConcurrentInsertion,
    DeleteModify,
    OverlappingEdits,
}

impl TextMergeConflictKind {
    const fn tag(self) -> u8 {
        match self {
            Self::ConcurrentInsertion => 1,
            Self::DeleteModify => 2,
            Self::OverlappingEdits => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextMergeConflictSpan {
    kind: TextMergeConflictKind,
    base_start_line: u32,
    base_end_line: u32,
    base: TextMergeFragmentCommitment,
    ours: TextMergeFragmentCommitment,
    theirs: TextMergeFragmentCommitment,
}

impl TextMergeConflictSpan {
    pub const fn kind(&self) -> TextMergeConflictKind {
        self.kind
    }

    pub const fn base_start_line(&self) -> u32 {
        self.base_start_line
    }

    pub const fn base_end_line(&self) -> u32 {
        self.base_end_line
    }

    pub const fn base(&self) -> TextMergeFragmentCommitment {
        self.base
    }

    pub const fn ours(&self) -> TextMergeFragmentCommitment {
        self.ours
    }

    pub const fn theirs(&self) -> TextMergeFragmentCommitment {
        self.theirs
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextMergeClean {
    algorithm: TextMergeAlgorithm,
    options: TextMergeOptions,
    request_commitment: [u8; 32],
    output: Box<[u8]>,
    output_digest: [u8; 32],
    output_commitment: [u8; 32],
    ledger: TextMergeLedger,
}

impl TextMergeClean {
    pub const fn algorithm(&self) -> TextMergeAlgorithm {
        self.algorithm
    }

    pub const fn options(&self) -> TextMergeOptions {
        self.options
    }

    pub const fn request_commitment(&self) -> [u8; 32] {
        self.request_commitment
    }

    pub fn output(&self) -> &[u8] {
        &self.output
    }

    pub const fn output_digest(&self) -> [u8; 32] {
        self.output_digest
    }

    pub const fn output_commitment(&self) -> [u8; 32] {
        self.output_commitment
    }

    pub const fn ledger(&self) -> TextMergeLedger {
        self.ledger
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextMergeConflicted {
    algorithm: TextMergeAlgorithm,
    options: TextMergeOptions,
    request_commitment: [u8; 32],
    conflicts: Box<[TextMergeConflictSpan]>,
    conflict_commitment: [u8; 32],
    ledger: TextMergeLedger,
}

impl TextMergeConflicted {
    pub const fn algorithm(&self) -> TextMergeAlgorithm {
        self.algorithm
    }

    pub const fn options(&self) -> TextMergeOptions {
        self.options
    }

    pub const fn request_commitment(&self) -> [u8; 32] {
        self.request_commitment
    }

    pub fn conflicts(&self) -> &[TextMergeConflictSpan] {
        &self.conflicts
    }

    pub const fn conflict_commitment(&self) -> [u8; 32] {
        self.conflict_commitment
    }

    pub const fn ledger(&self) -> TextMergeLedger {
        self.ledger
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TextMergeOutcome {
    Clean(TextMergeClean),
    Conflict(TextMergeConflicted),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MergePhase {
    Start,
    InputValidation,
    LineIndex,
    Tokenization,
    LcsOurs,
    LcsTheirs,
    Merge,
    Finalize,
}

struct Budget<'a> {
    probe: &'a mut dyn FnMut(MergePhase) -> bool,
    work_units: u64,
    cancellation_checks: u64,
    admitted_peak_memory_bytes: u64,
}

impl Budget<'_> {
    fn check_cancel(&mut self, phase: MergePhase) -> TextMergeResult<()> {
        self.cancellation_checks = checked_add(self.cancellation_checks, 1)?;
        if (self.probe)(phase) {
            Err(error(TextMergeErrorKind::Cancelled, None))
        } else {
            Ok(())
        }
    }

    fn work(&mut self, amount: u64) -> TextMergeResult<()> {
        let next = checked_add(self.work_units, amount)?;
        if next > TEXT_MERGE_WORK_UNITS_MAXIMUM {
            return Err(limit(TextMergeLimitKind::WorkUnits, None));
        }
        self.work_units = next;
        Ok(())
    }

    fn ensure_work(&self, amount: u64) -> TextMergeResult<()> {
        if self
            .work_units
            .checked_add(amount)
            .is_none_or(|value| value > TEXT_MERGE_WORK_UNITS_MAXIMUM)
        {
            Err(limit(TextMergeLimitKind::WorkUnits, None))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct InputSummary {
    bytes: u64,
    lines: u64,
}

#[derive(Clone, Copy, Debug)]
struct Line {
    start: u32,
    end: u32,
    token: u32,
}

#[derive(Clone, Copy, Debug)]
struct TokenRepresentative {
    side: TextMergeSide,
    start: u32,
    end: u32,
    token: u32,
}

#[derive(Clone, Copy, Debug)]
struct Edit {
    base_start: usize,
    base_end: usize,
    side_start: usize,
    side_end: usize,
}

impl Edit {
    const fn insertion(self) -> bool {
        self.base_start == self.base_end
    }
}

#[derive(Clone, Copy, Debug)]
struct InteractionGroup {
    base_start: usize,
    base_end: usize,
    ours_end: usize,
    theirs_end: usize,
}

/// Runs the private built-in line-oriented three-way text merge. Inputs are
/// borrowed and no result is exposed until the final cancellation fence and
/// commitment have completed. Conflict results contain only spans, sizes, and
/// digests; this function never manufactures conflict-marker file bytes.
pub fn merge_text_three_way(
    request: TextMergeRequest<'_>,
    control: &OperationControl,
) -> TextMergeResult<TextMergeOutcome> {
    merge_text_with_probe(request, &mut |_| control.is_cancelled())
}

fn merge_text_with_probe(
    request: TextMergeRequest<'_>,
    probe: &mut dyn FnMut(MergePhase) -> bool,
) -> TextMergeResult<TextMergeOutcome> {
    let mut budget = Budget {
        probe,
        work_units: 0,
        cancellation_checks: 0,
        admitted_peak_memory_bytes: 0,
    };
    budget.check_cancel(MergePhase::Start)?;

    let base = inspect_input(TextMergeSide::Base, request.base, &mut budget)?;
    let ours = inspect_input(TextMergeSide::Ours, request.ours, &mut budget)?;
    let theirs = inspect_input(TextMergeSide::Theirs, request.theirs, &mut budget)?;
    let total_bytes = checked_add(checked_add(base.bytes, ours.bytes)?, theirs.bytes)?;
    if total_bytes > TEXT_MERGE_TOTAL_INPUT_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::TotalInputBytes, None));
    }
    let total_lines = checked_add(checked_add(base.lines, ours.lines)?, theirs.lines)?;
    let request_commitment = request_commitment(request)?;

    if equal_bytes(request.ours.bytes, request.theirs.bytes, &mut budget)? {
        return clean_shortcut(
            request,
            request.ours.bytes,
            request_commitment,
            total_bytes,
            total_lines,
            &mut budget,
        );
    }
    if equal_bytes(request.base.bytes, request.ours.bytes, &mut budget)? {
        return clean_shortcut(
            request,
            request.theirs.bytes,
            request_commitment,
            total_bytes,
            total_lines,
            &mut budget,
        );
    }
    if equal_bytes(request.base.bytes, request.theirs.bytes, &mut budget)? {
        return clean_shortcut(
            request,
            request.ours.bytes,
            request_commitment,
            total_bytes,
            total_lines,
            &mut budget,
        );
    }

    let ours_cells = lcs_cells(base.lines, ours.lines, TextMergeSide::Ours)?;
    let theirs_cells = lcs_cells(base.lines, theirs.lines, TextMergeSide::Theirs)?;
    let lcs_cells = checked_add(ours_cells, theirs_cells)?;
    preflight_nontrivial(
        base,
        ours,
        theirs,
        total_bytes,
        ours_cells,
        theirs_cells,
        &mut budget,
    )?;

    let mut base_lines = build_lines(request.base.bytes, base.lines, &mut budget)?;
    let mut ours_lines = build_lines(request.ours.bytes, ours.lines, &mut budget)?;
    let mut theirs_lines = build_lines(request.theirs.bytes, theirs.lines, &mut budget)?;
    assign_line_tokens(
        request,
        &mut base_lines,
        &mut ours_lines,
        &mut theirs_lines,
        &mut budget,
    )?;

    let ours_edits = build_edit_script(&base_lines, &ours_lines, MergePhase::LcsOurs, &mut budget)?;
    let theirs_edits = build_edit_script(
        &base_lines,
        &theirs_lines,
        MergePhase::LcsTheirs,
        &mut budget,
    )?;

    let (output, conflicts) = combine_edits(
        request,
        &base_lines,
        &ours_lines,
        &theirs_lines,
        &ours_edits,
        &theirs_edits,
        total_bytes,
        &mut budget,
    )?;
    budget.check_cancel(MergePhase::Finalize)?;
    let ledger = TextMergeLedger {
        input_bytes: total_bytes,
        input_lines: total_lines,
        lcs_cells,
        work_units: budget.work_units,
        cancellation_checks: budget.cancellation_checks,
        admitted_peak_memory_bytes: budget.admitted_peak_memory_bytes,
    };

    if conflicts.is_empty() {
        clean_outcome(request, output, request_commitment, ledger, &mut budget)
    } else {
        drop(output);
        let conflict_commitment = conflict_commitment(request_commitment, &conflicts, &mut budget)?;
        budget.check_cancel(MergePhase::Finalize)?;
        let ledger = TextMergeLedger {
            work_units: budget.work_units,
            cancellation_checks: budget.cancellation_checks,
            ..ledger
        };
        Ok(TextMergeOutcome::Conflict(TextMergeConflicted {
            algorithm: request.algorithm,
            options: request.options,
            request_commitment,
            conflicts: conflicts.into_boxed_slice(),
            conflict_commitment,
            ledger,
        }))
    }
}

fn inspect_input(
    side: TextMergeSide,
    input: TextMergeInput<'_>,
    budget: &mut Budget<'_>,
) -> TextMergeResult<InputSummary> {
    budget.check_cancel(MergePhase::InputValidation)?;
    let bytes = u64::try_from(input.bytes.len()).map_err(|_| arithmetic())?;
    if bytes > TEXT_MERGE_INPUT_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::InputBytes, Some(side)));
    }
    let actual = digest_bytes(input.bytes, MergePhase::InputValidation, budget)?;
    if actual != input.digest {
        return Err(error(
            TextMergeErrorKind::InvalidInput(TextMergeInputErrorKind::DigestMismatch),
            Some(side),
        ));
    }
    budget.work(bytes)?;
    budget.check_cancel(MergePhase::InputValidation)?;
    let text = str::from_utf8(input.bytes).map_err(|_| {
        error(
            TextMergeErrorKind::InvalidInput(TextMergeInputErrorKind::InvalidUtf8),
            Some(side),
        )
    })?;
    budget.check_cancel(MergePhase::InputValidation)?;

    let mut lines = 0u64;
    let mut line_bytes = 0u64;
    for (index, character) in text.chars().enumerate() {
        if index % 4_096 == 0 {
            budget.check_cancel(MergePhase::InputValidation)?;
        }
        if character == '\r' {
            return Err(error(
                TextMergeErrorKind::InvalidInput(TextMergeInputErrorKind::CarriageReturnForbidden),
                Some(side),
            ));
        }
        if character.is_control() && !matches!(character, '\n' | '\t') {
            return Err(error(
                TextMergeErrorKind::InvalidInput(TextMergeInputErrorKind::BinaryControl),
                Some(side),
            ));
        }
        line_bytes = checked_add(
            line_bytes,
            u64::try_from(character.len_utf8()).map_err(|_| arithmetic())?,
        )?;
        if line_bytes > TEXT_MERGE_LINE_BYTES_MAXIMUM {
            return Err(limit(TextMergeLimitKind::LineBytes, Some(side)));
        }
        if character == '\n' {
            lines = checked_add(lines, 1)?;
            if lines > TEXT_MERGE_LINES_PER_INPUT_MAXIMUM {
                return Err(limit(TextMergeLimitKind::Lines, Some(side)));
            }
            line_bytes = 0;
        }
    }
    if !input.bytes.is_empty() && input.bytes.last() != Some(&b'\n') {
        lines = checked_add(lines, 1)?;
        if lines > TEXT_MERGE_LINES_PER_INPUT_MAXIMUM {
            return Err(limit(TextMergeLimitKind::Lines, Some(side)));
        }
    }
    budget.work(bytes)?;
    Ok(InputSummary { bytes, lines })
}

fn preflight_nontrivial(
    base: InputSummary,
    ours: InputSummary,
    theirs: InputSummary,
    total_bytes: u64,
    ours_cells: u64,
    theirs_cells: u64,
    budget: &mut Budget<'_>,
) -> TextMergeResult<()> {
    let total_lines = checked_add(checked_add(base.lines, ours.lines)?, theirs.lines)?;
    let line_charge = checked_mul(total_lines, usize_charge::<Line>()?)?;
    let token_charge = checked_mul(total_lines, TOKEN_CHARGE)?;
    let ours_script = checked_mul(
        checked_add(base.lines, ours.lines)?,
        usize_charge::<Edit>()?,
    )?;
    let theirs_script = checked_mul(
        checked_add(base.lines, theirs.lines)?,
        usize_charge::<Edit>()?,
    )?;
    let matrix_charge = checked_mul(ours_cells.max(theirs_cells), 4)?;
    let conflict_charge = checked_mul(
        TEXT_MERGE_CONFLICTS_MAXIMUM,
        usize_charge::<TextMergeConflictSpan>()?,
    )?;
    let tokenize_peak = checked_add(checked_add(FIXED_STATE_CHARGE, line_charge)?, token_charge)?;
    let lcs_peak = checked_add(
        checked_add(checked_add(FIXED_STATE_CHARGE, line_charge)?, ours_script)?,
        checked_add(theirs_script, matrix_charge)?,
    )?;
    let merge_peak = checked_add(
        checked_add(
            checked_add(
                checked_add(checked_add(FIXED_STATE_CHARGE, line_charge)?, ours_script)?,
                theirs_script,
            )?,
            conflict_charge,
        )?,
        checked_mul(total_bytes, 3)?,
    )?;
    let peak = tokenize_peak.max(lcs_peak).max(merge_peak);
    if peak > TEXT_MERGE_CHARGED_MEMORY_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::ChargedMemory, None));
    }
    budget.admitted_peak_memory_bytes = peak;

    let fill_and_backtrack = checked_add(
        checked_add(ours_cells, theirs_cells)?,
        checked_add(
            checked_add(base.lines, ours.lines)?,
            checked_add(base.lines, theirs.lines)?,
        )?,
    )?;
    let remaining_byte_work = checked_mul(total_bytes, 3)?;
    budget.ensure_work(checked_add(fill_and_backtrack, remaining_byte_work)?)?;
    Ok(())
}

fn build_lines(bytes: &[u8], count: u64, budget: &mut Budget<'_>) -> TextMergeResult<Vec<Line>> {
    budget.check_cancel(MergePhase::LineIndex)?;
    let capacity = usize::try_from(count).map_err(|_| arithmetic())?;
    let mut lines = Vec::with_capacity(capacity);
    let mut start = 0usize;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index % 4_096 == 0 {
            budget.check_cancel(MergePhase::LineIndex)?;
        }
        if byte == b'\n' {
            lines.push(Line {
                start: u32::try_from(start).map_err(|_| arithmetic())?,
                end: u32::try_from(index + 1).map_err(|_| arithmetic())?,
                token: 0,
            });
            start = index + 1;
        }
    }
    if start < bytes.len() {
        lines.push(Line {
            start: u32::try_from(start).map_err(|_| arithmetic())?,
            end: u32::try_from(bytes.len()).map_err(|_| arithmetic())?,
            token: 0,
        });
    }
    budget.work(u64::try_from(bytes.len()).map_err(|_| arithmetic())?)?;
    if lines.len() != capacity {
        return Err(arithmetic());
    }
    Ok(lines)
}

fn assign_line_tokens(
    request: TextMergeRequest<'_>,
    base: &mut [Line],
    ours: &mut [Line],
    theirs: &mut [Line],
    budget: &mut Budget<'_>,
) -> TextMergeResult<()> {
    let mut representatives = BTreeMap::<([u8; 32], u32), Vec<TokenRepresentative>>::new();
    let mut next_token = 1u32;
    assign_side_tokens(
        TextMergeSide::Base,
        request,
        base,
        &mut representatives,
        &mut next_token,
        budget,
    )?;
    assign_side_tokens(
        TextMergeSide::Ours,
        request,
        ours,
        &mut representatives,
        &mut next_token,
        budget,
    )?;
    assign_side_tokens(
        TextMergeSide::Theirs,
        request,
        theirs,
        &mut representatives,
        &mut next_token,
        budget,
    )
}

fn assign_side_tokens(
    side: TextMergeSide,
    request: TextMergeRequest<'_>,
    lines: &mut [Line],
    representatives: &mut BTreeMap<([u8; 32], u32), Vec<TokenRepresentative>>,
    next_token: &mut u32,
    budget: &mut Budget<'_>,
) -> TextMergeResult<()> {
    for line in lines {
        budget.check_cancel(MergePhase::Tokenization)?;
        let bytes = side_bytes(request, side);
        let value = &bytes[usize::try_from(line.start).map_err(|_| arithmetic())?
            ..usize::try_from(line.end).map_err(|_| arithmetic())?];
        let digest = digest_bytes(value, MergePhase::Tokenization, budget)?;
        let length = line.end.checked_sub(line.start).ok_or_else(arithmetic)?;
        budget.work(16)?;
        let bucket = representatives.entry((digest, length)).or_default();
        let mut token = None;
        for representative in bucket.iter().copied() {
            let existing = representative_bytes(request, representative)?;
            budget.work(u64::from(length))?;
            if value == existing {
                token = Some(representative.token);
                break;
            }
        }
        let token = match token {
            Some(token) => token,
            None => {
                let token = *next_token;
                *next_token = next_token.checked_add(1).ok_or_else(arithmetic)?;
                bucket.push(TokenRepresentative {
                    side,
                    start: line.start,
                    end: line.end,
                    token,
                });
                token
            }
        };
        line.token = token;
    }
    Ok(())
}

fn representative_bytes(
    request: TextMergeRequest<'_>,
    representative: TokenRepresentative,
) -> TextMergeResult<&[u8]> {
    let bytes = side_bytes(request, representative.side);
    let start = usize::try_from(representative.start).map_err(|_| arithmetic())?;
    let end = usize::try_from(representative.end).map_err(|_| arithmetic())?;
    bytes.get(start..end).ok_or_else(arithmetic)
}

fn build_edit_script(
    base: &[Line],
    side: &[Line],
    phase: MergePhase,
    budget: &mut Budget<'_>,
) -> TextMergeResult<Vec<Edit>> {
    budget.check_cancel(phase)?;
    let width = side.len().checked_add(1).ok_or_else(arithmetic)?;
    let height = base.len().checked_add(1).ok_or_else(arithmetic)?;
    let cells = width.checked_mul(height).ok_or_else(arithmetic)?;
    if u64::try_from(cells).map_err(|_| arithmetic())? > TEXT_MERGE_LCS_CELLS_MAXIMUM {
        return Err(limit(TextMergeLimitKind::LcsCells, None));
    }
    let mut table = vec![0u32; cells];
    for base_index in (0..base.len()).rev() {
        budget.check_cancel(phase)?;
        budget.work(u64::try_from(side.len()).map_err(|_| arithmetic())?)?;
        for side_index in (0..side.len()).rev() {
            let index = base_index * width + side_index;
            table[index] = if base[base_index].token == side[side_index].token {
                table[(base_index + 1) * width + side_index + 1]
                    .checked_add(1)
                    .ok_or_else(arithmetic)?
            } else {
                table[(base_index + 1) * width + side_index]
                    .max(table[base_index * width + side_index + 1])
            };
        }
    }

    let script_capacity = base.len().checked_add(side.len()).ok_or_else(arithmetic)?;
    let mut edits = Vec::with_capacity(script_capacity);
    let mut base_index = 0usize;
    let mut side_index = 0usize;
    let mut pending = None;
    while base_index < base.len() || side_index < side.len() {
        if (base_index + side_index) % 256 == 0 {
            budget.check_cancel(phase)?;
        }
        budget.work(1)?;
        if base_index < base.len()
            && side_index < side.len()
            && base[base_index].token == side[side_index].token
        {
            flush_edit(&mut edits, &mut pending, base_index, side_index);
            base_index += 1;
            side_index += 1;
            continue;
        }
        pending.get_or_insert((base_index, side_index));
        let delete_base = side_index == side.len()
            || base_index < base.len()
                && table[(base_index + 1) * width + side_index]
                    >= table[base_index * width + side_index + 1];
        if delete_base {
            base_index += 1;
        } else {
            side_index += 1;
        }
    }
    flush_edit(&mut edits, &mut pending, base_index, side_index);
    drop(table);
    Ok(edits)
}

fn flush_edit(
    edits: &mut Vec<Edit>,
    pending: &mut Option<(usize, usize)>,
    base_end: usize,
    side_end: usize,
) {
    if let Some((base_start, side_start)) = pending.take() {
        let base_length = base_end - base_start;
        let side_length = side_end - side_start;
        if base_length > 0 && side_length > 0 && (base_length > 1 || side_length > 1) {
            let paired = base_length.min(side_length);
            for offset in 0..paired {
                edits.push(Edit {
                    base_start: base_start + offset,
                    base_end: base_start + offset + 1,
                    side_start: side_start + offset,
                    side_end: side_start + offset + 1,
                });
            }
            if base_length > paired {
                edits.push(Edit {
                    base_start: base_start + paired,
                    base_end,
                    side_start: side_start + paired,
                    side_end,
                });
            } else if side_length > paired {
                edits.push(Edit {
                    base_start: base_end,
                    base_end,
                    side_start: side_start + paired,
                    side_end,
                });
            }
        } else {
            edits.push(Edit {
                base_start,
                base_end,
                side_start,
                side_end,
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn combine_edits(
    request: TextMergeRequest<'_>,
    base_lines: &[Line],
    ours_lines: &[Line],
    theirs_lines: &[Line],
    ours_edits: &[Edit],
    theirs_edits: &[Edit],
    total_bytes: u64,
    budget: &mut Budget<'_>,
) -> TextMergeResult<(Vec<u8>, Vec<TextMergeConflictSpan>)> {
    budget.check_cancel(MergePhase::Merge)?;
    let output_capacity = usize::try_from(total_bytes).map_err(|_| arithmetic())?;
    if total_bytes > TEXT_MERGE_OUTPUT_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::OutputBytes, None));
    }
    let mut output = Vec::with_capacity(output_capacity);
    let mut conflicts = Vec::with_capacity(
        usize::try_from(TEXT_MERGE_CONFLICTS_MAXIMUM).map_err(|_| arithmetic())?,
    );
    let mut ours_index = 0usize;
    let mut theirs_index = 0usize;
    let mut base_position = 0usize;

    while ours_index < ours_edits.len() || theirs_index < theirs_edits.len() {
        budget.check_cancel(MergePhase::Merge)?;
        match (ours_edits.get(ours_index), theirs_edits.get(theirs_index)) {
            (Some(ours), Some(theirs)) if edits_interact(*ours, *theirs) => {
                let group =
                    collect_interaction_group(ours_edits, theirs_edits, ours_index, theirs_index);
                append_base(
                    &mut output,
                    request.base.bytes,
                    base_lines,
                    base_position,
                    group.base_start,
                    budget,
                )?;
                let ours_candidate = render_candidate(
                    request.base.bytes,
                    base_lines,
                    request.ours.bytes,
                    ours_lines,
                    &ours_edits[ours_index..group.ours_end],
                    group.base_start,
                    group.base_end,
                    budget,
                )?;
                let theirs_candidate = render_candidate(
                    request.base.bytes,
                    base_lines,
                    request.theirs.bytes,
                    theirs_lines,
                    &theirs_edits[theirs_index..group.theirs_end],
                    group.base_start,
                    group.base_end,
                    budget,
                )?;
                if ours_candidate == theirs_candidate {
                    append_bytes(&mut output, &ours_candidate, budget)?;
                } else {
                    if u64::try_from(conflicts.len()).map_err(|_| arithmetic())?
                        >= TEXT_MERGE_CONFLICTS_MAXIMUM
                    {
                        return Err(limit(TextMergeLimitKind::Conflicts, None));
                    }
                    let base_fragment = line_slice(
                        request.base.bytes,
                        base_lines,
                        group.base_start,
                        group.base_end,
                    )?;
                    conflicts.push(conflict_span(
                        group,
                        base_fragment,
                        &ours_candidate,
                        &theirs_candidate,
                        budget,
                    )?);
                }
                base_position = group.base_end;
                ours_index = group.ours_end;
                theirs_index = group.theirs_end;
            }
            (Some(ours), Some(theirs)) => {
                if edit_sort_key(*ours, TextMergeSide::Ours)
                    < edit_sort_key(*theirs, TextMergeSide::Theirs)
                {
                    apply_edit(
                        &mut output,
                        request.base.bytes,
                        base_lines,
                        request.ours.bytes,
                        ours_lines,
                        *ours,
                        &mut base_position,
                        budget,
                    )?;
                    ours_index += 1;
                } else {
                    apply_edit(
                        &mut output,
                        request.base.bytes,
                        base_lines,
                        request.theirs.bytes,
                        theirs_lines,
                        *theirs,
                        &mut base_position,
                        budget,
                    )?;
                    theirs_index += 1;
                }
            }
            (Some(ours), None) => {
                apply_edit(
                    &mut output,
                    request.base.bytes,
                    base_lines,
                    request.ours.bytes,
                    ours_lines,
                    *ours,
                    &mut base_position,
                    budget,
                )?;
                ours_index += 1;
            }
            (None, Some(theirs)) => {
                apply_edit(
                    &mut output,
                    request.base.bytes,
                    base_lines,
                    request.theirs.bytes,
                    theirs_lines,
                    *theirs,
                    &mut base_position,
                    budget,
                )?;
                theirs_index += 1;
            }
            (None, None) => break,
        }
    }
    append_base(
        &mut output,
        request.base.bytes,
        base_lines,
        base_position,
        base_lines.len(),
        budget,
    )?;
    Ok((output, conflicts))
}

fn edits_interact(left: Edit, right: Edit) -> bool {
    match (left.insertion(), right.insertion()) {
        (true, true) => left.base_start == right.base_start,
        (true, false) => right.base_start < left.base_start && left.base_start < right.base_end,
        (false, true) => left.base_start < right.base_start && right.base_start < left.base_end,
        (false, false) => left.base_start.max(right.base_start) < left.base_end.min(right.base_end),
    }
}

fn edit_interacts_region(edit: Edit, start: usize, end: usize) -> bool {
    if start == end {
        edit.insertion() && edit.base_start == start
    } else if edit.insertion() {
        start < edit.base_start && edit.base_start < end
    } else {
        edit.base_start.max(start) < edit.base_end.min(end)
    }
}

fn collect_interaction_group(
    ours: &[Edit],
    theirs: &[Edit],
    ours_start: usize,
    theirs_start: usize,
) -> InteractionGroup {
    let first_ours = ours[ours_start];
    let first_theirs = theirs[theirs_start];
    let mut group = InteractionGroup {
        base_start: first_ours.base_start.min(first_theirs.base_start),
        base_end: first_ours.base_end.max(first_theirs.base_end),
        ours_end: ours_start + 1,
        theirs_end: theirs_start + 1,
    };
    loop {
        let mut extended = false;
        if ours
            .get(group.ours_end)
            .is_some_and(|edit| edit_interacts_region(*edit, group.base_start, group.base_end))
        {
            let edit = ours[group.ours_end];
            group.base_start = group.base_start.min(edit.base_start);
            group.base_end = group.base_end.max(edit.base_end);
            group.ours_end += 1;
            extended = true;
        }
        if theirs
            .get(group.theirs_end)
            .is_some_and(|edit| edit_interacts_region(*edit, group.base_start, group.base_end))
        {
            let edit = theirs[group.theirs_end];
            group.base_start = group.base_start.min(edit.base_start);
            group.base_end = group.base_end.max(edit.base_end);
            group.theirs_end += 1;
            extended = true;
        }
        if !extended {
            return group;
        }
    }
}

fn edit_sort_key(edit: Edit, side: TextMergeSide) -> (usize, u8, u8) {
    (
        edit.base_start,
        if edit.insertion() { 0 } else { 1 },
        side.tag(),
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_edit(
    output: &mut Vec<u8>,
    base_bytes: &[u8],
    base_lines: &[Line],
    side_bytes: &[u8],
    side_lines: &[Line],
    edit: Edit,
    base_position: &mut usize,
    budget: &mut Budget<'_>,
) -> TextMergeResult<()> {
    if edit.base_start < *base_position {
        return Err(arithmetic());
    }
    append_base(
        output,
        base_bytes,
        base_lines,
        *base_position,
        edit.base_start,
        budget,
    )?;
    append_bytes(
        output,
        line_slice(side_bytes, side_lines, edit.side_start, edit.side_end)?,
        budget,
    )?;
    *base_position = edit.base_end;
    Ok(())
}

fn append_base(
    output: &mut Vec<u8>,
    bytes: &[u8],
    lines: &[Line],
    start: usize,
    end: usize,
    budget: &mut Budget<'_>,
) -> TextMergeResult<()> {
    append_bytes(output, line_slice(bytes, lines, start, end)?, budget)
}

fn append_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
    budget: &mut Budget<'_>,
) -> TextMergeResult<()> {
    budget.check_cancel(MergePhase::Merge)?;
    let next = output
        .len()
        .checked_add(bytes.len())
        .ok_or_else(arithmetic)?;
    if u64::try_from(next).map_err(|_| arithmetic())? > TEXT_MERGE_OUTPUT_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::OutputBytes, None));
    }
    budget.work(u64::try_from(bytes.len()).map_err(|_| arithmetic())?)?;
    output.extend_from_slice(bytes);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_candidate(
    base_bytes: &[u8],
    base_lines: &[Line],
    side_bytes: &[u8],
    side_lines: &[Line],
    edits: &[Edit],
    start: usize,
    end: usize,
    budget: &mut Budget<'_>,
) -> TextMergeResult<Vec<u8>> {
    let mut length = 0usize;
    let mut position = start;
    for edit in edits {
        if edit.base_start < position || edit.base_end > end {
            return Err(arithmetic());
        }
        let base_length = line_slice(base_bytes, base_lines, position, edit.base_start)?.len();
        let side_length = line_slice(side_bytes, side_lines, edit.side_start, edit.side_end)?.len();
        length = length
            .checked_add(base_length)
            .and_then(|value| value.checked_add(side_length))
            .ok_or_else(arithmetic)?;
        position = edit.base_end;
    }
    length = length
        .checked_add(line_slice(base_bytes, base_lines, position, end)?.len())
        .ok_or_else(arithmetic)?;
    if u64::try_from(length).map_err(|_| arithmetic())? > TEXT_MERGE_OUTPUT_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::OutputBytes, None));
    }
    budget.check_cancel(MergePhase::Merge)?;
    let mut candidate = Vec::with_capacity(length);
    position = start;
    for edit in edits {
        append_bytes(
            &mut candidate,
            line_slice(base_bytes, base_lines, position, edit.base_start)?,
            budget,
        )?;
        append_bytes(
            &mut candidate,
            line_slice(side_bytes, side_lines, edit.side_start, edit.side_end)?,
            budget,
        )?;
        position = edit.base_end;
    }
    append_bytes(
        &mut candidate,
        line_slice(base_bytes, base_lines, position, end)?,
        budget,
    )?;
    Ok(candidate)
}

fn line_slice<'a>(
    bytes: &'a [u8],
    lines: &[Line],
    start: usize,
    end: usize,
) -> TextMergeResult<&'a [u8]> {
    if start > end || end > lines.len() {
        return Err(arithmetic());
    }
    let start_byte = line_boundary(bytes, lines, start)?;
    let end_byte = line_boundary(bytes, lines, end)?;
    bytes.get(start_byte..end_byte).ok_or_else(arithmetic)
}

fn line_boundary(bytes: &[u8], lines: &[Line], boundary: usize) -> TextMergeResult<usize> {
    if boundary == lines.len() {
        Ok(bytes.len())
    } else {
        lines
            .get(boundary)
            .map(|line| usize::try_from(line.start).map_err(|_| arithmetic()))
            .ok_or_else(arithmetic)?
    }
}

fn conflict_span(
    group: InteractionGroup,
    base: &[u8],
    ours: &[u8],
    theirs: &[u8],
    budget: &mut Budget<'_>,
) -> TextMergeResult<TextMergeConflictSpan> {
    let kind = if group.base_start == group.base_end {
        TextMergeConflictKind::ConcurrentInsertion
    } else if ours.is_empty() != theirs.is_empty() {
        TextMergeConflictKind::DeleteModify
    } else {
        TextMergeConflictKind::OverlappingEdits
    };
    Ok(TextMergeConflictSpan {
        kind,
        base_start_line: u32::try_from(group.base_start).map_err(|_| arithmetic())?,
        base_end_line: u32::try_from(group.base_end).map_err(|_| arithmetic())?,
        base: fragment_commitment(base, budget)?,
        ours: fragment_commitment(ours, budget)?,
        theirs: fragment_commitment(theirs, budget)?,
    })
}

fn fragment_commitment(
    bytes: &[u8],
    budget: &mut Budget<'_>,
) -> TextMergeResult<TextMergeFragmentCommitment> {
    Ok(TextMergeFragmentCommitment {
        line_count: u32::try_from(line_count(bytes)).map_err(|_| arithmetic())?,
        byte_count: u64::try_from(bytes.len()).map_err(|_| arithmetic())?,
        digest: digest_bytes(bytes, MergePhase::Merge, budget)?,
    })
}

fn line_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
        + usize::from(!bytes.is_empty() && bytes.last() != Some(&b'\n'))
}

fn clean_shortcut(
    request: TextMergeRequest<'_>,
    bytes: &[u8],
    request_commitment: [u8; 32],
    total_bytes: u64,
    total_lines: u64,
    budget: &mut Budget<'_>,
) -> TextMergeResult<TextMergeOutcome> {
    let peak = checked_add(
        FIXED_STATE_CHARGE,
        u64::try_from(bytes.len()).map_err(|_| arithmetic())?,
    )?;
    if peak > TEXT_MERGE_CHARGED_MEMORY_BYTES_MAXIMUM {
        return Err(limit(TextMergeLimitKind::ChargedMemory, None));
    }
    budget.admitted_peak_memory_bytes = peak;
    budget.check_cancel(MergePhase::Finalize)?;
    budget.work(u64::try_from(bytes.len()).map_err(|_| arithmetic())?)?;
    let output = bytes.to_vec();
    let ledger = TextMergeLedger {
        input_bytes: total_bytes,
        input_lines: total_lines,
        lcs_cells: 0,
        work_units: budget.work_units,
        cancellation_checks: budget.cancellation_checks,
        admitted_peak_memory_bytes: peak,
    };
    clean_outcome(request, output, request_commitment, ledger, budget)
}

fn clean_outcome(
    request: TextMergeRequest<'_>,
    output: Vec<u8>,
    request_commitment: [u8; 32],
    ledger: TextMergeLedger,
    budget: &mut Budget<'_>,
) -> TextMergeResult<TextMergeOutcome> {
    let output_digest = digest_bytes(&output, MergePhase::Finalize, budget)?;
    let output_commitment = output_commitment(request_commitment, &output, output_digest)?;
    budget.check_cancel(MergePhase::Finalize)?;
    let ledger = TextMergeLedger {
        work_units: budget.work_units,
        cancellation_checks: budget.cancellation_checks,
        ..ledger
    };
    Ok(TextMergeOutcome::Clean(TextMergeClean {
        algorithm: request.algorithm,
        options: request.options,
        request_commitment,
        output: output.into_boxed_slice(),
        output_digest,
        output_commitment,
        ledger,
    }))
}

fn request_commitment(request: TextMergeRequest<'_>) -> TextMergeResult<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(REQUEST_COMMITMENT_DOMAIN);
    digest.update([request.algorithm.tag()]);
    digest.update([request.options.line_endings.tag()]);
    digest.update([request.options.whitespace.tag()]);
    for (side, input) in [
        (TextMergeSide::Base, request.base),
        (TextMergeSide::Ours, request.ours),
        (TextMergeSide::Theirs, request.theirs),
    ] {
        digest.update([side.tag()]);
        digest.update(
            u64::try_from(input.bytes.len())
                .map_err(|_| arithmetic())?
                .to_be_bytes(),
        );
        digest.update(input.digest);
    }
    Ok(digest.finalize().into())
}

fn output_commitment(
    request_commitment: [u8; 32],
    output: &[u8],
    output_digest: [u8; 32],
) -> TextMergeResult<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(OUTPUT_COMMITMENT_DOMAIN);
    digest.update(request_commitment);
    digest.update(
        u64::try_from(output.len())
            .map_err(|_| arithmetic())?
            .to_be_bytes(),
    );
    digest.update(output_digest);
    Ok(digest.finalize().into())
}

fn conflict_commitment(
    request_commitment: [u8; 32],
    conflicts: &[TextMergeConflictSpan],
    budget: &mut Budget<'_>,
) -> TextMergeResult<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(CONFLICT_COMMITMENT_DOMAIN);
    digest.update(request_commitment);
    digest.update(
        u64::try_from(conflicts.len())
            .map_err(|_| arithmetic())?
            .to_be_bytes(),
    );
    for conflict in conflicts {
        budget.check_cancel(MergePhase::Finalize)?;
        budget.work(128)?;
        digest.update([conflict.kind.tag()]);
        digest.update(conflict.base_start_line.to_be_bytes());
        digest.update(conflict.base_end_line.to_be_bytes());
        for fragment in [conflict.base, conflict.ours, conflict.theirs] {
            digest.update(fragment.line_count.to_be_bytes());
            digest.update(fragment.byte_count.to_be_bytes());
            digest.update(fragment.digest);
        }
    }
    Ok(digest.finalize().into())
}

fn digest_bytes(
    bytes: &[u8],
    phase: MergePhase,
    budget: &mut Budget<'_>,
) -> TextMergeResult<[u8; 32]> {
    budget.work(u64::try_from(bytes.len()).map_err(|_| arithmetic())?)?;
    let mut digest = Sha256::new();
    for chunk in bytes.chunks(4_096) {
        budget.check_cancel(phase)?;
        digest.update(chunk);
    }
    if bytes.is_empty() {
        budget.check_cancel(phase)?;
    }
    Ok(digest.finalize().into())
}

fn equal_bytes(left: &[u8], right: &[u8], budget: &mut Budget<'_>) -> TextMergeResult<bool> {
    budget.check_cancel(MergePhase::InputValidation)?;
    budget.work(u64::try_from(left.len().min(right.len())).map_err(|_| arithmetic())?)?;
    Ok(left == right)
}

fn lcs_cells(base_lines: u64, side_lines: u64, side: TextMergeSide) -> TextMergeResult<u64> {
    let cells = base_lines
        .checked_add(1)
        .and_then(|base| {
            side_lines
                .checked_add(1)
                .and_then(|side| base.checked_mul(side))
        })
        .ok_or_else(arithmetic)?;
    if cells > TEXT_MERGE_LCS_CELLS_MAXIMUM {
        Err(limit(TextMergeLimitKind::LcsCells, Some(side)))
    } else {
        Ok(cells)
    }
}

fn side_bytes(request: TextMergeRequest<'_>, side: TextMergeSide) -> &[u8] {
    match side {
        TextMergeSide::Base => request.base.bytes,
        TextMergeSide::Ours => request.ours.bytes,
        TextMergeSide::Theirs => request.theirs.bytes,
    }
}

fn checked_add(left: u64, right: u64) -> TextMergeResult<u64> {
    left.checked_add(right).ok_or_else(arithmetic)
}

fn checked_mul(left: u64, right: u64) -> TextMergeResult<u64> {
    left.checked_mul(right).ok_or_else(arithmetic)
}

fn usize_charge<T>() -> TextMergeResult<u64> {
    u64::try_from(size_of::<T>()).map_err(|_| arithmetic())
}

fn error(kind: TextMergeErrorKind, side: Option<TextMergeSide>) -> TextMergeError {
    TextMergeError { kind, side }
}

fn limit(kind: TextMergeLimitKind, side: Option<TextMergeSide>) -> TextMergeError {
    error(TextMergeErrorKind::Limit(kind), side)
}

fn arithmetic() -> TextMergeError {
    limit(TextMergeLimitKind::Arithmetic, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn request<'a>(base: &'a [u8], ours: &'a [u8], theirs: &'a [u8]) -> TextMergeRequest<'a> {
        TextMergeRequest {
            algorithm: TextMergeAlgorithm::LineDiff3V1,
            options: TextMergeOptions::default(),
            base: TextMergeInput {
                bytes: base,
                digest: digest(base),
            },
            ours: TextMergeInput {
                bytes: ours,
                digest: digest(ours),
            },
            theirs: TextMergeInput {
                bytes: theirs,
                digest: digest(theirs),
            },
        }
    }

    #[test]
    fn cancellation_at_validation_lcs_merge_and_finalize_never_returns_partial_output() {
        let request = request(b"a\nb\nc\nd\n", b"a\nours\nc\nd\n", b"a\nb\nc\ntheirs\n");
        for phase in [
            MergePhase::InputValidation,
            MergePhase::LineIndex,
            MergePhase::Tokenization,
            MergePhase::LcsOurs,
            MergePhase::LcsTheirs,
            MergePhase::Merge,
            MergePhase::Finalize,
        ] {
            let mut cancelled = false;
            let error = merge_text_with_probe(request, &mut |current| {
                if !cancelled && current == phase {
                    cancelled = true;
                    true
                } else {
                    false
                }
            })
            .unwrap_err();
            assert_eq!(error.kind, TextMergeErrorKind::Cancelled, "{phase:?}");
        }
    }
}
