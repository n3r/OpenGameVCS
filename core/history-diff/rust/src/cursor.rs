use std::{collections::BTreeSet, str::FromStr};

use ogvcs_object_model::{FileId, ObjectKind, ObjectRef, ProfileRef};
use ogvcs_path_contract::{CaseMode, PathProfile};
use sha2::{Digest, Sha256};

use crate::model::{
    ChangeFlags, CorruptKind, DiffRecord, DiffRequest, EntryView, Failure, FailureKind, Generation,
    HistoryRequest, LimitKind, Limits, MoveHint, PresenceChange, Result, WorkLedger,
};

const HISTORY_MAGIC: &[u8; 8] = b"OGHIST01";
const DIFF_MAGIC: &[u8; 8] = b"OGDIFF01";
const HISTORY_DOMAIN: &[u8] = b"OpenGameVCS private history cursor rc1\0";
const DIFF_DOMAIN: &[u8] = b"OpenGameVCS private snapshot diff cursor rc1\0";
const SEAL_BYTES: usize = 32;
const ENTRY_STRING_MAXIMUM: usize = 1_048_576;
const PROFILE_STRING_MAXIMUM: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoryFrame {
    pub snapshot: ObjectRef,
    pub root_tree: ObjectRef,
    pub depth: u32,
    pub next_parent: u8,
    pub parents: Vec<ObjectRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HistoryState {
    pub generation: Generation,
    pub request: HistoryRequest,
    pub limits: Limits,
    pub ledger: WorkLedger,
    pub frames: Vec<HistoryFrame>,
    pub black: BTreeSet<ObjectRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiffState {
    pub generation: Generation,
    pub request: DiffRequest,
    pub limits: Limits,
    pub ledger: WorkLedger,
    pub path_profile: String,
    pub position: u64,
    pub records: Vec<DiffRecord>,
}

pub(crate) fn encode_history(state: &HistoryState) -> Result<Vec<u8>> {
    let encoded_length = history_encoded_length(state)?;
    enforce_cursor_length(encoded_length, state.limits)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_length)
        .map_err(|_| Failure::new(FailureKind::Limit(LimitKind::ChargedMemory)))?;
    bytes.extend_from_slice(HISTORY_MAGIC);
    put_generation(&mut bytes, state.generation);
    put_history_request(&mut bytes, state.request);
    put_limits(&mut bytes, state.limits);
    put_ledger(&mut bytes, state.ledger);
    put_u32(&mut bytes, checked_u32(state.frames.len())?);
    for frame in &state.frames {
        put_ref(&mut bytes, frame.snapshot);
        put_ref(&mut bytes, frame.root_tree);
        put_u32(&mut bytes, frame.depth);
        put_u8(&mut bytes, frame.next_parent);
        put_u8(&mut bytes, checked_u8(frame.parents.len())?);
        for parent in &frame.parents {
            put_ref(&mut bytes, *parent);
        }
    }
    put_u32(&mut bytes, checked_u32(state.black.len())?);
    for reference in &state.black {
        put_ref(&mut bytes, *reference);
    }
    append_seal(&mut bytes, HISTORY_DOMAIN);
    enforce_cursor_size(&bytes, state.limits)?;
    Ok(bytes)
}

pub(crate) fn decode_history(bytes: &[u8], outer_maximum: u64) -> Result<HistoryState> {
    verify_seal(bytes, HISTORY_DOMAIN, outer_maximum)?;
    let mut reader = Reader::new(&bytes[..bytes.len() - SEAL_BYTES]);
    reader.magic(HISTORY_MAGIC)?;
    let generation = reader.generation()?;
    let request = reader.history_request()?;
    let limits = reader.limits()?;
    validate_embedded_limits(limits, bytes.len(), outer_maximum)?;
    let ledger = reader.ledger()?;
    let frame_count = reader.u32()? as u64;
    if frame_count == 0
        || frame_count > limits.max_history_snapshots
        || frame_count > u64::try_from(reader.remaining() / 74).unwrap_or(u64::MAX)
        || !valid_ledger(ledger, limits)
    {
        return corrupt_cursor();
    }
    let decoded_nodes = preflight_history_allocation(reader, frame_count, limits)?;
    preflight_decode_accounting(ledger, bytes.len(), decoded_nodes, limits)?;
    let mut frames = Vec::with_capacity(checked_usize(frame_count)?);
    let mut gray = BTreeSet::new();
    for _ in 0..frame_count {
        let snapshot = reader.reference()?;
        let root_tree = reader.reference()?;
        let depth = reader.u32()?;
        let next_parent = reader.u8()?;
        let parent_count = reader.u8()?;
        if snapshot.kind != ObjectKind::Snapshot
            || root_tree.kind != ObjectKind::Tree
            || parent_count > 8
            || next_parent > parent_count
            || !gray.insert(snapshot)
        {
            return corrupt_cursor();
        }
        let mut parents = Vec::with_capacity(usize::from(parent_count));
        let mut unique = BTreeSet::new();
        for _ in 0..parent_count {
            let parent = reader.reference()?;
            if parent.kind != ObjectKind::Snapshot || !unique.insert(parent) {
                return corrupt_cursor();
            }
            parents.push(parent);
        }
        frames.push(HistoryFrame {
            snapshot,
            root_tree,
            depth,
            next_parent,
            parents,
        });
    }
    if frames
        .first()
        .is_none_or(|frame| frame.snapshot != request.start_snapshot || frame.depth != 0)
    {
        return corrupt_cursor();
    }
    for pair in frames.windows(2) {
        let parent = &pair[0];
        let child = &pair[1];
        let selected = parent
            .next_parent
            .checked_sub(1)
            .and_then(|index| parent.parents.get(usize::from(index)));
        let expected_depth = parent.depth.checked_add(1);
        if selected != Some(&child.snapshot) || expected_depth != Some(child.depth) {
            return corrupt_cursor();
        }
    }
    let black_count = reader.u32()? as u64;
    if black_count > limits.max_history_snapshots
        || black_count > u64::try_from(reader.remaining() / 34).unwrap_or(u64::MAX)
        || black_count
            .checked_mul(96)
            .is_none_or(|bytes| bytes > limits.max_charged_memory_bytes)
    {
        return corrupt_cursor();
    }
    let mut black = BTreeSet::new();
    let mut previous = None;
    for _ in 0..black_count {
        let reference = reader.reference()?;
        if reference.kind != ObjectKind::Snapshot
            || previous.is_some_and(|value| value >= reference)
            || gray.contains(&reference)
            || !black.insert(reference)
        {
            return corrupt_cursor();
        }
        previous = Some(reference);
    }
    reader.finish()?;
    let discovered = u64::try_from(
        frames
            .len()
            .checked_add(black.len())
            .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?,
    )
    .unwrap_or(u64::MAX);
    if discovered > limits.max_history_snapshots
        || ledger.emitted_records != u64::try_from(black.len()).unwrap_or(u64::MAX)
        || ledger.metadata_objects < ledger.emitted_records
    {
        return corrupt_cursor();
    }
    let state = HistoryState {
        generation,
        request,
        limits,
        ledger,
        frames,
        black,
    };
    let modeled = crate::history_state_charge(&state)
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
    validate_retained_charge(modeled, ledger, bytes.len(), limits)?;
    Ok(state)
}

pub(crate) fn encode_diff(state: &DiffState) -> Result<Vec<u8>> {
    let encoded_length = diff_encoded_length(state)?;
    enforce_cursor_length(encoded_length, state.limits)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_length)
        .map_err(|_| Failure::new(FailureKind::Limit(LimitKind::ChargedMemory)))?;
    bytes.extend_from_slice(DIFF_MAGIC);
    put_generation(&mut bytes, state.generation);
    put_diff_request(&mut bytes, state.request);
    put_limits(&mut bytes, state.limits);
    put_ledger(&mut bytes, state.ledger);
    put_string(&mut bytes, &state.path_profile)?;
    put_u64(&mut bytes, state.position);
    put_u32(&mut bytes, checked_u32(state.records.len())?);
    for record in &state.records {
        put_diff_record(&mut bytes, record)?;
    }
    append_seal(&mut bytes, DIFF_DOMAIN);
    enforce_cursor_size(&bytes, state.limits)?;
    Ok(bytes)
}

pub(crate) fn decode_diff(bytes: &[u8], outer_maximum: u64) -> Result<DiffState> {
    verify_seal(bytes, DIFF_DOMAIN, outer_maximum)?;
    let mut reader = Reader::new(&bytes[..bytes.len() - SEAL_BYTES]);
    reader.magic(DIFF_MAGIC)?;
    let generation = reader.generation()?;
    let request = reader.diff_request()?;
    let limits = reader.limits()?;
    validate_embedded_limits(limits, bytes.len(), outer_maximum)?;
    let ledger = reader.ledger()?;
    let path_profile = reader.string(PROFILE_STRING_MAXIMUM)?;
    let position = reader.u64()?;
    let record_count = reader.u32()? as u64;
    if PathProfile::parse(&path_profile).is_err()
        || position == 0
        || record_count > limits.max_diff_records
        || position >= record_count
        || record_count > u64::try_from(reader.remaining() / 22).unwrap_or(u64::MAX)
        || !valid_ledger(ledger, limits)
    {
        return corrupt_cursor();
    }
    preflight_diff_allocation(reader, record_count, path_profile.len(), limits)?;
    preflight_decode_accounting(ledger, bytes.len(), record_count, limits)?;
    let mut records = Vec::with_capacity(checked_usize(record_count)?);
    let mut previous = None;
    for _ in 0..record_count {
        let record = reader.diff_record()?;
        let key = diff_sort_key(&record);
        if previous.as_ref().is_some_and(|value| value >= &key) {
            return corrupt_cursor();
        }
        previous = Some(key);
        records.push(record);
    }
    reader.finish()?;
    if ledger.emitted_records != position {
        return corrupt_cursor();
    }
    let state = DiffState {
        generation,
        request,
        limits,
        ledger,
        path_profile,
        position,
        records,
    };
    let modeled = crate::diff_state_charge(&state)
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
    validate_retained_charge(modeled, ledger, bytes.len(), limits)?;
    Ok(state)
}

fn diff_sort_key(record: &DiffRecord) -> [u8; 16] {
    *record.file_id.as_bytes()
}

fn put_diff_record(bytes: &mut Vec<u8>, record: &DiffRecord) -> Result<()> {
    bytes.extend_from_slice(record.file_id.as_bytes());
    put_optional_entry(bytes, record.before.as_ref())?;
    put_optional_entry(bytes, record.after.as_ref())?;
    put_u8(
        bytes,
        match record.presence {
            PresenceChange::Added => 1,
            PresenceChange::Deleted => 2,
            PresenceChange::Retained => 3,
        },
    );
    put_u16(bytes, record.changes.bits());
    put_u8(
        bytes,
        match record.move_hint {
            MoveHint::None => 0,
            MoveHint::Rename => 1,
            MoveHint::Move => 2,
        },
    );
    Ok(())
}

pub(crate) fn history_encoded_length(state: &HistoryState) -> Result<usize> {
    checked_u32(state.frames.len())?;
    checked_u32(state.black.len())?;
    let mut length = 8usize
        .checked_add(32)
        .and_then(|value| value.checked_add(3 * 34))
        .and_then(|value| value.checked_add(12 * 8))
        .and_then(|value| value.checked_add(16 * 8))
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    for frame in &state.frames {
        checked_u8(frame.parents.len())?;
        length = length
            .checked_add(74)
            .and_then(|value| value.checked_add(frame.parents.len().checked_mul(34)?))
            .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    }
    length = length
        .checked_add(4)
        .and_then(|value| value.checked_add(state.black.len().checked_mul(34)?))
        .and_then(|value| value.checked_add(SEAL_BYTES))
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    Ok(length)
}

pub(crate) fn diff_encoded_length(state: &DiffState) -> Result<usize> {
    checked_u32(state.path_profile.len())?;
    checked_u32(state.records.len())?;
    let mut length = 8usize
        .checked_add(32)
        .and_then(|value| value.checked_add(3 * 34 + 1))
        .and_then(|value| value.checked_add(12 * 8))
        .and_then(|value| value.checked_add(16 * 8))
        .and_then(|value| value.checked_add(4 + state.path_profile.len()))
        .and_then(|value| value.checked_add(8 + 4))
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    for record in &state.records {
        length = length
            .checked_add(16 + 1 + 1 + 1 + 2 + 1)
            .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
        for entry in [&record.before, &record.after].into_iter().flatten() {
            checked_u32(entry.path.len())?;
            let profile = entry.content_policy.to_string();
            checked_u32(profile.len())?;
            length = length
                .checked_add(4 + entry.path.len() + 1 + 1 + 34 + 8 + 4 + profile.len())
                .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
        }
    }
    length = length
        .checked_add(SEAL_BYTES)
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    Ok(length)
}

fn put_optional_entry(bytes: &mut Vec<u8>, entry: Option<&EntryView>) -> Result<()> {
    match entry {
        None => put_u8(bytes, 0),
        Some(entry) => {
            put_u8(bytes, 1);
            put_string(bytes, &entry.path)?;
            put_u8(bytes, entry.entry_kind);
            put_u8(bytes, entry.mode);
            put_ref(bytes, entry.target);
            put_u64(bytes, entry.logical_bytes);
            put_string(bytes, &entry.content_policy.to_string())?;
        }
    }
    Ok(())
}

fn put_history_request(bytes: &mut Vec<u8>, request: HistoryRequest) {
    put_ref(bytes, request.start_snapshot);
    put_ref(bytes, request.repository_descriptor);
    put_ref(bytes, request.designated_root);
}

fn put_diff_request(bytes: &mut Vec<u8>, request: DiffRequest) {
    put_ref(bytes, request.before_snapshot);
    put_ref(bytes, request.after_snapshot);
    put_ref(bytes, request.repository_descriptor);
    put_u8(
        bytes,
        match request.case_mode {
            CaseMode::Sensitive => 1,
            CaseMode::Folded => 2,
        },
    );
}

fn put_limits(bytes: &mut Vec<u8>, limits: Limits) {
    for value in [
        limits.page_records,
        limits.max_history_snapshots,
        limits.max_tree_objects,
        limits.max_tree_entries,
        limits.max_diff_records,
        limits.max_source_reads,
        limits.max_source_bytes,
        limits.max_object_bytes,
        limits.max_work_units,
        limits.max_cursor_bytes,
        limits.max_charged_memory_bytes,
        limits.max_decode_working_bytes,
    ] {
        put_u64(bytes, value);
    }
}

fn put_ledger(bytes: &mut Vec<u8>, ledger: WorkLedger) {
    for value in [
        ledger.generation_checks,
        ledger.cancellation_checks,
        ledger.source_reads,
        ledger.source_bytes,
        ledger.metadata_objects,
        ledger.snapshot_edges,
        ledger.tree_edges,
        ledger.tree_entries,
        ledger.comparisons,
        ledger.emitted_records,
        ledger.cursor_bytes_encoded,
        ledger.cursor_bytes_decoded,
        ledger.cursor_records_decoded,
        ledger.work_units,
        ledger.charged_memory_bytes,
        ledger.peak_charged_memory_bytes,
    ] {
        put_u64(bytes, value);
    }
}

fn put_generation(bytes: &mut Vec<u8>, generation: Generation) {
    bytes.extend_from_slice(&generation);
}

fn put_ref(bytes: &mut Vec<u8>, reference: ObjectRef) {
    put_u16(bytes, reference.kind.code());
    bytes.extend_from_slice(&reference.digest);
}

fn put_string(bytes: &mut Vec<u8>, value: &str) -> Result<()> {
    put_u32(bytes, checked_u32(value.len())?);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn checked_u8(value: usize) -> Result<u8> {
    u8::try_from(value).map_err(|_| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))
}

fn checked_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))
}

fn checked_usize(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))
}

fn append_seal(bytes: &mut Vec<u8>, domain: &[u8]) {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(&*bytes)
        .finalize();
    bytes.extend_from_slice(&digest);
}

fn verify_seal(bytes: &[u8], domain: &[u8], outer_maximum: u64) -> Result<()> {
    if bytes.len() < 8 + SEAL_BYTES
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > outer_maximum
    {
        return Err(Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)));
    }
    let (body, seal) = bytes.split_at(bytes.len() - SEAL_BYTES);
    let expected = Sha256::new()
        .chain_update(domain)
        .chain_update(body)
        .finalize();
    if expected.as_slice() != seal {
        return corrupt_cursor();
    }
    Ok(())
}

fn enforce_cursor_size(bytes: &[u8], limits: Limits) -> Result<()> {
    enforce_cursor_length(bytes.len(), limits)
}

fn enforce_cursor_length(length: usize, limits: Limits) -> Result<()> {
    let length = u64::try_from(length).unwrap_or(u64::MAX);
    if length > limits.max_cursor_bytes {
        Err(Failure::new(FailureKind::Limit(LimitKind::CursorBytes)))
    } else if length
        .checked_add(512)
        .is_none_or(|charge| charge > limits.max_charged_memory_bytes)
    {
        Err(Failure::new(FailureKind::Limit(LimitKind::ChargedMemory)))
    } else {
        Ok(())
    }
}

fn validate_embedded_limits(limits: Limits, bytes: usize, outer_maximum: u64) -> Result<()> {
    if !limits.is_valid()
        || u64::try_from(bytes).unwrap_or(u64::MAX) > limits.max_cursor_bytes
        || limits.max_cursor_bytes > outer_maximum
    {
        corrupt_cursor()
    } else {
        Ok(())
    }
}

fn valid_ledger(ledger: WorkLedger, limits: Limits) -> bool {
    ledger.generation_checks > 0
        && ledger.source_reads <= limits.max_source_reads
        && ledger.source_bytes <= limits.max_source_bytes
        && ledger.metadata_objects <= ledger.source_reads
        && ledger.tree_entries <= limits.max_tree_entries.saturating_mul(2)
        && ledger.work_units <= limits.max_work_units
        && ledger.charged_memory_bytes <= limits.max_charged_memory_bytes
        && ledger.peak_charged_memory_bytes <= limits.max_charged_memory_bytes
        && ledger.peak_charged_memory_bytes >= ledger.charged_memory_bytes
}

fn validate_retained_charge(
    modeled_state: u64,
    ledger: WorkLedger,
    cursor_bytes: usize,
    limits: Limits,
) -> Result<()> {
    let cursor_bytes = u64::try_from(cursor_bytes)
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
    let cursor_charge = cursor_bytes
        .checked_add(crate::PERSISTENT_BASE_CHARGE)
        .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
    let expected = modeled_state.max(cursor_charge);
    if expected > limits.max_charged_memory_bytes
        || ledger.charged_memory_bytes != expected
        || ledger.cursor_bytes_encoded < cursor_bytes
    {
        corrupt_cursor()
    } else {
        Ok(())
    }
}

fn preflight_decode_accounting(
    ledger: WorkLedger,
    bytes: usize,
    records: u64,
    limits: Limits,
) -> Result<()> {
    let bytes = u64::try_from(bytes)
        .map_err(|_| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    ledger
        .cursor_bytes_decoded
        .checked_add(bytes)
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    ledger
        .cursor_records_decoded
        .checked_add(records)
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))?;
    let work = ledger
        .work_units
        .checked_add(records)
        .ok_or_else(|| Failure::new(FailureKind::Limit(LimitKind::WorkUnits)))?;
    if work > limits.max_work_units {
        Err(Failure::new(FailureKind::Limit(LimitKind::WorkUnits)))
    } else {
        Ok(())
    }
}

fn preflight_history_allocation(
    mut reader: Reader<'_>,
    frame_count: u64,
    limits: Limits,
) -> Result<u64> {
    let mut modeled = crate::PERSISTENT_BASE_CHARGE;
    for _ in 0..frame_count {
        reader.reference()?;
        reader.reference()?;
        reader.u32()?;
        reader.u8()?;
        let parent_count = reader.u8()?;
        if parent_count > 8 {
            return corrupt_cursor();
        }
        modeled = modeled
            .checked_add(256)
            .and_then(|value| value.checked_add(u64::from(parent_count) * 34))
            .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        for _ in 0..parent_count {
            reader.reference()?;
        }
    }
    let black_count = u64::from(reader.u32()?);
    if black_count > limits.max_history_snapshots
        || frame_count
            .checked_add(black_count)
            .is_none_or(|count| count > limits.max_history_snapshots)
    {
        return corrupt_cursor();
    }
    modeled = modeled
        .checked_add(
            black_count
                .checked_mul(96)
                .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?,
        )
        .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
    if modeled > limits.max_charged_memory_bytes {
        return corrupt_cursor();
    }
    for _ in 0..black_count {
        reader.reference()?;
    }
    reader.finish()?;
    frame_count
        .checked_add(black_count)
        .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))
}

fn preflight_diff_allocation(
    mut reader: Reader<'_>,
    record_count: u64,
    path_profile_bytes: usize,
    limits: Limits,
) -> Result<()> {
    let mut modeled = crate::PERSISTENT_BASE_CHARGE
        .checked_add(u64::try_from(path_profile_bytes).unwrap_or(u64::MAX))
        .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
    for _ in 0..record_count {
        reader.take(16)?;
        let before = reader.preflight_optional_entry()?;
        let after = reader.preflight_optional_entry()?;
        if !matches!(reader.u8()?, 1..=3) {
            return corrupt_cursor();
        }
        reader.u16()?;
        if !matches!(reader.u8()?, 0..=2) {
            return corrupt_cursor();
        }
        modeled = modeled
            .checked_add(448)
            .and_then(|value| value.checked_add(before))
            .and_then(|value| value.checked_add(after))
            .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        if modeled > limits.max_charged_memory_bytes {
            return corrupt_cursor();
        }
    }
    reader.finish()
}

fn corrupt_cursor<T>() -> Result<T> {
    Err(Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        self.position = end;
        Ok(value)
    }

    fn magic(&mut self, expected: &[u8; 8]) -> Result<()> {
        if self.take(8)? == expected {
            Ok(())
        } else {
            corrupt_cursor()
        }
    }

    fn generation(&mut self) -> Result<Generation> {
        self.array()
    }

    fn history_request(&mut self) -> Result<HistoryRequest> {
        let request = HistoryRequest {
            start_snapshot: self.reference()?,
            repository_descriptor: self.reference()?,
            designated_root: self.reference()?,
        };
        if request.start_snapshot.kind != ObjectKind::Snapshot
            || request.designated_root.kind != ObjectKind::Snapshot
            || request.repository_descriptor.kind != ObjectKind::RepositoryDescriptor
        {
            return corrupt_cursor();
        }
        Ok(request)
    }

    fn diff_request(&mut self) -> Result<DiffRequest> {
        let before_snapshot = self.reference()?;
        let after_snapshot = self.reference()?;
        let repository_descriptor = self.reference()?;
        let case_mode = match self.u8()? {
            1 => CaseMode::Sensitive,
            2 => CaseMode::Folded,
            _ => return corrupt_cursor(),
        };
        if before_snapshot.kind != ObjectKind::Snapshot
            || after_snapshot.kind != ObjectKind::Snapshot
            || repository_descriptor.kind != ObjectKind::RepositoryDescriptor
        {
            return corrupt_cursor();
        }
        Ok(DiffRequest {
            before_snapshot,
            after_snapshot,
            repository_descriptor,
            case_mode,
        })
    }

    fn limits(&mut self) -> Result<Limits> {
        Ok(Limits {
            page_records: self.u64()?,
            max_history_snapshots: self.u64()?,
            max_tree_objects: self.u64()?,
            max_tree_entries: self.u64()?,
            max_diff_records: self.u64()?,
            max_source_reads: self.u64()?,
            max_source_bytes: self.u64()?,
            max_object_bytes: self.u64()?,
            max_work_units: self.u64()?,
            max_cursor_bytes: self.u64()?,
            max_charged_memory_bytes: self.u64()?,
            max_decode_working_bytes: self.u64()?,
        })
    }

    fn ledger(&mut self) -> Result<WorkLedger> {
        Ok(WorkLedger {
            generation_checks: self.u64()?,
            cancellation_checks: self.u64()?,
            source_reads: self.u64()?,
            source_bytes: self.u64()?,
            metadata_objects: self.u64()?,
            snapshot_edges: self.u64()?,
            tree_edges: self.u64()?,
            tree_entries: self.u64()?,
            comparisons: self.u64()?,
            emitted_records: self.u64()?,
            cursor_bytes_encoded: self.u64()?,
            cursor_bytes_decoded: self.u64()?,
            cursor_records_decoded: self.u64()?,
            work_units: self.u64()?,
            charged_memory_bytes: self.u64()?,
            peak_charged_memory_bytes: self.u64()?,
        })
    }

    fn diff_record(&mut self) -> Result<DiffRecord> {
        let file_id = FileId::new(self.array()?)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        let before = self.optional_entry()?;
        let after = self.optional_entry()?;
        let presence = match self.u8()? {
            1 => PresenceChange::Added,
            2 => PresenceChange::Deleted,
            3 => PresenceChange::Retained,
            _ => return corrupt_cursor(),
        };
        let changes = ChangeFlags::from_bits(self.u16()?)
            .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        let move_hint = match self.u8()? {
            0 => MoveHint::None,
            1 => MoveHint::Rename,
            2 => MoveHint::Move,
            _ => return corrupt_cursor(),
        };
        Ok(DiffRecord {
            file_id,
            before,
            after,
            presence,
            changes,
            move_hint,
        })
    }

    fn optional_entry(&mut self) -> Result<Option<EntryView>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(EntryView {
                path: self.string(ENTRY_STRING_MAXIMUM)?,
                entry_kind: self.u8()?,
                mode: self.u8()?,
                target: self.reference()?,
                logical_bytes: self.u64()?,
                content_policy: ProfileRef::from_str(&self.string(PROFILE_STRING_MAXIMUM)?)
                    .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?,
            })),
            _ => corrupt_cursor(),
        }
    }

    fn reference(&mut self) -> Result<ObjectRef> {
        let kind = ObjectKind::from_code(u64::from(self.u16()?))
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        Ok(ObjectRef {
            kind,
            digest: self.array()?,
        })
    }

    fn string(&mut self, maximum: usize) -> Result<String> {
        Ok(self.borrowed_string(maximum)?.to_owned())
    }

    fn borrowed_string(&mut self, maximum: usize) -> Result<&'a str> {
        let length = self.u32()? as usize;
        if length > maximum {
            return corrupt_cursor();
        }
        std::str::from_utf8(self.take(length)?)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))
    }

    fn preflight_optional_entry(&mut self) -> Result<u64> {
        match self.u8()? {
            0 => Ok(0),
            1 => {
                let path_bytes = self.borrowed_string(ENTRY_STRING_MAXIMUM)?.len();
                self.u8()?;
                self.u8()?;
                self.reference()?;
                self.u64()?;
                let profile_bytes = self.borrowed_string(PROFILE_STRING_MAXIMUM)?.len();
                u64::try_from(path_bytes)
                    .unwrap_or(u64::MAX)
                    .checked_add(u64::try_from(profile_bytes).unwrap_or(u64::MAX))
                    .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))
            }
            _ => corrupt_cursor(),
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            corrupt_cursor()
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kind: ObjectKind, value: u8) -> ObjectRef {
        ObjectRef {
            kind,
            digest: [value; 32],
        }
    }

    #[test]
    fn history_seal_rejects_every_single_byte_mutation() {
        let request = HistoryRequest {
            start_snapshot: reference(ObjectKind::Snapshot, 1),
            repository_descriptor: reference(ObjectKind::RepositoryDescriptor, 2),
            designated_root: reference(ObjectKind::Snapshot, 1),
        };
        let mut state = HistoryState {
            generation: [3; 32],
            request,
            limits: Limits::default(),
            ledger: WorkLedger {
                generation_checks: 1,
                charged_memory_bytes: 512,
                peak_charged_memory_bytes: 512,
                ..WorkLedger::default()
            },
            frames: vec![HistoryFrame {
                snapshot: request.start_snapshot,
                root_tree: reference(ObjectKind::Tree, 4),
                depth: 0,
                next_parent: 0,
                parents: vec![],
            }],
            black: BTreeSet::new(),
        };
        let bytes = crate::finalize_history_cursor(&mut state).unwrap();
        assert_eq!(
            decode_history(&bytes, Limits::default().max_cursor_bytes).unwrap(),
            state
        );
        assert_eq!(
            decode_diff(&bytes, Limits::default().max_cursor_bytes)
                .unwrap_err()
                .kind,
            FailureKind::Corrupt(CorruptKind::Cursor)
        );
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(decode_history(&changed, Limits::default().max_cursor_bytes).is_err());
        }
    }

    #[test]
    fn authenticated_hostile_count_is_rejected_before_allocation() {
        let request = HistoryRequest {
            start_snapshot: reference(ObjectKind::Snapshot, 1),
            repository_descriptor: reference(ObjectKind::RepositoryDescriptor, 2),
            designated_root: reference(ObjectKind::Snapshot, 1),
        };
        let mut state = HistoryState {
            generation: [3; 32],
            request,
            limits: Limits::default(),
            ledger: WorkLedger {
                generation_checks: 1,
                peak_charged_memory_bytes: 512,
                charged_memory_bytes: 512,
                ..WorkLedger::default()
            },
            frames: vec![HistoryFrame {
                snapshot: request.start_snapshot,
                root_tree: reference(ObjectKind::Tree, 4),
                depth: 0,
                next_parent: 0,
                parents: vec![],
            }],
            black: BTreeSet::new(),
        };
        let mut bytes = crate::finalize_history_cursor(&mut state).unwrap();
        bytes.truncate(bytes.len() - SEAL_BYTES);
        let frame_count_offset = 8 + 32 + 3 * 34 + 12 * 8 + 16 * 8;
        bytes[frame_count_offset..frame_count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        append_seal(&mut bytes, HISTORY_DOMAIN);
        assert_eq!(
            decode_history(&bytes, Limits::default().max_cursor_bytes)
                .unwrap_err()
                .kind,
            FailureKind::Corrupt(CorruptKind::Cursor)
        );
    }

    #[test]
    fn authenticated_cursor_with_inconsistent_retained_charge_is_rejected() {
        let request = HistoryRequest {
            start_snapshot: reference(ObjectKind::Snapshot, 1),
            repository_descriptor: reference(ObjectKind::RepositoryDescriptor, 2),
            designated_root: reference(ObjectKind::Snapshot, 1),
        };
        let mut state = HistoryState {
            generation: [3; 32],
            request,
            limits: Limits::default(),
            ledger: WorkLedger {
                generation_checks: 1,
                peak_charged_memory_bytes: 512,
                charged_memory_bytes: 512,
                ..WorkLedger::default()
            },
            frames: vec![HistoryFrame {
                snapshot: request.start_snapshot,
                root_tree: reference(ObjectKind::Tree, 4),
                depth: 0,
                next_parent: 0,
                parents: vec![],
            }],
            black: BTreeSet::new(),
        };
        let mut bytes = crate::finalize_history_cursor(&mut state).unwrap();
        bytes.truncate(bytes.len() - SEAL_BYTES);
        let ledger_offset = 8 + 32 + 3 * 34 + 12 * 8;
        let charged_offset = ledger_offset + 14 * 8;
        let charged = u64::from_be_bytes(
            bytes[charged_offset..charged_offset + 8]
                .try_into()
                .unwrap(),
        );
        bytes[charged_offset..charged_offset + 8].copy_from_slice(&(charged - 1).to_be_bytes());
        append_seal(&mut bytes, HISTORY_DOMAIN);
        assert_eq!(
            decode_history(&bytes, Limits::default().max_cursor_bytes)
                .unwrap_err()
                .kind,
            FailureKind::Corrupt(CorruptKind::Cursor)
        );
    }

    #[test]
    fn decoded_state_memory_is_preflighted_before_record_or_frame_allocation() {
        let limits = Limits {
            max_object_bytes: 256,
            max_decode_working_bytes: 256,
            max_cursor_bytes: 4_096,
            max_charged_memory_bytes: 5_000,
            ..Limits::default()
        };
        assert!(limits.is_valid());

        let profile = ProfileRef::from_str("content-policy.test/opaque@1").unwrap();
        let record = DiffRecord {
            file_id: FileId::new([1; 16]).unwrap(),
            before: None,
            after: Some(EntryView {
                path: "a".to_owned(),
                entry_kind: 2,
                mode: 2,
                target: reference(ObjectKind::ContentManifest, 3),
                logical_bytes: 1,
                content_policy: profile,
            }),
            presence: PresenceChange::Added,
            changes: ChangeFlags::default(),
            move_hint: MoveHint::None,
        };
        let mut diff_records = Vec::new();
        for _ in 0..20 {
            put_diff_record(&mut diff_records, &record).unwrap();
        }
        assert_eq!(
            preflight_diff_allocation(Reader::new(&diff_records), 20, 0, limits)
                .unwrap_err()
                .kind,
            FailureKind::Corrupt(CorruptKind::Cursor)
        );

        let mut history_frames = Vec::new();
        for _ in 0..20 {
            put_ref(&mut history_frames, reference(ObjectKind::Snapshot, 1));
            put_ref(&mut history_frames, reference(ObjectKind::Tree, 2));
            put_u32(&mut history_frames, 0);
            put_u8(&mut history_frames, 0);
            put_u8(&mut history_frames, 0);
        }
        put_u32(&mut history_frames, 0);
        assert_eq!(
            preflight_history_allocation(Reader::new(&history_frames), 20, limits)
                .unwrap_err()
                .kind,
            FailureKind::Corrupt(CorruptKind::Cursor)
        );
    }

    #[test]
    fn cumulative_decode_accounting_is_preflighted_exactly() {
        let limits = Limits::default();
        let exact = WorkLedger {
            work_units: limits.max_work_units - 1,
            ..WorkLedger::default()
        };
        assert!(preflight_decode_accounting(exact, 1, 1, limits).is_ok());

        let exhausted = WorkLedger {
            work_units: limits.max_work_units,
            ..WorkLedger::default()
        };
        assert_eq!(
            preflight_decode_accounting(exhausted, 1, 1, limits)
                .unwrap_err()
                .kind,
            FailureKind::Limit(LimitKind::WorkUnits)
        );

        let overflowed = WorkLedger {
            cursor_records_decoded: u64::MAX,
            ..WorkLedger::default()
        };
        assert_eq!(
            preflight_decode_accounting(overflowed, 1, 1, limits)
                .unwrap_err()
                .kind,
            FailureKind::Limit(LimitKind::Arithmetic)
        );
    }
}
