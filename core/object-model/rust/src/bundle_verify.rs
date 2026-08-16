//! High-level, resource-bounded verification for format-v1 logical bundles.
//!
//! [`visit_logical_bundle`](crate::visit_logical_bundle) is the small framing
//! API.  This module builds the supplied-closure verifier on top of it.  The
//! input, fixed-width indexes, edge lists, work queue, and reachability bitmap
//! live in caller-selected scratch storage; only one configured-size bundle
//! item is decoded at a time.

use core::cmp::Ordering;
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::hard_limits::{
    configured_hard_limit, enforce_hard_limit_context, MAX_BUNDLE_INDEX_ENTRIES,
    MAX_BUNDLE_ITEM_BYTES, MAX_BUNDLE_LOGICAL_RECORDS, MAX_BUNDLE_OBJECTS, MAX_BUNDLE_ROOTS,
    MAX_BUNDLE_SEQUENCE_BYTES, MAX_BUNDLE_TOTAL_ITEMS, MAX_BUNDLE_TRAVERSAL_EDGES, MAX_CHUNK_BYTES,
    MAX_GENERIC_VALUE_BYTES, MAX_MANIFEST_CHUNKS, MAX_METADATA_BYTES,
};
use crate::{
    decode_canonical, encode_canonical_with_limits, hash::opaque_logical_record_id, scan_metadata,
    validate_logical_record, validate_metadata_schema, BundleItemInfo, BundleLimits,
    BundleTranscriptHashWriter, BundleVisitor, Cbor, Error, ErrorCode, Limits, ObjectKind,
    ObjectRef, OpaqueObjectHashWriter, Operation, ProfileRef, Registry, RegistryAssignment, Result,
    TypedDigest, ValidationStage,
};

const ITEM_OFFSET_BYTES: usize = 18;
const REF_BYTES: usize = 34;
const OBJECT_INDEX_BYTES: usize = 42;
const LOGICAL_INDEX_BYTES: usize = 40;
const EDGE_RANGE_BYTES: usize = 16;
const MAX_OPEN_RUNS: usize = 256;
const MAX_RETAINED_RUN_FILES: usize = 16_384;

/// Logical limits and implementation resource ceilings for a complete bundle
/// verification. Values are always constrained by the format-v1 hard maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalBundleVerifyLimits {
    pub sequence_bytes: u64,
    pub item_bytes: u64,
    pub objects: u64,
    pub logical_records: u64,
    pub roots: u64,
    pub items: u64,
    pub traversal_edges: u64,
    pub index_entries: u64,
    pub max_memory_bytes: usize,
    pub max_scratch_bytes: u64,
    pub max_elapsed: Option<Duration>,
    pub max_decoded_item_bytes: usize,
    pub max_run_bytes: usize,
    pub max_open_runs: usize,
    pub read_chunk_bytes: usize,
}

impl Default for LogicalBundleVerifyLimits {
    fn default() -> Self {
        Self {
            sequence_bytes: MAX_BUNDLE_SEQUENCE_BYTES,
            item_bytes: MAX_BUNDLE_ITEM_BYTES,
            objects: MAX_BUNDLE_OBJECTS,
            logical_records: MAX_BUNDLE_LOGICAL_RECORDS,
            roots: MAX_BUNDLE_ROOTS,
            items: MAX_BUNDLE_TOTAL_ITEMS,
            traversal_edges: MAX_BUNDLE_TRAVERSAL_EDGES,
            index_entries: MAX_BUNDLE_INDEX_ENTRIES,
            max_memory_bytes: 64 * 1024 * 1024,
            max_scratch_bytes: 8 * 1024 * 1024 * 1024,
            max_elapsed: None,
            max_decoded_item_bytes: 29_242_720,
            max_run_bytes: 8 * 1024 * 1024,
            max_open_runs: 32,
            read_chunk_bytes: 64 * 1024,
        }
    }
}

impl LogicalBundleVerifyLimits {
    fn constrained(self) -> Result<Self> {
        let result = Self {
            sequence_bytes: configured_hard_limit("bundle-sequence-bytes", self.sequence_bytes)?,
            item_bytes: configured_hard_limit("bundle-largest-item-bytes", self.item_bytes)?,
            objects: configured_hard_limit("bundle-objects", self.objects)?,
            logical_records: configured_hard_limit("bundle-logical-records", self.logical_records)?,
            roots: configured_hard_limit("bundle-roots", self.roots)?,
            items: configured_hard_limit("bundle-total-items", self.items)?,
            traversal_edges: configured_hard_limit("bundle-traversal-edges", self.traversal_edges)?,
            index_entries: configured_hard_limit("bundle-index-entries", self.index_entries)?,
            max_decoded_item_bytes: self
                .max_decoded_item_bytes
                .min(MAX_BUNDLE_ITEM_BYTES as usize),
            max_open_runs: self.max_open_runs.min(MAX_OPEN_RUNS),
            ..self
        };
        if result.max_decoded_item_bytes == 0
            || result.max_open_runs < 2
            || result.read_chunk_bytes == 0
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid)
                .with_layer(1)
                .with_stage(ValidationStage::ConfiguredResourcePreflight));
        }
        let resident = resident_base(&result);
        if resident > result.max_memory_bytes || result.max_run_bytes < OBJECT_INDEX_BYTES {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok(result)
    }
}

/// Caller-selected semantic context and private scratch directory.
#[derive(Clone, Copy)]
pub struct LogicalBundleVerifyOptions<'a> {
    pub scratch_directory: &'a Path,
    pub registry: &'a Registry,
    pub operation: Operation,
    pub limits: LogicalBundleVerifyLimits,
}

impl<'a> LogicalBundleVerifyOptions<'a> {
    pub fn new(scratch_directory: &'a Path, registry: &'a Registry) -> Self {
        Self {
            scratch_directory,
            registry,
            operation: Operation::ConformanceWrite,
            limits: LogicalBundleVerifyLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogicalBundleScratchMetrics {
    pub peak_scratch_bytes: u64,
    pub scratch_files: u64,
    pub index_runs: u64,
}

/// Privacy-safe successful result. It contains counts and digests, never
/// payload bytes, paths, identities, messages, or extension values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalBundleVerifySummary {
    pub highest_layer: u8,
    pub bytes: u64,
    pub items: u64,
    pub object_count: u64,
    pub logical_record_count: u64,
    pub root_count: u64,
    pub traversal_edges: u64,
    pub index_entries: u64,
    pub transcript_digest: [u8; 32],
    pub elapsed: Duration,
    pub scratch: LogicalBundleScratchMetrics,
}

/// Verifies a logical-bundle reader through supplied closure. The reader need
/// not implement `Seek`; exact input bytes are spooled to private scratch.
pub fn verify_logical_bundle_stream<R: Read>(
    reader: R,
    options: LogicalBundleVerifyOptions<'_>,
) -> Result<LogicalBundleVerifySummary> {
    let limits = options.limits.constrained()?;
    let budget = Budget::new(limits)?;
    let workspace = ScratchWorkspace::new(options.scratch_directory, limits.max_scratch_bytes)?;
    verify_spooled(
        reader,
        options.registry,
        options.operation,
        &budget,
        &workspace,
    )
}

/// File convenience entry point for [`verify_logical_bundle_stream`].
pub fn verify_logical_bundle_file(
    path: impl AsRef<Path>,
    options: LogicalBundleVerifyOptions<'_>,
) -> Result<LogicalBundleVerifySummary> {
    let limits = options.limits.constrained()?;
    let mut open = OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    open.custom_flags(no_follow_flag());
    let file = open
        .open(path)
        .map_err(|_| configured_resource_schema_error())?;
    let initial = file
        .metadata()
        .map_err(|_| configured_resource_schema_error())?;
    if !initial.is_file() {
        return Err(configured_resource_schema_error());
    }
    bundle_limit(
        "bundle-sequence-bytes",
        initial.len(),
        limits.sequence_bytes,
    )?;
    let result = verify_logical_bundle_stream(&file, options)?;
    let final_metadata = file
        .metadata()
        .map_err(|_| Error::new(ErrorCode::BundleSequenceInvalid))?;
    if !final_metadata.is_file() || final_metadata.len() != initial.len() {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    Ok(result)
}

struct Budget {
    limits: LogicalBundleVerifyLimits,
    started: Instant,
}

impl Budget {
    fn new(limits: LogicalBundleVerifyLimits) -> Result<Self> {
        let result = Self {
            limits,
            started: Instant::now(),
        };
        result.check_time()?;
        Ok(result)
    }

    fn check_time(&self) -> Result<()> {
        if self
            .limits
            .max_elapsed
            .is_some_and(|maximum| self.started.elapsed() >= maximum)
        {
            Err(Error::new(ErrorCode::LimitTime))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct ScratchState {
    current_bytes: u64,
    peak_bytes: u64,
    files_created: u64,
    index_runs: u64,
}

#[derive(Clone)]
struct ScratchWorkspace {
    directory: PathBuf,
    maximum: u64,
    state: Rc<RefCell<ScratchState>>,
}

impl ScratchWorkspace {
    fn new(directory: &Path, maximum: u64) -> Result<Self> {
        let supplied =
            std::fs::symlink_metadata(directory).map_err(|_| configured_resource_schema_error())?;
        if !supplied.is_dir() || supplied.file_type().is_symlink() {
            return Err(configured_resource_schema_error());
        }
        let canonical =
            std::fs::canonicalize(directory).map_err(|_| configured_resource_schema_error())?;
        let target = std::fs::symlink_metadata(&canonical)
            .map_err(|_| configured_resource_schema_error())?;
        if !target.is_dir() || target.file_type().is_symlink() {
            return Err(configured_resource_schema_error());
        }
        Ok(Self {
            directory: canonical,
            maximum,
            state: Rc::new(RefCell::new(ScratchState::default())),
        })
    }

    fn create(&self, label: &str) -> Result<ScratchFile> {
        let safe: String = label
            .chars()
            .map(|value| {
                if value.is_ascii_alphanumeric() || value == '-' {
                    value
                } else {
                    '-'
                }
            })
            .take(32)
            .collect();
        for _ in 0..32 {
            let mut nonce = [0u8; 12];
            getrandom::getrandom(&mut nonce).map_err(|_| Error::new(ErrorCode::LimitScratch))?;
            let mut suffix = String::with_capacity(24);
            for byte in nonce {
                use core::fmt::Write as _;
                write!(&mut suffix, "{byte:02x}").expect("writing to String");
            }
            let path = self
                .directory
                .join(format!(".ogvcs-bundle-{safe}-{suffix}.tmp"));
            let mut open = OpenOptions::new();
            open.read(true).write(true).create_new(true);
            configure_private_open(&mut open);
            match open.open(&path) {
                Ok(file) => {
                    let metadata = file
                        .metadata()
                        .map_err(|_| Error::new(ErrorCode::LimitScratch))?;
                    #[cfg(unix)]
                    {
                        let mode = metadata.permissions().mode() & 0o777;
                        if mode != 0o600 {
                            let _ = std::fs::remove_file(&path);
                            return Err(Error::new(ErrorCode::LimitScratch));
                        }
                    }
                    self.state.borrow_mut().files_created += 1;
                    return Ok(ScratchFile {
                        path,
                        file,
                        size: 0,
                        maximum: self.maximum,
                        state: Rc::clone(&self.state),
                        identity: ScratchIdentity::from_metadata(&metadata),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(Error::new(ErrorCode::LimitScratch)),
            }
        }
        Err(Error::new(ErrorCode::LimitScratch))
    }

    fn metrics(&self) -> LogicalBundleScratchMetrics {
        let state = self.state.borrow();
        LogicalBundleScratchMetrics {
            peak_scratch_bytes: state.peak_bytes,
            scratch_files: state.files_created,
            index_runs: state.index_runs,
        }
    }
}

fn configured_resource_schema_error() -> Error {
    Error::new(ErrorCode::SchemaFieldInvalid)
        .with_layer(1)
        .with_stage(ValidationStage::ConfiguredResourcePreflight)
}

fn configure_private_open(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(no_follow_flag());
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const fn no_follow_flag() -> i32 {
    0o400000
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const fn no_follow_flag() -> i32 {
    0x100
}

struct ScratchFile {
    path: PathBuf,
    file: File,
    size: u64,
    maximum: u64,
    state: Rc<RefCell<ScratchState>>,
    identity: ScratchIdentity,
}

#[derive(Clone, Copy)]
struct ScratchIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ScratchIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        }
    }

    fn matches(self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        {
            metadata.dev() == self.device && metadata.ino() == self.inode
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            true
        }
    }
}

impl ScratchFile {
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        self.verify_path()?;
        let length = u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::LimitScratch))?;
        self.reserve(length)?;
        self.file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(bytes))
            .map_err(|_| {
                self.release(length);
                Error::new(ErrorCode::LimitScratch)
            })?;
        self.size += length;
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<()> {
        let mut state = self.state.borrow_mut();
        if bytes > self.maximum.saturating_sub(state.current_bytes) {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        state.current_bytes += bytes;
        state.peak_bytes = state.peak_bytes.max(state.current_bytes);
        Ok(())
    }

    fn release(&self, bytes: u64) {
        let mut state = self.state.borrow_mut();
        state.current_bytes = state.current_bytes.saturating_sub(bytes);
    }

    fn read_exact_at(&mut self, position: u64, target: &mut [u8]) -> Result<()> {
        self.verify_path()?;
        let length =
            u64::try_from(target.len()).map_err(|_| Error::new(ErrorCode::LimitScratch))?;
        if position > self.size || length > self.size - position {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        self.file
            .seek(SeekFrom::Start(position))
            .and_then(|_| self.file.read_exact(target))
            .map_err(|_| Error::new(ErrorCode::LimitScratch))
    }

    fn write_exact_at(&mut self, position: u64, bytes: &[u8]) -> Result<()> {
        self.verify_path()?;
        let length = u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::LimitScratch))?;
        if position > self.size || length > self.size - position {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        self.file
            .seek(SeekFrom::Start(position))
            .and_then(|_| self.file.write_all(bytes))
            .map_err(|_| Error::new(ErrorCode::LimitScratch))
    }

    fn allocate_zeroed(&mut self, size: u64, chunk_bytes: usize) -> Result<()> {
        if self.size != 0 || chunk_bytes == 0 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let buffer = vec![0u8; chunk_bytes.min(64 * 1024)];
        let mut remaining = size;
        while remaining != 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            self.append(&buffer[..take])?;
            remaining -= take as u64;
        }
        Ok(())
    }

    fn verify_path(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)
            .map_err(|_| Error::new(ErrorCode::LimitScratch))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != self.size
            || !self.identity.matches(&metadata)
        {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        Ok(())
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        self.release(self.size);
        self.size = 0;
        let _ = std::fs::remove_file(&self.path);
    }
}

struct FixedSorter<const RECORD: usize, const KEY: usize> {
    workspace: ScratchWorkspace,
    records: Vec<[u8; RECORD]>,
    maximum_records: usize,
    max_open_runs: usize,
    runs: Vec<ScratchFile>,
    count: u64,
}

impl<const RECORD: usize, const KEY: usize> FixedSorter<RECORD, KEY> {
    fn new(
        workspace: &ScratchWorkspace,
        max_run_bytes: usize,
        max_open_runs: usize,
    ) -> Result<Self> {
        if RECORD == 0 || KEY == 0 || KEY > RECORD || max_open_runs < 2 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let maximum_records = max_run_bytes / RECORD;
        if maximum_records == 0 {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok(Self {
            workspace: workspace.clone(),
            records: Vec::with_capacity(maximum_records.min(65_536)),
            maximum_records,
            max_open_runs,
            runs: Vec::new(),
            count: 0,
        })
    }

    fn add(&mut self, record: [u8; RECORD], budget: &Budget) -> Result<()> {
        if self.records.len() == self.maximum_records {
            self.flush_run()?;
            if self.runs.len() >= self.max_open_runs {
                let runs = std::mem::take(&mut self.runs);
                self.runs.push(self.merge(runs, budget)?);
            }
        }
        self.records.push(record);
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
        Ok(())
    }

    fn flush_run(&mut self) -> Result<()> {
        if self.records.is_empty() {
            return Ok(());
        }
        if self.runs.len() >= MAX_RETAINED_RUN_FILES {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        self.records
            .sort_unstable_by(|left, right| left[..KEY].cmp(&right[..KEY]).then(left.cmp(right)));
        let mut run = self.workspace.create("index-run")?;
        for record in self.records.drain(..) {
            run.append(&record)?;
        }
        self.workspace.state.borrow_mut().index_runs += 1;
        self.runs.push(run);
        Ok(())
    }

    fn finish(mut self, budget: &Budget) -> Result<SortedIndex<RECORD, KEY>> {
        self.flush_run()?;
        if self.runs.is_empty() {
            self.runs.push(self.workspace.create("index-empty")?);
        }
        while self.runs.len() > 1 {
            budget.check_time()?;
            let mut next = Vec::with_capacity(self.runs.len().div_ceil(self.max_open_runs));
            let mut source = std::mem::take(&mut self.runs).into_iter();
            loop {
                let group: Vec<_> = source.by_ref().take(self.max_open_runs).collect();
                if group.is_empty() {
                    break;
                }
                if group.len() == 1 {
                    next.extend(group);
                } else {
                    next.push(self.merge(group, budget)?);
                }
            }
            self.runs = next;
        }
        Ok(SortedIndex {
            file: self.runs.pop().expect("one final run"),
            count: self.count,
        })
    }

    fn merge(&self, runs: Vec<ScratchFile>, budget: &Budget) -> Result<ScratchFile> {
        let mut cursors: Vec<RunCursor<RECORD>> =
            runs.into_iter().map(RunCursor::<RECORD>::new).collect();
        for cursor in &mut cursors {
            cursor.advance()?;
        }
        let mut output = self.workspace.create("index-merge")?;
        loop {
            budget.check_time()?;
            let selected = cursors
                .iter()
                .enumerate()
                .filter_map(|(index, cursor)| cursor.current.as_ref().map(|record| (index, record)))
                .min_by(|(_, left), (_, right)| {
                    left[..KEY].cmp(&right[..KEY]).then(left.cmp(right))
                })
                .map(|(index, _)| index);
            let Some(selected) = selected else {
                break;
            };
            output.append(cursors[selected].current.as_ref().expect("selected record"))?;
            cursors[selected].advance()?;
        }
        self.workspace.state.borrow_mut().index_runs += 1;
        Ok(output)
    }
}

struct RunCursor<const RECORD: usize> {
    file: ScratchFile,
    position: u64,
    current: Option<[u8; RECORD]>,
}

impl<const RECORD: usize> RunCursor<RECORD> {
    fn new(file: ScratchFile) -> Self {
        Self {
            file,
            position: 0,
            current: None,
        }
    }

    fn advance(&mut self) -> Result<()> {
        if self.position == self.file.size {
            self.current = None;
            return Ok(());
        }
        let mut record = [0u8; RECORD];
        self.file.read_exact_at(self.position, &mut record)?;
        self.position += RECORD as u64;
        self.current = Some(record);
        Ok(())
    }
}

struct SortedIndex<const RECORD: usize, const KEY: usize> {
    file: ScratchFile,
    count: u64,
}

impl<const RECORD: usize, const KEY: usize> SortedIndex<RECORD, KEY> {
    fn record(&mut self, index: u64) -> Result<[u8; RECORD]> {
        if index >= self.count {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        let mut record = [0u8; RECORD];
        self.file
            .read_exact_at(index.saturating_mul(RECORD as u64), &mut record)?;
        Ok(record)
    }

    fn lower_bound(&mut self, key: &[u8; KEY]) -> Result<u64> {
        let mut left = 0u64;
        let mut right = self.count;
        while left < right {
            let middle = left + (right - left) / 2;
            let record = self.record(middle)?;
            if record[..KEY] < key[..] {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        Ok(left)
    }

    fn find(&mut self, key: &[u8; KEY]) -> Result<Option<[u8; RECORD]>> {
        let index = self.lower_bound(key)?;
        if index == self.count {
            return Ok(None);
        }
        let record = self.record(index)?;
        Ok((record[..KEY] == key[..]).then_some(record))
    }
}

struct SpoolVisitor<'a> {
    sequence: &'a mut ScratchFile,
    offsets: &'a mut ScratchFile,
    budget: &'a Budget,
    total: u64,
    largest_item: u64,
    saw_trailer: bool,
}

impl BundleVisitor for SpoolVisitor<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.budget.check_time()?;
        let length =
            u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
        let total = self
            .total
            .checked_add(length)
            .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded).with_layer(1))?;
        bundle_limit(
            "bundle-sequence-bytes",
            total,
            self.budget.limits.sequence_bytes,
        )?;
        self.sequence.append(bytes)?;
        self.total += length;
        Ok(())
    }

    fn item_end(&mut self, info: BundleItemInfo) -> Result<()> {
        let bytes =
            u64::try_from(info.bytes).map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
        bundle_limit(
            "bundle-largest-item-bytes",
            bytes,
            self.budget.limits.item_bytes,
        )?;
        self.largest_item = self.largest_item.max(bytes);
        self.saw_trailer |= info.item_type == 5;
        let mut record = [0u8; ITEM_OFFSET_BYTES];
        record[..2].copy_from_slice(&info.item_type.to_be_bytes());
        record[2..10].copy_from_slice(&(info.offset as u64).to_be_bytes());
        record[10..].copy_from_slice(&bytes.to_be_bytes());
        self.offsets.append(&record)
    }
}

#[derive(Clone, Copy)]
struct ItemOffset {
    item_type: u16,
    offset: u64,
    bytes: u64,
}

fn read_item_offset(file: &mut ScratchFile, index: u64) -> Result<ItemOffset> {
    let mut record = [0u8; ITEM_OFFSET_BYTES];
    file.read_exact_at(index.saturating_mul(ITEM_OFFSET_BYTES as u64), &mut record)?;
    Ok(ItemOffset {
        item_type: u16::from_be_bytes([record[0], record[1]]),
        offset: u64::from_be_bytes(record[2..10].try_into().expect("fixed offset")),
        bytes: u64::from_be_bytes(record[10..18].try_into().expect("fixed length")),
    })
}

struct PrefixReader {
    bytes: Vec<u8>,
    cursor: usize,
    absolute_offset: u64,
}

impl PrefixReader {
    fn new(bytes: Vec<u8>, absolute_offset: u64) -> Self {
        Self {
            bytes,
            cursor: 0,
            absolute_offset,
        }
    }

    fn take(&mut self, count: usize) -> Result<&[u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?;
        if end > self.bytes.len() {
            return Err(Error::at(
                ErrorCode::BundleSequenceInvalid,
                usize::try_from(self.absolute_offset).unwrap_or(usize::MAX),
            ));
        }
        let start = self.cursor;
        self.cursor = end;
        Ok(&self.bytes[start..end])
    }

    fn head(&mut self) -> Result<(u8, u64)> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let additional = first & 31;
        if major == 6 || major == 7 || additional == 31 {
            return Err(Error::new(ErrorCode::CborNonCanonical));
        }
        let (size, mut value) = match additional {
            0..=23 => (0usize, additional as u64),
            24 => (1, 0),
            25 => (2, 0),
            26 => (4, 0),
            27 => (8, 0),
            _ => return Err(Error::new(ErrorCode::CborNonCanonical)),
        };
        if size != 0 {
            for byte in self.take(size)? {
                value = (value << 8) | u64::from(*byte);
            }
            if (size == 1 && value < 24)
                || (size == 2 && value <= 0xff)
                || (size == 4 && value <= 0xffff)
                || (size == 8 && value <= 0xffff_ffff)
            {
                return Err(Error::new(ErrorCode::CborNonCanonical));
            }
        }
        Ok((major, value))
    }

    fn unsigned(&mut self, expected: Option<u64>) -> Result<u64> {
        let (major, value) = self.head()?;
        if major != 0 || expected.is_some_and(|expected| expected != value) {
            Err(Error::new(ErrorCode::SchemaFieldInvalid))
        } else {
            Ok(value)
        }
    }

    fn skip_value(&mut self, depth: usize) -> Result<()> {
        if depth > 8 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let (major, length) = self.head()?;
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let length = usize::try_from(length)
                    .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
                self.take(length)?;
                Ok(())
            }
            4 => {
                for _ in 0..length {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..length {
                    self.skip_value(depth + 1)?;
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        }
    }
}

struct OpaqueObjectEnvelope {
    ordinal: u64,
    sort_key: Vec<u8>,
}

fn opaque_object_envelope(
    sequence: &mut ScratchFile,
    item: ItemOffset,
) -> Result<OpaqueObjectEnvelope> {
    // The frozen ObjectRef wire shape is much smaller than this prefix. Keep
    // the payload opaque so chunk-sized object items are never decoded merely
    // to establish section ordering.
    let prefix_length = item.bytes.min(1_024) as usize;
    let mut prefix = vec![0u8; prefix_length];
    sequence.read_exact_at(item.offset, &mut prefix)?;
    let mut reader = PrefixReader::new(prefix, item.offset);
    if reader.head()? != (5, 5) {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    reader.unsigned(Some(0))?;
    reader.unsigned(Some(1))?;
    reader.unsigned(Some(1))?;
    reader.unsigned(Some(2))?;
    reader.unsigned(Some(2))?;
    let ordinal = reader.unsigned(None)?;
    reader.unsigned(Some(3))?;
    let reference_start = reader.cursor;
    reader.skip_value(0).map_err(|_| {
        Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::CanonicalFraming)
    })?;
    let reference_end = reader.cursor;
    if reference_end.saturating_sub(reference_start) > 512 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::CanonicalFraming));
    }
    let sort_key = reader.bytes[reference_start..reference_end].to_vec();
    reader.unsigned(Some(4))?;
    let (major, payload_length) = reader.head()?;
    if major != 2 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::CanonicalFraming));
    }
    let payload_offset = item
        .offset
        .checked_add(reader.cursor as u64)
        .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?;
    if payload_offset.checked_add(payload_length) != item.offset.checked_add(item.bytes) {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    Ok(OpaqueObjectEnvelope { ordinal, sort_key })
}

#[derive(Clone, Copy)]
struct ObjectEnvelope {
    kind: u16,
    digest: [u8; 32],
    payload_offset: u64,
    payload_length: u64,
}

impl ObjectEnvelope {
    fn reference(self) -> Result<ObjectRef> {
        Ok(ObjectRef {
            kind: ObjectKind::from_code(u64::from(self.kind))?,
            digest: self.digest,
        })
    }
}

fn object_envelope(sequence: &mut ScratchFile, item: ItemOffset) -> Result<ObjectEnvelope> {
    let prefix_length = item.bytes.min(512) as usize;
    let mut prefix = vec![0u8; prefix_length];
    sequence.read_exact_at(item.offset, &mut prefix)?;
    let mut reader = PrefixReader::new(prefix, item.offset);
    if reader.head()? != (5, 5) {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    reader.unsigned(Some(0))?;
    reader.unsigned(Some(1))?;
    reader.unsigned(Some(1))?;
    reader.unsigned(Some(2))?;
    reader.unsigned(Some(2))?;
    reader.unsigned(None)?;
    reader.unsigned(Some(3))?;
    let (kind, digest) = (|| {
        if reader.head()? != (5, 4) {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        reader.unsigned(Some(0))?;
        if reader.unsigned(None)? != 1 {
            return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
        }
        reader.unsigned(Some(1))?;
        let kind = u16::try_from(reader.unsigned(None)?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if kind == 0 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        reader.unsigned(Some(2))?;
        if reader.unsigned(None)? != 1 {
            return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
        }
        reader.unsigned(Some(3))?;
        if reader.head()? != (2, 32) {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let digest = reader.take(32)?.try_into().expect("fixed object digest");
        Ok((kind, digest))
    })()
    .map_err(|error: Error| error.with_layer(1))?;
    reader.unsigned(Some(4))?;
    let (major, payload_length) = reader.head()?;
    if major != 2 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid).with_layer(1));
    }
    let payload_offset = item
        .offset
        .checked_add(reader.cursor as u64)
        .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?;
    if payload_offset.checked_add(payload_length) != item.offset.checked_add(item.bytes) {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    Ok(ObjectEnvelope {
        kind,
        digest,
        payload_offset,
        payload_length,
    })
}

fn resident_base(limits: &LogicalBundleVerifyLimits) -> usize {
    let write_buffer = (limits.max_memory_bytes / 16).clamp(1, 32_768);
    limits
        .max_run_bytes
        .saturating_add(limits.read_chunk_bytes.saturating_mul(2))
        .saturating_add(write_buffer.saturating_mul(3))
        .saturating_add(limits.max_open_runs.saturating_mul(OBJECT_INDEX_BYTES))
        .saturating_add(4_096)
}

fn bundle_limit(name: &'static str, value: u64, configured: u64) -> Result<()> {
    enforce_hard_limit_context(name, value, configured, ErrorCode::BundleBudgetExceeded, 1)
        .map(|_| ())
}

fn scanner_value_bytes(limits: &LogicalBundleVerifyLimits) -> usize {
    (limits
        .max_memory_bytes
        .saturating_sub(resident_base(limits))
        / 4)
    .clamp(1, MAX_GENERIC_VALUE_BYTES as usize)
}

fn read_payload(
    sequence: &mut ScratchFile,
    envelope: ObjectEnvelope,
    budget: &Budget,
    hash: bool,
) -> Result<Option<Vec<u8>>> {
    budget.check_time()?;
    let metadata = envelope.kind != ObjectKind::Chunk.code();
    let payload_length =
        usize::try_from(envelope.payload_length).map_err(|_| Error::new(ErrorCode::LimitMemory))?;
    if metadata && payload_length > budget.limits.max_decoded_item_bytes {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    if metadata
        && resident_base(&budget.limits).saturating_add(payload_length)
            > budget.limits.max_memory_bytes
    {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    let mut payload = metadata.then(|| vec![0u8; payload_length]);
    let buffer_length = budget.limits.read_chunk_bytes.min(payload_length.max(1));
    let mut buffer = payload.is_none().then(|| vec![0u8; buffer_length]);
    let mut hasher = if hash {
        Some(OpaqueObjectHashWriter::new(
            envelope.kind,
            if metadata {
                MAX_METADATA_BYTES as usize
            } else {
                MAX_CHUNK_BYTES as usize
            },
        )?)
    } else {
        None
    };
    let mut cursor = 0usize;
    while cursor < payload_length {
        budget.check_time()?;
        let take = (payload_length - cursor).min(budget.limits.read_chunk_bytes);
        if let Some(payload) = &mut payload {
            sequence.read_exact_at(
                envelope.payload_offset + cursor as u64,
                &mut payload[cursor..cursor + take],
            )?;
            if let Some(hasher) = &mut hasher {
                hasher.update(&payload[cursor..cursor + take])?;
            }
        } else {
            let buffer = buffer.as_mut().expect("chunk buffer");
            sequence.read_exact_at(envelope.payload_offset + cursor as u64, &mut buffer[..take])?;
            if let Some(hasher) = &mut hasher {
                hasher.update(&buffer[..take])?;
            }
        }
        cursor += take;
    }
    if let Some(hasher) = hasher {
        if hasher.finish()? != envelope.digest {
            return Err(Error::new(ErrorCode::ObjectIdMismatch));
        }
    }
    Ok(payload)
}

fn scan_object_payload(
    sequence: &mut ScratchFile,
    envelope: ObjectEnvelope,
    budget: &Budget,
) -> Result<crate::MetadataObject> {
    let payload =
        read_payload(sequence, envelope, budget, false)?.expect("metadata payload is retained");
    let live_raw = resident_base(&budget.limits)
        .checked_add(payload.len().saturating_mul(2))
        .and_then(|bytes| bytes.checked_add(4_096))
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    let decode_memory = budget
        .limits
        .max_memory_bytes
        .checked_sub(live_raw)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    let scanned = scan_metadata(
        &payload,
        Limits {
            max_input_bytes: payload.len(),
            // `scan_metadata` retains its own canonical raw copy while
            // decoding. Both that copy and this spooled payload remain live
            // until the scan succeeds.
            max_working_bytes: decode_memory,
            ..Limits::METADATA
        },
    )?;
    drop(payload);
    Ok(scanned)
}

fn decode_item(sequence: &mut ScratchFile, item: ItemOffset, budget: &Budget) -> Result<Cbor> {
    budget.check_time()?;
    let length = usize::try_from(item.bytes).map_err(|_| Error::new(ErrorCode::LimitMemory))?;
    if length > budget.limits.max_decoded_item_bytes {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    let live_before_decode = resident_base(&budget.limits)
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    let decode_memory = budget
        .limits
        .max_memory_bytes
        .checked_sub(live_before_decode)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    let mut bytes = vec![0u8; length];
    sequence.read_exact_at(item.offset, &mut bytes)?;
    decode_canonical(
        &bytes,
        Limits {
            max_input_bytes: length,
            max_value_bytes: length.min(MAX_GENERIC_VALUE_BYTES as usize),
            max_nesting: 32,
            max_container_items: MAX_MANIFEST_CHUNKS as usize,
            // The raw item and all resident sorter/read buffers are live while
            // the compact CBOR representation expands into owned nodes.
            max_working_bytes: decode_memory,
        },
    )
}

fn decoded_record_bytes(value: &Cbor, budget: &Budget) -> Result<Vec<u8>> {
    let limit = budget.limits.max_decoded_item_bytes;
    encode_canonical_with_limits(
        value,
        Limits {
            max_input_bytes: limit,
            max_value_bytes: limit.min(MAX_GENERIC_VALUE_BYTES as usize),
            max_nesting: 32,
            max_container_items: MAX_MANIFEST_CHUNKS as usize,
            max_working_bytes: budget.limits.max_memory_bytes,
        },
    )
}

fn opaque_sort_key(value: &Cbor, budget: &Budget) -> Result<Vec<u8>> {
    // ObjectRef, TypedDigest, logical type, and ProfileRef sort components all
    // fit comfortably below this envelope-specific cap when well shaped. A
    // larger opaque component is already an invalid bundle-envelope value;
    // reject it without allocating another item-sized buffer.
    encode_canonical_with_limits(
        value,
        Limits {
            max_input_bytes: 512,
            max_value_bytes: 512,
            max_nesting: 8,
            max_container_items: 16,
            max_working_bytes: budget.limits.max_memory_bytes.min(4_096),
        },
    )
    .map_err(|_| {
        Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::CanonicalFraming)
    })
}

fn observe_known_schema_error(best: &mut Option<Error>, error: Error) -> Result<()> {
    if error.layer != 2 || error.stage != ValidationStage::KnownSchema {
        return Err(error);
    }
    if best
        .as_ref()
        .is_none_or(|current| error.precedence_key() < current.precedence_key())
    {
        *best = Some(error);
    }
    Ok(())
}

fn map_fields<'a>(value: &'a Cbor, expected: &[u64], code: ErrorCode) -> Result<Vec<&'a Cbor>> {
    let Cbor::Map(entries) = value else {
        return Err(Error::new(code));
    };
    if entries.len() != expected.len() {
        return Err(Error::new(code));
    }
    let mut values = Vec::with_capacity(expected.len());
    for ((key, value), expected) in entries.iter().zip(expected) {
        if key != &Cbor::UInt(*expected) {
            return Err(Error::new(code));
        }
        values.push(value);
    }
    Ok(values)
}

fn field(value: &Cbor, wanted: u64) -> Result<&Cbor> {
    let Cbor::Map(entries) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    entries
        .iter()
        .find_map(|(key, value)| (key == &Cbor::UInt(wanted)).then_some(value))
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn optional_field(value: &Cbor, wanted: u64) -> Option<&Cbor> {
    let Cbor::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| (key == &Cbor::UInt(wanted)).then_some(value))
}

fn uint(value: &Cbor, code: ErrorCode) -> Result<u64> {
    if let Cbor::UInt(value) = value {
        Ok(*value)
    } else {
        Err(Error::new(code))
    }
}

fn array(value: &Cbor) -> Result<&[Cbor]> {
    if let Cbor::Array(value) = value {
        Ok(value)
    } else {
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    }
}

fn typed_digest(value: &Cbor) -> Result<[u8; 32]> {
    Ok(*TypedDigest::from_cbor(value)?.digest())
}

fn bundle_envelope_object_ref(value: &Cbor) -> Result<ObjectRef> {
    let fields = map_fields(value, &[0, 1, 2, 3], ErrorCode::SchemaFieldInvalid)
        .map_err(|error| error.with_layer(1))?;
    let version =
        uint(fields[0], ErrorCode::SchemaFieldInvalid).map_err(|error| error.with_layer(1))?;
    let kind_code =
        uint(fields[1], ErrorCode::SchemaFieldInvalid).map_err(|error| error.with_layer(1))?;
    let algorithm =
        uint(fields[2], ErrorCode::SchemaFieldInvalid).map_err(|error| error.with_layer(1))?;
    let Cbor::Bytes(digest) = fields[3] else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid).with_layer(1));
    };
    let digest: [u8; 32] = digest
        .as_slice()
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(1))?;
    if version != 1 || algorithm != 1 {
        return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported).with_layer(1));
    }
    let kind = ObjectKind::from_code(kind_code)?;
    Ok(ObjectRef { kind, digest })
}

fn ref_bytes(reference: ObjectRef) -> [u8; REF_BYTES] {
    let mut result = [0u8; REF_BYTES];
    result[..2].copy_from_slice(&reference.kind.code().to_be_bytes());
    result[2..].copy_from_slice(&reference.digest);
    result
}

fn ref_from_bytes(value: &[u8; REF_BYTES]) -> Result<ObjectRef> {
    let kind = ObjectKind::from_code(u16::from_be_bytes([value[0], value[1]]) as u64)?;
    let digest = value[2..].try_into().expect("fixed digest");
    Ok(ObjectRef { kind, digest })
}

fn object_index_record(reference: ObjectRef, ordinal: u64) -> [u8; OBJECT_INDEX_BYTES] {
    let mut result = [0u8; OBJECT_INDEX_BYTES];
    result[..32].copy_from_slice(&reference.digest);
    result[32..34].copy_from_slice(&reference.kind.code().to_be_bytes());
    result[34..].copy_from_slice(&ordinal.to_be_bytes());
    result
}

fn logical_index_record(digest: [u8; 32], ordinal: u64) -> [u8; LOGICAL_INDEX_BYTES] {
    let mut result = [0u8; LOGICAL_INDEX_BYTES];
    result[..32].copy_from_slice(&digest);
    result[32..].copy_from_slice(&ordinal.to_be_bytes());
    result
}

fn object_index_key(reference: ObjectRef) -> [u8; 34] {
    let mut result = [0u8; 34];
    result[..32].copy_from_slice(&reference.digest);
    result[32..].copy_from_slice(&reference.kind.code().to_be_bytes());
    result
}

#[derive(Clone, Copy)]
struct Header {
    object_count: u64,
    logical_count: u64,
    root_count: u64,
    declared_bytes: u64,
    declared_largest: u64,
    declared_edges: u64,
    declared_index: u64,
}

fn parse_header(value: &Cbor, limits: &LogicalBundleVerifyLimits) -> Result<Header> {
    let fields = map_fields(
        value,
        &[0, 1, 2, 3, 4, 5, 6],
        ErrorCode::BundleSequenceInvalid,
    )?;
    if uint(fields[0], ErrorCode::BundleSequenceInvalid)? != 1
        || uint(fields[1], ErrorCode::BundleSequenceInvalid)? != 1
    {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    if uint(fields[2], ErrorCode::BundleSequenceInvalid)? != 1 {
        return Err(Error::new(ErrorCode::BundleModeUnsupported));
    }
    let object_count = uint(fields[3], ErrorCode::BundleSequenceInvalid)?;
    let logical_count = uint(fields[4], ErrorCode::BundleSequenceInvalid)?;
    let root_count = uint(fields[5], ErrorCode::BundleSequenceInvalid)?;
    let declarations = map_fields(fields[6], &[0, 1, 2, 3], ErrorCode::BundleSequenceInvalid)?;
    let result = Header {
        object_count,
        logical_count,
        root_count,
        declared_bytes: uint(declarations[0], ErrorCode::BundleSequenceInvalid)?,
        declared_largest: uint(declarations[1], ErrorCode::BundleSequenceInvalid)?,
        declared_edges: uint(declarations[2], ErrorCode::BundleSequenceInvalid)?,
        declared_index: uint(declarations[3], ErrorCode::BundleSequenceInvalid)?,
    };
    for (name, value, maximum) in [
        ("bundle-objects", result.object_count, limits.objects),
        (
            "bundle-logical-records",
            result.logical_count,
            limits.logical_records,
        ),
        ("bundle-roots", result.root_count, limits.roots),
        (
            "bundle-sequence-bytes",
            result.declared_bytes,
            limits.sequence_bytes,
        ),
        (
            "bundle-largest-item-bytes",
            result.declared_largest,
            limits.item_bytes,
        ),
        (
            "bundle-traversal-edges",
            result.declared_edges,
            limits.traversal_edges,
        ),
        (
            "bundle-index-entries",
            result.declared_index,
            limits.index_entries,
        ),
    ] {
        bundle_limit(name, value, maximum)?;
    }
    let items = result
        .object_count
        .checked_add(result.logical_count)
        .and_then(|value| value.checked_add(result.root_count))
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded).with_layer(1))?;
    bundle_limit("bundle-total-items", items, limits.items)?;
    Ok(result)
}

fn parse_trailer(value: &Cbor, header: Header, items: u64, transcript: [u8; 32]) -> Result<()> {
    let fields = map_fields(
        value,
        &[0, 1, 2, 3, 4, 5, 6],
        ErrorCode::BundleSequenceInvalid,
    )?;
    if uint(fields[0], ErrorCode::BundleSequenceInvalid)? != 1
        || uint(fields[1], ErrorCode::BundleSequenceInvalid)? != 5
    {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    if uint(fields[2], ErrorCode::BundleTrailerMismatch)? != header.object_count
        || uint(fields[3], ErrorCode::BundleTrailerMismatch)? != header.logical_count
        || uint(fields[4], ErrorCode::BundleTrailerMismatch)? != header.root_count
        || uint(fields[5], ErrorCode::BundleTrailerMismatch)? != items
        || typed_digest(fields[6])? != transcript
    {
        return Err(Error::new(ErrorCode::BundleTrailerMismatch));
    }
    Ok(())
}

fn transcript(sequence: &mut ScratchFile, end: u64, budget: &Budget) -> Result<[u8; 32]> {
    let mut hash = BundleTranscriptHashWriter::new(
        usize::try_from(budget.limits.sequence_bytes).unwrap_or(usize::MAX),
    );
    let mut buffer = vec![0u8; budget.limits.read_chunk_bytes];
    let mut position = 0u64;
    while position < end {
        budget.check_time()?;
        let take = (end - position).min(buffer.len() as u64) as usize;
        sequence.read_exact_at(position, &mut buffer[..take])?;
        hash.update(&buffer[..take])?;
        position += take as u64;
    }
    Ok(*hash.finish()?.digest())
}

#[derive(Clone, Copy)]
struct DeferredSemanticError(Option<ErrorCode>);

impl DeferredSemanticError {
    fn new() -> Self {
        Self(None)
    }

    fn observe(&mut self, error: Error) -> Result<()> {
        if matches!(
            error.code,
            ErrorCode::RequiredFeatureUnsupported
                | ErrorCode::ProfileUnknown
                | ErrorCode::ProfileConformanceOnly
                | ErrorCode::ProfileStateForbidden
        ) {
            if self
                .0
                .is_none_or(|current| semantic_rank(error.code) < semantic_rank(current))
            {
                self.0 = Some(error.code);
            }
            Ok(())
        } else {
            Err(error)
        }
    }

    fn finish(self) -> Result<()> {
        if let Some(code) = self.0 {
            Err(Error::new(code))
        } else {
            Ok(())
        }
    }
}

fn semantic_rank(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::RequiredFeatureUnsupported => 0,
        ErrorCode::ProfileUnknown => 1,
        ErrorCode::ProfileConformanceOnly => 2,
        ErrorCode::ProfileStateForbidden => 3,
        _ => u8::MAX,
    }
}

fn check_assignment(
    registry: &Registry,
    assignment: RegistryAssignment<'_>,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    if let Err(error) = registry.check_assignment_if_present(assignment, operation) {
        deferred.observe(error)?;
    }
    Ok(())
}

fn check_rule_fields(
    value: &Cbor,
    cddl_rule: &str,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    let Cbor::Map(fields) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    for (key, _) in fields {
        let Cbor::UInt(code) = key else {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        };
        let code = u16::try_from(*code).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        check_assignment(
            registry,
            RegistryAssignment::KindField { cddl_rule, code },
            operation,
            deferred,
        )?;
    }
    Ok(())
}

fn check_rule_codes(
    codes: &[u16],
    cddl_rule: &str,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    for &code in codes {
        check_assignment(
            registry,
            RegistryAssignment::KindField { cddl_rule, code },
            operation,
            deferred,
        )?;
    }
    Ok(())
}

fn check_enum(
    registry: &Registry,
    domain: &str,
    code: u64,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    let code = u32::try_from(code).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    check_assignment(
        registry,
        RegistryAssignment::SemanticEnum { domain, code },
        operation,
        deferred,
    )
}

fn object_rule(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Chunk => "chunk",
        ObjectKind::ContentManifest => "content-manifest",
        ObjectKind::Tree => "tree",
        ObjectKind::ChangeSet => "change-set",
        ObjectKind::AssetGroupSet => "group-set",
        ObjectKind::RepositoryDescriptor => "repository-descriptor",
        ObjectKind::Snapshot => "snapshot",
        ObjectKind::ShelfRevision => "shelf-revision",
        ObjectKind::Provenance => "provenance",
        ObjectKind::Attestation => "attestation",
        ObjectKind::ConflictSet => "conflict-set",
    }
}

fn logical_rule(record_type: u16) -> Result<&'static str> {
    Ok(match record_type {
        1 => "repository-root-record",
        2 => "mutable-ref-record",
        3 => "shelf-pointer-record",
        4 => "fileid-lifetime-record",
        5 => "import-mapping-record",
        6 => "pending-change-reference-record",
        7 => "lock-reference-record",
        8 => "annotation-record",
        9 => "fixture-event-record",
        _ => return Err(Error::new(ErrorCode::LogicalRecordTypeUnsupported)),
    })
}

fn check_object_envelope_assignments(
    kind: ObjectKind,
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_assignment(
        registry,
        RegistryAssignment::ObjectKind(kind.code()),
        operation,
        deferred,
    )?;
    check_assignment(
        registry,
        RegistryAssignment::HashAlgorithm(1),
        operation,
        deferred,
    )?;
    for key in 0..=3 {
        if optional_field(value, key).is_some() {
            check_assignment(
                registry,
                RegistryAssignment::CommonField(key as u16),
                operation,
                deferred,
            )?;
        }
    }
    let Cbor::Map(fields) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    for (key, _) in fields {
        if let Cbor::UInt(code @ 16..=4095) = key {
            check_assignment(
                registry,
                RegistryAssignment::KindField {
                    cddl_rule: object_rule(kind),
                    code: *code as u16,
                },
                operation,
                deferred,
            )?;
        }
    }
    if let Some(Cbor::Map(extensions)) = optional_field(value, 3) {
        for (key, _) in extensions {
            let Cbor::Text(key) = key else {
                return Err(Error::new(ErrorCode::ExtensionKeyInvalid));
            };
            let extension = ProfileRef::from_str(key)
                .map_err(|_| Error::new(ErrorCode::ExtensionKeyInvalid))?;
            if registry.extension(&extension).is_some() {
                check_assignment(
                    registry,
                    RegistryAssignment::Extension(&extension),
                    operation,
                    deferred,
                )?;
            }
        }
    }
    Ok(())
}

fn check_profile(
    value: &Cbor,
    families: &[&str],
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, "profile-ref", registry, operation, deferred)?;
    let profile = ProfileRef::from_cbor(value)?;
    let Some(entry) = registry.profile(&profile) else {
        return deferred.observe(Error::new(ErrorCode::ProfileUnknown));
    };
    if !families.contains(&entry.family.as_str()) {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    if let Err(error) = registry.check_profile(&profile, &entry.family, operation) {
        deferred.observe(error)?;
    }
    Ok(())
}

fn check_features(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    for value in array(field(value, 2)?)? {
        let code = u32::try_from(uint(value, ErrorCode::SchemaFieldInvalid)?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if let Err(error) =
            registry.check_assignment(RegistryAssignment::RequiredFeature(code), operation)
        {
            deferred.observe(error)?;
        }
    }
    Ok(())
}

const CONTENT_FAMILIES: &[&str] = &["content-policy", "fixture-content-policy"];
const GROUP_FAMILIES: &[&str] = &["group", "fixture-group"];
const ROLE_FAMILIES: &[&str] = &["group-role", "fixture-group-role"];
const EXTERNAL_FAMILIES: &[&str] = &["external-key", "fixture-external-key"];

fn check_ref_assignments(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, "object-ref", registry, operation, deferred)?;
    check_assignment(
        registry,
        RegistryAssignment::ObjectKind(
            u16::try_from(uint(field(value, 1)?, ErrorCode::SchemaFieldInvalid)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        ),
        operation,
        deferred,
    )?;
    check_assignment(
        registry,
        RegistryAssignment::HashAlgorithm(
            u16::try_from(uint(field(value, 2)?, ErrorCode::SchemaFieldInvalid)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        ),
        operation,
        deferred,
    )
}

fn emit_ref(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    check_ref_assignments(value, registry, operation, deferred)?;
    emit(ObjectRef::from_cbor(value)?)
}

fn check_bundle_item_assignments(
    value: &Cbor,
    rule: &str,
    item_type: u64,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, rule, registry, operation, deferred)?;
    check_enum(registry, "bundle-item-type", item_type, operation, deferred)
}

fn check_bundle_item_shape(
    rule: &str,
    fields: &[u16],
    item_type: u64,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_codes(fields, rule, registry, operation, deferred)?;
    check_enum(registry, "bundle-item-type", item_type, operation, deferred)
}

fn check_typed_digest(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, "typed-digest", registry, operation, deferred)?;
    check_assignment(
        registry,
        RegistryAssignment::HashAlgorithm(
            u16::try_from(uint(field(value, 0)?, ErrorCode::SchemaFieldInvalid)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        ),
        operation,
        deferred,
    )
}

fn check_identity_profiles(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, "identity-ref", registry, operation, deferred)?;
    check_profile(
        field(value, 0)?,
        &["identity"],
        registry,
        operation,
        deferred,
    )
}

fn check_policy_profiles(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, "policy-result", registry, operation, deferred)?;
    check_enum(
        registry,
        "policy-decision",
        uint(field(value, 2)?, ErrorCode::SchemaFieldInvalid)?,
        operation,
        deferred,
    )?;
    check_profile(field(value, 0)?, &["policy"], registry, operation, deferred)?;
    let profile = ProfileRef::from_cbor(field(value, 0)?)?;
    if profile.to_string() == "policy.test/allow@1"
        && uint(field(value, 2)?, ErrorCode::SchemaFieldInvalid)? != 1
    {
        return Err(Error::new(ErrorCode::ProfileStateForbidden)
            .with_stage(ValidationStage::RegistrySemantics));
    }
    Ok(())
}

fn analyze_entry_state(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    check_rule_fields(value, "entry-state", registry, operation, deferred)?;
    check_assignment(
        registry,
        RegistryAssignment::EntryKind(
            u16::try_from(uint(field(value, 1)?, ErrorCode::SchemaFieldInvalid)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        ),
        operation,
        deferred,
    )?;
    check_assignment(
        registry,
        RegistryAssignment::EntryMode(
            u16::try_from(uint(field(value, 3)?, ErrorCode::SchemaFieldInvalid)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        ),
        operation,
        deferred,
    )?;
    if let Some(target) = optional_field(value, 4) {
        emit_ref(target, registry, operation, deferred, emit)?;
    }
    check_profile(
        field(value, 6)?,
        CONTENT_FAMILIES,
        registry,
        operation,
        deferred,
    )
}

fn analyze_asset_group(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
) -> Result<()> {
    check_rule_fields(value, "asset-group", registry, operation, deferred)?;
    check_profile(
        field(value, 1)?,
        GROUP_FAMILIES,
        registry,
        operation,
        deferred,
    )?;
    for member in array(field(value, 3)?)? {
        check_rule_fields(member, "group-member", registry, operation, deferred)?;
        check_profile(
            field(member, 1)?,
            ROLE_FAMILIES,
            registry,
            operation,
            deferred,
        )?;
    }
    if let Some(keys) = optional_field(value, 4) {
        for key in array(keys)? {
            check_rule_fields(key, "external-key", registry, operation, deferred)?;
            check_profile(
                field(key, 0)?,
                EXTERNAL_FAMILIES,
                registry,
                operation,
                deferred,
            )?;
        }
    }
    Ok(())
}

fn analyze_operation(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    let operation_code = uint(field(value, 1)?, ErrorCode::SchemaFieldInvalid)?;
    check_enum(registry, "operation", operation_code, operation, deferred)?;
    let rule = match operation_code {
        1 => "create-operation",
        2 => "modify-operation",
        3 => "copy-operation",
        4 => "move-operation",
        5 => "rename-operation",
        6 => "delete-operation",
        7 => "restore-operation",
        8 => "group-create-operation",
        9 => "group-update-operation",
        10 => "group-delete-operation",
        11 => "merge-resolution-operation",
        _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    };
    check_rule_fields(value, rule, registry, operation, deferred)?;
    for key in [2, 3, 4] {
        if let Some(state) = optional_field(value, key) {
            analyze_entry_state(state, registry, operation, deferred, emit)?;
        }
    }
    if let Some(subject) = optional_field(value, 11) {
        let subject_kind = uint(field(value, 10)?, ErrorCode::SchemaFieldInvalid)?;
        check_enum(
            registry,
            "conflict-subject-kind",
            subject_kind,
            operation,
            deferred,
        )?;
        if subject_kind == 1 {
            analyze_entry_state(subject, registry, operation, deferred, emit)?;
        } else {
            analyze_asset_group(subject, registry, operation, deferred)?;
        }
    }
    if let Some(proof) = optional_field(value, 5) {
        check_rule_fields(proof, "allocation-proof", registry, operation, deferred)?;
        check_enum(
            registry,
            "allocation-kind",
            uint(field(proof, 1)?, ErrorCode::SchemaFieldInvalid)?,
            operation,
            deferred,
        )?;
        emit_ref(field(proof, 0)?, registry, operation, deferred, emit)?;
    }
    if let Some(proof) = optional_field(value, 6) {
        check_rule_fields(proof, "restore-proof", registry, operation, deferred)?;
        for key in [0, 1, 3] {
            emit_ref(field(proof, key)?, registry, operation, deferred, emit)?;
        }
    }
    for key in [7, 8] {
        if let Some(group) = optional_field(value, key) {
            analyze_asset_group(group, registry, operation, deferred)?;
        }
    }
    Ok(())
}

fn analyze_conflict_side(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    let side_kind = uint(field(value, 0)?, ErrorCode::SchemaFieldInvalid)?;
    check_enum(
        registry,
        "conflict-side-kind",
        side_kind,
        operation,
        deferred,
    )?;
    check_rule_fields(
        value,
        if side_kind == 1 {
            "entry-conflict-side"
        } else {
            "group-conflict-side"
        },
        registry,
        operation,
        deferred,
    )?;
    match side_kind {
        1 => analyze_entry_state(field(value, 1)?, registry, operation, deferred, emit),
        2 => analyze_asset_group(field(value, 2)?, registry, operation, deferred),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn analyze_conflict_record(
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    check_rule_fields(value, "conflict-record", registry, operation, deferred)?;
    check_enum(
        registry,
        "conflict-kind",
        uint(field(value, 1)?, ErrorCode::SchemaFieldInvalid)?,
        operation,
        deferred,
    )?;
    let Cbor::Array(subject) = field(value, 2)? else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    let subject_kind = subject
        .first()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    check_enum(
        registry,
        "conflict-subject-kind",
        uint(subject_kind, ErrorCode::SchemaFieldInvalid)?,
        operation,
        deferred,
    )?;
    for key in [3, 4, 5] {
        if let Some(side) = optional_field(value, key) {
            analyze_conflict_side(side, registry, operation, deferred, emit)?;
        }
    }
    let resolution = field(value, 6)?;
    check_rule_fields(
        resolution,
        "conflict-resolution",
        registry,
        operation,
        deferred,
    )?;
    let resolution_state = uint(field(resolution, 0)?, ErrorCode::SchemaFieldInvalid)?;
    check_enum(
        registry,
        "conflict-resolution-state",
        resolution_state,
        operation,
        deferred,
    )?;
    if resolution_state == 1 {
        let choice = uint(field(resolution, 1)?, ErrorCode::SchemaFieldInvalid)?;
        check_enum(
            registry,
            "conflict-resolution-choice",
            choice,
            operation,
            deferred,
        )?;
        if let Some(side) = optional_field(resolution, 2) {
            analyze_conflict_side(side, registry, operation, deferred, emit)?;
        }
        if choice == 5 {
            check_profile(
                field(resolution, 3)?,
                &["conflict-driver"],
                registry,
                operation,
                deferred,
            )?;
        }
    }
    Ok(())
}

fn analyze_object(
    kind: ObjectKind,
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    check_object_envelope_assignments(kind, value, registry, operation, deferred)?;
    check_features(value, registry, operation, deferred)?;
    match kind {
        ObjectKind::Chunk => {}
        ObjectKind::ContentManifest => {
            check_typed_digest(field(value, 17)?, registry, operation, deferred)?;
            check_profile(
                field(value, 18)?,
                &["chunking"],
                registry,
                operation,
                deferred,
            )?;
            for part in array(field(value, 19)?)? {
                check_rule_fields(part, "chunk-part", registry, operation, deferred)?;
                emit_ref(field(part, 0)?, registry, operation, deferred, emit)?;
            }
        }
        ObjectKind::Tree => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            for entry in array(field(value, 17)?)? {
                check_rule_fields(entry, "tree-entry", registry, operation, deferred)?;
                check_assignment(
                    registry,
                    RegistryAssignment::EntryKind(
                        u16::try_from(uint(field(entry, 1)?, ErrorCode::SchemaFieldInvalid)?)
                            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
                    ),
                    operation,
                    deferred,
                )?;
                check_assignment(
                    registry,
                    RegistryAssignment::EntryMode(
                        u16::try_from(uint(field(entry, 3)?, ErrorCode::SchemaFieldInvalid)?)
                            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
                    ),
                    operation,
                    deferred,
                )?;
                emit_ref(field(entry, 4)?, registry, operation, deferred, emit)?;
                check_profile(
                    field(entry, 6)?,
                    CONTENT_FAMILIES,
                    registry,
                    operation,
                    deferred,
                )?;
            }
        }
        ObjectKind::ChangeSet => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            if let Some(base) = optional_field(value, 17) {
                emit_ref(base, registry, operation, deferred, emit)?;
            }
            for item in array(field(value, 18)?)? {
                analyze_operation(item, registry, operation, deferred, emit)?;
            }
        }
        ObjectKind::AssetGroupSet => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            for group in array(field(value, 17)?)? {
                analyze_asset_group(group, registry, operation, deferred)?;
            }
        }
        ObjectKind::RepositoryDescriptor => {
            check_profile(field(value, 17)?, &["path"], registry, operation, deferred)?;
            for profile in array(field(value, 18)?)? {
                check_profile(profile, CONTENT_FAMILIES, registry, operation, deferred)?;
            }
            for profile in array(field(value, 19)?)? {
                check_profile(profile, GROUP_FAMILIES, registry, operation, deferred)?;
            }
            if let Some(profiles) = optional_field(value, 20) {
                for profile in array(profiles)? {
                    check_profile(profile, &["chunking"], registry, operation, deferred)?;
                }
            }
        }
        ObjectKind::Snapshot => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            for parent in array(field(value, 17)?)? {
                emit_ref(parent, registry, operation, deferred, emit)?;
            }
            emit_ref(field(value, 18)?, registry, operation, deferred, emit)?;
            emit_ref(field(value, 19)?, registry, operation, deferred, emit)?;
            if let Some(group) = optional_field(value, 20) {
                emit_ref(group, registry, operation, deferred, emit)?;
            }
            check_identity_profiles(field(value, 21)?, registry, operation, deferred)?;
            check_identity_profiles(field(value, 22)?, registry, operation, deferred)?;
            check_policy_profiles(field(value, 26)?, registry, operation, deferred)?;
            if let Some(provenance) = optional_field(value, 27) {
                for reference in array(provenance)? {
                    emit_ref(reference, registry, operation, deferred, emit)?;
                }
            }
            if let Some(conflict) = optional_field(value, 28) {
                emit_ref(conflict, registry, operation, deferred, emit)?;
            }
        }
        ObjectKind::ShelfRevision => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            if let Some(previous) = optional_field(value, 19) {
                emit_ref(previous, registry, operation, deferred, emit)?;
            }
            for key in [20, 21, 22, 23, 24] {
                if let Some(reference) = optional_field(value, key) {
                    emit_ref(reference, registry, operation, deferred, emit)?;
                }
            }
            check_identity_profiles(field(value, 25)?, registry, operation, deferred)?;
            check_policy_profiles(field(value, 28)?, registry, operation, deferred)?;
            if let Some(provenance) = optional_field(value, 29) {
                for reference in array(provenance)? {
                    emit_ref(reference, registry, operation, deferred, emit)?;
                }
            }
        }
        ObjectKind::Provenance => {
            check_profile(
                field(value, 16)?,
                &["provenance"],
                registry,
                operation,
                deferred,
            )?;
            for reference in array(field(value, 17)?)? {
                emit_ref(reference, registry, operation, deferred, emit)?;
            }
        }
        ObjectKind::Attestation => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            check_profile(
                field(value, 17)?,
                &["attestation-predicate"],
                registry,
                operation,
                deferred,
            )?;
            check_identity_profiles(field(value, 18)?, registry, operation, deferred)?;
            if let Some(signature) = optional_field(value, 21) {
                check_profile(signature, &["signature"], registry, operation, deferred)?;
            }
        }
        ObjectKind::ConflictSet => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            for record in array(field(value, 17)?)? {
                analyze_conflict_record(record, registry, operation, deferred, emit)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn visit_validated_object_references(
    kind: ObjectKind,
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    let mut deferred = DeferredSemanticError::new();
    analyze_object(kind, value, registry, operation, &mut deferred, emit)?;
    deferred.finish()
}

fn analyze_logical_record(
    record_type: u16,
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
    deferred: &mut DeferredSemanticError,
    emit: &mut dyn FnMut(ObjectRef) -> Result<()>,
) -> Result<()> {
    check_assignment(
        registry,
        RegistryAssignment::LogicalRecordType(record_type),
        operation,
        deferred,
    )?;
    check_rule_fields(
        value,
        logical_rule(record_type)?,
        registry,
        operation,
        deferred,
    )?;
    if record_type <= 7 {
        emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
    }
    match record_type {
        1 => emit_ref(field(value, 17)?, registry, operation, deferred, emit)?,
        2 => {
            check_enum(
                registry,
                "ref-kind",
                uint(field(value, 17)?, ErrorCode::SchemaFieldInvalid)?,
                operation,
                deferred,
            )?;
            emit_ref(field(value, 19)?, registry, operation, deferred, emit)?;
        }
        3 => emit_ref(field(value, 18)?, registry, operation, deferred, emit)?,
        4 => {
            check_enum(
                registry,
                "lifetime-origin",
                uint(field(value, 18)?, ErrorCode::SchemaFieldInvalid)?,
                operation,
                deferred,
            )?;
            emit_ref(field(value, 19)?, registry, operation, deferred, emit)?;
        }
        5 => check_profile(
            field(value, 17)?,
            &["importer"],
            registry,
            operation,
            deferred,
        )
        .and_then(|()| {
            check_enum(
                registry,
                "import-state",
                uint(field(value, 21)?, ErrorCode::SchemaFieldInvalid)?,
                operation,
                deferred,
            )
        })?,
        6 => {
            emit_ref(field(value, 18)?, registry, operation, deferred, emit)?;
            emit_ref(field(value, 19)?, registry, operation, deferred, emit)?;
            if let Some(conflicts) = optional_field(value, 20) {
                emit_ref(conflicts, registry, operation, deferred, emit)?;
            }
        }
        7 => {
            check_enum(
                registry,
                "lock-target-kind",
                uint(field(value, 17)?, ErrorCode::SchemaFieldInvalid)?,
                operation,
                deferred,
            )?;
            emit_ref(field(value, 19)?, registry, operation, deferred, emit)?;
        }
        8 => {
            emit_ref(field(value, 16)?, registry, operation, deferred, emit)?;
            check_profile(
                field(value, 17)?,
                &["annotation-payload"],
                registry,
                operation,
                deferred,
            )?;
        }
        9 => check_profile(
            field(value, 18)?,
            &["fixture-event"],
            registry,
            operation,
            deferred,
        )?,
        _ => return Err(Error::new(ErrorCode::LogicalRecordTypeUnsupported)),
    }
    Ok(())
}

pub(crate) fn validate_bundle_object_for_write(
    kind: ObjectKind,
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
) -> Result<u64> {
    let mut edges = 0u64;
    let mut emit = |_reference: ObjectRef| {
        edges = edges
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
        Ok(())
    };
    visit_validated_object_references(kind, value, registry, operation, &mut emit)?;
    Ok(edges)
}

pub(crate) fn validate_bundle_logical_record_for_write(
    record_type: u16,
    value: &Cbor,
    registry: &Registry,
    operation: Operation,
) -> Result<u64> {
    let mut deferred = DeferredSemanticError::new();
    let mut edges = 0u64;
    let mut emit = |_reference: ObjectRef| {
        edges = edges
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
        Ok(())
    };
    analyze_logical_record(
        record_type,
        value,
        registry,
        operation,
        &mut deferred,
        &mut emit,
    )?;
    deferred.finish()?;
    Ok(edges)
}

#[allow(clippy::too_many_lines)]
fn verify_spooled<R: Read>(
    reader: R,
    registry: &Registry,
    operation: Operation,
    budget: &Budget,
    workspace: &ScratchWorkspace,
) -> Result<LogicalBundleVerifySummary> {
    let mut sequence = workspace.create("sequence")?;
    let mut offsets = workspace.create("item-offsets")?;
    let (framed, largest_item) = {
        let mut visitor = SpoolVisitor {
            sequence: &mut sequence,
            offsets: &mut offsets,
            budget,
            total: 0,
            largest_item: 0,
            saw_trailer: false,
        };
        let scan = crate::bundle_stream::visit_logical_bundle_deferred_object_refs(
            reader,
            &mut visitor,
            BundleLimits {
                max_value_bytes: scanner_value_bytes(&budget.limits),
                ..BundleLimits::HARD
            },
        );
        let framed = scan.map_err(|error| {
            if error.code == ErrorCode::SchemaFieldInvalid && visitor.saw_trailer {
                Error::at(ErrorCode::BundleSequenceInvalid, error.offset.unwrap_or(0))
            } else {
                error
            }
        })?;
        (framed, visitor.largest_item)
    };
    budget.check_time()?;
    let item_count =
        u64::try_from(framed.items).map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
    let sequence_bytes =
        u64::try_from(framed.bytes).map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))?;
    if item_count < 2 {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    bundle_limit("bundle-total-items", item_count, budget.limits.items)?;
    bundle_limit(
        "bundle-sequence-bytes",
        sequence_bytes,
        budget.limits.sequence_bytes,
    )?;
    bundle_limit(
        "bundle-largest-item-bytes",
        largest_item,
        budget.limits.item_bytes,
    )?;
    if offsets.size != item_count.saturating_mul(ITEM_OFFSET_BYTES as u64) {
        return Err(Error::new(ErrorCode::LimitScratch));
    }

    let header_item = read_item_offset(&mut offsets, 0)?;
    if header_item.item_type != 1 {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    let header = parse_header(
        &decode_item(&mut sequence, header_item, budget)?,
        &budget.limits,
    )?;
    let expected_items = header
        .object_count
        .checked_add(header.logical_count)
        .and_then(|value| value.checked_add(header.root_count))
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?;
    if expected_items != item_count {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid));
    }
    let object_start = 1u64;
    let logical_start = object_start + header.object_count;
    let root_start = logical_start + header.logical_count;
    let trailer_index = root_start + header.root_count;
    for index in 0..item_count {
        let actual = read_item_offset(&mut offsets, index)?.item_type;
        let expected = if index == 0 {
            1
        } else if index < logical_start {
            2
        } else if index < root_start {
            3
        } else if index < trailer_index {
            4
        } else {
            5
        };
        if actual != expected {
            return Err(Error::new(ErrorCode::BundleSequenceInvalid));
        }
    }

    // Establish complete sequence ordering before hashing any payload. A
    // later out-of-order item must not be hidden by an earlier identity error.
    let mut saw_duplicate_identity = false;
    let mut previous_object: Option<Vec<u8>> = None;
    for ordinal in 0..header.object_count {
        budget.check_time()?;
        let envelope = opaque_object_envelope(
            &mut sequence,
            read_item_offset(&mut offsets, object_start + ordinal)?,
        )?;
        if envelope.ordinal != ordinal {
            return Err(Error::new(ErrorCode::BundleSequenceInvalid));
        }
        // Ordering is established on opaque canonical ObjectRef bytes. Shape,
        // algorithm, and known-kind interpretation belong to later stages and
        // must not hide a later order reversal.
        let key = envelope.sort_key;
        if let Some(previous) = previous_object.as_ref() {
            match previous.cmp(&key) {
                Ordering::Equal => saw_duplicate_identity = true,
                Ordering::Greater => return Err(Error::new(ErrorCode::BundleSequenceInvalid)),
                Ordering::Less => {}
            }
        }
        previous_object = Some(key);
    }

    let mut previous_logical: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut known_schema_error = None;
    for ordinal in 0..header.logical_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, logical_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4], ErrorCode::BundleSequenceInvalid)?;
        if uint(values[0], ErrorCode::BundleSequenceInvalid)? != 1
            || uint(values[1], ErrorCode::BundleSequenceInvalid)? != 3
            || uint(values[2], ErrorCode::BundleSequenceInvalid)? != ordinal
        {
            return Err(Error::new(ErrorCode::BundleSequenceInvalid));
        }
        let type_key = optional_field(values[4], 1)
            .map(|value| opaque_sort_key(value, budget))
            .transpose()?
            .unwrap_or_default();
        let identity_key = opaque_sort_key(values[3], budget)?;
        let key = (type_key, identity_key);
        if let Some(previous) = previous_logical.as_ref() {
            match previous.cmp(&key) {
                Ordering::Equal => saw_duplicate_identity = true,
                Ordering::Greater => return Err(Error::new(ErrorCode::BundleSequenceInvalid)),
                Ordering::Less => {}
            }
        }
        previous_logical = Some(key);
    }

    let mut previous_root: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = None;
    let mut previous_root_identity: Option<(Vec<u8>, Vec<u8>)> = None;
    for ordinal in 0..header.root_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, root_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4, 5], ErrorCode::BundleSequenceInvalid)?;
        if uint(values[0], ErrorCode::BundleSequenceInvalid)? != 1
            || uint(values[1], ErrorCode::BundleSequenceInvalid)? != 4
            || uint(values[2], ErrorCode::BundleSequenceInvalid)? != ordinal
        {
            return Err(Error::new(ErrorCode::BundleSequenceInvalid));
        }
        let root_kind = opaque_sort_key(values[3], budget)?;
        let identity_bytes = opaque_sort_key(values[4], budget)?;
        let role_bytes = opaque_sort_key(values[5], budget)?;
        let sort_key = (root_kind.clone(), identity_bytes.clone(), role_bytes);
        if let Some(previous) = previous_root.as_ref() {
            match previous.cmp(&sort_key) {
                Ordering::Greater => return Err(Error::new(ErrorCode::BundleSequenceInvalid)),
                Ordering::Equal => saw_duplicate_identity = true,
                Ordering::Less => {}
            }
        }
        let identity_key = (root_kind, identity_bytes);
        if previous_root_identity
            .as_ref()
            .is_some_and(|previous| previous == &identity_key)
        {
            saw_duplicate_identity = true;
        }
        previous_root = Some(sort_key);
        previous_root_identity = Some(identity_key);
    }
    if saw_duplicate_identity {
        return Err(Error::new(ErrorCode::BundleDuplicateIdentity));
    }

    // Declared identities are the next layer-one stage. Object hashing uses
    // the numeric kind domain without requiring that the base schema already
    // knows the kind; unknown kinds are rejected only after authentication.
    for ordinal in 0..header.object_count {
        budget.check_time()?;
        let envelope = object_envelope(
            &mut sequence,
            read_item_offset(&mut offsets, object_start + ordinal)?,
        )?;
        read_payload(&mut sequence, envelope, budget, true)?;
    }
    for ordinal in 0..header.logical_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, logical_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4], ErrorCode::BundleSequenceInvalid)?;
        let record_bytes = decoded_record_bytes(values[4], budget)?;
        let identity = typed_digest(values[3]).map_err(|error| {
            error
                .with_layer(1)
                .with_stage(ValidationStage::CanonicalFraming)
        })?;
        let record_type = field(values[4], 1)
            .and_then(|value| uint(value, ErrorCode::LogicalRecordTypeUnsupported))
            .and_then(|value| {
                u16::try_from(value)
                    .ok()
                    .filter(|value| *value != 0)
                    .ok_or_else(|| Error::new(ErrorCode::LogicalRecordTypeUnsupported))
            });
        let record_type = match record_type {
            Ok(record_type) => record_type,
            Err(error) => {
                observe_known_schema_error(&mut known_schema_error, error)?;
                continue;
            }
        };
        if opaque_logical_record_id(record_type, &record_bytes)? != identity {
            return Err(Error::new(ErrorCode::BundleRecordIdMismatch));
        }
    }

    let trailer_offset = read_item_offset(&mut offsets, trailer_index)?;
    let transcript_digest = transcript(&mut sequence, trailer_offset.offset, budget)?;
    let trailer_value = decode_item(&mut sequence, trailer_offset, budget)?;
    parse_trailer(&trailer_value, header, item_count, transcript_digest)?;

    let index_entries = header
        .object_count
        .checked_add(header.logical_count)
        .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
    bundle_limit(
        "bundle-index-entries",
        index_entries,
        budget.limits.index_entries,
    )?;
    // These authenticated layer-one measurements are safely known before any
    // layer-two closure decision and therefore cannot be deferred behind it.
    if sequence_bytes > header.declared_bytes
        || largest_item > header.declared_largest
        || index_entries > header.declared_index
    {
        return Err(Error::new(ErrorCode::BundleBudgetExceeded)
            .with_stage(ValidationStage::DeclaredAccounting));
    }

    // Complete one bounded known-schema pass over every authenticated object,
    // logical record, and root before traversal. The selected failure follows
    // the frozen catalogue, never bundle offset or ObjectRef sort order.
    for ordinal in 0..header.object_count {
        budget.check_time()?;
        let envelope = object_envelope(
            &mut sequence,
            read_item_offset(&mut offsets, object_start + ordinal)?,
        )?;
        let expected_kind = match envelope.reference() {
            Ok(reference) => reference.kind,
            Err(error) => {
                observe_known_schema_error(&mut known_schema_error, error)?;
                // Unknown numeric kinds remain opaque after layer-one hash
                // verification; their payload has no locally known schema.
                continue;
            }
        };
        if expected_kind == ObjectKind::Chunk {
            continue;
        }
        let scanned = match scan_object_payload(&mut sequence, envelope, budget) {
            Ok(scanned) => scanned,
            Err(error) => {
                observe_known_schema_error(&mut known_schema_error, error)?;
                continue;
            }
        };
        match validate_metadata_schema(&scanned) {
            Ok(actual_kind) => {
                if expected_kind != actual_kind {
                    observe_known_schema_error(
                        &mut known_schema_error,
                        Error::new(ErrorCode::ObjectReferenceKindMismatch)
                            .with_stage(ValidationStage::KnownSchema),
                    )?;
                }
            }
            Err(error) => observe_known_schema_error(&mut known_schema_error, error)?,
        }
    }
    for ordinal in 0..header.logical_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, logical_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4], ErrorCode::BundleSequenceInvalid)?;
        let record_bytes = decoded_record_bytes(values[4], budget)?;
        if let Err(error) = validate_logical_record(
            &record_bytes,
            Limits {
                max_input_bytes: record_bytes.len(),
                ..Limits::METADATA
            },
        ) {
            observe_known_schema_error(&mut known_schema_error, error)?;
        }
    }
    for ordinal in 0..header.root_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, root_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4, 5], ErrorCode::BundleSequenceInvalid)?;
        match uint(values[3], ErrorCode::BundleRootInvalid) {
            Ok(1) => {
                if let Err(error) = bundle_envelope_object_ref(values[4]) {
                    observe_known_schema_error(&mut known_schema_error, error)?;
                }
            }
            Ok(2) => {
                if let Err(error) = TypedDigest::from_cbor(values[4]) {
                    observe_known_schema_error(&mut known_schema_error, error)?;
                }
            }
            Ok(_) | Err(_) => observe_known_schema_error(
                &mut known_schema_error,
                Error::new(ErrorCode::BundleRootInvalid).with_stage(ValidationStage::KnownSchema),
            )?,
        }
        if let Err(error) = ProfileRef::from_cbor(values[5]) {
            observe_known_schema_error(&mut known_schema_error, error)?;
        }
    }
    if let Some(error) = known_schema_error {
        return Err(error);
    }

    // Known schema, root/profile semantics, and closure begin only after the
    // complete layer-one sequence has authenticated.
    let mut deferred = DeferredSemanticError::new();
    let semantic_header = decode_item(&mut sequence, header_item, budget)?;
    check_bundle_item_assignments(
        &semantic_header,
        "bundle-header",
        1,
        registry,
        operation,
        &mut deferred,
    )?;
    check_enum(
        registry,
        "bundle-mode",
        uint(
            field(&semantic_header, 2)?,
            ErrorCode::BundleModeUnsupported,
        )?,
        operation,
        &mut deferred,
    )?;
    check_rule_fields(
        field(&semantic_header, 6)?,
        "bundle-budget",
        registry,
        operation,
        &mut deferred,
    )?;
    check_bundle_item_assignments(
        &trailer_value,
        "bundle-trailer",
        5,
        registry,
        operation,
        &mut deferred,
    )?;
    let mut object_sorter = FixedSorter::<OBJECT_INDEX_BYTES, 34>::new(
        workspace,
        budget.limits.max_run_bytes,
        budget.limits.max_open_runs,
    )?;
    for ordinal in 0..header.object_count {
        let envelope = object_envelope(
            &mut sequence,
            read_item_offset(&mut offsets, object_start + ordinal)?,
        )?;
        check_bundle_item_shape(
            "bundle-object",
            &[0, 1, 2, 3, 4],
            2,
            registry,
            operation,
            &mut deferred,
        )?;
        check_rule_codes(
            &[0, 1, 2, 3],
            "object-ref",
            registry,
            operation,
            &mut deferred,
        )?;
        let reference = envelope.reference()?;
        check_assignment(
            registry,
            RegistryAssignment::ObjectKind(reference.kind.code()),
            operation,
            &mut deferred,
        )?;
        check_assignment(
            registry,
            RegistryAssignment::HashAlgorithm(1),
            operation,
            &mut deferred,
        )?;
        object_sorter.add(object_index_record(reference, ordinal), budget)?;
    }
    let mut object_index = object_sorter.finish(budget)?;

    let mut logical_sorter = FixedSorter::<LOGICAL_INDEX_BYTES, 32>::new(
        workspace,
        budget.limits.max_run_bytes,
        budget.limits.max_open_runs,
    )?;
    for ordinal in 0..header.logical_count {
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, logical_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4], ErrorCode::BundleSequenceInvalid)?;
        check_bundle_item_assignments(
            &item,
            "bundle-logical-record",
            3,
            registry,
            operation,
            &mut deferred,
        )?;
        check_typed_digest(values[3], registry, operation, &mut deferred)?;
        logical_sorter.add(
            logical_index_record(typed_digest(values[3])?, ordinal),
            budget,
        )?;
    }

    let mut queue = workspace.create("closure-queue")?;
    let mut logical_roots = workspace.create("logical-roots")?;
    let mut object_roots = 0u64;
    let mut logical_root_count = 0u64;
    for ordinal in 0..header.root_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, root_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4, 5], ErrorCode::BundleSequenceInvalid)?;
        check_bundle_item_assignments(&item, "bundle-root", 4, registry, operation, &mut deferred)?;
        let root_kind = uint(values[3], ErrorCode::BundleRootInvalid)?;
        check_enum(
            registry,
            "bundle-root-kind",
            root_kind,
            operation,
            &mut deferred,
        )?;
        check_profile(
            values[5],
            &["bundle-root-role"],
            registry,
            operation,
            &mut deferred,
        )?;
        match root_kind {
            1 => {
                let reference = bundle_envelope_object_ref(values[4])?;
                check_ref_assignments(values[4], registry, operation, &mut deferred)?;
                queue.append(&ref_bytes(reference))?;
                object_roots += 1;
            }
            2 => {
                check_typed_digest(values[4], registry, operation, &mut deferred)?;
                logical_roots.append(&typed_digest(values[4])?)?;
                logical_root_count += 1;
            }
            _ => {
                return Err(Error::new(ErrorCode::BundleRootInvalid)
                    .with_stage(ValidationStage::KnownSchema));
            }
        }
    }

    let mut logical_index = logical_sorter.finish(budget)?;
    let mut previous_logical_identity: Option<[u8; 32]> = None;
    for index in 0..logical_index.count {
        let record = logical_index.record(index)?;
        let identity: [u8; 32] = record[..32].try_into().expect("fixed logical digest");
        if previous_logical_identity == Some(identity) {
            return Err(Error::new(ErrorCode::BundleDuplicateIdentity));
        }
        previous_logical_identity = Some(identity);
    }

    if header.object_count != 0 && object_roots == 0 {
        return Err(Error::new(ErrorCode::BundleRootInvalid)
            .with_layer(2)
            .with_stage(ValidationStage::ClosureAndReferenceResolution));
    }
    if logical_root_count != header.logical_count {
        return Err(Error::new(ErrorCode::BundleRootInvalid)
            .with_layer(2)
            .with_stage(ValidationStage::ClosureAndReferenceResolution));
    }
    for ordinal in 0..logical_root_count {
        let mut root = [0u8; 32];
        logical_roots.read_exact_at(ordinal * 32, &mut root)?;
        let record = logical_index.record(ordinal)?;
        if root != record[..32] {
            return Err(Error::new(ErrorCode::BundleRootInvalid)
                .with_layer(2)
                .with_stage(ValidationStage::ClosureAndReferenceResolution));
        }
    }

    let mut edges = workspace.create("object-edges")?;
    let mut edge_ranges = workspace.create("edge-ranges")?;
    let mut traversal_edges = 0u64;
    for ordinal in 0..header.object_count {
        budget.check_time()?;
        let envelope = object_envelope(
            &mut sequence,
            read_item_offset(&mut offsets, object_start + ordinal)?,
        )?;
        let reference = envelope.reference()?;
        let edge_start = edges.size / REF_BYTES as u64;
        if reference.kind != ObjectKind::Chunk {
            let scanned = scan_object_payload(&mut sequence, envelope, budget)?;
            let actual_kind = validate_metadata_schema(&scanned)?;
            if actual_kind != reference.kind {
                return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
                    .with_stage(ValidationStage::KnownSchema));
            }
            let mut emit = |child: ObjectRef| {
                traversal_edges = traversal_edges
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
                bundle_limit(
                    "bundle-traversal-edges",
                    traversal_edges,
                    budget.limits.traversal_edges,
                )?;
                edges.append(&ref_bytes(child))
            };
            analyze_object(
                reference.kind,
                scanned.value(),
                registry,
                operation,
                &mut deferred,
                &mut emit,
            )?;
        }
        let edge_count = edges.size / REF_BYTES as u64 - edge_start;
        let mut range = [0u8; EDGE_RANGE_BYTES];
        range[..8].copy_from_slice(&edge_start.to_be_bytes());
        range[8..].copy_from_slice(&edge_count.to_be_bytes());
        edge_ranges.append(&range)?;
    }

    for ordinal in 0..header.logical_count {
        budget.check_time()?;
        let item = decode_item(
            &mut sequence,
            read_item_offset(&mut offsets, logical_start + ordinal)?,
            budget,
        )?;
        let values = map_fields(&item, &[0, 1, 2, 3, 4], ErrorCode::BundleSequenceInvalid)?;
        let record_bytes = decoded_record_bytes(values[4], budget)?;
        let record_type = validate_logical_record(
            &record_bytes,
            Limits {
                max_input_bytes: record_bytes.len(),
                ..Limits::METADATA
            },
        )?;
        let mut emit = |child: ObjectRef| {
            traversal_edges = traversal_edges
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
            bundle_limit(
                "bundle-traversal-edges",
                traversal_edges,
                budget.limits.traversal_edges,
            )?;
            queue.append(&ref_bytes(child))
        };
        analyze_logical_record(
            record_type,
            values[4],
            registry,
            operation,
            &mut deferred,
            &mut emit,
        )?;
    }

    bundle_limit(
        "bundle-traversal-edges",
        traversal_edges,
        budget.limits.traversal_edges,
    )?;
    if traversal_edges > header.declared_edges {
        return Err(Error::new(ErrorCode::BundleBudgetExceeded)
            .with_stage(ValidationStage::DeclaredAccounting));
    }
    verify_closure(
        &mut object_index,
        &mut edge_ranges,
        &mut edges,
        &mut queue,
        header.object_count,
        budget,
        workspace,
    )?;
    deferred.finish()?;

    Ok(LogicalBundleVerifySummary {
        highest_layer: 2,
        bytes: sequence_bytes,
        items: item_count,
        object_count: header.object_count,
        logical_record_count: header.logical_count,
        root_count: header.root_count,
        traversal_edges,
        index_entries,
        transcript_digest,
        elapsed: budget.started.elapsed(),
        scratch: workspace.metrics(),
    })
}

fn verify_closure(
    object_index: &mut SortedIndex<OBJECT_INDEX_BYTES, 34>,
    edge_ranges: &mut ScratchFile,
    edges: &mut ScratchFile,
    queue: &mut ScratchFile,
    object_count: u64,
    budget: &Budget,
    workspace: &ScratchWorkspace,
) -> Result<()> {
    let mut reached = workspace.create("reached")?;
    reached.allocate_zeroed(object_count.div_ceil(8), budget.limits.read_chunk_bytes)?;
    let mut reached_count = 0u64;
    let mut queue_cursor = 0u64;
    while queue_cursor < queue.size {
        budget.check_time()?;
        let mut raw = [0u8; REF_BYTES];
        queue.read_exact_at(queue_cursor, &mut raw)?;
        queue_cursor += REF_BYTES as u64;
        let reference = ref_from_bytes(&raw)?;
        let key = object_index_key(reference);
        let Some(record) = object_index.find(&key)? else {
            let mut digest_start = [0u8; 34];
            digest_start[..32].copy_from_slice(&reference.digest);
            let candidate = object_index.lower_bound(&digest_start)?;
            if candidate < object_index.count
                && object_index.record(candidate)?[..32] == reference.digest
            {
                return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
                    .with_stage(ValidationStage::ClosureAndReferenceResolution));
            }
            return Err(Error::new(ErrorCode::BundleClosureMissing));
        };
        let ordinal = u64::from_be_bytes(record[34..42].try_into().expect("fixed ordinal"));
        let byte_offset = ordinal / 8;
        let mask = 1u8 << (ordinal % 8);
        let mut byte = [0u8; 1];
        reached.read_exact_at(byte_offset, &mut byte)?;
        if byte[0] & mask != 0 {
            continue;
        }
        byte[0] |= mask;
        reached.write_exact_at(byte_offset, &byte)?;
        reached_count += 1;

        let mut range = [0u8; EDGE_RANGE_BYTES];
        edge_ranges.read_exact_at(ordinal * EDGE_RANGE_BYTES as u64, &mut range)?;
        let start = u64::from_be_bytes(range[..8].try_into().expect("fixed edge start"));
        let count = u64::from_be_bytes(range[8..].try_into().expect("fixed edge count"));
        for edge in 0..count {
            let mut child = [0u8; REF_BYTES];
            edges.read_exact_at((start + edge) * REF_BYTES as u64, &mut child)?;
            queue.append(&child)?;
        }
    }
    if reached_count != object_count {
        return Err(Error::new(ErrorCode::BundleClosureExtra));
    }
    Ok(())
}
