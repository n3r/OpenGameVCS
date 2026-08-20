use std::{
    cell::RefCell,
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use unicode_normalization::is_nfc;

use crate::registry::require_write_operation;
use crate::{
    file_identity::FileIdentity,
    hard_limits::{
        enforce_hard_limit_context, MAX_CHUNK_BYTES, MAX_LOGICAL_FILE_BYTES, MAX_METADATA_BYTES,
        MAX_PATH_SEGMENT_BYTES, MAX_TREE_ENTRIES,
    },
    sha256,
    unicode_age::is_unicode_15,
    Error, ErrorCode, ObjectHashWriter, ObjectKind, ObjectRef, Operation, ProfileRef, Registry,
    RegistryAssignment, Result, Sha256Writer, ValidationStage,
};
const RUN_MAGIC: &[u8; 12] = b"OGVCS-RUN\0\x01\0";
const ID_RUN_MAGIC: &[u8; 12] = b"OGVCS-FID\0\x01\0";
const MAX_PRIVATE_ENTRY_BYTES: usize = 2_048;
// Conservative retained charge for one FileID plus the BTree node, allocator
// metadata, and balancing links used by the built-in transactional adapter.
const FILE_ID_INDEX_NODE_BYTES: usize = 64;
const TREE_STREAM_FIXED_MEMORY_BYTES: usize = 16 * 1024;

fn tree_stream_live_memory_bytes(limits: &TreeStreamLimits) -> Result<usize> {
    // A raw verifier/ordered writer simultaneously retains the reader/hash
    // workspace, the preceding basename, the current basename, and one
    // prepared entry while its FileID is staged in the external index.
    TREE_STREAM_FIXED_MEMORY_BYTES
        .checked_add(limits.max_path_segment_bytes.saturating_mul(2))
        .and_then(|bytes| bytes.checked_add(MAX_PRIVATE_ENTRY_BYTES))
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// A complete format-v1 `TreeEntry`. Raw numeric fields are intentional: the
/// streaming boundary validates them before writing trusted output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeStreamEntry {
    pub basename: String,
    pub entry_kind: u8,
    pub file_id: [u8; 16],
    pub portable_mode: u8,
    pub target: ObjectRef,
    pub logical_size: u64,
    pub content_policy: ProfileRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeStreamLimits {
    pub max_entries: u64,
    pub max_output_bytes: u64,
    pub max_logical_bytes: u64,
    pub max_path_segment_bytes: usize,
    /// Deterministic memory-accounting ceiling for retained sort records. The
    /// caller-owned iterator and caller-owned output writer are outside it.
    pub max_memory_bytes: usize,
    pub max_scratch_bytes: u64,
    pub max_elapsed: Option<Duration>,
}

impl Default for TreeStreamLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_TREE_ENTRIES,
            max_output_bytes: MAX_METADATA_BYTES,
            max_logical_bytes: MAX_LOGICAL_FILE_BYTES,
            max_path_segment_bytes: MAX_PATH_SEGMENT_BYTES as usize,
            max_memory_bytes: 64 * 1024 * 1024,
            max_scratch_bytes: 1_073_741_824,
            max_elapsed: None,
        }
    }
}

impl TreeStreamLimits {
    fn constrained(self) -> Self {
        Self {
            max_entries: self.max_entries.min(MAX_TREE_ENTRIES),
            max_output_bytes: self.max_output_bytes.min(MAX_METADATA_BYTES),
            max_logical_bytes: self.max_logical_bytes.min(MAX_LOGICAL_FILE_BYTES),
            max_path_segment_bytes: self
                .max_path_segment_bytes
                .min(MAX_PATH_SEGMENT_BYTES as usize),
            ..self
        }
    }
}

/// Contains counts and identities only; it never contains names, FileIDs, or
/// profile values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeStreamSummary {
    pub object_ref: ObjectRef,
    pub entries: u64,
    pub payload_bytes: u64,
    pub directories: u64,
    pub nondirectories: u64,
    pub logical_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TreeScratchMetrics {
    pub peak_bytes: u64,
    pub bytes_written: u64,
    pub files_created: u64,
    pub merge_passes: u32,
}

/// One atomic FileID-index attempt. `finish` proves uniqueness without
/// publishing caller-visible state; `commit` publishes only after every lower
/// validation layer and ranked lifecycle decision has succeeded. Dropping or
/// aborting a transaction leaves the underlying index unchanged.
pub trait TreeFileIdTransaction {
    fn insert(&mut self, file_id: [u8; 16]) -> Result<()>;
    fn finish(&mut self) -> Result<()>;
    fn commit(self: Box<Self>) -> Result<()>;
    fn abort(self: Box<Self>);
}

/// Exact transactional uniqueness service used by tree readers and writers.
/// Implementations must retain or externally sort every observed value until
/// commit; probabilistic filters do not satisfy this contract.
pub trait TreeFileIdIndex {
    fn begin(
        &mut self,
        maximum_items: u64,
        max_memory_bytes: usize,
    ) -> Result<Box<dyn TreeFileIdTransaction + '_>>;
}

impl TreeFileIdIndex for BTreeSet<[u8; 16]> {
    fn begin(
        &mut self,
        maximum_items: u64,
        max_memory_bytes: usize,
    ) -> Result<Box<dyn TreeFileIdTransaction + '_>> {
        Ok(Box::new(SetFileIdTransaction {
            target: self,
            pending: BTreeSet::new(),
            duplicate: false,
            maximum_items,
            max_memory_bytes,
        }))
    }
}

struct SetFileIdTransaction<'a> {
    target: &'a mut BTreeSet<[u8; 16]>,
    pending: BTreeSet<[u8; 16]>,
    duplicate: bool,
    maximum_items: u64,
    max_memory_bytes: usize,
}

impl TreeFileIdTransaction for SetFileIdTransaction<'_> {
    fn insert(&mut self, file_id: [u8; 16]) -> Result<()> {
        if self.pending.contains(&file_id) || self.target.contains(&file_id) {
            self.duplicate = true;
            return Ok(());
        }
        let next_count = self
            .pending
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        if u64::try_from(next_count).unwrap_or(u64::MAX) > self.maximum_items
            || next_count
                .checked_mul(FILE_ID_INDEX_NODE_BYTES)
                .is_none_or(|bytes| bytes > self.max_memory_bytes)
        {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        self.pending.insert(file_id);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if self.duplicate
            || self
                .pending
                .iter()
                .any(|file_id| self.target.contains(file_id))
        {
            Err(Error::new(ErrorCode::FileIdDuplicateInTree))
        } else {
            Ok(())
        }
    }

    fn commit(mut self: Box<Self>) -> Result<()> {
        self.finish()?;
        self.target.append(&mut self.pending);
        Ok(())
    }

    fn abort(self: Box<Self>) {
        drop(self);
    }
}

/// Exact bounded-memory FileID index backed by deterministic external merge
/// sort in an exclusive scratch subdirectory.
pub struct TreeFileIdScratchIndex {
    workspace: ScratchWorkspace,
    buffered: Vec<[u8; 16]>,
    runs: Vec<RunFile>,
    maximum_buffered: usize,
    configured_maximum_buffered: usize,
    started: Instant,
    max_elapsed: Option<Duration>,
    finished: bool,
    duplicate: bool,
}

impl TreeFileIdScratchIndex {
    pub fn new(
        scratch_directory: &Path,
        max_memory_bytes: usize,
        max_scratch_bytes: u64,
        max_elapsed: Option<Duration>,
    ) -> Result<Self> {
        let maximum_buffered = max_memory_bytes / std::mem::size_of::<[u8; 16]>();
        if maximum_buffered == 0 {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok(Self {
            workspace: ScratchWorkspace::new(scratch_directory, max_scratch_bytes)?,
            buffered: Vec::new(),
            runs: Vec::new(),
            maximum_buffered,
            configured_maximum_buffered: maximum_buffered,
            started: Instant::now(),
            max_elapsed,
            finished: false,
            duplicate: false,
        })
    }

    pub fn scratch_metrics(&self) -> TreeScratchMetrics {
        self.workspace.metrics
    }

    fn check_time(&self) -> Result<()> {
        if self
            .max_elapsed
            .is_some_and(|maximum| self.started.elapsed() >= maximum)
        {
            return Err(Error::new(ErrorCode::LimitTime));
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.buffered.is_empty() {
            self.buffered.sort_unstable();
            let before = self.buffered.len();
            self.buffered.dedup();
            self.duplicate |= self.buffered.len() != before;
            self.runs
                .push(self.workspace.write_id_run(&mut self.buffered)?);
        }
        Ok(())
    }

    fn abort_attempt(&mut self) {
        self.buffered.clear();
        self.buffered.shrink_to_fit();
        self.runs.clear();
        for path in std::mem::take(&mut self.workspace.files) {
            let _ = std::fs::remove_file(path);
        }
        self.workspace.live_bytes = 0;
        if self.workspace.directory_present {
            let _ = std::fs::remove_dir(&self.workspace.directory);
            self.workspace.directory_present = false;
        }
        self.finished = true;
        self.duplicate = false;
    }

    fn reset_attempt(&mut self, max_memory_bytes: usize) -> Result<()> {
        if self.workspace.directory_present {
            self.abort_attempt();
        }
        create_private_directory(&self.workspace.directory)?;
        self.workspace.directory_present = true;
        self.workspace.files.clear();
        self.workspace.live_bytes = 0;
        self.buffered.clear();
        self.runs.clear();
        self.duplicate = false;
        self.started = Instant::now();
        self.finished = false;
        self.maximum_buffered = self
            .configured_maximum_buffered
            .min(max_memory_bytes / std::mem::size_of::<[u8; 16]>());
        if self.maximum_buffered == 0 {
            self.abort_attempt();
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok(())
    }
}

impl TreeFileIdIndex for TreeFileIdScratchIndex {
    fn begin(
        &mut self,
        _maximum_items: u64,
        max_memory_bytes: usize,
    ) -> Result<Box<dyn TreeFileIdTransaction + '_>> {
        if self.finished {
            self.reset_attempt(max_memory_bytes)?;
        } else {
            self.maximum_buffered = self
                .configured_maximum_buffered
                .min(max_memory_bytes / std::mem::size_of::<[u8; 16]>());
            if self.maximum_buffered == 0 {
                return Err(Error::new(ErrorCode::LimitMemory));
            }
        }
        Ok(Box::new(ScratchFileIdTransaction {
            index: self,
            completed: false,
        }))
    }
}

struct ScratchFileIdTransaction<'a> {
    index: &'a mut TreeFileIdScratchIndex,
    completed: bool,
}

impl TreeFileIdTransaction for ScratchFileIdTransaction<'_> {
    fn insert(&mut self, file_id: [u8; 16]) -> Result<()> {
        if self.index.finished {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        self.index.check_time()?;
        if self.index.buffered.len() == self.index.maximum_buffered {
            self.index.flush()?;
        }
        self.index
            .buffered
            .try_reserve_exact(1)
            .map_err(|_| Error::new(ErrorCode::LimitMemory))?;
        self.index.buffered.push(file_id);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if self.index.finished {
            return Ok(());
        }
        self.index.flush()?;
        while self.index.runs.len() > 1 {
            self.index.check_time()?;
            self.index.workspace.metrics.merge_passes =
                self.index.workspace.metrics.merge_passes.saturating_add(1);
            let mut next = Vec::with_capacity(self.index.runs.len().div_ceil(2));
            let mut input = std::mem::take(&mut self.index.runs).into_iter();
            while let Some(left) = input.next() {
                if let Some(right) = input.next() {
                    next.push(self.index.workspace.merge_id_runs(left, right)?);
                } else {
                    next.push(left);
                }
            }
            self.index.runs = next;
        }
        if let Some(final_run) = self.index.runs.pop() {
            let reader = IdRunReader::open(&final_run)?;
            reader.finish()?;
            self.index.workspace.remove_run(&final_run)?;
        }
        self.index.workspace.close()?;
        self.index.finished = true;
        if self.index.duplicate {
            Err(Error::new(ErrorCode::FileIdDuplicateInTree))
        } else {
            Ok(())
        }
    }

    fn commit(mut self: Box<Self>) -> Result<()> {
        self.finish()?;
        self.completed = true;
        Ok(())
    }

    fn abort(mut self: Box<Self>) {
        self.index.abort_attempt();
        self.completed = true;
    }
}

impl Drop for ScratchFileIdTransaction<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.index.abort_attempt();
        }
    }
}

struct Budget {
    limits: TreeStreamLimits,
    started: Instant,
}

impl Budget {
    fn new(limits: TreeStreamLimits) -> Result<Self> {
        let result = Self {
            limits: limits.constrained(),
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
            return Err(Error::new(ErrorCode::LimitTime));
        }
        Ok(())
    }

    fn check_count(&self, count: u64) -> Result<()> {
        tree_limit(
            "tree-entries",
            count,
            self.limits.max_entries,
            ErrorCode::LimitCount,
            1,
        )
    }

    fn check_logical(&self, value: u64) -> Result<()> {
        tree_limit(
            "logical-file-bytes",
            value,
            self.limits.max_logical_bytes,
            ErrorCode::LimitLogicalBytes,
            2,
        )
    }

    fn check_basename(&self, bytes: usize) -> Result<()> {
        tree_limit(
            "path-segment-bytes",
            u64::try_from(bytes).unwrap_or(u64::MAX),
            u64::try_from(self.limits.max_path_segment_bytes).unwrap_or(u64::MAX),
            ErrorCode::PathCoreInvalid,
            2,
        )
    }
}

struct CanonicalSink<W> {
    writer: W,
    hash: ObjectHashWriter,
    written: u64,
    maximum: u64,
}

impl<W: Write> CanonicalSink<W> {
    fn new(writer: W, maximum: u64) -> Self {
        Self {
            writer,
            hash: ObjectHashWriter::new(
                ObjectKind::Tree,
                MAX_CHUNK_BYTES as usize,
                usize::try_from(maximum).unwrap_or(usize::MAX),
            ),
            written: 0,
            maximum,
        }
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let length =
            u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::LimitMetadataBytes))?;
        tree_limit(
            "metadata-payload-bytes",
            self.written.saturating_add(length),
            self.maximum,
            ErrorCode::LimitMetadataBytes,
            1,
        )?;
        self.writer
            .write_all(bytes)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        self.hash.update(bytes)?;
        self.written += length;
        Ok(())
    }

    fn head(&mut self, major: u8, value: u64) -> Result<()> {
        let (buffer, length) = cbor_head(major, value);
        self.bytes(&buffer[..length])
    }

    fn finish(self) -> Result<(ObjectRef, u64)> {
        Ok((self.hash.finish()?, self.written))
    }
}

#[derive(Clone, Debug)]
struct PreparedEntry {
    key: Vec<u8>,
    encoded: Vec<u8>,
    kind: u8,
    file_id: [u8; 16],
    logical_size: u64,
}

impl PreparedEntry {
    fn retained_cost(&self) -> usize {
        // Box/Vec allocator metadata and outer-vector spare capacity are
        // conservatively charged in addition to live byte buffers.
        self.key
            .len()
            .saturating_add(self.encoded.len())
            .saturating_add(128)
    }
}

/// Bounded raw-byte verifier for the canonical tree subset emitted by
/// [`encode_ordered_tree`]: no extensions and an empty required-feature array.
/// It validates and hashes bytes incrementally, retaining only the previous
/// basename and current entry. FileID uniqueness is delegated to the same exact
/// index contract used by the ordered encoder.
#[allow(clippy::too_many_arguments)]
pub fn verify_tree_stream<R: Read>(
    reader: R,
    expected_object: ObjectRef,
    repository_descriptor: ObjectRef,
    registry: &Registry,
    operation: Operation,
    file_ids: &mut dyn TreeFileIdIndex,
    limits: TreeStreamLimits,
) -> Result<TreeStreamSummary> {
    registry.require_complete_authority()?;
    let budget = Budget::new(limits)?;
    let live_memory = tree_stream_live_memory_bytes(&budget.limits)?;
    if budget.limits.max_memory_bytes < live_memory {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    if expected_object.kind != ObjectKind::Tree
        || repository_descriptor.kind != ObjectKind::RepositoryDescriptor
    {
        return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::KnownSchema));
    }
    let mut deferred_lifecycle = None;
    observe_deferred_lifecycle(
        &mut deferred_lifecycle,
        validate_tree_assignments(registry, operation),
    )?;
    let mut input = RawTreeReader::new(reader, &budget);
    input.exact_container(5, 5)?;
    input.exact_uint(0)?;
    input.exact_uint(1)?;
    input.exact_uint(1)?;
    input.exact_uint(3)?;
    input.exact_uint(2)?;
    let required_features = input.head(4)?;
    let mut previous_feature = 0u32;
    for _ in 0..required_features {
        budget.check_time()?;
        let feature =
            u32::try_from(input.head(0)?).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if feature == 0 || feature <= previous_feature {
            return Err(
                Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema)
            );
        }
        observe_deferred_lifecycle(
            &mut deferred_lifecycle,
            registry
                .check_assignment(RegistryAssignment::RequiredFeature(feature), operation)
                .map(|_| ()),
        )?;
        previous_feature = feature;
    }
    input.exact_uint(16)?;
    let actual_descriptor = input.object_ref()?;
    if actual_descriptor != repository_descriptor {
        observe_deferred_lifecycle(
            &mut deferred_lifecycle,
            Err(Error::new(ErrorCode::RepositoryDescriptorMismatch)),
        )?;
    }
    input.exact_uint(17)?;
    let entries = input.head(4)?;
    budget.check_count(entries)?;
    let index_memory = budget
        .limits
        .max_memory_bytes
        .checked_sub(live_memory)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    let mut file_id_transaction = file_ids.begin(entries, index_memory)?;

    let mut previous = Vec::new();
    let mut deferred_known_schema = None;
    let mut directories = 0u64;
    let mut nondirectories = 0u64;
    let mut logical_bytes = 0u64;
    for _ in 0..entries {
        budget.check_time()?;
        let entry_fields = input.head(5)?;
        if entry_fields < 7 {
            return Err(
                Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema)
            );
        }
        input.exact_uint(0)?;
        let basename = input.text(
            budget.limits.max_path_segment_bytes,
            ErrorCode::PathCoreInvalid,
        )?;
        budget.check_basename(basename.len())?;
        if basename.is_empty()
            || basename == "."
            || basename == ".."
            || basename.as_bytes().contains(&b'/')
            || basename.as_bytes().contains(&0)
        {
            observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::PathCoreInvalid),
            )?;
        }
        if !previous.is_empty() && previous.as_slice() >= basename.as_bytes() {
            observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::TreeEntryOrderInvalid),
            )?;
        }
        previous = basename.into_bytes();

        input.exact_uint(1)?;
        let kind = input.head(0)?;
        input.exact_uint(2)?;
        let file_id = input.fixed_bytes::<16>()?;
        if file_id == [0; 16] {
            observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::FileIdZero),
            )?;
        } else {
            file_id_transaction.insert(file_id)?;
        }
        input.exact_uint(3)?;
        let mode = input.head(0)?;
        input.exact_uint(4)?;
        let target = input.object_ref()?;
        input.exact_uint(5)?;
        let logical_size = input.head(0)?;
        input.exact_uint(6)?;
        let profile = input.profile()?;
        for _ in 7..entry_fields {
            input.head(0)?;
            input.skip_item(1)?;
            observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::SchemaFieldUnknown).with_stage(ValidationStage::KnownSchema),
            )?;
        }

        budget.check_logical(logical_size)?;
        if !(1..=4).contains(&kind) || mode != kind || (kind == 1 && logical_size != 0) {
            observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::TreeEntryTargetInvalid),
            )?;
        }
        let expected_target = if kind == 1 {
            ObjectKind::Tree
        } else {
            ObjectKind::ContentManifest
        };
        if target.kind != expected_target {
            observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::ObjectReferenceKindMismatch)
                    .with_stage(ValidationStage::KnownSchema),
            )?;
        }
        observe_deferred_lifecycle(
            &mut deferred_lifecycle,
            validate_tree_entry_assignments(kind, mode, target.kind, registry, operation),
        )?;
        observe_deferred_lifecycle(
            &mut deferred_lifecycle,
            validate_content_profile(&profile, registry, operation),
        )?;
        if kind == 1 {
            directories += 1;
        } else {
            nondirectories += 1;
        }
        match logical_bytes.checked_add(logical_size) {
            Some(value) => logical_bytes = value,
            None => observe_known_schema(
                &mut deferred_known_schema,
                Error::new(ErrorCode::LimitLogicalBytes),
            )?,
        }
    }
    let (actual_object, payload_bytes) = input.finish()?;
    if actual_object != expected_object {
        return Err(Error::new(ErrorCode::ObjectIdMismatch));
    }
    if let Some(error) = deferred_known_schema {
        file_id_transaction.abort();
        return Err(error);
    }
    observe_deferred_lifecycle(&mut deferred_lifecycle, file_id_transaction.finish())?;
    if let Some(error) = deferred_lifecycle {
        file_id_transaction.abort();
        return Err(error);
    }
    file_id_transaction.commit()?;
    Ok(TreeStreamSummary {
        object_ref: actual_object,
        entries,
        payload_bytes,
        directories,
        nondirectories,
        logical_bytes,
    })
}

struct RawTreeReader<'a, R> {
    reader: BufReader<R>,
    hash: ObjectHashWriter,
    bytes: u64,
    budget: &'a Budget,
}

impl<'a, R: Read> RawTreeReader<'a, R> {
    fn new(reader: R, budget: &'a Budget) -> Self {
        Self {
            reader: BufReader::with_capacity(4096, reader),
            hash: ObjectHashWriter::new(
                ObjectKind::Tree,
                MAX_CHUNK_BYTES as usize,
                usize::try_from(budget.limits.max_output_bytes).unwrap_or(usize::MAX),
            ),
            bytes: 0,
            budget,
        }
    }

    fn raw_byte(&mut self) -> Result<u8> {
        self.budget.check_time()?;
        let mut byte = [0u8; 1];
        if self.bytes >= self.budget.limits.max_output_bytes {
            return match self.reader.read(&mut byte) {
                Ok(0) => Err(Error::new(ErrorCode::CborTruncated)),
                Ok(_) => Err(Error::new(ErrorCode::LimitMetadataBytes)),
                Err(_) => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
            };
        }
        match self.reader.read(&mut byte) {
            Ok(0) => Err(Error::new(ErrorCode::CborTruncated)),
            Ok(_) => {
                self.hash.update(&byte)?;
                self.bytes += 1;
                Ok(byte[0])
            }
            Err(_) => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        }
    }

    fn raw_exact(&mut self, output: &mut [u8]) -> Result<()> {
        for byte in output {
            *byte = self.raw_byte()?;
        }
        Ok(())
    }

    fn head(&mut self, major: u8) -> Result<u64> {
        let offset = self.bytes as usize;
        let initial = self.raw_byte()?;
        if initial >> 5 != major || initial & 31 == 31 {
            return Err(Error::at(ErrorCode::CborNonCanonical, offset));
        }
        let additional = initial & 31;
        if additional < 24 {
            return Ok(u64::from(additional));
        }
        let length = match additional {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(Error::at(ErrorCode::CborNonCanonical, offset)),
        };
        let mut bytes = [0u8; 8];
        self.raw_exact(&mut bytes[8 - length..])?;
        let value = u64::from_be_bytes(bytes);
        let minimal = match length {
            1 => value >= 24,
            2 => value > 0xff,
            4 => value > 0xffff,
            8 => value > 0xffff_ffff,
            _ => false,
        };
        if !minimal {
            return Err(Error::at(ErrorCode::CborNonCanonical, offset));
        }
        Ok(value)
    }

    fn exact_uint(&mut self, expected: u64) -> Result<()> {
        if self.head(0)? != expected {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(())
    }

    fn exact_container(&mut self, major: u8, expected: u64) -> Result<()> {
        if self.head(major)? != expected {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(())
    }

    fn skip_item(&mut self, depth: usize) -> Result<()> {
        if depth > 32 {
            return Err(Error::new(ErrorCode::LimitNesting));
        }
        let offset = self.bytes as usize;
        let initial = self.raw_byte()?;
        let major = initial >> 5;
        let additional = initial & 31;
        if major == 6 || additional == 31 {
            return Err(Error::at(ErrorCode::CborNonCanonical, offset));
        }
        let value = if additional < 24 {
            u64::from(additional)
        } else {
            let length = match additional {
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return Err(Error::at(ErrorCode::CborNonCanonical, offset)),
            };
            let mut bytes = [0u8; 8];
            self.raw_exact(&mut bytes[8 - length..])?;
            let value = u64::from_be_bytes(bytes);
            let minimal = match length {
                1 => value >= 24,
                2 => value > 0xff,
                4 => value > 0xffff,
                8 => value > 0xffff_ffff,
                _ => false,
            };
            if !minimal {
                return Err(Error::at(ErrorCode::CborNonCanonical, offset));
            }
            value
        };
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let length =
                    usize::try_from(value).map_err(|_| Error::new(ErrorCode::LimitValueBytes))?;
                if length > self.budget.limits.max_memory_bytes {
                    return Err(Error::new(ErrorCode::LimitMemory));
                }
                for _ in 0..length {
                    self.raw_byte()?;
                }
                Ok(())
            }
            4 => {
                for _ in 0..value {
                    self.skip_item(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..value {
                    self.skip_item(depth + 1)?;
                    self.skip_item(depth + 1)?;
                }
                Ok(())
            }
            7 if additional == 20 || additional == 21 => Ok(()),
            _ => Err(Error::at(ErrorCode::CborNonCanonical, offset)),
        }
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.head(2)? != N as u64 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let mut bytes = [0u8; N];
        self.raw_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn text(&mut self, maximum: usize, maximum_error: ErrorCode) -> Result<String> {
        let length =
            usize::try_from(self.head(3)?).map_err(|_| Error::new(ErrorCode::LimitValueBytes))?;
        if length > maximum {
            return Err(Error::new(maximum_error));
        }
        if length > self.budget.limits.max_memory_bytes {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        let mut bytes = vec![0u8; length];
        self.raw_exact(&mut bytes)?;
        let text = String::from_utf8(bytes).map_err(|_| Error::new(ErrorCode::CborNonCanonical))?;
        if !is_unicode_15(&text) || !is_nfc(&text) {
            return Err(Error::new(ErrorCode::CborNonCanonical));
        }
        Ok(text)
    }

    fn object_ref(&mut self) -> Result<ObjectRef> {
        self.exact_container(5, 4)?;
        self.exact_uint(0)?;
        self.exact_uint(1)?;
        self.exact_uint(1)?;
        let kind = ObjectKind::from_code(self.head(0)?)?;
        self.exact_uint(2)?;
        self.exact_uint(1)?;
        self.exact_uint(3)?;
        let digest = self.fixed_bytes::<32>()?;
        Ok(ObjectRef { kind, digest })
    }

    fn profile(&mut self) -> Result<ProfileRef> {
        self.exact_container(5, 3)?;
        self.exact_uint(0)?;
        let namespace = self.text(253, ErrorCode::SchemaFieldInvalid)?;
        self.exact_uint(1)?;
        let id = self.text(63, ErrorCode::SchemaFieldInvalid)?;
        self.exact_uint(2)?;
        let major =
            u32::try_from(self.head(0)?).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        ProfileRef::new(namespace, id, major)
    }

    fn finish(mut self) -> Result<(ObjectRef, u64)> {
        self.budget.check_time()?;
        let mut trailing = [0u8; 1];
        match self.reader.read(&mut trailing) {
            Ok(0) => Ok((self.hash.finish()?, self.bytes)),
            Ok(_) if self.bytes >= self.budget.limits.max_output_bytes => {
                Err(Error::new(ErrorCode::LimitMetadataBytes))
            }
            Ok(_) => Err(Error::at(ErrorCode::CborTrailingBytes, self.bytes as usize)),
            Err(_) => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        }
    }
}

/// Validates and emits a one-directory format-v1 tree from an already strictly
/// ordered iterator. `declared_entries` supplies the definite-array length and
/// must equal the number of yielded entries.
#[allow(clippy::too_many_arguments)]
pub fn encode_ordered_tree<W, I>(
    writer: W,
    repository_descriptor: ObjectRef,
    declared_entries: u64,
    entries: I,
    registry: &Registry,
    operation: Operation,
    file_ids: &mut dyn TreeFileIdIndex,
    limits: TreeStreamLimits,
) -> Result<TreeStreamSummary>
where
    W: Write,
    I: IntoIterator<Item = TreeStreamEntry>,
{
    encode_ordered_tree_with_features(
        writer,
        repository_descriptor,
        &[],
        declared_entries,
        entries,
        registry,
        operation,
        file_ids,
        limits,
    )
}

/// Feature-aware form of [`encode_ordered_tree`]. The supplied required
/// features are lifecycle-checked and emitted in strict ascending order.
#[allow(clippy::too_many_arguments)]
pub fn encode_ordered_tree_with_features<W, I>(
    writer: W,
    repository_descriptor: ObjectRef,
    required_features: &[u32],
    declared_entries: u64,
    entries: I,
    registry: &Registry,
    operation: Operation,
    file_ids: &mut dyn TreeFileIdIndex,
    limits: TreeStreamLimits,
) -> Result<TreeStreamSummary>
where
    W: Write,
    I: IntoIterator<Item = TreeStreamEntry>,
{
    registry.require_complete_authority()?;
    require_write_operation(operation)?;
    let budget = Budget::new(limits)?;
    let live_memory = tree_stream_live_memory_bytes(&budget.limits)?;
    if budget.limits.max_memory_bytes < live_memory {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    budget.check_count(declared_entries)?;
    let mut deferred_lifecycle = None;
    observe_deferred_lifecycle(
        &mut deferred_lifecycle,
        validate_tree_assignments(registry, operation),
    )?;
    let mut iterator = entries.into_iter();
    let deferred_known_schema = RefCell::new(None);
    let mut raw_seen = 0u64;
    let index_memory = budget
        .limits
        .max_memory_bytes
        .checked_sub(live_memory)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    let mut file_id_transaction = file_ids.begin(declared_entries, index_memory)?;
    let result = encode_prepared_tree(
        writer,
        repository_descriptor,
        required_features,
        declared_entries,
        || {
            loop {
                let Some(entry) = iterator.next() else {
                    return Ok(None);
                };
                raw_seen = raw_seen
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
                // Count the caller's raw items before decoding/preparing one.
                // An invalid item cannot bypass the configured item ceiling.
                budget.check_count(raw_seen)?;
                if raw_seen > declared_entries {
                    observe_known_schema(
                        &mut deferred_known_schema.borrow_mut(),
                        Error::new(ErrorCode::SchemaFieldInvalid)
                            .with_stage(ValidationStage::KnownSchema),
                    )?;
                }
                observe_entry_lifecycle(&mut deferred_lifecycle, &entry, registry, operation)?;
                match prepare_entry(entry, &budget) {
                    Ok(prepared) => break Ok(Some(prepared)),
                    Err(error) => {
                        observe_known_schema(&mut deferred_known_schema.borrow_mut(), error)?
                    }
                }
            }
        },
        &budget,
        &deferred_known_schema,
        Some(file_id_transaction.as_mut()),
    );
    // The required-feature lifecycle is item-derived layer three. A bounded
    // declared-count/shape failure from the iterator must win first.
    if result.is_ok() {
        observe_deferred_lifecycle(
            &mut deferred_lifecycle,
            validate_required_features(required_features, registry, operation, &budget),
        )?;
        observe_deferred_lifecycle(&mut deferred_lifecycle, file_id_transaction.finish())?;
        if let Some(error) = deferred_lifecycle {
            file_id_transaction.abort();
            return Err(error);
        }
        file_id_transaction.commit()?;
    } else {
        file_id_transaction.abort();
    }
    result
}

/// Validates unordered entries, writes deterministic bounded-memory sort runs
/// beneath an exclusive private directory in `scratch_directory`, and emits
/// the same canonical payload as [`encode_ordered_tree`].
#[allow(clippy::too_many_arguments)]
pub fn encode_tree_with_scratch<W, I>(
    writer: W,
    repository_descriptor: ObjectRef,
    declared_entries: u64,
    entries: I,
    registry: &Registry,
    operation: Operation,
    scratch_directory: &Path,
    limits: TreeStreamLimits,
    scratch_metrics: &mut TreeScratchMetrics,
) -> Result<TreeStreamSummary>
where
    W: Write,
    I: IntoIterator<Item = TreeStreamEntry>,
{
    encode_tree_with_scratch_and_features(
        writer,
        repository_descriptor,
        &[],
        declared_entries,
        entries,
        registry,
        operation,
        scratch_directory,
        limits,
        scratch_metrics,
    )
}

/// Feature-aware form of [`encode_tree_with_scratch`].
#[allow(clippy::too_many_arguments)]
pub fn encode_tree_with_scratch_and_features<W, I>(
    writer: W,
    repository_descriptor: ObjectRef,
    required_features: &[u32],
    declared_entries: u64,
    entries: I,
    registry: &Registry,
    operation: Operation,
    scratch_directory: &Path,
    limits: TreeStreamLimits,
    scratch_metrics: &mut TreeScratchMetrics,
) -> Result<TreeStreamSummary>
where
    W: Write,
    I: IntoIterator<Item = TreeStreamEntry>,
{
    registry.require_complete_authority()?;
    require_write_operation(operation)?;
    let budget = Budget::new(limits)?;
    budget.check_count(declared_entries)?;
    let mut deferred_lifecycle = None;
    observe_deferred_lifecycle(
        &mut deferred_lifecycle,
        validate_tree_assignments(registry, operation),
    )?;
    if declared_entries == 0 {
        let mut iterator = entries.into_iter();
        let deferred_known_schema = RefCell::new(None);
        let mut raw_seen = 0u64;
        let result = encode_prepared_tree(
            writer,
            repository_descriptor,
            required_features,
            0,
            || loop {
                let Some(entry) = iterator.next() else {
                    return Ok(None);
                };
                raw_seen = raw_seen
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
                budget.check_count(raw_seen)?;
                observe_known_schema(
                    &mut deferred_known_schema.borrow_mut(),
                    Error::new(ErrorCode::SchemaFieldInvalid)
                        .with_stage(ValidationStage::KnownSchema),
                )?;
                observe_entry_lifecycle(&mut deferred_lifecycle, &entry, registry, operation)?;
                match prepare_entry(entry, &budget) {
                    Ok(prepared) => break Ok(Some(prepared)),
                    Err(error) => {
                        observe_known_schema(&mut deferred_known_schema.borrow_mut(), error)?
                    }
                }
            },
            &budget,
            &deferred_known_schema,
            None,
        );
        if result.is_ok() {
            observe_deferred_lifecycle(
                &mut deferred_lifecycle,
                validate_required_features(required_features, registry, operation, &budget),
            )?;
            if let Some(error) = deferred_lifecycle {
                return Err(error);
            }
        }
        return result;
    }

    let id_scratch_limit = budget.limits.max_scratch_bytes / 4;
    let name_scratch_limit = budget
        .limits
        .max_scratch_bytes
        .saturating_sub(id_scratch_limit);
    let id_memory_limit = budget.limits.max_memory_bytes / 4;
    let name_memory_limit = budget
        .limits
        .max_memory_bytes
        .saturating_sub(id_memory_limit);
    if id_memory_limit < 16 {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    let mut workspace = ScratchWorkspace::new(scratch_directory, name_scratch_limit)?;
    let mut file_ids = TreeFileIdScratchIndex::new(
        scratch_directory,
        id_memory_limit,
        id_scratch_limit,
        budget.limits.max_elapsed,
    )?;
    let mut file_id_transaction = file_ids.begin(declared_entries, id_memory_limit)?;
    let mut runs = Vec::new();
    let mut records = Vec::<PreparedEntry>::new();
    let mut retained = 0usize;
    let mut count = 0u64;
    let deferred_known_schema = RefCell::new(None);

    for entry in entries {
        budget.check_time()?;
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        budget.check_count(count)?;
        if count > declared_entries {
            observe_known_schema(
                &mut deferred_known_schema.borrow_mut(),
                Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema),
            )?;
        }
        observe_entry_lifecycle(&mut deferred_lifecycle, &entry, registry, operation)?;
        let prepared = match prepare_entry(entry, &budget) {
            Ok(prepared) => prepared,
            Err(error) => {
                observe_known_schema(&mut deferred_known_schema.borrow_mut(), error)?;
                continue;
            }
        };
        file_id_transaction.insert(prepared.file_id)?;
        let cost = prepared.retained_cost();
        if cost > name_memory_limit {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        if !records.is_empty() && cost > name_memory_limit.saturating_sub(retained) {
            runs.push(workspace.write_sorted_run(&mut records, &budget)?);
            retained = 0;
        }
        retained = retained
            .checked_add(cost)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        records.push(prepared);
    }
    if count != declared_entries {
        observe_known_schema(
            &mut deferred_known_schema.borrow_mut(),
            Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema),
        )?;
    }
    if let Some(error) = deferred_known_schema.borrow().clone() {
        file_id_transaction.abort();
        return Err(error);
    }
    observe_deferred_lifecycle(
        &mut deferred_lifecycle,
        validate_required_features(required_features, registry, operation, &budget),
    )?;
    observe_deferred_lifecycle(&mut deferred_lifecycle, file_id_transaction.finish())?;
    if !records.is_empty() {
        runs.push(workspace.write_sorted_run(&mut records, &budget)?);
    }
    while runs.len() > 1 {
        budget.check_time()?;
        workspace.metrics.merge_passes = workspace.metrics.merge_passes.saturating_add(1);
        let mut next = Vec::with_capacity(runs.len().div_ceil(2));
        let mut input = runs.into_iter();
        while let Some(left) = input.next() {
            if let Some(right) = input.next() {
                next.push(workspace.merge_runs(left, right, &budget)?);
            } else {
                next.push(left);
            }
        }
        runs = next;
    }

    let final_run = runs
        .pop()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let mut reader = RunReader::open(&final_run)?;
    let result = encode_prepared_tree(
        writer,
        repository_descriptor,
        required_features,
        declared_entries,
        || reader.next_record(),
        &budget,
        &deferred_known_schema,
        None,
    );
    if result.is_ok() {
        reader.finish()?;
        if let Some(error) = deferred_lifecycle {
            file_id_transaction.abort();
            return Err(error);
        }
        file_id_transaction.commit()?;
        let file_id_metrics = file_ids.scratch_metrics();
        *scratch_metrics = TreeScratchMetrics {
            peak_bytes: workspace
                .metrics
                .peak_bytes
                .saturating_add(file_id_metrics.peak_bytes),
            bytes_written: workspace
                .metrics
                .bytes_written
                .saturating_add(file_id_metrics.bytes_written),
            files_created: workspace
                .metrics
                .files_created
                .saturating_add(file_id_metrics.files_created),
            merge_passes: workspace
                .metrics
                .merge_passes
                .saturating_add(file_id_metrics.merge_passes),
        };
    } else {
        file_id_transaction.abort();
    }
    result
}

fn encode_prepared_tree<W, F>(
    writer: W,
    repository_descriptor: ObjectRef,
    required_features: &[u32],
    declared_entries: u64,
    mut next: F,
    budget: &Budget,
    known_schema: &RefCell<Option<Error>>,
    mut file_ids: Option<&mut dyn TreeFileIdTransaction>,
) -> Result<TreeStreamSummary>
where
    W: Write,
    F: FnMut() -> Result<Option<PreparedEntry>>,
{
    if repository_descriptor.kind != ObjectKind::RepositoryDescriptor {
        return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::KnownSchema));
    }
    budget.check_count(declared_entries)?;
    budget.check_time()?;

    let mut sink = CanonicalSink::new(writer, budget.limits.max_output_bytes);
    sink.head(5, 5)?;
    sink.head(0, 0)?;
    sink.head(0, 1)?;
    sink.head(0, 1)?;
    sink.head(0, 3)?;
    sink.head(0, 2)?;
    sink.head(
        4,
        u64::try_from(required_features.len()).map_err(|_| Error::new(ErrorCode::LimitCount))?,
    )?;
    for feature in required_features {
        sink.head(0, u64::from(*feature))?;
    }
    sink.head(0, 16)?;
    write_object_ref(&mut sink, repository_descriptor)?;
    sink.head(0, 17)?;
    sink.head(4, declared_entries)?;

    let mut previous = Vec::new();
    let mut seen = 0u64;
    let mut directories = 0u64;
    let mut nondirectories = 0u64;
    let mut logical_bytes = 0u64;
    while let Some(entry) = next()? {
        budget.check_time()?;
        seen = seen
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        budget.check_count(seen)?;
        if seen > declared_entries {
            observe_known_schema(
                &mut known_schema.borrow_mut(),
                Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema),
            )?;
            continue;
        }
        if !previous.is_empty() && previous.as_slice() >= entry.key.as_slice() {
            observe_known_schema(
                &mut known_schema.borrow_mut(),
                Error::new(ErrorCode::TreeEntryOrderInvalid),
            )?;
        }
        previous = entry.key;
        if let Some(index) = file_ids.as_deref_mut() {
            index.insert(entry.file_id)?;
        }
        if entry.kind == 1 {
            directories += 1;
        } else {
            nondirectories += 1;
        }
        logical_bytes = logical_bytes
            .checked_add(entry.logical_size)
            .ok_or_else(|| Error::new(ErrorCode::LimitLogicalBytes))?;
        sink.bytes(&entry.encoded)?;
    }
    if seen != declared_entries {
        observe_known_schema(
            &mut known_schema.borrow_mut(),
            Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema),
        )?;
    }
    let (object_ref, payload_bytes) = sink.finish()?;
    if let Some(error) = known_schema.borrow().clone() {
        return Err(error);
    }
    Ok(TreeStreamSummary {
        object_ref,
        entries: seen,
        payload_bytes,
        directories,
        nondirectories,
        logical_bytes,
    })
}

fn prepare_entry(entry: TreeStreamEntry, budget: &Budget) -> Result<PreparedEntry> {
    budget.check_time()?;
    let name = entry.basename.as_bytes();
    budget.check_basename(name.len())?;
    if name.is_empty()
        || !is_unicode_15(&entry.basename)
        || !is_nfc(&entry.basename)
        || entry.basename == "."
        || entry.basename == ".."
        || name.contains(&b'/')
        || name.contains(&0)
    {
        return Err(Error::new(ErrorCode::PathCoreInvalid));
    }
    if entry.file_id == [0; 16] {
        return Err(Error::new(ErrorCode::FileIdZero));
    }
    budget.check_logical(entry.logical_size)?;
    if !(1..=4).contains(&entry.entry_kind)
        || entry.portable_mode != entry.entry_kind
        || (entry.entry_kind == 1 && entry.logical_size != 0)
    {
        return Err(Error::new(ErrorCode::TreeEntryTargetInvalid));
    }
    let expected_target = if entry.entry_kind == 1 {
        ObjectKind::Tree
    } else {
        ObjectKind::ContentManifest
    };
    if entry.target.kind != expected_target {
        return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::KnownSchema));
    }
    let mut encoded = Vec::with_capacity(128 + name.len());
    push_head(&mut encoded, 5, 7);
    push_head(&mut encoded, 0, 0);
    push_text(&mut encoded, &entry.basename);
    push_head(&mut encoded, 0, 1);
    push_head(&mut encoded, 0, u64::from(entry.entry_kind));
    push_head(&mut encoded, 0, 2);
    push_bytes(&mut encoded, &entry.file_id);
    push_head(&mut encoded, 0, 3);
    push_head(&mut encoded, 0, u64::from(entry.portable_mode));
    push_head(&mut encoded, 0, 4);
    push_object_ref(&mut encoded, entry.target);
    push_head(&mut encoded, 0, 5);
    push_head(&mut encoded, 0, entry.logical_size);
    push_head(&mut encoded, 0, 6);
    push_profile(&mut encoded, &entry.content_policy);
    if encoded.len() > MAX_PRIVATE_ENTRY_BYTES {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    let prepared = PreparedEntry {
        key: name.to_vec(),
        encoded,
        kind: entry.entry_kind,
        file_id: entry.file_id,
        logical_size: entry.logical_size,
    };
    if prepared.retained_cost() > budget.limits.max_memory_bytes {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    Ok(prepared)
}

fn observe_entry_lifecycle(
    best: &mut Option<Error>,
    entry: &TreeStreamEntry,
    registry: &Registry,
    operation: Operation,
) -> Result<()> {
    observe_deferred_lifecycle(
        best,
        validate_tree_entry_assignments(
            u64::from(entry.entry_kind),
            u64::from(entry.portable_mode),
            entry.target.kind,
            registry,
            operation,
        ),
    )?;
    observe_deferred_lifecycle(
        best,
        validate_content_profile(&entry.content_policy, registry, operation),
    )
}

fn observe_deferred_lifecycle(best: &mut Option<Error>, result: Result<()>) -> Result<()> {
    let Err(error) = result else {
        return Ok(());
    };
    if error.layer < 3 {
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

fn observe_known_schema(best: &mut Option<Error>, error: Error) -> Result<()> {
    if error.layer != 2 {
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

fn tree_limit(
    name: &'static str,
    value: u64,
    configured: u64,
    code: ErrorCode,
    layer: u8,
) -> Result<()> {
    enforce_hard_limit_context(name, value, configured, code, layer).map(|_| ())
}

fn validate_required_features(
    features: &[u32],
    registry: &Registry,
    operation: Operation,
    budget: &Budget,
) -> Result<()> {
    let mut previous = 0u32;
    for feature in features {
        budget.check_time()?;
        if *feature == 0 || *feature <= previous {
            return Err(
                Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema)
            );
        }
        registry.check_assignment(RegistryAssignment::RequiredFeature(*feature), operation)?;
        previous = *feature;
    }
    Ok(())
}

fn validate_tree_assignments(registry: &Registry, operation: Operation) -> Result<()> {
    for assignment in [
        RegistryAssignment::ObjectKind(ObjectKind::Tree.code()),
        RegistryAssignment::ObjectKind(ObjectKind::RepositoryDescriptor.code()),
        RegistryAssignment::HashAlgorithm(1),
        RegistryAssignment::CommonField(0),
        RegistryAssignment::CommonField(1),
        RegistryAssignment::CommonField(2),
    ] {
        registry.check_assignment_if_present(assignment, operation)?;
    }
    for (rule, fields) in [("tree", &[16, 17][..]), ("object-ref", &[0, 1, 2, 3][..])] {
        for &code in fields {
            registry.check_assignment_if_present(
                RegistryAssignment::KindField {
                    cddl_rule: rule,
                    code,
                },
                operation,
            )?;
        }
    }
    Ok(())
}

fn validate_tree_entry_assignments(
    kind: u64,
    mode: u64,
    target_kind: ObjectKind,
    registry: &Registry,
    operation: Operation,
) -> Result<()> {
    for code in 0..=6 {
        registry.check_assignment_if_present(
            RegistryAssignment::KindField {
                cddl_rule: "tree-entry",
                code,
            },
            operation,
        )?;
    }
    for code in 0..=2 {
        registry.check_assignment_if_present(
            RegistryAssignment::KindField {
                cddl_rule: "profile-ref",
                code,
            },
            operation,
        )?;
    }
    let kind = u16::try_from(kind).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let mode = u16::try_from(mode).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    for assignment in [
        RegistryAssignment::EntryKind(kind),
        RegistryAssignment::EntryMode(mode),
        RegistryAssignment::ObjectKind(target_kind.code()),
        RegistryAssignment::HashAlgorithm(1),
    ] {
        registry.check_assignment_if_present(assignment, operation)?;
    }
    Ok(())
}

fn validate_content_profile(
    profile: &ProfileRef,
    registry: &Registry,
    operation: Operation,
) -> Result<()> {
    let entry = registry
        .profile(profile)
        .ok_or_else(|| Error::new(ErrorCode::ProfileUnknown))?;
    if entry.family != "content-policy" && entry.family != "fixture-content-policy" {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    registry.check_profile(profile, &entry.family, operation)
}

fn write_object_ref<W: Write>(sink: &mut CanonicalSink<W>, reference: ObjectRef) -> Result<()> {
    let mut encoded = Vec::with_capacity(42);
    push_object_ref(&mut encoded, reference);
    sink.bytes(&encoded)
}

fn push_object_ref(output: &mut Vec<u8>, reference: ObjectRef) {
    push_head(output, 5, 4);
    push_head(output, 0, 0);
    push_head(output, 0, 1);
    push_head(output, 0, 1);
    push_head(output, 0, u64::from(reference.kind.code()));
    push_head(output, 0, 2);
    push_head(output, 0, 1);
    push_head(output, 0, 3);
    push_bytes(output, &reference.digest);
}

fn push_profile(output: &mut Vec<u8>, profile: &ProfileRef) {
    push_head(output, 5, 3);
    push_head(output, 0, 0);
    push_text(output, profile.namespace());
    push_head(output, 0, 1);
    push_text(output, profile.id());
    push_head(output, 0, 2);
    push_head(output, 0, u64::from(profile.major()));
}

fn push_text(output: &mut Vec<u8>, text: &str) {
    push_head(output, 3, text.len() as u64);
    output.extend_from_slice(text.as_bytes());
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    push_head(output, 2, bytes.len() as u64);
    output.extend_from_slice(bytes);
}

fn push_head(output: &mut Vec<u8>, major: u8, value: u64) {
    let (bytes, length) = cbor_head(major, value);
    output.extend_from_slice(&bytes[..length]);
}

fn cbor_head(major: u8, value: u64) -> ([u8; 9], usize) {
    let mut bytes = [0u8; 9];
    let prefix = major << 5;
    match value {
        0..=23 => {
            bytes[0] = prefix | value as u8;
            (bytes, 1)
        }
        24..=0xff => {
            bytes[0] = prefix | 24;
            bytes[1] = value as u8;
            (bytes, 2)
        }
        0x100..=0xffff => {
            bytes[0] = prefix | 25;
            bytes[1..3].copy_from_slice(&(value as u16).to_be_bytes());
            (bytes, 3)
        }
        0x1_0000..=0xffff_ffff => {
            bytes[0] = prefix | 26;
            bytes[1..5].copy_from_slice(&(value as u32).to_be_bytes());
            (bytes, 5)
        }
        _ => {
            bytes[0] = prefix | 27;
            bytes[1..9].copy_from_slice(&value.to_be_bytes());
            (bytes, 9)
        }
    }
}

#[derive(Clone, Debug)]
struct RunFile {
    path: PathBuf,
    bytes: u64,
    records: u64,
    identity: FileIdentity,
    digest: [u8; 32],
}

fn run_file_digest(file: &mut File) -> Result<[u8; 32]> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let mut digest = Sha256Writer::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    Ok(digest.finish())
}

fn open_verified_run(run: &RunFile) -> Result<File> {
    let metadata = std::fs::symlink_metadata(&run.path)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != run.bytes {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let mut file = File::open(&run.path).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let opened = file
        .metadata()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    if !opened.is_file()
        || opened.len() != run.bytes
        || FileIdentity::from_file(&file).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?
            != run.identity
        || run_file_digest(&mut file)? != run.digest
    {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    Ok(file)
}

struct ScratchWorkspace {
    directory: PathBuf,
    files: BTreeSet<PathBuf>,
    directory_present: bool,
    live_bytes: u64,
    maximum: u64,
    metrics: TreeScratchMetrics,
}

impl ScratchWorkspace {
    fn new(parent: &Path, maximum: u64) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(parent)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|_| Error::new(ErrorCode::FileIdEntropyUnavailable))?;
        let token = hex_lower(&random);
        let directory = parent.join(format!(".ogvcs-sort-{token}"));
        create_private_directory(&directory)?;
        let created = std::fs::symlink_metadata(&directory)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if created.file_type().is_symlink() || !created.is_dir() {
            let _ = std::fs::remove_dir(&directory);
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(Self {
            directory,
            files: BTreeSet::new(),
            directory_present: true,
            live_bytes: 0,
            maximum,
            metrics: TreeScratchMetrics::default(),
        })
    }

    fn create_file(&mut self) -> Result<(PathBuf, File)> {
        for _ in 0..32 {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| Error::new(ErrorCode::FileIdEntropyUnavailable))?;
            let token = hex_lower(&random);
            let path = self.directory.join(format!("run-{token}.bin"));
            match create_private_file(&path) {
                Ok(file) => {
                    if !file
                        .metadata()
                        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?
                        .is_file()
                    {
                        let _ = std::fs::remove_file(&path);
                        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
                    }
                    self.files.insert(path.clone());
                    self.metrics.files_created = self.metrics.files_created.saturating_add(1);
                    return Ok((path, file));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
            }
        }
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    }

    fn reserve_write(&mut self, length: usize) -> Result<()> {
        let length = u64::try_from(length).map_err(|_| Error::new(ErrorCode::LimitScratch))?;
        if length > self.maximum.saturating_sub(self.live_bytes) {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        self.live_bytes += length;
        self.metrics.bytes_written = self.metrics.bytes_written.saturating_add(length);
        self.metrics.peak_bytes = self.metrics.peak_bytes.max(self.live_bytes);
        Ok(())
    }

    fn write_bytes(&mut self, file: &mut File, bytes: &[u8]) -> Result<()> {
        self.reserve_write(bytes.len())?;
        file.write_all(bytes)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
    }

    fn write_sorted_run(
        &mut self,
        records: &mut Vec<PreparedEntry>,
        budget: &Budget,
    ) -> Result<RunFile> {
        records.sort_unstable_by(|left, right| left.key.cmp(&right.key));
        let count = records.len() as u64;
        let (path, mut file) = self.create_file()?;
        self.write_bytes(&mut file, RUN_MAGIC)?;
        self.write_bytes(&mut file, &count.to_be_bytes())?;
        for record in records.drain(..) {
            budget.check_time()?;
            self.write_record(&mut file, &record)?;
        }
        self.finish_run(path, file, count)
    }

    fn write_record(&mut self, file: &mut File, record: &PreparedEntry) -> Result<()> {
        let mut body = Vec::with_capacity(record.key.len() + record.encoded.len() + 32);
        body.push(record.kind);
        body.extend_from_slice(&record.logical_size.to_be_bytes());
        body.extend_from_slice(&record.file_id);
        body.extend_from_slice(&(record.key.len() as u16).to_be_bytes());
        body.extend_from_slice(&record.key);
        body.extend_from_slice(&(record.encoded.len() as u32).to_be_bytes());
        body.extend_from_slice(&record.encoded);
        let length =
            u32::try_from(body.len()).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        self.write_bytes(file, &length.to_be_bytes())?;
        self.write_bytes(file, &body)?;
        self.write_bytes(file, &sha256(&body))
    }

    fn merge_runs(&mut self, left: RunFile, right: RunFile, budget: &Budget) -> Result<RunFile> {
        let mut left_reader = RunReader::open(&left)?;
        let mut right_reader = RunReader::open(&right)?;
        let records = left
            .records
            .checked_add(right.records)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        let (path, mut output) = self.create_file()?;
        self.write_bytes(&mut output, RUN_MAGIC)?;
        self.write_bytes(&mut output, &records.to_be_bytes())?;
        let mut left_value = left_reader.next_record()?;
        let mut right_value = right_reader.next_record()?;
        while left_value.is_some() || right_value.is_some() {
            budget.check_time()?;
            let take_left = match (&left_value, &right_value) {
                (Some(left), Some(right)) => left.key <= right.key,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => break,
            };
            if take_left {
                self.write_record(&mut output, left_value.as_ref().expect("present"))?;
                left_value = left_reader.next_record()?;
            } else {
                self.write_record(&mut output, right_value.as_ref().expect("present"))?;
                right_value = right_reader.next_record()?;
            }
        }
        left_reader.finish()?;
        right_reader.finish()?;
        let merged = self.finish_run(path, output, records)?;
        self.remove_run(&left)?;
        self.remove_run(&right)?;
        Ok(merged)
    }

    fn write_id_run(&mut self, ids: &mut Vec<[u8; 16]>) -> Result<RunFile> {
        ids.sort_unstable();
        if ids.windows(2).any(|window| window[0] == window[1]) {
            return Err(Error::new(ErrorCode::FileIdDuplicateInTree));
        }
        let records = ids.len() as u64;
        let (path, mut file) = self.create_file()?;
        self.write_bytes(&mut file, ID_RUN_MAGIC)?;
        self.write_bytes(&mut file, &records.to_be_bytes())?;
        for file_id in ids.drain(..) {
            self.write_bytes(&mut file, &file_id)?;
        }
        self.finish_run(path, file, records)
    }

    fn merge_id_runs(&mut self, left: RunFile, right: RunFile) -> Result<RunFile> {
        let mut left_reader = IdRunReader::open(&left)?;
        let mut right_reader = IdRunReader::open(&right)?;
        let records = left
            .records
            .checked_add(right.records)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        let (path, mut output) = self.create_file()?;
        self.write_bytes(&mut output, ID_RUN_MAGIC)?;
        self.write_bytes(&mut output, &records.to_be_bytes())?;
        let mut left_value = left_reader.next_id()?;
        let mut right_value = right_reader.next_id()?;
        while left_value.is_some() || right_value.is_some() {
            let value = match (left_value, right_value) {
                (Some(left_id), Some(right_id)) if left_id == right_id => {
                    return Err(Error::new(ErrorCode::FileIdDuplicateInTree));
                }
                (Some(left_id), Some(right_id)) if left_id < right_id => {
                    left_value = left_reader.next_id()?;
                    right_value = Some(right_id);
                    left_id
                }
                (Some(left_id), Some(right_id)) => {
                    left_value = Some(left_id);
                    right_value = right_reader.next_id()?;
                    right_id
                }
                (Some(left_id), None) => {
                    left_value = left_reader.next_id()?;
                    left_id
                }
                (None, Some(right_id)) => {
                    right_value = right_reader.next_id()?;
                    right_id
                }
                (None, None) => break,
            };
            self.write_bytes(&mut output, &value)?;
        }
        left_reader.finish()?;
        right_reader.finish()?;
        let merged = self.finish_run(path, output, records)?;
        self.remove_run(&left)?;
        self.remove_run(&right)?;
        Ok(merged)
    }

    fn finish_run(&self, path: PathBuf, mut file: File, records: u64) -> Result<RunFile> {
        file.flush()
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let metadata = file
            .metadata()
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let bytes = metadata.len();
        let identity = FileIdentity::from_file(&file)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let digest = run_file_digest(&mut file)?;
        Ok(RunFile {
            path,
            bytes,
            records,
            identity,
            digest,
        })
    }

    fn remove_run(&mut self, run: &RunFile) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&run.path)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != run.bytes
            || !run
                .identity
                .matches_path(&run.path, &metadata)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        std::fs::remove_file(&run.path).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        self.files.remove(&run.path);
        self.live_bytes = self.live_bytes.saturating_sub(run.bytes);
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        if !self.files.is_empty() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        if self.directory_present {
            std::fs::remove_dir(&self.directory)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
            self.directory_present = false;
        }
        Ok(())
    }
}

impl Drop for ScratchWorkspace {
    fn drop(&mut self) {
        for path in &self.files {
            let _ = std::fs::remove_file(path);
        }
        if self.directory_present {
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

struct RunReader {
    reader: BufReader<File>,
    remaining: u64,
    previous: Vec<u8>,
}

impl RunReader {
    fn open(run: &RunFile) -> Result<Self> {
        let file = open_verified_run(run)?;
        let mut reader = BufReader::new(file);
        let mut magic = [0u8; RUN_MAGIC.len()];
        read_exact(&mut reader, &mut magic)?;
        if &magic != RUN_MAGIC {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let records = read_u64(&mut reader)?;
        if records != run.records {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(Self {
            reader,
            remaining: records,
            previous: Vec::new(),
        })
    }

    fn next_record(&mut self) -> Result<Option<PreparedEntry>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let length = read_u32(&mut self.reader)? as usize;
        if !(31..=MAX_PRIVATE_ENTRY_BYTES + 512).contains(&length) {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let mut body = vec![0u8; length];
        read_exact(&mut self.reader, &mut body)?;
        let mut expected = [0u8; 32];
        read_exact(&mut self.reader, &mut expected)?;
        if sha256(&body) != expected {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let kind = body[0];
        let logical_size = u64::from_be_bytes(
            body[1..9]
                .try_into()
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        );
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&body[9..25]);
        let key_length = u16::from_be_bytes([body[25], body[26]]) as usize;
        let key_end = 27usize
            .checked_add(key_length)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let entry_length_end = key_end
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if key_length == 0
            || key_length > MAX_PATH_SEGMENT_BYTES as usize
            || entry_length_end > body.len()
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let entry_length = u32::from_be_bytes(
            body[key_end..entry_length_end]
                .try_into()
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
        ) as usize;
        if entry_length > MAX_PRIVATE_ENTRY_BYTES
            || entry_length_end.saturating_add(entry_length) != body.len()
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let key = body[27..key_end].to_vec();
        if !self.previous.is_empty() && self.previous > key {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        self.previous = key.clone();
        self.remaining -= 1;
        Ok(Some(PreparedEntry {
            key,
            encoded: body[entry_length_end..].to_vec(),
            kind,
            file_id,
            logical_size,
        }))
    }

    fn finish(mut self) -> Result<()> {
        if self.remaining != 0 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let mut byte = [0u8; 1];
        if self
            .reader
            .read(&mut byte)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?
            != 0
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(())
    }
}

struct IdRunReader {
    reader: BufReader<File>,
    remaining: u64,
    previous: Option<[u8; 16]>,
}

impl IdRunReader {
    fn open(run: &RunFile) -> Result<Self> {
        let expected_bytes = 20u64
            .checked_add(
                run.records
                    .checked_mul(16)
                    .ok_or_else(|| Error::new(ErrorCode::LimitScratch))?,
            )
            .ok_or_else(|| Error::new(ErrorCode::LimitScratch))?;
        if run.bytes != expected_bytes {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let file = open_verified_run(run)?;
        let mut reader = BufReader::new(file);
        let mut magic = [0u8; ID_RUN_MAGIC.len()];
        read_exact(&mut reader, &mut magic)?;
        if &magic != ID_RUN_MAGIC || read_u64(&mut reader)? != run.records {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(Self {
            reader,
            remaining: run.records,
            previous: None,
        })
    }

    fn next_id(&mut self) -> Result<Option<[u8; 16]>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        let mut file_id = [0u8; 16];
        read_exact(&mut self.reader, &mut file_id)?;
        if self.previous.is_some_and(|previous| previous >= file_id) {
            return Err(Error::new(ErrorCode::FileIdDuplicateInTree));
        }
        self.previous = Some(file_id);
        self.remaining -= 1;
        Ok(Some(file_id))
    }

    fn finish(mut self) -> Result<()> {
        while self.next_id()?.is_some() {}
        let mut trailing = [0u8; 1];
        if self
            .reader
            .read(&mut trailing)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?
            != 0
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(())
    }
}

fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<()> {
    reader
        .read_exact(bytes)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn read_u32(reader: &mut impl Read) -> Result<u32> {
    let mut bytes = [0u8; 4];
    read_exact(reader, &mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> Result<u64> {
    let mut bytes = [0u8; 8];
    read_exact(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir(path).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true).mode(0o600);
    options.open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TemporaryParent(PathBuf);

    impl TemporaryParent {
        fn new() -> Self {
            let mut token = [0u8; 16];
            getrandom::getrandom(&mut token).unwrap();
            let name = hex_lower(&token);
            let path = std::env::temp_dir().join(format!("ogvcs-tree-test-{name}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryParent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn replace_with_identical_bytes(path: &Path) {
        let bytes = std::fs::read(path).unwrap();
        let replacement = path.with_extension("replacement");
        let backup = path.with_extension("original");
        std::fs::write(&replacement, bytes).unwrap();
        std::fs::rename(path, &backup).unwrap();
        std::fs::rename(replacement, path).unwrap();
    }

    #[test]
    fn reopened_name_and_file_id_runs_reject_same_size_replacement() {
        let parent = TemporaryParent::new();
        let budget = Budget::new(TreeStreamLimits::default()).unwrap();

        let mut names = ScratchWorkspace::new(&parent.0, 1024 * 1024).unwrap();
        let mut records = vec![PreparedEntry {
            key: b"entry".to_vec(),
            encoded: vec![0xa0],
            kind: 2,
            file_id: [1; 16],
            logical_size: 0,
        }];
        let name_run = names.write_sorted_run(&mut records, &budget).unwrap();
        replace_with_identical_bytes(&name_run.path);
        assert_eq!(
            RunReader::open(&name_run).err().unwrap().code,
            ErrorCode::SchemaFieldInvalid
        );

        let mut ids = ScratchWorkspace::new(&parent.0, 1024 * 1024).unwrap();
        let mut values = vec![[1; 16], [2; 16]];
        let id_run = ids.write_id_run(&mut values).unwrap();
        replace_with_identical_bytes(&id_run.path);
        assert_eq!(
            IdRunReader::open(&id_run).err().unwrap().code,
            ErrorCode::SchemaFieldInvalid
        );
    }

    #[test]
    fn reopened_run_rejects_same_identity_same_size_content_change() {
        let parent = TemporaryParent::new();
        let budget = Budget::new(TreeStreamLimits::default()).unwrap();
        let mut workspace = ScratchWorkspace::new(&parent.0, 1024 * 1024).unwrap();
        let mut records = vec![PreparedEntry {
            key: b"entry".to_vec(),
            encoded: vec![0xa0],
            kind: 2,
            file_id: [1; 16],
            logical_size: 0,
        }];
        let run = workspace.write_sorted_run(&mut records, &budget).unwrap();
        let replacement = std::fs::read(&run.path).unwrap().last().copied().unwrap() ^ 0xff;
        let mut file = OpenOptions::new().write(true).open(&run.path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[replacement]).unwrap();
        file.flush().unwrap();
        assert_eq!(
            RunReader::open(&run).err().unwrap().code,
            ErrorCode::SchemaFieldInvalid
        );
    }
}
