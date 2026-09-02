//! Private bounded, read-only OGVCS-015 immutable history and snapshot-diff
//! candidate. This crate is deliberately unpublished and unwired.
#![forbid(unsafe_code)]

mod cursor;
mod model;

pub use model::*;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cursor::{
    decode_diff, decode_history, diff_encoded_length, encode_diff, encode_history,
    history_encoded_length, DiffState, HistoryFrame, HistoryState,
};
use ogvcs_object_model::{
    object_id, scan_metadata, validate_semantic_object, Cbor, Error as ObjectError,
    ErrorCode as ObjectErrorCode, FileId, Limits as CborLimits, MetadataObject, ObjectKind,
    ObjectRef, ProfileRef, Registry, ValidationMode,
};
use ogvcs_path_contract::{
    path_collision_keys_with_options, validate_repository_path_with_profile, PathProfile,
};

const PERSISTENT_BASE_CHARGE: u64 = 512;
const HISTORY_FRAME_CHARGE: u64 = 256;
const HISTORY_BLACK_CHARGE: u64 = 96;
const TREE_FRAME_CHARGE: u64 = 256;
const TREE_COLOR_CHARGE: u64 = 96;
const FLAT_ENTRY_CHARGE: u64 = 384;
const PATH_INDEX_CHARGE: u64 = 128;
const MANIFEST_INDEX_CHARGE: u64 = 96;
const DESCRIPTOR_PROFILE_CHARGE: u64 = 128;
const DIFF_RECORD_CHARGE: u64 = 448;

#[derive(Debug)]
struct LoadedMetadata {
    object: MetadataObject,
    charged_bytes: u64,
}

impl LoadedMetadata {
    fn value(&self) -> &Cbor {
        self.object.value()
    }
}

#[derive(Debug)]
struct DescriptorContext {
    path_profile: PathProfile,
    content_policies: BTreeSet<ProfileRef>,
    chunk_profiles: BTreeSet<ProfileRef>,
    charged_bytes: u64,
}

#[derive(Clone, Debug)]
struct SnapshotValue {
    parents: Vec<ObjectRef>,
    root_tree: ObjectRef,
}

#[derive(Clone, Debug)]
struct RawTreeEntry {
    name: String,
    entry_kind: u8,
    file_id: FileId,
    mode: u8,
    target: ObjectRef,
    logical_bytes: u64,
    content_policy: ProfileRef,
}

#[derive(Clone, Debug)]
struct TreeFrame {
    reference: ObjectRef,
    prefix: String,
    entries: VecDeque<RawTreeEntry>,
    charged_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeColor {
    Gray,
    Black,
}

#[derive(Clone, Debug, Default)]
struct FlatSnapshot {
    by_file_id: BTreeMap<FileId, EntryView>,
    exact_paths: BTreeSet<String>,
    repository_keys: BTreeSet<String>,
    platform_keys: BTreeSet<String>,
}

struct Engine<'a, S: ImmutableObjectSource> {
    source: &'a mut S,
    generation: Generation,
    limits: Limits,
    ledger: WorkLedger,
    control: &'a OperationControl,
    registry: Registry,
}

/// Returns one deterministic post-order ancestry page. Valid merge-DAG
/// convergence is emitted once; a gray back-edge, self-parent, duplicate parent
/// inside one Snapshot, or a second zero-parent root fails closed.
pub fn history_page<S: ImmutableObjectSource>(
    source: &mut S,
    request: HistoryRequest,
    limits: Limits,
    control: &OperationControl,
    cursor: Option<&HistoryCursor>,
) -> Result<HistoryPage> {
    validate_history_request(request)?;
    validate_limits(limits)?;
    if control.is_cancelled() {
        return Err(Failure::new(FailureKind::Cancelled));
    }

    let (generation, ledger, mut state) = match cursor {
        Some(cursor) => {
            let mut state = decode_history(cursor.as_bytes(), limits.max_cursor_bytes)?;
            if state.request != request || state.limits != limits {
                return Err(Failure::new(FailureKind::CursorOptionsMismatch));
            }
            account_cursor_decode(
                &mut state.ledger,
                cursor.as_bytes().len(),
                checked_usize_add(state.frames.len(), state.black.len())?,
                limits,
            )?;
            (state.generation, state.ledger, state)
        }
        None => {
            let generation = source
                .generation()
                .map_err(|_| Failure::new(FailureKind::SourceFailure))?;
            let ledger = WorkLedger {
                generation_checks: 1,
                work_units: 1,
                charged_memory_bytes: PERSISTENT_BASE_CHARGE,
                peak_charged_memory_bytes: PERSISTENT_BASE_CHARGE,
                ..WorkLedger::default()
            };
            (
                generation,
                ledger,
                HistoryState {
                    generation,
                    request,
                    limits,
                    ledger,
                    frames: Vec::new(),
                    black: BTreeSet::new(),
                },
            )
        }
    };

    let mut engine = Engine::new(source, generation, limits, ledger, control);
    engine.check_generation()?;

    if state.frames.is_empty() {
        engine.load_descriptor_path_profile(request.repository_descriptor)?;
        let snapshot = engine.load_snapshot(request.start_snapshot, request)?;
        let charge = history_frame_charge(&snapshot.parents)?;
        engine.admit_persistent(charge)?;
        state.frames.push(HistoryFrame {
            snapshot: request.start_snapshot,
            root_tree: snapshot.root_tree,
            depth: 0,
            next_parent: 0,
            parents: snapshot.parents,
        });
    }

    let mut records = Vec::new();
    let page_maximum = checked_usize(limits.page_records)?;
    while records.len() < page_maximum && !state.frames.is_empty() {
        engine.check_cancel()?;
        engine.work(1)?;
        let top_index = state.frames.len() - 1;
        let next_index = usize::from(state.frames[top_index].next_parent);
        if next_index < state.frames[top_index].parents.len() {
            let parent = state.frames[top_index].parents[next_index];
            state.frames[top_index].next_parent = state.frames[top_index]
                .next_parent
                .checked_add(1)
                .ok_or_else(arithmetic_failure)?;
            engine.ledger.snapshot_edges =
                checked_add(engine.ledger.snapshot_edges, 1, LimitKind::Arithmetic)?;
            if state.black.contains(&parent) {
                continue;
            }
            if engine.history_stack_contains(&state.frames, parent)? {
                return Err(Failure::for_reference(
                    FailureKind::Corrupt(CorruptKind::SnapshotParentCycle),
                    parent,
                ));
            }
            let snapshot = engine.load_snapshot(parent, request)?;
            let depth = state.frames[top_index]
                .depth
                .checked_add(1)
                .ok_or_else(arithmetic_failure)?;
            let charge = history_frame_charge(&snapshot.parents)?;
            engine.admit_persistent(charge)?;
            state.frames.push(HistoryFrame {
                snapshot: parent,
                root_tree: snapshot.root_tree,
                depth,
                next_parent: 0,
                parents: snapshot.parents,
            });
            let discovered =
                u64::try_from(checked_usize_add(state.frames.len(), state.black.len())?)
                    .unwrap_or(u64::MAX);
            if discovered > limits.max_history_snapshots {
                return Err(Failure::new(FailureKind::Limit(
                    LimitKind::HistorySnapshots,
                )));
            }
            continue;
        }

        let frame = state.frames.pop().expect("nonempty history stack");
        engine.release_persistent(history_frame_charge(&frame.parents)?);
        if state.black.contains(&frame.snapshot) {
            return Err(Failure::for_reference(
                FailureKind::Corrupt(CorruptKind::SnapshotParentCycle),
                frame.snapshot,
            ));
        }
        engine.admit_persistent(HISTORY_BLACK_CHARGE)?;
        state.black.insert(frame.snapshot);
        engine.ledger.emitted_records =
            checked_add(engine.ledger.emitted_records, 1, LimitKind::Arithmetic)?;
        records.push(HistoryRecord {
            snapshot: frame.snapshot,
            root_tree: frame.root_tree,
            parent_count: u8::try_from(frame.parents.len()).map_err(|_| arithmetic_failure())?,
            depth: frame.depth,
        });
    }

    // The view may be invalidated while the last in-memory record is being
    // prepared. Fence once more before any page or cursor can escape.
    engine.check_generation()?;

    if state.frames.is_empty() && !state.black.contains(&request.designated_root) {
        return Err(Failure::new(FailureKind::Corrupt(
            CorruptKind::SnapshotSecondRoot,
        )));
    }

    let complete = state.frames.is_empty();
    let next = if complete {
        engine.ledger.charged_memory_bytes = 0;
        None
    } else {
        state.ledger = engine.ledger;
        let cursor = finalize_history_cursor(&mut state)?;
        engine.ledger = state.ledger;
        Some(HistoryCursor(cursor))
    };
    Ok(HistoryPage {
        generation,
        records,
        next,
        complete,
        ledger: engine.ledger,
    })
}

/// Returns one deterministic snapshot-diff page. On the first call both
/// snapshots and their complete root-Tree projections are validated before any
/// record or resumable cursor is returned.
pub fn diff_page<S: ImmutableObjectSource>(
    source: &mut S,
    request: DiffRequest,
    limits: Limits,
    control: &OperationControl,
    cursor: Option<&DiffCursor>,
) -> Result<DiffPage> {
    validate_diff_request(request)?;
    validate_limits(limits)?;
    if control.is_cancelled() {
        return Err(Failure::new(FailureKind::Cancelled));
    }

    let (generation, ledger, mut state) = match cursor {
        Some(cursor) => {
            let mut state = decode_diff(cursor.as_bytes(), limits.max_cursor_bytes)?;
            if state.request != request || state.limits != limits {
                return Err(Failure::new(FailureKind::CursorOptionsMismatch));
            }
            account_cursor_decode(
                &mut state.ledger,
                cursor.as_bytes().len(),
                state.records.len(),
                limits,
            )?;
            (state.generation, state.ledger, state)
        }
        None => {
            let generation = source
                .generation()
                .map_err(|_| Failure::new(FailureKind::SourceFailure))?;
            let ledger = WorkLedger {
                generation_checks: 1,
                work_units: 1,
                charged_memory_bytes: PERSISTENT_BASE_CHARGE,
                peak_charged_memory_bytes: PERSISTENT_BASE_CHARGE,
                ..WorkLedger::default()
            };
            (
                generation,
                ledger,
                DiffState {
                    generation,
                    request,
                    limits,
                    ledger,
                    path_profile: String::new(),
                    position: 0,
                    records: Vec::new(),
                },
            )
        }
    };
    let mut engine = Engine::new(source, generation, limits, ledger, control);
    engine.check_generation()?;

    if state.path_profile.is_empty() {
        let descriptor = engine.load_descriptor_context(request.repository_descriptor)?;
        let path_profile = descriptor.path_profile;
        let before_snapshot = engine.load_snapshot_for_diff(request.before_snapshot, request)?;
        let after_snapshot = engine.load_snapshot_for_diff(request.after_snapshot, request)?;
        let mut manifests = BTreeMap::new();
        let before = engine.flatten_tree(
            before_snapshot.root_tree,
            request,
            &descriptor,
            &mut manifests,
        )?;
        let after = engine.flatten_tree(
            after_snapshot.root_tree,
            request,
            &descriptor,
            &mut manifests,
        )?;
        engine.release_persistent(descriptor.charged_bytes);
        state.records = engine.classify_diff(before, after)?;
        state.path_profile = path_profile.as_str().to_owned();
        for record in &state.records {
            engine.check_cancel()?;
            validate_diff_record(record, path_profile, request.case_mode)?;
        }
        state.ledger = engine.ledger;
    } else {
        let path_profile = PathProfile::parse(&state.path_profile)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        for record in &state.records {
            engine.check_cancel()?;
            validate_diff_record(record, path_profile, request.case_mode)?;
        }
    }

    let page_maximum = limits.page_records;
    let mut records = Vec::new();
    while state.position < u64::try_from(state.records.len()).unwrap_or(u64::MAX)
        && u64::try_from(records.len()).unwrap_or(u64::MAX) < page_maximum
    {
        engine.check_cancel()?;
        engine.work(1)?;
        let index = checked_usize(state.position)?;
        records.push(state.records[index].clone());
        state.position = checked_add(state.position, 1, LimitKind::Arithmetic)?;
        engine.ledger.emitted_records =
            checked_add(engine.ledger.emitted_records, 1, LimitKind::Arithmetic)?;
    }

    // A resumed page can otherwise release records after its single opening
    // generation check even if the caller invalidates the view mid-page.
    engine.check_generation()?;

    let complete = state.position == u64::try_from(state.records.len()).unwrap_or(u64::MAX);
    let next = if complete {
        engine.ledger.charged_memory_bytes = 0;
        None
    } else {
        state.ledger = engine.ledger;
        let cursor = finalize_diff_cursor(&mut state)?;
        engine.ledger = state.ledger;
        Some(DiffCursor(cursor))
    };
    Ok(DiffPage {
        generation,
        path_profile: state.path_profile,
        records,
        next,
        complete,
        ledger: engine.ledger,
    })
}

impl<'a, S: ImmutableObjectSource> Engine<'a, S> {
    fn new(
        source: &'a mut S,
        generation: Generation,
        limits: Limits,
        ledger: WorkLedger,
        control: &'a OperationControl,
    ) -> Self {
        Self {
            source,
            generation,
            limits,
            ledger,
            control,
            registry: Registry::bundled(),
        }
    }

    fn check_cancel(&mut self) -> Result<()> {
        self.ledger.cancellation_checks =
            checked_add(self.ledger.cancellation_checks, 1, LimitKind::Arithmetic)?;
        if self.control.is_cancelled() {
            Err(Failure::new(FailureKind::Cancelled))
        } else {
            Ok(())
        }
    }

    fn check_generation(&mut self) -> Result<()> {
        self.check_cancel()?;
        self.work(1)?;
        self.ledger.generation_checks =
            checked_add(self.ledger.generation_checks, 1, LimitKind::Arithmetic)?;
        let current = self
            .source
            .generation()
            .map_err(|_| Failure::new(FailureKind::SourceFailure))?;
        if current == self.generation {
            Ok(())
        } else {
            Err(Failure::new(FailureKind::GenerationChanged))
        }
    }

    fn history_stack_contains(
        &mut self,
        frames: &[HistoryFrame],
        candidate: ObjectRef,
    ) -> Result<bool> {
        for frame in frames {
            self.check_cancel()?;
            self.work(1)?;
            self.ledger.comparisons =
                checked_add(self.ledger.comparisons, 1, LimitKind::Arithmetic)?;
            if frame.snapshot == candidate {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn work(&mut self, units: u64) -> Result<()> {
        self.ledger.work_units = checked_add(self.ledger.work_units, units, LimitKind::WorkUnits)?;
        if self.ledger.work_units > self.limits.max_work_units {
            Err(Failure::new(FailureKind::Limit(LimitKind::WorkUnits)))
        } else {
            Ok(())
        }
    }

    fn admit_persistent(&mut self, bytes: u64) -> Result<()> {
        let next = checked_add(
            self.ledger.charged_memory_bytes,
            bytes,
            LimitKind::ChargedMemory,
        )?;
        if next > self.limits.max_charged_memory_bytes {
            return Err(Failure::new(FailureKind::Limit(LimitKind::ChargedMemory)));
        }
        self.ledger.charged_memory_bytes = next;
        self.ledger.peak_charged_memory_bytes = self.ledger.peak_charged_memory_bytes.max(next);
        Ok(())
    }

    fn release_persistent(&mut self, bytes: u64) {
        self.ledger.charged_memory_bytes = self
            .ledger
            .charged_memory_bytes
            .checked_sub(bytes)
            .expect("persistent history/diff charges are balanced");
    }

    fn ensure_transient_capacity(&self, bytes: u64) -> Result<()> {
        let peak = checked_add(
            self.ledger.charged_memory_bytes,
            bytes,
            LimitKind::ChargedMemory,
        )?;
        if peak > self.limits.max_charged_memory_bytes {
            Err(Failure::new(FailureKind::Limit(LimitKind::ChargedMemory)))
        } else {
            Ok(())
        }
    }

    fn load_metadata(
        &mut self,
        reference: ObjectRef,
        expected: ObjectKind,
    ) -> Result<LoadedMetadata> {
        self.check_cancel()?;
        if reference.kind != expected {
            return Err(Failure::for_reference(
                FailureKind::Corrupt(CorruptKind::ReferenceKind),
                reference,
            ));
        }
        self.check_generation()?;
        self.ledger.source_reads =
            checked_add(self.ledger.source_reads, 1, LimitKind::SourceReads)?;
        if self.ledger.source_reads > self.limits.max_source_reads {
            return Err(Failure::new(FailureKind::Limit(LimitKind::SourceReads)));
        }
        self.work(1)?;
        let maximum_transient = self
            .limits
            .max_object_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.limits.max_decode_working_bytes))
            .and_then(|value| value.checked_add(512))
            .ok_or_else(arithmetic_failure)?;
        // The source owns its allocation mechanism, so reserve the complete
        // allowed return/decode envelope before asking it to allocate. The
        // exact returned capacity is charged after the source responds.
        self.ensure_transient_capacity(maximum_transient)?;
        let read = self
            .source
            .read_object(&reference, self.limits.max_object_bytes)
            .map_err(|_| Failure::new(FailureKind::SourceFailure))?;
        if read.generation != self.generation {
            return Err(Failure::for_reference(
                FailureKind::GenerationChanged,
                reference,
            ));
        }
        let payload = match read.outcome {
            ObjectReadOutcome::Found(payload) => payload,
            ObjectReadOutcome::Missing => {
                return Err(Failure::for_reference(
                    FailureKind::Missing(MissingKind::Object),
                    reference,
                ))
            }
            ObjectReadOutcome::Ambiguous => {
                return Err(Failure::for_reference(
                    FailureKind::Ambiguous(AmbiguousKind::Source),
                    reference,
                ))
            }
            ObjectReadOutcome::ByteLimit { .. } => {
                return Err(Failure::for_reference(
                    FailureKind::Limit(LimitKind::ObjectBytes),
                    reference,
                ))
            }
        };
        let length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let capacity = u64::try_from(payload.capacity()).unwrap_or(u64::MAX);
        if length > self.limits.max_object_bytes || capacity > self.limits.max_object_bytes {
            return Err(Failure::for_reference(
                FailureKind::Limit(LimitKind::ObjectBytes),
                reference,
            ));
        }
        self.ledger.source_bytes =
            checked_add(self.ledger.source_bytes, length, LimitKind::SourceBytes)?;
        if self.ledger.source_bytes > self.limits.max_source_bytes {
            return Err(Failure::new(FailureKind::Limit(LimitKind::SourceBytes)));
        }
        let transient = capacity
            .checked_add(length)
            .and_then(|value| value.checked_add(self.limits.max_decode_working_bytes))
            .and_then(|value| value.checked_add(512))
            .ok_or_else(arithmetic_failure)?;
        self.admit_persistent(transient)?;
        self.work(4)?;
        let digest = object_id(reference.kind, &payload).map_err(|_| {
            Failure::for_reference(FailureKind::Corrupt(CorruptKind::ObjectIdentity), reference)
        })?;
        if digest != reference.digest {
            return Err(Failure::for_reference(
                FailureKind::Corrupt(CorruptKind::ObjectIdentity),
                reference,
            ));
        }
        let configured = CborLimits {
            max_input_bytes: checked_usize(self.limits.max_object_bytes)?,
            max_value_bytes: checked_usize(self.limits.max_object_bytes)?,
            max_nesting: CborLimits::METADATA.max_nesting,
            // Tree-entry and history-node ceilings are semantic operation
            // limits, not generic CBOR-map/array limits. Reusing them here can
            // make a valid one-node request reject its descriptor map before
            // the relevant semantic counter is reached.
            max_container_items: CborLimits::METADATA.max_container_items,
            max_working_bytes: checked_usize(self.limits.max_decode_working_bytes)?,
        };
        let scanned = scan_metadata(&payload, CborLimits::METADATA.constrained_by(configured))
            .map_err(|error| map_object_error(reference, error))?;
        // OGVCS-002 currently has no production Snapshot/identity/policy/content
        // writer profile set. This private candidate therefore consumes an
        // explicitly conformance-scoped immutable view. It must not be wired to
        // production reads until those profile assignments exist.
        let semantic =
            validate_semantic_object(&scanned, &self.registry, ValidationMode::Conformance)
                .map_err(|error| map_object_error(reference, error))?;
        if semantic.kind != expected {
            return Err(Failure::for_reference(
                FailureKind::Corrupt(CorruptKind::ReferenceKind),
                reference,
            ));
        }
        self.check_generation()?;
        self.ledger.metadata_objects =
            checked_add(self.ledger.metadata_objects, 1, LimitKind::Arithmetic)?;
        Ok(LoadedMetadata {
            object: scanned,
            charged_bytes: transient,
        })
    }

    fn load_descriptor_path_profile(&mut self, reference: ObjectRef) -> Result<PathProfile> {
        let loaded = self.load_metadata(reference, ObjectKind::RepositoryDescriptor)?;
        let result = descriptor_path_profile(loaded.value());
        self.release_persistent(loaded.charged_bytes);
        result
    }

    fn load_descriptor_context(&mut self, reference: ObjectRef) -> Result<DescriptorContext> {
        let loaded = self.load_metadata(reference, ObjectKind::RepositoryDescriptor)?;
        let result = (|| {
            let path_profile = descriptor_path_profile(loaded.value())?;
            let content_values = array(field(loaded.value(), 18)?)?;
            let chunk_values = optional_field(loaded.value(), 20)
                .map(array)
                .transpose()?
                .unwrap_or_default();
            let charged_bytes = descriptor_context_charge(content_values, chunk_values)?;
            self.admit_persistent(charged_bytes)?;
            let content_policies = parse_profile_set(content_values)?;
            let chunk_profiles = parse_profile_set(chunk_values)?;
            Ok(DescriptorContext {
                path_profile,
                content_policies,
                chunk_profiles,
                charged_bytes,
            })
        })();
        self.release_persistent(loaded.charged_bytes);
        result
    }

    fn load_snapshot(
        &mut self,
        reference: ObjectRef,
        request: HistoryRequest,
    ) -> Result<SnapshotValue> {
        let loaded = self.load_metadata(reference, ObjectKind::Snapshot)?;
        let result = (|| {
            let snapshot = parse_snapshot(loaded.value())?;
            if snapshot_descriptor(loaded.value())? != request.repository_descriptor {
                return Err(Failure::for_reference(
                    FailureKind::Corrupt(CorruptKind::RepositoryDescriptor),
                    reference,
                ));
            }
            validate_snapshot_root(reference, &snapshot.parents, request.designated_root)?;
            Ok(snapshot)
        })();
        self.release_persistent(loaded.charged_bytes);
        result
    }

    fn load_snapshot_for_diff(
        &mut self,
        reference: ObjectRef,
        request: DiffRequest,
    ) -> Result<SnapshotValue> {
        let loaded = self.load_metadata(reference, ObjectKind::Snapshot)?;
        let result = (|| {
            let snapshot = parse_snapshot(loaded.value())?;
            if snapshot_descriptor(loaded.value())? != request.repository_descriptor {
                return Err(Failure::for_reference(
                    FailureKind::Corrupt(CorruptKind::RepositoryDescriptor),
                    reference,
                ));
            }
            Ok(snapshot)
        })();
        self.release_persistent(loaded.charged_bytes);
        result
    }

    fn validate_manifest_once(
        &mut self,
        reference: ObjectRef,
        descriptor: &DescriptorContext,
        manifests: &mut BTreeMap<ObjectRef, u64>,
    ) -> Result<u64> {
        if let Some(logical_bytes) = manifests.get(&reference) {
            return Ok(*logical_bytes);
        }
        let loaded = self.load_metadata(reference, ObjectKind::ContentManifest)?;
        let result = (|| {
            let logical_bytes = uint(field(loaded.value(), 16)?)?;
            let chunk_profile = ProfileRef::from_cbor(field(loaded.value(), 18)?)
                .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
            if !descriptor.chunk_profiles.contains(&chunk_profile) {
                return Err(Failure::for_reference(
                    FailureKind::Corrupt(CorruptKind::RepositoryDescriptor),
                    reference,
                ));
            }
            Ok(logical_bytes)
        })();
        self.release_persistent(loaded.charged_bytes);
        let logical_bytes = result?;
        self.admit_persistent(MANIFEST_INDEX_CHARGE)?;
        manifests.insert(reference, logical_bytes);
        Ok(logical_bytes)
    }

    fn flatten_tree(
        &mut self,
        root: ObjectRef,
        request: DiffRequest,
        descriptor: &DescriptorContext,
        manifests: &mut BTreeMap<ObjectRef, u64>,
    ) -> Result<FlatSnapshot> {
        let mut result = FlatSnapshot::default();
        let mut colors = BTreeMap::<ObjectRef, TreeColor>::new();
        let starting_entries = self.ledger.tree_entries;
        let root_frame = self.load_tree_frame(root, String::new(), request)?;
        self.admit_persistent(TREE_COLOR_CHARGE)?;
        colors.insert(root, TreeColor::Gray);
        let mut stack = vec![root_frame];

        while !stack.is_empty() {
            self.check_cancel()?;
            self.work(1)?;
            let top_index = stack.len() - 1;
            if stack[top_index].entries.is_empty() {
                let frame = stack.pop().expect("nonempty tree stack");
                self.release_persistent(frame.charged_bytes);
                colors.insert(frame.reference, TreeColor::Black);
                continue;
            }
            let entry = stack[top_index]
                .entries
                .pop_front()
                .expect("nonempty Tree entry queue");
            self.ledger.tree_entries =
                checked_add(self.ledger.tree_entries, 1, LimitKind::TreeEntries)?;
            if self
                .ledger
                .tree_entries
                .checked_sub(starting_entries)
                .is_none_or(|count| count > self.limits.max_tree_entries)
            {
                return Err(Failure::new(FailureKind::Limit(LimitKind::TreeEntries)));
            }
            let path = join_path(&stack[top_index].prefix, &entry.name)?;
            let keys = path_collision_keys_with_options(
                path.as_str(),
                descriptor.path_profile,
                request.case_mode,
            )
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Path)))?;
            let canonical = keys.path().canonical().to_owned();
            let repository_key = keys.repository_key().as_str().to_owned();
            let platform_key = keys.platform_key().to_owned();
            if result.by_file_id.contains_key(&entry.file_id) {
                return Err(Failure::new(FailureKind::Ambiguous(
                    AmbiguousKind::DuplicateFileId,
                )));
            }
            if !descriptor.content_policies.contains(&entry.content_policy) {
                return Err(Failure::new(FailureKind::Corrupt(
                    CorruptKind::RepositoryDescriptor,
                )));
            }
            if result.exact_paths.contains(&canonical) {
                return Err(Failure::new(FailureKind::Ambiguous(
                    AmbiguousKind::DuplicatePath,
                )));
            }
            if result.repository_keys.contains(&repository_key) {
                return Err(Failure::new(FailureKind::Ambiguous(
                    AmbiguousKind::RepositoryPathCollision,
                )));
            }
            if result.platform_keys.contains(&platform_key) {
                return Err(Failure::new(FailureKind::Ambiguous(
                    AmbiguousKind::PlatformPathCollision,
                )));
            }
            let entry_charge = flat_entry_charge(&canonical, &entry.content_policy)?;
            let index_charge = path_index_charge(&canonical, &repository_key, &platform_key)?;
            self.admit_persistent(checked_add(
                entry_charge,
                index_charge,
                LimitKind::ChargedMemory,
            )?)?;
            let view = EntryView {
                path: canonical.clone(),
                entry_kind: entry.entry_kind,
                mode: entry.mode,
                target: entry.target,
                logical_bytes: entry.logical_bytes,
                content_policy: entry.content_policy,
            };
            result.exact_paths.insert(canonical);
            result.repository_keys.insert(repository_key);
            result.platform_keys.insert(platform_key);
            result.by_file_id.insert(entry.file_id, view);

            if entry.entry_kind == 1 {
                self.ledger.tree_edges =
                    checked_add(self.ledger.tree_edges, 1, LimitKind::TreeObjects)?;
                match colors.get(&entry.target) {
                    Some(TreeColor::Gray) => {
                        return Err(Failure::for_reference(
                            FailureKind::Corrupt(CorruptKind::TreeCycle),
                            entry.target,
                        ))
                    }
                    Some(TreeColor::Black) => {
                        return Err(Failure::for_reference(
                            FailureKind::Ambiguous(AmbiguousKind::SharedTree),
                            entry.target,
                        ))
                    }
                    None => {}
                }
                if u64::try_from(colors.len()).unwrap_or(u64::MAX) >= self.limits.max_tree_objects {
                    return Err(Failure::new(FailureKind::Limit(LimitKind::TreeObjects)));
                }
                let frame = self.load_tree_frame(entry.target, path, request)?;
                self.admit_persistent(TREE_COLOR_CHARGE)?;
                colors.insert(entry.target, TreeColor::Gray);
                stack.push(frame);
            } else {
                let manifest_bytes =
                    self.validate_manifest_once(entry.target, descriptor, manifests)?;
                if manifest_bytes != entry.logical_bytes {
                    return Err(Failure::for_reference(
                        FailureKind::Corrupt(CorruptKind::TreeEntryTarget),
                        entry.target,
                    ));
                }
            }
        }
        let color_charge = u64::try_from(colors.len())
            .unwrap_or(u64::MAX)
            .checked_mul(TREE_COLOR_CHARGE)
            .ok_or_else(arithmetic_failure)?;
        self.release_persistent(color_charge);
        Ok(result)
    }

    fn load_tree_frame(
        &mut self,
        reference: ObjectRef,
        prefix: String,
        request: DiffRequest,
    ) -> Result<TreeFrame> {
        let loaded = self.load_metadata(reference, ObjectKind::Tree)?;
        let result = (|| {
            if tree_descriptor(loaded.value())? != request.repository_descriptor {
                return Err(Failure::for_reference(
                    FailureKind::Corrupt(CorruptKind::RepositoryDescriptor),
                    reference,
                ));
            }
            let raw_entries = array(field(loaded.value(), 17)?)?;
            let charged_bytes = tree_frame_cbor_charge(&prefix, raw_entries)?;
            // Reserve the complete retained frame before cloning any decoded
            // Tree entry into the traversal representation.
            self.admit_persistent(charged_bytes)?;
            let entries = parse_tree_entries(loaded.value())?;
            Ok(TreeFrame {
                reference,
                prefix,
                entries,
                charged_bytes,
            })
        })();
        self.release_persistent(loaded.charged_bytes);
        result
    }

    fn classify_diff(
        &mut self,
        before: FlatSnapshot,
        after: FlatSnapshot,
    ) -> Result<Vec<DiffRecord>> {
        let mut before_ids = before.by_file_id.keys().peekable();
        let mut after_ids = after.by_file_id.keys().peekable();
        let mut records = Vec::new();
        loop {
            let file_id = match (before_ids.peek(), after_ids.peek()) {
                (Some(left), Some(right)) => match left.cmp(right) {
                    std::cmp::Ordering::Less => *before_ids.next().expect("peeked before FileID"),
                    std::cmp::Ordering::Equal => {
                        let value = *before_ids.next().expect("peeked before FileID");
                        after_ids.next();
                        value
                    }
                    std::cmp::Ordering::Greater => *after_ids.next().expect("peeked after FileID"),
                },
                (Some(_), None) => *before_ids.next().expect("peeked before FileID"),
                (None, Some(_)) => *after_ids.next().expect("peeked after FileID"),
                (None, None) => break,
            };
            self.check_cancel()?;
            self.work(1)?;
            self.ledger.comparisons =
                checked_add(self.ledger.comparisons, 1, LimitKind::Arithmetic)?;
            let before_entry = before.by_file_id.get(&file_id);
            let after_entry = after.by_file_id.get(&file_id);
            if before_entry == after_entry {
                continue;
            }
            let charge = diff_record_charge_from_views(before_entry, after_entry)?;
            // The returned record allocation becomes the retained record; make
            // its exact model fit before `classify_entry` clones either view.
            self.ensure_transient_capacity(charge)?;
            let record = classify_entry(file_id, before_entry, after_entry);
            if let Some(record) = record {
                if u64::try_from(records.len()).unwrap_or(u64::MAX) >= self.limits.max_diff_records
                {
                    return Err(Failure::new(FailureKind::Limit(LimitKind::DiffRecords)));
                }
                self.admit_persistent(charge)?;
                records.push(record);
            }
        }
        Ok(records)
    }
}

fn validate_history_request(request: HistoryRequest) -> Result<()> {
    if request.start_snapshot.kind != ObjectKind::Snapshot
        || request.designated_root.kind != ObjectKind::Snapshot
        || request.repository_descriptor.kind != ObjectKind::RepositoryDescriptor
    {
        Err(Failure::new(FailureKind::Corrupt(
            CorruptKind::ReferenceKind,
        )))
    } else {
        Ok(())
    }
}

fn validate_diff_request(request: DiffRequest) -> Result<()> {
    if request.before_snapshot.kind != ObjectKind::Snapshot
        || request.after_snapshot.kind != ObjectKind::Snapshot
        || request.repository_descriptor.kind != ObjectKind::RepositoryDescriptor
    {
        Err(Failure::new(FailureKind::Corrupt(
            CorruptKind::ReferenceKind,
        )))
    } else {
        Ok(())
    }
}

fn validate_limits(limits: Limits) -> Result<()> {
    if limits.is_valid() {
        Ok(())
    } else {
        Err(Failure::new(FailureKind::Limit(LimitKind::Configuration)))
    }
}

fn descriptor_path_profile(value: &Cbor) -> Result<PathProfile> {
    let profile = ProfileRef::from_cbor(field(value, 17)?)
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
    PathProfile::parse(&profile.to_string())
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::SemanticProfile)))
}

fn snapshot_descriptor(value: &Cbor) -> Result<ObjectRef> {
    ObjectRef::from_cbor(field(value, 16)?)
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))
}

fn tree_descriptor(value: &Cbor) -> Result<ObjectRef> {
    snapshot_descriptor(value)
}

fn parse_snapshot(value: &Cbor) -> Result<SnapshotValue> {
    let parents_value = array(field(value, 17)?)?;
    let mut parents = Vec::with_capacity(parents_value.len());
    let mut unique = BTreeSet::new();
    for value in parents_value {
        let parent = ObjectRef::from_cbor(value)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
        if parent.kind != ObjectKind::Snapshot {
            return Err(Failure::new(FailureKind::Corrupt(
                CorruptKind::ReferenceKind,
            )));
        }
        if !unique.insert(parent) {
            return Err(Failure::new(FailureKind::Corrupt(
                CorruptKind::SnapshotParentDuplicate,
            )));
        }
        parents.push(parent);
    }
    let root_tree = ObjectRef::from_cbor(field(value, 18)?)
        .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
    if root_tree.kind != ObjectKind::Tree {
        return Err(Failure::new(FailureKind::Corrupt(
            CorruptKind::SnapshotRoot,
        )));
    }
    Ok(SnapshotValue { parents, root_tree })
}

fn validate_snapshot_root(
    reference: ObjectRef,
    parents: &[ObjectRef],
    designated_root: ObjectRef,
) -> Result<()> {
    if parents.iter().any(|parent| *parent == reference) {
        return Err(Failure::for_reference(
            FailureKind::Corrupt(CorruptKind::SnapshotParentCycle),
            reference,
        ));
    }
    if reference == designated_root && !parents.is_empty() {
        return Err(Failure::for_reference(
            FailureKind::Corrupt(CorruptKind::SnapshotRoot),
            reference,
        ));
    }
    if reference != designated_root && parents.is_empty() {
        return Err(Failure::for_reference(
            FailureKind::Corrupt(CorruptKind::SnapshotSecondRoot),
            reference,
        ));
    }
    Ok(())
}

fn parse_tree_entries(value: &Cbor) -> Result<VecDeque<RawTreeEntry>> {
    let values = array(field(value, 17)?)?;
    let mut entries = VecDeque::with_capacity(values.len());
    for value in values {
        let name = text(field(value, 0)?)?.to_owned();
        let entry_kind = checked_u8(uint(field(value, 1)?)?)?;
        let file_id = FileId::from_cbor(field(value, 2)?)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
        let mode = checked_u8(uint(field(value, 3)?)?)?;
        let target = ObjectRef::from_cbor(field(value, 4)?)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
        let logical_bytes = uint(field(value, 5)?)?;
        let content_policy = ProfileRef::from_cbor(field(value, 6)?)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
        if !(1..=4).contains(&entry_kind)
            || mode != entry_kind
            || (entry_kind == 1 && target.kind != ObjectKind::Tree)
            || (entry_kind != 1 && target.kind != ObjectKind::ContentManifest)
        {
            return Err(Failure::new(FailureKind::Corrupt(
                CorruptKind::ReferenceKind,
            )));
        }
        entries.push_back(RawTreeEntry {
            name,
            entry_kind,
            file_id,
            mode,
            target,
            logical_bytes,
            content_policy,
        });
    }
    Ok(entries)
}

fn classify_entry(
    file_id: FileId,
    before: Option<&EntryView>,
    after: Option<&EntryView>,
) -> Option<DiffRecord> {
    match (before, after) {
        (None, Some(after)) => Some(DiffRecord {
            file_id,
            before: None,
            after: Some(after.clone()),
            presence: PresenceChange::Added,
            changes: ChangeFlags::default(),
            move_hint: MoveHint::None,
        }),
        (Some(before), None) => Some(DiffRecord {
            file_id,
            before: Some(before.clone()),
            after: None,
            presence: PresenceChange::Deleted,
            changes: ChangeFlags::default(),
            move_hint: MoveHint::None,
        }),
        (Some(before), Some(after)) => {
            let mut changes = ChangeFlags::default();
            if before.target != after.target {
                if before.entry_kind == 1 || after.entry_kind == 1 {
                    changes.insert(ChangeFlags::TREE_METADATA);
                }
                if before.entry_kind != 1 || after.entry_kind != 1 {
                    changes.insert(ChangeFlags::CONTENT_MANIFEST);
                }
            }
            if before.entry_kind != after.entry_kind {
                changes.insert(ChangeFlags::ENTRY_TYPE);
            }
            if before.mode != after.mode {
                changes.insert(ChangeFlags::MODE);
            }
            if before.content_policy != after.content_policy {
                changes.insert(ChangeFlags::CONTENT_POLICY);
            }
            if before.logical_bytes != after.logical_bytes {
                changes.insert(ChangeFlags::LOGICAL_SIZE);
            }
            let move_hint = if before.path != after.path {
                changes.insert(ChangeFlags::PATH);
                if parent_path(&before.path) == parent_path(&after.path) {
                    MoveHint::Rename
                } else {
                    MoveHint::Move
                }
            } else {
                MoveHint::None
            };
            (!changes.is_empty()).then(|| DiffRecord {
                file_id,
                before: Some(before.clone()),
                after: Some(after.clone()),
                presence: PresenceChange::Retained,
                changes,
                move_hint,
            })
        }
        (None, None) => None,
    }
}

fn validate_diff_record(
    record: &DiffRecord,
    path_profile: PathProfile,
    case_mode: ogvcs_path_contract::CaseMode,
) -> Result<()> {
    for entry in [&record.before, &record.after].into_iter().flatten() {
        validate_repository_path_with_profile(&entry.path, path_profile)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        path_collision_keys_with_options(&entry.path, path_profile, case_mode)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))?;
        if !(1..=4).contains(&entry.entry_kind)
            || entry.mode != entry.entry_kind
            || (entry.entry_kind == 1 && entry.target.kind != ObjectKind::Tree)
            || (entry.entry_kind != 1 && entry.target.kind != ObjectKind::ContentManifest)
        {
            return Err(Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)));
        }
    }
    let expected = classify_entry(
        record.file_id,
        record.before.as_ref(),
        record.after.as_ref(),
    );
    if expected.as_ref() == Some(record) {
        Ok(())
    } else {
        Err(Failure::new(FailureKind::Corrupt(CorruptKind::Cursor)))
    }
}

fn field(value: &Cbor, key: u64) -> Result<&Cbor> {
    let Cbor::Map(fields) = value else {
        return Err(Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)));
    };
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == Cbor::UInt(key)).then_some(value))
        .ok_or_else(|| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))
}

fn optional_field(value: &Cbor, key: u64) -> Option<&Cbor> {
    let Cbor::Map(fields) = value else {
        return None;
    };
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == Cbor::UInt(key)).then_some(value))
}

fn array(value: &Cbor) -> Result<&[Cbor]> {
    let Cbor::Array(values) = value else {
        return Err(Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)));
    };
    Ok(values)
}

fn text(value: &Cbor) -> Result<&str> {
    let Cbor::Text(value) = value else {
        return Err(Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)));
    };
    Ok(value)
}

fn uint(value: &Cbor) -> Result<u64> {
    let Cbor::UInt(value) = value else {
        return Err(Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)));
    };
    Ok(*value)
}

fn join_path(prefix: &str, basename: &str) -> Result<String> {
    let length = prefix
        .len()
        .checked_add(usize::from(!prefix.is_empty()))
        .and_then(|value| value.checked_add(basename.len()))
        .ok_or_else(arithmetic_failure)?;
    let mut path = String::with_capacity(length);
    if !prefix.is_empty() {
        path.push_str(prefix);
        path.push('/');
    }
    path.push_str(basename);
    Ok(path)
}

fn parent_path(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn map_object_error(reference: ObjectRef, error: ObjectError) -> Failure {
    if error.code == ObjectErrorCode::LimitMemory {
        return Failure::for_reference(FailureKind::Limit(LimitKind::ChargedMemory), reference);
    }
    let kind = match error.code {
        ObjectErrorCode::ObjectIdMismatch => CorruptKind::ObjectIdentity,
        ObjectErrorCode::ObjectReferenceKindMismatch => CorruptKind::ReferenceKind,
        ObjectErrorCode::SnapshotParentDuplicate => CorruptKind::SnapshotParentDuplicate,
        ObjectErrorCode::SnapshotParentCycle => CorruptKind::SnapshotParentCycle,
        _ if error.layer <= 1 => CorruptKind::CanonicalFraming,
        _ if error.layer == 2 => CorruptKind::KnownSchema,
        _ => CorruptKind::SemanticProfile,
    };
    Failure::for_reference(FailureKind::Corrupt(kind), reference)
}

fn account_cursor_decode(
    ledger: &mut WorkLedger,
    bytes: usize,
    records: usize,
    limits: Limits,
) -> Result<()> {
    ledger.cursor_bytes_decoded = checked_add(
        ledger.cursor_bytes_decoded,
        u64::try_from(bytes).unwrap_or(u64::MAX),
        LimitKind::Arithmetic,
    )?;
    ledger.cursor_records_decoded = checked_add(
        ledger.cursor_records_decoded,
        u64::try_from(records).unwrap_or(u64::MAX),
        LimitKind::Arithmetic,
    )?;
    ledger.work_units = checked_add(
        ledger.work_units,
        u64::try_from(records).unwrap_or(u64::MAX),
        LimitKind::WorkUnits,
    )?;
    if ledger.work_units > limits.max_work_units {
        Err(Failure::new(FailureKind::Limit(LimitKind::WorkUnits)))
    } else {
        Ok(())
    }
}

fn finalize_history_cursor(state: &mut HistoryState) -> Result<Vec<u8>> {
    let modeled = history_state_charge(state)?;
    state.ledger.charged_memory_bytes = modeled;
    state.ledger.peak_charged_memory_bytes = state
        .ledger
        .peak_charged_memory_bytes
        .max(state.ledger.charged_memory_bytes);
    let encoded_length = history_encoded_length(state)?;
    finalize_cursor_accounting(&mut state.ledger, encoded_length, state.limits, modeled)?;
    encode_history(state)
}

fn finalize_diff_cursor(state: &mut DiffState) -> Result<Vec<u8>> {
    let modeled = diff_state_charge(state)?;
    state.ledger.charged_memory_bytes = modeled;
    state.ledger.peak_charged_memory_bytes = state.ledger.peak_charged_memory_bytes.max(modeled);
    let encoded_length = diff_encoded_length(state)?;
    finalize_cursor_accounting(&mut state.ledger, encoded_length, state.limits, modeled)?;
    encode_diff(state)
}

fn finalize_cursor_accounting(
    ledger: &mut WorkLedger,
    bytes: usize,
    limits: Limits,
    modeled_state: u64,
) -> Result<()> {
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    let cursor_charge = bytes
        .checked_add(PERSISTENT_BASE_CHARGE)
        .ok_or_else(arithmetic_failure)?;
    if bytes > limits.max_cursor_bytes {
        return Err(Failure::new(FailureKind::Limit(LimitKind::CursorBytes)));
    }
    let encoding_peak = modeled_state
        .checked_add(cursor_charge)
        .ok_or_else(arithmetic_failure)?;
    if encoding_peak > limits.max_charged_memory_bytes {
        return Err(Failure::new(FailureKind::Limit(LimitKind::ChargedMemory)));
    }
    ledger.cursor_bytes_encoded =
        checked_add(ledger.cursor_bytes_encoded, bytes, LimitKind::Arithmetic)?;
    ledger.charged_memory_bytes = modeled_state.max(cursor_charge);
    ledger.peak_charged_memory_bytes = ledger.peak_charged_memory_bytes.max(encoding_peak);
    Ok(())
}

fn history_state_charge(state: &HistoryState) -> Result<u64> {
    let mut charge = PERSISTENT_BASE_CHARGE;
    for frame in &state.frames {
        charge = checked_add(
            charge,
            history_frame_charge(&frame.parents)?,
            LimitKind::ChargedMemory,
        )?;
    }
    checked_add(
        charge,
        u64::try_from(state.black.len())
            .unwrap_or(u64::MAX)
            .checked_mul(HISTORY_BLACK_CHARGE)
            .ok_or_else(arithmetic_failure)?,
        LimitKind::ChargedMemory,
    )
}

fn diff_state_charge(state: &DiffState) -> Result<u64> {
    let mut charge = PERSISTENT_BASE_CHARGE
        .checked_add(u64::try_from(state.path_profile.len()).unwrap_or(u64::MAX))
        .ok_or_else(arithmetic_failure)?;
    for record in &state.records {
        charge = checked_add(
            charge,
            diff_record_charge(record)?,
            LimitKind::ChargedMemory,
        )?;
    }
    Ok(charge)
}

fn history_frame_charge(parents: &[ObjectRef]) -> Result<u64> {
    HISTORY_FRAME_CHARGE
        .checked_add(
            u64::try_from(parents.len())
                .unwrap_or(u64::MAX)
                .checked_mul(34)
                .ok_or_else(arithmetic_failure)?,
        )
        .ok_or_else(arithmetic_failure)
}

fn tree_frame_cbor_charge(prefix: &str, entries: &[Cbor]) -> Result<u64> {
    let mut charge = TREE_FRAME_CHARGE
        .checked_add(u64::try_from(prefix.len()).unwrap_or(u64::MAX))
        .ok_or_else(arithmetic_failure)?;
    for entry in entries {
        let name = text(field(entry, 0)?)?;
        let profile_length = profile_display_length(field(entry, 6)?)?;
        charge = charge
            .checked_add(256)
            .and_then(|value| value.checked_add(u64::try_from(name.len()).unwrap_or(u64::MAX)))
            .and_then(|value| value.checked_add(profile_length))
            .ok_or_else(arithmetic_failure)?;
    }
    Ok(charge)
}

fn descriptor_context_charge(content: &[Cbor], chunks: &[Cbor]) -> Result<u64> {
    let mut charge = 0u64;
    for profile in content.iter().chain(chunks) {
        let profile_length = profile_display_length(profile)?;
        charge = charge
            .checked_add(DESCRIPTOR_PROFILE_CHARGE)
            .and_then(|value| value.checked_add(profile_length))
            .ok_or_else(arithmetic_failure)?;
    }
    Ok(charge)
}

fn parse_profile_set(values: &[Cbor]) -> Result<BTreeSet<ProfileRef>> {
    let mut profiles = BTreeSet::new();
    for value in values {
        let profile = ProfileRef::from_cbor(value)
            .map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))?;
        if !profiles.insert(profile) {
            return Err(Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)));
        }
    }
    Ok(profiles)
}

fn profile_display_length(value: &Cbor) -> Result<u64> {
    let namespace = text(field(value, 0)?)?;
    let id = text(field(value, 1)?)?;
    let major = uint(field(value, 2)?)?;
    let digits = if major == 0 {
        1
    } else {
        u64::from(major.ilog10()) + 1
    };
    u64::try_from(namespace.len())
        .unwrap_or(u64::MAX)
        .checked_add(1)
        .and_then(|length| length.checked_add(u64::try_from(id.len()).unwrap_or(u64::MAX)))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(digits))
        .ok_or_else(arithmetic_failure)
}

fn flat_entry_charge(path: &str, profile: &ProfileRef) -> Result<u64> {
    FLAT_ENTRY_CHARGE
        .checked_add(u64::try_from(path.len()).unwrap_or(u64::MAX))
        .and_then(|value| {
            value.checked_add(u64::try_from(profile.to_string().len()).unwrap_or(u64::MAX))
        })
        .ok_or_else(arithmetic_failure)
}

fn path_index_charge(path: &str, repository: &str, platform: &str) -> Result<u64> {
    PATH_INDEX_CHARGE
        .checked_mul(3)
        .and_then(|value| value.checked_add(u64::try_from(path.len()).unwrap_or(u64::MAX)))
        .and_then(|value| value.checked_add(u64::try_from(repository.len()).unwrap_or(u64::MAX)))
        .and_then(|value| value.checked_add(u64::try_from(platform.len()).unwrap_or(u64::MAX)))
        .ok_or_else(arithmetic_failure)
}

fn diff_record_charge(record: &DiffRecord) -> Result<u64> {
    diff_record_charge_from_views(record.before.as_ref(), record.after.as_ref())
}

fn diff_record_charge_from_views(
    before: Option<&EntryView>,
    after: Option<&EntryView>,
) -> Result<u64> {
    let mut charge = DIFF_RECORD_CHARGE;
    for entry in [before, after].into_iter().flatten() {
        charge = charge
            .checked_add(u64::try_from(entry.path.len()).unwrap_or(u64::MAX))
            .and_then(|value| {
                value.checked_add(
                    u64::try_from(entry.content_policy.to_string().len()).unwrap_or(u64::MAX),
                )
            })
            .ok_or_else(arithmetic_failure)?;
    }
    Ok(charge)
}

fn checked_add(value: u64, amount: u64, kind: LimitKind) -> Result<u64> {
    value
        .checked_add(amount)
        .ok_or_else(|| Failure::new(FailureKind::Limit(kind)))
}

fn checked_usize(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| Failure::new(FailureKind::Limit(LimitKind::Arithmetic)))
}

fn checked_usize_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).ok_or_else(arithmetic_failure)
}

fn checked_u8(value: u64) -> Result<u8> {
    u8::try_from(value).map_err(|_| Failure::new(FailureKind::Corrupt(CorruptKind::KnownSchema)))
}

fn arithmetic_failure() -> Failure {
    Failure::new(FailureKind::Limit(LimitKind::Arithmetic))
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
    fn graph_color_classifier_distinguishes_cycle_shared_and_new() {
        let tree = reference(ObjectKind::Tree, 1);
        let other = reference(ObjectKind::Tree, 2);
        let mut colors = BTreeMap::new();
        colors.insert(tree, TreeColor::Gray);
        assert_eq!(colors.get(&tree), Some(&TreeColor::Gray));
        colors.insert(tree, TreeColor::Black);
        assert_eq!(colors.get(&tree), Some(&TreeColor::Black));
        assert_eq!(colors.get(&other), None);
    }

    #[test]
    fn typed_self_parent_is_rejected_even_without_a_representable_hash_fixed_point() {
        let snapshot = reference(ObjectKind::Snapshot, 7);
        assert_eq!(
            validate_snapshot_root(snapshot, &[snapshot], snapshot)
                .unwrap_err()
                .kind,
            FailureKind::Corrupt(CorruptKind::SnapshotParentCycle)
        );
    }
}
