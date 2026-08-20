//! Deterministic, resource-bounded emission of format-v1 logical bundles.
//!
//! The header precedes the data it describes, so callers supply the frozen
//! counts and declaration budgets in [`LogicalBundleWritePlan`]. Items are
//! then accepted in their normative order. The writer retains only counters,
//! the current item, and the immediately previous sort keys; it never retains
//! the complete bundle or object graph.

use core::cmp::Ordering;
use std::{
    io::{self, ErrorKind, Write},
    time::{Duration, Instant},
};

use crate::hard_limits::{
    configured_hard_limit, enforce_hard_limit_context, MAX_BUNDLE_INDEX_ENTRIES,
    MAX_BUNDLE_ITEM_BYTES, MAX_BUNDLE_LOGICAL_RECORDS, MAX_BUNDLE_OBJECTS, MAX_BUNDLE_ROOTS,
    MAX_BUNDLE_SEQUENCE_BYTES, MAX_BUNDLE_TOTAL_ITEMS, MAX_BUNDLE_TRAVERSAL_EDGES,
    MAX_CBOR_NESTING, MAX_CHUNK_BYTES, MAX_GENERIC_VALUE_BYTES, MAX_MANIFEST_CHUNKS,
    MAX_METADATA_BYTES,
};
use crate::{
    bundle_verify::{
        visit_schema_logical_record_references, visit_schema_object_references,
        visit_validated_logical_record_references, visit_validated_object_references,
    },
    encode_canonical_with_limits, logical_record_id, object_id, opaque_object_digest,
    scan_metadata, validate_logical_record, validate_metadata_schema, BundleTranscriptHashWriter,
    Cbor, Error, ErrorCode, Limits, ObjectKind, ObjectRef, Operation, ProfileRef, Registry,
    RegistryAssignment, Result, TypedDigest, ValidationStage,
};
use crate::registry::require_write_operation;
const DEFAULT_MAX_MEMORY_BYTES: usize = 67_108_864;
const DEFAULT_MAX_ELAPSED: Duration = Duration::from_secs(600);
const FIXED_WRITER_MEMORY_BYTES: usize = 4_096;
const WRITE_CHECKPOINT_BYTES: usize = 65_536;

/// The four declarations encoded in bundle-header field 6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalBundleBudget {
    pub sequence_bytes: u64,
    pub largest_item_bytes: u64,
    pub traversal_edges: u64,
    pub index_entries: u64,
}

/// Frozen header counts and declarations for one deterministic sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalBundleWritePlan {
    pub object_count: u64,
    pub logical_record_count: u64,
    pub root_count: u64,
    pub budget: LogicalBundleBudget,
}

/// Receiver/deployment ceilings applied in addition to the format maxima.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalBundleWriteLimits {
    pub sequence_bytes: u64,
    pub item_bytes: u64,
    pub objects: u64,
    pub logical_records: u64,
    pub roots: u64,
    pub items: u64,
    pub traversal_edges: u64,
    pub index_entries: u64,
    pub chunk_bytes: usize,
    pub metadata_bytes: usize,
    pub value_bytes: usize,
    pub container_items: usize,
    pub nesting: usize,
    /// Maximum temporary memory retained by the writer itself. Borrowed
    /// caller-owned payloads and values are not charged a second time.
    pub max_memory_bytes: usize,
    /// Wall-clock deadline measured from writer construction.
    pub max_elapsed: Duration,
}

impl LogicalBundleWriteLimits {
    pub const HARD: Self = Self {
        sequence_bytes: MAX_BUNDLE_SEQUENCE_BYTES,
        item_bytes: MAX_BUNDLE_ITEM_BYTES,
        objects: MAX_BUNDLE_OBJECTS,
        logical_records: MAX_BUNDLE_LOGICAL_RECORDS,
        roots: MAX_BUNDLE_ROOTS,
        items: MAX_BUNDLE_TOTAL_ITEMS,
        traversal_edges: MAX_BUNDLE_TRAVERSAL_EDGES,
        index_entries: MAX_BUNDLE_INDEX_ENTRIES,
        chunk_bytes: MAX_CHUNK_BYTES as usize,
        metadata_bytes: MAX_METADATA_BYTES as usize,
        value_bytes: MAX_GENERIC_VALUE_BYTES as usize,
        container_items: MAX_MANIFEST_CHUNKS as usize,
        nesting: MAX_CBOR_NESTING as usize,
        max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
        max_elapsed: DEFAULT_MAX_ELAPSED,
    };

    fn constrained(self) -> Result<Self> {
        Ok(Self {
            sequence_bytes: configured_hard_limit("bundle-sequence-bytes", self.sequence_bytes)?,
            item_bytes: configured_hard_limit("bundle-largest-item-bytes", self.item_bytes)?,
            objects: configured_hard_limit("bundle-objects", self.objects)?,
            logical_records: configured_hard_limit("bundle-logical-records", self.logical_records)?,
            roots: configured_hard_limit("bundle-roots", self.roots)?,
            items: configured_hard_limit("bundle-total-items", self.items)?,
            traversal_edges: configured_hard_limit("bundle-traversal-edges", self.traversal_edges)?,
            index_entries: configured_hard_limit("bundle-index-entries", self.index_entries)?,
            chunk_bytes: configured_usize("chunk-payload-bytes", self.chunk_bytes)?,
            metadata_bytes: configured_usize("metadata-payload-bytes", self.metadata_bytes)?,
            value_bytes: configured_usize("generic-text-or-byte-value-bytes", self.value_bytes)?,
            container_items: configured_usize("manifest-chunks", self.container_items)?,
            nesting: configured_usize("cbor-nesting-depth", self.nesting)?,
            max_memory_bytes: self.max_memory_bytes,
            max_elapsed: self.max_elapsed,
        })
    }
}

impl Default for LogicalBundleWriteLimits {
    fn default() -> Self {
        Self::HARD
    }
}

/// Registry context and deployment ceilings for bundle emission.
#[derive(Clone, Copy)]
pub struct LogicalBundleWriteOptions<'a> {
    pub registry: &'a Registry,
    pub operation: Operation,
    pub limits: LogicalBundleWriteLimits,
}

impl<'a> LogicalBundleWriteOptions<'a> {
    pub fn new(registry: &'a Registry, operation: Operation) -> Self {
        Self {
            registry,
            operation,
            limits: LogicalBundleWriteLimits::default(),
        }
    }
}

/// Privacy-safe accounting returned after the trailer has been flushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalBundleWriteSummary {
    pub bytes: u64,
    pub items: u64,
    pub largest_item_bytes: u64,
    pub object_count: u64,
    pub logical_record_count: u64,
    pub root_count: u64,
    pub traversal_edges: u64,
    pub index_entries: u64,
    pub transcript_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Objects,
    LogicalRecords,
    Roots,
    Trailer,
    Finished,
    Failed,
}

/// Stateful writer for one `logical-bundle-v1` CBOR sequence.
///
/// Objects, logical records, and roots must already be in normative order.
/// Any rejected item poisons the attempt: bytes already written belong only
/// to the caller-designated staging sink and cannot later be committed by
/// replacing the rejected item and finishing the same writer.
pub struct LogicalBundleWriter<'a, W: Write> {
    output: W,
    registry: &'a Registry,
    operation: Operation,
    limits: LogicalBundleWriteLimits,
    plan: LogicalBundleWritePlan,
    phase: Phase,
    objects: u64,
    logical_records: u64,
    roots: u64,
    object_roots: u64,
    logical_roots: u64,
    items: u64,
    written: u64,
    largest_item: u64,
    traversal_edges: u64,
    trailer_bytes: u64,
    transcript: Option<BundleTranscriptHashWriter>,
    started: Instant,
    previous_object: Option<ObjectRef>,
    previous_logical: Option<(u16, [u8; 32])>,
    previous_root: Option<(u8, Vec<u8>, Vec<u8>)>,
    previous_root_identity: Option<(u8, Vec<u8>)>,
    deferred_error: Option<Error>,
}

impl<'a, W: Write> LogicalBundleWriter<'a, W> {
    /// Validates the plan and writes the header. No item declaration is
    /// interpreted as an allocation request.
    pub fn new(
        mut output: W,
        plan: LogicalBundleWritePlan,
        options: LogicalBundleWriteOptions<'a>,
    ) -> Result<Self> {
        options.registry.require_complete_authority()?;
        require_write_operation(options.operation)?;
        let started = Instant::now();
        let limits = options.limits.constrained()?;
        check_deadline(started, limits.max_elapsed)?;
        ensure_memory(limits, FIXED_WRITER_MEMORY_BYTES)?;
        validate_plan(plan, limits)?;
        validate_write_item_shape(
            options.registry,
            options.operation,
            "bundle-header",
            &[0, 1, 2, 3, 4, 5, 6],
            1,
        )?;
        validate_write_shape(
            options.registry,
            options.operation,
            "bundle-budget",
            &[0, 1, 2, 3],
        )?;
        validate_write_enum(options.registry, options.operation, "bundle-mode", 1)?;
        validate_write_item_shape(
            options.registry,
            options.operation,
            "bundle-trailer",
            &[0, 1, 2, 3, 4, 5, 6],
            5,
        )?;
        validate_write_shape(options.registry, options.operation, "typed-digest", &[0, 1])?;
        validate_write_assignment(
            options.registry,
            options.operation,
            RegistryAssignment::HashAlgorithm(1),
        )?;
        let encoding_limits = item_encoding_limits(limits);
        let header = encode_canonical_with_limits(&header_value(plan), encoding_limits)?;
        let dummy_trailer =
            encode_canonical_with_limits(&trailer_value(plan, [0; 32]), encoding_limits)?;
        let header_bytes = as_u64(header.len())?;
        let trailer_bytes = as_u64(dummy_trailer.len())?;
        check_deadline(started, limits.max_elapsed)?;
        if header_bytes > limits.item_bytes || trailer_bytes > limits.item_bytes {
            return Err(Error::new(ErrorCode::BundleBudgetExceeded));
        }
        if header_bytes > plan.budget.largest_item_bytes
            || trailer_bytes > plan.budget.largest_item_bytes
            || header_bytes
                .checked_add(trailer_bytes)
                .is_none_or(|minimum| minimum > plan.budget.sequence_bytes)
        {
            return Err(Error::new(ErrorCode::BundleBudgetExceeded)
                .with_stage(ValidationStage::DeclaredAccounting));
        }

        write_all_checked(&mut output, &header, started, limits.max_elapsed)?;
        let transcript_limit = usize::try_from(plan.budget.sequence_bytes).unwrap_or(usize::MAX);
        let mut transcript = BundleTranscriptHashWriter::new(transcript_limit);
        transcript.update(&header)?;
        let mut writer = Self {
            output,
            registry: options.registry,
            operation: options.operation,
            limits,
            plan,
            phase: Phase::Objects,
            objects: 0,
            logical_records: 0,
            roots: 0,
            object_roots: 0,
            logical_roots: 0,
            items: 1,
            written: header_bytes,
            largest_item: header_bytes,
            traversal_edges: 0,
            trailer_bytes,
            transcript: Some(transcript),
            started,
            previous_object: None,
            previous_logical: None,
            previous_root: None,
            previous_root_identity: None,
            deferred_error: None,
        };
        writer.advance_phase();
        Ok(writer)
    }

    /// Writes one immutable object wrapper while forwarding `payload`
    /// byte-for-byte. Metadata is canonical/schema checked before emission;
    /// chunks are hashed as raw bytes.
    pub fn write_object(&mut self, reference: ObjectRef, payload: &[u8]) -> Result<()> {
        let result = self.write_object_inner(reference, payload);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn write_object_inner(&mut self, reference: ObjectRef, payload: &[u8]) -> Result<()> {
        self.require_phase(Phase::Objects)?;
        self.check_time()?;
        ensure_memory(self.limits, FIXED_WRITER_MEMORY_BYTES)?;
        if let Some(previous) = self.previous_object {
            match previous.cmp(&reference) {
                Ordering::Equal => {
                    return Err(Error::new(ErrorCode::BundleDuplicateIdentity));
                }
                Ordering::Greater => {
                    return Err(Error::new(ErrorCode::BundleSequenceInvalid));
                }
                Ordering::Less => {}
            }
        }
        let envelope = validate_write_item_shape(
            self.registry,
            self.operation,
            "bundle-object",
            &[0, 1, 2, 3, 4],
            2,
        );
        self.observe_deferred(envelope)?;
        let reference_shape =
            validate_write_shape(self.registry, self.operation, "object-ref", &[0, 1, 2, 3]);
        self.observe_deferred(reference_shape)?;
        let kind_assignment = validate_write_assignment(
            self.registry,
            self.operation,
            RegistryAssignment::ObjectKind(reference.kind.code()),
        );
        self.observe_deferred(kind_assignment)?;
        let hash_assignment = validate_write_assignment(
            self.registry,
            self.operation,
            RegistryAssignment::HashAlgorithm(1),
        );
        self.observe_deferred(hash_assignment)?;
        let ordinal = self.objects;
        let payload_maximum = if reference.kind == ObjectKind::Chunk {
            self.limits.chunk_bytes
        } else {
            self.limits.metadata_bytes
        };
        let (limit_name, limit_code) = if reference.kind == ObjectKind::Chunk {
            ("chunk-payload-bytes", ErrorCode::LimitChunkBytes)
        } else {
            ("metadata-payload-bytes", ErrorCode::LimitMetadataBytes)
        };
        enforce_hard_limit_context(
            limit_name,
            as_u64(payload.len())?,
            u64::try_from(payload_maximum).unwrap_or(u64::MAX),
            limit_code,
            1,
        )?;
        let actual_digest = if reference.kind == ObjectKind::Chunk {
            object_id(reference.kind, payload)?
        } else {
            opaque_object_digest(reference.kind.code(), payload)?
        };
        if actual_digest != reference.digest {
            self.record_deferred(Error::new(ErrorCode::ObjectIdMismatch));
        }
        let mut edges = 0u64;
        if reference.kind != ObjectKind::Chunk {
            let retained = payload
                .len()
                .checked_mul(16)
                .and_then(|value| value.checked_add(FIXED_WRITER_MEMORY_BYTES))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            ensure_memory(self.limits, retained)?;
            let scanned = scan_metadata(
                payload,
                metadata_limits_with_retained(self.limits, payload.len())?,
            )?;
            if scanned.framing().numeric_kind != reference.kind.code() {
                self.record_deferred(
                    Error::new(ErrorCode::ObjectReferenceKindMismatch)
                        .with_stage(ValidationStage::KnownSchema),
                );
            }
            let schema_result = validate_metadata_schema(&scanned);
            let actual_kind = self.observe_deferred(schema_result)?;
            if let Some(actual_kind) = actual_kind {
                if actual_kind != reference.kind {
                    self.record_deferred(
                        Error::new(ErrorCode::ObjectReferenceKindMismatch)
                            .with_stage(ValidationStage::KnownSchema),
                    );
                } else {
                    let mut emit = |_reference: ObjectRef| {
                        edges = edges.checked_add(1).ok_or_else(|| {
                            Error::new(ErrorCode::BundleBudgetExceeded)
                                .with_stage(ValidationStage::DeclaredAccounting)
                        })?;
                        Ok(())
                    };
                    let schema = visit_schema_object_references(
                        actual_kind,
                        scanned.value(),
                        self.registry,
                        self.operation,
                        &mut emit,
                    );
                    if self.observe_deferred(schema)?.is_some() {
                        let mut ignore = |_reference: ObjectRef| Ok(());
                        let semantics = visit_validated_object_references(
                            actual_kind,
                            scanned.value(),
                            self.registry,
                            self.operation,
                            &mut ignore,
                        );
                        self.observe_deferred(semantics)?;
                    }
                }
            }
        }
        self.check_edges(edges)?;
        self.check_time()?;
        let reference_bytes = encode_canonical_with_limits(
            &reference.to_cbor(),
            nested_item_encoding_limits(self.limits)?,
        )?;
        let mut prefix = vec![0xa5, 0x00, 0x01, 0x01, 0x02, 0x02];
        append_head(&mut prefix, 0, ordinal);
        prefix.push(0x03);
        prefix.extend_from_slice(&reference_bytes);
        prefix.push(0x04);
        append_head(&mut prefix, 2, as_u64(payload.len())?);
        self.emit_transcript_item(&[&prefix, payload])?;
        self.objects += 1;
        self.traversal_edges += edges;
        self.previous_object = Some(reference);
        self.advance_phase();
        Ok(())
    }

    /// Validates, identifies, and writes one typed logical record. The
    /// computed SHA-256 typed identity is returned for use by a later root.
    pub fn write_logical_record(&mut self, record: &Cbor) -> Result<TypedDigest> {
        let result = self.write_logical_record_inner(record);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn write_logical_record_inner(&mut self, record: &Cbor) -> Result<TypedDigest> {
        self.require_phase(Phase::LogicalRecords)?;
        self.check_time()?;
        ensure_memory(self.limits, FIXED_WRITER_MEMORY_BYTES)?;
        let ordinal = self.logical_records;
        let measurement_limits = nested_metadata_encoding_limits(self.limits)?;
        let record_length = crate::encode_canonical_to(record, io::sink(), measurement_limits)?;
        if record_length
            .checked_add(FIXED_WRITER_MEMORY_BYTES)
            .is_none_or(|retained| retained > self.limits.max_memory_bytes)
        {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        self.check_time()?;
        let record_bytes = encode_canonical_with_limits(
            record,
            encoding_limits_with_retained(measurement_limits, self.limits, record_length)?,
        )?;
        // The numeric record type and canonical bytes are enough to derive the
        // declared sort identity. Do that before the full layer-two schema
        // pass so a safely hashable early schema error cannot hide a later
        // duplicate or descending identity in this section.
        let record_type = raw_logical_record_type(record)?;
        let identity = logical_record_id(record_type, &record_bytes)?;
        let sort_key = (record_type, identity);
        if let Some(previous) = self.previous_logical {
            match previous.cmp(&sort_key) {
                Ordering::Equal => {
                    return Err(Error::new(ErrorCode::BundleDuplicateIdentity));
                }
                Ordering::Greater => {
                    return Err(Error::new(ErrorCode::BundleSequenceInvalid));
                }
                Ordering::Less => {}
            }
        }
        // Complete phase, identity, duplicate, and ordering checks before any
        // registry lifecycle decision derived from this item.
        let schema = validate_logical_record(
            &record_bytes,
            metadata_limits_with_retained(self.limits, record_bytes.len())?,
        );
        let schema_valid = self.observe_deferred(schema)?.is_some();
        let item_shape = validate_write_item_shape(
            self.registry,
            self.operation,
            "bundle-logical-record",
            &[0, 1, 2, 3, 4],
            3,
        );
        self.observe_deferred(item_shape)?;
        let digest_shape =
            validate_write_shape(self.registry, self.operation, "typed-digest", &[0, 1]);
        self.observe_deferred(digest_shape)?;
        let hash_assignment = validate_write_assignment(
            self.registry,
            self.operation,
            RegistryAssignment::HashAlgorithm(1),
        );
        self.observe_deferred(hash_assignment)?;
        let mut edges = 0u64;
        if schema_valid {
            let mut emit = |_reference: ObjectRef| {
                edges = edges.checked_add(1).ok_or_else(|| {
                    Error::new(ErrorCode::BundleBudgetExceeded)
                        .with_stage(ValidationStage::DeclaredAccounting)
                })?;
                Ok(())
            };
            let schema = visit_schema_logical_record_references(
                record_type,
                record,
                self.registry,
                self.operation,
                &mut emit,
            );
            if self.observe_deferred(schema)?.is_some() {
                let mut ignore = |_reference: ObjectRef| Ok(());
                let semantics = visit_validated_logical_record_references(
                    record_type,
                    record,
                    self.registry,
                    self.operation,
                    &mut ignore,
                );
                self.observe_deferred(semantics)?;
            }
        }
        self.check_edges(edges)?;
        self.check_time()?;

        let typed = TypedDigest::sha256(identity);
        let identity_bytes = encode_canonical_with_limits(
            &typed.to_cbor(),
            nested_item_encoding_limits(self.limits)?,
        )?;
        let mut prefix = vec![0xa5, 0x00, 0x01, 0x01, 0x03, 0x02];
        append_head(&mut prefix, 0, ordinal);
        prefix.push(0x03);
        prefix.extend_from_slice(&identity_bytes);
        prefix.push(0x04);
        self.emit_transcript_item(&[&prefix, &record_bytes])?;
        self.logical_records += 1;
        self.traversal_edges += edges;
        self.previous_logical = Some(sort_key);
        self.advance_phase();
        Ok(typed)
    }

    /// Writes a kind-1 root for an immutable object identity.
    pub fn write_object_root(&mut self, identity: ObjectRef, role: &ProfileRef) -> Result<()> {
        let result = self.write_object_root_inner(identity, role);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn write_object_root_inner(&mut self, identity: ObjectRef, role: &ProfileRef) -> Result<()> {
        self.require_phase(Phase::Roots)?;
        let identity_bytes = encode_canonical_with_limits(
            &identity.to_cbor(),
            nested_item_encoding_limits(self.limits)?,
        )?;
        self.write_root(1, identity_bytes, role, Some(identity.kind.code()))?;
        self.object_roots += 1;
        Ok(())
    }

    /// Writes a kind-2 root for a typed logical-record identity.
    pub fn write_logical_record_root(
        &mut self,
        identity: TypedDigest,
        role: &ProfileRef,
    ) -> Result<()> {
        let result = self.write_logical_record_root_inner(identity, role);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn write_logical_record_root_inner(
        &mut self,
        identity: TypedDigest,
        role: &ProfileRef,
    ) -> Result<()> {
        self.require_phase(Phase::Roots)?;
        let identity_bytes = encode_canonical_with_limits(
            &identity.to_cbor(),
            nested_item_encoding_limits(self.limits)?,
        )?;
        self.write_root(2, identity_bytes, role, None)?;
        self.logical_roots += 1;
        Ok(())
    }

    /// Writes the integrity trailer and flushes the sink. A successful result
    /// is wire-integrity evidence, not a supplied-closure or export claim.
    pub fn finish(&mut self) -> Result<LogicalBundleWriteSummary> {
        let result = self.finish_inner();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn finish_inner(&mut self) -> Result<LogicalBundleWriteSummary> {
        self.require_phase(Phase::Trailer)?;
        self.check_time()?;
        if (self.plan.object_count != 0 && self.object_roots == 0)
            || self.logical_roots != self.plan.logical_record_count
        {
            self.record_deferred(
                Error::new(ErrorCode::BundleRootInvalid)
                    .with_stage(ValidationStage::ClosureAndReferenceResolution),
            );
        }
        if let Some(error) = self.deferred_error.take() {
            return Err(error);
        }
        let transcript = self
            .transcript
            .take()
            .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?
            .finish()?;
        let digest = *transcript.digest();
        let trailer = encode_canonical_with_limits(
            &trailer_value(self.plan, digest),
            item_encoding_limits(self.limits),
        )?;
        if as_u64(trailer.len())? != self.trailer_bytes {
            self.phase = Phase::Failed;
            return Err(Error::new(ErrorCode::BundleSequenceInvalid));
        }
        self.emit_trailer(&trailer)?;
        self.output.flush().map_err(|_| {
            self.phase = Phase::Failed;
            Error::new(ErrorCode::SchemaFieldInvalid)
        })?;
        if let Err(error) = self.check_time() {
            self.phase = Phase::Failed;
            return Err(error);
        }
        self.phase = Phase::Finished;
        Ok(LogicalBundleWriteSummary {
            bytes: self.written,
            items: self.items,
            largest_item_bytes: self.largest_item,
            object_count: self.objects,
            logical_record_count: self.logical_records,
            root_count: self.roots,
            traversal_edges: self.traversal_edges,
            index_entries: self.objects + self.logical_records,
            transcript_digest: digest,
        })
    }

    /// Returns the underlying sink. Callers should only consume its bytes as a
    /// bundle after [`finish`](Self::finish) succeeds.
    pub fn into_inner(self) -> W {
        self.output
    }

    fn write_root(
        &mut self,
        kind: u8,
        identity_bytes: Vec<u8>,
        role: &ProfileRef,
        object_kind: Option<u16>,
    ) -> Result<()> {
        self.require_phase(Phase::Roots)?;
        self.check_time()?;
        ensure_memory(self.limits, FIXED_WRITER_MEMORY_BYTES)?;
        let role_bytes = encode_canonical_with_limits(
            &role.to_cbor(),
            nested_item_encoding_limits(self.limits)?,
        )?;
        let sort_key = (kind, identity_bytes.clone(), role_bytes.clone());
        if self
            .previous_root
            .as_ref()
            .is_some_and(|previous| previous >= &sort_key)
        {
            return Err(Error::new(ErrorCode::BundleSequenceInvalid));
        }
        let identity_key = (kind, identity_bytes.clone());
        if self
            .previous_root_identity
            .as_ref()
            .is_some_and(|previous| previous == &identity_key)
        {
            return Err(Error::new(ErrorCode::BundleDuplicateIdentity));
        }

        // Registry assignments and role lifecycle are layer-three work. They
        // cannot hide a wrong phase, duplicate, or descending root.
        let item_shape = validate_write_item_shape(
            self.registry,
            self.operation,
            "bundle-root",
            &[0, 1, 2, 3, 4, 5],
            4,
        );
        self.observe_deferred(item_shape)?;
        let root_kind = validate_write_enum(
            self.registry,
            self.operation,
            "bundle-root-kind",
            u32::from(kind),
        );
        self.observe_deferred(root_kind)?;
        if let Some(object_kind) = object_kind {
            let object_ref =
                validate_write_shape(self.registry, self.operation, "object-ref", &[0, 1, 2, 3]);
            self.observe_deferred(object_ref)?;
            let object_kind = validate_write_assignment(
                self.registry,
                self.operation,
                RegistryAssignment::ObjectKind(object_kind),
            );
            self.observe_deferred(object_kind)?;
        } else {
            let typed_digest =
                validate_write_shape(self.registry, self.operation, "typed-digest", &[0, 1]);
            self.observe_deferred(typed_digest)?;
        }
        let hash_assignment = validate_write_assignment(
            self.registry,
            self.operation,
            RegistryAssignment::HashAlgorithm(1),
        );
        self.observe_deferred(hash_assignment)?;
        let profile_shape =
            validate_write_shape(self.registry, self.operation, "profile-ref", &[0, 1, 2]);
        self.observe_deferred(profile_shape)?;
        let role_result = validate_root_role(self.registry, self.operation, role);
        self.observe_deferred(role_result)?;

        let ordinal = self.roots;
        let mut prefix = vec![0xa6, 0x00, 0x01, 0x01, 0x04, 0x02];
        append_head(&mut prefix, 0, ordinal);
        prefix.extend_from_slice(&[0x03, kind, 0x04]);
        prefix.extend_from_slice(&identity_bytes);
        prefix.push(0x05);
        prefix.extend_from_slice(&role_bytes);
        self.emit_transcript_item(&[&prefix])?;
        self.roots += 1;
        self.previous_root = Some(sort_key);
        self.previous_root_identity = Some(identity_key);
        self.advance_phase();
        Ok(())
    }

    fn record_deferred(&mut self, error: Error) {
        if self
            .deferred_error
            .as_ref()
            .is_none_or(|current| error.precedence_key() < current.precedence_key())
        {
            self.deferred_error = Some(error);
        }
    }

    fn observe_deferred<T>(&mut self, result: Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error)
                if matches!(
                    error.stage,
                    ValidationStage::DeclaredIdentity
                        | ValidationStage::KnownSchema
                        | ValidationStage::RegistrySemantics
                ) =>
            {
                self.record_deferred(error);
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn check_edges(&self, additional: u64) -> Result<()> {
        let total = self
            .traversal_edges
            .checked_add(additional)
            .ok_or_else(|| {
                Error::new(ErrorCode::BundleBudgetExceeded)
                    .with_stage(ValidationStage::DeclaredAccounting)
            })?;
        bundle_limit("bundle-traversal-edges", total, self.limits.traversal_edges)?;
        if total > self.plan.budget.traversal_edges {
            Err(Error::new(ErrorCode::BundleBudgetExceeded)
                .with_stage(ValidationStage::DeclaredAccounting))
        } else {
            Ok(())
        }
    }

    fn emit_transcript_item(&mut self, parts: &[&[u8]]) -> Result<()> {
        let length = parts.iter().try_fold(0u64, |total, part| {
            total.checked_add(as_u64(part.len())?).ok_or_else(|| {
                Error::new(ErrorCode::BundleBudgetExceeded)
                    .with_stage(ValidationStage::DeclaredAccounting)
            })
        })?;
        self.check_item_length(length, true)?;
        for part in parts {
            self.write_transcript_bytes(part)?;
        }
        self.written += length;
        self.items += 1;
        self.largest_item = self.largest_item.max(length);
        Ok(())
    }

    fn emit_trailer(&mut self, trailer: &[u8]) -> Result<()> {
        let length = as_u64(trailer.len())?;
        self.check_item_length(length, false)?;
        self.write_output_bytes(trailer)?;
        self.written += length;
        self.items += 1;
        self.largest_item = self.largest_item.max(length);
        Ok(())
    }

    fn check_item_length(&self, length: u64, reserve_trailer: bool) -> Result<()> {
        bundle_limit("bundle-largest-item-bytes", length, self.limits.item_bytes)?;
        if length > self.plan.budget.largest_item_bytes {
            return Err(Error::new(ErrorCode::BundleBudgetExceeded)
                .with_stage(ValidationStage::DeclaredAccounting));
        }
        let reserved = if reserve_trailer {
            self.trailer_bytes
        } else {
            0
        };
        let total = self
            .written
            .checked_add(length)
            .and_then(|total| total.checked_add(reserved))
            .ok_or_else(|| {
                Error::new(ErrorCode::BundleBudgetExceeded)
                    .with_layer(1)
                    .with_stage(ValidationStage::DeclaredAccounting)
            })?;
        bundle_limit("bundle-sequence-bytes", total, self.limits.sequence_bytes)?;
        if total > self.plan.budget.sequence_bytes {
            Err(Error::new(ErrorCode::BundleBudgetExceeded)
                .with_stage(ValidationStage::DeclaredAccounting))
        } else {
            Ok(())
        }
    }

    fn require_phase(&self, expected: Phase) -> Result<()> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(Error::new(ErrorCode::BundleSequenceInvalid))
        }
    }

    fn check_time(&self) -> Result<()> {
        check_deadline(self.started, self.limits.max_elapsed)
    }

    fn write_transcript_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let end = offset
                .saturating_add(WRITE_CHECKPOINT_BYTES)
                .min(bytes.len());
            self.write_output_bytes(&bytes[offset..end])?;
            if self
                .transcript
                .as_mut()
                .ok_or_else(|| Error::new(ErrorCode::BundleSequenceInvalid))?
                .update(&bytes[offset..end])
                .is_err()
            {
                self.phase = Phase::Failed;
                return Err(Error::new(ErrorCode::BundleBudgetExceeded)
                    .with_stage(ValidationStage::DeclaredAccounting));
            }
            offset = end;
        }
        Ok(())
    }

    fn write_output_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if let Err(error) = self.check_time() {
                self.phase = Phase::Failed;
                return Err(error);
            }
            let chunk_len = remaining.len().min(WRITE_CHECKPOINT_BYTES);
            match self.output.write(&remaining[..chunk_len]) {
                Ok(0) => {
                    self.phase = Phase::Failed;
                    return Err(Error::new(ErrorCode::SchemaFieldInvalid));
                }
                Ok(written) => {
                    remaining = &remaining[written..];
                    if let Err(error) = self.check_time() {
                        self.phase = Phase::Failed;
                        return Err(error);
                    }
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    self.phase = Phase::Failed;
                    return Err(Error::new(ErrorCode::SchemaFieldInvalid));
                }
            }
        }
        Ok(())
    }

    fn advance_phase(&mut self) {
        loop {
            self.phase = match self.phase {
                Phase::Objects if self.objects == self.plan.object_count => Phase::LogicalRecords,
                Phase::LogicalRecords if self.logical_records == self.plan.logical_record_count => {
                    Phase::Roots
                }
                Phase::Roots if self.roots == self.plan.root_count => Phase::Trailer,
                phase => phase,
            };
            if !matches!(
                self.phase,
                Phase::Objects | Phase::LogicalRecords | Phase::Roots
            ) || (self.phase == Phase::Objects && self.objects != self.plan.object_count)
                || (self.phase == Phase::LogicalRecords
                    && self.logical_records != self.plan.logical_record_count)
                || (self.phase == Phase::Roots && self.roots != self.plan.root_count)
            {
                break;
            }
        }
    }
}

fn validate_write_assignment(
    registry: &Registry,
    operation: Operation,
    assignment: RegistryAssignment<'_>,
) -> Result<()> {
    registry
        .check_assignment_if_present(assignment, operation)
        .map(|_| ())
}

fn validate_write_shape(
    registry: &Registry,
    operation: Operation,
    rule: &str,
    fields: &[u16],
) -> Result<()> {
    for &code in fields {
        validate_write_assignment(
            registry,
            operation,
            RegistryAssignment::KindField {
                cddl_rule: rule,
                code,
            },
        )?;
    }
    Ok(())
}

fn validate_write_enum(
    registry: &Registry,
    operation: Operation,
    domain: &str,
    code: u32,
) -> Result<()> {
    validate_write_assignment(
        registry,
        operation,
        RegistryAssignment::SemanticEnum { domain, code },
    )
}

fn validate_write_item_shape(
    registry: &Registry,
    operation: Operation,
    rule: &str,
    fields: &[u16],
    item_type: u32,
) -> Result<()> {
    validate_write_shape(registry, operation, rule, fields)?;
    validate_write_enum(registry, operation, "bundle-item-type", item_type)
}

fn raw_logical_record_type(value: &Cbor) -> Result<u16> {
    let Cbor::Map(fields) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_stage(ValidationStage::KnownSchema));
    };
    let value = fields
        .iter()
        .find_map(|(key, value)| matches!(key, Cbor::UInt(1)).then_some(value))
        .ok_or_else(|| {
            Error::new(ErrorCode::SchemaFieldInvalid).with_stage(ValidationStage::KnownSchema)
        })?;
    let Cbor::UInt(value) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_stage(ValidationStage::KnownSchema));
    };
    u16::try_from(*value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            Error::new(ErrorCode::LogicalRecordTypeUnsupported)
                .with_stage(ValidationStage::KnownSchema)
        })
}

fn validate_plan(plan: LogicalBundleWritePlan, limits: LogicalBundleWriteLimits) -> Result<()> {
    let items = plan
        .object_count
        .checked_add(plan.logical_record_count)
        .and_then(|count| count.checked_add(plan.root_count))
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
    let index_entries = plan
        .object_count
        .checked_add(plan.logical_record_count)
        .ok_or_else(|| Error::new(ErrorCode::BundleBudgetExceeded))?;
    for (name, value, maximum) in [
        ("bundle-objects", plan.object_count, limits.objects),
        (
            "bundle-logical-records",
            plan.logical_record_count,
            limits.logical_records,
        ),
        ("bundle-roots", plan.root_count, limits.roots),
        ("bundle-total-items", items, limits.items),
        (
            "bundle-sequence-bytes",
            plan.budget.sequence_bytes,
            limits.sequence_bytes,
        ),
        (
            "bundle-largest-item-bytes",
            plan.budget.largest_item_bytes,
            limits.item_bytes,
        ),
        (
            "bundle-traversal-edges",
            plan.budget.traversal_edges,
            limits.traversal_edges,
        ),
        (
            "bundle-index-entries",
            plan.budget.index_entries,
            limits.index_entries,
        ),
    ] {
        bundle_limit(name, value, maximum)?;
    }
    bundle_limit("bundle-index-entries", index_entries, limits.index_entries)?;
    if index_entries > plan.budget.index_entries {
        return Err(Error::new(ErrorCode::BundleBudgetExceeded)
            .with_stage(ValidationStage::DeclaredAccounting));
    }
    Ok(())
}

fn validate_root_role(registry: &Registry, operation: Operation, role: &ProfileRef) -> Result<()> {
    let entry = registry
        .profile(role)
        .ok_or_else(|| Error::new(ErrorCode::ProfileUnknown))?;
    if entry.family != "bundle-root-role" {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    registry.check_profile(role, "bundle-root-role", operation)
}

fn header_value(plan: LogicalBundleWritePlan) -> Cbor {
    Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(1)),
        (Cbor::UInt(2), Cbor::UInt(1)),
        (Cbor::UInt(3), Cbor::UInt(plan.object_count)),
        (Cbor::UInt(4), Cbor::UInt(plan.logical_record_count)),
        (Cbor::UInt(5), Cbor::UInt(plan.root_count)),
        (
            Cbor::UInt(6),
            Cbor::Map(vec![
                (Cbor::UInt(0), Cbor::UInt(plan.budget.sequence_bytes)),
                (Cbor::UInt(1), Cbor::UInt(plan.budget.largest_item_bytes)),
                (Cbor::UInt(2), Cbor::UInt(plan.budget.traversal_edges)),
                (Cbor::UInt(3), Cbor::UInt(plan.budget.index_entries)),
            ]),
        ),
    ])
}

fn trailer_value(plan: LogicalBundleWritePlan, transcript: [u8; 32]) -> Cbor {
    Cbor::Map(vec![
        (Cbor::UInt(0), Cbor::UInt(1)),
        (Cbor::UInt(1), Cbor::UInt(5)),
        (Cbor::UInt(2), Cbor::UInt(plan.object_count)),
        (Cbor::UInt(3), Cbor::UInt(plan.logical_record_count)),
        (Cbor::UInt(4), Cbor::UInt(plan.root_count)),
        (
            Cbor::UInt(5),
            Cbor::UInt(plan.object_count + plan.logical_record_count + plan.root_count + 2),
        ),
        (Cbor::UInt(6), TypedDigest::sha256(transcript).to_cbor()),
    ])
}

fn item_encoding_limits(limits: LogicalBundleWriteLimits) -> Limits {
    Limits {
        max_input_bytes: usize::try_from(limits.item_bytes).unwrap_or(usize::MAX),
        max_value_bytes: limits.value_bytes,
        max_nesting: limits.nesting,
        max_container_items: limits.container_items,
        max_working_bytes: limits
            .max_memory_bytes
            .saturating_sub(FIXED_WRITER_MEMORY_BYTES),
    }
}

fn nested_item_encoding_limits(limits: LogicalBundleWriteLimits) -> Result<Limits> {
    if limits.nesting == 0 {
        return Err(Error::new(ErrorCode::LimitNesting));
    }
    Ok(Limits {
        max_nesting: limits.nesting - 1,
        ..item_encoding_limits(limits)
    })
}

fn metadata_limits(limits: LogicalBundleWriteLimits) -> Limits {
    Limits {
        max_input_bytes: limits.metadata_bytes,
        max_value_bytes: limits.value_bytes,
        max_nesting: limits.nesting,
        max_container_items: limits.container_items,
        max_working_bytes: limits
            .max_memory_bytes
            .saturating_sub(FIXED_WRITER_MEMORY_BYTES),
    }
}

fn nested_metadata_encoding_limits(limits: LogicalBundleWriteLimits) -> Result<Limits> {
    if limits.nesting == 0 {
        return Err(Error::new(ErrorCode::LimitNesting));
    }
    Ok(Limits {
        max_input_bytes: limits.metadata_bytes,
        max_value_bytes: limits.value_bytes,
        max_nesting: limits.nesting - 1,
        max_container_items: limits.container_items,
        max_working_bytes: limits
            .max_memory_bytes
            .saturating_sub(FIXED_WRITER_MEMORY_BYTES),
    })
}

fn metadata_limits_with_retained(
    limits: LogicalBundleWriteLimits,
    retained_bytes: usize,
) -> Result<Limits> {
    let reserved = retained_bytes
        .checked_add(FIXED_WRITER_MEMORY_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    ensure_memory(limits, reserved)?;
    Ok(Limits {
        max_working_bytes: limits.max_memory_bytes - reserved,
        ..metadata_limits(limits)
    })
}

fn encoding_limits_with_retained(
    mut encoding_limits: Limits,
    limits: LogicalBundleWriteLimits,
    retained_bytes: usize,
) -> Result<Limits> {
    let reserved = retained_bytes
        .checked_add(FIXED_WRITER_MEMORY_BYTES)
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
    ensure_memory(limits, reserved)?;
    encoding_limits.max_working_bytes = limits.max_memory_bytes - reserved;
    Ok(encoding_limits)
}

fn ensure_memory(limits: LogicalBundleWriteLimits, required: usize) -> Result<()> {
    if required > limits.max_memory_bytes {
        Err(Error::new(ErrorCode::LimitMemory))
    } else {
        Ok(())
    }
}

fn check_deadline(started: Instant, maximum: Duration) -> Result<()> {
    if maximum.is_zero() || started.elapsed() > maximum {
        Err(Error::new(ErrorCode::LimitTime))
    } else {
        Ok(())
    }
}

fn write_all_checked<W: Write>(
    output: &mut W,
    bytes: &[u8],
    started: Instant,
    maximum: Duration,
) -> Result<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        check_deadline(started, maximum)?;
        let chunk_len = remaining.len().min(WRITE_CHECKPOINT_BYTES);
        match output.write(&remaining[..chunk_len]) {
            Ok(0) => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
            Ok(written) => {
                remaining = &remaining[written..];
                check_deadline(started, maximum)?;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        }
    }
    Ok(())
}

fn append_head(output: &mut Vec<u8>, major: u8, value: u64) {
    if value < 24 {
        output.push((major << 5) | value as u8);
    } else if value <= u8::MAX as u64 {
        output.extend_from_slice(&[(major << 5) | 24, value as u8]);
    } else if value <= u16::MAX as u64 {
        output.push((major << 5) | 25);
        output.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        output.push((major << 5) | 26);
        output.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        output.push((major << 5) | 27);
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn as_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::new(ErrorCode::BundleBudgetExceeded))
}

fn configured_usize(name: &'static str, configured: usize) -> Result<usize> {
    let configured = u64::try_from(configured).unwrap_or(u64::MAX);
    usize::try_from(configured_hard_limit(name, configured)?).map_err(|_| {
        Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight)
    })
}

fn bundle_limit(name: &'static str, value: u64, configured: u64) -> Result<()> {
    enforce_hard_limit_context(name, value, configured, ErrorCode::BundleBudgetExceeded, 1)
        .map(|_| ())
}
