use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::unicode_age::is_unicode_15;
use crate::{
    bundle_verify::{visit_schema_object_references, visit_validated_object_references},
    conflict_id, encode_canonical,
    hard_limits::{
        enforce_hard_limit_context, MAX_CHUNK_BYTES, MAX_PATH_BYTES, MAX_PATH_SEGMENTS,
        MAX_PATH_SEGMENT_BYTES,
    },
    object_id, scan_metadata_with_hard_limits, validate_metadata_schema, Cbor, Error, ErrorCode,
    FileId, HardLimitCeilings, Limits, MetadataObject, ObjectKind, ObjectRef, Operation,
    ProfileRef, Registry, RegistryAssignment, Result, Sha256Writer, ValidationStage,
};
use unicode_normalization::is_nfc;
const IMPORT_MAPPING_DOMAIN: &[u8] = b"OpenGameVCS import mapping\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    /// Interpret an existing durable value outside a declared conformance run.
    Read,
    /// Validate or construct a declared specification/fixture corpus value.
    Conformance,
    /// Validate a value selected for new durable production output.
    Production,
}

impl ValidationMode {
    fn operation(self) -> Operation {
        match self {
            Self::Read => Operation::Read,
            Self::Conformance => Operation::ConformanceWrite,
            Self::Production => Operation::ProductionWrite,
        }
    }
}

/// Successful layer-3 validation of one known metadata object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticObjectValidation {
    pub kind: ObjectKind,
    pub highest_layer: u8,
}

/// Validates a scanned metadata object in normative layer order: known base
/// schema first, then required-feature and profile semantics.
pub fn validate_semantic_object(
    object: &MetadataObject,
    registry: &Registry,
    mode: ValidationMode,
) -> Result<SemanticObjectValidation> {
    registry.require_complete_authority()?;
    let kind = validate_metadata_schema(object)?;
    let mut discard_reference = |_reference: ObjectRef| Ok(());
    visit_validated_object_references(
        kind,
        object.value(),
        registry,
        mode.operation(),
        &mut discard_reference,
    )?;
    Ok(SemanticObjectValidation {
        kind,
        highest_layer: 3,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct RepositoryLimits {
    pub max_objects: usize,
    pub max_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_edges: usize,
    pub max_memory_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_time: Option<Duration>,
    /// Format-family ceilings, each capped by its frozen v1 maximum.
    pub hard_limits: HardLimitCeilings,
}

impl Default for RepositoryLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_bytes: 134_217_728,
            max_chunk_bytes: MAX_CHUNK_BYTES as usize,
            max_edges: 1_000_000,
            max_memory_bytes: 1_073_741_824,
            max_scratch_bytes: 1_073_741_824,
            max_time: Some(Duration::from_secs(600)),
            hard_limits: HardLimitCeilings::HARD,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceSummary {
    pub objects: usize,
    pub bytes: usize,
    pub edges: usize,
    pub retained_bytes: usize,
    pub scratch_bytes: usize,
}

#[derive(Debug)]
struct ResourceGuard {
    limits: RepositoryLimits,
    start: Instant,
    summary: ResourceSummary,
    operation_depth: usize,
    operation_baseline: Option<(usize, usize)>,
}

impl ResourceGuard {
    fn new(limits: RepositoryLimits) -> Self {
        Self {
            limits,
            start: Instant::now(),
            summary: ResourceSummary::default(),
            operation_depth: 0,
            operation_baseline: None,
        }
    }

    fn check_time(&self) -> Result<()> {
        if self
            .limits
            .max_time
            .is_some_and(|maximum| maximum.is_zero() || self.start.elapsed() > maximum)
        {
            Err(Error::new(ErrorCode::LimitTime))
        } else {
            Ok(())
        }
    }

    fn object(&mut self, bytes: usize, _is_chunk: bool) -> Result<()> {
        self.summary.objects = self
            .summary
            .objects
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        self.summary.bytes = self
            .summary
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        // The lookup owns one Arc-backed payload plus its ordered-map node.
        // Decoded metadata and other derived structures are reserved
        // separately from their measured retained sizes.
        let retained = bytes
            .checked_add(512)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        self.summary.retained_bytes = self
            .summary
            .retained_bytes
            .checked_add(retained)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        if self.summary.objects > self.limits.max_objects {
            return Err(Error::new(ErrorCode::LimitCount));
        }
        if self.summary.bytes > self.limits.max_bytes
            || self.summary.retained_bytes > self.limits.max_memory_bytes
        {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        self.check_time()
    }

    fn edge(&mut self) -> Result<()> {
        self.summary.edges = self
            .summary
            .edges
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        if self.summary.edges > self.limits.max_edges {
            return Err(Error::new(ErrorCode::LimitCount));
        }
        self.check_time()
    }

    fn scratch(&mut self, bytes: usize) -> Result<()> {
        self.summary.scratch_bytes = self
            .summary
            .scratch_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::LimitScratch))?;
        if self.summary.scratch_bytes > self.limits.max_scratch_bytes {
            return Err(Error::new(ErrorCode::LimitScratch));
        }
        self.check_time()
    }

    fn reserve_derived(&mut self, bytes: usize) -> Result<()> {
        let retained = self
            .summary
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        if retained > self.limits.max_memory_bytes {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        self.summary.retained_bytes = retained;
        self.check_time()
    }

    fn release_derived(&mut self, bytes: usize) {
        self.summary.retained_bytes = self
            .summary
            .retained_bytes
            .checked_sub(bytes)
            .expect("derived-memory reservations are balanced");
    }

    fn begin_operation(&mut self) {
        if self.operation_depth == 0 {
            self.operation_baseline = Some((self.summary.edges, self.summary.scratch_bytes));
        }
        self.operation_depth = self
            .operation_depth
            .checked_add(1)
            .expect("repository operation nesting is bounded");
    }

    fn end_operation(&mut self) {
        self.operation_depth = self
            .operation_depth
            .checked_sub(1)
            .expect("repository operations are balanced");
        if self.operation_depth == 0 {
            let (edges, scratch_bytes) = self
                .operation_baseline
                .take()
                .expect("outer repository operation has a baseline");
            self.summary.edges = edges;
            self.summary.scratch_bytes = scratch_bytes;
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedObject {
    pub reference: ObjectRef,
    pub payload: Arc<[u8]>,
    pub value: Option<Arc<Cbor>>,
}

#[derive(Clone, Debug)]
struct CachedResolvedObject {
    object: ResolvedObject,
    semantic_validated: bool,
    retained_bytes: usize,
    operation_id: Option<u64>,
}

#[derive(Default)]
struct LookupOperationState {
    depth: usize,
    deferred_registry_error: Option<Error>,
    next_operation_id: u64,
    active_operation_id: Option<u64>,
}

/// Caller-supplied immutable object lookup. It verifies identity, kind, strict
/// schema, required features, and profile families before returning an object.
/// Resource counters are shared by all semantic traversals over the lookup.
pub struct RepositoryObjectLookup {
    entries: BTreeMap<ObjectRef, Arc<[u8]>>,
    cache: RefCell<BTreeMap<ObjectRef, CachedResolvedObject>>,
    guard: Rc<RefCell<ResourceGuard>>,
    registry: Registry,
    mode: ValidationMode,
    semantic_profiles: bool,
    operation_state: RefCell<LookupOperationState>,
}

impl RepositoryObjectLookup {
    pub fn new(
        entries: impl IntoIterator<Item = (ObjectRef, Vec<u8>)>,
        registry: Registry,
        mode: ValidationMode,
        limits: RepositoryLimits,
    ) -> Result<Self> {
        registry.require_complete_authority()?;
        if mode == ValidationMode::Read {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid)
                .with_layer(1)
                .with_stage(ValidationStage::ConfiguredResourcePreflight));
        }
        Self::build(entries, registry, mode, true, limits)
    }

    /// Explicit registry-free lookup capped at framing, identity, and known
    /// format-v1 schema validation. Repository-semantic entry points reject
    /// this authority before inspecting their payload.
    pub fn new_layer2(
        entries: impl IntoIterator<Item = (ObjectRef, Vec<u8>)>,
        limits: RepositoryLimits,
    ) -> Result<Self> {
        Self::build(
            entries,
            Registry::bundled(),
            ValidationMode::Read,
            false,
            limits,
        )
    }

    fn build(
        entries: impl IntoIterator<Item = (ObjectRef, Vec<u8>)>,
        registry: Registry,
        mode: ValidationMode,
        semantic_profiles: bool,
        limits: RepositoryLimits,
    ) -> Result<Self> {
        let mut indexed = BTreeMap::<ObjectRef, Arc<[u8]>>::new();
        let mut guard = ResourceGuard::new(limits);
        // A zero configured duration is an immediate configured-resource
        // failure even when the caller supplies an empty iterator.
        guard.check_time()?;
        for (reference, payload) in entries {
            // The supplied iterable is itself untrusted input. Charge and
            // checkpoint every element before coalescing identical entries so
            // duplicate floods cannot bypass count, memory, or time ceilings.
            guard.object(payload.len(), reference.kind == ObjectKind::Chunk)?;
            if let Some(previous) = indexed.get(&reference) {
                if previous.as_ref() != payload.as_slice() {
                    return Err(Error::new(ErrorCode::ObjectIdMismatch));
                }
                continue;
            }
            indexed.insert(reference, Arc::from(payload.into_boxed_slice()));
        }
        Ok(Self {
            entries: indexed,
            cache: RefCell::new(BTreeMap::new()),
            guard: Rc::new(RefCell::new(guard)),
            registry,
            mode,
            semantic_profiles,
            operation_state: RefCell::new(LookupOperationState::default()),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn resource_summary(&self) -> ResourceSummary {
        self.guard.borrow().summary
    }

    pub fn resolve(&self, reference: ObjectRef) -> Result<ResolvedObject> {
        self.resolve_kind(reference, None)
    }

    pub fn resolve_expected(
        &self,
        reference: ObjectRef,
        expected_kind: ObjectKind,
    ) -> Result<ResolvedObject> {
        self.resolve_kind(reference, Some(expected_kind))
    }

    fn resolve_kind(
        &self,
        reference: ObjectRef,
        expected_kind: Option<ObjectKind>,
    ) -> Result<ResolvedObject> {
        self.checkpoint()?;
        if expected_kind.is_some_and(|expected| expected != reference.kind) {
            return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
                .with_stage(ValidationStage::ClosureAndReferenceResolution));
        }
        if let Some(cached) = self.cache.borrow().get(&reference).cloned() {
            if self.semantic_profiles && !cached.semantic_validated {
                let semantic_validated =
                    self.validate_resolved_semantics(reference, cached.object.value.as_deref())?;
                if semantic_validated {
                    if let Some(entry) = self.cache.borrow_mut().get_mut(&reference) {
                        entry.semantic_validated = true;
                    }
                }
            }
            return Ok(cached.object);
        }
        let payload = self
            .entries
            .get(&reference)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::ObjectReferenceMissing))?;
        if reference.kind == ObjectKind::Chunk {
            let limits = self.guard.borrow().limits;
            let configured = u64::try_from(limits.max_chunk_bytes)
                .unwrap_or(u64::MAX)
                .min(limits.hard_limits.maximum("chunk-payload-bytes")?);
            enforce_hard_limit_context(
                "chunk-payload-bytes",
                u64::try_from(payload.len()).unwrap_or(u64::MAX),
                configured,
                ErrorCode::LimitChunkBytes,
                1,
            )?;
        }
        if object_id(reference.kind, payload.as_ref())? != reference.digest {
            return Err(Error::new(ErrorCode::ObjectIdMismatch));
        }
        let (value, retained) = if reference.kind == ObjectKind::Chunk {
            // Even a chunk cache entry retains an Arc, key and BTree node.
            // Charge that fixed index ownership before publishing the entry.
            let retained = 256usize;
            self.reserve_derived(retained)?;
            (None, retained)
        } else {
            let object = self.scan_metadata_with_remaining_memory(payload.as_ref())?;
            if object.framing().numeric_kind != reference.kind.code() {
                return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
                    .with_stage(ValidationStage::KnownSchema));
            }
            let actual_kind = validate_metadata_schema(&object)?;
            if actual_kind != reference.kind {
                return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
                    .with_stage(ValidationStage::KnownSchema));
            }
            let retained = object
                .decoded_retained_bytes()
                .checked_add(512)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            self.reserve_derived(retained)?;
            (Some(Arc::new(object.into_value())), retained)
        };
        let result = ResolvedObject {
            reference,
            payload,
            value,
        };
        let semantic_validated = if self.semantic_profiles {
            match self.validate_resolved_semantics(reference, result.value.as_deref()) {
                Ok(validated) => validated,
                Err(error) => {
                    self.release_derived(retained);
                    return Err(error);
                }
            }
        } else {
            true
        };
        self.cache.borrow_mut().insert(
            reference,
            CachedResolvedObject {
                object: result.clone(),
                semantic_validated,
                retained_bytes: retained,
                operation_id: self.operation_state.borrow().active_operation_id,
            },
        );
        Ok(result)
    }

    fn validate_resolved_semantics(
        &self,
        reference: ObjectRef,
        value: Option<&Cbor>,
    ) -> Result<bool> {
        let mut validated = true;
        for result in [
            self.registry.check_assignment_if_present(
                RegistryAssignment::ObjectKind(reference.kind.code()),
                self.mode.operation(),
            ),
            self.registry.check_assignment_if_present(
                RegistryAssignment::HashAlgorithm(1),
                self.mode.operation(),
            ),
        ] {
            if let Err(error) = result {
                validated &= !self.defer_registry_error(error)?;
            }
        }
        if let Some(value) = value {
            let mut discard_reference = |_reference: ObjectRef| Ok(());
            if let Err(error) = visit_validated_object_references(
                reference.kind,
                value,
                &self.registry,
                self.mode.operation(),
                &mut discard_reference,
            ) {
                validated &= !self.defer_registry_error(error)?;
            }
        }
        Ok(validated)
    }

    fn defer_registry_error(&self, error: Error) -> Result<bool> {
        let mut state = self.operation_state.borrow_mut();
        if state.depth == 0 || error.layer != 3 || error.stage != ValidationStage::RegistrySemantics
        {
            return Err(error);
        }
        observe_lookup_error(&mut state.deferred_registry_error, error);
        Ok(true)
    }

    pub fn edge(&self, reference: ObjectRef, expected_kind: ObjectKind) -> Result<ResolvedObject> {
        self.guard.borrow_mut().edge()?;
        self.resolve_expected(reference, expected_kind)
    }

    pub fn edge_any(&self, reference: ObjectRef) -> Result<ResolvedObject> {
        self.guard.borrow_mut().edge()?;
        self.resolve(reference)
    }

    pub fn validate_all(&self) -> Result<()> {
        // Finish the bounded layer-one pass for every supplied entry before
        // any known-schema or registry decision. Otherwise BTree key order
        // could let an early layer-two error hide a later identity failure.
        let mut framing_error = None;
        for (reference, payload) in &self.entries {
            self.checkpoint()?;
            if reference.kind == ObjectKind::Chunk {
                let limits = self.guard.borrow().limits;
                let configured = u64::try_from(limits.max_chunk_bytes)
                    .unwrap_or(u64::MAX)
                    .min(limits.hard_limits.maximum("chunk-payload-bytes")?);
                enforce_hard_limit_context(
                    "chunk-payload-bytes",
                    u64::try_from(payload.len()).unwrap_or(u64::MAX),
                    configured,
                    ErrorCode::LimitChunkBytes,
                    1,
                )?;
            } else if let Err(error) = self.scan_metadata_with_remaining_memory(payload) {
                if lookup_error_is_terminal(&error) {
                    return Err(error);
                }
                observe_lookup_error(&mut framing_error, error);
            }
            match object_id(reference.kind, payload) {
                Ok(identity) if identity == reference.digest => {}
                Ok(_) => observe_lookup_error(
                    &mut framing_error,
                    Error::new(ErrorCode::ObjectIdMismatch),
                ),
                Err(error) if lookup_error_is_terminal(&error) => return Err(error),
                Err(error) => observe_lookup_error(&mut framing_error, error),
            }
        }
        if let Some(error) = framing_error {
            return Err(error);
        }

        // Complete the whole-set known-schema phase before consulting any
        // lifecycle assignment. Otherwise BTree key order could let an early
        // conformance-only profile hide a later layer-two schema defect.
        let mut schema_error = None;
        for (reference, payload) in &self.entries {
            self.checkpoint()?;
            if reference.kind == ObjectKind::Chunk {
                continue;
            }
            let object = match self.scan_metadata_with_remaining_memory(payload) {
                Ok(object) => object,
                Err(error) if lookup_error_is_terminal(&error) => return Err(error),
                Err(error) => {
                    observe_lookup_error(&mut schema_error, error);
                    continue;
                }
            };
            match validate_metadata_schema(&object) {
                Ok(kind) if kind == reference.kind => {}
                Ok(_) => observe_lookup_error(
                    &mut schema_error,
                    Error::new(ErrorCode::ObjectReferenceKindMismatch)
                        .with_stage(ValidationStage::KnownSchema),
                ),
                Err(error) if lookup_error_is_terminal(&error) => return Err(error),
                Err(error) => observe_lookup_error(&mut schema_error, error),
            }
        }
        if let Some(error) = schema_error {
            return Err(error);
        }

        // Only after every object has passed L1/L2 do operation-aware registry
        // semantics run. Select by the frozen catalogue, not ObjectRef order.
        let mut best = None;
        for reference in self.entries.keys().copied() {
            self.checkpoint()?;
            if let Err(error) = self.resolve(reference) {
                if lookup_error_is_terminal(&error) {
                    return Err(error);
                }
                observe_lookup_error(&mut best, error);
            }
        }
        if let Some(error) = best {
            return Err(error);
        }
        // When validate_all participates in a larger repository operation,
        // resolve() defers layer-three registry failures.  This API is itself
        // a complete schema/registry boundary, so do not return success and
        // allow repository callbacks to run under an invalid authority.
        if self.operation_state.borrow().depth > 0 {
            self.finish_registry_phase()?;
        }
        Ok(())
    }

    fn preflight_all_l1_l2(&self) -> Result<()> {
        let mut framing_error = None;
        for (reference, payload) in &self.entries {
            self.checkpoint()?;
            if reference.kind == ObjectKind::Chunk {
                let limits = self.guard.borrow().limits;
                let configured = u64::try_from(limits.max_chunk_bytes)
                    .unwrap_or(u64::MAX)
                    .min(limits.hard_limits.maximum("chunk-payload-bytes")?);
                enforce_hard_limit_context(
                    "chunk-payload-bytes",
                    u64::try_from(payload.len()).unwrap_or(u64::MAX),
                    configured,
                    ErrorCode::LimitChunkBytes,
                    1,
                )?;
            } else if let Err(error) = self.scan_metadata_with_remaining_memory(payload) {
                if lookup_error_is_terminal(&error) {
                    return Err(error);
                }
                observe_lookup_error(&mut framing_error, error);
            }
            match object_id(reference.kind, payload) {
                Ok(identity) if identity == reference.digest => {}
                Ok(_) => observe_lookup_error(
                    &mut framing_error,
                    Error::new(ErrorCode::ObjectIdMismatch),
                ),
                Err(error) if lookup_error_is_terminal(&error) => return Err(error),
                Err(error) => observe_lookup_error(&mut framing_error, error),
            }
        }
        if let Some(error) = framing_error {
            return Err(error);
        }
        let mut schema_error = None;
        for (reference, payload) in &self.entries {
            self.checkpoint()?;
            if reference.kind == ObjectKind::Chunk {
                continue;
            }
            let object = match self.scan_metadata_with_remaining_memory(payload) {
                Ok(object) => object,
                Err(error) if lookup_error_is_terminal(&error) => return Err(error),
                Err(error) => {
                    observe_lookup_error(&mut schema_error, error);
                    continue;
                }
            };
            match validate_metadata_schema(&object) {
                Ok(kind) if kind == reference.kind => {}
                Ok(_) => observe_lookup_error(
                    &mut schema_error,
                    Error::new(ErrorCode::ObjectReferenceKindMismatch)
                        .with_stage(ValidationStage::KnownSchema),
                ),
                Err(error) if lookup_error_is_terminal(&error) => return Err(error),
                Err(error) => observe_lookup_error(&mut schema_error, error),
            }
        }
        if let Some(error) = schema_error {
            return Err(error);
        }
        Ok(())
    }

    fn finish_all_registry(&self) -> Result<()> {
        let mut best = None;
        for reference in self.entries.keys().copied() {
            self.checkpoint()?;
            if let Err(error) = self.resolve(reference) {
                if lookup_error_is_terminal(&error) {
                    return Err(error);
                }
                observe_lookup_error(&mut best, error);
            }
        }
        if let Err(error) = self.finish_registry_phase() {
            observe_lookup_error(&mut best, error);
        }
        if let Some(error) = best {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn scan_metadata_with_remaining_memory(&self, payload: &[u8]) -> Result<MetadataObject> {
        let (hard_limits, available) = {
            let guard = self.guard.borrow();
            (
                guard.limits.hard_limits,
                guard
                    .limits
                    .max_memory_bytes
                    .checked_sub(guard.summary.retained_bytes)
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
            )
        };
        let decode_pool = available
            .checked_sub(payload.len())
            .and_then(|bytes| bytes.checked_sub(512))
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        // The scanner retains its own raw payload and feature projection in
        // addition to the decoded CBOR graph. Keep a conservative fraction of
        // the remaining pool outside the decoder for those live allocations.
        let decode_memory = decode_pool
            .checked_mul(15)
            .map(|bytes| bytes / 16)
            .filter(|bytes| *bytes > 0)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        let object = scan_metadata_with_hard_limits(
            payload,
            Limits {
                max_working_bytes: decode_memory,
                ..Limits::METADATA
            },
            hard_limits,
        )?;
        if object.total_retained_bytes()? > available {
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok(object)
    }

    fn scratch(&self, bytes: usize) -> Result<()> {
        self.guard.borrow_mut().scratch(bytes)
    }

    fn reserve_derived(&self, bytes: usize) -> Result<()> {
        self.guard.borrow_mut().reserve_derived(bytes)
    }

    fn release_derived(&self, bytes: usize) {
        self.guard.borrow_mut().release_derived(bytes);
    }

    fn checkpoint(&self) -> Result<()> {
        self.guard.borrow().check_time()
    }

    fn with_operation<T>(&self, callback: impl FnOnce() -> Result<T>) -> Result<T> {
        let outer = {
            let mut state = self.operation_state.borrow_mut();
            let outer = state.depth == 0;
            if outer {
                state.deferred_registry_error = None;
                state.next_operation_id = state
                    .next_operation_id
                    .checked_add(1)
                    .expect("repository operation identifiers are bounded");
                state.active_operation_id = Some(state.next_operation_id);
            }
            state.depth = state
                .depth
                .checked_add(1)
                .expect("repository operation nesting is bounded");
            outer
        };
        self.guard.borrow_mut().begin_operation();
        let mut result = callback();
        self.guard.borrow_mut().end_operation();
        let completed_operation_id = {
            let mut state = self.operation_state.borrow_mut();
            state.depth = state
                .depth
                .checked_sub(1)
                .expect("repository operations are balanced");
            if outer {
                if let Some(deferred) = state.deferred_registry_error.take() {
                    match &result {
                        Ok(_) => result = Err(deferred),
                        Err(current) if deferred.precedence_key() < current.precedence_key() => {
                            result = Err(deferred);
                        }
                        Err(_) => {}
                    }
                }
                state.active_operation_id.take()
            } else {
                None
            }
        };
        // Route-internal decoded objects are operation-scoped. Remove and
        // release them after either success or failure so same-authority
        // retries observe the exact pre-operation accounting baseline. Cache
        // entries created by explicit resolve()/validate_all() outside a
        // repository operation remain reusable.
        if let Some(operation_id) = completed_operation_id {
            let mut released = 0usize;
            self.cache.borrow_mut().retain(|_, entry| {
                if entry.operation_id == Some(operation_id) {
                    released = released.saturating_add(entry.retained_bytes);
                    false
                } else {
                    true
                }
            });
            self.release_derived(released);
        }
        result
    }

    fn finish_registry_phase(&self) -> Result<()> {
        let mut state = self.operation_state.borrow_mut();
        if state.depth == 0 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid)
                .with_layer(1)
                .with_stage(ValidationStage::ConfiguredResourcePreflight));
        }
        if let Some(error) = state.deferred_registry_error.take() {
            Err(error)
        } else {
            Ok(())
        }
    }

    fn require_repository_semantics(&self) -> Result<()> {
        if !self.semantic_profiles || self.mode == ValidationMode::Read {
            Err(Error::new(ErrorCode::SchemaFieldInvalid)
                .with_layer(1)
                .with_stage(ValidationStage::ConfiguredResourcePreflight))
        } else {
            Ok(())
        }
    }

    fn hard_limits(&self) -> HardLimitCeilings {
        self.guard.borrow().limits.hard_limits
    }
}

#[derive(Debug)]
struct OwnedDerivedMemory {
    guard: Rc<RefCell<ResourceGuard>>,
    bytes: usize,
}

impl OwnedDerivedMemory {
    fn empty(lookup: &RepositoryObjectLookup) -> Self {
        Self::from_guard(&lookup.guard)
    }

    fn from_guard(guard: &Rc<RefCell<ResourceGuard>>) -> Self {
        Self {
            guard: Rc::clone(guard),
            bytes: 0,
        }
    }

    fn grow_by(&mut self, bytes: usize) -> Result<()> {
        let retained = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        self.guard.borrow_mut().reserve_derived(bytes)?;
        self.bytes = retained;
        Ok(())
    }
}

impl Drop for OwnedDerivedMemory {
    fn drop(&mut self) {
        self.guard.borrow_mut().release_derived(self.bytes);
    }
}

fn lookup_error_is_terminal(error: &Error) -> bool {
    matches!(
        error.code,
        ErrorCode::LimitMetadataBytes
            | ErrorCode::LimitChunkBytes
            | ErrorCode::LimitNesting
            | ErrorCode::LimitCount
            | ErrorCode::LimitMemory
            | ErrorCode::LimitScratch
            | ErrorCode::LimitTime
            | ErrorCode::LimitValueBytes
            | ErrorCode::LimitExtensionBytes
            | ErrorCode::LimitLogicalBytes
    )
}

fn observe_lookup_error(best: &mut Option<Error>, error: Error) {
    if best
        .as_ref()
        .is_none_or(|current| error.precedence_key() < current.precedence_key())
    {
        *best = Some(error);
    }
}

fn collect_lookup_result<T>(best: &mut Option<Error>, result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if lookup_error_is_terminal(&error) => Err(error),
        Err(error) => {
            observe_lookup_error(best, error);
            Ok(None)
        }
    }
}

fn finish_lookup_selection(best: Option<Error>) -> Result<()> {
    match best {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestSummary {
    pub logical_length: u64,
    pub chunks: usize,
}

pub fn verify_manifest(
    reference: ObjectRef,
    lookup: &RepositoryObjectLookup,
) -> Result<ManifestSummary> {
    lookup.require_repository_semantics()?;
    lookup.with_operation(|| verify_manifest_operation(reference, lookup))
}

fn verify_manifest_operation(
    reference: ObjectRef,
    lookup: &RepositoryObjectLookup,
) -> Result<ManifestSummary> {
    let object = lookup.resolve_expected(reference, ObjectKind::ContentManifest)?;
    let manifest = metadata_value(&object)?;
    let declared = uint(field(manifest, 16)?)?;
    let parts = array(field(manifest, 19)?)?;
    // Complete layer-two reference resolution precedes layer-three content
    // agreement. A missing later chunk must not be hidden by an earlier
    // declared/raw-length disagreement.
    let mut lookup_error = None;
    for part in parts {
        let chunk_ref = object_ref(field(part, 0)?)?;
        let _ =
            collect_lookup_result(&mut lookup_error, lookup.edge(chunk_ref, ObjectKind::Chunk))?;
    }
    finish_lookup_selection(lookup_error)?;
    lookup.finish_registry_phase()?;
    let mut sum = 0u64;
    let mut digest = Sha256Writer::new();
    for part in parts {
        let length = uint(field(part, 1)?)?;
        if length == 0 {
            return Err(Error::new(ErrorCode::ManifestChunkLengthInvalid));
        }
        enforce_hard_limit_context(
            "chunk-payload-bytes",
            length,
            lookup.hard_limits().maximum("chunk-payload-bytes")?,
            ErrorCode::ManifestChunkLengthInvalid,
            2,
        )?;
        sum = sum
            .checked_add(length)
            .ok_or_else(|| Error::new(ErrorCode::LimitLogicalBytes))?;
        enforce_hard_limit_context(
            "logical-file-bytes",
            sum,
            lookup.hard_limits().maximum("logical-file-bytes")?,
            ErrorCode::LimitLogicalBytes,
            2,
        )?;
        let chunk_ref = object_ref(field(part, 0)?)?;
        let chunk = lookup.resolve_expected(chunk_ref, ObjectKind::Chunk)?;
        if chunk.payload.len() as u64 != length {
            return Err(Error::new(ErrorCode::ManifestChunkLengthInvalid).with_layer(3));
        }
        digest.update(&chunk.payload);
    }
    if sum != declared || (declared == 0 && !parts.is_empty()) {
        return Err(Error::new(ErrorCode::ManifestLengthMismatch));
    }
    let expected = digest32(field(field(manifest, 17)?, 1)?)?;
    if digest.finish() != expected {
        return Err(Error::new(ErrorCode::ManifestFileDigestMismatch));
    }
    Ok(ManifestSummary {
        logical_length: declared,
        chunks: parts.len(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryState {
    pub path: Vec<String>,
    pub kind: u8,
    pub file_id: FileId,
    pub mode: u8,
    pub target: Option<ObjectRef>,
    pub logical_size: u64,
    pub content_policy: ProfileRef,
    raw: Cbor,
}

impl EntryState {
    fn from_cbor(value: &Cbor) -> Result<Self> {
        Ok(Self {
            path: path(field(value, 0)?)?,
            kind: u8::try_from(uint(field(value, 1)?)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
            file_id: file_id(field(value, 2)?)?,
            mode: u8::try_from(uint(field(value, 3)?)?)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
            target: optional_field(value, 4).map(object_ref).transpose()?,
            logical_size: uint(field(value, 5)?)?,
            content_policy: profile_ref(field(value, 6)?)?,
            raw: value.clone(),
        })
    }

    fn from_tree_entry(prefix: &[String], value: &Cbor) -> Result<Self> {
        let mut state_path = prefix.to_vec();
        state_path.push(text(field(value, 0)?)?.to_owned());
        validate_composed_path(&state_path)?;
        let kind = u8::try_from(uint(field(value, 1)?)?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        let target = object_ref(field(value, 4)?)?;
        let mut fields = vec![
            (Cbor::UInt(0), path_cbor(&state_path)),
            (Cbor::UInt(1), Cbor::UInt(kind.into())),
            (Cbor::UInt(2), field(value, 2)?.clone()),
            (Cbor::UInt(3), field(value, 3)?.clone()),
        ];
        if kind != 1 {
            fields.push((Cbor::UInt(4), target.to_cbor()));
        }
        fields.push((Cbor::UInt(5), field(value, 5)?.clone()));
        fields.push((Cbor::UInt(6), field(value, 6)?.clone()));
        Self::from_cbor(&Cbor::Map(fields))
    }

    fn encoded_len(&self, lookup: &RepositoryObjectLookup) -> Result<usize> {
        cbor_encoded_len(&self.raw, lookup, 0)
    }

    fn retained_cost(&self) -> Result<usize> {
        cbor_retained_cost(&self.raw, 0)?
            .checked_add(512)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetGroup {
    pub id: [u8; 16],
    pub profile: ProfileRef,
    pub primary_file_id: FileId,
    pub members: Vec<(FileId, ProfileRef)>,
    pub external_keys: Vec<(ProfileRef, Vec<u8>)>,
    raw: Cbor,
}

impl AssetGroup {
    /// Parses one already schema-shaped asset-group value for standalone
    /// registry-authoritative validation.
    pub fn from_cbor(value: &Cbor) -> Result<Self> {
        let members = array(field(value, 3)?)?
            .iter()
            .map(|member| Ok((file_id(field(member, 0)?)?, profile_ref(field(member, 1)?)?)))
            .collect::<Result<Vec<_>>>()?;
        let external_keys = optional_field(value, 4)
            .map(|values| {
                array(values)?
                    .iter()
                    .map(|key| {
                        Ok((
                            profile_ref(field(key, 0)?)?,
                            bytes(field(key, 1)?)?.to_vec(),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            id: id128(field(value, 0)?)?,
            profile: profile_ref(field(value, 1)?)?,
            primary_file_id: file_id(field(value, 2)?)?,
            members,
            external_keys,
            raw: value.clone(),
        })
    }

    fn encoded_len(&self, lookup: &RepositoryObjectLookup) -> Result<usize> {
        cbor_encoded_len(&self.raw, lookup, 0)
    }

    fn retained_cost(&self) -> Result<usize> {
        cbor_retained_cost(&self.raw, 0)?
            .checked_add(512)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepositoryState {
    pub entries: BTreeMap<Vec<String>, EntryState>,
    pub groups: BTreeMap<[u8; 16], AssetGroup>,
}

impl RepositoryState {
    fn retained_cost(&self) -> Result<usize> {
        self.entries
            .values()
            .map(EntryState::retained_cost)
            .chain(self.groups.values().map(AssetGroup::retained_cost))
            .try_fold(512usize, |total, cost| {
                total
                    .checked_add(cost?)
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
            })
    }
}

fn derived_value_cost(encoded_len: usize) -> Result<usize> {
    encoded_len
        .checked_mul(16)
        .and_then(|bytes| bytes.checked_add(512))
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
}

fn profile_retained_cost(profile: &ProfileRef) -> Result<usize> {
    profile
        .namespace()
        .len()
        .checked_add(profile.id().len())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(256))
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
}

fn path_retained_cost(path: &[String]) -> Result<usize> {
    path.iter().try_fold(128usize, |total, segment| {
        segment
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(64))
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    })
}

fn cbor_retained_cost(value: &Cbor, depth: usize) -> Result<usize> {
    if depth > 256 {
        return Err(Error::new(ErrorCode::LimitMemory));
    }
    let checked_add = |left: usize, right: usize| {
        left.checked_add(right)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    };
    match value {
        Cbor::UInt(_) | Cbor::NInt(_) | Cbor::Bool(_) => Ok(32),
        Cbor::Bytes(bytes) => checked_add(
            bytes
                .len()
                .checked_mul(2)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
            128,
        ),
        Cbor::Text(text) => checked_add(
            text.len()
                .checked_mul(2)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
            128,
        ),
        Cbor::Array(values) => {
            let mut total = checked_add(
                128,
                values
                    .len()
                    .checked_mul(32)
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
            )?;
            for item in values {
                total = checked_add(total, cbor_retained_cost(item, depth + 1)?)?;
            }
            Ok(total)
        }
        Cbor::Map(entries) => {
            let mut total = checked_add(
                256,
                entries
                    .len()
                    .checked_mul(64)
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
            )?;
            for (key, item) in entries {
                total = checked_add(total, cbor_retained_cost(key, depth + 1)?)?;
                total = checked_add(total, cbor_retained_cost(item, depth + 1)?)?;
            }
            Ok(total)
        }
    }
}

fn cbor_argument_header_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Measure canonical CBOR without first materializing an encoded buffer.
/// Every retained node is also a deadline checkpoint, so scratch preflight
/// cannot become an unbounded traversal in its own right.
fn cbor_encoded_len(value: &Cbor, lookup: &RepositoryObjectLookup, depth: usize) -> Result<usize> {
    lookup.checkpoint()?;
    if depth > 256 {
        return Err(Error::new(ErrorCode::LimitNesting));
    }
    let checked_add = |left: usize, right: usize| {
        left.checked_add(right)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    };
    match value {
        Cbor::UInt(value) => Ok(cbor_argument_header_len(*value)),
        Cbor::NInt(value) => {
            let argument = u64::try_from(-1i128 - i128::from(*value))
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
            Ok(cbor_argument_header_len(argument))
        }
        Cbor::Bool(_) => Ok(1),
        Cbor::Bytes(bytes) => checked_add(
            cbor_argument_header_len(
                u64::try_from(bytes.len()).map_err(|_| Error::new(ErrorCode::LimitMemory))?,
            ),
            bytes.len(),
        ),
        Cbor::Text(text) => checked_add(
            cbor_argument_header_len(
                u64::try_from(text.len()).map_err(|_| Error::new(ErrorCode::LimitMemory))?,
            ),
            text.len(),
        ),
        Cbor::Array(values) => {
            let mut total = cbor_argument_header_len(
                u64::try_from(values.len()).map_err(|_| Error::new(ErrorCode::LimitMemory))?,
            );
            for item in values {
                total = checked_add(total, cbor_encoded_len(item, lookup, depth + 1)?)?;
            }
            Ok(total)
        }
        Cbor::Map(entries) => {
            let mut total = cbor_argument_header_len(
                u64::try_from(entries.len()).map_err(|_| Error::new(ErrorCode::LimitMemory))?,
            );
            for (key, item) in entries {
                total = checked_add(total, cbor_encoded_len(key, lookup, depth + 1)?)?;
                total = checked_add(total, cbor_encoded_len(item, lookup, depth + 1)?)?;
            }
            Ok(total)
        }
    }
}

#[derive(Debug)]
pub struct TreeExpansion {
    pub descriptor: ObjectRef,
    pub entries: BTreeMap<Vec<String>, EntryState>,
    pub file_ids: BTreeMap<FileId, Vec<String>>,
}

#[derive(Debug)]
struct ReservedTreeExpansion {
    descriptor: ObjectRef,
    entries: BTreeMap<Vec<String>, EntryState>,
    file_ids: BTreeMap<FileId, Vec<String>>,
    memory: OwnedDerivedMemory,
}

impl ReservedTreeExpansion {
    fn into_public(self) -> TreeExpansion {
        TreeExpansion {
            descriptor: self.descriptor,
            entries: self.entries,
            file_ids: self.file_ids,
        }
    }
}

/// Result returned by an external, version-pinned path-profile validator.
///
/// The opaque keys let the selected profile expose repository and platform
/// collision equivalence without this crate reimplementing those semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathProfileDecision {
    Accepted {
        repository_key: String,
        platform_key: String,
    },
    Rejected,
}

/// Authenticated repository case-equivalence mode supplied alongside an
/// external path-profile adapter. It is repository context, not object
/// identity, in format v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathCaseMode {
    CaseSensitive,
    CaseFolded,
}

impl PathProfileDecision {
    pub fn accepted(repository_key: impl Into<String>, platform_key: impl Into<String>) -> Self {
        Self::Accepted {
            repository_key: repository_key.into(),
            platform_key: platform_key.into(),
        }
    }

    pub const fn rejected() -> Self {
        Self::Rejected
    }
}

/// Synchronous adapter for one exact registered path-profile assignment.
///
/// Implementations live in the crate that owns the selected profile. The
/// returned profile is an exact namespace/id/major pin; a descriptor selecting
/// any other assignment is rejected without invoking [`Self::validate`].
pub trait PathProfileValidator {
    fn profile(&self) -> &ProfileRef;
    fn case_mode(&self) -> PathCaseMode;

    /// Validates one complete root-relative path after core path validation.
    fn validate(&self, segments: &[String]) -> PathProfileDecision;
}

/// Expands a tree without an external path-profile adapter.
///
/// This remains sufficient for the built-in `path.test/*@1` conformance
/// profiles. A ratified/external profile fails closed; use
/// [`expand_tree_with_path_profile_validator`] for that case.
pub fn expand_tree(
    root_reference: ObjectRef,
    lookup: &RepositoryObjectLookup,
    descriptor_reference: ObjectRef,
    verify_content: bool,
    case_mode: PathCaseMode,
) -> Result<TreeExpansion> {
    expand_tree_with_path_profile_validator(
        root_reference,
        lookup,
        descriptor_reference,
        verify_content,
        case_mode,
        None,
    )
}

/// Expands a tree and invokes the exact descriptor-selected path profile.
///
/// External profile semantics are accepted only when `validator.profile()`
/// exactly matches the selected namespace, id, and major version. The adapter
/// is called after core joined-path checks. Accepted decisions must provide
/// both collision keys. They are kept in bounded derived memory for the
/// duration of the expansion and must be unique within their respective
/// domains.
pub fn expand_tree_with_path_profile_validator(
    root_reference: ObjectRef,
    lookup: &RepositoryObjectLookup,
    descriptor_reference: ObjectRef,
    verify_content: bool,
    case_mode: PathCaseMode,
    validator: Option<&dyn PathProfileValidator>,
) -> Result<TreeExpansion> {
    lookup.require_repository_semantics()?;
    lookup.with_operation(|| {
        expand_tree_owned(
            root_reference,
            lookup,
            descriptor_reference,
            verify_content,
            case_mode,
            validator,
        )
        .map(ReservedTreeExpansion::into_public)
    })
}

fn expand_tree_owned(
    root_reference: ObjectRef,
    lookup: &RepositoryObjectLookup,
    descriptor_reference: ObjectRef,
    verify_content: bool,
    case_mode: PathCaseMode,
    validator: Option<&dyn PathProfileValidator>,
) -> Result<ReservedTreeExpansion> {
    lookup.require_repository_semantics()?;
    expect_ref_kind(descriptor_reference, ObjectKind::RepositoryDescriptor)?;
    preflight_tree_closure(root_reference, lookup, descriptor_reference, verify_content)?;
    lookup.finish_registry_phase()?;
    let descriptor_object =
        lookup.resolve_expected(descriptor_reference, ObjectKind::RepositoryDescriptor)?;
    let descriptor = metadata_value(&descriptor_object)?;
    let mut result = ReservedTreeExpansion {
        descriptor: descriptor_reference,
        entries: BTreeMap::new(),
        file_ids: BTreeMap::new(),
        memory: OwnedDerivedMemory::empty(lookup),
    };
    lookup.checkpoint()?;
    result
        .memory
        .grow_by(cbor_retained_cost(field(descriptor, 17)?, 0)?.saturating_add(256))?;
    let path_profile = profile_ref(field(descriptor, 17)?)?;
    require_path_profile_validator(&path_profile, case_mode, validator)?;
    let allowed_content = charged_profile_set(field(descriptor, 18)?, lookup, &mut result.memory)?;
    let allowed_chunks = optional_field(descriptor, 20)
        .map(|value| charged_profile_set(value, lookup, &mut result.memory))
        .transpose()?
        .unwrap_or_default();
    let mut visiting = BTreeSet::new();
    let mut repository_keys = BTreeSet::new();
    let mut platform_keys = BTreeSet::new();
    let mut path_profile_memory = OwnedDerivedMemory::empty(lookup);
    walk_tree(
        root_reference,
        &[],
        lookup,
        descriptor_reference,
        &path_profile,
        &allowed_content,
        &allowed_chunks,
        verify_content,
        validator,
        &mut repository_keys,
        &mut platform_keys,
        &mut path_profile_memory,
        &mut visiting,
        &mut result,
    )?;
    Ok(result)
}

fn preflight_tree_closure(
    root_reference: ObjectRef,
    lookup: &RepositoryObjectLookup,
    descriptor_reference: ObjectRef,
    verify_content: bool,
) -> Result<()> {
    let mut lookup_error = None;
    let _ = collect_lookup_result(
        &mut lookup_error,
        lookup.edge(descriptor_reference, ObjectKind::RepositoryDescriptor),
    )?;
    let mut memory = OwnedDerivedMemory::empty(lookup);
    let mut visited = BTreeSet::new();
    let mut stack = vec![root_reference];
    memory.grow_by(derived_value_cost(35)?)?;
    while let Some(reference) = stack.pop() {
        lookup.checkpoint()?;
        expect_ref_kind(reference, ObjectKind::Tree)?;
        if visited.contains(&reference) {
            continue;
        }
        memory.grow_by(derived_value_cost(34)?)?;
        visited.insert(reference);
        let Some(object) =
            collect_lookup_result(&mut lookup_error, lookup.edge(reference, ObjectKind::Tree))?
        else {
            continue;
        };
        let tree = metadata_value(&object)?;
        let _ = collect_lookup_result(
            &mut lookup_error,
            lookup.edge(
                object_ref(field(tree, 16)?)?,
                ObjectKind::RepositoryDescriptor,
            ),
        )?;
        for raw_entry in array(field(tree, 17)?)? {
            lookup.checkpoint()?;
            let kind = uint(field(raw_entry, 1)?)?;
            let target = object_ref(field(raw_entry, 4)?)?;
            if kind == 1 {
                memory.grow_by(derived_value_cost(35)?)?;
                stack.push(target);
            } else {
                let manifest = collect_lookup_result(
                    &mut lookup_error,
                    lookup.edge(target, ObjectKind::ContentManifest),
                )?;
                if verify_content && manifest.is_some() {
                    let manifest = manifest.expect("checked present");
                    let manifest = metadata_value(&manifest)?;
                    for part in array(field(manifest, 19)?)? {
                        lookup.checkpoint()?;
                        let _ = collect_lookup_result(
                            &mut lookup_error,
                            lookup.edge(object_ref(field(part, 0)?)?, ObjectKind::Chunk),
                        )?;
                    }
                }
            }
        }
    }
    finish_lookup_selection(lookup_error)
}

#[allow(clippy::too_many_arguments)]
fn walk_tree(
    tree_reference: ObjectRef,
    prefix: &[String],
    lookup: &RepositoryObjectLookup,
    descriptor_reference: ObjectRef,
    path_profile: &ProfileRef,
    allowed_content: &BTreeSet<ProfileRef>,
    allowed_chunks: &BTreeSet<ProfileRef>,
    verify_content: bool,
    path_profile_validator: Option<&dyn PathProfileValidator>,
    repository_keys: &mut BTreeSet<String>,
    platform_keys: &mut BTreeSet<String>,
    path_profile_memory: &mut OwnedDerivedMemory,
    visiting: &mut BTreeSet<ObjectRef>,
    result: &mut ReservedTreeExpansion,
) -> Result<()> {
    if visiting.contains(&tree_reference) {
        // Ordinary byte-valid object cycles require a hash fixed point, but a
        // defensive implementation still bounds and rejects traversal cycles.
        return Err(Error::new(ErrorCode::ProvenanceCycle));
    }
    path_profile_memory.grow_by(derived_value_cost(34)?)?;
    visiting.insert(tree_reference);
    let object = lookup.edge(tree_reference, ObjectKind::Tree)?;
    let tree = metadata_value(&object)?;
    if object_ref(field(tree, 16)?)? != descriptor_reference {
        return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
    }
    for raw_entry in array(field(tree, 17)?)? {
        lookup.checkpoint()?;
        // Reserve the parsed EntryState plus both retained path-map views from
        // the caller-owned CBOR before `from_tree_entry` performs any clone.
        let prefix_retained = path_retained_cost(prefix)?
            .checked_mul(3)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        let retained = cbor_retained_cost(raw_entry, 0)?
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(prefix_retained))
            .and_then(|bytes| bytes.checked_add(2_048))
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        result.memory.grow_by(retained)?;
        let state = EntryState::from_tree_entry(prefix, raw_entry)?;
        validate_path_profile(
            path_profile,
            &state.path,
            path_profile_validator,
            repository_keys,
            platform_keys,
            path_profile_memory,
        )?;
        lookup.scratch(state.encoded_len(lookup)?)?;
        if result.entries.contains_key(&state.path) {
            return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
        }
        if result.file_ids.contains_key(&state.file_id) {
            return Err(Error::new(ErrorCode::FileIdDuplicateInTree));
        }
        if !allowed_content.contains(&state.content_policy) {
            return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
        }
        let target = object_ref(field(raw_entry, 4)?)?;
        result.file_ids.insert(state.file_id, state.path.clone());
        result.entries.insert(state.path.clone(), state.clone());
        if state.kind == 1 {
            walk_tree(
                target,
                &state.path,
                lookup,
                descriptor_reference,
                path_profile,
                allowed_content,
                allowed_chunks,
                verify_content,
                path_profile_validator,
                repository_keys,
                platform_keys,
                path_profile_memory,
                visiting,
                result,
            )?;
        } else {
            let manifest_object = lookup.edge(target, ObjectKind::ContentManifest)?;
            let manifest = metadata_value(&manifest_object)?;
            if !allowed_chunks.contains(&profile_ref(field(manifest, 18)?)?) {
                return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
            }
            let logical_length = if verify_content {
                verify_manifest(target, lookup)?.logical_length
            } else {
                uint(field(manifest, 16)?)?
            };
            if logical_length != state.logical_size {
                return Err(Error::new(ErrorCode::TreeEntryTargetInvalid)
                    .with_layer(3)
                    .with_stage(ValidationStage::RepositorySemantics));
            }
        }
    }
    visiting.remove(&tree_reference);
    Ok(())
}

fn is_builtin_path_profile(profile: &ProfileRef) -> bool {
    profile.namespace() == "path.test"
        && profile.major() == 1
        && matches!(profile.id(), "opaque" | "reject-reserved")
}

fn require_path_profile_validator(
    profile: &ProfileRef,
    case_mode: PathCaseMode,
    validator: Option<&dyn PathProfileValidator>,
) -> Result<()> {
    if is_builtin_path_profile(profile) {
        return Ok(());
    }
    if validator.is_some_and(|validator| {
        validator.profile() == profile && validator.case_mode() == case_mode
    }) {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::PathProfileInvalid))
    }
}

fn remember_path_profile_key(
    key: String,
    keys: &mut BTreeSet<String>,
    memory: &mut OwnedDerivedMemory,
) -> Result<()> {
    // JSON Schema maxLength counts Unicode scalar values. A Rust String is
    // already valid scalar UTF-8; the byte precheck bounds the subsequent
    // allocation-free scalar count (four bytes per scalar maximum).
    if key.is_empty()
        || key.len() > 32_768 * 4
        || !is_unicode_15(&key)
        || key.chars().count() > 32_768
    {
        return Err(Error::new(ErrorCode::PathProfileInvalid));
    }
    if keys.contains(&key) {
        return Err(Error::new(ErrorCode::PathProfileInvalid));
    }
    memory.grow_by(derived_value_cost(key.len())?)?;
    keys.insert(key);
    Ok(())
}

fn validate_path_profile(
    profile: &ProfileRef,
    path: &[String],
    validator: Option<&dyn PathProfileValidator>,
    repository_keys: &mut BTreeSet<String>,
    platform_keys: &mut BTreeSet<String>,
    memory: &mut OwnedDerivedMemory,
) -> Result<()> {
    if profile.namespace() == "path.test" && profile.id() == "opaque" && profile.major() == 1 {
        return Ok(());
    }
    if profile.namespace() == "path.test"
        && profile.id() == "reject-reserved"
        && profile.major() == 1
    {
        return if path.iter().any(|segment| segment == "reserved") {
            Err(Error::new(ErrorCode::PathProfileInvalid))
        } else {
            Ok(())
        };
    }
    let validator = validator.ok_or_else(|| Error::new(ErrorCode::PathProfileInvalid))?;
    if validator.profile() != profile {
        return Err(Error::new(ErrorCode::PathProfileInvalid));
    }
    match validator.validate(path) {
        PathProfileDecision::Rejected => Err(Error::new(ErrorCode::PathProfileInvalid)),
        PathProfileDecision::Accepted {
            repository_key,
            platform_key,
        } => {
            remember_path_profile_key(repository_key, repository_keys, memory)?;
            remember_path_profile_key(platform_key, platform_keys, memory)
        }
    }
}

struct ReservedGroups {
    groups: BTreeMap<[u8; 16], AssetGroup>,
    memory: OwnedDerivedMemory,
}

fn groups_from_set(
    reference: Option<ObjectRef>,
    lookup: &RepositoryObjectLookup,
    descriptor_reference: ObjectRef,
) -> Result<ReservedGroups> {
    let mut memory = OwnedDerivedMemory::empty(lookup);
    let Some(reference) = reference else {
        return Ok(ReservedGroups {
            groups: BTreeMap::new(),
            memory,
        });
    };
    let object = lookup.edge(reference, ObjectKind::AssetGroupSet)?;
    let set = metadata_value(&object)?;
    if object_ref(field(set, 16)?)? != descriptor_reference {
        return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
    }
    let descriptor_object =
        lookup.resolve_expected(descriptor_reference, ObjectKind::RepositoryDescriptor)?;
    let descriptor = metadata_value(&descriptor_object)?;
    let allowed = charged_profile_set(field(descriptor, 19)?, lookup, &mut memory)?;
    let mut groups = BTreeMap::new();
    for value in array(field(set, 17)?)? {
        lookup.checkpoint()?;
        // `AssetGroup::from_cbor` clones the complete caller-owned record.
        // Charge both the parsed group and ordered-map node before that clone.
        memory.grow_by(
            cbor_retained_cost(value, 0)?
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(1_024))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
        )?;
        let group = AssetGroup::from_cbor(value)?;
        lookup.scratch(group.encoded_len(lookup)?)?;
        if !allowed.contains(&group.profile) {
            return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
        }
        groups.insert(group.id, group);
    }
    Ok(ReservedGroups { groups, memory })
}

fn metadata_value(object: &ResolvedObject) -> Result<&Cbor> {
    object.value.as_deref().ok_or_else(|| {
        Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::ClosureAndReferenceResolution)
    })
}

fn field(value: &Cbor, key: u64) -> Result<&Cbor> {
    optional_field(value, key).ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn optional_field(value: &Cbor, key: u64) -> Option<&Cbor> {
    let Cbor::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(candidate, value)| (*candidate == Cbor::UInt(key)).then_some(value))
}

fn array(value: &Cbor) -> Result<&[Cbor]> {
    match value {
        Cbor::Array(values) => Ok(values),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn uint(value: &Cbor) -> Result<u64> {
    match value {
        Cbor::UInt(value) => Ok(*value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn text(value: &Cbor) -> Result<&str> {
    match value {
        Cbor::Text(value) if is_unicode_15(value) && is_nfc(value) => Ok(value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn bytes(value: &Cbor) -> Result<&[u8]> {
    match value {
        Cbor::Bytes(value) => Ok(value),
        _ => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    }
}

fn digest32(value: &Cbor) -> Result<[u8; 32]> {
    bytes(value)?
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn id128(value: &Cbor) -> Result<[u8; 16]> {
    let result: [u8; 16] = bytes(value)?
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    if result == [0; 16] {
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    } else {
        Ok(result)
    }
}

fn object_ref(value: &Cbor) -> Result<ObjectRef> {
    ObjectRef::from_cbor(value)
}

fn expect_ref_kind(reference: ObjectRef, expected: ObjectKind) -> Result<()> {
    if reference.kind == expected {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::ClosureAndReferenceResolution))
    }
}

fn file_id(value: &Cbor) -> Result<FileId> {
    FileId::from_cbor(value)
}

fn profile_ref(value: &Cbor) -> Result<ProfileRef> {
    ProfileRef::from_cbor(value)
}

fn charged_profile_set(
    value: &Cbor,
    lookup: &RepositoryObjectLookup,
    memory: &mut OwnedDerivedMemory,
) -> Result<BTreeSet<ProfileRef>> {
    let mut profiles = BTreeSet::new();
    for raw in array(value)? {
        lookup.checkpoint()?;
        // ProfileRef parsing clones its namespace/id. Reserve the candidate
        // and ordered-set node before parsing or inserting it.
        memory.grow_by(cbor_retained_cost(raw, 0)?.saturating_add(256))?;
        profiles.insert(profile_ref(raw)?);
    }
    Ok(profiles)
}

fn path(value: &Cbor) -> Result<Vec<String>> {
    let result = array(value)?
        .iter()
        .map(|segment| Ok(text(segment)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    validate_composed_path(&result)?;
    Ok(result)
}

fn validate_composed_path(value: &[String]) -> Result<()> {
    if value.is_empty() {
        return Err(Error::new(ErrorCode::PathCoreInvalid).with_layer(3));
    }
    enforce_repository_limit(
        "path-segments",
        value.len(),
        MAX_PATH_SEGMENTS,
        ErrorCode::PathCoreInvalid,
    )?;
    let mut joined = value.len() - 1;
    for segment in value {
        enforce_repository_limit(
            "path-segment-bytes",
            segment.len(),
            MAX_PATH_SEGMENT_BYTES,
            ErrorCode::PathCoreInvalid,
        )?;
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.as_bytes().contains(&b'/')
            || segment.as_bytes().contains(&0)
        {
            return Err(Error::new(ErrorCode::PathCoreInvalid).with_layer(3));
        }
        joined = joined
            .checked_add(segment.len())
            .ok_or_else(|| Error::new(ErrorCode::PathCoreInvalid).with_layer(3))?;
    }
    enforce_repository_limit(
        "path-bytes",
        joined,
        MAX_PATH_BYTES,
        ErrorCode::PathCoreInvalid,
    )?;
    Ok(())
}

fn enforce_repository_limit(
    name: &'static str,
    value: usize,
    configured: u64,
    code: ErrorCode,
) -> Result<()> {
    enforce_hard_limit_context(
        name,
        u64::try_from(value).unwrap_or(u64::MAX),
        configured,
        code,
        3,
    )
    .map(|_| ())
}

fn path_cbor(value: &[String]) -> Cbor {
    Cbor::Array(value.iter().cloned().map(Cbor::Text).collect())
}

fn keyed_conflict_preimage(record: &Cbor) -> Result<Vec<u8>> {
    let mut fields = vec![
        (Cbor::UInt(0), field(record, 1)?.clone()),
        (Cbor::UInt(1), field(record, 2)?.clone()),
    ];
    for (source, target) in [(3, 2), (4, 3), (5, 4)] {
        if let Some(value) = optional_field(record, source) {
            fields.push((Cbor::UInt(target), value.clone()));
        }
    }
    encode_canonical(&Cbor::Map(fields))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifetimeOrigin {
    NativeCreate,
    NativeCopy,
    Import,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifetimeRecord {
    pub file_id: FileId,
    pub origin: LifetimeOrigin,
    pub first_change_set: ObjectRef,
    pub first_operation: u64,
    pub import_mapping_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportState {
    Reserved,
    Materialized,
    Published,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportMapping {
    /// Repository authority serialized with this opaque/import-state row.
    /// Canonical CBOR mappings derive this from their authenticated context;
    /// callers of the typed state API must provide it explicitly.
    pub descriptor: ObjectRef,
    pub importer_profile: ProfileRef,
    pub source_namespace_digest: [u8; 32],
    pub source_identity_digest: [u8; 32],
    pub file_id: FileId,
    pub state: ImportState,
    pub declared_mapping_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportRequest {
    pub importer_profile: ProfileRef,
    pub source_namespace_digest: [u8; 32],
    pub source_identity_digest: [u8; 32],
    pub requested_file_id: FileId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportDecision {
    pub file_id: FileId,
    pub state: ImportState,
    pub retry: bool,
    pub mapping_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupRoleCardinality {
    pub role: ProfileRef,
    pub minimum: usize,
    pub maximum: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupProfileRule {
    pub profile: ProfileRef,
    pub roles: Vec<GroupRoleCardinality>,
    pub unique_external_key_profiles: Vec<ProfileRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupValidationSummary {
    pub groups: usize,
    pub members: usize,
}

pub struct RepositoryContext<'a> {
    pub lookup: &'a RepositoryObjectLookup,
    pub descriptor: ObjectRef,
    pub designated_root: ObjectRef,
    pub lifetime_records: &'a [LifetimeRecord],
    pub working_lifetime_additions: &'a [LifetimeRecord],
    pub import_mappings: &'a [ImportMapping],
    pub verify_content: bool,
    pub require_complete_lifetime: bool,
    pub group_profile_rules: &'a [GroupProfileRule],
    pub unique_external_key_profiles: &'a [ProfileRef],
    /// Exact-version adapter for the descriptor-selected external path
    /// profile. Built-in `path.test/*@1` conformance profiles do not use it.
    pub path_profile_validator: Option<&'a dyn PathProfileValidator>,
    /// Authenticated case-equivalence mode pinned to the external adapter.
    pub path_case_mode: PathCaseMode,
}

impl<'a> RepositoryContext<'a> {
    pub fn new(
        lookup: &'a RepositoryObjectLookup,
        descriptor: ObjectRef,
        designated_root: ObjectRef,
        path_case_mode: PathCaseMode,
    ) -> Self {
        Self {
            lookup,
            descriptor,
            designated_root,
            lifetime_records: &[],
            working_lifetime_additions: &[],
            import_mappings: &[],
            verify_content: true,
            require_complete_lifetime: false,
            group_profile_rules: &[],
            unique_external_key_profiles: &[],
            path_profile_validator: None,
            path_case_mode,
        }
    }
}

fn complete_lifetime_context<'a>(context: &RepositoryContext<'a>) -> RepositoryContext<'a> {
    RepositoryContext {
        lookup: context.lookup,
        descriptor: context.descriptor,
        designated_root: context.designated_root,
        lifetime_records: context.lifetime_records,
        working_lifetime_additions: context.working_lifetime_additions,
        import_mappings: context.import_mappings,
        verify_content: context.verify_content,
        require_complete_lifetime: true,
        group_profile_rules: context.group_profile_rules,
        unique_external_key_profiles: context.unique_external_key_profiles,
        path_profile_validator: context.path_profile_validator,
        path_case_mode: context.path_case_mode,
    }
}

#[derive(Clone, Debug)]
pub struct AllocationEvidence {
    pub sequence: u64,
    pub operation_code: u8,
    pub after: EntryState,
    operation: Cbor,
}

#[derive(Clone, Debug)]
pub struct ReplaySummary {
    pub state: RepositoryState,
    pub allocations: Vec<AllocationEvidence>,
    pub restorations: Vec<EntryState>,
}

pub fn replay_change_set(
    change_set_reference: ObjectRef,
    base: &RepositoryState,
    context: &RepositoryContext<'_>,
    conflict_set: Option<&Cbor>,
) -> Result<ReplaySummary> {
    context.lookup.require_repository_semantics()?;
    context.lookup.with_operation(|| {
        replay_change_set_operation(change_set_reference, base, context, conflict_set)
    })
}

fn replay_change_set_operation(
    change_set_reference: ObjectRef,
    base: &RepositoryState,
    context: &RepositoryContext<'_>,
    conflict_set: Option<&Cbor>,
) -> Result<ReplaySummary> {
    let base_cost = base.retained_cost()?;
    let change = context
        .lookup
        .resolve_expected(change_set_reference, ObjectKind::ChangeSet)?;
    let operations = array(field(metadata_value(&change)?, 18)?)?;
    let change_cost = derived_value_cost(change.payload.len())?;
    let conflict_cost = conflict_set
        .map(|value| cbor_retained_cost(value, 0))
        .transpose()?
        .unwrap_or(0);
    let reservation = if operations.is_empty() {
        base_cost
    } else {
        base_cost
            .checked_add(change_cost)
            .and_then(|bytes| bytes.checked_add(conflict_cost))
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?
    };
    // Reserve the complete clone/replay workspace before cloning caller-owned
    // state. The guard is released after the direct operation returns.
    let _memory = DerivedMemory::reserve(context.lookup, reservation)?;
    replay_change_set_internal(
        change_set_reference,
        base.clone(),
        context,
        conflict_set,
        false,
    )
}

fn preflight_change_set_operations(
    operations: &[Cbor],
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    // Sequence is the first catalogue code in this stage, so finish that pass
    // across the complete bounded operation list before inspecting any
    // transition relationship.
    for (expected_sequence, operation) in operations.iter().enumerate() {
        lookup.checkpoint()?;
        if uint(field(operation, 0)?)? != expected_sequence as u64 {
            return Err(Error::new(ErrorCode::ChangeSetSequenceInvalid));
        }
    }
    for operation in operations {
        lookup.checkpoint()?;
        let code = u8::try_from(uint(field(operation, 1)?)?)
            .map_err(|_| Error::new(ErrorCode::ChangeSetTransitionInvalid))?;
        match code {
            2 => {
                let before = EntryState::from_cbor(field(operation, 2)?)?;
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                if before.path != after.path
                    || before.file_id != after.file_id
                    || before.raw == after.raw
                {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
            }
            3 => {
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                let source = EntryState::from_cbor(field(operation, 4)?)?;
                if source.kind == 1
                    || source.file_id == after.file_id
                    || !same_except(&source.raw, &after.raw, &[0, 2])?
                {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
            }
            4 | 5 => {
                let before = EntryState::from_cbor(field(operation, 2)?)?;
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                let before_parent = parent_path(&before.path);
                let after_parent = parent_path(&after.path);
                let before_name = before.path.last();
                let after_name = after.path.last();
                let relationship_invalid = if code == 4 {
                    before_parent == after_parent || before_name != after_name
                } else {
                    before_parent != after_parent || before_name == after_name
                };
                if !same_except(&before.raw, &after.raw, &[0])?
                    || relationship_invalid
                    || (before.kind == 1 && starts_with_path(&after.path, &before.path))
                {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
            }
            1 | 6..=11 => {}
            _ => return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid)),
        }
    }
    Ok(())
}

fn replay_change_set_internal(
    change_set_reference: ObjectRef,
    base: RepositoryState,
    context: &RepositoryContext<'_>,
    conflict_set: Option<&Cbor>,
    historical: bool,
) -> Result<ReplaySummary> {
    expect_ref_kind(change_set_reference, ObjectKind::ChangeSet)?;
    let object = context
        .lookup
        .resolve_expected(change_set_reference, ObjectKind::ChangeSet)?;
    let change_set = metadata_value(&object)?;
    let operations = array(field(change_set, 18)?)?;
    preflight_replay_closure(change_set, operations, context)?;
    context.lookup.finish_registry_phase()?;
    if object_ref(field(change_set, 16)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
    }
    preflight_change_set_operations(operations, context.lookup)?;
    let mut replay_index_memory = OwnedDerivedMemory::empty(context.lookup);
    let mut immutable_base_file_ids = BTreeSet::new();
    for entry in base.entries.values() {
        context.lookup.checkpoint()?;
        if !immutable_base_file_ids.contains(&entry.file_id) {
            replay_index_memory.grow_by(derived_value_cost(16)?)?;
            immutable_base_file_ids.insert(entry.file_id);
        }
    }
    let mut state = base;
    context.lookup.checkpoint()?;
    let mut allocations = Vec::new();
    let mut restorations = Vec::new();
    for (expected_sequence, operation) in operations.iter().enumerate() {
        context.lookup.checkpoint()?;
        let sequence = uint(field(operation, 0)?)?;
        if sequence != expected_sequence as u64 {
            return Err(Error::new(ErrorCode::ChangeSetSequenceInvalid));
        }
        let code = u8::try_from(uint(field(operation, 1)?)?)
            .map_err(|_| Error::new(ErrorCode::ChangeSetTransitionInvalid))?;
        match code {
            1 => {
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                require_absent(&state.entries, &after.path)?;
                require_parent(&state.entries, &after.path)?;
                require_file_id_absent(
                    &state.entries,
                    after.file_id,
                    context.lookup,
                    ErrorCode::FileIdAlreadyConsumed,
                )?;
                insert_state(&mut state.entries, after.clone(), context.lookup)?;
                allocations.push(AllocationEvidence {
                    sequence,
                    operation_code: code,
                    after,
                    operation: operation.clone(),
                });
            }
            2 => {
                let before = EntryState::from_cbor(field(operation, 2)?)?;
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                get_exact(&state.entries, &before, ErrorCode::FileIdSourceMismatch)?;
                insert_state(&mut state.entries, after, context.lookup)?;
            }
            3 => {
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                let source = EntryState::from_cbor(field(operation, 4)?)?;
                get_exact(&state.entries, &source, ErrorCode::FileIdSourceMismatch)?;
                require_absent(&state.entries, &after.path)?;
                require_parent(&state.entries, &after.path)?;
                require_file_id_absent(
                    &state.entries,
                    after.file_id,
                    context.lookup,
                    ErrorCode::FileIdAlreadyConsumed,
                )?;
                insert_state(&mut state.entries, after.clone(), context.lookup)?;
                allocations.push(AllocationEvidence {
                    sequence,
                    operation_code: code,
                    after,
                    operation: operation.clone(),
                });
            }
            4 | 5 => {
                let before = EntryState::from_cbor(field(operation, 2)?)?;
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                get_exact(&state.entries, &before, ErrorCode::FileIdSourceMismatch)?;
                require_absent(&state.entries, &after.path)?;
                require_parent(&state.entries, &after.path)?;
                if before.kind == 1 {
                    replace_prefix(
                        &mut state.entries,
                        &before.path,
                        &after.path,
                        context.lookup,
                    )?;
                } else {
                    state.entries.remove(&before.path);
                    insert_state(&mut state.entries, after, context.lookup)?;
                }
            }
            6 => {
                let before = EntryState::from_cbor(field(operation, 2)?)?;
                get_exact(&state.entries, &before, ErrorCode::FileIdSourceMismatch)?;
                if before.kind == 1
                    && has_descendants(&state.entries, &before.path, context.lookup)?
                {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
                state.entries.remove(&before.path);
            }
            7 => {
                let after = EntryState::from_cbor(field(operation, 3)?)?;
                require_absent(&state.entries, &after.path)?;
                require_parent(&state.entries, &after.path)?;
                if immutable_base_file_ids.contains(&after.file_id) {
                    return Err(Error::new(ErrorCode::FileIdRestoreProofInvalid));
                }
                require_file_id_absent(
                    &state.entries,
                    after.file_id,
                    context.lookup,
                    ErrorCode::FileIdRestoreProofInvalid,
                )?;
                let base_snapshot = optional_field(change_set, 17)
                    .map(object_ref)
                    .transpose()?
                    .ok_or_else(|| Error::new(ErrorCode::FileIdRestoreProofInvalid))?;
                validate_restore(operation, &after, base_snapshot, context)?;
                insert_state(&mut state.entries, after.clone(), context.lookup)?;
                restorations.push(after);
            }
            8 => {
                let after = AssetGroup::from_cbor(field(operation, 8)?)?;
                if state.groups.contains_key(&after.id) {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
                context.lookup.scratch(after.encoded_len(context.lookup)?)?;
                state.groups.insert(after.id, after);
            }
            9 => {
                let before = AssetGroup::from_cbor(field(operation, 7)?)?;
                let after = AssetGroup::from_cbor(field(operation, 8)?)?;
                if before.id != after.id || state.groups.get(&before.id) != Some(&before) {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
                context.lookup.scratch(after.encoded_len(context.lookup)?)?;
                state.groups.insert(after.id, after);
            }
            10 => {
                let before = AssetGroup::from_cbor(field(operation, 7)?)?;
                if state.groups.get(&before.id) != Some(&before) {
                    return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
                }
                state.groups.remove(&before.id);
            }
            11 => {
                replay_merge_resolution(operation, &mut state, conflict_set, context.lookup)?;
            }
            _ => return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid)),
        }
    }
    let mut lifetime_file_ids = immutable_base_file_ids;
    for entry in state.entries.values() {
        context.lookup.checkpoint()?;
        if !lifetime_file_ids.contains(&entry.file_id) {
            replay_index_memory.grow_by(derived_value_cost(16)?)?;
            lifetime_file_ids.insert(entry.file_id);
        }
    }
    validate_lifetime_and_imports_inner(
        context,
        Some(change_set_reference),
        &allocations,
        Some(&lifetime_file_ids),
        &restorations,
        false,
        historical,
        None,
    )?;
    Ok(ReplaySummary {
        state,
        allocations,
        restorations,
    })
}

fn preflight_replay_closure(
    change_set: &Cbor,
    operations: &[Cbor],
    context: &RepositoryContext<'_>,
) -> Result<()> {
    let mut scheduled = BTreeSet::new();
    let mut stack = Vec::new();
    let mut memory = OwnedDerivedMemory::empty(context.lookup);
    let mut lookup_error = None;
    schedule_replay_reference(
        context.descriptor,
        ObjectKind::RepositoryDescriptor,
        context.lookup,
        &mut scheduled,
        &mut stack,
        &mut memory,
    )?;
    schedule_replay_change_set(
        change_set,
        operations,
        context,
        &mut scheduled,
        &mut stack,
        &mut memory,
    )?;
    while let Some(reference) = stack.pop() {
        context.lookup.checkpoint()?;
        let Some(object) = collect_lookup_result(
            &mut lookup_error,
            context.lookup.edge(reference, reference.kind),
        )?
        else {
            continue;
        };
        if reference.kind == ObjectKind::Chunk || reference.kind == ObjectKind::RepositoryDescriptor
        {
            continue;
        }
        let value = metadata_value(&object)?;
        match reference.kind {
            ObjectKind::Snapshot => {
                schedule_replay_reference(
                    object_ref(field(value, 16)?)?,
                    ObjectKind::RepositoryDescriptor,
                    context.lookup,
                    &mut scheduled,
                    &mut stack,
                    &mut memory,
                )?;
                for parent in array(field(value, 17)?)? {
                    schedule_replay_reference(
                        object_ref(parent)?,
                        ObjectKind::Snapshot,
                        context.lookup,
                        &mut scheduled,
                        &mut stack,
                        &mut memory,
                    )?;
                }
                for (field_number, kind) in [(18, ObjectKind::Tree), (19, ObjectKind::ChangeSet)] {
                    schedule_replay_reference(
                        object_ref(field(value, field_number)?)?,
                        kind,
                        context.lookup,
                        &mut scheduled,
                        &mut stack,
                        &mut memory,
                    )?;
                }
                if let Some(groups) = optional_field(value, 20) {
                    schedule_replay_reference(
                        object_ref(groups)?,
                        ObjectKind::AssetGroupSet,
                        context.lookup,
                        &mut scheduled,
                        &mut stack,
                        &mut memory,
                    )?;
                }
            }
            ObjectKind::ChangeSet => {
                schedule_replay_change_set(
                    value,
                    array(field(value, 18)?)?,
                    context,
                    &mut scheduled,
                    &mut stack,
                    &mut memory,
                )?;
            }
            ObjectKind::Tree => {
                schedule_replay_reference(
                    object_ref(field(value, 16)?)?,
                    ObjectKind::RepositoryDescriptor,
                    context.lookup,
                    &mut scheduled,
                    &mut stack,
                    &mut memory,
                )?;
                for raw_entry in array(field(value, 17)?)? {
                    context.lookup.checkpoint()?;
                    let kind = if uint(field(raw_entry, 1)?)? == 1 {
                        ObjectKind::Tree
                    } else {
                        ObjectKind::ContentManifest
                    };
                    schedule_replay_reference(
                        object_ref(field(raw_entry, 4)?)?,
                        kind,
                        context.lookup,
                        &mut scheduled,
                        &mut stack,
                        &mut memory,
                    )?;
                }
            }
            ObjectKind::ContentManifest if context.verify_content => {
                for part in array(field(value, 19)?)? {
                    context.lookup.checkpoint()?;
                    schedule_replay_reference(
                        object_ref(field(part, 0)?)?,
                        ObjectKind::Chunk,
                        context.lookup,
                        &mut scheduled,
                        &mut stack,
                        &mut memory,
                    )?;
                }
            }
            ObjectKind::AssetGroupSet => {
                schedule_replay_reference(
                    object_ref(field(value, 16)?)?,
                    ObjectKind::RepositoryDescriptor,
                    context.lookup,
                    &mut scheduled,
                    &mut stack,
                    &mut memory,
                )?;
            }
            _ => {}
        }
    }
    finish_lookup_selection(lookup_error)
}

fn schedule_replay_reference(
    reference: ObjectRef,
    expected: ObjectKind,
    lookup: &RepositoryObjectLookup,
    scheduled: &mut BTreeSet<ObjectRef>,
    stack: &mut Vec<ObjectRef>,
    memory: &mut OwnedDerivedMemory,
) -> Result<()> {
    expect_ref_kind(reference, expected)?;
    if scheduled.contains(&reference) {
        return Ok(());
    }
    lookup.checkpoint()?;
    memory.grow_by(derived_value_cost(35)?)?;
    scheduled.insert(reference);
    stack.push(reference);
    Ok(())
}

fn schedule_replay_entry_target(
    value: &Cbor,
    context: &RepositoryContext<'_>,
    scheduled: &mut BTreeSet<ObjectRef>,
    stack: &mut Vec<ObjectRef>,
    memory: &mut OwnedDerivedMemory,
) -> Result<()> {
    let state = EntryState::from_cbor(value)?;
    let kind = if state.kind == 1 {
        ObjectKind::Tree
    } else {
        ObjectKind::ContentManifest
    };
    if let Some(target) = state.target {
        schedule_replay_reference(target, kind, context.lookup, scheduled, stack, memory)?;
    }
    Ok(())
}

fn schedule_replay_change_set(
    change_set: &Cbor,
    operations: &[Cbor],
    context: &RepositoryContext<'_>,
    scheduled: &mut BTreeSet<ObjectRef>,
    stack: &mut Vec<ObjectRef>,
    memory: &mut OwnedDerivedMemory,
) -> Result<()> {
    schedule_replay_reference(
        object_ref(field(change_set, 16)?)?,
        ObjectKind::RepositoryDescriptor,
        context.lookup,
        scheduled,
        stack,
        memory,
    )?;
    if let Some(base) = optional_field(change_set, 17) {
        schedule_replay_reference(
            object_ref(base)?,
            ObjectKind::Snapshot,
            context.lookup,
            scheduled,
            stack,
            memory,
        )?;
    }
    for operation in operations {
        context.lookup.checkpoint()?;
        for key in [2, 3, 4] {
            if let Some(state) = optional_field(operation, key) {
                schedule_replay_entry_target(state, context, scheduled, stack, memory)?;
            }
        }
        if optional_field(operation, 10)
            .map(|value| uint(value))
            .transpose()?
            == Some(1)
        {
            if let Some(state) = optional_field(operation, 11) {
                schedule_replay_entry_target(state, context, scheduled, stack, memory)?;
            }
        }
        if let Some(proof) = optional_field(operation, 5) {
            schedule_replay_reference(
                object_ref(field(proof, 0)?)?,
                ObjectKind::RepositoryDescriptor,
                context.lookup,
                scheduled,
                stack,
                memory,
            )?;
        }
        if uint(field(operation, 1)?)? == 7 {
            if let Some(proof) = optional_field(operation, 6) {
                schedule_replay_reference(
                    object_ref(field(proof, 0)?)?,
                    ObjectKind::RepositoryDescriptor,
                    context.lookup,
                    scheduled,
                    stack,
                    memory,
                )?;
                for key in [1, 3] {
                    if let Some(snapshot) = optional_field(proof, key) {
                        schedule_replay_reference(
                            object_ref(snapshot)?,
                            ObjectKind::Snapshot,
                            context.lookup,
                            scheduled,
                            stack,
                            memory,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn insert_state(
    entries: &mut BTreeMap<Vec<String>, EntryState>,
    state: EntryState,
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    lookup.scratch(state.encoded_len(lookup)?)?;
    entries.insert(state.path.clone(), state);
    Ok(())
}

fn get_exact<'a>(
    entries: &'a BTreeMap<Vec<String>, EntryState>,
    expected: &EntryState,
    error: ErrorCode,
) -> Result<&'a EntryState> {
    entries
        .get(&expected.path)
        .filter(|current| current.raw == expected.raw)
        .ok_or_else(|| Error::new(error))
}

fn require_absent(entries: &BTreeMap<Vec<String>, EntryState>, path: &[String]) -> Result<()> {
    if entries.contains_key(path) {
        Err(Error::new(ErrorCode::ChangeSetTransitionInvalid))
    } else {
        Ok(())
    }
}

fn require_parent(entries: &BTreeMap<Vec<String>, EntryState>, path: &[String]) -> Result<()> {
    let parent = parent_path(path);
    if parent.is_empty() {
        return Ok(());
    }
    if entries.get(parent).is_some_and(|state| state.kind == 1) {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::ChangeSetTransitionInvalid))
    }
}

fn require_file_id_absent(
    entries: &BTreeMap<Vec<String>, EntryState>,
    file_id: FileId,
    lookup: &RepositoryObjectLookup,
    error: ErrorCode,
) -> Result<()> {
    for state in entries.values() {
        lookup.checkpoint()?;
        if state.file_id == file_id {
            return Err(Error::new(error));
        }
    }
    Ok(())
}

fn parent_path(path: &[String]) -> &[String] {
    &path[..path.len().saturating_sub(1)]
}

fn starts_with_path(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

fn has_descendants(
    entries: &BTreeMap<Vec<String>, EntryState>,
    prefix: &[String],
    lookup: &RepositoryObjectLookup,
) -> Result<bool> {
    for path in entries.keys() {
        lookup.checkpoint()?;
        if path.len() > prefix.len() && starts_with_path(path, prefix) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn replace_prefix(
    entries: &mut BTreeMap<Vec<String>, EntryState>,
    before: &[String],
    after: &[String],
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    let mut workspace = OwnedDerivedMemory::empty(lookup);
    let mut affected = Vec::new();
    for (path, state) in entries.iter() {
        lookup.checkpoint()?;
        if path == before || starts_with_path(path, before) {
            let retained = state
                .retained_cost()?
                .checked_add(path_retained_cost(path)?)
                .and_then(|bytes| bytes.checked_add(128))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            workspace.grow_by(retained)?;
            affected.push((path.clone(), state.clone()));
        }
    }
    let mut old_paths = BTreeSet::new();
    for (path, _) in &affected {
        lookup.checkpoint()?;
        let retained = path_retained_cost(path)?
            .checked_add(128)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        workspace.grow_by(retained)?;
        old_paths.insert(path.clone());
    }
    let mut replacements = Vec::new();
    for (_, original) in &affected {
        lookup.checkpoint()?;
        let mut state = original.clone();
        let mut next = after.to_vec();
        next.extend_from_slice(&state.path[before.len()..]);
        if entries.contains_key(&next) && !old_paths.contains(&next) {
            return Err(Error::new(ErrorCode::ChangeSetTransitionInvalid));
        }
        state.path = next.clone();
        set_numeric_field(&mut state.raw, 0, path_cbor(&next))?;
        lookup.scratch(state.encoded_len(lookup)?)?;
        let retained = state
            .retained_cost()?
            .checked_add(path_retained_cost(&next)?)
            .and_then(|bytes| bytes.checked_add(128))
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        workspace.grow_by(retained)?;
        replacements.push((next, state));
    }
    for (path, _) in affected {
        lookup.checkpoint()?;
        entries.remove(&path);
    }
    for (path, state) in replacements {
        lookup.checkpoint()?;
        entries.insert(path, state);
    }
    Ok(())
}

fn set_numeric_field(value: &mut Cbor, key: u64, replacement: Cbor) -> Result<()> {
    let Cbor::Map(entries) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    let slot = entries
        .iter_mut()
        .find_map(|(candidate, value)| (*candidate == Cbor::UInt(key)).then_some(value))
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    *slot = replacement;
    Ok(())
}

fn same_except(left: &Cbor, right: &Cbor, ignored: &[u64]) -> Result<bool> {
    let Cbor::Map(left) = left else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    let Cbor::Map(right) = right else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    let filtered = |values: &[(Cbor, Cbor)]| {
        values
            .iter()
            .filter(|(key, _)| match key {
                Cbor::UInt(key) => !ignored.contains(key),
                _ => true,
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    Ok(filtered(left) == filtered(right))
}

fn snapshot_object(reference: ObjectRef, lookup: &RepositoryObjectLookup) -> Result<Arc<Cbor>> {
    lookup
        .edge(reference, ObjectKind::Snapshot)?
        .value
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn is_ancestor(
    ancestor: ObjectRef,
    descendant: ObjectRef,
    lookup: &RepositoryObjectLookup,
    allow_self: bool,
) -> Result<bool> {
    if allow_self && ancestor == descendant {
        return Ok(true);
    }
    let mut seen = BTreeSet::new();
    let mut stack = vec![descendant];
    let mut memory = OwnedDerivedMemory::empty(lookup);
    memory.grow_by(derived_value_cost(34)?)?;
    while let Some(current) = stack.pop() {
        lookup.checkpoint()?;
        if seen.contains(&current) {
            continue;
        }
        memory.grow_by(derived_value_cost(34)?)?;
        seen.insert(current);
        let snapshot = snapshot_object(current, lookup)?;
        for parent in array(field(snapshot.as_ref(), 17)?)? {
            let parent = object_ref(parent)?;
            if parent == ancestor {
                return Ok(true);
            }
            memory.grow_by(derived_value_cost(34)?)?;
            stack.push(parent);
        }
    }
    Ok(false)
}

struct MaterializedRepositoryState {
    state: RepositoryState,
    _tree_memory: OwnedDerivedMemory,
    _group_memory: OwnedDerivedMemory,
}

fn state_at_snapshot(
    snapshot_reference: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<MaterializedRepositoryState> {
    let snapshot = snapshot_object(snapshot_reference, context.lookup)?;
    if object_ref(field(&snapshot, 16)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::FileIdCrossRepositoryProof));
    }
    let tree = expand_tree_owned(
        object_ref(field(&snapshot, 18)?)?,
        context.lookup,
        context.descriptor,
        context.verify_content,
        context.path_case_mode,
        context.path_profile_validator,
    )?;
    let groups = groups_from_set(
        optional_field(&snapshot, 20).map(object_ref).transpose()?,
        context.lookup,
        context.descriptor,
    )?;
    Ok(MaterializedRepositoryState {
        state: RepositoryState {
            entries: tree.entries,
            groups: groups.groups,
        },
        _tree_memory: tree.memory,
        _group_memory: groups.memory,
    })
}

fn validate_restore(
    operation: &Cbor,
    after: &EntryState,
    base_snapshot: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<()> {
    let proof = field(operation, 6)?;
    if object_ref(field(proof, 0)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::FileIdCrossRepositoryProof));
    }
    let source = object_ref(field(proof, 1)?)?;
    let source_path = path(field(proof, 2)?)?;
    let deleted = object_ref(field(proof, 3)?)?;
    if !is_ancestor(source, deleted, context.lookup, false)?
        || !is_ancestor(deleted, base_snapshot, context.lookup, true)?
    {
        return Err(Error::new(ErrorCode::FileIdRestoreProofInvalid));
    }
    let source_state = state_at_snapshot(source, context)?
        .state
        .entries
        .remove(&source_path)
        .filter(|state| state.raw == after.raw)
        .ok_or_else(|| Error::new(ErrorCode::FileIdRestoreProofInvalid))?;
    let delete_snapshot = snapshot_object(deleted, context.lookup)?;
    if object_ref(field(&delete_snapshot, 16)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::FileIdCrossRepositoryProof));
    }
    let delete_change = context.lookup.edge(
        object_ref(field(&delete_snapshot, 19)?)?,
        ObjectKind::ChangeSet,
    )?;
    let delete_change = metadata_value(&delete_change)?;
    if object_ref(field(delete_change, 16)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::FileIdCrossRepositoryProof));
    }
    let mut contains_delete = false;
    for operation in array(field(delete_change, 18)?)? {
        context.lookup.checkpoint()?;
        if uint(field(operation, 1).unwrap_or(&Cbor::UInt(0))).ok() == Some(6)
            && optional_field(operation, 2).is_some_and(|before| before == &source_state.raw)
        {
            contains_delete = true;
            break;
        }
    }
    if !contains_delete {
        return Err(Error::new(ErrorCode::FileIdRestoreProofInvalid));
    }
    Ok(())
}

fn replay_merge_resolution(
    operation: &Cbor,
    state: &mut RepositoryState,
    conflict_set: Option<&Cbor>,
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    let wanted = digest32(field(operation, 9)?)?;
    let records = conflict_set
        .and_then(|set| optional_field(set, 17))
        .and_then(|records| array(records).ok())
        .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?;
    let mut record = None;
    for candidate in records {
        lookup.checkpoint()?;
        if optional_field(candidate, 0).and_then(|value| digest32(value).ok()) == Some(wanted) {
            record = Some(candidate);
            break;
        }
    }
    let record = record.ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?;
    let subject_kind = uint(field(operation, 10)?)?;
    if uint(
        array(field(record, 2)?)?
            .first()
            .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?,
    )? != subject_kind
    {
        return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
    }
    let resolution = field(record, 6)?;
    if uint(field(resolution, 0)?)? != 1 {
        return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
    }
    let choice = uint(field(resolution, 1)?)?;
    clear_conflict_subject(state, record, lookup)?;
    if choice == 4 {
        if optional_field(operation, 11).is_some() {
            return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
        }
        return Ok(());
    }
    let side = field(resolution, 2)?;
    let side_value = field(side, if subject_kind == 1 { 1 } else { 2 })?;
    if optional_field(operation, 11) != Some(side_value) {
        return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
    }
    if subject_kind == 1 {
        insert_state(
            &mut state.entries,
            EntryState::from_cbor(side_value)?,
            lookup,
        )?;
    } else {
        let group = AssetGroup::from_cbor(side_value)?;
        lookup.scratch(group.encoded_len(lookup)?)?;
        state.groups.insert(group.id, group);
    }
    Ok(())
}

fn clear_conflict_subject(
    state: &mut RepositoryState,
    record: &Cbor,
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    let subject = array(field(record, 2)?)?;
    match uint(
        subject
            .first()
            .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?,
    )? {
        1 => {
            let file_ids = array(
                subject
                    .get(1)
                    .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?,
            )?
            .iter()
            .map(file_id)
            .collect::<Result<BTreeSet<_>>>()?;
            let paths = array(
                subject
                    .get(2)
                    .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?,
            )?
            .iter()
            .map(path)
            .collect::<Result<BTreeSet<_>>>()?;
            let path_collision = uint(field(record, 1)?)? == 8;
            // Complete all deadline checks before mutating the caller-visible
            // replay workspace so a deadline failure cannot leave a partial
            // resolution applied.
            for _ in state.entries.values() {
                lookup.checkpoint()?;
            }
            state.entries.retain(|entry_path, entry| {
                !paths.contains(entry_path)
                    && (path_collision || !file_ids.contains(&entry.file_id))
            });
        }
        2 => {
            let id = id128(
                subject
                    .get(1)
                    .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?,
            )?;
            state.groups.remove(&id);
        }
        _ => return Err(Error::new(ErrorCode::ConflictResolutionMismatch)),
    }
    Ok(())
}

pub fn import_mapping_key(descriptor: ObjectRef, mapping: &ImportMapping) -> Result<[u8; 32]> {
    expect_ref_kind(descriptor, ObjectKind::RepositoryDescriptor)?;
    let payload = encode_canonical(&Cbor::Array(vec![
        descriptor.to_cbor(),
        mapping.importer_profile.to_cbor(),
        Cbor::Bytes(mapping.source_namespace_digest.to_vec()),
        Cbor::Bytes(mapping.source_identity_digest.to_vec()),
    ]))?;
    let mut hash = Sha256Writer::new();
    hash.update(IMPORT_MAPPING_DOMAIN);
    hash.update(&1u16.to_be_bytes());
    hash.update(&payload);
    Ok(hash.finish())
}

pub fn validate_import_request(
    context: &RepositoryContext<'_>,
    request: &ImportRequest,
) -> Result<ImportDecision> {
    context.lookup.require_repository_semantics()?;
    context
        .lookup
        .with_operation(|| validate_import_request_operation(context, request))
}

fn validate_import_request_operation(
    context: &RepositoryContext<'_>,
    request: &ImportRequest,
) -> Result<ImportDecision> {
    validate_lifetime_and_imports_inner(context, None, &[], None, &[], true, false, Some(request))?
        .ok_or_else(|| Error::new(ErrorCode::FileIdImportMappingConflict))
}

pub fn validate_lifetime_and_imports(
    context: &RepositoryContext<'_>,
    change_set_reference: ObjectRef,
    allocations: &[AllocationEvidence],
    entries: Option<&BTreeMap<Vec<String>, EntryState>>,
) -> Result<()> {
    context.lookup.require_repository_semantics()?;
    context.lookup.with_operation(|| {
        validate_lifetime_and_imports_operation(context, change_set_reference, allocations, entries)
    })
}

fn validate_lifetime_and_imports_operation(
    context: &RepositoryContext<'_>,
    change_set_reference: ObjectRef,
    allocations: &[AllocationEvidence],
    entries: Option<&BTreeMap<Vec<String>, EntryState>>,
) -> Result<()> {
    let mut file_id_memory = None;
    let file_ids = if let Some(entries) = entries {
        let bytes = entries
            .len()
            .checked_mul(derived_value_cost(16)?)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        file_id_memory = Some(DerivedMemory::reserve(context.lookup, bytes)?);
        let mut file_ids = BTreeSet::new();
        for entry in entries.values() {
            context.lookup.checkpoint()?;
            file_ids.insert(entry.file_id);
        }
        Some(file_ids)
    } else {
        None
    };
    let result = validate_lifetime_and_imports_inner(
        context,
        Some(change_set_reference),
        allocations,
        file_ids.as_ref(),
        &[],
        false,
        false,
        None,
    )
    .map(|_| ());
    drop(file_id_memory);
    result
}

fn validate_lifetime_and_imports_inner(
    context: &RepositoryContext<'_>,
    change_set_reference: Option<ObjectRef>,
    allocations: &[AllocationEvidence],
    entry_file_ids: Option<&BTreeSet<FileId>>,
    restorations: &[EntryState],
    allow_unrelated_working: bool,
    historical: bool,
    import_request: Option<&ImportRequest>,
) -> Result<Option<ImportDecision>> {
    let mut workspace_bytes = 2_048usize;
    let mut add_workspace = |bytes: usize| -> Result<()> {
        workspace_bytes = workspace_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        Ok(())
    };
    for _ in context.lifetime_records {
        add_workspace(512)?;
    }
    for mapping in context.import_mappings {
        add_workspace(
            768usize
                .checked_add(mapping.importer_profile.namespace().len().saturating_mul(2))
                .and_then(|bytes| {
                    bytes.checked_add(mapping.importer_profile.id().len().saturating_mul(2))
                })
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
        )?;
    }
    for allocation in allocations {
        add_workspace(
            allocation
                .after
                .retained_cost()?
                .checked_add(cbor_retained_cost(&allocation.operation, 0)?)
                .and_then(|bytes| bytes.checked_add(512))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
        )?;
    }
    for _ in context.working_lifetime_additions {
        add_workspace(512)?;
    }
    for restoration in restorations {
        add_workspace(restoration.retained_cost()?.saturating_add(256))?;
    }
    let _workspace = DerivedMemory::reserve(context.lookup, workspace_bytes)?;

    // Whole-input authority phase: known profile-family assignments and every
    // syntactically kind-4 lifetime reference are checked before any duplicate,
    // tuple, or lifetime semantics. Unknown/lifecycle decisions remain L3 and
    // are ranked only after this complete L2 pass.
    for mapping in context.import_mappings {
        context.lookup.checkpoint()?;
        expect_ref_kind(mapping.descriptor, ObjectKind::RepositoryDescriptor)?;
        if context
            .lookup
            .registry
            .profile(&mapping.importer_profile)
            .is_some_and(|entry| entry.family != "importer")
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
    }
    if let Some(request) = import_request {
        if context
            .lookup
            .registry
            .profile(&request.importer_profile)
            .is_some_and(|entry| entry.family != "importer")
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
    }
    let mut missing_lifetime_reference = false;
    for record in context
        .lifetime_records
        .iter()
        .chain(context.working_lifetime_additions.iter())
    {
        context.lookup.checkpoint()?;
        match context
            .lookup
            .resolve_expected(record.first_change_set, ObjectKind::ChangeSet)
        {
            Ok(_) => {}
            Err(error) if error.code == ErrorCode::ObjectReferenceMissing => {
                missing_lifetime_reference = true;
            }
            Err(error) => return Err(error),
        }
    }
    let mut registry_error = None;
    for mapping in context.import_mappings {
        context.lookup.checkpoint()?;
        if let Err(error) = context.lookup.registry.check_profile(
            &mapping.importer_profile,
            "importer",
            context.lookup.mode.operation(),
        ) {
            observe_lookup_error(&mut registry_error, error);
        }
    }
    if let Some(request) = import_request {
        if let Err(error) = context.lookup.registry.check_profile(
            &request.importer_profile,
            "importer",
            context.lookup.mode.operation(),
        ) {
            observe_lookup_error(&mut registry_error, error);
        }
    }
    if let Err(error) = context.lookup.finish_registry_phase() {
        observe_lookup_error(&mut registry_error, error);
    }
    if let Some(error) = registry_error {
        return Err(error);
    }
    if missing_lifetime_reference {
        return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
    }

    let mut prior = BTreeMap::new();
    for record in context.lifetime_records {
        context.lookup.checkpoint()?;
        if prior.insert(record.file_id, record).is_some() {
            return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
        }
    }

    type MappingTuple = (ProfileRef, [u8; 32], [u8; 32]);
    let mut mappings = BTreeMap::<MappingTuple, (&ImportMapping, [u8; 32])>::new();
    let mut mappings_by_key = BTreeMap::<[u8; 32], &ImportMapping>::new();
    let mut mapped_files = BTreeMap::<FileId, MappingTuple>::new();
    for mapping in context.import_mappings {
        context.lookup.checkpoint()?;
        if mapping.descriptor != context.descriptor {
            return Err(Error::new(ErrorCode::FileIdCrossRepositoryProof));
        }
        let key = import_mapping_key(mapping.descriptor, mapping)?;
        if mapping.declared_mapping_key != key {
            return Err(Error::new(ErrorCode::FileIdImportMappingConflict));
        }
        let tuple = (
            mapping.importer_profile.clone(),
            mapping.source_namespace_digest,
            mapping.source_identity_digest,
        );
        if mappings.contains_key(&tuple)
            || mappings_by_key.contains_key(&key)
            || mapped_files
                .get(&mapping.file_id)
                .is_some_and(|owner| owner != &tuple)
        {
            return Err(Error::new(ErrorCode::FileIdImportMappingConflict));
        }
        mappings.insert(tuple.clone(), (mapping, key));
        mappings_by_key.insert(key, mapping);
        mapped_files.insert(mapping.file_id, tuple);
    }
    for (mapping, key) in mappings.values() {
        context.lookup.checkpoint()?;
        if prior.get(&mapping.file_id).is_some_and(|evidence| {
            evidence.origin != LifetimeOrigin::Import || evidence.import_mapping_key != Some(*key)
        }) {
            return Err(Error::new(ErrorCode::FileIdImportMappingConflict));
        }
    }

    if !historical {
        let mut native_allocations = BTreeSet::new();
        for allocation in allocations {
            context.lookup.checkpoint()?;
            let proof = field(&allocation.operation, 5)?;
            if uint(field(proof, 1)?)? != 2
                && (prior.contains_key(&allocation.after.file_id)
                    || !native_allocations.insert(allocation.after.file_id))
            {
                return Err(Error::new(ErrorCode::FileIdAlreadyConsumed));
            }
        }
    }

    let mut expected = BTreeMap::<FileId, LifetimeRecord>::new();
    for allocation in allocations {
        context.lookup.checkpoint()?;
        let file_id = allocation.after.file_id;
        let proof = field(&allocation.operation, 5)?;
        if object_ref(field(proof, 0)?)? != context.descriptor {
            return Err(Error::new(ErrorCode::FileIdCrossRepositoryProof));
        }
        let allocation_kind = uint(field(proof, 1)?)?;
        let mapping_key = optional_field(proof, 2).map(digest32).transpose()?;
        let origin = if allocation_kind == 2 {
            LifetimeOrigin::Import
        } else if allocation.operation_code == 1 {
            LifetimeOrigin::NativeCreate
        } else {
            LifetimeOrigin::NativeCopy
        };
        if origin == LifetimeOrigin::Import {
            let mapping_key =
                mapping_key.ok_or_else(|| Error::new(ErrorCode::FileIdImportMappingConflict))?;
            if !mappings_by_key
                .get(&mapping_key)
                .is_some_and(|mapping| mapping.file_id == file_id)
            {
                return Err(Error::new(ErrorCode::FileIdImportMappingConflict));
            }
            let evidence = prior
                .get(&file_id)
                .ok_or_else(|| Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid))?;
            if evidence.origin != LifetimeOrigin::Import
                || evidence.import_mapping_key != Some(mapping_key)
                || Some(evidence.first_change_set) != change_set_reference
                || evidence.first_operation != allocation.sequence
            {
                return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
            }
            continue;
        }
        if historical {
            let evidence = prior
                .get(&file_id)
                .ok_or_else(|| Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid))?;
            if evidence.origin != origin
                || evidence.import_mapping_key != mapping_key
                || Some(evidence.first_change_set) != change_set_reference
                || evidence.first_operation != allocation.sequence
            {
                return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
            }
            continue;
        }
        if prior.contains_key(&file_id) || expected.contains_key(&file_id) {
            return Err(Error::new(ErrorCode::FileIdAlreadyConsumed));
        }
        expected.insert(
            file_id,
            LifetimeRecord {
                file_id,
                origin,
                first_change_set: change_set_reference
                    .ok_or_else(|| Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid))?,
                first_operation: allocation.sequence,
                import_mapping_key: mapping_key,
            },
        );
    }
    let mut working = BTreeMap::<FileId, &LifetimeRecord>::new();
    if !historical {
        for record in context.working_lifetime_additions {
            context.lookup.checkpoint()?;
            if working.insert(record.file_id, record).is_some()
                || prior.contains_key(&record.file_id)
                || !matches!(
                    record.origin,
                    LifetimeOrigin::NativeCreate | LifetimeOrigin::NativeCopy
                )
                || record.import_mapping_key.is_some()
            {
                return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
            }
        }
        if !allow_unrelated_working && working.len() != expected.len() {
            return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
        }
        for (file_id, record) in &expected {
            context.lookup.checkpoint()?;
            if working.get(file_id).copied() != Some(record) {
                return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
            }
        }
    }

    for restoration in restorations {
        context.lookup.checkpoint()?;
        if !prior.contains_key(&restoration.file_id) {
            return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
        }
    }
    for record in context.lifetime_records {
        context.lookup.checkpoint()?;
        validate_lifetime_record(record, context)?;
    }
    for mapping in context.import_mappings {
        context.lookup.checkpoint()?;
        let key = import_mapping_key(mapping.descriptor, mapping)?;
        if !prior.get(&mapping.file_id).is_some_and(|record| {
            record.origin == LifetimeOrigin::Import && record.import_mapping_key == Some(key)
        }) {
            return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
        }
    }
    if context.require_complete_lifetime {
        for file_id in entry_file_ids
            .into_iter()
            .flat_map(|file_ids| file_ids.iter())
        {
            context.lookup.checkpoint()?;
            if !prior.contains_key(file_id) && !working.contains_key(file_id) {
                return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
            }
        }
    }
    let Some(request) = import_request else {
        return Ok(None);
    };
    let tuple = (
        request.importer_profile.clone(),
        request.source_namespace_digest,
        request.source_identity_digest,
    );
    let mut requested_mapping = ImportMapping {
        descriptor: context.descriptor,
        importer_profile: request.importer_profile.clone(),
        source_namespace_digest: request.source_namespace_digest,
        source_identity_digest: request.source_identity_digest,
        file_id: request.requested_file_id,
        state: ImportState::Reserved,
        declared_mapping_key: [0; 32],
    };
    let requested_key = import_mapping_key(context.descriptor, &requested_mapping)?;
    requested_mapping.declared_mapping_key = requested_key;
    if let Some((mapping, _)) = mappings.get(&tuple) {
        if mapping.file_id != request.requested_file_id {
            return Err(Error::new(ErrorCode::FileIdImportMappingConflict));
        }
        return Ok(Some(ImportDecision {
            file_id: mapping.file_id,
            state: mapping.state,
            retry: true,
            mapping_key: requested_key,
        }));
    }
    if mapped_files.contains_key(&request.requested_file_id)
        || prior.contains_key(&request.requested_file_id)
        || working.contains_key(&request.requested_file_id)
    {
        return Err(Error::new(ErrorCode::FileIdImportMappingConflict));
    }
    Ok(Some(ImportDecision {
        file_id: request.requested_file_id,
        state: ImportState::Reserved,
        retry: false,
        mapping_key: requested_key,
    }))
}

fn validate_lifetime_record(
    record: &LifetimeRecord,
    context: &RepositoryContext<'_>,
) -> Result<()> {
    let object = match context
        .lookup
        .resolve_expected(record.first_change_set, ObjectKind::ChangeSet)
    {
        Ok(object) => object,
        Err(error) if error.code == ErrorCode::ObjectReferenceMissing => {
            return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
        }
        Err(error) => return Err(error),
    };
    let change_set = metadata_value(&object)?;
    if object_ref(field(change_set, 16)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
    }
    let operation = array(field(change_set, 18)?)?
        .get(
            usize::try_from(record.first_operation)
                .map_err(|_| Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid))?,
        )
        .ok_or_else(|| Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid))?;
    if uint(field(operation, 0)?)? != record.first_operation {
        return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
    }
    let code = uint(field(operation, 1)?)?;
    if !matches!(code, 1 | 3) {
        return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
    }
    let after = EntryState::from_cbor(field(operation, 3)?)?;
    if after.file_id != record.file_id {
        return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
    }
    let proof = field(operation, 5)?;
    if object_ref(field(proof, 0)?)? != context.descriptor {
        return Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid));
    }
    let allocation_kind = uint(field(proof, 1)?)?;
    let proof_mapping = optional_field(proof, 2).map(digest32).transpose()?;
    let matches = match record.origin {
        LifetimeOrigin::NativeCreate => {
            code == 1
                && allocation_kind == 1
                && proof_mapping.is_none()
                && record.import_mapping_key.is_none()
        }
        LifetimeOrigin::NativeCopy => {
            code == 3
                && allocation_kind == 1
                && proof_mapping.is_none()
                && record.import_mapping_key.is_none()
        }
        LifetimeOrigin::Import => {
            allocation_kind == 2
                && proof_mapping.is_some()
                && proof_mapping == record.import_mapping_key
        }
    };
    if matches {
        Ok(())
    } else {
        Err(Error::new(ErrorCode::FileIdLifetimeEvidenceInvalid))
    }
}

#[derive(Clone, Debug)]
pub struct ConflictSummary {
    pub records: Vec<Cbor>,
}

struct ReservedConflictSummary<'a> {
    summary: ConflictSummary,
    _memory: DerivedMemory<'a>,
}

pub fn validate_conflict_set(
    reference: Option<ObjectRef>,
    lookup: &RepositoryObjectLookup,
    descriptor: ObjectRef,
    published: bool,
) -> Result<ConflictSummary> {
    lookup.require_repository_semantics()?;
    lookup.with_operation(|| {
        validate_conflict_set_owned(reference, lookup, descriptor, published)
            .map(|owned| owned.summary)
    })
}

fn validate_conflict_set_owned<'a>(
    reference: Option<ObjectRef>,
    lookup: &'a RepositoryObjectLookup,
    descriptor: ObjectRef,
    published: bool,
) -> Result<ReservedConflictSummary<'a>> {
    lookup.require_repository_semantics()?;
    let Some(reference) = reference else {
        return Ok(ReservedConflictSummary {
            summary: ConflictSummary {
                records: Vec::new(),
            },
            _memory: DerivedMemory::reserve(lookup, 0)?,
        });
    };
    let object = lookup.resolve_expected(reference, ObjectKind::ConflictSet)?;
    let set = metadata_value(&object)?;
    // The direct conflict route closes over its authenticated descriptor and
    // every directly carried EntryState target.  This pass is intentionally
    // shallow: content-manifest chunks are not conflict-route dependencies.
    // Complete it before descriptor, conflict, or publication semantics so a
    // missing/wrong-kind edge retains its layer-two precedence.
    let mut lookup_error = None;
    let _ = collect_lookup_result(
        &mut lookup_error,
        lookup.edge(descriptor, ObjectKind::RepositoryDescriptor),
    )?;
    let _ = collect_lookup_result(
        &mut lookup_error,
        lookup.edge(
            object_ref(field(set, 16)?)?,
            ObjectKind::RepositoryDescriptor,
        ),
    )?;
    let records = array(field(set, 17)?)?;
    for record in records {
        lookup.checkpoint()?;
        for key in [3, 4, 5] {
            if let Some(side) = optional_field(record, key) {
                resolve_conflict_entry_target(side, lookup, &mut lookup_error)?;
            }
        }
        let resolution = field(record, 6)?;
        if let Some(side) = optional_field(resolution, 2) {
            resolve_conflict_entry_target(side, lookup, &mut lookup_error)?;
        }
    }
    finish_lookup_selection(lookup_error)?;
    lookup.finish_registry_phase()?;
    if object_ref(field(set, 16)?)? != descriptor {
        return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
    }
    validate_conflict_records(records, published, lookup)?;
    let retained = records.iter().try_fold(256usize, |total, record| {
        total
            .checked_add(cbor_retained_cost(record, 0)?)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    })?;
    let memory = DerivedMemory::reserve(lookup, retained)?;
    Ok(ReservedConflictSummary {
        summary: ConflictSummary {
            records: records.to_vec(),
        },
        _memory: memory,
    })
}

fn resolve_conflict_entry_target(
    side: &Cbor,
    lookup: &RepositoryObjectLookup,
    lookup_error: &mut Option<Error>,
) -> Result<()> {
    if uint(field(side, 0)?)? != 1 {
        return Ok(());
    }
    let state = EntryState::from_cbor(field(side, 1)?)?;
    let expected = if state.kind == 1 {
        ObjectKind::Tree
    } else {
        ObjectKind::ContentManifest
    };
    if let Some(target) = state.target {
        let _ = collect_lookup_result(lookup_error, lookup.edge(target, expected))?;
    }
    Ok(())
}

fn validate_conflict_records(
    records: &[Cbor],
    published: bool,
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    // Declared identities are a lower-layer terminal pass across the complete
    // bounded set. Only then rank independent repository-stage semantics.
    for record in records {
        lookup.checkpoint()?;
        validate_conflict_record_identity(record, Some(lookup))?;
    }
    let mut best = None;
    for record in records {
        lookup.checkpoint()?;
        if let Err(error) = validate_conflict_record_semantics(record, published) {
            if error.layer < 3 || lookup_error_is_terminal(&error) {
                return Err(error);
            }
            observe_lookup_error(&mut best, error);
        }
    }
    if let Some(error) = best {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
fn validate_conflict_record(record: &Cbor, published: bool) -> Result<()> {
    validate_conflict_record_identity(record, None)?;
    validate_conflict_record_semantics(record, published)
}

fn validate_conflict_record_identity(
    record: &Cbor,
    lookup: Option<&RepositoryObjectLookup>,
) -> Result<()> {
    // The keyed preimage clones a bounded projection and canonical-encodes it.
    // Reserve that transient working set before either allocation.
    let _memory = lookup
        .map(|lookup| {
            cbor_retained_cost(record, 0)?
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(512))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
                .and_then(|bytes| DerivedMemory::reserve(lookup, bytes))
        })
        .transpose()?;
    let declared_id = digest32(field(record, 0)?)?;
    if conflict_id(&keyed_conflict_preimage(record)?) != declared_id {
        return Err(Error::new(ErrorCode::ConflictIdMismatch));
    }
    Ok(())
}

fn validate_conflict_record_semantics(record: &Cbor, published: bool) -> Result<()> {
    let kind = uint(field(record, 1)?)?;
    if kind == 5 || !(1..=8).contains(&kind) {
        // Code 5 is an immutable reserved assignment in format v1.
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let subject = array(field(record, 2)?)?;
    let subject_kind = uint(
        subject
            .first()
            .ok_or_else(|| Error::new(ErrorCode::ConflictSubjectInvalid))?,
    )?;
    let base = optional_field(record, 3);
    let left = optional_field(record, 4);
    let right = optional_field(record, 5);
    let resolution = field(record, 6)?;
    if uint(field(resolution, 0)?)? == 0 {
        if published {
            return Err(Error::new(ErrorCode::ConflictUnresolvedPublished));
        }
        return Ok(());
    }
    let choice = uint(field(resolution, 1)?)?;
    if (1..=3).contains(&choice) {
        let selected = optional_field(record, choice + 2)
            .ok_or_else(|| Error::new(ErrorCode::ConflictResolutionMismatch))?;
        if optional_field(resolution, 2) != Some(selected) {
            return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
        }
    }
    if let Some(result) = optional_field(resolution, 2) {
        if uint(field(result, 0)?)? != subject_kind {
            return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
        }
    }
    let valid = if subject_kind == 1 {
        validate_entry_conflict_relationship(kind, subject, base, left, right)?
    } else if subject_kind == 2 {
        validate_group_conflict_relationship(kind, subject, base, left, right)?
    } else {
        false
    };
    if !valid {
        return Err(Error::new(ErrorCode::ConflictSubjectInvalid));
    }
    Ok(())
}

fn validate_entry_conflict_relationship(
    kind: u64,
    subject: &[Cbor],
    base: Option<&Cbor>,
    left: Option<&Cbor>,
    right: Option<&Cbor>,
) -> Result<bool> {
    if subject.len() != 3 {
        return Ok(false);
    }
    let ids = array(&subject[1])?
        .iter()
        .map(file_id)
        .collect::<Result<Vec<_>>>()?;
    let paths = array(&subject[2])?
        .iter()
        .map(path)
        .collect::<Result<Vec<_>>>()?;
    let matches = |side: Option<&Cbor>| -> Result<bool> {
        let Some(side) = side else {
            return Ok(false);
        };
        if uint(field(side, 0)?)? != 1 {
            return Ok(false);
        }
        let state = EntryState::from_cbor(field(side, 1)?)?;
        Ok(ids.contains(&state.file_id) && paths.contains(&state.path))
    };
    let base_ok = matches(base)?;
    let left_ok = matches(left)?;
    let right_ok = matches(right)?;
    let entry = |side: Option<&Cbor>| -> Result<EntryState> {
        EntryState::from_cbor(field(
            side.ok_or_else(|| Error::new(ErrorCode::ConflictSubjectInvalid))?,
            1,
        )?)
    };
    Ok(match kind {
        1 => {
            ids.len() == 1
                && paths.len() == 1
                && base_ok
                && left_ok
                && right_ok
                && entry(left)?.target != entry(right)?.target
        }
        2 => {
            ids.len() == 1
                && (2..=3).contains(&paths.len())
                && base_ok
                && left_ok
                && right_ok
                && entry(left)?.path != entry(right)?.path
        }
        3 => {
            ids.len() == 1
                && paths.len() == 1
                && base_ok
                && ((left.is_none() && right_ok) || (left_ok && right.is_none()))
                && entry(left.or(right))?.raw != entry(base)?.raw
        }
        4 => {
            ids.len() == 1
                && paths.len() == 1
                && base_ok
                && left_ok
                && right_ok
                && entry(left)?.kind != entry(right)?.kind
        }
        6 => {
            ids.len() == 1
                && paths.len() == 1
                && base_ok
                && left_ok
                && right_ok
                && entry(left)?.content_policy != entry(right)?.content_policy
        }
        8 => {
            (2..=3).contains(&ids.len())
                && paths.len() == 1
                && left_ok
                && right_ok
                && entry(left)?.file_id != entry(right)?.file_id
                && (base.is_none() || base_ok)
        }
        _ => false,
    })
}

fn validate_group_conflict_relationship(
    kind: u64,
    subject: &[Cbor],
    base: Option<&Cbor>,
    left: Option<&Cbor>,
    right: Option<&Cbor>,
) -> Result<bool> {
    if subject.len() != 2 || kind != 7 {
        return Ok(false);
    }
    let id = id128(&subject[1])?;
    let matches = |side: Option<&Cbor>| -> Result<bool> {
        let Some(side) = side else {
            return Ok(false);
        };
        Ok(uint(field(side, 0)?)? == 2 && AssetGroup::from_cbor(field(side, 2)?)?.id == id)
    };
    Ok(matches(base)?
        && (left.is_some() || right.is_some())
        && (left.is_none() || matches(left)?)
        && (right.is_none() || matches(right)?)
        && left != right)
}

#[derive(Clone, Debug)]
pub struct SnapshotGraphSummary {
    pub visited: BTreeSet<ObjectRef>,
}

pub fn validate_snapshot_graph(
    candidate: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<SnapshotGraphSummary> {
    context.lookup.require_repository_semantics()?;
    context
        .lookup
        .with_operation(|| validate_snapshot_graph_operation(candidate, context))
}

fn validate_snapshot_graph_operation(
    candidate: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<SnapshotGraphSummary> {
    expect_ref_kind(candidate, ObjectKind::Snapshot)?;
    expect_ref_kind(context.descriptor, ObjectKind::RepositoryDescriptor)?;
    expect_ref_kind(context.designated_root, ObjectKind::Snapshot)?;
    let mut colors = BTreeMap::<ObjectRef, u8>::new();
    let mut visited = BTreeSet::new();
    let mut snapshots = BTreeMap::<ObjectRef, Arc<Cbor>>::new();
    let mut memory = OwnedDerivedMemory::empty(context.lookup);
    let mut saw_cycle = false;
    let mut lookup_error = None;
    memory.grow_by(derived_value_cost(35)?)?;
    let mut stack = vec![(candidate, false)];
    while let Some((reference, exiting)) = stack.pop() {
        context.lookup.checkpoint()?;
        if exiting {
            colors.insert(reference, 2);
            if !visited.contains(&reference) {
                memory.grow_by(derived_value_cost(34)?)?;
            }
            visited.insert(reference);
            continue;
        }
        match colors.get(&reference).copied() {
            Some(1) => {
                saw_cycle = true;
                continue;
            }
            Some(2) => continue,
            _ => {}
        }
        memory.grow_by(derived_value_cost(35)?)?;
        colors.insert(reference, 1);
        let Some(snapshot) = collect_lookup_result(
            &mut lookup_error,
            snapshot_object(reference, context.lookup),
        )?
        else {
            continue;
        };
        let descriptor = object_ref(field(&snapshot, 16)?)?;
        let _ = collect_lookup_result(
            &mut lookup_error,
            context
                .lookup
                .edge(descriptor, ObjectKind::RepositoryDescriptor),
        )?;
        let raw_parents = array(field(&snapshot, 17)?)?;
        memory.grow_by(derived_value_cost(raw_parents.len().saturating_mul(34))?)?;
        let parents = raw_parents
            .iter()
            .map(object_ref)
            .collect::<Result<Vec<_>>>()?;
        let change_reference = object_ref(field(&snapshot, 19)?)?;
        let _ = collect_lookup_result(
            &mut lookup_error,
            context.lookup.edge(change_reference, ObjectKind::ChangeSet),
        )?;
        memory.grow_by(derived_value_cost(64)?)?;
        snapshots.insert(reference, snapshot);
        memory.grow_by(derived_value_cost(35)?)?;
        stack.push((reference, true));
        for parent in parents.into_iter().rev() {
            memory.grow_by(derived_value_cost(35)?)?;
            stack.push((parent, false));
        }
    }

    finish_lookup_selection(lookup_error)?;
    context.lookup.finish_registry_phase()?;

    // All safely discoverable references above are resolved before any
    // repository-layer decision. Then select layer-three failures in the
    // frozen catalogue order, independent of traversal or map order.
    for (reference, snapshot) in &snapshots {
        context.lookup.checkpoint()?;
        let parents = array(field(snapshot, 17)?)?;
        if *reference == context.designated_root {
            if !parents.is_empty() {
                return Err(Error::new(ErrorCode::SnapshotRootInvalid));
            }
        } else if parents.is_empty() {
            return Err(Error::new(ErrorCode::SnapshotRootInvalid));
        }
    }
    if saw_cycle {
        return Err(Error::new(ErrorCode::SnapshotParentCycle));
    }
    for snapshot in snapshots.values() {
        context.lookup.checkpoint()?;
        if object_ref(field(snapshot, 16)?)? != context.descriptor {
            return Err(Error::new(ErrorCode::SnapshotParentCrossRepository));
        }
    }
    if !visited.contains(&context.designated_root) {
        return Err(Error::new(ErrorCode::SnapshotRootInvalid));
    }
    for snapshot in snapshots.values() {
        context.lookup.checkpoint()?;
        let parent_refs = array(field(snapshot, 17)?)?
            .iter()
            .map(object_ref)
            .collect::<Result<Vec<_>>>()?;
        let change = context
            .lookup
            .resolve_expected(object_ref(field(snapshot, 19)?)?, ObjectKind::ChangeSet)?;
        let change = metadata_value(&change)?;
        let base = optional_field(change, 17).map(object_ref).transpose()?;
        if (parent_refs.is_empty() && base.is_some())
            || (!parent_refs.is_empty() && base != parent_refs.first().copied())
        {
            return Err(Error::new(ErrorCode::ChangeSetBaseMismatch));
        }
    }
    Ok(SnapshotGraphSummary { visited })
}

#[derive(Clone, Debug)]
pub struct ProvenanceGraphSummary {
    pub visited: BTreeSet<ObjectRef>,
}

pub fn validate_provenance_graph(
    references: &[ObjectRef],
    lookup: &RepositoryObjectLookup,
    forbidden: &[ObjectRef],
) -> Result<ProvenanceGraphSummary> {
    lookup.require_repository_semantics()?;
    lookup.with_operation(|| validate_provenance_graph_operation(references, lookup, forbidden))
}

fn validate_provenance_graph_operation(
    references: &[ObjectRef],
    lookup: &RepositoryObjectLookup,
    forbidden: &[ObjectRef],
) -> Result<ProvenanceGraphSummary> {
    for reference in references {
        lookup.checkpoint()?;
        expect_ref_kind(*reference, ObjectKind::Provenance)?;
    }
    let mut memory = OwnedDerivedMemory::empty(lookup);
    memory.grow_by(derived_value_cost(forbidden.len().saturating_mul(34))?)?;
    let mut forbidden_set = BTreeSet::new();
    for reference in forbidden {
        lookup.checkpoint()?;
        forbidden_set.insert(*reference);
    }
    // First discover the complete reachable L2 closure without allowing a
    // cycle/forbidden repository error on one branch to hide a missing or
    // wrong-kind edge on another branch.
    let mut reached = BTreeSet::new();
    let mut adjacency = BTreeMap::<ObjectRef, Vec<ObjectRef>>::new();
    let mut lookup_error = None;
    memory.grow_by(derived_value_cost(references.len().saturating_mul(35))?)?;
    let mut closure_stack = Vec::new();
    for reference in references.iter().rev() {
        lookup.checkpoint()?;
        closure_stack.push(*reference);
    }
    while let Some(reference) = closure_stack.pop() {
        lookup.checkpoint()?;
        if forbidden_set.contains(&reference) || reached.contains(&reference) {
            continue;
        }
        memory.grow_by(derived_value_cost(69)?)?;
        reached.insert(reference);
        let Some(object) = collect_lookup_result(&mut lookup_error, lookup.edge_any(reference))?
        else {
            continue;
        };
        let mut inputs = Vec::new();
        if let Some(value) = object.value.as_ref() {
            visit_schema_object_references(
                reference.kind,
                value,
                &lookup.registry,
                lookup.mode.operation(),
                &mut |input| {
                    lookup.checkpoint()?;
                    memory.grow_by(derived_value_cost(35)?)?;
                    inputs.push(input);
                    if !forbidden_set.contains(&input) && !reached.contains(&input) {
                        closure_stack.push(input);
                    }
                    Ok(())
                },
            )?;
        }
        adjacency.insert(reference, inputs);
    }

    finish_lookup_selection(lookup_error)?;
    lookup.finish_registry_phase()?;

    // Repository phase: run cycle/forbidden detection over the already closed
    // adjacency graph. No lookup or caller hook occurs after this boundary.
    let mut colors = BTreeMap::<ObjectRef, u8>::new();
    let mut visited = BTreeSet::new();
    let mut stack = Vec::new();
    for reference in references.iter().rev() {
        memory.grow_by(derived_value_cost(35)?)?;
        stack.push((*reference, false));
    }
    while let Some((reference, exiting)) = stack.pop() {
        lookup.checkpoint()?;
        if forbidden_set.contains(&reference) {
            return Err(Error::new(ErrorCode::ProvenanceCycle));
        }
        if exiting {
            colors.insert(reference, 2);
            if !visited.contains(&reference) {
                memory.grow_by(derived_value_cost(34)?)?;
                visited.insert(reference);
            }
            continue;
        }
        match colors.get(&reference).copied() {
            Some(1) => return Err(Error::new(ErrorCode::ProvenanceCycle)),
            Some(2) => continue,
            _ => {}
        }
        colors.insert(reference, 1);
        memory.grow_by(derived_value_cost(35)?)?;
        stack.push((reference, true));
        for input in adjacency.get(&reference).into_iter().flatten().rev() {
            memory.grow_by(derived_value_cost(35)?)?;
            stack.push((*input, false));
        }
    }
    Ok(ProvenanceGraphSummary { visited })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepositoryValidationSummary {
    pub highest_layer: u8,
    pub entries: usize,
    pub groups: usize,
    pub conflicts: usize,
}

struct DerivedMemory<'a> {
    lookup: &'a RepositoryObjectLookup,
    bytes: usize,
}

impl<'a> DerivedMemory<'a> {
    fn reserve(lookup: &'a RepositoryObjectLookup, bytes: usize) -> Result<Self> {
        lookup.reserve_derived(bytes)?;
        Ok(Self { lookup, bytes })
    }

    fn grow_to(&mut self, bytes: usize) -> Result<()> {
        if bytes > self.bytes {
            self.lookup.reserve_derived(bytes - self.bytes)?;
            self.bytes = bytes;
        }
        Ok(())
    }

    fn shrink_to(&mut self, bytes: usize) {
        if bytes < self.bytes {
            self.lookup.release_derived(self.bytes - bytes);
            self.bytes = bytes;
        }
    }
}

impl Drop for DerivedMemory<'_> {
    fn drop(&mut self) {
        self.lookup.release_derived(self.bytes);
    }
}

struct ReservedRepositoryState<'a> {
    state: RepositoryState,
    memory: DerivedMemory<'a>,
}

impl<'a> ReservedRepositoryState<'a> {
    fn empty(lookup: &'a RepositoryObjectLookup) -> Result<Self> {
        let state = RepositoryState::default();
        let memory = DerivedMemory::reserve(lookup, state.retained_cost()?)?;
        Ok(Self { state, memory })
    }

    fn clone_from(other: &Self) -> Result<Self> {
        // Reserve before cloning so allocation never transiently crosses the
        // configured receiver ceiling.
        let memory = DerivedMemory::reserve(other.memory.lookup, other.memory.bytes)?;
        let state = other.state.clone();
        Ok(Self { state, memory })
    }
}

struct SnapshotReplay<'a> {
    state: ReservedRepositoryState<'a>,
    conflicts: usize,
}

#[derive(Debug)]
struct SnapshotReplayPlan {
    parents: BTreeMap<ObjectRef, Vec<ObjectRef>>,
    remaining_uses: BTreeMap<ObjectRef, usize>,
    _memory: OwnedDerivedMemory,
}

impl SnapshotReplayPlan {
    fn build(roots: &[ObjectRef], context: &RepositoryContext<'_>) -> Result<SnapshotReplayPlan> {
        let mut memory = OwnedDerivedMemory::empty(context.lookup);
        let mut parents = BTreeMap::<ObjectRef, Vec<ObjectRef>>::new();
        let mut checked_roots = BTreeSet::new();
        for root in roots {
            context.lookup.checkpoint()?;
            if !checked_roots.contains(root) {
                memory.grow_by(derived_value_cost(34)?)?;
                checked_roots.insert(*root);
                validate_snapshot_graph(*root, context)?;
            }
            let postorder = snapshot_postorder(*root, context)?;
            for reference in postorder.ordered.iter().copied() {
                context.lookup.checkpoint()?;
                if parents.contains_key(&reference) {
                    continue;
                }
                let snapshot = snapshot_object(reference, context.lookup)?;
                let raw_parents = array(field(&snapshot, 17)?)?;
                memory.grow_by(derived_value_cost(
                    34usize.saturating_mul(raw_parents.len().saturating_add(1)),
                )?)?;
                let mut parent_refs = Vec::new();
                for parent in raw_parents {
                    context.lookup.checkpoint()?;
                    parent_refs.push(object_ref(parent)?);
                }
                parents.insert(reference, parent_refs);
            }
        }
        memory.grow_by(derived_value_cost(parents.len().saturating_mul(42))?)?;
        let mut remaining_uses = BTreeMap::new();
        for reference in parents.keys().copied() {
            context.lookup.checkpoint()?;
            remaining_uses.insert(reference, 0usize);
        }
        for parent_refs in parents.values() {
            context.lookup.checkpoint()?;
            if let Some(parent) = parent_refs.first() {
                *remaining_uses
                    .get_mut(parent)
                    .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))? += 1;
            }
        }
        for root in roots {
            context.lookup.checkpoint()?;
            *remaining_uses
                .get_mut(root)
                .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))? += 1;
        }
        Ok(Self {
            parents,
            remaining_uses,
            _memory: memory,
        })
    }
}

struct SnapshotReplayWorkspace<'a, 'context> {
    context: &'context RepositoryContext<'a>,
    plan: SnapshotReplayPlan,
    cache: BTreeMap<ObjectRef, SnapshotReplay<'a>>,
    completed: BTreeSet<ObjectRef>,
    index_memory: OwnedDerivedMemory,
}

struct ReservedPostorder {
    ordered: Vec<ObjectRef>,
    _memory: OwnedDerivedMemory,
}

fn snapshot_postorder(
    root: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<ReservedPostorder> {
    let mut memory = OwnedDerivedMemory::empty(context.lookup);
    let mut colors = BTreeMap::<ObjectRef, u8>::new();
    let mut ordered = Vec::new();
    memory.grow_by(derived_value_cost(35)?)?;
    let mut stack = vec![(root, false)];
    while let Some((reference, exiting)) = stack.pop() {
        context.lookup.checkpoint()?;
        if exiting {
            colors.insert(reference, 2);
            memory.grow_by(derived_value_cost(34)?)?;
            ordered.push(reference);
            continue;
        }
        match colors.get(&reference).copied() {
            Some(1) => return Err(Error::new(ErrorCode::SnapshotParentCycle)),
            Some(2) => continue,
            _ => {}
        }
        memory.grow_by(derived_value_cost(35)?)?;
        colors.insert(reference, 1);
        let snapshot = snapshot_object(reference, context.lookup)?;
        memory.grow_by(derived_value_cost(35)?)?;
        stack.push((reference, true));
        for parent in array(field(&snapshot, 17)?)?.iter().rev() {
            context.lookup.checkpoint()?;
            memory.grow_by(derived_value_cost(35)?)?;
            stack.push((object_ref(parent)?, false));
        }
    }
    Ok(ReservedPostorder {
        ordered,
        _memory: memory,
    })
}

fn replay_working_reservation(
    state: &ReservedRepositoryState<'_>,
    change_reference: ObjectRef,
    context: &RepositoryContext<'_>,
    conflict_set: Option<&Cbor>,
) -> Result<usize> {
    let change = context
        .lookup
        .resolve_expected(change_reference, ObjectKind::ChangeSet)?;
    let operations = array(field(metadata_value(&change)?, 18)?)?;
    if operations.is_empty() {
        return Ok(state.memory.bytes);
    }
    let change_cost = derived_value_cost(change.payload.len())?;
    let conflict_cost = conflict_set
        .map(|value| cbor_encoded_len(value, context.lookup, 0).and_then(derived_value_cost))
        .transpose()?
        .unwrap_or(0);
    state
        .memory
        .bytes
        .checked_add(change_cost)
        .and_then(|bytes| bytes.checked_add(conflict_cost))
        .and_then(|bytes| bytes.checked_mul(4))
        .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
}

fn replay_reserved_change_set<'a>(
    mut base: ReservedRepositoryState<'a>,
    change_reference: ObjectRef,
    context: &RepositoryContext<'a>,
    conflict_set: Option<&Cbor>,
    historical: bool,
) -> Result<ReservedRepositoryState<'a>> {
    let reservation = replay_working_reservation(&base, change_reference, context, conflict_set)?;
    base.memory.grow_to(reservation)?;
    let replayed = replay_change_set_internal(
        change_reference,
        base.state,
        context,
        conflict_set,
        historical,
    )?;
    let ReplaySummary {
        state,
        allocations: _,
        restorations: _,
    } = replayed;
    let retained = state.retained_cost()?;
    // The conservative preflight above must cover the final state. Keep this
    // defensive check for future operation families before publishing it.
    base.memory.grow_to(retained)?;
    base.memory.shrink_to(retained);
    Ok(ReservedRepositoryState {
        state,
        memory: base.memory,
    })
}

impl<'a, 'context> SnapshotReplayWorkspace<'a, 'context> {
    fn new(roots: &[ObjectRef], context: &'context RepositoryContext<'a>) -> Result<Self> {
        Ok(Self {
            context,
            plan: SnapshotReplayPlan::build(roots, context)?,
            cache: BTreeMap::new(),
            completed: BTreeSet::new(),
            index_memory: OwnedDerivedMemory::empty(context.lookup),
        })
    }

    fn consume_state(&mut self, reference: ObjectRef) -> Result<ReservedRepositoryState<'a>> {
        let remaining = self
            .plan
            .remaining_uses
            .get_mut(&reference)
            .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))?;
        *remaining = remaining
            .checked_sub(1)
            .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))?;
        if *remaining == 0 {
            return self
                .cache
                .remove(&reference)
                .map(|replay| replay.state)
                .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid));
        }
        let cached = self
            .cache
            .get(&reference)
            .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))?;
        ReservedRepositoryState::clone_from(&cached.state)
    }

    fn ensure(&mut self, root: ObjectRef, current: Option<ObjectRef>) -> Result<()> {
        let postorder = snapshot_postorder(root, self.context)?;
        for reference in postorder.ordered.iter().copied() {
            self.context.lookup.checkpoint()?;
            if self.completed.contains(&reference) {
                continue;
            }
            let snapshot = snapshot_object(reference, self.context.lookup)?;
            let parent_count = self
                .plan
                .parents
                .get(&reference)
                .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))?
                .len();
            self.index_memory
                .grow_by(derived_value_cost(parent_count.saturating_mul(34))?)?;
            let parent_refs = self.plan.parents[&reference].clone();
            let base = if let Some(parent) = parent_refs.first() {
                self.consume_state(*parent)?
            } else {
                ReservedRepositoryState::empty(self.context.lookup)?
            };
            let conflict_reference = optional_field(&snapshot, 28).map(object_ref).transpose()?;
            let conflicts = validate_conflict_set_owned(
                conflict_reference,
                self.context.lookup,
                self.context.descriptor,
                true,
            )?;
            let conflict_object = conflict_reference
                .map(|conflict_reference| {
                    self.context
                        .lookup
                        .resolve_expected(conflict_reference, ObjectKind::ConflictSet)
                        .and_then(|object| {
                            object
                                .value
                                .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
                        })
                })
                .transpose()?;
            let change_reference = object_ref(field(&snapshot, 19)?)?;
            let replayed = replay_reserved_change_set(
                base,
                change_reference,
                self.context,
                conflict_object.as_deref(),
                current != Some(reference),
            )?;
            compare_state_to_roots(
                &replayed.state,
                object_ref(field(&snapshot, 18)?)?,
                optional_field(&snapshot, 20).map(object_ref).transpose()?,
                self.context,
            )?;
            validate_resolution_operation_counts(
                &conflicts.summary.records,
                metadata_value(
                    &self
                        .context
                        .lookup
                        .resolve_expected(change_reference, ObjectKind::ChangeSet)?,
                )?,
                self.context.lookup,
            )?;
            let provenance = optional_field(&snapshot, 27)
                .map(|values| {
                    array(values)?
                        .iter()
                        .map(object_ref)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            validate_provenance_graph(&provenance, self.context.lookup, &[reference])?;
            if !self.completed.contains(&reference) {
                self.index_memory.grow_by(derived_value_cost(34)?)?;
                self.completed.insert(reference);
            }
            if self
                .plan
                .remaining_uses
                .get(&reference)
                .copied()
                .unwrap_or(0)
                > 0
            {
                self.index_memory.grow_by(derived_value_cost(64)?)?;
                self.cache.insert(
                    reference,
                    SnapshotReplay {
                        state: replayed,
                        conflicts: conflicts.summary.records.len(),
                    },
                );
            }
        }
        Ok(())
    }

    fn consume(&mut self, reference: ObjectRef) -> Result<SnapshotReplay<'a>> {
        let conflicts = self
            .cache
            .get(&reference)
            .map(|replay| replay.conflicts)
            .ok_or_else(|| Error::new(ErrorCode::SnapshotRootInvalid))?;
        Ok(SnapshotReplay {
            state: self.consume_state(reference)?,
            conflicts,
        })
    }
}

pub fn validate_repository_candidate(
    candidate: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<RepositoryValidationSummary> {
    context.lookup.require_repository_semantics()?;
    if !context.verify_content {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight));
    }
    context
        .lookup
        .with_operation(|| validate_repository_candidate_operation(candidate, context))
}

fn validate_repository_candidate_operation(
    candidate: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<RepositoryValidationSummary> {
    let context = complete_lifetime_context(context);
    // Candidate validation is the whole-supplied boundary. Rank every supplied
    // L1/L2 defect, then the complete candidate/outbound closure, before any
    // registry or repository semantics.
    context.lookup.preflight_all_l1_l2()?;
    preflight_candidate_closure(candidate, &context)?;
    context.lookup.finish_all_registry()?;
    let mut workspace = SnapshotReplayWorkspace::new(&[candidate], &context)?;
    workspace.ensure(candidate, Some(candidate))?;
    let replayed = workspace.consume(candidate)?;
    Ok(RepositoryValidationSummary {
        highest_layer: 3,
        entries: replayed.state.state.entries.len(),
        groups: replayed.state.state.groups.len(),
        conflicts: replayed.conflicts,
    })
}

fn preflight_candidate_closure(
    candidate: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<()> {
    let mut memory = OwnedDerivedMemory::empty(context.lookup);
    let mut reached = BTreeSet::new();
    let mut stack = vec![candidate];
    let mut lookup_error = None;
    memory.grow_by(derived_value_cost(35)?)?;
    while let Some(reference) = stack.pop() {
        context.lookup.checkpoint()?;
        if reached.contains(&reference) {
            continue;
        }
        memory.grow_by(derived_value_cost(34)?)?;
        reached.insert(reference);
        let Some(object) =
            collect_lookup_result(&mut lookup_error, context.lookup.edge_any(reference))?
        else {
            continue;
        };
        if let Some(value) = object.value.as_ref() {
            visit_schema_object_references(
                reference.kind,
                value,
                &context.lookup.registry,
                context.lookup.mode.operation(),
                &mut |outbound| {
                    context.lookup.checkpoint()?;
                    if !reached.contains(&outbound) {
                        memory.grow_by(derived_value_cost(35)?)?;
                        stack.push(outbound);
                    }
                    Ok(())
                },
            )?;
        }
    }
    finish_lookup_selection(lookup_error)
}

pub fn validate_shelf_revision(
    reference: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<RepositoryValidationSummary> {
    context.lookup.require_repository_semantics()?;
    if !context.verify_content {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight));
    }
    context
        .lookup
        .with_operation(|| validate_shelf_revision_operation(reference, context))
}

fn validate_shelf_revision_operation(
    reference: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<RepositoryValidationSummary> {
    let context = complete_lifetime_context(context);
    // Shelf validation is an exact reached-set boundary: discover the complete
    // previous-chain and every consumed replay/content dependency first, then
    // finish registry semantics before chain/replay repository decisions.
    preflight_candidate_closure(reference, &context)?;
    context.lookup.finish_registry_phase()?;
    expect_ref_kind(reference, ObjectKind::ShelfRevision)?;
    let mut chain = validate_shelf_chain(reference, &context)?;
    chain.memory.grow_by(derived_value_cost(
        chain.references.len().saturating_mul(34),
    )?)?;
    let base_roots = chain
        .references
        .iter()
        .map(|shelf_reference| {
            context.lookup.checkpoint()?;
            let shelf = context
                .lookup
                .resolve_expected(*shelf_reference, ObjectKind::ShelfRevision)?;
            object_ref(field(metadata_value(&shelf)?, 20)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut snapshot_workspace = SnapshotReplayWorkspace::new(&base_roots, &context)?;
    let mut result = None;
    for (shelf_reference, base_reference) in chain
        .references
        .iter()
        .copied()
        .zip(base_roots.iter().copied())
    {
        context.lookup.checkpoint()?;
        let shelf_object = context
            .lookup
            .resolve_expected(shelf_reference, ObjectKind::ShelfRevision)?;
        let shelf = metadata_value(&shelf_object)?;
        snapshot_workspace.ensure(base_reference, None)?;
        let base = snapshot_workspace.consume(base_reference)?.state;
        let conflict_reference = optional_field(&shelf, 24).map(object_ref).transpose()?;
        let conflicts = validate_conflict_set_owned(
            conflict_reference,
            context.lookup,
            context.descriptor,
            false,
        )?;
        let conflict_object = conflict_reference
            .map(|conflict_reference| {
                context
                    .lookup
                    .resolve_expected(conflict_reference, ObjectKind::ConflictSet)
                    .and_then(|object| {
                        object
                            .value
                            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
                    })
            })
            .transpose()?;
        let change_reference = object_ref(field(&shelf, 21)?)?;
        let change_object = context
            .lookup
            .resolve_expected(change_reference, ObjectKind::ChangeSet)?;
        if optional_field(metadata_value(&change_object)?, 17)
            .map(object_ref)
            .transpose()?
            != Some(base_reference)
        {
            return Err(Error::new(ErrorCode::ChangeSetBaseMismatch));
        }
        let replayed = replay_reserved_change_set(
            base,
            change_reference,
            &context,
            conflict_object.as_deref(),
            shelf_reference != reference,
        )?;
        compare_state_to_roots(
            &replayed.state,
            object_ref(field(&shelf, 22)?)?,
            optional_field(&shelf, 23).map(object_ref).transpose()?,
            &context,
        )?;
        validate_resolution_operation_counts(
            &conflicts.summary.records,
            metadata_value(&change_object)?,
            context.lookup,
        )?;
        let provenance = optional_field(&shelf, 29)
            .map(|values| {
                array(values)?
                    .iter()
                    .map(object_ref)
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        validate_provenance_graph(&provenance, context.lookup, &[shelf_reference])?;
        result = Some(RepositoryValidationSummary {
            highest_layer: 3,
            entries: replayed.state.entries.len(),
            groups: replayed.state.groups.len(),
            conflicts: conflicts.summary.records.len(),
        });
    }
    result.ok_or_else(|| Error::new(ErrorCode::ShelfChainInvalid))
}

struct ReservedShelfChain {
    references: Vec<ObjectRef>,
    memory: OwnedDerivedMemory,
}

fn validate_shelf_chain(
    reference: ObjectRef,
    context: &RepositoryContext<'_>,
) -> Result<ReservedShelfChain> {
    let mut current = reference;
    let mut seen = BTreeSet::new();
    let mut chain = Vec::new();
    let mut memory = OwnedDerivedMemory::empty(context.lookup);
    loop {
        context.lookup.checkpoint()?;
        if seen.contains(&current) {
            return Err(Error::new(ErrorCode::ShelfChainInvalid));
        }
        memory.grow_by(derived_value_cost(68)?)?;
        seen.insert(current);
        chain.push(current);
        let shelf_object = context
            .lookup
            .resolve_expected(current, ObjectKind::ShelfRevision)?;
        let shelf = metadata_value(&shelf_object)?;
        if object_ref(field(&shelf, 16)?)? != context.descriptor {
            return Err(Error::new(ErrorCode::RepositoryDescriptorMismatch));
        }
        let revision = uint(field(&shelf, 18)?)?;
        let previous = optional_field(&shelf, 19).map(object_ref).transpose()?;
        if (revision == 1) != previous.is_none() {
            return Err(Error::new(ErrorCode::ShelfChainInvalid));
        }
        let Some(previous_ref) = previous else {
            chain.reverse();
            return Ok(ReservedShelfChain {
                references: chain,
                memory,
            });
        };
        let previous_object = context
            .lookup
            .edge(previous_ref, ObjectKind::ShelfRevision)?;
        let previous_value = metadata_value(&previous_object)?;
        let previous_revision = uint(field(&previous_value, 18)?)?;
        if object_ref(field(&previous_value, 16)?)? != context.descriptor
            || field(&previous_value, 17)? != field(&shelf, 17)?
            || previous_revision.checked_add(1) != Some(revision)
        {
            return Err(Error::new(ErrorCode::ShelfChainInvalid));
        }
        current = previous_ref;
    }
}

fn compare_state_to_roots(
    state: &RepositoryState,
    tree_reference: ObjectRef,
    group_reference: Option<ObjectRef>,
    context: &RepositoryContext<'_>,
) -> Result<()> {
    let expected_tree = expand_tree_owned(
        tree_reference,
        context.lookup,
        context.descriptor,
        context.verify_content,
        context.path_case_mode,
        context.path_profile_validator,
    )?;
    let expected_groups = groups_from_set(group_reference, context.lookup, context.descriptor)?;
    context.lookup.checkpoint()?;
    if state.entries != expected_tree.entries || state.groups != expected_groups.groups {
        return Err(Error::new(ErrorCode::ChangeSetResultMismatch));
    }
    context.lookup.checkpoint()?;
    validate_asset_groups_inner(
        &state.groups,
        &expected_tree.file_ids,
        context.group_profile_rules,
        context.unique_external_key_profiles,
        &context.lookup.registry,
        context.lookup.mode.operation(),
        Some(&context.lookup.guard),
        context.lookup.hard_limits(),
    )?;
    Ok(())
}

pub fn validate_asset_groups(
    groups: &BTreeMap<[u8; 16], AssetGroup>,
    file_ids: &BTreeMap<FileId, Vec<String>>,
    configured_rules: &[GroupProfileRule],
    unique_external_key_profiles: &[ProfileRef],
    registry: &Registry,
    mode: ValidationMode,
) -> Result<GroupValidationSummary> {
    validate_asset_groups_with_limits(
        groups,
        file_ids,
        configured_rules,
        unique_external_key_profiles,
        registry,
        mode,
        RepositoryLimits::default(),
    )
}

pub fn validate_asset_groups_with_hard_limits(
    groups: &BTreeMap<[u8; 16], AssetGroup>,
    file_ids: &BTreeMap<FileId, Vec<String>>,
    configured_rules: &[GroupProfileRule],
    unique_external_key_profiles: &[ProfileRef],
    registry: &Registry,
    mode: ValidationMode,
    hard_limits: HardLimitCeilings,
) -> Result<GroupValidationSummary> {
    validate_asset_groups_with_limits(
        groups,
        file_ids,
        configured_rules,
        unique_external_key_profiles,
        registry,
        mode,
        RepositoryLimits {
            hard_limits,
            ..RepositoryLimits::default()
        },
    )
}

pub fn validate_asset_groups_with_limits(
    groups: &BTreeMap<[u8; 16], AssetGroup>,
    file_ids: &BTreeMap<FileId, Vec<String>>,
    configured_rules: &[GroupProfileRule],
    unique_external_key_profiles: &[ProfileRef],
    registry: &Registry,
    mode: ValidationMode,
    limits: RepositoryLimits,
) -> Result<GroupValidationSummary> {
    registry.require_complete_authority()?;
    if mode == ValidationMode::Read {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight));
    }
    let guard = Rc::new(RefCell::new(ResourceGuard::new(limits)));
    guard.borrow().check_time()?;
    validate_asset_groups_inner(
        groups,
        file_ids,
        configured_rules,
        unique_external_key_profiles,
        registry,
        mode.operation(),
        Some(&guard),
        limits.hard_limits,
    )
}

fn validate_asset_groups_inner(
    groups: &BTreeMap<[u8; 16], AssetGroup>,
    file_ids: &BTreeMap<FileId, Vec<String>>,
    configured_rules: &[GroupProfileRule],
    unique_external_key_profiles: &[ProfileRef],
    registry: &Registry,
    operation: Operation,
    resource_guard: Option<&Rc<RefCell<ResourceGuard>>>,
    hard_limits: HardLimitCeilings,
) -> Result<GroupValidationSummary> {
    enforce_hard_limit_context(
        "asset-groups",
        u64::try_from(groups.len()).unwrap_or(u64::MAX),
        hard_limits.maximum("asset-groups")?,
        ErrorCode::LimitCount,
        2,
    )?;
    let mut memory = resource_guard.map(OwnedDerivedMemory::from_guard);
    if let Some(memory) = &mut memory {
        memory.grow_by(512)?;
    }
    let mut membership = BTreeMap::<FileId, [u8; 16]>::new();
    let mut external_owners = BTreeMap::<(ProfileRef, Vec<u8>), [u8; 16]>::new();
    let mut configured_unique = BTreeSet::new();
    for profile in unique_external_key_profiles {
        resource_checkpoint(resource_guard)?;
        if !configured_unique.contains(profile) {
            if let Some(memory) = &mut memory {
                memory.grow_by(profile_retained_cost(profile)?)?;
            }
            configured_unique.insert(profile.clone());
        }
    }
    // Whole-input phase order: every known family assignment is L2 and must be
    // established before any lifecycle decision from an earlier group. Then
    // rank lifecycle errors across the complete bounded input before entering
    // group membership/cardinality semantics.
    for group in groups.values() {
        resource_checkpoint(resource_guard)?;
        validate_group_profile_family(registry, &group.profile, &["group", "fixture-group"])?;
        for (_, role) in &group.members {
            resource_checkpoint(resource_guard)?;
            validate_group_profile_family(registry, role, &["group-role", "fixture-group-role"])?;
        }
        for (scheme, _) in &group.external_keys {
            resource_checkpoint(resource_guard)?;
            validate_group_profile_family(
                registry,
                scheme,
                &["external-key", "fixture-external-key"],
            )?;
        }
    }
    let mut lifecycle_error = None;
    for group in groups.values() {
        resource_checkpoint(resource_guard)?;
        for profile in std::iter::once(&group.profile)
            .chain(group.members.iter().map(|(_, role)| role))
            .chain(group.external_keys.iter().map(|(scheme, _)| scheme))
        {
            if let Err(error) =
                registry.check_assignment(RegistryAssignment::Profile(profile), operation)
            {
                observe_lookup_error(&mut lifecycle_error, error);
            }
        }
    }
    if let Some(error) = lifecycle_error {
        return Err(error);
    }
    let mut best_error = None;
    for group in groups.values() {
        enforce_hard_limit_context(
            "asset-group-members",
            u64::try_from(group.members.len()).unwrap_or(u64::MAX),
            hard_limits.maximum("asset-group-members")?,
            ErrorCode::LimitCount,
            2,
        )?;
        if let Some(guard) = resource_guard {
            guard.borrow().check_time()?;
        }
        let mut primary_present = false;
        for (file_id, _) in &group.members {
            if let Some(guard) = resource_guard {
                guard.borrow().check_time()?;
            }
            if *file_id == group.primary_file_id {
                primary_present = true;
            }
        }
        if !primary_present {
            observe_group_error(&mut best_error, Error::new(ErrorCode::GroupMemberInvalid))?;
        }
        let mut local = BTreeSet::new();
        let mut role_counts = BTreeMap::<ProfileRef, usize>::new();
        for (file_id, role) in &group.members {
            if let Some(guard) = resource_guard {
                guard.borrow().check_time()?;
            }
            let local_new = !local.contains(file_id);
            if local_new {
                if let Some(memory) = &mut memory {
                    memory.grow_by(derived_value_cost(16)?)?;
                }
                local.insert(*file_id);
            }
            if !local_new || !file_ids.contains_key(file_id) {
                observe_group_error(&mut best_error, Error::new(ErrorCode::GroupMemberInvalid))?;
            }
            if !membership.contains_key(file_id) {
                if let Some(memory) = &mut memory {
                    memory.grow_by(derived_value_cost(32)?)?;
                }
            }
            if membership.insert(*file_id, group.id).is_some() {
                observe_group_error(
                    &mut best_error,
                    Error::new(ErrorCode::GroupMembershipOverlap),
                )?;
            }
            if !role_counts.contains_key(role) {
                if let Some(memory) = &mut memory {
                    memory.grow_by(profile_retained_cost(role)?)?;
                }
            }
            *role_counts.entry(role.clone()).or_default() += 1;
        }
        let configured =
            find_configured_group_rule(configured_rules, &group.profile, resource_guard)?;
        if let Some(rule) = configured {
            if let Err(error) =
                validate_role_counts_guarded(&role_counts, &rule.roles, resource_guard)
            {
                observe_group_error(&mut best_error, error)?;
            }
        } else if let Err(error) =
            validate_builtin_role_counts_guarded(&group.profile, &role_counts, resource_guard)
        {
            observe_group_error(&mut best_error, error)?;
        }
        for (scheme, value) in &group.external_keys {
            if let Some(guard) = resource_guard {
                guard.borrow().check_time()?;
            }
            if let Some(memory) = &mut memory {
                let key_bytes = scheme
                    .namespace()
                    .len()
                    .checked_add(scheme.id().len())
                    .and_then(|bytes| bytes.checked_add(value.len()))
                    .and_then(|bytes| bytes.checked_add(48))
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
                memory.grow_by(derived_value_cost(key_bytes)?)?;
            }
            let configured_rule_unique = match configured {
                Some(rule) => {
                    configured_rule_has_unique_external_profile(rule, scheme, resource_guard)?
                }
                None => false,
            };
            if scheme.to_string() != "fixture-key.opengamevcs.test/synthetic-guid@2"
                && !configured_unique.contains(scheme)
                && !configured_rule_unique
            {
                continue;
            }
            let key = (scheme.clone(), value.clone());
            if external_owners
                .get(&key)
                .is_some_and(|owner| owner != &group.id)
            {
                observe_group_error(
                    &mut best_error,
                    Error::new(ErrorCode::GroupExternalKeyDuplicate),
                )?;
            }
            external_owners.insert(key, group.id);
        }
    }
    if let Some(error) = best_error {
        return Err(error);
    }
    Ok(GroupValidationSummary {
        groups: groups.len(),
        members: membership.len(),
    })
}

fn validate_group_profile_family(
    registry: &Registry,
    profile: &ProfileRef,
    families: &[&str],
) -> Result<()> {
    if let Some(entry) = registry.profile(profile) {
        if !families.contains(&entry.family.as_str()) {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid)
                .with_layer(2)
                .with_stage(ValidationStage::KnownSchema));
        }
    }
    Ok(())
}

fn observe_group_error(best: &mut Option<Error>, error: Error) -> Result<()> {
    let rank = |code| match code {
        ErrorCode::GroupMemberInvalid => Some(0),
        ErrorCode::GroupMembershipOverlap => Some(1),
        ErrorCode::GroupRequiredRoleMissing => Some(2),
        ErrorCode::GroupExternalKeyDuplicate => Some(3),
        _ => None,
    };
    let candidate = rank(error.code).ok_or(error.clone())?;
    if best
        .as_ref()
        .and_then(|current| rank(current.code))
        .is_none_or(|current| candidate < current)
    {
        *best = Some(error);
    }
    Ok(())
}

fn resource_checkpoint(resource_guard: Option<&Rc<RefCell<ResourceGuard>>>) -> Result<()> {
    if let Some(guard) = resource_guard {
        guard.borrow().check_time()?;
    }
    Ok(())
}

fn find_configured_group_rule<'a>(
    rules: &'a [GroupProfileRule],
    profile: &ProfileRef,
    resource_guard: Option<&Rc<RefCell<ResourceGuard>>>,
) -> Result<Option<&'a GroupProfileRule>> {
    for rule in rules {
        resource_checkpoint(resource_guard)?;
        if &rule.profile == profile {
            return Ok(Some(rule));
        }
    }
    Ok(None)
}

fn configured_rule_has_unique_external_profile(
    rule: &GroupProfileRule,
    profile: &ProfileRef,
    resource_guard: Option<&Rc<RefCell<ResourceGuard>>>,
) -> Result<bool> {
    for configured in &rule.unique_external_key_profiles {
        resource_checkpoint(resource_guard)?;
        if configured == profile {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
fn validate_role_counts(
    counts: &BTreeMap<ProfileRef, usize>,
    rules: &[GroupRoleCardinality],
) -> Result<()> {
    validate_role_counts_guarded(counts, rules, None)
}

fn validate_role_counts_guarded(
    counts: &BTreeMap<ProfileRef, usize>,
    rules: &[GroupRoleCardinality],
    resource_guard: Option<&Rc<RefCell<ResourceGuard>>>,
) -> Result<()> {
    for role in counts.keys() {
        resource_checkpoint(resource_guard)?;
        let mut allowed = false;
        for rule in rules {
            resource_checkpoint(resource_guard)?;
            if &rule.role == role {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(Error::new(ErrorCode::GroupRequiredRoleMissing));
        }
    }
    for rule in rules {
        resource_checkpoint(resource_guard)?;
        let count = counts.get(&rule.role).copied().unwrap_or_default();
        if count < rule.minimum || rule.maximum.is_some_and(|maximum| count > maximum) {
            return Err(Error::new(ErrorCode::GroupRequiredRoleMissing));
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_builtin_role_counts(
    profile: &ProfileRef,
    counts: &BTreeMap<ProfileRef, usize>,
) -> Result<()> {
    validate_builtin_role_counts_guarded(profile, counts, None)
}

fn validate_builtin_role_counts_guarded(
    profile: &ProfileRef,
    counts: &BTreeMap<ProfileRef, usize>,
    resource_guard: Option<&Rc<RefCell<ResourceGuard>>>,
) -> Result<()> {
    let rules: &[(&str, usize, Option<usize>)] = match profile.to_string().as_str() {
        "fixture-group.opengamevcs.test/package-sidecars@2" => &[
            ("fixture-role.opengamevcs.test/package@2", 1, Some(1)),
            ("fixture-role.opengamevcs.test/sidecar@2", 1, None),
        ],
        "fixture-group.opengamevcs.test/map-external-actors@2" => &[
            ("fixture-role.opengamevcs.test/map@2", 1, Some(1)),
            ("fixture-role.opengamevcs.test/external-actor@2", 1, None),
        ],
        "fixture-group.opengamevcs.test/asset-meta@2" => &[
            ("fixture-role.opengamevcs.test/primary@2", 1, Some(1)),
            ("fixture-role.opengamevcs.test/meta@2", 1, Some(1)),
        ],
        "fixture-group.opengamevcs.test/binary-version-family@2"
        | "fixture-group.opengamevcs.test/site@2"
        | "fixture-group.opengamevcs.test/team@2"
        | "fixture-group.opengamevcs.test/asset@2" => {
            &[("fixture-role.opengamevcs.test/member@2", 1, None)]
        }
        _ => &[],
    };
    if !rules.is_empty() {
        for profile in counts.keys() {
            resource_checkpoint(resource_guard)?;
            let profile = profile.to_string();
            let mut allowed = false;
            for (role, _, _) in rules {
                resource_checkpoint(resource_guard)?;
                if profile == *role {
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Err(Error::new(ErrorCode::GroupRequiredRoleMissing));
            }
        }
    }
    for (role, minimum, maximum) in rules {
        resource_checkpoint(resource_guard)?;
        let mut count = 0;
        for (profile, candidate) in counts {
            resource_checkpoint(resource_guard)?;
            if profile.to_string() == *role {
                count = *candidate;
                break;
            }
        }
        if count < *minimum || maximum.is_some_and(|maximum| count > maximum) {
            return Err(Error::new(ErrorCode::GroupRequiredRoleMissing));
        }
    }
    Ok(())
}

fn validate_resolution_operation_counts(
    records: &[Cbor],
    change_set: &Cbor,
    lookup: &RepositoryObjectLookup,
) -> Result<()> {
    let mut counts = BTreeMap::<[u8; 32], usize>::new();
    let mut memory = OwnedDerivedMemory::empty(lookup);
    for operation in array(field(change_set, 18)?)? {
        lookup.checkpoint()?;
        if uint(field(operation, 1)?)? == 11 {
            let id = digest32(field(operation, 9)?)?;
            if !counts.contains_key(&id) {
                memory.grow_by(derived_value_cost(40)?)?;
            }
            *counts.entry(id).or_default() += 1;
        }
    }
    for record in records {
        lookup.checkpoint()?;
        let id = digest32(field(record, 0)?)?;
        let resolved = uint(field(field(record, 6)?, 0)?)? == 1;
        if counts.get(&id).copied().unwrap_or_default() != usize::from(resolved) {
            return Err(Error::new(ErrorCode::ConflictResolutionMismatch));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbstractGraphSummary {
    pub highest_layer: u8,
    pub nodes: usize,
    pub edges: usize,
}

pub fn validate_abstract_reference_graph(
    graph: &JsonValue,
    limits: RepositoryLimits,
) -> Result<AbstractGraphSummary> {
    let mut guard = ResourceGuard::new(limits);
    // Configured-resource authority precedes all caller graph traversal.
    guard.check_time()?;
    let object = json_object_exact(
        graph,
        &[
            "schemaVersion",
            "assumedValidation",
            "graphKind",
            "roots",
            "nodes",
        ],
    )?;
    if json_string(object, "schemaVersion")?
        != "ogvcs.repository-format/abstract-reference-graph/v1"
        || json_string(object, "assumedValidation")?
            != "canonical-framing-schema-and-identity-prevalidated"
    {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let (node_type, edge_kind, cycle_code) = match json_string(object, "graphKind")? {
        "snapshot-parent" => ("snapshot", "parent", ErrorCode::SnapshotParentCycle),
        "provenance-input" => ("provenance", "provenance-input", ErrorCode::ProvenanceCycle),
        _ => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
    };
    let nodes_value = object
        .get("nodes")
        .and_then(JsonValue::as_array)
        .filter(|nodes| !nodes.is_empty())
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let mut nodes = BTreeMap::<String, Vec<String>>::new();
    let mut previous_node: Option<&str> = None;
    for node in nodes_value {
        guard.object(0, false)?;
        let node = json_object_exact(node, &["id", "type", "edges"])?;
        let id = json_string(node, "id")?;
        guard.reserve_derived(
            id.len()
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(256))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
        )?;
        guard.scratch(id.len())?;
        if !valid_abstract_node_id(id, &mut guard)?
            || previous_node
                .map(|previous| compare_abstract_node_id(previous, id, &mut guard))
                .transpose()?
                .is_some_and(|ordering| ordering != std::cmp::Ordering::Less)
            || json_string(node, "type")? != node_type
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let edges = node
            .get("edges")
            .and_then(JsonValue::as_array)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        // Grow only after the corresponding edge reservation below. A hostile
        // declared edge count must never trigger an eager capacity allocation.
        let mut targets = Vec::new();
        let mut previous_edge: Option<&str> = None;
        for edge in edges {
            // Every supplied edge is part of the untrusted input budget even
            // when its node is unreachable from the selected roots.
            guard.edge()?;
            let edge = json_object_exact(edge, &["kind", "target"])?;
            let kind = json_string(edge, "kind")?;
            let target = json_string(edge, "target")?;
            guard.reserve_derived(
                target
                    .len()
                    .checked_mul(4)
                    .and_then(|bytes| bytes.checked_add(128))
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
            )?;
            guard.scratch(target.len())?;
            if kind != edge_kind
                || !valid_abstract_node_id(target, &mut guard)?
                || previous_edge
                    .map(|previous| compare_abstract_node_id(previous, target, &mut guard))
                    .transpose()?
                    .is_some_and(|ordering| ordering != std::cmp::Ordering::Less)
            {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
            previous_edge = Some(target);
            targets.push(target.to_owned());
        }
        if nodes.insert(id.to_owned(), targets).is_some() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        previous_node = Some(id);
    }
    let roots = object
        .get("roots")
        .and_then(JsonValue::as_array)
        .filter(|roots| !roots.is_empty())
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    // Root storage is likewise allocated only after each root is charged.
    let mut root_ids = Vec::new();
    let mut previous_root: Option<&str> = None;
    for root in roots {
        let root = root
            .as_str()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        guard.reserve_derived(
            root.len()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(64))
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?,
        )?;
        if !valid_abstract_node_id(root, &mut guard)?
            || !nodes.contains_key(root)
            || previous_root
                .map(|previous| compare_abstract_node_id(previous, root, &mut guard))
                .transpose()?
                .is_some_and(|ordering| ordering != std::cmp::Ordering::Less)
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        previous_root = Some(root);
        root_ids.push(root.to_owned());
    }
    for targets in nodes.values() {
        for target in targets {
            guard.check_time()?;
            if !nodes.contains_key(target) {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
        }
    }
    let mut colors = BTreeMap::<String, u8>::new();
    let mut visited = BTreeSet::new();
    for root in &root_ids {
        guard.reserve_derived(derived_value_cost(root.len())?)?;
    }
    let mut stack = root_ids
        .iter()
        .rev()
        .map(|root| (root.clone(), false))
        .collect::<Vec<_>>();
    while let Some((id, exiting)) = stack.pop() {
        guard.release_derived(derived_value_cost(id.len())?);
        guard.check_time()?;
        if exiting {
            colors.insert(id.clone(), 2);
            if !visited.contains(&id) {
                guard.reserve_derived(derived_value_cost(id.len())?)?;
            }
            visited.insert(id);
            continue;
        }
        match colors.get(&id).copied() {
            Some(1) => return Err(Error::new(cycle_code)),
            Some(2) => continue,
            _ => {}
        }
        guard.reserve_derived(derived_value_cost(id.len())?)?;
        colors.insert(id.clone(), 1);
        let targets = nodes
            .get(&id)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        guard.reserve_derived(derived_value_cost(id.len())?)?;
        stack.push((id, true));
        for target in targets.iter().rev() {
            guard.check_time()?;
            guard.reserve_derived(derived_value_cost(target.len())?)?;
            stack.push((target.clone(), false));
        }
    }
    Ok(AbstractGraphSummary {
        highest_layer: 3,
        nodes: visited.len(),
        edges: guard.summary.edges,
    })
}

fn json_object_exact<'a>(
    value: &'a JsonValue,
    keys: &[&str],
) -> Result<&'a JsonMap<String, JsonValue>> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    Ok(object)
}

fn json_string<'a>(object: &'a JsonMap<String, JsonValue>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn valid_abstract_node_id(value: &str, guard: &mut ResourceGuard) -> Result<bool> {
    if value.is_empty() {
        return Ok(false);
    }
    let mut previous_hyphen = false;
    for (index, byte) in value.bytes().enumerate() {
        if index % 1_024 == 0 {
            guard.check_time()?;
        }
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => previous_hyphen = false,
            b'-' if index > 0 && !previous_hyphen => previous_hyphen = true,
            _ => return Ok(false),
        }
    }
    Ok(!previous_hyphen)
}

fn compare_abstract_node_id(
    left: &str,
    right: &str,
    guard: &mut ResourceGuard,
) -> Result<std::cmp::Ordering> {
    for (index, (left, right)) in left.bytes().zip(right.bytes()).enumerate() {
        if index % 1_024 == 0 {
            guard.check_time()?;
        }
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    Ok(left.len().cmp(&right.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_reference(kind: ObjectKind, byte: u8) -> ObjectRef {
        ObjectRef {
            kind,
            digest: [byte; 32],
        }
    }

    fn allocation(descriptor: ObjectRef, file_id: FileId, sequence: u64) -> AllocationEvidence {
        AllocationEvidence {
            sequence,
            operation_code: 1,
            after: EntryState {
                path: vec![format!("{sequence}.bin")],
                kind: 2,
                file_id,
                mode: 2,
                target: None,
                logical_size: 0,
                content_policy: ProfileRef::new("content-policy.test", "allow", 1).unwrap(),
                raw: Cbor::Map(vec![]),
            },
            operation: Cbor::Map(vec![(
                Cbor::UInt(5),
                Cbor::Map(vec![
                    (Cbor::UInt(0), descriptor.to_cbor()),
                    (Cbor::UInt(1), Cbor::UInt(1)),
                ]),
            )]),
        }
    }

    #[test]
    fn working_lifetime_additions_are_file_id_keyed_and_unique() {
        let descriptor = test_reference(ObjectKind::RepositoryDescriptor, 1);
        let change_set = test_reference(ObjectKind::ChangeSet, 2);
        let lookup = RepositoryObjectLookup::new(
            [],
            Registry::bundled(),
            ValidationMode::Conformance,
            RepositoryLimits::default(),
        )
        .unwrap();
        let first = FileId::new([0x11; 16]).unwrap();
        let second = FileId::new([0x22; 16]).unwrap();
        let allocations = vec![
            allocation(descriptor, second, 0),
            allocation(descriptor, first, 1),
        ];
        let working = vec![
            LifetimeRecord {
                file_id: first,
                origin: LifetimeOrigin::NativeCreate,
                first_change_set: change_set,
                first_operation: 1,
                import_mapping_key: None,
            },
            LifetimeRecord {
                file_id: second,
                origin: LifetimeOrigin::NativeCreate,
                first_change_set: change_set,
                first_operation: 0,
                import_mapping_key: None,
            },
        ];
        let mut context = RepositoryContext::new(
            &lookup,
            descriptor,
            test_reference(ObjectKind::Snapshot, 3),
            PathCaseMode::CaseSensitive,
        );
        context.working_lifetime_additions = &working;
        validate_lifetime_and_imports(&context, change_set, &allocations, None).unwrap();

        let duplicate = vec![working[0].clone(), working[0].clone()];
        context.working_lifetime_additions = &duplicate;
        assert_eq!(
            validate_lifetime_and_imports(&context, change_set, &allocations, None)
                .unwrap_err()
                .code,
            ErrorCode::FileIdLifetimeEvidenceInvalid
        );
    }

    #[test]
    fn already_consumed_native_allocation_outranks_foreign_proof() {
        let descriptor = test_reference(ObjectKind::RepositoryDescriptor, 1);
        let foreign_descriptor = test_reference(ObjectKind::RepositoryDescriptor, 9);
        let change_set = test_reference(ObjectKind::ChangeSet, 2);
        let file_id = FileId::new([0x55; 16]).unwrap();
        let lookup = RepositoryObjectLookup::new(
            [],
            Registry::bundled(),
            ValidationMode::Conformance,
            RepositoryLimits::default(),
        )
        .unwrap();
        let prior = [LifetimeRecord {
            file_id,
            origin: LifetimeOrigin::NativeCreate,
            first_change_set: test_reference(ObjectKind::ChangeSet, 8),
            first_operation: 0,
            import_mapping_key: None,
        }];
        let mut context = RepositoryContext::new(
            &lookup,
            descriptor,
            test_reference(ObjectKind::Snapshot, 3),
            PathCaseMode::CaseSensitive,
        );
        context.lifetime_records = &prior;
        let error = validate_lifetime_and_imports(
            &context,
            change_set,
            &[allocation(foreign_descriptor, file_id, 0)],
            None,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::FileIdAlreadyConsumed);
    }

    #[test]
    fn declared_transition_invalid_outranks_missing_source_state() {
        let descriptor = test_reference(ObjectKind::RepositoryDescriptor, 1);
        let file_id = FileId::new([0x61; 16]).unwrap();
        let entry = |name: &str, target_byte: u8| {
            Cbor::Map(vec![
                (
                    Cbor::UInt(0),
                    Cbor::Array(vec![Cbor::Text(name.to_owned())]),
                ),
                (Cbor::UInt(1), Cbor::UInt(2)),
                (Cbor::UInt(2), file_id.to_cbor()),
                (Cbor::UInt(3), Cbor::UInt(2)),
                (
                    Cbor::UInt(4),
                    test_reference(ObjectKind::ContentManifest, target_byte).to_cbor(),
                ),
                (Cbor::UInt(5), Cbor::UInt(0)),
                (
                    Cbor::UInt(6),
                    ProfileRef::new("content-policy.test", "opaque", 1)
                        .unwrap()
                        .to_cbor(),
                ),
            ])
        };
        let change = Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(4)),
            (Cbor::UInt(2), Cbor::Array(Vec::new())),
            (Cbor::UInt(16), descriptor.to_cbor()),
            (
                Cbor::UInt(18),
                Cbor::Array(vec![Cbor::Map(vec![
                    (Cbor::UInt(0), Cbor::UInt(0)),
                    (Cbor::UInt(1), Cbor::UInt(2)),
                    (Cbor::UInt(2), entry("missing.bin", 2)),
                    (Cbor::UInt(3), entry("different.bin", 3)),
                ])]),
            ),
        ]);
        let payload = encode_canonical(&change).unwrap();
        let change_reference = ObjectRef {
            kind: ObjectKind::ChangeSet,
            digest: object_id(ObjectKind::ChangeSet, &payload).unwrap(),
        };
        let lookup = RepositoryObjectLookup::new(
            [(change_reference, payload)],
            Registry::bundled(),
            ValidationMode::Conformance,
            RepositoryLimits::default(),
        )
        .unwrap();
        let context = RepositoryContext::new(
            &lookup,
            descriptor,
            test_reference(ObjectKind::Snapshot, 4),
            PathCaseMode::CaseSensitive,
        );
        assert_eq!(
            replay_change_set(
                change_reference,
                &RepositoryState::default(),
                &context,
                None
            )
            .unwrap_err()
            .code,
            ErrorCode::ChangeSetTransitionInvalid
        );
    }

    #[test]
    fn published_unresolved_conflict_outranks_invalid_subject_relationship() {
        let subject = Cbor::Array(vec![
            Cbor::UInt(1),
            Cbor::Array(vec![Cbor::Bytes(vec![0x31; 16])]),
            Cbor::Array(vec![Cbor::Array(vec![Cbor::Text("asset.bin".into())])]),
        ]);
        let preimage = Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), subject.clone()),
        ]);
        let declared = conflict_id(&encode_canonical(&preimage).unwrap());
        let record = Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::Bytes(declared.to_vec())),
            (Cbor::UInt(1), Cbor::UInt(1)),
            (Cbor::UInt(2), subject),
            (
                Cbor::UInt(6),
                Cbor::Map(vec![(Cbor::UInt(0), Cbor::UInt(0))]),
            ),
        ]);
        let error = validate_conflict_record(&record, true).unwrap_err();
        assert_eq!(
            (error.code, error.layer),
            (ErrorCode::ConflictUnresolvedPublished, 3)
        );
    }

    #[test]
    fn later_conflict_record_errors_are_ranked_across_the_complete_set() {
        let subject = Cbor::Array(vec![
            Cbor::UInt(1),
            Cbor::Array(vec![Cbor::Bytes(vec![0x41; 16])]),
            Cbor::Array(vec![Cbor::Array(vec![Cbor::Text("bad.bin".into())])]),
        ]);
        let record = |resolution: Cbor| {
            let mut record = Cbor::Map(vec![
                (Cbor::UInt(0), Cbor::Bytes(vec![0; 32])),
                (Cbor::UInt(1), Cbor::UInt(1)),
                (Cbor::UInt(2), subject.clone()),
                (Cbor::UInt(6), resolution),
            ]);
            let declared = conflict_id(&keyed_conflict_preimage(&record).unwrap());
            set_numeric_field(&mut record, 0, Cbor::Bytes(declared.to_vec())).unwrap();
            record
        };
        let subject_invalid = record(Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(4)),
        ]));
        let unresolved = record(Cbor::Map(vec![(Cbor::UInt(0), Cbor::UInt(0))]));
        let resolution_mismatch = record(Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(1)),
        ]));
        let lookup = RepositoryObjectLookup::new(
            [],
            Registry::bundled(),
            ValidationMode::Conformance,
            RepositoryLimits::default(),
        )
        .unwrap();
        assert_eq!(
            validate_conflict_records(&[subject_invalid.clone(), unresolved], true, &lookup)
                .unwrap_err()
                .code,
            ErrorCode::ConflictUnresolvedPublished
        );
        assert_eq!(
            validate_conflict_records(&[subject_invalid, resolution_mismatch], true, &lookup)
                .unwrap_err()
                .code,
            ErrorCode::ConflictResolutionMismatch
        );
    }

    #[test]
    fn fixture_group_role_sets_are_exhaustive_before_cardinality() {
        let package = ProfileRef::new("fixture-role.opengamevcs.test", "package", 2).unwrap();
        let sidecar = ProfileRef::new("fixture-role.opengamevcs.test", "sidecar", 2).unwrap();
        let foreign =
            ProfileRef::new("fixture-role.opengamevcs.test", "external-actor", 2).unwrap();
        let counts = BTreeMap::from([(package.clone(), 1), (sidecar.clone(), 1), (foreign, 1)]);
        let profile =
            ProfileRef::new("fixture-group.opengamevcs.test", "package-sidecars", 2).unwrap();
        assert_eq!(
            validate_builtin_role_counts(&profile, &counts)
                .unwrap_err()
                .code,
            ErrorCode::GroupRequiredRoleMissing
        );
        let rules = [
            GroupRoleCardinality {
                role: package,
                minimum: 1,
                maximum: Some(1),
            },
            GroupRoleCardinality {
                role: sidecar,
                minimum: 1,
                maximum: None,
            },
        ];
        assert_eq!(
            validate_role_counts(&counts, &rules).unwrap_err().code,
            ErrorCode::GroupRequiredRoleMissing
        );
    }

    #[test]
    fn later_missing_group_member_outranks_earlier_membership_overlap() {
        let file_a = FileId::new([0x11; 16]).unwrap();
        let file_b = FileId::new([0x22; 16]).unwrap();
        let group_profile = ProfileRef::new("group.test", "opaque", 1).unwrap();
        let role = ProfileRef::new("group-role.test", "member", 1).unwrap();
        let make_group = |id: u8, file_id| AssetGroup {
            id: [id; 16],
            profile: group_profile.clone(),
            primary_file_id: file_id,
            members: vec![(file_id, role.clone())],
            external_keys: vec![],
            raw: Cbor::Map(vec![]),
        };
        let groups = BTreeMap::from([
            ([1; 16], make_group(1, file_a)),
            ([2; 16], make_group(2, file_a)),
            ([3; 16], make_group(3, file_b)),
        ]);
        let file_ids = BTreeMap::from([(file_a, vec!["present.bin".to_owned()])]);
        assert_eq!(
            validate_asset_groups(
                &groups,
                &file_ids,
                &[],
                &[],
                &Registry::bundled(),
                ValidationMode::Conformance,
            )
            .unwrap_err()
            .code,
            ErrorCode::GroupMemberInvalid
        );
    }

    #[test]
    fn standalone_group_validation_requires_complete_authority_and_charges_indexes() {
        let file_id = FileId::new([0x11; 16]).unwrap();
        let group = AssetGroup {
            id: [1; 16],
            profile: ProfileRef::new("group.test", "opaque", 1).unwrap(),
            primary_file_id: file_id,
            members: vec![(
                file_id,
                ProfileRef::new("group-role.test", "member", 1).unwrap(),
            )],
            external_keys: vec![],
            raw: Cbor::Map(vec![]),
        };
        let groups = BTreeMap::from([([1; 16], group)]);
        let file_ids = BTreeMap::from([(file_id, vec!["present.bin".to_owned()])]);
        let partial = Registry::load([], []).unwrap();
        let error = validate_asset_groups(
            &groups,
            &file_ids,
            &[],
            &[],
            &partial,
            ValidationMode::Conformance,
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer, error.stage),
            (
                ErrorCode::SchemaFieldInvalid,
                1,
                ValidationStage::ConfiguredResourcePreflight,
            )
        );

        let error = validate_asset_groups_with_limits(
            &groups,
            &file_ids,
            &[],
            &[],
            &Registry::bundled(),
            ValidationMode::Conformance,
            RepositoryLimits {
                max_memory_bytes: 511,
                ..RepositoryLimits::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            (error.code, error.layer, error.stage),
            (
                ErrorCode::LimitMemory,
                1,
                ValidationStage::ConfiguredResourcePreflight,
            )
        );
    }
}
