use std::{cell::Cell, collections::BTreeSet, str::FromStr};

use crate::{
    conflict_id, encode_canonical, hard_limits::enforce_hard_limit_context, sha256,
    unicode_age::is_unicode_15, Cbor, Error, ErrorCode, HardLimitCeilings, Limits, ObjectKind,
    ObjectRef, ProfileRef, Registry, Result, TypedDigest, ValidationStage,
};
use unicode_normalization::is_nfc;

#[derive(Clone, Debug)]
pub struct FramingScan {
    pub numeric_kind: u16,
    pub required_features: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct MetadataObject {
    original: Vec<u8>,
    value: Cbor,
    decoded_retained_bytes: usize,
    scan: FramingScan,
    hard_limits: HardLimitCeilings,
}

impl MetadataObject {
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }
    pub fn value(&self) -> &Cbor {
        &self.value
    }
    pub(crate) fn decoded_retained_bytes(&self) -> usize {
        self.decoded_retained_bytes
    }
    pub(crate) fn total_retained_bytes(&self) -> Result<usize> {
        self.original
            .capacity()
            .checked_add(self.decoded_retained_bytes)
            .and_then(|bytes| {
                bytes.checked_add(
                    self.scan
                        .required_features
                        .capacity()
                        .saturating_mul(core::mem::size_of::<u32>()),
                )
            })
            .and_then(|bytes| bytes.checked_add(512))
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
    }
    pub(crate) fn into_value(self) -> Cbor {
        self.value
    }
    pub fn framing(&self) -> &FramingScan {
        &self.scan
    }
    /// Applies additional schema ceilings to an already successful framing
    /// scan. Existing scan ceilings can only be retained or reduced.
    pub fn constrained_by(mut self, hard_limits: HardLimitCeilings) -> Self {
        self.hard_limits = self.hard_limits.constrained_by(hard_limits);
        self
    }
    pub fn lossless_roundtrip(&self) -> Result<Vec<u8>> {
        encode_canonical(&self.value)
    }
}

pub fn scan_metadata(input: &[u8], configured: Limits) -> Result<MetadataObject> {
    scan_metadata_with_hard_limits(input, configured, HardLimitCeilings::HARD)
}

/// Performs the framing scan with caller ceilings capped by the frozen
/// format-v1 maxima. The selected ceilings are retained for the subsequent
/// known-schema validation of this object.
pub fn scan_metadata_with_hard_limits(
    input: &[u8],
    configured: Limits,
    hard_limits: HardLimitCeilings,
) -> Result<MetadataObject> {
    scan_metadata_inner(input, configured, hard_limits).map_err(|error| error.with_layer(1))
}

fn scan_metadata_inner(
    input: &[u8],
    configured: Limits,
    hard_limits: HardLimitCeilings,
) -> Result<MetadataObject> {
    framing_limit(
        hard_limits,
        "metadata-payload-bytes",
        input.len(),
        ErrorCode::LimitMetadataBytes,
    )?;
    let mut decode_limits = Limits::METADATA.constrained_by(configured);
    decode_limits.max_input_bytes = decode_limits
        .max_input_bytes
        .min(limit_usize(hard_limits, "metadata-payload-bytes")?);
    decode_limits.max_value_bytes = decode_limits.max_value_bytes.min(limit_usize(
        hard_limits,
        "generic-text-or-byte-value-bytes",
    )?);
    decode_limits.max_nesting = decode_limits
        .max_nesting
        .min(limit_usize(hard_limits, "cbor-nesting-depth")?);
    decode_limits.max_container_items = decode_limits
        .max_container_items
        .min(limit_usize(hard_limits, "manifest-chunks")?);
    let (value, decoded_retained_bytes) =
        crate::cbor::decode_canonical_measured(input, decode_limits)?;
    let fields = Fields::new(&value)?;
    if fields.u(0)? != 1 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let kind = fields.u(1)?;
    if kind == 0 || kind > u16::MAX as u64 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let features = array(fields.get(2)?)?;
    let mut required_features = Vec::with_capacity(features.len());
    for value in features {
        let feature = u(value)?;
        if feature > u32::MAX as u64 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        required_features.push(feature as u32);
    }
    if let Some(extension_value) = fields.opt(3) {
        let Cbor::Map(extensions) = extension_value else {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        };
        if extensions.is_empty() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        framing_limit(
            hard_limits,
            "extensions-per-object",
            extensions.len(),
            ErrorCode::LimitCount,
        )?;
        let mut aggregate = 0usize;
        for (_, value) in extensions {
            aggregate = aggregate
                .checked_add(encode_canonical(value)?.len())
                .ok_or_else(|| Error::new(ErrorCode::LimitExtensionBytes))?;
            framing_limit(
                hard_limits,
                "extension-aggregate-bytes-per-object",
                aggregate,
                ErrorCode::LimitExtensionBytes,
            )?;
        }
    }
    Ok(MetadataObject {
        original: input.to_vec(),
        value,
        decoded_retained_bytes,
        scan: FramingScan {
            numeric_kind: kind as u16,
            required_features,
        },
        hard_limits,
    })
}

pub fn validate_metadata_schema(object: &MetadataObject) -> Result<ObjectKind> {
    validate_metadata_schema_with_limits(object, usize::MAX)
}

/// Validates one already-scanned metadata object with a finite diagnostic
/// workspace. Error ranking retains one fixed candidate regardless of the
/// number of invalid fields, but that fixed workspace is admitted before the
/// caller-owned value is traversed.
pub fn validate_metadata_schema_with_limits(
    object: &MetadataObject,
    max_working_bytes: usize,
) -> Result<ObjectKind> {
    const DIAGNOSTIC_WORKING_BYTES: usize = 512;
    if max_working_bytes < DIAGNOSTIC_WORKING_BYTES {
        return Err(Error::new(ErrorCode::LimitMemory)
            .with_layer(1)
            .with_stage(ValidationStage::ConfiguredResourcePreflight));
    }
    with_deferred_unknown_fields(|| validate_metadata_schema_inner(object))
        .map_err(|error| error.with_layer(2))
}

thread_local! {
    // 0 is strict/default, 1 defers unknown fields, and 2 records that at
    // least one unknown field was found during the deferred pass.
    static UNKNOWN_FIELD_STATE: Cell<u8> = const { Cell::new(0) };
}

fn with_deferred_unknown_fields<T>(validate: impl FnOnce() -> Result<T>) -> Result<T> {
    UNKNOWN_FIELD_STATE.with(|state| {
        let previous = state.replace(1);
        let result = validate();
        let unknown = state.get() == 2;
        state.set(previous);
        if !unknown {
            return result;
        }
        match result {
            Err(error) if error.code == ErrorCode::SchemaFieldInvalid || error.layer < 2 => {
                Err(error)
            }
            _ => Err(Error::new(ErrorCode::SchemaFieldUnknown)),
        }
    })
}

fn validate_metadata_schema_inner(object: &MetadataObject) -> Result<ObjectKind> {
    let kind = ObjectKind::from_code(object.scan.numeric_kind as u64)?;
    let fields = Fields::new(&object.value)?;
    let limits = object.hard_limits;
    metadata_schema_preflight(kind, &fields, limits)?;
    match kind {
        ObjectKind::Chunk => return Err(Error::new(ErrorCode::ObjectKindUnsupported)),
        ObjectKind::ContentManifest => manifest(&fields, limits)?,
        ObjectKind::Tree => tree(&fields, limits)?,
        ObjectKind::ChangeSet => change_set(&fields, limits)?,
        ObjectKind::AssetGroupSet => group_set(&fields, limits)?,
        ObjectKind::RepositoryDescriptor => descriptor(&fields, limits)?,
        ObjectKind::Snapshot => snapshot(&fields, limits)?,
        ObjectKind::ShelfRevision => shelf(&fields, limits)?,
        ObjectKind::Provenance => provenance(&fields, limits)?,
        ObjectKind::Attestation => attestation(&fields, limits)?,
        ObjectKind::ConflictSet => conflict_set(&fields, limits)?,
    }
    Ok(kind)
}

pub fn validate_logical_record(input: &[u8], configured: Limits) -> Result<u16> {
    validate_logical_record_with_hard_limits(input, configured, HardLimitCeilings::HARD)
}

pub fn validate_logical_record_with_hard_limits(
    input: &[u8],
    configured: Limits,
    hard_limits: HardLimitCeilings,
) -> Result<u16> {
    let value = crate::decode_canonical(input, metadata_decode_limits(configured, hard_limits)?)?;
    with_deferred_unknown_fields(|| {
        let f = Fields::new(&value)?;
        if f.u(0)? != 1 {
            return invalid();
        }
        let ty = f.u(1)?;
        logical_record_schema_preflight(&f, ty, hard_limits)?;
        match ty {
            1 => {
                f.shape(&[0, 1, 16, 17], &[])?;
                object_ref(f.get(16)?, Some(6))?;
                object_ref(f.get(17)?, Some(7))?;
            }
            2 => {
                f.shape(&[0, 1, 16, 17, 18, 19, 20], &[])?;
                object_ref(f.get(16)?, Some(6))?;
                range(f.get(17)?, 1, 2)?;
                nonempty_text(f.get(18)?)?;
                object_ref(f.get(19)?, Some(7))?;
                u(f.get(20)?)?;
            }
            3 => {
                f.shape(&[0, 1, 16, 17, 18, 19], &[])?;
                object_ref(f.get(16)?, Some(6))?;
                id128(f.get(17)?)?;
                object_ref(f.get(18)?, Some(8))?;
                u(f.get(19)?)?;
            }
            4 => {
                f.shape(&[0, 1, 16, 17, 18, 19, 20], &[21])?;
                object_ref(f.get(16)?, Some(6))?;
                file_id(f.get(17)?)?;
                let origin = range(f.get(18)?, 1, 3)?;
                object_ref(f.get(19)?, Some(4))?;
                u(f.get(20)?)?;
                if (origin == 3) != f.opt(21).is_some() {
                    return invalid();
                }
                if let Some(v) = f.opt(21) {
                    digest(v)?;
                }
            }
            5 => {
                f.shape(&[0, 1, 16, 17, 18, 19, 20, 21], &[])?;
                object_ref(f.get(16)?, Some(6))?;
                profile_in(f.get(17)?, &["importer"])?;
                digest(f.get(18)?)?;
                digest(f.get(19)?)?;
                file_id(f.get(20)?)?;
                range(f.get(21)?, 1, 3)?;
            }
            6 => {
                f.shape(&[0, 1, 16, 17, 18, 19], &[20])?;
                object_ref(f.get(16)?, Some(6))?;
                id128(f.get(17)?)?;
                object_ref(f.get(18)?, Some(7))?;
                object_ref(f.get(19)?, Some(4))?;
                if let Some(v) = f.opt(20) {
                    object_ref(v, Some(11))?;
                }
            }
            7 => {
                f.shape(&[0, 1, 16, 17, 18, 19, 20], &[])?;
                object_ref(f.get(16)?, Some(6))?;
                let target = range(f.get(17)?, 1, 2)?;
                if target == 1 {
                    file_id(f.get(18)?)?;
                } else {
                    id128(f.get(18)?)?;
                }
                object_ref(f.get(19)?, Some(7))?;
                u(f.get(20)?)?;
            }
            8 => {
                f.shape(&[0, 1, 16, 17, 18], &[])?;
                object_ref(f.get(16)?, None)?;
                profile_in(f.get(17)?, &["annotation-payload"])?;
                bytes(f.get(18)?)?;
            }
            9 => {
                f.shape(&[0, 1, 16, 17, 18, 19, 20], &[])?;
                typed_digest(f.get(16)?)?;
                u(f.get(17)?)?;
                profile_in(f.get(18)?, &["fixture-event"])?;
                typed_digest(f.get(19)?)?;
                fixture_op(f.get(20)?)?;
            }
            _ => return Err(Error::new(ErrorCode::LogicalRecordTypeUnsupported)),
        }
        Ok(ty as u16)
    })
}

fn logical_record_schema_preflight(
    f: &Fields<'_>,
    ty: u64,
    _limits: HardLimitCeilings,
) -> Result<()> {
    match ty {
        1 => {
            f.shape(&[0, 1, 16, 17], &[])?;
            object_ref_schema_preflight(f.get(16)?)?;
            object_ref_schema_preflight(f.get(17)?)?;
        }
        2 => {
            f.shape(&[0, 1, 16, 17, 18, 19, 20], &[])?;
            object_ref_schema_preflight(f.get(16)?)?;
            generic_schema_check(range(f.get(17)?, 1, 2))?;
            generic_schema_check(nonempty_text(f.get(18)?))?;
            object_ref_schema_preflight(f.get(19)?)?;
            generic_schema_check(u(f.get(20)?))?;
        }
        3 => {
            f.shape(&[0, 1, 16, 17, 18, 19], &[])?;
            object_ref_schema_preflight(f.get(16)?)?;
            generic_schema_check(id128(f.get(17)?))?;
            object_ref_schema_preflight(f.get(18)?)?;
            generic_schema_check(u(f.get(19)?))?;
        }
        4 => {
            f.shape(&[0, 1, 16, 17, 18, 19, 20], &[21])?;
            object_ref_schema_preflight(f.get(16)?)?;
            generic_schema_check(raw_id128(f.get(17)?))?;
            generic_schema_check(range(f.get(18)?, 1, 3))?;
            object_ref_schema_preflight(f.get(19)?)?;
            generic_schema_check(u(f.get(20)?))?;
            if let Some(value) = f.opt(21) {
                generic_schema_check(digest(value))?;
            }
        }
        5 => {
            f.shape(&[0, 1, 16, 17, 18, 19, 20, 21], &[])?;
            object_ref_schema_preflight(f.get(16)?)?;
            profile_schema_preflight(f.get(17)?)?;
            generic_schema_check(digest(f.get(18)?))?;
            generic_schema_check(digest(f.get(19)?))?;
            generic_schema_check(raw_id128(f.get(20)?))?;
            generic_schema_check(range(f.get(21)?, 1, 3))?;
        }
        6 => {
            f.shape(&[0, 1, 16, 17, 18, 19], &[20])?;
            object_ref_schema_preflight(f.get(16)?)?;
            generic_schema_check(id128(f.get(17)?))?;
            object_ref_schema_preflight(f.get(18)?)?;
            object_ref_schema_preflight(f.get(19)?)?;
            if let Some(value) = f.opt(20) {
                object_ref_schema_preflight(value)?;
            }
        }
        7 => {
            f.shape(&[0, 1, 16, 17, 18, 19, 20], &[])?;
            object_ref_schema_preflight(f.get(16)?)?;
            generic_schema_check(range(f.get(17)?, 1, 2))?;
            generic_schema_check(raw_id128(f.get(18)?))?;
            object_ref_schema_preflight(f.get(19)?)?;
            generic_schema_check(u(f.get(20)?))?;
        }
        8 => {
            f.shape(&[0, 1, 16, 17, 18], &[])?;
            object_ref_schema_preflight(f.get(16)?)?;
            profile_schema_preflight(f.get(17)?)?;
            generic_schema_check(bytes(f.get(18)?))?;
        }
        9 => {
            f.shape(&[0, 1, 16, 17, 18, 19, 20], &[])?;
            typed_digest_schema_preflight(f.get(16)?)?;
            generic_schema_check(u(f.get(17)?))?;
            profile_schema_preflight(f.get(18)?)?;
            typed_digest_schema_preflight(f.get(19)?)?;
            generic_schema_check(fixture_op(f.get(20)?))?;
        }
        _ => return Err(Error::new(ErrorCode::LogicalRecordTypeUnsupported)),
    }
    Ok(())
}

pub fn validate_conflict_preimage(input: &[u8], configured: Limits) -> Result<()> {
    validate_conflict_preimage_with_hard_limits(input, configured, HardLimitCeilings::HARD)
}

pub fn validate_conflict_preimage_with_hard_limits(
    input: &[u8],
    configured: Limits,
    hard_limits: HardLimitCeilings,
) -> Result<()> {
    let value = crate::decode_canonical(input, metadata_decode_limits(configured, hard_limits)?)?;
    with_deferred_unknown_fields(|| {
        let f = Fields::new(&value)?;
        conflict_preimage_schema_preflight(&f, hard_limits)?;
        f.shape(&[0, 1], &[2, 3, 4])?;
        conflict_kind(f.get(0)?)?;
        conflict_subject(f.get(1)?, hard_limits)?;
        for key in 2..=4 {
            if let Some(value) = f.opt(key) {
                conflict_side(value, hard_limits)?;
            }
        }
        Ok(())
    })
}

fn limit_usize(limits: HardLimitCeilings, name: &'static str) -> Result<usize> {
    usize::try_from(limits.maximum(name)?)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(2))
}

fn metadata_decode_limits(configured: Limits, hard_limits: HardLimitCeilings) -> Result<Limits> {
    let mut result = Limits::METADATA.constrained_by(configured);
    result.max_input_bytes = result
        .max_input_bytes
        .min(limit_usize(hard_limits, "metadata-payload-bytes")?);
    result.max_value_bytes = result.max_value_bytes.min(limit_usize(
        hard_limits,
        "generic-text-or-byte-value-bytes",
    )?);
    result.max_nesting = result
        .max_nesting
        .min(limit_usize(hard_limits, "cbor-nesting-depth")?);
    result.max_container_items = result
        .max_container_items
        .min(limit_usize(hard_limits, "manifest-chunks")?);
    Ok(result)
}

fn contextual_limit(
    limits: HardLimitCeilings,
    name: &'static str,
    value: usize,
    code: ErrorCode,
    layer: u8,
) -> Result<()> {
    let value = u64::try_from(value).map_err(|_| Error::new(code).with_layer(layer))?;
    enforce_hard_limit_context(name, value, limits.maximum(name)?, code, layer).map(|_| ())
}

fn contextual_limit_u64(
    limits: HardLimitCeilings,
    name: &'static str,
    value: u64,
    code: ErrorCode,
    layer: u8,
) -> Result<()> {
    enforce_hard_limit_context(name, value, limits.maximum(name)?, code, layer).map(|_| ())
}

fn framing_limit(
    limits: HardLimitCeilings,
    name: &'static str,
    value: usize,
    code: ErrorCode,
) -> Result<()> {
    contextual_limit(limits, name, value, code, 1)
}

fn schema_limit(
    limits: HardLimitCeilings,
    name: &'static str,
    value: usize,
    code: ErrorCode,
) -> Result<()> {
    contextual_limit(limits, name, value, code, 2)
}

fn schema_limit_u64(
    limits: HardLimitCeilings,
    name: &'static str,
    value: u64,
    code: ErrorCode,
) -> Result<()> {
    contextual_limit_u64(limits, name, value, code, 2)
}

fn common(
    f: &Fields<'_>,
    kind: u64,
    required: &[u64],
    optional: &[u64],
    limits: HardLimitCeilings,
) -> Result<()> {
    let mut req = vec![0, 1, 2];
    req.extend_from_slice(required);
    let mut opt = vec![3];
    opt.extend_from_slice(optional);
    f.shape(&req, &opt)?;
    if f.u(0)? != 1 || f.u(1)? != kind {
        return invalid();
    }
    let features = array(f.get(2)?)?;
    let mut previous = None;
    for value in features {
        let feature = u(value)?;
        if feature > u32::MAX as u64 || previous.is_some_and(|prior| prior >= feature) {
            return invalid();
        }
        previous = Some(feature);
    }
    if let Some(extensions) = f.opt(3) {
        let entries = map(extensions)?;
        if entries.is_empty() {
            return invalid();
        }
        schema_limit(
            limits,
            "extensions-per-object",
            entries.len(),
            ErrorCode::LimitCount,
        )?;
        let mut aggregate = 0usize;
        for (key, value) in entries {
            let key = text(key).map_err(|_| Error::new(ErrorCode::ExtensionKeyInvalid))?;
            ProfileRef::from_str(key).map_err(|_| Error::new(ErrorCode::ExtensionKeyInvalid))?;
            validate_extension_value(value)?;
            aggregate = aggregate
                .checked_add(encode_canonical(value)?.len())
                .ok_or_else(|| Error::new(ErrorCode::LimitExtensionBytes))?;
            schema_limit(
                limits,
                "extension-aggregate-bytes-per-object",
                aggregate,
                ErrorCode::LimitExtensionBytes,
            )?;
        }
    }
    Ok(())
}

fn manifest(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 2, &[16, 17, 18, 19], &[], limits)?;
    let logical = logical_length(f.get(16)?, limits)?;
    typed_digest(f.get(17)?)?;
    profile_in(f.get(18)?, &["chunking"])?;
    let chunks = array(f.get(19)?)?;
    schema_limit(
        limits,
        "manifest-chunks",
        chunks.len(),
        ErrorCode::LimitCount,
    )?;
    let mut sum = 0u64;
    for chunk in chunks {
        let c = Fields::new(chunk)?;
        c.shape(&[0, 1], &[])?;
        object_ref(c.get(0)?, Some(1))?;
        let n = u(c.get(1)?)?;
        if n == 0 {
            return Err(Error::new(ErrorCode::ManifestChunkLengthInvalid));
        }
        schema_limit_u64(
            limits,
            "chunk-payload-bytes",
            n,
            ErrorCode::ManifestChunkLengthInvalid,
        )?;
        sum = sum
            .checked_add(n)
            .ok_or_else(|| Error::new(ErrorCode::LimitLogicalBytes))?;
        schema_limit_u64(
            limits,
            "logical-file-bytes",
            sum,
            ErrorCode::LimitLogicalBytes,
        )?;
    }
    if sum != logical {
        return Err(Error::new(ErrorCode::ManifestLengthMismatch));
    }
    Ok(())
}

fn tree(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    let mut best = None;
    observe_schema_result(&mut best, &common(f, 3, &[16, 17], &[], limits));
    let descriptor = f.get(16).and_then(|value| object_ref(value, Some(6)));
    observe_schema_result(&mut best, &descriptor);
    let entries = f.get(17).and_then(array);
    observe_schema_result(&mut best, &entries);
    let Ok(entries) = entries else {
        return Err(best.expect("entry array failure was observed"));
    };
    schema_limit(limits, "tree-entries", entries.len(), ErrorCode::LimitCount)?;
    let mut previous: Option<&[u8]> = None;
    for value in entries {
        let e = Fields::new(value);
        observe_schema_result(&mut best, &e);
        let Ok(e) = e else {
            continue;
        };
        observe_schema_result(&mut best, &e.shape(&[0, 1, 2, 3, 4, 5, 6], &[]));
        let name = e.get(0).and_then(|value| basename(value, limits));
        observe_schema_result(&mut best, &name);
        if let Ok(name) = name {
            if previous.is_some_and(|p| p >= name.as_bytes()) {
                observe_schema_error(&mut best, Error::new(ErrorCode::TreeEntryOrderInvalid));
            }
            previous = Some(name.as_bytes());
        }
        let kind = e.get(1).and_then(|value| range(value, 1, 4));
        observe_schema_result(&mut best, &kind);
        let id = e.get(2).and_then(file_id);
        observe_schema_result(&mut best, &id);
        let mode = e.get(3).and_then(|value| range(value, 1, 4));
        observe_schema_result(&mut best, &mode);
        let expected_target = kind
            .as_ref()
            .ok()
            .map(|kind| if *kind == 1 { 3 } else { 2 });
        let target = e
            .get(4)
            .and_then(|value| object_ref(value, expected_target));
        observe_schema_result(&mut best, &target);
        let size = e.get(5).and_then(|value| logical_length(value, limits));
        observe_schema_result(&mut best, &size);
        let content_profile = e.get(6).and_then(profile);
        observe_schema_result(&mut best, &content_profile);
        if let (Ok(kind), Ok(mode), Ok(size)) = (kind, mode, size) {
            if kind != mode || kind == 1 && size != 0 {
                observe_schema_error(&mut best, Error::new(ErrorCode::TreeEntryTargetInvalid));
            }
        }
    }
    best.map_or(Ok(()), Err)
}

fn observe_schema_result<T>(best: &mut Option<Error>, result: &Result<T>) {
    if let Err(error) = result {
        observe_schema_error(best, error.clone());
    }
}

fn observe_schema_error(best: &mut Option<Error>, error: Error) {
    if best
        .as_ref()
        .is_none_or(|current| (error.code as u8) < (current.code as u8))
    {
        *best = Some(error);
    }
}

fn change_set(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 4, &[16, 18], &[17], limits)?;
    object_ref(f.get(16)?, Some(6))?;
    if let Some(v) = f.opt(17) {
        object_ref(v, Some(7))?;
    }
    let ops = array(f.get(18)?)?;
    schema_limit(
        limits,
        "change-set-operations",
        ops.len(),
        ErrorCode::LimitCount,
    )?;
    for (seq, v) in ops.iter().enumerate() {
        operation(v, seq as u64, limits)?;
    }
    Ok(())
}
fn group_set(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 5, &[16, 17], &[], limits)?;
    object_ref(f.get(16)?, Some(6))?;
    let groups = array(f.get(17)?)?;
    schema_limit(limits, "asset-groups", groups.len(), ErrorCode::LimitCount)?;
    let mut prev = None;
    for g in groups {
        let id = asset_group(g, limits)?;
        if prev.is_some_and(|p: [u8; 16]| p >= id) {
            return invalid();
        }
        prev = Some(id);
    }
    Ok(())
}
fn descriptor(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 6, &[16, 17, 18, 19], &[20], limits)?;
    id128(f.get(16)?)?;
    profile_in(f.get(17)?, &["path"])?;
    sorted_profiles(f.get(18)?, true, &["content-policy", "fixture-content-policy"])?;
    sorted_profiles(f.get(19)?, false, &["group", "fixture-group"])?;
    if let Some(v) = f.opt(20) {
        let a = array(v)?;
        if a.is_empty() {
            return invalid();
        }
        sorted_profiles(v, false, &["chunking"])?;
    }
    Ok(())
}
fn snapshot(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(
        f,
        7,
        &[16, 17, 18, 19, 21, 22, 23, 24, 25, 26],
        &[20, 27, 28],
        limits,
    )?;
    object_ref(f.get(16)?, Some(6))?;
    let p = array(f.get(17)?)?;
    schema_limit(
        limits,
        "snapshot-parents",
        p.len(),
        ErrorCode::SnapshotParentCountInvalid,
    )?;
    let mut seen = BTreeSet::new();
    for v in p {
        let r = object_ref(v, Some(7))?;
        if !seen.insert(r) {
            return Err(Error::new(ErrorCode::SnapshotParentDuplicate));
        }
    }
    object_ref(f.get(18)?, Some(3))?;
    object_ref(f.get(19)?, Some(4))?;
    if let Some(v) = f.opt(20) {
        object_ref(v, Some(5))?;
    }
    identity(f.get(21)?)?;
    identity(f.get(22)?)?;
    integer(f.get(23)?)?;
    integer(f.get(24)?)?;
    schema_limit(
        limits,
        "snapshot-message-bytes",
        text(f.get(25)?)?.len(),
        ErrorCode::LimitValueBytes,
    )?;
    policy(f.get(26)?)?;
    if let Some(v) = f.opt(27) {
        sorted_refs(v, Some(9))?;
    }
    if let Some(v) = f.opt(28) {
        object_ref(v, Some(11))?;
    }
    Ok(())
}
fn shelf(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(
        f,
        8,
        &[16, 17, 18, 20, 21, 22, 25, 26, 27, 28],
        &[19, 23, 24, 29],
        limits,
    )?;
    object_ref(f.get(16)?, Some(6))?;
    id128(f.get(17)?)?;
    let revision = range(f.get(18)?, 1, u32::MAX as u64)?;
    if (revision == 1) != f.opt(19).is_none() {
        return invalid();
    }
    if let Some(v) = f.opt(19) {
        object_ref(v, Some(8))?;
    }
    object_ref(f.get(20)?, Some(7))?;
    object_ref(f.get(21)?, Some(4))?;
    object_ref(f.get(22)?, Some(3))?;
    if let Some(v) = f.opt(23) {
        object_ref(v, Some(5))?;
    }
    if let Some(v) = f.opt(24) {
        object_ref(v, Some(11))?;
    }
    identity(f.get(25)?)?;
    integer(f.get(26)?)?;
    schema_limit(
        limits,
        "snapshot-message-bytes",
        text(f.get(27)?)?.len(),
        ErrorCode::LimitValueBytes,
    )?;
    policy(f.get(28)?)?;
    if let Some(v) = f.opt(29) {
        sorted_refs(v, Some(9))?;
    }
    Ok(())
}
fn provenance(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 9, &[16, 17, 18], &[19], limits)?;
    profile_in(f.get(16)?, &["provenance"])?;
    sorted_refs(f.get(17)?, None)?;
    let claim = typed_digest(f.get(18)?)?;
    if let Some(v) = f.opt(19) {
        if &sha256(bytes(v)?) != claim.digest() {
            return invalid();
        }
    }
    Ok(())
}
fn attestation(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 10, &[16, 17, 18, 19, 20], &[21, 22], limits)?;
    object_ref(f.get(16)?, None)?;
    profile_in(f.get(17)?, &["attestation-predicate"])?;
    identity(f.get(18)?)?;
    integer(f.get(19)?)?;
    bytes(f.get(20)?)?;
    match (f.opt(21), f.opt(22)) {
        (Some(p), Some(s)) => {
            profile_in(p, &["signature"])?;
            if bytes(s)?.is_empty() {
                return Err(Error::new(ErrorCode::AttestationSignatureShapeInvalid));
            }
        }
        (None, None) => {}
        _ => return Err(Error::new(ErrorCode::AttestationSignatureShapeInvalid)),
    }
    Ok(())
}
fn conflict_set(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    common(f, 11, &[16, 17], &[], limits)?;
    object_ref(f.get(16)?, Some(6))?;
    let records = array(f.get(17)?)?;
    if records.is_empty() {
        return invalid();
    }
    let mut prev = None;
    for r in records {
        let x = conflict_record(r, limits)?;
        if prev.is_some_and(|p: [u8; 32]| p >= x) {
            return invalid();
        }
        prev = Some(x);
    }
    Ok(())
}

fn metadata_schema_preflight(
    kind: ObjectKind,
    f: &Fields<'_>,
    limits: HardLimitCeilings,
) -> Result<()> {
    match kind {
        ObjectKind::Chunk => Ok(()),
        ObjectKind::ContentManifest => {
            generic_schema_check(common(f, 2, &[16, 17, 18, 19], &[], limits))?;
            generic_schema_check(u(f.get(16)?))?;
            typed_digest_schema_preflight(f.get(17)?)?;
            profile_schema_preflight(f.get(18)?)?;
            let chunks = array(f.get(19)?)?;
            for chunk in chunks {
                let chunk = Fields::new(chunk)?;
                chunk.shape(&[0, 1], &[])?;
                object_ref_schema_preflight(chunk.get(0)?)?;
                generic_schema_check(u(chunk.get(1)?))?;
            }
            Ok(())
        }
        ObjectKind::Tree => {
            generic_schema_check(common(f, 3, &[16, 17], &[], limits))?;
            object_ref_schema_preflight(f.get(16)?)?;
            for entry in array(f.get(17)?)? {
                let entry = Fields::new(entry)?;
                entry.shape(&[0, 1, 2, 3, 4, 5, 6], &[])?;
                generic_schema_check(text(entry.get(0)?))?;
                generic_schema_check(range(entry.get(1)?, 1, 4))?;
                generic_schema_check(raw_id128(entry.get(2)?))?;
                generic_schema_check(range(entry.get(3)?, 1, 4))?;
                object_ref_schema_preflight(entry.get(4)?)?;
                generic_schema_check(u(entry.get(5)?))?;
                profile_schema_preflight(entry.get(6)?)?;
            }
            Ok(())
        }
        ObjectKind::ChangeSet => {
            generic_schema_check(common(f, 4, &[16, 18], &[17], limits))?;
            object_ref_schema_preflight(f.get(16)?)?;
            if let Some(value) = f.opt(17) {
                object_ref_schema_preflight(value)?;
            }
            for operation in array(f.get(18)?)? {
                operation_generic_preflight(operation, limits)?;
            }
            Ok(())
        }
        ObjectKind::AssetGroupSet => {
            generic_schema_check(common(f, 5, &[16, 17], &[], limits))?;
            object_ref_schema_preflight(f.get(16)?)?;
            for group in array(f.get(17)?)? {
                asset_group_schema_preflight(group, limits)?;
            }
            Ok(())
        }
        ObjectKind::RepositoryDescriptor => {
            generic_schema_check(common(f, 6, &[16, 17, 18, 19], &[20], limits))?;
            generic_schema_check(id128(f.get(16)?))?;
            profile_schema_preflight(f.get(17)?)?;
            profile_array_schema_preflight(f.get(18)?)?;
            profile_array_schema_preflight(f.get(19)?)?;
            if let Some(value) = f.opt(20) {
                profile_array_schema_preflight(value)?;
            }
            Ok(())
        }
        ObjectKind::Snapshot => {
            generic_schema_check(common(
                f,
                7,
                &[16, 17, 18, 19, 21, 22, 23, 24, 25, 26],
                &[20, 27, 28],
                limits,
            ))?;
            object_ref_schema_preflight(f.get(16)?)?;
            object_ref_array_schema_preflight(f.get(17)?)?;
            object_ref_schema_preflight(f.get(18)?)?;
            object_ref_schema_preflight(f.get(19)?)?;
            if let Some(value) = f.opt(20) {
                object_ref_schema_preflight(value)?;
            }
            identity_schema_preflight(f.get(21)?)?;
            identity_schema_preflight(f.get(22)?)?;
            generic_schema_check(integer(f.get(23)?))?;
            generic_schema_check(integer(f.get(24)?))?;
            generic_schema_check(text(f.get(25)?))?;
            policy_schema_preflight(f.get(26)?)?;
            if let Some(value) = f.opt(27) {
                object_ref_array_schema_preflight(value)?;
            }
            if let Some(value) = f.opt(28) {
                object_ref_schema_preflight(value)?;
            }
            Ok(())
        }
        ObjectKind::ShelfRevision => {
            generic_schema_check(common(
                f,
                8,
                &[16, 17, 18, 20, 21, 22, 25, 26, 27, 28],
                &[19, 23, 24, 29],
                limits,
            ))?;
            object_ref_schema_preflight(f.get(16)?)?;
            generic_schema_check(id128(f.get(17)?))?;
            generic_schema_check(range(f.get(18)?, 1, u32::MAX as u64))?;
            for key in [19, 20, 21, 22, 23, 24] {
                if let Some(value) = f.opt(key) {
                    object_ref_schema_preflight(value)?;
                }
            }
            identity_schema_preflight(f.get(25)?)?;
            generic_schema_check(integer(f.get(26)?))?;
            generic_schema_check(text(f.get(27)?))?;
            policy_schema_preflight(f.get(28)?)?;
            if let Some(value) = f.opt(29) {
                object_ref_array_schema_preflight(value)?;
            }
            Ok(())
        }
        ObjectKind::Provenance => {
            generic_schema_check(common(f, 9, &[16, 17, 18], &[19], limits))?;
            profile_schema_preflight(f.get(16)?)?;
            object_ref_array_schema_preflight(f.get(17)?)?;
            typed_digest_schema_preflight(f.get(18)?)?;
            if let Some(value) = f.opt(19) {
                generic_schema_check(bytes(value))?;
            }
            Ok(())
        }
        ObjectKind::Attestation => {
            generic_schema_check(common(f, 10, &[16, 17, 18, 19, 20], &[21, 22], limits))?;
            object_ref_schema_preflight(f.get(16)?)?;
            profile_schema_preflight(f.get(17)?)?;
            identity_schema_preflight(f.get(18)?)?;
            generic_schema_check(integer(f.get(19)?))?;
            generic_schema_check(bytes(f.get(20)?))?;
            if let Some(value) = f.opt(21) {
                profile_schema_preflight(value)?;
            }
            if let Some(value) = f.opt(22) {
                generic_schema_check(nonempty_bytes(value))?;
            }
            Ok(())
        }
        ObjectKind::ConflictSet => {
            generic_schema_check(common(f, 11, &[16, 17], &[], limits))?;
            object_ref_schema_preflight(f.get(16)?)?;
            let records = array(f.get(17)?)?;
            for record in records {
                conflict_record_schema_preflight(record, limits)?;
            }
            Ok(())
        }
    }
}

fn profile_array_schema_preflight(v: &Cbor) -> Result<()> {
    for value in array(v)? {
        profile_schema_preflight(value)?;
    }
    Ok(())
}

fn object_ref_array_schema_preflight(v: &Cbor) -> Result<()> {
    for value in array(v)? {
        object_ref_schema_preflight(value)?;
    }
    Ok(())
}

fn operation(v: &Cbor, seq: u64, limits: HardLimitCeilings) -> Result<()> {
    operation_generic_preflight(v, limits)?;
    let f = Fields::new(v)?;
    let code = range(f.get(1)?, 1, 11)?;
    match code {
        1 => f.shape(&[0, 1, 3, 5], &[])?,
        2 | 4 | 5 => f.shape(&[0, 1, 2, 3], &[])?,
        3 => f.shape(&[0, 1, 3, 4, 5], &[])?,
        6 => f.shape(&[0, 1, 2], &[])?,
        7 => f.shape(&[0, 1, 3, 6], &[])?,
        8 => f.shape(&[0, 1, 8], &[])?,
        9 => f.shape(&[0, 1, 7, 8], &[])?,
        10 => f.shape(&[0, 1, 7], &[])?,
        11 => f.shape(&[0, 1, 9, 10], &[11])?,
        _ => unreachable!("range above constrains the operation code"),
    }
    let mut best = (f.u(0)? != seq).then(|| Error::new(ErrorCode::ChangeSetSequenceInvalid));
    if let Err(error) = validate_operation_body(&f, code, limits) {
        observe_schema_error(&mut best, error);
    }
    best.map_or(Ok(()), Err)
}

fn operation_generic_preflight(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    generic_schema_check(u(f.get(0)?))?;
    let code = range(f.get(1)?, 1, 11)?;
    match code {
        1 => f.shape(&[0, 1, 3, 5], &[])?,
        2 | 4 | 5 => f.shape(&[0, 1, 2, 3], &[])?,
        3 => f.shape(&[0, 1, 3, 4, 5], &[])?,
        6 => f.shape(&[0, 1, 2], &[])?,
        7 => f.shape(&[0, 1, 3, 6], &[])?,
        8 => f.shape(&[0, 1, 8], &[])?,
        9 => f.shape(&[0, 1, 7, 8], &[])?,
        10 => f.shape(&[0, 1, 7], &[])?,
        11 => f.shape(&[0, 1, 9, 10], &[11])?,
        _ => unreachable!("range above constrains the operation code"),
    }
    operation_schema_preflight(&f, limits)
}

fn validate_operation_body(f: &Fields<'_>, code: u64, limits: HardLimitCeilings) -> Result<()> {
    match code {
        1 => {
            entry_state(f.get(3)?, limits)?;
            allocation(f.get(5)?)?
        }
        2 | 4 | 5 => {
            entry_state(f.get(2)?, limits)?;
            entry_state(f.get(3)?, limits)?
        }
        3 => {
            entry_state(f.get(3)?, limits)?;
            entry_state(f.get(4)?, limits)?;
            allocation(f.get(5)?)?
        }
        6 => entry_state(f.get(2)?, limits)?,
        7 => {
            entry_state(f.get(3)?, limits)?;
            restore(f.get(6)?, limits)?
        }
        8 => {
            asset_group(f.get(8)?, limits)?;
        }
        9 => {
            asset_group(f.get(7)?, limits)?;
            asset_group(f.get(8)?, limits)?;
        }
        10 => {
            asset_group(f.get(7)?, limits)?;
        }
        11 => {
            digest(f.get(9)?)?;
            let subject = range(f.get(10)?, 1, 2)?;
            if let Some(x) = f.opt(11) {
                if subject == 1 {
                    entry_state(x, limits)?;
                } else {
                    asset_group(x, limits)?;
                }
            }
        }
        _ => return invalid(),
    }
    Ok(())
}

fn operation_schema_preflight(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    for key in [2, 3, 4] {
        if let Some(value) = f.opt(key) {
            entry_state_schema_preflight(value, limits)?;
        }
    }
    if let Some(value) = f.opt(5) {
        allocation_schema_preflight(value)?;
    }
    if let Some(value) = f.opt(6) {
        restore_schema_preflight(value, limits)?;
    }
    for key in [7, 8] {
        if let Some(value) = f.opt(key) {
            asset_group_schema_preflight(value, limits)?;
        }
    }
    if let Some(value) = f.opt(9) {
        generic_schema_check(digest(value))?;
    }
    if let Some(value) = f.opt(10) {
        generic_schema_check(range(value, 1, 2))?;
    }
    if let Some(value) = f.opt(11) {
        match f.opt(10).and_then(|subject| u(subject).ok()) {
            Some(1) => entry_state_schema_preflight(value, limits)?,
            Some(2) => asset_group_schema_preflight(value, limits)?,
            _ => {}
        }
    }
    Ok(())
}

fn entry_state_schema_preflight(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3, 5, 6], &[4])?;
    path_schema_preflight(f.get(0)?)?;
    generic_schema_check(range(f.get(1)?, 1, 4))?;
    generic_schema_check(raw_id128(f.get(2)?))?;
    generic_schema_check(u(f.get(3)?))?;
    if let Some(value) = f.opt(4) {
        object_ref_schema_preflight(value)?;
    }
    generic_schema_check(u(f.get(5)?))?;
    profile_schema_preflight(f.get(6)?)?;
    generic_schema_check(schema_limit_u64(
        limits,
        "logical-file-bytes",
        u(f.get(5)?)?,
        ErrorCode::LimitLogicalBytes,
    ))?;
    Ok(())
}

fn allocation_schema_preflight(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1], &[2])?;
    object_ref_schema_preflight(f.get(0)?)?;
    generic_schema_check(range(f.get(1)?, 1, 2))?;
    if let Some(value) = f.opt(2) {
        generic_schema_check(digest(value))?;
    }
    Ok(())
}

fn restore_schema_preflight(v: &Cbor, _limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[])?;
    object_ref_schema_preflight(f.get(0)?)?;
    object_ref_schema_preflight(f.get(1)?)?;
    path_schema_preflight(f.get(2)?)?;
    object_ref_schema_preflight(f.get(3)?)?;
    Ok(())
}

fn asset_group_schema_preflight(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[4])?;
    generic_schema_check(id128(f.get(0)?))?;
    profile_schema_preflight(f.get(1)?)?;
    generic_schema_check(raw_id128(f.get(2)?))?;
    for member in array(f.get(3)?)? {
        let member = Fields::new(member)?;
        member.shape(&[0, 1], &[])?;
        generic_schema_check(raw_id128(member.get(0)?))?;
        profile_schema_preflight(member.get(1)?)?;
    }
    if let Some(values) = f.opt(4) {
        for external in array(values)? {
            let external = Fields::new(external)?;
            external.shape(&[0, 1], &[])?;
            profile_schema_preflight(external.get(0)?)?;
            generic_schema_check(nonempty_bytes(external.get(1)?))?;
        }
    }
    // Keep schema resource ceilings in the preflight, but leave their typed
    // limit errors to the specialized pass below.
    generic_schema_check(schema_limit(
        limits,
        "asset-group-members",
        array(f.get(3)?)?.len(),
        ErrorCode::LimitCount,
    ))?;
    Ok(())
}

fn generic_schema_check<T>(result: Result<T>) -> Result<()> {
    match result {
        Err(error) if error.code == ErrorCode::SchemaFieldInvalid => Err(error),
        _ => Ok(()),
    }
}

fn object_ref_schema_preflight(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[])?;
    generic_schema_check(u(f.get(0)?))?;
    generic_schema_check(range(f.get(1)?, 1, u16::MAX as u64))?;
    generic_schema_check(u(f.get(2)?))?;
    generic_schema_check(digest(f.get(3)?))?;
    Ok(())
}

fn typed_digest_schema_preflight(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1], &[])?;
    generic_schema_check(u(f.get(0)?))?;
    generic_schema_check(digest(f.get(1)?))?;
    Ok(())
}

fn profile_schema_preflight(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2], &[])?;
    generic_schema_check(text(f.get(0)?))?;
    generic_schema_check(text(f.get(1)?))?;
    generic_schema_check(range(f.get(2)?, 1, u32::MAX as u64))?;
    Ok(())
}

fn path_schema_preflight(v: &Cbor) -> Result<()> {
    for segment in array(v)? {
        generic_schema_check(text(segment))?;
    }
    Ok(())
}

fn identity_schema_preflight(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1], &[2])?;
    profile_schema_preflight(f.get(0)?)?;
    generic_schema_check(nonempty_bytes(f.get(1)?))?;
    if let Some(value) = f.opt(2) {
        generic_schema_check(text(value))?;
    }
    Ok(())
}

fn policy_schema_preflight(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[])?;
    profile_schema_preflight(f.get(0)?)?;
    generic_schema_check(u(f.get(1)?))?;
    generic_schema_check(range(f.get(2)?, 1, 2))?;
    typed_digest_schema_preflight(f.get(3)?)?;
    Ok(())
}
fn entry_state(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3, 5, 6], &[4])?;
    path(f.get(0)?, limits)?;
    let kind = range(f.get(1)?, 1, 4)?;
    file_id(f.get(2)?)?;
    let mode = range(f.get(3)?, 1, 4)?;
    let size = logical_length(f.get(5)?, limits)?;
    profile_in(f.get(6)?, &["content-policy", "fixture-content-policy"])?;
    if kind != mode {
        return Err(Error::new(ErrorCode::TreeEntryTargetInvalid));
    }
    match (kind, f.opt(4)) {
        (1, None) if size == 0 => Ok(()),
        (1, _) => Err(Error::new(ErrorCode::TreeEntryTargetInvalid)),
        (_, Some(r)) => {
            object_ref(r, Some(2))?;
            Ok(())
        }
        _ => Err(Error::new(ErrorCode::TreeEntryTargetInvalid)),
    }
}
fn allocation(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1], &[2])?;
    object_ref(f.get(0)?, Some(6))?;
    let kind = range(f.get(1)?, 1, 2)?;
    if (kind == 2) != f.opt(2).is_some() {
        return invalid();
    }
    if let Some(v) = f.opt(2) {
        digest(v)?;
    }
    Ok(())
}
fn restore(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[])?;
    object_ref(f.get(0)?, Some(6))?;
    object_ref(f.get(1)?, Some(7))?;
    path(f.get(2)?, limits)?;
    object_ref(f.get(3)?, Some(7))?;
    Ok(())
}
fn asset_group(v: &Cbor, limits: HardLimitCeilings) -> Result<[u8; 16]> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[4])?;
    let id = id128(f.get(0)?)?;
    profile_in(f.get(1)?, &["group", "fixture-group"])?;
    file_id(f.get(2)?)?;
    let members = array(f.get(3)?)?;
    if members.is_empty() {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    schema_limit(
        limits,
        "asset-group-members",
        members.len(),
        ErrorCode::LimitCount,
    )?;
    let mut previous_member = None;
    for m in members {
        let mf = Fields::new(m)?;
        mf.shape(&[0, 1], &[])?;
        let fid = file_id(mf.get(0)?)?;
        profile_in(mf.get(1)?, &["group-role", "fixture-group-role"])?;
        let current = (encode_canonical(mf.get(1)?)?, fid);
        if previous_member
            .as_ref()
            .is_some_and(|prior| prior >= &current)
        {
            return invalid();
        }
        previous_member = Some(current);
    }
    if let Some(x) = f.opt(4) {
        let mut prior = None;
        for e in array(x)? {
            let ef = Fields::new(e)?;
            ef.shape(&[0, 1], &[])?;
            profile_in(ef.get(0)?, &["external-key", "fixture-external-key"])?;
            let raw_value = bytes(ef.get(1)?)?;
            if raw_value.is_empty() {
                return invalid();
            }
            let current = (encode_canonical(ef.get(0)?)?, raw_value.to_vec());
            if prior.as_ref().is_some_and(|p| p >= &current) {
                return invalid();
            }
            prior = Some(current);
        }
    }
    Ok(id)
}

fn conflict_preimage_schema_preflight(f: &Fields<'_>, limits: HardLimitCeilings) -> Result<()> {
    f.shape(&[0, 1], &[2, 3, 4])?;
    generic_schema_check(conflict_kind(f.get(0)?))?;
    conflict_subject_schema_preflight(f.get(1)?)?;
    for key in 2..=4 {
        if let Some(value) = f.opt(key) {
            conflict_side_schema_preflight(value, limits)?;
        }
    }
    Ok(())
}

fn conflict_record_schema_preflight(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 6], &[3, 4, 5])?;
    generic_schema_check(digest(f.get(0)?))?;
    generic_schema_check(conflict_kind(f.get(1)?))?;
    conflict_subject_schema_preflight(f.get(2)?)?;
    for key in 3..=5 {
        if let Some(value) = f.opt(key) {
            conflict_side_schema_preflight(value, limits)?;
        }
    }
    resolution_schema_preflight(f.get(6)?, limits)
}

fn conflict_subject_schema_preflight(v: &Cbor) -> Result<()> {
    let values = array(v)?;
    let kind = range(
        values
            .first()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?,
        1,
        2,
    )?;
    if kind == 1 {
        if values.len() != 3 {
            return invalid();
        }
        let ids = array(&values[1])?;
        if ids.is_empty() || ids.len() > 3 {
            return invalid();
        }
        for value in ids {
            generic_schema_check(raw_id128(value))?;
        }
        let paths = array(&values[2])?;
        if paths.is_empty() || paths.len() > 3 {
            return invalid();
        }
        for value in paths {
            path_schema_preflight(value)?;
        }
    } else {
        if values.len() != 2 {
            return invalid();
        }
        generic_schema_check(id128(&values[1]))?;
    }
    Ok(())
}

fn conflict_side_schema_preflight(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    match range(f.get(0)?, 1, 2)? {
        1 => {
            f.shape(&[0, 1], &[])?;
            entry_state_schema_preflight(f.get(1)?, limits)
        }
        2 => {
            f.shape(&[0, 2], &[])?;
            asset_group_schema_preflight(f.get(2)?, limits)
        }
        _ => unreachable!("range above constrains the conflict-side kind"),
    }
}

fn resolution_schema_preflight(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    match range(f.get(0)?, 0, 1)? {
        0 => f.shape(&[0], &[]),
        1 => {
            let choice = range(f.get(1)?, 1, 5)?;
            match choice {
                1..=3 => {
                    f.shape(&[0, 1, 2], &[])?;
                    conflict_side_schema_preflight(f.get(2)?, limits)?;
                }
                4 => f.shape(&[0, 1], &[])?,
                5 => {
                    f.shape(&[0, 1, 2, 3], &[])?;
                    conflict_side_schema_preflight(f.get(2)?, limits)?;
                    profile_schema_preflight(f.get(3)?)?;
                }
                _ => unreachable!("range above constrains the resolution choice"),
            }
            Ok(())
        }
        _ => unreachable!("range above constrains the resolution state"),
    }
}

fn conflict_record(v: &Cbor, limits: HardLimitCeilings) -> Result<[u8; 32]> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 6], &[3, 4, 5])?;
    let id = digest(f.get(0)?)?;
    conflict_kind(f.get(1)?)?;
    conflict_subject(f.get(2)?, limits)?;
    for k in 3..=5 {
        if let Some(x) = f.opt(k) {
            conflict_side(x, limits)?;
        }
    }
    resolution(f.get(6)?, limits)?;
    let mut preimage = vec![
        (Cbor::UInt(0), f.get(1)?.clone()),
        (Cbor::UInt(1), f.get(2)?.clone()),
    ];
    for (source, target) in [(3, 2), (4, 3), (5, 4)] {
        if let Some(side) = f.opt(source) {
            preimage.push((Cbor::UInt(target), side.clone()));
        }
    }
    let encoded = encode_canonical(&Cbor::Map(preimage))?;
    if conflict_id(&encoded) != id {
        return Err(Error::new(ErrorCode::ConflictIdMismatch));
    }
    Ok(id)
}
fn conflict_kind(v: &Cbor) -> Result<u64> {
    match u(v)? {
        value @ (1..=4 | 6..=8) => Ok(value),
        _ => invalid(),
    }
}
fn conflict_subject(v: &Cbor, limits: HardLimitCeilings) -> Result<u64> {
    let values = array(v)?;
    let Some(kind_value) = values.first() else {
        return invalid();
    };
    let kind = range(kind_value, 1, 2)?;
    if kind == 1 {
        if values.len() != 3 {
            return invalid();
        }
        sorted_ids(&values[1], 1, 3)?;
        let paths = array(&values[2])?;
        if paths.is_empty() || paths.len() > 3 {
            return invalid();
        }
        let mut previous = None;
        for value in paths {
            path(value, limits)?;
            let encoded = encode_canonical(value)?;
            if previous
                .as_ref()
                .is_some_and(|prior: &Vec<u8>| prior >= &encoded)
            {
                return invalid();
            }
            previous = Some(encoded);
        }
    } else {
        if values.len() != 2 {
            return invalid();
        }
        id128(&values[1])?;
    }
    Ok(kind)
}
fn conflict_side(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    match f.u(0)? {
        1 => {
            f.shape(&[0, 1], &[])?;
            entry_state(f.get(1)?, limits)
        }
        2 => {
            f.shape(&[0, 2], &[])?;
            asset_group(f.get(2)?, limits)?;
            Ok(())
        }
        _ => invalid(),
    }
}
fn resolution(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let f = Fields::new(v)?;
    match f.u(0)? {
        0 => f.shape(&[0], &[]),
        1 => {
            let choice = range(f.get(1)?, 1, 5)?;
            match choice {
                1..=3 => {
                    f.shape(&[0, 1, 2], &[])?;
                    conflict_side(f.get(2)?, limits)?;
                }
                4 => f.shape(&[0, 1], &[])?,
                5 => {
                    f.shape(&[0, 1, 2, 3], &[])?;
                    conflict_side(f.get(2)?, limits)?;
                    profile_in(f.get(3)?, &["conflict-driver"])?;
                }
                _ => unreachable!(),
            }
            Ok(())
        }
        _ => invalid(),
    }
}

fn object_ref(v: &Cbor, expected: Option<u64>) -> Result<ObjectRef> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[])?;
    if f.u(0)? != 1 || f.u(2)? != 1 {
        return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
    }
    let kind = ObjectKind::from_code(f.u(1)?)?;
    if expected.is_some_and(|x| x != kind.code() as u64) {
        return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::KnownSchema));
    }
    Ok(ObjectRef {
        kind,
        digest: digest(f.get(3)?)?,
    })
}
fn typed_digest(v: &Cbor) -> Result<TypedDigest> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1], &[])?;
    if f.u(0)? != 1 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    Ok(TypedDigest::sha256(digest(f.get(1)?)?))
}
fn profile(v: &Cbor) -> Result<ProfileRef> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2], &[])?;
    ProfileRef::new(
        text(f.get(0)?)?,
        text(f.get(1)?)?,
        u32::try_from(range(f.get(2)?, 1, u32::MAX as u64)?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?,
    )
}
fn profile_in(v: &Cbor, families: &[&str]) -> Result<ProfileRef> {
    let profile = profile(v)?;
    if Registry::bundled()
        .profile(&profile)
        .is_some_and(|entry| !families.contains(&entry.family.as_str()))
    {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    Ok(profile)
}
fn identity(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1], &[2])?;
    profile_in(f.get(0)?, &["identity"])?;
    if bytes(f.get(1)?)?.is_empty() {
        return invalid();
    }
    if let Some(v) = f.opt(2) {
        text(v)?;
    }
    Ok(())
}
fn policy(v: &Cbor) -> Result<()> {
    let f = Fields::new(v)?;
    f.shape(&[0, 1, 2, 3], &[])?;
    profile_in(f.get(0)?, &["policy"])?;
    u(f.get(1)?)?;
    range(f.get(2)?, 1, 2)?;
    typed_digest(f.get(3)?)?;
    Ok(())
}
fn path(v: &Cbor, limits: HardLimitCeilings) -> Result<()> {
    let a = array(v)?;
    if a.is_empty() {
        return Err(Error::new(ErrorCode::PathCoreInvalid));
    }
    schema_limit(limits, "path-segments", a.len(), ErrorCode::PathCoreInvalid)?;
    let mut joined = a.len() - 1;
    for x in a {
        let s = basename(x, limits)?;
        joined = joined
            .checked_add(s.len())
            .ok_or_else(|| Error::new(ErrorCode::PathCoreInvalid))?;
    }
    schema_limit(limits, "path-bytes", joined, ErrorCode::PathCoreInvalid)?;
    Ok(())
}
fn basename(v: &Cbor, limits: HardLimitCeilings) -> Result<&str> {
    let s = text(v)?;
    schema_limit(
        limits,
        "path-segment-bytes",
        s.len(),
        ErrorCode::PathCoreInvalid,
    )?;
    if s.is_empty()
        || s == "."
        || s == ".."
        || s.as_bytes().contains(&b'/')
        || s.as_bytes().contains(&0)
    {
        return Err(Error::new(ErrorCode::PathCoreInvalid));
    }
    Ok(s)
}
fn sorted_profiles(v: &Cbor, nonempty: bool, families: &[&str]) -> Result<()> {
    let a = array(v)?;
    if nonempty && a.is_empty() {
        return invalid();
    }
    let mut prev = None;
    for p in a {
        profile_in(p, families)?;
        let enc = encode_canonical(p)?;
        if prev.as_ref().is_some_and(|x: &Vec<u8>| x >= &enc) {
            return invalid();
        }
        prev = Some(enc);
    }
    Ok(())
}
fn sorted_refs(v: &Cbor, kind: Option<u64>) -> Result<()> {
    let mut prev = None;
    for r in array(v)? {
        object_ref(r, kind)?;
        let enc = encode_canonical(r)?;
        if prev.as_ref().is_some_and(|x: &Vec<u8>| x >= &enc) {
            return invalid();
        }
        prev = Some(enc);
    }
    Ok(())
}
fn sorted_ids(v: &Cbor, min: usize, max: usize) -> Result<()> {
    let a = array(v)?;
    if a.len() < min || a.len() > max {
        return invalid();
    }
    let mut prev = None;
    for x in a {
        let id = file_id(x)?;
        if prev.is_some_and(|p: [u8; 16]| p >= id) {
            return invalid();
        }
        prev = Some(id);
    }
    Ok(())
}
fn file_id(v: &Cbor) -> Result<[u8; 16]> {
    let x = raw_id128(v)?;
    if x == [0; 16] {
        Err(Error::new(ErrorCode::FileIdZero))
    } else {
        Ok(x)
    }
}
fn id128(v: &Cbor) -> Result<[u8; 16]> {
    let value = raw_id128(v)?;
    if value == [0; 16] {
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    } else {
        Ok(value)
    }
}
fn raw_id128(v: &Cbor) -> Result<[u8; 16]> {
    bytes(v)?
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}
fn digest(v: &Cbor) -> Result<[u8; 32]> {
    bytes(v)?
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}
fn logical_length(v: &Cbor, limits: HardLimitCeilings) -> Result<u64> {
    let x = u(v)?;
    schema_limit_u64(
        limits,
        "logical-file-bytes",
        x,
        ErrorCode::LimitLogicalBytes,
    )?;
    Ok(x)
}
fn range(v: &Cbor, min: u64, max: u64) -> Result<u64> {
    let x = u(v)?;
    if x < min || x > max {
        return invalid();
    }
    Ok(x)
}
fn nonempty_text(v: &Cbor) -> Result<&str> {
    let s = text(v)?;
    if s.is_empty() {
        return invalid();
    }
    Ok(s)
}
fn fixture_op(v: &Cbor) -> Result<()> {
    const OPS: &[&str] = &[
        "branch",
        "branch-update",
        "ci-materialize",
        "copy",
        "create",
        "delete",
        "edit",
        "interrupt",
        "lock-acquire",
        "lock-conflict",
        "lock-loss",
        "merge",
        "move",
        "network-condition",
        "rename",
        "review",
        "selective-sync",
        "submit",
    ];
    if OPS.contains(&text(v)?) {
        Ok(())
    } else {
        invalid()
    }
}
fn integer(v: &Cbor) -> Result<()> {
    match v {
        Cbor::UInt(value) if *value <= i64::MAX as u64 => Ok(()),
        Cbor::NInt(_) => Ok(()),
        _ => invalid(),
    }
}
fn u(v: &Cbor) -> Result<u64> {
    if let Cbor::UInt(x) = v {
        Ok(*x)
    } else {
        invalid()
    }
}
fn bytes(v: &Cbor) -> Result<&[u8]> {
    if let Cbor::Bytes(x) = v {
        Ok(x)
    } else {
        invalid()
    }
}
fn nonempty_bytes(v: &Cbor) -> Result<&[u8]> {
    let value = bytes(v)?;
    if value.is_empty() {
        invalid()
    } else {
        Ok(value)
    }
}
fn text(v: &Cbor) -> Result<&str> {
    if let Cbor::Text(x) = v {
        if !is_unicode_15(x) || !is_nfc(x) {
            return invalid();
        }
        Ok(x)
    } else {
        invalid()
    }
}
fn array(v: &Cbor) -> Result<&[Cbor]> {
    if let Cbor::Array(x) = v {
        Ok(x)
    } else {
        invalid()
    }
}
fn map(v: &Cbor) -> Result<&[(Cbor, Cbor)]> {
    if let Cbor::Map(x) = v {
        Ok(x)
    } else {
        invalid()
    }
}
fn invalid<T>() -> Result<T> {
    Err(Error::new(ErrorCode::SchemaFieldInvalid))
}

fn validate_extension_value(v: &Cbor) -> Result<()> {
    match v {
        Cbor::UInt(_) | Cbor::NInt(_) | Cbor::Bytes(_) | Cbor::Bool(_) => Ok(()),
        Cbor::Text(_) => text(v).map(|_| ()),
        Cbor::Array(a) => a.iter().try_for_each(validate_extension_value),
        Cbor::Map(m) => m.iter().try_for_each(|(k, v)| {
            u(k)?;
            validate_extension_value(v)
        }),
    }
}

struct Fields<'a> {
    values: Vec<(u64, &'a Cbor)>,
}
impl<'a> Fields<'a> {
    fn new(v: &'a Cbor) -> Result<Self> {
        let mut values = Vec::new();
        for (k, v) in map(v)? {
            values.push((u(k)?, v));
        }
        Ok(Self { values })
    }
    fn get(&self, key: u64) -> Result<&'a Cbor> {
        self.opt(key)
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
    }
    fn opt(&self, key: u64) -> Option<&'a Cbor> {
        self.values.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
    fn u(&self, key: u64) -> Result<u64> {
        u(self.get(key)?)
    }
    fn shape(&self, required: &[u64], optional: &[u64]) -> Result<()> {
        for key in required {
            if self.opt(*key).is_none() {
                return invalid();
            }
        }
        for (key, _) in &self.values {
            if !required.contains(key) && !optional.contains(key) {
                let deferred = UNKNOWN_FIELD_STATE.with(|state| {
                    if state.get() == 0 {
                        false
                    } else {
                        state.set(2);
                        true
                    }
                });
                if deferred {
                    continue;
                }
                return Err(Error::new(ErrorCode::SchemaFieldUnknown));
            }
        }
        Ok(())
    }
}
