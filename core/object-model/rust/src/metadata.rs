use std::io::{Read, Write};

use crate::{
    cbor::{encode_canonical_with_limits, Cbor, Limits},
    registry::{require_write_operation, Operation, Registry},
    repository::{validate_semantic_object, ValidationMode},
    schema::{scan_metadata, MetadataObject},
    Error, ErrorCode, ObjectKind, Result,
};

/// Complete authority and explicit lifecycle selection for semantic metadata
/// decoding. Construction is cheap; authority is checked before reading from
/// the caller's source.
#[derive(Clone, Copy)]
pub struct MetadataDecodeOptions<'a> {
    pub registry: &'a Registry,
    pub operation: Operation,
    pub limits: Limits,
}

impl<'a> MetadataDecodeOptions<'a> {
    pub const fn new(registry: &'a Registry, operation: Operation) -> Self {
        Self {
            registry,
            operation,
            limits: Limits::METADATA,
        }
    }
}

/// Successful registry-authoritative decode through repository layer three.
#[derive(Clone, Debug)]
pub struct MetadataDecodeSummary {
    pub object: MetadataObject,
    pub kind: ObjectKind,
    pub highest_layer: u8,
}

/// Complete authority and explicit write lifecycle selection for metadata
/// emission. `Operation::Read` is rejected before the caller's value or sink
/// is touched.
#[derive(Clone, Copy)]
pub struct MetadataEncodeOptions<'a> {
    pub registry: &'a Registry,
    pub operation: Operation,
    pub limits: Limits,
}

impl<'a> MetadataEncodeOptions<'a> {
    pub const fn new(registry: &'a Registry, operation: Operation) -> Self {
        Self {
            registry,
            operation,
            limits: Limits::METADATA,
        }
    }
}

/// Successful registry-authoritative metadata emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataEncodeSummary {
    pub bytes: usize,
    pub kind: ObjectKind,
    pub highest_layer: u8,
}

/// Reads and validates one canonical metadata object. The complete registry
/// authority and lifecycle operation are validated before the first read.
pub fn decode_metadata<R: Read>(
    mut reader: R,
    options: MetadataDecodeOptions<'_>,
) -> Result<MetadataDecodeSummary> {
    options.registry.require_complete_authority()?;
    let maximum = Limits::METADATA
        .constrained_by(options.limits)
        .max_input_bytes;
    let take = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| Error::new(ErrorCode::LimitMetadataBytes))?;
    let mut bytes = Vec::new();
    reader
        .take(take)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    let object = scan_metadata(&bytes, options.limits)?;
    let semantic = validate_semantic_object(
        &object,
        options.registry,
        validation_mode(options.operation),
    )?;
    Ok(MetadataDecodeSummary {
        object,
        kind: semantic.kind,
        highest_layer: semantic.highest_layer,
    })
}

/// Validates and writes one canonical metadata object. No bytes are written
/// until authority, operation, canonical shape, known schema, and lifecycle
/// semantics have all succeeded.
pub fn encode_metadata<W: Write>(
    value: &Cbor,
    mut writer: W,
    options: MetadataEncodeOptions<'_>,
) -> Result<MetadataEncodeSummary> {
    options.registry.require_complete_authority()?;
    require_write_operation(options.operation)?;
    let bytes = encode_canonical_with_limits(value, options.limits)?;
    let object = scan_metadata(&bytes, options.limits)?;
    let semantic = validate_semantic_object(
        &object,
        options.registry,
        validation_mode(options.operation),
    )?;
    writer
        .write_all(&bytes)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    Ok(MetadataEncodeSummary {
        bytes: bytes.len(),
        kind: semantic.kind,
        highest_layer: semantic.highest_layer,
    })
}

fn validation_mode(operation: Operation) -> ValidationMode {
    match operation {
        Operation::Read => ValidationMode::Read,
        Operation::ConformanceWrite => ValidationMode::Conformance,
        Operation::ProductionWrite => ValidationMode::Production,
    }
}
