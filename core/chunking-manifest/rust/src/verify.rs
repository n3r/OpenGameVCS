use std::collections::BTreeMap;

use ogvcs_object_model::{
    object_id, scan_metadata, validate_metadata_schema, Cbor, Limits, ObjectHashWriter,
    ObjectKind, ObjectRef, ProfileRef, Sha256Writer,
};

use crate::{
    gear_table, ChunkError, Ledger, LedgerMetrics, LedgerOptions, LedgerRecord,
    CHUNK_COUNT_MAXIMUM, LOGICAL_MAXIMUM, MAXIMUM, MINIMUM, PROFILE, SMALL_MAXIMUM, TARGET,
};

const EARLY_MASK: u64 = 0x001f_ffff;
const LATE_MASK: u64 = 0x0007_ffff;
const INDEX_ENTRY_BYTES: u64 = 256;

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub max_manifest_bytes: usize,
    pub max_decode_working_bytes: usize,
    pub max_index_memory_bytes: u64,
    pub expected_manifest_object_id: Option<String>,
    pub ledger: LedgerOptions,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 64 * 1024 * 1024,
            max_decode_working_bytes: 64 * 1024 * 1024,
            max_index_memory_bytes: 256 * 1024 * 1024,
            expected_manifest_object_id: None,
            ledger: LedgerOptions::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPart {
    pub reference: ObjectRef,
    pub length: u64,
}

pub trait ChunkSource {
    fn stream_chunk(
        &mut self,
        part: &ManifestPart,
        occurrence: usize,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), ChunkError>,
    ) -> Result<(), ChunkError>;
}

pub trait TransactionalPublication {
    fn write(&mut self, bytes: &[u8], occurrence: usize) -> Result<(), ChunkError>;
    fn commit(&mut self) -> Result<(), ChunkError>;
    fn abort(&mut self, cause: ChunkError) -> Result<(), ChunkError>;
}

pub trait KnownChunkIndex {
    fn known_length(&mut self, reference: &ObjectRef) -> Result<Option<u64>, ChunkError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifySummary {
    pub logical_bytes: u64,
    pub manifest_object_id: String,
    pub part_count: usize,
    pub provider_reads: usize,
    pub unique_bytes: u64,
    pub repeated_bytes: u64,
    pub ledger: LedgerMetrics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompareSummary {
    pub logical_bytes: u64,
    pub manifest_object_id: String,
    pub newly_required_bytes: u64,
    pub part_count: usize,
    pub repeated_bytes: u64,
    pub reused_bytes: u64,
    pub unique_bytes: u64,
    pub unique_chunks: usize,
    pub ledger: LedgerMetrics,
}

struct ParsedManifest {
    ledger: Ledger,
    logical_length: u64,
    manifest_object_id: String,
    metadata: BTreeMap<ObjectRef, u64>,
    part_count: usize,
    unique_bytes: u64,
    whole_file_digest: [u8; 32],
}

fn map(value: &Cbor) -> Result<&[(Cbor, Cbor)], ChunkError> {
    match value {
        Cbor::Map(entries) => Ok(entries),
        _ => Err(ChunkError::ManifestMismatch),
    }
}

fn field(value: &Cbor, key: u64) -> Result<&Cbor, ChunkError> {
    map(value)?
        .iter()
        .find_map(|(candidate, value)| (candidate == &Cbor::UInt(key)).then_some(value))
        .ok_or(ChunkError::ManifestMismatch)
}

fn uint(value: &Cbor) -> Result<u64, ChunkError> {
    match value {
        Cbor::UInt(value) => Ok(*value),
        _ => Err(ChunkError::ManifestMismatch),
    }
}

fn array(value: &Cbor) -> Result<&[Cbor], ChunkError> {
    match value {
        Cbor::Array(values) => Ok(values),
        _ => Err(ChunkError::ManifestMismatch),
    }
}

fn whole_digest(value: &Cbor) -> Result<[u8; 32], ChunkError> {
    let entries = map(value)?;
    if entries.len() != 2 || uint(field(value, 0)?)? != 1 {
        return Err(ChunkError::ManifestMismatch);
    }
    match field(value, 1)? {
        Cbor::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| ChunkError::ManifestMismatch),
        _ => Err(ChunkError::ManifestMismatch),
    }
}

fn parse_manifest(manifest: &[u8], options: &VerifyOptions) -> Result<ParsedManifest, ChunkError> {
    if manifest.len() > options.max_manifest_bytes {
        return Err(ChunkError::ManifestMismatch);
    }
    let configured = Limits {
        max_input_bytes: options.max_manifest_bytes,
        max_value_bytes: options.max_manifest_bytes,
        max_nesting: Limits::METADATA.max_nesting,
        max_container_items: CHUNK_COUNT_MAXIMUM,
        max_working_bytes: options.max_decode_working_bytes.min(64 * 1024 * 1024),
    };

    // OGVCS-002 framing and known-schema validation intentionally happen
    // before the candidate Gear profile is interpreted.
    let scanned = scan_metadata(manifest, configured).map_err(|_| ChunkError::ManifestMismatch)?;
    let kind = validate_metadata_schema(&scanned).map_err(|_| ChunkError::ManifestMismatch)?;
    if kind != ObjectKind::ContentManifest {
        return Err(ChunkError::ManifestMismatch);
    }
    let digest = object_id(ObjectKind::ContentManifest, manifest)
        .map_err(|_| ChunkError::ManifestMismatch)?;
    let manifest_object_id = ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest,
    }
    .to_string();
    if options
        .expected_manifest_object_id
        .as_ref()
        .is_some_and(|expected| expected != &manifest_object_id)
    {
        return Err(ChunkError::ManifestMismatch);
    }

    let value = scanned.value();
    let profile = ProfileRef::from_cbor(field(value, 18)?)
        .map_err(|_| ChunkError::ManifestMismatch)?;
    if profile.to_string() != PROFILE {
        return Err(ChunkError::ProfileUnsupported);
    }
    let logical_length = uint(field(value, 16)?)?;
    if logical_length > LOGICAL_MAXIMUM {
        return Err(ChunkError::ManifestMismatch);
    }
    let whole_file_digest = whole_digest(field(value, 17)?)?;
    let parts = array(field(value, 19)?)?;
    if parts.len() > CHUNK_COUNT_MAXIMUM {
        return Err(ChunkError::ManifestMismatch);
    }

    let mut ledger = Ledger::new(options.ledger.clone())?;
    let mut metadata = BTreeMap::new();
    let mut logical = 0u64;
    let mut unique_bytes = 0u64;
    for raw in parts {
        if map(raw)?.len() != 2 {
            return Err(ChunkError::ManifestMismatch);
        }
        let reference = ObjectRef::from_cbor(field(raw, 0)?)
            .map_err(|_| ChunkError::ManifestMismatch)?;
        if reference.kind != ObjectKind::Chunk {
            return Err(ChunkError::ManifestMismatch);
        }
        let length = uint(field(raw, 1)?)?;
        if length == 0 || length > MAXIMUM as u64 {
            return Err(ChunkError::ManifestMismatch);
        }
        if let Some(previous) = metadata.get(&reference) {
            if *previous != length {
                return Err(ChunkError::MetadataConflict);
            }
        } else {
            let next_entries = metadata.len() as u64 + 1;
            if next_entries
                .checked_mul(INDEX_ENTRY_BYTES)
                .is_none_or(|bytes| bytes > options.max_index_memory_bytes)
            {
                return Err(ChunkError::ResourceExhausted);
            }
            metadata.insert(reference, length);
            unique_bytes = unique_bytes
                .checked_add(length)
                .ok_or(ChunkError::ManifestMismatch)?;
        }
        logical = logical
            .checked_add(length)
            .filter(|value| *value <= LOGICAL_MAXIMUM)
            .ok_or(ChunkError::ManifestMismatch)?;
        ledger.append(LedgerRecord {
            digest: reference.digest,
            length,
            boundary: logical,
        })?;
    }
    if logical != logical_length || (logical_length == 0 && !parts.is_empty()) {
        return Err(ChunkError::ManifestMismatch);
    }
    Ok(ParsedManifest {
        ledger,
        logical_length,
        manifest_object_id,
        metadata,
        part_count: parts.len(),
        unique_bytes,
        whole_file_digest,
    })
}

struct GearScanner {
    table: [u64; 256],
    fingerprint: u64,
    current_length: usize,
    consumed: u64,
    last_boundary: u64,
    logical_length: u64,
}

impl GearScanner {
    fn new(logical_length: u64) -> Self {
        Self {
            table: gear_table(),
            fingerprint: 0,
            current_length: 0,
            consumed: 0,
            last_boundary: 0,
            logical_length,
        }
    }

    fn update(&mut self, bytes: &[u8], mut boundary: impl FnMut(u64)) {
        for &byte in bytes {
            self.consumed += 1;
            self.current_length += 1;
            if self.logical_length <= SMALL_MAXIMUM {
                continue;
            }
            self.fingerprint = self
                .fingerprint
                .wrapping_shl(1)
                .wrapping_add(self.table[byte as usize]);
            if self.current_length >= MINIMUM {
                let mask = if self.current_length < TARGET {
                    EARLY_MASK
                } else {
                    LATE_MASK
                };
                if self.fingerprint & mask == 0 || self.current_length == MAXIMUM {
                    self.last_boundary = self.consumed;
                    boundary(self.consumed);
                    self.fingerprint = 0;
                    self.current_length = 0;
                }
            }
        }
    }
}

fn consume_content<S: ChunkSource>(
    parsed: &mut ParsedManifest,
    source: &mut S,
    mut publish: impl FnMut(&[u8], usize) -> Result<(), ChunkError>,
) -> Result<VerifySummary, ChunkError> {
    let mut whole = Sha256Writer::new();
    let mut scanner = GearScanner::new(parsed.logical_length);
    let mut boundary_mismatch = parsed.logical_length <= SMALL_MAXIMUM
        && parsed.part_count != if parsed.logical_length == 0 { 0 } else { 1 };
    let mut content_bytes = 0u64;
    let mut provider_reads = 0usize;
    let mut occurrence = 0usize;
    let logical_length = parsed.logical_length;
    let part_count = parsed.part_count;

    parsed.ledger.for_each(|record| {
        let part = ManifestPart {
            reference: ObjectRef {
                kind: ObjectKind::Chunk,
                digest: record.digest,
            },
            length: record.length,
        };
        let mut chunk_hash = ObjectHashWriter::new(
            ObjectKind::Chunk,
            MAXIMUM,
            options_metadata_maximum(),
        );
        let mut part_bytes = 0u64;
        provider_reads += 1;
        source.stream_chunk(&part, occurrence, &mut |fragment| {
            if fragment.len() > 64 * 1024 * 1024 {
                return Err(ChunkError::SourceInvalid);
            }
            part_bytes = part_bytes
                .checked_add(fragment.len() as u64)
                .filter(|bytes| *bytes <= record.length)
                .ok_or(ChunkError::DigestMismatch)?;
            content_bytes = content_bytes
                .checked_add(fragment.len() as u64)
                .ok_or(ChunkError::DigestMismatch)?;
            chunk_hash
                .update(fragment)
                .map_err(|_| ChunkError::DigestMismatch)?;
            whole.update(fragment);
            scanner.update(fragment, |boundary| {
                if boundary != record.boundary {
                    boundary_mismatch = true;
                }
            });
            publish(fragment, occurrence)
        })?;
        let actual = chunk_hash.finish().map_err(|_| ChunkError::DigestMismatch)?;
        if part_bytes != record.length || actual != part.reference {
            return Err(ChunkError::DigestMismatch);
        }
        if logical_length > SMALL_MAXIMUM
            && occurrence + 1 < part_count
            && scanner.last_boundary != record.boundary
        {
            boundary_mismatch = true;
        }
        occurrence += 1;
        Ok(())
    })?;

    if content_bytes != parsed.logical_length || whole.finish() != parsed.whole_file_digest {
        return Err(ChunkError::DigestMismatch);
    }
    if boundary_mismatch {
        return Err(ChunkError::BoundaryMismatch);
    }
    Ok(VerifySummary {
        logical_bytes: parsed.logical_length,
        manifest_object_id: parsed.manifest_object_id.clone(),
        part_count: parsed.part_count,
        provider_reads,
        unique_bytes: parsed.unique_bytes,
        repeated_bytes: parsed.logical_length - parsed.unique_bytes,
        ledger: parsed.ledger.metrics(),
    })
}

const fn options_metadata_maximum() -> usize {
    64 * 1024 * 1024
}

pub fn verify_manifest<S: ChunkSource>(
    manifest: &[u8],
    source: &mut S,
    options: &VerifyOptions,
) -> Result<VerifySummary, ChunkError> {
    let mut parsed = parse_manifest(manifest, options)?;
    consume_content(&mut parsed, source, |_bytes, _occurrence| Ok(()))
}

pub fn reconstruct_manifest<S: ChunkSource, P: TransactionalPublication>(
    manifest: &[u8],
    source: &mut S,
    publication: &mut P,
    options: &VerifyOptions,
) -> Result<VerifySummary, ChunkError> {
    let mut parsed = parse_manifest(manifest, options)?;
    let mut started = false;
    let verified = consume_content(&mut parsed, source, |bytes, occurrence| {
        started = true;
        publication
            .write(bytes, occurrence)
            .map_err(|_| ChunkError::PublicationFailed)
    });
    match verified {
        Ok(summary) => match publication.commit() {
            Ok(()) => Ok(summary),
            Err(_) => {
                let error = ChunkError::PublicationFailed;
                if started {
                    let _ = publication.abort(error);
                }
                Err(error)
            }
        },
        Err(error) => {
            if started {
                let _ = publication.abort(error);
            }
            Err(error)
        }
    }
}

pub fn compare_manifest<K: KnownChunkIndex>(
    manifest: &[u8],
    known: &mut K,
    options: &VerifyOptions,
) -> Result<CompareSummary, ChunkError> {
    let parsed = parse_manifest(manifest, options)?;
    let mut reused_bytes = 0u64;
    for (reference, length) in &parsed.metadata {
        if let Some(known_length) = known.known_length(reference)? {
            if known_length != *length {
                return Err(ChunkError::MetadataConflict);
            }
            reused_bytes = reused_bytes
                .checked_add(*length)
                .ok_or(ChunkError::MetadataConflict)?;
        }
    }
    Ok(CompareSummary {
        logical_bytes: parsed.logical_length,
        manifest_object_id: parsed.manifest_object_id,
        newly_required_bytes: parsed.unique_bytes - reused_bytes,
        part_count: parsed.part_count,
        repeated_bytes: parsed.logical_length - parsed.unique_bytes,
        reused_bytes,
        unique_bytes: parsed.unique_bytes,
        unique_chunks: parsed.metadata.len(),
        ledger: parsed.ledger.metrics(),
    })
}
