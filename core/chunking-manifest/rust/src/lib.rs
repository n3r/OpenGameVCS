#![forbid(unsafe_code)]

mod ledger;
mod verify;

pub use ledger::{LedgerMetrics, LedgerOptions, LEDGER_RECORD_BYTES};
pub use verify::{
    compare_manifest, reconstruct_manifest, verify_manifest, ChunkSource, CompareSummary,
    KnownChunkIndex, ManifestPart, TransactionalPublication, VerifyOptions, VerifySummary,
};

use std::sync::OnceLock;

use ogvcs_object_model::{encode_canonical, object_id, sha256, Cbor, ObjectKind, ObjectRef, ProfileRef, Sha256Writer};
use ledger::{Ledger, LedgerRecord};

pub const PROFILE: &str = "chunking.opengamevcs/gear-fastcdc-1m@1";
pub const SMALL_MAXIMUM: u64 = 262_144;
pub const MINIMUM: usize = 262_144;
pub const TARGET: usize = 1_048_576;
pub const MAXIMUM: usize = 2_097_152;
pub const LOGICAL_MAXIMUM: u64 = 1_099_511_627_776;
pub const CHUNK_COUNT_MAXIMUM: usize = 1_048_576;
pub const SCALAR_WORKING_MINIMUM: u64 = 4_259_840;
pub const WORKING_MAXIMUM: u64 = 1_073_741_824;
const EARLY_MASK: u64 = 0x001f_ffff;
const LATE_MASK: u64 = 0x0007_ffff;
const TABLE_DOMAIN: &[u8] = b"OpenGameVCS Gear table v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChunkError {
    BoundaryMismatch,
    CountExceeded,
    DeclaredLengthInvalid,
    DigestMismatch,
    FingerprintInputInvalid,
    FragmentInvalid,
    ManifestMismatch,
    MetadataConflict,
    ProfileUnsupported,
    PublicationFailed,
    ResourceExhausted,
    ResourceInvalid,
    ResourceUnsupported,
    ScratchExhausted,
    SinkFailed,
    SinkInvalid,
    SourceInvalid,
    SourceMissing,
    SourceTooLong,
    SourceTooShort,
    SessionFailed,
    SessionFinished,
}

impl ChunkError {
    pub const ALL: [Self; 22] = [
        Self::BoundaryMismatch, Self::CountExceeded, Self::DeclaredLengthInvalid,
        Self::DigestMismatch, Self::FingerprintInputInvalid, Self::FragmentInvalid,
        Self::ManifestMismatch, Self::MetadataConflict, Self::ProfileUnsupported,
        Self::PublicationFailed, Self::ResourceExhausted, Self::ResourceInvalid,
        Self::ResourceUnsupported, Self::ScratchExhausted, Self::SessionFailed,
        Self::SessionFinished, Self::SinkFailed, Self::SinkInvalid, Self::SourceInvalid,
        Self::SourceMissing, Self::SourceTooLong, Self::SourceTooShort,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::BoundaryMismatch => "CHUNK_BOUNDARY_MISMATCH",
            Self::CountExceeded => "CHUNK_COUNT_EXCEEDED",
            Self::DeclaredLengthInvalid => "CHUNK_DECLARED_LENGTH_INVALID",
            Self::DigestMismatch => "CHUNK_DIGEST_MISMATCH",
            Self::FingerprintInputInvalid => "CHUNK_FINGERPRINT_INPUT_INVALID",
            Self::FragmentInvalid => "CHUNK_FRAGMENT_INVALID",
            Self::ManifestMismatch => "CHUNK_MANIFEST_MISMATCH",
            Self::MetadataConflict => "CHUNK_METADATA_CONFLICT",
            Self::ProfileUnsupported => "CHUNK_PROFILE_UNSUPPORTED",
            Self::PublicationFailed => "CHUNK_PUBLICATION_FAILED",
            Self::ResourceExhausted => "CHUNK_RESOURCE_EXHAUSTED",
            Self::ResourceInvalid => "CHUNK_RESOURCE_INVALID",
            Self::ResourceUnsupported => "CHUNK_RESOURCE_UNSUPPORTED",
            Self::ScratchExhausted => "CHUNK_SCRATCH_EXHAUSTED",
            Self::SessionFailed => "CHUNK_SESSION_FAILED",
            Self::SessionFinished => "CHUNK_SESSION_FINISHED",
            Self::SinkFailed => "CHUNK_SINK_FAILED",
            Self::SinkInvalid => "CHUNK_SINK_INVALID",
            Self::SourceInvalid => "CHUNK_SOURCE_INVALID",
            Self::SourceMissing => "CHUNK_SOURCE_MISSING",
            Self::SourceTooLong => "CHUNK_SOURCE_TOO_LONG",
            Self::SourceTooShort => "CHUNK_SOURCE_TOO_SHORT",
        }
    }
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ChunkError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkPart {
    pub digest: [u8; 32],
    pub length: u64,
    pub object_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Manifest {
    pub bytes: Vec<u8>,
    pub object_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkResult {
    pub boundaries: Vec<u64>,
    pub class: &'static str,
    pub logical_length: u64,
    pub parts: Vec<ChunkPart>,
    pub whole_file_digest: [u8; 32],
    pub manifest: Manifest,
    pub ledger: LedgerMetrics,
}

fn shared_gear_table() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u64; 256];
        for (index, slot) in table.iter_mut().enumerate() {
            let mut preimage = Vec::with_capacity(TABLE_DOMAIN.len() + 2);
            preimage.extend_from_slice(TABLE_DOMAIN);
            preimage.extend_from_slice(&(index as u16).to_be_bytes());
            *slot = u64::from_be_bytes(sha256(&preimage)[..8].try_into().expect("eight bytes"));
        }
        table
    })
}

pub fn gear_table() -> [u64; 256] {
    *shared_gear_table()
}

pub fn gear_table_sha256() -> [u8; 32] {
    let mut bytes = Vec::with_capacity(256 * 8);
    for value in gear_table() {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    sha256(&bytes)
}

pub struct Chunker<F>
where
    F: FnMut(&[u8], &ChunkPart, usize) -> Result<(), ChunkError>,
{
    declared_length: u64,
    consumed: u64,
    fingerprint: u64,
    current: Vec<u8>,
    ledger: Ledger,
    retain_entries: bool,
    table: &'static [u64; 256],
    whole: Sha256Writer,
    sink: F,
    failed: bool,
}

impl<F> Chunker<F>
where
    F: FnMut(&[u8], &ChunkPart, usize) -> Result<(), ChunkError>,
{
    pub fn new(declared_length: u64, profile: &str, sink: F) -> Result<Self, ChunkError> {
        Self::new_with_resources(declared_length, profile, 1, 0, SCALAR_WORKING_MINIMUM, sink)
    }

    pub fn new_bounded(
        declared_length: u64,
        profile: &str,
        ledger_options: LedgerOptions,
        sink: F,
    ) -> Result<Self, ChunkError> {
        Self::new_with_ledger_resources(
            declared_length,
            profile,
            1,
            0,
            SCALAR_WORKING_MINIMUM,
            ledger_options,
            false,
            sink,
        )
    }

    pub fn new_with_resources(
        declared_length: u64,
        profile: &str,
        workers: u32,
        queued_chunks: u32,
        max_working_memory_bytes: u64,
        sink: F,
    ) -> Result<Self, ChunkError> {
        Self::new_with_ledger_resources(
            declared_length,
            profile,
            workers,
            queued_chunks,
            max_working_memory_bytes,
            LedgerOptions::default(),
            true,
            sink,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ledger_resources(
        declared_length: u64,
        profile: &str,
        workers: u32,
        queued_chunks: u32,
        max_working_memory_bytes: u64,
        ledger_options: LedgerOptions,
        retain_entries: bool,
        sink: F,
    ) -> Result<Self, ChunkError> {
        if declared_length > LOGICAL_MAXIMUM {
            return Err(ChunkError::DeclaredLengthInvalid);
        }
        if profile != PROFILE {
            return Err(ChunkError::ProfileUnsupported);
        }
        if workers != 1 || queued_chunks != 0 {
            return Err(ChunkError::ResourceUnsupported);
        }
        if max_working_memory_bytes < SCALAR_WORKING_MINIMUM {
            return Err(ChunkError::ResourceExhausted);
        }
        if max_working_memory_bytes > WORKING_MAXIMUM {
            return Err(ChunkError::ResourceInvalid);
        }
        let ledger = Ledger::new(ledger_options)?;
        Ok(Self {
            declared_length,
            consumed: 0,
            fingerprint: 0,
            current: Vec::with_capacity((declared_length.min(MAXIMUM as u64)) as usize),
            ledger,
            retain_entries,
            table: shared_gear_table(),
            whole: Sha256Writer::new(),
            sink,
            failed: false,
        })
    }

    fn emit(&mut self) -> Result<(), ChunkError> {
        if self.ledger.len() >= CHUNK_COUNT_MAXIMUM as u64 {
            return Err(ChunkError::CountExceeded);
        }
        let digest = object_id(ObjectKind::Chunk, &self.current).map_err(|_| ChunkError::SessionFailed)?;
        let part = ChunkPart {
            digest,
            length: self.current.len() as u64,
            object_id: object_text(ObjectKind::Chunk, digest),
        };
        let index = self.ledger.len() as usize;
        self.ledger.append(LedgerRecord {
            digest: part.digest,
            length: part.length,
            boundary: self.consumed,
        })?;
        (self.sink)(&self.current, &part, index).map_err(|_| ChunkError::SinkFailed)?;
        self.current.clear();
        self.fingerprint = 0;
        Ok(())
    }

    pub fn update(&mut self, fragment: &[u8]) -> Result<u64, ChunkError> {
        if self.failed {
            return Err(ChunkError::SessionFailed);
        }
        if fragment.len() > 64 * 1024 * 1024 {
            self.failed = true;
            self.ledger.cleanup();
            return Err(ChunkError::FragmentInvalid);
        }
        if self.consumed.saturating_add(fragment.len() as u64) > self.declared_length {
            self.failed = true;
            self.ledger.cleanup();
            return Err(ChunkError::SourceTooLong);
        }
        self.whole.update(fragment);
        for &byte in fragment {
            self.current.push(byte);
            self.consumed += 1;
            if self.declared_length > SMALL_MAXIMUM {
                self.fingerprint = self.fingerprint.wrapping_shl(1).wrapping_add(self.table[byte as usize]);
                let length = self.current.len();
                if length >= MINIMUM {
                    let mask = if length < TARGET { EARLY_MASK } else { LATE_MASK };
                    if self.fingerprint & mask == 0 || length == MAXIMUM {
                        if let Err(error) = self.emit() {
                            self.failed = true;
                            self.ledger.cleanup();
                            return Err(error);
                        }
                    }
                }
            }
        }
        Ok(self.consumed)
    }

    pub fn finish(mut self) -> Result<ChunkResult, ChunkError> {
        if self.failed {
            return Err(ChunkError::SessionFailed);
        }
        if self.consumed != self.declared_length {
            return Err(ChunkError::SourceTooShort);
        }
        if !self.current.is_empty() {
            self.emit()?;
        }
        let whole_file_digest = self.whole.finish();
        let manifest_bytes = encode_manifest(self.declared_length, whole_file_digest, &mut self.ledger)?;
        let manifest_digest = object_id(ObjectKind::ContentManifest, &manifest_bytes).map_err(|_| ChunkError::SessionFailed)?;
        let ledger_metrics = self.ledger.metrics();
        let mut boundaries = Vec::new();
        let mut parts = Vec::new();
        if self.retain_entries {
            self.ledger.for_each(|record| {
                boundaries.push(record.boundary);
                parts.push(ChunkPart {
                    digest: record.digest,
                    length: record.length,
                    object_id: object_text(ObjectKind::Chunk, record.digest),
                });
                Ok(())
            })?;
        }
        Ok(ChunkResult {
            boundaries,
            class: if self.declared_length == 0 { "empty" } else if self.declared_length <= SMALL_MAXIMUM { "whole" } else { "cdc-1m" },
            logical_length: self.declared_length,
            parts,
            whole_file_digest,
            manifest: Manifest { bytes: manifest_bytes, object_id: object_text(ObjectKind::ContentManifest, manifest_digest) },
            ledger: ledger_metrics,
        })
    }
}

pub fn chunk_bytes<F>(bytes: &[u8], sink: F) -> Result<ChunkResult, ChunkError>
where
    F: FnMut(&[u8], &ChunkPart, usize) -> Result<(), ChunkError>,
{
    let mut chunker = Chunker::new(bytes.len() as u64, PROFILE, sink)?;
    chunker.update(bytes)?;
    chunker.finish()
}

fn object_text(kind: ObjectKind, digest: [u8; 32]) -> String {
    let mut text = format!("ogvcs:v1:{}:sha256:", kind.token());
    for byte in digest {
        use std::fmt::Write;
        write!(&mut text, "{byte:02x}").expect("string write");
    }
    text
}

fn cbor_array_header(length: u64) -> Result<Vec<u8>, ChunkError> {
    let marker = 4u8 << 5;
    Ok(if length < 24 {
        vec![marker | length as u8]
    } else if length <= u8::MAX as u64 {
        vec![marker | 24, length as u8]
    } else if length <= u16::MAX as u64 {
        let mut bytes = vec![marker | 25];
        bytes.extend_from_slice(&(length as u16).to_be_bytes());
        bytes
    } else if length <= u32::MAX as u64 {
        let mut bytes = vec![marker | 26];
        bytes.extend_from_slice(&(length as u32).to_be_bytes());
        bytes
    } else {
        return Err(ChunkError::CountExceeded);
    })
}

fn append_canonical(output: &mut Vec<u8>, value: &Cbor) -> Result<(), ChunkError> {
    output.extend_from_slice(&encode_canonical(value).map_err(|_| ChunkError::SessionFailed)?);
    Ok(())
}

fn encode_manifest(logical_length: u64, whole: [u8; 32], ledger: &mut Ledger) -> Result<Vec<u8>, ChunkError> {
    let profile = ProfileRef::new("chunking.opengamevcs", "gear-fastcdc-1m", 1)
        .map_err(|_| ChunkError::SessionFailed)?;
    let mut output = Vec::new();
    output.push(0xa7);
    for value in [
        Cbor::UInt(0), Cbor::UInt(1),
        Cbor::UInt(1), Cbor::UInt(ObjectKind::ContentManifest.code().into()),
        Cbor::UInt(2), Cbor::Array(Vec::new()),
        Cbor::UInt(16), Cbor::UInt(logical_length),
        Cbor::UInt(17), Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::Bytes(whole.to_vec())),
        ]),
        Cbor::UInt(18), profile.to_cbor(), Cbor::UInt(19),
    ] {
        append_canonical(&mut output, &value)?;
    }
    output.extend_from_slice(&cbor_array_header(ledger.len())?);
    ledger.for_each(|record| {
        append_canonical(&mut output, &Cbor::Map(vec![
            (Cbor::UInt(0), ObjectRef {
                kind: ObjectKind::Chunk,
                digest: record.digest,
            }.to_cbor()),
            (Cbor::UInt(1), Cbor::UInt(record.length)),
        ]))
    })?;
    Ok(output)
}
