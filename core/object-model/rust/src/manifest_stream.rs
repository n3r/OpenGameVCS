use std::{
    io::Write,
    time::{Duration, Instant},
};

use crate::{
    hard_limits::{
        enforce_hard_limit_context, MAX_CHUNK_BYTES, MAX_LOGICAL_FILE_BYTES, MAX_MANIFEST_CHUNKS,
        MAX_METADATA_BYTES,
    },
    Error, ErrorCode, ObjectHashWriter, ObjectKind, ObjectRef, Operation, ProfileRef, Registry,
    RegistryAssignment, Result, Sha256Writer, ValidationStage,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestStreamPart {
    pub chunk: ObjectRef,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestStreamLimits {
    pub max_parts: u64,
    pub max_output_bytes: u64,
    pub max_logical_bytes: u64,
    pub max_chunk_bytes: u64,
    /// Largest single source slice accepted by the verifier. The verifier
    /// never retains source slices or complete chunk payloads.
    pub max_memory_bytes: usize,
    pub max_elapsed: Option<Duration>,
}

impl Default for ManifestStreamLimits {
    fn default() -> Self {
        Self {
            max_parts: MAX_MANIFEST_CHUNKS,
            max_output_bytes: MAX_METADATA_BYTES,
            max_logical_bytes: MAX_LOGICAL_FILE_BYTES,
            max_chunk_bytes: MAX_CHUNK_BYTES,
            max_memory_bytes: 8 * 1024 * 1024,
            max_elapsed: None,
        }
    }
}

impl ManifestStreamLimits {
    fn constrained(self) -> Self {
        Self {
            max_parts: self.max_parts.min(MAX_MANIFEST_CHUNKS),
            max_output_bytes: self.max_output_bytes.min(MAX_METADATA_BYTES),
            max_logical_bytes: self.max_logical_bytes.min(MAX_LOGICAL_FILE_BYTES),
            max_chunk_bytes: self.max_chunk_bytes.min(MAX_CHUNK_BYTES),
            ..self
        }
    }
}

/// Contains only counts, lengths, and durable digests. Source bytes are never
/// retained or included in diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestStreamSummary {
    pub object_ref: ObjectRef,
    pub parts: u64,
    pub payload_bytes: u64,
    pub logical_bytes: u64,
    pub whole_file_digest: [u8; 32],
}

/// Supplies a chunk as one or more borrowed slices. Implementations may reuse
/// one fixed buffer for every part; the verifier consumes each slice before
/// `stream_chunk` continues.
pub trait ManifestChunkSource {
    fn stream_chunk(
        &mut self,
        part_index: u64,
        part: &ManifestStreamPart,
        consume: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()>;
}

impl<F> ManifestChunkSource for F
where
    F: FnMut(u64, &ManifestStreamPart, &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>,
{
    fn stream_chunk(
        &mut self,
        part_index: u64,
        part: &ManifestStreamPart,
        consume: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self(part_index, part, consume)
    }
}

struct Budget {
    limits: ManifestStreamLimits,
    started: Instant,
}

impl Budget {
    fn new(limits: ManifestStreamLimits) -> Result<Self> {
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
        manifest_limit(
            "manifest-chunks",
            count,
            self.limits.max_parts,
            ErrorCode::LimitCount,
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
                ObjectKind::ContentManifest,
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
        manifest_limit(
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

struct ContentPass {
    logical_bytes: u64,
    whole_file_digest: [u8; 32],
    part_transcript: [u8; 32],
}

struct PartPass {
    logical_bytes: u64,
    part_transcript: [u8; 32],
}

/// Preflights the lightweight part iterator, streams every referenced byte
/// once, derives the whole-file digest, then replays the iterator to emit a
/// canonical `ContentManifestV1`. The factory must return the same ordered
/// parts on all three calls.
#[allow(clippy::too_many_arguments)]
pub fn encode_content_manifest_stream<W, F, I, S>(
    writer: W,
    declared_parts: u64,
    parts_factory: F,
    chunk_profile: &ProfileRef,
    source: &mut S,
    registry: &Registry,
    operation: Operation,
    limits: ManifestStreamLimits,
) -> Result<ManifestStreamSummary>
where
    W: Write,
    F: FnMut() -> I,
    I: IntoIterator<Item = ManifestStreamPart>,
    S: ManifestChunkSource + ?Sized,
{
    encode_manifest_internal(
        writer,
        declared_parts,
        parts_factory,
        chunk_profile,
        source,
        registry,
        operation,
        limits,
        None,
    )
}

/// As [`encode_content_manifest_stream`], additionally requiring an exact
/// caller-declared logical length and whole-file SHA-256 digest.
#[allow(clippy::too_many_arguments)]
pub fn encode_and_verify_content_manifest_stream<W, F, I, S>(
    writer: W,
    declared_parts: u64,
    parts_factory: F,
    chunk_profile: &ProfileRef,
    expected_logical_bytes: u64,
    expected_whole_file_digest: [u8; 32],
    source: &mut S,
    registry: &Registry,
    operation: Operation,
    limits: ManifestStreamLimits,
) -> Result<ManifestStreamSummary>
where
    W: Write,
    F: FnMut() -> I,
    I: IntoIterator<Item = ManifestStreamPart>,
    S: ManifestChunkSource + ?Sized,
{
    encode_manifest_internal(
        writer,
        declared_parts,
        parts_factory,
        chunk_profile,
        source,
        registry,
        operation,
        limits,
        Some((expected_logical_bytes, expected_whole_file_digest)),
    )
}

#[allow(clippy::too_many_arguments)]
fn encode_manifest_internal<W, F, I, S>(
    writer: W,
    declared_parts: u64,
    mut parts_factory: F,
    chunk_profile: &ProfileRef,
    source: &mut S,
    registry: &Registry,
    operation: Operation,
    limits: ManifestStreamLimits,
    expected: Option<(u64, [u8; 32])>,
) -> Result<ManifestStreamSummary>
where
    W: Write,
    F: FnMut() -> I,
    I: IntoIterator<Item = ManifestStreamPart>,
    S: ManifestChunkSource + ?Sized,
{
    let budget = Budget::new(limits)?;
    budget.check_count(declared_parts)?;
    validate_manifest_assignments(registry, operation)?;
    validate_chunk_profile(chunk_profile, registry, operation)?;
    if let Some((logical, _)) = expected {
        manifest_limit(
            "logical-file-bytes",
            logical,
            budget.limits.max_logical_bytes,
            ErrorCode::LimitLogicalBytes,
            2,
        )?;
    }

    let preflight = preflight_parts(declared_parts, parts_factory(), &budget)?;
    if expected.is_some_and(|(expected_length, _)| expected_length != preflight.logical_bytes) {
        return Err(Error::new(ErrorCode::ManifestLengthMismatch));
    }
    let pass = verify_content(declared_parts, parts_factory(), source, &budget)?;
    if pass.logical_bytes != preflight.logical_bytes
        || pass.part_transcript != preflight.part_transcript
    {
        return Err(Error::new(ErrorCode::ManifestLengthMismatch));
    }
    if let Some((expected_length, expected_digest)) = expected {
        if pass.logical_bytes != expected_length {
            return Err(Error::new(ErrorCode::ManifestLengthMismatch));
        }
        if pass.whole_file_digest != expected_digest {
            return Err(Error::new(ErrorCode::ManifestFileDigestMismatch));
        }
    }

    budget.check_time()?;
    let mut sink = CanonicalSink::new(writer, budget.limits.max_output_bytes);
    sink.head(5, 7)?;
    sink.head(0, 0)?;
    sink.head(0, 1)?;
    sink.head(0, 1)?;
    sink.head(0, 2)?;
    sink.head(0, 2)?;
    sink.head(4, 0)?;
    sink.head(0, 16)?;
    sink.head(0, pass.logical_bytes)?;
    sink.head(0, 17)?;
    write_typed_digest(&mut sink, &pass.whole_file_digest)?;
    sink.head(0, 18)?;
    write_profile(&mut sink, chunk_profile)?;
    sink.head(0, 19)?;
    sink.head(4, declared_parts)?;

    let mut second_count = 0u64;
    let mut second_logical = 0u64;
    let mut second_transcript = Sha256Writer::new();
    for part in parts_factory() {
        budget.check_time()?;
        second_count = second_count
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        if second_count > declared_parts {
            return Err(Error::new(ErrorCode::LimitCount));
        }
        validate_part(&part, &budget)?;
        second_logical = add_logical(second_logical, part.length, &budget)?;
        let encoded = encode_part(&part);
        second_transcript.update(&encoded);
        sink.bytes(&encoded)?;
    }
    if second_count != declared_parts {
        return Err(Error::new(ErrorCode::LimitCount));
    }
    if second_logical != pass.logical_bytes || second_transcript.finish() != pass.part_transcript {
        return Err(Error::new(ErrorCode::ManifestLengthMismatch));
    }

    let (object_ref, payload_bytes) = sink.finish()?;
    Ok(ManifestStreamSummary {
        object_ref,
        parts: declared_parts,
        payload_bytes,
        logical_bytes: pass.logical_bytes,
        whole_file_digest: pass.whole_file_digest,
    })
}

fn preflight_parts<I>(declared_parts: u64, parts: I, budget: &Budget) -> Result<PartPass>
where
    I: IntoIterator<Item = ManifestStreamPart>,
{
    let mut count = 0u64;
    let mut logical_bytes = 0u64;
    let mut transcript = Sha256Writer::new();
    for part in parts {
        budget.check_time()?;
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        if count > declared_parts {
            return Err(Error::new(ErrorCode::LimitCount));
        }
        validate_part(&part, budget)?;
        logical_bytes = add_logical(logical_bytes, part.length, budget)?;
        transcript.update(&encode_part(&part));
    }
    if count != declared_parts {
        return Err(Error::new(ErrorCode::LimitCount));
    }
    Ok(PartPass {
        logical_bytes,
        part_transcript: transcript.finish(),
    })
}

fn verify_content<I, S>(
    declared_parts: u64,
    parts: I,
    source: &mut S,
    budget: &Budget,
) -> Result<ContentPass>
where
    I: IntoIterator<Item = ManifestStreamPart>,
    S: ManifestChunkSource + ?Sized,
{
    let mut count = 0u64;
    let mut logical_bytes = 0u64;
    let mut whole_file = Sha256Writer::new();
    let mut transcript = Sha256Writer::new();
    for part in parts {
        budget.check_time()?;
        let part_index = count;
        count = count
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorCode::LimitCount))?;
        if count > declared_parts {
            return Err(Error::new(ErrorCode::LimitCount));
        }
        validate_part(&part, budget)?;
        logical_bytes = add_logical(logical_bytes, part.length, budget)?;
        transcript.update(&encode_part(&part));

        let mut emitted = 0u64;
        let mut chunk_hash = ObjectHashWriter::new(
            ObjectKind::Chunk,
            MAX_CHUNK_BYTES as usize,
            MAX_METADATA_BYTES as usize,
        );
        let mut consume = |bytes: &[u8]| -> Result<()> {
            budget.check_time()?;
            if bytes.len() > budget.limits.max_memory_bytes {
                return Err(Error::new(ErrorCode::LimitMemory));
            }
            let length = u64::try_from(bytes.len())
                .map_err(|_| Error::new(ErrorCode::ManifestChunkLengthInvalid))?;
            emitted = emitted
                .checked_add(length)
                .ok_or_else(|| Error::new(ErrorCode::ManifestChunkLengthInvalid))?;
            if emitted > part.length {
                return Err(Error::new(ErrorCode::ManifestChunkLengthInvalid));
            }
            chunk_hash.update(bytes)?;
            whole_file.update(bytes);
            Ok(())
        };
        source.stream_chunk(part_index, &part, &mut consume)?;
        if emitted != part.length {
            return Err(Error::new(ErrorCode::ManifestChunkLengthInvalid));
        }
        if chunk_hash.finish()? != part.chunk {
            return Err(Error::new(ErrorCode::ObjectIdMismatch));
        }
    }
    if count != declared_parts {
        return Err(Error::new(ErrorCode::LimitCount));
    }
    Ok(ContentPass {
        logical_bytes,
        whole_file_digest: whole_file.finish(),
        part_transcript: transcript.finish(),
    })
}

fn validate_part(part: &ManifestStreamPart, budget: &Budget) -> Result<()> {
    if part.chunk.kind != ObjectKind::Chunk {
        return Err(Error::new(ErrorCode::ObjectReferenceKindMismatch)
            .with_stage(ValidationStage::KnownSchema));
    }
    if part.length == 0 {
        return Err(Error::new(ErrorCode::ManifestChunkLengthInvalid));
    }
    manifest_limit(
        "chunk-payload-bytes",
        part.length,
        budget.limits.max_chunk_bytes,
        ErrorCode::ManifestChunkLengthInvalid,
        2,
    )?;
    Ok(())
}

fn add_logical(current: u64, length: u64, budget: &Budget) -> Result<u64> {
    let sum = current
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorCode::LimitLogicalBytes))?;
    manifest_limit(
        "logical-file-bytes",
        sum,
        budget.limits.max_logical_bytes,
        ErrorCode::LimitLogicalBytes,
        2,
    )?;
    Ok(sum)
}

fn manifest_limit(
    name: &'static str,
    value: u64,
    configured: u64,
    code: ErrorCode,
    layer: u8,
) -> Result<()> {
    enforce_hard_limit_context(name, value, configured, code, layer).map(|_| ())
}

fn validate_chunk_profile(
    profile: &ProfileRef,
    registry: &Registry,
    operation: Operation,
) -> Result<()> {
    let entry = registry
        .profile(profile)
        .ok_or_else(|| Error::new(ErrorCode::ProfileUnknown))?;
    if entry.family != "chunking" {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    registry.check_profile(profile, "chunking", operation)
}

fn validate_manifest_assignments(registry: &Registry, operation: Operation) -> Result<()> {
    for assignment in [
        RegistryAssignment::ObjectKind(ObjectKind::ContentManifest.code()),
        RegistryAssignment::ObjectKind(ObjectKind::Chunk.code()),
        RegistryAssignment::HashAlgorithm(1),
        RegistryAssignment::CommonField(0),
        RegistryAssignment::CommonField(1),
        RegistryAssignment::CommonField(2),
    ] {
        registry.check_assignment_if_present(assignment, operation)?;
    }
    for (rule, fields) in [
        ("content-manifest", &[16, 17, 18, 19][..]),
        ("typed-digest", &[0, 1][..]),
        ("profile-ref", &[0, 1, 2][..]),
        ("chunk-part", &[0, 1][..]),
        ("object-ref", &[0, 1, 2, 3][..]),
    ] {
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

fn encode_part(part: &ManifestStreamPart) -> Vec<u8> {
    let mut output = Vec::with_capacity(56);
    push_head(&mut output, 5, 2);
    push_head(&mut output, 0, 0);
    push_object_ref(&mut output, part.chunk);
    push_head(&mut output, 0, 1);
    push_head(&mut output, 0, part.length);
    output
}

fn write_typed_digest<W: Write>(sink: &mut CanonicalSink<W>, digest: &[u8; 32]) -> Result<()> {
    sink.head(5, 2)?;
    sink.head(0, 0)?;
    sink.head(0, 1)?;
    sink.head(0, 1)?;
    sink.head(2, 32)?;
    sink.bytes(digest)
}

fn write_profile<W: Write>(sink: &mut CanonicalSink<W>, profile: &ProfileRef) -> Result<()> {
    sink.head(5, 3)?;
    sink.head(0, 0)?;
    sink.head(3, profile.namespace().len() as u64)?;
    sink.bytes(profile.namespace().as_bytes())?;
    sink.head(0, 1)?;
    sink.head(3, profile.id().len() as u64)?;
    sink.bytes(profile.id().as_bytes())?;
    sink.head(0, 2)?;
    sink.head(0, u64::from(profile.major()))
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
    push_head(output, 2, 32);
    output.extend_from_slice(&reference.digest);
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
