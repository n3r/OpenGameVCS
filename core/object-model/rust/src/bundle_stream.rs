use core::cmp::Ordering;
use std::io::Read;

use unicode_normalization::is_nfc;

use crate::{
    hard_limits::{
        enforce_hard_limit_context, MAX_BUNDLE_ITEM_BYTES, MAX_BUNDLE_SEQUENCE_BYTES,
        MAX_BUNDLE_TOTAL_ITEMS, MAX_CBOR_NESTING, MAX_CHUNK_BYTES, MAX_GENERIC_VALUE_BYTES,
        MAX_MANIFEST_CHUNKS, MAX_METADATA_BYTES,
    },
    unicode_age::is_unicode_15,
    Error, ErrorCode, Result, ValidationStage,
};

#[derive(Clone, Copy, Debug)]
pub struct BundleLimits {
    pub max_sequence_bytes: usize,
    pub max_item_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_value_bytes: usize,
    /// Aggregate capacity of canonical-map-key capture buffers. The scanner
    /// admits deterministic buffer growth before allocation and includes both
    /// active nested captures and the retained preceding key for each map.
    pub max_capture_bytes: usize,
    pub max_container_items: usize,
    pub max_nesting: usize,
    pub max_items: usize,
}

impl BundleLimits {
    pub const HARD: Self = Self {
        max_sequence_bytes: MAX_BUNDLE_SEQUENCE_BYTES as usize,
        max_item_bytes: MAX_BUNDLE_ITEM_BYTES as usize,
        max_chunk_bytes: MAX_CHUNK_BYTES as usize,
        max_metadata_bytes: MAX_METADATA_BYTES as usize,
        max_value_bytes: MAX_GENERIC_VALUE_BYTES as usize,
        max_capture_bytes: 64 * 1024 * 1024,
        max_container_items: MAX_MANIFEST_CHUNKS as usize,
        max_nesting: MAX_CBOR_NESTING as usize,
        max_items: MAX_BUNDLE_TOTAL_ITEMS as usize,
    };

    pub const fn constrained_by(self, configured: Self) -> Self {
        Self {
            max_sequence_bytes: min(self.max_sequence_bytes, configured.max_sequence_bytes),
            max_item_bytes: min(self.max_item_bytes, configured.max_item_bytes),
            max_chunk_bytes: min(self.max_chunk_bytes, configured.max_chunk_bytes),
            max_metadata_bytes: min(self.max_metadata_bytes, configured.max_metadata_bytes),
            max_value_bytes: min(self.max_value_bytes, configured.max_value_bytes),
            max_capture_bytes: min(self.max_capture_bytes, configured.max_capture_bytes),
            max_container_items: min(self.max_container_items, configured.max_container_items),
            max_nesting: min(self.max_nesting, configured.max_nesting),
            max_items: min(self.max_items, configured.max_items),
        }
    }
}

const fn min(a: usize, b: usize) -> usize {
    if a < b {
        a
    } else {
        b
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleItemInfo {
    pub index: usize,
    pub item_type: u16,
    pub offset: usize,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleSummary {
    pub items: usize,
    pub bytes: usize,
}

/// Bounded callbacks for a logical-bundle scan. Implementations must consume a
/// payload chunk during the callback; the scanner does not retain it.
pub trait BundleVisitor {
    fn bytes(&mut self, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }
    fn item_start(&mut self, _index: usize, _item_type: u16, _offset: usize) -> Result<()> {
        Ok(())
    }
    fn object_payload_start(
        &mut self,
        _index: usize,
        _kind: u16,
        _length: usize,
        _offset: usize,
    ) -> Result<()> {
        Ok(())
    }
    fn object_payload_chunk(&mut self, _index: usize, _kind: u16, _bytes: &[u8]) -> Result<()> {
        Ok(())
    }
    fn object_payload_end(&mut self, _index: usize, _kind: u16, _length: usize) -> Result<()> {
        Ok(())
    }
    fn item_end(&mut self, _info: BundleItemInfo) -> Result<()> {
        Ok(())
    }
}

pub fn visit_logical_bundle<R: Read, V: BundleVisitor>(
    input: R,
    visitor: &mut V,
    limits: BundleLimits,
) -> Result<BundleSummary> {
    visit_logical_bundle_inner(input, visitor, limits, false)
}

pub(crate) fn visit_logical_bundle_deferred_object_refs<R: Read, V: BundleVisitor>(
    input: R,
    visitor: &mut V,
    limits: BundleLimits,
) -> Result<BundleSummary> {
    visit_logical_bundle_inner(input, visitor, limits, true)
}

fn visit_logical_bundle_inner<R: Read, V: BundleVisitor>(
    input: R,
    visitor: &mut V,
    limits: BundleLimits,
    defer_object_ref_format: bool,
) -> Result<BundleSummary> {
    let limits = BundleLimits::HARD.constrained_by(limits);
    let mut reader = StreamReader::new(input, visitor, limits, defer_object_ref_format)?;
    let mut items = 0usize;
    while reader.has_more()? {
        enforce_at(
            "bundle-total-items",
            items.saturating_add(1),
            limits.max_items,
            ErrorCode::BundleBudgetExceeded,
            reader.offset,
        )?;
        bundle_item(&mut reader, items)?;
        items += 1;
    }
    Ok(BundleSummary {
        items,
        bytes: reader.offset,
    })
}

struct StreamReader<'a, R, V> {
    input: R,
    visitor: &'a mut V,
    limits: BundleLimits,
    offset: usize,
    item_start: usize,
    lookahead: Option<u8>,
    captures: Vec<Capture>,
    capture_capacity_bytes: usize,
    defer_object_ref_format: bool,
}

impl<'a, R: Read, V: BundleVisitor> StreamReader<'a, R, V> {
    fn new(
        input: R,
        visitor: &'a mut V,
        limits: BundleLimits,
        defer_object_ref_format: bool,
    ) -> Result<Self> {
        // The capture stack itself is a fixed, hard-bounded part of the
        // scanner resident base. Reserve it once so pushing a nested capture
        // never performs an unadmitted allocation.
        let mut captures = Vec::new();
        captures
            .try_reserve_exact(limits.max_nesting.saturating_add(2))
            .map_err(|_| Error::new(ErrorCode::LimitMemory))?;
        Ok(Self {
            input,
            visitor,
            limits,
            offset: 0,
            item_start: 0,
            lookahead: None,
            captures,
            capture_capacity_bytes: 0,
            defer_object_ref_format,
        })
    }

    fn has_more(&mut self) -> Result<bool> {
        if self.lookahead.is_some() {
            return Ok(true);
        }
        let mut byte = [0u8; 1];
        match self.input.read(&mut byte) {
            Ok(0) => Ok(false),
            Ok(_) => {
                self.lookahead = Some(byte[0]);
                Ok(true)
            }
            Err(_) => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        }
    }

    fn account(&mut self, bytes: &[u8]) -> Result<()> {
        enforce_at(
            "bundle-sequence-bytes",
            self.offset.saturating_add(bytes.len()),
            self.limits.max_sequence_bytes,
            ErrorCode::BundleBudgetExceeded,
            self.offset,
        )?;
        enforce_at(
            "bundle-largest-item-bytes",
            self.offset
                .saturating_sub(self.item_start)
                .saturating_add(bytes.len()),
            self.limits.max_item_bytes,
            ErrorCode::BundleBudgetExceeded,
            self.offset,
        )?;
        for index in 0..self.captures.len() {
            let old_length = self.captures[index].length;
            let new_length = old_length
                .checked_add(bytes.len())
                .ok_or_else(|| Error::at(ErrorCode::LimitValueBytes, self.offset).with_layer(1))?;
            if new_length > self.limits.max_value_bytes.saturating_add(16) {
                return Err(Error::at(ErrorCode::LimitValueBytes, self.offset).with_layer(1));
            }
            self.grow_capture(index, new_length)?;
            self.captures[index].bytes[old_length..new_length].copy_from_slice(bytes);
            self.captures[index].length = new_length;
        }
        self.visitor.bytes(bytes)?;
        self.offset += bytes.len();
        Ok(())
    }

    fn byte(&mut self) -> Result<u8> {
        if let Some(byte) = self.lookahead.take() {
            self.account(&[byte])?;
            return Ok(byte);
        }
        let mut byte = [0u8; 1];
        self.input
            .read_exact(&mut byte)
            .map_err(|_| Error::at(ErrorCode::CborTruncated, self.offset))?;
        self.account(&byte)?;
        Ok(byte[0])
    }

    fn take<F>(&mut self, mut length: usize, mut callback: F) -> Result<()>
    where
        F: FnMut(&mut V, &[u8]) -> Result<()>,
    {
        let mut buffer = [0u8; 65_536];
        let sequence_over = enforce_at(
            "bundle-sequence-bytes",
            self.offset.saturating_add(length),
            self.limits.max_sequence_bytes,
            ErrorCode::BundleBudgetExceeded,
            self.offset,
        )
        .is_err();
        let item_over = enforce_at(
            "bundle-largest-item-bytes",
            self.offset
                .saturating_sub(self.item_start)
                .saturating_add(length),
            self.limits.max_item_bytes,
            ErrorCode::BundleBudgetExceeded,
            self.offset,
        )
        .is_err();
        if sequence_over || item_over {
            return self.prove_declared_bytes_or_limit(
                length,
                ErrorCode::BundleBudgetExceeded,
                self.offset,
            );
        }
        while length != 0 {
            if let Some(byte) = self.lookahead.take() {
                self.account(&[byte])?;
                callback(self.visitor, &[byte])?;
                length -= 1;
                continue;
            }
            let take = length.min(buffer.len());
            self.input
                .read_exact(&mut buffer[..take])
                .map_err(|_| Error::at(ErrorCode::CborTruncated, self.offset))?;
            self.account(&buffer[..take])?;
            callback(self.visitor, &buffer[..take])?;
            length -= take;
        }
        Ok(())
    }

    /// A declared byte body that exceeds a configured ceiling is still
    /// physically framed first. Fixed-size draining proves whether the body is
    /// complete without retaining or visiting it: premature EOF wins as
    /// `CBOR_TRUNCATED`; a fully present over-limit body gets the saved limit.
    fn prove_declared_bytes_or_limit(
        &mut self,
        mut length: usize,
        code: ErrorCode,
        error_offset: usize,
    ) -> Result<()> {
        if self.lookahead.take().is_some() {
            length = length.saturating_sub(1);
        }
        let mut buffer = [0u8; 65_536];
        while length != 0 {
            let requested = length.min(buffer.len());
            match self.input.read(&mut buffer[..requested]) {
                Ok(0) => return Err(Error::at(ErrorCode::CborTruncated, self.offset)),
                Ok(read) => length -= read,
                Err(_) => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
            }
        }
        Err(Error::at(code, error_offset).with_layer(1))
    }

    fn take_plain(&mut self, length: usize) -> Result<()> {
        self.take(length, |_, _| Ok(()))
    }

    fn grow_capture(&mut self, index: usize, required: usize) -> Result<()> {
        let old_capacity = self.captures[index].bytes.len();
        if required <= old_capacity {
            return Ok(());
        }
        let mut new_capacity = old_capacity.max(64);
        while new_capacity < required {
            new_capacity = new_capacity.checked_mul(2).ok_or_else(|| {
                Error::at(ErrorCode::LimitMemory, self.offset)
                    .with_stage(ValidationStage::ConfiguredResourcePreflight)
            })?;
        }

        // The old allocation remains live until its bytes have been copied,
        // so admit the complete replacement capacity before allocating it.
        if new_capacity
            > self
                .limits
                .max_capture_bytes
                .saturating_sub(self.capture_capacity_bytes)
        {
            return Err(Error::at(ErrorCode::LimitMemory, self.offset)
                .with_stage(ValidationStage::ConfiguredResourcePreflight));
        }
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(new_capacity)
            .map_err(|_| Error::at(ErrorCode::LimitMemory, self.offset))?;
        replacement.resize(new_capacity, 0);
        replacement[..self.captures[index].length]
            .copy_from_slice(&self.captures[index].bytes[..self.captures[index].length]);
        let replacement = replacement.into_boxed_slice();
        let old = core::mem::replace(&mut self.captures[index].bytes, replacement);
        self.capture_capacity_bytes = self
            .capture_capacity_bytes
            .saturating_add(new_capacity)
            .saturating_sub(old_capacity);
        drop(old);
        Ok(())
    }

    fn capture_start(&mut self) -> Result<()> {
        if self.captures.len() == self.captures.capacity() {
            return Err(Error::at(ErrorCode::LimitMemory, self.offset)
                .with_stage(ValidationStage::ConfiguredResourcePreflight));
        }
        self.captures.push(Capture {
            bytes: Vec::new().into_boxed_slice(),
            length: 0,
        });
        Ok(())
    }

    fn capture_end(&mut self) -> Result<CapturedKey> {
        self.captures
            .pop()
            .map(|capture| CapturedKey {
                bytes: capture.bytes,
                length: capture.length,
            })
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))
    }

    fn release_capture(&mut self, capture: CapturedKey) {
        self.capture_capacity_bytes = self
            .capture_capacity_bytes
            .saturating_sub(capture.bytes.len());
        drop(capture);
    }
}

struct Capture {
    bytes: Box<[u8]>,
    length: usize,
}

struct CapturedKey {
    bytes: Box<[u8]>,
    length: usize,
}

impl CapturedKey {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[derive(Clone, Copy)]
struct Head {
    major: u8,
    value: u64,
    start: usize,
}

fn head<R: Read, V: BundleVisitor>(reader: &mut StreamReader<R, V>) -> Result<Head> {
    let start = reader.offset;
    let initial = reader.byte()?;
    let major = initial >> 5;
    let ai = initial & 31;
    if ai == 31 || major == 6 {
        return Err(Error::at(ErrorCode::CborNonCanonical, start));
    }
    if major == 7 {
        return match ai {
            20 | 21 => Ok(Head {
                major,
                value: u64::from(ai == 21),
                start,
            }),
            _ => Err(Error::at(ErrorCode::CborNonCanonical, start)),
        };
    }
    let value = match ai {
        0..=23 => ai as u64,
        24 => reader.byte()? as u64,
        25 => {
            let mut bytes = [0u8; 2];
            let mut offset = 0;
            reader.take(2, |_, part| {
                bytes[offset..offset + part.len()].copy_from_slice(part);
                offset += part.len();
                Ok(())
            })?;
            u16::from_be_bytes(bytes) as u64
        }
        26 => fixed_argument::<4, _, _>(reader)? as u64,
        27 => fixed_argument::<8, _, _>(reader)?,
        _ => return Err(Error::at(ErrorCode::CborNonCanonical, start)),
    };
    if (ai == 24 && value < 24)
        || (ai == 25 && value <= 0xff)
        || (ai == 26 && value <= 0xffff)
        || (ai == 27 && value <= 0xffff_ffff)
    {
        return Err(Error::at(ErrorCode::CborNonCanonical, start));
    }
    if major == 1 && value > i64::MAX as u64 {
        return Err(Error::at(ErrorCode::CborNonCanonical, start));
    }
    Ok(Head {
        major,
        value,
        start,
    })
}

fn fixed_argument<const N: usize, R: Read, V: BundleVisitor>(
    reader: &mut StreamReader<R, V>,
) -> Result<u64> {
    let mut bytes = [0u8; N];
    let mut offset = 0;
    reader.take(N, |_, part| {
        bytes[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
        Ok(())
    })?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(byte);
    }
    Ok(value)
}

fn enforce_at(
    name: &'static str,
    value: usize,
    configured: usize,
    code: ErrorCode,
    offset: usize,
) -> Result<()> {
    let at_site = |layer| {
        let error = Error::at(code, offset).with_layer(layer);
        if code == ErrorCode::LimitCount && layer == 1 {
            error.with_stage(ValidationStage::CanonicalFraming)
        } else {
            error
        }
    };
    let value = u64::try_from(value).map_err(|_| at_site(1))?;
    let configured = u64::try_from(configured).unwrap_or(u64::MAX);
    enforce_hard_limit_context(name, value, configured, code, 1)
        .map(|_| ())
        .map_err(|error| at_site(error.layer))
}

fn unsigned<R: Read, V: BundleVisitor>(
    reader: &mut StreamReader<R, V>,
    expected: Option<u64>,
) -> Result<u64> {
    let value = head(reader)?;
    if value.major != 0 || expected.is_some_and(|expected| expected != value.value) {
        Err(Error::at(ErrorCode::SchemaFieldInvalid, value.start))
    } else {
        Ok(value.value)
    }
}

fn scan_value<R: Read, V: BundleVisitor>(
    reader: &mut StreamReader<R, V>,
    depth: usize,
) -> Result<()> {
    let value = head(reader)?;
    match value.major {
        0 | 1 | 7 => Ok(()),
        2 => {
            let length = usize::try_from(value.value)
                .map_err(|_| Error::at(ErrorCode::LimitValueBytes, value.start))?;
            enforce_at(
                "generic-text-or-byte-value-bytes",
                length,
                reader.limits.max_value_bytes,
                ErrorCode::LimitValueBytes,
                value.start,
            )?;
            reader.take_plain(length)
        }
        3 => {
            let length = usize::try_from(value.value)
                .map_err(|_| Error::at(ErrorCode::LimitValueBytes, value.start))?;
            enforce_at(
                "generic-text-or-byte-value-bytes",
                length,
                reader.limits.max_value_bytes,
                ErrorCode::LimitValueBytes,
                value.start,
            )?;
            let mut bytes = Vec::with_capacity(length);
            reader.take(length, |_, part| {
                bytes.extend_from_slice(part);
                Ok(())
            })?;
            let text = core::str::from_utf8(&bytes)
                .map_err(|_| Error::at(ErrorCode::CborNonCanonical, value.start))?;
            if !is_unicode_15(text) || !is_nfc(text) {
                return Err(Error::at(ErrorCode::CborNonCanonical, value.start));
            }
            Ok(())
        }
        4 => {
            nested(reader, depth, value.start)?;
            let length = usize::try_from(value.value).map_err(|_| {
                Error::at(ErrorCode::LimitCount, value.start)
                    .with_stage(ValidationStage::CanonicalFraming)
            })?;
            enforce_at(
                "manifest-chunks",
                length,
                reader.limits.max_container_items,
                ErrorCode::LimitCount,
                value.start,
            )?;
            for _ in 0..length {
                scan_value(reader, depth + 1)?;
            }
            Ok(())
        }
        5 => {
            nested(reader, depth, value.start)?;
            let length = usize::try_from(value.value).map_err(|_| {
                Error::at(ErrorCode::LimitCount, value.start)
                    .with_stage(ValidationStage::CanonicalFraming)
            })?;
            enforce_at(
                "manifest-chunks",
                length,
                reader.limits.max_container_items,
                ErrorCode::LimitCount,
                value.start,
            )?;
            let mut previous: Option<CapturedKey> = None;
            for _ in 0..length {
                reader.capture_start()?;
                scan_value(reader, depth + 1)?;
                let key = reader.capture_end()?;
                if previous.as_ref().is_some_and(|previous| {
                    canonical_cmp(previous.as_slice(), key.as_slice()) != Ordering::Less
                }) {
                    reader.release_capture(key);
                    if let Some(previous) = previous.take() {
                        reader.release_capture(previous);
                    }
                    return Err(Error::at(ErrorCode::CborNonCanonical, value.start));
                }
                if let Some(previous) = previous.take() {
                    reader.release_capture(previous);
                }
                previous = Some(key);
                scan_value(reader, depth + 1)?;
            }
            if let Some(previous) = previous {
                reader.release_capture(previous);
            }
            Ok(())
        }
        _ => Err(Error::at(ErrorCode::CborNonCanonical, value.start)),
    }
}

fn nested<R, V>(reader: &StreamReader<R, V>, depth: usize, offset: usize) -> Result<()> {
    enforce_at(
        "cbor-nesting-depth",
        depth,
        reader.limits.max_nesting,
        ErrorCode::LimitNesting,
        offset,
    )
}

fn canonical_cmp(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn object_ref<R: Read, V: BundleVisitor>(reader: &mut StreamReader<R, V>) -> Result<u16> {
    let map = head(reader)?;
    if map.major != 5 || map.value != 4 {
        return Err(Error::at(ErrorCode::SchemaFieldInvalid, map.start).with_layer(1));
    }
    unsigned(reader, Some(0)).map_err(|error| error.with_layer(1))?;
    let version = unsigned(reader, None).map_err(|error| error.with_layer(1))?;
    let mut format_supported = version == 1;
    unsigned(reader, Some(1)).map_err(|error| error.with_layer(1))?;
    let kind_code = unsigned(reader, None).map_err(|error| error.with_layer(1))?;
    let kind = u16::try_from(kind_code)
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid).with_layer(1))?;
    if kind == 0 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid).with_layer(1));
    }
    unsigned(reader, Some(2)).map_err(|error| error.with_layer(1))?;
    let algorithm = unsigned(reader, None).map_err(|error| error.with_layer(1))?;
    format_supported &= algorithm == 1;
    if !format_supported && !reader.defer_object_ref_format {
        return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported).with_layer(1));
    }
    unsigned(reader, Some(3)).map_err(|error| error.with_layer(1))?;
    let digest = head(reader)?;
    if digest.major != 2 || digest.value != 32 {
        return Err(Error::at(ErrorCode::SchemaFieldInvalid, digest.start).with_layer(1));
    }
    reader.take_plain(32)?;
    Ok(kind)
}

fn bundle_item<R: Read, V: BundleVisitor>(
    reader: &mut StreamReader<R, V>,
    index: usize,
) -> Result<()> {
    reader.item_start = reader.offset;
    let start = reader.offset;
    let map = head(reader)?;
    if map.major != 5 {
        return Err(Error::at(ErrorCode::BundleSequenceInvalid, map.start).with_layer(1));
    }
    let fields = usize::try_from(map.value)
        .map_err(|_| Error::at(ErrorCode::BundleSequenceInvalid, map.start).with_layer(1))?;
    if fields < 2 {
        return Err(Error::at(ErrorCode::BundleSequenceInvalid, map.start).with_layer(1));
    }
    let sequence_unsigned = |reader: &mut StreamReader<R, V>, expected| {
        unsigned(reader, expected).map_err(|error| {
            if error.code == ErrorCode::SchemaFieldInvalid {
                Error::at(
                    ErrorCode::BundleSequenceInvalid,
                    error.offset.unwrap_or(start),
                )
                .with_layer(1)
            } else {
                error
            }
        })
    };
    sequence_unsigned(reader, Some(0))?;
    sequence_unsigned(reader, Some(1))?;
    sequence_unsigned(reader, Some(1))?;
    let item_type = u16::try_from(sequence_unsigned(reader, None)?)
        .map_err(|_| Error::new(ErrorCode::BundleSequenceInvalid).with_layer(1))?;
    let expected_fields = match item_type {
        1 | 5 => 7,
        2 | 3 => 5,
        4 => 6,
        _ => return Err(Error::new(ErrorCode::BundleSequenceInvalid).with_layer(1)),
    };
    if fields != expected_fields {
        return Err(Error::new(ErrorCode::BundleSequenceInvalid).with_layer(1));
    }
    reader.visitor.item_start(index, item_type, start)?;
    let mut kind = None;
    for key in 2..fields {
        sequence_unsigned(reader, Some(key as u64))?;
        if item_type == 2 && key == 3 {
            kind = Some(object_ref(reader)?);
        } else if item_type == 2 && key == 4 {
            let payload = head(reader)?;
            if payload.major != 2 {
                return Err(Error::at(ErrorCode::SchemaFieldInvalid, payload.start).with_layer(1));
            }
            let kind = kind.ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
            let (maximum, code) = if kind == 1 {
                (reader.limits.max_chunk_bytes, ErrorCode::LimitChunkBytes)
            } else {
                (
                    reader.limits.max_metadata_bytes,
                    ErrorCode::LimitMetadataBytes,
                )
            };
            let length =
                usize::try_from(payload.value).map_err(|_| Error::at(code, payload.start))?;
            let name = if kind == 1 {
                "chunk-payload-bytes"
            } else {
                "metadata-payload-bytes"
            };
            if enforce_at(name, length, maximum, code, payload.start).is_err() {
                return reader.prove_declared_bytes_or_limit(length, code, payload.start);
            }
            reader
                .visitor
                .object_payload_start(index, kind, length, payload.start)?;
            reader.take(length, |visitor, bytes| {
                visitor.object_payload_chunk(index, kind, bytes)
            })?;
            reader.visitor.object_payload_end(index, kind, length)?;
        } else {
            scan_value(reader, 2)?;
        }
    }
    reader.visitor.item_end(BundleItemInfo {
        index,
        item_type,
        offset: start,
        bytes: reader.offset - start,
    })?;
    Ok(())
}
