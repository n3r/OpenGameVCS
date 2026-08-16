use core::cmp::Ordering;
use std::io::Write;

use crate::{
    hard_limits::{
        enforce_hard_limit_context, MAX_BUNDLE_ITEM_BYTES, MAX_CBOR_NESTING,
        MAX_GENERIC_VALUE_BYTES, MAX_MANIFEST_CHUNKS, MAX_METADATA_BYTES,
    },
    Error, ErrorCode, Result, ValidationStage,
};
use unicode_normalization::is_nfc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Cbor {
    UInt(u64),
    NInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_value_bytes: usize,
    pub max_nesting: usize,
    pub max_container_items: usize,
    /// Maximum temporary storage used to order and deduplicate canonical map
    /// keys. The caller-owned `Cbor` value is not included in this budget.
    pub max_working_bytes: usize,
}

impl Limits {
    pub const METADATA: Self = Self {
        max_input_bytes: MAX_METADATA_BYTES as usize,
        max_value_bytes: MAX_GENERIC_VALUE_BYTES as usize,
        max_nesting: MAX_CBOR_NESTING as usize,
        max_container_items: MAX_MANIFEST_CHUNKS as usize,
        max_working_bytes: 67_108_864,
    };

    /// Absolute framing maxima for the widest format-v1 standalone item: a
    /// logical-bundle object wrapper. Contextual metadata validation applies
    /// the smaller `METADATA` value ceiling after unwrapping.
    pub const BUNDLE_ITEM: Self = Self {
        max_input_bytes: MAX_BUNDLE_ITEM_BYTES as usize,
        max_value_bytes: MAX_METADATA_BYTES as usize,
        max_nesting: MAX_CBOR_NESTING as usize,
        max_container_items: MAX_MANIFEST_CHUNKS as usize,
        max_working_bytes: 67_108_864,
    };

    pub const fn constrained_by(self, configured: Self) -> Self {
        Self {
            max_input_bytes: if self.max_input_bytes < configured.max_input_bytes {
                self.max_input_bytes
            } else {
                configured.max_input_bytes
            },
            max_value_bytes: if self.max_value_bytes < configured.max_value_bytes {
                self.max_value_bytes
            } else {
                configured.max_value_bytes
            },
            max_nesting: if self.max_nesting < configured.max_nesting {
                self.max_nesting
            } else {
                configured.max_nesting
            },
            max_container_items: if self.max_container_items < configured.max_container_items {
                self.max_container_items
            } else {
                configured.max_container_items
            },
            max_working_bytes: if self.max_working_bytes < configured.max_working_bytes {
                self.max_working_bytes
            } else {
                configured.max_working_bytes
            },
        }
    }
}

pub fn decode_canonical(input: &[u8], limits: Limits) -> Result<Cbor> {
    decode_canonical_measured(input, limits).map(|(value, _)| value)
}

pub(crate) fn decode_canonical_measured(input: &[u8], limits: Limits) -> Result<(Cbor, usize)> {
    let limits = Limits::BUNDLE_ITEM.constrained_by(limits);
    enforce_cbor_limit(
        "bundle-largest-item-bytes",
        input.len(),
        limits.max_input_bytes,
        ErrorCode::LimitMetadataBytes,
        0,
    )?;
    let mut decoder = Decoder {
        input,
        offset: 0,
        limits,
        retained_bytes: 0,
    };
    let value = decoder.value(0)?;
    if decoder.offset != input.len() {
        return Err(Error::at(ErrorCode::CborTrailingBytes, decoder.offset));
    }
    Ok((value, decoder.retained_bytes))
}

pub fn encode_canonical(value: &Cbor) -> Result<Vec<u8>> {
    encode_canonical_with_limits(value, Limits::METADATA)
}

pub fn encode_canonical_with_limits(value: &Cbor, limits: Limits) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_canonical_to(value, &mut out, limits)?;
    Ok(out)
}

/// Writes deterministic CBOR without accumulating the complete encoded value.
/// Only canonical map keys are encoded into temporary buffers for ordering;
/// values and string bodies are forwarded directly to `writer`.
pub fn encode_canonical_to<W: Write>(value: &Cbor, writer: W, limits: Limits) -> Result<usize> {
    let limits = Limits::BUNDLE_ITEM.constrained_by(limits);
    let mut preflight_working = WorkingBudget {
        used: 0,
        maximum: limits.max_working_bytes,
    };
    let encoded_size = validate_for_encoding(value, limits, 0, &mut preflight_working)?;
    enforce_cbor_limit(
        "bundle-largest-item-bytes",
        encoded_size,
        limits.max_input_bytes,
        ErrorCode::LimitMetadataBytes,
        0,
    )?;
    let mut writer = LimitedWriter {
        inner: writer,
        written: 0,
        maximum: limits.max_input_bytes,
    };
    let mut working = WorkingBudget {
        used: 0,
        maximum: limits.max_working_bytes,
    };
    encode_to(value, &mut writer, limits, 0, &mut working)?;
    Ok(writer.written)
}

struct LimitedWriter<W> {
    inner: W,
    written: usize,
    maximum: usize,
}

impl<W: Write> LimitedWriter<W> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.maximum.saturating_sub(self.written) {
            return Err(Error::new(ErrorCode::LimitMetadataBytes));
        }
        self.inner
            .write_all(bytes)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        self.written += bytes.len();
        Ok(())
    }
}

const MAP_KEY_RECORD_BYTES: usize = 64;

fn enforce_cbor_limit(
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

fn checked_encoded_sum(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| Error::new(ErrorCode::LimitMetadataBytes))
}

fn validate_for_encoding(
    value: &Cbor,
    limits: Limits,
    depth: usize,
    working: &mut WorkingBudget,
) -> Result<usize> {
    let encoded_size = match value {
        Cbor::Bytes(value) => {
            enforce_cbor_limit(
                "generic-text-or-byte-value-bytes",
                value.len(),
                limits.max_value_bytes,
                ErrorCode::LimitValueBytes,
                0,
            )?;
            checked_encoded_sum(head_len(value.len() as u64), value.len())?
        }
        Cbor::Text(value) => {
            enforce_cbor_limit(
                "generic-text-or-byte-value-bytes",
                value.len(),
                limits.max_value_bytes,
                ErrorCode::LimitValueBytes,
                0,
            )?;
            if !is_nfc(value) {
                return Err(Error::new(ErrorCode::CborNonCanonical));
            }
            checked_encoded_sum(head_len(value.len() as u64), value.len())?
        }
        Cbor::Array(values) => {
            validate_container_for_encoding(values.len(), limits, depth)?;
            let mut size = head_len(values.len() as u64);
            for value in values {
                size = checked_encoded_sum(
                    size,
                    validate_for_encoding(value, limits, depth + 1, working)?,
                )?;
            }
            size
        }
        Cbor::Map(values) => {
            validate_container_for_encoding(values.len(), limits, depth)?;
            let record_bytes = values
                .len()
                .checked_mul(MAP_KEY_RECORD_BYTES)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            let key_bytes_total = values.iter().try_fold(0usize, |total, (key, _)| {
                total
                    .checked_add(measured_size(key, limits, depth + 1)?)
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
            })?;
            let reserved = record_bytes
                .checked_add(key_bytes_total)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            working.reserve(reserved)?;
            let result = (|| {
                let mut encoded_keys = Vec::with_capacity(values.len());
                let mut size = head_len(values.len() as u64);
                for (key, value) in values {
                    let key_size = validate_for_encoding(key, limits, depth + 1, working)?;
                    let value_size = validate_for_encoding(value, limits, depth + 1, working)?;
                    size = checked_encoded_sum(size, key_size)?;
                    size = checked_encoded_sum(size, value_size)?;

                    let mut key_bytes = Vec::with_capacity(key_size);
                    encode(key, &mut key_bytes)?;
                    debug_assert_eq!(key_bytes.len(), key_size);
                    encoded_keys.push(key_bytes);
                }
                encoded_keys.sort_by(|left, right| canonical_cmp(left, right));
                if encoded_keys.windows(2).any(|window| window[0] == window[1]) {
                    return Err(Error::new(ErrorCode::CborNonCanonical));
                }
                Ok(size)
            })();
            working.release(reserved);
            result?
        }
        Cbor::UInt(value) => head_len(*value),
        Cbor::NInt(value) if *value < 0 => head_len((-1i128 - i128::from(*value)) as u64),
        Cbor::NInt(_) => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        Cbor::Bool(_) => 1,
    };
    enforce_cbor_limit(
        "bundle-largest-item-bytes",
        encoded_size,
        limits.max_input_bytes,
        ErrorCode::LimitMetadataBytes,
        0,
    )?;
    Ok(encoded_size)
}

fn validate_container_for_encoding(len: usize, limits: Limits, depth: usize) -> Result<()> {
    enforce_cbor_limit(
        "cbor-nesting-depth",
        depth.saturating_add(1),
        limits.max_nesting,
        ErrorCode::LimitNesting,
        0,
    )?;
    enforce_cbor_limit(
        "manifest-chunks",
        len,
        limits.max_container_items,
        ErrorCode::LimitCount,
        0,
    )?;
    Ok(())
}

fn encode(value: &Cbor, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Cbor::UInt(v) => head(0, *v, out),
        Cbor::NInt(v) if *v < 0 => head(1, (-1i128 - i128::from(*v)) as u64, out),
        Cbor::NInt(_) => return Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        Cbor::Bytes(v) => {
            head(2, v.len() as u64, out);
            out.extend_from_slice(v);
        }
        Cbor::Text(v) => {
            if !is_nfc(v) {
                return Err(Error::new(ErrorCode::CborNonCanonical));
            }
            head(3, v.len() as u64, out);
            out.extend_from_slice(v.as_bytes());
        }
        Cbor::Array(values) => {
            head(4, values.len() as u64, out);
            for value in values {
                encode(value, out)?;
            }
        }
        Cbor::Map(values) => {
            let mut encoded = Vec::with_capacity(values.len());
            for (key, value) in values {
                let mut key_bytes = Vec::new();
                encode(key, &mut key_bytes)?;
                encoded.push((key_bytes, value));
            }
            encoded.sort_by(|a, b| canonical_cmp(&a.0, &b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(Error::new(ErrorCode::CborNonCanonical));
            }
            head(5, encoded.len() as u64, out);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                encode(value, out)?;
            }
        }
        Cbor::Bool(false) => out.push(0xf4),
        Cbor::Bool(true) => out.push(0xf5),
    }
    Ok(())
}

struct WorkingBudget {
    used: usize,
    maximum: usize,
}

impl WorkingBudget {
    fn reserve(&mut self, bytes: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
        if self.used > self.maximum {
            self.used -= bytes;
            return Err(Error::new(ErrorCode::LimitMemory));
        }
        Ok(())
    }

    fn release(&mut self, bytes: usize) {
        self.used = self.used.saturating_sub(bytes);
    }
}

fn measured_size(value: &Cbor, limits: Limits, depth: usize) -> Result<usize> {
    match value {
        Cbor::UInt(value) => Ok(head_len(*value)),
        Cbor::NInt(value) if *value < 0 => Ok(head_len((-1i128 - i128::from(*value)) as u64)),
        Cbor::NInt(_) => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        Cbor::Bytes(value) => {
            enforce_cbor_limit(
                "generic-text-or-byte-value-bytes",
                value.len(),
                limits.max_value_bytes,
                ErrorCode::LimitValueBytes,
                0,
            )?;
            checked_encoded_sum(head_len(value.len() as u64), value.len())
        }
        Cbor::Text(value) => {
            enforce_cbor_limit(
                "generic-text-or-byte-value-bytes",
                value.len(),
                limits.max_value_bytes,
                ErrorCode::LimitValueBytes,
                0,
            )?;
            if !is_nfc(value) {
                return Err(Error::new(ErrorCode::CborNonCanonical));
            }
            checked_encoded_sum(head_len(value.len() as u64), value.len())
        }
        Cbor::Array(values) => {
            validate_container_for_encoding(values.len(), limits, depth)?;
            values
                .iter()
                .try_fold(head_len(values.len() as u64), |size, value| {
                    checked_encoded_sum(size, measured_size(value, limits, depth + 1)?)
                })
        }
        Cbor::Map(values) => {
            validate_container_for_encoding(values.len(), limits, depth)?;
            values
                .iter()
                .try_fold(head_len(values.len() as u64), |size, (key, value)| {
                    let size = checked_encoded_sum(size, measured_size(key, limits, depth + 1)?)?;
                    checked_encoded_sum(size, measured_size(value, limits, depth + 1)?)
                })
        }
        Cbor::Bool(_) => Ok(1),
    }
}

fn encode_to<W: Write>(
    value: &Cbor,
    out: &mut LimitedWriter<W>,
    limits: Limits,
    depth: usize,
    working: &mut WorkingBudget,
) -> Result<()> {
    match value {
        Cbor::UInt(v) => out.bytes(&head_bytes(0, *v)),
        Cbor::NInt(v) if *v < 0 => out.bytes(&head_bytes(1, (-1i128 - i128::from(*v)) as u64)),
        Cbor::NInt(_) => Err(Error::new(ErrorCode::SchemaFieldInvalid)),
        Cbor::Bytes(value) => {
            out.bytes(&head_bytes(2, value.len() as u64))?;
            out.bytes(value)
        }
        Cbor::Text(value) => {
            if !is_nfc(value) {
                return Err(Error::new(ErrorCode::CborNonCanonical));
            }
            out.bytes(&head_bytes(3, value.len() as u64))?;
            out.bytes(value.as_bytes())
        }
        Cbor::Array(values) => {
            out.bytes(&head_bytes(4, values.len() as u64))?;
            for value in values {
                encode_to(value, out, limits, depth + 1, working)?;
            }
            Ok(())
        }
        Cbor::Map(values) => {
            let record_bytes = values
                .len()
                .checked_mul(MAP_KEY_RECORD_BYTES)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            let key_bytes = values.iter().try_fold(0usize, |total, (key, _)| {
                total
                    .checked_add(measured_size(key, limits, depth + 1)?)
                    .ok_or_else(|| Error::new(ErrorCode::LimitMemory))
            })?;
            let reserved = record_bytes
                .checked_add(key_bytes)
                .ok_or_else(|| Error::new(ErrorCode::LimitMemory))?;
            working.reserve(reserved)?;
            let result = (|| {
                let mut keys = Vec::with_capacity(values.len());
                for (key, value) in values {
                    let key_size = measured_size(key, limits, depth + 1)?;
                    let mut key_bytes = Vec::with_capacity(key_size);
                    let mut key_writer = LimitedWriter {
                        inner: &mut key_bytes,
                        written: 0,
                        maximum: key_size,
                    };
                    encode_to(key, &mut key_writer, limits, depth + 1, working)?;
                    keys.push((key_bytes, value));
                }
                keys.sort_by(|a, b| canonical_cmp(&a.0, &b.0));
                if keys.windows(2).any(|window| window[0].0 == window[1].0) {
                    return Err(Error::new(ErrorCode::CborNonCanonical));
                }
                out.bytes(&head_bytes(5, keys.len() as u64))?;
                for (key, value) in keys {
                    out.bytes(&key)?;
                    encode_to(value, out, limits, depth + 1, working)?;
                }
                Ok(())
            })();
            working.release(reserved);
            result
        }
        Cbor::Bool(false) => out.bytes(&[0xf4]),
        Cbor::Bool(true) => out.bytes(&[0xf5]),
    }
}

fn head_bytes(major: u8, value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    head(major, value, &mut out);
    out
}

const fn head_len(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn head(major: u8, value: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => out.extend_from_slice(&[prefix | 24, value as u8]),
        0x100..=0xffff => {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(prefix | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    limits: Limits,
    retained_bytes: usize,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Cbor> {
        let start = self.offset;
        let initial = self.byte()?;
        let major = initial >> 5;
        let ai = initial & 31;
        if ai == 31 {
            return Err(Error::at(ErrorCode::CborNonCanonical, start));
        }
        match major {
            0 => Ok(Cbor::UInt(self.argument(ai, start)?)),
            1 => {
                let n = self.argument(ai, start)?;
                if n > i64::MAX as u64 {
                    return Err(Error::at(ErrorCode::CborNonCanonical, start));
                }
                Ok(Cbor::NInt(-1 - n as i64))
            }
            2 | 3 => {
                let len = self.length(ai, start)?;
                enforce_cbor_limit(
                    "generic-text-or-byte-value-bytes",
                    len,
                    self.limits.max_value_bytes,
                    ErrorCode::LimitValueBytes,
                    start,
                )?;
                self.ensure_available(len)?;
                if major == 2 {
                    self.retain(len.saturating_add(32), start)?;
                    let bytes = self.take(len)?;
                    Ok(Cbor::Bytes(bytes.to_vec()))
                } else {
                    self.retain(len.saturating_mul(2).saturating_add(32), start)?;
                    let bytes = self.take(len)?;
                    let text = core::str::from_utf8(bytes)
                        .map_err(|_| Error::at(ErrorCode::CborNonCanonical, start))?;
                    if !is_nfc(text) {
                        return Err(Error::at(ErrorCode::CborNonCanonical, start));
                    }
                    Ok(Cbor::Text(text.to_owned()))
                }
            }
            4 => {
                self.nested(depth, start)?;
                let len = self.container_len(ai, start)?;
                self.retain(len.saturating_mul(64), start)?;
                let mut values = Vec::with_capacity(len.min(4096));
                for _ in 0..len {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Cbor::Array(values))
            }
            5 => {
                self.nested(depth, start)?;
                let len = self.container_len(ai, start)?;
                self.retain(len.saturating_mul(128), start)?;
                let mut values = Vec::with_capacity(len.min(4096));
                let mut previous: Option<&[u8]> = None;
                for _ in 0..len {
                    let key_start = self.offset;
                    let key = self.value(depth + 1)?;
                    let key_end = self.offset;
                    let encoded_key = &self.input[key_start..key_end];
                    if let Some(prior) = previous {
                        if canonical_cmp(prior, encoded_key) != Ordering::Less {
                            return Err(Error::at(ErrorCode::CborNonCanonical, key_start));
                        }
                    }
                    previous = Some(encoded_key);
                    let value = self.value(depth + 1)?;
                    values.push((key, value));
                }
                Ok(Cbor::Map(values))
            }
            6 => Err(Error::at(ErrorCode::CborNonCanonical, start)),
            7 => match ai {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                _ => Err(Error::at(ErrorCode::CborNonCanonical, start)),
            },
            _ => unreachable!(),
        }
    }

    fn nested(&self, depth: usize, offset: usize) -> Result<()> {
        enforce_cbor_limit(
            "cbor-nesting-depth",
            depth.saturating_add(1),
            self.limits.max_nesting,
            ErrorCode::LimitNesting,
            offset,
        )
    }

    fn retain(&mut self, bytes: usize, offset: usize) -> Result<()> {
        self.retained_bytes = self
            .retained_bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::at(ErrorCode::LimitMemory, offset))?;
        if self.retained_bytes > self.limits.max_working_bytes {
            return Err(Error::at(ErrorCode::LimitMemory, offset));
        }
        Ok(())
    }

    fn length(&mut self, ai: u8, start: usize) -> Result<usize> {
        let value = self.argument(ai, start)?;
        usize::try_from(value).map_err(|_| Error::at(ErrorCode::LimitValueBytes, start))
    }

    fn container_len(&mut self, ai: u8, start: usize) -> Result<usize> {
        let len = self.length(ai, start)?;
        enforce_cbor_limit(
            "manifest-chunks",
            len,
            self.limits.max_container_items,
            ErrorCode::LimitCount,
            start,
        )?;
        Ok(len)
    }

    fn argument(&mut self, ai: u8, start: usize) -> Result<u64> {
        let value = match ai {
            0..=23 => return Ok(ai as u64),
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.array()?) as u64,
            26 => u32::from_be_bytes(self.array()?) as u64,
            27 => u64::from_be_bytes(self.array()?),
            _ => return Err(Error::at(ErrorCode::CborNonCanonical, start)),
        };
        let minimal = match ai {
            24 => value >= 24,
            25 => value > 0xff,
            26 => value > 0xffff,
            27 => value > 0xffff_ffff,
            _ => true,
        };
        if !minimal {
            Err(Error::at(ErrorCode::CborNonCanonical, start))
        } else {
            Ok(value)
        }
    }

    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .input
            .get(self.offset)
            .ok_or_else(|| Error::at(ErrorCode::CborTruncated, self.offset))?;
        self.offset += 1;
        Ok(value)
    }

    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::at(ErrorCode::CborTruncated, self.offset))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| Error::at(ErrorCode::CborTruncated, self.offset))?;
        self.offset = end;
        Ok(bytes)
    }

    fn ensure_available(&self, len: usize) -> Result<()> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::at(ErrorCode::CborTruncated, self.offset))?;
        if end > self.input.len() {
            Err(Error::at(ErrorCode::CborTruncated, self.offset))
        } else {
            Ok(())
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::at(ErrorCode::CborTruncated, self.offset))
    }
}

fn canonical_cmp(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}
