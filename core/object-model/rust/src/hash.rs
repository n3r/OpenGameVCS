use std::io::Read;

use crate::{
    hard_limits::{
        enforce_hard_limit_context, MAX_BUNDLE_SEQUENCE_BYTES, MAX_CHUNK_BYTES, MAX_METADATA_BYTES,
    },
    Error, ErrorCode, ObjectKind, ObjectRef, Result, TypedDigest,
};

pub type Digest = [u8; 32];

const OBJECT_DOMAIN: &[u8] = b"OpenGameVCS object\0";
const LOGICAL_DOMAIN: &[u8] = b"OpenGameVCS logical record\0";
const CONFLICT_DOMAIN: &[u8] = b"OpenGameVCS conflict\0";
const BUNDLE_DOMAIN: &[u8] = b"OpenGameVCS logical bundle\0";

pub fn object_id(kind: ObjectKind, payload: &[u8]) -> Result<Digest> {
    let mut writer =
        ObjectHashWriter::new(kind, MAX_CHUNK_BYTES as usize, MAX_METADATA_BYTES as usize);
    writer.update(payload)?;
    Ok(writer.finish()?.digest)
}

pub fn hash_chunk(payload: &[u8], configured_max_bytes: usize) -> Result<Digest> {
    enforce_hash_limit(
        "chunk-payload-bytes",
        payload.len(),
        configured_max_bytes,
        ErrorCode::LimitChunkBytes,
    )?;
    object_id(ObjectKind::Chunk, payload)
}

pub fn logical_record_id(record_type: u16, payload: &[u8]) -> Result<Digest> {
    let mut writer = LogicalRecordHashWriter::new(record_type, MAX_METADATA_BYTES as usize)?;
    writer.update(payload)?;
    Ok(*writer.finish()?.digest())
}

/// Integrity-only logical-record digest used by the bundle framing layer.
/// Unknown nonzero type codes remain hashable and forwardable until the
/// known-schema layer decides whether the type is supported.
pub(crate) fn opaque_logical_record_id(record_type: u16, payload: &[u8]) -> Result<Digest> {
    if record_type == 0 {
        return Err(Error::new(ErrorCode::LogicalRecordTypeUnsupported));
    }
    let mut writer = DomainHashWriter::new(
        LOGICAL_DOMAIN,
        Some(record_type),
        MAX_METADATA_BYTES as usize,
        "metadata-payload-bytes",
        ErrorCode::LimitMetadataBytes,
        Some(record_type),
    )?;
    writer.update(payload)?;
    writer.finish()
}

pub fn conflict_id(keyed_preimage: &[u8]) -> Digest {
    let mut hash = Sha256Writer::new();
    hash.update(CONFLICT_DOMAIN);
    hash.update(&1u16.to_be_bytes());
    hash.update(keyed_preimage);
    hash.finish()
}

/// Integrity-only digest for a framing scanner. Unlike `object_id`, this does
/// not return a serializable durable `ObjectRef` and accepts future kind codes.
pub fn opaque_object_digest(kind: u16, payload: &[u8]) -> Result<Digest> {
    let mut writer = OpaqueObjectHashWriter::new(kind, MAX_METADATA_BYTES as usize)?;
    writer.update(payload)?;
    writer.finish()
}

pub fn sha256(bytes: &[u8]) -> Digest {
    let mut h = Sha256Writer::new();
    h.update(bytes);
    h.finish()
}

#[derive(Clone)]
pub struct Sha256Writer {
    state: [u32; 8],
    block: [u8; 64],
    used: usize,
    len: u64,
}

impl Default for Sha256Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Writer {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            used: 0,
            len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.used != 0 {
            let take = (64 - self.used).min(data.len());
            self.block[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == 64 {
                let block = self.block;
                self.compress(&block);
                self.used = 0;
            } else {
                return;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        self.block[..data.len()].copy_from_slice(data);
        self.used = data.len();
    }

    pub fn update_reader<R: Read>(&mut self, mut reader: R) -> Result<usize> {
        let mut buffer = [0u8; 65_536];
        let mut total = 0usize;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
            if read == 0 {
                return Ok(total);
            }
            self.update(&buffer[..read]);
            total = total
                .checked_add(read)
                .ok_or_else(|| Error::new(ErrorCode::LimitMetadataBytes))?;
        }
    }

    pub fn update_chunks<I, B>(&mut self, chunks: I)
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        for chunk in chunks {
            self.update(chunk.as_ref());
        }
    }

    pub fn finish(mut self) -> Digest {
        let bit_len = self.len.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 56 {
            self.block[self.used..].fill(0);
            let block = self.block;
            self.compress(&block);
            self.block = [0; 64];
        } else {
            self.block[self.used..56].fill(0);
        }
        self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.block;
        self.compress(&block);
        let mut out = [0u8; 32];
        for (chunk, value) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

struct DomainHashWriter {
    hash: Sha256Writer,
    bytes: usize,
    maximum: usize,
    limit_name: &'static str,
    limit: ErrorCode,
    expected_field_one: Option<u16>,
    prefix: Vec<u8>,
}

impl DomainHashWriter {
    fn new(
        domain: &[u8],
        discriminator: Option<u16>,
        maximum: usize,
        limit_name: &'static str,
        limit: ErrorCode,
        expected_field_one: Option<u16>,
    ) -> Result<Self> {
        if discriminator == Some(0) {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let mut hash = Sha256Writer::new();
        hash.update(domain);
        hash.update(&1u16.to_be_bytes());
        if let Some(value) = discriminator {
            hash.update(&value.to_be_bytes());
        }
        Ok(Self {
            hash,
            bytes: 0,
            maximum,
            limit_name,
            limit,
            expected_field_one,
            prefix: Vec::with_capacity(128),
        })
    }

    fn update(&mut self, bytes: &[u8]) -> Result<()> {
        let total = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| Error::new(self.limit).with_layer(1))?;
        enforce_hash_limit(self.limit_name, total, self.maximum, self.limit)?;
        self.bytes = total;
        if self.expected_field_one.is_some()
            && discriminator_field_one(&self.prefix)?.is_none()
            && self.prefix.len() < 128
        {
            let take = bytes.len().min(128 - self.prefix.len());
            self.prefix.extend_from_slice(&bytes[..take]);
        }
        self.hash.update(bytes);
        Ok(())
    }

    fn update_reader<R: Read>(&mut self, mut reader: R) -> Result<usize> {
        let mut buffer = [0u8; 65_536];
        let mut total = 0usize;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
            if read == 0 {
                return Ok(total);
            }
            self.update(&buffer[..read])?;
            total += read;
        }
    }

    fn finish(self) -> Result<Digest> {
        if let Some(expected) = self.expected_field_one {
            if discriminator_field_one(&self.prefix)? != Some(expected) {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
        }
        Ok(self.hash.finish())
    }
}

pub struct ObjectHashWriter {
    kind: ObjectKind,
    inner: DomainHashWriter,
}

impl ObjectHashWriter {
    pub fn new(kind: ObjectKind, max_chunk_bytes: usize, max_metadata_bytes: usize) -> Self {
        let (maximum, limit, expected) = if kind == ObjectKind::Chunk {
            (
                max_chunk_bytes.min(MAX_CHUNK_BYTES as usize),
                ErrorCode::LimitChunkBytes,
                None,
            )
        } else {
            (
                max_metadata_bytes.min(MAX_METADATA_BYTES as usize),
                ErrorCode::LimitMetadataBytes,
                Some(kind.code()),
            )
        };
        Self {
            kind,
            inner: DomainHashWriter::new(
                OBJECT_DOMAIN,
                Some(kind.code()),
                maximum,
                if kind == ObjectKind::Chunk {
                    "chunk-payload-bytes"
                } else {
                    "metadata-payload-bytes"
                },
                limit,
                expected,
            )
            .expect("ObjectKind is nonzero"),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.inner.update(bytes)
    }

    pub fn update_reader<R: Read>(&mut self, reader: R) -> Result<usize> {
        self.inner.update_reader(reader)
    }

    pub fn finish(self) -> Result<ObjectRef> {
        Ok(ObjectRef {
            kind: self.kind,
            digest: self.inner.finish()?,
        })
    }
}

pub struct OpaqueObjectHashWriter(DomainHashWriter);

impl OpaqueObjectHashWriter {
    pub fn new(kind: u16, maximum: usize) -> Result<Self> {
        Ok(Self(DomainHashWriter::new(
            OBJECT_DOMAIN,
            Some(kind),
            maximum.min(MAX_METADATA_BYTES as usize),
            "metadata-payload-bytes",
            ErrorCode::LimitMetadataBytes,
            None,
        )?))
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.update(bytes)
    }

    pub fn update_reader<R: Read>(&mut self, reader: R) -> Result<usize> {
        self.0.update_reader(reader)
    }

    pub fn finish(self) -> Result<Digest> {
        self.0.finish()
    }
}

pub struct LogicalRecordHashWriter(DomainHashWriter);

impl LogicalRecordHashWriter {
    pub fn new(record_type: u16, maximum: usize) -> Result<Self> {
        if !(1..=9).contains(&record_type) {
            return Err(Error::new(ErrorCode::LogicalRecordTypeUnsupported));
        }
        Ok(Self(DomainHashWriter::new(
            LOGICAL_DOMAIN,
            Some(record_type),
            maximum.min(MAX_METADATA_BYTES as usize),
            "metadata-payload-bytes",
            ErrorCode::LimitMetadataBytes,
            Some(record_type),
        )?))
    }

    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.update(bytes)
    }

    pub fn update_reader<R: Read>(&mut self, reader: R) -> Result<usize> {
        self.0.update_reader(reader)
    }

    pub fn finish(self) -> Result<TypedDigest> {
        Ok(TypedDigest::sha256(self.0.finish()?))
    }
}

pub struct ConflictHashWriter(DomainHashWriter);

impl ConflictHashWriter {
    pub fn new(maximum: usize) -> Self {
        Self(
            DomainHashWriter::new(
                CONFLICT_DOMAIN,
                None,
                maximum.min(MAX_METADATA_BYTES as usize),
                "metadata-payload-bytes",
                ErrorCode::LimitMetadataBytes,
                None,
            )
            .expect("no discriminator"),
        )
    }
    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.update(bytes)
    }
    pub fn update_reader<R: Read>(&mut self, reader: R) -> Result<usize> {
        self.0.update_reader(reader)
    }
    pub fn finish(self) -> Result<TypedDigest> {
        Ok(TypedDigest::sha256(self.0.finish()?))
    }
}

pub struct BundleTranscriptHashWriter(DomainHashWriter);

impl BundleTranscriptHashWriter {
    pub fn new(maximum: usize) -> Self {
        Self(
            DomainHashWriter::new(
                BUNDLE_DOMAIN,
                None,
                maximum.min(MAX_BUNDLE_SEQUENCE_BYTES as usize),
                "bundle-sequence-bytes",
                ErrorCode::BundleBudgetExceeded,
                None,
            )
            .expect("no discriminator"),
        )
    }
    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        self.0.update(bytes)
    }
    pub fn update_reader<R: Read>(&mut self, reader: R) -> Result<usize> {
        self.0.update_reader(reader)
    }
    pub fn finish(self) -> Result<TypedDigest> {
        Ok(TypedDigest::sha256(self.0.finish()?))
    }
}

fn enforce_hash_limit(
    name: &'static str,
    value: usize,
    configured: usize,
    code: ErrorCode,
) -> Result<()> {
    let value = u64::try_from(value).map_err(|_| Error::new(code).with_layer(1))?;
    let configured = u64::try_from(configured).unwrap_or(u64::MAX);
    enforce_hard_limit_context(name, value, configured, code, 1).map(|_| ())
}

fn unsigned_at(input: &[u8], offset: usize) -> Result<Option<(u64, usize)>> {
    let Some(initial) = input.get(offset).copied() else {
        return Ok(None);
    };
    if initial >> 5 != 0 || initial & 31 == 31 {
        return Err(Error::at(ErrorCode::CborNonCanonical, offset));
    }
    let ai = initial & 31;
    if ai < 24 {
        return Ok(Some((ai as u64, offset + 1)));
    }
    let size = match ai {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(Error::at(ErrorCode::CborNonCanonical, offset)),
    };
    let Some(body) = input.get(offset + 1..offset + 1 + size) else {
        return Ok(None);
    };
    let mut value = 0u64;
    for byte in body {
        value = (value << 8) | u64::from(*byte);
    }
    let minimal = match size {
        1 => value >= 24,
        2 => value > 0xff,
        4 => value > 0xffff,
        8 => value > 0xffff_ffff,
        _ => false,
    };
    if !minimal {
        return Err(Error::at(ErrorCode::CborNonCanonical, offset));
    }
    Ok(Some((value, offset + 1 + size)))
}

fn discriminator_field_one(input: &[u8]) -> Result<Option<u16>> {
    let Some(initial) = input.first().copied() else {
        return Ok(None);
    };
    if initial >> 5 != 5 || initial & 31 == 31 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let ai = initial & 31;
    let (length, mut offset) = if ai < 24 {
        (ai as u64, 1)
    } else {
        let mut header = input.to_vec();
        header[0] = ai;
        let Some((length, offset)) = unsigned_at(&header, 0)? else {
            return Ok(None);
        };
        (length, offset)
    };
    if length < 2 {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    for expected in [0, 1, 1] {
        let Some((actual, next)) = unsigned_at(input, offset)? else {
            return Ok(None);
        };
        if actual != expected {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        offset = next;
    }
    let Some((value, _)) = unsigned_at(input, offset)? else {
        return Ok(None);
    };
    let value = u16::try_from(value).map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: Digest) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(d.len() * 2);
        for byte in d {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[test]
    fn sha256_known_answers_cover_padding_and_many_blocks() {
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(sha256(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_is_chunk_boundary_invariant() {
        let input: Vec<u8> = (0..4097).map(|index| (index % 251) as u8).collect();
        let expected = sha256(&input);
        for chunk_size in [1, 3, 7, 31, 63, 64, 65, 257, 1024] {
            let mut state = Sha256Writer::new();
            for chunk in input.chunks(chunk_size) {
                state.update(chunk);
            }
            assert_eq!(state.finish(), expected, "chunk size {chunk_size}");
        }
    }
}
