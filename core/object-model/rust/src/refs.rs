use core::{fmt, str::FromStr};

use crate::{Cbor, Error, ErrorCode, Result};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ObjectKind {
    Chunk = 1,
    ContentManifest = 2,
    Tree = 3,
    ChangeSet = 4,
    AssetGroupSet = 5,
    RepositoryDescriptor = 6,
    Snapshot = 7,
    ShelfRevision = 8,
    Provenance = 9,
    Attestation = 10,
    ConflictSet = 11,
}

impl ObjectKind {
    pub fn from_code(code: u64) -> Result<Self> {
        Ok(match code {
            1 => Self::Chunk,
            2 => Self::ContentManifest,
            3 => Self::Tree,
            4 => Self::ChangeSet,
            5 => Self::AssetGroupSet,
            6 => Self::RepositoryDescriptor,
            7 => Self::Snapshot,
            8 => Self::ShelfRevision,
            9 => Self::Provenance,
            10 => Self::Attestation,
            11 => Self::ConflictSet,
            _ => return Err(Error::new(ErrorCode::ObjectKindUnsupported)),
        })
    }

    pub const fn code(self) -> u16 {
        self as u16
    }

    pub const fn token(self) -> &'static str {
        match self {
            Self::Chunk => "chunk",
            Self::ContentManifest => "content-manifest",
            Self::Tree => "tree",
            Self::ChangeSet => "change-set",
            Self::AssetGroupSet => "asset-group-set",
            Self::RepositoryDescriptor => "repository-descriptor",
            Self::Snapshot => "snapshot",
            Self::ShelfRevision => "shelf-revision",
            Self::Provenance => "provenance",
            Self::Attestation => "attestation",
            Self::ConflictSet => "conflict-set",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        (1..=11).find_map(|code| {
            let kind = Self::from_code(code).ok()?;
            (kind.token() == token).then_some(kind)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectRef {
    pub kind: ObjectKind,
    pub digest: [u8; 32],
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ogvcs:v1:{}:sha256:", self.kind.token())?;
        write_hex(f, &self.digest)
    }
}

impl ObjectRef {
    pub fn from_cbor(value: &Cbor) -> Result<Self> {
        let fields = numeric_map(value, &[0, 1, 2, 3])?;
        if uint(fields[0])? != 1 || uint(fields[2])? != 1 {
            return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
        }
        let kind = ObjectKind::from_code(uint(fields[1])?)?;
        let digest = byte_array(fields[3])?;
        Ok(Self { kind, digest })
    }

    pub fn to_cbor(self) -> Cbor {
        Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(1)),
            (Cbor::UInt(1), Cbor::UInt(self.kind.code() as u64)),
            (Cbor::UInt(2), Cbor::UInt(1)),
            (Cbor::UInt(3), Cbor::Bytes(self.digest.to_vec())),
        ])
    }
}

impl FromStr for ObjectRef {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        // 63-byte registered kind token plus the frozen framing and SHA-256
        // hex representation. Reject before splitting or retaining parts.
        if text.len() > 144 {
            return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
        }
        let mut parts = text.split(':');
        if parts.next() != Some("ogvcs") || parts.next() != Some("v1") {
            return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
        }
        let kind = parts
            .next()
            .and_then(ObjectKind::from_token)
            .ok_or_else(|| Error::new(ErrorCode::ObjectKindUnsupported))?;
        if parts.next() != Some("sha256") {
            return Err(Error::new(ErrorCode::ObjectReferenceFormatUnsupported));
        }
        let digest = parts
            .next()
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if parts.next().is_some() {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(Self {
            kind,
            digest: parse_hex::<32>(digest)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FileId([u8; 16]);

impl FileId {
    pub fn new(bytes: [u8; 16]) -> Result<Self> {
        if bytes == [0; 16] {
            Err(Error::new(ErrorCode::FileIdZero))
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_cbor(value: &Cbor) -> Result<Self> {
        Self::new(byte_array(value)?)
    }

    pub fn to_cbor(self) -> Cbor {
        Cbor::Bytes(self.0.to_vec())
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fid:")?;
        write_hex(f, &self.0)
    }
}

impl FromStr for FileId {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let body = text
            .strip_prefix("fid:")
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        Self::new(parse_hex::<16>(body)?)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProfileRef {
    namespace: String,
    id: String,
    major: u32,
}

impl ProfileRef {
    pub fn new(namespace: impl Into<String>, id: impl Into<String>, major: u32) -> Result<Self> {
        let value = Self {
            namespace: namespace.into(),
            id: id.into(),
            major,
        };
        if value.major == 0
            || value.namespace.len() > 253
            || value.id.len() > 63
            || !valid_namespace(&value.namespace)
            || !valid_token(&value.id)
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(value)
    }

    pub fn from_cbor(value: &Cbor) -> Result<Self> {
        let fields = numeric_map(value, &[0, 1, 2])?;
        let namespace = cbor_text(fields[0])?;
        let id = cbor_text(fields[1])?;
        let major = u32::try_from(uint(fields[2])?)
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        Self::new(namespace, id, major)
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn major(&self) -> u32 {
        self.major
    }

    pub fn to_cbor(&self) -> Cbor {
        Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::Text(self.namespace.clone())),
            (Cbor::UInt(1), Cbor::Text(self.id.clone())),
            (Cbor::UInt(2), Cbor::UInt(self.major as u64)),
        ])
    }
}

impl fmt::Display for ProfileRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}@{}", self.namespace, self.id, self.major)
    }
}

impl FromStr for ProfileRef {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        let (namespace, tail) = text
            .split_once('/')
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if tail.contains('/') {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let (id, major) = tail
            .split_once('@')
            .ok_or_else(|| Error::new(ErrorCode::SchemaFieldInvalid))?;
        if major.is_empty()
            || major.len() > 10
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || major.len() > 1 && major.starts_with('0')
        {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        let major = major
            .parse::<u32>()
            .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))?;
        Self::new(namespace, id, major)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypedDigest {
    algorithm: u16,
    digest: [u8; 32],
}

impl TypedDigest {
    pub const fn sha256(digest: [u8; 32]) -> Self {
        Self {
            algorithm: 1,
            digest,
        }
    }

    pub const fn algorithm(&self) -> u16 {
        self.algorithm
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn from_cbor(value: &Cbor) -> Result<Self> {
        let fields = numeric_map(value, &[0, 1])?;
        let algorithm = uint(fields[0])?;
        if algorithm != 1 {
            return Err(Error::new(ErrorCode::SchemaFieldInvalid));
        }
        Ok(Self::sha256(byte_array(fields[1])?))
    }

    pub fn to_cbor(self) -> Cbor {
        Cbor::Map(vec![
            (Cbor::UInt(0), Cbor::UInt(self.algorithm as u64)),
            (Cbor::UInt(1), Cbor::Bytes(self.digest.to_vec())),
        ])
    }
}

fn numeric_map<'a>(value: &'a Cbor, expected: &[u64]) -> Result<Vec<&'a Cbor>> {
    let Cbor::Map(entries) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    if entries.len() != expected.len() {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    expected
        .iter()
        .zip(entries)
        .map(|(wanted, (key, value))| {
            if uint(key)? != *wanted {
                return Err(Error::new(ErrorCode::SchemaFieldInvalid));
            }
            Ok(value)
        })
        .collect()
}

fn uint(value: &Cbor) -> Result<u64> {
    if let Cbor::UInt(value) = value {
        Ok(*value)
    } else {
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    }
}

fn cbor_text(value: &Cbor) -> Result<&str> {
    if let Cbor::Text(value) = value {
        Ok(value)
    } else {
        Err(Error::new(ErrorCode::SchemaFieldInvalid))
    }
}

fn byte_array<const N: usize>(value: &Cbor) -> Result<[u8; N]> {
    let Cbor::Bytes(value) = value else {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| Error::new(ErrorCode::SchemaFieldInvalid))
}

fn valid_namespace(s: &str) -> bool {
    s.is_ascii() && s.split('.').count() >= 2 && s.split('.').all(valid_token)
}

fn valid_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && !s.ends_with('-')
        && !s.contains("--")
}

fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || text
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    let mut out = [0u8; N];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        out[i] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        _ => byte - b'a' + 10,
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
