use std::fmt;
use std::str::FromStr;

/// A Git object identifier with the hash algorithm in its type-level value.
/// SHA-1 and SHA-256 identifiers can never compare equal accidentally.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitObjectId(GitObjectIdRepr);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum GitObjectIdRepr {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitObjectIdErrorCode {
    PrefixInvalid,
    LengthInvalid,
    HexInvalid,
    NonCanonical,
    ZeroInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitObjectIdError {
    code: GitObjectIdErrorCode,
}

impl GitObjectIdError {
    const fn new(code: GitObjectIdErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> GitObjectIdErrorCode {
        self.code
    }
}

impl fmt::Display for GitObjectIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            GitObjectIdErrorCode::PrefixInvalid => "GIT_OBJECT_ID_PREFIX_INVALID",
            GitObjectIdErrorCode::LengthInvalid => "GIT_OBJECT_ID_LENGTH_INVALID",
            GitObjectIdErrorCode::HexInvalid => "GIT_OBJECT_ID_HEX_INVALID",
            GitObjectIdErrorCode::NonCanonical => "GIT_OBJECT_ID_NON_CANONICAL",
            GitObjectIdErrorCode::ZeroInvalid => "GIT_OBJECT_ID_ZERO_INVALID",
        })
    }
}

impl std::error::Error for GitObjectIdError {}

impl GitObjectId {
    pub fn from_sha1(bytes: [u8; 20]) -> Result<Self, GitObjectIdError> {
        if bytes == [0; 20] {
            Err(GitObjectIdError::new(GitObjectIdErrorCode::ZeroInvalid))
        } else {
            Ok(Self(GitObjectIdRepr::Sha1(bytes)))
        }
    }

    pub fn from_sha256(bytes: [u8; 32]) -> Result<Self, GitObjectIdError> {
        if bytes == [0; 32] {
            Err(GitObjectIdError::new(GitObjectIdErrorCode::ZeroInvalid))
        } else {
            Ok(Self(GitObjectIdRepr::Sha256(bytes)))
        }
    }

    pub fn parse_sha1(hex: &str) -> Result<Self, GitObjectIdError> {
        Self::from_sha1(parse_hex::<20>(hex)?)
    }

    pub fn parse_sha256(hex: &str) -> Result<Self, GitObjectIdError> {
        Self::from_sha256(parse_hex::<32>(hex)?)
    }

    pub const fn algorithm(self) -> &'static str {
        match self.0 {
            GitObjectIdRepr::Sha1(_) => "sha1",
            GitObjectIdRepr::Sha256(_) => "sha256",
        }
    }

    pub const fn byte_len(self) -> usize {
        match self.0 {
            GitObjectIdRepr::Sha1(_) => 20,
            GitObjectIdRepr::Sha256(_) => 32,
        }
    }

    pub const fn sha1_bytes(&self) -> Option<&[u8; 20]> {
        match &self.0 {
            GitObjectIdRepr::Sha1(bytes) => Some(bytes),
            GitObjectIdRepr::Sha256(_) => None,
        }
    }

    pub const fn sha256_bytes(&self) -> Option<&[u8; 32]> {
        match &self.0 {
            GitObjectIdRepr::Sha1(_) => None,
            GitObjectIdRepr::Sha256(bytes) => Some(bytes),
        }
    }

    pub fn write_raw(self, output: &mut Vec<u8>) {
        output.push(match self.0 {
            GitObjectIdRepr::Sha1(_) => 1,
            GitObjectIdRepr::Sha256(_) => 2,
        });
        match self.0 {
            GitObjectIdRepr::Sha1(bytes) => output.extend_from_slice(&bytes),
            GitObjectIdRepr::Sha256(bytes) => output.extend_from_slice(&bytes),
        }
    }

    pub fn to_hex(self) -> String {
        let bytes: &[u8] = match &self.0 {
            GitObjectIdRepr::Sha1(bytes) => bytes,
            GitObjectIdRepr::Sha256(bytes) => bytes,
        };
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        value
    }

    pub(crate) const fn tagged_bytes(&self) -> (u8, &[u8]) {
        match &self.0 {
            GitObjectIdRepr::Sha1(bytes) => (1, bytes),
            GitObjectIdRepr::Sha256(bytes) => (2, bytes),
        }
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm(), self.to_hex())
    }
}

impl FromStr for GitObjectId {
    type Err = GitObjectIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(hex) = value.strip_prefix("sha1:") {
            Self::parse_sha1(hex)
        } else if let Some(hex) = value.strip_prefix("sha256:") {
            Self::parse_sha256(hex)
        } else {
            Err(GitObjectIdError::new(GitObjectIdErrorCode::PrefixInvalid))
        }
    }
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], GitObjectIdError> {
    if value.len() != N * 2 {
        return Err(GitObjectIdError::new(GitObjectIdErrorCode::LengthInvalid));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(GitObjectIdError::new(GitObjectIdErrorCode::NonCanonical));
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    if output == [0; N] {
        return Err(GitObjectIdError::new(GitObjectIdErrorCode::ZeroInvalid));
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, GitObjectIdError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(GitObjectIdError::new(GitObjectIdErrorCode::HexInvalid)),
    }
}
