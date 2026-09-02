use std::collections::BTreeSet;
use std::fmt;

/// The Git LFS specification requires pointer files to be strictly smaller
/// than 1024 bytes, including extension lines.
pub const GIT_LFS_POINTER_BYTES_MAXIMUM: usize = 1_023;
const CURRENT_VERSION: &str = "https://git-lfs.github.com/spec/v1";
const LEGACY_VERSIONS: [&str; 2] = [
    "http://git-media.io/v/2",
    "https://hawser.github.com/spec/v1",
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LfsObjectId([u8; 32]);

impl LfsObjectId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut value = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LfsExtension {
    pub priority: u8,
    pub name: String,
    pub input_oid: LfsObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LfsPointer {
    pub oid: LfsObjectId,
    pub size: u64,
    pub extensions: Vec<LfsExtension>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointerClassification {
    NotPointer,
    Canonical(LfsPointer),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerErrorCode {
    Utf8Invalid,
    Malformed,
    VersionUnsupported,
    OidInvalid,
    SizeInvalid,
    ExtensionInvalid,
    DuplicateExtensionPriority,
    NonCanonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PointerError {
    code: PointerErrorCode,
}

impl PointerError {
    const fn new(code: PointerErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> PointerErrorCode {
        self.code
    }
}

impl fmt::Display for PointerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            PointerErrorCode::Utf8Invalid => "GIT_LFS_POINTER_UTF8_INVALID",
            PointerErrorCode::Malformed => "GIT_LFS_POINTER_MALFORMED",
            PointerErrorCode::VersionUnsupported => "GIT_LFS_POINTER_VERSION_UNSUPPORTED",
            PointerErrorCode::OidInvalid => "GIT_LFS_POINTER_OID_INVALID",
            PointerErrorCode::SizeInvalid => "GIT_LFS_POINTER_SIZE_INVALID",
            PointerErrorCode::ExtensionInvalid => "GIT_LFS_POINTER_EXTENSION_INVALID",
            PointerErrorCode::DuplicateExtensionPriority => {
                "GIT_LFS_POINTER_EXTENSION_PRIORITY_DUPLICATE"
            }
            PointerErrorCode::NonCanonical => "GIT_LFS_POINTER_NON_CANONICAL",
        })
    }
}

impl std::error::Error for PointerError {}

/// Classify bytes using the canonical Git LFS v1 text encoding. Ordinary
/// bytes are returned as `NotPointer`; bytes that advertise Git LFS but are
/// malformed are errors and can never be silently substituted as file data.
pub fn classify_lfs_pointer(bytes: &[u8]) -> Result<PointerClassification, PointerError> {
    if bytes.is_empty() {
        // Git LFS passes an empty file through unchanged. It is not a textual
        // pointer and therefore has no external object to resolve.
        return Ok(PointerClassification::NotPointer);
    }
    // The reference DecodePointerFromBlob contract treats every blob at or
    // above the 1024-byte cutoff as not-a-pointer before parsing its bytes.
    if bytes.len() > GIT_LFS_POINTER_BYTES_MAXIMUM {
        return Ok(PointerClassification::NotPointer);
    }
    let looks_like_pointer = bytes
        .windows(b"git-lfs".len())
        .any(|part| part == b"git-lfs")
        || bytes
            .windows(b"git-media".len())
            .any(|part| part == b"git-media")
        || bytes.windows(b"hawser".len()).any(|part| part == b"hawser");
    if !looks_like_pointer {
        return Ok(PointerClassification::NotPointer);
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| PointerError::new(PointerErrorCode::Utf8Invalid))?;
    if !text.ends_with('\n') || text.contains('\r') || text.contains('\0') {
        return Err(PointerError::new(PointerErrorCode::NonCanonical));
    }
    let mut lines = text[..text.len() - 1].split('\n');
    let version = lines
        .next()
        .ok_or_else(|| PointerError::new(PointerErrorCode::Malformed))?;
    let version_value = version
        .strip_prefix("version ")
        .ok_or_else(|| PointerError::new(PointerErrorCode::Malformed))?;
    if version_value != CURRENT_VERSION {
        return if LEGACY_VERSIONS.contains(&version_value) {
            Err(PointerError::new(PointerErrorCode::NonCanonical))
        } else {
            Err(PointerError::new(PointerErrorCode::VersionUnsupported))
        };
    }

    let mut extensions = Vec::new();
    let mut oid = None;
    let mut size = None;
    let mut priorities = BTreeSet::new();
    let mut previous_key: Option<&str> = None;
    for line in lines {
        let (key, value) = split_line(line)?;
        if let Some(previous) = previous_key {
            if previous >= key {
                return Err(PointerError::new(PointerErrorCode::NonCanonical));
            }
        }
        previous_key = Some(key);
        match key {
            "oid" => {
                if oid.is_some() {
                    return Err(PointerError::new(PointerErrorCode::Malformed));
                }
                oid = Some(parse_sha256(value, PointerErrorCode::OidInvalid)?);
            }
            "size" => {
                if size.is_some() {
                    return Err(PointerError::new(PointerErrorCode::Malformed));
                }
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(PointerError::new(PointerErrorCode::SizeInvalid));
                }
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| PointerError::new(PointerErrorCode::SizeInvalid))?;
                if parsed == 0 || parsed > i64::MAX as u64 {
                    return Err(PointerError::new(PointerErrorCode::NonCanonical));
                }
                size = Some(parsed);
            }
            _ if key.starts_with("ext-") => {
                let extension = parse_extension(key, value)?;
                if !priorities.insert(extension.priority) {
                    return Err(PointerError::new(
                        PointerErrorCode::DuplicateExtensionPriority,
                    ));
                }
                extensions.push(extension);
            }
            _ => return Err(PointerError::new(PointerErrorCode::Malformed)),
        }
    }
    let pointer = LfsPointer {
        oid: oid.ok_or_else(|| PointerError::new(PointerErrorCode::OidInvalid))?,
        size: size.ok_or_else(|| PointerError::new(PointerErrorCode::SizeInvalid))?,
        extensions,
    };
    if encode_pointer(&pointer).as_bytes() != bytes {
        return Err(PointerError::new(PointerErrorCode::NonCanonical));
    }
    Ok(PointerClassification::Canonical(pointer))
}

fn split_line(line: &str) -> Result<(&str, &str), PointerError> {
    let (key, value) = line
        .split_once(' ')
        .ok_or_else(|| PointerError::new(PointerErrorCode::Malformed))?;
    if key.is_empty() || value.is_empty() || value.starts_with(' ') {
        return Err(PointerError::new(PointerErrorCode::NonCanonical));
    }
    Ok((key, value))
}

fn parse_extension(key: &str, value: &str) -> Result<LfsExtension, PointerError> {
    let mut parts = key.splitn(3, '-');
    if parts.next() != Some("ext") {
        return Err(PointerError::new(PointerErrorCode::ExtensionInvalid));
    }
    let priority_text = parts
        .next()
        .ok_or_else(|| PointerError::new(PointerErrorCode::ExtensionInvalid))?;
    let name = parts
        .next()
        .ok_or_else(|| PointerError::new(PointerErrorCode::ExtensionInvalid))?;
    // The official Git LFS reference parser recognizes one decimal digit.
    if priority_text.len() != 1 || !priority_text.as_bytes()[0].is_ascii_digit() || name.is_empty()
    {
        return Err(PointerError::new(PointerErrorCode::ExtensionInvalid));
    }
    // Match the reference extRE envelope (`\Aext-\d{1}-\w+`): the name
    // must begin with an ASCII word byte, while the unanchored suffix is
    // preserved verbatim by parsePointerExtension and the canonical encoder.
    let first = name.as_bytes()[0];
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return Err(PointerError::new(PointerErrorCode::ExtensionInvalid));
    }
    Ok(LfsExtension {
        priority: priority_text.as_bytes()[0] - b'0',
        name: name.to_owned(),
        input_oid: parse_sha256(value, PointerErrorCode::ExtensionInvalid)?,
    })
}

fn parse_sha256(value: &str, code: PointerErrorCode) -> Result<LfsObjectId, PointerError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| PointerError::new(code))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PointerError::new(code));
    }
    let mut output = [0; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(LfsObjectId(output))
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal"),
    }
}

fn encode_pointer(pointer: &LfsPointer) -> String {
    let mut encoded = format!("version {CURRENT_VERSION}\n");
    let mut extensions = pointer.extensions.clone();
    extensions.sort_by_key(|extension| extension.priority);
    for extension in extensions {
        use fmt::Write as _;
        writeln!(
            &mut encoded,
            "ext-{}-{} sha256:{}",
            extension.priority,
            extension.name,
            extension.input_oid.to_hex()
        )
        .expect("writing to String cannot fail");
    }
    use fmt::Write as _;
    writeln!(&mut encoded, "oid sha256:{}", pointer.oid.to_hex())
        .expect("writing to String cannot fail");
    writeln!(&mut encoded, "size {}", pointer.size).expect("writing to String cannot fail");
    encoded
}
