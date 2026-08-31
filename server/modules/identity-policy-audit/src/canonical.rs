use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;

use crate::{ParticipantError, ParticipantErrorCode, Result};

pub(crate) const IDENTITY_CREDENTIAL_DOMAIN: &[u8] = b"OGVCS-IDENTITY-CREDENTIAL-V1\0";
pub(crate) const IDENTITY_SUBJECT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-SUBJECT-V1\0";
pub(crate) const DECISION_COMMITMENT_DOMAIN: &[u8] =
    b"OGVCS-IDENTITY-DECISION-COMMITMENT-V1\0";

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn decode_digest(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ParticipantError::new(ParticipantErrorCode::InputInvalid)),
    }
}

pub(crate) fn digest_matches(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    serde_json::to_vec(&canonical_value(value))
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
}

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.into_iter().map(canonical_value).collect())
        }
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical_value(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        value => value,
    }
}

pub(crate) fn digest_json<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(sha256(&[&canonical_bytes(value)?]))
}

pub(crate) fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'.' || *byte == b'-')
}

pub(crate) fn valid_opaque(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

pub(crate) fn valid_safe_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=256).contains(&bytes.len())
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{7f}')
}

pub(crate) fn valid_actor_pseudonym(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("pseudonym:")
        && value[10..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn canonical_path(value: &str, case_mode: &str, allow_empty: bool) -> Result<String> {
    if value.is_empty() {
        return allow_empty
            .then(String::new)
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    if value.as_bytes().len() > 4096
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.chars().any(|character| character.is_control() || character == '\u{7f}')
        || value.nfc().collect::<String>() != value
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    let segments: Vec<_> = value.split('/').collect();
    if segments.len() > 256
        || segments.iter().any(|segment| {
            segment.is_empty()
                || *segment == "."
                || *segment == ".."
                || segment.as_bytes().len() > 255
        })
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    match case_mode {
        "case-sensitive" => Ok(value.to_owned()),
        "case-folded" => Ok(value
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>()
            .nfc()
            .collect()),
        _ => Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        )),
    }
}

pub(crate) fn path_in_prefixes(
    path: Option<&str>,
    prefixes: &[String],
    case_mode: &str,
) -> Result<bool> {
    if prefixes.is_empty() {
        return Ok(true);
    }
    let Some(path) = path else {
        return Ok(false);
    };
    let actual = canonical_path(path, case_mode, false)?;
    for prefix in prefixes {
        let expected = canonical_path(prefix, case_mode, true)?;
        if expected.is_empty()
            || actual == expected
            || actual
                .strip_prefix(&expected)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn bounded_json(
    value: &Value,
    maximum_bytes: usize,
    maximum_depth: usize,
    maximum_nodes: usize,
    maximum_string_bytes: usize,
) -> Result<Vec<u8>> {
    let mut nodes = 0_usize;
    inspect_json(value, 0, maximum_depth, maximum_nodes, maximum_string_bytes, &mut nodes)?;
    let bytes = canonical_bytes(value)?;
    if bytes.len() > maximum_bytes {
        return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
    }
    Ok(bytes)
}

fn inspect_json(
    value: &Value,
    depth: usize,
    maximum_depth: usize,
    maximum_nodes: usize,
    maximum_string_bytes: usize,
    nodes: &mut usize,
) -> Result<()> {
    *nodes += 1;
    if depth > maximum_depth || *nodes > maximum_nodes {
        return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
    }
    match value {
        Value::String(value) if value.len() > maximum_string_bytes => {
            Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded))
        }
        Value::Array(values) => {
            for value in values {
                inspect_json(
                    value,
                    depth + 1,
                    maximum_depth,
                    maximum_nodes,
                    maximum_string_bytes,
                    nodes,
                )?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > maximum_string_bytes {
                    return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
                }
                inspect_json(
                    value,
                    depth + 1,
                    maximum_depth,
                    maximum_nodes,
                    maximum_string_bytes,
                    nodes,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

