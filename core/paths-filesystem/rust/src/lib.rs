//! Pure, bounded Rust binding for the ratified OGVCS-004 path contract v1.
//!
//! The generated constants and Unicode full-fold table are authenticated by
//! the companion manifest. Validation rejects non-NFC input; folding applies
//! only Unicode 16.0.0 `C` and `F` mappings and deliberately performs no
//! post-fold normalization.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;

use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GeneratedProfile {
    reference: &'static str,
    code: u8,
    platform_case_fold: bool,
    windows_names: bool,
    macos_colon: bool,
    depth: usize,
    joined_utf8_bytes: usize,
    joined_utf16_units: usize,
    segment_utf8_bytes: usize,
    segment_utf16_units: usize,
}

include!("generated_contract.rs");

const REPOSITORY_KEY_DOMAIN: &str = "ogvcs-path-key-v1";
const PLATFORM_KEY_DOMAIN: &str = "ogvcs-platform-key-v1";
const MAXIMUM_DIAGNOSTIC_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathProfile(&'static GeneratedProfile);

impl PathProfile {
    pub fn parse(value: &str) -> Result<Self> {
        GENERATED_PROFILES
            .iter()
            .find(|profile| profile.reference == value)
            .map(Self)
            .ok_or_else(|| PathError::new(PathErrorCode::PathProfileUnknown))
    }

    pub const fn as_str(self) -> &'static str {
        self.0.reference
    }

    pub const fn code(self) -> u8 {
        self.0.code
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaseMode {
    Sensitive,
    Folded,
}

impl CaseMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "case-sensitive" => Ok(Self::Sensitive),
            "case-folded" => Ok(Self::Folded),
            _ => Err(PathError::new(PathErrorCode::CaseModeInvalid)),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sensitive => "case-sensitive",
            Self::Folded => "case-folded",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathErrorCode {
    PathInputInvalid,
    PathNotNfc,
    PathLimitExceeded,
    PathProfileUnknown,
    PathPlatformForbidden,
    PathCollision,
    CaseModeInvalid,
    LimitExceeded,
}

impl PathErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PathInputInvalid => "PATH_INPUT_INVALID",
            Self::PathNotNfc => "PATH_NOT_NFC",
            Self::PathLimitExceeded => "PATH_LIMIT_EXCEEDED",
            Self::PathProfileUnknown => "PATH_PROFILE_UNKNOWN",
            Self::PathPlatformForbidden => "PATH_PLATFORM_FORBIDDEN",
            Self::PathCollision => "PATH_COLLISION",
            Self::CaseModeInvalid => "CASE_MODE_INVALID",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathErrorDetail {
    Segment(usize),
    Resource(&'static str),
    ResourceSegment {
        resource: &'static str,
        segment: usize,
    },
    RuleSegment {
        rule: &'static str,
        segment: usize,
    },
    Item(usize),
    Collision {
        class: &'static str,
        first: String,
        second: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathError {
    code: PathErrorCode,
    detail: Option<PathErrorDetail>,
}

impl PathError {
    const fn new(code: PathErrorCode) -> Self {
        Self { code, detail: None }
    }

    const fn detailed(code: PathErrorCode, detail: PathErrorDetail) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    pub const fn code(&self) -> PathErrorCode {
        self.code
    }

    pub const fn detail(&self) -> Option<&PathErrorDetail> {
        self.detail.as_ref()
    }
}

impl std::fmt::Display for PathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for PathError {}

pub type Result<T> = std::result::Result<T, PathError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathMeasures {
    pub depth: usize,
    pub joined_utf8_bytes: usize,
    pub joined_utf16_units: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPath {
    canonical: String,
    segments: Vec<String>,
    measures: PathMeasures,
    profile: PathProfile,
}

impl ValidatedPath {
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub const fn measures(&self) -> PathMeasures {
        self.measures
    }

    pub const fn profile(&self) -> PathProfile {
        self.profile
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathCollisionKeys {
    path: ValidatedPath,
    repository_key: RepositoryPathKey,
    platform_key: String,
}

impl PathCollisionKeys {
    pub const fn path(&self) -> &ValidatedPath {
        &self.path
    }

    pub const fn repository_key(&self) -> &RepositoryPathKey {
        &self.repository_key
    }

    pub fn platform_key(&self) -> &str {
        &self.platform_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPathKey {
    encoded: String,
    profile: PathProfile,
    case_mode: CaseMode,
}

impl RepositoryPathKey {
    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub const fn profile(&self) -> PathProfile {
        self.profile
    }

    pub const fn case_mode(&self) -> CaseMode {
        self.case_mode
    }
}

/// A component-bound repository prefix plus deterministic binary-collation
/// bounds. The range is `[lower_inclusive, upper_exclusive)` and includes the
/// exact prefix and all descendants. Callers persisting these strings must use
/// bytewise/C collation; locale collation is outside the contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPrefix {
    exact: Option<String>,
    lower_inclusive: String,
    upper_exclusive: String,
    profile: PathProfile,
    case_mode: CaseMode,
}

impl RepositoryPrefix {
    pub fn matches(&self, path: &RepositoryPathKey) -> bool {
        if self.profile != path.profile || self.case_mode != path.case_mode {
            return false;
        }
        let Some(exact) = self.exact.as_deref() else {
            return true;
        };
        path.encoded == exact
            || path
                .encoded
                .strip_prefix(exact)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    pub fn lower_inclusive(&self) -> &str {
        &self.lower_inclusive
    }

    pub fn upper_exclusive(&self) -> &str {
        &self.upper_exclusive
    }

    pub const fn is_root(&self) -> bool {
        self.exact.is_none()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathCandidate<'a> {
    pub id: &'a str,
    pub path: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollisionPath {
    pub id: String,
    pub path: String,
    pub repository_key: String,
    pub platform_key: String,
}

pub fn case_fold(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for scalar in value.chars() {
        let code = u32::from(scalar);
        match CASE_FOLDING.binary_search_by_key(&code, |(source, _)| *source) {
            Ok(index) => {
                for mapped in CASE_FOLDING[index].1 {
                    // Generated mappings are validated Unicode scalar values.
                    result.push(char::from_u32(*mapped).expect("generated mapping is a scalar"));
                }
            }
            Err(_) => result.push(scalar),
        }
    }
    result
}

pub fn validate_repository_path(input: &str, profile_ref: &str) -> Result<ValidatedPath> {
    validate_repository_path_with_profile(input, PathProfile::parse(profile_ref)?)
}

pub fn validate_repository_path_with_profile(
    input: &str,
    profile: PathProfile,
) -> Result<ValidatedPath> {
    if input.is_empty() || input.starts_with('/') {
        return Err(PathError::new(PathErrorCode::PathInputInvalid));
    }
    let joined_utf16_units = input
        .encode_utf16()
        .take(profile.0.joined_utf16_units + 1)
        .count();
    if joined_utf16_units > profile.0.joined_utf16_units {
        return Err(PathError::detailed(
            PathErrorCode::PathLimitExceeded,
            PathErrorDetail::Resource("joined-path"),
        ));
    }
    let raw_segments: Vec<_> = input.split('/').collect();
    if raw_segments.len() > profile.0.depth {
        return Err(PathError::detailed(
            PathErrorCode::PathLimitExceeded,
            PathErrorDetail::Resource("depth"),
        ));
    }
    let mut segments = Vec::with_capacity(raw_segments.len());
    for (index, segment) in raw_segments.into_iter().enumerate() {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.contains('/')
            || segment.contains('\\')
            || segment.contains('\0')
        {
            return Err(PathError::detailed(
                PathErrorCode::PathInputInvalid,
                PathErrorDetail::Segment(index),
            ));
        }
        if segment
            .encode_utf16()
            .take(profile.0.segment_utf16_units + 1)
            .count()
            > profile.0.segment_utf16_units
        {
            return Err(PathError::detailed(
                PathErrorCode::PathLimitExceeded,
                PathErrorDetail::ResourceSegment {
                    resource: "segment",
                    segment: index,
                },
            ));
        }
        if segment.nfc().ne(segment.chars()) {
            return Err(PathError::detailed(
                PathErrorCode::PathNotNfc,
                PathErrorDetail::Segment(index),
            ));
        }
        if segment.len() > profile.0.segment_utf8_bytes {
            return Err(PathError::detailed(
                PathErrorCode::PathLimitExceeded,
                PathErrorDetail::ResourceSegment {
                    resource: "segment",
                    segment: index,
                },
            ));
        }
        if segment
            .chars()
            .any(|scalar| matches!(u32::from(scalar), 0x00..=0x1f | 0x7f))
        {
            return Err(PathError::detailed(
                PathErrorCode::PathPlatformForbidden,
                PathErrorDetail::RuleSegment {
                    rule: "control",
                    segment: index,
                },
            ));
        }
        if case_fold(segment) == ".ogvcs" {
            return Err(PathError::detailed(
                PathErrorCode::PathPlatformForbidden,
                PathErrorDetail::RuleSegment {
                    rule: "workspace-reserved",
                    segment: index,
                },
            ));
        }
        if profile.0.windows_names {
            if segment
                .chars()
                .any(|scalar| matches!(scalar, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
            {
                return Err(PathError::detailed(
                    PathErrorCode::PathPlatformForbidden,
                    PathErrorDetail::RuleSegment {
                        rule: "windows-character",
                        segment: index,
                    },
                ));
            }
            if segment.ends_with(['.', ' ']) {
                return Err(PathError::detailed(
                    PathErrorCode::PathPlatformForbidden,
                    PathErrorDetail::RuleSegment {
                        rule: "windows-trailing",
                        segment: index,
                    },
                ));
            }
            if is_windows_device(segment) {
                return Err(PathError::detailed(
                    PathErrorCode::PathPlatformForbidden,
                    PathErrorDetail::RuleSegment {
                        rule: "windows-device",
                        segment: index,
                    },
                ));
            }
        } else if profile.0.macos_colon && segment.contains(':') {
            return Err(PathError::detailed(
                PathErrorCode::PathPlatformForbidden,
                PathErrorDetail::RuleSegment {
                    rule: "macos-colon",
                    segment: index,
                },
            ));
        }
        segments.push(segment.to_owned());
    }
    if input.len() > profile.0.joined_utf8_bytes {
        return Err(PathError::detailed(
            PathErrorCode::PathLimitExceeded,
            PathErrorDetail::Resource("joined-path"),
        ));
    }
    Ok(ValidatedPath {
        canonical: input.to_owned(),
        measures: PathMeasures {
            depth: segments.len(),
            joined_utf8_bytes: input.len(),
            joined_utf16_units,
        },
        segments,
        profile,
    })
}

pub fn path_collision_keys(
    input: &str,
    profile_ref: &str,
    case_mode_ref: &str,
) -> Result<PathCollisionKeys> {
    let case_mode = CaseMode::parse(case_mode_ref)?;
    let profile = PathProfile::parse(profile_ref)?;
    path_collision_keys_with_options(input, profile, case_mode)
}

pub fn path_collision_keys_with_options(
    input: &str,
    profile: PathProfile,
    case_mode: CaseMode,
) -> Result<PathCollisionKeys> {
    let path = validate_repository_path_with_profile(input, profile)?;
    let repository_segments: Vec<_> = path
        .segments
        .iter()
        .map(|segment| match case_mode {
            CaseMode::Sensitive => segment.clone(),
            CaseMode::Folded => case_fold(segment),
        })
        .collect();
    let platform_segments: Vec<_> = path
        .segments
        .iter()
        .map(|segment| {
            if profile.0.platform_case_fold {
                case_fold(segment)
            } else {
                segment.clone()
            }
        })
        .collect();
    let repository_key = format!(
        "{REPOSITORY_KEY_DOMAIN}:{}:{}",
        case_mode.as_str(),
        encode_key_segments(&repository_segments)
    );
    let platform_key = format!(
        "{PLATFORM_KEY_DOMAIN}:{}:{}",
        profile.as_str(),
        encode_key_segments(&platform_segments)
    );
    Ok(PathCollisionKeys {
        path,
        repository_key: RepositoryPathKey {
            encoded: repository_key,
            profile,
            case_mode,
        },
        platform_key,
    })
}

pub fn repository_path_key(
    input: &str,
    profile: PathProfile,
    case_mode: CaseMode,
) -> Result<RepositoryPathKey> {
    Ok(path_collision_keys_with_options(input, profile, case_mode)?.repository_key)
}

pub fn repository_prefix(
    input: &str,
    profile: PathProfile,
    case_mode: CaseMode,
) -> Result<RepositoryPrefix> {
    let base = format!("{REPOSITORY_KEY_DOMAIN}:{}:", case_mode.as_str());
    if input.is_empty() {
        return Ok(RepositoryPrefix {
            exact: None,
            lower_inclusive: base.clone(),
            upper_exclusive: format!("{REPOSITORY_KEY_DOMAIN}:{};", case_mode.as_str()),
            profile,
            case_mode,
        });
    }
    let key = repository_path_key(input, profile, case_mode)?.encoded;
    Ok(RepositoryPrefix {
        exact: Some(key.clone()),
        lower_inclusive: key.clone(),
        upper_exclusive: format!("{key}0"),
        profile,
        case_mode,
    })
}

pub fn find_path_collisions(
    candidates: &[PathCandidate<'_>],
    profile_ref: &str,
    case_mode_ref: &str,
    maximum_paths: usize,
) -> Result<Vec<CollisionPath>> {
    if candidates.len() > maximum_paths {
        return Err(PathError::detailed(
            PathErrorCode::LimitExceeded,
            PathErrorDetail::Resource("paths"),
        ));
    }
    let case_mode = CaseMode::parse(case_mode_ref)?;
    let profile = PathProfile::parse(profile_ref)?;
    let mut repository: HashMap<String, String> = HashMap::with_capacity(candidates.len());
    let mut platform: HashMap<String, String> = HashMap::with_capacity(candidates.len());
    let mut output = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        if !valid_diagnostic_id(candidate.id) {
            return Err(PathError::detailed(
                PathErrorCode::PathInputInvalid,
                PathErrorDetail::Item(index),
            ));
        }
        let keys = path_collision_keys_with_options(candidate.path, profile, case_mode)?;
        if let Some(first) = repository.get(keys.repository_key.as_str()) {
            return Err(PathError::detailed(
                PathErrorCode::PathCollision,
                PathErrorDetail::Collision {
                    class: "repository",
                    first: first.clone(),
                    second: candidate.id.to_owned(),
                },
            ));
        }
        if let Some(first) = platform.get(keys.platform_key()) {
            return Err(PathError::detailed(
                PathErrorCode::PathCollision,
                PathErrorDetail::Collision {
                    class: "platform",
                    first: first.clone(),
                    second: candidate.id.to_owned(),
                },
            ));
        }
        repository.insert(
            keys.repository_key.as_str().to_owned(),
            candidate.id.to_owned(),
        );
        platform.insert(keys.platform_key().to_owned(), candidate.id.to_owned());
        output.push(CollisionPath {
            id: candidate.id.to_owned(),
            path: keys.path.canonical,
            repository_key: keys.repository_key.encoded,
            platform_key: keys.platform_key,
        });
    }
    Ok(output)
}

fn is_windows_device(segment: &str) -> bool {
    let basename = segment.split('.').next().unwrap_or(segment);
    matches!(
        case_fold(basename).as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
            | "com¹"
            | "com²"
            | "com³"
            | "lpt¹"
            | "lpt²"
            | "lpt³"
    )
}

fn encode_key_segments(segments: &[String]) -> String {
    let capacity = segments
        .iter()
        .map(|segment| 5 + segment.len() * 2)
        .sum::<usize>()
        .saturating_add(segments.len().saturating_sub(1));
    let mut output = String::with_capacity(capacity);
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            output.push('/');
        }
        write!(&mut output, "{:04x}:", segment.len()).expect("writing to a String cannot fail");
        for byte in segment.as_bytes() {
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
        }
    }
    output
}

fn valid_diagnostic_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_DIAGNOSTIC_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_dependency_is_unicode_16() {
        assert_eq!(unicode_normalization::UNICODE_VERSION, (16, 0, 0));
        assert_eq!(UNICODE_CASE_FOLDING_MAPPING_COUNT, CASE_FOLDING.len());
    }

    #[test]
    fn component_prefixes_and_binary_ranges_are_separated() {
        let profile = PathProfile::parse("path.opengamevcs/linux@1").unwrap();
        let mode = CaseMode::Folded;
        let prefix = repository_prefix("Game/Hero", profile, mode).unwrap();
        let exact = repository_path_key("game/hero", profile, mode).unwrap();
        let child = repository_path_key("GAME/HERO/Texture", profile, mode).unwrap();
        let sibling = repository_path_key("Game/Heroic", profile, mode).unwrap();
        assert!(prefix.matches(&exact));
        assert!(prefix.matches(&child));
        assert!(!prefix.matches(&sibling));
        assert!(prefix.lower_inclusive() <= exact.as_str());
        assert!(exact.as_str() < prefix.upper_exclusive());
        assert!(prefix.lower_inclusive() <= child.as_str());
        assert!(child.as_str() < prefix.upper_exclusive());
        assert!(
            !(prefix.lower_inclusive() <= sibling.as_str()
                && sibling.as_str() < prefix.upper_exclusive())
        );
    }

    #[test]
    fn every_profile_and_case_mode_is_typed_and_bounded() {
        for profile_ref in [
            "path.opengamevcs/portable@1",
            "path.opengamevcs/windows@1",
            "path.opengamevcs/macos@1",
            "path.opengamevcs/linux@1",
        ] {
            let profile = PathProfile::parse(profile_ref).unwrap();
            for mode in [CaseMode::Sensitive, CaseMode::Folded] {
                let keys = path_collision_keys_with_options("Game/Café/🎮", profile, mode)
                    .expect("ratified profile/mode accepts canonical path");
                assert!(keys
                    .repository_key()
                    .as_str()
                    .starts_with(&format!("ogvcs-path-key-v1:{}:", mode.as_str())));
            }
            assert_eq!(
                validate_repository_path(".OGVCS/state", profile_ref)
                    .unwrap_err()
                    .code(),
                PathErrorCode::PathPlatformForbidden
            );
        }
    }

    #[test]
    fn folding_does_not_normalize_and_input_is_never_repaired() {
        let folded = case_fold("ǰ");
        assert_eq!(folded, "j\u{30c}");
        assert_ne!(folded, folded.nfc().collect::<String>());

        let error = validate_repository_path("Game/Cafe\u{301}/asset", "path.opengamevcs/linux@1")
            .unwrap_err();
        assert_eq!(error.code(), PathErrorCode::PathNotNfc);
        assert_eq!(error.detail(), Some(&PathErrorDetail::Segment(1)));
    }

    #[test]
    fn joined_count_is_bounded_without_changing_segment_error_precedence() {
        let profile = "path.opengamevcs/linux@1";
        let huge = "a".repeat(1_000_000);
        assert_eq!(
            validate_repository_path(&huge, profile)
                .unwrap_err()
                .detail(),
            Some(&PathErrorDetail::Resource("joined-path"))
        );

        let non_nfc_before_overlong_utf8 = format!("Cafe\u{301}/{}", "🎮".repeat(2_000));
        let error = validate_repository_path(&non_nfc_before_overlong_utf8, profile).unwrap_err();
        assert_eq!(error.code(), PathErrorCode::PathNotNfc);
        assert_eq!(error.detail(), Some(&PathErrorDetail::Segment(0)));
    }
}
