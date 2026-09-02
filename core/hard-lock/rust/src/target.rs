use std::collections::{BTreeMap, BTreeSet};

use ogvcs_object_model::FileId;
use ogvcs_path_contract::{
    repository_path_key, repository_prefix, CaseMode, PathProfile, RepositoryPathKey,
    RepositoryPrefix,
};

use crate::digest::{Digest, DigestBuilder};

pub const TARGET_EXPANSION_VERSION: u16 = 1;
pub const ASSET_GROUP_MEMBERS_MAXIMUM: usize = 256;
pub const PREFIX_EXPANSION_MEMBERS_MAXIMUM: usize = 256;
pub const TARGET_PATH_BYTES_MAXIMUM: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetGroupId([u8; 16]);

impl AssetGroupId {
    pub fn new(value: [u8; 16]) -> Result<Self, TargetError> {
        if value == [0; 16] {
            return Err(TargetError::InvalidGroup);
        }
        Ok(Self(value))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LockTarget {
    File(FileId),
    Prefix(String),
    AssetGroup {
        group_id: AssetGroupId,
        policy_version: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpandedMember {
    pub file_id: FileId,
    pub canonical_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetExpansion {
    pub schema_version: u16,
    pub view_generation: u64,
    pub policy_version: u32,
    pub policy_digest: Digest,
    pub members: Vec<ExpandedMember>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetInput {
    pub target: LockTarget,
    pub expansion: TargetExpansion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    UnsupportedExpansion,
    InvalidGeneration,
    InvalidGroup,
    InvalidPolicyBinding,
    MemberLimit,
    MemberRequired,
    FileMemberMismatch,
    DuplicateMember,
    PathCollision,
    PathInvalid,
    PrefixMemberOutsideTarget,
}

impl TargetError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedExpansion => "LOCK_TARGET_EXPANSION_UNSUPPORTED",
            Self::InvalidGeneration => "LOCK_TARGET_GENERATION_INVALID",
            Self::InvalidGroup => "LOCK_TARGET_GROUP_INVALID",
            Self::InvalidPolicyBinding => "LOCK_TARGET_POLICY_BINDING_INVALID",
            Self::MemberLimit => "LOCK_TARGET_MEMBER_LIMIT",
            Self::MemberRequired => "LOCK_TARGET_MEMBER_REQUIRED",
            Self::FileMemberMismatch => "LOCK_TARGET_FILE_MEMBER_MISMATCH",
            Self::DuplicateMember => "LOCK_TARGET_MEMBER_DUPLICATE",
            Self::PathCollision => "LOCK_TARGET_PATH_COLLISION",
            Self::PathInvalid => "LOCK_TARGET_PATH_INVALID",
            Self::PrefixMemberOutsideTarget => "LOCK_TARGET_PREFIX_MEMBER_OUTSIDE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TargetAnchor {
    File(FileId),
    Prefix,
    AssetGroup(AssetGroupId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NormalizedTarget {
    anchor: TargetAnchor,
    prefix: Option<RepositoryPrefix>,
    prefix_key: Option<RepositoryPathKey>,
    member_file_ids: BTreeSet<FileId>,
    member_path_keys: Vec<String>,
    digest: Digest,
}

impl NormalizedTarget {
    pub(crate) const fn digest(&self) -> &Digest {
        &self.digest
    }

    pub(crate) fn overlap_work(&self, other: &Self) -> u64 {
        1_u64
            .saturating_add(self.member_file_ids.len() as u64)
            .saturating_add(other.member_file_ids.len() as u64)
            .saturating_add(self.member_path_keys.len() as u64)
            .saturating_add(other.member_path_keys.len() as u64)
    }

    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        if matches!(
            (&self.anchor, &other.anchor),
            (TargetAnchor::File(left), TargetAnchor::File(right)) if left == right
        ) {
            return true;
        }
        if matches!(
            (&self.anchor, &other.anchor),
            (TargetAnchor::AssetGroup(left), TargetAnchor::AssetGroup(right)) if left == right
        ) {
            return true;
        }
        if self
            .member_file_ids
            .iter()
            .any(|file_id| other.member_file_ids.contains(file_id))
        {
            return true;
        }
        if let (Some(left), Some(right)) = (self.prefix.as_ref(), other.prefix.as_ref()) {
            if left.lower_inclusive() < right.upper_exclusive()
                && right.lower_inclusive() < left.upper_exclusive()
            {
                return true;
            }
        }
        if let Some(prefix) = self.prefix.as_ref() {
            if other
                .prefix_key
                .as_ref()
                .is_some_and(|key| prefix.matches(key))
                || other
                    .member_path_keys
                    .iter()
                    .any(|key| prefix_matches_encoded(prefix, key, other.prefix_key.as_ref()))
            {
                return true;
            }
        }
        if let Some(prefix) = other.prefix.as_ref() {
            if self
                .prefix_key
                .as_ref()
                .is_some_and(|key| prefix.matches(key))
                || self
                    .member_path_keys
                    .iter()
                    .any(|key| prefix_matches_encoded(prefix, key, self.prefix_key.as_ref()))
            {
                return true;
            }
        }
        false
    }
}

// `RepositoryPathKey` deliberately has no public constructor. A member key can
// only be tested through the exact key retained alongside its prefix target;
// all other member comparisons use the prefix's bytewise range.
fn prefix_matches_encoded(
    prefix: &RepositoryPrefix,
    encoded: &str,
    exact_key: Option<&RepositoryPathKey>,
) -> bool {
    if let Some(key) = exact_key.filter(|key| key.as_str() == encoded) {
        return prefix.matches(key);
    }
    encoded >= prefix.lower_inclusive() && encoded < prefix.upper_exclusive()
}

pub(crate) fn normalize_target(
    input: &TargetInput,
    profile: PathProfile,
    case_mode: CaseMode,
) -> Result<NormalizedTarget, TargetError> {
    if input.expansion.schema_version != TARGET_EXPANSION_VERSION {
        return Err(TargetError::UnsupportedExpansion);
    }
    if input.expansion.view_generation == 0 {
        return Err(TargetError::InvalidGeneration);
    }

    let (anchor, prefix, prefix_key, maximum_members) = match &input.target {
        LockTarget::File(file_id) => {
            if input.expansion.policy_version != 0 || input.expansion.policy_digest != [0; 32] {
                return Err(TargetError::InvalidPolicyBinding);
            }
            if input.expansion.members.len() != 1 {
                return Err(TargetError::MemberRequired);
            }
            if input.expansion.members[0].file_id != *file_id {
                return Err(TargetError::FileMemberMismatch);
            }
            (
                TargetAnchor::File(*file_id),
                None,
                None,
                PREFIX_EXPANSION_MEMBERS_MAXIMUM,
            )
        }
        LockTarget::Prefix(path) => {
            if input.expansion.policy_version != 0 || input.expansion.policy_digest != [0; 32] {
                return Err(TargetError::InvalidPolicyBinding);
            }
            if path.len() > TARGET_PATH_BYTES_MAXIMUM {
                return Err(TargetError::PathInvalid);
            }
            let prefix = repository_prefix(path, profile, case_mode)
                .map_err(|_| TargetError::PathInvalid)?;
            let prefix_key = if path.is_empty() {
                None
            } else {
                Some(
                    repository_path_key(path, profile, case_mode)
                        .map_err(|_| TargetError::PathInvalid)?,
                )
            };
            (
                TargetAnchor::Prefix,
                Some(prefix),
                prefix_key,
                PREFIX_EXPANSION_MEMBERS_MAXIMUM,
            )
        }
        LockTarget::AssetGroup {
            group_id,
            policy_version,
        } => {
            if *policy_version == 0
                || input.expansion.policy_version != *policy_version
                || input.expansion.policy_digest == [0; 32]
            {
                return Err(TargetError::InvalidPolicyBinding);
            }
            if input.expansion.members.is_empty() {
                return Err(TargetError::MemberRequired);
            }
            (
                TargetAnchor::AssetGroup(*group_id),
                None,
                None,
                ASSET_GROUP_MEMBERS_MAXIMUM,
            )
        }
    };

    if input.expansion.members.len() > maximum_members {
        return Err(TargetError::MemberLimit);
    }

    let mut members = BTreeMap::<FileId, String>::new();
    let mut path_owners = BTreeMap::<String, FileId>::new();
    for member in &input.expansion.members {
        if member.canonical_path.len() > TARGET_PATH_BYTES_MAXIMUM {
            return Err(TargetError::PathInvalid);
        }
        let path_key = repository_path_key(&member.canonical_path, profile, case_mode)
            .map_err(|_| TargetError::PathInvalid)?;
        if let Some(target_prefix) = prefix.as_ref() {
            if !target_prefix.matches(&path_key) {
                return Err(TargetError::PrefixMemberOutsideTarget);
            }
        }
        let encoded = path_key.as_str().to_owned();
        if members.insert(member.file_id, encoded.clone()).is_some() {
            return Err(TargetError::DuplicateMember);
        }
        if path_owners.insert(encoded, member.file_id).is_some() {
            return Err(TargetError::PathCollision);
        }
    }

    let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-TARGET-V1");
    match &anchor {
        TargetAnchor::File(file_id) => {
            digest.u8(1);
            digest.fixed(file_id.as_bytes());
        }
        TargetAnchor::Prefix => {
            digest.u8(2);
            digest.bytes(
                prefix_key
                    .as_ref()
                    .map_or_else(|| b"".as_slice(), |key| key.as_str().as_bytes()),
            );
        }
        TargetAnchor::AssetGroup(group_id) => {
            digest.u8(3);
            digest.fixed(group_id.as_bytes());
        }
    }
    digest.u16(input.expansion.schema_version);
    digest.u64(input.expansion.view_generation);
    digest.u32(input.expansion.policy_version);
    digest.fixed(&input.expansion.policy_digest);
    digest.u64(members.len() as u64);
    for (file_id, path_key) in &members {
        digest.fixed(file_id.as_bytes());
        digest.bytes(path_key.as_bytes());
    }

    Ok(NormalizedTarget {
        anchor,
        prefix,
        prefix_key,
        member_file_ids: members.keys().copied().collect(),
        member_path_keys: members.into_values().collect(),
        digest: digest.finish(),
    })
}

pub(crate) fn digest_target_input(input: &TargetInput) -> Digest {
    let mut digest = DigestBuilder::new(b"OGVCS-PRIVATE-LOCK-RAW-TARGET-V1");
    match &input.target {
        LockTarget::File(file_id) => {
            digest.u8(1);
            digest.fixed(file_id.as_bytes());
        }
        LockTarget::Prefix(path) => {
            digest.u8(2);
            digest.bytes(path.as_bytes());
        }
        LockTarget::AssetGroup {
            group_id,
            policy_version,
        } => {
            digest.u8(3);
            digest.fixed(group_id.as_bytes());
            digest.u32(*policy_version);
        }
    }
    digest.u16(input.expansion.schema_version);
    digest.u64(input.expansion.view_generation);
    digest.u32(input.expansion.policy_version);
    digest.fixed(&input.expansion.policy_digest);
    digest.u64(input.expansion.members.len() as u64);
    for member in &input.expansion.members {
        digest.fixed(member.file_id.as_bytes());
        digest.bytes(member.canonical_path.as_bytes());
    }
    digest.finish()
}

pub(crate) fn bounded_target_input_work(input: &TargetInput) -> Result<u64, ()> {
    if input.expansion.members.len() > ASSET_GROUP_MEMBERS_MAXIMUM + 1 {
        return Err(());
    }
    let mut work = 1_u64;
    match &input.target {
        LockTarget::File(_) | LockTarget::AssetGroup { .. } => {}
        LockTarget::Prefix(path) => {
            if path.len() > TARGET_PATH_BYTES_MAXIMUM + 1 {
                return Err(());
            }
            work = work.checked_add(path.len() as u64).ok_or(())?;
        }
    }
    for member in &input.expansion.members {
        if member.canonical_path.len() > TARGET_PATH_BYTES_MAXIMUM + 1 {
            return Err(());
        }
        work = work
            .checked_add(1)
            .and_then(|value| value.checked_add(member.canonical_path.len() as u64))
            .ok_or(())?;
    }
    Ok(work)
}
