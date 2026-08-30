use ogvcs_object_model::{FileId, ObjectRef};

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 16]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_id!(TenantId);
opaque_id!(RepositoryId);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CommitSequence(u64);

impl CommitSequence {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseMode {
    CaseSensitive,
    CaseFolded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositorySettings {
    pub required_features: Vec<u16>,
    pub case_mode: CaseMode,
    pub path_profile: String,
    pub platform_profile: String,
    pub content_policy_profile: String,
    pub tenant_boundary: TenantId,
}

impl RepositorySettings {
    pub fn has_sorted_unique_features(&self) -> bool {
        self.required_features.windows(2).all(|pair| pair[0] < pair[1])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceKind {
    Branch,
    Tag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceName(String);

impl ReferenceName {
    pub fn new(value: String) -> Option<Self> {
        let length = value.len();
        (length > 0 && length <= 512).then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceExpected {
    Absent,
    Present { target: ObjectRef, generation: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCasRequest {
    pub repository_id: RepositoryId,
    pub kind: ReferenceKind,
    pub name: ReferenceName,
    pub expected: ReferenceExpected,
    pub desired: Option<ObjectRef>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceCasResult {
    pub prior: Option<ObjectRef>,
    pub current: Option<ObjectRef>,
    pub generation: u64,
    pub commit_sequence: CommitSequence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdOrigin {
    Create,
    Copy,
    Restore,
    Import,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdOwnerKind {
    Published,
    Draft,
    Shelf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdReservation {
    pub repository_id: RepositoryId,
    pub file_id: FileId,
    pub origin: FileIdOrigin,
    pub owner_kind: FileIdOwnerKind,
    pub owner_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectPutOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug)]
pub struct ObjectWrite<'a> {
    pub repository_id: RepositoryId,
    pub object_ref: &'a ObjectRef,
    pub canonical_bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsistencyToken(String);

impl ConsistencyToken {
    pub fn from_opaque(value: String) -> Option<Self> {
        let payload = value.strip_prefix("ct1.")?;
        (payload.len() == 43
            && payload
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
        .then_some(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub subject_digest: [u8; 32],
    pub tenant_id: TenantId,
    pub authorization_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionOptions {
    RepeatableRead,
    Serializable { maximum_retries: u8 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEvent {
    pub event_id: [u8; 16],
    pub repository_id: RepositoryId,
    pub event_type: &'static str,
    pub resource_type: &'static str,
    pub resource_opaque_id: String,
}
