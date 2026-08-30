use core::fmt;

/// Stable assignments from `spec/repository-metadata/v1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DomainErrorCode {
    RepositorySettingsImmutable = 1001,
    ObjectInvalid = 1002,
    ObjectIdCollision = 1003,
    ReferenceConflict = 1004,
    FileIdConflict = 1005,
    HistoryLimitReached = 1006,
    ConsistencyTokenUnsatisfied = 1007,
    MigrationIncompatible = 1008,
    MigrationChecksumMismatch = 1009,
    MetadataNotFoundOrDenied = 1010,
    TransactionRetryExhausted = 1011,
}

impl DomainErrorCode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::RepositorySettingsImmutable => "REPOSITORY_SETTINGS_IMMUTABLE",
            Self::ObjectInvalid => "OBJECT_INVALID",
            Self::ObjectIdCollision => "OBJECT_ID_COLLISION",
            Self::ReferenceConflict => "REFERENCE_CONFLICT",
            Self::FileIdConflict => "FILEID_CONFLICT",
            Self::HistoryLimitReached => "HISTORY_LIMIT_REACHED",
            Self::ConsistencyTokenUnsatisfied => "CONSISTENCY_TOKEN_UNSATISFIED",
            Self::MigrationIncompatible => "MIGRATION_INCOMPATIBLE",
            Self::MigrationChecksumMismatch => "MIGRATION_CHECKSUM_MISMATCH",
            Self::MetadataNotFoundOrDenied => "METADATA_NOT_FOUND_OR_DENIED",
            Self::TransactionRetryExhausted => "TRANSACTION_RETRY_EXHAUSTED",
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::HistoryLimitReached
                | Self::ConsistencyTokenUnsatisfied
                | Self::TransactionRetryExhausted
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainError {
    pub code: DomainErrorCode,
    pub retry_after_ms: Option<u64>,
    pub visible_current_generation: Option<u64>,
}

impl DomainError {
    pub const fn new(code: DomainErrorCode) -> Self {
        Self {
            code,
            retry_after_ms: None,
            visible_current_generation: None,
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.name())
    }
}

impl std::error::Error for DomainError {}

pub type Result<T> = core::result::Result<T, DomainError>;
