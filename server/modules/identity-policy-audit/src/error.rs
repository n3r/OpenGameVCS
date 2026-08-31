use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipantErrorCode {
    InputInvalid,
    AuthenticationDenied,
    EpochStale,
    PolicyUnavailable,
    PolicyGenerationMismatch,
    TransactionMismatch,
    StateConflict,
    LimitExceeded,
    AuditInvalid,
    AuditIntegrity,
    MigrationIncompatible,
    MigrationChecksumMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParticipantError {
    code: ParticipantErrorCode,
}

impl ParticipantError {
    pub(crate) const fn new(code: ParticipantErrorCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> ParticipantErrorCode {
        self.code
    }
}

impl fmt::Display for ParticipantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identity authorization failed closed")
    }
}

impl std::error::Error for ParticipantError {}

pub type Result<T> = std::result::Result<T, ParticipantError>;
