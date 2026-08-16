use crate::{Error, ErrorCode, FileId, Result};

pub const MAX_FILE_ID_ALLOCATION_ATTEMPTS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdAllocationRequest {
    pub candidate_file_id: FileId,
    pub retry_limit: usize,
}

pub trait EntropySource {
    fn fill(&mut self, bytes: &mut [u8]) -> std::io::Result<()>;
}

struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> std::io::Result<()> {
        getrandom::getrandom(bytes).map_err(|error| std::io::Error::other(error.to_string()))
    }
}

pub fn allocate_file_id(
    mut is_consumed: impl FnMut(&FileId) -> bool,
    attempts: usize,
) -> Result<FileId> {
    allocate_file_id_with(&mut OsEntropy, &mut is_consumed, attempts)
}

pub fn allocate_file_id_with(
    entropy: &mut impl EntropySource,
    is_consumed: &mut impl FnMut(&FileId) -> bool,
    attempts: usize,
) -> Result<FileId> {
    if attempts == 0 || attempts > MAX_FILE_ID_ALLOCATION_ATTEMPTS {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    for _ in 0..attempts {
        let mut bytes = [0u8; 16];
        entropy
            .fill(&mut bytes)
            .map_err(|_| Error::new(ErrorCode::FileIdEntropyUnavailable))?;
        let Ok(candidate) = FileId::new(bytes) else {
            continue;
        };
        if !is_consumed(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::new(ErrorCode::FileIdAllocationExhausted))
}

/// Pure compare-and-finalize preflight for a caller-selected reservation.
/// Neither lifetime slice is mutated. A concurrent winner is distinct from
/// entropy retry exhaustion.
pub fn validate_file_id_allocation(
    request: FileIdAllocationRequest,
    lifetime_file_ids: &[FileId],
    working_lifetime_file_ids: &[FileId],
) -> Result<FileId> {
    if request.retry_limit == 0 || request.retry_limit > MAX_FILE_ID_ALLOCATION_ATTEMPTS {
        return Err(Error::new(ErrorCode::SchemaFieldInvalid));
    }
    if lifetime_file_ids
        .iter()
        .chain(working_lifetime_file_ids)
        .any(|file_id| *file_id == request.candidate_file_id)
    {
        return Err(Error::new(ErrorCode::FileIdAllocationCollision));
    }
    Ok(request.candidate_file_id)
}
