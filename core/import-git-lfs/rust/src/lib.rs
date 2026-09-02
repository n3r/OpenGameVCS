//! Private, read-only, bounded preflight primitives for a caller-supplied Git
//! import inventory. This crate does not parse Git packs, read a filesystem,
//! fetch a network resource, authorize an import, persist a mapping, convert an
//! object, or publish repository state.
#![forbid(unsafe_code)]

mod lfs;
mod oid;
mod preflight;

pub use lfs::{
    classify_lfs_pointer, LfsExtension, LfsObjectId, LfsPointer, PointerClassification,
    PointerError, PointerErrorCode, GIT_LFS_POINTER_BYTES_MAXIMUM,
};
pub use oid::{GitObjectId, GitObjectIdError, GitObjectIdErrorCode};
pub use preflight::{
    preflight_git_import, ExpectedInventory, Finding, FindingKind, GitEntryMode, ImportLimits,
    ImportPolicy, ImportPreflightError, ImportPreflightErrorCode, ImportPreflightReport,
    ImportReadStatus, ImportRecord, ImportRecordKey, InventoryCounts, InventorySource,
    LfsContentSource, LfsDisposition, MappingAuthority, MappingPlan, OperationControl,
    PreparedImport, SourceOccurrence, GIT_BYTES_HARD_MAXIMUM, INPUT_BYTES_HARD_MAXIMUM,
    ITEMS_HARD_MAXIMUM, LFS_BYTES_HARD_MAXIMUM, PATH_BYTES_HARD_MAXIMUM,
    READ_CHUNK_BYTES_HARD_MAXIMUM, REF_NAME_BYTES_HARD_MAXIMUM, RELATIONSHIPS_HARD_MAXIMUM,
    RETAINED_BYTES_HARD_MAXIMUM, WORK_UNITS_HARD_MAXIMUM,
};

// Re-export the exact OGVCS-002 types used at the mapping seam. This crate does
// not define a competing FileID or import-mapping representation.
pub use ogvcs_object_model::{
    import_mapping_key, FileId, ImportDecision, ImportMapping, ImportRequest, ImportState,
    ObjectKind, ObjectRef, ProfileRef,
};
pub use ogvcs_path_contract::{CaseMode, PathProfile};
