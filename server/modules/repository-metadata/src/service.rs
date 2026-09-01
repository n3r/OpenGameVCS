//! Framework-neutral OGVCS-006 public service contract boundary.
//!
//! This module validates and classifies the complete candidate operation set,
//! but deliberately assigns no HTTP route, status, or media type. Syntax
//! admission is also not mutation authority: operations that publish a root,
//! compare-and-swap a reference, tombstone a FileID, or restore a lifetime are
//! branded coordinator-required and have no production dispatcher here.

use crate::{
    AllocationReceipt, ConsistencyToken, CursorToken, DomainError, DomainErrorCode,
    FileIdAllocation, HistoryIncompleteReason, HistoryPage, IdempotencyReservation,
    IdempotencyStatus, MetadataHttpResponse, MetadataPermission, Page, PageState, ProjectId,
    RepositoryId, TenantId,
};
use ogvcs_object_model::{FileId, ObjectKind, ObjectRef, Operation, ProfileRef, Registry};
use serde::{
    de::{Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    io::{self, Write},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const METADATA_SERVICE_CONTRACT_VERSION: &str = "0.2.0";
pub const METADATA_SERVICE_REQUEST_SCHEMA: &str = "ogvcs.repository-metadata/operation-request/v1";
pub const METADATA_SERVICE_RESPONSE_SCHEMA: &str = "ogvcs.repository-metadata/http-response/v1";
pub const METADATA_SERVICE_MANIFEST_SHA256: &str =
    "19f0139ad22f8546d1c3c998e972ebc5c21b39d742a92b8fe3eefb8042d13d89";
pub const METADATA_SERVICE_OPERATION_COUNT: usize = 22;
pub const PUBLIC_PAGE_ITEMS_MAXIMUM: u16 = 10_000;
pub const PUBLIC_HISTORY_DEPTH_MAXIMUM: u64 = 100_000;
pub const PUBLIC_CANONICAL_METADATA_BYTES_MAXIMUM: u64 = 536_870_912;
pub const PUBLIC_OUTBOX_CLAIM_ITEMS_MAXIMUM: u64 = 1_000;
pub const PUBLIC_TOKEN_TTL_SECONDS_MAXIMUM: u64 = 86_400;

const CONTROL_MESSAGE_BYTES_MAXIMUM: usize = 1_048_576;
const JSON_DEPTH_MAXIMUM: usize = 64;
const JSON_NODES_MAXIMUM: usize = 100_000;
const JSON_OBJECT_MEMBERS_MAXIMUM: usize = 256;
const JSON_COLLECTION_ITEMS_MAXIMUM: usize = 100_000;
const JSON_STRING_BYTES_MAXIMUM: usize = 65_536;
const JSON_KEY_BYTES_MAXIMUM: usize = 256;
const REFERENCE_NAME_BYTES_MAXIMUM: usize = 512;
const PATH_SEGMENTS_MAXIMUM: usize = 256;
const PATH_SEGMENT_BYTES_MAXIMUM: usize = 255;
const PATH_BYTES_MAXIMUM: usize = 4_096;
const IDEMPOTENCY_KEY_SCHEMA_BYTES_MAXIMUM: usize = 512;
const PERSISTED_IDENTIFIER_BYTES_MAXIMUM: usize = 256;
const SAFE_RESULT_BYTES_MAXIMUM: usize = 1_048_576;
const JSON_SAFE_INTEGER_MAXIMUM: u64 = 9_007_199_254_740_991;
const IDEMPOTENCY_FINGERPRINT_DOMAIN: &[u8] = b"ogvcs.protocol/idempotency/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MetadataOperation {
    RepositoryCreate,
    RepositoryGetSettings,
    RepositoryList,
    ObjectPut,
    ObjectGet,
    TreePage,
    ReferenceRead,
    ReferenceList,
    ReferenceCompareAndSwap,
    HistoryAncestryPage,
    HistoryFileIdPage,
    HistoryPathPage,
    FileIdAllocate,
    FileIdRegister,
    FileIdRegisterImport,
    FileIdTombstone,
    FileIdHistory,
    IdempotencyStatus,
    ConsistencyIssueToken,
    OutboxClaim,
    OutboxAcknowledge,
    OutboxRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataOperationClass {
    Query,
    Mutation,
    InternalMutation,
}

impl MetadataOperationClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
            Self::InternalMutation => "internal-mutation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataPayloadCarrier {
    Json,
    CanonicalMetadataByteStream,
}

impl MetadataPayloadCarrier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::CanonicalMetadataByteStream => "canonical-metadata-byte-stream",
        }
    }
}

/// Classifies service composition, not authorization. Every admitted request
/// still requires the exact OGVCS-009 decision before lookup or execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataOperationExposure {
    IdentityBound,
    AggregateCoordinatorRequired,
    InternalOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataOperationDescriptor {
    pub code: u8,
    pub operation: MetadataOperation,
    pub name: &'static str,
    pub class: MetadataOperationClass,
    pub permission: MetadataPermission,
    pub resource_type: &'static str,
    pub idempotency_required: bool,
    pub payload_carrier: MetadataPayloadCarrier,
}

pub const METADATA_OPERATION_DESCRIPTORS: [MetadataOperationDescriptor;
    METADATA_SERVICE_OPERATION_COUNT] = [
    descriptor(
        1,
        MetadataOperation::RepositoryCreate,
        "repository.create",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "repository",
        true,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        2,
        MetadataOperation::RepositoryGetSettings,
        "repository.get-settings",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "repository",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        3,
        MetadataOperation::RepositoryList,
        "repository.list",
        MetadataOperationClass::Query,
        MetadataPermission::Discover,
        "repository",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        4,
        MetadataOperation::ObjectPut,
        "object.put",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "snapshot",
        true,
        MetadataPayloadCarrier::CanonicalMetadataByteStream,
    ),
    descriptor(
        5,
        MetadataOperation::ObjectGet,
        "object.get",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "snapshot",
        false,
        MetadataPayloadCarrier::CanonicalMetadataByteStream,
    ),
    descriptor(
        6,
        MetadataOperation::TreePage,
        "tree.page",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "tree",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        7,
        MetadataOperation::ReferenceRead,
        "reference.read",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "reference",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        8,
        MetadataOperation::ReferenceList,
        "reference.list",
        MetadataOperationClass::Query,
        MetadataPermission::Discover,
        "reference",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        9,
        MetadataOperation::ReferenceCompareAndSwap,
        "reference.compare-and-swap",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "reference",
        true,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        10,
        MetadataOperation::HistoryAncestryPage,
        "history.ancestry-page",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "snapshot",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        11,
        MetadataOperation::HistoryFileIdPage,
        "history.file-id-page",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "path",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        12,
        MetadataOperation::HistoryPathPage,
        "history.path-page",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "path",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        13,
        MetadataOperation::FileIdAllocate,
        "file-id.allocate",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "path",
        true,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        14,
        MetadataOperation::FileIdRegister,
        "file-id.register",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "path",
        true,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        15,
        MetadataOperation::FileIdRegisterImport,
        "file-id.register-import",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "path",
        true,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        16,
        MetadataOperation::FileIdTombstone,
        "file-id.tombstone",
        MetadataOperationClass::Mutation,
        MetadataPermission::Submit,
        "path",
        true,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        17,
        MetadataOperation::FileIdHistory,
        "file-id.history",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "path",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        18,
        MetadataOperation::IdempotencyStatus,
        "idempotency.status",
        MetadataOperationClass::Query,
        MetadataPermission::Submit,
        "repository",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        19,
        MetadataOperation::ConsistencyIssueToken,
        "consistency.issue-token",
        MetadataOperationClass::Query,
        MetadataPermission::MetadataRead,
        "repository",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        20,
        MetadataOperation::OutboxClaim,
        "outbox.claim",
        MetadataOperationClass::InternalMutation,
        MetadataPermission::ServiceInternal,
        "event",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        21,
        MetadataOperation::OutboxAcknowledge,
        "outbox.acknowledge",
        MetadataOperationClass::InternalMutation,
        MetadataPermission::ServiceInternal,
        "event",
        false,
        MetadataPayloadCarrier::Json,
    ),
    descriptor(
        22,
        MetadataOperation::OutboxRelease,
        "outbox.release",
        MetadataOperationClass::InternalMutation,
        MetadataPermission::ServiceInternal,
        "event",
        false,
        MetadataPayloadCarrier::Json,
    ),
];

// The authenticated operation registry has eight fixed columns; keeping that
// row shape visible makes assignment drift reviewable.
#[allow(clippy::too_many_arguments)]
const fn descriptor(
    code: u8,
    operation: MetadataOperation,
    name: &'static str,
    class: MetadataOperationClass,
    permission: MetadataPermission,
    resource_type: &'static str,
    idempotency_required: bool,
    payload_carrier: MetadataPayloadCarrier,
) -> MetadataOperationDescriptor {
    MetadataOperationDescriptor {
        code,
        operation,
        name,
        class,
        permission,
        resource_type,
        idempotency_required,
        payload_carrier,
    }
}

impl MetadataOperation {
    pub fn from_name(value: &str) -> Option<Self> {
        METADATA_OPERATION_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.name == value)
            .map(|descriptor| descriptor.operation)
    }

    pub const fn descriptor(self) -> &'static MetadataOperationDescriptor {
        &METADATA_OPERATION_DESCRIPTORS[self as usize]
    }

    pub const fn name(self) -> &'static str {
        self.descriptor().name
    }

    pub const fn is_page(self) -> bool {
        matches!(
            self,
            Self::RepositoryList
                | Self::TreePage
                | Self::ReferenceList
                | Self::HistoryAncestryPage
                | Self::HistoryFileIdPage
                | Self::HistoryPathPage
                | Self::FileIdHistory
        )
    }

    pub const fn exposure(self) -> MetadataOperationExposure {
        match self {
            Self::RepositoryCreate | Self::ReferenceCompareAndSwap | Self::FileIdTombstone => {
                MetadataOperationExposure::AggregateCoordinatorRequired
            }
            // This operation is a tagged union containing the proof-bound
            // restore form. Only a successfully parsed native create/copy
            // request may narrow this fail-closed default.
            Self::FileIdRegister => MetadataOperationExposure::AggregateCoordinatorRequired,
            Self::OutboxClaim | Self::OutboxAcknowledge | Self::OutboxRelease => {
                MetadataOperationExposure::InternalOnly
            }
            _ => MetadataOperationExposure::IdentityBound,
        }
    }

    const fn generic_json_result(self) -> bool {
        !self.is_page()
            && !matches!(
                self,
                Self::FileIdAllocate | Self::IdempotencyStatus | Self::ObjectGet
            )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataServiceBoundaryError {
    InputInvalid,
    LimitExceeded,
    OperationUnavailable,
}

impl fmt::Display for MetadataServiceBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputInvalid => "metadata service input invalid",
            Self::LimitExceeded => "metadata service input limit exceeded",
            Self::OperationUnavailable => "metadata service operation unavailable",
        })
    }
}

impl std::error::Error for MetadataServiceBoundaryError {}

type BoundaryResult<T> = std::result::Result<T, MetadataServiceBoundaryError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePageRequest {
    pub page_size: u16,
    pub cursor: Option<CursorToken>,
}

impl ServicePageRequest {
    pub const fn is_bounded(&self) -> bool {
        self.page_size <= PUBLIC_PAGE_ITEMS_MAXIMUM
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataOperationRequest {
    operation: MetadataOperation,
    body: Value,
    idempotency_key: Option<String>,
    semantic_fingerprint: Option<[u8; 32]>,
    tenant_id: Option<TenantId>,
    repository_id: Option<RepositoryId>,
    project_id: Option<ProjectId>,
    minimum_consistency_token: Option<ConsistencyToken>,
    page: Option<ServicePageRequest>,
    exposure: MetadataOperationExposure,
}

impl MetadataOperationRequest {
    pub fn parse(bytes: &[u8]) -> BoundaryResult<Self> {
        if bytes.is_empty() {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        }
        if bytes.len() > CONTROL_MESSAGE_BYTES_MAXIMUM {
            return Err(MetadataServiceBoundaryError::LimitExceeded);
        }
        let StrictValue(mut value) = serde_json::from_slice(bytes)
            .map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
        normalize_json_numbers(&mut value)?;
        inspect_json(&value)?;
        if canonical_json_bytes(&value)?.len() > CONTROL_MESSAGE_BYTES_MAXIMUM {
            return Err(MetadataServiceBoundaryError::LimitExceeded);
        }
        let envelope = object(&value)?;
        exact_members(
            envelope,
            &["schemaVersion", "operation", "body", "idempotencyKey"],
        )?;
        if text(envelope, "schemaVersion", 1, 128)? != METADATA_SERVICE_REQUEST_SCHEMA {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        }
        let operation = MetadataOperation::from_name(text(envelope, "operation", 1, 128)?)
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
        let body = envelope
            .get("body")
            .cloned()
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
        let body_map = object(&body)?;
        let idempotency = envelope
            .get("idempotencyKey")
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
        let idempotency_key = if operation.descriptor().idempotency_required {
            let value = value_text(idempotency, 1, IDEMPOTENCY_KEY_SCHEMA_BYTES_MAXIMUM)?;
            idempotency_window(value)?;
            Some(value.to_owned())
        } else if idempotency.is_null() {
            None
        } else {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        };
        let facts = validate_body(operation, body_map)?;
        let semantic_fingerprint = idempotency_key
            .as_ref()
            .map(|_| semantic_fingerprint(operation, &body))
            .transpose()?;
        Ok(Self {
            operation,
            body,
            idempotency_key,
            semantic_fingerprint,
            tenant_id: facts.tenant_id,
            repository_id: facts.repository_id,
            project_id: facts.project_id,
            minimum_consistency_token: facts.minimum_consistency_token,
            page: facts.page,
            exposure: facts.exposure.unwrap_or(operation.exposure()),
        })
    }

    pub const fn operation(&self) -> MetadataOperation {
        self.operation
    }

    pub fn body(&self) -> &Value {
        &self.body
    }

    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    pub const fn semantic_fingerprint(&self) -> Option<[u8; 32]> {
        self.semantic_fingerprint
    }

    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    pub const fn repository_id(&self) -> Option<RepositoryId> {
        self.repository_id
    }

    pub const fn project_id(&self) -> Option<ProjectId> {
        self.project_id
    }

    pub fn minimum_consistency_token(&self) -> Option<&ConsistencyToken> {
        self.minimum_consistency_token.as_ref()
    }

    pub fn page(&self) -> Option<&ServicePageRequest> {
        self.page.as_ref()
    }

    pub const fn exposure(&self) -> MetadataOperationExposure {
        self.exposure
    }

    /// Converts the self-dating public key into the exact persistence
    /// reservation. The caller supplies the server clock explicitly.
    pub fn idempotency_reservation_at(
        &self,
        server_now: SystemTime,
    ) -> BoundaryResult<Option<IdempotencyReservation>> {
        let Some(key) = self.idempotency_key.as_ref() else {
            return Ok(None);
        };
        let (issued_at_unix_ms, expires_at_unix_ms) = idempotency_window(key)?;
        let server_now_unix_ms = u64::try_from(
            server_now
                .duration_since(UNIX_EPOCH)
                .map_err(|_| MetadataServiceBoundaryError::InputInvalid)?
                .as_millis(),
        )
        .map_err(|_| MetadataServiceBoundaryError::LimitExceeded)?;
        if issued_at_unix_ms > server_now_unix_ms || server_now_unix_ms >= expires_at_unix_ms {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        }
        // Parsing remains platform-neutral for the complete OGVCS-041 safe
        // integer domain. Convert to `SystemTime` only after the server clock
        // proves the key is current, so an unreachable far-future timestamp
        // cannot make otherwise valid syntax platform-dependent.
        let issued_at = UNIX_EPOCH
            .checked_add(Duration::from_millis(issued_at_unix_ms))
            .ok_or(MetadataServiceBoundaryError::LimitExceeded)?;
        let expires_at = UNIX_EPOCH
            .checked_add(Duration::from_millis(expires_at_unix_ms))
            .ok_or(MetadataServiceBoundaryError::LimitExceeded)?;
        let reservation = IdempotencyReservation {
            operation: self.operation.name().to_owned(),
            key: key.clone(),
            semantic_fingerprint: self
                .semantic_fingerprint
                .ok_or(MetadataServiceBoundaryError::InputInvalid)?,
            issued_at,
            expires_at,
        };
        if !reservation.is_valid_at(server_now) {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        }
        Ok(Some(reservation))
    }

    /// Public syntax validation never implies authority. This explicit guard
    /// prevents coordinator/internal operations from entering a direct
    /// identity-bound dispatcher.
    pub fn require_identity_bound(&self) -> BoundaryResult<()> {
        if self.exposure == MetadataOperationExposure::IdentityBound {
            Ok(())
        } else {
            Err(MetadataServiceBoundaryError::OperationUnavailable)
        }
    }
}

#[derive(Default)]
struct BodyFacts {
    tenant_id: Option<TenantId>,
    repository_id: Option<RepositoryId>,
    project_id: Option<ProjectId>,
    minimum_consistency_token: Option<ConsistencyToken>,
    page: Option<ServicePageRequest>,
    exposure: Option<MetadataOperationExposure>,
}

fn validate_body(
    operation: MetadataOperation,
    body: &Map<String, Value>,
) -> BoundaryResult<BodyFacts> {
    match operation {
        MetadataOperation::RepositoryCreate => validate_repository_create(body),
        MetadataOperation::RepositoryGetSettings => {
            exact_members(
                body,
                &["tenantId", "repositoryId", "minimumConsistencyToken"],
            )?;
            scoped_consistent(body)
        }
        MetadataOperation::RepositoryList => validate_repository_list(body),
        MetadataOperation::ObjectPut => validate_object_put(body),
        MetadataOperation::ObjectGet => {
            exact_members(
                body,
                &[
                    "tenantId",
                    "repositoryId",
                    "minimumConsistencyToken",
                    "objectRef",
                ],
            )?;
            let facts = scoped_consistent(body)?;
            if !metadata_kind(object_ref(body, "objectRef")?.kind) {
                return input_invalid();
            }
            Ok(facts)
        }
        MetadataOperation::TreePage => validate_tree_page(body),
        MetadataOperation::ReferenceRead => validate_reference_read(body),
        MetadataOperation::ReferenceList => validate_reference_list(body),
        MetadataOperation::ReferenceCompareAndSwap => validate_reference_cas(body),
        MetadataOperation::HistoryAncestryPage => validate_history_ancestry(body),
        MetadataOperation::HistoryFileIdPage => validate_history_file_id(body),
        MetadataOperation::HistoryPathPage => validate_history_path(body),
        MetadataOperation::FileIdAllocate => {
            exact_members(body, &["tenantId", "repositoryId"])?;
            scoped(body)
        }
        MetadataOperation::FileIdRegister => validate_file_id_register(body),
        MetadataOperation::FileIdRegisterImport => validate_file_id_import(body),
        MetadataOperation::FileIdTombstone => validate_file_id_tombstone(body),
        MetadataOperation::FileIdHistory => validate_file_id_history(body),
        MetadataOperation::IdempotencyStatus => validate_idempotency_status(body),
        MetadataOperation::ConsistencyIssueToken => validate_consistency_issue(body),
        MetadataOperation::OutboxClaim => validate_outbox_claim(body),
        MetadataOperation::OutboxAcknowledge => validate_outbox_action(body, false),
        MetadataOperation::OutboxRelease => validate_outbox_action(body, true),
    }
}

fn validate_repository_create(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "projectId",
            "repositoryId",
            "settings",
            "rootSnapshot",
            "defaultReference",
        ],
    )?;
    let request_tenant_id = tenant_id(body, "tenantId")?;
    let project_id = project_id(body, "projectId")?;
    let repository_id = repository_id(body, "repositoryId")?;
    let settings = object(required(body, "settings")?)?;
    exact_members(
        settings,
        &[
            "schemaVersion",
            "repositoryFormat",
            "requiredFeatures",
            "caseMode",
            "pathProfile",
            "platformProfile",
            "contentPolicyProfile",
            "structuralLimits",
            "tenantBoundary",
        ],
    )?;
    if text(settings, "schemaVersion", 1, 128)?
        != "ogvcs.repository-metadata/repository-settings/v1"
        || text(settings, "repositoryFormat", 1, 128)? != "ogvcs.repository-format@1"
    {
        return input_invalid();
    }
    let features = array(settings, "requiredFeatures", 128, 0)?;
    let mut previous = None;
    for feature in features {
        let feature = value_uint(feature, 65_535)?;
        if previous.is_some_and(|previous| previous >= feature) {
            return input_invalid();
        }
        previous = Some(feature);
    }
    enum_text(settings, "caseMode", &["case-sensitive", "case-folded"])?;
    let path_profile = profile(settings, "pathProfile")?;
    let platform_profile = profile(settings, "platformProfile")?;
    let content_profile = profile(settings, "contentPolicyProfile")?;
    let registry = Registry::bundled();
    for (profile, family) in [
        (&path_profile, "path"),
        (&platform_profile, "path"),
        (&content_profile, "content-policy"),
    ] {
        // The candidate request contract includes conformance-only fixture
        // profiles. This structural boundary verifies their registry family
        // and non-reserved state; the eventual coordinator must revalidate
        // production-write eligibility before any repository is created.
        registry
            .check_profile(profile, family, Operation::ConformanceWrite)
            .map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
    }
    let limits = object(required(settings, "structuralLimits")?)?;
    exact_members(
        limits,
        &[
            "maxTreeEntries",
            "maxPathBytes",
            "maxPathSegments",
            "maxSnapshotParents",
        ],
    )?;
    uint(limits, "maxTreeEntries", 1_000_000)?;
    uint(limits, "maxPathBytes", 4_096)?;
    uint(limits, "maxPathSegments", 256)?;
    uint(limits, "maxSnapshotParents", 8)?;
    if tenant_id(settings, "tenantBoundary")? != request_tenant_id {
        return input_invalid();
    }
    if object_ref(body, "rootSnapshot")?.kind != ObjectKind::Snapshot {
        return input_invalid();
    }
    reference_name(body, "defaultReference")?;
    Ok(BodyFacts {
        tenant_id: Some(request_tenant_id),
        repository_id: Some(repository_id),
        project_id: Some(project_id),
        exposure: Some(MetadataOperationExposure::AggregateCoordinatorRequired),
        ..BodyFacts::default()
    })
}

fn validate_repository_list(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(body, &["tenantId", "projectId", "pageSize", "cursor"])?;
    Ok(BodyFacts {
        tenant_id: Some(tenant_id(body, "tenantId")?),
        project_id: Some(project_id(body, "projectId")?),
        page: Some(page(body)?),
        ..BodyFacts::default()
    })
}

fn validate_object_put(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "objectRef",
            "canonicalByteLength",
            "streamDigestSha256",
        ],
    )?;
    let facts = scoped(body)?;
    if !metadata_kind(object_ref(body, "objectRef")?.kind) {
        return input_invalid();
    }
    uint(
        body,
        "canonicalByteLength",
        PUBLIC_CANONICAL_METADATA_BYTES_MAXIMUM,
    )?;
    digest32(body, "streamDigestSha256")?;
    Ok(facts)
}

fn validate_tree_page(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "snapshot",
            "tree",
            "prefix",
            "pageSize",
            "cursor",
        ],
    )?;
    let mut facts = scoped_consistent(body)?;
    if object_ref(body, "snapshot")?.kind != ObjectKind::Snapshot
        || object_ref(body, "tree")?.kind != ObjectKind::Tree
    {
        return input_invalid();
    }
    path(body, "prefix", true)?;
    facts.page = Some(page(body)?);
    Ok(facts)
}

fn validate_reference_read(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "referenceKind",
            "referenceName",
        ],
    )?;
    let facts = scoped_consistent(body)?;
    enum_text(body, "referenceKind", &["branch", "tag"])?;
    reference_name(body, "referenceName")?;
    Ok(facts)
}

fn validate_reference_list(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "referenceKind",
            "pageSize",
            "cursor",
        ],
    )?;
    let mut facts = scoped_consistent(body)?;
    enum_text(body, "referenceKind", &["branch", "tag", "all"])?;
    facts.page = Some(page(body)?);
    Ok(facts)
}

fn validate_reference_cas(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "referenceKind",
            "referenceName",
            "expected",
            "desired",
        ],
    )?;
    let mut facts = scoped(body)?;
    enum_text(body, "referenceKind", &["branch", "tag"])?;
    reference_name(body, "referenceName")?;
    let expected = object(required(body, "expected")?)?;
    match text(expected, "state", 1, 16)? {
        "absent" => exact_members(expected, &["state"])?,
        "present" => {
            exact_members(expected, &["state", "target", "generation"])?;
            if object_ref(expected, "target")?.kind != ObjectKind::Snapshot {
                return input_invalid();
            }
            uint(expected, "generation", JSON_SAFE_INTEGER_MAXIMUM)?;
        }
        _ => return input_invalid(),
    }
    if let Some(desired) = nullable_object_ref(body, "desired")? {
        if desired.kind != ObjectKind::Snapshot {
            return input_invalid();
        }
    }
    facts.exposure = Some(MetadataOperationExposure::AggregateCoordinatorRequired);
    Ok(facts)
}

fn validate_history_ancestry(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "snapshot",
            "maxDepth",
            "pageSize",
            "cursor",
        ],
    )?;
    let mut facts = scoped_consistent(body)?;
    if object_ref(body, "snapshot")?.kind != ObjectKind::Snapshot {
        return input_invalid();
    }
    uint(body, "maxDepth", PUBLIC_HISTORY_DEPTH_MAXIMUM)?;
    facts.page = Some(page(body)?);
    Ok(facts)
}

fn validate_history_file_id(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "snapshot",
            "fileId",
            "maxDepth",
            "pageSize",
            "cursor",
        ],
    )?;
    let mut facts = scoped_consistent(body)?;
    if object_ref(body, "snapshot")?.kind != ObjectKind::Snapshot {
        return input_invalid();
    }
    file_id(body, "fileId")?;
    uint(body, "maxDepth", PUBLIC_HISTORY_DEPTH_MAXIMUM)?;
    facts.page = Some(page(body)?);
    Ok(facts)
}

fn validate_history_path(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "snapshot",
            "path",
            "maxDepth",
            "pageSize",
            "cursor",
        ],
    )?;
    let mut facts = scoped_consistent(body)?;
    if object_ref(body, "snapshot")?.kind != ObjectKind::Snapshot {
        return input_invalid();
    }
    path(body, "path", false)?;
    uint(body, "maxDepth", PUBLIC_HISTORY_DEPTH_MAXIMUM)?;
    facts.page = Some(page(body)?);
    Ok(facts)
}

fn validate_file_id_register(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "fileId",
            "origin",
            "allocationReceipt",
            "ownerKind",
            "ownerId",
        ],
    )?;
    let mut facts = scoped(body)?;
    file_id(body, "fileId")?;
    let origin = enum_text(body, "origin", &["create", "copy", "restore"])?;
    match origin {
        "create" | "copy" => {
            let receipt = text(body, "allocationReceipt", 48, 48)?;
            AllocationReceipt::from_opaque(receipt.to_owned())
                .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
            facts.exposure = Some(MetadataOperationExposure::IdentityBound);
        }
        "restore" => {
            if !required(body, "allocationReceipt")?.is_null() {
                return input_invalid();
            }
            facts.exposure = Some(MetadataOperationExposure::AggregateCoordinatorRequired);
        }
        _ => return input_invalid(),
    }
    enum_text(body, "ownerKind", &["published", "draft", "shelf"])?;
    persisted_identifier(body, "ownerId")?;
    Ok(facts)
}

fn validate_file_id_import(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "fileId",
            "importerProfile",
            "sourceNamespaceDigest",
            "sourceIdentityDigest",
            "ownerKind",
            "ownerId",
        ],
    )?;
    let facts = scoped(body)?;
    file_id(body, "fileId")?;
    profile(body, "importerProfile")?;
    digest32(body, "sourceNamespaceDigest")?;
    digest32(body, "sourceIdentityDigest")?;
    enum_text(body, "ownerKind", &["published", "draft", "shelf"])?;
    persisted_identifier(body, "ownerId")?;
    Ok(facts)
}

fn validate_file_id_tombstone(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &["tenantId", "repositoryId", "fileId", "expectedState"],
    )?;
    let mut facts = scoped(body)?;
    file_id(body, "fileId")?;
    enum_text(body, "expectedState", &["active", "reserved"])?;
    facts.exposure = Some(MetadataOperationExposure::AggregateCoordinatorRequired);
    Ok(facts)
}

fn validate_file_id_history(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &[
            "tenantId",
            "repositoryId",
            "minimumConsistencyToken",
            "fileId",
            "pageSize",
            "cursor",
        ],
    )?;
    let mut facts = scoped_consistent(body)?;
    file_id(body, "fileId")?;
    facts.page = Some(page(body)?);
    Ok(facts)
}

fn validate_idempotency_status(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(
        body,
        &["tenantId", "repositoryId", "operation", "idempotencyKey"],
    )?;
    let facts = scoped(body)?;
    text(body, "operation", 1, 128)?;
    value_text(
        required(body, "idempotencyKey")?,
        1,
        IDEMPOTENCY_KEY_SCHEMA_BYTES_MAXIMUM,
    )?;
    Ok(facts)
}

fn validate_consistency_issue(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(body, &["tenantId", "repositoryId", "ttlSeconds"])?;
    let facts = scoped(body)?;
    uint(body, "ttlSeconds", PUBLIC_TOKEN_TTL_SECONDS_MAXIMUM)?;
    Ok(facts)
}

fn validate_outbox_claim(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    exact_members(body, &["consumerId", "maximumItems", "leaseSeconds"])?;
    persisted_identifier(body, "consumerId")?;
    uint(body, "maximumItems", PUBLIC_OUTBOX_CLAIM_ITEMS_MAXIMUM)?;
    uint(body, "leaseSeconds", 3_600)?;
    Ok(BodyFacts {
        exposure: Some(MetadataOperationExposure::InternalOnly),
        ..BodyFacts::default()
    })
}

fn validate_outbox_action(body: &Map<String, Value>, release: bool) -> BoundaryResult<BodyFacts> {
    if release {
        exact_members(
            body,
            &["consumerId", "eventId", "leaseId", "retryAfterSeconds"],
        )?;
        uint(body, "retryAfterSeconds", PUBLIC_TOKEN_TTL_SECONDS_MAXIMUM)?;
    } else {
        exact_members(body, &["consumerId", "eventId", "leaseId"])?;
    }
    persisted_identifier(body, "consumerId")?;
    public_uuid(body, "eventId")?;
    public_uuid(body, "leaseId")?;
    Ok(BodyFacts {
        exposure: Some(MetadataOperationExposure::InternalOnly),
        ..BodyFacts::default()
    })
}

fn scoped(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    Ok(BodyFacts {
        tenant_id: Some(tenant_id(body, "tenantId")?),
        repository_id: Some(repository_id(body, "repositoryId")?),
        ..BodyFacts::default()
    })
}

fn scoped_consistent(body: &Map<String, Value>) -> BoundaryResult<BodyFacts> {
    let mut facts = scoped(body)?;
    facts.minimum_consistency_token = optional_consistency(body, "minimumConsistencyToken")?;
    Ok(facts)
}

fn page(body: &Map<String, Value>) -> BoundaryResult<ServicePageRequest> {
    let page_size = u16::try_from(uint(
        body,
        "pageSize",
        u64::from(PUBLIC_PAGE_ITEMS_MAXIMUM),
    )?)
    .map_err(|_| MetadataServiceBoundaryError::LimitExceeded)?;
    let cursor = optional_cursor(body, "cursor")?;
    Ok(ServicePageRequest { page_size, cursor })
}

fn path(body: &Map<String, Value>, key: &str, allow_empty: bool) -> BoundaryResult<Vec<String>> {
    let values = array(
        body,
        key,
        PATH_SEGMENTS_MAXIMUM,
        if allow_empty { 0 } else { 1 },
    )?;
    let mut result = Vec::with_capacity(values.len());
    let mut bytes = values.len().saturating_sub(1);
    for value in values {
        let value = value_text(value, 1, PATH_SEGMENT_BYTES_MAXIMUM)?;
        if value.len() > PATH_SEGMENT_BYTES_MAXIMUM {
            return Err(MetadataServiceBoundaryError::LimitExceeded);
        }
        if value == "."
            || value == ".."
            || value == ".ogvcs"
            || value.contains('/')
            || value.contains('\\')
            || value.contains('\0')
            || value.chars().any(is_c0_or_del)
            || !value.nfc().eq(value.chars())
        {
            return input_invalid();
        }
        bytes = bytes.saturating_add(value.len());
        if bytes > PATH_BYTES_MAXIMUM {
            return Err(MetadataServiceBoundaryError::LimitExceeded);
        }
        result.push(value.to_owned());
    }
    Ok(result)
}

fn semantic_fingerprint(operation: MetadataOperation, body: &Value) -> BoundaryResult<[u8; 32]> {
    let projection = serde_json::json!({
        "schemaVersion": METADATA_SERVICE_REQUEST_SCHEMA,
        "operation": operation.name(),
        "body": body,
        "extensions": {},
    });
    let canonical = canonical_json_bytes(&projection)?;
    if canonical.len() > CONTROL_MESSAGE_BYTES_MAXIMUM {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    let mut digest = Sha256::new();
    digest.update(IDEMPOTENCY_FINGERPRINT_DOMAIN);
    digest.update(canonical);
    Ok(digest.finalize().into())
}

fn idempotency_window(key: &str) -> BoundaryResult<(u64, u64)> {
    let mut parts = key.split('.');
    if parts.next() != Some("ik1") {
        return input_invalid();
    }
    let issued = canonical_decimal(
        parts
            .next()
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?,
    )?;
    let expires = canonical_decimal(
        parts
            .next()
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?,
    )?;
    let entropy = parts
        .next()
        .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
    if parts.next().is_some()
        || !(22..=218).contains(&entropy.len())
        || !entropy
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || expires <= issued
        || expires - issued > 86_400_000
    {
        return input_invalid();
    }
    Ok((issued, expires))
}

fn canonical_decimal(value: &str) -> BoundaryResult<u64> {
    if value.is_empty()
        || value.len() > 16
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return input_invalid();
    }
    let value = value
        .parse()
        .map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
    if value > JSON_SAFE_INTEGER_MAXIMUM {
        Err(MetadataServiceBoundaryError::LimitExceeded)
    } else {
        Ok(value)
    }
}

impl MetadataHttpResponse {
    pub fn success_json(operation: MetadataOperation, mut body: Value) -> crate::Result<Self> {
        normalize_json_numbers(&mut body)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if !operation.generic_json_result()
            || body.as_object().is_none_or(|body| body.len() > 128)
            || response_json_bytes(&body)? > SAFE_RESULT_BYTES_MAXIMUM
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(Self::new(operation, "success", "json", body))
    }

    pub fn page<T: Serialize>(
        operation: MetadataOperation,
        page: Page<T>,
        consistency: &ConsistencyToken,
    ) -> crate::Result<Self> {
        if !operation.is_page() || page.items.len() > usize::from(PUBLIC_PAGE_ITEMS_MAXIMUM) {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let state = if page.next_cursor.is_some() {
            PageState::More
        } else {
            PageState::Complete
        };
        page_response(
            operation,
            state,
            page.items,
            page.next_cursor,
            None,
            consistency,
        )
    }

    pub fn history_page<T: Serialize>(
        operation: MetadataOperation,
        page: HistoryPage<T>,
        consistency: &ConsistencyToken,
    ) -> crate::Result<Self> {
        let shape_valid = match page.state {
            PageState::More => page.next_cursor.is_some() && page.incomplete_reason.is_none(),
            PageState::Complete => page.next_cursor.is_none() && page.incomplete_reason.is_none(),
            PageState::Incomplete => page.incomplete_reason.is_some(),
        };
        if !shape_valid
            || !matches!(
                operation,
                MetadataOperation::HistoryAncestryPage
                    | MetadataOperation::HistoryFileIdPage
                    | MetadataOperation::HistoryPathPage
                    | MetadataOperation::FileIdHistory
            )
            || page.items.len() > usize::from(PUBLIC_PAGE_ITEMS_MAXIMUM)
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        page_response(
            operation,
            page.state,
            page.items,
            page.next_cursor,
            page.incomplete_reason,
            consistency,
        )
    }

    pub fn file_id_allocation(allocation: &FileIdAllocation) -> crate::Result<Self> {
        let expires = unix_ms(allocation.expires_at)?;
        let repository_id = public_uuid_text(allocation.repository_id.as_bytes())?;
        Ok(Self::new(
            MetadataOperation::FileIdAllocate,
            "success",
            "json",
            serde_json::json!({
                "schemaVersion": "ogvcs.repository-metadata/file-id-allocation/v1",
                "repositoryId": repository_id,
                "fileId": allocation.file_id.to_string(),
                "allocationReceipt": allocation.allocation_receipt.as_str(),
                "expiresAtUnixMs": expires,
            }),
        ))
    }

    pub fn idempotency_status(status: &IdempotencyStatus) -> crate::Result<Self> {
        let body = match status {
            IdempotencyStatus::Absent => serde_json::json!({
                "schemaVersion": "ogvcs.repository-metadata/idempotency-status/v1",
                "state": "absent",
            }),
            IdempotencyStatus::Reserved { expires_at } => serde_json::json!({
                "schemaVersion": "ogvcs.repository-metadata/idempotency-status/v1",
                "state": "reserved",
                "expiresAtUnixMs": unix_ms(*expires_at)?,
            }),
            IdempotencyStatus::Committed {
                expires_at,
                safe_result,
            } => {
                let safe_result = bounded_json_value(safe_result, SAFE_RESULT_BYTES_MAXIMUM)?;
                serde_json::json!({
                    "schemaVersion": "ogvcs.repository-metadata/idempotency-status/v1",
                    "state": "committed",
                    "expiresAtUnixMs": unix_ms(*expires_at)?,
                    "safeResult": safe_result,
                })
            }
        };
        if response_json_bytes(&body)? > SAFE_RESULT_BYTES_MAXIMUM {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(Self::new(
            MetadataOperation::IdempotencyStatus,
            "success",
            "json",
            body,
        ))
    }

    pub fn object_stream(
        object_ref: ObjectRef,
        canonical_byte_length: u64,
        stream_digest: [u8; 32],
    ) -> crate::Result<Self> {
        if !metadata_kind(object_ref.kind)
            || canonical_byte_length > PUBLIC_CANONICAL_METADATA_BYTES_MAXIMUM
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(Self::new(
            MetadataOperation::ObjectGet,
            "success",
            "canonical-metadata-byte-stream",
            serde_json::json!({
                "objectRef": object_ref.to_string(),
                "canonicalByteLength": canonical_byte_length,
                "streamDigestSha256": hex(&stream_digest),
            }),
        ))
    }

    pub fn domain_error(operation: MetadataOperation, error: &DomainError) -> Self {
        let mut safe_parameters = Map::new();
        match error.code {
            DomainErrorCode::ConsistencyTokenUnsatisfied
            | DomainErrorCode::TransactionRetryExhausted => {
                if let Some(retry_after @ 0..=86_400_000) = error.retry_after_ms {
                    safe_parameters.insert("retryAfterMs".to_owned(), retry_after.into());
                }
            }
            _ => {}
        }
        Self::new(
            operation,
            "domain-error",
            "domain-error",
            serde_json::json!({
                "schemaVersion": "ogvcs.repository-metadata/domain-error/v1",
                "code": error.code.name(),
                "numericCode": error.code as u16,
                "retryable": error.code.retryable(),
                "safeParameters": safe_parameters,
            }),
        )
    }

    fn new(
        operation: MetadataOperation,
        outcome: &'static str,
        carrier: &'static str,
        body: Value,
    ) -> Self {
        Self {
            schema_version: METADATA_SERVICE_RESPONSE_SCHEMA,
            operation: operation.name(),
            outcome,
            carrier,
            body,
        }
    }
}

fn page_response<T: Serialize>(
    operation: MetadataOperation,
    state: PageState,
    items: Vec<T>,
    next_cursor: Option<CursorToken>,
    incomplete_reason: Option<HistoryIncompleteReason>,
    consistency: &ConsistencyToken,
) -> crate::Result<MetadataHttpResponse> {
    let items = bounded_json_value(&items, SAFE_RESULT_BYTES_MAXIMUM)?;
    let body = serde_json::json!({
        "schemaVersion": "ogvcs.repository-metadata/page-result/v1",
        "operation": operation.name(),
        "state": match state { PageState::More => "more", PageState::Complete => "complete", PageState::Incomplete => "incomplete" },
        "items": items,
        "nextCursor": next_cursor.map(|value| value.as_str().to_owned()),
        "incompleteReason": incomplete_reason.map(|reason| match reason {
            HistoryIncompleteReason::DepthLimit => "depth-limit",
            HistoryIncompleteReason::WorkLimit => "work-limit",
            HistoryIncompleteReason::RetentionGap => "retention-gap",
        }),
        "consistencyToken": consistency.as_str(),
    });
    if response_json_bytes(&body)? > SAFE_RESULT_BYTES_MAXIMUM {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok(MetadataHttpResponse::new(
        operation,
        "success",
        "page-result",
        body,
    ))
}

fn bounded_json_value<T: Serialize + ?Sized>(value: &T, maximum: usize) -> crate::Result<Value> {
    let mut output = BoundedJsonBuffer::new(maximum);
    serde_json::to_writer(&mut output, value)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let StrictValue(mut value) = serde_json::from_slice(output.as_slice())
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    normalize_json_numbers(&mut value)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    inspect_json(&value).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok(value)
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedJsonBuffer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Write for BoundedJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "bounded metadata JSON response exceeded its limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn response_json_bytes(value: &Value) -> crate::Result<usize> {
    inspect_json(value).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    canonical_json_bytes(value)
        .map(|bytes| bytes.len())
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn unix_ms(value: SystemTime) -> crate::Result<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .filter(|value| *value <= JSON_SAFE_INTEGER_MAXIMUM)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn public_uuid_text(bytes: &[u8; 16]) -> crate::Result<String> {
    let version = bytes[6] >> 4;
    let variant = bytes[8] >> 6;
    if !(1..=8).contains(&version) || variant != 0b10 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok(Uuid::from_bytes(*bytes).to_string())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn object(value: &Value) -> BoundaryResult<&Map<String, Value>> {
    value
        .as_object()
        .ok_or(MetadataServiceBoundaryError::InputInvalid)
}

fn required<'a>(body: &'a Map<String, Value>, key: &str) -> BoundaryResult<&'a Value> {
    body.get(key)
        .ok_or(MetadataServiceBoundaryError::InputInvalid)
}

fn exact_members(body: &Map<String, Value>, expected: &[&str]) -> BoundaryResult<()> {
    if body.len() != expected.len() || body.keys().any(|key| !expected.contains(&key.as_str())) {
        input_invalid()
    } else {
        Ok(())
    }
}

fn value_text(value: &Value, minimum: usize, maximum: usize) -> BoundaryResult<&str> {
    let value = value
        .as_str()
        .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
    let characters = value.chars().count();
    if characters < minimum {
        return input_invalid();
    }
    if characters > maximum {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    Ok(value)
}

fn text<'a>(
    body: &'a Map<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> BoundaryResult<&'a str> {
    value_text(required(body, key)?, minimum, maximum)
}

fn persisted_identifier<'a>(body: &'a Map<String, Value>, key: &str) -> BoundaryResult<&'a str> {
    let value = text(body, key, 1, PERSISTED_IDENTIFIER_BYTES_MAXIMUM)?;
    if value.len() > PERSISTED_IDENTIFIER_BYTES_MAXIMUM {
        Err(MetadataServiceBoundaryError::LimitExceeded)
    } else if value.contains('\0') {
        input_invalid()
    } else {
        Ok(value)
    }
}

fn is_c0_or_del(value: char) -> bool {
    matches!(value, '\0'..='\u{1f}' | '\u{7f}')
}

fn metadata_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::ContentManifest
            | ObjectKind::Tree
            | ObjectKind::ChangeSet
            | ObjectKind::AssetGroupSet
            | ObjectKind::RepositoryDescriptor
            | ObjectKind::Snapshot
            | ObjectKind::Provenance
            | ObjectKind::Attestation
            | ObjectKind::ConflictSet
    )
}

fn enum_text<'a>(
    body: &'a Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> BoundaryResult<&'a str> {
    let value = text(body, key, 1, 64)?;
    if allowed.contains(&value) {
        Ok(value)
    } else {
        input_invalid()
    }
}

fn value_uint(value: &Value, maximum: u64) -> BoundaryResult<u64> {
    let value = value
        .as_u64()
        .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
    if value > maximum {
        Err(MetadataServiceBoundaryError::LimitExceeded)
    } else {
        Ok(value)
    }
}

fn uint(body: &Map<String, Value>, key: &str, maximum: u64) -> BoundaryResult<u64> {
    value_uint(required(body, key)?, maximum)
}

fn array<'a>(
    body: &'a Map<String, Value>,
    key: &str,
    maximum: usize,
    minimum: usize,
) -> BoundaryResult<&'a [Value]> {
    let values = required(body, key)?
        .as_array()
        .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
    if values.len() < minimum {
        return input_invalid();
    }
    if values.len() > maximum {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    Ok(values)
}

fn public_uuid(body: &Map<String, Value>, key: &str) -> BoundaryResult<[u8; 16]> {
    let value = text(body, key, 36, 36)?;
    let parsed = Uuid::parse_str(value).map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
    let bytes = *parsed.as_bytes();
    if parsed.to_string() != value || !(1..=8).contains(&(bytes[6] >> 4)) || bytes[8] & 0xc0 != 0x80
    {
        return input_invalid();
    }
    Ok(bytes)
}

fn tenant_id(body: &Map<String, Value>, key: &str) -> BoundaryResult<TenantId> {
    public_uuid(body, key).map(TenantId::from_bytes)
}

fn repository_id(body: &Map<String, Value>, key: &str) -> BoundaryResult<RepositoryId> {
    public_uuid(body, key).map(RepositoryId::from_bytes)
}

fn project_id(body: &Map<String, Value>, key: &str) -> BoundaryResult<ProjectId> {
    public_uuid(body, key).map(ProjectId::from_bytes)
}

fn object_ref(body: &Map<String, Value>, key: &str) -> BoundaryResult<ObjectRef> {
    let value = text(body, key, 1, 144)?;
    let reference =
        ObjectRef::from_str(value).map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
    if reference.to_string() == value {
        Ok(reference)
    } else {
        input_invalid()
    }
}

fn nullable_object_ref(body: &Map<String, Value>, key: &str) -> BoundaryResult<Option<ObjectRef>> {
    let value = required(body, key)?;
    if value.is_null() {
        Ok(None)
    } else {
        let text = value_text(value, 1, 144)?;
        let reference =
            ObjectRef::from_str(text).map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
        if reference.to_string() == text {
            Ok(Some(reference))
        } else {
            input_invalid()
        }
    }
}

fn file_id(body: &Map<String, Value>, key: &str) -> BoundaryResult<FileId> {
    let value = text(body, key, 36, 36)?;
    let file_id =
        FileId::from_str(value).map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
    if file_id.to_string() == value {
        Ok(file_id)
    } else {
        input_invalid()
    }
}

fn profile(body: &Map<String, Value>, key: &str) -> BoundaryResult<ProfileRef> {
    ProfileRef::from_str(text(body, key, 1, 328)?)
        .map_err(|_| MetadataServiceBoundaryError::InputInvalid)
}

fn digest32(body: &Map<String, Value>, key: &str) -> BoundaryResult<[u8; 32]> {
    let value = text(body, key, 64, 64)?;
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(digest)
}

fn nibble(value: u8) -> BoundaryResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => input_invalid(),
    }
}

fn reference_name<'a>(body: &'a Map<String, Value>, key: &str) -> BoundaryResult<&'a str> {
    let value = text(body, key, 1, REFERENCE_NAME_BYTES_MAXIMUM)?;
    if value.len() > REFERENCE_NAME_BYTES_MAXIMUM {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    if value.contains('\0') {
        input_invalid()
    } else {
        Ok(value)
    }
}

fn optional_consistency(
    body: &Map<String, Value>,
    key: &str,
) -> BoundaryResult<Option<ConsistencyToken>> {
    let value = required(body, key)?;
    if value.is_null() {
        return Ok(None);
    }
    let value = value_text(value, 47, 47)?;
    ConsistencyToken::from_opaque(value.to_owned())
        .map(Some)
        .ok_or(MetadataServiceBoundaryError::InputInvalid)
}

fn optional_cursor(body: &Map<String, Value>, key: &str) -> BoundaryResult<Option<CursorToken>> {
    let value = required(body, key)?;
    if value.is_null() {
        return Ok(None);
    }
    let value = value_text(value, 48, 48)?;
    CursorToken::from_opaque(value.to_owned())
        .map(Some)
        .ok_or(MetadataServiceBoundaryError::InputInvalid)
}

fn canonical_json_bytes(value: &Value) -> BoundaryResult<Vec<u8>> {
    serde_json::to_vec(&canonical_json(value.clone()))
        .map_err(|_| MetadataServiceBoundaryError::InputInvalid)
}

fn normalize_json_numbers(value: &mut Value) -> BoundaryResult<()> {
    let mut state = JsonInspection::default();
    normalize_json_numbers_inner(value, 0, &mut state)
}

fn normalize_json_numbers_inner(
    value: &mut Value,
    depth: usize,
    state: &mut JsonInspection,
) -> BoundaryResult<()> {
    state.nodes = state.nodes.saturating_add(1);
    if depth > JSON_DEPTH_MAXIMUM || state.nodes > JSON_NODES_MAXIMUM {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                return if value <= JSON_SAFE_INTEGER_MAXIMUM {
                    Ok(())
                } else {
                    Err(MetadataServiceBoundaryError::LimitExceeded)
                };
            }
            if let Some(value) = number.as_i64() {
                return if value >= -(JSON_SAFE_INTEGER_MAXIMUM as i64)
                    && value <= JSON_SAFE_INTEGER_MAXIMUM as i64
                {
                    Ok(())
                } else {
                    Err(MetadataServiceBoundaryError::LimitExceeded)
                };
            }
            let value = number
                .as_f64()
                .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
            if !value.is_finite() || value.fract() != 0.0 {
                return input_invalid();
            }
            if value.abs() > JSON_SAFE_INTEGER_MAXIMUM as f64 {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            *number = if value >= 0.0 {
                Number::from(value as u64)
            } else {
                Number::from(value as i64)
            };
            Ok(())
        }
        Value::String(value) if value.len() > JSON_STRING_BYTES_MAXIMUM => {
            Err(MetadataServiceBoundaryError::LimitExceeded)
        }
        Value::Array(values) => {
            state.collection_items = state.collection_items.saturating_add(values.len());
            if state.collection_items > JSON_COLLECTION_ITEMS_MAXIMUM {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            for value in values {
                normalize_json_numbers_inner(value, depth + 1, state)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > JSON_OBJECT_MEMBERS_MAXIMUM {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            state.collection_items = state.collection_items.saturating_add(values.len());
            if state.collection_items > JSON_COLLECTION_ITEMS_MAXIMUM
                || values.keys().any(|key| key.len() > JSON_KEY_BYTES_MAXIMUM)
            {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            for value in values.values_mut() {
                normalize_json_numbers_inner(value, depth + 1, state)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        Value::Object(values) => {
            let values: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect();
            Value::Object(values.into_iter().collect())
        }
        value => value,
    }
}

fn inspect_json(value: &Value) -> BoundaryResult<()> {
    let mut state = JsonInspection::default();
    inspect_json_inner(value, 0, &mut state)
}

#[derive(Default)]
struct JsonInspection {
    nodes: usize,
    collection_items: usize,
}

fn inspect_json_inner(
    value: &Value,
    depth: usize,
    state: &mut JsonInspection,
) -> BoundaryResult<()> {
    state.nodes = state.nodes.saturating_add(1);
    if depth > JSON_DEPTH_MAXIMUM || state.nodes > JSON_NODES_MAXIMUM {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    match value {
        Value::Number(value) => {
            let safe_unsigned = value
                .as_u64()
                .is_some_and(|value| value <= JSON_SAFE_INTEGER_MAXIMUM);
            let safe_signed = value.as_i64().is_some_and(|value| {
                value >= -(JSON_SAFE_INTEGER_MAXIMUM as i64)
                    && value <= JSON_SAFE_INTEGER_MAXIMUM as i64
            });
            if safe_unsigned || safe_signed {
                Ok(())
            } else {
                Err(MetadataServiceBoundaryError::LimitExceeded)
            }
        }
        Value::String(value) if value.len() > JSON_STRING_BYTES_MAXIMUM => {
            Err(MetadataServiceBoundaryError::LimitExceeded)
        }
        Value::Array(values) => {
            state.collection_items = state.collection_items.saturating_add(values.len());
            if state.collection_items > JSON_COLLECTION_ITEMS_MAXIMUM {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            for value in values {
                inspect_json_inner(value, depth + 1, state)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > JSON_OBJECT_MEMBERS_MAXIMUM {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            state.collection_items = state.collection_items.saturating_add(values.len());
            if state.collection_items > JSON_COLLECTION_ITEMS_MAXIMUM
                || values.keys().any(|key| key.len() > JSON_KEY_BYTES_MAXIMUM)
            {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            for value in values.values() {
                inspect_json_inner(value, depth + 1, state)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor).map(Self)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("duplicate-free JSON")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON member"));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(Value::Object(values))
    }
}

fn input_invalid<T>() -> BoundaryResult<T> {
    Err(MetadataServiceBoundaryError::InputInvalid)
}
