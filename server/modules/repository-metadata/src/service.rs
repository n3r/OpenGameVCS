//! Framework-neutral OGVCS-006 public service contract boundary.
//!
//! This module validates and classifies the complete candidate operation set
//! and implements its framework-neutral OGVCS-041 route adapter. Syntax and
//! route admission are not mutation authority: ordinary reference CAS, FileID
//! tombstone/restore, internal outbox delivery, and submit publication remain
//! behind their exact coordinator boundaries.

use crate::{
    AllocationReceipt, CaseMode, CommitSequence, ConsistencyToken, CursorToken, DomainError,
    DomainErrorCode, FileIdAllocation, HistoryIncompleteReason, HistoryPage,
    IdempotencyReservation, IdempotencyStatus, MetadataHttpResponse, MetadataPermission, Page,
    PageState, ProjectId, ReferenceKind, ReferenceName, ReferenceRecord, RepositoryId,
    RepositorySettings, TenantId,
};
use base64::Engine as _;
use hmac::{Hmac, Mac};
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
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

pub const METADATA_SERVICE_CONTRACT_VERSION: &str = "0.3.0";
pub const METADATA_SERVICE_REQUEST_SCHEMA: &str = "ogvcs.protocol/request-envelope/v1";
pub const METADATA_SERVICE_RESPONSE_SCHEMA: &str = "ogvcs.protocol/response-envelope/v1";
pub const METADATA_SERVICE_RESULT_BODY_SCHEMA: &str = "ogvcs.repository-metadata/result-body/v1";
pub const METADATA_SERVICE_MANIFEST_SHA256: &str =
    "58e595947993900f530fa16a9181f3a064fd66d0363f5ae976017c162a57cdde";
pub const OGVCS_041_MANIFEST_SHA256: &str = opengamevcs_protocol_v1::CONTRACT_MANIFEST_SHA256;
pub const OGVCS_041_REGISTRY_SET_SHA256: &str =
    "2a49361363cc16e743948fa3cc5e266cd1bc6e31b312cde15b5dab1ad7e5c5b0";
pub const OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256: &str =
    "2b1913f9451b9f99966a24942a262846f07662b17cbb41ad6eea6474c23b4352";
pub const OGVCS_041_CONTROL_PROFILE_SHA256: &str =
    "3934506ee6d21005dc4b9b91e924e33601de3ade5417e4393a8acb8178bb36f9";
pub const OGVCS_041_REQUEST_ENVELOPE_SHA256: &str =
    "740fc71a4ba1e480076b8b6d3fc8bb5b5374e86157976747795a139694bbadd9";
pub const OGVCS_041_RESPONSE_ENVELOPE_SHA256: &str =
    "47792190106b0742af4245c69eff3eb9d6e9555c557b16f23fae3d12d8790900";
pub const OGVCS_041_PROBLEM_DETAILS_SHA256: &str =
    "deba5763c47a54e23489d427eb094fa905fadfa81806a3e2da5f752501dfb6a1";
pub const OGVCS_041_ERROR_REGISTRY_SHA256: &str =
    "2801e26224536b8b9f2072324d25c6b472274ce45135bd65e6e9e11a643a922f";
pub const METADATA_PROTOCOL_PROFILE: &str = opengamevcs_protocol_v1::PROTOCOL_VERSION;
pub const METADATA_CONTROL_MEDIA_TYPE: &str = "application/json";
pub const METADATA_RESPONSE_MEDIA_TYPE: &str = "application/json";
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
const PROTOCOL_JSON_VALUE_DEPTH_MAXIMUM: usize = 32;
const PROTOCOL_JSON_VALUE_NODES_MAXIMUM: usize = 10_000;
const PROTOCOL_JSON_ARRAY_ITEMS_MAXIMUM: usize = 4_096;
const PROTOCOL_EXTENSION_VALUE_DEPTH_MAXIMUM: usize = 8;
const PROTOCOL_EXTENSION_VALUE_NODES_MAXIMUM: usize = 1_000;
const JSON_STRING_BYTES_MAXIMUM: usize = 65_536;
const JSON_KEY_BYTES_MAXIMUM: usize = 256;
const REFERENCE_NAME_BYTES_MAXIMUM: usize = 512;
const PATH_SEGMENTS_MAXIMUM: usize = 256;
const PATH_SEGMENT_BYTES_MAXIMUM: usize = 255;
const PATH_BYTES_MAXIMUM: usize = 4_096;
const IDEMPOTENCY_KEY_SCHEMA_BYTES_MAXIMUM: usize = 256;
const PERSISTED_IDENTIFIER_BYTES_MAXIMUM: usize = 256;
const SAFE_RESULT_BYTES_MAXIMUM: usize = 1_048_576;
const JSON_SAFE_INTEGER_MAXIMUM: u64 = 9_007_199_254_740_991;
const METADATA_NEGOTIATION_TENANT_DOMAIN: &[u8] = b"OGVCS-METADATA-NEGOTIATION-TENANT-BINDING-V1\0";
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
    AtomicCreateCoordinator,
    ProjectAuthorityRequired,
    VariantGated,
    StreamCarrierRequired,
    AggregateCoordinatorRequired,
    InternalOnly,
}

impl MetadataOperationExposure {
    /// No v0.3 operation may be handed to a network router. The authenticated
    /// route assignments are frozen for interop, but an operation becomes
    /// network-registered only with an end-to-end identity/coordinator
    /// dispatcher that retains its authorization brand through the response.
    pub const fn network_registered(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataStreamBinding {
    None,
    BoundedPage,
    CarrierUnassignedClosed,
}

impl MetadataStreamBinding {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BoundedPage => "bounded-page",
            Self::CarrierUnassignedClosed => "carrier-unassigned-closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataTransportDescriptor {
    pub operation: MetadataOperation,
    pub method: &'static str,
    pub path: &'static str,
    pub request_media_type: &'static str,
    pub success_status: u16,
    pub success_media_type: &'static str,
    pub error_media_type: &'static str,
    pub stream: MetadataStreamBinding,
    pub exposure: MetadataOperationExposure,
    pub network_registered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataTransportError {
    Malformed,
    LimitExceeded,
    Unsupported,
    AuthorizationDenied,
    CompressionForbidden,
    RedirectForbidden,
    NegotiationReceiptInvalid,
    NegotiationReceiptExpired,
    DeadlineExceeded,
}

impl MetadataTransportError {
    pub const fn protocol_code(self) -> &'static str {
        match self {
            Self::Malformed => "PROTOCOL_MALFORMED",
            Self::LimitExceeded => "PROTOCOL_LIMIT_EXCEEDED",
            Self::Unsupported => "PROTOCOL_UNSUPPORTED",
            Self::AuthorizationDenied => "AUTHORIZATION_DENIED",
            Self::CompressionForbidden => "COMPRESSION_FORBIDDEN",
            Self::RedirectForbidden => "REDIRECT_FORBIDDEN",
            Self::NegotiationReceiptInvalid => "NEGOTIATION_RECEIPT_INVALID",
            Self::NegotiationReceiptExpired => "NEGOTIATION_RECEIPT_EXPIRED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataTransportRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub request_media_type: &'a str,
    pub accept: &'a str,
    pub content_coding: &'a str,
    pub redirect_hops: u8,
    pub control: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedMetadataRoute {
    descriptor: &'static MetadataTransportDescriptor,
    request: MetadataOperationRequest,
}

/// Supplies active server negotiation keys without exposing them through the
/// request or response model.
pub trait MetadataNegotiationKeyProvider {
    fn key(&self, key_id: &str) -> Option<&[u8]>;
}

/// Bounded server-owned key ring used to reverify a negotiation brand at the
/// PostgreSQL dispatch boundary. Holding an independently constructed ring is
/// not enough: the dispatcher always uses the ring installed at startup.
pub struct MetadataNegotiationKeyRing {
    keys: BTreeMap<String, Box<[u8]>>,
}

impl MetadataNegotiationKeyRing {
    pub fn new(
        entries: Vec<(String, Vec<u8>)>,
    ) -> std::result::Result<Self, MetadataServiceBoundaryError> {
        if entries.is_empty() || entries.len() > 16 {
            return input_invalid();
        }
        let mut keys = BTreeMap::new();
        for (key_id, key) in entries {
            if !(1..=256).contains(&key_id.len())
                || !protocol_identifier(&key_id)
                || !(32..=64).contains(&key.len())
                || keys.insert(key_id, key.into_boxed_slice()).is_some()
            {
                return input_invalid();
            }
        }
        Ok(Self { keys })
    }
}

impl MetadataNegotiationKeyProvider for MetadataNegotiationKeyRing {
    fn key(&self, key_id: &str) -> Option<&[u8]> {
        self.keys.get(key_id).map(AsRef::as_ref)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataNegotiationPrincipal {
    pub subject_digest: [u8; 32],
    pub tenant_digest: [u8; 32],
    pub authority_epoch: u64,
    pub session_id: String,
    pub now_unix_ms: u64,
}

impl MetadataNegotiationPrincipal {
    pub(crate) const fn subject_digest(&self) -> &[u8; 32] {
        &self.subject_digest
    }

    pub(crate) const fn tenant_digest(&self) -> &[u8; 32] {
        &self.tenant_digest
    }

    pub(crate) const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }
}

/// Brand returned only after the receipt MAC, selected authority tuple,
/// principal/session binding, and currentness have all been revalidated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationVerifiedMetadataRoute {
    admitted: AdmittedMetadataRoute,
}

/// Syntax-only request brand returned after OGVCS-041 negotiation receipt
/// verification. This is deliberately not an OGVCS-009 authorization brand
/// and cannot construct a success response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiationVerifiedMetadataRequest {
    request: MetadataOperationRequest,
    principal: MetadataNegotiationPrincipal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataServerCorrelationId(String);

impl MetadataServerCorrelationId {
    /// Creates a bounded server-generated correlation ID for failures that
    /// occur before a request correlation ID can be safely parsed. Callers
    /// must not reflect unvalidated request bytes into this value.
    pub fn new(value: String) -> BoundaryResult<Self> {
        if (16..=128).contains(&value.len()) && ascii_token(&value) {
            Ok(Self(value))
        } else {
            input_invalid()
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact OGVCS-041 `ResponseEnvelope`. Metadata result values exist only as
/// its `body`; unassigned metadata domain errors cannot be emitted as wire
/// problems through this type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataResponseEnvelope {
    schema_version: &'static str,
    correlation_id: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<MetadataProtocolProblem>,
}

pub(crate) struct PreparedMetadataDispatchSuccess {
    body: Value,
}

impl PreparedMetadataDispatchSuccess {
    pub(crate) const fn decision_result(&self) -> &Value {
        &self.body
    }
}

/// Private adapter projection used only to join an authenticated negotiation
/// principal to the exact parsed metadata tenant. OGVCS-041 intentionally
/// treats `tenantDigest` as opaque; this is not a protocol-level mapping.
pub(crate) fn metadata_negotiation_tenant_digest(tenant_id: TenantId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(METADATA_NEGOTIATION_TENANT_DOMAIN);
    digest.update(tenant_id.as_bytes());
    digest.finalize().into()
}

/// Closed registered OGVCS-041 `ProblemDetails` subset used by this adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataProtocolProblem {
    #[serde(rename = "type")]
    problem_type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    retryable: bool,
    correlation_id: String,
}

impl AdmittedMetadataRoute {
    pub const fn descriptor(&self) -> &'static MetadataTransportDescriptor {
        self.descriptor
    }

    pub const fn request(&self) -> &MetadataOperationRequest {
        &self.request
    }

    pub fn into_request(self) -> MetadataOperationRequest {
        self.request
    }

    pub fn verify_negotiation<K: MetadataNegotiationKeyProvider>(
        &self,
        keys: &K,
        principal: &MetadataNegotiationPrincipal,
    ) -> std::result::Result<NegotiationVerifiedMetadataRoute, MetadataTransportError> {
        self.request.verify_negotiation(keys, principal)?;
        Ok(NegotiationVerifiedMetadataRoute {
            admitted: self.clone(),
        })
    }

    pub fn problem_response(&self, error: MetadataTransportError) -> MetadataResponseEnvelope {
        MetadataResponseEnvelope {
            schema_version: METADATA_SERVICE_RESPONSE_SCHEMA,
            correlation_id: self.request.correlation_id().to_owned(),
            success: false,
            body: None,
            problem: Some(MetadataProtocolProblem::registered(
                error,
                self.request.correlation_id(),
            )),
        }
    }
}

impl NegotiationVerifiedMetadataRoute {
    pub const fn descriptor(&self) -> &'static MetadataTransportDescriptor {
        self.admitted.descriptor
    }

    pub const fn request(&self) -> &MetadataOperationRequest {
        &self.admitted.request
    }

    pub fn into_request(self) -> MetadataOperationRequest {
        self.admitted.request
    }
}

impl NegotiationVerifiedMetadataRequest {
    pub const fn request(&self) -> &MetadataOperationRequest {
        &self.request
    }

    pub fn into_request(self) -> MetadataOperationRequest {
        self.request
    }

    pub(crate) const fn principal(&self) -> &MetadataNegotiationPrincipal {
        &self.principal
    }

    pub(crate) fn reverify_at<K: MetadataNegotiationKeyProvider>(
        &self,
        keys: &K,
        now_unix_ms: u64,
    ) -> std::result::Result<(), MetadataTransportError> {
        let mut principal = self.principal.clone();
        principal.now_unix_ms = now_unix_ms;
        self.request
            .verify_negotiation(keys, &principal)
            .map(|_| ())
    }
}

impl MetadataResponseEnvelope {
    pub fn preparse_problem(
        correlation_id: &MetadataServerCorrelationId,
        error: MetadataTransportError,
    ) -> BoundaryResult<Self> {
        if matches!(
            error,
            MetadataTransportError::AuthorizationDenied
                | MetadataTransportError::NegotiationReceiptInvalid
                | MetadataTransportError::NegotiationReceiptExpired
                | MetadataTransportError::DeadlineExceeded
        ) {
            return input_invalid();
        }
        Ok(Self {
            schema_version: METADATA_SERVICE_RESPONSE_SCHEMA,
            correlation_id: correlation_id.as_str().to_owned(),
            success: false,
            body: None,
            problem: Some(MetadataProtocolProblem::registered(
                error,
                correlation_id.as_str(),
            )),
        })
    }

    pub(crate) fn prepare_authorized_dispatch(
        result: MetadataHttpResponse,
    ) -> BoundaryResult<PreparedMetadataDispatchSuccess> {
        let body =
            serde_json::to_value(result).map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
        inspect_protocol_json_value(
            &body,
            PROTOCOL_JSON_VALUE_DEPTH_MAXIMUM,
            PROTOCOL_JSON_VALUE_NODES_MAXIMUM,
        )?;
        Ok(PreparedMetadataDispatchSuccess { body })
    }

    pub(crate) fn success_for_committed_dispatch(
        _committed: crate::postgres::CommittedMetadataReadDispatch,
        correlation_id: &str,
        prepared: PreparedMetadataDispatchSuccess,
    ) -> Self {
        Self {
            schema_version: METADATA_SERVICE_RESPONSE_SCHEMA,
            correlation_id: correlation_id.to_owned(),
            success: true,
            body: Some(prepared.body),
            problem: None,
        }
    }

    pub const fn schema_version(&self) -> &'static str {
        self.schema_version
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    pub const fn success(&self) -> bool {
        self.success
    }

    pub fn body(&self) -> Option<&Value> {
        self.body.as_ref()
    }

    pub const fn problem(&self) -> Option<&MetadataProtocolProblem> {
        self.problem.as_ref()
    }
}

impl MetadataProtocolProblem {
    fn registered(error: MetadataTransportError, correlation_id: &str) -> Self {
        let (problem_type, title, status, retryable) = match error {
            MetadataTransportError::Malformed => (
                "https://errors.opengamevcs.dev/protocol/v1/protocol-malformed",
                "Malformed protocol message",
                400,
                false,
            ),
            MetadataTransportError::LimitExceeded => (
                "https://errors.opengamevcs.dev/protocol/v1/protocol-limit-exceeded",
                "Protocol resource limit exceeded",
                413,
                true,
            ),
            MetadataTransportError::Unsupported => (
                "https://errors.opengamevcs.dev/protocol/v1/protocol-unsupported",
                "Protocol profile unsupported",
                426,
                false,
            ),
            MetadataTransportError::AuthorizationDenied => (
                "https://errors.opengamevcs.dev/protocol/v1/authorization-denied",
                "Operation not authorized",
                403,
                false,
            ),
            MetadataTransportError::CompressionForbidden => (
                "https://errors.opengamevcs.dev/protocol/v1/compression-forbidden",
                "Content coding forbidden",
                415,
                false,
            ),
            MetadataTransportError::RedirectForbidden => (
                "https://errors.opengamevcs.dev/protocol/v1/redirect-forbidden",
                "Redirect forbidden",
                409,
                false,
            ),
            MetadataTransportError::NegotiationReceiptInvalid => (
                "https://errors.opengamevcs.dev/protocol/v1/negotiation-receipt-invalid",
                "Negotiation receipt invalid",
                401,
                false,
            ),
            MetadataTransportError::NegotiationReceiptExpired => (
                "https://errors.opengamevcs.dev/protocol/v1/negotiation-receipt-expired",
                "Negotiation receipt expired",
                401,
                true,
            ),
            MetadataTransportError::DeadlineExceeded => (
                "https://errors.opengamevcs.dev/protocol/v1/deadline-exceeded",
                "Deadline exceeded",
                504,
                true,
            ),
        };
        Self {
            problem_type,
            title,
            status,
            code: error.protocol_code(),
            retryable,
            correlation_id: correlation_id.to_owned(),
        }
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }
}

const TRANSPORT_BASE_CAPABILITIES: &[&str] = &[
    "ogvcs.control.https-json@1",
    "ogvcs.protocol.schema@1",
    "ogvcs.authorization@1",
    "ogvcs.receipt.hmac-sha256@1",
];
const TRANSPORT_MUTATION_CAPABILITIES: &[&str] = &[
    "ogvcs.control.https-json@1",
    "ogvcs.protocol.schema@1",
    "ogvcs.authorization@1",
    "ogvcs.receipt.hmac-sha256@1",
    "ogvcs.idempotency.semantic-jcs@1",
];
impl MetadataTransportDescriptor {
    pub const fn required_capabilities(self) -> &'static [&'static str] {
        match self.operation.descriptor().idempotency_required {
            false => TRANSPORT_BASE_CAPABILITIES,
            true => TRANSPORT_MUTATION_CAPABILITIES,
        }
    }
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

macro_rules! transport {
    ($operation:ident, $path:literal, $status:literal, $media:expr, $stream:ident, $exposure:ident) => {
        MetadataTransportDescriptor {
            operation: MetadataOperation::$operation,
            method: "POST",
            path: $path,
            request_media_type: METADATA_CONTROL_MEDIA_TYPE,
            success_status: $status,
            success_media_type: $media,
            error_media_type: METADATA_RESPONSE_MEDIA_TYPE,
            stream: MetadataStreamBinding::$stream,
            exposure: MetadataOperationExposure::$exposure,
            network_registered: MetadataOperationExposure::$exposure.network_registered(),
        }
    };
}

pub const METADATA_TRANSPORT_DESCRIPTORS: [MetadataTransportDescriptor;
    METADATA_SERVICE_OPERATION_COUNT] = [
    transport!(
        RepositoryCreate,
        "/v1/repository-metadata/operations/repository.create",
        201,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        AtomicCreateCoordinator
    ),
    transport!(
        RepositoryGetSettings,
        "/v1/repository-metadata/operations/repository.get-settings",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        IdentityBound
    ),
    transport!(
        RepositoryList,
        "/v1/repository-metadata/operations/repository.list",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        ProjectAuthorityRequired
    ),
    transport!(
        ObjectPut,
        "/v1/repository-metadata/operations/object.put",
        201,
        METADATA_RESPONSE_MEDIA_TYPE,
        CarrierUnassignedClosed,
        StreamCarrierRequired
    ),
    transport!(
        ObjectGet,
        "/v1/repository-metadata/operations/object.get",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        CarrierUnassignedClosed,
        StreamCarrierRequired
    ),
    transport!(
        TreePage,
        "/v1/repository-metadata/operations/tree.page",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        IdentityBound
    ),
    transport!(
        ReferenceRead,
        "/v1/repository-metadata/operations/reference.read",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        IdentityBound
    ),
    transport!(
        ReferenceList,
        "/v1/repository-metadata/operations/reference.list",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        IdentityBound
    ),
    transport!(
        ReferenceCompareAndSwap,
        "/v1/repository-metadata/operations/reference.compare-and-swap",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        AggregateCoordinatorRequired
    ),
    transport!(
        HistoryAncestryPage,
        "/v1/repository-metadata/operations/history.ancestry-page",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        IdentityBound
    ),
    transport!(
        HistoryFileIdPage,
        "/v1/repository-metadata/operations/history.file-id-page",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        IdentityBound
    ),
    transport!(
        HistoryPathPage,
        "/v1/repository-metadata/operations/history.path-page",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        IdentityBound
    ),
    transport!(
        FileIdAllocate,
        "/v1/repository-metadata/operations/file-id.allocate",
        201,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        IdentityBound
    ),
    transport!(
        FileIdRegister,
        "/v1/repository-metadata/operations/file-id.register",
        201,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        VariantGated
    ),
    transport!(
        FileIdRegisterImport,
        "/v1/repository-metadata/operations/file-id.register-import",
        201,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        IdentityBound
    ),
    transport!(
        FileIdTombstone,
        "/v1/repository-metadata/operations/file-id.tombstone",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        AggregateCoordinatorRequired
    ),
    transport!(
        FileIdHistory,
        "/v1/repository-metadata/operations/file-id.history",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        BoundedPage,
        IdentityBound
    ),
    transport!(
        IdempotencyStatus,
        "/v1/repository-metadata/operations/idempotency.status",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        IdentityBound
    ),
    transport!(
        ConsistencyIssueToken,
        "/v1/repository-metadata/operations/consistency.issue-token",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        IdentityBound
    ),
    transport!(
        OutboxClaim,
        "/v1/repository-metadata/operations/outbox.claim",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        InternalOnly
    ),
    transport!(
        OutboxAcknowledge,
        "/v1/repository-metadata/operations/outbox.acknowledge",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        InternalOnly
    ),
    transport!(
        OutboxRelease,
        "/v1/repository-metadata/operations/outbox.release",
        200,
        METADATA_RESPONSE_MEDIA_TYPE,
        None,
        InternalOnly
    ),
];

/// Returns the only descriptors a network adapter may register. The complete
/// registry above remains available for authenticated assignment checks, but
/// coordinator-owned, internal, and carrier-unassigned operations cannot leak
/// into route installation through this boundary.
pub fn network_transport_descriptors() -> impl Iterator<Item = &'static MetadataTransportDescriptor>
{
    METADATA_TRANSPORT_DESCRIPTORS
        .iter()
        .filter(|descriptor| descriptor.network_registered)
}

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
            Self::RepositoryCreate => MetadataOperationExposure::AtomicCreateCoordinator,
            Self::RepositoryList => MetadataOperationExposure::ProjectAuthorityRequired,
            Self::ObjectPut | Self::ObjectGet => MetadataOperationExposure::StreamCarrierRequired,
            Self::ReferenceCompareAndSwap | Self::FileIdTombstone => {
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

    pub const fn transport_descriptor(self) -> &'static MetadataTransportDescriptor {
        &METADATA_TRANSPORT_DESCRIPTORS[self as usize]
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
    correlation_id: String,
    deadline_unix_ms: Option<u64>,
    negotiation_receipt: Value,
    body: Value,
    extensions: Value,
    idempotency_key: Option<String>,
    semantic_fingerprint: Option<[u8; 32]>,
    tenant_id: Option<TenantId>,
    repository_id: Option<RepositoryId>,
    project_id: Option<ProjectId>,
    minimum_consistency_token: Option<ConsistencyToken>,
    reference_kind: Option<ReferenceKind>,
    reference_name: Option<ReferenceName>,
    page: Option<ServicePageRequest>,
    exposure: MetadataOperationExposure,
}

impl MetadataOperationRequest {
    pub fn parse(bytes: &[u8]) -> BoundaryResult<Self> {
        Self::parse_for_operation(bytes, None)
    }

    fn parse_for_operation(
        bytes: &[u8],
        expected_operation: Option<MetadataOperation>,
    ) -> BoundaryResult<Self> {
        if bytes.is_empty() {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        }
        if bytes.len() > CONTROL_MESSAGE_BYTES_MAXIMUM {
            return Err(MetadataServiceBoundaryError::LimitExceeded);
        }
        let StrictValue(mut value) = serde_json::from_slice(bytes).map_err(|error| {
            if error.to_string().contains("JSON resource limit exceeded") {
                MetadataServiceBoundaryError::LimitExceeded
            } else {
                MetadataServiceBoundaryError::InputInvalid
            }
        })?;
        normalize_json_numbers(&mut value)?;
        inspect_json(&value)?;
        if canonical_json_bytes(&value)?.len() > CONTROL_MESSAGE_BYTES_MAXIMUM {
            return Err(MetadataServiceBoundaryError::LimitExceeded);
        }
        let envelope = object(&value)?;
        closed_members(
            envelope,
            &[
                "schemaVersion",
                "operation",
                "correlationId",
                "deadlineUnixMs",
                "negotiationReceipt",
                "idempotency",
                "body",
                "extensions",
            ],
            &[
                "schemaVersion",
                "operation",
                "correlationId",
                "negotiationReceipt",
                "body",
            ],
        )?;
        if text(envelope, "schemaVersion", 1, 128)? != METADATA_SERVICE_REQUEST_SCHEMA {
            return Err(MetadataServiceBoundaryError::InputInvalid);
        }
        let operation = MetadataOperation::from_name(text(envelope, "operation", 1, 256)?)
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
        if expected_operation.is_some_and(|expected| operation != expected) {
            return input_invalid();
        }
        let correlation_id = correlation_id(envelope, "correlationId")?.to_owned();
        let deadline_unix_ms = envelope
            .get("deadlineUnixMs")
            .map(|value| value_uint(value, JSON_SAFE_INTEGER_MAXIMUM))
            .transpose()?;
        let negotiation_receipt = required(envelope, "negotiationReceipt")?.clone();
        validate_negotiation_receipt_shape(&negotiation_receipt)?;
        let body = envelope
            .get("body")
            .cloned()
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?;
        inspect_protocol_json_value(
            &body,
            PROTOCOL_JSON_VALUE_DEPTH_MAXIMUM,
            PROTOCOL_JSON_VALUE_NODES_MAXIMUM,
        )?;
        let body_map = object(&body)?;
        let extensions = envelope
            .get("extensions")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        validate_extensions(&extensions)?;
        let facts = validate_body(operation, body_map)?;
        let semantic_fingerprint = semantic_fingerprint(operation, &body, &extensions)?;
        let idempotency_key = match (
            operation.descriptor().idempotency_required,
            envelope.get("idempotency"),
        ) {
            (true, Some(descriptor)) => Some(validate_idempotency_descriptor(
                descriptor,
                semantic_fingerprint,
            )?),
            (true, None) | (false, Some(_)) => return input_invalid(),
            (false, None) => None,
        };
        Ok(Self {
            operation,
            correlation_id,
            deadline_unix_ms,
            negotiation_receipt,
            body,
            extensions,
            semantic_fingerprint: idempotency_key.as_ref().map(|_| semantic_fingerprint),
            idempotency_key,
            tenant_id: facts.tenant_id,
            repository_id: facts.repository_id,
            project_id: facts.project_id,
            minimum_consistency_token: facts.minimum_consistency_token,
            reference_kind: facts.reference_kind,
            reference_name: facts.reference_name,
            page: facts.page,
            exposure: facts.exposure.unwrap_or(operation.exposure()),
        })
    }

    pub const fn operation(&self) -> MetadataOperation {
        self.operation
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }

    pub const fn deadline_unix_ms(&self) -> Option<u64> {
        self.deadline_unix_ms
    }

    /// The receipt stays opaque here. Shape/selection validation is not MAC
    /// verification; the production dispatcher must verify the current
    /// OGVCS-041 receipt before any authorization or repository lookup.
    pub fn negotiation_receipt(&self) -> &Value {
        &self.negotiation_receipt
    }

    pub fn extensions(&self) -> &Value {
        &self.extensions
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

    pub(crate) const fn reference_kind(&self) -> Option<ReferenceKind> {
        self.reference_kind
    }

    pub(crate) fn reference_name(&self) -> Option<&ReferenceName> {
        self.reference_name.as_ref()
    }

    pub fn page(&self) -> Option<&ServicePageRequest> {
        self.page.as_ref()
    }

    pub const fn exposure(&self) -> MetadataOperationExposure {
        self.exposure
    }

    /// Verifies the request deadline and authenticated OGVCS-041 negotiation
    /// receipt. The returned brand proves negotiation only; an exact OGVCS-009
    /// authorized view is still mandatory before lookup, mutation, or success
    /// response construction.
    pub fn verify_negotiation<K: MetadataNegotiationKeyProvider>(
        &self,
        keys: &K,
        principal: &MetadataNegotiationPrincipal,
    ) -> std::result::Result<NegotiationVerifiedMetadataRequest, MetadataTransportError> {
        if let Some(deadline) = self.deadline_unix_ms() {
            if principal.now_unix_ms >= deadline {
                return Err(MetadataTransportError::DeadlineExceeded);
            }
            if deadline - principal.now_unix_ms > 86_400_000 {
                return Err(MetadataTransportError::LimitExceeded);
            }
        }
        verify_negotiation_receipt(
            self.negotiation_receipt(),
            self.extensions(),
            keys,
            principal,
        )?;
        Ok(NegotiationVerifiedMetadataRequest {
            request: self.clone(),
            principal: principal.clone(),
        })
    }

    /// Builds an exact failure envelope after this request's correlation ID
    /// has passed syntax admission. This method cannot build success.
    pub fn problem_response(&self, error: MetadataTransportError) -> MetadataResponseEnvelope {
        MetadataResponseEnvelope {
            schema_version: METADATA_SERVICE_RESPONSE_SCHEMA,
            correlation_id: self.correlation_id().to_owned(),
            success: false,
            body: None,
            problem: Some(MetadataProtocolProblem::registered(
                error,
                self.correlation_id(),
            )),
        }
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

impl MetadataTransportRequest<'_> {
    /// Applies only the public OGVCS-041 transport and syntax boundary. The
    /// returned request must still pass the production identity/coordinator
    /// dispatcher; no authorization resource is accepted from this type.
    pub fn admit(self) -> std::result::Result<AdmittedMetadataRoute, MetadataTransportError> {
        // Resolve the static registry before touching the control body. This
        // keeps known-but-unregistered operations from becoming a body-shape,
        // identifier, or authorization oracle.
        let descriptor = METADATA_TRANSPORT_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.path == self.path)
            .ok_or(MetadataTransportError::Malformed)?;
        if self.method != descriptor.method {
            return Err(MetadataTransportError::Malformed);
        }
        if !descriptor.network_registered {
            return Err(MetadataTransportError::Unsupported);
        }
        validate_registered_transport_constraints(&self, descriptor)?;
        let request =
            MetadataOperationRequest::parse_for_operation(self.control, Some(descriptor.operation))
                .map_err(|error| match error {
                    MetadataServiceBoundaryError::InputInvalid => MetadataTransportError::Malformed,
                    MetadataServiceBoundaryError::LimitExceeded => {
                        MetadataTransportError::LimitExceeded
                    }
                    MetadataServiceBoundaryError::OperationUnavailable => {
                        MetadataTransportError::AuthorizationDenied
                    }
                })?;
        match (descriptor.exposure, request.exposure()) {
            (
                MetadataOperationExposure::IdentityBound,
                MetadataOperationExposure::IdentityBound,
            )
            | (MetadataOperationExposure::VariantGated, MetadataOperationExposure::IdentityBound) =>
                {}
            _ => {
                return Err(MetadataTransportError::AuthorizationDenied);
            }
        }
        Ok(AdmittedMetadataRoute {
            descriptor,
            request,
        })
    }
}

fn validate_registered_transport_constraints(
    request: &MetadataTransportRequest<'_>,
    descriptor: &MetadataTransportDescriptor,
) -> std::result::Result<(), MetadataTransportError> {
    if request.content_coding != "identity" {
        return Err(MetadataTransportError::CompressionForbidden);
    }
    if request.redirect_hops != 0 {
        return Err(MetadataTransportError::RedirectForbidden);
    }
    if request.request_media_type != descriptor.request_media_type
        || request.accept != descriptor.success_media_type
    {
        return Err(MetadataTransportError::Unsupported);
    }
    Ok(())
}

#[derive(Default)]
struct BodyFacts {
    tenant_id: Option<TenantId>,
    repository_id: Option<RepositoryId>,
    project_id: Option<ProjectId>,
    minimum_consistency_token: Option<ConsistencyToken>,
    reference_kind: Option<ReferenceKind>,
    reference_name: Option<ReferenceName>,
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
        exposure: Some(MetadataOperationExposure::AtomicCreateCoordinator),
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
    let mut facts = scoped_consistent(body)?;
    facts.reference_kind = Some(
        match enum_text(body, "referenceKind", &["branch", "tag"])? {
            "branch" => ReferenceKind::Branch,
            "tag" => ReferenceKind::Tag,
            _ => return input_invalid(),
        },
    );
    facts.reference_name = Some(
        ReferenceName::new(reference_name(body, "referenceName")?.to_owned())
            .ok_or(MetadataServiceBoundaryError::InputInvalid)?,
    );
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

fn validate_idempotency_descriptor(
    value: &Value,
    expected_fingerprint: [u8; 32],
) -> BoundaryResult<String> {
    let descriptor = object(value)?;
    exact_members(
        descriptor,
        &[
            "key",
            "algorithm",
            "projectionVersion",
            "fingerprint",
            "issuedAtUnixMs",
            "expiresAtUnixMs",
        ],
    )?;
    if text(descriptor, "algorithm", 1, 64)? != "OGVCS-SEMANTIC-JCS-SHA-256"
        || text(descriptor, "projectionVersion", 1, 128)?
            != "ogvcs.protocol/fingerprint-projection@1"
    {
        return input_invalid();
    }
    let key = text(descriptor, "key", 30, IDEMPOTENCY_KEY_SCHEMA_BYTES_MAXIMUM)?;
    let (key_issued, key_expires) = idempotency_window(key)?;
    let issued = uint(descriptor, "issuedAtUnixMs", JSON_SAFE_INTEGER_MAXIMUM)?;
    let expires = uint(descriptor, "expiresAtUnixMs", JSON_SAFE_INTEGER_MAXIMUM)?;
    if issued != key_issued || expires != key_expires {
        return input_invalid();
    }
    if digest32(descriptor, "fingerprint")? != expected_fingerprint {
        return input_invalid();
    }
    Ok(key.to_owned())
}

fn validate_extensions(value: &Value) -> BoundaryResult<()> {
    let extensions = object(value)?;
    if extensions.len() > 32 {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    for (key, value) in extensions {
        if !extension_key(key) {
            return input_invalid();
        }
        inspect_protocol_json_value(
            value,
            PROTOCOL_EXTENSION_VALUE_DEPTH_MAXIMUM,
            PROTOCOL_EXTENSION_VALUE_NODES_MAXIMUM,
        )?;
    }
    Ok(())
}

fn validate_negotiation_receipt_shape(value: &Value) -> BoundaryResult<()> {
    if canonical_json_bytes(value)?.len() > 16_384 {
        return Err(MetadataServiceBoundaryError::LimitExceeded);
    }
    let receipt = object(value)?;
    exact_members(receipt, &["algorithm", "keyId", "claims", "mac"])?;
    if text(receipt, "algorithm", 1, 32)? != "HMAC-SHA-256"
        || !protocol_identifier(text(receipt, "keyId", 1, 256)?)
        || !canonical_base64url(text(receipt, "mac", 43, 43)?, 32, 32)
    {
        return input_invalid();
    }
    let claims = object(required(receipt, "claims")?)?;
    exact_members(
        claims,
        &[
            "schemaVersion",
            "selection",
            "subjectDigest",
            "tenantDigest",
            "authorityEpoch",
            "sessionId",
            "clientNonce",
            "serverNonce",
            "issuedAtUnixMs",
            "expiresAtUnixMs",
        ],
    )?;
    if text(claims, "schemaVersion", 1, 128)? != "ogvcs.protocol/negotiation-receipt-claims/v1"
        || !ascii_token(text(claims, "sessionId", 16, 256)?)
        || !canonical_base64url(text(claims, "clientNonce", 22, 86)?, 16, 64)
        || !canonical_base64url(text(claims, "serverNonce", 22, 86)?, 16, 64)
    {
        return input_invalid();
    }
    digest32(claims, "subjectDigest")?;
    digest32(claims, "tenantDigest")?;
    uint(claims, "authorityEpoch", JSON_SAFE_INTEGER_MAXIMUM)?;
    uint(claims, "issuedAtUnixMs", JSON_SAFE_INTEGER_MAXIMUM)?;
    uint(claims, "expiresAtUnixMs", JSON_SAFE_INTEGER_MAXIMUM)?;

    let selection = object(required(claims, "selection")?)?;
    exact_members(
        selection,
        &[
            "schemaVersion",
            "protocolVersion",
            "messageSchemaVersion",
            "repositoryFormat",
            "authorizationContract",
            "authorizationRegistrySha256",
            "pathContract",
            "pathProfile",
            "pathRegistrySha256",
            "eventVersion",
            "transferProfile",
            "extensions",
            "protocolRegistrySetSha256",
            "repositoryRegistrySha256",
        ],
    )?;
    for field in [
        "schemaVersion",
        "protocolVersion",
        "messageSchemaVersion",
        "repositoryFormat",
        "authorizationContract",
        "pathContract",
        "pathProfile",
        "eventVersion",
        "transferProfile",
    ] {
        text(selection, field, 1, 256)?;
    }
    for field in [
        "authorizationRegistrySha256",
        "pathRegistrySha256",
        "protocolRegistrySetSha256",
        "repositoryRegistrySha256",
    ] {
        digest32(selection, field)?;
    }
    let values = array(selection, "extensions", 128, 0)?;
    let mut selected = Vec::with_capacity(values.len());
    for value in values {
        let value = value_text(value, 1, 256)?;
        if !protocol_identifier(value) || selected.iter().any(|existing| existing == value) {
            return input_invalid();
        }
        selected.push(value.to_owned());
    }
    Ok(())
}

fn verify_negotiation_receipt<K: MetadataNegotiationKeyProvider>(
    value: &Value,
    request_extensions: &Value,
    keys: &K,
    principal: &MetadataNegotiationPrincipal,
) -> std::result::Result<(), MetadataTransportError> {
    let invalid = || MetadataTransportError::NegotiationReceiptInvalid;
    let receipt = value.as_object().ok_or_else(invalid)?;
    let key_id = receipt
        .get("keyId")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let key = keys
        .key(key_id)
        .filter(|key| key.len() >= 32)
        .ok_or_else(invalid)?;
    let claims = receipt.get("claims").ok_or_else(invalid)?;
    let supplied_mac = receipt
        .get("mac")
        .and_then(Value::as_str)
        .and_then(|value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value)
                .ok()
        })
        .filter(|value| value.len() == 32)
        .ok_or_else(invalid)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| invalid())?;
    mac.update(b"OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0");
    mac.update(key_id.as_bytes());
    mac.update(&[0]);
    mac.update(&canonical_json_bytes(claims).map_err(|_| invalid())?);
    let expected_mac = mac.finalize().into_bytes();
    if !bool::from(expected_mac.as_slice().ct_eq(&supplied_mac)) {
        return Err(invalid());
    }

    let claims = claims.as_object().ok_or_else(invalid)?;
    let selection = claims
        .get("selection")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let selected_extensions = validate_negotiation_selection(selection).map_err(|_| invalid())?;
    let request_extensions = request_extensions.as_object().ok_or_else(invalid)?;
    if request_extensions
        .keys()
        .any(|key| !selected_extensions.iter().any(|selected| selected == key))
    {
        return Err(invalid());
    }
    let issued =
        uint(claims, "issuedAtUnixMs", JSON_SAFE_INTEGER_MAXIMUM).map_err(|_| invalid())?;
    let expires =
        uint(claims, "expiresAtUnixMs", JSON_SAFE_INTEGER_MAXIMUM).map_err(|_| invalid())?;
    if expires <= issued || expires - issued > 300_000 {
        return Err(invalid());
    }
    let subject = digest32(claims, "subjectDigest").map_err(|_| invalid())?;
    let tenant = digest32(claims, "tenantDigest").map_err(|_| invalid())?;
    let epoch = uint(claims, "authorityEpoch", JSON_SAFE_INTEGER_MAXIMUM).map_err(|_| invalid())?;
    let session = claims
        .get("sessionId")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if !bool::from(subject.ct_eq(&principal.subject_digest))
        || !bool::from(tenant.ct_eq(&principal.tenant_digest))
        || epoch != principal.authority_epoch
        || session != principal.session_id
    {
        return Err(invalid());
    }
    if principal.now_unix_ms < issued || principal.now_unix_ms >= expires {
        return Err(MetadataTransportError::NegotiationReceiptExpired);
    }
    Ok(())
}

fn validate_negotiation_selection(selection: &Map<String, Value>) -> BoundaryResult<Vec<String>> {
    for (field, expected) in [
        ("schemaVersion", "ogvcs.protocol/negotiation-selection/v1"),
        ("protocolVersion", METADATA_PROTOCOL_PROFILE),
        ("messageSchemaVersion", "ogvcs.protocol.schema@1"),
        ("repositoryFormat", "ogvcs.repository-format@1"),
        ("authorizationContract", "ogvcs.authorization@1"),
        (
            "authorizationRegistrySha256",
            "293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc",
        ),
        ("pathContract", "ogvcs.path-filesystem@1"),
        ("pathProfile", "path.opengamevcs/portable@1"),
        (
            "pathRegistrySha256",
            "bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42",
        ),
        ("eventVersion", "ogvcs.events.base@1"),
        ("transferProfile", "ogvcs.transfer.range-resume-probe@1"),
        (
            "protocolRegistrySetSha256",
            OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256,
        ),
        (
            "repositoryRegistrySha256",
            "6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6",
        ),
    ] {
        if text(selection, field, 1, 256)? != expected {
            return input_invalid();
        }
    }
    let values = array(selection, "extensions", 128, 0)?;
    let mut selected = Vec::with_capacity(values.len());
    for value in values {
        let value = value_text(value, 1, 256)?;
        if !protocol_identifier(value) || selected.iter().any(|existing| existing == value) {
            return input_invalid();
        }
        selected.push(value.to_owned());
    }
    Ok(selected)
}

fn semantic_fingerprint(
    operation: MetadataOperation,
    body: &Value,
    extensions: &Value,
) -> BoundaryResult<[u8; 32]> {
    let projection = serde_json::json!({
        "schemaVersion": METADATA_SERVICE_REQUEST_SCHEMA,
        "operation": operation.name(),
        "body": body,
        "extensions": extensions,
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
    pub fn repository_settings(
        settings: &RepositorySettings,
        consistency: &ConsistencyToken,
        observed: CommitSequence,
    ) -> crate::Result<Self> {
        let tenant_boundary = public_uuid_text(settings.tenant_boundary.as_bytes())?;
        let body = serde_json::json!({
            "schemaVersion": "ogvcs.repository-metadata/repository-settings-result/v1",
            "settingsGeneration": 1,
            "settings": {
                "schemaVersion": "ogvcs.repository-metadata/repository-settings/v1",
                "repositoryFormat": settings.repository_format,
                "requiredFeatures": settings.required_features,
                "caseMode": match settings.case_mode {
                    CaseMode::CaseSensitive => "case-sensitive",
                    CaseMode::CaseFolded => "case-folded",
                },
                "pathProfile": settings.path_profile,
                "platformProfile": settings.platform_profile,
                "contentPolicyProfile": settings.content_policy_profile,
                "structuralLimits": settings.structural_limits,
                "tenantBoundary": tenant_boundary,
            },
            "observedCommitSequence": observed.get().to_string(),
            "consistencyToken": consistency.as_str(),
        });
        if response_json_bytes(&body)? > SAFE_RESULT_BYTES_MAXIMUM {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(Self::new(
            MetadataOperation::RepositoryGetSettings,
            "success",
            "json",
            body,
        ))
    }

    pub fn reference_read(
        reference: &ReferenceRecord,
        consistency: &ConsistencyToken,
        observed: CommitSequence,
    ) -> crate::Result<Self> {
        let body = serde_json::json!({
            "schemaVersion": "ogvcs.repository-metadata/reference-read-result/v1",
            "referenceKind": match reference.kind {
                ReferenceKind::Branch => "branch",
                ReferenceKind::Tag => "tag",
            },
            "referenceName": reference.name.as_str(),
            "target": reference.target.to_string(),
            "generation": reference.generation.to_string(),
            "commitSequence": reference.commit_sequence.get().to_string(),
            "observedCommitSequence": observed.get().to_string(),
            "consistencyToken": consistency.as_str(),
        });
        if response_json_bytes(&body)? > SAFE_RESULT_BYTES_MAXIMUM {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(Self::new(
            MetadataOperation::ReferenceRead,
            "success",
            "json",
            body,
        ))
    }

    pub fn consistency_token(
        consistency: &ConsistencyToken,
        minimum: CommitSequence,
    ) -> crate::Result<Self> {
        let body = serde_json::json!({
            "schemaVersion": "ogvcs.repository-metadata/consistency-token-result/v1",
            "minimumCommitSequence": minimum.get().to_string(),
            "consistencyToken": consistency.as_str(),
        });
        if response_json_bytes(&body)? > SAFE_RESULT_BYTES_MAXIMUM {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(Self::new(
            MetadataOperation::ConsistencyIssueToken,
            "success",
            "json",
            body,
        ))
    }

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

    fn new(
        operation: MetadataOperation,
        outcome: &'static str,
        carrier: &'static str,
        body: Value,
    ) -> Self {
        Self {
            schema_version: METADATA_SERVICE_RESULT_BODY_SCHEMA,
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

fn closed_members(
    body: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> BoundaryResult<()> {
    if body.keys().any(|key| !allowed.contains(&key.as_str()))
        || required.iter().any(|key| !body.contains_key(*key))
    {
        input_invalid()
    } else {
        Ok(())
    }
}

fn correlation_id<'a>(body: &'a Map<String, Value>, key: &str) -> BoundaryResult<&'a str> {
    let value = text(body, key, 16, 128)?;
    if ascii_token(value) {
        Ok(value)
    } else {
        input_invalid()
    }
}

fn ascii_token(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn protocol_identifier(value: &str) -> bool {
    let (identifier, version) = match value.split_once('@') {
        Some((identifier, version)) => {
            if version.is_empty()
                || version.bytes().any(|byte| !byte.is_ascii_digit())
                || version.contains('@')
            {
                return false;
            }
            (identifier, Some(version))
        }
        None => (value, None),
    };
    let mut bytes = identifier.bytes();
    let valid = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        });
    valid && version.is_none_or(|value| !value.is_empty())
}

fn extension_key(value: &str) -> bool {
    let Some((identifier, version)) = value.rsplit_once('@') else {
        return false;
    };
    !identifier.is_empty()
        && protocol_identifier(identifier)
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn canonical_base64url(
    value: &str,
    minimum_decoded_bytes: usize,
    maximum_decoded_bytes: usize,
) -> bool {
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return false;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .is_some_and(|decoded| {
            (minimum_decoded_bytes..=maximum_decoded_bytes).contains(&decoded.len())
                && base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded) == value
        })
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
    let mut output = Vec::new();
    write_jcs(value, &mut output)?;
    Ok(output)
}

fn write_jcs(value: &Value, output: &mut Vec<u8>) -> BoundaryResult<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(value) => serde_json::to_writer(output, value)
            .map_err(|_| MetadataServiceBoundaryError::InputInvalid)?,
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_jcs(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| MetadataServiceBoundaryError::InputInvalid)?;
                output.push(b':');
                write_jcs(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
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

fn inspect_json(value: &Value) -> BoundaryResult<()> {
    let mut state = JsonInspection::default();
    inspect_json_inner(value, 0, &mut state)
}

fn inspect_protocol_json_value(
    value: &Value,
    maximum_depth: usize,
    maximum_nodes: usize,
) -> BoundaryResult<()> {
    let mut nodes = 0_usize;
    inspect_protocol_json_value_inner(value, 0, maximum_depth, maximum_nodes, &mut nodes)
}

fn inspect_protocol_json_value_inner(
    value: &Value,
    depth: usize,
    maximum_depth: usize,
    maximum_nodes: usize,
    nodes: &mut usize,
) -> BoundaryResult<()> {
    *nodes = nodes.saturating_add(1);
    if depth > maximum_depth || *nodes > maximum_nodes {
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
            if values.len() > PROTOCOL_JSON_ARRAY_ITEMS_MAXIMUM {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            for value in values {
                inspect_protocol_json_value_inner(
                    value,
                    depth + 1,
                    maximum_depth,
                    maximum_nodes,
                    nodes,
                )?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > JSON_OBJECT_MEMBERS_MAXIMUM
                || values.keys().any(|key| key.len() > JSON_KEY_BYTES_MAXIMUM)
            {
                return Err(MetadataServiceBoundaryError::LimitExceeded);
            }
            for value in values.values() {
                inspect_protocol_json_value_inner(
                    value,
                    depth + 1,
                    maximum_depth,
                    maximum_nodes,
                    nodes,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
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
        if value.len() > JSON_STRING_BYTES_MAXIMUM {
            return Err(E::custom("JSON resource limit exceeded"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > JSON_STRING_BYTES_MAXIMUM {
            return Err(E::custom("JSON resource limit exceeded"));
        }
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
            if values.len() >= PROTOCOL_JSON_ARRAY_ITEMS_MAXIMUM {
                return Err(A::Error::custom("JSON resource limit exceeded"));
            }
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
            if values.len() >= JSON_OBJECT_MEMBERS_MAXIMUM || key.len() > JSON_KEY_BYTES_MAXIMUM {
                return Err(A::Error::custom("JSON resource limit exceeded"));
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_tenant_projection_and_key_ring_boundaries_are_frozen() {
        let mut tenant = [0x11; 16];
        tenant[6] = 0x41;
        tenant[8] = 0x91;
        assert_eq!(
            hex(&metadata_negotiation_tenant_digest(TenantId::from_bytes(
                tenant
            ))),
            "d14c066eb9bd93d48f3506b3c6585c9a2c7d84b3649ccb390ac4f897e6260c9f"
        );
        assert!(MetadataNegotiationKeyRing::new(Vec::new()).is_err());
        assert!(MetadataNegotiationKeyRing::new(vec![("key@1".to_owned(), vec![0; 31])]).is_err());
        assert!(MetadataNegotiationKeyRing::new(vec![("key@1".to_owned(), vec![0; 65])]).is_err());
        assert!(MetadataNegotiationKeyRing::new(
            (0..17)
                .map(|index| (format!("key@{index}"), vec![index as u8; 32]))
                .collect(),
        )
        .is_err());
        assert!(MetadataNegotiationKeyRing::new(vec![
            ("key@1".to_owned(), vec![1; 32]),
            ("key@1".to_owned(), vec![2; 32]),
        ])
        .is_err());
        let ring = MetadataNegotiationKeyRing::new(vec![
            ("key@1".to_owned(), vec![1; 32]),
            ("key@2".to_owned(), vec![2; 64]),
        ])
        .unwrap();
        assert_eq!(ring.key("key@1"), Some([1; 32].as_slice()));
        assert!(ring.key("key@3").is_none());
    }

    #[test]
    fn authorized_success_uses_the_exact_ogvcs_041_response_envelope() {
        let result = MetadataHttpResponse::success_json(
            MetadataOperation::RepositoryGetSettings,
            serde_json::json!({"settingsGeneration": 1}),
        )
        .unwrap();
        let prepared = MetadataResponseEnvelope::prepare_authorized_dispatch(result).unwrap();
        let response = MetadataResponseEnvelope::success_for_committed_dispatch(
            crate::postgres::committed_metadata_read_dispatch_for_test(),
            "correlation-0001",
            prepared,
        );
        let response = serde_json::to_value(response).unwrap();
        assert_eq!(
            response,
            serde_json::json!({
                "schemaVersion": "ogvcs.protocol/response-envelope/v1",
                "correlationId": "correlation-0001",
                "success": true,
                "body": {
                    "schemaVersion": "ogvcs.repository-metadata/result-body/v1",
                    "operation": "repository.get-settings",
                    "outcome": "success",
                    "carrier": "json",
                    "body": {"settingsGeneration": 1},
                },
            })
        );
    }

    #[test]
    fn registered_transport_profile_forbids_compression_and_redirects_independently() {
        let descriptor = MetadataOperation::RepositoryGetSettings.transport_descriptor();
        let compressed = MetadataTransportRequest {
            method: descriptor.method,
            path: descriptor.path,
            request_media_type: descriptor.request_media_type,
            accept: descriptor.success_media_type,
            content_coding: "gzip",
            redirect_hops: 0,
            control: b"{}",
        };
        assert_eq!(
            validate_registered_transport_constraints(&compressed, descriptor),
            Err(MetadataTransportError::CompressionForbidden)
        );
        let redirected = MetadataTransportRequest {
            content_coding: "identity",
            redirect_hops: 1,
            ..compressed
        };
        assert_eq!(
            validate_registered_transport_constraints(&redirected, descriptor),
            Err(MetadataTransportError::RedirectForbidden)
        );
    }
}
