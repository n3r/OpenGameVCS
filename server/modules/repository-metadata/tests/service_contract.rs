use ogvcs_repository_metadata::{
    AllocationReceipt, ConsistencyToken, CursorToken, DomainError, DomainErrorCode, FileId,
    FileIdAllocation, HistoryIncompleteReason, HistoryPage, IdempotencyStatus,
    MetadataHttpResponse, MetadataOperation, MetadataOperationClass, MetadataOperationExposure,
    MetadataOperationRequest, MetadataPayloadCarrier, MetadataPermission,
    MetadataServiceBoundaryError, ObjectRef, Page, PageState, RepositoryId,
    METADATA_OPERATION_DESCRIPTORS, METADATA_SERVICE_CONTRACT_VERSION,
    METADATA_SERVICE_MANIFEST_SHA256, METADATA_SERVICE_OPERATION_COUNT,
    METADATA_SERVICE_REQUEST_SCHEMA, PUBLIC_PAGE_ITEMS_MAXIMUM,
};
use serde::{ser::SerializeSeq, Serialize, Serializer};
use serde_json::{json, Map, Value};
use std::{
    str::FromStr,
    time::{Duration, UNIX_EPOCH},
};

const TENANT: &str = "00000000-0000-4000-8000-000000000001";
const REPOSITORY: &str = "00000000-0000-4000-8000-000000000002";
const PROJECT: &str = "00000000-0000-4000-8000-000000000003";
const EVENT: &str = "00000000-0000-4000-8000-000000000004";
const LEASE: &str = "00000000-0000-4000-8000-000000000005";
const SNAPSHOT: &str =
    "ogvcs:v1:snapshot:sha256:0202020202020202020202020202020202020202020202020202020202020202";
const NEXT_SNAPSHOT: &str =
    "ogvcs:v1:snapshot:sha256:0303030303030303030303030303030303030303030303030303030303030303";
const TREE: &str =
    "ogvcs:v1:tree:sha256:0101010101010101010101010101010101010101010101010101010101010101";
const FILE_ID: &str = "fid:04040404040404040404040404040404";

fn opaque(prefix: &str, byte: char) -> String {
    format!("{prefix}.{}", byte.to_string().repeat(43))
}

fn idempotency_key(entropy: char) -> String {
    format!("ik1.1000.2000.{}", entropy.to_string().repeat(22))
}

fn dated_idempotency_key(issued: u64, expires: u64, entropy: char) -> String {
    format!("ik1.{issued}.{expires}.{}", entropy.to_string().repeat(22))
}

fn request_value(operation: &str, body: Value, key: Option<&str>) -> Value {
    json!({
        "schemaVersion": METADATA_SERVICE_REQUEST_SCHEMA,
        "operation": operation,
        "body": body,
        "idempotencyKey": key,
    })
}

fn parse_value(value: &Value) -> Result<MetadataOperationRequest, MetadataServiceBoundaryError> {
    MetadataOperationRequest::parse(&serde_json::to_vec(value).expect("fixture serializes"))
}

struct OversizedSequence;

impl Serialize for OversizedSequence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(300_000))?;
        for _ in 0..300_000 {
            sequence.serialize_element(&())?;
        }
        sequence.end()
    }
}

fn object_reference(kind: &str) -> String {
    format!("ogvcs:v1:{kind}:sha256:{}", "11".repeat(32))
}

fn settings() -> Value {
    json!({
        "schemaVersion": "ogvcs.repository-metadata/repository-settings/v1",
        "repositoryFormat": "ogvcs.repository-format@1",
        "requiredFeatures": [1, 7, 65535],
        "caseMode": "case-sensitive",
        "pathProfile": "path.opengamevcs/portable@1",
        "platformProfile": "path.opengamevcs/portable@1",
        "contentPolicyProfile": "content-policy.test/opaque@1",
        "structuralLimits": {
            "maxTreeEntries": 1_000_000,
            "maxPathBytes": 4_096,
            "maxPathSegments": 256,
            "maxSnapshotParents": 8,
        },
        "tenantBoundary": TENANT,
    })
}

fn valid_cases() -> Vec<(&'static str, Value)> {
    let consistency = opaque("ct1", 'T');
    let cursor = opaque("cur1", 'C');
    vec![
        (
            "repository.create",
            json!({
                "tenantId": TENANT,
                "projectId": PROJECT,
                "repositoryId": REPOSITORY,
                "settings": settings(),
                "rootSnapshot": SNAPSHOT,
                "defaultReference": "main",
            }),
        ),
        (
            "repository.get-settings",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": consistency,
            }),
        ),
        (
            "repository.list",
            json!({
                "tenantId": TENANT,
                "projectId": PROJECT,
                "pageSize": 10_000,
                "cursor": cursor,
            }),
        ),
        (
            "object.put",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "objectRef": TREE,
                "canonicalByteLength": 536_870_912,
                "streamDigestSha256": "ab".repeat(32),
            }),
        ),
        (
            "object.get",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "objectRef": TREE,
            }),
        ),
        (
            "tree.page",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "snapshot": SNAPSHOT,
                "tree": TREE,
                "prefix": ["Assets", "Textures"],
                "pageSize": 100,
                "cursor": null,
            }),
        ),
        (
            "reference.read",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "referenceKind": "branch",
                "referenceName": "main",
            }),
        ),
        (
            "reference.list",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "referenceKind": "all",
                "pageSize": 0,
                "cursor": null,
            }),
        ),
        (
            "reference.compare-and-swap",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "referenceKind": "branch",
                "referenceName": "main",
                "expected": { "state": "present", "target": SNAPSHOT, "generation": 1 },
                "desired": NEXT_SNAPSHOT,
            }),
        ),
        (
            "history.ancestry-page",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "snapshot": SNAPSHOT,
                "maxDepth": 100_000,
                "pageSize": 10_000,
                "cursor": null,
            }),
        ),
        (
            "history.file-id-page",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "snapshot": SNAPSHOT,
                "fileId": FILE_ID,
                "maxDepth": 100_000,
                "pageSize": 10_000,
                "cursor": null,
            }),
        ),
        (
            "history.path-page",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "snapshot": SNAPSHOT,
                "path": ["Assets", "hero.uasset"],
                "maxDepth": 100_000,
                "pageSize": 10_000,
                "cursor": null,
            }),
        ),
        (
            "file-id.allocate",
            json!({ "tenantId": TENANT, "repositoryId": REPOSITORY }),
        ),
        (
            "file-id.register",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "fileId": FILE_ID,
                "origin": "copy",
                "allocationReceipt": opaque("far1", 'A'),
                "ownerKind": "draft",
                "ownerId": "draft-1",
            }),
        ),
        (
            "file-id.register-import",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "fileId": FILE_ID,
                "importerProfile": "import.example/perforce@1",
                "sourceNamespaceDigest": "11".repeat(32),
                "sourceIdentityDigest": "22".repeat(32),
                "ownerKind": "published",
                "ownerId": "import-1",
            }),
        ),
        (
            "file-id.tombstone",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "fileId": FILE_ID,
                "expectedState": "active",
            }),
        ),
        (
            "file-id.history",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "fileId": FILE_ID,
                "pageSize": 10_000,
                "cursor": null,
            }),
        ),
        (
            "idempotency.status",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "operation": "object.put",
                "idempotencyKey": idempotency_key('S'),
            }),
        ),
        (
            "consistency.issue-token",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "ttlSeconds": 86_400,
            }),
        ),
        (
            "outbox.claim",
            json!({ "consumerId": "worker-1", "maximumItems": 1_000, "leaseSeconds": 3_600 }),
        ),
        (
            "outbox.acknowledge",
            json!({ "consumerId": "worker-1", "eventId": EVENT, "leaseId": LEASE }),
        ),
        (
            "outbox.release",
            json!({
                "consumerId": "worker-1",
                "eventId": EVENT,
                "leaseId": LEASE,
                "retryAfterSeconds": 86_400,
            }),
        ),
    ]
}

#[test]
fn descriptor_table_is_the_exact_authenticated_candidate_registry() {
    assert_eq!(METADATA_SERVICE_CONTRACT_VERSION, "0.2.0");
    assert_eq!(
        METADATA_SERVICE_MANIFEST_SHA256,
        "19f0139ad22f8546d1c3c998e972ebc5c21b39d742a92b8fe3eefb8042d13d89"
    );
    assert_eq!(METADATA_SERVICE_OPERATION_COUNT, 22);
    assert_eq!(METADATA_OPERATION_DESCRIPTORS.len(), 22);

    let expected = [
        (
            "repository.create",
            "mutation",
            "submit",
            "repository",
            true,
            "json",
        ),
        (
            "repository.get-settings",
            "query",
            "metadata.read",
            "repository",
            false,
            "json",
        ),
        (
            "repository.list",
            "query",
            "discover",
            "repository",
            false,
            "json",
        ),
        (
            "object.put",
            "mutation",
            "submit",
            "snapshot",
            true,
            "canonical-metadata-byte-stream",
        ),
        (
            "object.get",
            "query",
            "metadata.read",
            "snapshot",
            false,
            "canonical-metadata-byte-stream",
        ),
        ("tree.page", "query", "metadata.read", "tree", false, "json"),
        (
            "reference.read",
            "query",
            "metadata.read",
            "reference",
            false,
            "json",
        ),
        (
            "reference.list",
            "query",
            "discover",
            "reference",
            false,
            "json",
        ),
        (
            "reference.compare-and-swap",
            "mutation",
            "submit",
            "reference",
            true,
            "json",
        ),
        (
            "history.ancestry-page",
            "query",
            "metadata.read",
            "snapshot",
            false,
            "json",
        ),
        (
            "history.file-id-page",
            "query",
            "metadata.read",
            "path",
            false,
            "json",
        ),
        (
            "history.path-page",
            "query",
            "metadata.read",
            "path",
            false,
            "json",
        ),
        (
            "file-id.allocate",
            "mutation",
            "submit",
            "path",
            true,
            "json",
        ),
        (
            "file-id.register",
            "mutation",
            "submit",
            "path",
            true,
            "json",
        ),
        (
            "file-id.register-import",
            "mutation",
            "submit",
            "path",
            true,
            "json",
        ),
        (
            "file-id.tombstone",
            "mutation",
            "submit",
            "path",
            true,
            "json",
        ),
        (
            "file-id.history",
            "query",
            "metadata.read",
            "path",
            false,
            "json",
        ),
        (
            "idempotency.status",
            "query",
            "submit",
            "repository",
            false,
            "json",
        ),
        (
            "consistency.issue-token",
            "query",
            "metadata.read",
            "repository",
            false,
            "json",
        ),
        (
            "outbox.claim",
            "internal-mutation",
            "service-internal",
            "event",
            false,
            "json",
        ),
        (
            "outbox.acknowledge",
            "internal-mutation",
            "service-internal",
            "event",
            false,
            "json",
        ),
        (
            "outbox.release",
            "internal-mutation",
            "service-internal",
            "event",
            false,
            "json",
        ),
    ];
    for (index, descriptor) in METADATA_OPERATION_DESCRIPTORS.iter().enumerate() {
        let (name, class, permission, resource, idempotency, carrier) = expected[index];
        assert_eq!(usize::from(descriptor.code), index + 1);
        assert_eq!(descriptor.name, name);
        assert_eq!(descriptor.class.as_str(), class);
        assert_eq!(descriptor.permission.as_str(), permission);
        assert_eq!(descriptor.resource_type, resource);
        assert_eq!(descriptor.idempotency_required, idempotency);
        assert_eq!(descriptor.payload_carrier.as_str(), carrier);
        assert_eq!(descriptor.operation.name(), descriptor.name);
        assert_eq!(
            MetadataOperation::from_name(descriptor.name),
            Some(descriptor.operation)
        );
    }
    assert_eq!(MetadataOperation::from_name("publish"), None);

    let put = MetadataOperation::ObjectPut.descriptor();
    assert_eq!(put.class, MetadataOperationClass::Mutation);
    assert_eq!(put.permission, MetadataPermission::Submit);
    assert_eq!(put.resource_type, "snapshot");
    assert!(put.idempotency_required);
    assert_eq!(
        put.payload_carrier,
        MetadataPayloadCarrier::CanonicalMetadataByteStream
    );
    let outbox = MetadataOperation::OutboxClaim.descriptor();
    assert_eq!(outbox.class, MetadataOperationClass::InternalMutation);
    assert_eq!(outbox.permission, MetadataPermission::ServiceInternal);
    assert!(!outbox.idempotency_required);
}

#[test]
fn all_twenty_two_request_variants_are_validated_and_bound() {
    let cases = valid_cases();
    assert_eq!(cases.len(), METADATA_SERVICE_OPERATION_COUNT);
    for (index, (name, body)) in cases.into_iter().enumerate() {
        let descriptor = &METADATA_OPERATION_DESCRIPTORS[index];
        assert_eq!(descriptor.name, name);
        let key = descriptor
            .idempotency_required
            .then(|| idempotency_key('A'));
        let request = request_value(name, body, key.as_deref());
        let parsed = parse_value(&request).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(parsed.operation(), descriptor.operation);
        assert_eq!(
            parsed.idempotency_key().is_some(),
            descriptor.idempotency_required
        );
        assert_eq!(
            parsed.semantic_fingerprint().is_some(),
            descriptor.idempotency_required
        );
    }
}

#[test]
fn public_page_and_consistency_token_boundaries_are_exact() {
    for page_size in [0, 1, 9_999, 10_000] {
        let request = request_value(
            "repository.list",
            json!({
                "tenantId": TENANT,
                "projectId": PROJECT,
                "pageSize": page_size,
                "cursor": null,
            }),
            None,
        );
        let parsed = parse_value(&request).expect("candidate page bound accepted");
        assert_eq!(parsed.page().expect("page facts").page_size, page_size);
        assert!(parsed.page().expect("page facts").is_bounded());
    }
    let over = request_value(
        "repository.list",
        json!({
            "tenantId": TENANT,
            "projectId": PROJECT,
            "pageSize": 10_001,
            "cursor": null,
        }),
        None,
    );
    assert_eq!(
        parse_value(&over),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    let token = opaque("ct1", 'Z');
    let consistent = request_value(
        "object.get",
        json!({
            "tenantId": TENANT,
            "repositoryId": REPOSITORY,
            "minimumConsistencyToken": token,
            "objectRef": TREE,
        }),
        None,
    );
    let parsed = parse_value(&consistent).expect("valid consistency token");
    assert_eq!(
        parsed
            .minimum_consistency_token()
            .map(ConsistencyToken::as_str),
        Some(token.as_str())
    );
    let mut wrong_prefix = consistent;
    wrong_prefix["body"]["minimumConsistencyToken"] = Value::String(opaque("xx1", 'Z'));
    assert_eq!(
        parse_value(&wrong_prefix),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    assert_eq!(PUBLIC_PAGE_ITEMS_MAXIMUM, 10_000);
}

#[test]
fn coordinator_and_internal_mutations_cannot_enter_identity_bound_dispatch() {
    for operation in [
        MetadataOperation::RepositoryCreate,
        MetadataOperation::ReferenceCompareAndSwap,
        MetadataOperation::FileIdRegister,
        MetadataOperation::FileIdTombstone,
    ] {
        assert_eq!(
            operation.exposure(),
            MetadataOperationExposure::AggregateCoordinatorRequired
        );
    }
    for operation in [
        MetadataOperation::OutboxClaim,
        MetadataOperation::OutboxAcknowledge,
        MetadataOperation::OutboxRelease,
    ] {
        assert_eq!(
            operation.exposure(),
            MetadataOperationExposure::InternalOnly
        );
    }

    for (name, body) in valid_cases() {
        let descriptor = MetadataOperation::from_name(name).unwrap().descriptor();
        let key = descriptor
            .idempotency_required
            .then(|| idempotency_key('A'));
        let parsed = parse_value(&request_value(name, body, key.as_deref())).unwrap();
        if matches!(
            parsed.exposure(),
            MetadataOperationExposure::AggregateCoordinatorRequired
                | MetadataOperationExposure::InternalOnly
        ) {
            assert_eq!(
                parsed.require_identity_bound(),
                Err(MetadataServiceBoundaryError::OperationUnavailable),
                "{name} escaped its production gate"
            );
        }
    }

    let restore = request_value(
        "file-id.register",
        json!({
            "tenantId": TENANT,
            "repositoryId": REPOSITORY,
            "fileId": FILE_ID,
            "origin": "restore",
            "allocationReceipt": null,
            "ownerKind": "published",
            "ownerId": "restore-1",
        }),
        Some(&idempotency_key('R')),
    );
    let restore = parse_value(&restore).expect("restore syntax remains representable");
    assert_eq!(
        restore.exposure(),
        MetadataOperationExposure::AggregateCoordinatorRequired
    );
    assert_eq!(
        restore.require_identity_bound(),
        Err(MetadataServiceBoundaryError::OperationUnavailable)
    );

    let native = valid_cases()
        .into_iter()
        .find(|(name, _)| *name == "file-id.register")
        .unwrap();
    let native = parse_value(&request_value(
        native.0,
        native.1,
        Some(&idempotency_key('N')),
    ))
    .expect("native registration");
    assert_eq!(native.exposure(), MetadataOperationExposure::IdentityBound);
    assert_eq!(native.require_identity_bound(), Ok(()));
}

#[test]
fn semantic_idempotency_is_order_independent_but_operation_and_body_bound() {
    let first = format!(
        "{{\"schemaVersion\":\"{METADATA_SERVICE_REQUEST_SCHEMA}\",\"operation\":\"object.put\",\"body\":{{\"tenantId\":\"{TENANT}\",\"repositoryId\":\"{REPOSITORY}\",\"objectRef\":\"{TREE}\",\"canonicalByteLength\":7,\"streamDigestSha256\":\"{}\"}},\"idempotencyKey\":\"{}\"}}",
        "ab".repeat(32),
        idempotency_key('A')
    );
    let reordered = format!(
        "{{\"idempotencyKey\":\"{}\",\"body\":{{\"streamDigestSha256\":\"{}\",\"canonicalByteLength\":7,\"objectRef\":\"{TREE}\",\"repositoryId\":\"{REPOSITORY}\",\"tenantId\":\"{TENANT}\"}},\"operation\":\"object.put\",\"schemaVersion\":\"{METADATA_SERVICE_REQUEST_SCHEMA}\"}}",
        idempotency_key('B'),
        "ab".repeat(32),
    );
    let first = MetadataOperationRequest::parse(first.as_bytes()).unwrap();
    let reordered = MetadataOperationRequest::parse(reordered.as_bytes()).unwrap();
    assert_eq!(
        first.semantic_fingerprint(),
        reordered.semantic_fingerprint()
    );
    assert_eq!(
        hex(first.semantic_fingerprint().unwrap()),
        "b1bb38aff0d8b09f2cd7d56a74bcfcc98c33b6d6f17433b28f4e0609d828ca96"
    );

    let mut changed_body = first.body().clone();
    changed_body["canonicalByteLength"] = json!(8);
    let changed = parse_value(&request_value(
        "object.put",
        changed_body,
        Some(&idempotency_key('C')),
    ))
    .unwrap();
    assert_ne!(first.semantic_fingerprint(), changed.semantic_fingerprint());

    let reservation = first
        .idempotency_reservation_at(UNIX_EPOCH + Duration::from_millis(1_500))
        .unwrap()
        .unwrap();
    assert_eq!(reservation.operation, "object.put");
    assert_eq!(reservation.key, idempotency_key('A'));
    assert_eq!(
        reservation.semantic_fingerprint,
        first.semantic_fingerprint().unwrap()
    );
    assert_eq!(
        first.idempotency_reservation_at(UNIX_EPOCH + Duration::from_millis(999)),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    assert_eq!(
        first.idempotency_reservation_at(UNIX_EPOCH + Duration::from_millis(2_000)),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );

    let exact_safe_maximum = request_value(
        "file-id.allocate",
        json!({ "tenantId": TENANT, "repositoryId": REPOSITORY }),
        Some(&dated_idempotency_key(
            9_007_199_254_740_990,
            9_007_199_254_740_991,
            'J',
        )),
    );
    assert!(parse_value(&exact_safe_maximum).is_ok());
    let over_safe_maximum = request_value(
        "file-id.allocate",
        json!({ "tenantId": TENANT, "repositoryId": REPOSITORY }),
        Some(&dated_idempotency_key(
            9_007_199_254_740_991,
            9_007_199_254_740_992,
            'J',
        )),
    );
    assert_eq!(
        parse_value(&over_safe_maximum),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    let integer_forms = ["1", "1.0", "1e0"].map(|number| {
        let request = format!(
            "{{\"schemaVersion\":\"{METADATA_SERVICE_REQUEST_SCHEMA}\",\"operation\":\"object.put\",\"body\":{{\"tenantId\":\"{TENANT}\",\"repositoryId\":\"{REPOSITORY}\",\"objectRef\":\"{TREE}\",\"canonicalByteLength\":{number},\"streamDigestSha256\":\"{}\"}},\"idempotencyKey\":\"{}\"}}",
            "cd".repeat(32),
            idempotency_key('Q'),
        );
        MetadataOperationRequest::parse(request.as_bytes())
            .expect("schema-equivalent integer form")
            .semantic_fingerprint()
            .unwrap()
    });
    assert_eq!(integer_forms[0], integer_forms[1]);
    assert_eq!(integer_forms[1], integer_forms[2]);

    for number in ["1.5", "9007199254740992.0", "-9007199254740992.0"] {
        let request = format!(
            "{{\"schemaVersion\":\"{METADATA_SERVICE_REQUEST_SCHEMA}\",\"operation\":\"object.put\",\"body\":{{\"tenantId\":\"{TENANT}\",\"repositoryId\":\"{REPOSITORY}\",\"objectRef\":\"{TREE}\",\"canonicalByteLength\":{number},\"streamDigestSha256\":\"{}\"}},\"idempotencyKey\":\"{}\"}}",
            "cd".repeat(32),
            idempotency_key('Q'),
        );
        assert!(MetadataOperationRequest::parse(request.as_bytes()).is_err());
    }
}

#[test]
fn object_stream_operations_admit_only_repository_metadata_kinds() {
    let metadata_kinds = [
        "content-manifest",
        "tree",
        "change-set",
        "asset-group-set",
        "repository-descriptor",
        "snapshot",
        "provenance",
        "attestation",
        "conflict-set",
    ];
    for kind in metadata_kinds {
        let reference = object_reference(kind);
        let put = request_value(
            "object.put",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "objectRef": reference,
                "canonicalByteLength": 1,
                "streamDigestSha256": "11".repeat(32),
            }),
            Some(&idempotency_key('M')),
        );
        assert!(parse_value(&put).is_ok(), "put rejected {kind}");
        let get = request_value(
            "object.get",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "objectRef": reference,
            }),
            None,
        );
        assert!(parse_value(&get).is_ok(), "get rejected {kind}");
        assert!(MetadataHttpResponse::object_stream(
            ObjectRef::from_str(&object_reference(kind)).unwrap(),
            1,
            [0; 32],
        )
        .is_ok());
    }

    for kind in ["chunk", "shelf-revision"] {
        let reference = object_reference(kind);
        let put = request_value(
            "object.put",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "objectRef": reference,
                "canonicalByteLength": 1,
                "streamDigestSha256": "11".repeat(32),
            }),
            Some(&idempotency_key('M')),
        );
        assert_eq!(
            parse_value(&put),
            Err(MetadataServiceBoundaryError::InputInvalid),
            "put admitted {kind}"
        );
        let get = request_value(
            "object.get",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "objectRef": reference,
            }),
            None,
        );
        assert_eq!(
            parse_value(&get),
            Err(MetadataServiceBoundaryError::InputInvalid),
            "get admitted {kind}"
        );
        assert!(MetadataHttpResponse::object_stream(
            ObjectRef::from_str(&object_reference(kind)).unwrap(),
            1,
            [0; 32],
        )
        .is_err());
    }
}

#[test]
fn malformed_duplicate_and_over_limit_inputs_fail_before_dispatch() {
    assert_eq!(
        MetadataOperationRequest::parse(b""),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    let duplicate = format!(
        "{{\"schemaVersion\":\"{METADATA_SERVICE_REQUEST_SCHEMA}\",\"operation\":\"file-id.allocate\",\"operation\":\"file-id.allocate\",\"body\":{{\"tenantId\":\"{TENANT}\",\"repositoryId\":\"{REPOSITORY}\"}},\"idempotencyKey\":\"{}\"}}",
        idempotency_key('D')
    );
    assert_eq!(
        MetadataOperationRequest::parse(duplicate.as_bytes()),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    let duplicate_nested = format!(
        "{{\"schemaVersion\":\"{METADATA_SERVICE_REQUEST_SCHEMA}\",\"operation\":\"file-id.allocate\",\"body\":{{\"tenantId\":\"{TENANT}\",\"tenantId\":\"{TENANT}\",\"repositoryId\":\"{REPOSITORY}\"}},\"idempotencyKey\":\"{}\"}}",
        idempotency_key('D')
    );
    assert_eq!(
        MetadataOperationRequest::parse(duplicate_nested.as_bytes()),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );

    let mut unknown = request_value(
        "file-id.allocate",
        json!({ "tenantId": TENANT, "repositoryId": REPOSITORY }),
        Some(&idempotency_key('E')),
    );
    unknown["body"]["protectedPath"] = json!("secret/project");
    assert_eq!(
        parse_value(&unknown),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    unknown["body"]
        .as_object_mut()
        .unwrap()
        .remove("protectedPath");
    unknown.as_object_mut().unwrap().remove("idempotencyKey");
    assert_eq!(
        parse_value(&unknown),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );

    let no_key = request_value(
        "file-id.allocate",
        json!({ "tenantId": TENANT, "repositoryId": REPOSITORY }),
        None,
    );
    assert_eq!(
        parse_value(&no_key),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    let malformed_key = request_value(
        "file-id.allocate",
        json!({ "tenantId": TENANT, "repositoryId": REPOSITORY }),
        Some("not-self-dating"),
    );
    assert_eq!(
        parse_value(&malformed_key),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    let query_key = request_value(
        "repository.list",
        json!({ "tenantId": TENANT, "projectId": PROJECT, "pageSize": 1, "cursor": null }),
        Some(&idempotency_key('Q')),
    );
    assert_eq!(
        parse_value(&query_key),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );

    let status_for_query = request_value(
        "idempotency.status",
        json!({
            "tenantId": TENANT,
            "repositoryId": REPOSITORY,
            "operation": "repository.list",
            "idempotencyKey": idempotency_key('S'),
        }),
        None,
    );
    assert!(parse_value(&status_for_query).is_ok());

    let over_control = vec![b' '; 1_048_577];
    assert_eq!(
        MetadataOperationRequest::parse(&over_control),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    let mut deep = json!(null);
    for _ in 0..66 {
        deep = json!([deep]);
    }
    let deep = request_value("file-id.allocate", deep, Some(&idempotency_key('F')));
    assert_eq!(
        parse_value(&deep),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    let mut many_members = Map::new();
    for index in 0..257 {
        many_members.insert(format!("k{index}"), Value::Null);
    }
    let many_members = request_value(
        "file-id.allocate",
        Value::Object(many_members),
        Some(&idempotency_key('M')),
    );
    assert_eq!(
        parse_value(&many_members),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    let many_items = request_value(
        "file-id.allocate",
        json!({ "unexpected": vec![Value::Null; 100_001] }),
        Some(&idempotency_key('V')),
    );
    assert_eq!(
        parse_value(&many_items),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
    let long_string = request_value(
        "file-id.allocate",
        json!({ "unexpected": "x".repeat(65_537) }),
        Some(&idempotency_key('W')),
    );
    assert_eq!(
        parse_value(&long_string),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
    let mut long_key_body = Map::new();
    long_key_body.insert("k".repeat(257), Value::Null);
    let long_key = request_value(
        "file-id.allocate",
        Value::Object(long_key_body),
        Some(&idempotency_key('X')),
    );
    assert_eq!(
        parse_value(&long_key),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
}

#[test]
fn semantic_path_identifier_and_numeric_guards_reject_hostile_values() {
    let base = |path: Value| {
        request_value(
            "history.path-page",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "snapshot": SNAPSHOT,
                "path": path,
                "maxDepth": 1,
                "pageSize": 1,
                "cursor": null,
            }),
            None,
        )
    };
    for invalid in [
        json!([]),
        json!(["."]),
        json!([".."]),
        json!([".ogvcs"]),
        json!(["a/b"]),
        json!(["a\\b"]),
        json!(["\u{1}"]),
        json!(["e\u{301}"]),
    ] {
        assert_eq!(
            parse_value(&base(invalid)),
            Err(MetadataServiceBoundaryError::InputInvalid)
        );
    }
    assert_eq!(
        parse_value(&base(json!(["x".repeat(256)]))),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
    assert_eq!(
        parse_value(&base(json!(["é".repeat(128)]))),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
    assert_eq!(
        parse_value(&base(json!(vec!["x"; 257]))),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
    assert_eq!(
        parse_value(&base(json!(vec!["x".repeat(255); 17]))),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    let bad_uuid = request_value(
        "file-id.allocate",
        json!({ "tenantId": "AAAAAAAA-0000-4000-8000-000000000001", "repositoryId": REPOSITORY }),
        Some(&idempotency_key('U')),
    );
    assert_eq!(
        parse_value(&bad_uuid),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    let bad_ref = request_value(
        "object.put",
        json!({
            "tenantId": TENANT,
            "repositoryId": REPOSITORY,
            "objectRef": TREE.to_uppercase(),
            "canonicalByteLength": 1,
            "streamDigestSha256": "00".repeat(32),
        }),
        Some(&idempotency_key('O')),
    );
    assert_eq!(
        parse_value(&bad_ref),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );
    let bad_number = request_value(
        "consistency.issue-token",
        json!({ "tenantId": TENANT, "repositoryId": REPOSITORY, "ttlSeconds": 86_401 }),
        None,
    );
    assert_eq!(
        parse_value(&bad_number),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );

    assert!(parse_value(&base(json!(["\u{85}"]))).is_ok());

    let reference = |name: String| {
        request_value(
            "reference.read",
            json!({
                "tenantId": TENANT,
                "repositoryId": REPOSITORY,
                "minimumConsistencyToken": null,
                "referenceKind": "branch",
                "referenceName": name,
            }),
            None,
        )
    };
    assert!(parse_value(&reference("💾".repeat(128))).is_ok());
    assert!(parse_value(&reference("\u{85}".to_owned())).is_ok());
    assert_eq!(
        parse_value(&reference("💾".repeat(129))),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
    assert_eq!(
        parse_value(&reference("main\0hidden".to_owned())),
        Err(MetadataServiceBoundaryError::InputInvalid)
    );

    let unicode_owner = request_value(
        "file-id.register",
        json!({
            "tenantId": TENANT,
            "repositoryId": REPOSITORY,
            "fileId": FILE_ID,
            "origin": "copy",
            "allocationReceipt": opaque("far1", 'A'),
            "ownerKind": "draft",
            "ownerId": "💾".repeat(64),
        }),
        Some(&idempotency_key('I')),
    );
    assert!(parse_value(&unicode_owner).is_ok());
    let mut too_many_bytes = unicode_owner;
    too_many_bytes["body"]["ownerId"] = Value::String("💾".repeat(65));
    assert_eq!(
        parse_value(&too_many_bytes),
        Err(MetadataServiceBoundaryError::LimitExceeded)
    );
}

#[test]
fn response_constructors_bind_shapes_limits_and_non_disclosure() {
    let consistency = ConsistencyToken::from_opaque(opaque("ct1", 'K')).unwrap();
    let cursor = CursorToken::from_opaque(opaque("cur1", 'L')).unwrap();
    let page = MetadataHttpResponse::page(
        MetadataOperation::RepositoryList,
        Page {
            items: vec![Value::Null; 10_000],
            next_cursor: Some(cursor),
        },
        &consistency,
    )
    .expect("exact public maximum response");
    let page_json = serde_json::to_value(&page).unwrap();
    assert_eq!(
        page.schema_version(),
        "ogvcs.repository-metadata/http-response/v1"
    );
    assert_eq!(page.operation(), "repository.list");
    assert_eq!(page.outcome(), "success");
    assert_eq!(page.carrier(), "page-result");
    assert_eq!(page_json["body"]["state"], "more");
    assert_eq!(page_json["body"]["items"].as_array().unwrap().len(), 10_000);
    assert_eq!(page_json["body"]["consistencyToken"], consistency.as_str());

    assert!(MetadataHttpResponse::page(
        MetadataOperation::RepositoryList,
        Page {
            items: vec![Value::Null; 10_001],
            next_cursor: None,
        },
        &consistency,
    )
    .is_err());
    assert!(MetadataHttpResponse::page(
        MetadataOperation::RepositoryList,
        Page {
            items: vec![OversizedSequence],
            next_cursor: None,
        },
        &consistency,
    )
    .is_err());
    let mut over_nested = Value::Null;
    for _ in 0..65 {
        over_nested = json!([over_nested]);
    }
    assert!(MetadataHttpResponse::page(
        MetadataOperation::RepositoryList,
        Page {
            items: vec![over_nested],
            next_cursor: None,
        },
        &consistency,
    )
    .is_err());
    assert!(MetadataHttpResponse::page(
        MetadataOperation::ObjectPut,
        Page::<Value> {
            items: Vec::new(),
            next_cursor: None,
        },
        &consistency,
    )
    .is_err());

    let history = MetadataHttpResponse::history_page(
        MetadataOperation::HistoryPathPage,
        HistoryPage::<Value> {
            state: PageState::Incomplete,
            items: Vec::new(),
            next_cursor: None,
            incomplete_reason: Some(HistoryIncompleteReason::RetentionGap),
        },
        &consistency,
    )
    .unwrap();
    assert_eq!(history.body()["state"], "incomplete");
    assert_eq!(history.body()["incompleteReason"], "retention-gap");

    let mut hidden = DomainError::new(DomainErrorCode::ObjectInvalid);
    hidden.retry_after_ms = Some(12);
    let hidden = MetadataHttpResponse::domain_error(MetadataOperation::ObjectPut, &hidden);
    assert_eq!(hidden.body()["safeParameters"], json!({}));
    assert!(!serde_json::to_string(&hidden)
        .unwrap()
        .contains("protected"));

    let mut conflict = DomainError::new(DomainErrorCode::ReferenceConflict);
    conflict.retry_after_ms = Some(99);
    let conflict =
        MetadataHttpResponse::domain_error(MetadataOperation::ReferenceCompareAndSwap, &conflict);
    assert_eq!(conflict.body()["safeParameters"], json!({}));

    let mut retry = DomainError::new(DomainErrorCode::ConsistencyTokenUnsatisfied);
    retry.retry_after_ms = Some(86_400_000);
    let retry = MetadataHttpResponse::domain_error(MetadataOperation::ObjectGet, &retry);
    assert_eq!(
        retry.body()["safeParameters"],
        json!({ "retryAfterMs": 86_400_000_u64 })
    );

    let mut excessive_retry = DomainError::new(DomainErrorCode::TransactionRetryExhausted);
    excessive_retry.retry_after_ms = Some(86_400_001);
    let excessive_retry = MetadataHttpResponse::domain_error(
        MetadataOperation::RepositoryGetSettings,
        &excessive_retry,
    );
    assert_eq!(excessive_retry.body()["safeParameters"], json!({}));

    let all_errors = [
        DomainErrorCode::RepositorySettingsImmutable,
        DomainErrorCode::ObjectInvalid,
        DomainErrorCode::ObjectIdCollision,
        DomainErrorCode::ReferenceConflict,
        DomainErrorCode::FileIdConflict,
        DomainErrorCode::HistoryLimitReached,
        DomainErrorCode::ConsistencyTokenUnsatisfied,
        DomainErrorCode::MigrationIncompatible,
        DomainErrorCode::MigrationChecksumMismatch,
        DomainErrorCode::MetadataNotFoundOrDenied,
        DomainErrorCode::TransactionRetryExhausted,
    ];
    for (index, code) in all_errors.into_iter().enumerate() {
        let response = MetadataHttpResponse::domain_error(
            MetadataOperation::RepositoryGetSettings,
            &DomainError::new(code),
        );
        assert_eq!(response.body()["code"], code.name());
        assert_eq!(response.body()["numericCode"], 1001 + index);
        assert_eq!(response.body()["retryable"], code.retryable());
        assert_eq!(response.body()["safeParameters"], json!({}));
    }
}

#[test]
fn every_success_carrier_has_one_bounded_schema_shaped_constructor() {
    let generic = MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "settingsGeneration": 3 }),
    )
    .unwrap();
    assert_eq!(generic.carrier(), "json");
    assert_eq!(generic.body()["settingsGeneration"], 3);
    assert!(MetadataHttpResponse::success_json(MetadataOperation::ObjectGet, json!({})).is_err());
    assert!(MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "maximum": 9_007_199_254_740_991_u64, "minimum": -9_007_199_254_740_991_i64 }),
    )
    .is_ok());
    assert!(MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "unsafeInteger": 9_007_199_254_740_992_u64 }),
    )
    .is_err());
    assert!(MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "float": 1.5 }),
    )
    .is_err());
    let normalized_integer = MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "integer": 1.0 }),
    )
    .unwrap();
    assert_eq!(normalized_integer.body()["integer"], 1);
    let mut over_nested = Value::Null;
    for _ in 0..65 {
        over_nested = json!([over_nested]);
    }
    assert!(MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "nested": over_nested }),
    )
    .is_err());
    assert!(MetadataHttpResponse::success_json(
        MetadataOperation::RepositoryGetSettings,
        json!({ "items": vec![Value::Null; 100_001] }),
    )
    .is_err());

    let object_ref = ObjectRef::from_str(TREE).unwrap();
    let stream = MetadataHttpResponse::object_stream(object_ref, 536_870_912, [0xab; 32])
        .expect("exact stream maximum");
    assert_eq!(stream.operation(), "object.get");
    assert_eq!(stream.carrier(), "canonical-metadata-byte-stream");
    assert_eq!(stream.body()["canonicalByteLength"], 536_870_912);
    assert_eq!(stream.body()["streamDigestSha256"], "ab".repeat(32));
    assert!(MetadataHttpResponse::object_stream(
        ObjectRef::from_str(TREE).unwrap(),
        536_870_913,
        [0; 32],
    )
    .is_err());

    let allocation = FileIdAllocation {
        repository_id: RepositoryId::from_bytes([
            0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 2,
        ]),
        file_id: FileId::from_str(FILE_ID).unwrap(),
        allocation_receipt: AllocationReceipt::from_opaque(opaque("far1", 'A')).unwrap(),
        expires_at: UNIX_EPOCH + Duration::from_millis(2_000),
    };
    let allocation = MetadataHttpResponse::file_id_allocation(&allocation).unwrap();
    assert_eq!(allocation.operation(), "file-id.allocate");
    assert_eq!(allocation.body()["repositoryId"], REPOSITORY);
    assert_eq!(allocation.body()["fileId"], FILE_ID);
    assert_eq!(allocation.body()["expiresAtUnixMs"], 2_000);
    let invalid_allocation = FileIdAllocation {
        repository_id: RepositoryId::from_bytes([0; 16]),
        file_id: FileId::from_str(FILE_ID).unwrap(),
        allocation_receipt: AllocationReceipt::from_opaque(opaque("far1", 'A')).unwrap(),
        expires_at: UNIX_EPOCH + Duration::from_millis(2_000),
    };
    assert!(MetadataHttpResponse::file_id_allocation(&invalid_allocation).is_err());

    let absent = MetadataHttpResponse::idempotency_status(&IdempotencyStatus::Absent).unwrap();
    assert_eq!(absent.body()["state"], "absent");
    let reserved = MetadataHttpResponse::idempotency_status(&IdempotencyStatus::Reserved {
        expires_at: UNIX_EPOCH + Duration::from_millis(2_000),
    })
    .unwrap();
    assert_eq!(reserved.body()["state"], "reserved");
    let committed = MetadataHttpResponse::idempotency_status(&IdempotencyStatus::Committed {
        expires_at: UNIX_EPOCH + Duration::from_millis(2_000),
        safe_result: json!({ "accepted": true }),
    })
    .unwrap();
    assert_eq!(committed.body()["state"], "committed");
    assert_eq!(committed.body()["safeResult"], json!({ "accepted": true }));

    let safe_maximum_time = UNIX_EPOCH + Duration::from_millis(9_007_199_254_740_991);
    let maximum = MetadataHttpResponse::idempotency_status(&IdempotencyStatus::Reserved {
        expires_at: safe_maximum_time,
    })
    .unwrap();
    assert_eq!(maximum.body()["expiresAtUnixMs"], 9_007_199_254_740_991_u64);
    let over_maximum = UNIX_EPOCH + Duration::from_millis(9_007_199_254_740_992);
    assert!(
        MetadataHttpResponse::idempotency_status(&IdempotencyStatus::Reserved {
            expires_at: over_maximum,
        })
        .is_err()
    );
}

fn hex(bytes: [u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
