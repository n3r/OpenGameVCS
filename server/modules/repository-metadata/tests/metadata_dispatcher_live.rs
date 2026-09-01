use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use ogvcs_identity_policy_audit_postgres::{
    run_migrations as run_identity_migrations, CredentialScope,
    MigrationRunOptions as IdentityMigrationRunOptions, PolicyDocument, PolicyRule,
    PostgresTransactionAuthorizationParticipant, RuleSubjects,
};
use ogvcs_object_model::{
    decode_canonical, encode_canonical, object_id, Cbor, Limits, ObjectKind, ProfileRef,
};
use ogvcs_repository_metadata::{
    run_migrations as run_metadata_migrations, MetadataNegotiationKeyRing,
    MetadataNegotiationPrincipal, MetadataOperationRequest, MetadataResponseEnvelope,
    MigrationRunOptions as MetadataMigrationRunOptions, PostgresMetadataReadDispatcher,
    RepositoryId, TenantId, TransactionCredentialRequest, METADATA_SERVICE_REQUEST_SCHEMA,
    OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256,
};
use postgres::{types::Json, Client, GenericClient, NoTls};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const DATABASE_ENV: &str = "OGVCS_METADATA_DISPATCH_DATABASE_URL";
const PRESENTATION_A: &str = "metadata-dispatch-presentation-a";
const PRESENTATION_B: &str = "metadata-dispatch-presentation-b";
const NEGOTIATION_KEY_ID: &str = "metadata-dispatch@1";
const NEGOTIATION_KEY: [u8; 32] = [0x91; 32];
const SUBJECT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-SUBJECT-V1\0";
const CREDENTIAL_DOMAIN: &[u8] = b"OGVCS-IDENTITY-CREDENTIAL-V1\0";
const TENANT_PROJECTION_DOMAIN: &[u8] = b"OGVCS-METADATA-NEGOTIATION-TENANT-BINDING-V1\0";
const REFERENCE_PROJECTION_DOMAIN: &[u8] = b"OGVCS-METADATA-REFERENCE-DISPATCH-RESOURCE-V1\0";
const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors/objects";

#[test]
fn sealed_metadata_dispatcher_is_current_non_enumerating_and_commit_atomic() {
    let Ok(database_url) = std::env::var(DATABASE_ENV) else {
        return;
    };
    let fixture = prepare_fresh_database(&database_url);
    let trusted_keys = Arc::new(
        MetadataNegotiationKeyRing::new(vec![(
            NEGOTIATION_KEY_ID.to_owned(),
            NEGOTIATION_KEY.to_vec(),
        )])
        .unwrap(),
    );
    let participant = PostgresTransactionAuthorizationParticipant::new().unwrap();
    let mut dispatcher = PostgresMetadataReadDispatcher::connect(
        &database_url,
        participant,
        Arc::clone(&trusted_keys),
    )
    .unwrap();

    let settings = dispatch(
        &mut dispatcher,
        trusted_keys.as_ref(),
        request(
            "repository.get-settings",
            &fixture,
            fixture.tenant_id,
            json!({
                "tenantId": uuid(fixture.tenant_id),
                "repositoryId": uuid(fixture.repository_id),
                "minimumConsistencyToken": null,
            }),
            fixture.subject_a,
            1,
            "correlation.settings.success",
            NEGOTIATION_KEY,
            None,
        ),
        PRESENTATION_A,
        "correlation.settings.success",
    );
    assert!(settings.success());
    let settings_body = response_body(&settings);
    assert_eq!(
        settings_body["operation"],
        Value::String("repository.get-settings".to_owned())
    );
    assert_eq!(settings_body["body"]["observedCommitSequence"], "1");
    let consistency = settings_body["body"]["consistencyToken"]
        .as_str()
        .unwrap()
        .to_owned();

    let reference = dispatch(
        &mut dispatcher,
        trusted_keys.as_ref(),
        request(
            "reference.read",
            &fixture,
            fixture.tenant_id,
            json!({
                "tenantId": uuid(fixture.tenant_id),
                "repositoryId": uuid(fixture.repository_id),
                "minimumConsistencyToken": consistency.clone(),
                "referenceKind": "branch",
                "referenceName": "main",
            }),
            fixture.subject_a,
            1,
            "correlation.reference.success",
            NEGOTIATION_KEY,
            None,
        ),
        PRESENTATION_A,
        "correlation.reference.success",
    );
    assert!(reference.success());
    assert_eq!(response_body(&reference)["body"]["referenceName"], "main");
    assert_counts(&database_url, 2, 2);

    let cross_subject_token = dispatch(
        &mut dispatcher,
        trusted_keys.as_ref(),
        request(
            "repository.get-settings",
            &fixture,
            fixture.tenant_id,
            settings_body_request(&fixture, Some(&consistency)),
            fixture.subject_b,
            1,
            "correlation.denied.cross-subject-token",
            NEGOTIATION_KEY,
            None,
        ),
        PRESENTATION_B,
        "correlation.denied.cross-subject-token",
    );
    assert_uniform_denial(
        &cross_subject_token,
        "correlation.denied.cross-subject-token",
        "valid-token-cross-subject-replay",
    );
    assert_counts(&database_url, 2, 2);

    let denial_cases = [
        (
            "hidden-reference",
            request(
                "reference.read",
                &fixture,
                fixture.tenant_id,
                reference_body(&fixture, "branch", "hidden", None),
                fixture.subject_a,
                1,
                "correlation.denied.hidden",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.hidden",
        ),
        (
            "missing-reference",
            request(
                "reference.read",
                &fixture,
                fixture.tenant_id,
                reference_body(&fixture, "tag", "missing", None),
                fixture.subject_a,
                1,
                "correlation.denied.missing",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.missing",
        ),
        (
            "cross-tenant",
            request(
                "repository.get-settings",
                &fixture,
                fixture.other_tenant_id,
                json!({
                    "tenantId": uuid(fixture.other_tenant_id),
                    "repositoryId": uuid(fixture.repository_id),
                    "minimumConsistencyToken": null,
                }),
                fixture.subject_a,
                1,
                "correlation.denied.cross-tenant",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.cross-tenant",
        ),
        (
            "cross-subject",
            request(
                "repository.get-settings",
                &fixture,
                fixture.tenant_id,
                settings_body_request(&fixture, None),
                fixture.subject_b,
                1,
                "correlation.denied.cross-subject",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.cross-subject",
        ),
        (
            "stale-epoch",
            request(
                "repository.get-settings",
                &fixture,
                fixture.tenant_id,
                settings_body_request(&fixture, None),
                fixture.subject_a,
                2,
                "correlation.denied.stale-epoch",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.stale-epoch",
        ),
        (
            "invalid-minimum-token",
            request(
                "repository.get-settings",
                &fixture,
                fixture.tenant_id,
                settings_body_request(
                    &fixture,
                    Some("ct1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                ),
                fixture.subject_a,
                1,
                "correlation.denied.token",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.token",
        ),
        (
            "operation-not-whitelisted",
            request(
                "object.get",
                &fixture,
                fixture.tenant_id,
                json!({
                    "tenantId": uuid(fixture.tenant_id),
                    "repositoryId": uuid(fixture.repository_id),
                    "minimumConsistencyToken": null,
                    "objectRef": format!("ogvcs:v1:tree:sha256:{}", "44".repeat(32)),
                }),
                fixture.subject_a,
                1,
                "correlation.denied.operation",
                NEGOTIATION_KEY,
                None,
            ),
            PRESENTATION_A,
            "correlation.denied.operation",
        ),
    ];
    for (label, request, presentation, correlation) in denial_cases {
        let response = dispatch(
            &mut dispatcher,
            trusted_keys.as_ref(),
            request,
            presentation,
            correlation,
        );
        assert_uniform_denial(&response, correlation, label);
    }

    let expired = request(
        "repository.get-settings",
        &fixture,
        fixture.tenant_id,
        settings_body_request(&fixture, None),
        fixture.subject_a,
        1,
        "correlation.denied.expired",
        NEGOTIATION_KEY,
        Some((fixture.now_unix_ms - 10_000, fixture.now_unix_ms - 1)),
    );
    let expired_principal = principal(
        fixture.subject_a,
        fixture.tenant_id,
        1,
        fixture.now_unix_ms - 5_000,
    );
    let expired_verified = expired
        .verify_negotiation(trusted_keys.as_ref(), &expired_principal)
        .unwrap();
    let expired_response = dispatcher.dispatch_verified_read(
        expired_verified,
        credentials(PRESENTATION_A, "correlation.denied.expired"),
    );
    assert_uniform_denial(
        &expired_response,
        "correlation.denied.expired",
        "database-clock-expiry",
    );

    let attacker_keys =
        MetadataNegotiationKeyRing::new(vec![(NEGOTIATION_KEY_ID.to_owned(), vec![0x22; 32])])
            .unwrap();
    let forged = request(
        "repository.get-settings",
        &fixture,
        fixture.tenant_id,
        settings_body_request(&fixture, None),
        fixture.subject_a,
        1,
        "correlation.denied.forged",
        [0x22; 32],
        None,
    );
    let forged_verified = forged
        .verify_negotiation(
            &attacker_keys,
            &principal(fixture.subject_a, fixture.tenant_id, 1, fixture.now_unix_ms),
        )
        .unwrap();
    let forged_response = dispatcher.dispatch_verified_read(
        forged_verified,
        credentials(PRESENTATION_A, "correlation.denied.forged"),
    );
    assert_uniform_denial(
        &forged_response,
        "correlation.denied.forged",
        "substituted-key-ring",
    );

    let mismatch = request(
        "repository.get-settings",
        &fixture,
        fixture.tenant_id,
        settings_body_request(&fixture, None),
        fixture.subject_a,
        1,
        "correlation.request",
        NEGOTIATION_KEY,
        None,
    );
    let mismatch_response = dispatch(
        &mut dispatcher,
        trusted_keys.as_ref(),
        mismatch,
        PRESENTATION_A,
        "correlation.credentials",
    );
    assert_uniform_denial(
        &mismatch_response,
        "correlation.request",
        "credential-correlation-substitution",
    );
    assert_counts(&database_url, 2, 2);

    install_deferred_commit_fault(&database_url);
    let commit_fault = dispatch(
        &mut dispatcher,
        trusted_keys.as_ref(),
        request(
            "repository.get-settings",
            &fixture,
            fixture.tenant_id,
            settings_body_request(&fixture, None),
            fixture.subject_a,
            1,
            "correlation.denied.commit-fault",
            NEGOTIATION_KEY,
            None,
        ),
        PRESENTATION_A,
        "correlation.denied.commit-fault",
    );
    assert_uniform_denial(
        &commit_fault,
        "correlation.denied.commit-fault",
        "post-decision-commit-fault",
    );
    assert_counts(&database_url, 2, 2);
    remove_deferred_commit_fault(&database_url);

    assert_eq!(
        reference_projection("branch", "main"),
        "reference.branch.018091fc8353e10067e61086bb9c21889eb805c3c9ef179505202658450afc18"
    );
}

fn dispatch(
    dispatcher: &mut PostgresMetadataReadDispatcher,
    keys: &MetadataNegotiationKeyRing,
    request: MetadataOperationRequest,
    presentation: &str,
    credential_correlation: &str,
) -> MetadataResponseEnvelope {
    let claims = request.negotiation_receipt()["claims"].as_object().unwrap();
    let subject = decode_hex_32(claims["subjectDigest"].as_str().unwrap());
    let tenant = request.tenant_id().unwrap();
    let epoch = claims["authorityEpoch"].as_u64().unwrap();
    let now = claims["issuedAtUnixMs"].as_u64().unwrap();
    let verified = request
        .verify_negotiation(keys, &principal(subject, tenant, epoch, now))
        .unwrap();
    dispatcher.dispatch_verified_read(verified, credentials(presentation, credential_correlation))
}

fn credentials<'a>(
    presentation: &'a str,
    correlation_id: &'a str,
) -> TransactionCredentialRequest<'a> {
    TransactionCredentialRequest {
        request_id: correlation_id,
        correlation_id,
        credential_presentation: presentation,
        reason: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn request(
    operation: &str,
    fixture: &Fixture,
    principal_tenant: TenantId,
    body: Value,
    subject_digest: [u8; 32],
    authority_epoch: u64,
    correlation_id: &str,
    signing_key: [u8; 32],
    validity: Option<(u64, u64)>,
) -> MetadataOperationRequest {
    let (issued_at, expires_at) = validity.unwrap_or((
        fixture.now_unix_ms.saturating_sub(1_000),
        fixture.now_unix_ms + 240_000,
    ));
    let claims = json!({
        "schemaVersion": "ogvcs.protocol/negotiation-receipt-claims/v1",
        "selection": negotiation_selection(),
        "subjectDigest": hex(&subject_digest),
        "tenantDigest": hex(&tenant_projection(principal_tenant)),
        "authorityEpoch": authority_epoch,
        "sessionId": "metadata-dispatch-session-0001",
        "clientNonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "serverNonce": "AQEBAQEBAQEBAQEBAQEBAQ",
        "issuedAtUnixMs": issued_at,
        "expiresAtUnixMs": expires_at,
    });
    let mut receipt = json!({
        "algorithm": "HMAC-SHA-256",
        "keyId": NEGOTIATION_KEY_ID,
        "claims": claims,
        "mac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    });
    sign_receipt(&mut receipt, &signing_key);
    let document = json!({
        "schemaVersion": METADATA_SERVICE_REQUEST_SCHEMA,
        "operation": operation,
        "correlationId": correlation_id,
        "negotiationReceipt": receipt,
        "body": body,
        "extensions": {},
    });
    MetadataOperationRequest::parse(&serde_json::to_vec(&document).unwrap()).unwrap_or_else(
        |error| panic!("request parse failed for {operation}: {error:?}: {document}"),
    )
}

fn negotiation_selection() -> Value {
    json!({
        "schemaVersion": "ogvcs.protocol/negotiation-selection/v1",
        "protocolVersion": "ogvcs.control.https-json@1",
        "messageSchemaVersion": "ogvcs.protocol.schema@1",
        "repositoryFormat": "ogvcs.repository-format@1",
        "authorizationContract": "ogvcs.authorization@1",
        "authorizationRegistrySha256": "293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc",
        "pathContract": "ogvcs.path-filesystem@1",
        "pathProfile": "path.opengamevcs/portable@1",
        "pathRegistrySha256": "bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42",
        "eventVersion": "ogvcs.events.base@1",
        "transferProfile": "ogvcs.transfer.range-resume-probe@1",
        "extensions": [],
        "protocolRegistrySetSha256": OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256,
        "repositoryRegistrySha256": "6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6",
    })
}

fn sign_receipt(receipt: &mut Value, key: &[u8]) {
    let key_id = receipt["keyId"].as_str().unwrap().to_owned();
    let claims = receipt["claims"].clone();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(b"OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0");
    mac.update(key_id.as_bytes());
    mac.update(&[0]);
    mac.update(&jcs(&claims));
    receipt["mac"] = Value::String(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));
}

fn jcs(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    write_jcs(value, &mut output);
    output
}

fn write_jcs(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => serde_json::to_writer(output, value).unwrap(),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_jcs(value, output);
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut values: Vec<_> = values.iter().collect();
            values.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
            output.push(b'{');
            for (index, (key, value)) in values.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).unwrap();
                output.push(b':');
                write_jcs(value, output);
            }
            output.push(b'}');
        }
    }
}

fn principal(
    subject_digest: [u8; 32],
    tenant_id: TenantId,
    authority_epoch: u64,
    now_unix_ms: u64,
) -> MetadataNegotiationPrincipal {
    MetadataNegotiationPrincipal {
        subject_digest,
        tenant_digest: tenant_projection(tenant_id),
        authority_epoch,
        session_id: "metadata-dispatch-session-0001".to_owned(),
        now_unix_ms,
    }
}

fn tenant_projection(tenant_id: TenantId) -> [u8; 32] {
    digest_parts(&[TENANT_PROJECTION_DOMAIN, tenant_id.as_bytes()])
}

fn reference_projection(kind: &str, name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(REFERENCE_PROJECTION_DOMAIN);
    digest.update((kind.len() as u64).to_be_bytes());
    digest.update(kind.as_bytes());
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    format!("reference.{kind}.{}", hex(&digest.finalize()))
}

fn settings_body_request(fixture: &Fixture, minimum: Option<&str>) -> Value {
    json!({
        "tenantId": uuid(fixture.tenant_id),
        "repositoryId": uuid(fixture.repository_id),
        "minimumConsistencyToken": minimum,
    })
}

fn reference_body(fixture: &Fixture, kind: &str, name: &str, minimum: Option<&str>) -> Value {
    json!({
        "tenantId": uuid(fixture.tenant_id),
        "repositoryId": uuid(fixture.repository_id),
        "minimumConsistencyToken": minimum,
        "referenceKind": kind,
        "referenceName": name,
    })
}

fn response_body(response: &MetadataResponseEnvelope) -> &Value {
    response.body().unwrap()
}

fn assert_uniform_denial(response: &MetadataResponseEnvelope, correlation: &str, label: &str) {
    assert!(!response.success(), "{label} unexpectedly succeeded");
    assert!(response.body().is_none(), "{label} disclosed a body");
    assert_eq!(response.correlation_id(), correlation, "{label}");
    let problem = response.problem().unwrap();
    assert_eq!(problem.code(), "AUTHORIZATION_DENIED", "{label}");
    assert_eq!(problem.status(), 403, "{label}");
}

fn assert_counts(database_url: &str, commitments: i64, tokens: i64) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments),
               (SELECT count(*) FROM ogvcs_metadata.consistency_tokens)",
            &[],
        )
        .unwrap();
    assert_eq!(
        (row.get::<_, i64>(0), row.get::<_, i64>(1)),
        (commitments, tokens)
    );
}

fn install_deferred_commit_fault(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .batch_execute(
            "CREATE FUNCTION ogvcs_metadata.reject_dispatch_commit_for_test()
             RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'dispatch commit fault'; END $$;
             CREATE CONSTRAINT TRIGGER reject_dispatch_commit_for_test
             AFTER INSERT ON ogvcs_metadata.consistency_tokens
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
             EXECUTE FUNCTION ogvcs_metadata.reject_dispatch_commit_for_test();",
        )
        .unwrap();
}

fn remove_deferred_commit_fault(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .batch_execute(
            "DROP TRIGGER reject_dispatch_commit_for_test
             ON ogvcs_metadata.consistency_tokens;
             DROP FUNCTION ogvcs_metadata.reject_dispatch_commit_for_test();",
        )
        .unwrap();
}

struct Fixture {
    tenant_id: TenantId,
    other_tenant_id: TenantId,
    repository_id: RepositoryId,
    subject_a: [u8; 32],
    subject_b: [u8; 32],
    now_unix_ms: u64,
}

fn prepare_fresh_database(database_url: &str) -> Fixture {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let empty: bool = client
        .query_one(
            "SELECT to_regnamespace('ogvcs_identity') IS NULL
                 AND to_regnamespace('ogvcs_metadata') IS NULL",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(
        empty,
        "metadata dispatcher live test requires a fresh database"
    );
    run_identity_migrations(
        &mut client,
        IdentityMigrationRunOptions {
            application_version: "0.2.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();
    run_metadata_migrations(
        &mut client,
        MetadataMigrationRunOptions {
            application_version: "0.1.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();

    let descriptor_path = format!(
        "{}/{VECTOR_ROOT}/06-repository-descriptor.cbor",
        env!("CARGO_MANIFEST_DIR")
    );
    let descriptor_template = fs::read(descriptor_path).unwrap();
    let repository_id = RepositoryId::from_bytes(public_uuid(0x22));
    let mut descriptor = decode_canonical(&descriptor_template, Limits::METADATA).unwrap();
    let Cbor::Map(descriptor_fields) = &mut descriptor else {
        panic!("descriptor")
    };
    descriptor_fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(16))
        .unwrap()
        .1 = Cbor::Bytes(repository_id.as_bytes().to_vec());
    let descriptor_bytes = encode_canonical(&descriptor).unwrap();
    let tenant_id = TenantId::from_bytes(public_uuid(0x11));
    let other_tenant_id = TenantId::from_bytes(public_uuid(0x12));
    let repository_uuid = uuid_value(repository_id);
    let tenant_uuid = uuid_value(tenant_id);
    let descriptor_digest = object_id(ObjectKind::RepositoryDescriptor, &descriptor_bytes).unwrap();
    let (features, path_profile, content_profile) = descriptor_settings(&descriptor);
    let tree_digest = [0x33; 32];
    let snapshot_digest = [0x44; 32];

    client
        .execute(
            "INSERT INTO ogvcs_metadata.repositories (repository_id, tenant_id, project_id)
             VALUES ($1, $2, $3)",
            &[
                &repository_uuid,
                &tenant_uuid,
                &Uuid::from_bytes(public_uuid(0x13)),
            ],
        )
        .unwrap();
    for (kind, digest, bytes) in [
        (6_i16, descriptor_digest, descriptor_bytes.as_slice()),
        (3_i16, tree_digest, &[0xa0][..]),
        (7_i16, snapshot_digest, &[0xa0][..]),
    ] {
        client
            .execute(
                "INSERT INTO ogvcs_metadata.metadata_objects
                 (repository_id, object_kind, digest_algorithm, object_digest,
                  canonical_bytes, validation_contract)
                 VALUES ($1, $2, 1, $3, $4, 'ogvcs.repository-format@1')",
                &[&repository_uuid, &kind, &&digest[..], &bytes],
            )
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_settings
             (repository_id, descriptor_kind, descriptor_algorithm, descriptor_digest,
              repository_format, required_features, case_mode, path_profile,
              platform_profile, content_policy_profile, structural_limits,
              tenant_boundary, settings_generation)
             VALUES ($1, 6, 1, $2, 'ogvcs.repository-format@1', $3, 'case-sensitive',
                     $4, $4, $5,
                     '{\"maxTreeEntries\":1000000,\"maxPathBytes\":4096,\"maxPathSegments\":256,\"maxSnapshotParents\":8}'::jsonb,
                     $6, 1)",
            &[
                &repository_uuid,
                &&descriptor_digest[..],
                &Json(&features),
                &path_profile,
                &content_profile,
                &tenant_uuid,
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_commit_sequences
             (repository_id, applied_sequence) VALUES ($1, 1)",
            &[&repository_uuid],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.snapshots
             (repository_id, snapshot_digest, root_tree_digest, published_commit_sequence)
             VALUES ($1, $2, $3, 1)",
            &[&repository_uuid, &&snapshot_digest[..], &&tree_digest[..]],
        )
        .unwrap();
    for name in ["main", "hidden"] {
        client
            .execute(
                "INSERT INTO ogvcs_metadata.references
                 (repository_id, reference_kind, reference_name, target_snapshot_digest,
                  generation, commit_sequence) VALUES ($1, 'branch', $2, $3, 1, 1)",
                &[&repository_uuid, &name, &&snapshot_digest[..]],
            )
            .unwrap();
    }

    let tenant = identity_tenant(tenant_id);
    let repository = identity_repository(repository_id);
    client
        .execute(
            "INSERT INTO ogvcs_identity.authority_states
             (tenant_id, authority_epoch, key_generation) VALUES ($1, 1, 1)",
            &[&tenant],
        )
        .unwrap();
    let policy = PolicyDocument {
        schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
        id: "policy.metadata-dispatch".to_owned(),
        version: "version.one".to_owned(),
        generation: 1,
        authority_epoch: 1,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        case_mode: "case-sensitive".to_owned(),
        default_effect: "deny".to_owned(),
        composition: "deny-overrides-v1".to_owned(),
        rules: vec![
            policy_rule(
                "allow-reference",
                "allow",
                &tenant,
                &repository,
                vec![],
                vec!["reference"],
            ),
            policy_rule(
                "allow-repository",
                "allow",
                &tenant,
                &repository,
                vec![],
                vec!["repository"],
            ),
            policy_rule(
                "deny-hidden-reference",
                "deny",
                &tenant,
                &repository,
                vec![reference_projection("branch", "hidden")],
                vec!["reference"],
            ),
        ],
    };
    client
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch, policy_id,
              policy_version, path_profile, case_mode, policy_json, policy_digest)
             VALUES ($1, $2, 1, 1, $3, $4, $5, $6, $7, $8)",
            &[
                &tenant,
                &repository,
                &policy.id,
                &policy.version,
                &policy.path_profile,
                &policy.case_mode,
                &Json(&policy),
                &&digest_json(&policy)[..],
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_identity.current_policies
             (tenant_id, repository_id, policy_generation) VALUES ($1, $2, 1)",
            &[&tenant, &repository],
        )
        .unwrap();
    let subject_a = seed_credential(
        &mut client,
        &tenant,
        &repository,
        "subject.a",
        PRESENTATION_A,
    );
    let subject_b = seed_credential(
        &mut client,
        &tenant,
        &repository,
        "subject.b",
        PRESENTATION_B,
    );
    Fixture {
        tenant_id,
        other_tenant_id,
        repository_id,
        subject_a,
        subject_b,
        now_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    }
}

fn policy_rule(
    id: &str,
    effect: &str,
    tenant: &str,
    repository: &str,
    references: Vec<String>,
    resource_types: Vec<&str>,
) -> PolicyRule {
    PolicyRule {
        id: id.to_owned(),
        effect: effect.to_owned(),
        subjects: RuleSubjects {
            identities: Vec::new(),
            groups: Vec::new(),
            actor_classes: vec!["service".to_owned()],
        },
        tenant: tenant.to_owned(),
        repository: repository.to_owned(),
        references,
        path_prefixes: Vec::new(),
        resource_types: resource_types.into_iter().map(str::to_owned).collect(),
        permissions: vec!["metadata.read".to_owned()],
    }
}

fn seed_credential(
    client: &mut impl GenericClient,
    tenant: &str,
    repository: &str,
    subject: &str,
    presentation: &str,
) -> [u8; 32] {
    let scope = CredentialScope {
        tenants: vec![tenant.to_owned()],
        repositories: vec![repository.to_owned()],
        references: Vec::new(),
        path_prefixes: Vec::new(),
        permissions: vec!["metadata.read".to_owned()],
    };
    let subject_digest = digest_parts(&[SUBJECT_DOMAIN, subject.as_bytes()]);
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation, presentation_digest,
              subject_id, subject_digest, actor_class, credential_class, groups_json,
              authority_epoch, issued_at, expires_at, state, scope_json, scope_digest)
             VALUES ($1, $2, 1, $3, $2, $4, 'service', 'service-token', '[]'::jsonb,
                     1, clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '30 minutes', 'active', $5, $6)",
            &[
                &tenant,
                &subject,
                &&digest_parts(&[CREDENTIAL_DOMAIN, presentation.as_bytes()])[..],
                &&subject_digest[..],
                &Json(&scope),
                &&digest_json(&scope)[..],
            ],
        )
        .unwrap();
    subject_digest
}

fn descriptor_settings(descriptor: &Cbor) -> (Vec<u16>, String, String) {
    let Cbor::Array(features) = cbor_field(descriptor, 2) else {
        panic!("features")
    };
    let features = features
        .iter()
        .map(|value| match value {
            Cbor::UInt(code) => u16::try_from(*code).unwrap(),
            _ => panic!("feature"),
        })
        .collect();
    let path = ProfileRef::from_cbor(cbor_field(descriptor, 17))
        .unwrap()
        .to_string();
    let Cbor::Array(content) = cbor_field(descriptor, 18) else {
        panic!("content")
    };
    let content = ProfileRef::from_cbor(&content[0]).unwrap().to_string();
    (features, path, content)
}

fn cbor_field(value: &Cbor, key: u64) -> &Cbor {
    let Cbor::Map(fields) = value else {
        panic!("map")
    };
    &fields
        .iter()
        .find(|(field, _)| *field == Cbor::UInt(key))
        .unwrap()
        .1
}

fn digest_json<T: Serialize>(value: &T) -> [u8; 32] {
    let value = serde_json::to_value(value).unwrap();
    digest_parts(&[&serde_json::to_vec(&canonical(value)).unwrap()])
}

fn canonical(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical).collect()),
        Value::Object(values) => {
            let values: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect();
            Value::Object(values.into_iter().collect())
        }
        value => value,
    }
}

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("hex"),
    }
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

fn public_uuid(marker: u8) -> [u8; 16] {
    let mut bytes = [marker; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn uuid<T: PublicUuid>(value: T) -> String {
    Uuid::from_bytes(value.bytes()).to_string()
}
fn uuid_value<T: PublicUuid>(value: T) -> Uuid {
    Uuid::from_bytes(value.bytes())
}

trait PublicUuid: Copy {
    fn bytes(self) -> [u8; 16];
}
impl PublicUuid for TenantId {
    fn bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}
impl PublicUuid for RepositoryId {
    fn bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}

fn identity_tenant(tenant_id: TenantId) -> String {
    format!("tenant.{}", hex(tenant_id.as_bytes()))
}
fn identity_repository(repository_id: RepositoryId) -> String {
    format!("repository.{}", hex(repository_id.as_bytes()))
}
