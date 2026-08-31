use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ogvcs_identity_policy_audit_postgres::{
    run_migrations as run_identity_migrations,
    AuthorizationResource as IdentityAuthorizationResource, CredentialScope,
    MigrationRunOptions as IdentityMigrationRunOptions, PolicyDocument, PolicyRule,
    PostgresTransactionAuthorizationParticipant, RuleSubjects, TransactionAuthorizationParticipant,
    TransactionAuthorizationRequest,
};
use ogvcs_repository_metadata::{
    run_migrations as run_metadata_migrations, CommitSequence, DomainErrorCode, FileId,
    FileIdOrigin, FileIdOwnerKind, FileIdReservation, IdempotencyReservation,
    IdempotencyReservationOutcome, IdentityBoundPostgresMetadataStore, MetadataTransaction,
    MigrationRunOptions as MetadataMigrationRunOptions, NativeFileIdReservation, OutboxEvent,
    RepositoryId, TenantId, TransactionCapability, TransactionCredentialRequest,
    TransactionOptions,
};
use postgres::{types::Json, Client, NoTls};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PRESENTATION_A: &str = "credential-presentation-a";
const PRESENTATION_B: &str = "credential-presentation-b";

#[test]
fn identity_bound_metadata_is_scope_receipt_and_commitment_atomic() {
    let Ok(database_url) = std::env::var("OGVCS_METADATA_IDENTITY_DATABASE_URL") else {
        return;
    };
    let tenant_id = TenantId::from_bytes(public_uuid_bytes(0x11));
    let repository_id = RepositoryId::from_bytes(public_uuid_bytes(0x22));
    prepare_database(&database_url, tenant_id, repository_id);

    let probe = PostgresTransactionAuthorizationParticipant::new().unwrap();
    let mut probe_client = Client::connect(&database_url, NoTls).unwrap();
    let identical_subject_scopes: (i64, i64) = probe_client
        .query_one(
            "SELECT count(*), count(DISTINCT scope_digest)
             FROM ogvcs_identity.credentials
             WHERE credential_id IN ('credential.a', 'credential.b')",
            &[],
        )
        .map(|row| (row.get(0), row.get(1)))
        .unwrap();
    assert_eq!(
        identical_subject_scopes,
        (2, 1),
        "the cross-subject replay probe requires byte-identical credential scopes"
    );
    let mut probe_transaction = probe_client.transaction().unwrap();
    let tenant = format!("tenant.{}", hex(tenant_id.as_bytes()));
    let repository = format!("repository.{}", hex(repository_id.as_bytes()));
    let resource = IdentityAuthorizationResource {
        resource_type: "repository".to_owned(),
        path: None,
        file_id: None,
        object_id: None,
        name: Some("file-id.register".to_owned()),
    };
    probe
        .authorize(
            &mut probe_transaction,
            &TransactionAuthorizationRequest {
                request_id: "request.probe",
                credential_presentation: PRESENTATION_A,
                tenant: &tenant,
                repository: &repository,
                permission: "submit",
                reason: None,
                resource: &resource,
                reference: None,
                snapshot: None,
            },
        )
        .unwrap();
    probe_transaction.rollback().unwrap();

    let participant = PostgresTransactionAuthorizationParticipant::new().unwrap();
    let mut store =
        IdentityBoundPostgresMetadataStore::connect(&database_url, participant).unwrap();

    let capability_scope_key = idempotency("scope.probe", "capability-scope", [0x2f; 32]);
    let mut reserve_scope = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.scope.reserve",
                "correlation.scope.reserve",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        reserve_scope
            .reserve_idempotency(capability_scope_key.clone())
            .unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    reserve_scope
        .commit_idempotency(&capability_scope_key, json!({"capability": "reserve"}))
        .unwrap();
    assert_eq!(reserve_scope.commit().unwrap().get(), 0);

    let mut tombstone_scope = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.scope.tombstone",
                "correlation.scope.tombstone",
            ),
            tenant_id,
            TransactionCapability::TombstoneFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        tombstone_scope
            .reserve_idempotency(capability_scope_key)
            .unwrap(),
        IdempotencyReservationOutcome::Reserved,
        "the same authority scope, operation, and key must not cross capabilities"
    );
    tombstone_scope.rollback().unwrap();

    let allocate = idempotency("file-id.allocate", "allocation-a", [0x31; 32]);
    let first = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.allocate.a1",
                "correlation.allocate.a1",
            ),
            tenant_id,
            repository_id,
            allocate.clone(),
        )
        .unwrap();
    let retry = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.allocate.a2",
                "correlation.allocate.a2",
            ),
            tenant_id,
            repository_id,
            allocate,
        )
        .unwrap();
    assert_eq!(
        retry, first,
        "an exact allocation retry must not draw entropy"
    );

    let other_scope = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_B,
                "request.allocate.b",
                "correlation.allocate.b",
            ),
            tenant_id,
            repository_id,
            idempotency("file-id.allocate", "allocation-a", [0x31; 32]),
        )
        .unwrap();
    assert_ne!(other_scope.file_id, first.file_id);
    assert_ne!(other_scope.allocation_receipt, first.allocation_receipt);

    let epoch_scope_key = idempotency("file-id.allocate", "epoch-scope", [0x3a; 32]);
    let pre_epoch_scope = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.allocate.epoch-one",
                "correlation.allocate.epoch-one",
            ),
            tenant_id,
            repository_id,
            epoch_scope_key.clone(),
        )
        .unwrap();

    let denied_key = idempotency("file-id.register", "path-denied", [0x30; 32]);
    let mut path_denied = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_B,
                "request.path-denied",
                "correlation.path-denied",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    path_denied.reserve_idempotency(denied_key.clone()).unwrap();
    path_denied
        .register_allocated_file_id(native(repository_id, &other_scope, "path-denied"))
        .unwrap();
    path_denied
        .append_outbox(OutboxEvent {
            event_id: public_uuid_bytes(0x41),
            repository_id,
            correlation_id: public_uuid_bytes(0x42),
        })
        .unwrap();
    path_denied
        .commit_idempotency(
            &denied_key,
            json!({"must": "be denied by exact path resource"}),
        )
        .unwrap();
    assert_eq!(
        path_denied.commit().unwrap_err().code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let mut cross_scope = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_B,
                "request.cross-scope",
                "correlation.cross-scope",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    cross_scope
        .reserve_idempotency(idempotency("file-id.register", "cross-scope", [0x32; 32]))
        .unwrap();
    assert_eq!(
        cross_scope
            .register_allocated_file_id(native(repository_id, &first, "cross-scope"))
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        cross_scope.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let mut bypass = store
        .begin_identity_authorized(
            credentials(PRESENTATION_A, "request.bypass", "correlation.bypass"),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    bypass
        .reserve_idempotency(idempotency("file-id.register", "bypass", [0x33; 32]))
        .unwrap();
    assert_eq!(
        bypass
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id: FileId::new([0x44; 16]).unwrap(),
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "receiptless".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        bypass.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let register_key = idempotency("file-id.register", "commit", [0x34; 32]);
    let mut committed = store
        .begin_identity_authorized(
            credentials(PRESENTATION_A, "request.commit", "correlation.commit"),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    committed.reserve_idempotency(register_key.clone()).unwrap();
    committed
        .register_allocated_file_id(native(repository_id, &first, "committed"))
        .unwrap();
    committed
        .append_outbox(OutboxEvent {
            event_id: public_uuid_bytes(0x51),
            repository_id,
            correlation_id: public_uuid_bytes(0x52),
        })
        .unwrap();
    committed
        .commit_idempotency(
            &register_key,
            json!({"registered": first.file_id.to_string()}),
        )
        .unwrap();
    assert_eq!(committed.commit().unwrap().get(), 1);

    let publish_allocation = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.allocate.publish",
                "correlation.allocate.publish",
            ),
            tenant_id,
            repository_id,
            idempotency("file-id.allocate", "publish", [0x38; 32]),
        )
        .unwrap();
    let publish_key = idempotency("file-id.register", "publish", [0x39; 32]);
    let mut publish_register = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.publish-register",
                "correlation.publish-register",
            ),
            tenant_id,
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    publish_register
        .reserve_idempotency(publish_key.clone())
        .unwrap();
    publish_register
        .register_allocated_file_id(native(
            repository_id,
            &publish_allocation,
            "publish-register",
        ))
        .unwrap();
    publish_register
        .append_outbox(OutboxEvent {
            event_id: public_uuid_bytes(0x53),
            repository_id,
            correlation_id: public_uuid_bytes(0x54),
        })
        .unwrap();
    publish_register
        .commit_idempotency(
            &publish_key,
            json!({"registered": publish_allocation.file_id.to_string()}),
        )
        .unwrap();
    assert_eq!(publish_register.commit().unwrap().get(), 2);

    let mut token_transaction = store
        .begin_identity_authorized(
            credentials(PRESENTATION_A, "request.token", "correlation.token"),
            tenant_id,
            TransactionCapability::IssueConsistencyToken,
            repository_id,
            TransactionOptions::RepeatableRead,
        )
        .unwrap();
    token_transaction
        .issue_consistency_token(CommitSequence::new(1))
        .unwrap();
    assert_eq!(token_transaction.commit().unwrap().get(), 0);

    let mut replay_receipt = store
        .begin_identity_authorized(
            credentials(PRESENTATION_A, "request.replay", "correlation.replay"),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    replay_receipt
        .reserve_idempotency(idempotency("file-id.register", "replay", [0x35; 32]))
        .unwrap();
    assert_eq!(
        replay_receipt
            .register_allocated_file_id(native(repository_id, &first, "replay"))
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        replay_receipt.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let rollback_allocation = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.allocate.rollback",
                "correlation.allocate.rollback",
            ),
            tenant_id,
            repository_id,
            idempotency("file-id.allocate", "rollback", [0x36; 32]),
        )
        .unwrap();
    let rollback_key = idempotency("file-id.register", "rollback", [0x37; 32]);
    let mut rollback = store
        .begin_identity_authorized(
            credentials(PRESENTATION_A, "request.rollback", "correlation.rollback"),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    rollback.reserve_idempotency(rollback_key.clone()).unwrap();
    rollback
        .register_allocated_file_id(native(repository_id, &rollback_allocation, "rollback"))
        .unwrap();
    rollback
        .append_outbox(OutboxEvent {
            event_id: public_uuid_bytes(0x61),
            repository_id,
            correlation_id: public_uuid_bytes(0x62),
        })
        .unwrap();
    rollback
        .commit_idempotency(&rollback_key, json!({"must": "roll back"}))
        .unwrap();
    let ignored = rollback.reserve_file_id(FileIdReservation {
        repository_id,
        file_id: FileId::new([0x63; 16]).unwrap(),
        origin: FileIdOrigin::Copy,
        owner_kind: FileIdOwnerKind::Draft,
        owner_id: "ignored-error".to_owned(),
    });
    assert_eq!(ignored.unwrap_err().code, DomainErrorCode::FileIdConflict);
    assert_eq!(
        rollback.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let mut client = Client::connect(&database_url, NoTls).unwrap();
    let registered: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.file_id_registry WHERE repository_id = $1",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap()
        .get(0);
    assert_eq!(registered, 2, "only the two atomic successes may persist");
    let rolled_back_receipt: Option<SystemTime> = client
        .query_one(
            "SELECT consumed_at FROM ogvcs_metadata.file_id_allocation_receipts
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&rollback_allocation.file_id.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert!(rolled_back_receipt.is_none());
    let commit_decisions: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments
             WHERE correlation_id = 'correlation.commit'",
            &[],
        )
        .unwrap()
        .get(0);
    let scoped_tokens: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.consistency_tokens
             WHERE authenticated_scope_digest IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0);
    let rollback_decisions: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments
             WHERE correlation_id = 'correlation.rollback'",
            &[],
        )
        .unwrap()
        .get(0);
    let denied_decisions: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments
             WHERE correlation_id = 'correlation.path-denied'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(commit_decisions, 1);
    assert_eq!(scoped_tokens, 1);
    assert_eq!(rollback_decisions, 0);
    assert_eq!(denied_decisions, 0);
    drop(client);

    promote_subject_a_authority(&database_url, &tenant, &repository);
    let post_epoch_scope = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.allocate.epoch-two",
                "correlation.allocate.epoch-two",
            ),
            tenant_id,
            repository_id,
            epoch_scope_key,
        )
        .unwrap();
    assert_ne!(post_epoch_scope.file_id, pre_epoch_scope.file_id);
    assert_ne!(
        post_epoch_scope.allocation_receipt,
        pre_epoch_scope.allocation_receipt
    );

    let mut cross_epoch = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.cross-epoch",
                "correlation.cross-epoch",
            ),
            tenant_id,
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    cross_epoch
        .reserve_idempotency(idempotency("file-id.register", "cross-epoch", [0x3b; 32]))
        .unwrap();
    assert_eq!(
        cross_epoch
            .register_allocated_file_id(native(repository_id, &pre_epoch_scope, "cross-epoch",))
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        cross_epoch.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let post_epoch_key = idempotency("file-id.register", "epoch-two", [0x3c; 32]);
    let mut post_epoch_publish = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.publish.epoch-two",
                "correlation.publish.epoch-two",
            ),
            tenant_id,
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    post_epoch_publish
        .reserve_idempotency(post_epoch_key.clone())
        .unwrap();
    post_epoch_publish
        .register_allocated_file_id(native(repository_id, &post_epoch_scope, "epoch-two"))
        .unwrap();
    post_epoch_publish
        .append_outbox(OutboxEvent {
            event_id: public_uuid_bytes(0x71),
            repository_id,
            correlation_id: public_uuid_bytes(0x72),
        })
        .unwrap();
    post_epoch_publish
        .commit_idempotency(
            &post_epoch_key,
            json!({"registered": post_epoch_scope.file_id.to_string()}),
        )
        .unwrap();
    assert!(post_epoch_publish.commit().unwrap().get() > 2);
}

fn promote_subject_a_authority(database_url: &str, tenant: &str, repository: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    let Json(mut policy): Json<PolicyDocument> = transaction
        .query_one(
            "SELECT version.policy_json
             FROM ogvcs_identity.current_policies AS current
             JOIN ogvcs_identity.policy_versions AS version
               ON version.tenant_id = current.tenant_id
              AND version.repository_id = current.repository_id
              AND version.policy_generation = current.policy_generation
             WHERE current.tenant_id = $1 AND current.repository_id = $2",
            &[&tenant, &repository],
        )
        .unwrap()
        .get(0);
    policy.generation = 2;
    policy.authority_epoch = 2;
    policy.version = "version.two".to_owned();
    let policy_digest = digest_json(&policy);
    transaction
        .execute(
            "UPDATE ogvcs_identity.authority_states
             SET authority_epoch = 2, key_generation = 2, updated_at = clock_timestamp()
             WHERE tenant_id = $1",
            &[&tenant],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE ogvcs_identity.credentials SET authority_epoch = 2
             WHERE tenant_id = $1 AND credential_id = 'credential.a'",
            &[&tenant],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch, policy_id,
              policy_version, path_profile, case_mode, policy_json, policy_digest)
             VALUES ($1, $2, 2, 2, $3, $4, $5, $6, $7, $8)",
            &[
                &tenant,
                &repository,
                &policy.id,
                &policy.version,
                &policy.path_profile,
                &policy.case_mode,
                &Json(&policy),
                &&policy_digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE ogvcs_identity.current_policies
             SET policy_generation = 2, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND repository_id = $2",
            &[&tenant, &repository],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn prepare_database(database_url: &str, tenant_id: TenantId, repository_id: RepositoryId) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    run_metadata_migrations(
        &mut client,
        MetadataMigrationRunOptions {
            application_version: "0.1.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();
    run_identity_migrations(
        &mut client,
        IdentityMigrationRunOptions {
            application_version: "0.2.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();
    let tenant = format!("tenant.{}", hex(tenant_id.as_bytes()));
    let repository = format!("repository.{}", hex(repository_id.as_bytes()));
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repositories (repository_id, tenant_id, project_id)
             VALUES ($1, $2, $3)",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &Uuid::from_bytes(*tenant_id.as_bytes()),
                &Uuid::from_bytes(public_uuid_bytes(0x23)),
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_commit_sequences (repository_id) VALUES ($1)",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_identity.authority_states
             (tenant_id, authority_epoch, key_generation) VALUES ($1, 1, 1)",
            &[&tenant],
        )
        .unwrap();

    let policy = PolicyDocument {
        schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
        id: "policy.metadata".to_owned(),
        version: "version.one".to_owned(),
        generation: 1,
        authority_epoch: 1,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        case_mode: "case-sensitive".to_owned(),
        default_effect: "deny".to_owned(),
        composition: "deny-overrides-v1".to_owned(),
        rules: vec![
            PolicyRule {
                id: "allow.repository".to_owned(),
                effect: "allow".to_owned(),
                subjects: RuleSubjects {
                    identities: Vec::new(),
                    groups: Vec::new(),
                    actor_classes: vec!["service".to_owned()],
                },
                tenant: tenant.clone(),
                repository: repository.clone(),
                references: Vec::new(),
                path_prefixes: Vec::new(),
                resource_types: vec!["repository".to_owned()],
                permissions: vec!["metadata.read".to_owned(), "submit".to_owned()],
            },
            PolicyRule {
                id: "allow.subject-a-path".to_owned(),
                effect: "allow".to_owned(),
                subjects: RuleSubjects {
                    identities: vec!["subject.a".to_owned()],
                    groups: Vec::new(),
                    actor_classes: Vec::new(),
                },
                tenant: tenant.clone(),
                repository: repository.clone(),
                references: Vec::new(),
                path_prefixes: Vec::new(),
                resource_types: vec!["path".to_owned()],
                permissions: vec!["submit".to_owned()],
            },
            PolicyRule {
                id: "deny.subject-b-path".to_owned(),
                effect: "deny".to_owned(),
                subjects: RuleSubjects {
                    identities: vec!["subject.b".to_owned()],
                    groups: Vec::new(),
                    actor_classes: Vec::new(),
                },
                tenant: tenant.clone(),
                repository: repository.clone(),
                references: Vec::new(),
                path_prefixes: Vec::new(),
                resource_types: vec!["path".to_owned()],
                permissions: vec!["submit".to_owned()],
            },
        ],
    };
    let policy_digest = digest_json(&policy);
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
                &&policy_digest[..],
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
    seed_credential(
        &mut client,
        &tenant,
        &repository,
        "credential.a",
        "subject.a",
        PRESENTATION_A,
        vec![
            "discover".to_owned(),
            "metadata.read".to_owned(),
            "submit".to_owned(),
        ],
    );
    seed_credential(
        &mut client,
        &tenant,
        &repository,
        "credential.b",
        "subject.b",
        PRESENTATION_B,
        vec![
            "discover".to_owned(),
            "metadata.read".to_owned(),
            "submit".to_owned(),
        ],
    );
}

fn seed_credential(
    client: &mut Client,
    tenant: &str,
    repository: &str,
    credential_id: &str,
    subject_id: &str,
    presentation: &str,
    permissions: Vec<String>,
) {
    let scope = CredentialScope {
        tenants: vec![tenant.to_owned()],
        repositories: vec![repository.to_owned()],
        references: Vec::new(),
        path_prefixes: Vec::new(),
        permissions,
    };
    let presentation_digest =
        digest_parts(&[b"OGVCS-IDENTITY-CREDENTIAL-V1\0", presentation.as_bytes()]);
    let subject_digest = digest_parts(&[b"OGVCS-IDENTITY-SUBJECT-V1\0", subject_id.as_bytes()]);
    let scope_digest = digest_json(&scope);
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation, presentation_digest, subject_id,
              subject_digest, actor_class, credential_class, groups_json, authority_epoch,
              issued_at, expires_at, state, scope_json, scope_digest)
             VALUES ($1, $2, 1, $3, $4, $5, 'service', 'service-token', '[]'::jsonb, 1,
                     clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '30 minutes', 'active', $6, $7)",
            &[
                &tenant,
                &credential_id,
                &&presentation_digest[..],
                &subject_id,
                &&subject_digest[..],
                &Json(&scope),
                &&scope_digest[..],
            ],
        )
        .unwrap();
}

fn native(
    repository_id: RepositoryId,
    allocation: &ogvcs_repository_metadata::FileIdAllocation,
    owner: &str,
) -> NativeFileIdReservation {
    NativeFileIdReservation {
        reservation: FileIdReservation {
            repository_id,
            file_id: allocation.file_id,
            origin: FileIdOrigin::Create,
            owner_kind: FileIdOwnerKind::Draft,
            owner_id: owner.to_owned(),
        },
        allocation_receipt: allocation.allocation_receipt.clone(),
    }
}

fn credentials<'a>(
    presentation: &'a str,
    request_id: &'a str,
    correlation_id: &'a str,
) -> TransactionCredentialRequest<'a> {
    TransactionCredentialRequest {
        request_id,
        correlation_id,
        credential_presentation: presentation,
        reason: Some("bounded integration proof"),
    }
}

fn idempotency(operation: &str, entropy: &str, fingerprint: [u8; 32]) -> IdempotencyReservation {
    let issued_at = SystemTime::now() - Duration::from_secs(1);
    let expires_at = issued_at + Duration::from_secs(300);
    let issued_ms = issued_at.duration_since(UNIX_EPOCH).unwrap().as_millis();
    let expires_ms = expires_at.duration_since(UNIX_EPOCH).unwrap().as_millis();
    IdempotencyReservation {
        operation: operation.to_owned(),
        key: format!("ik1.{issued_ms}.{expires_ms}.{entropy:0<22}"),
        semantic_fingerprint: fingerprint,
        issued_at,
        expires_at,
    }
}

fn public_uuid_bytes(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn digest_json<T: Serialize>(value: &T) -> [u8; 32] {
    let value = serde_json::to_value(value).unwrap();
    let bytes = serde_json::to_vec(&canonical(value)).unwrap();
    digest_parts(&[&bytes])
}

fn canonical(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical).collect()),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
