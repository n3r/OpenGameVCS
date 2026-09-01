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
    TransactionOptions, MIGRATIONS,
};
use postgres::{types::Json, Client, GenericClient, NoTls};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PRESENTATION_A: &str = "credential-presentation-a";
const PRESENTATION_A_V2: &str = "credential-presentation-a-v2";
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

    let mut reserve_replay = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.scope.replay",
                "correlation.scope.replay",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        reserve_replay
            .reserve_idempotency(capability_scope_key.clone())
            .unwrap(),
        IdempotencyReservationOutcome::CommittedReplayPending,
    );
    assert_eq!(
        reserve_replay.finish_committed_replay().unwrap(),
        json!({"capability": "reserve"})
    );

    let numeric_key = idempotency("scope.probe", "jsonb-numeric", [0x2e; 32]);
    let numeric_result =
        serde_json::from_str::<Value>(r#"{"exponent":1e3,"negativeZero":-0.0,"scaled":1.2300}"#)
            .unwrap();
    let mut numeric_commit = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.numeric.commit",
                "correlation.numeric.commit",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    numeric_commit
        .reserve_idempotency(numeric_key.clone())
        .unwrap();
    numeric_commit
        .commit_idempotency(&numeric_key, numeric_result)
        .unwrap();
    numeric_commit.commit().unwrap();
    let Json(stored_numeric): Json<Value> = Client::connect(&database_url, NoTls)
        .unwrap()
        .query_one(
            "SELECT safe_result FROM ogvcs_metadata.idempotency_records
             WHERE operation = $1 AND idempotency_key = $2",
            &[&numeric_key.operation, &numeric_key.key],
        )
        .unwrap()
        .get(0);
    let mut numeric_replay = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.numeric.replay",
                "correlation.numeric.replay",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        numeric_replay.reserve_idempotency(numeric_key).unwrap(),
        IdempotencyReservationOutcome::CommittedReplayPending
    );
    assert_eq!(
        numeric_replay.finish_committed_replay().unwrap(),
        stored_numeric,
        "safe-result digesting must use PostgreSQL's normalized jsonb value"
    );

    let mut import_scope = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.scope.import",
                "correlation.scope.import",
            ),
            tenant_id,
            TransactionCapability::ImportFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        import_scope
            .reserve_idempotency(capability_scope_key)
            .unwrap(),
        IdempotencyReservationOutcome::Reserved,
        "the same authority scope, operation, and key must not cross capabilities"
    );
    import_scope.rollback().unwrap();

    let repository_rows_before: (i64, i64, i64, i64) = Client::connect(&database_url, NoTls)
        .unwrap()
        .query_one(
            "SELECT
                 (SELECT count(*) FROM ogvcs_metadata.repositories WHERE repository_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.repository_settings WHERE repository_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.metadata_objects WHERE repository_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.repository_commit_sequences WHERE repository_id = $1)",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    for (index, capability) in [
        TransactionCapability::CreateRepository,
        TransactionCapability::Publish,
        TransactionCapability::CompareAndSwapReference,
        TransactionCapability::TombstoneFileId,
        TransactionCapability::RestoreFileId,
    ]
    .into_iter()
    .enumerate()
    {
        let result = store.begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                &format!("request.denied-capability.{index}"),
                &format!("correlation.denied-capability.{index}"),
            ),
            tenant_id,
            capability,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        );
        match result {
            Err(error) => assert_eq!(error.code, DomainErrorCode::MetadataNotFoundOrDenied),
            Ok(transaction) => {
                transaction.rollback().unwrap();
                panic!("default identity boundary admitted {capability:?}");
            }
        }
    }
    let repository_rows_after: (i64, i64, i64, i64) = Client::connect(&database_url, NoTls)
        .unwrap()
        .query_one(
            "SELECT
                 (SELECT count(*) FROM ogvcs_metadata.repositories WHERE repository_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.repository_settings WHERE repository_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.metadata_objects WHERE repository_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.repository_commit_sequences WHERE repository_id = $1)",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(
        repository_rows_after, repository_rows_before,
        "coordinator-only capabilities must not leave partial repository rows"
    );

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
            allocate.clone(),
        )
        .unwrap();
    assert_eq!(
        retry, first,
        "an exact allocation retry must not draw entropy"
    );
    exercise_tampered_allocation_replay(
        &database_url,
        &mut store,
        tenant_id,
        repository_id,
        &allocate,
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
    assert_eq!(
        path_denied
            .register_allocated_file_id(native(repository_id, &other_scope, "path-denied"))
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        path_denied
            .append_outbox(OutboxEvent {
                event_id: public_uuid_bytes(0x41),
                repository_id,
                correlation_id: public_uuid_bytes(0x42),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        path_denied.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
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
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        cross_scope.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let mut cross_subject_receipt = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A,
                "request.cross-subject-receipt",
                "correlation.cross-subject-receipt",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    cross_subject_receipt
        .reserve_idempotency(idempotency(
            "file-id.register",
            "cross-subject-receipt",
            [0x3d; 32],
        ))
        .unwrap();
    assert_eq!(
        cross_subject_receipt
            .register_allocated_file_id(native(
                repository_id,
                &other_scope,
                "cross-subject-receipt",
            ))
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict,
        "an authorized FileID fact still cannot consume another subject's receipt"
    );
    assert_eq!(
        cross_subject_receipt.commit().unwrap_err().code,
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
    assert_eq!(registered, 1, "only the atomic success may persist");
    let denied_receipt: Option<SystemTime> = client
        .query_one(
            "SELECT consumed_at FROM ogvcs_metadata.file_id_allocation_receipts
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&other_scope.file_id.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert!(
        denied_receipt.is_none(),
        "exact-resource denial must precede receipt consumption"
    );
    let denied_idempotency_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.idempotency_records
             WHERE operation = $1 AND idempotency_key = $2",
            &[&denied_key.operation, &denied_key.key],
        )
        .unwrap()
        .get(0);
    assert_eq!(denied_idempotency_rows, 0);
    let denied_outbox_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.outbox_events WHERE correlation_id = $1",
            &[&Uuid::from_bytes(public_uuid_bytes(0x42))],
        )
        .unwrap()
        .get(0);
    assert_eq!(denied_outbox_rows, 0);
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
    assert_eq!(
        store
            .allocate_file_id_identity_authorized(
                credentials(
                    PRESENTATION_A,
                    "request.allocate.stale-epoch-one",
                    "correlation.allocate.stale-epoch-one",
                ),
                tenant_id,
                repository_id,
                epoch_scope_key.clone(),
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
    );
    let post_epoch_scope = store
        .allocate_file_id_identity_authorized(
            credentials(
                PRESENTATION_A_V2,
                "request.allocate.epoch-two",
                "correlation.allocate.epoch-two",
            ),
            tenant_id,
            repository_id,
            epoch_scope_key.clone(),
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
                PRESENTATION_A_V2,
                "request.cross-epoch",
                "correlation.cross-epoch",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
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
    let mut post_epoch_register = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A_V2,
                "request.register.epoch-two",
                "correlation.register.epoch-two",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    post_epoch_register
        .reserve_idempotency(post_epoch_key.clone())
        .unwrap();
    post_epoch_register
        .register_allocated_file_id(native(repository_id, &post_epoch_scope, "epoch-two"))
        .unwrap();
    post_epoch_register
        .append_outbox(OutboxEvent {
            event_id: public_uuid_bytes(0x71),
            repository_id,
            correlation_id: public_uuid_bytes(0x72),
        })
        .unwrap();
    post_epoch_register
        .commit_idempotency(
            &post_epoch_key,
            json!({"registered": post_epoch_scope.file_id.to_string()}),
        )
        .unwrap();
    assert!(post_epoch_register.commit().unwrap().get() > 1);

    let mut exact_replay = store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A_V2,
                "request.replay.epoch-two",
                "correlation.replay.epoch-two",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        exact_replay
            .reserve_idempotency(post_epoch_key.clone())
            .unwrap(),
        IdempotencyReservationOutcome::CommittedReplayPending
    );
    assert_eq!(
        exact_replay.finish_committed_replay().unwrap(),
        json!({"registered": post_epoch_scope.file_id.to_string()})
    );
    prove_replay_rollback_failure_hides_result(
        &database_url,
        tenant_id,
        repository_id,
        &post_epoch_key,
    );

    exercise_tampered_replay_authority(
        &database_url,
        &mut store,
        tenant_id,
        repository_id,
        &post_epoch_key,
    );
    narrow_subject_a_path_same_epoch(&database_url, &tenant, &repository);
    assert_replay_denied(
        &mut store,
        tenant_id,
        repository_id,
        &post_epoch_key,
        "same-epoch-policy-narrowing",
    );
    narrow_subject_a_repository_same_epoch(&database_url, &tenant, &repository);
    assert_eq!(
        store
            .allocate_file_id_identity_authorized(
                credentials(
                    PRESENTATION_A_V2,
                    "request.allocation.policy-narrowed",
                    "correlation.allocation.policy-narrowed",
                ),
                tenant_id,
                repository_id,
                epoch_scope_key,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    let mut client = Client::connect(&database_url, NoTls).unwrap();
    let narrowing_commitments: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments
             WHERE correlation_id LIKE 'correlation.replay-denied.%'
                OR correlation_id = 'correlation.allocation.policy-narrowed'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(narrowing_commitments, 0);
    drop(client);

    prove_v7_to_v8_upgrade_and_bounds(&database_url);
}

fn exercise_tampered_allocation_replay(
    database_url: &str,
    store: &mut IdentityBoundPostgresMetadataStore,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    reservation: &IdempotencyReservation,
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT authorization_reference, authorization_resources,
                    authorization_binding_digest, safe_result
             FROM ogvcs_metadata.idempotency_records
             WHERE operation = $1 AND idempotency_key = $2",
            &[&reservation.operation, &reservation.key],
        )
        .unwrap();
    let original_reference: Option<String> = row.get(0);
    let Json(original_resources): Json<Value> = row.get(1);
    let original_digest: Vec<u8> = row.get(2);
    let Json(original_result): Json<Value> = row.get(3);
    assert!(original_reference.is_none());

    let mut malformed_resources = original_resources.clone();
    malformed_resources[0]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    for (label, reference, resources, digest, result) in [
        (
            "allocation-resources",
            None,
            Some(&malformed_resources),
            Some(original_digest.as_slice()),
            &original_result,
        ),
        (
            "allocation-reference",
            Some("refs/heads/substituted"),
            Some(&original_resources),
            Some(original_digest.as_slice()),
            &original_result,
        ),
        (
            "allocation-result",
            None,
            Some(&original_resources),
            Some(original_digest.as_slice()),
            &json!({"substituted": true}),
        ),
    ] {
        update_replay_authority(
            &mut client,
            reservation,
            reference,
            resources,
            digest,
            result,
        );
        let request_id = format!("request.{label}");
        let correlation_id = format!("correlation.{label}");
        assert_eq!(
            store
                .allocate_file_id_identity_authorized(
                    credentials(PRESENTATION_A, &request_id, &correlation_id),
                    tenant_id,
                    repository_id,
                    reservation.clone(),
                )
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );
        restore_replay_authority(
            &mut client,
            reservation,
            original_reference.as_deref(),
            &original_resources,
            &original_digest,
            &original_result,
        );
    }

    let mut tampered_digest = original_digest.clone();
    tampered_digest[0] ^= 0x01;
    update_replay_authority(
        &mut client,
        reservation,
        None,
        Some(&original_resources),
        Some(&tampered_digest),
        &original_result,
    );
    assert_eq!(
        store
            .allocate_file_id_identity_authorized(
                credentials(
                    PRESENTATION_A,
                    "request.allocation-digest",
                    "correlation.allocation-digest",
                ),
                tenant_id,
                repository_id,
                reservation.clone(),
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    restore_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        &original_resources,
        &original_digest,
        &original_result,
    );
    let escaped_commitments: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments
             WHERE correlation_id LIKE 'correlation.allocation-%'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(escaped_commitments, 0);
}

fn prove_replay_rollback_failure_hides_result(
    database_url: &str,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    reservation: &IdempotencyReservation,
) {
    let mut audit = Client::connect(database_url, NoTls).unwrap();
    let existing_pids = audit
        .query(
            "SELECT pid FROM pg_stat_activity WHERE datname = current_database()",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, i32>(0))
        .collect::<Vec<_>>();
    let participant = PostgresTransactionAuthorizationParticipant::new().unwrap();
    let mut replay_store =
        IdentityBoundPostgresMetadataStore::connect(database_url, participant).unwrap();
    let replay_pid: i32 = audit
        .query(
            "SELECT pid FROM pg_stat_activity WHERE datname = current_database()",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .find(|pid| !existing_pids.contains(pid))
        .expect("the dedicated replay connection must be observable");
    let mut replay = replay_store
        .begin_identity_authorized(
            credentials(
                PRESENTATION_A_V2,
                "request.replay.rollback-failure",
                "correlation.replay.rollback-failure",
            ),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        replay.reserve_idempotency(reservation.clone()).unwrap(),
        IdempotencyReservationOutcome::CommittedReplayPending
    );
    let terminated: bool = audit
        .query_one("SELECT pg_terminate_backend($1)", &[&replay_pid])
        .unwrap()
        .get(0);
    assert!(terminated);
    assert_eq!(
        replay.finish_committed_replay().unwrap_err().code,
        DomainErrorCode::ObjectInvalid,
        "rollback failure must not release the privately held replay result"
    );
}

fn exercise_tampered_replay_authority(
    database_url: &str,
    store: &mut IdentityBoundPostgresMetadataStore,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    reservation: &IdempotencyReservation,
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT authorization_reference, authorization_resources,
                    authorization_binding_digest, safe_result
             FROM ogvcs_metadata.idempotency_records
             WHERE operation = $1 AND idempotency_key = $2",
            &[&reservation.operation, &reservation.key],
        )
        .unwrap();
    let original_reference: Option<String> = row.get(0);
    let Json(original_resources): Json<Value> = row.get(1);
    let original_digest: Vec<u8> = row.get(2);
    let Json(original_result): Json<Value> = row.get(3);
    assert_eq!(original_digest.len(), 32);
    assert_eq!(original_resources.as_array().unwrap().len(), 2);

    let mut malformed_cases = Vec::new();
    let mut extra = original_resources.clone();
    extra.as_array_mut().unwrap()[0]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), json!(true));
    malformed_cases.push(("extra-member", extra));
    for (label, resource_type, field) in [
        ("missing-path", "path", "path"),
        ("missing-file-id", "path", "fileId"),
        ("missing-object-id", "path", "objectId"),
        ("missing-name", "repository", "name"),
    ] {
        let mut missing = original_resources.clone();
        let member = missing
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|member| member["type"] == resource_type)
            .unwrap();
        member.as_object_mut().unwrap().remove(field);
        malformed_cases.push((label, missing));
    }
    let mut unsorted = original_resources.clone();
    unsorted.as_array_mut().unwrap().reverse();
    malformed_cases.push(("unsorted", unsorted));
    let duplicate = Value::Array(vec![
        original_resources[0].clone(),
        original_resources[0].clone(),
    ]);
    malformed_cases.push(("duplicate", duplicate));
    let mut invalid_combo = original_resources.clone();
    invalid_combo
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|member| member["type"] == "path")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("name".to_owned(), json!("invalid-on-path"));
    malformed_cases.push(("invalid-field-combination", invalid_combo));

    for (label, resources) in malformed_cases {
        update_replay_authority(
            &mut client,
            reservation,
            original_reference.as_deref(),
            Some(&resources),
            Some(&original_digest),
            &original_result,
        );
        assert_replay_denied(store, tenant_id, repository_id, reservation, label);
        restore_replay_authority(
            &mut client,
            reservation,
            original_reference.as_deref(),
            &original_resources,
            &original_digest,
            &original_result,
        );
    }

    update_replay_authority(
        &mut client,
        reservation,
        Some("refs/heads/tampered"),
        Some(&original_resources),
        Some(&original_digest),
        &original_result,
    );
    assert_replay_denied(
        store,
        tenant_id,
        repository_id,
        reservation,
        "tampered-reference",
    );
    restore_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        &original_resources,
        &original_digest,
        &original_result,
    );

    let tampered_result = json!({"registered": "substituted"});
    update_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        Some(&original_resources),
        Some(&original_digest),
        &tampered_result,
    );
    assert_replay_denied(
        store,
        tenant_id,
        repository_id,
        reservation,
        "tampered-result",
    );
    restore_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        &original_resources,
        &original_digest,
        &original_result,
    );

    let mut tampered_digest = original_digest.clone();
    tampered_digest[0] ^= 0x80;
    update_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        Some(&original_resources),
        Some(&tampered_digest),
        &original_result,
    );
    assert_replay_denied(
        store,
        tenant_id,
        repository_id,
        reservation,
        "tampered-digest",
    );
    restore_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        &original_resources,
        &original_digest,
        &original_result,
    );

    update_replay_authority(&mut client, reservation, None, None, None, &original_result);
    assert_replay_denied(
        store,
        tenant_id,
        repository_id,
        reservation,
        "missing-authority",
    );
    restore_replay_authority(
        &mut client,
        reservation,
        original_reference.as_deref(),
        &original_resources,
        &original_digest,
        &original_result,
    );
}

fn update_replay_authority(
    client: &mut Client,
    reservation: &IdempotencyReservation,
    reference: Option<&str>,
    resources: Option<&Value>,
    digest: Option<&[u8]>,
    safe_result: &Value,
) {
    let resources = resources.cloned().map(Json);
    let digest = digest.map(ToOwned::to_owned);
    client
        .execute(
            "UPDATE ogvcs_metadata.idempotency_records
             SET authorization_reference = $3, authorization_resources = $4,
                 authorization_binding_digest = $5, safe_result = $6
             WHERE operation = $1 AND idempotency_key = $2",
            &[
                &reservation.operation,
                &reservation.key,
                &reference,
                &resources,
                &digest,
                &Json(safe_result),
            ],
        )
        .unwrap();
}

fn restore_replay_authority(
    client: &mut Client,
    reservation: &IdempotencyReservation,
    reference: Option<&str>,
    resources: &Value,
    digest: &[u8],
    safe_result: &Value,
) {
    update_replay_authority(
        client,
        reservation,
        reference,
        Some(resources),
        Some(digest),
        safe_result,
    );
}

fn assert_replay_denied(
    store: &mut IdentityBoundPostgresMetadataStore,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    reservation: &IdempotencyReservation,
    label: &str,
) {
    let request_id = format!("request.replay-denied.{label}");
    let correlation_id = format!("correlation.replay-denied.{label}");
    let mut replay = store
        .begin_identity_authorized(
            credentials(PRESENTATION_A_V2, &request_id, &correlation_id),
            tenant_id,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        replay
            .reserve_idempotency(reservation.clone())
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "{label} must fail closed without exposing the stored result"
    );
    assert_eq!(
        replay.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid,
        "{label} must poison the replay transaction"
    );
}

fn narrow_subject_a_path_same_epoch(database_url: &str, tenant: &str, repository: &str) {
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
    assert_eq!(policy.authority_epoch, 2);
    policy.generation = 3;
    policy.version = "version.three.path-narrowed".to_owned();
    policy.rules.push(PolicyRule {
        id: "deny.subject-a-path-after-commit".to_owned(),
        effect: "deny".to_owned(),
        subjects: RuleSubjects {
            identities: vec!["subject.a".to_owned()],
            groups: Vec::new(),
            actor_classes: Vec::new(),
        },
        tenant: tenant.to_owned(),
        repository: repository.to_owned(),
        references: Vec::new(),
        path_prefixes: Vec::new(),
        resource_types: vec!["path".to_owned()],
        permissions: vec!["submit".to_owned()],
    });
    let policy_digest = digest_json(&policy);
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch, policy_id,
              policy_version, path_profile, case_mode, policy_json, policy_digest)
             VALUES ($1, $2, 3, 2, $3, $4, $5, $6, $7, $8)",
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
             SET policy_generation = 3, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND repository_id = $2",
            &[&tenant, &repository],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn narrow_subject_a_repository_same_epoch(database_url: &str, tenant: &str, repository: &str) {
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
    assert_eq!(policy.authority_epoch, 2);
    policy.generation = 4;
    policy.version = "version.four.repository-narrowed".to_owned();
    policy.rules.push(PolicyRule {
        id: "deny.subject-a-repository-after-allocation".to_owned(),
        effect: "deny".to_owned(),
        subjects: RuleSubjects {
            identities: vec!["subject.a".to_owned()],
            groups: Vec::new(),
            actor_classes: Vec::new(),
        },
        tenant: tenant.to_owned(),
        repository: repository.to_owned(),
        references: Vec::new(),
        path_prefixes: Vec::new(),
        resource_types: vec!["repository".to_owned()],
        permissions: vec!["submit".to_owned()],
    });
    let policy_digest = digest_json(&policy);
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch, policy_id,
              policy_version, path_profile, case_mode, policy_json, policy_digest)
             VALUES ($1, $2, 4, 2, $3, $4, $5, $6, $7, $8)",
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
             SET policy_generation = 4, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND repository_id = $2",
            &[&tenant, &repository],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn prove_v7_to_v8_upgrade_and_bounds(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .batch_execute("DROP SCHEMA ogvcs_metadata CASCADE")
        .unwrap();
    for migration in MIGRATIONS.iter().take(21) {
        let body = migration
            .sql
            .strip_prefix("BEGIN;\n")
            .and_then(|sql| sql.strip_suffix("COMMIT;\n"))
            .unwrap();
        let mut transaction = client.transaction().unwrap();
        transaction.batch_execute(body).unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.schema_migrations
                 (version, phase, checksum_sha256, state, minimum_application_version,
                  maximum_application_version, started_at, completed_at)
                 VALUES ($1, $2, $3, 'completed', $4, $5,
                         clock_timestamp(), clock_timestamp())",
                &[
                    &(migration.version as i64),
                    &migration.phase.as_str(),
                    &migration.checksum_sha256,
                    &migration.minimum_application_version,
                    &migration.maximum_application_version,
                ],
            )
            .unwrap();
        transaction.commit().unwrap();
    }
    let scope = vec![0x91_u8; 32];
    let fingerprint = vec![0x92_u8; 32];
    client
        .execute(
            "INSERT INTO ogvcs_metadata.idempotency_records
             (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
              state, safe_result, issued_at, expires_at, committed_at)
             VALUES ($1, 'upgrade.fixture', 'legacy-large', $2, 'committed',
                     to_jsonb(array_fill(0, ARRAY[400000])),
                     clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '10 minutes', clock_timestamp())",
            &[&scope, &fingerprint],
        )
        .unwrap();
    let legacy_sizes: (i64, i64, i64) = client
        .query_one(
            "SELECT jsonb_array_length(safe_result)::bigint,
                    pg_column_size(safe_result)::bigint,
                    octet_length(safe_result::text)::bigint
             FROM ogvcs_metadata.idempotency_records
             WHERE operation = 'upgrade.fixture' AND idempotency_key = 'legacy-large'",
            &[],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(legacy_sizes.0, 400_000);
    let compact_v7_bytes = legacy_sizes.0.checked_mul(2).unwrap() + 1;
    assert!(compact_v7_bytes <= 1_048_576);
    assert!(legacy_sizes.1 > 1_048_576 || legacy_sizes.2 > 1_048_576);

    let report = run_metadata_migrations(
        &mut client,
        MetadataMigrationRunOptions {
            application_version: "0.1.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();
    assert_eq!(report.already_applied, 21);
    assert_eq!(report.applied, 12);
    let upgraded: (bool, bool, i64) = client
        .query_one(
            "SELECT authorization_resources IS NULL,
                    authorization_binding_digest IS NULL,
                    jsonb_array_length(safe_result)::bigint
             FROM ogvcs_metadata.idempotency_records
             WHERE operation = 'upgrade.fixture' AND idempotency_key = 'legacy-large'",
            &[],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(upgraded, (true, true, 400_000));

    let bounded_resource = json!([{
        "type": "repository",
        "path": null,
        "fileId": null,
        "objectId": null,
        "name": "file-id.register"
    }]);
    let oversized_identity_update = client.execute(
        "UPDATE ogvcs_metadata.idempotency_records
         SET authorization_resources = $1, authorization_binding_digest = $2
         WHERE operation = 'upgrade.fixture' AND idempotency_key = 'legacy-large'",
        &[&Json(&bounded_resource), &vec![0x93_u8; 32]],
    );
    assert!(oversized_identity_update.is_err());

    let exact_safe = client.execute(
        "INSERT INTO ogvcs_metadata.idempotency_records
         (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
          state, safe_result, issued_at, expires_at, committed_at,
          authorization_resources, authorization_binding_digest)
         VALUES ($1, 'bound.fixture', 'safe-max', $2, 'committed',
                 to_jsonb(repeat('x', 1048564)), clock_timestamp() - interval '1 minute',
                 clock_timestamp() + interval '10 minutes', clock_timestamp(), $3, $4)",
        &[
            &vec![0x94_u8; 32],
            &vec![0x95_u8; 32],
            &Json(&bounded_resource),
            &vec![0x96_u8; 32],
        ],
    );
    assert_eq!(exact_safe.unwrap(), 1);
    let exact_safe_expression_size: i64 = client
        .query_one(
            "SELECT pg_column_size(to_jsonb(repeat('x', 1048564)))::bigint",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(exact_safe_expression_size, 1_048_576);
    let over_safe = client.execute(
        "INSERT INTO ogvcs_metadata.idempotency_records
         (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
          state, safe_result, issued_at, expires_at, committed_at,
          authorization_resources, authorization_binding_digest)
         VALUES ($1, 'bound.fixture', 'safe-over', $2, 'committed',
                 to_jsonb(repeat('x', 1048565)), clock_timestamp() - interval '1 minute',
                 clock_timestamp() + interval '10 minutes', clock_timestamp(), $3, $4)",
        &[
            &vec![0x97_u8; 32],
            &vec![0x98_u8; 32],
            &Json(&bounded_resource),
            &vec![0x99_u8; 32],
        ],
    );
    assert!(over_safe.is_err());

    let exact_resources = client.execute(
        "WITH empty_resource AS (
           SELECT jsonb_build_array(jsonb_build_object(
             'type', 'repository', 'path', NULL, 'fileId', NULL,
             'objectId', NULL, 'name', '')) AS resources
         ), exact_resource AS (
           SELECT jsonb_build_array(jsonb_build_object(
             'type', 'repository', 'path', NULL, 'fileId', NULL, 'objectId', NULL,
             'name', repeat('x', 8388608 - pg_column_size(resources)))) AS resources
           FROM empty_resource
         )
         INSERT INTO ogvcs_metadata.idempotency_records
         (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
          state, safe_result, issued_at, expires_at, committed_at,
          authorization_resources, authorization_binding_digest)
         SELECT $1, 'bound.fixture', 'resources-max', $2, 'committed', '{}'::jsonb,
                clock_timestamp() - interval '1 minute',
                clock_timestamp() + interval '10 minutes', clock_timestamp(), resources, $3
         FROM exact_resource",
        &[&vec![0xa1_u8; 32], &vec![0xa2_u8; 32], &vec![0xa3_u8; 32]],
    );
    assert_eq!(exact_resources.unwrap(), 1);
    let exact_resource_size: (i64, i64, i64) = client
        .query_one(
            "SELECT length(authorization_resources->0->>'name')::bigint,
                    octet_length(authorization_resources::text)::bigint,
                    pg_column_size(jsonb_build_array(jsonb_build_object(
                      'type', 'repository', 'path', NULL, 'fileId', NULL,
                      'objectId', NULL,
                      'name', authorization_resources->0->>'name')))::bigint
             FROM ogvcs_metadata.idempotency_records
             WHERE operation = 'bound.fixture' AND idempotency_key = 'resources-max'",
            &[],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(exact_resource_size, (8_388_516, 8_388_600, 8_388_608));
    let over_resources = client.execute(
        "UPDATE ogvcs_metadata.idempotency_records
         SET authorization_resources = jsonb_set(
           authorization_resources, '{0,name}',
           to_jsonb((authorization_resources->0->>'name') || 'x'))
         WHERE operation = 'bound.fixture' AND idempotency_key = 'resources-max'",
        &[],
    );
    assert!(over_resources.is_err());
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
    seed_credential(
        &mut transaction,
        tenant,
        repository,
        CredentialFixture {
            credential_id: "credential.a",
            credential_generation: 2,
            subject_id: "subject.a",
            presentation: PRESENTATION_A_V2,
            authority_epoch: 2,
            permissions: vec![
                "discover".to_owned(),
                "metadata.read".to_owned(),
                "submit".to_owned(),
            ],
        },
    );
    transaction.commit().unwrap();
}

fn prepare_database(database_url: &str, tenant_id: TenantId, repository_id: RepositoryId) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
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
        CredentialFixture {
            credential_id: "credential.a",
            credential_generation: 1,
            subject_id: "subject.a",
            presentation: PRESENTATION_A,
            authority_epoch: 1,
            permissions: vec![
                "discover".to_owned(),
                "metadata.read".to_owned(),
                "submit".to_owned(),
            ],
        },
    );
    seed_credential(
        &mut client,
        &tenant,
        &repository,
        CredentialFixture {
            credential_id: "credential.b",
            credential_generation: 1,
            subject_id: "subject.b",
            presentation: PRESENTATION_B,
            authority_epoch: 1,
            permissions: vec![
                "discover".to_owned(),
                "metadata.read".to_owned(),
                "submit".to_owned(),
            ],
        },
    );
}

struct CredentialFixture<'a> {
    credential_id: &'a str,
    credential_generation: i64,
    subject_id: &'a str,
    presentation: &'a str,
    authority_epoch: i64,
    permissions: Vec<String>,
}

fn seed_credential(
    client: &mut impl GenericClient,
    tenant: &str,
    repository: &str,
    fixture: CredentialFixture<'_>,
) {
    let scope = CredentialScope {
        tenants: vec![tenant.to_owned()],
        repositories: vec![repository.to_owned()],
        references: Vec::new(),
        path_prefixes: Vec::new(),
        permissions: fixture.permissions,
    };
    let presentation_digest = digest_parts(&[
        b"OGVCS-IDENTITY-CREDENTIAL-V1\0",
        fixture.presentation.as_bytes(),
    ]);
    let subject_digest = digest_parts(&[
        b"OGVCS-IDENTITY-SUBJECT-V1\0",
        fixture.subject_id.as_bytes(),
    ]);
    let scope_digest = digest_json(&scope);
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation, presentation_digest, subject_id,
              subject_digest, actor_class, credential_class, groups_json, authority_epoch,
              issued_at, expires_at, state, scope_json, scope_digest)
             VALUES ($1, $2, $3, $4, $5, $6, 'service', 'service-token', '[]'::jsonb, $7,
                     clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '30 minutes', 'active', $8, $9)",
            &[
                &tenant,
                &fixture.credential_id,
                &fixture.credential_generation,
                &&presentation_digest[..],
                &fixture.subject_id,
                &&subject_digest[..],
                &fixture.authority_epoch,
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
