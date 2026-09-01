use std::{
    collections::BTreeMap,
    sync::{Arc, Barrier, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};

use ogvcs_identity_policy_audit_postgres::{
    run_migrations as run_identity_migrations, AggregateAuthorizationReceipt, AggregatePlanRequest,
    AggregateSigningKeyRegistration, AuthorizationResource as IdentityAuthorizationResource,
    CredentialScope, HmacSha256KeyRing, MigrationRunOptions as IdentityMigrationRunOptions,
    ParticipantErrorCode, PolicyDocument, PolicyRule, PostgresAggregateAuthorizationParticipant,
    PostgresTransactionAuthorizationParticipant, RepositoryContractBindingRequest, RuleSubjects,
    AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY, AGGREGATE_SUBMIT_PERMISSION,
    MAXIMUM_AGGREGATE_RESOURCES,
};
use ogvcs_object_model::{encode_canonical, Cbor, ObjectKind, ObjectRef};
use ogvcs_repository_metadata::{
    aggregate_plan_digest, run_migrations as run_metadata_migrations, AggregateChunkCommitment,
    AggregateLifecycleApplyRequest, AggregatePlanChunk, AggregatePublicationPlan,
    AtomicSubmitFaultForTest, DomainErrorCode, IdempotencyReservation,
    IdentityBoundPostgresMetadataStore, LifecycleHealth, LifecycleObjectBinding, LifecycleState,
    MigrationRunOptions as MetadataMigrationRunOptions, PostgresMetadataStore,
    PreallocatedCreationSubmitFinalizeRequest, PreallocatedCreationSubmitIntentRequest,
    PreallocatedCreationSubmitPreflightRequest, PreallocatedCreationSubmitReconciliation,
    RepositoryId, TenantId, AUTHORIZATION_MANIFEST_SHA256, LIFECYCLE_CONTRACT_SHA256,
};
use postgres::{types::Json, Client, NoTls};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PRESENTATION: &str = "bridge.aggregate.credential.presentation";
const KEY_REFERENCE: &str = "kms://identity/bridge/aggregate-key-1";
const CREDENTIAL_DOMAIN: &[u8] = b"OGVCS-IDENTITY-CREDENTIAL-V1\0";
const SUBJECT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-SUBJECT-V1\0";
const REFERENCE: &str = "main";
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn private_preallocated_creation_submit_is_atomic_replayable_and_reconcilable() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_000,
        3,
        public_uuid(0x91),
        "atomic-submit",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x92),
        "atomic-submit-plan",
        None,
    );
    assert_zero_operation_intent_rejected(&database_url, &fixture, lifecycle_plan);
    let mut store = production_store(&database_url, provider);
    let intent = store
        .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            expected_head: fixture.old_head,
            expected_generation: 1,
        })
        .unwrap();
    assert_eq!(intent.operation_count(), 1);
    assert_eq!(
        intent.candidate_change_set_digest(),
        &fixture.candidate_change_set.digest
    );
    let preflight = store
        .preflight_preallocated_creation_submit(PreallocatedCreationSubmitPreflightRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
        })
        .unwrap();
    assert!(preflight.branch_matches());

    let unknown = store
        .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.one",
        })
        .unwrap();
    assert!(matches!(
        unknown,
        PreallocatedCreationSubmitReconciliation::UnknownRecovering { .. }
    ));
    assert!(!store
        .caught_bridge_error_commits_for_test(AggregateLifecycleApplyRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            consumption_id: "invalid/slash",
        })
        .unwrap());

    for fault in [
        AtomicSubmitFaultForTest::BeforeBridge,
        AtomicSubmitFaultForTest::AfterBridge,
        AtomicSubmitFaultForTest::AfterFileIdConsumption,
        AtomicSubmitFaultForTest::AfterSnapshotMarker,
        AtomicSubmitFaultForTest::AfterBranchCas,
        AtomicSubmitFaultForTest::AfterAudit,
        AtomicSubmitFaultForTest::AfterOutbox,
        AtomicSubmitFaultForTest::AfterOutcome,
    ] {
        let error = store
            .finalize_preallocated_creation_submit_with_fault_for_test(
                PreallocatedCreationSubmitFinalizeRequest {
                    intent_id: *intent.intent_id(),
                    authorization: &bundle.receipt,
                    consumption_id: "atomic.consume.one",
                },
                fault,
            )
            .unwrap_err();
        assert_eq!(error.code, DomainErrorCode::MetadataNotFoundOrDenied);
        assert_atomic_submit_not_visible(&database_url, &fixture, &bundle, lifecycle_plan);
    }

    assert_eq!(
        store
            .finalize_preallocated_creation_submit_with_lost_response_for_test(
                PreallocatedCreationSubmitFinalizeRequest {
                    intent_id: *intent.intent_id(),
                    authorization: &bundle.receipt,
                    consumption_id: "atomic.consume.one",
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::TransactionRetryExhausted
    );
    let replay = store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.one",
        })
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.new_head(), fixture.publication);
    assert_eq!(replay.branch_generation(), 2);
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        1
    );
    assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 1);

    assert_eq!(
        store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.different",
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    revoke_credential(&database_url, &fixture);
    for error in [
        store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.one",
            })
            .unwrap_err(),
        store
            .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.one",
            })
            .unwrap_err(),
    ] {
        assert_eq!(error.code, DomainErrorCode::MetadataNotFoundOrDenied);
    }
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        1
    );
    assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 1);
    assert_atomic_submit_visible(&database_url, &fixture, replay.outbox_event_id(), 1);
}

#[test]
fn private_submit_accepts_exactly_1000_operations_and_rejects_1001_before_sealing() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };

    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    seed_additional_atomic_candidate_operations(&database_url, &fixture, 1_000);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_300,
        2,
        public_uuid(0x97),
        "atomic-exact-1000",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x98),
        "atomic-exact-1000-plan",
        None,
    );
    let mut store = production_store(&database_url, provider);
    let started = Instant::now();
    let intent = store
        .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            expected_head: fixture.old_head,
            expected_generation: 1,
        })
        .unwrap();
    assert_eq!(intent.operation_count(), 1_000);
    let outcome = store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.exact-1000",
        })
        .unwrap();
    let mut client = Client::connect(&database_url, NoTls).unwrap();
    let counts = client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations
                  WHERE intent_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.submit_file_id_consumptions
                  WHERE intent_id = $1),
                 (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations
                  WHERE intent_id = $1 AND operation_kind = 'create'),
                 (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations
                  WHERE intent_id = $1 AND operation_kind = 'copy'),
                 (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations
                  WHERE intent_id = $1 AND operation_kind = 'import')",
            &[&Uuid::from_bytes(*intent.intent_id())],
        )
        .unwrap();
    assert_eq!(counts.get::<_, i64>(0), 1_000);
    assert_eq!(counts.get::<_, i64>(1), 1_000);
    assert_eq!(counts.get::<_, i64>(2), 334);
    assert_eq!(counts.get::<_, i64>(3), 333);
    assert_eq!(counts.get::<_, i64>(4), 333);
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        1
    );
    assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 1);
    eprintln!(
        "private atomic submit exact 1000: elapsed_ms={} operation_rows=1000 consumption_rows=1000 create=334 copy=333 import=333",
        started.elapsed().as_millis()
    );
    assert_atomic_submit_visible(&database_url, &fixture, outcome.outbox_event_id(), 1_000);

    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    seed_additional_atomic_candidate_operations(&database_url, &fixture, 1_001);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_400,
        2,
        public_uuid(0x99),
        "atomic-overflow-1001",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x9a),
        "atomic-overflow-1001-plan",
        None,
    );
    let mut store = production_store(&database_url, provider);
    assert_eq!(
        store
            .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
                authorization: &bundle.receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head: fixture.old_head,
                expected_generation: 1,
            },)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    let persisted = Client::connect(&database_url, NoTls)
        .unwrap()
        .query_one(
            "SELECT
                 (SELECT count(*) FROM ogvcs_metadata.submit_intents),
                 (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations),
                 (SELECT count(*) FROM ogvcs_identity.aggregate_plan_consumptions),
                 (SELECT count(*) FROM ogvcs_metadata.lifecycle_applications)",
            &[],
        )
        .unwrap();
    assert_eq!(persisted.get::<_, i64>(0), 0);
    assert_eq!(persisted.get::<_, i64>(1), 0);
    assert_eq!(persisted.get::<_, i64>(2), 0);
    assert_eq!(persisted.get::<_, i64>(3), 0);
}

#[test]
fn private_submit_rejects_import_without_a_server_mapping_before_sealing() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    seed_additional_atomic_candidate_operations(&database_url, &fixture, 3);
    let mut client = Client::connect(&database_url, NoTls).unwrap();
    assert_eq!(
        client
            .execute(
                "DELETE FROM ogvcs_metadata.file_id_import_mappings
                 WHERE repository_id = $1",
                &[&Uuid::from_bytes(*fixture.repository_id.as_bytes())],
            )
            .unwrap(),
        1
    );
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_500,
        2,
        public_uuid(0x9b),
        "atomic-import-mapping-missing",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x9c),
        "atomic-import-mapping-missing-plan",
        None,
    );
    let mut store = production_store(&database_url, provider);
    assert_eq!(
        store
            .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
                authorization: &bundle.receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head: fixture.old_head,
                expected_generation: 1,
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    let persisted = client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM ogvcs_metadata.submit_intents),
                 (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations),
                 (SELECT count(*) FROM ogvcs_identity.aggregate_plan_consumptions),
                 (SELECT count(*) FROM ogvcs_metadata.lifecycle_applications)",
            &[],
        )
        .unwrap();
    for index in 0..4 {
        assert_eq!(persisted.get::<_, i64>(index), 0);
    }
}

#[test]
fn concurrent_private_submit_has_one_consumption_and_one_branch_advance() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_100,
        2,
        public_uuid(0x93),
        "atomic-concurrent",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x94),
        "atomic-concurrent-plan",
        None,
    );
    let mut creator = production_store(&database_url, provider.clone());
    let intent = creator
        .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            expected_head: fixture.old_head,
            expected_generation: 1,
        })
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for receipt in [bundle.receipt.clone(), bundle.receipt.clone()] {
        let database_url = database_url.clone();
        let provider = provider.clone();
        let barrier = barrier.clone();
        let intent_id = *intent.intent_id();
        workers.push(thread::spawn(move || {
            let mut store = production_store(&database_url, provider);
            barrier.wait();
            store.finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id,
                authorization: &receipt,
                consumption_id: "atomic.consume.concurrent",
            })
        }));
    }
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert!(results.iter().any(Result::is_ok));
    assert!(results.iter().all(|result| {
        result.is_ok()
            || result.as_ref().unwrap_err().code == DomainErrorCode::TransactionRetryExhausted
            || result.as_ref().unwrap_err().code == DomainErrorCode::MetadataNotFoundOrDenied
    }));
    let mut replay_store = production_store(&database_url, provider);
    let replay = replay_store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.concurrent",
        })
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        1
    );
    assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 1);
    assert_atomic_submit_visible(&database_url, &fixture, replay.outbox_event_id(), 1);
}

#[test]
fn private_submit_rechecks_revocation_after_preflight_without_partial_visibility() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_200,
        2,
        public_uuid(0x95),
        "atomic-revoked",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x96),
        "atomic-revoked-plan",
        None,
    );
    let mut store = production_store(&database_url, provider);
    let intent = store
        .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            expected_head: fixture.old_head,
            expected_generation: 1,
        })
        .unwrap();
    revoke_credential(&database_url, &fixture);
    assert_eq!(
        store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.revoked",
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_atomic_submit_not_visible(&database_url, &fixture, &bundle, lifecycle_plan);
}

#[test]
fn aggregate_receipt_and_lifecycle_apply_are_one_serializable_transaction() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);

    let first = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        0,
        3,
        public_uuid(0x31),
        "bridge-first",
        300,
    );
    let wrong_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &first,
        public_uuid(0x32),
        "bridge-wrong-projection",
        Some(1),
    );
    let correct_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &first,
        public_uuid(0x33),
        "bridge-correct",
        None,
    );
    let mut store = production_store(&database_url, provider.clone());
    let denied = store
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &first.receipt,
            lifecycle_plan_id: wrong_plan,
            consumption_id: "bridge.consume.first",
        })
        .unwrap_err();
    assert_eq!(denied.code, DomainErrorCode::MetadataNotFoundOrDenied);
    assert_eq!(
        identity_consumptions(&database_url, first.receipt.plan_id()),
        0
    );

    for invalid_consumption_id in [
        String::new(),
        "invalid/slash".to_owned(),
        "non-ascii-é".to_owned(),
        "a".repeat(257),
    ] {
        let denied = store
            .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
                authorization: &first.receipt,
                lifecycle_plan_id: correct_plan,
                consumption_id: &invalid_consumption_id,
            })
            .unwrap_err();
        assert_eq!(denied.code, DomainErrorCode::MetadataNotFoundOrDenied);
        assert_eq!(
            identity_consumptions(&database_url, first.receipt.plan_id()),
            0
        );
        assert_eq!(lifecycle_applications(&database_url, correct_plan), 0);
    }

    let wrong_context = store
        .apply_aggregate_lifecycle_publication_with_wrong_context_for_test(
            AggregateLifecycleApplyRequest {
                authorization: &first.receipt,
                lifecycle_plan_id: correct_plan,
                consumption_id: "bridge.consume.first",
            },
        )
        .unwrap_err();
    assert_eq!(
        wrong_context.code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        identity_consumptions(&database_url, first.receipt.plan_id()),
        0
    );
    assert_eq!(lifecycle_applications(&database_url, correct_plan), 0);

    let applied = store
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &first.receipt,
            lifecycle_plan_id: correct_plan,
            consumption_id: "bridge.consume.first",
        })
        .unwrap();
    assert_eq!(applied.lifecycle().object_count, 3);
    assert_eq!(applied.identity_plan_id(), first.receipt.plan_id());
    assert_eq!(applied.operation_digest().len(), 32);
    assert_eq!(applied.projection_page_count(), 1);
    assert_eq!(applied.protected_result_page_count(), 1);
    assert_eq!(applied.application_write_batch_count(), 1);
    assert_eq!(applied.maximum_materialized_item_count(), 3);
    assert_application_counts(&database_url, applied.lifecycle().application_id, 3);
    assert_late_child_appends_rejected(&database_url, applied.lifecycle().application_id);
    let replay = store
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &first.receipt,
            lifecycle_plan_id: correct_plan,
            consumption_id: "bridge.consume.replay",
        })
        .unwrap_err();
    assert_eq!(replay.code, DomainErrorCode::MetadataNotFoundOrDenied);

    let rollback = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        100,
        2,
        public_uuid(0x41),
        "bridge-rollback",
        300,
    );
    let rollback_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &rollback,
        public_uuid(0x42),
        "bridge-rollback-plan",
        None,
    );
    let failed = store
        .apply_aggregate_lifecycle_publication_with_post_consume_failure_for_test(
            AggregateLifecycleApplyRequest {
                authorization: &rollback.receipt,
                lifecycle_plan_id: rollback_plan,
                consumption_id: "bridge.consume.rollback",
            },
        )
        .unwrap_err();
    assert_eq!(failed.code, DomainErrorCode::MetadataNotFoundOrDenied);
    assert_eq!(
        identity_consumptions(&database_url, rollback.receipt.plan_id()),
        0
    );
    assert_eq!(lifecycle_applications(&database_url, rollback_plan), 0);
    store
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &rollback.receipt,
            lifecycle_plan_id: rollback_plan,
            consumption_id: "bridge.consume.rollback",
        })
        .unwrap();

    let concurrent = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        200,
        2,
        public_uuid(0x51),
        "bridge-concurrent",
        300,
    );
    let concurrent_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &concurrent,
        public_uuid(0x52),
        "bridge-concurrent-plan",
        None,
    );
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for index in 0..2 {
        let database_url = database_url.clone();
        let receipt = concurrent.receipt.clone();
        let provider = provider.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let mut store = production_store(&database_url, provider);
            barrier.wait();
            store
                .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
                    authorization: &receipt,
                    lifecycle_plan_id: concurrent_plan,
                    consumption_id: &format!("bridge.consume.concurrent.{index}"),
                })
                .is_ok()
        }));
    }
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|allowed| *allowed)
            .count(),
        1
    );
    assert_eq!(
        identity_consumptions(&database_url, concurrent.receipt.plan_id()),
        1
    );

    let wrong_key = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        300,
        1,
        public_uuid(0x61),
        "bridge-wrong-key",
        300,
    );
    let wrong_key_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &wrong_key,
        public_uuid(0x62),
        "bridge-wrong-key-plan",
        None,
    );
    let mut wrong_store = production_store(&database_url, key_provider([0x6b; 32]));
    assert_eq!(
        wrong_store
            .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
                authorization: &wrong_key.receipt,
                lifecycle_plan_id: wrong_key_plan,
                consumption_id: "bridge.consume.wrong-key",
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        identity_consumptions(&database_url, wrong_key.receipt.plan_id()),
        0
    );
}

#[test]
fn aggregate_bridge_rejects_expired_revoked_and_stale_current_authority() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    for scenario in [
        "expired",
        "revoked",
        "epoch-stale",
        "policy-stale",
        "authority-contract-stale",
    ] {
        reset_database(&database_url);
        let fixture = seed(&database_url);
        let provider = key_provider([0x5a; 32]);
        let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
        prepare_identity_authority(&database_url, &fixture, &participant);
        let ttl = if scenario == "expired" { 3 } else { 300 };
        let bundle = prepare_bundle(
            &database_url,
            &fixture,
            &participant,
            400,
            2,
            public_uuid(0x71),
            scenario,
            ttl,
        );
        let lifecycle_plan = if scenario == "authority-contract-stale" {
            persist_lifecycle_plan_with_authority(
                &database_url,
                &fixture,
                &bundle,
                public_uuid(0x72),
                &format!("bridge-{scenario}"),
                None,
                [0xa3; 32],
            )
        } else {
            persist_lifecycle_plan(
                &database_url,
                &fixture,
                &bundle,
                public_uuid(0x72),
                &format!("bridge-{scenario}"),
                None,
            )
        };
        let mut client = Client::connect(&database_url, NoTls).unwrap();
        match scenario {
            "expired" => thread::sleep(Duration::from_secs(4)),
            "revoked" => {
                client
                    .execute(
                        "UPDATE ogvcs_identity.credentials
                         SET state='revoked', revoked_at=clock_timestamp()
                         WHERE tenant_id=$1 AND credential_id='bridge-credential'
                           AND credential_generation=1",
                        &[&fixture.tenant],
                    )
                    .unwrap();
            }
            "epoch-stale" => {
                client
                    .execute(
                        "UPDATE ogvcs_identity.authority_states
                         SET authority_epoch=2, key_generation=2,
                             updated_at=clock_timestamp()
                         WHERE tenant_id=$1",
                        &[&fixture.tenant],
                    )
                    .unwrap();
            }
            "policy-stale" => {
                let next = policy_at(&fixture.tenant, &fixture.repository, 2);
                let mut transaction = client.transaction().unwrap();
                transaction
                    .execute(
                        "INSERT INTO ogvcs_identity.policy_versions
                         (tenant_id, repository_id, policy_generation, authority_epoch,
                          policy_id, policy_version, path_profile, case_mode,
                          policy_json, policy_digest)
                         VALUES ($1, $2, 2, 1, $3, $4, $5, $6, $7, $8)",
                        &[
                            &fixture.tenant,
                            &fixture.repository,
                            &next.id,
                            &next.version,
                            &next.path_profile,
                            &next.case_mode,
                            &Json(&next),
                            &digest_json(&next),
                        ],
                    )
                    .unwrap();
                transaction
                    .execute(
                        "UPDATE ogvcs_identity.current_policies
                         SET policy_generation=2, updated_at=clock_timestamp()
                         WHERE tenant_id=$1 AND repository_id=$2",
                        &[&fixture.tenant, &fixture.repository],
                    )
                    .unwrap();
                transaction.commit().unwrap();
            }
            "authority-contract-stale" => {}
            _ => unreachable!(),
        }
        drop(client);
        let mut store = production_store(&database_url, provider);
        assert_eq!(
            store
                .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
                    authorization: &bundle.receipt,
                    lifecycle_plan_id: lifecycle_plan,
                    consumption_id: &format!("bridge.consume.{scenario}"),
                })
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied,
            "scenario {scenario} must not disclose a partial decision"
        );
        assert_eq!(
            identity_consumptions(&database_url, bundle.receipt.plan_id()),
            0
        );
        assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 0);
    }
}

#[test]
fn denied_resource_position_has_one_indistinguishable_complete_set_result() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    let participant = PostgresAggregateAuthorizationParticipant::new(key_provider([0x5a; 32]));
    prepare_identity_authority(&database_url, &fixture, &participant);
    let cases = [
        [
            "Game/A-Denied.asset",
            "Game/B-Safe.asset",
            "Game/C-Safe.asset",
        ],
        [
            "Game/A-Safe.asset",
            "Game/M-Denied.asset",
            "Game/Z-Safe.asset",
        ],
        [
            "Game/A-Safe.asset",
            "Game/B-Safe.asset",
            "Game/Z-Denied.asset",
        ],
    ];
    let snapshot = fixture.publication.to_string();
    let mut errors = Vec::new();
    let mut client = Client::connect(&database_url, NoTls).unwrap();
    for paths in cases {
        let handle = {
            let mut transaction = client.transaction().unwrap();
            let handle = participant
                .begin_plan(
                    &mut transaction,
                    &AggregatePlanRequest {
                        credential_presentation: PRESENTATION,
                        tenant: &fixture.tenant,
                        repository: &fixture.repository,
                        permission: AGGREGATE_SUBMIT_PERMISSION,
                        capability: AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY,
                        reference: Some(REFERENCE),
                        snapshot: Some(&snapshot),
                        reason: Some("deny-overrides complete set test"),
                        ttl_seconds: 300,
                    },
                )
                .unwrap();
            transaction.commit().unwrap();
            handle
        };
        let resources = paths.map(path_resource);
        let mut transaction = client.transaction().unwrap();
        participant
            .append_chunk(&mut transaction, &handle, &resources)
            .unwrap();
        transaction.commit().unwrap();
        let mut transaction = client.transaction().unwrap();
        let error = participant
            .authorize_plan(&mut transaction, &handle)
            .unwrap_err();
        errors.push(error.code());
        transaction.rollback().unwrap();
    }
    assert_eq!(errors, vec![ParticipantErrorCode::AuthenticationDenied; 3]);
    let decisions: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.aggregate_decision_commitments",
            &[],
        )
        .unwrap()
        .get(0);
    let applications: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.lifecycle_applications",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!((decisions, applications), (0, 0));
}

#[test]
fn exact_100000_bridge_is_streamed_in_measured_bounded_pages() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_EXACT_DATABASE_URL") else {
        return;
    };
    let total_started = Instant::now();
    reset_database(&database_url);
    let fixture = seed(&database_url);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);

    let identity_started = Instant::now();
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        0,
        MAXIMUM_AGGREGATE_RESOURCES as u32,
        public_uuid(0x81),
        "bridge-exact-100000",
        900,
    );
    let identity_elapsed = identity_started.elapsed();

    let lifecycle_plan_started = Instant::now();
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x82),
        "bridge-exact-100000-plan",
        None,
    );
    let lifecycle_plan_elapsed = lifecycle_plan_started.elapsed();

    let apply_started = Instant::now();
    let mut store = production_store(&database_url, provider);
    let applied = store
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            consumption_id: "bridge.consume.exact-100000",
        })
        .unwrap();
    let apply_elapsed = apply_started.elapsed();

    assert_eq!(applied.lifecycle().object_count, 100_000);
    assert_eq!(applied.projection_page_count(), 100);
    assert_eq!(applied.protected_result_page_count(), 100);
    assert_eq!(applied.application_write_batch_count(), 100);
    assert_eq!(applied.maximum_materialized_item_count(), 1_000);
    assert_application_counts(&database_url, applied.lifecycle().application_id, 100_000);
    eprintln!(
        "aggregate-bridge-exact-scale identity={identity_elapsed:?} lifecycle_plan={lifecycle_plan_elapsed:?} apply={apply_elapsed:?} total={:?} projection_pages={} protected_pages={} write_batches={} maximum_materialized_items={}",
        total_started.elapsed(),
        applied.projection_page_count(),
        applied.protected_result_page_count(),
        applied.application_write_batch_count(),
        applied.maximum_materialized_item_count(),
    );
}

#[derive(Clone)]
struct Fixture {
    tenant_id: TenantId,
    repository_id: RepositoryId,
    tenant: String,
    repository: String,
    publication: ObjectRef,
    old_head: ObjectRef,
    candidate_change_set: ObjectRef,
    candidate_file_id: [u8; 16],
}

struct PreparedBundle {
    receipt: AggregateAuthorizationReceipt,
    first_resource: u32,
    resource_count: u32,
    ttl_seconds: u64,
}

fn reset_database(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert!(database.starts_with("ogvcs_metadata_test_"));
    client
        .batch_execute(
            "DROP SCHEMA IF EXISTS ogvcs_metadata CASCADE;
             DROP SCHEMA IF EXISTS ogvcs_identity CASCADE;",
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
    run_metadata_migrations(
        &mut client,
        MetadataMigrationRunOptions {
            application_version: "0.1.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();
}

fn seed(database_url: &str) -> Fixture {
    let tenant_id = TenantId::from_bytes(public_uuid(0x11));
    let repository_id = RepositoryId::from_bytes(public_uuid(0x22));
    let tenant = format!("tenant.{}", hex(tenant_id.as_bytes()));
    let repository = format!("repository.{}", hex(repository_id.as_bytes()));
    let publication = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [0x55; 32],
    };
    let old_head = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [0x54; 32],
    };
    let candidate_change_set = ObjectRef {
        kind: ObjectKind::ChangeSet,
        digest: [0x56; 32],
    };
    let candidate_file_id = [0x57; 16];
    let subject_digest: [u8; 32] = digest_parts(&[SUBJECT_DOMAIN, b"bridge.publisher"])
        .try_into()
        .unwrap();
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repositories
             (repository_id, tenant_id, project_id) VALUES ($1, $2, $3)",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &Uuid::from_bytes(*tenant_id.as_bytes()),
                &Uuid::from_bytes(public_uuid(0x23)),
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.metadata_objects
             (repository_id, object_kind, digest_algorithm, object_digest,
              canonical_bytes, validation_contract)
             VALUES ($1, 6, 1, $2, $3, 'ogvcs.repository-format@1')",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&[9_u8; 32][..],
                &&[0xa0_u8][..],
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_settings
             (repository_id, descriptor_kind, descriptor_algorithm, descriptor_digest,
              repository_format, required_features, case_mode, path_profile,
              platform_profile, content_policy_profile, structural_limits,
              tenant_boundary, settings_generation)
             VALUES ($1, 6, 1, $2, 'ogvcs.repository-format@1', '[]'::jsonb,
                     'case-sensitive', 'path.opengamevcs/portable@1',
                     'platform.opengamevcs/portable@1', 'content.opengamevcs/default@1',
                     '{}'::jsonb, $3, 1)",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&[9_u8; 32][..],
                &Uuid::from_bytes(*tenant_id.as_bytes()),
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_commit_sequences (repository_id)
             VALUES ($1)",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap();

    let scope = CredentialScope {
        tenants: vec![tenant.clone()],
        repositories: vec![repository.clone()],
        references: vec![REFERENCE.to_owned()],
        path_prefixes: vec!["Game".to_owned()],
        permissions: vec![AGGREGATE_SUBMIT_PERMISSION.to_owned()],
    };
    let policy = policy_at(&tenant, &repository, 1);
    client
        .execute(
            "INSERT INTO ogvcs_identity.authority_states
             (tenant_id, authority_epoch, key_generation) VALUES ($1, 1, 1)",
            &[&tenant],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation,
              presentation_digest, subject_id, subject_digest, actor_class,
              credential_class, groups_json, authority_epoch, issued_at,
              expires_at, state, scope_json, scope_digest)
             VALUES ($1, 'bridge-credential', 1, $2, 'bridge.publisher', $3,
                     'service', 'session', '[]'::jsonb, 1,
                     clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '1 hour', 'active', $4, $5)",
            &[
                &tenant,
                &digest_parts(&[CREDENTIAL_DOMAIN, PRESENTATION.as_bytes()]),
                &&subject_digest[..],
                &Json(&scope),
                &digest_json(&scope),
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_identity.policy_versions
             (tenant_id, repository_id, policy_generation, authority_epoch,
              policy_id, policy_version, path_profile, case_mode,
              policy_json, policy_digest)
             VALUES ($1, $2, 1, 1, $3, $4, $5, $6, $7, $8)",
            &[
                &tenant,
                &repository,
                &policy.id,
                &policy.version,
                &policy.path_profile,
                &policy.case_mode,
                &Json(&policy),
                &digest_json(&policy),
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
    Fixture {
        tenant_id,
        repository_id,
        tenant,
        repository,
        publication,
        old_head,
        candidate_change_set,
        candidate_file_id,
    }
}

fn seed_atomic_candidate(database_url: &str, fixture: &Fixture) {
    let tree_digest = [0x58; 32];
    let snapshot_bytes = encode_canonical(&Cbor::Map(vec![(
        Cbor::UInt(19),
        fixture.candidate_change_set.to_cbor(),
    )]))
    .unwrap();
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    for (kind, digest, bytes) in [
        (3_i16, tree_digest.as_slice(), &[0xa0_u8][..]),
        (
            4_i16,
            fixture.candidate_change_set.digest.as_slice(),
            &[0xa0_u8][..],
        ),
        (7_i16, fixture.old_head.digest.as_slice(), &[0xa0_u8][..]),
        (
            7_i16,
            fixture.publication.digest.as_slice(),
            snapshot_bytes.as_slice(),
        ),
    ] {
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.metadata_objects
                 (repository_id, object_kind, digest_algorithm, object_digest,
                  canonical_bytes, validation_contract)
                 VALUES ($1, $2, 1, $3, $4, 'ogvcs.repository-format@1')",
                &[
                    &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                    &kind,
                    &digest,
                    &bytes,
                ],
            )
            .unwrap();
    }
    for (digest, sequence) in [
        (fixture.old_head.digest, Some(1_i64)),
        (fixture.publication.digest, None),
    ] {
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.snapshots
                 (repository_id, snapshot_digest, root_tree_digest, published_commit_sequence)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                    &&digest[..],
                    &&tree_digest[..],
                    &sequence,
                ],
            )
            .unwrap();
    }
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.object_edges
             (repository_id, source_kind, source_digest, ordinal,
              target_kind, target_digest)
             VALUES ($1, 7, $2, 0, 4, $3)",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.publication.digest[..],
                &&fixture.candidate_change_set.digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE ogvcs_metadata.repository_commit_sequences
             SET applied_sequence = 1 WHERE repository_id = $1",
            &[&Uuid::from_bytes(*fixture.repository_id.as_bytes())],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.references
             (repository_id, reference_kind, reference_name, target_snapshot_digest,
              generation, commit_sequence)
             VALUES ($1, 'branch', 'main', $2, 1, 1)",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.old_head.digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.file_id_registry
             (repository_id, file_id, state, origin, owner_kind, owner_id,
              first_change_set_digest, first_operation)
             VALUES ($1, $2, 'active', 'create', 'draft', 'draft.atomic-candidate', $3, 0)",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.candidate_file_id[..],
                &&fixture.candidate_change_set.digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.file_path_history
             (repository_id, snapshot_digest, operation_ordinal, file_id,
              repository_path_utf8, operation_kind)
             VALUES ($1, $2, 0, $3, $4, 'create')",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.publication.digest[..],
                &&fixture.candidate_file_id[..],
                &&b"Game/Atomic.asset"[..],
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn seed_additional_atomic_candidate_operations(
    database_url: &str,
    fixture: &Fixture,
    total_operations: i32,
) {
    assert!((2..=1_001).contains(&total_operations));
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "WITH operation AS (
                 SELECT ordinal,
                        decode(repeat('59', 12), 'hex') || int4send(ordinal) AS file_id,
                        format('draft.atomic-generated-%s', ordinal) AS owner_id,
                        convert_to(format('Game/Generated-%s.asset', ordinal), 'UTF8') AS path,
                        CASE ordinal % 3
                            WHEN 0 THEN 'create'
                            WHEN 1 THEN 'copy'
                            ELSE 'import'
                        END AS operation_kind
                 FROM generate_series(1, $1 - 1) AS ordinal
             )
             INSERT INTO ogvcs_metadata.file_id_registry
             (repository_id, file_id, state, origin, owner_kind, owner_id,
              first_change_set_digest, first_operation)
             SELECT $2, file_id, 'active', operation_kind::ogvcs_metadata.file_id_origin,
                    'draft', owner_id, $3, ordinal
             FROM operation ORDER BY ordinal",
            &[
                &total_operations,
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.candidate_change_set.digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "WITH operation AS (
                 SELECT ordinal,
                        decode(repeat('59', 12), 'hex') || int4send(ordinal) AS file_id,
                        convert_to(format('Game/Generated-%s.asset', ordinal), 'UTF8') AS path,
                        CASE ordinal % 3
                            WHEN 0 THEN 'create'
                            WHEN 1 THEN 'copy'
                            ELSE 'import'
                        END AS operation_kind
                 FROM generate_series(1, $1 - 1) AS ordinal
             )
             INSERT INTO ogvcs_metadata.file_path_history
             (repository_id, snapshot_digest, operation_ordinal, file_id,
              repository_path_utf8, operation_kind)
             SELECT $2, $3, ordinal, file_id, path, operation_kind
             FROM operation ORDER BY ordinal",
            &[
                &total_operations,
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.publication.digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "WITH import_operation AS (
                 SELECT ordinal,
                        decode(repeat('59', 12), 'hex') || int4send(ordinal) AS file_id,
                        decode(repeat('6a', 28), 'hex') || int4send(ordinal) AS namespace_digest,
                        decode(repeat('6b', 28), 'hex') || int4send(ordinal) AS identity_digest
                 FROM generate_series(1, $1 - 1) AS ordinal
                 WHERE ordinal % 3 = 2
             )
             INSERT INTO ogvcs_metadata.file_id_import_mappings
             (repository_id, importer_profile, source_namespace_digest,
              source_identity_digest, file_id)
             SELECT $2, 'atomic-submit-test/import@1', namespace_digest,
                    identity_digest, file_id
             FROM import_operation ORDER BY ordinal",
            &[
                &total_operations,
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn revoke_credential(database_url: &str, fixture: &Fixture) {
    Client::connect(database_url, NoTls)
        .unwrap()
        .execute(
            "UPDATE ogvcs_identity.credentials
             SET state = 'revoked', revoked_at = clock_timestamp()
             WHERE tenant_id = $1 AND credential_id = 'bridge-credential'
               AND credential_generation = 1",
            &[&fixture.tenant],
        )
        .unwrap();
}

fn policy_at(tenant: &str, repository: &str, generation: u64) -> PolicyDocument {
    PolicyDocument {
        schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
        id: "bridge.aggregate.policy".to_owned(),
        version: format!("v{generation}"),
        generation,
        authority_epoch: 1,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        case_mode: "case-sensitive".to_owned(),
        default_effect: "deny".to_owned(),
        composition: "deny-overrides-v1".to_owned(),
        rules: vec![
            PolicyRule {
                id: "allow.bridge.objects".to_owned(),
                effect: "allow".to_owned(),
                subjects: RuleSubjects {
                    identities: vec!["bridge.publisher".to_owned()],
                    groups: Vec::new(),
                    actor_classes: vec!["service".to_owned()],
                },
                tenant: tenant.to_owned(),
                repository: repository.to_owned(),
                references: vec![REFERENCE.to_owned()],
                path_prefixes: Vec::new(),
                resource_types: vec!["object".to_owned()],
                permissions: vec![AGGREGATE_SUBMIT_PERMISSION.to_owned()],
            },
            PolicyRule {
                id: "allow.bridge.paths".to_owned(),
                effect: "allow".to_owned(),
                subjects: RuleSubjects {
                    identities: vec!["bridge.publisher".to_owned()],
                    groups: Vec::new(),
                    actor_classes: vec!["service".to_owned()],
                },
                tenant: tenant.to_owned(),
                repository: repository.to_owned(),
                references: vec![REFERENCE.to_owned()],
                path_prefixes: vec!["Game".to_owned()],
                resource_types: vec!["path".to_owned()],
                permissions: vec![AGGREGATE_SUBMIT_PERMISSION.to_owned()],
            },
            PolicyRule {
                id: "deny.bridge.paths".to_owned(),
                effect: "deny".to_owned(),
                subjects: RuleSubjects {
                    identities: Vec::new(),
                    groups: Vec::new(),
                    actor_classes: Vec::new(),
                },
                tenant: tenant.to_owned(),
                repository: repository.to_owned(),
                references: vec![REFERENCE.to_owned()],
                path_prefixes: vec![
                    "Game/A-Denied.asset".to_owned(),
                    "Game/M-Denied.asset".to_owned(),
                    "Game/Z-Denied.asset".to_owned(),
                ],
                resource_types: vec!["path".to_owned()],
                permissions: vec![AGGREGATE_SUBMIT_PERMISSION.to_owned()],
            },
        ],
    }
}

fn prepare_identity_authority(
    database_url: &str,
    fixture: &Fixture,
    participant: &PostgresAggregateAuthorizationParticipant,
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    participant
        .bind_repository_contract(
            &mut transaction,
            &RepositoryContractBindingRequest {
                tenant: &fixture.tenant,
                repository: &fixture.repository,
                metadata_tenant_id: &Uuid::from_bytes(*fixture.tenant_id.as_bytes()).to_string(),
                metadata_repository_id: &Uuid::from_bytes(*fixture.repository_id.as_bytes())
                    .to_string(),
            },
        )
        .unwrap();
    participant
        .register_signing_key(
            &mut transaction,
            &AggregateSigningKeyRegistration {
                tenant: &fixture.tenant,
                key_generation: 1,
                authority_epoch: 1,
                key_reference: KEY_REFERENCE,
            },
        )
        .unwrap();
    participant
        .compile_current_policy(&mut transaction, &fixture.tenant, &fixture.repository)
        .unwrap();
    transaction.commit().unwrap();
}

#[allow(clippy::too_many_arguments)]
fn prepare_bundle(
    database_url: &str,
    fixture: &Fixture,
    participant: &PostgresAggregateAuthorizationParticipant,
    first_resource: u32,
    resource_count: u32,
    _lifecycle_plan_id: [u8; 16],
    _key: &str,
    ttl_seconds: u64,
) -> PreparedBundle {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let snapshot = fixture.publication.to_string();
    let handle = {
        let mut transaction = client.transaction().unwrap();
        let handle = participant
            .begin_plan(
                &mut transaction,
                &AggregatePlanRequest {
                    credential_presentation: PRESENTATION,
                    tenant: &fixture.tenant,
                    repository: &fixture.repository,
                    permission: AGGREGATE_SUBMIT_PERMISSION,
                    capability: AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY,
                    reference: Some(REFERENCE),
                    snapshot: Some(&snapshot),
                    reason: Some("publish a sealed repository snapshot"),
                    ttl_seconds,
                },
            )
            .unwrap();
        transaction.commit().unwrap();
        handle
    };
    let mut appended = 0_u32;
    while appended < resource_count {
        let count = (resource_count - appended).min(1_000);
        let resources = (0..count)
            .map(|offset| identity_resource(first_resource + appended + offset))
            .collect::<Vec<_>>();
        let mut transaction = client.transaction().unwrap();
        participant
            .append_chunk(&mut transaction, &handle, &resources)
            .unwrap();
        transaction.commit().unwrap();
        appended += count;
    }
    if resource_count as usize == MAXIMUM_AGGREGATE_RESOURCES {
        let overflow = [identity_resource(first_resource + resource_count)];
        let mut transaction = client.transaction().unwrap();
        let error = participant
            .append_chunk(&mut transaction, &handle, &overflow)
            .unwrap_err();
        assert_eq!(error.code(), ParticipantErrorCode::LimitExceeded);
        transaction.rollback().unwrap();
        let persisted_count: i64 = client
            .query_one(
                "SELECT count(*) FROM ogvcs_identity.aggregate_plan_resources
                 WHERE plan_id = $1",
                &[&handle.plan_id()],
            )
            .unwrap()
            .get(0);
        assert_eq!(persisted_count, MAXIMUM_AGGREGATE_RESOURCES as i64);
    }
    let receipt = {
        let mut transaction = client.transaction().unwrap();
        let receipt = participant
            .authorize_plan(&mut transaction, &handle)
            .unwrap();
        transaction.commit().unwrap();
        receipt
    };
    PreparedBundle {
        receipt,
        first_resource,
        resource_count,
        ttl_seconds,
    }
}

fn persist_lifecycle_plan(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    plan_id: [u8; 16],
    key: &str,
    tamper_projection_at: Option<u32>,
) -> [u8; 16] {
    persist_lifecycle_plan_with_authority(
        database_url,
        fixture,
        bundle,
        plan_id,
        key,
        tamper_projection_at,
        decode_hex(AUTHORIZATION_MANIFEST_SHA256),
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_lifecycle_plan_with_authority(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    plan_id: [u8; 16],
    key: &str,
    tamper_projection_at: Option<u32>,
    authority_contract_digest: [u8; 32],
) -> [u8; 16] {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    seed_lifecycle_rows(
        &mut client,
        fixture,
        bundle.first_resource,
        bundle.resource_count,
    );
    let mut commitments = Vec::new();
    let mut encoded_bytes = 0_u64;
    let mut next = 0_u32;
    while next < bundle.resource_count {
        let digests = load_resource_digest_batch(
            &mut client,
            bundle.receipt.plan_id(),
            next,
            bundle.resource_count,
        );
        let items =
            lifecycle_item_batch(bundle.first_resource, next, digests, tamper_projection_at);
        let chunk = AggregatePlanChunk::new(plan_id, commitments.len() as u16, items).unwrap();
        encoded_bytes += u64::from(chunk.encoded_bytes);
        commitments.push(AggregateChunkCommitment {
            chunk_ordinal: chunk.chunk_ordinal,
            item_count: chunk.items.len() as u16,
            encoded_bytes: chunk.encoded_bytes,
            chunk_digest: chunk.chunk_digest,
        });
        next += chunk.items.len() as u32;
    }
    let reservation = reservation(key, bundle.ttl_seconds);
    let subject = decode_hex(bundle.receipt.subject_digest());
    let scope = decode_hex(bundle.receipt.authenticated_scope_digest());
    let provisional = AggregatePublicationPlan::new_authorized(
        plan_id,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.publication,
        REFERENCE.to_owned(),
        fixture.publication.to_string(),
        subject,
        bundle.receipt.authority_epoch(),
        authority_contract_digest,
        fixture.publication.digest,
        [0; 32],
        scope,
        reservation.clone(),
        bundle.resource_count,
        encoded_bytes,
    )
    .unwrap();
    let plan_digest = aggregate_plan_digest(&provisional, &commitments).unwrap();
    let plan = AggregatePublicationPlan::new_authorized(
        plan_id,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.publication,
        REFERENCE.to_owned(),
        fixture.publication.to_string(),
        subject,
        bundle.receipt.authority_epoch(),
        authority_contract_digest,
        fixture.publication.digest,
        plan_digest,
        scope,
        reservation,
        bundle.resource_count,
        encoded_bytes,
    )
    .unwrap();
    drop(client);
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    let mut writer = store.begin_lifecycle_plan_for_test(plan).unwrap();
    let mut digest_client = Client::connect(database_url, NoTls).unwrap();
    let mut next = 0_u32;
    while next < bundle.resource_count {
        let digests = load_resource_digest_batch(
            &mut digest_client,
            bundle.receipt.plan_id(),
            next,
            bundle.resource_count,
        );
        let items =
            lifecycle_item_batch(bundle.first_resource, next, digests, tamper_projection_at);
        let chunk = AggregatePlanChunk::new(plan_id, (next / 1_000) as u16, items).unwrap();
        next += chunk.items.len() as u32;
        writer.append_chunk(chunk).unwrap();
    }
    assert_eq!(writer.seal().unwrap(), plan_digest);
    plan_id
}

fn load_resource_digest_batch(
    client: &mut Client,
    identity_plan_id: &str,
    first_ordinal: u32,
    total: u32,
) -> Vec<[u8; 32]> {
    let limit = (total - first_ordinal).min(1_000);
    let rows = client
        .query(
            "SELECT item_ordinal, resource_digest
             FROM ogvcs_identity.aggregate_plan_resources
             WHERE plan_id = $1 AND item_ordinal >= $2
             ORDER BY item_ordinal LIMIT $3",
            &[&identity_plan_id, &(first_ordinal as i32), &(limit as i64)],
        )
        .unwrap();
    assert_eq!(rows.len(), limit as usize);
    rows.into_iter()
        .enumerate()
        .map(|(offset, row)| {
            assert_eq!(row.get::<_, i32>(0), first_ordinal as i32 + offset as i32);
            <[u8; 32]>::try_from(row.get::<_, Vec<u8>>(1)).unwrap()
        })
        .collect()
}

fn lifecycle_item_batch(
    first_resource: u32,
    first_ordinal: u32,
    digests: Vec<[u8; 32]>,
    tamper_projection_at: Option<u32>,
) -> Vec<LifecycleObjectBinding> {
    digests
        .into_iter()
        .enumerate()
        .map(|(offset, mut digest)| {
            let ordinal = first_ordinal + offset as u32;
            if tamper_projection_at == Some(ordinal) {
                digest[0] ^= 1;
            }
            lifecycle_item(first_resource + ordinal, digest)
        })
        .collect()
}

fn seed_lifecycle_rows(
    client: &mut Client,
    fixture: &Fixture,
    first_resource: u32,
    resource_count: u32,
) {
    let lifecycle_contract = decode_hex(LIFECYCLE_CONTRACT_SHA256);
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "WITH item AS (
                 SELECT value::integer AS value
                 FROM generate_series($1::integer, $2::integer) AS value
             ), binding AS (
                 SELECT value,
                        decode(repeat('10', 28), 'hex') || int4send(value) AS opaque_key,
                        decode(repeat('a1', 28), 'hex') || int4send(value) AS authority_digest,
                        decode(repeat('b1', 28), 'hex') || int4send(value) AS backend_digest,
                        decode(repeat('c1', 28), 'hex') || int4send(value) AS health_digest,
                        decode(repeat('d1', 28), 'hex') || int4send(value) AS backend_evidence,
                        decode(repeat('e1', 28), 'hex') || int4send(value) AS health_evidence
                 FROM item
             )
             INSERT INTO ogvcs_metadata.lifecycle_receipts
             (receipt_digest, receipt_kind, tenant_id, repository_id, opaque_key,
              object_kind, object_digest, expected_state, expected_generation,
              target_state, target_generation, authority_binding_digest,
              health_result, health_generation, lifecycle_contract_digest,
              evidence_digest)
             SELECT backend_digest, 'backend-durable', $3::uuid, $4::uuid, opaque_key,
                    3, opaque_key, 'staged', 1, 'available', 2, authority_digest,
                    NULL, NULL, $5::bytea, backend_evidence
             FROM binding
             UNION ALL
             SELECT health_digest, 'health-observation', $3::uuid, $4::uuid, opaque_key,
                    3, opaque_key, 'available', 2, 'available', 2, authority_digest,
                    'healthy', 1, $5::bytea, health_evidence
             FROM binding
             ON CONFLICT DO NOTHING",
            &[
                &(first_resource as i32),
                &((first_resource + resource_count - 1) as i32),
                &Uuid::from_bytes(*fixture.tenant_id.as_bytes()),
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&lifecycle_contract[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "WITH item AS (
                 SELECT value::integer AS value,
                        decode(repeat('10', 28), 'hex') || int4send(value::integer) AS opaque_key
                 FROM generate_series($1::integer, $2::integer) AS value
             )
             INSERT INTO ogvcs_metadata.object_lifecycle
             (tenant_id, repository_id, opaque_key, object_kind, object_digest,
              object_length, tenant_scope_digest, state, generation, health,
              health_generation, health_observation_digest, authority_binding_digest,
              backend_receipt_digest, verification_receipt_digest,
              deletion_receipt_digest, retention_until)
             SELECT $3, $4, opaque_key, 3, opaque_key, 1,
                    decode(repeat('91', 28), 'hex') || int4send(value),
                    'available', 2, 'healthy', 1,
                    decode(repeat('c1', 28), 'hex') || int4send(value),
                    decode(repeat('a1', 28), 'hex') || int4send(value),
                    decode(repeat('b1', 28), 'hex') || int4send(value),
                    NULL, NULL, clock_timestamp() + interval '1 hour'
             FROM item ON CONFLICT DO NOTHING",
            &[
                &(first_resource as i32),
                &((first_resource + resource_count - 1) as i32),
                &Uuid::from_bytes(*fixture.tenant_id.as_bytes()),
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn lifecycle_item(index: u32, resource_digest: [u8; 32]) -> LifecycleObjectBinding {
    LifecycleObjectBinding {
        opaque_key: opaque_key(index),
        object_ref: object_ref(index),
        expected_state: LifecycleState::Available,
        expected_generation: 2,
        expected_health: LifecycleHealth::Healthy,
        expected_health_generation: Some(1),
        current_health_observation_digest: Some(receipt_digest(0xc1, index)),
        authority_binding_digest: receipt_digest(0xa1, index),
        current_backend_receipt_digest: Some(receipt_digest(0xb1, index)),
        current_verification_receipt_digest: None,
        current_deletion_receipt_digest: None,
        transition_backend_receipt_digest: None,
        transition_verification_receipt_digest: None,
        transition_deletion_receipt_digest: None,
        resource_opaque_digest: resource_digest,
    }
}

fn identity_resource(index: u32) -> IdentityAuthorizationResource {
    IdentityAuthorizationResource {
        resource_type: "object".to_owned(),
        path: None,
        file_id: None,
        object_id: Some(object_ref(index).to_string()),
        name: None,
    }
}

fn path_resource(path: &str) -> IdentityAuthorizationResource {
    IdentityAuthorizationResource {
        resource_type: "path".to_owned(),
        path: Some(path.to_owned()),
        file_id: None,
        object_id: None,
        name: None,
    }
}

fn object_ref(index: u32) -> ObjectRef {
    ObjectRef {
        kind: ObjectKind::Tree,
        digest: opaque_key(index),
    }
}

fn opaque_key(index: u32) -> [u8; 32] {
    let mut key = [0x10; 32];
    key[28..].copy_from_slice(&index.to_be_bytes());
    key
}

fn receipt_digest(domain: u8, index: u32) -> [u8; 32] {
    let mut bytes = [domain; 32];
    bytes[28..].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn reservation(key: &str, ttl_seconds: u64) -> IdempotencyReservation {
    let issued_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let expires_ms = issued_ms + ttl_seconds * 1_000;
    let issued_at = SystemTime::UNIX_EPOCH + Duration::from_millis(issued_ms);
    IdempotencyReservation {
        operation: "submit.finalize".to_owned(),
        key: format!(
            "ik1.{issued_ms}.{expires_ms}.{}",
            hex(&Sha256::digest(key.as_bytes()))
        ),
        semantic_fingerprint: Sha256::digest(key.as_bytes()).into(),
        issued_at,
        expires_at: SystemTime::UNIX_EPOCH + Duration::from_millis(expires_ms),
    }
}

fn production_store(
    database_url: &str,
    provider: Arc<HmacSha256KeyRing>,
) -> IdentityBoundPostgresMetadataStore {
    IdentityBoundPostgresMetadataStore::connect_with_aggregate_authorization(
        database_url,
        PostgresTransactionAuthorizationParticipant::new().unwrap(),
        PostgresAggregateAuthorizationParticipant::new(provider),
    )
    .unwrap()
}

fn key_provider(key: [u8; 32]) -> Arc<HmacSha256KeyRing> {
    Arc::new(HmacSha256KeyRing::new([(KEY_REFERENCE.to_owned(), key)]).unwrap())
}

fn identity_consumptions(database_url: &str, plan_id: &str) -> i64 {
    Client::connect(database_url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.aggregate_plan_consumptions
             WHERE plan_id = $1",
            &[&plan_id],
        )
        .unwrap()
        .get(0)
}

fn lifecycle_applications(database_url: &str, plan_id: [u8; 16]) -> i64 {
    Client::connect(database_url, NoTls)
        .unwrap()
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.lifecycle_applications WHERE plan_id = $1",
            &[&Uuid::from_bytes(plan_id)],
        )
        .unwrap()
        .get(0)
}

fn assert_zero_operation_intent_rejected(
    database_url: &str,
    fixture: &Fixture,
    lifecycle_plan: [u8; 16],
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let error = client
        .execute(
            "INSERT INTO ogvcs_metadata.submit_intents
             (intent_id, tenant_id, repository_id, lifecycle_plan_id,
              reference_name, expected_head_digest, expected_generation,
              candidate_snapshot_digest, candidate_change_set_digest,
              lifecycle_plan_digest, authenticated_scope_digest,
              idempotency_operation, idempotency_key,
              lifecycle_semantic_fingerprint, submit_fingerprint,
              operation_count, operation_set_digest, intent_digest, expires_at)
             SELECT $1, plan.tenant_id, plan.repository_id, plan.plan_id,
                    plan.authorization_reference, $3, 1,
                    plan.publication_digest, $4, seal.plan_digest,
                    plan.idempotency_scope_digest, plan.idempotency_operation,
                    plan.idempotency_key, plan.semantic_fingerprint,
                    decode(repeat('f1', 32), 'hex'), 0,
                    decode(repeat('f2', 32), 'hex'), decode(repeat('f3', 32), 'hex'),
                    plan.expires_at
             FROM ogvcs_metadata.lifecycle_publication_plans AS plan
             JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal USING (plan_id)
             WHERE plan.plan_id = $2",
            &[
                &Uuid::from_bytes(public_uuid(0x9f)),
                &Uuid::from_bytes(lifecycle_plan),
                &&fixture.old_head.digest[..],
                &&fixture.candidate_change_set.digest[..],
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().unwrap().code(), "23514");
    let count: i64 = client
        .query_one("SELECT count(*) FROM ogvcs_metadata.submit_intents", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

fn assert_atomic_submit_not_visible(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    lifecycle_plan: [u8; 16],
) {
    assert_eq!(
        identity_consumptions(database_url, bundle.receipt.plan_id()),
        0
    );
    assert_eq!(lifecycle_applications(database_url, lifecycle_plan), 0);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT reference.target_snapshot_digest, reference.generation,
                    snapshot.published_commit_sequence, registry.owner_kind::text,
                    registry.owner_id,
                    (SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes),
                    (SELECT count(*) FROM ogvcs_metadata.submit_file_id_consumptions)
             FROM ogvcs_metadata.references AS reference
             JOIN ogvcs_metadata.snapshots AS snapshot
               ON snapshot.repository_id = reference.repository_id
              AND snapshot.snapshot_digest = $3
             JOIN ogvcs_metadata.file_id_registry AS registry
               ON registry.repository_id = reference.repository_id
              AND registry.file_id = $4
             WHERE reference.repository_id = $1 AND reference.reference_kind = 'branch'
               AND reference.reference_name = $2",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &REFERENCE,
                &&fixture.publication.digest[..],
                &&fixture.candidate_file_id[..],
            ],
        )
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), fixture.old_head.digest);
    assert_eq!(row.get::<_, i64>(1), 1);
    assert_eq!(row.get::<_, Option<i64>>(2), None);
    assert_eq!(row.get::<_, String>(3), "draft");
    assert_eq!(row.get::<_, String>(4), "draft.atomic-candidate");
    assert_eq!(row.get::<_, i64>(5), 0);
    assert_eq!(row.get::<_, i64>(6), 0);
}

fn assert_atomic_submit_visible(
    database_url: &str,
    fixture: &Fixture,
    outbox_event_id: &[u8; 16],
    operation_count: i64,
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT reference.target_snapshot_digest, reference.generation,
                    snapshot.published_commit_sequence, registry.owner_kind::text,
                    registry.owner_id,
                    (SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes),
                    (SELECT count(*) FROM ogvcs_metadata.submit_file_id_consumptions)
             FROM ogvcs_metadata.references AS reference
             JOIN ogvcs_metadata.snapshots AS snapshot
               ON snapshot.repository_id = reference.repository_id
              AND snapshot.snapshot_digest = $3
             JOIN ogvcs_metadata.file_id_registry AS registry
               ON registry.repository_id = reference.repository_id
              AND registry.file_id = $4
             WHERE reference.repository_id = $1 AND reference.reference_kind = 'branch'
               AND reference.reference_name = $2",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &REFERENCE,
                &&fixture.publication.digest[..],
                &&fixture.candidate_file_id[..],
            ],
        )
        .unwrap();
    assert_eq!(row.get::<_, Vec<u8>>(0), fixture.publication.digest);
    assert_eq!(row.get::<_, i64>(1), 2);
    assert!(row.get::<_, Option<i64>>(2).is_some());
    assert_eq!(row.get::<_, String>(3), "published");
    assert_eq!(row.get::<_, String>(4), hex(&fixture.publication.digest));
    assert_eq!(row.get::<_, i64>(5), 1);
    assert_eq!(row.get::<_, i64>(6), operation_count);

    let lease_id = Uuid::from_bytes(public_uuid(0xa8));
    assert_eq!(
        client
            .execute(
                "UPDATE ogvcs_metadata.outbox_events
                 SET lease_id = $2, leased_by = 'atomic-submit-test-consumer',
                     lease_expires_at = clock_timestamp() + interval '1 minute',
                     delivery_attempts = delivery_attempts + 1
                 WHERE event_id = $1 AND acknowledged_at IS NULL AND lease_id IS NULL",
                &[&Uuid::from_bytes(*outbox_event_id), &lease_id],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        client
            .execute(
                "UPDATE ogvcs_metadata.outbox_events
                 SET acknowledged_at = clock_timestamp(), lease_id = NULL,
                     leased_by = NULL, lease_expires_at = NULL
                 WHERE event_id = $1 AND lease_id = $2",
                &[&Uuid::from_bytes(*outbox_event_id), &lease_id],
            )
            .unwrap(),
        1
    );
    let hostile = client.execute(
        "UPDATE ogvcs_metadata.outbox_events
         SET safe_payload = '{\"class\":\"tampered\"}'::jsonb WHERE event_id = $1",
        &[&Uuid::from_bytes(*outbox_event_id)],
    );
    assert_eq!(hostile.unwrap_err().code().unwrap().code(), "55000");
    let prior_owner_tamper = client.execute(
        "UPDATE ogvcs_metadata.submit_file_id_consumptions
         SET prior_owner_id = 'forged-prior-owner'",
        &[],
    );
    assert_eq!(
        prior_owner_tamper.unwrap_err().code().unwrap().code(),
        "55000"
    );
    let late_append = client.execute(
        "INSERT INTO ogvcs_metadata.submit_file_id_consumptions
         SELECT * FROM ogvcs_metadata.submit_file_id_consumptions LIMIT 1",
        &[],
    );
    assert_eq!(late_append.unwrap_err().code().unwrap().code(), "55000");
}

fn assert_application_counts(database_url: &str, application_id: [u8; 16], count: i64) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_transaction_facts
                 WHERE application_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_reachability
                 WHERE application_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_internal_outbox
                 WHERE application_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence
                 WHERE application_id = $1)",
            &[&Uuid::from_bytes(application_id)],
        )
        .unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
            row.get::<_, i64>(3)
        ),
        (count, count, count + 1, 1)
    );
}

fn assert_late_child_appends_rejected(database_url: &str, application_id: [u8; 16]) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let application_id = Uuid::from_bytes(application_id);
    for table in [
        "lifecycle_transaction_facts",
        "lifecycle_publication_reachability",
        "lifecycle_internal_outbox",
    ] {
        let statement = format!(
            "INSERT INTO ogvcs_metadata.{table}
             SELECT * FROM ogvcs_metadata.{table}
             WHERE application_id = $1 LIMIT 1"
        );
        let error = client.execute(&statement, &[&application_id]).unwrap_err();
        assert_eq!(error.code().map(|code| code.code()), Some("55000"));
        assert_eq!(
            error.as_db_error().map(|error| error.message()),
            Some("aggregate lifecycle child evidence is sealed")
        );
    }
}

fn canonical_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_value).collect()),
        Value::Object(values) => {
            let sorted: BTreeMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, canonical_value(value)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        value => value,
    }
}

fn digest_json<T: Serialize>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value).unwrap();
    Sha256::digest(serde_json::to_vec(&canonical_value(value)).unwrap()).to_vec()
}

fn digest_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().to_vec()
}

fn decode_hex(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut result = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    result
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("non-canonical hex"),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(DIGITS[(byte >> 4) as usize] as char);
        value.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}

fn public_uuid(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = (value[6] & 0x0f) | 0x40;
    value[8] = (value[8] & 0x3f) | 0x80;
    value
}
