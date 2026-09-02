use std::{
    collections::BTreeMap,
    sync::{mpsc, Arc, Barrier, Mutex},
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
    AggregateIdentityMappingFaultForTest, AggregateLifecycleApplyRequest, AggregatePlanChunk,
    AggregatePublicationPlan, AtomicSubmitFaultForTest, AtomicSubmitRestartBoundaryForTest,
    DomainErrorCode, IdempotencyReservation, IdentityBoundPostgresMetadataStore, LifecycleHealth,
    LifecycleObjectBinding, LifecycleState, MigrationRunOptions as MetadataMigrationRunOptions,
    PostgresMetadataStore, PreallocatedCreationSubmitFinalizeRequest,
    PreallocatedCreationSubmitIntentRequest, PreallocatedCreationSubmitPreflightRequest,
    PreallocatedCreationSubmitReconciliation, RepositoryId, TenantId,
    AUTHORIZATION_MANIFEST_SHA256, LIFECYCLE_CONTRACT_SHA256,
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
const SECOND_REFERENCE: &str = "release";
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
    let mut store = production_store(&database_url, provider.clone());
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
    let before_caught_bridge = atomic_submit_state(
        &database_url,
        &fixture,
        &bundle,
        lifecycle_plan,
        *intent.intent_id(),
    );
    assert!(!store
        .caught_bridge_error_commits_for_test(AggregateLifecycleApplyRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            consumption_id: "invalid/slash",
        })
        .unwrap());
    assert_eq!(
        atomic_submit_state(
            &database_url,
            &fixture,
            &bundle,
            lifecycle_plan,
            *intent.intent_id(),
        ),
        before_caught_bridge,
        "a caught bridge error must leave every durable submit projection unchanged"
    );

    for fault in [
        AtomicSubmitFaultForTest::BeforeBridge,
        AtomicSubmitFaultForTest::AfterBridge,
        AtomicSubmitFaultForTest::AfterFileIdConsumption,
        AtomicSubmitFaultForTest::AfterSnapshotMarker,
        AtomicSubmitFaultForTest::AfterBranchCas,
        AtomicSubmitFaultForTest::AfterAudit,
        AtomicSubmitFaultForTest::AfterOutboxEvent,
        AtomicSubmitFaultForTest::AfterConsistencyToken,
        AtomicSubmitFaultForTest::AfterFinalOutcome,
        AtomicSubmitFaultForTest::AfterReconciliation,
        AtomicSubmitFaultForTest::BeforeCommit,
    ] {
        let before = atomic_submit_state(
            &database_url,
            &fixture,
            &bundle,
            lifecycle_plan,
            *intent.intent_id(),
        );
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
        assert_eq!(
            atomic_submit_state(
                &database_url,
                &fixture,
                &bundle,
                lifecycle_plan,
                *intent.intent_id(),
            ),
            before,
            "fault {fault:?} changed durable submit state despite rollback"
        );
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
    drop(store);
    let mut store = production_store(&database_url, provider.clone());
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
    drop(store);
    let mut store = production_store(&database_url, provider);
    let restarted_replay = store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.one",
        })
        .unwrap();
    assert_eq!(restarted_replay, replay);
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
fn private_atomic_submit_hard_restart_is_exact_old_or_new_and_recoverable() {
    let _guard = TEST_LOCK.lock().unwrap();
    let (Ok(database_url), Ok(boundary_name)) = (
        std::env::var("OGVCS_METADATA_RESTART_DATABASE_URL"),
        std::env::var("OGVCS_METADATA_RESTART_BOUNDARY"),
    ) else {
        return;
    };
    let boundary = atomic_submit_restart_boundary(&boundary_name);
    reset_database(&database_url);
    install_commit_io_restart_rendezvous(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        19_000,
        3,
        public_uuid(0xe1),
        "atomic-hard-restart",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0xe2),
        "atomic-hard-restart-plan",
        None,
    );
    let mut store = production_store(&database_url, provider.clone());
    let intent = store
        .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            expected_head: fixture.old_head,
            expected_generation: 1,
        })
        .unwrap();
    let preflight = store
        .preflight_preallocated_creation_submit(PreallocatedCreationSubmitPreflightRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
        })
        .unwrap();
    assert!(preflight.branch_matches());
    let before = atomic_submit_state(
        &database_url,
        &fixture,
        &bundle,
        lifecycle_plan,
        *intent.intent_id(),
    );

    let restart_error = store
        .finalize_preallocated_creation_submit_with_restart_rendezvous_for_test(
            PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.hard-restart",
            },
            boundary,
            120,
        )
        .unwrap_err();
    assert_eq!(
        restart_error.code,
        DomainErrorCode::ObjectInvalid,
        "restart call did not fail through mapped PostgreSQL I/O"
    );
    drop(store);
    wait_for_restarted_database(&database_url);

    let observed_after_restart = atomic_submit_state(
        &database_url,
        &fixture,
        &bundle,
        lifecycle_plan,
        *intent.intent_id(),
    );
    let initial_state = if observed_after_restart == before {
        "old"
    } else {
        assert_complete_new_atomic_submit_state(&observed_after_restart, 1);
        "new"
    };
    match boundary {
        AtomicSubmitRestartBoundaryForTest::CommitIo => {}
        AtomicSubmitRestartBoundaryForTest::AfterCommitBeforeResponse => assert_eq!(
            initial_state, "new",
            "postcommit response-loss boundary did not preserve the committed projection"
        ),
        _ => assert_eq!(
            initial_state, "old",
            "precommit restart boundary unexpectedly committed"
        ),
    }

    if initial_state == "old" {
        assert_atomic_submit_not_visible(&database_url, &fixture, &bundle, lifecycle_plan);
        let mut reconciliation_store = production_store(&database_url, provider.clone());
        assert!(matches!(
            reconciliation_store
                .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                    intent_id: *intent.intent_id(),
                    authorization: &bundle.receipt,
                    consumption_id: "atomic.consume.hard-restart",
                },)
                .unwrap(),
            PreallocatedCreationSubmitReconciliation::UnknownRecovering { .. }
        ));
        let after_unknown = atomic_submit_state(
            &database_url,
            &fixture,
            &bundle,
            lifecycle_plan,
            *intent.intent_id(),
        );
        assert_only_one_reconciliation_was_appended(&before, &after_unknown, "unknown-recovering");
        drop(reconciliation_store);
        let mut retry_store = production_store(&database_url, provider.clone());
        let retry = retry_store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.hard-restart",
            })
            .unwrap();
        assert!(!retry.replayed());
    } else {
        let mut replay_store = production_store(&database_url, provider.clone());
        let replay = replay_store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.hard-restart",
            })
            .unwrap();
        assert!(replay.replayed());
        assert_eq!(
            atomic_submit_state(
                &database_url,
                &fixture,
                &bundle,
                lifecycle_plan,
                *intent.intent_id(),
            ),
            observed_after_restart,
            "replay mutated the exact durable new state"
        );
    }

    let mut replay_store = production_store(&database_url, provider.clone());
    let canonical_replay = replay_store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.hard-restart",
        })
        .unwrap();
    assert!(canonical_replay.replayed());
    drop(replay_store);
    assert_atomic_submit_visible(
        &database_url,
        &fixture,
        canonical_replay.outbox_event_id(),
        1,
    );
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        1
    );
    assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 1);

    let before_committed_reconciliation = atomic_submit_state(
        &database_url,
        &fixture,
        &bundle,
        lifecycle_plan,
        *intent.intent_id(),
    );
    assert_complete_new_atomic_submit_state(
        &before_committed_reconciliation,
        if initial_state == "old" { 2 } else { 1 },
    );
    let mut reconciliation_store = production_store(&database_url, provider.clone());
    let committed = reconciliation_store
        .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &bundle.receipt,
            consumption_id: "atomic.consume.hard-restart",
        })
        .unwrap();
    let PreallocatedCreationSubmitReconciliation::Committed(committed) = committed else {
        panic!("committed restart outcome reconciled as unknown");
    };
    assert_eq!(*committed, canonical_replay);
    drop(reconciliation_store);
    let after_committed_reconciliation = atomic_submit_state(
        &database_url,
        &fixture,
        &bundle,
        lifecycle_plan,
        *intent.intent_id(),
    );
    assert_only_one_reconciliation_was_appended(
        &before_committed_reconciliation,
        &after_committed_reconciliation,
        "committed",
    );

    let mut final_replay_store = production_store(&database_url, provider);
    assert_eq!(
        final_replay_store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
                consumption_id: "atomic.consume.hard-restart",
            })
            .unwrap(),
        canonical_replay
    );
    assert_eq!(
        atomic_submit_state(
            &database_url,
            &fixture,
            &bundle,
            lifecycle_plan,
            *intent.intent_id(),
        ),
        after_committed_reconciliation,
        "fresh-connection replay changed durable recovery state"
    );
    println!(
        "OGVCS_METADATA_RESTART_RESULT {}",
        serde_json::json!({
            "schemaVersion": "ogvcs.repository-metadata/restart-case-result/v1",
            "boundary": boundary.name(),
            "initialState": initial_state,
            "identityConsumptions": 1,
            "lifecycleApplications": 1,
            "fileIdConsumptions": 1,
            "finalOutcomes": 1,
            "resultDigest": hex(canonical_replay.result_digest()),
        })
    );
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
fn private_submit_binds_the_exact_aggregate_plan_and_rejects_request_reuse() {
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
    let exact = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_700,
        2,
        public_uuid(0xa0),
        "atomic-exact-plan",
        300,
    );
    let substitute = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        9_800,
        2,
        public_uuid(0xa1),
        "atomic-substitute-plan",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &exact,
        public_uuid(0xa2),
        "atomic-exact-plan-lifecycle",
        None,
    );
    let mut store = production_store(&database_url, provider);
    assert_eq!(
        store
            .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
                authorization: &substitute.receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head: fixture.old_head,
                expected_generation: 1,
            },)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    let empty: i64 = Client::connect(&database_url, NoTls)
        .unwrap()
        .query_one("SELECT count(*) FROM ogvcs_metadata.submit_intents", &[])
        .unwrap()
        .get(0);
    assert_eq!(empty, 0, "a substitute aggregate plan sealed an intent");

    let intent = store
        .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
            authorization: &exact.receipt,
            lifecycle_plan_id: lifecycle_plan,
            expected_head: fixture.old_head,
            expected_generation: 1,
        })
        .unwrap();
    let before = atomic_submit_state(
        &database_url,
        &fixture,
        &exact,
        lifecycle_plan,
        *intent.intent_id(),
    );
    for error in [
        store
            .preflight_preallocated_creation_submit(PreallocatedCreationSubmitPreflightRequest {
                intent_id: *intent.intent_id(),
                authorization: &substitute.receipt,
            })
            .unwrap_err(),
        store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &substitute.receipt,
                consumption_id: "atomic.consume.substitute",
            })
            .unwrap_err(),
        store
            .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &substitute.receipt,
                consumption_id: "atomic.consume.substitute",
            })
            .unwrap_err(),
        store
            .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
                authorization: &exact.receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head: fixture.old_head,
                expected_generation: 2,
            })
            .unwrap_err(),
    ] {
        assert_eq!(error.code, DomainErrorCode::MetadataNotFoundOrDenied);
    }
    assert_eq!(
        atomic_submit_state(
            &database_url,
            &fixture,
            &exact,
            lifecycle_plan,
            *intent.intent_id(),
        ),
        before,
        "receipt substitution or changed-request reuse mutated submit state"
    );
    assert_eq!(
        identity_consumptions(&database_url, exact.receipt.plan_id()),
        0
    );
    assert_eq!(
        identity_consumptions(&database_url, substitute.receipt.plan_id()),
        0
    );
    let preflight = store
        .preflight_preallocated_creation_submit(PreallocatedCreationSubmitPreflightRequest {
            intent_id: *intent.intent_id(),
            authorization: &exact.receipt,
        })
        .unwrap();
    assert!(preflight.branch_matches());
    let outcome = store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &exact.receipt,
            consumption_id: "atomic.consume.exact-plan",
        })
        .unwrap();
    simulate_pre_v13_committed_mapping_absence(&database_url, lifecycle_plan, 2);
    let committed = atomic_submit_state(
        &database_url,
        &fixture,
        &exact,
        lifecycle_plan,
        *intent.intent_id(),
    );
    for error in [
        store
            .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &substitute.receipt,
                consumption_id: "atomic.consume.exact-plan",
            })
            .unwrap_err(),
        store
            .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                intent_id: *intent.intent_id(),
                authorization: &substitute.receipt,
                consumption_id: "atomic.consume.exact-plan",
            })
            .unwrap_err(),
    ] {
        assert_eq!(error.code, DomainErrorCode::MetadataNotFoundOrDenied);
    }
    assert_eq!(
        atomic_submit_state(
            &database_url,
            &fixture,
            &exact,
            lifecycle_plan,
            *intent.intent_id(),
        ),
        committed,
        "receipt substitution mutated the committed replay projection"
    );
    assert_eq!(
        identity_consumptions(&database_url, substitute.receipt.plan_id()),
        0
    );
    let replay = store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &exact.receipt,
            consumption_id: "atomic.consume.exact-plan",
        })
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay.result_digest(), outcome.result_digest());
    let reconciliation = store
        .reconcile_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: *intent.intent_id(),
            authorization: &exact.receipt,
            consumption_id: "atomic.consume.exact-plan",
        })
        .unwrap();
    let PreallocatedCreationSubmitReconciliation::Committed(reconciled) = reconciliation else {
        panic!("historical committed outcome reconciled as unknown");
    };
    assert_eq!(reconciled.result_digest(), outcome.result_digest());
}

#[test]
fn intent_and_preflight_observations_do_not_wait_behind_publication_locks() {
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
        9_600,
        2,
        public_uuid(0x9d),
        "atomic-observation-lock-order",
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0x9e),
        "atomic-observation-lock-order-plan",
        None,
    );

    let mut blocker_client = Client::connect(&database_url, NoTls).unwrap();
    let mut blocker = blocker_client.transaction().unwrap();
    let locked = blocker
        .query(
            "SELECT reference.reference_name, registry.file_id
             FROM ogvcs_metadata.references AS reference
             JOIN ogvcs_metadata.file_id_registry AS registry
               ON registry.repository_id = reference.repository_id
             WHERE reference.repository_id = $1
               AND reference.reference_kind = 'branch'
               AND reference.reference_name = $2
               AND registry.file_id = $3
             FOR UPDATE OF reference, registry",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &REFERENCE,
                &&fixture.candidate_file_id[..],
            ],
        )
        .unwrap();
    assert_eq!(
        locked.len(),
        1,
        "publication blocker did not lock exact rows"
    );

    let (intent_sender, intent_receiver) = mpsc::channel();
    let intent_database_url = database_url.clone();
    let intent_provider = provider.clone();
    let intent_receipt = bundle.receipt.clone();
    let expected_head = fixture.old_head;
    let intent_worker = thread::spawn(move || {
        let mut store = production_store(&intent_database_url, intent_provider);
        let result = store.create_preallocated_creation_submit_intent(
            PreallocatedCreationSubmitIntentRequest {
                authorization: &intent_receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head,
                expected_generation: 1,
            },
        );
        intent_sender.send(result).unwrap();
    });
    let intent = intent_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("intent creation waited behind non-reserving publication rows")
        .unwrap();
    intent_worker.join().unwrap();

    let (preflight_sender, preflight_receiver) = mpsc::channel();
    let preflight_database_url = database_url.clone();
    let preflight_receipt = bundle.receipt.clone();
    let intent_id = *intent.intent_id();
    let preflight_worker = thread::spawn(move || {
        let mut store = production_store(&preflight_database_url, provider);
        let result = store.preflight_preallocated_creation_submit(
            PreallocatedCreationSubmitPreflightRequest {
                intent_id,
                authorization: &preflight_receipt,
            },
        );
        preflight_sender.send(result).unwrap();
    });
    let preflight = preflight_receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("preflight waited behind a non-reserving branch row")
        .unwrap();
    assert!(preflight.branch_matches());
    preflight_worker.join().unwrap();
    blocker.rollback().unwrap();
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
fn eight_distinct_private_intents_from_one_head_publish_exactly_one_candidate() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    seed_atomic_candidate(&database_url, &fixture);
    let mut candidates = vec![fixture.clone()];
    for index in 1..=7 {
        let candidate = atomic_candidate_variant(&fixture, index);
        seed_atomic_candidate_variant(&database_url, &candidate, index);
        candidates.push(candidate);
    }

    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let mut cases = Vec::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        let bundle = prepare_bundle(
            &database_url,
            &candidate,
            &participant,
            10_000 + index as u32 * 10,
            1,
            public_uuid(0xd0 + index as u8),
            &format!("atomic-one-head-{index}"),
            300,
        );
        let lifecycle_plan = persist_lifecycle_plan(
            &database_url,
            &candidate,
            &bundle,
            public_uuid(0xd0 + index as u8),
            &format!("atomic-one-head-plan-{index}"),
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
        cases.push((candidate, bundle, lifecycle_plan, *intent.intent_id()));
    }

    let barrier = Arc::new(Barrier::new(cases.len()));
    let workers = cases
        .iter()
        .enumerate()
        .map(|(index, (_, bundle, _, intent_id))| {
            let database_url = database_url.clone();
            let provider = provider.clone();
            let receipt = bundle.receipt.clone();
            let intent_id = *intent_id;
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = production_store(&database_url, provider);
                barrier.wait();
                (
                    index,
                    store.finalize_preallocated_creation_submit(
                        PreallocatedCreationSubmitFinalizeRequest {
                            intent_id,
                            authorization: &receipt,
                            consumption_id: &format!("atomic.consume.one-head-{index}"),
                        },
                    ),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let winners = results
        .iter()
        .filter_map(|(index, result)| result.as_ref().ok().map(|outcome| (*index, outcome)))
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1, "one expected head must have one winner");
    let (winner_index, winner) = winners[0];
    for (index, result) in &results {
        if *index != winner_index {
            assert!(
                matches!(
                    result.as_ref().unwrap_err().code,
                    DomainErrorCode::MetadataNotFoundOrDenied
                        | DomainErrorCode::TransactionRetryExhausted
                ),
                "loser {index} returned an unexpected class"
            );
        }
    }

    let mut client = Client::connect(&database_url, NoTls).unwrap();
    let reference = client
        .query_one(
            "SELECT target_snapshot_digest, generation, commit_sequence
             FROM ogvcs_metadata.references
             WHERE repository_id = $1 AND reference_kind = 'branch'
               AND reference_name = $2",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &REFERENCE,
            ],
        )
        .unwrap();
    assert_eq!(
        reference.get::<_, Vec<u8>>(0),
        cases[winner_index].0.publication.digest
    );
    assert_eq!(reference.get::<_, i64>(1), 2);
    assert_eq!(reference.get::<_, i64>(2), winner.commit_sequence() as i64);

    for (index, (candidate, bundle, lifecycle_plan, intent_id)) in cases.iter().enumerate() {
        let row = client
            .query_one(
                "SELECT snapshot.published_commit_sequence,
                        registry.owner_kind::text,
                        (SELECT count(*)
                         FROM ogvcs_metadata.submit_file_id_consumptions
                         WHERE intent_id = $4)
                 FROM ogvcs_metadata.snapshots AS snapshot
                 JOIN ogvcs_metadata.file_id_registry AS registry
                   ON registry.repository_id = snapshot.repository_id
                  AND registry.file_id = $3
                 WHERE snapshot.repository_id = $1
                   AND snapshot.snapshot_digest = $2",
                &[
                    &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                    &&candidate.publication.digest[..],
                    &&candidate.candidate_file_id[..],
                    &Uuid::from_bytes(*intent_id),
                ],
            )
            .unwrap();
        if index == winner_index {
            assert_eq!(
                row.get::<_, Option<i64>>(0),
                Some(winner.commit_sequence() as i64)
            );
            assert_eq!(row.get::<_, String>(1), "published");
            assert_eq!(row.get::<_, i64>(2), 1);
            assert_eq!(
                identity_consumptions(&database_url, bundle.receipt.plan_id()),
                1
            );
            assert_eq!(lifecycle_applications(&database_url, *lifecycle_plan), 1);
        } else {
            assert_eq!(row.get::<_, Option<i64>>(0), None);
            assert_eq!(row.get::<_, String>(1), "draft");
            assert_eq!(row.get::<_, i64>(2), 0);
            assert_eq!(
                identity_consumptions(&database_url, bundle.receipt.plan_id()),
                0
            );
            assert_eq!(lifecycle_applications(&database_url, *lifecycle_plan), 0);
        }
    }
    let counts = client
        .query_one(
            "SELECT
                (SELECT count(*) FROM ogvcs_metadata.references
                 WHERE repository_id = $1 AND reference_kind = 'branch'),
                (SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes),
                (SELECT count(*) FROM ogvcs_metadata.submit_internal_audit_evidence),
                (SELECT count(*) FROM ogvcs_metadata.outbox_events
                 WHERE event_type = 'internal.submit-committed-candidate'),
                (SELECT count(*) FROM ogvcs_metadata.consistency_tokens),
                (SELECT count(*) FROM ogvcs_metadata.submit_file_id_consumptions),
                (SELECT count(*) FROM ogvcs_metadata.submit_reconciliation_records)",
            &[&Uuid::from_bytes(*fixture.repository_id.as_bytes())],
        )
        .unwrap();
    assert_eq!(
        (
            counts.get::<_, i64>(0),
            counts.get::<_, i64>(1),
            counts.get::<_, i64>(2),
            counts.get::<_, i64>(3),
            counts.get::<_, i64>(4),
            counts.get::<_, i64>(5),
            counts.get::<_, i64>(6),
        ),
        (1, 1, 1, 1, 1, 1, 1)
    );
}

#[test]
fn reversed_shared_file_id_ordinals_are_rejected_before_intent_sealing() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let base = seed(&database_url);
    seed_atomic_candidate(&database_url, &base);
    let (main, _, shared_file_ids) =
        seed_reverse_order_cross_branch_candidates(&database_url, &base);
    assert!(shared_file_ids[0] > shared_file_ids[1]);
    let reversed = seed_reversed_shared_file_id_candidate(&database_url, &main, shared_file_ids);

    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &base, &participant);
    let bundle = prepare_bundle_for_reference(
        &database_url,
        &reversed,
        &participant,
        12_000,
        2,
        REFERENCE,
        300,
    );
    let lifecycle_plan = persist_lifecycle_plan_for_reference(
        &database_url,
        &reversed,
        &bundle,
        public_uuid(0xe1),
        "atomic-reversed-shared-file-id-plan",
        REFERENCE,
        None,
    );
    let nonexistent_intent_id = public_uuid(0xe2);
    let before = atomic_submit_state(
        &database_url,
        &reversed,
        &bundle,
        lifecycle_plan,
        nonexistent_intent_id,
    );

    let mut store = production_store(&database_url, provider);
    assert_eq!(
        store
            .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
                authorization: &bundle.receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head: base.old_head,
                expected_generation: 1,
            },)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        atomic_submit_state(
            &database_url,
            &reversed,
            &bundle,
            lifecycle_plan,
            nonexistent_intent_id,
        ),
        before,
        "reversing immutable shared FileID ordinals must fail before any submit state changes"
    );
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        0
    );
    assert_eq!(lifecycle_applications(&database_url, lifecycle_plan), 0);
    let mut client = Client::connect(&database_url, NoTls).unwrap();
    let leaked = client
        .query_one(
            "SELECT (SELECT count(*) FROM ogvcs_metadata.submit_intents),
                    (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations)",
            &[],
        )
        .unwrap();
    assert_eq!((leaked.get::<_, i64>(0), leaked.get::<_, i64>(1)), (0, 0));
}

#[test]
fn cross_branch_shared_file_id_collision_has_one_complete_nonreplay_winner() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let base = seed(&database_url);
    seed_atomic_candidate(&database_url, &base);
    let (main, release, shared_file_ids) =
        seed_reverse_order_cross_branch_candidates(&database_url, &base);
    assert!(
        shared_file_ids[0] > shared_file_ids[1],
        "operation ordinal intentionally differs from canonical FileID lock order"
    );

    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &base, &participant);
    let specifications = [
        (REFERENCE, main, 13_000_u32),
        (SECOND_REFERENCE, release, 13_100),
    ];
    let mut cases = Vec::new();
    for (index, (reference, candidate, first_resource)) in specifications.into_iter().enumerate() {
        let bundle = prepare_bundle_for_reference(
            &database_url,
            &candidate,
            &participant,
            first_resource,
            2,
            reference,
            300,
        );
        let lifecycle_plan = persist_lifecycle_plan_for_reference(
            &database_url,
            &candidate,
            &bundle,
            public_uuid(0xe4 + index as u8),
            &format!("atomic-cross-branch-plan-{index}"),
            reference,
            None,
        );
        let mut creator = production_store(&database_url, provider.clone());
        let intent = creator
            .create_preallocated_creation_submit_intent(PreallocatedCreationSubmitIntentRequest {
                authorization: &bundle.receipt,
                lifecycle_plan_id: lifecycle_plan,
                expected_head: base.old_head,
                expected_generation: 1,
            })
            .unwrap();
        assert_eq!(intent.operation_count(), 2);
        cases.push((
            reference.to_owned(),
            candidate,
            bundle,
            lifecycle_plan,
            *intent.intent_id(),
        ));
    }

    let barrier = Arc::new(Barrier::new(cases.len()));
    let workers = cases
        .iter()
        .enumerate()
        .map(|(index, (_, _, bundle, _, intent_id))| {
            let database_url = database_url.clone();
            let provider = provider.clone();
            let receipt = bundle.receipt.clone();
            let intent_id = *intent_id;
            let barrier = barrier.clone();
            thread::spawn(move || {
                let mut store = production_store(&database_url, provider);
                barrier.wait();
                (
                    index,
                    store.finalize_preallocated_creation_submit(
                        PreallocatedCreationSubmitFinalizeRequest {
                            intent_id,
                            authorization: &receipt,
                            consumption_id: &format!("atomic.consume.cross-branch-{index}"),
                        },
                    ),
                )
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    let winners = results
        .iter()
        .filter_map(|(index, result)| result.as_ref().ok().map(|outcome| (*index, outcome)))
        .collect::<Vec<_>>();
    assert_eq!(winners.len(), 1);
    let (winner_index, winner) = winners[0];
    assert!(
        !winner.replayed(),
        "a distinct intent conflict is not a replay"
    );
    let loser_index = 1 - winner_index;
    assert!(matches!(
        results[loser_index].1.as_ref().unwrap_err().code,
        DomainErrorCode::MetadataNotFoundOrDenied | DomainErrorCode::TransactionRetryExhausted
    ));

    let mut client = Client::connect(&database_url, NoTls).unwrap();
    for (index, (reference, candidate, bundle, lifecycle_plan, intent_id)) in
        cases.iter().enumerate()
    {
        let row = client
            .query_one(
                "SELECT reference.target_snapshot_digest, reference.generation,
                        snapshot.published_commit_sequence,
                        (SELECT count(*)
                         FROM ogvcs_metadata.submit_file_id_consumptions
                         WHERE intent_id = $4),
                        (SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes
                         WHERE intent_id = $4)
                 FROM ogvcs_metadata.references AS reference
                 JOIN ogvcs_metadata.snapshots AS snapshot
                   ON snapshot.repository_id = reference.repository_id
                  AND snapshot.snapshot_digest = $3
                 WHERE reference.repository_id = $1
                   AND reference.reference_kind = 'branch'
                   AND reference.reference_name = $2",
                &[
                    &Uuid::from_bytes(*base.repository_id.as_bytes()),
                    reference,
                    &&candidate.publication.digest[..],
                    &Uuid::from_bytes(*intent_id),
                ],
            )
            .unwrap();
        if index == winner_index {
            assert_eq!(row.get::<_, Vec<u8>>(0), candidate.publication.digest);
            assert_eq!(row.get::<_, i64>(1), 2);
            assert_eq!(
                row.get::<_, Option<i64>>(2),
                Some(winner.commit_sequence() as i64)
            );
            assert_eq!(row.get::<_, i64>(3), 2);
            assert_eq!(row.get::<_, i64>(4), 1);
            assert_eq!(
                identity_consumptions(&database_url, bundle.receipt.plan_id()),
                1
            );
            assert_eq!(lifecycle_applications(&database_url, *lifecycle_plan), 1);
        } else {
            assert_eq!(row.get::<_, Vec<u8>>(0), base.old_head.digest);
            assert_eq!(row.get::<_, i64>(1), 1);
            assert_eq!(row.get::<_, Option<i64>>(2), None);
            assert_eq!(row.get::<_, i64>(3), 0);
            assert_eq!(row.get::<_, i64>(4), 0);
            assert_eq!(
                identity_consumptions(&database_url, bundle.receipt.plan_id()),
                0
            );
            assert_eq!(lifecycle_applications(&database_url, *lifecycle_plan), 0);
        }
    }
    let registry = client
        .query(
            "SELECT file_id, owner_kind::text, owner_id,
                    first_operation, first_change_set_digest
             FROM ogvcs_metadata.file_id_registry
             WHERE repository_id = $1 AND file_id IN ($2, $3)
             ORDER BY file_id",
            &[
                &Uuid::from_bytes(*base.repository_id.as_bytes()),
                &&shared_file_ids[0][..],
                &&shared_file_ids[1][..],
            ],
        )
        .unwrap();
    assert_eq!(registry.len(), 2);
    let expected_owner = hex(&cases[winner_index].1.publication.digest);
    for row in registry {
        assert_eq!(row.get::<_, String>(1), "published");
        assert_eq!(row.get::<_, String>(2), expected_owner);
        assert_eq!(
            row.get::<_, Vec<u8>>(4),
            cases[winner_index].1.candidate_change_set.digest
        );
    }
    assert_eq!(
        registry_first_operations(&database_url, &base, shared_file_ids),
        vec![1, 0]
    );

    assert_application_counts(&database_url, *winner.application_id(), 2);
    let global = client
        .query_one(
            "SELECT
                (SELECT count(*) FROM ogvcs_metadata.submit_intents),
                (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations),
                (SELECT count(*) FROM ogvcs_metadata.submit_internal_audit_evidence),
                (SELECT count(*) FROM ogvcs_metadata.outbox_events
                 WHERE event_type = 'internal.submit-committed-candidate'),
                (SELECT count(*) FROM ogvcs_metadata.consistency_tokens
                 WHERE repository_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.submit_reconciliation_records),
                (SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes),
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_transaction_facts),
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_reachability),
                (SELECT count(*) FROM ogvcs_metadata.lifecycle_internal_outbox),
                (SELECT count(*)
                 FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence),
                (SELECT count(*) FROM ogvcs_metadata.snapshots
                 WHERE repository_id = $1 AND snapshot_digest IN ($2, $3)
                   AND published_commit_sequence IS NOT NULL)",
            &[
                &Uuid::from_bytes(*base.repository_id.as_bytes()),
                &&cases[0].1.publication.digest[..],
                &&cases[1].1.publication.digest[..],
            ],
        )
        .unwrap();
    assert_eq!(
        (
            global.get::<_, i64>(0),
            global.get::<_, i64>(1),
            global.get::<_, i64>(2),
            global.get::<_, i64>(3),
            global.get::<_, i64>(4),
            global.get::<_, i64>(5),
            global.get::<_, i64>(6),
            global.get::<_, i64>(7),
            global.get::<_, i64>(8),
            global.get::<_, i64>(9),
            global.get::<_, i64>(10),
            global.get::<_, i64>(11),
        ),
        (2, 4, 1, 1, 1, 1, 1, 2, 2, 3, 1, 1)
    );

    let loser = &cases[loser_index];
    let loser_evidence = client
        .query_one(
            "SELECT
                (SELECT count(*) FROM ogvcs_metadata.submit_file_id_consumptions
                 WHERE intent_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.submit_internal_audit_evidence
                 WHERE intent_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.submit_reconciliation_records
                 WHERE intent_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes
                 WHERE intent_id = $1),
                (SELECT count(*) FROM ogvcs_metadata.outbox_events
                 WHERE event_id IN (SELECT outbox_event_id
                                    FROM ogvcs_metadata.submit_final_outcomes
                                    WHERE intent_id = $1)),
                (SELECT count(*) FROM ogvcs_metadata.consistency_tokens
                 WHERE token_digest IN (SELECT consistency_token_digest
                                        FROM ogvcs_metadata.submit_final_outcomes
                                        WHERE intent_id = $1)),
                (SELECT count(*)
                 FROM ogvcs_metadata.lifecycle_transaction_facts AS fact
                 JOIN ogvcs_metadata.lifecycle_applications AS application
                   USING (application_id)
                 WHERE application.plan_id = $2),
                (SELECT count(*)
                 FROM ogvcs_metadata.lifecycle_publication_reachability AS reachability
                 JOIN ogvcs_metadata.lifecycle_applications AS application
                   USING (application_id)
                 WHERE application.plan_id = $2),
                (SELECT count(*)
                 FROM ogvcs_metadata.lifecycle_internal_outbox AS event
                 JOIN ogvcs_metadata.lifecycle_applications AS application
                   USING (application_id)
                 WHERE application.plan_id = $2),
                (SELECT count(*)
                 FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence AS evidence
                 JOIN ogvcs_metadata.lifecycle_applications AS application
                   USING (application_id)
                 WHERE application.plan_id = $2),
                (SELECT count(*) FROM ogvcs_metadata.snapshots
                 WHERE repository_id = $3 AND snapshot_digest = $4
                   AND published_commit_sequence IS NOT NULL)",
            &[
                &Uuid::from_bytes(loser.4),
                &Uuid::from_bytes(loser.3),
                &Uuid::from_bytes(*base.repository_id.as_bytes()),
                &&loser.1.publication.digest[..],
            ],
        )
        .unwrap();
    assert_eq!(
        (
            loser_evidence.get::<_, i64>(0),
            loser_evidence.get::<_, i64>(1),
            loser_evidence.get::<_, i64>(2),
            loser_evidence.get::<_, i64>(3),
            loser_evidence.get::<_, i64>(4),
            loser_evidence.get::<_, i64>(5),
            loser_evidence.get::<_, i64>(6),
            loser_evidence.get::<_, i64>(7),
            loser_evidence.get::<_, i64>(8),
            loser_evidence.get::<_, i64>(9),
            loser_evidence.get::<_, i64>(10),
        ),
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    );

    let winner_case = &cases[winner_index];
    let before_replay = atomic_submit_state(
        &database_url,
        &winner_case.1,
        &winner_case.2,
        winner_case.3,
        winner_case.4,
    );
    let mut replay_store = production_store(&database_url, provider);
    let replay = replay_store
        .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
            intent_id: winner_case.4,
            authorization: &winner_case.2.receipt,
            consumption_id: &format!("atomic.consume.cross-branch-{winner_index}"),
        })
        .unwrap();
    assert!(
        replay.replayed(),
        "only the same committed intent is replayed"
    );
    assert_eq!(replay.result_digest(), winner.result_digest());
    assert_eq!(
        atomic_submit_state(
            &database_url,
            &winner_case.1,
            &winner_case.2,
            winner_case.3,
            winner_case.4,
        ),
        before_replay,
        "same-intent replay must not create a second publication"
    );
}

#[test]
fn private_submit_rechecks_credential_epoch_and_policy_after_actual_preflight() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    for (scenario_index, scenario) in ["credential-revoked", "epoch-stale", "policy-stale"]
        .into_iter()
        .enumerate()
    {
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
            9_200 + scenario_index as u32 * 100,
            2,
            public_uuid(0x95 + scenario_index as u8 * 2),
            &format!("atomic-{scenario}"),
            300,
        );
        let lifecycle_plan = persist_lifecycle_plan(
            &database_url,
            &fixture,
            &bundle,
            public_uuid(0x96 + scenario_index as u8 * 2),
            &format!("atomic-{scenario}-plan"),
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
        let preflight = store
            .preflight_preallocated_creation_submit(PreallocatedCreationSubmitPreflightRequest {
                intent_id: *intent.intent_id(),
                authorization: &bundle.receipt,
            })
            .unwrap();
        assert!(preflight.branch_matches());

        match scenario {
            "credential-revoked" => revoke_credential(&database_url, &fixture),
            "epoch-stale" => advance_authority_epoch(&database_url, &fixture),
            "policy-stale" => advance_policy_generation(&database_url, &fixture),
            _ => unreachable!(),
        }
        let before = atomic_submit_state(
            &database_url,
            &fixture,
            &bundle,
            lifecycle_plan,
            *intent.intent_id(),
        );
        assert_eq!(
            store
                .finalize_preallocated_creation_submit(PreallocatedCreationSubmitFinalizeRequest {
                    intent_id: *intent.intent_id(),
                    authorization: &bundle.receipt,
                    consumption_id: &format!("atomic.consume.{scenario}"),
                })
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied,
            "scenario {scenario} must fail closed after preflight"
        );
        assert_eq!(
            atomic_submit_state(
                &database_url,
                &fixture,
                &bundle,
                lifecycle_plan,
                *intent.intent_id(),
            ),
            before,
            "scenario {scenario} mutated submit state after currentness denial"
        );
        assert_atomic_submit_not_visible(&database_url, &fixture, &bundle, lifecycle_plan);
    }
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
    let mut mapping_writer = PostgresMetadataStore::connect(&database_url).unwrap();
    assert_eq!(
        mapping_writer
            .seal_aggregate_identity_mapping_for_test(
                wrong_plan,
                first.receipt.plan_id(),
                &[0, 1, 2],
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "a lifecycle resource-projection substitution must not acquire a v13 mapping seal"
    );
    assert_eq!(aggregate_identity_mapping_counts(&database_url), (0, 0));
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
fn aggregate_identity_mapping_is_required_immutable_and_rolls_back_hostile_relations() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        5_000,
        3,
        public_uuid(0xa1),
        "mapping-hostile",
        300,
    );
    let lifecycle_plan = persist_unmapped_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0xa2),
        "mapping-hostile-plan",
    );
    let mut production = production_store(&database_url, provider);
    assert_eq!(
        production
            .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
                authorization: &bundle.receipt,
                lifecycle_plan_id: lifecycle_plan,
                consumption_id: "mapping.consume.unmapped",
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        identity_consumptions(&database_url, bundle.receipt.plan_id()),
        0,
        "an old unconsumed plan without a v13 mapping consumed authority"
    );

    let mut fixture_store = PostgresMetadataStore::connect(&database_url).unwrap();
    for (scenario, mapping) in [
        ("positional-swap", vec![1, 0, 2]),
        ("duplicate", vec![0, 0, 2]),
        ("missing", vec![0, 1]),
        ("extra", vec![0, 1, 2, 3]),
    ] {
        assert_eq!(
            fixture_store
                .seal_aggregate_identity_mapping_for_test(
                    lifecycle_plan,
                    bundle.receipt.plan_id(),
                    &mapping,
                )
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied,
            "hostile {scenario} mapping was accepted"
        );
        assert_eq!(aggregate_identity_mapping_counts(&database_url), (0, 0));
    }

    for fault in [
        AggregateIdentityMappingFaultForTest::ForgeFirstItemDigest,
        AggregateIdentityMappingFaultForTest::ForgeSealDigest,
    ] {
        assert_eq!(
            fixture_store
                .seal_aggregate_identity_mapping_with_fault_for_test(
                    lifecycle_plan,
                    bundle.receipt.plan_id(),
                    &[0, 1, 2],
                    fault,
                )
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );
        assert_eq!(aggregate_identity_mapping_counts(&database_url), (0, 0));
    }

    let cross_plan = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        5_100,
        3,
        public_uuid(0xa3),
        "mapping-cross-plan",
        300,
    );
    assert_eq!(
        fixture_store
            .seal_aggregate_identity_mapping_for_test(
                lifecycle_plan,
                cross_plan.receipt.plan_id(),
                &[0, 1, 2],
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(aggregate_identity_mapping_counts(&database_url), (0, 0));
    assert_eq!(
        identity_consumptions(&database_url, cross_plan.receipt.plan_id()),
        0
    );

    fixture_store
        .seal_aggregate_identity_mapping_for_test(
            lifecycle_plan,
            bundle.receipt.plan_id(),
            &[0, 1, 2],
        )
        .unwrap();
    assert_eq!(aggregate_identity_mapping_counts(&database_url), (1, 3));
    assert_aggregate_identity_mapping_immutable(&database_url, lifecycle_plan);
    let applied = production
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            consumption_id: "mapping.consume.valid",
        })
        .unwrap();
    assert_eq!(applied.lifecycle().object_count, 3);
}

#[test]
fn aggregate_identity_projection_can_reverse_lifecycle_opaque_order() {
    let _guard = TEST_LOCK.lock().unwrap();
    let Ok(database_url) = std::env::var("OGVCS_METADATA_AGGREGATE_DATABASE_URL") else {
        return;
    };
    reset_database(&database_url);
    let fixture = seed(&database_url);
    let provider = key_provider([0x5a; 32]);
    let participant = PostgresAggregateAuthorizationParticipant::new(provider.clone());
    prepare_identity_authority(&database_url, &fixture, &participant);
    let bundle = prepare_bundle(
        &database_url,
        &fixture,
        &participant,
        5_200,
        3,
        public_uuid(0xa4),
        "mapping-reversed",
        300,
    );
    let lifecycle_plan = persist_reversed_lifecycle_plan(
        &database_url,
        &fixture,
        &bundle,
        public_uuid(0xa5),
        "mapping-reversed-plan",
    );
    let mut store = production_store(&database_url, provider);
    let applied = store
        .apply_aggregate_lifecycle_publication(AggregateLifecycleApplyRequest {
            authorization: &bundle.receipt,
            lifecycle_plan_id: lifecycle_plan,
            consumption_id: "mapping.consume.reversed",
        })
        .unwrap();
    assert_eq!(applied.lifecycle().object_count, 3);
    assert_eq!(applied.projection_page_count(), 1);
    let mut client = Client::connect(&database_url, NoTls).unwrap();
    let relation = client
        .query(
            "SELECT lifecycle_global_ordinal, identity_item_ordinal
             FROM ogvcs_metadata.lifecycle_aggregate_identity_items
             WHERE lifecycle_plan_id = $1
             ORDER BY lifecycle_global_ordinal",
            &[&Uuid::from_bytes(lifecycle_plan)],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get::<_, i32>(0), row.get::<_, i32>(1)))
        .collect::<Vec<_>>();
    assert_eq!(relation, vec![(0, 2), (1, 1), (2, 0)]);
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

fn atomic_submit_restart_boundary(name: &str) -> AtomicSubmitRestartBoundaryForTest {
    match name {
        "before-bridge" => AtomicSubmitRestartBoundaryForTest::BeforeBridge,
        "after-bridge" => AtomicSubmitRestartBoundaryForTest::AfterBridge,
        "after-file-id-consumption" => AtomicSubmitRestartBoundaryForTest::AfterFileIdConsumption,
        "after-snapshot-marker" => AtomicSubmitRestartBoundaryForTest::AfterSnapshotMarker,
        "after-branch-cas" => AtomicSubmitRestartBoundaryForTest::AfterBranchCas,
        "after-audit" => AtomicSubmitRestartBoundaryForTest::AfterAudit,
        "after-outbox-event" => AtomicSubmitRestartBoundaryForTest::AfterOutboxEvent,
        "after-consistency-token" => AtomicSubmitRestartBoundaryForTest::AfterConsistencyToken,
        "after-final-outcome" => AtomicSubmitRestartBoundaryForTest::AfterFinalOutcome,
        "after-reconciliation" => AtomicSubmitRestartBoundaryForTest::AfterReconciliation,
        "before-commit" => AtomicSubmitRestartBoundaryForTest::BeforeCommit,
        "commit-io" => AtomicSubmitRestartBoundaryForTest::CommitIo,
        "after-commit-before-response" => {
            AtomicSubmitRestartBoundaryForTest::AfterCommitBeforeResponse
        }
        _ => panic!("unknown bounded restart boundary: {name}"),
    }
}

fn install_commit_io_restart_rendezvous(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .batch_execute(
            "CREATE SCHEMA ogvcs_restart_test;
             CREATE TABLE ogvcs_restart_test.commit_rendezvous (
                 intent_id uuid PRIMARY KEY
             );
             CREATE FUNCTION ogvcs_restart_test.sleep_during_commit()
             RETURNS trigger LANGUAGE plpgsql AS $$
             DECLARE
                 seconds integer;
             BEGIN
                 seconds := current_setting(
                     'ogvcs.restart_commit_sleep_seconds', TRUE
                 )::integer;
                 IF seconds IS NULL OR seconds < 1 OR seconds > 300 THEN
                     RAISE EXCEPTION 'invalid bounded commit rendezvous';
                 END IF;
                 PERFORM pg_sleep(seconds::double precision);
                 RETURN NEW;
             END
             $$;
             CREATE CONSTRAINT TRIGGER sleep_during_commit
             AFTER INSERT ON ogvcs_restart_test.commit_rendezvous
             DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW EXECUTE FUNCTION ogvcs_restart_test.sleep_during_commit();",
        )
        .unwrap();
}

fn wait_for_restarted_database(database_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let mut config: postgres::Config = database_url.parse().unwrap();
        config.connect_timeout(Duration::from_secs(2));
        if let Ok(mut client) = config.connect(NoTls) {
            if client.simple_query("SELECT 1").is_ok() {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "PostgreSQL did not recover within the bounded restart window"
        );
        thread::sleep(Duration::from_millis(250));
    }
}

fn assert_complete_new_atomic_submit_state(state: &Value, reconciliation_count: usize) {
    assert_eq!(state["identityPlanState"], "consumed");
    for key in [
        "identityConsumptions",
        "lifecycleApplications",
        "lifecycleAuthorizationEvidence",
        "fileIdConsumptions",
        "auditEvidence",
        "metadataOutbox",
        "consistencyTokens",
        "finalOutcomes",
    ] {
        assert_eq!(state[key], 1, "incomplete committed projection: {key}");
    }
    assert_eq!(state["lifecycleFacts"], 3);
    assert_eq!(state["lifecycleReachability"], 3);
    assert_eq!(state["lifecycleOutbox"], 4);
    assert_eq!(state["lifecycleRows"].as_array().unwrap().len(), 3);
    assert_eq!(
        state["reconciliations"].as_array().unwrap().len(),
        reconciliation_count
    );
}

fn assert_only_one_reconciliation_was_appended(
    before: &Value,
    after: &Value,
    expected_observation: &str,
) {
    let mut before_without_reconciliations = before.clone();
    let before_reconciliations = before_without_reconciliations
        .as_object_mut()
        .unwrap()
        .remove("reconciliations")
        .unwrap();
    let mut after_without_reconciliations = after.clone();
    let after_reconciliations = after_without_reconciliations
        .as_object_mut()
        .unwrap()
        .remove("reconciliations")
        .unwrap();
    assert_eq!(
        after_without_reconciliations, before_without_reconciliations,
        "reconciliation changed a non-reconciliation durable projection"
    );
    let before_rows = before_reconciliations.as_array().unwrap();
    let after_rows = after_reconciliations.as_array().unwrap();
    assert_eq!(after_rows.len(), before_rows.len() + 1);
    assert_eq!(&after_rows[..before_rows.len()], before_rows);
    assert_eq!(after_rows.last().unwrap()[0], expected_observation);
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
        references: vec![REFERENCE.to_owned(), SECOND_REFERENCE.to_owned()],
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

fn atomic_candidate_variant(base: &Fixture, index: u8) -> Fixture {
    assert!((1..=7).contains(&index));
    let mut fixture = base.clone();
    fixture.publication = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [0x60 + index; 32],
    };
    fixture.candidate_change_set = ObjectRef {
        kind: ObjectKind::ChangeSet,
        digest: [0x70 + index; 32],
    };
    fixture.candidate_file_id = [0x80 + index; 16];
    fixture
}

fn seed_atomic_candidate_variant(database_url: &str, fixture: &Fixture, index: u8) {
    let tree_digest = [0x90 + index; 32];
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
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.snapshots
             (repository_id, snapshot_digest, root_tree_digest, published_commit_sequence)
             VALUES ($1, $2, $3, NULL)",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.publication.digest[..],
                &&tree_digest[..],
            ],
        )
        .unwrap();
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
    let owner_id = format!("draft.atomic-racer-{index}");
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.file_id_registry
             (repository_id, file_id, state, origin, owner_kind, owner_id,
              first_change_set_digest, first_operation)
             VALUES ($1, $2, 'active', 'create', 'draft', $3, $4, 0)",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.candidate_file_id[..],
                &owner_id,
                &&fixture.candidate_change_set.digest[..],
            ],
        )
        .unwrap();
    let path = format!("Game/Atomic-racer-{index}.asset");
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
                &path.as_bytes(),
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn seed_reverse_order_cross_branch_candidates(
    database_url: &str,
    base: &Fixture,
) -> (Fixture, Fixture, [[u8; 16]; 2]) {
    let change_set = ObjectRef {
        kind: ObjectKind::ChangeSet,
        digest: [0xb1; 32],
    };
    let high_file_id = [0xf1; 16];
    let low_file_id = [0x01; 16];
    let mut main = base.clone();
    main.publication = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [0xb2; 32],
    };
    main.candidate_change_set = change_set;
    main.candidate_file_id = high_file_id;
    let mut release = main.clone();
    release.publication = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [0xb3; 32],
    };

    let snapshot_bytes =
        encode_canonical(&Cbor::Map(vec![(Cbor::UInt(19), change_set.to_cbor())])).unwrap();
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.metadata_objects
             (repository_id, object_kind, digest_algorithm, object_digest,
              canonical_bytes, validation_contract)
             VALUES ($1, 4, 1, $2, $3, 'ogvcs.repository-format@1')",
            &[
                &Uuid::from_bytes(*base.repository_id.as_bytes()),
                &&change_set.digest[..],
                &&[0xa0_u8][..],
            ],
        )
        .unwrap();
    for (index, candidate) in [&main, &release].into_iter().enumerate() {
        let tree_digest = [0xc1 + index as u8; 32];
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.metadata_objects
                 (repository_id, object_kind, digest_algorithm, object_digest,
                  canonical_bytes, validation_contract)
                 VALUES ($1, 3, 1, $2, $3, 'ogvcs.repository-format@1'),
                        ($1, 7, 1, $4, $5, 'ogvcs.repository-format@1')",
                &[
                    &Uuid::from_bytes(*base.repository_id.as_bytes()),
                    &&tree_digest[..],
                    &&[0xa0_u8][..],
                    &&candidate.publication.digest[..],
                    &snapshot_bytes,
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.snapshots
                 (repository_id, snapshot_digest, root_tree_digest,
                  published_commit_sequence)
                 VALUES ($1, $2, $3, NULL)",
                &[
                    &Uuid::from_bytes(*base.repository_id.as_bytes()),
                    &&candidate.publication.digest[..],
                    &&tree_digest[..],
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.object_edges
                 (repository_id, source_kind, source_digest, ordinal,
                  target_kind, target_digest)
                 VALUES ($1, 7, $2, 0, 4, $3)",
                &[
                    &Uuid::from_bytes(*base.repository_id.as_bytes()),
                    &&candidate.publication.digest[..],
                    &&change_set.digest[..],
                ],
            )
            .unwrap();
        for (ordinal, (file_id, path)) in [
            (high_file_id, b"Game/Reverse-high.asset".as_slice()),
            (low_file_id, b"Game/Reverse-low.asset".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            transaction
                .execute(
                    "INSERT INTO ogvcs_metadata.file_path_history
                     (repository_id, snapshot_digest, operation_ordinal, file_id,
                      repository_path_utf8, operation_kind)
                     VALUES ($1, $2, $3, $4, $5, 'create')",
                    &[
                        &Uuid::from_bytes(*base.repository_id.as_bytes()),
                        &&candidate.publication.digest[..],
                        &(ordinal as i32),
                        &&file_id[..],
                        &path,
                    ],
                )
                .unwrap();
        }
    }
    for (ordinal, file_id) in [high_file_id, low_file_id].into_iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.file_id_registry
                 (repository_id, file_id, state, origin, owner_kind, owner_id,
                  first_change_set_digest, first_operation)
                 VALUES ($1, $2, 'active', 'create', 'draft',
                         'draft.reverse-order', $3, $4)",
                &[
                    &Uuid::from_bytes(*base.repository_id.as_bytes()),
                    &&file_id[..],
                    &&change_set.digest[..],
                    &(ordinal as i32),
                ],
            )
            .unwrap();
    }
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.references
             (repository_id, reference_kind, reference_name,
              target_snapshot_digest, generation, commit_sequence)
             VALUES ($1, 'branch', $2, $3, 1, 1)",
            &[
                &Uuid::from_bytes(*base.repository_id.as_bytes()),
                &SECOND_REFERENCE,
                &&base.old_head.digest[..],
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
    (main, release, [high_file_id, low_file_id])
}

fn seed_reversed_shared_file_id_candidate(
    database_url: &str,
    valid_candidate: &Fixture,
    shared_file_ids: [[u8; 16]; 2],
) -> Fixture {
    let mut reversed = valid_candidate.clone();
    reversed.publication = ObjectRef {
        kind: ObjectKind::Snapshot,
        digest: [0xb4; 32],
    };
    reversed.candidate_file_id = shared_file_ids[1];
    let tree_digest = [0xc4_u8; 32];
    let snapshot_bytes = encode_canonical(&Cbor::Map(vec![(
        Cbor::UInt(19),
        reversed.candidate_change_set.to_cbor(),
    )]))
    .unwrap();
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.metadata_objects
             (repository_id, object_kind, digest_algorithm, object_digest,
              canonical_bytes, validation_contract)
             VALUES ($1, 3, 1, $2, $3, 'ogvcs.repository-format@1'),
                    ($1, 7, 1, $4, $5, 'ogvcs.repository-format@1')",
            &[
                &Uuid::from_bytes(*reversed.repository_id.as_bytes()),
                &&tree_digest[..],
                &&[0xa0_u8][..],
                &&reversed.publication.digest[..],
                &snapshot_bytes,
            ],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.snapshots
             (repository_id, snapshot_digest, root_tree_digest,
              published_commit_sequence)
             VALUES ($1, $2, $3, NULL)",
            &[
                &Uuid::from_bytes(*reversed.repository_id.as_bytes()),
                &&reversed.publication.digest[..],
                &&tree_digest[..],
            ],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.object_edges
             (repository_id, source_kind, source_digest, ordinal,
              target_kind, target_digest)
             VALUES ($1, 7, $2, 0, 4, $3)",
            &[
                &Uuid::from_bytes(*reversed.repository_id.as_bytes()),
                &&reversed.publication.digest[..],
                &&reversed.candidate_change_set.digest[..],
            ],
        )
        .unwrap();
    for (ordinal, (file_id, path)) in [
        (
            shared_file_ids[1],
            b"Game/Reversed-low-first.asset".as_slice(),
        ),
        (
            shared_file_ids[0],
            b"Game/Reversed-high-second.asset".as_slice(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.file_path_history
                 (repository_id, snapshot_digest, operation_ordinal, file_id,
                  repository_path_utf8, operation_kind)
                 VALUES ($1, $2, $3, $4, $5, 'create')",
                &[
                    &Uuid::from_bytes(*reversed.repository_id.as_bytes()),
                    &&reversed.publication.digest[..],
                    &(ordinal as i32),
                    &&file_id[..],
                    &path,
                ],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
    reversed
}

fn registry_first_operations(
    database_url: &str,
    fixture: &Fixture,
    shared_file_ids: [[u8; 16]; 2],
) -> Vec<i32> {
    Client::connect(database_url, NoTls)
        .unwrap()
        .query(
            "SELECT first_operation
             FROM ogvcs_metadata.file_id_registry
             WHERE repository_id = $1 AND file_id IN ($2, $3)
             ORDER BY file_id",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&shared_file_ids[0][..],
                &&shared_file_ids[1][..],
            ],
        )
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect()
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

fn advance_authority_epoch(database_url: &str, fixture: &Fixture) {
    Client::connect(database_url, NoTls)
        .unwrap()
        .execute(
            "UPDATE ogvcs_identity.authority_states
             SET authority_epoch = 2, key_generation = 2,
                 updated_at = clock_timestamp()
             WHERE tenant_id = $1",
            &[&fixture.tenant],
        )
        .unwrap();
}

fn advance_policy_generation(database_url: &str, fixture: &Fixture) {
    let next = policy_at(&fixture.tenant, &fixture.repository, 2);
    let mut client = Client::connect(database_url, NoTls).unwrap();
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
             SET policy_generation = 2, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND repository_id = $2",
            &[&fixture.tenant, &fixture.repository],
        )
        .unwrap();
    transaction.commit().unwrap();
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
                references: vec![REFERENCE.to_owned(), SECOND_REFERENCE.to_owned()],
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
                references: vec![REFERENCE.to_owned(), SECOND_REFERENCE.to_owned()],
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
                references: vec![REFERENCE.to_owned(), SECOND_REFERENCE.to_owned()],
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
    prepare_bundle_for_reference(
        database_url,
        fixture,
        participant,
        first_resource,
        resource_count,
        REFERENCE,
        ttl_seconds,
    )
}

fn prepare_bundle_for_reference(
    database_url: &str,
    fixture: &Fixture,
    participant: &PostgresAggregateAuthorizationParticipant,
    first_resource: u32,
    resource_count: u32,
    reference: &str,
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
                    reference: Some(reference),
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
    let seal_mapping = tamper_projection_at.is_none();
    persist_lifecycle_plan_for_reference_with_authority(
        database_url,
        fixture,
        bundle,
        plan_id,
        key,
        REFERENCE,
        tamper_projection_at,
        decode_hex(AUTHORIZATION_MANIFEST_SHA256),
        seal_mapping,
    )
}

fn persist_lifecycle_plan_for_reference(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    plan_id: [u8; 16],
    key: &str,
    reference: &str,
    tamper_projection_at: Option<u32>,
) -> [u8; 16] {
    let seal_mapping = tamper_projection_at.is_none();
    persist_lifecycle_plan_for_reference_with_authority(
        database_url,
        fixture,
        bundle,
        plan_id,
        key,
        reference,
        tamper_projection_at,
        decode_hex(AUTHORIZATION_MANIFEST_SHA256),
        seal_mapping,
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
    let seal_mapping = tamper_projection_at.is_none();
    persist_lifecycle_plan_for_reference_with_authority(
        database_url,
        fixture,
        bundle,
        plan_id,
        key,
        REFERENCE,
        tamper_projection_at,
        authority_contract_digest,
        seal_mapping,
    )
}

#[allow(clippy::too_many_arguments)]
fn persist_lifecycle_plan_for_reference_with_authority(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    plan_id: [u8; 16],
    key: &str,
    reference: &str,
    tamper_projection_at: Option<u32>,
    authority_contract_digest: [u8; 32],
    seal_mapping: bool,
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
        reference.to_owned(),
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
        reference.to_owned(),
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
    if seal_mapping {
        let identity_ordinals = (0..bundle.resource_count).collect::<Vec<_>>();
        store
            .seal_aggregate_identity_mapping_for_test(
                plan_id,
                bundle.receipt.plan_id(),
                &identity_ordinals,
            )
            .unwrap();
    }
    plan_id
}

fn persist_unmapped_lifecycle_plan(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    plan_id: [u8; 16],
    key: &str,
) -> [u8; 16] {
    persist_lifecycle_plan_for_reference_with_authority(
        database_url,
        fixture,
        bundle,
        plan_id,
        key,
        REFERENCE,
        None,
        decode_hex(AUTHORIZATION_MANIFEST_SHA256),
        false,
    )
}

fn persist_reversed_lifecycle_plan(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    plan_id: [u8; 16],
    key: &str,
) -> [u8; 16] {
    assert_eq!(bundle.resource_count, 3);
    let identity_ordinals = [2_u32, 1, 0];
    let mut client = Client::connect(database_url, NoTls).unwrap();
    seed_reordered_lifecycle_rows(
        &mut client,
        fixture,
        bundle.first_resource,
        &identity_ordinals,
    );
    let digests = load_resource_digest_batch(
        &mut client,
        bundle.receipt.plan_id(),
        0,
        bundle.resource_count,
    );
    let items = identity_ordinals
        .iter()
        .enumerate()
        .map(|(lifecycle_ordinal, identity_ordinal)| {
            lifecycle_item_with_object(
                bundle.first_resource + lifecycle_ordinal as u32,
                bundle.first_resource + *identity_ordinal,
                digests[*identity_ordinal as usize],
            )
        })
        .collect::<Vec<_>>();
    let chunk = AggregatePlanChunk::new(plan_id, 0, items).unwrap();
    let encoded_bytes = u64::from(chunk.encoded_bytes);
    let commitments = [AggregateChunkCommitment {
        chunk_ordinal: chunk.chunk_ordinal,
        item_count: chunk.items.len() as u16,
        encoded_bytes: chunk.encoded_bytes,
        chunk_digest: chunk.chunk_digest,
    }];
    let reservation = reservation(key, bundle.ttl_seconds);
    let subject = decode_hex(bundle.receipt.subject_digest());
    let scope = decode_hex(bundle.receipt.authenticated_scope_digest());
    let authority = decode_hex(AUTHORIZATION_MANIFEST_SHA256);
    let provisional = AggregatePublicationPlan::new_authorized(
        plan_id,
        fixture.tenant_id,
        fixture.repository_id,
        fixture.publication,
        REFERENCE.to_owned(),
        fixture.publication.to_string(),
        subject,
        bundle.receipt.authority_epoch(),
        authority,
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
        authority,
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
    writer.append_chunk(chunk).unwrap();
    assert_eq!(writer.seal().unwrap(), plan_digest);
    store
        .seal_aggregate_identity_mapping_for_test(
            plan_id,
            bundle.receipt.plan_id(),
            &identity_ordinals,
        )
        .unwrap();
    plan_id
}

fn aggregate_identity_mapping_counts(database_url: &str) -> (i64, i64) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT
                 (SELECT count(*)
                  FROM ogvcs_metadata.lifecycle_aggregate_identity_seals),
                 (SELECT count(*)
                  FROM ogvcs_metadata.lifecycle_aggregate_identity_items)",
            &[],
        )
        .unwrap();
    (row.get(0), row.get(1))
}

fn assert_aggregate_identity_mapping_immutable(database_url: &str, lifecycle_plan_id: [u8; 16]) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let plan_id = Uuid::from_bytes(lifecycle_plan_id);
    let before_row = client
        .query_one(
            "SELECT seal.mapping_digest,
                    (SELECT count(*)
                     FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS item
                     WHERE item.lifecycle_plan_id = seal.lifecycle_plan_id)
             FROM ogvcs_metadata.lifecycle_aggregate_identity_seals AS seal
             WHERE seal.lifecycle_plan_id = $1",
            &[&plan_id],
        )
        .unwrap();
    let before = (before_row.get::<_, Vec<u8>>(0), before_row.get::<_, i64>(1));
    let late_insert = client
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_aggregate_identity_items
             (lifecycle_plan_id, lifecycle_global_ordinal, identity_plan_id,
              identity_item_ordinal, object_kind, object_digest, resource_digest,
              mapping_item_digest)
             SELECT lifecycle_plan_id, 99, identity_plan_id,
                    99, object_kind, object_digest, resource_digest,
                    decode(repeat('7f', 32), 'hex')
             FROM ogvcs_metadata.lifecycle_aggregate_identity_items
             WHERE lifecycle_plan_id = $1 AND lifecycle_global_ordinal = 0",
            &[&plan_id],
        )
        .unwrap_err();
    assert_eq!(late_insert.code().map(|code| code.code()), Some("55000"));
    assert_eq!(
        late_insert.as_db_error().map(|error| error.message()),
        Some("aggregate identity mapping is sealed")
    );
    let after_late_insert = client
        .query_one(
            "SELECT seal.mapping_digest,
                    (SELECT count(*)
                     FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS item
                     WHERE item.lifecycle_plan_id = seal.lifecycle_plan_id)
             FROM ogvcs_metadata.lifecycle_aggregate_identity_seals AS seal
             WHERE seal.lifecycle_plan_id = $1",
            &[&plan_id],
        )
        .unwrap();
    assert_eq!(after_late_insert.get::<_, Vec<u8>>(0), before.0);
    assert_eq!(after_late_insert.get::<_, i64>(1), before.1);
    for statement in [
        "UPDATE ogvcs_metadata.lifecycle_aggregate_identity_seals
         SET mapping_digest = mapping_digest WHERE lifecycle_plan_id = $1",
        "DELETE FROM ogvcs_metadata.lifecycle_aggregate_identity_seals
         WHERE lifecycle_plan_id = $1",
        "UPDATE ogvcs_metadata.lifecycle_aggregate_identity_items
         SET resource_digest = resource_digest WHERE lifecycle_plan_id = $1",
        "DELETE FROM ogvcs_metadata.lifecycle_aggregate_identity_items
         WHERE lifecycle_plan_id = $1",
    ] {
        assert!(client.execute(statement, &[&plan_id]).is_err());
        let after = client
            .query_one(
                "SELECT seal.mapping_digest,
                        (SELECT count(*)
                         FROM ogvcs_metadata.lifecycle_aggregate_identity_items AS item
                         WHERE item.lifecycle_plan_id = seal.lifecycle_plan_id)
                 FROM ogvcs_metadata.lifecycle_aggregate_identity_seals AS seal
                 WHERE seal.lifecycle_plan_id = $1",
                &[&plan_id],
            )
            .unwrap();
        assert_eq!(after.get::<_, Vec<u8>>(0), before.0);
        assert_eq!(after.get::<_, i64>(1), before.1);
    }
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

fn seed_reordered_lifecycle_rows(
    client: &mut Client,
    fixture: &Fixture,
    first_resource: u32,
    identity_ordinal_by_lifecycle_ordinal: &[u32],
) {
    let lifecycle_contract = decode_hex(LIFECYCLE_CONTRACT_SHA256);
    let mut transaction = client.transaction().unwrap();
    for (lifecycle_ordinal, identity_ordinal) in
        identity_ordinal_by_lifecycle_ordinal.iter().enumerate()
    {
        let storage_index = first_resource + lifecycle_ordinal as u32;
        let object_index = first_resource + *identity_ordinal;
        let opaque = opaque_key(storage_index);
        let object = object_ref(object_index);
        let authority = receipt_digest(0xa1, storage_index);
        let backend = receipt_digest(0xb1, storage_index);
        let health = receipt_digest(0xc1, storage_index);
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_receipts
                 (receipt_digest, receipt_kind, tenant_id, repository_id, opaque_key,
                  object_kind, object_digest, expected_state, expected_generation,
                  target_state, target_generation, authority_binding_digest,
                  health_result, health_generation, lifecycle_contract_digest,
                  evidence_digest)
                 VALUES
                 ($1, 'backend-durable', $2, $3, $4, $5, $6,
                  'staged', 1, 'available', 2, $7, NULL, NULL, $8, $9),
                 ($10, 'health-observation', $2, $3, $4, $5, $6,
                  'available', 2, 'available', 2, $7, 'healthy', 1, $8, $11)",
                &[
                    &&backend[..],
                    &Uuid::from_bytes(*fixture.tenant_id.as_bytes()),
                    &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                    &&opaque[..],
                    &(object.kind.code() as i16),
                    &&object.digest[..],
                    &&authority[..],
                    &&lifecycle_contract[..],
                    &&receipt_digest(0xd1, storage_index)[..],
                    &&health[..],
                    &&receipt_digest(0xe1, storage_index)[..],
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.object_lifecycle
                 (tenant_id, repository_id, opaque_key, object_kind, object_digest,
                  object_length, tenant_scope_digest, state, generation, health,
                  health_generation, health_observation_digest, authority_binding_digest,
                  backend_receipt_digest, verification_receipt_digest,
                  deletion_receipt_digest, retention_until)
                 VALUES ($1, $2, $3, $4, $5, 1, $6, 'available', 2, 'healthy',
                         1, $7, $8, $9, NULL, NULL,
                         clock_timestamp() + interval '1 hour')",
                &[
                    &Uuid::from_bytes(*fixture.tenant_id.as_bytes()),
                    &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                    &&opaque[..],
                    &(object.kind.code() as i16),
                    &&object.digest[..],
                    &&receipt_digest(0x91, storage_index)[..],
                    &&health[..],
                    &&authority[..],
                    &&backend[..],
                ],
            )
            .unwrap();
    }
    transaction.commit().unwrap();
}

fn lifecycle_item(index: u32, resource_digest: [u8; 32]) -> LifecycleObjectBinding {
    lifecycle_item_with_object(index, index, resource_digest)
}

fn lifecycle_item_with_object(
    storage_index: u32,
    object_index: u32,
    resource_digest: [u8; 32],
) -> LifecycleObjectBinding {
    LifecycleObjectBinding {
        opaque_key: opaque_key(storage_index),
        object_ref: object_ref(object_index),
        expected_state: LifecycleState::Available,
        expected_generation: 2,
        expected_health: LifecycleHealth::Healthy,
        expected_health_generation: Some(1),
        current_health_observation_digest: Some(receipt_digest(0xc1, storage_index)),
        authority_binding_digest: receipt_digest(0xa1, storage_index),
        current_backend_receipt_digest: Some(receipt_digest(0xb1, storage_index)),
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

fn simulate_pre_v13_committed_mapping_absence(
    database_url: &str,
    lifecycle_plan: [u8; 16],
    object_count: u64,
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    // v13 deliberately leaves already committed v11/v12 applications
    // unmapped. Reproduce that migration boundary without changing durable
    // trigger configuration: the disposable superuser connection suppresses
    // origin triggers only for this session, then restores them before it is
    // dropped. ALTER TABLE cannot be used here because the deletes create
    // deferred trigger events that make re-enabling triggers in the same
    // transaction invalid on PostgreSQL 15.
    client
        .batch_execute("SET session_replication_role = replica")
        .unwrap();
    let mut transaction = client.transaction().unwrap();
    assert_eq!(
        transaction
            .execute(
                "DELETE FROM ogvcs_metadata.lifecycle_aggregate_identity_items
                 WHERE lifecycle_plan_id = $1",
                &[&Uuid::from_bytes(lifecycle_plan)],
            )
            .unwrap(),
        object_count
    );
    assert_eq!(
        transaction
            .execute(
                "DELETE FROM ogvcs_metadata.lifecycle_aggregate_identity_seals
                 WHERE lifecycle_plan_id = $1",
                &[&Uuid::from_bytes(lifecycle_plan)],
            )
            .unwrap(),
        1
    );
    transaction.commit().unwrap();
    client
        .batch_execute("SET session_replication_role = origin")
        .unwrap();
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

fn atomic_submit_state(
    database_url: &str,
    fixture: &Fixture,
    bundle: &PreparedBundle,
    lifecycle_plan: [u8; 16],
    intent_id: [u8; 16],
) -> Value {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let state: Json<Value> = client
        .query_one(
            "SELECT jsonb_build_object(
                'identityPlanState', (
                    SELECT state FROM ogvcs_identity.aggregate_plans WHERE plan_id = $1),
                'identityConsumptions', (
                    SELECT count(*) FROM ogvcs_identity.aggregate_plan_consumptions
                    WHERE plan_id = $1),
                'lifecycleApplications', (
                    SELECT count(*) FROM ogvcs_metadata.lifecycle_applications
                    WHERE plan_id = $2),
                'lifecycleFacts', (
                    SELECT count(*)
                    FROM ogvcs_metadata.lifecycle_transaction_facts AS fact
                    JOIN ogvcs_metadata.lifecycle_applications AS application
                      USING (application_id)
                    WHERE application.plan_id = $2),
                'lifecycleReachability', (
                    SELECT count(*)
                    FROM ogvcs_metadata.lifecycle_publication_reachability AS reachability
                    JOIN ogvcs_metadata.lifecycle_applications AS application
                      USING (application_id)
                    WHERE application.plan_id = $2),
                'lifecycleOutbox', (
                    SELECT count(*)
                    FROM ogvcs_metadata.lifecycle_internal_outbox AS event
                    JOIN ogvcs_metadata.lifecycle_applications AS application
                      USING (application_id)
                    WHERE application.plan_id = $2),
                'lifecycleAuthorizationEvidence', (
                    SELECT count(*)
                    FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence AS evidence
                    JOIN ogvcs_metadata.lifecycle_applications AS application
                      USING (application_id)
                    WHERE application.plan_id = $2),
                'lifecycleRows', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        encode(lifecycle.opaque_key, 'hex'), lifecycle.state,
                        lifecycle.generation, lifecycle.health,
                        lifecycle.health_generation,
                        COALESCE(lifecycle.last_application_id::text, ''),
                        lifecycle.last_commit_sequence
                    ) ORDER BY lifecycle.opaque_key), '[]'::jsonb)
                    FROM ogvcs_metadata.lifecycle_publication_plan_items AS item
                    JOIN ogvcs_metadata.lifecycle_publication_plans AS plan USING (plan_id)
                    JOIN ogvcs_metadata.object_lifecycle AS lifecycle
                      ON lifecycle.tenant_id = plan.tenant_id
                     AND lifecycle.repository_id = plan.repository_id
                     AND lifecycle.opaque_key = item.opaque_key
                    WHERE item.plan_id = $2),
                'repositoryCommitSequence', (
                    SELECT applied_sequence
                    FROM ogvcs_metadata.repository_commit_sequences
                    WHERE repository_id = $3),
                'reference', (
                    SELECT jsonb_build_array(encode(target_snapshot_digest, 'hex'),
                                             generation, commit_sequence)
                    FROM ogvcs_metadata.references
                    WHERE repository_id = $3 AND reference_kind = 'branch'
                      AND reference_name = $4),
                'allReferences', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        reference_name, encode(target_snapshot_digest, 'hex'),
                        generation, commit_sequence
                    ) ORDER BY reference_name), '[]'::jsonb)
                    FROM ogvcs_metadata.references
                    WHERE repository_id = $3 AND reference_kind = 'branch'),
                'candidateSnapshotMarker', (
                    SELECT published_commit_sequence
                    FROM ogvcs_metadata.snapshots
                    WHERE repository_id = $3 AND snapshot_digest = $5),
                'allSnapshotMarkers', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        encode(snapshot_digest, 'hex'), published_commit_sequence
                    ) ORDER BY snapshot_digest), '[]'::jsonb)
                    FROM ogvcs_metadata.snapshots
                    WHERE repository_id = $3),
                'allFileIds', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        encode(file_id, 'hex'), state::text, origin::text,
                        owner_kind::text, owner_id,
                        encode(first_change_set_digest, 'hex'), first_operation
                    ) ORDER BY file_id), '[]'::jsonb)
                    FROM ogvcs_metadata.file_id_registry
                    WHERE repository_id = $3),
                'submitIntents', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        intent_id::text, lifecycle_plan_id::text, reference_name,
                        encode(expected_head_digest, 'hex'), expected_generation,
                        encode(candidate_snapshot_digest, 'hex'),
                        encode(candidate_change_set_digest, 'hex'), operation_count,
                        encode(operation_set_digest, 'hex'), encode(intent_digest, 'hex')
                    ) ORDER BY intent_id), '[]'::jsonb)
                    FROM ogvcs_metadata.submit_intents
                    WHERE repository_id = $3),
                'submitOperations', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        intent_id::text, operation_ordinal, operation_kind,
                        encode(file_id, 'hex'), convert_from(repository_path_utf8, 'UTF8'),
                        prior_owner_kind, prior_owner_id, encode(operation_digest, 'hex')
                    ) ORDER BY intent_id, operation_ordinal), '[]'::jsonb)
                    FROM ogvcs_metadata.submit_intent_operations
                    WHERE repository_id = $3),
                'intentOperations', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        operation.operation_ordinal,
                        encode(operation.file_id, 'hex'),
                        registry.state::text, registry.origin::text,
                        registry.owner_kind::text, registry.owner_id,
                        encode(registry.first_change_set_digest, 'hex'),
                        registry.first_operation
                    ) ORDER BY operation.operation_ordinal), '[]'::jsonb)
                    FROM ogvcs_metadata.submit_intent_operations AS operation
                    JOIN ogvcs_metadata.file_id_registry AS registry
                      ON registry.repository_id = operation.repository_id
                     AND registry.file_id = operation.file_id
                    WHERE operation.intent_id = $6),
                'fileIdConsumptions', (
                    SELECT count(*) FROM ogvcs_metadata.submit_file_id_consumptions
                    WHERE intent_id = $6),
                'auditEvidence', (
                    SELECT count(*) FROM ogvcs_metadata.submit_internal_audit_evidence
                    WHERE intent_id = $6),
                'metadataOutbox', (
                    SELECT count(*) FROM ogvcs_metadata.outbox_events
                    WHERE repository_id = $3
                      AND event_type = 'internal.submit-committed-candidate'),
                'consistencyTokens', (
                    SELECT count(*) FROM ogvcs_metadata.consistency_tokens
                    WHERE repository_id = $3),
                'finalOutcomes', (
                    SELECT count(*) FROM ogvcs_metadata.submit_final_outcomes
                    WHERE intent_id = $6),
                'reconciliations', (
                    SELECT COALESCE(jsonb_agg(jsonb_build_array(
                        observed_result, encode(outcome_digest, 'hex'), authority_epoch
                    ) ORDER BY created_at, reconciliation_id), '[]'::jsonb)
                    FROM ogvcs_metadata.submit_reconciliation_records
                    WHERE intent_id = $6)
             )",
            &[
                &bundle.receipt.plan_id(),
                &Uuid::from_bytes(lifecycle_plan),
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &REFERENCE,
                &&fixture.publication.digest[..],
                &Uuid::from_bytes(intent_id),
            ],
        )
        .unwrap()
        .get(0);
    state.0
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
