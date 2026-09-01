use std::{collections::BTreeMap, env};

use ogvcs_identity_policy_audit_postgres::{
    run_migrations as run_identity_migrations, CredentialScope,
    MigrationRunOptions as IdentityMigrationRunOptions, PolicyDocument, PolicyRule,
    PostgresTransactionAuthorizationParticipant, RuleSubjects,
};
use ogvcs_object_model::{ObjectKind, ObjectRef};
use ogvcs_repository_metadata::{
    run_migrations as run_metadata_migrations, ContentManifestAvailabilityCommitRequest,
    ContentManifestAvailabilityFaultForTest, ContentManifestAvailabilityReconciliation,
    ContentManifestCommittedProofLookup, ContentManifestDependencyBinding,
    ContentManifestExplicitAuthority, ContentManifestProductionStatement, DomainErrorCode,
    IdentityBoundPostgresMetadataStore, MigrationRunOptions as MetadataMigrationRunOptions,
    RepositoryId, TenantId, TransactionCredentialRequest, CONTENT_MANIFEST_PRODUCTION_BOUNDARY,
    CONTENT_MANIFEST_PRODUCTION_PROFILE, CONTENT_MANIFEST_PRODUCTION_VERIFIER,
    LIFECYCLE_CONTRACT_SHA256,
};
use postgres::{types::Json, Client, NoTls};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const PRESENTATION: &str = "content-manifest-production-credential";
const PRESENTATION_V2: &str = "content-manifest-production-credential-v2";
const AUTHORIZATION_CLOSURE_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-AUTHORIZATION-CLOSURE-V1\0";
const DEPENDENCY_GENERATIONS_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-DEPENDENCY-GENERATIONS-V1\0";
const PRODUCTION_STATEMENT_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-PRODUCTION-V1\0";
const LIFECYCLE_VERIFICATION_RECEIPT_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-LIFECYCLE-VERIFICATION-RECEIPT-V1\0";

#[test]
fn explicit_set_availability_is_atomic_replayable_and_page_bounded() {
    let Ok(database_url) = env::var("OGVCS_METADATA_OBJECT_TRANSFER_DATABASE_URL") else {
        eprintln!("skipped content-manifest PostgreSQL conformance: database URL is unset");
        return;
    };
    let tenant_id = TenantId::from_bytes(public_uuid(0x11));
    let small_repository = RepositoryId::from_bytes(public_uuid(0x22));
    let maximum_repository = RepositoryId::from_bytes(public_uuid(0x33));
    let wrong_backend_repository = RepositoryId::from_bytes(public_uuid(0x44));
    let wrong_verification_repository = RepositoryId::from_bytes(public_uuid(0x55));
    let wrong_shared_contract_repository = RepositoryId::from_bytes(public_uuid(0x66));
    prepare_database(
        &database_url,
        tenant_id,
        &[
            small_repository,
            maximum_repository,
            wrong_backend_repository,
            wrong_verification_repository,
            wrong_shared_contract_repository,
        ],
    );
    let identity_subject_digest = identity_subject_digest("subject.content-manifest");
    let small = seed_fixture(
        &database_url,
        tenant_id,
        small_repository,
        identity_subject_digest,
        2,
        0x41,
    );
    let wrong_backend = seed_fixture_with_receipt_contracts(
        &database_url,
        tenant_id,
        wrong_backend_repository,
        identity_subject_digest,
        1,
        0x51,
        [0x51; 32],
        lifecycle_contract_digest(),
    );
    let wrong_verification = seed_fixture_with_receipt_contracts(
        &database_url,
        tenant_id,
        wrong_verification_repository,
        identity_subject_digest,
        1,
        0x52,
        lifecycle_contract_digest(),
        [0x52; 32],
    );
    let wrong_shared_contract = seed_fixture_with_receipt_contracts(
        &database_url,
        tenant_id,
        wrong_shared_contract_repository,
        identity_subject_digest,
        1,
        0x53,
        [0x53; 32],
        [0x53; 32],
    );

    let mut store = IdentityBoundPostgresMetadataStore::connect(
        &database_url,
        PostgresTransactionAuthorizationParticipant::new().unwrap(),
    )
    .unwrap();

    let unknown = store
        .reconcile_content_manifest_availability(
            wrong_backend.lookup(PRESENTATION, "request.unknown-observation"),
        )
        .unwrap();
    let ContentManifestAvailabilityReconciliation::UnknownRecovering {
        observation_digest: unknown_digest,
    } = unknown
    else {
        panic!("an uncommitted authorized lookup must remain unknown")
    };
    let mut distinct_unknown =
        wrong_backend.lookup(PRESENTATION, "request.distinct-unknown-observation");
    distinct_unknown.authority.production_subject_digest[0] ^= 0x80;
    let ContentManifestAvailabilityReconciliation::UnknownRecovering {
        observation_digest: distinct_digest,
    } = store
        .reconcile_content_manifest_availability(distinct_unknown)
        .unwrap()
    else {
        panic!("a distinct uncommitted authorized lookup must remain unknown")
    };
    assert_ne!(unknown_digest, distinct_digest);

    assert_eq!(
        store
            .commit_content_manifest_availability(
                wrong_backend.request(PRESENTATION, "request.wrong-backend-contract"),
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &wrong_backend, 0);
    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                wrong_backend.request(PRESENTATION, "request.sql-contract-fence"),
                ContentManifestAvailabilityFaultForTest::WrongReceiptContractAtSqlProofBoundary,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "the deferred v12 proof trigger rejects a wrong receipt contract even when a hostile test writer bypasses the runtime check"
    );
    assert_old(&database_url, &wrong_backend, 0);
    assert_eq!(
        store
            .commit_content_manifest_availability(
                wrong_verification.request(PRESENTATION, "request.wrong-verification-contract"),
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &wrong_verification, 0);
    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                wrong_shared_contract.request(PRESENTATION, "request.sql-shared-contract-fence"),
                ContentManifestAvailabilityFaultForTest::WrongSharedContractAtSqlProofBoundary,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "the deferred v12 proof trigger pins the current lifecycle contract even when the application and both receipts share one wrong digest"
    );
    assert_old(&database_url, &wrong_shared_contract, 0);

    let mut forged_receipt_binding = small.request(PRESENTATION, "request.forged-receipt-binding");
    forged_receipt_binding.verification_receipt_digest[0] ^= 0x80;
    assert_eq!(
        store
            .commit_content_manifest_availability(forged_receipt_binding)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &small, 0);
    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                small.request(PRESENTATION, "request.sql-tenant-scope-fence"),
                ContentManifestAvailabilityFaultForTest::WrongTenantScopeAtSqlProofBoundary,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "the deferred v12 proof trigger rejects proof tenant scope that differs from the current lifecycle row"
    );
    assert_old(&database_url, &small, 0);
    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                small.request(PRESENTATION, "request.sql-fact-outbox-fence"),
                ContentManifestAvailabilityFaultForTest::WrongFactOutboxAtSqlProofBoundary,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "the deferred v12 proof trigger rejects a fact that names a different outbox event"
    );
    assert_old(&database_url, &small, 0);
    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                small.request(PRESENTATION, "request.sql-receipt-binding-fence"),
                ContentManifestAvailabilityFaultForTest::WrongReceiptBindingAtSqlProofBoundary,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "the deferred v12 proof trigger independently recomputes the lifecycle-bound receipt"
    );
    assert_old(&database_url, &small, 0);

    let bad_credential = small.request("not-the-credential", "request.bad-credential");
    assert_eq!(
        store
            .commit_content_manifest_availability(bad_credential)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &small, 0);

    let mut forged_identity_subject =
        small.request(PRESENTATION, "request.forged-identity-subject");
    forged_identity_subject.authority.identity_subject_digest[0] ^= 0x80;
    assert_eq!(
        store
            .commit_content_manifest_availability(forged_identity_subject)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &small, 0);

    let mut unsorted_set = small.object_set.clone();
    unsorted_set.swap(0, 1);
    let mut unsorted = small.request(PRESENTATION, "request.unsorted");
    unsorted.authority.object_set = &unsorted_set;
    unsorted.authority.authorization_closure_digest = authorization_closure(&unsorted_set);
    assert_eq!(
        store
            .commit_content_manifest_availability(unsorted)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &small, 0);

    let mut stale_dependencies = small.dependencies.clone();
    stale_dependencies[0].generation += 1;
    let stale_digest =
        dependency_generation_digest(tenant_id, small_repository, &stale_dependencies);
    let mut stale = small.request(PRESENTATION, "request.stale-generation");
    stale.dependencies = &stale_dependencies;
    stale.dependency_generation_set_digest = stale_digest;
    assert_eq!(
        store
            .commit_content_manifest_availability(stale)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_old(&database_url, &small, 0);

    let missing_ref = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: [0xfd; 32],
    };
    let mut missing_dependencies = small.dependencies.clone();
    missing_dependencies[0] = ContentManifestDependencyBinding {
        opaque_key: [0xfc; 32],
        object_ref: missing_ref,
        length: 19,
        generation: 1,
        authority_binding_digest: [0xfb; 32],
        backend_receipt_digest: [0xfa; 32],
    };
    missing_dependencies.sort_by_key(|dependency| dependency.opaque_key);
    let mut missing_set = missing_dependencies
        .iter()
        .map(|dependency| dependency.object_ref)
        .chain(std::iter::once(small.manifest))
        .collect::<Vec<_>>();
    missing_set.sort_by_key(ToString::to_string);
    let mut missing = small.request(PRESENTATION, "request.missing-object");
    missing.authority.object_set = &missing_set;
    missing.authority.authorization_closure_digest = authorization_closure(&missing_set);
    missing.dependencies = &missing_dependencies;
    missing.dependency_generation_set_digest =
        dependency_generation_digest(tenant_id, small_repository, &missing_dependencies);
    assert_eq!(
        store
            .commit_content_manifest_availability(missing)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "an authorized missing object has the same closed error as denied authority"
    );
    assert_old(&database_url, &small, 0);

    for boundary in [
        ContentManifestAvailabilityFaultForTest::AfterAuthority,
        ContentManifestAvailabilityFaultForTest::AfterApplication,
        ContentManifestAvailabilityFaultForTest::AfterReceiptConsumption,
        ContentManifestAvailabilityFaultForTest::AfterLifecycleCas,
        ContentManifestAvailabilityFaultForTest::AfterFact,
        ContentManifestAvailabilityFaultForTest::AfterProof,
        ContentManifestAvailabilityFaultForTest::BeforeCommit,
    ] {
        assert_eq!(
            store
                .commit_content_manifest_availability_with_fault_for_test(
                    small.request(PRESENTATION, "request.precommit-fault"),
                    boundary,
                )
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied,
            "fault {boundary:?} must fail closed"
        );
        assert_old(&database_url, &small, 0);
    }

    {
        let mut transaction = store
            .begin_content_manifest_availability_transaction()
            .unwrap();
        let proof = transaction
            .apply(&small.request(PRESENTATION, "request.caller-owned-rollback"))
            .unwrap();
        assert!(!proof.replayed());
        transaction.rollback().unwrap();
    }
    assert_old(&database_url, &small, 0);

    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                small.request(PRESENTATION, "request.response-loss"),
                ContentManifestAvailabilityFaultForTest::AfterCommitResponse,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_committed(&database_url, &small, 1, 3);

    let reconciled = store
        .reconcile_content_manifest_availability(
            small.lookup(PRESENTATION, "request.reconcile-response-loss"),
        )
        .unwrap();
    let ContentManifestAvailabilityReconciliation::Committed(reconciled) = reconciled else {
        panic!("durable response-loss commit must reconcile as committed")
    };
    assert!(reconciled.replayed());
    assert_eq!(reconciled.dependency_count(), 2);

    let replay = store
        .commit_content_manifest_availability(small.request(PRESENTATION, "request.exact-replay"))
        .unwrap();
    assert!(replay.replayed());
    assert_eq!(replay, *reconciled);
    assert_committed(&database_url, &small, 1, 3);

    let mut wrong_generation_replay =
        small.request(PRESENTATION, "request.wrong-settled-generation");
    wrong_generation_replay.expected_generation = 2;
    assert_eq!(
        store
            .commit_content_manifest_availability(wrong_generation_replay)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_committed(&database_url, &small, 1, 3);

    {
        let mut transaction = store
            .begin_content_manifest_availability_transaction()
            .unwrap();
        let participant_replay = transaction
            .apply(&small.request(PRESENTATION, "request.participant-replay"))
            .unwrap();
        assert_eq!(participant_replay, replay);
        transaction.commit().unwrap();
    }
    assert_committed(&database_url, &small, 1, 3);

    let mut forged_lookup = small.lookup(PRESENTATION, "request.forged-lookup");
    forged_lookup.backend_receipt_digest[0] ^= 0x80;
    assert_eq!(
        store
            .reconcile_content_manifest_availability(forged_lookup)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let mut forged_production_subject =
        small.lookup(PRESENTATION, "request.forged-production-subject");
    forged_production_subject
        .authority
        .production_subject_digest[0] ^= 0x80;
    assert_eq!(
        store
            .reconcile_content_manifest_availability(forged_production_subject)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let mut forged_epoch_replay = small.request(PRESENTATION, "request.forged-epoch-replay");
    forged_epoch_replay.authority.authority_epoch = 2;
    assert_eq!(
        store
            .commit_content_manifest_availability(forged_epoch_replay)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    let mut forged_epoch_lookup = small.lookup(PRESENTATION, "request.forged-epoch-lookup");
    forged_epoch_lookup.authority.authority_epoch = 2;
    assert_eq!(
        store
            .reconcile_content_manifest_availability(forged_epoch_lookup)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_committed(&database_url, &small, 1, 3);

    assert_immutable(&database_url, &small);

    let mut lifecycle_client = Client::connect(&database_url, NoTls).unwrap();
    let mut drifted_tenant_scope = small.tenant_scope_digest;
    drifted_tenant_scope[0] ^= 0x80;
    assert_eq!(
        lifecycle_client
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle
                 SET tenant_scope_digest = $3
                 WHERE repository_id = $1 AND opaque_key = $2",
                &[
                    &Uuid::from_bytes(*small.repository_id.as_bytes()),
                    &&small.manifest_opaque_key[..],
                    &&drifted_tenant_scope[..],
                ],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        store
            .reconcile_content_manifest_availability(
                small.lookup(PRESENTATION, "request.drifted-tenant-scope"),
            )
            .unwrap(),
        ContentManifestAvailabilityReconciliation::UnknownRecovering { .. }
    ));
    assert_eq!(
        lifecycle_client
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle
                 SET tenant_scope_digest = $3
                 WHERE repository_id = $1 AND opaque_key = $2",
                &[
                    &Uuid::from_bytes(*small.repository_id.as_bytes()),
                    &&small.manifest_opaque_key[..],
                    &&small.tenant_scope_digest[..],
                ],
            )
            .unwrap(),
        1
    );
    assert_eq!(
        lifecycle_client
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle
                 SET object_length = $3
                 WHERE repository_id = $1 AND opaque_key = $2",
                &[
                    &Uuid::from_bytes(*small.repository_id.as_bytes()),
                    &&small.manifest_opaque_key[..],
                    &((small.manifest_length + 1) as i64),
                ],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        store
            .reconcile_content_manifest_availability(
                small.lookup(PRESENTATION, "request.drifted-object-length"),
            )
            .unwrap(),
        ContentManifestAvailabilityReconciliation::UnknownRecovering { .. }
    ));
    assert_eq!(
        lifecycle_client
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle
                 SET object_length = $3
                 WHERE repository_id = $1 AND opaque_key = $2",
                &[
                    &Uuid::from_bytes(*small.repository_id.as_bytes()),
                    &&small.manifest_opaque_key[..],
                    &(small.manifest_length as i64),
                ],
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        store
            .reconcile_content_manifest_availability(
                small.lookup(PRESENTATION, "request.restored-current-lifecycle"),
            )
            .unwrap(),
        ContentManifestAvailabilityReconciliation::Committed(_)
    ));

    let maximum = seed_fixture(
        &database_url,
        tenant_id,
        maximum_repository,
        identity_subject_digest,
        4_095,
        0x61,
    );
    assert_eq!(
        store
            .commit_content_manifest_availability_with_fault_for_test(
                maximum.request(PRESENTATION, "request.noncanonical-page-split"),
                ContentManifestAvailabilityFaultForTest::NonCanonicalPageSplitAtSqlProofBoundary,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "the deferred v12 proof trigger rejects a non-canonical authorization-page split"
    );
    assert_old(&database_url, &maximum, 1);
    let maximum_proof = store
        .commit_content_manifest_availability(
            maximum.request(PRESENTATION, "request.maximum-explicit-set"),
        )
        .unwrap();
    assert_eq!(maximum_proof.dependency_count(), 4_095);
    assert_committed(&database_url, &maximum, 5, 4_096);

    promote_authority_epoch(
        &database_url,
        tenant_id,
        &[
            small_repository,
            maximum_repository,
            wrong_backend_repository,
            wrong_verification_repository,
            wrong_shared_contract_repository,
        ],
    );
    let mut changed_epoch_replay = small.request(PRESENTATION_V2, "request.changed-epoch-replay");
    changed_epoch_replay.authority.authority_epoch = 2;
    assert_eq!(
        store
            .commit_content_manifest_availability(changed_epoch_replay)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "a newly authorized epoch cannot replay an epoch-one settled proof"
    );
    let mut changed_epoch_lookup = small.lookup(PRESENTATION_V2, "request.changed-epoch-lookup");
    changed_epoch_lookup.authority.authority_epoch = 2;
    assert_eq!(
        store
            .reconcile_content_manifest_availability(changed_epoch_lookup)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "reconciliation binds the settled proof to its accepted authority epoch"
    );
    assert_committed(&database_url, &small, 1, 3);
}

struct Fixture {
    tenant_id: TenantId,
    repository_id: RepositoryId,
    identity_subject_digest: [u8; 32],
    production_subject_digest: [u8; 32],
    tenant_scope_digest: [u8; 32],
    manifest_opaque_key: [u8; 32],
    manifest: ObjectRef,
    manifest_length: u64,
    authority_binding_digest: [u8; 32],
    backend_receipt_digest: [u8; 32],
    verification_receipt_digest: [u8; 32],
    finalize_semantic_fingerprint: [u8; 32],
    dependencies: Vec<ContentManifestDependencyBinding>,
    dependency_generation_set_digest: [u8; 32],
    object_set: Vec<ObjectRef>,
    authorization_closure_digest: [u8; 32],
    statement: ContentManifestProductionStatement,
}

impl Fixture {
    fn authority<'a>(
        &'a self,
        presentation: &'a str,
        request_id: &'a str,
    ) -> ContentManifestExplicitAuthority<'a> {
        ContentManifestExplicitAuthority {
            credentials: TransactionCredentialRequest {
                request_id,
                correlation_id: request_id,
                credential_presentation: presentation,
                reason: Some("bounded explicit-object-set conformance"),
            },
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            object_set: &self.object_set,
            identity_subject_digest: self.identity_subject_digest,
            production_subject_digest: self.production_subject_digest,
            authority_epoch: 1,
            authorization_closure_digest: self.authorization_closure_digest,
            tenant_scope_digest: self.tenant_scope_digest,
        }
    }

    fn request<'a>(
        &'a self,
        presentation: &'a str,
        request_id: &'a str,
    ) -> ContentManifestAvailabilityCommitRequest<'a> {
        ContentManifestAvailabilityCommitRequest {
            authority: self.authority(presentation, request_id),
            opaque_key: self.manifest_opaque_key,
            object_ref: self.manifest,
            length: self.manifest_length,
            expected_generation: 1,
            authority_binding_digest: self.authority_binding_digest,
            backend_receipt_digest: self.backend_receipt_digest,
            verification_receipt_digest: self.verification_receipt_digest,
            finalize_semantic_fingerprint: self.finalize_semantic_fingerprint,
            dependencies: &self.dependencies,
            dependency_generation_set_digest: self.dependency_generation_set_digest,
            production_statement: self.statement.clone(),
        }
    }

    fn lookup<'a>(
        &'a self,
        presentation: &'a str,
        request_id: &'a str,
    ) -> ContentManifestCommittedProofLookup<'a> {
        ContentManifestCommittedProofLookup {
            authority: self.authority(presentation, request_id),
            opaque_key: self.manifest_opaque_key,
            object_ref: self.manifest,
            length: self.manifest_length,
            authority_binding_digest: self.authority_binding_digest,
            backend_receipt_digest: self.backend_receipt_digest,
            finalize_semantic_fingerprint: self.finalize_semantic_fingerprint,
        }
    }
}

fn prepare_database(database_url: &str, tenant_id: TenantId, repositories: &[RepositoryId]) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
    assert!(
        database.starts_with("ogvcs_metadata_test_"),
        "live object-transfer test refuses non-disposable database {database:?}"
    );
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

    let tenant = identity_tenant(tenant_id);
    client
        .execute(
            "INSERT INTO ogvcs_identity.authority_states
             (tenant_id, authority_epoch, key_generation) VALUES ($1, 1, 1)",
            &[&tenant],
        )
        .unwrap();
    for (index, repository_id) in repositories.iter().enumerate() {
        let repository_uuid = Uuid::from_bytes(*repository_id.as_bytes());
        client
            .execute(
                "INSERT INTO ogvcs_metadata.repositories
                 (repository_id, tenant_id, project_id) VALUES ($1, $2, $3)",
                &[
                    &repository_uuid,
                    &Uuid::from_bytes(*tenant_id.as_bytes()),
                    &Uuid::from_bytes(public_uuid(0x80 + index as u8)),
                ],
            )
            .unwrap();
        client
            .execute(
                "INSERT INTO ogvcs_metadata.repository_commit_sequences (repository_id)
                 VALUES ($1)",
                &[&repository_uuid],
            )
            .unwrap();
        seed_policy(&mut client, &tenant, &identity_repository(*repository_id));
    }
    seed_credential(&mut client, &tenant, repositories);
}

fn seed_policy(client: &mut Client, tenant: &str, repository: &str) {
    let policy = PolicyDocument {
        schema_version: "ogvcs.identity-policy/policy/v1".to_owned(),
        id: format!("policy.{repository}"),
        version: "version.one".to_owned(),
        generation: 1,
        authority_epoch: 1,
        path_profile: "path.opengamevcs/portable@1".to_owned(),
        case_mode: "case-sensitive".to_owned(),
        default_effect: "deny".to_owned(),
        composition: "deny-overrides-v1".to_owned(),
        rules: vec![PolicyRule {
            id: "allow.content-upload".to_owned(),
            effect: "allow".to_owned(),
            subjects: RuleSubjects {
                identities: vec!["subject.content-manifest".to_owned()],
                groups: Vec::new(),
                actor_classes: Vec::new(),
            },
            tenant: tenant.to_owned(),
            repository: repository.to_owned(),
            references: Vec::new(),
            path_prefixes: Vec::new(),
            resource_types: vec!["content".to_owned()],
            permissions: vec!["content.upload".to_owned()],
        }],
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
}

fn seed_credential(client: &mut Client, tenant: &str, repositories: &[RepositoryId]) {
    let scope = CredentialScope {
        tenants: vec![tenant.to_owned()],
        repositories: repositories
            .iter()
            .map(|repository| identity_repository(*repository))
            .collect(),
        references: Vec::new(),
        path_prefixes: Vec::new(),
        permissions: vec!["content.upload".to_owned()],
    };
    let presentation_digest =
        digest_parts(&[b"OGVCS-IDENTITY-CREDENTIAL-V1\0", PRESENTATION.as_bytes()]);
    let subject_digest = identity_subject_digest("subject.content-manifest");
    let scope_digest = digest_json(&scope);
    client
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation, presentation_digest,
              subject_id, subject_digest, actor_class, credential_class, groups_json,
              authority_epoch, issued_at, expires_at, state, scope_json, scope_digest)
             VALUES ($1, 'credential.content-manifest', 1, $2,
                     'subject.content-manifest', $3, 'service', 'service-token',
                     '[]'::jsonb, 1, clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '30 minutes', 'active', $4, $5)",
            &[
                &tenant,
                &&presentation_digest[..],
                &&subject_digest[..],
                &Json(&scope),
                &&scope_digest[..],
            ],
        )
        .unwrap();
}

fn promote_authority_epoch(database_url: &str, tenant_id: TenantId, repositories: &[RepositoryId]) {
    let tenant = identity_tenant(tenant_id);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    transaction
        .execute(
            "UPDATE ogvcs_identity.authority_states
             SET authority_epoch = 2, key_generation = 2, updated_at = clock_timestamp()
             WHERE tenant_id = $1",
            &[&tenant],
        )
        .unwrap();
    for repository_id in repositories {
        let repository = identity_repository(*repository_id);
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
    }
    let scope = CredentialScope {
        tenants: vec![tenant.clone()],
        repositories: repositories
            .iter()
            .map(|repository| identity_repository(*repository))
            .collect(),
        references: Vec::new(),
        path_prefixes: Vec::new(),
        permissions: vec!["content.upload".to_owned()],
    };
    let presentation_digest = digest_parts(&[
        b"OGVCS-IDENTITY-CREDENTIAL-V1\0",
        PRESENTATION_V2.as_bytes(),
    ]);
    let subject_digest = identity_subject_digest("subject.content-manifest");
    let scope_digest = digest_json(&scope);
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.credentials
             (tenant_id, credential_id, credential_generation, presentation_digest,
              subject_id, subject_digest, actor_class, credential_class, groups_json,
              authority_epoch, issued_at, expires_at, state, scope_json, scope_digest)
             VALUES ($1, 'credential.content-manifest-v2', 2, $2,
                     'subject.content-manifest', $3, 'service', 'service-token',
                     '[]'::jsonb, 2, clock_timestamp() - interval '1 minute',
                     clock_timestamp() + interval '30 minutes', 'active', $4, $5)",
            &[
                &tenant,
                &&presentation_digest[..],
                &&subject_digest[..],
                &Json(&scope),
                &&scope_digest[..],
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn seed_fixture(
    database_url: &str,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    identity_subject_digest: [u8; 32],
    dependency_count: usize,
    seed: u8,
) -> Fixture {
    seed_fixture_with_receipt_contracts(
        database_url,
        tenant_id,
        repository_id,
        identity_subject_digest,
        dependency_count,
        seed,
        lifecycle_contract_digest(),
        lifecycle_contract_digest(),
    )
}

#[allow(clippy::too_many_arguments)]
fn seed_fixture_with_receipt_contracts(
    database_url: &str,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    identity_subject_digest: [u8; 32],
    dependency_count: usize,
    seed: u8,
    backend_contract_digest: [u8; 32],
    verification_contract_digest: [u8; 32],
) -> Fixture {
    let tenant_scope_digest = digest_parts(&[b"tenant-scope", &[seed]]);
    let manifest_opaque_key = digest_parts(&[b"manifest-opaque", &[seed]]);
    let manifest = ObjectRef {
        kind: ObjectKind::ContentManifest,
        digest: digest_parts(&[b"manifest-object", &[seed]]),
    };
    let manifest_length = 321;
    let authority_binding_digest = digest_parts(&[b"manifest-authority", &[seed]]);
    let backend_receipt_digest = digest_parts(&[b"manifest-backend", &[seed]]);
    let finalize_semantic_fingerprint = digest_parts(&[b"manifest-finalize", &[seed]]);
    let statement = ContentManifestProductionStatement {
        boundary: CONTENT_MANIFEST_PRODUCTION_BOUNDARY.to_owned(),
        logical_bytes: dependency_count as u64 * 64,
        manifest_object_id: manifest,
        manifest_sha256: digest_parts(&[b"manifest-bytes-sha", &[seed]]),
        profile: CONTENT_MANIFEST_PRODUCTION_PROFILE.to_owned(),
        verifier: CONTENT_MANIFEST_PRODUCTION_VERIFIER.to_owned(),
        whole_file_sha256: digest_parts(&[b"whole-file", &[seed]]),
    };
    let verification_receipt_digest = lifecycle_verification_receipt_digest(
        tenant_id,
        repository_id,
        manifest_opaque_key,
        manifest,
        1,
        authority_binding_digest,
        production_statement_digest(&statement),
    );
    let mut dependencies = (0..dependency_count)
        .map(|index| {
            let index = (index as u32).to_be_bytes();
            ContentManifestDependencyBinding {
                opaque_key: digest_parts(&[b"dependency-opaque", &[seed], &index]),
                object_ref: ObjectRef {
                    kind: ObjectKind::Chunk,
                    digest: digest_parts(&[b"dependency-object", &[seed], &index]),
                },
                length: 64,
                generation: 2,
                authority_binding_digest: digest_parts(&[b"dependency-authority", &[seed], &index]),
                backend_receipt_digest: digest_parts(&[b"dependency-backend", &[seed], &index]),
            }
        })
        .collect::<Vec<_>>();
    dependencies.sort_by_key(|dependency| dependency.opaque_key);
    let dependency_generation_set_digest =
        dependency_generation_digest(tenant_id, repository_id, &dependencies);
    let mut object_set = dependencies
        .iter()
        .map(|dependency| dependency.object_ref)
        .chain(std::iter::once(manifest))
        .collect::<Vec<_>>();
    object_set.sort_by_key(ToString::to_string);
    let authorization_closure_digest = authorization_closure(&object_set);

    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    let receipt_digests = dependencies
        .iter()
        .map(|dependency| dependency.backend_receipt_digest.to_vec())
        .collect::<Vec<_>>();
    let opaque_keys = dependencies
        .iter()
        .map(|dependency| dependency.opaque_key.to_vec())
        .collect::<Vec<_>>();
    let object_digests = dependencies
        .iter()
        .map(|dependency| dependency.object_ref.digest.to_vec())
        .collect::<Vec<_>>();
    let lengths = dependencies
        .iter()
        .map(|dependency| dependency.length as i64)
        .collect::<Vec<_>>();
    let authority_bindings = dependencies
        .iter()
        .map(|dependency| dependency.authority_binding_digest.to_vec())
        .collect::<Vec<_>>();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_receipts
             (receipt_digest, receipt_kind, tenant_id, repository_id, opaque_key,
              object_kind, object_digest, expected_state, expected_generation,
              target_state, target_generation, authority_binding_digest,
              lifecycle_contract_digest, evidence_digest)
             SELECT input.receipt, 'backend-durable', $1, $2, input.opaque_key,
                    1, input.object_digest, 'staged', 1, 'available', 2,
                    input.authority_binding, $3, input.receipt
             FROM unnest($4::bytea[], $5::bytea[], $6::bytea[], $7::bytea[])
                  AS input(receipt, opaque_key, object_digest, authority_binding)",
            &[
                &Uuid::from_bytes(*tenant_id.as_bytes()),
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&lifecycle_contract_digest()[..],
                &receipt_digests,
                &opaque_keys,
                &object_digests,
                &authority_bindings,
            ],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.object_lifecycle
             (tenant_id, repository_id, opaque_key, object_kind, object_digest,
              object_length, tenant_scope_digest, state, generation, health,
              authority_binding_digest, backend_receipt_digest, retention_until)
             SELECT $1, $2, input.opaque_key, 1, input.object_digest, input.length,
                    $3, 'available', 2, 'not-applicable', input.authority_binding,
                    input.receipt, clock_timestamp() + interval '1 day'
             FROM unnest($4::bytea[], $5::bytea[], $6::bigint[], $7::bytea[], $8::bytea[])
                  AS input(opaque_key, object_digest, length, authority_binding, receipt)",
            &[
                &Uuid::from_bytes(*tenant_id.as_bytes()),
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&tenant_scope_digest[..],
                &opaque_keys,
                &object_digests,
                &lengths,
                &authority_bindings,
                &receipt_digests,
            ],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.object_lifecycle
             (tenant_id, repository_id, opaque_key, object_kind, object_digest,
              object_length, tenant_scope_digest, state, generation, health,
              authority_binding_digest, retention_until)
             VALUES ($1, $2, $3, 2, $4, $5, $6, 'staged', 1,
                     'not-applicable', $7, clock_timestamp() + interval '1 day')",
            &[
                &Uuid::from_bytes(*tenant_id.as_bytes()),
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&manifest_opaque_key[..],
                &&manifest.digest[..],
                &(manifest_length as i64),
                &&tenant_scope_digest[..],
                &&authority_binding_digest[..],
            ],
        )
        .unwrap();
    for (kind, receipt, contract_digest) in [
        (
            "backend-durable",
            backend_receipt_digest,
            backend_contract_digest,
        ),
        (
            "production-verification",
            verification_receipt_digest,
            verification_contract_digest,
        ),
    ] {
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.lifecycle_receipts
                 (receipt_digest, receipt_kind, tenant_id, repository_id, opaque_key,
                  object_kind, object_digest, expected_state, expected_generation,
                  target_state, target_generation, authority_binding_digest,
                  lifecycle_contract_digest, evidence_digest)
                 VALUES ($1, $2, $3, $4, $5, 2, $6, 'staged', 1,
                         'available', 2, $7, $8, $9)",
                &[
                    &&receipt[..],
                    &kind,
                    &Uuid::from_bytes(*tenant_id.as_bytes()),
                    &Uuid::from_bytes(*repository_id.as_bytes()),
                    &&manifest_opaque_key[..],
                    &&manifest.digest[..],
                    &&authority_binding_digest[..],
                    &&contract_digest[..],
                    &&receipt[..],
                ],
            )
            .unwrap();
    }
    transaction.commit().unwrap();

    Fixture {
        tenant_id,
        repository_id,
        identity_subject_digest,
        production_subject_digest: production_subject_digest("auth.example", "artist-one"),
        tenant_scope_digest,
        manifest_opaque_key,
        manifest,
        manifest_length,
        authority_binding_digest,
        backend_receipt_digest,
        verification_receipt_digest,
        finalize_semantic_fingerprint,
        dependencies,
        dependency_generation_set_digest,
        object_set,
        authorization_closure_digest,
        statement,
    }
}

fn assert_old(database_url: &str, fixture: &Fixture, expected_decisions: i64) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let lifecycle: (String, i64, bool, bool, bool) = client
        .query_one(
            "SELECT state, generation, backend_receipt_digest IS NULL,
                    verification_receipt_digest IS NULL, last_application_id IS NULL
             FROM ogvcs_metadata.object_lifecycle
             WHERE repository_id = $1 AND opaque_key = $2",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.manifest_opaque_key[..],
            ],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        .unwrap();
    assert_eq!(lifecycle, ("staged".to_owned(), 1, true, true, true));
    let counts = transaction_counts(&mut client, fixture);
    assert_eq!(counts, (0, 0, 0, 0, 0, 0, 0));
    let decisions: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_identity.transaction_decision_commitments
             WHERE tenant_id = $1",
            &[&identity_tenant(fixture.tenant_id)],
        )
        .unwrap()
        .get(0);
    assert_eq!(decisions, expected_decisions);
}

fn assert_committed(
    database_url: &str,
    fixture: &Fixture,
    expected_pages: i64,
    expected_resources: i64,
) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let lifecycle: (String, i64, Vec<u8>, Vec<u8>) = client
        .query_one(
            "SELECT state, generation, backend_receipt_digest,
                    verification_receipt_digest
             FROM ogvcs_metadata.object_lifecycle
             WHERE repository_id = $1 AND opaque_key = $2",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.manifest_opaque_key[..],
            ],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(lifecycle.0, "available");
    assert_eq!(lifecycle.1, 2);
    assert_eq!(lifecycle.2, fixture.backend_receipt_digest);
    assert_eq!(lifecycle.3, fixture.verification_receipt_digest);
    assert_eq!(
        transaction_counts(&mut client, fixture),
        (1, 1, 1, 1, 1, expected_pages, 1)
    );
    let pages: (i64, i64, i64, i64) = client
        .query_one(
            "SELECT count(*), COALESCE(sum(resource_count), 0),
                    min(page_ordinal)::bigint, max(page_ordinal)::bigint
             FROM ogvcs_metadata.content_manifest_availability_authorization_pages
             WHERE application_id = (
               SELECT application_id
               FROM ogvcs_metadata.content_manifest_availability_proofs
               WHERE repository_id = $1 AND opaque_key = $2)",
            &[
                &Uuid::from_bytes(*fixture.repository_id.as_bytes()),
                &&fixture.manifest_opaque_key[..],
            ],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(pages.0, expected_pages);
    assert_eq!(pages.1, expected_resources);
    assert_eq!(pages.2, 0);
    assert_eq!(pages.3, expected_pages - 1);
}

fn transaction_counts(
    client: &mut Client,
    fixture: &Fixture,
) -> (i64, i64, i64, i64, i64, i64, i64) {
    client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_applications
                WHERE repository_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_receipt_consumptions
                WHERE repository_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_transaction_facts AS fact
                JOIN ogvcs_metadata.lifecycle_applications AS application USING (application_id)
                WHERE application.repository_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_internal_outbox AS outbox
                JOIN ogvcs_metadata.lifecycle_applications AS application USING (application_id)
                WHERE application.repository_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.content_manifest_availability_proofs
                WHERE repository_id = $1),
               (SELECT count(*)
                FROM ogvcs_metadata.content_manifest_availability_authorization_pages AS page
                JOIN ogvcs_metadata.content_manifest_availability_proofs AS proof USING (application_id)
                WHERE proof.repository_id = $1),
               (SELECT applied_sequence FROM ogvcs_metadata.repository_commit_sequences
                WHERE repository_id = $1)",
            &[&Uuid::from_bytes(*fixture.repository_id.as_bytes())],
        )
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
                row.get(6),
            )
        })
        .unwrap()
}

fn assert_immutable(database_url: &str, fixture: &Fixture) {
    for statement in [
        "UPDATE ogvcs_metadata.content_manifest_availability_proofs
         SET dependency_count = dependency_count WHERE repository_id = $1",
        "DELETE FROM ogvcs_metadata.content_manifest_availability_proofs
         WHERE repository_id = $1",
        "UPDATE ogvcs_metadata.content_manifest_availability_authorization_pages
         SET resource_count = resource_count WHERE application_id IN
           (SELECT application_id FROM ogvcs_metadata.content_manifest_availability_proofs
            WHERE repository_id = $1)",
    ] {
        let mut client = Client::connect(database_url, NoTls).unwrap();
        assert!(client
            .execute(
                statement,
                &[&Uuid::from_bytes(*fixture.repository_id.as_bytes())],
            )
            .is_err());
    }
}

fn authorization_closure(object_set: &[ObjectRef]) -> [u8; 32] {
    let mut object_ids = object_set
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    object_ids.sort();
    digest_parts(&[
        AUTHORIZATION_CLOSURE_DOMAIN,
        &canonical_bytes(&json!({"objectIds": object_ids, "requestRoot": Value::Null})),
    ])
}

fn dependency_generation_digest(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    dependencies: &[ContentManifestDependencyBinding],
) -> [u8; 32] {
    let mut ordered = dependencies.to_vec();
    ordered.sort_by_key(|dependency| dependency.opaque_key);
    let mut digest = Sha256::new();
    digest.update(DEPENDENCY_GENERATIONS_DOMAIN);
    digest.update((ordered.len() as u32).to_be_bytes());
    for dependency in ordered {
        let encoded = canonical_bytes(&json!({
            "schemaVersion": "ogvcs.object-transfer/content-manifest-current-object/v1",
            "tenantId": Uuid::from_bytes(*tenant_id.as_bytes()).to_string(),
            "repositoryId": Uuid::from_bytes(*repository_id.as_bytes()).to_string(),
            "opaqueKey": hex(&dependency.opaque_key),
            "objectId": dependency.object_ref.to_string(),
            "length": dependency.length,
            "state": "available",
            "generation": dependency.generation,
            "authorityBindingSha256": hex(&dependency.authority_binding_digest),
            "backendReceiptSha256": hex(&dependency.backend_receipt_digest),
            "durableBackendReceiptSha256": hex(&dependency.backend_receipt_digest),
            "verificationReceiptSha256": Value::Null,
        }));
        digest.update((encoded.len() as u32).to_be_bytes());
        digest.update(encoded);
    }
    digest.finalize().into()
}

fn production_statement_digest(statement: &ContentManifestProductionStatement) -> [u8; 32] {
    digest_parts(&[
        PRODUCTION_STATEMENT_DOMAIN,
        &canonical_bytes(&json!({
            "boundary": statement.boundary,
            "logicalBytes": statement.logical_bytes.to_string(),
            "manifestObjectId": statement.manifest_object_id.to_string(),
            "manifestSha256": hex(&statement.manifest_sha256),
            "profile": statement.profile,
            "verifier": statement.verifier,
            "wholeFileSha256": hex(&statement.whole_file_sha256),
        })),
    ])
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_verification_receipt_digest(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    opaque_key: [u8; 32],
    object_ref: ObjectRef,
    expected_generation: u64,
    authority_binding_digest: [u8; 32],
    production_statement_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(320);
    receipt_field(&mut bytes, b"production-verification");
    receipt_field(&mut bytes, tenant_id.as_bytes());
    receipt_field(&mut bytes, repository_id.as_bytes());
    receipt_field(&mut bytes, &opaque_key);
    receipt_field(&mut bytes, &object_ref.kind.code().to_be_bytes());
    receipt_field(&mut bytes, &object_ref.digest);
    receipt_field(&mut bytes, b"staged");
    receipt_field(&mut bytes, &expected_generation.to_be_bytes());
    receipt_field(&mut bytes, b"available");
    receipt_field(&mut bytes, &(expected_generation + 1).to_be_bytes());
    receipt_field(&mut bytes, &authority_binding_digest);
    receipt_field(&mut bytes, &production_statement_digest);
    digest_parts(&[LIFECYCLE_VERIFICATION_RECEIPT_DOMAIN, &bytes])
}

fn receipt_field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn identity_subject_digest(subject: &str) -> [u8; 32] {
    digest_parts(&[b"OGVCS-IDENTITY-SUBJECT-V1\0", subject.as_bytes()])
}

fn production_subject_digest(issuer: &str, subject: &str) -> [u8; 32] {
    let value = json!({ "issuer": issuer, "subject": subject });
    digest_parts(&[
        b"OGVCS-OBJECT-TRANSFER-PRODUCTION-SUBJECT-V1\0",
        &canonical_bytes(&value),
    ])
}

fn lifecycle_contract_digest() -> [u8; 32] {
    decode_hex32(LIFECYCLE_CONTRACT_SHA256)
}

fn decode_hex32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut decoded = [0; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    decoded
}

fn digest_json<T: Serialize>(value: &T) -> [u8; 32] {
    digest_parts(&[&canonical_bytes(value)])
}

fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value).unwrap();
    serde_json::to_vec(&canonical(value)).unwrap()
}

fn canonical(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonical).collect()),
        Value::Object(values) => {
            let values = values
                .into_iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect::<BTreeMap<_, _>>();
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

fn public_uuid(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn identity_tenant(tenant_id: TenantId) -> String {
    format!("tenant.{}", hex(tenant_id.as_bytes()))
}

fn identity_repository(repository_id: RepositoryId) -> String {
    format!("repository.{}", hex(repository_id.as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}
