use std::{
    env, fs,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, SystemTime},
};

use ogvcs_object_model::{
    decode_canonical, encode_canonical, object_id, scan_metadata, validate_semantic_object, Cbor,
    Limits, ObjectKind, ObjectRef, ProfileRef, Registry, ValidationMode,
};
use ogvcs_repository_metadata::{
    AuthorizationContext, AuthorizationPort, CaseMode, CommitSequence, DomainErrorCode,
    FileHistoryWrite, FileId, FileIdImportReservation, FileIdOrigin, FileIdOwnerKind,
    FileIdReservation, FileIdReservationOutcome, IdempotencyReservation,
    IdempotencyReservationOutcome, MetadataTransaction, ObjectPutOutcome, ObjectValidationPort,
    ObjectWrite, OutboxEvent, PageRequest, PostgresMetadataStore, ProjectId, ReferenceCasRequest,
    ReferenceExpected, ReferenceKind, ReferenceName, RepositoryCreate, RepositoryId,
    RepositorySettings, SnapshotWrite, TenantId, TransactionOptions, TreeEntryWrite,
};
use postgres::{Client, NoTls};
use serde_json::json;
use uuid::Uuid;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors/objects";

#[derive(Clone, Copy)]
struct IsolatedAllow;

#[derive(Clone, Copy)]
struct IsolatedConformanceValidation;

#[derive(Clone, Debug, Eq, PartialEq)]
struct IsolatedAuthorizedView {
    context: AuthorizationContext,
    repository_id: RepositoryId,
}

impl AuthorizationPort for IsolatedAllow {
    type AuthorizedView = IsolatedAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        _permission: &'static str,
        _resource_type: &'static str,
        repository_id: RepositoryId,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(IsolatedAuthorizedView {
            context: context.clone(),
            repository_id,
        })
    }
}

impl ObjectValidationPort for IsolatedConformanceValidation {
    fn validate(&self, write: &ObjectWrite<'_>) -> ogvcs_repository_metadata::Result<()> {
        let object = scan_metadata(write.canonical_bytes, Limits::METADATA)
            .map_err(|_| ogvcs_repository_metadata::DomainError::new(DomainErrorCode::ObjectInvalid))?;
        validate_semantic_object(&object, &Registry::bundled(), ValidationMode::Conformance)
            .map_err(|_| ogvcs_repository_metadata::DomainError::new(DomainErrorCode::ObjectInvalid))?;
        Ok(())
    }
}

#[test]
fn production_reference_postgres_report() {
    let Ok(database_url) = env::var("OGVCS_METADATA_DATABASE_URL") else {
        eprintln!("skipped PostgreSQL integration: OGVCS_METADATA_DATABASE_URL is unset");
        return;
    };
    reset_disposable_schema(&database_url);
    migration_report(&database_url);
    report("migration-repeat-checksum-downgrade");

    let tenant_id = TenantId::from_bytes([4; 16]);
    let context = AuthorizationContext {
        subject_digest: [6; 32],
        tenant_id,
        authorization_epoch: 1,
    };
    let descriptor = fixture(ObjectKind::RepositoryDescriptor, "06-repository-descriptor.cbor");
    let repository_id = descriptor_repository_id(&descriptor.1);
    let (required_features, path_profile, content_policy_profile) =
        descriptor_settings(&descriptor.1);
    let manifest = fixture(ObjectKind::ContentManifest, "02-content-manifest.cbor");
    let tree = fixture(ObjectKind::Tree, "03-tree.cbor");
    let snapshot = fixture(ObjectKind::Snapshot, "07-snapshot.cbor");
    let (ordinal, basename, file_id, entry_kind, target, logical_size) =
        regular_tree_entry(&tree.1);
    let (root_tree, snapshot_parents) = snapshot_index(&snapshot.1);
    assert_eq!((root_tree, target), (tree.0, manifest.0));

    let mut store = PostgresMetadataStore::connect(&database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow)
        .with_object_validator(IsolatedConformanceValidation);
    let create_key = idempotency("repository.create", "ik-create", [10; 32]);
    let mut transaction = store
        .begin_authorized(
            &context,
            "repository.create",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 8 },
        )
        .unwrap();
    assert_eq!(transaction.authorized_repository_id(), repository_id);
    assert_eq!(transaction.authorization_context(), &context);
    assert_eq!(
        transaction.authorized_view(),
        &IsolatedAuthorizedView {
            context: context.clone(),
            repository_id,
        }
    );
    assert_eq!(
        transaction.reserve_idempotency(create_key.clone()).unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    transaction
        .create_repository(RepositoryCreate {
            repository_id,
            tenant_id,
            project_id: ProjectId::from_bytes([5; 16]),
            settings: RepositorySettings {
                repository_format: "ogvcs.repository-format@1".to_owned(),
                required_features,
                case_mode: CaseMode::CaseSensitive,
                path_profile: path_profile.clone(),
                platform_profile: path_profile,
                content_policy_profile,
                structural_limits: json!({
                    "maxTreeEntries": 999999,
                    "maxPathBytes": 4096,
                    "maxPathSegments": 256,
                    "maxSnapshotParents": 8
                }),
                tenant_boundary: tenant_id,
            },
            descriptor: write(repository_id, &descriptor),
        })
        .unwrap();
    transaction
        .commit_idempotency(&create_key, json!({"created": true}))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 1, "repository.created", "repository"))
        .unwrap();
    assert_eq!(transaction.commit().unwrap(), CommitSequence::new(1));

    let publish_key = idempotency("reference.cas", "ik-publish", [11; 32]);
    let mut transaction = store
        .begin_authorized(
            &context,
            "repository.publish",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 8 },
        )
        .unwrap();
    transaction.reserve_idempotency(publish_key.clone()).unwrap();
    assert_eq!(
        transaction.put_object(write(repository_id, &manifest)).unwrap(),
        ObjectPutOutcome::Inserted
    );
    transaction.put_object(write(repository_id, &tree)).unwrap();
    transaction.put_object(write(repository_id, &snapshot)).unwrap();
    transaction
        .reserve_file_id(FileIdReservation {
            repository_id,
            file_id,
            origin: FileIdOrigin::Create,
            owner_kind: FileIdOwnerKind::Published,
            owner_id: snapshot.0.to_string(),
        })
        .unwrap();
    transaction.activate_file_id(repository_id, file_id).unwrap();
    transaction
        .index_tree_entry(TreeEntryWrite {
            repository_id,
            tree: tree.0,
            ordinal,
            basename_utf8: basename.clone(),
            file_id,
            entry_kind,
            target,
            logical_size,
        })
        .unwrap();
    transaction
        .index_snapshot(SnapshotWrite {
            repository_id,
            snapshot: snapshot.0,
            root_tree,
            parents: snapshot_parents,
        })
        .unwrap();
    transaction
        .append_file_history(FileHistoryWrite {
            repository_id,
            snapshot: snapshot.0,
            operation_ordinal: 0,
            file_id,
            repository_path_utf8: basename,
            operation_kind: "create".to_owned(),
        })
        .unwrap();
    let reference = transaction
        .compare_and_swap_reference(ReferenceCasRequest {
            repository_id,
            kind: ReferenceKind::Branch,
            name: ReferenceName::new("main".to_owned()).unwrap(),
            expected: ReferenceExpected::Absent,
            desired: Some(snapshot.0),
        })
        .unwrap();
    transaction
        .commit_idempotency(&publish_key, json!({"generation": reference.generation}))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 2, "metadata.object-accepted", "snapshot"))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 3, "file-id.state-changed", "path"))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 4, "reference.changed", "reference"))
        .unwrap();
    assert_eq!(transaction.commit().unwrap(), CommitSequence::new(2));

    assert_eq!(
        store
            .read_reference(
                &context,
                repository_id,
                ReferenceKind::Branch,
                &ReferenceName::new("main".to_owned()).unwrap(),
                None,
            )
            .unwrap()
            .generation,
        1
    );
    assert_eq!(
        store
            .tree_page(
                &context,
                repository_id,
                tree.0,
                &[],
                PageRequest { limit: 1, cursor: None },
            )
            .unwrap()
            .items[0]
            .file_id,
        file_id
    );
    assert_eq!(
        store
            .file_history_page(
                &context,
                repository_id,
                file_id,
                PageRequest { limit: 1, cursor: None },
            )
            .unwrap()
            .items
            .len(),
        1
    );
    assert_eq!(
        store
            .reference_page(
                &context,
                repository_id,
                PageRequest { limit: 1, cursor: None },
            )
            .unwrap()
            .items
            .len(),
        1
    );
    object_replay_and_collision(&database_url, &mut store, &context, repository_id, &manifest);
    immutable_settings(&database_url, repository_id);
    report("canonical-file-graph");

    authorization_and_poisoning_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        tenant_id,
        &descriptor,
        &create_key,
    );
    report("authorization-binding-and-poisoning");

    rollback_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        snapshot.0,
        &create_key,
    );
    report("rollback-outbox-idempotency");
    consistency_report(&database_url, &mut store, &context, repository_id);
    report("consistency-token-primary-and-lag");
    drop(store);

    file_id_race(&database_url, context.clone(), repository_id);
    report("file-id-race-and-tombstone");
    cas_race(&database_url, context, repository_id, snapshot.0);
    report("cas-100-racers");
    reset_disposable_schema(&database_url);
}

fn reset_disposable_schema(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).expect("connect PostgreSQL test database");
    let database: String = client.query_one("SELECT current_database()", &[]).unwrap().get(0);
    assert!(
        database.starts_with("ogvcs_metadata_test_")
            && database
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "live metadata tests refuse to reset non-disposable database {database:?}; use ogvcs_metadata_test_<suffix>"
    );
    client
        .batch_execute("DROP SCHEMA IF EXISTS ogvcs_metadata CASCADE")
        .unwrap();
}

fn migration_report(database_url: &str) {
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    let options = ogvcs_repository_metadata::MigrationRunOptions {
        application_version: "0.1.0",
        compatibility_fence_open: true,
    };
    assert_eq!(store.migrate(options).unwrap().applied, 3);
    assert_eq!(store.migrate(options).unwrap().already_applied, 3);
    drop(store);

    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.schema_migrations SET checksum_sha256 = repeat('0', 64)
             WHERE version = 1 AND phase = 'contract'",
            &[],
        )
        .unwrap();
    drop(client);
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    assert_eq!(
        store
            .migrate(ogvcs_repository_metadata::MigrationRunOptions {
                application_version: "0.1.0",
                compatibility_fence_open: false,
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MigrationChecksumMismatch
    );
    drop(store);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.schema_migrations SET checksum_sha256 = $1
             WHERE version = 1 AND phase = 'contract'",
            &[&ogvcs_repository_metadata::MIGRATIONS[2].checksum_sha256],
        )
        .unwrap();
    client
        .execute(
            "DELETE FROM ogvcs_metadata.schema_migrations
             WHERE version = 1 AND phase = 'contract'",
            &[],
        )
        .unwrap();
    drop(client);
    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    let compatibility_error = match store.begin_authorized(
        &AuthorizationContext {
            subject_digest: [1; 32],
            tenant_id: TenantId::from_bytes([2; 16]),
            authorization_epoch: 1,
        },
        "repository.create",
        RepositoryId::from_bytes([3; 16]),
        TransactionOptions::Serializable { maximum_retries: 0 },
    ) {
        Ok(_) => panic!("mutation started without a completed contract migration"),
        Err(error) => error,
    };
    assert_eq!(compatibility_error.code, DomainErrorCode::MigrationIncompatible);
    drop(store);
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    assert_eq!(store.migrate(options).unwrap().applied, 1);
    drop(store);

    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.schema_migrations SET checksum_sha256 = repeat('0', 64)
             WHERE version = 1 AND phase = 'expand'",
            &[],
        )
        .unwrap();
    drop(client);
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    assert_eq!(store.migrate(options).unwrap_err().code, DomainErrorCode::MigrationChecksumMismatch);
    drop(store);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.schema_migrations SET checksum_sha256 = $1
             WHERE version = 1 AND phase = 'expand'",
            &[&ogvcs_repository_metadata::MIGRATIONS[0].checksum_sha256],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.schema_migrations
             (version, phase, checksum_sha256, state, minimum_application_version,
              maximum_application_version, completed_at)
             VALUES (2, 'expand', repeat('a', 64), 'completed', '0.2.0', '0.2.x', clock_timestamp())",
            &[],
        )
        .unwrap();
    drop(client);
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    assert_eq!(store.migrate(options).unwrap_err().code, DomainErrorCode::MigrationIncompatible);
    drop(store);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client.execute("DELETE FROM ogvcs_metadata.schema_migrations WHERE version = 2", &[]).unwrap();
}

fn object_replay_and_collision(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    manifest: &(ObjectRef, Vec<u8>),
) {
    let mut unbound = store
        .begin_authorized(
            context,
            "repository.object.put",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        unbound
            .put_object(write(repository_id, manifest))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        unbound.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let mut transaction = store
        .begin_authorized(
            context,
            "repository.object.put",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 2 },
        )
        .unwrap();
    let replay_key = idempotency("object.put", "object-replay", [12; 32]);
    assert_eq!(
        transaction.reserve_idempotency(replay_key.clone()).unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    assert_eq!(
        transaction.put_object(write(repository_id, manifest)).unwrap(),
        ObjectPutOutcome::ExactReplay
    );
    transaction
        .commit_idempotency(&replay_key, json!({"replayed": true}))
        .unwrap();
    transaction.commit().unwrap();

    let mut foreign_tree = decode_canonical(
        &fixture(ObjectKind::Tree, "03-tree.cbor").1,
        Limits::METADATA,
    )
    .unwrap();
    let Cbor::Map(fields) = &mut foreign_tree else {
        panic!("tree map");
    };
    let descriptor_field = fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(16))
        .unwrap();
    let foreign_descriptor = ObjectRef {
        kind: ObjectKind::RepositoryDescriptor,
        digest: [88; 32],
    };
    descriptor_field.1 = foreign_descriptor.to_cbor();
    let foreign_tree_bytes = encode_canonical(&foreign_tree).unwrap();
    let foreign_tree = (
        ObjectRef {
            kind: ObjectKind::Tree,
            digest: object_id(ObjectKind::Tree, &foreign_tree_bytes).unwrap(),
        },
        foreign_tree_bytes,
    );
    let settings_key = idempotency("object.put", "foreign-descriptor", [16; 32]);
    let mut settings_validation = store
        .begin_authorized(
            context,
            "repository.object.put",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    settings_validation
        .reserve_idempotency(settings_key)
        .unwrap();
    assert_eq!(
        settings_validation
            .put_object(write(repository_id, &foreign_tree))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        settings_validation.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let change_set = fixture(ObjectKind::ChangeSet, "04-change-set.cbor");
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.metadata_objects
             (repository_id, object_kind, digest_algorithm, object_digest, canonical_bytes,
              validation_contract) VALUES ($1, 4, 1, $2, $3, 'fault-injection')",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&change_set.0.digest[..],
                &&b"corrupt"[..],
            ],
        )
        .unwrap();
    drop(client);
    let mut transaction = store
        .begin_authorized(
            context,
            "repository.object.put",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    let collision_key = idempotency("object.put", "object-collision", [13; 32]);
    transaction.reserve_idempotency(collision_key).unwrap();
    assert_eq!(
        transaction
            .put_object(write(repository_id, &change_set))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectIdCollision
    );
}

fn immutable_settings(database_url: &str, repository_id: RepositoryId) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let error = client
        .execute(
            "UPDATE ogvcs_metadata.repository_settings SET case_mode = 'case-folded'
             WHERE repository_id = $1",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap_err();
    assert_eq!(error.as_db_error().unwrap().code().code(), "55000");
}

#[allow(clippy::too_many_arguments)]
fn authorization_and_poisoning_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    tenant_id: TenantId,
    descriptor: &(ObjectRef, Vec<u8>),
    committed_key: &IdempotencyReservation,
) {
    let mut replay = store
        .begin_authorized(
            context,
            "repository.create",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        replay.reserve_idempotency(committed_key.clone()).unwrap(),
        IdempotencyReservationOutcome::CommittedReplay(json!({"created": true}))
    );
    assert_eq!(
        replay.finish_committed_replay().unwrap(),
        json!({"created": true})
    );

    let cross_subject = AuthorizationContext {
        subject_digest: [7; 32],
        ..context.clone()
    };
    let mut independently_scoped = store
        .begin_authorized(
            &cross_subject,
            "repository.create",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        independently_scoped
            .reserve_idempotency(committed_key.clone())
            .unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    independently_scoped.rollback().unwrap();

    let future_issued = SystemTime::now() + Duration::from_secs(60);
    let future_key = idempotency_window(
        "repository.create",
        "future-issued",
        [17; 32],
        future_issued,
        future_issued + Duration::from_secs(300),
    );
    let mut future = store
        .begin_authorized(
            context,
            "repository.create",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        future
            .reserve_idempotency(future_key)
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        future.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let wrong_tenant = AuthorizationContext {
        subject_digest: context.subject_digest,
        tenant_id: TenantId::from_bytes([99; 16]),
        authorization_epoch: context.authorization_epoch,
    };
    let tenant_error = match store.begin_authorized(
        &wrong_tenant,
        "repository.publish",
        repository_id,
        TransactionOptions::Serializable { maximum_retries: 0 },
    ) {
        Ok(_) => panic!("cross-tenant transaction was opened"),
        Err(error) => error,
    };
    assert_eq!(
        tenant_error.code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let other_repository = RepositoryId::from_bytes([98; 16]);
    let cross_repository_key = idempotency("file-id.reserve", "cross-repository", [14; 32]);
    let mut cross_repository = store
        .begin_authorized(
            context,
            "repository.file-id.reserve",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    cross_repository
        .reserve_idempotency(cross_repository_key.clone())
        .unwrap();
    assert_eq!(
        cross_repository
            .reserve_file_id(FileIdReservation {
                repository_id: other_repository,
                file_id: FileId::new([97; 16]).unwrap(),
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "cross-repository".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        cross_repository.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let invalid_repository = RepositoryId::from_bytes([96; 16]);
    let invalid_create_key = idempotency("repository.create", "invalid-create", [15; 32]);
    let (required_features, path_profile, content_policy_profile) =
        descriptor_settings(&descriptor.1);
    let mut invalid_create = store
        .begin_authorized(
            context,
            "repository.create",
            invalid_repository,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    invalid_create
        .reserve_idempotency(invalid_create_key.clone())
        .unwrap();
    assert_eq!(
        invalid_create
            .create_repository(RepositoryCreate {
                repository_id: invalid_repository,
                tenant_id,
                project_id: ProjectId::from_bytes([95; 16]),
                settings: RepositorySettings {
                    repository_format: "ogvcs.repository-format@1".to_owned(),
                    required_features,
                    case_mode: CaseMode::CaseSensitive,
                    path_profile: path_profile.clone(),
                    platform_profile: path_profile,
                    content_policy_profile,
                    structural_limits: json!({
                        "maxTreeEntries": 1,
                        "maxPathBytes": 4096,
                        "maxPathSegments": 256,
                        "maxSnapshotParents": 8
                    }),
                    tenant_boundary: tenant_id,
                },
                descriptor: write(invalid_repository, descriptor),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        invalid_create.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let mut client = Client::connect(database_url, NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ogvcs_metadata.repositories WHERE repository_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.file_id_registry WHERE repository_id = $2),
               (SELECT count(*) FROM ogvcs_metadata.idempotency_records
                WHERE idempotency_key IN ($3, $4))",
            &[
                &Uuid::from_bytes(*invalid_repository.as_bytes()),
                &Uuid::from_bytes(*other_repository.as_bytes()),
                &invalid_create_key.key,
                &cross_repository_key.key,
            ],
        )
        .unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, i64>(1), row.get::<_, i64>(2)), (0, 0, 0));
}

fn rollback_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    snapshot: ObjectRef,
    committed_key: &IdempotencyReservation,
) {
    let baseline = counts(database_url, repository_id);
    for (index, fault) in [
        "after-idempotency",
        "after-file-id",
        "after-cas",
        "after-outbox",
        "before-commit",
    ]
    .into_iter()
    .enumerate()
    {
        let reservation = idempotency("fault.publish", fault, [30 + index as u8; 32]);
        let mut transaction = store
            .begin_authorized(
                context,
                "repository.publish",
                repository_id,
                TransactionOptions::Serializable { maximum_retries: 0 },
            )
            .unwrap();
        transaction.reserve_idempotency(reservation.clone()).unwrap();
        if index >= 1 {
            transaction
                .reserve_file_id(FileIdReservation {
                    repository_id,
                    file_id: FileId::new([40 + index as u8; 16]).unwrap(),
                    origin: FileIdOrigin::Create,
                    owner_kind: FileIdOwnerKind::Draft,
                    owner_id: fault.to_owned(),
                })
                .unwrap();
        }
        if index >= 2 {
            transaction
                .compare_and_swap_reference(ReferenceCasRequest {
                    repository_id,
                    kind: ReferenceKind::Branch,
                    name: ReferenceName::new("main".to_owned()).unwrap(),
                    expected: ReferenceExpected::Present { target: snapshot, generation: 1 },
                    desired: Some(snapshot),
                })
                .unwrap();
        }
        if index >= 3 {
            transaction
                .append_outbox(event(
                    repository_id,
                    20 + index as u128,
                    "reference.changed",
                    "reference",
                ))
                .unwrap();
        }
        if index >= 4 {
            transaction
                .commit_idempotency(&reservation, json!({"fault": fault}))
                .unwrap();
        }
        transaction.rollback().unwrap();
        assert_eq!(counts(database_url, repository_id), baseline, "fault point {fault}");
    }
    let event_binding_key = idempotency("file-id.reserve", "event-binding", [39; 32]);
    let mut event_binding = store
        .begin_authorized(
            context,
            "repository.file-id.reserve",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    event_binding
        .reserve_idempotency(event_binding_key.clone())
        .unwrap();
    event_binding
        .reserve_file_id(FileIdReservation {
            repository_id,
            file_id: FileId::new([39; 16]).unwrap(),
            origin: FileIdOrigin::Create,
            owner_kind: FileIdOwnerKind::Draft,
            owner_id: "event-binding".to_owned(),
        })
        .unwrap();
    event_binding
        .commit_idempotency(&event_binding_key, json!({"reserved": true}))
        .unwrap();
    assert_eq!(
        event_binding
            .append_outbox(event(repository_id, 29, "reference.changed", "reference"))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        event_binding.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);

    let event_cardinality_key =
        idempotency("file-id.reserve", "event-cardinality", [38; 32]);
    let mut event_cardinality = store
        .begin_authorized(
            context,
            "repository.file-id.reserve",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    event_cardinality
        .reserve_idempotency(event_cardinality_key.clone())
        .unwrap();
    for byte in [37_u8, 38_u8] {
        event_cardinality
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id: FileId::new([byte; 16]).unwrap(),
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: format!("event-cardinality-{byte}"),
            })
            .unwrap();
    }
    event_cardinality
        .commit_idempotency(&event_cardinality_key, json!({"reserved": 2}))
        .unwrap();
    event_cardinality
        .append_outbox(event(
            repository_id,
            28,
            "file-id.state-changed",
            "path",
        ))
        .unwrap();
    assert_eq!(
        event_cardinality.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);

    let mut reuse = store
        .begin_authorized(
            context,
            "repository.create",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    let mut mismatched = committed_key.clone();
    mismatched.semantic_fingerprint = [99; 32];
    assert_eq!(
        reuse.reserve_idempotency(mismatched).unwrap(),
        IdempotencyReservationOutcome::KeyReuseRejected
    );
    assert_eq!(
        reuse.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);
}

fn consistency_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
) {
    let mut transaction = store
        .begin_authorized(
            context,
            "repository.consistency.issue",
            repository_id,
            TransactionOptions::RepeatableRead,
        )
        .unwrap();
    let token = transaction
        .issue_consistency_token(CommitSequence::new(2))
        .unwrap();
    transaction.commit().unwrap();
    assert_eq!(
        store.require_consistency(context, repository_id, &token).unwrap(),
        CommitSequence::new(2)
    );
    for mismatched in [
        AuthorizationContext {
            subject_digest: [44; 32],
            ..context.clone()
        },
        AuthorizationContext {
            tenant_id: TenantId::from_bytes([45; 16]),
            ..context.clone()
        },
        AuthorizationContext {
            authorization_epoch: context.authorization_epoch + 1,
            ..context.clone()
        },
    ] {
        assert_eq!(
            store
                .require_consistency(&mismatched, repository_id, &token)
                .unwrap_err()
                .code,
            DomainErrorCode::ConsistencyTokenUnsatisfied
        );
    }
    assert_eq!(
        store
            .require_consistency(
                context,
                RepositoryId::from_bytes([46; 16]),
                &token,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::ConsistencyTokenUnsatisfied
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.repository_commit_sequences SET applied_sequence = 1
             WHERE repository_id = $1",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap();
    drop(client);
    assert_eq!(
        store.require_consistency(context, repository_id, &token).unwrap_err().code,
        DomainErrorCode::ConsistencyTokenUnsatisfied
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.repository_commit_sequences SET applied_sequence = 2
             WHERE repository_id = $1",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap();
}

fn file_id_race(database_url: &str, context: AuthorizationContext, repository_id: RepositoryId) {
    let unused_restore = FileId::new([69; 16]).unwrap();
    let unused_restore_key = idempotency("file-id.restore", "unused-restore", [79; 32]);
    let mut restore_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    let mut restore = restore_store
        .begin_authorized(
            &context,
            "repository.file-id.restore",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    restore
        .reserve_idempotency(unused_restore_key.clone())
        .unwrap();
    assert_eq!(
        restore
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id: unused_restore,
                origin: FileIdOrigin::Restore,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "unproved-unused-restore".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        restore.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let unused_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.file_id_registry
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&unused_restore.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(unused_rows, 0);
    drop(client);
    drop(restore_store);

    let file_id = FileId::new([70; 16]).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for index in 0..2_u8 {
        let database_url = database_url.to_owned();
        let context = context.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let mut store = PostgresMetadataStore::connect(&database_url)
                .unwrap()
                .with_authorizer(IsolatedAllow);
            let key = idempotency("file-id.reserve", &format!("file-race-{index}"), [80 + index; 32]);
            barrier.wait();
            store.execute_serializable(
                &context,
                "repository.file-id.reserve",
                repository_id,
                16,
                |transaction| {
                    transaction.reserve_idempotency(key.clone())?;
                    transaction.reserve_file_id(FileIdReservation {
                        repository_id,
                        file_id,
                        origin: FileIdOrigin::Copy,
                        owner_kind: FileIdOwnerKind::Draft,
                        owner_id: format!("race-{index}"),
                    })?;
                    transaction.commit_idempotency(&key, json!({"reserved": true}))?;
                    transaction.append_outbox(event(
                        repository_id,
                        100 + u128::from(index),
                        "file-id.state-changed",
                        "path",
                    ))?;
                    Ok(())
                },
            )
        }));
    }
    let results = workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|result| {
            result.as_ref().is_err_and(|error| error.code == DomainErrorCode::FileIdConflict)
        }).count(),
        1
    );

    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    let mut transaction = store
        .begin_authorized(
            &context,
            "repository.file-id.tombstone",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 4 },
        )
        .unwrap();
    let tombstone_key = idempotency("file-id.tombstone", "file-tombstone", [83; 32]);
    transaction.reserve_idempotency(tombstone_key.clone()).unwrap();
    transaction.tombstone_file_id(repository_id, file_id).unwrap();
    transaction
        .commit_idempotency(&tombstone_key, json!({"tombstoned": true}))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 103, "file-id.state-changed", "path"))
        .unwrap();
    transaction.commit().unwrap();
    let mut recreate = store
        .begin_authorized(
            &context,
            "repository.file-id.reserve",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    let recreate_key = idempotency("file-id.restore", "tombstoned-restore", [85; 32]);
    recreate.reserve_idempotency(recreate_key).unwrap();
    assert_eq!(
        recreate
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id,
                origin: FileIdOrigin::Restore,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "forged-restore".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        recreate.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let state: String = client
        .query_one(
            "SELECT state FROM ogvcs_metadata.file_id_registry
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&file_id.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(state, "tombstoned");
    drop(client);

    let recreate_create_key =
        idempotency("file-id.reserve", "tombstoned-create", [87; 32]);
    let mut recreate_create = store
        .begin_authorized(
            &context,
            "repository.file-id.reserve",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    recreate_create
        .reserve_idempotency(recreate_create_key)
        .unwrap();
    assert_eq!(
        recreate_create
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id,
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "forged-recreate".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        recreate_create.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let imported = FileId::new([71; 16]).unwrap();
    let import = FileIdImportReservation {
        reservation: FileIdReservation {
            repository_id,
            file_id: imported,
            origin: FileIdOrigin::Import,
            owner_kind: FileIdOwnerKind::Published,
            owner_id: "import-1".to_owned(),
        },
        importer_profile: "import.test/v1".to_owned(),
        source_namespace_digest: [72; 32],
        source_identity_digest: [73; 32],
    };
    let mut transaction = store
        .begin_authorized(
            &context,
            "repository.file-id.import",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 4 },
        )
        .unwrap();
    let import_key = idempotency("file-id.import", "file-import", [84; 32]);
    transaction.reserve_idempotency(import_key.clone()).unwrap();
    assert_eq!(
        transaction.reserve_imported_file_id(import.clone()).unwrap(),
        FileIdReservationOutcome::Reserved
    );
    transaction
        .commit_idempotency(&import_key, json!({"imported": true}))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 104, "file-id.state-changed", "path"))
        .unwrap();
    transaction.commit().unwrap();
    let mut replay = store
        .begin_authorized(
            &context,
            "repository.file-id.import",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 4 },
        )
        .unwrap();
    let import_replay_key = idempotency("file-id.import", "file-import-replay", [86; 32]);
    replay
        .reserve_idempotency(import_replay_key.clone())
        .unwrap();
    assert_eq!(
        replay.reserve_imported_file_id(import).unwrap(),
        FileIdReservationOutcome::ExactImportReplay
    );
    replay
        .commit_idempotency(&import_replay_key, json!({"replayed": true}))
        .unwrap();
    replay.commit().unwrap();
}

fn cas_race(
    database_url: &str,
    context: AuthorizationContext,
    repository_id: RepositoryId,
    snapshot: ObjectRef,
) {
    let barrier = Arc::new(Barrier::new(100));
    let mut workers = Vec::new();
    for index in 0..100_u128 {
        let database_url = database_url.to_owned();
        let context = context.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let mut store = PostgresMetadataStore::connect(&database_url)
                .unwrap()
                .with_authorizer(IsolatedAllow);
            let key = idempotency("reference.cas", &format!("cas-race-{index}"), [90; 32]);
            barrier.wait();
            store.execute_serializable(
                &context,
                "repository.reference.cas",
                repository_id,
                64,
                |transaction| {
                    transaction.reserve_idempotency(key.clone())?;
                    let result = transaction.compare_and_swap_reference(ReferenceCasRequest {
                        repository_id,
                        kind: ReferenceKind::Branch,
                        name: ReferenceName::new("main".to_owned()).unwrap(),
                        expected: ReferenceExpected::Present { target: snapshot, generation: 1 },
                        desired: Some(snapshot),
                    })?;
                    transaction
                        .commit_idempotency(&key, json!({"generation": result.generation}))?;
                    transaction.append_outbox(event(
                        repository_id,
                        1000 + index,
                        "reference.changed",
                        "reference",
                    ))?;
                    Ok(result)
                },
            )
        }));
    }
    let results = workers.into_iter().map(|worker| worker.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results.iter().filter(|result| {
            result.as_ref().is_err_and(|error| error.code == DomainErrorCode::ReferenceConflict)
        }).count(),
        99
    );
}

fn counts(database_url: &str, repository_id: RepositoryId) -> (i64, i64, i64, i64) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let repository = Uuid::from_bytes(*repository_id.as_bytes());
    let row = client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ogvcs_metadata.file_id_registry WHERE repository_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.idempotency_records),
               (SELECT count(*) FROM ogvcs_metadata.outbox_events WHERE repository_id = $1),
               (SELECT generation FROM ogvcs_metadata.references
                WHERE repository_id = $1 AND reference_kind = 'branch' AND reference_name = 'main')",
            &[&repository],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

fn fixture(kind: ObjectKind, name: &str) -> (ObjectRef, Vec<u8>) {
    let path = format!("{}/{VECTOR_ROOT}/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = fs::read(path).unwrap();
    (
        ObjectRef { kind, digest: object_id(kind, &bytes).unwrap() },
        bytes,
    )
}

fn write<'a>(repository_id: RepositoryId, fixture: &'a (ObjectRef, Vec<u8>)) -> ObjectWrite<'a> {
    ObjectWrite {
        repository_id,
        object_ref: &fixture.0,
        canonical_bytes: &fixture.1,
    }
}

fn regular_tree_entry(bytes: &[u8]) -> (u32, Vec<u8>, FileId, u16, ObjectRef, u64) {
    let tree = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Array(entries) = field(&tree, 17) else { panic!("tree entries") };
    for (ordinal, entry) in entries.iter().enumerate() {
        let Cbor::UInt(entry_kind) = field(entry, 1) else { panic!("entry kind") };
        if *entry_kind == 2 {
            let Cbor::Text(basename) = field(entry, 0) else { panic!("basename") };
            let file_id = FileId::from_cbor(field(entry, 2)).unwrap();
            let target = ObjectRef::from_cbor(field(entry, 4)).unwrap();
            let Cbor::UInt(logical_size) = field(entry, 5) else { panic!("logical size") };
            return (
                ordinal as u32,
                basename.as_bytes().to_vec(),
                file_id,
                2,
                target,
                *logical_size,
            );
        }
    }
    panic!("golden tree has no regular file")
}

fn snapshot_index(bytes: &[u8]) -> (ObjectRef, Vec<ObjectRef>) {
    let snapshot = decode_canonical(bytes, Limits::METADATA).unwrap();
    let root = ObjectRef::from_cbor(field(&snapshot, 18)).unwrap();
    let Cbor::Array(parents) = field(&snapshot, 17) else { panic!("snapshot parents") };
    let parents = parents
        .iter()
        .map(|parent| ObjectRef::from_cbor(parent).unwrap())
        .collect();
    (root, parents)
}

fn descriptor_repository_id(bytes: &[u8]) -> RepositoryId {
    let descriptor = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Bytes(bytes) = field(&descriptor, 16) else { panic!("repository ID") };
    RepositoryId::from_bytes(bytes.as_slice().try_into().unwrap())
}

fn descriptor_settings(bytes: &[u8]) -> (Vec<u16>, String, String) {
    let descriptor = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Array(features) = field(&descriptor, 2) else { panic!("required features") };
    let features = features
        .iter()
        .map(|value| match value {
            Cbor::UInt(code) => u16::try_from(*code).unwrap(),
            _ => panic!("feature code"),
        })
        .collect();
    let path = ProfileRef::from_cbor(field(&descriptor, 17)).unwrap().to_string();
    let Cbor::Array(content) = field(&descriptor, 18) else { panic!("content policies") };
    let content = ProfileRef::from_cbor(&content[0]).unwrap().to_string();
    (features, path, content)
}

fn field(value: &Cbor, key: u64) -> &Cbor {
    let Cbor::Map(fields) = value else { panic!("CBOR map") };
    &fields.iter().find(|(field, _)| *field == Cbor::UInt(key)).unwrap().1
}

fn idempotency(operation: &str, key: &str, fingerprint: [u8; 32]) -> IdempotencyReservation {
    let issued_at = SystemTime::now();
    let expires_at = issued_at + Duration::from_secs(300);
    idempotency_window(operation, key, fingerprint, issued_at, expires_at)
}

fn idempotency_window(
    operation: &str,
    key: &str,
    fingerprint: [u8; 32],
    issued_at: SystemTime,
    expires_at: SystemTime,
) -> IdempotencyReservation {
    let issued_ms = issued_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    let expires_ms = expires_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    IdempotencyReservation {
        operation: operation.to_owned(),
        key: format!("ik1.{issued_ms}.{expires_ms}.{key}{}", "A".repeat(22)),
        semantic_fingerprint: fingerprint,
        issued_at,
        expires_at,
    }
}

fn event(
    repository_id: RepositoryId,
    ordinal: u128,
    event_type: &'static str,
    resource_type: &'static str,
) -> OutboxEvent {
    OutboxEvent {
        event_id: ordinal.to_be_bytes(),
        repository_id,
        event_type,
        event_version: 1,
        correlation_id: (ordinal + 10_000).to_be_bytes(),
        resource_type,
        resource_opaque_id: format!("rr1.{}", "A".repeat(43)),
        safe_payload: json!({"class": "integration"}),
    }
}

fn report(case: &str) {
    println!("OGVCS_METADATA_REPORT {case}");
}
