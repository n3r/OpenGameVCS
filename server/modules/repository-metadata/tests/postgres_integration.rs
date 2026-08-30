use std::{env, fs, sync::{Arc, Barrier}, thread, time::{Duration, SystemTime}};

use ogvcs_object_model::{
    decode_canonical, object_id, scan_metadata, validate_semantic_object, Cbor, Limits, ObjectKind,
    ObjectRef, ProfileRef, Registry, ValidationMode,
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

impl AuthorizationPort for IsolatedAllow {
    type AuthorizedView = ();

    fn authorize(
        &self,
        _context: &AuthorizationContext,
        _permission: &'static str,
        _resource_type: &'static str,
        _repository_id: RepositoryId,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(())
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
                structural_limits: json!({"maxTreeEntries": 999999}),
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
        .append_outbox(event(repository_id, 2, "reference.changed", "reference"))
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
    let mut transaction = store
        .begin_authorized(
            context,
            "repository.object.put",
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 2 },
        )
        .unwrap();
    assert_eq!(
        transaction.put_object(write(repository_id, manifest)).unwrap(),
        ObjectPutOutcome::ExactReplay
    );
    transaction.commit().unwrap();

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
        DomainErrorCode::TransactionRetryExhausted
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
        .issue_consistency_token(context, repository_id, CommitSequence::new(2))
        .unwrap();
    transaction.commit().unwrap();
    assert_eq!(
        store.require_consistency(context, repository_id, &token).unwrap(),
        CommitSequence::new(2)
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
    drop(recreate);

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
    assert_eq!(
        replay.reserve_imported_file_id(import).unwrap(),
        FileIdReservationOutcome::ExactImportReplay
    );
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
    let issued_ms = issued_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    let expires_ms = expires_at.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis();
    IdempotencyReservation {
        authenticated_scope_digest: [9; 32],
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
