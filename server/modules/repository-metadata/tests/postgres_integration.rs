use std::{
    env, fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier,
    },
    thread,
    time::{Duration, SystemTime},
};

use ogvcs_identity_policy_audit_postgres::{
    run_migrations as run_identity_migrations, MigrationRunOptions as IdentityMigrationRunOptions,
};
use ogvcs_object_model::{
    decode_canonical, encode_canonical, object_id, scan_metadata, validate_semantic_object, Cbor,
    Limits, ObjectKind, ObjectRef, ProfileRef, Registry, ValidationMode,
};
use ogvcs_repository_metadata::{
    aggregate_plan_digest, AggregateChunkCommitment, AggregatePlanChunk, AggregatePublicationPlan,
    AncestryRecord, AuthorizationContext, AuthorizationPort, AuthorizationResource, AuthorizedView,
    CaseMode, CommitSequence, DomainError, DomainErrorCode, FileHistoryWrite, FileId,
    FileIdExpectedState, FileIdImportReservation, FileIdOrigin, FileIdOwnerKind, FileIdReservation,
    FileIdReservationOutcome, HistoryIncompleteReason, IdempotencyReservation,
    IdempotencyReservationOutcome, LifecycleCapability, LifecycleDirectCommand, LifecycleHealth,
    LifecycleHealthObservation, LifecycleObjectBinding, LifecycleReceiptKind,
    LifecycleReceiptWrite, LifecycleState, MetadataPermission, MetadataTransaction,
    ObjectPutOutcome, ObjectValidationPort, ObjectWrite, OutboxClaimRequest, OutboxEvent,
    OutboxLeaseAction, OutboxReleaseRequest, PageRequest, PageState, PostgresMetadataStore,
    ProjectId, ReferenceCasRequest, ReferenceExpected, ReferenceFilter, ReferenceKind,
    ReferenceName, RepositoryCreate, RepositoryId, RepositorySettings, SnapshotWrite,
    StagedLifecycleObject, TenantId, TransactionCapability, TransactionOptions, TreeEntryWrite,
};
use postgres::{Client, NoTls};
use serde_json::{json, Value};
use uuid::Uuid;

const VECTOR_ROOT: &str = "../../../spec/repository-format/v1/vectors/objects";

#[derive(Clone, Copy)]
struct IsolatedAllow;

#[derive(Clone, Copy)]
struct MisbindingAllow;

#[derive(Clone, Copy)]
struct CollectionOnlyAllow;

#[derive(Clone, Copy)]
struct CapabilityMisbindingAllow;

#[derive(Clone)]
struct RevocableAllow(Arc<AtomicBool>);

#[derive(Clone, Copy)]
struct SingleUseAllow;

#[derive(Clone, Copy)]
struct IsolatedConformanceValidation;

#[derive(Clone, Copy)]
struct RejectObjectValidation;

#[derive(Clone, Debug, Eq, PartialEq)]
struct IsolatedAuthorizedView {
    context: AuthorizationContext,
    permission: MetadataPermission,
    resource: AuthorizationResource,
}

impl AuthorizedView for IsolatedAuthorizedView {
    fn permits(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> bool {
        if self.context != *context || self.permission != permission {
            return false;
        }
        if self.resource == *resource {
            return true;
        }
        match (&self.resource, resource) {
            (
                AuthorizationResource::ProjectRepositories {
                    tenant_id: expected_tenant,
                    project_id: expected_project,
                },
                AuthorizationResource::ProjectRepository {
                    tenant_id,
                    project_id,
                    ..
                },
            ) => expected_tenant == tenant_id && expected_project == project_id,
            (
                AuthorizationResource::ReferenceCollection {
                    repository_id: expected,
                },
                AuthorizationResource::Reference { repository_id, .. },
            ) => expected == repository_id,
            (
                AuthorizationResource::TreePrefix {
                    repository_id: expected_repository,
                    snapshot: expected_snapshot,
                    tree: expected_tree,
                    prefix,
                },
                AuthorizationResource::TreeEntry {
                    repository_id,
                    snapshot,
                    tree,
                    repository_path,
                    ..
                },
            ) => {
                expected_repository == repository_id
                    && expected_snapshot == snapshot
                    && expected_tree == tree
                    && repository_path.len() == prefix.len() + 1
                    && repository_path.starts_with(prefix)
            }
            (
                AuthorizationResource::FileHistory {
                    repository_id: expected_repository,
                    file_id: expected_file_id,
                },
                AuthorizationResource::FileHistoryEntry {
                    repository_id,
                    file_id,
                    ..
                },
            ) => expected_repository == repository_id && expected_file_id == file_id,
            (
                AuthorizationResource::SnapshotHistory {
                    repository_id: expected_repository,
                    snapshot: expected_root,
                },
                AuthorizationResource::SnapshotHistoryEntry {
                    repository_id,
                    root_snapshot,
                    ..
                },
            ) => expected_repository == repository_id && expected_root == root_snapshot,
            (
                AuthorizationResource::SnapshotFileHistory {
                    repository_id: expected_repository,
                    root_snapshot: expected_root,
                    file_id: expected_file_id,
                },
                AuthorizationResource::SnapshotFileHistoryEntry {
                    repository_id,
                    root_snapshot,
                    file_id,
                    ..
                },
            ) => {
                expected_repository == repository_id
                    && expected_root == root_snapshot
                    && expected_file_id == file_id
            }
            (
                AuthorizationResource::SnapshotFileHistory {
                    repository_id: expected_repository,
                    root_snapshot: expected_root,
                    ..
                }
                | AuthorizationResource::SnapshotPathHistory {
                    repository_id: expected_repository,
                    root_snapshot: expected_root,
                    ..
                },
                AuthorizationResource::SnapshotHistoryEntry {
                    repository_id,
                    root_snapshot,
                    ..
                },
            ) => expected_repository == repository_id && expected_root == root_snapshot,
            (
                AuthorizationResource::SnapshotPathHistory {
                    repository_id: expected_repository,
                    root_snapshot: expected_root,
                    repository_path_utf8: expected_path,
                },
                AuthorizationResource::SnapshotFileHistoryEntry {
                    repository_id,
                    root_snapshot,
                    repository_path_utf8,
                    ..
                },
            ) => {
                expected_repository == repository_id
                    && expected_root == root_snapshot
                    && expected_path == repository_path_utf8
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CollectionOnlyAuthorizedView {
    context: AuthorizationContext,
    permission: MetadataPermission,
    resource: AuthorizationResource,
}

#[derive(Clone)]
struct RevocableAuthorizedView {
    context: AuthorizationContext,
    permission: MetadataPermission,
    resource: AuthorizationResource,
    valid: Arc<AtomicBool>,
}

struct SingleUseAuthorizedView {
    inner: IsolatedAuthorizedView,
    first_check: AtomicBool,
}

impl AuthorizedView for SingleUseAuthorizedView {
    fn permits(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> bool {
        self.inner.permits(context, permission, resource)
            && self.first_check.swap(false, Ordering::SeqCst)
    }
}

impl AuthorizedView for RevocableAuthorizedView {
    fn permits(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> bool {
        self.valid.load(Ordering::SeqCst)
            && self.context == *context
            && self.permission == permission
            && self.resource == *resource
    }
}

impl AuthorizedView for CollectionOnlyAuthorizedView {
    fn permits(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> bool {
        self.context == *context && self.permission == permission && self.resource == *resource
    }
}

impl AuthorizationPort for IsolatedAllow {
    type AuthorizedView = IsolatedAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(IsolatedAuthorizedView {
            context: context.clone(),
            permission,
            resource: resource.clone(),
        })
    }
}

impl AuthorizationPort for MisbindingAllow {
    type AuthorizedView = IsolatedAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        _permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(IsolatedAuthorizedView {
            context: context.clone(),
            permission: MetadataPermission::Discover,
            resource: resource.clone(),
        })
    }
}

impl AuthorizationPort for CollectionOnlyAllow {
    type AuthorizedView = CollectionOnlyAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(CollectionOnlyAuthorizedView {
            context: context.clone(),
            permission,
            resource: resource.clone(),
        })
    }
}

impl AuthorizationPort for CapabilityMisbindingAllow {
    type AuthorizedView = IsolatedAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        let resource = match resource {
            AuthorizationResource::RepositoryTransaction { repository_id, .. } => {
                AuthorizationResource::RepositoryTransaction {
                    repository_id: *repository_id,
                    capability: TransactionCapability::PutObject,
                }
            }
            resource => resource.clone(),
        };
        Ok(IsolatedAuthorizedView {
            context: context.clone(),
            permission,
            resource,
        })
    }
}

impl AuthorizationPort for RevocableAllow {
    type AuthorizedView = RevocableAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(RevocableAuthorizedView {
            context: context.clone(),
            permission,
            resource: resource.clone(),
            valid: self.0.clone(),
        })
    }
}

impl AuthorizationPort for SingleUseAllow {
    type AuthorizedView = SingleUseAuthorizedView;

    fn authorize(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> ogvcs_repository_metadata::Result<Self::AuthorizedView> {
        Ok(SingleUseAuthorizedView {
            inner: IsolatedAuthorizedView {
                context: context.clone(),
                permission,
                resource: resource.clone(),
            },
            first_check: AtomicBool::new(true),
        })
    }
}

impl ObjectValidationPort for IsolatedConformanceValidation {
    fn validate(&self, write: &ObjectWrite<'_>) -> ogvcs_repository_metadata::Result<()> {
        let object = scan_metadata(write.canonical_bytes, Limits::METADATA).map_err(|_| {
            ogvcs_repository_metadata::DomainError::new(DomainErrorCode::ObjectInvalid)
        })?;
        validate_semantic_object(&object, &Registry::bundled(), ValidationMode::Conformance)
            .map_err(|_| {
                ogvcs_repository_metadata::DomainError::new(DomainErrorCode::ObjectInvalid)
            })?;
        Ok(())
    }

    fn registry(&self) -> Registry {
        Registry::bundled()
    }

    fn validation_mode(&self) -> ValidationMode {
        ValidationMode::Conformance
    }

    fn resolve_chunk(&self, reference: ObjectRef) -> ogvcs_repository_metadata::Result<Vec<u8>> {
        let path = format!("{}/{VECTOR_ROOT}/01-chunk.bin", env!("CARGO_MANIFEST_DIR"));
        let bytes = fs::read(path).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if reference.kind == ObjectKind::Chunk
            && object_id(ObjectKind::Chunk, &bytes)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
                == reference.digest
        {
            Ok(bytes)
        } else {
            Err(DomainError::new(DomainErrorCode::ObjectInvalid))
        }
    }
}

impl ObjectValidationPort for RejectObjectValidation {
    fn validate(&self, _write: &ObjectWrite<'_>) -> ogvcs_repository_metadata::Result<()> {
        Err(DomainError::new(DomainErrorCode::ObjectInvalid))
    }

    fn registry(&self) -> Registry {
        Registry::bundled()
    }

    fn validation_mode(&self) -> ValidationMode {
        ValidationMode::Conformance
    }
}

#[test]
fn production_reference_postgres_report() {
    let Ok(database_url) = env::var("OGVCS_METADATA_DATABASE_URL") else {
        eprintln!("skipped PostgreSQL integration: OGVCS_METADATA_DATABASE_URL is unset");
        return;
    };
    reset_disposable_schema(&database_url);
    ensure_identity_schema(&database_url);
    migration_v1_v5_upgrade_report(&database_url);
    report("migration-v1-v5-upgrade-preserves-unpublished-history");
    reset_disposable_schema(&database_url);
    migration_report(&database_url);
    report("migration-repeat-checksum-downgrade");

    let tenant_id = TenantId::from_bytes([4; 16]);
    let context = AuthorizationContext {
        subject_digest: [6; 32],
        tenant_id,
        authorization_epoch: 1,
    };
    let descriptor = fixture(
        ObjectKind::RepositoryDescriptor,
        "06-repository-descriptor.cbor",
    );
    let repository_id = descriptor_repository_id(&descriptor.1);
    let project_id = ProjectId::from_bytes([5; 16]);
    let (required_features, path_profile, content_policy_profile) =
        descriptor_settings(&descriptor.1);
    let manifest = fixture(ObjectKind::ContentManifest, "02-content-manifest.cbor");
    let child_tree = fixture(ObjectKind::Tree, "03-tree-child.cbor");
    let tree = fixture(ObjectKind::Tree, "03-tree.cbor");
    let change = fixture(ObjectKind::ChangeSet, "04-change-set.cbor");
    let groups = fixture(ObjectKind::AssetGroupSet, "05-asset-group-set.cbor");
    let snapshot = fixture(ObjectKind::Snapshot, "07-snapshot.cbor");
    let provenance = fixture(ObjectKind::Provenance, "09-provenance.cbor");
    let tree_entries = tree_entries(&tree.1);
    let (_, history_path, file_id, _, target, _) = regular_tree_entry(&tree.1);
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
            TransactionCapability::CreateRepository,
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
            permission: MetadataPermission::Submit,
            resource: AuthorizationResource::RepositoryTransaction {
                repository_id,
                capability: TransactionCapability::CreateRepository,
            },
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
            project_id,
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
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 8 },
        )
        .unwrap();
    transaction
        .reserve_idempotency(publish_key.clone())
        .unwrap();
    assert_eq!(
        transaction
            .put_object(write(repository_id, &manifest))
            .unwrap(),
        ObjectPutOutcome::Inserted
    );
    transaction
        .put_object(write(repository_id, &child_tree))
        .unwrap();
    transaction.put_object(write(repository_id, &tree)).unwrap();
    transaction
        .put_object(write(repository_id, &change))
        .unwrap();
    transaction
        .put_object(write(repository_id, &groups))
        .unwrap();
    transaction
        .put_object(write(repository_id, &provenance))
        .unwrap();
    transaction
        .put_object(write(repository_id, &snapshot))
        .unwrap();
    for (_, _, file_id, _, _, _) in &tree_entries {
        transaction
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id: *file_id,
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Published,
                owner_id: snapshot.0.to_string(),
            })
            .unwrap();
    }
    for (_, _, file_id, _, _, _) in &tree_entries {
        transaction
            .activate_file_id(repository_id, *file_id)
            .unwrap();
    }
    for (ordinal, basename, file_id, entry_kind, target, logical_size) in &tree_entries {
        transaction
            .index_tree_entry(TreeEntryWrite {
                repository_id,
                tree: tree.0,
                ordinal: *ordinal,
                basename_utf8: basename.clone(),
                file_id: *file_id,
                entry_kind: *entry_kind,
                target: *target,
                logical_size: *logical_size,
            })
            .unwrap();
    }
    transaction
        .index_snapshot(SnapshotWrite {
            repository_id,
            snapshot: snapshot.0,
            root_tree,
            parents: snapshot_parents,
        })
        .unwrap();
    for (ordinal, basename, file_id, _, _, _) in &tree_entries {
        transaction
            .append_file_history(FileHistoryWrite {
                repository_id,
                snapshot: snapshot.0,
                operation_ordinal: *ordinal,
                file_id: *file_id,
                repository_path_utf8: basename.clone(),
                operation_kind: "create".to_owned(),
            })
            .unwrap();
    }
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
        .append_outbox(event(
            repository_id,
            2,
            "metadata.object-accepted",
            "snapshot",
        ))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 3, "file-id.state-changed", "path"))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 4, "reference.changed", "reference"))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 5, "reference.changed", "reference"))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 6, "reference.changed", "reference"))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 7, "reference.changed", "reference"))
        .unwrap();
    assert_eq!(transaction.commit().unwrap(), CommitSequence::new(2));

    let mut audit = Client::connect(&database_url, NoTls).unwrap();
    let events = audit
        .query(
            "SELECT event_type, resource_type, safe_payload
             FROM ogvcs_metadata.outbox_events
             WHERE repository_id = $1 ORDER BY event_id",
            &[&Uuid::from_bytes(*repository_id.as_bytes())],
        )
        .unwrap();
    let actual = events
        .iter()
        .map(|row| {
            let postgres::types::Json(payload): postgres::types::Json<serde_json::Value> =
                row.get(2);
            (row.get::<_, String>(0), row.get::<_, String>(1), payload)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            (
                "repository.created".to_owned(),
                "repository".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "state": "created"
                }),
            ),
            (
                "file-id.state-changed".to_owned(),
                "path".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "state": "active"
                }),
            ),
            (
                "file-id.state-changed".to_owned(),
                "path".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "state": "active"
                }),
            ),
            (
                "file-id.state-changed".to_owned(),
                "path".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "state": "active"
                }),
            ),
            (
                "file-id.state-changed".to_owned(),
                "path".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "state": "active"
                }),
            ),
            (
                "reference.changed".to_owned(),
                "reference".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "generation": 1,
                    "deleted": false
                }),
            ),
            (
                "metadata.object-accepted".to_owned(),
                "snapshot".to_owned(),
                json!({
                    "schemaVersion": "ogvcs.repository-metadata/outbox-safe-payload/v1",
                    "kind": "snapshot",
                    "state": "accepted"
                }),
            ),
        ]
    );
    let published_sequence: i64 = audit
        .query_one(
            "SELECT published_commit_sequence FROM ogvcs_metadata.snapshots
             WHERE repository_id = $1 AND snapshot_digest = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&snapshot.0.digest[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(published_sequence, 2);
    drop(audit);

    legacy_oversized_status_report(&database_url, &mut store, &context, repository_id);
    report("legacy-oversized-status-fails-bounded");
    immutable_read_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        tenant_id,
        &manifest,
    );
    report("immutable-settings-object-read");
    outbox_delivery_report(&database_url, &context, tenant_id);
    report("outbox-lease-ack-release");
    repository_list_report(
        &database_url,
        &mut store,
        &context,
        tenant_id,
        project_id,
        repository_id,
        &descriptor,
    );
    report("project-repository-list-cursors");
    let ancestry_chain =
        install_published_snapshot_chain(&database_url, repository_id, root_tree, &snapshot);
    ancestry_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        ancestry_chain,
        file_id,
        history_path,
    );
    report("bounded-ancestry-file-path-history");

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
            .reference_page_filtered(
                &context,
                repository_id,
                ReferenceFilter::Kind(ReferenceKind::Branch),
                None,
                PageRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap()
            .items
            .len(),
        1
    );
    assert!(store
        .reference_page_filtered(
            &context,
            repository_id,
            ReferenceFilter::Kind(ReferenceKind::Tag),
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap()
        .items
        .is_empty());
    assert!(store
        .tree_page(
            &context,
            repository_id,
            snapshot.0,
            tree.0,
            &[],
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap()
        .items
        .iter()
        .any(|entry| entry.file_id == file_id));
    assert_eq!(
        store
            .file_history_page(
                &context,
                repository_id,
                file_id,
                PageRequest {
                    limit: 1,
                    cursor: None
                },
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
                PageRequest {
                    limit: 1,
                    cursor: None
                },
            )
            .unwrap()
            .items
            .len(),
        1
    );
    projection_non_disclosure_report(
        &database_url,
        &context,
        repository_id,
        snapshot.0,
        tree.0,
        file_id,
    );
    read_revalidation_report(
        &database_url,
        &context,
        repository_id,
        snapshot.0,
        tree.0,
        file_id,
    );
    report("authorized-view-item-projections");
    publication_binding_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        tree.0,
        snapshot.0,
        file_id,
    );
    report("publication-index-and-lifetime-binding");
    object_replay_and_collision(
        &database_url,
        &mut store,
        &context,
        repository_id,
        &manifest,
    );
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
    consistency_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        snapshot.0,
        tree.0,
        file_id,
    );
    report("consistency-token-primary-and-lag");
    lifecycle_v9_report(
        &database_url,
        &mut store,
        &context,
        repository_id,
        snapshot.0,
    );
    report("lifecycle-v9-atomic-publication");
    drop(store);

    file_id_race(&database_url, context.clone(), repository_id);
    report("file-id-race-and-tombstone");
    cas_race(&database_url, context, repository_id, snapshot.0);
    report("cas-100-racers");
    reset_disposable_schema(&database_url);
}

fn reset_disposable_schema(database_url: &str) {
    let mut client =
        Client::connect(database_url, NoTls).expect("connect PostgreSQL test database");
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .unwrap()
        .get(0);
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

fn ensure_identity_schema(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    run_identity_migrations(
        &mut client,
        IdentityMigrationRunOptions {
            application_version: "0.2.0",
            compatibility_fence_open: true,
        },
    )
    .unwrap();
}

fn lifecycle_v9_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    publication: ObjectRef,
) {
    let opaque_key = [0x71; 32];
    let object_ref = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: [0x72; 32],
    };
    let authority_binding_digest = [0x73; 32];
    store
        .register_staged_lifecycle_for_test(&StagedLifecycleObject {
            tenant_id: context.tenant_id,
            repository_id,
            opaque_key,
            object_ref,
            object_length: 4096,
            tenant_scope_digest: [0x74; 32],
            authority_binding_digest,
            retention_until: SystemTime::now() + Duration::from_secs(3600),
        })
        .unwrap();

    let backend_receipt = lifecycle_receipt(
        [0x75; 32],
        LifecycleReceiptKind::BackendDurable,
        context.tenant_id,
        repository_id,
        opaque_key,
        object_ref,
        LifecycleState::Staged,
        1,
        LifecycleState::Available,
        2,
        authority_binding_digest,
        None,
        None,
    );
    store
        .persist_lifecycle_receipt_for_test(&backend_receipt)
        .unwrap();

    let mut client = Client::connect(database_url, NoTls).unwrap();
    assert_eq!(
        client
            .execute(
                "UPDATE ogvcs_metadata.object_lifecycle
                 SET state = 'available', generation = 2, backend_receipt_digest = $3
                 WHERE repository_id = $1 AND opaque_key = $2",
                &[
                    &Uuid::from_bytes(*repository_id.as_bytes()),
                    &&opaque_key[..],
                    &&backend_receipt.receipt_digest[..],
                ],
            )
            .unwrap(),
        1
    );
    let available_without_observation: (String, Option<i64>, Option<Vec<u8>>) = client
        .query_one(
            "SELECT health, health_generation, health_observation_digest
             FROM ogvcs_metadata.object_lifecycle
             WHERE repository_id = $1 AND opaque_key = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&opaque_key[..],
            ],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .unwrap();
    assert_eq!(
        available_without_observation,
        ("not-applicable".to_owned(), None, None)
    );
    assert!(client
        .execute(
            "UPDATE ogvcs_metadata.object_lifecycle
             SET health = 'healthy', health_generation = NULL
             WHERE repository_id = $1 AND opaque_key = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&opaque_key[..]
            ],
        )
        .is_err());
    drop(client);

    let health_receipt = lifecycle_receipt(
        [0x76; 32],
        LifecycleReceiptKind::HealthObservation,
        context.tenant_id,
        repository_id,
        opaque_key,
        object_ref,
        LifecycleState::Available,
        2,
        LifecycleState::Available,
        2,
        authority_binding_digest,
        Some(LifecycleHealth::Healthy),
        Some(1),
    );
    store
        .persist_lifecycle_receipt_for_test(&health_receipt)
        .unwrap();
    store
        .record_lifecycle_health_for_test(&LifecycleHealthObservation {
            tenant_id: context.tenant_id,
            repository_id,
            opaque_key,
            object_ref,
            expected_state: LifecycleState::Available,
            expected_generation: 2,
            expected_health: LifecycleHealth::NotApplicable,
            expected_health_generation: None,
            expected_health_observation_digest: None,
            next_health: LifecycleHealth::Healthy,
            next_health_generation: 1,
            authority_binding_digest,
            observation_receipt_digest: health_receipt.receipt_digest,
        })
        .unwrap();

    let reservation = idempotency("submit.finalize", "lifecycle-direct", [0x77; 32]);
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        transaction
            .reserve_idempotency(reservation.clone())
            .unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    let command = LifecycleDirectCommand::seal(
        format!("ltx1.{}", "L".repeat(43)),
        context.tenant_id,
        repository_id,
        context.subject_digest,
        context.authorization_epoch,
        LifecycleCapability::SubmitConsumePublication,
        [0x78; 32],
        Some(publication),
        None,
        transaction.lifecycle_authenticated_scope_digest_for_test(),
        reservation.clone(),
        vec![LifecycleObjectBinding {
            opaque_key,
            object_ref,
            expected_state: LifecycleState::Available,
            expected_generation: 2,
            expected_health: LifecycleHealth::Healthy,
            expected_health_generation: Some(1),
            current_health_observation_digest: Some(health_receipt.receipt_digest),
            authority_binding_digest,
            current_backend_receipt_digest: Some(backend_receipt.receipt_digest),
            current_verification_receipt_digest: None,
            current_deletion_receipt_digest: None,
            transition_backend_receipt_digest: None,
            transition_verification_receipt_digest: None,
            transition_deletion_receipt_digest: None,
            resource_opaque_digest: [0x79; 32],
        }],
    )
    .unwrap();
    let application = transaction
        .apply_lifecycle_direct_for_test(&command)
        .unwrap();
    transaction
        .commit_idempotency(
            &reservation,
            json!({
                "lifecycleApplicationReceipt": {
                    "objectCount": application.object_count,
                    "protectedResultDigest": application.protected_result_digest,
                }
            }),
        )
        .unwrap();
    let committed = transaction.commit().unwrap();
    assert_eq!(application.commit_sequence, committed.get());

    let mut client = Client::connect(database_url, NoTls).unwrap();
    let exact_atomic_rows: (i64, i64, i64, i64) = client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_applications
                WHERE application_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_transaction_facts
                WHERE application_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_reachability
                WHERE application_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_internal_outbox
                WHERE application_id = $1)",
            &[&Uuid::from_bytes(application.application_id)],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(exact_atomic_rows, (1, 1, 1, 1));
    let persisted_receipt: Vec<u8> = client
        .query_one(
            "SELECT receipt_digest FROM ogvcs_metadata.lifecycle_applications
             WHERE application_id = $1",
            &[&Uuid::from_bytes(application.application_id)],
        )
        .unwrap()
        .get(0);
    assert_eq!(persisted_receipt, application.receipt_digest);
    drop(client);

    aggregate_lifecycle_plan_v9_report(database_url, store, context, repository_id, publication);

    let gc_reservation = idempotency("gc.acquire-deleting", "lifecycle-gc-denied", [0x7a; 32]);
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    transaction
        .reserve_idempotency(gc_reservation.clone())
        .unwrap();
    let denied_gc = LifecycleDirectCommand::seal(
        format!("ltx1.{}", "G".repeat(43)),
        context.tenant_id,
        repository_id,
        context.subject_digest,
        context.authorization_epoch,
        LifecycleCapability::GcAcquireDeleting,
        [0x78; 32],
        None,
        Some([0x7b; 32]),
        transaction.lifecycle_authenticated_scope_digest_for_test(),
        gc_reservation,
        vec![LifecycleObjectBinding {
            opaque_key,
            object_ref,
            expected_state: LifecycleState::Quarantined,
            expected_generation: 3,
            expected_health: LifecycleHealth::Unhealthy,
            expected_health_generation: Some(2),
            current_health_observation_digest: Some([0x7c; 32]),
            authority_binding_digest,
            current_backend_receipt_digest: Some(backend_receipt.receipt_digest),
            current_verification_receipt_digest: None,
            current_deletion_receipt_digest: None,
            transition_backend_receipt_digest: None,
            transition_verification_receipt_digest: None,
            transition_deletion_receipt_digest: None,
            resource_opaque_digest: [0x7d; 32],
        }],
    )
    .unwrap();
    assert_eq!(
        transaction
            .apply_lifecycle_direct_for_test(&denied_gc)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        transaction.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
}

fn aggregate_lifecycle_plan_v9_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    publication: ObjectRef,
) {
    let plan_id = public_uuid_bytes(0x81);
    let items: Vec<_> = (0_u32..1_001).map(aggregate_lifecycle_item).collect();
    let first = AggregatePlanChunk::new(plan_id, 0, items[..1_000].to_vec()).unwrap();
    let second = AggregatePlanChunk::new(plan_id, 1, items[1_000..].to_vec()).unwrap();
    let encoded_bytes = u64::from(first.encoded_bytes) + u64::from(second.encoded_bytes);
    let reservation = idempotency("submit.finalize", "lifecycle-aggregate", [0x82; 32]);
    let mut conflicting_reservation = reservation.clone();
    conflicting_reservation.semantic_fingerprint[0] ^= 1;
    let provisional = AggregatePublicationPlan::new(
        plan_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0; 32],
        [0x85; 32],
        reservation.clone(),
        1_001,
        encoded_bytes,
    )
    .unwrap();
    let commitments = [
        AggregateChunkCommitment {
            chunk_ordinal: 0,
            item_count: 1_000,
            encoded_bytes: first.encoded_bytes,
            chunk_digest: first.chunk_digest,
        },
        AggregateChunkCommitment {
            chunk_ordinal: 1,
            item_count: 1,
            encoded_bytes: second.encoded_bytes,
            chunk_digest: second.chunk_digest,
        },
    ];
    let declared_plan_digest = aggregate_plan_digest(&provisional, &commitments).unwrap();
    let plan = AggregatePublicationPlan::new(
        plan_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        declared_plan_digest,
        [0x85; 32],
        reservation,
        1_001,
        encoded_bytes,
    )
    .unwrap();
    let mut writer = store.begin_lifecycle_plan_for_test(plan).unwrap();
    writer.append_chunk(first).unwrap();
    writer.append_chunk(second).unwrap();
    assert_eq!(writer.seal().unwrap(), declared_plan_digest);

    let mut client = Client::connect(database_url, NoTls).unwrap();
    let persisted: (i64, i64, i64, i64) = client
        .query_one(
            "SELECT
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_plan_chunks
                WHERE plan_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_plan_items
                WHERE plan_id = $1),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_plan_items
                WHERE plan_id = $1 AND resource_opaque_digest IS NOT NULL),
               (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_plan_seals
                WHERE plan_id = $1)",
            &[&Uuid::from_bytes(plan_id)],
        )
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .unwrap();
    assert_eq!(persisted, (2, 1_001, 1_001, 1));
    drop(client);

    let conflicting_plan = AggregatePublicationPlan::new(
        public_uuid_bytes(0x89),
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0x8a; 32],
        [0x85; 32],
        conflicting_reservation,
        1,
        1,
    )
    .unwrap();
    assert_eq!(
        store
            .begin_lifecycle_plan_for_test(conflicting_plan)
            .err()
            .unwrap()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let wrong_tenant_plan = AggregatePublicationPlan::new(
        public_uuid_bytes(0x8b),
        TenantId::from_bytes([0xee; 16]),
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0x8c; 32],
        [0x8d; 32],
        idempotency("submit.finalize", "lifecycle-wrong-tenant", [0x8e; 32]),
        1,
        1,
    )
    .unwrap();
    assert_eq!(
        store
            .begin_lifecycle_plan_for_test(wrong_tenant_plan)
            .err()
            .unwrap()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    let wrong_repository_plan = AggregatePublicationPlan::new(
        public_uuid_bytes(0x8f),
        context.tenant_id,
        RepositoryId::from_bytes([0xef; 16]),
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0x90; 32],
        [0x91; 32],
        idempotency("submit.finalize", "lifecycle-wrong-repository", [0x92; 32]),
        1,
        1,
    )
    .unwrap();
    assert_eq!(
        store
            .begin_lifecycle_plan_for_test(wrong_repository_plan)
            .err()
            .unwrap()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let substituted_id = public_uuid_bytes(0x86);
    let substituted_chunk =
        AggregatePlanChunk::new(substituted_id, 0, vec![aggregate_lifecycle_item(0)]).unwrap();
    let substituted_commitment = [AggregateChunkCommitment {
        chunk_ordinal: 0,
        item_count: 1,
        encoded_bytes: substituted_chunk.encoded_bytes,
        chunk_digest: substituted_chunk.chunk_digest,
    }];
    let substituted_reservation =
        idempotency("submit.finalize", "lifecycle-substitution", [0x87; 32]);
    let provisional = AggregatePublicationPlan::new(
        substituted_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0; 32],
        [0x88; 32],
        substituted_reservation.clone(),
        1,
        u64::from(substituted_chunk.encoded_bytes),
    )
    .unwrap();
    let exact_digest = aggregate_plan_digest(&provisional, &substituted_commitment).unwrap();
    let bad_plan = AggregatePublicationPlan::new(
        substituted_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        {
            let mut tampered = exact_digest;
            tampered[0] ^= 1;
            tampered
        },
        [0x88; 32],
        substituted_reservation,
        1,
        u64::from(substituted_chunk.encoded_bytes),
    )
    .unwrap();
    let mut writer = store.begin_lifecycle_plan_for_test(bad_plan).unwrap();
    writer.append_chunk(substituted_chunk).unwrap();
    assert_eq!(
        writer.seal().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let boundary_plan_id = public_uuid_bytes(0x95);
    let mut high_items: Vec<_> = (1_u32..=1_000).map(aggregate_lifecycle_item).collect();
    let low_item = aggregate_lifecycle_item(0);
    let boundary_first =
        AggregatePlanChunk::new(boundary_plan_id, 0, std::mem::take(&mut high_items)).unwrap();
    let boundary_second = AggregatePlanChunk::new(boundary_plan_id, 1, vec![low_item]).unwrap();
    let boundary_bytes =
        u64::from(boundary_first.encoded_bytes) + u64::from(boundary_second.encoded_bytes);
    let boundary_plan = AggregatePublicationPlan::new(
        boundary_plan_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0x96; 32],
        [0x97; 32],
        idempotency("submit.finalize", "lifecycle-boundary-order", [0x98; 32]),
        1_001,
        boundary_bytes,
    )
    .unwrap();
    let mut writer = store.begin_lifecycle_plan_for_test(boundary_plan).unwrap();
    writer.append_chunk(boundary_first).unwrap();
    assert_eq!(
        writer.append_chunk(boundary_second).unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    drop(writer);

    let duplicate_plan_id = public_uuid_bytes(0x99);
    let duplicate_first = aggregate_lifecycle_item(0);
    let mut duplicate_second = aggregate_lifecycle_item(1);
    duplicate_second.object_ref = duplicate_first.object_ref;
    let duplicate_chunk = AggregatePlanChunk::new(
        duplicate_plan_id,
        0,
        vec![duplicate_first, duplicate_second],
    )
    .unwrap();
    let duplicate_reservation = idempotency("submit.finalize", "lifecycle-duplicate", [0x9a; 32]);
    let provisional = AggregatePublicationPlan::new(
        duplicate_plan_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        [0; 32],
        [0x9b; 32],
        duplicate_reservation.clone(),
        2,
        u64::from(duplicate_chunk.encoded_bytes),
    )
    .unwrap();
    let commitments = [AggregateChunkCommitment {
        chunk_ordinal: 0,
        item_count: 2,
        encoded_bytes: duplicate_chunk.encoded_bytes,
        chunk_digest: duplicate_chunk.chunk_digest,
    }];
    let exact_digest = aggregate_plan_digest(&provisional, &commitments).unwrap();
    let duplicate_plan = AggregatePublicationPlan::new(
        duplicate_plan_id,
        context.tenant_id,
        repository_id,
        publication,
        context.subject_digest,
        context.authorization_epoch,
        [0x83; 32],
        [0x84; 32],
        exact_digest,
        [0x9b; 32],
        duplicate_reservation,
        2,
        u64::from(duplicate_chunk.encoded_bytes),
    )
    .unwrap();
    let mut writer = store.begin_lifecycle_plan_for_test(duplicate_plan).unwrap();
    assert_eq!(
        writer.append_chunk(duplicate_chunk).unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
}

fn aggregate_lifecycle_item(index: u32) -> LifecycleObjectBinding {
    let mut opaque_key = [0_u8; 32];
    opaque_key[28..].copy_from_slice(&index.to_be_bytes());
    let mut resource_opaque_digest = opaque_key;
    resource_opaque_digest[0] = 0x91;
    LifecycleObjectBinding {
        opaque_key,
        object_ref: ObjectRef {
            kind: ObjectKind::Chunk,
            digest: opaque_key,
        },
        expected_state: LifecycleState::Available,
        expected_generation: 2,
        expected_health: LifecycleHealth::Healthy,
        expected_health_generation: Some(1),
        current_health_observation_digest: Some([0x92; 32]),
        authority_binding_digest: [0x93; 32],
        current_backend_receipt_digest: Some([0x94; 32]),
        current_verification_receipt_digest: None,
        current_deletion_receipt_digest: None,
        transition_backend_receipt_digest: None,
        transition_verification_receipt_digest: None,
        transition_deletion_receipt_digest: None,
        resource_opaque_digest,
    }
}

fn public_uuid_bytes(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

#[allow(clippy::too_many_arguments)]
fn lifecycle_receipt(
    receipt_digest: [u8; 32],
    kind: LifecycleReceiptKind,
    tenant_id: TenantId,
    repository_id: RepositoryId,
    opaque_key: [u8; 32],
    object_ref: ObjectRef,
    expected_state: LifecycleState,
    expected_generation: u64,
    target_state: LifecycleState,
    target_generation: u64,
    authority_binding_digest: [u8; 32],
    health_result: Option<LifecycleHealth>,
    health_generation: Option<u64>,
) -> LifecycleReceiptWrite {
    let mut receipt = LifecycleReceiptWrite {
        receipt_digest,
        kind,
        tenant_id,
        repository_id,
        opaque_key,
        object_ref,
        expected_state,
        expected_generation,
        target_state,
        target_generation,
        authority_binding_digest,
        health_result,
        health_generation,
        evidence_digest: [0; 32],
    };
    receipt.evidence_digest = receipt.binding_digest();
    assert!(receipt.is_valid());
    receipt
}

fn legacy_oversized_status_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
) {
    let reservation = idempotency("legacy.status", "oversized", [0x5e; 32]);
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    transaction
        .reserve_idempotency(reservation.clone())
        .unwrap();
    transaction
        .commit_idempotency(&reservation, json!({"seed": true}))
        .unwrap();
    transaction.commit().unwrap();

    let mut client = Client::connect(database_url, NoTls).unwrap();
    assert_eq!(
        client
            .execute(
                "UPDATE ogvcs_metadata.idempotency_records
                 SET safe_result = to_jsonb(array_fill(0, ARRAY[400000]))
                 WHERE operation = $1 AND idempotency_key = $2
                   AND authorization_resources IS NULL",
                &[&reservation.operation, &reservation.key],
            )
            .unwrap(),
        1
    );
    let sizes: (i64, i64) = client
        .query_one(
            "SELECT pg_column_size(safe_result)::bigint,
                    octet_length(safe_result::text)::bigint
             FROM ogvcs_metadata.idempotency_records
             WHERE operation = $1 AND idempotency_key = $2",
            &[&reservation.operation, &reservation.key],
        )
        .map(|row| (row.get(0), row.get(1)))
        .unwrap();
    assert!(sizes.0 > 1_048_576 || sizes.1 > 1_048_576);
    assert_eq!(
        store
            .idempotency_status(
                context,
                repository_id,
                TransactionCapability::PutObject,
                &reservation.operation,
                &reservation.key,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
}

fn immutable_read_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    tenant_id: TenantId,
    manifest: &(ObjectRef, Vec<u8>),
) {
    let settings = store
        .get_repository_settings(context, repository_id, None)
        .unwrap();
    assert_eq!(settings.repository_format, "ogvcs.repository-format@1");
    assert_eq!(settings.case_mode, CaseMode::CaseSensitive);
    assert_eq!(settings.tenant_boundary, tenant_id);
    assert!(settings.has_sorted_unique_features());
    let object = store
        .get_object(context, repository_id, manifest.0, None)
        .unwrap();
    assert_eq!(object.object_ref, manifest.0);
    assert_eq!(object.canonical_bytes, manifest.1);

    let mut single_use = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(SingleUseAllow)
        .with_object_validator(IsolatedConformanceValidation);
    assert_eq!(
        single_use
            .get_repository_settings(context, repository_id, None)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        single_use
            .get_object(context, repository_id, manifest.0, None)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let wrong_tenant = AuthorizationContext {
        subject_digest: context.subject_digest,
        tenant_id: TenantId::from_bytes([99; 16]),
        authorization_epoch: context.authorization_epoch,
    };
    assert_eq!(
        store
            .get_repository_settings(&wrong_tenant, repository_id, None)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        store
            .get_object(&wrong_tenant, repository_id, manifest.0, None)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
}

#[allow(clippy::too_many_arguments)]
fn repository_list_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    tenant_id: TenantId,
    project_id: ProjectId,
    original_repository_id: RepositoryId,
    descriptor_template: &(ObjectRef, Vec<u8>),
) {
    let mut second_bytes = *original_repository_id.as_bytes();
    second_bytes[15] ^= 1;
    let second_repository_id = RepositoryId::from_bytes(second_bytes);
    assert_ne!(second_repository_id, original_repository_id);
    let second_descriptor = descriptor_for_repository(descriptor_template, second_repository_id);
    let settings = store
        .get_repository_settings(context, original_repository_id, None)
        .unwrap();
    let reservation = idempotency("repository.create", "ik-create-second", [54; 32]);
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::CreateRepository,
            second_repository_id,
            TransactionOptions::Serializable { maximum_retries: 2 },
        )
        .unwrap();
    assert_eq!(
        transaction
            .reserve_idempotency(reservation.clone())
            .unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    transaction
        .create_repository(RepositoryCreate {
            repository_id: second_repository_id,
            tenant_id,
            project_id,
            settings,
            descriptor: write(second_repository_id, &second_descriptor),
        })
        .unwrap();
    transaction
        .commit_idempotency(&reservation, json!({"created": true}))
        .unwrap();
    transaction
        .append_outbox(event(
            second_repository_id,
            500,
            "repository.created",
            "repository",
        ))
        .unwrap();
    assert_eq!(transaction.commit().unwrap(), CommitSequence::new(1));

    let first = store
        .repository_page(
            context,
            project_id,
            PageRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].project_id, project_id);
    assert!(matches!(
        first.items[0].repository_id,
        id if id == original_repository_id || id == second_repository_id
    ));
    let cursor = first.next_cursor.unwrap();
    let wrong_project = ProjectId::from_bytes([93; 16]);
    assert_eq!(
        store
            .repository_page(
                context,
                wrong_project,
                PageRequest {
                    limit: 1,
                    cursor: Some(cursor.clone()),
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "project-list cursor must be bound to its exact project",
    );
    let second = store
        .repository_page(
            context,
            project_id,
            PageRequest {
                limit: 1,
                cursor: Some(cursor),
            },
        )
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_ne!(second.items[0].repository_id, first.items[0].repository_id);
    assert!(second.next_cursor.is_none());

    let mut single_use = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(SingleUseAllow)
        .with_object_validator(IsolatedConformanceValidation);
    assert_eq!(
        single_use
            .repository_page(
                context,
                project_id,
                PageRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "repository-list authorization must be revalidated before response",
    );
}

fn outbox_delivery_report(database_url: &str, context: &AuthorizationContext, tenant_id: TenantId) {
    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    assert!(store
        .claim_outbox(
            context,
            OutboxClaimRequest {
                consumer_id: "bounded-indexer".to_owned(),
                maximum_items: 0,
                lease_seconds: 60,
            },
        )
        .unwrap()
        .is_empty());
    let first = store
        .claim_outbox(
            context,
            OutboxClaimRequest {
                consumer_id: "bounded-indexer".to_owned(),
                maximum_items: 2,
                lease_seconds: 60,
            },
        )
        .unwrap();
    assert_eq!(first.len(), 2);
    assert!(first.iter().all(|lease| {
        lease.consumer_id == "bounded-indexer"
            && lease.delivery_attempt == 1
            && lease.event.tenant_id == tenant_id
    }));
    let remaining = store
        .claim_outbox(
            context,
            OutboxClaimRequest {
                consumer_id: "bounded-indexer-2".to_owned(),
                maximum_items: 1_000,
                lease_seconds: 60,
            },
        )
        .unwrap();
    assert_eq!(remaining.len(), 5);
    assert!(remaining.iter().all(|candidate| {
        first
            .iter()
            .all(|leased| candidate.event.event_id != leased.event.event_id)
    }));

    let released = OutboxLeaseAction {
        consumer_id: first[0].consumer_id.clone(),
        event_id: first[0].event.event_id,
        lease_id: first[0].lease_id,
    };
    let mut wrong_consumer = released.clone();
    wrong_consumer.consumer_id = "wrong-consumer".to_owned();
    assert_eq!(
        store
            .acknowledge_outbox(context, wrong_consumer)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    store
        .release_outbox(
            context,
            OutboxReleaseRequest {
                lease: released.clone(),
                retry_after_seconds: 0,
            },
        )
        .unwrap();
    assert_eq!(
        store
            .acknowledge_outbox(context, released)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let acknowledged = OutboxLeaseAction {
        consumer_id: first[1].consumer_id.clone(),
        event_id: first[1].event.event_id,
        lease_id: first[1].lease_id,
    };
    store.acknowledge_outbox(context, acknowledged).unwrap();
    let reclaimed = store
        .claim_outbox(
            context,
            OutboxClaimRequest {
                consumer_id: "bounded-indexer-3".to_owned(),
                maximum_items: 1,
                lease_seconds: 60,
            },
        )
        .unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].event.event_id, first[0].event.event_id);
    assert_ne!(reclaimed[0].lease_id, first[0].lease_id);
    assert_eq!(reclaimed[0].delivery_attempt, 2);
    store
        .acknowledge_outbox(
            context,
            OutboxLeaseAction {
                consumer_id: reclaimed[0].consumer_id.clone(),
                event_id: reclaimed[0].event.event_id,
                lease_id: reclaimed[0].lease_id,
            },
        )
        .unwrap();
    for lease in remaining {
        store
            .acknowledge_outbox(
                context,
                OutboxLeaseAction {
                    consumer_id: lease.consumer_id,
                    event_id: lease.event.event_id,
                    lease_id: lease.lease_id,
                },
            )
            .unwrap();
    }
    drop(store);

    let mut audit = Client::connect(database_url, NoTls).unwrap();
    let state: (i64, i64, i64) = {
        let row = audit
            .query_one(
                "SELECT count(*) FILTER (WHERE acknowledged_at IS NOT NULL),
                        count(*) FILTER (WHERE lease_id IS NOT NULL),
                        sum(delivery_attempts)::bigint
                 FROM ogvcs_metadata.outbox_events WHERE tenant_id = $1",
                &[&Uuid::from_bytes(*tenant_id.as_bytes())],
            )
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
    };
    assert_eq!(state, (7, 0, 8));
}

fn ancestry_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    chain: [ObjectRef; 3],
    file_id: FileId,
    history_path: Vec<u8>,
) {
    let first = store
        .ancestry_page(
            context,
            repository_id,
            chain[2],
            10,
            None,
            PageRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(first.state, PageState::More);
    assert_eq!(
        first.items,
        vec![AncestryRecord {
            snapshot: chain[2],
            depth: 0,
        }]
    );
    assert_eq!(first.incomplete_reason, None);
    let first_cursor = first.next_cursor.unwrap();
    assert_eq!(
        store
            .ancestry_page(
                context,
                repository_id,
                chain[2],
                1,
                None,
                PageRequest {
                    limit: 1,
                    cursor: Some(first_cursor.clone()),
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "cursor must remain bound to the exact depth query",
    );
    let second = store
        .ancestry_page(
            context,
            repository_id,
            chain[2],
            10,
            None,
            PageRequest {
                limit: 1,
                cursor: Some(first_cursor),
            },
        )
        .unwrap();
    assert_eq!(second.state, PageState::More);
    assert_eq!(second.items[0].snapshot, chain[1]);
    assert_eq!(second.items[0].depth, 1);
    let third = store
        .ancestry_page(
            context,
            repository_id,
            chain[2],
            10,
            None,
            PageRequest {
                limit: 1,
                cursor: second.next_cursor,
            },
        )
        .unwrap();
    assert_eq!(third.state, PageState::Complete);
    assert_eq!(
        third.items,
        vec![AncestryRecord {
            snapshot: chain[0],
            depth: 2,
        }]
    );
    assert_eq!(third.next_cursor, None);
    assert_eq!(third.incomplete_reason, None);

    let depth_limited = store
        .ancestry_page(
            context,
            repository_id,
            chain[2],
            1,
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(depth_limited.state, PageState::Incomplete);
    assert_eq!(
        depth_limited
            .items
            .iter()
            .map(|record| (record.snapshot, record.depth))
            .collect::<Vec<_>>(),
        vec![(chain[2], 0), (chain[1], 1)]
    );
    assert_eq!(
        depth_limited.incomplete_reason,
        Some(HistoryIncompleteReason::DepthLimit)
    );

    let file_history = store
        .history_file_id_page(
            context,
            repository_id,
            chain[2],
            file_id,
            10,
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(file_history.state, PageState::Complete);
    assert_eq!(file_history.items.len(), 1);
    assert_eq!(file_history.items[0].snapshot, chain[0]);
    assert_eq!(file_history.items[0].file_id, file_id);
    assert_eq!(file_history.items[0].repository_path_utf8, history_path);

    let depth_limited_file_history = store
        .history_file_id_page(
            context,
            repository_id,
            chain[2],
            file_id,
            1,
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert!(depth_limited_file_history.items.is_empty());
    assert_eq!(depth_limited_file_history.state, PageState::Incomplete);
    assert_eq!(
        depth_limited_file_history.incomplete_reason,
        Some(HistoryIncompleteReason::DepthLimit)
    );

    let path = vec![String::from_utf8(history_path.clone()).unwrap()];
    let path_history = store
        .history_path_page(
            context,
            repository_id,
            chain[2],
            &path,
            10,
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(path_history.state, PageState::Complete);
    assert_eq!(path_history.items.len(), 1);
    assert_eq!(path_history.items[0].snapshot, chain[0]);
    assert_eq!(path_history.items[0].file_id, file_id);
    assert_eq!(
        store
            .history_path_page(
                context,
                repository_id,
                chain[2],
                &[],
                10,
                None,
                PageRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid,
    );
    assert_eq!(
        store
            .ancestry_page(
                context,
                repository_id,
                chain[2],
                100_001,
                None,
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::HistoryLimitReached,
    );

    let mut collection_only = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(CollectionOnlyAllow)
        .with_object_validator(IsolatedConformanceValidation);
    let hidden_ancestry = collection_only
        .ancestry_page(
            context,
            repository_id,
            chain[2],
            1,
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert!(hidden_ancestry.items.is_empty());
    assert_eq!(hidden_ancestry.state, PageState::Complete);
    assert_eq!(hidden_ancestry.incomplete_reason, None);
    let hidden_file_history = collection_only
        .history_file_id_page(
            context,
            repository_id,
            chain[2],
            file_id,
            1,
            None,
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap();
    assert!(hidden_file_history.items.is_empty());
    assert_eq!(hidden_file_history.state, PageState::Complete);
    assert_eq!(hidden_file_history.incomplete_reason, None);

    let mut single_use = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(SingleUseAllow)
        .with_object_validator(IsolatedConformanceValidation);
    assert_eq!(
        single_use
            .ancestry_page(
                context,
                repository_id,
                chain[2],
                10,
                None,
                PageRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied,
        "history authorization must be revalidated before response",
    );
}

fn install_published_snapshot_chain(
    database_url: &str,
    repository_id: RepositoryId,
    root_tree: ObjectRef,
    base: &(ObjectRef, Vec<u8>),
) -> [ObjectRef; 3] {
    let first = snapshot_with_parents(&base.1, &[base.0]);
    let second = snapshot_with_parents(&base.1, &[first.0]);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let mut transaction = client.transaction().unwrap();
    for (snapshot, parents) in [(&first, vec![base.0]), (&second, vec![first.0])] {
        let scanned = scan_metadata(&snapshot.1, Limits::METADATA).unwrap();
        validate_semantic_object(&scanned, &Registry::bundled(), ValidationMode::Conformance)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.metadata_objects
                 (repository_id, object_kind, digest_algorithm, object_digest,
                  canonical_bytes, validation_contract)
                 VALUES ($1, 7, 1, $2, $3, 'ogvcs.repository-format@1')",
                &[
                    &Uuid::from_bytes(*repository_id.as_bytes()),
                    &&snapshot.0.digest[..],
                    &snapshot.1,
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO ogvcs_metadata.snapshots
                 (repository_id, snapshot_digest, root_tree_digest, published_commit_sequence)
                 VALUES ($1, $2, $3, 2)",
                &[
                    &Uuid::from_bytes(*repository_id.as_bytes()),
                    &&snapshot.0.digest[..],
                    &&root_tree.digest[..],
                ],
            )
            .unwrap();
        for (ordinal, parent) in parents.iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO ogvcs_metadata.snapshot_parents
                     (repository_id, snapshot_digest, ordinal, parent_snapshot_digest)
                     VALUES ($1, $2, $3, $4)",
                    &[
                        &Uuid::from_bytes(*repository_id.as_bytes()),
                        &&snapshot.0.digest[..],
                        &i16::try_from(ordinal).unwrap(),
                        &&parent.digest[..],
                    ],
                )
                .unwrap();
        }
    }
    transaction.commit().unwrap();
    [base.0, first.0, second.0]
}

fn migration_v1_v5_upgrade_report(database_url: &str) {
    let mut client = Client::connect(database_url, NoTls).unwrap();
    for migration in &ogvcs_repository_metadata::MIGRATIONS[..3] {
        client.batch_execute(migration.sql).unwrap();
        client
            .execute(
                "INSERT INTO ogvcs_metadata.schema_migrations
                 (version, phase, checksum_sha256, state, minimum_application_version,
                  maximum_application_version, completed_at)
                 VALUES ($1, $2, $3, 'completed', $4, $5, clock_timestamp())",
                &[
                    &(migration.version as i64),
                    &migration.phase.as_str(),
                    &migration.checksum_sha256,
                    &migration.minimum_application_version,
                    &migration.maximum_application_version,
                ],
            )
            .unwrap();
    }

    let tenant_id = TenantId::from_bytes([81; 16]);
    let repository_id = RepositoryId::from_bytes([82; 16]);
    let tenant = Uuid::from_bytes(*tenant_id.as_bytes());
    let repository = Uuid::from_bytes(*repository_id.as_bytes());
    let project = Uuid::from_bytes([83; 16]);
    let tree_digest = vec![84_u8; 32];
    let snapshot_digest = vec![85_u8; 32];
    let file_id = vec![86_u8; 16];
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repositories
             (repository_id, tenant_id, project_id) VALUES ($1, $2, $3)",
            &[&repository, &tenant, &project],
        )
        .unwrap();
    for (kind, digest) in [(3_i16, &tree_digest), (7_i16, &snapshot_digest)] {
        client
            .execute(
                "INSERT INTO ogvcs_metadata.metadata_objects
                 (repository_id, object_kind, digest_algorithm, object_digest,
                  canonical_bytes, validation_contract)
                 VALUES ($1, $2, 1, $3, $4, 'ogvcs.repository-format@1')",
                &[&repository, &kind, digest, &&[0xa0_u8][..]],
            )
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO ogvcs_metadata.snapshots
             (repository_id, snapshot_digest, root_tree_digest, published_commit_sequence)
             VALUES ($1, $2, $3, NULL)",
            &[&repository, &snapshot_digest, &tree_digest],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.file_id_registry
             (repository_id, file_id, state, origin, owner_kind, owner_id)
             VALUES ($1, $2, 'active'::ogvcs_metadata.file_id_state,
                     'create'::ogvcs_metadata.file_id_origin,
                     'published'::ogvcs_metadata.file_id_owner_kind, 'legacy-main')",
            &[&repository, &file_id],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.file_path_history
             (repository_id, snapshot_digest, operation_ordinal, file_id,
              repository_path_utf8, operation_kind)
             VALUES ($1, $2, 0, $3, $4, 'create')",
            &[
                &repository,
                &snapshot_digest,
                &file_id,
                &&b"Content/legacy.bin"[..],
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.repository_commit_sequences
             (repository_id, applied_sequence) VALUES ($1, 1)",
            &[&repository],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.references
             (repository_id, reference_kind, reference_name, target_snapshot_digest,
              generation, commit_sequence)
             VALUES ($1, 'branch', 'main', $2, 1, 1)",
            &[&repository, &snapshot_digest],
        )
        .unwrap();
    drop(client);

    let options = ogvcs_repository_metadata::MigrationRunOptions {
        application_version: "0.1.0",
        compatibility_fence_open: true,
    };
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    let upgrade = store.migrate(options).unwrap();
    assert_eq!((upgrade.applied, upgrade.already_applied), (30, 3));
    drop(store);

    let mut client = Client::connect(database_url, NoTls).unwrap();
    let history_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.file_path_history
             WHERE repository_id = $1 AND snapshot_digest = $2",
            &[&repository, &snapshot_digest],
        )
        .unwrap()
        .get(0);
    assert_eq!(history_rows, 1);
    let published: Option<i64> = client
        .query_one(
            "SELECT published_commit_sequence FROM ogvcs_metadata.snapshots
             WHERE repository_id = $1 AND snapshot_digest = $2",
            &[&repository, &snapshot_digest],
        )
        .unwrap()
        .get(0);
    assert_eq!(published, None, "v2 must not infer historical publication");
    drop(client);

    let context = AuthorizationContext {
        subject_digest: [87; 32],
        tenant_id,
        authorization_epoch: 1,
    };
    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    assert_eq!(
        store
            .read_reference(
                &context,
                repository_id,
                ReferenceKind::Branch,
                &ReferenceName::new("main".to_owned()).unwrap(),
                None,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
}

fn migration_report(database_url: &str) {
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    let options = ogvcs_repository_metadata::MigrationRunOptions {
        application_version: "0.1.0",
        compatibility_fence_open: true,
    };
    assert_eq!(store.migrate(options).unwrap().applied, 33);
    assert_eq!(store.migrate(options).unwrap().already_applied, 33);
    drop(store);

    let mut client = Client::connect(database_url, NoTls).unwrap();
    let history_index: String = client
        .query_one(
            "SELECT pg_get_indexdef('ogvcs_metadata.file_path_history_by_file_id'::regclass)",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(history_index.contains("repository_id, file_id, snapshot_digest, operation_ordinal"));
    let version_one_checksum: String = client
        .query_one(
            "SELECT checksum_sha256 FROM ogvcs_metadata.schema_migrations
             WHERE version = 1 AND phase = 'expand'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        version_one_checksum,
        "58b53c7cd61b5f8b0e6fca4184a36379c049947a34751bedb1bd77ded674d53c"
    );
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
    let compatibility_context = AuthorizationContext {
        subject_digest: [1; 32],
        tenant_id: TenantId::from_bytes([2; 16]),
        authorization_epoch: 1,
    };
    let compatibility_repository = RepositoryId::from_bytes([3; 16]);
    assert_eq!(
        store
            .reference_page(
                &compatibility_context,
                compatibility_repository,
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MigrationIncompatible
    );
    let compatibility_error = match store.begin_authorized(
        &compatibility_context,
        TransactionCapability::CreateRepository,
        compatibility_repository,
        TransactionOptions::Serializable { maximum_retries: 0 },
    ) {
        Ok(_) => panic!("mutation started without a completed contract migration"),
        Err(error) => error,
    };
    assert_eq!(
        compatibility_error.code,
        DomainErrorCode::MigrationIncompatible
    );
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
    assert_eq!(
        store.migrate(options).unwrap_err().code,
        DomainErrorCode::MigrationChecksumMismatch
    );
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
             VALUES (12, 'expand', repeat('a', 64), 'completed', '0.2.0', '0.2.x', clock_timestamp())",
            &[],
        )
        .unwrap();
    drop(client);
    let mut store = PostgresMetadataStore::connect(database_url).unwrap();
    assert_eq!(
        store.migrate(options).unwrap_err().code,
        DomainErrorCode::MigrationIncompatible
    );
    drop(store);
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "DELETE FROM ogvcs_metadata.schema_migrations WHERE version = 12",
            &[],
        )
        .unwrap();
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
            TransactionCapability::PutObject,
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
            TransactionCapability::PutObject,
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
        transaction
            .put_object(write(repository_id, manifest))
            .unwrap(),
        ObjectPutOutcome::ExactReplay
    );
    transaction
        .commit_idempotency(&replay_key, json!({"replayed": true}))
        .unwrap();
    transaction.commit().unwrap();

    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.metadata_objects SET validation_contract = 'fault-injection'
             WHERE repository_id = $1 AND object_kind = $2 AND object_digest = $3",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &(manifest.0.kind.code() as i16),
                &&manifest.0.digest[..],
            ],
        )
        .unwrap();
    drop(client);
    let mut unvalidated_replay = store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    unvalidated_replay
        .reserve_idempotency(idempotency(
            "object.put",
            "unvalidated-exact-replay",
            [15; 32],
        ))
        .unwrap();
    assert_eq!(
        unvalidated_replay
            .put_object(write(repository_id, manifest))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        unvalidated_replay.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.metadata_objects
             SET validation_contract = 'ogvcs.repository-format@1'
             WHERE repository_id = $1 AND object_kind = $2 AND object_digest = $3",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &(manifest.0.kind.code() as i16),
                &&manifest.0.digest[..],
            ],
        )
        .unwrap();
    drop(client);

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
            TransactionCapability::PutObject,
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

    let collision_object = fixture(ObjectKind::Attestation, "10-attestation.cbor");
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "INSERT INTO ogvcs_metadata.metadata_objects
             (repository_id, object_kind, digest_algorithm, object_digest, canonical_bytes,
              validation_contract) VALUES ($1, $2, 1, $3, $4, 'fault-injection')",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &(collision_object.0.kind.code() as i16),
                &&collision_object.0.digest[..],
                &&b"corrupt"[..],
            ],
        )
        .unwrap();
    drop(client);
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    let collision_key = idempotency("object.put", "object-collision", [13; 32]);
    transaction.reserve_idempotency(collision_key).unwrap();
    assert_eq!(
        transaction
            .put_object(write(repository_id, &collision_object))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectIdCollision
    );
    assert_eq!(
        transaction.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "DELETE FROM ogvcs_metadata.metadata_objects
             WHERE repository_id = $1 AND object_kind = $2 AND object_digest = $3",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &(collision_object.0.kind.code() as i16),
                &&collision_object.0.digest[..],
            ],
        )
        .unwrap();
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

fn projection_non_disclosure_report(
    database_url: &str,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    snapshot: ObjectRef,
    tree: ObjectRef,
    file_id: FileId,
) {
    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(CollectionOnlyAllow)
        .with_object_validator(IsolatedConformanceValidation);
    let references = store
        .reference_page(
            context,
            repository_id,
            PageRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert!(references.items.is_empty());
    assert!(references.next_cursor.is_none());

    let entries = store
        .tree_page(
            context,
            repository_id,
            snapshot,
            tree,
            &[],
            PageRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert!(entries.items.is_empty());
    assert!(entries.next_cursor.is_none());

    let history = store
        .file_history_page(
            context,
            repository_id,
            file_id,
            PageRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap();
    assert!(history.items.is_empty());
    assert!(history.next_cursor.is_none());
}

fn read_revalidation_report(
    database_url: &str,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    snapshot: ObjectRef,
    tree: ObjectRef,
    file_id: FileId,
) {
    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(SingleUseAllow)
        .with_object_validator(IsolatedConformanceValidation);
    assert_eq!(
        store
            .read_reference(
                context,
                repository_id,
                ReferenceKind::Branch,
                &ReferenceName::new("main".to_owned()).unwrap(),
                None,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        store
            .reference_page(
                context,
                repository_id,
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        store
            .tree_page(
                context,
                repository_id,
                snapshot,
                tree,
                &[],
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        store
            .file_history_page(
                context,
                repository_id,
                file_id,
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
}

fn publication_binding_report(
    database_url: &str,
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    tree: ObjectRef,
    snapshot: ObjectRef,
    file_id: FileId,
) {
    let baseline = counts(database_url, repository_id);
    let repository = Uuid::from_bytes(*repository_id.as_bytes());
    let mut client = Client::connect(database_url, NoTls).unwrap();
    let original_publication_sequence: i64 = client
        .query_one(
            "SELECT published_commit_sequence FROM ogvcs_metadata.snapshots
             WHERE repository_id = $1 AND snapshot_digest = $2",
            &[&repository, &&snapshot.digest[..]],
        )
        .unwrap()
        .get(0);
    let original_basename: Vec<u8> = client
        .query_one(
            "SELECT basename_utf8 FROM ogvcs_metadata.tree_entries
             WHERE repository_id = $1 AND tree_digest = $2 AND file_id = $3",
            &[&repository, &&tree.digest[..], &&file_id.as_bytes()[..]],
        )
        .unwrap()
        .get(0);
    client
        .execute(
            "UPDATE ogvcs_metadata.tree_entries SET basename_utf8 = $4
             WHERE repository_id = $1 AND tree_digest = $2 AND file_id = $3",
            &[
                &repository,
                &&tree.digest[..],
                &&file_id.as_bytes()[..],
                &&b"tampered-index"[..],
            ],
        )
        .unwrap();
    drop(client);
    assert_publication_rejected(
        store,
        context,
        repository_id,
        snapshot,
        "tampered-tree-index",
        [41; 32],
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.tree_entries SET basename_utf8 = $4
             WHERE repository_id = $1 AND tree_digest = $2 AND file_id = $3",
            &[
                &repository,
                &&tree.digest[..],
                &&file_id.as_bytes()[..],
                &original_basename,
            ],
        )
        .unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.file_id_registry SET origin = 'copy'
             WHERE repository_id = $1 AND file_id = $2",
            &[&repository, &&file_id.as_bytes()[..]],
        )
        .unwrap();
    drop(client);
    assert_publication_rejected(
        store,
        context,
        repository_id,
        snapshot,
        "tampered-lifetime-origin",
        [42; 32],
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.file_id_registry SET origin = 'create'
             WHERE repository_id = $1 AND file_id = $2",
            &[&repository, &&file_id.as_bytes()[..]],
        )
        .unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.snapshots SET published_commit_sequence = NULL
             WHERE repository_id = $1 AND snapshot_digest = $2",
            &[&repository, &&snapshot.digest[..]],
        )
        .unwrap();
    drop(client);
    assert_eq!(
        store
            .read_reference(
                context,
                repository_id,
                ReferenceKind::Branch,
                &ReferenceName::new("main".to_owned()).unwrap(),
                None,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        store
            .reference_page(
                context,
                repository_id,
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        store
            .tree_page(
                context,
                repository_id,
                snapshot,
                tree,
                &[],
                PageRequest {
                    limit: 1,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert!(store
        .file_history_page(
            context,
            repository_id,
            file_id,
            PageRequest {
                limit: 1,
                cursor: None,
            },
        )
        .unwrap()
        .items
        .is_empty());
    assert_publication_rejected(
        store,
        context,
        repository_id,
        snapshot,
        "missing-publication-marker",
        [43; 32],
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.snapshots SET published_commit_sequence = $3
             WHERE repository_id = $1 AND snapshot_digest = $2",
            &[
                &repository,
                &&snapshot.digest[..],
                &original_publication_sequence,
            ],
        )
        .unwrap();
    assert_eq!(counts(database_url, repository_id), baseline);
}

fn assert_publication_rejected(
    store: &mut PostgresMetadataStore<IsolatedAllow, IsolatedConformanceValidation>,
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    snapshot: ObjectRef,
    reference_name: &str,
    fingerprint: [u8; 32],
) {
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::CompareAndSwapReference,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    transaction
        .reserve_idempotency(idempotency("reference.cas", reference_name, fingerprint))
        .unwrap();
    assert_eq!(
        transaction
            .compare_and_swap_reference(ReferenceCasRequest {
                repository_id,
                kind: ReferenceKind::Branch,
                name: ReferenceName::new(reference_name.to_owned()).unwrap(),
                expected: ReferenceExpected::Absent,
                desired: Some(snapshot),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        transaction.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
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
    let mut misbound_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(MisbindingAllow)
        .with_object_validator(IsolatedConformanceValidation);
    let misbound = match misbound_store.begin_authorized(
        context,
        TransactionCapability::Publish,
        repository_id,
        TransactionOptions::Serializable { maximum_retries: 0 },
    ) {
        Ok(_) => panic!("misbound authorization view opened a transaction"),
        Err(error) => error,
    };
    assert_eq!(misbound.code, DomainErrorCode::MetadataNotFoundOrDenied);
    drop(misbound_store);

    let mut capability_misbound_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(CapabilityMisbindingAllow)
        .with_object_validator(IsolatedConformanceValidation);
    let capability_misbound = match capability_misbound_store.begin_authorized(
        context,
        TransactionCapability::Publish,
        repository_id,
        TransactionOptions::Serializable { maximum_retries: 0 },
    ) {
        Ok(_) => panic!("capability-misbound authorization view opened a transaction"),
        Err(error) => error,
    };
    assert_eq!(
        capability_misbound.code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    drop(capability_misbound_store);

    let authorization_valid = Arc::new(AtomicBool::new(true));
    let mut revocable_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(RevocableAllow(authorization_valid.clone()))
        .with_object_validator(IsolatedConformanceValidation);
    let mut revoked = revocable_store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    authorization_valid.store(false, Ordering::SeqCst);
    assert_eq!(
        revoked
            .reserve_idempotency(idempotency(
                "object.put",
                "revoked-authorized-view",
                [19; 32],
            ))
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        revoked.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    drop(revocable_store);

    let mut synthetic_attempts = 0;
    let synthetic_retry = store
        .execute_serializable(
            context,
            TransactionCapability::PutObject,
            repository_id,
            5,
            |_transaction| {
                synthetic_attempts += 1;
                Err::<(), _>(DomainError::new(DomainErrorCode::TransactionRetryExhausted))
            },
        )
        .unwrap_err();
    assert_eq!(
        synthetic_retry.code,
        DomainErrorCode::TransactionRetryExhausted
    );
    assert_eq!(synthetic_attempts, 1);

    let capability_key = idempotency("capability.probe", "put-only", [18; 32]);
    let mut capability_probe = store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    capability_probe
        .reserve_idempotency(capability_key)
        .unwrap();
    assert_eq!(
        capability_probe
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id: FileId::new([18; 16]).unwrap(),
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "capability-probe".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        capability_probe.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let mut replay = store
        .begin_authorized(
            context,
            TransactionCapability::CreateRepository,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        replay.reserve_idempotency(committed_key.clone()).unwrap(),
        IdempotencyReservationOutcome::CommittedReplayPending
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
            TransactionCapability::CreateRepository,
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

    let mut capability_scoped = store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        capability_scoped
            .reserve_idempotency(committed_key.clone())
            .unwrap(),
        IdempotencyReservationOutcome::Reserved
    );
    capability_scoped.rollback().unwrap();

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
            TransactionCapability::CreateRepository,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    assert_eq!(
        future.reserve_idempotency(future_key).unwrap_err().code,
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
        TransactionCapability::Publish,
        repository_id,
        TransactionOptions::Serializable { maximum_retries: 0 },
    ) {
        Ok(_) => panic!("cross-tenant transaction was opened"),
        Err(error) => error,
    };
    assert_eq!(tenant_error.code, DomainErrorCode::MetadataNotFoundOrDenied);
    assert_eq!(
        store
            .read_reference(
                &wrong_tenant,
                repository_id,
                ReferenceKind::Branch,
                &ReferenceName::new("main".to_owned()).unwrap(),
                None,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );

    let other_repository = RepositoryId::from_bytes([98; 16]);
    let cross_repository_key = idempotency("file-id.reserve", "cross-repository", [14; 32]);
    let mut cross_repository = store
        .begin_authorized(
            context,
            TransactionCapability::ReserveFileId,
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

    let invalid_repository = RepositoryId::from_bytes([94; 16]);
    let invalid_descriptor = descriptor_for_repository(descriptor, invalid_repository);
    let invalid_create_key = idempotency("repository.create", "invalid-create", [15; 32]);
    let (required_features, path_profile, content_policy_profile) =
        descriptor_settings(&invalid_descriptor.1);
    let mut rejecting_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow)
        .with_object_validator(RejectObjectValidation);
    let mut invalid_create = rejecting_store
        .begin_authorized(
            context,
            TransactionCapability::CreateRepository,
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
                descriptor: write(invalid_repository, &invalid_descriptor),
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
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (0, 0, 0)
    );
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
    let forged_history_key = idempotency("history.append", "forged-history", [37; 32]);
    let mut forged_history = store
        .begin_authorized(
            context,
            TransactionCapability::Publish,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    forged_history
        .reserve_idempotency(forged_history_key)
        .unwrap();
    assert_eq!(
        forged_history
            .append_file_history(FileHistoryWrite {
                repository_id,
                snapshot,
                operation_ordinal: 0,
                file_id: FileId::new([37; 16]).unwrap(),
                repository_path_utf8: b"forged/path".to_vec(),
                operation_kind: "create".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        forged_history.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );

    let incomplete_key = idempotency("reference.cas", "missing-closure", [36; 32]);
    let mut incomplete = store
        .begin_authorized(
            context,
            TransactionCapability::CompareAndSwapReference,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    incomplete.reserve_idempotency(incomplete_key).unwrap();
    assert_eq!(
        incomplete
            .compare_and_swap_reference(ReferenceCasRequest {
                repository_id,
                kind: ReferenceKind::Branch,
                name: ReferenceName::new("missing-closure".to_owned()).unwrap(),
                expected: ReferenceExpected::Absent,
                desired: Some(ObjectRef {
                    kind: ObjectKind::Snapshot,
                    digest: [36; 32],
                }),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        incomplete.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);
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
                TransactionCapability::Publish,
                repository_id,
                TransactionOptions::Serializable { maximum_retries: 0 },
            )
            .unwrap();
        transaction
            .reserve_idempotency(reservation.clone())
            .unwrap();
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
                    expected: ReferenceExpected::Present {
                        target: snapshot,
                        generation: 1,
                    },
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
        assert_eq!(
            counts(database_url, repository_id),
            baseline,
            "fault point {fault}"
        );
    }
    let oversized_result_key = idempotency("object.put", "deep-safe-result", [35; 32]);
    let mut oversized_result = store
        .begin_authorized(
            context,
            TransactionCapability::PutObject,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    oversized_result
        .reserve_idempotency(oversized_result_key.clone())
        .unwrap();
    let mut deep_result = Value::Null;
    for _ in 0..130 {
        deep_result = Value::Array(vec![deep_result]);
    }
    assert_eq!(
        oversized_result
            .commit_idempotency(&oversized_result_key, deep_result)
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        oversized_result.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);

    let invalid_envelope_key = idempotency("file-id.reserve", "invalid-envelope", [36; 32]);
    let mut invalid_envelope = store
        .begin_authorized(
            context,
            TransactionCapability::ReserveFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    invalid_envelope
        .reserve_idempotency(invalid_envelope_key.clone())
        .unwrap();
    invalid_envelope
        .reserve_file_id(FileIdReservation {
            repository_id,
            file_id: FileId::new([36; 16]).unwrap(),
            origin: FileIdOrigin::Create,
            owner_kind: FileIdOwnerKind::Draft,
            owner_id: "invalid-envelope".to_owned(),
        })
        .unwrap();
    invalid_envelope
        .commit_idempotency(&invalid_envelope_key, json!({"reserved": true}))
        .unwrap();
    let mut invalid_event = event(repository_id, 27, "file-id.state-changed", "path");
    invalid_event.event_id = [0; 16];
    assert_eq!(
        invalid_envelope
            .append_outbox(invalid_event)
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        invalid_envelope.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);

    let event_binding_key = idempotency("file-id.reserve", "event-binding", [39; 32]);
    let mut event_binding = store
        .begin_authorized(
            context,
            TransactionCapability::ReserveFileId,
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
    event_binding
        .append_outbox(event(repository_id, 29, "file-id.state-changed", "path"))
        .unwrap();
    assert_eq!(
        event_binding
            .append_outbox(event(repository_id, 30, "file-id.state-changed", "path"))
            .unwrap_err()
            .code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(
        event_binding.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);

    let event_cardinality_key = idempotency("file-id.reserve", "event-cardinality", [38; 32]);
    let mut event_cardinality = store
        .begin_authorized(
            context,
            TransactionCapability::ReserveFileId,
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
        .append_outbox(event(repository_id, 28, "file-id.state-changed", "path"))
        .unwrap();
    assert_eq!(
        event_cardinality.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    assert_eq!(counts(database_url, repository_id), baseline);

    let mut reuse = store
        .begin_authorized(
            context,
            TransactionCapability::CreateRepository,
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
    snapshot: ObjectRef,
    tree: ObjectRef,
    file_id: FileId,
) {
    let mut transaction = store
        .begin_authorized(
            context,
            TransactionCapability::IssueConsistencyToken,
            repository_id,
            TransactionOptions::RepeatableRead,
        )
        .unwrap();
    let token = transaction
        .issue_consistency_token(CommitSequence::new(2))
        .unwrap();
    transaction.commit().unwrap();
    assert_eq!(
        store
            .require_consistency(context, repository_id, &token)
            .unwrap(),
        CommitSequence::new(2)
    );
    assert!(!store
        .tree_page_consistent(
            context,
            repository_id,
            snapshot,
            tree,
            &[],
            Some(&token),
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap()
        .items
        .is_empty());
    assert_eq!(
        store
            .reference_page_filtered(
                context,
                repository_id,
                ReferenceFilter::All,
                Some(&token),
                PageRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap()
            .items
            .len(),
        1
    );
    assert!(!store
        .file_history_page_consistent(
            context,
            repository_id,
            file_id,
            Some(&token),
            PageRequest {
                limit: 10,
                cursor: None,
            },
        )
        .unwrap()
        .items
        .is_empty());
    for mismatched in [
        AuthorizationContext {
            subject_digest: [44; 32],
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
                &AuthorizationContext {
                    tenant_id: TenantId::from_bytes([45; 16]),
                    ..context.clone()
                },
                repository_id,
                &token,
            )
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        store
            .require_consistency(context, RepositoryId::from_bytes([46; 16]), &token,)
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
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
        store
            .require_consistency(context, repository_id, &token)
            .unwrap_err()
            .code,
        DomainErrorCode::ConsistencyTokenUnsatisfied
    );
    assert_eq!(
        store
            .tree_page_consistent(
                context,
                repository_id,
                snapshot,
                tree,
                &[],
                Some(&token),
                PageRequest {
                    limit: 10,
                    cursor: None,
                },
            )
            .unwrap_err()
            .code,
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
    let restore_capability_alias = FileId::new([68; 16]).unwrap();
    let mut restore_alias_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    let mut restore_alias = restore_alias_store
        .begin_authorized(
            &context,
            TransactionCapability::RestoreFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    restore_alias
        .reserve_idempotency(idempotency(
            "file-id.restore",
            "restore-capability-alias",
            [78; 32],
        ))
        .unwrap();
    assert_eq!(
        restore_alias
            .reserve_file_id(FileIdReservation {
                repository_id,
                file_id: restore_capability_alias,
                origin: FileIdOrigin::Create,
                owner_kind: FileIdOwnerKind::Draft,
                owner_id: "restore-must-not-alias-create".to_owned(),
            })
            .unwrap_err()
            .code,
        DomainErrorCode::MetadataNotFoundOrDenied
    );
    assert_eq!(
        restore_alias.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    drop(restore_alias_store);

    let unused_restore = FileId::new([69; 16]).unwrap();
    let unused_restore_key = idempotency("file-id.restore", "unused-restore", [79; 32]);
    let mut restore_store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow);
    let mut restore = restore_store
        .begin_authorized(
            &context,
            TransactionCapability::RestoreFileId,
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
        DomainErrorCode::MetadataNotFoundOrDenied
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
    let aliased_rows: i64 = client
        .query_one(
            "SELECT count(*) FROM ogvcs_metadata.file_id_registry
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&restore_capability_alias.as_bytes()[..],
            ],
        )
        .unwrap()
        .get(0);
    assert_eq!(aliased_rows, 0);
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
            barrier.wait();
            let mut store = PostgresMetadataStore::connect(&database_url)
                .unwrap()
                .with_authorizer(IsolatedAllow)
                .with_object_validator(IsolatedConformanceValidation);
            let key = idempotency(
                "file-id.reserve",
                &format!("file-race-{index}"),
                [80 + index; 32],
            );
            store.execute_serializable(
                &context,
                TransactionCapability::ReserveFileId,
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
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                result
                    .as_ref()
                    .is_err_and(|error| error.code == DomainErrorCode::FileIdConflict)
            })
            .count(),
        1
    );

    let mut store = PostgresMetadataStore::connect(database_url)
        .unwrap()
        .with_authorizer(IsolatedAllow)
        .with_object_validator(IsolatedConformanceValidation);
    let mut wrong_expected_state = store
        .begin_authorized(
            &context,
            TransactionCapability::TombstoneFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    wrong_expected_state
        .reserve_idempotency(idempotency(
            "file-id.tombstone",
            "wrong-expected-state",
            [82; 32],
        ))
        .unwrap();
    assert_eq!(
        wrong_expected_state
            .tombstone_file_id(repository_id, file_id, FileIdExpectedState::Active)
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        wrong_expected_state.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    let mut transaction = store
        .begin_authorized(
            &context,
            TransactionCapability::TombstoneFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 4 },
        )
        .unwrap();
    let tombstone_key = idempotency("file-id.tombstone", "file-tombstone", [83; 32]);
    transaction
        .reserve_idempotency(tombstone_key.clone())
        .unwrap();
    transaction
        .tombstone_file_id(repository_id, file_id, FileIdExpectedState::Reserved)
        .unwrap();
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
            TransactionCapability::ReserveFileId,
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
            "SELECT state::text FROM ogvcs_metadata.file_id_registry
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

    let recreate_create_key = idempotency("file-id.reserve", "tombstoned-create", [87; 32]);
    let mut recreate_create = store
        .begin_authorized(
            &context,
            TransactionCapability::ReserveFileId,
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
        importer_profile: "importer.test/fixture-adapter@1".to_owned(),
        source_namespace_digest: [72; 32],
        source_identity_digest: [73; 32],
    };
    let mut transaction = store
        .begin_authorized(
            &context,
            TransactionCapability::ImportFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 4 },
        )
        .unwrap();
    let import_key = idempotency("file-id.import", "file-import", [84; 32]);
    transaction.reserve_idempotency(import_key.clone()).unwrap();
    assert_eq!(
        transaction
            .reserve_imported_file_id(import.clone())
            .unwrap(),
        FileIdReservationOutcome::Reserved
    );
    transaction
        .commit_idempotency(&import_key, json!({"imported": true}))
        .unwrap();
    transaction
        .append_outbox(event(repository_id, 104, "file-id.state-changed", "path"))
        .unwrap();
    transaction.commit().unwrap();
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.file_id_registry SET owner_id = 'tampered-import-owner'
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&imported.as_bytes()[..],
            ],
        )
        .unwrap();
    drop(client);
    let mut tampered_replay = store
        .begin_authorized(
            &context,
            TransactionCapability::ImportFileId,
            repository_id,
            TransactionOptions::Serializable { maximum_retries: 0 },
        )
        .unwrap();
    tampered_replay
        .reserve_idempotency(idempotency(
            "file-id.import",
            "file-import-tampered-owner",
            [88; 32],
        ))
        .unwrap();
    assert_eq!(
        tampered_replay
            .reserve_imported_file_id(import.clone())
            .unwrap_err()
            .code,
        DomainErrorCode::FileIdConflict
    );
    assert_eq!(
        tampered_replay.commit().unwrap_err().code,
        DomainErrorCode::ObjectInvalid
    );
    let mut client = Client::connect(database_url, NoTls).unwrap();
    client
        .execute(
            "UPDATE ogvcs_metadata.file_id_registry SET owner_id = $3
             WHERE repository_id = $1 AND file_id = $2",
            &[
                &Uuid::from_bytes(*repository_id.as_bytes()),
                &&imported.as_bytes()[..],
                &import.reservation.owner_id,
            ],
        )
        .unwrap();
    drop(client);
    let mut replay = store
        .begin_authorized(
            &context,
            TransactionCapability::ImportFileId,
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
            barrier.wait();
            let mut store = PostgresMetadataStore::connect(&database_url)
                .unwrap()
                .with_authorizer(IsolatedAllow)
                .with_object_validator(IsolatedConformanceValidation);
            let key = idempotency("reference.cas", &format!("cas-race-{index}"), [90; 32]);
            store.execute_serializable(
                &context,
                TransactionCapability::CompareAndSwapReference,
                repository_id,
                64,
                |transaction| {
                    transaction.reserve_idempotency(key.clone())?;
                    let result = transaction.compare_and_swap_reference(ReferenceCasRequest {
                        repository_id,
                        kind: ReferenceKind::Branch,
                        name: ReferenceName::new("main".to_owned()).unwrap(),
                        expected: ReferenceExpected::Present {
                            target: snapshot,
                            generation: 1,
                        },
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
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                result
                    .as_ref()
                    .is_err_and(|error| error.code == DomainErrorCode::ReferenceConflict)
            })
            .count(),
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
        ObjectRef {
            kind,
            digest: object_id(kind, &bytes).unwrap(),
        },
        bytes,
    )
}

fn write(repository_id: RepositoryId, fixture: &(ObjectRef, Vec<u8>)) -> ObjectWrite<'_> {
    ObjectWrite {
        repository_id,
        object_ref: &fixture.0,
        canonical_bytes: &fixture.1,
    }
}

fn descriptor_for_repository(
    template: &(ObjectRef, Vec<u8>),
    repository_id: RepositoryId,
) -> (ObjectRef, Vec<u8>) {
    let mut descriptor = decode_canonical(&template.1, Limits::METADATA).unwrap();
    let Cbor::Map(fields) = &mut descriptor else {
        panic!("repository descriptor map")
    };
    fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(16))
        .expect("repository id field")
        .1 = Cbor::Bytes(repository_id.as_bytes().to_vec());
    let bytes = encode_canonical(&descriptor).unwrap();
    (
        ObjectRef {
            kind: ObjectKind::RepositoryDescriptor,
            digest: object_id(ObjectKind::RepositoryDescriptor, &bytes).unwrap(),
        },
        bytes,
    )
}

fn regular_tree_entry(bytes: &[u8]) -> (u32, Vec<u8>, FileId, u16, ObjectRef, u64) {
    tree_entries(bytes)
        .into_iter()
        .find(|(_, _, _, entry_kind, _, _)| *entry_kind == 2)
        .expect("golden tree has a regular file")
}

fn tree_entries(bytes: &[u8]) -> Vec<(u32, Vec<u8>, FileId, u16, ObjectRef, u64)> {
    let tree = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Array(entries) = field(&tree, 17) else {
        panic!("tree entries")
    };
    entries
        .iter()
        .enumerate()
        .map(|(ordinal, entry)| {
            let Cbor::UInt(entry_kind) = field(entry, 1) else {
                panic!("entry kind")
            };
            let Cbor::Text(basename) = field(entry, 0) else {
                panic!("basename")
            };
            let file_id = FileId::from_cbor(field(entry, 2)).unwrap();
            let target = ObjectRef::from_cbor(field(entry, 4)).unwrap();
            let Cbor::UInt(logical_size) = field(entry, 5) else {
                panic!("logical size")
            };
            (
                ordinal as u32,
                basename.as_bytes().to_vec(),
                file_id,
                u16::try_from(*entry_kind).unwrap(),
                target,
                *logical_size,
            )
        })
        .collect()
}

fn snapshot_index(bytes: &[u8]) -> (ObjectRef, Vec<ObjectRef>) {
    let snapshot = decode_canonical(bytes, Limits::METADATA).unwrap();
    let root = ObjectRef::from_cbor(field(&snapshot, 18)).unwrap();
    let Cbor::Array(parents) = field(&snapshot, 17) else {
        panic!("snapshot parents")
    };
    let parents = parents
        .iter()
        .map(|parent| ObjectRef::from_cbor(parent).unwrap())
        .collect();
    (root, parents)
}

fn snapshot_with_parents(bytes: &[u8], parents: &[ObjectRef]) -> (ObjectRef, Vec<u8>) {
    let mut snapshot = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Map(fields) = &mut snapshot else {
        panic!("snapshot map")
    };
    fields
        .iter_mut()
        .find(|(key, _)| *key == Cbor::UInt(17))
        .expect("snapshot parents field")
        .1 = Cbor::Array(parents.iter().map(|parent| parent.to_cbor()).collect());
    let canonical_bytes = encode_canonical(&snapshot).unwrap();
    (
        ObjectRef {
            kind: ObjectKind::Snapshot,
            digest: object_id(ObjectKind::Snapshot, &canonical_bytes).unwrap(),
        },
        canonical_bytes,
    )
}

fn descriptor_repository_id(bytes: &[u8]) -> RepositoryId {
    let descriptor = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Bytes(bytes) = field(&descriptor, 16) else {
        panic!("repository ID")
    };
    RepositoryId::from_bytes(bytes.as_slice().try_into().unwrap())
}

fn descriptor_settings(bytes: &[u8]) -> (Vec<u16>, String, String) {
    let descriptor = decode_canonical(bytes, Limits::METADATA).unwrap();
    let Cbor::Array(features) = field(&descriptor, 2) else {
        panic!("required features")
    };
    let features = features
        .iter()
        .map(|value| match value {
            Cbor::UInt(code) => u16::try_from(*code).unwrap(),
            _ => panic!("feature code"),
        })
        .collect();
    let path = ProfileRef::from_cbor(field(&descriptor, 17))
        .unwrap()
        .to_string();
    let Cbor::Array(content) = field(&descriptor, 18) else {
        panic!("content policies")
    };
    let content = ProfileRef::from_cbor(&content[0]).unwrap().to_string();
    (features, path, content)
}

fn field(value: &Cbor, key: u64) -> &Cbor {
    let Cbor::Map(fields) = value else {
        panic!("CBOR map")
    };
    &fields
        .iter()
        .find(|(field, _)| *field == Cbor::UInt(key))
        .unwrap()
        .1
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
    let issued_ms = issued_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let expires_ms = expires_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis();
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
    _event_type: &'static str,
    _resource_type: &'static str,
) -> OutboxEvent {
    let mut event_id = ordinal.to_be_bytes();
    event_id[6] = (event_id[6] & 0x0f) | 0x40;
    event_id[8] = (event_id[8] & 0x3f) | 0x80;
    let mut correlation_id = (ordinal + 10_000).to_be_bytes();
    correlation_id[6] = (correlation_id[6] & 0x0f) | 0x40;
    correlation_id[8] = (correlation_id[8] & 0x3f) | 0x80;
    OutboxEvent {
        event_id,
        repository_id,
        correlation_id,
    }
}

fn report(case: &str) {
    println!("OGVCS_METADATA_REPORT {case}");
}
