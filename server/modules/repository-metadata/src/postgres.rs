use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ogvcs_identity_policy_audit_postgres::{
    AuthorizationResource as IdentityAuthorizationResource, DecisionCommitmentRequest,
    PostgresTransactionAuthorizationParticipant, TransactionAuthorizationParticipant,
    TransactionAuthorizationRequest, TransactionAuthorizedView, TransactionBatchRecheck,
    MAXIMUM_BATCH_RESOURCES,
};
use ogvcs_object_model::{
    decode_canonical, expand_tree_with_path_profile_validator, import_mapping_key, object_id,
    scan_metadata, validate_metadata_schema, validate_repository_candidate,
    validate_snapshot_graph, Cbor, EntryState, ImportMapping, ImportState, LifetimeOrigin,
    LifetimeRecord, Limits, ObjectKind, PathCaseMode, ProfileRef, RepositoryContext,
    RepositoryLimits, RepositoryObjectLookup,
};
use postgres::types::Json;
use postgres::{Client, IsolationLevel, NoTls, Row, Transaction};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AllocationReceipt, AncestryRecord, AuthorizationContext, AuthorizationPort,
    AuthorizationResource, AuthorizedView, CaseMode, CommitSequence, ConsistencyToken, CursorToken,
    DenyAllAuthorization, DomainError, DomainErrorCode, FileHistoryRecord, FileHistoryWrite,
    FileId, FileIdAllocation, FileIdExpectedState, FileIdImportReservation, FileIdOrigin,
    FileIdOwnerKind, FileIdReservation, FileIdReservationOutcome, HistoryIncompleteReason,
    HistoryPage, IdempotencyReservation, IdempotencyReservationOutcome, IdempotencyStatus,
    MetadataObjectRecord, MetadataPermission, MetadataStore, MetadataTransaction,
    NativeFileIdReservation, ObjectPutOutcome, ObjectRef, ObjectValidationPort, ObjectWrite,
    OutboxClaimRequest, OutboxEvent, OutboxEventRecord, OutboxLeaseAction, OutboxLeaseRecord,
    OutboxReleaseRequest, Page, PageRequest, PageState, ProductionObjectValidator,
    ReferenceCasRequest, ReferenceCasResult, ReferenceExpected, ReferenceFilter, ReferenceKind,
    ReferenceName, ReferenceRecord, RepositoryCreate, RepositoryId, RepositoryRecord,
    RepositorySettings, Result, SnapshotWrite, TenantId, TransactionCapability,
    TransactionCredentialRequest, TransactionOptions, TreeEntryRecord, TreeEntryWrite,
};

const VALIDATION_CONTRACT: &str = "ogvcs.repository-format@1";
const OUTBOX_PAYLOAD_SCHEMA: &str = "ogvcs.repository-metadata/outbox-safe-payload/v1";
const MAX_REQUIRED_OUTBOX_EVENTS: usize = 10_000;
const MAX_AUTHORIZATION_SCAN: usize = 100_000;
const MAX_HISTORY_WORK: usize = 100_000;
const MAX_HISTORY_DEPTH: u32 = 100_000;
const MAX_JSON_PREFLIGHT_BYTES: usize = 1_048_576;
const MAX_JSON_PREFLIGHT_DEPTH: usize = 128;
const MAX_JSON_PREFLIGHT_NODES: usize = 131_072;

macro_rules! poison_transaction_on_error {
    ($transaction:ident, $body:block) => {{
        let result = (|| $body)();
        if result.is_err() {
            $transaction.failed = true;
        }
        result
    }};
}

pub struct PostgresMetadataStore<A = DenyAllAuthorization, V = ProductionObjectValidator> {
    client: Client,
    authorization: A,
    validation: V,
    transaction_authorization: Option<PostgresTransactionAuthorizationParticipant>,
}

/// Production typestate. It deliberately does not implement `MetadataStore`
/// and does not dereference to the legacy adapter, so caller-context entry
/// points and receiptless reservation are absent from its public surface.
pub struct IdentityBoundPostgresMetadataStore<
    A = DenyAllAuthorization,
    V = ProductionObjectValidator,
> {
    store: PostgresMetadataStore<A, V>,
}

impl PostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator> {
    #[cfg(feature = "legacy-test-adapter")]
    pub fn connect(database_url: &str) -> Result<Self> {
        Self::connect_internal(database_url)
    }

    fn connect_internal(database_url: &str) -> Result<Self> {
        let client = Client::connect(database_url, NoTls).map_err(database_error)?;
        Ok(Self {
            client,
            authorization: DenyAllAuthorization,
            validation: ProductionObjectValidator::default(),
            transaction_authorization: None,
        })
    }
}

impl<A, V> PostgresMetadataStore<A, V> {
    #[cfg(feature = "legacy-test-adapter")]
    pub fn with_authorizer<B>(self, authorization: B) -> PostgresMetadataStore<B, V> {
        PostgresMetadataStore {
            client: self.client,
            authorization,
            validation: self.validation,
            transaction_authorization: self.transaction_authorization,
        }
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn with_object_validator<W>(self, validation: W) -> PostgresMetadataStore<A, W> {
        PostgresMetadataStore {
            client: self.client,
            authorization: self.authorization,
            validation,
            transaction_authorization: self.transaction_authorization,
        }
    }

    /// Installs the production OGVCS-009 participant. It is invoked only by
    /// the identity-authorized entry points, which retain both the branded
    /// view and the live PostgreSQL transaction internally.
    fn with_transaction_authorization_participant(
        mut self,
        participant: PostgresTransactionAuthorizationParticipant,
    ) -> IdentityBoundPostgresMetadataStore<A, V> {
        self.transaction_authorization = Some(participant);
        IdentityBoundPostgresMetadataStore { store: self }
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn migrate(
        &mut self,
        options: crate::MigrationRunOptions,
    ) -> Result<crate::MigrationRunReport> {
        crate::run_migrations(&mut self.client, options)
    }
}

impl<A: AuthorizationPort, V: ObjectValidationPort> PostgresMetadataStore<A, V> {
    /// Performs the complete `file-id.allocate` operation under one
    /// OGVCS-009-authorized transaction. The idempotency result contains the
    /// exact opaque receipt, so an exact retry returns the original allocation
    /// rather than consuming fresh entropy.
    fn allocate_file_id_identity_authorized_inner(
        &mut self,
        credentials: TransactionCredentialRequest<'_>,
        tenant_id: TenantId,
        repository_id: RepositoryId,
        reservation: IdempotencyReservation,
    ) -> Result<FileIdAllocation> {
        if reservation.operation != "file-id.allocate" {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        crate::verify_schema_compatibility(&mut self.client)?;
        let participant = self
            .transaction_authorization
            .as_ref()
            .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        let tenant = identity_tenant_id(tenant_id);
        let repository = identity_repository_id(repository_id);
        let permission = MetadataPermission::Submit.as_str();
        let resource = identity_allocation_resource();
        let mut transaction = self.client.transaction().map_err(database_error)?;
        let view = match participant.authorize(
            &mut transaction,
            &TransactionAuthorizationRequest {
                request_id: credentials.request_id,
                credential_presentation: credentials.credential_presentation,
                tenant: &tenant,
                repository: &repository,
                permission,
                reason: credentials.reason,
                resource: &resource,
                reference: None,
                snapshot: None,
            },
        ) {
            Ok(view) => view,
            Err(_) => {
                let _ = transaction.rollback();
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
        };
        let scope = identity_metadata_scope_digest(
            decode_identity_digest(view.authenticated_scope_digest())?,
            tenant_id,
            repository_id,
            TransactionCapability::ReserveFileId,
        );
        let server_now: SystemTime = transaction
            .query_one("SELECT clock_timestamp()", &[])
            .map_err(database_error)?
            .get(0);
        let valid_window = reservation.is_valid_at(server_now)
            && reservation
                .expires_at
                .duration_since(server_now)
                .is_ok_and(|remaining| remaining.as_secs() <= 600);
        let tenant_matches = transaction
            .query_opt(
                "SELECT 1 FROM ogvcs_metadata.repositories
                 WHERE repository_id = $1 AND tenant_id = $2",
                &[&uuid(repository_id), &uuid(tenant_id)],
            )
            .map_err(database_error)?
            .is_some();
        if !valid_window || !tenant_matches {
            poison_identity_transaction(&mut transaction);
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let allocation_expires_at = normalize_unix_milliseconds(reservation.expires_at)?;
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_metadata.idempotency_records
                 (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
                  state, issued_at, expires_at)
                 VALUES ($1, $2, $3, $4, 'reserved', $5, $6) ON CONFLICT DO NOTHING",
                &[
                    &&scope[..],
                    &reservation.operation,
                    &reservation.key,
                    &&reservation.semantic_fingerprint[..],
                    &reservation.issued_at,
                    &reservation.expires_at,
                ],
            )
            .map_err(database_error)?;
        if inserted == 0 {
            let row = transaction
                .query_one(
                    "SELECT semantic_fingerprint, state, safe_result
                     FROM ogvcs_metadata.idempotency_records
                     WHERE authenticated_scope_digest = $1 AND operation = $2
                       AND idempotency_key = $3 FOR UPDATE",
                    &[&&scope[..], &reservation.operation, &reservation.key],
                )
                .map_err(database_error)?;
            let fingerprint: Vec<u8> = row.get(0);
            let state: String = row.get(1);
            if !bool::from(
                fingerprint
                    .as_slice()
                    .ct_eq(&reservation.semantic_fingerprint),
            ) || state != "committed"
            {
                poison_identity_transaction(&mut transaction);
                let _ = transaction.rollback();
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let Json(safe_result): Json<Value> = row.get(2);
            let allocation = decode_allocation_result(repository_id, &safe_result)?;
            finalize_identity_decision(
                participant,
                &mut transaction,
                &view,
                credentials.correlation_id,
                &tenant,
                &repository,
                permission,
                None,
                std::slice::from_ref(&resource),
                &safe_result,
            )?;
            transaction.commit().map_err(database_error)?;
            return Ok(allocation);
        }

        let mut allocation = None;
        for _ in 0..32 {
            let mut file_id_bytes = [0_u8; 16];
            getrandom::getrandom(&mut file_id_bytes)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let Ok(file_id) = FileId::new(file_id_bytes) else {
                continue;
            };
            let mut receipt_bytes = [0_u8; 32];
            getrandom::getrandom(&mut receipt_bytes)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let receipt = AllocationReceipt::from_opaque(format!(
                "far1.{}",
                URL_SAFE_NO_PAD.encode(receipt_bytes)
            ))
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let digest = Sha256::digest(receipt.as_str().as_bytes());
            let created = transaction
                .execute(
                    "INSERT INTO ogvcs_metadata.file_id_allocation_receipts
                     (receipt_digest, authenticated_scope_digest, repository_id, file_id, expires_at)
                     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                    &[
                        &&digest[..],
                        &&scope[..],
                        &uuid(repository_id),
                        &&file_id.as_bytes()[..],
                        &allocation_expires_at,
                    ],
                )
                .map_err(database_error)?;
            if created == 1 {
                allocation = Some(FileIdAllocation {
                    repository_id,
                    file_id,
                    allocation_receipt: receipt,
                    expires_at: allocation_expires_at,
                });
                break;
            }
        }
        let allocation =
            allocation.ok_or_else(|| DomainError::new(DomainErrorCode::FileIdConflict))?;
        let safe_result = allocation_result(&allocation)?;
        let updated = transaction
            .execute(
                "UPDATE ogvcs_metadata.idempotency_records
                 SET state = 'committed', safe_result = $4, committed_at = clock_timestamp()
                 WHERE authenticated_scope_digest = $1 AND operation = $2
                   AND idempotency_key = $3 AND semantic_fingerprint = $5
                   AND state = 'reserved' AND expires_at > clock_timestamp()",
                &[
                    &&scope[..],
                    &reservation.operation,
                    &reservation.key,
                    &Json(&safe_result),
                    &&reservation.semantic_fingerprint[..],
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            poison_identity_transaction(&mut transaction);
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        finalize_identity_decision(
            participant,
            &mut transaction,
            &view,
            credentials.correlation_id,
            &tenant,
            &repository,
            permission,
            None,
            std::slice::from_ref(&resource),
            &safe_result,
        )?;
        transaction.commit().map_err(database_error)?;
        Ok(allocation)
    }

    /// Allocates a random FileID together with a one-use receipt. The receipt
    /// is scope- and repository-bound in the database; it is not a bearer
    /// authorization credential and cannot be replayed by a different actor.
    pub fn allocate_file_id(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
    ) -> Result<FileIdAllocation> {
        let capability = TransactionCapability::ReserveFileId;
        let resource = AuthorizationResource::RepositoryTransaction {
            repository_id,
            capability,
        };
        let view = self.authorize_exact(context, MetadataPermission::Submit, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        let scope = metadata_scope_digest(context, repository_id, capability);
        let mut transaction = self.client.transaction().map_err(database_error)?;
        for _ in 0..32 {
            let mut file_id_bytes = [0_u8; 16];
            getrandom::getrandom(&mut file_id_bytes)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let file_id = match FileId::new(file_id_bytes) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let mut receipt_bytes = [0_u8; 32];
            getrandom::getrandom(&mut receipt_bytes)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let receipt = AllocationReceipt::from_opaque(format!(
                "far1.{}",
                URL_SAFE_NO_PAD.encode(receipt_bytes)
            ))
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let digest = Sha256::digest(receipt.as_str().as_bytes());
            let row = transaction
                .query_opt(
                    "INSERT INTO ogvcs_metadata.file_id_allocation_receipts
                 (receipt_digest, authenticated_scope_digest, repository_id, file_id, expires_at)
                 VALUES ($1, $2, $3, $4, clock_timestamp() + interval '10 minutes')
                 ON CONFLICT DO NOTHING RETURNING expires_at",
                    &[
                        &&digest[..],
                        &&scope[..],
                        &uuid(repository_id),
                        &&file_id.as_bytes()[..],
                    ],
                )
                .map_err(database_error)?;
            if let Some(row) = row {
                if !view.permits(context, MetadataPermission::Submit, &resource) {
                    transaction.rollback().map_err(database_error)?;
                    return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
                }
                let expires_at: SystemTime = row.get(0);
                transaction.commit().map_err(database_error)?;
                return Ok(FileIdAllocation {
                    repository_id,
                    file_id,
                    allocation_receipt: receipt,
                    expires_at,
                });
            }
        }
        transaction.rollback().map_err(database_error)?;
        Err(DomainError::new(DomainErrorCode::FileIdConflict))
    }

    /// Looks up idempotency state only in the exact authenticated scope that
    /// would execute the named capability. This prevents cross-principal and
    /// cross-epoch replay disclosure.
    pub fn idempotency_status(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        capability: TransactionCapability,
        operation: &str,
        key: &str,
    ) -> Result<IdempotencyStatus> {
        if operation.is_empty() || operation.len() > 128 || key.is_empty() || key.len() > 512 {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let resource = AuthorizationResource::RepositoryTransaction {
            repository_id,
            capability,
        };
        let view = self.authorize_exact(context, MetadataPermission::Submit, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        let scope = metadata_scope_digest(context, repository_id, capability);
        let row = self
            .client
            .query_opt(
                "SELECT state, expires_at, safe_result FROM ogvcs_metadata.idempotency_records
             WHERE authenticated_scope_digest = $1 AND operation = $2 AND idempotency_key = $3
               AND expires_at > clock_timestamp()",
                &[&&scope[..], &operation, &key],
            )
            .map_err(database_error)?;
        if !view.permits(context, MetadataPermission::Submit, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let Some(row) = row else {
            return Ok(IdempotencyStatus::Absent);
        };
        let state: String = row.get(0);
        let expires_at: SystemTime = row.get(1);
        match state.as_str() {
            "reserved" => Ok(IdempotencyStatus::Reserved { expires_at }),
            "committed" => {
                let Json(safe_result): Json<Value> = row.get(2);
                Ok(IdempotencyStatus::Committed {
                    expires_at,
                    safe_result,
                })
            }
            _ => Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        }
    }

    fn authorize_exact(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> Result<A::AuthorizedView> {
        let view = self
            .authorization
            .authorize(context, permission, resource)?;
        if !view.permits(context, permission, resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        Ok(view)
    }

    fn require_repository_tenant(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
    ) -> Result<()> {
        let exists = self
            .client
            .query_opt(
                "SELECT 1 FROM ogvcs_metadata.repositories
                 WHERE repository_id = $1 AND tenant_id = $2",
                &[&uuid(repository_id), &uuid(context.tenant_id)],
            )
            .map_err(database_error)?
            .is_some();
        if exists {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
        }
    }

    fn require_published_snapshot_tree(
        &mut self,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        tree: ObjectRef,
        prefix: &[String],
    ) -> Result<()> {
        let snapshot_row = self
            .client
            .query_opt(
                "SELECT indexed.root_tree_digest, indexed.published_commit_sequence,
                        object.canonical_bytes, object.validation_contract
                 FROM ogvcs_metadata.snapshots AS indexed
                 JOIN ogvcs_metadata.metadata_objects AS object
                   ON object.repository_id = indexed.repository_id
                  AND object.object_kind = 7
                  AND object.digest_algorithm = 1
                  AND object.object_digest = indexed.snapshot_digest
                 WHERE indexed.repository_id = $1 AND indexed.snapshot_digest = $2
                   AND indexed.published_commit_sequence IS NOT NULL",
                &[&uuid(repository_id), &&snapshot.digest[..]],
            )
            .map_err(database_error)?
            .ok_or_else(not_found)?;
        let root = object_ref(ObjectKind::Tree, snapshot_row.get(0))?;
        let published_sequence: i64 = snapshot_row.get(1);
        let snapshot_bytes: Vec<u8> = snapshot_row.get(2);
        let validation_contract: String = snapshot_row.get(3);
        let snapshot_value = decode_canonical(&snapshot_bytes, Limits::METADATA)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if positive_u64(published_sequence).is_err()
            || validation_contract != VALIDATION_CONTRACT
            || object_id(ObjectKind::Snapshot, &snapshot_bytes)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
                != snapshot.digest
            || cbor_field(&snapshot_value, 18).and_then(|value| ObjectRef::from_cbor(value).ok())
                != Some(root)
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }

        let limits = RepositoryLimits::default();
        let preflight = self
            .client
            .query_one(
                "SELECT count(*)::bigint, COALESCE(sum(byte_length), 0)::text
                 FROM ogvcs_metadata.metadata_objects
                 WHERE repository_id = $1 AND object_kind = 3",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?;
        let object_count = usize::try_from(preflight.get::<_, i64>(0))
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let byte_count = preflight
            .get::<_, String>(1)
            .parse::<usize>()
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if object_count > limits.max_objects || byte_count > limits.max_bytes {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let fetch_limit = limits
            .max_objects
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let rows = self
            .client
            .query(
                "SELECT object_digest, canonical_bytes, validation_contract
                 FROM ogvcs_metadata.metadata_objects
                 WHERE repository_id = $1 AND object_kind = 3
                 ORDER BY object_digest
                 LIMIT $2",
                &[&uuid(repository_id), &fetch_limit],
            )
            .map_err(database_error)?;
        if rows.len() > limits.max_objects {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let mut trees = BTreeMap::new();
        let mut loaded_bytes = 0_usize;
        for row in rows {
            let reference = object_ref(ObjectKind::Tree, row.get(0))?;
            let canonical: Vec<u8> = row.get(1);
            let validation_contract: String = row.get(2);
            loaded_bytes = loaded_bytes
                .checked_add(canonical.len())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            if validation_contract != VALIDATION_CONTRACT
                || loaded_bytes > limits.max_bytes
                || object_id(ObjectKind::Tree, &canonical)
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
                    != reference.digest
                || trees.insert(reference, canonical).is_some()
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
        }
        if resolve_tree_prefix(&trees, root, prefix, limits.max_edges)? == tree {
            Ok(())
        } else {
            Err(not_found())
        }
    }

    fn require_published_snapshot(
        &mut self,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
    ) -> Result<()> {
        if snapshot.kind != ObjectKind::Snapshot {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let row = self
            .client
            .query_opt(
                "SELECT snapshot.published_commit_sequence, object.canonical_bytes,
                        object.validation_contract
                 FROM ogvcs_metadata.snapshots AS snapshot
                 JOIN ogvcs_metadata.metadata_objects AS object
                   ON object.repository_id = snapshot.repository_id
                  AND object.object_kind = 7
                  AND object.digest_algorithm = 1
                  AND object.object_digest = snapshot.snapshot_digest
                 WHERE snapshot.repository_id = $1 AND snapshot.snapshot_digest = $2",
                &[&uuid(repository_id), &&snapshot.digest[..]],
            )
            .map_err(database_error)?
            .ok_or_else(not_found)?;
        let published: Option<i64> = row.get(0);
        let canonical: Vec<u8> = row.get(1);
        let validation_contract: String = row.get(2);
        if published
            .and_then(|value| positive_u64(value).ok())
            .is_none()
            || validation_contract != VALIDATION_CONTRACT
            || object_id(ObjectKind::Snapshot, &canonical)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
                != snapshot.digest
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(())
    }

    fn load_ancestry(
        &mut self,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        maximum_depth: u32,
    ) -> Result<LoadedAncestry> {
        let fetch_limit = i32::try_from(MAX_HISTORY_WORK + 1)
            .map_err(|_| DomainError::new(DomainErrorCode::HistoryLimitReached))?;
        let rows = self
            .client
            .query(
                "SELECT traversal.snapshot_digest, traversal.traversal_depth,
                        traversal.visit_ordinal, traversal.has_parents,
                        snapshot.published_commit_sequence
                 FROM ogvcs_metadata.bounded_snapshot_ancestry($1, $2, $3, $4)
                      AS traversal
                 JOIN ogvcs_metadata.snapshots AS snapshot
                   ON snapshot.repository_id = $1
                  AND snapshot.snapshot_digest = traversal.snapshot_digest
                 ORDER BY traversal.visit_ordinal",
                &[
                    &uuid(repository_id),
                    &&snapshot.digest[..],
                    &i32::try_from(maximum_depth)
                        .map_err(|_| DomainError::new(DomainErrorCode::HistoryLimitReached))?,
                    &fetch_limit,
                ],
            )
            .map_err(database_error)?;
        let work_incomplete = rows.len() > MAX_HISTORY_WORK;
        let mut nodes = Vec::with_capacity(rows.len().min(MAX_HISTORY_WORK));
        let mut seen = BTreeSet::new();
        let mut previous_visit = 0_u32;
        let mut depth_incomplete = false;
        for row in rows.into_iter().take(MAX_HISTORY_WORK) {
            let reference = object_ref(ObjectKind::Snapshot, row.get(0))?;
            let depth = u32::try_from(row.get::<_, i32>(1))
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let visit = u32::try_from(row.get::<_, i32>(2))
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let has_parents: bool = row.get(3);
            let published: Option<i64> = row.get(4);
            if visit <= previous_visit
                || depth > maximum_depth
                || published
                    .and_then(|value| positive_u64(value).ok())
                    .is_none()
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            previous_visit = visit;
            if depth == maximum_depth && has_parents {
                depth_incomplete = true;
            }
            if seen.insert(reference) {
                nodes.push(AncestryNode {
                    snapshot: reference,
                    depth,
                    visit,
                });
            }
        }
        Ok(LoadedAncestry {
            nodes,
            incomplete_reason: if work_incomplete {
                Some(HistoryIncompleteReason::WorkLimit)
            } else if depth_incomplete {
                Some(HistoryIncompleteReason::DepthLimit)
            } else {
                None
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn load_snapshot_history_rows(
        &mut self,
        repository_id: RepositoryId,
        ancestry: &LoadedAncestry,
        file_id_filter: Option<FileId>,
        path_filter: Option<&[u8]>,
        after_visit: u32,
        after_ordinal: u32,
    ) -> Result<(Vec<LoadedHistoryRecord>, bool)> {
        if file_id_filter.is_some() == path_filter.is_some() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let digests = ancestry
            .nodes
            .iter()
            .map(|node| node.snapshot.digest.to_vec())
            .collect::<Vec<_>>();
        let visits = ancestry
            .nodes
            .iter()
            .map(|node| {
                i32::try_from(node.visit)
                    .map_err(|_| DomainError::new(DomainErrorCode::HistoryLimitReached))
            })
            .collect::<Result<Vec<_>>>()?;
        let depths = ancestry
            .nodes
            .iter()
            .map(|node| {
                i32::try_from(node.depth)
                    .map_err(|_| DomainError::new(DomainErrorCode::HistoryLimitReached))
            })
            .collect::<Result<Vec<_>>>()?;
        let file_id_filter = file_id_filter.map(|file_id| file_id.as_bytes().to_vec());
        let path_filter = path_filter.map(<[u8]>::to_vec);
        let after_visit = i32::try_from(after_visit)
            .map_err(|_| DomainError::new(DomainErrorCode::HistoryLimitReached))?;
        let after_ordinal = i32::try_from(after_ordinal)
            .map_err(|_| DomainError::new(DomainErrorCode::HistoryLimitReached))?;
        let rows = self
            .client
            .query(
                "SELECT history.snapshot_digest, history.operation_ordinal, history.file_id,
                        history.repository_path_utf8, history.operation_kind,
                        traversal.visit_ordinal, traversal.traversal_depth
                 FROM unnest($2::bytea[], $3::integer[], $4::integer[])
                      AS traversal(snapshot_digest, visit_ordinal, traversal_depth)
                 JOIN ogvcs_metadata.file_path_history AS history
                   ON history.repository_id = $1
                  AND history.snapshot_digest = traversal.snapshot_digest
                 WHERE ($5::bytea IS NULL OR history.file_id = $5)
                   AND ($6::bytea IS NULL OR history.repository_path_utf8 = $6)
                   AND (traversal.visit_ordinal, history.operation_ordinal) > ($7, $8)
                 ORDER BY traversal.visit_ordinal, history.operation_ordinal
                 LIMIT $9",
                &[
                    &uuid(repository_id),
                    &digests,
                    &visits,
                    &depths,
                    &file_id_filter,
                    &path_filter,
                    &after_visit,
                    &after_ordinal,
                    &((MAX_AUTHORIZATION_SCAN + 1) as i64),
                ],
            )
            .map_err(database_error)?;
        let truncated = rows.len() > MAX_AUTHORIZATION_SCAN;
        let mut records = Vec::with_capacity(rows.len().min(MAX_AUTHORIZATION_SCAN));
        for row in rows.into_iter().take(MAX_AUTHORIZATION_SCAN) {
            let snapshot = object_ref(ObjectKind::Snapshot, row.get(0))?;
            let operation_ordinal = u32::try_from(row.get::<_, i32>(1))
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let file_id = file_id(row.get(2))?;
            let repository_path_utf8: Vec<u8> = row.get(3);
            let operation_kind: String = row.get(4);
            let visit = u32::try_from(row.get::<_, i32>(5))
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let depth = u32::try_from(row.get::<_, i32>(6))
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            if repository_path_utf8.is_empty()
                || repository_path_utf8.len() > 4096
                || !matches!(
                    operation_kind.as_str(),
                    "create"
                        | "modify"
                        | "copy"
                        | "move"
                        | "rename"
                        | "delete"
                        | "restore"
                        | "import"
                )
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            records.push(LoadedHistoryRecord {
                record: FileHistoryRecord {
                    snapshot,
                    operation_ordinal,
                    file_id,
                    repository_path_utf8,
                    operation_kind,
                },
                visit,
                depth,
            });
        }
        Ok((records, truncated))
    }

    /// Opens the production metadata transaction and authorizes it through
    /// OGVCS-009 on that exact live PostgreSQL transaction. The returned
    /// adapter owns the transaction; callers cannot extract it or manufacture
    /// the authenticated scope used by idempotency and allocation receipts.
    fn begin_identity_authorized_inner(
        &mut self,
        credentials: TransactionCredentialRequest<'_>,
        tenant_id: TenantId,
        capability: TransactionCapability,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<PostgresMetadataTransaction<'_, V, IdentityMetadataAuthorizedView>> {
        crate::verify_schema_compatibility(&mut self.client)?;
        let participant = self
            .transaction_authorization
            .as_ref()
            .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        let tenant = identity_tenant_id(tenant_id);
        let repository = identity_repository_id(repository_id);
        let permission = capability.permission().as_str().to_owned();
        let resource = identity_repository_resource(capability);
        let isolation = match options {
            TransactionOptions::RepeatableRead => IsolationLevel::RepeatableRead,
            TransactionOptions::Serializable { .. } => IsolationLevel::Serializable,
        };
        let mut transaction = self
            .client
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .map_err(database_error)?;
        let view = match participant.authorize(
            &mut transaction,
            &TransactionAuthorizationRequest {
                request_id: credentials.request_id,
                credential_presentation: credentials.credential_presentation,
                tenant: &tenant,
                repository: &repository,
                permission: &permission,
                reason: credentials.reason,
                resource: &resource,
                reference: None,
                snapshot: None,
            },
        ) {
            Ok(view) => view,
            Err(_) => {
                let _ = transaction.rollback();
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
        };
        let repository_tenant = transaction
            .query_opt(
                "SELECT tenant_id FROM ogvcs_metadata.repositories WHERE repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?;
        if repository_tenant
            .is_some_and(|row| row.get::<_, Uuid>(0).as_bytes() != tenant_id.as_bytes())
        {
            poison_identity_transaction(&mut transaction);
            let _ = transaction.rollback();
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let context = AuthorizationContext {
            subject_digest: decode_identity_digest(view.subject_digest())?,
            tenant_id,
            authorization_epoch: view.authority_epoch(),
        };
        let authority_scope_digest = decode_identity_digest(view.authenticated_scope_digest())?;
        let authenticated_scope_digest = identity_metadata_scope_digest(
            authority_scope_digest,
            tenant_id,
            repository_id,
            capability,
        );
        let allocation_receipt_scope_digest = identity_metadata_scope_digest(
            authority_scope_digest,
            tenant_id,
            repository_id,
            TransactionCapability::ReserveFileId,
        );
        Ok(PostgresMetadataTransaction {
            transaction: Some(transaction),
            failed: false,
            commit_sequence: None,
            pending_idempotency: None,
            idempotency_committed: false,
            committed_replay: None,
            mutation_started: false,
            outbox_events: Vec::new(),
            capability,
            authorized_repository_id: repository_id,
            authorization_context: context.clone(),
            authorized_view: IdentityMetadataAuthorizedView {
                context,
                repository_id,
                permission: capability.permission(),
            },
            validation: &self.validation,
            authenticated_scope_digest,
            allocation_receipt_scope_digest,
            allocation_receipt_required: true,
            identity_binding: Some(IdentityTransactionBinding {
                participant,
                view,
                tenant,
                repository,
                permission,
                correlation_id: credentials.correlation_id.to_owned(),
                reference: None,
            }),
            identity_resources: vec![resource],
        })
    }

    /// Development/test adapter entry point. Production callers use
    /// `begin_identity_authorized`; this compatibility path never acquires an
    /// OGVCS-009 branded transaction view.
    pub fn begin_authorized(
        &mut self,
        context: &AuthorizationContext,
        capability: TransactionCapability,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<PostgresMetadataTransaction<'_, V, A::AuthorizedView>> {
        let resource = AuthorizationResource::RepositoryTransaction {
            repository_id,
            capability,
        };
        let authorized_view = self.authorize_exact(context, capability.permission(), &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        if let Some(row) = self
            .client
            .query_opt(
                "SELECT tenant_id FROM ogvcs_metadata.repositories WHERE repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?
        {
            let tenant_id: Uuid = row.get(0);
            if tenant_id.as_bytes() != context.tenant_id.as_bytes() {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
        }
        let isolation = match options {
            TransactionOptions::RepeatableRead => IsolationLevel::RepeatableRead,
            TransactionOptions::Serializable { .. } => IsolationLevel::Serializable,
        };
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(isolation)
            .start()
            .map_err(database_error)?;
        Ok(PostgresMetadataTransaction {
            transaction: Some(transaction),
            failed: false,
            commit_sequence: None,
            pending_idempotency: None,
            idempotency_committed: false,
            committed_replay: None,
            mutation_started: false,
            outbox_events: Vec::new(),
            capability,
            authorized_repository_id: repository_id,
            authorization_context: context.clone(),
            authorized_view,
            validation: &self.validation,
            authenticated_scope_digest: metadata_scope_digest(context, repository_id, capability),
            allocation_receipt_scope_digest: metadata_scope_digest(
                context,
                repository_id,
                capability,
            ),
            allocation_receipt_required: false,
            identity_binding: None,
            identity_resources: Vec::new(),
        })
    }

    /// Replays a caller-declared deterministic transaction after PostgreSQL
    /// serialization/deadlock failures. Domain conflicts are never retried.
    pub fn execute_serializable<T>(
        &mut self,
        context: &AuthorizationContext,
        capability: TransactionCapability,
        repository_id: RepositoryId,
        maximum_retries: u8,
        mut operation: impl FnMut(
            &mut PostgresMetadataTransaction<'_, V, A::AuthorizedView>,
        ) -> Result<T>,
    ) -> Result<(T, CommitSequence)> {
        for attempt in 0..=maximum_retries {
            let mut transaction = self.begin_authorized(
                context,
                capability,
                repository_id,
                TransactionOptions::Serializable { maximum_retries },
            )?;
            match operation(&mut transaction) {
                Ok(value) => match transaction.commit() {
                    Ok(sequence) => return Ok((value, sequence)),
                    Err(error) if error.is_database_concurrency() && attempt < maximum_retries => {}
                    Err(error) => return Err(error),
                },
                Err(error) if error.is_database_concurrency() && attempt < maximum_retries => {
                    let _ = transaction.rollback();
                }
                Err(error) => {
                    let _ = transaction.rollback();
                    return Err(error);
                }
            }
        }
        Err(DomainError::new(DomainErrorCode::TransactionRetryExhausted))
    }

    pub fn get_repository_settings(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        minimum: Option<&ConsistencyToken>,
    ) -> Result<RepositorySettings> {
        let resource = AuthorizationResource::Repository { repository_id };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        let row = self
            .client
            .query_opt(
                "SELECT settings.repository_format, settings.required_features,
                        settings.case_mode, settings.path_profile, settings.platform_profile,
                        settings.content_policy_profile, settings.structural_limits,
                        settings.tenant_boundary, settings.settings_generation,
                        settings.descriptor_digest, descriptor.canonical_bytes,
                        descriptor.validation_contract
                 FROM ogvcs_metadata.repository_settings AS settings
                 JOIN ogvcs_metadata.metadata_objects AS descriptor
                   ON descriptor.repository_id = settings.repository_id
                  AND descriptor.object_kind = 6
                  AND descriptor.digest_algorithm = 1
                  AND descriptor.object_digest = settings.descriptor_digest
                 WHERE settings.repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?
            .ok_or_else(not_found)?;
        let settings = repository_settings_record(&row, repository_id, context.tenant_id)?;
        if !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        Ok(settings)
    }

    pub fn repository_page(
        &mut self,
        context: &AuthorizationContext,
        project_id: crate::ProjectId,
        request: PageRequest,
    ) -> Result<Page<RepositoryRecord>> {
        let resource = AuthorizationResource::ProjectRepositories {
            tenant_id: context.tenant_id,
            project_id,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::Discover, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        if !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let after =
            self.repository_list_cursor_position(context, project_id, request.cursor.as_ref())?;
        let after = after.map(uuid);
        let rows = self
            .client
            .query(
                "SELECT repository_id
                 FROM ogvcs_metadata.repositories
                 WHERE tenant_id = $1 AND project_id = $2
                   AND ($3::uuid IS NULL OR repository_id > $3)
                 ORDER BY repository_id
                 LIMIT $4",
                &[
                    &uuid(context.tenant_id),
                    &uuid(project_id),
                    &after,
                    &((MAX_AUTHORIZATION_SCAN + 1) as i64),
                ],
            )
            .map_err(database_error)?;
        let truncated = rows.len() > MAX_AUTHORIZATION_SCAN;
        let mut items = Vec::with_capacity(usize::from(request.limit) + 1);
        for row in rows.iter().take(MAX_AUTHORIZATION_SCAN) {
            let repository_uuid: Uuid = row.get(0);
            let repository_id = RepositoryId::from_bytes(*repository_uuid.as_bytes());
            let exact = AuthorizationResource::ProjectRepository {
                tenant_id: context.tenant_id,
                project_id,
                repository_id,
            };
            if authorized_view.permits(context, MetadataPermission::Discover, &exact) {
                items.push(RepositoryRecord {
                    repository_id,
                    project_id,
                });
                if items.len() > usize::from(request.limit) {
                    break;
                }
            }
        }
        if truncated && items.len() <= usize::from(request.limit) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        if !authorized_view.permits(context, MetadataPermission::Discover, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let has_more = items.len() > usize::from(request.limit);
        items.truncate(usize::from(request.limit));
        let next_cursor = if has_more {
            let last = items.last().ok_or_else(not_found)?;
            Some(self.issue_repository_list_cursor(context, project_id, last.repository_id)?)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    pub fn get_object(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        reference: ObjectRef,
        minimum: Option<&ConsistencyToken>,
    ) -> Result<MetadataObjectRecord> {
        let resource = AuthorizationResource::MetadataObject {
            repository_id,
            object_ref: reference,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if !metadata_kind(reference.kind) {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let row = self
            .client
            .query_opt(
                "SELECT canonical_bytes, validation_contract
                 FROM ogvcs_metadata.metadata_objects
                 WHERE repository_id = $1 AND object_kind = $2
                   AND digest_algorithm = 1 AND object_digest = $3",
                &[
                    &uuid(repository_id),
                    &(reference.kind.code() as i16),
                    &&reference.digest[..],
                ],
            )
            .map_err(database_error)?
            .ok_or_else(not_found)?;
        let canonical_bytes: Vec<u8> = row.get(0);
        let validation_contract: String = row.get(1);
        let scanned = scan_metadata(&canonical_bytes, Limits::METADATA)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let kind = validate_metadata_schema(&scanned)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let digest = object_id(kind, &canonical_bytes)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if validation_contract != VALIDATION_CONTRACT
            || kind != reference.kind
            || digest != reference.digest
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        if !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        Ok(MetadataObjectRecord {
            object_ref: reference,
            canonical_bytes,
        })
    }

    pub fn read_reference(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        kind: ReferenceKind,
        name: &ReferenceName,
        minimum: Option<&ConsistencyToken>,
    ) -> Result<ReferenceRecord> {
        let resource = AuthorizationResource::Reference {
            repository_id,
            kind,
            name: name.clone(),
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        let row = self
            .client
            .query_opt(
                "SELECT reference.target_snapshot_digest, reference.generation,
                        reference.commit_sequence, snapshot.published_commit_sequence
                 FROM ogvcs_metadata.references AS reference
                 JOIN ogvcs_metadata.snapshots AS snapshot
                   ON snapshot.repository_id = reference.repository_id
                  AND snapshot.snapshot_digest = reference.target_snapshot_digest
                 WHERE reference.repository_id = $1 AND reference.reference_kind = $2
                   AND reference.reference_name = $3",
                &[&uuid(repository_id), &reference_kind(kind), &name.as_str()],
            )
            .map_err(database_error)?
            .ok_or_else(not_found)?;
        let published: Option<i64> = row.get(3);
        if published
            .and_then(|value| positive_u64(value).ok())
            .is_none()
            || !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource)
        {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        Ok(ReferenceRecord {
            kind,
            name: name.clone(),
            target: object_ref(ObjectKind::Snapshot, row.get(0))?,
            generation: positive_u64(row.get(1))?,
            commit_sequence: CommitSequence::new(nonnegative_u64(row.get(2))?),
        })
    }

    pub fn require_consistency(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        token: &ConsistencyToken,
    ) -> Result<CommitSequence> {
        let resource = AuthorizationResource::Repository { repository_id };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        let sequence = self.require_consistency_authorized(context, repository_id, token)?;
        if !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        Ok(sequence)
    }

    fn require_consistency_authorized(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        token: &ConsistencyToken,
    ) -> Result<CommitSequence> {
        let digest = Sha256::digest(token.as_str().as_bytes()).to_vec();
        let row = self
            .client
            .query_opt(
                "SELECT minimum_commit_sequence
                 FROM ogvcs_metadata.consistency_tokens
                 WHERE token_digest = $1 AND subject_digest = $2 AND tenant_id = $3
                   AND repository_id = $4 AND authorization_epoch = $5
                   AND authenticated_scope_digest IS NULL
                   AND expires_at > clock_timestamp()",
                &[
                    &digest,
                    &&context.subject_digest[..],
                    &uuid(context.tenant_id),
                    &uuid(repository_id),
                    &(context.authorization_epoch as i64),
                ],
            )
            .map_err(database_error)?
            .ok_or_else(|| DomainError::new(DomainErrorCode::ConsistencyTokenUnsatisfied))?;
        let minimum = nonnegative_u64(row.get(0))?;
        let observed: i64 = self
            .client
            .query_one(
                "SELECT applied_sequence FROM ogvcs_metadata.repository_commit_sequences WHERE repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?
            .get(0);
        if nonnegative_u64(observed)? < minimum {
            return Err(DomainError::new(
                DomainErrorCode::ConsistencyTokenUnsatisfied,
            ));
        }
        Ok(CommitSequence::new(minimum))
    }

    /// Atomically leases the oldest currently deliverable events in this
    /// authenticated tenant. Concurrent consumers cannot receive the same
    /// active lease because selection and update share one row-lock statement.
    pub fn claim_outbox(
        &mut self,
        context: &AuthorizationContext,
        request: OutboxClaimRequest,
    ) -> Result<Vec<OutboxLeaseRecord>> {
        let resource = AuthorizationResource::OutboxCollection {
            tenant_id: context.tenant_id,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::ServiceInternal, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        if !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        if request.maximum_items == 0 || request.lease_seconds == 0 {
            if !authorized_view.permits(context, MetadataPermission::ServiceInternal, &resource) {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
            return Ok(Vec::new());
        }
        let lease_id = random_public_uuid()?;
        let mut transaction = self.client.transaction().map_err(database_error)?;
        let rows = transaction
            .query(
                "WITH candidates AS (
                    SELECT event_id
                    FROM ogvcs_metadata.outbox_events
                    WHERE tenant_id = $1
                      AND acknowledged_at IS NULL
                      AND available_at <= clock_timestamp()
                      AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
                    ORDER BY available_at, event_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT $2
                 )
                 UPDATE ogvcs_metadata.outbox_events AS event
                 SET lease_id = $3, leased_by = $4,
                     lease_expires_at = clock_timestamp() + ($5::bigint * interval '1 second'),
                     delivery_attempts = delivery_attempts + 1
                 FROM candidates
                 WHERE event.event_id = candidates.event_id
                 RETURNING event.event_id, event.event_type, event.event_version,
                           event.tenant_id, event.repository_id, event.commit_sequence,
                           event.correlation_id, event.resource_type,
                           event.resource_opaque_id, event.safe_payload,
                           event.lease_id, event.leased_by, event.lease_expires_at,
                           event.delivery_attempts",
                &[
                    &uuid(context.tenant_id),
                    &i64::from(request.maximum_items),
                    &Uuid::from_bytes(lease_id),
                    &request.consumer_id,
                    &i64::from(request.lease_seconds),
                ],
            )
            .map_err(database_error)?;
        let leases = rows
            .iter()
            .map(outbox_lease_record)
            .collect::<Result<Vec<_>>>()?;
        if !authorized_view.permits(context, MetadataPermission::ServiceInternal, &resource) {
            transaction.rollback().map_err(database_error)?;
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        transaction.commit().map_err(database_error)?;
        Ok(leases)
    }

    /// Acknowledges only the caller's exact, still-live lease. The update also
    /// clears every lease field so an acknowledged row cannot be reclaimed.
    pub fn acknowledge_outbox(
        &mut self,
        context: &AuthorizationContext,
        request: OutboxLeaseAction,
    ) -> Result<()> {
        if !request.is_valid() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let resource = AuthorizationResource::OutboxDeliveryEvent {
            tenant_id: context.tenant_id,
            event_id: request.event_id,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::ServiceInternal, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        let mut transaction = self.client.transaction().map_err(database_error)?;
        let updated = transaction
            .execute(
                "UPDATE ogvcs_metadata.outbox_events
                 SET acknowledged_at = clock_timestamp(),
                     lease_id = NULL, leased_by = NULL, lease_expires_at = NULL
                 WHERE tenant_id = $1 AND event_id = $2 AND lease_id = $3
                   AND leased_by = $4 AND acknowledged_at IS NULL
                   AND lease_expires_at > clock_timestamp()",
                &[
                    &uuid(context.tenant_id),
                    &Uuid::from_bytes(request.event_id),
                    &Uuid::from_bytes(request.lease_id),
                    &request.consumer_id,
                ],
            )
            .map_err(database_error)?;
        if updated != 1
            || !authorized_view.permits(context, MetadataPermission::ServiceInternal, &resource)
        {
            transaction.rollback().map_err(database_error)?;
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        transaction.commit().map_err(database_error)
    }

    /// Releases only the exact live lease and moves its next availability
    /// monotonically forward by the bounded retry delay.
    pub fn release_outbox(
        &mut self,
        context: &AuthorizationContext,
        request: OutboxReleaseRequest,
    ) -> Result<()> {
        if !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let resource = AuthorizationResource::OutboxDeliveryEvent {
            tenant_id: context.tenant_id,
            event_id: request.lease.event_id,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::ServiceInternal, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        let mut transaction = self.client.transaction().map_err(database_error)?;
        let updated = transaction
            .execute(
                "UPDATE ogvcs_metadata.outbox_events
                 SET available_at = GREATEST(
                         available_at,
                         clock_timestamp() + ($5::bigint * interval '1 second')
                     ),
                     lease_id = NULL, leased_by = NULL, lease_expires_at = NULL
                 WHERE tenant_id = $1 AND event_id = $2 AND lease_id = $3
                   AND leased_by = $4 AND acknowledged_at IS NULL
                   AND lease_expires_at > clock_timestamp()",
                &[
                    &uuid(context.tenant_id),
                    &Uuid::from_bytes(request.lease.event_id),
                    &Uuid::from_bytes(request.lease.lease_id),
                    &request.lease.consumer_id,
                    &i64::from(request.retry_after_seconds),
                ],
            )
            .map_err(database_error)?;
        if updated != 1
            || !authorized_view.permits(context, MetadataPermission::ServiceInternal, &resource)
        {
            transaction.rollback().map_err(database_error)?;
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        transaction.commit().map_err(database_error)
    }

    pub fn tree_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        tree: ObjectRef,
        prefix: &[String],
        request: PageRequest,
    ) -> Result<Page<TreeEntryRecord>> {
        self.tree_page_consistent(
            context,
            repository_id,
            snapshot,
            tree,
            prefix,
            None,
            request,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tree_page_consistent(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        tree: ObjectRef,
        prefix: &[String],
        minimum: Option<&ConsistencyToken>,
        request: PageRequest,
    ) -> Result<Page<TreeEntryRecord>> {
        if !valid_tree_prefix(prefix) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let resource = AuthorizationResource::TreePrefix {
            repository_id,
            snapshot,
            tree,
            prefix: prefix.to_vec(),
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if snapshot.kind != ObjectKind::Snapshot
            || tree.kind != ObjectKind::Tree
            || !request.is_bounded()
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        self.require_published_snapshot_tree(repository_id, snapshot, tree, prefix)?;
        let query_digest = tree_query_digest(repository_id, snapshot, tree, prefix);
        let after = self.cursor_position(
            context,
            repository_id,
            "tree.page",
            query_digest,
            request.cursor.as_ref(),
            "key",
        )?;
        let rows = self
            .client
            .query(
                "SELECT ordinal, basename_utf8, file_id, entry_kind, target_kind, target_digest,
                        logical_size::text
                 FROM ogvcs_metadata.tree_entries
                 WHERE repository_id = $1 AND tree_digest = $2
                   AND ($3::bytea IS NULL OR basename_utf8 > $3)
                 ORDER BY basename_utf8
                 LIMIT $4",
                &[
                    &uuid(repository_id),
                    &&tree.digest[..],
                    &after,
                    &((MAX_AUTHORIZATION_SCAN + 1) as i64),
                ],
            )
            .map_err(database_error)?;
        let truncated = rows.len() > MAX_AUTHORIZATION_SCAN;
        let mut items = Vec::with_capacity(usize::from(request.limit) + 1);
        for row in rows.into_iter().take(MAX_AUTHORIZATION_SCAN) {
            let basename_utf8: Vec<u8> = row.get(1);
            let basename = String::from_utf8(basename_utf8)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let mut repository_path = prefix.to_vec();
            repository_path.push(basename);
            let exact = AuthorizationResource::TreeEntry {
                repository_id,
                snapshot,
                tree,
                repository_path,
                file_id: file_id(row.get(2))?,
            };
            if authorized_view.permits(context, MetadataPermission::MetadataRead, &exact) {
                items.push(tree_entry(row)?);
                if items.len() > usize::from(request.limit) {
                    break;
                }
            }
        }
        if truncated && items.len() <= usize::from(request.limit) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let has_more = items.len() > usize::from(request.limit);
        items.truncate(usize::from(request.limit));
        if !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let next_cursor = if has_more {
            let key = items
                .last()
                .map(|item| item.basename_utf8.clone())
                .ok_or_else(not_found)?;
            Some(self.issue_cursor(
                context,
                repository_id,
                "tree.page",
                query_digest,
                Some(tree),
                "key",
                &key,
            )?)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    pub fn reference_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        request: PageRequest,
    ) -> Result<Page<ReferenceRecord>> {
        self.reference_page_filtered(context, repository_id, ReferenceFilter::All, None, request)
    }

    pub fn reference_page_filtered(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        filter: ReferenceFilter,
        minimum: Option<&ConsistencyToken>,
        request: PageRequest,
    ) -> Result<Page<ReferenceRecord>> {
        let resource = AuthorizationResource::ReferenceCollection { repository_id };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::Discover, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let kind_filter = match filter {
            ReferenceFilter::All => None,
            ReferenceFilter::Kind(kind) => Some(reference_kind(kind)),
        };
        let query_digest = query_digest(
            b"reference",
            repository_id,
            kind_filter.unwrap_or("all").as_bytes(),
            &[],
        );
        let after = self.cursor_position(
            context,
            repository_id,
            "reference.list",
            query_digest,
            request.cursor.as_ref(),
            "key",
        )?;
        let (after_kind, after_name) = decode_reference_key(after.as_deref())?;
        let rows = self
            .client
            .query(
                "SELECT reference.reference_kind, reference.reference_name,
                        reference.target_snapshot_digest, reference.generation,
                        reference.commit_sequence, snapshot.published_commit_sequence
                 FROM ogvcs_metadata.references AS reference
                 JOIN ogvcs_metadata.snapshots AS snapshot
                   ON snapshot.repository_id = reference.repository_id
                  AND snapshot.snapshot_digest = reference.target_snapshot_digest
                 WHERE reference.repository_id = $1
                   AND ($2::text IS NULL OR reference.reference_kind = $2)
                   AND ($3::text IS NULL OR
                        (reference.reference_kind, reference.reference_name) > ($3, $4))
                 ORDER BY reference.reference_kind, reference.reference_name
                 LIMIT $5",
                &[
                    &uuid(repository_id),
                    &kind_filter,
                    &after_kind,
                    &after_name,
                    &((MAX_AUTHORIZATION_SCAN + 1) as i64),
                ],
            )
            .map_err(database_error)?;
        let truncated = rows.len() > MAX_AUTHORIZATION_SCAN;
        let mut items = Vec::with_capacity(usize::from(request.limit) + 1);
        for row in rows.iter().take(MAX_AUTHORIZATION_SCAN) {
            let kind = parsed_reference_kind(&row.get::<_, String>(0))?;
            let name = ReferenceName::new(row.get(1))
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let exact = AuthorizationResource::Reference {
                repository_id,
                kind,
                name,
            };
            if authorized_view.permits(context, MetadataPermission::Discover, &exact) {
                let published: Option<i64> = row.get(5);
                if published
                    .and_then(|value| positive_u64(value).ok())
                    .is_none()
                {
                    return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                }
                items.push(reference_record(row)?);
                if items.len() > usize::from(request.limit) {
                    break;
                }
            }
        }
        if truncated && items.len() <= usize::from(request.limit) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let has_more = items.len() > usize::from(request.limit);
        items.truncate(usize::from(request.limit));
        if !authorized_view.permits(context, MetadataPermission::Discover, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let next_cursor = if has_more {
            let item = items.last().ok_or_else(not_found)?;
            let key = reference_key(reference_kind(item.kind), item.name.as_str())?;
            Some(self.issue_cursor(
                context,
                repository_id,
                "reference.list",
                query_digest,
                None,
                "key",
                &key,
            )?)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    pub fn ancestry_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        maximum_depth: u32,
        minimum: Option<&ConsistencyToken>,
        request: PageRequest,
    ) -> Result<HistoryPage<AncestryRecord>> {
        let resource = AuthorizationResource::SnapshotHistory {
            repository_id,
            snapshot,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if maximum_depth > MAX_HISTORY_DEPTH || !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::HistoryLimitReached));
        }
        self.require_published_snapshot(repository_id, snapshot)?;
        let query_digest = query_digest(
            b"history.ancestry-page",
            repository_id,
            &snapshot.digest,
            &maximum_depth.to_be_bytes(),
        );
        let after = self.cursor_position(
            context,
            repository_id,
            "history.ancestry-page",
            query_digest,
            request.cursor.as_ref(),
            "visit",
        )?;
        let after = decode_visit(after.as_deref())?;
        let loaded = self.load_ancestry(repository_id, snapshot, maximum_depth)?;
        let mut authorized = Vec::with_capacity(usize::from(request.limit) + 1);
        let mut complete_traversal_visible = true;
        for node in &loaded.nodes {
            let exact = AuthorizationResource::SnapshotHistoryEntry {
                repository_id,
                root_snapshot: snapshot,
                snapshot: node.snapshot,
                depth: node.depth,
            };
            let permitted =
                authorized_view.permits(context, MetadataPermission::MetadataRead, &exact);
            complete_traversal_visible &= permitted;
            if permitted && node.visit > after {
                authorized.push((
                    AncestryRecord {
                        snapshot: node.snapshot,
                        depth: node.depth,
                    },
                    node.visit,
                ));
            }
        }
        if !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let has_more = authorized.len() > usize::from(request.limit);
        authorized.truncate(usize::from(request.limit));
        let next_cursor = if has_more {
            let visit = authorized
                .last()
                .map(|(_, visit)| visit.to_be_bytes())
                .ok_or_else(not_found)?;
            Some(self.issue_cursor(
                context,
                repository_id,
                "history.ancestry-page",
                query_digest,
                Some(snapshot),
                "visit",
                &visit,
            )?)
        } else {
            None
        };
        let incomplete_reason = complete_traversal_visible
            .then_some(loaded.incomplete_reason)
            .flatten();
        let state = if has_more {
            PageState::More
        } else if incomplete_reason.is_some() {
            PageState::Incomplete
        } else {
            PageState::Complete
        };
        Ok(HistoryPage {
            state,
            items: authorized.into_iter().map(|(item, _)| item).collect(),
            next_cursor,
            incomplete_reason: (!has_more).then_some(incomplete_reason).flatten(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn history_file_id_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        file_id: FileId,
        maximum_depth: u32,
        minimum: Option<&ConsistencyToken>,
        request: PageRequest,
    ) -> Result<HistoryPage<FileHistoryRecord>> {
        let resource = AuthorizationResource::SnapshotFileHistory {
            repository_id,
            root_snapshot: snapshot,
            file_id,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if maximum_depth > MAX_HISTORY_DEPTH || !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::HistoryLimitReached));
        }
        self.require_published_snapshot(repository_id, snapshot)?;
        let query_digest = snapshot_history_query_digest(
            b"history.file-id-page",
            repository_id,
            snapshot,
            maximum_depth,
            file_id.as_bytes(),
        );
        let after = self.cursor_position(
            context,
            repository_id,
            "history.file-id-page",
            query_digest,
            request.cursor.as_ref(),
            "key",
        )?;
        let (after_visit, after_ordinal) = decode_snapshot_history_key(after.as_deref())?;
        let ancestry = self.load_ancestry(repository_id, snapshot, maximum_depth)?;
        let complete_traversal_visible = ancestry.nodes.iter().all(|node| {
            authorized_view.permits(
                context,
                MetadataPermission::MetadataRead,
                &AuthorizationResource::SnapshotHistoryEntry {
                    repository_id,
                    root_snapshot: snapshot,
                    snapshot: node.snapshot,
                    depth: node.depth,
                },
            )
        });
        let (rows, truncated) = self.load_snapshot_history_rows(
            repository_id,
            &ancestry,
            Some(file_id),
            None,
            after_visit,
            after_ordinal,
        )?;
        let mut items = Vec::with_capacity(usize::from(request.limit) + 1);
        for row in rows {
            let exact = AuthorizationResource::SnapshotFileHistoryEntry {
                repository_id,
                root_snapshot: snapshot,
                snapshot: row.record.snapshot,
                depth: row.depth,
                file_id: row.record.file_id,
                repository_path_utf8: row.record.repository_path_utf8.clone(),
            };
            if authorized_view.permits(context, MetadataPermission::MetadataRead, &exact) {
                items.push(row);
                if items.len() > usize::from(request.limit) {
                    break;
                }
            }
        }
        self.finish_snapshot_history_page(
            context,
            repository_id,
            snapshot,
            "history.file-id-page",
            query_digest,
            request.limit,
            complete_traversal_visible
                .then_some(ancestry.incomplete_reason)
                .flatten(),
            truncated,
            authorized_view.permits(context, MetadataPermission::MetadataRead, &resource),
            items,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn history_path_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        path: &[String],
        maximum_depth: u32,
        minimum: Option<&ConsistencyToken>,
        request: PageRequest,
    ) -> Result<HistoryPage<FileHistoryRecord>> {
        if path.is_empty() || !valid_tree_prefix(path) {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let repository_path_utf8 = path.join("/").into_bytes();
        let resource = AuthorizationResource::SnapshotPathHistory {
            repository_id,
            root_snapshot: snapshot,
            repository_path_utf8: repository_path_utf8.clone(),
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if maximum_depth > MAX_HISTORY_DEPTH || !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::HistoryLimitReached));
        }
        self.require_published_snapshot(repository_id, snapshot)?;
        let query_digest = snapshot_history_query_digest(
            b"history.path-page",
            repository_id,
            snapshot,
            maximum_depth,
            &repository_path_utf8,
        );
        let after = self.cursor_position(
            context,
            repository_id,
            "history.path-page",
            query_digest,
            request.cursor.as_ref(),
            "key",
        )?;
        let (after_visit, after_ordinal) = decode_snapshot_history_key(after.as_deref())?;
        let ancestry = self.load_ancestry(repository_id, snapshot, maximum_depth)?;
        let complete_traversal_visible = ancestry.nodes.iter().all(|node| {
            authorized_view.permits(
                context,
                MetadataPermission::MetadataRead,
                &AuthorizationResource::SnapshotHistoryEntry {
                    repository_id,
                    root_snapshot: snapshot,
                    snapshot: node.snapshot,
                    depth: node.depth,
                },
            )
        });
        let (rows, truncated) = self.load_snapshot_history_rows(
            repository_id,
            &ancestry,
            None,
            Some(&repository_path_utf8),
            after_visit,
            after_ordinal,
        )?;
        let mut items = Vec::with_capacity(usize::from(request.limit) + 1);
        for row in rows {
            let exact = AuthorizationResource::SnapshotFileHistoryEntry {
                repository_id,
                root_snapshot: snapshot,
                snapshot: row.record.snapshot,
                depth: row.depth,
                file_id: row.record.file_id,
                repository_path_utf8: row.record.repository_path_utf8.clone(),
            };
            if authorized_view.permits(context, MetadataPermission::MetadataRead, &exact) {
                items.push(row);
                if items.len() > usize::from(request.limit) {
                    break;
                }
            }
        }
        self.finish_snapshot_history_page(
            context,
            repository_id,
            snapshot,
            "history.path-page",
            query_digest,
            request.limit,
            complete_traversal_visible
                .then_some(ancestry.incomplete_reason)
                .flatten(),
            truncated,
            authorized_view.permits(context, MetadataPermission::MetadataRead, &resource),
            items,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_snapshot_history_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        snapshot: ObjectRef,
        operation: &str,
        query_digest: [u8; 32],
        limit: u16,
        incomplete_reason: Option<HistoryIncompleteReason>,
        truncated: bool,
        authorization_still_valid: bool,
        mut rows: Vec<LoadedHistoryRecord>,
    ) -> Result<HistoryPage<FileHistoryRecord>> {
        if truncated && rows.len() <= usize::from(limit) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        if !authorization_still_valid {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let has_more = rows.len() > usize::from(limit);
        rows.truncate(usize::from(limit));
        let next_cursor = if has_more {
            let row = rows.last().ok_or_else(not_found)?;
            let key = snapshot_history_key(row.visit, row.record.operation_ordinal)?;
            Some(self.issue_cursor(
                context,
                repository_id,
                operation,
                query_digest,
                Some(snapshot),
                "key",
                &key,
            )?)
        } else {
            None
        };
        let state = if has_more {
            PageState::More
        } else if incomplete_reason.is_some() {
            PageState::Incomplete
        } else {
            PageState::Complete
        };
        Ok(HistoryPage {
            state,
            items: rows.into_iter().map(|row| row.record).collect(),
            next_cursor,
            incomplete_reason: (!has_more).then_some(incomplete_reason).flatten(),
        })
    }

    pub fn file_history_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        file_id: FileId,
        request: PageRequest,
    ) -> Result<Page<FileHistoryRecord>> {
        self.file_history_page_consistent(context, repository_id, file_id, None, request)
    }

    pub fn file_history_page_consistent(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        file_id: FileId,
        minimum: Option<&ConsistencyToken>,
        request: PageRequest,
    ) -> Result<Page<FileHistoryRecord>> {
        let resource = AuthorizationResource::FileHistory {
            repository_id,
            file_id,
        };
        let authorized_view =
            self.authorize_exact(context, MetadataPermission::MetadataRead, &resource)?;
        crate::verify_schema_compatibility(&mut self.client)?;
        self.require_repository_tenant(context, repository_id)?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        if !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::HistoryLimitReached));
        }
        let query_digest = query_digest(b"history", repository_id, file_id.as_bytes(), &[]);
        let after = self.cursor_position(
            context,
            repository_id,
            "file-id.history",
            query_digest,
            request.cursor.as_ref(),
            "key",
        )?;
        let (after_digest, after_ordinal) = decode_history_key(after.as_deref())?;
        let rows = self
            .client
            .query(
                "SELECT history.snapshot_digest, history.operation_ordinal,
                        history.repository_path_utf8, history.operation_kind
                 FROM ogvcs_metadata.file_path_history AS history
                 JOIN ogvcs_metadata.snapshots AS snapshot
                   ON snapshot.repository_id = history.repository_id
                  AND snapshot.snapshot_digest = history.snapshot_digest
                  AND snapshot.published_commit_sequence > 0
                 WHERE history.repository_id = $1 AND history.file_id = $2
                   AND ($3::bytea IS NULL OR
                        (history.snapshot_digest, history.operation_ordinal) > ($3, $4))
                 ORDER BY history.snapshot_digest, history.operation_ordinal
                 LIMIT $5",
                &[
                    &uuid(repository_id),
                    &&file_id.as_bytes()[..],
                    &after_digest,
                    &after_ordinal,
                    &((MAX_AUTHORIZATION_SCAN + 1) as i64),
                ],
            )
            .map_err(database_error)?;
        let truncated = rows.len() > MAX_AUTHORIZATION_SCAN;
        let mut items = Vec::with_capacity(usize::from(request.limit) + 1);
        for row in rows.iter().take(MAX_AUTHORIZATION_SCAN) {
            let record = file_history_record(row, file_id)?;
            let exact = AuthorizationResource::FileHistoryEntry {
                repository_id,
                file_id,
                snapshot: record.snapshot,
                repository_path_utf8: record.repository_path_utf8.clone(),
            };
            if authorized_view.permits(context, MetadataPermission::MetadataRead, &exact) {
                items.push(record);
                if items.len() > usize::from(request.limit) {
                    break;
                }
            }
        }
        if truncated && items.len() <= usize::from(request.limit) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let has_more = items.len() > usize::from(request.limit);
        items.truncate(usize::from(request.limit));
        if !authorized_view.permits(context, MetadataPermission::MetadataRead, &resource) {
            return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
        }
        let next_cursor = if has_more {
            let item = items.last().ok_or_else(not_found)?;
            let ordinal = i32::try_from(item.operation_ordinal)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let key = history_key(&item.snapshot.digest, ordinal)?;
            Some(self.issue_cursor(
                context,
                repository_id,
                "file-id.history",
                query_digest,
                Some(item.snapshot),
                "key",
                &key,
            )?)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    fn repository_list_cursor_position(
        &mut self,
        context: &AuthorizationContext,
        project_id: crate::ProjectId,
        cursor: Option<&CursorToken>,
    ) -> Result<Option<RepositoryId>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let authorization_epoch = i64::try_from(context.authorization_epoch)
            .map_err(|_| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        let digest = Sha256::digest(cursor.as_str().as_bytes()).to_vec();
        let row = self
            .client
            .query_opt(
                "SELECT position_repository_id
                 FROM ogvcs_metadata.repository_list_cursor_states
                 WHERE token_digest = $1 AND subject_digest = $2 AND tenant_id = $3
                   AND project_id = $4 AND authorization_epoch = $5
                   AND expires_at > clock_timestamp()",
                &[
                    &digest,
                    &&context.subject_digest[..],
                    &uuid(context.tenant_id),
                    &uuid(project_id),
                    &authorization_epoch,
                ],
            )
            .map_err(database_error)?
            .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        let position: Uuid = row.get(0);
        Ok(Some(RepositoryId::from_bytes(*position.as_bytes())))
    }

    fn issue_repository_list_cursor(
        &mut self,
        context: &AuthorizationContext,
        project_id: crate::ProjectId,
        position: RepositoryId,
    ) -> Result<CursorToken> {
        let token = opaque_token("cur1.")?;
        let cursor = CursorToken::from_opaque(token.clone())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let digest = Sha256::digest(token.as_bytes()).to_vec();
        let authorization_epoch = i64::try_from(context.authorization_epoch)
            .map_err(|_| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        self.client
            .execute(
                "INSERT INTO ogvcs_metadata.repository_list_cursor_states
                 (token_digest, subject_digest, tenant_id, project_id,
                  position_repository_id, authorization_epoch, issued_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6,
                         clock_timestamp(), clock_timestamp() + interval '1 day')",
                &[
                    &digest,
                    &&context.subject_digest[..],
                    &uuid(context.tenant_id),
                    &uuid(project_id),
                    &uuid(position),
                    &authorization_epoch,
                ],
            )
            .map_err(database_error)?;
        Ok(cursor)
    }

    fn cursor_position(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        operation: &str,
        query_digest: [u8; 32],
        cursor: Option<&CursorToken>,
        field: &str,
    ) -> Result<Option<Vec<u8>>> {
        let Some(cursor) = cursor else {
            return Ok(None);
        };
        let digest = Sha256::digest(cursor.as_str().as_bytes()).to_vec();
        let row = self
            .client
            .query_opt(
                "SELECT position
                 FROM ogvcs_metadata.cursor_states
                 WHERE token_digest = $1 AND subject_digest = $2 AND tenant_id = $3
                   AND repository_id = $4 AND operation = $5 AND query_digest = $6
                   AND authorization_epoch = $7 AND expires_at > clock_timestamp()",
                &[
                    &digest,
                    &&context.subject_digest[..],
                    &uuid(context.tenant_id),
                    &uuid(repository_id),
                    &operation,
                    &&query_digest[..],
                    &(context.authorization_epoch as i64),
                ],
            )
            .map_err(database_error)?
            .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        let Json(position): Json<Value> = row.get(0);
        let encoded = position
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map(Some)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_cursor(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        operation: &str,
        query_digest: [u8; 32],
        bound: Option<ObjectRef>,
        field: &str,
        position: &[u8],
    ) -> Result<CursorToken> {
        let token = opaque_token("cur1.")?;
        let cursor = CursorToken::from_opaque(token.clone())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let digest = Sha256::digest(token.as_bytes()).to_vec();
        let mut position_map = Map::new();
        position_map.insert(
            field.to_owned(),
            Value::String(URL_SAFE_NO_PAD.encode(position)),
        );
        let position = Value::Object(position_map);
        let (kind, object_digest) = bound
            .map(|object| {
                (
                    Some(i16::try_from(object.kind.code()).unwrap()),
                    Some(object.digest.to_vec()),
                )
            })
            .unwrap_or((None, None));
        self.client
            .execute(
                "INSERT INTO ogvcs_metadata.cursor_states
                 (token_digest, subject_digest, tenant_id, repository_id, operation, query_digest,
                  bound_object_kind, bound_object_digest, position, authorization_epoch,
                  issued_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         clock_timestamp(), clock_timestamp() + interval '1 day')",
                &[
                    &digest,
                    &&context.subject_digest[..],
                    &uuid(context.tenant_id),
                    &uuid(repository_id),
                    &operation,
                    &&query_digest[..],
                    &kind,
                    &object_digest,
                    &Json(&position),
                    &(context.authorization_epoch as i64),
                ],
            )
            .map_err(database_error)?;
        Ok(cursor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingIdempotency {
    operation: String,
    key: String,
    semantic_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AncestryNode {
    snapshot: ObjectRef,
    depth: u32,
    visit: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedAncestry {
    nodes: Vec<AncestryNode>,
    incomplete_reason: Option<HistoryIncompleteReason>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedHistoryRecord {
    record: FileHistoryRecord,
    visit: u32,
    depth: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileIdEventState {
    Reserved,
    Active,
    Tombstoned,
}

impl FileIdEventState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Tombstoned => "tombstoned",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequiredOutboxFact {
    RepositoryCreated,
    SnapshotAccepted {
        digest: [u8; 32],
    },
    ReferenceChanged {
        kind: ReferenceKind,
        name: String,
        current: Option<ObjectRef>,
        generation: u64,
    },
    FileIdStateChanged {
        file_id: FileId,
        state: FileIdEventState,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequiredOutboxEvent {
    fact: RequiredOutboxFact,
    emitted: bool,
}

/// Metadata-side projection of an OGVCS-009 branded view. Its fields are
/// private so only this adapter can construct it after same-transaction
/// authorization.
#[derive(Debug)]
pub struct IdentityMetadataAuthorizedView {
    context: AuthorizationContext,
    repository_id: RepositoryId,
    permission: MetadataPermission,
}

impl AuthorizedView for IdentityMetadataAuthorizedView {
    fn permits(
        &self,
        context: &AuthorizationContext,
        permission: MetadataPermission,
        resource: &AuthorizationResource,
    ) -> bool {
        self.context == *context
            && self.permission == permission
            && resource.repository_id() == Some(self.repository_id)
    }
}

struct IdentityTransactionBinding<'a> {
    participant: &'a PostgresTransactionAuthorizationParticipant,
    view: TransactionAuthorizedView,
    tenant: String,
    repository: String,
    permission: String,
    correlation_id: String,
    reference: Option<String>,
}

impl RequiredOutboxFact {
    fn event_type(&self) -> &'static str {
        match self {
            Self::RepositoryCreated => "repository.created",
            Self::SnapshotAccepted { .. } => "metadata.object-accepted",
            Self::ReferenceChanged { .. } => "reference.changed",
            Self::FileIdStateChanged { .. } => "file-id.state-changed",
        }
    }

    fn resource_type(&self) -> &'static str {
        match self {
            Self::RepositoryCreated => "repository",
            Self::SnapshotAccepted { .. } => "snapshot",
            Self::ReferenceChanged { .. } => "reference",
            Self::FileIdStateChanged { .. } => "path",
        }
    }

    fn safe_payload(&self) -> Value {
        match self {
            Self::RepositoryCreated => json!({
                "schemaVersion": OUTBOX_PAYLOAD_SCHEMA,
                "state": "created"
            }),
            Self::SnapshotAccepted { .. } => json!({
                "schemaVersion": OUTBOX_PAYLOAD_SCHEMA,
                "kind": "snapshot",
                "state": "accepted"
            }),
            Self::ReferenceChanged {
                current,
                generation,
                ..
            } => json!({
                "schemaVersion": OUTBOX_PAYLOAD_SCHEMA,
                "generation": generation,
                "deleted": current.is_none()
            }),
            Self::FileIdStateChanged { state, .. } => json!({
                "schemaVersion": OUTBOX_PAYLOAD_SCHEMA,
                "state": state.as_str()
            }),
        }
    }

    fn resource_opaque_id(
        &self,
        repository_id: RepositoryId,
        event_id: [u8; 16],
        safe_payload: &Value,
    ) -> Result<String> {
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let mut hash = Sha256::new();
        hash.update(b"OpenGameVCS metadata outbox resource binding\0");
        hash.update(nonce);
        hash.update(repository_id.as_bytes());
        hash.update(event_id);
        hash.update(self.event_type().as_bytes());
        match self {
            Self::RepositoryCreated => hash.update(b"repository"),
            Self::SnapshotAccepted { digest } => hash.update(digest),
            Self::ReferenceChanged {
                kind,
                name,
                current,
                generation,
            } => {
                hash.update(reference_kind(*kind).as_bytes());
                hash.update((name.len() as u64).to_be_bytes());
                hash.update(name.as_bytes());
                if let Some(current) = current {
                    hash.update(current.kind.code().to_be_bytes());
                    hash.update(current.digest);
                }
                hash.update(generation.to_be_bytes());
            }
            Self::FileIdStateChanged { file_id, state } => {
                hash.update(file_id.as_bytes());
                hash.update(state.as_str().as_bytes());
            }
        }
        let payload = serde_json::to_vec(safe_payload)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        hash.update((payload.len() as u64).to_be_bytes());
        hash.update(payload);
        Ok(format!("rr1.{}", URL_SAFE_NO_PAD.encode(hash.finalize())))
    }
}

pub struct PostgresMetadataTransaction<
    'a,
    V: ObjectValidationPort,
    View: AuthorizedView = crate::DeniedAuthorizedView,
> {
    transaction: Option<Transaction<'a>>,
    failed: bool,
    commit_sequence: Option<(RepositoryId, CommitSequence)>,
    pending_idempotency: Option<PendingIdempotency>,
    idempotency_committed: bool,
    committed_replay: Option<Value>,
    mutation_started: bool,
    outbox_events: Vec<RequiredOutboxEvent>,
    capability: TransactionCapability,
    authorized_repository_id: RepositoryId,
    authorization_context: AuthorizationContext,
    authorized_view: View,
    validation: &'a V,
    authenticated_scope_digest: [u8; 32],
    allocation_receipt_scope_digest: [u8; 32],
    allocation_receipt_required: bool,
    identity_binding: Option<IdentityTransactionBinding<'a>>,
    identity_resources: Vec<IdentityAuthorizationResource>,
}

impl<'a, V: ObjectValidationPort, View: AuthorizedView> PostgresMetadataTransaction<'a, V, View> {
    pub fn authorized_repository_id(&self) -> RepositoryId {
        self.authorized_repository_id
    }

    pub fn authorization_context(&self) -> &AuthorizationContext {
        &self.authorization_context
    }

    pub fn authorized_view(&self) -> &View {
        &self.authorized_view
    }

    /// Ends the read-only replay probe without exposing an ambiguous commit
    /// result or sending it through the transaction retry loop.
    pub fn finish_committed_replay(mut self) -> Result<Value> {
        let capability = self.capability;
        self.require_capability(&[capability])?;
        let result = self
            .committed_replay
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        self.transaction
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?
            .rollback()
            .map_err(database_error)?;
        Ok(result)
    }

    fn transaction(&mut self) -> Result<&mut Transaction<'a>> {
        if self.failed {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        self.transaction
            .as_mut()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))
    }

    fn fail<T>(&mut self, error: DomainError) -> Result<T> {
        self.failed = true;
        Err(error)
    }

    fn ensure_sequence(&mut self, repository_id: RepositoryId) -> Result<CommitSequence> {
        self.require_repository(repository_id)?;
        if let Some((existing_repository, sequence)) = self.commit_sequence {
            if existing_repository != repository_id {
                return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            return Ok(sequence);
        }
        let row = self
            .transaction()?
            .query_one(
                "UPDATE ogvcs_metadata.repository_commit_sequences
                 SET applied_sequence = applied_sequence + 1
                 WHERE repository_id = $1
                 RETURNING applied_sequence",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?;
        let sequence = CommitSequence::new(positive_u64(row.get(0))?);
        self.commit_sequence = Some((repository_id, sequence));
        Ok(sequence)
    }

    fn require_repository(&self, repository_id: RepositoryId) -> Result<()> {
        if repository_id == self.authorized_repository_id {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
        }
    }

    fn require_capability(&self, allowed: &[TransactionCapability]) -> Result<()> {
        let resource = AuthorizationResource::RepositoryTransaction {
            repository_id: self.authorized_repository_id,
            capability: self.capability,
        };
        if allowed.contains(&self.capability)
            && self.authorized_view.permits(
                &self.authorization_context,
                self.capability.permission(),
                &resource,
            )
        {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))
        }
    }

    fn require_submit_capability(&self) -> Result<()> {
        self.require_capability(&[
            TransactionCapability::CreateRepository,
            TransactionCapability::PutObject,
            TransactionCapability::Publish,
            TransactionCapability::ReserveFileId,
            TransactionCapability::ImportFileId,
            TransactionCapability::RestoreFileId,
            TransactionCapability::TombstoneFileId,
            TransactionCapability::CompareAndSwapReference,
        ])
    }

    fn require_pending_idempotency(&self) -> Result<()> {
        if self.pending_idempotency.is_some() && !self.idempotency_committed {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::ObjectInvalid))
        }
    }

    fn begin_mutation(&mut self, repository_id: RepositoryId) -> Result<CommitSequence> {
        self.require_pending_idempotency()?;
        if self.outbox_events.iter().any(|event| event.emitted) {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let sequence = self.ensure_sequence(repository_id)?;
        self.mutation_started = true;
        Ok(sequence)
    }

    fn record_identity_resource(&mut self, resource: IdentityAuthorizationResource) -> Result<()> {
        if self.identity_binding.is_none() {
            return Ok(());
        }
        if !prepare_identity_resource(&mut self.identity_resources, &resource) {
            return Ok(());
        }
        if self.identity_resources.len() >= MAXIMUM_BATCH_RESOURCES {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        self.identity_resources.push(resource);
        Ok(())
    }

    fn bind_identity_reference(&mut self, reference: &str) -> Result<()> {
        let mismatch = if let Some(binding) = self.identity_binding.as_mut() {
            match binding.reference.as_deref() {
                Some(bound) => bound != reference,
                None => {
                    binding.reference = Some(reference.to_owned());
                    false
                }
            }
        } else {
            false
        };
        if mismatch {
            self.fail(DomainError::new(DomainErrorCode::ObjectInvalid))
        } else {
            Ok(())
        }
    }

    fn require_repository_event(&mut self) -> Result<()> {
        if !self
            .outbox_events
            .iter()
            .any(|event| event.fact == RequiredOutboxFact::RepositoryCreated)
        {
            if self.outbox_events.len() >= MAX_REQUIRED_OUTBOX_EVENTS {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.outbox_events.push(RequiredOutboxEvent {
                fact: RequiredOutboxFact::RepositoryCreated,
                emitted: false,
            });
        }
        Ok(())
    }

    fn require_object_event(&mut self, snapshot_digest: [u8; 32]) -> Result<()> {
        if !self.outbox_events.iter().any(|event| {
            matches!(
                &event.fact,
                RequiredOutboxFact::SnapshotAccepted { digest } if *digest == snapshot_digest
            )
        }) {
            if self.outbox_events.len() >= MAX_REQUIRED_OUTBOX_EVENTS {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.outbox_events.push(RequiredOutboxEvent {
                fact: RequiredOutboxFact::SnapshotAccepted {
                    digest: snapshot_digest,
                },
                emitted: false,
            });
        }
        Ok(())
    }

    fn require_reference_event(
        &mut self,
        kind: ReferenceKind,
        name: &ReferenceName,
        current: Option<ObjectRef>,
        generation: u64,
    ) -> Result<()> {
        if let Some(event) = self.outbox_events.iter_mut().find(|event| {
            matches!(
                &event.fact,
                RequiredOutboxFact::ReferenceChanged {
                    kind: existing_kind,
                    name: existing_name,
                    ..
                } if *existing_kind == kind && existing_name == name.as_str()
            )
        }) {
            event.fact = RequiredOutboxFact::ReferenceChanged {
                kind,
                name: name.as_str().to_owned(),
                current,
                generation,
            };
        } else {
            if self.outbox_events.len() >= MAX_REQUIRED_OUTBOX_EVENTS {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.outbox_events.push(RequiredOutboxEvent {
                fact: RequiredOutboxFact::ReferenceChanged {
                    kind,
                    name: name.as_str().to_owned(),
                    current,
                    generation,
                },
                emitted: false,
            });
        }
        Ok(())
    }

    fn require_file_id_event(&mut self, file_id: FileId, state: FileIdEventState) -> Result<()> {
        if let Some(event) = self.outbox_events.iter_mut().find(|event| {
            matches!(
                &event.fact,
                RequiredOutboxFact::FileIdStateChanged {
                    file_id: existing,
                    ..
                } if *existing == file_id
            )
        }) {
            event.fact = RequiredOutboxFact::FileIdStateChanged { file_id, state };
        } else {
            if self.outbox_events.len() >= MAX_REQUIRED_OUTBOX_EVENTS {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.outbox_events.push(RequiredOutboxEvent {
                fact: RequiredOutboxFact::FileIdStateChanged { file_id, state },
                emitted: false,
            });
        }
        Ok(())
    }

    fn idempotency_scope_digest(&self) -> [u8; 32] {
        self.authenticated_scope_digest
    }

    fn consume_allocation_receipt(
        &mut self,
        receipt: &AllocationReceipt,
        file_id: FileId,
    ) -> Result<()> {
        let digest = Sha256::digest(receipt.as_str().as_bytes());
        let scope = self.allocation_receipt_scope_digest;
        let repository_id = uuid(self.authorized_repository_id);
        let consumed = self
            .transaction()?
            .query_opt(
                "UPDATE ogvcs_metadata.file_id_allocation_receipts
             SET consumed_at = clock_timestamp()
             WHERE receipt_digest = $1 AND authenticated_scope_digest = $2
               AND repository_id = $3 AND file_id = $4
               AND consumed_at IS NULL AND expires_at > clock_timestamp()
             RETURNING 1",
                &[
                    &&digest[..],
                    &&scope[..],
                    &repository_id,
                    &&file_id.as_bytes()[..],
                ],
            )
            .map_err(database_error)?
            .is_some();
        if consumed {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }

    fn validate_object_settings(&mut self, write: &ObjectWrite<'_>) -> Result<()> {
        let row = self
            .transaction()?
            .query_opt(
                "SELECT settings.descriptor_digest, settings.required_features,
                        settings.structural_limits, descriptor.canonical_bytes
                 FROM ogvcs_metadata.repository_settings AS settings
                 JOIN ogvcs_metadata.metadata_objects AS descriptor
                   ON descriptor.repository_id = settings.repository_id
                  AND descriptor.object_kind = settings.descriptor_kind
                  AND descriptor.digest_algorithm = settings.descriptor_algorithm
                  AND descriptor.object_digest = settings.descriptor_digest
                 WHERE settings.repository_id = $1",
                &[&uuid(write.repository_id)],
            )
            .map_err(database_error)?
            .ok_or_else(|| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
        let descriptor_digest: Vec<u8> = row.get(0);
        let Json(required_features): Json<Value> = row.get(1);
        let Json(structural_limits): Json<Value> = row.get(2);
        let descriptor_bytes: Vec<u8> = row.get(3);
        if repository_object_matches_settings(
            write,
            &descriptor_digest,
            &required_features,
            &structural_limits,
            &descriptor_bytes,
        ) {
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::ObjectInvalid))
        }
    }

    fn validate_publication_candidate(&mut self, candidate: ObjectRef) -> Result<()> {
        if candidate.kind != ObjectKind::Snapshot {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let repository_id = self.authorized_repository_id;
        let settings = self
            .transaction()?
            .query_one(
                "SELECT descriptor_digest, repository_format, required_features, case_mode,
                        path_profile, platform_profile, content_policy_profile, structural_limits,
                        tenant_boundary
                 FROM ogvcs_metadata.repository_settings WHERE repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?;
        let descriptor_digest: Vec<u8> = settings.get(0);
        let repository_format: String = settings.get(1);
        let Json(required_features_json): Json<Value> = settings.get(2);
        let case_mode: String = settings.get(3);
        let path_profile_name: String = settings.get(4);
        let platform_profile_name: String = settings.get(5);
        let content_policy_profile_name: String = settings.get(6);
        let Json(structural_limits): Json<Value> = settings.get(7);
        let tenant_boundary: Uuid = settings.get(8);
        let required_features = json_features(&required_features_json)
            .filter(|features| {
                features.len() <= 128 && features.windows(2).all(|pair| pair[0] < pair[1])
            })
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if repository_format != VALIDATION_CONTRACT
            || !valid_structural_limits(&structural_limits)
            || tenant_boundary.as_bytes() != self.authorization_context.tenant_id.as_bytes()
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let path_profile = path_profile_name
            .parse::<ProfileRef>()
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let platform_profile = platform_profile_name
            .parse::<ProfileRef>()
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let content_policy_profile = content_policy_profile_name
            .parse::<ProfileRef>()
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        self.validation.validate_repository_profiles(
            &path_profile,
            &platform_profile,
            &content_policy_profile,
        )?;

        let limits = RepositoryLimits::default();
        let preflight = self
            .transaction()?
            .query_one(
                "SELECT count(*)::bigint, COALESCE(sum(byte_length), 0)::text
                 FROM ogvcs_metadata.metadata_objects WHERE repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?;
        let object_count = usize::try_from(preflight.get::<_, i64>(0))
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let byte_count = preflight
            .get::<_, String>(1)
            .parse::<usize>()
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if object_count > limits.max_objects || byte_count > limits.max_bytes {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let rows = self
            .transaction()?
            .query(
                "SELECT object_kind, object_digest, canonical_bytes, validation_contract
                 FROM ogvcs_metadata.metadata_objects
                 WHERE repository_id = $1 ORDER BY object_kind, object_digest",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?;
        let mut entries = BTreeMap::new();
        for row in rows {
            let reference = object_ref(object_kind(row.get(0))?, row.get(1))?;
            let canonical: Vec<u8> = row.get(2);
            let validation_contract: String = row.get(3);
            if validation_contract != VALIDATION_CONTRACT {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            if entries.insert(reference, canonical).is_some() {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
        }
        let closure = metadata_closure(&entries, candidate)?;
        let designated_root = designated_snapshot_root(&entries, candidate)?;
        self.verify_publication_indexes(&entries, &closure)?;

        let descriptor = object_ref(ObjectKind::RepositoryDescriptor, descriptor_digest)?;
        if !closure.contains(&descriptor)
            || !descriptor_matches_repository_settings(
                repository_id,
                &required_features,
                &path_profile_name,
                &content_policy_profile_name,
                entries
                    .get(&descriptor)
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            )
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let (lifetime_records, working_lifetime_additions) =
            derive_lifetime_evidence(&entries, &closure, candidate)?;
        let candidate_change = snapshot_change_ref(&entries, candidate)?;
        let candidate_base = change_base_snapshot_ref(&entries, candidate_change)?;
        let required_active = lifetime_records
            .iter()
            .filter(|record| record.first_change_set == candidate_change)
            .map(|record| record.file_id)
            .chain(
                working_lifetime_additions
                    .iter()
                    .map(|record| record.file_id),
            )
            .chain(candidate_tree_file_ids(&entries, candidate)?)
            .collect::<BTreeSet<_>>();
        let file_id_evidence = self.load_file_id_evidence(limits.max_edges)?;
        verify_lifetime_evidence(
            &file_id_evidence,
            lifetime_records.iter().chain(&working_lifetime_additions),
            candidate_change,
        )?;
        verify_active_file_ids(&file_id_evidence, &required_active)?;
        let published_imports = lifetime_records
            .iter()
            .filter(|record| {
                record.origin == LifetimeOrigin::Import
                    && record.first_change_set != candidate_change
            })
            .map(|record| record.file_id)
            .collect::<BTreeSet<_>>();
        let required_imports = lifetime_records
            .iter()
            .filter(|record| record.origin == LifetimeOrigin::Import)
            .map(|record| record.file_id)
            .collect::<BTreeSet<_>>();
        let import_mappings = self.load_import_mappings(
            descriptor,
            &required_imports,
            &published_imports,
            limits.max_edges,
        )?;
        let chunk_references = required_chunk_references(&entries, &closure)?;
        let mut loaded_bytes = byte_count;
        for reference in chunk_references {
            let payload = self.validation.resolve_chunk(reference)?;
            if object_id(ObjectKind::Chunk, &payload)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
                != reference.digest
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            loaded_bytes = loaded_bytes
                .checked_add(payload.len())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            if loaded_bytes > limits.max_bytes || entries.insert(reference, payload).is_some() {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            if entries.len() > limits.max_objects {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
        }
        let registry = self.validation.registry();
        let mode = self.validation.validation_mode();
        let lookup = RepositoryObjectLookup::new(entries.into_iter(), registry, mode, limits)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        for reference in &closure {
            lookup
                .resolve(*reference)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        }
        let path_case_mode = match case_mode.as_str() {
            "case-sensitive" => PathCaseMode::CaseSensitive,
            "case-folded" => PathCaseMode::CaseFolded,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        let mut context =
            RepositoryContext::new(&lookup, descriptor, designated_root, path_case_mode);
        context.lifetime_records = &lifetime_records;
        context.working_lifetime_additions = &working_lifetime_additions;
        context.import_mappings = &import_mappings;
        context.verify_content = true;
        context.path_profile_validator = self.validation.path_profile_validator();
        validate_snapshot_graph(candidate, &context)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        validate_repository_candidate(candidate, &context)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let mut candidate_paths = None;
        let mut base_paths = candidate_base.is_none().then(BTreeMap::new);
        for snapshot in closure
            .iter()
            .filter(|reference| reference.kind == ObjectKind::Snapshot)
        {
            let snapshot_value = lookup
                .resolve(*snapshot)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
                .value
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let root_tree = cbor_field(&snapshot_value, 18)
                .and_then(|value| ObjectRef::from_cbor(value).ok())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let expansion = expand_tree_with_path_profile_validator(
                root_tree,
                &lookup,
                descriptor,
                false,
                path_case_mode,
                self.validation.path_profile_validator(),
            )
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            enforce_configured_tree_limits(&expansion.entries, &structural_limits)?;
            if *snapshot == candidate {
                candidate_paths = Some(expansion.entries);
            } else if candidate_base == Some(*snapshot) {
                base_paths = Some(expansion.entries);
            }
        }
        self.record_exact_tree_delta_resources(
            base_paths
                .as_ref()
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            candidate_paths
                .as_ref()
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            candidate,
        )?;
        Ok(())
    }

    fn record_exact_tree_delta_resources(
        &mut self,
        before: &BTreeMap<Vec<String>, EntryState>,
        after: &BTreeMap<Vec<String>, EntryState>,
        candidate: ObjectRef,
    ) -> Result<()> {
        for (path, state) in before {
            if after.get(path) != Some(state) {
                self.record_identity_resource(identity_file_resource(
                    state.file_id,
                    Some(root_relative_path(path, state)?),
                    Some(candidate),
                ))?;
            }
        }
        for (path, state) in after {
            if before.get(path) != Some(state) {
                self.record_identity_resource(identity_file_resource(
                    state.file_id,
                    Some(root_relative_path(path, state)?),
                    Some(candidate),
                ))?;
            }
        }
        Ok(())
    }

    fn load_file_id_evidence(
        &mut self,
        maximum_records: usize,
    ) -> Result<BTreeMap<FileId, StoredFileIdEvidence>> {
        let repository_id = self.authorized_repository_id;
        let fetch_limit = maximum_records
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let rows = self
            .transaction()?
            .query(
                "SELECT file_id, state::text, origin::text, first_change_set_digest,
                        first_operation
                 FROM ogvcs_metadata.file_id_registry
                 WHERE repository_id = $1 ORDER BY file_id LIMIT $2",
                &[&uuid(repository_id), &fetch_limit],
            )
            .map_err(database_error)?;
        if rows.len() > maximum_records {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let mut evidence = BTreeMap::new();
        for row in rows {
            let file_id = file_id(row.get(0))?;
            let first_change_set = row
                .get::<_, Option<Vec<u8>>>(3)
                .map(|digest| {
                    digest
                        .try_into()
                        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
                })
                .transpose()?;
            let first_operation = row
                .get::<_, Option<i32>>(4)
                .map(|value| {
                    u64::try_from(value)
                        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
                })
                .transpose()?;
            if evidence
                .insert(
                    file_id,
                    StoredFileIdEvidence {
                        state: row.get(1),
                        origin: row.get(2),
                        first_change_set,
                        first_operation,
                    },
                )
                .is_some()
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
        }
        Ok(evidence)
    }

    fn load_import_mappings(
        &mut self,
        descriptor: ObjectRef,
        required: &BTreeSet<FileId>,
        published: &BTreeSet<FileId>,
        maximum_records: usize,
    ) -> Result<Vec<ImportMapping>> {
        let repository_id = self.authorized_repository_id;
        let fetch_limit = maximum_records
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let rows = self
            .transaction()?
            .query(
                "SELECT mapping.importer_profile, mapping.source_namespace_digest,
                        mapping.source_identity_digest, mapping.file_id, registry.state::text
                 FROM ogvcs_metadata.file_id_import_mappings AS mapping
                 JOIN ogvcs_metadata.file_id_registry AS registry
                   ON registry.repository_id = mapping.repository_id
                  AND registry.file_id = mapping.file_id
                 WHERE mapping.repository_id = $1
                 ORDER BY mapping.importer_profile, mapping.source_namespace_digest,
                          mapping.source_identity_digest
                 LIMIT $2",
                &[&uuid(repository_id), &fetch_limit],
            )
            .map_err(database_error)?;
        if rows.len() > maximum_records {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let mut mappings = Vec::with_capacity(rows.len());
        for row in rows {
            let file_id = file_id(row.get(3))?;
            if !required.contains(&file_id) {
                continue;
            }
            let state: String = row.get(4);
            let state = if published.contains(&file_id) {
                ImportState::Published
            } else {
                match state.as_str() {
                    "reserved" => ImportState::Reserved,
                    "active" => ImportState::Materialized,
                    _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
                }
            };
            let mut mapping = ImportMapping {
                descriptor,
                importer_profile: row
                    .get::<_, String>(0)
                    .parse()
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
                source_namespace_digest: row
                    .get::<_, Vec<u8>>(1)
                    .try_into()
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
                source_identity_digest: row
                    .get::<_, Vec<u8>>(2)
                    .try_into()
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
                file_id,
                state,
                declared_mapping_key: [0; 32],
            };
            mapping.declared_mapping_key = import_mapping_key(descriptor, &mapping)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            mappings.push(mapping);
        }
        if mappings.len() != required.len() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(mappings)
    }

    fn verify_publication_indexes(
        &mut self,
        entries: &BTreeMap<ObjectRef, Vec<u8>>,
        closure: &BTreeSet<ObjectRef>,
    ) -> Result<()> {
        let repository_id = self.authorized_repository_id;
        for reference in closure {
            match reference.kind {
                ObjectKind::Tree => {
                    let canonical = entries
                        .get(reference)
                        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                    let value = decode_canonical(canonical, Limits::METADATA)
                        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                    let expected = match cbor_field(&value, 17) {
                        Some(Cbor::Array(entries)) => entries.len(),
                        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
                    };
                    let rows = self
                        .transaction()?
                        .query(
                            "SELECT ordinal, basename_utf8, file_id, entry_kind, target_kind,
                                    target_digest, logical_size::text
                             FROM ogvcs_metadata.tree_entries
                             WHERE repository_id = $1 AND tree_digest = $2 ORDER BY ordinal",
                            &[&uuid(repository_id), &&reference.digest[..]],
                        )
                        .map_err(database_error)?;
                    if rows.len() != expected {
                        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                    }
                    for row in rows {
                        let indexed = TreeEntryWrite {
                            repository_id,
                            tree: *reference,
                            ordinal: u32::try_from(row.get::<_, i32>(0))
                                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
                            basename_utf8: row.get(1),
                            file_id: file_id(row.get(2))?,
                            entry_kind: u16::try_from(row.get::<_, i16>(3))
                                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
                            target: object_ref(object_kind(row.get(4))?, row.get(5))?,
                            logical_size: row
                                .get::<_, String>(6)
                                .parse()
                                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
                        };
                        if !tree_entry_matches(canonical, &indexed) {
                            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                        }
                    }
                }
                ObjectKind::Snapshot => {
                    self.verify_snapshot_index(entries, *reference)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn verify_snapshot_index(
        &mut self,
        entries: &BTreeMap<ObjectRef, Vec<u8>>,
        snapshot: ObjectRef,
    ) -> Result<()> {
        let repository_id = self.authorized_repository_id;
        let canonical = entries
            .get(&snapshot)
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let value = decode_canonical(canonical, Limits::METADATA)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let root = cbor_field(&value, 18)
            .and_then(|value| ObjectRef::from_cbor(value).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let parents = match cbor_field(&value, 17) {
            Some(Cbor::Array(parents)) => parents
                .iter()
                .map(|parent| ObjectRef::from_cbor(parent).ok())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        let indexed = self
            .transaction()?
            .query_opt(
                "SELECT root_tree_digest FROM ogvcs_metadata.snapshots
                 WHERE repository_id = $1 AND snapshot_digest = $2",
                &[&uuid(repository_id), &&snapshot.digest[..]],
            )
            .map_err(database_error)?
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let indexed_root: Vec<u8> = indexed.get(0);
        if indexed_root.as_slice() != &root.digest[..] {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let indexed_parents = self
            .transaction()?
            .query(
                "SELECT ordinal, parent_snapshot_digest FROM ogvcs_metadata.snapshot_parents
                 WHERE repository_id = $1 AND snapshot_digest = $2 ORDER BY ordinal",
                &[&uuid(repository_id), &&snapshot.digest[..]],
            )
            .map_err(database_error)?;
        if indexed_parents.len() != parents.len()
            || indexed_parents
                .iter()
                .enumerate()
                .zip(&parents)
                .any(|((ordinal, row), expected)| {
                    usize::try_from(row.get::<_, i16>(0)).ok() != Some(ordinal)
                        || row.get::<_, Vec<u8>>(1).as_slice() != &expected.digest[..]
                })
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let expected_history = canonical_file_history_facts(entries, snapshot)?;
        let actual_history = self
            .transaction()?
            .query(
                "SELECT operation_ordinal, file_id, repository_path_utf8, operation_kind
                 FROM ogvcs_metadata.file_path_history
                 WHERE repository_id = $1 AND snapshot_digest = $2 ORDER BY operation_ordinal",
                &[&uuid(repository_id), &&snapshot.digest[..]],
            )
            .map_err(database_error)?;
        if actual_history.len() != expected_history.len()
            || actual_history
                .iter()
                .zip(&expected_history)
                .any(|(row, expected)| {
                    u32::try_from(row.get::<_, i32>(0)).ok() != Some(expected.operation_ordinal)
                        || row.get::<_, Vec<u8>>(1).as_slice() != expected.file_id.as_bytes()
                        || row.get::<_, Vec<u8>>(2) != expected.repository_path_utf8
                        || row.get::<_, String>(3).as_str() != expected.operation_kind.as_str()
                })
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        Ok(())
    }

    fn put_object_inner(
        &mut self,
        write: ObjectWrite<'_>,
        repository_creation_descriptor: bool,
    ) -> Result<ObjectPutOutcome> {
        self.require_repository(write.repository_id)?;
        self.require_pending_idempotency()?;
        if !metadata_kind(write.object_ref.kind) {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        self.validation.validate(&write)?;
        let scanned = scan_metadata(write.canonical_bytes, Limits::METADATA)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let kind = validate_metadata_schema(&scanned)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let digest = object_id(kind, write.canonical_bytes)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if kind != write.object_ref.kind || digest != write.object_ref.digest {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        if !repository_creation_descriptor {
            self.validate_object_settings(&write)?;
        }
        let inserted = self
            .transaction()?
            .query_opt(
                "INSERT INTO ogvcs_metadata.metadata_objects
                 (repository_id, object_kind, digest_algorithm, object_digest, canonical_bytes,
                  validation_contract)
                 VALUES ($1, $2, 1, $3, $4, $5)
                 ON CONFLICT DO NOTHING RETURNING 1",
                &[
                    &uuid(write.repository_id),
                    &(write.object_ref.kind.code() as i16),
                    &&write.object_ref.digest[..],
                    &write.canonical_bytes,
                    &VALIDATION_CONTRACT,
                ],
            )
            .map_err(database_error)?;
        if inserted.is_some() {
            if !repository_creation_descriptor {
                self.begin_mutation(write.repository_id)?;
            }
            self.record_identity_resource(identity_object_resource(*write.object_ref))?;
            return Ok(ObjectPutOutcome::Inserted);
        }
        let stored = self
            .transaction()?
            .query_one(
                "SELECT canonical_bytes, validation_contract FROM ogvcs_metadata.metadata_objects
                 WHERE repository_id = $1 AND object_kind = $2 AND digest_algorithm = 1
                   AND object_digest = $3",
                &[
                    &uuid(write.repository_id),
                    &(write.object_ref.kind.code() as i16),
                    &&write.object_ref.digest[..],
                ],
            )
            .map_err(database_error)?;
        let stored_bytes: Vec<u8> = stored.get(0);
        let validation_contract: String = stored.get(1);
        if stored_bytes.len() == write.canonical_bytes.len()
            && bool::from(stored_bytes.as_slice().ct_eq(write.canonical_bytes))
        {
            if validation_contract == VALIDATION_CONTRACT {
                Ok(ObjectPutOutcome::ExactReplay)
            } else {
                Err(DomainError::new(DomainErrorCode::ObjectInvalid))
            }
        } else {
            Err(DomainError::new(DomainErrorCode::ObjectIdCollision))
        }
    }

    fn reserve_file_id_inner(
        &mut self,
        reservation: FileIdReservation,
        imported_with_mapping: bool,
    ) -> Result<()> {
        self.require_repository(reservation.repository_id)?;
        self.require_pending_idempotency()?;
        if reservation.origin == FileIdOrigin::Restore
            || (reservation.origin == FileIdOrigin::Import && !imported_with_mapping)
            || (reservation.origin != FileIdOrigin::Import && imported_with_mapping)
            || reservation.owner_id.is_empty()
            || reservation.owner_id.len() > 256
            || reservation.owner_id.contains('\0')
        {
            return Err(DomainError::new(DomainErrorCode::FileIdConflict));
        }
        let inserted = self
            .transaction()?
            .execute(
                "INSERT INTO ogvcs_metadata.file_id_registry
                 (repository_id, file_id, state, origin, owner_kind, owner_id)
                 VALUES ($1, $2, 'reserved',
                         $3::text::ogvcs_metadata.file_id_origin,
                         $4::text::ogvcs_metadata.file_id_owner_kind,
                         $5)
                 ON CONFLICT DO NOTHING",
                &[
                    &uuid(reservation.repository_id),
                    &&reservation.file_id.as_bytes()[..],
                    &file_id_origin(reservation.origin),
                    &file_id_owner(reservation.owner_kind),
                    &reservation.owner_id,
                ],
            )
            .map_err(file_id_database_error)?;
        if inserted == 1 {
            self.begin_mutation(reservation.repository_id)?;
            self.require_file_id_event(reservation.file_id, FileIdEventState::Reserved)?;
            self.record_identity_resource(identity_file_resource(reservation.file_id, None, None))?;
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }
}

impl<V: ObjectValidationPort, View: AuthorizedView> MetadataTransaction
    for PostgresMetadataTransaction<'_, V, View>
{
    fn create_repository(&mut self, request: RepositoryCreate<'_>) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(request.repository_id)?;
            self.require_capability(&[TransactionCapability::CreateRepository])?;
            self.require_pending_idempotency()?;
            let path_profile = request
                .settings
                .path_profile
                .parse::<ProfileRef>()
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let platform_profile = request
                .settings
                .platform_profile
                .parse::<ProfileRef>()
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let content_policy_profile = request
                .settings
                .content_policy_profile
                .parse::<ProfileRef>()
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            self.validation.validate_repository_profiles(
                &path_profile,
                &platform_profile,
                &content_policy_profile,
            )?;
            if request.tenant_id != self.authorization_context.tenant_id
                || request.settings.tenant_boundary != request.tenant_id
                || request.descriptor.repository_id != request.repository_id
                || request.descriptor.object_ref.kind != ObjectKind::RepositoryDescriptor
                || !request.settings.has_sorted_unique_features()
                || !valid_structural_limits(&request.settings.structural_limits)
                || !repository_settings_match_descriptor(&request)
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.transaction()
                .and_then(|transaction| {
                    transaction
                        .execute(
                            "INSERT INTO ogvcs_metadata.repositories (repository_id, tenant_id, project_id)
                             VALUES ($1, $2, $3)",
                            &[
                                &uuid(request.repository_id),
                                &uuid(request.tenant_id),
                                &uuid(request.project_id),
                            ],
                        )
                        .map_err(database_error)?;
                    transaction
                        .execute(
                            "INSERT INTO ogvcs_metadata.repository_commit_sequences (repository_id)
                             VALUES ($1)",
                            &[&uuid(request.repository_id)],
                        )
                        .map_err(database_error)?;
                    Ok(())
                })?;
            self.put_object_inner(request.descriptor, true)?;
            let features = json!(&request.settings.required_features);
            let case_mode = match request.settings.case_mode {
                CaseMode::CaseSensitive => "case-sensitive",
                CaseMode::CaseFolded => "case-folded",
            };
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.repository_settings
                     (repository_id, descriptor_kind, descriptor_algorithm, descriptor_digest,
                      repository_format, required_features, case_mode, path_profile, platform_profile,
                      content_policy_profile, structural_limits, tenant_boundary)
                     VALUES ($1, 6, 1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &uuid(request.repository_id),
                        &&request.descriptor.object_ref.digest[..],
                        &request.settings.repository_format,
                        &Json(&features),
                        &case_mode,
                        &request.settings.path_profile,
                        &request.settings.platform_profile,
                        &request.settings.content_policy_profile,
                        &Json(&request.settings.structural_limits),
                        &uuid(request.settings.tenant_boundary),
                    ],
                )
                .map_err(database_error)?;
            self.begin_mutation(request.repository_id)?;
            self.require_repository_event()?;
            Ok(())
        })
    }

    fn put_object(&mut self, write: ObjectWrite<'_>) -> Result<ObjectPutOutcome> {
        poison_transaction_on_error!(self, {
            self.require_capability(&[
                TransactionCapability::PutObject,
                TransactionCapability::Publish,
            ])?;
            self.put_object_inner(write, false)
        })
    }

    fn index_tree_entry(&mut self, entry: TreeEntryWrite) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(entry.repository_id)?;
            self.require_capability(&[TransactionCapability::Publish])?;
            self.require_pending_idempotency()?;
            if entry.tree.kind != ObjectKind::Tree {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let canonical: Vec<u8> = self
                .transaction()?
                .query_one(
                    "SELECT canonical_bytes FROM ogvcs_metadata.metadata_objects
                     WHERE repository_id = $1 AND object_kind = 3 AND digest_algorithm = 1
                       AND object_digest = $2",
                    &[&uuid(entry.repository_id), &&entry.tree.digest[..]],
                )
                .map_err(database_error)?
                .get(0);
            if !tree_entry_matches(&canonical, &entry) {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.tree_entries
                     (repository_id, tree_digest, ordinal, basename_utf8, file_id, entry_kind,
                      target_kind, target_digest, logical_size)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::numeric)",
                    &[
                        &uuid(entry.repository_id),
                        &&entry.tree.digest[..],
                        &(entry.ordinal as i32),
                        &entry.basename_utf8,
                        &&entry.file_id.as_bytes()[..],
                        &(entry.entry_kind as i16),
                        &(entry.target.kind.code() as i16),
                        &&entry.target.digest[..],
                        &entry.logical_size.to_string(),
                    ],
                )
                .map_err(database_error)?;
            self.begin_mutation(entry.repository_id)?;
            self.record_identity_resource(identity_file_resource(
                entry.file_id,
                None,
                Some(entry.target),
            ))?;
            Ok(())
        })
    }

    fn index_snapshot(&mut self, snapshot: SnapshotWrite) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(snapshot.repository_id)?;
            self.require_capability(&[TransactionCapability::Publish])?;
            self.require_pending_idempotency()?;
            if snapshot.snapshot.kind != ObjectKind::Snapshot
                || snapshot.root_tree.kind != ObjectKind::Tree
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let canonical: Vec<u8> = self
                .transaction()?
                .query_one(
                    "SELECT canonical_bytes FROM ogvcs_metadata.metadata_objects
                     WHERE repository_id = $1 AND object_kind = 7 AND digest_algorithm = 1
                       AND object_digest = $2",
                    &[
                        &uuid(snapshot.repository_id),
                        &&snapshot.snapshot.digest[..],
                    ],
                )
                .map_err(database_error)?
                .get(0);
            if !snapshot_index_matches(&canonical, &snapshot) {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.snapshots
                     (repository_id, snapshot_digest, root_tree_digest) VALUES ($1, $2, $3)",
                    &[
                        &uuid(snapshot.repository_id),
                        &&snapshot.snapshot.digest[..],
                        &&snapshot.root_tree.digest[..],
                    ],
                )
                .map_err(database_error)?;
            for (ordinal, parent) in snapshot.parents.into_iter().enumerate() {
                if parent.kind != ObjectKind::Snapshot || ordinal > 7 {
                    return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                }
                self.transaction()?
                    .execute(
                        "INSERT INTO ogvcs_metadata.snapshot_parents
                         (repository_id, snapshot_digest, ordinal, parent_snapshot_digest)
                         VALUES ($1, $2, $3, $4)",
                        &[
                            &uuid(snapshot.repository_id),
                            &&snapshot.snapshot.digest[..],
                            &(ordinal as i16),
                            &&parent.digest[..],
                        ],
                    )
                    .map_err(database_error)?;
            }
            self.begin_mutation(snapshot.repository_id)?;
            self.record_identity_resource(identity_object_resource(snapshot.snapshot))?;
            Ok(())
        })
    }

    fn append_file_history(&mut self, history: FileHistoryWrite) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(history.repository_id)?;
            self.require_capability(&[TransactionCapability::Publish])?;
            self.require_pending_idempotency()?;
            if history.snapshot.kind != ObjectKind::Snapshot
                || history.repository_path_utf8.is_empty()
                || history.repository_path_utf8.len() > 4096
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let snapshot_bytes: Vec<u8> = self
                .transaction()?
                .query_one(
                    "SELECT canonical_bytes FROM ogvcs_metadata.metadata_objects
                     WHERE repository_id = $1 AND object_kind = 7 AND digest_algorithm = 1
                       AND object_digest = $2",
                    &[&uuid(history.repository_id), &&history.snapshot.digest[..]],
                )
                .map_err(database_error)?
                .get(0);
            let snapshot_value = decode_canonical(&snapshot_bytes, Limits::METADATA)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let change = cbor_field(&snapshot_value, 19)
                .and_then(|value| ObjectRef::from_cbor(value).ok())
                .filter(|reference| reference.kind == ObjectKind::ChangeSet)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let change_bytes: Vec<u8> = self
                .transaction()?
                .query_one(
                    "SELECT canonical_bytes FROM ogvcs_metadata.metadata_objects
                     WHERE repository_id = $1 AND object_kind = 4 AND digest_algorithm = 1
                       AND object_digest = $2",
                    &[&uuid(history.repository_id), &&change.digest[..]],
                )
                .map_err(database_error)?
                .get(0);
            let expected = canonical_file_history_from_change(&change_bytes)?
                .into_iter()
                .find(|fact| fact.operation_ordinal == history.operation_ordinal)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            if expected.file_id != history.file_id
                || expected.repository_path_utf8 != history.repository_path_utf8
                || expected.operation_kind != history.operation_kind
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let identity_resources = expected
                .affected_paths
                .iter()
                .map(|affected| {
                    String::from_utf8(affected.repository_path_utf8.clone())
                        .map(|path| {
                            identity_file_resource(
                                affected.file_id,
                                Some(path),
                                Some(history.snapshot),
                            )
                        })
                        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
                })
                .collect::<Result<Vec<_>>>()?;
            if let Some(origin) = allocation_history_origin(&expected.operation_kind) {
                let first_operation = i32::try_from(expected.operation_ordinal)
                    .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                let updated = self
                    .transaction()?
                    .execute(
                        "UPDATE ogvcs_metadata.file_id_registry
                         SET first_change_set_digest = $3, first_operation = $4
                         WHERE repository_id = $1 AND file_id = $2 AND state = 'active'
                           AND origin::text = $5
                           AND ((first_change_set_digest IS NULL AND first_operation IS NULL)
                             OR (first_change_set_digest = $3 AND first_operation = $4))",
                        &[
                            &uuid(history.repository_id),
                            &&history.file_id.as_bytes()[..],
                            &&change.digest[..],
                            &first_operation,
                            &origin,
                        ],
                    )
                    .map_err(database_error)?;
                if updated != 1 {
                    return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                }
            }
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.file_path_history
                     (repository_id, snapshot_digest, operation_ordinal, file_id,
                      repository_path_utf8, operation_kind)
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &uuid(history.repository_id),
                        &&history.snapshot.digest[..],
                        &(history.operation_ordinal as i32),
                        &&history.file_id.as_bytes()[..],
                        &history.repository_path_utf8,
                        &history.operation_kind,
                    ],
                )
                .map_err(database_error)?;
            self.begin_mutation(history.repository_id)?;
            for resource in identity_resources {
                self.record_identity_resource(resource)?;
            }
            Ok(())
        })
    }

    fn reserve_file_id(&mut self, reservation: FileIdReservation) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_capability(&[
                TransactionCapability::ReserveFileId,
                TransactionCapability::Publish,
            ])?;
            if self.allocation_receipt_required
                && matches!(
                    reservation.origin,
                    FileIdOrigin::Create | FileIdOrigin::Copy
                )
            {
                return Err(DomainError::new(DomainErrorCode::FileIdConflict));
            }
            self.reserve_file_id_inner(reservation, false)
        })
    }

    fn register_allocated_file_id(&mut self, request: NativeFileIdReservation) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_capability(&[
                TransactionCapability::ReserveFileId,
                TransactionCapability::Publish,
            ])?;
            if !request.is_valid() {
                return Err(DomainError::new(DomainErrorCode::FileIdConflict));
            }
            self.require_repository(request.reservation.repository_id)?;
            self.require_pending_idempotency()?;
            self.consume_allocation_receipt(
                &request.allocation_receipt,
                request.reservation.file_id,
            )?;
            self.reserve_file_id_inner(request.reservation, false)
        })
    }

    fn reserve_imported_file_id(
        &mut self,
        request: FileIdImportReservation,
    ) -> Result<FileIdReservationOutcome> {
        poison_transaction_on_error!(self, {
            self.require_repository(request.reservation.repository_id)?;
            self.require_capability(&[
                TransactionCapability::ImportFileId,
                TransactionCapability::Publish,
            ])?;
            self.require_pending_idempotency()?;
            if request.reservation.origin != FileIdOrigin::Import {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            if request.importer_profile.len() > 512 {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let importer_profile = request
                .importer_profile
                .parse::<ProfileRef>()
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            self.validation
                .validate_profile(&importer_profile, "importer")?;
            let inserted = self
                .transaction()?
                .query_opt(
                    "INSERT INTO ogvcs_metadata.file_id_import_mappings
                     (repository_id, importer_profile, source_namespace_digest,
                      source_identity_digest, file_id)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (repository_id, importer_profile, source_namespace_digest,
                                  source_identity_digest) DO NOTHING
                     RETURNING file_id",
                    &[
                        &uuid(request.reservation.repository_id),
                        &request.importer_profile,
                        &&request.source_namespace_digest[..],
                        &&request.source_identity_digest[..],
                        &&request.reservation.file_id.as_bytes()[..],
                    ],
                )
                .map_err(file_id_database_error)?;
            if inserted.is_some() {
                self.reserve_file_id_inner(request.reservation, true)?;
                return Ok(FileIdReservationOutcome::Reserved);
            }
            let existing = self
                .transaction()?
                .query_one(
                    "SELECT mapping.file_id, registry.state::text, registry.origin::text,
                            registry.owner_kind::text, registry.owner_id
                     FROM ogvcs_metadata.file_id_import_mappings AS mapping
                     JOIN ogvcs_metadata.file_id_registry AS registry
                       ON registry.repository_id = mapping.repository_id
                      AND registry.file_id = mapping.file_id
                     WHERE mapping.repository_id = $1 AND mapping.importer_profile = $2
                       AND mapping.source_namespace_digest = $3
                       AND mapping.source_identity_digest = $4",
                    &[
                        &uuid(request.reservation.repository_id),
                        &request.importer_profile,
                        &&request.source_namespace_digest[..],
                        &&request.source_identity_digest[..],
                    ],
                )
                .map_err(database_error)?;
            let existing_file_id: Vec<u8> = existing.get(0);
            let existing_state: String = existing.get(1);
            let existing_origin: String = existing.get(2);
            let existing_owner_kind: String = existing.get(3);
            let existing_owner_id: String = existing.get(4);
            if existing_file_id.as_slice() == request.reservation.file_id.as_bytes()
                && matches!(existing_state.as_str(), "reserved" | "active")
                && existing_origin == "import"
                && existing_owner_kind == file_id_owner(request.reservation.owner_kind)
                && existing_owner_id == request.reservation.owner_id
            {
                Ok(FileIdReservationOutcome::ExactImportReplay)
            } else {
                Err(DomainError::new(DomainErrorCode::FileIdConflict))
            }
        })
    }

    fn tombstone_file_id(
        &mut self,
        repository_id: RepositoryId,
        file_id: FileId,
        expected_state: FileIdExpectedState,
    ) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(repository_id)?;
            self.require_capability(&[
                TransactionCapability::TombstoneFileId,
                TransactionCapability::Publish,
            ])?;
            self.require_pending_idempotency()?;
            let updated = self
                .transaction()?
                .execute(
                    "UPDATE ogvcs_metadata.file_id_registry
                     SET state = 'tombstoned', tombstoned_at = COALESCE(tombstoned_at, clock_timestamp())
                     WHERE repository_id = $1 AND file_id = $2 AND state::text = $3",
                    &[
                        &uuid(repository_id),
                        &&file_id.as_bytes()[..],
                        &expected_state.as_str(),
                    ],
                )
                .map_err(database_error)?;
            if updated == 1 {
                self.begin_mutation(repository_id)?;
                self.require_file_id_event(file_id, FileIdEventState::Tombstoned)?;
                self.record_identity_resource(identity_file_resource(file_id, None, None))?;
                Ok(())
            } else {
                Err(DomainError::new(DomainErrorCode::FileIdConflict))
            }
        })
    }

    fn activate_file_id(&mut self, repository_id: RepositoryId, file_id: FileId) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(repository_id)?;
            self.require_capability(&[
                TransactionCapability::ReserveFileId,
                TransactionCapability::Publish,
            ])?;
            self.require_pending_idempotency()?;
            let updated = self
                .transaction()?
                .execute(
                    "UPDATE ogvcs_metadata.file_id_registry SET state = 'active'
                     WHERE repository_id = $1 AND file_id = $2 AND state = 'reserved'",
                    &[&uuid(repository_id), &&file_id.as_bytes()[..]],
                )
                .map_err(database_error)?;
            if updated == 1 {
                self.begin_mutation(repository_id)?;
                self.require_file_id_event(file_id, FileIdEventState::Active)?;
                self.record_identity_resource(identity_file_resource(file_id, None, None))?;
                Ok(())
            } else {
                Err(DomainError::new(DomainErrorCode::FileIdConflict))
            }
        })
    }

    fn reserve_idempotency(
        &mut self,
        reservation: IdempotencyReservation,
    ) -> Result<IdempotencyReservationOutcome> {
        poison_transaction_on_error!(self, {
            self.require_submit_capability()?;
            if self.pending_idempotency.is_some()
                || self.idempotency_committed
                || !reservation.is_valid_at(SystemTime::now())
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let server_now: SystemTime = self
                .transaction()?
                .query_one("SELECT clock_timestamp()", &[])
                .map_err(database_error)?
                .get(0);
            if !reservation.is_valid_at(server_now) {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let scope = self.idempotency_scope_digest();
            let inserted = self
                .transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.idempotency_records
                     (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
                      state, issued_at, expires_at)
                     VALUES ($1, $2, $3, $4, 'reserved', $5, $6) ON CONFLICT DO NOTHING",
                    &[
                        &&scope[..],
                        &reservation.operation,
                        &reservation.key,
                        &&reservation.semantic_fingerprint[..],
                        &reservation.issued_at,
                        &reservation.expires_at,
                    ],
                )
                .map_err(database_error)?;
            if inserted == 1 {
                self.pending_idempotency = Some(PendingIdempotency {
                    operation: reservation.operation,
                    key: reservation.key,
                    semantic_fingerprint: reservation.semantic_fingerprint,
                });
                return Ok(IdempotencyReservationOutcome::Reserved);
            }
            let row = self
                .transaction()?
                .query_one(
                    "SELECT semantic_fingerprint, state, safe_result
                     FROM ogvcs_metadata.idempotency_records
                     WHERE authenticated_scope_digest = $1 AND operation = $2 AND idempotency_key = $3
                     FOR UPDATE",
                    &[&&scope[..], &reservation.operation, &reservation.key],
                )
                .map_err(database_error)?;
            let fingerprint: Vec<u8> = row.get(0);
            if fingerprint.as_slice() != reservation.semantic_fingerprint {
                self.failed = true;
                return Ok(IdempotencyReservationOutcome::KeyReuseRejected);
            }
            let state: String = row.get(1);
            if state == "committed" {
                let Json(result): Json<Value> = row.get(2);
                self.committed_replay = Some(result.clone());
                self.failed = true;
                Ok(IdempotencyReservationOutcome::CommittedReplay(result))
            } else {
                Err(DomainError::new(DomainErrorCode::ObjectInvalid))
            }
        })
    }

    fn commit_idempotency(
        &mut self,
        reservation: &IdempotencyReservation,
        safe_result: Value,
    ) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_submit_capability()?;
            let expected = PendingIdempotency {
                operation: reservation.operation.clone(),
                key: reservation.key.clone(),
                semantic_fingerprint: reservation.semantic_fingerprint,
            };
            if self.pending_idempotency.as_ref() != Some(&expected)
                || !reservation.is_valid_at(SystemTime::now())
                || json_size(&safe_result).is_none_or(|size| size > 1_048_576)
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let scope = self.idempotency_scope_digest();
            let updated = self
                .transaction()?
                .execute(
                    "UPDATE ogvcs_metadata.idempotency_records
                     SET state = 'committed', safe_result = $4, committed_at = clock_timestamp()
                     WHERE authenticated_scope_digest = $1 AND operation = $2 AND idempotency_key = $3
                       AND semantic_fingerprint = $5 AND state = 'reserved'
                       AND issued_at <= clock_timestamp() AND expires_at > clock_timestamp()",
                    &[
                        &&scope[..],
                        &reservation.operation,
                        &reservation.key,
                        &Json(&safe_result),
                        &&reservation.semantic_fingerprint[..],
                    ],
                )
                .map_err(database_error)?;
            if updated == 1 {
                self.pending_idempotency = None;
                self.idempotency_committed = true;
                Ok(())
            } else {
                Err(DomainError::new(DomainErrorCode::ObjectInvalid))
            }
        })
    }

    fn compare_and_swap_reference(
        &mut self,
        request: ReferenceCasRequest,
    ) -> Result<ReferenceCasResult> {
        poison_transaction_on_error!(self, {
            self.require_repository(request.repository_id)?;
            self.require_capability(&[
                TransactionCapability::CompareAndSwapReference,
                TransactionCapability::Publish,
            ])?;
            self.require_pending_idempotency()?;
            if request
                .desired
                .is_some_and(|target| target.kind != ObjectKind::Snapshot)
            {
                return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            if let Some(desired) = request.desired {
                self.validate_publication_candidate(desired)?;
                let publication = self
                    .transaction()?
                    .query_one(
                        "SELECT snapshot.published_commit_sequence,
                                EXISTS (
                                  SELECT 1 FROM ogvcs_metadata.references AS reference
                                  WHERE reference.repository_id = snapshot.repository_id
                                    AND reference.target_snapshot_digest = snapshot.snapshot_digest
                                )
                         FROM ogvcs_metadata.snapshots AS snapshot
                         WHERE snapshot.repository_id = $1 AND snapshot.snapshot_digest = $2",
                        &[&uuid(request.repository_id), &&desired.digest[..]],
                    )
                    .map_err(database_error)?;
                let published: Option<i64> = publication.get(0);
                let referenced: bool = publication.get(1);
                if published.is_some_and(|sequence| positive_u64(sequence).is_err())
                    || (published.is_none() && referenced)
                {
                    return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                }
            }
            let sequence = self.begin_mutation(request.repository_id)?;
            let row = match request.expected {
                ReferenceExpected::Absent => {
                    let Some(desired) = request.desired else {
                        return self.fail(DomainError::new(DomainErrorCode::ReferenceConflict));
                    };
                    self.transaction()?
                        .query_opt(
                            "INSERT INTO ogvcs_metadata.references
                             (repository_id, reference_kind, reference_name, target_snapshot_digest,
                              generation, commit_sequence)
                             VALUES ($1, $2, $3, $4, 1, $5)
                             ON CONFLICT DO NOTHING
                             RETURNING target_snapshot_digest, generation, commit_sequence",
                            &[
                                &uuid(request.repository_id),
                                &reference_kind(request.kind),
                                &request.name.as_str(),
                                &&desired.digest[..],
                                &(sequence.get() as i64),
                            ],
                        )
                        .map_err(database_error)?
                        .map(|row| (None, Some(desired), row))
                }
                ReferenceExpected::Present { target, generation } => {
                    if target.kind != ObjectKind::Snapshot {
                        return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
                    }
                    if let Some(desired) = request.desired {
                        self.transaction()?
                            .query_opt(
                                "UPDATE ogvcs_metadata.references
                                 SET target_snapshot_digest = $6, generation = generation + 1,
                                     commit_sequence = $7, updated_at = clock_timestamp()
                                 WHERE repository_id = $1 AND reference_kind = $2 AND reference_name = $3
                                   AND target_snapshot_digest = $4 AND generation = $5
                                 RETURNING target_snapshot_digest, generation, commit_sequence",
                                &[
                                    &uuid(request.repository_id),
                                    &reference_kind(request.kind),
                                    &request.name.as_str(),
                                    &&target.digest[..],
                                    &(generation as i64),
                                    &&desired.digest[..],
                                    &(sequence.get() as i64),
                                ],
                            )
                            .map_err(database_error)?
                            .map(|row| (Some(target), Some(desired), row))
                    } else {
                        self.transaction()?
                            .query_opt(
                                "DELETE FROM ogvcs_metadata.references
                                 WHERE repository_id = $1 AND reference_kind = $2 AND reference_name = $3
                                   AND target_snapshot_digest = $4 AND generation = $5
                                 RETURNING target_snapshot_digest, generation + 1, $6::bigint",
                                &[
                                    &uuid(request.repository_id),
                                    &reference_kind(request.kind),
                                    &request.name.as_str(),
                                    &&target.digest[..],
                                    &(generation as i64),
                                    &(sequence.get() as i64),
                                ],
                            )
                            .map_err(database_error)?
                            .map(|row| (Some(target), None, row))
                    }
                }
            };
            let Some((prior, current, row)) = row else {
                return self.fail(DomainError::new(DomainErrorCode::ReferenceConflict));
            };
            let generation = positive_u64(row.get(1))?;
            let newly_accepted_snapshot = if let Some(snapshot) = current {
                let accepted = self
                    .transaction()?
                    .query_opt(
                        "UPDATE ogvcs_metadata.snapshots
                         SET published_commit_sequence = $3
                         WHERE repository_id = $1 AND snapshot_digest = $2
                           AND published_commit_sequence IS NULL
                         RETURNING 1",
                        &[
                            &uuid(request.repository_id),
                            &&snapshot.digest[..],
                            &(sequence.get() as i64),
                        ],
                    )
                    .map_err(database_error)?
                    .is_some();
                if !accepted {
                    let published: Option<i64> = self
                        .transaction()?
                        .query_one(
                            "SELECT published_commit_sequence
                             FROM ogvcs_metadata.snapshots
                             WHERE repository_id = $1 AND snapshot_digest = $2",
                            &[&uuid(request.repository_id), &&snapshot.digest[..]],
                        )
                        .map_err(database_error)?
                        .get(0);
                    if published
                        .and_then(|value| nonnegative_u64(value).ok())
                        .is_none()
                    {
                        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                    }
                }
                accepted
            } else {
                false
            };
            self.require_reference_event(request.kind, &request.name, current, generation)?;
            if newly_accepted_snapshot {
                let snapshot =
                    current.ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                self.require_object_event(snapshot.digest)?;
            }
            self.bind_identity_reference(request.name.as_str())?;
            self.record_identity_resource(identity_reference_resource(
                request.name.as_str(),
                current,
            ))?;
            Ok(ReferenceCasResult {
                prior,
                current,
                generation,
                commit_sequence: CommitSequence::new(positive_u64(row.get(2))?),
            })
        })
    }

    fn append_outbox(&mut self, event: OutboxEvent) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_submit_capability()?;
            self.require_repository(event.repository_id)?;
            if !valid_public_uuid(&event.event_id) || !valid_public_uuid(&event.correlation_id) {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            let fact = self
                .outbox_events
                .iter()
                .find(|required| !required.emitted)
                .map(|required| required.fact.clone())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let sequence = self.ensure_sequence(event.repository_id)?;
            let tenant: Uuid = self
                .transaction()?
                .query_one(
                    "SELECT tenant_id FROM ogvcs_metadata.repositories WHERE repository_id = $1",
                    &[&uuid(event.repository_id)],
                )
                .map_err(database_error)?
                .get(0);
            if tenant.as_bytes() != self.authorization_context.tenant_id.as_bytes() {
                return Err(DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied));
            }
            let safe_payload = fact.safe_payload();
            let resource_opaque_id =
                fact.resource_opaque_id(event.repository_id, event.event_id, &safe_payload)?;
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.outbox_events
                     (event_id, tenant_id, repository_id, commit_sequence, event_type, event_version,
                      correlation_id, resource_type, resource_opaque_id, safe_payload)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                    &[
                        &Uuid::from_bytes(event.event_id),
                        &tenant,
                        &uuid(event.repository_id),
                        &(sequence.get() as i64),
                        &fact.event_type(),
                        &1_i16,
                        &Uuid::from_bytes(event.correlation_id),
                        &fact.resource_type(),
                        &resource_opaque_id,
                        &Json(&safe_payload),
                    ],
                )
                .map_err(database_error)?;
            self.outbox_events
                .iter_mut()
                .find(|required| !required.emitted)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?
                .emitted = true;
            Ok(())
        })
    }

    fn issue_consistency_token(&mut self, minimum: CommitSequence) -> Result<ConsistencyToken> {
        poison_transaction_on_error!(self, {
            self.require_capability(&[
                TransactionCapability::IssueConsistencyToken,
                TransactionCapability::Publish,
            ])?;
            let repository_id = self.authorized_repository_id;
            let subject_digest = self.authorization_context.subject_digest;
            let tenant_id = self.authorization_context.tenant_id;
            let authorization_epoch = self.authorization_context.authorization_epoch;
            let current: i64 = self
                .transaction()?
                .query_one(
                    "SELECT applied_sequence FROM ogvcs_metadata.repository_commit_sequences
                     WHERE repository_id = $1",
                    &[&uuid(repository_id)],
                )
                .map_err(database_error)?
                .get(0);
            if nonnegative_u64(current)? < minimum.get() {
                return Err(DomainError::new(
                    DomainErrorCode::ConsistencyTokenUnsatisfied,
                ));
            }
            let token = opaque_token("ct1.")?;
            let typed = ConsistencyToken::from_opaque(token.clone())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let digest = Sha256::digest(token.as_bytes()).to_vec();
            let authenticated_scope_digest = self
                .identity_binding
                .as_ref()
                .map(|_| self.authenticated_scope_digest.to_vec());
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.consistency_tokens
                     (token_digest, subject_digest, tenant_id, repository_id, minimum_commit_sequence,
                      authorization_epoch, authenticated_scope_digest, issued_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp(),
                             clock_timestamp() + interval '5 minutes')",
                    &[
                        &digest,
                        &&subject_digest[..],
                        &uuid(tenant_id),
                        &uuid(repository_id),
                        &(minimum.get() as i64),
                        &(authorization_epoch as i64),
                        &authenticated_scope_digest,
                    ],
                )
                .map_err(database_error)?;
            Ok(typed)
        })
    }

    fn commit(mut self) -> Result<CommitSequence> {
        let capability = self.capability;
        let authorization_still_valid = self.require_capability(&[capability]).is_ok();
        if !authorization_still_valid
            || self.failed
            || self.pending_idempotency.is_some()
            || (self.mutation_started && !self.idempotency_committed)
            || self.outbox_events.iter().any(|event| !event.emitted)
        {
            if let Some(transaction) = self.transaction.take() {
                let _ = transaction.rollback();
            }
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let sequence = self
            .commit_sequence
            .map(|(_, sequence)| sequence)
            .unwrap_or_else(|| CommitSequence::new(0));
        if let Some(binding) = self.identity_binding.take() {
            let resources = std::mem::take(&mut self.identity_resources);
            let result = json!({
                "commitSequence": sequence.get().to_string(),
                "outcome": "committed",
                "repository": binding.repository,
            });
            let decision = {
                let transaction = self
                    .transaction
                    .as_mut()
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                finalize_identity_decision(
                    binding.participant,
                    transaction,
                    &binding.view,
                    &binding.correlation_id,
                    &binding.tenant,
                    &binding.repository,
                    &binding.permission,
                    binding.reference.as_deref(),
                    &resources,
                    &result,
                )
            };
            if let Err(error) = decision {
                if let Some(transaction) = self.transaction.take() {
                    let _ = transaction.rollback();
                }
                return Err(error);
            }
        }
        self.transaction
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?
            .commit()
            .map_err(database_error)?;
        Ok(sequence)
    }

    fn rollback(mut self) -> Result<()> {
        self.transaction
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?
            .rollback()
            .map_err(database_error)
    }
}

impl<A: AuthorizationPort, V: ObjectValidationPort> MetadataStore for PostgresMetadataStore<A, V> {
    type Transaction<'store>
        = PostgresMetadataTransaction<'store, V, A::AuthorizedView>
    where
        Self: 'store;

    fn begin_authorized(
        &mut self,
        context: &AuthorizationContext,
        capability: TransactionCapability,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<Self::Transaction<'_>> {
        PostgresMetadataStore::begin_authorized(self, context, capability, repository_id, options)
    }
}

impl<A, V> IdentityBoundPostgresMetadataStore<A, V> {
    #[cfg(feature = "legacy-test-adapter")]
    pub fn with_object_validator<W>(
        self,
        validation: W,
    ) -> IdentityBoundPostgresMetadataStore<A, W> {
        IdentityBoundPostgresMetadataStore {
            store: self.store.with_object_validator(validation),
        }
    }

    pub fn migrate(
        &mut self,
        options: crate::MigrationRunOptions,
    ) -> Result<crate::MigrationRunReport> {
        crate::run_migrations(&mut self.store.client, options)
    }
}

impl IdentityBoundPostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator> {
    /// Opens the production metadata adapter with the OGVCS-009 participant
    /// installed before the store can be observed by its caller.
    pub fn connect(
        database_url: &str,
        participant: PostgresTransactionAuthorizationParticipant,
    ) -> Result<Self> {
        Ok(PostgresMetadataStore::connect_internal(database_url)?
            .with_transaction_authorization_participant(participant))
    }
}

impl<A: AuthorizationPort, V: ObjectValidationPort> IdentityBoundPostgresMetadataStore<A, V> {
    pub fn allocate_file_id_identity_authorized(
        &mut self,
        credentials: TransactionCredentialRequest<'_>,
        tenant_id: TenantId,
        repository_id: RepositoryId,
        reservation: IdempotencyReservation,
    ) -> Result<FileIdAllocation> {
        self.store.allocate_file_id_identity_authorized_inner(
            credentials,
            tenant_id,
            repository_id,
            reservation,
        )
    }

    pub fn begin_identity_authorized(
        &mut self,
        credentials: TransactionCredentialRequest<'_>,
        tenant_id: TenantId,
        capability: TransactionCapability,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<PostgresMetadataTransaction<'_, V, IdentityMetadataAuthorizedView>> {
        self.store.begin_identity_authorized_inner(
            credentials,
            tenant_id,
            capability,
            repository_id,
            options,
        )
    }
}

fn tree_entry(row: Row) -> Result<TreeEntryRecord> {
    let file_id = file_id(row.get(2))?;
    let target_kind = object_kind(row.get::<_, i16>(4))?;
    let logical_size: String = row.get(6);
    Ok(TreeEntryRecord {
        ordinal: u32::try_from(row.get::<_, i32>(0))
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
        basename_utf8: row.get(1),
        file_id,
        entry_kind: u16::try_from(row.get::<_, i16>(3))
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
        target: object_ref(target_kind, row.get(5))?,
        logical_size: logical_size
            .parse()
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
    })
}

fn repository_settings_record(
    row: &Row,
    repository_id: RepositoryId,
    expected_tenant: TenantId,
) -> Result<RepositorySettings> {
    let repository_format: String = row.get(0);
    let Json(required_features_json): Json<Value> = row.get(1);
    let case_mode_text: String = row.get(2);
    let path_profile: String = row.get(3);
    let platform_profile: String = row.get(4);
    let content_policy_profile: String = row.get(5);
    let Json(structural_limits): Json<Value> = row.get(6);
    let tenant_boundary = TenantId::from_bytes(*row.get::<_, Uuid>(7).as_bytes());
    let settings_generation: i64 = row.get(8);
    let descriptor_digest: Vec<u8> = row.get(9);
    let descriptor_bytes: Vec<u8> = row.get(10);
    let validation_contract: String = row.get(11);
    let required_features = json_features(&required_features_json)
        .filter(|features| {
            features.len() <= 128 && features.windows(2).all(|pair| pair[0] < pair[1])
        })
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let case_mode = match case_mode_text.as_str() {
        "case-sensitive" => CaseMode::CaseSensitive,
        "case-folded" => CaseMode::CaseFolded,
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    let descriptor = object_ref(ObjectKind::RepositoryDescriptor, descriptor_digest)?;
    if repository_format != VALIDATION_CONTRACT
        || validation_contract != VALIDATION_CONTRACT
        || settings_generation != 1
        || tenant_boundary != expected_tenant
        || !valid_structural_limits(&structural_limits)
        || json_size(&structural_limits).is_none_or(|size| size > 65_536)
        || path_profile.parse::<ProfileRef>().is_err()
        || platform_profile.parse::<ProfileRef>().is_err()
        || content_policy_profile.parse::<ProfileRef>().is_err()
        || object_id(ObjectKind::RepositoryDescriptor, &descriptor_bytes)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?
            != descriptor.digest
        || !descriptor_matches_repository_settings(
            repository_id,
            &required_features,
            &path_profile,
            &content_policy_profile,
            &descriptor_bytes,
        )
    {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok(RepositorySettings {
        repository_format,
        required_features,
        case_mode,
        path_profile,
        platform_profile,
        content_policy_profile,
        structural_limits,
        tenant_boundary,
    })
}

fn reference_record(row: &Row) -> Result<ReferenceRecord> {
    let kind_text: String = row.get(0);
    let kind = parsed_reference_kind(&kind_text)?;
    Ok(ReferenceRecord {
        kind,
        name: ReferenceName::new(row.get(1))
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
        target: object_ref(ObjectKind::Snapshot, row.get(2))?,
        generation: positive_u64(row.get(3))?,
        commit_sequence: CommitSequence::new(positive_u64(row.get(4))?),
    })
}

fn outbox_lease_record(row: &Row) -> Result<OutboxLeaseRecord> {
    let event_id = *row.get::<_, Uuid>(0).as_bytes();
    let event_type: String = row.get(1);
    let event_version: i16 = row.get(2);
    let tenant_id = TenantId::from_bytes(*row.get::<_, Uuid>(3).as_bytes());
    let repository_id = RepositoryId::from_bytes(*row.get::<_, Uuid>(4).as_bytes());
    let commit_sequence = CommitSequence::new(positive_u64(row.get(5))?);
    let correlation_id = *row.get::<_, Uuid>(6).as_bytes();
    let resource_type: String = row.get(7);
    let resource_opaque_id: String = row.get(8);
    let Json(safe_payload): Json<Value> = row.get(9);
    let lease_id = *row.get::<_, Uuid>(10).as_bytes();
    let consumer_id: String = row.get(11);
    let lease_expires_at: SystemTime = row.get(12);
    let delivery_attempt = u32::try_from(row.get::<_, i32>(13))
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let expected_resource_type = match event_type.as_str() {
        "repository.created" => "repository",
        "metadata.object-accepted" => "snapshot",
        "reference.changed" => "reference",
        "file-id.state-changed" => "path",
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    if event_version != 1
        || resource_type != expected_resource_type
        || !valid_public_uuid(&event_id)
        || !valid_public_uuid(&correlation_id)
        || !valid_public_uuid(&lease_id)
        || consumer_id.is_empty()
        || consumer_id.len() > 256
        || consumer_id.contains('\0')
        || delivery_attempt == 0
        || resource_opaque_id.len() != 47
        || !resource_opaque_id.starts_with("rr1.")
        || !resource_opaque_id[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        || safe_payload.get("schemaVersion").and_then(Value::as_str) != Some(OUTBOX_PAYLOAD_SCHEMA)
        || json_size(&safe_payload).is_none_or(|size| size > MAX_JSON_PREFLIGHT_BYTES)
    {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok(OutboxLeaseRecord {
        lease_id,
        consumer_id,
        lease_expires_at,
        delivery_attempt,
        event: OutboxEventRecord {
            event_id,
            event_type,
            tenant_id,
            repository_id,
            commit_sequence,
            correlation_id,
            resource_type,
            resource_opaque_id,
            safe_payload,
        },
    })
}

fn parsed_reference_kind(value: &str) -> Result<ReferenceKind> {
    Ok(match value {
        "branch" => ReferenceKind::Branch,
        "tag" => ReferenceKind::Tag,
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    })
}

fn file_history_record(row: &Row, file_id: FileId) -> Result<FileHistoryRecord> {
    Ok(FileHistoryRecord {
        snapshot: object_ref(ObjectKind::Snapshot, row.get(0))?,
        operation_ordinal: u32::try_from(row.get::<_, i32>(1))
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
        file_id,
        repository_path_utf8: row.get(2),
        operation_kind: row.get(3),
    })
}

fn history_key(digest: &[u8], ordinal: i32) -> Result<Vec<u8>> {
    if digest.len() != 32 || ordinal < 0 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let mut key = digest.to_vec();
    key.extend_from_slice(&ordinal.to_be_bytes());
    Ok(key)
}

fn reference_key(kind: &str, name: &str) -> Result<Vec<u8>> {
    let tag = match kind {
        "branch" => 1,
        "tag" => 2,
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    let mut key = Vec::with_capacity(name.len() + 1);
    key.push(tag);
    key.extend_from_slice(name.as_bytes());
    Ok(key)
}

fn decode_reference_key(key: Option<&[u8]>) -> Result<(Option<String>, Option<String>)> {
    let Some(key) = key else {
        return Ok((None, None));
    };
    let Some((&tag, name)) = key.split_first() else {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    };
    let kind = match tag {
        1 => "branch",
        2 => "tag",
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    let name =
        std::str::from_utf8(name).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok((Some(kind.to_owned()), Some(name.to_owned())))
}

fn decode_history_key(key: Option<&[u8]>) -> Result<(Option<Vec<u8>>, i32)> {
    let Some(key) = key else {
        return Ok((None, 0));
    };
    if key.len() != 36 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok((
        Some(key[..32].to_vec()),
        i32::from_be_bytes(key[32..].try_into().unwrap()),
    ))
}

fn decode_visit(value: Option<&[u8]>) -> Result<u32> {
    match value {
        None => Ok(0),
        Some(bytes) => bytes
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid)),
    }
}

fn snapshot_history_key(visit: u32, ordinal: u32) -> Result<[u8; 8]> {
    if visit == 0 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let mut key = [0_u8; 8];
    key[..4].copy_from_slice(&visit.to_be_bytes());
    key[4..].copy_from_slice(&ordinal.to_be_bytes());
    Ok(key)
}

fn decode_snapshot_history_key(value: Option<&[u8]>) -> Result<(u32, u32)> {
    let Some(value) = value else {
        return Ok((0, 0));
    };
    if value.len() != 8 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok((
        u32::from_be_bytes(value[..4].try_into().unwrap()),
        u32::from_be_bytes(value[4..].try_into().unwrap()),
    ))
}

fn query_digest(
    domain: &[u8],
    repository_id: RepositoryId,
    first: &[u8],
    second: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OpenGameVCS metadata query\0");
    hash.update(domain);
    hash.update(repository_id.as_bytes());
    hash.update(first);
    hash.update(second);
    hash.finalize().into()
}

fn snapshot_history_query_digest(
    domain: &[u8],
    repository_id: RepositoryId,
    snapshot: ObjectRef,
    maximum_depth: u32,
    selector: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OpenGameVCS metadata query\0snapshot-history\0");
    hash.update(domain);
    hash.update(repository_id.as_bytes());
    hash.update(snapshot.kind.code().to_be_bytes());
    hash.update(snapshot.digest);
    hash.update(maximum_depth.to_be_bytes());
    hash.update((selector.len() as u64).to_be_bytes());
    hash.update(selector);
    hash.finalize().into()
}

fn tree_query_digest(
    repository_id: RepositoryId,
    snapshot: ObjectRef,
    tree: ObjectRef,
    prefix: &[String],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OpenGameVCS metadata query\0tree\0");
    hash.update(repository_id.as_bytes());
    hash.update(snapshot.kind.code().to_be_bytes());
    hash.update(snapshot.digest);
    hash.update(tree.kind.code().to_be_bytes());
    hash.update(tree.digest);
    hash.update((prefix.len() as u64).to_be_bytes());
    for segment in prefix {
        hash.update((segment.len() as u64).to_be_bytes());
        hash.update(segment.as_bytes());
    }
    hash.finalize().into()
}

fn valid_tree_prefix(prefix: &[String]) -> bool {
    if prefix.len() > 256 {
        return false;
    }
    let mut bytes = prefix.len().saturating_sub(1);
    for segment in prefix {
        if segment.is_empty()
            || segment.len() > 255
            || matches!(segment.as_str(), "." | "..")
            || segment.contains('/')
            || segment.contains('\0')
        {
            return false;
        }
        let Some(total) = bytes.checked_add(segment.len()) else {
            return false;
        };
        bytes = total;
    }
    bytes <= 4096
}

fn opaque_token(prefix: &str) -> Result<String> {
    let mut entropy = [0_u8; 32];
    getrandom::getrandom(&mut entropy)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(entropy)))
}

fn random_public_uuid() -> Result<[u8; 16]> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}

trait UuidId {
    fn uuid_bytes(self) -> [u8; 16];
}

impl UuidId for RepositoryId {
    fn uuid_bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}

impl UuidId for TenantId {
    fn uuid_bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}

impl UuidId for crate::ProjectId {
    fn uuid_bytes(self) -> [u8; 16] {
        *self.as_bytes()
    }
}

fn uuid(id: impl UuidId) -> Uuid {
    Uuid::from_bytes(id.uuid_bytes())
}

fn object_ref(kind: ObjectKind, digest: Vec<u8>) -> Result<ObjectRef> {
    let digest = digest
        .try_into()
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok(ObjectRef { kind, digest })
}

fn object_kind(code: i16) -> Result<ObjectKind> {
    let code = u64::try_from(code).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    ObjectKind::from_code(code).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn file_id(bytes: Vec<u8>) -> Result<FileId> {
    let bytes = bytes
        .try_into()
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    FileId::new(bytes).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn positive_u64(value: i64) -> Result<u64> {
    let value = nonnegative_u64(value)?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn nonnegative_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn metadata_kind(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::ContentManifest
            | ObjectKind::Tree
            | ObjectKind::ChangeSet
            | ObjectKind::AssetGroupSet
            | ObjectKind::RepositoryDescriptor
            | ObjectKind::Snapshot
            | ObjectKind::Provenance
            | ObjectKind::Attestation
            | ObjectKind::ConflictSet
    )
}

fn valid_structural_limits(limits: &Value) -> bool {
    let Some(limits) = limits.as_object() else {
        return false;
    };
    limits.len() == 4
        && json_limit(limits, "maxTreeEntries").is_some_and(|value| value <= 1_000_000)
        && json_limit(limits, "maxPathBytes").is_some_and(|value| value <= 4_096)
        && json_limit(limits, "maxPathSegments").is_some_and(|value| value <= 256)
        && json_limit(limits, "maxSnapshotParents").is_some_and(|value| value <= 8)
}

fn json_limit(limits: &Map<String, Value>, name: &str) -> Option<u64> {
    limits.get(name).and_then(Value::as_u64)
}

fn cbor_field(value: &Cbor, code: u64) -> Option<&Cbor> {
    let Cbor::Map(fields) = value else {
        return None;
    };
    fields
        .iter()
        .find(|(key, _)| key == &Cbor::UInt(code))
        .map(|(_, value)| value)
}

fn cbor_features(value: &Cbor) -> Option<Vec<u16>> {
    let Cbor::Array(features) = cbor_field(value, 2)? else {
        return None;
    };
    features
        .iter()
        .map(|feature| match feature {
            Cbor::UInt(code) => u16::try_from(*code).ok(),
            _ => None,
        })
        .collect()
}

fn json_features(value: &Value) -> Option<Vec<u16>> {
    value
        .as_array()?
        .iter()
        .map(|feature| feature.as_u64().and_then(|code| u16::try_from(code).ok()))
        .collect()
}

fn repository_object_matches_settings(
    write: &ObjectWrite<'_>,
    descriptor_digest: &[u8],
    required_features: &Value,
    structural_limits: &Value,
    descriptor_bytes: &[u8],
) -> bool {
    let Ok(object) = decode_canonical(write.canonical_bytes, Limits::METADATA) else {
        return false;
    };
    let Ok(descriptor) = decode_canonical(descriptor_bytes, Limits::METADATA) else {
        return false;
    };
    if cbor_features(&object) != json_features(required_features) {
        return false;
    }
    let Some(descriptor_digest): Option<[u8; 32]> = descriptor_digest.try_into().ok() else {
        return false;
    };
    let descriptor_ref = ObjectRef {
        kind: ObjectKind::RepositoryDescriptor,
        digest: descriptor_digest,
    };
    let descriptor_bound = matches!(
        write.object_ref.kind,
        ObjectKind::Tree
            | ObjectKind::ChangeSet
            | ObjectKind::AssetGroupSet
            | ObjectKind::Snapshot
            | ObjectKind::ConflictSet
    );
    if descriptor_bound
        && cbor_field(&object, 16).and_then(|value| ObjectRef::from_cbor(value).ok())
            != Some(descriptor_ref)
    {
        return false;
    }
    match write.object_ref.kind {
        ObjectKind::RepositoryDescriptor => {
            write.object_ref.digest == descriptor_ref.digest
                && matches!(
                    cbor_field(&object, 16),
                    Some(Cbor::Bytes(repository_id))
                        if repository_id.as_slice() == write.repository_id.as_bytes()
                )
        }
        ObjectKind::ContentManifest => {
            let Some(profile) =
                cbor_field(&object, 18).and_then(|value| ProfileRef::from_cbor(value).ok())
            else {
                return false;
            };
            matches!(
                cbor_field(&descriptor, 20),
                Some(Cbor::Array(profiles)) if profiles.iter().any(|candidate| {
                    ProfileRef::from_cbor(candidate).ok().as_ref() == Some(&profile)
                })
            )
        }
        ObjectKind::Tree => cbor_field(&object, 17)
            .and_then(|entries| match entries {
                Cbor::Array(entries) => Some(entries.len() as u64),
                _ => None,
            })
            .zip(
                structural_limits
                    .as_object()
                    .and_then(|limits| json_limit(limits, "maxTreeEntries")),
            )
            .is_some_and(|(actual, maximum)| actual <= maximum),
        ObjectKind::Snapshot => cbor_field(&object, 17)
            .and_then(|parents| match parents {
                Cbor::Array(parents) => Some(parents.len() as u64),
                _ => None,
            })
            .zip(
                structural_limits
                    .as_object()
                    .and_then(|limits| json_limit(limits, "maxSnapshotParents")),
            )
            .is_some_and(|(actual, maximum)| actual <= maximum),
        ObjectKind::ChangeSet
        | ObjectKind::AssetGroupSet
        | ObjectKind::Provenance
        | ObjectKind::Attestation
        | ObjectKind::ConflictSet => true,
        _ => false,
    }
}

fn repository_settings_match_descriptor(request: &RepositoryCreate<'_>) -> bool {
    if request.settings.repository_format != "ogvcs.repository-format@1"
        || request.settings.required_features.len() > 128
        || !valid_structural_limits(&request.settings.structural_limits)
        || json_size(&request.settings.structural_limits).is_none_or(|size| size > 65_536)
        || request.settings.path_profile.parse::<ProfileRef>().is_err()
        || request
            .settings
            .platform_profile
            .parse::<ProfileRef>()
            .is_err()
        || request
            .settings
            .content_policy_profile
            .parse::<ProfileRef>()
            .is_err()
    {
        return false;
    }
    descriptor_matches_repository_settings(
        request.repository_id,
        &request.settings.required_features,
        &request.settings.path_profile,
        &request.settings.content_policy_profile,
        request.descriptor.canonical_bytes,
    )
}

fn descriptor_matches_repository_settings(
    repository_id: RepositoryId,
    required_features: &[u16],
    path_profile: &str,
    content_policy_profile: &str,
    descriptor_bytes: &[u8],
) -> bool {
    let Ok(Cbor::Map(fields)) = decode_canonical(descriptor_bytes, Limits::METADATA) else {
        return false;
    };
    let field = |code| {
        fields
            .iter()
            .find(|(key, _)| key == &Cbor::UInt(code))
            .map(|(_, value)| value)
    };
    let repository_matches = matches!(
        field(16),
        Some(Cbor::Bytes(bytes)) if bytes.as_slice() == repository_id.as_bytes()
    );
    let features_match = match field(2) {
        Some(Cbor::Array(features)) => features
            .iter()
            .map(|value| match value {
                Cbor::UInt(code) => u16::try_from(*code).ok(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .is_some_and(|features| features == required_features),
        _ => false,
    };
    let path_matches = field(17)
        .and_then(|value| ProfileRef::from_cbor(value).ok())
        .is_some_and(|profile| profile.to_string() == path_profile);
    let content_policy_matches = match field(18) {
        Some(Cbor::Array(profiles)) => profiles.iter().any(|value| {
            ProfileRef::from_cbor(value)
                .ok()
                .is_some_and(|profile| profile.to_string() == content_policy_profile)
        }),
        _ => false,
    };
    repository_matches && features_match && path_matches && content_policy_matches
}

fn tree_entry_matches(canonical: &[u8], expected: &TreeEntryWrite) -> bool {
    let Ok(Cbor::Map(tree)) = decode_canonical(canonical, Limits::METADATA) else {
        return false;
    };
    let Some(Cbor::Array(entries)) = tree
        .iter()
        .find(|(key, _)| key == &Cbor::UInt(17))
        .map(|(_, value)| value)
    else {
        return false;
    };
    let Some(Cbor::Map(entry)) = entries.get(expected.ordinal as usize) else {
        return false;
    };
    let field = |code| {
        entry
            .iter()
            .find(|(key, _)| key == &Cbor::UInt(code))
            .map(|(_, value)| value)
    };
    matches!(field(0), Some(Cbor::Text(value)) if value.as_bytes() == expected.basename_utf8)
        && matches!(field(1), Some(Cbor::UInt(value)) if *value == u64::from(expected.entry_kind))
        && matches!(field(2), Some(Cbor::Bytes(value)) if value.as_slice() == expected.file_id.as_bytes())
        && field(4)
            .and_then(|value| ObjectRef::from_cbor(value).ok())
            .is_some_and(|target| target == expected.target)
        && matches!(field(5), Some(Cbor::UInt(value)) if *value == expected.logical_size)
}

fn snapshot_index_matches(canonical: &[u8], expected: &SnapshotWrite) -> bool {
    let Ok(Cbor::Map(snapshot)) = decode_canonical(canonical, Limits::METADATA) else {
        return false;
    };
    let field = |code| {
        snapshot
            .iter()
            .find(|(key, _)| key == &Cbor::UInt(code))
            .map(|(_, value)| value)
    };
    let root_matches = field(18)
        .and_then(|value| ObjectRef::from_cbor(value).ok())
        .is_some_and(|root| root == expected.root_tree);
    let parents_match = match field(17) {
        Some(Cbor::Array(parents)) => parents
            .iter()
            .map(|value| ObjectRef::from_cbor(value).ok())
            .collect::<Option<Vec<_>>>()
            .is_some_and(|parents| parents == expected.parents),
        _ => false,
    };
    root_matches && parents_match
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalFileHistoryFact {
    operation_ordinal: u32,
    file_id: FileId,
    repository_path_utf8: Vec<u8>,
    operation_kind: String,
    affected_paths: Vec<CanonicalAffectedPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalAffectedPath {
    file_id: FileId,
    repository_path_utf8: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredFileIdEvidence {
    state: String,
    origin: String,
    first_change_set: Option<[u8; 32]>,
    first_operation: Option<u64>,
}

fn metadata_closure(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    candidate: ObjectRef,
) -> Result<BTreeSet<ObjectRef>> {
    let limits = RepositoryLimits::default();
    let mut closure = BTreeSet::new();
    let mut stack = vec![candidate];
    let mut traversed_edges = 0_usize;
    while let Some(reference) = stack.pop() {
        if reference.kind == ObjectKind::Chunk || closure.contains(&reference) {
            continue;
        }
        if !metadata_kind(reference.kind) {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let canonical = entries
            .get(&reference)
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let actual = object_id(reference.kind, canonical)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if actual != reference.digest {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let value = decode_canonical(canonical, Limits::METADATA)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        closure.insert(reference);
        let mut outbound = Vec::new();
        collect_object_references(&value, &mut outbound);
        traversed_edges = traversed_edges
            .checked_add(outbound.len())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if traversed_edges > limits.max_edges {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        for target in outbound.into_iter().rev() {
            if target.kind != ObjectKind::Chunk && !closure.contains(&target) {
                stack.push(target);
            }
        }
        if closure.len() > limits.max_objects {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
    }
    Ok(closure)
}

fn required_chunk_references(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    closure: &BTreeSet<ObjectRef>,
) -> Result<BTreeSet<ObjectRef>> {
    let mut chunks = BTreeSet::new();
    for reference in closure {
        let value = entries
            .get(reference)
            .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let mut outbound = Vec::new();
        collect_object_references(&value, &mut outbound);
        chunks.extend(
            outbound
                .into_iter()
                .filter(|target| target.kind == ObjectKind::Chunk),
        );
    }
    Ok(chunks)
}

fn resolve_tree_prefix(
    trees: &BTreeMap<ObjectRef, Vec<u8>>,
    root: ObjectRef,
    prefix: &[String],
    maximum_edges: usize,
) -> Result<ObjectRef> {
    if root.kind != ObjectKind::Tree {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let mut current = root;
    let mut traversed_edges = 0_usize;
    for segment in prefix {
        let value = trees
            .get(&current)
            .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let entries = match cbor_field(&value, 17) {
            Some(Cbor::Array(entries)) => entries,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        traversed_edges = traversed_edges
            .checked_add(entries.len())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if traversed_edges > maximum_edges {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        current = entries
            .iter()
            .find(|entry| matches!(cbor_field(entry, 0), Some(Cbor::Text(name)) if name == segment))
            .filter(|entry| matches!(cbor_field(entry, 1), Some(Cbor::UInt(1))))
            .and_then(|entry| cbor_field(entry, 4))
            .and_then(|value| ObjectRef::from_cbor(value).ok())
            .filter(|reference| reference.kind == ObjectKind::Tree)
            .ok_or_else(not_found)?;
    }
    Ok(current)
}

fn candidate_tree_file_ids(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    candidate: ObjectRef,
) -> Result<BTreeSet<FileId>> {
    let snapshot = entries
        .get(&candidate)
        .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let root = cbor_field(&snapshot, 18)
        .and_then(|value| ObjectRef::from_cbor(value).ok())
        .filter(|reference| reference.kind == ObjectKind::Tree)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let mut file_ids = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![root];
    let mut traversed_edges = 0_usize;
    while let Some(tree) = stack.pop() {
        if !visited.insert(tree) {
            continue;
        }
        let value = entries
            .get(&tree)
            .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let tree_entries = match cbor_field(&value, 17) {
            Some(Cbor::Array(tree_entries)) => tree_entries,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        traversed_edges = traversed_edges
            .checked_add(tree_entries.len())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if traversed_edges > RepositoryLimits::default().max_edges {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        for entry in tree_entries {
            let file_id = cbor_field(entry, 2)
                .and_then(|value| FileId::from_cbor(value).ok())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            file_ids.insert(file_id);
            let kind = match cbor_field(entry, 1) {
                Some(Cbor::UInt(kind)) => *kind,
                _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
            };
            let target = cbor_field(entry, 4)
                .and_then(|value| ObjectRef::from_cbor(value).ok())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            if kind == 1 {
                if target.kind != ObjectKind::Tree {
                    return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
                }
                stack.push(target);
            }
        }
    }
    Ok(file_ids)
}

fn verify_lifetime_evidence<'a>(
    stored: &BTreeMap<FileId, StoredFileIdEvidence>,
    records: impl Iterator<Item = &'a LifetimeRecord>,
    candidate_change: ObjectRef,
) -> Result<()> {
    for record in records {
        let evidence = stored
            .get(&record.file_id)
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let expected_origin = match record.origin {
            LifetimeOrigin::NativeCreate => "create",
            LifetimeOrigin::NativeCopy => "copy",
            LifetimeOrigin::Import => "import",
        };
        if evidence.origin != expected_origin
            || evidence.first_change_set != Some(record.first_change_set.digest)
            || evidence.first_operation != Some(record.first_operation)
            || (record.first_change_set == candidate_change && evidence.state != "active")
            || !matches!(evidence.state.as_str(), "active" | "tombstoned")
        {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
    }
    Ok(())
}

fn verify_active_file_ids(
    stored: &BTreeMap<FileId, StoredFileIdEvidence>,
    required: &BTreeSet<FileId>,
) -> Result<()> {
    if required.iter().all(|file_id| {
        stored
            .get(file_id)
            .is_some_and(|evidence| evidence.state == "active")
    }) {
        Ok(())
    } else {
        Err(DomainError::new(DomainErrorCode::ObjectInvalid))
    }
}

fn snapshot_change_ref(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    snapshot: ObjectRef,
) -> Result<ObjectRef> {
    entries
        .get(&snapshot)
        .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
        .and_then(|value| cbor_field(&value, 19).and_then(|value| ObjectRef::from_cbor(value).ok()))
        .filter(|reference| reference.kind == ObjectKind::ChangeSet)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn change_base_snapshot_ref(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    change: ObjectRef,
) -> Result<Option<ObjectRef>> {
    let value = entries
        .get(&change)
        .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    cbor_field(&value, 17)
        .map(|value| {
            ObjectRef::from_cbor(value)
                .ok()
                .filter(|reference| reference.kind == ObjectKind::Snapshot)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))
        })
        .transpose()
}

fn derive_lifetime_evidence(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    closure: &BTreeSet<ObjectRef>,
    candidate: ObjectRef,
) -> Result<(Vec<LifetimeRecord>, Vec<LifetimeRecord>)> {
    let mut prior = BTreeMap::<FileId, LifetimeRecord>::new();
    let mut working = BTreeMap::<FileId, LifetimeRecord>::new();
    for snapshot in closure
        .iter()
        .filter(|reference| reference.kind == ObjectKind::Snapshot)
    {
        let change = snapshot_change_ref(entries, *snapshot)?;
        let value = entries
            .get(&change)
            .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let operations = match cbor_field(&value, 18) {
            Some(Cbor::Array(operations)) => operations,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        for operation in operations {
            let operation_code = match cbor_field(operation, 1) {
                Some(Cbor::UInt(code)) if matches!(*code, 1 | 3) => *code,
                Some(Cbor::UInt(_)) => continue,
                _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
            };
            let sequence = match cbor_field(operation, 0) {
                Some(Cbor::UInt(sequence)) => *sequence,
                _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
            };
            let after = cbor_field(operation, 3)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let file_id = cbor_field(after, 2)
                .and_then(|value| FileId::from_cbor(value).ok())
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let proof = cbor_field(operation, 5)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let allocation_kind = match cbor_field(proof, 1) {
                Some(Cbor::UInt(kind)) if matches!(*kind, 1 | 2) => *kind,
                _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
            };
            let import_mapping_key = if allocation_kind == 2 {
                let key: [u8; 32] = cbor_field(proof, 2)
                    .and_then(|value| match value {
                        Cbor::Bytes(bytes) => bytes.as_slice().try_into().ok(),
                        _ => None,
                    })
                    .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
                Some(key)
            } else {
                None
            };
            let origin = if allocation_kind == 2 {
                LifetimeOrigin::Import
            } else if operation_code == 1 {
                LifetimeOrigin::NativeCreate
            } else {
                LifetimeOrigin::NativeCopy
            };
            let record = LifetimeRecord {
                file_id,
                origin,
                first_change_set: change,
                first_operation: sequence,
                import_mapping_key,
            };
            if prior.contains_key(&file_id) || working.contains_key(&file_id) {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            if *snapshot == candidate && origin != LifetimeOrigin::Import {
                working.insert(file_id, record);
            } else {
                prior.insert(file_id, record);
            }
        }
    }
    Ok((
        prior.into_values().collect(),
        working.into_values().collect(),
    ))
}

fn collect_object_references(value: &Cbor, references: &mut Vec<ObjectRef>) {
    if let Ok(reference) = ObjectRef::from_cbor(value) {
        references.push(reference);
        return;
    }
    match value {
        Cbor::Array(values) => {
            for value in values {
                collect_object_references(value, references);
            }
        }
        Cbor::Map(fields) => {
            for (key, value) in fields {
                collect_object_references(key, references);
                collect_object_references(value, references);
            }
        }
        Cbor::UInt(_) | Cbor::NInt(_) | Cbor::Bytes(_) | Cbor::Text(_) | Cbor::Bool(_) => {}
    }
}

fn designated_snapshot_root(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    candidate: ObjectRef,
) -> Result<ObjectRef> {
    let mut visited = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut stack = vec![candidate];
    while let Some(reference) = stack.pop() {
        if reference.kind != ObjectKind::Snapshot || !visited.insert(reference) {
            continue;
        }
        let value = entries
            .get(&reference)
            .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let parents = match cbor_field(&value, 17) {
            Some(Cbor::Array(parents)) => parents,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        if parents.is_empty() {
            roots.insert(reference);
        }
        for parent in parents {
            let parent = ObjectRef::from_cbor(parent)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            if parent.kind != ObjectKind::Snapshot {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
            stack.push(parent);
        }
    }
    if roots.len() == 1 {
        Ok(*roots.iter().next().unwrap())
    } else {
        Err(DomainError::new(DomainErrorCode::ObjectInvalid))
    }
}

fn enforce_configured_tree_limits(
    entries: &BTreeMap<Vec<String>, ogvcs_object_model::EntryState>,
    configured: &Value,
) -> Result<()> {
    let limits = configured
        .as_object()
        .filter(|limits| valid_structural_limits(configured) && limits.len() == 4)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let max_entries = usize::try_from(json_limit(limits, "maxTreeEntries").unwrap())
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let max_path_bytes = usize::try_from(json_limit(limits, "maxPathBytes").unwrap())
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let max_path_segments = usize::try_from(json_limit(limits, "maxPathSegments").unwrap())
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    if entries.len() > max_entries {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    for path in entries.keys() {
        let path_bytes = path
            .iter()
            .try_fold(path.len().saturating_sub(1), |total, segment| {
                total.checked_add(segment.len())
            })
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if path.len() > max_path_segments || path_bytes > max_path_bytes {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
    }
    Ok(())
}

fn canonical_file_history_facts(
    entries: &BTreeMap<ObjectRef, Vec<u8>>,
    snapshot: ObjectRef,
) -> Result<Vec<CanonicalFileHistoryFact>> {
    let snapshot_value = entries
        .get(&snapshot)
        .and_then(|canonical| decode_canonical(canonical, Limits::METADATA).ok())
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let change = cbor_field(&snapshot_value, 19)
        .and_then(|value| ObjectRef::from_cbor(value).ok())
        .filter(|reference| reference.kind == ObjectKind::ChangeSet)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let change_bytes = entries
        .get(&change)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    canonical_file_history_from_change(change_bytes)
}

fn canonical_file_history_from_change(canonical: &[u8]) -> Result<Vec<CanonicalFileHistoryFact>> {
    let value = decode_canonical(canonical, Limits::METADATA)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let operations = match cbor_field(&value, 18) {
        Some(Cbor::Array(operations)) => operations,
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    let mut facts = Vec::new();
    for operation in operations {
        let ordinal = match cbor_field(operation, 0) {
            Some(Cbor::UInt(value)) => u32::try_from(*value)
                .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        let kind = match cbor_field(operation, 1) {
            Some(Cbor::UInt(value)) => *value,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        let (state_field, affected_state_fields, operation_kind): (u64, &[u64], &str) = match kind {
            1 => (3, &[3], allocation_operation_kind(operation, "create")?),
            2 => (3, &[2, 3], "modify"),
            3 => (3, &[4, 3], allocation_operation_kind(operation, "copy")?),
            4 => (3, &[2, 3], "move"),
            5 => (3, &[2, 3], "rename"),
            6 => (2, &[2], "delete"),
            7 => (3, &[3], "restore"),
            8..=11 => continue,
            _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
        };
        let state = cbor_field(operation, state_field)
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let (file_id, path) = canonical_file_path(state)?;
        let mut affected_paths = Vec::with_capacity(affected_state_fields.len());
        for field in affected_state_fields {
            let affected_state = cbor_field(operation, *field)
                .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
            let (file_id, repository_path_utf8) = canonical_file_path(affected_state)?;
            let affected = CanonicalAffectedPath {
                file_id,
                repository_path_utf8,
            };
            if !affected_paths.contains(&affected) {
                affected_paths.push(affected);
            }
        }
        facts.push(CanonicalFileHistoryFact {
            operation_ordinal: ordinal,
            file_id,
            repository_path_utf8: path,
            operation_kind: operation_kind.to_owned(),
            affected_paths,
        });
    }
    facts.sort_by_key(|fact| fact.operation_ordinal);
    if facts
        .windows(2)
        .any(|pair| pair[0].operation_ordinal == pair[1].operation_ordinal)
    {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok(facts)
}

fn canonical_file_path(state: &Cbor) -> Result<(FileId, Vec<u8>)> {
    let file_id = cbor_field(state, 2)
        .and_then(|value| FileId::from_cbor(value).ok())
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let segments = match cbor_field(state, 0) {
        Some(Cbor::Array(segments)) if !segments.is_empty() => segments
            .iter()
            .map(|segment| match segment {
                Cbor::Text(segment) if !segment.is_empty() => Some(segment.as_bytes()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    let length = segments
        .iter()
        .try_fold(segments.len() - 1, |total, segment| {
            total.checked_add(segment.len())
        })
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    if length > 4096 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let mut path = Vec::with_capacity(length);
    for (index, segment) in segments.into_iter().enumerate() {
        if index > 0 {
            path.push(b'/');
        }
        path.extend_from_slice(segment);
    }
    Ok((file_id, path))
}

fn allocation_operation_kind<'a>(operation: &Cbor, native: &'a str) -> Result<&'a str> {
    match cbor_field(operation, 5).and_then(|proof| cbor_field(proof, 1)) {
        Some(Cbor::UInt(1)) => Ok(native),
        Some(Cbor::UInt(2)) => Ok("import"),
        _ => Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    }
}

fn allocation_history_origin(operation_kind: &str) -> Option<&'static str> {
    match operation_kind {
        "create" => Some("create"),
        "copy" => Some("copy"),
        "import" => Some("import"),
        _ => None,
    }
}

fn reference_kind(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::Branch => "branch",
        ReferenceKind::Tag => "tag",
    }
}

fn json_size(value: &Value) -> Option<usize> {
    let mut stack = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut scheduled_nodes = 1_usize;
    let mut conservative_bytes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1)?;
        if nodes > MAX_JSON_PREFLIGHT_NODES || depth > MAX_JSON_PREFLIGHT_DEPTH {
            return None;
        }
        let add = match value {
            Value::Null => 4,
            Value::Bool(true) => 4,
            Value::Bool(false) => 5,
            Value::Number(number) => number.to_string().len(),
            Value::String(value) => value.len().checked_mul(6)?.checked_add(2)?,
            Value::Array(values) => {
                scheduled_nodes = scheduled_nodes.checked_add(values.len())?;
                if scheduled_nodes > MAX_JSON_PREFLIGHT_NODES {
                    return None;
                }
                for value in values {
                    stack.push((value, depth.checked_add(1)?));
                }
                values.len().checked_add(2)?
            }
            Value::Object(values) => {
                scheduled_nodes = scheduled_nodes.checked_add(values.len())?;
                if scheduled_nodes > MAX_JSON_PREFLIGHT_NODES {
                    return None;
                }
                let mut bytes = values.len().checked_add(2)?;
                for (key, value) in values {
                    bytes = bytes
                        .checked_add(key.len().checked_mul(6)?)?
                        .checked_add(3)?;
                    stack.push((value, depth.checked_add(1)?));
                }
                bytes
            }
        };
        conservative_bytes = conservative_bytes.checked_add(add)?;
        if conservative_bytes > MAX_JSON_PREFLIGHT_BYTES {
            return None;
        }
    }
    serde_json::to_vec(value).ok().map(|bytes| bytes.len())
}

fn valid_public_uuid(bytes: &[u8; 16]) -> bool {
    matches!(bytes[6] >> 4, 1..=8) && bytes[8] & 0xc0 == 0x80
}

fn identity_tenant_id(tenant_id: TenantId) -> String {
    format!("tenant.{}", hex_bytes(tenant_id.as_bytes()))
}

fn identity_repository_id(repository_id: RepositoryId) -> String {
    format!("repository.{}", hex_bytes(repository_id.as_bytes()))
}

fn identity_repository_resource(
    capability: TransactionCapability,
) -> IdentityAuthorizationResource {
    IdentityAuthorizationResource {
        resource_type: "repository".to_owned(),
        path: None,
        file_id: None,
        object_id: None,
        name: Some(capability.as_str().to_owned()),
    }
}

fn identity_allocation_resource() -> IdentityAuthorizationResource {
    IdentityAuthorizationResource {
        resource_type: "repository".to_owned(),
        path: None,
        file_id: None,
        object_id: None,
        name: Some("file-id.allocate".to_owned()),
    }
}

fn identity_object_resource(reference: ObjectRef) -> IdentityAuthorizationResource {
    let resource_type = match reference.kind {
        ObjectKind::Snapshot => "snapshot",
        ObjectKind::Tree => "tree",
        _ => "object",
    };
    IdentityAuthorizationResource {
        resource_type: resource_type.to_owned(),
        path: None,
        file_id: None,
        object_id: Some(reference.to_string()),
        name: None,
    }
}

fn identity_file_resource(
    file_id: FileId,
    path: Option<String>,
    object: Option<ObjectRef>,
) -> IdentityAuthorizationResource {
    IdentityAuthorizationResource {
        resource_type: "path".to_owned(),
        path,
        file_id: Some(hex_bytes(file_id.as_bytes())),
        object_id: object.map(|reference| reference.to_string()),
        name: None,
    }
}

fn root_relative_path(path: &[String], state: &EntryState) -> Result<String> {
    if path.is_empty() || state.path != path {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let length = path
        .iter()
        .try_fold(path.len() - 1, |total, segment| {
            total.checked_add(segment.len())
        })
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    if length > 4096 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    Ok(path.join("/"))
}

fn prepare_identity_resource(
    resources: &mut Vec<IdentityAuthorizationResource>,
    resource: &IdentityAuthorizationResource,
) -> bool {
    if resource.resource_type == "path" {
        if let Some(file_id) = resource.file_id.as_deref() {
            if resource.path.is_some() {
                resources.retain(|existing| {
                    existing.resource_type != "path"
                        || existing.file_id.as_deref() != Some(file_id)
                        || existing.path.is_some()
                });
                if resources.iter().any(|existing| {
                    existing.resource_type == "path"
                        && existing.file_id.as_deref() == Some(file_id)
                        && existing.path == resource.path
                }) {
                    return false;
                }
            } else if resources.iter().any(|existing| {
                existing.resource_type == "path"
                    && existing.file_id.as_deref() == Some(file_id)
                    && existing.path.is_some()
            }) {
                return false;
            }
        }
    }
    !resources.contains(resource)
}

fn identity_reference_resource(
    name: &str,
    target: Option<ObjectRef>,
) -> IdentityAuthorizationResource {
    IdentityAuthorizationResource {
        resource_type: "reference".to_owned(),
        path: None,
        file_id: None,
        object_id: target.map(|reference| reference.to_string()),
        name: Some(name.to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_identity_decision(
    participant: &PostgresTransactionAuthorizationParticipant,
    transaction: &mut Transaction<'_>,
    view: &TransactionAuthorizedView,
    correlation_id: &str,
    tenant: &str,
    repository: &str,
    permission: &str,
    reference: Option<&str>,
    resources: &[IdentityAuthorizationResource],
    result: &Value,
) -> Result<()> {
    participant
        .recheck_batch(
            transaction,
            view,
            &TransactionBatchRecheck {
                tenant,
                repository,
                permission,
                reference,
                resources,
            },
        )
        .map_err(|_| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
    participant
        .append_decision_commitment(
            transaction,
            view,
            &DecisionCommitmentRequest {
                correlation_id,
                tenant,
                repository,
                permission,
                reference,
                resources,
                result,
            },
        )
        .map_err(|_| DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied))?;
    Ok(())
}

fn poison_identity_transaction(transaction: &mut Transaction<'_>) {
    let _ = transaction.simple_query("SELECT ogvcs_identity.poison_transaction()");
}

fn allocation_result(allocation: &FileIdAllocation) -> Result<Value> {
    let expires_at = allocation
        .expires_at_unix_ms()
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok(json!({
        "schemaVersion": "ogvcs.repository-metadata/file-id-allocation/v1",
        "repositoryId": hex_bytes(allocation.repository_id.as_bytes()),
        "fileId": allocation.file_id.to_string(),
        "allocationReceipt": allocation.allocation_receipt.as_str(),
        "expiresAtUnixMs": expires_at.to_string(),
    }))
}

fn normalize_unix_milliseconds(value: SystemTime) -> Result<SystemTime> {
    let milliseconds = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(milliseconds))
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))
}

fn decode_allocation_result(
    repository_id: RepositoryId,
    value: &Value,
) -> Result<FileIdAllocation> {
    let object = value
        .as_object()
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    if object.get("schemaVersion").and_then(Value::as_str)
        != Some("ogvcs.repository-metadata/file-id-allocation/v1")
        || object.get("repositoryId").and_then(Value::as_str)
            != Some(hex_bytes(repository_id.as_bytes()).as_str())
    {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let file_id = object
        .get("fileId")
        .and_then(Value::as_str)
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?
        .parse::<FileId>()
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let allocation_receipt = object
        .get("allocationReceipt")
        .and_then(Value::as_str)
        .and_then(|value| AllocationReceipt::from_opaque(value.to_owned()))
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let expires_at_ms = object
        .get("expiresAtUnixMs")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    let expires_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(expires_at_ms))
        .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok(FileIdAllocation {
        repository_id,
        file_id,
        allocation_receipt,
        expires_at,
    })
}

fn decode_identity_digest(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    }
    Ok(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn metadata_scope_digest(
    context: &AuthorizationContext,
    repository_id: RepositoryId,
    capability: TransactionCapability,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OpenGameVCS metadata idempotency scope\0");
    hash.update(context.subject_digest);
    hash.update(context.tenant_id.as_bytes());
    hash.update(context.authorization_epoch.to_be_bytes());
    hash.update(repository_id.as_bytes());
    hash.update(capability.as_str().as_bytes());
    hash.finalize().into()
}

fn identity_metadata_scope_digest(
    authority_scope_digest: [u8; 32],
    tenant_id: TenantId,
    repository_id: RepositoryId,
    capability: TransactionCapability,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OpenGameVCS identity-bound metadata scope v1\0");
    hash.update(authority_scope_digest);
    hash.update(tenant_id.as_bytes());
    hash.update(repository_id.as_bytes());
    hash.update((capability.as_str().len() as u64).to_be_bytes());
    hash.update(capability.as_str().as_bytes());
    hash.finalize().into()
}

fn file_id_origin(origin: FileIdOrigin) -> &'static str {
    match origin {
        FileIdOrigin::Create => "create",
        FileIdOrigin::Copy => "copy",
        FileIdOrigin::Restore => "restore",
        FileIdOrigin::Import => "import",
    }
}

fn file_id_owner(owner: FileIdOwnerKind) -> &'static str {
    match owner {
        FileIdOwnerKind::Published => "published",
        FileIdOwnerKind::Draft => "draft",
        FileIdOwnerKind::Shelf => "shelf",
    }
}

fn not_found() -> DomainError {
    DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)
}

fn database_error(error: postgres::Error) -> DomainError {
    if error
        .as_db_error()
        .is_some_and(|error| matches!(error.code().code(), "40001" | "40P01"))
    {
        DomainError::database_concurrency()
    } else {
        DomainError::new(DomainErrorCode::ObjectInvalid)
    }
}

fn file_id_database_error(error: postgres::Error) -> DomainError {
    if error
        .as_db_error()
        .is_some_and(|error| matches!(error.code().code(), "23505" | "23503" | "23514"))
    {
        DomainError::new(DomainErrorCode::FileIdConflict)
    } else {
        database_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_file_history_from_change, identity_file_resource, identity_metadata_scope_digest,
        prepare_identity_resource, ObjectKind,
    };
    use crate::{FileId, ObjectRef, RepositoryId, TenantId, TransactionCapability};

    #[test]
    fn authority_scope_is_domain_separated_by_tenant_repository_and_capability() {
        let authority_scope = [0x11; 32];
        let tenant = TenantId::from_bytes([0x22; 16]);
        let other_tenant = TenantId::from_bytes([0x23; 16]);
        let repository = RepositoryId::from_bytes([0x33; 16]);
        let other_repository = RepositoryId::from_bytes([0x34; 16]);
        let baseline = identity_metadata_scope_digest(
            authority_scope,
            tenant,
            repository,
            TransactionCapability::ReserveFileId,
        );
        assert_eq!(
            baseline,
            identity_metadata_scope_digest(
                authority_scope,
                tenant,
                repository,
                TransactionCapability::ReserveFileId,
            )
        );
        assert_ne!(
            baseline,
            identity_metadata_scope_digest(
                authority_scope,
                other_tenant,
                repository,
                TransactionCapability::ReserveFileId,
            )
        );
        assert_ne!(
            baseline,
            identity_metadata_scope_digest(
                authority_scope,
                tenant,
                other_repository,
                TransactionCapability::ReserveFileId,
            )
        );
        assert_ne!(
            baseline,
            identity_metadata_scope_digest(
                authority_scope,
                tenant,
                repository,
                TransactionCapability::TombstoneFileId,
            )
        );
    }

    #[test]
    fn move_authorization_uses_both_full_root_relative_paths() {
        let facts = canonical_file_history_from_change(include_bytes!(
            "../../../../spec/repository-format/v1/vectors/scenarios/objects/transition-move/candidate-change.cbor"
        ))
        .unwrap();
        assert_eq!(facts.len(), 1);
        let affected = &facts[0].affected_paths;
        assert_eq!(affected.len(), 2);
        assert_eq!(affected[0].repository_path_utf8, b"left/asset");
        assert_eq!(affected[1].repository_path_utf8, b"right/asset");
        assert_eq!(affected[0].file_id.as_bytes(), &[0x21; 16]);
        assert_eq!(affected[1].file_id.as_bytes(), &[0x21; 16]);
        assert!(affected
            .iter()
            .all(|resource| resource.repository_path_utf8 != b"asset"));
    }

    #[test]
    fn copy_authorization_uses_exact_source_and_destination_file_ids() {
        let facts = canonical_file_history_from_change(include_bytes!(
            "../../../../spec/repository-format/v1/vectors/scenarios/objects/transition-copy/candidate-change.cbor"
        ))
        .unwrap();
        assert_eq!(facts.len(), 1);
        let affected = &facts[0].affected_paths;
        assert_eq!(affected.len(), 2);
        assert_eq!(affected[0].repository_path_utf8, b"asset");
        assert_eq!(affected[0].file_id.as_bytes(), &[0x21; 16]);
        assert_eq!(affected[1].repository_path_utf8, b"asset-copy");
        assert_eq!(affected[1].file_id.as_bytes(), &[0x22; 16]);
    }

    #[test]
    fn complete_path_replaces_file_id_only_placeholder_without_losing_both_move_paths() {
        let file_id = FileId::new([0x21; 16]).unwrap();
        let target = ObjectRef {
            kind: ObjectKind::ContentManifest,
            digest: [0x31; 32],
        };
        let snapshot = ObjectRef {
            kind: ObjectKind::Snapshot,
            digest: [0x32; 32],
        };
        let mut resources = vec![identity_file_resource(file_id, None, Some(target))];
        let before = identity_file_resource(file_id, Some("left/asset".to_owned()), Some(snapshot));
        assert!(prepare_identity_resource(&mut resources, &before));
        resources.push(before);
        let after = identity_file_resource(file_id, Some("right/asset".to_owned()), Some(snapshot));
        assert!(prepare_identity_resource(&mut resources, &after));
        resources.push(after);
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].path.as_deref(), Some("left/asset"));
        assert_eq!(resources[1].path.as_deref(), Some("right/asset"));
        let late_placeholder = identity_file_resource(file_id, None, None);
        assert!(!prepare_identity_resource(
            &mut resources,
            &late_placeholder
        ));
        assert_eq!(resources.len(), 2);
    }
}
