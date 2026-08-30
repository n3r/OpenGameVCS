use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ogvcs_object_model::{
    decode_canonical, object_id, scan_metadata, validate_metadata_schema, Cbor, Limits, ObjectKind,
    ProfileRef,
};
use postgres::{Client, IsolationLevel, NoTls, Row, Transaction};
use postgres::types::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    AuthorizationContext, AuthorizationPort, CaseMode, CommitSequence, ConsistencyToken,
    CursorToken, DenyAllAuthorization, DomainError, DomainErrorCode, FileHistoryRecord,
    FileHistoryWrite, FileId, FileIdImportReservation, FileIdOrigin, FileIdOwnerKind,
    FileIdReservation, FileIdReservationOutcome, IdempotencyReservation,
    IdempotencyReservationOutcome, MetadataStore, MetadataTransaction, ObjectPutOutcome, ObjectRef,
    ObjectWrite, ObjectValidationPort, OutboxEvent, Page, PageRequest, ProductionObjectValidator,
    ReferenceCasRequest, ReferenceCasResult, ReferenceExpected, ReferenceKind, ReferenceName,
    ReferenceRecord, RepositoryCreate, RepositoryId, Result, SnapshotWrite, TenantId,
    TransactionOptions, TreeEntryRecord, TreeEntryWrite,
};

const VALIDATION_CONTRACT: &str = "ogvcs.repository-format@1";
const EVENT_REPOSITORY: usize = 0;
const EVENT_OBJECT: usize = 1;
const EVENT_REFERENCE: usize = 2;
const EVENT_FILE_ID: usize = 3;

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
}

impl PostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator> {
    pub fn connect(database_url: &str) -> Result<Self> {
        let client = Client::connect(database_url, NoTls).map_err(database_error)?;
        Ok(Self {
            client,
            authorization: DenyAllAuthorization,
            validation: ProductionObjectValidator::default(),
        })
    }
}

impl<A, V> PostgresMetadataStore<A, V> {
    pub fn with_authorizer<B>(self, authorization: B) -> PostgresMetadataStore<B, V> {
        PostgresMetadataStore {
            client: self.client,
            authorization,
            validation: self.validation,
        }
    }

    pub fn with_object_validator<W>(self, validation: W) -> PostgresMetadataStore<A, W> {
        PostgresMetadataStore {
            client: self.client,
            authorization: self.authorization,
            validation,
        }
    }

    pub fn migrate(
        &mut self,
        options: crate::MigrationRunOptions,
    ) -> Result<crate::MigrationRunReport> {
        crate::run_migrations(&mut self.client, options)
    }
}

impl<A: AuthorizationPort, V: ObjectValidationPort> PostgresMetadataStore<A, V> {
    /// The only production transaction entry point. OGVCS-010 composes all of
    /// its publication writes through the returned database transaction.
    pub fn begin_authorized(
        &mut self,
        context: &AuthorizationContext,
        permission: &'static str,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<PostgresMetadataTransaction<'_, V, A::AuthorizedView>> {
        let authorized_view = self
            .authorization
            .authorize(context, permission, "repository", repository_id)?;
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
                return Err(DomainError::new(
                    DomainErrorCode::MetadataNotFoundOrDenied,
                ));
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
            required_events: [0; 4],
            written_events: [0; 4],
            event_snapshots: Vec::new(),
            event_references: Vec::new(),
            event_file_ids: Vec::new(),
            authorized_repository_id: repository_id,
            authorization_context: context.clone(),
            authorized_view,
            validation: &self.validation,
        })
    }

    /// Replays a caller-declared deterministic transaction after PostgreSQL
    /// serialization/deadlock failures. Domain conflicts are never retried.
    pub fn execute_serializable<T>(
        &mut self,
        context: &AuthorizationContext,
        permission: &'static str,
        repository_id: RepositoryId,
        maximum_retries: u8,
        mut operation: impl FnMut(
            &mut PostgresMetadataTransaction<'_, V, A::AuthorizedView>,
        ) -> Result<T>,
    ) -> Result<(T, CommitSequence)> {
        for attempt in 0..=maximum_retries {
            let mut transaction = self.begin_authorized(
                context,
                permission,
                repository_id,
                TransactionOptions::Serializable { maximum_retries },
            )?;
            match operation(&mut transaction) {
                Ok(value) => match transaction.commit() {
                    Ok(sequence) => return Ok((value, sequence)),
                    Err(error)
                        if error.code == DomainErrorCode::TransactionRetryExhausted
                            && attempt < maximum_retries => {}
                    Err(error) => return Err(error),
                },
                Err(error)
                    if error.code == DomainErrorCode::TransactionRetryExhausted
                        && attempt < maximum_retries =>
                {
                    let _ = transaction.rollback();
                }
                Err(error) => {
                    let _ = transaction.rollback();
                    return Err(error);
                }
            }
        }
        Err(DomainError::new(
            DomainErrorCode::TransactionRetryExhausted,
        ))
    }

    pub fn read_reference(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        kind: ReferenceKind,
        name: &ReferenceName,
        minimum: Option<&ConsistencyToken>,
    ) -> Result<ReferenceRecord> {
        self.authorization.authorize(
            context,
            "repository.reference.read",
            "repository",
            repository_id,
        )?;
        if let Some(token) = minimum {
            self.require_consistency_authorized(context, repository_id, token)?;
        }
        let row = self
            .client
            .query_opt(
                "SELECT target_snapshot_digest, generation, commit_sequence
                 FROM ogvcs_metadata.references
                 WHERE repository_id = $1 AND reference_kind = $2 AND reference_name = $3",
                &[&uuid(repository_id), &reference_kind(kind), &name.as_str()],
            )
            .map_err(database_error)?
            .ok_or_else(not_found)?;
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
        self.authorization.authorize(
            context,
            "repository.consistency.read",
            "repository",
            repository_id,
        )?;
        self.require_consistency_authorized(context, repository_id, token)
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

    pub fn tree_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        tree: ObjectRef,
        prefix: &[u8],
        request: PageRequest,
    ) -> Result<Page<TreeEntryRecord>> {
        self.authorization.authorize(
            context,
            "repository.tree.read",
            "repository",
            repository_id,
        )?;
        if tree.kind != ObjectKind::Tree || !request.is_bounded() || prefix.len() > 4096 {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let query_digest = query_digest(b"tree", repository_id, &tree.digest, prefix);
        let after = self.cursor_position(
            context,
            repository_id,
            "tree.page",
            query_digest,
            request.cursor.as_ref(),
            "key",
        )?;
        let lower = (!prefix.is_empty()).then(|| prefix.to_vec());
        let upper = prefix_upper_bound(prefix);
        let rows = self
            .client
            .query(
                "SELECT ordinal, basename_utf8, file_id, entry_kind, target_kind, target_digest,
                        logical_size::text
                 FROM ogvcs_metadata.tree_entries
                 WHERE repository_id = $1 AND tree_digest = $2
                   AND ($3::bytea IS NULL OR basename_utf8 > $3)
                   AND ($4::bytea IS NULL OR basename_utf8 >= $4)
                   AND ($5::bytea IS NULL OR basename_utf8 < $5)
                 ORDER BY basename_utf8
                 LIMIT $6",
                &[
                    &uuid(repository_id),
                    &&tree.digest[..],
                    &after,
                    &lower,
                    &upper,
                    &(i64::from(request.limit) + 1),
                ],
            )
            .map_err(database_error)?;
        let has_more = rows.len() > usize::from(request.limit);
        let items = rows
            .into_iter()
            .take(usize::from(request.limit))
            .map(tree_entry)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            let key = items.last().map(|item| item.basename_utf8.clone()).ok_or_else(not_found)?;
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
        Ok(Page {
            items,
            next_cursor,
        })
    }

    pub fn reference_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        request: PageRequest,
    ) -> Result<Page<ReferenceRecord>> {
        self.authorization.authorize(
            context,
            "repository.reference.list",
            "repository",
            repository_id,
        )?;
        if !request.is_bounded() {
            return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let query_digest = query_digest(b"reference", repository_id, &[], &[]);
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
                "SELECT reference_kind, reference_name, target_snapshot_digest, generation, commit_sequence
                 FROM ogvcs_metadata.references
                 WHERE repository_id = $1
                   AND ($2::text IS NULL OR (reference_kind, reference_name) > ($2, $3))
                 ORDER BY reference_kind, reference_name
                 LIMIT $4",
                &[
                    &uuid(repository_id),
                    &after_kind,
                    &after_name,
                    &(i64::from(request.limit) + 1),
                ],
            )
            .map_err(database_error)?;
        let has_more = rows.len() > usize::from(request.limit);
        let items = rows
            .iter()
            .take(usize::from(request.limit))
            .map(reference_record)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            let row = &rows[usize::from(request.limit) - 1];
            let key = reference_key(&row.get::<_, String>(0), &row.get::<_, String>(1))?;
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

    pub fn file_history_page(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        file_id: FileId,
        request: PageRequest,
    ) -> Result<Page<FileHistoryRecord>> {
        self.authorization.authorize(
            context,
            "repository.history.read",
            "repository",
            repository_id,
        )?;
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
                "SELECT snapshot_digest, operation_ordinal, repository_path_utf8, operation_kind
                 FROM ogvcs_metadata.file_path_history
                 WHERE repository_id = $1 AND file_id = $2
                   AND ($3::bytea IS NULL OR (snapshot_digest, operation_ordinal) > ($3, $4))
                 ORDER BY snapshot_digest, operation_ordinal
                 LIMIT $5",
                &[
                    &uuid(repository_id),
                    &&file_id.as_bytes()[..],
                    &after_digest,
                    &after_ordinal,
                    &(i64::from(request.limit) + 1),
                ],
            )
            .map_err(database_error)?;
        let has_more = rows.len() > usize::from(request.limit);
        let items = rows
            .iter()
            .take(usize::from(request.limit))
            .map(|row| file_history_record(row, file_id))
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            let row = &rows[usize::from(request.limit) - 1];
            let key = history_key(&row.get::<_, Vec<u8>>(0), row.get(1))?;
            Some(self.issue_cursor(
                context,
                repository_id,
                "file-id.history",
                query_digest,
                Some(object_ref(ObjectKind::Snapshot, row.get(0))?),
                "key",
                &key,
            )?)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
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
        position_map.insert(field.to_owned(), Value::String(URL_SAFE_NO_PAD.encode(position)));
        let position = Value::Object(position_map);
        let (kind, object_digest) = bound
            .map(|object| (Some(i16::try_from(object.kind.code()).unwrap()), Some(object.digest.to_vec())))
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

pub struct PostgresMetadataTransaction<'a, V: ObjectValidationPort, AuthorizedView = ()> {
    transaction: Option<Transaction<'a>>,
    failed: bool,
    commit_sequence: Option<(RepositoryId, CommitSequence)>,
    pending_idempotency: Option<PendingIdempotency>,
    idempotency_committed: bool,
    committed_replay: Option<Value>,
    mutation_started: bool,
    required_events: [usize; 4],
    written_events: [usize; 4],
    event_snapshots: Vec<[u8; 32]>,
    event_references: Vec<(ReferenceKind, String)>,
    event_file_ids: Vec<FileId>,
    authorized_repository_id: RepositoryId,
    authorization_context: AuthorizationContext,
    authorized_view: AuthorizedView,
    validation: &'a V,
}

impl<V: ObjectValidationPort, AuthorizedView>
    PostgresMetadataTransaction<'_, V, AuthorizedView>
{
    pub fn authorized_repository_id(&self) -> RepositoryId {
        self.authorized_repository_id
    }

    pub fn authorization_context(&self) -> &AuthorizationContext {
        &self.authorization_context
    }

    pub fn authorized_view(&self) -> &AuthorizedView {
        &self.authorized_view
    }

    /// Ends the read-only replay probe without exposing an ambiguous commit
    /// result or sending it through the transaction retry loop.
    pub fn finish_committed_replay(mut self) -> Result<Value> {
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

    fn transaction(&mut self) -> Result<&mut Transaction<'_>> {
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
            Err(DomainError::new(
                DomainErrorCode::MetadataNotFoundOrDenied,
            ))
        }
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
        let sequence = self.ensure_sequence(repository_id)?;
        self.mutation_started = true;
        Ok(sequence)
    }

    fn require_repository_event(&mut self) {
        self.required_events[EVENT_REPOSITORY] = 1;
    }

    fn require_object_event(&mut self, snapshot_digest: [u8; 32]) {
        if !self.event_snapshots.contains(&snapshot_digest) {
            self.event_snapshots.push(snapshot_digest);
            self.required_events[EVENT_OBJECT] = self.event_snapshots.len();
        }
    }

    fn require_reference_event(&mut self, kind: ReferenceKind, name: &ReferenceName) {
        let identity = (kind, name.as_str().to_owned());
        if !self.event_references.contains(&identity) {
            self.event_references.push(identity);
            self.required_events[EVENT_REFERENCE] = self.event_references.len();
        }
    }

    fn require_file_id_event(&mut self, file_id: FileId) {
        if !self.event_file_ids.contains(&file_id) {
            self.event_file_ids.push(file_id);
            self.required_events[EVENT_FILE_ID] = self.event_file_ids.len();
        }
    }

    fn idempotency_scope_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"OpenGameVCS metadata idempotency scope\0");
        hash.update(self.authorization_context.subject_digest);
        hash.update(self.authorization_context.tenant_id.as_bytes());
        hash.update(self.authorization_context.authorization_epoch.to_be_bytes());
        hash.update(self.authorized_repository_id.as_bytes());
        hash.finalize().into()
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
                if write.object_ref.kind == ObjectKind::Snapshot {
                    self.require_object_event(write.object_ref.digest);
                }
            }
            return Ok(ObjectPutOutcome::Inserted);
        }
        let stored: Vec<u8> = self
            .transaction()?
            .query_one(
                "SELECT canonical_bytes FROM ogvcs_metadata.metadata_objects
                 WHERE repository_id = $1 AND object_kind = $2 AND digest_algorithm = 1
                   AND object_digest = $3",
                &[
                    &uuid(write.repository_id),
                    &(write.object_ref.kind.code() as i16),
                    &&write.object_ref.digest[..],
                ],
            )
            .map_err(database_error)?
            .get(0);
        if stored.len() == write.canonical_bytes.len()
            && bool::from(stored.as_slice().ct_eq(write.canonical_bytes))
        {
            Ok(ObjectPutOutcome::ExactReplay)
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
        {
            return Err(DomainError::new(DomainErrorCode::FileIdConflict));
        }
        let inserted = self
            .transaction()?
            .execute(
                "INSERT INTO ogvcs_metadata.file_id_registry
                 (repository_id, file_id, state, origin, owner_kind, owner_id)
                 VALUES ($1, $2, 'reserved', $3, $4, $5) ON CONFLICT DO NOTHING",
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
            self.require_file_id_event(reservation.file_id);
            Ok(())
        } else {
            Err(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }
}

impl<V: ObjectValidationPort, AuthorizedView> MetadataTransaction
    for PostgresMetadataTransaction<'_, V, AuthorizedView>
{
    fn create_repository(&mut self, request: RepositoryCreate<'_>) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(request.repository_id)?;
            self.require_pending_idempotency()?;
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
            self.require_repository_event();
            Ok(())
        })
    }

    fn put_object(&mut self, write: ObjectWrite<'_>) -> Result<ObjectPutOutcome> {
        poison_transaction_on_error!(self, { self.put_object_inner(write, false) })
    }

    fn index_tree_entry(&mut self, entry: TreeEntryWrite) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(entry.repository_id)?;
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
            Ok(())
        })
    }

    fn index_snapshot(&mut self, snapshot: SnapshotWrite) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(snapshot.repository_id)?;
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
                    &[&uuid(snapshot.repository_id), &&snapshot.snapshot.digest[..]],
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
            Ok(())
        })
    }

    fn append_file_history(&mut self, history: FileHistoryWrite) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(history.repository_id)?;
            self.require_pending_idempotency()?;
            if history.snapshot.kind != ObjectKind::Snapshot
                || history.repository_path_utf8.is_empty()
                || history.repository_path_utf8.len() > 4096
            {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
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
            Ok(())
        })
    }

    fn reserve_file_id(&mut self, reservation: FileIdReservation) -> Result<()> {
        poison_transaction_on_error!(self, { self.reserve_file_id_inner(reservation, false) })
    }

    fn reserve_imported_file_id(
        &mut self,
        request: FileIdImportReservation,
    ) -> Result<FileIdReservationOutcome> {
        poison_transaction_on_error!(self, {
            self.require_repository(request.reservation.repository_id)?;
            self.require_pending_idempotency()?;
            if request.reservation.origin != FileIdOrigin::Import {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
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
            let existing: Vec<u8> = self
                .transaction()?
                .query_one(
                    "SELECT file_id FROM ogvcs_metadata.file_id_import_mappings
                     WHERE repository_id = $1 AND importer_profile = $2
                       AND source_namespace_digest = $3 AND source_identity_digest = $4",
                    &[
                        &uuid(request.reservation.repository_id),
                        &request.importer_profile,
                        &&request.source_namespace_digest[..],
                        &&request.source_identity_digest[..],
                    ],
                )
                .map_err(database_error)?
                .get(0);
            if existing.as_slice() == request.reservation.file_id.as_bytes() {
                Ok(FileIdReservationOutcome::ExactImportReplay)
            } else {
                Err(DomainError::new(DomainErrorCode::FileIdConflict))
            }
        })
    }

    fn tombstone_file_id(&mut self, repository_id: RepositoryId, file_id: FileId) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(repository_id)?;
            self.require_pending_idempotency()?;
            let updated = self
                .transaction()?
                .execute(
                    "UPDATE ogvcs_metadata.file_id_registry
                     SET state = 'tombstoned', tombstoned_at = COALESCE(tombstoned_at, clock_timestamp())
                     WHERE repository_id = $1 AND file_id = $2",
                    &[&uuid(repository_id), &&file_id.as_bytes()[..]],
                )
                .map_err(database_error)?;
            if updated == 1 {
                self.begin_mutation(repository_id)?;
                self.require_file_id_event(file_id);
                Ok(())
            } else {
                Err(DomainError::new(DomainErrorCode::FileIdConflict))
            }
        })
    }

    fn activate_file_id(&mut self, repository_id: RepositoryId, file_id: FileId) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(repository_id)?;
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
                self.require_file_id_event(file_id);
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
            self.require_pending_idempotency()?;
            if request
                .desired
                .is_some_and(|target| target.kind != ObjectKind::Snapshot)
            {
                return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
            self.require_reference_event(request.kind, &request.name);
            Ok(ReferenceCasResult {
                prior,
                current,
                generation: positive_u64(row.get(1))?,
                commit_sequence: CommitSequence::new(positive_u64(row.get(2))?),
            })
        })
    }

    fn append_outbox(&mut self, event: OutboxEvent) -> Result<()> {
        poison_transaction_on_error!(self, {
            self.require_repository(event.repository_id)?;
            let Some(requirement) = outbox_requirement(&event) else {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            };
            if self.written_events[requirement] >= self.required_events[requirement] {
                return Err(DomainError::new(DomainErrorCode::ObjectInvalid));
            }
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
                return Err(DomainError::new(
                    DomainErrorCode::MetadataNotFoundOrDenied,
                ));
            }
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
                        &event.event_type,
                        &(event.event_version as i16),
                        &Uuid::from_bytes(event.correlation_id),
                        &event.resource_type,
                        &event.resource_opaque_id,
                        &Json(&event.safe_payload),
                    ],
                )
                .map_err(database_error)?;
            self.written_events[requirement] += 1;
            Ok(())
        })
    }

    fn issue_consistency_token(
        &mut self,
        minimum: CommitSequence,
    ) -> Result<ConsistencyToken> {
        poison_transaction_on_error!(self, {
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
            self.transaction()?
                .execute(
                    "INSERT INTO ogvcs_metadata.consistency_tokens
                     (token_digest, subject_digest, tenant_id, repository_id, minimum_commit_sequence,
                      authorization_epoch, issued_at, expires_at)
                     VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp(),
                             clock_timestamp() + interval '5 minutes')",
                    &[
                        &digest,
                        &&subject_digest[..],
                        &uuid(tenant_id),
                        &uuid(repository_id),
                        &(minimum.get() as i64),
                        &(authorization_epoch as i64),
                    ],
                )
                .map_err(database_error)?;
            Ok(typed)
        })
    }

    fn commit(mut self) -> Result<CommitSequence> {
        if self.failed
            || self.pending_idempotency.is_some()
            || (self.mutation_started && !self.idempotency_committed)
            || self.required_events != self.written_events
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
        permission: &'static str,
        repository_id: RepositoryId,
        options: TransactionOptions,
    ) -> Result<Self::Transaction<'_>> {
        PostgresMetadataStore::begin_authorized(
            self,
            context,
            permission,
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

fn reference_record(row: &Row) -> Result<ReferenceRecord> {
    let kind_text: String = row.get(0);
    let kind = match kind_text.as_str() {
        "branch" => ReferenceKind::Branch,
        "tag" => ReferenceKind::Tag,
        _ => return Err(DomainError::new(DomainErrorCode::ObjectInvalid)),
    };
    Ok(ReferenceRecord {
        kind,
        name: ReferenceName::new(row.get(1))
            .ok_or_else(|| DomainError::new(DomainErrorCode::ObjectInvalid))?,
        target: object_ref(ObjectKind::Snapshot, row.get(2))?,
        generation: positive_u64(row.get(3))?,
        commit_sequence: CommitSequence::new(positive_u64(row.get(4))?),
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
    let name = std::str::from_utf8(name)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
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

fn query_digest(domain: &[u8], repository_id: RepositoryId, first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"OpenGameVCS metadata query\0");
    hash.update(domain);
    hash.update(repository_id.as_bytes());
    hash.update(first);
    hash.update(second);
    hash.finalize().into()
}

fn prefix_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut upper = prefix.to_vec();
    for index in (0..upper.len()).rev() {
        if upper[index] != u8::MAX {
            upper[index] += 1;
            upper.truncate(index + 1);
            return Some(upper);
        }
    }
    None
}

fn opaque_token(prefix: &str) -> Result<String> {
    let mut entropy = [0_u8; 32];
    getrandom::getrandom(&mut entropy)
        .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(entropy)))
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
        && cbor_field(&object, 16)
            .and_then(|value| ObjectRef::from_cbor(value).ok())
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
            let Some(profile) = cbor_field(&object, 18)
                .and_then(|value| ProfileRef::from_cbor(value).ok())
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
        || request.settings.platform_profile.parse::<ProfileRef>().is_err()
        || request.settings.content_policy_profile.parse::<ProfileRef>().is_err()
    {
        return false;
    }
    let Ok(Cbor::Map(fields)) = decode_canonical(request.descriptor.canonical_bytes, Limits::METADATA)
    else {
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
        Some(Cbor::Bytes(bytes)) if bytes.as_slice() == request.repository_id.as_bytes()
    );
    let features_match = match field(2) {
        Some(Cbor::Array(features)) => features
            .iter()
            .map(|value| match value {
                Cbor::UInt(code) => u16::try_from(*code).ok(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .is_some_and(|features| features == request.settings.required_features),
        _ => false,
    };
    let path_matches = field(17)
        .and_then(|value| ProfileRef::from_cbor(value).ok())
        .is_some_and(|profile| profile.to_string() == request.settings.path_profile);
    let content_policy_matches = match field(18) {
        Some(Cbor::Array(profiles)) => profiles.iter().any(|value| {
            ProfileRef::from_cbor(value)
                .ok()
                .is_some_and(|profile| profile.to_string() == request.settings.content_policy_profile)
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

fn reference_kind(kind: ReferenceKind) -> &'static str {
    match kind {
        ReferenceKind::Branch => "branch",
        ReferenceKind::Tag => "tag",
    }
}

fn outbox_requirement(event: &OutboxEvent) -> Option<usize> {
    if event.event_version != 1
        || event.resource_opaque_id.len() != 47
        || !event
            .resource_opaque_id
            .strip_prefix("rr1.")
            .is_some_and(|payload| {
                payload.len() == 43
                    && payload.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
                    })
            })
        || !event.safe_payload.is_object()
        || json_size(&event.safe_payload).is_none_or(|size| size > 1_048_576)
    {
        return None;
    }
    match (event.event_type, event.resource_type) {
        ("repository.created", "repository") => Some(EVENT_REPOSITORY),
        ("metadata.object-accepted", "snapshot") => Some(EVENT_OBJECT),
        ("reference.changed", "reference") => Some(EVENT_REFERENCE),
        ("file-id.state-changed", "path") => Some(EVENT_FILE_ID),
        _ => None,
    }
}

fn json_size(value: &Value) -> Option<usize> {
    serde_json::to_vec(value).ok().map(|bytes| bytes.len())
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
        DomainError::new(DomainErrorCode::TransactionRetryExhausted)
    } else if error
        .as_db_error()
        .is_some_and(|error| matches!(error.code().code(), "23505" | "23503" | "23514"))
    {
        DomainError::new(DomainErrorCode::ObjectInvalid)
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
