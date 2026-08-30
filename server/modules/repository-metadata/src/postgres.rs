use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ogvcs_object_model::{
    decode_canonical, object_id, scan_metadata, validate_metadata_schema, Cbor, Limits, ObjectKind,
    ProfileRef,
};
use postgres::{Client, IsolationLevel, NoTls, Row, Transaction};
use postgres::types::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
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
    ) -> Result<PostgresMetadataTransaction<'_, V>> {
        self.authorization
            .authorize(context, permission, "repository", repository_id)?;
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
            pending_idempotency: 0,
            idempotency_committed: false,
            outbox_required: false,
            outbox_written: false,
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
        mut operation: impl FnMut(&mut PostgresMetadataTransaction<'_, V>) -> Result<T>,
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

pub struct PostgresMetadataTransaction<'a, V: ObjectValidationPort> {
    transaction: Option<Transaction<'a>>,
    failed: bool,
    commit_sequence: Option<(RepositoryId, CommitSequence)>,
    pending_idempotency: usize,
    idempotency_committed: bool,
    outbox_required: bool,
    outbox_written: bool,
    validation: &'a V,
}

impl<V: ObjectValidationPort> PostgresMetadataTransaction<'_, V> {
    fn transaction(&mut self) -> Result<&mut Transaction<'_>> {
        if self.failed {
            return Err(DomainError::new(
                DomainErrorCode::TransactionRetryExhausted,
            ));
        }
        self.transaction
            .as_mut()
            .ok_or_else(|| DomainError::new(DomainErrorCode::TransactionRetryExhausted))
    }

    fn fail<T>(&mut self, error: DomainError) -> Result<T> {
        self.failed = true;
        Err(error)
    }

    fn ensure_sequence(&mut self, repository_id: RepositoryId) -> Result<CommitSequence> {
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
}

impl<V: ObjectValidationPort> MetadataTransaction for PostgresMetadataTransaction<'_, V> {
    fn create_repository(&mut self, request: RepositoryCreate<'_>) -> Result<()> {
        if request.settings.tenant_boundary != request.tenant_id
            || request.descriptor.repository_id != request.repository_id
            || request.descriptor.object_ref.kind != ObjectKind::RepositoryDescriptor
            || !request.settings.has_sorted_unique_features()
            || !repository_settings_match_descriptor(&request)
        {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
        self.put_object(request.descriptor)?;
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
        self.outbox_required = true;
        Ok(())
    }

    fn put_object(&mut self, write: ObjectWrite<'_>) -> Result<ObjectPutOutcome> {
        if !metadata_kind(write.object_ref.kind) {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        self.validation.validate(&write)?;
        let scanned = scan_metadata(write.canonical_bytes, Limits::METADATA)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let kind = validate_metadata_schema(&scanned)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        let digest = object_id(kind, write.canonical_bytes)
            .map_err(|_| DomainError::new(DomainErrorCode::ObjectInvalid))?;
        if kind != write.object_ref.kind || digest != write.object_ref.digest {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
            self.fail(DomainError::new(DomainErrorCode::ObjectIdCollision))
        }
    }

    fn index_tree_entry(&mut self, entry: TreeEntryWrite) -> Result<()> {
        if entry.tree.kind != ObjectKind::Tree {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
        Ok(())
    }

    fn index_snapshot(&mut self, snapshot: SnapshotWrite) -> Result<()> {
        if snapshot.snapshot.kind != ObjectKind::Snapshot || snapshot.root_tree.kind != ObjectKind::Tree {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
                return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
        Ok(())
    }

    fn append_file_history(&mut self, history: FileHistoryWrite) -> Result<()> {
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
        Ok(())
    }

    fn reserve_file_id(&mut self, reservation: FileIdReservation) -> Result<()> {
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
            .map_err(database_error)?;
        if inserted == 1 {
            self.outbox_required = true;
            Ok(())
        } else {
            self.fail(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }

    fn reserve_imported_file_id(
        &mut self,
        request: FileIdImportReservation,
    ) -> Result<FileIdReservationOutcome> {
        if request.reservation.origin != FileIdOrigin::Import {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
            self.reserve_file_id(request.reservation)?;
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
            self.fail(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }

    fn tombstone_file_id(&mut self, repository_id: RepositoryId, file_id: FileId) -> Result<()> {
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
            self.outbox_required = true;
            Ok(())
        } else {
            self.fail(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }

    fn activate_file_id(&mut self, repository_id: RepositoryId, file_id: FileId) -> Result<()> {
        let updated = self
            .transaction()?
            .execute(
                "UPDATE ogvcs_metadata.file_id_registry SET state = 'active'
                 WHERE repository_id = $1 AND file_id = $2 AND state = 'reserved'",
                &[&uuid(repository_id), &&file_id.as_bytes()[..]],
            )
            .map_err(database_error)?;
        if updated == 1 {
            self.outbox_required = true;
            Ok(())
        } else {
            self.fail(DomainError::new(DomainErrorCode::FileIdConflict))
        }
    }

    fn reserve_idempotency(
        &mut self,
        reservation: IdempotencyReservation,
    ) -> Result<IdempotencyReservationOutcome> {
        if !reservation.is_valid() {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let inserted = self
            .transaction()?
            .execute(
                "INSERT INTO ogvcs_metadata.idempotency_records
                 (authenticated_scope_digest, operation, idempotency_key, semantic_fingerprint,
                  state, issued_at, expires_at)
                 VALUES ($1, $2, $3, $4, 'reserved', $5, $6) ON CONFLICT DO NOTHING",
                &[
                    &&reservation.authenticated_scope_digest[..],
                    &reservation.operation,
                    &reservation.key,
                    &&reservation.semantic_fingerprint[..],
                    &reservation.issued_at,
                    &reservation.expires_at,
                ],
            )
            .map_err(database_error)?;
        if inserted == 1 {
            self.pending_idempotency += 1;
            return Ok(IdempotencyReservationOutcome::Reserved);
        }
        let row = self
            .transaction()?
            .query_one(
                "SELECT semantic_fingerprint, state, safe_result
                 FROM ogvcs_metadata.idempotency_records
                 WHERE authenticated_scope_digest = $1 AND operation = $2 AND idempotency_key = $3
                 FOR UPDATE",
                &[
                    &&reservation.authenticated_scope_digest[..],
                    &reservation.operation,
                    &reservation.key,
                ],
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
            self.failed = true;
            Ok(IdempotencyReservationOutcome::CommittedReplay(result))
        } else {
            self.fail(DomainError::new(
                DomainErrorCode::TransactionRetryExhausted,
            ))
        }
    }

    fn commit_idempotency(
        &mut self,
        reservation: &IdempotencyReservation,
        safe_result: Value,
    ) -> Result<()> {
        if json_size(&safe_result).is_none_or(|size| size > 1_048_576) {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let updated = self
            .transaction()?
            .execute(
                "UPDATE ogvcs_metadata.idempotency_records
                 SET state = 'committed', safe_result = $4, committed_at = clock_timestamp()
                 WHERE authenticated_scope_digest = $1 AND operation = $2 AND idempotency_key = $3
                   AND semantic_fingerprint = $5 AND state = 'reserved'",
                &[
                    &&reservation.authenticated_scope_digest[..],
                    &reservation.operation,
                    &reservation.key,
                    &Json(&safe_result),
                    &&reservation.semantic_fingerprint[..],
                ],
            )
            .map_err(database_error)?;
        if updated == 1 {
            self.pending_idempotency = self.pending_idempotency.saturating_sub(1);
            self.idempotency_committed = true;
            Ok(())
        } else {
            self.fail(DomainError::new(DomainErrorCode::ObjectInvalid))
        }
    }

    fn compare_and_swap_reference(
        &mut self,
        request: ReferenceCasRequest,
    ) -> Result<ReferenceCasResult> {
        if request.desired.is_some_and(|target| target.kind != ObjectKind::Snapshot) {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
        }
        let sequence = self.ensure_sequence(request.repository_id)?;
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
        self.outbox_required = true;
        Ok(ReferenceCasResult {
            prior,
            current,
            generation: positive_u64(row.get(1))?,
            commit_sequence: CommitSequence::new(positive_u64(row.get(2))?),
        })
    }

    fn append_outbox(&mut self, event: OutboxEvent) -> Result<()> {
        if !valid_outbox_event(&event) {
            return self.fail(DomainError::new(DomainErrorCode::ObjectInvalid));
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
        self.outbox_written = true;
        Ok(())
    }

    fn issue_consistency_token(
        &mut self,
        context: &AuthorizationContext,
        repository_id: RepositoryId,
        minimum: CommitSequence,
    ) -> Result<ConsistencyToken> {
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
            return self.fail(DomainError::new(
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
                    &&context.subject_digest[..],
                    &uuid(context.tenant_id),
                    &uuid(repository_id),
                    &(minimum.get() as i64),
                    &(context.authorization_epoch as i64),
                ],
            )
            .map_err(database_error)?;
        Ok(typed)
    }

    fn commit(mut self) -> Result<CommitSequence> {
        if self.failed
            || self.pending_idempotency != 0
            || (self.outbox_required && !self.idempotency_committed)
            || (self.outbox_required && !self.outbox_written)
        {
            if let Some(transaction) = self.transaction.take() {
                let _ = transaction.rollback();
            }
            return Err(DomainError::new(
                DomainErrorCode::TransactionRetryExhausted,
            ));
        }
        let sequence = self
            .commit_sequence
            .map(|(_, sequence)| sequence)
            .unwrap_or_else(|| CommitSequence::new(0));
        self.transaction
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::TransactionRetryExhausted))?
            .commit()
            .map_err(database_error)?;
        Ok(sequence)
    }

    fn rollback(mut self) -> Result<()> {
        self.transaction
            .take()
            .ok_or_else(|| DomainError::new(DomainErrorCode::TransactionRetryExhausted))?
            .rollback()
            .map_err(database_error)
    }
}

impl<A: AuthorizationPort, V: ObjectValidationPort> MetadataStore for PostgresMetadataStore<A, V> {
    type Transaction<'store>
        = PostgresMetadataTransaction<'store, V>
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
        .map_err(|_| DomainError::new(DomainErrorCode::TransactionRetryExhausted))?;
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

fn repository_settings_match_descriptor(request: &RepositoryCreate<'_>) -> bool {
    if request.settings.repository_format != "ogvcs.repository-format@1"
        || !request.settings.structural_limits.is_object()
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

fn valid_outbox_event(event: &OutboxEvent) -> bool {
    event.event_version == 1
        && matches!(
            (event.event_type, event.resource_type),
            ("repository.created", "repository")
                | ("metadata.object-accepted", "snapshot")
                | ("reference.changed", "reference")
                | ("file-id.state-changed", "path")
        )
        && event.resource_opaque_id.len() == 47
        && event
            .resource_opaque_id
            .strip_prefix("rr1.")
            .is_some_and(|payload| {
                payload.len() == 43
                    && payload.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
                    })
            })
        && event.safe_payload.is_object()
        && json_size(&event.safe_payload).is_some_and(|size| size <= 1_048_576)
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
        .is_some_and(|error| matches!(error.code().code(), "23505" | "23503" | "23514"))
    {
        DomainError::new(DomainErrorCode::ObjectInvalid)
    } else {
        DomainError::new(DomainErrorCode::TransactionRetryExhausted)
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
