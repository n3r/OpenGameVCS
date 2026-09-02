use super::*;
use crate::{
    service::{metadata_negotiation_tenant_digest, PreparedMetadataDispatchSuccess},
    MetadataHttpResponse, MetadataNegotiationKeyRing, MetadataOperation, MetadataResponseEnvelope,
    MetadataTransportError, NegotiationVerifiedMetadataRequest,
};
use std::sync::Arc;

const REFERENCE_DISPATCH_RESOURCE_DOMAIN: &[u8] =
    b"OGVCS-METADATA-REFERENCE-DISPATCH-RESOURCE-V1\0";
const METADATA_READ_PERMISSION: &str = "metadata.read";

/// Production-only dispatcher for the first two OGVCS-006 metadata reads.
///
/// The negotiation key ring is retained by the dispatcher and used again at
/// the database clock immediately before OGVCS-009 authorization. A caller
/// cannot substitute the key provider that originally produced the request
/// brand. Network route registration remains intentionally absent.
pub struct PostgresMetadataReadDispatcher {
    store: IdentityBoundPostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator>,
    negotiation_keys: Arc<MetadataNegotiationKeyRing>,
}

impl PostgresMetadataReadDispatcher {
    pub fn connect(
        database_url: &str,
        participant: PostgresTransactionAuthorizationParticipant,
        negotiation_keys: Arc<MetadataNegotiationKeyRing>,
    ) -> Result<Self> {
        Ok(Self {
            store: IdentityBoundPostgresMetadataStore::connect(database_url, participant)?,
            negotiation_keys,
        })
    }

    pub fn from_store(
        store: IdentityBoundPostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator>,
        negotiation_keys: Arc<MetadataNegotiationKeyRing>,
    ) -> Self {
        Self {
            store,
            negotiation_keys,
        }
    }

    /// Dispatches only a negotiation-verified `repository.get-settings` or
    /// `reference.read` request. Every post-admission failure has the same
    /// non-enumerating public projection.
    pub fn dispatch_verified_read(
        &mut self,
        verified: NegotiationVerifiedMetadataRequest,
        credentials: TransactionCredentialRequest<'_>,
    ) -> MetadataResponseEnvelope {
        match self.dispatch_verified_read_inner(&verified, credentials) {
            Ok((prepared, committed)) => {
                MetadataResponseEnvelope::success_for_committed_dispatch(committed, prepared)
            }
            Err(_) => verified
                .request()
                .problem_response(MetadataTransportError::AuthorizationDenied),
        }
    }

    fn dispatch_verified_read_inner(
        &mut self,
        verified: &NegotiationVerifiedMetadataRequest,
        credentials: TransactionCredentialRequest<'_>,
    ) -> Result<(
        PreparedMetadataDispatchSuccess,
        CommittedMetadataReadDispatch,
    )> {
        let request = verified.request();
        if credentials.correlation_id != request.correlation_id() {
            return denied();
        }
        let tenant_id = request.tenant_id().ok_or_else(denied_error)?;
        let repository_id = request.repository_id().ok_or_else(denied_error)?;
        if !bool::from(
            metadata_negotiation_tenant_digest(tenant_id)
                .as_slice()
                .ct_eq(verified.principal().tenant_digest()),
        ) {
            return denied();
        }

        let (resource, reference) = dispatch_resource(request)?;
        crate::verify_schema_compatibility(&mut self.store.store.client)?;
        let participant = self
            .store
            .store
            .transaction_authorization
            .as_ref()
            .ok_or_else(denied_error)?;
        let tenant = identity_tenant_id(tenant_id);
        let repository = identity_repository_id(repository_id);
        let mut transaction = self
            .store
            .store
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;

        let now_unix_ms = database_now_unix_ms(&mut transaction)?;
        verified
            .reverify_at(self.negotiation_keys.as_ref(), now_unix_ms)
            .map_err(|_| denied_error())?;
        let view = participant
            .authorize(
                &mut transaction,
                &TransactionAuthorizationRequest {
                    request_id: credentials.request_id,
                    credential_presentation: credentials.credential_presentation,
                    tenant: &tenant,
                    repository: &repository,
                    permission: METADATA_READ_PERMISSION,
                    reason: credentials.reason,
                    resource: &resource,
                    reference: reference.as_deref(),
                    snapshot: None,
                },
            )
            .map_err(|_| denied_error())?;

        let subject_digest = decode_identity_digest(view.subject_digest())?;
        if view.tenant() != tenant
            || view.repository() != repository
            || view.permission() != METADATA_READ_PERMISSION
            || view.authority_epoch() != verified.principal().authority_epoch()
            || !bool::from(
                subject_digest
                    .as_slice()
                    .ct_eq(verified.principal().subject_digest()),
            )
        {
            poison_identity_transaction(&mut transaction);
            return denied();
        }
        let authority_scope_digest = decode_identity_digest(view.authenticated_scope_digest())?;
        let token_scope_digest = identity_metadata_scope_digest(
            authority_scope_digest,
            subject_digest,
            view.authority_epoch(),
            tenant_id,
            repository_id,
            TransactionCapability::IssueConsistencyToken,
        );

        let repository_tenant = transaction
            .query_opt(
                "SELECT tenant_id FROM ogvcs_metadata.repositories WHERE repository_id = $1",
                &[&uuid(repository_id)],
            )
            .map_err(database_error)?
            .ok_or_else(denied_error)?;
        if repository_tenant.get::<_, Uuid>(0).as_bytes() != tenant_id.as_bytes() {
            poison_identity_transaction(&mut transaction);
            return denied();
        }

        let observed = observed_sequence(&mut transaction, repository_id)?;
        if let Some(minimum) = request.minimum_consistency_token() {
            require_dispatch_consistency(
                &mut transaction,
                minimum,
                subject_digest,
                tenant_id,
                repository_id,
                view.authority_epoch(),
                token_scope_digest,
                observed,
            )?;
        }

        let response = match request.operation() {
            MetadataOperation::RepositoryGetSettings => {
                let settings =
                    load_repository_settings(&mut transaction, tenant_id, repository_id)?;
                let consistency = issue_dispatch_consistency_token(
                    &mut transaction,
                    subject_digest,
                    tenant_id,
                    repository_id,
                    view.authority_epoch(),
                    token_scope_digest,
                    observed,
                )?;
                MetadataHttpResponse::repository_settings(&settings, &consistency, observed)?
            }
            MetadataOperation::ReferenceRead => {
                let kind = request.reference_kind().ok_or_else(denied_error)?;
                let name = request.reference_name().ok_or_else(denied_error)?;
                let reference_record =
                    load_reference(&mut transaction, repository_id, kind, name, observed)?;
                let consistency = issue_dispatch_consistency_token(
                    &mut transaction,
                    subject_digest,
                    tenant_id,
                    repository_id,
                    view.authority_epoch(),
                    token_scope_digest,
                    observed,
                )?;
                MetadataHttpResponse::reference_read(&reference_record, &consistency, observed)?
            }
            _ => return denied(),
        };
        let prepared = MetadataResponseEnvelope::prepare_authorized_dispatch(
            request.correlation_id(),
            request.operation(),
            response,
        )
        .map_err(|_| denied_error())?;
        finalize_identity_decision(
            participant,
            &mut transaction,
            &view,
            request.correlation_id(),
            &tenant,
            &repository,
            METADATA_READ_PERMISSION,
            reference.as_deref(),
            std::slice::from_ref(&resource),
            prepared.decision_result(),
        )?;
        transaction.commit().map_err(database_error)?;
        Ok((prepared, CommittedMetadataReadDispatch { _sealed: () }))
    }
}

fn dispatch_resource(
    request: &crate::MetadataOperationRequest,
) -> Result<(IdentityAuthorizationResource, Option<String>)> {
    match request.operation() {
        MetadataOperation::RepositoryGetSettings => Ok((
            IdentityAuthorizationResource {
                resource_type: "repository".to_owned(),
                path: None,
                file_id: None,
                object_id: None,
                name: Some("repository.get-settings".to_owned()),
            },
            None,
        )),
        MetadataOperation::ReferenceRead => {
            let kind = request.reference_kind().ok_or_else(denied_error)?;
            let name = request.reference_name().ok_or_else(denied_error)?;
            let projected = reference_dispatch_resource(kind, name);
            Ok((
                IdentityAuthorizationResource {
                    resource_type: "reference".to_owned(),
                    path: None,
                    file_id: None,
                    object_id: None,
                    name: Some(projected.clone()),
                },
                Some(projected),
            ))
        }
        _ => denied(),
    }
}

fn reference_dispatch_resource(kind: ReferenceKind, name: &ReferenceName) -> String {
    let kind = match kind {
        ReferenceKind::Branch => "branch",
        ReferenceKind::Tag => "tag",
    };
    let mut digest = Sha256::new();
    digest.update(REFERENCE_DISPATCH_RESOURCE_DOMAIN);
    digest.update((kind.len() as u64).to_be_bytes());
    digest.update(kind.as_bytes());
    digest.update((name.as_str().len() as u64).to_be_bytes());
    digest.update(name.as_str().as_bytes());
    format!("reference.{kind}.{}", hex_bytes(&digest.finalize()))
}

fn database_now_unix_ms(transaction: &mut Transaction<'_>) -> Result<u64> {
    let value: i64 = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    u64::try_from(value).map_err(|_| denied_error())
}

fn observed_sequence(
    transaction: &mut Transaction<'_>,
    repository_id: RepositoryId,
) -> Result<CommitSequence> {
    let observed: i64 = transaction
        .query_one(
            "SELECT applied_sequence FROM ogvcs_metadata.repository_commit_sequences
             WHERE repository_id = $1",
            &[&uuid(repository_id)],
        )
        .map_err(database_error)?
        .get(0);
    Ok(CommitSequence::new(nonnegative_u64(observed)?))
}

#[allow(clippy::too_many_arguments)]
fn require_dispatch_consistency(
    transaction: &mut Transaction<'_>,
    token: &ConsistencyToken,
    subject_digest: [u8; 32],
    tenant_id: TenantId,
    repository_id: RepositoryId,
    authority_epoch: u64,
    authenticated_scope_digest: [u8; 32],
    observed: CommitSequence,
) -> Result<()> {
    let token_digest = Sha256::digest(token.as_str().as_bytes()).to_vec();
    let minimum = transaction
        .query_opt(
            "SELECT minimum_commit_sequence
             FROM ogvcs_metadata.consistency_tokens
             WHERE token_digest = $1 AND subject_digest = $2 AND tenant_id = $3
               AND repository_id = $4 AND authorization_epoch = $5
               AND authenticated_scope_digest = $6
               AND expires_at > clock_timestamp()",
            &[
                &token_digest,
                &&subject_digest[..],
                &uuid(tenant_id),
                &uuid(repository_id),
                &(authority_epoch as i64),
                &&authenticated_scope_digest[..],
            ],
        )
        .map_err(database_error)?
        .ok_or_else(denied_error)?
        .get::<_, i64>(0);
    if nonnegative_u64(minimum)? > observed.get() {
        return denied();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn issue_dispatch_consistency_token(
    transaction: &mut Transaction<'_>,
    subject_digest: [u8; 32],
    tenant_id: TenantId,
    repository_id: RepositoryId,
    authority_epoch: u64,
    authenticated_scope_digest: [u8; 32],
    observed: CommitSequence,
) -> Result<ConsistencyToken> {
    let token = opaque_token("ct1.")?;
    let typed = ConsistencyToken::from_opaque(token.clone()).ok_or_else(denied_error)?;
    let token_digest = Sha256::digest(token.as_bytes()).to_vec();
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.consistency_tokens
             (token_digest, subject_digest, tenant_id, repository_id,
              minimum_commit_sequence, authorization_epoch,
              authenticated_scope_digest, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, clock_timestamp(),
                     clock_timestamp() + interval '5 minutes')",
            &[
                &token_digest,
                &&subject_digest[..],
                &uuid(tenant_id),
                &uuid(repository_id),
                &(observed.get() as i64),
                &(authority_epoch as i64),
                &&authenticated_scope_digest[..],
            ],
        )
        .map_err(database_error)?;
    Ok(typed)
}

fn load_repository_settings(
    transaction: &mut Transaction<'_>,
    tenant_id: TenantId,
    repository_id: RepositoryId,
) -> Result<RepositorySettings> {
    let row = transaction
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
        .ok_or_else(denied_error)?;
    repository_settings_record(&row, repository_id, tenant_id)
}

fn load_reference(
    transaction: &mut Transaction<'_>,
    repository_id: RepositoryId,
    kind: ReferenceKind,
    name: &ReferenceName,
    observed: CommitSequence,
) -> Result<ReferenceRecord> {
    let row = transaction
        .query_opt(
            "SELECT reference.reference_kind, reference.reference_name,
                    reference.target_snapshot_digest, reference.generation,
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
        .ok_or_else(denied_error)?;
    let published = row
        .get::<_, Option<i64>>(5)
        .and_then(|value| positive_u64(value).ok())
        .ok_or_else(denied_error)?;
    let reference = reference_record(&row)?;
    if published > observed.get() || reference.commit_sequence.get() > observed.get() {
        return denied();
    }
    Ok(reference)
}

fn denied<T>() -> Result<T> {
    Err(denied_error())
}

fn denied_error() -> DomainError {
    DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_projection_binds_domain_kind_and_full_name() {
        let name = ReferenceName::new("Release/β".to_owned()).unwrap();
        let branch = reference_dispatch_resource(ReferenceKind::Branch, &name);
        let tag = reference_dispatch_resource(ReferenceKind::Tag, &name);
        let changed = reference_dispatch_resource(
            ReferenceKind::Branch,
            &ReferenceName::new("Release/γ".to_owned()).unwrap(),
        );
        assert_eq!(branch.len(), "reference.branch.".len() + 64);
        assert_ne!(branch, tag);
        assert_ne!(branch, changed);
        assert_eq!(
            branch,
            "reference.branch.2cd0b847a464a2cec4ebf08c70f4401eb104f4ab789422c4a30d60c482fea32a"
        );
    }
}
