use std::collections::BTreeMap;
use std::sync::Arc;

use ogvcs_path_contract::{repository_path_key, repository_prefix, CaseMode, PathProfile};
use postgres::fallible_iterator::FallibleIterator;
use postgres::{error::SqlState, Transaction};
use serde::Serialize;
use serde_json::Value;

use crate::canonical::{
    canonical_bytes, decode_digest, digest_json, digest_matches, hex, sha256, valid_id,
    valid_opaque, valid_safe_text, IDENTITY_CREDENTIAL_DOMAIN, IDENTITY_SUBJECT_DOMAIN,
};
use crate::migration_runner::verify_schema_in_transaction;
use crate::participant::poison_on_error;
use crate::policy::{validate_policy, validate_resource, validate_scope, ActorFacts};
use crate::{
    AuthorizationResource, CredentialScope, ParticipantError, ParticipantErrorCode, PolicyDocument,
    Result,
};

pub const MAXIMUM_AGGREGATE_RESOURCES: usize = 100_000;
pub const MAXIMUM_AGGREGATE_CHUNK_ITEMS: usize = 1_000;
pub const MAXIMUM_AGGREGATE_CHUNK_BYTES: usize = 1_048_576;
pub const MAXIMUM_AGGREGATE_PLAN_TTL_SECONDS: u64 = 900;
pub const AGGREGATE_PLAN_HANDLE_SCHEMA: &str = "ogvcs.identity-policy/aggregate-plan-handle/v1";
pub const AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA: &str =
    "ogvcs.identity-policy/aggregate-authorization-receipt/v1";
pub const AGGREGATE_RESOURCE_DIGEST_PROJECTION_ALGORITHM: &str =
    "ogvcs.identity-policy/resource-digest-projection/v1";
pub const AGGREGATE_SUBMIT_PERMISSION: &str = "submit";
pub const AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY: &str = "submit.consume-publication";

const PLAN_ID_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-PLAN-ID-V1\0";
const PLAN_HANDLE_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-PLAN-HMAC-V1\0";
const RECEIPT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-RECEIPT-HMAC-V1\0";
const RESOURCE_CHAIN_INITIAL_DOMAIN: &[u8] =
    b"OGVCS-IDENTITY-AGGREGATE-RESOURCE-CHAIN-INITIAL-V1\0";
const RESOURCE_CHAIN_STEP_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-RESOURCE-CHAIN-STEP-V1\0";
const RESOURCE_SET_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-RESOURCE-SET-V1\0";
const RESOURCE_DIGEST_PROJECTION_INITIAL_DOMAIN: &[u8] =
    b"OGVCS-IDENTITY-AGGREGATE-RESOURCE-DIGEST-PROJECTION-INITIAL-V1\0";
const RESOURCE_DIGEST_PROJECTION_STEP_DOMAIN: &[u8] =
    b"OGVCS-IDENTITY-AGGREGATE-RESOURCE-DIGEST-PROJECTION-STEP-V1\0";
const RESOURCE_DIGEST_PROJECTION_FINAL_DOMAIN: &[u8] =
    b"OGVCS-IDENTITY-AGGREGATE-RESOURCE-DIGEST-PROJECTION-FINAL-V1\0";
const CHUNK_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-CHUNK-V1\0";
const DECISION_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-DECISION-V1\0";
const COMMITMENT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-COMMITMENT-V1\0";
const COMPILED_POLICY_DOMAIN: &[u8] = b"OGVCS-IDENTITY-COMPILED-POLICY-V1\0";
const KEY_FINGERPRINT_DOMAIN: &[u8] = b"OGVCS-IDENTITY-HMAC-KEY-FINGERPRINT-V1\0";
const REASON_DOMAIN: &[u8] = b"OGVCS-IDENTITY-AGGREGATE-REASON-V1\0";

/// Secret-provider boundary for aggregate HMAC keys. Implementations may use
/// an in-process ring, an HSM, or a KMS MAC operation. PostgreSQL stores only
/// the opaque reference and this provider's non-secret fingerprint.
pub trait AggregateHmacKeyProvider: Send + Sync {
    fn fingerprint(&self, key_reference: &str) -> Result<[u8; 32]>;
    fn sign_hmac_sha256(&self, key_reference: &str, message: &[u8]) -> Result<[u8; 32]>;
}

struct HmacSecret([u8; 32]);

impl Drop for HmacSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Small production-capable in-process key ring. Deployments that require an
/// HSM/KMS should implement `AggregateHmacKeyProvider` instead. Debug output
/// and accessors never expose key bytes, and owned bytes are cleared on drop.
pub struct HmacSha256KeyRing {
    keys: BTreeMap<String, HmacSecret>,
}

impl std::fmt::Debug for HmacSha256KeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HmacSha256KeyRing")
            .field("key_references", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl HmacSha256KeyRing {
    pub fn new(keys: impl IntoIterator<Item = (String, [u8; 32])>) -> Result<Self> {
        let mut ring = BTreeMap::new();
        for (reference, secret) in keys {
            if !valid_key_reference(&reference)
                || ring.insert(reference, HmacSecret(secret)).is_some()
            {
                return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
            }
        }
        if ring.is_empty() {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        Ok(Self { keys: ring })
    }

    fn secret(&self, key_reference: &str) -> Result<&[u8; 32]> {
        self.keys
            .get(key_reference)
            .map(|secret| &secret.0)
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
    }
}

impl AggregateHmacKeyProvider for HmacSha256KeyRing {
    fn fingerprint(&self, key_reference: &str) -> Result<[u8; 32]> {
        Ok(sha256(&[
            KEY_FINGERPRINT_DOMAIN,
            self.secret(key_reference)?,
        ]))
    }

    fn sign_hmac_sha256(&self, key_reference: &str, message: &[u8]) -> Result<[u8; 32]> {
        Ok(hmac_sha256(self.secret(key_reference)?, message))
    }
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, value) in key.iter().enumerate() {
        inner_pad[index] ^= value;
        outer_pad[index] ^= value;
    }
    let inner = sha256(&[&inner_pad, message]);
    sha256(&[&outer_pad, &inner])
}

pub struct RepositoryContractBindingRequest<'a> {
    pub tenant: &'a str,
    pub repository: &'a str,
    pub metadata_tenant_id: &'a str,
    pub metadata_repository_id: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryContractBinding {
    tenant: String,
    repository: String,
    metadata_tenant_id: String,
    metadata_repository_id: String,
    settings_generation: u64,
    descriptor_digest: String,
    path_profile: String,
    case_mode: String,
}

impl RepositoryContractBinding {
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn metadata_repository_id(&self) -> &str {
        &self.metadata_repository_id
    }

    pub fn metadata_tenant_id(&self) -> &str {
        &self.metadata_tenant_id
    }

    pub const fn settings_generation(&self) -> u64 {
        self.settings_generation
    }

    pub fn descriptor_digest(&self) -> &str {
        &self.descriptor_digest
    }

    pub fn path_profile(&self) -> &str {
        &self.path_profile
    }

    pub fn case_mode(&self) -> &str {
        &self.case_mode
    }
}

pub struct AggregateSigningKeyRegistration<'a> {
    pub tenant: &'a str,
    pub key_generation: u64,
    pub authority_epoch: u64,
    pub key_reference: &'a str,
}

pub struct AggregatePlanRequest<'a> {
    pub credential_presentation: &'a str,
    pub tenant: &'a str,
    pub repository: &'a str,
    pub permission: &'a str,
    pub capability: &'a str,
    pub reference: Option<&'a str>,
    pub snapshot: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub ttl_seconds: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatePlanHandle {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    plan_id: String,
    tenant: String,
    repository: String,
    credential_id: String,
    credential_generation: u64,
    presentation_digest: String,
    subject_digest: String,
    authenticated_scope_digest: String,
    authority_epoch: u64,
    security_epoch: u64,
    policy_generation: u64,
    policy_digest: String,
    metadata_tenant_id: String,
    metadata_repository_id: String,
    settings_generation: u64,
    settings_descriptor_digest: String,
    path_profile: String,
    case_mode: String,
    permission: String,
    capability: String,
    reference: Option<String>,
    snapshot: Option<String>,
    reason: Option<String>,
    reason_digest: String,
    issued_at: u64,
    expires_at: u64,
    signer_key_generation: u64,
    signer_key_reference: String,
    signer_key_fingerprint: String,
    upload_nonce: String,
    #[serde(skip)]
    mac: [u8; 32],
}

impl std::fmt::Debug for AggregatePlanHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregatePlanHandle")
            .field("plan_id", &self.plan_id)
            .field("tenant", &self.tenant)
            .field("repository", &self.repository)
            .field("authority_epoch", &self.authority_epoch)
            .field("policy_generation", &self.policy_generation)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl AggregatePlanHandle {
    pub const fn schema_version() -> &'static str {
        AGGREGATE_PLAN_HANDLE_SCHEMA
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn security_epoch(&self) -> u64 {
        self.security_epoch
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub fn path_profile(&self) -> &str {
        &self.path_profile
    }

    pub fn case_mode(&self) -> &str {
        &self.case_mode
    }

    pub fn metadata_tenant_id(&self) -> &str {
        &self.metadata_tenant_id
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateUploadProgress {
    item_count: usize,
    chunk_count: usize,
}

impl AggregateUploadProgress {
    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    pub const fn chunk_count(&self) -> usize {
        self.chunk_count
    }
}

/// O(1)-memory reconstruction of the receipt commitment over the ordered
/// 32-byte per-resource digests persisted by repository metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateResourceDigestProjection {
    count: usize,
    chain: [u8; 32],
}

impl AggregateResourceDigestProjection {
    pub fn new() -> Self {
        Self {
            count: 0,
            chain: sha256(&[RESOURCE_DIGEST_PROJECTION_INITIAL_DOMAIN]),
        }
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    pub fn push(&mut self, resource_digest: &[u8]) -> Result<()> {
        if self.count >= MAXIMUM_AGGREGATE_RESOURCES {
            return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
        }
        let digest: [u8; 32] = resource_digest
            .try_into()
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::InputInvalid))?;
        self.chain = sha256(&[RESOURCE_DIGEST_PROJECTION_STEP_DOMAIN, &self.chain, &digest]);
        self.count += 1;
        Ok(())
    }

    pub fn finish(&self) -> Result<String> {
        if self.count == 0 {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        Ok(hex(&self.finish_bytes()))
    }

    fn finish_bytes(&self) -> [u8; 32] {
        sha256(&[
            RESOURCE_DIGEST_PROJECTION_FINAL_DOMAIN,
            &(self.count as u64).to_be_bytes(),
            &self.chain,
        ])
    }
}

impl Default for AggregateResourceDigestProjection {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateAuthorizationReceipt {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    plan_id: String,
    tenant: String,
    repository: String,
    subject_digest: String,
    authenticated_scope_digest: String,
    credential_generation: u64,
    authority_epoch: u64,
    security_epoch: u64,
    policy_generation: u64,
    policy_digest: String,
    metadata_tenant_id: String,
    metadata_repository_id: String,
    settings_generation: u64,
    settings_descriptor_digest: String,
    path_profile: String,
    case_mode: String,
    permission: String,
    capability: String,
    reference: Option<String>,
    snapshot: Option<String>,
    reason_digest: String,
    resource_count: usize,
    resource_set_digest: String,
    resource_digest_projection_digest: String,
    decision_digest: String,
    plan_nonce: String,
    issued_at: u64,
    expires_at: u64,
    signer_key_generation: u64,
    signer_key_reference: String,
    signer_key_fingerprint: String,
    #[serde(skip)]
    mac: [u8; 32],
}

impl std::fmt::Debug for AggregateAuthorizationReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AggregateAuthorizationReceipt")
            .field("plan_id", &self.plan_id)
            .field("tenant", &self.tenant)
            .field("repository", &self.repository)
            .field("resource_count", &self.resource_count)
            .field("resource_set_digest", &self.resource_set_digest)
            .field("decision_digest", &self.decision_digest)
            .finish_non_exhaustive()
    }
}

impl AggregateAuthorizationReceipt {
    pub const fn schema_version() -> &'static str {
        AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub fn authenticated_scope_digest(&self) -> &str {
        &self.authenticated_scope_digest
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub const fn resource_count(&self) -> usize {
        self.resource_count
    }

    pub fn resource_set_digest(&self) -> &str {
        &self.resource_set_digest
    }

    pub fn resource_digest_projection_digest(&self) -> &str {
        &self.resource_digest_projection_digest
    }

    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    /// Server-derived nonce that makes the aggregate plan identity unique.
    /// It is authenticated by the receipt MAC and is not signing-key material.
    pub fn plan_nonce(&self) -> &str {
        &self.plan_nonce
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn security_epoch(&self) -> u64 {
        self.security_epoch
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    pub fn metadata_repository_id(&self) -> &str {
        &self.metadata_repository_id
    }

    pub fn metadata_tenant_id(&self) -> &str {
        &self.metadata_tenant_id
    }

    pub const fn settings_generation(&self) -> u64 {
        self.settings_generation
    }

    pub fn settings_descriptor_digest(&self) -> &str {
        &self.settings_descriptor_digest
    }

    pub fn path_profile(&self) -> &str {
        &self.path_profile
    }

    pub fn case_mode(&self) -> &str {
        &self.case_mode
    }

    pub fn permission(&self) -> &str {
        &self.permission
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    pub fn snapshot(&self) -> Option<&str> {
        self.snapshot.as_deref()
    }

    pub fn reason_digest(&self) -> &str {
        &self.reason_digest
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub const fn signer_key_generation(&self) -> u64 {
        self.signer_key_generation
    }

    pub fn signer_key_reference(&self) -> &str {
        &self.signer_key_reference
    }

    pub fn signer_key_fingerprint(&self) -> &str {
        &self.signer_key_fingerprint
    }
}

pub struct AggregateReceiptConsumptionRequest<'a> {
    pub consumption_id: &'a str,
    pub operation_digest: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateReceiptConsumption {
    plan_id: String,
    consumption_id: String,
    operation_digest: String,
    authorization: AggregateAuthorizationReceipt,
}

impl AggregateReceiptConsumption {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn consumption_id(&self) -> &str {
        &self.consumption_id
    }

    pub fn operation_digest(&self) -> &str {
        &self.operation_digest
    }

    /// Returns the exact receipt after HMAC verification, currentness checks,
    /// and one-use consumption have all succeeded in this transaction.
    pub const fn authorization(&self) -> &AggregateAuthorizationReceipt {
        &self.authorization
    }
}

pub struct PostgresAggregateAuthorizationParticipant {
    keys: Arc<dyn AggregateHmacKeyProvider>,
}

impl std::fmt::Debug for PostgresAggregateAuthorizationParticipant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresAggregateAuthorizationParticipant")
            .finish_non_exhaustive()
    }
}

impl PostgresAggregateAuthorizationParticipant {
    pub fn new(keys: Arc<dyn AggregateHmacKeyProvider>) -> Self {
        Self { keys }
    }

    pub fn bind_repository_contract(
        &self,
        transaction: &mut Transaction<'_>,
        request: &RepositoryContractBindingRequest<'_>,
    ) -> Result<RepositoryContractBinding> {
        let result = self.bind_repository_contract_inner(transaction, request);
        poison_on_error(transaction, result)
    }

    pub fn register_signing_key(
        &self,
        transaction: &mut Transaction<'_>,
        request: &AggregateSigningKeyRegistration<'_>,
    ) -> Result<()> {
        let result = self.register_signing_key_inner(transaction, request);
        poison_on_error(transaction, result)
    }

    pub fn compile_current_policy(
        &self,
        transaction: &mut Transaction<'_>,
        tenant: &str,
        repository: &str,
    ) -> Result<()> {
        let result = self.compile_current_policy_inner(transaction, tenant, repository);
        poison_on_error(transaction, result)
    }

    pub fn begin_plan(
        &self,
        transaction: &mut Transaction<'_>,
        request: &AggregatePlanRequest<'_>,
    ) -> Result<AggregatePlanHandle> {
        let result = self.begin_plan_inner(transaction, request);
        poison_on_error(transaction, result)
    }

    pub fn append_chunk(
        &self,
        transaction: &mut Transaction<'_>,
        handle: &AggregatePlanHandle,
        resources: &[AuthorizationResource],
    ) -> Result<AggregateUploadProgress> {
        let result = self.append_chunk_inner(transaction, handle, resources);
        poison_on_error(transaction, result)
    }

    pub fn authorize_plan(
        &self,
        transaction: &mut Transaction<'_>,
        handle: &AggregatePlanHandle,
    ) -> Result<AggregateAuthorizationReceipt> {
        let result = self.authorize_plan_inner(transaction, handle);
        poison_on_error(transaction, result)
    }

    pub fn consume_receipt(
        &self,
        transaction: &mut Transaction<'_>,
        receipt: &AggregateAuthorizationReceipt,
        request: &AggregateReceiptConsumptionRequest<'_>,
    ) -> Result<AggregateReceiptConsumption> {
        let result = self.consume_receipt_inner(transaction, receipt, request);
        poison_on_error(transaction, result)
    }

    /// Verifies that an opaque aggregate receipt is authentic and still bound
    /// to the current credential, epoch, policy, repository settings, and
    /// signing key without consuming it. This supports private, non-mutating
    /// submit intent/preflight work; mutation still requires `consume_receipt`.
    pub fn verify_receipt_current(
        &self,
        transaction: &mut Transaction<'_>,
        receipt: &AggregateAuthorizationReceipt,
    ) -> Result<()> {
        let result = self.verify_receipt_current_inner(transaction, receipt);
        poison_on_error(transaction, result)
    }

    /// Revalidates an exact already-consumed receipt without creating a second
    /// consumption. This exists only for a durable idempotent outcome replay
    /// inside the same PostgreSQL authority; it does not make a consumed plan
    /// reusable for another operation.
    pub fn revalidate_consumption(
        &self,
        transaction: &mut Transaction<'_>,
        receipt: &AggregateAuthorizationReceipt,
        request: &AggregateReceiptConsumptionRequest<'_>,
    ) -> Result<AggregateReceiptConsumption> {
        let result = self.revalidate_consumption_inner(transaction, receipt, request);
        poison_on_error(transaction, result)
    }

    fn bind_repository_contract_inner(
        &self,
        transaction: &mut Transaction<'_>,
        request: &RepositoryContractBindingRequest<'_>,
    ) -> Result<RepositoryContractBinding> {
        verify_schema_in_transaction(transaction)?;
        if !valid_id(request.tenant)
            || !valid_id(request.repository)
            || !valid_uuid_text(request.metadata_tenant_id)
            || !valid_uuid_text(request.metadata_repository_id)
        {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        lock_scope(transaction, request.tenant, request.repository)?;
        let metadata_exists: bool = transaction
            .query_one(
                "SELECT to_regclass('ogvcs_metadata.repositories') IS NOT NULL
                        AND to_regclass('ogvcs_metadata.repository_settings') IS NOT NULL",
                &[],
            )
            .map_err(database_error)?
            .get(0);
        if !metadata_exists {
            return Err(ParticipantError::new(
                ParticipantErrorCode::PolicyUnavailable,
            ));
        }
        let row = transaction
            .query_opt(
                "SELECT r.tenant_id::text, s.settings_generation,
                        s.descriptor_digest, s.path_profile, s.case_mode
                 FROM ogvcs_metadata.repositories r
                 JOIN ogvcs_metadata.repository_settings s USING (repository_id)
                 WHERE r.repository_id = CAST($1::text AS uuid)
                 FOR SHARE OF r, s",
                &[&request.metadata_repository_id],
            )
            .map_err(database_error)?
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let metadata_tenant_id: String = row.get(0);
        let settings_generation = positive(row.get(1))?;
        let descriptor_digest = row_digest(&row, 2)?;
        let path_profile: String = row.get(3);
        let case_mode: String = row.get(4);
        if metadata_tenant_id != request.metadata_tenant_id {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        let policy = load_current_policy(transaction, request.tenant, request.repository)?;
        if policy.document.path_profile != path_profile || policy.document.case_mode != case_mode {
            return Err(ParticipantError::new(
                ParticipantErrorCode::PolicyGenerationMismatch,
            ));
        }
        PathProfile::parse(&path_profile)
            .and_then(|_| CaseMode::parse(&case_mode).map(|_| ()))
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let expected = RepositoryContractBinding {
            tenant: request.tenant.to_owned(),
            repository: request.repository.to_owned(),
            metadata_tenant_id,
            metadata_repository_id: request.metadata_repository_id.to_owned(),
            settings_generation,
            descriptor_digest: hex(&descriptor_digest),
            path_profile,
            case_mode,
        };
        let inserted_root = transaction
            .execute(
                "INSERT INTO ogvcs_identity.repository_contract_roots
                 (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (tenant_id, repository_id) DO NOTHING",
                &[
                    &expected.tenant,
                    &expected.repository,
                    &expected.metadata_tenant_id,
                    &expected.metadata_repository_id,
                ],
            )
            .map_err(database_error)?;
        if inserted_root == 0 {
            let (metadata_tenant, metadata_repository) =
                load_repository_root(transaction, request.tenant, request.repository)?;
            if metadata_tenant != expected.metadata_tenant_id
                || metadata_repository != expected.metadata_repository_id
            {
                return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
            }
        }
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_identity.repository_contract_bindings
             (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id,
              settings_generation, descriptor_digest, path_profile, case_mode)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (tenant_id, repository_id, settings_generation) DO NOTHING",
                &[
                    &expected.tenant,
                    &expected.repository,
                    &expected.metadata_tenant_id,
                    &expected.metadata_repository_id,
                    &(expected.settings_generation as i64),
                    &&descriptor_digest[..],
                    &expected.path_profile,
                    &expected.case_mode,
                ],
            )
            .map_err(database_error)?;
        if inserted == 0 {
            let current = load_repository_binding(
                transaction,
                request.tenant,
                request.repository,
                settings_generation,
            )?;
            if current != expected {
                return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
            }
        }
        Ok(expected)
    }

    fn register_signing_key_inner(
        &self,
        transaction: &mut Transaction<'_>,
        request: &AggregateSigningKeyRegistration<'_>,
    ) -> Result<()> {
        verify_schema_in_transaction(transaction)?;
        if !valid_id(request.tenant)
            || request.key_generation == 0
            || request.authority_epoch == 0
            || !valid_key_reference(request.key_reference)
        {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        lock_scope(transaction, request.tenant, "key-registry")?;
        let authority = load_authority(transaction, request.tenant)?;
        if authority.authority_epoch != request.authority_epoch
            || authority.security_epoch != request.authority_epoch
            || authority.key_generation != request.key_generation
        {
            return Err(ParticipantError::new(ParticipantErrorCode::EpochStale));
        }
        let fingerprint = self.keys.fingerprint(request.key_reference)?;
        transaction
            .execute(
                "UPDATE ogvcs_identity.aggregate_signing_keys
                 SET state = 'verify-only'
                 WHERE tenant_id = $1 AND state = 'active' AND key_generation <> $2",
                &[&request.tenant, &(request.key_generation as i64)],
            )
            .map_err(database_error)?;
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_identity.aggregate_signing_keys
                 (tenant_id, key_generation, authority_epoch, key_reference,
                  key_fingerprint, state)
                 VALUES ($1, $2, $3, $4, $5, 'active')
                 ON CONFLICT (tenant_id, key_generation) DO NOTHING",
                &[
                    &request.tenant,
                    &(request.key_generation as i64),
                    &(request.authority_epoch as i64),
                    &request.key_reference,
                    &&fingerprint[..],
                ],
            )
            .map_err(database_error)?;
        if inserted == 0 {
            let key = load_signing_key(transaction, request.tenant, request.key_generation)?;
            if key.authority_epoch != request.authority_epoch
                || key.reference != request.key_reference
                || !digest_matches(&key.fingerprint, &fingerprint)
                || key.state != "active"
            {
                return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
            }
        }
        Ok(())
    }

    fn compile_current_policy_inner(
        &self,
        transaction: &mut Transaction<'_>,
        tenant: &str,
        repository: &str,
    ) -> Result<()> {
        verify_schema_in_transaction(transaction)?;
        if !valid_id(tenant) || !valid_id(repository) {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        lock_scope(transaction, tenant, repository)?;
        let policy = load_current_policy(transaction, tenant, repository)?;
        let binding = load_and_verify_repository_binding(transaction, tenant, repository)?;
        if binding.path_profile != policy.document.path_profile
            || binding.case_mode != policy.document.case_mode
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::PolicyGenerationMismatch,
            ));
        }
        ensure_compiled_policy(transaction, tenant, repository, &policy)
    }

    fn begin_plan_inner(
        &self,
        transaction: &mut Transaction<'_>,
        request: &AggregatePlanRequest<'_>,
    ) -> Result<AggregatePlanHandle> {
        verify_schema_in_transaction(transaction)?;
        validate_plan_request(request)?;
        lock_scope(transaction, request.tenant, request.repository)?;
        let presentation_digest = sha256(&[
            IDENTITY_CREDENTIAL_DOMAIN,
            request.credential_presentation.as_bytes(),
        ]);
        let credential = load_credential(transaction, &presentation_digest)?;
        let authority = load_authority(transaction, request.tenant)?;
        let policy = load_current_policy(transaction, request.tenant, request.repository)?;
        verify_current_context(&credential, &authority, &policy, request.tenant)?;
        let binding =
            load_and_verify_repository_binding(transaction, request.tenant, request.repository)?;
        if binding.path_profile != policy.document.path_profile
            || binding.case_mode != policy.document.case_mode
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::PolicyGenerationMismatch,
            ));
        }
        ensure_compiled_policy(transaction, request.tenant, request.repository, &policy)?;
        validate_scope(
            &credential.scope,
            PathProfile::parse(&policy.document.path_profile)
                .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?,
            CaseMode::parse(&policy.document.case_mode)
                .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?,
        )
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        validate_outer_scope(&credential.scope, request)?;
        let key = load_signing_key(transaction, request.tenant, authority.key_generation)?;
        verify_active_key(&*self.keys, &authority, &key)?;

        let issued_at = credential.now;
        let requested_expiry = issued_at
            .checked_add(request.ttl_seconds)
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::LimitExceeded))?;
        let expires_at = requested_expiry.min(credential.expires_at);
        if expires_at <= issued_at {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        let mut nonce = [0_u8; 32];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let plan_id = format!(
            "aggregate.{}",
            hex(&sha256(&[
                PLAN_ID_DOMAIN,
                request.tenant.as_bytes(),
                request.repository.as_bytes(),
                &nonce,
            ]))
        );
        let reason_digest = sha256(&[REASON_DOMAIN, request.reason.unwrap_or_default().as_bytes()]);
        let mut handle = AggregatePlanHandle {
            schema_version: AGGREGATE_PLAN_HANDLE_SCHEMA,
            plan_id,
            tenant: request.tenant.to_owned(),
            repository: request.repository.to_owned(),
            credential_id: credential.credential_id.clone(),
            credential_generation: credential.credential_generation,
            presentation_digest: hex(&presentation_digest),
            subject_digest: hex(&credential.subject_digest),
            authenticated_scope_digest: hex(&credential.scope_digest),
            authority_epoch: authority.authority_epoch,
            security_epoch: authority.security_epoch,
            policy_generation: policy.document.generation,
            policy_digest: hex(&policy.digest),
            metadata_tenant_id: binding.metadata_tenant_id.clone(),
            metadata_repository_id: binding.metadata_repository_id.clone(),
            settings_generation: binding.settings_generation,
            settings_descriptor_digest: binding.descriptor_digest.clone(),
            path_profile: policy.document.path_profile.clone(),
            case_mode: policy.document.case_mode.clone(),
            permission: request.permission.to_owned(),
            capability: request.capability.to_owned(),
            reference: request.reference.map(str::to_owned),
            snapshot: request.snapshot.map(str::to_owned),
            reason: request.reason.map(str::to_owned),
            reason_digest: hex(&reason_digest),
            issued_at,
            expires_at,
            signer_key_generation: key.generation,
            signer_key_reference: key.reference.clone(),
            signer_key_fingerprint: hex(&key.fingerprint),
            upload_nonce: hex(&nonce),
            mac: [0; 32],
        };
        handle.mac = self.sign_handle(&handle)?;
        let initial_chain = initial_resource_chain();
        let policy_digest = decode_digest(&handle.policy_digest)?;
        let settings_digest = decode_digest(&handle.settings_descriptor_digest)?;
        let key_fingerprint = decode_digest(&handle.signer_key_fingerprint)?;
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.aggregate_plans
                 (plan_id, tenant_id, repository_id, credential_id,
                  credential_generation, presentation_digest, subject_digest,
                  authenticated_scope_digest, authority_epoch, security_epoch,
                  policy_generation, policy_digest, metadata_tenant_id,
                  metadata_repository_id, settings_generation,
                  settings_descriptor_digest, path_profile,
                  case_mode, permission, capability, reference_name, snapshot_id,
                  reason, reason_digest, issued_at, expires_at, signer_key_generation,
                  signer_key_reference, signer_key_fingerprint, upload_nonce,
                  handle_mac, state, resource_chain_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                         $21, $22, $23, $24, to_timestamp($25::bigint), to_timestamp($26::bigint),
                         $27, $28, $29, $30, $31, 'initializing', $32)",
                &[
                    &handle.plan_id,
                    &handle.tenant,
                    &handle.repository,
                    &handle.credential_id,
                    &(handle.credential_generation as i64),
                    &&presentation_digest[..],
                    &&credential.subject_digest[..],
                    &&credential.scope_digest[..],
                    &(handle.authority_epoch as i64),
                    &(handle.security_epoch as i64),
                    &(handle.policy_generation as i64),
                    &&policy_digest[..],
                    &handle.metadata_tenant_id,
                    &handle.metadata_repository_id,
                    &(handle.settings_generation as i64),
                    &&settings_digest[..],
                    &handle.path_profile,
                    &handle.case_mode,
                    &handle.permission,
                    &handle.capability,
                    &handle.reference,
                    &handle.snapshot,
                    &handle.reason,
                    &&reason_digest[..],
                    &(handle.issued_at as i64),
                    &(handle.expires_at as i64),
                    &(handle.signer_key_generation as i64),
                    &handle.signer_key_reference,
                    &&key_fingerprint[..],
                    &&nonce[..],
                    &&handle.mac[..],
                    &&initial_chain[..],
                ],
            )
            .map_err(database_error)?;
        insert_plan_actor_and_scope(transaction, &handle.plan_id, &credential, &policy.document)?;
        let initialized = transaction
            .execute(
                "UPDATE ogvcs_identity.aggregate_plans SET state='uploading'
                 WHERE plan_id=$1 AND state='initializing'",
                &[&handle.plan_id],
            )
            .map_err(database_error)?;
        if initialized != 1 {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        Ok(handle)
    }

    fn append_chunk_inner(
        &self,
        transaction: &mut Transaction<'_>,
        handle: &AggregatePlanHandle,
        resources: &[AuthorizationResource],
    ) -> Result<AggregateUploadProgress> {
        verify_schema_in_transaction(transaction)?;
        if resources.is_empty() || resources.len() > MAXIMUM_AGGREGATE_CHUNK_ITEMS {
            return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
        }
        lock_plan_scope(transaction, handle.plan_id())?;
        let plan = load_plan(transaction, handle.plan_id(), true)?;
        self.verify_handle(handle, &plan)?;
        verify_plan_currentness(transaction, &*self.keys, &plan)?;
        if plan.state != "uploading" {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        let next_count = checked_aggregate_count(plan.item_count, resources.len())?;
        let profile = PathProfile::parse(&plan.path_profile)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let mode = CaseMode::parse(&plan.case_mode)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let prepared = prepare_chunk(resources, profile, mode, plan.last_resource_key.as_deref())?;
        let mut chain = plan.resource_chain_digest;
        for item in &prepared.items {
            chain = resource_chain_step(&chain, &item.canonical_key);
        }
        let chunk_digest = prepared.chunk_digest;
        let chunk_ordinal = plan.chunk_count;
        let first_item_ordinal = plan.item_count;
        let resource_types = prepared
            .items
            .iter()
            .map(|item| item.resource.resource_type.clone())
            .collect::<Vec<_>>();
        let values = prepared
            .items
            .iter()
            .map(|item| item.value.clone())
            .collect::<Vec<_>>();
        let canonical_keys = prepared
            .items
            .iter()
            .map(|item| item.canonical_key.clone())
            .collect::<Vec<_>>();
        let resource_digests = prepared
            .items
            .iter()
            .map(|item| item.digest.to_vec())
            .collect::<Vec<_>>();
        let path_keys = prepared
            .items
            .iter()
            .map(|item| item.path_key.clone())
            .collect::<Vec<_>>();
        let file_ids = prepared
            .items
            .iter()
            .map(|item| item.resource.file_id.clone())
            .collect::<Vec<_>>();
        let object_ids = prepared
            .items
            .iter()
            .map(|item| item.resource.object_id.clone())
            .collect::<Vec<_>>();
        let names = prepared
            .items
            .iter()
            .map(|item| item.resource.name.clone())
            .collect::<Vec<_>>();
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.aggregate_plan_chunks
                 (plan_id, chunk_ordinal, first_item_ordinal, item_count,
                  encoded_bytes, chunk_digest)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &plan.plan_id,
                    &(chunk_ordinal as i32),
                    &(first_item_ordinal as i32),
                    &(resources.len() as i32),
                    &(prepared.encoded_bytes as i32),
                    &&chunk_digest[..],
                ],
            )
            .map_err(database_error)?;
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_identity.aggregate_plan_resources
                 (plan_id, item_ordinal, resource_type, canonical_resource,
                  canonical_resource_key, resource_digest, path_key, file_id,
                  object_id, resource_name)
                 SELECT $1, $2 + ordinality::integer - 1, resource_type,
                        canonical_resource, canonical_key, resource_digest,
                        path_key, file_id, object_id, resource_name
                 FROM unnest($3::text[], $4::jsonb[], $5::bytea[], $6::bytea[],
                             $7::text[], $8::text[], $9::text[], $10::text[])
                      WITH ORDINALITY AS resource(resource_type, canonical_resource,
                        canonical_key, resource_digest, path_key, file_id,
                        object_id, resource_name, ordinality)",
                &[
                    &plan.plan_id,
                    &(first_item_ordinal as i32),
                    &resource_types,
                    &values,
                    &canonical_keys,
                    &resource_digests,
                    &path_keys,
                    &file_ids,
                    &object_ids,
                    &names,
                ],
            )
            .map_err(database_error)?;
        if usize::try_from(inserted).ok() != Some(resources.len()) {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        let last_key = prepared
            .items
            .last()
            .map(|item| item.canonical_key.as_slice())
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::LimitExceeded))?;
        let updated = transaction
            .execute(
                "UPDATE ogvcs_identity.aggregate_plans
                 SET item_count = $2, chunk_count = $3,
                     resource_chain_digest = $4, last_resource_key = $5
                 WHERE plan_id = $1 AND state = 'uploading'
                   AND item_count = $6 AND chunk_count = $7
                   AND resource_chain_digest = $8",
                &[
                    &plan.plan_id,
                    &(next_count as i32),
                    &((chunk_ordinal + 1) as i32),
                    &&chain[..],
                    &last_key,
                    &(plan.item_count as i32),
                    &(plan.chunk_count as i32),
                    &&plan.resource_chain_digest[..],
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        Ok(AggregateUploadProgress {
            item_count: next_count,
            chunk_count: chunk_ordinal + 1,
        })
    }

    fn authorize_plan_inner(
        &self,
        transaction: &mut Transaction<'_>,
        handle: &AggregatePlanHandle,
    ) -> Result<AggregateAuthorizationReceipt> {
        verify_schema_in_transaction(transaction)?;
        lock_plan_scope(transaction, handle.plan_id())?;
        let plan = load_plan(transaction, handle.plan_id(), true)?;
        self.verify_handle(handle, &plan)?;
        verify_plan_currentness(transaction, &*self.keys, &plan)?;
        if plan.state != "uploading" || plan.item_count == 0 {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        let uploaded = verify_uploaded_facts(transaction, &plan)?;
        let row = transaction
            .query_one(AGGREGATE_EVALUATION_SQL, &[&plan.plan_id])
            .map_err(database_error)?;
        let evaluated_count: i64 = row.get(0);
        let denied_count: i64 = row.get(1);
        if usize::try_from(evaluated_count).ok() != Some(plan.item_count) {
            return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
        }
        if denied_count != 0 {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        let decision_core = AggregateDecisionCore {
            schema_version: "ogvcs.authorization/aggregate-decision/v1",
            plan_id: &plan.plan_id,
            tenant: &plan.tenant,
            repository: &plan.repository,
            subject_digest: &hex(&plan.subject_digest),
            authenticated_scope_digest: &hex(&plan.scope_digest),
            credential_generation: plan.credential_generation,
            authority_epoch: plan.authority_epoch,
            security_epoch: plan.security_epoch,
            policy_generation: plan.policy_generation,
            policy_digest: &hex(&plan.policy_digest),
            metadata_tenant_id: &plan.metadata_tenant_id,
            metadata_repository_id: &plan.metadata_repository_id,
            settings_generation: plan.settings_generation,
            settings_descriptor_digest: &hex(&plan.settings_digest),
            path_profile: &plan.path_profile,
            case_mode: &plan.case_mode,
            permission: &plan.permission,
            capability: &plan.capability,
            reference: plan.reference.as_deref(),
            snapshot: plan.snapshot.as_deref(),
            reason_digest: &hex(&plan.reason_digest),
            resource_count: plan.item_count,
            resource_set_digest: &hex(&uploaded.resource_set_digest),
            resource_digest_projection_digest: &hex(&uploaded.resource_digest_projection_digest),
            allowed: true,
            code: "ALLOW_EXPLICIT",
        };
        let decision_digest = sha256(&[DECISION_DOMAIN, &canonical_bytes(&decision_core)?]);
        let mut receipt = AggregateAuthorizationReceipt {
            schema_version: AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA,
            plan_id: plan.plan_id.clone(),
            tenant: plan.tenant.clone(),
            repository: plan.repository.clone(),
            subject_digest: hex(&plan.subject_digest),
            authenticated_scope_digest: hex(&plan.scope_digest),
            credential_generation: plan.credential_generation,
            authority_epoch: plan.authority_epoch,
            security_epoch: plan.security_epoch,
            policy_generation: plan.policy_generation,
            policy_digest: hex(&plan.policy_digest),
            metadata_tenant_id: plan.metadata_tenant_id.clone(),
            metadata_repository_id: plan.metadata_repository_id.clone(),
            settings_generation: plan.settings_generation,
            settings_descriptor_digest: hex(&plan.settings_digest),
            path_profile: plan.path_profile.clone(),
            case_mode: plan.case_mode.clone(),
            permission: plan.permission.clone(),
            capability: plan.capability.clone(),
            reference: plan.reference.clone(),
            snapshot: plan.snapshot.clone(),
            reason_digest: hex(&plan.reason_digest),
            resource_count: plan.item_count,
            resource_set_digest: hex(&uploaded.resource_set_digest),
            resource_digest_projection_digest: hex(&uploaded.resource_digest_projection_digest),
            decision_digest: hex(&decision_digest),
            plan_nonce: hex(&plan.upload_nonce),
            issued_at: plan.issued_at,
            expires_at: plan.expires_at,
            signer_key_generation: plan.signer_key_generation,
            signer_key_reference: plan.signer_key_reference.clone(),
            signer_key_fingerprint: hex(&plan.signer_key_fingerprint),
            mac: [0; 32],
        };
        receipt.mac = self.sign_receipt(&receipt)?;
        let commitment_core = AggregateCommitmentCore {
            plan_id: &receipt.plan_id,
            tenant: &receipt.tenant,
            repository: &receipt.repository,
            subject_digest: &receipt.subject_digest,
            authenticated_scope_digest: &receipt.authenticated_scope_digest,
            credential_generation: receipt.credential_generation,
            authority_epoch: receipt.authority_epoch,
            security_epoch: receipt.security_epoch,
            policy_generation: receipt.policy_generation,
            policy_digest: &receipt.policy_digest,
            metadata_tenant_id: &receipt.metadata_tenant_id,
            metadata_repository_id: &receipt.metadata_repository_id,
            settings_generation: receipt.settings_generation,
            settings_descriptor_digest: &receipt.settings_descriptor_digest,
            path_profile: &receipt.path_profile,
            case_mode: &receipt.case_mode,
            permission: &receipt.permission,
            capability: &receipt.capability,
            reference: receipt.reference.as_deref(),
            snapshot: receipt.snapshot.as_deref(),
            reason_digest: &receipt.reason_digest,
            resource_count: receipt.resource_count,
            resource_set_digest: &receipt.resource_set_digest,
            resource_digest_projection_digest: &receipt.resource_digest_projection_digest,
            decision_digest: &receipt.decision_digest,
            signer_key_generation: receipt.signer_key_generation,
            receipt_mac: &hex(&receipt.mac),
        };
        let record_digest = sha256(&[COMMITMENT_DOMAIN, &canonical_bytes(&commitment_core)?]);
        let updated = transaction
            .execute(
                "UPDATE ogvcs_identity.aggregate_plans
                 SET state = 'authorized', resource_set_digest = $2,
                     resource_digest_projection_digest = $3,
                     decision_digest = $4, commitment_digest = $5,
                     receipt_mac = $6,
                     authorized_at = clock_timestamp()
                 WHERE plan_id = $1 AND state = 'uploading'
                   AND item_count = $7 AND resource_chain_digest = $8",
                &[
                    &receipt.plan_id,
                    &&uploaded.resource_set_digest[..],
                    &&uploaded.resource_digest_projection_digest[..],
                    &&decision_digest[..],
                    &&record_digest[..],
                    &&receipt.mac[..],
                    &(receipt.resource_count as i32),
                    &&plan.resource_chain_digest[..],
                ],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.aggregate_decision_commitments
                 (plan_id, tenant_id, repository_id, subject_digest,
                  authenticated_scope_digest, credential_generation,
                  authority_epoch, security_epoch, policy_generation,
                  policy_digest, metadata_tenant_id, metadata_repository_id,
                  settings_generation,
                  settings_descriptor_digest, path_profile, case_mode,
                  permission, capability, reference_name, snapshot_id,
                  reason_digest, resource_count,
                  resource_set_digest, resource_digest_projection_digest,
                  decision_digest, signer_key_generation,
                  receipt_mac, record_digest)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                         $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                         $21, $22, $23, $24, $25, $26, $27, $28)",
                &[
                    &receipt.plan_id,
                    &receipt.tenant,
                    &receipt.repository,
                    &&plan.subject_digest[..],
                    &&plan.scope_digest[..],
                    &(receipt.credential_generation as i64),
                    &(receipt.authority_epoch as i64),
                    &(receipt.security_epoch as i64),
                    &(receipt.policy_generation as i64),
                    &&plan.policy_digest[..],
                    &receipt.metadata_tenant_id,
                    &receipt.metadata_repository_id,
                    &(receipt.settings_generation as i64),
                    &&plan.settings_digest[..],
                    &receipt.path_profile,
                    &receipt.case_mode,
                    &receipt.permission,
                    &receipt.capability,
                    &receipt.reference,
                    &receipt.snapshot,
                    &&plan.reason_digest[..],
                    &(receipt.resource_count as i32),
                    &&uploaded.resource_set_digest[..],
                    &&uploaded.resource_digest_projection_digest[..],
                    &&decision_digest[..],
                    &(receipt.signer_key_generation as i64),
                    &&receipt.mac[..],
                    &&record_digest[..],
                ],
            )
            .map_err(database_error)?;
        Ok(receipt)
    }

    fn consume_receipt_inner(
        &self,
        transaction: &mut Transaction<'_>,
        receipt: &AggregateAuthorizationReceipt,
        request: &AggregateReceiptConsumptionRequest<'_>,
    ) -> Result<AggregateReceiptConsumption> {
        verify_schema_in_transaction(transaction)?;
        if !valid_opaque(request.consumption_id) {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        let operation_digest = decode_digest(request.operation_digest)?;
        lock_plan_scope(transaction, receipt.plan_id())?;
        let plan = load_plan(transaction, receipt.plan_id(), true)?;
        verify_plan_currentness(transaction, &*self.keys, &plan)?;
        self.verify_receipt(receipt, &plan)?;
        if plan.state != "authorized" {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        let inserted = transaction.execute(
            "INSERT INTO ogvcs_identity.aggregate_plan_consumptions
             (plan_id, consumption_id, operation_digest) VALUES ($1, $2, $3)",
            &[
                &plan.plan_id,
                &request.consumption_id,
                &&operation_digest[..],
            ],
        );
        match inserted {
            Ok(1) => {}
            Ok(_) => return Err(ParticipantError::new(ParticipantErrorCode::StateConflict)),
            Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
            }
            Err(error) => return Err(database_error(error)),
        }
        let updated = transaction
            .execute(
                "UPDATE ogvcs_identity.aggregate_plans
                 SET state = 'consumed', consumed_at = clock_timestamp()
                 WHERE plan_id = $1 AND state = 'authorized'",
                &[&plan.plan_id],
            )
            .map_err(database_error)?;
        if updated != 1 {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        Ok(AggregateReceiptConsumption {
            plan_id: plan.plan_id,
            consumption_id: request.consumption_id.to_owned(),
            operation_digest: request.operation_digest.to_owned(),
            authorization: receipt.clone(),
        })
    }

    fn revalidate_consumption_inner(
        &self,
        transaction: &mut Transaction<'_>,
        receipt: &AggregateAuthorizationReceipt,
        request: &AggregateReceiptConsumptionRequest<'_>,
    ) -> Result<AggregateReceiptConsumption> {
        verify_schema_in_transaction(transaction)?;
        if !valid_opaque(request.consumption_id) {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        let operation_digest = decode_digest(request.operation_digest)?;
        lock_plan_scope(transaction, receipt.plan_id())?;
        let plan = load_plan(transaction, receipt.plan_id(), true)?;
        verify_plan_currentness(transaction, &*self.keys, &plan)?;
        self.verify_receipt(receipt, &plan)?;
        if plan.state != "consumed" {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        let exact: bool = transaction
            .query_one(
                "SELECT EXISTS (
                   SELECT 1 FROM ogvcs_identity.aggregate_plan_consumptions
                   WHERE plan_id = $1 AND consumption_id = $2
                     AND operation_digest = $3)",
                &[
                    &plan.plan_id,
                    &request.consumption_id,
                    &&operation_digest[..],
                ],
            )
            .map_err(database_error)?
            .get(0);
        if !exact {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        Ok(AggregateReceiptConsumption {
            plan_id: plan.plan_id,
            consumption_id: request.consumption_id.to_owned(),
            operation_digest: request.operation_digest.to_owned(),
            authorization: receipt.clone(),
        })
    }

    fn verify_receipt_current_inner(
        &self,
        transaction: &mut Transaction<'_>,
        receipt: &AggregateAuthorizationReceipt,
    ) -> Result<()> {
        verify_schema_in_transaction(transaction)?;
        lock_plan_scope(transaction, receipt.plan_id())?;
        let plan = load_plan(transaction, receipt.plan_id(), true)?;
        verify_plan_currentness(transaction, &*self.keys, &plan)?;
        self.verify_receipt(receipt, &plan)?;
        if plan.state != "authorized" {
            return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
        }
        Ok(())
    }

    fn sign_handle(&self, handle: &AggregatePlanHandle) -> Result<[u8; 32]> {
        let bytes = canonical_bytes(handle)?;
        self.keys.sign_hmac_sha256(
            &handle.signer_key_reference,
            &[PLAN_HANDLE_DOMAIN, bytes.as_slice()].concat(),
        )
    }

    fn verify_handle(&self, handle: &AggregatePlanHandle, plan: &PlanRecord) -> Result<()> {
        let expected = self.sign_handle(handle)?;
        if !digest_matches(&expected, &handle.mac)
            || !digest_matches(&handle.mac, &plan.handle_mac)
            || !handle_matches_plan(handle, plan)?
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        Ok(())
    }

    fn sign_receipt(&self, receipt: &AggregateAuthorizationReceipt) -> Result<[u8; 32]> {
        let bytes = canonical_bytes(receipt)?;
        self.keys.sign_hmac_sha256(
            &receipt.signer_key_reference,
            &[RECEIPT_DOMAIN, bytes.as_slice()].concat(),
        )
    }

    fn verify_receipt(
        &self,
        receipt: &AggregateAuthorizationReceipt,
        plan: &PlanRecord,
    ) -> Result<()> {
        let expected = self.sign_receipt(receipt)?;
        if !digest_matches(&expected, &receipt.mac)
            || plan
                .receipt_mac
                .as_ref()
                .is_none_or(|mac| !digest_matches(mac, &receipt.mac))
            || receipt.plan_id != plan.plan_id
            || receipt.tenant != plan.tenant
            || receipt.repository != plan.repository
            || receipt.subject_digest != hex(&plan.subject_digest)
            || receipt.authenticated_scope_digest != hex(&plan.scope_digest)
            || receipt.credential_generation != plan.credential_generation
            || receipt.authority_epoch != plan.authority_epoch
            || receipt.security_epoch != plan.security_epoch
            || receipt.policy_generation != plan.policy_generation
            || receipt.policy_digest != hex(&plan.policy_digest)
            || receipt.metadata_tenant_id != plan.metadata_tenant_id
            || receipt.metadata_repository_id != plan.metadata_repository_id
            || receipt.settings_generation != plan.settings_generation
            || receipt.settings_descriptor_digest != hex(&plan.settings_digest)
            || receipt.path_profile != plan.path_profile
            || receipt.case_mode != plan.case_mode
            || receipt.permission != plan.permission
            || receipt.capability != plan.capability
            || receipt.reference != plan.reference
            || receipt.snapshot != plan.snapshot
            || receipt.reason_digest != hex(&plan.reason_digest)
            || receipt.resource_count != plan.item_count
            || plan
                .resource_set_digest
                .as_ref()
                .is_none_or(|digest| receipt.resource_set_digest != hex(digest))
            || plan
                .resource_digest_projection_digest
                .as_ref()
                .is_none_or(|digest| receipt.resource_digest_projection_digest != hex(digest))
            || plan
                .decision_digest
                .as_ref()
                .is_none_or(|digest| receipt.decision_digest != hex(digest))
            || receipt.plan_nonce != hex(&plan.upload_nonce)
            || plan.commitment_digest.is_none()
            || receipt.issued_at != plan.issued_at
            || receipt.expires_at != plan.expires_at
            || receipt.signer_key_generation != plan.signer_key_generation
            || receipt.signer_key_reference != plan.signer_key_reference
            || receipt.signer_key_fingerprint != hex(&plan.signer_key_fingerprint)
        {
            return Err(ParticipantError::new(
                ParticipantErrorCode::AuthenticationDenied,
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateDecisionCore<'a> {
    schema_version: &'a str,
    plan_id: &'a str,
    tenant: &'a str,
    repository: &'a str,
    subject_digest: &'a str,
    authenticated_scope_digest: &'a str,
    credential_generation: u64,
    authority_epoch: u64,
    security_epoch: u64,
    policy_generation: u64,
    policy_digest: &'a str,
    metadata_tenant_id: &'a str,
    metadata_repository_id: &'a str,
    settings_generation: u64,
    settings_descriptor_digest: &'a str,
    path_profile: &'a str,
    case_mode: &'a str,
    permission: &'a str,
    capability: &'a str,
    reference: Option<&'a str>,
    snapshot: Option<&'a str>,
    reason_digest: &'a str,
    resource_count: usize,
    resource_set_digest: &'a str,
    resource_digest_projection_digest: &'a str,
    allowed: bool,
    code: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AggregateCommitmentCore<'a> {
    plan_id: &'a str,
    tenant: &'a str,
    repository: &'a str,
    subject_digest: &'a str,
    authenticated_scope_digest: &'a str,
    credential_generation: u64,
    authority_epoch: u64,
    security_epoch: u64,
    policy_generation: u64,
    policy_digest: &'a str,
    metadata_tenant_id: &'a str,
    metadata_repository_id: &'a str,
    settings_generation: u64,
    settings_descriptor_digest: &'a str,
    path_profile: &'a str,
    case_mode: &'a str,
    permission: &'a str,
    capability: &'a str,
    reference: Option<&'a str>,
    snapshot: Option<&'a str>,
    reason_digest: &'a str,
    resource_count: usize,
    resource_set_digest: &'a str,
    resource_digest_projection_digest: &'a str,
    decision_digest: &'a str,
    signer_key_generation: u64,
    receipt_mac: &'a str,
}

struct AuthorityRecord {
    authority_epoch: u64,
    security_epoch: u64,
    key_generation: u64,
}

struct CredentialRecord {
    tenant: String,
    credential_id: String,
    credential_generation: u64,
    presentation_digest: [u8; 32],
    subject_digest: [u8; 32],
    actor: ActorFacts,
    authority_epoch: u64,
    security_epoch: u64,
    expires_at: u64,
    state: String,
    scope: CredentialScope,
    scope_digest: [u8; 32],
    now: u64,
}

struct CurrentPolicy {
    document: PolicyDocument,
    digest: [u8; 32],
}

struct SigningKeyRecord {
    generation: u64,
    authority_epoch: u64,
    reference: String,
    fingerprint: [u8; 32],
    state: String,
}

struct PlanRecord {
    plan_id: String,
    tenant: String,
    repository: String,
    credential_id: String,
    credential_generation: u64,
    presentation_digest: [u8; 32],
    subject_digest: [u8; 32],
    scope_digest: [u8; 32],
    authority_epoch: u64,
    security_epoch: u64,
    policy_generation: u64,
    policy_digest: [u8; 32],
    metadata_tenant_id: String,
    metadata_repository_id: String,
    settings_generation: u64,
    settings_digest: [u8; 32],
    path_profile: String,
    case_mode: String,
    permission: String,
    capability: String,
    reference: Option<String>,
    snapshot: Option<String>,
    reason: Option<String>,
    reason_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    signer_key_generation: u64,
    signer_key_reference: String,
    signer_key_fingerprint: [u8; 32],
    upload_nonce: [u8; 32],
    handle_mac: [u8; 32],
    state: String,
    item_count: usize,
    chunk_count: usize,
    resource_chain_digest: [u8; 32],
    last_resource_key: Option<Vec<u8>>,
    resource_set_digest: Option<[u8; 32]>,
    resource_digest_projection_digest: Option<[u8; 32]>,
    decision_digest: Option<[u8; 32]>,
    commitment_digest: Option<[u8; 32]>,
    receipt_mac: Option<[u8; 32]>,
    now: u64,
}

struct PreparedResource {
    resource: AuthorizationResource,
    value: Value,
    canonical_key: Vec<u8>,
    digest: [u8; 32],
    path_key: Option<String>,
}

struct PreparedChunk {
    items: Vec<PreparedResource>,
    encoded_bytes: usize,
    chunk_digest: [u8; 32],
}

fn prepare_chunk(
    resources: &[AuthorizationResource],
    profile: PathProfile,
    mode: CaseMode,
    prior_key: Option<&[u8]>,
) -> Result<PreparedChunk> {
    let mut items = Vec::with_capacity(resources.len());
    let mut encoded_bytes = 0_usize;
    let mut previous = prior_key;
    let mut chunk_chain = sha256(&[CHUNK_DOMAIN]);
    for resource in resources {
        validate_resource(resource, profile, mode)?;
        let canonical_key = canonical_bytes(resource)?;
        encoded_bytes = encoded_bytes
            .checked_add(canonical_key.len())
            .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::LimitExceeded))?;
        if encoded_bytes > MAXIMUM_AGGREGATE_CHUNK_BYTES {
            return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
        }
        if previous.is_some_and(|prior| prior >= canonical_key.as_slice()) {
            return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
        }
        let digest = sha256(&[canonical_key.as_slice()]);
        chunk_chain = resource_chain_step(&chunk_chain, &canonical_key);
        let path_key = resource
            .path
            .as_deref()
            .map(|path| {
                repository_path_key(path, profile, mode)
                    .map(|key| key.as_str().to_owned())
                    .map_err(|_| ParticipantError::new(ParticipantErrorCode::InputInvalid))
            })
            .transpose()?;
        let value = serde_json::to_value(resource)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::InputInvalid))?;
        items.push(PreparedResource {
            resource: resource.clone(),
            value,
            canonical_key,
            digest,
            path_key,
        });
        previous = items.last().map(|item| item.canonical_key.as_slice());
    }
    let chunk_digest = sha256(&[
        CHUNK_DOMAIN,
        &(items.len() as u64).to_be_bytes(),
        &(encoded_bytes as u64).to_be_bytes(),
        &chunk_chain,
    ]);
    Ok(PreparedChunk {
        items,
        encoded_bytes,
        chunk_digest,
    })
}

fn initial_resource_chain() -> [u8; 32] {
    sha256(&[RESOURCE_CHAIN_INITIAL_DOMAIN])
}

fn checked_aggregate_count(current: usize, additions: usize) -> Result<usize> {
    let next = current
        .checked_add(additions)
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::LimitExceeded))?;
    if additions == 0
        || additions > MAXIMUM_AGGREGATE_CHUNK_ITEMS
        || next > MAXIMUM_AGGREGATE_RESOURCES
    {
        return Err(ParticipantError::new(ParticipantErrorCode::LimitExceeded));
    }
    Ok(next)
}

fn resource_chain_step(previous: &[u8; 32], canonical_resource: &[u8]) -> [u8; 32] {
    sha256(&[
        RESOURCE_CHAIN_STEP_DOMAIN,
        previous,
        &(canonical_resource.len() as u64).to_be_bytes(),
        canonical_resource,
    ])
}

fn final_resource_set_digest(count: usize, chain: &[u8; 32]) -> [u8; 32] {
    sha256(&[RESOURCE_SET_DOMAIN, &(count as u64).to_be_bytes(), chain])
}

fn validate_plan_request(request: &AggregatePlanRequest<'_>) -> Result<()> {
    if request.credential_presentation.is_empty()
        || request.credential_presentation.len() > 1_024
        || !valid_id(request.tenant)
        || !valid_id(request.repository)
        || !valid_id(request.permission)
        || !valid_id(request.capability)
        || request.reference.is_some_and(|value| !valid_id(value))
        || request.snapshot.is_some_and(|value| !valid_opaque(value))
        || request.reason.is_some_and(|value| !valid_safe_text(value))
        || request.ttl_seconds == 0
        || request.ttl_seconds > MAXIMUM_AGGREGATE_PLAN_TTL_SECONDS
    {
        return Err(ParticipantError::new(ParticipantErrorCode::InputInvalid));
    }
    if is_privileged_permission(request.permission)
        && request.reason.is_none_or(|reason| reason.trim().is_empty())
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    if (request.permission == AGGREGATE_SUBMIT_PERMISSION
        || request.capability == AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY)
        && (request.permission != AGGREGATE_SUBMIT_PERMISSION
            || request.capability != AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    Ok(())
}

fn is_privileged_permission(permission: &str) -> bool {
    matches!(
        permission,
        "export"
            | "policy.administer"
            | "lock.force-unlock"
            | "repair"
            | "retention.delete"
            | "audit.read"
            | "impersonate"
    )
}

fn validate_outer_scope(scope: &CredentialScope, request: &AggregatePlanRequest<'_>) -> Result<()> {
    if !scope.tenants.iter().any(|value| value == request.tenant)
        || !scope
            .repositories
            .iter()
            .any(|value| value == request.repository)
        || !scope
            .permissions
            .iter()
            .any(|value| value == request.permission)
        || (!scope.references.is_empty()
            && request
                .reference
                .is_none_or(|reference| !scope.references.iter().any(|value| value == reference)))
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    Ok(())
}

fn valid_key_reference(value: &str) -> bool {
    (1..=256).contains(&value.len())
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\u{7f}')
}

fn valid_uuid_text(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn lock_plan_scope(transaction: &mut Transaction<'_>, plan_id: &str) -> Result<()> {
    let row = transaction
        .query_opt(
            "SELECT tenant_id, repository_id
             FROM ogvcs_identity.aggregate_plans WHERE plan_id = $1",
            &[&plan_id],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    let tenant: String = row.get(0);
    let repository: String = row.get(1);
    lock_scope(transaction, &tenant, &repository)
}

fn lock_scope(transaction: &mut Transaction<'_>, tenant: &str, repository: &str) -> Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1 || ':' || $2, 0))",
            &[&tenant, &repository],
        )
        .map(|_| ())
        .map_err(database_error)
}

fn load_authority(transaction: &mut Transaction<'_>, tenant: &str) -> Result<AuthorityRecord> {
    let row = transaction
        .query_opt(
            "SELECT authority_epoch, security_epoch, key_generation
             FROM ogvcs_identity.authority_states
             WHERE tenant_id = $1 FOR SHARE",
            &[&tenant],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    Ok(AuthorityRecord {
        authority_epoch: positive(row.get(0))?,
        security_epoch: positive(row.get(1))?,
        key_generation: positive(row.get(2))?,
    })
}

fn load_credential(
    transaction: &mut Transaction<'_>,
    presentation_digest: &[u8; 32],
) -> Result<CredentialRecord> {
    let row = transaction
        .query_opt(
            "SELECT tenant_id, credential_id, credential_generation,
                    presentation_digest, subject_id, subject_digest, actor_class,
                    credential_class, groups_json, authority_epoch,
                    security_epoch, extract(epoch FROM issued_at)::bigint,
                    extract(epoch FROM expires_at)::bigint, state, scope_json,
                    scope_digest, credential_digest_algorithm,
                    reconstruction_version,
                    extract(epoch FROM clock_timestamp())::bigint
             FROM ogvcs_identity.credentials
             WHERE presentation_digest = $1 FOR SHARE",
            &[&&presentation_digest[..]],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    let tenant: String = row.get(0);
    let credential_id: String = row.get(1);
    let credential_generation = positive(row.get(2))?;
    let stored_presentation = row_digest(&row, 3)?;
    let subject_id: String = row.get(4);
    let subject_digest = row_digest(&row, 5)?;
    let actor_class: String = row.get(6);
    let credential_class: String = row.get(7);
    let groups: Vec<String> = serde_json::from_value(row.get(8))
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let authority_epoch = positive(row.get(9))?;
    let security_epoch = positive(row.get(10))?;
    let issued_at = nonnegative(row.get(11))?;
    let expires_at = positive(row.get(12))?;
    let state: String = row.get(13);
    let scope: CredentialScope = serde_json::from_value(row.get(14))
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let scope_digest = row_digest(&row, 15)?;
    let digest_algorithm: String = row.get(16);
    let reconstruction_version: String = row.get(17);
    let now = nonnegative(row.get(18))?;
    let expected_subject = sha256(&[IDENTITY_SUBJECT_DOMAIN, subject_id.as_bytes()]);
    let expected_scope = digest_json(&scope)?;
    if !valid_id(&tenant)
        || !valid_id(&credential_id)
        || !valid_id(&subject_id)
        || !matches!(actor_class.as_str(), "human" | "service" | "administrator")
        || !matches!(credential_class.as_str(), "session" | "service-token")
        || groups.len() > 64
        || groups.iter().any(|group| !valid_id(group))
        || !digest_matches(&stored_presentation, presentation_digest)
        || !digest_matches(&expected_subject, &subject_digest)
        || !digest_matches(&expected_scope, &scope_digest)
        || digest_algorithm != "sha256"
        || reconstruction_version != "postgres-credential-v1"
        || issued_at >= expires_at
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    Ok(CredentialRecord {
        tenant,
        credential_id,
        credential_generation,
        presentation_digest: stored_presentation,
        subject_digest,
        actor: ActorFacts {
            id: subject_id,
            class: actor_class,
            groups,
            credential_class,
            credential_generation,
            authority_epoch,
        },
        authority_epoch,
        security_epoch,
        expires_at,
        state,
        scope,
        scope_digest,
        now,
    })
}

fn load_current_policy(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
) -> Result<CurrentPolicy> {
    let row = transaction
        .query_opt(
            "SELECT pv.policy_generation, pv.authority_epoch, pv.policy_id,
                    pv.policy_version, pv.path_profile, pv.case_mode,
                    pv.policy_json, pv.policy_digest
             FROM ogvcs_identity.current_policies cp
             JOIN ogvcs_identity.policy_versions pv
               ON pv.tenant_id = cp.tenant_id
              AND pv.repository_id = cp.repository_id
              AND pv.policy_generation = cp.policy_generation
             WHERE cp.tenant_id = $1 AND cp.repository_id = $2
             FOR SHARE OF cp, pv",
            &[&tenant, &repository],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let generation = positive(row.get(0))?;
    let authority_epoch = positive(row.get(1))?;
    let policy_id: String = row.get(2);
    let policy_version: String = row.get(3);
    let path_profile: String = row.get(4);
    let case_mode: String = row.get(5);
    let document: PolicyDocument = serde_json::from_value(row.get(6))
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let digest = row_digest(&row, 7)?;
    validate_policy(&document)?;
    if document.generation != generation
        || document.authority_epoch != authority_epoch
        || document.id != policy_id
        || document.version != policy_version
        || document.path_profile != path_profile
        || document.case_mode != case_mode
        || !digest_matches(&digest_json(&document)?, &digest)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    Ok(CurrentPolicy { document, digest })
}

fn verify_current_context(
    credential: &CredentialRecord,
    authority: &AuthorityRecord,
    policy: &CurrentPolicy,
    tenant: &str,
) -> Result<()> {
    if credential.tenant != tenant
        || credential.state != "active"
        || credential.now >= credential.expires_at
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    if authority.authority_epoch != authority.security_epoch
        || credential.authority_epoch != authority.authority_epoch
        || credential.security_epoch != authority.security_epoch
        || policy.document.authority_epoch != authority.authority_epoch
    {
        return Err(ParticipantError::new(ParticipantErrorCode::EpochStale));
    }
    Ok(())
}

fn load_signing_key(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    generation: u64,
) -> Result<SigningKeyRecord> {
    let row = transaction
        .query_opt(
            "SELECT key_generation, authority_epoch, key_reference,
                    key_fingerprint, state
             FROM ogvcs_identity.aggregate_signing_keys
             WHERE tenant_id = $1 AND key_generation = $2 FOR SHARE",
            &[&tenant, &(generation as i64)],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    Ok(SigningKeyRecord {
        generation: positive(row.get(0))?,
        authority_epoch: positive(row.get(1))?,
        reference: row.get(2),
        fingerprint: row_digest(&row, 3)?,
        state: row.get(4),
    })
}

fn verify_active_key(
    provider: &dyn AggregateHmacKeyProvider,
    authority: &AuthorityRecord,
    key: &SigningKeyRecord,
) -> Result<()> {
    let fingerprint = provider.fingerprint(&key.reference)?;
    if key.generation != authority.key_generation
        || key.authority_epoch != authority.authority_epoch
        || key.state != "active"
        || !digest_matches(&key.fingerprint, &fingerprint)
    {
        return Err(ParticipantError::new(ParticipantErrorCode::EpochStale));
    }
    Ok(())
}

fn load_repository_root(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
) -> Result<(String, String)> {
    let row = transaction
        .query_opt(
            "SELECT metadata_tenant_id, metadata_repository_id
             FROM ogvcs_identity.repository_contract_roots
             WHERE tenant_id = $1 AND repository_id = $2 FOR SHARE",
            &[&tenant, &repository],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    Ok((row.get(0), row.get(1)))
}

fn load_repository_binding(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
    settings_generation: u64,
) -> Result<RepositoryContractBinding> {
    let row = transaction
        .query_opt(
            "SELECT tenant_id, repository_id, metadata_tenant_id,
                    metadata_repository_id, settings_generation,
                    descriptor_digest, path_profile, case_mode
             FROM ogvcs_identity.repository_contract_bindings
             WHERE tenant_id = $1 AND repository_id = $2
               AND settings_generation = $3 FOR SHARE",
            &[&tenant, &repository, &(settings_generation as i64)],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    Ok(RepositoryContractBinding {
        tenant: row.get(0),
        repository: row.get(1),
        metadata_tenant_id: row.get(2),
        metadata_repository_id: row.get(3),
        settings_generation: positive(row.get(4))?,
        descriptor_digest: hex(&row_digest(&row, 5)?),
        path_profile: row.get(6),
        case_mode: row.get(7),
    })
}

fn load_and_verify_repository_binding(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
) -> Result<RepositoryContractBinding> {
    let (metadata_tenant_id, metadata_repository_id) =
        load_repository_root(transaction, tenant, repository)?;
    let metadata_exists: bool = transaction
        .query_one(
            "SELECT to_regclass('ogvcs_metadata.repositories') IS NOT NULL
                    AND to_regclass('ogvcs_metadata.repository_settings') IS NOT NULL",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    if !metadata_exists {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    let row = transaction
        .query_opt(
            "SELECT r.tenant_id::text, s.settings_generation,
                    s.descriptor_digest, s.path_profile, s.case_mode
             FROM ogvcs_metadata.repositories r
             JOIN ogvcs_metadata.repository_settings s USING (repository_id)
             WHERE r.repository_id = CAST($1::text AS uuid)
             FOR SHARE OF r, s",
            &[&metadata_repository_id],
        )
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let actual_tenant: String = row.get(0);
    let actual_generation = positive(row.get(1))?;
    let actual_digest = hex(&row_digest(&row, 2)?);
    let actual_profile: String = row.get(3);
    let actual_mode: String = row.get(4);
    if actual_tenant != metadata_tenant_id {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyGenerationMismatch,
        ));
    }
    let binding = load_repository_binding(transaction, tenant, repository, actual_generation)?;
    if binding.metadata_tenant_id != metadata_tenant_id
        || binding.metadata_repository_id != metadata_repository_id
        || actual_digest != binding.descriptor_digest
        || actual_profile != binding.path_profile
        || actual_mode != binding.case_mode
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyGenerationMismatch,
        ));
    }
    Ok(binding)
}

fn ensure_compiled_policy(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
    policy: &CurrentPolicy,
) -> Result<()> {
    let compiled_digest = sha256(&[COMPILED_POLICY_DOMAIN, &canonical_bytes(&policy.document)?]);
    let existing = transaction
        .query_opt(
            "SELECT authority_epoch, policy_digest, compiled_digest,
                    path_profile, case_mode, state, sealed_at IS NOT NULL
             FROM ogvcs_identity.compiled_policies
             WHERE tenant_id = $1 AND repository_id = $2
               AND policy_generation = $3 FOR SHARE",
            &[&tenant, &repository, &(policy.document.generation as i64)],
        )
        .map_err(database_error)?;
    if let Some(row) = existing {
        let authority_epoch = positive(row.get(0))?;
        let policy_digest = row_digest(&row, 1)?;
        let stored_compiled = row_digest(&row, 2)?;
        let profile: String = row.get(3);
        let mode: String = row.get(4);
        let state: String = row.get(5);
        let has_sealed_at: bool = row.get(6);
        if authority_epoch != policy.document.authority_epoch
            || !digest_matches(&policy_digest, &policy.digest)
            || !digest_matches(&stored_compiled, &compiled_digest)
            || profile != policy.document.path_profile
            || mode != policy.document.case_mode
            || state != "sealed"
            || !has_sealed_at
            || !compiled_counts_match(transaction, tenant, repository, policy)?
        {
            return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
        }
        return Ok(());
    }
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.compiled_policies
             (tenant_id, repository_id, policy_generation, authority_epoch,
              policy_digest, compiled_digest, path_profile, case_mode, state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'compiling')",
            &[
                &tenant,
                &repository,
                &(policy.document.generation as i64),
                &(policy.document.authority_epoch as i64),
                &&policy.digest[..],
                &&compiled_digest[..],
                &policy.document.path_profile,
                &policy.document.case_mode,
            ],
        )
        .map_err(database_error)?;
    let profile = PathProfile::parse(&policy.document.path_profile)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let mode = CaseMode::parse(&policy.document.case_mode)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    for (ordinal, rule) in policy.document.rules.iter().enumerate() {
        let generation = policy.document.generation as i64;
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.compiled_policy_rules
                 (tenant_id, repository_id, policy_generation, rule_ordinal,
                  rule_id, effect) VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &tenant,
                    &repository,
                    &generation,
                    &(ordinal as i32),
                    &rule.id,
                    &rule.effect,
                ],
            )
            .map_err(database_error)?;
        let subject_kinds = std::iter::repeat("identity")
            .take(rule.subjects.identities.len())
            .chain(std::iter::repeat("group").take(rule.subjects.groups.len()))
            .chain(std::iter::repeat("actor-class").take(rule.subjects.actor_classes.len()))
            .collect::<Vec<_>>();
        let subject_values = rule
            .subjects
            .identities
            .iter()
            .chain(rule.subjects.groups.iter())
            .chain(rule.subjects.actor_classes.iter())
            .cloned()
            .collect::<Vec<_>>();
        if !subject_values.is_empty() {
            transaction
                .execute(
                    "INSERT INTO ogvcs_identity.compiled_policy_subjects
                     (tenant_id, repository_id, policy_generation,
                      rule_ordinal, subject_kind, subject_value)
                     SELECT $1, $2, $3, $4, kind, value
                     FROM unnest($5::text[], $6::text[]) AS subject(kind, value)",
                    &[
                        &tenant,
                        &repository,
                        &generation,
                        &(ordinal as i32),
                        &subject_kinds,
                        &subject_values,
                    ],
                )
                .map_err(database_error)?;
        }
        let rule_key = CompiledRuleKey {
            tenant,
            repository,
            generation,
            ordinal,
        };
        insert_text_values(
            transaction,
            "compiled_policy_references",
            "reference_name",
            rule_key,
            &rule.references,
        )?;
        insert_text_values(
            transaction,
            "compiled_policy_resource_types",
            "resource_type",
            rule_key,
            &rule.resource_types,
        )?;
        insert_text_values(
            transaction,
            "compiled_policy_permissions",
            "permission",
            rule_key,
            &rule.permissions,
        )?;
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.compiled_policy_terms
                 (tenant_id, repository_id, policy_generation, rule_ordinal,
                  term_kind, term_value)
                 VALUES ($1, $2, $3, $4, 'tenant', $5),
                        ($1, $2, $3, $4, 'repository', $6)",
                &[
                    &tenant,
                    &repository,
                    &generation,
                    &(ordinal as i32),
                    &rule.tenant,
                    &rule.repository,
                ],
            )
            .map_err(database_error)?;
        if !rule.path_prefixes.is_empty() {
            let mut canonical = Vec::with_capacity(rule.path_prefixes.len());
            let mut lowers = Vec::with_capacity(rule.path_prefixes.len());
            let mut uppers = Vec::with_capacity(rule.path_prefixes.len());
            let mut roots = Vec::with_capacity(rule.path_prefixes.len());
            for prefix in &rule.path_prefixes {
                let bounds = repository_prefix(prefix, profile, mode)
                    .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
                canonical.push(if bounds.is_root() {
                    String::new()
                } else {
                    bounds.lower_inclusive().to_owned()
                });
                lowers.push(bounds.lower_inclusive().to_owned());
                uppers.push(bounds.upper_exclusive().to_owned());
                roots.push(bounds.is_root());
            }
            transaction
                .execute(
                    "INSERT INTO ogvcs_identity.compiled_policy_path_prefixes
                     (tenant_id, repository_id, policy_generation,
                      rule_ordinal, prefix_ordinal, canonical_prefix,
                      lower_inclusive, upper_exclusive, is_root)
                     SELECT $1, $2, $3, $4, ordinality::integer - 1,
                            canonical_prefix, lower_inclusive,
                            upper_exclusive, is_root
                     FROM unnest($5::text[], $6::text[], $7::text[], $8::boolean[])
                          WITH ORDINALITY AS prefix(canonical_prefix,
                            lower_inclusive, upper_exclusive, is_root, ordinality)",
                    &[
                        &tenant,
                        &repository,
                        &generation,
                        &(ordinal as i32),
                        &canonical,
                        &lowers,
                        &uppers,
                        &roots,
                    ],
                )
                .map_err(database_error)?;
        }
    }
    if !compiled_counts_match(transaction, tenant, repository, policy)? {
        return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
    }
    let sealed = transaction
        .execute(
            "UPDATE ogvcs_identity.compiled_policies
             SET state='sealed', sealed_at=clock_timestamp()
             WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3
               AND state='compiling'",
            &[&tenant, &repository, &(policy.document.generation as i64)],
        )
        .map_err(database_error)?;
    if sealed != 1 {
        return Err(ParticipantError::new(ParticipantErrorCode::StateConflict));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CompiledRuleKey<'a> {
    tenant: &'a str,
    repository: &'a str,
    generation: i64,
    ordinal: usize,
}

fn insert_text_values(
    transaction: &mut Transaction<'_>,
    table: &str,
    column: &str,
    key: CompiledRuleKey<'_>,
    values: &[String],
) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    let allowed = [
        ("compiled_policy_references", "reference_name"),
        ("compiled_policy_resource_types", "resource_type"),
        ("compiled_policy_permissions", "permission"),
    ];
    if !allowed.contains(&(table, column)) {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyUnavailable,
        ));
    }
    let statement = format!(
        "INSERT INTO ogvcs_identity.{table}
         (tenant_id, repository_id, policy_generation, rule_ordinal, {column})
         SELECT $1, $2, $3, $4, value FROM unnest($5::text[]) AS entry(value)"
    );
    transaction
        .execute(
            &statement,
            &[
                &key.tenant,
                &key.repository,
                &key.generation,
                &(key.ordinal as i32),
                &values,
            ],
        )
        .map(|_| ())
        .map_err(database_error)
}

fn compiled_counts_match(
    transaction: &mut Transaction<'_>,
    tenant: &str,
    repository: &str,
    policy: &CurrentPolicy,
) -> Result<bool> {
    let row = transaction
        .query_one(
            "SELECT
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_rules
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3),
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_subjects
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3),
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_references
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3),
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_path_prefixes
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3),
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_resource_types
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3),
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_permissions
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3),
                (SELECT count(*) FROM ogvcs_identity.compiled_policy_terms
                 WHERE tenant_id=$1 AND repository_id=$2 AND policy_generation=$3)",
            &[&tenant, &repository, &(policy.document.generation as i64)],
        )
        .map_err(database_error)?;
    let expected_subjects = policy
        .document
        .rules
        .iter()
        .map(|rule| {
            rule.subjects.identities.len()
                + rule.subjects.groups.len()
                + rule.subjects.actor_classes.len()
        })
        .sum::<usize>();
    let expected_references = policy
        .document
        .rules
        .iter()
        .map(|rule| rule.references.len())
        .sum::<usize>();
    let expected_prefixes = policy
        .document
        .rules
        .iter()
        .map(|rule| rule.path_prefixes.len())
        .sum::<usize>();
    let expected_types = policy
        .document
        .rules
        .iter()
        .map(|rule| rule.resource_types.len())
        .sum::<usize>();
    let expected_permissions = policy
        .document
        .rules
        .iter()
        .map(|rule| rule.permissions.len())
        .sum::<usize>();
    let actual = (0..7)
        .map(|index| usize::try_from(row.get::<_, i64>(index)).ok())
        .collect::<Vec<_>>();
    Ok(actual
        == vec![
            Some(policy.document.rules.len()),
            Some(expected_subjects),
            Some(expected_references),
            Some(expected_prefixes),
            Some(expected_types),
            Some(expected_permissions),
            Some(policy.document.rules.len() * 2),
        ])
}

fn insert_plan_actor_and_scope(
    transaction: &mut Transaction<'_>,
    plan_id: &str,
    credential: &CredentialRecord,
    policy: &PolicyDocument,
) -> Result<()> {
    let subject_kinds = std::iter::once("identity")
        .chain(std::iter::once("actor-class"))
        .chain(std::iter::repeat("group").take(credential.actor.groups.len()))
        .collect::<Vec<_>>();
    let subject_values = std::iter::once(credential.actor.id.clone())
        .chain(std::iter::once(credential.actor.class.clone()))
        .chain(credential.actor.groups.iter().cloned())
        .collect::<Vec<_>>();
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.aggregate_plan_subject_terms
             (plan_id, subject_kind, subject_value)
             SELECT $1, kind, value
             FROM unnest($2::text[], $3::text[]) AS subject(kind, value)",
            &[&plan_id, &subject_kinds, &subject_values],
        )
        .map_err(database_error)?;
    let scope_kinds = std::iter::repeat("tenant")
        .take(credential.scope.tenants.len())
        .chain(std::iter::repeat("repository").take(credential.scope.repositories.len()))
        .chain(std::iter::repeat("reference").take(credential.scope.references.len()))
        .chain(std::iter::repeat("permission").take(credential.scope.permissions.len()))
        .collect::<Vec<_>>();
    let scope_values = credential
        .scope
        .tenants
        .iter()
        .chain(credential.scope.repositories.iter())
        .chain(credential.scope.references.iter())
        .chain(credential.scope.permissions.iter())
        .cloned()
        .collect::<Vec<_>>();
    transaction
        .execute(
            "INSERT INTO ogvcs_identity.aggregate_plan_scope_terms
             (plan_id, scope_kind, scope_value)
             SELECT $1, kind, value
             FROM unnest($2::text[], $3::text[]) AS scope(kind, value)",
            &[&plan_id, &scope_kinds, &scope_values],
        )
        .map_err(database_error)?;
    if !credential.scope.path_prefixes.is_empty() {
        let profile = PathProfile::parse(&policy.path_profile)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let mode = CaseMode::parse(&policy.case_mode)
            .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
        let mut canonical = Vec::with_capacity(credential.scope.path_prefixes.len());
        let mut lowers = Vec::with_capacity(credential.scope.path_prefixes.len());
        let mut uppers = Vec::with_capacity(credential.scope.path_prefixes.len());
        let mut roots = Vec::with_capacity(credential.scope.path_prefixes.len());
        for prefix in &credential.scope.path_prefixes {
            let bounds = repository_prefix(prefix, profile, mode)
                .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
            canonical.push(if bounds.is_root() {
                String::new()
            } else {
                bounds.lower_inclusive().to_owned()
            });
            lowers.push(bounds.lower_inclusive().to_owned());
            uppers.push(bounds.upper_exclusive().to_owned());
            roots.push(bounds.is_root());
        }
        transaction
            .execute(
                "INSERT INTO ogvcs_identity.aggregate_plan_scope_path_prefixes
                 (plan_id, prefix_ordinal, canonical_prefix,
                  lower_inclusive, upper_exclusive, is_root)
                 SELECT $1, ordinality::integer - 1, canonical_prefix,
                        lower_inclusive, upper_exclusive, is_root
                 FROM unnest($2::text[], $3::text[], $4::text[], $5::boolean[])
                      WITH ORDINALITY AS prefix(canonical_prefix, lower_inclusive,
                        upper_exclusive, is_root, ordinality)",
                &[&plan_id, &canonical, &lowers, &uppers, &roots],
            )
            .map_err(database_error)?;
    }
    Ok(())
}

fn load_plan(
    transaction: &mut Transaction<'_>,
    plan_id: &str,
    for_update: bool,
) -> Result<PlanRecord> {
    let lock = if for_update {
        " FOR UPDATE"
    } else {
        " FOR SHARE"
    };
    let statement = format!(
        "SELECT plan_id, tenant_id, repository_id, credential_id,
                credential_generation, presentation_digest, subject_digest,
                authenticated_scope_digest, authority_epoch, security_epoch,
                policy_generation, policy_digest, metadata_tenant_id,
                metadata_repository_id, settings_generation,
                settings_descriptor_digest, path_profile,
                case_mode, permission, capability, reference_name, snapshot_id,
                reason, reason_digest, extract(epoch FROM issued_at)::bigint,
                extract(epoch FROM expires_at)::bigint, signer_key_generation,
                signer_key_reference, signer_key_fingerprint, upload_nonce,
                handle_mac, state, item_count, chunk_count,
                resource_chain_digest, last_resource_key, resource_set_digest,
                resource_digest_projection_digest, decision_digest,
                commitment_digest, receipt_mac,
                extract(epoch FROM clock_timestamp())::bigint
         FROM ogvcs_identity.aggregate_plans WHERE plan_id = $1{lock}"
    );
    let row = transaction
        .query_opt(&statement, &[&plan_id])
        .map_err(database_error)?
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuthenticationDenied))?;
    Ok(PlanRecord {
        plan_id: row.get(0),
        tenant: row.get(1),
        repository: row.get(2),
        credential_id: row.get(3),
        credential_generation: positive(row.get(4))?,
        presentation_digest: row_digest(&row, 5)?,
        subject_digest: row_digest(&row, 6)?,
        scope_digest: row_digest(&row, 7)?,
        authority_epoch: positive(row.get(8))?,
        security_epoch: positive(row.get(9))?,
        policy_generation: positive(row.get(10))?,
        policy_digest: row_digest(&row, 11)?,
        metadata_tenant_id: row.get(12),
        metadata_repository_id: row.get(13),
        settings_generation: positive(row.get(14))?,
        settings_digest: row_digest(&row, 15)?,
        path_profile: row.get(16),
        case_mode: row.get(17),
        permission: row.get(18),
        capability: row.get(19),
        reference: row.get(20),
        snapshot: row.get(21),
        reason: row.get(22),
        reason_digest: row_digest(&row, 23)?,
        issued_at: nonnegative(row.get(24))?,
        expires_at: positive(row.get(25))?,
        signer_key_generation: positive(row.get(26))?,
        signer_key_reference: row.get(27),
        signer_key_fingerprint: row_digest(&row, 28)?,
        upload_nonce: row_digest(&row, 29)?,
        handle_mac: row_digest(&row, 30)?,
        state: row.get(31),
        item_count: nonnegative_usize(row.get(32))?,
        chunk_count: nonnegative_usize(row.get(33))?,
        resource_chain_digest: row_digest(&row, 34)?,
        last_resource_key: row.get(35),
        resource_set_digest: optional_row_digest(&row, 36)?,
        resource_digest_projection_digest: optional_row_digest(&row, 37)?,
        decision_digest: optional_row_digest(&row, 38)?,
        commitment_digest: optional_row_digest(&row, 39)?,
        receipt_mac: optional_row_digest(&row, 40)?,
        now: nonnegative(row.get(41))?,
    })
}

fn handle_matches_plan(handle: &AggregatePlanHandle, plan: &PlanRecord) -> Result<bool> {
    Ok(handle.schema_version == AGGREGATE_PLAN_HANDLE_SCHEMA
        && handle.plan_id == plan.plan_id
        && handle.tenant == plan.tenant
        && handle.repository == plan.repository
        && handle.credential_id == plan.credential_id
        && handle.credential_generation == plan.credential_generation
        && decode_digest(&handle.presentation_digest)? == plan.presentation_digest
        && decode_digest(&handle.subject_digest)? == plan.subject_digest
        && decode_digest(&handle.authenticated_scope_digest)? == plan.scope_digest
        && handle.authority_epoch == plan.authority_epoch
        && handle.security_epoch == plan.security_epoch
        && handle.policy_generation == plan.policy_generation
        && decode_digest(&handle.policy_digest)? == plan.policy_digest
        && handle.metadata_tenant_id == plan.metadata_tenant_id
        && handle.metadata_repository_id == plan.metadata_repository_id
        && handle.settings_generation == plan.settings_generation
        && decode_digest(&handle.settings_descriptor_digest)? == plan.settings_digest
        && handle.path_profile == plan.path_profile
        && handle.case_mode == plan.case_mode
        && handle.permission == plan.permission
        && handle.capability == plan.capability
        && handle.reference == plan.reference
        && handle.snapshot == plan.snapshot
        && handle.reason == plan.reason
        && decode_digest(&handle.reason_digest)? == plan.reason_digest
        && handle.issued_at == plan.issued_at
        && handle.expires_at == plan.expires_at
        && handle.signer_key_generation == plan.signer_key_generation
        && handle.signer_key_reference == plan.signer_key_reference
        && decode_digest(&handle.signer_key_fingerprint)? == plan.signer_key_fingerprint
        && decode_digest(&handle.upload_nonce)? == plan.upload_nonce)
}

fn verify_plan_currentness(
    transaction: &mut Transaction<'_>,
    provider: &dyn AggregateHmacKeyProvider,
    plan: &PlanRecord,
) -> Result<()> {
    if plan.now >= plan.expires_at {
        return Err(ParticipantError::new(
            ParticipantErrorCode::AuthenticationDenied,
        ));
    }
    let authority = load_authority(transaction, &plan.tenant)?;
    let policy = load_current_policy(transaction, &plan.tenant, &plan.repository)?;
    let credential = load_credential(transaction, &plan.presentation_digest)?;
    verify_current_context(&credential, &authority, &policy, &plan.tenant)?;
    let binding = load_and_verify_repository_binding(transaction, &plan.tenant, &plan.repository)?;
    let key = load_signing_key(transaction, &plan.tenant, plan.signer_key_generation)?;
    verify_active_key(provider, &authority, &key)?;
    ensure_compiled_policy(transaction, &plan.tenant, &plan.repository, &policy)?;
    if credential.credential_id != plan.credential_id
        || credential.credential_generation != plan.credential_generation
        || !digest_matches(&credential.presentation_digest, &plan.presentation_digest)
        || !digest_matches(&credential.subject_digest, &plan.subject_digest)
        || !digest_matches(&credential.scope_digest, &plan.scope_digest)
        || plan.authority_epoch != authority.authority_epoch
        || plan.security_epoch != authority.security_epoch
        || plan.policy_generation != policy.document.generation
        || !digest_matches(&plan.policy_digest, &policy.digest)
        || plan.metadata_tenant_id != binding.metadata_tenant_id
        || plan.metadata_repository_id != binding.metadata_repository_id
        || plan.settings_generation != binding.settings_generation
        || hex(&plan.settings_digest) != binding.descriptor_digest
        || plan.path_profile != binding.path_profile
        || plan.case_mode != binding.case_mode
        || plan.signer_key_generation != key.generation
        || plan.signer_key_reference != key.reference
        || !digest_matches(&plan.signer_key_fingerprint, &key.fingerprint)
    {
        return Err(ParticipantError::new(
            ParticipantErrorCode::PolicyGenerationMismatch,
        ));
    }
    Ok(())
}

struct VerifiedChunk {
    ordinal: usize,
    first_item_ordinal: usize,
    expected_items: usize,
    expected_bytes: usize,
    expected_digest: [u8; 32],
    seen_items: usize,
    seen_bytes: usize,
    chain: [u8; 32],
}

struct VerifiedUploadedFacts {
    resource_set_digest: [u8; 32],
    resource_digest_projection_digest: [u8; 32],
}

impl VerifiedChunk {
    fn finish(self) -> Result<()> {
        let actual = sha256(&[
            CHUNK_DOMAIN,
            &(self.seen_items as u64).to_be_bytes(),
            &(self.seen_bytes as u64).to_be_bytes(),
            &self.chain,
        ]);
        if self.seen_items != self.expected_items
            || self.seen_bytes != self.expected_bytes
            || !digest_matches(&actual, &self.expected_digest)
        {
            return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
        }
        Ok(())
    }
}

/// Reconstructs the seal from a single server-side row stream.  It retains one
/// resource and one chunk accumulator at a time; no 100,000-item Rust Vec and
/// no per-item query loop are involved.
fn verify_uploaded_facts(
    transaction: &mut Transaction<'_>,
    plan: &PlanRecord,
) -> Result<VerifiedUploadedFacts> {
    let summary = transaction
        .query_one(
            "WITH ordered AS (
                 SELECT chunk_ordinal, first_item_ordinal, item_count,
                        row_number() OVER (ORDER BY chunk_ordinal) - 1 AS expected_chunk,
                        COALESCE(sum(item_count) OVER
                          (ORDER BY chunk_ordinal ROWS BETWEEN UNBOUNDED PRECEDING
                           AND 1 PRECEDING), 0) AS expected_first
                 FROM ogvcs_identity.aggregate_plan_chunks WHERE plan_id=$1)
             SELECT count(*)::bigint, COALESCE(sum(item_count), 0)::bigint,
                    COALESCE(bool_and(chunk_ordinal=expected_chunk
                                     AND first_item_ordinal=expected_first), false)
             FROM ordered",
            &[&plan.plan_id],
        )
        .map_err(database_error)?;
    let chunk_count = usize::try_from(summary.get::<_, i64>(0))
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?;
    let covered_items = usize::try_from(summary.get::<_, i64>(1))
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?;
    let contiguous: bool = summary.get(2);
    if chunk_count != plan.chunk_count || covered_items != plan.item_count || !contiguous {
        return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
    }

    let profile = PathProfile::parse(&plan.path_profile)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let mode = CaseMode::parse(&plan.case_mode)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))?;
    let mut resource_chain = initial_resource_chain();
    let mut digest_projection = AggregateResourceDigestProjection::new();
    let mut previous_key: Option<Vec<u8>> = None;
    let mut expected_item = 0_usize;
    let mut active_chunk: Option<VerifiedChunk> = None;
    {
        let mut rows = transaction
            .query_raw(
                "SELECT resource.item_ordinal, resource.canonical_resource,
                        resource.canonical_resource_key, resource.resource_digest,
                        resource.path_key, chunk.chunk_ordinal,
                        chunk.first_item_ordinal, chunk.item_count,
                        chunk.encoded_bytes, chunk.chunk_digest
                 FROM ogvcs_identity.aggregate_plan_resources resource
                 JOIN ogvcs_identity.aggregate_plan_chunks chunk
                   ON chunk.plan_id=resource.plan_id
                  AND resource.item_ordinal >= chunk.first_item_ordinal
                  AND resource.item_ordinal < chunk.first_item_ordinal + chunk.item_count
                 WHERE resource.plan_id=$1
                 ORDER BY resource.item_ordinal, chunk.chunk_ordinal",
                [&plan.plan_id],
            )
            .map_err(database_error)?;
        while let Some(row) = rows.next().map_err(database_error)? {
            let item_ordinal = nonnegative_usize(row.get(0))?;
            let value: Value = row.get(1);
            let stored_key: Vec<u8> = row.get(2);
            let stored_digest = row_digest(&row, 3)?;
            let stored_path_key: Option<String> = row.get(4);
            let chunk_ordinal = nonnegative_usize(row.get(5))?;
            let first_item_ordinal = nonnegative_usize(row.get(6))?;
            let expected_items = nonnegative_usize(row.get(7))?;
            let expected_bytes = nonnegative_usize(row.get(8))?;
            let expected_digest = row_digest(&row, 9)?;
            if item_ordinal != expected_item {
                return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
            }
            if active_chunk
                .as_ref()
                .is_some_and(|chunk| chunk.ordinal != chunk_ordinal)
            {
                active_chunk
                    .take()
                    .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?
                    .finish()?;
            }
            let chunk = active_chunk.get_or_insert_with(|| VerifiedChunk {
                ordinal: chunk_ordinal,
                first_item_ordinal,
                expected_items,
                expected_bytes,
                expected_digest,
                seen_items: 0,
                seen_bytes: 0,
                chain: sha256(&[CHUNK_DOMAIN]),
            });
            if chunk.first_item_ordinal + chunk.seen_items != item_ordinal
                || chunk.expected_items != expected_items
                || chunk.expected_bytes != expected_bytes
                || !digest_matches(&chunk.expected_digest, &expected_digest)
            {
                return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
            }
            let resource: AuthorizationResource = serde_json::from_value(value)
                .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?;
            validate_resource(&resource, profile, mode)
                .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?;
            let canonical_key = canonical_bytes(&resource)?;
            if canonical_key != stored_key
                || previous_key
                    .as_deref()
                    .is_some_and(|previous| previous >= canonical_key.as_slice())
                || !digest_matches(&sha256(&[&canonical_key]), &stored_digest)
            {
                return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
            }
            let expected_path_key = resource
                .path
                .as_deref()
                .map(|path| {
                    repository_path_key(path, profile, mode)
                        .map(|key| key.as_str().to_owned())
                        .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))
                })
                .transpose()?;
            if stored_path_key != expected_path_key {
                return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
            }
            chunk.seen_items += 1;
            chunk.seen_bytes = chunk
                .seen_bytes
                .checked_add(canonical_key.len())
                .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::LimitExceeded))?;
            chunk.chain = resource_chain_step(&chunk.chain, &canonical_key);
            resource_chain = resource_chain_step(&resource_chain, &canonical_key);
            digest_projection.push(&stored_digest)?;
            previous_key = Some(canonical_key);
            expected_item += 1;
        }
    }
    active_chunk
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))?
        .finish()?;
    if expected_item != plan.item_count
        || !digest_matches(&resource_chain, &plan.resource_chain_digest)
        || previous_key.as_deref() != plan.last_resource_key.as_deref()
    {
        return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
    }
    if digest_projection.count() != plan.item_count {
        return Err(ParticipantError::new(ParticipantErrorCode::AuditIntegrity));
    }
    Ok(VerifiedUploadedFacts {
        resource_set_digest: final_resource_set_digest(plan.item_count, &resource_chain),
        resource_digest_projection_digest: digest_projection.finish_bytes(),
    })
}

fn row_digest(row: &postgres::Row, index: usize) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(index);
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))
}

fn optional_row_digest(row: &postgres::Row, index: usize) -> Result<Option<[u8; 32]>> {
    row.get::<_, Option<Vec<u8>>>(index)
        .map(|bytes| {
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ParticipantError::new(ParticipantErrorCode::AuditIntegrity))
        })
        .transpose()
}

fn positive(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
}

fn nonnegative(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
}

fn nonnegative_usize(value: i32) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| ParticipantError::new(ParticipantErrorCode::PolicyUnavailable))
}

fn database_error(_error: postgres::Error) -> ParticipantError {
    ParticipantError::new(ParticipantErrorCode::PolicyUnavailable)
}

const AGGREGATE_EVALUATION_SQL: &str = r#"
WITH matched AS (
    SELECT resource.item_ordinal, rule.effect
    FROM ogvcs_identity.aggregate_plan_resources resource
    JOIN ogvcs_identity.aggregate_plans plan ON plan.plan_id = resource.plan_id
    JOIN ogvcs_identity.compiled_policy_rules rule
      ON rule.tenant_id = plan.tenant_id
     AND rule.repository_id = plan.repository_id
     AND rule.policy_generation = plan.policy_generation
    WHERE resource.plan_id = $1
      AND EXISTS (
          SELECT 1 FROM ogvcs_identity.compiled_policy_terms term
          WHERE term.tenant_id=rule.tenant_id AND term.repository_id=rule.repository_id
            AND term.policy_generation=rule.policy_generation
            AND term.rule_ordinal=rule.rule_ordinal
            AND term.term_kind='tenant' AND term.term_value=plan.tenant_id)
      AND EXISTS (
          SELECT 1 FROM ogvcs_identity.compiled_policy_terms term
          WHERE term.tenant_id=rule.tenant_id AND term.repository_id=rule.repository_id
            AND term.policy_generation=rule.policy_generation
            AND term.rule_ordinal=rule.rule_ordinal
            AND term.term_kind='repository' AND term.term_value=plan.repository_id)
      AND (
          NOT EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_subjects subject
              WHERE subject.tenant_id=rule.tenant_id AND subject.repository_id=rule.repository_id
                AND subject.policy_generation=rule.policy_generation
                AND subject.rule_ordinal=rule.rule_ordinal AND subject.subject_kind='identity')
          OR EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_subjects subject
              JOIN ogvcs_identity.aggregate_plan_subject_terms actual
                ON actual.plan_id=plan.plan_id AND actual.subject_kind='identity'
               AND actual.subject_value=subject.subject_value
              WHERE subject.tenant_id=rule.tenant_id AND subject.repository_id=rule.repository_id
                AND subject.policy_generation=rule.policy_generation
                AND subject.rule_ordinal=rule.rule_ordinal AND subject.subject_kind='identity'))
      AND (
          NOT EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_subjects subject
              WHERE subject.tenant_id=rule.tenant_id AND subject.repository_id=rule.repository_id
                AND subject.policy_generation=rule.policy_generation
                AND subject.rule_ordinal=rule.rule_ordinal AND subject.subject_kind='group')
          OR EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_subjects subject
              JOIN ogvcs_identity.aggregate_plan_subject_terms actual
                ON actual.plan_id=plan.plan_id AND actual.subject_kind='group'
               AND actual.subject_value=subject.subject_value
              WHERE subject.tenant_id=rule.tenant_id AND subject.repository_id=rule.repository_id
                AND subject.policy_generation=rule.policy_generation
                AND subject.rule_ordinal=rule.rule_ordinal AND subject.subject_kind='group'))
      AND (
          NOT EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_subjects subject
              WHERE subject.tenant_id=rule.tenant_id AND subject.repository_id=rule.repository_id
                AND subject.policy_generation=rule.policy_generation
                AND subject.rule_ordinal=rule.rule_ordinal AND subject.subject_kind='actor-class')
          OR EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_subjects subject
              JOIN ogvcs_identity.aggregate_plan_subject_terms actual
                ON actual.plan_id=plan.plan_id AND actual.subject_kind='actor-class'
               AND actual.subject_value=subject.subject_value
              WHERE subject.tenant_id=rule.tenant_id AND subject.repository_id=rule.repository_id
                AND subject.policy_generation=rule.policy_generation
                AND subject.rule_ordinal=rule.rule_ordinal AND subject.subject_kind='actor-class'))
      AND EXISTS (
          SELECT 1 FROM ogvcs_identity.compiled_policy_resource_types resource_type
          WHERE resource_type.tenant_id=rule.tenant_id
            AND resource_type.repository_id=rule.repository_id
            AND resource_type.policy_generation=rule.policy_generation
            AND resource_type.rule_ordinal=rule.rule_ordinal
            AND resource_type.resource_type=resource.resource_type)
      AND EXISTS (
          SELECT 1 FROM ogvcs_identity.compiled_policy_permissions permission
          WHERE permission.tenant_id=rule.tenant_id
            AND permission.repository_id=rule.repository_id
            AND permission.policy_generation=rule.policy_generation
            AND permission.rule_ordinal=rule.rule_ordinal
            AND permission.permission=plan.permission)
      AND (
          NOT EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_references reference
              WHERE reference.tenant_id=rule.tenant_id
                AND reference.repository_id=rule.repository_id
                AND reference.policy_generation=rule.policy_generation
                AND reference.rule_ordinal=rule.rule_ordinal)
          OR EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_references reference
              WHERE reference.tenant_id=rule.tenant_id
                AND reference.repository_id=rule.repository_id
                AND reference.policy_generation=rule.policy_generation
                AND reference.rule_ordinal=rule.rule_ordinal
                AND reference.reference_name=plan.reference_name))
      AND (
          NOT EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_path_prefixes prefix
              WHERE prefix.tenant_id=rule.tenant_id
                AND prefix.repository_id=rule.repository_id
                AND prefix.policy_generation=rule.policy_generation
                AND prefix.rule_ordinal=rule.rule_ordinal)
          OR (resource.path_key IS NOT NULL AND EXISTS (
              SELECT 1 FROM ogvcs_identity.compiled_policy_path_prefixes prefix
              WHERE prefix.tenant_id=rule.tenant_id
                AND prefix.repository_id=rule.repository_id
                AND prefix.policy_generation=rule.policy_generation
                AND prefix.rule_ordinal=rule.rule_ordinal
                AND (prefix.is_root OR
                     (resource.path_key COLLATE "C" >= prefix.lower_inclusive
                      AND resource.path_key COLLATE "C" < prefix.upper_exclusive)))))
), outcomes AS (
    SELECT resource.item_ordinal,
           COALESCE(bool_or(matched.effect='deny'), false) AS denied,
           COALESCE(bool_or(matched.effect='allow'), false) AS allowed,
           CASE WHEN resource.resource_type <> 'path' THEN true
                WHEN NOT EXISTS (
                    SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_path_prefixes scope_path
                    WHERE scope_path.plan_id=resource.plan_id) THEN true
                ELSE resource.path_key IS NOT NULL AND EXISTS (
                    SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_path_prefixes scope_path
                    WHERE scope_path.plan_id=resource.plan_id
                      AND (scope_path.is_root OR
                           (resource.path_key COLLATE "C" >= scope_path.lower_inclusive
                            AND resource.path_key COLLATE "C" < scope_path.upper_exclusive)))
           END AS scope_path_allowed
    FROM ogvcs_identity.aggregate_plan_resources resource
    LEFT JOIN matched USING (item_ordinal)
    WHERE resource.plan_id=$1
    GROUP BY resource.plan_id, resource.item_ordinal, resource.resource_type, resource.path_key
), scalar_scope AS (
    SELECT
      EXISTS (SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_terms scope
              WHERE scope.plan_id=plan.plan_id AND scope.scope_kind='tenant'
                AND scope.scope_value=plan.tenant_id)
      AND EXISTS (SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_terms scope
                  WHERE scope.plan_id=plan.plan_id AND scope.scope_kind='repository'
                    AND scope.scope_value=plan.repository_id)
      AND EXISTS (SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_terms scope
                  WHERE scope.plan_id=plan.plan_id AND scope.scope_kind='permission'
                    AND scope.scope_value=plan.permission)
      AND (NOT EXISTS (SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_terms scope
                       WHERE scope.plan_id=plan.plan_id AND scope.scope_kind='reference')
           OR EXISTS (SELECT 1 FROM ogvcs_identity.aggregate_plan_scope_terms scope
                      WHERE scope.plan_id=plan.plan_id AND scope.scope_kind='reference'
                        AND scope.scope_value=plan.reference_name)) AS allowed
    FROM ogvcs_identity.aggregate_plans plan WHERE plan.plan_id=$1
)
SELECT count(*)::bigint,
       count(*) FILTER (WHERE outcomes.denied OR NOT outcomes.allowed
                         OR NOT outcomes.scope_path_allowed
                         OR NOT scalar_scope.allowed)::bigint
FROM outcomes CROSS JOIN scalar_scope
"#;

#[cfg(test)]
mod tests {
    use super::{
        checked_aggregate_count, final_resource_set_digest, hmac_sha256, initial_resource_chain,
        prepare_chunk, resource_chain_step, validate_plan_request, AggregateAuthorizationReceipt,
        AggregatePlanHandle, AggregatePlanRequest, AggregateResourceDigestProjection,
        HmacSha256KeyRing, PostgresAggregateAuthorizationParticipant,
        AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA, AGGREGATE_PLAN_HANDLE_SCHEMA,
        AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY, AGGREGATE_SUBMIT_PERMISSION,
        MAXIMUM_AGGREGATE_RESOURCES,
    };
    use crate::{AggregateHmacKeyProvider, AuthorizationResource, ParticipantErrorCode};
    use ogvcs_path_contract::{repository_path_key, CaseMode, PathProfile};

    fn resource(index: usize) -> AuthorizationResource {
        AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some(format!("Game/{index:06}.asset")),
            file_id: None,
            object_id: None,
            name: None,
        }
    }

    fn sealed_handle() -> (
        PostgresAggregateAuthorizationParticipant,
        AggregatePlanHandle,
    ) {
        let ring = std::sync::Arc::new(
            HmacSha256KeyRing::new([("kms://aggregate/1".to_owned(), [7; 32])]).unwrap(),
        );
        let participant = PostgresAggregateAuthorizationParticipant::new(ring);
        let mut handle = AggregatePlanHandle {
            schema_version: AGGREGATE_PLAN_HANDLE_SCHEMA,
            plan_id: "aggregate.fixture".to_owned(),
            tenant: "studio".to_owned(),
            repository: "game".to_owned(),
            credential_id: "credential".to_owned(),
            credential_generation: 3,
            presentation_digest: "01".repeat(32),
            subject_digest: "02".repeat(32),
            authenticated_scope_digest: "03".repeat(32),
            authority_epoch: 4,
            security_epoch: 4,
            policy_generation: 5,
            policy_digest: "04".repeat(32),
            metadata_tenant_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            metadata_repository_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            settings_generation: 6,
            settings_descriptor_digest: "05".repeat(32),
            path_profile: "path.opengamevcs/portable@1".to_owned(),
            case_mode: "case-folded".to_owned(),
            permission: "metadata.read".to_owned(),
            capability: "aggregate.read".to_owned(),
            reference: Some("main".to_owned()),
            snapshot: Some("snapshot.1".to_owned()),
            reason: None,
            reason_digest: "06".repeat(32),
            issued_at: 10,
            expires_at: 20,
            signer_key_generation: 7,
            signer_key_reference: "kms://aggregate/1".to_owned(),
            signer_key_fingerprint: "07".repeat(32),
            upload_nonce: "08".repeat(32),
            mac: [0; 32],
        };
        handle.mac = participant.sign_handle(&handle).unwrap();
        (participant, handle)
    }

    fn sealed_receipt() -> (
        PostgresAggregateAuthorizationParticipant,
        AggregateAuthorizationReceipt,
    ) {
        let ring = std::sync::Arc::new(
            HmacSha256KeyRing::new([("kms://aggregate/1".to_owned(), [7; 32])]).unwrap(),
        );
        let participant = PostgresAggregateAuthorizationParticipant::new(ring);
        let mut receipt = AggregateAuthorizationReceipt {
            schema_version: AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA,
            plan_id: "aggregate.fixture".to_owned(),
            tenant: "studio".to_owned(),
            repository: "game".to_owned(),
            subject_digest: "02".repeat(32),
            authenticated_scope_digest: "03".repeat(32),
            credential_generation: 3,
            authority_epoch: 4,
            security_epoch: 4,
            policy_generation: 5,
            policy_digest: "04".repeat(32),
            metadata_tenant_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            metadata_repository_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            settings_generation: 6,
            settings_descriptor_digest: "05".repeat(32),
            path_profile: "path.opengamevcs/portable@1".to_owned(),
            case_mode: "case-folded".to_owned(),
            permission: "metadata.read".to_owned(),
            capability: "aggregate.read".to_owned(),
            reference: Some("main".to_owned()),
            snapshot: Some("snapshot.1".to_owned()),
            reason_digest: "06".repeat(32),
            resource_count: 100_000,
            resource_set_digest: "09".repeat(32),
            resource_digest_projection_digest: "0b".repeat(32),
            decision_digest: "0a".repeat(32),
            plan_nonce: "08".repeat(32),
            issued_at: 10,
            expires_at: 20,
            signer_key_generation: 7,
            signer_key_reference: "kms://aggregate/1".to_owned(),
            signer_key_fingerprint: "07".repeat(32),
            mac: [0; 32],
        };
        receipt.mac = participant.sign_receipt(&receipt).unwrap();
        (participant, receipt)
    }

    #[test]
    fn hmac_matches_independent_sha256_vector() {
        let key = [0x0b_u8; 32];
        let actual = hmac_sha256(&key, b"Hi There");
        // Independent OpenSSL HMAC-SHA256 value for this crate's fixed
        // 32-byte secret boundary.
        assert_eq!(
            crate::canonical::hex(&actual),
            "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
        );
    }

    #[test]
    fn key_ring_rejects_wrong_reference_and_has_stable_fingerprint() {
        let ring = HmacSha256KeyRing::new([("kms://aggregate/1".to_owned(), [7; 32])]).unwrap();
        assert_eq!(
            ring.fingerprint("kms://aggregate/1").unwrap(),
            ring.fingerprint("kms://aggregate/1").unwrap()
        );
        assert_eq!(
            ring.sign_hmac_sha256("kms://missing", b"value")
                .unwrap_err()
                .code(),
            ParticipantErrorCode::PolicyUnavailable
        );
    }

    #[test]
    fn privileged_aggregate_permissions_require_a_nonblank_reason() {
        let mut request = AggregatePlanRequest {
            credential_presentation: "presentation",
            tenant: "studio",
            repository: "game",
            permission: "export",
            capability: "aggregate.export",
            reference: Some("main"),
            snapshot: None,
            reason: None,
            ttl_seconds: 60,
        };
        assert_eq!(
            validate_plan_request(&request).unwrap_err().code(),
            ParticipantErrorCode::AuthenticationDenied
        );
        request.reason = Some("   ");
        assert_eq!(
            validate_plan_request(&request).unwrap_err().code(),
            ParticipantErrorCode::AuthenticationDenied
        );
        request.reason = Some("approved export ticket change-42");
        assert!(validate_plan_request(&request).is_ok());
    }

    #[test]
    fn submit_receipts_use_the_exact_lifecycle_permission_capability_pair() {
        let mut request = AggregatePlanRequest {
            credential_presentation: "presentation",
            tenant: "studio",
            repository: "game",
            permission: AGGREGATE_SUBMIT_PERMISSION,
            capability: AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY,
            reference: Some("main"),
            snapshot: None,
            reason: None,
            ttl_seconds: 60,
        };
        assert!(validate_plan_request(&request).is_ok());

        request.capability = "aggregate.submit";
        assert_eq!(
            validate_plan_request(&request).unwrap_err().code(),
            ParticipantErrorCode::AuthenticationDenied
        );
        request.permission = "metadata.write";
        request.capability = AGGREGATE_SUBMIT_CONSUME_PUBLICATION_CAPABILITY;
        assert_eq!(
            validate_plan_request(&request).unwrap_err().code(),
            ParticipantErrorCode::AuthenticationDenied
        );
    }

    #[test]
    fn handle_mac_binds_subject_epoch_policy_profile_settings_and_signer() {
        let (participant, handle) = sealed_handle();
        for mutated in [
            {
                let mut value = handle.clone();
                value.subject_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = handle.clone();
                value.authority_epoch += 1;
                value
            },
            {
                let mut value = handle.clone();
                value.policy_generation += 1;
                value
            },
            {
                let mut value = handle.clone();
                value.path_profile = "path.opengamevcs/linux@1".to_owned();
                value
            },
            {
                let mut value = handle.clone();
                value.settings_generation += 1;
                value
            },
            {
                let mut value = handle.clone();
                value.metadata_tenant_id = "33333333-3333-4333-8333-333333333333".to_owned();
                value
            },
            {
                let mut value = handle.clone();
                value.signer_key_generation += 1;
                value
            },
        ] {
            assert_ne!(participant.sign_handle(&mutated).unwrap(), handle.mac);
        }
    }

    #[test]
    fn receipt_mac_binds_complete_aggregate_authority_and_resource_set() {
        let (participant, receipt) = sealed_receipt();
        for mutated in [
            {
                let mut value = receipt.clone();
                value.subject_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.authenticated_scope_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.policy_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.settings_descriptor_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.metadata_tenant_id = "33333333-3333-4333-8333-333333333333".to_owned();
                value
            },
            {
                let mut value = receipt.clone();
                value.reason_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.resource_count -= 1;
                value
            },
            {
                let mut value = receipt.clone();
                value.resource_set_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.resource_digest_projection_digest = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.expires_at += 1;
                value
            },
            {
                let mut value = receipt.clone();
                value.plan_nonce = "ff".repeat(32);
                value
            },
            {
                let mut value = receipt.clone();
                value.signer_key_generation += 1;
                value
            },
            {
                let mut value = receipt.clone();
                value.signer_key_fingerprint = "ff".repeat(32);
                value
            },
        ] {
            assert_ne!(participant.sign_receipt(&mutated).unwrap(), receipt.mac);
        }
    }

    #[test]
    fn chunks_enforce_order_duplicates_and_byte_bound() {
        let profile = PathProfile::parse("path.opengamevcs/portable@1").unwrap();
        let resources = vec![resource(0), resource(1)];
        assert!(prepare_chunk(&resources, profile, CaseMode::Sensitive, None).is_ok());
        assert!(prepare_chunk(
            &[resource(1), resource(0)],
            profile,
            CaseMode::Sensitive,
            None
        )
        .is_err());
        assert!(prepare_chunk(
            &[resource(0), resource(0)],
            profile,
            CaseMode::Sensitive,
            None
        )
        .is_err());
    }

    #[test]
    fn resource_digest_projection_is_ordered_bounded_and_constant_memory() {
        let mut projection = AggregateResourceDigestProjection::new();
        projection.push(&[1; 32]).unwrap();
        projection.push(&[2; 32]).unwrap();
        let digest = projection.finish().unwrap();
        assert_eq!(projection.count(), 2);
        assert_eq!(digest.len(), 64);

        let mut same = AggregateResourceDigestProjection::new();
        same.push(&[1; 32]).unwrap();
        same.push(&[2; 32]).unwrap();
        assert_eq!(same.finish().unwrap(), digest);

        let mut reversed = AggregateResourceDigestProjection::new();
        reversed.push(&[2; 32]).unwrap();
        reversed.push(&[1; 32]).unwrap();
        assert_ne!(reversed.finish().unwrap(), digest);
        assert_eq!(
            AggregateResourceDigestProjection::new()
                .finish()
                .unwrap_err()
                .code(),
            ParticipantErrorCode::InputInvalid
        );
        assert_eq!(
            AggregateResourceDigestProjection::new()
                .push(&[0; 31])
                .unwrap_err()
                .code(),
            ParticipantErrorCode::InputInvalid
        );
    }

    #[test]
    fn oversized_rows_and_chunks_fail_before_database_allocation() {
        let profile = PathProfile::parse("path.opengamevcs/portable@1").unwrap();
        let mut oversized_row = resource(0);
        oversized_row.name = Some("n".repeat(257));
        assert_eq!(
            prepare_chunk(&[oversized_row], profile, CaseMode::Sensitive, None)
                .err()
                .expect("oversized row is rejected")
                .code(),
            ParticipantErrorCode::InputInvalid
        );

        let long_prefix = std::iter::repeat("a".repeat(200))
            .take(6)
            .collect::<Vec<_>>()
            .join("/");
        let resources = (0..1_000)
            .map(|index| AuthorizationResource {
                resource_type: "path".to_owned(),
                path: Some(format!("Game/{long_prefix}/{index:06}.asset")),
                file_id: None,
                object_id: None,
                name: None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            prepare_chunk(&resources, profile, CaseMode::Sensitive, None)
                .err()
                .expect("oversized chunk is rejected")
                .code(),
            ParticipantErrorCode::LimitExceeded
        );
    }

    #[test]
    fn exact_hundred_thousand_limit_is_streamed_in_one_thousand_item_chunks() {
        let profile = PathProfile::parse("path.opengamevcs/portable@1").unwrap();
        let mut chain = initial_resource_chain();
        let mut projection = AggregateResourceDigestProjection::new();
        let mut previous = None;
        let mut count = 0_usize;
        for chunk_index in 0..100 {
            let start = chunk_index * 1_000;
            let resources = (start..start + 1_000).map(resource).collect::<Vec<_>>();
            let prepared = prepare_chunk(
                &resources,
                profile,
                CaseMode::Sensitive,
                previous.as_deref(),
            )
            .unwrap();
            for item in &prepared.items {
                chain = resource_chain_step(&chain, &item.canonical_key);
                projection.push(&item.digest).unwrap();
            }
            previous = prepared.items.last().map(|item| item.canonical_key.clone());
            count += prepared.items.len();
        }
        assert_eq!(count, MAXIMUM_AGGREGATE_RESOURCES);
        assert_ne!(final_resource_set_digest(count, &chain), [0; 32]);
        assert_eq!(projection.count(), MAXIMUM_AGGREGATE_RESOURCES);
        assert_eq!(projection.finish().unwrap().len(), 64);
        assert_eq!(
            projection.push(&[0; 32]).unwrap_err().code(),
            ParticipantErrorCode::LimitExceeded
        );
        assert_eq!(checked_aggregate_count(count - 1, 1).unwrap(), count);
        assert_eq!(
            checked_aggregate_count(count, 1).unwrap_err().code(),
            ParticipantErrorCode::LimitExceeded
        );
    }

    #[test]
    fn unicode_folded_keys_use_the_exact_path_contract() {
        let profile = PathProfile::parse("path.opengamevcs/portable@1").unwrap();
        let sharp_s = AuthorizationResource {
            resource_type: "path".to_owned(),
            path: Some("Game/Straße.asset".to_owned()),
            file_id: None,
            object_id: None,
            name: None,
        };
        let prepared = prepare_chunk(&[sharp_s], profile, CaseMode::Folded, None).unwrap();
        let expected =
            repository_path_key("Game/STRASSE.asset", profile, CaseMode::Folded).unwrap();
        assert_eq!(
            prepared.items[0].path_key.as_deref().unwrap(),
            expected.as_str()
        );
    }
}
