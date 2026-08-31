use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA: &str =
    "ogvcs.identity-policy/transaction-credential-evidence/v1";
pub const TRANSACTION_AUTHORIZED_VIEW_SCHEMA: &str =
    "ogvcs.identity-policy/transaction-authorized-view/v1";
pub const AUTHORIZED_RESOURCE_BATCH_SCHEMA: &str =
    "ogvcs.identity-policy/authorized-resource-batch/v1";
pub const TRANSACTION_DECISION_COMMITMENT_SCHEMA: &str =
    "ogvcs.identity-policy/transaction-decision-commitment/v1";
pub const PRIVILEGED_AUDIT_EVENT_SCHEMA: &str = "ogvcs.authorization/audit-event/v1";

pub const MAXIMUM_BATCH_RESOURCES: usize = 1_000;
pub const MAXIMUM_DECISION_CHAIN_SCAN: usize = 10_000;
pub const MAXIMUM_DECISION_RESULT_BYTES: usize = 2_048;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionCredentialEvidence {
    #[serde(rename = "schemaVersion")]
    pub(crate) schema_version: &'static str,
    pub(crate) presentation_digest: String,
    pub(crate) credential_id: String,
    pub(crate) credential_generation: u64,
    pub(crate) subject_digest: String,
    pub(crate) tenant: String,
    pub(crate) authority_epoch: u64,
    pub(crate) policy_generation: u64,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) authenticated_scope_digest: String,
}

impl TransactionCredentialEvidence {
    pub const fn schema_version() -> &'static str {
        TRANSACTION_CREDENTIAL_EVIDENCE_SCHEMA
    }

    pub fn presentation_digest(&self) -> &str {
        &self.presentation_digest
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn authenticated_scope_digest(&self) -> &str {
        &self.authenticated_scope_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransactionBinding {
    pub backend_pid: i32,
    pub transaction_xid: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundRequest {
    pub request_id: String,
    pub reason: Option<String>,
    pub reference: Option<String>,
    pub snapshot: Option<String>,
    pub resource: AuthorizationResource,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAuthorizedView {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    transaction_id: String,
    evidence_digest: String,
    subject_digest: String,
    authenticated_scope_digest: String,
    request_fingerprint: String,
    decision_digest: String,
    tenant: String,
    repository: String,
    permission: String,
    authority_epoch: u64,
    credential_generation: u64,
    policy_generation: u64,
    expires_at: u64,
    #[serde(skip)]
    pub(crate) evidence: TransactionCredentialEvidence,
    #[serde(skip)]
    pub(crate) request: BoundRequest,
    #[serde(skip)]
    pub(crate) binding: TransactionBinding,
    #[serde(skip)]
    pub(crate) seal: [u8; 32],
}

impl std::fmt::Debug for TransactionAuthorizedView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransactionAuthorizedView")
            .field("transaction_id", &self.transaction_id)
            .field("evidence_digest", &self.evidence_digest)
            .field("subject_digest", &self.subject_digest)
            .field(
                "authenticated_scope_digest",
                &self.authenticated_scope_digest,
            )
            .field("request_fingerprint", &self.request_fingerprint)
            .field("decision_digest", &self.decision_digest)
            .field("tenant", &self.tenant)
            .field("repository", &self.repository)
            .field("permission", &self.permission)
            .field("authority_epoch", &self.authority_epoch)
            .field("credential_generation", &self.credential_generation)
            .field("policy_generation", &self.policy_generation)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl TransactionAuthorizedView {
    pub const fn schema_version() -> &'static str {
        TRANSACTION_AUTHORIZED_VIEW_SCHEMA
    }

    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    /// This digest is authority-derived and is the only idempotency/allocation
    /// scope a consuming metadata adapter may use.
    pub fn authenticated_scope_digest(&self) -> &str {
        &self.authenticated_scope_digest
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn permission(&self) -> &str {
        &self.permission
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn neutral_clone(&self) -> NeutralAuthorizedView<'_> {
        NeutralAuthorizedView {
            schema_version: self.schema_version,
            transaction_id: &self.transaction_id,
            evidence_digest: &self.evidence_digest,
            subject_digest: &self.subject_digest,
            authenticated_scope_digest: &self.authenticated_scope_digest,
            request_fingerprint: &self.request_fingerprint,
            decision_digest: &self.decision_digest,
            tenant: &self.tenant,
            repository: &self.repository,
            permission: &self.permission,
            authority_epoch: self.authority_epoch,
            credential_generation: self.credential_generation,
            policy_generation: self.policy_generation,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NeutralAuthorizedView<'a> {
    pub schema_version: &'a str,
    pub transaction_id: &'a str,
    pub evidence_digest: &'a str,
    pub subject_digest: &'a str,
    pub authenticated_scope_digest: &'a str,
    pub request_fingerprint: &'a str,
    pub decision_digest: &'a str,
    pub tenant: &'a str,
    pub repository: &'a str,
    pub permission: &'a str,
    pub authority_epoch: u64,
    pub credential_generation: u64,
    pub policy_generation: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDecisionCommitment {
    #[serde(rename = "schemaVersion")]
    pub(crate) schema_version: &'static str,
    pub(crate) commitment_id: String,
    pub(crate) transaction_id: String,
    pub(crate) correlation_id: String,
    pub(crate) tenant: String,
    pub(crate) repository: String,
    pub(crate) authority_epoch: u64,
    pub(crate) decision_digest: String,
    pub(crate) resource_set_digest: String,
    pub(crate) result_digest: String,
    pub(crate) sequence: u64,
    pub(crate) previous_hash: Option<String>,
    pub(crate) record_hash: String,
}

impl TransactionDecisionCommitment {
    pub const fn schema_version() -> &'static str {
        TRANSACTION_DECISION_COMMITMENT_SCHEMA
    }

    pub fn commitment_id(&self) -> &str {
        &self.commitment_id
    }

    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
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

    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }

    pub fn resource_set_digest(&self) -> &str {
        &self.resource_set_digest
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn previous_hash(&self) -> Option<&str> {
        self.previous_hash.as_deref()
    }

    pub fn record_hash(&self) -> &str {
        &self.record_hash
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizationResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub path: Option<String>,
    #[serde(rename = "fileId")]
    pub file_id: Option<String>,
    #[serde(rename = "objectId")]
    pub object_id: Option<String>,
    pub name: Option<String>,
}

pub struct TransactionAuthorizationRequest<'a> {
    pub request_id: &'a str,
    pub credential_presentation: &'a str,
    pub tenant: &'a str,
    pub repository: &'a str,
    pub permission: &'a str,
    pub reason: Option<&'a str>,
    pub resource: &'a AuthorizationResource,
    pub reference: Option<&'a str>,
    pub snapshot: Option<&'a str>,
}

pub struct TransactionBatchRecheck<'a> {
    pub tenant: &'a str,
    pub repository: &'a str,
    pub permission: &'a str,
    pub reference: Option<&'a str>,
    pub resources: &'a [AuthorizationResource],
}

pub struct DecisionCommitmentRequest<'a> {
    pub correlation_id: &'a str,
    pub tenant: &'a str,
    pub repository: &'a str,
    pub permission: &'a str,
    pub reference: Option<&'a str>,
    pub resources: &'a [AuthorizationResource],
    pub result: &'a Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedResourceBatch {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    transaction_id: String,
    resource_set_digest: String,
    items: Vec<AuthorizedResourceBatchItem>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedResourceBatchItem {
    decision_digest: String,
}

impl AuthorizedResourceBatch {
    pub const fn schema_version() -> &'static str {
        AUTHORIZED_RESOURCE_BATCH_SCHEMA
    }

    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub fn resource_set_digest(&self) -> &str {
        &self.resource_set_digest
    }

    pub fn items(&self) -> &[AuthorizedResourceBatchItem] {
        &self.items
    }
}

impl AuthorizedResourceBatchItem {
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialScope {
    pub tenants: Vec<String>,
    pub repositories: Vec<String>,
    pub references: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleSubjects {
    pub identities: Vec<String>,
    pub groups: Vec<String>,
    pub actor_classes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyRule {
    pub id: String,
    pub effect: String,
    pub subjects: RuleSubjects,
    pub tenant: String,
    pub repository: String,
    pub references: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub resource_types: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: String,
    pub id: String,
    pub version: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub path_profile: String,
    pub case_mode: String,
    #[serde(rename = "default")]
    pub default_effect: String,
    pub composition: String,
    pub rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegedAuditDetails {
    pub target_class: String,
    pub change_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivilegedAuditEvent {
    pub(crate) schema_version: String,
    pub(crate) event_id: String,
    pub(crate) event_class: String,
    pub(crate) occurred_at: u64,
    pub(crate) tenant: String,
    pub(crate) repository: String,
    pub(crate) actor_class: String,
    pub(crate) actor_pseudonym: String,
    pub(crate) permission: String,
    pub(crate) reason: String,
    pub(crate) outcome_code: String,
    pub(crate) correlation_id: String,
    pub(crate) details: PrivilegedAuditDetails,
}

impl PrivilegedAuditEvent {
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn event_class(&self) -> &str {
        &self.event_class
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }
}

pub struct PrivilegedAuditContext<'a> {
    pub event_id: &'a str,
    pub correlation_id: &'a str,
    pub reason: &'a str,
    pub change_ref: Option<&'a str>,
}

pub struct PolicyReplacement<'a> {
    pub tenant: &'a str,
    pub repository: &'a str,
    pub expected_generation: u64,
    pub next_policy: &'a PolicyDocument,
    pub audit: PrivilegedAuditContext<'a>,
}

pub struct CredentialRevocation<'a> {
    pub tenant: &'a str,
    pub repository: &'a str,
    pub credential_id: &'a str,
    pub credential_generation: u64,
    pub audit: PrivilegedAuditContext<'a>,
}

pub struct EpochPromotion<'a> {
    pub tenant: &'a str,
    pub repository: &'a str,
    pub expected_authority_epoch: u64,
    pub next_authority_epoch: u64,
    pub next_key_generation: u64,
    pub audit: PrivilegedAuditContext<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionChainVerification {
    records: usize,
    tail_hash: Option<String>,
}

impl DecisionChainVerification {
    pub const fn records(&self) -> usize {
        self.records
    }

    pub fn tail_hash(&self) -> Option<&str> {
        self.tail_hash.as_deref()
    }
}

pub(crate) struct ViewParts {
    pub transaction_id: String,
    pub evidence_digest: String,
    pub subject_digest: String,
    pub authenticated_scope_digest: String,
    pub request_fingerprint: String,
    pub decision_digest: String,
    pub tenant: String,
    pub repository: String,
    pub permission: String,
    pub authority_epoch: u64,
    pub credential_generation: u64,
    pub policy_generation: u64,
    pub expires_at: u64,
    pub evidence: TransactionCredentialEvidence,
    pub request: BoundRequest,
    pub binding: TransactionBinding,
}

impl TransactionAuthorizedView {
    pub(crate) fn from_parts(parts: ViewParts) -> Self {
        Self {
            schema_version: TRANSACTION_AUTHORIZED_VIEW_SCHEMA,
            transaction_id: parts.transaction_id,
            evidence_digest: parts.evidence_digest,
            subject_digest: parts.subject_digest,
            authenticated_scope_digest: parts.authenticated_scope_digest,
            request_fingerprint: parts.request_fingerprint,
            decision_digest: parts.decision_digest,
            tenant: parts.tenant,
            repository: parts.repository,
            permission: parts.permission,
            authority_epoch: parts.authority_epoch,
            credential_generation: parts.credential_generation,
            policy_generation: parts.policy_generation,
            expires_at: parts.expires_at,
            evidence: parts.evidence,
            request: parts.request,
            binding: parts.binding,
            seal: [0; 32],
        }
    }

    pub(crate) fn set_seal(&mut self, seal: [u8; 32]) {
        self.seal = seal;
    }
}

impl AuthorizedResourceBatch {
    pub(crate) fn new(
        transaction_id: String,
        resource_set_digest: String,
        decision_digests: Vec<String>,
    ) -> Self {
        Self {
            schema_version: AUTHORIZED_RESOURCE_BATCH_SCHEMA,
            transaction_id,
            resource_set_digest,
            items: decision_digests
                .into_iter()
                .map(|decision_digest| AuthorizedResourceBatchItem { decision_digest })
                .collect(),
        }
    }
}

impl DecisionChainVerification {
    pub(crate) fn new(records: usize, tail_hash: Option<String>) -> Self {
        Self { records, tail_hash }
    }
}
