use super::*;
use crate::lifecycle::{
    application_receipt_digest, domain_digest, lifecycle_contract_digest, protected_fact_digest,
    LifecycleApplicationReceipt, LifecycleCapability, LifecycleDirectCommand, LifecycleHealth,
    LifecycleObjectBinding, LifecycleReceiptKind, LifecycleState,
};
use ogvcs_identity_policy_audit_postgres::{
    AuthorizationResource as IdentityAuthorizationResource, DecisionCommitmentRequest,
    TransactionAuthorizationParticipant, TransactionAuthorizationRequest,
    TransactionAuthorizedView, TransactionBatchRecheck, MAXIMUM_BATCH_RESOURCES,
};
use serde::Serialize;
use std::{fmt, sync::Arc};

use crate::{
    service::metadata_negotiation_tenant_digest, MetadataNegotiationKeyRing, MetadataOperation,
    MetadataOperationExposure, NegotiationVerifiedMetadataRequest,
};

pub const CONTENT_MANIFEST_EXPLICIT_OBJECTS_MAXIMUM: usize = 4_096;
pub const CONTENT_MANIFEST_PRODUCTION_BOUNDARY: &str =
    "ogvcs.chunking-manifest/production-boundary@1";
pub const CONTENT_MANIFEST_PRODUCTION_PROFILE: &str = "chunking.opengamevcs/gear-fastcdc-1m@1";
pub const CONTENT_MANIFEST_PRODUCTION_VERIFIER: &str = "ogvcs.chunking-manifest/verifier@1";
/// Existing OGVCS-041 control-envelope assignment used only as authenticated,
/// route-less composition facts. It is not registered as an object-transfer
/// route and does not change the request-root-only public transfer carrier.
pub const CONTENT_MANIFEST_EXPLICIT_COMPOSITION_OPERATION: &str = "object.put";

// v12 persists at most five fixed-width OGVCS-009 authorization pages. A
// future identity participant width change therefore requires a new metadata
// schema rather than silently changing the proof shape.
const _: () = assert!(MAXIMUM_BATCH_RESOURCES == 1_000);

const CONTENT_UPLOAD_PERMISSION: &str = "content.upload";
const COMMITTED_PROOF_SCHEMA: &str = "ogvcs.object-transfer/content-manifest-committed-current/v1";
const AUTHORIZATION_CLOSURE_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-AUTHORIZATION-CLOSURE-V1";
const DEPENDENCY_GENERATIONS_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-DEPENDENCY-GENERATIONS-V1\0";
const PRODUCTION_STATEMENT_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-PRODUCTION-V1";
const LIFECYCLE_VERIFICATION_RECEIPT_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-LIFECYCLE-VERIFICATION-RECEIPT-V1";
const COMMITTED_PROOF_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-COMMITTED-PROOF-V1";
const EXPLICIT_AUTHORITY_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-EXPLICIT-AUTHORITY-V1";
const IDEMPOTENCY_SCOPE_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-MANIFEST-IDEMPOTENCY-SCOPE-V1";
const RESOURCE_OPAQUE_DOMAIN: &[u8] = b"OGVCS-OBJECT-TRANSFER-MANIFEST-RESOURCE-V1";
const DECISION_CORRELATION_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-MANIFEST-DECISION-CORRELATION-V1";
const RECONCILIATION_OBSERVATION_DOMAIN: &[u8] =
    b"OGVCS-OBJECT-TRANSFER-MANIFEST-RECONCILIATION-V1";
const EXPLICIT_COMPOSITION_NEGOTIATION_RECEIPT_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-NEGOTIATION-RECEIPT-V1";
const EXPLICIT_COMPOSITION_CONTROL_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-CONTROL-V1";
const EXPLICIT_COMPOSITION_OBJECT_SET_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-OBJECT-SET-V1";
const EXPLICIT_COMPOSITION_AUTHORITY_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-AUTHORITY-V1";
const EXPLICIT_COMPOSITION_COMMIT_TARGET_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-COMMIT-TARGET-V1";
const EXPLICIT_COMPOSITION_RECONCILIATION_TARGET_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-RECONCILIATION-TARGET-V1";
const EXPLICIT_COMPOSITION_COMMIT_RECEIPT_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-COMMIT-RECEIPT-V1";
const EXPLICIT_COMPOSITION_RECONCILIATION_RECEIPT_DOMAIN: &[u8] =
    b"OGVCS-REPOSITORY-METADATA-EXPLICIT-COMPOSITION-RECONCILIATION-RECEIPT-V1";

/// Existing OGVCS-009 authority projected onto one exact sorted ObjectID set.
/// There is intentionally no bounded-root field or expansion callback.
#[derive(Clone, Copy, Debug)]
pub struct ContentManifestExplicitAuthority<'a> {
    pub credentials: TransactionCredentialRequest<'a>,
    pub tenant_id: TenantId,
    pub repository_id: RepositoryId,
    pub object_set: &'a [ObjectRef],
    /// OGVCS-009 subject digest. This is checked against every authorized
    /// view and written into the lifecycle application.
    pub identity_subject_digest: [u8; 32],
    /// Existing object-transfer production-subject digest. The still-private
    /// adapter is responsible for mapping its issuer/subject claims to the
    /// independently authenticated OGVCS-009 identity above.
    pub production_subject_digest: [u8; 32],
    pub authority_epoch: u64,
    pub authorization_closure_digest: [u8; 32],
    pub tenant_scope_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentManifestDependencyBinding {
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub length: u64,
    pub generation: u64,
    pub authority_binding_digest: [u8; 32],
    pub backend_receipt_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentManifestProductionStatement {
    pub boundary: String,
    pub logical_bytes: u64,
    pub manifest_object_id: ObjectRef,
    pub manifest_sha256: [u8; 32],
    pub profile: String,
    pub verifier: String,
    pub whole_file_sha256: [u8; 32],
}

impl ContentManifestProductionStatement {
    fn is_valid_for(&self, manifest: ObjectRef) -> bool {
        self.boundary == CONTENT_MANIFEST_PRODUCTION_BOUNDARY
            && self.logical_bytes <= 107_374_182_400
            && self.manifest_object_id == manifest
            && self.profile == CONTENT_MANIFEST_PRODUCTION_PROFILE
            && self.verifier == CONTENT_MANIFEST_PRODUCTION_VERIFIER
    }
}

pub struct ContentManifestAvailabilityCommitRequest<'a> {
    pub authority: ContentManifestExplicitAuthority<'a>,
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub length: u64,
    pub expected_generation: u64,
    pub authority_binding_digest: [u8; 32],
    pub backend_receipt_digest: [u8; 32],
    pub verification_receipt_digest: [u8; 32],
    pub finalize_semantic_fingerprint: [u8; 32],
    pub dependencies: &'a [ContentManifestDependencyBinding],
    pub dependency_generation_set_digest: [u8; 32],
    pub production_statement: ContentManifestProductionStatement,
}

pub struct ContentManifestCommittedProofLookup<'a> {
    pub authority: ContentManifestExplicitAuthority<'a>,
    pub opaque_key: [u8; 32],
    pub object_ref: ObjectRef,
    pub length: u64,
    pub authority_binding_digest: [u8; 32],
    pub backend_receipt_digest: [u8; 32],
    pub finalize_semantic_fingerprint: [u8; 32],
}

/// Opaque composition brand produced after one exact OGVCS-041 `object.put`
/// request has been matched to the complete explicit-set availability command.
/// It cannot be constructed outside this module or replayed through a second
/// composition instance.
pub struct BoundContentManifestAvailabilityCommit<'a> {
    binding: BrandedComposition<BoundCompositionCommit<'a>>,
}

/// Opaque composition brand for authenticated committed-proof reconciliation.
/// The expected raw manifest SHA-256 is retained because the v12 lookup itself
/// intentionally contains no public carrier fields.
pub struct BoundContentManifestAvailabilityReconciliation<'a> {
    binding: BrandedComposition<BoundCompositionReconciliation<'a>>,
}

struct BoundCompositionCommit<'a> {
    verified: NegotiationVerifiedMetadataRequest,
    request: ContentManifestAvailabilityCommitRequest<'a>,
    commitments: ExplicitCompositionInputCommitments,
}

struct BoundCompositionReconciliation<'a> {
    verified: NegotiationVerifiedMetadataRequest,
    lookup: ContentManifestCommittedProofLookup<'a>,
    expected_manifest_sha256: [u8; 32],
    commitments: ExplicitCompositionInputCommitments,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExplicitCompositionInputCommitments {
    control: [u8; 32],
    authority: [u8; 32],
    target: [u8; 32],
}

/// Route-less production composition of the existing OGVCS-041 request brand,
/// OGVCS-009 transaction participant, and v12 explicit-set availability seam.
/// No HTTP router, generic transfer route, or request-root expansion surface is
/// exposed by this type.
pub struct PostgresContentManifestExplicitComposition {
    store: IdentityBoundPostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator>,
    negotiation_keys: Arc<MetadataNegotiationKeyRing>,
    brand: ExplicitCompositionBrand,
}

#[derive(Clone)]
struct ExplicitCompositionBrand(Arc<()>);

struct BrandedComposition<T> {
    origin: Arc<()>,
    value: T,
}

/// Opaque evidence returned only after the authenticated control binding and
/// the existing v12 mutation have both completed. The ordinary v12 proof is
/// intentionally not exposed through this type.
pub struct ContentManifestExplicitCompositionCommitReceipt {
    control_commitment: [u8; 32],
    authority_commitment: [u8; 32],
    target_commitment: [u8; 32],
    committed_proof_digest: [u8; 32],
    proof_replayed: bool,
    receipt_digest: [u8; 32],
}

/// Closed reconciliation outcome carried by the opaque composition receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentManifestExplicitCompositionReconciliationStatus {
    Committed,
    UnknownRecovering,
}

/// Opaque reconciliation evidence. Both committed and unknown-recovering
/// results bind the exact authenticated request and explicit authority input.
pub struct ContentManifestExplicitCompositionReconciliationReceipt {
    status: ContentManifestExplicitCompositionReconciliationStatus,
    control_commitment: [u8; 32],
    authority_commitment: [u8; 32],
    target_commitment: [u8; 32],
    underlying_evidence_digest: [u8; 32],
    receipt_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentManifestCommittedProof {
    application_id: [u8; 16],
    tenant_id: TenantId,
    repository_id: RepositoryId,
    opaque_key: [u8; 32],
    object_ref: ObjectRef,
    length: u64,
    generation: u64,
    authorization_closure_digest: [u8; 32],
    authority_binding_digest: [u8; 32],
    tenant_scope_digest: [u8; 32],
    identity_subject_digest: [u8; 32],
    production_subject_digest: [u8; 32],
    backend_receipt_digest: [u8; 32],
    dependency_count: u16,
    dependency_generation_set_digest: [u8; 32],
    verification_receipt_digest: [u8; 32],
    finalize_semantic_fingerprint: [u8; 32],
    production_statement: ContentManifestProductionStatement,
    production_statement_digest: [u8; 32],
    proof_digest: [u8; 32],
    replayed: bool,
}

impl ContentManifestCommittedProof {
    pub const fn application_id(&self) -> &[u8; 16] {
        &self.application_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn dependency_count(&self) -> u16 {
        self.dependency_count
    }

    pub const fn dependency_generation_set_digest(&self) -> &[u8; 32] {
        &self.dependency_generation_set_digest
    }

    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }

    pub const fn production_statement(&self) -> &ContentManifestProductionStatement {
        &self.production_statement
    }

    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

impl ContentManifestExplicitCompositionCommitReceipt {
    pub const fn receipt_sha256(&self) -> &[u8; 32] {
        &self.receipt_digest
    }

    pub const fn control_commitment_sha256(&self) -> &[u8; 32] {
        &self.control_commitment
    }

    pub const fn authority_commitment_sha256(&self) -> &[u8; 32] {
        &self.authority_commitment
    }

    pub const fn target_commitment_sha256(&self) -> &[u8; 32] {
        &self.target_commitment
    }

    pub const fn committed_proof_sha256(&self) -> &[u8; 32] {
        &self.committed_proof_digest
    }

    pub const fn proof_replayed(&self) -> bool {
        self.proof_replayed
    }
}

impl fmt::Debug for ContentManifestExplicitCompositionCommitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentManifestExplicitCompositionCommitReceipt")
            .field("bindings", &"[REDACTED]")
            .field("committed_proof", &"[REDACTED]")
            .field("receipt", &"[REDACTED]")
            .finish()
    }
}

impl ContentManifestExplicitCompositionReconciliationReceipt {
    pub const fn status(&self) -> ContentManifestExplicitCompositionReconciliationStatus {
        self.status
    }

    pub const fn receipt_sha256(&self) -> &[u8; 32] {
        &self.receipt_digest
    }

    pub const fn control_commitment_sha256(&self) -> &[u8; 32] {
        &self.control_commitment
    }

    pub const fn authority_commitment_sha256(&self) -> &[u8; 32] {
        &self.authority_commitment
    }

    pub const fn target_commitment_sha256(&self) -> &[u8; 32] {
        &self.target_commitment
    }

    pub const fn underlying_evidence_sha256(&self) -> &[u8; 32] {
        &self.underlying_evidence_digest
    }
}

impl fmt::Debug for ContentManifestExplicitCompositionReconciliationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentManifestExplicitCompositionReconciliationReceipt")
            .field("status", &self.status)
            .field("bindings", &"[REDACTED]")
            .field("underlying_evidence", &"[REDACTED]")
            .field("receipt", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentManifestAvailabilityReconciliation {
    Committed(Box<ContentManifestCommittedProof>),
    UnknownRecovering { observation_digest: [u8; 32] },
}

#[cfg(feature = "legacy-test-adapter")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentManifestAvailabilityFaultForTest {
    AfterAuthority,
    AfterApplication,
    AfterReceiptConsumption,
    AfterLifecycleCas,
    AfterFact,
    AfterProof,
    BeforeCommit,
    AfterCommitResponse,
    WrongReceiptContractAtSqlProofBoundary,
    WrongSharedContractAtSqlProofBoundary,
    WrongReceiptBindingAtSqlProofBoundary,
    WrongTenantScopeAtSqlProofBoundary,
    WrongFactOutboxAtSqlProofBoundary,
    NonCanonicalPageSplitAtSqlProofBoundary,
}

#[derive(Clone, Copy, Default)]
struct TransferFault {
    #[cfg(feature = "legacy-test-adapter")]
    boundary: Option<ContentManifestAvailabilityFaultForTest>,
}

struct AuthorizedExplicitSet {
    pages: Vec<TransactionAuthorizedView>,
    resources: Vec<IdentityAuthorizationResource>,
}

impl AuthorizedExplicitSet {
    fn primary_view(&self) -> Result<&TransactionAuthorizedView> {
        self.pages.first().ok_or_else(denied_error)
    }
}

/// One caller-owned, transaction-bound availability participant. The raw
/// PostgreSQL transaction and OGVCS-009 participant remain sealed so callers
/// cannot execute this transition without the exact verified authority path.
pub struct ContentManifestAvailabilityTransaction<'store> {
    transaction: Option<Transaction<'store>>,
    participant: &'store PostgresTransactionAuthorizationParticipant,
    state: BoundTransactionState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum BoundTransactionState {
    Ready,
    Applied,
    Failed,
}

#[derive(Clone)]
struct LockedLifecycle {
    opaque_key: [u8; 32],
    object_ref: ObjectRef,
    length: u64,
    tenant_scope_digest: [u8; 32],
    state: String,
    generation: u64,
    authority_binding_digest: [u8; 32],
    backend_receipt_digest: Option<[u8; 32]>,
    verification_receipt_digest: Option<[u8; 32]>,
    deletion_receipt_digest: Option<[u8; 32]>,
}

impl<A, V> IdentityBoundPostgresMetadataStore<A, V> {
    pub fn begin_content_manifest_availability_transaction(
        &mut self,
    ) -> Result<ContentManifestAvailabilityTransaction<'_>> {
        crate::verify_schema_compatibility(&mut self.store.client)?;
        let PostgresMetadataStore {
            client,
            transaction_authorization,
            ..
        } = &mut self.store;
        let participant = transaction_authorization
            .as_ref()
            .ok_or_else(denied_error)?;
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        Ok(ContentManifestAvailabilityTransaction {
            transaction: Some(transaction),
            participant,
            state: BoundTransactionState::Ready,
        })
    }

    pub fn commit_content_manifest_availability(
        &mut self,
        request: ContentManifestAvailabilityCommitRequest<'_>,
    ) -> Result<ContentManifestCommittedProof> {
        self.commit_content_manifest_availability_inner(request, TransferFault::default())
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn commit_content_manifest_availability_with_fault_for_test(
        &mut self,
        request: ContentManifestAvailabilityCommitRequest<'_>,
        boundary: ContentManifestAvailabilityFaultForTest,
    ) -> Result<ContentManifestCommittedProof> {
        self.commit_content_manifest_availability_inner(
            request,
            TransferFault {
                boundary: Some(boundary),
            },
        )
    }

    fn commit_content_manifest_availability_inner(
        &mut self,
        request: ContentManifestAvailabilityCommitRequest<'_>,
        fault: TransferFault,
    ) -> Result<ContentManifestCommittedProof> {
        validate_commit_request(&request)?;
        let mut transaction = self.begin_content_manifest_availability_transaction()?;
        let result = transaction.apply_inner(&request, fault);
        let proof = match result {
            Ok(proof) => proof,
            Err(_) => {
                let _ = transaction.rollback();
                return denied();
            }
        };
        transaction.commit()?;
        if fault.at(ContentManifestAvailabilityFaultForTestMarker::AfterCommitResponse) {
            return denied();
        }
        Ok(proof)
    }

    pub fn reconcile_content_manifest_availability(
        &mut self,
        lookup: ContentManifestCommittedProofLookup<'_>,
    ) -> Result<ContentManifestAvailabilityReconciliation> {
        validate_lookup(&lookup)?;
        crate::verify_schema_compatibility(&mut self.store.client)?;
        let PostgresMetadataStore {
            client,
            transaction_authorization,
            ..
        } = &mut self.store;
        let participant = transaction_authorization
            .as_ref()
            .ok_or_else(denied_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(database_error)?;
        let result = reconcile_in_transaction(&mut transaction, participant, &lookup);
        let _ = transaction.rollback();
        result.map_err(|_| denied_error())
    }
}

fn reconcile_in_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresTransactionAuthorizationParticipant,
    lookup: &ContentManifestCommittedProofLookup<'_>,
) -> Result<ContentManifestAvailabilityReconciliation> {
    let authorized = authorize_explicit_set(
        transaction,
        participant,
        &lookup.authority,
        lookup.object_ref,
    )?;
    let proof = load_committed_proof(transaction, lookup, false)?;
    let observation_digest = reconciliation_observation_digest(lookup, authorized.primary_view()?)?;
    Ok(match proof {
        Some(mut proof) => {
            proof.replayed = true;
            ContentManifestAvailabilityReconciliation::Committed(Box::new(proof))
        }
        None => ContentManifestAvailabilityReconciliation::UnknownRecovering { observation_digest },
    })
}

impl ExplicitCompositionBrand {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn bind<T>(&self, value: T) -> BrandedComposition<T> {
        BrandedComposition {
            origin: Arc::clone(&self.0),
            value,
        }
    }

    fn take<T>(&self, branded: BrandedComposition<T>) -> Result<T> {
        if !Arc::ptr_eq(&self.0, &branded.origin) {
            return denied();
        }
        Ok(branded.value)
    }
}

impl PostgresContentManifestExplicitComposition {
    /// Opens the route-less composition with both OGVCS-009 and OGVCS-041
    /// verifier authorities installed before it becomes observable.
    pub fn connect(
        database_url: &str,
        participant: PostgresTransactionAuthorizationParticipant,
        negotiation_keys: Arc<MetadataNegotiationKeyRing>,
    ) -> Result<Self> {
        Ok(Self::from_store(
            IdentityBoundPostgresMetadataStore::connect(database_url, participant)?,
            negotiation_keys,
        ))
    }

    pub fn from_store(
        store: IdentityBoundPostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator>,
        negotiation_keys: Arc<MetadataNegotiationKeyRing>,
    ) -> Self {
        Self {
            store,
            negotiation_keys,
            brand: ExplicitCompositionBrand::new(),
        }
    }

    /// Matches an already negotiation-verified OGVCS-041 `object.put`
    /// envelope to the complete explicit-set command without performing a
    /// database lookup or mutation.
    pub fn bind_commit<'a>(
        &self,
        verified: NegotiationVerifiedMetadataRequest,
        request: ContentManifestAvailabilityCommitRequest<'a>,
    ) -> Result<BoundContentManifestAvailabilityCommit<'a>> {
        validate_commit_request(&request)?;
        validate_composition_control(
            &verified,
            &request.authority,
            request.object_ref,
            request.length,
            request.production_statement.manifest_sha256,
        )?;
        let commitments = commit_composition_input_commitments(&verified, &request)?;
        Ok(BoundContentManifestAvailabilityCommit {
            binding: self.brand.bind(BoundCompositionCommit {
                verified,
                request,
                commitments,
            }),
        })
    }

    /// Re-verifies the carrier at the database clock, delegates the only
    /// mutation to the existing v12 OGVCS-009-bound transaction, and returns
    /// only an opaque receipt binding that proof to the authenticated input.
    pub fn commit(
        &mut self,
        bound: BoundContentManifestAvailabilityCommit<'_>,
    ) -> Result<ContentManifestExplicitCompositionCommitReceipt> {
        let BoundCompositionCommit {
            verified,
            request,
            commitments,
        } = self.brand.take(bound.binding)?;
        validate_commit_request(&request)?;
        validate_composition_control(
            &verified,
            &request.authority,
            request.object_ref,
            request.length,
            request.production_statement.manifest_sha256,
        )?;
        if commit_composition_input_commitments(&verified, &request)? != commitments {
            return denied();
        }
        crate::verify_schema_compatibility(&mut self.store.store.client)
            .map_err(|_| denied_error())?;
        let PostgresMetadataStore {
            client,
            transaction_authorization,
            ..
        } = &mut self.store.store;
        let participant = transaction_authorization
            .as_ref()
            .ok_or_else(denied_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(|_| denied_error())?;
        let result: Result<ContentManifestExplicitCompositionCommitReceipt> = (|| {
            let now_unix_ms = composition_database_now_unix_ms(&mut transaction)?;
            reverify_composition_at_database_clock(
                &verified,
                self.negotiation_keys.as_ref(),
                now_unix_ms,
            )?;
            let (mut proof, wrote) = commit_in_transaction(
                &mut transaction,
                participant,
                &request,
                TransferFault::default(),
            )?;
            proof.replayed = !wrote;
            composition_commit_receipt(commitments, &request, proof)
        })();
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(_) => {
                let _ = transaction.rollback();
                return denied();
            }
        };
        transaction.commit().map_err(|_| denied_error())?;
        Ok(receipt)
    }

    /// Binds a committed-proof lookup to the same route-less public control
    /// facts. The raw manifest digest is explicit because v12 intentionally
    /// keeps it outside the stable lookup identity.
    pub fn bind_reconciliation<'a>(
        &self,
        verified: NegotiationVerifiedMetadataRequest,
        lookup: ContentManifestCommittedProofLookup<'a>,
        expected_manifest_sha256: [u8; 32],
    ) -> Result<BoundContentManifestAvailabilityReconciliation<'a>> {
        validate_lookup(&lookup)?;
        validate_composition_control(
            &verified,
            &lookup.authority,
            lookup.object_ref,
            lookup.length,
            expected_manifest_sha256,
        )?;
        let commitments = reconciliation_composition_input_commitments(
            &verified,
            &lookup,
            expected_manifest_sha256,
        )?;
        Ok(BoundContentManifestAvailabilityReconciliation {
            binding: self.brand.bind(BoundCompositionReconciliation {
                verified,
                lookup,
                expected_manifest_sha256,
                commitments,
            }),
        })
    }

    /// Re-verifies and reauthorizes the exact explicit set in one read-only
    /// SERIALIZABLE transaction. The opaque output binds either an exact
    /// committed proof or the authorized unknown observation to the public
    /// carrier, including its raw manifest digest.
    pub fn reconcile(
        &mut self,
        bound: BoundContentManifestAvailabilityReconciliation<'_>,
    ) -> Result<ContentManifestExplicitCompositionReconciliationReceipt> {
        let BoundCompositionReconciliation {
            verified,
            lookup,
            expected_manifest_sha256,
            commitments,
        } = self.brand.take(bound.binding)?;
        validate_lookup(&lookup)?;
        validate_composition_control(
            &verified,
            &lookup.authority,
            lookup.object_ref,
            lookup.length,
            expected_manifest_sha256,
        )?;
        if reconciliation_composition_input_commitments(
            &verified,
            &lookup,
            expected_manifest_sha256,
        )? != commitments
        {
            return denied();
        }
        crate::verify_schema_compatibility(&mut self.store.store.client)
            .map_err(|_| denied_error())?;
        let PostgresMetadataStore {
            client,
            transaction_authorization,
            ..
        } = &mut self.store.store;
        let participant = transaction_authorization
            .as_ref()
            .ok_or_else(denied_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(|_| denied_error())?;
        let result: Result<ContentManifestExplicitCompositionReconciliationReceipt> = (|| {
            let now_unix_ms = composition_database_now_unix_ms(&mut transaction)?;
            reverify_composition_at_database_clock(
                &verified,
                self.negotiation_keys.as_ref(),
                now_unix_ms,
            )?;
            let result = reconcile_in_transaction(&mut transaction, participant, &lookup)?;
            if let ContentManifestAvailabilityReconciliation::Committed(proof) = &result {
                if proof.production_statement.manifest_sha256 != expected_manifest_sha256 {
                    return denied();
                }
            }
            composition_reconciliation_receipt(
                commitments,
                &lookup,
                expected_manifest_sha256,
                result,
            )
        })();
        let _ = transaction.rollback();
        result.map_err(|_| denied_error())
    }
}

fn validate_composition_control(
    verified: &NegotiationVerifiedMetadataRequest,
    authority: &ContentManifestExplicitAuthority<'_>,
    manifest: ObjectRef,
    length: u64,
    manifest_sha256: [u8; 32],
) -> Result<()> {
    validate_authority(authority, manifest)?;
    let request = verified.request();
    let body = request.body().as_object().ok_or_else(denied_error)?;
    if request.operation() != MetadataOperation::ObjectPut
        || request.operation().name() != CONTENT_MANIFEST_EXPLICIT_COMPOSITION_OPERATION
        || request.exposure() != MetadataOperationExposure::StreamCarrierRequired
        || request
            .operation()
            .transport_descriptor()
            .network_registered
        || request.semantic_fingerprint().is_none()
        || request.tenant_id() != Some(authority.tenant_id)
        || request.repository_id() != Some(authority.repository_id)
        || authority.credentials.correlation_id != request.correlation_id()
        || verified.principal().authority_epoch() != authority.authority_epoch
        || !bool::from(
            verified
                .principal()
                .subject_digest()
                .ct_eq(&authority.identity_subject_digest),
        )
        || !bool::from(
            verified
                .principal()
                .tenant_digest()
                .ct_eq(&metadata_negotiation_tenant_digest(authority.tenant_id)),
        )
        || body.get("objectRef").and_then(Value::as_str) != Some(manifest.to_string().as_str())
        || body.get("canonicalByteLength").and_then(Value::as_u64) != Some(length)
        || body.get("streamDigestSha256").and_then(Value::as_str)
            != Some(hex_bytes(&manifest_sha256).as_str())
    {
        return denied();
    }
    Ok(())
}

fn commit_composition_input_commitments(
    verified: &NegotiationVerifiedMetadataRequest,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
) -> Result<ExplicitCompositionInputCommitments> {
    Ok(ExplicitCompositionInputCommitments {
        control: explicit_composition_control_commitment(verified)?,
        authority: explicit_composition_authority_commitment(&request.authority)?,
        target: explicit_composition_commit_target_commitment(request)?,
    })
}

fn reconciliation_composition_input_commitments(
    verified: &NegotiationVerifiedMetadataRequest,
    lookup: &ContentManifestCommittedProofLookup<'_>,
    expected_manifest_sha256: [u8; 32],
) -> Result<ExplicitCompositionInputCommitments> {
    Ok(ExplicitCompositionInputCommitments {
        control: explicit_composition_control_commitment(verified)?,
        authority: explicit_composition_authority_commitment(&lookup.authority)?,
        target: explicit_composition_reconciliation_target_commitment(
            lookup,
            expected_manifest_sha256,
        ),
    })
}

fn explicit_composition_control_commitment(
    verified: &NegotiationVerifiedMetadataRequest,
) -> Result<[u8; 32]> {
    let request = verified.request();
    let semantic_fingerprint = request.semantic_fingerprint().ok_or_else(denied_error)?;
    let idempotency_key = request.idempotency_key().ok_or_else(denied_error)?;
    let negotiation_receipt = domain_digest(
        EXPLICIT_COMPOSITION_NEGOTIATION_RECEIPT_DOMAIN,
        &canonical_json_bytes(request.negotiation_receipt())?,
    );
    let principal = verified.principal();
    let mut bytes = Vec::with_capacity(512);
    receipt_field(&mut bytes, request.operation().name().as_bytes());
    receipt_field(&mut bytes, request.correlation_id().as_bytes());
    match request.deadline_unix_ms() {
        Some(deadline) => {
            receipt_field(&mut bytes, b"deadline-present");
            receipt_field(&mut bytes, &deadline.to_be_bytes());
        }
        None => receipt_field(&mut bytes, b"deadline-absent"),
    }
    receipt_field(&mut bytes, idempotency_key.as_bytes());
    receipt_field(&mut bytes, &semantic_fingerprint);
    receipt_field(&mut bytes, &negotiation_receipt);
    receipt_field(&mut bytes, principal.subject_digest());
    receipt_field(&mut bytes, principal.tenant_digest());
    receipt_field(&mut bytes, &principal.authority_epoch().to_be_bytes());
    receipt_field(&mut bytes, principal.session_id.as_bytes());
    Ok(domain_digest(EXPLICIT_COMPOSITION_CONTROL_DOMAIN, &bytes))
}

fn explicit_composition_object_set_commitment(object_set: &[ObjectRef]) -> Result<[u8; 32]> {
    let count = u64::try_from(object_set.len()).map_err(|_| denied_error())?;
    let mut bytes = Vec::with_capacity(object_set.len().saturating_mul(96));
    receipt_field(&mut bytes, &count.to_be_bytes());
    for object_ref in object_set {
        receipt_field(&mut bytes, object_ref.to_string().as_bytes());
    }
    Ok(domain_digest(
        EXPLICIT_COMPOSITION_OBJECT_SET_DOMAIN,
        &bytes,
    ))
}

fn explicit_composition_authority_commitment(
    authority: &ContentManifestExplicitAuthority<'_>,
) -> Result<[u8; 32]> {
    validate_authority_set(authority)?;
    let object_set = explicit_composition_object_set_commitment(authority.object_set)?;
    let count = u64::try_from(authority.object_set.len()).map_err(|_| denied_error())?;
    let mut bytes = Vec::with_capacity(384);
    receipt_field(&mut bytes, authority.credentials.correlation_id.as_bytes());
    receipt_field(&mut bytes, authority.tenant_id.as_bytes());
    receipt_field(&mut bytes, authority.repository_id.as_bytes());
    receipt_field(&mut bytes, &count.to_be_bytes());
    receipt_field(&mut bytes, &object_set);
    receipt_field(&mut bytes, &authority.authorization_closure_digest);
    receipt_field(&mut bytes, &authority.identity_subject_digest);
    receipt_field(&mut bytes, &authority.production_subject_digest);
    receipt_field(&mut bytes, &authority.authority_epoch.to_be_bytes());
    receipt_field(&mut bytes, &authority.tenant_scope_digest);
    Ok(domain_digest(EXPLICIT_COMPOSITION_AUTHORITY_DOMAIN, &bytes))
}

fn explicit_composition_commit_target_commitment(
    request: &ContentManifestAvailabilityCommitRequest<'_>,
) -> Result<[u8; 32]> {
    let dependency_count = u64::try_from(request.dependencies.len()).map_err(|_| denied_error())?;
    let statement_digest = production_statement_digest(&request.production_statement)?;
    let mut bytes = Vec::with_capacity(512);
    receipt_field(&mut bytes, &request.opaque_key);
    receipt_field(&mut bytes, request.object_ref.to_string().as_bytes());
    receipt_field(&mut bytes, &request.length.to_be_bytes());
    receipt_field(&mut bytes, &request.expected_generation.to_be_bytes());
    receipt_field(&mut bytes, &request.authority_binding_digest);
    receipt_field(&mut bytes, &request.backend_receipt_digest);
    receipt_field(&mut bytes, &request.verification_receipt_digest);
    receipt_field(&mut bytes, &request.finalize_semantic_fingerprint);
    receipt_field(&mut bytes, &dependency_count.to_be_bytes());
    receipt_field(&mut bytes, &request.dependency_generation_set_digest);
    receipt_field(&mut bytes, &request.production_statement.manifest_sha256);
    receipt_field(&mut bytes, &statement_digest);
    Ok(domain_digest(
        EXPLICIT_COMPOSITION_COMMIT_TARGET_DOMAIN,
        &bytes,
    ))
}

fn explicit_composition_reconciliation_target_commitment(
    lookup: &ContentManifestCommittedProofLookup<'_>,
    expected_manifest_sha256: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(384);
    receipt_field(&mut bytes, &lookup.opaque_key);
    receipt_field(&mut bytes, lookup.object_ref.to_string().as_bytes());
    receipt_field(&mut bytes, &lookup.length.to_be_bytes());
    receipt_field(&mut bytes, &lookup.authority_binding_digest);
    receipt_field(&mut bytes, &lookup.backend_receipt_digest);
    receipt_field(&mut bytes, &lookup.finalize_semantic_fingerprint);
    receipt_field(&mut bytes, &expected_manifest_sha256);
    domain_digest(EXPLICIT_COMPOSITION_RECONCILIATION_TARGET_DOMAIN, &bytes)
}

fn composition_commit_receipt(
    commitments: ExplicitCompositionInputCommitments,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    proof: ContentManifestCommittedProof,
) -> Result<ContentManifestExplicitCompositionCommitReceipt> {
    if explicit_composition_authority_commitment(&request.authority)? != commitments.authority
        || explicit_composition_commit_target_commitment(request)? != commitments.target
    {
        return denied();
    }
    let expected_generation = request
        .expected_generation
        .checked_add(1)
        .ok_or_else(denied_error)?;
    if proof.tenant_id != request.authority.tenant_id
        || proof.repository_id != request.authority.repository_id
        || proof.object_ref != request.object_ref
        || proof.length != request.length
        || proof.generation != expected_generation
        || proof.authorization_closure_digest != request.authority.authorization_closure_digest
        || proof.authority_binding_digest != request.authority_binding_digest
        || proof.tenant_scope_digest != request.authority.tenant_scope_digest
        || proof.identity_subject_digest != request.authority.identity_subject_digest
        || proof.production_subject_digest != request.authority.production_subject_digest
        || proof.backend_receipt_digest != request.backend_receipt_digest
        || usize::from(proof.dependency_count) != request.dependencies.len()
        || proof.dependency_generation_set_digest != request.dependency_generation_set_digest
        || proof.verification_receipt_digest != request.verification_receipt_digest
        || proof.finalize_semantic_fingerprint != request.finalize_semantic_fingerprint
        || proof.production_statement != request.production_statement
        || proof.production_statement_digest
            != production_statement_digest(&request.production_statement)?
        || proof.proof_digest != committed_proof_digest(&proof)?
    {
        return denied();
    }
    let receipt_digest =
        explicit_composition_commit_receipt_digest(commitments, proof.proof_digest, proof.replayed);
    Ok(ContentManifestExplicitCompositionCommitReceipt {
        control_commitment: commitments.control,
        authority_commitment: commitments.authority,
        target_commitment: commitments.target,
        committed_proof_digest: proof.proof_digest,
        proof_replayed: proof.replayed,
        receipt_digest,
    })
}

fn explicit_composition_commit_receipt_digest(
    commitments: ExplicitCompositionInputCommitments,
    committed_proof_digest: [u8; 32],
    proof_replayed: bool,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(192);
    receipt_field(&mut bytes, &commitments.control);
    receipt_field(&mut bytes, &commitments.authority);
    receipt_field(&mut bytes, &commitments.target);
    receipt_field(&mut bytes, &committed_proof_digest);
    receipt_field(
        &mut bytes,
        if proof_replayed { b"replayed" } else { b"new" },
    );
    domain_digest(EXPLICIT_COMPOSITION_COMMIT_RECEIPT_DOMAIN, &bytes)
}

fn composition_reconciliation_receipt(
    commitments: ExplicitCompositionInputCommitments,
    lookup: &ContentManifestCommittedProofLookup<'_>,
    expected_manifest_sha256: [u8; 32],
    result: ContentManifestAvailabilityReconciliation,
) -> Result<ContentManifestExplicitCompositionReconciliationReceipt> {
    if explicit_composition_authority_commitment(&lookup.authority)? != commitments.authority
        || explicit_composition_reconciliation_target_commitment(lookup, expected_manifest_sha256)
            != commitments.target
    {
        return denied();
    }
    let (status, underlying_evidence_digest) = match result {
        ContentManifestAvailabilityReconciliation::Committed(proof) => {
            if !proof.replayed
                || proof.tenant_id != lookup.authority.tenant_id
                || proof.repository_id != lookup.authority.repository_id
                || proof.object_ref != lookup.object_ref
                || proof.length != lookup.length
                || proof.authorization_closure_digest
                    != lookup.authority.authorization_closure_digest
                || proof.authority_binding_digest != lookup.authority_binding_digest
                || proof.tenant_scope_digest != lookup.authority.tenant_scope_digest
                || proof.identity_subject_digest != lookup.authority.identity_subject_digest
                || proof.production_subject_digest != lookup.authority.production_subject_digest
                || proof.backend_receipt_digest != lookup.backend_receipt_digest
                || proof.finalize_semantic_fingerprint != lookup.finalize_semantic_fingerprint
                || proof.production_statement.manifest_sha256 != expected_manifest_sha256
                || proof.proof_digest != committed_proof_digest(&proof)?
            {
                return denied();
            }
            (
                ContentManifestExplicitCompositionReconciliationStatus::Committed,
                proof.proof_digest,
            )
        }
        ContentManifestAvailabilityReconciliation::UnknownRecovering { observation_digest } => (
            ContentManifestExplicitCompositionReconciliationStatus::UnknownRecovering,
            observation_digest,
        ),
    };
    let receipt_digest = explicit_composition_reconciliation_receipt_digest(
        commitments,
        status,
        underlying_evidence_digest,
    );
    Ok(ContentManifestExplicitCompositionReconciliationReceipt {
        status,
        control_commitment: commitments.control,
        authority_commitment: commitments.authority,
        target_commitment: commitments.target,
        underlying_evidence_digest,
        receipt_digest,
    })
}

fn explicit_composition_reconciliation_receipt_digest(
    commitments: ExplicitCompositionInputCommitments,
    status: ContentManifestExplicitCompositionReconciliationStatus,
    underlying_evidence_digest: [u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(192);
    receipt_field(&mut bytes, &commitments.control);
    receipt_field(&mut bytes, &commitments.authority);
    receipt_field(&mut bytes, &commitments.target);
    receipt_field(
        &mut bytes,
        match status {
            ContentManifestExplicitCompositionReconciliationStatus::Committed => b"committed",
            ContentManifestExplicitCompositionReconciliationStatus::UnknownRecovering => {
                b"unknown-recovering"
            }
        },
    );
    receipt_field(&mut bytes, &underlying_evidence_digest);
    domain_digest(EXPLICIT_COMPOSITION_RECONCILIATION_RECEIPT_DOMAIN, &bytes)
}

fn composition_database_now_unix_ms(transaction: &mut Transaction<'_>) -> Result<u64> {
    let value: i64 = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
            &[],
        )
        .map_err(database_error)?
        .get(0);
    u64::try_from(value).map_err(|_| denied_error())
}

fn reverify_composition_at_database_clock(
    verified: &NegotiationVerifiedMetadataRequest,
    keys: &MetadataNegotiationKeyRing,
    now_unix_ms: u64,
) -> Result<()> {
    verified
        .reverify_at(keys, now_unix_ms)
        .map_err(|_| denied_error())?;
    let now = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_millis(now_unix_ms))
        .ok_or_else(denied_error)?;
    if verified
        .request()
        .idempotency_reservation_at(now)
        .map_err(|_| denied_error())?
        .is_none()
    {
        return denied();
    }
    Ok(())
}

impl ContentManifestAvailabilityTransaction<'_> {
    pub fn apply(
        &mut self,
        request: &ContentManifestAvailabilityCommitRequest<'_>,
    ) -> Result<ContentManifestCommittedProof> {
        self.apply_inner(request, TransferFault::default())
    }

    #[cfg(feature = "legacy-test-adapter")]
    pub fn apply_with_fault_for_test(
        &mut self,
        request: &ContentManifestAvailabilityCommitRequest<'_>,
        boundary: ContentManifestAvailabilityFaultForTest,
    ) -> Result<ContentManifestCommittedProof> {
        self.apply_inner(
            request,
            TransferFault {
                boundary: Some(boundary),
            },
        )
    }

    fn apply_inner(
        &mut self,
        request: &ContentManifestAvailabilityCommitRequest<'_>,
        fault: TransferFault,
    ) -> Result<ContentManifestCommittedProof> {
        if self.state != BoundTransactionState::Ready {
            self.state = BoundTransactionState::Failed;
            return denied();
        }
        if validate_commit_request(request).is_err() {
            self.state = BoundTransactionState::Failed;
            return denied();
        }
        let Some(transaction) = self.transaction.as_mut() else {
            self.state = BoundTransactionState::Failed;
            return denied();
        };
        let result = commit_in_transaction(transaction, self.participant, request, fault);
        match result {
            Ok((mut proof, wrote)) => {
                proof.replayed = !wrote;
                self.state = BoundTransactionState::Applied;
                Ok(proof)
            }
            Err(_) => {
                self.state = BoundTransactionState::Failed;
                denied()
            }
        }
    }

    pub fn commit(mut self) -> Result<()> {
        if self.state != BoundTransactionState::Applied {
            let _ = self.transaction.take().map(Transaction::rollback);
            return denied();
        }
        self.transaction
            .take()
            .ok_or_else(denied_error)?
            .commit()
            .map_err(|_| denied_error())
    }

    pub fn rollback(mut self) -> Result<()> {
        self.transaction
            .take()
            .ok_or_else(denied_error)?
            .rollback()
            .map_err(|_| denied_error())
    }
}

// The cfg-neutral marker keeps the ordinary build free from public fault
// symbols while allowing one implementation of the boundary check.
#[derive(Clone, Copy)]
enum ContentManifestAvailabilityFaultForTestMarker {
    AfterAuthority,
    AfterApplication,
    AfterReceiptConsumption,
    AfterLifecycleCas,
    AfterFact,
    AfterProof,
    BeforeCommit,
    AfterCommitResponse,
    WrongReceiptContractAtSqlProofBoundary,
    WrongSharedContractAtSqlProofBoundary,
    WrongReceiptBindingAtSqlProofBoundary,
    WrongTenantScopeAtSqlProofBoundary,
    WrongFactOutboxAtSqlProofBoundary,
    NonCanonicalPageSplitAtSqlProofBoundary,
}

impl TransferFault {
    fn at(self, marker: ContentManifestAvailabilityFaultForTestMarker) -> bool {
        #[cfg(feature = "legacy-test-adapter")]
        {
            let expected = match marker {
                ContentManifestAvailabilityFaultForTestMarker::AfterAuthority => {
                    ContentManifestAvailabilityFaultForTest::AfterAuthority
                }
                ContentManifestAvailabilityFaultForTestMarker::AfterApplication => {
                    ContentManifestAvailabilityFaultForTest::AfterApplication
                }
                ContentManifestAvailabilityFaultForTestMarker::AfterReceiptConsumption => {
                    ContentManifestAvailabilityFaultForTest::AfterReceiptConsumption
                }
                ContentManifestAvailabilityFaultForTestMarker::AfterLifecycleCas => {
                    ContentManifestAvailabilityFaultForTest::AfterLifecycleCas
                }
                ContentManifestAvailabilityFaultForTestMarker::AfterFact => {
                    ContentManifestAvailabilityFaultForTest::AfterFact
                }
                ContentManifestAvailabilityFaultForTestMarker::AfterProof => {
                    ContentManifestAvailabilityFaultForTest::AfterProof
                }
                ContentManifestAvailabilityFaultForTestMarker::BeforeCommit => {
                    ContentManifestAvailabilityFaultForTest::BeforeCommit
                }
                ContentManifestAvailabilityFaultForTestMarker::AfterCommitResponse => {
                    ContentManifestAvailabilityFaultForTest::AfterCommitResponse
                }
                ContentManifestAvailabilityFaultForTestMarker::WrongReceiptContractAtSqlProofBoundary => {
                    ContentManifestAvailabilityFaultForTest::WrongReceiptContractAtSqlProofBoundary
                }
                ContentManifestAvailabilityFaultForTestMarker::WrongSharedContractAtSqlProofBoundary => {
                    ContentManifestAvailabilityFaultForTest::WrongSharedContractAtSqlProofBoundary
                }
                ContentManifestAvailabilityFaultForTestMarker::WrongReceiptBindingAtSqlProofBoundary => {
                    ContentManifestAvailabilityFaultForTest::WrongReceiptBindingAtSqlProofBoundary
                }
                ContentManifestAvailabilityFaultForTestMarker::WrongTenantScopeAtSqlProofBoundary => {
                    ContentManifestAvailabilityFaultForTest::WrongTenantScopeAtSqlProofBoundary
                }
                ContentManifestAvailabilityFaultForTestMarker::WrongFactOutboxAtSqlProofBoundary => {
                    ContentManifestAvailabilityFaultForTest::WrongFactOutboxAtSqlProofBoundary
                }
                ContentManifestAvailabilityFaultForTestMarker::NonCanonicalPageSplitAtSqlProofBoundary => {
                    ContentManifestAvailabilityFaultForTest::NonCanonicalPageSplitAtSqlProofBoundary
                }
            };
            self.boundary == Some(expected)
        }
        #[cfg(not(feature = "legacy-test-adapter"))]
        {
            let _ = marker;
            false
        }
    }
}

fn commit_in_transaction(
    transaction: &mut Transaction<'_>,
    participant: &PostgresTransactionAuthorizationParticipant,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    fault: TransferFault,
) -> Result<(ContentManifestCommittedProof, bool)> {
    let authorized = authorize_explicit_set(
        transaction,
        participant,
        &request.authority,
        request.object_ref,
    )?;
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::AfterAuthority,
    )?;

    let lookup = lookup_from_commit(request);
    if let Some(proof) = load_committed_proof(transaction, &lookup, false)? {
        let target_generation = request
            .expected_generation
            .checked_add(1)
            .ok_or_else(denied_error)?;
        if proof.generation != target_generation
            || proof.dependency_count as usize != request.dependencies.len()
            || proof.dependency_generation_set_digest != request.dependency_generation_set_digest
            || proof.verification_receipt_digest != request.verification_receipt_digest
            || proof.production_statement != request.production_statement
        {
            return denied();
        }
        return Ok((proof, false));
    }

    let locked = lock_exact_lifecycle_set(transaction, request)?;
    let dependency_digest = dependency_generation_set_digest(
        request.authority.tenant_id,
        request.authority.repository_id,
        &locked[1..],
    )?;
    if dependency_digest != request.dependency_generation_set_digest {
        return denied();
    }
    let command = lifecycle_command(request, authorized.primary_view()?)?;
    let application = write_lifecycle_application(transaction, &command, request, fault)?;
    let mut proof = committed_proof(request, &application, false)?;
    let outbox_event_id = proof_outbox_event(transaction, application.application_id)?;
    insert_proof(
        transaction,
        request,
        &proof,
        application.commit_sequence,
        outbox_event_id,
        fault,
    )?;
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::AfterProof,
    )?;
    append_decision_commitments(participant, transaction, &authorized, &proof, fault)?;
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::BeforeCommit,
    )?;
    proof.replayed = false;
    Ok((proof, true))
}

fn validate_commit_request(request: &ContentManifestAvailabilityCommitRequest<'_>) -> Result<()> {
    validate_authority(&request.authority, request.object_ref)?;
    let production_statement_digest = production_statement_digest(&request.production_statement)?;
    let expected_verification_receipt = lifecycle_verification_receipt_digest(
        request.authority.tenant_id,
        request.authority.repository_id,
        request.opaque_key,
        request.object_ref,
        request.expected_generation,
        request.authority_binding_digest,
        production_statement_digest,
    )?;
    if request.object_ref.kind != ObjectKind::ContentManifest
        || request.length > 67_108_864
        || request.expected_generation == 0
        || request.expected_generation >= crate::lifecycle::MAXIMUM_SAFE_GENERATION
        || !request
            .production_statement
            .is_valid_for(request.object_ref)
        || request.verification_receipt_digest != expected_verification_receipt
        || request.dependencies.len() + 1 != request.authority.object_set.len()
        || request.dependencies.len() >= CONTENT_MANIFEST_EXPLICIT_OBJECTS_MAXIMUM
        || request
            .dependencies
            .windows(2)
            .any(|pair| pair[0].opaque_key >= pair[1].opaque_key)
        || request.dependencies.iter().any(|dependency| {
            dependency.object_ref.kind != ObjectKind::Chunk
                || dependency.length == 0
                || dependency.length > 67_108_864
                || dependency.generation == 0
                || dependency.generation > crate::lifecycle::MAXIMUM_SAFE_GENERATION
                || dependency.opaque_key == request.opaque_key
        })
    {
        return denied();
    }
    let mut expected = request
        .dependencies
        .iter()
        .map(|dependency| dependency.object_ref)
        .chain(std::iter::once(request.object_ref))
        .collect::<Vec<_>>();
    expected.sort_by_key(ToString::to_string);
    if expected != request.authority.object_set {
        return denied();
    }
    let input_digest = dependency_generation_set_digest_from_input(request)?;
    if input_digest != request.dependency_generation_set_digest {
        return denied();
    }
    Ok(())
}

fn validate_lookup(lookup: &ContentManifestCommittedProofLookup<'_>) -> Result<()> {
    validate_authority(&lookup.authority, lookup.object_ref)?;
    if lookup.object_ref.kind != ObjectKind::ContentManifest || lookup.length > 67_108_864 {
        return denied();
    }
    Ok(())
}

fn validate_authority(
    authority: &ContentManifestExplicitAuthority<'_>,
    manifest: ObjectRef,
) -> Result<()> {
    validate_authority_set(authority)?;
    if !authority.object_set.contains(&manifest) {
        return denied();
    }
    Ok(())
}

fn validate_authority_set(authority: &ContentManifestExplicitAuthority<'_>) -> Result<()> {
    if authority.object_set.is_empty()
        || authority.object_set.len() > CONTENT_MANIFEST_EXPLICIT_OBJECTS_MAXIMUM
        || authority.authority_epoch == 0
        || authority.authority_epoch > crate::lifecycle::MAXIMUM_SAFE_GENERATION
        || authority
            .object_set
            .windows(2)
            .any(|pair| pair[0].to_string() >= pair[1].to_string())
        || authority.object_set.iter().any(|reference| {
            !matches!(
                reference.kind,
                ObjectKind::Chunk | ObjectKind::ContentManifest
            )
        })
        || authorization_closure_digest(authority.object_set)?
            != authority.authorization_closure_digest
    {
        return denied();
    }
    Ok(())
}

fn authorize_explicit_set(
    transaction: &mut Transaction<'_>,
    participant: &PostgresTransactionAuthorizationParticipant,
    authority: &ContentManifestExplicitAuthority<'_>,
    manifest: ObjectRef,
) -> Result<AuthorizedExplicitSet> {
    validate_authority(authority, manifest)?;
    let tenant = identity_tenant_id(authority.tenant_id);
    let repository = identity_repository_id(authority.repository_id);
    let resources = authority
        .object_set
        .iter()
        .map(|object_ref| IdentityAuthorizationResource {
            resource_type: "content".to_owned(),
            path: None,
            file_id: None,
            object_id: Some(object_ref.to_string()),
            name: None,
        })
        .collect::<Vec<_>>();
    let mut pages = Vec::with_capacity(resources.len().div_ceil(MAXIMUM_BATCH_RESOURCES));
    for page in resources.chunks(MAXIMUM_BATCH_RESOURCES) {
        let resource = page.first().ok_or_else(denied_error)?;
        let view = participant
            .authorize(
                transaction,
                &TransactionAuthorizationRequest {
                    request_id: authority.credentials.request_id,
                    credential_presentation: authority.credentials.credential_presentation,
                    tenant: &tenant,
                    repository: &repository,
                    permission: CONTENT_UPLOAD_PERMISSION,
                    reason: authority.credentials.reason,
                    resource,
                    reference: None,
                    snapshot: None,
                },
            )
            .map_err(|_| denied_error())?;
        if view.tenant() != tenant
            || view.repository() != repository
            || view.permission() != CONTENT_UPLOAD_PERMISSION
            || view.authority_epoch() != authority.authority_epoch
            || decode_identity_digest(view.subject_digest())? != authority.identity_subject_digest
        {
            poison_identity_transaction(transaction);
            return denied();
        }
        participant
            .recheck_batch(
                transaction,
                &view,
                &TransactionBatchRecheck {
                    tenant: &tenant,
                    repository: &repository,
                    permission: CONTENT_UPLOAD_PERMISSION,
                    reference: None,
                    resources: page,
                },
            )
            .map_err(|_| denied_error())?;
        pages.push(view);
    }
    Ok(AuthorizedExplicitSet { pages, resources })
}

fn lock_exact_lifecycle_set(
    transaction: &mut Transaction<'_>,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
) -> Result<Vec<LockedLifecycle>> {
    let mut opaque_keys = request
        .dependencies
        .iter()
        .map(|dependency| dependency.opaque_key)
        .chain(std::iter::once(request.opaque_key))
        .collect::<Vec<_>>();
    opaque_keys.sort();
    if opaque_keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return denied();
    }
    let key_bytes = opaque_keys
        .iter()
        .map(|key| key.to_vec())
        .collect::<Vec<_>>();
    let rows = transaction
        .query(
            "SELECT opaque_key, object_kind, object_digest, object_length,
                    tenant_scope_digest, state, generation, authority_binding_digest,
                    backend_receipt_digest, verification_receipt_digest,
                    deletion_receipt_digest
             FROM ogvcs_metadata.object_lifecycle
             WHERE tenant_id = $1 AND repository_id = $2 AND opaque_key = ANY($3)
             ORDER BY opaque_key
             FOR UPDATE",
            &[
                &uuid(request.authority.tenant_id),
                &uuid(request.authority.repository_id),
                &key_bytes,
            ],
        )
        .map_err(database_error)?;
    if rows.len() != opaque_keys.len() {
        return denied();
    }
    let mut locked = rows
        .iter()
        .map(locked_lifecycle)
        .collect::<Result<Vec<_>>>()?;
    if locked.iter().map(|row| row.opaque_key).collect::<Vec<_>>() != opaque_keys {
        return denied();
    }
    let manifest = locked
        .iter()
        .find(|row| row.opaque_key == request.opaque_key)
        .ok_or_else(denied_error)?;
    if manifest.object_ref != request.object_ref
        || manifest.length != request.length
        || manifest.tenant_scope_digest != request.authority.tenant_scope_digest
        || manifest.state != "staged"
        || manifest.generation != request.expected_generation
        || manifest.authority_binding_digest != request.authority_binding_digest
        || manifest.backend_receipt_digest.is_some()
        || manifest.verification_receipt_digest.is_some()
        || manifest.deletion_receipt_digest.is_some()
    {
        return denied();
    }
    for dependency in request.dependencies {
        let current = locked
            .iter()
            .find(|row| row.opaque_key == dependency.opaque_key)
            .ok_or_else(denied_error)?;
        if current.object_ref != dependency.object_ref
            || current.length != dependency.length
            || current.tenant_scope_digest != request.authority.tenant_scope_digest
            || current.state != "available"
            || current.generation != dependency.generation
            || current.authority_binding_digest != dependency.authority_binding_digest
            || current.backend_receipt_digest != Some(dependency.backend_receipt_digest)
            || current.verification_receipt_digest.is_some()
            || current.deletion_receipt_digest.is_some()
        {
            return denied();
        }
    }
    let manifest_index = locked
        .iter()
        .position(|row| row.opaque_key == request.opaque_key)
        .ok_or_else(denied_error)?;
    let manifest = locked.remove(manifest_index);
    locked.insert(0, manifest);
    Ok(locked)
}

fn locked_lifecycle(row: &Row) -> Result<LockedLifecycle> {
    Ok(LockedLifecycle {
        opaque_key: digest32(row.get(0))?,
        object_ref: object_ref(object_kind(row.get(1))?, row.get(2))?,
        length: positive_or_zero_u64(row.get(3))?,
        tenant_scope_digest: digest32(row.get(4))?,
        state: row.get(5),
        generation: positive_u64(row.get(6))?,
        authority_binding_digest: digest32(row.get(7))?,
        backend_receipt_digest: optional_digest32(row.get(8))?,
        verification_receipt_digest: optional_digest32(row.get(9))?,
        deletion_receipt_digest: optional_digest32(row.get(10))?,
    })
}

fn lifecycle_command(
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    view: &TransactionAuthorizedView,
) -> Result<LifecycleDirectCommand> {
    let now = SystemTime::now();
    let expires = now
        .checked_add(Duration::from_secs(3_600))
        .ok_or_else(denied_error)?;
    let issued_ms = unix_milliseconds(now)?;
    let expires_ms = unix_milliseconds(expires)?;
    let identity_scope = decode_identity_digest(view.authenticated_scope_digest())?;
    let idempotency_scope_digest = domain_digest(
        IDEMPOTENCY_SCOPE_DOMAIN,
        &[
            identity_scope.as_slice(),
            request.authority.authorization_closure_digest.as_slice(),
            request.opaque_key.as_slice(),
            request.finalize_semantic_fingerprint.as_slice(),
        ]
        .concat(),
    );
    let authority_contract_digest = domain_digest(
        EXPLICIT_AUTHORITY_DOMAIN,
        &[
            identity_scope.as_slice(),
            request.authority.authorization_closure_digest.as_slice(),
            request.authority.identity_subject_digest.as_slice(),
            request.authority.authority_epoch.to_be_bytes().as_slice(),
        ]
        .concat(),
    );
    let resource_opaque_digest = domain_digest(
        RESOURCE_OPAQUE_DOMAIN,
        &[
            request.authority.authorization_closure_digest.as_slice(),
            request.opaque_key.as_slice(),
        ]
        .concat(),
    );
    let idempotency = IdempotencyReservation {
        operation: LifecycleCapability::TransferRecordAvailable
            .operation()
            .to_owned(),
        key: format!(
            "ik1.{issued_ms}.{expires_ms}.{}",
            hex_bytes(&request.finalize_semantic_fingerprint)
        ),
        semantic_fingerprint: request.finalize_semantic_fingerprint,
        issued_at: now,
        expires_at: expires,
    };
    let lifecycle_transaction_digest = domain_digest(
        b"OGVCS-OBJECT-TRANSFER-MANIFEST-LIFECYCLE-TRANSACTION-V1",
        view.transaction_id().as_bytes(),
    );
    LifecycleDirectCommand::seal(
        format!(
            "ltx1.{}",
            URL_SAFE_NO_PAD.encode(lifecycle_transaction_digest)
        ),
        request.authority.tenant_id,
        request.authority.repository_id,
        request.authority.identity_subject_digest,
        request.authority.authority_epoch,
        LifecycleCapability::TransferRecordAvailable,
        authority_contract_digest,
        None,
        None,
        idempotency_scope_digest,
        idempotency,
        vec![LifecycleObjectBinding {
            opaque_key: request.opaque_key,
            object_ref: request.object_ref,
            expected_state: LifecycleState::Staged,
            expected_generation: request.expected_generation,
            expected_health: LifecycleHealth::NotApplicable,
            expected_health_generation: None,
            current_health_observation_digest: None,
            authority_binding_digest: request.authority_binding_digest,
            current_backend_receipt_digest: None,
            current_verification_receipt_digest: None,
            current_deletion_receipt_digest: None,
            transition_backend_receipt_digest: Some(request.backend_receipt_digest),
            transition_verification_receipt_digest: Some(request.verification_receipt_digest),
            transition_deletion_receipt_digest: None,
            resource_opaque_digest,
        }],
    )
}

fn write_lifecycle_application(
    transaction: &mut Transaction<'_>,
    command: &LifecycleDirectCommand,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    fault: TransferFault,
) -> Result<LifecycleApplicationReceipt> {
    if !command.integrity_valid()
        || command.capability != LifecycleCapability::TransferRecordAvailable
        || command.objects.len() != 1
    {
        return denied();
    }
    validate_transition_receipt(
        transaction,
        request,
        request.backend_receipt_digest,
        LifecycleReceiptKind::BackendDurable,
        fault,
    )?;
    validate_transition_receipt(
        transaction,
        request,
        request.verification_receipt_digest,
        LifecycleReceiptKind::ProductionVerification,
        fault,
    )?;
    let transaction_digest = domain_digest(
        b"OGVCS-LIFECYCLE-TRANSACTION-ID-V1",
        command.transaction_id.as_bytes(),
    );
    let lock_identity = format!(
        "lifecycle:{}:{}:{}",
        hex_bytes(&command.idempotency_scope_digest),
        command.capability.operation(),
        hex_bytes(&transaction_digest)
    );
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&lock_identity],
        )
        .map_err(database_error)?;
    let sequence = positive_u64(
        transaction
            .query_one(
                "UPDATE ogvcs_metadata.repository_commit_sequences
                 SET applied_sequence = applied_sequence + 1
                 WHERE repository_id = $1
                 RETURNING applied_sequence",
                &[&uuid(command.repository_id)],
            )
            .map_err(database_error)?
            .get(0),
    )?;
    let application_id = random_public_uuid()?;
    let audit_correlation_id = random_public_uuid()?;
    let outbox_event_id = random_public_uuid()?;
    let object = &command.objects[0];
    let next_generation = object
        .expected_generation
        .checked_add(1)
        .ok_or_else(denied_error)?;
    let fact_digest = protected_fact_digest(
        command,
        object,
        LifecycleState::Available,
        next_generation,
        Some(request.verification_receipt_digest),
    );
    let protected_result_digest = domain_digest(
        b"OGVCS-LIFECYCLE-DIRECT-PROTECTED-RESULT-V1",
        &[
            fact_digest.as_slice(),
            audit_correlation_id.as_slice(),
            outbox_event_id.as_slice(),
        ]
        .concat(),
    );
    let receipt_digest = application_receipt_digest(
        application_id,
        command.repository_id,
        sequence,
        command.capability,
        command.lifecycle_plan_digest,
        1,
        protected_result_digest,
    );
    let application_contract_digest = if fault
        .at(ContentManifestAvailabilityFaultForTestMarker::WrongSharedContractAtSqlProofBoundary)
    {
        [0x53; 32]
    } else {
        lifecycle_contract_digest()
    };
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_applications
             (application_id, receipt_kind, receipt_digest, application_kind,
              capability, operation, transaction_id, transaction_id_digest, plan_id,
              tenant_id, repository_id, subject_digest, authorization_epoch,
              context_digest, authority_contract_digest, lifecycle_contract_digest,
              candidate_digest, publication_kind, publication_digest, root_proof_digest,
              lifecycle_plan_digest, idempotency_scope_digest, idempotency_operation,
              idempotency_key, semantic_fingerprint, object_count,
              protected_result_digest, commit_sequence)
             VALUES ($1, 'ogvcs.lifecycle-application/v1', $2, 'direct', $3, $4,
                     $5, $6, NULL, $7, $8, $9, $10, $11, $12, $13,
                     NULL, NULL, NULL, NULL, $14, $15, $16, $17, $18, 1, $19, $20)",
            &[
                &Uuid::from_bytes(application_id),
                &&receipt_digest[..],
                &command.capability.as_str(),
                &command.capability.operation(),
                &command.transaction_id,
                &&transaction_digest[..],
                &uuid(command.tenant_id),
                &uuid(command.repository_id),
                &&command.subject_digest[..],
                &(command.authorization_epoch as i64),
                &&command.context_digest[..],
                &&command.authority_contract_digest[..],
                &&application_contract_digest[..],
                &&command.lifecycle_plan_digest[..],
                &&command.idempotency_scope_digest[..],
                &command.idempotency.operation,
                &command.idempotency.key,
                &&command.idempotency.semantic_fingerprint[..],
                &&protected_result_digest[..],
                &(sequence as i64),
            ],
        )
        .map_err(database_error)?;
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::AfterApplication,
    )?;
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_receipt_consumptions
             (receipt_digest, receipt_kind, repository_id, opaque_key, purpose,
              expected_generation, application_id)
             VALUES ($1, 'production-verification', $2, $3,
                     'content-manifest-availability', $4, $5)",
            &[
                &&request.verification_receipt_digest[..],
                &uuid(command.repository_id),
                &&request.opaque_key[..],
                &(request.expected_generation as i64),
                &Uuid::from_bytes(application_id),
            ],
        )
        .map_err(database_error)?;
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::AfterReceiptConsumption,
    )?;
    let updated = transaction
        .execute(
            "UPDATE ogvcs_metadata.object_lifecycle
             SET state = 'available', generation = $6, health = 'not-applicable',
                 health_generation = NULL, health_observation_digest = NULL,
                 backend_receipt_digest = $7, verification_receipt_digest = $8,
                 deletion_receipt_digest = NULL, last_application_id = $9,
                 last_commit_sequence = $10, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND repository_id = $2 AND opaque_key = $3
               AND object_kind = 2 AND object_digest = $4
               AND state = 'staged' AND generation = $5
               AND authority_binding_digest = $11
               AND backend_receipt_digest IS NULL
               AND verification_receipt_digest IS NULL
               AND deletion_receipt_digest IS NULL",
            &[
                &uuid(command.tenant_id),
                &uuid(command.repository_id),
                &&request.opaque_key[..],
                &&request.object_ref.digest[..],
                &(request.expected_generation as i64),
                &(next_generation as i64),
                &&request.backend_receipt_digest[..],
                &&request.verification_receipt_digest[..],
                &Uuid::from_bytes(application_id),
                &(sequence as i64),
                &&request.authority_binding_digest[..],
            ],
        )
        .map_err(database_error)?;
    if updated != 1 {
        return denied();
    }
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::AfterLifecycleCas,
    )?;
    let fact_outbox_event_id = if fault
        .at(ContentManifestAvailabilityFaultForTestMarker::WrongFactOutboxAtSqlProofBoundary)
    {
        random_public_uuid()?
    } else {
        outbox_event_id
    };
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_transaction_facts
             (application_id, fact_ordinal, resource_opaque_digest, opaque_key,
              object_kind, object_digest, prior_state, prior_generation,
              next_state, next_generation, health_generation, reachability_recorded,
              receipt_digest, result_class, fact_digest, audit_correlation_id,
              outbox_event_id)
             VALUES ($1, 0, $2, $3, 2, $4, 'staged', $5, 'available', $6,
                     NULL, false, $7, 'availability-recorded', $8, $9, $10)",
            &[
                &Uuid::from_bytes(application_id),
                &&object.resource_opaque_digest[..],
                &&object.opaque_key[..],
                &&object.object_ref.digest[..],
                &(object.expected_generation as i64),
                &(next_generation as i64),
                &&request.verification_receipt_digest[..],
                &&fact_digest[..],
                &Uuid::from_bytes(audit_correlation_id),
                &Uuid::from_bytes(fact_outbox_event_id),
            ],
        )
        .map_err(database_error)?;
    transaction
        .execute(
            "INSERT INTO ogvcs_metadata.lifecycle_internal_outbox
             (event_id, application_id, fact_ordinal, aggregate_event,
              protected_fact_digest)
             VALUES ($1, $2, 0, false, $3)",
            &[
                &Uuid::from_bytes(outbox_event_id),
                &Uuid::from_bytes(application_id),
                &&fact_digest[..],
            ],
        )
        .map_err(database_error)?;
    fail_at(
        fault,
        ContentManifestAvailabilityFaultForTestMarker::AfterFact,
    )?;
    Ok(LifecycleApplicationReceipt {
        application_id,
        receipt_digest,
        commit_sequence: sequence,
        object_count: 1,
        protected_result_digest,
    })
}

fn validate_transition_receipt(
    transaction: &mut Transaction<'_>,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    receipt: [u8; 32],
    kind: LifecycleReceiptKind,
    fault: TransferFault,
) -> Result<()> {
    let expected_contract = if fault
        .at(ContentManifestAvailabilityFaultForTestMarker::WrongReceiptContractAtSqlProofBoundary)
        || fault.at(
            ContentManifestAvailabilityFaultForTestMarker::WrongSharedContractAtSqlProofBoundary,
        ) {
        None
    } else {
        Some(lifecycle_contract_digest().to_vec())
    };
    let exists: bool = transaction
        .query_one(
            "SELECT EXISTS (
                SELECT 1 FROM ogvcs_metadata.lifecycle_receipts
                WHERE receipt_digest = $1 AND receipt_kind = $2
                  AND tenant_id = $3 AND repository_id = $4 AND opaque_key = $5
                  AND object_kind = 2 AND object_digest = $6
                  AND expected_state = 'staged' AND expected_generation = $7
                  AND target_state = 'available' AND target_generation = $8
                  AND authority_binding_digest = $9
                  AND ($10::bytea IS NULL OR lifecycle_contract_digest = $10))",
            &[
                &&receipt[..],
                &kind.as_str(),
                &uuid(request.authority.tenant_id),
                &uuid(request.authority.repository_id),
                &&request.opaque_key[..],
                &&request.object_ref.digest[..],
                &(request.expected_generation as i64),
                &((request.expected_generation + 1) as i64),
                &&request.authority_binding_digest[..],
                &expected_contract,
            ],
        )
        .map_err(database_error)?
        .get(0);
    if exists {
        Ok(())
    } else {
        denied()
    }
}

fn committed_proof(
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    application: &LifecycleApplicationReceipt,
    replayed: bool,
) -> Result<ContentManifestCommittedProof> {
    let production_statement_digest = production_statement_digest(&request.production_statement)?;
    let mut proof = ContentManifestCommittedProof {
        application_id: application.application_id,
        tenant_id: request.authority.tenant_id,
        repository_id: request.authority.repository_id,
        opaque_key: request.opaque_key,
        object_ref: request.object_ref,
        length: request.length,
        generation: request.expected_generation + 1,
        authorization_closure_digest: request.authority.authorization_closure_digest,
        authority_binding_digest: request.authority_binding_digest,
        tenant_scope_digest: request.authority.tenant_scope_digest,
        identity_subject_digest: request.authority.identity_subject_digest,
        production_subject_digest: request.authority.production_subject_digest,
        backend_receipt_digest: request.backend_receipt_digest,
        dependency_count: request.dependencies.len() as u16,
        dependency_generation_set_digest: request.dependency_generation_set_digest,
        verification_receipt_digest: request.verification_receipt_digest,
        finalize_semantic_fingerprint: request.finalize_semantic_fingerprint,
        production_statement: request.production_statement.clone(),
        production_statement_digest,
        proof_digest: [0; 32],
        replayed,
    };
    proof.proof_digest = committed_proof_digest(&proof)?;
    Ok(proof)
}

fn insert_proof(
    transaction: &mut Transaction<'_>,
    request: &ContentManifestAvailabilityCommitRequest<'_>,
    proof: &ContentManifestCommittedProof,
    commit_sequence: u64,
    outbox_event_id: [u8; 16],
    fault: TransferFault,
) -> Result<()> {
    let mut stored_production_statement_digest = proof.production_statement_digest;
    if fault
        .at(ContentManifestAvailabilityFaultForTestMarker::WrongReceiptBindingAtSqlProofBoundary)
    {
        stored_production_statement_digest[0] ^= 0x80;
    }
    let mut stored_tenant_scope_digest = proof.tenant_scope_digest;
    if fault.at(ContentManifestAvailabilityFaultForTestMarker::WrongTenantScopeAtSqlProofBoundary) {
        stored_tenant_scope_digest[0] ^= 0x80;
    }
    let inserted = transaction
        .execute(
            "INSERT INTO ogvcs_metadata.content_manifest_availability_proofs
             (application_id, fact_ordinal, proof_schema, tenant_id, repository_id,
              opaque_key, object_kind, object_digest, object_length, lifecycle_state,
              expected_generation, lifecycle_generation, commit_sequence,
              authorization_closure_digest, authority_binding_digest, tenant_scope_digest,
              identity_subject_digest, production_subject_digest,
              authorization_epoch, authorization_page_count,
              backend_receipt_digest, verification_receipt_digest,
              finalize_semantic_fingerprint, dependency_count,
              dependency_generation_set_digest, statement_boundary,
              statement_logical_bytes, statement_manifest_sha256, statement_profile,
              statement_verifier, statement_whole_file_sha256,
              production_statement_digest, proof_digest, outbox_event_id)
             VALUES ($1, 0, $2, $3, $4, $5, 2, $6, $7, 'available', $8, $9,
                     $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
                     $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31)",
            &[
                &Uuid::from_bytes(proof.application_id),
                &COMMITTED_PROOF_SCHEMA,
                &uuid(proof.tenant_id),
                &uuid(proof.repository_id),
                &&proof.opaque_key[..],
                &&proof.object_ref.digest[..],
                &(proof.length as i64),
                &(request.expected_generation as i64),
                &(proof.generation as i64),
                &(commit_sequence as i64),
                &&proof.authorization_closure_digest[..],
                &&proof.authority_binding_digest[..],
                &&stored_tenant_scope_digest[..],
                &&proof.identity_subject_digest[..],
                &&proof.production_subject_digest[..],
                &(request.authority.authority_epoch as i64),
                &(request
                    .authority
                    .object_set
                    .len()
                    .div_ceil(MAXIMUM_BATCH_RESOURCES) as i16),
                &&proof.backend_receipt_digest[..],
                &&proof.verification_receipt_digest[..],
                &&proof.finalize_semantic_fingerprint[..],
                &(proof.dependency_count as i32),
                &&proof.dependency_generation_set_digest[..],
                &proof.production_statement.boundary,
                &(proof.production_statement.logical_bytes as i64),
                &&proof.production_statement.manifest_sha256[..],
                &proof.production_statement.profile,
                &proof.production_statement.verifier,
                &&proof.production_statement.whole_file_sha256[..],
                &&stored_production_statement_digest[..],
                &&proof.proof_digest[..],
                &Uuid::from_bytes(outbox_event_id),
            ],
        )
        .map_err(database_error)?;
    if inserted == 1 {
        Ok(())
    } else {
        denied()
    }
}

fn load_committed_proof(
    transaction: &mut Transaction<'_>,
    lookup: &ContentManifestCommittedProofLookup<'_>,
    replayed: bool,
) -> Result<Option<ContentManifestCommittedProof>> {
    let row = transaction
        .query_opt(
            "SELECT proof.application_id, proof.tenant_id, proof.repository_id,
                    proof.opaque_key, proof.object_kind, proof.object_digest,
                    proof.object_length, proof.lifecycle_generation,
                    proof.authorization_closure_digest, proof.authority_binding_digest,
                    proof.tenant_scope_digest, proof.identity_subject_digest,
                    proof.production_subject_digest,
                    proof.backend_receipt_digest, proof.dependency_count,
                    proof.dependency_generation_set_digest,
                    proof.verification_receipt_digest,
                    proof.finalize_semantic_fingerprint, proof.statement_boundary,
                    proof.statement_logical_bytes, proof.statement_manifest_sha256,
                    proof.statement_profile, proof.statement_verifier,
                    proof.statement_whole_file_sha256,
                    proof.production_statement_digest, proof.proof_digest
                    , proof.authorization_epoch
             FROM ogvcs_metadata.content_manifest_availability_proofs AS proof
             JOIN ogvcs_metadata.object_lifecycle AS lifecycle
               ON lifecycle.repository_id = proof.repository_id
              AND lifecycle.opaque_key = proof.opaque_key
              AND lifecycle.object_length = proof.object_length
              AND lifecycle.tenant_scope_digest = proof.tenant_scope_digest
              AND lifecycle.state = 'available'
              AND lifecycle.generation = proof.lifecycle_generation
              AND lifecycle.last_application_id = proof.application_id
              AND lifecycle.backend_receipt_digest = proof.backend_receipt_digest
              AND lifecycle.verification_receipt_digest = proof.verification_receipt_digest
             WHERE proof.tenant_id = $1 AND proof.repository_id = $2
               AND proof.opaque_key = $3",
            &[
                &uuid(lookup.authority.tenant_id),
                &uuid(lookup.authority.repository_id),
                &&lookup.opaque_key[..],
            ],
        )
        .map_err(database_error)?;
    let Some(row) = row else { return Ok(None) };
    let application_uuid: Uuid = row.get(0);
    let tenant_uuid: Uuid = row.get(1);
    let repository_uuid: Uuid = row.get(2);
    let object_ref = object_ref(object_kind(row.get(4))?, row.get(5))?;
    let stored_authorization_epoch = positive_u64(row.get(26))?;
    let mut proof = ContentManifestCommittedProof {
        application_id: *application_uuid.as_bytes(),
        tenant_id: TenantId::from_bytes(*tenant_uuid.as_bytes()),
        repository_id: RepositoryId::from_bytes(*repository_uuid.as_bytes()),
        opaque_key: digest32(row.get(3))?,
        object_ref,
        length: positive_or_zero_u64(row.get(6))?,
        generation: positive_u64(row.get(7))?,
        authorization_closure_digest: digest32(row.get(8))?,
        authority_binding_digest: digest32(row.get(9))?,
        tenant_scope_digest: digest32(row.get(10))?,
        identity_subject_digest: digest32(row.get(11))?,
        production_subject_digest: digest32(row.get(12))?,
        backend_receipt_digest: digest32(row.get(13))?,
        dependency_count: u16::try_from(row.get::<_, i32>(14)).map_err(|_| denied_error())?,
        dependency_generation_set_digest: digest32(row.get(15))?,
        verification_receipt_digest: digest32(row.get(16))?,
        finalize_semantic_fingerprint: digest32(row.get(17))?,
        production_statement: ContentManifestProductionStatement {
            boundary: row.get(18),
            logical_bytes: positive_or_zero_u64(row.get(19))?,
            manifest_object_id: object_ref,
            manifest_sha256: digest32(row.get(20))?,
            profile: row.get(21),
            verifier: row.get(22),
            whole_file_sha256: digest32(row.get(23))?,
        },
        production_statement_digest: digest32(row.get(24))?,
        proof_digest: digest32(row.get(25))?,
        replayed,
    };
    if proof.tenant_id != lookup.authority.tenant_id
        || proof.repository_id != lookup.authority.repository_id
        || proof.opaque_key != lookup.opaque_key
        || proof.object_ref != lookup.object_ref
        || proof.length != lookup.length
        || proof.authorization_closure_digest != lookup.authority.authorization_closure_digest
        || proof.authority_binding_digest != lookup.authority_binding_digest
        || proof.tenant_scope_digest != lookup.authority.tenant_scope_digest
        || proof.identity_subject_digest != lookup.authority.identity_subject_digest
        || proof.production_subject_digest != lookup.authority.production_subject_digest
        || stored_authorization_epoch != lookup.authority.authority_epoch
        || proof.backend_receipt_digest != lookup.backend_receipt_digest
        || proof.finalize_semantic_fingerprint != lookup.finalize_semantic_fingerprint
        || !proof.production_statement.is_valid_for(proof.object_ref)
        || production_statement_digest(&proof.production_statement)?
            != proof.production_statement_digest
        || lifecycle_verification_receipt_digest(
            proof.tenant_id,
            proof.repository_id,
            proof.opaque_key,
            proof.object_ref,
            proof.generation.checked_sub(1).ok_or_else(denied_error)?,
            proof.authority_binding_digest,
            proof.production_statement_digest,
        )? != proof.verification_receipt_digest
        || committed_proof_digest(&proof)? != proof.proof_digest
    {
        return denied();
    }
    proof.replayed = replayed;
    Ok(Some(proof))
}

fn proof_outbox_event(
    transaction: &mut Transaction<'_>,
    application_id: [u8; 16],
) -> Result<[u8; 16]> {
    let value: Uuid = transaction
        .query_one(
            "SELECT event_id FROM ogvcs_metadata.lifecycle_internal_outbox
             WHERE application_id = $1 AND fact_ordinal = 0 AND NOT aggregate_event",
            &[&Uuid::from_bytes(application_id)],
        )
        .map_err(database_error)?
        .get(0);
    Ok(*value.as_bytes())
}

fn append_decision_commitments(
    participant: &PostgresTransactionAuthorizationParticipant,
    transaction: &mut Transaction<'_>,
    authorized: &AuthorizedExplicitSet,
    proof: &ContentManifestCommittedProof,
    fault: TransferFault,
) -> Result<()> {
    let tenant = identity_tenant_id(proof.tenant_id);
    let repository = identity_repository_id(proof.repository_id);
    let page_count = authorized.resources.len().div_ceil(MAXIMUM_BATCH_RESOURCES);
    if page_count != authorized.pages.len() {
        return denied();
    }
    for (index, (page, view)) in authorized
        .resources
        .chunks(MAXIMUM_BATCH_RESOURCES)
        .zip(&authorized.pages)
        .enumerate()
    {
        let resource_count =
            noncanonical_resource_count_for_test(fault, index, page_count, page.len())?;
        let correlation = decision_correlation(proof.proof_digest, index as u32);
        let result = json!({
            "schemaVersion": "ogvcs.object-transfer/content-manifest-private-decision/v1",
            "result": "available",
            "applicationId": Uuid::from_bytes(proof.application_id).to_string(),
            "proofSha256": hex_bytes(&proof.proof_digest),
            "authorizationClosureSha256": hex_bytes(&proof.authorization_closure_digest),
            "pageIndex": index,
            "pageCount": page_count,
        });
        let commitment = participant
            .append_decision_commitment(
                transaction,
                view,
                &DecisionCommitmentRequest {
                    correlation_id: &correlation,
                    tenant: &tenant,
                    repository: &repository,
                    permission: CONTENT_UPLOAD_PERMISSION,
                    reference: None,
                    resources: page,
                    result: &result,
                },
            )
            .map_err(|_| denied_error())?;
        let inserted = transaction
            .execute(
                "INSERT INTO ogvcs_metadata.content_manifest_availability_authorization_pages
                 (application_id, page_ordinal, page_count, resource_count,
                  transaction_id, correlation_id, commitment_id, authority_epoch,
                  decision_digest, resource_set_digest, result_digest, record_hash)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                &[
                    &Uuid::from_bytes(proof.application_id),
                    &(index as i16),
                    &(page_count as i16),
                    &(resource_count as i32),
                    &commitment.transaction_id(),
                    &commitment.correlation_id(),
                    &commitment.commitment_id(),
                    &(commitment.authority_epoch() as i64),
                    &&decode_identity_digest(commitment.decision_digest())?[..],
                    &&decode_identity_digest(commitment.resource_set_digest())?[..],
                    &&decode_identity_digest(commitment.result_digest())?[..],
                    &&decode_identity_digest(commitment.record_hash())?[..],
                ],
            )
            .map_err(database_error)?;
        if inserted != 1 {
            return denied();
        }
    }
    Ok(())
}

fn noncanonical_resource_count_for_test(
    fault: TransferFault,
    page_index: usize,
    page_count: usize,
    actual: usize,
) -> Result<usize> {
    if !fault
        .at(ContentManifestAvailabilityFaultForTestMarker::NonCanonicalPageSplitAtSqlProofBoundary)
    {
        return Ok(actual);
    }
    if page_count < 2 {
        return denied();
    }
    if page_index == 0 {
        actual.checked_sub(1).ok_or_else(denied_error)
    } else if page_index + 1 == page_count {
        actual.checked_add(1).ok_or_else(denied_error)
    } else {
        Ok(actual)
    }
}

fn decision_correlation(proof_digest: [u8; 32], page: u32) -> String {
    let digest = domain_digest(
        DECISION_CORRELATION_DOMAIN,
        &[proof_digest.as_slice(), page.to_be_bytes().as_slice()].concat(),
    );
    format!("transfer.{}", hex_bytes(&digest))
}

fn lookup_from_commit<'a>(
    request: &'a ContentManifestAvailabilityCommitRequest<'a>,
) -> ContentManifestCommittedProofLookup<'a> {
    ContentManifestCommittedProofLookup {
        authority: request.authority,
        opaque_key: request.opaque_key,
        object_ref: request.object_ref,
        length: request.length,
        authority_binding_digest: request.authority_binding_digest,
        backend_receipt_digest: request.backend_receipt_digest,
        finalize_semantic_fingerprint: request.finalize_semantic_fingerprint,
    }
}

fn authorization_closure_digest(object_set: &[ObjectRef]) -> Result<[u8; 32]> {
    let object_ids = object_set
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let bytes = canonical_json_bytes(&json!({
        "objectIds": object_ids,
        "requestRoot": Value::Null,
    }))?;
    Ok(domain_digest(AUTHORIZATION_CLOSURE_DOMAIN, &bytes))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DependencyCurrentJson {
    #[serde(rename = "schemaVersion")]
    schema_version: &'static str,
    tenant_id: String,
    repository_id: String,
    opaque_key: String,
    object_id: String,
    length: u64,
    state: &'static str,
    generation: u64,
    authority_binding_sha256: String,
    backend_receipt_sha256: String,
    durable_backend_receipt_sha256: String,
    verification_receipt_sha256: Option<String>,
}

fn dependency_generation_set_digest(
    tenant_id: TenantId,
    repository_id: RepositoryId,
    dependencies: &[LockedLifecycle],
) -> Result<[u8; 32]> {
    let values = dependencies
        .iter()
        .map(|dependency| {
            let backend_receipt = dependency.backend_receipt_digest.ok_or_else(denied_error)?;
            Ok(DependencyCurrentJson {
                schema_version: "ogvcs.object-transfer/content-manifest-current-object/v1",
                tenant_id: uuid(tenant_id).to_string(),
                repository_id: uuid(repository_id).to_string(),
                opaque_key: hex_bytes(&dependency.opaque_key),
                object_id: dependency.object_ref.to_string(),
                length: dependency.length,
                state: "available",
                generation: dependency.generation,
                authority_binding_sha256: hex_bytes(&dependency.authority_binding_digest),
                backend_receipt_sha256: hex_bytes(&backend_receipt),
                durable_backend_receipt_sha256: hex_bytes(&backend_receipt),
                verification_receipt_sha256: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    dependency_generation_digest_json(&values)
}

fn dependency_generation_set_digest_from_input(
    request: &ContentManifestAvailabilityCommitRequest<'_>,
) -> Result<[u8; 32]> {
    let values = request
        .dependencies
        .iter()
        .map(|dependency| DependencyCurrentJson {
            schema_version: "ogvcs.object-transfer/content-manifest-current-object/v1",
            tenant_id: uuid(request.authority.tenant_id).to_string(),
            repository_id: uuid(request.authority.repository_id).to_string(),
            opaque_key: hex_bytes(&dependency.opaque_key),
            object_id: dependency.object_ref.to_string(),
            length: dependency.length,
            state: "available",
            generation: dependency.generation,
            authority_binding_sha256: hex_bytes(&dependency.authority_binding_digest),
            backend_receipt_sha256: hex_bytes(&dependency.backend_receipt_digest),
            durable_backend_receipt_sha256: hex_bytes(&dependency.backend_receipt_digest),
            verification_receipt_sha256: None,
        })
        .collect::<Vec<_>>();
    dependency_generation_digest_json(&values)
}

fn dependency_generation_digest_json(values: &[DependencyCurrentJson]) -> Result<[u8; 32]> {
    let count = u32::try_from(values.len()).map_err(|_| denied_error())?;
    let mut digest = Sha256::new();
    digest.update(DEPENDENCY_GENERATIONS_DOMAIN);
    digest.update(count.to_be_bytes());
    for value in values {
        let encoded = canonical_json_bytes(value)?;
        let length = u32::try_from(encoded.len()).map_err(|_| denied_error())?;
        digest.update(length.to_be_bytes());
        digest.update(encoded);
    }
    Ok(digest.finalize().into())
}

fn production_statement_value(statement: &ContentManifestProductionStatement) -> Value {
    json!({
        "boundary": statement.boundary,
        "logicalBytes": statement.logical_bytes.to_string(),
        "manifestObjectId": statement.manifest_object_id.to_string(),
        "manifestSha256": hex_bytes(&statement.manifest_sha256),
        "profile": statement.profile,
        "verifier": statement.verifier,
        "wholeFileSha256": hex_bytes(&statement.whole_file_sha256),
    })
}

fn production_statement_digest(statement: &ContentManifestProductionStatement) -> Result<[u8; 32]> {
    let bytes = canonical_json_bytes(&production_statement_value(statement))?;
    Ok(domain_digest(PRODUCTION_STATEMENT_DOMAIN, &bytes))
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
) -> Result<[u8; 32]> {
    let target_generation = expected_generation
        .checked_add(1)
        .filter(|generation| *generation <= crate::lifecycle::MAXIMUM_SAFE_GENERATION)
        .ok_or_else(denied_error)?;
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
    receipt_field(&mut bytes, &target_generation.to_be_bytes());
    receipt_field(&mut bytes, &authority_binding_digest);
    receipt_field(&mut bytes, &production_statement_digest);
    Ok(domain_digest(LIFECYCLE_VERIFICATION_RECEIPT_DOMAIN, &bytes))
}

fn receipt_field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn committed_proof_value(proof: &ContentManifestCommittedProof) -> Value {
    json!({
        "schemaVersion": COMMITTED_PROOF_SCHEMA,
        "applicationId": Uuid::from_bytes(proof.application_id).to_string(),
        "tenantId": uuid(proof.tenant_id).to_string(),
        "repositoryId": uuid(proof.repository_id).to_string(),
        "opaqueKey": hex_bytes(&proof.opaque_key),
        "objectId": proof.object_ref.to_string(),
        "length": proof.length,
        "state": "available",
        "generation": proof.generation,
        "authorizationClosureSha256": hex_bytes(&proof.authorization_closure_digest),
        "authorityBindingSha256": hex_bytes(&proof.authority_binding_digest),
        "tenantScopeSha256": hex_bytes(&proof.tenant_scope_digest),
        "subjectDigestSha256": hex_bytes(&proof.production_subject_digest),
        "backendReceiptSha256": hex_bytes(&proof.backend_receipt_digest),
        "dependencyCount": proof.dependency_count,
        "dependencyGenerationSetSha256": hex_bytes(&proof.dependency_generation_set_digest),
        "verificationReceiptSha256": hex_bytes(&proof.verification_receipt_digest),
        "finalizeSemanticFingerprint": hex_bytes(&proof.finalize_semantic_fingerprint),
        "productionStatement": production_statement_value(&proof.production_statement),
        "productionStatementSha256": hex_bytes(&proof.production_statement_digest),
    })
}

fn committed_proof_digest(proof: &ContentManifestCommittedProof) -> Result<[u8; 32]> {
    let bytes = canonical_json_bytes(&committed_proof_value(proof))?;
    Ok(domain_digest(COMMITTED_PROOF_DOMAIN, &bytes))
}

fn reconciliation_observation_digest(
    lookup: &ContentManifestCommittedProofLookup<'_>,
    view: &TransactionAuthorizedView,
) -> Result<[u8; 32]> {
    let bytes = canonical_json_bytes(&json!({
        "tenantId": uuid(lookup.authority.tenant_id).to_string(),
        "repositoryId": uuid(lookup.authority.repository_id).to_string(),
        "opaqueKey": hex_bytes(&lookup.opaque_key),
        "objectId": lookup.object_ref.to_string(),
        "length": lookup.length,
        "authorizationClosureSha256": hex_bytes(&lookup.authority.authorization_closure_digest),
        "authorityEpoch": view.authority_epoch(),
        "authorityBindingSha256": hex_bytes(&lookup.authority_binding_digest),
        "tenantScopeSha256": hex_bytes(&lookup.authority.tenant_scope_digest),
        "identitySubjectSha256": hex_bytes(&lookup.authority.identity_subject_digest),
        "productionSubjectSha256": hex_bytes(&lookup.authority.production_subject_digest),
        "backendReceiptSha256": hex_bytes(&lookup.backend_receipt_digest),
        "finalizeSemanticFingerprint": hex_bytes(&lookup.finalize_semantic_fingerprint),
    }))?;
    Ok(domain_digest(RECONCILIATION_OBSERVATION_DOMAIN, &bytes))
}

fn unix_milliseconds(value: SystemTime) -> Result<u64> {
    value
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(denied_error)
}

fn positive_or_zero_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| denied_error())
}

fn digest32(value: Vec<u8>) -> Result<[u8; 32]> {
    value.try_into().map_err(|_| denied_error())
}

fn optional_digest32(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    value.map(digest32).transpose()
}

fn denied<T>() -> Result<T> {
    Err(denied_error())
}

fn denied_error() -> DomainError {
    DomainError::new(DomainErrorCode::MetadataNotFoundOrDenied)
}

fn fail_at(
    fault: TransferFault,
    marker: ContentManifestAvailabilityFaultForTestMarker,
) -> Result<()> {
    if fault.at(marker) {
        denied()
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MetadataNegotiationPrincipal, MetadataOperationRequest, METADATA_SERVICE_REQUEST_SCHEMA,
        OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256,
    };
    use hmac::{Hmac, Mac};

    fn reference(kind: ObjectKind, byte: u8) -> ObjectRef {
        ObjectRef {
            kind,
            digest: [byte; 32],
        }
    }

    fn id(value: &str) -> [u8; 16] {
        *Uuid::parse_str(value).unwrap().as_bytes()
    }

    fn digest(value: &str) -> [u8; 32] {
        decode_identity_digest(value).unwrap()
    }

    #[test]
    fn digests_match_independent_javascript_known_answers() {
        let tenant_id = TenantId::from_bytes(id("11111111-1111-4111-8111-111111111111"));
        let repository_id = RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222222"));
        let chunk = ObjectRef {
            kind: ObjectKind::Chunk,
            digest: digest("7f61171100c2f32c713016b92f8dad057703ce9853029a67a0913647fbdd34c4"),
        };
        let manifest = ObjectRef {
            kind: ObjectKind::ContentManifest,
            digest: digest("6e0acb8f9543ea98c64bd11b0dcd6decdc446cc52bf44dd3a75ecbadc973b382"),
        };
        let object_set = [chunk, manifest];
        let closure = authorization_closure_digest(&object_set).unwrap();
        assert_eq!(
            closure,
            digest("0888671dd3f318f53cd5d99436afa1d11b45044cc7466ec91708b41f7c8393b1")
        );

        let dependencies = [LockedLifecycle {
            opaque_key: [0x11; 32],
            object_ref: chunk,
            length: 56,
            tenant_scope_digest: [0xbb; 32],
            state: "available".to_owned(),
            generation: 2,
            authority_binding_digest: [0x44; 32],
            backend_receipt_digest: Some([0x55; 32]),
            verification_receipt_digest: None,
            deletion_receipt_digest: None,
        }];
        let dependency_digest =
            dependency_generation_set_digest(tenant_id, repository_id, &dependencies).unwrap();
        assert_eq!(
            dependency_digest,
            digest("62e0656ff0e697c7e5cf3d80302ad979bdefbe5adb05c6191d29cbc1bcd7077e")
        );

        let statement = ContentManifestProductionStatement {
            boundary: CONTENT_MANIFEST_PRODUCTION_BOUNDARY.to_owned(),
            logical_bytes: 56,
            manifest_object_id: manifest,
            manifest_sha256: digest(
                "ac762d7f4130ce05b17dfaacea1e9204c1485fa939e7c61c1a04daa90dc19a33",
            ),
            profile: CONTENT_MANIFEST_PRODUCTION_PROFILE.to_owned(),
            verifier: CONTENT_MANIFEST_PRODUCTION_VERIFIER.to_owned(),
            whole_file_sha256: digest(
                "26a4fd74c5f94f41b20cfe2a4cb486bffb6be3e016caf45c8fad50e50d1c780c",
            ),
        };
        assert_ne!(statement.manifest_sha256, manifest.digest);
        assert!(statement.is_valid_for(manifest));
        let statement_digest = production_statement_digest(&statement).unwrap();
        assert_eq!(
            statement_digest,
            digest("9458069ee34f5018b7bf74eb354ca59e078a3e6e10b0dc869e490a27148e32dd")
        );
        let verification_receipt_digest = lifecycle_verification_receipt_digest(
            tenant_id,
            repository_id,
            [0x33; 32],
            manifest,
            3,
            [0xaa; 32],
            statement_digest,
        )
        .unwrap();
        assert_eq!(
            verification_receipt_digest,
            digest("4e941cced00b6fe3bb7a1855b37ac0b165a045e5f3285f6ed061700f4ace0a3d")
        );
        assert_eq!(
            lifecycle_verification_receipt_digest(
                tenant_id,
                repository_id,
                [0x33; 32],
                manifest,
                3,
                [0xaa; 32],
                statement_digest,
            )
            .unwrap(),
            verification_receipt_digest,
            "an exact retry retains one deterministic one-use receipt identity"
        );
        let mut hostile_statement_digest = statement_digest;
        hostile_statement_digest[0] ^= 0x80;
        let mut hostile_authority = [0xaa; 32];
        hostile_authority[0] ^= 0x80;
        for hostile in [
            lifecycle_verification_receipt_digest(
                tenant_id,
                RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222223")),
                [0x33; 32],
                manifest,
                3,
                [0xaa; 32],
                statement_digest,
            )
            .unwrap(),
            lifecycle_verification_receipt_digest(
                tenant_id,
                repository_id,
                [0x33; 32],
                manifest,
                4,
                [0xaa; 32],
                statement_digest,
            )
            .unwrap(),
            lifecycle_verification_receipt_digest(
                tenant_id,
                repository_id,
                [0x33; 32],
                manifest,
                3,
                hostile_authority,
                statement_digest,
            )
            .unwrap(),
            lifecycle_verification_receipt_digest(
                tenant_id,
                repository_id,
                [0x33; 32],
                manifest,
                3,
                [0xaa; 32],
                hostile_statement_digest,
            )
            .unwrap(),
            lifecycle_verification_receipt_digest(
                tenant_id,
                repository_id,
                [0x33; 32],
                reference(ObjectKind::ContentManifest, 0x6f),
                3,
                [0xaa; 32],
                statement_digest,
            )
            .unwrap(),
        ] {
            assert_ne!(hostile, verification_receipt_digest);
        }
        let mut proof = ContentManifestCommittedProof {
            application_id: id("33333333-3333-4333-8333-333333333333"),
            tenant_id,
            repository_id,
            opaque_key: [0x33; 32],
            object_ref: manifest,
            length: 141,
            generation: 4,
            authorization_closure_digest: closure,
            authority_binding_digest: [0xaa; 32],
            tenant_scope_digest: [0xbb; 32],
            identity_subject_digest: digest(
                "96aea37fc72fab80a8bc28f168001b237a20fd85b3e4a948ad73800852456eb5",
            ),
            production_subject_digest: digest(
                "90c0f1f509b03d44c9014f03aefd489ac58f2020891f4ea70cec5e567638ba1b",
            ),
            backend_receipt_digest: [0xee; 32],
            dependency_count: 1,
            dependency_generation_set_digest: dependency_digest,
            verification_receipt_digest,
            finalize_semantic_fingerprint: [0xff; 32],
            production_statement: statement,
            production_statement_digest: statement_digest,
            proof_digest: [0; 32],
            replayed: false,
        };
        assert_ne!(
            proof.identity_subject_digest, proof.production_subject_digest,
            "OGVCS-009 identity and object-transfer production subject are separate bindings"
        );
        proof.proof_digest = committed_proof_digest(&proof).unwrap();
        assert_eq!(
            proof.proof_digest,
            digest("3aa67a120438b8c5d35c87d838b1464a452dcfb8698f2368fdd9dc775b6ad6d2")
        );
    }

    #[test]
    fn explicit_authority_is_sorted_unique_route_less_and_bounded() {
        assert_eq!(MAXIMUM_BATCH_RESOURCES, 1_000);
        let mut maximum = (0_u32..4_095)
            .map(|index| {
                let mut digest = [0; 32];
                digest[28..].copy_from_slice(&index.to_be_bytes());
                ObjectRef {
                    kind: ObjectKind::Chunk,
                    digest,
                }
            })
            .collect::<Vec<_>>();
        let manifest = reference(ObjectKind::ContentManifest, 0xfe);
        maximum.push(manifest);
        let closure = authorization_closure_digest(&maximum).unwrap();
        let authority = ContentManifestExplicitAuthority {
            credentials: TransactionCredentialRequest {
                request_id: "request",
                correlation_id: "correlation",
                credential_presentation: "credential",
                reason: None,
            },
            tenant_id: TenantId::from_bytes(id("11111111-1111-4111-8111-111111111111")),
            repository_id: RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222222")),
            object_set: &maximum,
            identity_subject_digest: [3; 32],
            production_subject_digest: [5; 32],
            authority_epoch: 1,
            authorization_closure_digest: closure,
            tenant_scope_digest: [4; 32],
        };
        assert!(validate_authority(&authority, manifest).is_ok());

        let mut over = maximum.clone();
        over.insert(4_095, reference(ObjectKind::Chunk, 0xff));
        let over_authority = ContentManifestExplicitAuthority {
            object_set: &over,
            authorization_closure_digest: [0; 32],
            ..authority
        };
        assert_eq!(
            validate_authority(&over_authority, manifest)
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );

        let mut unsorted = maximum[..3].to_vec();
        unsorted.swap(0, 1);
        let unsorted_authority = ContentManifestExplicitAuthority {
            object_set: &unsorted,
            authorization_closure_digest: authorization_closure_digest(&unsorted).unwrap(),
            ..authority
        };
        assert_eq!(
            validate_authority(&unsorted_authority, unsorted[0])
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );
    }

    #[test]
    fn composition_brand_is_instance_exact_and_unforgeable_by_shape() {
        let first = ExplicitCompositionBrand::new();
        let second = ExplicitCompositionBrand::new();
        let cross_instance = first.bind(7_u8);
        assert_eq!(
            second.take(cross_instance).unwrap_err().code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );
        let forged = BrandedComposition {
            origin: Arc::new(()),
            value: 9_u8,
        };
        assert_eq!(
            first.take(forged).unwrap_err().code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );
        assert_eq!(first.take(first.bind(11_u8)).unwrap(), 11);
    }

    #[test]
    fn composition_binds_exact_public_facts_without_registering_a_route() {
        let tenant = TenantId::from_bytes(id("11111111-1111-4111-8111-111111111111"));
        let repository = RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222222"));
        let manifest = reference(ObjectKind::ContentManifest, 0x61);
        let object_set = [manifest];
        let identity_subject = [0x31; 32];
        let manifest_sha256 = [0x41; 32];
        let authority = authority(
            tenant,
            repository,
            &object_set,
            identity_subject,
            7,
            "composition-correlation-0001",
        );
        let verified = verified_object_put(
            tenant,
            repository,
            identity_subject,
            7,
            "composition-correlation-0001",
            manifest,
            141,
            manifest_sha256,
        );
        validate_composition_control(&verified, &authority, manifest, 141, manifest_sha256)
            .unwrap();
        let keys =
            MetadataNegotiationKeyRing::new(vec![("composition-key@1".to_owned(), vec![0x5a; 32])])
                .unwrap();
        reverify_composition_at_database_clock(&verified, &keys, 1_500).unwrap();
        assert_eq!(
            reverify_composition_at_database_clock(&verified, &keys, 2_000)
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied,
            "the public mutation idempotency window must be current at the database clock"
        );
        assert!(
            !MetadataOperation::ObjectPut
                .transport_descriptor()
                .network_registered
        );
        assert_eq!(crate::network_transport_descriptors().count(), 0);
    }

    #[test]
    fn composition_rejects_principal_scope_and_explicit_set_substitution() {
        let tenant = TenantId::from_bytes(id("11111111-1111-4111-8111-111111111111"));
        let other_tenant = TenantId::from_bytes(id("11111111-1111-4111-8111-111111111112"));
        let repository = RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222222"));
        let other_repository = RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222223"));
        let manifest = reference(ObjectKind::ContentManifest, 0x61);
        let object_set = [manifest];
        let identity_subject = [0x31; 32];
        let manifest_sha256 = [0x41; 32];
        let exact = authority(
            tenant,
            repository,
            &object_set,
            identity_subject,
            7,
            "composition-correlation-0001",
        );
        let denied = |verified: NegotiationVerifiedMetadataRequest,
                      authority: &ContentManifestExplicitAuthority<'_>| {
            assert_eq!(
                validate_composition_control(&verified, authority, manifest, 141, manifest_sha256,)
                    .unwrap_err()
                    .code,
                DomainErrorCode::MetadataNotFoundOrDenied
            );
        };

        denied(
            verified_object_put(
                tenant,
                repository,
                [0x32; 32],
                7,
                "composition-correlation-0001",
                manifest,
                141,
                manifest_sha256,
            ),
            &exact,
        );
        denied(
            verified_object_put(
                other_tenant,
                repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                manifest,
                141,
                manifest_sha256,
            ),
            &exact,
        );
        denied(
            verified_object_put(
                tenant,
                other_repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                manifest,
                141,
                manifest_sha256,
            ),
            &exact,
        );
        denied(
            verified_object_put(
                tenant,
                repository,
                identity_subject,
                8,
                "composition-correlation-0001",
                manifest,
                141,
                manifest_sha256,
            ),
            &exact,
        );

        let wrong_correlation = ContentManifestExplicitAuthority {
            credentials: TransactionCredentialRequest {
                correlation_id: "composition-correlation-0002",
                ..exact.credentials
            },
            ..exact
        };
        denied(
            verified_object_put(
                tenant,
                repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                manifest,
                141,
                manifest_sha256,
            ),
            &wrong_correlation,
        );

        denied(
            verified_object_put(
                tenant,
                repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                reference(ObjectKind::ContentManifest, 0x62),
                141,
                manifest_sha256,
            ),
            &exact,
        );
        denied(
            verified_object_put(
                tenant,
                repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                manifest,
                142,
                manifest_sha256,
            ),
            &exact,
        );
        denied(
            verified_object_put(
                tenant,
                repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                manifest,
                141,
                [0x42; 32],
            ),
            &exact,
        );

        let substituted_set = [reference(ObjectKind::Chunk, 0x01), manifest];
        let substituted = ContentManifestExplicitAuthority {
            object_set: &substituted_set,
            authorization_closure_digest: exact.authorization_closure_digest,
            ..exact
        };
        denied(
            verified_object_put(
                tenant,
                repository,
                identity_subject,
                7,
                "composition-correlation-0001",
                manifest,
                141,
                manifest_sha256,
            ),
            &substituted,
        );
    }

    #[test]
    fn composition_outputs_bind_post_call_evidence_and_redact_debug() {
        let tenant = TenantId::from_bytes(id("11111111-1111-4111-8111-111111111111"));
        let repository = RepositoryId::from_bytes(id("22222222-2222-4222-8222-222222222222"));
        let chunk = reference(ObjectKind::Chunk, 0x21);
        let manifest = reference(ObjectKind::ContentManifest, 0x61);
        let object_set = [chunk, manifest];
        let identity_subject = [0x31; 32];
        let manifest_sha256 = [0x41; 32];
        let exact_authority = authority(
            tenant,
            repository,
            &object_set,
            identity_subject,
            7,
            "composition-correlation-0001",
        );
        let verified = verified_object_put(
            tenant,
            repository,
            identity_subject,
            7,
            "composition-correlation-0001",
            manifest,
            141,
            manifest_sha256,
        );
        let dependencies = [ContentManifestDependencyBinding {
            opaque_key: [0x11; 32],
            object_ref: chunk,
            length: 56,
            generation: 2,
            authority_binding_digest: [0x44; 32],
            backend_receipt_digest: [0x55; 32],
        }];
        let request = composition_commit_request(
            exact_authority,
            &dependencies,
            manifest,
            141,
            manifest_sha256,
        );
        validate_commit_request(&request).unwrap();
        let commitments = commit_composition_input_commitments(&verified, &request).unwrap();
        let proof = composition_proof(&request, false);
        let proof_digest = proof.proof_digest;
        let commit_receipt = composition_commit_receipt(commitments, &request, proof).unwrap();
        assert!(!commit_receipt.proof_replayed());
        assert_eq!(commit_receipt.committed_proof_sha256(), &proof_digest);

        let lookup = lookup_from_commit(&request);
        let reconciliation_commitments =
            reconciliation_composition_input_commitments(&verified, &lookup, manifest_sha256)
                .unwrap();
        let unknown_observation = [0x91; 32];
        let unknown_receipt = composition_reconciliation_receipt(
            reconciliation_commitments,
            &lookup,
            manifest_sha256,
            ContentManifestAvailabilityReconciliation::UnknownRecovering {
                observation_digest: unknown_observation,
            },
        )
        .unwrap();
        assert_eq!(
            unknown_receipt.status(),
            ContentManifestExplicitCompositionReconciliationStatus::UnknownRecovering
        );
        assert_eq!(
            unknown_receipt.underlying_evidence_sha256(),
            &unknown_observation
        );

        let committed_receipt = composition_reconciliation_receipt(
            reconciliation_commitments,
            &lookup,
            manifest_sha256,
            ContentManifestAvailabilityReconciliation::Committed(Box::new(composition_proof(
                &request, true,
            ))),
        )
        .unwrap();
        assert_eq!(
            committed_receipt.status(),
            ContentManifestExplicitCompositionReconciliationStatus::Committed
        );

        let known_answers = [
            hex_bytes(commit_receipt.control_commitment_sha256()),
            hex_bytes(commit_receipt.authority_commitment_sha256()),
            hex_bytes(commit_receipt.target_commitment_sha256()),
            hex_bytes(commit_receipt.receipt_sha256()),
            hex_bytes(unknown_receipt.target_commitment_sha256()),
            hex_bytes(unknown_receipt.receipt_sha256()),
            hex_bytes(committed_receipt.receipt_sha256()),
        ];
        assert_eq!(
            known_answers,
            [
                "c56a0bdc2560bfb33fe9331f8055f9b9ed824dec644672d9a9a537e3ce494347",
                "79396991108969a477a4a38189378c45fa9da7711bf34f667a6af3644153c63b",
                "9bbd0645b3a8f218779b9696c20f54fa6e3fdec7281bcca5b911461454224361",
                "abb5bd04ebf35a619d01f9c315b2cabaa8824128488e288388fbd496a272cb74",
                "62c00a55eeced1d47ac6c9217890c50fd563e10593198f1f82ed097bf27cecde",
                "bd338ed0d35452b819e48ab578e0f6aef3aedf773d16eb539f8af5a3858dbb26",
                "a83d9bdb2e64068ef76c22a447ac9bafc05e34dd8c700a9abaf559f89cb2cb30",
            ],
            "freeze deterministic composition commitments and receipts"
        );

        for rendered in [
            format!("{commit_receipt:?}"),
            format!("{unknown_receipt:?}"),
            format!("{committed_receipt:?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains(&known_answers[0]));
            assert!(!rendered.contains(&known_answers[3]));
            assert!(!rendered.contains(&hex_bytes(&proof_digest)));
            assert!(!rendered.contains(&hex_bytes(&unknown_observation)));
        }

        let changed_correlation = verified_object_put(
            tenant,
            repository,
            identity_subject,
            7,
            "composition-correlation-0002",
            manifest,
            141,
            manifest_sha256,
        );
        let changed_semantics = verified_object_put(
            tenant,
            repository,
            identity_subject,
            7,
            "composition-correlation-0001",
            manifest,
            142,
            manifest_sha256,
        );
        let changed_negotiation = verified_object_put_with_session(
            tenant,
            repository,
            identity_subject,
            7,
            "composition-correlation-0001",
            manifest,
            141,
            manifest_sha256,
            "composition-session-0002",
        );
        for hostile_control in [
            explicit_composition_control_commitment(&changed_correlation).unwrap(),
            explicit_composition_control_commitment(&changed_semantics).unwrap(),
            explicit_composition_control_commitment(&changed_negotiation).unwrap(),
        ] {
            assert_ne!(hostile_control, commitments.control);
            let hostile = ExplicitCompositionInputCommitments {
                control: hostile_control,
                ..commitments
            };
            assert_ne!(
                explicit_composition_commit_receipt_digest(hostile, proof_digest, false),
                *commit_receipt.receipt_sha256()
            );
            assert_ne!(
                explicit_composition_reconciliation_receipt_digest(
                    hostile,
                    ContentManifestExplicitCompositionReconciliationStatus::UnknownRecovering,
                    unknown_observation,
                ),
                *unknown_receipt.receipt_sha256()
            );
        }

        let substituted_set = [reference(ObjectKind::Chunk, 0x01), chunk, manifest];
        let substituted_authority = authority(
            tenant,
            repository,
            &substituted_set,
            identity_subject,
            7,
            "composition-correlation-0001",
        );
        let hostile_authority =
            explicit_composition_authority_commitment(&substituted_authority).unwrap();
        assert_ne!(hostile_authority, commitments.authority);
        assert_ne!(
            explicit_composition_commit_receipt_digest(
                ExplicitCompositionInputCommitments {
                    authority: hostile_authority,
                    ..commitments
                },
                proof_digest,
                false,
            ),
            *commit_receipt.receipt_sha256()
        );

        let hostile_request =
            composition_commit_request(exact_authority, &dependencies, manifest, 141, [0x42; 32]);
        let hostile_length_request = composition_commit_request(
            exact_authority,
            &dependencies,
            manifest,
            142,
            manifest_sha256,
        );
        let hostile_manifest_request = composition_commit_request(
            exact_authority,
            &dependencies,
            reference(ObjectKind::ContentManifest, 0x62),
            141,
            manifest_sha256,
        );
        for hostile_target in [
            explicit_composition_commit_target_commitment(&hostile_request).unwrap(),
            explicit_composition_commit_target_commitment(&hostile_length_request).unwrap(),
            explicit_composition_commit_target_commitment(&hostile_manifest_request).unwrap(),
        ] {
            assert_ne!(hostile_target, commitments.target);
        }
        for hostile_lookup in [
            lookup_from_commit(&hostile_length_request),
            lookup_from_commit(&hostile_manifest_request),
        ] {
            assert_ne!(
                explicit_composition_reconciliation_target_commitment(
                    &hostile_lookup,
                    manifest_sha256,
                ),
                reconciliation_commitments.target
            );
        }
        assert_eq!(
            composition_reconciliation_receipt(
                reconciliation_commitments,
                &lookup,
                [0x42; 32],
                ContentManifestAvailabilityReconciliation::UnknownRecovering {
                    observation_digest: unknown_observation,
                },
            )
            .unwrap_err()
            .code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );

        let mut substituted_proof = composition_proof(&request, false);
        substituted_proof.length += 1;
        substituted_proof.proof_digest = committed_proof_digest(&substituted_proof).unwrap();
        assert_eq!(
            composition_commit_receipt(commitments, &request, substituted_proof)
                .unwrap_err()
                .code,
            DomainErrorCode::MetadataNotFoundOrDenied
        );
        assert_ne!(
            explicit_composition_reconciliation_receipt_digest(
                reconciliation_commitments,
                ContentManifestExplicitCompositionReconciliationStatus::UnknownRecovering,
                [0x92; 32],
            ),
            *unknown_receipt.receipt_sha256(),
            "unknown recovery must bind the exact authorized observation"
        );
    }

    fn composition_commit_request<'a>(
        authority: ContentManifestExplicitAuthority<'a>,
        dependencies: &'a [ContentManifestDependencyBinding],
        manifest: ObjectRef,
        length: u64,
        manifest_sha256: [u8; 32],
    ) -> ContentManifestAvailabilityCommitRequest<'a> {
        let production_statement = ContentManifestProductionStatement {
            boundary: CONTENT_MANIFEST_PRODUCTION_BOUNDARY.to_owned(),
            logical_bytes: 56,
            manifest_object_id: manifest,
            manifest_sha256,
            profile: CONTENT_MANIFEST_PRODUCTION_PROFILE.to_owned(),
            verifier: CONTENT_MANIFEST_PRODUCTION_VERIFIER.to_owned(),
            whole_file_sha256: [0x71; 32],
        };
        let production_statement_digest =
            production_statement_digest(&production_statement).unwrap();
        let verification_receipt_digest = lifecycle_verification_receipt_digest(
            authority.tenant_id,
            authority.repository_id,
            [0x33; 32],
            manifest,
            3,
            [0xaa; 32],
            production_statement_digest,
        )
        .unwrap();
        let mut request = ContentManifestAvailabilityCommitRequest {
            authority,
            opaque_key: [0x33; 32],
            object_ref: manifest,
            length,
            expected_generation: 3,
            authority_binding_digest: [0xaa; 32],
            backend_receipt_digest: [0xee; 32],
            verification_receipt_digest,
            finalize_semantic_fingerprint: [0xff; 32],
            dependencies,
            dependency_generation_set_digest: [0; 32],
            production_statement,
        };
        request.dependency_generation_set_digest =
            dependency_generation_set_digest_from_input(&request).unwrap();
        request
    }

    fn composition_proof(
        request: &ContentManifestAvailabilityCommitRequest<'_>,
        replayed: bool,
    ) -> ContentManifestCommittedProof {
        let mut proof = ContentManifestCommittedProof {
            application_id: id("33333333-3333-4333-8333-333333333333"),
            tenant_id: request.authority.tenant_id,
            repository_id: request.authority.repository_id,
            opaque_key: request.opaque_key,
            object_ref: request.object_ref,
            length: request.length,
            generation: request.expected_generation + 1,
            authorization_closure_digest: request.authority.authorization_closure_digest,
            authority_binding_digest: request.authority_binding_digest,
            tenant_scope_digest: request.authority.tenant_scope_digest,
            identity_subject_digest: request.authority.identity_subject_digest,
            production_subject_digest: request.authority.production_subject_digest,
            backend_receipt_digest: request.backend_receipt_digest,
            dependency_count: u16::try_from(request.dependencies.len()).unwrap(),
            dependency_generation_set_digest: request.dependency_generation_set_digest,
            verification_receipt_digest: request.verification_receipt_digest,
            finalize_semantic_fingerprint: request.finalize_semantic_fingerprint,
            production_statement: request.production_statement.clone(),
            production_statement_digest: production_statement_digest(&request.production_statement)
                .unwrap(),
            proof_digest: [0; 32],
            replayed,
        };
        proof.proof_digest = committed_proof_digest(&proof).unwrap();
        proof
    }

    fn authority<'a>(
        tenant_id: TenantId,
        repository_id: RepositoryId,
        object_set: &'a [ObjectRef],
        identity_subject_digest: [u8; 32],
        authority_epoch: u64,
        correlation_id: &'a str,
    ) -> ContentManifestExplicitAuthority<'a> {
        ContentManifestExplicitAuthority {
            credentials: TransactionCredentialRequest {
                request_id: correlation_id,
                correlation_id,
                credential_presentation: "credential-presentation",
                reason: None,
            },
            tenant_id,
            repository_id,
            object_set,
            identity_subject_digest,
            production_subject_digest: [0x51; 32],
            authority_epoch,
            authorization_closure_digest: authorization_closure_digest(object_set).unwrap(),
            tenant_scope_digest: [0x61; 32],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_object_put(
        tenant_id: TenantId,
        repository_id: RepositoryId,
        subject_digest: [u8; 32],
        authority_epoch: u64,
        correlation_id: &str,
        manifest: ObjectRef,
        length: u64,
        manifest_sha256: [u8; 32],
    ) -> NegotiationVerifiedMetadataRequest {
        verified_object_put_with_session(
            tenant_id,
            repository_id,
            subject_digest,
            authority_epoch,
            correlation_id,
            manifest,
            length,
            manifest_sha256,
            "composition-session-0001",
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verified_object_put_with_session(
        tenant_id: TenantId,
        repository_id: RepositoryId,
        subject_digest: [u8; 32],
        authority_epoch: u64,
        correlation_id: &str,
        manifest: ObjectRef,
        length: u64,
        manifest_sha256: [u8; 32],
        session_id: &str,
    ) -> NegotiationVerifiedMetadataRequest {
        let key = [0x5a; 32];
        let claims = json!({
            "schemaVersion": "ogvcs.protocol/negotiation-receipt-claims/v1",
            "selection": negotiation_selection(),
            "subjectDigest": hex_bytes(&subject_digest),
            "tenantDigest": hex_bytes(&metadata_negotiation_tenant_digest(tenant_id)),
            "authorityEpoch": authority_epoch,
            "sessionId": session_id,
            "clientNonce": "AAAAAAAAAAAAAAAAAAAAAA",
            "serverNonce": "AQEBAQEBAQEBAQEBAQEBAQ",
            "issuedAtUnixMs": 1_000,
            "expiresAtUnixMs": 301_000,
        });
        let mut receipt = json!({
            "algorithm": "HMAC-SHA-256",
            "keyId": "composition-key@1",
            "claims": claims,
            "mac": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        });
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(b"OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\0");
        mac.update(b"composition-key@1\0");
        mac.update(&canonical_json_bytes(&receipt["claims"]).unwrap());
        receipt["mac"] = Value::String(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));

        let body = json!({
            "tenantId": uuid(tenant_id).to_string(),
            "repositoryId": uuid(repository_id).to_string(),
            "objectRef": manifest.to_string(),
            "canonicalByteLength": length,
            "streamDigestSha256": hex_bytes(&manifest_sha256),
        });
        let extensions = json!({});
        let projection = json!({
            "schemaVersion": METADATA_SERVICE_REQUEST_SCHEMA,
            "operation": CONTENT_MANIFEST_EXPLICIT_COMPOSITION_OPERATION,
            "body": body,
            "extensions": extensions,
        });
        let mut fingerprint = Sha256::new();
        fingerprint.update(b"ogvcs.protocol/idempotency/v1\0");
        fingerprint.update(canonical_json_bytes(&projection).unwrap());
        let fingerprint: [u8; 32] = fingerprint.finalize().into();
        let request = json!({
            "schemaVersion": METADATA_SERVICE_REQUEST_SCHEMA,
            "operation": CONTENT_MANIFEST_EXPLICIT_COMPOSITION_OPERATION,
            "correlationId": correlation_id,
            "negotiationReceipt": receipt,
            "idempotency": {
                "key": "ik1.1000.2000.AAAAAAAAAAAAAAAAAAAAAA",
                "algorithm": "OGVCS-SEMANTIC-JCS-SHA-256",
                "projectionVersion": "ogvcs.protocol/fingerprint-projection@1",
                "fingerprint": hex_bytes(&fingerprint),
                "issuedAtUnixMs": 1_000,
                "expiresAtUnixMs": 2_000,
            },
            "body": body,
            "extensions": extensions,
        });
        let parsed = MetadataOperationRequest::parse(&serde_json::to_vec(&request).unwrap())
            .unwrap_or_else(|error| panic!("composition request parse failed: {error:?}"));
        let keys =
            MetadataNegotiationKeyRing::new(vec![("composition-key@1".to_owned(), key.to_vec())])
                .unwrap();
        parsed
            .verify_negotiation(
                &keys,
                &MetadataNegotiationPrincipal {
                    subject_digest,
                    tenant_digest: metadata_negotiation_tenant_digest(tenant_id),
                    authority_epoch,
                    session_id: session_id.to_owned(),
                    now_unix_ms: 1_500,
                },
            )
            .unwrap()
    }

    fn negotiation_selection() -> Value {
        json!({
            "schemaVersion": "ogvcs.protocol/negotiation-selection/v1",
            "protocolVersion": "ogvcs.control.https-json@1",
            "messageSchemaVersion": "ogvcs.protocol.schema@1",
            "repositoryFormat": "ogvcs.repository-format@1",
            "authorizationContract": "ogvcs.authorization@1",
            "authorizationRegistrySha256": "293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc",
            "pathContract": "ogvcs.path-filesystem@1",
            "pathProfile": "path.opengamevcs/portable@1",
            "pathRegistrySha256": "bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42",
            "eventVersion": "ogvcs.events.base@1",
            "transferProfile": "ogvcs.transfer.range-resume-probe@1",
            "extensions": [],
            "protocolRegistrySetSha256": OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256,
            "repositoryRegistrySha256": "6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6",
        })
    }
}
