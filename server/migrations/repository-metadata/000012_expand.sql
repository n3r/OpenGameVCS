BEGIN;

-- Freeze this additive candidate against the exact v11 authority. The
-- migration runner verifies every predecessor too; this fence prevents a
-- standalone migration host from attaching transfer proof rows to a
-- different lifecycle schema.
DO $ogvcs$
BEGIN
    IF (
        SELECT count(*)
        FROM ogvcs_metadata.schema_migrations
        WHERE version = 11
          AND state = 'completed'
          AND (
              (phase = 'expand' AND checksum_sha256 =
                  'ba12a576e2a186e75becb51773e9f9c4322c41f37e115546c31eb29776463f3f')
              OR (phase = 'migrate' AND checksum_sha256 =
                  '2f9e6d1c74b5bd58f42cd004db6e8547c78d9c92aa98e13cc100f17eb84f1c4d')
              OR (phase = 'contract' AND checksum_sha256 =
                  'bd54d48f750ca52660d596377c5819eb66f68b8743d3286bd248c14bc03e26e3')
          )
    ) <> 3 THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'repository metadata v12 predecessor authority mismatch';
    END IF;
END;
$ogvcs$;

-- A production statement digest is evidence, not a globally unique lifecycle
-- receipt identity. The receipt is instead derived from the exact typed
-- lifecycle binding plus that evidence. These PostgreSQL 15 built-ins mirror
-- the Rust/JavaScript u64-length framing without requiring an extension.
CREATE FUNCTION ogvcs_metadata.content_manifest_receipt_field_v12(value bytea)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $ogvcs$
    SELECT int8send(octet_length(value)::bigint) || value
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.content_manifest_verification_receipt_digest_v12(
    receipt_kind text,
    tenant_id uuid,
    repository_id uuid,
    opaque_key bytea,
    object_kind smallint,
    object_digest bytea,
    expected_state text,
    expected_generation bigint,
    target_state text,
    target_generation bigint,
    authority_binding_digest bytea,
    production_statement_digest bytea
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $ogvcs$
    SELECT sha256(
        convert_to(
            'OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-LIFECYCLE-VERIFICATION-RECEIPT-V1',
            'UTF8'
        ) || decode('00', 'hex')
        || ogvcs_metadata.content_manifest_receipt_field_v12(
            convert_to(receipt_kind, 'UTF8')
        )
        || ogvcs_metadata.content_manifest_receipt_field_v12(uuid_send(tenant_id))
        || ogvcs_metadata.content_manifest_receipt_field_v12(uuid_send(repository_id))
        || ogvcs_metadata.content_manifest_receipt_field_v12(opaque_key)
        || ogvcs_metadata.content_manifest_receipt_field_v12(int2send(object_kind))
        || ogvcs_metadata.content_manifest_receipt_field_v12(object_digest)
        || ogvcs_metadata.content_manifest_receipt_field_v12(
            convert_to(expected_state, 'UTF8')
        )
        || ogvcs_metadata.content_manifest_receipt_field_v12(
            int8send(expected_generation)
        )
        || ogvcs_metadata.content_manifest_receipt_field_v12(
            convert_to(target_state, 'UTF8')
        )
        || ogvcs_metadata.content_manifest_receipt_field_v12(
            int8send(target_generation)
        )
        || ogvcs_metadata.content_manifest_receipt_field_v12(authority_binding_digest)
        || ogvcs_metadata.content_manifest_receipt_field_v12(production_statement_digest)
    )
$ogvcs$;

-- One typed immutable row is the recovery oracle for a kind-2 availability
-- commit. Generic application digests cannot reconstruct the bounded
-- production statement after commit-response loss, so the exact fixed fields
-- are retained here. This table is not a route, transfer session, GC permit,
-- request-root authority, or public receipt format.
CREATE TABLE ogvcs_metadata.content_manifest_availability_proofs (
    application_id uuid PRIMARY KEY
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    fact_ordinal integer NOT NULL DEFAULT 0 CHECK (fact_ordinal = 0),
    proof_schema text NOT NULL CHECK (
        proof_schema = 'ogvcs.object-transfer/content-manifest-committed-current/v1'
    ),
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    object_kind smallint NOT NULL CHECK (object_kind = 2),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    object_length bigint NOT NULL CHECK (object_length BETWEEN 0 AND 67108864),
    lifecycle_state text NOT NULL CHECK (lifecycle_state = 'available'),
    expected_generation bigint NOT NULL CHECK (
        expected_generation BETWEEN 1 AND 9007199254740990
    ),
    lifecycle_generation bigint NOT NULL CHECK (
        lifecycle_generation = expected_generation + 1
        AND lifecycle_generation BETWEEN 2 AND 9007199254740991
    ),
    commit_sequence bigint NOT NULL CHECK (
        commit_sequence BETWEEN 1 AND 9007199254740991
    ),
    authorization_closure_digest bytea NOT NULL
        CHECK (octet_length(authorization_closure_digest) = 32),
    authority_binding_digest bytea NOT NULL
        CHECK (octet_length(authority_binding_digest) = 32),
    tenant_scope_digest bytea NOT NULL CHECK (octet_length(tenant_scope_digest) = 32),
    identity_subject_digest bytea NOT NULL
        CHECK (octet_length(identity_subject_digest) = 32),
    production_subject_digest bytea NOT NULL
        CHECK (octet_length(production_subject_digest) = 32),
    authorization_epoch bigint NOT NULL CHECK (
        authorization_epoch BETWEEN 1 AND 9007199254740991
    ),
    authorization_page_count smallint NOT NULL CHECK (
        authorization_page_count BETWEEN 1 AND 5
    ),
    backend_receipt_digest bytea NOT NULL
        CHECK (octet_length(backend_receipt_digest) = 32)
        REFERENCES ogvcs_metadata.lifecycle_receipts(receipt_digest),
    verification_receipt_digest bytea NOT NULL
        CHECK (octet_length(verification_receipt_digest) = 32),
    finalize_semantic_fingerprint bytea NOT NULL
        CHECK (octet_length(finalize_semantic_fingerprint) = 32),
    dependency_count integer NOT NULL CHECK (dependency_count BETWEEN 0 AND 4095),
    dependency_generation_set_digest bytea NOT NULL
        CHECK (octet_length(dependency_generation_set_digest) = 32),
    statement_boundary text NOT NULL CHECK (
        statement_boundary = 'ogvcs.chunking-manifest/production-boundary@1'
    ),
    statement_logical_bytes bigint NOT NULL CHECK (
        statement_logical_bytes BETWEEN 0 AND 107374182400
    ),
    statement_manifest_sha256 bytea NOT NULL
        CHECK (octet_length(statement_manifest_sha256) = 32),
    statement_profile text NOT NULL CHECK (
        statement_profile = 'chunking.opengamevcs/gear-fastcdc-1m@1'
    ),
    statement_verifier text NOT NULL CHECK (
        statement_verifier = 'ogvcs.chunking-manifest/verifier@1'
    ),
    statement_whole_file_sha256 bytea NOT NULL
        CHECK (octet_length(statement_whole_file_sha256) = 32),
    production_statement_digest bytea NOT NULL
        CHECK (octet_length(production_statement_digest) = 32),
    proof_digest bytea NOT NULL UNIQUE CHECK (octet_length(proof_digest) = 32),
    outbox_event_id uuid NOT NULL UNIQUE
        REFERENCES ogvcs_metadata.lifecycle_internal_outbox(event_id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, opaque_key, lifecycle_generation),
    UNIQUE (repository_id, object_kind, object_digest, lifecycle_generation),
    FOREIGN KEY (repository_id, tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id),
    FOREIGN KEY (repository_id, opaque_key, object_kind, object_digest)
        REFERENCES ogvcs_metadata.object_lifecycle(
            repository_id, opaque_key, object_kind, object_digest
        ),
    FOREIGN KEY (application_id, fact_ordinal)
        REFERENCES ogvcs_metadata.lifecycle_transaction_facts(application_id, fact_ordinal),
    FOREIGN KEY (verification_receipt_digest)
        REFERENCES ogvcs_metadata.lifecycle_receipts(receipt_digest),
    FOREIGN KEY (verification_receipt_digest)
        REFERENCES ogvcs_metadata.lifecycle_receipt_consumptions(receipt_digest)
);

-- Every <=1,000-object OGVCS-009 page is retained as typed evidence. The
-- identity ledger remains authoritative; this table only binds its immutable
-- commitment to the single reconstructed availability proof.
CREATE TABLE ogvcs_metadata.content_manifest_availability_authorization_pages (
    application_id uuid NOT NULL
        REFERENCES ogvcs_metadata.content_manifest_availability_proofs(application_id),
    page_ordinal smallint NOT NULL CHECK (page_ordinal BETWEEN 0 AND 4),
    page_count smallint NOT NULL CHECK (page_count BETWEEN 1 AND 5),
    resource_count integer NOT NULL CHECK (resource_count BETWEEN 1 AND 1000),
    transaction_id text NOT NULL CHECK (
        transaction_id ~ '^tx\.[0-9a-f]{64}$'
    ),
    correlation_id text NOT NULL CHECK (
        correlation_id ~ '^transfer\.[0-9a-f]{64}$'
    ),
    commitment_id text NOT NULL UNIQUE
        REFERENCES ogvcs_identity.transaction_decision_commitments(commitment_id),
    authority_epoch bigint NOT NULL CHECK (
        authority_epoch BETWEEN 1 AND 9007199254740991
    ),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest) = 32),
    resource_set_digest bytea NOT NULL CHECK (octet_length(resource_set_digest) = 32),
    result_digest bytea NOT NULL CHECK (octet_length(result_digest) = 32),
    record_hash bytea NOT NULL CHECK (octet_length(record_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (application_id, page_ordinal),
    UNIQUE (application_id, transaction_id),
    UNIQUE (application_id, correlation_id),
    CHECK (page_ordinal < page_count)
);

CREATE FUNCTION ogvcs_metadata.validate_content_manifest_authorization_page_v12()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.content_manifest_availability_proofs AS proof
        JOIN ogvcs_identity.transaction_decision_commitments AS commitment
          ON commitment.commitment_id = NEW.commitment_id
        WHERE proof.application_id = NEW.application_id
          AND proof.authorization_epoch = NEW.authority_epoch
          AND proof.authorization_page_count = NEW.page_count
          AND commitment.transaction_id = NEW.transaction_id
          AND commitment.correlation_id = NEW.correlation_id
          AND commitment.tenant_id =
              'tenant.' || replace(proof.tenant_id::text, '-', '')
          AND commitment.repository_id =
              'repository.' || replace(proof.repository_id::text, '-', '')
          AND commitment.authority_epoch = NEW.authority_epoch
          AND commitment.decision_digest = NEW.decision_digest
          AND commitment.resource_set_digest = NEW.resource_set_digest
          AND commitment.result_digest = NEW.result_digest
          AND commitment.record_hash = NEW.record_hash
    ) INTO complete;
    IF NOT complete THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'invalid content manifest authorization page';
    END IF;
    RETURN NULL;
END;
$ogvcs$;

CREATE CONSTRAINT TRIGGER content_manifest_authorization_page_complete_v12
AFTER INSERT ON ogvcs_metadata.content_manifest_availability_authorization_pages
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
    ogvcs_metadata.validate_content_manifest_authorization_page_v12();

CREATE FUNCTION ogvcs_metadata.validate_content_manifest_availability_proof_v12()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_applications AS application
        JOIN ogvcs_metadata.lifecycle_transaction_facts AS fact
          ON fact.application_id = application.application_id
         AND fact.fact_ordinal = NEW.fact_ordinal
        JOIN ogvcs_metadata.lifecycle_internal_outbox AS outbox
          ON outbox.event_id = NEW.outbox_event_id
         AND outbox.application_id = application.application_id
         AND outbox.fact_ordinal = fact.fact_ordinal
         AND NOT outbox.aggregate_event
         AND outbox.protected_fact_digest = fact.fact_digest
        JOIN ogvcs_metadata.lifecycle_receipt_consumptions AS consumption
          ON consumption.receipt_digest = NEW.verification_receipt_digest
         AND consumption.application_id = application.application_id
        JOIN ogvcs_metadata.lifecycle_receipts AS backend
          ON backend.receipt_digest = NEW.backend_receipt_digest
        JOIN ogvcs_metadata.lifecycle_receipts AS verification
          ON verification.receipt_digest = NEW.verification_receipt_digest
        JOIN ogvcs_metadata.object_lifecycle AS lifecycle
          ON lifecycle.repository_id = NEW.repository_id
         AND lifecycle.opaque_key = NEW.opaque_key
        WHERE application.application_id = NEW.application_id
          AND application.application_kind = 'direct'
          AND application.capability = 'transfer.record-available'
          AND application.operation = 'transfer.record-available'
          AND application.tenant_id = NEW.tenant_id
          AND application.repository_id = NEW.repository_id
          AND application.subject_digest = NEW.identity_subject_digest
          AND application.authorization_epoch = NEW.authorization_epoch
          AND application.semantic_fingerprint = NEW.finalize_semantic_fingerprint
          AND application.lifecycle_contract_digest = decode(
              'db379ccdd81cfe94fec08ddda2ae5031c9ab5b7750007cf1e096cf1e4299a3bc',
              'hex'
          )
          AND application.commit_sequence = NEW.commit_sequence
          AND application.object_count = 1
          AND fact.opaque_key = NEW.opaque_key
          AND fact.object_kind = NEW.object_kind
          AND fact.object_digest = NEW.object_digest
          AND fact.prior_state = 'staged'
          AND fact.prior_generation = NEW.expected_generation
          AND fact.next_state = NEW.lifecycle_state
          AND fact.next_generation = NEW.lifecycle_generation
          AND NOT fact.reachability_recorded
          AND fact.receipt_digest = NEW.verification_receipt_digest
          AND fact.result_class = 'availability-recorded'
          AND fact.outbox_event_id = NEW.outbox_event_id
          AND consumption.receipt_kind = 'production-verification'
          AND consumption.repository_id = NEW.repository_id
          AND consumption.opaque_key = NEW.opaque_key
          AND consumption.purpose = 'content-manifest-availability'
          AND consumption.expected_generation = NEW.expected_generation
          AND backend.receipt_kind = 'backend-durable'
          AND backend.tenant_id = NEW.tenant_id
          AND backend.repository_id = NEW.repository_id
          AND backend.opaque_key = NEW.opaque_key
          AND backend.object_kind = NEW.object_kind
          AND backend.object_digest = NEW.object_digest
          AND backend.expected_state = 'staged'
          AND backend.expected_generation = NEW.expected_generation
          AND backend.target_state = NEW.lifecycle_state
          AND backend.target_generation = NEW.lifecycle_generation
          AND backend.authority_binding_digest = NEW.authority_binding_digest
          AND backend.lifecycle_contract_digest = application.lifecycle_contract_digest
          AND verification.receipt_kind = 'production-verification'
          AND verification.tenant_id = NEW.tenant_id
          AND verification.repository_id = NEW.repository_id
          AND verification.opaque_key = NEW.opaque_key
          AND verification.object_kind = NEW.object_kind
          AND verification.object_digest = NEW.object_digest
          AND verification.expected_state = 'staged'
          AND verification.expected_generation = NEW.expected_generation
          AND verification.target_state = NEW.lifecycle_state
          AND verification.target_generation = NEW.lifecycle_generation
          AND verification.authority_binding_digest = NEW.authority_binding_digest
          AND verification.lifecycle_contract_digest = application.lifecycle_contract_digest
          AND verification.receipt_digest =
              ogvcs_metadata.content_manifest_verification_receipt_digest_v12(
                  verification.receipt_kind,
                  verification.tenant_id,
                  verification.repository_id,
                  verification.opaque_key,
                  verification.object_kind,
                  verification.object_digest,
                  verification.expected_state,
                  verification.expected_generation,
                  verification.target_state,
                  verification.target_generation,
                  verification.authority_binding_digest,
                  NEW.production_statement_digest
              )
          AND lifecycle.tenant_id = NEW.tenant_id
          AND lifecycle.object_kind = NEW.object_kind
          AND lifecycle.object_digest = NEW.object_digest
          AND lifecycle.object_length = NEW.object_length
          AND lifecycle.tenant_scope_digest = NEW.tenant_scope_digest
          AND lifecycle.state = NEW.lifecycle_state
          AND lifecycle.generation = NEW.lifecycle_generation
          AND lifecycle.authority_binding_digest = NEW.authority_binding_digest
          AND lifecycle.backend_receipt_digest = NEW.backend_receipt_digest
          AND lifecycle.verification_receipt_digest = NEW.verification_receipt_digest
          AND lifecycle.last_application_id = NEW.application_id
          AND lifecycle.last_commit_sequence = NEW.commit_sequence
          AND NEW.authorization_page_count =
              (NEW.dependency_count + 1000) / 1000
          AND (
              SELECT count(*)
              FROM ogvcs_metadata.content_manifest_availability_authorization_pages AS page
              WHERE page.application_id = NEW.application_id
          ) = NEW.authorization_page_count
          AND (
              SELECT COALESCE(sum(page.resource_count), 0)
              FROM ogvcs_metadata.content_manifest_availability_authorization_pages AS page
              WHERE page.application_id = NEW.application_id
          ) = NEW.dependency_count + 1
          AND NOT EXISTS (
              SELECT 1
              FROM generate_series(0, NEW.authorization_page_count - 1) AS ordinal(value)
              WHERE NOT EXISTS (
                  SELECT 1
                  FROM ogvcs_metadata.content_manifest_availability_authorization_pages AS page
                  WHERE page.application_id = NEW.application_id
                    AND page.page_ordinal = ordinal.value
                    AND page.page_count = NEW.authorization_page_count
                    AND page.resource_count = CASE
                        WHEN ordinal.value < NEW.authorization_page_count - 1
                            THEN 1000
                        ELSE NEW.dependency_count + 1
                             - (1000 * (NEW.authorization_page_count - 1))
                    END
              )
          )
    ) INTO complete;
    IF NOT complete THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'incomplete content manifest availability proof';
    END IF;
    RETURN NULL;
END;
$ogvcs$;

CREATE CONSTRAINT TRIGGER content_manifest_availability_proof_complete_v12
AFTER INSERT ON ogvcs_metadata.content_manifest_availability_proofs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
    ogvcs_metadata.validate_content_manifest_availability_proof_v12();

CREATE TRIGGER content_manifest_availability_proofs_immutable_v12
BEFORE UPDATE OR DELETE ON ogvcs_metadata.content_manifest_availability_proofs
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER content_manifest_availability_authorization_pages_immutable_v12
BEFORE UPDATE OR DELETE
ON ogvcs_metadata.content_manifest_availability_authorization_pages
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

COMMIT;
