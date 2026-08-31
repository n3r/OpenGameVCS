BEGIN;

-- OGVCS-008 lifecycle facts are repository metadata. Backend verification,
-- deletion, reopen, and OGVCS-007 production verification happen before the
-- final metadata transaction and leave only immutable digest-bound receipts.
CREATE TABLE ogvcs_metadata.lifecycle_receipts (
    receipt_digest bytea PRIMARY KEY CHECK (octet_length(receipt_digest) = 32),
    receipt_kind text NOT NULL CHECK (receipt_kind IN (
        'backend-durable', 'production-verification', 'health-observation',
        'backend-deletion', 'backend-reopen'
    )),
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    object_kind smallint NOT NULL CHECK (object_kind BETWEEN 1 AND 11),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    expected_state text NOT NULL CHECK (expected_state IN (
        'staged', 'available', 'quarantined', 'deleting', 'deleted'
    )),
    expected_generation bigint NOT NULL
        CHECK (expected_generation BETWEEN 1 AND 9007199254740991),
    target_state text NOT NULL CHECK (target_state IN (
        'staged', 'available', 'quarantined', 'deleting', 'deleted'
    )),
    target_generation bigint NOT NULL
        CHECK (target_generation BETWEEN 1 AND 9007199254740991),
    authority_binding_digest bytea NOT NULL
        CHECK (octet_length(authority_binding_digest) = 32),
    health_result text CHECK (health_result IS NULL OR health_result IN ('healthy', 'unhealthy')),
    health_generation bigint CHECK (
        health_generation IS NULL
        OR health_generation BETWEEN 1 AND 9007199254740991
    ),
    lifecycle_contract_digest bytea NOT NULL
        CHECK (octet_length(lifecycle_contract_digest) = 32),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (receipt_digest, receipt_kind, repository_id, opaque_key),
    UNIQUE (
        receipt_digest, receipt_kind, repository_id, opaque_key, expected_generation
    ),
    UNIQUE (receipt_digest, repository_id, opaque_key, object_kind, object_digest),
    FOREIGN KEY (repository_id, tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id),
    CHECK (
        (receipt_kind = 'backend-durable'
            AND expected_state = 'staged' AND target_state = 'available'
            AND target_generation = expected_generation + 1)
        OR
        (receipt_kind = 'production-verification'
            AND expected_state IN ('staged', 'quarantined')
            AND target_state = 'available'
            AND target_generation = expected_generation + 1)
        OR
        (receipt_kind = 'health-observation'
            AND expected_state IN ('available', 'quarantined')
            AND target_state = expected_state
            AND target_generation = expected_generation)
        OR
        (receipt_kind = 'backend-deletion'
            AND expected_state = 'deleting' AND target_state = 'deleted'
            AND target_generation = expected_generation + 1)
        OR
        (receipt_kind = 'backend-reopen'
            AND expected_state = 'deleted' AND target_state = 'staged'
            AND target_generation = expected_generation + 1)
    ),
    CHECK ((receipt_kind = 'health-observation')
           = (health_result IS NOT NULL AND health_generation IS NOT NULL))
);

CREATE TABLE ogvcs_metadata.object_lifecycle (
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    object_kind smallint NOT NULL CHECK (object_kind BETWEEN 1 AND 11),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    object_length bigint NOT NULL CHECK (object_length BETWEEN 0 AND 67108864),
    tenant_scope_digest bytea NOT NULL CHECK (octet_length(tenant_scope_digest) = 32),
    state text NOT NULL CHECK (state IN (
        'staged', 'available', 'quarantined', 'deleting', 'deleted'
    )),
    generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    health text NOT NULL CHECK (health IN (
        'not-applicable', 'healthy', 'unhealthy'
    )),
    health_generation bigint CHECK (
        health_generation IS NULL
        OR health_generation BETWEEN 1 AND 9007199254740991
    ),
    health_observation_digest bytea CHECK (
        health_observation_digest IS NULL OR octet_length(health_observation_digest) = 32
    ),
    authority_binding_digest bytea NOT NULL
        CHECK (octet_length(authority_binding_digest) = 32),
    backend_receipt_digest bytea CHECK (
        backend_receipt_digest IS NULL OR octet_length(backend_receipt_digest) = 32
    ),
    verification_receipt_digest bytea CHECK (
        verification_receipt_digest IS NULL OR octet_length(verification_receipt_digest) = 32
    ),
    deletion_receipt_digest bytea CHECK (
        deletion_receipt_digest IS NULL OR octet_length(deletion_receipt_digest) = 32
    ),
    retention_until timestamptz NOT NULL,
    last_application_id uuid,
    last_commit_sequence bigint CHECK (
        last_commit_sequence IS NULL
        OR last_commit_sequence BETWEEN 1 AND 9007199254740991
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, opaque_key),
    UNIQUE (repository_id, object_kind, object_digest),
    UNIQUE (repository_id, opaque_key, object_kind, object_digest),
    FOREIGN KEY (repository_id, tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id),
    FOREIGN KEY (backend_receipt_digest)
        REFERENCES ogvcs_metadata.lifecycle_receipts(receipt_digest),
    FOREIGN KEY (verification_receipt_digest)
        REFERENCES ogvcs_metadata.lifecycle_receipts(receipt_digest),
    FOREIGN KEY (deletion_receipt_digest)
        REFERENCES ogvcs_metadata.lifecycle_receipts(receipt_digest),
    CHECK ((health = 'not-applicable')
           = (health_generation IS NULL AND health_observation_digest IS NULL)),
    CHECK ((health_generation IS NULL) = (health_observation_digest IS NULL)),
    CHECK (state NOT IN ('staged', 'deleting', 'deleted')
           OR (health = 'not-applicable' AND health_generation IS NULL)),
    CHECK ((state = 'staged') = (backend_receipt_digest IS NULL)),
    CHECK ((state = 'deleted') = (deletion_receipt_digest IS NOT NULL)),
    CHECK (object_kind <> 2 OR state = 'staged'
           OR verification_receipt_digest IS NOT NULL),
    CHECK ((last_application_id IS NULL) = (last_commit_sequence IS NULL))
);

ALTER TABLE ogvcs_metadata.lifecycle_receipts
    ADD CONSTRAINT lifecycle_receipts_exact_object_fk
    FOREIGN KEY (repository_id, opaque_key, object_kind, object_digest)
    REFERENCES ogvcs_metadata.object_lifecycle(
        repository_id, opaque_key, object_kind, object_digest
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ogvcs_metadata.lifecycle_receipt_consumptions (
    receipt_digest bytea PRIMARY KEY,
    receipt_kind text NOT NULL CHECK (receipt_kind IN (
        'production-verification', 'backend-deletion', 'backend-reopen'
    )),
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    purpose text NOT NULL CHECK (purpose IN (
        'publication-revival', 'content-manifest-availability',
        'deletion-completion', 'deleted-generation-reopen'
    )),
    expected_generation bigint NOT NULL
        CHECK (expected_generation BETWEEN 1 AND 9007199254740991),
    application_id uuid NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (
        receipt_digest, receipt_kind, repository_id, opaque_key, expected_generation
    )
        REFERENCES ogvcs_metadata.lifecycle_receipts(
            receipt_digest, receipt_kind, repository_id, opaque_key, expected_generation
        ),
    CHECK (
        (receipt_kind = 'production-verification'
            AND purpose IN ('publication-revival', 'content-manifest-availability'))
        OR (receipt_kind = 'backend-deletion' AND purpose = 'deletion-completion')
        OR (receipt_kind = 'backend-reopen' AND purpose = 'deleted-generation-reopen')
    )
);

-- Aggregate publication plans are server-derived and immutable. The declared
-- count is bounded before any item is accepted; deterministic non-final chunks
-- contain 1,000 items and every chunk is at most 1 MiB.
CREATE TABLE ogvcs_metadata.lifecycle_publication_plans (
    plan_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    publication_kind smallint NOT NULL CHECK (publication_kind BETWEEN 1 AND 11),
    publication_digest bytea NOT NULL CHECK (octet_length(publication_digest) = 32),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    authorization_epoch bigint NOT NULL
        CHECK (authorization_epoch BETWEEN 1 AND 9007199254740991),
    authority_contract_digest bytea NOT NULL
        CHECK (octet_length(authority_contract_digest) = 32),
    structural_commitment_digest bytea NOT NULL
        CHECK (octet_length(structural_commitment_digest) = 32),
    lifecycle_contract_digest bytea NOT NULL
        CHECK (octet_length(lifecycle_contract_digest) = 32),
    candidate_digest bytea NOT NULL CHECK (octet_length(candidate_digest) = 32),
    declared_plan_digest bytea NOT NULL CHECK (octet_length(declared_plan_digest) = 32),
    idempotency_scope_digest bytea NOT NULL
        CHECK (octet_length(idempotency_scope_digest) = 32),
    idempotency_operation text NOT NULL
        CHECK (octet_length(idempotency_operation) BETWEEN 1 AND 128),
    idempotency_key text NOT NULL
        CHECK (octet_length(idempotency_key) BETWEEN 30 AND 256),
    semantic_fingerprint bytea NOT NULL CHECK (octet_length(semantic_fingerprint) = 32),
    declared_object_count integer NOT NULL
        CHECK (declared_object_count BETWEEN 1 AND 100000),
    declared_chunk_count integer NOT NULL
        CHECK (declared_chunk_count BETWEEN 1 AND 100),
    declared_encoded_bytes bigint NOT NULL
        CHECK (declared_encoded_bytes BETWEEN 1 AND 104857600),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (repository_id, tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id),
    UNIQUE (idempotency_scope_digest, idempotency_operation, idempotency_key),
    CHECK (declared_chunk_count = (declared_object_count + 999) / 1000),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '1 day')
);

CREATE TABLE ogvcs_metadata.lifecycle_publication_plan_chunks (
    plan_id uuid NOT NULL
        REFERENCES ogvcs_metadata.lifecycle_publication_plans(plan_id),
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal BETWEEN 0 AND 99),
    first_item_ordinal integer NOT NULL
        CHECK (first_item_ordinal BETWEEN 0 AND 99999),
    item_count integer NOT NULL CHECK (item_count BETWEEN 1 AND 1000),
    encoded_bytes integer NOT NULL CHECK (encoded_bytes BETWEEN 1 AND 1048576),
    encoded_payload bytea NOT NULL CHECK (
        octet_length(encoded_payload) BETWEEN 1 AND 1048576
    ),
    chunk_digest bytea NOT NULL CHECK (octet_length(chunk_digest) = 32),
    PRIMARY KEY (plan_id, chunk_ordinal),
    UNIQUE (plan_id, first_item_ordinal),
    UNIQUE (plan_id, chunk_digest),
    CHECK (first_item_ordinal = chunk_ordinal * 1000),
    CHECK (encoded_bytes = octet_length(encoded_payload))
);

CREATE TABLE ogvcs_metadata.lifecycle_publication_plan_items (
    plan_id uuid NOT NULL,
    chunk_ordinal integer NOT NULL,
    item_ordinal integer NOT NULL CHECK (item_ordinal BETWEEN 0 AND 999),
    global_ordinal integer NOT NULL CHECK (global_ordinal BETWEEN 0 AND 99999),
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    object_kind smallint NOT NULL CHECK (object_kind BETWEEN 1 AND 11),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    expected_state text NOT NULL CHECK (expected_state IN ('available', 'quarantined')),
    expected_generation bigint NOT NULL
        CHECK (expected_generation BETWEEN 1 AND 9007199254740991),
    expected_health text NOT NULL CHECK (expected_health = 'healthy'),
    expected_health_generation bigint NOT NULL
        CHECK (expected_health_generation BETWEEN 1 AND 9007199254740991),
    current_health_observation_digest bytea NOT NULL
        CHECK (octet_length(current_health_observation_digest) = 32),
    authority_binding_digest bytea NOT NULL
        CHECK (octet_length(authority_binding_digest) = 32),
    current_backend_receipt_digest bytea NOT NULL
        CHECK (octet_length(current_backend_receipt_digest) = 32),
    current_verification_receipt_digest bytea CHECK (
        current_verification_receipt_digest IS NULL
        OR octet_length(current_verification_receipt_digest) = 32
    ),
    transition_verification_receipt_digest bytea CHECK (
        transition_verification_receipt_digest IS NULL
        OR octet_length(transition_verification_receipt_digest) = 32
    ),
    resource_opaque_digest bytea NOT NULL
        CHECK (octet_length(resource_opaque_digest) = 32),
    item_digest bytea NOT NULL CHECK (octet_length(item_digest) = 32),
    PRIMARY KEY (plan_id, global_ordinal),
    UNIQUE (plan_id, opaque_key),
    UNIQUE (plan_id, object_kind, object_digest),
    UNIQUE (plan_id, item_digest),
    FOREIGN KEY (plan_id, chunk_ordinal)
        REFERENCES ogvcs_metadata.lifecycle_publication_plan_chunks(plan_id, chunk_ordinal),
    CHECK (global_ordinal = chunk_ordinal * 1000 + item_ordinal),
    CHECK ((expected_state = 'quarantined')
           = (transition_verification_receipt_digest IS NOT NULL)),
    CHECK (object_kind <> 2 OR current_verification_receipt_digest IS NOT NULL)
);

CREATE TABLE ogvcs_metadata.lifecycle_publication_plan_seals (
    plan_id uuid PRIMARY KEY
        REFERENCES ogvcs_metadata.lifecycle_publication_plans(plan_id),
    object_count integer NOT NULL CHECK (object_count BETWEEN 1 AND 100000),
    chunk_count integer NOT NULL CHECK (chunk_count BETWEEN 1 AND 100),
    encoded_bytes bigint NOT NULL CHECK (encoded_bytes BETWEEN 1 AND 104857600),
    plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
    sealed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ogvcs_metadata.lifecycle_applications (
    application_id uuid PRIMARY KEY,
    receipt_kind text NOT NULL CHECK (
        receipt_kind = 'ogvcs.lifecycle-application/v1'
    ),
    receipt_digest bytea NOT NULL UNIQUE CHECK (octet_length(receipt_digest) = 32),
    application_kind text NOT NULL CHECK (application_kind IN ('direct', 'aggregate')),
    capability text NOT NULL CHECK (capability IN (
        'submit.consume-publication', 'gc.acquire-deleting',
        'gc.complete-deletion', 'transfer.reverify-deleted',
        'transfer.record-available'
    )),
    operation text NOT NULL CHECK (octet_length(operation) BETWEEN 1 AND 128),
    transaction_id text,
    transaction_id_digest bytea CHECK (
        transaction_id_digest IS NULL OR octet_length(transaction_id_digest) = 32
    ),
    plan_id uuid REFERENCES ogvcs_metadata.lifecycle_publication_plan_seals(plan_id),
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    authorization_epoch bigint NOT NULL
        CHECK (authorization_epoch BETWEEN 1 AND 9007199254740991),
    context_digest bytea NOT NULL CHECK (octet_length(context_digest) = 32),
    authority_contract_digest bytea NOT NULL
        CHECK (octet_length(authority_contract_digest) = 32),
    lifecycle_contract_digest bytea NOT NULL
        CHECK (octet_length(lifecycle_contract_digest) = 32),
    candidate_digest bytea CHECK (candidate_digest IS NULL OR octet_length(candidate_digest) = 32),
    publication_kind smallint CHECK (publication_kind IS NULL OR publication_kind BETWEEN 1 AND 11),
    publication_digest bytea CHECK (
        publication_digest IS NULL OR octet_length(publication_digest) = 32
    ),
    root_proof_digest bytea CHECK (
        root_proof_digest IS NULL OR octet_length(root_proof_digest) = 32
    ),
    lifecycle_plan_digest bytea NOT NULL CHECK (octet_length(lifecycle_plan_digest) = 32),
    idempotency_scope_digest bytea NOT NULL
        CHECK (octet_length(idempotency_scope_digest) = 32),
    idempotency_operation text NOT NULL
        CHECK (octet_length(idempotency_operation) BETWEEN 1 AND 128),
    idempotency_key text NOT NULL
        CHECK (octet_length(idempotency_key) BETWEEN 30 AND 256),
    semantic_fingerprint bytea NOT NULL CHECK (octet_length(semantic_fingerprint) = 32),
    object_count integer NOT NULL CHECK (object_count BETWEEN 1 AND 100000),
    protected_result_digest bytea NOT NULL
        CHECK (octet_length(protected_result_digest) = 32),
    commit_sequence bigint NOT NULL
        CHECK (commit_sequence BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (repository_id, tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id),
    UNIQUE (idempotency_scope_digest, idempotency_operation, idempotency_key),
    UNIQUE (idempotency_scope_digest, operation, transaction_id_digest),
    UNIQUE (plan_id),
    CHECK (
        (application_kind = 'direct'
            AND transaction_id ~ '^ltx1\.[A-Za-z0-9_-]{43}$'
            AND transaction_id_digest IS NOT NULL AND plan_id IS NULL
            AND object_count BETWEEN 1 AND 1024)
        OR
        (application_kind = 'aggregate'
            AND transaction_id IS NULL AND transaction_id_digest IS NULL AND plan_id IS NOT NULL
            AND capability = 'submit.consume-publication')
    ),
    CHECK (
        (capability = 'submit.consume-publication'
            AND operation = 'submit.finalize'
            AND publication_kind IS NOT NULL AND publication_digest IS NOT NULL
            AND root_proof_digest IS NULL)
        OR
        (capability IN ('gc.acquire-deleting', 'gc.complete-deletion')
            AND operation = capability
            AND publication_kind IS NULL AND publication_digest IS NULL
            AND root_proof_digest IS NOT NULL)
        OR
        (capability IN ('transfer.reverify-deleted', 'transfer.record-available')
            AND operation = capability
            AND publication_kind IS NULL AND publication_digest IS NULL
            AND root_proof_digest IS NULL)
    ),
    CHECK (idempotency_operation = operation)
);

ALTER TABLE ogvcs_metadata.lifecycle_receipt_consumptions
    ADD CONSTRAINT lifecycle_receipt_consumptions_application_fk
    FOREIGN KEY (application_id)
    REFERENCES ogvcs_metadata.lifecycle_applications(application_id)
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ogvcs_metadata.object_lifecycle
    ADD CONSTRAINT object_lifecycle_last_application_fk
    FOREIGN KEY (last_application_id)
    REFERENCES ogvcs_metadata.lifecycle_applications(application_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ogvcs_metadata.lifecycle_transaction_facts (
    application_id uuid NOT NULL
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    fact_ordinal integer NOT NULL CHECK (fact_ordinal BETWEEN 0 AND 1023),
    resource_opaque_digest bytea NOT NULL CHECK (octet_length(resource_opaque_digest) = 32),
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    object_kind smallint NOT NULL CHECK (object_kind BETWEEN 1 AND 11),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    prior_state text NOT NULL CHECK (prior_state IN (
        'staged', 'available', 'quarantined', 'deleting', 'deleted'
    )),
    prior_generation bigint NOT NULL
        CHECK (prior_generation BETWEEN 1 AND 9007199254740991),
    next_state text NOT NULL CHECK (next_state IN (
        'staged', 'available', 'quarantined', 'deleting', 'deleted'
    )),
    next_generation bigint NOT NULL
        CHECK (next_generation BETWEEN 1 AND 9007199254740991),
    health_generation bigint CHECK (
        health_generation IS NULL
        OR health_generation BETWEEN 1 AND 9007199254740991
    ),
    reachability_recorded boolean NOT NULL,
    receipt_digest bytea CHECK (receipt_digest IS NULL OR octet_length(receipt_digest) = 32),
    result_class text NOT NULL CHECK (result_class IN (
        'publication-linked', 'quarantine-revived-and-linked',
        'deleting-acquired', 'deletion-recorded',
        'deleted-generation-reopened', 'availability-recorded'
    )),
    fact_digest bytea NOT NULL CHECK (octet_length(fact_digest) = 32),
    -- Correlates the protected fact with a future OGVCS-009 audit append. It
    -- is not itself evidence that an authenticated audit participant ran.
    audit_correlation_id uuid NOT NULL UNIQUE,
    outbox_event_id uuid NOT NULL UNIQUE,
    PRIMARY KEY (application_id, fact_ordinal),
    UNIQUE (application_id, opaque_key),
    UNIQUE (application_id, fact_digest)
);

CREATE TABLE ogvcs_metadata.lifecycle_publication_reachability (
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    publication_kind smallint NOT NULL CHECK (publication_kind BETWEEN 1 AND 11),
    publication_digest bytea NOT NULL CHECK (octet_length(publication_digest) = 32),
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    lifecycle_generation bigint NOT NULL
        CHECK (lifecycle_generation BETWEEN 1 AND 9007199254740991),
    link_digest bytea NOT NULL CHECK (octet_length(link_digest) = 32),
    application_id uuid NOT NULL
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    commit_sequence bigint NOT NULL
        CHECK (commit_sequence BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, publication_kind, publication_digest, opaque_key),
    UNIQUE (application_id, opaque_key),
    UNIQUE (link_digest),
    FOREIGN KEY (repository_id, opaque_key)
        REFERENCES ogvcs_metadata.object_lifecycle(repository_id, opaque_key)
);

CREATE INDEX lifecycle_reachability_by_object
    ON ogvcs_metadata.lifecycle_publication_reachability(repository_id, opaque_key);

CREATE TABLE ogvcs_metadata.lifecycle_deletion_fences (
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    opaque_key bytea NOT NULL CHECK (octet_length(opaque_key) = 32),
    prior_generation bigint NOT NULL
        CHECK (prior_generation BETWEEN 1 AND 9007199254740990),
    deleting_generation bigint NOT NULL
        CHECK (deleting_generation BETWEEN 2 AND 9007199254740991),
    root_proof_digest bytea NOT NULL CHECK (octet_length(root_proof_digest) = 32),
    authority_contract_digest bytea NOT NULL
        CHECK (octet_length(authority_contract_digest) = 32),
    authority_binding_digest bytea NOT NULL
        CHECK (octet_length(authority_binding_digest) = 32),
    backend_permit_digest bytea NOT NULL UNIQUE
        CHECK (octet_length(backend_permit_digest) = 32),
    acquired_application_id uuid NOT NULL
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    acquired_commit_sequence bigint NOT NULL
        CHECK (acquired_commit_sequence BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, opaque_key, deleting_generation),
    FOREIGN KEY (repository_id, opaque_key)
        REFERENCES ogvcs_metadata.object_lifecycle(repository_id, opaque_key),
    CHECK (deleting_generation = prior_generation + 1)
);

-- This queue is internal lifecycle evidence. It does not assign a public
-- OGVCS-006 event type or protocol route.
CREATE TABLE ogvcs_metadata.lifecycle_internal_outbox (
    event_id uuid PRIMARY KEY,
    application_id uuid NOT NULL,
    fact_ordinal integer CHECK (fact_ordinal IS NULL OR fact_ordinal BETWEEN 0 AND 1023),
    aggregate_event boolean NOT NULL,
    protected_fact_digest bytea NOT NULL CHECK (octet_length(protected_fact_digest) = 32),
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (application_id, fact_ordinal),
    UNIQUE (application_id, protected_fact_digest),
    FOREIGN KEY (application_id, fact_ordinal)
        REFERENCES ogvcs_metadata.lifecycle_transaction_facts(application_id, fact_ordinal)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (aggregate_event = (fact_ordinal IS NULL))
);

CREATE UNIQUE INDEX lifecycle_internal_outbox_one_aggregate
    ON ogvcs_metadata.lifecycle_internal_outbox(application_id)
    WHERE fact_ordinal IS NULL;

CREATE INDEX object_lifecycle_gc_candidates_v9
    ON ogvcs_metadata.object_lifecycle(repository_id, retention_until, opaque_key)
    WHERE state = 'quarantined';

CREATE FUNCTION ogvcs_metadata.validate_lifecycle_receipt_bindings()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF NEW.backend_receipt_digest IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM ogvcs_metadata.lifecycle_receipts AS receipt
        WHERE receipt.receipt_digest = NEW.backend_receipt_digest
          AND receipt.receipt_kind = 'backend-durable'
          AND receipt.repository_id = NEW.repository_id
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.opaque_key = NEW.opaque_key
          AND receipt.object_kind = NEW.object_kind
          AND receipt.object_digest = NEW.object_digest
          AND receipt.authority_binding_digest = NEW.authority_binding_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid lifecycle receipt binding';
    END IF;
    IF NEW.verification_receipt_digest IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM ogvcs_metadata.lifecycle_receipts AS receipt
        WHERE receipt.receipt_digest = NEW.verification_receipt_digest
          AND receipt.receipt_kind = 'production-verification'
          AND receipt.repository_id = NEW.repository_id
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.opaque_key = NEW.opaque_key
          AND receipt.object_kind = NEW.object_kind
          AND receipt.object_digest = NEW.object_digest
          AND receipt.authority_binding_digest = NEW.authority_binding_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid lifecycle receipt binding';
    END IF;
    IF NEW.deletion_receipt_digest IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM ogvcs_metadata.lifecycle_receipts AS receipt
        WHERE receipt.receipt_digest = NEW.deletion_receipt_digest
          AND receipt.receipt_kind = 'backend-deletion'
          AND receipt.repository_id = NEW.repository_id
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.opaque_key = NEW.opaque_key
          AND receipt.object_kind = NEW.object_kind
          AND receipt.object_digest = NEW.object_digest
          AND receipt.target_generation = NEW.generation
          AND receipt.authority_binding_digest = NEW.authority_binding_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid lifecycle receipt binding';
    END IF;
    IF NEW.health_observation_digest IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM ogvcs_metadata.lifecycle_receipts AS receipt
        WHERE receipt.receipt_digest = NEW.health_observation_digest
          AND receipt.receipt_kind = 'health-observation'
          AND receipt.repository_id = NEW.repository_id
          AND receipt.tenant_id = NEW.tenant_id
          AND receipt.opaque_key = NEW.opaque_key
          AND receipt.object_kind = NEW.object_kind
          AND receipt.object_digest = NEW.object_digest
          AND receipt.health_result = NEW.health
          AND receipt.health_generation = NEW.health_generation
          AND receipt.authority_binding_digest = NEW.authority_binding_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid lifecycle receipt binding';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE TRIGGER object_lifecycle_receipt_bindings
BEFORE INSERT OR UPDATE ON ogvcs_metadata.object_lifecycle
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.validate_lifecycle_receipt_bindings();

-- Locks and validates a sealed aggregate without returning per-object state to
-- Rust. Submit and lifecycle/GC participants serialize on the same canonical
-- (repository_id, opaque_key) order with one set-based locking statement.
CREATE FUNCTION ogvcs_metadata.lock_and_validate_lifecycle_publication_plan(
    requested_plan_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
AS $ogvcs$
DECLARE
    plan_row record;
    bindings_valid boolean;
BEGIN
    SELECT plan.repository_id, plan.tenant_id, plan.lifecycle_contract_digest
    INTO plan_row
    FROM ogvcs_metadata.lifecycle_publication_plans AS plan
    JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal
      ON seal.plan_id = plan.plan_id
     AND seal.object_count = plan.declared_object_count
     AND seal.chunk_count = plan.declared_chunk_count
     AND seal.encoded_bytes = plan.declared_encoded_bytes
     AND seal.plan_digest = plan.declared_plan_digest
    WHERE plan.plan_id = requested_plan_id
      AND plan.expires_at > clock_timestamp();
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    -- One ordered set query acquires every lifecycle row lock. There is no
    -- per-item round trip or materialized Rust result.
    PERFORM lifecycle.opaque_key
    FROM ogvcs_metadata.lifecycle_publication_plan_items AS item
    JOIN ogvcs_metadata.object_lifecycle AS lifecycle
      ON lifecycle.repository_id = plan_row.repository_id
     AND lifecycle.tenant_id = plan_row.tenant_id
     AND lifecycle.opaque_key = item.opaque_key
     AND lifecycle.object_kind = item.object_kind
     AND lifecycle.object_digest = item.object_digest
    WHERE item.plan_id = requested_plan_id
    ORDER BY lifecycle.repository_id, lifecycle.opaque_key
    FOR UPDATE OF lifecycle;

    SELECT seal.object_count = count(item.global_ordinal)
           AND seal.object_count = count(lifecycle.opaque_key)
           AND COALESCE(bool_and(
                lifecycle.state = item.expected_state
                AND lifecycle.generation = item.expected_generation
                AND lifecycle.health = item.expected_health
                AND lifecycle.health_generation = item.expected_health_generation
                AND lifecycle.health_observation_digest
                    = item.current_health_observation_digest
                AND lifecycle.authority_binding_digest = item.authority_binding_digest
                AND lifecycle.backend_receipt_digest = item.current_backend_receipt_digest
                AND lifecycle.verification_receipt_digest
                    IS NOT DISTINCT FROM item.current_verification_receipt_digest
                AND (item.expected_state <> 'quarantined'
                     OR (item.expected_generation < 9007199254740991 AND EXISTS (
                        SELECT 1
                        FROM ogvcs_metadata.lifecycle_receipts AS receipt
                        WHERE receipt.receipt_digest = item.transition_verification_receipt_digest
                          AND receipt.receipt_kind = 'production-verification'
                          AND receipt.repository_id = plan_row.repository_id
                          AND receipt.tenant_id = plan_row.tenant_id
                          AND receipt.opaque_key = item.opaque_key
                          AND receipt.object_kind = item.object_kind
                          AND receipt.object_digest = item.object_digest
                          AND receipt.expected_state = 'quarantined'
                          AND receipt.expected_generation = item.expected_generation
                          AND receipt.target_state = 'available'
                          AND receipt.target_generation = item.expected_generation + 1
                          AND receipt.authority_binding_digest = item.authority_binding_digest
                          AND receipt.lifecycle_contract_digest
                              = plan_row.lifecycle_contract_digest
                     )))
           ), false)
    INTO bindings_valid
    FROM ogvcs_metadata.lifecycle_publication_plan_seals AS seal
    LEFT JOIN ogvcs_metadata.lifecycle_publication_plan_items AS item
      ON item.plan_id = seal.plan_id
    LEFT JOIN ogvcs_metadata.object_lifecycle AS lifecycle
      ON lifecycle.repository_id = plan_row.repository_id
     AND lifecycle.tenant_id = plan_row.tenant_id
     AND lifecycle.opaque_key = item.opaque_key
     AND lifecycle.object_kind = item.object_kind
     AND lifecycle.object_digest = item.object_digest
    WHERE seal.plan_id = requested_plan_id
    GROUP BY seal.object_count;
    RETURN COALESCE(bindings_valid, false);
END
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'lifecycle evidence is immutable';
END
$ogvcs$;

CREATE TRIGGER lifecycle_receipts_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_receipts
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_receipt_consumptions_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_receipt_consumptions
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_publication_plans_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_publication_plans
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_publication_plan_chunks_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_publication_plan_chunks
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_publication_plan_items_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_publication_plan_items
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_publication_plan_seals_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_publication_plan_seals
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_applications_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_applications
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_transaction_facts_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_transaction_facts
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_publication_reachability_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_publication_reachability
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_deletion_fences_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_deletion_fences
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

CREATE TRIGGER lifecycle_internal_outbox_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_internal_outbox
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

COMMIT;
