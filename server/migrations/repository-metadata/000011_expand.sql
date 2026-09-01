BEGIN;

-- Private OGVCS-010 candidate state. This migration deliberately does not
-- assign a public submit protocol or a disaster-recovery receipt format.
CREATE TABLE ogvcs_metadata.submit_intents (
    intent_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    lifecycle_plan_id uuid NOT NULL UNIQUE
        REFERENCES ogvcs_metadata.lifecycle_publication_plan_seals(plan_id),
    reference_name text NOT NULL CHECK (
        octet_length(reference_name) BETWEEN 1 AND 512
        AND reference_name !~ '[[:cntrl:]]'
    ),
    expected_head_digest bytea NOT NULL CHECK (octet_length(expected_head_digest) = 32),
    expected_generation bigint NOT NULL CHECK (expected_generation >= 1),
    candidate_snapshot_digest bytea NOT NULL
        CHECK (octet_length(candidate_snapshot_digest) = 32),
    candidate_change_set_digest bytea NOT NULL
        CHECK (octet_length(candidate_change_set_digest) = 32),
    lifecycle_plan_digest bytea NOT NULL CHECK (octet_length(lifecycle_plan_digest) = 32),
    authenticated_scope_digest bytea NOT NULL
        CHECK (octet_length(authenticated_scope_digest) = 32),
    idempotency_operation text NOT NULL CHECK (idempotency_operation = 'submit.finalize'),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 512),
    lifecycle_semantic_fingerprint bytea NOT NULL
        CHECK (octet_length(lifecycle_semantic_fingerprint) = 32),
    submit_fingerprint bytea NOT NULL CHECK (octet_length(submit_fingerprint) = 32),
    operation_count integer NOT NULL CHECK (operation_count BETWEEN 1 AND 1000),
    operation_set_digest bytea NOT NULL CHECK (octet_length(operation_set_digest) = 32),
    intent_digest bytea NOT NULL UNIQUE CHECK (octet_length(intent_digest) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (intent_id, repository_id, candidate_snapshot_digest),
    UNIQUE (authenticated_scope_digest, idempotency_operation, idempotency_key),
    CHECK (expires_at > created_at),
    FOREIGN KEY (repository_id, tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id),
    FOREIGN KEY (repository_id, expected_head_digest)
        REFERENCES ogvcs_metadata.snapshots(repository_id, snapshot_digest),
    FOREIGN KEY (repository_id, candidate_snapshot_digest)
        REFERENCES ogvcs_metadata.snapshots(repository_id, snapshot_digest)
);

CREATE TABLE ogvcs_metadata.submit_intent_operations (
    intent_id uuid NOT NULL,
    repository_id uuid NOT NULL,
    candidate_snapshot_digest bytea NOT NULL
        CHECK (octet_length(candidate_snapshot_digest) = 32),
    operation_ordinal integer NOT NULL CHECK (operation_ordinal BETWEEN 0 AND 999),
    -- This private candidate deliberately closes only lifetime-first-use
    -- operations. A later public submit contract must add and prove the
    -- remaining operation kinds rather than routing them through this table.
    operation_kind text NOT NULL CHECK (
        operation_kind IN ('create', 'copy', 'import')
    ),
    file_id bytea NOT NULL CHECK (
        octet_length(file_id) = 16 AND file_id <> decode(repeat('00', 16), 'hex')
    ),
    repository_path_utf8 bytea NOT NULL
        CHECK (octet_length(repository_path_utf8) BETWEEN 1 AND 4096),
    prior_owner_kind text NOT NULL CHECK (prior_owner_kind IN ('draft', 'shelf')),
    prior_owner_id text NOT NULL CHECK (octet_length(prior_owner_id) BETWEEN 1 AND 256),
    operation_digest bytea NOT NULL CHECK (octet_length(operation_digest) = 32),
    PRIMARY KEY (intent_id, operation_ordinal),
    UNIQUE (intent_id, operation_digest),
    UNIQUE (intent_id, file_id),
    FOREIGN KEY (intent_id, repository_id, candidate_snapshot_digest)
        REFERENCES ogvcs_metadata.submit_intents(
            intent_id, repository_id, candidate_snapshot_digest
        ) DEFERRABLE INITIALLY DEFERRED
);

-- Permanent, exact first-consumption evidence. FileIDs can be reserved and
-- candidate history can be staged before publication, but a create/copy/import
-- lifetime is consumed only here in the same transaction as lifecycle apply
-- and branch CAS. UNIQUE(repository_id, file_id) makes that first use global
-- for the repository lifetime.
CREATE TABLE ogvcs_metadata.submit_file_id_consumptions (
    intent_id uuid NOT NULL,
    operation_ordinal integer NOT NULL CHECK (operation_ordinal BETWEEN 0 AND 999),
    repository_id uuid NOT NULL,
    candidate_snapshot_digest bytea NOT NULL
        CHECK (octet_length(candidate_snapshot_digest) = 32),
    file_id bytea NOT NULL CHECK (
        octet_length(file_id) = 16 AND file_id <> decode(repeat('00', 16), 'hex')
    ),
    operation_kind text NOT NULL CHECK (operation_kind IN ('create', 'copy', 'import')),
    prior_owner_kind text NOT NULL CHECK (prior_owner_kind IN ('draft', 'shelf')),
    prior_owner_id text NOT NULL CHECK (octet_length(prior_owner_id) BETWEEN 1 AND 256),
    result_owner_kind text NOT NULL CHECK (result_owner_kind = 'published'),
    result_owner_id text NOT NULL CHECK (octet_length(result_owner_id) BETWEEN 1 AND 256),
    application_id uuid NOT NULL
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    consumption_digest bytea NOT NULL UNIQUE CHECK (octet_length(consumption_digest) = 32),
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (intent_id, operation_ordinal),
    UNIQUE (intent_id, file_id),
    UNIQUE (repository_id, file_id),
    FOREIGN KEY (intent_id, operation_ordinal)
        REFERENCES ogvcs_metadata.submit_intent_operations(intent_id, operation_ordinal)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (intent_id, repository_id, candidate_snapshot_digest)
        REFERENCES ogvcs_metadata.submit_intents(
            intent_id, repository_id, candidate_snapshot_digest
        ) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.submit_preflights (
    preflight_id uuid PRIMARY KEY,
    intent_id uuid NOT NULL REFERENCES ogvcs_metadata.submit_intents(intent_id),
    preflight_revision bigint NOT NULL CHECK (preflight_revision >= 1),
    observed_head_digest bytea NOT NULL CHECK (octet_length(observed_head_digest) = 32),
    observed_generation bigint NOT NULL CHECK (observed_generation >= 1),
    branch_matches boolean NOT NULL,
    lifecycle_plan_digest bytea NOT NULL CHECK (octet_length(lifecycle_plan_digest) = 32),
    operation_set_digest bytea NOT NULL CHECK (octet_length(operation_set_digest) = 32),
    mutable_checks_repeat boolean NOT NULL CHECK (mutable_checks_repeat),
    preflight_digest bytea NOT NULL UNIQUE CHECK (octet_length(preflight_digest) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (intent_id, preflight_revision),
    CHECK (expires_at > created_at)
);

CREATE TABLE ogvcs_metadata.submit_internal_audit_evidence (
    audit_correlation_id uuid PRIMARY KEY,
    intent_id uuid NOT NULL UNIQUE REFERENCES ogvcs_metadata.submit_intents(intent_id),
    application_id uuid NOT NULL UNIQUE
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    event_class text NOT NULL CHECK (event_class = 'internal.submit-committed-candidate/v1'),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    protected_event_digest bytea NOT NULL UNIQUE
        CHECK (octet_length(protected_event_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ogvcs_metadata.submit_final_outcomes (
    intent_id uuid PRIMARY KEY REFERENCES ogvcs_metadata.submit_intents(intent_id),
    application_id uuid NOT NULL UNIQUE
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    identity_plan_id text NOT NULL,
    consumption_id text NOT NULL CHECK (
        octet_length(consumption_id) BETWEEN 1 AND 256
        AND consumption_id !~ '[^A-Za-z0-9._:-]'
    ),
    operation_digest bytea NOT NULL CHECK (octet_length(operation_digest) = 32),
    old_head_digest bytea NOT NULL CHECK (octet_length(old_head_digest) = 32),
    new_head_digest bytea NOT NULL CHECK (octet_length(new_head_digest) = 32),
    branch_generation bigint NOT NULL CHECK (branch_generation >= 2),
    commit_sequence bigint NOT NULL CHECK (commit_sequence >= 1),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    audit_correlation_id uuid NOT NULL UNIQUE
        REFERENCES ogvcs_metadata.submit_internal_audit_evidence(audit_correlation_id),
    outbox_event_id uuid NOT NULL UNIQUE REFERENCES ogvcs_metadata.outbox_events(event_id),
    consistency_token text NOT NULL CHECK (consistency_token ~ '^ct1\.[A-Za-z0-9_-]{43}$'),
    consistency_token_digest bytea NOT NULL UNIQUE
        CHECK (octet_length(consistency_token_digest) = 32)
        REFERENCES ogvcs_metadata.consistency_tokens(token_digest),
    result_digest bytea NOT NULL UNIQUE CHECK (octet_length(result_digest) = 32),
    reconciliation_commitment_digest bytea NOT NULL UNIQUE
        CHECK (octet_length(reconciliation_commitment_digest) = 32),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (identity_plan_id, consumption_id, operation_digest),
    FOREIGN KEY (identity_plan_id, consumption_id, operation_digest)
        REFERENCES ogvcs_identity.aggregate_plan_consumptions(
            plan_id, consumption_id, operation_digest
        ) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.submit_reconciliation_records (
    reconciliation_id uuid PRIMARY KEY,
    intent_id uuid NOT NULL REFERENCES ogvcs_metadata.submit_intents(intent_id),
    observed_result text NOT NULL CHECK (
        observed_result IN ('committed', 'unknown-recovering')
    ),
    outcome_digest bytea CHECK (outcome_digest IS NULL OR octet_length(outcome_digest) = 32),
    authority_epoch bigint CHECK (authority_epoch IS NULL OR authority_epoch >= 1),
    observation_digest bytea NOT NULL UNIQUE CHECK (octet_length(observation_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (observed_result = 'committed') =
        (outcome_digest IS NOT NULL AND authority_epoch IS NOT NULL)
    )
);

CREATE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'submit evidence is immutable';
END;
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.reject_sealed_submit_operation_insert_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ogvcs_metadata.submit_intents
        WHERE intent_id = NEW.intent_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'submit operation set is sealed';
    END IF;
    RETURN NEW;
END;
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.reject_completed_submit_consumption_insert_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ogvcs_metadata.submit_final_outcomes
        WHERE intent_id = NEW.intent_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'submit FileID evidence is sealed';
    END IF;
    RETURN NEW;
END;
$ogvcs$;

CREATE TRIGGER submit_intents_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_intents
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();
CREATE TRIGGER submit_operations_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_intent_operations
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();
CREATE TRIGGER submit_operations_sealed_insert_v11
BEFORE INSERT ON ogvcs_metadata.submit_intent_operations
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_sealed_submit_operation_insert_v11();
CREATE TRIGGER submit_file_id_consumptions_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_file_id_consumptions
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();
CREATE TRIGGER submit_file_id_consumptions_sealed_insert_v11
BEFORE INSERT ON ogvcs_metadata.submit_file_id_consumptions
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_completed_submit_consumption_insert_v11();
CREATE TRIGGER submit_preflights_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_preflights
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();
CREATE TRIGGER submit_audit_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_internal_audit_evidence
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();
CREATE TRIGGER submit_outcomes_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_final_outcomes
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();
CREATE TRIGGER submit_reconciliations_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.submit_reconciliation_records
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_submit_evidence_mutation_v11();

CREATE FUNCTION ogvcs_metadata.validate_submit_intent_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_publication_plans AS plan
        JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal USING (plan_id)
        WHERE plan.plan_id = NEW.lifecycle_plan_id
          AND plan.tenant_id = NEW.tenant_id
          AND plan.repository_id = NEW.repository_id
          AND plan.publication_kind = 7
          AND plan.publication_digest = NEW.candidate_snapshot_digest
          AND plan.authorization_reference = NEW.reference_name
          AND plan.declared_plan_digest = NEW.lifecycle_plan_digest
          AND seal.plan_digest = NEW.lifecycle_plan_digest
          AND plan.idempotency_scope_digest = NEW.authenticated_scope_digest
          AND plan.idempotency_operation = NEW.idempotency_operation
          AND plan.idempotency_key = NEW.idempotency_key
          AND plan.semantic_fingerprint = NEW.lifecycle_semantic_fingerprint
          AND plan.expires_at = NEW.expires_at
          AND EXISTS (
              SELECT 1
              FROM ogvcs_metadata.object_edges AS edge
              WHERE edge.repository_id = NEW.repository_id
                AND edge.source_kind = 7
                AND edge.source_digest = NEW.candidate_snapshot_digest
                AND edge.target_kind = 4
                AND edge.target_digest = NEW.candidate_change_set_digest
          )
          AND (SELECT count(*) FROM ogvcs_metadata.submit_intent_operations AS operation
               WHERE operation.intent_id = NEW.intent_id) = NEW.operation_count
          AND (SELECT count(*) FROM ogvcs_metadata.file_path_history AS history
               WHERE history.repository_id = NEW.repository_id
                 AND history.snapshot_digest = NEW.candidate_snapshot_digest) = NEW.operation_count
          AND (SELECT min(operation_ordinal)
               FROM ogvcs_metadata.submit_intent_operations
               WHERE intent_id = NEW.intent_id) = 0
          AND (SELECT max(operation_ordinal)
               FROM ogvcs_metadata.submit_intent_operations
               WHERE intent_id = NEW.intent_id) = NEW.operation_count - 1
          AND NOT EXISTS (
              SELECT 1
              FROM ogvcs_metadata.submit_intent_operations AS operation
              FULL JOIN ogvcs_metadata.file_path_history AS history
                ON history.repository_id = operation.repository_id
               AND history.snapshot_digest = operation.candidate_snapshot_digest
               AND history.operation_ordinal = operation.operation_ordinal
               AND history.operation_kind = operation.operation_kind
               AND history.file_id = operation.file_id
               AND history.repository_path_utf8 = operation.repository_path_utf8
              WHERE (operation.intent_id = NEW.intent_id
                     OR (history.repository_id = NEW.repository_id
                         AND history.snapshot_digest = NEW.candidate_snapshot_digest))
                AND (operation.intent_id IS NULL OR history.repository_id IS NULL)
          )
          AND NOT EXISTS (
              SELECT 1
              FROM ogvcs_metadata.submit_intent_operations AS operation
              LEFT JOIN ogvcs_metadata.file_id_registry AS registry
                ON registry.repository_id = operation.repository_id
               AND registry.file_id = operation.file_id
              WHERE operation.intent_id = NEW.intent_id
                AND (
                    registry.file_id IS NULL
                    OR registry.state <> 'active'
                    OR registry.origin::text <> operation.operation_kind
                    OR registry.owner_kind NOT IN ('draft', 'shelf')
                    OR registry.owner_kind::text <> operation.prior_owner_kind
                    OR registry.owner_id <> operation.prior_owner_id
                    OR registry.first_change_set_digest <> NEW.candidate_change_set_digest
                    OR registry.first_operation <> operation.operation_ordinal
                    OR (
                        operation.operation_kind = 'import'
                        AND NOT EXISTS (
                            SELECT 1
                            FROM ogvcs_metadata.file_id_import_mappings AS mapping
                            WHERE mapping.repository_id = operation.repository_id
                              AND mapping.file_id = operation.file_id
                        )
                    )
                )
          )
    ) INTO complete;
    IF NOT complete THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'incomplete submit intent';
    END IF;
    RETURN NULL;
END;
$ogvcs$;

CREATE CONSTRAINT TRIGGER submit_intent_complete_v11
AFTER INSERT ON ogvcs_metadata.submit_intents
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.validate_submit_intent_v11();

CREATE FUNCTION ogvcs_metadata.validate_submit_outcome_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.submit_intents AS intent
        JOIN ogvcs_metadata.lifecycle_aggregate_authorization_evidence AS auth_evidence
          ON auth_evidence.lifecycle_plan_id = intent.lifecycle_plan_id
        JOIN ogvcs_metadata.lifecycle_applications AS application
          ON application.application_id = auth_evidence.application_id
        JOIN ogvcs_metadata.submit_internal_audit_evidence AS audit
          ON audit.audit_correlation_id = NEW.audit_correlation_id
        JOIN ogvcs_metadata.outbox_events AS event
          ON event.event_id = NEW.outbox_event_id
        JOIN ogvcs_metadata.consistency_tokens AS token
          ON token.token_digest = NEW.consistency_token_digest
        JOIN ogvcs_metadata.snapshots AS snapshot
          ON snapshot.repository_id = intent.repository_id
         AND snapshot.snapshot_digest = intent.candidate_snapshot_digest
        JOIN ogvcs_metadata.references AS reference
          ON reference.repository_id = intent.repository_id
         AND reference.reference_kind = 'branch'
         AND reference.reference_name = intent.reference_name
        WHERE intent.intent_id = NEW.intent_id
          AND application.application_id = NEW.application_id
          AND auth_evidence.identity_plan_id = NEW.identity_plan_id
          AND auth_evidence.consumption_id = NEW.consumption_id
          AND auth_evidence.operation_digest = NEW.operation_digest
          AND NEW.old_head_digest = intent.expected_head_digest
          AND NEW.new_head_digest = intent.candidate_snapshot_digest
          AND NEW.branch_generation = intent.expected_generation + 1
          AND NEW.commit_sequence = application.commit_sequence
          AND NEW.authority_epoch = application.authorization_epoch
          AND audit.intent_id = NEW.intent_id
          AND audit.application_id = NEW.application_id
          AND audit.authority_epoch = NEW.authority_epoch
          AND event.tenant_id = intent.tenant_id
          AND event.repository_id = intent.repository_id
          AND event.commit_sequence = NEW.commit_sequence
          AND event.correlation_id = NEW.audit_correlation_id
          AND event.event_type = 'internal.submit-committed-candidate'
          AND event.event_version = 1
          AND event.resource_type = 'reference'
          AND token.subject_digest = application.subject_digest
          AND token.tenant_id = intent.tenant_id
          AND token.repository_id = intent.repository_id
          AND token.minimum_commit_sequence = NEW.commit_sequence
          AND token.authorization_epoch = NEW.authority_epoch
          AND token.authenticated_scope_digest = intent.authenticated_scope_digest
          AND snapshot.published_commit_sequence = NEW.commit_sequence
          AND reference.target_snapshot_digest = NEW.new_head_digest
          AND reference.generation = NEW.branch_generation
          AND reference.commit_sequence = NEW.commit_sequence
          AND EXISTS (
              SELECT 1
              FROM ogvcs_metadata.submit_reconciliation_records AS reconciliation
              WHERE reconciliation.intent_id = NEW.intent_id
                AND reconciliation.observed_result = 'committed'
                AND reconciliation.outcome_digest = NEW.result_digest
                AND reconciliation.authority_epoch = NEW.authority_epoch
          )
          AND (SELECT count(*)
               FROM ogvcs_metadata.submit_file_id_consumptions AS consumption
               WHERE consumption.intent_id = NEW.intent_id) = intent.operation_count
          AND NOT EXISTS (
              SELECT 1
              FROM ogvcs_metadata.submit_intent_operations AS operation
              LEFT JOIN ogvcs_metadata.submit_file_id_consumptions AS consumption
                ON consumption.intent_id = operation.intent_id
               AND consumption.operation_ordinal = operation.operation_ordinal
               AND consumption.repository_id = operation.repository_id
               AND consumption.candidate_snapshot_digest = intent.candidate_snapshot_digest
               AND consumption.file_id = operation.file_id
               AND consumption.operation_kind = operation.operation_kind
               AND consumption.prior_owner_kind = operation.prior_owner_kind
               AND consumption.prior_owner_id = operation.prior_owner_id
               AND consumption.application_id = NEW.application_id
               AND consumption.result_owner_kind = 'published'
               AND consumption.result_owner_id = encode(intent.candidate_snapshot_digest, 'hex')
              LEFT JOIN ogvcs_metadata.file_id_registry AS registry
                ON registry.repository_id = operation.repository_id
               AND registry.file_id = operation.file_id
              WHERE operation.intent_id = NEW.intent_id
                AND (
                    consumption.intent_id IS NULL
                    OR registry.state <> 'active'
                    OR registry.origin::text <> operation.operation_kind
                    OR registry.owner_kind <> 'published'
                    OR registry.owner_id <> encode(intent.candidate_snapshot_digest, 'hex')
                    OR registry.first_change_set_digest <> intent.candidate_change_set_digest
                    OR registry.first_operation <> operation.operation_ordinal
                )
          )
    ) INTO complete;
    IF NOT complete THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'incomplete submit outcome';
    END IF;
    RETURN NULL;
END;
$ogvcs$;

CREATE CONSTRAINT TRIGGER submit_outcome_complete_v11
AFTER INSERT ON ogvcs_metadata.submit_final_outcomes
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.validate_submit_outcome_v11();

CREATE FUNCTION ogvcs_metadata.protect_committed_submit_dependencies_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ogvcs_metadata.submit_final_outcomes
        WHERE outbox_event_id = OLD.event_id
    ) THEN
        -- Delivery ownership is mutable by the outbox service. The committed
        -- event identity and payload are not.
        IF TG_OP = 'DELETE' OR (
            NEW.event_id IS DISTINCT FROM OLD.event_id
            OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
            OR NEW.commit_sequence IS DISTINCT FROM OLD.commit_sequence
            OR NEW.event_type IS DISTINCT FROM OLD.event_type
            OR NEW.event_version IS DISTINCT FROM OLD.event_version
            OR NEW.correlation_id IS DISTINCT FROM OLD.correlation_id
            OR NEW.resource_type IS DISTINCT FROM OLD.resource_type
            OR NEW.resource_opaque_id IS DISTINCT FROM OLD.resource_opaque_id
            OR NEW.safe_payload IS DISTINCT FROM OLD.safe_payload
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'committed submit event identity is immutable';
        END IF;
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.protect_committed_submit_token_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ogvcs_metadata.submit_final_outcomes
        WHERE consistency_token_digest = OLD.token_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'committed submit dependency is immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$ogvcs$;

CREATE FUNCTION ogvcs_metadata.protect_committed_submit_snapshot_v11()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ogvcs_metadata.submit_final_outcomes AS outcome
        JOIN ogvcs_metadata.submit_intents AS intent USING (intent_id)
        WHERE intent.repository_id = OLD.repository_id
          AND intent.candidate_snapshot_digest = OLD.snapshot_digest
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'committed submit dependency is immutable';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$ogvcs$;

CREATE TRIGGER submit_outbox_dependency_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.outbox_events
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.protect_committed_submit_dependencies_v11();
CREATE TRIGGER submit_token_dependency_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.consistency_tokens
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.protect_committed_submit_token_v11();
CREATE TRIGGER submit_snapshot_dependency_immutable_v11
BEFORE UPDATE OR DELETE ON ogvcs_metadata.snapshots
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.protect_committed_submit_snapshot_v11();

COMMIT;
