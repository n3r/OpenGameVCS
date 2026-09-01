BEGIN;

-- V10 is the production bridge from the sealed OGVCS-009 aggregate receipt
-- to the v9 lifecycle plan. Existing v9 rows remain readable but are not
-- bridge-eligible until a new server-derived plan supplies these exact facts.
ALTER TABLE ogvcs_metadata.lifecycle_publication_plans
    ADD COLUMN authorization_reference text,
    ADD COLUMN authorization_snapshot text,
    ADD CONSTRAINT lifecycle_plan_authorization_binding_v10 CHECK (
        (authorization_reference IS NULL AND authorization_snapshot IS NULL)
        OR
        (octet_length(authorization_reference) BETWEEN 1 AND 512
         AND authorization_reference !~ '[[:cntrl:]]'
         AND octet_length(authorization_snapshot) BETWEEN 1 AND 160
         AND authorization_snapshot !~ '[^A-Za-z0-9._:-]')
    );

-- Direct application remains capped at 1,024 by lifecycle_applications. The
-- shared evidence tables must additionally admit the aggregate 100,000 cap.
ALTER TABLE ogvcs_metadata.lifecycle_transaction_facts
    DROP CONSTRAINT lifecycle_transaction_facts_fact_ordinal_check,
    ADD CONSTRAINT lifecycle_transaction_facts_fact_ordinal_check
        CHECK (fact_ordinal BETWEEN 0 AND 99999);

ALTER TABLE ogvcs_metadata.lifecycle_internal_outbox
    DROP CONSTRAINT lifecycle_internal_outbox_fact_ordinal_check,
    ADD CONSTRAINT lifecycle_internal_outbox_fact_ordinal_check
        CHECK (fact_ordinal IS NULL OR fact_ordinal BETWEEN 0 AND 99999);

CREATE TABLE ogvcs_metadata.lifecycle_aggregate_authorization_evidence (
    application_id uuid PRIMARY KEY
        REFERENCES ogvcs_metadata.lifecycle_applications(application_id),
    lifecycle_plan_id uuid NOT NULL UNIQUE
        REFERENCES ogvcs_metadata.lifecycle_publication_plan_seals(plan_id),
    identity_plan_id text NOT NULL
        REFERENCES ogvcs_identity.aggregate_decision_commitments(plan_id),
    consumption_id text NOT NULL CHECK (
        octet_length(consumption_id) BETWEEN 1 AND 256
        AND consumption_id !~ '[^A-Za-z0-9._:-]'
    ),
    operation_digest bytea NOT NULL CHECK (octet_length(operation_digest) = 32),
    identity_decision_digest bytea NOT NULL
        CHECK (octet_length(identity_decision_digest) = 32),
    identity_plan_nonce bytea NOT NULL CHECK (octet_length(identity_plan_nonce) = 32),
    metadata_tenant_id uuid NOT NULL,
    metadata_repository_id uuid NOT NULL,
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    authenticated_scope_digest bytea NOT NULL
        CHECK (octet_length(authenticated_scope_digest) = 32),
    credential_generation bigint NOT NULL CHECK (credential_generation >= 1),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    security_epoch bigint NOT NULL CHECK (security_epoch >= 1),
    policy_generation bigint NOT NULL CHECK (policy_generation >= 1),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    settings_generation bigint NOT NULL CHECK (settings_generation >= 1),
    settings_descriptor_digest bytea NOT NULL
        CHECK (octet_length(settings_descriptor_digest) = 32),
    path_profile text NOT NULL CHECK (octet_length(path_profile) BETWEEN 1 AND 128),
    case_mode text NOT NULL CHECK (case_mode IN ('case-sensitive', 'case-folded')),
    permission text NOT NULL CHECK (permission = 'submit'),
    capability text NOT NULL CHECK (capability = 'submit.consume-publication'),
    authorization_reference text NOT NULL
        CHECK (octet_length(authorization_reference) BETWEEN 1 AND 512),
    authorization_snapshot text NOT NULL
        CHECK (octet_length(authorization_snapshot) BETWEEN 1 AND 160),
    reason_digest bytea NOT NULL CHECK (octet_length(reason_digest) = 32),
    resource_count integer NOT NULL CHECK (resource_count BETWEEN 1 AND 100000),
    resource_set_digest bytea NOT NULL CHECK (octet_length(resource_set_digest) = 32),
    resource_digest_projection_digest bytea NOT NULL
        CHECK (octet_length(resource_digest_projection_digest) = 32),
    signer_key_generation bigint NOT NULL CHECK (signer_key_generation >= 1),
    signer_key_reference text NOT NULL CHECK (
        octet_length(signer_key_reference) BETWEEN 1 AND 256
    ),
    signer_key_fingerprint bytea NOT NULL
        CHECK (octet_length(signer_key_fingerprint) = 32),
    identity_issued_at_epoch bigint NOT NULL CHECK (identity_issued_at_epoch >= 1),
    identity_expires_at_epoch bigint NOT NULL CHECK (
        identity_expires_at_epoch > identity_issued_at_epoch
    ),
    lifecycle_plan_digest bytea NOT NULL CHECK (octet_length(lifecycle_plan_digest) = 32),
    lifecycle_chunk_count integer NOT NULL CHECK (lifecycle_chunk_count BETWEEN 1 AND 100),
    lifecycle_encoded_bytes bigint NOT NULL
        CHECK (lifecycle_encoded_bytes BETWEEN 1 AND 104857600),
    lifecycle_expires_at timestamptz NOT NULL,
    lifecycle_contract_manifest_digest bytea NOT NULL CHECK (
        lifecycle_contract_manifest_digest =
        decode('1b6fac7f90f03b3470786e5e3ed810f7dbcc9a041d735a621c79feefecd15efa', 'hex')
    ),
    lifecycle_contract_artifact_set_digest bytea NOT NULL CHECK (
        lifecycle_contract_artifact_set_digest =
        decode('556f289fe90c91c85fdcd812e1576276b206287bd18333beb7caea0457c1bbae', 'hex')
    ),
    object_transfer_manifest_digest bytea NOT NULL
        CHECK (
            object_transfer_manifest_digest =
            decode('6748334b4cbc9b155941d8382b6a67c348f0612432a9555cfa215f62681af1d3', 'hex')
        ),
    object_transfer_artifact_set_digest bytea NOT NULL
        CHECK (
            object_transfer_artifact_set_digest =
            decode('8e96a6fc57aeabb9c3bd8a363b4bbb70b2bfc4832206b20c1581e92e463bec38', 'hex')
        ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (identity_plan_id, consumption_id, operation_digest),
    FOREIGN KEY (identity_plan_id, consumption_id, operation_digest)
        REFERENCES ogvcs_identity.aggregate_plan_consumptions(
            plan_id, consumption_id, operation_digest
        ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (metadata_repository_id, metadata_tenant_id)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id)
);

-- Runtime inserts the application, its bounded child evidence, and finally
-- the aggregate authorization row in one transaction. Once that final row
-- exists, no later transaction may inflate any exact child cardinality.
CREATE FUNCTION ogvcs_metadata.reject_sealed_aggregate_child_insert_v10()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence AS evidence
        WHERE evidence.application_id = NEW.application_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'aggregate lifecycle child evidence is sealed';
    END IF;
    RETURN NEW;
END;
$ogvcs$;

CREATE TRIGGER lifecycle_transaction_facts_aggregate_sealed_v10
BEFORE INSERT ON ogvcs_metadata.lifecycle_transaction_facts
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_sealed_aggregate_child_insert_v10();

CREATE TRIGGER lifecycle_reachability_aggregate_sealed_v10
BEFORE INSERT ON ogvcs_metadata.lifecycle_publication_reachability
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_sealed_aggregate_child_insert_v10();

CREATE TRIGGER lifecycle_outbox_aggregate_sealed_v10
BEFORE INSERT ON ogvcs_metadata.lifecycle_internal_outbox
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_sealed_aggregate_child_insert_v10();

CREATE FUNCTION ogvcs_metadata.validate_lifecycle_aggregate_evidence_v10()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
DECLARE
    complete boolean;
BEGIN
    IF NEW.application_kind <> 'aggregate' THEN
        RETURN NEW;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM ogvcs_metadata.lifecycle_aggregate_authorization_evidence AS evidence
        JOIN ogvcs_metadata.lifecycle_publication_plans AS plan
          ON plan.plan_id = evidence.lifecycle_plan_id
        JOIN ogvcs_metadata.lifecycle_publication_plan_seals AS seal
          ON seal.plan_id = plan.plan_id
        JOIN ogvcs_identity.aggregate_decision_commitments AS decision
          ON decision.plan_id = evidence.identity_plan_id
        JOIN ogvcs_identity.aggregate_plans AS identity_plan
          ON identity_plan.plan_id = decision.plan_id
        WHERE evidence.application_id = NEW.application_id
          AND evidence.lifecycle_plan_id = NEW.plan_id
          AND NEW.context_digest = evidence.operation_digest
          AND plan.tenant_id = NEW.tenant_id
          AND plan.repository_id = NEW.repository_id
          AND plan.subject_digest = NEW.subject_digest
          AND plan.authorization_epoch = NEW.authorization_epoch
          AND plan.authority_contract_digest = NEW.authority_contract_digest
          AND plan.authority_contract_digest =
              decode('3fb4dd4a89eb914f93a589b013bda8afcf4744c0d27171ee5849ca3b7bf62447', 'hex')
          AND plan.lifecycle_contract_digest = NEW.lifecycle_contract_digest
          AND plan.lifecycle_contract_digest = evidence.lifecycle_contract_manifest_digest
          AND plan.candidate_digest = NEW.candidate_digest
          AND plan.publication_kind = NEW.publication_kind
          AND plan.publication_digest = NEW.publication_digest
          AND plan.declared_plan_digest = NEW.lifecycle_plan_digest
          AND plan.idempotency_scope_digest = NEW.idempotency_scope_digest
          AND plan.idempotency_operation = NEW.idempotency_operation
          AND plan.idempotency_key = NEW.idempotency_key
          AND plan.semantic_fingerprint = NEW.semantic_fingerprint
          AND plan.declared_object_count = NEW.object_count
          AND plan.authorization_reference = evidence.authorization_reference
          AND plan.authorization_snapshot = evidence.authorization_snapshot
          AND seal.object_count = evidence.resource_count
          AND seal.chunk_count = evidence.lifecycle_chunk_count
          AND seal.encoded_bytes = evidence.lifecycle_encoded_bytes
          AND seal.plan_digest = evidence.lifecycle_plan_digest
          AND plan.expires_at = evidence.lifecycle_expires_at
          AND decision.subject_digest = evidence.subject_digest
          AND decision.authenticated_scope_digest = evidence.authenticated_scope_digest
          AND decision.credential_generation = evidence.credential_generation
          AND decision.authority_epoch = evidence.authority_epoch
          AND decision.security_epoch = evidence.security_epoch
          AND decision.policy_generation = evidence.policy_generation
          AND decision.policy_digest = evidence.policy_digest
          AND decision.metadata_tenant_id = evidence.metadata_tenant_id::text
          AND decision.metadata_repository_id = evidence.metadata_repository_id::text
          AND decision.settings_generation = evidence.settings_generation
          AND decision.settings_descriptor_digest = evidence.settings_descriptor_digest
          AND decision.path_profile = evidence.path_profile
          AND decision.case_mode = evidence.case_mode
          AND decision.permission = evidence.permission
          AND decision.capability = evidence.capability
          AND decision.reference_name = evidence.authorization_reference
          AND decision.snapshot_id = evidence.authorization_snapshot
          AND decision.reason_digest = evidence.reason_digest
          AND decision.resource_count = evidence.resource_count
          AND decision.resource_set_digest = evidence.resource_set_digest
          AND decision.resource_digest_projection_digest
              = evidence.resource_digest_projection_digest
          AND decision.decision_digest = evidence.identity_decision_digest
          AND decision.signer_key_generation = evidence.signer_key_generation
          AND identity_plan.state = 'consumed'
          AND identity_plan.item_count = evidence.resource_count
          AND identity_plan.resource_set_digest = evidence.resource_set_digest
          AND identity_plan.resource_digest_projection_digest
              = evidence.resource_digest_projection_digest
          AND identity_plan.decision_digest = evidence.identity_decision_digest
          AND identity_plan.upload_nonce = evidence.identity_plan_nonce
          AND EXTRACT(EPOCH FROM identity_plan.issued_at)
              = evidence.identity_issued_at_epoch::numeric
          AND EXTRACT(EPOCH FROM identity_plan.expires_at)
              = evidence.identity_expires_at_epoch::numeric
          AND identity_plan.signer_key_generation = evidence.signer_key_generation
          AND identity_plan.signer_key_reference = evidence.signer_key_reference
          AND identity_plan.signer_key_fingerprint = evidence.signer_key_fingerprint
          AND evidence.metadata_tenant_id = NEW.tenant_id
          AND evidence.metadata_repository_id = NEW.repository_id
    )
    AND (SELECT count(*) FROM ogvcs_metadata.lifecycle_transaction_facts AS fact
         WHERE fact.application_id = NEW.application_id) = NEW.object_count
    AND (SELECT count(*) FROM ogvcs_metadata.lifecycle_publication_reachability AS reachability
         WHERE reachability.application_id = NEW.application_id) = NEW.object_count
    AND (SELECT count(*) FROM ogvcs_metadata.lifecycle_internal_outbox AS outbox
         WHERE outbox.application_id = NEW.application_id
           AND NOT outbox.aggregate_event) = NEW.object_count
    AND (SELECT count(*) FROM ogvcs_metadata.lifecycle_internal_outbox AS outbox
         WHERE outbox.application_id = NEW.application_id
           AND outbox.aggregate_event) = 1
    INTO complete;

    IF NOT COALESCE(complete, false) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'aggregate lifecycle authorization evidence is incomplete';
    END IF;
    RETURN NEW;
END
$ogvcs$;

CREATE CONSTRAINT TRIGGER lifecycle_aggregate_evidence_complete_v10
AFTER INSERT ON ogvcs_metadata.lifecycle_applications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.validate_lifecycle_aggregate_evidence_v10();

CREATE TRIGGER lifecycle_aggregate_authorization_evidence_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.lifecycle_aggregate_authorization_evidence
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_lifecycle_immutable_mutation();

COMMIT;
