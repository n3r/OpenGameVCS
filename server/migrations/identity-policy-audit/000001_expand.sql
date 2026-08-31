BEGIN;

CREATE SCHEMA ogvcs_identity;

CREATE TABLE ogvcs_identity.schema_migrations (
    version bigint NOT NULL,
    phase text NOT NULL CHECK (phase IN ('expand', 'migrate', 'contract')),
    checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('started', 'completed')),
    minimum_application_version text NOT NULL,
    maximum_application_version text NOT NULL,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (version, phase),
    CHECK ((state = 'completed') = (completed_at IS NOT NULL))
);

CREATE TABLE ogvcs_identity.authority_states (
    tenant_id text PRIMARY KEY CHECK (tenant_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    key_generation bigint NOT NULL CHECK (key_generation >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE ogvcs_identity.credentials (
    tenant_id text NOT NULL REFERENCES ogvcs_identity.authority_states(tenant_id),
    credential_id text NOT NULL CHECK (credential_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    credential_generation bigint NOT NULL CHECK (credential_generation >= 1),
    presentation_digest bytea NOT NULL UNIQUE CHECK (octet_length(presentation_digest) = 32),
    subject_id text NOT NULL CHECK (subject_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    actor_class text NOT NULL CHECK (actor_class IN ('human', 'service', 'administrator')),
    credential_class text NOT NULL CHECK (credential_class IN ('session', 'service-token')),
    groups_json jsonb NOT NULL CHECK (jsonb_typeof(groups_json) = 'array'),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'revoked')),
    revoked_at timestamptz,
    scope_json jsonb NOT NULL CHECK (jsonb_typeof(scope_json) = 'object'),
    scope_digest bytea NOT NULL CHECK (octet_length(scope_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, credential_id, credential_generation),
    CHECK (expires_at > issued_at),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX credentials_by_subject_generation
    ON ogvcs_identity.credentials(tenant_id, subject_id, credential_class, credential_generation DESC);

CREATE TABLE ogvcs_identity.policy_versions (
    tenant_id text NOT NULL REFERENCES ogvcs_identity.authority_states(tenant_id),
    repository_id text NOT NULL CHECK (repository_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    policy_generation bigint NOT NULL CHECK (policy_generation >= 1),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    policy_id text NOT NULL CHECK (policy_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    policy_version text NOT NULL CHECK (policy_version ~ '^[a-z][a-z0-9.-]{0,127}$'),
    path_profile text NOT NULL CHECK (octet_length(path_profile) BETWEEN 1 AND 328),
    case_mode text NOT NULL CHECK (case_mode IN ('case-sensitive', 'case-folded')),
    policy_json jsonb NOT NULL CHECK (jsonb_typeof(policy_json) = 'object'),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, policy_generation)
);

CREATE TABLE ogvcs_identity.current_policies (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL CHECK (policy_generation >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id),
    FOREIGN KEY (tenant_id, repository_id, policy_generation)
        REFERENCES ogvcs_identity.policy_versions(tenant_id, repository_id, policy_generation)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_identity.decision_chain_heads (
    tenant_id text PRIMARY KEY REFERENCES ogvcs_identity.authority_states(tenant_id),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    tail_hash bytea CHECK (tail_hash IS NULL OR octet_length(tail_hash) = 32),
    CHECK ((sequence = 0) = (tail_hash IS NULL))
);

CREATE TABLE ogvcs_identity.transaction_decision_commitments (
    commitment_id text PRIMARY KEY CHECK (octet_length(commitment_id) BETWEEN 1 AND 256 AND commitment_id ~ '^[A-Za-z0-9._:-]+$'),
    transaction_id text NOT NULL CHECK (octet_length(transaction_id) BETWEEN 1 AND 256 AND transaction_id ~ '^[A-Za-z0-9._:-]+$'),
    correlation_id text NOT NULL CHECK (octet_length(correlation_id) BETWEEN 1 AND 256 AND correlation_id ~ '^[A-Za-z0-9._:-]+$'),
    tenant_id text NOT NULL REFERENCES ogvcs_identity.authority_states(tenant_id),
    repository_id text NOT NULL CHECK (repository_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest) = 32),
    resource_set_digest bytea NOT NULL CHECK (octet_length(resource_set_digest) = 32),
    result_digest bytea NOT NULL CHECK (octet_length(result_digest) = 32),
    sequence bigint NOT NULL CHECK (sequence >= 1),
    previous_hash bytea CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
    record_hash bytea NOT NULL CHECK (octet_length(record_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, sequence),
    UNIQUE (tenant_id, transaction_id),
    CHECK ((sequence = 1) = (previous_hash IS NULL))
);

CREATE INDEX decision_commitments_by_tenant_sequence
    ON ogvcs_identity.transaction_decision_commitments(tenant_id, sequence);

-- Frozen OGVCS-003 AuditEvent storage is deliberately separate from ordinary
-- authorization decision commitments. This participant emits only the three
-- policy-authority classes it owns.
CREATE TABLE ogvcs_identity.privileged_audit_events (
    schema_version text NOT NULL CHECK (schema_version = 'ogvcs.authorization/audit-event/v1'),
    event_id text PRIMARY KEY CHECK (octet_length(event_id) BETWEEN 1 AND 256 AND event_id ~ '^[A-Za-z0-9._:-]+$'),
    event_class text NOT NULL CHECK (event_class IN ('policy.changed', 'grant.revoked', 'authority.epoch-changed')),
    occurred_at bigint NOT NULL CHECK (occurred_at >= 0),
    tenant_id text NOT NULL REFERENCES ogvcs_identity.authority_states(tenant_id),
    repository_id text NOT NULL CHECK (repository_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    actor_class text NOT NULL CHECK (actor_class IN ('anonymous', 'human', 'service', 'administrator', 'cache', 'sandbox-worker')),
    actor_pseudonym text NOT NULL CHECK (actor_pseudonym ~ '^pseudonym:[0-9a-f]{32}$'),
    permission text NOT NULL CHECK (permission = 'policy.administer'),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 256),
    outcome_code text NOT NULL CHECK (outcome_code = 'ALLOW_EXPLICIT'),
    correlation_id text NOT NULL CHECK (octet_length(correlation_id) BETWEEN 1 AND 256 AND correlation_id ~ '^[A-Za-z0-9._:-]+$'),
    details_target_class text NOT NULL CHECK (details_target_class ~ '^[a-z][a-z0-9.-]{0,127}$'),
    details_change_ref text CHECK (details_change_ref IS NULL OR (octet_length(details_change_ref) BETWEEN 1 AND 256 AND details_change_ref ~ '^[A-Za-z0-9._:-]+$')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION ogvcs_identity.reject_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'identity decision and audit ledgers are append-only';
END
$ogvcs$;

CREATE TRIGGER transaction_decision_commitments_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.transaction_decision_commitments
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE TRIGGER privileged_audit_events_append_only
BEFORE UPDATE OR DELETE ON ogvcs_identity.privileged_audit_events
FOR EACH ROW EXECUTE FUNCTION ogvcs_identity.reject_append_only_mutation();

CREATE FUNCTION ogvcs_identity.poison_transaction()
RETURNS void
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = 'identity authorization failed closed';
END
$ogvcs$;

COMMIT;
