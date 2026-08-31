BEGIN;

-- The v1 authority and credential records are already durable.  v3 makes the
-- security-epoch and restart-reconstruction contract explicit without
-- rewriting the immutable predecessors or making existing inserts provide
-- duplicate epoch data.
ALTER TABLE ogvcs_identity.authority_states
    ADD COLUMN security_epoch bigint
        GENERATED ALWAYS AS (authority_epoch) STORED;

ALTER TABLE ogvcs_identity.credentials
    ADD COLUMN security_epoch bigint
        GENERATED ALWAYS AS (authority_epoch) STORED,
    ADD COLUMN credential_digest_algorithm text NOT NULL DEFAULT 'sha256'
        CHECK (credential_digest_algorithm = 'sha256'),
    ADD COLUMN reconstruction_version text NOT NULL DEFAULT 'postgres-credential-v1'
        CHECK (reconstruction_version = 'postgres-credential-v1');

-- Repository metadata owns these immutable settings. Identity first binds a
-- stable metadata repository identity, then appends one exact handoff per
-- settings generation. This keeps old plans verifiable while allowing a newer
-- metadata settings generation to be promoted without rewriting history.
CREATE TABLE ogvcs_identity.repository_contract_roots (
    tenant_id text NOT NULL REFERENCES ogvcs_identity.authority_states(tenant_id),
    repository_id text NOT NULL CHECK (repository_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    metadata_tenant_id text NOT NULL CHECK (octet_length(metadata_tenant_id) BETWEEN 1 AND 64),
    metadata_repository_id text NOT NULL CHECK (octet_length(metadata_repository_id) BETWEEN 1 AND 64),
    bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id),
    UNIQUE (metadata_repository_id),
    UNIQUE (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id)
);

CREATE TABLE ogvcs_identity.repository_contract_bindings (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    metadata_tenant_id text NOT NULL CHECK (octet_length(metadata_tenant_id) BETWEEN 1 AND 64),
    metadata_repository_id text NOT NULL CHECK (octet_length(metadata_repository_id) BETWEEN 1 AND 64),
    settings_generation bigint NOT NULL CHECK (settings_generation >= 1),
    descriptor_digest bytea NOT NULL CHECK (octet_length(descriptor_digest) = 32),
    path_profile text NOT NULL CHECK (octet_length(path_profile) BETWEEN 1 AND 328),
    case_mode text NOT NULL CHECK (case_mode IN ('case-sensitive', 'case-folded')),
    bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, repository_id, settings_generation),
    UNIQUE (metadata_repository_id, settings_generation),
    UNIQUE (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id,
            settings_generation, descriptor_digest, path_profile, case_mode),
    FOREIGN KEY (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id)
        REFERENCES ogvcs_identity.repository_contract_roots
            (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id)
);

-- Policy JSON remains the source artifact.  Aggregate authorization consumes
-- this normalized, generation-bound projection so the complete resource set
-- can be evaluated by one relational query.
CREATE TABLE ogvcs_identity.compiled_policies (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL CHECK (policy_generation >= 1),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    compiled_digest bytea NOT NULL CHECK (octet_length(compiled_digest) = 32),
    path_profile text NOT NULL CHECK (octet_length(path_profile) BETWEEN 1 AND 328),
    case_mode text NOT NULL CHECK (case_mode IN ('case-sensitive', 'case-folded')),
    state text NOT NULL CHECK (state IN ('compiling', 'sealed')),
    compiled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    sealed_at timestamptz,
    PRIMARY KEY (tenant_id, repository_id, policy_generation),
    UNIQUE (tenant_id, repository_id, policy_generation, authority_epoch,
            policy_digest, path_profile, case_mode),
    FOREIGN KEY (tenant_id, repository_id, policy_generation)
        REFERENCES ogvcs_identity.policy_versions(tenant_id, repository_id, policy_generation),
    CHECK ((state = 'sealed') = (sealed_at IS NOT NULL))
);

CREATE TABLE ogvcs_identity.compiled_policy_rules (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL CHECK (rule_ordinal BETWEEN 0 AND 1023),
    rule_id text NOT NULL CHECK (rule_id ~ '^[a-z][a-z0-9.-]{0,127}$'),
    effect text NOT NULL CHECK (effect IN ('allow', 'deny')),
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal),
    UNIQUE (tenant_id, repository_id, policy_generation, rule_id),
    FOREIGN KEY (tenant_id, repository_id, policy_generation)
        REFERENCES ogvcs_identity.compiled_policies(tenant_id, repository_id, policy_generation)
        ON DELETE CASCADE
);

CREATE TABLE ogvcs_identity.compiled_policy_subjects (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL,
    subject_kind text NOT NULL CHECK (subject_kind IN ('identity', 'group', 'actor-class')),
    subject_value text NOT NULL CHECK (octet_length(subject_value) BETWEEN 1 AND 128),
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal, subject_kind, subject_value),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, rule_ordinal)
        REFERENCES ogvcs_identity.compiled_policy_rules(tenant_id, repository_id, policy_generation, rule_ordinal)
        ON DELETE CASCADE
);

CREATE TABLE ogvcs_identity.compiled_policy_references (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL,
    reference_name text NOT NULL CHECK (reference_name ~ '^[a-z][a-z0-9.-]{0,127}$'),
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal, reference_name),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, rule_ordinal)
        REFERENCES ogvcs_identity.compiled_policy_rules(tenant_id, repository_id, policy_generation, rule_ordinal)
        ON DELETE CASCADE
);

CREATE TABLE ogvcs_identity.compiled_policy_path_prefixes (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL,
    prefix_ordinal integer NOT NULL CHECK (prefix_ordinal BETWEEN 0 AND 127),
    canonical_prefix text COLLATE "C" NOT NULL,
    lower_inclusive text COLLATE "C" NOT NULL,
    upper_exclusive text COLLATE "C" NOT NULL,
    is_root boolean NOT NULL,
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal, prefix_ordinal),
    UNIQUE (tenant_id, repository_id, policy_generation, rule_ordinal, canonical_prefix),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, rule_ordinal)
        REFERENCES ogvcs_identity.compiled_policy_rules(tenant_id, repository_id, policy_generation, rule_ordinal)
        ON DELETE CASCADE,
    CHECK ((is_root AND canonical_prefix = '') OR (NOT is_root AND canonical_prefix <> '')),
    CHECK (lower_inclusive < upper_exclusive)
);

CREATE TABLE ogvcs_identity.compiled_policy_resource_types (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL,
    resource_type text NOT NULL CHECK (octet_length(resource_type) BETWEEN 1 AND 64),
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal, resource_type),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, rule_ordinal)
        REFERENCES ogvcs_identity.compiled_policy_rules(tenant_id, repository_id, policy_generation, rule_ordinal)
        ON DELETE CASCADE
);

CREATE TABLE ogvcs_identity.compiled_policy_permissions (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL,
    permission text NOT NULL CHECK (octet_length(permission) BETWEEN 1 AND 64),
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal, permission),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, rule_ordinal)
        REFERENCES ogvcs_identity.compiled_policy_rules(tenant_id, repository_id, policy_generation, rule_ordinal)
        ON DELETE CASCADE
);

CREATE TABLE ogvcs_identity.compiled_policy_terms (
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    policy_generation bigint NOT NULL,
    rule_ordinal integer NOT NULL,
    term_kind text NOT NULL CHECK (term_kind IN ('tenant', 'repository')),
    term_value text NOT NULL CHECK (octet_length(term_value) BETWEEN 1 AND 128),
    PRIMARY KEY (tenant_id, repository_id, policy_generation, rule_ordinal, term_kind),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, rule_ordinal)
        REFERENCES ogvcs_identity.compiled_policy_rules(tenant_id, repository_id, policy_generation, rule_ordinal)
        ON DELETE CASCADE
);

-- Secrets never enter PostgreSQL.  This registry binds an authority/security
-- epoch to an opaque secret-manager/KMS reference and a non-secret provider
-- fingerprint.  Rotation changes authority_states.key_generation.
CREATE TABLE ogvcs_identity.aggregate_signing_keys (
    tenant_id text NOT NULL REFERENCES ogvcs_identity.authority_states(tenant_id),
    key_generation bigint NOT NULL CHECK (key_generation >= 1),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    key_reference text NOT NULL CHECK (octet_length(key_reference) BETWEEN 1 AND 256),
    key_fingerprint bytea NOT NULL CHECK (octet_length(key_fingerprint) = 32),
    state text NOT NULL CHECK (state IN ('active', 'verify-only', 'retired')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    retired_at timestamptz,
    PRIMARY KEY (tenant_id, key_generation),
    UNIQUE (tenant_id, key_reference),
    UNIQUE (tenant_id, key_generation, authority_epoch, key_reference,
            key_fingerprint),
    CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE UNIQUE INDEX aggregate_signing_keys_one_active_per_tenant
    ON ogvcs_identity.aggregate_signing_keys(tenant_id) WHERE state = 'active';

CREATE TABLE ogvcs_identity.aggregate_plans (
    plan_id text PRIMARY KEY CHECK (octet_length(plan_id) BETWEEN 1 AND 256 AND plan_id !~ '[^A-Za-z0-9._:-]'),
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    credential_id text NOT NULL,
    credential_generation bigint NOT NULL CHECK (credential_generation >= 1),
    presentation_digest bytea NOT NULL CHECK (octet_length(presentation_digest) = 32),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    authenticated_scope_digest bytea NOT NULL CHECK (octet_length(authenticated_scope_digest) = 32),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    security_epoch bigint NOT NULL CHECK (security_epoch >= 1),
    policy_generation bigint NOT NULL CHECK (policy_generation >= 1),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    metadata_tenant_id text NOT NULL,
    metadata_repository_id text NOT NULL,
    settings_generation bigint NOT NULL CHECK (settings_generation >= 1),
    settings_descriptor_digest bytea NOT NULL CHECK (octet_length(settings_descriptor_digest) = 32),
    path_profile text NOT NULL CHECK (octet_length(path_profile) BETWEEN 1 AND 328),
    case_mode text NOT NULL CHECK (case_mode IN ('case-sensitive', 'case-folded')),
    permission text NOT NULL CHECK (octet_length(permission) BETWEEN 1 AND 64),
    capability text NOT NULL CHECK (octet_length(capability) BETWEEN 1 AND 128),
    reference_name text CHECK (reference_name IS NULL OR octet_length(reference_name) BETWEEN 1 AND 128),
    snapshot_id text CHECK (snapshot_id IS NULL OR octet_length(snapshot_id) BETWEEN 1 AND 256),
    reason text CHECK (reason IS NULL OR octet_length(reason) BETWEEN 1 AND 256),
    reason_digest bytea NOT NULL CHECK (octet_length(reason_digest) = 32),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    signer_key_generation bigint NOT NULL CHECK (signer_key_generation >= 1),
    signer_key_reference text NOT NULL,
    signer_key_fingerprint bytea NOT NULL CHECK (octet_length(signer_key_fingerprint) = 32),
    upload_nonce bytea NOT NULL UNIQUE CHECK (octet_length(upload_nonce) = 32),
    handle_mac bytea NOT NULL CHECK (octet_length(handle_mac) = 32),
    state text NOT NULL CHECK (state IN ('initializing', 'uploading', 'authorized', 'consumed')),
    item_count integer NOT NULL DEFAULT 0 CHECK (item_count BETWEEN 0 AND 100000),
    chunk_count integer NOT NULL DEFAULT 0 CHECK (chunk_count BETWEEN 0 AND 100000),
    resource_chain_digest bytea NOT NULL CHECK (octet_length(resource_chain_digest) = 32),
    last_resource_key bytea CHECK (last_resource_key IS NULL OR octet_length(last_resource_key) <= 16384),
    resource_set_digest bytea CHECK (resource_set_digest IS NULL OR octet_length(resource_set_digest) = 32),
    resource_digest_projection_digest bytea CHECK (resource_digest_projection_digest IS NULL OR octet_length(resource_digest_projection_digest) = 32),
    decision_digest bytea CHECK (decision_digest IS NULL OR octet_length(decision_digest) = 32),
    commitment_digest bytea CHECK (commitment_digest IS NULL OR octet_length(commitment_digest) = 32),
    receipt_mac bytea CHECK (receipt_mac IS NULL OR octet_length(receipt_mac) = 32),
    authorized_at timestamptz,
    consumed_at timestamptz,
    FOREIGN KEY (tenant_id, credential_id, credential_generation)
        REFERENCES ogvcs_identity.credentials(tenant_id, credential_id, credential_generation),
    FOREIGN KEY (tenant_id, repository_id, policy_generation)
        REFERENCES ogvcs_identity.compiled_policies(tenant_id, repository_id, policy_generation),
    FOREIGN KEY (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id,
                 settings_generation, settings_descriptor_digest, path_profile, case_mode)
        REFERENCES ogvcs_identity.repository_contract_bindings
            (tenant_id, repository_id, metadata_tenant_id, metadata_repository_id,
             settings_generation, descriptor_digest, path_profile, case_mode),
    FOREIGN KEY (tenant_id, repository_id, policy_generation, authority_epoch,
                 policy_digest, path_profile, case_mode)
        REFERENCES ogvcs_identity.compiled_policies
            (tenant_id, repository_id, policy_generation, authority_epoch,
             policy_digest, path_profile, case_mode),
    FOREIGN KEY (tenant_id, signer_key_generation)
        REFERENCES ogvcs_identity.aggregate_signing_keys(tenant_id, key_generation),
    FOREIGN KEY (tenant_id, signer_key_generation, authority_epoch,
                 signer_key_reference, signer_key_fingerprint)
        REFERENCES ogvcs_identity.aggregate_signing_keys
            (tenant_id, key_generation, authority_epoch, key_reference,
             key_fingerprint),
    CHECK (expires_at > issued_at),
    CHECK ((item_count = 0) = (last_resource_key IS NULL)),
    CHECK ((state IN ('initializing', 'uploading')) =
           (resource_set_digest IS NULL AND resource_digest_projection_digest IS NULL
            AND decision_digest IS NULL
            AND commitment_digest IS NULL AND receipt_mac IS NULL AND authorized_at IS NULL)),
    CHECK ((state = 'consumed') = (consumed_at IS NOT NULL)),
    CHECK (state IN ('initializing', 'uploading') OR
           (resource_set_digest IS NOT NULL AND resource_digest_projection_digest IS NOT NULL
            AND decision_digest IS NOT NULL
            AND commitment_digest IS NOT NULL AND receipt_mac IS NOT NULL
            AND authorized_at IS NOT NULL)),
    CHECK (state IN ('initializing', 'uploading') OR (item_count >= 1 AND chunk_count >= 1)),
    CHECK (state <> 'initializing' OR
           (item_count = 0 AND chunk_count = 0 AND last_resource_key IS NULL))
);

CREATE INDEX aggregate_plans_by_authority
    ON ogvcs_identity.aggregate_plans(tenant_id, repository_id, authority_epoch, policy_generation);

CREATE TABLE ogvcs_identity.aggregate_plan_subject_terms (
    plan_id text NOT NULL REFERENCES ogvcs_identity.aggregate_plans(plan_id) ON DELETE CASCADE,
    subject_kind text NOT NULL CHECK (subject_kind IN ('identity', 'group', 'actor-class')),
    subject_value text NOT NULL CHECK (octet_length(subject_value) BETWEEN 1 AND 128),
    PRIMARY KEY (plan_id, subject_kind, subject_value)
);

CREATE TABLE ogvcs_identity.aggregate_plan_scope_terms (
    plan_id text NOT NULL REFERENCES ogvcs_identity.aggregate_plans(plan_id) ON DELETE CASCADE,
    scope_kind text NOT NULL CHECK (scope_kind IN ('tenant', 'repository', 'reference', 'permission')),
    scope_value text NOT NULL CHECK (octet_length(scope_value) BETWEEN 1 AND 128),
    PRIMARY KEY (plan_id, scope_kind, scope_value)
);

CREATE TABLE ogvcs_identity.aggregate_plan_scope_path_prefixes (
    plan_id text NOT NULL REFERENCES ogvcs_identity.aggregate_plans(plan_id) ON DELETE CASCADE,
    prefix_ordinal integer NOT NULL CHECK (prefix_ordinal BETWEEN 0 AND 127),
    canonical_prefix text COLLATE "C" NOT NULL,
    lower_inclusive text COLLATE "C" NOT NULL,
    upper_exclusive text COLLATE "C" NOT NULL,
    is_root boolean NOT NULL,
    PRIMARY KEY (plan_id, prefix_ordinal),
    UNIQUE (plan_id, canonical_prefix),
    CHECK ((is_root AND canonical_prefix = '') OR (NOT is_root AND canonical_prefix <> '')),
    CHECK (lower_inclusive < upper_exclusive)
);

CREATE TABLE ogvcs_identity.aggregate_plan_chunks (
    plan_id text NOT NULL REFERENCES ogvcs_identity.aggregate_plans(plan_id) ON DELETE CASCADE,
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal BETWEEN 0 AND 99999),
    first_item_ordinal integer NOT NULL CHECK (first_item_ordinal BETWEEN 0 AND 99999),
    item_count integer NOT NULL CHECK (item_count BETWEEN 1 AND 1000),
    encoded_bytes integer NOT NULL CHECK (encoded_bytes BETWEEN 1 AND 1048576),
    chunk_digest bytea NOT NULL CHECK (octet_length(chunk_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (plan_id, chunk_ordinal),
    UNIQUE (plan_id, first_item_ordinal)
);

CREATE TABLE ogvcs_identity.aggregate_plan_resources (
    plan_id text NOT NULL REFERENCES ogvcs_identity.aggregate_plans(plan_id) ON DELETE CASCADE,
    item_ordinal integer NOT NULL CHECK (item_ordinal BETWEEN 0 AND 99999),
    resource_type text NOT NULL CHECK (resource_type IN
        ('repository', 'reference', 'snapshot', 'tree', 'path', 'object',
         'content', 'lock', 'review', 'search', 'event', 'cache-entry',
         'export', 'policy', 'audit', 'retention', 'repair-job', 'sandbox-job')),
    canonical_resource jsonb NOT NULL,
    canonical_resource_key bytea NOT NULL CHECK (octet_length(canonical_resource_key) BETWEEN 1 AND 16384),
    resource_digest bytea NOT NULL CHECK (octet_length(resource_digest) = 32),
    path_key text COLLATE "C" CHECK (path_key IS NULL OR octet_length(path_key) BETWEEN 1 AND 16384),
    file_id text CHECK (file_id IS NULL OR (octet_length(file_id) = 32 AND file_id !~ '[^0-9a-f]')),
    object_id text CHECK (object_id IS NULL OR (octet_length(object_id) BETWEEN 1 AND 160 AND object_id !~ '[^A-Za-z0-9._:-]')),
    resource_name text CHECK (resource_name IS NULL OR octet_length(resource_name) BETWEEN 1 AND 256),
    PRIMARY KEY (plan_id, item_ordinal),
    UNIQUE (plan_id, canonical_resource_key),
    CHECK (jsonb_typeof(canonical_resource) = 'object'),
    CHECK (octet_length(canonical_resource::text) BETWEEN 1 AND 16384),
    CHECK (canonical_resource ?& ARRAY['type', 'path', 'fileId', 'objectId', 'name']),
    CHECK ((canonical_resource - ARRAY['type', 'path', 'fileId', 'objectId', 'name']) = '{}'::jsonb),
    CHECK (jsonb_typeof(canonical_resource->'type') = 'string'),
    CHECK (canonical_resource->>'type' = resource_type),
    CHECK ((canonical_resource->'path') = 'null'::jsonb OR jsonb_typeof(canonical_resource->'path') = 'string'),
    CHECK ((canonical_resource->'fileId') = 'null'::jsonb OR jsonb_typeof(canonical_resource->'fileId') = 'string'),
    CHECK ((canonical_resource->'objectId') = 'null'::jsonb OR jsonb_typeof(canonical_resource->'objectId') = 'string'),
    CHECK ((canonical_resource->'name') = 'null'::jsonb OR jsonb_typeof(canonical_resource->'name') = 'string'),
    CHECK ((canonical_resource->>'fileId') IS NOT DISTINCT FROM file_id),
    CHECK ((canonical_resource->>'objectId') IS NOT DISTINCT FROM object_id),
    CHECK ((canonical_resource->>'name') IS NOT DISTINCT FROM resource_name),
    CHECK (canonical_resource->>'path' IS NULL OR octet_length(canonical_resource->>'path') BETWEEN 1 AND 4096)
);

CREATE INDEX aggregate_plan_resources_set_evaluation
    ON ogvcs_identity.aggregate_plan_resources(plan_id, resource_type, path_key COLLATE "C");

CREATE TABLE ogvcs_identity.aggregate_decision_commitments (
    plan_id text PRIMARY KEY REFERENCES ogvcs_identity.aggregate_plans(plan_id),
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    authenticated_scope_digest bytea NOT NULL CHECK (octet_length(authenticated_scope_digest) = 32),
    credential_generation bigint NOT NULL CHECK (credential_generation >= 1),
    authority_epoch bigint NOT NULL CHECK (authority_epoch >= 1),
    security_epoch bigint NOT NULL CHECK (security_epoch >= 1),
    policy_generation bigint NOT NULL CHECK (policy_generation >= 1),
    policy_digest bytea NOT NULL CHECK (octet_length(policy_digest) = 32),
    metadata_tenant_id text NOT NULL,
    metadata_repository_id text NOT NULL,
    settings_generation bigint NOT NULL CHECK (settings_generation >= 1),
    settings_descriptor_digest bytea NOT NULL CHECK (octet_length(settings_descriptor_digest) = 32),
    path_profile text NOT NULL,
    case_mode text NOT NULL,
    permission text NOT NULL,
    capability text NOT NULL,
    reference_name text,
    snapshot_id text,
    reason_digest bytea NOT NULL CHECK (octet_length(reason_digest) = 32),
    resource_count integer NOT NULL CHECK (resource_count BETWEEN 1 AND 100000),
    resource_set_digest bytea NOT NULL CHECK (octet_length(resource_set_digest) = 32),
    resource_digest_projection_digest bytea NOT NULL CHECK (octet_length(resource_digest_projection_digest) = 32),
    decision_digest bytea NOT NULL CHECK (octet_length(decision_digest) = 32),
    signer_key_generation bigint NOT NULL CHECK (signer_key_generation >= 1),
    receipt_mac bytea NOT NULL CHECK (octet_length(receipt_mac) = 32),
    record_digest bytea NOT NULL CHECK (octet_length(record_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, record_digest)
);

CREATE TABLE ogvcs_identity.aggregate_plan_consumptions (
    plan_id text PRIMARY KEY REFERENCES ogvcs_identity.aggregate_plans(plan_id),
    consumption_id text NOT NULL UNIQUE CHECK (octet_length(consumption_id) BETWEEN 1 AND 256 AND consumption_id !~ '[^A-Za-z0-9._:-]'),
    operation_digest bytea NOT NULL CHECK (octet_length(operation_digest) = 32),
    consumed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (plan_id, consumption_id, operation_digest)
);

COMMIT;
