BEGIN;

CREATE SCHEMA IF NOT EXISTS ogvcs_metadata;

CREATE TABLE ogvcs_metadata.schema_migrations (
    version bigint NOT NULL,
    phase text NOT NULL CHECK (phase IN ('expand', 'migrate', 'contract')),
    checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('started', 'completed')),
    minimum_application_version text NOT NULL,
    maximum_application_version text NOT NULL,
    resume_cursor jsonb,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (version, phase),
    CHECK ((state = 'completed') = (completed_at IS NOT NULL))
);

CREATE TABLE ogvcs_metadata.repositories (
    repository_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    archived_at timestamptz,
    UNIQUE (tenant_id, project_id, repository_id),
    UNIQUE (repository_id, tenant_id)
);

CREATE TABLE ogvcs_metadata.repository_settings (
    repository_id uuid PRIMARY KEY REFERENCES ogvcs_metadata.repositories(repository_id),
    descriptor_kind smallint NOT NULL CHECK (descriptor_kind = 6),
    descriptor_algorithm smallint NOT NULL DEFAULT 1 CHECK (descriptor_algorithm = 1),
    descriptor_digest bytea NOT NULL CHECK (octet_length(descriptor_digest) = 32),
    repository_format text NOT NULL,
    required_features jsonb NOT NULL,
    case_mode text NOT NULL CHECK (case_mode IN ('case-sensitive', 'case-folded')),
    path_profile text NOT NULL,
    platform_profile text NOT NULL,
    content_policy_profile text NOT NULL,
    structural_limits jsonb NOT NULL,
    tenant_boundary uuid NOT NULL,
    settings_generation bigint NOT NULL DEFAULT 1 CHECK (settings_generation = 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, descriptor_kind, descriptor_digest),
    FOREIGN KEY (repository_id, tenant_boundary)
        REFERENCES ogvcs_metadata.repositories(repository_id, tenant_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.metadata_objects (
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    object_kind smallint NOT NULL CHECK (object_kind IN (2, 3, 4, 5, 6, 7, 9, 10, 11)),
    digest_algorithm smallint NOT NULL CHECK (digest_algorithm = 1),
    object_digest bytea NOT NULL CHECK (octet_length(object_digest) = 32),
    canonical_bytes bytea NOT NULL CHECK (octet_length(canonical_bytes) <= 536870912),
    byte_length bigint GENERATED ALWAYS AS (octet_length(canonical_bytes)) STORED,
    validation_contract text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, object_kind, digest_algorithm, object_digest)
);

ALTER TABLE ogvcs_metadata.repository_settings
    ADD CONSTRAINT repository_settings_descriptor_fk
    FOREIGN KEY (repository_id, descriptor_kind, descriptor_algorithm, descriptor_digest)
    REFERENCES ogvcs_metadata.metadata_objects(repository_id, object_kind, digest_algorithm, object_digest)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ogvcs_metadata.object_edges (
    repository_id uuid NOT NULL,
    source_kind smallint NOT NULL,
    source_algorithm smallint NOT NULL DEFAULT 1 CHECK (source_algorithm = 1),
    source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    target_kind smallint NOT NULL,
    target_algorithm smallint NOT NULL DEFAULT 1 CHECK (target_algorithm = 1),
    target_digest bytea NOT NULL CHECK (octet_length(target_digest) = 32),
    PRIMARY KEY (repository_id, source_kind, source_digest, ordinal),
    FOREIGN KEY (repository_id, source_kind, source_algorithm, source_digest)
        REFERENCES ogvcs_metadata.metadata_objects(repository_id, object_kind, digest_algorithm, object_digest)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.tree_entries (
    repository_id uuid NOT NULL,
    tree_kind smallint NOT NULL DEFAULT 3 CHECK (tree_kind = 3),
    tree_algorithm smallint NOT NULL DEFAULT 1 CHECK (tree_algorithm = 1),
    tree_digest bytea NOT NULL CHECK (octet_length(tree_digest) = 32),
    ordinal integer NOT NULL CHECK (ordinal >= 0 AND ordinal < 1000000),
    basename_utf8 bytea NOT NULL CHECK (octet_length(basename_utf8) BETWEEN 1 AND 255),
    file_id bytea NOT NULL CHECK (octet_length(file_id) = 16 AND file_id <> decode(repeat('00', 16), 'hex')),
    entry_kind smallint NOT NULL CHECK (entry_kind BETWEEN 1 AND 4),
    target_kind smallint NOT NULL,
    target_algorithm smallint NOT NULL DEFAULT 1 CHECK (target_algorithm = 1),
    target_digest bytea NOT NULL CHECK (octet_length(target_digest) = 32),
    logical_size numeric(20, 0) NOT NULL CHECK (logical_size >= 0),
    CHECK ((entry_kind = 1 AND target_kind = 3) OR (entry_kind IN (2, 3, 4) AND target_kind = 2)),
    PRIMARY KEY (repository_id, tree_digest, ordinal),
    UNIQUE (repository_id, tree_digest, basename_utf8),
    UNIQUE (repository_id, tree_digest, file_id),
    FOREIGN KEY (repository_id, tree_kind, tree_algorithm, tree_digest)
        REFERENCES ogvcs_metadata.metadata_objects(repository_id, object_kind, digest_algorithm, object_digest)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (repository_id, target_kind, target_algorithm, target_digest)
        REFERENCES ogvcs_metadata.metadata_objects(repository_id, object_kind, digest_algorithm, object_digest)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.snapshots (
    repository_id uuid NOT NULL,
    snapshot_kind smallint NOT NULL DEFAULT 7 CHECK (snapshot_kind = 7),
    snapshot_algorithm smallint NOT NULL DEFAULT 1 CHECK (snapshot_algorithm = 1),
    snapshot_digest bytea NOT NULL CHECK (octet_length(snapshot_digest) = 32),
    root_tree_kind smallint NOT NULL DEFAULT 3 CHECK (root_tree_kind = 3),
    root_tree_algorithm smallint NOT NULL DEFAULT 1 CHECK (root_tree_algorithm = 1),
    root_tree_digest bytea NOT NULL CHECK (octet_length(root_tree_digest) = 32),
    published_commit_sequence bigint,
    PRIMARY KEY (repository_id, snapshot_digest),
    FOREIGN KEY (repository_id, snapshot_kind, snapshot_algorithm, snapshot_digest)
        REFERENCES ogvcs_metadata.metadata_objects(repository_id, object_kind, digest_algorithm, object_digest)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (repository_id, root_tree_kind, root_tree_algorithm, root_tree_digest)
        REFERENCES ogvcs_metadata.metadata_objects(repository_id, object_kind, digest_algorithm, object_digest)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.snapshot_parents (
    repository_id uuid NOT NULL,
    snapshot_digest bytea NOT NULL,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 7),
    parent_snapshot_digest bytea NOT NULL CHECK (octet_length(parent_snapshot_digest) = 32),
    PRIMARY KEY (repository_id, snapshot_digest, ordinal),
    UNIQUE (repository_id, snapshot_digest, parent_snapshot_digest),
    FOREIGN KEY (repository_id, snapshot_digest)
        REFERENCES ogvcs_metadata.snapshots(repository_id, snapshot_digest)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (repository_id, parent_snapshot_digest)
        REFERENCES ogvcs_metadata.snapshots(repository_id, snapshot_digest)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE ogvcs_metadata.file_path_history (
    repository_id uuid NOT NULL,
    snapshot_digest bytea NOT NULL,
    operation_ordinal integer NOT NULL CHECK (operation_ordinal >= 0),
    file_id bytea NOT NULL CHECK (octet_length(file_id) = 16),
    repository_path_utf8 bytea NOT NULL CHECK (octet_length(repository_path_utf8) BETWEEN 1 AND 4096),
    operation_kind text NOT NULL CHECK (operation_kind IN ('create', 'modify', 'copy', 'move', 'rename', 'delete', 'restore', 'import')),
    PRIMARY KEY (repository_id, snapshot_digest, operation_ordinal),
    FOREIGN KEY (repository_id, snapshot_digest)
        REFERENCES ogvcs_metadata.snapshots(repository_id, snapshot_digest)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX file_path_history_by_file_id
    ON ogvcs_metadata.file_path_history(repository_id, file_id, snapshot_digest);
CREATE INDEX file_path_history_by_path
    ON ogvcs_metadata.file_path_history(repository_id, repository_path_utf8, snapshot_digest);

CREATE TABLE ogvcs_metadata.repository_commit_sequences (
    repository_id uuid PRIMARY KEY REFERENCES ogvcs_metadata.repositories(repository_id),
    applied_sequence bigint NOT NULL DEFAULT 0 CHECK (applied_sequence >= 0)
);

CREATE TABLE ogvcs_metadata.references (
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    reference_kind text NOT NULL CHECK (reference_kind IN ('branch', 'tag')),
    reference_name text NOT NULL CHECK (octet_length(reference_name) BETWEEN 1 AND 512),
    target_snapshot_digest bytea NOT NULL CHECK (octet_length(target_snapshot_digest) = 32),
    generation bigint NOT NULL CHECK (generation >= 1),
    commit_sequence bigint NOT NULL CHECK (commit_sequence >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, reference_kind, reference_name),
    FOREIGN KEY (repository_id, target_snapshot_digest)
        REFERENCES ogvcs_metadata.snapshots(repository_id, snapshot_digest)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TYPE ogvcs_metadata.file_id_state AS ENUM ('reserved', 'active', 'tombstoned');
CREATE TYPE ogvcs_metadata.file_id_origin AS ENUM ('create', 'copy', 'restore', 'import');
CREATE TYPE ogvcs_metadata.file_id_owner_kind AS ENUM ('published', 'draft', 'shelf');

CREATE TABLE ogvcs_metadata.file_id_registry (
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    file_id bytea NOT NULL CHECK (octet_length(file_id) = 16 AND file_id <> decode(repeat('00', 16), 'hex')),
    state ogvcs_metadata.file_id_state NOT NULL,
    origin ogvcs_metadata.file_id_origin NOT NULL,
    owner_kind ogvcs_metadata.file_id_owner_kind NOT NULL,
    owner_id text NOT NULL CHECK (octet_length(owner_id) BETWEEN 1 AND 256),
    first_change_set_digest bytea CHECK (first_change_set_digest IS NULL OR octet_length(first_change_set_digest) = 32),
    first_operation integer CHECK (first_operation IS NULL OR first_operation >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    tombstoned_at timestamptz,
    PRIMARY KEY (repository_id, file_id),
    CHECK ((state = 'tombstoned') = (tombstoned_at IS NOT NULL))
);

CREATE TABLE ogvcs_metadata.file_id_import_mappings (
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    importer_profile text NOT NULL,
    source_namespace_digest bytea NOT NULL CHECK (octet_length(source_namespace_digest) = 32),
    source_identity_digest bytea NOT NULL CHECK (octet_length(source_identity_digest) = 32),
    file_id bytea NOT NULL CHECK (octet_length(file_id) = 16),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (repository_id, importer_profile, source_namespace_digest, source_identity_digest),
    UNIQUE (repository_id, file_id),
    FOREIGN KEY (repository_id, file_id)
        REFERENCES ogvcs_metadata.file_id_registry(repository_id, file_id)
        DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE ogvcs_metadata.file_path_history
    ADD CONSTRAINT file_path_history_file_id_fk
    FOREIGN KEY (repository_id, file_id)
    REFERENCES ogvcs_metadata.file_id_registry(repository_id, file_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ogvcs_metadata.idempotency_records (
    authenticated_scope_digest bytea NOT NULL CHECK (octet_length(authenticated_scope_digest) = 32),
    operation text NOT NULL,
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 512),
    semantic_fingerprint bytea NOT NULL CHECK (octet_length(semantic_fingerprint) = 32),
    state text NOT NULL CHECK (state IN ('reserved', 'committed')),
    safe_result jsonb,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    committed_at timestamptz,
    PRIMARY KEY (authenticated_scope_digest, operation, idempotency_key),
    CHECK (expires_at > issued_at),
    CHECK ((state = 'committed') = (safe_result IS NOT NULL AND committed_at IS NOT NULL))
);

CREATE TABLE ogvcs_metadata.cursor_states (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    operation text NOT NULL,
    query_digest bytea NOT NULL CHECK (octet_length(query_digest) = 32),
    bound_object_kind smallint,
    bound_object_digest bytea CHECK (bound_object_digest IS NULL OR octet_length(bound_object_digest) = 32),
    position jsonb NOT NULL,
    authorization_epoch bigint NOT NULL CHECK (authorization_epoch >= 0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at)
);

CREATE TABLE ogvcs_metadata.consistency_tokens (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    minimum_commit_sequence bigint NOT NULL CHECK (minimum_commit_sequence >= 0),
    authorization_epoch bigint NOT NULL CHECK (authorization_epoch >= 0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at)
);

CREATE TABLE ogvcs_metadata.outbox_events (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    commit_sequence bigint NOT NULL CHECK (commit_sequence >= 1),
    event_type text NOT NULL,
    event_version smallint NOT NULL CHECK (event_version = 1),
    correlation_id uuid NOT NULL,
    resource_type text NOT NULL CHECK (resource_type IN ('repository', 'reference', 'snapshot', 'tree', 'path')),
    resource_opaque_id text NOT NULL CHECK (resource_opaque_id ~ '^rr1\.[A-Za-z0-9_-]{43}$'),
    safe_payload jsonb NOT NULL,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (repository_id, commit_sequence, event_id)
);

CREATE INDEX outbox_events_available
    ON ogvcs_metadata.outbox_events(available_at, event_id);

COMMIT;
