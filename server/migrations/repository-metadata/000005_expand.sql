BEGIN;

CREATE TABLE ogvcs_metadata.repository_list_cursor_states (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    subject_digest bytea NOT NULL CHECK (octet_length(subject_digest) = 32),
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    position_repository_id uuid NOT NULL,
    authorization_epoch bigint NOT NULL CHECK (authorization_epoch >= 0),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > issued_at)
);

CREATE INDEX repository_list_cursor_states_expiry
    ON ogvcs_metadata.repository_list_cursor_states(expires_at);

COMMIT;
