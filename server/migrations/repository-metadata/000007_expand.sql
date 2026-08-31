BEGIN;

ALTER TABLE ogvcs_metadata.consistency_tokens
    ADD COLUMN authenticated_scope_digest bytea
        CHECK (authenticated_scope_digest IS NULL
               OR octet_length(authenticated_scope_digest) = 32);

ALTER TABLE ogvcs_metadata.cursor_states
    ADD COLUMN authenticated_scope_digest bytea
        CHECK (authenticated_scope_digest IS NULL
               OR octet_length(authenticated_scope_digest) = 32);

ALTER TABLE ogvcs_metadata.repository_list_cursor_states
    ADD COLUMN authenticated_scope_digest bytea
        CHECK (authenticated_scope_digest IS NULL
               OR octet_length(authenticated_scope_digest) = 32);

CREATE INDEX consistency_tokens_authenticated_scope
    ON ogvcs_metadata.consistency_tokens(authenticated_scope_digest, repository_id)
    WHERE authenticated_scope_digest IS NOT NULL;

COMMIT;
