BEGIN;

CREATE TABLE ogvcs_metadata.file_id_allocation_receipts (
    receipt_digest bytea PRIMARY KEY CHECK (octet_length(receipt_digest) = 32),
    authenticated_scope_digest bytea NOT NULL CHECK (octet_length(authenticated_scope_digest) = 32),
    repository_id uuid NOT NULL REFERENCES ogvcs_metadata.repositories(repository_id),
    file_id bytea NOT NULL CHECK (octet_length(file_id) = 16),
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz NULL,
    CHECK (expires_at > issued_at),
    UNIQUE (repository_id, file_id)
);

CREATE INDEX file_id_allocation_receipts_expiry
    ON ogvcs_metadata.file_id_allocation_receipts(expires_at)
    WHERE consumed_at IS NULL;

COMMIT;
