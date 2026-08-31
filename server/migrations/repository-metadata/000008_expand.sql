BEGIN;

ALTER TABLE ogvcs_metadata.idempotency_records
    ADD COLUMN authorization_reference text,
    ADD COLUMN authorization_resources jsonb,
    ADD COLUMN authorization_binding_digest bytea,
    ADD CONSTRAINT idempotency_authorization_resources_bounded
        CHECK (
            CASE
                WHEN authorization_resources IS NULL THEN true
                WHEN jsonb_typeof(authorization_resources) = 'array'
                    THEN jsonb_array_length(authorization_resources) BETWEEN 1 AND 1000
                        AND pg_column_size(authorization_resources) <= 8388608
                        AND octet_length(authorization_resources::text) <= 8388608
                ELSE false
            END
        ),
    ADD CONSTRAINT idempotency_authorization_binding_complete
        CHECK (
            (authorization_resources IS NULL AND authorization_binding_digest IS NULL
                AND authorization_reference IS NULL)
            OR
            (authorization_resources IS NOT NULL
                AND authorization_binding_digest IS NOT NULL
                AND octet_length(authorization_binding_digest) = 32
                AND (authorization_reference IS NULL
                    OR length(authorization_reference) BETWEEN 1 AND 512))
        ),
    ADD CONSTRAINT idempotency_identity_safe_result_bounded
        CHECK (
            authorization_resources IS NULL
            OR safe_result IS NULL
            OR (pg_column_size(safe_result) <= 1048576
                AND octet_length(safe_result::text) <= 1048576)
        );

COMMIT;
