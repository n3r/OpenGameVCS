BEGIN;

-- Generated columns must reconstruct the exact durable epoch after upgrade.
DO $ogvcs$
BEGIN
    IF EXISTS (
        SELECT 1 FROM ogvcs_identity.authority_states
        WHERE security_epoch IS DISTINCT FROM authority_epoch
    ) OR EXISTS (
        SELECT 1 FROM ogvcs_identity.credentials
        WHERE security_epoch IS DISTINCT FROM authority_epoch
           OR credential_digest_algorithm <> 'sha256'
           OR reconstruction_version <> 'postgres-credential-v1'
    ) THEN
        RAISE EXCEPTION 'identity credential/security epoch reconstruction failed';
    END IF;
END
$ogvcs$;

COMMIT;
