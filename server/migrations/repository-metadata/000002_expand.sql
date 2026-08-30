BEGIN;

-- Repository format settings are an identity boundary.  Install immutability
-- as a new migration; version 1 bytes are already durable migration identity.
CREATE FUNCTION ogvcs_metadata.reject_repository_settings_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $ogvcs$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'repository settings are immutable outside a migration';
END
$ogvcs$;

CREATE TRIGGER repository_settings_immutable
BEFORE UPDATE OR DELETE ON ogvcs_metadata.repository_settings
FOR EACH ROW EXECUTE FUNCTION ogvcs_metadata.reject_repository_settings_mutation();

CREATE INDEX file_path_history_by_file_id_v2
    ON ogvcs_metadata.file_path_history(
        repository_id,
        file_id,
        snapshot_digest,
        operation_ordinal
    );

COMMIT;
