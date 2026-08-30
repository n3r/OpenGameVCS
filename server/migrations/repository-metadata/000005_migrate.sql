BEGIN;

-- Version 5 adds an empty server-owned cursor ledger; no data backfill exists.
DO $ogvcs$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'OGVCS metadata schema v5 requires PostgreSQL 15 or newer';
    END IF;
END
$ogvcs$;

COMMIT;
