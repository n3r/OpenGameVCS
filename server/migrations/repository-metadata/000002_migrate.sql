BEGIN;

-- Version 2 changes only enforcement and an access-path index.  There is no
-- row backfill, but keep the ordered phase explicit for deterministic ledgers.
DO $ogvcs$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'OGVCS metadata schema v2 requires PostgreSQL 15 or newer';
    END IF;
END
$ogvcs$;

COMMIT;
