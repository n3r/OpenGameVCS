BEGIN;

-- Version 1 creates no backfill. Keeping an explicit migrate phase fixes the
-- ordered expand/migrate/contract protocol for every later schema version.
DO $ogvcs$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'OGVCS metadata schema v1 requires PostgreSQL 15 or newer';
    END IF;
END
$ogvcs$;

COMMIT;
