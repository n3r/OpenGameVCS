BEGIN;

-- Version 4 adds a read primitive only; retain an explicit restartable phase.
DO $ogvcs$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'OGVCS metadata schema v4 requires PostgreSQL 15 or newer';
    END IF;
END
$ogvcs$;

COMMIT;
