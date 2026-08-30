BEGIN;

-- Existing events are unclaimed and immediately eligible under the additive
-- delivery columns.  Keep an explicit, restartable phase in the ledger.
DO $ogvcs$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'OGVCS metadata schema v3 requires PostgreSQL 15 or newer';
    END IF;
END
$ogvcs$;

COMMIT;
