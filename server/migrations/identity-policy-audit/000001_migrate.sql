BEGIN;

DO $ogvcs$
BEGIN
    IF current_setting('server_version_num')::integer < 150000 THEN
        RAISE EXCEPTION 'OGVCS identity-policy participant requires PostgreSQL 15 or newer';
    END IF;
END
$ogvcs$;

COMMIT;

