BEGIN;

-- Application roles receive narrower grants from deployment migrations. PUBLIC
-- never receives direct mutation authority for module-owned tables.
REVOKE ALL ON SCHEMA ogvcs_metadata FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ogvcs_metadata FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA ogvcs_metadata FROM PUBLIC;

COMMIT;
