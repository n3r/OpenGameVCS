BEGIN;

-- Legacy adapter tokens remain explicitly unbound to an OGVCS-009 scope.
-- Production-bound writes populate the additive column immediately.
SELECT 1;

COMMIT;
