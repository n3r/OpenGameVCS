BEGIN;

-- V9 plans intentionally remain unbound and cannot enter the production v10
-- bridge. No inferred reference or snapshot is safe to backfill.
SELECT 1;

COMMIT;
