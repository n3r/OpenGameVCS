BEGIN;

-- No legacy lifecycle projection is contracted away. The empty contract phase
-- preserves expand/migrate/contract rollout and its compatibility fence.
SELECT 1;

COMMIT;
