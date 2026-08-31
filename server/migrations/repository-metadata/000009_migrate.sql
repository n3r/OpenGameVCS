BEGIN;

-- The v9 lifecycle ledger is additive. Historical repository metadata never
-- implied backend durability, lifecycle generation, health, or reachability,
-- so manufacturing lifecycle rows from object presence would be unsafe.
SELECT 1;

COMMIT;
