BEGIN;

-- The typed private mapping remains required. There is no public submit route,
-- request-root parser, closure planner, recovery service, or destructive GC
-- contraction in this tranche.
SELECT 1;

COMMIT;
