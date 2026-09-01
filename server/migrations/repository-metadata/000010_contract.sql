BEGIN;

-- The nullable v9 compatibility columns remain; production eligibility is
-- enforced by the exact evidence constraint and bridge revalidation.
SELECT 1;

COMMIT;
