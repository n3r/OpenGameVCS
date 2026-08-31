BEGIN;

-- Null remains valid for legacy adapter rows during the candidate window.
-- Production consumption rejects null and legacy consumption rejects non-null.
SELECT 1;

COMMIT;
