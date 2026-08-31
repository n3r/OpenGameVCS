BEGIN;

-- Additive receipt ledger: native FileID registrations created before v0.2
-- remain historical facts and do not receive synthetic receipts.
SELECT 1;

COMMIT;
