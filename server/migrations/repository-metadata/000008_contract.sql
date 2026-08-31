BEGIN;

-- Null authority remains valid only for legacy-adapter rows. Production
-- identity-bound replay rejects it in the transaction participant boundary.
SELECT 1;

COMMIT;
