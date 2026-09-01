BEGIN;

-- Existing transfer.record-available candidate rows predate reconstructable
-- proof storage. They deliberately remain readable as lifecycle history but
-- cannot be promoted into authenticated committed proofs by fabrication.
SELECT 1;

COMMIT;
