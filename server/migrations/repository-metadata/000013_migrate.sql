BEGIN;

-- Historical aggregate applications remain immutable and readable. A mapping
-- cannot be reconstructed honestly from the positional v9/v10 projection, so
-- old unconsumed lifecycle plans are deliberately not backfilled and fail
-- closed at the v13 bridge.
SELECT 1;

COMMIT;
