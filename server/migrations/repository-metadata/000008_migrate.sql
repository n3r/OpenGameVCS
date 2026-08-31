BEGIN;

-- Historical legacy-adapter records intentionally remain authority-unbound,
-- including results whose jsonb representation exceeds the new identity-row
-- ceiling. Identity-bound replay fails closed unless all v8 authority columns
-- exist; bounded SELECT projections avoid materializing an oversized legacy
-- result in the client.
SELECT 1;

COMMIT;
