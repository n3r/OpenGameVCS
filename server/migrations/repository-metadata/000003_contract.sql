BEGIN;

-- Once all binaries understand acknowledgement state, replace the v1 access
-- path with the partial index that excludes permanently acknowledged events.
DROP INDEX ogvcs_metadata.outbox_events_available;
ALTER INDEX ogvcs_metadata.outbox_events_deliverable_v3
    RENAME TO outbox_events_available;

COMMIT;
