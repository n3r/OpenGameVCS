BEGIN;

-- Outbox delivery state is service-owned and additive.  A lease is either
-- completely absent or completely bound to one consumer and expiry.
ALTER TABLE ogvcs_metadata.outbox_events
    ADD COLUMN lease_id uuid,
    ADD COLUMN leased_by text,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN delivery_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN acknowledged_at timestamptz,
    ADD CONSTRAINT outbox_events_lease_complete CHECK (
        (lease_id IS NULL AND leased_by IS NULL AND lease_expires_at IS NULL)
        OR
        (lease_id IS NOT NULL
         AND leased_by IS NOT NULL
         AND octet_length(leased_by) BETWEEN 1 AND 256
         AND lease_expires_at IS NOT NULL)
    ),
    ADD CONSTRAINT outbox_events_delivery_attempts_nonnegative
        CHECK (delivery_attempts >= 0),
    ADD CONSTRAINT outbox_events_acknowledgement_clears_lease CHECK (
        acknowledged_at IS NULL
        OR (lease_id IS NULL AND leased_by IS NULL AND lease_expires_at IS NULL)
    );

CREATE INDEX outbox_events_deliverable_v3
    ON ogvcs_metadata.outbox_events(available_at, event_id)
    WHERE acknowledged_at IS NULL;

COMMIT;
