BEGIN;

-- Drop only the v1 constraints whose PostgreSQL regex cannot be evaluated.
-- The validated v2 constraints preserve the exact 1..256 ASCII surface.
ALTER TABLE ogvcs_identity.transaction_decision_commitments
    DROP CONSTRAINT transaction_decision_commitments_commitment_id_check,
    DROP CONSTRAINT transaction_decision_commitments_transaction_id_check,
    DROP CONSTRAINT transaction_decision_commitments_correlation_id_check;

ALTER TABLE ogvcs_identity.privileged_audit_events
    DROP CONSTRAINT privileged_audit_events_event_id_check,
    DROP CONSTRAINT privileged_audit_events_correlation_id_check,
    DROP CONSTRAINT privileged_audit_events_details_change_ref_check;

COMMIT;
