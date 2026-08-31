BEGIN;

ALTER TABLE ogvcs_identity.transaction_decision_commitments
    VALIDATE CONSTRAINT transaction_decision_commitments_commitment_id_opaque_v2,
    VALIDATE CONSTRAINT transaction_decision_commitments_transaction_id_opaque_v2,
    VALIDATE CONSTRAINT transaction_decision_commitments_correlation_id_opaque_v2;

ALTER TABLE ogvcs_identity.privileged_audit_events
    VALIDATE CONSTRAINT privileged_audit_events_event_id_opaque_v2,
    VALIDATE CONSTRAINT privileged_audit_events_correlation_id_opaque_v2,
    VALIDATE CONSTRAINT privileged_audit_events_details_change_ref_opaque_v2;

COMMIT;
