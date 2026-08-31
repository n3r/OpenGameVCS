BEGIN;

-- PostgreSQL's ARE engine rejects interval upper bounds greater than 255.
-- Add equivalent length-plus-character constraints without modifying the
-- immutable v1 migration or dropping its constraints before validation.
ALTER TABLE ogvcs_identity.transaction_decision_commitments
    ADD CONSTRAINT transaction_decision_commitments_commitment_id_opaque_v2
        CHECK (octet_length(commitment_id) BETWEEN 1 AND 256
               AND commitment_id !~ '[^A-Za-z0-9._:-]') NOT VALID,
    ADD CONSTRAINT transaction_decision_commitments_transaction_id_opaque_v2
        CHECK (octet_length(transaction_id) BETWEEN 1 AND 256
               AND transaction_id !~ '[^A-Za-z0-9._:-]') NOT VALID,
    ADD CONSTRAINT transaction_decision_commitments_correlation_id_opaque_v2
        CHECK (octet_length(correlation_id) BETWEEN 1 AND 256
               AND correlation_id !~ '[^A-Za-z0-9._:-]') NOT VALID;

ALTER TABLE ogvcs_identity.privileged_audit_events
    ADD CONSTRAINT privileged_audit_events_event_id_opaque_v2
        CHECK (octet_length(event_id) BETWEEN 1 AND 256
               AND event_id !~ '[^A-Za-z0-9._:-]') NOT VALID,
    ADD CONSTRAINT privileged_audit_events_correlation_id_opaque_v2
        CHECK (octet_length(correlation_id) BETWEEN 1 AND 256
               AND correlation_id !~ '[^A-Za-z0-9._:-]') NOT VALID,
    ADD CONSTRAINT privileged_audit_events_details_change_ref_opaque_v2
        CHECK (details_change_ref IS NULL
               OR (octet_length(details_change_ref) BETWEEN 1 AND 256
                   AND details_change_ref !~ '[^A-Za-z0-9._:-]')) NOT VALID;

COMMIT;
