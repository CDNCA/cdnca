DROP TRIGGER IF EXISTS node_certificate_events_append_only ON node_certificate_events;
DROP FUNCTION IF EXISTS prevent_node_certificate_event_mutation();
DROP TABLE IF EXISTS node_certificate_events;

DROP TRIGGER IF EXISTS node_certificate_revocations_append_only ON node_certificate_revocations;
DROP FUNCTION IF EXISTS prevent_node_certificate_revocation_mutation();
DROP TABLE IF EXISTS node_certificate_revocations;

ALTER TABLE IF EXISTS node_certificate_renewal_requests
    DROP CONSTRAINT IF EXISTS node_certificate_renewal_current_fk,
    DROP CONSTRAINT IF EXISTS node_certificate_renewal_issued_fk;
ALTER TABLE IF EXISTS node_identity_authorizations
    DROP CONSTRAINT IF EXISTS node_identity_authorizations_certificate_fk;

DROP TRIGGER IF EXISTS node_certificate_renewals_protected ON node_certificate_renewal_requests;
DROP FUNCTION IF EXISTS protect_node_certificate_renewal();
DROP TRIGGER IF EXISTS node_certificates_protected ON node_certificates;
DROP FUNCTION IF EXISTS protect_node_certificate();
DROP TABLE IF EXISTS node_certificates;
DROP INDEX IF EXISTS node_certificate_renewal_one_live_child_idx;
DROP TABLE IF EXISTS node_certificate_renewal_requests;

ALTER TABLE IF EXISTS node_identity_state
    DROP CONSTRAINT IF EXISTS node_identity_state_active_artifact_key_fk;
DROP TRIGGER IF EXISTS node_artifact_encryption_keys_protected ON node_artifact_encryption_keys;
DROP FUNCTION IF EXISTS protect_node_artifact_encryption_key();
DROP INDEX IF EXISTS node_artifact_encryption_keys_one_active_idx;
DROP TABLE IF EXISTS node_artifact_encryption_keys;

DROP FUNCTION IF EXISTS valid_public_certificate_chain(bytea[]);
DROP TRIGGER IF EXISTS node_identity_authorizations_protected ON node_identity_authorizations;
DROP FUNCTION IF EXISTS protect_node_identity_authorization();
DROP TABLE IF EXISTS node_identity_authorizations;
DROP INDEX IF EXISTS node_enrollment_authorizations_id_node_idx;

DROP TRIGGER IF EXISTS node_identity_revision_monotonic ON node_identity_state;
DROP FUNCTION IF EXISTS protect_node_identity_revision();
DROP TRIGGER IF EXISTS nodes_maintain_identity_state ON nodes;
DROP FUNCTION IF EXISTS maintain_node_identity_state();
DROP TABLE IF EXISTS node_identity_state;
