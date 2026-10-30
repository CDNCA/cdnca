LOCK TABLE node_certificate_renewal_requests,
           node_certificates,
           node_certificate_revocations,
           node_certificate_events,
           node_ca_key_epochs,
           node_ca_key_epoch_revocations
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM node_ca_key_epochs) OR
       EXISTS (SELECT 1 FROM node_certificates WHERE rotation_status <> 'legacy_unbound') OR
       EXISTS (SELECT 1 FROM node_certificate_renewal_requests WHERE pop_status <> 'legacy_unbound') OR
       EXISTS (SELECT 1 FROM node_certificate_revocations WHERE binding_status <> 'legacy_unbound') THEN
        RAISE EXCEPTION 'cannot roll back node certificate lifecycle while 036 live facts exist';
    END IF;
END;
$$;

DROP TRIGGER node_certificate_events_truncate_protected ON node_certificate_events;
DROP TRIGGER node_certificate_revocations_truncate_protected ON node_certificate_revocations;
DROP TRIGGER node_certificate_renewals_truncate_protected ON node_certificate_renewal_requests;
DROP TRIGGER node_certificates_truncate_protected ON node_certificates;
DROP TRIGGER node_ca_key_epoch_revocations_truncate_protected ON node_ca_key_epoch_revocations;
DROP TRIGGER node_ca_key_epochs_truncate_protected ON node_ca_key_epochs;
DROP FUNCTION prevent_node_certificate_lifecycle_truncate();

DROP INDEX node_certificate_revocations_certificate_effective_idx;

ALTER TABLE node_certificate_revocations
    DROP CONSTRAINT node_certificate_revocations_binding_check,
    DROP CONSTRAINT node_certificate_revocations_binding_status_check,
    DROP CONSTRAINT node_certificate_revocations_leaf_digest_check,
    DROP CONSTRAINT node_certificate_revocations_ca_epoch_fk,
    DROP CONSTRAINT node_certificate_revocations_installation_fk,
    DROP CONSTRAINT node_certificate_revocations_owner_node_fk,
    DROP COLUMN binding_status,
    DROP COLUMN effective_at,
    DROP COLUMN leaf_der_sha256,
    DROP COLUMN ca_epoch_id,
    DROP COLUMN installation_id,
    DROP COLUMN owner_scope_id;

ALTER TABLE node_certificate_revocations
    ADD CONSTRAINT node_certificate_revocations_certificate_id_key UNIQUE (certificate_id);

DROP TRIGGER node_certificate_renewals_pop_columns_protected ON node_certificate_renewal_requests;
DROP FUNCTION protect_node_certificate_renewal_pop_columns();

CREATE OR REPLACE FUNCTION protect_node_certificate_renewal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node certificate renewal requests are immutable';
    END IF;
    IF ROW(NEW.request_id, NEW.request_digest, NEW.node_id, NEW.current_certificate_id,
           NEW.current_serial_number, NEW.csr_der, NEW.csr_sha256,
           NEW.gateway_workload_identity, NEW.gateway_instance_id, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.request_id, OLD.request_digest, OLD.node_id, OLD.current_certificate_id,
           OLD.current_serial_number, OLD.csr_der, OLD.csr_sha256,
           OLD.gateway_workload_identity, OLD.gateway_instance_id, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'node certificate renewal content is immutable';
    END IF;
    IF NOT (
        (OLD.status = 'pending' AND NEW.status IN ('signing', 'expired')) OR
        (OLD.status = 'signing' AND NEW.status IN ('pending', 'issued', 'expired'))
    ) THEN
        RAISE EXCEPTION 'invalid node certificate renewal transition';
    END IF;
    IF NEW.signing_attempt < OLD.signing_attempt THEN
        RAISE EXCEPTION 'signing attempt cannot decrease';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE node_certificate_renewal_requests
    DROP CONSTRAINT node_certificate_renewals_message_digest_check,
    DROP CONSTRAINT node_certificate_renewals_leaf_digest_check,
    DROP CONSTRAINT node_certificate_renewals_rotation_binding_check,
    DROP CONSTRAINT node_certificate_renewals_pop_binding_check,
    DROP CONSTRAINT node_certificate_renewals_pop_revision_check,
    DROP CONSTRAINT node_certificate_renewals_pop_status_check,
    DROP CONSTRAINT node_certificate_renewals_issued_ca_epoch_fk,
    DROP CONSTRAINT node_certificate_renewals_ca_epoch_fk,
    DROP CONSTRAINT node_certificate_renewals_installation_fk,
    DROP CONSTRAINT node_certificate_renewals_owner_node_fk,
    DROP COLUMN overlap_until,
    DROP COLUMN rotation_bound_at,
    DROP COLUMN issued_ca_epoch_id,
    DROP COLUMN issued_leaf_der_sha256,
    DROP COLUMN pop_observed_at,
    DROP COLUMN pop_signature,
    DROP COLUMN pop_algorithm,
    DROP COLUMN pop_message_sha256,
    DROP COLUMN pop_method,
    DROP COLUMN pop_revision,
    DROP COLUMN pop_status,
    DROP COLUMN current_leaf_der_sha256,
    DROP COLUMN ca_epoch_id,
    DROP COLUMN installation_id,
    DROP COLUMN owner_scope_id;

DROP TRIGGER node_certificates_lifecycle_columns_protected ON node_certificates;
DROP FUNCTION protect_node_certificate_lifecycle_columns();

CREATE OR REPLACE FUNCTION protect_node_certificate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node certificates are immutable';
    END IF;
    IF ROW(NEW.id, NEW.node_id, NEW.issuance_kind, NEW.enrollment_authorization_id,
           NEW.renewal_request_id, NEW.replaces_certificate_id, NEW.serial_number,
           NEW.csr_sha256, NEW.certificate_public_key_sha256, NEW.uri_san,
           NEW.not_before, NEW.not_after, NEW.renewal_at, NEW.leaf_certificate_pem,
           NEW.issuing_chain_pem, NEW.leaf_certificate_sha256, NEW.issued_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.node_id, OLD.issuance_kind, OLD.enrollment_authorization_id,
           OLD.renewal_request_id, OLD.replaces_certificate_id, OLD.serial_number,
           OLD.csr_sha256, OLD.certificate_public_key_sha256, OLD.uri_san,
           OLD.not_before, OLD.not_after, OLD.renewal_at, OLD.leaf_certificate_pem,
           OLD.issuing_chain_pem, OLD.leaf_certificate_sha256, OLD.issued_at) THEN
        RAISE EXCEPTION 'node certificate content is immutable';
    END IF;
    IF OLD.status <> 'active' OR NEW.status <> 'revoked' THEN
        RAISE EXCEPTION 'invalid node certificate transition';
    END IF;
    RETURN NEW;
END;
$$;

DROP INDEX node_certificates_lifecycle_scope_node_idx;
DROP INDEX node_certificates_one_lifecycle_overlap_idx;
DROP INDEX node_certificates_one_lifecycle_current_idx;

ALTER TABLE node_certificates
    DROP CONSTRAINT node_certificates_lifecycle_binding_check,
    DROP CONSTRAINT node_certificates_ca_epoch_fk,
    DROP CONSTRAINT node_certificates_installation_fk,
    DROP CONSTRAINT node_certificates_owner_node_fk,
    DROP CONSTRAINT node_certificates_lifecycle_request_digest_check,
    DROP CONSTRAINT node_certificates_lifecycle_request_id_unique,
    DROP CONSTRAINT node_certificates_lifecycle_revision_check,
    DROP CONSTRAINT node_certificates_rotation_status_check,
    DROP CONSTRAINT node_certificates_leaf_der_sha256_check,
    DROP COLUMN overlap_until,
    DROP COLUMN lifecycle_bound_at,
    DROP COLUMN lifecycle_request_digest,
    DROP COLUMN lifecycle_request_id,
    DROP COLUMN lifecycle_revision,
    DROP COLUMN rotation_status,
    DROP COLUMN leaf_der_sha256,
    DROP COLUMN ca_epoch_id,
    DROP COLUMN installation_id,
    DROP COLUMN owner_scope_id;

DROP TRIGGER node_ca_key_epoch_revocations_append_only ON node_ca_key_epoch_revocations;
DROP FUNCTION prevent_node_ca_key_epoch_revocation_mutation();
DROP TABLE node_ca_key_epoch_revocations;

DROP TRIGGER node_ca_key_epochs_protected ON node_ca_key_epochs;
DROP FUNCTION protect_node_ca_key_epoch();
DROP TABLE node_ca_key_epochs;

DELETE FROM role_permissions WHERE permission_name = 'node_ca.manage';
DELETE FROM permissions WHERE name = 'node_ca.manage';
