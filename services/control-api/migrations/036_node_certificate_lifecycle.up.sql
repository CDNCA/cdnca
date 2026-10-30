INSERT INTO permissions (name, description) VALUES
    ('node_ca.manage', 'Rotate and revoke the node certificate authority trust root');

INSERT INTO role_permissions (role_id, permission_name)
SELECT id, 'node_ca.manage' FROM roles
WHERE system_role AND name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE TABLE node_ca_key_epochs (
    id uuid PRIMARY KEY,
    installation_id text NOT NULL REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    epoch bigint NOT NULL CHECK (epoch > 0),
    key_id text NOT NULL CHECK (
        char_length(key_id) BETWEEN 1 AND 128 AND key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    ca_certificate_pem bytea NOT NULL CHECK (octet_length(ca_certificate_pem) BETWEEN 1 AND 65536),
    ca_certificate_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(ca_certificate_sha256) = 32),
    public_key_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(public_key_sha256) = 32),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'retired', 'revoked')),
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    retired_at timestamptz,
    revoked_at timestamptz,
    revocation_reason text CHECK (
        revocation_reason IS NULL OR
        (revocation_reason = btrim(revocation_reason) AND char_length(revocation_reason) BETWEEN 1 AND 256)
    ),
    UNIQUE (installation_id, epoch),
    UNIQUE (installation_id, id),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (not_after > not_before),
    CHECK (
        (status = 'active' AND retired_at IS NULL AND revoked_at IS NULL AND revocation_reason IS NULL) OR
        (status = 'retired' AND retired_at IS NOT NULL AND revoked_at IS NULL AND revocation_reason IS NULL) OR
        (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE UNIQUE INDEX node_ca_key_epochs_one_active_idx
    ON node_ca_key_epochs (installation_id) WHERE status = 'active';

CREATE FUNCTION protect_node_ca_key_epoch()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node CA key epochs cannot be deleted';
    END IF;
    IF ROW(NEW.id, NEW.installation_id, NEW.epoch, NEW.key_id, NEW.ca_certificate_pem,
           NEW.ca_certificate_sha256, NEW.public_key_sha256, NEW.not_before, NEW.not_after,
           NEW.request_id, NEW.request_digest, NEW.created_by_scope_id, NEW.created_by_user_id,
           NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.installation_id, OLD.epoch, OLD.key_id, OLD.ca_certificate_pem,
           OLD.ca_certificate_sha256, OLD.public_key_sha256, OLD.not_before, OLD.not_after,
           OLD.request_id, OLD.request_digest, OLD.created_by_scope_id, OLD.created_by_user_id,
           OLD.created_at) THEN
        RAISE EXCEPTION 'node CA key epoch content is immutable';
    END IF;
    IF NOT (
        (OLD.status = 'active' AND NEW.status IN ('retired', 'revoked')) OR
        (OLD.status = 'retired' AND NEW.status = 'revoked')
    ) THEN
        RAISE EXCEPTION 'invalid node CA key epoch transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_ca_key_epochs_protected
BEFORE UPDATE OR DELETE ON node_ca_key_epochs
FOR EACH ROW EXECUTE FUNCTION protect_node_ca_key_epoch();

CREATE TABLE node_ca_key_epoch_revocations (
    request_id uuid PRIMARY KEY,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    ca_epoch_id uuid NOT NULL UNIQUE REFERENCES node_ca_key_epochs(id) ON DELETE RESTRICT,
    installation_id text NOT NULL,
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 256
    ),
    revoked_at timestamptz NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    FOREIGN KEY (installation_id, ca_epoch_id)
        REFERENCES node_ca_key_epochs(installation_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE FUNCTION prevent_node_ca_key_epoch_revocation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node CA key epoch revocations are append-only';
END;
$$;

CREATE TRIGGER node_ca_key_epoch_revocations_append_only
BEFORE UPDATE OR DELETE ON node_ca_key_epoch_revocations
FOR EACH ROW EXECUTE FUNCTION prevent_node_ca_key_epoch_revocation_mutation();

ALTER TABLE node_certificates
    ADD COLUMN owner_scope_id uuid,
    ADD COLUMN installation_id text,
    ADD COLUMN ca_epoch_id uuid,
    ADD COLUMN leaf_der_sha256 bytea,
    ADD COLUMN rotation_status text NOT NULL DEFAULT 'legacy_unbound',
    ADD COLUMN lifecycle_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN lifecycle_request_id uuid,
    ADD COLUMN lifecycle_request_digest bytea,
    ADD COLUMN lifecycle_bound_at timestamptz,
    ADD COLUMN overlap_until timestamptz,
    ADD CONSTRAINT node_certificates_leaf_der_sha256_check
        CHECK (leaf_der_sha256 IS NULL OR octet_length(leaf_der_sha256) = 32),
    ADD CONSTRAINT node_certificates_rotation_status_check
        CHECK (rotation_status IN ('legacy_unbound', 'current', 'overlap', 'retired')),
    ADD CONSTRAINT node_certificates_lifecycle_revision_check
        CHECK (lifecycle_revision >= 0),
    ADD CONSTRAINT node_certificates_lifecycle_request_id_unique UNIQUE (lifecycle_request_id),
    ADD CONSTRAINT node_certificates_lifecycle_request_digest_check
        CHECK (lifecycle_request_digest IS NULL OR octet_length(lifecycle_request_digest) = 32),
    ADD CONSTRAINT node_certificates_owner_node_fk
        FOREIGN KEY (owner_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificates_installation_fk
        FOREIGN KEY (installation_id) REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificates_ca_epoch_fk
        FOREIGN KEY (installation_id, ca_epoch_id) REFERENCES node_ca_key_epochs(installation_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificates_lifecycle_binding_check CHECK (
        (rotation_status = 'legacy_unbound' AND owner_scope_id IS NULL AND installation_id IS NULL AND
         ca_epoch_id IS NULL AND leaf_der_sha256 IS NULL AND lifecycle_revision = 0 AND
         lifecycle_request_id IS NULL AND lifecycle_request_digest IS NULL AND
         lifecycle_bound_at IS NULL AND overlap_until IS NULL) OR
        (rotation_status = 'current' AND owner_scope_id IS NOT NULL AND installation_id IS NOT NULL AND
         ca_epoch_id IS NOT NULL AND leaf_der_sha256 IS NOT NULL AND lifecycle_revision > 0 AND
         lifecycle_request_id IS NOT NULL AND lifecycle_request_digest IS NOT NULL AND
         lifecycle_bound_at IS NOT NULL AND overlap_until IS NULL) OR
        (rotation_status IN ('overlap', 'retired') AND owner_scope_id IS NOT NULL AND installation_id IS NOT NULL AND
         ca_epoch_id IS NOT NULL AND leaf_der_sha256 IS NOT NULL AND lifecycle_revision > 0 AND
         lifecycle_request_id IS NOT NULL AND lifecycle_request_digest IS NOT NULL AND
         lifecycle_bound_at IS NOT NULL AND overlap_until IS NOT NULL)
    );

CREATE UNIQUE INDEX node_certificates_one_lifecycle_current_idx
    ON node_certificates (installation_id, node_id)
    WHERE rotation_status = 'current' AND status = 'active';
CREATE UNIQUE INDEX node_certificates_one_lifecycle_overlap_idx
    ON node_certificates (installation_id, node_id)
    WHERE rotation_status = 'overlap' AND status = 'active';
CREATE INDEX node_certificates_lifecycle_scope_node_idx
    ON node_certificates (owner_scope_id, node_id, rotation_status);

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
    IF NEW.status IS DISTINCT FROM OLD.status AND (OLD.status <> 'active' OR NEW.status <> 'revoked') THEN
        RAISE EXCEPTION 'invalid node certificate transition';
    END IF;
    IF NEW.status IS NOT DISTINCT FROM OLD.status AND
       ROW(NEW.revoked_at, NEW.revocation_reason) IS DISTINCT FROM
       ROW(OLD.revoked_at, OLD.revocation_reason) THEN
        RAISE EXCEPTION 'node certificate revocation fact is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_node_certificate_lifecycle_columns()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.owner_scope_id, NEW.installation_id, NEW.ca_epoch_id, NEW.leaf_der_sha256,
           NEW.rotation_status, NEW.lifecycle_revision, NEW.lifecycle_request_id,
           NEW.lifecycle_request_digest, NEW.lifecycle_bound_at, NEW.overlap_until)
       IS NOT DISTINCT FROM
       ROW(OLD.owner_scope_id, OLD.installation_id, OLD.ca_epoch_id, OLD.leaf_der_sha256,
           OLD.rotation_status, OLD.lifecycle_revision, OLD.lifecycle_request_id,
           OLD.lifecycle_request_digest, OLD.lifecycle_bound_at, OLD.overlap_until) THEN
        RETURN NEW;
    END IF;
    IF OLD.rotation_status = 'legacy_unbound' AND NEW.rotation_status = 'current' AND
       NEW.lifecycle_revision = 1 THEN
        RETURN NEW;
    END IF;
    IF OLD.rotation_status = 'current' AND NEW.rotation_status = 'overlap' AND
       NEW.lifecycle_revision = OLD.lifecycle_revision + 1 AND
       ROW(NEW.owner_scope_id, NEW.installation_id, NEW.ca_epoch_id, NEW.leaf_der_sha256,
           NEW.lifecycle_request_id, NEW.lifecycle_request_digest, NEW.lifecycle_bound_at)
       IS NOT DISTINCT FROM
       ROW(OLD.owner_scope_id, OLD.installation_id, OLD.ca_epoch_id, OLD.leaf_der_sha256,
           OLD.lifecycle_request_id, OLD.lifecycle_request_digest, OLD.lifecycle_bound_at) THEN
        RETURN NEW;
    END IF;
    IF OLD.rotation_status = 'overlap' AND NEW.rotation_status = 'retired' AND
       NEW.lifecycle_revision = OLD.lifecycle_revision + 1 AND
       ROW(NEW.owner_scope_id, NEW.installation_id, NEW.ca_epoch_id, NEW.leaf_der_sha256,
           NEW.lifecycle_request_id, NEW.lifecycle_request_digest, NEW.lifecycle_bound_at, NEW.overlap_until)
       IS NOT DISTINCT FROM
       ROW(OLD.owner_scope_id, OLD.installation_id, OLD.ca_epoch_id, OLD.leaf_der_sha256,
           OLD.lifecycle_request_id, OLD.lifecycle_request_digest, OLD.lifecycle_bound_at, OLD.overlap_until) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid node certificate lifecycle transition';
END;
$$;

CREATE TRIGGER node_certificates_lifecycle_columns_protected
BEFORE UPDATE ON node_certificates
FOR EACH ROW EXECUTE FUNCTION protect_node_certificate_lifecycle_columns();

ALTER TABLE node_certificate_renewal_requests
    ADD COLUMN owner_scope_id uuid,
    ADD COLUMN installation_id text,
    ADD COLUMN ca_epoch_id uuid,
    ADD COLUMN current_leaf_der_sha256 bytea,
    ADD COLUMN pop_status text NOT NULL DEFAULT 'legacy_unbound',
    ADD COLUMN pop_revision bigint NOT NULL DEFAULT 0,
    ADD COLUMN pop_method text,
    ADD COLUMN pop_message_sha256 bytea,
    ADD COLUMN pop_algorithm text,
    ADD COLUMN pop_signature bytea,
    ADD COLUMN pop_observed_at timestamptz,
    ADD COLUMN issued_leaf_der_sha256 bytea,
    ADD COLUMN issued_ca_epoch_id uuid,
    ADD COLUMN rotation_bound_at timestamptz,
    ADD COLUMN overlap_until timestamptz,
    ADD CONSTRAINT node_certificate_renewals_owner_node_fk
        FOREIGN KEY (owner_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_renewals_installation_fk
        FOREIGN KEY (installation_id) REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_renewals_ca_epoch_fk
        FOREIGN KEY (installation_id, ca_epoch_id) REFERENCES node_ca_key_epochs(installation_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_renewals_issued_ca_epoch_fk
        FOREIGN KEY (installation_id, issued_ca_epoch_id) REFERENCES node_ca_key_epochs(installation_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_renewals_pop_status_check
        CHECK (pop_status IN ('legacy_unbound', 'gateway_mtls_proven', 'cryptographic_proven')),
    ADD CONSTRAINT node_certificate_renewals_pop_revision_check CHECK (pop_revision >= 0),
    ADD CONSTRAINT node_certificate_renewals_pop_binding_check CHECK (
        (pop_status = 'legacy_unbound' AND owner_scope_id IS NULL AND installation_id IS NULL AND
         ca_epoch_id IS NULL AND current_leaf_der_sha256 IS NULL AND pop_revision = 0 AND
         pop_method IS NULL AND pop_message_sha256 IS NULL AND pop_algorithm IS NULL AND
         pop_signature IS NULL AND pop_observed_at IS NULL AND issued_leaf_der_sha256 IS NULL AND
         issued_ca_epoch_id IS NULL AND rotation_bound_at IS NULL AND overlap_until IS NULL) OR
        (pop_status = 'gateway_mtls_proven' AND owner_scope_id IS NOT NULL AND installation_id IS NOT NULL AND
         ca_epoch_id IS NOT NULL AND current_leaf_der_sha256 IS NOT NULL AND pop_revision > 0 AND
         pop_method = 'gateway_mtls' AND pop_message_sha256 IS NOT NULL AND pop_algorithm IS NULL AND
         pop_signature IS NULL AND pop_observed_at IS NOT NULL) OR
        (pop_status = 'cryptographic_proven' AND owner_scope_id IS NOT NULL AND installation_id IS NOT NULL AND
         ca_epoch_id IS NOT NULL AND current_leaf_der_sha256 IS NOT NULL AND pop_revision > 0 AND
         pop_method = 'certificate_signature' AND pop_message_sha256 IS NOT NULL AND
         pop_algorithm IN ('ed25519', 'ecdsa_sha256', 'rsa_pss_sha256') AND
         pop_signature IS NOT NULL AND octet_length(pop_signature) BETWEEN 1 AND 1024 AND
         pop_observed_at IS NOT NULL)
    ),
    ADD CONSTRAINT node_certificate_renewals_rotation_binding_check CHECK (
        (rotation_bound_at IS NULL AND issued_leaf_der_sha256 IS NULL AND issued_ca_epoch_id IS NULL AND overlap_until IS NULL) OR
        (rotation_bound_at IS NOT NULL AND issued_leaf_der_sha256 IS NOT NULL AND
         octet_length(issued_leaf_der_sha256) = 32 AND issued_ca_epoch_id IS NOT NULL AND overlap_until IS NOT NULL)
    ),
    ADD CONSTRAINT node_certificate_renewals_leaf_digest_check
        CHECK (current_leaf_der_sha256 IS NULL OR octet_length(current_leaf_der_sha256) = 32),
    ADD CONSTRAINT node_certificate_renewals_message_digest_check
        CHECK (pop_message_sha256 IS NULL OR octet_length(pop_message_sha256) = 32);

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
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
        (OLD.status = 'pending' AND NEW.status IN ('signing', 'expired')) OR
        (OLD.status = 'signing' AND NEW.status IN ('pending', 'issued', 'expired'))
    ) THEN
        RAISE EXCEPTION 'invalid node certificate renewal transition';
    END IF;
    IF NEW.status IS NOT DISTINCT FROM OLD.status AND
       ROW(NEW.signing_attempt, NEW.signing_lease_id, NEW.signing_lease_expires_at,
           NEW.issued_certificate_id, NEW.completed_at) IS DISTINCT FROM
       ROW(OLD.signing_attempt, OLD.signing_lease_id, OLD.signing_lease_expires_at,
           OLD.issued_certificate_id, OLD.completed_at) THEN
        RAISE EXCEPTION 'node certificate renewal state is immutable without a transition';
    END IF;
    IF NEW.signing_attempt < OLD.signing_attempt THEN
        RAISE EXCEPTION 'signing attempt cannot decrease';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_node_certificate_renewal_pop_columns()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.owner_scope_id, NEW.installation_id, NEW.ca_epoch_id,
           NEW.current_leaf_der_sha256, NEW.pop_status, NEW.pop_revision, NEW.pop_method,
           NEW.pop_message_sha256, NEW.pop_algorithm, NEW.pop_signature, NEW.pop_observed_at,
           NEW.issued_leaf_der_sha256, NEW.issued_ca_epoch_id, NEW.rotation_bound_at, NEW.overlap_until)
       IS NOT DISTINCT FROM
       ROW(OLD.owner_scope_id, OLD.installation_id, OLD.ca_epoch_id,
           OLD.current_leaf_der_sha256, OLD.pop_status, OLD.pop_revision, OLD.pop_method,
           OLD.pop_message_sha256, OLD.pop_algorithm, OLD.pop_signature, OLD.pop_observed_at,
           OLD.issued_leaf_der_sha256, OLD.issued_ca_epoch_id, OLD.rotation_bound_at, OLD.overlap_until) THEN
        RETURN NEW;
    END IF;
    IF OLD.pop_status = 'legacy_unbound' AND
       NEW.pop_status IN ('gateway_mtls_proven', 'cryptographic_proven') AND NEW.pop_revision = 1 AND
       NEW.rotation_bound_at IS NULL THEN
        RETURN NEW;
    END IF;
    IF OLD.pop_status = NEW.pop_status AND OLD.pop_status <> 'legacy_unbound' AND
       NEW.pop_revision = OLD.pop_revision + 1 AND OLD.rotation_bound_at IS NULL AND
       NEW.rotation_bound_at IS NOT NULL AND
       ROW(NEW.owner_scope_id, NEW.installation_id, NEW.ca_epoch_id,
           NEW.current_leaf_der_sha256, NEW.pop_method, NEW.pop_message_sha256,
           NEW.pop_algorithm, NEW.pop_signature, NEW.pop_observed_at)
       IS NOT DISTINCT FROM
       ROW(OLD.owner_scope_id, OLD.installation_id, OLD.ca_epoch_id,
           OLD.current_leaf_der_sha256, OLD.pop_method, OLD.pop_message_sha256,
           OLD.pop_algorithm, OLD.pop_signature, OLD.pop_observed_at) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid node certificate renewal proof transition';
END;
$$;

CREATE TRIGGER node_certificate_renewals_pop_columns_protected
BEFORE UPDATE ON node_certificate_renewal_requests
FOR EACH ROW EXECUTE FUNCTION protect_node_certificate_renewal_pop_columns();

ALTER TABLE node_certificate_revocations
    DROP CONSTRAINT node_certificate_revocations_certificate_id_key;

ALTER TABLE node_certificate_revocations
    ADD COLUMN owner_scope_id uuid,
    ADD COLUMN installation_id text,
    ADD COLUMN ca_epoch_id uuid,
    ADD COLUMN leaf_der_sha256 bytea,
    ADD COLUMN effective_at timestamptz,
    ADD COLUMN binding_status text NOT NULL DEFAULT 'legacy_unbound',
    ADD CONSTRAINT node_certificate_revocations_owner_node_fk
        FOREIGN KEY (owner_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_revocations_installation_fk
        FOREIGN KEY (installation_id) REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_revocations_ca_epoch_fk
        FOREIGN KEY (installation_id, ca_epoch_id) REFERENCES node_ca_key_epochs(installation_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_revocations_leaf_digest_check
        CHECK (leaf_der_sha256 IS NULL OR octet_length(leaf_der_sha256) = 32),
    ADD CONSTRAINT node_certificate_revocations_binding_status_check
        CHECK (binding_status IN ('legacy_unbound', 'bound')),
    ADD CONSTRAINT node_certificate_revocations_binding_check CHECK (
        (binding_status = 'legacy_unbound' AND owner_scope_id IS NULL AND installation_id IS NULL AND
         ca_epoch_id IS NULL AND leaf_der_sha256 IS NULL AND effective_at IS NULL) OR
        (binding_status = 'bound' AND owner_scope_id IS NOT NULL AND installation_id IS NOT NULL AND
         ca_epoch_id IS NOT NULL AND leaf_der_sha256 IS NOT NULL AND effective_at IS NOT NULL AND
         effective_at >= revoked_at)
    );

CREATE INDEX node_certificate_revocations_certificate_effective_idx
    ON node_certificate_revocations (certificate_id, effective_at);

CREATE FUNCTION prevent_node_certificate_lifecycle_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node certificate lifecycle history cannot be truncated';
END;
$$;

CREATE TRIGGER node_ca_key_epochs_truncate_protected
BEFORE TRUNCATE ON node_ca_key_epochs
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();

CREATE TRIGGER node_ca_key_epoch_revocations_truncate_protected
BEFORE TRUNCATE ON node_ca_key_epoch_revocations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();

CREATE TRIGGER node_certificates_truncate_protected
BEFORE TRUNCATE ON node_certificates
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();

CREATE TRIGGER node_certificate_renewals_truncate_protected
BEFORE TRUNCATE ON node_certificate_renewal_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();

CREATE TRIGGER node_certificate_revocations_truncate_protected
BEFORE TRUNCATE ON node_certificate_revocations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();

CREATE TRIGGER node_certificate_events_truncate_protected
BEFORE TRUNCATE ON node_certificate_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_certificate_lifecycle_truncate();
