CREATE TABLE node_identity_state (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    authorization_revision bigint NOT NULL DEFAULT 1 CHECK (authorization_revision > 0),
    active_artifact_key_id text,
    updated_at timestamptz NOT NULL
);

INSERT INTO node_identity_state (node_id, authorization_revision, updated_at)
SELECT id, 1, created_at FROM nodes;

CREATE FUNCTION maintain_node_identity_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO node_identity_state (node_id, authorization_revision, updated_at)
        VALUES (NEW.id, 1, NEW.created_at);
    ELSIF NEW.admin_state IS DISTINCT FROM OLD.admin_state THEN
        UPDATE node_identity_state
        SET authorization_revision = authorization_revision + 1,
            updated_at = GREATEST(node_identity_state.updated_at, NEW.updated_at)
        WHERE node_id = NEW.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER nodes_maintain_identity_state
AFTER INSERT OR UPDATE OF admin_state ON nodes
FOR EACH ROW EXECUTE FUNCTION maintain_node_identity_state();

CREATE FUNCTION protect_node_identity_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node identity state cannot be deleted';
    END IF;
    IF NEW.node_id IS DISTINCT FROM OLD.node_id OR
       NEW.authorization_revision <= OLD.authorization_revision OR
       NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node authorization revision must increase monotonically';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_identity_revision_monotonic
BEFORE UPDATE OR DELETE ON node_identity_state
FOR EACH ROW EXECUTE FUNCTION protect_node_identity_revision();

CREATE UNIQUE INDEX node_enrollment_authorizations_id_node_idx
    ON node_enrollment_authorizations (id, node_id);

CREATE TABLE node_identity_authorizations (
    id uuid PRIMARY KEY,
    token_id uuid NOT NULL UNIQUE,
    node_id uuid NOT NULL,
    purpose text NOT NULL,
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    csr_der bytea NOT NULL CHECK (octet_length(csr_der) BETWEEN 1 AND 65536),
    csr_sha256 bytea NOT NULL CHECK (octet_length(csr_sha256) = 32),
    machine_fingerprint_sha256 bytea NOT NULL CHECK (octet_length(machine_fingerprint_sha256) = 32),
    protocol_min_major integer NOT NULL CHECK (protocol_min_major BETWEEN 0 AND 65535),
    protocol_min_minor integer NOT NULL CHECK (protocol_min_minor BETWEEN 0 AND 65535),
    protocol_max_major integer NOT NULL CHECK (protocol_max_major BETWEEN 0 AND 65535),
    protocol_max_minor integer NOT NULL CHECK (protocol_max_minor BETWEEN 0 AND 65535),
    selected_protocol_major integer NOT NULL CHECK (selected_protocol_major BETWEEN 0 AND 65535),
    selected_protocol_minor integer NOT NULL CHECK (selected_protocol_minor BETWEEN 0 AND 65535),
    capabilities_snapshot bytea NOT NULL CHECK (octet_length(capabilities_snapshot) BETWEEN 1 AND 65536),
    capabilities_sha256 bytea NOT NULL CHECK (octet_length(capabilities_sha256) = 32),
    gateway_workload_identity text NOT NULL CHECK (
        gateway_workload_identity = btrim(gateway_workload_identity) AND
        char_length(gateway_workload_identity) BETWEEN 1 AND 256
    ),
    gateway_instance_id text NOT NULL CHECK (
        gateway_instance_id = btrim(gateway_instance_id) AND
        char_length(gateway_instance_id) BETWEEN 1 AND 128
    ),
    peer_ip inet,
    artifact_key_id text NOT NULL,
    artifact_public_key bytea NOT NULL CHECK (octet_length(artifact_public_key) = 32),
    status text NOT NULL CHECK (status IN ('authorized', 'signing', 'issued', 'expired')),
    authorized_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    signing_attempt integer NOT NULL DEFAULT 0 CHECK (signing_attempt >= 0),
    signing_lease_id uuid,
    signing_lease_expires_at timestamptz,
    issued_certificate_id uuid,
    completed_at timestamptz,
    FOREIGN KEY (id, node_id)
        REFERENCES node_enrollment_authorizations(id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (token_id, node_id, purpose)
        REFERENCES node_enrollment_tokens(id, node_id, purpose) ON DELETE RESTRICT,
    UNIQUE (id, node_id),
    CHECK (expires_at > authorized_at),
    CHECK (
        (protocol_min_major, protocol_min_minor) <= (selected_protocol_major, selected_protocol_minor) AND
        (selected_protocol_major, selected_protocol_minor) <= (protocol_max_major, protocol_max_minor)
    ),
    CHECK (
        (status = 'signing' AND signing_lease_id IS NOT NULL AND signing_lease_expires_at IS NOT NULL) OR
        (status <> 'signing' AND signing_lease_id IS NULL AND signing_lease_expires_at IS NULL)
    ),
    CHECK (
        (status = 'issued' AND issued_certificate_id IS NOT NULL AND completed_at IS NOT NULL) OR
        (status <> 'issued' AND issued_certificate_id IS NULL AND completed_at IS NULL)
    )
);

CREATE INDEX node_identity_authorizations_node_idx
    ON node_identity_authorizations (node_id, authorized_at DESC);
CREATE INDEX node_identity_authorizations_signing_idx
    ON node_identity_authorizations (signing_lease_expires_at) WHERE status = 'signing';

CREATE FUNCTION protect_node_identity_authorization()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node identity authorizations are immutable';
    END IF;
    IF ROW(NEW.id, NEW.token_id, NEW.node_id, NEW.purpose, NEW.request_id,
           NEW.request_digest, NEW.token_hash, NEW.csr_der, NEW.csr_sha256,
           NEW.machine_fingerprint_sha256, NEW.protocol_min_major, NEW.protocol_min_minor,
           NEW.protocol_max_major, NEW.protocol_max_minor, NEW.selected_protocol_major,
           NEW.selected_protocol_minor, NEW.capabilities_snapshot, NEW.capabilities_sha256,
           NEW.gateway_workload_identity, NEW.gateway_instance_id, NEW.peer_ip,
           NEW.artifact_key_id, NEW.artifact_public_key, NEW.authorized_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.token_id, OLD.node_id, OLD.purpose, OLD.request_id,
           OLD.request_digest, OLD.token_hash, OLD.csr_der, OLD.csr_sha256,
           OLD.machine_fingerprint_sha256, OLD.protocol_min_major, OLD.protocol_min_minor,
           OLD.protocol_max_major, OLD.protocol_max_minor, OLD.selected_protocol_major,
           OLD.selected_protocol_minor, OLD.capabilities_snapshot, OLD.capabilities_sha256,
           OLD.gateway_workload_identity, OLD.gateway_instance_id, OLD.peer_ip,
           OLD.artifact_key_id, OLD.artifact_public_key, OLD.authorized_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'node identity authorization content is immutable';
    END IF;
    IF NOT (
        (OLD.status = 'authorized' AND NEW.status IN ('signing', 'expired')) OR
        (OLD.status = 'signing' AND NEW.status IN ('authorized', 'issued', 'expired'))
    ) THEN
        RAISE EXCEPTION 'invalid node identity authorization transition';
    END IF;
    IF NEW.signing_attempt < OLD.signing_attempt THEN
        RAISE EXCEPTION 'signing attempt cannot decrease';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_identity_authorizations_protected
BEFORE UPDATE OR DELETE ON node_identity_authorizations
FOR EACH ROW EXECUTE FUNCTION protect_node_identity_authorization();

CREATE FUNCTION valid_public_certificate_chain(value bytea[])
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item bytea;
    total_bytes bigint := 0;
BEGIN
    IF value IS NULL OR cardinality(value) < 1 OR cardinality(value) > 8 THEN
        RETURN false;
    END IF;
    FOREACH item IN ARRAY value LOOP
        IF item IS NULL OR octet_length(item) < 1 OR octet_length(item) > 65536 THEN
            RETURN false;
        END IF;
        total_bytes := total_bytes + octet_length(item);
    END LOOP;
    RETURN total_bytes <= 262144;
END;
$$;

CREATE TABLE node_artifact_encryption_keys (
    id text PRIMARY KEY CHECK (
        char_length(id) = 71 AND id ~ '^x25519:[0-9a-f]{64}$'
    ),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    authorization_id uuid NOT NULL UNIQUE,
    public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    public_key_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(public_key_sha256) = 32),
    status text NOT NULL CHECK (status IN ('pending', 'active', 'retired', 'revoked')),
    created_at timestamptz NOT NULL,
    activated_at timestamptz,
    deactivated_at timestamptz,
    deactivation_reason text CHECK (
        deactivation_reason IS NULL OR
        (deactivation_reason = btrim(deactivation_reason) AND char_length(deactivation_reason) BETWEEN 1 AND 256)
    ),
    FOREIGN KEY (authorization_id, node_id)
        REFERENCES node_identity_authorizations(id, node_id) ON DELETE RESTRICT,
    UNIQUE (id, node_id),
    CHECK (
        (status = 'pending' AND activated_at IS NULL AND deactivated_at IS NULL AND deactivation_reason IS NULL) OR
        (status = 'active' AND activated_at IS NOT NULL AND deactivated_at IS NULL AND deactivation_reason IS NULL) OR
        (status = 'retired' AND activated_at IS NOT NULL AND deactivated_at IS NOT NULL AND deactivation_reason IS NOT NULL) OR
        (status = 'revoked' AND deactivated_at IS NOT NULL AND deactivation_reason IS NOT NULL)
    ),
    CHECK (activated_at IS NULL OR activated_at >= created_at),
    CHECK (deactivated_at IS NULL OR (deactivated_at >= created_at AND (activated_at IS NULL OR deactivated_at >= activated_at)))
);

CREATE UNIQUE INDEX node_artifact_encryption_keys_one_active_idx
    ON node_artifact_encryption_keys (node_id) WHERE status = 'active';

CREATE FUNCTION protect_node_artifact_encryption_key()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'node artifact encryption keys are immutable';
    END IF;
    IF ROW(NEW.id, NEW.node_id, NEW.authorization_id, NEW.public_key,
           NEW.public_key_sha256, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.node_id, OLD.authorization_id, OLD.public_key,
           OLD.public_key_sha256, OLD.created_at) THEN
        RAISE EXCEPTION 'node artifact encryption key content is immutable';
    END IF;
    IF NOT (
        (OLD.status = 'pending' AND NEW.status IN ('active', 'revoked')) OR
        (OLD.status = 'active' AND NEW.status IN ('retired', 'revoked'))
    ) THEN
        RAISE EXCEPTION 'invalid artifact encryption key transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_artifact_encryption_keys_protected
BEFORE UPDATE OR DELETE ON node_artifact_encryption_keys
FOR EACH ROW EXECUTE FUNCTION protect_node_artifact_encryption_key();

ALTER TABLE node_identity_state
    ADD CONSTRAINT node_identity_state_active_artifact_key_fk
    FOREIGN KEY (active_artifact_key_id, node_id)
    REFERENCES node_artifact_encryption_keys(id, node_id) ON DELETE RESTRICT;

CREATE TABLE node_certificate_renewal_requests (
    request_id uuid PRIMARY KEY,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    current_certificate_id uuid NOT NULL,
    current_serial_number text NOT NULL CHECK (
        char_length(current_serial_number) BETWEEN 1 AND 128 AND current_serial_number ~ '^[0-9a-f]+$'
    ),
    csr_der bytea NOT NULL CHECK (octet_length(csr_der) BETWEEN 1 AND 65536),
    csr_sha256 bytea NOT NULL CHECK (octet_length(csr_sha256) = 32),
    gateway_workload_identity text NOT NULL CHECK (
        gateway_workload_identity = btrim(gateway_workload_identity) AND
        char_length(gateway_workload_identity) BETWEEN 1 AND 256
    ),
    gateway_instance_id text NOT NULL CHECK (
        gateway_instance_id = btrim(gateway_instance_id) AND
        char_length(gateway_instance_id) BETWEEN 1 AND 128
    ),
    status text NOT NULL CHECK (status IN ('pending', 'signing', 'issued', 'expired')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    signing_attempt integer NOT NULL DEFAULT 0 CHECK (signing_attempt >= 0),
    signing_lease_id uuid,
    signing_lease_expires_at timestamptz,
    issued_certificate_id uuid,
    completed_at timestamptz,
    UNIQUE (request_id, node_id),
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'signing' AND signing_lease_id IS NOT NULL AND signing_lease_expires_at IS NOT NULL) OR
        (status <> 'signing' AND signing_lease_id IS NULL AND signing_lease_expires_at IS NULL)
    ),
    CHECK (
        (status = 'issued' AND issued_certificate_id IS NOT NULL AND completed_at IS NOT NULL) OR
        (status <> 'issued' AND issued_certificate_id IS NULL AND completed_at IS NULL)
    )
);

CREATE UNIQUE INDEX node_certificate_renewal_one_live_child_idx
    ON node_certificate_renewal_requests (current_certificate_id)
    WHERE status <> 'expired';

CREATE TABLE node_certificates (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    issuance_kind text NOT NULL CHECK (issuance_kind IN ('initial', 'renewal')),
    enrollment_authorization_id uuid,
    renewal_request_id uuid,
    replaces_certificate_id uuid,
    serial_number text NOT NULL UNIQUE CHECK (
        char_length(serial_number) BETWEEN 1 AND 128 AND serial_number ~ '^[0-9a-f]+$'
    ),
    csr_sha256 bytea NOT NULL CHECK (octet_length(csr_sha256) = 32),
    certificate_public_key_sha256 bytea NOT NULL CHECK (octet_length(certificate_public_key_sha256) = 32),
    uri_san text NOT NULL CHECK (
        uri_san = btrim(uri_san) AND char_length(uri_san) BETWEEN 1 AND 512
    ),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    renewal_at timestamptz NOT NULL,
    leaf_certificate_pem bytea NOT NULL CHECK (octet_length(leaf_certificate_pem) BETWEEN 1 AND 65536),
    issuing_chain_pem bytea[] NOT NULL CHECK (valid_public_certificate_chain(issuing_chain_pem)),
    leaf_certificate_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(leaf_certificate_sha256) = 32),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    issued_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason text CHECK (
        revocation_reason IS NULL OR
        (revocation_reason = btrim(revocation_reason) AND char_length(revocation_reason) BETWEEN 1 AND 256)
    ),
    UNIQUE (id, node_id),
    UNIQUE (enrollment_authorization_id),
    UNIQUE (renewal_request_id),
    FOREIGN KEY (enrollment_authorization_id, node_id)
        REFERENCES node_identity_authorizations(id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (renewal_request_id, node_id)
        REFERENCES node_certificate_renewal_requests(request_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (replaces_certificate_id, node_id)
        REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT,
    CHECK (not_before < renewal_at AND renewal_at < not_after),
    CHECK (
        (issuance_kind = 'initial' AND enrollment_authorization_id IS NOT NULL AND
         renewal_request_id IS NULL AND replaces_certificate_id IS NULL) OR
        (issuance_kind = 'renewal' AND enrollment_authorization_id IS NULL AND
         renewal_request_id IS NOT NULL AND replaces_certificate_id IS NOT NULL)
    ),
    CHECK (
        (status = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL) OR
        (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

ALTER TABLE node_identity_authorizations
    ADD CONSTRAINT node_identity_authorizations_certificate_fk
    FOREIGN KEY (issued_certificate_id, node_id)
    REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT;

ALTER TABLE node_certificate_renewal_requests
    ADD CONSTRAINT node_certificate_renewal_current_fk
    FOREIGN KEY (current_certificate_id, node_id)
    REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT,
    ADD CONSTRAINT node_certificate_renewal_issued_fk
    FOREIGN KEY (issued_certificate_id, node_id)
    REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT;

CREATE INDEX node_certificates_node_expiry_idx
    ON node_certificates (node_id, not_after DESC);
CREATE INDEX node_certificates_active_expiry_idx
    ON node_certificates (not_after) WHERE status = 'active';

CREATE FUNCTION protect_node_certificate()
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

CREATE TRIGGER node_certificates_protected
BEFORE UPDATE OR DELETE ON node_certificates
FOR EACH ROW EXECUTE FUNCTION protect_node_certificate();

CREATE FUNCTION protect_node_certificate_renewal()
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

CREATE TRIGGER node_certificate_renewals_protected
BEFORE UPDATE OR DELETE ON node_certificate_renewal_requests
FOR EACH ROW EXECUTE FUNCTION protect_node_certificate_renewal();

CREATE TABLE node_certificate_revocations (
    request_id uuid PRIMARY KEY,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    certificate_id uuid NOT NULL UNIQUE,
    node_id uuid NOT NULL,
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 256
    ),
    revoked_at timestamptz NOT NULL,
    authorization_revision bigint NOT NULL CHECK (authorization_revision > 0),
    FOREIGN KEY (certificate_id, node_id)
        REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT,
    UNIQUE (node_id, authorization_revision)
);

CREATE FUNCTION prevent_node_certificate_revocation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node certificate revocations are append-only';
END;
$$;

CREATE TRIGGER node_certificate_revocations_append_only
BEFORE UPDATE OR DELETE ON node_certificate_revocations
FOR EACH ROW EXECUTE FUNCTION prevent_node_certificate_revocation_mutation();

CREATE TABLE node_certificate_events (
    id uuid PRIMARY KEY,
    node_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('issued', 'renewed', 'revoked')),
    related_certificate_id uuid,
    reason text,
    authorization_revision bigint NOT NULL CHECK (authorization_revision > 0),
    occurred_at timestamptz NOT NULL,
    FOREIGN KEY (certificate_id, node_id)
        REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (related_certificate_id, node_id)
        REFERENCES node_certificates(id, node_id) ON DELETE RESTRICT,
    UNIQUE (node_id, authorization_revision),
    CHECK (
        (event_type = 'issued' AND related_certificate_id IS NULL AND reason IS NULL) OR
        (event_type = 'renewed' AND related_certificate_id IS NOT NULL AND reason IS NULL) OR
        (event_type = 'revoked' AND related_certificate_id IS NULL AND reason IS NOT NULL AND
         reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 256)
    )
);

CREATE FUNCTION prevent_node_certificate_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node certificate events are append-only';
END;
$$;

CREATE TRIGGER node_certificate_events_append_only
BEFORE UPDATE OR DELETE ON node_certificate_events
FOR EACH ROW EXECUTE FUNCTION prevent_node_certificate_event_mutation();
