LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 110 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 110 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=110 AND migration_id='110_traffic_package_product_lifecycle'
          AND checksum_sha256='e645c599cb1b1ffe3dfe0a53a5acdaa87d04d97518dbf19747aceef5d8dcf44b'
          AND down_checksum_sha256='0dc88fe739b7fa14378d70724a5a37a0cdb03b4ef1899baf8052d2773929f690'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 111 requires the exact verified 110 release head' USING ERRCODE='P1110';
    END IF;
END;
$$;

CREATE TABLE firewall_command_outbox (
    id uuid PRIMARY KEY,
    installation_id text NOT NULL REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_kind text NOT NULL CHECK (policy_kind IN ('waf','cc','acl')),
    binding_id uuid NOT NULL,
    publication_id uuid NOT NULL,
    node_id uuid NOT NULL,
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    expected_active_policy_version bigint NOT NULL CHECK (expected_active_policy_version >= 0),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._-]+$'),
    command_bytes bytea NOT NULL CHECK (octet_length(command_bytes) BETWEEN 1 AND 1048576),
    command_sha256 bytea NOT NULL CHECK (octet_length(command_sha256)=32),
    publication_bundle_sha256 bytea NOT NULL CHECK (octet_length(publication_bundle_sha256)=32),
    canonical_payload_sha256 bytea NOT NULL CHECK (octet_length(canonical_payload_sha256)=32),
    runtime_snapshot_sha256 bytea NOT NULL CHECK (octet_length(runtime_snapshot_sha256)=32),
    signing_key_id text NOT NULL CHECK (char_length(signing_key_id) BETWEEN 1 AND 128 AND signing_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
    signature_algorithm text NOT NULL CHECK (signature_algorithm='ed25519'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','published','acked','retryable','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 16),
    available_at timestamptz NOT NULL,
    published_at timestamptz,
    acked_at timestamptz,
    last_error text CHECK (last_error IS NULL OR char_length(last_error) <= 2048),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, idempotency_key),
    UNIQUE (publication_id, node_id),
    FOREIGN KEY (tenant_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,node_id) REFERENCES nodes(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,binding_id) REFERENCES security_policy_site_bindings(tenant_scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,publication_id,binding_id) REFERENCES security_policy_publications(tenant_scope_id,id,binding_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,policy_id,policy_kind) REFERENCES security_policies(scope_id,id,kind) ON DELETE RESTRICT,
    CHECK (policy_version = expected_active_policy_version + 1),
    CHECK ((state='acked') = (acked_at IS NOT NULL)),
    CHECK (acked_at IS NULL OR published_at IS NOT NULL)
);

CREATE INDEX firewall_command_outbox_ready_idx ON firewall_command_outbox(available_at,id)
    WHERE state IN ('pending','retryable');

CREATE FUNCTION protect_firewall_command_outbox_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'firewall command outbox facts are append-only';
    END IF;
    IF ROW(NEW.id,NEW.installation_id,NEW.tenant_scope_id,NEW.site_id,NEW.policy_id,NEW.policy_kind,NEW.binding_id,
           NEW.publication_id,NEW.node_id,NEW.policy_version,NEW.expected_active_policy_version,
           NEW.idempotency_key,NEW.command_bytes,NEW.command_sha256,NEW.publication_bundle_sha256,
           NEW.canonical_payload_sha256,NEW.runtime_snapshot_sha256,NEW.signing_key_id,NEW.signature_algorithm,
           NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.installation_id,OLD.tenant_scope_id,OLD.site_id,
           OLD.policy_id,OLD.policy_kind,OLD.binding_id,OLD.publication_id,OLD.node_id,OLD.policy_version,
           OLD.expected_active_policy_version,OLD.idempotency_key,OLD.command_bytes,OLD.command_sha256,
           OLD.publication_bundle_sha256,OLD.canonical_payload_sha256,OLD.runtime_snapshot_sha256,
           OLD.signing_key_id,OLD.signature_algorithm,OLD.created_at) THEN
        RAISE EXCEPTION 'firewall command outbox command identity is immutable';
    END IF;
    IF NOT ((OLD.state='pending' AND NEW.state IN ('published','retryable','failed')) OR
            (OLD.state='retryable' AND NEW.state IN ('pending','published','failed')) OR
            (OLD.state='published' AND NEW.state IN ('acked','retryable','failed'))) THEN
        RAISE EXCEPTION 'invalid firewall command outbox state transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_command_outbox_mutation
BEFORE UPDATE OR DELETE ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION protect_firewall_command_outbox_mutation();

CREATE FUNCTION validate_firewall_command_outbox_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE publication record;
BEGIN
    SELECT p.tenant_scope_id,p.site_id,p.policy_id,p.policy_kind,p.policy_version,p.expected_active_version,
           p.bundle_sha256,p.canonical_payload_sha256,p.runtime_snapshot_sha256,p.signing_key_id,
           t.node_id INTO publication
    FROM security_policy_publications p
    JOIN security_policy_publication_targets t ON t.tenant_scope_id=p.tenant_scope_id AND t.publication_id=p.id AND t.binding_id=p.binding_id
    WHERE p.tenant_scope_id=NEW.tenant_scope_id AND p.id=NEW.publication_id AND p.binding_id=NEW.binding_id
      AND t.node_id=NEW.node_id AND t.released_at IS NULL
    FOR SHARE OF p,t;
    IF NOT FOUND OR publication.tenant_scope_id<>NEW.tenant_scope_id OR publication.site_id<>NEW.site_id OR
       publication.policy_id<>NEW.policy_id OR publication.policy_kind<>NEW.policy_kind OR
       publication.policy_version<>NEW.policy_version OR
       publication.expected_active_version<>NEW.expected_active_policy_version OR
       publication.bundle_sha256<>NEW.publication_bundle_sha256 OR
       publication.canonical_payload_sha256<>NEW.canonical_payload_sha256 OR
       publication.runtime_snapshot_sha256<>NEW.runtime_snapshot_sha256 OR
       publication.signing_key_id<>NEW.signing_key_id THEN
        RAISE EXCEPTION 'firewall command outbox publication scope or target mismatch' USING ERRCODE='P1111';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_command_outbox_binding_valid
BEFORE INSERT ON firewall_command_outbox
FOR EACH ROW EXECUTE FUNCTION validate_firewall_command_outbox_binding();
