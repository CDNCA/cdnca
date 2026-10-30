INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND permissions.name IN ('certificates.read', 'certificates.manage')
  AND (
      (roles.name = 'tenant_owner') OR
      (roles.name = 'tenant_viewer' AND permissions.name = 'certificates.read')
  )
ON CONFLICT DO NOTHING;

CREATE FUNCTION certificate_asset_valid_dns_names(names text[])
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    name text;
    label text;
    candidate text;
BEGIN
    IF cardinality(names) NOT BETWEEN 1 AND 100 THEN
        RETURN false;
    END IF;
    FOREACH name IN ARRAY names LOOP
        IF name IS NULL OR name <> lower(name) OR name <> btrim(name)
           OR octet_length(name) NOT BETWEEN 3 AND 253 OR name ~ '[[:cntrl:]]'
           OR NOT (name LIKE '%.%') OR right(name, 1) = '.' THEN
            RETURN false;
        END IF;
        candidate := name;
        IF left(candidate, 2) = '*.' THEN
            candidate := substr(candidate, 3);
        ELSIF position('*' IN candidate) > 0 THEN
            RETURN false;
        END IF;
        FOREACH label IN ARRAY string_to_array(candidate, '.') LOOP
            IF label !~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' THEN
                RETURN false;
            END IF;
        END LOOP;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION certificate_asset_domain_covered(names text[], domain text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    name text;
    suffix text;
BEGIN
    IF domain IS NULL OR domain <> lower(domain) OR domain <> btrim(domain)
       OR domain ~ '[[:cntrl:]]' OR position('*' IN domain) > 0 THEN
        RETURN false;
    END IF;
    FOREACH name IN ARRAY names LOOP
        IF name = domain THEN
            RETURN true;
        END IF;
        IF left(name, 2) = '*.' THEN
            suffix := substr(name, 3);
            IF right(domain, octet_length(suffix) + 1) = '.' || suffix
               AND length(domain) - length(replace(domain, '.', ''))
                   = length(suffix) - length(replace(suffix, '.', '')) + 1 THEN
                RETURN true;
            END IF;
        END IF;
    END LOOP;
    RETURN false;
END;
$$;

CREATE FUNCTION assert_certificate_asset_tenant_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_kind text;
BEGIN
    SELECT kind INTO scope_kind FROM access_scopes WHERE id = NEW.tenant_scope_id;
    IF scope_kind IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'certificate asset scope must be a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE certificate_assets (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    id uuid NOT NULL,
    name text NOT NULL CHECK (
        name = btrim(name)
        AND octet_length(name) BETWEEN 1 AND 128
        AND name !~ '[[:cntrl:]]'
    ),
    source text NOT NULL CHECK (source IN ('uploaded', 'acme')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    deleted_by_user_id uuid,
    PRIMARY KEY (tenant_scope_id, id),
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, updated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, deleted_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (
        (deleted_at IS NULL AND deleted_by_user_id IS NULL) OR
        (deleted_at IS NOT NULL AND deleted_by_user_id IS NOT NULL AND deleted_at >= created_at)
    )
);

CREATE TRIGGER certificate_assets_tenant_scope
BEFORE INSERT OR UPDATE OF tenant_scope_id ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION assert_certificate_asset_tenant_scope();

CREATE INDEX certificate_assets_tenant_created_active_idx
    ON certificate_assets (tenant_scope_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE certificate_asset_versions (
    tenant_scope_id uuid NOT NULL,
    id uuid NOT NULL,
    asset_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    initial_status text NOT NULL CHECK (initial_status IN ('default', 'pending_activation')),
    fingerprint_sha256 bytea NOT NULL CHECK (octet_length(fingerprint_sha256) = 32),
    certificate_pem bytea NOT NULL CHECK (octet_length(certificate_pem) BETWEEN 1 AND 262144),
    public_key_sha256 bytea NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    private_key_reference text NOT NULL CHECK (
        octet_length(private_key_reference) BETWEEN 1 AND 256
        AND private_key_reference = btrim(private_key_reference)
        AND private_key_reference !~ '[[:cntrl:]]'
    ),
    private_key_aad_sha256 bytea NOT NULL CHECK (octet_length(private_key_aad_sha256) = 32),
    sans text[] NOT NULL CHECK (certificate_asset_valid_dns_names(sans)),
    leaf_subject text NOT NULL CHECK (
        octet_length(leaf_subject) <= 2048 AND leaf_subject !~ '[[:cntrl:]]'
    ),
    serial_number text NOT NULL CHECK (serial_number ~ '^[0-9a-f]{1,128}$'),
    public_key_algorithm text NOT NULL CHECK (public_key_algorithm IN ('rsa', 'ecdsa', 'ed25519')),
    public_key_bits integer NOT NULL CHECK (public_key_bits BETWEEN 256 AND 16384),
    signature_algorithm text NOT NULL CHECK (
        octet_length(signature_algorithm) BETWEEN 1 AND 64
        AND signature_algorithm !~ '[[:cntrl:]]'
    ),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    acme_order_id uuid,
    renewal_due_at timestamptz,
    imported_by_user_id uuid NOT NULL,
    imported_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, id),
    UNIQUE (tenant_scope_id, asset_id, id),
    UNIQUE (tenant_scope_id, asset_id, version),
    UNIQUE (tenant_scope_id, fingerprint_sha256),
    FOREIGN KEY (tenant_scope_id, asset_id)
        REFERENCES certificate_assets(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, imported_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, acme_order_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT,
    CHECK (not_after > not_before),
    CHECK (
        (acme_order_id IS NULL AND renewal_due_at IS NULL) OR
        (acme_order_id IS NOT NULL AND renewal_due_at IS NOT NULL
            AND renewal_due_at >= not_before AND renewal_due_at < not_after)
    )
);

CREATE INDEX certificate_asset_versions_asset_version_idx
    ON certificate_asset_versions (tenant_scope_id, asset_id, version DESC);
CREATE UNIQUE INDEX certificate_asset_versions_acme_order_idx
    ON certificate_asset_versions (tenant_scope_id, acme_order_id)
    WHERE acme_order_id IS NOT NULL;
CREATE INDEX certificate_asset_versions_renewal_due_idx
    ON certificate_asset_versions (tenant_scope_id, renewal_due_at, asset_id)
    INCLUDE (id, not_after, acme_order_id)
    WHERE acme_order_id IS NOT NULL;

CREATE TABLE certificate_asset_private_key_envelope_facts (
    tenant_scope_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    certificate_fingerprint_sha256 bytea NOT NULL
        CHECK (octet_length(certificate_fingerprint_sha256) = 32),
    certificate_public_key_sha256 bytea NOT NULL
        CHECK (octet_length(certificate_public_key_sha256) = 32),
    private_key_reference text NOT NULL CHECK (
        octet_length(private_key_reference) BETWEEN 1 AND 256
        AND private_key_reference = btrim(private_key_reference)
        AND private_key_reference !~ '[[:cntrl:]]'
    ),
    aad_sha256 bytea NOT NULL CHECK (octet_length(aad_sha256) = 32),
    private_key_ciphertext bytea NOT NULL
        CHECK (octet_length(private_key_ciphertext) BETWEEN 16 AND 131072),
    private_key_key_id text NOT NULL CHECK (
        octet_length(private_key_key_id) BETWEEN 1 AND 128
        AND private_key_key_id = btrim(private_key_key_id)
        AND private_key_key_id !~ '[[:cntrl:]]'
    ),
    private_key_nonce bytea NOT NULL CHECK (octet_length(private_key_nonce) BETWEEN 8 AND 64),
    private_key_metadata jsonb NOT NULL CHECK (
        jsonb_typeof(private_key_metadata) = 'object'
        AND octet_length(private_key_metadata::text) <= 4096
    ),
    change_kind text NOT NULL CHECK (change_kind IN ('initial', 'rewrap')),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id = btrim(request_id)
        AND request_id !~ '[[:cntrl:]]'
    ),
    changed_by_user_id uuid NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, asset_id, version_id, sequence),
    FOREIGN KEY (tenant_scope_id, asset_id, version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE TABLE certificate_asset_activation_facts (
    tenant_scope_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    sequence bigint NOT NULL CHECK (sequence > 0),
    version_id uuid NOT NULL,
    previous_version_id uuid,
    expected_asset_revision bigint NOT NULL CHECK (expected_asset_revision > 0),
    resulting_asset_revision bigint NOT NULL CHECK (resulting_asset_revision > 1),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id = btrim(request_id)
        AND request_id !~ '[[:cntrl:]]'
    ),
    activated_by_user_id uuid NOT NULL,
    activated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, asset_id, sequence),
    FOREIGN KEY (tenant_scope_id, asset_id, version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, asset_id, previous_version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, activated_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (resulting_asset_revision = expected_asset_revision + 1),
    CHECK (previous_version_id IS NULL OR previous_version_id <> version_id)
);

CREATE INDEX certificate_asset_activation_latest_idx
    ON certificate_asset_activation_facts (tenant_scope_id, asset_id, sequence DESC)
    INCLUDE (version_id, previous_version_id, activated_at);

CREATE TABLE certificate_asset_revocation_facts (
    tenant_scope_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    expected_asset_revision bigint NOT NULL CHECK (expected_asset_revision > 0),
    resulting_asset_revision bigint NOT NULL CHECK (resulting_asset_revision > 1),
    reason text NOT NULL CHECK (
        reason = btrim(reason)
        AND octet_length(reason) BETWEEN 1 AND 256
        AND reason !~ '[[:cntrl:]]'
    ),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id = btrim(request_id)
        AND request_id !~ '[[:cntrl:]]'
    ),
    revoked_by_user_id uuid NOT NULL,
    revoked_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, asset_id, version_id),
    FOREIGN KEY (tenant_scope_id, asset_id, version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, revoked_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (resulting_asset_revision = expected_asset_revision + 1)
);

CREATE TABLE certificate_site_binding_facts (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    action text NOT NULL CHECK (action IN ('bind', 'unbind')),
    asset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    is_default boolean NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    resulting_revision bigint NOT NULL CHECK (resulting_revision > 0),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id = btrim(request_id)
        AND request_id !~ '[[:cntrl:]]'
    ),
    changed_by_user_id uuid NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, site_id, sequence),
    FOREIGN KEY (tenant_scope_id, asset_id, version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, changed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (resulting_revision = expected_revision + 1)
);

CREATE INDEX certificate_site_binding_latest_idx
    ON certificate_site_binding_facts (tenant_scope_id, site_id, sequence DESC)
    INCLUDE (action, asset_id, version_id, is_default, changed_at);
CREATE INDEX certificate_site_binding_asset_reference_idx
    ON certificate_site_binding_facts (tenant_scope_id, asset_id, site_id, sequence DESC)
    INCLUDE (action, version_id);

CREATE TABLE certificate_asset_write_requests (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN (
        'certificate.asset.import', 'certificate.asset.activate', 'certificate.asset.revoke',
        'certificate.asset.delete', 'certificate.asset.bind', 'certificate.asset.unbind',
        'certificate.asset.rewrap'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key = btrim(idempotency_key)
        AND idempotency_key !~ '[[:cntrl:]]'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (tenant_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL
            AND completed_at >= created_at)
    )
);

CREATE INDEX certificate_asset_write_requests_tenant_created_idx
    ON certificate_asset_write_requests (tenant_scope_id, created_at DESC, id DESC);

CREATE FUNCTION protect_certificate_asset()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'certificate assets cannot be physically removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'certificate asset must start at revision one without a tombstone';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted certificate asset is immutable';
    END IF;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.source IS DISTINCT FROM OLD.source
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'certificate asset revision must advance by one';
    END IF;
    IF NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (site_id) site_id, action, asset_id
            FROM certificate_site_binding_facts
            WHERE tenant_scope_id = OLD.tenant_scope_id
            ORDER BY site_id, sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind' AND current_binding.asset_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'referenced certificate asset cannot be deleted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_assets_protect
BEFORE INSERT OR UPDATE OR DELETE ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset();
CREATE TRIGGER certificate_assets_no_truncate
BEFORE TRUNCATE ON certificate_assets
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_asset();

CREATE FUNCTION protect_certificate_asset_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_version bigint;
    asset_source text;
    asset_deleted_at timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate asset versions are immutable';
    END IF;
    SELECT source, deleted_at INTO asset_source, asset_deleted_at
    FROM certificate_assets
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.asset_id;
    IF asset_source IS NULL OR asset_deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'certificate asset version requires a live asset';
    END IF;
    SELECT COALESCE(max(version), 0) + 1 INTO expected_version
    FROM certificate_asset_versions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id;
    IF NEW.version <> expected_version
       OR (NEW.version = 1 AND NEW.initial_status <> 'default')
       OR (NEW.version > 1 AND NEW.initial_status <> 'pending_activation') THEN
        RAISE EXCEPTION 'certificate asset version sequence or initial status is invalid';
    END IF;
    IF (asset_source = 'uploaded' AND NEW.acme_order_id IS NOT NULL)
       OR (asset_source = 'acme' AND NEW.acme_order_id IS NULL) THEN
        RAISE EXCEPTION 'certificate asset source and ACME order do not match';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_asset_versions_immutable
BEFORE INSERT OR UPDATE OR DELETE ON certificate_asset_versions
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset_version();
CREATE TRIGGER certificate_asset_versions_no_truncate
BEFORE TRUNCATE ON certificate_asset_versions
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_asset_version();

CREATE FUNCTION protect_certificate_asset_private_key_envelope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    version_fingerprint bytea;
    version_public_key bytea;
    version_key_reference text;
    version_aad bytea;
    expected_sequence bigint;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate private key envelope facts are immutable';
    END IF;
    SELECT fingerprint_sha256, public_key_sha256, private_key_reference, private_key_aad_sha256
      INTO version_fingerprint, version_public_key, version_key_reference, version_aad
    FROM certificate_asset_versions
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND asset_id = NEW.asset_id AND id = NEW.version_id;
    SELECT COALESCE(max(sequence), 0) + 1 INTO expected_sequence
    FROM certificate_asset_private_key_envelope_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND asset_id = NEW.asset_id AND version_id = NEW.version_id;
    IF version_fingerprint IS NULL
       OR NEW.certificate_fingerprint_sha256 IS DISTINCT FROM version_fingerprint
       OR NEW.certificate_public_key_sha256 IS DISTINCT FROM version_public_key
       OR NEW.private_key_reference IS DISTINCT FROM version_key_reference
       OR NEW.aad_sha256 IS DISTINCT FROM version_aad
       OR NEW.sequence <> expected_sequence
       OR (NEW.sequence = 1 AND NEW.change_kind <> 'initial')
       OR (NEW.sequence > 1 AND NEW.change_kind <> 'rewrap') THEN
        RAISE EXCEPTION 'certificate private key envelope context is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_asset_private_key_envelopes_immutable
BEFORE INSERT OR UPDATE OR DELETE ON certificate_asset_private_key_envelope_facts
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset_private_key_envelope();
CREATE TRIGGER certificate_asset_private_key_envelopes_no_truncate
BEFORE TRUNCATE ON certificate_asset_private_key_envelope_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_asset_private_key_envelope();

CREATE FUNCTION validate_certificate_asset_version_envelope_commit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM certificate_asset_private_key_envelope_facts envelope
        WHERE envelope.tenant_scope_id = NEW.tenant_scope_id
          AND envelope.asset_id = NEW.asset_id
          AND envelope.version_id = NEW.id
          AND envelope.sequence = 1
          AND envelope.certificate_fingerprint_sha256 = NEW.fingerprint_sha256
          AND envelope.certificate_public_key_sha256 = NEW.public_key_sha256
          AND envelope.private_key_reference = NEW.private_key_reference
          AND envelope.aad_sha256 = NEW.private_key_aad_sha256
    ) THEN
        RAISE EXCEPTION 'certificate asset version requires an initial private key envelope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER certificate_asset_version_envelope_required
AFTER INSERT ON certificate_asset_versions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_version_envelope_commit();

CREATE FUNCTION protect_certificate_asset_activation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_revision bigint;
    asset_deleted_at timestamptz;
    expected_sequence bigint;
    previous_active uuid;
    target_not_before timestamptz;
    target_not_after timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate activation facts are immutable';
    END IF;
    SELECT revision, deleted_at INTO current_revision, asset_deleted_at
    FROM certificate_assets
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.asset_id;
    IF current_revision IS DISTINCT FROM NEW.resulting_asset_revision OR asset_deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'certificate activation revision does not match live asset';
    END IF;
    SELECT COALESCE(max(sequence), 0) + 1 INTO expected_sequence
    FROM certificate_asset_activation_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id;
    SELECT version_id INTO previous_active
    FROM certificate_asset_activation_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id
    ORDER BY sequence DESC LIMIT 1;
    SELECT not_before, not_after INTO target_not_before, target_not_after
    FROM certificate_asset_versions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id AND id = NEW.version_id;
    IF NOT EXISTS (
        SELECT 1 FROM certificate_asset_private_key_envelope_facts envelope
        JOIN certificate_asset_versions version
          ON version.tenant_scope_id = envelope.tenant_scope_id
         AND version.asset_id = envelope.asset_id AND version.id = envelope.version_id
        WHERE envelope.tenant_scope_id = NEW.tenant_scope_id
          AND envelope.asset_id = NEW.asset_id AND envelope.version_id = NEW.version_id
          AND envelope.sequence = 1
          AND envelope.certificate_fingerprint_sha256 = version.fingerprint_sha256
          AND envelope.certificate_public_key_sha256 = version.public_key_sha256
          AND envelope.private_key_reference = version.private_key_reference
          AND envelope.aad_sha256 = version.private_key_aad_sha256
    ) THEN
        RAISE EXCEPTION 'certificate activation requires an initial private key envelope';
    END IF;
    IF NEW.sequence <> expected_sequence
       OR NEW.previous_version_id IS DISTINCT FROM previous_active
       OR NEW.version_id IS NOT DISTINCT FROM previous_active
       OR target_not_after IS NULL OR target_not_before > NEW.activated_at
       OR target_not_after <= NEW.activated_at
       OR EXISTS (
           SELECT 1 FROM certificate_asset_revocation_facts
           WHERE tenant_scope_id = NEW.tenant_scope_id
             AND asset_id = NEW.asset_id AND version_id = NEW.version_id
       ) THEN
        RAISE EXCEPTION 'certificate activation fact is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_asset_activations_immutable
BEFORE INSERT OR UPDATE OR DELETE ON certificate_asset_activation_facts
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset_activation();
CREATE TRIGGER certificate_asset_activations_no_truncate
BEFORE TRUNCATE ON certificate_asset_activation_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_asset_activation();

CREATE FUNCTION validate_certificate_activation_bindings_commit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (site_id) site_id, action, asset_id, version_id
            FROM certificate_site_binding_facts
            WHERE tenant_scope_id = NEW.tenant_scope_id
            ORDER BY site_id, sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind'
          AND current_binding.asset_id = NEW.asset_id
          AND current_binding.version_id <> NEW.version_id
    ) THEN
        RAISE EXCEPTION 'certificate activation must migrate every current binding atomically';
    END IF;
    RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER certificate_activation_bindings_required
AFTER INSERT ON certificate_asset_activation_facts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_certificate_activation_bindings_commit();

CREATE FUNCTION protect_certificate_asset_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_revision bigint;
    asset_deleted_at timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate revocation facts are immutable';
    END IF;
    SELECT revision, deleted_at INTO current_revision, asset_deleted_at
    FROM certificate_assets
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.asset_id;
    IF current_revision IS DISTINCT FROM NEW.resulting_asset_revision OR asset_deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'certificate revocation revision does not match live asset';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (site_id) site_id, action, asset_id, version_id
            FROM certificate_site_binding_facts
            WHERE tenant_scope_id = NEW.tenant_scope_id
            ORDER BY site_id, sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind'
          AND current_binding.asset_id = NEW.asset_id
          AND current_binding.version_id = NEW.version_id
    ) THEN
        RAISE EXCEPTION 'bound certificate version cannot be revoked';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_asset_revocations_immutable
BEFORE INSERT OR UPDATE OR DELETE ON certificate_asset_revocation_facts
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset_revocation();
CREATE TRIGGER certificate_asset_revocations_no_truncate
BEFORE TRUNCATE ON certificate_asset_revocation_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_asset_revocation();

CREATE FUNCTION protect_certificate_site_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    site_scope_id uuid;
    site_deleted_at timestamptz;
    site_domain text;
    expected_sequence bigint;
    previous_action text;
    previous_asset_id uuid;
    previous_version_id uuid;
    previous_default boolean;
    asset_deleted_at timestamptz;
    version_not_after timestamptz;
    version_sans text[];
    active_version_id uuid;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'certificate site binding facts are immutable';
    END IF;
    SELECT scope_id, deleted_at, domain INTO site_scope_id, site_deleted_at, site_domain
    FROM sites WHERE id = NEW.site_id;
    IF site_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR site_deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'certificate binding site scope is invalid';
    END IF;
    SELECT COALESCE(max(sequence), 0) + 1 INTO expected_sequence
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id;
    SELECT action, asset_id, version_id, is_default
      INTO previous_action, previous_asset_id, previous_version_id, previous_default
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id
    ORDER BY sequence DESC LIMIT 1;
    IF NEW.sequence <> expected_sequence OR NEW.expected_revision <> expected_sequence - 1 THEN
        RAISE EXCEPTION 'certificate binding revision is invalid';
    END IF;
    IF NEW.action = 'unbind' THEN
        IF previous_action IS DISTINCT FROM 'bind'
           OR NEW.asset_id IS DISTINCT FROM previous_asset_id
           OR NEW.version_id IS DISTINCT FROM previous_version_id
           OR NEW.is_default IS DISTINCT FROM previous_default THEN
            RAISE EXCEPTION 'certificate unbind fact does not match current binding';
        END IF;
        RETURN NEW;
    END IF;
    SELECT deleted_at INTO asset_deleted_at
    FROM certificate_assets
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.asset_id;
    SELECT not_after, sans INTO version_not_after, version_sans
    FROM certificate_asset_versions
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id AND id = NEW.version_id;
    SELECT version_id INTO active_version_id
    FROM certificate_asset_activation_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id AND asset_id = NEW.asset_id
    ORDER BY sequence DESC LIMIT 1;
    IF asset_deleted_at IS NOT NULL OR version_not_after IS NULL OR version_not_after <= NEW.changed_at
       OR NOT certificate_asset_domain_covered(version_sans, site_domain)
       OR active_version_id IS DISTINCT FROM NEW.version_id
       OR EXISTS (
           SELECT 1 FROM certificate_asset_revocation_facts
           WHERE tenant_scope_id = NEW.tenant_scope_id
             AND asset_id = NEW.asset_id AND version_id = NEW.version_id
       ) THEN
        RAISE EXCEPTION 'certificate binding requires a live active version';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_site_bindings_immutable
BEFORE INSERT OR UPDATE OR DELETE ON certificate_site_binding_facts
FOR EACH ROW EXECUTE FUNCTION protect_certificate_site_binding();
CREATE TRIGGER certificate_site_bindings_no_truncate
BEFORE TRUNCATE ON certificate_site_binding_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_site_binding();

CREATE FUNCTION protect_certificate_asset_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'certificate asset write requests cannot be truncated';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.resource_id IS NOT NULL OR NEW.response_body IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'certificate asset write request must start unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'certificate asset write requests cannot be deleted';
    END IF;
    IF OLD.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'completed certificate asset write request is immutable';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.operation IS DISTINCT FROM OLD.operation
       OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
       OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.resource_id IS NULL OR NEW.response_body IS NULL OR NEW.completed_at IS NULL
       OR NEW.completed_at < OLD.created_at THEN
        RAISE EXCEPTION 'certificate asset write request must complete atomically';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_asset_write_requests_protect
BEFORE INSERT OR UPDATE OR DELETE ON certificate_asset_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset_write_request();
CREATE TRIGGER certificate_asset_write_requests_no_truncate
BEFORE TRUNCATE ON certificate_asset_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_certificate_asset_write_request();
