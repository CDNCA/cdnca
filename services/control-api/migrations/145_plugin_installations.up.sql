LOCK TABLE schema_migrations, access_scopes, tenants, permissions, memberships, auth_sessions,
    roles, role_permissions, role_assignments, audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_145$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 144 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 144 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 144 AND migration_id = '144_waf_geo_authority' AND
              checksum_sha256 = '7fac4e1bdec793d461ef3a1735c81d4b7c020dd876fa565dd919a68bb493ce95' AND
              down_checksum_sha256 = '51d17cc3aac3ad80f4d3afc968e2ed504b608558aed521a0a75f2ef99f31ea2c' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('plugin_installation_heads') IS NOT NULL OR
         to_regclass('plugin_installation_receipts') IS NOT NULL OR
         EXISTS (SELECT 1 FROM permissions WHERE name IN ('plugin_installations.read','plugin_installations.manage')) THEN
        RAISE EXCEPTION 'migration 145 requires the exact verified 144 release head'
            USING ERRCODE = 'P1450';
    END IF;
END;
$migration_145$;

INSERT INTO permissions(name,description) VALUES
    ('plugin_installations.read','Read tenant plugin installation authorization state'),
    ('plugin_installations.manage','Confirm, upgrade, disable, and uninstall tenant plugins');

CREATE FUNCTION valid_plugin_installation_scopes_145(scope_values text[])
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    item text;
    previous text;
BEGIN
    IF scope_values IS NULL OR cardinality(scope_values) > 64 THEN
        RETURN false;
    END IF;
    FOREACH item IN ARRAY scope_values LOOP
        IF item IS NULL OR item !~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,7}$' OR
           char_length(item) NOT BETWEEN 3 AND 128 OR (previous IS NOT NULL AND previous >= item) THEN
            RETURN false;
        END IF;
        previous := item;
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE plugin_installation_heads (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    authorization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    verification_id uuid NOT NULL,
    plugin_id text NOT NULL CHECK (plugin_id ~ '^[a-z0-9]+([.-][a-z0-9]+)+$' AND char_length(plugin_id) BETWEEN 3 AND 128),
    plugin_version text NOT NULL CHECK (plugin_version = btrim(plugin_version) AND char_length(plugin_version) BETWEEN 5 AND 128),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    configuration_schema_sha256 bytea NOT NULL CHECK (octet_length(configuration_schema_sha256) = 32),
    manifest_scopes text[] NOT NULL CHECK (valid_plugin_installation_scopes_145(manifest_scopes)),
    approved_scopes text[] NOT NULL CHECK (valid_plugin_installation_scopes_145(approved_scopes) AND approved_scopes <@ manifest_scopes),
    sensitive_scopes text[] NOT NULL CHECK (valid_plugin_installation_scopes_145(sensitive_scopes) AND sensitive_scopes <@ manifest_scopes),
    status text NOT NULL CHECK (status IN ('enabled','disabled','uninstalled')),
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    identity_generation bigint NOT NULL CHECK (identity_generation > 0 AND identity_generation <= 9007199254740991),
    lkg_verification_id uuid,
    lkg_version text,
    stable_reason_code text CHECK (stable_reason_code IS NULL OR stable_reason_code ~ '^[a-z][a-z0-9_]{0,127}$'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id,authorization_id),
    UNIQUE (tenant_scope_id,installation_id,authorization_id),
    CHECK (updated_at >= created_at),
    CHECK ((lkg_verification_id IS NULL) = (lkg_version IS NULL)),
    CHECK (lkg_version IS NULL OR (lkg_version = btrim(lkg_version) AND char_length(lkg_version) BETWEEN 5 AND 128))
);

CREATE INDEX plugin_installation_heads_list_145_idx
    ON plugin_installation_heads(tenant_scope_id,updated_at DESC,authorization_id DESC);
CREATE INDEX plugin_installation_heads_filter_145_idx
    ON plugin_installation_heads(tenant_scope_id,status,plugin_id,updated_at DESC,authorization_id DESC);

CREATE TABLE plugin_installation_receipts (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('confirm','upgrade','disable','uninstall')),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text NOT NULL CHECK (request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND request_id !~ '[[:cntrl:]]'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    from_revision bigint NOT NULL CHECK (from_revision >= 0),
    to_revision bigint NOT NULL CHECK (to_revision > 0),
    result text NOT NULL CHECK (result IN ('installed','upgrade_applied','upgrade_failed_lkg_preserved','disabled','uninstalled')),
    reason text CHECK (reason IS NULL OR (reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 500)),
    stable_reason_code text CHECK (stable_reason_code IS NULL OR stable_reason_code ~ '^[a-z][a-z0-9_]{0,127}$'),
    attempted_verification_id uuid,
    attempted_version text,
    response_snapshot jsonb NOT NULL CHECK (jsonb_typeof(response_snapshot) = 'object'),
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, authorization_id, idempotency_key),
    FOREIGN KEY (tenant_scope_id,authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id,authorization_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_session_id)
        REFERENCES auth_sessions(id) ON DELETE RESTRICT,
    CHECK (to_revision = from_revision + 1 OR (from_revision = 0 AND to_revision = 1)),
    CHECK ((attempted_verification_id IS NULL) = (attempted_version IS NULL))
);

CREATE INDEX plugin_installation_receipts_history_145_idx
    ON plugin_installation_receipts(tenant_scope_id,authorization_id,occurred_at DESC,id DESC);

CREATE FUNCTION validate_plugin_installation_head_145()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.authorization_id IS DISTINCT FROM OLD.authorization_id OR
       NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
       NEW.plugin_id IS DISTINCT FROM OLD.plugin_id OR NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.revision <> OLD.revision + 1 OR NEW.identity_generation < OLD.identity_generation OR
       NEW.identity_generation > OLD.identity_generation + 1 OR NEW.updated_at < OLD.updated_at OR
       (OLD.status = 'uninstalled') OR
       (OLD.status = 'disabled' AND NEW.status NOT IN ('disabled','uninstalled')) OR
       (OLD.status = 'enabled' AND NEW.status NOT IN ('enabled','disabled','uninstalled')) THEN
        RAISE EXCEPTION 'invalid plugin installation head transition' USING ERRCODE = 'P1451';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_installation_heads_transition_145
BEFORE UPDATE ON plugin_installation_heads
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_head_145();

CREATE FUNCTION protect_plugin_installation_head_delete_145()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'plugin installation heads cannot be deleted' USING ERRCODE = 'P1452';
END;
$$;

CREATE TRIGGER plugin_installation_heads_no_delete_145
BEFORE DELETE ON plugin_installation_heads
FOR EACH ROW EXECUTE FUNCTION protect_plugin_installation_head_delete_145();

CREATE FUNCTION protect_plugin_installation_receipt_145()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'plugin installation receipts are append-only' USING ERRCODE = 'P1453';
END;
$$;

CREATE TRIGGER plugin_installation_receipts_append_only_145
BEFORE UPDATE OR DELETE ON plugin_installation_receipts
FOR EACH ROW EXECUTE FUNCTION protect_plugin_installation_receipt_145();

CREATE FUNCTION prevent_plugin_installation_truncate_145()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'plugin installation facts cannot be truncated' USING ERRCODE = 'P1454';
END;
$$;

CREATE TRIGGER plugin_installation_heads_no_truncate_145
BEFORE TRUNCATE ON plugin_installation_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_installation_truncate_145();
CREATE TRIGGER plugin_installation_receipts_no_truncate_145
BEFORE TRUNCATE ON plugin_installation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_installation_truncate_145();
