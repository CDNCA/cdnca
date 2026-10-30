LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions,
    access_scopes, tenants, users, memberships, auth_sessions, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_147$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 146 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 146 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 146 AND migration_id = '146_package_cycle_enforcement' AND
              checksum_sha256 = '9763f9d3bbba5f12560e3254e2ab22281fb0d0e63b3b412e807b121ef3643a25' AND
              down_checksum_sha256 = '1d9986f1c21d13957a57b00c63c7c06b0f7a5497c53df19695d6c2ad1a8b16ad' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('site_capture_policy_revisions') IS NOT NULL OR
         to_regclass('site_capture_policy_heads') IS NOT NULL OR
         to_regclass('site_capture_policy_receipts') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 147 requires the exact verified 146 release head'
            USING ERRCODE = 'P1470';
    END IF;
END;
$migration_147$;

INSERT INTO permissions(name,description) VALUES
    ('site_capture.read','Read durable per-site telemetry capture policies'),
    ('site_capture.manage','Create revisions of per-site telemetry capture policies');

INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required) VALUES
    ('site_capture.read',false),('site_capture.manage',false);

INSERT INTO role_permissions(role_id,permission_name)
SELECT id,'site_capture.read' FROM roles
WHERE system_role AND name IN ('platform_owner','tenant_owner','tenant_viewer')
ON CONFLICT DO NOTHING;
INSERT INTO role_permissions(role_id,permission_name)
SELECT id,'site_capture.manage' FROM roles
WHERE system_role AND name IN ('platform_owner','tenant_owner')
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_site_capture_permissions_147()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    IF NEW.name IN ('platform_owner','tenant_owner') THEN
        INSERT INTO role_permissions(role_id,permission_name) VALUES
            (NEW.id,'site_capture.read'),(NEW.id,'site_capture.manage')
        ON CONFLICT DO NOTHING;
    ELSIF NEW.name = 'tenant_viewer' THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'site_capture.read') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_site_capture_permissions_147
AFTER INSERT ON roles FOR EACH ROW EXECUTE FUNCTION grant_site_capture_permissions_147();

CREATE TABLE site_capture_policy_revisions (
    scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    document_bytes bytea NOT NULL CHECK (octet_length(document_bytes) BETWEEN 2 AND 1048576),
    document_sha256 bytea NOT NULL CHECK (
        octet_length(document_sha256) = 32 AND
        document_sha256 = sha256(document_bytes) AND
        document = convert_from(document_bytes,'UTF8')::jsonb
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (scope_id,site_id,revision),
    FOREIGN KEY (scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT
);

CREATE INDEX site_capture_policy_revisions_created_147_idx
    ON site_capture_policy_revisions(scope_id,created_at DESC,site_id,revision DESC);

CREATE TABLE site_capture_policy_heads (
    scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    current_revision bigint NOT NULL CHECK (current_revision > 0 AND current_revision <= 9007199254740991),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (scope_id,site_id),
    FOREIGN KEY (scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,site_id,current_revision)
        REFERENCES site_capture_policy_revisions(scope_id,site_id,revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE site_capture_policy_receipts (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    action_code text NOT NULL CHECK (action_code = 'site.capture_policy.set'),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id text NOT NULL CHECK (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    target_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0 AND expected_revision < 9007199254740991),
    state text NOT NULL CHECK (state IN ('pending','completed')),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at) AND completed_at >= created_at),
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_session_id,actor_scope_id,actor_user_id)
        REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id,actor_user_id,actor_session_id,action_code,idempotency_key),
    CHECK (
        (state = 'pending' AND response_body IS NULL AND completed_at IS NULL) OR
        (state = 'completed' AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX site_capture_policy_receipts_target_147_idx
    ON site_capture_policy_receipts(target_scope_id,site_id,created_at DESC,id DESC);

CREATE FUNCTION protect_site_capture_revision_147()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'site capture policy revisions are append-only' USING ERRCODE = 'P1471';
END;
$$;

CREATE FUNCTION guard_site_capture_head_147()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'site capture policy heads cannot be deleted' USING ERRCODE = 'P1472';
    END IF;
    IF NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.site_id IS DISTINCT FROM OLD.site_id OR
       NEW.current_revision <> OLD.current_revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'site capture policy head revision must advance by one' USING ERRCODE = 'P1473';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_site_capture_receipt_147()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'site capture policy receipts are append-only' USING ERRCODE = 'P1474';
    END IF;
    IF OLD.state <> 'pending' OR NEW.state <> 'completed' OR
       OLD.id IS DISTINCT FROM NEW.id OR OLD.actor_scope_id IS DISTINCT FROM NEW.actor_scope_id OR
       OLD.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR OLD.actor_session_id IS DISTINCT FROM NEW.actor_session_id OR
       OLD.action_code IS DISTINCT FROM NEW.action_code OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key OR
       OLD.request_id IS DISTINCT FROM NEW.request_id OR OLD.trace_id IS DISTINCT FROM NEW.trace_id OR
       OLD.request_digest IS DISTINCT FROM NEW.request_digest OR OLD.target_scope_id IS DISTINCT FROM NEW.target_scope_id OR
       OLD.site_id IS DISTINCT FROM NEW.site_id OR OLD.expected_revision IS DISTINCT FROM NEW.expected_revision OR
       OLD.created_at IS DISTINCT FROM NEW.created_at OR NEW.response_body IS NULL OR NEW.completed_at IS NULL THEN
        RAISE EXCEPTION 'site capture policy receipts only allow pending to completed' USING ERRCODE = 'P1475';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_site_capture_truncate_147()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'site capture policy authority tables cannot be truncated' USING ERRCODE = 'P1476';
END;
$$;

CREATE TRIGGER site_capture_policy_revisions_immutable_147
BEFORE UPDATE OR DELETE ON site_capture_policy_revisions
FOR EACH ROW EXECUTE FUNCTION protect_site_capture_revision_147();
CREATE TRIGGER site_capture_policy_heads_guard_147
BEFORE UPDATE OR DELETE ON site_capture_policy_heads
FOR EACH ROW EXECUTE FUNCTION guard_site_capture_head_147();
CREATE TRIGGER site_capture_policy_receipts_guard_147
BEFORE UPDATE OR DELETE ON site_capture_policy_receipts
FOR EACH ROW EXECUTE FUNCTION guard_site_capture_receipt_147();

CREATE TRIGGER site_capture_policy_revisions_no_truncate_147
BEFORE TRUNCATE ON site_capture_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_site_capture_truncate_147();
CREATE TRIGGER site_capture_policy_heads_no_truncate_147
BEFORE TRUNCATE ON site_capture_policy_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_site_capture_truncate_147();
CREATE TRIGGER site_capture_policy_receipts_no_truncate_147
BEFORE TRUNCATE ON site_capture_policy_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_site_capture_truncate_147();

REVOKE ALL ON site_capture_policy_revisions, site_capture_policy_heads,
    site_capture_policy_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_site_capture_permissions_147() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_site_capture_revision_147() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_site_capture_head_147() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_site_capture_receipt_147() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_site_capture_truncate_147() FROM PUBLIC;
