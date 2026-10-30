LOCK TABLE schema_migrations, permissions, roles, role_permissions, theme_packages IN ACCESS EXCLUSIVE MODE;

DO $migration_373_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 372 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 372 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=372 AND
        migration_id='372_market_data_packs' AND
        checksum_sha256='fb96f7ce4d0ee1f212339007e8ce20359a395959d130c0b02a2cd7cc00170049' AND
        down_checksum_sha256='79e46e119c37ce5133e30cd99b3ad7a60d96711f7b97dd10ffcd131112edc941' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.theme_tenant_settings') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name = 'tenant_theme.manage') THEN
        RAISE EXCEPTION 'migration 373 requires the exact verified 372 release head' USING ERRCODE='P3730';
    END IF;
END;
$migration_373_up$;

-- r136 PA-26 white-label themes (placeholder number 373, guard on 372 = the
-- integration head 372_market_data_packs + 1, a number pa12 reserved but has
-- not merged; its migration_id and checksums below are placeholders the
-- merge replaces with the real 372 head). PA-17 made the theme platform-wide; a tenant
-- (an agent/reseller included) may now pick its own theme among the packages
-- the platform downloaded. The platform decides whether tenants may choose
-- (theme_tenant_policy) and may override that per tenant (selection_mode:
-- inherit / allow / deny). A tenant with no usable choice sees the platform
-- theme. Tenant themes reach the tenant console, the sign-in page served on a
-- hostname bound to the tenant (theme_tenant_domains) and the tenant's node
-- error pages.

INSERT INTO permissions(name, description) VALUES
    ('tenant_theme.manage', 'Choose the tenant theme among the themes the platform downloaded');

CREATE TABLE theme_tenant_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    tenant_selection_allowed boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    updated_at timestamptz NOT NULL
);

CREATE TABLE theme_tenant_settings (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    selection_mode text NOT NULL CHECK (selection_mode IN ('inherit', 'allow', 'deny')),
    -- NULL: follow the platform theme.
    package_sha256 bytea REFERENCES theme_packages(package_sha256) ON DELETE RESTRICT,
    -- A package the platform assigned always applies; one the tenant chose
    -- applies only while the tenant may choose.
    package_assigned_by text CHECK (package_assigned_by IN ('platform', 'tenant')),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    updated_at timestamptz NOT NULL,
    CHECK ((package_sha256 IS NULL) = (package_assigned_by IS NULL))
);
CREATE INDEX theme_tenant_settings_package_373 ON theme_tenant_settings(package_sha256) WHERE package_sha256 IS NOT NULL;

CREATE TABLE theme_tenant_domains (
    hostname text PRIMARY KEY CHECK (
        octet_length(hostname) <= 253 AND
        hostname ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL
);
CREATE INDEX theme_tenant_domains_scope_373 ON theme_tenant_domains(tenant_scope_id);

-- Tenant rows name a tenant scope and a downloaded, not removed package. The
-- theme activation lock serializes them with package removal.
CREATE FUNCTION validate_theme_tenant_row_373()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('theme-activation', 0));
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.tenant_scope_id AND kind = 'tenant' AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'theme tenant rows require a tenant scope' USING ERRCODE = 'P3731';
    END IF;
    IF TG_TABLE_NAME <> 'theme_tenant_settings' THEN
        RETURN NEW;
    END IF;
    -- (Fields of theme_tenant_settings only from here: plpgsql resolves
    -- NEW.<field> when the statement runs.)
    IF NEW.package_sha256 IS NOT NULL THEN
        IF (TG_OP = 'INSERT' OR NEW.package_sha256 IS DISTINCT FROM OLD.package_sha256) AND
           NOT EXISTS (SELECT 1 FROM theme_packages WHERE package_sha256 = NEW.package_sha256 AND removed_at IS NULL) THEN
            RAISE EXCEPTION 'tenant theme package is not downloaded' USING ERRCODE = 'P3732';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR NEW.revision <> OLD.revision + 1 THEN
            RAISE EXCEPTION 'invalid tenant theme settings transition' USING ERRCODE = 'P3733';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER theme_tenant_settings_validate_373
BEFORE INSERT OR UPDATE ON theme_tenant_settings
FOR EACH ROW EXECUTE FUNCTION validate_theme_tenant_row_373();
CREATE TRIGGER theme_tenant_domains_validate_373
BEFORE INSERT OR UPDATE ON theme_tenant_domains
FOR EACH ROW EXECUTE FUNCTION validate_theme_tenant_row_373();

CREATE FUNCTION validate_theme_tenant_policy_373()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND NEW.revision <> OLD.revision + 1) OR
       (TG_OP = 'INSERT' AND NEW.revision <> 1) THEN
        RAISE EXCEPTION 'invalid tenant theme policy transition' USING ERRCODE = 'P3734';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER theme_tenant_policy_validate_373
BEFORE INSERT OR UPDATE OR DELETE ON theme_tenant_policy
FOR EACH ROW EXECUTE FUNCTION validate_theme_tenant_policy_373();

-- A package a tenant has chosen cannot be removed.
CREATE FUNCTION protect_tenant_theme_package_373()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.removed_at IS NOT NULL AND OLD.removed_at IS NULL AND
       EXISTS (SELECT 1 FROM theme_tenant_settings WHERE package_sha256 = NEW.package_sha256) THEN
        RAISE EXCEPTION 'a tenant theme package cannot be removed' USING ERRCODE = 'P3735';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER theme_packages_tenant_selected_373
BEFORE UPDATE ON theme_packages
FOR EACH ROW EXECUTE FUNCTION protect_tenant_theme_package_373();

-- tenant_owner chooses the tenant theme: existing roles now, new ones as they
-- are created (every tenant creation path inserts the system roles).
INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'tenant_theme.manage'
FROM roles role JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'tenant'
WHERE role.system_role AND role.name = 'tenant_owner'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_tenant_theme_to_tenant_owner_373()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.system_role AND NEW.name = 'tenant_owner' AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant'
    ) THEN
        INSERT INTO role_permissions(role_id, permission_name)
        VALUES (NEW.id, 'tenant_theme.manage')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_tenant_owner_theme_373
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_tenant_theme_to_tenant_owner_373();

REVOKE ALL ON theme_tenant_policy, theme_tenant_settings, theme_tenant_domains FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_theme_tenant_row_373(), validate_theme_tenant_policy_373(),
    protect_tenant_theme_package_373(), grant_tenant_theme_to_tenant_owner_373() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON theme_tenant_policy, theme_tenant_settings TO cdnca_control_app;
GRANT SELECT, INSERT, DELETE ON theme_tenant_domains TO cdnca_control_app;
GRANT SELECT ON theme_tenant_policy, theme_tenant_settings, theme_tenant_domains TO cdnca_control_runtime;
