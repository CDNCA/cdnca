LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_223$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 222 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 222 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 222 AND migration_id = '222_openresty_security_platform_scope' AND
              checksum_sha256 = '9608c52faf69e6ef329dd57e752727c6e83880b6091c88437c5277bcae16f2fc' AND
              down_checksum_sha256 = 'dab33f6c9a728f05872b856f3e6f6788de49fd30dfc2af0ed8976b0915525b13' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.region_catalog') IS NOT NULL OR
            to_regclass(current_schema() || '.region_catalog_display_id_seq') IS NOT NULL OR
            to_regprocedure(current_schema() || '.protect_region_catalog_display_id_223()') IS NOT NULL OR
            to_regprocedure(current_schema() || '.validate_region_catalog_platform_scope_223()') IS NOT NULL OR
            to_regprocedure(current_schema() || '.sync_node_region_catalog_223()') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name = 'regions.read') THEN
        RAISE EXCEPTION 'migration 223 requires the exact verified 222 release head and an untouched region catalog schema'
            USING ERRCODE = 'P2230';
    END IF;
END;
$migration_223$;

INSERT INTO permissions(name, description) VALUES ('regions.read', 'Read the platform region catalog');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'regions.read'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name IN ('platform_owner', 'platform_admin')
ON CONFLICT DO NOTHING;

CREATE SEQUENCE region_catalog_display_id_seq AS bigint MINVALUE 1 NO MAXVALUE NO CYCLE;

CREATE TABLE region_catalog (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    display_id bigint NOT NULL DEFAULT nextval('region_catalog_display_id_seq'),
    name text NOT NULL CHECK (
        name = btrim(name) AND char_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(updated_at) AND updated_at >= created_at),
    CONSTRAINT region_catalog_display_id_positive CHECK (display_id > 0),
    CONSTRAINT region_catalog_display_id_unique UNIQUE (display_id),
    CONSTRAINT region_catalog_scope_name_unique UNIQUE (platform_scope_id, name)
);

CREATE INDEX region_catalog_scope_name_idx ON region_catalog (platform_scope_id, name, display_id);

CREATE FUNCTION validate_region_catalog_platform_scope_223()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes scope
        WHERE scope.id = NEW.platform_scope_id AND scope.kind = 'platform'
    ) THEN
        RAISE EXCEPTION 'region catalog requires a platform scope' USING ERRCODE = 'P2232';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER region_catalog_platform_scope_223
BEFORE INSERT OR UPDATE OF platform_scope_id ON region_catalog
FOR EACH ROW EXECUTE FUNCTION validate_region_catalog_platform_scope_223();

CREATE FUNCTION protect_region_catalog_display_id_223()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.display_id IS DISTINCT FROM OLD.display_id THEN
        RAISE EXCEPTION 'region catalog display ID is immutable' USING ERRCODE = 'P2231';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER region_catalog_display_id_immutable_223
BEFORE UPDATE OF display_id ON region_catalog
FOR EACH ROW EXECUTE FUNCTION protect_region_catalog_display_id_223();

WITH candidates AS (
    SELECT scope.id AS platform_scope_id, seed.name
    FROM access_scopes scope
    CROSS JOIN (VALUES ('默认')) seed(name)
    WHERE scope.kind = 'platform'
    UNION
    SELECT scope.id, btrim(node.region)
    FROM nodes node
    JOIN access_scopes scope ON scope.id = node.scope_id AND scope.kind = 'platform'
    WHERE node.admin_state <> 'retired' AND btrim(node.region) <> ''
), ranked AS (
    SELECT platform_scope_id, name,
           row_number() OVER (
               ORDER BY platform_scope_id,
                        CASE WHEN name = '默认' THEN 0 ELSE 1 END,
                        name COLLATE "C"
           ) AS display_id
    FROM candidates
)
INSERT INTO region_catalog(id, platform_scope_id, display_id, name)
SELECT gen_random_uuid(), platform_scope_id, display_id, name
FROM ranked
ORDER BY display_id;

SELECT setval(
    'region_catalog_display_id_seq',
    COALESCE((SELECT max(display_id) FROM region_catalog), 0) + 1,
    false
);

CREATE FUNCTION sync_node_region_catalog_223()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.admin_state <> 'retired' AND btrim(NEW.region) <> '' AND EXISTS (
        SELECT 1 FROM access_scopes scope
        WHERE scope.id = NEW.scope_id AND scope.kind = 'platform'
    ) THEN
        INSERT INTO region_catalog(id, platform_scope_id, name)
        VALUES (gen_random_uuid(), NEW.scope_id, btrim(NEW.region))
        ON CONFLICT (platform_scope_id, name) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER nodes_region_catalog_sync_223
AFTER INSERT OR UPDATE OF region, admin_state ON nodes
FOR EACH ROW EXECUTE FUNCTION sync_node_region_catalog_223();

DO $region_catalog_runtime_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT, INSERT ON region_catalog TO cdnca_control_app;
        GRANT USAGE, SELECT ON SEQUENCE region_catalog_display_id_seq TO cdnca_control_app;
    END IF;
END;
$region_catalog_runtime_grants$;
