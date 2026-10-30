LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions,
    users, nodes, region_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_235$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 234 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 234 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 234 AND migration_id = '234_node_line_group_reference_fields' AND
              checksum_sha256 = 'a5d30907333cf8c888f83477828c094e5b9d4a518c8ee4c56c067ed2f521b328' AND
              down_checksum_sha256 = '13eb7df03a065c9d0208f161f9e195ac3deb82d160b38fd4fdc019aab51f426c' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.region_catalog_write_requests') IS NOT NULL OR
            to_regprocedure(current_schema() || '.protect_region_catalog_management_235()') IS NOT NULL OR
            to_regprocedure(current_schema() || '.protect_region_catalog_write_request_235()') IS NOT NULL OR
            EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema=current_schema() AND table_name='region_catalog' AND
                      column_name IN ('description','l2_check_port','sort_order','revision')
            ) OR EXISTS (SELECT 1 FROM permissions WHERE name = 'regions.manage') THEN
        RAISE EXCEPTION 'migration 235 requires the exact verified 234 release head and untouched region management schema'
            USING ERRCODE = 'P2350';
    END IF;
END;
$migration_235$;

INSERT INTO permissions(name, description)
VALUES ('regions.manage', 'Create, update, and delete platform regions');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'regions.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name IN ('platform_owner', 'platform_admin')
ON CONFLICT DO NOTHING;

ALTER TABLE region_catalog
    ADD COLUMN description text NOT NULL DEFAULT '',
    ADD COLUMN l2_check_port integer NOT NULL DEFAULT 80,
    ADD COLUMN sort_order integer NOT NULL DEFAULT 100,
    ADD COLUMN revision bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT region_catalog_description_235_check CHECK (
        description = btrim(description) AND char_length(description) <= 1024 AND
        description !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT region_catalog_l2_check_port_235_check CHECK (l2_check_port BETWEEN 1 AND 65535),
    ADD CONSTRAINT region_catalog_sort_order_235_check CHECK (sort_order BETWEEN 0 AND 999999),
    ADD CONSTRAINT region_catalog_revision_235_check CHECK (revision > 0);

CREATE INDEX region_catalog_scope_sort_235_idx
    ON region_catalog(platform_scope_id, sort_order, display_id);

CREATE FUNCTION protect_region_catalog_management_235()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'region catalog cannot be truncated' USING ERRCODE = 'P2352';
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (
            SELECT 1 FROM nodes node
            WHERE node.scope_id = OLD.platform_scope_id AND
                  node.admin_state <> 'retired' AND btrim(node.region) = OLD.name
        ) THEN
            RAISE EXCEPTION 'referenced region cannot be deleted' USING ERRCODE = 'P2352';
        END IF;
        RETURN OLD;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR
       NEW.platform_scope_id IS DISTINCT FROM OLD.platform_scope_id OR
       NEW.display_id IS DISTINCT FROM OLD.display_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'region catalog revision must advance by one' USING ERRCODE = 'P2351';
    END IF;
    IF NEW.name IS DISTINCT FROM OLD.name AND EXISTS (
        SELECT 1 FROM nodes node
        WHERE node.scope_id = OLD.platform_scope_id AND
              node.admin_state <> 'retired' AND btrim(node.region) = OLD.name
    ) THEN
        RAISE EXCEPTION 'referenced region cannot be renamed' USING ERRCODE = 'P2352';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER region_catalog_management_update_235
BEFORE UPDATE ON region_catalog
FOR EACH ROW EXECUTE FUNCTION protect_region_catalog_management_235();

CREATE TRIGGER region_catalog_management_delete_235
BEFORE DELETE ON region_catalog
FOR EACH ROW EXECUTE FUNCTION protect_region_catalog_management_235();

CREATE TRIGGER region_catalog_management_truncate_235
BEFORE TRUNCATE ON region_catalog
FOR EACH STATEMENT EXECUTE FUNCTION protect_region_catalog_management_235();

CREATE TABLE region_catalog_write_requests (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (
        operation IN ('region_catalog.create', 'region_catalog.update', 'region_catalog.delete')
    ),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_status integer CHECK (response_status IN (200, 201, 204)),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at) AND completed_at >= created_at),
    CONSTRAINT region_catalog_write_requests_identity_235_unique
        UNIQUE(actor_user_id, operation, idempotency_key),
    CONSTRAINT region_catalog_write_requests_completion_235_check CHECK (
        (response_status IS NULL AND response_body IS NULL AND completed_at IS NULL) OR
        (response_status IS NOT NULL AND response_body IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE FUNCTION protect_region_catalog_write_request_235()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL AND
       OLD.response_status IS NULL AND NEW.response_status IS NOT NULL AND
       OLD.response_body IS NULL AND NEW.response_body IS NOT NULL AND
       NEW.id IS NOT DISTINCT FROM OLD.id AND
       NEW.actor_user_id IS NOT DISTINCT FROM OLD.actor_user_id AND
       NEW.actor_scope_id IS NOT DISTINCT FROM OLD.actor_scope_id AND
       NEW.operation IS NOT DISTINCT FROM OLD.operation AND
       NEW.idempotency_key IS NOT DISTINCT FROM OLD.idempotency_key AND
       NEW.request_digest IS NOT DISTINCT FROM OLD.request_digest AND
       NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'region catalog write requests are immutable after completion';
END;
$$;

CREATE TRIGGER region_catalog_write_requests_immutable_235
BEFORE UPDATE OR DELETE ON region_catalog_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_region_catalog_write_request_235();

CREATE TRIGGER region_catalog_write_requests_truncate_235
BEFORE TRUNCATE ON region_catalog_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_region_catalog_write_request_235();

DO $region_catalog_management_runtime_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT UPDATE, DELETE ON region_catalog TO cdnca_control_app;
        GRANT SELECT, INSERT, UPDATE ON region_catalog_write_requests TO cdnca_control_app;
    END IF;
END;
$region_catalog_management_runtime_grants$;
