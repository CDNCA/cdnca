LOCK TABLE schema_migrations, access_scopes, users, memberships,
    node_line_groups, node_line_group_revisions, node_line_endpoints,
    node_line_endpoint_health, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_233_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 233 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 233 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 233 AND migration_id = '233_node_line_group_platform_scope_delete' AND
              checksum_sha256 = '81831602f2f93f107f8b350b1d2178e9231b320dcc1f979b03d265fcb1e50d85' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 233 rollback requires the exact verified 233 head'
            USING ERRCODE = 'P2331';
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_line_groups line_group
        JOIN access_scopes scope ON scope.id = line_group.tenant_scope_id
        WHERE scope.kind <> 'tenant' OR line_group.deleted_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM node_scheduling_write_requests
        WHERE operation = 'node_scheduling.group.delete'
    ) THEN
        RAISE EXCEPTION 'migration 233 rollback cannot represent platform or deleted node line groups'
            USING ERRCODE = 'P2331';
    END IF;
END;
$migration_233_down$;

CREATE OR REPLACE FUNCTION assert_node_scheduling_tenant_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_kind text;
BEGIN
    SELECT kind INTO actual_kind FROM access_scopes WHERE id = NEW.tenant_scope_id;
    IF actual_kind IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'node scheduling scope must be a tenant scope';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_node_line_group()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node line groups cannot be physically deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_value IS NULL OR NEW.resolved_value = '' THEN
            NEW.resolved_value := 'lg-' || replace(NEW.id::text, '-', '');
        END IF;
        IF NEW.current_revision <> 1 THEN
            RAISE EXCEPTION 'node line group initial revision must be one';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.current_revision <> OLD.current_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node line group revision must advance by one';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_operation_check,
    ADD CONSTRAINT node_scheduling_write_requests_operation_check CHECK (operation IN (
        'node_scheduling.group.put',
        'node_scheduling.group.create',
        'node_scheduling.group.update',
        'node_scheduling.group.rollback',
        'node_scheduling.target_snapshot.create'
    ));

DROP INDEX node_line_groups_scope_resolved_value_unique;
ALTER TABLE node_line_groups
    ADD CONSTRAINT node_line_groups_scope_resolved_value_unique UNIQUE (tenant_scope_id, resolved_value);

DROP INDEX node_line_groups_tenant_name_idx;
CREATE UNIQUE INDEX node_line_groups_tenant_name_idx
    ON node_line_groups (tenant_scope_id, lower(name));

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_deleted_actor_233_fk,
    DROP CONSTRAINT node_line_groups_deleted_actor_233_check,
    DROP CONSTRAINT node_line_groups_deleted_time_233_check,
    DROP COLUMN deleted_by_user_id,
    DROP COLUMN deleted_at;
