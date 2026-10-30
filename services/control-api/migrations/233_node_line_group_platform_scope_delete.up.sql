LOCK TABLE schema_migrations, access_scopes, users, memberships,
    node_line_groups, node_line_group_revisions, node_line_endpoints,
    node_line_endpoint_health, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_233$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 232 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 232 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 232 AND migration_id = '232_active_config_identity_configuration_scope' AND
              checksum_sha256 = 'a034c7c7036d2af6be7fd99094d0ea938170339e0dc937db54a1c333973bfa0a' AND
              down_checksum_sha256 = '0e36532308868afb1f7b81f3ca6a0eb720ef8c303f6fb6d728ce7c01d0b703fc' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'node_line_groups' AND
              column_name IN ('deleted_at', 'deleted_by_user_id')
       ) OR to_regprocedure(current_schema() || '.assert_node_scheduling_tenant_scope()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_node_line_group()') IS NULL THEN
        RAISE EXCEPTION 'migration 233 requires the exact verified 232 head and canonical node scheduling guards'
            USING ERRCODE = 'P2330';
    END IF;
END;
$migration_233$;

ALTER TABLE node_line_groups
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN deleted_by_user_id uuid,
    ADD CONSTRAINT node_line_groups_deleted_actor_233_check CHECK (
        (deleted_at IS NULL AND deleted_by_user_id IS NULL) OR
        (deleted_at IS NOT NULL AND deleted_by_user_id IS NOT NULL AND
         updated_by_user_id = deleted_by_user_id AND updated_at = deleted_at)
    ),
    ADD CONSTRAINT node_line_groups_deleted_time_233_check CHECK (
        deleted_at IS NULL OR (isfinite(deleted_at) AND deleted_at >= created_at)
    ),
    ADD CONSTRAINT node_line_groups_deleted_actor_233_fk
        FOREIGN KEY (tenant_scope_id, deleted_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

DROP INDEX node_line_groups_tenant_name_idx;
CREATE UNIQUE INDEX node_line_groups_tenant_name_idx
    ON node_line_groups (tenant_scope_id, lower(name))
    WHERE deleted_at IS NULL;

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_scope_resolved_value_unique;
CREATE UNIQUE INDEX node_line_groups_scope_resolved_value_unique
    ON node_line_groups (tenant_scope_id, resolved_value)
    WHERE deleted_at IS NULL;

ALTER TABLE node_scheduling_write_requests
    DROP CONSTRAINT node_scheduling_write_requests_operation_check,
    ADD CONSTRAINT node_scheduling_write_requests_operation_check CHECK (operation IN (
        'node_scheduling.group.put',
        'node_scheduling.group.create',
        'node_scheduling.group.update',
        'node_scheduling.group.rollback',
        'node_scheduling.group.delete',
        'node_scheduling.target_snapshot.create'
    ));

CREATE OR REPLACE FUNCTION assert_node_scheduling_tenant_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_kind text;
BEGIN
    SELECT kind INTO actual_kind FROM access_scopes WHERE id = NEW.tenant_scope_id;
    IF actual_kind IS NULL OR actual_kind NOT IN ('tenant', 'platform') THEN
        RAISE EXCEPTION 'node scheduling scope must be a tenant or platform scope';
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
        IF NEW.current_revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'node line group initial revision must be one without a tombstone';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted node line groups are immutable';
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
           OR NEW.name IS DISTINCT FROM OLD.name
           OR NEW.region IS DISTINCT FROM OLD.region
           OR NEW.resolved_value IS DISTINCT FROM OLD.resolved_value
           OR NEW.note IS DISTINCT FROM OLD.note
           OR NEW.sort_order IS DISTINCT FROM OLD.sort_order
           OR NEW.current_revision IS DISTINCT FROM OLD.current_revision
           OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.deleted_by_user_id IS NULL
           OR NEW.updated_by_user_id IS DISTINCT FROM NEW.deleted_by_user_id
           OR NEW.updated_at IS DISTINCT FROM NEW.deleted_at
           OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'node line group tombstone must preserve immutable configuration facts';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.deleted_by_user_id IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
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
