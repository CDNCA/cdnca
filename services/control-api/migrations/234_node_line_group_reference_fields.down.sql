LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions,
    node_line_endpoints, node_line_endpoint_health, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_234_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 234 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 234 OR EXISTS (
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
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR (SELECT count(*) FROM information_schema.columns
             WHERE table_schema = current_schema() AND
                   table_name IN ('node_line_groups', 'node_line_group_revisions') AND
                   column_name IN ('ipv4_resolved_value', 'l2_config_id', 'failover_mode')) <> 6 OR
          to_regprocedure(current_schema() || '.assert_node_line_group_reference_234()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_node_line_group()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_node_line_group_revision()') IS NULL OR
          to_regprocedure(current_schema() || '.assert_node_line_group_current_snapshot()') IS NULL THEN
        RAISE EXCEPTION 'migration 234 rollback requires the exact verified 234 head and canonical line group guards'
            USING ERRCODE = 'P2341';
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_line_groups
        WHERE ipv4_resolved_value IS DISTINCT FROM 'v4-' || replace(id::text, '-', '') OR
              l2_config_id IS NOT NULL OR failover_mode IS DISTINCT FROM 'primary_offline'
    ) OR EXISTS (
        SELECT 1 FROM node_line_group_revisions
        WHERE ipv4_resolved_value IS DISTINCT FROM 'v4-' || replace(line_group_id::text, '-', '') OR
              l2_config_id IS NOT NULL OR failover_mode IS DISTINCT FROM 'primary_offline'
    ) THEN
        RAISE EXCEPTION 'migration 234 rollback cannot represent custom IPv4 resolution, L2 references, or failover modes'
            USING ERRCODE = 'P2341';
    END IF;
END;
$migration_234_down$;

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
UPDATE node_scheduling_write_requests
SET response_body = response_body
    #- '{group,ipv4_resolved_value}'
    #- '{group,l2_config_id}'
    #- '{group,failover_mode}'
WHERE completed_at IS NOT NULL AND response_body IS NOT NULL AND
      jsonb_typeof(response_body->'group') = 'object' AND
      (response_body->'group') ?| ARRAY['ipv4_resolved_value', 'l2_config_id', 'failover_mode'];
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;

DROP TRIGGER node_line_groups_reference_insert_234 ON node_line_groups;
DROP TRIGGER node_line_groups_reference_update_234 ON node_line_groups;
DROP FUNCTION assert_node_line_group_reference_234();

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

CREATE OR REPLACE FUNCTION protect_node_line_group_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_value IS NULL OR NEW.resolved_value = '' THEN
            NEW.resolved_value := 'lg-' || replace(NEW.line_group_id::text, '-', '');
        END IF;
        IF NEW.sealed_at IS NOT NULL THEN
            RAISE EXCEPTION 'node line group revisions must start unsealed';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.sealed_at IS NULL
       AND NEW.sealed_at IS NOT NULL
       AND NEW.line_group_id IS NOT DISTINCT FROM OLD.line_group_id
       AND NEW.tenant_scope_id IS NOT DISTINCT FROM OLD.tenant_scope_id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.name IS NOT DISTINCT FROM OLD.name
       AND NEW.region IS NOT DISTINCT FROM OLD.region
       AND NEW.resolved_value IS NOT DISTINCT FROM OLD.resolved_value
       AND NEW.note IS NOT DISTINCT FROM OLD.note
       AND NEW.sort_order IS NOT DISTINCT FROM OLD.sort_order
       AND NEW.probe_interval_ms IS NOT DISTINCT FROM OLD.probe_interval_ms
       AND NEW.probe_timeout_ms IS NOT DISTINCT FROM OLD.probe_timeout_ms
       AND NEW.failure_threshold IS NOT DISTINCT FROM OLD.failure_threshold
       AND NEW.recovery_threshold IS NOT DISTINCT FROM OLD.recovery_threshold
       AND NEW.failure_debounce_ms IS NOT DISTINCT FROM OLD.failure_debounce_ms
       AND NEW.recovery_debounce_ms IS NOT DISTINCT FROM OLD.recovery_debounce_ms
       AND NEW.endpoint_count IS NOT DISTINCT FROM OLD.endpoint_count
       AND NEW.configuration_digest IS NOT DISTINCT FROM OLD.configuration_digest
       AND NEW.created_by_user_id IS NOT DISTINCT FROM OLD.created_by_user_id
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'node line group revisions are immutable after sealing';
END;
$$;

CREATE OR REPLACE FUNCTION assert_node_line_group_current_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_count integer;
    actual_count integer;
    actual_health_count integer;
    snapshot_name text;
    snapshot_region text;
    snapshot_resolved_value text;
    snapshot_note text;
    snapshot_sort_order integer;
    snapshot_sealed_at timestamptz;
BEGIN
    SELECT endpoint_count, name, region, resolved_value, note, sort_order, sealed_at
    INTO expected_count, snapshot_name, snapshot_region, snapshot_resolved_value,
         snapshot_note, snapshot_sort_order, snapshot_sealed_at
    FROM node_line_group_revisions
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.id
      AND revision = NEW.current_revision;
    SELECT count(*) INTO actual_count
    FROM node_line_endpoints
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.id
      AND config_revision = NEW.current_revision;
    SELECT count(*) INTO actual_health_count
    FROM node_line_endpoint_health
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND line_group_id = NEW.id
      AND config_revision = NEW.current_revision;
    IF snapshot_sealed_at IS NULL OR snapshot_name IS DISTINCT FROM NEW.name
       OR snapshot_region IS DISTINCT FROM NEW.region
       OR snapshot_resolved_value IS DISTINCT FROM NEW.resolved_value
       OR snapshot_note IS DISTINCT FROM NEW.note
       OR snapshot_sort_order IS DISTINCT FROM NEW.sort_order
       OR expected_count IS DISTINCT FROM actual_count
       OR expected_count IS DISTINCT FROM actual_health_count THEN
        RAISE EXCEPTION 'current node line group revision must be sealed and complete';
    END IF;
    RETURN NEW;
END;
$$;

DROP INDEX node_line_groups_scope_ipv4_resolved_value_unique_234;

ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_l2_scope_234_fk,
    DROP CONSTRAINT node_line_group_revisions_failover_mode_234_check,
    DROP CONSTRAINT node_line_group_revisions_l2_not_self_234_check,
    DROP CONSTRAINT node_line_group_revisions_ipv4_resolved_value_234_check,
    DROP COLUMN failover_mode,
    DROP COLUMN l2_config_id,
    DROP COLUMN ipv4_resolved_value;

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_l2_scope_234_fk,
    DROP CONSTRAINT node_line_groups_failover_mode_234_check,
    DROP CONSTRAINT node_line_groups_l2_not_self_234_check,
    DROP CONSTRAINT node_line_groups_ipv4_resolved_value_234_check,
    DROP COLUMN failover_mode,
    DROP COLUMN l2_config_id,
    DROP COLUMN ipv4_resolved_value;
