LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions,
    node_line_endpoints, node_line_endpoint_health, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_234$
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
              down_checksum_sha256 = '45a59232eedd4873336421cc53cc5c393e9258f666a0d9c7569fd1d03547bfce' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND
              table_name IN ('node_line_groups', 'node_line_group_revisions') AND
              column_name IN ('ipv4_resolved_value', 'l2_config_id', 'failover_mode')
       ) OR to_regprocedure(current_schema() || '.protect_node_line_group()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_node_line_group_revision()') IS NULL OR
          to_regprocedure(current_schema() || '.assert_node_line_group_current_snapshot()') IS NULL THEN
        RAISE EXCEPTION 'migration 234 requires the exact verified 233 head and canonical node line group guards'
            USING ERRCODE = 'P2340';
    END IF;
END;
$migration_234$;

ALTER TABLE node_line_groups
    ADD COLUMN ipv4_resolved_value text NOT NULL DEFAULT '',
    ADD COLUMN l2_config_id uuid,
    ADD COLUMN failover_mode text NOT NULL DEFAULT 'primary_offline';

ALTER TABLE node_line_group_revisions
    ADD COLUMN ipv4_resolved_value text NOT NULL DEFAULT '',
    ADD COLUMN l2_config_id uuid,
    ADD COLUMN failover_mode text NOT NULL DEFAULT 'primary_offline';

ALTER TABLE node_line_groups DISABLE TRIGGER node_line_groups_protect_revision;
UPDATE node_line_groups
SET ipv4_resolved_value = 'v4-' || replace(id::text, '-', '');
ALTER TABLE node_line_groups ENABLE TRIGGER node_line_groups_protect_revision;

ALTER TABLE node_line_group_revisions DISABLE TRIGGER node_line_group_revisions_immutable;
ALTER TABLE node_line_group_revisions DISABLE TRIGGER node_line_group_revisions_health_complete;
UPDATE node_line_group_revisions
SET ipv4_resolved_value = 'v4-' || replace(line_group_id::text, '-', '');
ALTER TABLE node_line_group_revisions ENABLE TRIGGER node_line_group_revisions_immutable;
ALTER TABLE node_line_group_revisions ENABLE TRIGGER node_line_group_revisions_health_complete;

ALTER TABLE node_line_groups
    ADD CONSTRAINT node_line_groups_ipv4_resolved_value_234_check CHECK (
        char_length(ipv4_resolved_value) BETWEEN 1 AND 63 AND
        ipv4_resolved_value = lower(ipv4_resolved_value) AND
        ipv4_resolved_value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    ADD CONSTRAINT node_line_groups_l2_not_self_234_check CHECK (
        l2_config_id IS NULL OR l2_config_id <> id
    ),
    ADD CONSTRAINT node_line_groups_failover_mode_234_check CHECK (
        failover_mode IN ('primary_offline', 'online_less_than_backup_count', 'interval')
    ),
    ADD CONSTRAINT node_line_groups_l2_scope_234_fk
        FOREIGN KEY (tenant_scope_id, l2_config_id)
        REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX node_line_groups_scope_ipv4_resolved_value_unique_234
    ON node_line_groups (tenant_scope_id, ipv4_resolved_value)
    WHERE deleted_at IS NULL;

ALTER TABLE node_line_group_revisions
    ADD CONSTRAINT node_line_group_revisions_ipv4_resolved_value_234_check CHECK (
        char_length(ipv4_resolved_value) BETWEEN 1 AND 63 AND
        ipv4_resolved_value = lower(ipv4_resolved_value) AND
        ipv4_resolved_value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    ADD CONSTRAINT node_line_group_revisions_l2_not_self_234_check CHECK (
        l2_config_id IS NULL OR l2_config_id <> line_group_id
    ),
    ADD CONSTRAINT node_line_group_revisions_failover_mode_234_check CHECK (
        failover_mode IN ('primary_offline', 'online_less_than_backup_count', 'interval')
    ),
    ADD CONSTRAINT node_line_group_revisions_l2_scope_234_fk
        FOREIGN KEY (tenant_scope_id, l2_config_id)
        REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

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
        IF NEW.ipv4_resolved_value IS NULL OR NEW.ipv4_resolved_value = '' THEN
            NEW.ipv4_resolved_value := 'v4-' || replace(NEW.id::text, '-', '');
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
           OR NEW.ipv4_resolved_value IS DISTINCT FROM OLD.ipv4_resolved_value
           OR NEW.l2_config_id IS DISTINCT FROM OLD.l2_config_id
           OR NEW.failover_mode IS DISTINCT FROM OLD.failover_mode
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
        IF NEW.ipv4_resolved_value IS NULL OR NEW.ipv4_resolved_value = '' THEN
            NEW.ipv4_resolved_value := 'v4-' || replace(NEW.line_group_id::text, '-', '');
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
       AND NEW.ipv4_resolved_value IS NOT DISTINCT FROM OLD.ipv4_resolved_value
       AND NEW.l2_config_id IS NOT DISTINCT FROM OLD.l2_config_id
       AND NEW.failover_mode IS NOT DISTINCT FROM OLD.failover_mode
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
    snapshot_ipv4_resolved_value text;
    snapshot_l2_config_id uuid;
    snapshot_failover_mode text;
    snapshot_note text;
    snapshot_sort_order integer;
    snapshot_sealed_at timestamptz;
BEGIN
    SELECT endpoint_count, name, region, resolved_value, ipv4_resolved_value, l2_config_id,
           failover_mode, note, sort_order, sealed_at
    INTO expected_count, snapshot_name, snapshot_region, snapshot_resolved_value,
         snapshot_ipv4_resolved_value, snapshot_l2_config_id, snapshot_failover_mode,
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
       OR snapshot_ipv4_resolved_value IS DISTINCT FROM NEW.ipv4_resolved_value
       OR snapshot_l2_config_id IS DISTINCT FROM NEW.l2_config_id
       OR snapshot_failover_mode IS DISTINCT FROM NEW.failover_mode
       OR snapshot_note IS DISTINCT FROM NEW.note
       OR snapshot_sort_order IS DISTINCT FROM NEW.sort_order
       OR expected_count IS DISTINCT FROM actual_count
       OR expected_count IS DISTINCT FROM actual_health_count THEN
        RAISE EXCEPTION 'current node line group revision must be sealed and complete';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_node_line_group_reference_234()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_region text;
    target_l2_config_id uuid;
BEGIN
    IF NEW.l2_config_id IS NOT NULL THEN
        IF NEW.l2_config_id = NEW.id THEN
            RAISE EXCEPTION 'node line group cannot reference itself as L2 configuration'
                USING ERRCODE = 'P2342';
        END IF;
        SELECT region, l2_config_id INTO target_region, target_l2_config_id
        FROM node_line_groups
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND id = NEW.l2_config_id
          AND deleted_at IS NULL
        FOR KEY SHARE;
        IF NOT FOUND OR target_l2_config_id IS NOT NULL OR target_region IS DISTINCT FROM NEW.region THEN
            RAISE EXCEPTION 'L2 configuration must be an active standalone line group in the same scope and region'
                USING ERRCODE = 'P2342';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_line_groups dependent
        WHERE dependent.tenant_scope_id = NEW.tenant_scope_id
          AND dependent.l2_config_id = NEW.id
          AND dependent.deleted_at IS NULL
          AND (NEW.deleted_at IS NOT NULL OR NEW.l2_config_id IS NOT NULL OR
               dependent.region IS DISTINCT FROM NEW.region)
    ) THEN
        RAISE EXCEPTION 'referenced L2 configuration cannot be deleted, nested, or moved to another region'
            USING ERRCODE = 'P2342';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_line_groups_reference_insert_234
BEFORE INSERT ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_reference_234();

CREATE TRIGGER node_line_groups_reference_update_234
BEFORE UPDATE OF tenant_scope_id, id, region, l2_config_id, deleted_at ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_reference_234();

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
UPDATE node_scheduling_write_requests request
SET response_body = jsonb_set(
    request.response_body,
    '{group}',
    (request.response_body->'group') || jsonb_build_object(
        'ipv4_resolved_value', revision.ipv4_resolved_value,
        'l2_config_id', revision.l2_config_id,
        'failover_mode', revision.failover_mode
    ),
    true
)
FROM node_line_group_revisions revision
WHERE request.tenant_scope_id = revision.tenant_scope_id AND
      request.target_group_id = revision.line_group_id AND
      request.completed_at IS NOT NULL AND request.response_body IS NOT NULL AND
      jsonb_typeof(request.response_body->'group') = 'object' AND
      jsonb_typeof(request.response_body->'group'->'revision') = 'number' AND
      revision.revision = (request.response_body->'group'->>'revision')::bigint;

DO $migration_234_receipts$
BEGIN
    IF EXISTS (
        SELECT 1 FROM node_scheduling_write_requests
        WHERE completed_at IS NOT NULL AND response_body IS NOT NULL AND
              jsonb_typeof(response_body->'group') = 'object' AND NOT (
                  (response_body->'group') ?& ARRAY['ipv4_resolved_value', 'l2_config_id', 'failover_mode']
              )
    ) THEN
        RAISE EXCEPTION 'migration 234 could not bind every historical line group receipt to its immutable revision'
            USING ERRCODE = 'P2343';
    END IF;
END;
$migration_234_receipts$;
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;
