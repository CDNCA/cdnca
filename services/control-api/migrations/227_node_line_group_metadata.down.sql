LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions,
    node_line_endpoints, node_line_endpoint_health, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_227_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 227 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 227 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 227 AND migration_id = '227_node_line_group_metadata' AND
              checksum_sha256 = '8c0eb0c65e2b1e0d08f27bbaca740284b1206c4be4da3fa9f34512921a166bf0' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 226 AND migration_id = '226_system_configuration_tls_protocols' AND
              checksum_sha256 = 'ec27c02f2461808e26f872011d6cdf6810100160039ddaeef30abddd3eaf845b' AND
              down_checksum_sha256 = 'ffde321f4610b9be49f9ce3d4a8f962fed6e8b75964c35c95008de0b3ff75327' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 227 rollback requires the exact verified 227 release head'
            USING ERRCODE = 'P2270';
    END IF;

    IF EXISTS (
        SELECT 1 FROM node_line_groups
        WHERE region <> '' OR note <> '' OR sort_order <> 100 OR
              resolved_value <> 'lg-' || replace(id::text, '-', '')
    ) OR EXISTS (
        SELECT 1 FROM node_line_group_revisions
        WHERE region <> '' OR note <> '' OR sort_order <> 100 OR endpoint_count = 0 OR
              resolved_value <> 'lg-' || replace(line_group_id::text, '-', '')
    ) THEN
        RAISE EXCEPTION 'migration 227 rollback refused: line group metadata or empty revisions would be lost'
            USING ERRCODE = 'P2271';
    END IF;
END;
$migration_227_down$;

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
UPDATE node_scheduling_write_requests
SET response_body = response_body #- '{group,region}' #- '{group,resolved_value}' #- '{group,note}' #- '{group,sort_order}'
WHERE completed_at IS NOT NULL AND response_body IS NOT NULL AND
      jsonb_typeof(response_body->'group') = 'object';
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;

CREATE OR REPLACE FUNCTION protect_node_line_group()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node line groups cannot be physically deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
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

CREATE OR REPLACE FUNCTION protect_node_line_group_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
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
    snapshot_sealed_at timestamptz;
BEGIN
    SELECT endpoint_count, name, sealed_at INTO expected_count, snapshot_name, snapshot_sealed_at
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
       OR expected_count IS DISTINCT FROM actual_count
       OR expected_count IS DISTINCT FROM actual_health_count OR actual_count < 1 THEN
        RAISE EXCEPTION 'current node line group revision must be sealed and non-empty';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_endpoint_count_bounds,
    ADD CONSTRAINT node_line_group_revisions_endpoint_count_check CHECK (endpoint_count BETWEEN 1 AND 512),
    DROP CONSTRAINT node_line_group_revisions_region_valid,
    DROP CONSTRAINT node_line_group_revisions_resolved_value_valid,
    DROP CONSTRAINT node_line_group_revisions_note_valid,
    DROP CONSTRAINT node_line_group_revisions_sort_order_positive,
    DROP COLUMN region,
    DROP COLUMN resolved_value,
    DROP COLUMN note,
    DROP COLUMN sort_order;

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_scope_resolved_value_unique,
    DROP CONSTRAINT node_line_groups_region_valid,
    DROP CONSTRAINT node_line_groups_resolved_value_valid,
    DROP CONSTRAINT node_line_groups_note_valid,
    DROP CONSTRAINT node_line_groups_sort_order_positive,
    DROP COLUMN region,
    DROP COLUMN resolved_value,
    DROP COLUMN note,
    DROP COLUMN sort_order;
