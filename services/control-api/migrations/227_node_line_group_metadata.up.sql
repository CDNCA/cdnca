LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions,
    node_line_endpoints, node_line_endpoint_health, node_scheduling_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_227$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 226 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 226 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 226 AND migration_id = '226_system_configuration_tls_protocols' AND
              checksum_sha256 = 'ec27c02f2461808e26f872011d6cdf6810100160039ddaeef30abddd3eaf845b' AND
              down_checksum_sha256 = 'ffde321f4610b9be49f9ce3d4a8f962fed6e8b75964c35c95008de0b3ff75327' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND
              table_name IN ('node_line_groups', 'node_line_group_revisions') AND
              column_name IN ('region', 'resolved_value', 'note', 'sort_order')
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'node_line_group_revisions'::regclass AND
              conname = 'node_line_group_revisions_endpoint_count_check'
       ) OR to_regprocedure(current_schema() || '.protect_node_line_group()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_node_line_group_revision()') IS NULL OR
          to_regprocedure(current_schema() || '.assert_node_line_group_current_snapshot()') IS NULL OR
          to_regprocedure(current_schema() || '.assert_node_line_group_revision_health_complete()') IS NULL THEN
        RAISE EXCEPTION 'migration 227 requires the exact verified 226 release head and canonical node scheduling guards'
            USING ERRCODE = 'P2270';
    END IF;
END;
$migration_227$;

ALTER TABLE node_line_groups
    ADD COLUMN region text NOT NULL DEFAULT '',
    ADD COLUMN resolved_value text NOT NULL DEFAULT '',
    ADD COLUMN note text NOT NULL DEFAULT '',
    ADD COLUMN sort_order integer NOT NULL DEFAULT 100;

ALTER TABLE node_line_group_revisions
    ADD COLUMN region text NOT NULL DEFAULT '',
    ADD COLUMN resolved_value text NOT NULL DEFAULT '',
    ADD COLUMN note text NOT NULL DEFAULT '',
    ADD COLUMN sort_order integer NOT NULL DEFAULT 100;

ALTER TABLE node_line_groups DISABLE TRIGGER node_line_groups_protect_revision;
UPDATE node_line_groups
SET resolved_value = 'lg-' || replace(id::text, '-', '');
ALTER TABLE node_line_groups ENABLE TRIGGER node_line_groups_protect_revision;

ALTER TABLE node_line_group_revisions
    DISABLE TRIGGER node_line_group_revisions_immutable;
ALTER TABLE node_line_group_revisions
    DISABLE TRIGGER node_line_group_revisions_health_complete;
UPDATE node_line_group_revisions
SET resolved_value = 'lg-' || replace(line_group_id::text, '-', '');
ALTER TABLE node_line_group_revisions ENABLE TRIGGER node_line_group_revisions_immutable;
ALTER TABLE node_line_group_revisions ENABLE TRIGGER node_line_group_revisions_health_complete;

ALTER TABLE node_line_groups
    ADD CONSTRAINT node_line_groups_region_valid CHECK (
        region = btrim(region) AND char_length(region) <= 64 AND region !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT node_line_groups_resolved_value_valid CHECK (
        char_length(resolved_value) BETWEEN 1 AND 63 AND
        resolved_value = lower(resolved_value) AND
        resolved_value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    ADD CONSTRAINT node_line_groups_note_valid CHECK (
        note = btrim(note) AND char_length(note) <= 512 AND note !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT node_line_groups_sort_order_positive CHECK (sort_order > 0),
    ADD CONSTRAINT node_line_groups_scope_resolved_value_unique UNIQUE (tenant_scope_id, resolved_value);

ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_endpoint_count_check,
    ADD CONSTRAINT node_line_group_revisions_endpoint_count_bounds CHECK (endpoint_count BETWEEN 0 AND 512),
    ADD CONSTRAINT node_line_group_revisions_region_valid CHECK (
        region = btrim(region) AND char_length(region) <= 64 AND region !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT node_line_group_revisions_resolved_value_valid CHECK (
        char_length(resolved_value) BETWEEN 1 AND 63 AND
        resolved_value = lower(resolved_value) AND
        resolved_value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    ADD CONSTRAINT node_line_group_revisions_note_valid CHECK (
        note = btrim(note) AND char_length(note) <= 512 AND note !~ '[[:cntrl:]]'
    ),
    ADD CONSTRAINT node_line_group_revisions_sort_order_positive CHECK (sort_order > 0);

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

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
UPDATE node_scheduling_write_requests request
SET response_body = jsonb_set(
    request.response_body,
    '{group}',
    (request.response_body->'group') || jsonb_build_object(
        'region', revision.region,
        'resolved_value', revision.resolved_value,
        'note', revision.note,
        'sort_order', revision.sort_order
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

DO $migration_227_receipts$
BEGIN
    IF EXISTS (
        SELECT 1 FROM node_scheduling_write_requests
        WHERE completed_at IS NOT NULL AND response_body IS NOT NULL AND
              jsonb_typeof(response_body->'group') = 'object' AND NOT (
                  (response_body->'group') ?& ARRAY['region', 'resolved_value', 'note', 'sort_order']
              )
    ) THEN
        RAISE EXCEPTION 'migration 227 could not bind every historical line group receipt to its immutable revision'
            USING ERRCODE = 'P2272';
    END IF;
END;
$migration_227_receipts$;
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;
