LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_540_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 540 OR
       (SELECT max(version) FROM schema_migrations) <> 540 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=540 AND
        migration_id='540_access_log_fields' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM system_configuration_revisions
        WHERE convert_from(canonical_snapshot, 'UTF8')::jsonb->'configuration' ? 'access_log_fields'
       ) THEN
        RAISE EXCEPTION 'migration 540 down requires the exact verified migration head and no access_log_fields revision'
            USING ERRCODE='P5401';
    END IF;
END;
$migration_540_down$;

CREATE OR REPLACE FUNCTION system_configuration_snapshot_is_valid(candidate bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    raw text;
    document jsonb;
    configuration jsonb;
BEGIN
    raw := convert_from(candidate, 'UTF8');
    IF raw <> btrim(raw) THEN RETURN false; END IF;
    document := raw::jsonb;
    IF raw <> document::text OR
       NOT system_configuration_v2_json_keys_exact(document, ARRAY['schema','configuration']) OR
       jsonb_typeof(document->'schema') <> 'string' OR
       document->>'schema' <> 'cdnca.system-configuration/v2' THEN
        RETURN false;
    END IF;
    configuration := document->'configuration';
    IF NOT system_configuration_v2_json_keys_exact(configuration, ARRAY[
           'nginx','secrets','defaults','resources','error_pages'
       ], ARRAY['node_monitoring','ddos_protection']) OR
       NOT system_configuration_v2_nginx_is_valid(configuration->'nginx') OR
       NOT system_configuration_v2_defaults_is_valid(configuration->'defaults') OR
       NOT system_configuration_v2_resources_is_valid(configuration->'resources') OR
       NOT system_configuration_v2_error_pages_is_valid(configuration->'error_pages') OR
       NOT system_configuration_v2_secrets_is_valid(configuration->'secrets') OR
       (configuration ? 'node_monitoring' AND
        NOT system_configuration_v2_node_monitoring_is_valid(configuration->'node_monitoring')) OR
       (configuration ? 'ddos_protection' AND
        NOT system_configuration_v2_ddos_protection_is_valid(configuration->'ddos_protection')) THEN
        RETURN false;
    END IF;
    RETURN system_configuration_render_canonical_snapshot(document) = candidate;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

DROP FUNCTION system_configuration_v2_access_log_fields_is_valid(jsonb);
