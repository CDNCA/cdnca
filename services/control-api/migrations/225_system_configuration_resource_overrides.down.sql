LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_225_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 225 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 225 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 225 AND migration_id = '225_system_configuration_resource_overrides' AND
              checksum_sha256 = '6ca959a26bb17feffb477cb9435e09c5b74f3183523f1c428ba4b425264b32f6' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 224 AND migration_id = '224_system_configuration_resource_paths' AND
              checksum_sha256 = '5066e72135c6b46224a0774cd8909ef78cde45c544ea8fbb69a3c5ccc38d01e5' AND
              down_checksum_sha256 = '748d05a3179aa4afa1c92cb98bf91f8fdfdb33aa175000f61e5066bb23c8fd23' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regprocedure(
            current_schema() || '.system_configuration_v2_resource_override_key_225(jsonb)'
       ) IS NULL OR to_regprocedure(
            current_schema() || '.system_configuration_v2_resources_is_valid_219_compat_225(jsonb)'
       ) IS NULL THEN
        RAISE EXCEPTION 'migration 225 rollback requires the exact verified 225 release head'
            USING ERRCODE = 'P2250';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM system_configuration_revisions revision
        CROSS JOIN LATERAL (
            SELECT convert_from(revision.canonical_snapshot, 'UTF8')::jsonb
                   #> '{configuration,resources}' AS resources
        ) document
        WHERE NOT system_configuration_v2_resources_is_valid_219_compat_225(document.resources) OR
              COALESCE(jsonb_array_length(document.resources #> '{stream,custom_port_not_allow}'), 0) > 128 OR
              COALESCE(jsonb_array_length(document.resources #> '{site_stream,custom_port_not_allow}'), 0) > 128 OR
              COALESCE(jsonb_array_length(document.resources #> '{site_stream,custom_port_allow}'), 0) > 128 OR
              EXISTS (
                SELECT 1 FROM jsonb_array_elements(document.resources->'overrides') item
                WHERE COALESCE(jsonb_array_length(item #> '{values,stream,custom_port_not_allow}'), 0) > 128 OR
                      COALESCE(jsonb_array_length(item #> '{values,site_stream,custom_port_not_allow}'), 0) > 128 OR
                      COALESCE(jsonb_array_length(item #> '{values,site_stream,custom_port_allow}'), 0) > 128
              )
    ) THEN
        RAISE EXCEPTION 'migration 225 rollback refused: resource revision facts require one-setting overrides or expanded port ranges'
            USING ERRCODE = 'P2252';
    END IF;
END;
$migration_225_down$;

CREATE OR REPLACE FUNCTION system_configuration_v2_port_ranges(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    previous_to integer := 0;
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' OR jsonb_array_length(candidate) > 128 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['from','to']) OR
           NOT system_configuration_json_integer(item->'from', 1, 65535) OR
           NOT system_configuration_json_integer(item->'to', 1, 65535) OR
           (item->>'from')::integer > (item->>'to')::integer OR
           (item->>'from')::integer <= previous_to THEN
            RETURN false;
        END IF;
        previous_to := (item->>'to')::integer;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION system_configuration_v2_resources_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_scopes text[] := ARRAY[]::text[];
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(
           candidate, ARRAY['site','stream','overrides','site_stream']
       ) OR NOT system_configuration_v2_resource_site(candidate->'site') OR
       NOT system_configuration_v2_resource_stream(candidate->'stream') OR
       NOT system_configuration_v2_resource_site_stream(candidate->'site_stream') OR
       jsonb_typeof(candidate->'overrides') <> 'array' THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate->'overrides') LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['id','scope','values','scope_id']) OR
           NOT system_configuration_v2_short_id(item->'id') OR item->>'scope' <> 'region' OR
           NOT system_configuration_v2_safe_label(item->'scope_id') OR
           NOT system_configuration_v2_resources_override(item->'values') OR
           item->>'id' = ANY(seen_ids) OR item->>'scope_id' = ANY(seen_scopes) THEN
            RETURN false;
        END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_scopes := array_append(seen_scopes, item->>'scope_id');
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

DROP FUNCTION system_configuration_v2_resources_is_valid_219_compat_225(jsonb);
DROP FUNCTION system_configuration_v2_resource_override_key_225(jsonb);
