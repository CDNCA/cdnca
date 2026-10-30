LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_224_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 224 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 224 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 224 AND migration_id = '224_system_configuration_resource_paths' AND
              checksum_sha256 = '5066e72135c6b46224a0774cd8909ef78cde45c544ea8fbb69a3c5ccc38d01e5' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 223 AND migration_id = '223_region_catalog' AND
              checksum_sha256 = '75fdb6a530e0f3369c235aa4d45e0ebcd24be9ac2ee16b5e733ce047eaf7f719' AND
              down_checksum_sha256 = 'fe4fa01774301dd82eb3308d06c5a06c8259c71c6acd7a414f2fc2c4646f8cda' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regprocedure(
            current_schema() || '.system_configuration_v2_resource_access_log_path_224(jsonb)'
       ) IS NULL THEN
        RAISE EXCEPTION 'migration 224 rollback requires the exact verified 224 release head'
            USING ERRCODE = 'P2240';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM system_configuration_revisions revision
        CROSS JOIN LATERAL (
            SELECT convert_from(revision.canonical_snapshot, 'UTF8')::jsonb
                   #> '{configuration,resources,site}' AS site
        ) document
        WHERE NOT system_configuration_json_integer(
                  document.site->'related_config_max_times_limit', 1, 100
              ) OR
              jsonb_typeof(document.site->'access_log_tmp_dir') <> 'string' OR
              document.site->>'access_log_tmp_dir' !~ '^/var/lib/cdnca(/[^/]+)*$' OR
              document.site->>'access_log_tmp_dir' ~ '(^|/)\.\.?(/|$)|[[:cntrl:]\\]'
    ) THEN
        RAISE EXCEPTION 'migration 224 rollback refused: resource revision facts require the expanded path or multiplier contract'
            USING ERRCODE = 'P2241';
    END IF;
END;
$migration_224_down$;

CREATE OR REPLACE FUNCTION system_configuration_v2_resource_site(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'black_ip_limit','white_ip_limit','cc_rule_max_limit','access_log_tmp_dir',
               'max_domains_per_site','daily_clean_dir_limit','daily_clean_url_limit',
               'daily_ip_unlock_limit','daily_pre_cache_url_limit','access_log_retain_hours',
               'listen_default_http_80','related_config_min_limit','ip_unlock_per_request_limit',
               'daily_access_log_download_limit','related_config_max_times_limit'
           ])
       AND system_configuration_json_integer(candidate->'related_config_min_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'related_config_max_times_limit', 1, 100)
       AND system_configuration_json_integer(candidate->'black_ip_limit', 1, 1000000)
       AND system_configuration_json_integer(candidate->'white_ip_limit', 1, 1000000)
       AND system_configuration_json_integer(candidate->'daily_clean_url_limit', 1, 10000000)
       AND system_configuration_json_integer(candidate->'daily_clean_dir_limit', 1, 1000000)
       AND system_configuration_json_integer(candidate->'daily_pre_cache_url_limit', 1, 10000000)
       AND system_configuration_json_integer(candidate->'daily_ip_unlock_limit', 1, 10000000)
       AND system_configuration_json_integer(candidate->'ip_unlock_per_request_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'cc_rule_max_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'max_domains_per_site', 1, 100)
       AND jsonb_typeof(candidate->'listen_default_http_80') = 'boolean'
       AND system_configuration_json_integer(candidate->'daily_access_log_download_limit', 1, 100000)
       AND jsonb_typeof(candidate->'access_log_tmp_dir') = 'string'
       AND candidate->>'access_log_tmp_dir' ~ '^/var/lib/cdnca(/[^/]+)*$'
       AND candidate->>'access_log_tmp_dir' !~ '(^|/)\.\.?(/|$)|[[:cntrl:]\\]'
       AND system_configuration_json_integer(candidate->'access_log_retain_hours', 1, 720);
$$;

DROP FUNCTION system_configuration_v2_resource_access_log_path_224(jsonb);
