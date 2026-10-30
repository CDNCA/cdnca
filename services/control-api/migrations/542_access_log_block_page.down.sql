LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_542_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 542 OR
       (SELECT max(version) FROM schema_migrations) <> 542 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=542 AND
        migration_id='542_access_log_block_page' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM system_configuration_revisions
        WHERE convert_from(canonical_snapshot, 'UTF8')::jsonb->'configuration'->'access_log_fields'->'fields' ? 'block_page'
       ) THEN
        RAISE EXCEPTION 'migration 542 down requires the exact verified migration head and no revision recording block_page'
            USING ERRCODE='P5421';
    END IF;
END;
$migration_542_down$;

CREATE OR REPLACE FUNCTION system_configuration_v2_access_log_fields_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    catalog text[] := ARRAY['client_family','client_geo','referer','user_agent','accept_language','content_type',
        'content_encoding','origin_timing','upstream_addr','cache_control','x_forwarded_for','x_real_ip','ja4'];
    given text[];
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY['fields']) OR
       jsonb_typeof(candidate->'fields') <> 'array' OR
       EXISTS (SELECT 1 FROM jsonb_array_elements(candidate->'fields') item WHERE jsonb_typeof(item) <> 'string') THEN
        RETURN false;
    END IF;
    SELECT coalesce(array_agg(value ORDER BY ordinality), ARRAY[]::text[]) INTO given
    FROM jsonb_array_elements_text(candidate->'fields') WITH ORDINALITY;
    -- Canonical: known keys, unique, in catalog order.
    RETURN given = ARRAY(SELECT key FROM unnest(catalog) WITH ORDINALITY AS t(key, position)
                         WHERE key = ANY(given) ORDER BY position);
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
