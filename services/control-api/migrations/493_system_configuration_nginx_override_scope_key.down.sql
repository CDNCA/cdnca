-- 493（r136 nginx-region-b）回退：恢复 219 原定义（含 scope_key 优先级缺陷）。已写入的带 nginx
-- 覆盖的修订仍在表里，回退后新的同类修订再次无法写入。
LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_493_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 493 OR
       (SELECT max(version) FROM schema_migrations) <> 493 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=493 AND
        migration_id='493_system_configuration_nginx_override_scope_key' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 493 down requires the exact verified migration head' USING ERRCODE='P4931';
    END IF;
END;
$migration_493_down$;

CREATE OR REPLACE FUNCTION system_configuration_v2_nginx_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_scopes text[] := ARRAY[]::text[];
    scope_key text;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY['http','stream','worker','overrides']) OR
       NOT system_configuration_v2_nginx_worker(candidate->'worker') OR
       NOT system_configuration_v2_nginx_http(candidate->'http') OR
       NOT system_configuration_v2_nginx_stream(candidate->'stream') OR
       jsonb_typeof(candidate->'overrides') <> 'array' THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate->'overrides') LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['id','scope','values','scope_id']) OR
           NOT system_configuration_v2_short_id(item->'id') OR
           item->>'scope' NOT IN ('region','node') OR
           NOT system_configuration_v2_safe_label(item->'scope_id') OR
           NOT system_configuration_v2_nginx_override(item->'values', candidate) OR
           item->>'id' = ANY(seen_ids) THEN
            RETURN false;
        END IF;
        scope_key := item->>'scope' || E'\x1f' || item->>'scope_id';
        IF scope_key = ANY(seen_scopes) THEN RETURN false; END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_scopes := array_append(seen_scopes, scope_key);
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
