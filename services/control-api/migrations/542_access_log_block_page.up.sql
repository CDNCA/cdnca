-- 542（fix-decide1027b 第1项，用户 10-27："是否拦截页"改成可选）：
-- access_log_fields 目录加可选字段 block_page（edgeconfig.AccessLogFieldBlockPage，排在 x_real_ip 之后）。
-- 未勾选时主控入库前把 blocked 置 false，套餐计费因而把拦截页流量计入套餐流量。
-- 默认选择（从未保存的平台）含 block_page，行为不变；已保存过选择的平台需重新勾选才继续记录。
-- 只替换库内目录校验函数，不迁移数据。前驱 541（plugin_webhook_actor_definer），守卫钉 541 校验和。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_542_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 541 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 541 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=541 AND
        migration_id='541_plugin_webhook_actor_definer' AND
        checksum_sha256='cd2de7278778f876b787ce96cae349df7cf8fe37ec391e7e33658bbda1f153c1' AND
        down_checksum_sha256='511539fd73c838689d1d660146b387c4ee591ff5fc29451c26140043aa5b6253' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('system_configuration_v2_access_log_fields_is_valid(jsonb)') IS NULL THEN
        RAISE EXCEPTION 'migration 542 requires the exact verified 541 release head' USING ERRCODE='P5420';
    END IF;
END;
$migration_542_up$;

CREATE OR REPLACE FUNCTION system_configuration_v2_access_log_fields_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    catalog text[] := ARRAY['client_family','client_geo','referer','user_agent','accept_language','content_type',
        'content_encoding','origin_timing','upstream_addr','cache_control','x_forwarded_for','x_real_ip','block_page','ja4'];
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
