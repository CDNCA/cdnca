-- 493（r136 nginx-region-b，本地占位 490，merge-p3 合入改为 493、前驱 492）。
-- 219 的 system_configuration_v2_nginx_is_valid 里
--   scope_key := item->>'scope' || E'\x1f' || item->>'scope_id';
-- 按运算符优先级被解析成 ((item->>'scope') || E'\x1f' || item) ->> 'scope_id'，即 text ->> text，
-- 每次执行都报错并被 EXCEPTION WHEN OTHERS 吞成 false：只要 nginx.overrides 非空，系统配置修订
-- 插入触发器（validate_system_configuration_revision_insert）就拒绝写入，「Nginx 配置 > 区域及节点配置」
-- 从来无法保存。只加括号，其余逐字照抄 219；资源/默认配置的覆盖校验不用这个表达式，不受影响。
LOCK TABLE schema_migrations, system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_493_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 492 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 492 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=492 AND
        migration_id='492_tenant_site_defaults_auto_dns' AND
        checksum_sha256='53389281060ad1dd6b5616b3f8b2b137ff568674459b57fedcde97b4995cf3c5' AND
        down_checksum_sha256='4378935fb9b80acc14a6390888f4545adb07bc467f175b8f33d07b8a581171d6' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.system_configuration_v2_nginx_is_valid(jsonb)') IS NULL THEN
        RAISE EXCEPTION 'migration 493 requires the exact verified 492 release head' USING ERRCODE='P4930';
    END IF;
END;
$migration_493_up$;

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
        scope_key := (item->>'scope') || E'\x1f' || (item->>'scope_id');
        IF scope_key = ANY(seen_scopes) THEN RETURN false; END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_scopes := array_append(seen_scopes, scope_key);
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
