-- 540（fix-logfields2，用户 10-27："系统配置中可选择日志记录值……要不访问量高了根本没地方存"）：
-- 系统配置新增可选类别 access_log_fields（edgeconfig.AccessLogFields）：访问日志记录哪些可选字段。
-- 值 {"fields":[...]}，元素为固定目录内的键，按目录顺序、不重复（Go 写规范形式，这里是库内上限）。
-- 未保存过的平台按 edgeconfig.DefaultAccessLogFields。不迁移数据。
-- 前驱 539（ticket_soft_delete），守卫钉 539 校验和。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_540_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 539 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 539 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=539 AND
        migration_id='539_ticket_soft_delete' AND
        checksum_sha256='2b6a4e41a1b492d9bedec9a13888557279f1aad806745b2c2f7923ce8863a974' AND
        down_checksum_sha256='380532e653efe7b0cc0dbb71e07c681ddb472e8f200f300669a7bd036015fbdf' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('system_configuration_v2_ddos_protection_is_valid(jsonb)') IS NULL OR
       to_regprocedure('system_configuration_v2_access_log_fields_is_valid(jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 540 requires the exact verified 539 release head' USING ERRCODE='P5400';
    END IF;
END;
$migration_540_up$;

CREATE FUNCTION system_configuration_v2_access_log_fields_is_valid(candidate jsonb)
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
       ], ARRAY['node_monitoring','ddos_protection','access_log_fields']) OR
       NOT system_configuration_v2_nginx_is_valid(configuration->'nginx') OR
       NOT system_configuration_v2_defaults_is_valid(configuration->'defaults') OR
       NOT system_configuration_v2_resources_is_valid(configuration->'resources') OR
       NOT system_configuration_v2_error_pages_is_valid(configuration->'error_pages') OR
       NOT system_configuration_v2_secrets_is_valid(configuration->'secrets') OR
       (configuration ? 'node_monitoring' AND
        NOT system_configuration_v2_node_monitoring_is_valid(configuration->'node_monitoring')) OR
       (configuration ? 'ddos_protection' AND
        NOT system_configuration_v2_ddos_protection_is_valid(configuration->'ddos_protection')) OR
       (configuration ? 'access_log_fields' AND
        NOT system_configuration_v2_access_log_fields_is_valid(configuration->'access_log_fields')) THEN
        RETURN false;
    END IF;
    RETURN system_configuration_render_canonical_snapshot(document) = candidate;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
