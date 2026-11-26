-- 690（前驱 689_certificate_publication_actor_refreshed_session）。
-- 「其它配置 → 访问与网络 → 源IP请求头」恢复生效：control-api 按 settings.source_ip_header 取访客 IP
-- （internal/clientip）。此前该字段没有读取方，旧默认值 X-Real-IP 与旧页面存下的任意值都不是管理员
-- 按现在的含义选的；原样生效会让直连主控的请求按客户端自带的头记来源 IP。这里一律清空为 ""（直连），
-- 由管理员在页面重新选择；revision 加一，旧页面带着旧 revision 的保存按冲突拒绝，不会把旧值写回。
-- 其余设置与 dns_config 不动。
-- 错误码：头检查 P6908；down 头检查 P6909。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE platform_system_other_settings IN SHARE ROW EXCLUSIVE MODE;

DO $migration_690_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 689 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 689 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=689 AND
        migration_id='689_certificate_publication_actor_refreshed_session' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR
       to_regclass('platform_system_other_settings') IS NULL THEN
        RAISE EXCEPTION 'migration 690 requires the exact verified 689 release head' USING ERRCODE='P6908';
    END IF;
END;
$migration_690_up$;

UPDATE platform_system_other_settings
   SET settings=jsonb_set(settings, '{source_ip_header}', '""'::jsonb), revision=revision+1
 WHERE settings ? 'source_ip_header' AND settings->'source_ip_header' IS DISTINCT FROM '""'::jsonb
   AND revision < 9223372036854775806;
