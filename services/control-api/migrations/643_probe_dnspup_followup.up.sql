-- 643（前驱 642_market_local_labels）：
-- 拨测插件 module.probe.dnspup 补完（docs/architecture/probe-dnspup-unified.md）。
--   1. probe_dnspup_plugin_requests（639）此前只在读取时按 expires_at 判过期，没有清理。
--      FX01 retention worker 以专用清理角色 cdnca_retention_cleanup 按小时分批删除 expires_at 已过的行；
--      本迁移给该角色 SELECT/DELETE，并加逐行守卫：清理角色只能删已过期的行。其他角色的删除不变。
--   2. probe_dnspup_purposes.probe_type：聚合边缘候选拨测（edge_health）可选 tcping（默认，现状）/ https；
--      https 时 dnspup 用 http 类型按接入点域名拨（客户 API 不能指定 SNI / Host；接入点是 IP 的仍用 tcping）。
--      其他用途的拨测类型不在这里设（为 NULL）。
LOCK TABLE schema_migrations, probe_dnspup_plugin_requests, probe_dnspup_purposes IN ACCESS EXCLUSIVE MODE;

DO $migration_643_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 642 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 642 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=642 AND
        migration_id='642_market_local_labels' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.probe_dnspup_plugin_requests') IS NULL
         OR to_regprocedure(current_schema() || '.guard_retention_delete_probe_request_643()') IS NOT NULL
         OR EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema()
                    AND table_name = 'probe_dnspup_purposes' AND column_name = 'probe_type') THEN
        RAISE EXCEPTION 'migration 643 requires the exact verified 642 release head' USING ERRCODE='P6430';
    END IF;
END;
$migration_643_up$;

-- 清理角色删除插件拨测请求时逐行复核：只能删 expires_at 已过的行。
CREATE FUNCTION guard_retention_delete_probe_request_643()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT OLD.expires_at < transaction_timestamp() THEN
        RAISE EXCEPTION 'probe request has not expired' USING ERRCODE='P6432';
    END IF;
    RETURN OLD;
END;
$function$;
CREATE TRIGGER probe_dnspup_plugin_requests_retention_643 BEFORE DELETE ON probe_dnspup_plugin_requests FOR EACH ROW
    WHEN (current_user = 'cdnca_retention_cleanup') EXECUTE FUNCTION guard_retention_delete_probe_request_643();

ALTER TABLE probe_dnspup_purposes ADD COLUMN probe_type text;
UPDATE probe_dnspup_purposes SET probe_type = 'tcping' WHERE purpose = 'edge_health';
ALTER TABLE probe_dnspup_purposes ADD CONSTRAINT probe_dnspup_purposes_probe_type_643_check CHECK (
    CASE WHEN purpose = 'edge_health' THEN probe_type IN ('tcping', 'https') ELSE probe_type IS NULL END);

DO $migration_643_grants$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_retention_cleanup', current_schema());
        GRANT SELECT, DELETE ON probe_dnspup_plugin_requests TO cdnca_retention_cleanup;
    END IF;
END;
$migration_643_grants$;
