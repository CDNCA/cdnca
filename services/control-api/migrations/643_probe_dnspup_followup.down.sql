-- 643 回退：撤销清理角色对插件拨测请求表的权限与守卫，过期行回到只在读取时判过期（不再清理）；
-- 删除 probe_dnspup_purposes.probe_type，聚合边缘候选拨测回到固定 tcping（已选 https 的设置随列丢弃）。
LOCK TABLE schema_migrations, probe_dnspup_plugin_requests, probe_dnspup_purposes IN ACCESS EXCLUSIVE MODE;

DO $migration_643_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 643 OR
       (SELECT max(version) FROM schema_migrations) <> 643 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=643 AND
        migration_id='643_probe_dnspup_followup' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 643 down requires the exact verified migration head' USING ERRCODE='P6431';
    END IF;
END;
$migration_643_down$;

DO $migration_643_revoke$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        REVOKE SELECT, DELETE ON probe_dnspup_plugin_requests FROM cdnca_retention_cleanup;
    END IF;
END;
$migration_643_revoke$;
DROP TRIGGER probe_dnspup_plugin_requests_retention_643 ON probe_dnspup_plugin_requests;
DROP FUNCTION guard_retention_delete_probe_request_643();
ALTER TABLE probe_dnspup_purposes DROP COLUMN probe_type;
