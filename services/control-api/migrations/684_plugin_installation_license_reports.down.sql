-- 684 回滚：去掉插件安装回执的授权端送达确认。683 及更早版本在回报失败时直接返回 503（结果未知），
-- 未送达的回执不再补报，需要管理员原样重试那次请求。
LOCK TABLE schema_migrations, plugin_installation_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_684_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 684 OR
       (SELECT max(version) FROM schema_migrations) <> 684 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=684 AND
        migration_id='684_plugin_installation_license_reports' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 684 down requires the exact verified migration head' USING ERRCODE='P6842';
    END IF;
END;
$migration_684_down$;

DROP TABLE plugin_installation_license_report_attempts;
DROP TABLE plugin_installation_license_reports;
DROP FUNCTION protect_plugin_installation_license_report_684();
