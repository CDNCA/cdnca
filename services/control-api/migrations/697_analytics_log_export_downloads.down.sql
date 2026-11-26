-- 697 回退：删除导出下载记录表。下载审计仍在 audit_events；696 及更早版本按已消费授权计数，不读这张表。
LOCK TABLE schema_migrations, analytics_log_exports_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_697_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 697 OR
       (SELECT max(version) FROM schema_migrations) <> 697 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=697 AND
        migration_id='697_analytics_log_export_downloads' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 697 down requires the exact verified migration head' USING ERRCODE='P6971';
    END IF;
END;
$migration_697_down$;

DROP TABLE analytics_log_export_downloads_v1;
