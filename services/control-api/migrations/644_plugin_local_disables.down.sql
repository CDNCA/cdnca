-- 644 回退：删除本机停用名单与写回执。回退后被本机停用的插件按租约重新生效（停用人与原因保留在审计日志里）；
-- 对挂了被停用规则包的网站，下一次发布会重新带上该规则包。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_644_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 644 OR
       (SELECT max(version) FROM schema_migrations) <> 644 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=644 AND
        migration_id='644_plugin_local_disables' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 644 down requires the exact verified migration head' USING ERRCODE='P6441';
    END IF;
END;
$migration_644_down$;

DROP TABLE plugin_local_disable_requests;
DROP TABLE plugin_local_disables;
