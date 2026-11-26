-- 690 回退：只检查迁移头。清空前的 source_ip_header 没有读取方、也不保留，回退不恢复；
-- 旧版 control-api 不读该字段，"" 对它无影响。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_690_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 690 OR
       (SELECT max(version) FROM schema_migrations) <> 690 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=690 AND
        migration_id='690_source_ip_header_reset' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 690 down requires the exact verified migration head' USING ERRCODE='P6909';
    END IF;
END;
$migration_690_down$;
