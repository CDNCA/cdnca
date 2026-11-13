-- 665 回退：删除按分钟的异常明细表（只是排查用的记录，不影响状态页）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_665_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 665 OR
       (SELECT max(version) FROM schema_migrations) <> 665 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=665 AND
        migration_id='665_status_page_samples' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 665 down requires the exact verified migration head' USING ERRCODE='P6651';
    END IF;
END;
$migration_665_down$;

DROP TABLE status_page_samples;
