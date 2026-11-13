-- 662 回退：删除全局时间索引（只影响查询速度，不丢数据）。
LOCK TABLE schema_migrations, audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_662_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 662 OR
       (SELECT max(version) FROM schema_migrations) <> 662 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=662 AND migration_id='662_audit_events_time_idx' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 662 down requires the exact verified migration head' USING ERRCODE='P6621';
    END IF;
END;
$migration_662_down$;

DROP INDEX audit_events_time_id_662;
