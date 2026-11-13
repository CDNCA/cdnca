-- 663 回退：删除批量函数（dashboard 的读方在回退前的版本里是逐站调用，不依赖它）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_663_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 663 OR
       (SELECT max(version) FROM schema_migrations) <> 663 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=663 AND migration_id='663_site_sync_status_batch' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 663 down requires the exact verified migration head' USING ERRCODE='P6631';
    END IF;
END;
$migration_663_down$;

DROP FUNCTION site_sync_status_batch_663(uuid[]);
