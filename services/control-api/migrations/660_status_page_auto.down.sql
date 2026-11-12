-- 660 回退：删除组件隐藏列、线路组同步时间列与已处理线路组表。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_660_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 660 OR
       (SELECT max(version) FROM schema_migrations) <> 660 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=660 AND
        migration_id='660_status_page_auto' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 660 down requires the exact verified migration head' USING ERRCODE='P6601';
    END IF;
END;
$migration_660_down$;

DROP TABLE status_page_line_group_seen;
ALTER TABLE status_page_settings DROP COLUMN lines_synced_at;
ALTER TABLE status_page_components DROP COLUMN hidden;
