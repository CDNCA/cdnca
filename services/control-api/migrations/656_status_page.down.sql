-- 656 回退：删除状态页的五张表（设置、组件、事件、进展、每日汇总）。不涉及权限与其他表。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_656_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 656 OR
       (SELECT max(version) FROM schema_migrations) <> 656 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=656 AND
        migration_id='656_status_page' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 656 down requires the exact verified migration head' USING ERRCODE='P6561';
    END IF;
END;
$migration_656_down$;

DROP TABLE status_page_daily;
DROP TABLE status_page_incident_updates;
DROP TABLE status_page_incidents;
DROP TABLE status_page_components;
DROP TABLE status_page_settings;
