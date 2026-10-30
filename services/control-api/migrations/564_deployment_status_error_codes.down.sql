LOCK TABLE schema_migrations, deployment_status_events IN ACCESS EXCLUSIVE MODE;

DO $migration_564_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 564 OR
       (SELECT max(version) FROM schema_migrations) <> 564 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=564 AND
        migration_id='564_deployment_status_error_codes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 564 down requires the exact verified migration head' USING ERRCODE='P5641';
    END IF;
END;
$migration_564_down$;

-- 回到 554：节点回执原文仍在 payload 里，去掉的只是冗余的错误码列；554 把这些部署都算作失败。
ALTER TABLE deployment_status_events DROP COLUMN error_code;
