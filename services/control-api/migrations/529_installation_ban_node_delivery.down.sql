-- 529 回退（r136 p1-ticket-receipt）：去掉"已应用"水位与失败分级列，回到 489 的形状。
LOCK TABLE schema_migrations, installation_ban_node_state IN ACCESS EXCLUSIVE MODE;

DO $migration_529_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 529 OR
       (SELECT max(version) FROM schema_migrations) <> 529 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=529 AND
        migration_id='529_installation_ban_node_delivery' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 529 down requires the exact verified migration head' USING ERRCODE='P5291';
    END IF;
END;
$migration_529_down$;

ALTER TABLE installation_ban_node_state
    DROP CONSTRAINT installation_ban_node_state_delivery_529_check,
    DROP COLUMN next_retry_at,
    DROP COLUMN failed_attempts,
    DROP COLUMN failure_class,
    DROP COLUMN applied_revision;
