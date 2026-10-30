-- 525（r136 fz-x1 NODE-N05）回退：删除授出记录列表索引，数据不动。
LOCK TABLE schema_migrations, node_line_group_grants IN ACCESS EXCLUSIVE MODE;

DO $migration_525_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 525 OR
       (SELECT max(version) FROM schema_migrations) <> 525 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=525 AND
        migration_id='525_line_group_grants_grantor_history' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 525 down requires the exact verified migration head' USING ERRCODE='P5251';
    END IF;
END;
$migration_525_down$;

DROP INDEX node_line_group_grants_grantor_history_525_idx;
