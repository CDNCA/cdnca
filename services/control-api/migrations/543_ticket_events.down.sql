-- 543 回滚：去掉工单事件表（只丢系统行时间线，工单与消息不受影响）。
LOCK TABLE schema_migrations, tickets IN ACCESS EXCLUSIVE MODE;

DO $migration_543_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 543 OR
       (SELECT max(version) FROM schema_migrations) <> 543 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=543 AND
        migration_id='543_ticket_events' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 543 down requires the exact verified migration head' USING ERRCODE='P5431';
    END IF;
END;
$migration_543_down$;

DROP TABLE ticket_events;
