-- 489（r136 pf09-ticket）回退：只去掉两列凭据时间，回执行保留。
LOCK TABLE schema_migrations, installation_ban_node_state IN ACCESS EXCLUSIVE MODE;

DO $migration_489_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 489 OR
       (SELECT max(version) FROM schema_migrations) <> 489 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=489 AND
        migration_id='489_installation_ban_node_ticket' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 489 down requires the exact verified migration head' USING ERRCODE='P4891';
    END IF;
END;
$migration_489_down$;

ALTER TABLE installation_ban_node_state
    DROP CONSTRAINT installation_ban_node_state_ticket_489_check,
    DROP COLUMN ticket_not_after,
    DROP COLUMN ticket_issued_at;
