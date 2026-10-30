-- 539 回滚：去掉工单软删除。已有被删除的工单时拒绝回滚（回滚会让它们重新出现）。
LOCK TABLE schema_migrations, tickets IN ACCESS EXCLUSIVE MODE;

DO $migration_539_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 539 OR
       (SELECT max(version) FROM schema_migrations) <> 539 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=539 AND
        migration_id='539_ticket_soft_delete' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 539 down requires the exact verified migration head' USING ERRCODE='P5391';
    END IF;
    IF EXISTS (SELECT 1 FROM tickets WHERE deleted_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 539 rollback would restore deleted tickets' USING ERRCODE='P5392';
    END IF;
END;
$migration_539_down$;

DROP TRIGGER tickets_deleted_guard_539 ON tickets;
DROP FUNCTION tickets_deleted_guard_539();
ALTER TABLE tickets DROP CONSTRAINT tickets_deleted_by_539_check;
ALTER TABLE tickets DROP COLUMN deleted_by_user_id;
ALTER TABLE tickets DROP COLUMN deleted_at;
