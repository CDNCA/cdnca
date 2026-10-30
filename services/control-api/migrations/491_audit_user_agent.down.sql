-- 491（r136 tp-b6b）回退：去掉 user_agent 列，归档守卫恢复为 361 版。
LOCK TABLE schema_migrations, audit_events, audit_event_archive IN ACCESS EXCLUSIVE MODE;

DO $migration_491_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 491 OR
       (SELECT max(version) FROM schema_migrations) <> 491 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=491 AND
        migration_id='491_audit_user_agent' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 491 down requires the exact verified migration head' USING ERRCODE='P4911';
    END IF;
    -- 非空 user_agent 在事件哈希里：删列会让这些行校验失败。
    IF EXISTS (SELECT 1 FROM audit_events WHERE user_agent <> '') OR
       EXISTS (SELECT 1 FROM audit_event_archive WHERE user_agent <> '') THEN
        RAISE EXCEPTION 'migration 491 down refuses to drop hashed user agents' USING ERRCODE='P4912';
    END IF;
END;
$migration_491_down$;

DROP TRIGGER audit_event_archive_insert_491 ON audit_event_archive;
CREATE TRIGGER audit_event_archive_insert_361 BEFORE INSERT ON audit_event_archive
    FOR EACH ROW EXECUTE FUNCTION guard_audit_event_archive_insert_361();
DROP FUNCTION guard_audit_event_archive_insert_491();

ALTER TABLE audit_event_archive DROP COLUMN user_agent;
ALTER TABLE audit_events
    DROP CONSTRAINT audit_events_user_agent_491,
    DROP COLUMN user_agent;
