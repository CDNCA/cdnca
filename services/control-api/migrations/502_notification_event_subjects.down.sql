-- 502（r136 fp-sec）回退：已记下资源 ID 的事件在 501 无法表达时拒绝回退。
LOCK TABLE schema_migrations, notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_502_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 502 OR
       (SELECT max(version) FROM schema_migrations) <> 502 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=502 AND
        migration_id='502_notification_event_subjects' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 502 down requires the exact verified migration head' USING ERRCODE='P5021';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_events WHERE subject_site_id IS NOT NULL OR subject_package_id IS NOT NULL) THEN
        RAISE EXCEPTION 'retain notification event resource facts during binary rollback' USING ERRCODE='P5022';
    END IF;
END;
$migration_502_down$;

DROP INDEX notification_events_recipient_created_502;
ALTER TABLE notification_events
    DROP CONSTRAINT notification_events_subjects_member_502,
    DROP COLUMN subject_package_id,
    DROP COLUMN subject_site_id;
