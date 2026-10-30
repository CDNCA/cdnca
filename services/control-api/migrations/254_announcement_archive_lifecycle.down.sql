LOCK TABLE schema_migrations, announcement_archive_254, announcement_lifecycle_facts_254, announcement_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_254_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 254 OR
       EXISTS (SELECT 1 FROM announcement_archive_254 WHERE archived) OR
       EXISTS (SELECT 1 FROM announcement_lifecycle_facts_254 WHERE state='archived') THEN
        RAISE EXCEPTION 'migration 254 rollback requires every announcement to be active and archive facts to be absent'
            USING ERRCODE='P2543';
    END IF;
END;
$migration_254_down$;

DROP TRIGGER announcement_lifecycle_facts_254_no_truncate ON announcement_lifecycle_facts_254;
DROP TRIGGER announcement_lifecycle_facts_254_append_only ON announcement_lifecycle_facts_254;
DROP FUNCTION protect_announcement_lifecycle_facts_254();
DROP TABLE announcement_lifecycle_facts_254;
DROP TABLE announcement_archive_254;

ALTER TABLE announcement_write_requests DROP CONSTRAINT announcement_write_requests_operation_254_check;
ALTER TABLE announcement_write_requests ADD CONSTRAINT announcement_write_requests_operation_141_check CHECK (operation IN (
    'announcement.create', 'announcement.update', 'announcement.schedule',
    'announcement.publish', 'announcement.scheduled_publish', 'announcement.revise',
    'announcement.withdraw', 'announcement.deliver', 'announcement.read',
    'announcement.global.create', 'announcement.global.update',
    'announcement.global.publish', 'announcement.global.withdraw'
));
