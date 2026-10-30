LOCK TABLE schema_migrations, platform_announcements_141, platform_announcement_archive_255,
    platform_announcement_snapshots_255, announcement_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_255_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 255 OR (SELECT max(version) FROM schema_migrations) <> 255 OR
       NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=255 AND migration_id='255_global_announcement_archive'
           AND checksum_sha256='0b49d5118389ab946f26cacccd0cce04a5f16862d430215eeaec2aa073809d60' AND integrity_state='verified') OR
       EXISTS(SELECT 1 FROM platform_announcement_archive_255 WHERE archived OR revision <> 1) OR
       EXISTS(SELECT 1 FROM platform_announcement_snapshots_255 WHERE NOT baseline) OR
       EXISTS(SELECT 1 FROM announcement_write_requests WHERE operation IN ('announcement.global.archive','announcement.global.restore')) THEN
        RAISE EXCEPTION 'migration 255 rollback cannot discard global announcement management history' USING ERRCODE='P2553';
    END IF;
END;
$migration_255_down$;

DROP TRIGGER zzzz_platform_announcements_255_snapshot ON platform_announcements_141;
DROP TRIGGER platform_announcements_255_archive_guard ON platform_announcements_141;
DROP TRIGGER platform_announcement_archive_255_snapshot ON platform_announcement_archive_255;
DROP FUNCTION capture_global_announcement_255();
DROP FUNCTION guard_archived_global_announcement_255();
DROP TABLE platform_announcement_snapshots_255;
DROP FUNCTION protect_platform_announcement_snapshot_255();
DROP FUNCTION platform_announcement_snapshot_255(uuid);
DROP TABLE platform_announcement_archive_255;
DROP FUNCTION protect_platform_announcement_archive_255();
ALTER TABLE platform_announcements_141 DROP CONSTRAINT platform_announcements_255_scope_id_key;
ALTER TABLE announcement_write_requests DROP CONSTRAINT announcement_write_requests_operation_255_check;
ALTER TABLE announcement_write_requests ADD CONSTRAINT announcement_write_requests_operation_254_check CHECK (operation IN (
    'announcement.create','announcement.update','announcement.schedule','announcement.publish','announcement.scheduled_publish',
    'announcement.revise','announcement.withdraw','announcement.archive','announcement.restore','announcement.deliver','announcement.read',
    'announcement.global.create','announcement.global.update','announcement.global.publish','announcement.global.withdraw'
));
