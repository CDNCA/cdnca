LOCK TABLE schema_migrations, announcement_write_requests, announcement_state_facts,
    announcement_state_watermarks, platform_announcements_141,
    platform_announcement_recipients_141 IN ACCESS EXCLUSIVE MODE;

DO $migration_141$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 141 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 141 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 141 AND migration_id = '141_platform_global_announcements' AND
              checksum_sha256 = 'd078248a163d03698eb559bec8c45b5f7ebc6b682603ed6e1f6448958c26af7f' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 140 AND migration_id = '140_package_subscription_manual_open' AND
              checksum_sha256 = 'a89707a1033c0b192569081af1119ca1e075016a06cdd40df71fb8d7d28d5489' AND
              down_checksum_sha256 = '58a58b9c789b244eff9eb88b35eab2c924f4721c00f1fc9a6cbb44d2b2bfd542' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 141 rollback requires the exact verified 141 head'
            USING ERRCODE = 'P1410';
    END IF;
    IF EXISTS (SELECT 1 FROM platform_announcements_141) OR
       EXISTS (SELECT 1 FROM platform_announcement_recipients_141) OR
       EXISTS (
           SELECT 1 FROM announcement_write_requests
           WHERE operation IN (
               'announcement.global.create', 'announcement.global.update',
               'announcement.global.publish', 'announcement.global.withdraw'
           )
       ) OR EXISTS (
           SELECT 1 FROM announcement_state_facts
           WHERE payload->>'source' = 'platform_global'
       ) THEN
        RAISE EXCEPTION 'migration 141 rollback would discard durable platform global announcement facts'
            USING ERRCODE = 'P1412';
    END IF;
END;
$migration_141$;

DROP TRIGGER platform_announcements_141_version_facts ON platform_announcements_141;
DROP FUNCTION record_platform_announcement_version_facts_141();
DROP TRIGGER platform_announcement_recipients_141_update_fact ON platform_announcement_recipients_141;
DROP FUNCTION record_platform_announcement_recipient_state_fact_141();
DROP TRIGGER platform_announcement_recipients_141_insert_facts ON platform_announcement_recipients_141;
DROP FUNCTION record_platform_announcement_recipient_facts_141();

DROP TRIGGER platform_announcement_recipients_141_truncate_guard
    ON platform_announcement_recipients_141;
DROP TRIGGER platform_announcement_recipients_141_guard
    ON platform_announcement_recipients_141;
DROP FUNCTION protect_platform_announcement_recipient_141();
DROP TRIGGER platform_announcements_141_truncate_guard ON platform_announcements_141;
DROP TRIGGER platform_announcements_141_guard ON platform_announcements_141;
DROP FUNCTION protect_platform_announcement_141();

DROP TABLE platform_announcement_recipients_141;
DROP TABLE platform_announcements_141;

ALTER TABLE announcement_write_requests
    DROP CONSTRAINT announcement_write_requests_operation_141_check,
    ADD CONSTRAINT announcement_write_requests_operation_check CHECK (operation IN (
        'announcement.create', 'announcement.update', 'announcement.schedule',
        'announcement.publish', 'announcement.scheduled_publish', 'announcement.revise',
        'announcement.withdraw', 'announcement.deliver', 'announcement.read'
    ));
