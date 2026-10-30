LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_384_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 384 OR
       (SELECT max(version) FROM schema_migrations) <> 384 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=384 AND
        migration_id='384_admin_inbox_messages' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 384 down requires the exact verified migration head' USING ERRCODE='P3841';
    END IF;
END;
$migration_384_down$;

-- Inbox copies of already delivered operations events; the events themselves
-- stay in notification_events.
DROP TABLE admin_inbox_messages;
