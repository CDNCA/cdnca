LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_198_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 198 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 198 OR
       EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE migration_id IS NULL OR migration_id='' OR
                 checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
                 down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
                 integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE version=198 AND migration_id='198_notification_anonymous_verification_events' AND
                 integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
           SELECT 1 FROM notification_events
           WHERE event_type IN ('identity.account_registration_verification','identity.account_login_verification')
       ) THEN
        RAISE EXCEPTION 'migration 198 rollback requires the exact unused verified release head'
            USING ERRCODE='P1980';
    END IF;
END;
$migration_198_down$;

ALTER TABLE notification_events
    DROP CONSTRAINT notification_events_recipient_one_of_049,
    ADD CONSTRAINT notification_events_recipient_one_of_049 CHECK (
        (
            recipient_kind = 'member' AND
            recipient_user_id IS NOT NULL AND
            anonymous_dispatch_reference IS NULL AND
            event_type <> 'identity.account_recovery'
        ) OR (
            recipient_kind = 'anonymous' AND
            recipient_user_id IS NULL AND
            anonymous_dispatch_reference IS NOT NULL AND
            anonymous_dispatch_reference <> '00000000-0000-0000-0000-000000000000'::uuid AND
            event_type = 'identity.account_recovery' AND
            delivery_policy = 'system_required'
        )
    );
