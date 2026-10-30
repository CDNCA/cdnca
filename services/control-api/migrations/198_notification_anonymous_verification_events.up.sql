LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE notification_events IN ACCESS EXCLUSIVE MODE;

DO $migration_198$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 197 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 197 OR
       EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE migration_id IS NULL OR migration_id='' OR
                 checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
                 down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
                 integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
           SELECT 1 FROM schema_migrations
           WHERE version=197 AND migration_id='197_account_login_challenge' AND
                 checksum_sha256='b3df6e3759ecdee5d726ebe94f7a15f287abc3790c5f84b5137130bbd744bd22' AND
                 down_checksum_sha256='16576a892e38097fdbf078cac3b718161b1753b18e7eb2ab49d106c7a27b9e1d' AND
                 integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 198 requires the exact verified 197 release head'
            USING ERRCODE='P1980';
    END IF;
END;
$migration_198$;

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
            event_type IN (
                'identity.account_recovery',
                'identity.account_registration_verification',
                'identity.account_login_verification'
            ) AND
            delivery_policy = 'system_required'
        )
    );
