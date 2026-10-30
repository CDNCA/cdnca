LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_197_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 197 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 197 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=197 AND migration_id='197_account_login_challenge' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=196 AND migration_id='196_platform_system_other_settings' AND checksum_sha256='296e9eb4404dc60f37b3564e960fa6194ad8ae7b0cd41925fc5c64c26feed011' AND down_checksum_sha256='8d2af779e2da3218c17f063de6fd6e99f60838994a16ee120dbcf9966a992eb7' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type='identity.account_login_verification') THEN
        RAISE EXCEPTION 'migration 197 rollback requires the exact unused verified release head' USING ERRCODE='P1970';
    END IF;
END;
$migration_197_down$;

DROP TABLE account_login_challenge_dispatch_claims_197;
DROP TABLE account_login_challenge_verify_receipts_197;
DROP TABLE account_login_challenges_197;
DROP TABLE account_login_challenge_writes_197;
DELETE FROM notification_templates WHERE template_id='account_login_verification' AND version=1 AND channel IN ('email','sms');
