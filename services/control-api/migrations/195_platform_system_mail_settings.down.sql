LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_195_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 195 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 195 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=195 AND migration_id='195_platform_system_mail_settings' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=194 AND migration_id='194_platform_system_user_settings' AND checksum_sha256='9f26f465cecf170606bf5c3a65bd42aca5b0463e61ddfc1a200fe6bfd37cda3b' AND down_checksum_sha256='b2e061e4a430ba356d45fec63af78aeeb71c346f9e9b791d9b9fd06b892e33fb' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 195 rollback requires the exact verified release head' USING ERRCODE='P1950';
    END IF;
END;
$migration_195_down$;

DROP TABLE platform_system_mail_settings_write_requests;
DROP TRIGGER platform_system_mail_settings_scope_195 ON platform_system_mail_settings;
DROP FUNCTION validate_platform_system_mail_settings_scope_195();
DROP TABLE platform_system_mail_settings;
