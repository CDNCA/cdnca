LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_196_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 196 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 196 OR
       EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=196 AND migration_id='196_platform_system_other_settings' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=195 AND migration_id='195_platform_system_mail_settings' AND checksum_sha256='37f666d8f4d51db10b4ea70731ed1cf41b8005318b2d326b09cee1605906fdd0' AND down_checksum_sha256='c042473c80293ae72e05bdbcec5ef64934e327280d44bfc4d7adca52f838fcf8' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 196 rollback requires the exact verified release head' USING ERRCODE='P1960';
    END IF;
END;
$migration_196_down$;

DROP TABLE platform_system_other_settings_write_requests;
DROP TRIGGER platform_system_other_settings_scope_196 ON platform_system_other_settings;
DROP FUNCTION validate_platform_system_other_settings_scope_196();
DROP TABLE platform_system_other_settings;
