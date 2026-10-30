LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_193_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 193 OR (SELECT min(version) FROM schema_migrations) <> 1 OR (SELECT max(version) FROM schema_migrations) <> 193 OR EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id = '' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=193 AND migration_id='193_platform_system_cleanup_settings' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=192 AND migration_id='192_platform_system_settings' AND checksum_sha256='4eea40966f0c6b5833135d62668250f032bcd4c9d363bd2041de577c7f7a0ab0' AND down_checksum_sha256='885084c8e9a5af5b0990f2a86a31761471bddf27ec5ceebf2805350d78f89047' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 193 rollback requires the exact verified release head' USING ERRCODE='P1930';
    END IF;
END;
$migration_193_down$;

DROP TABLE platform_system_cleanup_settings_write_requests;
DROP TRIGGER platform_system_cleanup_settings_scope_193 ON platform_system_cleanup_settings;
DROP FUNCTION validate_platform_system_cleanup_settings_scope_193();
DROP TABLE platform_system_cleanup_settings;
