LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_194_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 194 OR (SELECT min(version) FROM schema_migrations) <> 1 OR (SELECT max(version) FROM schema_migrations) <> 194 OR EXISTS (SELECT 1 FROM schema_migrations WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) OR NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=194 AND migration_id='194_platform_system_user_settings' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) OR NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=193 AND migration_id='193_platform_system_cleanup_settings' AND checksum_sha256='89a1973a220e729afbcdbe9f6c5605f9a1d8ca4797f5ca7ccf751cdb30dae3d9' AND down_checksum_sha256='38ce3bff16af336cff92ebed4c52c91a0e93d4059dfeb18db43efc7d8a6243b0' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 194 rollback requires the exact verified release head' USING ERRCODE='P1940';
    END IF;
END;
$migration_194_down$;

DROP TABLE platform_system_user_settings_write_requests;
DROP TRIGGER platform_system_user_settings_scope_194 ON platform_system_user_settings;
DROP FUNCTION validate_platform_system_user_settings_scope_194();
DROP TABLE platform_system_user_settings;
