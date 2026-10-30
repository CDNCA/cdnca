LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_192_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 192 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 192 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=192 AND migration_id='192_platform_system_settings' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 192 rollback requires the exact verified release head'
            USING ERRCODE='P1920';
    END IF;
END;
$migration_192_down$;

DROP TABLE platform_system_settings_write_requests;
DROP TRIGGER platform_system_settings_scope_192 ON platform_system_settings;
DROP FUNCTION validate_platform_system_settings_scope_192();
DROP TABLE platform_system_settings;
