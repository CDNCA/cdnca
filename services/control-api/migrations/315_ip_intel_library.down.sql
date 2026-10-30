LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_315_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 315 OR
       (SELECT max(version) FROM schema_migrations) <> 315 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=315 AND
        migration_id='315_ip_intel_library' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 315 down requires the exact verified migration head' USING ERRCODE='P3151';
    END IF;
END;
$migration_315_down$;

-- The library is re-fetched from the license service after a re-upgrade.
DROP TABLE ip_intel_sync_state;
DROP TRIGGER ip_intel_library_forward_315 ON ip_intel_library;
DROP FUNCTION protect_ip_intel_library_315();
DROP TABLE ip_intel_library;
