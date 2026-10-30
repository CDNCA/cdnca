LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_295_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 295 OR
       (SELECT max(version) FROM schema_migrations) <> 295 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=295 AND
        migration_id='295_config_version_telemetry_site_bindings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 295 down requires the exact verified migration head' USING ERRCODE='P2952';
    END IF;
    -- Site runtime v2 versions published since 295 depend on their rows for
    -- exact telemetry attribution.
    IF EXISTS (SELECT 1 FROM config_version_telemetry_site_bindings) THEN
        RAISE EXCEPTION 'retain telemetry site bindings of site runtime v2 versions during binary rollback'
            USING ERRCODE='P2953';
    END IF;
END;
$migration_295_down$;

-- Only an empty table is dropped; authorization then reads v2 versions
-- through the package monitor bindings (114) again.
DROP TABLE config_version_telemetry_site_bindings;
DROP FUNCTION protect_config_version_telemetry_site_bindings_295();
