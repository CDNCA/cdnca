LOCK TABLE schema_migrations, traffic_package_cycle_deductions, traffic_package_grants,
    package_addon_assignments IN ACCESS EXCLUSIVE MODE;

DO $migration_338_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 338 OR
       (SELECT max(version) FROM schema_migrations) <> 338 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=338 AND
        migration_id='338_traffic_package_coverage_wake' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 338 down requires the exact verified migration head' USING ERRCODE='P3381';
    END IF;
END;
$migration_338_down$;

DROP TRIGGER package_addon_assignments_wake_enforcement_338 ON package_addon_assignments;
DROP TRIGGER traffic_package_grants_wake_enforcement_338 ON traffic_package_grants;
DROP FUNCTION wake_package_traffic_enforcement_338();

ALTER TABLE traffic_package_cycle_deductions
    DROP CONSTRAINT traffic_package_cycle_deductions_cycle_338,
    DROP COLUMN cycle_ends_at,
    DROP COLUMN cycle_starts_at;
