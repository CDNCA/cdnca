LOCK TABLE schema_migrations, traffic_package_cycle_deductions IN ACCESS EXCLUSIVE MODE;

DO $migration_330_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 330 OR
       (SELECT max(version) FROM schema_migrations) <> 330 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=330 AND
        migration_id='330_traffic_package_cycle_deductions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 330 down requires the exact verified migration head' USING ERRCODE='P3301';
    END IF;
    -- Package coverage is billing evidence: dropping it would let the next
    -- evaluation deduct the same overage again.
    IF EXISTS (SELECT 1 FROM traffic_package_cycle_deductions) THEN
        RAISE EXCEPTION 'migration 330 down refuses to drop recorded traffic package deductions' USING ERRCODE='P3302';
    END IF;
END;
$migration_330_down$;

DROP INDEX traffic_package_grants_due_330;
DROP TABLE traffic_package_cycle_deductions;
