LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_381_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 381 OR
       (SELECT max(version) FROM schema_migrations) <> 381 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=381 AND
        migration_id='381_platform_admin_access_policy' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 381 down requires the exact verified migration head' USING ERRCODE='P3811';
    END IF;
END;
$migration_381_down$;

-- Dropping the policy lifts the administration access restriction.
DROP TABLE platform_admin_access_policy;
