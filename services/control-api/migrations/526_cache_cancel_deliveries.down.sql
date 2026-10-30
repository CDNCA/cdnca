LOCK TABLE schema_migrations, cache_operation_cancel_deliveries IN ACCESS EXCLUSIVE MODE;

DO $migration_526_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 526 OR
       (SELECT max(version) FROM schema_migrations) <> 526 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=526 AND
        migration_id='526_cache_cancel_deliveries' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 526 down requires the exact verified migration head' USING ERRCODE='P5261';
    END IF;
    IF EXISTS (SELECT 1 FROM cache_operation_cancel_deliveries WHERE state = 'pending') THEN
        RAISE EXCEPTION 'migration 526 rollback would drop cache cancels still waiting for a node' USING ERRCODE='P5262';
    END IF;
END;
$migration_526_down$;

DROP TABLE cache_operation_cancel_deliveries;
