LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_450_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 450 OR
       (SELECT max(version) FROM schema_migrations) <> 450 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=450 AND
        migration_id='450_waf_adapt_node_limits' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 450 down requires the exact verified migration head' USING ERRCODE='P4502';
    END IF;
END;
$migration_450_down$;

-- Display only (the nodes report again within the hour).
DROP TABLE waf_adapt_node_limits;
