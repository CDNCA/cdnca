LOCK TABLE schema_migrations, node_presence IN ACCESS EXCLUSIVE MODE;

DO $migration_401_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 401 OR
       (SELECT max(version) FROM schema_migrations) <> 401 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=401 AND
        migration_id='401_node_market_probe_role' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 401 down requires the exact verified migration head' USING ERRCODE='P4011';
    END IF;
END;
$migration_401_down$;

ALTER TABLE node_presence DROP COLUMN market_probe_role;
