LOCK TABLE schema_migrations, node_presence, node_config_state IN ACCESS EXCLUSIVE MODE;

DO $migration_290_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 290 OR
       (SELECT max(version) FROM schema_migrations) <> 290 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=290 AND
        migration_id='290_node_presence_scope_identities' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 290 down requires the exact verified migration head' USING ERRCODE='P2901';
    END IF;
END;
$migration_290_down$;

-- Scoped identities are a projection of the latest heartbeat; the next
-- heartbeat after rolling forward rebuilds them.
DROP TABLE node_presence_scope_identities;
DROP FUNCTION validate_node_presence_scope_identity_290();
