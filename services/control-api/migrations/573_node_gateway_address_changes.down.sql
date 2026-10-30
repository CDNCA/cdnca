LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_573_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 573 OR
       (SELECT max(version) FROM schema_migrations) <> 573 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=573 AND
        migration_id='573_node_gateway_address_changes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 573 down requires the exact verified migration head' USING ERRCODE='P5731';
    END IF;
    -- An open change means nodes may still switch on a signed document the
    -- control plane would forget: refuse instead.
    IF EXISTS (SELECT 1 FROM node_gateway_address_change_nodes WHERE state IN ('pending', 'delivered', 'probing')) THEN
        RAISE EXCEPTION 'migration 573 rollback would abandon open gateway address changes' USING ERRCODE='P5732';
    END IF;
END;
$migration_573_down$;

DROP TABLE node_gateway_address_change_nodes;
DROP TABLE node_gateway_address_node_revisions;
DROP TABLE node_gateway_address_changes;
