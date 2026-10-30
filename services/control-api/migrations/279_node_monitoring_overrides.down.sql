LOCK TABLE schema_migrations, node_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_279_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 279 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 279 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=279 AND
        migration_id='279_node_monitoring_overrides' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 279 down requires the exact verified migration head' USING ERRCODE='P2790';
    END IF;
    -- Dropping recorded overrides would lower delivered config revisions, which
    -- installed Agents reject; recorded overrides block rollback.
    IF EXISTS (SELECT 1 FROM node_monitoring_overrides) OR
       EXISTS (SELECT 1 FROM node_write_requests WHERE operation='node.monitoring_override') THEN
        RAISE EXCEPTION 'migration 279 down refuses to discard node monitoring overrides' USING ERRCODE='P2793';
    END IF;
END;
$migration_279_down$;

ALTER TABLE node_write_requests
    DROP CONSTRAINT node_write_requests_operation_check,
    ADD CONSTRAINT node_write_requests_operation_check
        CHECK (operation IN ('node.create', 'node.update', 'node.batch_admin_state'));
DROP TABLE node_monitoring_overrides;
DROP FUNCTION protect_node_monitoring_override_279();
