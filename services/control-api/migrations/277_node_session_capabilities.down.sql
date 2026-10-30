LOCK TABLE schema_migrations, node_session_capabilities IN ACCESS EXCLUSIVE MODE;

DO $migration_277_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 277 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 277 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=277 AND
        migration_id='277_node_session_capabilities' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 277 down requires the exact verified migration head' USING ERRCODE='P2770';
    END IF;
    IF EXISTS (SELECT 1 FROM node_session_capabilities) THEN
        RAISE EXCEPTION 'migration 277 down refuses to discard recorded session evidence' USING ERRCODE='P2772';
    END IF;
END;
$migration_277_down$;

DROP TABLE node_session_capabilities;
DROP FUNCTION protect_node_session_capabilities_277();
