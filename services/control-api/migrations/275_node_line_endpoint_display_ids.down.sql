LOCK TABLE schema_migrations, node_line_endpoints, node_line_endpoint_display_ids IN ACCESS EXCLUSIVE MODE;

DO $migration_275_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 275 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 275 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=275 AND
        migration_id='275_node_line_endpoint_display_ids' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 275 down requires the exact verified migration head' USING ERRCODE='P2750';
    END IF;
    IF EXISTS (SELECT 1 FROM node_line_endpoint_display_ids) THEN
        RAISE EXCEPTION 'migration 275 down refuses to discard endpoint display IDs' USING ERRCODE='P2752';
    END IF;
END;
$migration_275_down$;

DROP TRIGGER node_line_endpoints_assign_display_id_275 ON node_line_endpoints;
DROP FUNCTION assign_node_line_endpoint_display_id_275();
DROP TABLE node_line_endpoint_display_ids;
DROP FUNCTION protect_node_line_endpoint_display_ids_275();
