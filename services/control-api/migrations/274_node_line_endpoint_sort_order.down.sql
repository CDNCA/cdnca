LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_274_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 274 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 274 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=274 AND
        migration_id='274_node_line_endpoint_sort_order' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 274 down requires the exact verified migration head' USING ERRCODE='P2741';
    END IF;
    IF EXISTS (SELECT 1 FROM node_line_endpoints WHERE sort_order <> 100) THEN
        RAISE EXCEPTION 'migration 274 down refuses to discard endpoint sort values' USING ERRCODE='P2742';
    END IF;
END;
$migration_274_down$;

DROP INDEX node_line_endpoints_sort_274_idx;
ALTER TABLE node_line_endpoints
    DROP CONSTRAINT node_line_endpoints_sort_order_274_check,
    DROP COLUMN sort_order;
