LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_649_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 649 OR
       (SELECT max(version) FROM schema_migrations) <> 649 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=649 AND
        migration_id='649_edge_publication_left_out_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 649 down requires the exact verified migration head' USING ERRCODE='P6491';
    END IF;
END;
$migration_649_down$;

-- The same facts stay in each publication audit (key_envelope_oversized_nodes,
-- site_selection_unsupported_nodes); only the publication list loses them.
ALTER TABLE edge_config_publications
    DROP COLUMN site_selection_unsupported_node_ids,
    DROP COLUMN key_envelope_oversized_node_ids;
