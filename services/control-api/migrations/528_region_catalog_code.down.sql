LOCK TABLE schema_migrations, region_catalog, node_ssh_install_jobs, edge_node_network_marks IN ACCESS EXCLUSIVE MODE;

DO $migration_528_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 528 OR
       (SELECT max(version) FROM schema_migrations) <> 528 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=528 AND
        migration_id='528_region_catalog_code' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 528 down requires the exact verified migration head' USING ERRCODE='P5282';
    END IF;
END;
$migration_528_down$;

ALTER TABLE edge_node_network_marks DROP COLUMN regions_sha256;

ALTER TABLE node_ssh_install_jobs
    ADD COLUMN node_region text NOT NULL DEFAULT 'default' CHECK (node_region ~ '^[a-z0-9][a-z0-9-]{0,62}$');

DROP TRIGGER region_catalog_code_528 ON region_catalog;
DROP FUNCTION assign_region_catalog_code_528();
ALTER TABLE region_catalog DROP COLUMN code;
DROP FUNCTION region_catalog_code_528(uuid, text, bigint);
