LOCK TABLE schema_migrations, edge_publication_compile_inputs IN ACCESS EXCLUSIVE MODE;

DO $migration_325_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 325 OR
       (SELECT max(version) FROM schema_migrations) <> 325 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=325 AND
        migration_id='325_edge_publication_compile_inputs_v2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 325 down requires the exact verified migration head' USING ERRCODE='P3251';
    END IF;
    IF EXISTS (SELECT 1 FROM edge_publication_compile_inputs WHERE site_runtime_v2 IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 325 rollback would drop site runtime v2 compile inputs' USING ERRCODE='P3251';
    END IF;
END;
$migration_325_down$;

ALTER TABLE edge_publication_compile_inputs
    DROP CONSTRAINT edge_publication_compile_inputs_one_source_325,
    DROP COLUMN site_runtime_v2,
    ALTER COLUMN spec SET NOT NULL;
