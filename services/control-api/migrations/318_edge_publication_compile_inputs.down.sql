LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_318_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 318 OR
       (SELECT max(version) FROM schema_migrations) <> 318 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=318 AND
        migration_id='318_edge_publication_compile_inputs' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 318 down requires the exact verified migration head' USING ERRCODE='P3182';
    END IF;
    IF EXISTS (SELECT 1 FROM edge_publication_compile_inputs) THEN
        RAISE EXCEPTION 'migration 318 rollback would drop publication compile inputs' USING ERRCODE='P3182';
    END IF;
END;
$migration_318_down$;

DROP TABLE edge_publication_compile_inputs;
DROP FUNCTION protect_edge_publication_compile_inputs_318();
