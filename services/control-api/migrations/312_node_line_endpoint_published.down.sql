LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_312_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 312 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 312 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=312 AND
        migration_id='312_node_line_endpoint_published' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 312 down requires the exact verified migration head' USING ERRCODE='P3121';
    END IF;
END;
$migration_312_down$;

DROP VIEW node_line_endpoint_published;
