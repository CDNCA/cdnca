LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_414_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 414 OR
       (SELECT max(version) FROM schema_migrations) <> 414 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=414 AND
        migration_id='414_autodefense_module_values' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 414 down requires the exact verified migration head' USING ERRCODE='P4141';
    END IF;
END;
$migration_414_down$;

-- Shown values only: nodes report them again on their next change.
DROP TABLE autodefense_module_values;
