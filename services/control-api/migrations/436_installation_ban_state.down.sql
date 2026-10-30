LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_436_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 436 OR
       (SELECT max(version) FROM schema_migrations) <> 436 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=436 AND
        migration_id='436_installation_ban_state' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 436 down requires the exact verified migration head' USING ERRCODE='P4361';
    END IF;
END;
$migration_436_down$;

DROP TABLE installation_ban_node_state;
DROP TABLE control_installation_ban_state;
