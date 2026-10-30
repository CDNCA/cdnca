LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_267_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 266 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 266 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 266 AND migration_id = '266_node_monitoring_command_outbox' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 267 requires the exact verified 266 release head'
            USING ERRCODE = 'P2670';
    END IF;
END;
$migration_267_up$;

GRANT SELECT, INSERT, UPDATE ON node_monitoring_command_outbox TO cdnca_control_runtime;
GRANT EXECUTE ON FUNCTION protect_node_monitoring_command_outbox() TO cdnca_control_runtime;
