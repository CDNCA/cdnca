LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_267_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 267 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 267 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 267 AND migration_id = '267_node_monitoring_command_outbox_privileges' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 267 rollback requires the exact verified 267 release head'
            USING ERRCODE = 'P2671';
    END IF;
END;
$migration_267_down$;

REVOKE EXECUTE ON FUNCTION protect_node_monitoring_command_outbox() FROM cdnca_control_runtime;
REVOKE SELECT, INSERT, UPDATE ON node_monitoring_command_outbox FROM cdnca_control_runtime;
