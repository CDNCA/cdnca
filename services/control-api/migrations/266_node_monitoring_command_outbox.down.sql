LOCK TABLE schema_migrations, node_monitoring_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_266_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 266 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 266 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 266 AND migration_id = '266_node_monitoring_command_outbox' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 266 rollback requires the exact verified 266 release head'
            USING ERRCODE = 'P2661';
    END IF;
    IF EXISTS (SELECT 1 FROM node_monitoring_command_outbox) THEN
        RAISE EXCEPTION 'migration 266 rollback would discard node monitoring command facts'
            USING ERRCODE = 'P2662';
    END IF;
END;
$migration_266_down$;

DROP TRIGGER node_monitoring_command_outbox_append_only ON node_monitoring_command_outbox;
DROP FUNCTION protect_node_monitoring_command_outbox();
DROP TABLE node_monitoring_command_outbox;
