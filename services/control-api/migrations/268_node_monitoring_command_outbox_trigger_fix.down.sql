LOCK TABLE schema_migrations, node_monitoring_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_268_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 268 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 268 OR
       NOT EXISTS (
        SELECT 1
        FROM schema_migrations
        WHERE version = 268 AND migration_id = '268_node_monitoring_command_outbox_trigger_fix' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 268 rollback requires the exact verified 268 release head'
            USING ERRCODE = 'P2681';
    END IF;
    RAISE EXCEPTION 'migration 268 rollback is blocked to retain the corrected node monitoring outbox trigger'
        USING ERRCODE = 'P2682';
END;
$migration_268_down$;
