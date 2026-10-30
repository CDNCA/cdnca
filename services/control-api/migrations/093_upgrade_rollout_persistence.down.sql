LOCK TABLE schema_migrations,
    control_upgrade_status_receipts,
    control_upgrade_outbox,
    control_upgrade_node_commands,
    control_upgrade_rollout_events,
    control_upgrade_rollout_plans
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 93 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 93 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 93
          AND migration_id = '093_upgrade_rollout_persistence'
          AND checksum_sha256 = '3614fd6c9d624f2e75ded822c2de8fe62940267c4a5e9b76340a37e428e319af'
          AND integrity_state = 'verified'
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 92
          AND migration_id = '092_l4_package_runtime_contract'
          AND checksum_sha256 = '5b9d6ced167be563e6dfdbe022681b7ed6842728a831597389a3a4e9280d8c6d'
          AND down_checksum_sha256 = '8cd70b1cf78f3ea668934b6db898a2c0d1a487bc4a85f05dd9585d4a66058bbc'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 093 rollback requires the verified 093 head'
            USING ERRCODE = 'P9300';
    END IF;
    IF EXISTS (SELECT 1 FROM control_upgrade_status_receipts) OR
       EXISTS (SELECT 1 FROM control_upgrade_outbox) OR
       EXISTS (SELECT 1 FROM control_upgrade_node_commands) OR
       EXISTS (SELECT 1 FROM control_upgrade_rollout_events) OR
       EXISTS (SELECT 1 FROM control_upgrade_rollout_plans) THEN
        RAISE EXCEPTION 'migration 093 rollback would discard upgrade rollout facts'
            USING ERRCODE = 'P9301';
    END IF;
END;
$$;

DROP TABLE control_upgrade_status_receipts;
DROP TABLE control_upgrade_outbox;
DROP TABLE control_upgrade_node_commands;
DROP TABLE control_upgrade_rollout_events;
DROP TABLE control_upgrade_rollout_plans;

DROP FUNCTION validate_control_upgrade_status_093();
DROP FUNCTION validate_control_upgrade_command_outbox_093();
DROP FUNCTION validate_control_upgrade_outbox_093();
DROP FUNCTION validate_control_upgrade_command_093();
DROP FUNCTION validate_control_upgrade_event_history_093();
DROP FUNCTION validate_control_upgrade_event_093();
DROP FUNCTION validate_control_upgrade_plan_093();
