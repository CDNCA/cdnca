LOCK TABLE schema_migrations,control_upgrade_node_commands IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 101 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 101 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=101 AND migration_id='101_upgrade_dual_sequence'
          AND checksum_sha256='198238a302b07d49751543329dfa51361fecd6238ba7bc0ec59a8dd96c34cb18'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regprocedure(format('%I.%I()',current_schema(),'validate_control_upgrade_dual_sequence_101')) IS NULL THEN
        RAISE EXCEPTION 'migration 101 rollback requires the exact verified 101 head'
            USING ERRCODE='P1010';
    END IF;
    IF EXISTS (
        SELECT 1 FROM control_upgrade_node_commands
        WHERE command_schema IS NOT NULL OR execution_sequence IS NOT NULL OR
              release_sequence IS NOT NULL OR component IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'upgrade command v3 facts exist; rollback is unsafe'
            USING ERRCODE='P1011';
    END IF;
END;
$$;

DROP TRIGGER control_upgrade_dual_sequence_validate_101 ON control_upgrade_node_commands;
DROP FUNCTION validate_control_upgrade_dual_sequence_101();

ALTER TABLE control_upgrade_node_commands
    DROP CONSTRAINT control_upgrade_node_commands_execution_101_uk,
    DROP CONSTRAINT control_upgrade_node_commands_v3_shape_101,
    DROP COLUMN execution_sequence,
    DROP COLUMN release_sequence,
    DROP COLUMN command_schema,
    DROP COLUMN component;
