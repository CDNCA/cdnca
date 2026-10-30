LOCK TABLE schema_migrations, firewall_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 111 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 111 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=111 AND migration_id='111_firewall_command_outbox'
          AND checksum_sha256='dd1f37db9068df613adcb435ec46686b5d6a4e23593cb987ea67d1412a42d3e6'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=110 AND migration_id='110_traffic_package_product_lifecycle'
          AND checksum_sha256='e645c599cb1b1ffe3dfe0a53a5acdaa87d04d97518dbf19747aceef5d8dcf44b'
          AND down_checksum_sha256='0dc88fe739b7fa14378d70724a5a37a0cdb03b4ef1899baf8052d2773929f690'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 111 rollback requires the exact verified head' USING ERRCODE='P1110';
    END IF;
END;
$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM firewall_command_outbox) THEN
        RAISE EXCEPTION 'migration 111 rollback would discard firewall command facts' USING ERRCODE='P1111';
    END IF;
END;
$$;

DROP TRIGGER firewall_command_outbox_binding_valid ON firewall_command_outbox;
DROP FUNCTION validate_firewall_command_outbox_binding();
DROP TRIGGER firewall_command_outbox_mutation ON firewall_command_outbox;
DROP FUNCTION protect_firewall_command_outbox_mutation();
DROP TABLE firewall_command_outbox;
