LOCK TABLE schema_migrations,control_upgrade_status_receipts IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 102 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 102 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=102 AND migration_id='102_upgrade_status_puback_identity'
          AND checksum_sha256='1350b63f8f7ae54dccee84aeaee13b1923704c6fab61e8c2d1ddf91e79b79700'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regprocedure(format('%I.%I()',current_schema(),
        'validate_control_upgrade_status_puback_identity_102')) IS NULL THEN
        RAISE EXCEPTION 'migration 102 rollback requires the exact verified 102 head'
            USING ERRCODE='P1020';
    END IF;
    IF EXISTS (
        SELECT 1 FROM control_upgrade_status_receipts
        WHERE delivery_stream IS NOT NULL OR delivery_consumer IS NOT NULL OR delivery_sequence IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'status PubAck delivery facts exist; rollback is unsafe'
            USING ERRCODE='P1021';
    END IF;
END;
$$;

DROP TRIGGER control_upgrade_status_puback_identity_102 ON control_upgrade_status_receipts;
DROP FUNCTION validate_control_upgrade_status_puback_identity_102();

ALTER TABLE control_upgrade_status_receipts
    DROP CONSTRAINT control_upgrade_status_receipts_delivery_102_uk,
    DROP CONSTRAINT control_upgrade_status_receipts_delivery_shape_102,
    DROP COLUMN delivery_sequence,
    DROP COLUMN delivery_consumer,
    DROP COLUMN delivery_stream;
