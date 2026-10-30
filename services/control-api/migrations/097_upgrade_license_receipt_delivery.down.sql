LOCK TABLE schema_migrations,
    control_upgrade_license_receipt_outbox_097,
    control_upgrade_license_receipt_deliveries_097,
    control_upgrade_rollout_plans
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 97 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 97 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=97 AND migration_id='097_upgrade_license_receipt_delivery'
          AND checksum_sha256='38e154e329fb72b2664c84b777fbe63b9ba299e1a73397e7f7fddbc9a7bddd11'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 097 rollback requires the exact verified 097 head'
            USING ERRCODE = 'P9700';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=96 AND migration_id='096_upgrade_runtime_control'
          AND checksum_sha256='5f6cbeaec3ea9d0e0b59861516575147a6b897022c5f25d911c115976d72214f'
          AND down_checksum_sha256='3f1302b42bbe9a841da0892a989422d661407a381a1052522634ed0335f3eac4'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 097 rollback requires the exact verified 096 parent'
            USING ERRCODE = 'P9700';
    END IF;
    IF EXISTS (SELECT 1 FROM control_upgrade_license_receipt_outbox_097) OR
       EXISTS (SELECT 1 FROM control_upgrade_license_receipt_deliveries_097) THEN
        RAISE EXCEPTION 'migration 097 rollback would discard License receipt delivery facts'
            USING ERRCODE = 'P9701';
    END IF;
END;
$$;

DROP TRIGGER control_upgrade_license_receipt_delivery_fact_097
    ON control_upgrade_license_receipt_deliveries_097;
DROP TRIGGER control_upgrade_license_receipt_delivered_097
    ON control_upgrade_license_receipt_outbox_097;
DROP TRIGGER control_upgrade_license_receipt_delivery_no_truncate_097
    ON control_upgrade_license_receipt_deliveries_097;
DROP TRIGGER control_upgrade_license_receipt_outbox_no_truncate_097
    ON control_upgrade_license_receipt_outbox_097;
DROP TRIGGER control_upgrade_license_receipt_delivery_validate_097
    ON control_upgrade_license_receipt_deliveries_097;
DROP TRIGGER control_upgrade_license_receipt_outbox_validate_097
    ON control_upgrade_license_receipt_outbox_097;

DROP FUNCTION prevent_control_upgrade_license_receipt_truncate_097();
DROP FUNCTION enforce_control_upgrade_license_receipt_delivery_097();
DROP FUNCTION validate_control_upgrade_license_receipt_delivery_097();
DROP FUNCTION validate_control_upgrade_license_receipt_outbox_097();
DROP FUNCTION validate_control_upgrade_license_receipt_fact_097(control_upgrade_license_receipt_outbox_097);

DROP TABLE control_upgrade_license_receipt_deliveries_097;
DROP TABLE control_upgrade_license_receipt_outbox_097;

DROP FUNCTION control_upgrade_license_receipt_reason_097(bytea);
DROP FUNCTION control_upgrade_license_receipt_id_097(uuid,text);
DROP FUNCTION control_upgrade_license_receipt_digest_097(uuid,uuid,uuid,text,text,text,timestamptz);

ALTER TABLE control_upgrade_rollout_plans
    DROP CONSTRAINT control_upgrade_rollout_license_identity_097_uk;
