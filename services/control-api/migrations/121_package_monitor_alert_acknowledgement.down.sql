LOCK TABLE schema_migrations,
    package_monitor_alert_acknowledgement_receipts,
    package_monitor_alert_acknowledgement_facts,
    package_monitor_alert_acknowledgement_heads
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 121 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 121 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=121 AND migration_id='121_package_monitor_alert_acknowledgement'
          AND checksum_sha256='b0b22d4317e5e250bee2a9734bab7028d0a0438cc78c54a5b1a0fc7f62633a6f'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 121 rollback requires the exact verified 121 release head'
            USING ERRCODE='P1210';
    END IF;
    IF EXISTS (SELECT 1 FROM package_monitor_alert_acknowledgement_facts) OR
       EXISTS (SELECT 1 FROM package_monitor_alert_acknowledgement_heads) OR
       EXISTS (SELECT 1 FROM package_monitor_alert_acknowledgement_receipts WHERE completed_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 121 rollback would discard package monitor alert acknowledgement facts'
            USING ERRCODE='P1212';
    END IF;
END;
$$;

DROP TRIGGER package_monitor_alert_acknowledgement_audit_validate_121 ON package_monitor_alert_acknowledgement_facts;
DROP FUNCTION validate_package_monitor_alert_acknowledgement_audit_121();
DROP TRIGGER package_monitor_alert_acknowledgement_heads_validate_121 ON package_monitor_alert_acknowledgement_heads;
DROP FUNCTION validate_package_monitor_alert_acknowledgement_head_121();
DROP TRIGGER package_monitor_alert_acknowledgement_facts_validate_121 ON package_monitor_alert_acknowledgement_facts;
DROP FUNCTION validate_package_monitor_alert_acknowledgement_fact_121();
DROP TRIGGER package_monitor_alert_acknowledgement_receipts_protect_121 ON package_monitor_alert_acknowledgement_receipts;
DROP FUNCTION protect_package_monitor_alert_acknowledgement_receipt_121();
DROP TRIGGER package_monitor_alert_acknowledgement_facts_no_truncate_121 ON package_monitor_alert_acknowledgement_facts;
DROP TRIGGER package_monitor_alert_acknowledgement_facts_append_only_121 ON package_monitor_alert_acknowledgement_facts;
DROP FUNCTION protect_package_monitor_alert_acknowledgement_fact_121();
DROP TABLE package_monitor_alert_acknowledgement_heads;
DROP TABLE package_monitor_alert_acknowledgement_facts;
DROP TABLE package_monitor_alert_acknowledgement_receipts;
