LOCK TABLE schema_migrations,
    analytics_history_recoveries,
    analytics_ingest_receipts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 98 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 98 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=98 AND migration_id='098_analytics_ingest_history_authority'
          AND checksum_sha256='7e1ec92c377a0486ec2551334150d99ea58a61a0bc27b18054e8b33b23989102'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=97 AND migration_id='097_upgrade_license_receipt_delivery'
          AND checksum_sha256='38e154e329fb72b2664c84b777fbe63b9ba299e1a73397e7f7fddbc9a7bddd11'
          AND down_checksum_sha256='2a741f9196025c13982a0cba09091e6dc70f2903d374caae3593e178c14b6552'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 098 rollback requires the exact verified 098 head'
            USING ERRCODE = 'P9800';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_ingest_receipts) OR
       EXISTS (SELECT 1 FROM analytics_history_recoveries) THEN
        RAISE EXCEPTION 'migration 098 rollback would discard analytics ingest history facts'
            USING ERRCODE = 'P9801';
    END IF;
END;
$$;

DROP TRIGGER analytics_history_recoveries_truncate_guard_098 ON analytics_history_recoveries;
DROP TRIGGER analytics_history_recoveries_delete_guard_098 ON analytics_history_recoveries;
DROP TRIGGER analytics_history_recoveries_guard_098 ON analytics_history_recoveries;
DROP TRIGGER analytics_ingest_receipts_truncate_guard_098 ON analytics_ingest_receipts;
DROP TRIGGER analytics_ingest_receipts_delete_guard_098 ON analytics_ingest_receipts;
DROP TRIGGER analytics_ingest_receipts_guard_098 ON analytics_ingest_receipts;

DROP FUNCTION analytics_history_complete_recovery_098(uuid,uuid,timestamptz);
DROP FUNCTION analytics_history_reconcile_recovery_098(uuid,uuid,numeric,numeric,timestamptz);
DROP FUNCTION analytics_history_claim_recovery_098(uuid,text,uuid,timestamptz,timestamptz);
DROP FUNCTION analytics_history_schedule_recovery_098(uuid,text,timestamptz);
DROP FUNCTION prevent_analytics_history_recovery_truncate_098();
DROP FUNCTION prevent_analytics_history_recovery_delete_098();
DROP FUNCTION guard_analytics_history_recovery_098();
DROP FUNCTION analytics_ingest_mark_broker_ack_observed_098(uuid,numeric,bytea,timestamptz);
DROP FUNCTION analytics_ingest_mark_prepared_098(uuid,numeric,bytea,timestamptz);
DROP FUNCTION prevent_analytics_ingest_receipt_truncate_098();
DROP FUNCTION prevent_analytics_ingest_receipt_delete_098();
DROP FUNCTION guard_analytics_ingest_receipt_098();

DROP TABLE analytics_history_recoveries;
DROP TABLE analytics_ingest_receipts;
