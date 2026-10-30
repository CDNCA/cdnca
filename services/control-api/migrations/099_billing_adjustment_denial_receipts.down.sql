LOCK TABLE schema_migrations,
    billing_adjustment_denial_receipts,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 99 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 99 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=99 AND migration_id='099_billing_adjustment_denial_receipts'
          AND checksum_sha256='ec616f2b6851956945ef67a4940e09051470b8e30431efee188034592692dc1a'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=98 AND migration_id='098_analytics_ingest_history_authority'
          AND checksum_sha256='7e1ec92c377a0486ec2551334150d99ea58a61a0bc27b18054e8b33b23989102'
          AND down_checksum_sha256='4a475ca2db6eb6aeb8e79883fa3f26345314a3331e5319d5fbbe7140f2e969cc'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 099 rollback requires the exact verified 099 head'
            USING ERRCODE = 'P9900';
    END IF;
    IF EXISTS (SELECT 1 FROM billing_adjustment_denial_receipts) OR EXISTS (
        SELECT 1 FROM audit_events
        WHERE result='denied' AND actor_user_id IS NOT NULL
          AND action='billing.adjustment.create'
    ) THEN
        RAISE EXCEPTION 'migration 099 rollback would discard billing adjustment denial facts'
            USING ERRCODE = 'P9901';
    END IF;
END;
$$;

DROP INDEX audit_events_billing_adjustment_denied_identity_099;
DROP TRIGGER billing_adjustment_denial_receipts_no_truncate_099
    ON billing_adjustment_denial_receipts;
DROP TRIGGER billing_adjustment_denial_receipts_immutable_099
    ON billing_adjustment_denial_receipts;
DROP FUNCTION prevent_billing_adjustment_denial_receipt_mutation_099();
DROP TABLE billing_adjustment_denial_receipts;
