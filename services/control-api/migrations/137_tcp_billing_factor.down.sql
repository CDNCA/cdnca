-- migration 137 rollback requires the exact verified 137 head
LOCK TABLE schema_migrations, tcp_billing_factor_revisions, tcp_billing_cycle_settlements,
    tcp_billing_adjustments, tcp_billing_write_receipts, permissions, role_permissions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_137$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 137 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 137 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 137 AND migration_id = '137_tcp_billing_factor' AND
              checksum_sha256 = '741cabd2ca7d32915d7c2a5e13f42a75ccd9888f3662be8f572cacd3b6d7a4df' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 136 AND migration_id = '136_site_protocol_batch' AND
              checksum_sha256 = 'f73cf9d49c0da51b31186cadfa57bb68438041fe5af2289d66d85a8f19b38ccb' AND
              down_checksum_sha256 = 'dd787a88f25e0594a9daa8a687224ce464fa67d0b91c8cb5c6ecb0d2206000f1' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 137 rollback requires the exact verified 137 head'
            USING ERRCODE = 'P1376';
    END IF;
END;
$migration_137$;

DROP TRIGGER tcp_billing_write_receipts_no_truncate_137 ON tcp_billing_write_receipts;
DROP TRIGGER tcp_billing_write_receipts_immutable_137 ON tcp_billing_write_receipts;
DROP TRIGGER tcp_billing_adjustments_no_truncate_137 ON tcp_billing_adjustments;
DROP TRIGGER tcp_billing_adjustments_immutable_137 ON tcp_billing_adjustments;
DROP TRIGGER tcp_billing_settlements_no_truncate_137 ON tcp_billing_cycle_settlements;
DROP TRIGGER tcp_billing_settlements_immutable_137 ON tcp_billing_cycle_settlements;
DROP TRIGGER tcp_billing_factor_revisions_no_truncate_137 ON tcp_billing_factor_revisions;
DROP TRIGGER tcp_billing_factor_revisions_immutable_137 ON tcp_billing_factor_revisions;
DROP TRIGGER tcp_billing_adjustment_balance_137 ON tcp_billing_adjustments;

DROP FUNCTION prevent_tcp_billing_fact_mutation_137();
DROP FUNCTION enforce_tcp_billing_adjustment_balance_137();

DROP TABLE tcp_billing_write_receipts;
DROP TABLE tcp_billing_adjustments;
DROP TABLE tcp_billing_cycle_settlements;
DROP TABLE tcp_billing_factor_revisions;

DELETE FROM role_permissions WHERE permission_name IN (
    'tcp_billing.read','tcp_billing.manage','tcp_billing.settle','tcp_billing.adjust'
);
DELETE FROM permissions WHERE name IN (
    'tcp_billing.read','tcp_billing.manage','tcp_billing.settle','tcp_billing.adjust'
);
