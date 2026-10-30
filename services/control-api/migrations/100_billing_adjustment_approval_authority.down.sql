LOCK TABLE schema_migrations,billing_adjustment_legacy_authority,
    billing_adjustment_requests,billing_adjustment_decisions,
    billing_adjustment_write_receipts,billing_transactions,audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 100 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 100 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=100 AND migration_id='100_billing_adjustment_approval_authority'
          AND checksum_sha256='1ee7685a1adeebc2d4aefea26e8f33b41e10409594b97550d508060a44cd05ad'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=99 AND migration_id='099_billing_adjustment_denial_receipts'
          AND checksum_sha256='ec616f2b6851956945ef67a4940e09051470b8e30431efee188034592692dc1a'
          AND down_checksum_sha256='0afc07827ca395c1b9393fc6cf606377f6979140177084be18621e2eb062d1b3'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 100 rollback requires the exact verified 100 head'
            USING ERRCODE='P1000';
    END IF;
    IF EXISTS(SELECT 1 FROM billing_adjustment_requests) OR
       EXISTS(SELECT 1 FROM billing_adjustment_decisions) OR
       EXISTS(SELECT 1 FROM billing_adjustment_write_receipts) OR
       EXISTS(SELECT 1 FROM billing_transactions WHERE adjustment_request_id IS NOT NULL) OR
       EXISTS(
        SELECT 1 FROM audit_events
        WHERE action IN ('billing.adjustment.propose','billing.adjustment.approve',
                         'billing.adjustment.reject','billing.adjustment.cancel')
       ) OR EXISTS(
        SELECT 1 FROM billing_adjustment_legacy_authority legacy
        JOIN billing_transactions transaction ON transaction.id=legacy.transaction_id
        WHERE transaction.operation<>'manual_adjustment'
           OR transaction.adjustment_request_id IS NOT NULL
           OR legacy.transaction_digest<>billing_adjustment_transaction_digest_100(transaction.id)
       ) OR EXISTS(
        SELECT 1 FROM billing_transactions transaction
        WHERE transaction.operation='manual_adjustment' AND NOT EXISTS(
            SELECT 1 FROM billing_adjustment_legacy_authority legacy
            WHERE legacy.transaction_id=transaction.id
              AND legacy.transaction_digest=billing_adjustment_transaction_digest_100(transaction.id)
        )
       ) THEN
        RAISE EXCEPTION 'migration 100 rollback would discard billing approval authority facts'
            USING ERRCODE='P1001';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        JOIN access_scopes scope ON scope.id=role.scope_id
        WHERE grant_row.permission_name IN ('billing.adjustments.propose','billing.adjustments.approve')
          AND NOT (scope.kind='platform' AND role.system_role AND role.name='platform_owner')
    ) THEN
        RAISE EXCEPTION 'migration 100 rollback would discard custom billing approval grants'
            USING ERRCODE='P1001';
    END IF;
END;
$$;

DROP TRIGGER billing_adjustment_receipts_audit_100 ON billing_adjustment_write_receipts;
DROP TRIGGER billing_adjustment_decisions_audit_100 ON billing_adjustment_decisions;
DROP TRIGGER billing_adjustment_requests_audit_100 ON billing_adjustment_requests;
DROP TRIGGER billing_adjustment_decisions_commit_100 ON billing_adjustment_decisions;
DROP TRIGGER billing_adjustment_transactions_commit_100 ON billing_transactions;
DROP TRIGGER billing_adjustment_receipts_no_truncate_100 ON billing_adjustment_write_receipts;
DROP TRIGGER billing_adjustment_decisions_no_truncate_100 ON billing_adjustment_decisions;
DROP TRIGGER billing_adjustment_requests_no_truncate_100 ON billing_adjustment_requests;
DROP TRIGGER billing_adjustment_legacy_no_truncate_100 ON billing_adjustment_legacy_authority;
DROP TRIGGER billing_adjustment_receipts_immutable_100 ON billing_adjustment_write_receipts;
DROP TRIGGER billing_adjustment_decisions_immutable_100 ON billing_adjustment_decisions;
DROP TRIGGER billing_adjustment_requests_immutable_100 ON billing_adjustment_requests;
DROP TRIGGER billing_adjustment_legacy_immutable_100 ON billing_adjustment_legacy_authority;
DROP TRIGGER billing_adjustment_decisions_validate_100 ON billing_adjustment_decisions;
DROP TRIGGER billing_adjustment_requests_validate_100 ON billing_adjustment_requests;
DROP TRIGGER billing_adjustment_legacy_validate_100 ON billing_adjustment_legacy_authority;

DROP FUNCTION validate_billing_adjustment_fact_audit_100();
DROP FUNCTION validate_billing_adjustment_commit_100();
DROP FUNCTION validate_billing_adjustment_decision_100();
DROP FUNCTION validate_billing_adjustment_request_100();
DROP FUNCTION validate_billing_adjustment_legacy_authority_100();
DROP FUNCTION prevent_billing_adjustment_authority_mutation_100();

DROP TABLE billing_adjustment_write_receipts;
DROP TABLE billing_adjustment_decisions;
ALTER TABLE billing_transactions
    DROP CONSTRAINT billing_transactions_adjustment_request_fk_100;
DROP TABLE billing_adjustment_requests;
DROP TABLE billing_adjustment_legacy_authority;
DROP FUNCTION billing_adjustment_transaction_digest_100(uuid);

ALTER TABLE billing_transactions
    DROP CONSTRAINT billing_transactions_adjustment_request_shape_100,
    DROP CONSTRAINT billing_transactions_adjustment_request_unique_100,
    DROP COLUMN adjustment_request_id;

DELETE FROM role_permissions
WHERE permission_name IN ('billing.adjustments.propose','billing.adjustments.approve');
DELETE FROM permissions
WHERE name IN ('billing.adjustments.propose','billing.adjustments.approve');
