LOCK TABLE schema_migrations,recharge_orders_v1,recharge_order_events_v1,
    recharge_provider_callbacks_v1,recharge_settlements_v1,recharge_statistics_facts_v1,
    recharge_write_receipts_v1,billing_transactions,auth_sessions,permissions,role_permissions
IN ACCESS EXCLUSIVE MODE;

DO $migration_133$
BEGIN
    IF (SELECT max(version) FROM schema_migrations)<>133 OR EXISTS(
        SELECT 1 FROM recharge_orders_v1 LIMIT 1
    ) OR EXISTS(SELECT 1 FROM recharge_order_events_v1 LIMIT 1)
      OR EXISTS(SELECT 1 FROM recharge_provider_callbacks_v1 LIMIT 1)
      OR EXISTS(SELECT 1 FROM recharge_settlements_v1 LIMIT 1)
      OR EXISTS(SELECT 1 FROM recharge_statistics_facts_v1 LIMIT 1)
      OR EXISTS(SELECT 1 FROM recharge_write_receipts_v1 LIMIT 1)
      OR EXISTS(SELECT 1 FROM billing_transactions WHERE recharge_order_id IS NOT NULL LIMIT 1) THEN
        RAISE EXCEPTION 'migration 133 rollback would discard billing recharge facts' USING ERRCODE='P1334';
    END IF;
END;
$migration_133$;

DROP TRIGGER recharge_statistics_reconciled_v1 ON recharge_statistics_facts_v1;
DROP TRIGGER recharge_settlements_reconciled_v1 ON recharge_settlements_v1;
DROP TRIGGER recharge_receipts_append_only_v1 ON recharge_write_receipts_v1;
DROP TRIGGER recharge_statistics_append_only_v1 ON recharge_statistics_facts_v1;
DROP TRIGGER recharge_settlements_append_only_v1 ON recharge_settlements_v1;
DROP TRIGGER recharge_callbacks_append_only_v1 ON recharge_provider_callbacks_v1;
DROP TRIGGER recharge_order_events_append_only_v1 ON recharge_order_events_v1;
DROP TRIGGER recharge_orders_head_guard_v1 ON recharge_orders_v1;

DROP FUNCTION validate_billing_recharge_reconciliation_133();
DROP FUNCTION prevent_billing_recharge_fact_mutation_133();
DROP FUNCTION guard_billing_recharge_order_head_133();

DROP TABLE recharge_write_receipts_v1;
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_recharge_receipt_identity_133;
DROP TABLE recharge_statistics_facts_v1;
DROP TABLE recharge_settlements_v1;

DROP INDEX billing_transactions_recharge_order_v1_idx;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_recharge_identity_133;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP COLUMN recharge_order_id;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal',
        'package_upgrade','package_downgrade','package_refund','package_void','traffic_package_purchase'
    )),
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK(
        (operation='manual_adjustment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL AND payment_attempt_id IS NULL)
        OR (operation='provider_payment' AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL AND payment_attempt_id IS NOT NULL AND direction='credit')
        OR (operation IN ('package_purchase','package_renewal','package_upgrade','package_downgrade','traffic_package_purchase')
            AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL)
        OR (operation IN ('package_refund','package_void') AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NOT NULL AND direction='credit')
    );

DROP TABLE recharge_provider_callbacks_v1;
DROP TABLE recharge_order_events_v1;
DROP TABLE recharge_orders_v1;

DELETE FROM role_permissions WHERE permission_name IN ('billing.recharges.create','billing.recharges.read','billing.recharges.manage');
DELETE FROM permissions WHERE name IN ('billing.recharges.create','billing.recharges.read','billing.recharges.manage');
