LOCK TABLE schema_migrations, permissions, roles, role_permissions, payment_channels,
    payment_channel_write_requests, payment_channel_reconcile_schedule IN ACCESS EXCLUSIVE MODE;

DO $migration_298_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 298 OR
       (SELECT max(version) FROM schema_migrations) <> 298 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=298 AND
        migration_id='298_payment_channels' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 298 down requires the exact verified migration head' USING ERRCODE='P2981';
    END IF;
    -- Configured credentials and pending compensation must not be dropped
    -- silently; the operator disables and removes them first.
    IF EXISTS (SELECT 1 FROM payment_channels) OR
       EXISTS (SELECT 1 FROM payment_channel_reconcile_schedule WHERE state = 'pending') THEN
        RAISE EXCEPTION 'migration 298 rollback would discard payment channels or pending compensation'
            USING ERRCODE='P2981';
    END IF;
END;
$migration_298_down$;

-- Restore the 051 function body exactly.
CREATE OR REPLACE FUNCTION assert_package_commercial_transaction()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE original_target uuid;
DECLARE original_currency text;
DECLARE original_order uuid;
DECLARE original_amount bigint;
DECLARE original_operation text;
DECLARE reversal_total numeric;
DECLARE order_tenant uuid;
DECLARE order_currency text;
DECLARE order_amount bigint;
BEGIN
    IF NEW.operation = 'manual_adjustment' THEN
        RETURN NULL;
    END IF;
    SELECT tenant_scope_id, currency, payable_amount_minor
    INTO order_tenant, order_currency, order_amount
    FROM package_orders WHERE id = NEW.commercial_order_id;
    IF order_tenant IS DISTINCT FROM NEW.target_scope_id
       OR order_currency IS DISTINCT FROM NEW.currency
       OR (NEW.operation <> 'package_refund' AND NEW.operation <> 'package_void'
           AND NEW.amount_minor <> order_amount) THEN
        RAISE EXCEPTION 'commercial billing transaction does not match order';
    END IF;
    IF NEW.operation IN ('package_refund', 'package_void') THEN
        SELECT target_scope_id, currency, commercial_order_id, amount_minor, operation
        INTO original_target, original_currency, original_order, original_amount, original_operation
        FROM billing_transactions WHERE id = NEW.reverses_transaction_id;
        IF original_operation NOT IN ('package_purchase', 'package_renewal', 'package_upgrade',
                                      'package_downgrade', 'traffic_package_purchase')
           OR original_target IS DISTINCT FROM NEW.target_scope_id
           OR original_currency IS DISTINCT FROM NEW.currency
           OR original_order IS DISTINCT FROM NEW.commercial_order_id THEN
            RAISE EXCEPTION 'commercial reversal does not match original sale';
        END IF;
        SELECT COALESCE(sum(amount_minor::numeric), 0)
        INTO reversal_total FROM billing_transactions
        WHERE reverses_transaction_id = NEW.reverses_transaction_id;
        IF reversal_total > original_amount
           OR (NEW.operation = 'package_void' AND
               (reversal_total <> original_amount OR
                (SELECT count(*) FROM billing_transactions
                 WHERE reverses_transaction_id = NEW.reverses_transaction_id) <> 1)) THEN
            RAISE EXCEPTION 'commercial reversal exceeds original sale';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

DROP TABLE payment_channel_reconcile_schedule;
DROP TABLE payment_channel_write_requests;
DROP TABLE payment_channels;

DELETE FROM role_permissions WHERE permission_name = 'billing.payment_channels.manage';
DELETE FROM permissions WHERE name = 'billing.payment_channels.manage';
