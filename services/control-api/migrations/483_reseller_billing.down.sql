LOCK TABLE schema_migrations, package_orders, billing_transactions, billing_accounts, reseller_profiles,
    package_order_fulfillments, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_483_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 483 OR
       (SELECT max(version) FROM schema_migrations) <> 483 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=483 AND
        migration_id='483_reseller_billing' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 483 down requires the exact verified migration head' USING ERRCODE='P4836';
    END IF;
    -- 482 及以前的账本没有代理商这一边：已有代理商账或代理商单时拒绝回退，而不是丢账。
    IF EXISTS (SELECT 1 FROM billing_transactions WHERE operation IN ('reseller_sale','reseller_wholesale')) OR
       EXISTS (SELECT 1 FROM package_orders WHERE seller_scope_id <> package_catalog_platform_scope_481()
               OR funding_source = 'reseller') THEN
        RAISE EXCEPTION 'migration 483 down refuses to drop reseller ledger rows' USING ERRCODE='P4837';
    END IF;
END;
$migration_483_down$;

DELETE FROM notification_subscriptions WHERE event_type = 'reseller.prepaid.low_balance';
DELETE FROM admin_inbox_messages WHERE event_type = 'reseller.prepaid.low_balance';
ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id = 'reseller.prepaid.low_balance.zh-cn' AND version = 1;
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_event_policies WHERE event_type = 'reseller.prepaid.low_balance';

DROP TRIGGER package_order_fulfillments_reseller_483 ON package_order_fulfillments;
DROP FUNCTION assert_reseller_order_complete_483();
DROP TRIGGER billing_transactions_reseller_483 ON billing_transactions;
DROP FUNCTION assert_reseller_transaction_483();
DROP TRIGGER package_orders_seller_483 ON package_orders;
DROP FUNCTION guard_package_order_seller_483();
DROP FUNCTION reseller_wholesale_minor_483(uuid, jsonb, text);

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
    -- Recharge ledger rows are bound to their order by
    -- billing_transactions_recharge_event_fk_152 and the commerce shape check;
    -- they have no package order (298). Migration import credits are bound to
    -- their approved migrate_import_balance_credits row (446).
    IF NEW.operation IN ('manual_adjustment', 'recharge_payment', 'recharge_refund', 'recharge_void',
                         'migrate_import_credit') THEN
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

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase',
        'recharge_payment','recharge_refund','recharge_void',
        'migrate_import_credit'
    ));
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK(
        (operation='manual_adjustment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL)
        OR (operation='provider_payment' AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NOT NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND direction='credit')
        OR (operation IN ('package_purchase','package_renewal','package_upgrade','package_downgrade','traffic_package_purchase')
            AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL)
        OR (operation IN ('package_refund','package_void') AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NOT NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND direction='credit')
        OR (operation='recharge_payment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL AND recharge_provider_event_id IS NOT NULL AND direction='credit')
        OR (operation IN ('recharge_refund','recharge_void') AND commercial_order_id IS NULL
            AND reverses_transaction_id IS NOT NULL AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL
            AND recharge_provider_event_id IS NOT NULL AND direction='debit')
        OR (operation='migrate_import_credit' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL
            AND adjustment_request_id IS NULL AND direction='credit')
    );

DROP TRIGGER reseller_profiles_prepaid_483 ON reseller_profiles;
DROP FUNCTION bind_reseller_prepaid_account_483();
ALTER TABLE reseller_profiles DROP CONSTRAINT reseller_profiles_prepaid_account_483;
ALTER TABLE reseller_profiles ALTER COLUMN prepaid_account_id DROP NOT NULL;
ALTER TABLE reseller_profiles DISABLE TRIGGER USER;
UPDATE reseller_profiles SET prepaid_account_id = NULL;
ALTER TABLE reseller_profiles ENABLE TRIGGER USER;

DROP INDEX package_orders_seller_483_idx;
ALTER TABLE package_orders DROP CONSTRAINT package_orders_funding_source_check;
ALTER TABLE package_orders ADD CONSTRAINT package_orders_funding_source_check
    CHECK (funding_source IN ('balance', 'provider'));
ALTER TABLE package_orders DROP COLUMN wholesale_minor;
ALTER TABLE package_orders DROP COLUMN seller_scope_id;
