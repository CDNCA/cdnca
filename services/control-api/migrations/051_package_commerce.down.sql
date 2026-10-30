LOCK TABLE package_orders, payment_callback_events, package_commerce_outbox,
    billing_transactions, traffic_package_grants, package_subscription_versions
    IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM package_orders)
       OR EXISTS (SELECT 1 FROM payment_callback_events)
       OR EXISTS (SELECT 1 FROM package_commerce_outbox)
       OR EXISTS (SELECT 1 FROM billing_transactions WHERE commercial_order_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM traffic_package_grants WHERE commerce_order_id IS NOT NULL)
       OR EXISTS (SELECT 1 FROM package_subscription_versions WHERE order_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 051 rollback requires commerce facts to be archived and absent';
    END IF;
END;
$$;

DROP TRIGGER package_commerce_write_requests_no_truncate ON package_commerce_write_requests;
DROP TRIGGER package_commerce_write_requests_protect ON package_commerce_write_requests;
DROP TRIGGER package_commerce_manual_approvals_validate ON package_commerce_manual_approvals;
DROP TRIGGER package_balance_hold_events_validate ON package_balance_hold_events;
DROP TRIGGER traffic_package_grants_commerce_valid ON traffic_package_grants;
DROP TRIGGER package_subscriptions_revision_fact ON package_subscriptions;
DROP TRIGGER package_entitlement_versions_validate ON package_subscription_entitlement_versions;
DROP TRIGGER billing_transactions_commercial_valid ON billing_transactions;
DROP TRIGGER package_order_events_audited ON package_order_events;
DROP TRIGGER package_order_events_validate ON package_order_events;

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'package_orders', 'package_order_events', 'package_payment_attempts',
        'payment_callback_events', 'package_balance_holds', 'package_balance_hold_events',
        'package_order_fulfillments', 'package_subscription_entitlement_versions',
        'package_commerce_manual_approvals', 'package_commerce_approval_uses',
        'package_commerce_outbox'
    ] LOOP
        EXECUTE format('DROP TRIGGER %I_no_truncate ON %I', table_name, table_name);
        EXECUTE format('DROP TRIGGER %I_append_only ON %I', table_name, table_name);
    END LOOP;
END;
$$;

ALTER TABLE promotion_adjustment_decisions DROP COLUMN billing_transaction_id;

ALTER TABLE traffic_package_grants DROP CONSTRAINT traffic_package_grants_commerce_pair;
ALTER TABLE traffic_package_grants DROP COLUMN commerce_order_id;
ALTER TABLE traffic_package_grants DROP COLUMN billing_transaction_id;

ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_entitlement_fk;
ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_commerce_shape;
ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_operation_check;
ALTER TABLE package_subscription_versions DROP COLUMN entitlement_revision;
ALTER TABLE package_subscription_versions DROP COLUMN order_id;
ALTER TABLE package_subscription_versions
    ADD CONSTRAINT package_subscription_versions_operation_check
    CHECK (operation IN ('open', 'renew', 'cancel'));

DROP TABLE package_commerce_outbox;
DROP TABLE package_commerce_approval_uses;
DROP TABLE package_commerce_manual_approvals;
DROP TABLE package_commerce_write_requests;
DROP FUNCTION package_subscription_effective_entitlement_revision(uuid, timestamptz);
DROP TABLE package_subscription_entitlement_versions;
DROP TABLE package_order_fulfillments;
DROP TABLE package_balance_hold_events;
DROP TABLE package_balance_holds;

DROP INDEX billing_transactions_reversal_idx;
DROP INDEX billing_transactions_commercial_order_idx;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP COLUMN payment_attempt_id;
ALTER TABLE billing_transactions DROP COLUMN reverses_transaction_id;
ALTER TABLE billing_transactions DROP COLUMN commercial_order_id;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK (operation = 'manual_adjustment');

DROP TABLE payment_callback_events;
DROP TABLE package_payment_attempts;
DROP TABLE package_order_events;
DROP TABLE package_orders;

DROP FUNCTION assert_package_commerce_manual_approval();
DROP FUNCTION validate_package_balance_hold_event();
DROP FUNCTION assert_traffic_package_commerce_grant();
DROP FUNCTION assert_package_subscription_revision_fact();
DROP FUNCTION validate_package_entitlement_version();
DROP FUNCTION assert_package_commercial_transaction();
DROP FUNCTION assert_package_order_event_audited();
DROP FUNCTION validate_package_order_event();
DROP FUNCTION protect_package_commerce_write_request();
DROP FUNCTION prevent_package_commerce_fact_mutation();

CREATE OR REPLACE FUNCTION protect_package_subscription_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.product_id IS DISTINCT FROM OLD.product_id
       OR NEW.product_revision IS DISTINCT FROM OLD.product_revision
       OR NEW.product_snapshot IS DISTINCT FROM OLD.product_snapshot
       OR NEW.site_limit IS DISTINCT FROM OLD.site_limit
       OR NEW.domain_limit IS DISTINCT FROM OLD.domain_limit
       OR NEW.node_limit IS DISTINCT FROM OLD.node_limit
       OR NEW.traffic_limit_bytes IS DISTINCT FROM OLD.traffic_limit_bytes
       OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.cycle_kind IS DISTINCT FROM OLD.cycle_kind
       OR NEW.custom_cycle_days IS DISTINCT FROM OLD.custom_cycle_days
       OR NEW.tcp_factor_numerator IS DISTINCT FROM OLD.tcp_factor_numerator
       OR NEW.tcp_factor_denominator IS DISTINCT FROM OLD.tcp_factor_denominator
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package subscription snapshot is immutable';
    END IF;
    IF OLD.lifecycle_status = 'cancelled' THEN
        RAISE EXCEPTION 'cancelled package subscription is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'package subscription revision must advance by one';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'package subscription updated_at cannot move backwards';
    END IF;
    IF NEW.lifecycle_status = 'active' THEN
        IF NEW.ends_at <= OLD.ends_at OR NEW.cancelled_at IS NOT NULL THEN
            RAISE EXCEPTION 'active package subscription renewal must strictly extend ends_at';
        END IF;
    ELSIF NEW.lifecycle_status = 'cancelled' THEN
        IF NEW.ends_at IS DISTINCT FROM OLD.ends_at
           OR NEW.cancelled_at IS DISTINCT FROM NEW.updated_at
           OR NEW.cancelled_at < OLD.updated_at THEN
            RAISE EXCEPTION 'package subscription cancellation facts are invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid package subscription lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_traffic_package_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'traffic package grants cannot be deleted';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.bucket_id IS DISTINCT FROM OLD.bucket_id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.currency IS DISTINCT FROM OLD.currency
       OR NEW.metering_scope IS DISTINCT FROM OLD.metering_scope
       OR NEW.metering_version IS DISTINCT FROM OLD.metering_version
       OR NEW.product_snapshot_id IS DISTINCT FROM OLD.product_snapshot_id
       OR NEW.product_snapshot IS DISTINCT FROM OLD.product_snapshot
       OR NEW.granted_bytes IS DISTINCT FROM OLD.granted_bytes
       OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
       OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
       OR NEW.expiry_timezone IS DISTINCT FROM OLD.expiry_timezone
       OR NEW.priority IS DISTINCT FROM OLD.priority
       OR NEW.price_minor IS DISTINCT FROM OLD.price_minor
       OR NEW.external_ledger_reference IS DISTINCT FROM OLD.external_ledger_reference
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_by_scope_id IS DISTINCT FROM OLD.created_by_scope_id
       OR NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.trace_id IS DISTINCT FROM OLD.trace_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'traffic package grant snapshot is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'traffic package grant revision must advance by one';
    END IF;
    RETURN NEW;
END;
$$;
