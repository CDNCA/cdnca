-- 555（bb03）回退：订阅停用列与 suspend/unsuspend 操作、package_suspension trigger、代理商升降级守卫回到 483/538/261。
-- 已有停用/恢复事实、package_suspension 重发布或代理商升降级单时拒绝回退（前者无处安放，后者丢账）。
LOCK TABLE schema_migrations, package_subscriptions, package_subscription_versions,
    package_subscription_write_requests, package_orders, billing_transactions,
    edge_system_republication_heads, edge_system_republication_attempts, edge_system_revision_segments
    IN ACCESS EXCLUSIVE MODE;

DO $migration_555_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 555 OR
       (SELECT max(version) FROM schema_migrations) <> 555 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=555 AND
        migration_id='555_subscription_suspension_reseller_change' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 555 down requires the exact verified migration head' USING ERRCODE='P5551';
    END IF;
    IF EXISTS (SELECT 1 FROM package_subscription_versions WHERE operation IN ('suspend','unsuspend')) OR
       EXISTS (SELECT 1 FROM package_subscription_write_requests
               WHERE operation IN ('package.subscription.suspend','package.subscription.unsuspend')) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'package_suspension' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'package_suspension' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'package_suspension') OR
       EXISTS (SELECT 1 FROM package_orders WHERE operation IN ('upgrade','downgrade')
               AND seller_scope_id <> package_catalog_platform_scope_481()) THEN
        RAISE EXCEPTION 'migration 555 down: suspension or reseller change facts exist' USING ERRCODE='P5552';
    END IF;
END;
$migration_555_down$;

ALTER TABLE package_subscriptions DROP CONSTRAINT package_subscriptions_suspension_555_check,
    DROP COLUMN suspend_reason, DROP COLUMN suspended_at;
ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_operation_check,
    DROP CONSTRAINT package_subscription_versions_commerce_shape;
ALTER TABLE package_subscription_versions ADD CONSTRAINT package_subscription_versions_operation_check
 CHECK(operation IN ('open','renew','cancel','upgrade','downgrade','admin_edit','admin_enable','admin_disable','admin_delete')),
 ADD CONSTRAINT package_subscription_versions_commerce_shape CHECK(
 (operation IN ('open','cancel','admin_edit','admin_enable','admin_disable','admin_delete') AND order_id IS NULL AND entitlement_revision IS NULL)
 OR (operation='renew' AND ((order_id IS NULL AND entitlement_revision IS NULL) OR (order_id IS NOT NULL AND entitlement_revision IS NOT NULL)))
 OR (operation IN ('upgrade','downgrade') AND order_id IS NOT NULL AND entitlement_revision IS NOT NULL));
ALTER TABLE package_subscription_write_requests DROP CONSTRAINT package_subscription_write_requests_operation_check,
    ADD CONSTRAINT package_subscription_write_requests_operation_check CHECK (operation IN (
        'package.subscription.open', 'package.subscription.renew', 'package.subscription.cancel'));

CREATE OR REPLACE FUNCTION protect_package_subscription_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admin_operation text;
BEGIN
 SELECT operation INTO admin_operation FROM package_subscription_versions WHERE subscription_id=NEW.id AND revision=NEW.revision;
 IF admin_operation IN ('admin_edit','admin_enable','admin_disable','admin_delete') THEN
  IF OLD.deleted_at IS NOT NULL OR OLD.lifecycle_status<>'active' OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at
   OR NEW.id<>OLD.id OR NEW.tenant_scope_id<>OLD.tenant_scope_id OR NEW.product_id<>OLD.product_id OR NEW.product_revision<>OLD.product_revision
   OR NEW.site_limit<>OLD.site_limit OR NEW.node_limit<>OLD.node_limit OR NEW.starts_at<>OLD.starts_at OR NEW.timezone<>OLD.timezone
   OR NEW.cycle_kind<>OLD.cycle_kind OR NEW.custom_cycle_days<>OLD.custom_cycle_days
   OR NEW.tcp_factor_numerator<>OLD.tcp_factor_numerator OR NEW.tcp_factor_denominator<>OLD.tcp_factor_denominator
   OR NEW.created_by_user_id<>OLD.created_by_user_id OR NEW.created_at<>OLD.created_at OR NEW.lifecycle_status<>OLD.lifecycle_status
   OR NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at THEN
    RAISE EXCEPTION 'invalid sold package administrative transition';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM package_subscription_versions v WHERE v.subscription_id=NEW.id AND v.revision=NEW.revision
    AND (v.snapshot#>>'{sold,enabled}')::boolean=NEW.admin_enabled
    AND (v.snapshot#>>'{sold,deleted}')::boolean=(NEW.deleted_at IS NOT NULL)
    AND (v.snapshot#>>'{sold,ends_at}')::timestamptz=NEW.ends_at
    AND v.created_by_user_id=NEW.updated_by_user_id AND v.created_at=NEW.updated_at) THEN
    RAISE EXCEPTION 'sold package administrative snapshot does not match current row';
  END IF;
  IF admin_operation='admin_edit' THEN
   IF NOT EXISTS(SELECT 1 FROM package_subscription_versions v WHERE v.subscription_id=NEW.id AND v.revision=NEW.revision
    AND NEW.product_snapshot->'spec' @> (v.snapshot#>'{sold,config}')
    AND NEW.product_snapshot->>'name'=v.snapshot#>>'{sold,config,name}'
    AND NEW.domain_limit=(v.snapshot#>>'{sold,config,limits,domains}')::bigint
    AND NEW.traffic_limit_bytes=(v.snapshot#>>'{sold,config,limits,monthly_traffic_bytes}')::bigint) THEN
    RAISE EXCEPTION 'sold package config does not match administrative snapshot'; END IF;
   IF NEW.admin_enabled<>OLD.admin_enabled OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN RAISE EXCEPTION 'edit cannot change package status'; END IF;
  ELSIF NEW.product_snapshot<>OLD.product_snapshot OR NEW.domain_limit<>OLD.domain_limit OR NEW.traffic_limit_bytes<>OLD.traffic_limit_bytes OR NEW.ends_at<>OLD.ends_at THEN
   RAISE EXCEPTION 'status change cannot edit package snapshot';
  END IF;
  IF (admin_operation='admin_enable' AND (NOT NEW.admin_enabled OR NEW.deleted_at IS NOT NULL))
   OR (admin_operation='admin_disable' AND (NEW.admin_enabled OR NEW.deleted_at IS NOT NULL))
   OR (admin_operation='admin_delete' AND (NEW.admin_enabled OR NEW.deleted_at IS DISTINCT FROM NEW.updated_at)) THEN
   RAISE EXCEPTION 'invalid sold package status';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.admin_enabled IS DISTINCT FROM OLD.admin_enabled OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR OLD.deleted_at IS NOT NULL THEN
  RAISE EXCEPTION 'sold package status requires administrative version';
 END IF;

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
        IF NEW.ends_at < OLD.ends_at OR NEW.cancelled_at IS NOT NULL THEN
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
CREATE OR REPLACE FUNCTION assert_package_subscription_revision_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fact_operation text;
BEGIN
    SELECT operation INTO fact_operation
    FROM package_subscription_versions
    WHERE subscription_id = NEW.id AND revision = NEW.revision;
    IF fact_operation IN ('admin_edit','admin_enable','admin_disable','admin_delete') THEN RETURN NULL; END IF;
    IF fact_operation IS NULL
       OR (NEW.lifecycle_status = 'cancelled' AND fact_operation <> 'cancel')
       OR (NEW.lifecycle_status = 'active' AND NEW.ends_at > OLD.ends_at AND fact_operation <> 'renew')
       OR (NEW.lifecycle_status = 'active' AND NEW.ends_at = OLD.ends_at
           AND fact_operation NOT IN ('upgrade', 'downgrade')) THEN
        RAISE EXCEPTION 'package subscription revision requires matching version fact';
    END IF;
    RETURN NULL;
END;
$$;
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 20 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 20);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage'));

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
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
        -- 483：售出 reseller_sale 贷代理商、reseller_wholesale 借代理商；冲回（reverses 非空）方向相反。
        OR (operation='reseller_sale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'credit' ELSE 'debit' END)
        OR (operation='reseller_wholesale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'debit' ELSE 'credit' END)
    );

CREATE OR REPLACE FUNCTION guard_package_order_seller_483() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    platform_scope uuid := package_catalog_platform_scope_481();
    product_owner uuid;
    customer_parent uuid;
    expected bigint;
BEGIN
    SELECT tenant.parent_scope_id INTO customer_parent
    FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
    WHERE scope.id = NEW.tenant_scope_id;
    IF NEW.product_kind = 'traffic_package' THEN
        IF NEW.seller_scope_id IS DISTINCT FROM platform_scope OR NEW.wholesale_minor <> 0
           OR NEW.funding_source = 'reseller' THEN
            RAISE EXCEPTION 'traffic packages are sold by the platform' USING ERRCODE='P4832';
        END IF;
        RETURN NEW;
    END IF;
    -- package_orders.product_id 无外键：目录里找不到的套餐（历史/导入）按平台套餐对待。
    SELECT owner_scope_id INTO product_owner FROM package_products WHERE id = NEW.product_id;
    IF COALESCE(product_owner, platform_scope) IS DISTINCT FROM NEW.seller_scope_id OR
       NEW.seller_scope_id IS DISTINCT FROM COALESCE(customer_parent, platform_scope) THEN
        RAISE EXCEPTION 'package order seller must own the package and be the customer''s reseller or the platform'
            USING ERRCODE='P4832';
    END IF;
    IF NEW.seller_scope_id = platform_scope THEN
        IF NEW.wholesale_minor <> 0 OR NEW.funding_source = 'reseller' THEN
            RAISE EXCEPTION 'platform package orders carry no wholesale cost' USING ERRCODE='P4833';
        END IF;
        RETURN NEW;
    END IF;
    -- 代理商套餐：只有购买与续费（升降级的按比例批发价未定义）；只用余额或代下单（不走第三方支付）。
    IF NEW.operation NOT IN ('purchase', 'renew') OR NEW.funding_source NOT IN ('balance', 'reseller')
       OR NEW.settlement_direction <> 'debit' OR NEW.promotion_reservation_id IS NOT NULL THEN
        RAISE EXCEPTION 'reseller package orders are balance or reseller-placed purchases and renewals only'
            USING ERRCODE='P4833';
    END IF;
    expected := reseller_wholesale_minor_483(NEW.seller_scope_id,
        (SELECT spec FROM package_product_versions WHERE product_id = NEW.product_id AND revision = NEW.product_revision),
        NEW.package_period);
    -- 售价低于 W 不拦（ADR §5：平台按 W 收，与售价无关；差额由代理商承担）。
    IF expected IS NULL OR expected <> NEW.wholesale_minor THEN
        RAISE EXCEPTION 'reseller order wholesale cost does not match the price list' USING ERRCODE='P4834';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION assert_reseller_transaction_483() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    sold package_orders%ROWTYPE;
    addon bigint;
    original billing_transactions%ROWTYPE;
    reversed numeric;
BEGIN
    IF NEW.operation NOT IN ('reseller_sale', 'reseller_wholesale') THEN
        RETURN NULL;
    END IF;
    SELECT * INTO sold FROM package_orders WHERE id = NEW.commercial_order_id;
    addon := COALESCE((sold.pricing_snapshot->>'addon_original_minor')::bigint, 0);
    IF sold.id IS NULL OR sold.seller_scope_id IS DISTINCT FROM NEW.target_scope_id OR
       sold.seller_scope_id = package_catalog_platform_scope_481() OR NEW.currency <> sold.currency THEN
        RAISE EXCEPTION 'reseller transaction does not match its order' USING ERRCODE='P4831';
    END IF;
    IF NEW.reverses_transaction_id IS NULL THEN
        IF (NEW.operation = 'reseller_wholesale' AND NEW.amount_minor <> sold.wholesale_minor) OR
           (NEW.operation = 'reseller_sale' AND (sold.funding_source <> 'balance' OR
            NEW.amount_minor <> sold.payable_amount_minor - addon)) OR
           (SELECT count(*) FROM billing_transactions WHERE commercial_order_id = sold.id
              AND operation = NEW.operation AND reverses_transaction_id IS NULL) <> 1 THEN
            RAISE EXCEPTION 'reseller transaction does not match its order' USING ERRCODE='P4831';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO original FROM billing_transactions WHERE id = NEW.reverses_transaction_id;
    SELECT COALESCE(sum(amount_minor::numeric), 0) INTO reversed
    FROM billing_transactions WHERE reverses_transaction_id = NEW.reverses_transaction_id;
    IF original.operation IS DISTINCT FROM NEW.operation OR original.reverses_transaction_id IS NOT NULL OR
       original.commercial_order_id IS DISTINCT FROM NEW.commercial_order_id OR
       original.target_scope_id IS DISTINCT FROM NEW.target_scope_id OR reversed > original.amount_minor THEN
        RAISE EXCEPTION 'reseller reversal does not match the original transaction' USING ERRCODE='P4831';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION assert_reseller_order_complete_483() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    sold package_orders%ROWTYPE;
    addon bigint;
    wholesale_count bigint;
    sale_count bigint;
    customer_count bigint;
BEGIN
    SELECT * INTO sold FROM package_orders WHERE id = NEW.order_id;
    IF sold.seller_scope_id = package_catalog_platform_scope_481() THEN
        RETURN NULL;
    END IF;
    addon := COALESCE((sold.pricing_snapshot->>'addon_original_minor')::bigint, 0);
    SELECT count(*) FILTER (WHERE operation = 'reseller_wholesale'),
           count(*) FILTER (WHERE operation = 'reseller_sale'),
           count(*) FILTER (WHERE operation IN ('package_purchase', 'package_renewal'))
    INTO wholesale_count, sale_count, customer_count
    FROM billing_transactions WHERE commercial_order_id = sold.id AND reverses_transaction_id IS NULL;
    IF wholesale_count <> (CASE WHEN sold.wholesale_minor > 0 THEN 1 ELSE 0 END) OR
       (sold.funding_source = 'reseller' AND (sale_count <> 0 OR customer_count <> 0 OR
        NEW.billing_transaction_id IS NOT NULL)) OR
       (sold.funding_source = 'balance' AND (
        customer_count <> (CASE WHEN sold.payable_amount_minor > 0 THEN 1 ELSE 0 END) OR
        sale_count <> (CASE WHEN sold.payable_amount_minor - addon > 0 THEN 1 ELSE 0 END))) THEN
        RAISE EXCEPTION 'reseller order is missing its three-party ledger' USING ERRCODE='P4835';
    END IF;
    RETURN NULL;
END;
$$;
DROP FUNCTION reseller_change_wholesale_555(uuid, package_orders);
