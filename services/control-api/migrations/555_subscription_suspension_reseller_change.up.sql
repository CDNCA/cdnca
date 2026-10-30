-- 555（bb03，ADR 0019 §5；号为占位，合入时由主会话改号、重钉前驱守卫）：财务对接插件的订阅能力前置。
-- 1. 订阅级停用/恢复：package_subscriptions.suspended_at / suspend_reason；版本行 operation suspend/unsuspend
--    只改这两列（revision+1）；到期计时不暂停。下发侧过滤 suspended_at IS NULL，系统重发布新 trigger
--    package_suspension（538 的约束扩展，cardinality 20 -> 21）。写请求 operation 加 suspend/unsuspend。
-- 2. 代理商给客户升降级（Q2 a）：同一代理商自有套餐之间、立即生效、代下单（funding reseller，客户不扣款），
--    批发价差按剩余时长折算（旧价向下取整、新价向上取整，同 proration-utc-v1）：升级补扣预付余额，
--    降级 reseller_wholesale credit 退回；守卫按 pricing_snapshot 复算差额。
-- 错误码：P5550 前驱不符；P5551/P5552 down 前驱不符/已有停用或代理商升降级事实拒绝回退；
-- P5553 停用状态变更不合法；P5554 代理商升降级单形态不允许（批发差额不符沿用 P4834）；
-- P5555 代理商升降级单不可退款/作废（用户 10-27 定）。
-- 前驱 554（fix-cnamerand 554_node_bandwidth_alerts），守卫钉 554 校验和。
LOCK TABLE schema_migrations, package_subscriptions, package_subscription_versions,
    package_subscription_write_requests, package_orders, billing_transactions,
    edge_system_republication_heads, edge_system_republication_attempts, edge_system_revision_segments
    IN ACCESS EXCLUSIVE MODE;

DO $migration_555_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 554 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 554 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=554 AND
        migration_id='554_node_bandwidth_alerts' AND
        checksum_sha256='f070255f81f9751180a192fc73525fae7daff626693db1952639ba3c520530f0' AND
        down_checksum_sha256='04ce41b737cb4c3585ec9d7bacf73e18da8f2857c0ff4a9174515a6817b25663' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='package_subscriptions' AND column_name='suspended_at'
       ) THEN
        RAISE EXCEPTION 'migration 555 requires the exact verified 554 release head' USING ERRCODE='P5550';
    END IF;
END;
$migration_555_up$;

ALTER TABLE package_subscriptions
    ADD COLUMN suspended_at timestamptz,
    ADD COLUMN suspend_reason text CHECK (suspend_reason IS NULL OR char_length(suspend_reason) BETWEEN 1 AND 256),
    ADD CONSTRAINT package_subscriptions_suspension_555_check CHECK ((suspended_at IS NULL) = (suspend_reason IS NULL));
ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_operation_check,
    DROP CONSTRAINT package_subscription_versions_commerce_shape;
ALTER TABLE package_subscription_versions ADD CONSTRAINT package_subscription_versions_operation_check
    CHECK(operation IN ('open','renew','cancel','upgrade','downgrade','admin_edit','admin_enable','admin_disable',
        'admin_delete','suspend','unsuspend')),
    ADD CONSTRAINT package_subscription_versions_commerce_shape CHECK(
    (operation IN ('open','cancel','admin_edit','admin_enable','admin_disable','admin_delete','suspend','unsuspend')
        AND order_id IS NULL AND entitlement_revision IS NULL)
    OR (operation='renew' AND ((order_id IS NULL AND entitlement_revision IS NULL) OR (order_id IS NOT NULL AND entitlement_revision IS NOT NULL)))
    OR (operation IN ('upgrade','downgrade') AND order_id IS NOT NULL AND entitlement_revision IS NOT NULL));
ALTER TABLE package_subscription_write_requests DROP CONSTRAINT package_subscription_write_requests_operation_check,
    ADD CONSTRAINT package_subscription_write_requests_operation_check CHECK (operation IN (
        'package.subscription.open', 'package.subscription.renew', 'package.subscription.cancel',
        'package.subscription.suspend', 'package.subscription.unsuspend'));

-- 261 的快照保护加停用/恢复分支：只改 suspended_at/suspend_reason，其余列一律不变；其他操作不得改这两列。
CREATE OR REPLACE FUNCTION protect_package_subscription_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admin_operation text;
BEGIN
 SELECT operation INTO admin_operation FROM package_subscription_versions WHERE subscription_id=NEW.id AND revision=NEW.revision;
 IF admin_operation IN ('suspend','unsuspend') THEN
  IF OLD.deleted_at IS NOT NULL OR OLD.lifecycle_status<>'active' OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at
   OR (to_jsonb(NEW) - ARRAY['revision','updated_at','updated_by_user_id','suspended_at','suspend_reason'])
      IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['revision','updated_at','updated_by_user_id','suspended_at','suspend_reason'])
   OR (admin_operation='suspend' AND (OLD.suspended_at IS NOT NULL OR NEW.suspended_at IS DISTINCT FROM NEW.updated_at
       OR NEW.suspend_reason IS NULL))
   OR (admin_operation='unsuspend' AND (OLD.suspended_at IS NULL OR NEW.suspended_at IS NOT NULL))
   OR NOT EXISTS(SELECT 1 FROM package_subscription_versions v WHERE v.subscription_id=NEW.id AND v.revision=NEW.revision
       AND v.created_by_user_id=NEW.updated_by_user_id AND v.created_at=NEW.updated_at) THEN
    RAISE EXCEPTION 'invalid package subscription suspension transition' USING ERRCODE='P5553';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.suspended_at IS DISTINCT FROM OLD.suspended_at OR NEW.suspend_reason IS DISTINCT FROM OLD.suspend_reason THEN
  RAISE EXCEPTION 'package subscription suspension requires a suspension version' USING ERRCODE='P5553';
 END IF;
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
-- 停用/恢复不动 ends_at，不能被判成要求 upgrade/downgrade 事实。
CREATE OR REPLACE FUNCTION assert_package_subscription_revision_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fact_operation text;
BEGIN
    SELECT operation INTO fact_operation
    FROM package_subscription_versions
    WHERE subscription_id = NEW.id AND revision = NEW.revision;
    IF fact_operation IN ('admin_edit','admin_enable','admin_disable','admin_delete','suspend','unsuspend') THEN RETURN NULL; END IF;
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
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 21 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage', 'package_suspension']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 21);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage',
        'package_suspension'));

-- 代理商升降级：reseller_wholesale 首笔可以是 credit（降级退回折算差），冲回只能是 credit（只冲借方）。
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
        OR (operation='reseller_sale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'credit' ELSE 'debit' END)
        -- 555：首笔方向由 assert_reseller_transaction_483 按订单核对（升降级可为 credit）。
        OR (operation='reseller_wholesale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND (reverses_transaction_id IS NULL OR direction='credit'))
    );

-- 代理商升降级的批发差额 W 与方向（pricing_snapshot，proration-utc-v1 口径）：
--   旧折算 = floor(旧批发价 × 剩余 / 周期)，新折算 = ceil(新批发价 × 剩余 / 周期)，W = |新 - 旧|，
--   新 ≥ 旧 为 debit（补扣预付），否则 credit（退回预付）。旧/新批发价按代理商价表现价复算。
CREATE OR REPLACE FUNCTION reseller_change_wholesale_555(seller uuid, sold package_orders)
RETURNS TABLE (amount bigint, direction text) LANGUAGE plpgsql STABLE AS $$
DECLARE
    pricing jsonb := sold.pricing_snapshot;
    old_owner uuid;
    old_spec jsonb;
    old_price bigint;
    new_price bigint;
    remaining numeric;
    cycle numeric;
    old_credit numeric;
    new_charge numeric;
BEGIN
    SELECT product.owner_scope_id, version.spec INTO old_owner, old_spec
    FROM package_products product JOIN package_product_versions version ON version.product_id = product.id
    WHERE product.id = (pricing->>'wholesale_old_product_id')::uuid
      AND version.revision = (pricing->>'wholesale_old_product_revision')::bigint;
    old_price := reseller_wholesale_minor_483(seller, old_spec, pricing->>'wholesale_old_period');
    new_price := reseller_wholesale_minor_483(seller,
        (SELECT spec FROM package_product_versions WHERE product_id = sold.product_id AND revision = sold.product_revision),
        sold.package_period);
    -- omitempty: a zero remaining time or price is absent from the snapshot.
    remaining := COALESCE((pricing->>'remaining_nanoseconds')::numeric, 0);
    cycle := (pricing->>'cycle_nanoseconds')::numeric;
    IF old_owner IS DISTINCT FROM seller OR old_price IS NULL OR new_price IS NULL OR
       COALESCE((pricing->>'wholesale_old_price_minor')::bigint, 0) IS DISTINCT FROM old_price OR
       COALESCE((pricing->>'wholesale_new_price_minor')::bigint, 0) IS DISTINCT FROM new_price OR
       cycle IS NULL OR remaining IS NULL OR cycle <= 0 OR remaining < 0 OR remaining > cycle THEN
        RETURN;
    END IF;
    -- exact integer quotients (numeric division rounds at ~16 digits): floor, and ceil = div(a + c - 1, c)
    old_credit := div(old_price * remaining, cycle);
    new_charge := div(new_price * remaining + cycle - 1, cycle);
    amount := abs(new_charge - old_credit)::bigint;
    direction := CASE WHEN new_charge >= old_credit THEN 'debit' ELSE 'credit' END;
    RETURN NEXT;
END;
$$;
CREATE OR REPLACE FUNCTION guard_package_order_seller_483() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    platform_scope uuid := package_catalog_platform_scope_481();
    product_owner uuid;
    customer_parent uuid;
    expected bigint;
    change_direction text;
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
    -- 555：代理商代客户升降级（立即生效、代下单、客户不扣款），W 是折算批发差额（方向见 pricing_snapshot）。
    IF NEW.operation IN ('upgrade', 'downgrade') THEN
        IF NEW.funding_source <> 'reseller' OR NEW.settlement_direction <> 'debit' OR NEW.payable_amount_minor <> 0
           OR NEW.effective_mode <> 'immediate' OR NEW.promotion_reservation_id IS NOT NULL THEN
            RAISE EXCEPTION 'reseller package changes are reseller-placed immediate orders only' USING ERRCODE='P5554';
        END IF;
        SELECT change.amount, change.direction INTO expected, change_direction
        FROM reseller_change_wholesale_555(NEW.seller_scope_id, NEW) change;
        IF expected IS NULL OR expected <> NEW.wholesale_minor OR
           NEW.pricing_snapshot->>'wholesale_direction' IS DISTINCT FROM change_direction THEN
            RAISE EXCEPTION 'reseller order wholesale cost does not match the price list' USING ERRCODE='P4834';
        END IF;
        RETURN NEW;
    END IF;
    -- 其余代理商套餐单：购买与续费；只用余额或代下单（不走第三方支付）。
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

-- 代理商账：升降级的首笔 reseller_wholesale 方向按订单 pricing_snapshot（升级 debit 补扣、降级 credit 退回）。
CREATE OR REPLACE FUNCTION assert_reseller_transaction_483() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    sold package_orders%ROWTYPE;
    addon bigint;
    original billing_transactions%ROWTYPE;
    reversed numeric;
    expected_direction text;
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
        expected_direction := CASE
            WHEN NEW.operation = 'reseller_sale' THEN 'credit'
            WHEN sold.operation IN ('upgrade', 'downgrade') THEN sold.pricing_snapshot->>'wholesale_direction'
            ELSE 'debit' END;
        IF NEW.direction IS DISTINCT FROM expected_direction OR
           (NEW.operation = 'reseller_wholesale' AND NEW.amount_minor <> sold.wholesale_minor) OR
           (NEW.operation = 'reseller_sale' AND (sold.funding_source <> 'balance' OR
            NEW.amount_minor <> sold.payable_amount_minor - addon)) OR
           (SELECT count(*) FROM billing_transactions WHERE commercial_order_id = sold.id
              AND operation = NEW.operation AND reverses_transaction_id IS NULL) <> 1 THEN
            RAISE EXCEPTION 'reseller transaction does not match its order' USING ERRCODE='P4831';
        END IF;
        RETURN NULL;
    END IF;
    -- 代理商升降级单不可退款/作废（用户 10-27 定）：服务层先拒，这里兜底。
    IF sold.operation IN ('upgrade', 'downgrade') THEN
        RAISE EXCEPTION 'reseller change orders cannot be refunded or voided' USING ERRCODE='P5555';
    END IF;
    SELECT * INTO original FROM billing_transactions WHERE id = NEW.reverses_transaction_id;
    SELECT COALESCE(sum(amount_minor::numeric), 0) INTO reversed
    FROM billing_transactions WHERE reverses_transaction_id = NEW.reverses_transaction_id;
    IF original.operation IS DISTINCT FROM NEW.operation OR original.reverses_transaction_id IS NOT NULL OR
       original.direction = NEW.direction OR
       original.commercial_order_id IS DISTINCT FROM NEW.commercial_order_id OR
       original.target_scope_id IS DISTINCT FROM NEW.target_scope_id OR reversed > original.amount_minor THEN
        RAISE EXCEPTION 'reseller reversal does not match the original transaction' USING ERRCODE='P4831';
    END IF;
    RETURN NULL;
END;
$$;

-- 代理商单履约三方账：升降级是代下单形态（只有 W>0 时一笔 reseller_wholesale，客户无扣款）。
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
           count(*) FILTER (WHERE operation IN ('package_purchase', 'package_renewal', 'package_upgrade', 'package_downgrade'))
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

REVOKE ALL ON FUNCTION reseller_change_wholesale_555(uuid, package_orders) FROM PUBLIC;
