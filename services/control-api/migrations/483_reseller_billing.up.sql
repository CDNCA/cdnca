LOCK TABLE schema_migrations, package_orders, billing_transactions, billing_accounts, reseller_profiles,
    package_order_fulfillments, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_483_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 482 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 482 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=482 AND
        migration_id='482_reseller_impersonation' AND
        checksum_sha256='0dac3d102451e85c7a0c18be2f067d1efc3d57a9250d0e688383de2c3a93609f' AND
        down_checksum_sha256='59951ed53896a1e8a6646738ffcf7ac960b60bba75c222b9d011ac978b288d48' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.reseller_wholesale_prices') IS NULL OR
       to_regprocedure('package_catalog_platform_scope_481()') IS NULL OR
       EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='package_orders' AND column_name IN ('seller_scope_id','wholesale_minor')) THEN
        RAISE EXCEPTION 'migration 483 requires the exact verified 482 release head' USING ERRCODE='P4830';
    END IF;
END;
$migration_483_up$;

-- 483（r136 rs-03-billing，ADR 0018 RS-03 §5；合入时按集成头改号、重钉前驱 482）。
-- 代理商预付批发价（Q1）：客户买代理商套餐时同一事务记三笔账（每笔仍是"租户 ↔ platform_clearing"两分录）：
--   客户 package_purchase/renewal 借 P；代理商 reseller_wholesale 借 W（预付余额，不足整单拒绝）；
--   代理商 reseller_sale 贷 P（续费的加购包部分归平台，不计入）。净额：客户 -P、代理商 +P-W、平台 +W。
-- 代理商代下单（funding_source='reseller'）：只记 reseller_wholesale，客户余额不动。
-- 退款/作废按原单比例反向（reverses_transaction_id 指原交易）。
-- 预付账户就是代理商自己的 tenant_liability（id = scope_id）：reseller_profiles.prepaid_account_id 落值。
-- 客户只能买所属代理商（无则平台）的套餐（Q3）；流量包仍是平台的。
--
-- 错误码（482 占位用 P4820/P4821，本迁移从 P4830 起）：P4830 前驱不符；P4831 代理商账与订单不符；
-- P4832 订单卖方须为套餐所有者且是客户的上级（或平台）；P4833 代理商单形态不允许；P4834 批发价与价表不符/未定价；
-- P4835 代理商单三方账不全；P4836/P4837 down 前驱不符/已有代理商账拒绝回退。

-- 卖方（套餐所有者；流量包与平台套餐为平台 scope）与该单批发成本 W（分）。旧单都是平台卖的。
ALTER TABLE package_orders ADD COLUMN seller_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT;
ALTER TABLE package_orders ADD COLUMN wholesale_minor bigint NOT NULL DEFAULT 0
    CHECK (wholesale_minor BETWEEN 0 AND 1000000000000000);
ALTER TABLE package_orders DISABLE TRIGGER USER;
UPDATE package_orders SET seller_scope_id = package_catalog_platform_scope_481();
ALTER TABLE package_orders ENABLE TRIGGER USER;
ALTER TABLE package_orders ALTER COLUMN seller_scope_id SET DEFAULT package_catalog_platform_scope_481();
ALTER TABLE package_orders ALTER COLUMN seller_scope_id SET NOT NULL;
ALTER TABLE package_orders DROP CONSTRAINT package_orders_funding_source_check;
ALTER TABLE package_orders ADD CONSTRAINT package_orders_funding_source_check
    CHECK (funding_source IN ('balance', 'provider', 'reseller'));
CREATE INDEX package_orders_seller_483_idx ON package_orders (seller_scope_id, created_at DESC, id DESC);

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase',
        'recharge_payment','recharge_refund','recharge_void',
        'migrate_import_credit','reseller_sale','reseller_wholesale'
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
        -- 483：售出 reseller_sale 贷代理商、reseller_wholesale 借代理商；冲回（reverses 非空）方向相反。
        OR (operation='reseller_sale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'credit' ELSE 'debit' END)
        OR (operation='reseller_wholesale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'debit' ELSE 'credit' END)
    );

-- 预付账户：代理商自己的 tenant_liability（与 008 的租户账户同一行），开通时建好并落值。
CREATE FUNCTION bind_reseller_prepaid_account_483() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO billing_accounts (id, scope_id, kind, currency, balance_minor, revision, created_at, updated_at)
    VALUES (NEW.scope_id, NEW.scope_id, 'tenant_liability', 'CNY', 0, 1, NEW.created_at, NEW.created_at)
    ON CONFLICT (scope_id, kind) DO NOTHING;
    NEW.prepaid_account_id := NEW.scope_id;
    RETURN NEW;
END;
$$;
INSERT INTO billing_accounts (id, scope_id, kind, currency, balance_minor, revision, created_at, updated_at)
SELECT profile.scope_id, profile.scope_id, 'tenant_liability', 'CNY', 0, 1, profile.created_at, profile.created_at
FROM reseller_profiles profile
ON CONFLICT (scope_id, kind) DO NOTHING;
ALTER TABLE reseller_profiles DISABLE TRIGGER USER;
UPDATE reseller_profiles SET prepaid_account_id = scope_id;
ALTER TABLE reseller_profiles ENABLE TRIGGER USER;
ALTER TABLE reseller_profiles ALTER COLUMN prepaid_account_id SET NOT NULL;
ALTER TABLE reseller_profiles ADD CONSTRAINT reseller_profiles_prepaid_account_483 CHECK (prepaid_account_id = scope_id);
CREATE TRIGGER reseller_profiles_prepaid_483
BEFORE INSERT ON reseller_profiles
FOR EACH ROW EXECUTE FUNCTION bind_reseller_prepaid_account_483();

-- 批发成本 W（分）：口径同 RS-02 packagecatalog/wholesale.go validateWholesale——代理商价表里主线路组 + 备用线路组
-- 该周期的价之和（备用无价不计）；主线路组该周期无价返回 NULL（不能卖）。
CREATE FUNCTION reseller_wholesale_minor_483(reseller uuid, product_spec jsonb, sale_period text)
RETURNS bigint LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN bool_or(price.line_group_id::text = product_spec->>'node_group_id')
                THEN sum(price.price_minor)::bigint END
    FROM reseller_profiles profile
    JOIN reseller_wholesale_prices price
      ON price.price_list = profile.wholesale_price_list AND price.period = sale_period
    JOIN access_scopes platform ON platform.id = price.platform_scope_id AND platform.kind = 'platform'
    WHERE profile.scope_id = reseller
      AND price.line_group_id::text IN (product_spec->>'node_group_id', product_spec->>'backup_node_group_id')
$$;
-- 订单卖方：套餐单的卖方须是该版本套餐的所有者，且是客户的上级（代理商客户）或平台（直客）；
-- 流量包与平台套餐单 wholesale_minor=0；代理商单的 W 须等于价表按下单周期算出的值（主线路组须有价）。
CREATE FUNCTION guard_package_order_seller_483() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE TRIGGER package_orders_seller_483
BEFORE INSERT ON package_orders
FOR EACH ROW EXECUTE FUNCTION guard_package_order_seller_483();

-- 代理商账：target 是订单卖方；售出额 = 客户实付减续费加购包部分；批发额 = wholesale_minor；
-- 冲回不超过原交易，且原交易同单同类。
CREATE FUNCTION assert_reseller_transaction_483() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE CONSTRAINT TRIGGER billing_transactions_reseller_483
AFTER INSERT ON billing_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_reseller_transaction_483();

-- 051/446 的商业交易守卫只认 package_* 与充值/调账/导入；代理商账由上面的 483 守卫校验。
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
    -- their approved migrate_import_balance_credits row (446). Reseller rows
    -- are checked by assert_reseller_transaction_483 (483).
    IF NEW.operation IN ('manual_adjustment', 'recharge_payment', 'recharge_refund', 'recharge_void',
                         'migrate_import_credit', 'reseller_sale', 'reseller_wholesale') THEN
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

-- 代理商单履约时三方账必须齐：W>0 有 reseller_wholesale；余额单有客户扣款与（售出额>0 时）reseller_sale；
-- 代下单没有客户扣款、没有 reseller_sale。
CREATE FUNCTION assert_reseller_order_complete_483() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE CONSTRAINT TRIGGER package_order_fulfillments_reseller_483
AFTER INSERT ON package_order_fulfillments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_reseller_order_complete_483();

-- 低余额提醒（扣批发价后预付余额低于 low_balance_minor 时通知代理商；0 = 不提醒）。默认站内+邮件，短信关。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('reseller.prepaid.low_balance', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('reseller.prepaid.low_balance.zh-cn', 1, 'sms', '',
     '代理商预付余额仅剩{{.remaining}}元，低于提醒线{{.threshold}}元，余额不足批发价时客户将无法购买你的套餐，请及时充值。',
     ARRAY['remaining','threshold'], '2026-10-24 00:00:00+00'),
    ('reseller.prepaid.low_balance.zh-cn', 1, 'email', '代理商预付余额不足提醒',
     '你的代理商预付余额仅剩 {{.remaining}} 元，已低于提醒线 {{.threshold}} 元。客户每购买一单你的套餐，平台按批发价从预付余额扣款；余额不足批发价时该单会被拒绝。请到控制台「财务」充值。',
     ARRAY['remaining','threshold'], '2026-10-24 00:00:00+00');

REVOKE ALL ON FUNCTION guard_package_order_seller_483(), assert_reseller_transaction_483(),
    assert_reseller_order_complete_483(), bind_reseller_prepaid_account_483() FROM PUBLIC;
