-- 549（fix-pkgmkt，用户 10-27「按照竞品的做」）：升级包「购买」真实扣费。
-- 竞品（doc.cdnfly.com v6：POST /v1/user-package/:id/upgrades、GET .../upgrades/:up_id）按「剩余期限价格：原月价、
-- 优惠后月价、按剩余天数折算的总价」从余额扣款并生成已付款订单；同一普通升级包数量累加，WAF 固定一份。
-- 本迁移：
-- ① package_addon_orders：升级包订单（追加只读）。一单 = 一次购买：升级包快照、数量、剩余天数、折算原价、
--    折扣明细、应付、扣费流水；buyer_user_id 是套餐所属用户（扣其租户余额），actor_* 是实际操作人
--    （管理员代购时为管理员）。与 package_orders 分开：后者的履约/代理商三方账/退款约束都是套餐与流量包的。
-- ② billing_transactions.addon_order_id + 操作 package_addon_purchase（借租户、贷平台清算，只扣不退）。
--    形状约束：只有 package_addon_purchase 带 addon_order_id；一致性触发器校验金额/租户与订单一致。
-- ③ 分配表 package_addon_assignments 不变（charged_minor 仍恒为 0，263 守卫不许改）：是否付费、付了多少看订单。
--    累加购买更新分配的 amount，订单记本次数量与金额。免费分配（assignment.create）不产生订单。
-- 前驱 548（promotion_addon_user_groups），守卫钉 548 校验和。
LOCK TABLE schema_migrations, billing_transactions IN ACCESS EXCLUSIVE MODE;

DO $migration_549_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 548 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 548 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=548 AND
        migration_id='548_promotion_addon_user_groups' AND
        checksum_sha256='948706da9f42113170916a92b1388e8b76212a7a8184fa26f89005e83093219f' AND
        down_checksum_sha256='585d3a2e7fa4e713eda4ac40d11c6f9f8f5ebda07cc002e689bd36f64a3c82e3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('package_addon_orders') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 549 requires the exact verified 548 release head' USING ERRCODE='P5490';
    END IF;
END;
$migration_549_up$;

CREATE TABLE package_addon_orders (
    id uuid PRIMARY KEY,
    display_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    buyer_user_id uuid NOT NULL,
    subscription_id uuid NOT NULL REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    addon_id uuid NOT NULL REFERENCES package_addon_products(id) ON DELETE RESTRICT,
    assignment_id uuid NOT NULL REFERENCES package_addon_assignments(id) ON DELETE RESTRICT,
    addon_snapshot jsonb NOT NULL CHECK (jsonb_typeof(addon_snapshot)='object' AND octet_length(addon_snapshot::text)<=16384),
    amount bigint NOT NULL CHECK (amount BETWEEN 1 AND 1000000),
    monthly_price_minor bigint NOT NULL CHECK (monthly_price_minor BETWEEN 0 AND 1000000000000),
    remaining_days integer NOT NULL CHECK (remaining_days BETWEEN 1 AND 36600),
    currency text NOT NULL CHECK (currency='CNY'),
    original_amount_minor bigint NOT NULL CHECK (original_amount_minor BETWEEN 0 AND 1000000000000000),
    discount_amount_minor bigint NOT NULL CHECK (discount_amount_minor >= 0),
    payable_amount_minor bigint NOT NULL CHECK (payable_amount_minor >= 0),
    policies jsonb NOT NULL CHECK (jsonb_typeof(policies)='array' AND octet_length(policies::text)<=16384),
    billing_transaction_id uuid,
    subscription_ends_at timestamptz NOT NULL,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (tenant_scope_id, buyer_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (payable_amount_minor = original_amount_minor - discount_amount_minor),
    CHECK ((payable_amount_minor = 0) = (billing_transaction_id IS NULL)),
    CHECK (subscription_ends_at > created_at)
);
CREATE INDEX package_addon_orders_tenant_created_idx ON package_addon_orders (tenant_scope_id, created_at DESC, id DESC);
CREATE INDEX package_addon_orders_subscription_idx ON package_addon_orders (subscription_id, created_at DESC);
CREATE INDEX package_addon_orders_policies_idx ON package_addon_orders USING gin (policies jsonb_path_ops);

CREATE FUNCTION protect_package_addon_order_549() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'package addon orders are append-only' USING ERRCODE='P5491';
END $$;
CREATE TRIGGER package_addon_orders_append_only BEFORE UPDATE OR DELETE ON package_addon_orders
    FOR EACH ROW EXECUTE FUNCTION protect_package_addon_order_549();
CREATE TRIGGER package_addon_orders_no_truncate BEFORE TRUNCATE ON package_addon_orders
    FOR EACH STATEMENT EXECUTE FUNCTION protect_package_addon_order_549();

-- 订单必须有同事务的成功审计，扣费流水必须与订单一致（借方、金额、租户）。
CREATE FUNCTION assert_package_addon_order_549() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tx billing_transactions%ROWTYPE;
    assignment package_addon_assignments%ROWTYPE;
BEGIN
    SELECT * INTO assignment FROM package_addon_assignments WHERE id=NEW.assignment_id;
    IF assignment.subscription_id IS DISTINCT FROM NEW.subscription_id OR assignment.addon_id IS DISTINCT FROM NEW.addon_id
       OR assignment.tenant_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR assignment.owner_user_id IS DISTINCT FROM NEW.buyer_user_id THEN
        RAISE EXCEPTION 'package addon order does not match its assignment' USING ERRCODE='P5492';
    END IF;
    IF NEW.billing_transaction_id IS NOT NULL THEN
        SELECT * INTO tx FROM billing_transactions WHERE id=NEW.billing_transaction_id;
        IF tx.operation IS DISTINCT FROM 'package_addon_purchase' OR tx.addon_order_id IS DISTINCT FROM NEW.id
           OR tx.target_scope_id IS DISTINCT FROM NEW.tenant_scope_id OR tx.amount_minor IS DISTINCT FROM NEW.payable_amount_minor
           OR tx.direction IS DISTINCT FROM 'debit' OR tx.created_by_user_id IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'package addon order does not match its billing transaction' USING ERRCODE='P5493';
        END IF;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events WHERE scope_id=NEW.actor_scope_id AND action='package.addon.assignment.purchase'
          AND resource_type='package_addon' AND resource_id=NEW.assignment_id::text AND request_id=NEW.request_id
          AND result='success' AND payload->>'order_id'=NEW.id::text
    ) THEN
        RAISE EXCEPTION 'package addon order requires matching audit' USING ERRCODE='P5494';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER package_addon_orders_complete_549 AFTER INSERT ON package_addon_orders
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assert_package_addon_order_549();

ALTER TABLE billing_transactions ADD COLUMN addon_order_id uuid REFERENCES package_addon_orders(id) ON DELETE RESTRICT;
CREATE UNIQUE INDEX billing_transactions_addon_order_549_idx ON billing_transactions (addon_order_id)
    WHERE addon_order_id IS NOT NULL;
ALTER TABLE package_addon_orders ADD CONSTRAINT package_addon_orders_transaction_fk
    FOREIGN KEY (billing_transaction_id) REFERENCES billing_transactions(id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_operation_check CHECK(operation IN (
        'manual_adjustment','provider_payment','package_purchase','package_renewal','package_upgrade',
        'package_downgrade','package_refund','package_void','traffic_package_purchase',
        'recharge_payment','recharge_refund','recharge_void',
        'migrate_import_credit','reseller_sale','reseller_wholesale',
        'package_addon_purchase'
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
        -- 549：升级包购买，绑升级包订单，只扣不退（退款不在本期范围）。
        OR (operation='package_addon_purchase' AND addon_order_id IS NOT NULL AND commercial_order_id IS NULL
            AND reverses_transaction_id IS NULL AND payment_attempt_id IS NULL AND recharge_order_id IS NULL
            AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL AND adjustment_request_id IS NULL
            AND direction='debit')
    );

-- 升级包扣费流水只能由升级包订单引用（反向：每条都要有对应订单）。
CREATE FUNCTION assert_package_addon_transaction_549() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.operation <> 'package_addon_purchase' THEN
        IF NEW.addon_order_id IS NOT NULL THEN
            RAISE EXCEPTION 'only addon purchases may reference an addon order' USING ERRCODE='P5495';
        END IF;
        RETURN NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM package_addon_orders WHERE id=NEW.addon_order_id AND billing_transaction_id=NEW.id) THEN
        RAISE EXCEPTION 'addon purchase transaction lacks its order' USING ERRCODE='P5496';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER billing_transactions_addon_549 AFTER INSERT ON billing_transactions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assert_package_addon_transaction_549();

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
    -- are checked by assert_reseller_transaction_483 (483). Add-on purchases
    -- are bound to their package_addon_orders row (549).
    IF NEW.operation IN ('manual_adjustment', 'recharge_payment', 'recharge_refund', 'recharge_void',
                         'migrate_import_credit', 'reseller_sale', 'reseller_wholesale',
                         'package_addon_purchase') THEN
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

DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT, INSERT ON package_addon_orders TO cdnca_control_app;
        GRANT USAGE, SELECT ON SEQUENCE package_addon_orders_display_id_seq TO cdnca_control_app;
    END IF;
END $$;
