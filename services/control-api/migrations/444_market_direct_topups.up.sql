LOCK TABLE schema_migrations, payment_channels, payment_reconcile_mismatches, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_444_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 443 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 443 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=443 AND
        migration_id='443_market_terms_notice' AND
        checksum_sha256='eb0c5f3c1c7a5126c947b8da92354bfe37a0e0bafd057881281f620dab249577' AND
        down_checksum_sha256='3b39a41f9ddaadc7348e8bfb2afcc96bf5b8cb1ea9ff2863bd645e338c93a7f0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_direct_topup_orders') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 444 requires the exact verified 443 release head' USING ERRCODE='P4440';
    END IF;
END;
$migration_444_up$;

-- 444（r136 ml-direct-pay，ADR 0015 §3.3；占位号，BATCH-PLUGIN 39 登记 439，合入按实际顺序改号）。
-- 节点市场直结充值的卖方主控侧：订阅方在市场点充值，市场把签名的建单请求放进本主控收件箱，
-- 本主控用自己的收款通道（场景 market_direct）下单，支付回调/查单确认后记一笔到账事实，
-- 再经出站队列把卖方签名的到账报告推给市场，市场给订阅方在本卖方处记余额。钱进本主控商户号，
-- 本主控不给自己的余额记账（不是主控余额充值），所以不进 recharge_orders_v1。

-- 1. 通道场景：298 的无名 CHECK 锁死为 {recharge}，放宽为 recharge / market_direct 的非空子集。
DO $migration_444_scenes$
DECLARE
    found text;
BEGIN
    SELECT conname INTO found FROM pg_constraint
    WHERE conrelid = 'payment_channels'::regclass AND contype = 'c' AND
        pg_get_constraintdef(oid) LIKE 'CHECK ((scenes = ARRAY[''recharge''::text]%';
    IF found IS NULL THEN
        RAISE EXCEPTION 'migration 444: payment_channels scenes check not found' USING ERRCODE='P4443';
    END IF;
    EXECUTE format('ALTER TABLE payment_channels DROP CONSTRAINT %I', found);
END;
$migration_444_scenes$;
ALTER TABLE payment_channels ADD CONSTRAINT payment_channels_scenes_444
    CHECK (scenes <@ ARRAY['recharge', 'market_direct']::text[] AND cardinality(scenes) BETWEEN 1 AND 2);

-- 2. 充值单（以市场 topup_id 为主键，重复下行幂等）。reply 是签名回给市场的 CheckoutReply 原文，
--    重放时原样再签。补偿查单字段与 payment_channel_reconcile_schedule 同语义（那张表外键指向
--    recharge_orders_v1，不能复用）：1/5/15/60 分钟，exhausted = 通道不支持查单或已查满。
CREATE TABLE market_direct_topup_orders (
    topup_id uuid PRIMARY KEY CHECK (topup_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    seller_member_id uuid NOT NULL,
    buyer_member_id uuid NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor > 0 AND amount_minor <= 100000000),
    currency text NOT NULL CHECK (currency = 'CNY'),
    method text NOT NULL CHECK (method IN ('alipay', 'wxpay')),
    state text NOT NULL CHECK (state IN ('pending', 'paid', 'refused')),
    refusal_code text NOT NULL DEFAULT '' CHECK (refusal_code ~ '^[a-z_]{0,32}$'),
    channel_id uuid REFERENCES payment_channels(id) ON DELETE RESTRICT,
    reply jsonb NOT NULL CHECK (jsonb_typeof(reply) = 'object' AND octet_length(reply::text) <= 65536),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    comp_state text NOT NULL DEFAULT 'pending' CHECK (comp_state IN ('pending', 'settled', 'exhausted')),
    comp_attempt integer NOT NULL DEFAULT 0 CHECK (comp_attempt BETWEEN 0 AND 4),
    comp_next_at timestamptz NOT NULL CHECK (isfinite(comp_next_at)),
    comp_lease_until timestamptz,
    comp_error_code text NOT NULL DEFAULT '' CHECK (char_length(comp_error_code) <= 64),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    CHECK ((state = 'refused') = (channel_id IS NULL)),
    CHECK ((state = 'refused') = (refusal_code <> '')),
    CHECK (state <> 'refused' OR comp_state <> 'pending')
);
CREATE INDEX market_direct_topup_orders_comp_444_idx ON market_direct_topup_orders (comp_next_at) WHERE comp_state = 'pending';

-- 3. 到账事实：(channel_id, trade_no) 唯一 = 同一笔交易只记一次；sequence = 同单第几笔成功交易。
CREATE TABLE market_direct_topup_payments (
    id uuid PRIMARY KEY,
    topup_id uuid NOT NULL REFERENCES market_direct_topup_orders(topup_id) ON DELETE RESTRICT,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 100),
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    trade_no text NOT NULL CHECK (trade_no ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trade_digest text NOT NULL CHECK (trade_digest ~ '^[0-9a-f]{64}$'),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    source text NOT NULL CHECK (source IN ('notify', 'query')),
    verification_key_id text NOT NULL CHECK (char_length(verification_key_id) BETWEEN 1 AND 255),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    signature_sha256 bytea NOT NULL CHECK (octet_length(signature_sha256) = 32),
    paid_at timestamptz NOT NULL CHECK (isfinite(paid_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (channel_id, trade_no),
    UNIQUE (topup_id, sequence)
);
CREATE INDEX market_direct_topup_payments_paid_444_idx ON market_direct_topup_payments (channel_id, paid_at);

-- 4. 出站队列：每笔到账一行，签 PaidReport 推给市场；5xx/网络错退避后每小时重试，不放弃；
--    4xx = rejected（告警财务），不再重试。
CREATE TABLE market_direct_topup_reports (
    topup_id uuid NOT NULL,
    sequence integer NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'delivered', 'rejected')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
    lease_until timestamptz,
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 64),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (topup_id, sequence),
    FOREIGN KEY (topup_id, sequence) REFERENCES market_direct_topup_payments(topup_id, sequence) ON DELETE RESTRICT
);
CREATE INDEX market_direct_topup_reports_due_444_idx ON market_direct_topup_reports (next_attempt_at) WHERE state = 'pending';

-- 5. 插件通道按日对账（404）也覆盖市场充值：差异行的 order_id 外键只指向 recharge_orders_v1，
--    市场充值单记在 market_topup_id；404 的无名 CHECK 改为二者其一。
ALTER TABLE payment_reconcile_mismatches
    ADD COLUMN market_topup_id uuid REFERENCES market_direct_topup_orders(topup_id) ON DELETE RESTRICT;
DO $migration_444_mismatch$
DECLARE
    found text;
BEGIN
    SELECT conname INTO found FROM pg_constraint
    WHERE conrelid = 'payment_reconcile_mismatches'::regclass AND contype = 'c' AND
        pg_get_constraintdef(oid) LIKE '%order_id IS NOT NULL%local_amount_minor IS NOT NULL%';
    IF found IS NULL THEN
        RAISE EXCEPTION 'migration 444: payment_reconcile_mismatches order check not found' USING ERRCODE='P4444';
    END IF;
    EXECUTE format('ALTER TABLE payment_reconcile_mismatches DROP CONSTRAINT %I', found);
END;
$migration_444_mismatch$;
ALTER TABLE payment_reconcile_mismatches ADD CONSTRAINT payment_reconcile_mismatches_order_444 CHECK (
    (order_id IS NULL OR market_topup_id IS NULL) AND
    (kind = 'remote_only' OR ((order_id IS NOT NULL OR market_topup_id IS NOT NULL) AND local_amount_minor IS NOT NULL)));

-- 6. 通知：市场下行的两个 kind（买方/卖方）+ 本主控财务告警（市场拒收到账报告）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.direct_topup.paid', true, true, true, 1, 24, true, true, false, now()),
    ('market.direct_topup.received', true, true, true, 1, 24, true, true, false, now()),
    ('payment.market_topup.rejected', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.direct_topup.paid.zh-cn', 1, 'sms', '', '节点市场：你在{{.peer}}处充值{{.observed}}{{.currency}}（最小货币单位）已到账，单号{{.topup}}。', ARRAY['peer','topup','currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.direct_topup.paid.zh-cn', 1, 'email', '节点市场：{{.peer}} 充值已到账', '你在供货方 {{.peer}} 处的充值 {{.observed}}（{{.currency}}，最小货币单位，如分）已到账并计入你在该供货方处的余额，充值单 {{.topup}}。款项直接付给了供货方，平台不经手资金。', ARRAY['peer','topup','currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.direct_topup.received.zh-cn', 1, 'sms', '', '节点市场：订阅方{{.peer}}充值{{.observed}}{{.currency}}（最小货币单位）已入账，单号{{.topup}}。', ARRAY['peer','topup','currency','observed'], '2026-10-22 00:00:00+00'),
    ('market.direct_topup.received.zh-cn', 1, 'email', '节点市场：收到 {{.peer}} 的充值', '订阅方 {{.peer}} 通过你的收款通道充值 {{.observed}}（{{.currency}}，最小货币单位），市场已计入其在你处的余额，充值单 {{.topup}}。', ARRAY['peer','topup','currency','observed'], '2026-10-22 00:00:00+00'),
    ('payment.market_topup.rejected.zh-cn', 1, 'sms', '', '告警：节点市场直结充值{{.topup}}的到账报告被市场拒收({{.reason_code}})，订阅方余额未增加，请核对。', ARRAY['topup','reason_code'], '2026-10-22 00:00:00+00'),
    ('payment.market_topup.rejected.zh-cn', 1, 'email', '直结充值到账报告被市场拒收：{{.topup}}', '节点市场直结充值单 {{.topup}} 已在本主控的收款通道到账，但市场拒收了到账报告（原因：{{.reason_code}}），订阅方在你处的余额没有增加。请在收款通道后台核对该笔交易并联系订阅方处理。', ARRAY['topup','reason_code'], '2026-10-22 00:00:00+00');
