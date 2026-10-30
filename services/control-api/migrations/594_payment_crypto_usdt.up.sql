-- 594（fix-ctlusdt；原占位 590 与线上 590 冲突，merge-p25 按合入顺序改为 594，守卫钉 593_node_alert_intents）：
-- 主控租户充值接入 USDT（收款渠道 provider crypto，libs/payment/crypto，与授权端 071 同一套表结构）：
--   * 充值方式新增 usdt：payment_channels.method、recharge_orders_v1.channel、
--     recharge_statistics_facts_v1.channel、recharge_payment_cancellations_v1.provider 放行 'usdt'；
--     crypto 渠道只服务 usdt、只用于充值场景（节点市场直结仍只支持支付宝/微信）。
--   * crypto 渠道不一定有加密字段（地址池 + 公共只读数据源时无密钥），与 plugin 一样不强制 secret_key_id。
--   * 只读地址（xpub 派生 / 导入的一次性地址池，绝无私钥）、每单一张发票、最终确认且第二数据源核验过的转账
--     （按 channel, network, tx_hash, log_index 去重）、每网络扫描游标、人工复核异常台（少付/多付/超时到账/
--     重复/未归属/回滚/数据源分歧）。
-- 前驱：589（site_origin_tls_no_verify）。
LOCK TABLE schema_migrations, payment_channels, recharge_orders_v1, recharge_statistics_facts_v1,
    recharge_payment_cancellations_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_594_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 593 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 593 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=593 AND
        migration_id='593_node_alert_intents' AND
        checksum_sha256='1746fe4106b8527ab450e9deb41122b26ab22afd5476fc806fae5cadeac51553' AND
        down_checksum_sha256='4446c0f1eff1f4614fd76f5a41b3b0ab35380fcef43cc32168dbe0a6a4abe657' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM pg_catalog.pg_constraint WHERE
            (conrelid = 'payment_channels'::regclass AND conname IN ('payment_channels_method_check',
                'payment_channels_enabled_secrets_402')) OR
            (conrelid = 'recharge_orders_v1'::regclass AND conname = 'recharge_orders_v1_channel_check') OR
            (conrelid = 'recharge_statistics_facts_v1'::regclass AND conname = 'recharge_statistics_facts_v1_channel_check') OR
            (conrelid = 'recharge_payment_cancellations_v1'::regclass AND
                conname = 'recharge_payment_cancellations_v1_provider_check')) <> 5 OR
          to_regclass(current_schema() || '.payment_crypto_invoices') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 594 requires the exact verified 593 release head' USING ERRCODE='P5940';
    END IF;
END;
$migration_594_up$;

ALTER TABLE payment_channels
    DROP CONSTRAINT payment_channels_method_check,
    ADD CONSTRAINT payment_channels_method_check CHECK (method IN ('alipay', 'wxpay', 'usdt')),
    ADD CONSTRAINT payment_channels_crypto_method_594 CHECK ((provider = 'crypto') = (method = 'usdt')),
    ADD CONSTRAINT payment_channels_crypto_scenes_594 CHECK (provider <> 'crypto' OR scenes = ARRAY['recharge']::text[]),
    DROP CONSTRAINT payment_channels_enabled_secrets_402,
    ADD CONSTRAINT payment_channels_enabled_secrets_594
        CHECK (NOT enabled OR provider IN ('plugin', 'crypto') OR secret_key_id IS NOT NULL);

ALTER TABLE recharge_orders_v1
    DROP CONSTRAINT recharge_orders_v1_channel_check,
    ADD CONSTRAINT recharge_orders_v1_channel_check CHECK (channel IN ('alipay', 'wechat', 'transfer', 'usdt'));
ALTER TABLE recharge_statistics_facts_v1
    DROP CONSTRAINT recharge_statistics_facts_v1_channel_check,
    ADD CONSTRAINT recharge_statistics_facts_v1_channel_check CHECK (channel IN ('alipay', 'wechat', 'transfer', 'usdt'));
ALTER TABLE recharge_payment_cancellations_v1
    DROP CONSTRAINT recharge_payment_cancellations_v1_provider_check,
    ADD CONSTRAINT recharge_payment_cancellations_v1_provider_check CHECK (provider IN ('alipay', 'wechat', 'usdt'));

CREATE TABLE payment_crypto_hd_cursors (
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    family text NOT NULL CHECK (family IN ('tron', 'evm')),
    xpub_fingerprint text NOT NULL CHECK (xpub_fingerprint ~ '^[0-9a-f]{16}$'),
    next_index bigint NOT NULL DEFAULT 0 CHECK (next_index BETWEEN 0 AND 2147483647),
    PRIMARY KEY (channel_id, family, xpub_fingerprint)
);

CREATE TABLE payment_crypto_addresses (
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    family text NOT NULL CHECK (family IN ('tron', 'evm')),
    address text NOT NULL CHECK (char_length(address) BETWEEN 30 AND 64),
    source text NOT NULL CHECK (source IN ('xpub', 'pool')),
    payer_ref text NOT NULL DEFAULT '' CHECK (char_length(payer_ref) <= 128),
    state text NOT NULL CHECK (state IN ('available', 'assigned')),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (channel_id, family, address),
    -- An address serves exactly one channel (no shared xpub / pool entry).
    UNIQUE (family, address)
);
CREATE INDEX payment_crypto_addresses_pool_594_idx ON payment_crypto_addresses (channel_id, family, created_at)
    WHERE state = 'available';

CREATE TABLE payment_crypto_invoices (
    id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    order_ref text NOT NULL CHECK (char_length(order_ref) BETWEEN 1 AND 128),
    payer_ref text NOT NULL DEFAULT '' CHECK (char_length(payer_ref) <= 128),
    network text NOT NULL CHECK (network IN ('tron', 'bsc', 'polygon', 'ethereum')),
    address text NOT NULL,
    contract text NOT NULL,
    decimals integer NOT NULL CHECK (decimals BETWEEN 1 AND 36),
    token_amount numeric(78,0) NOT NULL CHECK (token_amount > 0),
    received numeric(78,0) NOT NULL DEFAULT 0 CHECK (received >= 0),
    fiat_minor bigint NOT NULL CHECK (fiat_minor > 0),
    currency text NOT NULL CHECK (currency = 'CNY'),
    rate_id text NOT NULL,
    start_block bigint NOT NULL CHECK (start_block >= 0),
    state text NOT NULL CHECK (state IN ('awaiting_payment', 'partially_paid', 'paid', 'overpaid', 'underpaid_expired',
        'paid_late', 'expired', 'closed')),
    credited_tx text,
    created_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL CHECK (valid_until > created_at),
    grace_until timestamptz NOT NULL CHECK (grace_until >= valid_until),
    updated_at timestamptz NOT NULL
);
CREATE INDEX payment_crypto_invoices_order_594_idx ON payment_crypto_invoices (channel_id, order_ref, created_at DESC);
CREATE INDEX payment_crypto_invoices_open_594_idx ON payment_crypto_invoices (channel_id, network, grace_until);

CREATE TABLE payment_crypto_transfers (
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    network text NOT NULL,
    tx_hash text NOT NULL CHECK (char_length(tx_hash) BETWEEN 1 AND 128),
    log_index integer NOT NULL CHECK (log_index >= 0),
    from_address text NOT NULL DEFAULT '',
    to_address text NOT NULL,
    contract text NOT NULL,
    amount numeric(78,0) NOT NULL CHECK (amount >= 0),
    block_number bigint NOT NULL,
    block_time timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('detected', 'finalized', 'verified', 'rejected', 'reorged')),
    invoice_id text REFERENCES payment_crypto_invoices(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (channel_id, network, tx_hash, log_index)
);
CREATE INDEX payment_crypto_transfers_to_594_idx ON payment_crypto_transfers (channel_id, network, to_address, block_number);
CREATE INDEX payment_crypto_transfers_status_594_idx ON payment_crypto_transfers (channel_id, network, status)
    WHERE status IN ('detected', 'finalized');

CREATE TABLE payment_crypto_cursors (
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    network text NOT NULL,
    block_number bigint NOT NULL CHECK (block_number >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (channel_id, network)
);

-- Manual review desk: irregular USDT payments are never credited automatically.
CREATE TABLE payment_crypto_exceptions (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    order_id uuid REFERENCES recharge_orders_v1(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('underpaid', 'overpaid', 'paid_late', 'unattributed', 'reorged',
        'duplicate_payment', 'conflicting_fact')),
    invoice_id text NOT NULL DEFAULT '' CHECK (char_length(invoice_id) <= 64),
    transfer text NOT NULL DEFAULT '' CHECK (char_length(transfer) <= 200),
    detail jsonb NOT NULL CHECK (jsonb_typeof(detail) = 'object' AND octet_length(detail::text) <= 8192),
    dedupe_key text NOT NULL UNIQUE CHECK (char_length(dedupe_key) BETWEEN 1 AND 300),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at))
);
CREATE INDEX payment_crypto_exceptions_channel_594_idx ON payment_crypto_exceptions (channel_id, created_at DESC);

REVOKE ALL ON payment_crypto_hd_cursors, payment_crypto_addresses, payment_crypto_invoices, payment_crypto_transfers,
    payment_crypto_cursors, payment_crypto_exceptions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON payment_crypto_hd_cursors, payment_crypto_addresses, payment_crypto_invoices,
    payment_crypto_transfers, payment_crypto_cursors TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON payment_crypto_exceptions TO cdnca_control_app, cdnca_control_runtime;
