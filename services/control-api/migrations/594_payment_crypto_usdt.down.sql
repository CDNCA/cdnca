-- 594 回滚：去掉 USDT 充值。已有 crypto 渠道或 USDT 充值单时拒绝回滚（不静默删除链上收款记录）。
LOCK TABLE schema_migrations, payment_channels, recharge_orders_v1, recharge_statistics_facts_v1,
    recharge_payment_cancellations_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_594_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 594 OR
       (SELECT max(version) FROM schema_migrations) <> 594 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=594 AND
        migration_id='594_payment_crypto_usdt' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 594 down requires the exact verified migration head' USING ERRCODE='P5941';
    END IF;
    IF EXISTS (SELECT 1 FROM payment_channels WHERE provider = 'crypto' OR method = 'usdt') OR
       EXISTS (SELECT 1 FROM recharge_orders_v1 WHERE channel = 'usdt') OR
       EXISTS (SELECT 1 FROM payment_crypto_invoices) THEN
        RAISE EXCEPTION 'migration 594 down refuses existing USDT channels or recharge orders' USING ERRCODE='P5942';
    END IF;
END;
$migration_594_down$;

DROP TABLE payment_crypto_exceptions, payment_crypto_cursors, payment_crypto_transfers, payment_crypto_invoices,
    payment_crypto_addresses, payment_crypto_hd_cursors;

ALTER TABLE recharge_payment_cancellations_v1
    DROP CONSTRAINT recharge_payment_cancellations_v1_provider_check,
    ADD CONSTRAINT recharge_payment_cancellations_v1_provider_check CHECK (provider IN ('alipay', 'wechat'));
ALTER TABLE recharge_statistics_facts_v1
    DROP CONSTRAINT recharge_statistics_facts_v1_channel_check,
    ADD CONSTRAINT recharge_statistics_facts_v1_channel_check CHECK (channel IN ('alipay', 'wechat', 'transfer'));
ALTER TABLE recharge_orders_v1
    DROP CONSTRAINT recharge_orders_v1_channel_check,
    ADD CONSTRAINT recharge_orders_v1_channel_check CHECK (channel IN ('alipay', 'wechat', 'transfer'));

ALTER TABLE payment_channels
    DROP CONSTRAINT payment_channels_enabled_secrets_594,
    ADD CONSTRAINT payment_channels_enabled_secrets_402
        CHECK (NOT enabled OR provider = 'plugin' OR secret_key_id IS NOT NULL),
    DROP CONSTRAINT payment_channels_crypto_scenes_594,
    DROP CONSTRAINT payment_channels_crypto_method_594,
    DROP CONSTRAINT payment_channels_method_check,
    ADD CONSTRAINT payment_channels_method_check CHECK (method IN ('alipay', 'wxpay'));
