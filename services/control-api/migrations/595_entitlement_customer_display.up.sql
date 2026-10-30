-- 595（fix-licui2，原占位 594；merge-p26 合入时改号为 595，前驱重钉 594_payment_crypto_usdt）：
-- 授权端在续期/激活响应里附带只读的 customer_display（客户名称与授权端登录账号，不进签名租约），
-- 主控存到 control_installation_entitlement.customer_display，首页授权区块显示“授权客户：名称（登录账号）”。
-- 只在响应带该字段时覆盖；NULL = 尚未收到。1.0.35 全新安装，不涉及旧数据。
-- 前驱：594_payment_crypto_usdt。
LOCK TABLE schema_migrations, control_installation_entitlement IN ACCESS EXCLUSIVE MODE;

DO $migration_595_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 594 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 594 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=594 AND
        migration_id='594_payment_crypto_usdt' AND
        checksum_sha256='5c1ce91d49408eadbfe004f91b039450840e6d95f254befcc5b782a6c348d334' AND
        down_checksum_sha256='e217d202fccdd8893daa276c2eb4e4921563954116727abea3aae4d73903d8aa' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='control_installation_entitlement' AND
            column_name='customer_display'
       ) THEN
        RAISE EXCEPTION 'migration 595 requires the exact verified 594 release head' USING ERRCODE='P5950';
    END IF;
END;
$migration_595_up$;

ALTER TABLE control_installation_entitlement
    ADD COLUMN customer_display jsonb
        CONSTRAINT control_installation_entitlement_customer_display_595_check CHECK (
            jsonb_typeof(customer_display) = 'object' AND octet_length(customer_display::text) <= 2048 AND
            jsonb_typeof(customer_display->'name') = 'string'
        );
