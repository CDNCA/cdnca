-- 574（fix-apikeysimple）：API 密钥 scopes 上限 32 → 128。
-- 用户端 API 密钥页简单版"打开开关即生成全部权限、不过期的密钥"，tenant_owner 可授权的安全权限
-- （去掉 identity.* / api_keys.* / platform.admin）已超过 32 个。鉴权模型不变：鉴权时仍取
-- 密钥 scopes 与持有人当前权限的交集（internal/apikey AuthenticateWithKeyID）。
-- 前驱：集成头 552（usage_report_state）；合入时若有并行任务先占 574，守卫改钉当时头号。
LOCK TABLE schema_migrations, api_keys IN ACCESS EXCLUSIVE MODE;

DO $migration_574_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 573 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 573 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=573 AND
        migration_id='573_node_gateway_address_changes' AND
        checksum_sha256='b8cc8181cbf0a625d7b922abeeb3d32e322c547dd286e84ea902172da86fe18c' AND
        down_checksum_sha256='087de3f98d24ad34f991c6930d9159179062590d08d34959d03badfa36d4e50e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid='api_keys'::regclass AND conname='api_keys_scopes_check'
       ) THEN
        RAISE EXCEPTION 'migration 574 requires the exact verified 573 release head' USING ERRCODE='P5740';
    END IF;
END;
$migration_574_up$;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_scopes_check,
    ADD CONSTRAINT api_keys_scopes_check CHECK (cardinality(scopes) BETWEEN 1 AND 128);
