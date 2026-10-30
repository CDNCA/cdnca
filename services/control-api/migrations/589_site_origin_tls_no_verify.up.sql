-- 589（fix-originnoverify，主会话占位 602；加载器要求连号，本地按集成头 574+1 写，合入时改号重钉）：
-- 回源 HTTPS 加"不校验源站证书"：site_origin_pools.tls_trust 增加 'none'（源站自签证书时选，存在中间人风险）。
-- 'none' 与 'system' 一样不带 CA（tls_ca_379 约束只要求 custom 才有 CA，不用改）；HTTP 回源仍只能 'system'（ports_494 不改）。
-- 发布需要节点能力 ORIGIN_TLS_NO_VERIFY（77，原生补丁 29），没有的节点拒发并给原因。
-- 前驱：588（cache_account_quotas）。
LOCK TABLE schema_migrations, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_589_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 588 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 588 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=588 AND
        migration_id='588_cache_account_quotas' AND
        checksum_sha256='c63c8624454b69bdaceddd9b17d810bcc04e80fed2ea5511f8e7c56168a4e257' AND
        down_checksum_sha256='b54815eb77c437e27e5ac937c591ffd185a7e060dc8775ddad77ce222cbd2f78' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid='site_origin_pools'::regclass AND conname='site_origin_pools_tls_trust_check'
       ) THEN
        RAISE EXCEPTION 'migration 589 requires the exact verified 588 release head' USING ERRCODE='P5890';
    END IF;
END;
$migration_589_up$;

ALTER TABLE site_origin_pools
    DROP CONSTRAINT site_origin_pools_tls_trust_check,
    ADD CONSTRAINT site_origin_pools_tls_trust_check CHECK (tls_trust IN ('system', 'custom', 'none'));
