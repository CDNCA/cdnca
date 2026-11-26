-- 685（前驱 684_plugin_installation_license_reports）。
-- 找回密码按注册时验证过的邮箱定位账号：按账号的注册幂等键摘要匹配已消费的邮箱证明
-- （account_registration_proofs_162.consumed_idempotency_digest，等值连接）。该列原本没有索引，每次按邮箱找回
-- 都要全表扫描，匿名请求可以借此放大负载；只给已消费的证明（use_revision=1）建部分索引。
-- 错误码：头检查 P6850；down 头检查 P6851。
LOCK TABLE schema_migrations, account_registration_proofs_162 IN ACCESS EXCLUSIVE MODE;

DO $migration_685_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 684 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 684 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=684 AND
        migration_id='684_plugin_installation_license_reports' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('account_registration_proofs_consumed_685') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 685 requires the exact verified 684 release head' USING ERRCODE='P6850';
    END IF;
END;
$migration_685_up$;

CREATE INDEX account_registration_proofs_consumed_685
    ON account_registration_proofs_162 (consumed_idempotency_digest)
    WHERE use_revision = 1;
