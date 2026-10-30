LOCK TABLE schema_migrations, admin_impersonation_grants IN ACCESS EXCLUSIVE MODE;

DO $migration_464_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 463 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 463 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=463 AND
        migration_id='463_dns_provider_namecom' AND
        checksum_sha256='b3bb9cdf50b04f0e4ade41ec6d00550b173f8e20ff8a6b9583e46316403b8434' AND
        down_checksum_sha256='079e199db4b99bbb307c2db9a70a3b8e35b0ec442df0c7970d056bbd4a8d4487' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='admin_impersonation_grants' AND column_name IN (
            'ticket', 'step_up_method', 'step_up_evidence_id', 'step_up_at', 'step_up_expires_at')) <> 5 THEN
        RAISE EXCEPTION 'migration 464 requires the exact verified 463 release head' USING ERRCODE='P4640';
    END IF;
END;
$migration_464_up$;

-- 464（r136 switch-login，占位号：主会话预留 control 464，本分支按 459 头连号为 464，
-- 合入时改号并把前驱守卫改为当时的头）。
-- 用户 10-23 定：主控用户列表「切换」直接以该用户身份登录，不再填工单号、原因，也不做
-- 动态验证码二次验证。因此代登录授权不再记录工单号与 step-up 证据；reason 列保留，
-- 由服务端固定写 'user_list_switch'。会话有效期、撤销、敏感操作拒绝、禁止嵌套不变。
-- 删列会由 PostgreSQL 一并删除涉及这些列的 CHECK（含 step_up 时间窗）与
-- UNIQUE (actor_scope_id, step_up_evidence_id)。
ALTER TABLE admin_impersonation_grants
    DROP COLUMN ticket,
    DROP COLUMN step_up_method,
    DROP COLUMN step_up_evidence_id,
    DROP COLUMN step_up_at,
    DROP COLUMN step_up_expires_at;
