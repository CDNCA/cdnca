LOCK TABLE schema_migrations, users IN ACCESS EXCLUSIVE MODE;

DO $migration_487_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 486 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 486 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=486 AND
        migration_id='486_shared_node_host_firewall' AND
        checksum_sha256='88269053938a4cc883c4b713bdf93f412e9f8d9eecb60c876f8790c5d32110e7' AND
        down_checksum_sha256='1b2123bcf4fdbd59ff791f1e5a2aad79f5c497e7fdb221b7b993bbb702995fc2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('tenant_member_password_reset_results') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 487 requires the exact verified 486 release head' USING ERRCODE='P4870';
    END IF;
END;
$migration_487_up$;

-- 487（r136 u2-identity，TENANT-PWRESET-UNKNOWN，用户 10-24 23:5x Q3；本地占位 = 集成头 484+1，合入时改 493 并重钉前驱，P487x 随号改）。
-- 租户管理员重置成员密码时，响应可能丢失：服务端已改密并撤会话，管理员却没拿到新密码。
-- 这里把生成的临时密码加密留存 10 分钟（expires_at），绑定操作者（actor_user_id + actor_scope_id）、
-- 成员与幂等键；同一操作者用同一幂等键再提交一次即取回，取回后立刻清掉密文（envelope/key_id 置空、
-- retrieved_at 记时间）。墓碑行保留 24 小时，期间同一幂等键返回"已取回/已过期"而不会再重置一次。
-- 清理在现有每分钟定时任务里做（过期清密文、超 24 小时删行）。
--
-- 错误码：P4870 前驱不符；P4871 down 前驱不符。

CREATE TABLE tenant_member_password_reset_results (
    idempotency_key text PRIMARY KEY CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_scope_id uuid NOT NULL,
    member_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id text,
    envelope bytea,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    retrieved_at timestamptz,
    CHECK ((key_id IS NULL) = (envelope IS NULL)),
    CHECK (retrieved_at IS NULL OR envelope IS NULL),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX tenant_member_password_reset_results_created_idx ON tenant_member_password_reset_results (created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_member_password_reset_results TO cdnca_control_app, cdnca_control_runtime;
