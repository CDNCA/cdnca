-- 556 回滚：去掉对接密钥、nonce、对接日志与 billing_bridge.manage。
-- 已建过对接密钥时，财务系统那边正在用它们；回滚会让对接悄悄失效并丢掉对接日志，此时拒绝回滚。
LOCK TABLE schema_migrations, billing_bridge_keys, billing_bridge_nonces, billing_bridge_logs, role_permissions, permissions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_556_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 556 OR
       (SELECT max(version) FROM schema_migrations) <> 556 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=556 AND
        migration_id='556_billing_bridge_keys' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 556 down requires the exact verified migration head' USING ERRCODE='P5565';
    END IF;
    IF EXISTS (SELECT 1 FROM billing_bridge_keys) OR EXISTS (SELECT 1 FROM billing_bridge_logs) THEN
        RAISE EXCEPTION 'migration 556 rollback would discard billing bridge keys or logs' USING ERRCODE='P5566';
    END IF;
END;
$migration_556_down$;

DELETE FROM role_permissions WHERE permission_name = 'billing_bridge.manage';
DELETE FROM permissions WHERE name = 'billing_bridge.manage';
DROP TABLE billing_bridge_logs;
DROP TABLE billing_bridge_nonces;
DROP TABLE billing_bridge_keys;
DROP FUNCTION guard_billing_bridge_key_556();
DROP FUNCTION billing_bridge_ip_allowlist_valid_556(cidr[]);
