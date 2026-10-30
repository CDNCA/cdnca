-- 486 down：终结的命令与发布是事实，不恢复排队（恢复会把租户宿主规则重新投到共享节点）。
-- 外键恢复为 134 的单条形状；已有 global 命令行时拒绝（134 形状装不下它们）。
LOCK TABLE schema_migrations, firewall_command_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_486_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 486 OR
       (SELECT max(version) FROM schema_migrations) <> 486 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=486 AND
        migration_id='486_shared_node_host_firewall' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 486 down requires the exact verified migration head' USING ERRCODE='P4861';
    END IF;
    IF EXISTS (SELECT 1 FROM firewall_command_outbox WHERE policy_kind='global') THEN
        RAISE EXCEPTION 'migration 486 down would orphan global firewall commands' USING ERRCODE='P4862';
    END IF;
END;
$migration_486_down$;

ALTER TABLE firewall_command_outbox
    DROP CONSTRAINT firewall_command_outbox_global_policy_486_fkey,
    DROP CONSTRAINT firewall_command_outbox_security_policy_486_fkey,
    DROP COLUMN global_policy_id,
    DROP COLUMN security_policy_kind,
    ADD CONSTRAINT firewall_command_outbox_tenant_policy_kind_fkey
        FOREIGN KEY(tenant_scope_id,policy_id,policy_kind) REFERENCES security_policies(scope_id,id,kind) ON DELETE RESTRICT;
