-- 607 回滚：去掉防火墙动作租户默认的回执列，恢复 605 守卫。
-- 已有默认被回执推进过（active/failed）时拒绝回滚：回滚后继承站点会改为下发当前修订，静默丢掉 LKG 回退。
LOCK TABLE schema_migrations, firewall_action_tenant_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_607_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 607 OR
       (SELECT max(version) FROM schema_migrations) <> 607 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=607 AND
        migration_id='607_firewall_action_default_receipt' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 607 down requires the exact verified migration head' USING ERRCODE='P6073';
    END IF;
    IF EXISTS (SELECT 1 FROM firewall_action_tenant_defaults WHERE deployment_state<>'pending') THEN
        RAISE EXCEPTION 'migration 607 down would discard firewall action default receipts' USING ERRCODE='P6074';
    END IF;
END;
$migration_607_down$;

DROP TRIGGER firewall_action_tenant_defaults_guard_607 ON firewall_action_tenant_defaults;
DROP FUNCTION guard_firewall_action_tenant_default_607();
CREATE TRIGGER firewall_action_tenant_defaults_guard_605
BEFORE UPDATE OR DELETE ON firewall_action_tenant_defaults
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_tenant_default_605();
ALTER TABLE firewall_action_tenant_defaults
    DROP CONSTRAINT firewall_action_tenant_defaults_deployment_607,
    DROP COLUMN deployment_state,
    DROP COLUMN lkg_revision,
    DROP COLUMN active_revision;
