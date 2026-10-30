-- 585（fix-plugconfirm，占位号；合入时按集成头连号并重钉前驱）：插件安装 head 记录资源作用域。
-- 报告 A：用户控制台主题、规则数据包等实例级资源由主控平台管理员确认，租户扩展由该租户确认。
-- resource_scope 来自授权端签名的候选/激活事实（清单 entrypoint 推导），必须与 head 所在 access_scope
-- 的 kind 一致且不可改写；平台确认的 head 存在平台 access_scope 下（memberships/receipts 外键原样可用）。
-- 新权限 plugin_installations.platform.read / .manage 只授予平台 platform_owner（不进入租户角色）。
-- 1.0.35 全新安装、不保留旧数据：既有 head 按所在 access_scope 的 kind 回填。
-- 前驱：584（recharge_payment_compensations）。
LOCK TABLE schema_migrations, access_scopes, plugin_installation_heads, roles, role_permissions, permissions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_585_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 584 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 584 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=584 AND
        migration_id='584_recharge_payment_compensations' AND
        checksum_sha256='55913a3b89e36e5041ebda5cfdb037c8f5b2962c32c4dd354bfc6d1f2e0403a6' AND
        down_checksum_sha256='c04940f5184e01162ae638f94fb3411cceb70f8b01884314f5050c1ced75e491' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='plugin_installation_heads' AND column_name='resource_scope'
       ) OR EXISTS (
        SELECT 1 FROM permissions
        WHERE name IN ('plugin_installations.platform.read','plugin_installations.platform.manage')
       ) THEN
        RAISE EXCEPTION 'migration 585 requires the exact verified 584 release head' USING ERRCODE='P5850';
    END IF;
END;
$migration_585_up$;

-- 默认 tenant：既有租户写入不变；平台作用域写入必须显式给 platform，否则下方触发器拒绝（P5852）。
ALTER TABLE plugin_installation_heads ADD COLUMN resource_scope text NOT NULL DEFAULT 'tenant';
-- 回填不是业务状态转移（不加 revision），581 的 head 转移触发器会拒绝（P1451）：回填期间停用，表已 ACCESS EXCLUSIVE 锁定。
ALTER TABLE plugin_installation_heads DISABLE TRIGGER plugin_installation_heads_transition_581;
UPDATE plugin_installation_heads head SET resource_scope=scope.kind
FROM access_scopes scope WHERE scope.id=head.tenant_scope_id AND scope.kind<>head.resource_scope;
ALTER TABLE plugin_installation_heads ENABLE TRIGGER plugin_installation_heads_transition_581;
ALTER TABLE plugin_installation_heads
    ADD CONSTRAINT plugin_installation_heads_resource_scope_585_check
        CHECK (resource_scope IN ('platform','tenant'));

CREATE INDEX plugin_installation_heads_platform_585_idx
    ON plugin_installation_heads(plugin_id,status,updated_at DESC)
    WHERE resource_scope='platform';

-- resource_scope 必须等于所在 access_scope 的 kind，且之后不可改。
CREATE FUNCTION validate_plugin_installation_resource_scope_585()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.resource_scope IS DISTINCT FROM OLD.resource_scope THEN
        RAISE EXCEPTION 'plugin installation resource scope is immutable' USING ERRCODE='P5851';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM access_scopes scope
                   WHERE scope.id=NEW.tenant_scope_id AND scope.kind=NEW.resource_scope) THEN
        RAISE EXCEPTION 'plugin installation resource scope does not match its access scope' USING ERRCODE='P5852';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_installation_heads_resource_scope_585
BEFORE INSERT OR UPDATE ON plugin_installation_heads
FOR EACH ROW EXECUTE FUNCTION validate_plugin_installation_resource_scope_585();

INSERT INTO permissions(name,description) VALUES
    ('plugin_installations.platform.read','Read platform plugin installations (themes, rule data packs)'),
    ('plugin_installations.platform.manage','Confirm, upgrade, disable, and uninstall platform plugins');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
CROSS JOIN (VALUES ('plugin_installations.platform.read'),('plugin_installations.platform.manage')) AS permission(name)
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;
