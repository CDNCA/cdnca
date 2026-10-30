-- 585 回滚：去掉 resource_scope 与平台插件安装权限。已有平台作用域 head 时拒绝回滚（回滚后租户守卫无法区分）。
LOCK TABLE schema_migrations, plugin_installation_heads, role_permissions, permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_585_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 585 OR
       (SELECT max(version) FROM schema_migrations) <> 585 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=585 AND
        migration_id='585_plugin_installation_resource_scope' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 585 down requires the exact verified migration head' USING ERRCODE='P5853';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_installation_heads WHERE resource_scope='platform') THEN
        RAISE EXCEPTION 'migration 585 down refuses platform plugin installations' USING ERRCODE='P5854';
    END IF;
END;
$migration_585_down$;

DELETE FROM role_permissions
WHERE permission_name IN ('plugin_installations.platform.read','plugin_installations.platform.manage');
DELETE FROM permissions
WHERE name IN ('plugin_installations.platform.read','plugin_installations.platform.manage');

DROP TRIGGER plugin_installation_heads_resource_scope_585 ON plugin_installation_heads;
DROP FUNCTION validate_plugin_installation_resource_scope_585();
DROP INDEX plugin_installation_heads_platform_585_idx;
ALTER TABLE plugin_installation_heads DROP COLUMN resource_scope;
