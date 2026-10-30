-- 600 回退：撤掉租户聚合边缘权限码、归属触发器与套餐 limits 包装函数，列名改回 platform_scope_id。
-- 存在租户归属的账号/供给/导入时拒绝回退（回退后这些行会被当成平台的）。
LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    custom_role_revisions, cdn_provider_accounts, site_supplies, cdn_zone_imports, site_supply_bindings,
    site_supply_cdn_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_600_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 600 OR
       (SELECT max(version) FROM schema_migrations) <> 600 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=600 AND
        migration_id='600_aggregated_edge_owner_scope' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 600 down requires the exact verified migration head' USING ERRCODE='P6004';
    END IF;
    IF EXISTS (SELECT 1 FROM custom_role_revisions WHERE permissions &&
               ARRAY['edge.tenant.read', 'edge.tenant.manage', 'edge.tenant.accounts.manage']::text[]) THEN
        RAISE EXCEPTION 'migration 600 down refuses: custom roles hold edge.tenant permissions' USING ERRCODE='P6005';
    END IF;
    IF EXISTS (SELECT 1 FROM cdn_provider_accounts row JOIN access_scopes scope ON scope.id = row.owner_scope_id
               WHERE scope.kind = 'tenant') OR
       EXISTS (SELECT 1 FROM site_supplies row JOIN access_scopes scope ON scope.id = row.owner_scope_id
               WHERE scope.kind = 'tenant') OR
       EXISTS (SELECT 1 FROM cdn_zone_imports row JOIN access_scopes scope ON scope.id = row.owner_scope_id
               WHERE scope.kind = 'tenant') THEN
        RAISE EXCEPTION 'migration 600 down refuses: tenant-owned aggregated edge rows exist' USING ERRCODE='P6006';
    END IF;
END;
$migration_600_down$;

DROP FUNCTION package_offer_spec_publishable_090(jsonb, timestamptz);
ALTER FUNCTION package_offer_spec_publishable_090_base(jsonb, timestamptz) RENAME TO package_offer_spec_publishable_090;

DROP TRIGGER roles_tenant_edge_permissions_600 ON roles;
DROP FUNCTION grant_tenant_edge_permissions_600();
DROP FUNCTION tenant_edge_permissions_600(text);
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name IN ('edge.tenant.read', 'edge.tenant.manage', 'edge.tenant.accounts.manage');
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM custom_rbac_permission_catalog WHERE permission_name IN ('edge.tenant.read', 'edge.tenant.manage', 'edge.tenant.accounts.manage');
DELETE FROM permissions WHERE name IN ('edge.tenant.read', 'edge.tenant.manage', 'edge.tenant.accounts.manage');

DROP TRIGGER cdn_zone_imports_owner_immutable_600 ON cdn_zone_imports;
DROP TRIGGER site_supplies_owner_immutable_600 ON site_supplies;
DROP TRIGGER cdn_provider_accounts_owner_immutable_600 ON cdn_provider_accounts;
DROP FUNCTION aggregated_edge_owner_immutable_600();
DROP TRIGGER site_supply_cdn_configs_account_owner_600 ON site_supply_cdn_configs;
DROP FUNCTION aggregated_edge_config_account_owner_600();
DROP TRIGGER site_supply_bindings_owner_600 ON site_supply_bindings;
DROP FUNCTION aggregated_edge_binding_owner_600();

DROP INDEX site_supplies_owner_scope_600_idx;
ALTER TABLE cdn_zone_imports RENAME COLUMN owner_scope_id TO platform_scope_id;
ALTER TABLE site_supplies RENAME COLUMN owner_scope_id TO platform_scope_id;
ALTER TABLE cdn_provider_accounts RENAME COLUMN owner_scope_id TO platform_scope_id;
