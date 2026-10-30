LOCK TABLE schema_migrations, tenants, access_scopes, roles, role_permissions, permissions,
    node_line_group_grants, escalate_package_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_480_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 480 OR
       (SELECT max(version) FROM schema_migrations) <> 480 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=480 AND
        migration_id='480_reseller_core' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 480 down requires the exact verified migration head' USING ERRCODE='P4810';
    END IF;
    -- 479 没有代理商：有代理商或代理商客户时拒绝，而不是丢掉这些关系。
    IF EXISTS (SELECT 1 FROM reseller_profiles) OR EXISTS (SELECT 1 FROM tenants WHERE parent_scope_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 480 down refuses to drop recorded resellers' USING ERRCODE='P4811';
    END IF;
END;
$migration_480_down$;

DROP FUNCTION reseller_products_using_line_group_480(uuid, uuid, uuid);
DROP TRIGGER node_line_group_grants_reseller_480 ON node_line_group_grants;
DROP FUNCTION guard_line_group_grant_reseller_480();
DROP TRIGGER role_permissions_reseller_guard_480 ON role_permissions;
DROP FUNCTION guard_reseller_permission_480();
DELETE FROM role_permissions WHERE permission_name LIKE 'reseller.%';
DELETE FROM permissions WHERE name IN ('reseller.packages.manage', 'reseller.customers.manage', 'reseller.customers.read');
DROP TRIGGER tenants_parent_guard_480 ON tenants;
DROP FUNCTION guard_tenant_parent_480();
DROP INDEX tenants_parent_scope_idx;
ALTER TABLE tenants DROP COLUMN parent_scope_id;
DROP TABLE reseller_profiles;
DROP FUNCTION sync_reseller_permissions_480();
DROP FUNCTION guard_reseller_profile_480();
DROP FUNCTION reseller_scope_active_480(uuid);
