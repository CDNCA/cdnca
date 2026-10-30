LOCK TABLE schema_migrations, permissions, roles, role_permissions, theme_packages,
    theme_tenant_policy, theme_tenant_settings, theme_tenant_domains IN ACCESS EXCLUSIVE MODE;

DO $migration_373_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 373 OR
       (SELECT max(version) FROM schema_migrations) <> 373 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=373 AND
        migration_id='373_theme_tenant_whitelabel' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 373 down requires the exact verified migration head' USING ERRCODE='P3736';
    END IF;
    -- Tenant choices change what tenants and their node error pages show;
    -- refuse rather than silently fall every tenant back to the platform theme.
    IF EXISTS (SELECT 1 FROM theme_tenant_settings) OR EXISTS (SELECT 1 FROM theme_tenant_domains) THEN
        RAISE EXCEPTION 'migration 373 down refuses to drop tenant theme choices in use' USING ERRCODE='P3737';
    END IF;
END;
$migration_373_down$;

DROP TRIGGER roles_tenant_owner_theme_373 ON roles;
DROP TRIGGER theme_packages_tenant_selected_373 ON theme_packages;
DROP TABLE theme_tenant_domains;
DROP TABLE theme_tenant_settings;
DROP TABLE theme_tenant_policy;
DROP FUNCTION grant_tenant_theme_to_tenant_owner_373();
DROP FUNCTION protect_tenant_theme_package_373();
DROP FUNCTION validate_theme_tenant_policy_373();
DROP FUNCTION validate_theme_tenant_row_373();
DELETE FROM role_permissions WHERE permission_name = 'tenant_theme.manage';
DELETE FROM permissions WHERE name = 'tenant_theme.manage';
