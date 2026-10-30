LOCK TABLE schema_migrations, access_scopes, roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_459_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 459 OR
       (SELECT max(version) FROM schema_migrations) <> 459 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=459 AND
        migration_id='459_tenant_system_role_grants' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 459 down requires the exact verified migration head' USING ERRCODE='P4591';
    END IF;
END;
$migration_459_down$;

DROP TRIGGER roles_tenant_system_role_grants_459 ON roles;
DROP FUNCTION grant_tenant_system_role_permissions_459();

-- 只撤本迁移新增的授权；迁移前已有的（030/037/044/068/134 回填）保持不动。
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions grant_row
USING tenant_system_role_grant_additions_459 addition
WHERE grant_row.role_id = addition.role_id AND grant_row.permission_name = addition.permission_name;
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TABLE tenant_system_role_grant_additions_459;
DROP FUNCTION tenant_system_role_grants_459(text);
