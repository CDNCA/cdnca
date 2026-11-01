-- 603 回退：撤 dns.records.manage。自定义角色或 API Key 仍引用它时拒绝回退（回退会让它们悄悄失效）。
LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    custom_role_revisions, api_keys IN ACCESS EXCLUSIVE MODE;

DO $migration_603_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 603 OR
       (SELECT max(version) FROM schema_migrations) <> 603 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=603 AND
        migration_id='603_dns_records_manage_permission' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 603 down requires the exact verified migration head' USING ERRCODE='P6031';
    END IF;
    IF EXISTS (SELECT 1 FROM custom_role_revisions WHERE 'dns.records.manage' = ANY(permissions)) OR
       EXISTS (SELECT 1 FROM api_keys WHERE 'dns.records.manage' = ANY(scopes)) THEN
        RAISE EXCEPTION 'migration 603 down refuses: custom roles or API keys hold dns.records.manage'
            USING ERRCODE='P6032';
    END IF;
END;
$migration_603_down$;

DROP TRIGGER roles_tenant_dns_records_manage_603 ON roles;
DROP FUNCTION grant_tenant_dns_records_manage_603();

ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name = 'dns.records.manage';
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TABLE tenant_system_role_grant_additions_603;
DELETE FROM custom_rbac_permission_catalog WHERE permission_name = 'dns.records.manage';
DELETE FROM permissions WHERE name = 'dns.records.manage';
