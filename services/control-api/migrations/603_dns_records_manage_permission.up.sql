-- 603（r136 plugapi-S1，调度预留 control 603，前驱 602 = fix-urlauthname）：
-- 插件开放接口：DNS 统一管理（/v1/dns/hub/*）的记录写入可由租户 API Key 调用。dns.manage 同时管
-- DNS 账号凭据（/v1/dns/providers 建/改/删/验证），把它交给插件会让插件能换掉客户的 DNS 密钥，
-- 所以新增只管记录的 dns.records.manage：
--   1. permissions + custom_rbac_permission_catalog（不要求 step-up，与 dns.manage 一致）；
--   2. 回填现有租户系统角色：凡已持有 dns.manage 的租户系统角色都获得 dns.records.manage
--      （tenant_owner 必有；其余系统角色若有 dns.manage 也一并获得，tenant_viewer 没有 dns.manage）；
--   3. roles AFTER INSERT 触发器：新建的 tenant_owner 同样获得（SeedTenantSystemRoles 不列它）；
--   4. 本迁移实际新增的授权记在 tenant_system_role_grant_additions_603，down 只撤这些。
-- 094 guard_system_role_permission_mutation 对 *.manage 只限制 tenant_viewer，守卫不改。
LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog
    IN ACCESS EXCLUSIVE MODE;

DO $migration_603_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 602 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 602 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=602 AND
        migration_id='602_url_auth_legacy_marker' AND
        checksum_sha256='4ebaa480871895f61c02b8a6fa4862ef2898184797441403bbc0d37fa513a57b' AND
        down_checksum_sha256='36e4c801af3b722cbbbff8de5e5d7d8171e8731b7337baf606543a25278f4a59' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (SELECT 1 FROM permissions WHERE name = 'dns.manage')
         OR EXISTS (SELECT 1 FROM permissions WHERE name = 'dns.records.manage') THEN
        RAISE EXCEPTION 'migration 603 requires the exact verified 602 release head' USING ERRCODE='P6030';
    END IF;
END;
$migration_603_up$;

INSERT INTO permissions(name, description) VALUES
    ('dns.records.manage', 'Create, update and delete records of the tenant''s own DNS domains in the DNS hub (not DNS account credentials)');

INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required) VALUES
    ('dns.records.manage', false);

CREATE TABLE tenant_system_role_grant_additions_603 (
    role_id uuid NOT NULL,
    permission_name text NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    CONSTRAINT tenant_system_role_grant_permission_fk_603
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE CASCADE
);

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, 'dns.records.manage'
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'tenant'
    WHERE role.system_role AND EXISTS (
        SELECT 1 FROM role_permissions held WHERE held.role_id = role.id AND held.permission_name = 'dns.manage')
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO tenant_system_role_grant_additions_603(role_id, permission_name)
SELECT role_id, permission_name FROM additions;

CREATE FUNCTION grant_tenant_dns_records_manage_603()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role OR NEW.name <> 'tenant_owner' OR NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant'
    ) THEN
        RETURN NEW;
    END IF;
    WITH additions AS (
        INSERT INTO role_permissions(role_id, permission_name)
        VALUES (NEW.id, 'dns.records.manage')
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO tenant_system_role_grant_additions_603(role_id, permission_name)
    SELECT role_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_tenant_dns_records_manage_603
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_tenant_dns_records_manage_603();

REVOKE ALL ON FUNCTION grant_tenant_dns_records_manage_603() FROM PUBLIC;
