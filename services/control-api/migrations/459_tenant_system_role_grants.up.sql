LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_459_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 458 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 458 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=458 AND
        migration_id='458_promotion_policy_archive' AND
        checksum_sha256='d528d0e45f9700a46b5064fc44d039cf4a9e9a75529d209b093b7401cb048271' AND
        down_checksum_sha256='4e0f8ab0c182ef72225383fae1b3bbc1b3f7698ea9e13c405f9776f13da86c86' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM permissions WHERE name IN (
            'url_auth_policies.read', 'url_auth_policies.manage',
            'identity_verification.self.manage', 'identity_verification.read', 'identity_verification.review',
            'identity_verification.evidence_settlement.requeue',
            'promotions.read', 'promotions.quote', 'promotions.redeem',
            'firewall.read', 'firewall.manage')) <> 11 THEN
        RAISE EXCEPTION 'migration 459 requires the exact verified 458 release head' USING ERRCODE='P4590';
    END IF;
END;
$migration_459_up$;

-- 459（r136 fix-perm，占位号：主会话预留 control 459，合入时改号并把前驱守卫改为 458）。
-- 030/037/044/068/134 只给“迁移时已存在”的 tenant_owner/tenant_viewer 一次性回填，没有
-- roles AFTER INSERT 触发器；之后新建的租户（管理员建用户、自助注册）一律缺这些权限
-- （live-click-A E2：t02 无 url_auth_policies.read → /site/url-auth 403；fix-session E5：
-- 无 identity_verification.* → 实名认证不可用）。本迁移：
--   1. 回填所有现有租户系统角色缺失的这些权限；
--   2. 加 roles AFTER INSERT 触发器，新建的租户系统角色同样获得；
--   3. 本迁移实际新增的授权记在 tenant_system_role_grant_additions_459，down 只撤这些。
-- 各权限的角色分配与原迁移一致：
--   tenant_owner：下列全部 11 项；
--   tenant_viewer：url_auth_policies.read(030)、identity_verification.self.manage(037)、promotions.read(044)。
-- 094 guard_system_role_permission_mutation 已放行以上组合，守卫不改。

CREATE TABLE tenant_system_role_grant_additions_459 (
    role_id uuid NOT NULL,
    permission_name text NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    CONSTRAINT tenant_system_role_grant_permission_fk_459
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE CASCADE
);

CREATE FUNCTION tenant_system_role_grants_459(role_name text)
RETURNS TABLE(permission_name text)
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT grant_row.permission_name
    FROM (VALUES
        ('url_auth_policies.read', true), ('url_auth_policies.manage', false),
        ('identity_verification.self.manage', true), ('identity_verification.read', false),
        ('identity_verification.review', false), ('identity_verification.evidence_settlement.requeue', false),
        ('promotions.read', true), ('promotions.quote', false), ('promotions.redeem', false),
        ('firewall.read', false), ('firewall.manage', false)
    ) AS grant_row(permission_name, viewer)
    WHERE role_name = 'tenant_owner' OR (role_name = 'tenant_viewer' AND grant_row.viewer);
$$;

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, grant_row.permission_name
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'tenant'
    CROSS JOIN LATERAL tenant_system_role_grants_459(role.name) grant_row
    WHERE role.system_role AND role.name IN ('tenant_owner', 'tenant_viewer')
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO tenant_system_role_grant_additions_459(role_id, permission_name)
SELECT role_id, permission_name FROM additions;

CREATE FUNCTION grant_tenant_system_role_permissions_459()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role OR NEW.name NOT IN ('tenant_owner', 'tenant_viewer') OR NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant'
    ) THEN
        RETURN NEW;
    END IF;
    WITH additions AS (
        INSERT INTO role_permissions(role_id, permission_name)
        SELECT NEW.id, grant_row.permission_name FROM tenant_system_role_grants_459(NEW.name) grant_row
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO tenant_system_role_grant_additions_459(role_id, permission_name)
    SELECT role_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_tenant_system_role_grants_459
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_tenant_system_role_permissions_459();

REVOKE ALL ON FUNCTION grant_tenant_system_role_permissions_459() FROM PUBLIC;
REVOKE ALL ON FUNCTION tenant_system_role_grants_459(text) FROM PUBLIC;
