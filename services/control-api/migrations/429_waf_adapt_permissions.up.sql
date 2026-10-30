LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    waf_adapt_exclusions IN ACCESS EXCLUSIVE MODE;

DO $migration_429_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 428 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 428 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=428 AND
        migration_id='428_dnspup_probe' AND
        checksum_sha256='7b4bd22bf266163c468bcae6b4ce1399f2028b1b290e82fd448d309db056089a' AND
        down_checksum_sha256='3b696105c80aabb235d328931a4d43596f41aa46b9f14e8b2ec030b422737337' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM permissions WHERE name IN ('waf_adapt.read', 'waf_adapt.manage')) THEN
        RAISE EXCEPTION 'migration 429 requires the exact verified 428 release head' USING ERRCODE='P4290';
    END IF;
END;
$migration_429_up$;

-- 429（r136 ri-gaps2，占位号 432：合入时由主会话统一改号）。网站 WAF“智能自动”区
-- （ADR 0011 RI-06/RI-07）的权限码与驳回原因码：
--   waf_adapt.read：读排除、证据、确定类型与灰区挑战（GET sites/{site}/waf-adapt）；
--   waf_adapt.manage：采纳/驳回/撤销/设为人工/恢复自动与灰区挑战开关（同 security_policies.manage 需二次验证）。
--   现有 tenant_owner 两者都授予、tenant_viewer 只授予 read（含之后新建的租户：roles AFTER INSERT 触发器），
--   平台 platform_owner 两者（管理员代租户操作同时要 platform.admin）。
--   tenant_viewer 走系统角色守卫（094 guard_system_role_permission_mutation）原有的 *.read 规则，守卫不改。
--   waf_adapt_exclusions.reject_reason：人工驳回/撤销时的原因码（false_positive 误判 / attack 攻击 /
--   unneeded 不需要；ADR 0011 §4.3 waf_rejections 上报需要），其它阶段变化清空。

INSERT INTO permissions(name, description) VALUES
    ('waf_adapt.read', 'Read the adaptive WAF (smart auto) exclusions, evidence, typed parameters and grey zone challenge of sites'),
    ('waf_adapt.manage', 'Decide adaptive WAF exclusions (adopt, reject, revoke, manual, resume) and set the grey zone challenge of sites');

INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required) VALUES
    ('waf_adapt.read', false),
    ('waf_adapt.manage', true);

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id
CROSS JOIN (VALUES ('waf_adapt.read'), ('waf_adapt.manage')) AS permission(name)
WHERE role.system_role AND (
    (scope.kind = 'tenant' AND role.name = 'tenant_owner') OR
    (scope.kind = 'tenant' AND role.name = 'tenant_viewer' AND permission.name = 'waf_adapt.read') OR
    (scope.kind = 'platform' AND role.name = 'platform_owner'))
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_waf_adapt_permissions_429()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_scope_kind text;
BEGIN
    IF NOT NEW.system_role OR NEW.name NOT IN ('tenant_owner', 'tenant_viewer', 'platform_owner') THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO target_scope_kind FROM access_scopes WHERE id = NEW.scope_id;
    IF target_scope_kind = 'tenant' AND NEW.name IN ('tenant_owner', 'tenant_viewer') OR
       target_scope_kind = 'platform' AND NEW.name = 'platform_owner' THEN
        INSERT INTO role_permissions(role_id, permission_name) VALUES (NEW.id, 'waf_adapt.read') ON CONFLICT DO NOTHING;
        IF NEW.name <> 'tenant_viewer' THEN
            INSERT INTO role_permissions(role_id, permission_name) VALUES (NEW.id, 'waf_adapt.manage') ON CONFLICT DO NOTHING;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_waf_adapt_permissions_429
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_waf_adapt_permissions_429();

REVOKE ALL ON FUNCTION grant_waf_adapt_permissions_429() FROM PUBLIC;

ALTER TABLE waf_adapt_exclusions
    ADD COLUMN reject_reason text CHECK (reject_reason IN ('false_positive', 'attack', 'unneeded')),
    ADD CONSTRAINT waf_adapt_exclusions_reject_reason_429 CHECK (reject_reason IS NULL OR stage = 'rejected');
