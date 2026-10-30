LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    cdn_provider_accounts, site_supplies, cdn_zone_imports, site_supply_bindings, site_supply_cdn_configs
    IN ACCESS EXCLUSIVE MODE;

DO $migration_600_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 599 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 599 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=599 AND
        migration_id='599_tenant_dns_hub' AND
        checksum_sha256='b77d0ad667929d25e0662953d9cf76e1addbb3ea01d363a60c7859c0fc20a600' AND
        down_checksum_sha256='ce3dfbd0dd0cb3f121eb18e8ee54678af8392599dbfcacebe7162835eaf61418' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM permissions WHERE name IN (
            'edge.tenant.read', 'edge.tenant.manage', 'edge.tenant.accounts.manage')) THEN
        RAISE EXCEPTION 'migration 600 requires the exact verified 599 release head' USING ERRCODE='P6000';
    END IF;
END;
$migration_600_up$;

-- 600（r136 fix-edgeowner，ADR 0020 §4.1 第②期地基；主会话预留 control 600，前驱 599 = fix-dnshub-api，
-- 本分支守卫里 599 的 migration_id 与两个校验和是占位，合并批统一重钉）。聚合边缘按所有者归属：
--   1. cdn_provider_accounts / site_supplies / cdn_zone_imports 的 platform_scope_id 改名 owner_scope_id
--      （平台或租户 scope；唯一键 (owner_scope_id,name) 随列改名）。全新安装，不做旧数据兼容（BATCH 第 9 条）。
--   2. 防线触发器：
--      · site_supply_bindings：供给 owner 必须是站点 scope 或平台 scope（同 fallbackchain.go SupplyEligible），P6001；
--      · site_supply_cdn_configs：账号 owner 必须等于供给 owner（租户不能用平台或他人的账号，反之亦然），P6002；
--      · 三张表 owner_scope_id 建后不可改（改 owner 会绕过以上两道），P6003。
--   3. 权限码（照 429/459：回填现有租户系统角色 + roles AFTER INSERT 触发器 + custom_rbac_permission_catalog）：
--      edge.tenant.read（tenant_owner/tenant_admin/tenant_viewer）、edge.tenant.manage（tenant_owner/tenant_admin）、
--      edge.tenant.accounts.manage（tenant_owner，step-up）。tenant_viewer 走 094 守卫的 *.read 规则，守卫不改。
--   4. 套餐 limits 新增可选键 aggregated_edge（布尔）、aggregated_edge_accounts（-1 不限 / 0..1000）：
--      090 package_offer_spec_publishable_090 要求 limits 键集合精确匹配，故改名为 _base，同名包装函数校验并剥掉
--      这两个键后交给 _base（481/532 的上架触发器按名调用，自动走包装）。

ALTER TABLE cdn_provider_accounts RENAME COLUMN platform_scope_id TO owner_scope_id;
ALTER TABLE site_supplies RENAME COLUMN platform_scope_id TO owner_scope_id;
ALTER TABLE cdn_zone_imports RENAME COLUMN platform_scope_id TO owner_scope_id;
CREATE INDEX site_supplies_owner_scope_600_idx ON site_supplies (owner_scope_id);

CREATE FUNCTION aggregated_edge_binding_owner_600()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM site_supplies supply JOIN sites site ON site.id = NEW.site_id
        JOIN access_scopes owner ON owner.id = supply.owner_scope_id
        WHERE supply.id = NEW.supply_id AND (supply.owner_scope_id = site.scope_id OR owner.kind = 'platform')) THEN
        RAISE EXCEPTION 'a supply can only carry its owner''s sites or be the platform''s' USING ERRCODE='P6001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_supply_bindings_owner_600
BEFORE INSERT OR UPDATE OF site_id, supply_id ON site_supply_bindings
FOR EACH ROW EXECUTE FUNCTION aggregated_edge_binding_owner_600();

CREATE FUNCTION aggregated_edge_config_account_owner_600()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.account_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM site_supplies supply JOIN cdn_provider_accounts account ON account.id = NEW.account_id
        WHERE supply.id = NEW.supply_id AND account.owner_scope_id = supply.owner_scope_id) THEN
        RAISE EXCEPTION 'a supply can only use an account of its own owner' USING ERRCODE='P6002';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_supply_cdn_configs_account_owner_600
BEFORE INSERT OR UPDATE OF supply_id, account_id ON site_supply_cdn_configs
FOR EACH ROW EXECUTE FUNCTION aggregated_edge_config_account_owner_600();

CREATE FUNCTION aggregated_edge_owner_immutable_600()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.owner_scope_id IS DISTINCT FROM OLD.owner_scope_id THEN
        RAISE EXCEPTION 'aggregated edge owner_scope_id is immutable' USING ERRCODE='P6003';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cdn_provider_accounts_owner_immutable_600
BEFORE UPDATE OF owner_scope_id ON cdn_provider_accounts
FOR EACH ROW EXECUTE FUNCTION aggregated_edge_owner_immutable_600();
CREATE TRIGGER site_supplies_owner_immutable_600
BEFORE UPDATE OF owner_scope_id ON site_supplies
FOR EACH ROW EXECUTE FUNCTION aggregated_edge_owner_immutable_600();
CREATE TRIGGER cdn_zone_imports_owner_immutable_600
BEFORE UPDATE OF owner_scope_id ON cdn_zone_imports
FOR EACH ROW EXECUTE FUNCTION aggregated_edge_owner_immutable_600();

INSERT INTO permissions(name, description) VALUES
    ('edge.tenant.read', 'Read the tenant''s own third-party CDN accounts, accesses, scheduling, switch history, probes and usage'),
    ('edge.tenant.manage', 'Manage the tenant''s own third-party CDN accesses, site bindings, sync, purge, scheduling and manual switching'),
    ('edge.tenant.accounts.manage', 'Bind, rotate and delete the tenant''s own third-party CDN accounts');

INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required) VALUES
    ('edge.tenant.read', false),
    ('edge.tenant.manage', false),
    ('edge.tenant.accounts.manage', true);

CREATE FUNCTION tenant_edge_permissions_600(role_name text)
RETURNS TABLE(permission_name text)
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT grant_row.permission_name
    FROM (VALUES
        ('edge.tenant.read', ARRAY['tenant_owner', 'tenant_admin', 'tenant_viewer']),
        ('edge.tenant.manage', ARRAY['tenant_owner', 'tenant_admin']),
        ('edge.tenant.accounts.manage', ARRAY['tenant_owner'])
    ) AS grant_row(permission_name, role_names)
    WHERE role_name = ANY(grant_row.role_names);
$$;

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, grant_row.permission_name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'tenant'
CROSS JOIN LATERAL tenant_edge_permissions_600(role.name) grant_row
WHERE role.system_role
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_tenant_edge_permissions_600()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role OR NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant') THEN
        RETURN NEW;
    END IF;
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT NEW.id, grant_row.permission_name FROM tenant_edge_permissions_600(NEW.name) grant_row
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_tenant_edge_permissions_600
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_tenant_edge_permissions_600();

ALTER FUNCTION package_offer_spec_publishable_090(jsonb, timestamptz) RENAME TO package_offer_spec_publishable_090_base;

CREATE FUNCTION package_offer_spec_publishable_090(product_spec jsonb, checked_at timestamptz)
RETURNS boolean
LANGUAGE plpgsql
STABLE
STRICT
AS $$
DECLARE
    limits jsonb := product_spec->'limits';
    accounts_text text;
BEGIN
    IF jsonb_typeof(limits) = 'object' THEN
        IF limits ? 'aggregated_edge' AND jsonb_typeof(limits->'aggregated_edge') IS DISTINCT FROM 'boolean' THEN
            RETURN false;
        END IF;
        IF limits ? 'aggregated_edge_accounts' THEN
            accounts_text := limits->>'aggregated_edge_accounts';
            IF jsonb_typeof(limits->'aggregated_edge_accounts') IS DISTINCT FROM 'number' OR
               accounts_text !~ '^(-1|[0-9]+)$' OR accounts_text::numeric > 1000 THEN
                RETURN false;
            END IF;
        END IF;
        product_spec := jsonb_set(product_spec, '{limits}', limits - 'aggregated_edge' - 'aggregated_edge_accounts');
    END IF;
    RETURN package_offer_spec_publishable_090_base(product_spec, checked_at);
END;
$$;

REVOKE ALL ON FUNCTION package_offer_spec_publishable_090(jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION aggregated_edge_binding_owner_600() FROM PUBLIC;
REVOKE ALL ON FUNCTION aggregated_edge_config_account_owner_600() FROM PUBLIC;
REVOKE ALL ON FUNCTION aggregated_edge_owner_immutable_600() FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_tenant_edge_permissions_600() FROM PUBLIC;
REVOKE ALL ON FUNCTION tenant_edge_permissions_600(text) FROM PUBLIC;
