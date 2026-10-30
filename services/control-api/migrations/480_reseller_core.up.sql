LOCK TABLE schema_migrations, tenants, access_scopes, roles, role_permissions, permissions,
    node_line_group_grants, escalate_package_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_480_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 479 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 479 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=479 AND
        migration_id='479_cname_cancelled_intent_fails_site' AND
        checksum_sha256='c75ffc514f776a7ec0161b29738bb1a6e15eaa896e5335954ee498d837bf6050' AND
        down_checksum_sha256='3479adb4c3b7feec74a7a88a4ab677e4d3e1abc871993be868b797c2020b9a9b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.reseller_profiles') IS NOT NULL OR
       EXISTS (SELECT 1 FROM permissions WHERE name LIKE 'reseller.%') THEN
        RAISE EXCEPTION 'migration 480 requires the exact verified 479 release head' USING ERRCODE='P4800';
    END IF;
END;
$migration_480_up$;

-- 480（r136 rs-01-core，ADR 0018 RS-01；合入时前驱改钉 479_cname_cancelled_intent_fails_site）。
-- 用户 10-24 15:4x：Q1 代理商预付批发价（平台给线路组/套餐定批发价，代理商先充值，售出一单按批发价扣
-- 代理商余额，售价自定；计费在 RS-03）；Q2 只做一级（may_regrant 一律拒绝）；Q5 撤销授权自动下架相关套餐、
-- 清 B/C，已售订阅用到期为止。
--
-- 错误码：P4801 grantee 不是有效代理商；P4802 本版不允许再授权（may_regrant）；P4803 grantor 须为线路组所有者
-- 且所有者是平台；P4804 所属代理商无效（不是有效代理商/停用）；P4805 不能把自己设为所属代理商；
-- P4806 代理商自己不能有所属代理商（一级）；P4807 代理商资料不删除；P4808 超过代理商客户数上限；
-- P4809 代理商只能是租户。

-- 代理商身份。一行 = 平台把一个租户（tenant scope）开通为代理商；停用写 status，不删行。
-- 预付批发价（RS-03 使用，本迁移只留字段）：
--   wholesale_price_list：平台给该代理商指定的批发价表（RS-03 的批发价按 (价表, 线路组/套餐) 定）；
--   prepaid_account_id：代理商预付余额所在的账户（RS-03 决定是代理商 tenant_liability 还是独立预付账户，未定前为空）；
--   low_balance_minor：预付余额低于此值（分）时提醒，0 = 不提醒；不透支（售出时余额不足整单拒绝，RS-03）。
CREATE TABLE reseller_profiles (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('active', 'suspended')),
    customer_limit integer CHECK (customer_limit IS NULL OR customer_limit >= 0),
    wholesale_price_list text NOT NULL DEFAULT 'standard'
        CHECK (wholesale_price_list ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    prepaid_account_id uuid REFERENCES billing_accounts(id) ON DELETE RESTRICT,
    low_balance_minor bigint NOT NULL DEFAULT 0 CHECK (low_balance_minor >= 0),
    currency text NOT NULL DEFAULT 'CNY' CHECK (currency = 'CNY'),
    revision bigint NOT NULL CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    suspended_at timestamptz CHECK (suspended_at IS NULL OR isfinite(suspended_at)),
    CHECK ((status = 'suspended') = (suspended_at IS NOT NULL))
);
CREATE INDEX reseller_profiles_active_idx ON reseller_profiles (scope_id) WHERE status = 'active';

-- 子租户（代理商的客户）：parent_scope_id 指向代理商 scope；NULL = 平台直客。
ALTER TABLE tenants ADD COLUMN parent_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT;
CREATE INDEX tenants_parent_scope_idx ON tenants (parent_scope_id) WHERE parent_scope_id IS NOT NULL;

-- 有效代理商：有资料且 active 的租户 scope。
CREATE FUNCTION reseller_scope_active_480(checked_scope uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM reseller_profiles profile
        JOIN access_scopes scope ON scope.id = profile.scope_id AND scope.kind = 'tenant'
        WHERE profile.scope_id = checked_scope AND profile.status = 'active')
$$;

CREATE FUNCTION guard_reseller_profile_480() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'reseller profiles are kept (suspend instead)' USING ERRCODE='P4807';
    END IF;
    IF TG_OP = 'UPDATE' AND (NEW.scope_id <> OLD.scope_id OR NEW.created_by_user_id <> OLD.created_by_user_id OR
        NEW.created_at <> OLD.created_at OR NEW.revision <> OLD.revision + 1) THEN
        RAISE EXCEPTION 'reseller profile identity is immutable and revisions advance by one' USING ERRCODE='P4807';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant') THEN
        RAISE EXCEPTION 'a reseller is a tenant scope' USING ERRCODE='P4809';
    END IF;
    -- 一级：代理商自己不能挂在别的代理商下面。
    IF EXISTS (SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.scope_id AND tenant.parent_scope_id IS NOT NULL) THEN
        RAISE EXCEPTION 'a reseller cannot itself belong to a reseller' USING ERRCODE='P4806';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER reseller_profiles_guard_480
BEFORE INSERT OR UPDATE OR DELETE ON reseller_profiles
FOR EACH ROW EXECUTE FUNCTION guard_reseller_profile_480();

-- 所属代理商：须为有效代理商、不是自己、自己不是代理商；新挂入的客户受 customer_limit 限制
-- （已挂入的不受后来调低的上限影响）。清空（转回平台直客）总是允许。
CREATE FUNCTION guard_tenant_parent_480() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    own_scope uuid;
    parent_limit integer;
BEGIN
    IF NEW.parent_scope_id IS NULL OR (TG_OP = 'UPDATE' AND NEW.parent_scope_id IS NOT DISTINCT FROM OLD.parent_scope_id) THEN
        RETURN NEW;
    END IF;
    SELECT id INTO own_scope FROM access_scopes WHERE tenant_id = NEW.id;
    IF own_scope IS NOT DISTINCT FROM NEW.parent_scope_id THEN
        RAISE EXCEPTION 'a tenant cannot belong to itself' USING ERRCODE='P4805';
    END IF;
    IF own_scope IS NOT NULL AND EXISTS (SELECT 1 FROM reseller_profiles WHERE scope_id = own_scope) THEN
        RAISE EXCEPTION 'a reseller cannot itself belong to a reseller' USING ERRCODE='P4806';
    END IF;
    SELECT profile.customer_limit INTO parent_limit FROM reseller_profiles profile
        JOIN access_scopes scope ON scope.id = profile.scope_id AND scope.kind = 'tenant'
        WHERE profile.scope_id = NEW.parent_scope_id AND profile.status = 'active'
        FOR UPDATE OF profile;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'parent scope is not an active reseller' USING ERRCODE='P4804';
    END IF;
    IF parent_limit IS NOT NULL AND (SELECT count(*) FROM tenants
        WHERE parent_scope_id = NEW.parent_scope_id AND id <> NEW.id) >= parent_limit THEN
        RAISE EXCEPTION 'reseller customer limit reached' USING ERRCODE='P4808';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenants_parent_guard_480
BEFORE INSERT OR UPDATE OF parent_scope_id ON tenants
FOR EACH ROW EXECUTE FUNCTION guard_tenant_parent_480();

-- 权限码：租户侧只给有效代理商的 tenant_owner 系统角色，开通（status=active）时授予、停用时收回；
-- 平台 platform_owner 也持有（bootstrap 给平台全部权限，平台可代代理商操作）。
-- 不进 custom_rbac_permission_catalog（自定义角色不能带），所以 094 守卫允许收回。
INSERT INTO permissions(name, description) VALUES
    ('reseller.packages.manage', 'Create, revise and publish the reseller''s own packages (ADR 0018)'),
    ('reseller.customers.manage', 'Create, suspend and order for the reseller''s own customer tenants (ADR 0018)'),
    ('reseller.customers.read', 'Read the reseller''s own customer tenants, their subscriptions, orders and usage (ADR 0018)');

CREATE FUNCTION guard_reseller_permission_480() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.permission_name LIKE 'reseller.%' AND NOT EXISTS (SELECT 1 FROM roles role
        JOIN access_scopes scope ON scope.id = role.scope_id
        WHERE role.id = NEW.role_id AND role.system_role AND (
            (role.name = 'tenant_owner' AND reseller_scope_active_480(role.scope_id)) OR
            (role.name = 'platform_owner' AND scope.kind = 'platform'))) THEN
        RAISE EXCEPTION 'reseller permissions belong to the owner role of an active reseller' USING ERRCODE='P4801';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER role_permissions_reseller_guard_480
BEFORE INSERT OR UPDATE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION guard_reseller_permission_480();

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, permission.name FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
CROSS JOIN (VALUES ('reseller.packages.manage'), ('reseller.customers.manage'), ('reseller.customers.read')) AS permission(name)
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

CREATE FUNCTION sync_reseller_permissions_480() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status = 'active' THEN
        INSERT INTO role_permissions(role_id, permission_name)
        SELECT role.id, permission.name FROM roles role
        CROSS JOIN (VALUES ('reseller.packages.manage'), ('reseller.customers.manage'), ('reseller.customers.read'))
            AS permission(name)
        WHERE role.scope_id = NEW.scope_id AND role.system_role AND role.name = 'tenant_owner'
        ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM role_permissions WHERE permission_name LIKE 'reseller.%' AND role_id IN (
            SELECT id FROM roles WHERE scope_id = NEW.scope_id);
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER reseller_profiles_sync_permissions_480
AFTER INSERT OR UPDATE OF status ON reseller_profiles
FOR EACH ROW EXECUTE FUNCTION sync_reseller_permissions_480();

-- 线路组授权（ADR 0018 §6，Q2 一级）：grantee 必须是有效代理商；不允许再授权；grantor 是线路组所有者且
-- 所有者是平台。只管新授权（撤销是 UPDATE，不受影响）。
CREATE FUNCTION guard_line_group_grant_reseller_480() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.may_regrant THEN
        RAISE EXCEPTION 'line group grants cannot be passed on in this release' USING ERRCODE='P4802';
    END IF;
    IF NEW.grantor_scope_id <> NEW.owner_scope_id OR NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.owner_scope_id AND kind = 'platform') THEN
        RAISE EXCEPTION 'only the platform grants its own line groups' USING ERRCODE='P4803';
    END IF;
    IF NOT reseller_scope_active_480(NEW.grantee_scope_id) THEN
        RAISE EXCEPTION 'line groups are granted to active resellers only' USING ERRCODE='P4801';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER node_line_group_grants_reseller_480
BEFORE INSERT ON node_line_group_grants
FOR EACH ROW EXECUTE FUNCTION guard_line_group_grant_reseller_480();

-- 撤销联动（Q5）：代理商引用某线路组的套餐。RS-01 只能从 B/C 策略找（escalate_package_policies.owner_scope_id
-- 是代理商）；RS-02 给 package_products 加 owner_scope_id 后 CREATE OR REPLACE 本函数，补上
-- owner_scope_id = reseller 且 spec 主线路 node_group_id / 备用 backup_node_group_id 是该组的套餐。
CREATE FUNCTION reseller_products_using_line_group_480(reseller uuid, group_owner uuid, group_id uuid)
RETURNS SETOF uuid LANGUAGE sql STABLE AS $$
    SELECT policy.product_id FROM escalate_package_policies policy
    WHERE policy.owner_scope_id = reseller AND (
        (policy.b_owner_scope_id = group_owner AND policy.b_line_group_id = group_id) OR
        (policy.c_owner_scope_id = group_owner AND policy.c_line_group_id = group_id))
$$;

REVOKE ALL ON FUNCTION guard_reseller_profile_480(), guard_tenant_parent_480(), guard_reseller_permission_480(),
    sync_reseller_permissions_480(), guard_line_group_grant_reseller_480() FROM PUBLIC;
