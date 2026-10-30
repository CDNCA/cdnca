LOCK TABLE schema_migrations, admin_impersonation_grants, admin_impersonation_sessions,
    admin_impersonation_revocations IN ACCESS EXCLUSIVE MODE;

DO $migration_482_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 481 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 481 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=481 AND
        migration_id='481_reseller_packages' AND
        checksum_sha256='0090f42d63231589ad8eff70f4d230da7b38bd9cb2a1080eae5cd8507c68b2b7' AND
        down_checksum_sha256='d23d1fa3bb822e9f2163be035e1406d4e4adc43723eec0453476467d9879e7ac' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('reseller_scope_active_480(uuid)') IS NULL OR
       to_regprocedure('impersonation_actor_may_target_482(uuid,uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 482 requires the exact verified 481 release head' USING ERRCODE='P4820';
    END IF;
END;
$migration_482_up$;

-- 482（r136 rs-07-whitelabel，ADR 0018 RS-07；481 是 RS-02 的本地占位，合入时前驱改钉 RS-02 的真 481）。
-- 用户 10-24 15:4x Q4：代理商可「切换」到自己的客户，规则同平台切换（10-23 21:30：点了直接登录、不填表单、
-- 照常审计、不能切到平台管理员、可随时退出回原身份）。
-- 代登录事实表（038）的三个触发器原先只认平台成员；本迁移放宽为：
--   平台成员持 identity.impersonation.manage → 任意租户（原规则不变）；
--   有效代理商的租户成员持 reseller.customers.manage → 只能是 tenants.parent_scope_id = 本代理商的客户。
-- 代理商只能撤销（退出）自己发起的代登录；平台照常可撤销任何代登录。
-- 错误码：P4820 up 前驱守卫；P4821 down 前驱守卫；P4822 已有代理商代登录记录时拒绝回退。

-- actor_scope 能否以 target_scope 的成员身份登录（不含权限码与会话检查）。
CREATE FUNCTION impersonation_actor_may_target_482(actor_scope uuid, target_scope uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM access_scopes actor
        JOIN access_scopes target ON target.id = target_scope AND target.kind = 'tenant'
        JOIN tenants customer ON customer.id = target.tenant_id
        WHERE actor.id = actor_scope AND (
            actor.kind = 'platform' AND actor.tenant_id IS NULL OR
            actor.kind = 'tenant' AND customer.parent_scope_id = actor.id AND reseller_scope_active_480(actor.id))
    )
$$;

-- 发起代登录所需权限码：平台 identity.impersonation.manage，代理商 reseller.customers.manage。
CREATE FUNCTION impersonation_actor_permitted_482(actor_scope uuid, actor_user uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM access_scopes scope
        JOIN role_assignments assignment ON assignment.scope_id = scope.id AND assignment.user_id = actor_user
        JOIN role_permissions permission ON permission.role_id = assignment.role_id
        WHERE scope.id = actor_scope AND permission.permission_name =
            CASE scope.kind WHEN 'platform' THEN 'identity.impersonation.manage' ELSE 'reseller.customers.manage' END
    )
$$;

CREATE OR REPLACE FUNCTION assert_admin_impersonation_grant_principals()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_active boolean;
    primary_session_valid boolean;
    target_kind text;
    target_active boolean;
BEGIN
    SELECT scope.kind,
           tenant.status = 'active' AND subject.status = 'active' AND membership.status = 'active'
      INTO target_kind, target_active
    FROM access_scopes scope
    JOIN tenants tenant ON tenant.id = scope.tenant_id
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.subject_user_id
    JOIN users subject ON subject.id = membership.user_id
    WHERE scope.id = NEW.tenant_scope_id AND scope.tenant_id = NEW.tenant_id;

    SELECT actor.status = 'active' AND membership.status = 'active'
      INTO actor_active
    FROM access_scopes scope
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.actor_user_id
    JOIN users actor ON actor.id = membership.user_id
    WHERE scope.id = NEW.actor_scope_id;

    SELECT auth_session.user_id = NEW.actor_user_id AND
           auth_session.scope_id = NEW.actor_scope_id AND
           auth_session.revoked_at IS NULL AND
           NEW.created_at >= auth_session.created_at AND
           NEW.created_at < auth_session.expires_at
      INTO primary_session_valid
    FROM auth_sessions auth_session
    WHERE auth_session.id = NEW.primary_auth_session_id
    FOR UPDATE OF auth_session;

    IF target_kind IS DISTINCT FROM 'tenant' OR target_active IS DISTINCT FROM true OR
       actor_active IS DISTINCT FROM true OR primary_session_valid IS DISTINCT FROM true OR
       NOT impersonation_actor_may_target_482(NEW.actor_scope_id, NEW.tenant_scope_id) OR
       NOT impersonation_actor_permitted_482(NEW.actor_scope_id, NEW.actor_user_id) THEN
        RAISE EXCEPTION 'invalid admin impersonation principals';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION assert_admin_impersonation_session_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    grant_created_at timestamptz;
    grant_expires_at timestamptz;
    grant_permissions_digest bytea;
    actor_active boolean;
    target_active boolean;
BEGIN
    SELECT grant_row.created_at, grant_row.expires_at, grant_row.subject_permissions_digest,
           actor.status = 'active' AND actor_membership.status = 'active',
           tenant.status = 'active' AND subject.status = 'active' AND
               subject_membership.status = 'active' AND subject_scope.kind = 'tenant'
      INTO grant_created_at, grant_expires_at, grant_permissions_digest,
           actor_active, target_active
    FROM admin_impersonation_grants grant_row
    JOIN access_scopes actor_scope ON actor_scope.id = NEW.actor_scope_id
    JOIN memberships actor_membership
      ON actor_membership.scope_id = NEW.actor_scope_id AND actor_membership.user_id = NEW.actor_user_id
    JOIN users actor ON actor.id = NEW.actor_user_id
    JOIN access_scopes subject_scope
      ON subject_scope.id = NEW.tenant_scope_id AND subject_scope.tenant_id = NEW.tenant_id
    JOIN tenants tenant ON tenant.id = NEW.tenant_id
    JOIN memberships subject_membership
      ON subject_membership.scope_id = NEW.tenant_scope_id AND
         subject_membership.user_id = NEW.subject_user_id
    JOIN users subject ON subject.id = NEW.subject_user_id
    WHERE grant_row.id = NEW.grant_id;

    IF grant_created_at IS NULL OR NEW.created_at < grant_created_at OR NEW.created_at >= grant_expires_at OR
       NEW.subject_permissions_digest IS DISTINCT FROM grant_permissions_digest OR
       actor_active IS DISTINCT FROM true OR target_active IS DISTINCT FROM true OR
       NOT impersonation_actor_may_target_482(NEW.actor_scope_id, NEW.tenant_scope_id) OR
       NOT impersonation_actor_permitted_482(NEW.actor_scope_id, NEW.actor_user_id) OR EXISTS (
           SELECT 1 FROM admin_impersonation_revocations WHERE grant_id = NEW.grant_id
       ) THEN
        RAISE EXCEPTION 'invalid admin impersonation session fact';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION assert_admin_impersonation_revoker()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_kind text;
    active boolean;
    grant_created_at timestamptz;
BEGIN
    SELECT scope.kind, actor.status = 'active' AND membership.status = 'active'
      INTO scope_kind, active
    FROM access_scopes scope
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.revoked_by_user_id
    JOIN users actor ON actor.id = membership.user_id
    WHERE scope.id = NEW.revoked_by_scope_id;

    SELECT created_at INTO grant_created_at
    FROM admin_impersonation_grants WHERE id = NEW.grant_id;

    -- 代理商只能撤销自己 scope 发起的代登录（退出），平台可撤销任何代登录。
    IF scope_kind IS DISTINCT FROM 'platform' AND (scope_kind IS DISTINCT FROM 'tenant' OR
           NEW.original_actor_scope_id IS DISTINCT FROM NEW.revoked_by_scope_id) OR
       active IS DISTINCT FROM true OR
       NOT impersonation_actor_permitted_482(NEW.revoked_by_scope_id, NEW.revoked_by_user_id) OR
       grant_created_at IS NULL OR NEW.revoked_at < grant_created_at THEN
        RAISE EXCEPTION 'invalid admin impersonation revoker';
    END IF;
    RETURN NEW;
END;
$$;
