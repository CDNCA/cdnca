LOCK TABLE schema_migrations, admin_impersonation_grants, admin_impersonation_sessions,
    admin_impersonation_revocations IN ACCESS EXCLUSIVE MODE;

DO $migration_482_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 482 OR
       (SELECT max(version) FROM schema_migrations) <> 482 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=482 AND
        migration_id='482_reseller_impersonation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 482 down requires the exact verified migration head' USING ERRCODE='P4821';
    END IF;
    -- 481 不认代理商代登录：已有代理商发起的代登录记录时拒绝回退（事实表只追加，不能删）。
    IF EXISTS (SELECT 1 FROM admin_impersonation_grants grant_row
        JOIN access_scopes scope ON scope.id = grant_row.actor_scope_id WHERE scope.kind <> 'platform') THEN
        RAISE EXCEPTION 'migration 482 down refuses to drop recorded reseller impersonations' USING ERRCODE='P4822';
    END IF;
END;
$migration_482_down$;

-- 还原 038 的三个触发器函数（原文）。
CREATE OR REPLACE FUNCTION assert_admin_impersonation_grant_principals()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor_kind text;
    actor_active boolean;
    actor_permitted boolean;
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

    SELECT scope.kind,
           actor.status = 'active' AND membership.status = 'active',
           EXISTS (
               SELECT 1
               FROM role_assignments assignment
               JOIN role_permissions permission ON permission.role_id = assignment.role_id
               WHERE assignment.scope_id = NEW.actor_scope_id
                 AND assignment.user_id = NEW.actor_user_id
                 AND permission.permission_name = 'identity.impersonation.manage'
           )
      INTO actor_kind, actor_active, actor_permitted
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
       actor_kind IS DISTINCT FROM 'platform' OR actor_active IS DISTINCT FROM true OR
       actor_permitted IS DISTINCT FROM true OR primary_session_valid IS DISTINCT FROM true THEN
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
    actor_permitted boolean;
    target_active boolean;
BEGIN
    SELECT grant_row.created_at, grant_row.expires_at, grant_row.subject_permissions_digest,
           actor.status = 'active' AND actor_membership.status = 'active' AND actor_scope.kind = 'platform',
           EXISTS (
               SELECT 1
               FROM role_assignments assignment
               JOIN role_permissions permission ON permission.role_id = assignment.role_id
               WHERE assignment.scope_id = NEW.actor_scope_id
                 AND assignment.user_id = NEW.actor_user_id
                 AND permission.permission_name = 'identity.impersonation.manage'
           ),
           tenant.status = 'active' AND subject.status = 'active' AND
               subject_membership.status = 'active' AND subject_scope.kind = 'tenant'
      INTO grant_created_at, grant_expires_at, grant_permissions_digest,
           actor_active, actor_permitted, target_active
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
       actor_active IS DISTINCT FROM true OR actor_permitted IS DISTINCT FROM true OR
       target_active IS DISTINCT FROM true OR EXISTS (
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
    permitted boolean;
    grant_created_at timestamptz;
BEGIN
    SELECT scope.kind,
           actor.status = 'active' AND membership.status = 'active',
           EXISTS (
               SELECT 1
               FROM role_assignments assignment
               JOIN role_permissions permission ON permission.role_id = assignment.role_id
               WHERE assignment.scope_id = NEW.revoked_by_scope_id
                 AND assignment.user_id = NEW.revoked_by_user_id
                 AND permission.permission_name = 'identity.impersonation.manage'
           )
      INTO scope_kind, active, permitted
    FROM access_scopes scope
    JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = NEW.revoked_by_user_id
    JOIN users actor ON actor.id = membership.user_id
    WHERE scope.id = NEW.revoked_by_scope_id;

    SELECT created_at INTO grant_created_at
    FROM admin_impersonation_grants WHERE id = NEW.grant_id;

    IF scope_kind IS DISTINCT FROM 'platform' OR active IS DISTINCT FROM true OR
       permitted IS DISTINCT FROM true OR grant_created_at IS NULL OR NEW.revoked_at < grant_created_at THEN
        RAISE EXCEPTION 'invalid admin impersonation revoker';
    END IF;
    RETURN NEW;
END;
$$;

DROP FUNCTION impersonation_actor_permitted_482(uuid, uuid);
DROP FUNCTION impersonation_actor_may_target_482(uuid, uuid);
