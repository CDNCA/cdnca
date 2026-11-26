-- 689（前驱 688_probe_dnspup_plugin_tenant_idempotency）。
-- 证书发布意图的操作人校验与普通鉴权 identity.Store.PrincipalForSession 一致：会话未撤销、未到期，账号与成员有效。
-- 120 版另要求 replaced_by_id IS NULL，控制台刷新 token 后（另一个标签页刷新也算），当前页旧 access token 读接口 200、
-- 绑定/解绑证书却被本触发器拒绝（P1201）。登出、refresh 重放、停用都会整族撤销，不依赖 replaced_by_id。
-- 只替换 validate_certificate_publication_actor_120 的函数体，触发器不变；其余条件（作用域种类、租户、
-- 账号与租户 revision）照旧。
-- 错误码：头检查 P6890；down 头检查 P6891。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE certificate_publication_intents IN SHARE ROW EXCLUSIVE MODE;

DO $migration_689_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 688 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 688 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=688 AND
        migration_id='688_probe_dnspup_plugin_tenant_idempotency' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR
       to_regprocedure('validate_certificate_publication_actor_120()') IS NULL THEN
        RAISE EXCEPTION 'migration 689 requires the exact verified 688 release head' USING ERRCODE='P6890';
    END IF;
END;
$migration_689_up$;

CREATE OR REPLACE FUNCTION validate_certificate_publication_actor_120()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_scope_kind text;
    current_tenant_id uuid;
    current_user_revision bigint;
    current_tenant_revision bigint;
BEGIN
    IF NEW.actor_session_id IS NULL THEN
        IF NEW.actor_scope_kind IS NOT NULL OR NEW.actor_user_revision IS NOT NULL OR
           NEW.target_tenant_id IS NOT NULL OR NEW.target_tenant_revision IS NOT NULL THEN
            RAISE EXCEPTION 'certificate publication legacy actor reference is incomplete'
                USING ERRCODE='P1201';
        END IF;
        RETURN NEW;
    END IF;
    SELECT kind INTO current_scope_kind FROM access_scopes WHERE id=NEW.actor_scope_id FOR KEY SHARE;
    SELECT tenant_id INTO current_tenant_id FROM access_scopes WHERE id=NEW.tenant_scope_id FOR KEY SHARE;
    SELECT revision INTO current_user_revision FROM users WHERE id=NEW.actor_user_id FOR KEY SHARE;
    SELECT revision INTO current_tenant_revision FROM tenants WHERE id=current_tenant_id FOR KEY SHARE;
    IF current_scope_kind IS DISTINCT FROM NEW.actor_scope_kind OR current_tenant_id IS NULL OR
       current_tenant_id IS DISTINCT FROM NEW.target_tenant_id OR
       current_user_revision IS DISTINCT FROM NEW.actor_user_revision OR
       current_tenant_revision IS DISTINCT FROM NEW.target_tenant_revision OR NOT EXISTS (
        SELECT 1 FROM auth_sessions session_row
        JOIN users account ON account.id=session_row.user_id AND account.status='active'
        JOIN memberships membership ON membership.scope_id=session_row.scope_id
            AND membership.user_id=session_row.user_id AND membership.status='active'
        WHERE session_row.id=NEW.actor_session_id AND session_row.scope_id=NEW.actor_scope_id
          AND session_row.user_id=NEW.actor_user_id AND session_row.revoked_at IS NULL
          AND session_row.expires_at>transaction_timestamp()
    ) THEN
        RAISE EXCEPTION 'certificate publication actor reference is not current'
            USING ERRCODE='P1201';
    END IF;
    RETURN NEW;
END;
$$;
