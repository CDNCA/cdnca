-- 689 回退：证书发布意图的操作人校验回到 120 版（会话还须未被 refresh 替换）。
-- 触发器只在插入时校验，已有意图行不受影响，不拒绝回退。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE certificate_publication_intents IN SHARE ROW EXCLUSIVE MODE;

DO $migration_689_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 689 OR
       (SELECT max(version) FROM schema_migrations) <> 689 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=689 AND
        migration_id='689_certificate_publication_actor_refreshed_session' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 689 down requires the exact verified migration head' USING ERRCODE='P6891';
    END IF;
END;
$migration_689_down$;

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
          AND session_row.replaced_by_id IS NULL AND session_row.expires_at>transaction_timestamp()
    ) THEN
        RAISE EXCEPTION 'certificate publication actor reference is not current'
            USING ERRCODE='P1201';
    END IF;
    RETURN NEW;
END;
$$;
