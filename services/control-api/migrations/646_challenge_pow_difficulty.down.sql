-- 646 回退：恢复 053 原版 validate_challenge_policy_revision_053 并删除 pow_difficulty 列。
-- 已有显式难度的 revision 是不可逆事实（其 document 带 pow_difficulty），存在时拒绝回退且不改数据库。
LOCK TABLE schema_migrations, challenge_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_646_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 646 OR
       (SELECT max(version) FROM schema_migrations) <> 646 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=646 AND
        migration_id='646_challenge_pow_difficulty' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 646 down requires the exact verified migration head' USING ERRCODE='P6461';
    END IF;
    IF EXISTS (SELECT 1 FROM challenge_policy_revisions WHERE pow_difficulty IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 646 down: challenge policy revisions carry explicit pow_difficulty facts'
            USING ERRCODE='P6462';
    END IF;
END;
$migration_646_down$;

CREATE OR REPLACE FUNCTION validate_challenge_policy_revision_053()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE head challenge_policies%ROWTYPE;
DECLARE previous challenge_policy_revisions%ROWTYPE;
DECLARE site_scope uuid;
DECLARE site_domain text;
DECLARE expected_document jsonb;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('challenge-policy:' || NEW.policy_id::text, 0));
    IF NOT challenge_policy_host_valid_053(NEW.host)
       OR NOT challenge_policy_bypass_valid_053(NEW.bypass_routes) THEN
        RAISE EXCEPTION 'invalid challenge policy host or bypass routes' USING ERRCODE = 'P0001';
    END IF;
    IF NOT challenge_policy_actor_can_053(
        NEW.created_by_scope_id, NEW.created_by_user_id, NEW.tenant_scope_id, 'challenge_policies.manage'
    ) THEN
        RAISE EXCEPTION 'challenge policy actor is not authorized' USING ERRCODE = 'P0001';
    END IF;
    SELECT scope_id, domain INTO site_scope, site_domain
    FROM sites WHERE id = NEW.site_id AND deleted_at IS NULL;
    IF site_scope IS DISTINCT FROM NEW.tenant_scope_id THEN
        RAISE EXCEPTION 'challenge policy site scope mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF left(site_domain, 2) = '*.' THEN
        IF NEW.host = substring(site_domain FROM 3)
           OR NEW.host NOT LIKE '%.' || substring(site_domain FROM 3) THEN
            RAISE EXCEPTION 'challenge policy host is outside the site domain' USING ERRCODE = 'P0001';
        END IF;
    ELSIF NEW.host <> site_domain THEN
        RAISE EXCEPTION 'challenge policy host is outside the site domain' USING ERRCODE = 'P0001';
    END IF;

    expected_document := jsonb_build_object(
        'schema_version', 'cdnca.control.challenge-policy/v1',
        'policy_id', NEW.policy_id::text,
        'tenant_scope_id', NEW.tenant_scope_id::text,
        'site_id', NEW.site_id::text,
        'host', NEW.host,
        'revision', NEW.revision,
        'priority', NEW.priority,
        'mode', NEW.mode,
        'min_delay_seconds', NEW.min_delay_seconds,
        'challenge_ttl_seconds', NEW.challenge_ttl_seconds,
        'pass_ttl_seconds', NEW.pass_ttl_seconds,
        'clock_skew_seconds', NEW.clock_skew_seconds,
        'attempts_per_nonce', NEW.attempts_per_nonce,
        'failure_window_seconds', NEW.failure_window_seconds,
        'max_failures_per_window', NEW.max_failures_per_window,
        'ip_binding', NEW.ip_binding,
        'bind_user_agent', NEW.bind_user_agent,
        'bypass_routes', NEW.bypass_routes,
        'key_reference', NEW.key_reference,
        'external_provider', CASE WHEN NEW.external_provider IS NULL THEN NULL ELSE jsonb_build_object(
            'provider', NEW.external_provider, 'app_reference', NEW.external_app_reference
        ) END,
        'enabled', NEW.enabled,
        'deleted', NEW.deleted
    );
    IF NEW.document IS DISTINCT FROM expected_document THEN
        RAISE EXCEPTION 'challenge policy document does not match revision facts' USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO head FROM challenge_policies WHERE id = NEW.policy_id FOR UPDATE;
    IF NOT FOUND THEN
        IF NEW.revision <> 1 OR NEW.action <> 'create' OR NEW.deleted THEN
            RAISE EXCEPTION 'challenge policy must start with create revision one' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF head.current_deleted OR NEW.action = 'create'
       OR NEW.revision <> head.current_revision + 1
       OR NEW.tenant_scope_id <> head.tenant_scope_id
       OR NEW.tenant_id <> head.tenant_id
       OR NEW.site_id <> head.site_id
       OR NEW.host <> head.host THEN
        RAISE EXCEPTION 'challenge policy revision is not monotonic or changes identity' USING ERRCODE = 'P0001';
    END IF;
    SELECT * INTO previous
    FROM challenge_policy_revisions
    WHERE policy_id = NEW.policy_id AND revision = head.current_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'challenge policy previous revision is missing' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.action IN ('enable', 'disable', 'delete') AND (
        NEW.priority IS DISTINCT FROM previous.priority OR
        NEW.mode IS DISTINCT FROM previous.mode OR
        NEW.min_delay_seconds IS DISTINCT FROM previous.min_delay_seconds OR
        NEW.challenge_ttl_seconds IS DISTINCT FROM previous.challenge_ttl_seconds OR
        NEW.pass_ttl_seconds IS DISTINCT FROM previous.pass_ttl_seconds OR
        NEW.clock_skew_seconds IS DISTINCT FROM previous.clock_skew_seconds OR
        NEW.attempts_per_nonce IS DISTINCT FROM previous.attempts_per_nonce OR
        NEW.failure_window_seconds IS DISTINCT FROM previous.failure_window_seconds OR
        NEW.max_failures_per_window IS DISTINCT FROM previous.max_failures_per_window OR
        NEW.ip_binding IS DISTINCT FROM previous.ip_binding OR
        NEW.bind_user_agent IS DISTINCT FROM previous.bind_user_agent OR
        NEW.bypass_routes IS DISTINCT FROM previous.bypass_routes OR
        NEW.key_reference IS DISTINCT FROM previous.key_reference OR
        NEW.external_provider IS DISTINCT FROM previous.external_provider OR
        NEW.external_app_reference IS DISTINCT FROM previous.external_app_reference
    ) THEN
        RAISE EXCEPTION 'challenge policy state transition cannot change configuration' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.action = 'update' AND (NEW.enabled <> head.current_enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'challenge policy update cannot change state' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'enable' AND (head.current_enabled OR NOT NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid challenge policy enable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'disable' AND (NOT head.current_enabled OR NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid challenge policy disable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'delete' AND (NEW.enabled OR NOT NEW.deleted) THEN
        RAISE EXCEPTION 'invalid challenge policy delete transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE challenge_policy_revisions
    DROP CONSTRAINT challenge_policy_revisions_pow_difficulty_646,
    DROP COLUMN pow_difficulty;
