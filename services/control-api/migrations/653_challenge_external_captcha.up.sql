-- 653 挑战策略外部验证：
-- 挑战策略外部验证接入 Cloudflare Turnstile 与 Google reCAPTCHA v3，并补上控制台录入外部验证凭据的入口。
--   1. challenge_policy_revisions.external_provider 名单放宽为 tencent / geetest-v4 / turnstile / recaptcha-v3
--      （053 的列 CHECK 未命名，PostgreSQL 默认名 challenge_policy_revisions_external_provider_check）。
--   2. 新增可空列 external_score_threshold（只 recaptcha-v3，0.1..0.9）与 external_unavailable
--      （builtin | closed，只 external 模式；NULL = 节点默认 builtin）。存量行全部为 NULL，不改数据。
--   3. CREATE OR REPLACE validate_challenge_policy_revision_053（以 646 版本为底）：两列为 NULL 时
--      document.external_provider 不含对应 key（与 Go 侧 omitempty 一致，存量 document 不变）；
--      enable/disable/delete 不得改两列。
--   4. 新表 challenge_external_credentials：每条策略一行，secret 用 CHALLENGE_POLICY_FACT_KEK 做
--      AES-256-GCM（AAD 见 challengepublication.ExternalCredentialAAD），接口只写不读。
LOCK TABLE schema_migrations, challenge_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_653_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 652 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 652 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=652 AND
        migration_id='652_security_string_sets' AND
        checksum_sha256='be3a12e43d1087869116e059d2cf6d647c3da43657d114368994ab4ef0d2fb45' AND
        down_checksum_sha256='4ed0c3be5b18ff19b98b34ebc4b0fc398df7404be7aa9dbae640b7ceb1f64a33' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='challenge_policy_revisions' AND column_name IN ('external_score_threshold', 'external_unavailable')
       ) OR to_regclass(current_schema() || '.challenge_external_credentials') IS NOT NULL
         OR NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid='challenge_policy_revisions'::regclass AND
        conname='challenge_policy_revisions_external_provider_check'
       ) OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='challenge_policy_revisions' AND column_name='pow_difficulty'
       ) THEN
        RAISE EXCEPTION 'migration 653 requires the exact verified 652 release head' USING ERRCODE='P6530';
    END IF;
END;
$migration_653_up$;

ALTER TABLE challenge_policy_revisions
    DROP CONSTRAINT challenge_policy_revisions_external_provider_check,
    ADD CONSTRAINT challenge_policy_revisions_external_provider_check CHECK (
        external_provider IN ('tencent', 'geetest-v4', 'turnstile', 'recaptcha-v3')
    ),
    ADD COLUMN external_score_threshold numeric(2,1),
    ADD COLUMN external_unavailable text,
    ADD CONSTRAINT challenge_policy_revisions_external_score_653 CHECK (
        external_score_threshold IS NULL OR (
            external_score_threshold BETWEEN 0.1 AND 0.9 AND external_provider = 'recaptcha-v3'
        )
    ),
    ADD CONSTRAINT challenge_policy_revisions_external_unavailable_653 CHECK (
        external_unavailable IS NULL OR (
            external_unavailable IN ('builtin', 'closed') AND mode = 'external'
        )
    );

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
        ) || CASE WHEN NEW.external_score_threshold IS NULL THEN '{}'::jsonb
                  ELSE jsonb_build_object('score_threshold', NEW.external_score_threshold) END
          || CASE WHEN NEW.external_unavailable IS NULL THEN '{}'::jsonb
                  ELSE jsonb_build_object('unavailable', NEW.external_unavailable) END END,
        'enabled', NEW.enabled,
        'deleted', NEW.deleted
    );
    IF NEW.pow_difficulty IS NOT NULL THEN
        expected_document := expected_document || jsonb_build_object('pow_difficulty', NEW.pow_difficulty);
    END IF;
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
        NEW.external_app_reference IS DISTINCT FROM previous.external_app_reference OR
        NEW.pow_difficulty IS DISTINCT FROM previous.pow_difficulty OR
        NEW.external_score_threshold IS DISTINCT FROM previous.external_score_threshold OR
        NEW.external_unavailable IS DISTINCT FROM previous.external_unavailable
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

CREATE TABLE challenge_external_credentials (
    policy_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    provider text NOT NULL CHECK (provider IN ('tencent', 'geetest-v4', 'turnstile', 'recaptcha-v3')),
    app_id text NOT NULL CHECK (
        octet_length(app_id) BETWEEN 1 AND 128 AND app_id ~ '^[A-Za-z0-9][A-Za-z0-9._:_-]*$'
    ),
    environment text NOT NULL DEFAULT 'production' CHECK (environment IN ('sandbox', 'production')),
    secret_ciphertext bytea NOT NULL CHECK (octet_length(secret_ciphertext) BETWEEN 29 AND 600),
    wrapping_key_id text NOT NULL CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128 AND
        wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (tenant_scope_id, policy_id)
        REFERENCES challenge_policies(tenant_scope_id, id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at)
);

REVOKE ALL ON challenge_external_credentials FROM PUBLIC;
