-- 557（bb0405，ADR 0019 BB-04/BB-05；占位，合入时由主会话改号；前驱钉 556_billing_bridge_keys）：
-- 财务对接门面的服务映射、客户映射、写请求幂等、免密登录票据与插件设置。
--
-- billing_bridge_clients：同一 owner 下 (external_system, external_client_id) → 一个 CDN 用户（A 代理商客户 / B 直客）。
-- billing_bridge_services：§4.2 服务映射表，(owner_scope_id, external_system, external_service_id) 唯一；
--   pending = 正在开通（下游开户/下单均按服务行派生的幂等键执行，中途失败重试不会重复开），active = 已开通，
--   terminated = 已终止。request_digest 是开通参数摘要：同一服务号重复开通参数相同返回同一服务，不同则 409
--   bridge_service_conflict。
-- billing_bridge_requests：门面写请求（停用/恢复/续费/改套餐/终止）按 Idempotency-Key 幂等：首次落库时记下
--   expected_revision，重试沿用同一修订号，下游包交易/订阅的幂等键因此保持一致，不会重复续费。
-- billing_bridge_sso_tickets：一次性登录票据，只存 token 的 SHA-256 摘要；60 秒有效、只能用一次、
--   验证码错 5 次作废；used_at 与 session_id 同时写（票据先于会话在同一事务内核销，外键延迟到提交时检查）。
--   auth_sessions 没有 method 列，也就没有 CHECK 约束要放开：登录方式 billing_bridge 记在 auth.login 审计的
--   authentication_method，并另记 auth.session.bridge_sso。
-- billing_bridge_settings：插件设置（每个 owner 一行）；sso_require_mfa 为真时开了 TOTP 的客户免密登录仍要验证。
--
-- 守卫（P5570–P5574）：映射行不删、owner/服务号/客户号/租户/用户/订阅一经写入不可改、terminated 不可恢复；
-- 票据只能从未用变为已用（并记会话），不可改回。
LOCK TABLE schema_migrations, billing_bridge_keys IN ACCESS EXCLUSIVE MODE;

DO $migration_557_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 556 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 556 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=556 AND
        migration_id='556_billing_bridge_keys' AND
        checksum_sha256='851befdf14743018f2b7dc90d28a6017b899fa00b5c4482871d72387820833c2' AND
        down_checksum_sha256='109233918232fd630a8ed6f86eb6dcecbda528507b14d025c69160eb30ec7e99' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.billing_bridge_services') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 557 requires the exact verified 556 release head' USING ERRCODE='P5570';
    END IF;
END;
$migration_557_up$;

CREATE TABLE billing_bridge_clients (
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    external_system text NOT NULL CHECK (external_system IN ('whmcs', 'zjmf', 'zjmf_cbap')),
    external_client_id text NOT NULL CHECK (external_client_id ~ '^[!-~]{1,64}$'),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (owner_scope_id, external_system, external_client_id)
);

CREATE TABLE billing_bridge_services (
    id uuid PRIMARY KEY,
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    key_id text NOT NULL REFERENCES billing_bridge_keys(key_id) ON DELETE RESTRICT,
    external_system text NOT NULL CHECK (external_system IN ('whmcs', 'zjmf', 'zjmf_cbap')),
    external_service_id text NOT NULL CHECK (external_service_id ~ '^[!-~]{1,64}$'),
    external_client_id text NOT NULL CHECK (external_client_id ~ '^[!-~]{1,64}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    status text NOT NULL CHECK (status IN ('pending', 'active', 'terminated')),
    tenant_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT,
    user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    subscription_id uuid REFERENCES package_subscriptions(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    terminated_at timestamptz CHECK (terminated_at IS NULL OR isfinite(terminated_at)),
    CONSTRAINT billing_bridge_services_external_557_key UNIQUE (owner_scope_id, external_system, external_service_id),
    CONSTRAINT billing_bridge_services_opened_557_check CHECK ((status = 'pending') =
        (tenant_scope_id IS NULL OR user_id IS NULL OR subscription_id IS NULL) AND
        (tenant_scope_id IS NULL) = (user_id IS NULL) AND (user_id IS NULL) = (subscription_id IS NULL)),
    CONSTRAINT billing_bridge_services_terminated_557_check CHECK ((status = 'terminated') = (terminated_at IS NOT NULL))
);
CREATE INDEX billing_bridge_services_client_557_idx
    ON billing_bridge_services (owner_scope_id, external_system, external_client_id);
CREATE INDEX billing_bridge_services_subscription_557_idx ON billing_bridge_services (subscription_id);

CREATE FUNCTION guard_billing_bridge_service_557() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing bridge services are kept (terminate instead)' USING ERRCODE='P5571';
    END IF;
    IF NEW.id <> OLD.id OR NEW.owner_scope_id <> OLD.owner_scope_id OR NEW.key_id <> OLD.key_id OR
       NEW.external_system <> OLD.external_system OR NEW.external_service_id <> OLD.external_service_id OR
       NEW.external_client_id <> OLD.external_client_id OR NEW.request_digest <> OLD.request_digest OR
       NEW.created_at <> OLD.created_at OR
       (OLD.status <> 'pending' AND (NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
        NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.subscription_id IS DISTINCT FROM OLD.subscription_id)) OR
       (OLD.status = 'active' AND NEW.status = 'pending') OR
       (OLD.status = 'terminated' AND (NEW.status <> 'terminated' OR NEW.terminated_at IS DISTINCT FROM OLD.terminated_at)) THEN
        RAISE EXCEPTION 'billing bridge service identity is immutable and termination is final' USING ERRCODE='P5572';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_bridge_services_guard_557
BEFORE UPDATE OR DELETE ON billing_bridge_services
FOR EACH ROW EXECUTE FUNCTION guard_billing_bridge_service_557();

CREATE TABLE billing_bridge_requests (
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{0,63}$'),
    service_id uuid NOT NULL REFERENCES billing_bridge_services(id) ON DELETE RESTRICT,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    response jsonb CHECK (response IS NULL OR jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    completed_at timestamptz CHECK (completed_at IS NULL OR isfinite(completed_at)),
    PRIMARY KEY (owner_scope_id, idempotency_key),
    CONSTRAINT billing_bridge_requests_completed_557_check CHECK ((response IS NULL) = (completed_at IS NULL))
);
CREATE INDEX billing_bridge_requests_created_557_idx ON billing_bridge_requests (created_at);

CREATE TABLE billing_bridge_sso_tickets (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    key_id text NOT NULL REFERENCES billing_bridge_keys(key_id) ON DELETE RESTRICT,
    service_id uuid NOT NULL REFERENCES billing_bridge_services(id) ON DELETE RESTRICT,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    redirect text NOT NULL CHECK (char_length(redirect) BETWEEN 1 AND 512 AND redirect ~ '^/' AND redirect !~ '^//'
        AND redirect !~ '[[:cntrl:]\\]'),
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > created_at AND
        expires_at <= created_at + interval '60 seconds'),
    used_at timestamptz CHECK (used_at IS NULL OR isfinite(used_at)),
    session_id uuid REFERENCES auth_sessions(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT billing_bridge_sso_tickets_used_557_check CHECK ((used_at IS NULL) = (session_id IS NULL))
);
CREATE INDEX billing_bridge_sso_tickets_expires_557_idx ON billing_bridge_sso_tickets (expires_at);

CREATE FUNCTION guard_billing_bridge_sso_ticket_557() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.token_digest <> OLD.token_digest OR NEW.owner_scope_id <> OLD.owner_scope_id OR
       NEW.key_id <> OLD.key_id OR NEW.service_id <> OLD.service_id OR NEW.user_id <> OLD.user_id OR
       NEW.tenant_scope_id <> OLD.tenant_scope_id OR NEW.redirect <> OLD.redirect OR
       NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at OR
       NEW.failed_attempts < OLD.failed_attempts OR OLD.used_at IS NOT NULL) THEN
        RAISE EXCEPTION 'billing bridge SSO tickets are single-use' USING ERRCODE='P5573';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_bridge_sso_tickets_guard_557
BEFORE UPDATE ON billing_bridge_sso_tickets
FOR EACH ROW EXECUTE FUNCTION guard_billing_bridge_sso_ticket_557();

CREATE TABLE billing_bridge_settings (
    owner_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    sso_require_mfa boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);

REVOKE ALL ON billing_bridge_clients, billing_bridge_services, billing_bridge_requests, billing_bridge_sso_tickets,
    billing_bridge_settings FROM PUBLIC;
GRANT SELECT, INSERT ON billing_bridge_clients TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON billing_bridge_services, billing_bridge_settings TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON billing_bridge_requests, billing_bridge_sso_tickets
    TO cdnca_control_app, cdnca_control_runtime;
