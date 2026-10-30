-- 556（bb0102，ADR 0019 BB-02；占位，合入时由主会话改号；前驱暂钉 555_subscription_suspension_reseller_change）：
-- 财务系统对接插件（module.billing.bridge）自有的对接密钥、防重放 nonce 与对接日志。不碰 api_keys。
--
-- billing_bridge_keys：一行一把密钥。owner_kind=platform（B：自建主控，owner 是平台 scope）或 reseller
--   （A：代理商在本平台转售，owner 是有效代理商的 tenant scope，reseller_profiles.status='active'）。
--   key_id 'cbb_'+22 位 base64url，请求头 X-Cdnca-Bridge-Key 携带，可公开；secret 只在创建/轮换时返回一次。
--   secret_seed：HMAC 请求签名要求服务端能算出 secret，单向摘要无法验签，因此库里不存 secret 也不存其摘要，
--   只存 32 字节随机 seed；secret = HMAC(pepper[pepper_version], 域 "cdnca-control-api/billing-bridge/digest/v1\x00",
--   key_id, 0x00, seed)（internal/billingbridge）。pepper 不在库里（与 API Key 共用 keyring、摘要域分离），
--   只拿到数据库算不出 secret，也不能伪造签名。每次轮换换 seed、revision+1。
--   ip_allowlist 必填至少一条（cidr，前缀长度 >0）。
-- billing_bridge_nonces：(key_id, nonce) 5 分钟内不可复用；按 seen_at 清理（验签成功时顺带删该 key 的过期行）。
-- billing_bridge_logs：每次门面调用（含已知 key 的鉴权失败）一行；reason_code 只在内部记失败原因，对外统一 401。
--
-- 守卫（P5560–P5564）：密钥行不删（吊销写 status）；owner_kind 须与 scope 种类相符；代理商 owner 在新建与轮换时须为
-- 有效代理商（服务层同样先校验，双保险）；key_id/owner/created_* 不可改；revoked 不可恢复；revision 只增。
-- 权限码 billing_bridge.manage 只给平台 platform_owner（管理 B 密钥）；代理商管理 A 密钥复用 reseller.customers.manage。
LOCK TABLE schema_migrations, access_scopes, reseller_profiles, roles, role_permissions, permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_556_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 555 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 555 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=555 AND
        migration_id='555_subscription_suspension_reseller_change' AND
        checksum_sha256='64e3ad1ac6f92d098cb9ceff562d8f30040ab8e45f4cbd949e961a67bf6fb071' AND
        down_checksum_sha256='f37b4b2e833f40dbb8455514695b4b1b1d20c31c68b5736f86d3c138e4c83ad9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.billing_bridge_keys') IS NOT NULL OR
       EXISTS (SELECT 1 FROM permissions WHERE name = 'billing_bridge.manage') THEN
        RAISE EXCEPTION 'migration 556 requires the exact verified 555 release head' USING ERRCODE='P5560';
    END IF;
END;
$migration_556_up$;

CREATE TABLE billing_bridge_keys (
    id uuid PRIMARY KEY,
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    owner_kind text NOT NULL CHECK (owner_kind IN ('platform', 'reseller')),
    name text NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 64),
    key_id text NOT NULL UNIQUE CHECK (key_id ~ '^cbb_[A-Za-z0-9_-]{22}$'),
    secret_seed bytea NOT NULL CHECK (octet_length(secret_seed) = 32),
    pepper_version text NOT NULL CHECK (pepper_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    ip_allowlist cidr[] NOT NULL CHECK (cardinality(ip_allowlist) BETWEEN 1 AND 32 AND
        array_position(ip_allowlist, NULL) IS NULL),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    expires_at timestamptz CHECK (expires_at IS NULL OR isfinite(expires_at)),
    last_used_at timestamptz CHECK (last_used_at IS NULL OR isfinite(last_used_at)),
    created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    revoked_at timestamptz CHECK (revoked_at IS NULL OR isfinite(revoked_at)),
    CONSTRAINT billing_bridge_keys_revoked_556_check CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CONSTRAINT billing_bridge_keys_expiry_556_check CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX billing_bridge_keys_owner_556_idx ON billing_bridge_keys (owner_scope_id, created_at DESC, id DESC);

CREATE FUNCTION billing_bridge_ip_allowlist_valid_556(entries cidr[]) RETURNS boolean
LANGUAGE sql IMMUTABLE AS $$
    SELECT NOT EXISTS (SELECT 1 FROM unnest(entries) entry WHERE masklen(entry) = 0)
$$;
ALTER TABLE billing_bridge_keys ADD CONSTRAINT billing_bridge_keys_allowlist_556_check
    CHECK (billing_bridge_ip_allowlist_valid_556(ip_allowlist));

CREATE FUNCTION guard_billing_bridge_key_556() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    scope_kind text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing bridge keys are kept (revoke instead)' USING ERRCODE='P5561';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id <> OLD.id OR NEW.key_id <> OLD.key_id OR NEW.owner_scope_id <> OLD.owner_scope_id OR
           NEW.owner_kind <> OLD.owner_kind OR NEW.created_by <> OLD.created_by OR NEW.created_at <> OLD.created_at OR
           NEW.revision < OLD.revision OR (OLD.status = 'revoked' AND (NEW.status <> 'revoked' OR
           NEW.secret_seed <> OLD.secret_seed OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)) THEN
            RAISE EXCEPTION 'billing bridge key identity is immutable and revocation is final' USING ERRCODE='P5562';
        END IF;
        -- Recording use or revoking needs no live owner; a new secret does.
        IF NEW.secret_seed = OLD.secret_seed OR NEW.status <> 'active' THEN
            RETURN NEW;
        END IF;
    END IF;
    SELECT kind INTO scope_kind FROM access_scopes WHERE id = NEW.owner_scope_id;
    IF NEW.owner_kind = 'platform' AND scope_kind IS DISTINCT FROM 'platform' OR
       NEW.owner_kind = 'reseller' AND scope_kind IS DISTINCT FROM 'tenant' THEN
        RAISE EXCEPTION 'billing bridge key owner kind does not match its scope' USING ERRCODE='P5563';
    END IF;
    IF NEW.owner_kind = 'reseller' AND (NOT reseller_scope_active_480(NEW.owner_scope_id) OR NOT EXISTS (
        SELECT 1 FROM access_scopes scope JOIN tenants tenant ON tenant.id = scope.tenant_id
        WHERE scope.id = NEW.owner_scope_id AND tenant.status = 'active')) THEN
        RAISE EXCEPTION 'billing bridge keys of a reseller need an active reseller' USING ERRCODE='P5564';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER billing_bridge_keys_guard_556
BEFORE INSERT OR UPDATE OR DELETE ON billing_bridge_keys
FOR EACH ROW EXECUTE FUNCTION guard_billing_bridge_key_556();

CREATE TABLE billing_bridge_nonces (
    key_id text NOT NULL REFERENCES billing_bridge_keys(key_id) ON DELETE RESTRICT,
    nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{16,64}$'),
    seen_at timestamptz NOT NULL CHECK (isfinite(seen_at)),
    PRIMARY KEY (key_id, nonce)
);
CREATE INDEX billing_bridge_nonces_seen_556_idx ON billing_bridge_nonces (seen_at);

CREATE TABLE billing_bridge_logs (
    id uuid PRIMARY KEY,
    key_id text NOT NULL REFERENCES billing_bridge_keys(key_id) ON DELETE RESTRICT,
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]{0,63}$'),
    external_service_id text CHECK (external_service_id IS NULL OR char_length(external_service_id) BETWEEN 1 AND 128),
    result text NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    reason_code text CHECK (reason_code IS NULL OR reason_code ~ '^[a-z][a-z0-9_.]{0,63}$'),
    http_status integer NOT NULL CHECK (http_status BETWEEN 100 AND 599),
    duration_ms integer NOT NULL CHECK (duration_ms >= 0),
    source_ip inet,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    CONSTRAINT billing_bridge_logs_reason_556_check CHECK ((result = 'denied') = (reason_code IS NOT NULL))
);
CREATE INDEX billing_bridge_logs_owner_556_idx ON billing_bridge_logs (owner_scope_id, created_at DESC, id DESC);
CREATE INDEX billing_bridge_logs_created_556_idx ON billing_bridge_logs (created_at);

REVOKE ALL ON billing_bridge_keys, billing_bridge_nonces, billing_bridge_logs FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON billing_bridge_keys TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, DELETE ON billing_bridge_nonces, billing_bridge_logs TO cdnca_control_app, cdnca_control_runtime;

INSERT INTO permissions(name, description)
VALUES ('billing_bridge.manage', 'Manage the platform billing bridge keys and read the bridge logs (ADR 0019)');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'billing_bridge.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;
