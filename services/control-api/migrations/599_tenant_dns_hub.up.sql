-- 599（fix-dnshub-api，ADR 0020 §3.1）：用户端「域名解析」——租户名下多家 DNS 账号统一管理。
-- tenant_dns_domains：每个自有 DNS 账号托管的域名清单缓存（进页面按需刷新，每账号最短 60 秒），
--   只是清单，不存记录内容；记录读取实时走 DNS 商。
-- tenant_dns_record_ops：每次增改删一行（Idempotency-Key 唯一、操作前后摘要、applied/failed/uncertain、
--   厂商记录 ID），用于幂等重放、"不确定"态重查与页面最近操作。
-- 两表只收租户自有账号（managed_by='tenant'），平台副本由触发器拒绝（同 10-29 00:0x）。
-- 不新增权限码：读 dns.read，写 dns.manage。1.0.35 全新安装，不涉及旧数据。前驱 598。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_599_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 598 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 598 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=598 AND
        migration_id='598_security_hold_republication' AND
        checksum_sha256='eb9347858ef08bfcc08baec9284d0aa61569873e01f1d1dc306f63714c1168da' AND
        down_checksum_sha256='6e47c6a8cd2a220650c0edf4f7ea50c0ff6795bdd492fd90213904f22f1be372' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.tenant_dns_domains') IS NOT NULL OR
         to_regclass(current_schema() || '.tenant_dns_record_ops') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 599 requires the exact verified 598 release head' USING ERRCODE='P5990';
    END IF;
END;
$migration_599_up$;

-- 账号的域名清单刷新状态（每账号一行；域名明细在 tenant_dns_domains）。
CREATE TABLE tenant_dns_provider_listings (
    scope_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    last_listed_at timestamptz CHECK (last_listed_at IS NULL OR isfinite(last_listed_at)),
    -- 最近一次拉清单失败的短码（'' = 成功或从未拉过）。
    list_error text NOT NULL DEFAULT '' CHECK (char_length(list_error) <= 64 AND list_error !~ '[[:cntrl:]]'),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (scope_id, provider_id),
    FOREIGN KEY (scope_id, provider_id) REFERENCES dns_providers(scope_id, id) ON DELETE CASCADE
);

CREATE TABLE tenant_dns_domains (
    scope_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    apex text NOT NULL CHECK (
        apex = lower(apex) AND char_length(apex) BETWEEN 3 AND 253 AND
        apex ~ '^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    -- 最近一次读记录时的 A/AAAA/CNAME/TXT 条数（NULL = 还没读过）。
    record_count integer CHECK (record_count IS NULL OR record_count BETWEEN 0 AND 10000),
    records_listed_at timestamptz CHECK (records_listed_at IS NULL OR isfinite(records_listed_at)),
    last_listed_at timestamptz NOT NULL CHECK (isfinite(last_listed_at)),
    list_error text NOT NULL DEFAULT '' CHECK (char_length(list_error) <= 64 AND list_error !~ '[[:cntrl:]]'),
    PRIMARY KEY (scope_id, provider_id, apex),
    FOREIGN KEY (scope_id, provider_id) REFERENCES tenant_dns_provider_listings(scope_id, provider_id) ON DELETE CASCADE,
    CHECK ((record_count IS NULL) = (records_listed_at IS NULL))
);
CREATE INDEX tenant_dns_domains_apex_599_idx ON tenant_dns_domains (scope_id, apex);

CREATE TABLE tenant_dns_record_ops (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    apex text NOT NULL CHECK (char_length(apex) BETWEEN 3 AND 253 AND apex = lower(apex)),
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    -- 请求体规范化后的 SHA-256：同 key 不同请求 = 冲突。
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    action text NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    record_type text NOT NULL CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'TXT')),
    -- 主机记录 FQDN（无末尾点）。
    record_name text NOT NULL CHECK (char_length(record_name) BETWEEN 1 AND 253 AND record_name = lower(record_name)),
    -- 操作前后的记录摘要 {name,type,value,ttl,line,weight}（值不是秘密，按原样记）。
    before jsonb CHECK (before IS NULL OR jsonb_typeof(before) = 'object'),
    after jsonb CHECK (after IS NULL OR jsonb_typeof(after) = 'object'),
    state text NOT NULL CHECK (state IN ('applied', 'failed', 'uncertain')),
    provider_record_id text NOT NULL DEFAULT '' CHECK (char_length(provider_record_id) <= 512 AND provider_record_id !~ '[[:cntrl:]]'),
    error_code text NOT NULL DEFAULT '' CHECK (char_length(error_code) <= 64 AND error_code !~ '[[:cntrl:]]'),
    -- 回放第一次结果用（HTTP 状态 + 响应体）。
    response_status integer NOT NULL CHECK (response_status BETWEEN 200 AND 599),
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    UNIQUE (scope_id, actor_user_id, idempotency_key),
    FOREIGN KEY (scope_id, provider_id) REFERENCES dns_providers(scope_id, id) ON DELETE CASCADE,
    CHECK ((state = 'failed') = (error_code <> '')),
    CHECK (action = 'create' OR before IS NOT NULL),
    CHECK (action = 'delete' OR after IS NOT NULL)
);
CREATE INDEX tenant_dns_record_ops_recent_599_idx ON tenant_dns_record_ops (scope_id, provider_id, apex, created_at DESC);

-- 只收租户作用域里由租户自己录入的账号：平台副本（managed_by='platform'）与非租户作用域一律拒绝。
CREATE FUNCTION tenant_dns_hub_provider_guard_599()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM dns_providers provider
        JOIN access_scopes scope ON scope.id = provider.scope_id AND scope.kind = 'tenant'
        WHERE provider.scope_id = NEW.scope_id AND provider.id = NEW.provider_id AND provider.managed_by = 'tenant'
    ) THEN
        RAISE EXCEPTION 'DNS hub rows only cover tenant-owned DNS accounts' USING ERRCODE = 'P5993';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER tenant_dns_provider_listings_guard_599 BEFORE INSERT OR UPDATE OF scope_id, provider_id
    ON tenant_dns_provider_listings FOR EACH ROW EXECUTE FUNCTION tenant_dns_hub_provider_guard_599();
CREATE TRIGGER tenant_dns_record_ops_guard_599 BEFORE INSERT OR UPDATE OF scope_id, provider_id
    ON tenant_dns_record_ops FOR EACH ROW EXECUTE FUNCTION tenant_dns_hub_provider_guard_599();

REVOKE ALL ON tenant_dns_provider_listings, tenant_dns_domains, tenant_dns_record_ops FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_dns_provider_listings, tenant_dns_domains
    TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON tenant_dns_record_ops TO cdnca_control_app, cdnca_control_runtime;
