-- 559（fix-readiness，用户 10-27 22:4x“接入已就绪本版就补上服务端字段”；占位，合入时由主会话改号与改钉前驱，
-- 前驱暂钉集成头 552_usage_report_state）。
-- 站点接入状态 dns_resolved 的后台检查结果：每站一行，主控本机解析器查站点每个域名是否 CNAME 到分配的
-- CNAME（或 A/AAAA 全部落在线路组节点 IP）。不调用 dnspup/DNS 服务商 API。
-- 站点列表/详情只读本表（internal/site access_readiness*.go），请求里不做解析。
-- 限频：通过后 10 分钟再查；未通过按 10m·2^(n-1) 退避，上限 1 小时；详情“立即检查”同站 1 分钟一次（manual_requested_at）。
-- cname/domains 记下检查时的目标：站点 CNAME 或域名变了，旧结果不再算数（读方按“未检查”处理），并且 next_check_at 不影响新站点。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_559_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 558 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 558 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=558 AND
        migration_id='558_market_renewal_compensated_notices' AND
        checksum_sha256='9e30e27e85c3b2663348006b58e2ce4c761b9c598f0a1f5759d3a1f2085170ab' AND
        down_checksum_sha256='ee9f945a38a7aa8b0978839b3cef82710deec109cafbb84caa275acd93f97c07' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('site_dns_resolution_checks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 559 requires the exact verified 558 release head' USING ERRCODE='P5590';
    END IF;
END;
$migration_559_up$;

CREATE TABLE site_dns_resolution_checks (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    scope_id uuid NOT NULL,
    -- ok：每个域名都解析到我们；detail：第一个未通过域名的原因码。
    ok boolean NOT NULL DEFAULT false,
    detail text CHECK (detail IS NULL OR detail ~ '^[a-z_]{1,64}$'),
    cname text NOT NULL DEFAULT '' CHECK (char_length(cname) <= 253),
    domains text[] NOT NULL DEFAULT '{}' CHECK (cardinality(domains) <= 100),
    -- [{domain, code?}]，每个域名一项。
    results jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(results) = 'array' AND octet_length(results::text) <= 65536),
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    next_check_at timestamptz NOT NULL CHECK (isfinite(next_check_at)),
    -- 租约：领取时 next_check_at 推到租约之后，进程崩溃后自动重领；generation 防止旧租约覆盖“立即检查”的结果。
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    checked_at timestamptz CHECK (checked_at IS NULL OR isfinite(checked_at)),
    manual_requested_at timestamptz CHECK (manual_requested_at IS NULL OR isfinite(manual_requested_at)),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    -- 未检查过的行没有结果；通过的行没有失败原因。
    CHECK (checked_at IS NOT NULL OR (NOT ok AND detail IS NULL AND results = '[]'::jsonb)),
    CHECK (NOT ok OR (checked_at IS NOT NULL AND detail IS NULL))
);

CREATE INDEX site_dns_resolution_checks_due_idx ON site_dns_resolution_checks (next_check_at);

REVOKE ALL ON site_dns_resolution_checks FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON site_dns_resolution_checks TO cdnca_control_app, cdnca_control_runtime;
