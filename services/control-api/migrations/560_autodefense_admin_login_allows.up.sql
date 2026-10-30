-- 560（fix-adplatwire，占位号，合入时按集成头顺延并改守卫）：管理登录来源 IP 自动加白（ADR 0010 §7.2 第 3 条）。
-- 主控登录成功时按平台设置 admin_login_whitelist_days 记录来源 IP（/32 或 /128）与到期时刻；分发器把未到期的
-- 行并入快照站点白名单（source=admin_login）：平台作用域的登录覆盖全部站点，租户作用域只覆盖该租户的站点。
-- 到期的行由分发器删除（审计 security.autodefense.admin_login_allow_expire）。
-- 前驱：集成头 552（usage_report_state）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_560_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 559 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 559 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=559 AND
        migration_id='559_site_dns_resolution_checks' AND
        checksum_sha256='40175e26c31666fd56387e1bee69e1982e394ba889dfb679667d7a975dec371f' AND
        down_checksum_sha256='2890be05f627c52dbb5bb9dc6c1bc1d0db62ffd41f5f19d849c6498c8cbf4271' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('autodefense_admin_login_allows') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 560 requires the exact verified 559 release head' USING ERRCODE='P5600';
    END IF;
END;
$migration_560_up$;

CREATE TABLE autodefense_admin_login_allows (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    cidr cidr NOT NULL CHECK (masklen(cidr) = CASE WHEN family(cidr) = 4 THEN 32 ELSE 128 END),
    user_id uuid NOT NULL,
    first_seen_at timestamptz NOT NULL CHECK (isfinite(first_seen_at)),
    last_login_at timestamptz NOT NULL CHECK (isfinite(last_login_at) AND last_login_at >= first_seen_at),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > last_login_at),
    PRIMARY KEY (scope_id, cidr)
);
CREATE INDEX autodefense_admin_login_allows_expiry_idx ON autodefense_admin_login_allows (expires_at);

REVOKE ALL ON autodefense_admin_login_allows FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_admin_login_allows TO cdnca_control_app, cdnca_control_runtime;
