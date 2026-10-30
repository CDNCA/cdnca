-- 492（r136 tp-b2，用户 10-25 04:1x：网站列表 DNS API / 默认设置补租户级后端，照竞品做）。
-- 原占位 490，merge-p2 合入时改号为 492，接在 491_audit_user_agent 之后。
LOCK TABLE schema_migrations, dns_providers, site_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_492_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 491 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 491 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=491 AND
        migration_id='491_audit_user_agent' AND
        checksum_sha256='910509fe143010d111092d82e708e54f306c6eb8ac16f496005999d1623a5ff2' AND
        down_checksum_sha256='86252f1ad503ed9ca383de7ef96d23d97361463daf94bfc1a8de2192271b908c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.site_user_defaults') IS NOT NULL OR
            to_regclass(current_schema() || '.site_auto_dns_tasks') IS NOT NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='dns_providers' AND column_name='remark') THEN
        RAISE EXCEPTION 'migration 492 requires the exact verified 491 release head' USING ERRCODE='P4920';
    END IF;
END;
$migration_492_up$;

-- 竞品 DNS API 列表与新增弹窗的"备注"。不进 089 的授权摘要：改备注不改变账号能写哪些记录。
ALTER TABLE dns_providers
    ADD COLUMN remark text NOT NULL DEFAULT '' CHECK (remark = btrim(remark) AND char_length(remark) <= 256);

-- 竞品用户端网站列表「默认设置」：租户给自己新建网站设的默认值（ID / 设置项 / 设置值 / 生效范围），
-- 生效范围 global（本用户全部新站）或 group（指定网站分组的新站，优先于 global）。
-- 只在建站时带入请求里没写的字段，不回写已有网站。
CREATE TABLE site_user_defaults (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    display_id bigint NOT NULL CHECK (display_id > 0),
    owner_user_id uuid NOT NULL,
    setting_name text NOT NULL CHECK (setting_name IN (
        'http_listen_port', 'https_listen_port', 'balance_way', 'backend_https_port',
        'ups_keepalive', 'ups_keepalive_timeout', 'websocket_enable', 'force_ssl_enable',
        'hsts', 'ocsp_stapling', 'recv_real_time', 'send_real_time')),
    setting_value text NOT NULL CHECK (setting_value = btrim(setting_value) AND char_length(setting_value) BETWEEN 1 AND 256),
    scope_name text NOT NULL CHECK (scope_name IN ('global', 'group')),
    group_id uuid,
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (scope_id, owner_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, group_id) REFERENCES site_groups(scope_id, id) ON DELETE CASCADE,
    CHECK ((scope_name = 'global') = (group_id IS NULL)),
    CHECK (updated_at >= created_at),
    UNIQUE (scope_id, display_id)
);
CREATE UNIQUE INDEX site_user_defaults_global_492_idx
    ON site_user_defaults (scope_id, owner_user_id, setting_name) WHERE group_id IS NULL;
CREATE UNIQUE INDEX site_user_defaults_group_492_idx
    ON site_user_defaults (scope_id, owner_user_id, setting_name, group_id) WHERE group_id IS NOT NULL;
CREATE INDEX site_user_defaults_scope_created_492_idx ON site_user_defaults (scope_id, created_at DESC, id DESC);

-- 建站弹窗「DNS API（自动添加记录）」：用租户自己的 DNS 账号把业务域名 CNAME 到站点 CNAME。
-- 每站一行，建站事务内写入；后台按 next_attempt_at 领取，写入服务商并回查一致即 done（用户 10-24 13:4x）。
-- 失败只记在这里并在站点上提示，不影响站点本身；暂时性失败按退避自动重试，「同步解析」手动重置。
CREATE TABLE site_auto_dns_tasks (
    site_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    provider_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'done', 'failed')),
    -- generation 每次「同步解析」加 1：领取时记下，回写时比对，旧的一轮结果不会覆盖新一轮。
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    failure_code text CHECK (failure_code IS NULL OR char_length(failure_code) BETWEEN 1 AND 128),
    results jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(results) = 'array'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    FOREIGN KEY (scope_id, provider_id) REFERENCES dns_providers(scope_id, id) ON DELETE CASCADE,
    CHECK ((state = 'failed') = (failure_code IS NOT NULL)),
    CHECK ((state = 'pending') = (completed_at IS NULL))
);
CREATE INDEX site_auto_dns_tasks_due_492_idx ON site_auto_dns_tasks (next_attempt_at) WHERE state = 'pending';
CREATE INDEX site_auto_dns_tasks_provider_492_idx ON site_auto_dns_tasks (provider_id);

ALTER TABLE site_write_requests
    DROP CONSTRAINT site_write_requests_operation_check,
    ADD CONSTRAINT site_write_requests_operation_check CHECK (
        operation IN ('site.create', 'site.update', 'site.delete', 'site.lock', 'site.unlock',
                      'site.status_recovery.unlock', 'site.status_recovery.renewal',
                      'site.status_recovery.traffic_top_up',
                      'site_default.create', 'site_default.update', 'site_default.delete')
    );

DO $migration_492_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON site_user_defaults, site_auto_dns_tasks TO cdnca_control_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_runtime') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON site_user_defaults, site_auto_dns_tasks TO cdnca_control_runtime;
    END IF;
END;
$migration_492_grants$;
