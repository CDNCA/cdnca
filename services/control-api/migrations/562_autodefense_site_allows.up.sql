-- 562（fix-adwhitelist，派单占位号，合入时由主会话按集成头顺延并改钉前驱）：智能自动防御“解除并加白”持久化（ADR 0010 §7.4）。
-- 最近判定/拉黑日志里“解除并加入白名单”的 IP/网段/JA4 写入本表（source=release，永久或选定期限，可在站点详情移除），每站最多 64 条；
-- 分发器把本表与站点 ACL 策略生效版本里的放行规则（source=user）一起并入快照站点白名单，节点处置门对其永不处置。
-- 同一迁移（fix-adwhitelist2）另建 autodefense_site_releases：单条解除的目标（ip/cidr/ja4）与时间，分发器把近 24 小时的
-- 条目随快照下发（Site.Releases），节点立即撤销该目标在解除前已有的本地处置（含它写入的内核封禁），SEC-CONTROL-RECOVERY-01。
-- 前驱：集成头 554（node_bandwidth_alerts）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_562_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 561 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 561 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=561 AND
        migration_id='561_fallback_chain' AND
        checksum_sha256='dde5d9feddd7570881033c218f65ad5ced0f75e54c147915edc85c7fcb81e281' AND
        down_checksum_sha256='ca1a7585ffc3bfedd2e42498fe74f5392dcc02d262742220ff208fdbf6425a11' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('autodefense_site_allows') IS NOT NULL OR
       to_regclass('autodefense_site_releases') IS NOT NULL OR
       to_regclass('autodefense_site_release_acks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 562 requires the exact verified 561 release head' USING ERRCODE='P5620';
    END IF;
END;
$migration_562_up$;

-- fix-adwhitelist3：加白目标可为 IP/网段（kind=cidr，target 为规范网段文本）或 JA4（kind=ja4），每站合计 ≤64；
-- expires_at NULL=永久，否则到期由分发器删除并下发（审计 site_allow_expire）。
CREATE TABLE autodefense_site_allows (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('cidr', 'ja4')),
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 128),
    source text NOT NULL CHECK (source = 'release'),
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz CHECK (expires_at IS NULL OR (isfinite(expires_at) AND expires_at > created_at)),
    PRIMARY KEY (tenant_scope_id, site_id, kind, target),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);
CREATE INDEX autodefense_site_allows_expires_at ON autodefense_site_allows (expires_at) WHERE expires_at IS NOT NULL;

REVOKE ALL ON autodefense_site_allows FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_site_allows TO cdnca_control_app, cdnca_control_runtime;

CREATE TABLE autodefense_site_releases (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('ip', 'cidr', 'ja4')),
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 128),
    released_by text NOT NULL CHECK (char_length(released_by) BETWEEN 1 AND 256),
    released_at timestamptz NOT NULL CHECK (isfinite(released_at)),
    -- fix-adwhitelist3：人工“重试”次数，随快照下发（Site.Releases.retry），节点按新值重新应用并回执
    retry integer NOT NULL DEFAULT 0 CHECK (retry BETWEEN 0 AND 100),
    PRIMARY KEY (tenant_scope_id, site_id, kind, target),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);
CREATE INDEX autodefense_site_releases_released_at ON autodefense_site_releases (released_at);

REVOKE ALL ON autodefense_site_releases FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_site_releases TO cdnca_control_app, cdnca_control_runtime;

-- fix-adwhitelist3：按目标的节点回执（报告 kind release_acks）。每个节点每个解除目标保留最新一条，
-- released_at/retry 为节点应用的那次解除；与 autodefense_site_releases 当前值相同才算“本次解除”的结果。
CREATE TABLE autodefense_site_release_acks (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('ip', 'cidr', 'ja4')),
    target text NOT NULL CHECK (char_length(target) BETWEEN 1 AND 128),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    released_at timestamptz NOT NULL CHECK (isfinite(released_at)),
    retry integer NOT NULL CHECK (retry BETWEEN 0 AND 100),
    applied boolean NOT NULL,
    error_code text CHECK (error_code IN ('gate_write_failed', 'kernel_unban_failed')),
    reported_at timestamptz NOT NULL CHECK (isfinite(reported_at)),
    CHECK (applied = (error_code IS NULL)),
    PRIMARY KEY (tenant_scope_id, site_id, kind, target, node_id),
    FOREIGN KEY (tenant_scope_id, site_id, kind, target)
        REFERENCES autodefense_site_releases(tenant_scope_id, site_id, kind, target) ON DELETE CASCADE
);

-- 节点的 release_acks 报告与其它报告一样记回执（423 的种类约束补上它）。
ALTER TABLE autodefense_report_receipts DROP CONSTRAINT autodefense_report_receipts_kind_check;
ALTER TABLE autodefense_report_receipts ADD CONSTRAINT autodefense_report_receipts_kind_check
    CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event', 'drift', 'waf_evidence',
                    'release_acks'));

REVOKE ALL ON autodefense_site_release_acks FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_site_release_acks TO cdnca_control_app, cdnca_control_runtime;
