-- 609（smartsched-core，调度预留 control 611；merge-p40b 改号 609，前驱 608_node_ssh_access）：线路组智能调度（用户 10-31）。
--   访客按「省份+运营商」解析到该线路下延迟最低、健康、未满载的 N 台自有节点；
--   线路无合格节点时逐级回退（省份运营商→同运营商全国→默认线路）。
-- 1) node_line_group_smart_schedules：每个线路组一份配置，默认关闭；关闭时 DNS 输出与现状一致。
-- 2) node_line_latency_samples：探测延迟按 线路组/端点/省份/运营商/来源/分钟 聚合（原值数组，p50 精确），
--    来源 dnspup 检查点与对端节点探测（node_dnspup_probe_results / node_peer_probe_results 的 checkpoints），
--    保留 2 小时（窗口上限 60 分钟），由 internal/smartsched 清理。
-- 3) smart_schedule_ingest_cursors：两个探测日志各自的已读到时刻。
-- 4) node_line_smart_selections：每条线路当前选中结果（滞回以它为准），scope 为 telecom/unicom/mobile
--    或 <省份>:<运营商>（如 广东:mobile）。
-- 5) cname_carrier_line_records.line_scope 放开 <省份>:<运营商>。
-- 前驱：608（node_ssh_access；集成头 604 之后 605–608 已合入）。
LOCK TABLE schema_migrations, cname_carrier_line_records IN ACCESS EXCLUSIVE MODE;

DO $migration_609_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 608 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 608 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=608 AND
        migration_id='608_node_ssh_access' AND
        checksum_sha256='bddca0189e651b9a1a2ec502517d74561a064268fa62682965416fee7beb1263' AND
        down_checksum_sha256='e2114a38aba9485d1ae854428fc1bde19086b18e29cfe8d8d68ba80d6e37483d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('node_line_group_smart_schedules') IS NOT NULL OR
       to_regclass('node_line_latency_samples') IS NOT NULL OR
       to_regclass('node_line_smart_selections') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 609 requires the exact verified 608 release head' USING ERRCODE='P6090';
    END IF;
END;
$migration_609_up$;

CREATE TABLE node_line_group_smart_schedules (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    top_n smallint NOT NULL DEFAULT 3 CHECK (top_n BETWEEN 1 AND 20),
    granularity text NOT NULL DEFAULT 'carrier' CHECK (granularity IN ('carrier', 'province_carrier')),
    latency_window_minutes smallint NOT NULL DEFAULT 15 CHECK (latency_window_minutes BETWEEN 5 AND 60),
    max_load_percent smallint NOT NULL DEFAULT 85 CHECK (max_load_percent BETWEEN 1 AND 100),
    fallback text NOT NULL DEFAULT 'carrier_then_default' CHECK (fallback = 'carrier_then_default'),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, line_group_id),
    FOREIGN KEY (tenant_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE CASCADE
);
REVOKE ALL ON node_line_group_smart_schedules FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_line_group_smart_schedules TO cdnca_control_app, cdnca_control_runtime;

CREATE TABLE node_line_latency_samples (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    address inet NOT NULL,
    -- '' = the checkpoint's province is unknown (counts for the carrier only).
    province text NOT NULL CHECK (province IN ('', '北京', '天津', '上海', '重庆', '河北', '山西', '辽宁', '吉林',
        '黑龙江', '江苏', '浙江', '安徽', '福建', '江西', '山东', '河南', '湖北', '湖南', '广东', '海南', '四川', '贵州',
        '云南', '陕西', '甘肃', '青海', '内蒙古', '广西', '西藏', '宁夏', '新疆')),
    carrier text NOT NULL CHECK (carrier IN ('telecom', 'unicom', 'mobile')),
    source text NOT NULL CHECK (source IN ('dnspup', 'peer')),
    bucket timestamptz NOT NULL CHECK (isfinite(bucket) AND bucket = date_trunc('minute', bucket)),
    latencies_ms integer[] NOT NULL CHECK (
        cardinality(latencies_ms) BETWEEN 1 AND 256 AND array_position(latencies_ms, NULL) IS NULL AND
        1 <= ALL (latencies_ms) AND 60000 >= ALL (latencies_ms)
    ),
    last_at timestamptz NOT NULL CHECK (isfinite(last_at)),
    PRIMARY KEY (tenant_scope_id, line_group_id, endpoint_id, province, carrier, source, bucket),
    FOREIGN KEY (tenant_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE CASCADE
);
CREATE INDEX node_line_latency_samples_bucket_609_idx ON node_line_latency_samples (bucket);
CREATE INDEX node_line_latency_samples_group_609_idx ON node_line_latency_samples (tenant_scope_id, line_group_id, bucket);
REVOKE ALL ON node_line_latency_samples FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_line_latency_samples TO cdnca_control_app, cdnca_control_runtime;

CREATE TABLE smart_schedule_ingest_cursors (
    source text PRIMARY KEY CHECK (source IN ('dnspup', 'peer')),
    observed_until timestamptz NOT NULL CHECK (isfinite(observed_until)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);
REVOKE ALL ON smart_schedule_ingest_cursors FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON smart_schedule_ingest_cursors TO cdnca_control_app, cdnca_control_runtime;

CREATE TABLE node_line_smart_selections (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    line_scope text NOT NULL CHECK (line_scope IN ('telecom', 'unicom', 'mobile') OR
        line_scope ~ '^(北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|内蒙古|广西|西藏|宁夏|新疆):(telecom|unicom|mobile)$'),
    -- The line group revision the selection was made from; another revision
    -- is ignored by the DNS writer until the next selection.
    group_revision bigint NOT NULL CHECK (group_revision > 0),
    -- latency: chosen by latency; static: no latency samples (the line keeps
    -- every endpoint, as without smart scheduling); fallback: nothing
    -- eligible at this level (fallback_from names the level).
    source text NOT NULL CHECK (source IN ('latency', 'static', 'fallback')),
    fallback_from text NOT NULL DEFAULT '' CHECK (fallback_from IN ('', 'province_carrier', 'carrier')),
    selected jsonb NOT NULL CHECK (jsonb_typeof(selected) = 'array' AND jsonb_array_length(selected) <= 512),
    selection_digest text NOT NULL CHECK (selection_digest ~ '^[0-9a-f]{64}$'),
    changed_at timestamptz NOT NULL CHECK (isfinite(changed_at)),
    refreshed_at timestamptz NOT NULL CHECK (isfinite(refreshed_at) AND refreshed_at >= changed_at),
    PRIMARY KEY (tenant_scope_id, line_group_id, line_scope),
    FOREIGN KEY (tenant_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE CASCADE,
    CHECK ((source = 'fallback') = (fallback_from <> ''))
);
REVOKE ALL ON node_line_smart_selections FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_line_smart_selections TO cdnca_control_app, cdnca_control_runtime;

ALTER TABLE cname_carrier_line_records DROP CONSTRAINT cname_carrier_line_records_line_scope_check,
    ADD CONSTRAINT cname_carrier_line_records_line_scope_609_check CHECK (
        line_scope IN ('telecom', 'unicom', 'mobile', 'overseas') OR
        line_scope ~ '^(北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|内蒙古|广西|西藏|宁夏|新疆):(telecom|unicom|mobile)$'
    );
