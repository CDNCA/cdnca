-- 553（fix-aephase1，主会话 10-27 预留；占位，合入时由主会话改号与改钉前驱，前驱暂钉 547_node_ip_location_resolution）：
-- 聚合调度对标 AxisNow 的低成本差距（订阅方视角，不开放租户端）。
-- ② 24 小时可用性/速度视图：aggregated_edge_probe_rounds 由保留 2 小时改为 26 小时（代码常量，无结构变化）；
--    自有节点组没有拨测轮次，新增 aggregated_edge_local_rounds：每次调度时记一行站点自有节点组当时是否有已发布端点。
-- ⑥ 拨测更灵活：第三方供给可选 GET/HEAD、自定义请求头（最多 8 个，不允许 Host 等由拨测自己定的头）、
--    连续失败/连续成功几次才改判（1–10，默认 3，与 ADR 0008 §6.3 原写死值一致）。
--    请求方法与请求头需要节点声明 AGGREGATED_EDGE_PROBE v1（能力 75）；不声明的旧节点仍按 GET、不带自定义头拨测。
LOCK TABLE schema_migrations, site_supply_cdn_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_553_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 552 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 552 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=552 AND
        migration_id='552_usage_report_state' AND
        checksum_sha256='8211118bdc7b76025ad0600d4e2f05790c65193510374eb019a54151ceefdc48' AND
        down_checksum_sha256='6e73505720198c4ce48ffd2f0fbf49f1c1afa2e9f435a4e2ded72c6e06353987' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.aggregated_edge_local_rounds') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 553 requires the exact verified 552 release head' USING ERRCODE='P5530';
    END IF;
END;
$migration_553_up$;

-- One scheduling pass's view of a site's own node group: healthy = it had
-- published endpoints then. Kept 26 hours like the probe rounds.
CREATE TABLE aggregated_edge_local_rounds (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    round_at timestamptz NOT NULL CHECK (isfinite(round_at)),
    healthy boolean NOT NULL,
    PRIMARY KEY (site_id, round_at)
);
CREATE INDEX aggregated_edge_local_rounds_age_553_idx ON aggregated_edge_local_rounds (round_at);

ALTER TABLE site_supply_cdn_configs
    ADD COLUMN health_method text NOT NULL DEFAULT 'GET' CHECK (health_method IN ('GET', 'HEAD')),
    -- [{"name","value"}]: names are HTTP tokens; Host, User-Agent, Connection, Content-Length, Transfer-Encoding,
    -- Upgrade and TE are set by the probe itself and refused.
    ADD COLUMN health_headers jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(health_headers) = 'array' AND jsonb_array_length(health_headers) <= 8 AND
        octet_length(health_headers::text) <= 4096),
    ADD COLUMN failure_threshold integer NOT NULL DEFAULT 3 CHECK (failure_threshold BETWEEN 1 AND 10),
    ADD COLUMN recovery_threshold integer NOT NULL DEFAULT 3 CHECK (recovery_threshold BETWEEN 1 AND 10);

REVOKE ALL ON aggregated_edge_local_rounds FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON aggregated_edge_local_rounds TO cdnca_control_app, cdnca_control_runtime;
