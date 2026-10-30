LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_450_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 449 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 449 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=449 AND
        migration_id='449_agent_gateway_disabled_at' AND
        checksum_sha256='ee29f2f7729d456bd7194e9730e13ebc235b8d8e5e934895f847bebffebd8afa' AND
        down_checksum_sha256='dd63d5ce247fa273fae90b965776a165aca3cbde6a9e617fc26c6104a7654fda' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.waf_adapt_node_limits') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 450 requires the exact verified 449 release head' USING ERRCODE='P4500';
    END IF;
END;
$migration_450_up$;

-- 450（r136 waf-exclcap2，merge-batch12 由占位 434 改号，用户 10-21 08:50：自动排除上限按节点动态调节）。
-- waf_adapt_node_limits: how many of a site's delivered active exclusions each
-- node applies (waf_evidence limit): the node takes the first applied by rank
-- from its own measured per exclusion cost and the platform's latency and
-- memory budgets; the rest stay checked by their rules. The site page shows
-- "本站在各节点实际生效 X/Y 条". One row per site and node, the newest report.
CREATE TABLE waf_adapt_node_limits (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    delivered integer NOT NULL CHECK (delivered BETWEEN 1 AND 512),
    applied integer NOT NULL CHECK (applied >= 0),
    latency_trimmed integer NOT NULL CHECK (latency_trimmed >= 0),
    memory_trimmed integer NOT NULL CHECK (memory_trimmed >= 0),
    cost_ns integer NOT NULL CHECK (cost_ns BETWEEN 0 AND 1000000),
    reported_at timestamptz NOT NULL CHECK (isfinite(reported_at)),
    PRIMARY KEY (tenant_scope_id, site_id, node_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK (applied + latency_trimmed + memory_trimmed = delivered)
);
