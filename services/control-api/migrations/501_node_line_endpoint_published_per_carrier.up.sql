-- 501（r136 fp-net2，主会话 10-25 续派：500 放开同 IP 多线路后的副作用修复）。merge-p5 由 498 改号 501，前驱 500。
-- node_line_endpoint_published（312）按地址族统计主备与在线数；同一 IP 挂在多条运营商线路时会被重复计数，
-- 且各线路的主备互相影响。改为按 (线路组版本, 运营商, 地址族) 分别计算：每条运营商线路自己的主 IP、备用 IP、
-- 上线判定与"该线路该地址族全部离线则全部发布"的兜底。输出列不变。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_501_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 500 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 500 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=500 AND
        migration_id='500_node_line_endpoint_carrier_unique' AND
        checksum_sha256='78742033724ff34b37c46cddd0eeb1382d582ba4e19d68cbd647a52190e6ffd9' AND
        down_checksum_sha256='98e26164798934be3f67f6466e0bd24de6bc3055c2709f3d7b90341fa1a04de1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_endpoint_published') IS NULL THEN
        RAISE EXCEPTION 'migration 501 requires the exact verified 500 release head' USING ERRCODE='P5010';
    END IF;
END;
$migration_501_up$;

CREATE OR REPLACE VIEW node_line_endpoint_published AS
WITH joined AS (
    SELECT serving.*, endpoint.carrier, endpoint.priority, endpoint.sort_order,
           COALESCE(revision.failover_mode, 'primary_offline') AS failover_mode,
           (serving.serving AND NOT serving.held) AS online
    FROM node_line_endpoint_serving serving
    JOIN node_line_endpoints endpoint
      ON endpoint.tenant_scope_id = serving.tenant_scope_id AND endpoint.line_group_id = serving.line_group_id
     AND endpoint.config_revision = serving.config_revision AND endpoint.id = serving.endpoint_id
    LEFT JOIN node_line_group_revisions revision
      ON revision.tenant_scope_id = serving.tenant_scope_id AND revision.line_group_id = serving.line_group_id
     AND revision.revision = serving.config_revision
), tiered AS (
    SELECT joined.*,
           min(priority) FILTER (WHERE admin_enabled) OVER family AS primary_priority
    FROM joined
    WINDOW family AS (PARTITION BY tenant_scope_id, line_group_id, config_revision, carrier, address_family)
), classified AS (
    SELECT tiered.*, COALESCE(admin_enabled AND priority = primary_priority, false) AS is_primary,
           COALESCE(admin_enabled AND priority > primary_priority, false) AS is_standby
    FROM tiered
), counted AS (
    SELECT classified.*,
           count(*) FILTER (WHERE is_primary) OVER family AS primaries,
           count(*) FILTER (WHERE is_primary AND online) OVER family AS online_primaries,
           count(*) FILTER (WHERE is_standby) OVER family AS standbys,
           count(*) FILTER (WHERE online) OVER family AS online_total,
           row_number() OVER (
               PARTITION BY tenant_scope_id, line_group_id, config_revision, carrier, address_family, (is_standby AND online)
               ORDER BY priority, sort_order, address) AS standby_rank
    FROM classified
    WINDOW family AS (PARTITION BY tenant_scope_id, line_group_id, config_revision, carrier, address_family)
)
SELECT tenant_scope_id, line_group_id, config_revision, endpoint_id, node_id, address, address_family,
       priority, sort_order, serving, is_standby AS standby,
       (serving AND (
           online_total = 0 OR (is_primary AND online) OR (is_standby AND online AND CASE
               WHEN failover_mode = 'online_less_than_backup_count' THEN online_primaries < standbys
               ELSE standby_rank <= primaries - online_primaries END)
       )) AS published
FROM counted;
