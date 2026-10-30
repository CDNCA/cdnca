-- 501（r136 fp-net2）回退：恢复 312 的按地址族（不分运营商）主备计算。视图无数据，可随时回退。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_501_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 501 OR
       (SELECT max(version) FROM schema_migrations) <> 501 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=501 AND
        migration_id='501_node_line_endpoint_published_per_carrier' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 501 down requires the exact verified migration head' USING ERRCODE='P5011';
    END IF;
END;
$migration_501_down$;

CREATE OR REPLACE VIEW node_line_endpoint_published AS
WITH joined AS (
    SELECT serving.*, endpoint.priority, endpoint.sort_order,
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
    WINDOW family AS (PARTITION BY tenant_scope_id, line_group_id, config_revision, address_family)
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
               PARTITION BY tenant_scope_id, line_group_id, config_revision, address_family, (is_standby AND online)
               ORDER BY priority, sort_order, address) AS standby_rank
    FROM classified
    WINDOW family AS (PARTITION BY tenant_scope_id, line_group_id, config_revision, address_family)
)
SELECT tenant_scope_id, line_group_id, config_revision, endpoint_id, node_id, address, address_family,
       priority, sort_order, serving, is_standby AS standby,
       (serving AND (
           online_total = 0 OR (is_primary AND online) OR (is_standby AND online AND CASE
               WHEN failover_mode = 'online_less_than_backup_count' THEN online_primaries < standbys
               ELSE standby_rank <= primaries - online_primaries END)
       )) AS published
FROM counted;
