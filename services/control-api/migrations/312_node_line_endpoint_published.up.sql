LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_312_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 311 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 311 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=311 AND
        migration_id='311_edge_system_republication' AND
        checksum_sha256='c3e3272b23d5b728ac56dc1ddcb0cfbecc06c7167ca802bfc44996bc3a9ea9ef' AND
        down_checksum_sha256='b2aa0eac0c6c022e024a843f8c6ed118a925f5e9ad72773afe1e8275cc3affb8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_endpoint_serving') IS NULL
         OR to_regclass(current_schema() || '.node_line_endpoint_published') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 312 requires the exact verified 311 release head' USING ERRCODE='P3120';
    END IF;
END;
$migration_312_up$;

-- 备用IP上线顺序 (NF19): which serving endpoints DNS publishes. Per address
-- family, the admin-enabled endpoints of the lowest priority are primaries;
-- higher priorities are standby IPs, ordered by (priority, sort_order,
-- address). failover_mode of the line group revision decides when standbys
-- come online:
--   primary_offline (and interval, whose rotation has no defined semantics
--   yet): one online standby per primary that is offline;
--   online_less_than_backup_count: every online standby once fewer primaries
--   are online than there are standby IPs.
-- When no endpoint of the family is online, every serving endpoint is
-- published (the fail-open of node_line_endpoint_serving). A single priority
-- tier publishes exactly the serving set. node_line_endpoint_serving is
-- unchanged: standby nodes still receive configuration.
CREATE VIEW node_line_endpoint_published AS
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

REVOKE ALL ON node_line_endpoint_published FROM PUBLIC;
GRANT SELECT ON node_line_endpoint_published TO cdnca_control_app, cdnca_control_runtime;
