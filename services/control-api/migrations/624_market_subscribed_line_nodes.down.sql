-- 624 回退：线路组当前版本里还有订阅节点端点时拒绝（回退后它们会变成不受订阅状态约束的普通 IP，
-- 订阅到期也照发）；先在线路分组>设置解析删除这些 IP 并保存。历史版本里的订阅端点回退后只剩 IP。
-- serving 视图恢复为 280 的定义。
LOCK TABLE schema_migrations, node_line_endpoints, site_supplies IN ACCESS EXCLUSIVE MODE;

DO $migration_624_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 624 OR
       (SELECT max(version) FROM schema_migrations) <> 624 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=624 AND
        migration_id='624_market_subscribed_line_nodes' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 624 down requires the exact verified migration head' USING ERRCODE='P6241';
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_line_endpoints endpoint
        JOIN node_line_groups line_group ON line_group.tenant_scope_id = endpoint.tenant_scope_id
         AND line_group.id = endpoint.line_group_id AND line_group.current_revision = endpoint.config_revision
         AND line_group.deleted_at IS NULL
        WHERE endpoint.market_node_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 624 down: live line groups still carry subscribed market nodes' USING ERRCODE='P6242';
    END IF;
END;
$migration_624_down$;

DROP TABLE site_market_line_rollouts;
DROP FUNCTION market_line_endpoint_unserved(uuid, uuid, uuid, bigint, uuid);

CREATE OR REPLACE VIEW node_line_endpoint_serving AS
WITH classified AS (
    SELECT endpoint.tenant_scope_id, endpoint.line_group_id, endpoint.config_revision,
           endpoint.id AS endpoint_id, endpoint.node_id, endpoint.address,
           family(endpoint.address) AS address_family,
           (endpoint.enabled AND (endpoint.node_id IS NULL OR node.admin_state IN ('active', 'draining'))) AS admin_enabled,
           EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id = endpoint.node_id AND hold.held) AS held
    FROM node_line_endpoints endpoint
    LEFT JOIN nodes node ON node.id = endpoint.node_id
), counted AS (
    SELECT classified.*,
           count(*) FILTER (WHERE admin_enabled AND NOT held) OVER (
               PARTITION BY tenant_scope_id, line_group_id, config_revision, address_family) AS family_serving
    FROM classified
)
SELECT tenant_scope_id, line_group_id, config_revision, endpoint_id, node_id, address, address_family,
       admin_enabled, held,
       (admin_enabled AND (NOT held OR family_serving = 0)) AS serving,
       (admin_enabled AND held AND family_serving = 0) AS protected
FROM counted;

DROP INDEX node_line_endpoints_market_node_idx;
ALTER TABLE node_line_endpoints DROP CONSTRAINT node_line_endpoints_market_node_624_check;
ALTER TABLE node_line_endpoints DROP COLUMN market_node_id;
DROP TABLE market_subscribed_nodes;
