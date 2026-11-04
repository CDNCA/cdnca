-- 624（r136 subline，用户 11-04；占位：前驱 623，合入时由主会话统一连号）。
-- 订阅来的节点像自有节点一样进线路分组（docs/architecture/market-subscribed-nodes.md §6）：
--   1. market_subscribed_nodes：买方主控经市场 mTLS 通道（GET /v1/supply-nodes）拉到的本机订阅节点，
--      每订阅每节点一行；address 是卖方节点 IP，受保护：线路组接口只在 ip_public（报价
--      ip_visibility=public）时返回。订阅不再列出时软删（removed_at），历史线路组版本仍可引用。
--   2. node_line_endpoints.market_node_id：订阅节点端点（与 node_id 互斥）。DNS 照常走
--      node_line_endpoint_published；不进 agent 下发（无 node_id）。
--   3. node_line_endpoint_serving：订阅节点端点仅在 行未移除、市场判定可调度（available）、
--      本机供给 active 且未本机停用 时 admin_enabled；市场判定 unhealthy 记为 held
--      （同地址族全部不可用时照发，同市场 dnsselect 的兜底）。输出列不变。
--   4. market_line_endpoint_unserved(site, endpoint)：订阅节点端点对某站点是否不发（DNS 逐站点门，
--      同 acme_http01_site_node_serving_blocked 的用法）：卖方主控还没有收下该站点（无 applied_revision>0
--      的供货节点组回执，如超出域名数限额 pool_domain_limit）时，该站点不解析到这些节点；
--      site 为 NULL（四层转发）时订阅节点一律不发（站点配置不含四层）。
--   5. site_market_line_rollouts：线路组含订阅节点时站点自动下发到卖方主控的最近结果与原因（页面展示）。
LOCK TABLE schema_migrations, node_line_endpoints, site_supplies IN ACCESS EXCLUSIVE MODE;

DO $migration_624_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 623 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 623 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=623 AND migration_id='623_market_supply_local_disable' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_endpoint_serving') IS NULL THEN
        RAISE EXCEPTION 'migration 624 requires the verified 623 release head' USING ERRCODE='P6240';
    END IF;
END;
$migration_624_up$;

CREATE TABLE market_subscribed_nodes (
    id uuid PRIMARY KEY,
    supply_id uuid NOT NULL REFERENCES site_supplies(id) ON DELETE RESTRICT,
    market_subscription_id uuid NOT NULL,
    leaf_member_id uuid NOT NULL,
    node_pool_ref text NOT NULL CHECK (char_length(node_pool_ref) BETWEEN 1 AND 128),
    ref text NOT NULL CHECK (ref ~ '^[0-9a-f]{16}$'),
    address inet NOT NULL CONSTRAINT market_subscribed_nodes_address_host CHECK (
        (family(address) = 4 AND masklen(address) = 32) OR
        (family(address) = 6 AND masklen(address) = 128 AND NOT (address <<= '::ffff:0:0/96'::inet))
    ),
    region text NOT NULL DEFAULT '' CHECK (char_length(region) <= 64 AND region !~ '[[:cntrl:]]'),
    carrier text NOT NULL DEFAULT '' CHECK (char_length(carrier) <= 64 AND carrier !~ '[[:cntrl:]]'),
    seller_name text NOT NULL DEFAULT '' CHECK (char_length(seller_name) <= 128 AND seller_name !~ '[[:cntrl:]]'),
    ip_public boolean NOT NULL DEFAULT false,
    available boolean NOT NULL DEFAULT false,
    health text NOT NULL DEFAULT 'unknown' CHECK (health IN ('healthy', 'unhealthy', 'unknown')),
    state text NOT NULL DEFAULT '' CHECK (char_length(state) <= 32 AND state !~ '[[:cntrl:]]'),
    synced_at timestamptz NOT NULL,
    removed_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (market_subscription_id, ref),
    CHECK (updated_at >= created_at)
);
CREATE INDEX market_subscribed_nodes_supply_idx ON market_subscribed_nodes (supply_id) WHERE removed_at IS NULL;

ALTER TABLE node_line_endpoints ADD COLUMN market_node_id uuid
    CONSTRAINT node_line_endpoints_market_node_624_fk REFERENCES market_subscribed_nodes(id) ON DELETE RESTRICT;
ALTER TABLE node_line_endpoints ADD CONSTRAINT node_line_endpoints_market_node_624_check
    CHECK (market_node_id IS NULL OR node_id IS NULL);
CREATE INDEX node_line_endpoints_market_node_idx ON node_line_endpoints (market_node_id) WHERE market_node_id IS NOT NULL;

CREATE OR REPLACE VIEW node_line_endpoint_serving AS
WITH classified AS (
    SELECT endpoint.tenant_scope_id, endpoint.line_group_id, endpoint.config_revision,
           endpoint.id AS endpoint_id, endpoint.node_id, endpoint.address,
           family(endpoint.address) AS address_family,
           (endpoint.enabled AND (endpoint.node_id IS NULL OR node.admin_state IN ('active', 'draining'))
            AND (endpoint.market_node_id IS NULL OR COALESCE(market.removed_at IS NULL AND market.available
                 AND supply.status = 'active' AND supply.local_disabled_at IS NULL, false))) AS admin_enabled,
           (EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id = endpoint.node_id AND hold.held)
            OR COALESCE(market.health = 'unhealthy', false)) AS held
    FROM node_line_endpoints endpoint
    LEFT JOIN nodes node ON node.id = endpoint.node_id
    LEFT JOIN market_subscribed_nodes market ON market.id = endpoint.market_node_id
    LEFT JOIN site_supplies supply ON supply.id = market.supply_id
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

CREATE FUNCTION market_line_endpoint_unserved(target_site_id uuid, endpoint_scope_id uuid, endpoint_group_id uuid,
    endpoint_revision bigint, target_endpoint_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $function$
    SELECT EXISTS (
        SELECT 1 FROM node_line_endpoints endpoint
        JOIN market_subscribed_nodes market ON market.id = endpoint.market_node_id
        WHERE endpoint.tenant_scope_id = endpoint_scope_id AND endpoint.line_group_id = endpoint_group_id
          AND endpoint.config_revision = endpoint_revision AND endpoint.id = target_endpoint_id
          AND NOT EXISTS (
              SELECT 1 FROM site_supply_leaf_sites leaf
              WHERE leaf.site_id = target_site_id AND leaf.supply_id = market.supply_id
                AND leaf.leaf_member_id = market.leaf_member_id AND leaf.node_pool_ref = market.node_pool_ref
                AND leaf.applied_revision > 0))
$function$;

CREATE TABLE site_market_line_rollouts (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    supply_ids uuid[] NOT NULL DEFAULT '{}',
    line_group_ids uuid[] NOT NULL DEFAULT '{}',
    site_version bigint NOT NULL DEFAULT 0 CHECK (site_version >= 0),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    digest text NOT NULL DEFAULT '' CHECK (char_length(digest) <= 128),
    state text NOT NULL CHECK (state IN ('applied', 'blocked', 'unsupported', 'failed')),
    reasons jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(reasons) = 'array' AND jsonb_array_length(reasons) <= 64),
    attempted_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL
);
