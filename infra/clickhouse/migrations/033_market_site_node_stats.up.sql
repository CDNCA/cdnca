-- 033 (前驱 032 market_site_stats): per-node traffic a leaf
-- controller relayed for this controller's market-supplied sites (operation
-- supply.sitestats, schema cdnca.market.sitestats.nodes/v1). One row per
-- site, subscribed node and minute with requests; node_ref is the market's
-- buyer-facing node name (market_subscribed_nodes.ref), never the seller's
-- node ID or address. Read for the node realtime page: one node's traffic
-- of this controller's sites. A redelivered summary replaces its own rows
-- (read with FINAL).
CREATE TABLE IF NOT EXISTS market_site_node_stats_v1
(
    tenant_id UUID,
    site_id UUID,
    supply_id UUID,
    leaf_member_id UUID,
    leaf_site_id UUID,
    node_ref String,
    bucket_at DateTime('UTC'),
    requests UInt64,
    bytes_in UInt64,
    bytes_out UInt64,
    peak_bps UInt64,
    status_2xx UInt64,
    status_3xx UInt64,
    status_4xx UInt64,
    status_5xx UInt64,
    received_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(bucket_at)
ORDER BY (leaf_member_id, node_ref, bucket_at, tenant_id, site_id)
TTL bucket_at + INTERVAL 30 DAY DELETE;
