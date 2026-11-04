-- 032 (after 031 market_security_logged): traffic summaries a leaf controller
-- relayed for this controller's market-supplied sites (operation
-- supply.sitestats, libs/marketproto/sitestats), bound to the local site by
-- site_supply_leaf_sites.leaf_site_id. Rows per site and leaf: one "minute"
-- row per minute with requests; one "code" row per top status code and one
-- "host" row per top host of a 5-minute window (bucket_at = window start).
-- A redelivered summary replaces its own rows (read with FINAL).
CREATE TABLE IF NOT EXISTS market_site_stats_v1
(
    tenant_id UUID,
    site_id UUID,
    supply_id UUID,
    leaf_member_id UUID,
    leaf_site_id UUID,
    row_kind LowCardinality(String),
    row_key String,
    bucket_at DateTime('UTC'),
    requests UInt64,
    bytes_in UInt64,
    bytes_out UInt64,
    peak_bps UInt64,
    status_2xx UInt64,
    status_3xx UInt64,
    status_4xx UInt64,
    status_5xx UInt64,
    cache_hits UInt64,
    cache_misses UInt64,
    cache_hit_bytes UInt64,
    errors UInt64,
    duration_us_sum UInt64,
    received_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(bucket_at)
ORDER BY (tenant_id, site_id, bucket_at, leaf_member_id, row_kind, row_key)
TTL bucket_at + INTERVAL 30 DAY DELETE;
