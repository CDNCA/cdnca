LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_431_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 430 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 430 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=430 AND
        migration_id='430_market_notices' AND
        checksum_sha256='ebebc97d03df96f86c067c467403efad6bf973817db0a3b4df6e5cb9cdf947bd' AND
        down_checksum_sha256='b434f5abca5ceb6f369528c5bf4d66177a5d4b394125161e1580ea725704e6f6' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_supply_limits') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 431 requires the exact verified 430 release head' USING ERRCODE='P4310';
    END IF;
END;
$migration_431_up$;

-- 431 (r136 ML-08, ADR 0012 §6.2/§6.3; placeholder number, BATCH-PLUGIN 33
-- reserves 431, renumbered on merge). A leaf's market supply limits as its
-- nodes run them: one row per hidden package subscription (marketsupply).
--   market_key     marketsupply.Key (subscription path + pool) of the grant;
--   total_*        the grant's supply totals (0 = not selected / unlimited);
--   hold_*         the last supply.hold the market gave (stop / pause /
--                  throttle, throttle_bps for monthly traffic), kept while the
--                  market is unreachable (§6.3), hold_revision its revision;
--   serving_nodes  the pool's serving node count the shares were split by;
--   node_*         this node's share, ceil(total / serving_nodes) (Q1), what
--                  publication writes into the site objects.
-- The publisher reads only node_*, so a publication compiles the same bytes
-- whatever the node count is now; marketsupply recomputes the row and
-- republishes the tenant (trigger market_limits) when a value changes.
CREATE TABLE market_supply_limits (
    package_subscription_id uuid PRIMARY KEY REFERENCES package_subscriptions(id) ON DELETE CASCADE,
    tenant_scope_id uuid NOT NULL,
    market_key text NOT NULL UNIQUE CHECK (market_key ~ '^[0-9a-f]{24}$'),
    node_pool_ref text NOT NULL CHECK (char_length(node_pool_ref) BETWEEN 1 AND 128),
    total_bandwidth_bps bigint NOT NULL DEFAULT 0 CHECK (total_bandwidth_bps >= 0),
    total_connections bigint NOT NULL DEFAULT 0 CHECK (total_connections >= 0),
    total_requests bigint NOT NULL DEFAULT 0 CHECK (total_requests >= 0),
    total_new_per_second bigint NOT NULL DEFAULT 0 CHECK (total_new_per_second >= 0),
    total_qps bigint NOT NULL DEFAULT 0 CHECK (total_qps >= 0),
    hold_action text CHECK (hold_action IN ('throttle', 'pause', 'stop')),
    hold_throttle_bps bigint NOT NULL DEFAULT 0 CHECK (hold_throttle_bps >= 0),
    hold_revision bigint NOT NULL DEFAULT 0 CHECK (hold_revision >= 0),
    serving_nodes integer NOT NULL CHECK (serving_nodes >= 1),
    node_requests bigint NOT NULL CHECK (node_requests BETWEEN -1 AND 65535),
    node_bandwidth_bps bigint NOT NULL DEFAULT 0 CHECK (node_bandwidth_bps >= 0),
    node_connections bigint NOT NULL DEFAULT 0 CHECK (node_connections >= 0),
    node_new_per_second bigint NOT NULL DEFAULT 0 CHECK (node_new_per_second >= 0),
    node_qps bigint NOT NULL DEFAULT 0 CHECK (node_qps >= 0),
    node_stopped boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL,
    CHECK ((hold_action = 'throttle') = (hold_throttle_bps > 0))
);
REVOKE ALL ON market_supply_limits FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON market_supply_limits TO cdnca_control_app, cdnca_control_runtime;

-- A share or hold change republishes the tenant through the system channel
-- (trigger market_limits; 418's checks extended, cardinality 15 -> 16).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 16 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 16);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits'));
