-- 637（独享订阅节点；
-- 前驱 636_plugin_installation_platform_targets）：买方主控记下哪些订阅节点是独享的，并保存独享节点的整机指标
-- （docs/architecture/market-subscribed-nodes.md §9.2）。
--
--   1. market_subscribed_nodes.exclusive：市场 /v1/supply-nodes 对独享订阅给 exclusive=true（同时 ip_public=true），
--      每轮同步写入；订阅结束、授权撤销后市场不再列出，行照旧软删。
--   2. market_subscribed_node_host_samples：卖方经 supply.sitestats 中继发来的整机批次（cdnca.market.sitestats.host/v1），
--      每节点每分钟一行（最后一个样本）；只收本主控订阅自该卖方、且是独享的节点。online 是卖方发送时的在线状态。
--      保留 24 小时（接收时清理），实时监控页读它。
-- 只加不改：已有行 exclusive=false，与之前的行为一致。
LOCK TABLE schema_migrations, market_subscribed_nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_637_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 636 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 636 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=636 AND
        migration_id='636_plugin_installation_platform_targets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_subscribed_nodes') IS NULL OR
          to_regclass(current_schema() || '.market_subscribed_node_host_samples') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 637 requires the exact verified 636 release head' USING ERRCODE='P6370';
    END IF;
END;
$migration_637_up$;

ALTER TABLE market_subscribed_nodes ADD COLUMN exclusive boolean NOT NULL DEFAULT false;

CREATE TABLE market_subscribed_node_host_samples (
    leaf_member_id uuid NOT NULL,
    ref text NOT NULL CHECK (ref ~ '^[0-9a-f]{16}$'),
    minute timestamptz NOT NULL CHECK (minute = date_trunc('minute', minute)),
    online boolean NOT NULL,
    cpu_percent double precision NOT NULL CHECK (cpu_percent BETWEEN 0 AND 100),
    memory_used_bytes bigint NOT NULL CHECK (memory_used_bytes >= 0),
    memory_total_bytes bigint NOT NULL CHECK (memory_total_bytes >= memory_used_bytes),
    active_connections bigint NOT NULL CHECK (active_connections >= 0),
    rx_bps bigint NOT NULL CHECK (rx_bps >= 0),
    tx_bps bigint NOT NULL CHECK (tx_bps >= 0),
    load_1 double precision NOT NULL CHECK (load_1 >= 0),
    load_5 double precision NOT NULL CHECK (load_5 >= 0),
    load_15 double precision NOT NULL CHECK (load_15 >= 0),
    disks jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(disks) = 'array'),
    received_at timestamptz NOT NULL,
    PRIMARY KEY (leaf_member_id, ref, minute)
);
CREATE INDEX market_subscribed_node_host_samples_received_637_idx ON market_subscribed_node_host_samples (received_at);

REVOKE ALL ON market_subscribed_node_host_samples FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON market_subscribed_node_host_samples TO cdnca_control_app, cdnca_control_runtime;
