-- 538（fix-nodesettings，主会话 10-27 分配）：编辑节点 → 节点设置的缓存目录/缓存上限/日志目录下发到节点
-- （NODE_STORAGE 能力 71，密钥文档 node_storage）。节点设置变化时节点网络扫描（NodeNetworksWatcher）
-- 重新发布全部租户 scope：新 trigger node_storage（511 的约束扩展，cardinality 19 -> 20），
-- edge_node_network_marks 记各节点存储设置摘要 storage_sha256（NULL = 尚未记录：首次扫描只记录不重发）。
-- 前驱 537（certificate_asset_auto_renew），守卫钉 537 校验和。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments, edge_node_network_marks IN ACCESS EXCLUSIVE MODE;

DO $migration_538_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 537 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 537 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=537 AND
        migration_id='537_certificate_asset_auto_renew' AND
        checksum_sha256='65f096fd33f0e08d255145daa9685bff9a72c1979472cc2446ab620e9c1c233f' AND
        down_checksum_sha256='03f8bde02c7d1d1ec69d1739c2ffe6c866a893a33c85b3775a2e1789d875e7dc' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='edge_node_network_marks' AND column_name='storage_sha256'
       ) THEN
        RAISE EXCEPTION 'migration 538 requires the exact verified 537 release head' USING ERRCODE='P5380';
    END IF;
END;
$migration_538_up$;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 20 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 20);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage'));

ALTER TABLE edge_node_network_marks
    ADD COLUMN storage_sha256 bytea CHECK (storage_sha256 IS NULL OR octet_length(storage_sha256) = 32);
