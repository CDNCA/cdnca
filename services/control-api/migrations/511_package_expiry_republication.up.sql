-- 511（r136 errpage-4 S3 套餐到期；分支占位 499，merge-p9 改为 511、前驱 510；
-- 常量集中在 package_expiry_republication_511_contract_test.go）。
-- 到期站点不再整 scope 发布失败：带 package_expired 标记下发，节点出"套餐到期"页、不回源（系统设置
-- "套餐到期后关闭网站" expiry_close 开启时；关闭时照常服务）。到期与续费由扫描触发系统重新发布，
-- 新 trigger package_expiry（460 的约束扩展，cardinality 18 -> 19）。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments, package_subscriptions IN ACCESS EXCLUSIVE MODE;

DO $migration_511_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 510 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 510 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=510 AND
        migration_id='510_escalate_blackhole_drop_confirmed' AND
        checksum_sha256='00eb12bd5ca291086208f1a244ef2c1e659259cccced2fcaac87547f6b1276f7' AND
        down_checksum_sha256='ad399589119e104d5bb31d2b0f8f30f3bb6c84d044a4d39838cf5ee5c9759090' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.package_expiry_republication_marks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 511 requires the exact verified 510 release head' USING ERRCODE='P5110';
    END IF;
END;
$migration_511_up$;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 19 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 19);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry'));

-- 扫描已处理的到期：订阅在 ends_at 到期、当时 expiry_close 为何值。续费（ends_at 变化或回到有效期内）
-- 或切换 expiry_close 时扫描发现不一致，再发一次重新发布并更新/删除这一行。
CREATE TABLE package_expiry_republication_marks (
    subscription_id uuid PRIMARY KEY REFERENCES package_subscriptions(id) ON DELETE CASCADE,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    ends_at timestamptz NOT NULL CHECK (isfinite(ends_at)),
    expiry_close boolean NOT NULL,
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at))
);
