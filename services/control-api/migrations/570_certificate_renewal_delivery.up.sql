-- 570（fix-dnscert3 卡 2-B 后半，占位号，合入时主会话统一连号）：自动续签的新证书不等人工发布。
-- 续签版本签发后，系统身份先把新版本私钥材料下发到需要它的节点（certificate_renewal_deliveries 记
-- 每轮下发的系统 rollout、退避与失败原因），全部节点回执成功后再切换站点到新版本并激活，经系统重新
-- 发布通道发出站点配置：新 trigger certificate_renewal（555 package_suspension 之后的约束扩展，cardinality 21 -> 22）。
-- 前驱 569（dns_provider_managed_by），守卫钉 569 校验和。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_570_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 569 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 569 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=569 AND
        migration_id='569_dns_provider_managed_by' AND
        checksum_sha256='26b098221e9b5fba4f8f4be3e8c99e22c74dc07fcca7c8465969c6e426e52a38' AND
        down_checksum_sha256='c920a0d83e918ccf6325b72fb1d77db57a96673b22ecfbd5ff0d5a30592438fa' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('certificate_renewal_deliveries') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 570 requires the exact verified 569 release head' USING ERRCODE='P5700';
    END IF;
END;
$migration_570_up$;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 22 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage', 'package_suspension', 'certificate_renewal']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 22);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage',
        'package_suspension', 'certificate_renewal'));

-- 一张续签子单一行：state delivering（本轮 rollout 在途）/ retry_wait（退避）/ activated（已切换）/
-- skipped（资产删除、禁用、关闭自动续签、版本吊销或绑定已被改动，不再切换）/ failed（重试用尽，旧证书继续服务）。
CREATE TABLE certificate_renewal_deliveries (
    scope_id uuid NOT NULL,
    order_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('delivering', 'retry_wait', 'activated', 'skipped', 'failed')),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 100),
    rollout_id uuid,
    site_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(site_ids) <= 10000),
    binding_revisions bigint[] NOT NULL DEFAULT '{}' CHECK (cardinality(binding_revisions) = cardinality(site_ids)),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    next_attempt_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, order_id),
    FOREIGN KEY (scope_id, asset_id, version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id, asset_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, rollout_id) REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT,
    CHECK (state <> 'delivering' OR rollout_id IS NOT NULL),
    CHECK (state NOT IN ('retry_wait', 'skipped', 'failed') OR failure_code IS NOT NULL)
);
CREATE INDEX certificate_renewal_deliveries_due_570_idx
    ON certificate_renewal_deliveries(next_attempt_at) WHERE state IN ('delivering', 'retry_wait');

GRANT SELECT, INSERT, UPDATE ON certificate_renewal_deliveries TO cdnca_control_app, cdnca_control_runtime;
