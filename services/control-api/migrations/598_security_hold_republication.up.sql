-- 598（用户 10-29）：系统重新发布新 trigger security_hold——安全规则（CC/WAF）
-- 停止下发或恢复下发时，各租户按当前状态重新发布一次（570 certificate_renewal 之后的约束扩展，
-- cardinality 22 -> 23）。前驱 597（l4_forward_optional_package），守卫钉 597 校验和。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_598_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 597 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 597 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=597 AND
        migration_id='597_l4_forward_optional_package' AND
        checksum_sha256='65872ed6d71298933138b0fbb88b6c2e87667807d0fbab911a0b30e5c45afc96' AND
        down_checksum_sha256='3080447e0a7ca5b44327695ac6a3e0667f2bdf39c0a35760b88722c0d3d671c6' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 598 requires the exact verified 597 release head' USING ERRCODE='P5980';
    END IF;
END;
$migration_598_up$;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 23 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage', 'package_suspension', 'certificate_renewal',
            'security_hold']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 23);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage',
        'package_suspension', 'certificate_renewal', 'security_hold'));
