-- 570（fix-dnscert3）回退：删 certificate_renewal_deliveries，trigger 枚举回到 555（含 package_suspension）
-- （certificate_renewal 的重新发布在回退前必须已处理完）。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_570_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 570 OR
       (SELECT max(version) FROM schema_migrations) <> 570 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=570 AND
        migration_id='570_certificate_renewal_delivery' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 570 down requires the exact verified migration head' USING ERRCODE='P5701';
    END IF;
    IF EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'certificate_renewal' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'certificate_renewal' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'certificate_renewal') THEN
        RAISE EXCEPTION 'migration 570 down: certificate renewal republications exist' USING ERRCODE='P5702';
    END IF;
END;
$migration_570_down$;

DROP TABLE certificate_renewal_deliveries;
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 21 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage', 'package_suspension']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 21);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage',
        'package_suspension'));
