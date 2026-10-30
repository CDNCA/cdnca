-- 511（r136 errpage-4 S3）回退：trigger 枚举回到 460，删到期扫描标记（package_expiry 的行在回退前必须已处理完）。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_511_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 511 OR
       (SELECT max(version) FROM schema_migrations) <> 511 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=511 AND
        migration_id='511_package_expiry_republication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 511 down requires the exact verified migration head' USING ERRCODE='P5111';
    END IF;
    IF EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'package_expiry' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'package_expiry' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'package_expiry') THEN
        RAISE EXCEPTION 'migration 511 down: package expiry republications exist' USING ERRCODE='P5112';
    END IF;
END;
$migration_511_down$;

DROP TABLE package_expiry_republication_marks;
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 18 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 18);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation'));
