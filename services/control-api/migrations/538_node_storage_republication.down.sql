-- 538（fix-nodesettings）回退：trigger 枚举回到 511，删 edge_node_network_marks.storage_sha256
-- （node_storage 的重新发布在回退前必须已处理完）。
LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments, edge_node_network_marks IN ACCESS EXCLUSIVE MODE;

DO $migration_538_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 538 OR
       (SELECT max(version) FROM schema_migrations) <> 538 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=538 AND
        migration_id='538_node_storage_republication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 538 down requires the exact verified migration head' USING ERRCODE='P5381';
    END IF;
    IF EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'node_storage' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'node_storage' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'node_storage') THEN
        RAISE EXCEPTION 'migration 538 down: node storage republications exist' USING ERRCODE='P5382';
    END IF;
END;
$migration_538_down$;

ALTER TABLE edge_node_network_marks DROP COLUMN storage_sha256;
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
