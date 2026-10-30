LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_revision_segments
    IN ACCESS EXCLUSIVE MODE;

DO $migration_451_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 451 OR
       (SELECT max(version) FROM schema_migrations) <> 451 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=451 AND
        migration_id='451_security_ip_lists' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 451 down requires the exact verified migration head' USING ERRCODE='P4511';
    END IF;
    -- A rule referencing a list, or a pending ip_list republication, cannot
    -- be expressed by the 446 schema.
    IF EXISTS (SELECT 1 FROM security_ip_lists WHERE deleted_at IS NULL) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'ip_list' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'ip_list') THEN
        RAISE EXCEPTION 'migration 451 rollback would drop IP lists' USING ERRCODE='P4512';
    END IF;
END;
$migration_451_down$;

ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits'));
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 16);
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 16 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits']::text[]);
DROP TABLE security_ip_list_write_requests;
DROP TABLE security_ip_lists;
