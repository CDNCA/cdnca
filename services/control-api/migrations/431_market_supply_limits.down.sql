LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_431_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 431 OR
       (SELECT max(version) FROM schema_migrations) <> 431 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=431 AND
        migration_id='431_market_supply_limits' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 431 down requires the exact verified migration head' USING ERRCODE='P4311';
    END IF;
    -- Applied shares or republication facts of a share change cannot be
    -- expressed by the 430 schema.
    IF EXISTS (SELECT 1 FROM market_supply_limits) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'market_limits' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'market_limits' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'market_limits') THEN
        RAISE EXCEPTION 'migration 431 rollback would drop market supply limit facts' USING ERRCODE='P4312';
    END IF;
END;
$migration_431_down$;

ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover'));
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 15);
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 15 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover']::text[]);

DROP TABLE market_supply_limits;
