LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_416_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 416 OR
       (SELECT max(version) FROM schema_migrations) <> 416 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=416 AND
        migration_id='416_site_facts_republication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 416 down requires the exact verified migration head' USING ERRCODE='P4161';
    END IF;
    -- Heads, attempts and segments are durable facts; the narrower checks
    -- cannot hold them.
    IF EXISTS (SELECT 1 FROM edge_system_republication_heads
        WHERE triggers && ARRAY['error_page_published', 'origin_auth_published']::text[] OR cardinality(triggers) > 12) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts
        WHERE triggers && ARRAY['error_page_published', 'origin_auth_published']::text[] OR cardinality(triggers) > 12) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments
        WHERE source IN ('error_page_published', 'origin_auth_published')) THEN
        RAISE EXCEPTION 'migration 416 rollback would orphan site facts republication facts' USING ERRCODE='P4162';
    END IF;
END;
$migration_416_down$;

-- Back to the 400 checks.
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks'));
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 12);
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 12 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks']::text[]);
