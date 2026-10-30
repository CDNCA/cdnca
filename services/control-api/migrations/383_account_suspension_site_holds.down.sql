LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_383_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 383 OR
       (SELECT max(version) FROM schema_migrations) <> 383 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=383 AND
        migration_id='383_account_suspension_site_holds' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 383 down requires the exact verified migration head' USING ERRCODE='P3831';
    END IF;
    -- Open holds stand for sites the control plane stopped; the narrower
    -- checks cannot hold the account_suspension republication facts.
    IF EXISTS (SELECT 1 FROM account_suspension_site_holds WHERE released_at IS NULL) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'account_suspension' = ANY(triggers) OR cardinality(triggers) > 10) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'account_suspension' = ANY(triggers) OR cardinality(triggers) > 10) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'account_suspension') THEN
        RAISE EXCEPTION 'migration 383 rollback would orphan account suspension facts' USING ERRCODE='P3832';
    END IF;
END;
$migration_383_down$;

ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement'));
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 10);
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 10 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation']::text[]);
DROP TABLE account_suspension_site_holds;
