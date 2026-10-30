LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_324_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 324 OR
       (SELECT max(version) FROM schema_migrations) <> 324 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=324 AND
        migration_id='324_system_republication_secondary_verification' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 324 down requires the exact verified migration head' USING ERRCODE='P3241';
    END IF;
    -- Segments and attempts are durable facts; the narrower checks cannot hold them.
    IF EXISTS (SELECT 1 FROM edge_system_republication_heads
        WHERE 'secondary_verification' = ANY(triggers) OR cardinality(triggers) > 5) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts
        WHERE 'secondary_verification' = ANY(triggers) OR cardinality(triggers) > 5) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'secondary_verification') THEN
        RAISE EXCEPTION 'migration 324 rollback would orphan secondary verification republication facts'
            USING ERRCODE='P3241';
    END IF;
END;
$migration_324_down$;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 5 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 5);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership'));
