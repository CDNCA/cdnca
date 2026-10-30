LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_324_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 323 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 323 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=323 AND
        migration_id='323_notification_subscription_defaults' AND
        checksum_sha256='c4e690903f4c234a6c1c3bf67df3a5e932536e4c8b82ca3978561bc6361ec18a' AND
        down_checksum_sha256='84764d52a8d5963f6084d1dddaa718500452debff122b2b7c9a4df096d3808cb' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR (SELECT count(*) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace AND conname IN (
        'edge_system_republication_heads_triggers_check', 'edge_system_republication_attempts_triggers_check',
        'edge_system_revision_segments_source_check')) <> 3 THEN
        RAISE EXCEPTION 'migration 324 requires the exact verified 323 release head' USING ERRCODE='P3240';
    END IF;
END;
$migration_324_up$;

-- FX57: an overdue secondary identity verification stops a user's sites and
-- its completion restores them; both are republished by the system channel
-- under their own trigger (r136 g11), one more possible trigger per head.
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 6 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 6);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification'));
