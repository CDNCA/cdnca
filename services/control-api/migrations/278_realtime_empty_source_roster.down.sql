LOCK TABLE schema_migrations, analytics_realtime_source_rosters_247 IN ACCESS EXCLUSIVE MODE;

DO $migration_278_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 278 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 278 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=278 AND
        migration_id='278_realtime_empty_source_roster' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 278 down requires the exact verified migration head' USING ERRCODE='P2780';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_realtime_source_rosters_247 WHERE jsonb_array_length(sources)=0) THEN
        RAISE EXCEPTION 'migration 278 down refuses to discard recorded empty rosters' USING ERRCODE='P2782';
    END IF;
END;
$migration_278_down$;

ALTER TABLE analytics_realtime_source_rosters_247
    DROP CONSTRAINT analytics_realtime_source_rosters_247_sources_check,
    ADD CONSTRAINT analytics_realtime_source_rosters_247_sources_check
        CHECK (jsonb_typeof(sources)='array' AND jsonb_array_length(sources) BETWEEN 1 AND 10000);
