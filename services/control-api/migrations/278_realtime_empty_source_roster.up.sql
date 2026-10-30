LOCK TABLE schema_migrations, analytics_realtime_source_rosters_247 IN ACCESS EXCLUSIVE MODE;

DO $migration_278_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 277 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 277 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=277 AND
        migration_id='277_node_session_capabilities' AND
        checksum_sha256='32fd892953ecdda2a5119ae57287ab03765c78d3b3a551f241b9ddccd295a6ff' AND
        down_checksum_sha256='ad2055218fe73ca6506ae75273d6aec1d92c57e38f1787fe7b5adb0832d33693' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 278 requires the exact verified 277 release head' USING ERRCODE='P2780';
    END IF;
END;
$migration_278_up$;

-- An empty roster records that no published listener existed for the hour.
-- It is evidence of absence, never a substitute for missing source windows.
ALTER TABLE analytics_realtime_source_rosters_247
    DROP CONSTRAINT analytics_realtime_source_rosters_247_sources_check,
    ADD CONSTRAINT analytics_realtime_source_rosters_247_sources_check
        CHECK (jsonb_typeof(sources)='array' AND jsonb_array_length(sources) BETWEEN 0 AND 10000);
