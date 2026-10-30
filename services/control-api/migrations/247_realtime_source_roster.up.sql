LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
DO $migration_247$ BEGIN
    IF (SELECT max(version) FROM schema_migrations)<>246 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=246 AND integrity_state='verified'
        AND checksum_sha256='2237c5ed6ee0bcf0407dcb3b6ae299c93b3f3fe92c71c093779517ea435ee318'
        AND down_checksum_sha256='7f6d241254000a1fd8db857af19b7b940184e34b81ed75d902f6aa5c24116d4b'
    ) THEN RAISE EXCEPTION 'migration 247 requires verified 246' USING ERRCODE='P2470'; END IF;
END $migration_247$;

CREATE TABLE analytics_realtime_source_rosters_247 (
    window_start timestamptz PRIMARY KEY CHECK(isfinite(window_start) AND window_start=date_trunc('hour',window_start)),
    sources jsonb NOT NULL CHECK(jsonb_typeof(sources)='array' AND jsonb_array_length(sources) BETWEEN 1 AND 10000),
    evidence_sha256 bytea NOT NULL CHECK(octet_length(evidence_sha256)=32),
    captured_at timestamptz NOT NULL CHECK(isfinite(captured_at) AND captured_at>=window_start)
);
CREATE FUNCTION protect_realtime_source_roster_247() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'realtime source roster is immutable' USING ERRCODE='P2472'; END;
$$;
CREATE TRIGGER realtime_source_roster_247_immutable BEFORE UPDATE OR DELETE ON analytics_realtime_source_rosters_247
FOR EACH ROW EXECUTE FUNCTION protect_realtime_source_roster_247();
CREATE TRIGGER realtime_source_roster_247_no_truncate BEFORE TRUNCATE ON analytics_realtime_source_rosters_247
FOR EACH STATEMENT EXECUTE FUNCTION protect_realtime_source_roster_247();
REVOKE ALL ON analytics_realtime_source_rosters_247 FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT ON analytics_realtime_source_rosters_247 TO cdnca_control_app;
    END IF;
END $$;
