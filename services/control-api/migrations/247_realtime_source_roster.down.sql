LOCK TABLE schema_migrations,analytics_realtime_source_rosters_247 IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF (SELECT max(version) FROM schema_migrations)<>247 OR EXISTS(SELECT 1 FROM analytics_realtime_source_rosters_247) THEN
        RAISE EXCEPTION 'retain nonempty realtime roster during binary rollback' USING ERRCODE='P2471';
    END IF;
END $$;
DROP TABLE analytics_realtime_source_rosters_247;
DROP FUNCTION protect_realtime_source_roster_247();
