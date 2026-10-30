DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 83 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 83 THEN
        RAISE EXCEPTION 'analytics observability rollback requires frozen migration head 083'
            USING ERRCODE = 'P8308';
    END IF;
END;
$$;

LOCK TABLE analytics_history_streams IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM analytics_history_streams) THEN
        RAISE EXCEPTION 'migration 083 rollback cannot represent analytics observability state'
            USING ERRCODE = 'P8309';
    END IF;
END;
$$;

DROP TRIGGER analytics_history_streams_truncate_guard_083 ON analytics_history_streams;
DROP TRIGGER analytics_history_streams_guard_083 ON analytics_history_streams;
DROP FUNCTION prevent_analytics_history_stream_truncate_083();
DROP FUNCTION guard_analytics_history_stream_083();
DROP TABLE analytics_history_streams;
