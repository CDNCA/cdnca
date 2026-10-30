LOCK TABLE schema_migrations,analytics_realtime_expected_counts_131
IN ACCESS EXCLUSIVE MODE;

DO $migration_131$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=131 AND migration_id='131_analytics_realtime_expected_counts'
          AND checksum_sha256='a76a12a05ca5418bf4485f8e2c0895b541907984ccfb02e0a6510fdd1270ee4c'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR (SELECT max(version) FROM schema_migrations) <> 131 OR
       to_regclass('analytics_realtime_expected_counts_131') IS NULL OR
       to_regprocedure('guard_analytics_realtime_expected_count_131()') IS NULL THEN
        RAISE EXCEPTION 'migration 131 rollback requires the verified 131 head'
            USING ERRCODE='P1310';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_realtime_expected_counts_131 LIMIT 1) THEN
        RAISE EXCEPTION 'migration 131 rollback would discard realtime expected counts'
            USING ERRCODE='P1311';
    END IF;
END;
$migration_131$;

DROP TABLE analytics_realtime_expected_counts_131;
DROP FUNCTION guard_analytics_realtime_expected_count_131();
