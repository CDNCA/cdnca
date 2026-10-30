LOCK TABLE schema_migrations,analytics_realtime_source_windows_184 IN ACCESS EXCLUSIVE MODE;

DO $migration_184_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>184 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>184 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=184 AND migration_id='184_analytics_realtime_source_window_authority' AND
              checksum_sha256='667f64f3907c25e555778df5005ce4b7a28b83fa24b0c93139785ac52d3c14e6' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=183 AND migration_id='183_high_risk_operations' AND
              checksum_sha256='6b9944051f89399f001da2943cc9407904961c2149b4f3091c42b3e9dadca590' AND
              down_checksum_sha256='75d27e61685c7a963f197b42d344d958692db03e061b9166728fc603bf59d38c' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 184 rollback requires the exact verified 184 and 183 release heads'
            USING ERRCODE='P1840';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_realtime_source_windows_184) THEN
        RAISE EXCEPTION 'migration 184 rollback would discard realtime source window evidence'
            USING ERRCODE='P1842';
    END IF;
END;
$migration_184_down$;

DROP TRIGGER analytics_realtime_source_windows_184_no_truncate ON analytics_realtime_source_windows_184;
DROP TRIGGER analytics_realtime_source_windows_184_immutable ON analytics_realtime_source_windows_184;
DROP TABLE analytics_realtime_source_windows_184;
DROP FUNCTION reject_analytics_realtime_source_window_truncate_184();
DROP FUNCTION guard_analytics_realtime_source_window_184();
