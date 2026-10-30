LOCK TABLE schema_migrations,analytics_log_exports_v1,analytics_log_export_events_v1,
    analytics_log_export_leases_v1,analytics_log_export_artifacts_v1,analytics_log_export_grants_v1
IN ACCESS EXCLUSIVE MODE;

DO $migration_132$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=132 AND migration_id='132_analytics_log_export'
          AND checksum_sha256='3afde20714a6fab00099c7506173138767a303c2119c6eeeba3826c3f2087719'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR (SELECT max(version) FROM schema_migrations) <> 132 THEN
        RAISE EXCEPTION 'migration 132 rollback requires the verified 132 head' USING ERRCODE='P1320';
    END IF;
    IF EXISTS (SELECT 1 FROM analytics_log_exports_v1 LIMIT 1) OR
       EXISTS (SELECT 1 FROM analytics_log_export_events_v1 LIMIT 1) OR
       EXISTS (SELECT 1 FROM analytics_log_export_leases_v1 LIMIT 1) OR
       EXISTS (SELECT 1 FROM analytics_log_export_artifacts_v1 LIMIT 1) OR
       EXISTS (SELECT 1 FROM analytics_log_export_grants_v1 LIMIT 1) THEN
        RAISE EXCEPTION 'migration 132 rollback would discard analytics log export facts' USING ERRCODE='P1323';
    END IF;
END;
$migration_132$;

DROP FUNCTION claim_analytics_log_export_132(uuid,timestamptz,interval);
DROP TABLE analytics_log_export_grants_v1;
DROP TABLE analytics_log_export_artifacts_v1;
DROP TABLE analytics_log_export_leases_v1;
DROP TABLE analytics_log_export_events_v1;
DROP TABLE analytics_log_exports_v1;
DROP FUNCTION guard_analytics_log_export_artifact_132();
DROP FUNCTION guard_analytics_log_export_grant_132();
DROP FUNCTION prevent_analytics_log_export_fact_mutation_132();
