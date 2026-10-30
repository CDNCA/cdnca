LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_329_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 329 OR
       (SELECT max(version) FROM schema_migrations) <> 329 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=329 AND
        migration_id='329_ip_intel_node_distribution' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 329 down requires the exact verified migration head' USING ERRCODE='P3291';
    END IF;
    -- Deployments already delivered node-side artifacts; their configuration
    -- rows are immutable history and cannot be explained without 329.
    IF EXISTS (SELECT 1 FROM ip_intel_node_distributions) THEN
        RAISE EXCEPTION 'migration 329 down refuses to orphan node-side artifact deployments' USING ERRCODE='P3291';
    END IF;
END;
$migration_329_down$;

DROP TABLE ip_intel_node_ready_marks;
DROP TABLE ip_intel_node_distributions;
DROP TRIGGER configuration_artifacts_node_artifact_329 ON configuration_artifacts;
DROP FUNCTION bind_node_artifact_media_type_329();
