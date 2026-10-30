LOCK TABLE schema_migrations, node_metric_samples, platform_system_cleanup_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_320_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 320 OR
       (SELECT max(version) FROM schema_migrations) <> 320 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=320 AND
        migration_id='320_retention_cleanup' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 320 down requires the exact verified migration head' USING ERRCODE='P3203';
    END IF;
END;
$migration_320_down$;

DO $migration_320_revoke$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        REVOKE SELECT, DELETE ON node_metric_samples FROM cdnca_retention_cleanup;
        EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM cdnca_retention_cleanup', current_schema());
    END IF;
END;
$migration_320_revoke$;

-- Restores the 284 delete guard: only a node purge may delete samples.
DROP TRIGGER node_metric_samples_retention_320 ON node_metric_samples;
DROP TRIGGER node_metric_samples_immutable_150_del ON node_metric_samples;
CREATE TRIGGER node_metric_samples_immutable_150_del BEFORE DELETE ON node_metric_samples FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_node_metric_sample_150();
DROP FUNCTION guard_retention_delete_node_metric_320();
DROP FUNCTION retention_cleanup_cutoff_320(text);
