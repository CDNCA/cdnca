LOCK TABLE schema_migrations, node_metric_samples, platform_system_cleanup_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_320_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 319 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 319 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=319 AND
        migration_id='319_site_protocol_scope_fields' AND
        checksum_sha256='5ec4f621fa457dc60cd348f6995170a45f5d0cc6719d8084b580d9085a6f3379' AND
        down_checksum_sha256='cbfcb9acfe69c76524efb4c612d5a13c850247b5d8cbbb8a74ade1cb8201d1f1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('retention_cleanup_cutoff_320(text)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 320 requires the exact verified 319 release head' USING ERRCODE='P3200';
    END IF;
END;
$migration_320_up$;

-- FX01: history tables were never pruned. Retention deletes are allowed only
-- for the dedicated NOLOGIN role cdnca_retention_cleanup (created by the
-- installer and granted to the application login; the migration login cannot
-- create roles) and only for rows older than the platform retention setting.
-- Everyone else keeps the append-only guarantee. Each batch is audited by the
-- worker (system_cleanup.retention.delete).

-- Oldest instant a row may keep: now() minus the configured days (the largest
-- value across platform scopes; the product default 7 when unset; NULL when 0,
-- which disables cleanup). Fails closed on a malformed setting.
DO $migration_320_cutoff$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.retention_cleanup_cutoff_320(setting text) RETURNS timestamptz
        LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        DECLARE
            days integer;
        BEGIN
            IF setting <> 'node_metrics_days' THEN
                RAISE EXCEPTION 'unknown retention setting %%', setting USING ERRCODE='P3201';
            END IF;
            SELECT max((settings->>setting)::integer) INTO days FROM %I.platform_system_cleanup_settings
                WHERE settings ? setting;
            days := COALESCE(days, 7);
            IF days < 0 OR days > 3650 THEN
                RAISE EXCEPTION 'retention setting %% is out of range', setting USING ERRCODE='P3201';
            END IF;
            -- 0 days means "never clean": no cutoff, every delete is refused.
            IF days = 0 THEN
                RETURN NULL;
            END IF;
            RETURN transaction_timestamp() - make_interval(days => days);
        END;
        $body$;
    $ddl$, current_schema(), current_schema());
END;
$migration_320_cutoff$;

CREATE FUNCTION guard_retention_delete_node_metric_320()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    -- Old enough, and never the newest sample of its node (node_metric_latest
    -- and the publication sequence guard keep working).
    IF NOT COALESCE(OLD.observed_at < retention_cleanup_cutoff_320('node_metrics_days'), false) OR NOT EXISTS (
        SELECT 1 FROM node_metric_samples newer
        WHERE newer.node_id = OLD.node_id AND newer.publication_sequence > OLD.publication_sequence
    ) THEN
        RAISE EXCEPTION 'node metric sample is within retention' USING ERRCODE='P3202';
    END IF;
    RETURN OLD;
END;
$function$;

DROP TRIGGER node_metric_samples_immutable_150_del ON node_metric_samples;
CREATE TRIGGER node_metric_samples_immutable_150_del BEFORE DELETE ON node_metric_samples FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress() AND current_user <> 'cdnca_retention_cleanup')
    EXECUTE FUNCTION protect_node_metric_sample_150();
CREATE TRIGGER node_metric_samples_retention_320 BEFORE DELETE ON node_metric_samples FOR EACH ROW
    WHEN (current_user = 'cdnca_retention_cleanup' AND NOT node_purge_in_progress())
    EXECUTE FUNCTION guard_retention_delete_node_metric_320();

DO $migration_320_grants$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_retention_cleanup', current_schema());
        GRANT SELECT, DELETE ON node_metric_samples TO cdnca_retention_cleanup;
        GRANT EXECUTE ON FUNCTION retention_cleanup_cutoff_320(text) TO cdnca_retention_cleanup;
    END IF;
END;
$migration_320_grants$;
