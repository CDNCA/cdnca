LOCK TABLE schema_migrations, node_traffic_policy_evaluations IN ACCESS EXCLUSIVE MODE;

DO $migration_332_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 331 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 331 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=331 AND
        migration_id='331_audit_event_archive' AND
        checksum_sha256='1af7fdf12733a8ddb1d322033c71e756d9ec13e18ff35acb10b7c3fe65715831' AND
        down_checksum_sha256='5d9b52ec22684e388f4faff0defa55e6cc10f2796a2ec77c5eae5fe8b32c18df' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.guard_retention_delete_node_traffic_332()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 332 requires the exact verified 331 release head' USING ERRCODE='P3320';
    END IF;
END;
$migration_332_up$;

-- FX01: node traffic history (node_traffic_policy_evaluations) follows
-- node_traffic_history_days. Only the cleanup role may delete, and only an
-- evaluation older than the cutoff that is neither its node's newest (the
-- store reads the latest one) nor referenced by a sync task (that foreign key
-- cascades since 284, so deleting it would also drop the task).
CREATE FUNCTION guard_retention_delete_node_traffic_332()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT COALESCE(OLD.evaluated_at < retention_cleanup_cutoff_331('node_traffic_history_days'), false) OR NOT EXISTS (
        SELECT 1 FROM node_traffic_policy_evaluations newer
        WHERE newer.scope_id = OLD.scope_id AND newer.node_id = OLD.node_id
          AND (newer.evaluated_at, newer.id) > (OLD.evaluated_at, OLD.id)
    ) OR EXISTS (SELECT 1 FROM node_traffic_sync_tasks task WHERE task.evaluation_id = OLD.id) THEN
        RAISE EXCEPTION 'node traffic evaluation is within retention' USING ERRCODE='P3321';
    END IF;
    RETURN OLD;
END;
$function$;

DROP TRIGGER node_traffic_policy_evaluations_immutable_181_del ON node_traffic_policy_evaluations;
CREATE TRIGGER node_traffic_policy_evaluations_immutable_181_del BEFORE DELETE ON node_traffic_policy_evaluations FOR EACH ROW
    WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))
    EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181();
-- A node purge never runs as the cleanup role, which cannot read nodes.
CREATE TRIGGER node_traffic_policy_evaluations_retention_332 BEFORE DELETE ON node_traffic_policy_evaluations FOR EACH ROW
    WHEN (current_user = 'cdnca_retention_cleanup')
    EXECUTE FUNCTION guard_retention_delete_node_traffic_332();

-- The sync-task check above runs per deleted row.
CREATE INDEX node_traffic_sync_tasks_evaluation_332_idx ON node_traffic_sync_tasks(evaluation_id);

DO $migration_332_grants$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO cdnca_retention_cleanup', current_schema());
        GRANT SELECT, DELETE ON node_traffic_policy_evaluations TO cdnca_retention_cleanup;
        GRANT SELECT ON node_traffic_sync_tasks TO cdnca_retention_cleanup;
    END IF;
END;
$migration_332_grants$;
