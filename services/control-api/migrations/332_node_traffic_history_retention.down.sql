LOCK TABLE schema_migrations, node_traffic_policy_evaluations IN ACCESS EXCLUSIVE MODE;

DO $migration_332_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 332 OR
       (SELECT max(version) FROM schema_migrations) <> 332 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=332 AND
        migration_id='332_node_traffic_history_retention' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 332 down requires the exact verified migration head' USING ERRCODE='P3322';
    END IF;
END;
$migration_332_down$;

DO $migration_332_revoke$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NOT NULL THEN
        REVOKE SELECT, DELETE ON node_traffic_policy_evaluations FROM cdnca_retention_cleanup;
        REVOKE SELECT ON node_traffic_sync_tasks FROM cdnca_retention_cleanup;
    END IF;
END;
$migration_332_revoke$;

-- Restores the 284 delete guard: only a node purge may delete evaluations.
DROP INDEX node_traffic_sync_tasks_evaluation_332_idx;
DROP TRIGGER node_traffic_policy_evaluations_retention_332 ON node_traffic_policy_evaluations;
DROP TRIGGER node_traffic_policy_evaluations_immutable_181_del ON node_traffic_policy_evaluations;
CREATE TRIGGER node_traffic_policy_evaluations_immutable_181_del BEFORE DELETE ON node_traffic_policy_evaluations FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181();
DROP FUNCTION guard_retention_delete_node_traffic_332();
