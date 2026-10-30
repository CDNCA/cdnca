LOCK TABLE schema_migrations,node_traffic_policies,node_traffic_policy_operations,
    node_traffic_policy_evaluations,node_traffic_sync_tasks IN ACCESS EXCLUSIVE MODE;

DO $migration_181_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>181 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>181 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=181 AND migration_id='181_node_traffic_policies' AND
              checksum_sha256='8595b4f05042263247425a1df790081fd5068ac194ac5da053946a832f414a8e' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 181 rollback requires the exact verified 181 head' USING ERRCODE='P1811';
    END IF;
    IF EXISTS (SELECT 1 FROM node_traffic_policies) OR
       EXISTS (SELECT 1 FROM node_traffic_policy_operations) OR
       EXISTS (SELECT 1 FROM node_traffic_policy_evaluations) OR
       EXISTS (SELECT 1 FROM node_traffic_sync_tasks) THEN
        RAISE EXCEPTION 'migration 181 rollback would discard durable node traffic policy or sync evidence'
            USING ERRCODE='P1812';
    END IF;
END;
$migration_181_down$;

DROP TABLE node_traffic_sync_tasks;
DROP TABLE node_traffic_policy_evaluations;
DROP TABLE node_traffic_policy_operations;
DROP TABLE node_traffic_policies;
DROP FUNCTION protect_node_traffic_sync_task_181();
DROP FUNCTION reject_node_traffic_evidence_mutation_181();
DROP FUNCTION protect_node_traffic_policy_identity_181();
