LOCK TABLE schema_migrations,node_isolation_states,node_isolation_reports,
    node_isolation_alert_events IN ACCESS EXCLUSIVE MODE;

DO $migration_182_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>182 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>182 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=182 AND migration_id='182_node_isolation' AND
              checksum_sha256='bfc432e0cdf91e7f0d666c0229b98dee466ee26c729f4c98b77166b0cc4cd962' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 182 rollback requires the exact verified 182 head' USING ERRCODE='P1821';
    END IF;
    IF EXISTS (SELECT 1 FROM node_isolation_states) OR
       EXISTS (SELECT 1 FROM node_isolation_reports) OR
       EXISTS (SELECT 1 FROM node_isolation_alert_events) THEN
        RAISE EXCEPTION 'migration 182 rollback would discard durable node isolation state, report, or alert evidence'
            USING ERRCODE='P1822';
    END IF;
END;
$migration_182_down$;

DROP TABLE node_isolation_alert_events;
DROP TABLE node_isolation_reports;
DROP TABLE node_isolation_states;
DROP FUNCTION reject_node_isolation_evidence_mutation_182();
DROP FUNCTION protect_node_isolation_state_182();
