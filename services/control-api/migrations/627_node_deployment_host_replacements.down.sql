LOCK TABLE schema_migrations, node_deployments, node_deployment_host_replacements IN ACCESS EXCLUSIVE MODE;

DO $migration_627_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 627 OR
       (SELECT max(version) FROM schema_migrations) <> 627 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=627 AND
        migration_id='627_node_deployment_host_replacements' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 627 down requires the exact verified migration head' USING ERRCODE='P6271';
    END IF;
    -- Deployments failed for a host replacement rest on these facts; the 046
    -- functions cannot account for them.
    IF EXISTS (SELECT 1 FROM node_deployment_host_replacements) THEN
        RAISE EXCEPTION 'migration 627 rollback would orphan host replaced deployment failures' USING ERRCODE='P6272';
    END IF;
END;
$migration_627_down$;

DROP TRIGGER node_deployments_fact_046 ON node_deployments;
CREATE CONSTRAINT TRIGGER node_deployments_fact_046
AFTER INSERT OR UPDATE OF state ON node_deployments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_node_deployment_fact_046();
DROP TRIGGER node_deployments_state_046 ON node_deployments;
CREATE TRIGGER node_deployments_state_046
BEFORE UPDATE OF state ON node_deployments
FOR EACH ROW EXECUTE FUNCTION enforce_node_deployment_state_046();
DROP FUNCTION assert_node_deployment_fact_627();
DROP FUNCTION enforce_node_deployment_state_627();

DROP TABLE node_deployment_host_replacements;
DROP FUNCTION guard_node_deployment_host_replacement_627();
