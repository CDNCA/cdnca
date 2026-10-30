LOCK TABLE schema_migrations, rollouts, node_config_state, node_deployments, node_traffic_sync_tasks
    IN ACCESS EXCLUSIVE MODE;

DO $migration_291_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 290 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 290 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=290 AND
        migration_id='290_node_presence_scope_identities' AND
        checksum_sha256='cb0d58a1540732697ee07343fa46b4f332ead7b2b3ce4f17996815c82e0e0ae2' AND
        down_checksum_sha256='2f84c4a265c19802604434c6dd50a168b0c3b0a7bb98158171bbb44daf8cd7c1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_config_state_single_scope_288_idx') IS NULL
         OR to_regclass(current_schema() || '.node_deployments_one_active_per_node_idx') IS NULL THEN
        RAISE EXCEPTION 'migration 291 requires the exact verified 290 release head' USING ERRCODE='P2910';
    END IF;
END;
$migration_291_up$;

-- A node declaring MULTI_TENANT_RUNTIME serves several configuration scopes,
-- each with its own state and its own running deployment. Which nodes may
-- take a second scope is decided from their session capabilities in the
-- claim paths (edgedeployment.NodeServesSeveralScopes); the schema keeps one
-- row per (node, scope).
DROP INDEX node_config_state_single_scope_288_idx;

-- Such an agent queues deployments itself (agent_queued). The writer records
-- that when it creates the deployment; any other deployment still runs alone
-- on its node, as before.
ALTER TABLE node_deployments ADD COLUMN queued_per_scope boolean NOT NULL DEFAULT false;
DROP INDEX node_deployments_one_active_per_node_idx;
CREATE UNIQUE INDEX node_deployments_one_active_unqueued_per_node_291_idx ON node_deployments (node_id)
    WHERE NOT queued_per_scope AND
          state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled']);
CREATE OR REPLACE FUNCTION bind_node_deployment_scope_288() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.configuration_scope_id IS DISTINCT FROM OLD.configuration_scope_id OR
           NEW.queued_per_scope IS DISTINCT FROM OLD.queued_per_scope THEN
            RAISE EXCEPTION 'node deployment configuration scope is immutable'
                USING ERRCODE = '23514', CONSTRAINT = 'node_deployments_scope_288';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.configuration_scope_id IS NULL THEN
        SELECT configuration_scope_id INTO NEW.configuration_scope_id FROM rollouts WHERE id = NEW.rollout_id;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER a_node_deployments_scope_288 ON node_deployments;
CREATE TRIGGER a_node_deployments_scope_288 BEFORE INSERT OR UPDATE OF configuration_scope_id, queued_per_scope
    ON node_deployments FOR EACH ROW EXECUTE FUNCTION bind_node_deployment_scope_288();

-- Reconciling one scope pauses only that scope's deployments.
CREATE OR REPLACE FUNCTION reject_node_deployment_during_reconciliation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    blocked boolean;
BEGIN
    SELECT reconciliation_required INTO blocked
    FROM node_config_state
    WHERE node_id = NEW.node_id AND configuration_scope_id = NEW.configuration_scope_id;
    IF blocked THEN
        RAISE EXCEPTION 'node configuration reconciliation is required'
            USING ERRCODE = '23514', CONSTRAINT = 'node_deployments_reconciliation_gate';
    END IF;
    RETURN NEW;
END;
$$;

-- A traffic sync re-applies the current configuration of its own scope.
CREATE OR REPLACE FUNCTION protect_node_traffic_sync_task_181()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_config_version_id uuid;
BEGIN
    IF TG_OP='INSERT' THEN
        SELECT state.current_config_version_id INTO current_config_version_id
        FROM node_config_state state WHERE state.node_id=NEW.node_id AND state.configuration_scope_id=NEW.scope_id;
        IF NOT FOUND OR current_config_version_id IS DISTINCT FROM NEW.config_version_id THEN
            RAISE EXCEPTION 'node traffic sync task must bind the current node configuration';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.evaluation_id,NEW.scope_id,NEW.node_id,NEW.config_version_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.evaluation_id,OLD.scope_id,OLD.node_id,OLD.config_version_id,OLD.created_at) OR
       (OLD.rollout_id IS NOT NULL AND NEW.rollout_id IS DISTINCT FROM OLD.rollout_id) OR
       NEW.updated_at<OLD.updated_at OR NOT (
           (OLD.status='queued' AND NEW.status='running' AND NEW.attempts=OLD.attempts+1) OR
           (OLD.status='running' AND NEW.status='running' AND NEW.attempts=OLD.attempts) OR
           (OLD.status='running' AND NEW.status IN ('succeeded','failed') AND NEW.attempts=OLD.attempts)
       ) THEN
        RAISE EXCEPTION 'invalid node traffic sync task mutation';
    END IF;
    RETURN NEW;
END;
$$;
