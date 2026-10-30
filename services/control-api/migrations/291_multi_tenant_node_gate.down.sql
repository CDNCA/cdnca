LOCK TABLE schema_migrations, rollouts, node_config_state, node_deployments, node_traffic_sync_tasks
    IN ACCESS EXCLUSIVE MODE;

DO $migration_291_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 291 OR
       (SELECT max(version) FROM schema_migrations) <> 291 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=291 AND
        migration_id='291_multi_tenant_node_gate' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 291 down requires the exact verified migration head' USING ERRCODE='P2911';
    END IF;
    -- 290 holds a node to one scope; refuse rather than drop a tenant.
    IF EXISTS (SELECT 1 FROM node_config_state GROUP BY node_id HAVING count(*) > 1) OR
       EXISTS (SELECT 1 FROM node_deployments
           WHERE state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled'])
           GROUP BY node_id HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'migration 291 down cannot fold several configuration scopes onto one node'
            USING ERRCODE='P2911';
    END IF;
END;
$migration_291_down$;

CREATE OR REPLACE FUNCTION protect_node_traffic_sync_task_181()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_scope_id uuid;
    current_config_version_id uuid;
BEGIN
    IF TG_OP='INSERT' THEN
        SELECT configuration_scope_id,current_config_version_id
        INTO current_scope_id,current_config_version_id
        FROM node_config_state WHERE node_id=NEW.node_id;
        IF current_scope_id IS DISTINCT FROM NEW.scope_id OR
           current_config_version_id IS DISTINCT FROM NEW.config_version_id THEN
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

CREATE OR REPLACE FUNCTION reject_node_deployment_during_reconciliation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    blocked boolean;
BEGIN
    SELECT reconciliation_required INTO blocked
    FROM node_config_state
    WHERE node_id = NEW.node_id;
    IF blocked THEN
        RAISE EXCEPTION 'node configuration reconciliation is required'
            USING ERRCODE = '23514', CONSTRAINT = 'node_deployments_reconciliation_gate';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER a_node_deployments_scope_288 ON node_deployments;
CREATE OR REPLACE FUNCTION bind_node_deployment_scope_288() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.configuration_scope_id IS DISTINCT FROM OLD.configuration_scope_id THEN
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
CREATE TRIGGER a_node_deployments_scope_288 BEFORE INSERT OR UPDATE OF configuration_scope_id
    ON node_deployments FOR EACH ROW EXECUTE FUNCTION bind_node_deployment_scope_288();
DROP INDEX node_deployments_one_active_unqueued_per_node_291_idx;
ALTER TABLE node_deployments DROP COLUMN queued_per_scope;
CREATE UNIQUE INDEX node_deployments_one_active_per_node_idx ON node_deployments (node_id)
    WHERE state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled']);
CREATE UNIQUE INDEX node_config_state_single_scope_288_idx ON node_config_state (node_id);
