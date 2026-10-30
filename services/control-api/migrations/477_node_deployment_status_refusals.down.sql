LOCK TABLE schema_migrations, node_deployments, node_deployment_status_refusals IN ACCESS EXCLUSIVE MODE;

DO $migration_477_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 477 OR
       (SELECT max(version) FROM schema_migrations) <> 477 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=477 AND
        migration_id='477_node_deployment_status_refusals' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 477 down requires the exact verified migration head' USING ERRCODE='P4771';
    END IF;
    -- A refused deployment's failed state rests only on its refusal row: 476
    -- has no fact for it, so refuse rather than leave a state nothing explains.
    IF EXISTS (SELECT 1 FROM node_deployment_status_refusals) THEN
        RAISE EXCEPTION 'migration 477 down refuses to drop recorded node deployment status refusals' USING ERRCODE='P4772';
    END IF;
END;
$migration_477_down$;

CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state IN ('delivered', 'cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_timeouts timeout
        WHERE timeout.deployment_id = NEW.id AND timeout.attempt = NEW.attempt AND timeout.previous_state = 'queued'
    ) THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'delivered' AND NEW.state IN ('agent_queued', 'staged', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'agent_queued' AND NEW.state IN ('started', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'started' AND NEW.state IN ('staged', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'staged' AND NEW.state IN ('prechecked', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'prechecked' AND NEW.state IN ('activated', 'reverting', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'activated' AND NEW.state IN ('healthy', 'reverting') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'reverting' AND NEW.state IN ('reverted', 'failed', 'rollback_failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid node deployment state transition' USING ERRCODE = 'P0001';
END;
$$;

CREATE OR REPLACE FUNCTION assert_node_deployment_fact_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    rollout_contract smallint;
BEGIN
    SELECT contract_version INTO rollout_contract FROM rollouts WHERE id = NEW.rollout_id;
    IF rollout_contract <> 1 THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' AND NEW.attempt = 1 THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM edge_rollout_write_requests request
            JOIN rollouts rollout ON rollout.id = request.rollout_id
            JOIN audit_events event
              ON event.scope_id = request.actor_scope_id
             AND event.actor_user_id = request.actor_user_id
             AND event.action = request.operation
             AND event.resource_type = 'edge_rollout'
             AND event.resource_id = request.rollout_id::text
             AND event.request_id = request.request_id::text
             AND event.result = 'success'
            WHERE request.rollout_id = NEW.rollout_id
              AND request.operation = 'edge_rollout.retry'
              AND request.expected_revision = rollout.revision - 1
              AND request.completed_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'deployment retry requires a completed rollout command' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NEW.state = 'cancelled' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM edge_rollout_write_requests request
            JOIN rollouts rollout ON rollout.id = request.rollout_id
            JOIN audit_events event
              ON event.scope_id = request.actor_scope_id
             AND event.actor_user_id = request.actor_user_id
             AND event.action = request.operation
             AND event.resource_type = 'edge_rollout'
             AND event.resource_id = request.rollout_id::text
             AND event.request_id = request.request_id::text
             AND event.result = 'success'
            WHERE request.rollout_id = NEW.rollout_id
              AND request.operation = 'edge_rollout.cancel'
              AND request.expected_revision = rollout.revision - 1
              AND request.completed_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'deployment cancellation requires a completed rollout command' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_timeouts timeout
        WHERE timeout.deployment_id = NEW.id AND timeout.attempt = NEW.attempt
          AND timeout.previous_state = OLD.state
    ) THEN
        RETURN NULL;
    END IF;
    IF OLD.state IS DISTINCT FROM NEW.state AND NOT EXISTS (
        SELECT 1 FROM deployment_status_events event
        WHERE event.deployment_id = NEW.id AND event.attempt = NEW.attempt AND event.state = NEW.state
    ) THEN
        RAISE EXCEPTION 'deployment state requires a matching agent status event' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

DROP TABLE node_deployment_status_refusals;
DROP FUNCTION guard_node_deployment_status_refusal_477();
