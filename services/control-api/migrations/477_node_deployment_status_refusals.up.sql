LOCK TABLE schema_migrations, node_deployments IN ACCESS EXCLUSIVE MODE;

DO $migration_477_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 476 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 476 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=476 AND
        migration_id='476_cname_record_retirements' AND
        checksum_sha256='174073e52e00432cf8e82224cfd962c1ff59e887212baab3199378910fc0bd5c' AND
        down_checksum_sha256='5e03007fa6e62255714591002896bed68dca0a4b8fbf03e569fee856d10231ce' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_deployment_status_refusals') IS NOT NULL OR
       to_regclass(current_schema() || '.node_deployment_timeouts') IS NULL THEN
        RAISE EXCEPTION 'migration 477 requires the exact verified 476 release head with 348''s timeouts'
            USING ERRCODE='P4770';
    END IF;
END;
$migration_477_up$;

-- r136 N13: the controller refused a node's deployment status for good (the
-- STARTED of a node clock behind the controller's, then every later status
-- as a skipped step) after the gateway had told the node it was stored. The
-- node dropped its journal, nothing was sent again, and the deployment held
-- its node's one-running-deployment-per-scope index (288/291) until its
-- deadline. A refusal of a status that would have advanced the deployment now
-- ends it as failed; this row is the fact that failed state rests on, as a
-- timeout is for 348. An activated or reverting deployment is never ended
-- here: the node may already run it, only its report ends it.
CREATE TABLE node_deployment_status_refusals (
    deployment_id uuid NOT NULL,
    attempt integer NOT NULL,
    previous_state text NOT NULL CHECK (previous_state IN (
        'queued', 'delivered', 'agent_queued', 'started', 'staged', 'prechecked')),
    reason_code text NOT NULL CHECK (reason_code IN ('status_binding_conflict', 'status_invalid_transition')),
    status_event_id uuid NOT NULL,
    transition_sequence bigint NOT NULL CHECK (transition_sequence > 0),
    refused_at timestamptz NOT NULL,
    PRIMARY KEY (deployment_id, attempt),
    FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments (id, attempt) ON DELETE RESTRICT
);

-- A refusal names the deployment as it is now, is not recorded ahead of the
-- database clock, and is never changed afterwards.
CREATE FUNCTION guard_node_deployment_status_refusal_477() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'node deployment status refusals are immutable' USING ERRCODE='P4774';
    END IF;
    IF NEW.refused_at > clock_timestamp() OR NOT EXISTS (
        SELECT 1 FROM node_deployments deployment
        WHERE deployment.id = NEW.deployment_id AND deployment.attempt = NEW.attempt
          AND deployment.state = NEW.previous_state
    ) THEN
        RAISE EXCEPTION 'node deployment status refusal does not match a running deployment' USING ERRCODE='P4773';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION guard_node_deployment_status_refusal_477() FROM PUBLIC;
CREATE TRIGGER node_deployment_status_refusals_guard_477
BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_status_refusals
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_status_refusal_477();
CREATE TRIGGER zz_core_fact_truncate_guard_477
BEFORE TRUNCATE ON node_deployment_status_refusals
FOR EACH STATEMENT EXECUTE FUNCTION prevent_core_fact_truncate_045();

REVOKE ALL ON node_deployment_status_refusals FROM PUBLIC;
GRANT SELECT, INSERT ON node_deployment_status_refusals TO cdnca_control_app, cdnca_control_runtime;

-- queued -> failed also through a recorded refusal (348 otherwise).
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
    IF OLD.state = 'queued' AND NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_status_refusals refusal
        WHERE refusal.deployment_id = NEW.id AND refusal.attempt = NEW.attempt AND refusal.previous_state = 'queued'
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

-- A recorded refusal is the fact of its failed state, as a timeout is (348
-- otherwise).
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
    IF NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_status_refusals refusal
        WHERE refusal.deployment_id = NEW.id AND refusal.attempt = NEW.attempt
          AND refusal.previous_state = OLD.state
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
