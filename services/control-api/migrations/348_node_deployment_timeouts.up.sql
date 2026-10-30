LOCK TABLE schema_migrations, node_deployments IN ACCESS EXCLUSIVE MODE;

DO $migration_348_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 347 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 347 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=347 AND
        migration_id='347_acme_http01_epoch_drift_alerts' AND
        checksum_sha256='53250a2b680900c2d6359e7b42de9cc30bfc6ab45363647c140299cc0a5ecb9a' AND
        down_checksum_sha256='71aaf1239c64112034810e49f68af26f6684a25bcfdfaa74bfe426d45156939e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_deployment_timeouts') IS NOT NULL OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='node_deployments'::regclass AND
        tgname='node_deployments_state_046' AND tgfoid='enforce_node_deployment_state_046()'::regprocedure
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='node_deployments'::regclass AND
        tgname='node_deployments_fact_046' AND tgfoid='assert_node_deployment_fact_046()'::regprocedure
       ) THEN
        RAISE EXCEPTION 'migration 348 requires the exact verified 347 release head' USING ERRCODE='P3480';
    END IF;
END;
$migration_348_up$;

-- r136 deploy-timeout: a deployment whose deadline passed while the node never
-- finished it (offline, command never delivered) kept its node's "one running
-- deployment per scope" index (288/291) forever, so every later deployment of
-- that scope to the node got ErrNodeDeploymentActive. The node serving worker
-- now ends such a deployment as failed once its deadline is one minute past and
-- stops sending its undelivered command. Every other state change rests on a
-- node status event; this row is the fact a timeout rests on. An activated or
-- reverting deployment never times out here: the node may already run it.
CREATE TABLE node_deployment_timeouts (
    deployment_id uuid NOT NULL,
    attempt integer NOT NULL,
    previous_state text NOT NULL CHECK (previous_state IN (
        'queued', 'delivered', 'agent_queued', 'started', 'staged', 'prechecked')),
    deadline_at timestamptz NOT NULL,
    timed_out_at timestamptz NOT NULL CHECK (timed_out_at >= deadline_at + interval '1 minute'),
    PRIMARY KEY (deployment_id, attempt),
    FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments (id, attempt) ON DELETE RESTRICT
);

-- A timeout names the deployment as it is now (state and deadline), is not
-- recorded ahead of the database clock, and is never changed afterwards.
CREATE FUNCTION guard_node_deployment_timeout_348() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'node deployment timeouts are immutable' USING ERRCODE='P3484';
    END IF;
    IF NEW.timed_out_at > clock_timestamp() OR NOT EXISTS (
        SELECT 1 FROM node_deployments deployment
        WHERE deployment.id = NEW.deployment_id AND deployment.attempt = NEW.attempt
          AND deployment.state = NEW.previous_state AND deployment.deadline_at = NEW.deadline_at
    ) THEN
        RAISE EXCEPTION 'node deployment timeout does not match an overdue running deployment' USING ERRCODE='P3483';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION guard_node_deployment_timeout_348() FROM PUBLIC;
CREATE TRIGGER node_deployment_timeouts_guard_348
BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_timeouts
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_timeout_348();
CREATE TRIGGER zz_core_fact_truncate_guard_348
BEFORE TRUNCATE ON node_deployment_timeouts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_core_fact_truncate_045();

-- The sweep reads only deployments still in flight before activation.
CREATE INDEX node_deployments_timeout_due_348_idx ON node_deployments (deadline_at)
    WHERE state IN ('queued', 'delivered', 'agent_queued', 'started', 'staged', 'prechecked');

REVOKE ALL ON node_deployment_timeouts FROM PUBLIC;
GRANT SELECT, INSERT ON node_deployment_timeouts TO cdnca_control_app, cdnca_control_runtime;

-- queued -> failed only through a recorded timeout (289 otherwise).
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

-- A recorded timeout is the fact of its failed state: no node status event
-- reports it (046 otherwise).
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
