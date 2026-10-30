INSERT INTO permissions (name, description) VALUES
    ('edge_publications.read', 'Read tenant edge publications, rollouts, and deployment results'),
    ('edge_publications.manage', 'Publish tenant edge configuration and control its rollouts');

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN permissions permission ON permission.name IN ('edge_publications.read', 'edge_publications.manage')
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

ALTER TABLE rollouts
    ADD COLUMN revision bigint,
    ADD COLUMN max_attempts integer,
    ADD COLUMN updated_at timestamptz,
    ADD COLUMN contract_version smallint;

UPDATE rollouts
SET revision = 1,
    max_attempts = 3,
    updated_at = COALESCE(queued_at, created_at),
    contract_version = 0;

ALTER TABLE rollouts
    ALTER COLUMN revision SET NOT NULL,
    ALTER COLUMN revision SET DEFAULT 1,
    ALTER COLUMN max_attempts SET NOT NULL,
    ALTER COLUMN max_attempts SET DEFAULT 3,
    ALTER COLUMN updated_at SET NOT NULL,
    ALTER COLUMN contract_version SET NOT NULL,
    ALTER COLUMN contract_version SET DEFAULT 0,
    ADD CONSTRAINT rollouts_revision_positive_046 CHECK (revision > 0),
    ADD CONSTRAINT rollouts_max_attempts_046 CHECK (max_attempts BETWEEN 1 AND 10),
    ADD CONSTRAINT rollouts_contract_version_046 CHECK (contract_version IN (0, 1)),
    ADD CONSTRAINT rollouts_updated_at_046 CHECK (updated_at >= created_at);

ALTER TABLE edge_config_publications
    ADD COLUMN expected_source_revision bigint,
    ADD COLUMN actor_user_id uuid,
    ADD COLUMN actor_scope_id uuid,
    ADD COLUMN target_kind text,
    ADD COLUMN target_snapshot_id uuid,
    ADD COLUMN target_snapshot_revision bigint,
    ADD COLUMN target_resolver_sha256 bytea,
    ADD COLUMN target_snapshot_sha256 bytea,
    ADD COLUMN contract_version smallint;

UPDATE edge_config_publications
SET expected_source_revision = source_revision,
    target_kind = 'legacy',
    target_snapshot_sha256 = request_digest,
    contract_version = 0;

ALTER TABLE edge_config_publications
    ALTER COLUMN expected_source_revision SET NOT NULL,
    ALTER COLUMN target_kind SET NOT NULL,
    ALTER COLUMN target_snapshot_sha256 SET NOT NULL,
    ALTER COLUMN contract_version SET NOT NULL,
    ALTER COLUMN contract_version SET DEFAULT 1,
    ADD CONSTRAINT edge_config_publications_expected_revision_046
        CHECK (expected_source_revision > 0 AND expected_source_revision = source_revision),
    ADD CONSTRAINT edge_config_publications_target_digest_046
        CHECK (octet_length(target_snapshot_sha256) = 32),
    ADD CONSTRAINT edge_config_publications_contract_046 CHECK (
        (contract_version = 0 AND target_kind = 'legacy' AND
         actor_user_id IS NULL AND actor_scope_id IS NULL AND
         target_snapshot_id IS NULL AND target_snapshot_revision IS NULL AND
         target_resolver_sha256 IS NULL) OR
        (contract_version = 1 AND target_kind = 'explicit' AND
         actor_user_id IS NOT NULL AND actor_scope_id IS NOT NULL AND
         target_snapshot_id IS NULL AND target_snapshot_revision IS NULL AND
         target_resolver_sha256 IS NULL) OR
        (contract_version = 1 AND target_kind = 'resolver' AND
         actor_user_id IS NOT NULL AND actor_scope_id IS NOT NULL AND
         target_snapshot_id IS NOT NULL AND target_snapshot_revision > 0 AND
         octet_length(target_resolver_sha256) = 32)
    ),
    ADD CONSTRAINT edge_config_publications_actor_membership_046
        FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX edge_config_publications_one_contract_source_idx
    ON edge_config_publications (configuration_scope_id, source_revision)
    WHERE contract_version = 1;

CREATE TABLE edge_rollout_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    configuration_scope_id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('edge_rollout.cancel', 'edge_rollout.retry')),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    expected_revision bigint NOT NULL CHECK (expected_revision > 0),
    request_id uuid NOT NULL,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, rollout_id)
        REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE INDEX edge_rollout_write_requests_scope_created_idx
    ON edge_rollout_write_requests (configuration_scope_id, created_at DESC, id DESC);

CREATE TRIGGER zz_core_fact_truncate_guard_045
BEFORE TRUNCATE ON edge_rollout_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_core_fact_truncate_045();
ALTER TABLE edge_rollout_write_requests ENABLE ALWAYS TRIGGER zz_core_fact_truncate_guard_045;

CREATE FUNCTION protect_edge_rollout_write_request_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'edge rollout write requests are immutable' USING ERRCODE = 'P0001';
    END IF;
    IF ROW(NEW.id, NEW.actor_user_id, NEW.actor_scope_id, NEW.configuration_scope_id,
           NEW.rollout_id, NEW.operation, NEW.idempotency_key, NEW.request_digest,
           NEW.expected_revision, NEW.request_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.actor_user_id, OLD.actor_scope_id, OLD.configuration_scope_id,
           OLD.rollout_id, OLD.operation, OLD.idempotency_key, OLD.request_digest,
           OLD.expected_revision, OLD.request_id, OLD.created_at) THEN
        RAISE EXCEPTION 'edge rollout write request identity is immutable' USING ERRCODE = 'P0001';
    END IF;
    IF OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'invalid edge rollout write request completion' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_rollout_write_requests_immutable_046
BEFORE UPDATE OR DELETE ON edge_rollout_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_edge_rollout_write_request_046();

ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_state_check;
ALTER TABLE node_deployments ADD CONSTRAINT node_deployments_state_046 CHECK (
    state IN ('queued', 'delivered', 'staged', 'prechecked', 'activated', 'healthy',
              'failed', 'reverting', 'reverted', 'rollback_failed', 'cancelled')
);

DROP INDEX node_deployments_one_active_per_node_idx;
CREATE UNIQUE INDEX node_deployments_one_active_per_node_idx
    ON node_deployments (node_id)
    WHERE state NOT IN ('healthy', 'failed', 'reverted', 'rollback_failed', 'cancelled');

ALTER TABLE edge_command_outbox DROP CONSTRAINT edge_command_outbox_status_check;
ALTER TABLE edge_command_outbox ADD CONSTRAINT edge_command_outbox_status_046 CHECK (
    status IN ('pending', 'publishing', 'published', 'failed', 'cancelled')
);

CREATE FUNCTION enforce_rollout_state_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id, NEW.configuration_scope_id, NEW.config_version_id, NEW.action,
           NEW.idempotency_key, NEW.request_digest, NEW.request_id, NEW.correlation_id,
           NEW.traceparent, NEW.task_id, NEW.activation_timeout_ms,
           NEW.observation_window_ms, NEW.required_consecutive_successes,
           NEW.deadline_at, NEW.created_at, NEW.max_attempts, NEW.contract_version)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.configuration_scope_id, OLD.config_version_id, OLD.action,
           OLD.idempotency_key, OLD.request_digest, OLD.request_id, OLD.correlation_id,
           OLD.traceparent, OLD.task_id, OLD.activation_timeout_ms,
           OLD.observation_window_ms, OLD.required_consecutive_successes,
           OLD.deadline_at, OLD.created_at, OLD.max_attempts, OLD.contract_version) THEN
        RAISE EXCEPTION 'rollout identity is immutable' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'rollout update time regressed' USING ERRCODE = 'P0001';
    END IF;
    IF OLD.status = 'building' AND NEW.status = 'queued' AND NEW.revision = OLD.revision THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'queued' AND NEW.status IN ('queued', 'cancelled') AND
       NEW.revision = OLD.revision + 1 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid rollout state transition' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER rollouts_state_046
BEFORE UPDATE ON rollouts
FOR EACH ROW EXECUTE FUNCTION enforce_rollout_state_046();

CREATE FUNCTION enforce_node_deployment_attempt_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    rollout_max_attempts integer;
    previous_state text;
BEGIN
    SELECT max_attempts INTO rollout_max_attempts FROM rollouts WHERE id = NEW.rollout_id;
    IF NEW.attempt > rollout_max_attempts THEN
        RAISE EXCEPTION 'deployment retry exceeds rollout max attempts' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.attempt = 1 THEN
        RETURN NEW;
    END IF;
    SELECT state INTO previous_state
    FROM node_deployments
    WHERE id = NEW.id AND attempt = NEW.attempt - 1;
    IF previous_state NOT IN ('failed', 'rollback_failed') THEN
        RAISE EXCEPTION 'deployment retry requires a failed previous attempt' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_deployments_attempt_046
BEFORE INSERT ON node_deployments
FOR EACH ROW EXECUTE FUNCTION enforce_node_deployment_attempt_046();

CREATE FUNCTION enforce_node_deployment_state_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state IN ('delivered', 'cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'delivered' AND NEW.state IN ('staged', 'failed') THEN
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

CREATE TRIGGER node_deployments_state_046
BEFORE UPDATE OF state ON node_deployments
FOR EACH ROW EXECUTE FUNCTION enforce_node_deployment_state_046();

CREATE FUNCTION enforce_edge_outbox_state_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('pending', 'failed') AND NEW.status = 'publishing' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'cancelled' THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'publishing' AND NEW.status IN ('published', 'failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid edge outbox state transition' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER edge_command_outbox_state_046
BEFORE UPDATE OF status ON edge_command_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_edge_outbox_state_046();

CREATE FUNCTION assert_edge_publication_contract_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.contract_version <> 1 THEN
        RAISE EXCEPTION 'new edge publications require contract version 1' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_config_publications_contract_046
BEFORE INSERT ON edge_config_publications
FOR EACH ROW EXECUTE FUNCTION assert_edge_publication_contract_046();

CREATE FUNCTION assert_edge_publication_audit_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = NEW.actor_scope_id
          AND event.actor_user_id = NEW.actor_user_id
          AND event.action = 'edge_publication.publish'
          AND event.resource_type = 'edge_config_publication'
          AND event.resource_id = NEW.id::text
          AND event.request_id = NEW.request_id::text
          AND event.result = 'success'
    ) THEN
        RAISE EXCEPTION 'edge publication requires matching success audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER edge_config_publications_audited_046
AFTER INSERT ON edge_config_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_edge_publication_audit_046();

CREATE FUNCTION assert_rollout_contract_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.contract_version <> 1 OR NEW.status = 'building' THEN
        RETURN NULL;
    END IF;
    IF NEW.revision = 1 THEN
        IF NOT EXISTS (
            SELECT 1 FROM edge_config_publications publication
            WHERE publication.rollout_id = NEW.id AND publication.contract_version = 1
        ) THEN
            RAISE EXCEPTION 'contract rollout requires an audited publication' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM edge_rollout_write_requests request
        JOIN audit_events event
          ON event.scope_id = request.actor_scope_id
         AND event.actor_user_id = request.actor_user_id
         AND event.action = request.operation
         AND event.resource_type = 'edge_rollout'
         AND event.resource_id = request.rollout_id::text
         AND event.request_id = request.request_id::text
         AND event.result = 'success'
        WHERE request.configuration_scope_id = NEW.configuration_scope_id
          AND request.rollout_id = NEW.id
          AND request.expected_revision = NEW.revision - 1
          AND request.operation = CASE
              WHEN NEW.status = 'cancelled' THEN 'edge_rollout.cancel'
              ELSE 'edge_rollout.retry'
          END
          AND request.completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'rollout command requires matching request and audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER rollouts_contract_audited_046
AFTER INSERT OR UPDATE ON rollouts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_rollout_contract_046();

CREATE FUNCTION assert_node_deployment_fact_046()
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
    IF OLD.state IS DISTINCT FROM NEW.state AND NOT EXISTS (
        SELECT 1 FROM deployment_status_events event
        WHERE event.deployment_id = NEW.id AND event.attempt = NEW.attempt AND event.state = NEW.state
    ) THEN
        RAISE EXCEPTION 'deployment state requires a matching agent status event' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER node_deployments_fact_046
AFTER INSERT OR UPDATE OF state ON node_deployments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_node_deployment_fact_046();
