CREATE TABLE artifact_signing_keys (
    id text PRIMARY KEY CHECK (
        char_length(id) BETWEEN 1 AND 128 AND
        id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    algorithm text NOT NULL CHECK (algorithm = 'ed25519'),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    created_at timestamptz NOT NULL
);

CREATE FUNCTION prevent_artifact_signing_key_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'artifact signing keys are immutable';
END;
$$;

CREATE TRIGGER artifact_signing_keys_immutable
BEFORE UPDATE OR DELETE ON artifact_signing_keys
FOR EACH ROW EXECUTE FUNCTION prevent_artifact_signing_key_mutation();

CREATE TABLE config_versions (
    id uuid PRIMARY KEY,
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    canonical_snapshot bytea NOT NULL CHECK (octet_length(canonical_snapshot) BETWEEN 1 AND 4194304),
    canonical_snapshot_sha256 bytea NOT NULL CHECK (octet_length(canonical_snapshot_sha256) = 32),
    generator_name text NOT NULL CHECK (
        generator_name = btrim(generator_name) AND char_length(generator_name) BETWEEN 1 AND 128
    ),
    generator_version text NOT NULL CHECK (
        generator_version = btrim(generator_version) AND char_length(generator_version) BETWEEN 1 AND 128
    ),
    status text NOT NULL CHECK (
        status IN ('building', 'validating', 'releasable', 'invalid', 'superseded', 'revoked')
    ),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    published_at timestamptz,
    UNIQUE (configuration_scope_id, idempotency_key),
    UNIQUE (configuration_scope_id, id),
    CHECK ((status IN ('releasable', 'superseded', 'revoked')) = (published_at IS NOT NULL))
);

CREATE FUNCTION protect_config_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.status IN ('releasable', 'superseded', 'revoked') THEN
            RAISE EXCEPTION 'published config versions are immutable';
        END IF;
        RETURN OLD;
    END IF;

    IF ROW(NEW.id, NEW.configuration_scope_id, NEW.canonical_snapshot,
           NEW.canonical_snapshot_sha256, NEW.generator_name, NEW.generator_version,
           NEW.idempotency_key, NEW.request_digest, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.configuration_scope_id, OLD.canonical_snapshot,
           OLD.canonical_snapshot_sha256, OLD.generator_name, OLD.generator_version,
           OLD.idempotency_key, OLD.request_digest, OLD.created_at) THEN
        RAISE EXCEPTION 'config version content is immutable';
    END IF;
    IF OLD.status IN ('releasable', 'superseded', 'revoked') AND
       NEW.published_at IS DISTINCT FROM OLD.published_at THEN
        RAISE EXCEPTION 'config version publication time is immutable';
    END IF;
    IF NOT (
        (OLD.status = 'building' AND NEW.status IN ('validating', 'invalid')) OR
        (OLD.status = 'validating' AND NEW.status IN ('releasable', 'invalid')) OR
        (OLD.status = 'releasable' AND NEW.status IN ('superseded', 'revoked')) OR
        (OLD.status = 'superseded' AND NEW.status = 'revoked')
    ) THEN
        RAISE EXCEPTION 'invalid config version status transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER config_versions_immutable_after_release
BEFORE UPDATE OR DELETE ON config_versions
FOR EACH ROW EXECUTE FUNCTION protect_config_version_mutation();

CREATE TABLE configuration_artifacts (
    id uuid PRIMARY KEY,
    config_version_id uuid NOT NULL REFERENCES config_versions(id) ON DELETE RESTRICT,
    ordinal integer NOT NULL CHECK (ordinal > 0),
    kind text NOT NULL CHECK (kind IN ('configuration', 'node_secret_bundle')),
    wire_bytes bytea NOT NULL CHECK (octet_length(wire_bytes) BETWEEN 1 AND 4194304),
    size_bytes bigint NOT NULL CHECK (size_bytes > 0),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    signing_key_id text NOT NULL REFERENCES artifact_signing_keys(id) ON DELETE RESTRICT,
    signature_algorithm text NOT NULL CHECK (signature_algorithm = 'ed25519'),
    compression text NOT NULL CHECK (compression IN ('none', 'zstd')),
    media_type text NOT NULL CHECK (
        media_type = btrim(media_type) AND char_length(media_type) BETWEEN 1 AND 128
    ),
    encryption_algorithm text NOT NULL CHECK (encryption_algorithm IN ('none', 'hpke_x25519_hkdf_sha256_aes_256_gcm')),
    recipient_key_id text,
    created_at timestamptz NOT NULL,
    UNIQUE (config_version_id, ordinal),
    UNIQUE (config_version_id, id),
    CHECK (size_bytes = octet_length(wire_bytes)),
    CHECK (
        (kind = 'node_secret_bundle' AND encryption_algorithm = 'hpke_x25519_hkdf_sha256_aes_256_gcm' AND
         recipient_key_id IS NOT NULL AND char_length(recipient_key_id) BETWEEN 1 AND 128) OR
        (kind = 'configuration' AND encryption_algorithm = 'none' AND recipient_key_id IS NULL)
    )
);

CREATE FUNCTION protect_configuration_artifact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_status text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'configuration artifacts are immutable';
    END IF;
    SELECT status INTO parent_status FROM config_versions WHERE id = NEW.config_version_id;
    IF parent_status NOT IN ('building', 'validating') THEN
        RAISE EXCEPTION 'artifacts cannot be added to a published config version';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER configuration_artifacts_immutable
BEFORE INSERT OR UPDATE OR DELETE ON configuration_artifacts
FOR EACH ROW EXECUTE FUNCTION protect_configuration_artifact_mutation();

CREATE TABLE rollouts (
    id uuid PRIMARY KEY,
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    config_version_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('apply', 'rollback')),
    status text NOT NULL CHECK (status IN ('building', 'queued', 'paused', 'completed', 'failed', 'cancelled')),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    traceparent text NOT NULL DEFAULT '' CHECK (char_length(traceparent) <= 512),
    task_id text CHECK (task_id IS NULL OR char_length(task_id) BETWEEN 1 AND 128),
    activation_timeout_ms bigint NOT NULL CHECK (activation_timeout_ms > 0),
    observation_window_ms bigint NOT NULL CHECK (observation_window_ms > 0),
    required_consecutive_successes integer NOT NULL CHECK (required_consecutive_successes > 0),
    deadline_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    queued_at timestamptz,
    UNIQUE (configuration_scope_id, idempotency_key),
    UNIQUE (configuration_scope_id, id),
    UNIQUE (id, config_version_id),
    FOREIGN KEY (configuration_scope_id, config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    CHECK ((status = 'building' AND queued_at IS NULL) OR (status <> 'building' AND queued_at IS NOT NULL)),
    CHECK (deadline_at > created_at)
);

CREATE TABLE node_config_state (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    configuration_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT,
    current_config_version_id uuid,
    previous_config_version_id uuid,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (configuration_scope_id, current_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, previous_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    CHECK (configuration_scope_id IS NOT NULL OR (current_config_version_id IS NULL AND previous_config_version_id IS NULL)),
    CHECK (current_config_version_id IS NULL OR current_config_version_id IS DISTINCT FROM previous_config_version_id)
);

CREATE TABLE node_deployments (
    id uuid NOT NULL,
    rollout_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    attempt integer NOT NULL CHECK (attempt > 0),
    config_version_id uuid NOT NULL REFERENCES config_versions(id) ON DELETE RESTRICT,
    previous_config_version_id uuid REFERENCES config_versions(id) ON DELETE RESTRICT,
    action text NOT NULL CHECK (action IN ('apply', 'rollback')),
    state text NOT NULL CHECK (
        state IN ('queued', 'delivered', 'staged', 'prechecked', 'activated', 'healthy',
                  'failed', 'reverting', 'reverted', 'rollback_failed')
    ),
    command_event_id uuid NOT NULL UNIQUE,
    command_bytes bytea NOT NULL CHECK (octet_length(command_bytes) BETWEEN 1 AND 1048576),
    command_sha256 bytea NOT NULL CHECK (octet_length(command_sha256) = 32),
    deadline_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (id, attempt),
    UNIQUE (rollout_id, node_id, attempt),
    UNIQUE (id, attempt, config_version_id),
    FOREIGN KEY (rollout_id, config_version_id)
        REFERENCES rollouts(id, config_version_id) ON DELETE RESTRICT,
    CHECK (deadline_at > created_at),
    CHECK ((action = 'rollback' AND previous_config_version_id IS NOT NULL) OR action = 'apply')
);

CREATE UNIQUE INDEX node_deployments_one_active_per_node_idx
    ON node_deployments (node_id)
    WHERE state NOT IN ('healthy', 'failed', 'reverted', 'rollback_failed');

CREATE INDEX node_deployments_rollout_state_idx ON node_deployments (rollout_id, state, node_id);

CREATE FUNCTION protect_node_deployment_command()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id, NEW.rollout_id, NEW.node_id, NEW.attempt, NEW.config_version_id,
           NEW.previous_config_version_id, NEW.action, NEW.command_event_id,
           NEW.command_bytes, NEW.command_sha256, NEW.deadline_at, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.rollout_id, OLD.node_id, OLD.attempt, OLD.config_version_id,
           OLD.previous_config_version_id, OLD.action, OLD.command_event_id,
           OLD.command_bytes, OLD.command_sha256, OLD.deadline_at, OLD.created_at) THEN
        RAISE EXCEPTION 'node deployment command identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_deployment_commands_immutable
BEFORE UPDATE ON node_deployments
FOR EACH ROW EXECUTE FUNCTION protect_node_deployment_command();

CREATE TABLE node_deployment_artifacts (
    deployment_id uuid NOT NULL,
    deployment_attempt integer NOT NULL CHECK (deployment_attempt > 0),
    config_version_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal > 0),
    PRIMARY KEY (deployment_id, deployment_attempt, artifact_id),
    UNIQUE (deployment_id, deployment_attempt, ordinal),
    FOREIGN KEY (deployment_id, deployment_attempt, config_version_id)
        REFERENCES node_deployments(id, attempt, config_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (config_version_id, artifact_id)
        REFERENCES configuration_artifacts(config_version_id, id) ON DELETE RESTRICT
);

CREATE FUNCTION prevent_node_deployment_artifact_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node deployment artifact bindings are immutable';
END;
$$;

CREATE TRIGGER node_deployment_artifacts_immutable
BEFORE UPDATE OR DELETE ON node_deployment_artifacts
FOR EACH ROW EXECUTE FUNCTION prevent_node_deployment_artifact_mutation();

CREATE TABLE edge_command_outbox (
    id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL,
    deployment_attempt integer NOT NULL CHECK (deployment_attempt > 0),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 256),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'publishing', 'published', 'failed')),
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    available_at timestamptz NOT NULL,
    published_at timestamptz,
    last_error text CHECK (last_error IS NULL OR char_length(last_error) <= 2048),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (deployment_id, deployment_attempt),
    FOREIGN KEY (deployment_id, deployment_attempt)
        REFERENCES node_deployments(id, attempt) ON DELETE RESTRICT,
    CHECK ((status = 'published') = (published_at IS NOT NULL))
);

CREATE INDEX edge_command_outbox_pending_idx
    ON edge_command_outbox (available_at, id) WHERE status IN ('pending', 'failed');

CREATE FUNCTION protect_edge_command_outbox_payload()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.id, NEW.deployment_id, NEW.deployment_attempt, NEW.node_id,
           NEW.subject, NEW.payload, NEW.payload_sha256, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.deployment_id, OLD.deployment_attempt, OLD.node_id,
           OLD.subject, OLD.payload, OLD.payload_sha256, OLD.created_at) THEN
        RAISE EXCEPTION 'edge command outbox payload is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_command_outbox_payload_immutable
BEFORE UPDATE ON edge_command_outbox
FOR EACH ROW EXECUTE FUNCTION protect_edge_command_outbox_payload();

CREATE TABLE deployment_status_events (
    id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL,
    event_id uuid NOT NULL UNIQUE,
    attempt integer NOT NULL CHECK (attempt > 0),
    transition_sequence bigint NOT NULL CHECK (transition_sequence > 0),
    state text NOT NULL CHECK (
        state IN ('queued', 'delivered', 'staged', 'prechecked', 'activated', 'healthy',
                  'failed', 'reverting', 'reverted', 'rollback_failed')
    ),
    payload bytea NOT NULL CHECK (octet_length(payload) > 0),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    FOREIGN KEY (deployment_id, attempt)
        REFERENCES node_deployments(id, attempt) ON DELETE RESTRICT,
    UNIQUE (deployment_id, attempt, transition_sequence)
);

CREATE FUNCTION prevent_deployment_status_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'deployment status events are append-only';
END;
$$;

CREATE TRIGGER deployment_status_events_append_only
BEFORE UPDATE OR DELETE ON deployment_status_events
FOR EACH ROW EXECUTE FUNCTION prevent_deployment_status_event_mutation();

CREATE TABLE artifact_fetch_requests (
    request_id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    attempt integer NOT NULL CHECK (attempt > 0),
    artifact_id uuid NOT NULL,
    offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    status text NOT NULL CHECK (status IN ('started', 'completed', 'failed')),
    bytes_served bigint NOT NULL DEFAULT 0 CHECK (bytes_served >= 0),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (deployment_id, attempt, artifact_id)
        REFERENCES node_deployment_artifacts(deployment_id, deployment_attempt, artifact_id) ON DELETE RESTRICT,
    CHECK ((status = 'started' AND completed_at IS NULL) OR (status <> 'started' AND completed_at IS NOT NULL))
);

CREATE INDEX artifact_fetch_requests_deployment_idx
    ON artifact_fetch_requests (deployment_id, created_at DESC);
