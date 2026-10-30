CREATE TABLE acme_http01_overlay_states (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
    latest_healthy_revision bigint CHECK (
        latest_healthy_revision IS NULL OR
        (latest_healthy_revision > 0 AND latest_healthy_revision <= current_revision)
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at)
);

CREATE TABLE acme_http01_overlay_publications (
    id uuid PRIMARY KEY,
    mode text NOT NULL CHECK (mode IN ('apply', 'cleanup')),
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id uuid NOT NULL,
    token_count integer NOT NULL CHECK (token_count BETWEEN 0 AND 1000),
    node_count integer NOT NULL CHECK (node_count BETWEEN 1 AND 10000),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    deadline_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, site_id, idempotency_key),
    UNIQUE (tenant_scope_id, site_id, revision),
    UNIQUE (tenant_scope_id, site_id, revision, id),
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES acme_http01_overlay_states(tenant_scope_id, site_id) ON DELETE RESTRICT,
    CHECK (revision = expected_revision + 1),
    CHECK ((mode = 'apply' AND token_count > 0) OR (mode = 'cleanup' AND expected_revision > 0)),
    CHECK (deadline_at > created_at)
);

CREATE TABLE acme_http01_overlay_versions (
    id uuid PRIMARY KEY,
    publication_id uuid NOT NULL UNIQUE,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    sealed_snapshot_sha256 bytea NOT NULL CHECK (octet_length(sealed_snapshot_sha256) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, site_id, revision),
    UNIQUE (tenant_scope_id, site_id, revision, id),
    FOREIGN KEY (tenant_scope_id, site_id, revision, publication_id)
        REFERENCES acme_http01_overlay_publications(tenant_scope_id, site_id, revision, id)
        ON DELETE RESTRICT
);

CREATE TABLE acme_http01_overlay_token_facts (
    version_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 1000),
    operation_id text NOT NULL,
    challenge_attempt_id uuid NOT NULL,
    domain text NOT NULL CHECK (
        domain = lower(domain) AND domain = btrim(domain)
        AND octet_length(domain) BETWEEN 3 AND 253 AND domain !~ '[[:cntrl:]]'
    ),
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    value_sha256 bytea NOT NULL CHECK (octet_length(value_sha256) = 32),
    key_id text NOT NULL CHECK (
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    nonce bytea NOT NULL CHECK (octet_length(nonce) BETWEEN 12 AND 64),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 16384),
    aad_sha256 bytea NOT NULL CHECK (octet_length(aad_sha256) = 32),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (version_id, ordinal),
    UNIQUE (version_id, operation_id, challenge_attempt_id),
    UNIQUE (version_id, token_sha256),
    FOREIGN KEY (tenant_scope_id, site_id, revision, version_id)
        REFERENCES acme_http01_overlay_versions(tenant_scope_id, site_id, revision, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, operation_id, challenge_attempt_id)
        REFERENCES acme_issuance_challenge_attempts(tenant_scope_id, operation_id, attempt_id)
        ON DELETE RESTRICT
);

CREATE TABLE acme_http01_overlay_targets (
    version_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 10000),
    node_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (version_id, node_id),
    UNIQUE (version_id, ordinal),
    FOREIGN KEY (tenant_scope_id, site_id, revision, version_id)
        REFERENCES acme_http01_overlay_versions(tenant_scope_id, site_id, revision, id)
        ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE acme_http01_overlay_deployments (
    id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 10),
    version_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    node_id uuid NOT NULL,
    retry_request_id uuid,
    deadline_at timestamptz NOT NULL,
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (id, attempt),
    UNIQUE (version_id, node_id, attempt),
    UNIQUE (id, attempt, version_id, node_id),
    FOREIGN KEY (version_id, node_id)
        REFERENCES acme_http01_overlay_targets(version_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id, revision, version_id)
        REFERENCES acme_http01_overlay_versions(tenant_scope_id, site_id, revision, id)
        ON DELETE RESTRICT,
    CHECK (attempt <= max_attempts),
    CHECK ((attempt = 1 AND retry_request_id IS NULL) OR (attempt > 1 AND retry_request_id IS NOT NULL)),
    CHECK (deadline_at > created_at)
);

CREATE UNIQUE INDEX acme_http01_overlay_deployment_retry_request_idx
    ON acme_http01_overlay_deployments(retry_request_id)
    WHERE retry_request_id IS NOT NULL;

CREATE TABLE acme_http01_overlay_deployment_events (
    deployment_id uuid NOT NULL,
    deployment_attempt integer NOT NULL CHECK (deployment_attempt BETWEEN 1 AND 10),
    sequence bigint NOT NULL CHECK (sequence > 0),
    state text NOT NULL CHECK (state IN (
        'queued', 'retry_queued', 'dispatched', 'applied', 'healthy', 'failed', 'timed_out'
    )),
    receipt_id uuid,
    receipt_digest bytea,
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9._-]{0,127}$'
    ),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (deployment_id, deployment_attempt, sequence),
    FOREIGN KEY (deployment_id, deployment_attempt)
        REFERENCES acme_http01_overlay_deployments(id, attempt) ON DELETE RESTRICT,
    CHECK ((receipt_id IS NULL) = (receipt_digest IS NULL)),
    CHECK (receipt_digest IS NULL OR octet_length(receipt_digest) = 32),
    CHECK (
        (state IN ('applied', 'healthy', 'failed') AND receipt_id IS NOT NULL) OR
        (state NOT IN ('applied', 'healthy', 'failed') AND receipt_id IS NULL)
    ),
    CHECK ((state = 'failed') = (failure_code IS NOT NULL) OR state = 'timed_out')
);

CREATE UNIQUE INDEX acme_http01_overlay_receipt_id_idx
    ON acme_http01_overlay_deployment_events(receipt_id)
    WHERE receipt_id IS NOT NULL;
CREATE INDEX acme_http01_overlay_deployment_latest_idx
    ON acme_http01_overlay_deployment_events(deployment_id, deployment_attempt, sequence DESC);

CREATE TABLE acme_http01_overlay_outbox (
    id uuid PRIMARY KEY,
    deployment_id uuid NOT NULL,
    deployment_attempt integer NOT NULL CHECK (deployment_attempt BETWEEN 1 AND 10),
    version_id uuid NOT NULL,
    node_id uuid NOT NULL,
    subject text NOT NULL CHECK (
        subject = btrim(subject) AND octet_length(subject) BETWEEN 1 AND 255
        AND subject !~ '[[:space:][:cntrl:]]'
    ),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (deployment_id, deployment_attempt),
    FOREIGN KEY (deployment_id, deployment_attempt)
        REFERENCES acme_http01_overlay_deployments(id, attempt) ON DELETE RESTRICT,
    FOREIGN KEY (deployment_id, deployment_attempt, version_id, node_id)
        REFERENCES acme_http01_overlay_deployments(id, attempt, version_id, node_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (version_id, node_id)
        REFERENCES acme_http01_overlay_targets(version_id, node_id) ON DELETE RESTRICT
);

CREATE TABLE acme_http01_overlay_outbox_states (
    outbox_id uuid PRIMARY KEY REFERENCES acme_http01_overlay_outbox(id) ON DELETE RESTRICT,
    status text NOT NULL CHECK (status IN ('pending', 'claimed', 'retry', 'published', 'exhausted')),
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts BETWEEN 0 AND 100),
    lease_token uuid,
    lease_expires_at timestamptz,
    available_at timestamptz NOT NULL,
    last_failure_code text CHECK (
        last_failure_code IS NULL OR last_failure_code ~ '^[a-z0-9][a-z0-9._-]{0,127}$'
    ),
    updated_at timestamptz NOT NULL,
    CHECK (
        (status = 'claimed' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL) OR
        (status <> 'claimed' AND lease_token IS NULL AND lease_expires_at IS NULL)
    ),
    CHECK ((status IN ('retry', 'exhausted')) = (last_failure_code IS NOT NULL))
);

CREATE INDEX acme_http01_overlay_outbox_claim_idx
    ON acme_http01_overlay_outbox_states(status, available_at, outbox_id)
    WHERE status IN ('pending', 'retry');
CREATE INDEX acme_http01_overlay_outbox_lease_idx
    ON acme_http01_overlay_outbox_states(lease_expires_at, outbox_id)
    WHERE status = 'claimed';

CREATE TABLE acme_http01_overlay_outbox_attempts (
    outbox_id uuid NOT NULL REFERENCES acme_http01_overlay_outbox(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    publish_attempt integer NOT NULL CHECK (publish_attempt BETWEEN 0 AND 100),
    event_type text NOT NULL CHECK (event_type IN ('claimed', 'published', 'retry', 'exhausted')),
    lease_token uuid,
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[a-z0-9][a-z0-9._-]{0,127}$'
    ),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (outbox_id, sequence),
    CHECK ((event_type IN ('retry', 'exhausted')) = (failure_code IS NOT NULL)),
    CHECK (
        (event_type = 'exhausted' AND publish_attempt = 0 AND lease_token IS NULL) OR
        (publish_attempt > 0 AND lease_token IS NOT NULL)
    )
);

CREATE FUNCTION protect_acme_http01_overlay_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'ACME HTTP-01 overlay facts are append-only' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION validate_acme_http01_overlay_publication()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_state acme_http01_overlay_states%ROWTYPE;
BEGIN
    SELECT * INTO current_state
    FROM acme_http01_overlay_states
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id
    FOR UPDATE;
    IF NOT FOUND OR current_state.current_revision <> NEW.expected_revision THEN
        RAISE EXCEPTION 'ACME HTTP-01 overlay revision conflict' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_acme_http01_overlay_publication_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    new_version_id uuid;
    prior_version_id uuid;
    actual_token_count integer;
    actual_node_count integer;
    actual_deployment_count integer;
    actual_initial_event_count integer;
    actual_outbox_count integer;
    actual_outbox_state_count integer;
    projected_revision bigint;
BEGIN
    SELECT version.id INTO new_version_id
    FROM acme_http01_overlay_versions version
    WHERE version.publication_id = NEW.id;
    IF new_version_id IS NULL THEN
        RAISE EXCEPTION 'ACME HTTP-01 publication requires a version fact' USING ERRCODE = 'P0001';
    END IF;
    SELECT count(*) INTO actual_token_count
    FROM acme_http01_overlay_token_facts token
    WHERE token.version_id = new_version_id;
    SELECT count(*) INTO actual_node_count
    FROM acme_http01_overlay_targets target
    WHERE target.version_id = new_version_id;
    SELECT count(*) INTO actual_deployment_count
    FROM acme_http01_overlay_deployments deployment
    WHERE deployment.version_id = new_version_id;
    SELECT count(*) INTO actual_initial_event_count
    FROM acme_http01_overlay_deployments deployment
    JOIN acme_http01_overlay_deployment_events event
      ON event.deployment_id = deployment.id AND event.deployment_attempt = deployment.attempt
    WHERE deployment.version_id = new_version_id
      AND deployment.attempt = 1 AND deployment.tenant_scope_id = NEW.tenant_scope_id
      AND deployment.site_id = NEW.site_id AND deployment.revision = NEW.revision
      AND deployment.deadline_at = NEW.deadline_at AND deployment.max_attempts = NEW.max_attempts
      AND deployment.created_at = NEW.created_at
      AND event.sequence = 1 AND event.state = 'queued' AND event.occurred_at = NEW.created_at;
    SELECT count(*) INTO actual_outbox_count
    FROM acme_http01_overlay_deployments deployment
    JOIN acme_http01_overlay_outbox outbox
      ON outbox.deployment_id = deployment.id
     AND outbox.deployment_attempt = deployment.attempt
     AND outbox.version_id = deployment.version_id
     AND outbox.node_id = deployment.node_id
    WHERE deployment.version_id = new_version_id AND deployment.attempt = 1
      AND outbox.created_at = NEW.created_at
      AND right(outbox.subject, 37) = '.' || outbox.node_id::text;
    SELECT count(*) INTO actual_outbox_state_count
    FROM acme_http01_overlay_deployments deployment
    JOIN acme_http01_overlay_outbox outbox
      ON outbox.deployment_id = deployment.id
     AND outbox.deployment_attempt = deployment.attempt
     AND outbox.version_id = deployment.version_id
     AND outbox.node_id = deployment.node_id
    JOIN acme_http01_overlay_outbox_states state ON state.outbox_id = outbox.id
    WHERE deployment.version_id = new_version_id AND deployment.attempt = 1
      AND state.status = 'pending' AND state.publish_attempts = 0
      AND state.lease_token IS NULL AND state.lease_expires_at IS NULL
      AND state.last_failure_code IS NULL
      AND state.available_at = NEW.created_at AND state.updated_at = NEW.created_at;
    SELECT current_revision INTO projected_revision
    FROM acme_http01_overlay_states
    WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id;
    IF actual_token_count <> NEW.token_count OR actual_node_count <> NEW.node_count
       OR actual_deployment_count <> NEW.node_count
       OR actual_initial_event_count <> NEW.node_count
       OR actual_outbox_count <> NEW.node_count
       OR actual_outbox_state_count <> NEW.node_count
       OR projected_revision < NEW.revision THEN
        RAISE EXCEPTION 'ACME HTTP-01 publication facts are incomplete' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.mode = 'cleanup' THEN
        SELECT previous.id INTO prior_version_id
        FROM acme_http01_overlay_versions previous
        WHERE previous.tenant_scope_id = NEW.tenant_scope_id
          AND previous.site_id = NEW.site_id
          AND previous.revision = NEW.expected_revision;
        IF prior_version_id IS NULL
           OR EXISTS (
               SELECT 1
               FROM acme_http01_overlay_token_facts token
               WHERE token.version_id = new_version_id
                 AND NOT EXISTS (
                     SELECT 1 FROM acme_http01_overlay_token_facts previous
                     WHERE previous.version_id = prior_version_id
                       AND previous.operation_id = token.operation_id
                       AND previous.challenge_attempt_id = token.challenge_attempt_id
                       AND previous.domain = token.domain
                       AND previous.token_sha256 = token.token_sha256
                       AND previous.value_sha256 = token.value_sha256
                       AND previous.aad_sha256 = token.aad_sha256
                 )
           )
           OR EXISTS (
               (SELECT node_id FROM acme_http01_overlay_targets WHERE version_id = new_version_id)
               EXCEPT
               (SELECT node_id FROM acme_http01_overlay_targets WHERE version_id = prior_version_id)
           )
           OR EXISTS (
               (SELECT node_id FROM acme_http01_overlay_targets WHERE version_id = prior_version_id)
               EXCEPT
               (SELECT node_id FROM acme_http01_overlay_targets WHERE version_id = new_version_id)
           ) THEN
            RAISE EXCEPTION 'ACME HTTP-01 cleanup may only shrink tokens on the current target set'
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_acme_http01_overlay_token()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    challenge_kind text;
    challenge_identifier text;
    challenge_wildcard boolean;
BEGIN
    SELECT challenge_type, identifier, wildcard
    INTO challenge_kind, challenge_identifier, challenge_wildcard
    FROM acme_issuance_challenge_attempts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND operation_id = NEW.operation_id
      AND attempt_id = NEW.challenge_attempt_id;
    IF NOT FOUND OR challenge_kind <> 'http-01' OR challenge_wildcard
       OR challenge_identifier <> NEW.domain THEN
        RAISE EXCEPTION 'invalid ACME HTTP-01 challenge binding' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_http01_overlay_deployment_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous acme_http01_overlay_deployment_events%ROWTYPE;
    expected_initial text;
BEGIN
    PERFORM 1 FROM acme_http01_overlay_deployments
    WHERE id = NEW.deployment_id AND attempt = NEW.deployment_attempt
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME HTTP-01 overlay deployment is missing' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.sequence = 1 THEN
        expected_initial := CASE WHEN NEW.deployment_attempt = 1 THEN 'queued' ELSE 'retry_queued' END;
        IF NEW.state <> expected_initial THEN
            RAISE EXCEPTION 'invalid initial ACME HTTP-01 deployment state' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO previous
    FROM acme_http01_overlay_deployment_events
    WHERE deployment_id = NEW.deployment_id
      AND deployment_attempt = NEW.deployment_attempt
      AND sequence = NEW.sequence - 1;
    IF NOT FOUND OR NEW.occurred_at < previous.occurred_at THEN
        RAISE EXCEPTION 'ACME HTTP-01 deployment event is not contiguous' USING ERRCODE = 'P0001';
    END IF;
    IF NOT (
        (previous.state IN ('queued', 'retry_queued') AND NEW.state IN ('dispatched', 'failed', 'timed_out')) OR
        (previous.state = 'dispatched' AND NEW.state IN ('applied', 'failed', 'timed_out')) OR
        (previous.state = 'applied' AND NEW.state IN ('healthy', 'failed', 'timed_out'))
    ) THEN
        RAISE EXCEPTION 'invalid ACME HTTP-01 deployment transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_acme_http01_overlay_outbox_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous acme_http01_overlay_outbox_attempts%ROWTYPE;
BEGIN
    PERFORM 1 FROM acme_http01_overlay_outbox
    WHERE id = NEW.outbox_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME HTTP-01 outbox fact is missing' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.sequence = 1 THEN
        IF NOT (
            (NEW.event_type = 'claimed' AND NEW.publish_attempt = 1 AND NEW.lease_token IS NOT NULL) OR
            (NEW.event_type = 'exhausted' AND NEW.publish_attempt = 0 AND NEW.lease_token IS NULL)
        ) THEN
            RAISE EXCEPTION 'invalid initial ACME HTTP-01 outbox attempt' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO previous
    FROM acme_http01_overlay_outbox_attempts
    WHERE outbox_id = NEW.outbox_id AND sequence = NEW.sequence - 1;
    IF NOT FOUND OR NEW.occurred_at < previous.occurred_at OR NOT (
        (previous.event_type = 'claimed' AND NEW.event_type IN ('published', 'retry', 'exhausted')
            AND NEW.publish_attempt = previous.publish_attempt AND NEW.lease_token = previous.lease_token) OR
        (previous.event_type = 'retry' AND NEW.event_type = 'claimed'
            AND NEW.publish_attempt = previous.publish_attempt + 1) OR
        (previous.event_type = 'retry' AND NEW.event_type = 'exhausted'
            AND NEW.publish_attempt = previous.publish_attempt AND NEW.lease_token = previous.lease_token)
    ) THEN
        RAISE EXCEPTION 'invalid ACME HTTP-01 outbox attempt transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_acme_http01_overlay_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ACME HTTP-01 overlay state cannot be deleted' USING ERRCODE = 'P0001';
    END IF;
    IF ROW(NEW.tenant_scope_id, NEW.site_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.tenant_scope_id, OLD.site_id, OLD.created_at)
       OR NEW.updated_at < OLD.updated_at
       OR NEW.current_revision NOT IN (OLD.current_revision, OLD.current_revision + 1)
       OR (OLD.latest_healthy_revision IS NOT NULL AND
           (NEW.latest_healthy_revision IS NULL OR NEW.latest_healthy_revision < OLD.latest_healthy_revision)) THEN
        RAISE EXCEPTION 'invalid ACME HTTP-01 overlay state transition' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.current_revision = OLD.current_revision + 1 AND NOT EXISTS (
        SELECT 1 FROM acme_http01_overlay_publications
        WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id
          AND revision = NEW.current_revision
    ) THEN
        RAISE EXCEPTION 'ACME HTTP-01 overlay state requires a publication fact' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.latest_healthy_revision IS DISTINCT FROM OLD.latest_healthy_revision AND NOT EXISTS (
        SELECT 1
        FROM acme_http01_overlay_versions version
        WHERE version.tenant_scope_id = NEW.tenant_scope_id
          AND version.site_id = NEW.site_id
          AND version.revision = NEW.latest_healthy_revision
          AND NOT EXISTS (
              SELECT 1
              FROM acme_http01_overlay_targets target
              LEFT JOIN LATERAL (
                  SELECT event.state
                  FROM acme_http01_overlay_deployments deployment
                  JOIN acme_http01_overlay_deployment_events event
                    ON event.deployment_id = deployment.id
                   AND event.deployment_attempt = deployment.attempt
                  WHERE deployment.version_id = target.version_id
                    AND deployment.node_id = target.node_id
                  ORDER BY deployment.attempt DESC, event.sequence DESC
                  LIMIT 1
              ) latest ON true
              WHERE target.version_id = version.id
                AND latest.state IS DISTINCT FROM 'healthy'
          )
    ) THEN
        RAISE EXCEPTION 'latest healthy ACME HTTP-01 revision is not healthy' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_acme_http01_overlay_outbox_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ACME HTTP-01 outbox state cannot be deleted' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.outbox_id <> OLD.outbox_id OR NEW.updated_at < OLD.updated_at
       OR NEW.publish_attempts < OLD.publish_attempts
       OR NEW.publish_attempts > OLD.publish_attempts + 1
       OR OLD.status IN ('published', 'exhausted') THEN
        RAISE EXCEPTION 'invalid ACME HTTP-01 outbox state transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_acme_http01_overlay_outbox_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    projected acme_http01_overlay_outbox_states%ROWTYPE;
    latest acme_http01_overlay_outbox_attempts%ROWTYPE;
    claimed_count integer;
BEGIN
    SELECT * INTO projected
    FROM acme_http01_overlay_outbox_states
    WHERE outbox_id = NEW.outbox_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ACME HTTP-01 outbox projection is missing' USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO latest
    FROM acme_http01_overlay_outbox_attempts
    WHERE outbox_id = projected.outbox_id
    ORDER BY sequence DESC
    LIMIT 1;
    SELECT count(*) INTO claimed_count
    FROM acme_http01_overlay_outbox_attempts
    WHERE outbox_id = projected.outbox_id AND event_type = 'claimed';

    IF projected.status = 'pending' THEN
        IF latest.outbox_id IS NOT NULL OR projected.publish_attempts <> 0
           OR projected.lease_token IS NOT NULL OR projected.lease_expires_at IS NOT NULL
           OR projected.last_failure_code IS NOT NULL OR projected.available_at <> projected.updated_at THEN
            RAISE EXCEPTION 'ACME HTTP-01 pending outbox projection is invalid' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;

    IF latest.outbox_id IS NULL
       OR projected.publish_attempts <> latest.publish_attempt
       OR claimed_count <> projected.publish_attempts
       OR projected.updated_at <> latest.occurred_at
       OR projected.last_failure_code IS DISTINCT FROM latest.failure_code THEN
        RAISE EXCEPTION 'ACME HTTP-01 outbox projection does not match its attempt ledger'
            USING ERRCODE = 'P0001';
    END IF;

    IF projected.status = 'claimed' THEN
        IF latest.event_type <> 'claimed' OR projected.lease_token IS DISTINCT FROM latest.lease_token
           OR projected.lease_expires_at IS NULL OR projected.lease_expires_at <= projected.updated_at THEN
            RAISE EXCEPTION 'ACME HTTP-01 claimed outbox projection is invalid' USING ERRCODE = 'P0001';
        END IF;
    ELSIF projected.status = 'retry' THEN
        IF latest.event_type <> 'retry' OR projected.lease_token IS NOT NULL
           OR projected.lease_expires_at IS NOT NULL OR projected.available_at <= projected.updated_at THEN
            RAISE EXCEPTION 'ACME HTTP-01 retry outbox projection is invalid' USING ERRCODE = 'P0001';
        END IF;
    ELSIF projected.status = 'published' THEN
        IF latest.event_type <> 'published' OR projected.lease_token IS NOT NULL
           OR projected.lease_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'ACME HTTP-01 published outbox projection is invalid' USING ERRCODE = 'P0001';
        END IF;
    ELSIF projected.status = 'exhausted' THEN
        IF latest.event_type <> 'exhausted' OR projected.lease_token IS NOT NULL
           OR projected.lease_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'ACME HTTP-01 exhausted outbox projection is invalid' USING ERRCODE = 'P0001';
        END IF;
    ELSE
        RAISE EXCEPTION 'unknown ACME HTTP-01 outbox projection state' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER acme_http01_overlay_publications_validate
BEFORE INSERT ON acme_http01_overlay_publications
FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_overlay_publication();
CREATE CONSTRAINT TRIGGER acme_http01_overlay_publications_complete
AFTER INSERT ON acme_http01_overlay_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_acme_http01_overlay_publication_complete();
CREATE TRIGGER acme_http01_overlay_token_facts_validate
BEFORE INSERT ON acme_http01_overlay_token_facts
FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_overlay_token();
CREATE TRIGGER acme_http01_overlay_deployment_events_validate
BEFORE INSERT ON acme_http01_overlay_deployment_events
FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_overlay_deployment_event();
CREATE TRIGGER acme_http01_overlay_outbox_attempts_validate
BEFORE INSERT ON acme_http01_overlay_outbox_attempts
FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_overlay_outbox_attempt();
CREATE TRIGGER acme_http01_overlay_states_protected
BEFORE UPDATE OR DELETE ON acme_http01_overlay_states
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_state();
CREATE TRIGGER acme_http01_overlay_states_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_states
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_state();
CREATE TRIGGER acme_http01_overlay_outbox_states_protected
BEFORE UPDATE OR DELETE ON acme_http01_overlay_outbox_states
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_outbox_state();
CREATE CONSTRAINT TRIGGER acme_http01_overlay_outbox_states_projected
AFTER INSERT OR UPDATE ON acme_http01_overlay_outbox_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_acme_http01_overlay_outbox_projection();
CREATE CONSTRAINT TRIGGER acme_http01_overlay_outbox_attempts_projected
AFTER INSERT ON acme_http01_overlay_outbox_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_acme_http01_overlay_outbox_projection();
CREATE TRIGGER acme_http01_overlay_outbox_states_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_outbox_states
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_outbox_state();

CREATE TRIGGER acme_http01_overlay_publications_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_publications
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_publications_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_publications
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_versions_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_versions
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_versions_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_versions
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_token_facts_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_token_facts
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_token_facts_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_token_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_targets_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_targets
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_targets_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_targets
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_deployments_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_deployments
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_deployments_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_deployments
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_deployment_events_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_deployment_events
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_deployment_events_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_deployment_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_outbox_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_outbox
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_outbox_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_outbox
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_outbox_attempts_immutable
BEFORE UPDATE OR DELETE ON acme_http01_overlay_outbox_attempts
FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_outbox_attempts_no_truncate
BEFORE TRUNCATE ON acme_http01_overlay_outbox_attempts
FOR EACH STATEMENT EXECUTE FUNCTION protect_acme_http01_overlay_fact();
