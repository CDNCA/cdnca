LOCK TABLE schema_migrations,
    access_scopes,
    tenants,
    users,
    memberships,
    edge_configuration_scopes
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 85 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 85 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 85 AND migration_id = '085_certificate_asset_actor_scope'
          AND checksum_sha256 = '1e2554228e01bcc8d79fa78e55dd51eb65e52ce45afcd754a2e6cd9a9a540937'
          AND down_checksum_sha256 = '116890b0368609b973415f1a25c599c145bd42fdfec0d1a25639160cc736f046'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'site and L4 automatic publication requires frozen verified migration head 085'
            USING ERRCODE = 'P8600';
    END IF;
END;
$$;

CREATE TABLE edge_automatic_publication_policy_facts (
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    mode text NOT NULL CHECK (mode IN ('manual', 'automatic')),
    node_ids uuid[] NOT NULL DEFAULT '{}'::uuid[],
    target_snapshot_id uuid,
    target_snapshot_revision bigint,
    target_snapshot_sha256 bytea,
    activation_timeout_ms bigint NOT NULL CHECK (activation_timeout_ms BETWEEN 1000 AND 600000),
    observation_window_ms bigint NOT NULL CHECK (observation_window_ms BETWEEN 1000 AND 600000),
    required_consecutive_successes integer NOT NULL CHECK (required_consecutive_successes BETWEEN 1 AND 100),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    deadline_window_seconds integer NOT NULL CHECK (deadline_window_seconds BETWEEN 30 AND 86400),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    reason text NOT NULL CHECK (
        reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 128 AND reason !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (target_scope_id, revision),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (mode = 'manual' AND cardinality(node_ids) = 0 AND target_snapshot_id IS NULL AND
         target_snapshot_revision IS NULL AND target_snapshot_sha256 IS NULL) OR
        (mode = 'automatic' AND (
            (cardinality(node_ids) BETWEEN 1 AND 10000 AND target_snapshot_id IS NULL AND
             target_snapshot_revision IS NULL AND target_snapshot_sha256 IS NULL) OR
            (cardinality(node_ids) = 0 AND target_snapshot_id IS NOT NULL AND
             target_snapshot_revision > 0 AND octet_length(target_snapshot_sha256) = 32)
        ))
    )
);

CREATE INDEX edge_automatic_publication_policy_created_086_idx
    ON edge_automatic_publication_policy_facts(target_scope_id, created_at DESC, revision DESC);

CREATE TABLE edge_automatic_publication_requests (
    id uuid PRIMARY KEY,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_scope_kind text NOT NULL CHECK (actor_scope_kind IN ('tenant', 'platform')),
    source_kind text NOT NULL CHECK (source_kind IN ('site', 'l4')),
    source_resource_id uuid,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    operation text NOT NULL CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete'
    )),
    reason text NOT NULL CHECK (reason = 'resource_mutation'),
    permission_name text NOT NULL CHECK (permission_name IN ('sites.manage', 'streams.manage')),
    source_request_id text NOT NULL CHECK (
        source_request_id = btrim(source_request_id) AND char_length(source_request_id) BETWEEN 1 AND 128 AND
        source_request_id !~ '[[:cntrl:]]'
    ),
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^edgeauto\.[0-9a-f-]{36}$' AND char_length(idempotency_key) <= 96
    ),
    correlation_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (target_scope_id, policy_revision)
        REFERENCES edge_automatic_publication_policy_facts(target_scope_id, revision) ON DELETE RESTRICT,
    UNIQUE (target_scope_id, source_revision),
    UNIQUE (target_scope_id, idempotency_key),
    UNIQUE (target_scope_id, correlation_id),
    CHECK (
        (source_kind = 'site' AND permission_name = 'sites.manage' AND (
            operation IN ('site.batch.enable', 'site.batch.disable', 'site.batch.delete') AND source_resource_id IS NULL OR
            operation IN ('site.create', 'site.update', 'site.origin.update', 'site.delete') AND source_resource_id IS NOT NULL
        )) OR
        (source_kind = 'l4' AND permission_name = 'streams.manage' AND
         operation IN ('stream.create', 'stream.update', 'stream.delete') AND source_resource_id IS NOT NULL)
    )
);

CREATE INDEX edge_automatic_publication_requests_scope_created_086_idx
    ON edge_automatic_publication_requests(target_scope_id, created_at DESC, id DESC);

CREATE TABLE edge_automatic_publication_request_state_facts (
    request_id uuid NOT NULL REFERENCES edge_automatic_publication_requests(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    state text NOT NULL CHECK (state IN (
        'pending', 'leased', 'retry_wait', 'reconciling', 'succeeded', 'failed', 'superseded'
    )),
    attempt integer NOT NULL CHECK (attempt >= 0),
    lease_owner text CHECK (
        lease_owner IS NULL OR
        (lease_owner = btrim(lease_owner) AND char_length(lease_owner) BETWEEN 1 AND 128 AND lease_owner !~ '[[:cntrl:]]')
    ),
    lease_token uuid,
    lease_expires_at timestamptz,
    publication_id uuid,
    rollout_id uuid,
    available_at timestamptz,
    terminal_code text CHECK (
        terminal_code IS NULL OR
        (terminal_code = btrim(terminal_code) AND char_length(terminal_code) BETWEEN 1 AND 128 AND
         terminal_code ~ '^[a-z0-9_]+$')
    ),
    error_class text CHECK (
        error_class IS NULL OR error_class IN ('publish_outcome_unknown', 'publication_actor_unavailable')
    ),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (request_id, sequence),
    CHECK (
        (state = 'leased') = (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
    ),
    CHECK (state = 'leased' OR (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CHECK ((state = 'retry_wait') = (available_at IS NOT NULL AND error_class IS NOT NULL)),
    CHECK (state = 'retry_wait' OR (available_at IS NULL AND error_class IS NULL)),
    CHECK (state NOT IN ('reconciling', 'succeeded') OR (publication_id IS NOT NULL AND rollout_id IS NOT NULL)),
    CHECK (state NOT IN ('succeeded', 'failed', 'superseded') OR terminal_code IS NOT NULL),
	CHECK ((state = 'pending' AND attempt = 0) OR state = 'superseded' OR
	       (state NOT IN ('pending', 'superseded') AND attempt > 0)),
    CHECK (lease_expires_at IS NULL OR lease_expires_at > occurred_at),
    CHECK (available_at IS NULL OR available_at >= occurred_at)
);

CREATE INDEX edge_automatic_publication_state_queue_086_idx
    ON edge_automatic_publication_request_state_facts(state, available_at, lease_expires_at, occurred_at);
CREATE UNIQUE INDEX edge_automatic_publication_state_lease_token_086_idx
    ON edge_automatic_publication_request_state_facts(lease_token) WHERE lease_token IS NOT NULL;

CREATE FUNCTION prevent_edge_automatic_publication_fact_mutation_086()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'automatic publication facts are append-only' USING ERRCODE = 'P8602';
END;
$$;

CREATE TRIGGER edge_automatic_publication_policy_facts_immutable_086
BEFORE UPDATE OR DELETE ON edge_automatic_publication_policy_facts
FOR EACH ROW EXECUTE FUNCTION prevent_edge_automatic_publication_fact_mutation_086();
CREATE TRIGGER edge_automatic_publication_policy_facts_no_truncate_086
BEFORE TRUNCATE ON edge_automatic_publication_policy_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_edge_automatic_publication_fact_mutation_086();
CREATE TRIGGER edge_automatic_publication_requests_immutable_086
BEFORE UPDATE OR DELETE ON edge_automatic_publication_requests
FOR EACH ROW EXECUTE FUNCTION prevent_edge_automatic_publication_fact_mutation_086();
CREATE TRIGGER edge_automatic_publication_requests_no_truncate_086
BEFORE TRUNCATE ON edge_automatic_publication_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_edge_automatic_publication_fact_mutation_086();
CREATE TRIGGER edge_automatic_publication_states_immutable_086
BEFORE UPDATE OR DELETE ON edge_automatic_publication_request_state_facts
FOR EACH ROW EXECUTE FUNCTION prevent_edge_automatic_publication_fact_mutation_086();
CREATE TRIGGER edge_automatic_publication_states_no_truncate_086
BEFORE TRUNCATE ON edge_automatic_publication_request_state_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_edge_automatic_publication_fact_mutation_086();

CREATE FUNCTION validate_edge_automatic_publication_policy_086()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous_revision bigint;
    target_kind text;
    actor_kind text;
    actor_active boolean;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'edge-automatic-publication-policy:' || NEW.target_scope_id::text, 0));
    SELECT kind INTO target_kind FROM access_scopes WHERE id = NEW.target_scope_id FOR SHARE;
    SELECT scope.kind, account.status = 'active' AND membership.status = 'active'
      INTO actor_kind, actor_active
    FROM access_scopes scope
    JOIN memberships membership
      ON membership.scope_id = scope.id AND membership.user_id = NEW.actor_user_id
    JOIN users account ON account.id = membership.user_id
    WHERE scope.id = NEW.actor_scope_id
    FOR SHARE OF scope, membership, account;
    SELECT max(revision) INTO previous_revision
    FROM edge_automatic_publication_policy_facts
    WHERE target_scope_id = NEW.target_scope_id;
    IF target_kind IS DISTINCT FROM 'tenant' OR actor_kind NOT IN ('tenant', 'platform') OR
       actor_active IS DISTINCT FROM true OR
       (actor_kind = 'tenant' AND NEW.actor_scope_id <> NEW.target_scope_id) OR
       NEW.revision <> COALESCE(previous_revision, 0) + 1 OR
       NEW.node_ids IS DISTINCT FROM ARRAY(
           SELECT DISTINCT node_id FROM unnest(NEW.node_ids) node_id ORDER BY node_id
       ) OR EXISTS (SELECT 1 FROM unnest(NEW.node_ids) node_id WHERE node_id IS NULL) THEN
        RAISE EXCEPTION 'invalid automatic publication policy fact' USING ERRCODE = 'P8602';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_automatic_publication_policy_validate_086
BEFORE INSERT ON edge_automatic_publication_policy_facts
FOR EACH ROW EXECUTE FUNCTION validate_edge_automatic_publication_policy_086();

CREATE FUNCTION validate_edge_automatic_publication_request_086()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_kind text;
    actor_kind text;
    actor_active boolean;
    policy_mode text;
BEGIN
    SELECT kind INTO target_kind FROM access_scopes WHERE id = NEW.target_scope_id FOR SHARE;
    SELECT scope.kind, account.status = 'active' AND membership.status = 'active'
      INTO actor_kind, actor_active
    FROM access_scopes scope
    JOIN memberships membership
      ON membership.scope_id = scope.id AND membership.user_id = NEW.actor_user_id
    JOIN users account ON account.id = membership.user_id
    WHERE scope.id = NEW.actor_scope_id
    FOR SHARE OF scope, membership, account;
    SELECT mode INTO policy_mode
    FROM edge_automatic_publication_policy_facts
    WHERE target_scope_id = NEW.target_scope_id AND revision = NEW.policy_revision;
    IF target_kind IS DISTINCT FROM 'tenant' OR actor_kind IS DISTINCT FROM NEW.actor_scope_kind OR
       actor_active IS DISTINCT FROM true OR policy_mode IS DISTINCT FROM 'automatic' OR
       (actor_kind = 'tenant' AND NEW.actor_scope_id <> NEW.target_scope_id) THEN
        RAISE EXCEPTION 'invalid automatic publication request identity' USING ERRCODE = 'P8602';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_automatic_publication_request_validate_086
BEFORE INSERT ON edge_automatic_publication_requests
FOR EACH ROW EXECUTE FUNCTION validate_edge_automatic_publication_request_086();

CREATE FUNCTION validate_edge_automatic_publication_state_086()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous edge_automatic_publication_request_state_facts%ROWTYPE;
BEGIN
    PERFORM 1 FROM edge_automatic_publication_requests WHERE id = NEW.request_id FOR UPDATE;
    SELECT * INTO previous
    FROM edge_automatic_publication_request_state_facts
    WHERE request_id = NEW.request_id
    ORDER BY sequence DESC LIMIT 1;
    IF previous.request_id IS NULL THEN
        IF NEW.sequence <> 1 OR NEW.state NOT IN ('pending', 'superseded') THEN
            RAISE EXCEPTION 'invalid initial automatic publication state' USING ERRCODE = 'P8602';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.sequence <> previous.sequence + 1 OR NEW.attempt < previous.attempt OR NOT (
        (previous.state IN ('pending', 'retry_wait') AND NEW.state IN ('leased', 'superseded')) OR
        (previous.state = 'leased' AND NEW.state IN ('retry_wait', 'reconciling', 'failed', 'superseded')) OR
        (previous.state = 'leased' AND NEW.state = 'leased' AND
         previous.lease_expires_at <= NEW.occurred_at AND NEW.attempt = previous.attempt + 1) OR
        (previous.state = 'reconciling' AND NEW.state IN ('succeeded', 'failed'))
    ) THEN
        RAISE EXCEPTION 'invalid automatic publication state transition' USING ERRCODE = 'P8602';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER edge_automatic_publication_state_validate_086
BEFORE INSERT ON edge_automatic_publication_request_state_facts
FOR EACH ROW EXECUTE FUNCTION validate_edge_automatic_publication_state_086();
