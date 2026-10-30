CREATE TABLE cache_policy_heads (
    site_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (scope_id, site_id),
    FOREIGN KEY (scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at)
);

CREATE TABLE cache_policy_revisions (
    site_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    mode text NOT NULL CHECK (mode IN ('disabled', 'follow_origin', 'override')),
    rules jsonb NOT NULL CHECK (
        jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) <= 100
    ),
    query_mode text NOT NULL CHECK (query_mode IN ('preserve', 'ignore', 'include', 'exclude')),
    query_names text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(query_names) <= 64),
    vary_headers text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(vary_headers) <= 16),
    disk_quota_bytes bigint NOT NULL CHECK (disk_quota_bytes BETWEEN 0 AND 17592186044416),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id = btrim(request_id) AND
        request_id !~ '[[:cntrl:]]' AND position(U&'\2028' in request_id) = 0 AND
        position(U&'\2029' in request_id) = 0
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, revision),
    UNIQUE (scope_id, site_id, revision),
    FOREIGN KEY (scope_id, site_id)
        REFERENCES cache_policy_heads(scope_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (mode = 'disabled' AND jsonb_array_length(rules) = 0 AND disk_quota_bytes = 0) OR
        (mode = 'follow_origin' AND jsonb_array_length(rules) = 0 AND disk_quota_bytes > 0) OR
        (mode = 'override' AND jsonb_array_length(rules) > 0 AND disk_quota_bytes > 0)
    ),
    CHECK (
        (query_mode IN ('preserve', 'ignore') AND cardinality(query_names) = 0) OR
        (query_mode IN ('include', 'exclude') AND cardinality(query_names) > 0)
    )
);

CREATE INDEX cache_policy_revisions_scope_created_idx
    ON cache_policy_revisions (scope_id, created_at DESC, site_id, revision DESC);

CREATE TABLE cache_policy_write_requests (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL,
    site_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_revision bigint,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (scope_id, idempotency_key),
    FOREIGN KEY (scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (site_id, response_revision)
        REFERENCES cache_policy_revisions(site_id, revision) ON DELETE RESTRICT,
    CHECK (
        (completed_at IS NULL AND response_revision IS NULL) OR
        (completed_at IS NOT NULL AND response_revision IS NOT NULL AND completed_at >= created_at)
    )
);

CREATE INDEX cache_policy_write_requests_scope_created_idx
    ON cache_policy_write_requests (scope_id, created_at DESC, id DESC);

CREATE TABLE cache_operations (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    site_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('purge', 'prewarm')),
    target_type text NOT NULL CHECK (target_type IN ('exact_url', 'directory_prefix', 'whole_site')),
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id = btrim(request_id) AND
        request_id !~ '[[:cntrl:]]' AND position(U&'\2028' in request_id) = 0 AND
        position(U&'\2029' in request_id) = 0
    ),
    actor_user_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN (
        'queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled'
    )),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 11),
    target_count integer NOT NULL CHECK (target_count BETWEEN 1 AND 1000),
    node_count integer NOT NULL CHECK (node_count BETWEEN 1 AND 1000),
    total_count integer NOT NULL CHECK (total_count BETWEEN 1 AND 100000),
    completed_count integer NOT NULL DEFAULT 0 CHECK (completed_count >= 0),
    succeeded_count integer NOT NULL DEFAULT 0 CHECK (succeeded_count >= 0),
    failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    cancelled_count integer NOT NULL DEFAULT 0 CHECK (cancelled_count >= 0),
    cancel_requested_at timestamptz,
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (scope_id, idempotency_key),
    UNIQUE (scope_id, id),
    UNIQUE (scope_id, id, site_id),
    FOREIGN KEY (scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (NOT (action = 'prewarm' AND target_type <> 'exact_url')),
    CHECK (total_count = target_count * node_count),
    CHECK (completed_count = succeeded_count + failed_count + cancelled_count),
    CHECK (completed_count <= total_count),
    CHECK (
        (state = 'queued' AND completed_at IS NULL) OR
        (state = 'running' AND started_at IS NOT NULL AND completed_at IS NULL) OR
        (state IN ('succeeded', 'partial_failed', 'failed', 'cancelled') AND completed_at IS NOT NULL)
    ),
    CHECK (updated_at >= created_at),
    CHECK (started_at IS NULL OR started_at >= created_at),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX cache_operations_scope_state_created_idx
    ON cache_operations (scope_id, state, created_at, id);
CREATE INDEX cache_operations_scope_site_created_idx
    ON cache_operations (scope_id, site_id, created_at DESC, id DESC);

CREATE TABLE cache_operation_commands (
    id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    command text NOT NULL CHECK (command IN ('retry', 'cancel')),
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    actor_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (scope_id, operation_id, command, idempotency_key),
    UNIQUE (scope_id, operation_id, id),
    FOREIGN KEY (scope_id, operation_id)
        REFERENCES cache_operations(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX cache_operation_commands_scope_created_idx
    ON cache_operation_commands (scope_id, created_at DESC, id DESC);

CREATE TABLE cache_operation_targets (
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 1000),
    canonical_url text NOT NULL CHECK (
        char_length(canonical_url) BETWEEN 1 AND 16384 AND
        canonical_url = btrim(canonical_url) AND canonical_url !~ '[[:cntrl:]]' AND
        position(U&'\2028' in canonical_url) = 0 AND position(U&'\2029' in canonical_url) = 0
    ),
    canonical_path text NOT NULL CHECK (
        char_length(canonical_path) BETWEEN 1 AND 8192 AND left(canonical_path, 1) = '/' AND
        canonical_path !~ '[[:cntrl:]]' AND position(U&'\2028' in canonical_path) = 0 AND
        position(U&'\2029' in canonical_path) = 0
    ),
    PRIMARY KEY (operation_id, ordinal),
    UNIQUE (scope_id, operation_id, ordinal),
    UNIQUE (operation_id, canonical_url),
    FOREIGN KEY (scope_id, operation_id)
        REFERENCES cache_operations(scope_id, id) ON DELETE RESTRICT
);

CREATE TABLE cache_operation_nodes (
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN (
        'queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled'
    )),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 11),
    lease_id uuid,
    lease_owner text,
    lease_expires_at timestamptz,
    next_attempt_at timestamptz,
    total_count integer NOT NULL CHECK (total_count BETWEEN 1 AND 1000),
    completed_count integer NOT NULL DEFAULT 0 CHECK (completed_count >= 0),
    succeeded_count integer NOT NULL DEFAULT 0 CHECK (succeeded_count >= 0),
    failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    cancelled_count integer NOT NULL DEFAULT 0 CHECK (cancelled_count >= 0),
    last_error_code text CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (operation_id, node_id),
    UNIQUE (scope_id, operation_id, node_id),
    FOREIGN KEY (scope_id, operation_id)
        REFERENCES cache_operations(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    CHECK (completed_count = succeeded_count + failed_count + cancelled_count),
    CHECK (completed_count <= total_count),
    CHECK (
        (state = 'queued' AND lease_id IS NULL AND lease_owner IS NULL AND
         lease_expires_at IS NULL AND next_attempt_at IS NOT NULL AND completed_at IS NULL) OR
        (state = 'running' AND attempt > 0 AND lease_id IS NOT NULL AND lease_owner IS NOT NULL AND
         lease_expires_at IS NOT NULL AND next_attempt_at IS NULL AND completed_at IS NULL) OR
        (state IN ('succeeded', 'partial_failed', 'failed', 'cancelled') AND
         lease_id IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL AND
         next_attempt_at IS NULL AND completed_at IS NOT NULL)
    ),
    CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX cache_operation_nodes_open_lease_idx
    ON cache_operation_nodes (lease_id) WHERE lease_id IS NOT NULL;
CREATE INDEX cache_operation_nodes_claim_idx
    ON cache_operation_nodes (scope_id, next_attempt_at, operation_id, node_id)
    WHERE state = 'queued';
CREATE INDEX cache_operation_nodes_expired_idx
    ON cache_operation_nodes (scope_id, lease_expires_at, operation_id, node_id)
    WHERE state = 'running';

CREATE TABLE cache_operation_node_targets (
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    target_ordinal integer NOT NULL,
    state text NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 11),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    error_code text CHECK (
        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    completed_at timestamptz,
    PRIMARY KEY (operation_id, node_id, target_ordinal),
    UNIQUE (scope_id, operation_id, node_id, target_ordinal),
    FOREIGN KEY (scope_id, operation_id, node_id)
        REFERENCES cache_operation_nodes(scope_id, operation_id, node_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, operation_id, target_ordinal)
        REFERENCES cache_operation_targets(scope_id, operation_id, ordinal) ON DELETE RESTRICT,
    CHECK (
        (state = 'queued' AND sequence = 0 AND error_code IS NULL AND completed_at IS NULL) OR
        (state = 'running' AND attempt > 0 AND sequence = 0 AND error_code IS NULL AND completed_at IS NULL) OR
        (state = 'succeeded' AND attempt > 0 AND sequence > 0 AND error_code IS NULL AND completed_at IS NOT NULL) OR
        (state = 'failed' AND attempt > 0 AND error_code IS NOT NULL AND completed_at IS NOT NULL) OR
        (state = 'cancelled' AND error_code = 'cancelled' AND completed_at IS NOT NULL)
    )
);

CREATE INDEX cache_operation_node_targets_state_idx
    ON cache_operation_node_targets (scope_id, operation_id, node_id, state, target_ordinal);

CREATE TABLE cache_operation_node_attempts (
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 11),
    lease_id uuid NOT NULL UNIQUE,
    worker_id text NOT NULL CHECK (
        char_length(worker_id) BETWEEN 1 AND 128 AND worker_id = btrim(worker_id) AND
        worker_id !~ '[[:cntrl:]]' AND position(U&'\2028' in worker_id) = 0 AND
        position(U&'\2029' in worker_id) = 0
    ),
    state text NOT NULL CHECK (state IN (
        'running', 'succeeded', 'partial_failed', 'failed', 'cancelled', 'lease_expired'
    )),
    target_count integer NOT NULL CHECK (target_count BETWEEN 1 AND 1000),
    report_sequence bigint NOT NULL DEFAULT 0 CHECK (report_sequence >= 0),
    report_digest bytea CHECK (report_digest IS NULL OR octet_length(report_digest) = 32),
    error_code text CHECK (
        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    started_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (operation_id, node_id, attempt),
    UNIQUE (scope_id, operation_id, node_id, attempt),
    FOREIGN KEY (scope_id, operation_id, node_id)
        REFERENCES cache_operation_nodes(scope_id, operation_id, node_id) ON DELETE RESTRICT,
    CHECK (lease_expires_at > started_at),
    CHECK (
        (state = 'running' AND report_sequence = 0 AND report_digest IS NULL AND
         error_code IS NULL AND completed_at IS NULL) OR
        (state IN ('succeeded', 'partial_failed', 'failed') AND report_sequence > 0 AND
         report_digest IS NOT NULL AND completed_at IS NOT NULL) OR
        (state IN ('cancelled', 'lease_expired') AND report_sequence = 0 AND
         report_digest IS NULL AND error_code IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX cache_operation_node_attempts_scope_started_idx
    ON cache_operation_node_attempts (scope_id, started_at DESC, operation_id, node_id);

CREATE TABLE cache_operation_target_results (
    id uuid PRIMARY KEY,
    operation_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    node_id uuid NOT NULL,
    target_ordinal integer NOT NULL,
    attempt integer CHECK (attempt BETWEEN 1 AND 11),
    source text NOT NULL CHECK (source IN ('report', 'lease_expire', 'cancel')),
    state text NOT NULL CHECK (state IN ('succeeded', 'failed', 'cancelled')),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    error_code text CHECK (
        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    report_digest bytea CHECK (report_digest IS NULL OR octet_length(report_digest) = 32),
    command_id uuid,
    audit_event_id uuid NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    UNIQUE NULLS NOT DISTINCT (operation_id, node_id, target_ordinal, attempt),
    UNIQUE (scope_id, operation_id, node_id, target_ordinal, attempt, source),
    FOREIGN KEY (scope_id, operation_id, node_id, target_ordinal)
        REFERENCES cache_operation_node_targets(scope_id, operation_id, node_id, target_ordinal)
        ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, operation_id, node_id, attempt)
        REFERENCES cache_operation_node_attempts(scope_id, operation_id, node_id, attempt)
        ON DELETE RESTRICT,
    FOREIGN KEY (scope_id, operation_id, command_id)
        REFERENCES cache_operation_commands(scope_id, operation_id, id) ON DELETE RESTRICT,
    CHECK (
        (source = 'report' AND attempt IS NOT NULL AND state IN ('succeeded', 'failed') AND
         sequence > 0 AND report_digest IS NOT NULL AND command_id IS NULL AND
         ((state = 'succeeded' AND error_code IS NULL) OR
          (state = 'failed' AND error_code IS NOT NULL))) OR
        (source = 'lease_expire' AND attempt IS NOT NULL AND state = 'failed' AND
         sequence = 0 AND report_digest IS NULL AND command_id IS NULL AND
         error_code = 'retries_exhausted') OR
        (source = 'cancel' AND state = 'cancelled' AND sequence = 0 AND
         report_digest IS NULL AND command_id IS NOT NULL AND error_code = 'cancelled')
    )
);

CREATE INDEX cache_operation_target_results_attempt_idx
    ON cache_operation_target_results (scope_id, operation_id, node_id, attempt, target_ordinal);

CREATE FUNCTION validate_cache_operation_target_result_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    operation_state text;
    projection_state text;
    projection_attempt integer;
BEGIN
    SELECT operation.state, projection.state, projection.attempt
    INTO operation_state, projection_state, projection_attempt
    FROM cache_operations operation
    JOIN cache_operation_node_targets projection
      ON projection.operation_id = operation.id AND projection.scope_id = operation.scope_id
    WHERE operation.scope_id = NEW.scope_id AND operation.id = NEW.operation_id
      AND projection.node_id = NEW.node_id AND projection.target_ordinal = NEW.target_ordinal;
    IF NOT FOUND OR operation_state IN ('succeeded', 'partial_failed', 'failed', 'cancelled') THEN
        RAISE EXCEPTION 'cache operation support facts cannot be added after completion';
    END IF;
    IF NEW.source IN ('report', 'lease_expire') AND
       (projection_state <> 'running' OR projection_attempt <> NEW.attempt) THEN
        RAISE EXCEPTION 'cache operation result does not match running projection';
    END IF;
    IF NEW.source = 'cancel' AND
       (projection_state NOT IN ('queued', 'running') OR
        COALESCE(NEW.attempt, 0) <> projection_attempt) THEN
        RAISE EXCEPTION 'cache operation cancellation result does not match projection';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.id = NEW.audit_event_id AND event.scope_id = NEW.scope_id
          AND event.resource_type = 'cache_operation'
          AND event.resource_id = NEW.operation_id::text AND event.result = 'success'
          AND (NEW.source = 'cancel' OR event.payload->>'node_id' = NEW.node_id::text)
          AND event.action = CASE NEW.source
              WHEN 'report' THEN 'cache.operation.report'
              WHEN 'lease_expire' THEN 'cache.operation.lease_expire'
              ELSE 'cache.operation.cancel'
          END
          AND (NEW.source = 'cancel' OR event.payload->>'attempt' = NEW.attempt::text)
          AND (NEW.source <> 'report' OR event.payload->>'sequence' = NEW.sequence::text)
    ) THEN
        RAISE EXCEPTION 'cache operation result requires matching audit fact';
    END IF;
    IF NEW.source = 'cancel' AND NOT EXISTS (
        SELECT 1 FROM cache_operation_commands command
        JOIN audit_events event ON event.id = NEW.audit_event_id
        WHERE command.id = NEW.command_id AND command.scope_id = NEW.scope_id
          AND command.operation_id = NEW.operation_id AND command.command = 'cancel'
          AND command.completed_at IS NULL AND event.actor_user_id = command.actor_user_id
    ) THEN
        RAISE EXCEPTION 'cache operation cancellation result requires unfinished command';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operation_target_results_validate_insert
BEFORE INSERT ON cache_operation_target_results
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_target_result_insert();

CREATE FUNCTION protect_cache_operation_audit_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    operation_state text;
BEGIN
    IF NEW.action NOT IN ('cache.operation.create', 'cache.operation.claim',
        'cache.operation.report', 'cache.operation.lease_expire',
        'cache.operation.retry', 'cache.operation.cancel') THEN
        RETURN NEW;
    END IF;
    BEGIN
        SELECT state INTO operation_state
        FROM cache_operations
        WHERE scope_id = NEW.scope_id AND id = NEW.resource_id::uuid;
    EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'cache operation audit has invalid resource';
    END;
    IF NOT FOUND OR
       (NEW.action = 'cache.operation.create' AND (
           operation_state <> 'queued' OR EXISTS (
               SELECT 1 FROM audit_events event
               WHERE event.scope_id = NEW.scope_id AND event.action = NEW.action
                 AND event.resource_type = 'cache_operation'
                 AND event.resource_id = NEW.resource_id AND event.result = 'success'
           )
       )) OR
       (NEW.action = 'cache.operation.claim' AND (
           operation_state <> 'running' OR NOT EXISTS (
               SELECT 1 FROM cache_operation_node_attempts attempt
               WHERE attempt.scope_id = NEW.scope_id AND attempt.operation_id = NEW.resource_id::uuid
                 AND attempt.node_id::text = NEW.payload->>'node_id'
                 AND attempt.attempt::text = NEW.payload->>'attempt'
                 AND attempt.lease_id::text = NEW.payload->>'lease_id'
                 AND attempt.target_count::text = NEW.payload->>'target_count'
           ) OR EXISTS (
               SELECT 1 FROM audit_events event
               WHERE event.scope_id = NEW.scope_id AND event.action = NEW.action
                 AND event.resource_type = 'cache_operation'
                 AND event.resource_id = NEW.resource_id AND event.result = 'success'
                 AND event.payload->>'node_id' = NEW.payload->>'node_id'
                 AND event.payload->>'attempt' = NEW.payload->>'attempt'
                 AND event.payload->>'lease_id' = NEW.payload->>'lease_id'
                 AND event.payload->>'target_count' = NEW.payload->>'target_count'
           )
       )) OR
       (NEW.action IN ('cache.operation.report', 'cache.operation.lease_expire') AND (
           operation_state <> 'running' OR NOT EXISTS (
               SELECT 1 FROM cache_operation_node_attempts attempt
               WHERE attempt.scope_id = NEW.scope_id AND attempt.operation_id = NEW.resource_id::uuid
                 AND attempt.state = 'running'
                 AND attempt.node_id::text = NEW.payload->>'node_id'
                 AND attempt.attempt::text = NEW.payload->>'attempt'
           ) OR EXISTS (
               SELECT 1 FROM audit_events event
               WHERE event.scope_id = NEW.scope_id AND event.action = NEW.action
                 AND event.resource_type = 'cache_operation'
                 AND event.resource_id = NEW.resource_id AND event.result = 'success'
                 AND event.payload->>'node_id' = NEW.payload->>'node_id'
                 AND event.payload->>'attempt' = NEW.payload->>'attempt'
           )
       )) OR
       (NEW.action = 'cache.operation.retry' AND (
           operation_state <> 'queued' OR NOT EXISTS (
               SELECT 1 FROM cache_operation_commands command
               WHERE command.scope_id = NEW.scope_id AND command.operation_id = NEW.resource_id::uuid
                 AND command.command = 'retry' AND command.completed_at IS NULL
                 AND command.actor_user_id IS NOT DISTINCT FROM NEW.actor_user_id
                 AND command.id::text = NEW.payload->>'command_id'
           ) OR EXISTS (
               SELECT 1 FROM audit_events event
               WHERE event.scope_id = NEW.scope_id AND event.action = NEW.action
                 AND event.resource_type = 'cache_operation'
                 AND event.resource_id = NEW.resource_id AND event.result = 'success'
                 AND event.payload->>'command_id' = NEW.payload->>'command_id'
           )
       )) OR
       (NEW.action = 'cache.operation.cancel' AND (
           operation_state NOT IN ('queued', 'running') OR NOT EXISTS (
               SELECT 1 FROM cache_operation_commands command
               WHERE command.scope_id = NEW.scope_id AND command.operation_id = NEW.resource_id::uuid
                 AND command.command = 'cancel' AND command.completed_at IS NULL
                 AND command.actor_user_id IS NOT DISTINCT FROM NEW.actor_user_id
                 AND command.id::text = NEW.payload->>'command_id'
           ) OR EXISTS (
               SELECT 1 FROM audit_events event
               WHERE event.scope_id = NEW.scope_id AND event.action = NEW.action
                 AND event.resource_type = 'cache_operation'
                 AND event.resource_id = NEW.resource_id AND event.result = 'success'
                 AND event.payload->>'command_id' = NEW.payload->>'command_id'
           )
       )) THEN
        RAISE EXCEPTION 'cache operation terminal audit cannot be added after completion';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operation_audit_validate_insert
BEFORE INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_audit_insert();

CREATE FUNCTION protect_cache_policy_audit_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    policy_site_id uuid;
    policy_revision bigint;
BEGIN
    IF NEW.action <> 'cache_policy.publish' THEN
        RETURN NEW;
    END IF;
    BEGIN
        policy_site_id := NEW.resource_id::uuid;
        policy_revision := (NEW.payload->>'revision')::bigint;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
        RAISE EXCEPTION 'cache policy audit has invalid resource or revision';
    END;
    IF NEW.resource_type <> 'cache_policy' OR NEW.result <> 'success' OR
       NEW.actor_user_id IS NULL OR policy_revision IS NULL OR NOT EXISTS (
           SELECT 1 FROM cache_policy_revisions revision
           JOIN cache_policy_write_requests request
             ON request.scope_id = revision.scope_id AND request.site_id = revision.site_id
            AND request.actor_user_id = revision.created_by_user_id
            AND request.request_digest = revision.request_digest
            AND request.completed_at IS NULL AND request.response_revision IS NULL
           WHERE revision.scope_id = NEW.scope_id AND revision.site_id = policy_site_id
             AND revision.revision = policy_revision
             AND revision.created_by_user_id = NEW.actor_user_id
             AND revision.request_id = NEW.request_id
       ) OR EXISTS (
           SELECT 1 FROM cache_policy_write_requests request
           WHERE request.scope_id = NEW.scope_id AND request.site_id = policy_site_id
             AND request.response_revision = policy_revision AND request.completed_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'cache policy audit cannot be added without an unfinished matching write';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_policy_audit_validate_insert
BEFORE INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION protect_cache_policy_audit_insert();

CREATE FUNCTION validate_cache_policy_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_site_id uuid;
    checked_scope_id uuid;
    head cache_policy_heads%ROWTYPE;
    revision_count bigint;
    minimum_revision bigint;
    maximum_revision bigint;
    first_created_at timestamptz;
    current_created_at timestamptz;
BEGIN
    IF TG_TABLE_NAME = 'audit_events' THEN
        IF NEW.action <> 'cache_policy.publish' THEN
            RETURN NULL;
        END IF;
        BEGIN
            checked_site_id := NEW.resource_id::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'cache policy integrity violation: invalid audit resource';
        END;
        checked_scope_id := NEW.scope_id;
    ELSE
        checked_site_id := COALESCE(NEW.site_id, OLD.site_id);
        checked_scope_id := COALESCE(NEW.scope_id, OLD.scope_id);
    END IF;

    SELECT * INTO head FROM cache_policy_heads
    WHERE site_id = checked_site_id AND scope_id = checked_scope_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'cache policy integrity violation: policy head missing';
    END IF;

    SELECT count(*),min(revision),max(revision),
           min(created_at) FILTER (WHERE revision = 1),
           min(created_at) FILTER (WHERE revision = head.current_revision)
    INTO revision_count,minimum_revision,maximum_revision,first_created_at,current_created_at
    FROM cache_policy_revisions
    WHERE site_id = head.site_id AND scope_id = head.scope_id;
    IF revision_count <> head.current_revision OR minimum_revision <> 1 OR
       maximum_revision <> head.current_revision OR first_created_at IS DISTINCT FROM head.created_at OR
       current_created_at IS DISTINCT FROM head.updated_at THEN
        RAISE EXCEPTION 'cache policy integrity violation: policy head is not the latest contiguous revision';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_policy_revisions revision
        WHERE revision.site_id = head.site_id AND (
            revision.scope_id <> head.scope_id OR revision.tenant_id <> head.tenant_id OR
            1 <> (
                SELECT count(*) FROM cache_policy_write_requests request
                WHERE request.scope_id = revision.scope_id AND request.site_id = revision.site_id
                  AND request.actor_user_id = revision.created_by_user_id
                  AND request.request_digest = revision.request_digest
                  AND request.response_revision = revision.revision AND request.completed_at IS NOT NULL
            ) OR 1 <> (
                SELECT count(*) FROM audit_events event
                WHERE event.scope_id = revision.scope_id
                  AND event.actor_user_id = revision.created_by_user_id
                  AND event.action = 'cache_policy.publish'
                  AND event.resource_type = 'cache_policy'
                  AND event.resource_id = revision.site_id::text
                  AND event.request_id = revision.request_id AND event.result = 'success'
                  AND event.payload->>'revision' = revision.revision::text
            )
        )
    ) THEN
        RAISE EXCEPTION 'cache policy integrity violation: revision support facts missing or ambiguous';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cache_policy_heads_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_integrity();

CREATE CONSTRAINT TRIGGER cache_policy_revisions_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_integrity();

CREATE CONSTRAINT TRIGGER cache_policy_write_requests_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_integrity();

CREATE CONSTRAINT TRIGGER cache_policy_audit_integrity
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_integrity();

CREATE FUNCTION validate_cache_operation_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_operation_id uuid;
    operation_row cache_operations%ROWTYPE;
    actual_targets integer;
    actual_nodes integer;
    actual_items integer;
    actual_completed integer;
    actual_succeeded integer;
    actual_failed integer;
    actual_cancelled integer;
BEGIN
    IF TG_TABLE_NAME = 'audit_events' THEN
        IF NEW.action NOT LIKE 'cache.operation.%' THEN
            RETURN NULL;
        END IF;
        BEGIN
            checked_operation_id := NEW.resource_id::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'cache operation integrity violation: invalid audit resource';
        END;
    ELSIF TG_TABLE_NAME = 'cache_operations' THEN
        checked_operation_id := COALESCE(NEW.id, OLD.id);
    ELSE
        checked_operation_id := COALESCE(NEW.operation_id, OLD.operation_id);
    END IF;

    SELECT * INTO operation_row FROM cache_operations WHERE id = checked_operation_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*)::integer INTO actual_targets
    FROM cache_operation_targets WHERE operation_id = operation_row.id;
    SELECT count(*)::integer INTO actual_nodes
    FROM cache_operation_nodes WHERE operation_id = operation_row.id;
    SELECT count(*)::integer,
           count(*) FILTER (WHERE state IN ('succeeded', 'failed', 'cancelled'))::integer,
           count(*) FILTER (WHERE state = 'succeeded')::integer,
           count(*) FILTER (WHERE state = 'failed')::integer,
           count(*) FILTER (WHERE state = 'cancelled')::integer
    INTO actual_items, actual_completed, actual_succeeded, actual_failed, actual_cancelled
    FROM cache_operation_node_targets WHERE operation_id = operation_row.id;
    IF actual_targets <> operation_row.target_count OR actual_nodes <> operation_row.node_count OR
       actual_items <> operation_row.total_count OR
       ROW(actual_completed, actual_succeeded, actual_failed, actual_cancelled) IS DISTINCT FROM
       ROW(operation_row.completed_count, operation_row.succeeded_count,
           operation_row.failed_count, operation_row.cancelled_count) THEN
        RAISE EXCEPTION 'cache operation integrity violation: operation aggregate mismatch';
    END IF;
    IF 1 <> (
        SELECT count(*) FROM audit_events event
        WHERE event.scope_id = operation_row.scope_id
          AND event.action = 'cache.operation.create'
          AND event.resource_type = 'cache_operation'
          AND event.resource_id = operation_row.id::text AND event.result = 'success'
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: creation audit missing or ambiguous';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_target_results result
        LEFT JOIN cache_operation_node_attempts attempt
          ON attempt.scope_id = result.scope_id AND attempt.operation_id = result.operation_id
         AND attempt.node_id = result.node_id AND attempt.attempt = result.attempt
        LEFT JOIN cache_operation_commands command ON command.id = result.command_id
        LEFT JOIN audit_events event ON event.id = result.audit_event_id
        WHERE result.operation_id = operation_row.id AND (
            event.id IS NULL OR event.scope_id <> result.scope_id OR
            event.resource_type <> 'cache_operation' OR event.resource_id <> result.operation_id::text OR
            event.result <> 'success' OR
            (result.source <> 'cancel' AND event.payload->>'node_id' <> result.node_id::text) OR
            event.action <> CASE result.source
                WHEN 'report' THEN 'cache.operation.report'
                WHEN 'lease_expire' THEN 'cache.operation.lease_expire'
                ELSE 'cache.operation.cancel'
            END OR
            (result.source <> 'cancel' AND event.payload->>'attempt' <> result.attempt::text) OR
            (result.source = 'report' AND (
                attempt.state NOT IN ('succeeded', 'partial_failed', 'failed') OR
                attempt.report_sequence <> result.sequence OR
                attempt.report_digest IS DISTINCT FROM result.report_digest OR
                event.payload->>'sequence' <> result.sequence::text
            )) OR
            (result.source = 'lease_expire' AND attempt.state <> 'lease_expired') OR
            (result.source = 'cancel' AND (
                command.id IS NULL OR command.scope_id <> result.scope_id OR
                command.operation_id <> result.operation_id OR command.command <> 'cancel' OR
                command.completed_at IS NULL OR event.actor_user_id IS DISTINCT FROM command.actor_user_id OR
                event.payload->>'command_id' <> command.id::text
            ))
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: invalid result support fact';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_node_attempts attempt
        WHERE attempt.operation_id = operation_row.id AND 1 <> (
            SELECT count(*) FROM audit_events event
            WHERE event.scope_id = attempt.scope_id
              AND event.action = 'cache.operation.claim'
              AND event.resource_type = 'cache_operation'
              AND event.resource_id = attempt.operation_id::text AND event.result = 'success'
              AND event.payload->>'node_id' = attempt.node_id::text
              AND event.payload->>'attempt' = attempt.attempt::text
              AND event.payload->>'lease_id' = attempt.lease_id::text
              AND event.payload->>'target_count' = attempt.target_count::text
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: attempt claim audit missing or ambiguous';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_node_attempts attempt
        LEFT JOIN LATERAL (
            SELECT count(*)::integer AS result_count,
                   count(*) FILTER (WHERE result.state = 'succeeded')::integer AS succeeded_count,
                   count(*) FILTER (WHERE result.state = 'failed')::integer AS failed_count,
                   count(*) FILTER (WHERE result.state = 'cancelled')::integer AS cancelled_count,
                   count(DISTINCT result.audit_event_id)::integer AS audit_count,
                   count(DISTINCT result.command_id)::integer AS command_count
            FROM cache_operation_target_results result
            WHERE result.operation_id = attempt.operation_id AND result.node_id = attempt.node_id
              AND result.attempt = attempt.attempt
              AND result.source = CASE
                  WHEN attempt.state IN ('succeeded', 'partial_failed', 'failed') THEN 'report'
                  WHEN attempt.state = 'lease_expired' THEN 'lease_expire'
                  WHEN attempt.state = 'cancelled' THEN 'cancel'
                  ELSE 'report'
              END
        ) result_stats ON true
        WHERE attempt.operation_id = operation_row.id AND attempt.state <> 'running' AND (
            (attempt.state = 'succeeded' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.succeeded_count <> attempt.target_count OR result_stats.audit_count <> 1)) OR
            (attempt.state = 'failed' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.failed_count <> attempt.target_count OR result_stats.audit_count <> 1)) OR
            (attempt.state = 'partial_failed' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.succeeded_count = 0 OR result_stats.failed_count = 0 OR
              result_stats.succeeded_count + result_stats.failed_count <> attempt.target_count OR
              result_stats.audit_count <> 1)) OR
            (attempt.state = 'cancelled' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.cancelled_count <> attempt.target_count OR
              result_stats.audit_count <> 1 OR result_stats.command_count <> 1)) OR
            (attempt.state = 'lease_expired' AND (
                1 <> (
                    SELECT count(*) FROM audit_events event
                    WHERE event.scope_id = attempt.scope_id
                      AND event.action = 'cache.operation.lease_expire'
                      AND event.resource_type = 'cache_operation'
                      AND event.resource_id = attempt.operation_id::text AND event.result = 'success'
                      AND event.payload->>'node_id' = attempt.node_id::text
                      AND event.payload->>'attempt' = attempt.attempt::text
                ) OR
                (attempt.attempt < operation_row.max_attempts AND result_stats.result_count <> 0) OR
                (attempt.attempt = operation_row.max_attempts AND
                 (result_stats.result_count <> attempt.target_count OR
                  result_stats.failed_count <> attempt.target_count OR result_stats.audit_count <> 1))
            )))
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: attempt result mismatch';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        LEFT JOIN LATERAL (
            SELECT count(*)::integer AS total_count,
                   count(*) FILTER (WHERE projection.state IN ('succeeded','failed','cancelled'))::integer AS completed_count,
                   count(*) FILTER (WHERE projection.state = 'succeeded')::integer AS succeeded_count,
                   count(*) FILTER (WHERE projection.state = 'failed')::integer AS failed_count,
                   count(*) FILTER (WHERE projection.state = 'cancelled')::integer AS cancelled_count,
                   count(*) FILTER (WHERE projection.state = 'running')::integer AS running_count,
                   count(*) FILTER (
                       WHERE projection.state = 'running' AND projection.attempt = node.attempt
                   )::integer AS current_running_count,
                   count(*) FILTER (WHERE projection.state = 'queued')::integer AS queued_count
            FROM cache_operation_node_targets projection
            WHERE projection.operation_id = node.operation_id AND projection.node_id = node.node_id
        ) projection_stats ON true
        LEFT JOIN LATERAL (
            SELECT count(*)::integer AS attempt_count,
                   COALESCE(max(attempt.attempt), 0)::integer AS maximum_attempt,
                   count(*) FILTER (WHERE attempt.state = 'running')::integer AS running_count
            FROM cache_operation_node_attempts attempt
            WHERE attempt.operation_id = node.operation_id AND attempt.node_id = node.node_id
        ) attempt_stats ON true
        LEFT JOIN cache_operation_node_attempts running_attempt
          ON running_attempt.operation_id = node.operation_id
         AND running_attempt.node_id = node.node_id
         AND running_attempt.attempt = node.attempt AND running_attempt.state = 'running'
        WHERE node.operation_id = operation_row.id AND (
            ROW(node.total_count, node.completed_count, node.succeeded_count,
                node.failed_count, node.cancelled_count) IS DISTINCT FROM
            ROW(projection_stats.total_count, projection_stats.completed_count,
                projection_stats.succeeded_count, projection_stats.failed_count,
                projection_stats.cancelled_count) OR
            node.attempt <> attempt_stats.attempt_count OR
            node.attempt <> attempt_stats.maximum_attempt OR
            (node.state = 'running' AND
             (attempt_stats.running_count <> 1 OR projection_stats.running_count = 0 OR
              projection_stats.running_count <> projection_stats.current_running_count OR
              running_attempt.target_count IS DISTINCT FROM projection_stats.current_running_count OR
              running_attempt.lease_id IS DISTINCT FROM node.lease_id OR
              running_attempt.worker_id IS DISTINCT FROM node.lease_owner OR
              running_attempt.lease_expires_at IS DISTINCT FROM node.lease_expires_at)) OR
            (node.state <> 'running' AND attempt_stats.running_count <> 0) OR
            (node.state = 'queued' AND projection_stats.queued_count = 0) OR
            (node.state IN ('succeeded','partial_failed','failed','cancelled') AND
             projection_stats.completed_count <> projection_stats.total_count) OR
            (node.state = 'succeeded' AND projection_stats.succeeded_count <> projection_stats.total_count) OR
            (node.state = 'failed' AND projection_stats.failed_count <> projection_stats.total_count) OR
            (node.state = 'partial_failed' AND
             (projection_stats.failed_count = 0 OR
              projection_stats.failed_count = projection_stats.total_count OR
              projection_stats.cancelled_count <> 0)) OR
            (node.state = 'cancelled' AND projection_stats.cancelled_count = 0)
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: node aggregate mismatch';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_node_targets projection
        WHERE projection.operation_id = operation_row.id
          AND projection.state IN ('succeeded','failed','cancelled')
          AND NOT EXISTS (
              SELECT 1 FROM cache_operation_target_results result
              WHERE result.operation_id = projection.operation_id
                AND result.node_id = projection.node_id
                AND result.target_ordinal = projection.target_ordinal
                AND COALESCE(result.attempt, 0) = projection.attempt
                AND result.state = projection.state AND result.sequence = projection.sequence
                AND result.error_code IS NOT DISTINCT FROM projection.error_code
          )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: terminal projection has no result fact';
    END IF;

    IF operation_row.state IN ('succeeded','partial_failed','failed','cancelled') AND
       actual_completed <> actual_items THEN
        RAISE EXCEPTION 'cache operation integrity violation: terminal operation is incomplete';
    END IF;
    IF operation_row.state IN ('queued','running') AND actual_completed = actual_items THEN
        RAISE EXCEPTION 'cache operation integrity violation: completed projections require a terminal operation';
    END IF;
    IF operation_row.state = 'succeeded' AND
       (actual_succeeded <> actual_items OR actual_failed <> 0 OR actual_cancelled <> 0) THEN
        RAISE EXCEPTION 'cache operation integrity violation: succeeded aggregate mismatch';
    END IF;
    IF operation_row.state = 'failed' AND actual_failed <> actual_items THEN
        RAISE EXCEPTION 'cache operation integrity violation: failed aggregate mismatch';
    END IF;
    IF operation_row.state = 'partial_failed' AND
       (actual_failed = 0 OR actual_failed = actual_items OR actual_cancelled <> 0) THEN
        RAISE EXCEPTION 'cache operation integrity violation: partial failure aggregate mismatch';
    END IF;
    IF operation_row.state = 'cancelled' AND (
        actual_cancelled = 0 OR operation_row.cancel_requested_at IS NULL OR
        NOT EXISTS (
            SELECT 1 FROM cache_operation_commands command
            JOIN audit_events event
              ON event.scope_id = command.scope_id
             AND event.action = 'cache.operation.cancel'
             AND event.resource_type = 'cache_operation'
             AND event.resource_id = command.operation_id::text
             AND event.actor_user_id = command.actor_user_id AND event.result = 'success'
            WHERE command.scope_id = operation_row.scope_id
              AND command.operation_id = operation_row.id AND command.command = 'cancel'
              AND command.completed_at IS NOT NULL
              AND event.payload->>'command_id' = command.id::text
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: cancellation support missing';
    END IF;
    IF operation_row.state <> 'cancelled' AND actual_cancelled <> 0 THEN
        RAISE EXCEPTION 'cache operation integrity violation: unexpected cancelled projection';
    END IF;
    IF operation_row.state = 'queued' AND EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        WHERE node.operation_id = operation_row.id AND node.state = 'running'
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: queued operation has running node';
    END IF;
    IF operation_row.state = 'queued' AND NOT EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        WHERE node.operation_id = operation_row.id AND node.state = 'queued'
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: queued operation has no queued node';
    END IF;
    IF operation_row.state = 'running' AND NOT EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        WHERE node.operation_id = operation_row.id AND node.state IN ('queued','running')
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: running operation has no pending node';
    END IF;
    IF operation_row.state = 'queued' AND EXISTS (
        SELECT 1 FROM cache_operation_node_attempts attempt
        WHERE attempt.operation_id = operation_row.id
    ) AND NOT EXISTS (
        SELECT 1 FROM cache_operation_commands command
        JOIN audit_events event
          ON event.scope_id = command.scope_id
         AND event.actor_user_id = command.actor_user_id
         AND event.action = 'cache.operation.retry'
         AND event.resource_type = 'cache_operation'
         AND event.resource_id = command.operation_id::text AND event.result = 'success'
        WHERE command.scope_id = operation_row.scope_id
          AND command.operation_id = operation_row.id AND command.command = 'retry'
          AND command.completed_at IS NOT NULL
          AND event.payload->>'command_id' = command.id::text
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: retry support missing';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION prevent_cache_append_only_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cache control history is append-only';
END;
$$;

CREATE TRIGGER cache_policy_revisions_append_only
BEFORE UPDATE OR DELETE ON cache_policy_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_cache_append_only_mutation();

CREATE FUNCTION protect_cache_policy_head()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.current_revision <> 1 OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION 'invalid cache policy head transition';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' OR
       ROW(NEW.site_id,NEW.scope_id,NEW.tenant_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.site_id,OLD.scope_id,OLD.tenant_id,OLD.created_at) OR
       NEW.current_revision <> OLD.current_revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid cache policy head transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_policy_heads_protected
BEFORE INSERT OR UPDATE OR DELETE ON cache_policy_heads
FOR EACH ROW EXECUTE FUNCTION protect_cache_policy_head();

CREATE TRIGGER cache_operation_targets_append_only
BEFORE UPDATE OR DELETE ON cache_operation_targets
FOR EACH ROW EXECUTE FUNCTION prevent_cache_append_only_mutation();

CREATE TRIGGER cache_operation_target_results_append_only
BEFORE UPDATE OR DELETE ON cache_operation_target_results
FOR EACH ROW EXECUTE FUNCTION prevent_cache_append_only_mutation();

CREATE FUNCTION protect_cache_operation_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.state <> 'running' OR
       ROW(NEW.operation_id, NEW.scope_id, NEW.node_id, NEW.attempt, NEW.lease_id,
           NEW.worker_id, NEW.target_count, NEW.started_at, NEW.lease_expires_at)
       IS DISTINCT FROM
       ROW(OLD.operation_id, OLD.scope_id, OLD.node_id, OLD.attempt, OLD.lease_id,
           OLD.worker_id, OLD.target_count, OLD.started_at, OLD.lease_expires_at) OR
       NEW.state = 'running' OR NEW.completed_at IS NULL OR EXISTS (
           SELECT 1 FROM cache_operations operation
           WHERE operation.id = OLD.operation_id
             AND operation.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled')
       ) THEN
        RAISE EXCEPTION 'invalid cache operation attempt transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operation_node_attempts_protected
BEFORE UPDATE OR DELETE ON cache_operation_node_attempts
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_attempt();

CREATE FUNCTION protect_cache_operation_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.scope_id, NEW.tenant_id, NEW.site_id, NEW.action, NEW.target_type,
           NEW.idempotency_key, NEW.request_digest, NEW.request_id, NEW.actor_user_id,
           NEW.max_attempts, NEW.target_count, NEW.node_count, NEW.total_count, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.scope_id, OLD.tenant_id, OLD.site_id, OLD.action, OLD.target_type,
           OLD.idempotency_key, OLD.request_digest, OLD.request_id, OLD.actor_user_id,
           OLD.max_attempts, OLD.target_count, OLD.node_count, OLD.total_count, OLD.created_at) OR
       NOT (
           (NEW.state = OLD.state AND OLD.state IN ('queued', 'running')) OR
           (OLD.state = 'queued' AND NEW.state IN ('running', 'cancelled')) OR
           (OLD.state = 'running' AND NEW.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled')) OR
           (OLD.state IN ('partial_failed', 'failed') AND NEW.state = 'queued' AND EXISTS (
               SELECT 1 FROM cache_operation_commands command
               WHERE command.scope_id = OLD.scope_id AND command.operation_id = OLD.id
                 AND command.command = 'retry' AND command.completed_at IS NULL
           ))
       ) THEN
        RAISE EXCEPTION 'invalid cache operation transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operations_protected
BEFORE UPDATE OR DELETE ON cache_operations
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_transition();

CREATE FUNCTION protect_cache_operation_node_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.operation_id, NEW.scope_id, NEW.node_id, NEW.total_count, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.operation_id, OLD.scope_id, OLD.node_id, OLD.total_count, OLD.created_at) OR
       NOT (
           (OLD.state = 'queued' AND NEW.state = 'running' AND NEW.attempt = OLD.attempt + 1) OR
           (OLD.state = 'queued' AND NEW.state = 'cancelled' AND NEW.attempt = OLD.attempt) OR
           (OLD.state = 'running' AND NEW.state IN ('succeeded','partial_failed','failed','cancelled')
            AND NEW.attempt = OLD.attempt) OR
           (OLD.state = 'running' AND NEW.state = 'queued' AND NEW.attempt = OLD.attempt
            AND EXISTS (
                SELECT 1 FROM cache_operation_node_attempts attempt
                WHERE attempt.operation_id = OLD.operation_id AND attempt.node_id = OLD.node_id
                  AND attempt.attempt = OLD.attempt AND attempt.state = 'lease_expired'
            )) OR
           (OLD.state IN ('partial_failed','failed') AND NEW.state = 'queued'
            AND NEW.attempt = OLD.attempt AND EXISTS (
                SELECT 1 FROM cache_operation_commands command
                WHERE command.scope_id = OLD.scope_id AND command.operation_id = OLD.operation_id
                  AND command.command = 'retry' AND command.completed_at IS NULL
            ))
       ) THEN
        RAISE EXCEPTION 'invalid cache operation node transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operation_nodes_protected
BEFORE UPDATE ON cache_operation_nodes
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_node_transition();

CREATE FUNCTION protect_cache_operation_target_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(NEW.operation_id, NEW.scope_id, NEW.node_id, NEW.target_ordinal)
       IS DISTINCT FROM ROW(OLD.operation_id, OLD.scope_id, OLD.node_id, OLD.target_ordinal) OR
       NOT (
           (OLD.state = 'queued' AND NEW.state = 'running' AND EXISTS (
               SELECT 1 FROM cache_operation_nodes node
               WHERE node.operation_id = OLD.operation_id AND node.node_id = OLD.node_id
                 AND node.state = 'queued' AND node.attempt + 1 = NEW.attempt
           )) OR
           (OLD.state = 'running' AND NEW.state = 'queued' AND NEW.attempt = 0
            AND EXISTS (
                SELECT 1 FROM cache_operation_node_attempts attempt
                WHERE attempt.operation_id = OLD.operation_id AND attempt.node_id = OLD.node_id
                  AND attempt.attempt = OLD.attempt AND attempt.state = 'lease_expired'
            )) OR
           (OLD.state IN ('queued','running') AND NEW.state = 'cancelled'
            AND NEW.attempt = OLD.attempt) OR
           (OLD.state = 'running' AND NEW.state IN ('succeeded','failed')
            AND NEW.attempt = OLD.attempt) OR
           (OLD.state = 'failed' AND NEW.state = 'queued' AND NEW.attempt = 0
            AND EXISTS (
                SELECT 1 FROM cache_operation_commands command
                WHERE command.scope_id = OLD.scope_id AND command.operation_id = OLD.operation_id
                  AND command.command = 'retry' AND command.completed_at IS NULL
            ))
       ) THEN
        RAISE EXCEPTION 'invalid cache operation target transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operation_node_targets_protected
BEFORE UPDATE ON cache_operation_node_targets
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_target_transition();

CREATE FUNCTION protect_cache_policy_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.response_revision IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
            RAISE EXCEPTION 'cache policy write requests must be inserted unfinished';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' OR OLD.completed_at IS NOT NULL OR
       ROW(NEW.id, NEW.scope_id, NEW.actor_user_id, NEW.site_id, NEW.idempotency_key,
           NEW.request_digest, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.scope_id, OLD.actor_user_id, OLD.site_id, OLD.idempotency_key,
           OLD.request_digest, OLD.created_at) OR
       NEW.response_revision IS NULL OR NEW.completed_at IS NULL OR NOT EXISTS (
           SELECT 1 FROM cache_policy_revisions revision
           JOIN audit_events event
             ON event.scope_id = revision.scope_id
            AND event.actor_user_id = revision.created_by_user_id
            AND event.action = 'cache_policy.publish'
            AND event.resource_type = 'cache_policy'
            AND event.resource_id = revision.site_id::text
            AND event.request_id = revision.request_id
            AND event.result = 'success'
            AND event.payload->>'revision' = revision.revision::text
           WHERE revision.scope_id = NEW.scope_id AND revision.site_id = NEW.site_id
             AND revision.revision = NEW.response_revision
             AND revision.created_by_user_id = NEW.actor_user_id
             AND revision.request_digest = NEW.request_digest
       ) THEN
        RAISE EXCEPTION 'invalid cache policy write request completion';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_policy_write_requests_protected
BEFORE INSERT OR UPDATE OR DELETE ON cache_policy_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_cache_policy_write_request();

CREATE FUNCTION protect_cache_operation_command()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command_operation_state text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT state INTO command_operation_state
        FROM cache_operations
        WHERE id = NEW.operation_id AND scope_id = NEW.scope_id
        FOR UPDATE;
        IF NOT FOUND OR NEW.completed_at IS NOT NULL OR NOT (
            (NEW.command = 'cancel' AND command_operation_state IN ('queued', 'running')) OR
            (NEW.command = 'retry' AND command_operation_state IN ('partial_failed', 'failed'))
        ) THEN
            RAISE EXCEPTION 'cache operation commands must be inserted unfinished';
        END IF;
        IF (NEW.command = 'cancel' AND EXISTS (
                SELECT 1 FROM cache_operation_commands command
                WHERE command.scope_id = NEW.scope_id AND command.operation_id = NEW.operation_id
                  AND command.command = 'cancel'
            )) OR (NEW.command = 'retry' AND
                (SELECT count(*) FROM cache_operation_commands command
                 WHERE command.scope_id = NEW.scope_id AND command.operation_id = NEW.operation_id
                   AND command.command = 'retry') >=
                (SELECT COALESCE(max(node.attempt), 0) FROM cache_operation_nodes node
                 WHERE node.scope_id = NEW.scope_id AND node.operation_id = NEW.operation_id)
            ) THEN
            RAISE EXCEPTION 'cache operation command already exists for current effect';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' OR OLD.completed_at IS NOT NULL OR
       ROW(NEW.id, NEW.operation_id, NEW.scope_id, NEW.command, NEW.idempotency_key,
           NEW.request_digest, NEW.actor_user_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.operation_id, OLD.scope_id, OLD.command, OLD.idempotency_key,
           OLD.request_digest, OLD.actor_user_id, OLD.created_at) OR
       NEW.completed_at IS NULL OR EXISTS (
           SELECT 1 FROM cache_operations operation
           WHERE operation.id = OLD.operation_id
             AND operation.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled')
       ) OR NOT EXISTS (
           SELECT 1 FROM audit_events event
           WHERE event.scope_id = NEW.scope_id
             AND event.actor_user_id = NEW.actor_user_id
             AND event.action = 'cache.operation.' || NEW.command
             AND event.resource_type = 'cache_operation'
             AND event.resource_id = NEW.operation_id::text
             AND event.result = 'success'
             AND event.payload->>'command_id' = NEW.id::text
       ) THEN
        RAISE EXCEPTION 'invalid cache operation command completion';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_operation_commands_protected
BEFORE INSERT OR UPDATE OR DELETE ON cache_operation_commands
FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_command();

CREATE FUNCTION validate_cache_idempotency_completion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    completed timestamptz;
BEGIN
    IF TG_TABLE_NAME = 'cache_policy_write_requests' THEN
        SELECT completed_at INTO completed FROM cache_policy_write_requests WHERE id = NEW.id;
    ELSE
        SELECT completed_at INTO completed FROM cache_operation_commands WHERE id = NEW.id;
    END IF;
    IF FOUND AND completed IS NULL THEN
        RAISE EXCEPTION 'cache control idempotency fact must complete atomically';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cache_policy_write_requests_complete
AFTER INSERT OR UPDATE ON cache_policy_write_requests
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_idempotency_completion();

CREATE CONSTRAINT TRIGGER cache_operation_commands_complete
AFTER INSERT OR UPDATE ON cache_operation_commands
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_idempotency_completion();

CREATE FUNCTION prevent_cache_projection_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cache operation projections cannot be deleted';
END;
$$;

CREATE TRIGGER cache_operation_nodes_no_delete
BEFORE DELETE ON cache_operation_nodes
FOR EACH ROW EXECUTE FUNCTION prevent_cache_projection_delete();

CREATE TRIGGER cache_operation_node_targets_no_delete
BEFORE DELETE ON cache_operation_node_targets
FOR EACH ROW EXECUTE FUNCTION prevent_cache_projection_delete();

CREATE FUNCTION prevent_cache_control_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cache control tables cannot be truncated';
END;
$$;

CREATE TRIGGER cache_policy_heads_no_truncate
BEFORE TRUNCATE ON cache_policy_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_policy_revisions_no_truncate
BEFORE TRUNCATE ON cache_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_policy_write_requests_no_truncate
BEFORE TRUNCATE ON cache_policy_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operations_no_truncate
BEFORE TRUNCATE ON cache_operations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_commands_no_truncate
BEFORE TRUNCATE ON cache_operation_commands
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_targets_no_truncate
BEFORE TRUNCATE ON cache_operation_targets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_nodes_no_truncate
BEFORE TRUNCATE ON cache_operation_nodes
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_node_targets_no_truncate
BEFORE TRUNCATE ON cache_operation_node_targets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_node_attempts_no_truncate
BEFORE TRUNCATE ON cache_operation_node_attempts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_target_results_no_truncate
BEFORE TRUNCATE ON cache_operation_target_results
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();
CREATE TRIGGER cache_operation_audit_no_truncate
BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_control_truncate();

CREATE CONSTRAINT TRIGGER cache_operations_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_operations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_nodes_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_operation_nodes
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_node_targets_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_operation_node_targets
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_node_attempts_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_operation_node_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_target_results_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_operation_target_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_commands_integrity
AFTER INSERT OR UPDATE OR DELETE ON cache_operation_commands
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_audit_integrity
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.action LIKE 'cache.operation.%')
EXECUTE FUNCTION validate_cache_operation_integrity();
