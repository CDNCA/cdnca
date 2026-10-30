CREATE TABLE background_jobs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9._-]{0,127}$'),
    subject text NOT NULL CHECK (
        char_length(subject) BETWEEN 1 AND 512 AND
        subject = btrim(subject) AND
        subject !~ '[[:cntrl:]]' AND
        position(U&'\2028' in subject) = 0 AND position(U&'\2029' in subject) = 0
    ),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id = btrim(request_id) AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in request_id) = 0 AND position(U&'\2029' in request_id) = 0
    ),
    trace_id text NOT NULL DEFAULT '' CHECK (
        char_length(trace_id) <= 512 AND trace_id = btrim(trace_id) AND
        trace_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in trace_id) = 0 AND position(U&'\2029' in trace_id) = 0
    ),
    state text NOT NULL CHECK (state IN (
        'queued', 'running', 'succeeded', 'partial_failed', 'failed', 'cancelled'
    )),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 1001),
    cancel_requested_at timestamptz,
    lease_id uuid,
    lease_owner text,
    lease_expires_at timestamptz,
    claimable_at timestamptz,
    total_count integer NOT NULL CHECK (total_count > 0),
    completed_count integer NOT NULL DEFAULT 0 CHECK (completed_count >= 0),
    succeeded_count integer NOT NULL DEFAULT 0 CHECK (succeeded_count >= 0),
    failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
    cancelled_count integer NOT NULL DEFAULT 0 CHECK (cancelled_count >= 0),
    last_error_code text CHECK (
        last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    updated_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (tenant_id, idempotency_key),
    UNIQUE (tenant_id, id),
    CHECK (attempt <= max_attempts),
    CHECK (
        isfinite(created_at) AND isfinite(updated_at) AND updated_at >= created_at AND
        (claimable_at IS NULL OR isfinite(claimable_at)) AND
        (cancel_requested_at IS NULL OR isfinite(cancel_requested_at)) AND
        (lease_expires_at IS NULL OR isfinite(lease_expires_at)) AND
        (started_at IS NULL OR isfinite(started_at)) AND
        (completed_at IS NULL OR isfinite(completed_at))
    ),
    CHECK (completed_count = succeeded_count + failed_count + cancelled_count),
    CHECK (completed_count <= total_count),
    CHECK (
        (state = 'queued' AND lease_id IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL AND
         claimable_at IS NOT NULL AND completed_at IS NULL) OR
        (state = 'running' AND attempt > 0 AND lease_id IS NOT NULL AND lease_owner IS NOT NULL AND
         lease_expires_at IS NOT NULL AND claimable_at = lease_expires_at AND completed_at IS NULL) OR
        (state IN ('succeeded', 'partial_failed', 'failed', 'cancelled') AND
         lease_id IS NULL AND lease_owner IS NULL AND lease_expires_at IS NULL AND
         claimable_at IS NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX background_jobs_claim_idx
    ON background_jobs (tenant_id, kind, claimable_at, created_at, id)
    WHERE state IN ('queued', 'running');
CREATE INDEX background_jobs_tenant_created_idx
    ON background_jobs (tenant_id, created_at DESC, id DESC);

CREATE TABLE background_job_items (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal > 0),
    item_id text NOT NULL CHECK (
        char_length(item_id) BETWEEN 1 AND 256 AND item_id = btrim(item_id) AND
        item_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in item_id) = 0 AND position(U&'\2029' in item_id) = 0
    ),
    node_id uuid,
    state text NOT NULL CHECK (state IN ('pending', 'succeeded', 'failed', 'cancelled')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'),
    completed_at timestamptz,
    PRIMARY KEY (job_id, item_id),
    UNIQUE (job_id, ordinal),
    UNIQUE (tenant_id, job_id, item_id),
    FOREIGN KEY (tenant_id, job_id) REFERENCES background_jobs(tenant_id, id) ON DELETE RESTRICT,
    CHECK (
        (state = 'pending' AND sequence = 0 AND error_code IS NULL AND completed_at IS NULL) OR
        (state = 'succeeded' AND attempt > 0 AND sequence > 0 AND error_code IS NULL AND completed_at IS NOT NULL) OR
        (state = 'failed' AND attempt > 0 AND error_code IS NOT NULL AND completed_at IS NOT NULL) OR
        (state = 'cancelled' AND error_code = 'cancelled' AND completed_at IS NOT NULL)
    ),
    CHECK (completed_at IS NULL OR isfinite(completed_at))
);

CREATE INDEX background_job_items_node_idx
    ON background_job_items (tenant_id, node_id, job_id) WHERE node_id IS NOT NULL;

CREATE TABLE background_job_attempts (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    lease_id uuid NOT NULL UNIQUE,
    worker_id text NOT NULL CHECK (
        char_length(worker_id) BETWEEN 1 AND 128 AND worker_id = btrim(worker_id) AND
        worker_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in worker_id) = 0 AND position(U&'\2029' in worker_id) = 0
    ),
    state text NOT NULL CHECK (state IN (
        'running', 'succeeded', 'partial_failed', 'failed', 'cancelled', 'lease_expired'
    )),
    started_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'),
    PRIMARY KEY (job_id, attempt),
    UNIQUE (tenant_id, job_id, attempt),
    FOREIGN KEY (tenant_id, job_id) REFERENCES background_jobs(tenant_id, id) ON DELETE RESTRICT,
    CHECK (
        (state = 'running' AND completed_at IS NULL AND error_code IS NULL) OR
        (state <> 'running' AND completed_at IS NOT NULL)
    ),
    CHECK (
        isfinite(started_at) AND isfinite(last_heartbeat_at) AND isfinite(lease_expires_at) AND
        started_at <= last_heartbeat_at AND last_heartbeat_at < lease_expires_at AND
        (completed_at IS NULL OR (isfinite(completed_at) AND completed_at >= last_heartbeat_at))
    )
);

CREATE TABLE background_job_results (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    item_id text NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    state text NOT NULL CHECK (state IN ('succeeded', 'failed')),
    error_code text CHECK (error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'),
    source text NOT NULL CHECK (source IN ('worker', 'system')),
    reported_at timestamptz NOT NULL,
    UNIQUE (job_id, item_id, attempt),
    FOREIGN KEY (tenant_id, job_id, item_id)
        REFERENCES background_job_items(tenant_id, job_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, job_id, attempt)
        REFERENCES background_job_attempts(tenant_id, job_id, attempt) ON DELETE RESTRICT,
    CHECK (
        (state = 'failed' AND error_code IS NOT NULL) OR
        (state = 'succeeded' AND error_code IS NULL)
    ),
    CHECK ((source = 'worker' AND sequence > 0) OR (source = 'system' AND sequence = 0)),
    CHECK (isfinite(reported_at))
);

CREATE INDEX background_job_results_job_item_idx
    ON background_job_results (tenant_id, job_id, item_id, attempt);

CREATE FUNCTION validate_background_job_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state <> 'queued' OR NEW.attempt <> 0 OR
       NEW.completed_count <> 0 OR NEW.succeeded_count <> 0 OR
       NEW.failed_count <> 0 OR NEW.cancelled_count <> 0 OR
       NEW.cancel_requested_at IS NOT NULL OR NEW.lease_id IS NOT NULL OR
       NEW.lease_owner IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
       NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR
       NEW.last_error_code IS NOT NULL OR NEW.claimable_at IS NULL OR
       NEW.updated_at IS DISTINCT FROM NEW.created_at OR
       NEW.claimable_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'background job must be inserted in strict queued initial state';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_jobs_insert_validated
BEFORE INSERT ON background_jobs
FOR EACH ROW EXECUTE FUNCTION validate_background_job_insert();

CREATE FUNCTION validate_background_job_item_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent_state text;
    parent_attempt integer;
    parent_total integer;
BEGIN
    IF NEW.state <> 'pending' OR NEW.attempt <> 0 OR NEW.sequence <> 0 OR
       NEW.error_code IS NOT NULL OR NEW.completed_at IS NOT NULL THEN
        RAISE EXCEPTION 'background job item must be inserted pending';
    END IF;
    SELECT state, attempt, total_count
    INTO parent_state, parent_attempt, parent_total
    FROM background_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF NOT FOUND OR parent_state <> 'queued' OR parent_attempt <> 0 OR NEW.ordinal > parent_total THEN
        RAISE EXCEPTION 'background job item must belong to initial queued job';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_items_insert_validated
BEFORE INSERT ON background_job_items
FOR EACH ROW EXECUTE FUNCTION validate_background_job_item_insert();

CREATE FUNCTION validate_background_job_attempt_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent background_jobs%ROWTYPE;
    running_attempts integer;
BEGIN
    IF NEW.state <> 'running' OR NEW.completed_at IS NOT NULL OR NEW.error_code IS NOT NULL OR
       NEW.last_heartbeat_at IS DISTINCT FROM NEW.started_at OR
       NEW.lease_expires_at <= NEW.started_at THEN
        RAISE EXCEPTION 'background job attempt must be inserted running with a forward lease';
    END IF;
    SELECT * INTO parent FROM background_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF NOT FOUND OR parent.state <> 'running' OR parent.attempt <> NEW.attempt OR
       parent.lease_id IS DISTINCT FROM NEW.lease_id OR
       parent.lease_owner IS DISTINCT FROM NEW.worker_id OR
       parent.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at OR
       parent.claimable_at IS DISTINCT FROM NEW.lease_expires_at OR
       parent.updated_at IS DISTINCT FROM NEW.started_at OR
       NEW.started_at < parent.created_at THEN
        RAISE EXCEPTION 'background job attempt does not match current claim';
    END IF;
    SELECT count(*) INTO running_attempts
    FROM background_job_attempts WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id AND state='running';
    IF running_attempts <> 0 THEN
        RAISE EXCEPTION 'background job already has a running attempt';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_attempts_insert_validated
BEFORE INSERT ON background_job_attempts
FOR EACH ROW EXECUTE FUNCTION validate_background_job_attempt_insert();

CREATE FUNCTION validate_background_job_result_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent background_jobs%ROWTYPE;
    item background_job_items%ROWTYPE;
    current_attempt background_job_attempts%ROWTYPE;
BEGIN
    SELECT * INTO parent FROM background_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'background job result parent is missing';
    END IF;
    SELECT * INTO item FROM background_job_items
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id AND item_id=NEW.item_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'background job result item is missing';
    END IF;
    SELECT * INTO current_attempt FROM background_job_attempts
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id AND attempt=NEW.attempt;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'background job result attempt is missing';
    END IF;
    IF parent.state <> 'running' OR parent.attempt <> NEW.attempt OR
       item.state <> 'pending' OR current_attempt.state <> 'running' OR
       current_attempt.lease_id IS DISTINCT FROM parent.lease_id OR
       current_attempt.worker_id IS DISTINCT FROM parent.lease_owner OR
       current_attempt.lease_expires_at IS DISTINCT FROM parent.lease_expires_at OR
       NEW.reported_at < current_attempt.started_at OR
       NEW.reported_at > current_attempt.lease_expires_at THEN
        RAISE EXCEPTION 'background job result does not match live claim';
    END IF;
    IF NEW.source = 'worker' THEN
        IF NEW.reported_at >= current_attempt.lease_expires_at THEN
            RAISE EXCEPTION 'worker result lease has expired';
        END IF;
    ELSIF NEW.state <> 'failed' OR NEW.sequence <> 0 OR
          NEW.error_code <> 'retries_exhausted' OR
          parent.attempt <> parent.max_attempts OR
          NEW.reported_at IS DISTINCT FROM current_attempt.lease_expires_at THEN
        RAISE EXCEPTION 'system result is not an exact exhausted lease result';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_results_insert_validated
BEFORE INSERT ON background_job_results
FOR EACH ROW EXECUTE FUNCTION validate_background_job_result_insert();

CREATE FUNCTION protect_background_job()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    retrying boolean;
BEGIN
    IF ROW(
        NEW.id, NEW.tenant_id, NEW.kind, NEW.subject, NEW.idempotency_key,
        NEW.request_digest, NEW.request_id, NEW.trace_id, NEW.max_attempts,
        NEW.total_count, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.tenant_id, OLD.kind, OLD.subject, OLD.idempotency_key,
        OLD.request_digest, OLD.request_id, OLD.trace_id, OLD.max_attempts,
        OLD.total_count, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'background job creation facts are immutable';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'background job updated time cannot move backwards';
    END IF;
    IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
        RAISE EXCEPTION 'background job started time is immutable once set';
    END IF;
    IF OLD.started_at IS NULL AND NEW.started_at IS NOT NULL AND NEW.started_at < OLD.created_at THEN
        RAISE EXCEPTION 'background job started time cannot predate creation';
    END IF;
    IF NEW.completed_at IS NOT NULL AND
       NEW.completed_at < COALESCE(NEW.started_at, OLD.created_at) THEN
        RAISE EXCEPTION 'background job completed time cannot predate start';
    END IF;
    IF OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT NULL AND
       NEW.completed_at < OLD.completed_at THEN
        RAISE EXCEPTION 'background job completed time cannot move backwards';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL AND
       NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at THEN
        RAISE EXCEPTION 'background job cancellation request is immutable once set';
    END IF;
    IF OLD.cancel_requested_at IS NULL AND NEW.cancel_requested_at IS NOT NULL AND
       NEW.cancel_requested_at < OLD.created_at THEN
        RAISE EXCEPTION 'background job cancellation cannot predate creation';
    END IF;

    retrying := NEW.state = 'queued' AND OLD.state IN ('running', 'failed', 'partial_failed');
    IF NEW.succeeded_count < OLD.succeeded_count OR NEW.cancelled_count < OLD.cancelled_count OR
       (NOT retrying AND
        (NEW.completed_count < OLD.completed_count OR NEW.failed_count < OLD.failed_count)) THEN
        RAISE EXCEPTION 'background job progress cannot move backwards outside retry';
    END IF;

    IF OLD.state = 'queued' THEN
        IF NEW.state = 'running' THEN
            IF NEW.attempt <> OLD.attempt + 1 OR NEW.attempt > OLD.max_attempts THEN
                RAISE EXCEPTION 'background job claim attempt is invalid';
            END IF;
        ELSIF NEW.state = 'cancelled' THEN
            IF NEW.attempt <> OLD.attempt THEN
                RAISE EXCEPTION 'background job cancellation changed attempt';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid background job transition from queued to %', NEW.state;
        END IF;
    ELSIF OLD.state = 'running' THEN
        IF NEW.state = 'running' OR NEW.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled') THEN
            IF NEW.attempt <> OLD.attempt THEN
                RAISE EXCEPTION 'background job running attempt changed';
            END IF;
        ELSIF NEW.state = 'queued' THEN
            IF NEW.attempt <> OLD.attempt OR OLD.attempt >= OLD.max_attempts OR
               OLD.claimable_at > NEW.updated_at THEN
                RAISE EXCEPTION 'background job lease retry is invalid';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid background job transition from running to %', NEW.state;
        END IF;
    ELSIF OLD.state IN ('failed', 'partial_failed') THEN
        IF NEW.state <> 'queued' OR NEW.attempt <> OLD.attempt OR OLD.attempt >= OLD.max_attempts THEN
            RAISE EXCEPTION 'background job retry is invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'terminal background job is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_jobs_protected
BEFORE UPDATE ON background_jobs
FOR EACH ROW EXECUTE FUNCTION protect_background_job();

CREATE FUNCTION protect_background_job_item()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent background_jobs%ROWTYPE;
    matching_result boolean;
BEGIN
    IF ROW(NEW.tenant_id, NEW.job_id, NEW.ordinal, NEW.item_id, NEW.node_id)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.job_id, OLD.ordinal, OLD.item_id, OLD.node_id) THEN
        RAISE EXCEPTION 'background job item creation facts are immutable';
    END IF;

    SELECT * INTO parent FROM background_jobs WHERE tenant_id=OLD.tenant_id AND id=OLD.job_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'background job item parent is missing';
    END IF;

    IF OLD.state <> 'pending' THEN
        IF OLD.state = 'failed' AND NEW.state = 'pending' AND NEW.attempt = 0 AND
           NEW.sequence = 0 AND NEW.error_code IS NULL AND NEW.completed_at IS NULL AND
           parent.state = 'queued' AND parent.attempt = OLD.attempt AND
           parent.attempt < parent.max_attempts THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'terminal background job item is immutable';
    END IF;
    IF NEW.state NOT IN ('succeeded', 'failed', 'cancelled') THEN
        RAISE EXCEPTION 'background job item must transition from pending to terminal';
    END IF;
    IF NEW.attempt < OLD.attempt OR NEW.sequence < OLD.sequence THEN
        RAISE EXCEPTION 'background job item attempt or sequence cannot move backwards';
    END IF;
    IF NEW.completed_at IS NULL OR
       NEW.completed_at < COALESCE(parent.started_at, parent.created_at) THEN
        RAISE EXCEPTION 'background job item completed time cannot move backwards';
    END IF;
    IF NEW.state = 'cancelled' THEN
        IF parent.state <> 'cancelled' OR parent.attempt <> NEW.attempt OR
           parent.cancel_requested_at IS DISTINCT FROM NEW.completed_at OR
           NEW.sequence <> 0 OR NEW.error_code <> 'cancelled' THEN
            RAISE EXCEPTION 'cancelled item does not match parent cancellation';
        END IF;
        RETURN NEW;
    END IF;
    IF parent.state NOT IN ('running', 'succeeded', 'partial_failed', 'failed') OR
       parent.attempt <> NEW.attempt THEN
        RAISE EXCEPTION 'background job item transition does not match current attempt';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM background_job_results result
        WHERE result.tenant_id=NEW.tenant_id AND result.job_id=NEW.job_id AND
              result.item_id=NEW.item_id AND result.attempt=NEW.attempt AND
              result.sequence=NEW.sequence AND result.state=NEW.state AND
              result.error_code IS NOT DISTINCT FROM NEW.error_code AND
              result.reported_at=NEW.completed_at
    ) INTO matching_result;
    IF NOT matching_result THEN
        RAISE EXCEPTION 'terminal background job item has no exact immutable result';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_items_protected
BEFORE UPDATE ON background_job_items
FOR EACH ROW EXECUTE FUNCTION protect_background_job_item();

CREATE FUNCTION protect_background_job_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent background_jobs%ROWTYPE;
BEGIN
    IF ROW(NEW.tenant_id, NEW.job_id, NEW.attempt, NEW.lease_id, NEW.worker_id, NEW.started_at)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.job_id, OLD.attempt, OLD.lease_id, OLD.worker_id, OLD.started_at) THEN
        RAISE EXCEPTION 'background job attempt identity is immutable';
    END IF;
    IF OLD.state <> 'running' THEN
        RAISE EXCEPTION 'completed background job attempt is immutable';
    END IF;
    IF NEW.last_heartbeat_at < OLD.last_heartbeat_at OR NEW.lease_expires_at < OLD.lease_expires_at THEN
        RAISE EXCEPTION 'background job attempt lease cannot move backwards';
    END IF;
    SELECT * INTO parent FROM background_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF NOT FOUND OR parent.attempt <> NEW.attempt THEN
        RAISE EXCEPTION 'background job attempt is not current';
    END IF;
    IF NEW.state = 'running' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.error_code IS NOT NULL OR
           parent.state <> 'running' OR parent.lease_id IS DISTINCT FROM NEW.lease_id OR
           parent.lease_owner IS DISTINCT FROM NEW.worker_id OR
           parent.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at OR
           parent.updated_at IS DISTINCT FROM NEW.last_heartbeat_at THEN
            RAISE EXCEPTION 'background job heartbeat does not match current claim';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.last_heartbeat_at IS DISTINCT FROM OLD.last_heartbeat_at OR
       NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at OR
       NEW.completed_at IS NULL OR NEW.completed_at < NEW.last_heartbeat_at THEN
        RAISE EXCEPTION 'background job attempt completion shape is invalid';
    END IF;
    IF (NEW.state = 'succeeded' AND NEW.error_code IS NOT NULL) OR
       (NEW.state = 'partial_failed' AND NEW.error_code <> 'item_failed') OR
       (NEW.state = 'failed' AND NEW.error_code <> 'all_items_failed') OR
       (NEW.state = 'cancelled' AND NEW.error_code <> 'cancelled') OR
       (NEW.state = 'lease_expired' AND NEW.error_code <> 'lease_expired') THEN
        RAISE EXCEPTION 'background job attempt terminal error is invalid';
    END IF;
    IF NEW.state = 'lease_expired' THEN
        IF NEW.completed_at < NEW.lease_expires_at OR
           (parent.state = 'running' AND
            (parent.lease_id IS DISTINCT FROM NEW.lease_id OR
             parent.lease_owner IS DISTINCT FROM NEW.worker_id OR
             parent.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at)) OR
           (parent.state IN ('failed','partial_failed') AND
            (parent.last_error_code <> 'retries_exhausted' OR
             parent.completed_at IS DISTINCT FROM NEW.completed_at)) OR
           parent.state NOT IN ('running','failed','partial_failed') THEN
            RAISE EXCEPTION 'expired attempt does not match parent lease exhaustion';
        END IF;
    ELSIF parent.state <> NEW.state OR
          parent.completed_at IS DISTINCT FROM NEW.completed_at OR
          parent.last_error_code IS DISTINCT FROM NEW.error_code THEN
        RAISE EXCEPTION 'terminal attempt does not match parent job';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_attempts_protected
BEFORE UPDATE ON background_job_attempts
FOR EACH ROW EXECUTE FUNCTION protect_background_job_attempt();

CREATE FUNCTION validate_background_job_projection(
    checked_tenant_id uuid,
    checked_job_id uuid,
    include_history boolean
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    parent background_jobs%ROWTYPE;
    current_attempt background_job_attempts%ROWTYPE;
    item_total integer;
    completed integer;
    succeeded integer;
    failed integer;
    cancelled integer;
    attempt_count integer;
    first_attempt integer;
    last_attempt integer;
    running_attempts integer;
    first_started_at timestamptz;
BEGIN
    SELECT * INTO parent FROM background_jobs
    WHERE tenant_id=checked_tenant_id AND id=checked_job_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'background job projection parent is missing';
    END IF;
    SELECT count(*)::integer,
           count(*) FILTER (WHERE state <> 'pending')::integer,
           count(*) FILTER (WHERE state = 'succeeded')::integer,
           count(*) FILTER (WHERE state = 'failed')::integer,
           count(*) FILTER (WHERE state = 'cancelled')::integer
    INTO item_total, completed, succeeded, failed, cancelled
    FROM background_job_items WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id;
    IF item_total <> parent.total_count OR completed <> parent.completed_count OR
       succeeded <> parent.succeeded_count OR failed <> parent.failed_count OR
       cancelled <> parent.cancelled_count THEN
        RAISE EXCEPTION 'background job progress does not match item aggregate';
    END IF;
    IF parent.state = 'queued' THEN
        IF failed <> 0 OR cancelled <> 0 OR completed <> succeeded OR
           parent.last_error_code IS NOT NULL OR parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'queued background job projection is invalid';
        END IF;
    ELSIF parent.state = 'running' THEN
        IF cancelled <> 0 OR parent.last_error_code IS NOT NULL OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'running background job projection is invalid';
        END IF;
    ELSIF parent.state = 'succeeded' THEN
        IF succeeded <> parent.total_count OR parent.last_error_code IS NOT NULL OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'succeeded background job projection is invalid';
        END IF;
    ELSIF parent.state = 'failed' THEN
        IF failed <> parent.total_count OR
           parent.last_error_code NOT IN ('all_items_failed','retries_exhausted') OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'failed background job projection is invalid';
        END IF;
    ELSIF parent.state = 'partial_failed' THEN
        IF completed <> parent.total_count OR succeeded = 0 OR failed = 0 OR cancelled <> 0 OR
           parent.last_error_code NOT IN ('item_failed','retries_exhausted') OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'partially failed background job projection is invalid';
        END IF;
    ELSIF parent.state = 'cancelled' THEN
        IF completed <> parent.total_count OR cancelled = 0 OR
           parent.last_error_code <> 'cancelled' OR parent.cancel_requested_at IS NULL OR
           parent.cancel_requested_at IS DISTINCT FROM parent.completed_at THEN
            RAISE EXCEPTION 'cancelled background job projection is invalid';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM background_job_items item
        WHERE item.tenant_id=checked_tenant_id AND item.job_id=checked_job_id AND
              item.state IN ('succeeded','failed') AND NOT EXISTS (
                  SELECT 1 FROM background_job_results result
                  WHERE result.tenant_id=item.tenant_id AND result.job_id=item.job_id AND
                        result.item_id=item.item_id AND result.attempt=item.attempt AND
                        result.sequence=item.sequence AND result.state=item.state AND
                        result.error_code IS NOT DISTINCT FROM item.error_code AND
                        result.reported_at=item.completed_at
              )
    ) THEN
        RAISE EXCEPTION 'terminal background job item is missing immutable result';
    END IF;
    IF NOT include_history THEN
        RETURN;
    END IF;

    SELECT count(*)::integer, min(attempt), max(attempt),
           count(*) FILTER (WHERE state='running')::integer
    INTO attempt_count, first_attempt, last_attempt, running_attempts
    FROM background_job_attempts WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id;
    IF attempt_count <> parent.attempt OR
       (parent.attempt > 0 AND (first_attempt <> 1 OR last_attempt <> parent.attempt)) THEN
        RAISE EXCEPTION 'background job attempt history is not contiguous';
    END IF;
    IF parent.attempt = 0 THEN
        IF parent.started_at IS NOT NULL OR parent.state NOT IN ('queued','cancelled') THEN
            RAISE EXCEPTION 'background job without attempts has invalid state';
        END IF;
        RETURN;
    END IF;
    SELECT started_at INTO first_started_at FROM background_job_attempts
    WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id AND attempt=1;
    SELECT * INTO current_attempt FROM background_job_attempts
    WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id AND attempt=parent.attempt;
    IF parent.started_at IS DISTINCT FROM first_started_at OR EXISTS (
        SELECT 1 FROM background_job_attempts
        WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id AND
              attempt < parent.attempt AND state='running'
    ) THEN
        RAISE EXCEPTION 'background job attempt history has invalid timing or active predecessor';
    END IF;
    IF parent.state = 'queued' THEN
        IF running_attempts <> 0 OR current_attempt.state NOT IN ('failed','partial_failed') THEN
            RAISE EXCEPTION 'retried queued job has invalid current attempt';
        END IF;
    ELSIF parent.state = 'running' THEN
        IF running_attempts <> 1 OR current_attempt.state <> 'running' OR
           current_attempt.lease_id IS DISTINCT FROM parent.lease_id OR
           current_attempt.worker_id IS DISTINCT FROM parent.lease_owner OR
           current_attempt.lease_expires_at IS DISTINCT FROM parent.lease_expires_at THEN
            RAISE EXCEPTION 'running background job does not match current attempt';
        END IF;
    ELSIF parent.state = 'succeeded' THEN
        IF running_attempts <> 0 OR current_attempt.state <> 'succeeded' OR
           current_attempt.error_code IS NOT NULL OR
           current_attempt.completed_at IS DISTINCT FROM parent.completed_at THEN
            RAISE EXCEPTION 'succeeded background job attempt is invalid';
        END IF;
    ELSIF parent.state IN ('failed','partial_failed') THEN
        IF running_attempts <> 0 OR current_attempt.completed_at IS DISTINCT FROM parent.completed_at OR
           NOT (
               (current_attempt.state = parent.state AND
                current_attempt.error_code IS NOT DISTINCT FROM parent.last_error_code) OR
               (current_attempt.state = 'lease_expired' AND
                current_attempt.error_code = 'lease_expired' AND
                parent.last_error_code = 'retries_exhausted')
           ) THEN
            RAISE EXCEPTION 'failed background job attempt is invalid';
        END IF;
    ELSIF parent.state = 'cancelled' THEN
        IF running_attempts <> 0 OR current_attempt.state <> 'cancelled' OR
           current_attempt.error_code <> 'cancelled' OR
           current_attempt.completed_at IS DISTINCT FROM parent.completed_at THEN
            RAISE EXCEPTION 'cancelled background job attempt is invalid';
        END IF;
    END IF;
END;
$$;

CREATE FUNCTION validate_background_job_items_statement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    changed record;
BEGIN
    FOR changed IN SELECT DISTINCT tenant_id, job_id FROM changed_items LOOP
        PERFORM validate_background_job_projection(changed.tenant_id, changed.job_id, false);
    END LOOP;
    RETURN NULL;
END;
$$;

CREATE TRIGGER background_job_items_insert_consistent
AFTER INSERT ON background_job_items
REFERENCING NEW TABLE AS changed_items
FOR EACH STATEMENT EXECUTE FUNCTION validate_background_job_items_statement();

CREATE TRIGGER background_job_items_update_consistent
AFTER UPDATE ON background_job_items
REFERENCING NEW TABLE AS changed_items
FOR EACH STATEMENT EXECUTE FUNCTION validate_background_job_items_statement();

CREATE FUNCTION validate_background_job_deferred()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM validate_background_job_projection(NEW.tenant_id, NEW.id, true);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER background_jobs_consistent
AFTER INSERT OR UPDATE ON background_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_background_job_deferred();

CREATE FUNCTION validate_background_job_attempt_deferred()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM validate_background_job_projection(NEW.tenant_id, NEW.job_id, true);
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER background_job_attempts_consistent
AFTER INSERT OR UPDATE ON background_job_attempts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_background_job_attempt_deferred();

CREATE FUNCTION validate_background_job_result_deferred()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    item background_job_items%ROWTYPE;
BEGIN
    SELECT * INTO item FROM background_job_items
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id AND item_id=NEW.item_id;
    IF item.state IS DISTINCT FROM NEW.state OR item.attempt <> NEW.attempt OR
       item.sequence <> NEW.sequence OR item.error_code IS DISTINCT FROM NEW.error_code OR
       NEW.reported_at IS DISTINCT FROM item.completed_at THEN
        RAISE EXCEPTION 'background job result was not applied to exact item';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER background_job_results_consistent
AFTER INSERT ON background_job_results
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_background_job_result_deferred();

CREATE FUNCTION prevent_background_job_history_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'background job history is retained';
END;
$$;

CREATE TRIGGER background_job_attempts_no_delete
BEFORE DELETE ON background_job_attempts
FOR EACH ROW EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_job_results_immutable
BEFORE UPDATE OR DELETE ON background_job_results
FOR EACH ROW EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_jobs_no_delete
BEFORE DELETE ON background_jobs
FOR EACH ROW EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_job_items_no_delete
BEFORE DELETE ON background_job_items
FOR EACH ROW EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_jobs_no_truncate
BEFORE TRUNCATE ON background_jobs
FOR EACH STATEMENT EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_job_items_no_truncate
BEFORE TRUNCATE ON background_job_items
FOR EACH STATEMENT EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_job_attempts_no_truncate
BEFORE TRUNCATE ON background_job_attempts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_background_job_history_delete();

CREATE TRIGGER background_job_results_no_truncate
BEFORE TRUNCATE ON background_job_results
FOR EACH STATEMENT EXECUTE FUNCTION prevent_background_job_history_delete();
