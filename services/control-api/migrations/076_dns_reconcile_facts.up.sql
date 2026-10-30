CREATE UNIQUE INDEX access_scopes_id_tenant_076_idx
    ON access_scopes (id, tenant_id);
CREATE UNIQUE INDEX sites_scope_id_id_076_idx
    ON sites (scope_id, id);

CREATE TABLE dns_reconcile_tasks (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL,
    job_id uuid PRIMARY KEY,
    site_id uuid NOT NULL,
    zone_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    job_idempotency_key text NOT NULL CHECK (job_idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    job_request_digest bytea NOT NULL CHECK (octet_length(job_request_digest) = 32),
    canonical_request jsonb NOT NULL CHECK (
        jsonb_typeof(canonical_request) = 'object' AND
        octet_length(canonical_request::text) BETWEEN 2 AND 1048576
    ),
    plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
    deterministic_plan jsonb NOT NULL CHECK (
        jsonb_typeof(deterministic_plan) = 'object' AND
        octet_length(deterministic_plan::text) BETWEEN 2 AND 1048576
    ),
    initial_provider_revision bigint NOT NULL CHECK (initial_provider_revision > 0),
    required_consecutive integer NOT NULL CHECK (required_consecutive BETWEEN 1 AND 5),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (tenant_id, job_id),
    UNIQUE (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES background_jobs(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX dns_reconcile_tasks_site_created_idx
    ON dns_reconcile_tasks (tenant_id, site_id, created_at DESC, job_id DESC);

CREATE TABLE dns_reconcile_operations (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    phase text NOT NULL CHECK (phase IN ('apply', 'commit')),
    ordinal integer NOT NULL CHECK (ordinal > 0),
    source_sequence integer NOT NULL CHECK (source_sequence > 0),
    action text NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    client_request_id text NOT NULL CHECK (
        octet_length(client_request_id) BETWEEN 1 AND 256 AND
        client_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    operation jsonb NOT NULL CHECK (
        jsonb_typeof(operation) = 'object' AND
        octet_length(operation::text) BETWEEN 2 AND 131072
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (job_id, phase, ordinal),
    UNIQUE (tenant_id, client_request_id),
    UNIQUE (tenant_id, job_id, phase, ordinal),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES dns_reconcile_tasks(tenant_id, job_id) ON DELETE RESTRICT,
    CHECK (
        (phase = 'apply' AND action IN ('create', 'update')) OR
        (phase = 'commit' AND action = 'delete')
    )
);

CREATE TABLE dns_reconcile_provider_reports (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    phase text NOT NULL,
    operation_ordinal integer NOT NULL,
    source text NOT NULL CHECK (source IN ('worker', 'workload')),
    command_idempotency_key text CHECK (
        command_idempotency_key IS NULL OR
        command_idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'
    ),
    command_digest bytea CHECK (
        command_digest IS NULL OR octet_length(command_digest) = 32
    ),
    request_id text CHECK (
        request_id IS NULL OR (
            octet_length(request_id) BETWEEN 1 AND 128 AND
            request_id = btrim(request_id) AND request_id !~ '[[:cntrl:]]'
        )
    ),
    traceparent text CHECK (
        traceparent IS NULL OR (
            octet_length(traceparent) BETWEEN 1 AND 512 AND
            traceparent = btrim(traceparent) AND traceparent !~ '[[:cntrl:]]'
        )
    ),
    expected_task_revision bigint CHECK (
        expected_task_revision IS NULL OR expected_task_revision > 0
    ),
    job_attempt integer CHECK (job_attempt IS NULL OR job_attempt > 0),
    lease_id uuid,
    worker_id text CHECK (
        worker_id IS NULL OR (
            octet_length(worker_id) BETWEEN 1 AND 128 AND
            worker_id = btrim(worker_id) AND worker_id !~ '[[:cntrl:]]'
        )
    ),
    report_sequence bigint NOT NULL CHECK (report_sequence > 0),
    status text NOT NULL CHECK (status IN (
        'running', 'succeeded', 'transient_failed', 'permanent_failed',
        'revision_conflict', 'cancelled', 'skipped'
    )),
    provider_request_id text CHECK (
        provider_request_id IS NULL OR (
            octet_length(provider_request_id) BETWEEN 1 AND 256 AND
            provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    provider_record_id text CHECK (
        provider_record_id IS NULL OR (
            octet_length(provider_record_id) BETWEEN 1 AND 256 AND
            provider_record_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    provider_revision bigint CHECK (provider_revision IS NULL OR provider_revision > 0),
    error_class text NOT NULL DEFAULT '' CHECK (
        error_class IN ('', 'transient', 'permanent', 'revision_conflict', 'cancelled', 'timeout')
    ),
    error_code text CHECK (
        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    accepted boolean NOT NULL,
    disposition text NOT NULL CHECK (disposition IN (
        'accepted', 'duplicate', 'stale_sequence', 'status_regression', 'conflict'
    )),
    reported_at timestamptz NOT NULL CHECK (isfinite(reported_at)),
    received_at timestamptz NOT NULL CHECK (isfinite(received_at)),
    UNIQUE (tenant_id, job_id, phase, operation_ordinal, id),
    FOREIGN KEY (tenant_id, job_id, phase, operation_ordinal)
        REFERENCES dns_reconcile_operations(tenant_id, job_id, phase, ordinal)
        ON DELETE RESTRICT,
    CHECK (reported_at <= received_at),
    CHECK (accepted = (disposition = 'accepted')),
    CHECK (
        status <> 'succeeded' OR (
            provider_request_id IS NOT NULL AND provider_record_id IS NOT NULL AND
            provider_revision IS NOT NULL AND error_class = '' AND error_code IS NULL
        )
    ),
    CHECK (
        (source = 'worker' AND command_idempotency_key IS NULL AND command_digest IS NULL AND
         request_id IS NULL AND traceparent IS NULL AND expected_task_revision IS NULL AND
         job_attempt IS NOT NULL AND lease_id IS NOT NULL AND worker_id IS NOT NULL) OR
        (source = 'workload' AND command_idempotency_key IS NOT NULL AND command_digest IS NOT NULL AND
         request_id IS NOT NULL AND traceparent IS NOT NULL AND expected_task_revision IS NOT NULL AND
         job_attempt IS NULL AND lease_id IS NULL AND worker_id IS NULL)
    )
);

CREATE UNIQUE INDEX dns_reconcile_provider_reports_accepted_sequence_idx
    ON dns_reconcile_provider_reports (
        job_id, phase, operation_ordinal, report_sequence
    ) WHERE accepted;
CREATE INDEX dns_reconcile_provider_reports_current_idx
    ON dns_reconcile_provider_reports (
        tenant_id, job_id, phase, operation_ordinal, report_sequence DESC, received_at DESC
    ) WHERE accepted;
CREATE UNIQUE INDEX dns_reconcile_provider_reports_workload_command_idx
    ON dns_reconcile_provider_reports (tenant_id, command_idempotency_key)
    WHERE source = 'workload';

CREATE TABLE dns_reconcile_propagation_attempts (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    job_attempt integer NOT NULL CHECK (job_attempt > 0),
    lease_id uuid NOT NULL,
    worker_id text NOT NULL CHECK (
        octet_length(worker_id) BETWEEN 1 AND 128 AND
        worker_id = btrim(worker_id) AND worker_id !~ '[[:cntrl:]]'
    ),
    attempt_number integer NOT NULL CHECK (attempt_number > 0),
    classification text NOT NULL CHECK (classification IN (
        'healthy', 'missing_record', 'wrong_value', 'cname_chain', 'cname_loop',
        'cname_depth_exceeded', 'nxdomain', 'servfail', 'timeout',
        'authority_inconsistent', 'public_propagating', 'public_propagation_failed',
        'resolver_failure', 'malformed_response'
    )),
    consecutive_healthy integer NOT NULL CHECK (
        consecutive_healthy BETWEEN 0 AND attempt_number
    ),
    check_result jsonb NOT NULL CHECK (
        jsonb_typeof(check_result) = 'object' AND
        octet_length(check_result::text) BETWEEN 2 AND 1048576
    ),
    checked_at timestamptz NOT NULL CHECK (isfinite(checked_at)),
    recorded_at timestamptz NOT NULL CHECK (isfinite(recorded_at)),
    PRIMARY KEY (job_id, job_attempt, attempt_number),
    UNIQUE (tenant_id, job_id, job_attempt, attempt_number),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES dns_reconcile_tasks(tenant_id, job_id) ON DELETE RESTRICT,
    CHECK (checked_at <= recorded_at)
);

CREATE TABLE dns_reconcile_task_events (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    source text NOT NULL CHECK (source IN ('worker', 'commit', 'workload', 'control')),
    job_attempt integer,
    lease_id uuid,
    worker_id text,
    status text NOT NULL CHECK (status IN (
        'applying', 'propagating', 'ready_to_commit', 'committed', 'failed',
        'cancelled', 'timed_out', 'commit_failed'
    )),
    provider_revision bigint CHECK (provider_revision IS NULL OR provider_revision > 0),
    result_snapshot jsonb NOT NULL CHECK (
        jsonb_typeof(result_snapshot) = 'object' AND
        octet_length(result_snapshot::text) BETWEEN 2 AND 2097152
    ),
    compensation_plan jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(compensation_plan) = 'array' AND
        octet_length(compensation_plan::text) <= 1048576
    ),
    error_class text NOT NULL DEFAULT '' CHECK (
        error_class IN ('', 'transient', 'permanent', 'revision_conflict', 'cancelled', 'timeout')
    ),
    error_code text CHECK (
        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    PRIMARY KEY (job_id, event_sequence),
    UNIQUE (tenant_id, job_id, event_sequence),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES dns_reconcile_tasks(tenant_id, job_id) ON DELETE RESTRICT,
    CHECK (
        (source IN ('worker', 'commit') AND job_attempt > 0 AND lease_id IS NOT NULL AND worker_id IS NOT NULL) OR
        (source IN ('workload', 'control') AND job_attempt IS NULL AND lease_id IS NULL AND worker_id IS NULL)
    ),
    CHECK ((error_class = '' AND error_code IS NULL) OR (error_class <> '' AND error_code IS NOT NULL))
);

CREATE INDEX dns_reconcile_task_events_current_idx
    ON dns_reconcile_task_events (tenant_id, job_id, event_sequence DESC);

CREATE TABLE dns_reconcile_commit_facts (
    tenant_id uuid NOT NULL,
    job_id uuid NOT NULL,
    command_idempotency_key text NOT NULL CHECK (
        command_idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'
    ),
    command_digest bytea NOT NULL CHECK (octet_length(command_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id = btrim(request_id) AND request_id !~ '[[:cntrl:]]'
    ),
    traceparent text NOT NULL CHECK (
        octet_length(traceparent) BETWEEN 1 AND 512 AND
        traceparent = btrim(traceparent) AND traceparent !~ '[[:cntrl:]]'
    ),
    expected_task_revision bigint NOT NULL CHECK (expected_task_revision > 0),
    fact_sequence bigint NOT NULL CHECK (fact_sequence > 0),
    commit_attempt integer NOT NULL CHECK (commit_attempt > 0),
    lease_id uuid NOT NULL,
    worker_id text NOT NULL CHECK (
        octet_length(worker_id) BETWEEN 1 AND 128 AND
        worker_id = btrim(worker_id) AND worker_id !~ '[[:cntrl:]]'
    ),
    lease_expires_at timestamptz NOT NULL CHECK (isfinite(lease_expires_at)),
    event_type text NOT NULL CHECK (event_type IN (
        'claimed', 'heartbeat', 'revision_checked', 'delete_succeeded', 'failed', 'committed'
    )),
    operation_phase text GENERATED ALWAYS AS ('commit'::text) STORED,
    operation_ordinal integer,
    provider_request_id text CHECK (
        provider_request_id IS NULL OR (
            octet_length(provider_request_id) BETWEEN 1 AND 256 AND
            provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    provider_record_id text CHECK (
        provider_record_id IS NULL OR (
            octet_length(provider_record_id) BETWEEN 1 AND 256 AND
            provider_record_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    report_sequence bigint CHECK (report_sequence IS NULL OR report_sequence > 0),
    expected_provider_revision bigint NOT NULL CHECK (expected_provider_revision > 0),
    provider_revision bigint CHECK (provider_revision IS NULL OR provider_revision > 0),
    compensation_plan jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(compensation_plan) = 'array' AND
        octet_length(compensation_plan::text) <= 1048576
    ),
    error_class text NOT NULL DEFAULT '' CHECK (
        error_class IN ('', 'transient', 'permanent', 'revision_conflict', 'cancelled', 'timeout')
    ),
    error_code text CHECK (
        error_code IS NULL OR error_code ~ '^[a-z][a-z0-9._-]{0,127}$'
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (job_id, fact_sequence),
    UNIQUE (tenant_id, job_id, fact_sequence),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES dns_reconcile_tasks(tenant_id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, job_id, operation_phase, operation_ordinal)
        REFERENCES dns_reconcile_operations(tenant_id, job_id, phase, ordinal)
        ON DELETE RESTRICT,
    CHECK (lease_expires_at > created_at),
    CHECK (
        (event_type = 'delete_succeeded' AND operation_ordinal IS NOT NULL AND
         provider_request_id IS NOT NULL AND provider_record_id IS NOT NULL AND
         report_sequence IS NOT NULL AND provider_revision IS NOT NULL) OR
        (event_type <> 'delete_succeeded' AND operation_ordinal IS NULL AND
         provider_request_id IS NULL AND provider_record_id IS NULL AND report_sequence IS NULL)
    ),
    CHECK (
        (event_type = 'failed' AND error_class <> '' AND error_code IS NOT NULL) OR
        (event_type <> 'failed' AND error_class = '' AND error_code IS NULL)
    )
);

CREATE INDEX dns_reconcile_commit_facts_current_idx
    ON dns_reconcile_commit_facts (tenant_id, job_id, fact_sequence DESC);
CREATE UNIQUE INDEX dns_reconcile_commit_facts_claimed_idx
    ON dns_reconcile_commit_facts (job_id, commit_attempt)
    WHERE event_type = 'claimed';
CREATE UNIQUE INDEX dns_reconcile_commit_facts_delete_idx
    ON dns_reconcile_commit_facts (job_id, operation_ordinal)
    WHERE event_type = 'delete_succeeded';
CREATE UNIQUE INDEX dns_reconcile_commit_facts_committed_idx
    ON dns_reconcile_commit_facts (job_id)
    WHERE event_type = 'committed';
CREATE UNIQUE INDEX dns_reconcile_commit_facts_command_idx
    ON dns_reconcile_commit_facts (tenant_id, command_idempotency_key)
    WHERE fact_sequence = 1;

CREATE TABLE dns_reconcile_cancel_facts (
    tenant_id uuid NOT NULL,
    job_id uuid PRIMARY KEY,
    site_id uuid NOT NULL,
    command_idempotency_key text NOT NULL CHECK (
        command_idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'
    ),
    command_digest bytea NOT NULL CHECK (octet_length(command_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id = btrim(request_id) AND request_id !~ '[[:cntrl:]]'
    ),
    traceparent text NOT NULL CHECK (
        octet_length(traceparent) BETWEEN 1 AND 512 AND
        traceparent = btrim(traceparent) AND traceparent !~ '[[:cntrl:]]'
    ),
    expected_task_revision bigint NOT NULL CHECK (expected_task_revision > 0),
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (tenant_id, command_idempotency_key),
    UNIQUE (tenant_id, job_id),
    FOREIGN KEY (tenant_id, job_id)
        REFERENCES dns_reconcile_tasks(tenant_id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, job_id, event_sequence)
        REFERENCES dns_reconcile_task_events(tenant_id, job_id, event_sequence) ON DELETE RESTRICT
);

CREATE FUNCTION protect_dns_reconcile_fact_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'DNS reconcile facts are append-only';
END;
$$;

CREATE FUNCTION validate_dns_reconcile_task_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    job background_jobs%ROWTYPE;
BEGIN
    SELECT * INTO job FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
    IF NOT FOUND OR job.kind <> 'dns_reconcile' OR
       job.idempotency_key IS DISTINCT FROM NEW.job_idempotency_key OR
       job.request_digest IS DISTINCT FROM NEW.job_request_digest OR
       job.state <> 'queued' OR job.attempt <> 0 OR job.total_count <> 1 OR
       job.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'DNS reconcile task must match its initial background job';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_dns_reconcile_live_claim_076(
    fact_tenant_id uuid,
    fact_job_id uuid,
    fact_attempt integer,
    fact_lease_id uuid,
    fact_worker_id text,
    fact_time timestamptz
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    live boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM background_jobs job
        JOIN background_job_attempts attempt
          ON attempt.tenant_id=job.tenant_id AND attempt.job_id=job.id
         AND attempt.attempt=job.attempt
        WHERE job.tenant_id=fact_tenant_id AND job.id=fact_job_id
          AND job.state='running' AND job.attempt=fact_attempt
          AND job.lease_id=fact_lease_id AND job.lease_owner=fact_worker_id
          AND job.lease_expires_at > fact_time
          AND attempt.state='running' AND attempt.lease_id=fact_lease_id
          AND attempt.worker_id=fact_worker_id
          AND attempt.lease_expires_at=job.lease_expires_at
    ) INTO live;
    IF NOT live THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DNS reconcile worker claim is stale or expired';
    END IF;
END;
$$;

CREATE FUNCTION validate_dns_reconcile_provider_report_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_sequence bigint;
    latest_revision bigint;
BEGIN
    PERFORM 1 FROM dns_reconcile_operations
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id
      AND phase=NEW.phase AND ordinal=NEW.operation_ordinal
    FOR UPDATE;
    IF NEW.source = 'worker' THEN
        PERFORM assert_dns_reconcile_live_claim_076(
            NEW.tenant_id, NEW.job_id, NEW.job_attempt, NEW.lease_id,
            NEW.worker_id, NEW.received_at
        );
    END IF;
    IF NEW.accepted THEN
        SELECT max(report_sequence), max(provider_revision)
        INTO latest_sequence, latest_revision
        FROM dns_reconcile_provider_reports
        WHERE job_id=NEW.job_id AND phase=NEW.phase
          AND operation_ordinal=NEW.operation_ordinal AND accepted;
        IF latest_sequence IS NOT NULL AND NEW.report_sequence <= latest_sequence THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'accepted DNS provider report sequence is not increasing';
        END IF;
        IF latest_revision IS NOT NULL AND NEW.provider_revision IS NOT NULL AND
           NEW.provider_revision < latest_revision THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'accepted DNS provider revision is not increasing';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_dns_reconcile_propagation_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_number integer;
BEGIN
    PERFORM 1 FROM dns_reconcile_tasks
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
    PERFORM assert_dns_reconcile_live_claim_076(
        NEW.tenant_id, NEW.job_id, NEW.job_attempt, NEW.lease_id,
        NEW.worker_id, NEW.recorded_at
    );
    SELECT COALESCE(max(attempt_number),0) INTO latest_number
    FROM dns_reconcile_propagation_attempts
    WHERE job_id=NEW.job_id;
    IF NEW.attempt_number <> latest_number + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DNS propagation attempt sequence is not contiguous';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_dns_reconcile_task_event_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest_sequence bigint;
    latest_commit record;
BEGIN
    PERFORM 1 FROM dns_reconcile_tasks
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
    SELECT COALESCE(max(event_sequence),0) INTO latest_sequence
    FROM dns_reconcile_task_events WHERE job_id=NEW.job_id;
    IF NEW.event_sequence <> latest_sequence + 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'DNS reconcile task event sequence is not contiguous';
    END IF;
    IF NEW.source = 'worker' THEN
        PERFORM assert_dns_reconcile_live_claim_076(
            NEW.tenant_id, NEW.job_id, NEW.job_attempt, NEW.lease_id,
            NEW.worker_id, NEW.occurred_at
        );
    ELSIF NEW.source = 'commit' THEN
        SELECT * INTO latest_commit FROM dns_reconcile_commit_facts
        WHERE job_id=NEW.job_id ORDER BY fact_sequence DESC LIMIT 1;
        IF NOT FOUND OR latest_commit.commit_attempt <> NEW.job_attempt OR
           latest_commit.lease_id <> NEW.lease_id OR latest_commit.worker_id <> NEW.worker_id OR
           latest_commit.created_at > NEW.occurred_at OR
           latest_commit.lease_expires_at <= NEW.occurred_at OR
           (latest_commit.event_type = 'failed' AND NEW.status NOT IN ('commit_failed','ready_to_commit')) OR
           (latest_commit.event_type = 'committed' AND NEW.status <> 'committed') THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'DNS reconcile commit claim is stale or expired';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_dns_reconcile_commit_fact_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    previous dns_reconcile_commit_facts%ROWTYPE;
    task_status text;
BEGIN
    PERFORM 1 FROM dns_reconcile_tasks
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
    SELECT status INTO task_status FROM dns_reconcile_task_events
    WHERE job_id=NEW.job_id ORDER BY event_sequence DESC LIMIT 1;
    IF task_status IS NULL OR task_status NOT IN ('ready_to_commit','commit_failed') THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS reconcile task is not commit ready';
    END IF;
    SELECT * INTO previous FROM dns_reconcile_commit_facts
    WHERE job_id=NEW.job_id ORDER BY fact_sequence DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.fact_sequence <> 1 OR NEW.commit_attempt <> 1 OR NEW.event_type <> 'claimed' THEN
            RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit must start with its first claim';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.command_idempotency_key <> previous.command_idempotency_key OR
       NEW.command_digest <> previous.command_digest OR
       NEW.expected_task_revision <> previous.expected_task_revision THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit command identity changed';
    END IF;
    IF NEW.fact_sequence <> previous.fact_sequence + 1 THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit fact sequence is not contiguous';
    END IF;
    IF previous.event_type = 'committed' THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='committed DNS task is immutable';
    END IF;
    IF previous.event_type = 'failed' OR NEW.created_at >= previous.lease_expires_at THEN
        IF NEW.event_type <> 'claimed' OR NEW.commit_attempt <> previous.commit_attempt + 1 OR
           NEW.lease_id = previous.lease_id THEN
            RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit recovery claim is invalid';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.event_type = 'claimed' OR NEW.commit_attempt <> previous.commit_attempt OR
       NEW.lease_id <> previous.lease_id OR NEW.worker_id <> previous.worker_id OR
       NEW.request_id <> previous.request_id OR NEW.traceparent <> previous.traceparent OR
       NEW.expected_provider_revision <> previous.expected_provider_revision OR
       NEW.created_at >= previous.lease_expires_at THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit lease was lost';
    END IF;
    IF NEW.event_type = 'heartbeat' THEN
        IF NEW.lease_expires_at <= previous.lease_expires_at THEN
            RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit heartbeat did not extend lease';
        END IF;
    ELSIF NEW.lease_expires_at <> previous.lease_expires_at THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS commit fact changed lease expiry';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_dns_reconcile_cancel_fact_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    task_site_id uuid;
    cancellation record;
BEGIN
    SELECT site_id INTO task_site_id FROM dns_reconcile_tasks
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
    IF NOT FOUND OR task_site_id <> NEW.site_id THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS cancellation does not match task';
    END IF;
    SELECT source,status,occurred_at INTO cancellation FROM dns_reconcile_task_events
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id
      AND event_sequence=NEW.event_sequence;
    IF NOT FOUND OR cancellation.source <> 'control' OR cancellation.status <> 'cancelled' OR
       cancellation.occurred_at <> NEW.created_at THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS cancellation fact is not canonical';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_reconcile_tasks_insert_validated_076
BEFORE INSERT ON dns_reconcile_tasks
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_task_076();
CREATE TRIGGER dns_reconcile_provider_reports_insert_validated_076
BEFORE INSERT ON dns_reconcile_provider_reports
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_provider_report_076();
CREATE TRIGGER dns_reconcile_propagation_insert_validated_076
BEFORE INSERT ON dns_reconcile_propagation_attempts
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_propagation_076();
CREATE TRIGGER dns_reconcile_task_events_insert_validated_076
BEFORE INSERT ON dns_reconcile_task_events
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_task_event_076();
CREATE TRIGGER dns_reconcile_commit_facts_insert_validated_076
BEFORE INSERT ON dns_reconcile_commit_facts
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_commit_fact_076();
CREATE TRIGGER dns_reconcile_cancel_facts_insert_validated_076
BEFORE INSERT ON dns_reconcile_cancel_facts
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_cancel_fact_076();

CREATE TRIGGER dns_reconcile_tasks_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_tasks
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_operations_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_operations
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_provider_reports_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_provider_reports
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_propagation_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_propagation_attempts
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_task_events_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_task_events
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_commit_facts_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_commit_facts
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_cancel_facts_append_only_076
BEFORE UPDATE OR DELETE ON dns_reconcile_cancel_facts
FOR EACH ROW EXECUTE FUNCTION protect_dns_reconcile_fact_076();

CREATE TRIGGER dns_reconcile_tasks_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_tasks
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_operations_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_operations
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_provider_reports_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_provider_reports
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_propagation_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_propagation_attempts
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_task_events_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_task_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_commit_facts_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_commit_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();
CREATE TRIGGER dns_reconcile_cancel_facts_no_truncate_076
BEFORE TRUNCATE ON dns_reconcile_cancel_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_reconcile_fact_076();

ALTER TABLE dns_reconcile_tasks ENABLE ALWAYS TRIGGER dns_reconcile_tasks_append_only_076;
ALTER TABLE dns_reconcile_operations ENABLE ALWAYS TRIGGER dns_reconcile_operations_append_only_076;
ALTER TABLE dns_reconcile_provider_reports ENABLE ALWAYS TRIGGER dns_reconcile_provider_reports_append_only_076;
ALTER TABLE dns_reconcile_propagation_attempts ENABLE ALWAYS TRIGGER dns_reconcile_propagation_append_only_076;
ALTER TABLE dns_reconcile_task_events ENABLE ALWAYS TRIGGER dns_reconcile_task_events_append_only_076;
ALTER TABLE dns_reconcile_commit_facts ENABLE ALWAYS TRIGGER dns_reconcile_commit_facts_append_only_076;
ALTER TABLE dns_reconcile_cancel_facts ENABLE ALWAYS TRIGGER dns_reconcile_cancel_facts_append_only_076;
ALTER TABLE dns_reconcile_tasks ENABLE ALWAYS TRIGGER dns_reconcile_tasks_no_truncate_076;
ALTER TABLE dns_reconcile_operations ENABLE ALWAYS TRIGGER dns_reconcile_operations_no_truncate_076;
ALTER TABLE dns_reconcile_provider_reports ENABLE ALWAYS TRIGGER dns_reconcile_provider_reports_no_truncate_076;
ALTER TABLE dns_reconcile_propagation_attempts ENABLE ALWAYS TRIGGER dns_reconcile_propagation_no_truncate_076;
ALTER TABLE dns_reconcile_task_events ENABLE ALWAYS TRIGGER dns_reconcile_task_events_no_truncate_076;
ALTER TABLE dns_reconcile_commit_facts ENABLE ALWAYS TRIGGER dns_reconcile_commit_facts_no_truncate_076;
ALTER TABLE dns_reconcile_cancel_facts ENABLE ALWAYS TRIGGER dns_reconcile_cancel_facts_no_truncate_076;
