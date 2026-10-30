LOCK TABLE schema_migrations,
    background_job_replay_facts,
    background_job_dead_letters,
    background_job_command_receipts,
    background_jobs,
    background_job_items,
    background_job_attempts,
    background_job_results,
    audit_events,
    access_scopes,
    memberships
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 104 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 104 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=104 AND migration_id='104_background_job_settlement_dlq'
          AND checksum_sha256='fac89e12c1c307327e4855a6cde1366026fb2914605723db14acd980519f3a5e'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=103
          AND migration_id='103_certificate_renewal_retry_after_failed_child'
          AND checksum_sha256='356d6bbee4f13cd68df4958156fc175663c500bf2c644630d35f8e5568483cf6'
          AND down_checksum_sha256='f7b6f88df56dbac6689bbc441bde80d6ab41a5eb8cf7af498778b5f25608b2ca'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 104 rollback requires the exact verified 104 head'
            USING ERRCODE='P1040';
    END IF;
    IF EXISTS (SELECT 1 FROM background_job_dead_letters) OR
       EXISTS (SELECT 1 FROM background_job_replay_facts) THEN
        RAISE EXCEPTION 'migration 104 rollback would discard settlement or replay facts'
            USING ERRCODE='P1041';
    END IF;
END;
$$;

DROP INDEX audit_events_job_command_denied_identity_094;
CREATE UNIQUE INDEX audit_events_job_command_denied_identity_094
ON audit_events(scope_id,actor_user_id,action,request_id)
WHERE result='denied'
  AND actor_user_id IS NOT NULL
  AND action IN ('job.cancel','job.retry');

CREATE OR REPLACE FUNCTION validate_background_job_command_success_audit_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.result = 'success' AND NEW.action IN ('job.cancel','job.retry') AND
       NOT EXISTS (
           SELECT 1 FROM background_job_command_receipts receipt
           WHERE receipt.audit_event_id=NEW.id
       ) THEN
        RAISE EXCEPTION 'successful background job command audit has no receipt'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION validate_background_job_command_mutation_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    job_row background_jobs%ROWTYPE;
    receipt_row background_job_command_receipts%ROWTYPE;
    audit_row audit_events%ROWTYPE;
    receipt_count integer;
BEGIN
    SELECT * INTO job_row FROM background_jobs
    WHERE id=NEW.id FOR SHARE;
    IF NOT FOUND OR job_row.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
        RAISE EXCEPTION 'invalid background job command mutation identity'
            USING ERRCODE = 'P9402';
    END IF;
    IF job_row.job_command_xact_id IS DISTINCT FROM pg_current_xact_id() THEN
        RETURN NULL;
    END IF;

    IF job_row.job_command_operation='dns_cancel' THEN
        IF NOT dns_reconcile_background_job_cancel_094(OLD,job_row) OR
           NOT dns_reconcile_cancel_final_094(job_row) THEN
            RAISE EXCEPTION 'invalid DNS reconcile cancel job mutation final state'
                USING ERRCODE = 'P9402';
        END IF;
        RETURN NULL;
    ELSIF job_row.job_command_operation='dns_recovery' THEN
        IF NOT dns_reconcile_background_job_recovery_final_094(OLD,job_row) THEN
            RAISE EXCEPTION 'invalid DNS reconcile recovery job mutation final state'
                USING ERRCODE = 'P9402';
        END IF;
        RETURN NULL;
    END IF;

    SELECT count(*) INTO receipt_count
    FROM background_job_command_receipts receipt
    WHERE receipt.tenant_id=job_row.tenant_id AND receipt.job_id=job_row.id
      AND receipt.job_command_xact_id=job_row.job_command_xact_id;
    IF receipt_count <> 1 THEN
        RAISE EXCEPTION 'background job command mutation requires exactly one receipt'
            USING ERRCODE = 'P9402';
    END IF;
    SELECT * INTO receipt_row FROM background_job_command_receipts receipt
    WHERE receipt.tenant_id=job_row.tenant_id AND receipt.job_id=job_row.id
      AND receipt.job_command_xact_id=job_row.job_command_xact_id;
    SELECT * INTO audit_row FROM audit_events WHERE id=receipt_row.audit_event_id FOR SHARE;

    IF audit_row.id IS NULL OR
       receipt_row.operation IS DISTINCT FROM job_row.job_command_operation OR
       audit_row.scope_id IS DISTINCT FROM receipt_row.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM receipt_row.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'job.'||receipt_row.operation OR
       audit_row.resource_type IS DISTINCT FROM 'background_job' OR
       audit_row.resource_id IS DISTINCT FROM job_row.id::text OR
       audit_row.request_id IS DISTINCT FROM receipt_row.request_id OR
       audit_row.result IS DISTINCT FROM 'success' OR
       ROW(job_row.kind,job_row.subject,job_row.request_id,job_row.trace_id,
           job_row.state,job_row.attempt,job_row.max_attempts,
           job_row.total_count,job_row.completed_count,job_row.succeeded_count,
           job_row.failed_count,job_row.cancelled_count,job_row.last_error_code,
           job_row.created_at,job_row.started_at,job_row.updated_at,job_row.completed_at)
       IS DISTINCT FROM
       ROW(receipt_row.result_kind,receipt_row.result_subject,
           receipt_row.result_request_id,receipt_row.result_trace_id,
           receipt_row.result_state,receipt_row.result_attempt,receipt_row.result_max_attempts,
           receipt_row.result_total_count,receipt_row.result_completed_count,
           receipt_row.result_succeeded_count,receipt_row.result_failed_count,
           receipt_row.result_cancelled_count,receipt_row.result_failure_code,
           receipt_row.result_created_at,receipt_row.result_started_at,
           receipt_row.result_updated_at,receipt_row.result_completed_at) OR
       receipt_row.created_at IS DISTINCT FROM receipt_row.result_updated_at OR
       audit_row.occurred_at < receipt_row.created_at THEN
        RAISE EXCEPTION 'invalid background job command mutation final state'
            USING ERRCODE = 'P9402';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION mark_background_job_command_mutation_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    command_operation text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.job_command_operation IS NOT NULL OR NEW.job_command_xact_id IS NOT NULL THEN
            RAISE EXCEPTION 'background job command markers are database managed'
                USING ERRCODE = 'P9402';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.job_command_operation,NEW.job_command_xact_id) IS DISTINCT FROM
       ROW(OLD.job_command_operation,OLD.job_command_xact_id) THEN
        RAISE EXCEPTION 'background job command markers are database managed'
            USING ERRCODE = 'P9402';
    END IF;

    IF OLD.state IN ('queued','running') AND NEW.state = 'cancelled' THEN
        IF dns_reconcile_background_job_cancel_094(OLD,NEW) THEN
            command_operation := 'dns_cancel';
        ELSE
            command_operation := 'cancel';
        END IF;
    ELSIF OLD.state IN ('failed','partial_failed') AND NEW.state = 'queued' THEN
        IF dns_reconcile_background_job_recovery_retry_089(OLD,NEW) AND EXISTS (
            SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
            WHERE continuation.tenant_id=OLD.tenant_id AND continuation.job_id=OLD.id
              AND continuation.consumed_at IS NULL
              AND continuation.job_transition_xact_id=pg_current_xact_id()
        ) THEN
            command_operation := 'dns_recovery';
        ELSE
            command_operation := 'retry';
        END IF;
    END IF;
    IF command_operation IS NOT NULL THEN
        IF OLD.job_command_xact_id = pg_current_xact_id() THEN
            RAISE EXCEPTION 'background job already has a command mutation in this transaction'
                USING ERRCODE = 'P9402';
        END IF;
        NEW.job_command_operation := command_operation;
        NEW.job_command_xact_id := pg_current_xact_id();
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_background_job()
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

CREATE OR REPLACE FUNCTION validate_background_job_projection(
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

CREATE OR REPLACE FUNCTION validate_background_job_command_receipt_094()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    audit_row audit_events%ROWTYPE;
    job_row background_jobs%ROWTYPE;
    actor_scope_kind text;
    actor_scope_tenant uuid;
    result_payload jsonb;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'background job command receipts are append-only'
            USING ERRCODE = 'P9402';
    END IF;
    IF NEW.job_command_xact_id IS DISTINCT FROM pg_current_xact_id() THEN
        RAISE EXCEPTION 'invalid background job command receipt transaction'
            USING ERRCODE = 'P9402';
    END IF;
    IF TG_WHEN = 'BEFORE' AND EXISTS (
        SELECT 1 FROM background_job_command_receipts receipt
        WHERE receipt.tenant_id=NEW.tenant_id AND receipt.job_id=NEW.job_id
          AND receipt.job_command_xact_id=NEW.job_command_xact_id
    ) THEN
        RAISE EXCEPTION 'background job command mutation already has a receipt'
            USING ERRCODE = 'P9402';
    END IF;
    SELECT kind,tenant_id INTO actor_scope_kind,actor_scope_tenant
    FROM access_scopes WHERE id=NEW.actor_scope_id FOR SHARE;
    IF NOT FOUND OR
       (NEW.audience = 'tenant' AND
        (actor_scope_kind <> 'tenant' OR actor_scope_tenant IS DISTINCT FROM NEW.tenant_id)) OR
       (NEW.audience = 'platform' AND
        (actor_scope_kind <> 'platform' OR actor_scope_tenant IS NOT NULL)) THEN
        RAISE EXCEPTION 'invalid background job command actor scope'
            USING ERRCODE = 'P9402';
    END IF;

    SELECT * INTO audit_row FROM audit_events WHERE id=NEW.audit_event_id FOR SHARE;
    SELECT * INTO job_row FROM background_jobs
    WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id FOR SHARE;
    IF NOT FOUND OR audit_row.id IS NULL OR
       audit_row.scope_id IS DISTINCT FROM NEW.actor_scope_id OR
       audit_row.actor_user_id IS DISTINCT FROM NEW.actor_user_id OR
       audit_row.action IS DISTINCT FROM 'job.'||NEW.operation OR
       audit_row.resource_type IS DISTINCT FROM 'background_job' OR
       audit_row.resource_id IS DISTINCT FROM NEW.job_id::text OR
       audit_row.request_id IS DISTINCT FROM NEW.request_id OR
       audit_row.result IS DISTINCT FROM 'success' OR
       job_row.job_command_operation IS DISTINCT FROM NEW.operation OR
       job_row.job_command_xact_id IS DISTINCT FROM NEW.job_command_xact_id OR
       ROW(job_row.kind,job_row.subject,job_row.request_id,job_row.trace_id,
           job_row.state,job_row.attempt,job_row.max_attempts,
           job_row.total_count,job_row.completed_count,job_row.succeeded_count,
           job_row.failed_count,job_row.cancelled_count,job_row.last_error_code,
           job_row.created_at,job_row.started_at,job_row.updated_at,job_row.completed_at)
       IS DISTINCT FROM
       ROW(NEW.result_kind,NEW.result_subject,NEW.result_request_id,NEW.result_trace_id,
           NEW.result_state,NEW.result_attempt,NEW.result_max_attempts,
           NEW.result_total_count,NEW.result_completed_count,NEW.result_succeeded_count,
           NEW.result_failed_count,NEW.result_cancelled_count,NEW.result_failure_code,
           NEW.result_created_at,NEW.result_started_at,NEW.result_updated_at,NEW.result_completed_at) OR
       NEW.created_at IS DISTINCT FROM NEW.result_updated_at OR
       audit_row.occurred_at < NEW.created_at THEN
        RAISE EXCEPTION 'invalid background job command receipt binding'
            USING ERRCODE = 'P9402';
    END IF;

    BEGIN
        result_payload := audit_row.payload->'result_data';
        IF audit_row.payload - ARRAY[
               'audience','operation','idempotency_key','request_digest','tenant_id','result_data'
           ] <> '{}'::jsonb OR
           NOT (audit_row.payload ?& ARRAY[
               'audience','operation','idempotency_key','request_digest','tenant_id','result_data'
           ]) OR
           audit_row.payload->>'audience' IS DISTINCT FROM NEW.audience OR
           audit_row.payload->>'operation' IS DISTINCT FROM NEW.operation OR
           audit_row.payload->>'idempotency_key' IS DISTINCT FROM NEW.idempotency_key OR
           audit_row.payload->>'request_digest' IS DISTINCT FROM encode(NEW.request_digest,'hex') OR
           audit_row.payload->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR
           jsonb_typeof(result_payload) IS DISTINCT FROM 'object' OR
           result_payload - ARRAY[
               'task_id','tenant_id','kind','subject','request_id','trace_id','state','attempt',
               'max_attempts','total_count','completed_count','succeeded_count','failed_count',
               'cancelled_count','failure_code','created_at','started_at','updated_at','completed_at'
           ] <> '{}'::jsonb OR
           NOT (result_payload ?& ARRAY[
               'task_id','tenant_id','kind','subject','request_id','trace_id','state','attempt',
               'max_attempts','total_count','completed_count','succeeded_count','failed_count',
               'cancelled_count','failure_code','created_at','started_at','updated_at','completed_at'
           ]) OR
           result_payload->>'task_id' IS DISTINCT FROM NEW.job_id::text OR
           result_payload->>'tenant_id' IS DISTINCT FROM NEW.tenant_id::text OR
           result_payload->>'kind' IS DISTINCT FROM NEW.result_kind OR
           result_payload->>'subject' IS DISTINCT FROM NEW.result_subject OR
           result_payload->>'request_id' IS DISTINCT FROM NEW.result_request_id OR
           result_payload->>'trace_id' IS DISTINCT FROM NEW.result_trace_id OR
           result_payload->>'state' IS DISTINCT FROM NEW.result_state OR
           (result_payload->>'attempt')::integer IS DISTINCT FROM NEW.result_attempt OR
           (result_payload->>'max_attempts')::integer IS DISTINCT FROM NEW.result_max_attempts OR
           (result_payload->>'total_count')::integer IS DISTINCT FROM NEW.result_total_count OR
           (result_payload->>'completed_count')::integer IS DISTINCT FROM NEW.result_completed_count OR
           (result_payload->>'succeeded_count')::integer IS DISTINCT FROM NEW.result_succeeded_count OR
           (result_payload->>'failed_count')::integer IS DISTINCT FROM NEW.result_failed_count OR
           (result_payload->>'cancelled_count')::integer IS DISTINCT FROM NEW.result_cancelled_count OR
           NULLIF(result_payload->>'failure_code','') IS DISTINCT FROM NEW.result_failure_code OR
           (result_payload->>'created_at')::timestamptz IS DISTINCT FROM NEW.result_created_at OR
           NULLIF(result_payload->>'started_at','')::timestamptz
               IS DISTINCT FROM NEW.result_started_at OR
           (result_payload->>'updated_at')::timestamptz IS DISTINCT FROM NEW.result_updated_at OR
           NULLIF(result_payload->>'completed_at','')::timestamptz
               IS DISTINCT FROM NEW.result_completed_at THEN
            RAISE EXCEPTION 'invalid background job command audit payload'
                USING ERRCODE = 'P9402';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'P9402' THEN RAISE;
        WHEN OTHERS THEN
            RAISE EXCEPTION 'invalid background job command audit payload'
                USING ERRCODE = 'P9402';
    END;
    RETURN NEW;
END;
$$;

ALTER TABLE background_job_command_receipts
    DROP CONSTRAINT background_job_command_receipts_operation_check,
    DROP CONSTRAINT background_job_command_receipts_result_check_104,
    ADD CONSTRAINT background_job_command_receipts_operation_check
        CHECK (operation IN ('cancel','retry')),
    ADD CONSTRAINT background_job_command_receipts_check3 CHECK (
        (operation = 'cancel' AND result_state = 'cancelled' AND
         result_completed_count = result_total_count AND result_failure_code = 'cancelled' AND
         result_completed_at IS NOT NULL) OR
        (operation = 'retry' AND result_state = 'queued' AND result_attempt > 0 AND
         result_completed_count = result_succeeded_count AND result_failed_count = 0 AND
         result_cancelled_count = 0 AND result_failure_code IS NULL AND result_completed_at IS NULL)
    );

ALTER TABLE background_jobs
    DROP CONSTRAINT background_jobs_job_command_marker_094,
    ADD CONSTRAINT background_jobs_job_command_marker_094 CHECK (
        (job_command_operation IS NULL AND job_command_xact_id IS NULL) OR
        (job_command_operation IN ('cancel','retry','dns_cancel','dns_recovery') AND
         job_command_xact_id IS NOT NULL)
    );

DROP TRIGGER background_job_replay_facts_immutable_104 ON background_job_replay_facts;
DROP TRIGGER background_job_replay_facts_final_104 ON background_job_replay_facts;
DROP TRIGGER background_job_replay_facts_validate_104 ON background_job_replay_facts;
DROP FUNCTION validate_background_job_replay_fact_104();
DROP TRIGGER background_job_dead_letters_immutable_104 ON background_job_dead_letters;
DROP TRIGGER background_job_dead_letters_final_104 ON background_job_dead_letters;
DROP TRIGGER background_job_dead_letters_validate_104 ON background_job_dead_letters;
DROP FUNCTION validate_background_job_dead_letter_104();

DROP TABLE background_job_replay_facts;
DROP TABLE background_job_dead_letters;

REVOKE ALL ON FUNCTION mark_background_job_command_mutation_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_background_job() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_background_job_command_receipt_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_background_job_command_mutation_094() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_background_job_command_success_audit_094() FROM PUBLIC;
