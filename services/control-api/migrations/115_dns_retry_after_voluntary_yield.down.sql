LOCK TABLE schema_migrations,
    background_job_yield_facts_115,
    background_jobs,
    background_job_attempts,
    background_job_items
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 115 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 115 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=115 AND migration_id='115_dns_retry_after_voluntary_yield'
          AND checksum_sha256='7cb3487ac88e30576b9553f587c4c0f91973899db6863ecb427eed237ce0875f'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=114 AND migration_id='114_package_monitor_metric_authority'
          AND checksum_sha256='438ff725214147c5bd10462396d715a47ba29aa554c7e180ff7a48b7bb37e5a3'
          AND down_checksum_sha256='60497e9b06e0157adf01fd1e01084fe25513118cad6ff8fcaf594a3147bb8415'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 115 rollback requires the exact verified 115 head'
            USING ERRCODE='P1150';
    END IF;
    IF EXISTS (SELECT 1 FROM background_job_yield_facts_115) THEN
        RAISE EXCEPTION 'migration 115 rollback would discard DNS Retry-After voluntary yield facts'
            USING ERRCODE='P1152';
    END IF;
    IF EXISTS (SELECT 1 FROM background_job_attempts WHERE state='deferred') THEN
        RAISE EXCEPTION 'migration 115 rollback would discard deferred background job attempts'
            USING ERRCODE='P1152';
    END IF;
END;
$$;

DROP TRIGGER background_job_yield_facts_final_115 ON background_job_yield_facts_115;
DROP TRIGGER background_job_yield_facts_no_truncate_115 ON background_job_yield_facts_115;
DROP TRIGGER background_job_yield_facts_protected_115 ON background_job_yield_facts_115;

CREATE OR REPLACE FUNCTION protect_background_job()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    retrying boolean;
    replaying boolean;
BEGIN
    replaying := NEW.state='queued' AND OLD.state IN ('failed','partial_failed') AND
        NEW.job_command_operation='replay' AND
        NEW.job_command_xact_id=pg_current_xact_id() AND EXISTS (
            SELECT 1 FROM background_job_replay_facts fact
            WHERE fact.tenant_id=OLD.tenant_id AND fact.job_id=OLD.id
              AND fact.dead_letter_attempt=OLD.attempt
              AND fact.old_max_attempts=OLD.max_attempts
              AND fact.new_max_attempts=NEW.max_attempts
              AND fact.job_command_xact_id=pg_current_xact_id()
        );
    IF ROW(
        NEW.id,NEW.tenant_id,NEW.kind,NEW.subject,NEW.idempotency_key,
        NEW.request_digest,NEW.request_id,NEW.trace_id,NEW.total_count,NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id,OLD.tenant_id,OLD.kind,OLD.subject,OLD.idempotency_key,
        OLD.request_digest,OLD.request_id,OLD.trace_id,OLD.total_count,OLD.created_at
    ) OR (NOT replaying AND NEW.max_attempts IS DISTINCT FROM OLD.max_attempts) OR
       (replaying AND NEW.max_attempts <> OLD.max_attempts+1) THEN
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
    IF NEW.completed_at IS NOT NULL AND NEW.completed_at < COALESCE(NEW.started_at,OLD.created_at) THEN
        RAISE EXCEPTION 'background job completed time cannot predate start';
    END IF;
    IF OLD.completed_at IS NOT NULL AND NEW.completed_at IS NOT NULL AND NEW.completed_at < OLD.completed_at THEN
        RAISE EXCEPTION 'background job completed time cannot move backwards';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL AND NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at THEN
        RAISE EXCEPTION 'background job cancellation request is immutable once set';
    END IF;
    IF OLD.cancel_requested_at IS NULL AND NEW.cancel_requested_at IS NOT NULL AND
       NEW.cancel_requested_at < OLD.created_at THEN
        RAISE EXCEPTION 'background job cancellation cannot predate creation';
    END IF;

    retrying := NEW.state='queued' AND OLD.state IN ('running','failed','partial_failed');
    IF NEW.succeeded_count < OLD.succeeded_count OR NEW.cancelled_count < OLD.cancelled_count OR
       (NOT retrying AND (NEW.completed_count < OLD.completed_count OR NEW.failed_count < OLD.failed_count)) THEN
        RAISE EXCEPTION 'background job progress cannot move backwards outside retry';
    END IF;

    IF OLD.state='queued' THEN
        IF NEW.state='running' THEN
            IF NEW.attempt <> OLD.attempt+1 OR NEW.attempt > OLD.max_attempts THEN
                RAISE EXCEPTION 'background job claim attempt is invalid';
            END IF;
        ELSIF NEW.state='cancelled' THEN
            IF NEW.attempt <> OLD.attempt THEN
                RAISE EXCEPTION 'background job cancellation changed attempt';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid background job transition from queued to %',NEW.state;
        END IF;
    ELSIF OLD.state='running' THEN
        IF NEW.state='running' OR NEW.state IN ('succeeded','partial_failed','failed','cancelled') THEN
            IF NEW.attempt <> OLD.attempt THEN
                RAISE EXCEPTION 'background job running attempt changed';
            END IF;
        ELSIF NEW.state='queued' THEN
            IF NEW.attempt <> OLD.attempt OR OLD.attempt >= OLD.max_attempts OR
               OLD.claimable_at > NEW.updated_at THEN
                RAISE EXCEPTION 'background job lease retry is invalid';
            END IF;
        ELSE
            RAISE EXCEPTION 'invalid background job transition from running to %',NEW.state;
        END IF;
    ELSIF OLD.state IN ('failed','partial_failed') THEN
        IF NEW.state <> 'queued' OR NEW.attempt <> OLD.attempt OR
           ((NOT replaying) AND OLD.attempt >= OLD.max_attempts) THEN
            RAISE EXCEPTION 'background job retry is invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'terminal background job is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_background_job_attempt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    parent background_jobs%ROWTYPE;
BEGIN
    IF ROW(NEW.tenant_id,NEW.job_id,NEW.attempt,NEW.lease_id,NEW.worker_id,NEW.started_at)
       IS DISTINCT FROM
       ROW(OLD.tenant_id,OLD.job_id,OLD.attempt,OLD.lease_id,OLD.worker_id,OLD.started_at) THEN
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
    IF NEW.state='running' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.error_code IS NOT NULL OR parent.state<>'running' OR
           parent.lease_id IS DISTINCT FROM NEW.lease_id OR parent.lease_owner IS DISTINCT FROM NEW.worker_id OR
           parent.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at OR
           parent.updated_at IS DISTINCT FROM NEW.last_heartbeat_at THEN
            RAISE EXCEPTION 'background job heartbeat does not match current claim';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.last_heartbeat_at IS DISTINCT FROM OLD.last_heartbeat_at OR
       NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at OR NEW.completed_at IS NULL OR
       NEW.completed_at < NEW.last_heartbeat_at THEN
        RAISE EXCEPTION 'background job attempt completion shape is invalid';
    END IF;
    IF (NEW.state='succeeded' AND NEW.error_code IS NOT NULL) OR
       (NEW.state='partial_failed' AND NEW.error_code<>'item_failed') OR
       (NEW.state='failed' AND NEW.error_code<>'all_items_failed') OR
       (NEW.state='cancelled' AND NEW.error_code<>'cancelled') OR
       (NEW.state='lease_expired' AND NEW.error_code<>'lease_expired') THEN
        RAISE EXCEPTION 'background job attempt terminal error is invalid';
    END IF;
    IF NEW.state='lease_expired' THEN
        IF NEW.completed_at < NEW.lease_expires_at OR
           (parent.state='running' AND
            (parent.lease_id IS DISTINCT FROM NEW.lease_id OR parent.lease_owner IS DISTINCT FROM NEW.worker_id OR
             parent.lease_expires_at IS DISTINCT FROM NEW.lease_expires_at)) OR
           (parent.state IN ('failed','partial_failed') AND
            (parent.last_error_code<>'retries_exhausted' OR parent.completed_at IS DISTINCT FROM NEW.completed_at)) OR
           parent.state NOT IN ('running','failed','partial_failed') THEN
            RAISE EXCEPTION 'expired attempt does not match parent lease exhaustion';
        END IF;
    ELSIF parent.state <> NEW.state OR parent.completed_at IS DISTINCT FROM NEW.completed_at OR
          parent.last_error_code IS DISTINCT FROM NEW.error_code THEN
        RAISE EXCEPTION 'terminal attempt does not match parent job';
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
    INTO item_total,completed,succeeded,failed,cancelled
    FROM background_job_items WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id;
    IF item_total<>parent.total_count OR completed<>parent.completed_count OR
       succeeded<>parent.succeeded_count OR failed<>parent.failed_count OR cancelled<>parent.cancelled_count THEN
        RAISE EXCEPTION 'background job progress does not match item aggregate';
    END IF;
    IF parent.state='queued' THEN
        IF failed<>0 OR cancelled<>0 OR completed<>succeeded OR parent.last_error_code IS NOT NULL OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'queued background job projection is invalid';
        END IF;
    ELSIF parent.state='running' THEN
        IF cancelled<>0 OR parent.last_error_code IS NOT NULL OR parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'running background job projection is invalid';
        END IF;
    ELSIF parent.state='succeeded' THEN
        IF succeeded<>parent.total_count OR parent.last_error_code IS NOT NULL OR parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'succeeded background job projection is invalid';
        END IF;
    ELSIF parent.state='failed' THEN
        IF failed<>parent.total_count OR parent.last_error_code NOT IN ('all_items_failed','retries_exhausted') OR
           parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'failed background job projection is invalid';
        END IF;
    ELSIF parent.state='partial_failed' THEN
        IF completed<>parent.total_count OR succeeded=0 OR failed=0 OR cancelled<>0 OR
           parent.last_error_code NOT IN ('item_failed','retries_exhausted') OR parent.cancel_requested_at IS NOT NULL THEN
            RAISE EXCEPTION 'partially failed background job projection is invalid';
        END IF;
    ELSIF parent.state='cancelled' THEN
        IF completed<>parent.total_count OR cancelled=0 OR parent.last_error_code<>'cancelled' OR
           parent.cancel_requested_at IS NULL OR parent.cancel_requested_at IS DISTINCT FROM parent.completed_at THEN
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
    SELECT count(*)::integer,min(attempt),max(attempt),
           count(*) FILTER (WHERE state='running')::integer
    INTO attempt_count,first_attempt,last_attempt,running_attempts
    FROM background_job_attempts WHERE tenant_id=checked_tenant_id AND job_id=checked_job_id;
    IF attempt_count<>parent.attempt OR
       (parent.attempt>0 AND (first_attempt<>1 OR last_attempt<>parent.attempt)) THEN
        RAISE EXCEPTION 'background job attempt history is not contiguous';
    END IF;
    IF parent.attempt=0 THEN
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
              attempt<parent.attempt AND state='running'
    ) THEN
        RAISE EXCEPTION 'background job attempt history has invalid timing or active predecessor';
    END IF;
    IF parent.state='queued' THEN
        IF running_attempts<>0 OR current_attempt.state NOT IN ('failed','partial_failed','lease_expired') OR
           (current_attempt.state='lease_expired' AND NOT (
                current_attempt.error_code IS NOT DISTINCT FROM 'lease_expired' AND
                current_attempt.completed_at IS NOT NULL AND parent.claimable_at>parent.updated_at
           )) THEN
            RAISE EXCEPTION 'retried queued job has invalid current attempt';
        END IF;
    ELSIF parent.state='running' THEN
        IF running_attempts<>1 OR current_attempt.state<>'running' OR
           current_attempt.lease_id IS DISTINCT FROM parent.lease_id OR
           current_attempt.worker_id IS DISTINCT FROM parent.lease_owner OR
           current_attempt.lease_expires_at IS DISTINCT FROM parent.lease_expires_at THEN
            RAISE EXCEPTION 'running background job does not match current attempt';
        END IF;
    ELSIF parent.state='succeeded' THEN
        IF running_attempts<>0 OR current_attempt.state<>'succeeded' OR current_attempt.error_code IS NOT NULL OR
           current_attempt.completed_at IS DISTINCT FROM parent.completed_at THEN
            RAISE EXCEPTION 'succeeded background job attempt is invalid';
        END IF;
    ELSIF parent.state IN ('failed','partial_failed') THEN
        IF running_attempts<>0 OR current_attempt.completed_at IS DISTINCT FROM parent.completed_at OR NOT (
            (current_attempt.state=parent.state AND current_attempt.error_code IS NOT DISTINCT FROM parent.last_error_code) OR
            (current_attempt.state='lease_expired' AND current_attempt.error_code='lease_expired' AND
             parent.last_error_code='retries_exhausted')
        ) THEN
            RAISE EXCEPTION 'failed background job attempt is invalid';
        END IF;
    ELSIF parent.state='cancelled' THEN
        IF running_attempts<>0 OR current_attempt.state<>'cancelled' OR current_attempt.error_code<>'cancelled' OR
           current_attempt.completed_at IS DISTINCT FROM parent.completed_at THEN
            RAISE EXCEPTION 'cancelled background job attempt is invalid';
        END IF;
    END IF;
END;
$$;

DROP FUNCTION validate_background_job_yield_fact_115();
DROP FUNCTION prevent_background_job_yield_fact_truncate_115();
DROP FUNCTION protect_background_job_yield_fact_115();
DROP TABLE background_job_yield_facts_115;

ALTER TABLE background_job_attempts
    DROP CONSTRAINT background_job_attempts_state_check,
    ADD CONSTRAINT background_job_attempts_state_check CHECK (state IN (
        'running','succeeded','partial_failed','failed','cancelled','lease_expired'
    ));
